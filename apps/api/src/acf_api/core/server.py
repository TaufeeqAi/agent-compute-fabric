"""The core's side of the command interface: a local socket that admits the edge's identity and no other.

The socket is the one seam between the role that parses and the role that decides. The kernel reports
who connected; a connection from any operating-system identity that is not a configured edge identity
is closed before a byte of it is read. That admits the *edge*. It says nothing about the *caller*: the
core verifies the caller's credential itself, on every command.

A connection carries one exchange at a time. If the edge goes away while a command is being handled,
the handling is cancelled, which abandons a wait and nothing else: the part of a mutation between its
claim and its bind is shielded and runs to its end.

Neither side logs a frame. The request frame carries the caller's credential.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import socket
import stat
import struct
from pathlib import Path
from typing import Final

from acf_api.command import codec
from acf_api.command.answers import (
    COMMAND_INTERFACE_VERSION,
    Answer,
    ErrorAnswer,
    HandleRequest,
    VerifyRequest,
)
from acf_api.command.errors import Code, Kind, Retry
from acf_api.command.model import ErrorBody
from acf_api.core.pipeline.service import RuntimeService
from acf_api.core.telemetry import Telemetry

_UCRED: Final = struct.Struct("3i")
_BACKLOG: Final = 512


class SocketInUse(Exception):
    """Something already answers on the socket path: another core serves this deployment."""


def peer_uid(writer: asyncio.StreamWriter) -> int | None:
    """The operating-system identity of the peer of a local socket, as the kernel reports it."""
    sock = writer.get_extra_info("socket")
    if sock is None:
        return None
    try:
        raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED.size)
    except OSError:
        return None
    _pid, uid, _gid = _UCRED.unpack(raw)
    return int(uid)


async def _something_answers(path: Path) -> bool:
    try:
        _reader, writer = await asyncio.wait_for(asyncio.open_unix_connection(str(path)), 1.0)
    except (OSError, TimeoutError):
        return False
    writer.close()
    return True


async def bind_private_socket(path: Path, *, mode: int, gid: int | None) -> socket.socket:
    """Bind a local socket that nobody else is serving. A live listener is another core, and is not displaced."""
    if path.exists():  # noqa: ASYNC240 - runs only while the core starts
        if not stat.S_ISSOCK(path.lstat().st_mode):  # noqa: ASYNC240 - runs only while the core starts
            raise SocketInUse(f"{path} exists and is not a socket")
        if await _something_answers(path):
            raise SocketInUse(f"something already serves {path}; a second core refuses to start")
        path.unlink()  # noqa: ASYNC240 - runs only while the core starts
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    previous = os.umask(0o177)
    try:
        sock.bind(str(path))
    finally:
        os.umask(previous)
    # A directory with the set-group-id bit has already given the socket its group; then nothing is asked
    # of the kernel that a confined service might not be allowed to ask.
    if gid is not None and path.lstat().st_gid != gid:  # noqa: ASYNC240 - runs only while the core starts
        os.chown(path, -1, gid)
    os.chmod(path, mode)
    sock.listen(_BACKLOG)
    sock.setblocking(False)  # noqa: FBT003 - the standard library's signature
    return sock


async def close_listener(server: asyncio.Server | None, connections: set[asyncio.Task[None]], path: Path) -> None:
    """Stop a listener this process bound: no new connection, every open one ended, its path removed.

    ``server`` is ``None`` when the socket was never bound, for example because another core answers
    on it. Then nothing here is this process's to remove: the path is the other core's socket, or a
    file somebody put there, and it is left exactly as it is.

    A peer keeps its connections open between two requests. Waiting for them to close would let the
    peer decide how long the core takes to stop, so they are ended here, before the wait. What the peer
    then sees is a lost answer, which is the truth.
    """
    if server is None:
        return
    server.close()
    open_connections = list(connections)
    for task in open_connections:
        task.cancel()
    if open_connections:
        await asyncio.gather(*open_connections, return_exceptions=True)
    with contextlib.suppress(Exception):
        await server.wait_closed()
    with contextlib.suppress(OSError):
        path.unlink()  # noqa: ASYNC240 - runs only while the core stops


class CommandServer:
    def __init__(
        self,
        service: RuntimeService,
        path: Path,
        *,
        allowed_uids: frozenset[int],
        socket_gid: int | None,
        telemetry: Telemetry,
        max_request_frame: int = codec.DEFAULT_MAX_REQUEST_FRAME,
        max_answer_frame: int = codec.DEFAULT_MAX_ANSWER_FRAME,
    ) -> None:
        self._service = service
        self._path = path
        self._allowed = allowed_uids
        self._gid = socket_gid
        self._telemetry = telemetry
        self._max_request = max_request_frame
        self._max_answer = max_answer_frame
        self._server: asyncio.Server | None = None
        self._connections: set[asyncio.Task[None]] = set()

    async def start(self) -> None:
        # Readable and writable by the socket's group, which is the edge's: the edge connects, nobody else can.
        sock = await bind_private_socket(self._path, mode=0o660, gid=self._gid)
        self._server = await asyncio.start_unix_server(self._accept, sock=sock)

    async def close(self) -> None:
        server, self._server = self._server, None
        await close_listener(server, self._connections, self._path)

    async def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._connections.add(task)
        try:
            uid = peer_uid(writer)
            if uid is None or uid not in self._allowed:
                self._telemetry.count("command_socket_rejected")
                self._telemetry.log(logging.WARNING, "command_socket_rejected", peer_uid=uid if uid is not None else -1)
                return
            await self._serve(reader, writer)
        except asyncio.CancelledError:
            pass
        finally:
            if task is not None:
                self._connections.discard(task)
            with contextlib.suppress(Exception):
                writer.close()

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while True:
            try:
                payload = await codec.read_frame(reader, self._max_request)
            except codec.FrameEof:
                return
            except codec.FrameError:
                self._telemetry.count("command_frames_rejected", reason="framing")
                return
            handling = asyncio.create_task(self._answer(payload))
            # While a command is handled the edge sends nothing. Anything that arrives is the edge going away.
            gone = asyncio.create_task(reader.read(1))
            done, _ = await asyncio.wait({handling, gone}, return_when=asyncio.FIRST_COMPLETED)
            if handling not in done:
                handling.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await handling
                self._telemetry.count("commands_abandoned")
                return
            gone.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await gone
            answer = handling.result()
            try:
                await codec.write_frame(
                    writer, codec.encode_answer(answer, COMMAND_INTERFACE_VERSION), self._max_answer
                )
            except (OSError, codec.FrameError):
                self._telemetry.count("command_answers_unwritten")
                return

    async def _answer(self, payload: bytes) -> Answer:
        try:
            request = codec.decode_request(payload)
        except codec.VersionRefused:
            self._telemetry.count("command_frames_rejected", reason="version")
            return _refusal(Code.UNSUPPORTED, "this core does not serve that version of the command interface")
        except codec.CodecError:
            self._telemetry.count("command_frames_rejected", reason="invalid")
            return _refusal(Code.INVALID_REQUEST, "the command is not valid for this version of the command interface")
        if isinstance(request, VerifyRequest):
            return await self._service.verify(request.credential, request.ctx)
        if isinstance(request, HandleRequest):
            return await self._service.handle(request.credential, request.ctx, request.command, request.idempotency_key)
        return await self._service.delivered(request.credential, request.ctx, request.delivery_token)


def _refusal(code: Code, message: str) -> ErrorAnswer:
    """A refusal of a frame that carried no usable request context."""
    return ErrorAnswer(
        error=ErrorBody(
            code=code.value,
            kind=Kind.REFUSED.value,
            retry=Retry.NEVER.value,
            message=message,
            request_id="req_" + "0" * 24,
        )
    )
