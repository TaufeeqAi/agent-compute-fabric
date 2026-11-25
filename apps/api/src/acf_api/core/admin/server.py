"""The admin socket: where an operator's commands reach the running core.

Only one process opens the store, the core. An operator therefore does not edit the store; the
operator's tool connects to this socket and the core carries the command out. The socket is owned by
the core's identity with mode 0600, and the kernel-reported identity of the peer is checked as well:
only the core's own identity and root are admitted. No public interface leads here.

The protocol is one JSON line in and one JSON line out per connection.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
from pathlib import Path
from typing import Any, Final

from acf_api.core.admin.commands import Admin, AdminError
from acf_api.core.server import bind_private_socket, close_listener, peer_uid
from acf_api.core.store.engine import StoreError
from acf_api.core.store.journal import JournalError
from acf_api.core.telemetry import Telemetry

_MAX_LINE: Final = 1024 * 1024
_TIMEOUT_S: Final = 120.0


class AdminServer:
    def __init__(self, admin: Admin, path: Path, telemetry: Telemetry) -> None:
        self._admin = admin
        self._path = path
        self._telemetry = telemetry
        self._server: asyncio.Server | None = None
        #: Connections that have not sent their request yet. A stop ends these and waits for the others:
        #: a command that is being carried out finishes, and a silent connection holds nothing up.
        self._waiting: set[asyncio.Task[None]] = set()

    async def start(self) -> None:
        sock = await bind_private_socket(self._path, mode=0o600, gid=None)
        self._server = await asyncio.start_unix_server(self._accept, sock=sock, limit=_MAX_LINE)

    async def close(self) -> None:
        server, self._server = self._server, None
        await close_listener(server, self._waiting, self._path)

    async def _read_request(self, reader: asyncio.StreamReader) -> bytes:
        task = asyncio.current_task()
        if task is not None:
            self._waiting.add(task)
        try:
            return await asyncio.wait_for(reader.readline(), _TIMEOUT_S)
        finally:
            if task is not None:
                self._waiting.discard(task)

    async def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            uid = peer_uid(writer)
            if uid is None or uid not in {0, os.geteuid()}:
                self._telemetry.log(logging.WARNING, "admin_socket_rejected", peer_uid=uid if uid is not None else -1)
                return
            try:
                line = await self._read_request(reader)
                request = json.loads(line)
                op, args = request["op"], request.get("args") or {}
                if not isinstance(op, str) or not isinstance(args, dict):
                    raise TypeError
            except (ValueError, KeyError, TypeError, TimeoutError, asyncio.LimitOverrunError):
                answer: dict[str, Any] = {"ok": False, "error": "the request is not one JSON line with `op` and `args`"}
            else:
                answer = await self._run(op, args)
            writer.write(json.dumps(answer, separators=(",", ":"), default=str).encode("utf-8") + b"\n")
            await writer.drain()
        except (OSError, asyncio.CancelledError):
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    async def _run(self, op: str, args: dict[str, Any]) -> dict[str, Any]:
        try:
            return {"ok": True, "result": await self._admin.run(op, args)}
        except AdminError as e:
            return {"ok": False, "error": str(e)}
        except (StoreError, JournalError) as e:
            return {"ok": False, "error": f"the store or the journal could not be written: {e}"}
        except Exception as e:  # reported to the operator, never to a public caller
            self._telemetry.count("admin_errors")
            return {"ok": False, "error": f"the command failed: {type(e).__name__}"}


async def call(path: Path, op: str, args: dict[str, Any], *, timeout_s: float = _TIMEOUT_S) -> Any:  # noqa: ANN401 - any JSON value: the result of the command
    """Send one admin command to a running core and return its result."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_unix_connection(str(path), limit=_MAX_LINE * 16), 5.0)
    except (OSError, TimeoutError) as e:
        raise AdminError(f"no core answers on {path}: is it running, and are you its user or root?") from e
    try:
        writer.write(json.dumps({"op": op, "args": args}, separators=(",", ":")).encode("utf-8") + b"\n")
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout_s)
    except (OSError, TimeoutError) as e:
        raise AdminError("the core did not answer the admin command") from e
    finally:
        with contextlib.suppress(Exception):
            writer.close()
    if not line:
        raise AdminError("the core closed the admin connection; this user is not admitted on the admin socket")
    answer = json.loads(line)
    if not answer.get("ok"):
        raise AdminError(str(answer.get("error", "the command failed")))
    return answer.get("result")
