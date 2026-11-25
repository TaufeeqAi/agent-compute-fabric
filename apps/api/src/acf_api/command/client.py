"""The edge's side of the command interface.

An edge process holds nothing: no host credential, no store, no key but its TLS key. Everything it
knows about a request it learned from the caller, and everything it answers it was told by the core
through this client.

One rule here matters more than the rest. When the core's answer to a mutating command does not
arrive, the edge cannot tell whether the core accepted the command. It then answers
``OUTCOME_UNRESOLVED`` and never ``REFUSED``: the caller asks again with the same idempotency key, and
the core's ledger resolves it. Only a command that provably never left this process is answered as a
refusal.
"""

from __future__ import annotations

import asyncio
import contextlib
import secrets
import string
from collections import deque
from typing import Final, Protocol

from acf_api.command import codec
from acf_api.command.answers import (
    COMMAND_INTERFACE_VERSION,
    Answer,
    DeliveredRequest,
    ErrorAnswer,
    HandleRequest,
    Request,
    RequestContext,
    VerifyRequest,
)
from acf_api.command.commands import CallTool, Command
from acf_api.command.errors import Code, Kind, Retry
from acf_api.command.model import ErrorBody
from acf_api.command.surface import BY_TOOL, OperationClass, containment_commands, mutating_commands

_ALPHABET: Final = string.ascii_letters + string.digits
_REQUEST_ID_LEN: Final = 24
#: How long a caller should wait before it asks again after a transport-level answer of the edge.
_RETRY_AFTER_S: Final = 1
#: Slack beyond a command's budget before the edge stops waiting for the core.
_ANSWER_GRACE_S: Final = 0.5
_MAX_IDLE_CONNECTIONS: Final = 32

_MUTATING: Final = mutating_commands() | {"mint_agent_credential", "revoke_agent_credential"}
_CONTAINMENT: Final = containment_commands()


def new_request_id() -> str:
    """A request id: random, and inside the host's syntax for the correlation label it becomes."""
    return "req_" + "".join(secrets.choice(_ALPHABET) for _ in range(_REQUEST_ID_LEN))


def is_containment(command: Command) -> bool:
    """Whether the edge counts a command against the share of its bound that is kept for containment."""
    if isinstance(command, CallTool):
        op = BY_TOOL.get(command.name)
        return op is not None and op.operation_class is OperationClass.CONTAINMENT
    return command.type in _CONTAINMENT


def may_create_work(command: Command) -> bool:
    """Whether a lost answer to this command leaves a doubt about something having been created."""
    if isinstance(command, CallTool):
        op = BY_TOOL.get(command.name)
        # An unknown tool is a protocol fault in the core and creates nothing; a doubt is still the safe reading.
        return op is None or op.operation_class in {OperationClass.GRANTING, OperationClass.CONTAINMENT}
    return command.type in _MUTATING


def _error(
    code: Code, kind: Kind, retry: Retry, message: str, ctx: RequestContext, key: str | None = None
) -> ErrorAnswer:
    return ErrorAnswer(
        error=ErrorBody(
            code=code.value,
            kind=kind.value,
            retry=retry.value,
            message=message,
            request_id=ctx.request_id,
            idempotency_key=key,
        ),
        retry_after_s=_RETRY_AFTER_S,
    )


def unavailable(ctx: RequestContext, message: str) -> ErrorAnswer:
    """Nothing left the edge: a refusal the caller may repeat later."""
    return _error(Code.UPSTREAM_UNAVAILABLE, Kind.REFUSED, Retry.SAME_REQUEST_LATER, message, ctx)


def unresolved(ctx: RequestContext, key: str | None) -> ErrorAnswer:
    """The command left the edge and no answer came back."""
    return _error(
        Code.OUTCOME_UNRESOLVED,
        Kind.UNRESOLVED,
        Retry.SAME_REQUEST_LATER,
        "the platform could not establish whether the request was accepted; ask again with the same idempotency key",
        ctx,
        key,
    )


def overloaded(ctx: RequestContext) -> ErrorAnswer:
    return _error(
        Code.RATE_LIMITED,
        Kind.REFUSED,
        Retry.SAME_REQUEST_LATER,
        "this endpoint has too many requests in flight; nothing was sent",
        ctx,
    )


class CoreClient(Protocol):
    """What an adapter may ask of the core."""

    async def verify(self, credential: str | None, ctx: RequestContext) -> Answer: ...

    async def handle(
        self, credential: str | None, ctx: RequestContext, command: Command, idempotency_key: str | None = None
    ) -> Answer: ...

    async def delivered(self, credential: str | None, ctx: RequestContext, delivery_token: str) -> None: ...

    async def aclose(self) -> None: ...


class _NotSent(Exception):
    """The request frame was not handed to the socket: the core cannot have acted on it."""


class _NoAnswer(Exception):
    """The request frame was handed to the socket and no usable answer came back."""


class SocketCoreClient:
    """The command interface over the core's local socket.

    A connection carries one exchange at a time. Idle connections are kept and reused; a connection is
    discarded on its first failure and never reused after one, so that a late answer is never read as
    the answer to a later command.
    """

    def __init__(
        self,
        socket_path: str,
        *,
        max_in_flight: int = 256,
        connect_timeout_s: float = 2.0,
        max_request_frame: int = codec.DEFAULT_MAX_REQUEST_FRAME,
        max_answer_frame: int = codec.DEFAULT_MAX_ANSWER_FRAME,
    ) -> None:
        if max_in_flight < 2:  # noqa: PLR2004 - one slot for containment and at least one for the rest
            msg = "max_in_flight must be at least 2"
            raise ValueError(msg)
        self._path = socket_path
        self._max_in_flight = max_in_flight
        # A tenth of the bound, and at least one slot, is kept for containment commands.
        self._general_limit = max_in_flight - max(1, max_in_flight // 10)
        self._in_flight = 0
        self._in_flight_general = 0
        self._connect_timeout_s = connect_timeout_s
        self._max_request_frame = max_request_frame
        self._max_answer_frame = max_answer_frame
        self._idle: deque[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = deque()
        self._closed = False

    # ------------------------------------------------------------------ bounds
    def _admit(self, *, containment: bool) -> bool:
        if self._in_flight >= self._max_in_flight:
            return False
        if not containment and self._in_flight_general >= self._general_limit:
            return False
        self._in_flight += 1
        if not containment:
            self._in_flight_general += 1
        return True

    def _release(self, *, containment: bool) -> None:
        self._in_flight -= 1
        if not containment:
            self._in_flight_general -= 1

    @property
    def in_flight(self) -> int:
        return self._in_flight

    # ------------------------------------------------------------------ connections
    async def _connection(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        while self._idle:
            reader, writer = self._idle.pop()
            if not writer.is_closing() and not reader.at_eof():
                return reader, writer
            _discard(writer)
        try:
            return await asyncio.wait_for(asyncio.open_unix_connection(self._path), self._connect_timeout_s)
        except (OSError, TimeoutError) as e:
            raise _NotSent from e

    def _keep(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self._closed or len(self._idle) >= _MAX_IDLE_CONNECTIONS or writer.is_closing():
            _discard(writer)
        else:
            self._idle.append((reader, writer))

    async def _exchange(self, request: Request, wait_s: float) -> Answer:
        try:
            frame = codec.encode_frame(codec.encode_request(request), self._max_request_frame)
        except codec.FrameTooLarge as e:
            raise _NotSent from e
        reader, writer = await self._connection()
        # From here on the frame may reach the core. Any failure is a lost answer, never "not sent".
        try:
            writer.write(frame)
            await writer.drain()
            payload = await asyncio.wait_for(codec.read_frame(reader, self._max_answer_frame), wait_s)
            answer = codec.decode_answer(payload)
        except (OSError, TimeoutError, codec.FrameError, codec.CodecError) as e:
            _discard(writer)
            raise _NoAnswer from e
        except BaseException:
            # Cancelled: the caller went away. The connection may still receive the answer, so it is not reused.
            _discard(writer)
            raise
        self._keep(reader, writer)
        return answer

    # ------------------------------------------------------------------ the three calls
    async def verify(self, credential: str | None, ctx: RequestContext) -> Answer:
        request = VerifyRequest(version=COMMAND_INTERFACE_VERSION, credential=credential, ctx=ctx)
        if not self._admit(containment=True):
            return overloaded(ctx)
        try:
            return await self._exchange(request, ctx.budget_ms / 1000 + _ANSWER_GRACE_S)
        except (_NotSent, _NoAnswer):
            # A credential check changes nothing, so a lost answer to it is a plain refusal.
            return unavailable(ctx, "the platform could not verify the credential; nothing was done")
        finally:
            self._release(containment=True)

    async def handle(
        self, credential: str | None, ctx: RequestContext, command: Command, idempotency_key: str | None = None
    ) -> Answer:
        containment = is_containment(command)
        if not self._admit(containment=containment):
            return overloaded(ctx)
        try:
            request = HandleRequest(
                version=COMMAND_INTERFACE_VERSION,
                credential=credential,
                ctx=ctx,
                idempotency_key=idempotency_key,
                command=command,
            )
            return await self._exchange(request, ctx.budget_ms / 1000 + _ANSWER_GRACE_S)
        except _NotSent:
            return unavailable(ctx, "the platform's core could not be reached; nothing was sent")
        except _NoAnswer:
            if may_create_work(command):
                return unresolved(ctx, idempotency_key)
            return unavailable(ctx, "the platform's core did not answer; the read can be repeated")
        finally:
            self._release(containment=containment)

    async def delivered(self, credential: str | None, ctx: RequestContext, delivery_token: str) -> None:
        """Report a result as written in full. Best effort: an unreported delivery only widens adoption."""
        request = DeliveredRequest(
            version=COMMAND_INTERFACE_VERSION, credential=credential, ctx=ctx, delivery_token=delivery_token
        )
        if not self._admit(containment=True):
            return
        try:
            await self._exchange(request, ctx.budget_ms / 1000 + _ANSWER_GRACE_S)
        except (_NotSent, _NoAnswer):
            return
        finally:
            self._release(containment=True)

    async def aclose(self) -> None:
        self._closed = True
        while self._idle:
            _, writer = self._idle.pop()
            _discard(writer)
        await asyncio.sleep(0)


def _discard(writer: asyncio.StreamWriter) -> None:
    with contextlib.suppress(Exception):
        writer.close()
