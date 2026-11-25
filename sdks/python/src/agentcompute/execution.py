"""Executions: one command, run in one generation of one sandbox, and its output.

An execution is started with ``sandbox.exec()``. What comes back is a handle on the execution as the
host reported it when the operation ended. A command that exits with a status other than 0 is a result,
not an error: ``status`` and ``exit_code`` say what the guest reported.

Output is read by stream and byte offset. It is what the command wrote, so it is data: the bytes are
returned as bytes, and they become text only with an encoding and an error policy the caller chose.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, Self

from agentcompute import _keys
from agentcompute._resources import Seed, cancel_execution, produced, read_execution
from agentcompute._transport import Engine, Flow, Request, identifier, segment
from agentcompute._units import whole
from agentcompute.errors import UnexpectedResponseError
from agentcompute.types import ExecutionView, OutputChunk

if TYPE_CHECKING:
    from agentcompute._binding import AsyncBinder, SyncBinder

__all__ = ["AsyncExecution", "AsyncExecutions", "Execution", "Executions"]

_STREAMS: Final = ("stdout", "stderr")


def _output_query(stream: str, offset: int, max_bytes: int | None) -> tuple[tuple[str, str], ...]:
    if stream not in _STREAMS:
        raise ValueError(f'stream must be "stdout" or "stderr", not {stream!r}')
    start = whole(offset)
    if start is None or start < 0:
        raise ValueError(f"offset must be a byte offset, zero or more, not {offset!r}")
    query = [("stream", stream), ("offset", str(start))]
    if max_bytes is not None:
        limit = whole(max_bytes)
        if limit is None or limit < 1:
            raise ValueError(f"max_bytes must be a positive integer, not {max_bytes!r}")
        query.append(("max_bytes", str(limit)))
    return tuple(query)


class _ExecutionFlows(ExecutionView):
    """An execution handle without a way to run its flows: what the two clients share."""

    __slots__ = ("_engine", "operation")

    def __init__(self, engine: Engine, seed: Seed) -> None:
        super().__init__(seed.raw, request_id=seed.request_id)
        self._engine = engine
        #: The operation whose answer this view came from: the one that ran the command, or a cancel.
        self.operation = seed.operation

    def _adopt(self, seed: Seed) -> None:
        if ExecutionView(seed.raw).execution_id != self.execution_id:
            raise UnexpectedResponseError(
                "the server answered with another execution than the one that was asked about",
                request_id=seed.request_id,
            )
        self.raw = seed.raw
        self.request_id = seed.request_id
        self.operation = seed.operation

    def _refresh(self) -> Flow[None]:
        self._adopt((yield from read_execution(self._engine, self.execution_id)))

    def _output(self, stream: str, offset: int, max_bytes: int | None) -> Flow[OutputChunk]:
        query = _output_query(stream, offset, max_bytes)
        project = yield from self._engine.project_path()
        path = f"{project}/executions/{segment(self.execution_id)}/output"
        answer = yield from self._engine.perform(Request("GET", path, query=query))
        return OutputChunk(answer.body, request_id=answer.request_id)

    def _read(self, stream: str) -> Flow[bytes]:
        collected = bytearray()
        offset = 0
        while True:
            chunk = yield from self._output(stream, offset, None)
            collected += chunk.data
            if chunk.eof:
                return bytes(collected)
            if chunk.next_offset <= offset:
                # A chunk that is not the last and does not advance would be asked for again and again.
                raise UnexpectedResponseError(
                    "the server answered an output chunk that neither ends the stream nor advances in it",
                    request_id=chunk.request_id,
                )
            offset = chunk.next_offset

    def _cancel(self, idempotency_key: str | None, follow_max: float | None) -> Flow[None]:
        key = _keys.for_call(idempotency_key)
        within = self._engine.follow_bound(follow_max)
        operation = yield from cancel_execution(self._engine, self.execution_id, key=key, within=within)
        self._adopt(produced(self._engine, operation, "execution"))


class Execution(_ExecutionFlows):
    """A handle on one execution. From ``sandbox.exec()``, ``fabric.executions.get()`` or ``.handle()``."""

    __slots__ = ("_binder",)

    def __init__(self, binder: SyncBinder, seed: Seed) -> None:
        super().__init__(binder.driver.engine, seed)
        self._binder = binder

    def output(self, stream: str = "stdout", *, offset: int = 0, max_bytes: int | None = None) -> OutputChunk:
        """One slice of a stream. ``data`` holds its bytes, ``next_offset`` and ``eof`` say how to go on."""
        return self._binder.driver.run("execution.output", self._output(stream, offset, max_bytes))

    def read(self, stream: str = "stdout") -> bytes:
        """Every stored byte of a stream, chunk after chunk to its end."""
        return self._binder.driver.run("execution.read", self._read(stream))

    def text(self, stream: str = "stdout", *, encoding: str = "utf-8", errors: str = "strict") -> str:
        """The stream as text. Output is guest data: the encoding and the error policy are the caller's choice."""
        return self.read(stream).decode(encoding, errors)

    def cancel(self, *, idempotency_key: str | None = None, follow_max: float | None = None) -> Self:
        """Cancel the execution on the host. Nothing else ends a command early: no timeout of this client does."""
        self._binder.driver.run("execution.cancel", self._cancel(idempotency_key, follow_max))
        return self

    def refresh(self) -> Self:
        """Read the execution again and update this handle."""
        self._binder.driver.run("execution.refresh", self._refresh())
        return self


class AsyncExecution(_ExecutionFlows):
    """A handle on one execution. From ``sandbox.exec()``, ``fabric.executions.get()`` or ``.handle()``."""

    __slots__ = ("_binder",)

    def __init__(self, binder: AsyncBinder, seed: Seed) -> None:
        super().__init__(binder.driver.engine, seed)
        self._binder = binder

    async def output(self, stream: str = "stdout", *, offset: int = 0, max_bytes: int | None = None) -> OutputChunk:
        """One slice of a stream. ``data`` holds its bytes, ``next_offset`` and ``eof`` say how to go on."""
        return await self._binder.driver.run("execution.output", self._output(stream, offset, max_bytes))

    async def read(self, stream: str = "stdout") -> bytes:
        """Every stored byte of a stream, chunk after chunk to its end."""
        return await self._binder.driver.run("execution.read", self._read(stream))

    async def text(self, stream: str = "stdout", *, encoding: str = "utf-8", errors: str = "strict") -> str:
        """The stream as text. Output is guest data: the encoding and the error policy are the caller's choice."""
        return (await self.read(stream)).decode(encoding, errors)

    async def cancel(self, *, idempotency_key: str | None = None, follow_max: float | None = None) -> Self:
        """Cancel the execution on the host. Nothing else ends a command early: no timeout of this client does."""
        await self._binder.driver.run("execution.cancel", self._cancel(idempotency_key, follow_max))
        return self

    async def refresh(self) -> Self:
        """Read the execution again and update this handle."""
        await self._binder.driver.run("execution.refresh", self._refresh())
        return self


def _get(engine: Engine, execution_id: str) -> Flow[Seed]:
    return (yield from read_execution(engine, identifier(execution_id, what="execution_id")))


def _unread(execution_id: str) -> Seed:
    return Seed({"execution_id": identifier(execution_id, what="execution_id")}, None)


class Executions:
    """``fabric.executions``."""

    __slots__ = ("_binder",)

    def __init__(self, binder: SyncBinder) -> None:
        self._binder = binder

    def get(self, execution_id: str) -> Execution:
        """Read the status and result of an execution."""
        driver = self._binder.driver
        return self._binder.execution(driver.run("executions.get", _get(driver.engine, execution_id)))

    def handle(self, execution_id: str) -> Execution:
        """A handle on an execution that was not read: no request is made.

        Its view holds the identifier and nothing else until ``cancel()`` or ``refresh()``. It is the way to
        cancel an execution, or to read its output, by an identifier that is already known. A cancel takes
        a privilege away: it is sent at once, and never waits behind a read that a limit could refuse.
        """
        return self._binder.execution(_unread(execution_id))


class AsyncExecutions:
    """``fabric.executions``."""

    __slots__ = ("_binder",)

    def __init__(self, binder: AsyncBinder) -> None:
        self._binder = binder

    async def get(self, execution_id: str) -> AsyncExecution:
        """Read the status and result of an execution."""
        driver = self._binder.driver
        return self._binder.execution(await driver.run("executions.get", _get(driver.engine, execution_id)))

    def handle(self, execution_id: str) -> AsyncExecution:
        """A handle on an execution that was not read: no request is made.

        Its view holds the identifier and nothing else until ``cancel()`` or ``refresh()``. It is the way to
        cancel an execution, or to read its output, by an identifier that is already known. A cancel takes
        a privilege away: it is sent at once, and never waits behind a read that a limit could refuse.
        """
        return self._binder.execution(_unread(execution_id))
