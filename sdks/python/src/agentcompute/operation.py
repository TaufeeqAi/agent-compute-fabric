"""Operations: every mutation is one, and any of them can be read or followed by its identifier.

The convenience calls (``sandboxes.create``, ``sandbox.exec``, ...) follow their own operation and turn
its outcome into a result or an error. This module is for everything else: looking at an operation
again, following one that was still running when a call gave up, and resolving what a process that
died left behind.

Nothing here judges an outcome. ``get`` and ``wait`` return the operation as the server shows it, in
whatever state, and the caller reads ``state``, ``effect`` and ``failure``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from typing import TYPE_CHECKING, Final

from agentcompute._transport import Engine, Flow, Request, identifier, segment
from agentcompute._units import whole
from agentcompute.types import Operation

if TYPE_CHECKING:
    from agentcompute._binding import AsyncBinder, SyncBinder

__all__ = ["AsyncOperations", "Operation", "Operations"]

_COLLECTION: Final = "/operations"


def _get(engine: Engine, operation_id: str, wait: int | None) -> Flow[Operation]:
    wanted = identifier(operation_id, what="operation_id")
    query: tuple[tuple[str, str], ...] = ()
    if wait is not None:
        patience = whole(wait)
        if patience is None or patience < 0:
            raise ValueError(f"wait must be a whole number of seconds, zero or more, not {wait!r}")
        query = (("wait", str(patience)),)
    path = (yield from engine.project_path()) + f"{_COLLECTION}/{segment(wanted)}"
    answer = yield from engine.perform(Request("GET", path, query=query))
    return Operation(answer.body, request_id=answer.request_id)


def _wait(engine: Engine, operation_id: str, follow_max: float | None) -> Flow[Operation]:
    wanted = identifier(operation_id, what="operation_id")
    return (yield from engine.watch(wanted, within=engine.follow_bound(follow_max)))


class Operations:
    """``fabric.operations``."""

    __slots__ = ("_binder",)

    def __init__(self, binder: SyncBinder) -> None:
        self._binder = binder

    def get(self, operation_id: str, *, wait: int | None = None) -> Operation:
        """Read an operation as it is now, or let the server wait up to ``wait`` seconds for it to end."""
        driver = self._binder.driver
        return driver.run("operations.get", _get(driver.engine, operation_id, wait))

    def list(self) -> Iterator[Operation]:
        """Every operation of the project. The listing is read to its end before the first one is yielded."""
        driver = self._binder.driver
        for raw, request_id in driver.run("operations.list", driver.engine.collect(_COLLECTION)):
            yield Operation(raw, request_id=request_id)

    def wait(self, operation_id: str, *, follow_max: float | None = None) -> Operation:
        """Follow an operation until it has ended, and return it whatever its outcome.

        An operation that ended ``FAILED``, ``CANCELLED`` or ``UNKNOWN`` is returned, not raised: the
        caller asked to see how it ended. ``OperationStillRunningError`` is raised at the follow bound.
        """
        driver = self._binder.driver
        return driver.run("operations.wait", _wait(driver.engine, operation_id, follow_max))


class AsyncOperations:
    """``fabric.operations``."""

    __slots__ = ("_binder",)

    def __init__(self, binder: AsyncBinder) -> None:
        self._binder = binder

    async def get(self, operation_id: str, *, wait: int | None = None) -> Operation:
        """Read an operation as it is now, or let the server wait up to ``wait`` seconds for it to end."""
        driver = self._binder.driver
        return await driver.run("operations.get", _get(driver.engine, operation_id, wait))

    async def list(self) -> AsyncIterator[Operation]:
        """Every operation of the project. The listing is read to its end before the first one is yielded."""
        driver = self._binder.driver
        for raw, request_id in await driver.run("operations.list", driver.engine.collect(_COLLECTION)):
            yield Operation(raw, request_id=request_id)

    async def wait(self, operation_id: str, *, follow_max: float | None = None) -> Operation:
        """Follow an operation until it has ended, and return it whatever its outcome.

        An operation that ended ``FAILED``, ``CANCELLED`` or ``UNKNOWN`` is returned, not raised: the
        caller asked to see how it ended. ``OperationStillRunningError`` is raised at the follow bound.
        """
        driver = self._binder.driver
        return await driver.run("operations.wait", _wait(driver.engine, operation_id, follow_max))
