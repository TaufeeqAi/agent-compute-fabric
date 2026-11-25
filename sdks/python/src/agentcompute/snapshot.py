"""Snapshots: a saved state of a sandbox, to restore from.

A snapshot is taken with ``sandbox.snapshot()``. It restores into the sandbox it came from or into any
other (``sandbox.restore(snapshot)``, a new generation of that sandbox), or as a sandbox of its own
(``snapshot.restore_as_new()``).

A snapshot handle acts on the identifier and the generation of the snapshot it was built from. A name
is only ever used to find a snapshot, once.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from typing import TYPE_CHECKING, Any, Self

from agentcompute import _keys
from agentcompute._resources import Seed, find_snapshot, produced
from agentcompute._transport import Engine, Flow, Request, encode, identifier, segment
from agentcompute._units import seconds, text
from agentcompute.errors import UnexpectedResponseError
from agentcompute.types import SnapshotView

if TYPE_CHECKING:
    from agentcompute._binding import AsyncBinder, SyncBinder
    from agentcompute.sandbox import AsyncSandbox, Sandbox

__all__ = ["AsyncSnapshot", "AsyncSnapshots", "Snapshot", "Snapshots"]

_COLLECTION = "/snapshots"


class _SnapshotFlows(SnapshotView):
    """A snapshot handle without a way to run its flows: what the two clients share."""

    __slots__ = ("_engine", "operation")

    def __init__(self, engine: Engine, seed: Seed) -> None:
        super().__init__(seed.raw, request_id=seed.request_id)
        self._engine = engine
        #: The operation whose answer this view came from. ``None`` when the snapshot was found by listing.
        self.operation = seed.operation

    def _path(self) -> Flow[str]:
        return (yield from self._engine.project_path()) + f"{_COLLECTION}/{segment(self.snapshot_id)}"

    def _restore_as_new(
        self, name: str | None, lifetime: int | str | None, idempotency_key: str | None, follow_max: float | None
    ) -> Flow[Seed]:
        target: dict[str, Any] = {"kind": "new"}
        if name is not None:
            target["name"] = text(name, what="name")
        if lifetime is not None:
            target["lifetime_seconds"] = seconds(lifetime, what="lifetime")
        body = encode({"snapshot_generation": self.snapshot_generation, "target": target})
        key = _keys.for_call(idempotency_key)
        engine = self._engine
        within = engine.follow_bound(follow_max)
        path = (yield from self._path()) + "/restore"
        operation = yield from engine.operate(Request("POST", path, body=body, key=key), within=within)
        engine.settle(operation, key=key)
        return produced(engine, operation, "sandbox")

    def _delete(self, idempotency_key: str | None, follow_max: float | None) -> Flow[None]:
        key = _keys.for_call(idempotency_key)
        engine, snapshot_id = self._engine, self.snapshot_id
        within = engine.follow_bound(follow_max)
        query = (("snapshot_generation", str(self.snapshot_generation)),)
        path = yield from self._path()
        operation = yield from engine.operate(Request("DELETE", path, query=query, key=key), within=within)
        engine.settle(operation, key=key)
        seed = produced(engine, operation, "snapshot")
        if SnapshotView(seed.raw).snapshot_id != snapshot_id:
            raise UnexpectedResponseError(
                "the server answered with another snapshot than the one that was deleted",
                request_id=seed.request_id,
            )
        self.raw = seed.raw
        self.request_id = seed.request_id
        self.operation = seed.operation


class Snapshot(_SnapshotFlows):
    """A handle on one snapshot. Obtained from ``sandbox.snapshot()`` or ``fabric.snapshots``."""

    __slots__ = ("_binder",)

    def __init__(self, binder: SyncBinder, seed: Seed) -> None:
        super().__init__(binder.driver.engine, seed)
        self._binder = binder

    def restore_as_new(
        self,
        *,
        name: str | None = None,
        lifetime: int | str | None = None,
        idempotency_key: str | None = None,
        follow_max: float | None = None,
    ) -> Sandbox:
        """Restore the snapshot as a new sandbox, and return a handle on that sandbox."""
        flow = self._restore_as_new(name, lifetime, idempotency_key, follow_max)
        return self._binder.sandbox(self._binder.driver.run("snapshot.restore_as_new", flow))

    def delete(self, *, idempotency_key: str | None = None, follow_max: float | None = None) -> Self:
        """Delete the snapshot. It is never resurrected."""
        self._binder.driver.run("snapshot.delete", self._delete(idempotency_key, follow_max))
        return self


class AsyncSnapshot(_SnapshotFlows):
    """A handle on one snapshot. Obtained from ``sandbox.snapshot()`` or ``fabric.snapshots``."""

    __slots__ = ("_binder",)

    def __init__(self, binder: AsyncBinder, seed: Seed) -> None:
        super().__init__(binder.driver.engine, seed)
        self._binder = binder

    async def restore_as_new(
        self,
        *,
        name: str | None = None,
        lifetime: int | str | None = None,
        idempotency_key: str | None = None,
        follow_max: float | None = None,
    ) -> AsyncSandbox:
        """Restore the snapshot as a new sandbox, and return a handle on that sandbox."""
        flow = self._restore_as_new(name, lifetime, idempotency_key, follow_max)
        return self._binder.sandbox(await self._binder.driver.run("snapshot.restore_as_new", flow))

    async def delete(self, *, idempotency_key: str | None = None, follow_max: float | None = None) -> Self:
        """Delete the snapshot. It is never resurrected."""
        await self._binder.driver.run("snapshot.delete", self._delete(idempotency_key, follow_max))
        return self


def _get(engine: Engine, snapshot: str) -> Flow[Seed]:
    return (yield from find_snapshot(engine, identifier(snapshot, what="snapshot")))


class Snapshots:
    """``fabric.snapshots``."""

    __slots__ = ("_binder",)

    def __init__(self, binder: SyncBinder) -> None:
        self._binder = binder

    def get(self, snapshot: str) -> Snapshot:
        """Find one snapshot by its identifier or its name. ``NotFoundError`` if the project lists none."""
        driver = self._binder.driver
        return self._binder.snapshot(driver.run("snapshots.get", _get(driver.engine, snapshot)))

    def list(self) -> Iterator[Snapshot]:
        """Every snapshot of the project. The listing is read to its end before the first one is yielded."""
        driver = self._binder.driver
        for raw, request_id in driver.run("snapshots.list", driver.engine.collect(_COLLECTION)):
            yield self._binder.snapshot(Seed(raw, request_id))


class AsyncSnapshots:
    """``fabric.snapshots``."""

    __slots__ = ("_binder",)

    def __init__(self, binder: AsyncBinder) -> None:
        self._binder = binder

    async def get(self, snapshot: str) -> AsyncSnapshot:
        """Find one snapshot by its identifier or its name. ``NotFoundError`` if the project lists none."""
        driver = self._binder.driver
        return self._binder.snapshot(await driver.run("snapshots.get", _get(driver.engine, snapshot)))

    async def list(self) -> AsyncIterator[AsyncSnapshot]:
        """Every snapshot of the project. The listing is read to its end before the first one is yielded."""
        driver = self._binder.driver
        for raw, request_id in await driver.run("snapshots.list", driver.engine.collect(_COLLECTION)):
            yield self._binder.snapshot(Seed(raw, request_id))
