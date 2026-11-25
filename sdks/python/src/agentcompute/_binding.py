"""How a handle gets to its client: the driver that runs its flows, and the handles it may hand out.

A mutation of one kind of resource can return another kind: a sandbox takes a snapshot, a snapshot
restores as a sandbox, a sandbox runs an execution. Each handle therefore holds a binder, which knows
every handle class of its client, instead of each handle module importing the others.
"""

from __future__ import annotations

from agentcompute._resources import Seed
from agentcompute._transport import AsyncDriver, SyncDriver
from agentcompute.execution import AsyncExecution, Execution
from agentcompute.sandbox import AsyncSandbox, Sandbox
from agentcompute.snapshot import AsyncSnapshot, Snapshot

__all__ = ["AsyncBinder", "SyncBinder"]


class SyncBinder:
    """The handles of a synchronous client."""

    __slots__ = ("driver",)

    def __init__(self, driver: SyncDriver) -> None:
        self.driver = driver

    def sandbox(self, seed: Seed, *, resolved_name: str | None = None) -> Sandbox:
        return Sandbox(self, seed, resolved_name=resolved_name)

    def snapshot(self, seed: Seed) -> Snapshot:
        return Snapshot(self, seed)

    def execution(self, seed: Seed) -> Execution:
        return Execution(self, seed)


class AsyncBinder:
    """The handles of an asynchronous client."""

    __slots__ = ("driver",)

    def __init__(self, driver: AsyncDriver) -> None:
        self.driver = driver

    def sandbox(self, seed: Seed, *, resolved_name: str | None = None) -> AsyncSandbox:
        return AsyncSandbox(self, seed, resolved_name=resolved_name)

    def snapshot(self, seed: Seed) -> AsyncSnapshot:
        return AsyncSnapshot(self, seed)

    def execution(self, seed: Seed) -> AsyncExecution:
        return AsyncExecution(self, seed)
