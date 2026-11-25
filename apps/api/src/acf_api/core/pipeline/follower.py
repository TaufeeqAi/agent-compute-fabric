"""The follower: one poll of the host per operation, for every caller that waits on it.

A caller's wait is never served by a host connection that stays open for it. For each operation that
at least one caller is waiting on, the core polls the host at most once per
``follow_poll_interval_min``, backing off to ``follow_poll_interval_max``, whatever the number of
waiters. A wait therefore costs the host reads per operation, not per caller.

Every waiter is answered from one read, and that read was started after the waiter arrived: a waiter
is never given a state that is older than its own request.

The pace belongs to the operation, not to the callers who happen to wait on it. When the last waiter
leaves, the time before which the operation may not be polled again is kept; a caller who arrives a
moment later waits for that time and is not answered by a poll of its own. Without this, callers
arriving one after the other on an operation that has ended would each cause a read, which is the cost
per caller that the follower exists to avoid.

The follower's reads come out of the reserve of the host's allowance. When more operations are
followed than the reserve allows, each is polled less often, and a wait then ends at its bound with an
answer in which the operation has not ended. That is always a correct answer.

Following never changes anything on the host. Abandoning a wait (a timeout, a disconnect, a cancelled
task) cancels nothing.

The cadence is scheduled on the event loop's own clock, because it is a matter of pacing and not of
recorded time.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field
from typing import Final

from acf_api.core.host.binding import HostBinding, Lane
from acf_api.core.host.wire import HostOperation, HostRefusal, HostRequest, HostResult, Unreachable
from acf_api.core.pipeline.limits import TokenBucket
from acf_api.core.telemetry import Telemetry

Followed = HostOperation | HostRefusal

#: Operations whose pace is remembered after their last waiter left. Past this number the expired ones
#: are dropped, and if that is not enough all of them: losing a pace allows one read too early for an
#: operation, and the follower's share of the host's allowance still bounds the total.
_MAX_RESTED: Final = 10_000


@dataclass(slots=True)
class _Waiter:
    arrival: int
    future: asyncio.Future[Followed]


@dataclass(slots=True)
class _Operation:
    #: When the next poll of this operation may start, on the event loop's clock.
    next_poll_at: float
    #: When the last poll started. ``None``: none has, for these waiters.
    last_poll_at: float | None = None
    waiters: list[_Waiter] = field(default_factory=list)
    task: asyncio.Task[None] | None = None
    #: The last answer read, and the arrival counter when that read started.
    latest: Followed | None = None
    latest_started: int = 0


class Follower:
    def __init__(
        self,
        binding: HostBinding,
        telemetry: Telemetry,
        *,
        interval_min_s: float,
        interval_max_s: float,
        reads_per_minute: float,
    ) -> None:
        self._binding = binding
        self._telemetry = telemetry
        self._min = interval_min_s
        self._max = interval_max_s
        self._reads_per_minute = reads_per_minute
        self._budget: TokenBucket | None = None
        self._operations: dict[tuple[str, str], _Operation] = {}
        #: For an operation nobody waits on any more: the time before which it may not be polled again.
        self._rested: dict[tuple[str, str], float] = {}
        self._arrivals = 0

    def followed(self) -> int:
        return len(self._operations)

    def following(self, owner_scope: str, operation_id: str) -> bool:
        """Whether somebody waits on the operation now. One more waiter then costs the host nothing."""
        return (owner_scope, operation_id) in self._operations

    def waiters(self) -> int:
        return sum(len(op.waiters) for op in self._operations.values())

    async def wait(
        self, owner_scope: str, operation_id: str, timeout_s: float, request_id: str, *, fresh: bool = False
    ) -> Followed | None:
        """Wait until the operation has ended, or ``timeout_s`` passes.

        Returns the ended operation, or a refusal of the read (the host no longer holds it). At the
        bound: the last state read *after this call arrived*, or ``None`` when no such read was made.

        ``fresh``: the caller has just received the operation's state from the host, so the first poll
        waits a full interval. Otherwise the first poll starts at once, unless the operation was polled
        less than an interval ago for callers who have left: then it starts when that interval is over.
        """
        if timeout_s <= 0:
            return None
        loop = asyncio.get_running_loop()
        self._arrivals += 1
        waiter = _Waiter(self._arrivals, loop.create_future())
        key = (owner_scope, operation_id)
        op = self._operations.get(key)
        if op is None:
            earliest = loop.time() + (self._min if fresh else 0.0)
            op = self._operations[key] = _Operation(next_poll_at=max(earliest, self._rested.pop(key, 0.0)))
        op.waiters.append(waiter)
        if op.task is None:
            op.task = asyncio.create_task(self._poll(key, op, request_id), name="acf-follow")
        try:
            return await asyncio.wait_for(asyncio.shield(waiter.future), timeout_s)
        except TimeoutError:
            return op.latest if op.latest is not None and op.latest_started >= waiter.arrival else None
        finally:
            with contextlib.suppress(ValueError):
                op.waiters.remove(waiter)
            if not waiter.future.done():
                waiter.future.cancel()
            if not op.waiters:
                if op.task is not None:
                    op.task.cancel()
                # Compared by identity: a later caller may already wait on a record of its own under this key.
                if self._operations.get(key) is op:
                    del self._operations[key]
                    self._rest(key, op, loop.time())

    def _rest(self, key: tuple[str, str], op: _Operation, now: float) -> None:
        """Keep the pace of an operation whose last waiter has left: one poll per shortest interval."""
        if op.last_poll_at is not None and op.last_poll_at + self._min > now:
            self._rested[key] = op.last_poll_at + self._min
        if len(self._rested) > _MAX_RESTED:
            self._rested = {k: at for k, at in self._rested.items() if at > now}
            if len(self._rested) > _MAX_RESTED:
                self._telemetry.count("follower_paces_dropped", len(self._rested))
                self._rested.clear()

    async def _poll(self, key: tuple[str, str], op: _Operation, request_id: str) -> None:
        owner_scope, operation_id = key
        loop = asyncio.get_running_loop()
        if self._budget is None:
            self._budget = TokenBucket(self._reads_per_minute, loop.time())
        interval = self._min
        while op.waiters:
            pause = op.next_poll_at - loop.time()
            if pause > 0:
                await asyncio.sleep(pause)
            delay = self._budget.peek(loop.time())
            if delay > 0:
                # The reserve is spent: this operation is polled less often.
                self._telemetry.count("follower_polls_deferred")
                op.next_poll_at = loop.time() + min(delay, self._max)
                continue
            self._budget.take(loop.time())
            started = self._arrivals
            op.last_poll_at = loop.time()
            op.next_poll_at = op.last_poll_at + interval
            interval = min(interval * 2, self._max)
            request = HostRequest(
                method="operation.get",
                owner_scope=owner_scope,
                params={"operation_id": operation_id},
                request_id=request_id,
            )
            try:
                answer = await self._binding.read(request, lane=Lane.RESOLUTION)
            except Unreachable:
                self._telemetry.count("follower_polls", outcome="unreachable")
                continue
            self._telemetry.count("follower_polls", outcome="answered")
            result: Followed
            if isinstance(answer, HostResult):
                if answer.type != "operation" or not isinstance(answer.data, dict):
                    continue
                result = HostOperation(answer.data, answer.as_of)
                op.latest, op.latest_started = result, started
                if not result.terminal:
                    continue
            else:
                result = answer
                op.latest, op.latest_started = result, started
            for waiter in list(op.waiters):
                if waiter.arrival <= started and not waiter.future.done():
                    waiter.future.set_result(result)

    async def aclose(self) -> None:
        for op in list(self._operations.values()):
            if op.task is not None:
                op.task.cancel()
        self._operations.clear()
        self._rested.clear()
        await asyncio.sleep(0)
