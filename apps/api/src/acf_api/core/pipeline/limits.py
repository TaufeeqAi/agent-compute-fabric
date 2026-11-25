"""Bounds per principal and per project: request rate, requests in flight, and the shares of the host's allowance.

All of it is state in the memory of the one core, so every bound holds for the deployment whatever the
number of edge processes. Losing it (a restart) can loosen a platform limit briefly; it never loosens a
limit of the host.

What is bounded here is granting work and reads. Containment and the resolution of an earlier request
are exempt: they never come through this module.

The total rate of granting work and of host reads that the platform causes stays inside the host's
allowance for one peer, less a reserve kept for containment, resolution and the follower. Within it a
project may use at most its share. A share is a ceiling, not a reservation: a project that reaches its
share is refused while other projects are unaffected, and no single project can take the whole.
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass
from typing import Final

from acf_api.core.clock import Clock

_MINUTE: Final = 60.0
_MAX_TRACKED: Final = 50_000


class TokenBucket:
    """A rate per minute with a burst of a tenth of a minute's worth, at least one."""

    __slots__ = ("_at", "_burst", "_rate", "_tokens")

    def __init__(self, per_minute: float, now: float) -> None:
        self._rate = max(per_minute, 0.0) / _MINUTE
        self._burst = max(1.0, per_minute / 10.0)
        self._tokens = self._burst
        self._at = now

    def _refill(self, now: float) -> None:
        if now > self._at:
            self._tokens = min(self._burst, self._tokens + (now - self._at) * self._rate)
            self._at = now

    def peek(self, now: float) -> float:
        """Seconds until one token is available. 0: one is available now."""
        self._refill(now)
        if self._tokens >= 1.0:
            return 0.0
        return math.inf if self._rate <= 0 else (1.0 - self._tokens) / self._rate

    def take(self, now: float) -> None:
        self._refill(now)
        self._tokens -= 1.0

    def idle(self, now: float) -> bool:
        self._refill(now)
        return self._tokens >= self._burst


@dataclass(frozen=True, slots=True)
class Refused:
    """A bound was reached. ``retry_after_s``: when asking again can succeed."""

    bound: str
    retry_after_s: int


class RateLimiter:
    """Rates for one kind of traffic: a total, a ceiling per project and a ceiling per principal."""

    def __init__(
        self, clock: Clock, *, total_per_minute: float, project_per_minute: float, principal_per_minute: float
    ) -> None:
        self._clock = clock
        self._total = TokenBucket(total_per_minute, clock.monotonic())
        self._project_rate = project_per_minute
        self._principal_rate = principal_per_minute
        self._projects: dict[str, TokenBucket] = {}
        self._principals: dict[tuple[str, str], TokenBucket] = {}
        self._shares: dict[str, float] = {}

    def set_project_rate(self, project_id: str, per_minute: float) -> None:
        """An operator's share for one project. Takes effect for the next request."""
        self._shares[project_id] = per_minute
        self._projects.pop(project_id, None)
        # A principal's ceiling is bounded by its project's, so its buckets are rebuilt as well.
        for key in [k for k in self._principals if k[0] == project_id]:
            del self._principals[key]

    def admit(self, project_id: str, principal_id: str) -> Refused | None:
        """Take one request's worth from every bucket, or take from none and say which bound was reached."""
        now = self._clock.monotonic()
        project = self._projects.get(project_id)
        if project is None:
            project = self._projects[project_id] = TokenBucket(self._shares.get(project_id, self._project_rate), now)
        key = (project_id, principal_id)
        principal = self._principals.get(key)
        if principal is None:
            principal = self._principals[key] = TokenBucket(
                min(self._principal_rate, self._shares.get(project_id, self._project_rate)), now
            )
        for name, bucket in (("principal_rate", principal), ("project_rate", project), ("host_allowance", self._total)):
            wait = bucket.peek(now)
            if wait > 0:
                return Refused(name, _seconds(wait))
        for bucket in (principal, project, self._total):
            bucket.take(now)
        self._trim(now)
        return None

    def _trim(self, now: float) -> None:
        if len(self._principals) > _MAX_TRACKED:
            for key in [k for k, b in self._principals.items() if b.idle(now)]:
                del self._principals[key]
        if len(self._projects) > _MAX_TRACKED:
            for pid in [k for k, b in self._projects.items() if b.idle(now)]:
                del self._projects[pid]


def _seconds(wait: float) -> int:
    return 3600 if math.isinf(wait) else max(1, math.ceil(wait))


class InFlight:
    """Requests in flight, per principal and per project, whichever interface they arrive through."""

    def __init__(self, *, principal_max: int, project_max: int) -> None:
        self._principal_max = principal_max
        self._project_max = project_max
        self._principals: dict[tuple[str, str], int] = {}
        self._projects: dict[str, int] = {}

    def enter(self, project_id: str, principal_id: str) -> Refused | None:
        key = (project_id, principal_id)
        if self._principals.get(key, 0) >= self._principal_max:
            return Refused("principal_max_in_flight", 1)
        if self._projects.get(project_id, 0) >= self._project_max:
            return Refused("project_max_in_flight", 1)
        self._principals[key] = self._principals.get(key, 0) + 1
        self._projects[project_id] = self._projects.get(project_id, 0) + 1
        return None

    def leave(self, project_id: str, principal_id: str) -> None:
        key = (project_id, principal_id)
        left = self._principals.get(key, 0) - 1
        if left > 0:
            self._principals[key] = left
        else:
            self._principals.pop(key, None)
        left = self._projects.get(project_id, 0) - 1
        if left > 0:
            self._projects[project_id] = left
        else:
            self._projects.pop(project_id, None)

    def snapshot(self) -> dict[str, int]:
        return {"principals": sum(self._principals.values()), "projects": sum(self._projects.values())}


class RetryBudget:
    """Retries as a share of recent requests. When it is spent, a retryable failure is surfaced instead."""

    def __init__(self, clock: Clock, *, ratio: float, floor: int = 10, window_s: float = 60.0) -> None:
        self._clock = clock
        self._ratio = ratio
        self._floor = floor
        self._window = window_s
        self._requests: deque[float] = deque()
        self._retries: deque[float] = deque()

    def _trim(self, now: float) -> None:
        cutoff = now - self._window
        for times in (self._requests, self._retries):
            while times and times[0] <= cutoff:
                times.popleft()

    def request(self) -> None:
        # Forgotten here as well as when a retry is asked for: a host that stays reachable for weeks asks
        # for no retry, and what is remembered must not grow by one entry for every request in that time.
        now = self._clock.monotonic()
        self._trim(now)
        self._requests.append(now)

    def allow_retry(self) -> bool:
        now = self._clock.monotonic()
        self._trim(now)
        if len(self._retries) >= self._floor + self._ratio * len(self._requests):
            return False
        self._retries.append(now)
        return True
