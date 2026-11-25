"""Time, as the core reads it: a wall clock for what is recorded, a monotonic clock for what is measured.

Both come from one object so that tests can move time. Nothing in the core calls ``time.time()`` or
``time.monotonic()`` directly.

Timestamps are RFC 3339 in UTC with milliseconds (``2026-01-02T03:04:05.678Z``), on the public surface
and toward the host alike.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Protocol


class Clock(Protocol):
    def wall_ms(self) -> int:
        """Milliseconds since the epoch, by the wall clock."""
        ...

    def monotonic(self) -> float:
        """Seconds on a clock that never goes backwards."""
        ...


class SystemClock:
    def wall_ms(self) -> int:
        return time.time_ns() // 1_000_000

    def monotonic(self) -> float:
        return time.monotonic()


def rfc3339(ms: int) -> str:
    """``ms`` since the epoch as RFC 3339 in UTC, with milliseconds."""
    moment = datetime.fromtimestamp(ms // 1000, tz=UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S") + f".{ms % 1000:03d}Z"


def parse_rfc3339(text: str) -> int | None:
    """Milliseconds since the epoch of an RFC 3339 UTC timestamp, or ``None`` if it is not one."""
    if not text.endswith("Z"):
        return None
    try:
        moment = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError:
        return None
    return int(moment.timestamp()) * 1000 + moment.microsecond // 1000
