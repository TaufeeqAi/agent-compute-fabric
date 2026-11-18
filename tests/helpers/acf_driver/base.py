"""What every part of the driver shares: its failure type, the client's exit codes, and waiting with a deadline."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Final

# Exit codes of acf-local (apps/cli/README.md, "Exit codes"). Named so that an assertion reads as a sentence.
EXIT_OK: Final = 0
EXIT_WORKLOAD_FAILED: Final = 1  # exec / run once: the operation succeeded, the command did not exit with status 0
EXIT_USAGE: Final = 2  # nothing was sent
EXIT_REFUSED: Final = 3  # the host refused: nothing was applied, no operation record exists
EXIT_FAILED: Final = 4  # the operation ended FAILED or CANCELLED
EXIT_UNKNOWN: Final = 5  # the operation ended UNKNOWN: neither success nor failure
EXIT_TRANSPORT: Final = 6  # the host could not be reached, or a read was not answered
EXIT_PROTOCOL: Final = 7  # the peer did not answer in acf.host/2
EXIT_UNRESOLVED: Final = 8  # not established yet: still in progress, or contact was lost after sending
EXIT_INTERRUPTED: Final = 130
EXIT_READER_GONE: Final = 141

PROTOCOL: Final = "acf.host/2"

# The terminal operation states (execution/contracts/host-api.json, "operation_states").
TERMINAL_STATES: Final = frozenset({"SUCCEEDED", "FAILED", "CANCELLED", "UNKNOWN"})


class DriverError(AssertionError):
    """The system did not do what the test needed in order to go on (the message carries what it said instead)."""


def tail(text: str, limit: int = 2000) -> str:
    return text if len(text) <= limit else "..." + text[-limit:]


def wait_for[T](what: str, probe: Callable[[], T | None], *, timeout: float, interval: float = 0.2) -> T:
    """Poll ``probe`` until it returns something other than ``None``; fail with ``what`` after ``timeout`` seconds.

    A black-box test cannot know in advance how long the host takes to notice something. The bound is the
    assertion ("a lost runtime is noticed within the detection bound"), never a sleep of a guessed length.
    """
    deadline = time.monotonic() + timeout
    while True:
        found = probe()
        if found is not None:
            return found
        if time.monotonic() >= deadline:
            raise DriverError(f"timed out after {timeout:.1f}s waiting for: {what}")
        time.sleep(interval)


def elapsed_since(started: float) -> float:
    """Seconds on the monotonic clock since ``started`` (a value of ``time.monotonic()``)."""
    return time.monotonic() - started
