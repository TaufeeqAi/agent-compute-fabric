"""What this package tells the outside about its own work: log records, and spans if someone wants them.

Nothing here leaves the process by itself. Log records go to the ``agentcompute`` logger, which has no
handler of its own. Spans are created through the OpenTelemetry API only when the application installed
that API itself: it is imported on first use, it is not a dependency of this package, and this package
never configures an exporter. An application that has not set up OpenTelemetry pays nothing and sends
nothing.

No record and no span ever holds a credential: what is recorded is the name of the call, the method and
path of a request (a path never holds a credential), an attempt number, a delay and a reason.
"""

from __future__ import annotations

import functools
import logging
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING, Final, NamedTuple

from agentcompute._version import __version__

if TYPE_CHECKING:
    from opentelemetry.trace import Span, Tracer

__all__ = ["logger", "retrying", "span"]

logger: Final = logging.getLogger("agentcompute")
# A library never decides where its records go. Without this, a record would reach the handler of last
# resort when the application configured no logging at all.
logger.addHandler(logging.NullHandler())

_INSTRUMENTATION: Final = "agentcompute"


class _OpenTelemetry(NamedTuple):
    tracer: Tracer
    current_span: Callable[[], Span]


@functools.cache
def _open_telemetry() -> _OpenTelemetry | None:
    """The application's OpenTelemetry API, or ``None`` when it installed none. Looked for once."""
    try:
        from opentelemetry import trace  # noqa: PLC0415 - optional, and only looked for when a call is made
    except ImportError:
        return None
    return _OpenTelemetry(trace.get_tracer(_INSTRUMENTATION, __version__), trace.get_current_span)


@contextmanager
def span(call: str) -> Iterator[None]:
    """One span around one logical call, however many requests the call makes."""
    api = _open_telemetry()
    if api is None:
        yield
        return
    with api.tracer.start_as_current_span(f"{_INSTRUMENTATION}.{call}"):
        yield


def retrying(*, method: str, path: str, attempt: int, delay: float, reason: str) -> None:
    """Record that a request is about to be sent again. A retry is counted, never silent."""
    logger.info("%s %s: attempt %d did not succeed (%s); asking again in %.3f s", method, path, attempt, reason, delay)
    api = _open_telemetry()
    if api is not None:
        api.current_span().add_event("retry", {"attempt": attempt, "delay_s": delay, "reason": reason})
