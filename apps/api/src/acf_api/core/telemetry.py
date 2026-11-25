"""Diagnostic telemetry of the core: counters, timings, structured log lines and optional spans.

Telemetry may be lost, and losing it changes no outcome: nothing in the core reads a counter, a log
line or a span to decide anything.

What never enters telemetry: credentials, tokens, secret material, execution output, argument and
environment values, file contents, full tool arguments. A label of a counter comes from a bounded set
that the code chooses; a caller-supplied string is never a label. :func:`safe` bounds and checks the
few caller-supplied identifiers that are logged.

Spans are emitted through the OpenTelemetry API only when the operator has installed it. The core
never exports by itself. A span continues the trace the caller named, so that one trace shows the
caller's own work and the platform's part of it.
"""

from __future__ import annotations

import contextlib
import json
import logging
import sys
import time
from collections.abc import Iterator
from typing import Any, Final

_SAFE: Final = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/@=+-")
_MAX_FIELD: Final = 128
_LOGGER: Final = logging.getLogger("acf_api")


def _load_opentelemetry() -> tuple[Any, Any]:
    """The OpenTelemetry API and its trace-context propagator, if the operator installed them."""
    try:
        from opentelemetry import trace  # noqa: PLC0415 - optional; the core runs without it
        from opentelemetry.trace.propagation.tracecontext import (  # noqa: PLC0415
            TraceContextTextMapPropagator,
        )
    except ImportError:
        return None, None
    return trace, TraceContextTextMapPropagator()


_OTEL, _PROPAGATOR = _load_opentelemetry()


class Span:
    """The span of a block, if there is one. Setting an attribute where there is no span does nothing."""

    __slots__ = ("_span",)

    def __init__(self, span: Any = None) -> None:  # noqa: ANN401 - a span of OpenTelemetry, which is installed only where an operator wants it
        self._span = span

    def set(self, key: str, value: str | int | bool) -> None:  # noqa: FBT001 - the value of an attribute, not a switch
        if self._span is not None:
            self._span.set_attribute(key, value)


_NO_SPAN: Final = Span()


def safe(value: object) -> str:
    """A caller-supplied identifier, bounded and reduced to an unambiguous character set, for a log line."""
    text = str(value)[:_MAX_FIELD]
    return "".join(ch if ch in _SAFE else "?" for ch in text)


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        body: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "event": record.getMessage(),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            body.update(fields)
        return json.dumps(body, separators=(",", ":"), ensure_ascii=True, default=str)


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_JsonFormatter())
    _LOGGER.handlers[:] = [handler]
    _LOGGER.setLevel(level)
    _LOGGER.propagate = False


class Telemetry:
    """Counters and timings in memory, read by the operator through the admin interface."""

    def __init__(self, tracer: Any = None) -> None:  # noqa: ANN401 - a tracer of OpenTelemetry, which is installed only where an operator wants it
        self._counters: dict[str, int] = {}
        self._timings: dict[str, tuple[int, float, float]] = {}
        #: ``tracer`` is the seam of the tests. A deployment passes none and gets the tracer of whatever
        #: provider the operator installed; the API's own default records nothing.
        self._tracer = tracer if tracer is not None else (_OTEL.get_tracer("acf_api") if _OTEL is not None else None)

    @staticmethod
    def _key(name: str, labels: dict[str, str]) -> str:
        if not labels:
            return name
        return name + "{" + ",".join(f"{k}={labels[k]}" for k in sorted(labels)) + "}"

    def count(self, name: str, value: int = 1, **labels: str) -> None:
        key = self._key(name, labels)
        self._counters[key] = self._counters.get(key, 0) + value

    def observe(self, name: str, seconds: float, **labels: str) -> None:
        key = self._key(name, labels)
        n, total, worst = self._timings.get(key, (0, 0.0, 0.0))
        self._timings[key] = (n + 1, total + seconds, max(worst, seconds))

    def get(self, name: str, **labels: str) -> int:
        return self._counters.get(self._key(name, labels), 0)

    def snapshot(self) -> dict[str, Any]:
        return {
            "counters": dict(sorted(self._counters.items())),
            "timings": {
                k: {"count": n, "sum_s": round(s, 6), "max_s": round(w, 6)}
                for k, (n, s, w) in sorted(self._timings.items())
            },
        }

    def log(self, level: int, event: str, **fields: object) -> None:
        """One structured log line. Callers pass identifiers and enumerations only."""
        _LOGGER.log(level, event, extra={"fields": fields})

    def diagnostic(self, event: str, **fields: object) -> None:
        """Something an operator must look at."""
        self.count("operator_diagnostics", kind=event)
        self.log(logging.ERROR, event, **fields)

    @contextlib.contextmanager
    def span(
        self, name: str, *, parent: str | None = None, server: bool = False, **attributes: str | int | bool
    ) -> Iterator[Span]:
        """A span around a block, when OpenTelemetry is installed. Otherwise the block runs and nothing else.

        ``parent`` is the caller's W3C ``traceparent``, already checked for its form: the span continues that
        trace. The name and the attributes are the code's own; a caller-supplied string is never one.
        """
        if self._tracer is None or _OTEL is None:
            yield _NO_SPAN
            return
        context = _PROPAGATOR.extract({"traceparent": parent}) if parent else None
        kind = _OTEL.SpanKind.SERVER if server else _OTEL.SpanKind.INTERNAL
        with self._tracer.start_as_current_span(name, context=context, kind=kind, attributes=dict(attributes)) as span:
            yield Span(span)
