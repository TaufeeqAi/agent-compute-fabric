"""Telemetry: spans only through an OpenTelemetry the application installed, and retries that are never silent.

The package never exports anything and never depends on OpenTelemetry. The tests install the
OpenTelemetry API the way an application would, with a tracer provider that records in memory, and
check what appears. One test takes the API away and checks that nothing changes but the spans.
"""

from __future__ import annotations

import importlib.metadata
import logging
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from opentelemetry import trace
from opentelemetry.util import types

from agentcompute import PermissionDeniedError, _telemetry
from support import CANARY_KEY, OP2, SBX, Harness, done, ex, fault, refusal, reply, sandbox


class _RecordedSpan(trace.NonRecordingSpan):
    """A span that keeps what it is told, in memory."""

    def __init__(self, name: str) -> None:
        super().__init__(trace.INVALID_SPAN_CONTEXT)
        self.name = name
        self.events: list[tuple[str, dict[str, Any]]] = []
        self.status: trace.StatusCode | None = None
        self.exceptions: list[BaseException] = []
        self.ended = False

    def is_recording(self) -> bool:
        return True

    def add_event(self, name: str, attributes: types.Attributes = None, timestamp: int | None = None) -> None:
        self.events.append((name, dict(attributes or {})))

    def set_status(self, status: trace.Status | trace.StatusCode, description: str | None = None) -> None:
        self.status = status.status_code if isinstance(status, trace.Status) else status

    def record_exception(
        self,
        exception: BaseException,
        attributes: types.Attributes = None,
        timestamp: int | None = None,
        escaped: bool = False,
    ) -> None:
        self.exceptions.append(exception)

    def end(self, end_time: int | None = None) -> None:
        self.ended = True


class _RecordingTracer(trace.Tracer):
    def __init__(self, spans: list[_RecordedSpan]) -> None:
        self._spans = spans

    def start_span(self, name: str, *args: Any, **kwargs: Any) -> trace.Span:
        span = _RecordedSpan(name)
        self._spans.append(span)
        return span

    # The API wraps this method in a context-manager type of its own, which is private to it. A plain
    # context manager behaves the same for a `with` statement, which is all this package uses.
    @contextmanager
    def start_as_current_span(  # type: ignore[override]
        self, name: str, *args: Any, **kwargs: Any
    ) -> Iterator[trace.Span]:
        with trace.use_span(self.start_span(name), end_on_exit=True) as span:
            yield span


class _RecordingProvider(trace.TracerProvider):
    def __init__(self) -> None:
        self.spans: list[_RecordedSpan] = []
        self.instrumentation: list[tuple[str, str | None]] = []

    def get_tracer(self, instrumenting_module_name: str, *args: Any, **kwargs: Any) -> trace.Tracer:
        version = args[0] if args else kwargs.get("instrumenting_library_version")
        self.instrumentation.append((instrumenting_module_name, version))
        return _RecordingTracer(self.spans)


#: What an application does once, at start-up. The API allows it once per process.
_PROVIDER = _RecordingProvider()
trace.set_tracer_provider(_PROVIDER)


@pytest.fixture
def spans() -> Iterator[list[_RecordedSpan]]:
    _telemetry._open_telemetry.cache_clear()
    _PROVIDER.spans.clear()
    yield _PROVIDER.spans
    _telemetry._open_telemetry.cache_clear()


def _created() -> Any:
    return reply(200, done("sandbox.create", "sandbox", sandbox("READY")))


def _started() -> Any:
    return reply(200, done("sandbox.start", "sandbox", sandbox("RUNNING"), operation_id=OP2))


def test_one_logical_call_is_one_span_however_many_requests_it_makes(
    harness: Harness, spans: list[_RecordedSpan]
) -> None:
    script = harness.script(
        ex("POST", "/sandboxes", fault()),
        ex("POST", "/sandboxes", _created()),
        ex("POST", f"/sandboxes/{SBX}/start", _started()),
        ex("GET", f"/sandboxes/{SBX}", reply(200, sandbox())),
    )
    fabric = harness.client(script)
    harness.run(fabric.sandboxes.create("python", cpu=1, memory=512, disk=1024))
    harness.run(fabric.sandboxes.get(SBX))

    assert [span.name for span in spans] == ["agentcompute.sandboxes.create", "agentcompute.sandboxes.get"]
    assert all(span.ended for span in spans)
    assert all(span.status is None and not span.exceptions for span in spans)
    assert ("agentcompute", "0.1.0") in _PROVIDER.instrumentation


def test_every_retry_is_an_event_with_its_attempt_number(harness: Harness, spans: list[_RecordedSpan]) -> None:
    script = harness.script(
        ex("GET", f"/sandboxes/{SBX}", refusal("UPSTREAM_UNAVAILABLE", retry_after=2)),
        ex("GET", f"/sandboxes/{SBX}", fault("timeout")),
        ex("GET", f"/sandboxes/{SBX}", reply(200, sandbox())),
    )
    harness.run(harness.client(script).sandboxes.get(SBX))
    (span,) = spans
    assert [name for name, _ in span.events] == ["retry", "retry"]
    first, second = (attributes for _, attributes in span.events)
    assert (first["attempt"], first["delay_s"], first["reason"]) == (1, 2.0, "UPSTREAM_UNAVAILABLE")
    assert second["attempt"] == 2
    assert "ReadTimeout" in second["reason"]


def test_a_call_that_fails_marks_its_span_and_records_no_credential(
    harness: Harness, spans: list[_RecordedSpan]
) -> None:
    script = harness.script(ex("GET", f"/sandboxes/{SBX}", refusal("PERMISSION_DENIED")))
    with pytest.raises(PermissionDeniedError):
        harness.run(harness.client(script).sandboxes.get(SBX))
    (span,) = spans
    assert span.status is trace.StatusCode.ERROR
    assert [type(error) for error in span.exceptions] == [PermissionDeniedError]
    assert span.ended
    shown = [span.name, repr(span.events), *(f"{error} {error!r}" for error in span.exceptions)]
    assert all(CANARY_KEY not in text for text in shown)


def test_a_refused_argument_is_inside_the_span_of_its_call(harness: Harness, spans: list[_RecordedSpan]) -> None:
    fabric = harness.client(harness.script())
    with pytest.raises(ValueError, match="memory must be"):
        harness.run(fabric.sandboxes.create("python", cpu=1, memory="4GB", disk=1024))
    assert [span.name for span in spans] == ["agentcompute.sandboxes.create"]
    assert spans[0].status is trace.StatusCode.ERROR


def test_without_opentelemetry_everything_works_and_nothing_is_recorded(
    harness: Harness, spans: list[_RecordedSpan], monkeypatch: pytest.MonkeyPatch
) -> None:
    """An application that did not install it: the import fails, and the package does not mind."""
    monkeypatch.setitem(sys.modules, "opentelemetry", None)
    _telemetry._open_telemetry.cache_clear()
    script = harness.script(
        ex("GET", f"/sandboxes/{SBX}", fault()),
        ex("GET", f"/sandboxes/{SBX}", reply(200, sandbox())),
    )
    assert harness.run(harness.client(script).sandboxes.get(SBX)).sandbox_id == SBX
    assert _telemetry._open_telemetry() is None
    assert spans == []


def test_the_distribution_has_one_runtime_dependency_and_it_is_not_opentelemetry() -> None:
    requirements = importlib.metadata.requires("agent-compute") or []
    assert len(requirements) == 1
    (only,) = requirements
    assert only.startswith("httpx2")
    assert ">=2.16.2" in only
    assert "<3" in only


def test_importing_the_package_does_not_import_opentelemetry() -> None:
    """It is looked for when a call is made, never at import. Checked in an interpreter that imported nothing else."""
    code = "import sys, agentcompute; print('opentelemetry' in sys.modules, 'agentcompute' in sys.modules)"
    # The interpreter of this test run, and a constant program: nothing here comes from outside.
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)  # noqa: S603
    assert done.stdout.split() == ["False", "True"]


# ------------------------------------------------------------------------------------------------- logging
def test_a_retry_is_never_silent(harness: Harness, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="agentcompute")
    script = harness.script(
        ex("POST", "/sandboxes", refusal("RATE_LIMITED", retry_after=3)),
        ex("POST", "/sandboxes", fault()),
        ex("POST", "/sandboxes", _created()),
    )
    fabric = harness.client(script)
    harness.run(fabric.sandboxes.create("python", cpu=1, memory=512, disk=1024, start=False))
    retries = [record for record in caplog.records if record.name == "agentcompute" and record.levelno == logging.INFO]
    assert len(retries) == 2
    assert "attempt 1" in retries[0].getMessage()
    assert "RATE_LIMITED" in retries[0].getMessage()
    assert "3.000 s" in retries[0].getMessage()
    assert "attempt 2" in retries[1].getMessage()
    assert "POST /v1/projects/prj_0000000000000001/sandboxes" in retries[1].getMessage()


def test_every_answer_is_a_debug_record_with_its_request_id(harness: Harness, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger="agentcompute")
    script = harness.script(ex("GET", f"/sandboxes/{SBX}", reply(200, sandbox())))
    harness.run(harness.client(script).sandboxes.get(SBX))
    messages = [record.getMessage() for record in caplog.records if record.name == "agentcompute"]
    assert messages == [
        f"GET /v1/projects/prj_0000000000000001/sandboxes/{SBX} -> 200 (request req_000000000000000000000001)"
    ]


def test_the_package_logger_decides_nothing_about_where_records_go() -> None:
    logger = logging.getLogger("agentcompute")
    assert [type(handler) for handler in logger.handlers] == [logging.NullHandler]
    assert logger.propagate is True
    assert logger.level == logging.NOTSET
