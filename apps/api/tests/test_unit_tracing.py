"""The span of one command: its name, what it carries, whose trace it continues, and what it never holds.

The conventions for spans of the agent protocol are in Development status, so every name is spelled out
here: a change of the conventions is a change of these tests, made on purpose.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import pytest

from acf_api.command import commands as c
from acf_api.command import model as m
from acf_api.command.answers import ErrorAnswer, ProtocolFaultAnswer, RequestContext, ToolAnswer, ViewAnswer
from acf_api.command.model import ErrorBody
from acf_api.core.agent import catalog
from acf_api.core.pipeline import tracing
from acf_api.core.telemetry import Telemetry
from tests.support.harness import Identity, Rig, build_rig

TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
PARENT_SPAN = "00f067aa0ba902b7"
TRACEPARENT = f"00-{TRACE_ID}-{PARENT_SPAN}-01"
REVISION = "2026-07-28"
PROJECT = "prj_" + "0" * 20


def context(
    interface: Literal["rest", "mcp", "mcp-stdio"] = "mcp", *, traceparent: str | None = None
) -> RequestContext:
    return RequestContext(
        request_id="req_" + "1" * 24,
        traceparent=traceparent,
        budget_ms=30_000,
        interface=interface,
        interface_version=REVISION if interface == "mcp" else m.API_VERSION,
    )


def error(code: str, retry: str = "NEVER", kind: str = "REFUSED") -> ErrorAnswer:
    return ErrorAnswer(error=ErrorBody(code=code, kind=kind, retry=retry, message="said", request_id="req_" + "1" * 24))


# ------------------------------------------------------------------------------------ names and attributes
def test_a_call_of_a_tool_of_the_catalogue_is_named_after_the_method_and_the_tool() -> None:
    name, attributes = tracing.span_of(context(), c.CallTool(name="sandbox_exec", arguments={"argv": ["true"]}))
    assert name == "tools/call sandbox_exec"
    assert attributes == {
        "acf.command": "call_tool",
        "acf.interface": "mcp",
        "mcp.method.name": "tools/call",
        "mcp.protocol.version": REVISION,
        "network.transport": "tcp",
        "gen_ai.tool.name": "sandbox_exec",
        "gen_ai.operation.name": "execute_tool",
    }


@pytest.mark.parametrize("tool", sorted(catalog.TOOLS))
def test_every_tool_of_the_catalogue_is_a_label(tool: str) -> None:
    name, attributes = tracing.span_of(context(), c.CallTool(name=tool))
    assert name == f"tools/call {tool}"
    assert attributes["gen_ai.tool.name"] == tool


def test_a_name_that_is_no_tool_is_what_a_caller_typed_and_never_becomes_a_label() -> None:
    typed = "x" * 64
    name, attributes = tracing.span_of(context(), c.CallTool(name=typed, arguments={"secret": "canary"}))
    assert name == "tools/call"
    assert "gen_ai.tool.name" not in attributes
    assert "gen_ai.operation.name" not in attributes
    everything = name + repr(attributes)
    assert typed not in everything
    assert "canary" not in everything


@pytest.mark.parametrize(
    ("command", "method"),
    [(c.ListTools(), "tools/list"), (c.Discover(), "server/discover")],
)
def test_the_other_methods_of_the_agent_protocol_are_named_after_the_method(command: c.Command, method: str) -> None:
    name, attributes = tracing.span_of(context(), command)
    assert name == method
    assert attributes["mcp.method.name"] == method
    assert "gen_ai.tool.name" not in attributes


def test_a_rest_command_is_named_after_the_command_and_carries_nothing_of_the_agent_protocol() -> None:
    name, attributes = tracing.span_of(context("rest"), c.ListSandboxes(project=PROJECT))
    assert name == "list_sandboxes"
    assert attributes == {"acf.command": "list_sandboxes", "acf.interface": "rest", "acf.api_version": m.API_VERSION}


def test_the_methods_named_are_the_three_the_adapter_serves() -> None:
    assert sorted(tracing.MCP_METHODS.values()) == ["server/discover", "tools/call", "tools/list"]
    for command in tracing.MCP_METHODS:
        assert command in {"call_tool", "list_tools", "discover"}


# --------------------------------------------------------------------------------------------- error.type
def test_a_tool_result_that_says_error_is_a_tool_error_and_one_that_does_not_is_none() -> None:
    assert tracing.error_type(ToolAnswer(structured={"ok": False}, is_error=True)) == "tool_error"
    assert tracing.error_type(ToolAnswer(structured={"ok": True}, is_error=False)) is None


@pytest.mark.parametrize(
    "code", ["PERMISSION_DENIED", "NOT_FOUND", "INVALID_REQUEST", "RATE_LIMITED", "REVISION_CONFLICT"]
)
def test_a_refusal_is_an_answer_and_not_an_error_of_the_server(code: str) -> None:
    assert tracing.error_type(error(code)) is None


@pytest.mark.parametrize(
    ("code", "retry", "kind"),
    [
        ("INTERNAL_ERROR", "NEVER", "REFUSED"),
        ("UPSTREAM_UNAVAILABLE", "SAME_REQUEST_LATER", "REFUSED"),
        ("OUTCOME_UNRESOLVED", "SAME_REQUEST_LATER", "UNRESOLVED"),
    ],
)
def test_an_answer_in_which_the_platform_failed_the_caller_names_its_code(code: str, retry: str, kind: str) -> None:
    assert tracing.error_type(error(code, retry, kind)) == code


def test_a_view_and_a_request_the_caller_got_wrong_are_no_errors() -> None:
    assert tracing.error_type(ViewAnswer(view="Sandbox", body={})) is None
    assert tracing.error_type(ProtocolFaultAnswer(fault="unknown_tool", message="no such tool")) is None


# ------------------------------------------------------------------------------------- the span itself
@dataclass
class Recorded:
    name: str
    kind: Any
    parent_trace_id: str | None
    attributes: dict[str, Any] = field(default_factory=dict)

    def set_attribute(self, key: str, value: Any) -> None:
        self.attributes[key] = value


class RecordingTracer:
    """A tracer that keeps what it is asked to record. It stands for whatever provider an operator installed."""

    def __init__(self) -> None:
        self.spans: list[Recorded] = []

    @contextlib.contextmanager
    def start_as_current_span(
        self, name: str, *, context: Any = None, kind: Any = None, attributes: Any = None
    ) -> Iterator[Recorded]:
        from opentelemetry import trace  # the test that calls this has imported it or skipped

        parent = trace.get_current_span(context).get_span_context() if context is not None else None
        span = Recorded(
            name,
            kind,
            f"{parent.trace_id:032x}" if parent is not None and parent.is_valid else None,
            dict(attributes or {}),
        )
        self.spans.append(span)
        yield span


def test_without_a_tracer_a_block_runs_and_setting_an_attribute_does_nothing() -> None:
    telemetry = Telemetry()
    with telemetry.span("anything", parent=TRACEPARENT, server=True, a="b") as span:
        span.set("error.type", "tool_error")


def test_a_span_continues_the_callers_trace_as_a_server_span() -> None:
    trace = pytest.importorskip("opentelemetry.trace")
    tracer = RecordingTracer()
    with Telemetry(tracer).span(
        "tools/list", parent=TRACEPARENT, server=True, **{"mcp.method.name": "tools/list"}
    ) as span:
        span.set("error.type", "tool_error")
    (recorded,) = tracer.spans
    assert recorded.name == "tools/list"
    assert recorded.kind is trace.SpanKind.SERVER
    assert recorded.parent_trace_id == TRACE_ID
    assert recorded.attributes == {"mcp.method.name": "tools/list", "error.type": "tool_error"}


def test_a_span_without_a_parent_starts_a_trace_of_its_own() -> None:
    pytest.importorskip("opentelemetry.trace")
    tracer = RecordingTracer()
    with Telemetry(tracer).span("list_sandboxes", server=True):
        pass
    assert tracer.spans[0].parent_trace_id is None


# --------------------------------------------------------------------------------- through the pipeline
async def test_one_command_is_one_server_span_in_the_callers_trace(tmp_path: Path) -> None:
    """OBS-2, B22: the trace context an agent sent in `params._meta` is the parent of the span of its call."""
    trace = pytest.importorskip("opentelemetry.trace")
    rig: Rig = await build_rig(tmp_path)
    try:
        dev: Identity = await rig.developer()
        agent = (await rig.mint_agent(dev))["secret"]
        tracer = RecordingTracer()
        rig.core.service.d.telemetry._tracer = tracer  # the seam a deployment fills by installing OpenTelemetry
        listed = await rig.core.service.handle(
            agent, context(traceparent=TRACEPARENT), c.CallTool(name="sandbox_list"), None
        )
        assert isinstance(listed, ToolAnswer)
        refused = await rig.core.service.handle(
            agent, context(), c.CallTool(name="sandbox_inspect", arguments={"sandbox": "sbx-" + "0" * 32}), None
        )
        assert isinstance(refused, ToolAnswer)
        assert refused.is_error
        ok, failed = tracer.spans
        assert (ok.name, ok.kind, ok.parent_trace_id) == ("tools/call sandbox_list", trace.SpanKind.SERVER, TRACE_ID)
        assert ok.attributes["gen_ai.tool.name"] == "sandbox_list"
        assert "error.type" not in ok.attributes
        assert (failed.name, failed.parent_trace_id) == ("tools/call sandbox_inspect", None)
        assert failed.attributes["error.type"] == "tool_error"
        # Nothing of the call but its tool: no argument, no credential, no identifier a caller chose.
        for span in tracer.spans:
            said = span.name + repr(span.attributes)
            assert agent not in said
            assert "sbx-" not in said
    finally:
        await rig.close()
