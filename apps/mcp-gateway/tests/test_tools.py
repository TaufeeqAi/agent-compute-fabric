"""`tools/list` and `tools/call`: one command each, and the core's answer in the protocol's shapes."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any

import httpx2
import pytest

from acf_api.command import client as command_client
from acf_api.command.answers import (
    ErrorAnswer,
    ProtocolFaultAnswer,
    RequestContext,
    ToolAnswer,
    ToolsAnswer,
    ViewAnswer,
)
from acf_api.command.commands import CallTool, ListTools
from acf_api.command.model import ErrorBody
from acf_mcp.gateway import Gateway
from tests.support import REVISION, FakeCore, call, catalogue, headers, post, rpc

INVALID_REQUEST = -32600
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
PORTABLE_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}")


def refused(code: str, retry: str = "NEVER", **members: Any) -> ErrorAnswer:
    body = ErrorBody(
        code=code, kind="REFUSED", retry=retry, message=f"the core says {code}", request_id="req_" + "b" * 24
    )
    return ErrorAnswer(
        error=body.model_copy(update=members), retry_after_s=1 if retry == "SAME_REQUEST_LATER" else None
    )


async def _call(
    client: httpx2.AsyncClient, name: str = "sandbox_list", arguments: dict[str, Any] | None = None
) -> httpx2.Response:
    return await client.post("/mcp", json=call(name, arguments), headers=headers("tools/call", name))


# ---------------------------------------------------------------------------- the catalogue
async def test_the_listing_is_the_published_catalogue_field_for_field(
    client: httpx2.AsyncClient, core: FakeCore
) -> None:
    """Every published tool, as the core defines it, comes out exactly as the platform publishes it."""
    published = catalogue()
    assert len(published) >= 16
    core.answers["list_tools"] = ToolsAnswer(tools=[definition for _, definition in published])
    response = await client.post("/mcp", json=rpc("tools/list"), headers=headers("tools/list"))
    assert response.status_code == 200
    result = response.json()["result"]
    expected = [{k: v for k, v in document.items() if not k.startswith("x-acf-")} for document, _ in published]
    assert result["tools"] == expected
    for listed in result["tools"]:
        assert set(listed) == {"name", "title", "description", "inputSchema", "outputSchema", "annotations"}
        assert set(listed["annotations"]) == {
            "title",
            "readOnlyHint",
            "destructiveHint",
            "idempotentHint",
            "openWorldHint",
        }
        assert PORTABLE_NAME.fullmatch(listed["name"])
    assert core.commands() == [ListTools()]


async def test_a_listing_claims_no_freshness_and_is_one_page(client: httpx2.AsyncClient) -> None:
    """It depends on the credential and on the host, and nothing tells the adapter how long it holds."""
    result = (await client.post("/mcp", json=rpc("tools/list"), headers=headers("tools/list"))).json()["result"]
    assert result["ttlMs"] == 0
    assert result["cacheScope"] == "private"
    assert result["resultType"] == "complete"
    assert "nextCursor" not in result


def test_no_published_tool_mirrors_a_parameter_into_a_header() -> None:
    """The adapter tells the SDK there is none, so that the SDK asks for no listing of its own before a call.

    If the catalogue ever declares one, validating the header needs the tool's schema here, and this
    test is where that is found out.
    """

    def keys(value: Any) -> set[str]:
        if isinstance(value, dict):
            return set(value) | {k for v in value.values() for k in keys(v)}
        if isinstance(value, list):
            return {k for v in value for k in keys(v)}
        return set()

    for document, _ in catalogue():
        assert "x-mcp-header" not in keys(document), document["name"]


async def test_a_call_is_one_command_and_no_listing(client: httpx2.AsyncClient, core: FakeCore) -> None:
    await _call(client, "sandbox_list", {"limit": 5})
    assert core.ops() == ["verify", "handle"]
    assert core.commands() == [CallTool(name="sandbox_list", arguments={"limit": 5})]


async def test_what_the_core_does_not_offer_is_not_listed(client: httpx2.AsyncClient, core: FakeCore) -> None:
    core.answers["list_tools"] = ToolsAnswer(tools=[])
    result = (await client.post("/mcp", json=rpc("tools/list"), headers=headers("tools/list"))).json()["result"]
    assert result["tools"] == []


async def test_a_cursor_was_never_issued(client: httpx2.AsyncClient, core: FakeCore) -> None:
    response = await client.post("/mcp", json=rpc("tools/list", {"cursor": "page-2"}), headers=headers("tools/list"))
    assert response.status_code == 400
    assert response.json()["error"]["code"] == INVALID_PARAMS
    assert core.ops() == ["verify"]


# ---------------------------------------------------------------------------- a call
async def test_arguments_reach_the_core_as_they_were_sent(client: httpx2.AsyncClient, core: FakeCore) -> None:
    """Nothing is validated, defaulted, reordered or dropped on the way."""
    arguments: dict[str, Any] = {
        "argv": ["sh", "-c", "echo 'h\N{LATIN SMALL LETTER E WITH ACUTE}llo' && exit 3"],
        "env": {
            "EMPTY": "",
            "UNICODE": "\N{CJK UNIFIED IDEOGRAPH-65E5}\N{CJK UNIFIED IDEOGRAPH-672C} \N{GRINNING FACE}",
        },
        "timeout": None,
        "nested": {"deep": [1, 2.5, True, None, {"k": []}]},
        "big": 2**63,
        "idempotency_key": "not-checked-here",
        "unknown_member": {"the adapter": "has no schema"},
    }
    await _call(client, "sandbox_exec", arguments)
    (command,) = core.commands()
    assert isinstance(command, CallTool)
    assert command.name == "sandbox_exec"
    assert command.arguments == arguments
    assert list(command.arguments) == list(arguments)
    assert core.asked[-1].idempotency_key is None


async def test_a_call_without_arguments_carries_an_empty_object(client: httpx2.AsyncClient, core: FakeCore) -> None:
    await _call(client, "health_check")
    assert core.commands() == [CallTool(name="health_check", arguments={})]


@pytest.mark.parametrize("is_error", [False, True])
@pytest.mark.parametrize(
    "structured",
    [
        {"ok": True},
        {"ok": False, "operation": {"state": "FAILED", "failure": {"code": "TIMEOUT"}}},
        {"ok": True, "replayed": True, "idempotency_key": "mk_1", "operation": {"state": "RUNNING", "result": None}},
        {},
    ],
)
async def test_a_result_is_what_the_core_produced_and_its_text_is_its_json(
    client: httpx2.AsyncClient, core: FakeCore, structured: dict[str, Any], is_error: bool
) -> None:
    core.answers["call_tool"] = ToolAnswer(structured=structured, is_error=is_error)
    response = await _call(client)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    result = response.json()["result"]
    assert set(result) == {"content", "structuredContent", "isError", "resultType", "_meta"}
    assert result["structuredContent"] == structured
    assert result["isError"] is is_error
    assert result["resultType"] == "complete"
    (block,) = result["content"]
    assert set(block) == {"type", "text"}
    assert block["type"] == "text"
    assert json.loads(block["text"]) == structured
    assert block["text"] == json.dumps(structured, separators=(",", ":"))


# ---------------------------------------------------------------------------- faults of the protocol
@pytest.mark.parametrize(
    ("fault", "message"),
    [("unknown_tool", "no such tool"), ("invalid_arguments", "the arguments do not fit the tool's input schema: argv")],
)
async def test_a_protocol_fault_is_a_json_rpc_error(
    client: httpx2.AsyncClient, core: FakeCore, fault: Any, message: str
) -> None:
    core.answers["call_tool"] = ProtocolFaultAnswer(fault=fault, message=message)
    response = await _call(client, "sandbox_exec", {"argv": 7})
    assert response.status_code == 400
    document = response.json()
    assert set(document) == {"jsonrpc", "id", "error"}
    assert document["id"] == 1
    assert document["error"] == {"code": INVALID_PARAMS, "message": message, "data": {"fault": fault}}


@pytest.mark.parametrize(
    "name",
    [
        "sandbox exec",
        "sandbox.exec",
        "s\N{LATIN SMALL LETTER A WITH DIAERESIS}ndbox",
        "a" * 65,
        "x;rm -rf /",
        "../../etc/passwd",
    ],
)
async def test_a_name_no_tool_can_have_is_an_unknown_tool(
    client: httpx2.AsyncClient, core: FakeCore, name: str
) -> None:
    """The command interface cannot carry such a name, so the core is not asked. The name is not repeated."""
    encoded = "=?base64?" + __import__("base64").b64encode(name.encode()).decode() + "?="
    response = await client.post("/mcp", json=call(name), headers=headers("tools/call", encoded))
    assert response.status_code == 400
    error = response.json()["error"]
    assert error["code"] == INVALID_PARAMS
    assert error["data"] == {"fault": "unknown_tool"}
    assert name not in response.text
    assert core.ops() == ["verify"]


async def test_arguments_that_are_not_an_object_are_malformed(client: httpx2.AsyncClient, core: FakeCore) -> None:
    body = call("sandbox_list")
    body["params"]["arguments"] = ["not", "an", "object"]
    response = await client.post("/mcp", json=body, headers=headers("tools/call", "sandbox_list"))
    assert response.status_code == 400
    assert response.json()["error"]["code"] == INVALID_PARAMS
    assert core.ops() == ["verify"]


# ---------------------------------------------------------------------------- unsuccessful outcomes
@pytest.mark.parametrize(
    "code", ["PERMISSION_DENIED", "NOT_FOUND", "STATE_CONFLICT", "RATE_LIMITED", "INVALID_REQUEST", "UNSUPPORTED"]
)
async def test_a_refusal_is_a_result_with_the_members_of_the_error(
    client: httpx2.AsyncClient, core: FakeCore, code: str
) -> None:
    answer = refused(code, reason="method")
    core.answers["call_tool"] = answer
    response = await _call(client)
    assert response.status_code == 200
    result = response.json()["result"]
    assert result["isError"] is True
    assert result["structuredContent"] == {
        "ok": False,
        "error": {
            "code": code,
            "kind": "REFUSED",
            "retry": "NEVER",
            "message": f"the core says {code}",
            "request_id": "req_" + "b" * 24,
            "reason": "method",
        },
    }
    assert json.loads(result["content"][0]["text"]) == result["structuredContent"]


async def test_no_answer_from_the_core_is_unresolved_and_never_a_refusal(
    client: httpx2.AsyncClient, core: FakeCore
) -> None:
    """The command client answers this when a call that can create work got no answer. It is passed on as it is."""
    core.answers["call_tool"] = lambda command: command_client.unresolved(core.asked[-1].ctx, None)
    response = await _call(client, "sandbox_exec", {"argv": ["true"]})
    assert response.status_code == 200
    result = response.json()["result"]
    assert result["isError"] is True
    error = result["structuredContent"]["error"]
    assert error["code"] == "OUTCOME_UNRESOLVED"
    assert error["kind"] == "UNRESOLVED"
    assert error["retry"] == "SAME_REQUEST_LATER"
    assert error["request_id"] == core.asked[-1].ctx.request_id
    # One command was sent. The adapter did not ask again.
    assert core.ops() == ["verify", "handle"]


async def test_a_core_that_cannot_be_reached_is_a_refusal_an_agent_can_read(
    client: httpx2.AsyncClient, core: FakeCore
) -> None:
    core.answers["call_tool"] = lambda command: command_client.unavailable(core.asked[-1].ctx, "nothing was sent")
    result = (await _call(client)).json()["result"]
    assert result["isError"] is True
    assert result["structuredContent"]["error"]["code"] == "UPSTREAM_UNAVAILABLE"
    assert result["structuredContent"]["error"]["kind"] == "REFUSED"


@pytest.mark.parametrize(
    ("answer", "status", "code"),
    [
        (refused("UPSTREAM_UNAVAILABLE", "SAME_REQUEST_LATER"), 503, INTERNAL_ERROR),
        (refused("RATE_LIMITED", "SAME_REQUEST_LATER"), 429, INVALID_REQUEST),
        (refused("UNSUPPORTED", "AFTER_CHANGE"), 422, INVALID_REQUEST),
    ],
)
async def test_a_listing_that_fails_has_no_result_to_carry_the_error(
    client: httpx2.AsyncClient, core: FakeCore, answer: ErrorAnswer, status: int, code: int
) -> None:
    """A listing is not a tool result: its failure is a JSON-RPC error, at the HTTP status of the platform's code."""
    core.answers["list_tools"] = answer
    response = await client.post("/mcp", json=rpc("tools/list"), headers=headers("tools/list"))
    assert response.status_code == status
    document = response.json()
    assert document["id"] == 1
    assert document["error"]["code"] == code
    assert document["error"]["message"] == answer.error.message
    assert document["error"]["data"] == answer.error.model_dump(mode="json", exclude_none=True)
    assert response.headers.get("retry-after") == ("1" if answer.retry_after_s else None)


async def test_an_answer_of_the_wrong_kind_is_an_internal_error(
    client: httpx2.AsyncClient, core: FakeCore, caplog: pytest.LogCaptureFixture
) -> None:
    view = ViewAnswer(view="Sandbox", body={"secret": "not for an agent"})
    core.answers.update(call_tool=view, list_tools=view, discover=view)
    with caplog.at_level(logging.ERROR, logger="acf_mcp"):
        answers = [
            await _call(client),
            await client.post("/mcp", json=rpc("tools/list"), headers=headers("tools/list")),
            await client.post("/mcp", json=rpc("server/discover"), headers=headers("server/discover")),
        ]
    for response in answers:
        assert response.json()["error"]["code"] == INTERNAL_ERROR
        assert "not for an agent" not in response.text
    assert [r.message for r in caplog.records] == ["unexpected_answer"] * 3


async def test_a_core_client_that_fails_is_an_internal_error_and_says_nothing(
    client: httpx2.AsyncClient, core: FakeCore
) -> None:
    core.answers["call_tool"] = RuntimeError("connection pool state: 0x7f")
    response = await _call(client)
    assert response.json()["error"] == {"code": INTERNAL_ERROR, "message": "Internal server error"}


# ---------------------------------------------------------------------------- the context of a request
async def test_the_context_says_which_interface_and_how_long(client: httpx2.AsyncClient, core: FakeCore) -> None:
    await _call(client)
    for asked in core.asked:
        ctx: RequestContext = asked.ctx
        assert ctx.interface == "mcp"
        assert ctx.interface_version == REVISION
        # The tool wait, 25 s, and the margin between edge and core, 2 s.
        assert ctx.budget_ms == 27_000
        assert re.fullmatch(r"req_[0-9A-Za-z]{24}", ctx.request_id)
    assert core.asked[0].ctx.request_id == core.asked[1].ctx.request_id


async def test_every_request_gets_an_id_of_its_own(client: httpx2.AsyncClient, core: FakeCore) -> None:
    await _call(client)
    await _call(client)
    assert len({a.ctx.request_id for a in core.asked}) == 2


async def test_client_information_comes_from_the_envelope_once_it_is_read(
    client: httpx2.AsyncClient, core: FakeCore
) -> None:
    await _call(client)
    check, command = core.asked
    # Before the body is read there is no envelope.
    assert (check.ctx.client.name, check.ctx.client.version) == ("", "")
    assert (command.ctx.client.name, command.ctx.client.version) == ("pytest", "1.0")


@pytest.mark.parametrize(
    ("info", "expected"),
    [
        ({"name": "claude-code", "version": "2.1.0"}, ("claude-code", "2.1.0")),
        ({"name": "  Cursor IDE  ", "version": " 0.9/beta+1 "}, ("Cursor IDE", "0.9/beta+1")),
        ({"name": "n" * 200, "version": "9" * 200}, ("n" * 64, "9" * 32)),
        ({"name": "evil\r\nname", "version": "1"}, ("", "")),
        ({"name": "na\N{LATIN SMALL LETTER I WITH DIAERESIS}ve", "version": "1"}, ("", "")),
        ({"name": "ok", "version": "<script>"}, ("", "")),
        ({"name": 7, "version": "1"}, None),
        ({"name": "no-version"}, None),
        ("a string", None),
        (None, ("", "")),
    ],
)
async def test_client_information_is_bounded_and_checked(
    client: httpx2.AsyncClient, core: FakeCore, info: Any, expected: tuple[str, str] | None
) -> None:
    body = call("sandbox_list")
    if info is None:
        del body["params"]["_meta"]["io.modelcontextprotocol/clientInfo"]
    else:
        body["params"]["_meta"]["io.modelcontextprotocol/clientInfo"] = info
    response = await client.post("/mcp", json=body, headers=headers("tools/call", "sandbox_list"))
    if expected is None:
        # Not the shape the protocol gives it: the SDK refuses the request before a handler runs.
        assert response.status_code == 400
        assert core.ops() == ["verify"]
        return
    assert response.status_code == 200
    command = core.asked[-1]
    assert (command.ctx.client.name, command.ctx.client.version) == expected


@pytest.mark.parametrize(
    ("traceparent", "kept"),
    [
        ("00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01", True),
        ("00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-00", True),
        ("01-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01", True),
        ("ff-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01", False),
        ("00-00000000000000000000000000000000-00f067aa0ba902b7-01", False),
        ("00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01", False),
        ("00-0AF7651916CD43DD8448EB211C80319C-00F067AA0BA902B7-01", False),
        ("00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7", False),
        ("00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01-extra", False),
        ("not a trace parent", False),
        ("", False),
        (7, False),
        (None, False),
    ],
)
async def test_a_valid_trace_parent_is_passed_on_and_any_other_is_ignored(
    client: httpx2.AsyncClient, core: FakeCore, traceparent: Any, kept: bool
) -> None:
    body = call("sandbox_list")
    if traceparent is not None:
        body["params"]["_meta"]["traceparent"] = traceparent
    response = await client.post("/mcp", json=body, headers=headers("tools/call", "sandbox_list"))
    # An invalid one is never an error.
    assert response.status_code == 200
    assert core.asked[-1].ctx.traceparent == (traceparent if kept else None)
    assert core.asked[0].ctx.traceparent is None


# ---------------------------------------------------------------------------- a call that takes long
async def test_a_long_call_is_answered_on_an_event_stream_with_keep_alives(
    app: Gateway, core: FakeCore, short_window: float
) -> None:
    """Past the SDK's window the answer is a stream, kept open by comments, that ends with the result."""
    core.hold = asyncio.Event()
    core.answers["call_tool"] = ToolAnswer(structured={"ok": True, "operation": {"state": "RUNNING"}}, is_error=False)
    exchange = post(app, call("sandbox_exec"), "tools/call", "sandbox_exec")
    running_call = asyncio.create_task(exchange.run())
    await core.handling.wait()
    await asyncio.sleep(short_window * 6)
    assert exchange.status == 200
    assert exchange.header("content-type") == "text/event-stream"
    assert exchange.header("x-accel-buffering") == "no"
    assert exchange.header("x-request-id") == core.asked[0].ctx.request_id
    assert exchange.body.count(b": ping\r\n\r\n") >= 2
    assert exchange.events() == []
    assert not exchange.complete

    core.hold.set()
    await running_call
    (message,) = exchange.events()
    assert exchange.sent[-1]["more_body"] is False
    assert message["id"] == 1
    assert message["result"]["structuredContent"] == {"ok": True, "operation": {"state": "RUNNING"}}
    assert json.loads(message["result"]["content"][0]["text"]) == message["result"]["structuredContent"]
    assert message["result"]["isError"] is False
    assert core.ops() == ["verify", "handle"]
