"""The adapter, as the client the ecosystem uses sees it.

The official SDK's client is driven against the application in process: it negotiates the revision,
lists the tools and calls one, with nothing between it and the adapter but an HTTP transport that
needs no socket.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx2
import pytest
from mcp import Client, MCPError
from mcp.client.streamable_http import streamable_http_client

from acf_api.command.answers import Challenge, ErrorAnswer, ProtocolFaultAnswer, ToolAnswer, ToolsAnswer
from acf_api.command.commands import CallTool, Discover, ListTools
from acf_api.command.model import ErrorBody
from acf_mcp.gateway import Gateway
from tests.support import BASE_URL, CANARY, REVISION, FakeCore, catalogue, tool

ENDPOINT = f"{BASE_URL}/mcp"


@pytest.fixture
async def http(app: Gateway) -> AsyncIterator[httpx2.AsyncClient]:
    """The HTTP client the SDK is given: it carries the credential, as an agent host would configure it."""
    transport = httpx2.ASGITransport(app=app)
    async with httpx2.AsyncClient(transport=transport, headers={"Authorization": f"Bearer {CANARY}"}) as client:
        yield client


async def test_the_official_client_negotiates_lists_and_calls(http: httpx2.AsyncClient, core: FakeCore) -> None:
    core.answers["call_tool"] = ToolAnswer(structured={"ok": True, "sandboxes": []}, is_error=False)
    async with Client(streamable_http_client(ENDPOINT, http_client=http)) as client:
        assert client.protocol_version == REVISION
        assert client.server_info is not None
        assert (client.server_info.name, client.server_info.version) == ("agent-compute-fabric", "9.9.9")
        assert client.instructions == "Tools for isolated sandboxes."
        assert client.server_capabilities.tools is not None
        assert client.server_capabilities.experimental == {
            "acf": {"platform_features": ["agent_credentials", "long_poll"], "host_features": ["allowlist_network"]}
        }

        listed = await client.list_tools()
        assert [t.name for t in listed.tools] == ["sandbox_list"]
        assert listed.tools[0].annotations is not None
        assert listed.tools[0].annotations.read_only_hint is True

        result = await client.call_tool("sandbox_list", {"limit": 2})
        assert result.is_error is False
        assert result.structured_content == {"ok": True, "sandboxes": []}
        assert [block.text for block in result.content if block.type == "text"] == ['{"ok":true,"sandboxes":[]}']

    commands = core.commands()
    assert commands[0] == Discover()
    assert ListTools() in commands
    assert [c for c in commands if isinstance(c, CallTool)] == [CallTool(name="sandbox_list", arguments={"limit": 2})]
    assert {a.credential for a in core.asked} == {CANARY}
    assert {a.ctx.client.name for a in core.asked if a.op == "handle"} == {"mcp"}


async def test_the_official_client_accepts_the_whole_published_catalogue(
    http: httpx2.AsyncClient, core: FakeCore
) -> None:
    """A client drops a tool whose definition it finds invalid. It drops none of these."""
    published = catalogue()
    core.answers["list_tools"] = ToolsAnswer(tools=[definition for _, definition in published])
    async with Client(streamable_http_client(ENDPOINT, http_client=http)) as client:
        listed = await client.list_tools()
    assert [t.name for t in listed.tools] == [document["name"] for document, _ in published]
    for listed_tool, (document, _) in zip(listed.tools, published, strict=True):
        assert listed_tool.input_schema == document["inputSchema"]
        assert listed_tool.output_schema == document["outputSchema"]


async def test_the_official_client_reads_a_refusal_as_a_result(http: httpx2.AsyncClient, core: FakeCore) -> None:
    core.answers["list_tools"] = ToolsAnswer(tools=[tool("sandbox_exec", output_schema={"type": "object"})])
    error = ErrorBody(
        code="STATE_CONFLICT",
        kind="REFUSED",
        retry="AFTER_CHANGE",
        message="the sandbox is not started",
        request_id="req_" + "e" * 24,
    )
    core.answers["call_tool"] = ErrorAnswer(error=error)
    async with Client(streamable_http_client(ENDPOINT, http_client=http)) as client:
        result = await client.call_tool("sandbox_exec", {"argv": ["true"]})
    assert result.is_error is True
    assert result.structured_content == {"ok": False, "error": error.model_dump(mode="json", exclude_none=True)}


async def test_the_official_client_reads_a_protocol_fault_as_an_error(http: httpx2.AsyncClient, core: FakeCore) -> None:
    core.answers["call_tool"] = ProtocolFaultAnswer(fault="unknown_tool", message="no such tool")
    async with Client(streamable_http_client(ENDPOINT, http_client=http)) as client:
        with pytest.raises(MCPError) as raised:
            await client.call_tool("sandbox_teleport", {})
    assert raised.value.code == -32602
    assert raised.value.message == "no such tool"
    assert raised.value.data == {"fault": "unknown_tool"}


async def test_a_client_pinned_to_this_revision_is_told_why_it_was_not_let_in(app: Gateway, core: FakeCore) -> None:
    """The core's message, not a stand-in for an HTTP status, is what the developer gets to read."""
    core.verified = ErrorAnswer(
        error=ErrorBody(
            code="UNAUTHENTICATED",
            kind="REFUSED",
            retry="NEVER",
            message="the request carries no credential that authenticates",
            request_id="req_" + "f" * 24,
        ),
        challenge=Challenge(www_authenticate="Bearer"),
    )
    transport = httpx2.ASGITransport(app=app)
    async with (
        httpx2.AsyncClient(transport=transport, headers={"Authorization": "Bearer wrong"}) as wrong,
        Client(streamable_http_client(ENDPOINT, http_client=wrong), mode=REVISION) as client,
    ):
        with pytest.raises(MCPError) as raised:
            await client.list_tools()
    assert raised.value.message == "the request carries no credential that authenticates"
    assert raised.value.data["code"] == "UNAUTHENTICATED"
    assert core.ops() == ["verify"]
