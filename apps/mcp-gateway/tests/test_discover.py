"""`server/discover`: what the platform says about itself, relayed from the core."""

from __future__ import annotations

import httpx2

from acf_api.command.answers import DiscoverAnswer
from acf_api.command.commands import Discover
from acf_mcp import __version__
from acf_mcp.relay import Relay
from tests.support import REVISION, FakeCore, headers, rpc


async def _discover(client: httpx2.AsyncClient) -> httpx2.Response:
    return await client.post("/mcp", json=rpc("server/discover"), headers=headers("server/discover"))


async def test_discovery_is_the_cores_answer(client: httpx2.AsyncClient, core: FakeCore) -> None:
    response = await _discover(client)
    assert response.status_code == 200
    assert response.json()["result"] == {
        "resultType": "complete",
        "supportedVersions": [REVISION],
        "capabilities": {
            "tools": {"listChanged": False},
            # The place the protocol keeps for capabilities it does not define.
            "experimental": {
                "acf": {"platform_features": ["agent_credentials", "long_poll"], "host_features": ["allowlist_network"]}
            },
        },
        "instructions": "Tools for isolated sandboxes.",
        "ttlMs": 0,
        "cacheScope": "private",
        "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "agent-compute-fabric", "version": "9.9.9"}},
    }
    assert core.commands() == [Discover()]


async def test_what_the_core_does_not_report_is_not_advertised(client: httpx2.AsyncClient, core: FakeCore) -> None:
    core.answers["discover"] = DiscoverAnswer(
        server_name="agent-compute-fabric",
        server_version="1.0.0",
        instructions="",
        platform_features=[],
        host_features=[],
    )
    result = (await _discover(client)).json()["result"]
    assert result["capabilities"]["experimental"] == {"acf": {"platform_features": [], "host_features": []}}
    assert "instructions" not in result


async def test_nothing_advertises_the_tasks_extension_or_any_other(client: httpx2.AsyncClient, core: FakeCore) -> None:
    """Even when the platform's own feature list has a feature of that name: a feature is not an extension."""
    core.answers["discover"] = DiscoverAnswer(
        server_name="agent-compute-fabric",
        server_version="1.0.0",
        instructions="",
        platform_features=["io.modelcontextprotocol/tasks", "tasks"],
        host_features=[],
    )
    capabilities = (await _discover(client)).json()["result"]["capabilities"]
    assert set(capabilities) == {"tools", "experimental"}
    assert "extensions" not in capabilities
    assert "tasks" not in capabilities
    assert set(capabilities["experimental"]) == {"acf"}


async def test_only_this_revision_is_advertised(client: httpx2.AsyncClient) -> None:
    assert (await _discover(client)).json()["result"]["supportedVersions"] == ["2026-07-28"]


async def test_discovery_needs_a_credential_like_everything_else(client: httpx2.AsyncClient, core: FakeCore) -> None:
    await client.post("/mcp", json=rpc("server/discover"), headers=headers("server/discover", credential=None))
    assert [(a.op, a.credential) for a in core.asked] == [("verify", None), ("handle", None)]


async def test_other_results_name_the_software_that_wrote_them(client: httpx2.AsyncClient) -> None:
    """What the platform is called is the core's to say, in discovery. This process only says what it is."""
    result = (await client.post("/mcp", json=rpc("tools/list"), headers=headers("tools/list"))).json()["result"]
    assert result["_meta"] == {
        "io.modelcontextprotocol/serverInfo": {"name": "acf-mcp-gateway", "version": __version__}
    }


def test_the_adapter_starts_no_telemetry_span_of_its_own(core: FakeCore) -> None:
    """The SDK's default would name a span after `params.name` as a caller sent it."""
    assert Relay(core, 27_000).server().middleware == []
