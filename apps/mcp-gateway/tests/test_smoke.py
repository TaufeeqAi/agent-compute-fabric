"""The shortest path through the adapter: list the tools, call one."""

from __future__ import annotations

import json

import httpx2

from acf_api.command.commands import CallTool, ListTools
from tests.support import CANARY, FakeCore, call, headers, rpc


async def test_list_then_call(client: httpx2.AsyncClient, core: FakeCore) -> None:
    listed = await client.post("/mcp", json=rpc("tools/list"), headers=headers("tools/list"))
    assert listed.status_code == 200, listed.text
    assert [t["name"] for t in listed.json()["result"]["tools"]] == ["sandbox_list"]

    called = await client.post(
        "/mcp", json=call("sandbox_list", {"limit": 3}), headers=headers("tools/call", "sandbox_list")
    )
    assert called.status_code == 200, called.text
    result = called.json()["result"]
    assert result["structuredContent"] == {"ok": True}
    assert json.loads(result["content"][0]["text"]) == {"ok": True}
    assert result["isError"] is False

    assert core.ops() == ["verify", "handle", "verify", "handle"]
    assert core.commands() == [ListTools(), CallTool(name="sandbox_list", arguments={"limit": 3})]
    assert {a.credential for a in core.asked} == {CANARY}
