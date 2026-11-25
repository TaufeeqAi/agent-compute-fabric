"""The adapter's own layer: bounds, Host and Origin, method, protocol revision, and what is served where.

Everything here is decided before a credential is looked at, so in most of these tests the core is
never asked anything.
"""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import AsyncIterator
from typing import Any

import httpx2
import pytest

from acf_mcp.gateway import Gateway
from tests.support import HOST, REVISION, Exchange, FakeCore, call, headers, post, rpc, running

HEADER_MISMATCH = -32020
UNSUPPORTED_PROTOCOL_VERSION = -32022
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602


@pytest.fixture
async def browser(core: FakeCore) -> AsyncIterator[httpx2.AsyncClient]:
    """An adapter that one origin may call."""
    async with running(core, mcp={"allowed_origins": ["https://app.example/"]}) as (_, http):
        yield http


@pytest.fixture
async def named(core: FakeCore) -> AsyncIterator[httpx2.AsyncClient]:
    """An adapter whose operator listed the names it answers to."""
    async with running(core, mcp={"allowed_hosts": ["mcp.example.com", "internal:9000"]}) as (_, http):
        yield http


def _error(response: httpx2.Response) -> dict[str, Any]:
    document = response.json()
    assert document["jsonrpc"] == "2.0"
    assert set(document) == {"jsonrpc", "id", "error"}
    error: dict[str, Any] = document["error"]
    return error


# ---------------------------------------------------------------------------- method
@pytest.mark.parametrize("method", ["GET", "DELETE", "PUT", "PATCH", "OPTIONS"])
async def test_only_post_is_answered(client: httpx2.AsyncClient, core: FakeCore, method: str) -> None:
    response = await client.request(method, "/mcp", headers=headers("tools/list"))
    assert response.status_code == 405
    assert response.headers["allow"] == "POST"
    assert _error(response)["code"] == INVALID_REQUEST
    assert core.asked == []


# ---------------------------------------------------------------------------- revision
async def test_a_request_without_the_revision_header_is_told_what_is_served(
    client: httpx2.AsyncClient, core: FakeCore
) -> None:
    sent = headers("tools/list")
    del sent["mcp-protocol-version"]
    response = await client.post("/mcp", json=rpc("tools/list"), headers=sent)
    assert response.status_code == 400
    error = _error(response)
    assert error["code"] == HEADER_MISMATCH
    assert "MCP-Protocol-Version" in error["message"]
    assert REVISION in error["message"]
    assert response.json()["id"] is None
    assert core.asked == []


@pytest.mark.parametrize(
    "requested", ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05", "2026-07-29", "1900-01-01", "draft", ""]
)
async def test_another_revision_is_refused_with_the_protocols_error(
    client: httpx2.AsyncClient, core: FakeCore, requested: str
) -> None:
    response = await client.post(
        "/mcp", json=rpc("tools/list"), headers={**headers("tools/list"), "mcp-protocol-version": requested}
    )
    assert response.status_code == 400
    error = _error(response)
    assert error["code"] == UNSUPPORTED_PROTOCOL_VERSION
    assert error["data"] == {"supported": [REVISION], "requested": requested}
    assert core.asked == []


async def test_a_long_revision_value_is_not_repeated_back_whole(client: httpx2.AsyncClient) -> None:
    response = await client.post(
        "/mcp", json=rpc("tools/list"), headers={**headers("tools/list"), "mcp-protocol-version": "9" * 4000}
    )
    assert _error(response)["data"]["requested"] == "9" * 64


async def test_a_repeated_revision_header_is_refused(client: httpx2.AsyncClient, core: FakeCore) -> None:
    sent = [*headers("tools/list").items(), ("mcp-protocol-version", "2025-11-25")]
    response = await client.post("/mcp", content=json.dumps(rpc("tools/list")), headers=sent)
    assert response.status_code == 400
    assert _error(response)["code"] == HEADER_MISMATCH
    assert core.asked == []


async def test_no_handshake_of_an_earlier_revision_is_served(
    app: Gateway, client: httpx2.AsyncClient, core: FakeCore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Whatever shape a request of an earlier revision has, the SDK's code for those revisions never runs."""
    reached: list[str] = []

    async def legacy(*_args: object, **_kwargs: object) -> None:
        reached.append("legacy")

    monkeypatch.setattr(app._transport, "_handle_stateless_request", legacy)
    monkeypatch.setattr(app._transport, "_handle_stateful_request", legacy)
    handshake: dict[str, Any] = {
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": {"name": "old", "version": "1"},
    }
    initialize = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": handshake}
    plain = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
    session = {"mcp-session-id": "0123456789abcdef", "last-event-id": "7"}
    authorized = {"authorization": headers("initialize")["authorization"]}

    answers = [
        await client.post("/mcp", json=initialize, headers={**plain, **authorized}),
        await client.post(
            "/mcp", json=initialize, headers={**plain, **authorized, "mcp-protocol-version": "2025-11-25"}
        ),
        await client.post("/mcp", json=initialize, headers={**plain, **authorized, **session}),
        await client.get("/mcp", headers={**plain, **authorized, **session, "mcp-protocol-version": "2025-11-25"}),
        await client.delete("/mcp", headers={**authorized, **session, "mcp-protocol-version": "2025-11-25"}),
    ]
    assert [a.status_code for a in answers] == [400, 400, 400, 405, 405]
    assert [_error(a)["code"] for a in answers[:3]] == [HEADER_MISMATCH, UNSUPPORTED_PROTOCOL_VERSION, HEADER_MISMATCH]
    assert all("mcp-session-id" not in a.headers for a in answers)
    assert reached == []
    assert core.asked == []

    # With the header of the revision that is served, the handshake is simply not a method of it.
    modern = await client.post("/mcp", json=rpc("initialize", handshake), headers=headers("initialize"))
    assert modern.status_code == 404
    assert _error(modern)["code"] == METHOD_NOT_FOUND
    assert reached == []
    assert core.ops() == ["verify"]


# ---------------------------------------------------------------------------- headers and body of the revision
@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"mcp-method": None}, HEADER_MISMATCH),
        ({"mcp-method": "tools/list"}, HEADER_MISMATCH),
        ({"mcp-name": None}, HEADER_MISMATCH),
        ({"mcp-name": "sandbox_destroy"}, HEADER_MISMATCH),
        ({"mcp-name": "=?base64?bm90IGJhc2U2NA?="}, HEADER_MISMATCH),
    ],
)
async def test_headers_that_disagree_with_the_body_are_refused(
    client: httpx2.AsyncClient, core: FakeCore, change: dict[str, str | None], code: int
) -> None:
    sent: dict[str, str] = headers("tools/call", "sandbox_list")
    for name, value in change.items():
        if value is None:
            del sent[name]
        else:
            sent[name] = value
    response = await client.post("/mcp", json=call("sandbox_list"), headers=sent)
    assert response.status_code == 400
    assert _error(response)["code"] == code
    assert response.json()["id"] == 1
    # The caller was authenticated, and nothing was asked on its behalf.
    assert core.ops() == ["verify"]


async def test_a_revision_in_the_body_that_differs_from_the_header_is_refused(
    client: httpx2.AsyncClient, core: FakeCore
) -> None:
    body = rpc("tools/list", {"_meta": {"io.modelcontextprotocol/protocolVersion": "2025-11-25"}})
    response = await client.post("/mcp", json=body, headers=headers("tools/list"))
    assert response.status_code == 400
    assert _error(response)["code"] == HEADER_MISMATCH
    assert core.ops() == ["verify"]


@pytest.mark.parametrize(
    "missing", ["io.modelcontextprotocol/protocolVersion", "io.modelcontextprotocol/clientCapabilities"]
)
async def test_a_request_without_its_envelope_is_malformed(
    client: httpx2.AsyncClient, core: FakeCore, missing: str
) -> None:
    body = rpc("tools/list")
    del body["params"]["_meta"][missing]
    response = await client.post("/mcp", json=body, headers=headers("tools/list"))
    assert response.status_code == 400
    assert _error(response)["code"] == INVALID_PARAMS
    assert core.ops() == ["verify"]


async def test_a_name_header_in_its_encoded_form_is_compared_decoded(
    client: httpx2.AsyncClient, core: FakeCore
) -> None:
    encoded = "=?base64?" + base64.b64encode(b"sandbox_list").decode("ascii") + "?="
    response = await client.post("/mcp", json=call("sandbox_list"), headers=headers("tools/call", encoded))
    assert response.status_code == 200
    assert core.ops() == ["verify", "handle"]


@pytest.mark.parametrize(
    ("method", "params"),
    [
        ("ping", {}),
        ("resources/list", {}),
        ("prompts/list", {}),
        ("subscriptions/listen", {"notifications": {"toolsListChanged": True}}),
        ("tasks/get", {"taskId": "t-1"}),
        ("nope", {}),
    ],
)
async def test_a_method_that_is_not_served_is_not_found(
    client: httpx2.AsyncClient, core: FakeCore, method: str, params: dict[str, Any]
) -> None:
    response = await client.post("/mcp", json=rpc(method, params), headers=headers(method))
    assert response.status_code == 404
    assert _error(response)["code"] == METHOD_NOT_FOUND
    assert core.ops() == ["verify"]


async def test_a_notification_is_acknowledged_and_goes_nowhere(client: httpx2.AsyncClient, core: FakeCore) -> None:
    """Cancellation on this transport is closing the stream. A posted notification cancels nothing."""
    notification = {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}}
    response = await client.post("/mcp", json=notification, headers=headers("notifications/cancelled"))
    assert response.status_code == 202
    assert response.content == b""
    assert core.ops() == ["verify"]


@pytest.mark.parametrize("body", [b"{not json", b"[]", b'{"jsonrpc":"2.0","id":1,"result":{}}'])
async def test_a_body_that_is_not_one_request_is_refused(
    client: httpx2.AsyncClient, core: FakeCore, body: bytes
) -> None:
    response = await client.post("/mcp", content=body, headers=headers("tools/list"))
    assert response.status_code == 400
    assert _error(response)["code"] in {-32700, INVALID_REQUEST}
    assert core.ops() == ["verify"]


# ---------------------------------------------------------------------------- Origin
async def test_a_request_without_an_origin_is_served(client: httpx2.AsyncClient) -> None:
    response = await client.post("/mcp", json=rpc("tools/list"), headers=headers("tools/list"))
    assert response.status_code == 200


@pytest.mark.parametrize("origin", ["https://app.example", "HTTPS://APP.EXAMPLE"])
async def test_a_listed_origin_is_served(browser: httpx2.AsyncClient, origin: str) -> None:
    response = await browser.post("/mcp", json=rpc("tools/list"), headers={**headers("tools/list"), "origin": origin})
    assert response.status_code == 200


@pytest.mark.parametrize(
    "origin",
    [
        "https://evil.example",
        "http://app.example",
        "https://app.example:8443",
        "https://app.example.evil.example",
        "null",
    ],
)
async def test_an_origin_that_is_not_listed_is_refused(
    browser: httpx2.AsyncClient, core: FakeCore, origin: str
) -> None:
    response = await browser.post("/mcp", json=rpc("tools/list"), headers={**headers("tools/list"), "origin": origin})
    assert response.status_code == 403
    assert _error(response)["code"] == INVALID_REQUEST
    assert response.json()["id"] is None
    assert core.asked == []


async def test_with_no_origin_listed_every_origin_is_refused(client: httpx2.AsyncClient, core: FakeCore) -> None:
    response = await client.post(
        "/mcp", json=rpc("tools/list"), headers={**headers("tools/list"), "origin": f"http://{HOST}"}
    )
    assert response.status_code == 403
    assert core.asked == []


async def test_two_origins_are_refused(browser: httpx2.AsyncClient, core: FakeCore) -> None:
    sent = [*headers("tools/list").items(), ("origin", "https://app.example"), ("origin", "https://evil.example")]
    response = await browser.post("/mcp", content=json.dumps(rpc("tools/list")), headers=sent)
    assert response.status_code == 403
    assert core.asked == []


async def test_the_origin_is_checked_on_every_path(browser: httpx2.AsyncClient) -> None:
    response = await browser.get("/.well-known/oauth-protected-resource", headers={"origin": "https://evil.example"})
    assert response.status_code == 403


# ---------------------------------------------------------------------------- Host
@pytest.mark.parametrize("host", [HOST, "127.0.0.1", "localhost", "localhost:9999", "LOCALHOST:8443"])
async def test_the_listen_address_and_localhost_are_answered(client: httpx2.AsyncClient, host: str) -> None:
    response = await client.post("/mcp", json=rpc("tools/list"), headers={**headers("tools/list"), "host": host})
    assert response.status_code == 200


@pytest.mark.parametrize(
    "host", ["evil.example", "evil.example:8443", "127.0.0.1.evil.example", "[::1]:8443", "a b", ""]
)
async def test_another_host_is_refused(client: httpx2.AsyncClient, core: FakeCore, host: str) -> None:
    """A page that rebinds its own name to this address still sends its own name."""
    response = await client.post("/mcp", json=rpc("tools/list"), headers={**headers("tools/list"), "host": host})
    assert response.status_code == 421
    assert _error(response)["code"] == INVALID_REQUEST
    assert core.asked == []


async def test_a_request_without_a_host_is_refused(app: Gateway, core: FakeCore) -> None:
    exchange = Exchange(app, headers=headers("tools/list"), chunks=[json.dumps(rpc("tools/list")).encode()])
    await exchange.run()
    assert exchange.status == 421
    assert core.asked == []


@pytest.mark.parametrize(
    ("host", "status"),
    [
        ("mcp.example.com", 200),
        ("mcp.example.com:443", 200),
        ("internal:9000", 200),
        ("internal:9001", 421),
        ("internal", 421),
        (HOST, 421),
        ("localhost", 421),
    ],
)
async def test_a_configured_list_of_hosts_replaces_the_defaults(
    named: httpx2.AsyncClient, host: str, status: int
) -> None:
    response = await named.post("/mcp", json=rpc("tools/list"), headers={**headers("tools/list"), "host": host})
    assert response.status_code == status


async def test_the_configured_resource_is_a_name_the_endpoint_answers_to(core: FakeCore) -> None:
    oauth = {"resource": "https://mcp.example.com/mcp", "authorization_servers": ["https://login.example.com"]}
    async with running(core, mcp=oauth) as (_, http):
        sent = {**headers("tools/list"), "host": "mcp.example.com"}
        assert (await http.post("/mcp", json=rpc("tools/list"), headers=sent)).status_code == 200


# ---------------------------------------------------------------------------- bounds
async def test_a_body_declared_larger_than_the_bound_is_refused_unread(core: FakeCore) -> None:
    async with running(core, limits={"max_public_request_bytes": 1024}) as (gateway, _):
        exchange = Exchange(
            gateway,
            headers={"host": HOST, **headers("tools/list"), "content-length": "1025"},
            chunks=[b"x" * 1025],
        )
        await exchange.run()
    assert exchange.status == 413
    assert json.loads(exchange.body)["error"]["code"] == INVALID_REQUEST
    assert exchange.body_reads == 0
    # Bounds come before the credential: an oversize request costs the core nothing.
    assert core.asked == []


async def test_a_body_that_grows_past_the_bound_is_refused_when_it_does(core: FakeCore) -> None:
    async with running(core, limits={"max_public_request_bytes": 1024}) as (gateway, _):
        exchange = Exchange(gateway, headers={"host": HOST, **headers("tools/list")}, chunks=[b"x" * 400] * 10)
        await exchange.run()
    assert exchange.status == 413
    # Three pieces make 1200 bytes. The seven behind them were never asked for.
    assert exchange.body_reads == 3
    assert core.ops() == ["verify"]


async def test_a_body_of_exactly_the_bound_is_read(core: FakeCore) -> None:
    body = json.dumps(rpc("tools/list")).encode()
    padded = body[:-1] + b" " * (1024 - len(body)) + body[-1:]
    assert len(padded) == 1024
    async with running(core, limits={"max_public_request_bytes": 1024}) as (gateway, _):
        exchange = Exchange(gateway, headers={"host": HOST, **headers("tools/list")}, chunks=[padded])
        await exchange.run()
    assert exchange.status == 200
    assert core.ops() == ["verify", "handle"]


@pytest.mark.parametrize("declared", ["12a", "-1", "1 2", "\N{ARABIC-INDIC DIGIT THREE}"])
async def test_a_declared_length_that_is_not_a_number_is_refused(app: Gateway, core: FakeCore, declared: str) -> None:
    sent = {"host": HOST, **headers("tools/list"), "content-length": declared}
    exchange = Exchange(app, headers={k: v.encode("utf-8").decode("latin-1") for k, v in sent.items()})
    await exchange.run()
    assert exchange.status == 400
    assert core.asked == []


async def test_a_declared_length_too_long_to_be_a_length_is_refused(app: Gateway, core: FakeCore) -> None:
    exchange = Exchange(app, headers={"host": HOST, **headers("tools/list"), "content-length": "9" * 9000})
    await exchange.run()
    assert exchange.status == 413
    assert core.asked == []


async def test_a_body_that_does_not_arrive_in_time_is_refused(core: FakeCore) -> None:
    async with running(core, limits={"body_read_timeout": 0.05}) as (gateway, _):
        exchange = post(gateway, rpc("tools/list"), "tools/list")
        exchange.body_gate = asyncio.Event()
        await exchange.run()
    assert exchange.status == 400
    assert "in time" in json.loads(exchange.body)["error"]["message"]
    assert core.ops() == ["verify"]


async def test_a_caller_that_leaves_before_its_request_is_whole_is_not_parsed(app: Gateway, core: FakeCore) -> None:
    """Nothing is handed on to be parsed, nothing is answered, and nothing is raised into the server's log."""
    exchange = Exchange(
        app,
        headers={"host": HOST, **headers("tools/list")},
        chunks=[b'{"jsonrpc":"2.0","id":1,', b'"method":"tools/list"}'],
    )
    exchange.body_gate = asyncio.Event()
    leaving = asyncio.create_task(exchange.run())
    await asyncio.sleep(0.02)
    exchange.disconnect()
    exchange.body_gate.set()
    await leaving
    assert exchange.sent == []
    assert exchange.dropped == []
    assert core.ops() == ["verify"]


@pytest.mark.parametrize(
    ("change", "status"),
    [
        ({"accept": "application/json"}, 406),
        ({"accept": "text/event-stream"}, 406),
        ({"accept": "text/html"}, 406),
        ({"content-type": "text/plain"}, 400),
        ({"content-type": "application/x-www-form-urlencoded"}, 400),
    ],
)
async def test_a_request_that_does_not_speak_the_transport_is_refused(
    client: httpx2.AsyncClient, core: FakeCore, change: dict[str, str], status: int
) -> None:
    """The transport is a POST of JSON whose sender accepts a JSON object or an event stream."""
    response = await client.post(
        "/mcp", content=json.dumps(rpc("tools/list")), headers={**headers("tools/list"), **change}
    )
    assert response.status_code == status
    assert core.ops() == ["verify"]


async def test_a_session_of_an_earlier_revision_is_neither_used_nor_echoed(
    client: httpx2.AsyncClient, core: FakeCore
) -> None:
    sent = {**headers("tools/list"), "mcp-session-id": "0123456789abcdef", "last-event-id": "42"}
    response = await client.post("/mcp", json=rpc("tools/list"), headers=sent)
    assert response.status_code == 200
    assert "mcp-session-id" not in response.headers
    assert core.ops() == ["verify", "handle"]


# ---------------------------------------------------------------------------- what is served where
@pytest.mark.parametrize(
    "path", ["/", "/mcp/", "/mcp/x", "/v1/info", "/healthz", "/.well-known/oauth-protected-resource"]
)
async def test_no_other_path_is_served(client: httpx2.AsyncClient, core: FakeCore, path: str) -> None:
    response = await client.post(path, json=rpc("tools/list"), headers=headers("tools/list"))
    assert response.status_code == 404
    # No JSON-RPC body: that would tell a client that an endpoint of this protocol is here.
    assert response.content == b""
    assert core.asked == []


async def test_the_endpoint_is_served_at_the_configured_path(core: FakeCore) -> None:
    async with running(core, mcp={"path": "/agents/v1"}) as (_, http):
        assert (await http.post("/agents/v1", json=rpc("tools/list"), headers=headers("tools/list"))).status_code == 200
        assert (await http.post("/mcp", json=rpc("tools/list"), headers=headers("tools/list"))).status_code == 404


async def test_every_answer_to_an_authenticated_request_names_the_request(
    client: httpx2.AsyncClient, core: FakeCore
) -> None:
    response = await client.post("/mcp", json=rpc("tools/list"), headers=headers("tools/list"))
    assert response.headers["x-request-id"] == core.asked[0].ctx.request_id
    assert core.asked[0].ctx.request_id == core.asked[1].ctx.request_id


async def test_the_core_client_is_closed_when_the_process_stops(core: FakeCore) -> None:
    async with running(core):
        assert not core.closed
    assert core.closed
