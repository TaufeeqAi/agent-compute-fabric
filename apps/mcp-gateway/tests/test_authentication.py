"""The adapter authenticates nobody and authorizes nothing: it carries a credential in and a verdict out.

What is tested here is the carrying: where the credential is read from, when the core is asked, and
that the core's challenge reaches the caller exactly as the core computed it.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
from typing import Any

import httpx2
import pytest

from acf_api.command.answers import Challenge, ErrorAnswer, ToolAnswer
from acf_api.command.model import ErrorBody
from acf_mcp.gateway import Gateway, Settings
from tests.support import CANARY, FakeCore, call, headers, post, rpc, running

RESOURCE_METADATA = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
UNAUTHENTICATED_CHALLENGE = f'Bearer resource_metadata="{RESOURCE_METADATA}"'
STEP_UP_CHALLENGE = (
    f'Bearer error="insufficient_scope", scope="acf:sandbox.exec", resource_metadata="{RESOURCE_METADATA}"'
)


def refusal(
    code: str, *, challenge: str | None = None, retry: str = "NEVER", retry_after_s: int | None = None
) -> ErrorAnswer:
    return ErrorAnswer(
        error=ErrorBody(
            code=code, kind="REFUSED", retry=retry, message=f"the core says {code}", request_id="req_" + "a" * 24
        ),
        retry_after_s=retry_after_s,
        challenge=Challenge(www_authenticate=challenge) if challenge is not None else None,
    )


def _error(body: bytes) -> dict[str, Any]:
    document = json.loads(body)
    assert set(document) == {"jsonrpc", "id", "error"}
    error: dict[str, Any] = document["error"]
    return error


# ---------------------------------------------------------------------------- the order
async def test_the_core_is_asked_before_a_byte_of_the_body_is_read(app: Gateway, core: FakeCore) -> None:
    exchange = post(app, call("sandbox_list"), "tools/call", "sandbox_list")
    core.watching = exchange
    await exchange.run()
    assert exchange.status == 200
    check, command = core.asked
    assert (check.op, check.body_reads) == ("verify", 0)
    assert (command.op, command.body_reads) == ("handle", 1)


async def test_a_caller_that_does_not_authenticate_never_has_its_body_read(app: Gateway, core: FakeCore) -> None:
    core.verified = refusal("UNAUTHENTICATED", challenge=UNAUTHENTICATED_CHALLENGE)
    exchange = post(app, call("sandbox_list"), "tools/call", "sandbox_list")
    core.watching = exchange
    await exchange.run()
    assert exchange.status == 401
    assert exchange.header("www-authenticate") == UNAUTHENTICATED_CHALLENGE
    assert exchange.body_reads == 0
    assert core.ops() == ["verify"]
    error = _error(exchange.body)
    assert error["message"] == "the core says UNAUTHENTICATED"
    assert error["data"]["code"] == "UNAUTHENTICATED"
    assert error["data"]["kind"] == "REFUSED"
    assert json.loads(exchange.body)["id"] is None


# ---------------------------------------------------------------------------- where the credential is read from
async def test_the_credential_goes_to_the_core_unchanged(client: httpx2.AsyncClient, core: FakeCore) -> None:
    await client.post("/mcp", json=rpc("tools/list"), headers=headers("tools/list"))
    assert [a.credential for a in core.asked] == [CANARY, CANARY]


@pytest.mark.parametrize("scheme", ["Bearer", "bearer", "BEARER"])
async def test_the_scheme_is_read_without_regard_to_case(
    client: httpx2.AsyncClient, core: FakeCore, scheme: str
) -> None:
    sent = {**headers("tools/list"), "authorization": f"{scheme} {CANARY}"}
    await client.post("/mcp", json=rpc("tools/list"), headers=sent)
    assert core.asked[0].credential == CANARY


@pytest.mark.parametrize(
    "authorization",
    [
        None,
        "",
        "Bearer",
        "Bearer ",
        f"Basic {CANARY}",
        f"Token {CANARY}",
        CANARY,
        "Bearer " + "x" * 16385,
        b"Bearer cl\xe9",
    ],
)
async def test_anything_else_is_no_credential_and_the_core_says_so(
    client: httpx2.AsyncClient, core: FakeCore, authorization: str | bytes | None
) -> None:
    """The adapter does not judge a missing credential. It asks the core, which answers with its challenge."""
    core.verified = refusal("UNAUTHENTICATED", challenge=UNAUTHENTICATED_CHALLENGE)
    sent = {k.encode("ascii"): v.encode("ascii") for k, v in headers("tools/list", credential=None).items()}
    if authorization is not None:
        sent[b"authorization"] = authorization if isinstance(authorization, bytes) else authorization.encode("ascii")
    response = await client.post("/mcp", json=rpc("tools/list"), headers=sent)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == UNAUTHENTICATED_CHALLENGE
    assert [(a.op, a.credential) for a in core.asked] == [("verify", None)]


async def test_two_authorization_headers_are_no_credential(app: Gateway, core: FakeCore) -> None:
    core.verified = refusal("UNAUTHENTICATED", challenge="Bearer")
    exchange = post(app, rpc("tools/list"), "tools/list")
    scope = exchange.scope
    scope["headers"] = [*scope["headers"], (b"authorization", b"Bearer another")]
    await app(scope, exchange.receive, exchange.send)
    assert exchange.status == 401
    assert core.asked[0].credential is None


@pytest.mark.parametrize(
    "query",
    [
        b"access_token=" + CANARY.encode(),
        b"api_key=x",
        b"apikey=x",
        b"key=x",
        b"token=x",
        b"Authorization=Bearer+x",
        b"ACCESS_TOKEN=x",
    ],
)
async def test_a_credential_in_the_url_is_refused(app: Gateway, core: FakeCore, query: bytes) -> None:
    """Refused even beside a good header: a URL is logged by everything it passes through."""
    exchange = post(app, rpc("tools/list"), "tools/list", query=query)
    await exchange.run()
    assert exchange.status == 400
    assert "never accepted in a URL" in _error(exchange.body)["message"]
    assert exchange.body_reads == 0
    assert core.asked == []


@pytest.mark.parametrize("query", [b"x=1", b"session=abc", b"=", b"a"])
async def test_the_endpoint_takes_no_query_parameters(app: Gateway, core: FakeCore, query: bytes) -> None:
    exchange = post(app, rpc("tools/list"), "tools/list", query=query)
    await exchange.run()
    assert exchange.status == 400
    assert "no query parameters" in _error(exchange.body)["message"]
    assert core.asked == []


# ---------------------------------------------------------------------------- what the check can answer
async def test_a_check_that_could_not_be_made_is_not_an_authentication_failure(
    client: httpx2.AsyncClient, core: FakeCore
) -> None:
    """A client that is told 401 throws its token away. Only the core's own verdict may say that."""
    core.verified = refusal("UPSTREAM_UNAVAILABLE", retry="SAME_REQUEST_LATER", retry_after_s=1)
    response = await client.post("/mcp", json=rpc("tools/list"), headers=headers("tools/list"))
    assert response.status_code == 503
    assert response.headers["retry-after"] == "1"
    assert "www-authenticate" not in response.headers
    assert response.json()["error"]["data"]["code"] == "UPSTREAM_UNAVAILABLE"
    assert core.ops() == ["verify"]


async def test_an_edge_with_too_much_in_flight_says_so(client: httpx2.AsyncClient, core: FakeCore) -> None:
    core.verified = refusal("RATE_LIMITED", retry="SAME_REQUEST_LATER", retry_after_s=1)
    response = await client.post("/mcp", json=rpc("tools/list"), headers=headers("tools/list"))
    assert response.status_code == 429
    assert response.headers["retry-after"] == "1"
    assert "www-authenticate" not in response.headers


async def test_a_401_always_carries_a_challenge(client: httpx2.AsyncClient, core: FakeCore) -> None:
    core.verified = refusal("UNAUTHENTICATED")
    response = await client.post("/mcp", json=rpc("tools/list"), headers=headers("tools/list"))
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize("challenge", ['Bearer realm="x"\r\nSet-Cookie: a=b', "Bearer \x00", "Bearer caf\xe9", ""])
async def test_a_challenge_that_cannot_be_a_header_is_not_sent(
    client: httpx2.AsyncClient, core: FakeCore, challenge: str
) -> None:
    core.verified = refusal("UNAUTHENTICATED", challenge=challenge)
    response = await client.post("/mcp", json=rpc("tools/list"), headers=headers("tools/list"))
    assert response.status_code == 500
    assert "www-authenticate" not in response.headers
    assert "set-cookie" not in response.headers


async def test_an_answer_that_is_neither_yes_nor_no_is_not_a_yes(client: httpx2.AsyncClient, core: FakeCore) -> None:
    core.verified = ToolAnswer(structured={"ok": True}, is_error=False)
    response = await client.post("/mcp", json=rpc("tools/list"), headers=headers("tools/list"))
    assert response.status_code == 500
    assert core.ops() == ["verify"]


# ---------------------------------------------------------------------------- the challenge of a later command
@pytest.mark.parametrize(
    ("method", "name"), [("tools/call", "sandbox_exec"), ("tools/list", None), ("server/discover", None)]
)
async def test_a_scope_challenge_is_relayed_as_403(
    client: httpx2.AsyncClient, core: FakeCore, method: str, name: str | None
) -> None:
    """The step-up answer of MCP authorization. The scope it names is the core's; the adapter holds none."""
    denied = refusal("PERMISSION_DENIED", challenge=STEP_UP_CHALLENGE)
    core.answers.update(call_tool=denied, list_tools=denied, discover=denied)
    body = call(name) if name is not None else rpc(method)
    response = await client.post("/mcp", json=body, headers=headers(method, name))
    assert response.status_code == 403
    assert response.headers["www-authenticate"] == STEP_UP_CHALLENGE
    document = response.json()
    assert document["id"] == 1
    assert document["error"]["message"] == "the core says PERMISSION_DENIED"
    assert document["error"]["data"]["code"] == "PERMISSION_DENIED"
    assert response.headers["x-request-id"] == core.asked[0].ctx.request_id
    assert core.ops() == ["verify", "handle"]


async def test_a_credential_that_stopped_authenticating_after_the_check_is_a_401(
    client: httpx2.AsyncClient, core: FakeCore
) -> None:
    core.answers["call_tool"] = refusal("UNAUTHENTICATED", challenge=UNAUTHENTICATED_CHALLENGE)
    response = await client.post("/mcp", json=call("sandbox_list"), headers=headers("tools/call", "sandbox_list"))
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == UNAUTHENTICATED_CHALLENGE


async def test_a_denial_without_a_challenge_is_a_result_an_agent_can_read(
    client: httpx2.AsyncClient, core: FakeCore
) -> None:
    core.answers["call_tool"] = refusal("PERMISSION_DENIED")
    response = await client.post("/mcp", json=call("sandbox_exec"), headers=headers("tools/call", "sandbox_exec"))
    assert response.status_code == 200
    assert "www-authenticate" not in response.headers
    result = response.json()["result"]
    assert result["isError"] is True
    assert result["structuredContent"]["error"]["code"] == "PERMISSION_DENIED"


async def test_on_a_stream_that_has_begun_the_challenge_can_only_be_a_result(
    app: Gateway, core: FakeCore, short_window: float
) -> None:
    """The status line is gone by then. What is left is the form every other refusal of a call has."""
    core.answers["call_tool"] = refusal("PERMISSION_DENIED", challenge=STEP_UP_CHALLENGE)
    core.hold = asyncio.Event()
    exchange = post(app, call("sandbox_exec"), "tools/call", "sandbox_exec")
    running_call = asyncio.create_task(exchange.run())
    await core.handling.wait()
    await asyncio.sleep(short_window * 4)
    assert exchange.status == 200
    assert exchange.header("content-type") == "text/event-stream"
    core.hold.set()
    await running_call
    assert exchange.header("www-authenticate") is None
    (message,) = exchange.events()
    assert message["result"]["isError"] is True
    assert message["result"]["structuredContent"]["error"]["code"] == "PERMISSION_DENIED"


# ---------------------------------------------------------------------------- no table of its own
def test_the_adapter_keeps_no_table_of_scopes_or_grants() -> None:
    """What it keeps from its configuration is transport: where, how much, how long, which names."""
    assert {f.name for f in dataclasses.fields(Settings)} == {
        "path",
        "max_body_bytes",
        "body_read_timeout",
        "budget_ms",
        "hosts",
        "hosts_with_port",
        "origins",
        "metadata",
    }


async def test_the_configured_scopes_change_the_published_document_and_nothing_else(core: FakeCore) -> None:
    oauth = {"resource": "https://mcp.example.com/mcp", "authorization_servers": ["https://login.example.com"]}
    answers: list[tuple[int, Any, list[str]]] = []
    for scopes in ([], ["acf:sandbox.exec"], ["something:else"]):
        core.asked.clear()
        async with running(core, mcp={**oauth, "scopes_supported": scopes}) as (_, http):
            sent = {**headers("tools/call", "sandbox_exec"), "host": "mcp.example.com"}
            response = await http.post("/mcp", json=call("sandbox_exec"), headers=sent)
            answers.append((response.status_code, response.json()["result"], core.ops()))
    assert answers[0] == answers[1] == answers[2]
