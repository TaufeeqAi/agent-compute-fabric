"""The caller's credential goes to the core with every command, and nowhere else.

A canary credential is sent through every kind of exchange the adapter has, including the ones that
fail. It must then be found in what the core was sent and in nothing this process wrote: no response,
no log record at any level, no error.
"""

from __future__ import annotations

import asyncio
import logging
import traceback
from collections.abc import Iterator
from typing import Any

import httpx2
import pytest

from acf_api.command.answers import Challenge, ErrorAnswer, ProtocolFaultAnswer, ToolAnswer, ViewAnswer
from acf_api.command.model import ErrorBody
from acf_mcp import exchange as exchange_module
from acf_mcp.asgi import Message
from acf_mcp.gateway import Gateway
from tests.support import CANARY, Exchange, FakeCore, call, headers, post, rpc


class Everything(logging.Handler):
    """Keeps every record of every logger, with everything a formatter or an exporter could print."""

    def __init__(self) -> None:
        super().__init__(level=logging.NOTSET)
        self.written: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        parts = [record.getMessage(), repr(record.__dict__)]
        if record.exc_info:
            parts.append("".join(traceback.format_exception(*record.exc_info)))
        self.written.append("\n".join(parts))


@pytest.fixture
def logs() -> Iterator[Everything]:
    root = logging.getLogger()
    handler = Everything()
    before = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    try:
        yield handler
    finally:
        root.removeHandler(handler)
        root.setLevel(before)


def refusal(code: str, challenge: str | None = None) -> ErrorAnswer:
    return ErrorAnswer(
        error=ErrorBody(
            code=code, kind="REFUSED", retry="NEVER", message=f"the core says {code}", request_id="req_" + "a" * 24
        ),
        challenge=Challenge(www_authenticate=challenge) if challenge is not None else None,
    )


def _written(exchange: Exchange) -> str:
    return repr(exchange.sent) + repr(exchange.dropped)


async def test_the_canary_is_in_what_the_core_was_sent_and_in_nothing_else(
    app: Gateway, client: httpx2.AsyncClient, core: FakeCore, logs: Everything, short_window: float
) -> None:
    seen: list[str] = []

    async def over_http(method: str, body: dict[str, Any], name: str | None = None, **changed: str) -> None:
        response = await client.post("/mcp", json=body, headers={**headers(method, name), **changed})
        seen.append(repr(response.status_code) + repr(response.headers) + response.text)

    # What succeeds.
    await over_http("server/discover", rpc("server/discover"))
    await over_http("tools/list", rpc("tools/list"))
    core.answers["call_tool"] = ToolAnswer(
        structured={"ok": True}, is_error=False, delivery_token="dt_0123456789abcdef"
    )
    await over_http("tools/call", call("sandbox_exec", {"argv": ["true"]}), "sandbox_exec")

    # What the core refuses, in each of the forms a refusal takes.
    core.answers["call_tool"] = refusal("PERMISSION_DENIED")
    await over_http("tools/call", call("sandbox_exec"), "sandbox_exec")
    core.answers["call_tool"] = refusal("PERMISSION_DENIED", 'Bearer error="insufficient_scope", scope="acf:x"')
    await over_http("tools/call", call("sandbox_exec"), "sandbox_exec")
    core.answers["call_tool"] = ProtocolFaultAnswer(fault="unknown_tool", message="no such tool")
    await over_http("tools/call", call("nope"), "nope")
    core.answers["list_tools"] = refusal("UPSTREAM_UNAVAILABLE")
    await over_http("tools/list", rpc("tools/list"))

    # What goes wrong inside.
    core.answers["call_tool"] = ViewAnswer(view="Sandbox", body={})
    await over_http("tools/call", call("sandbox_exec"), "sandbox_exec")
    core.answers["call_tool"] = RuntimeError("the pool is exhausted")
    await over_http("tools/call", call("sandbox_exec"), "sandbox_exec")
    core.answers["call_tool"] = ToolAnswer(
        structured={"ok": True}, is_error=False, delivery_token="dt_0123456789abcdef"
    )
    core.delivery_failure = OSError("the core went away")
    await over_http("tools/call", call("sandbox_exec"), "sandbox_exec")
    core.delivery_failure = None

    # What the adapter's own layer refuses, with the credential on the request all the same.
    await over_http("tools/list", rpc("tools/list"), **{"mcp-protocol-version": "2025-11-25"})
    await over_http("tools/list", rpc("tools/list"), origin="https://evil.example")
    await over_http("tools/list", rpc("tools/list"), host="evil.example")
    await over_http("tools/call", call("sandbox_exec"), "another_name")
    await over_http("tools/list", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    in_url = post(app, rpc("tools/list"), "tools/list", query=b"access_token=" + CANARY.encode())
    await in_url.run()
    assert in_url.status == 400
    seen.append(_written(in_url))

    # What the core does not let in.
    core.verified = refusal("UNAUTHENTICATED", 'Bearer resource_metadata="https://mcp.example.com/.well-known/x"')
    await over_http("tools/list", rpc("tools/list"))
    core.verified = refusal("UPSTREAM_UNAVAILABLE")
    await over_http("tools/list", rpc("tools/list"))
    core.verified = ToolAnswer(structured={}, is_error=False)
    await over_http("tools/list", rpc("tools/list"))
    core.verified = FakeCore().verified

    # A call on a stream, and calls whose stream is cut: before anything is written, and on the last chunk.
    core.hold = asyncio.Event()
    streamed = post(app, call("sandbox_exec"), "tools/call", "sandbox_exec")
    running_call = asyncio.create_task(streamed.run())
    await core.handling.wait()
    await asyncio.sleep(short_window * 3)
    core.hold.set()
    await running_call
    seen.append(_written(streamed))

    core.hold = asyncio.Event()
    core.handling.clear()
    cut = post(app, call("sandbox_exec"), "tools/call", "sandbox_exec")
    running_call = asyncio.create_task(cut.run())
    await core.handling.wait()
    cut.disconnect()
    await running_call
    seen.append(_written(cut))
    core.hold = None

    def leave_after_status(message: Message) -> None:
        if message["type"] == "http.response.start":
            raising.disconnect()

    raising = post(app, call("sandbox_exec"), "tools/call", "sandbox_exec", raise_when_gone=True)
    raising.on_send = leave_after_status
    with pytest.raises((OSError, BaseExceptionGroup)) as raised:
        await raising.run()
    seen.append("".join(traceback.format_exception(raised.value)))
    seen.append(_written(raising))

    # The canary went where it must: with every single thing the core was asked.
    asked_with_it = [a for a in core.asked if a.credential == CANARY]
    assert len(asked_with_it) >= 30
    assert {a.op for a in asked_with_it} == {"verify", "handle", "delivered"}
    assert [a for a in core.asked if a.credential != CANARY] == []

    # And nowhere else: not whole, and not the part of it that is the secret.
    assert len(seen) > 20
    assert len(logs.written) > 10
    for text in (*seen, *logs.written):
        assert CANARY not in text
        assert CANARY[9:] not in text


def test_the_object_that_holds_the_credential_does_not_show_it() -> None:
    held = exchange_module.Exchange(credential=CANARY, request_id="req_" + "a" * 24)
    ctx = exchange_module.request_context(held.request_id, 1000)
    held.delivery = ("dt_0123456789abcdef", ctx)
    shown = repr(held) + str(held) + f"{held!r:>10}"
    assert CANARY not in shown
    assert "dt_0123456789abcdef" not in shown
    assert held.request_id in shown


async def test_a_credential_in_a_refused_url_is_not_repeated_back(
    app: Gateway, core: FakeCore, logs: Everything
) -> None:
    exchange = post(app, rpc("tools/list"), "tools/list", query=b"token=" + CANARY.encode() + b"&x=" + CANARY.encode())
    exchange.headers = {k: v for k, v in exchange.headers.items() if k != "authorization"}
    await exchange.run()
    assert exchange.status == 400
    assert CANARY not in _written(exchange)
    assert all(CANARY not in line for line in logs.written)
    assert core.asked == []
