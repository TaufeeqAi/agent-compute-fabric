"""Delivery reports, and what a closed stream does.

A tool call that creates work has no idempotency key of the caller's: the core mints one, and treats
an identical call that follows an *undelivered* result as the same request. The adapter's part is to
say when a result was written in full, and to say nothing when it was not. A false report would turn
a caller's retry into a second operation, so every cut is tried here.

Closing the stream cancels the call's wait in the adapter and nothing else: no report, no cancel, no
other message to the core.
"""

from __future__ import annotations

import asyncio
import logging

import pytest

from acf_api.command.answers import ToolAnswer, ToolsAnswer
from acf_api.command.commands import CallTool
from acf_mcp.asgi import App, Message, Receive, Scope, Send
from acf_mcp.exchange import current, request_context
from acf_mcp.gateway import Gateway
from tests.support import CANARY, Exchange, FakeCore, call, post, rpc, tool

TOKEN = "dt_4f9a1c2e7b3d5a60"
HANDLE = {"ok": True, "idempotency_key": "mk_7Qd2", "operation": {"operation_id": "op-12345678", "state": "RUNNING"}}


@pytest.fixture
def creating(core: FakeCore) -> FakeCore:
    """A core whose answer to a call is a result it wants a delivery report for."""
    core.answers["call_tool"] = ToolAnswer(structured=HANDLE, is_error=False, delivery_token=TOKEN)
    return core


def exec_call(app: Gateway, **changes: object) -> Exchange:
    return post(app, call("sandbox_exec", {"argv": ["make", "test"]}), "tools/call", "sandbox_exec", **changes)


async def settle() -> None:
    """Give anything that should not happen every chance to happen."""
    for _ in range(20):
        await asyncio.sleep(0)
    await asyncio.sleep(0.02)


# ---------------------------------------------------------------------------- written in full
async def test_a_result_written_in_full_is_reported(app: Gateway, creating: FakeCore) -> None:
    exchange = exec_call(app)
    creating.watching = exchange
    await exchange.run()
    assert exchange.status == 200
    assert exchange.complete
    check, command, report = creating.asked
    assert (check.op, command.op, report.op) == ("verify", "handle", "delivered")
    assert report.delivery_token == TOKEN
    assert report.credential == CANARY
    assert report.ctx == command.ctx
    # The report was made after the last chunk had been handed over, not before.
    assert not command.response_complete
    assert report.response_complete


async def test_a_result_on_an_event_stream_is_reported_after_its_last_event(
    app: Gateway, creating: FakeCore, short_window: float
) -> None:
    creating.hold = asyncio.Event()
    exchange = exec_call(app)
    creating.watching = exchange
    running_call = asyncio.create_task(exchange.run())
    await creating.handling.wait()
    await asyncio.sleep(short_window * 3)
    assert exchange.header("content-type") == "text/event-stream"
    assert creating.ops() == ["verify", "handle"]
    creating.hold.set()
    await running_call
    assert creating.ops() == ["verify", "handle", "delivered"]
    assert creating.asked[-1].response_complete
    assert exchange.events()[-1]["result"]["structuredContent"] == HANDLE


async def test_an_unsuccessful_result_is_reported_like_any_other(app: Gateway, core: FakeCore) -> None:
    """The caller received it. What it says is not the adapter's to weigh."""
    refused = {"ok": False, "idempotency_key": "mk_7Qd2", "error": {"code": "STATE_CONFLICT", "kind": "REFUSED"}}
    core.answers["call_tool"] = ToolAnswer(structured=refused, is_error=True, delivery_token=TOKEN)
    exchange = exec_call(app)
    await exchange.run()
    assert core.ops() == ["verify", "handle", "delivered"]


async def test_nothing_is_reported_for_a_result_the_core_does_not_track(app: Gateway, core: FakeCore) -> None:
    core.answers["list_tools"] = ToolsAnswer(tools=[tool()])
    for exchange in (exec_call(app), post(app, rpc("tools/list"), "tools/list")):
        await exchange.run()
        assert exchange.status == 200
    assert core.ops() == ["verify", "handle", "verify", "handle"]


async def test_a_report_that_fails_changes_nothing_for_the_caller(
    app: Gateway, creating: FakeCore, caplog: pytest.LogCaptureFixture
) -> None:
    """An unreported delivery is the safe direction: a repeat is then the same request, not new work."""
    creating.delivery_failure = ConnectionResetError("the core went away")
    exchange = exec_call(app)
    with caplog.at_level(logging.WARNING, logger="acf_mcp"):
        await exchange.run()
    assert exchange.status == 200
    assert exchange.events() == []
    assert b'"structuredContent"' in exchange.body
    (record,) = caplog.records
    assert record.message == "delivery_not_reported"
    assert record.__dict__["fields"] == {
        "request_id": creating.asked[0].ctx.request_id,
        "error": "ConnectionResetError",
    }


# ---------------------------------------------------------------------------- the stream is cut
async def test_a_stream_cut_while_the_core_works_ends_the_wait_and_nothing_else(
    app: Gateway, creating: FakeCore
) -> None:
    creating.hold = asyncio.Event()
    exchange = exec_call(app)
    running_call = asyncio.create_task(exchange.run())
    await creating.handling.wait()
    assert creating.abandoned == 0

    exchange.disconnect()
    await running_call

    assert creating.abandoned == 1
    assert exchange.sent == []
    assert exchange.dropped == []
    # The core heard the command and has heard nothing since: no report, no cancel, no second command.
    creating.hold.set()
    await settle()
    assert creating.ops() == ["verify", "handle"]


async def test_a_stream_cut_after_it_began_ends_the_wait_and_nothing_else(
    app: Gateway, creating: FakeCore, short_window: float
) -> None:
    creating.hold = asyncio.Event()
    exchange = exec_call(app)
    running_call = asyncio.create_task(exchange.run())
    await creating.handling.wait()
    await asyncio.sleep(short_window * 4)
    assert exchange.header("content-type") == "text/event-stream"
    assert b": ping" in exchange.body

    exchange.disconnect()
    await running_call

    assert creating.abandoned == 1
    assert exchange.events() == []
    assert not exchange.complete
    creating.hold.set()
    await settle()
    assert creating.ops() == ["verify", "handle"]


async def test_a_stream_cut_as_the_core_answers_is_not_a_delivery(app: Gateway, creating: FakeCore) -> None:
    exchange = exec_call(app)
    creating.before_answer = exchange.disconnect
    await exchange.run()
    await settle()
    assert creating.ops() == ["verify", "handle"]
    assert exchange.sent == []


async def test_a_stream_cut_between_the_status_line_and_the_last_chunk_is_not_a_delivery(
    app: Gateway, creating: FakeCore
) -> None:
    """The server knows the client is gone and has not yet said so through `receive`.

    It will drop the last chunk without a word. Had the adapter judged "written" by `send` returning,
    this would be reported as delivered, and the caller's retry would run the command a second time.
    """

    def cut_after_status(message: Message) -> None:
        if message["type"] == "http.response.start":
            exchange.disconnect()

    exchange = exec_call(app)
    exchange.on_send = cut_after_status
    await exchange.run()
    await settle()
    assert creating.ops() == ["verify", "handle"]
    assert not exchange.complete
    assert [m["type"] for m in exchange.sent] == []


async def test_a_stream_cut_before_the_last_event_of_a_stream_is_not_a_delivery(
    app: Gateway, creating: FakeCore, short_window: float
) -> None:
    creating.hold = asyncio.Event()
    exchange = exec_call(app)
    running_call = asyncio.create_task(exchange.run())
    await creating.handling.wait()
    await asyncio.sleep(short_window * 3)
    assert exchange.header("content-type") == "text/event-stream"
    # The answer is on its way out of the core at the moment the client leaves.
    creating.before_answer = exchange.disconnect
    creating.hold.set()
    await running_call
    await settle()
    assert creating.ops() == ["verify", "handle"]
    assert exchange.events() == []


async def test_a_server_that_raises_for_a_client_that_is_gone_is_not_a_delivery(
    app: Gateway, creating: FakeCore
) -> None:
    """ASGI lets a server raise instead of dropping. Either way nothing was written."""

    def cut_after_status(message: Message) -> None:
        if message["type"] == "http.response.start":
            exchange.disconnect()

    exchange = exec_call(app, raise_when_gone=True)
    exchange.on_send = cut_after_status
    with pytest.raises((OSError, BaseExceptionGroup)):
        await exchange.run()
    await settle()
    assert creating.ops() == ["verify", "handle"]


async def test_a_client_that_leaves_after_the_whole_answer_was_written_received_it(
    app: Gateway, creating: FakeCore
) -> None:
    """Written means handed to the transport. What the client did next proves nothing either way."""

    def cut_after_last_chunk(message: Message) -> None:
        if message["type"] == "http.response.body" and not message.get("more_body", False):
            asyncio.get_running_loop().call_soon(exchange.disconnect)

    exchange = exec_call(app)
    exchange.on_send = cut_after_last_chunk
    await exchange.run()
    await settle()
    assert exchange.complete
    assert creating.ops() == ["verify", "handle", "delivered"]


# ---------------------------------------------------------------------------- the rule itself, whatever is behind it
def _writes_a_tracked_result(*, after_disconnect: bool) -> App:
    """Something behind the adapter's layer that writes an answer the core wants a report for.

    The SDK cancels its handler when the server reports the client gone, so behind the SDK this order
    of events does not occur. The adapter's layer does not lean on that.
    """

    async def behind(_scope: Scope, receive: Receive, send: Send) -> None:
        message = await receive()
        while after_disconnect and message["type"] != "http.disconnect":
            message = await receive()
        current().delivery = (TOKEN, request_context("req_" + "d" * 24, 1000))
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": b'{"part":1,', "more_body": True})
        await send({"type": "http.response.body", "body": b'"part":2}', "more_body": False})

    return behind


async def test_what_is_handed_over_while_the_client_is_there_counts_as_written(
    app: Gateway, core: FakeCore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app._transport, "handle_request", _writes_a_tracked_result(after_disconnect=False))
    exchange = exec_call(app)
    await exchange.run()
    assert exchange.body == b'{"part":1,"part":2}'
    assert core.ops() == ["verify", "delivered"]
    assert core.asked[-1].delivery_token == TOKEN


async def test_what_is_handed_over_after_the_server_said_the_client_is_gone_does_not(
    app: Gateway, core: FakeCore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app._transport, "handle_request", _writes_a_tracked_result(after_disconnect=True))
    exchange = exec_call(app)
    running_call = asyncio.create_task(exchange.run())
    await exchange.body_handed_over.wait()
    exchange.disconnect()
    await running_call
    await settle()
    assert exchange.sent == []
    assert len(exchange.dropped) == 3
    assert core.ops() == ["verify"]


# ---------------------------------------------------------------------------- the call that follows a cut
async def test_a_call_repeated_after_a_cut_is_sent_again_exactly_as_it_was(app: Gateway, creating: FakeCore) -> None:
    """The adapter adopts nothing and mints nothing. That the two calls are one request is the core's to see."""
    creating.hold = asyncio.Event()
    first = exec_call(app)
    running_call = asyncio.create_task(first.run())
    await creating.handling.wait()
    first.disconnect()
    await running_call

    creating.hold = None
    second = exec_call(app)
    await second.run()
    assert second.status == 200

    assert creating.ops() == ["verify", "handle", "verify", "handle", "delivered"]
    one, two = (a for a in creating.asked if a.op == "handle")
    assert one.command == two.command == CallTool(name="sandbox_exec", arguments={"argv": ["make", "test"]})
    assert one.idempotency_key is None
    assert two.idempotency_key is None
    assert one.ctx.request_id != two.ctx.request_id
    assert creating.asked[-1].ctx.request_id == two.ctx.request_id


async def test_a_posted_cancellation_reaches_nobody(app: Gateway, creating: FakeCore) -> None:
    """On this transport the protocol's cancellation is the closed stream. A message that claims it is dropped."""
    creating.hold = asyncio.Event()
    exchange = exec_call(app)
    running_call = asyncio.create_task(exchange.run())
    await creating.handling.wait()

    cancel = {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1, "reason": "stop"}}
    notification = post(app, cancel, "notifications/cancelled")
    await notification.run()
    assert notification.status == 202
    await settle()
    assert creating.abandoned == 0
    assert creating.ops() == ["verify", "handle", "verify"]

    creating.hold.set()
    await running_call
    assert exchange.status == 200
    assert creating.ops() == ["verify", "handle", "verify", "delivered"]
