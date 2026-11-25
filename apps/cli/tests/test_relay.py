"""The stdio relay: what it carries, what it adds, and the one thing it does of its own accord.

The relay is run here against a scripted MCP endpoint, with a client whose lines the test sends one by
one. Held in this file:

* framing: one message per line in, the exact line as the body out, one whole line of ASCII per answer;
* the headers the HTTP transport requires, each copied from the message and never made up;
* messages are carried at once and side by side, and an answer is never interleaved with another;
* a request the endpoint does not answer gets a JSON-RPC error that says so, and never a tool result;
* cancellation: in each of its cases, exactly the calls the platform's rule prescribes and no other;
* a closed input is a disconnect: what was read is carried to its end, and nothing is cancelled;
* nothing is validated, rewritten, cached or tried twice.
"""

from __future__ import annotations

import asyncio
import base64
import inspect
import io
import json
import os
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import httpx2
import pytest

from agentcompute_cli import relay as relay_module
from agentcompute_cli.relay import IN_FLIGHT_MAX, LINE_MAX, OVERSIZE, Oversize, Relay, stdin_lines
from support import AGENT_KEY, EXE, EXE2, MCP_URL, OP3, REPOSITORY, SBX, TOOLS, Json, execution, operation

REVISION = "2026-07-28"
META: Json = {
    "io.modelcontextprotocol/protocolVersion": REVISION,
    "io.modelcontextprotocol/clientCapabilities": {},
    "io.modelcontextprotocol/clientInfo": {"name": "test-host", "version": "1.0"},
}


# ----------------------------------------------------------------------------------------- messages
def request(rpc_id: Any, method: str, **params: Any) -> Json:
    return {"jsonrpc": "2.0", "id": rpc_id, "method": method, "params": {**params, "_meta": META}}


def call(rpc_id: Any, tool: str, **arguments: Any) -> Json:
    return request(rpc_id, "tools/call", name=tool, arguments=arguments)


def cancelled(rpc_id: Any) -> Json:
    return {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": rpc_id, "reason": "user"}}


def result(rpc_id: Any, body: Json) -> Json:
    return {"jsonrpc": "2.0", "id": rpc_id, "result": {"resultType": "complete", **body}}


def tool_result(rpc_id: Any, structured: Json, *, is_error: bool = False) -> Json:
    text = json.dumps(structured, separators=(",", ":"))
    return result(
        rpc_id, {"content": [{"type": "text", "text": text}], "structuredContent": structured, "isError": is_error}
    )


def running(execution_id: str = EXE) -> Json:
    """What the tool that starts an execution answers while the command still runs: a handle."""
    handle = operation(
        "execution.create",
        "IN_PROGRESS",
        operation_id=OP3,
        target={"sandbox_id": SBX, "generation": 1, "execution_id": execution_id},
    )
    return {"ok": True, "replayed": False, "idempotency_key": "minted-1", "operation": handle}


def finished(state: str = "SUCCEEDED", execution_id: str = EXE) -> Json:
    """What it answers when the command ended inside the wait."""
    view = execution(state=state, execution_id=execution_id)
    done = operation(
        "execution.create",
        state,
        operation_id=OP3,
        target={"sandbox_id": SBX, "generation": 1, "execution_id": execution_id},
        result={"execution": view},
    )
    return {"ok": state == "SUCCEEDED", "replayed": False, "idempotency_key": "minted-1", "operation": done,
            "execution": view}  # fmt: skip


def answer(message: Json, *, status: int = 200) -> httpx2.Response:
    return httpx2.Response(status, json=message)


def stream(*messages: Json, ping: bool = True) -> httpx2.Response:
    events = b": ping\r\n\r\n" if ping else b""
    for message in messages:
        events += b"event: message\r\ndata: " + json.dumps(message).encode() + b"\r\n\r\n"
    return httpx2.Response(200, headers={"content-type": "text/event-stream"}, content=events)


# -------------------------------------------------------------------------------------------- the stage
@dataclass
class Posted:
    """One POST as the endpoint saw it."""

    url: str
    headers: dict[str, str]
    body: bytes

    @property
    def message(self) -> Any:
        return json.loads(self.body)

    @property
    def tool(self) -> str | None:
        name = self.message.get("params", {}).get("name")
        return name if isinstance(name, str) else None


type Responder = Callable[[Posted], httpx2.Response | Awaitable[httpx2.Response]]


@dataclass
class Stage:
    """A relay between a client the test plays and an endpoint the test scripts."""

    responder: Responder
    seen: list[Posted] = field(default_factory=list)
    #: Every call of the relay's ``write``: one whole line each.
    written: list[bytes] = field(default_factory=list)
    log: list[str] = field(default_factory=list)
    aborted: list[Any] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._input: asyncio.Queue[bytes | Oversize | None] = asyncio.Queue()

    async def endpoint(self, posted: httpx2.Request) -> httpx2.Response:
        seen = Posted(str(posted.url), {name.lower(): value for name, value in posted.headers.items()}, posted.content)
        self.seen.append(seen)
        try:
            response = self.responder(seen)
            if inspect.isawaitable(response):
                response = await response
        except asyncio.CancelledError:
            # The relay closed the exchange: that is this transport's way of saying "cancelled".
            self.aborted.append(seen.message.get("id"))
            raise
        return response

    async def send(self, message: Json | bytes | Oversize) -> None:
        """The client writes one line."""
        line = message if isinstance(message, bytes | Oversize) else json.dumps(message).encode() + b"\n"
        await self._input.put(line)

    def close(self) -> None:
        """The client closes its end."""
        self._input.put_nowait(None)

    async def lines(self) -> AsyncIterator[bytes | Oversize]:
        while (line := await self._input.get()) is not None:
            yield line

    async def until(self, condition: Callable[[], bool]) -> None:
        async with asyncio.timeout(5):
            while not condition():
                await asyncio.sleep(0.001)

    @property
    def messages(self) -> list[Json]:
        return [json.loads(line) for line in self.written]

    def posted(self, tool: str) -> list[Posted]:
        return [seen for seen in self.seen if seen.tool == tool]


def play(script: Callable[[Stage], Awaitable[None]], responder: Responder, *, api_key: str = AGENT_KEY) -> Stage:
    """Run a relay, let ``script`` play the client, then close the input and let the relay finish."""

    async def main() -> Stage:
        stage = Stage(responder)
        async with httpx2.AsyncClient(transport=httpx2.MockTransport(stage.endpoint)) as http:
            relay = Relay(
                endpoint=MCP_URL, api_key=api_key, http=http, write=stage.written.append, log=stage.log.append
            )
            running_relay = asyncio.create_task(relay.run(stage.lines()))
            try:
                await script(stage)
            finally:
                stage.close()
            async with asyncio.timeout(10):
                await running_relay
        return stage

    return asyncio.run(main())


def carry(*lines: Json | bytes | Oversize, responder: Responder) -> Stage:
    """The simplest play: the client writes these lines and closes its end."""

    async def script(stage: Stage) -> None:
        for line in lines:
            await stage.send(line)

    return play(script, responder)


def echo(posted: Posted) -> httpx2.Response:
    """An endpoint that answers every request with a result naming the method it was asked."""
    message = posted.message
    return answer(result(message["id"], {"asked": message["method"]}))


# ---------------------------------------------------------------------------------------------- framing
def test_a_line_becomes_one_post_whose_body_is_the_line_as_the_client_wrote_it() -> None:
    line = b'{"jsonrpc": "2.0",   "id": 1, "method": "tools/list", "params": {"_meta": ' + json.dumps(META).encode()
    line += b', "cursor":   null}}'
    stage = carry(line + b"\r\n", responder=echo)
    assert [seen.body for seen in stage.seen] == [line], "not re-serialized, not trimmed, only the line end is gone"
    assert stage.seen[0].url == MCP_URL
    assert stage.messages == [result(1, {"asked": "tools/list"})]


def test_an_answer_is_one_line_of_ascii_whatever_the_endpoint_sent() -> None:
    structured = {"note": "line one\nline two \N{LINE SEPARATOR} \x1b[31m é ✓ \x7f"}
    pretty = json.dumps(tool_result(7, structured), indent=4, ensure_ascii=False).encode()

    stage = carry(call(7, "sandbox_list"), responder=lambda _: httpx2.Response(200, content=pretty, headers={
        "content-type": "application/json; charset=utf-8"}))  # fmt: skip

    assert len(stage.written) == 1
    line = stage.written[0]
    assert line.endswith(b"\n")
    assert line.count(b"\n") == 1, "a message never holds a line end of its own"
    assert all(0x20 <= byte < 0x7F for byte in line[:-1]), "printable ASCII: nothing in it can break or hide a line"
    assert json.loads(line) == tool_result(7, structured), "and it is the same message"


def test_a_streamed_answer_is_relayed_message_by_message_in_order() -> None:
    progress = {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progressToken": "t", "progress": 1}}
    stage = carry(
        call(3, "sandbox_create"), responder=lambda _: stream(progress, progress, tool_result(3, {"ok": True}))
    )
    assert stage.messages == [progress, progress, tool_result(3, {"ok": True})]


def test_what_is_not_a_message_on_a_stream_is_not_written() -> None:
    events = b": keep-alive\r\n\r\nevent: message\r\ndata: not json\r\n\r\nevent: message\r\ndata: [1]\r\n\r\n"
    events += b"event: message\r\ndata: " + json.dumps(result(3, {"ok": True})).encode() + b"\r\n\r\n"
    stage = carry(
        call(3, "x"),
        responder=lambda _: httpx2.Response(200, headers={"content-type": "text/event-stream"}, content=events),
    )
    assert stage.messages == [result(3, {"ok": True})]


def test_an_empty_line_is_not_a_message() -> None:
    stage = carry(b"\n", b"   \r\n", request(1, "tools/list"), responder=echo)
    assert len(stage.seen) == 1
    assert len(stage.written) == 1


@pytest.mark.parametrize(
    ("line", "code"),
    [
        (b"this is not json\n", -32700),
        (b"\xff\xfe\n", -32700),
        (b'[{"jsonrpc":"2.0"}]\n', -32600),
        (b'"text"\n', -32600),
    ],
    ids=["not-json", "not-text", "a-batch", "a-string"],
)
def test_a_line_that_holds_no_message_is_answered_here_and_not_relayed(line: bytes, code: int) -> None:
    stage = carry(line, request(2, "tools/list"), responder=echo)
    assert len(stage.seen) == 1, "only the message was relayed"
    refused, relayed = stage.messages
    assert refused["id"] is None, "the identifier of what could not be read is not known"
    assert refused["error"]["code"] == code
    assert refused["error"]["data"] == {"origin": "acf mcp relay"}
    assert "result" not in refused
    assert relayed == result(2, {"asked": "tools/list"})


def test_a_line_longer_than_the_relay_reads_is_answered_here() -> None:
    stage = carry(OVERSIZE, request(2, "tools/list"), responder=echo)
    assert stage.messages[0]["error"]["code"] == -32600
    assert str(LINE_MAX) in stage.messages[0]["error"]["message"]
    assert len(stage.seen) == 1


def test_a_message_is_not_judged_here_whatever_it_is() -> None:
    """Whether a message is one of the protocol is the endpoint's to say. The relay carries it."""
    odd: list[Json] = [
        {"jsonrpc": "1.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
        {"id": 2, "method": 7},
        {"jsonrpc": "2.0", "id": 3, "result": {"a client must not send a response": True}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": 5, "arguments": "not an object"}},
    ]
    stage = carry(*odd, responder=lambda posted: answer(result(posted.message["id"], {})))
    assert [seen.message for seen in stage.seen] == odd
    assert [message["id"] for message in stage.messages] == [1, 2, 3, 4]


# ---------------------------------------------------------------------------------------------- headers
def test_a_tool_call_carries_the_headers_the_transport_requires() -> None:
    stage = carry(call(1, "sandbox_list"), responder=echo)
    headers = stage.seen[0].headers
    assert headers["authorization"] == f"Bearer {AGENT_KEY}"
    assert headers["content-type"] == "application/json"
    assert {part.strip() for part in headers["accept"].split(",")} == {"application/json", "text/event-stream"}
    assert headers["mcp-protocol-version"] == REVISION
    assert headers["mcp-method"] == "tools/call"
    assert headers["mcp-name"] == "sandbox_list"
    assert headers["user-agent"].startswith("agent-compute-cli/")
    assert not [name for name in headers if name.startswith("mcp-param-") or name == "mcp-session-id"]


@pytest.mark.parametrize(
    ("message", "name"),
    [
        (request(1, "tools/list"), None),
        (request(1, "server/discover"), None),
        (request(1, "prompts/get", name="greeting"), "greeting"),
        (request(1, "resources/read", uri="file:///a b"), "file:///a b"),
        (request(1, "tools/call", arguments={}), None),
        (request(1, "tools/list", name="not a named method"), None),
    ],
)
def test_the_name_header_mirrors_the_named_parameter_of_the_methods_that_have_one(
    message: Json, name: str | None
) -> None:
    stage = carry(message, responder=echo)
    assert stage.seen[0].headers.get("mcp-name") == name
    assert stage.seen[0].headers["mcp-method"] == message["method"]


@pytest.mark.parametrize("name", ["Hello, 世界", " padded ", "line1\nline2", "=?base64?literal?=", "tab\there", ""])
def test_a_name_that_is_not_safe_as_a_header_is_sent_in_the_protocols_encoding(name: str) -> None:
    stage = carry(call(1, name), responder=echo)
    sent = stage.seen[0].headers["mcp-name"]
    assert sent.startswith("=?base64?")
    assert sent.endswith("?=")
    assert base64.b64decode(sent.removeprefix("=?base64?").removesuffix("?=")).decode() == name
    assert stage.seen[0].message["params"]["name"] == name, "the body is untouched"


def test_the_protocol_version_is_the_one_the_message_states_and_is_never_made_up() -> None:
    stated = call(1, "x")
    stated["params"]["_meta"] = {**META, "io.modelcontextprotocol/protocolVersion": "2099-01-01"}
    silent = {"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}}
    not_text = call(3, "x")
    not_text["params"]["_meta"] = {**META, "io.modelcontextprotocol/protocolVersion": 20260728}
    unsafe = call(4, "x")
    unsafe["params"]["_meta"] = {**META, "io.modelcontextprotocol/protocolVersion": "2026-07-28\r\nX-Injected: 1"}
    stage = carry(stated, silent, not_text, unsafe, responder=lambda posted: answer(result(posted.message["id"], {})))
    by_id = {seen.message["id"]: seen.headers for seen in stage.seen}
    assert by_id[1]["mcp-protocol-version"] == "2099-01-01"
    for rpc_id in (2, 3, 4):
        assert "mcp-protocol-version" not in by_id[rpc_id], "the endpoint says in its own words what it serves"
        assert "x-injected" not in by_id[rpc_id]


def test_a_method_that_cannot_be_a_header_value_is_sent_without_one() -> None:
    for method in ("tools/call\r\nX-Injected: 1", "méthode", " padded", ""):
        stage = carry(request(1, method), responder=lambda posted: answer(result(1, {})))
        assert "mcp-method" not in stage.seen[0].headers
        assert "x-injected" not in stage.seen[0].headers


def test_the_credential_goes_in_one_header_to_the_endpoint_and_nowhere_else() -> None:
    stage = carry(call(1, "sandbox_list"), cancelled(1), b"junk\n", responder=echo)
    for seen in stage.seen:
        assert seen.url == MCP_URL
        assert AGENT_KEY.encode() not in seen.body
        assert [name for name, value in seen.headers.items() if AGENT_KEY in value] == ["authorization"]
    assert AGENT_KEY not in "".join(stage.log)
    assert AGENT_KEY.encode() not in b"".join(stage.written)


def test_a_redirect_is_not_followed() -> None:
    redirect = httpx2.Response(307, headers={"location": "https://elsewhere.example/mcp"})
    stage = carry(call(1, "sandbox_list"), responder=lambda _: redirect)
    assert len(stage.seen) == 1, "the key was not carried to another address"
    assert stage.messages[0]["error"]["code"] == -32603


# ----------------------------------------------------------------------------- answers of the endpoint
def test_an_error_the_endpoint_gave_before_it_read_the_identifier_gets_the_identifier_of_its_request() -> None:
    """On HTTP an answer belongs to its request by position. On a shared stream only the identifier says so."""
    refused: Json = {
        "jsonrpc": "2.0",
        "id": None,
        "error": {"code": -32600, "message": "UNAUTHENTICATED", "data": {"code": "UNAUTHENTICATED", "kind": "REFUSED"}},
    }
    stage = carry(call("abc", "sandbox_list"), responder=lambda _: answer(refused, status=401))
    assert stage.messages == [{**refused, "id": "abc"}]


def test_an_error_of_the_protocol_is_relayed_whatever_its_http_status() -> None:
    unknown = {"jsonrpc": "2.0", "id": 5, "error": {"code": -32601, "message": "Method not found"}}
    stage = carry(request(5, "resources/list"), responder=lambda _: answer(unknown, status=404))
    assert stage.messages == [unknown]


def test_a_result_is_never_given_an_identifier_it_did_not_have() -> None:
    odd = {"jsonrpc": "2.0", "id": 99, "result": {"resultType": "complete"}}
    stage = carry(request(5, "tools/list"), responder=lambda _: answer(odd))
    assert stage.messages == [odd], "the relay does not correct what the endpoint said"


def silence(kind: type[Exception]) -> Responder:
    def responder(_: Posted) -> httpx2.Response:
        raise kind("the words of the library, which may quote the request")

    return responder


def always(response: httpx2.Response) -> Responder:
    """An endpoint that gives the same answer to everything."""

    def responder(_: Posted) -> httpx2.Response:
        return response

    return responder


def as_json(content: bytes) -> httpx2.Response:
    """An answer that says it is JSON, whatever it holds."""
    return httpx2.Response(200, content=content, headers={"content-type": "application/json"})


@pytest.mark.parametrize(
    ("responder", "said"),
    [
        (silence(httpx2.ConnectError), "could not be reached"),
        (silence(httpx2.ReadError), "could not be reached, or the connection was lost"),
        (silence(httpx2.ReadTimeout), "did not answer in time"),
        (lambda _: httpx2.Response(404), "HTTP 404 without a message of the protocol"),
        (lambda _: httpx2.Response(502, content=b"<html>bad gateway</html>"), "HTTP 502"),
        (lambda _: httpx2.Response(202), "acknowledged the request without answering it"),
        (always(as_json(b"<html>")), "not a response"),
        (lambda _: httpx2.Response(200, json=[1, 2]), "not a response"),
        (lambda _: httpx2.Response(200, json={"jsonrpc": "2.0", "method": "notifications/x"}), "not a response"),
        (always(as_json(b'{"jsonrpc":"2.0","id":1,"result":{"n":NaN}}')), "not a response"),
        (lambda _: stream(ping=True), "closed the stream without a response"),
    ],
    ids=[
        "connect",
        "reset",
        "timeout",
        "404",
        "502",
        "202",
        "not-json",
        "not-an-object",
        "not-a-response",
        "not-a-number",
        "empty-stream",
    ],
)
def test_a_request_the_endpoint_does_not_answer_gets_an_error_that_says_so_and_never_a_result(
    responder: Responder, said: str
) -> None:
    stage = carry(call(1, "sandbox_exec", sandbox_id=SBX, argv=["true"]), responder=responder)
    assert len(stage.seen) == 1, "nothing is tried a second time"
    (message,) = stage.messages
    assert message["id"] == 1
    assert "result" not in message, "the relay never makes up the result of a tool"
    assert message["error"]["code"] == -32603
    assert message["error"]["data"] == {"origin": "acf mcp relay"}
    assert said in message["error"]["message"]
    assert "made by the local relay, not by the platform" in message["error"]["message"]
    assert "the words of the library" not in message["error"]["message"]
    assert said in stage.log[0]


@pytest.mark.parametrize("streamed", [False, True], ids=["json", "event-stream"])
def test_an_answer_too_long_to_read_is_no_answer(monkeypatch: pytest.MonkeyPatch, streamed: bool) -> None:
    monkeypatch.setattr(relay_module, "ANSWER_MAX", 1024)
    long = result(1, {"blob": "x" * 4096})
    stage = carry(call(1, "x"), responder=always(stream(long) if streamed else answer(long)))
    (message,) = stage.messages
    assert "result" not in message
    assert message["error"]["code"] == -32603
    assert "longer than 1024 bytes" in message["error"]["message"]


def test_an_answer_that_cannot_be_decoded_is_no_answer_and_is_not_called_a_lost_connection() -> None:
    async def body() -> AsyncIterator[bytes]:
        yield b"not gzip at all"

    # A body that is given as a stream is decoded when it is read, as one from the network is.
    garbled = httpx2.Response(
        200, content=body(), headers={"content-type": "application/json", "content-encoding": "gzip"}
    )
    stage = carry(call(1, "x"), responder=always(garbled))
    (message,) = stage.messages
    assert "result" not in message
    assert "its answer could not be read (DecodingError)" in message["error"]["message"]


def test_a_notification_is_carried_and_nothing_is_written_for_it() -> None:
    note = {"jsonrpc": "2.0", "method": "notifications/custom", "params": {"_meta": META}}
    for response in (httpx2.Response(202), httpx2.Response(400, json={"jsonrpc": "2.0", "id": None, "error": {}})):
        stage = carry(note, responder=always(response))
        assert len(stage.seen) == 1
        assert stage.seen[0].headers["mcp-method"] == "notifications/custom"
        assert stage.written == []
    assert "did not accept a notification (HTTP 400)" in stage.log[0]
    lost = carry(note, responder=silence(httpx2.ConnectError))
    assert lost.written == []
    assert "did not reach the endpoint" in lost.log[0]


# ------------------------------------------------------------------------------------------ concurrency
def test_a_slow_call_does_not_hold_up_the_next_message() -> None:
    gate = asyncio.Event()

    async def responder(posted: Posted) -> httpx2.Response:
        if posted.message["id"] == "slow":
            await gate.wait()
        return answer(result(posted.message["id"], {}))

    async def script(stage: Stage) -> None:
        await stage.send(call("slow", "sandbox_exec"))
        await stage.send(request("fast", "tools/list"))
        await stage.until(lambda: len(stage.written) == 1)
        assert stage.messages[0]["id"] == "fast", "answered while the first was still on its way"
        gate.set()

    stage = play(script, responder)
    assert [message["id"] for message in stage.messages] == ["fast", "slow"]


def test_answers_are_written_whole_and_never_interleaved() -> None:
    count = 40

    async def responder(posted: Posted) -> httpx2.Response:
        rpc_id = posted.message["id"]
        await asyncio.sleep(0.001 * (count - rpc_id) % 7)
        note = {
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {"progressToken": rpc_id, "progress": 1},
        }
        return stream(note, tool_result(rpc_id, {"blob": "x" * 20_000}))

    stage = carry(*(call(rpc_id, "sandbox_list") for rpc_id in range(count)), responder=responder)
    assert len(stage.written) == 2 * count
    for line in stage.written:
        assert line.endswith(b"\n")
        assert line.count(b"\n") == 1
        json.loads(line)
    assert sorted(message["id"] for message in stage.messages if "id" in message) == list(range(count))


def test_no_more_than_the_limit_are_carried_at_once_and_the_rest_wait_their_turn() -> None:
    gate = asyncio.Event()
    at_once = 0
    most = 0

    async def responder(posted: Posted) -> httpx2.Response:
        nonlocal at_once, most
        at_once += 1
        most = max(most, at_once)
        await gate.wait()
        at_once -= 1
        return answer(result(posted.message["id"], {}))

    async def script(stage: Stage) -> None:
        for rpc_id in range(IN_FLIGHT_MAX + 10):
            await stage.send(request(rpc_id, "tools/list"))
        await stage.until(lambda: len(stage.seen) == IN_FLIGHT_MAX)
        await asyncio.sleep(0.02)
        assert len(stage.seen) == IN_FLIGHT_MAX
        gate.set()

    stage = play(script, responder)
    assert most == IN_FLIGHT_MAX
    assert len(stage.messages) == IN_FLIGHT_MAX + 10


# ----------------------------------------------------------------------------------------- cancellation
def cancelling(structured: Json = {"ok": True}) -> Responder:  # noqa: B006 - never changed
    def responder(posted: Posted) -> httpx2.Response:
        return answer(tool_result(posted.message["id"], structured))

    return responder


def test_cancelling_a_call_that_started_an_execution_cancels_the_execution() -> None:
    """Started and known: the call returned a handle, and the execution was not seen to end."""

    def responder(posted: Posted) -> httpx2.Response:
        if posted.tool == "sandbox_exec":
            return answer(tool_result(posted.message["id"], running()))
        return answer(tool_result(posted.message["id"], {"ok": True}))

    async def script(stage: Stage) -> None:
        await stage.send(call(1, "sandbox_exec", sandbox_id=SBX, argv=["sleep", "600"]))
        await stage.until(lambda: len(stage.written) == 1)
        await stage.send(cancelled(1))
        await stage.until(lambda: len(stage.seen) == 2)

    stage = play(script, responder)
    assert stage.messages == [tool_result(1, running())], "the answer to the cancel is the relay's, not the client's"
    (cancel,) = stage.posted("exec_cancel")
    sent = cancel.message
    assert sent["method"] == "tools/call"
    assert sent["params"]["arguments"] == {"execution_id": EXE}
    assert sent["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] == REVISION
    assert sent["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] == {}
    assert cancel.headers["mcp-method"] == "tools/call"
    assert cancel.headers["mcp-name"] == "exec_cancel"
    assert cancel.headers["mcp-protocol-version"] == REVISION
    assert cancel.headers["authorization"] == f"Bearer {AGENT_KEY}"
    assert f"execution {EXE} was cancelled" in stage.log[-1]
    assert not [seen for seen in stage.seen if seen.message.get("method") == "notifications/cancelled"], (
        "the notification is not posted: on this transport there is none"
    )


def test_cancelling_a_call_in_flight_waits_for_its_answer_and_cancels_what_it_started() -> None:
    """In flight and then known: only the answer says whether there is an execution to cancel."""
    gate = asyncio.Event()

    async def responder(posted: Posted) -> httpx2.Response:
        if posted.tool == "sandbox_exec":
            await gate.wait()
            return answer(tool_result(posted.message["id"], running()))
        return answer(tool_result(posted.message["id"], {"ok": True}))

    async def script(stage: Stage) -> None:
        await stage.send(call(1, "sandbox_exec", sandbox_id=SBX, argv=["sleep", "600"]))
        await stage.until(lambda: len(stage.seen) == 1)
        await stage.send(cancelled(1))
        await asyncio.sleep(0.02)
        assert stage.aborted == [], "the call is not closed: its answer is the only way to learn what it started"
        assert stage.posted("exec_cancel") == []
        gate.set()
        await stage.until(lambda: len(stage.seen) == 2)

    stage = play(script, responder)
    assert stage.written == [], "nothing more is written for a request the client cancelled"
    assert [seen.message["params"]["arguments"] for seen in stage.posted("exec_cancel")] == [{"execution_id": EXE}]


def test_cancelling_a_call_in_flight_whose_command_then_turns_out_to_have_ended_cancels_nothing() -> None:
    gate = asyncio.Event()

    async def responder(posted: Posted) -> httpx2.Response:
        await gate.wait()
        return answer(tool_result(posted.message["id"], finished()))

    async def script(stage: Stage) -> None:
        await stage.send(call(1, "sandbox_exec", sandbox_id=SBX, argv=["true"]))
        await stage.until(lambda: len(stage.seen) == 1)
        await stage.send(cancelled(1))
        gate.set()

    stage = play(script, responder)
    assert len(stage.seen) == 1
    assert stage.written == []
    assert "no execution that is still running" in stage.log[-1]


@pytest.mark.parametrize("tool", ["sandbox_create", "sandbox_start", "exec_status", "exec_cancel", "operation_get"])
def test_cancelling_a_call_that_starts_no_execution_closes_it_and_calls_nothing(tool: str) -> None:
    """Not an execution: the cancellation is carried the way this transport carries one, and that is all."""
    gate = asyncio.Event()

    async def responder(posted: Posted) -> httpx2.Response:
        await gate.wait()
        return answer(tool_result(posted.message["id"], running()))

    async def script(stage: Stage) -> None:
        await stage.send(call(1, tool, name="x"))
        await stage.until(lambda: len(stage.seen) == 1)
        await stage.send(cancelled(1))
        await stage.until(lambda: stage.aborted == [1])
        gate.set()

    stage = play(script, responder)
    assert len(stage.seen) == 1, "no cancel was called for anything"
    assert stage.written == []


def test_cancelling_a_request_that_is_not_a_tool_call_closes_it() -> None:
    gate = asyncio.Event()

    async def responder(_: Posted) -> httpx2.Response:
        await gate.wait()
        return stream()

    async def script(stage: Stage) -> None:
        await stage.send(request("listen", "subscriptions/listen"))
        await stage.until(lambda: len(stage.seen) == 1)
        await stage.send(cancelled("listen"))
        await stage.until(lambda: stage.aborted == ["listen"])

    stage = play(script, responder)
    assert stage.written == []


def test_cancelling_a_call_that_ended_and_started_nothing_calls_nothing() -> None:
    def responder(posted: Posted) -> httpx2.Response:
        structured = finished() if posted.tool == "sandbox_exec" else {"ok": True, "sandboxes": []}
        return answer(tool_result(posted.message["id"], structured))

    async def script(stage: Stage) -> None:
        await stage.send(call(1, "sandbox_exec", sandbox_id=SBX, argv=["true"]))
        await stage.send(call(2, "sandbox_list"))
        await stage.until(lambda: len(stage.written) == 2)
        for rpc_id in (1, 2, 3, "1", None, {"not": "an id"}):
            await stage.send(cancelled(rpc_id))
        await stage.send({"jsonrpc": "2.0", "method": "notifications/cancelled"})
        await stage.send(request(9, "tools/list"))
        await stage.until(lambda: len(stage.written) == 3)

    stage = play(script, responder)
    assert [seen.tool for seen in stage.seen] == ["sandbox_exec", "sandbox_list", None], "three requests, no cancel"


def test_an_execution_that_was_seen_to_end_is_not_cancelled_later() -> None:
    """The relay keeps note only of what it has not seen end, and a status read can show the end."""

    def responder(posted: Posted) -> httpx2.Response:
        rpc_id = posted.message["id"]
        if posted.tool == "sandbox_exec":
            return answer(tool_result(rpc_id, running()))
        return answer(tool_result(rpc_id, {"ok": True, "execution": execution()}))

    async def script(stage: Stage) -> None:
        await stage.send(call(1, "sandbox_exec", sandbox_id=SBX, argv=["true"]))
        await stage.until(lambda: len(stage.written) == 1)
        await stage.send(call(2, "exec_status", execution_id=EXE))
        await stage.until(lambda: len(stage.written) == 2)
        await stage.send(cancelled(1))
        await stage.send(request(3, "tools/list"))
        await stage.until(lambda: len(stage.written) == 3)

    stage = play(script, responder)
    assert stage.posted("exec_cancel") == []


def test_the_clients_own_cancel_of_an_execution_is_seen_too() -> None:
    def responder(posted: Posted) -> httpx2.Response:
        rpc_id = posted.message["id"]
        if posted.tool == "sandbox_exec":
            return answer(tool_result(rpc_id, running()))
        ended = operation(
            "execution.cancel", result={"execution": execution("CANCELLED", exit_code=None, state="CANCELLED")}
        )
        return answer(tool_result(rpc_id, {"ok": True, "operation": ended}))

    async def script(stage: Stage) -> None:
        await stage.send(call(1, "sandbox_exec", sandbox_id=SBX, argv=["true"]))
        await stage.until(lambda: len(stage.written) == 1)
        await stage.send(call(2, "exec_cancel", execution_id=EXE))
        await stage.until(lambda: len(stage.written) == 2)
        await stage.send(cancelled(1))
        await stage.send(request(3, "tools/list"))
        await stage.until(lambda: len(stage.written) == 3)

    stage = play(script, responder)
    assert len(stage.posted("exec_cancel")) == 1, "the client's own, and no second one"


def test_an_execution_whose_outcome_the_host_could_not_establish_is_still_cancelled_when_asked() -> None:
    def responder(posted: Posted) -> httpx2.Response:
        structured = finished("UNKNOWN") if posted.tool == "sandbox_exec" else {"ok": True}
        return answer(tool_result(posted.message["id"], structured, is_error=posted.tool == "sandbox_exec"))

    async def script(stage: Stage) -> None:
        await stage.send(call(1, "sandbox_exec", sandbox_id=SBX, argv=["true"]))
        await stage.until(lambda: len(stage.written) == 1)
        await stage.send(cancelled(1))
        await stage.until(lambda: len(stage.seen) == 2)

    stage = play(script, responder)
    assert len(stage.posted("exec_cancel")) == 1, "what is not known to have ended may still be running"


def test_an_identifier_names_the_latest_request_that_used_it() -> None:
    def responder(posted: Posted) -> httpx2.Response:
        rpc_id = posted.message["id"]
        return answer(tool_result(rpc_id, running() if posted.tool == "sandbox_exec" else {"ok": True}))

    async def script(stage: Stage) -> None:
        await stage.send(call(1, "sandbox_exec", sandbox_id=SBX, argv=["true"]))
        await stage.until(lambda: len(stage.written) == 1)
        await stage.send(call(1, "sandbox_list"))
        await stage.until(lambda: len(stage.written) == 2)
        await stage.send(cancelled(1))
        await stage.send(request(2, "tools/list"))
        await stage.until(lambda: len(stage.written) == 3)

    stage = play(script, responder)
    assert stage.posted("exec_cancel") == [], "the identifier no longer names the call that started the execution"


def test_identifiers_are_compared_exactly() -> None:
    async def script(stage: Stage) -> None:
        await stage.send(call(1, "sandbox_exec", sandbox_id=SBX, argv=["true"]))
        await stage.until(lambda: len(stage.written) == 1)
        await stage.send(cancelled("1"))
        await stage.send(cancelled(1.0))
        await stage.send(cancelled(True))
        await stage.send(request(2, "tools/list"))
        await stage.until(lambda: len(stage.written) == 2)

    stage = play(script, cancelling(running()))
    assert stage.posted("exec_cancel") == []


def test_each_execution_is_cancelled_for_the_call_that_started_it() -> None:
    def responder(posted: Posted) -> httpx2.Response:
        rpc_id = posted.message["id"]
        if posted.tool == "sandbox_exec":
            return answer(tool_result(rpc_id, running(EXE if rpc_id == "a" else EXE2)))
        return answer(tool_result(rpc_id, {"ok": True}))

    async def script(stage: Stage) -> None:
        await stage.send(call("a", "sandbox_exec", sandbox_id=SBX, argv=["one"]))
        await stage.send(call("b", "sandbox_exec", sandbox_id=SBX, argv=["two"]))
        await stage.until(lambda: len(stage.written) == 2)
        await stage.send(cancelled("b"))
        await stage.until(lambda: len(stage.seen) == 3)
        await stage.send(cancelled("b"))
        await stage.send(request(9, "tools/list"))
        await stage.until(lambda: len(stage.written) == 3)

    stage = play(script, responder)
    assert [seen.message["params"]["arguments"] for seen in stage.posted("exec_cancel")] == [{"execution_id": EXE2}]


def test_the_cancel_states_the_protocol_version_of_the_call_it_is_made_for() -> None:
    started = call(1, "sandbox_exec", sandbox_id=SBX, argv=["true"])
    started["params"]["_meta"] = {**META, "io.modelcontextprotocol/protocolVersion": "2027-01-01"}

    async def script(stage: Stage) -> None:
        await stage.send(started)
        await stage.until(lambda: len(stage.written) == 1)
        await stage.send(cancelled(1))
        await stage.until(lambda: len(stage.seen) == 2)

    stage = play(script, cancelling(running()))
    (cancel,) = stage.posted("exec_cancel")
    assert cancel.headers["mcp-protocol-version"] == "2027-01-01"
    assert cancel.message["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] == "2027-01-01"


@pytest.mark.parametrize(
    ("cancel_answer", "said"),
    [
        (httpx2.Response(503), "got no answer"),
        (
            answer(tool_result("x", {"ok": False, "error": {"code": "STATE_CONFLICT"}}, is_error=True)),
            "did not cancel it",
        ),
        (answer({"jsonrpc": "2.0", "id": "x", "error": {"code": -32602, "message": "no"}}), "did not cancel it"),
    ],
    ids=["no-answer", "refused", "protocol-error"],
)
def test_a_cancel_that_does_not_succeed_is_said_and_not_tried_again(cancel_answer: httpx2.Response, said: str) -> None:
    def responder(posted: Posted) -> httpx2.Response:
        return answer(tool_result(1, running())) if posted.tool == "sandbox_exec" else cancel_answer

    async def script(stage: Stage) -> None:
        await stage.send(call(1, "sandbox_exec", sandbox_id=SBX, argv=["true"]))
        await stage.until(lambda: len(stage.written) == 1)
        await stage.send(cancelled(1))
        await stage.until(lambda: len(stage.seen) == 2)

    stage = play(script, responder)
    assert len(stage.posted("exec_cancel")) == 1
    assert said in stage.log[-1]
    assert f"acf exec cancel {EXE}" in stage.log[-1], "the person is told how to do it themselves"
    assert len(stage.written) == 1


def test_a_cancelled_call_that_got_no_answer_cancels_nothing_and_says_so() -> None:
    gate = asyncio.Event()

    async def responder(_: Posted) -> httpx2.Response:
        await gate.wait()
        raise httpx2.ReadError("lost")

    async def script(stage: Stage) -> None:
        await stage.send(call(1, "sandbox_exec", sandbox_id=SBX, argv=["true"]))
        await stage.until(lambda: len(stage.seen) == 1)
        await stage.send(cancelled(1))
        gate.set()

    stage = play(script, responder)
    assert len(stage.seen) == 1
    assert stage.written == []
    assert "Whether it started an execution is not known, so nothing was cancelled" in stage.log[-1]


# --------------------------------------------------------------------------------------- the input ends
def test_a_closed_input_is_a_disconnect_what_was_read_is_carried_to_its_end_and_nothing_is_cancelled() -> None:
    gate = asyncio.Event()

    async def responder(posted: Posted) -> httpx2.Response:
        await gate.wait()
        return answer(tool_result(posted.message["id"], running()))

    async def script(stage: Stage) -> None:
        await stage.send(call(1, "sandbox_exec", sandbox_id=SBX, argv=["sleep", "600"]))
        await stage.until(lambda: len(stage.seen) == 1)
        stage.close()
        await asyncio.sleep(0.02)
        gate.set()

    stage = play(script, responder)
    assert stage.messages == [tool_result(1, running())], "the answer that was on its way is written"
    assert len(stage.seen) == 1, "and the execution it started is left running: a disconnect cancels nothing"
    assert stage.aborted == []


def test_stopping_the_relay_cancels_nothing_on_the_platform() -> None:
    """Ctrl-C and a termination signal stop the relay. What they close is a wait, never an execution."""

    async def main() -> Stage:
        gate = asyncio.Event()

        async def responder(posted: Posted) -> httpx2.Response:
            if posted.message["id"] == 2:
                await gate.wait()
            return answer(tool_result(posted.message["id"], running()))

        stage = Stage(responder)
        async with httpx2.AsyncClient(transport=httpx2.MockTransport(stage.endpoint)) as http:
            relay = Relay(
                endpoint=MCP_URL, api_key=AGENT_KEY, http=http, write=stage.written.append, log=stage.log.append
            )
            task = asyncio.create_task(relay.run(stage.lines()))
            await stage.send(call(1, "sandbox_exec", sandbox_id=SBX, argv=["one"]))
            await stage.send(call(2, "sandbox_exec", sandbox_id=SBX, argv=["two"]))
            await stage.until(lambda: len(stage.seen) == 2 and len(stage.written) == 1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        return stage

    stage = asyncio.run(main())
    assert stage.posted("exec_cancel") == [], "neither the execution that is known nor the one still being started"
    assert len(stage.seen) == 2


# --------------------------------------------------------------------------------------- standard input
def read_all(data: bytes) -> list[bytes | Oversize]:
    async def main() -> list[bytes | Oversize]:
        return [line async for line in stdin_lines(io.BytesIO(data))]

    return asyncio.run(main())


def test_standard_input_is_read_line_by_line_to_its_end() -> None:
    assert read_all(b'{"a":1}\n{"b":2}\r\n\n{"c":3}') == [b'{"a":1}\n', b'{"b":2}\r\n', b"\n", b'{"c":3}']
    assert read_all(b"") == []


def test_a_line_longer_than_the_bound_is_skipped_whole_and_reported() -> None:
    long = b"x" * (LINE_MAX + 5)
    exact = b"y" * LINE_MAX
    assert read_all(b"first\n" + long + b"\nlast\n") == [b"first\n", OVERSIZE, b"last\n"]
    assert read_all(exact + b"\n") == [exact + b"\n"], "a line of exactly the bound is read"
    assert read_all(long) == [OVERSIZE], "also when the input ends inside it"


def cut(data: bytes, size: int) -> Callable[[int], bytes]:
    """An input that gives ``size`` bytes at a time, whatever it is asked for."""
    stream = io.BytesIO(data)
    return lambda _: stream.read(size)


def test_the_lines_are_the_same_however_the_input_is_cut_into_reads() -> None:
    data = b'{"a":1}\n\n{"b":2}\r\nthe last one has no end'
    for size in (1, 2, 3, 5, 8, 1000):
        lines = list(relay_module._lines(cut(data, size)))
        assert lines == [b'{"a":1}\n', b"\n", b'{"b":2}\r\n', b"the last one has no end"], size


def test_the_bound_of_a_line_holds_however_the_input_is_cut(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(relay_module, "LINE_MAX", 8)
    data = b"12345678\n123456789\nshort\n" + b"x" * 30 + b"\n\nend"
    for size in (1, 2, 3, 4, 7, 8, 9, 10, 1000):
        lines = list(relay_module._lines(cut(data, size)))
        assert lines == [b"12345678\n", OVERSIZE, b"short\n", OVERSIZE, b"\n", b"end"], size
    assert list(relay_module._lines(cut(b"123456789", 4))) == [OVERSIZE], "also when the input ends inside it"


def test_a_buffered_stream_is_read_underneath_its_buffer() -> None:
    """The thread that waits for input must hold no lock an interpreter takes when it shuts down."""
    reader, writer = os.pipe()
    with os.fdopen(reader, "rb") as stream, os.fdopen(writer, "wb") as sender:
        assert relay_module._unbuffered(stream) == stream.raw.read
        sender.write(b"one line\n")
        sender.flush()
        assert relay_module._unbuffered(stream)(100) == b"one line\n", "a read gives what there is and does not wait"
    plain = io.BytesIO(b"abc")
    assert relay_module._unbuffered(plain) == plain.read


def test_a_pipe_is_read_while_it_is_written() -> None:
    reader, writer = os.pipe()

    async def main() -> list[bytes | Oversize]:
        seen: list[bytes | Oversize] = []
        with os.fdopen(reader, "rb") as stream:
            lines = stdin_lines(stream)
            os.write(writer, b"one\n")
            seen.append(await anext(lines))
            os.write(writer, b"two\n")
            seen.append(await anext(lines))
            os.close(writer)
            seen.extend([line async for line in lines])
        return seen

    assert asyncio.run(main()) == [b"one\n", b"two\n"]


# ------------------------------------------------------------------- what the relay knows about tools
def test_the_two_tools_the_relay_knows_by_name_are_tools_of_the_platform() -> None:
    catalogue = json.loads((REPOSITORY / "protocols" / "mcp" / "catalogue.json").read_text(encoding="utf-8"))
    methods = {tool["name"]: tool["method"] for tool in catalogue["tools"]}
    assert methods[relay_module._START_TOOL] == "execution.create"
    assert methods[relay_module._CANCEL_TOOL] == "execution.cancel"
    assert catalogue["protocol_revision"] == relay_module.REVISION
    assert [name for name, method in methods.items() if method == "execution.create"] == [relay_module._START_TOOL], (
        "a second tool that starts an execution would have to be taught to the relay"
    )


def test_the_cancel_the_relay_sends_is_one_the_tool_accepts() -> None:
    tool = json.loads((TOOLS / "exec_cancel.json").read_text(encoding="utf-8"))
    schema = tool["inputSchema"]
    assert schema["required"] == ["execution_id"]
    assert schema["additionalProperties"] is False
    assert "execution_id" in schema["properties"]


def test_results_show_an_execution_where_the_relay_looks_for_one() -> None:
    for name in ("sandbox_exec", "exec_status", "exec_cancel"):
        output = json.loads((TOOLS / f"{name}.json").read_text(encoding="utf-8"))["outputSchema"]
        places = set(output["properties"])
        assert places & {"execution", "operation"}, name
        if "operation" in places:
            definition = output["$defs"]["Operation"]["properties"]
            assert {"type", "state", "target", "result"} <= set(definition)
            assert "execution_id" in output["$defs"]["OperationTarget"]["properties"]
            assert "execution" in output["$defs"]["OperationResult"]["properties"]
        assert {"execution_id", "state"} <= set(output["$defs"]["Execution"]["properties"])


def test_no_tool_of_the_platform_mirrors_a_parameter_into_a_header() -> None:
    """The relay sends no ``Mcp-Param-*`` header, which is right as long as no tool declares one.

    Sending one would need the schema of the tool, and so a cache of the tool listing, which a relay
    that holds no tool semantics does not keep.
    """
    files = sorted(TOOLS.glob("*.json"))
    assert len(files) >= 16
    for file in files:
        assert "x-mcp-header" not in file.read_text(encoding="utf-8"), file.name
