"""Test support: a core that records what it is asked, and an HTTP exchange driven by hand.

Nothing here opens a socket. The adapter is an ASGI application, and the two things a test needs to
control are on either side of it: what the core answers, and what the HTTP server tells the
application about its client.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import httpx2

from acf_api.command.answers import (
    Answer,
    DiscoverAnswer,
    RequestContext,
    ToolAnswer,
    ToolDefinition,
    ToolsAnswer,
    VerifiedAnswer,
)
from acf_api.command.commands import Command
from acf_api.edge.config import EdgeConfig, parse_edge_config
from acf_mcp.asgi import Message, Scope
from acf_mcp.gateway import Gateway, create_app

REVISION: Final = "2026-07-28"
#: A credential that must never be seen anywhere but in what the core is sent.
CANARY: Final = "acf1_agt_CANARYq7Zr2mVx9KpL4sTd8WbY3nHc6JfUe1GaQo5_Zk3PqA"
HOST: Final = "127.0.0.1:8443"
BASE_URL: Final = f"http://{HOST}"
#: The tool catalogue the platform publishes, generated from the core's code.
CATALOGUE: Final = Path(__file__).resolve().parents[3] / "protocols" / "mcp" / "tools"

ENVELOPE: Final[dict[str, Any]] = {
    "io.modelcontextprotocol/protocolVersion": REVISION,
    "io.modelcontextprotocol/clientCapabilities": {},
    "io.modelcontextprotocol/clientInfo": {"name": "pytest", "version": "1.0"},
}


def edge_config(**sections: Any) -> EdgeConfig:
    """An edge configuration with defaults, and the given sections in place of theirs."""
    return parse_edge_config({"schema_version": 1, "command_socket": "/nonexistent/core.sock", **sections})


def tool(name: str = "sandbox_list", **changes: Any) -> ToolDefinition:
    """A small tool definition whose output schema a client can validate a result against."""
    members: dict[str, Any] = {
        "name": name,
        "title": "List sandboxes",
        "description": "List the sandboxes of the project.",
        "input_schema": {"type": "object", "properties": {"limit": {"type": "integer"}}, "additionalProperties": False},
        "output_schema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "read_only": True,
        "destructive": False,
        "idempotent": True,
        "open_world": False,
    }
    return ToolDefinition(**{**members, **changes})


def catalogue() -> list[tuple[dict[str, Any], ToolDefinition]]:
    """Every published tool: the published document, and the definition the core would answer with."""
    out: list[tuple[dict[str, Any], ToolDefinition]] = []
    for path in sorted(CATALOGUE.glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        hints = document["annotations"]
        out.append(
            (
                document,
                ToolDefinition(
                    name=document["name"],
                    title=document["title"],
                    description=document["description"],
                    input_schema=document["inputSchema"],
                    output_schema=document["outputSchema"],
                    read_only=hints["readOnlyHint"],
                    destructive=hints["destructiveHint"],
                    idempotent=hints["idempotentHint"],
                    open_world=hints["openWorldHint"],
                ),
            )
        )
    return out


@dataclass(slots=True)
class Asked:
    """One thing the core was asked."""

    op: str
    credential: str | None
    ctx: RequestContext
    command: Command | None = None
    idempotency_key: str | None = None
    delivery_token: str | None = None
    #: Request-body messages the application had read when this was asked.
    body_reads: int = 0
    #: Whether the whole response had been handed to the server when this was asked.
    response_complete: bool = False


Scripted = Answer | Callable[[Command], Answer] | BaseException


class FakeCore:
    """A client of the command interface that answers from a script and records every call."""

    def __init__(self) -> None:
        self.asked: list[Asked] = []
        self.verified: Answer = VerifiedAnswer()
        self.answers: dict[str, Scripted] = {
            "list_tools": ToolsAnswer(tools=[tool()]),
            "call_tool": ToolAnswer(structured={"ok": True}, is_error=False),
            "discover": DiscoverAnswer(
                server_name="agent-compute-fabric",
                server_version="9.9.9",
                instructions="Tools for isolated sandboxes.",
                platform_features=["agent_credentials", "long_poll"],
                host_features=["allowlist_network"],
            ),
        }
        #: While set, `handle` waits here after recording the call: an operation that has not ended yet.
        self.hold: asyncio.Event | None = None
        self.handling: asyncio.Event = asyncio.Event()
        #: Waits of `handle` that were cancelled: the caller went away.
        self.abandoned: int = 0
        self.delivery_failure: BaseException | None = None
        self.closed: bool = False
        #: The exchange under test, when a test wants to know what had crossed the wire at each call.
        self.watching: Exchange | None = None
        #: Called when `handle` is about to answer.
        self.before_answer: Callable[[], None] = lambda: None

    def _record(self, asked: Asked) -> None:
        if self.watching is not None:
            asked.body_reads = self.watching.body_reads
            asked.response_complete = self.watching.complete
        self.asked.append(asked)

    async def verify(self, credential: str | None, ctx: RequestContext) -> Answer:
        self._record(Asked("verify", credential, ctx))
        return self.verified

    async def handle(
        self, credential: str | None, ctx: RequestContext, command: Command, idempotency_key: str | None = None
    ) -> Answer:
        self._record(Asked("handle", credential, ctx, command, idempotency_key=idempotency_key))
        self.handling.set()
        if self.hold is not None:
            try:
                await self.hold.wait()
            except asyncio.CancelledError:
                self.abandoned += 1
                raise
        scripted = self.answers[command.type]
        if isinstance(scripted, BaseException):
            raise scripted
        self.before_answer()
        return scripted(command) if callable(scripted) else scripted

    async def delivered(self, credential: str | None, ctx: RequestContext, delivery_token: str) -> None:
        # A real client has to reach the core before anything is reported: a report that is made from
        # somewhere it can be cancelled must not count as made.
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        self._record(Asked("delivered", credential, ctx, delivery_token=delivery_token))
        if self.delivery_failure is not None:
            raise self.delivery_failure

    async def aclose(self) -> None:
        self.closed = True

    def ops(self) -> list[str]:
        return [a.op for a in self.asked]

    def commands(self) -> list[Command]:
        return [a.command for a in self.asked if a.command is not None]


@contextlib.asynccontextmanager
async def serving(app: Gateway) -> AsyncIterator[None]:
    """Run the application's lifespan around a test, as an HTTP server would."""
    to_app: asyncio.Queue[Message] = asyncio.Queue()
    from_app: asyncio.Queue[Message] = asyncio.Queue()
    lifespan = asyncio.create_task(app({"type": "lifespan", "asgi": {"version": "3.0"}}, to_app.get, from_app.put))
    await to_app.put({"type": "lifespan.startup"})
    started = await from_app.get()
    assert started["type"] == "lifespan.startup.complete"
    try:
        yield
    finally:
        await to_app.put({"type": "lifespan.shutdown"})
        stopped = await from_app.get()
        assert stopped["type"] == "lifespan.shutdown.complete"
        await lifespan


@contextlib.asynccontextmanager
async def running(core: FakeCore, **sections: Any) -> AsyncIterator[tuple[Gateway, httpx2.AsyncClient]]:
    """The adapter under a configuration of the test's own, served, with an HTTP client that reaches it."""
    gateway = create_app(core, edge_config(**sections))
    async with (
        serving(gateway),
        httpx2.AsyncClient(transport=httpx2.ASGITransport(app=gateway), base_url=BASE_URL) as http,
    ):
        yield gateway, http


def rpc(method: str, params: dict[str, Any] | None = None, *, rpc_id: int | str = 1) -> dict[str, Any]:
    """A request of the protocol with the envelope every request of this revision carries."""
    body = dict(params or {})
    body["_meta"] = {**ENVELOPE, **body.get("_meta", {})}
    return {"jsonrpc": "2.0", "id": rpc_id, "method": method, "params": body}


def headers(method: str, name: str | None = None, *, credential: str | None = CANARY) -> dict[str, str]:
    """The headers of a well-formed request of this revision."""
    out = {
        "content-type": "application/json",
        "accept": "application/json, text/event-stream",
        "mcp-protocol-version": REVISION,
        "mcp-method": method,
    }
    if name is not None:
        out["mcp-name"] = name
    if credential is not None:
        out["authorization"] = f"Bearer {credential}"
    return out


def call(name: str, arguments: dict[str, Any] | None = None, **extra: Any) -> dict[str, Any]:
    params: dict[str, Any] = {"name": name, **extra}
    if arguments is not None:
        params["arguments"] = arguments
    return rpc("tools/call", params)


@dataclass
class Exchange:
    """One HTTP request driven by hand, behaving as the HTTP server of an edge process does.

    Like that server it reports a disconnect through ``receive`` only, drops what is sent after the
    client has gone, and reports a disconnect once the response is complete.
    """

    app: Gateway
    method: str = "POST"
    path: str = "/mcp"
    headers: dict[str, str] = field(default_factory=dict)
    chunks: list[bytes] = field(default_factory=list)
    query: bytes = b""
    #: An ASGI server may raise instead of dropping what is sent to a client that has gone.
    raise_when_gone: bool = False
    #: Called with every message the application sends, before the server acts on it.
    on_send: Callable[[Message], None] = lambda _message: None

    body_reads: int = 0
    gone: bool = False
    complete: bool = False
    sent: list[Message] = field(default_factory=list)
    dropped: list[Message] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._pending = list(self.chunks)
        self._body_sent = False
        self._released = asyncio.Event()
        #: Set once the application has been handed the whole request body.
        self.body_handed_over = asyncio.Event()
        #: Set while the body is being held back by a test.
        self.body_gate: asyncio.Event | None = None

    @property
    def scope(self) -> Scope:
        return {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": self.method,
            "scheme": "http",
            "path": self.path,
            "raw_path": self.path.encode("ascii"),
            "query_string": self.query,
            "root_path": "",
            "server": ("127.0.0.1", 8443),
            "client": ("127.0.0.1", 50000),
            "headers": [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in self.headers.items()],
        }

    def disconnect(self) -> None:
        """The client closes the connection."""
        self.gone = True
        self._released.set()

    async def receive(self) -> Message:
        if self.body_gate is not None:
            await self.body_gate.wait()
        if not self._body_sent and not self.gone:
            self.body_reads += 1
            chunk = self._pending.pop(0) if self._pending else b""
            self._body_sent = not self._pending
            if self._body_sent:
                self.body_handed_over.set()
            return {"type": "http.request", "body": chunk, "more_body": not self._body_sent}
        await self._released.wait()
        return {"type": "http.disconnect"}

    async def send(self, message: Message) -> None:
        self.on_send(message)
        if self.gone:
            if self.raise_when_gone:
                raise OSError("the client is gone")
            self.dropped.append(message)
            return
        self.sent.append(message)
        if message["type"] == "http.response.body" and not message.get("more_body", False):
            self.complete = True
            self._released.set()

    async def run(self) -> None:
        await self.app(self.scope, self.receive, self.send)

    @property
    def status(self) -> int | None:
        for message in self.sent:
            if message["type"] == "http.response.start":
                return int(message["status"])
        return None

    def header(self, name: str) -> str | None:
        for message in self.sent:
            if message["type"] == "http.response.start":
                for key, value in message["headers"]:
                    if key == name.encode("ascii"):
                        return str(value.decode("latin-1"))
        return None

    @property
    def body(self) -> bytes:
        return b"".join(m.get("body", b"") for m in self.sent if m["type"] == "http.response.body")

    def events(self) -> list[dict[str, Any]]:
        """The JSON-RPC messages of an event-stream response, without the keep-alive comments."""
        out: list[dict[str, Any]] = []
        for block in self.body.decode("ascii").split("\r\n\r\n"):
            data = [line[len("data: ") :] for line in block.split("\r\n") if line.startswith("data: ")]
            if data:
                out.append(json.loads("\n".join(data)))
        return out


def post(app: Gateway, body: dict[str, Any], method: str, name: str | None = None, **changes: Any) -> Exchange:
    """A well-formed POST to the MCP endpoint, as an exchange a test can steer."""
    return Exchange(
        app,
        headers={"host": HOST, **headers(method, name)},
        chunks=[json.dumps(body).encode("utf-8")],
        **changes,
    )


_JSON_STRING: Final = re.compile(r'"(?:[^"\\]|\\.)*"')
_JSON_SKELETON: Final = re.compile(r"(?:[\[\]{}:,]|-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null)*")


def outside_strings(text: str) -> str:
    """What is left of a JSON text once every string token is taken out."""
    return _JSON_STRING.sub("", text)


def is_json_skeleton(text: str) -> bool:
    """Whether ``text`` is made of JSON punctuation, numbers and literals only."""
    return _JSON_SKELETON.fullmatch(text) is not None
