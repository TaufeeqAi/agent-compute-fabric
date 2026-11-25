"""The REST adapter over the real pipeline, in one process.

What stands behind the adapter here is the ``RuntimeService`` of a :class:`~tests.support.harness.Rig`:
the real pipeline, the real store and journal, the model host. Only the socket between the two roles is
left out. What crosses is still what a frame carries: every request and every answer is encoded and
decoded by the codec of the command interface, so a command or an answer the codec would refuse fails
here exactly as it would on the socket.

The client is the real :class:`~acf_api.command.client.SocketCoreClient` with its transport replaced,
and what answers it is the frame handling of the real :class:`~acf_api.core.server.CommandServer`.
The client's bounds, and above all its rule for an answer that did not arrive, are therefore the code
under test and not a copy of it: a test loses an answer, and the client decides what the caller is told.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import time
from collections.abc import AsyncIterator, Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import httpx2
from starlette.applications import Starlette

from acf_api.command import codec
from acf_api.command.answers import COMMAND_INTERFACE_VERSION, Answer, HandleRequest, Request
from acf_api.command.client import SocketCoreClient, _NoAnswer
from acf_api.core.server import CommandServer
from acf_api.edge.config import Limits
from acf_api.edge.http.app import create_app
from acf_api.edge.http.routes import RouteSpec
from tests.support.harness import Identity, Rig, build_rig

Op = Literal["verify", "handle", "delivered"]
#: Where an answer is lost: before the core saw the command, or after the core handled it.
Point = Literal["before", "after"]

BASE_URL = "http://edge.test"
REQUEST_ID = re.compile(r"^req_[0-9A-Za-z]{16,40}$")


@dataclass(frozen=True, slots=True)
class Seen:
    """One exchange the edge started, as the core would have received it."""

    op: Op
    credential: str | None
    request_id: str
    #: Milliseconds the edge gave the core to answer.
    budget_ms: int
    #: The command type of a ``handle``; ``None`` for the other two calls.
    command: str | None
    idempotency_key: str | None
    #: Whether the exchange reached the service. False for an answer lost before the core saw the command.
    reached: bool


class InProcessCore(SocketCoreClient):
    """The edge's client of the command interface, with the socket replaced by a call into one service.

    Controls: :meth:`lose_next` drops the answer of the next exchange before or after the service ran;
    :meth:`break_next` lets the service run and then fails the client itself; :meth:`answer_next`
    replaces the answer the service gave. ``seen`` records every exchange.
    """

    def __init__(self, rig: Rig, *, max_in_flight: int = 256) -> None:
        super().__init__("/nonexistent/in-process", max_in_flight=max_in_flight)
        # Never started: no socket is bound. Only its handling of one frame is used.
        self._server = CommandServer(
            rig.service,
            Path("/nonexistent/in-process"),
            allowed_uids=frozenset(),
            socket_gid=None,
            telemetry=rig.core.telemetry,
        )
        self._lose: dict[Op, Point] = {}
        self._break: BaseException | None = None
        self._replacement: Answer | None = None
        self.seen: list[Seen] = []
        self.closed = False

    # ------------------------------------------------------------------ controls
    def lose_next(self, point: Point, *, op: Op = "handle") -> None:
        """Lose the answer of the next ``op``: ``before`` the service saw it, or ``after`` it ran."""
        self._lose[op] = point

    def break_next(self, error: BaseException) -> None:
        """Let the next ``handle`` run in the service, then make the client fail with ``error``."""
        self._break = error

    def answer_next(self, answer: Answer) -> None:
        """Let the next ``handle`` run in the service, then hand the adapter ``answer`` in place of its answer."""
        self._replacement = answer

    def count(self, op: Op) -> int:
        return sum(1 for s in self.seen if s.op == op)

    def commands(self) -> list[str]:
        """The command types the adapter asked the core to handle, in order."""
        return [s.command for s in self.seen if s.command is not None]

    # ------------------------------------------------------------------ the transport
    async def _exchange(self, request: Request, wait_s: float) -> Answer:
        # What the core is given is the payload of the frame, not the object the adapter built.
        payload = codec.encode_request(request)
        op: Op = request.op
        lost = self._lose.pop(op, None)
        self.seen.append(
            Seen(
                op=op,
                credential=request.credential,
                request_id=request.ctx.request_id,
                budget_ms=request.ctx.budget_ms,
                command=request.command.type if isinstance(request, HandleRequest) else None,
                idempotency_key=request.idempotency_key if isinstance(request, HandleRequest) else None,
                reached=lost != "before",
            )
        )
        if lost == "before":
            raise _NoAnswer
        # The core's own handling of one frame: decoding, the version check and the three calls.
        answer = await self._server._answer(payload)
        if lost == "after":
            raise _NoAnswer
        if isinstance(request, HandleRequest):
            broken, self._break = self._break, None
            if broken is not None:
                raise broken
            replacement, self._replacement = self._replacement, None
            if replacement is not None:
                return replacement
        return codec.decode_answer(codec.encode_answer(answer, COMMAND_INTERFACE_VERSION))

    async def aclose(self) -> None:
        self.closed = True
        await super().aclose()


def limits_for(rig: Rig, **overrides: Any) -> Limits:
    """The transport bounds of an edge that fronts ``rig``: the waits are the core's, as a deployment sets them."""
    p = rig.config.parameters
    values: dict[str, Any] = {
        "public_wait_max": p.public_wait_max,
        "edge_core_deadline_margin": p.edge_core_deadline_margin,
        "max_public_request_bytes": p.max_public_request_bytes,
    }
    values.update(overrides)
    return Limits(**values)


@dataclass
class Edge:
    """The REST adapter over a rig, and an HTTP client that speaks to it."""

    rig: Rig
    core: InProcessCore
    app: Starlette
    http: httpx2.AsyncClient
    limits: Limits
    #: Every response this edge gave, for the checks that look at all of them.
    responses: list[httpx2.Response] = field(default_factory=list)

    async def request(
        self,
        method: str,
        path: str,
        who: Identity | str | None = None,
        *,
        key: str | bytes | None = None,
        json: Any = None,
        content: Any = None,
        params: Mapping[str, Any] | list[tuple[str, Any]] | None = None,
        headers: Mapping[str, str | bytes] | None = None,
    ) -> httpx2.Response:
        """One request. ``who`` is a developer or a raw credential; ``key`` becomes ``Idempotency-Key``."""
        sent: dict[str, str | bytes] = {}
        credential = who.key if isinstance(who, Identity) else who
        if credential is not None:
            sent["Authorization"] = f"Bearer {credential}"
        if key is not None:
            sent["Idempotency-Key"] = key
        sent.update(headers or {})
        # As bytes, so that a test can send a header value no well-behaved client would.
        raw = [
            (name.encode("ascii"), value if isinstance(value, bytes) else value.encode("utf-8"))
            for name, value in sent.items()
        ]
        response = await self.http.request(method, path, json=json, content=content, params=params, headers=raw)
        self.responses.append(response)
        return response

    async def get(self, path: str, who: Identity | str | None = None, **kw: Any) -> httpx2.Response:
        return await self.request("GET", path, who, **kw)

    async def post(self, path: str, who: Identity | str | None = None, **kw: Any) -> httpx2.Response:
        return await self.request("POST", path, who, **kw)

    async def delete(self, path: str, who: Identity | str | None = None, **kw: Any) -> httpx2.Response:
        return await self.request("DELETE", path, who, **kw)


@contextlib.asynccontextmanager
async def serving(rig: Rig, **limits: Any) -> AsyncIterator[Edge]:
    """The REST adapter in front of ``rig``, for the duration of the block.

    The application's own failures are returned as the response it wrote, not raised into the test: what
    a caller is told when the edge itself fails is one of the things under test.
    """
    bounds = limits_for(rig, **limits)
    core = InProcessCore(rig)
    app = create_app(core, bounds)
    transport = httpx2.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx2.AsyncClient(transport=transport, base_url=BASE_URL, timeout=30.0) as http:
        yield Edge(rig, core, app, http, bounds)


@contextlib.asynccontextmanager
async def standing_edge(
    root: Path, *, limits: Mapping[str, Any] | None = None, **parameters: Any
) -> AsyncIterator[Edge]:
    """A rig of its own under ``root`` with the given core parameters, and the REST adapter in front of it."""
    rig = await build_rig(root, **parameters)
    try:
        async with serving(rig, **dict(limits or {})) as edge:
            yield edge
    finally:
        await rig.close()


# ------------------------------------------------------------------------------- shared steps
def project_path(who: Identity, tail: str = "") -> str:
    return f"/v1/projects/{who.project_id}{tail}"


SANDBOX_BODY: dict[str, Any] = {"image": "python", "resources": {"vcpus": 1, "memory_mib": 512, "disk_mib": 1024}}


def problem_of(response: httpx2.Response) -> dict[str, Any]:
    """The problem document of an error answer, after checking that it is one."""
    assert response.headers["content-type"] == "application/problem+json", response.text
    body = response.json()
    assert isinstance(body, dict)
    return body


def view_of(response: httpx2.Response, status: int = 200) -> dict[str, Any]:
    """The view of a successful answer."""
    assert response.status_code == status, response.text
    assert response.headers["content-type"] == "application/json", response.text
    body = response.json()
    assert isinstance(body, dict)
    return body


async def create_sandbox(edge: Edge, who: Identity, key: str = "k-create", **spec: Any) -> dict[str, Any]:
    """Create a sandbox over HTTP and return its view."""
    response = await edge.post(project_path(who, "/sandboxes"), who, key=key, json={**SANDBOX_BODY, **spec})
    sandbox = view_of(response)["result"]["sandbox"]
    assert isinstance(sandbox, dict)
    return sandbox


async def start_sandbox(
    edge: Edge, who: Identity, sandbox_id: str, key: str = "k-start", generation: int = 1
) -> dict[str, Any]:
    response = await edge.post(
        project_path(who, f"/sandboxes/{sandbox_id}/start"), who, key=key, json={"expected_generation": generation}
    )
    return view_of(response)


async def started_sandbox(edge: Edge, who: Identity, key: str = "k-create", **spec: Any) -> str:
    """A created and started sandbox, as an SDK's ``create`` leaves it. Returns its identifier."""
    sandbox = await create_sandbox(edge, who, key, **spec)
    await start_sandbox(edge, who, str(sandbox["sandbox_id"]), key + ":start")
    return str(sandbox["sandbox_id"])


async def execute(edge: Edge, who: Identity, sandbox_id: str, key: str = "k-exec", **spec: Any) -> dict[str, Any]:
    """Run one command and return the operation view."""
    body = {"expected_generation": 1, "argv": ["echo", "hello"], **spec}
    response = await edge.post(project_path(who, f"/sandboxes/{sandbox_id}/executions"), who, key=key, json=body)
    assert response.status_code in {200, 202}, response.text
    operation = response.json()
    assert isinstance(operation, dict)
    return operation


async def take_snapshot(edge: Edge, who: Identity, sandbox_id: str, key: str = "k-snap", **spec: Any) -> dict[str, Any]:
    """Take a snapshot and return its view."""
    body = {"expected_generation": 1, **spec}
    response = await edge.post(project_path(who, f"/sandboxes/{sandbox_id}/snapshots"), who, key=key, json=body)
    snapshot = view_of(response)["result"]["snapshot"]
    assert isinstance(snapshot, dict)
    return snapshot


async def until(condition: Callable[[], bool], timeout_s: float = 3.0) -> None:
    """Poll ``condition`` at a short interval until it holds, or fail at the bound."""
    deadline = time.monotonic() + timeout_s
    while not condition():
        assert time.monotonic() < deadline, "the awaited condition did not come to hold"
        await asyncio.sleep(0.005)


# =============================================================================== the failure table
@dataclass(frozen=True)
class Row:
    """One row of the failure table of the contract (§15.2), transcribed by hand and not read from the code."""

    kind: str
    status: int
    retry_after: bool
    #: ``platform``, ``host`` or ``either``.
    decided_by: str


CONTRACT_TABLE: dict[str, Row] = {
    "INVALID_REQUEST": Row("REFUSED", 400, False, "either"),
    "UNAUTHENTICATED": Row("REFUSED", 401, False, "platform"),
    "PERMISSION_DENIED": Row("REFUSED", 403, False, "platform"),
    "SAFETY_CONTROL_DENIED": Row("REFUSED", 403, False, "host"),
    "NOT_FOUND": Row("REFUSED", 404, False, "either"),
    "STATE_CONFLICT": Row("REFUSED", 409, False, "host"),
    "QUARANTINED": Row("REFUSED", 409, False, "host"),
    "REVISION_CONFLICT": Row("REFUSED", 412, False, "host"),
    "IDEMPOTENCY_CONFLICT": Row("REFUSED", 422, False, "platform"),
    "REQUEST_IN_PROGRESS": Row("UNRESOLVED", 409, True, "platform"),
    "RATE_LIMITED": Row("REFUSED", 429, True, "platform"),
    "RESOURCE_EXHAUSTED": Row("REFUSED", 503, True, "host"),
    "HOST_NOT_SERVING": Row("REFUSED", 503, True, "host"),
    "UNSUPPORTED": Row("REFUSED", 422, False, "either"),
    "REQUEST_TOO_LARGE": Row("REFUSED", 413, False, "platform"),
    "CURSOR_EXPIRED": Row("REFUSED", 410, False, "host"),
    "INTEGRITY_FAILURE": Row("REFUSED", 409, False, "host"),
    "INCOMPATIBLE_RUNTIME": Row("REFUSED", 409, False, "host"),
    "CLOCK_SKEW": Row("REFUSED", 503, True, "platform"),
    "UPSTREAM_UNAVAILABLE": Row("REFUSED", 503, True, "platform"),
    "OUTCOME_UNRESOLVED": Row("UNRESOLVED", 503, True, "platform"),
    "OUTCOME_LOST": Row("UNRESOLVED", 410, False, "platform"),
    "INTERNAL_ERROR": Row("REFUSED", 500, False, "either"),
}
PROBLEM_MEMBERS = {"type", "title", "status", "detail", "instance", "code", "kind", "retry", "message", "request_id"}
RETRY_ADVICE = {"SAME_REQUEST_LATER", "AFTER_CHANGE", "NEVER"}


def assert_problem(response: httpx2.Response, code: str, *, retry: str | None = None) -> dict[str, Any]:
    """Check one error answer against the contract's table and the members every error answer carries."""
    row = CONTRACT_TABLE[code]
    body = problem_of(response)
    assert body.get("code") == code, body
    assert response.status_code == row.status, body
    assert body.keys() >= PROBLEM_MEMBERS, sorted(PROBLEM_MEMBERS - body.keys())
    assert body["status"] == row.status
    assert body["kind"] == row.kind
    assert body["retry"] in RETRY_ADVICE
    if retry is not None:
        assert body["retry"] == retry
    assert body["type"] == "urn:acf:problem:" + code.lower().replace("_", "-")
    assert isinstance(body["title"], str)
    assert body["title"]
    assert isinstance(body["message"], str)
    assert body["message"]
    assert body["detail"] == body["message"]
    assert REQUEST_ID.fullmatch(body["request_id"]), body["request_id"]
    assert body["instance"] == f"urn:acf:request:{body['request_id']}"
    assert response.headers["x-request-id"] == body["request_id"]
    assert response.headers["cache-control"] == "no-store"
    if row.retry_after:
        assert int(response.headers["retry-after"]) >= 1
    if row.status == 401:
        assert response.headers["www-authenticate"].startswith("Bearer")
    return body


# =============================================================================== a project with one of everything
@dataclass(frozen=True)
class World:
    """What one developer made through the API: enough to call every route once."""

    dev: Identity
    #: Created and started; an execution ran in it and a snapshot was taken of it.
    sandbox_id: str
    #: Created and not started.
    idle_id: str
    snapshot_id: str
    execution_id: str
    operation_id: str
    credential_id: str


async def build_world(edge: Edge, dev: Identity) -> World:
    sandbox_id = await started_sandbox(edge, dev, "w-create")
    idle = await create_sandbox(edge, dev, "w-idle")
    ran = await execute(edge, dev, sandbox_id, "w-exec")
    snapshot = await take_snapshot(edge, dev, sandbox_id, "w-snap", name="base")
    minted = view_of(
        await edge.post(
            project_path(dev, "/agent-credentials"), dev, json={"label": "agent-1", "lifetime_seconds": 3600}
        ),
        201,
    )
    return World(
        dev=dev,
        sandbox_id=sandbox_id,
        idle_id=str(idle["sandbox_id"]),
        snapshot_id=str(snapshot["snapshot_id"]),
        execution_id=str(ran["target"]["execution_id"]),
        operation_id=str(ran["operation_id"]),
        credential_id=str(minted["credential_id"]),
    )


@dataclass(frozen=True)
class Call:
    path: str
    params: dict[str, Any] | None = None
    json: Any = None


def route_calls(w: World) -> dict[str, Call]:
    """One valid request for each public operation, by public method."""
    p = f"/v1/projects/{w.dev.project_id}"
    return {
        "sandbox.create": Call(f"{p}/sandboxes", json={**SANDBOX_BODY, "name": "another"}),
        "sandbox.list": Call(f"{p}/sandboxes", params={"limit": 10}),
        "sandbox.get": Call(f"{p}/sandboxes/{w.sandbox_id}"),
        "sandbox.start": Call(f"{p}/sandboxes/{w.idle_id}/start", json={"expected_generation": 1}),
        "sandbox.stop": Call(f"{p}/sandboxes/{w.sandbox_id}/stop", json={"expected_generation": 1}),
        "sandbox.destroy": Call(f"{p}/sandboxes/{w.idle_id}", params={"expected_generation": 1}),
        "execution.create": Call(
            f"{p}/sandboxes/{w.sandbox_id}/executions", json={"expected_generation": 1, "argv": ["echo", "again"]}
        ),
        "snapshot.create": Call(
            f"{p}/sandboxes/{w.sandbox_id}/snapshots", json={"expected_generation": 1, "name": "second"}
        ),
        "execution.get": Call(f"{p}/executions/{w.execution_id}"),
        "execution.output": Call(
            f"{p}/executions/{w.execution_id}/output", params={"stream": "stdout", "offset": 0, "max_bytes": 64}
        ),
        "execution.cancel": Call(f"{p}/executions/{w.execution_id}/cancel"),
        "snapshot.list": Call(f"{p}/snapshots"),
        "snapshot.restore": Call(
            f"{p}/snapshots/{w.snapshot_id}/restore",
            json={"snapshot_generation": 1, "target": {"kind": "new", "name": "restored"}},
        ),
        "snapshot.delete": Call(f"{p}/snapshots/{w.snapshot_id}", params={"snapshot_generation": 1}),
        "operation.list": Call(f"{p}/operations", params={"limit": 5}),
        "operation.get": Call(f"{p}/operations/{w.operation_id}"),
        "agent_credential.mint": Call(f"{p}/agent-credentials", json={"label": "agent-2", "lifetime_seconds": 600}),
        "agent_credential.list": Call(f"{p}/agent-credentials"),
        "agent_credential.revoke": Call(f"{p}/agent-credentials/{w.credential_id}"),
        "platform.info": Call("/v1/info"),
        "auth.whoami": Call("/v1/auth/whoami"),
    }


def method_of(spec: RouteSpec) -> str:
    """The public method of a route: the name tests are parametrized by."""
    return spec.operation.method


async def call_route(
    edge: Edge, world: World, spec: RouteSpec, who: Identity | str | None, **overrides: Any
) -> httpx2.Response:
    """Issue the valid request of a route, as ``who``; ``overrides`` replace parts of it."""
    call = route_calls(world)[method_of(spec)]
    arguments: dict[str, Any] = {
        "key": "k-route" if spec.operation.keyed else None,
        "json": call.json,
        "params": call.params,
    }
    arguments.update(overrides)
    return await edge.request(spec.method, call.path, who, **arguments)
