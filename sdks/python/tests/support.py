"""What the tests share: canned answers, a scripted server, a clock that does not wait, and a harness.

The scripted server follows the matching rules of the client conformance suite, and adds four checks to
every request it sees, in every test:

* the request goes to the configured endpoint and nowhere else;
* it carries the credential in ``Authorization`` and nowhere else, and the ``User-Agent`` of this package;
* it is a request of the API: the generated OpenAPI document has the route, defines every query parameter
  that was sent, accepts the body, and takes an idempotency key exactly when one was sent;
* it is the request the script expects next. A request nobody scripted fails the test, and so does a
  scripted exchange that was never asked for.

The harness lets one test body drive the synchronous and the asynchronous client: ``run`` awaits what is
awaitable and returns what is not, ``collect`` drains an iterator of either kind.
"""

from __future__ import annotations

import asyncio
import json
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any, Final, overload

import httpx2

from agentcompute import AsyncFabric, Fabric, __version__
from contract import CONTRACT, REPOSITORY, registry_rows

SCENARIOS: Final = REPOSITORY / "protocols" / "conformance" / "scenarios.json"

#: The key every test client holds. It must never show up in anything a test can observe but the header.
CANARY_KEY: Final = "acf1_dev_canary_Zq7XvK2mP9w4"
BASE_URL: Final = "https://acf.test"
PROJECT: Final = "prj_0000000000000001"
ROOT: Final = f"/v1/projects/{PROJECT}"
PRINCIPAL: Final = "prn_0000000000000001"

SBX: Final = "sbx-" + "0" * 31 + "1"
SBX2: Final = "sbx-" + "0" * 31 + "2"
SNP: Final = "snp-" + "0" * 31 + "1"
SNP2: Final = "snp-" + "0" * 31 + "2"
EXE: Final = "exe-" + "0" * 31 + "1"
EXE2: Final = "exe-" + "0" * 31 + "2"
CRD: Final = "crd_0000000000000001"
OP: Final = "op-" + "a" * 32
OP2: Final = "op-" + "b" * 32
OP3: Final = "op-" + "c" * 32
REQ: Final = "req_000000000000000000000001"

type Json = dict[str, Any]
type Handler = Callable[[httpx2.Request], httpx2.Response]


#: The problem registry of the API: code -> its row.
REGISTRY_ROWS: Final = registry_rows()


# ------------------------------------------------------------------------------------------ canned views
def sandbox(state: str = "RUNNING", *, sandbox_id: str = SBX, generation: int = 1, **extra: Any) -> Json:
    view: Json = {
        "sandbox_id": sandbox_id,
        "project": PROJECT,
        "state": state,
        "generation": generation,
        "revision": f"r{generation + 10}.0123456789ab",
        "image": {"alias": "python", "digest": "sha256:" + "1" * 64},
        "resources": {"vcpus": 1, "memory_mib": 512, "disk_mib": 1024},
        "network": {"mode": "none", "entries": []},
        "expires_at": "2026-11-19T12:00:00.000Z",
        "notes": [],
        "updated_at": "2026-11-19T10:00:02.000Z",
    }
    view.update(extra)
    return view


def execution(
    status: str | None = "EXITED",
    *,
    exit_code: int | None = 0,
    state: str = "SUCCEEDED",
    execution_id: str = EXE,
    **extra: Any,
) -> Json:
    view: Json = {
        "execution_id": execution_id,
        "operation_id": OP3,
        "project": PROJECT,
        "sandbox_id": SBX,
        "generation": 1,
        "state": state,
        "terminal": state in {"SUCCEEDED", "FAILED", "CANCELLED", "UNKNOWN"},
        "stdout": {"stored_bytes": 0, "produced_bytes": 0, "completeness": "COMPLETE"},
        "stderr": {"stored_bytes": 0, "produced_bytes": 0, "completeness": "COMPLETE"},
        "provenance": {"status": "GUEST_REPORTED", "exit_code": "GUEST_REPORTED"},
    }
    if status is not None:
        view["status"] = status
    if exit_code is not None:
        view["exit_code"] = exit_code
    view.update(extra)
    return view


def snapshot(state: str = "READY", *, snapshot_id: str = SNP, generation: int = 1, **extra: Any) -> Json:
    view: Json = {
        "snapshot_id": snapshot_id,
        "snapshot_generation": generation,
        "project": PROJECT,
        "state": state,
        "revision": "r21.0123456789ab",
        "source_sandbox": {"sandbox_id": SBX, "generation": 1},
        "size_bytes": 4096,
        "restore_count": 0,
        "incompatible": [],
        "created_at": "2026-11-19T10:00:00.000Z",
    }
    view.update(extra)
    return view


def operation(
    kind: str = "sandbox.create",
    state: str = "SUCCEEDED",
    *,
    operation_id: str = OP,
    result: Json | None = None,
    effect: str | None = None,
    failure: Json | None = None,
    target: Json | None = None,
    **extra: Any,
) -> Json:
    view: Json = {
        "operation_id": operation_id,
        "project": PROJECT,
        "type": kind,
        "state": state,
        "terminal": state in {"SUCCEEDED", "FAILED", "CANCELLED", "UNKNOWN"},
        "target": target if target is not None else {"sandbox_id": SBX, "generation": 1},
        "initiated_by": "CALLER",
        "actor": {"principal_id": PRINCIPAL},
        "created_at": "2026-11-19T10:00:00.000Z",
        "updated_at": "2026-11-19T10:00:02.000Z",
        "replayed": False,
        "recorded": False,
    }
    if effect is None and state == "SUCCEEDED":
        effect = "APPLIED"
    if effect is not None:
        view["effect"] = effect
    if failure is not None:
        view["failure"] = failure
    if result is not None:
        view["result"] = result
    view.update(extra)
    return view


def failure(code: str, *, retry: str = "AFTER_CHANGE", message: str = "it failed") -> Json:
    return {"code": code, "retry": retry, "message": message, "side_effect": "NONE"}


def done(kind: str, member: str, view: Json, **extra: Any) -> Json:
    """An operation that succeeded and carries what it produced."""
    return operation(kind, "SUCCEEDED", result={member: view}, **extra)


def problem(code: str, *, kind: str | None = None, retry: str | None = None, **extra: Any) -> Json:
    """A problem document. A code of the registry gets its kind and its retry advice from there."""
    row = REGISTRY_ROWS.get(code, {})
    title = str(row.get("title", "A code this client has never seen"))
    body: Json = {
        "code": code,
        "kind": kind or row.get("kind") or "REFUSED",
        "retry": retry or row.get("retry") or "NEVER",
        "message": title,
        "request_id": REQ,
        "type": "urn:acf:problem:" + code.lower().replace("_", "-"),
        "title": title,
        "status": row.get("http_status") or 400,
        "detail": title,
        "instance": f"urn:acf:request:{REQ}",
    }
    body.update(extra)
    return body


def page(items: list[Json], *, more: bool = False, cursor: str = "end") -> Json:
    return {"next_cursor": cursor, "more": more, "items": items}


WHOAMI: Final[Json] = {
    "principal_id": PRINCIPAL,
    "project_id": PROJECT,
    "credential": {"credential_id": CRD, "kind": "developer", "expires_at": "2027-01-01T00:00:00.000Z"},
    "grants": {"methods": ["sandbox.create"]},
    "policy_version": "1",
}


# ------------------------------------------------------------------------------------- the scripted server
@dataclass(frozen=True)
class Seen:
    """One request as the server saw it."""

    method: str
    #: The path, decoded.
    path: str
    query: dict[str, str]
    headers: dict[str, str]
    body: bytes
    #: The path as it was sent, percent-encoding included, without the query.
    raw_path: str = ""

    @property
    def json(self) -> Any:
        return json.loads(self.body)

    @property
    def key(self) -> str | None:
        return self.headers.get("idempotency-key")


@dataclass(frozen=True)
class Exchange:
    """What the server expects next, and what it answers. The shapes are those of the conformance suite."""

    request: Json
    response: Json


def reply(status: int = 200, body: Json | None = None, **headers: str) -> Json:
    """A scripted answer. Header names are given with underscores: ``retry_after="1"``."""
    response: Json = {"status": status, "headers": {"x-request-id": REQ}}
    response["headers"].update({name.replace("_", "-"): value for name, value in headers.items()})
    if body is not None:
        response["json"] = body
    return response


def refusal(code: str, *, status: int | None = None, retry_after: int | None = None, **members: Any) -> Json:
    """A scripted error answer: a problem document with its media type."""
    body = problem(code, **members)
    response = reply(status or body["status"], body, content_type="application/problem+json")
    body["status"] = response["status"]
    if retry_after is not None:
        response["headers"]["retry-after"] = str(retry_after)
    return response


#: The faults a script can inject. The first two are those of the conformance suite: the request was
#: received and no response came. The others are for the tests of this package: failures that prove nothing
#: was sent (the three `connect`/`pool` ones), and other ways for an answer to be lost on the way back.
FAULTS: Final[dict[str, type[httpx2.RequestError]]] = {
    "connection_reset": httpx2.ReadError,
    "timeout": httpx2.ReadTimeout,
    "connect_error": httpx2.ConnectError,
    "connect_timeout": httpx2.ConnectTimeout,
    "pool_timeout": httpx2.PoolTimeout,
    "write_error": httpx2.WriteError,
    "write_timeout": httpx2.WriteTimeout,
    "protocol_error": httpx2.RemoteProtocolError,
    "decoding_error": httpx2.DecodingError,
}


def fault(kind: str = "connection_reset") -> Json:
    """No answer at all."""
    return {"fault": kind}


def ex(method: str, path: str, response: Json, **request: Any) -> Exchange:
    """One exchange. ``path`` is relative to the project unless it starts with ``/v1``."""
    full = path if path.startswith("/v1") else ROOT + path
    return Exchange({"method": method, "path": full, **request}, response)


@dataclass
class Script:
    """A server that answers a fixed sequence of requests and refuses everything else."""

    exchanges: Iterable[Exchange] = ()
    base_url: str = BASE_URL
    api_key: str = CANARY_KEY
    #: The idempotency key that ``$KEY`` stands for. Taken from the first request that carries one if not given.
    key: str | None = None
    seen: list[Seen] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.pending: deque[Exchange] = deque(self.exchanges)
        self._origin = httpx2.URL(self.base_url)

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        seen = Seen(
            request.method,
            request.url.path,
            dict(request.url.params),
            {name.lower(): value for name, value in request.headers.items()},
            request.content,
            request.url.raw_path.decode("ascii").partition("?")[0],
        )
        self.seen.append(seen)
        self._check_destination(request, seen)
        self._check_contract(seen)
        if not self.pending:
            self._fail(f"unexpected request: {seen.method} {seen.path} {seen.query}")
        exchange = self.pending.popleft()
        self._check_expected(exchange.request, seen)
        response = exchange.response
        if "fault" in response:
            words = response.get("message", f"scripted fault: {response['fault']}")
            raise FAULTS[response["fault"]](words, request=request)
        headers = dict(response.get("headers", {}))
        content = b""
        if "json" in response:
            content = json.dumps(response["json"]).encode()
            headers.setdefault("content-type", "application/json")
        elif "content" in response:
            content = response["content"]
        return httpx2.Response(response["status"], headers=headers, content=content)

    def _fail(self, message: str) -> None:
        self.failures.append(message)
        raise AssertionError(message)

    def _check_destination(self, request: httpx2.Request, seen: Seen) -> None:
        url = request.url
        if (url.scheme, url.host, url.port) != (self._origin.scheme, self._origin.host, self._origin.port):
            self._fail(f"a request left for another origin: {url.scheme}://{url.host}")
        if seen.headers.get("authorization") != f"Bearer {self.api_key}":
            self._fail("a request did not carry the credential in Authorization")
        if seen.headers.get("user-agent") != f"agent-compute-python/{__version__}":
            self._fail(f"unexpected User-Agent: {seen.headers.get('user-agent')}")
        if self.api_key in str(url) or self.api_key.encode() in seen.body:
            self._fail("the credential was sent outside the Authorization header")
        leaked = [name for name, value in seen.headers.items() if name != "authorization" and self.api_key in value]
        if leaked:
            self._fail(f"the credential was sent in other headers: {leaked}")

    def _check_contract(self, seen: Seen) -> None:
        """The request is one the API defines. The path is judged below the base URL's own path, if it has one."""
        prefix = self._origin.raw_path.decode("ascii").partition("?")[0].rstrip("/")
        problems = CONTRACT.judge(seen.method, seen.raw_path.removeprefix(prefix), seen.query, seen.headers, seen.body)
        if problems:
            self._fail("; ".join(problems))

    def _resolve(self, expected: Any) -> Any:
        """Replace ``$KEY`` by the key of the call, in a header value or anywhere in a body."""
        if isinstance(expected, str) and expected.startswith("$KEY") and self.key is not None:
            return self.key + expected.removeprefix("$KEY")
        if isinstance(expected, dict):
            return {name: self._resolve(value) for name, value in expected.items()}
        if isinstance(expected, list):
            return [self._resolve(value) for value in expected]
        return expected

    def _check_expected(self, expected: Json, seen: Seen) -> None:
        """The matching rules of the conformance suite: method and path equal, query and headers subsets, body equal."""
        if self.key is None and expected.get("headers", {}).get("idempotency-key") == "$KEY":
            self.key = seen.key
        if (seen.method, seen.path) != (expected["method"], expected["path"]):
            self._fail(f"expected {expected['method']} {expected['path']}, got {seen.method} {seen.path}")
        where = f"{seen.method} {seen.path}"
        for name, value in expected.get("query", {}).items():
            if seen.query.get(name) != value:
                self._fail(f"{where}: query {name}={seen.query.get(name)!r}, expected {value!r}")
        for name, value in expected.get("headers", {}).items():
            wanted = self._resolve(value)
            if seen.headers.get(name.lower()) != wanted:
                self._fail(f"{where}: header {name}={seen.headers.get(name.lower())!r}, expected {wanted!r}")
        self._check_absent(expected, seen, where)
        if "json" in expected:
            wanted = self._resolve(expected["json"])
            if wanted is None and seen.body:
                self._fail(f"{where}: a body was sent and none was expected")
            if wanted is not None and (not seen.body or seen.json != wanted):
                self._fail(f"{where}: body {seen.body!r}, expected {wanted!r}")

    def _check_absent(self, expected: Json, seen: Seen, where: str) -> None:
        """What a test of this package may add to an expectation: members that must not be sent at all."""
        for name in expected.get("absent_headers", ()):
            if name.lower() in seen.headers:
                self._fail(f"{where}: header {name} must not be sent")
        for name in expected.get("absent_query", ()):
            if name in seen.query:
                self._fail(f"{where}: query member {name} must not be sent")

    def finish(self) -> None:
        """Nothing unexpected happened, and nothing expected is left over."""
        assert not self.failures, self.failures
        left = [f"{e.request['method']} {e.request['path']}" for e in self.pending]
        assert not left, f"exchanges never asked for: {left}"


# ------------------------------------------------------------------------------------------ virtual time
class VirtualClock:
    """A clock that moves only when someone sleeps on it, so that no test waits."""

    def __init__(self) -> None:
        self.now = 1_000.0
        self.slept: list[float] = []

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        assert seconds >= 0
        self.slept.append(seconds)
        self.now += seconds

    async def asleep(self, seconds: float) -> None:
        self.sleep(seconds)

    @property
    def waited(self) -> float:
        return sum(self.slept)


# ------------------------------------------------------------------------------------------- the harness
class Harness:
    """Builds clients of one flavor on scripted servers and runs their calls."""

    def __init__(self, flavor: str) -> None:
        self.flavor = flavor
        self.is_async = flavor == "async"
        self.clock = VirtualClock()
        #: What `random.random()` would have returned: the middle of every backoff interval.
        self.jitter = 0.5
        self.scripts: list[Script] = []
        self._runner = asyncio.Runner()
        self._closers: list[Callable[[], None]] = []

    def script(self, *exchanges: Exchange, **options: Any) -> Script:
        script = Script(exchanges, **options)
        self.scripts.append(script)
        return script

    def client(self, server: Script | Handler, **options: Any) -> Fabric | AsyncFabric:
        """A client whose HTTP stack is the scripted server and whose clock is virtual."""
        handler = server.handler if isinstance(server, Script) else server
        options.setdefault("base_url", BASE_URL)
        options.setdefault("project", PROJECT)
        api_key = options.pop("api_key", CANARY_KEY)
        transport = httpx2.MockTransport(handler)
        fabric: Fabric | AsyncFabric
        if self.is_async:
            http = httpx2.AsyncClient(transport=transport)
            self._closers.append(lambda: self._runner.run(http.aclose()))
            fabric = AsyncFabric(api_key, http_client=http, **options)
        else:
            sync_http = httpx2.Client(transport=transport)
            self._closers.append(sync_http.close)
            fabric = Fabric(api_key, http_client=sync_http, **options)
        self.virtualize(fabric)
        return fabric

    def virtualize(self, fabric: Fabric | AsyncFabric) -> None:
        """Replace the client's clock, sleep and jitter. The seam every runner of the conformance suite needs."""
        engine = fabric._driver.engine
        engine.clock = self.clock.time
        engine.jitter = lambda: self.jitter
        if isinstance(fabric, AsyncFabric):
            fabric._driver.sleep = self.clock.asleep
        else:
            fabric._driver.sleep = self.clock.sleep

    @overload
    def run[T](self, value: Awaitable[T]) -> T: ...
    @overload
    def run[T](self, value: T) -> T: ...
    def run(self, value: Any) -> Any:
        """The result of a call of either client."""
        if isinstance(value, Awaitable):
            return self._runner.run(_await(value))
        return value

    @overload
    def collect[T](self, items: AsyncIterator[T]) -> list[T]: ...
    @overload
    def collect[T](self, items: Iterator[T]) -> list[T]: ...
    def collect(self, items: Any) -> list[Any]:
        """Every item of a listing of either client."""
        if isinstance(items, AsyncIterator):
            return self._runner.run(_drain(items))
        return list(items)

    def close(self) -> None:
        for closer in self._closers:
            closer()
        self._runner.close()

    def finish(self) -> None:
        for script in self.scripts:
            script.finish()


async def _await(value: Awaitable[Any]) -> Any:
    return await value


async def _drain(items: AsyncIterator[Any]) -> list[Any]:
    return [item async for item in items]
