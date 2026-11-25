"""What the tests share: canned answers, a scripted platform, a clock that does not wait, and a runner.

The scripted platform follows the matching rules of the client conformance suite (method and path equal,
query and headers as subsets, body equal, no request unexpected and none left over) and adds two checks
to every request it sees, in every test: the request goes to the configured endpoint and nowhere else,
and it carries the credential in ``Authorization`` and nowhere else.

The runner runs the real command line in this process: it parses the arguments as ``acf`` would, with
standard input, output and error replaced by streams the test can read and whose "is a terminal" it
controls. The SDK client the commands build is the real one, on a scripted transport.
"""

from __future__ import annotations

import io
import json
import ssl
import sys
import time
from collections import deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import httpx2
import pytest
import yaml
from agentcompute import Fabric

from agentcompute_cli import common, credentials, mcp
from agentcompute_cli.main import app

REPOSITORY: Final = Path(__file__).resolve().parents[3]
PACKAGE: Final = Path(__file__).resolve().parents[1]
SURFACE: Final = REPOSITORY / "protocols" / "api" / "surface.yaml"
REGISTRY: Final = REPOSITORY / "protocols" / "api" / "problems" / "registry.yaml"
SCENARIOS: Final = REPOSITORY / "protocols" / "conformance" / "scenarios.json"
TOOLS: Final = REPOSITORY / "protocols" / "mcp" / "tools"

#: The key every test client holds. It must never show up in anything a test can observe but the header.
CANARY_KEY: Final = "acf1_dev_canary_Zq7XvK2mP9w4"
#: The same, for the relay: a key whose marker says it is an agent's.
AGENT_KEY: Final = "acf1_agt_canary_Hn5RtB8sQ3y6"
BASE_URL: Final = "https://acf.test"
MCP_URL: Final = "https://mcp.acf.test/mcp"
PROJECT: Final = "prj_0000000000000001"
ROOT: Final = f"/v1/projects/{PROJECT}"
PRINCIPAL: Final = "prn_0000000000000001"

SBX: Final = "sbx-" + "0" * 31 + "1"
SBX2: Final = "sbx-" + "0" * 31 + "2"
SNP: Final = "snp-" + "0" * 31 + "1"
EXE: Final = "exe-" + "0" * 31 + "1"
EXE2: Final = "exe-" + "0" * 31 + "2"
CRD: Final = "crd_0000000000000001"
OP: Final = "op-" + "a" * 32
OP2: Final = "op-" + "b" * 32
OP3: Final = "op-" + "c" * 32
REQ: Final = "req_000000000000000000000001"

type Json = dict[str, Any]


def surface() -> list[Json]:
    """The public operations of the API, from the generated table."""
    document = yaml.safe_load(SURFACE.read_text(encoding="utf-8"))
    operations: list[Json] = document["operations"]
    return operations


def registry() -> dict[str, Json]:
    """The problem registry of the API: code -> its row."""
    document = yaml.safe_load(REGISTRY.read_text(encoding="utf-8"))
    return {row["code"]: row for row in document["codes"]}


REGISTRY_ROWS: Final = registry()


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
    stdout_bytes: int = 0,
    stderr_bytes: int = 0,
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
        "stdout": {"stored_bytes": stdout_bytes, "produced_bytes": stdout_bytes, "completeness": "COMPLETE"},
        "stderr": {"stored_bytes": stderr_bytes, "produced_bytes": stderr_bytes, "completeness": "COMPLETE"},
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


def whoami(kind: str = "developer", **extra: Any) -> Json:
    view: Json = {
        "principal_id": PRINCIPAL,
        "project_id": PROJECT,
        "credential": {"credential_id": CRD, "kind": kind, "expires_at": "2027-01-01T00:00:00.000Z"},
        "grants": {
            "methods": ["sandbox.create", "sandbox.get"],
            "images": ["python"],
            "network": {"modes": ["none"]},
            "ceilings": {"vcpus": 2, "memory_mib": 4096},
            "mint_agent_credentials": True,
        },
        "policy_version": "1",
    }
    view.update(extra)
    return view


def credential(status: str = "ACTIVE", **extra: Any) -> Json:
    view: Json = {
        "credential_id": CRD,
        "kind": "agent",
        "label": "builder",
        "display_prefix": "acf1_agt_abcd",
        "status": status,
        "issued_at": "2026-11-19T10:00:00.000Z",
        "expires_at": "2026-11-19T12:00:00.000Z",
    }
    view.update(extra)
    return view


def info(**extra: Any) -> Json:
    view: Json = {
        "api_versions": ["v1"],
        "serving": True,
        "ready": True,
        "platform_features": ["agent_credentials"],
        "host_features": ["snapshots"],
        "parameters": {"public_wait_max": 30},
        "ceilings": {
            "vcpus": 2,
            "memory_mib": 4096,
            "disk_mib": 20480,
            "execution_timeout_seconds": 600,
            "sandbox_lifetime_seconds": 86400,
            "allowlist_entries": 16,
        },
    }
    view.update(extra)
    return view


def chunk(data_base64: str = "", *, offset: int = 0, size: int = 0, eof: bool = True, **extra: Any) -> Json:
    view: Json = {
        "execution_id": EXE,
        "stream": "stdout",
        "offset": offset,
        "data_base64": data_base64,
        "next_offset": offset + size,
        "eof": eof,
        "stored_bytes": offset + size,
        "produced_bytes": offset + size,
        "completeness": "COMPLETE",
        "provenance": "GUEST_REPORTED",
    }
    view.update(extra)
    return view


# ------------------------------------------------------------------------------------- the scripted platform
@dataclass(frozen=True)
class Seen:
    """One request as the platform saw it."""

    method: str
    path: str
    query: dict[str, str]
    headers: dict[str, str]
    body: bytes

    @property
    def json(self) -> Any:
        return json.loads(self.body)

    @property
    def key(self) -> str | None:
        return self.headers.get("idempotency-key")


@dataclass(frozen=True)
class Exchange:
    """What the platform expects next, and what it answers. The shapes are those of the conformance suite."""

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


#: The ways a script can make an answer not arrive. The first two are those of the conformance suite: the
#: request was received and no response came. ``connect_error`` proves that nothing was sent.
FAULTS: Final[dict[str, type[httpx2.RequestError]]] = {
    "connection_reset": httpx2.ReadError,
    "timeout": httpx2.ReadTimeout,
    "connect_error": httpx2.ConnectError,
}


def fault(kind: str = "connection_reset", message: str | None = None) -> Json:
    """No answer at all. ``message`` is what the HTTP library says about it."""
    return {"fault": kind} if message is None else {"fault": kind, "message": message}


def interrupt() -> Json:
    """The person presses Ctrl-C while the request is on its way."""
    return {"interrupt": True}


def ex(method: str, path: str, response: Json, **request: Any) -> Exchange:
    """One exchange. ``path`` is relative to the project unless it starts with ``/v1``."""
    full = path if path.startswith("/v1") else ROOT + path
    return Exchange({"method": method, "path": full, **request}, response)


@dataclass
class Script:
    """A platform that answers a fixed sequence of requests and refuses everything else."""

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
        )
        self.seen.append(seen)
        self._check_destination(request, seen)
        if not self.pending:
            self._fail(f"unexpected request: {seen.method} {seen.path} {seen.query}")
        exchange = self.pending.popleft()
        self._check_expected(exchange.request, seen)
        response = exchange.response
        if "interrupt" in response:
            raise KeyboardInterrupt
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
        if self.api_key in str(url) or self.api_key.encode() in seen.body:
            self._fail("the credential was sent outside the Authorization header")
        leaked = [name for name, value in seen.headers.items() if name != "authorization" and self.api_key in value]
        if leaked:
            self._fail(f"the credential was sent in other headers: {leaked}")

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
        for name in expected.get("absent_headers", ()):
            if name.lower() in seen.headers:
                self._fail(f"{where}: header {name} must not be sent")
        if "json" in expected:
            wanted = self._resolve(expected["json"])
            if wanted is None and seen.body:
                self._fail(f"{where}: a body was sent and none was expected")
            if wanted is not None and (not seen.body or seen.json != wanted):
                self._fail(f"{where}: body {seen.body!r}, expected {wanted!r}")

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

    @property
    def waited(self) -> float:
        return sum(self.slept)


# -------------------------------------------------------------------------------------------- the runner
class FakeStream(io.TextIOWrapper):
    """A text stream over bytes that a test can read, and whose "is a terminal" the test decides."""

    def __init__(self, data: bytes = b"", *, tty: bool = False) -> None:
        self._raw = io.BytesIO(data)
        super().__init__(self._raw, encoding="utf-8", errors="backslashreplace", write_through=True)
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty

    @property
    def written(self) -> bytes:
        self.flush()
        return self._raw.getvalue()


@dataclass
class Run:
    """One run of the command line against a scripted platform."""

    exit_code: int
    stdout_bytes: bytes
    stderr_bytes: bytes
    script: Script

    @property
    def stdout(self) -> str:
        return self.stdout_bytes.decode("utf-8", "backslashreplace")

    @property
    def stderr(self) -> str:
        return self.stderr_bytes.decode("utf-8", "backslashreplace")

    @property
    def json(self) -> Any:
        """Standard output, which must be exactly one JSON document."""
        return json.loads(self.stdout_bytes)

    @property
    def error_document(self) -> Any:
        """The answer of the API that a failed ``--json`` command prints: the first line of standard error."""
        first = self.stderr.splitlines()[0]
        assert first.startswith("{"), f"standard error does not begin with a JSON document: {first!r}"
        return json.loads(first)

    @property
    def requests(self) -> list[Seen]:
        return self.script.seen


class Cli:
    """Runs ``acf`` in this process, on a scripted platform and a clock that does not wait."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
        self._monkeypatch = monkeypatch
        self.home = home
        self.clock = VirtualClock()
        self.scripts: list[Script] = []
        #: What each client the commands built was configured with: the settings, and the request timeout.
        self.clients: list[tuple[credentials.Settings, float | None]] = []
        #: Whom each relay was told to believe about the endpoint's certificate. ``None``: the default.
        self.relay_trust: list[ssl.SSLContext | None] = []
        #: The environment every run starts from. A test replaces or removes entries as it needs.
        self.env: dict[str, str | None] = {
            "ACF_API_KEY": CANARY_KEY,
            "ACF_BASE_URL": BASE_URL,
            "ACF_PROJECT": PROJECT,
            "ACF_PROFILE": None,
            "ACF_MCP_URL": None,
            "ACF_CA_FILE": None,
            "NO_COLOR": None,
            "XDG_CONFIG_HOME": str(home / "config"),
            "APPDATA": str(home / "roaming"),
            "HOME": str(home),
            "COLUMNS": "200",
        }

    @property
    def credentials_file(self) -> Path:
        return self.home / "config" / "acf" / "credentials.json"

    def run(
        self,
        args: Sequence[str],
        *exchanges: Exchange,
        env: Mapping[str, str | None] | None = None,
        stdin: bytes = b"",
        tty: bool = False,
        stdin_tty: bool = False,
        key: str | None = None,
        api_key: str = CANARY_KEY,
        base_url: str = BASE_URL,
        stdout: FakeStream | None = None,
        endpoint: Callable[[httpx2.Request], Any] | None = None,
    ) -> Run:
        """Run one command. ``exchanges`` is everything the platform is asked, in order, and what it answers.

        ``endpoint`` answers what ``acf mcp`` posts to the MCP endpoint. A run that has one keeps the real
        clock: the relay is an event loop, and an event loop needs time to pass.
        """
        script = Script(exchanges, base_url=base_url, api_key=api_key, key=key)
        self.scripts.append(script)
        transport = httpx2.MockTransport(script.handler)

        def new_fabric(settings: credentials.Settings, *, timeout: float | None) -> Fabric:
            self.clients.append((settings, timeout))
            http = httpx2.Client(transport=transport)
            options: dict[str, Any] = {} if timeout is None else {"timeout": timeout}
            return Fabric(
                settings.api_key, base_url=settings.base_url, project=settings.project, http_client=http, **options
            )

        def new_http_client(trust: ssl.SSLContext | None = None) -> httpx2.AsyncClient:
            assert endpoint is not None, "this run was not expected to relay anything"
            self.relay_trust.append(trust)
            return httpx2.AsyncClient(transport=httpx2.MockTransport(endpoint))

        out = stdout if stdout is not None else FakeStream(tty=tty)
        err = FakeStream(tty=tty)
        with self._monkeypatch.context() as patch:
            patch.setattr(common, "new_fabric", new_fabric)
            patch.setattr(mcp, "new_http_client", new_http_client)
            if endpoint is None:
                # The SDK takes its clock and its sleep from here when a client is built.
                patch.setattr(time, "monotonic", self.clock.time)
                patch.setattr(time, "sleep", self.clock.sleep)
            for name, value in {**self.env, **(env or {})}.items():
                if value is None:
                    patch.delenv(name, raising=False)
                else:
                    patch.setenv(name, value)
            patch.setattr(sys, "stdin", FakeStream(stdin, tty=stdin_tty))
            patch.setattr(sys, "stdout", out)
            patch.setattr(sys, "stderr", err)
            try:
                app(list(args), prog_name="acf")
            except SystemExit as stop:
                code = stop.code
            else:
                code = 0
            exit_code = 0 if code is None else code
            assert isinstance(exit_code, int), f"the process would exit with {exit_code!r}"
        return Run(exit_code, out.written, err.written, script)

    def finish(self) -> None:
        for script in self.scripts:
            script.finish()
