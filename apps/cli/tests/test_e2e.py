"""End to end: the real ``acf-local`` against the real host agent, over its local socket and over mutual TLS.

What is real here: both transports, the length-framed JSON protocol, the host's edge and admission
pipeline (enrolment, roles, owner scopes, the safety profile), the operation store and its
idempotency, the coordinator, snapshots and restore, host modes — and this client's argument
parsing, operation handling, output and exit codes.

What is *not* real: the virtual machine. The host runs over an in-memory backend (``acf-host-fake``,
built with ``--features testing``) whose guest "runs" a command by echoing its argument vector.
These tests prove the seams between client, wire and host; they prove nothing about isolation.

Every test starts a host of its own in a private state directory and stops it afterwards.

    cargo build -p acf-host-agent --features testing --bin acf-host-fake
    ACF_HOST_FAKE=/path/to/acf-host-fake pytest -m e2e

Without ``$ACF_HOST_FAKE`` the tests are skipped — unless ``ACF_REQUIRE_E2E=1`` (set it in CI), when
that is a failure: a silently skipped end-to-end suite is how drift gets shipped.

Every request the client sends is also validated against the published API description.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import ssl
import subprocess
import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from acf_cli import requests as rq
from acf_cli.client import ClientConfig, HostClient, require_success
from acf_cli.errors import ResponseLost
from acf_cli.main import app
from acf_cli.responses import SandboxBody
from acf_cli.transport import Connection, Exchange
from acf_cli.wire import FailureClass, OperationState
from hostproc import BINARY_ENV, REQUIRE_ENV, HostUnavailable, RunningHost, find_binary, required, running_host
from support import Contract, read_frame, send_frame

pytestmark = [pytest.mark.e2e, pytest.mark.timeout(120)]

APP_DIR = Path(__file__).resolve().parents[1]
#: Small enough that several sandboxes and their snapshots fit the test host's envelope.
SMALL = ["--memory", "128", "--disk", "64"]


# ----------------------------------------------------------------------------- the host under test
def _host(*, tls: bool) -> Iterator[RunningHost]:
    if find_binary() is None:
        reason = (
            f"${BINARY_ENV} does not name the test host; build it with "
            "`cargo build -p acf-host-agent --features testing --bin acf-host-fake`"
        )
        if required():
            pytest.fail(f"{reason} ({REQUIRE_ENV}=1, so a missing end-to-end prerequisite is a failure)", pytrace=False)
        pytest.skip(reason)
    try:
        with running_host(tls=tls) as host:
            yield host
    except HostUnavailable as e:
        pytest.fail(str(e), pytrace=False)


@pytest.fixture
def host() -> Iterator[RunningHost]:
    """A host of this test's own, reachable over its local socket."""
    yield from _host(tls=False)


@pytest.fixture
def tls_host() -> Iterator[RunningHost]:
    """A host of this test's own, with a mutual TLS endpoint and four generated client identities."""
    yield from _host(tls=True)


class Checking:
    """A transport that validates every request against the published description before it is sent."""

    def __init__(self, inner: Exchange, check: Callable[[dict[str, Any]], None]) -> None:
        self._inner = inner
        self._check = check
        self.requests: list[dict[str, Any]] = []

    def exchange(self, payload: bytes, *, read_timeout_s: float) -> bytes:
        request = json.loads(payload)
        self._check(request)
        self.requests.append(request)
        return self._inner.exchange(payload, read_timeout_s=read_timeout_s)

    def close(self) -> None:
        self._inner.close()


@pytest.fixture(autouse=True)
def every_request_is_contract_valid(contract: Contract, monkeypatch: pytest.MonkeyPatch) -> None:
    """Whatever the command line sends to the real host must also be valid against the published description."""

    def new_client(config: ClientConfig) -> HostClient:
        return HostClient(config, connection=Checking(Connection(config.endpoint), contract.check_request))

    monkeypatch.setattr("acf_cli.common.new_client", new_client)


# ----------------------------------------------------------------------------- the client under test
@dataclass(frozen=True)
class Done:
    exit_code: int
    stdout: str
    stderr: str
    stdout_bytes: bytes

    def json(self) -> Any:
        assert self.stdout, f"no JSON on stdout (exit {self.exit_code}): {self.stderr}"
        return json.loads(self.stdout)

    def refusal(self) -> dict[str, Any]:
        """The refusal this invocation ended with (it must have exited 3 with ``--json``)."""
        assert self.exit_code == 3, f"expected a refusal, got exit {self.exit_code}: {self.stdout}{self.stderr}"
        refusal: dict[str, Any] = self.json()["refusal"]
        return refusal


def cli(target: list[str], *args: str) -> Done:
    """Run ``acf-local`` in this process against ``target`` (the global options that select an endpoint).

    A trailing ``--json`` is moved in front of a ``--`` separator: after it, everything is the
    guest's command line.
    """
    argv = list(args)
    if argv and argv[-1] == "--json" and "--" in argv:
        argv.insert(argv.index("--"), argv.pop())
    result = CliRunner().invoke(app, [*target, *argv], catch_exceptions=False)
    return Done(result.exit_code, result.stdout, result.stderr, result.stdout_bytes)


def ok(target: list[str], *args: str) -> Any:
    """A command that must succeed with ``--json``; returns its document."""
    done = cli(target, *args, "--json")
    assert done.exit_code == 0, f"{' '.join(args)} exited {done.exit_code}: {done.stdout}{done.stderr}"
    return done.json()


def operation(target: list[str], *args: str) -> dict[str, Any]:
    """A successful operation-creating command; returns the operation view."""
    view: dict[str, Any] = ok(target, *args)["operation"]
    assert view["state"] == "SUCCEEDED", view
    assert view["effect"] == "APPLIED", view
    return view


def result(target: list[str], *args: str) -> Any:
    """What a successful operation produced (``operation.result.data``)."""
    return operation(target, *args)["result"]["data"]


def create(target: list[str], *extra: str) -> dict[str, Any]:
    view: dict[str, Any] = result(target, "sandbox", "create", "--image", "python", *SMALL, *extra)
    return view


def started(target: list[str], name: str) -> dict[str, Any]:
    create(target, "--name", name)
    view: dict[str, Any] = result(target, "sandbox", "start", name)
    assert view["state"] == "READY"
    return view


def listed(target: list[str], kind: str, *args: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = ok(target, kind, "list", *args)["result"]["data"]["items"]
    return items


# ----------------------------------------------------------------------------- the lifecycle, on every transport
def lifecycle(target: list[str], *, peer: str, scope: str = "default") -> None:
    """Create, start, exec, inspect, snapshot, stop, destroy, delete — and what the host recorded about it."""
    info = ok(target, "host", "info")["result"]["data"]
    assert info["mode"] == "SERVING"
    assert "acf.host/2" in info["protocols"]

    box = create(target, "--name", "box", "--lifetime", "30m")
    assert (box["generation"], box["state"], box["name"]) == (1, "PROVISIONING", "box")
    assert box["tags"] == {"peer_id": peer, "owner_scope": scope}
    assert box["resources"] == {"vcpus": 1, "memory_mib": 128, "disk_mib": 64, "network": {"mode": "none"}}

    ready = result(target, "sandbox", "start", "box")
    assert ready["state"] == "READY"
    assert ready["process"] is not None

    run = cli(target, "sandbox", "exec", "box", "--", "python", "-c", "print(1)")
    assert run.exit_code == 0, run.stderr
    assert run.stdout_bytes == b"python -c print(1)\n", "the test backend echoes the argument vector"
    assert "EXITED (exit 0)" in run.stderr
    assert "SUCCEEDED" in run.stderr

    inspected = ok(target, "sandbox", "inspect", "box")["result"]["data"]
    assert inspected["state"] == "COMPLETED"
    run_id = inspected["last_run"]
    assert run_id is not None
    record = ok(target, "run", "inspect", run_id)["result"]
    assert (record["type"], record["data"]["status"], record["data"]["exit_code"]) == ("run", "EXITED", 0)
    stored = cli(target, "run", "output", run_id, "--stream", "stdout")
    assert stored.exit_code == 0
    assert stored.stdout_bytes == b"python -c print(1)\n"
    assert cli(target, "run", "output", run_id, "--stream", "stderr").stdout_bytes == b""

    snapshot = result(target, "snapshot", "create", "box", "--name", "base")
    assert snapshot["state"] == "READY"
    assert snapshot["source_sandbox"] == [box["sandbox_id"], 1]
    assert [s["name"] for s in listed(target, "snapshot")] == ["base"]

    stopped = result(target, "sandbox", "stop", "box")
    assert stopped["state"] == "STOPPED"
    destroyed = result(target, "sandbox", "destroy", "box", "--yes")
    assert destroyed["state"] == "DESTROYED"
    deleted = result(target, "snapshot", "delete", "base", "--yes")
    assert deleted["state"] == "DELETED"
    assert listed(target, "sandbox") == []
    assert listed(target, "snapshot") == []

    recorded = [o["operation_type"] for o in listed(target, "operation", "--all")]
    assert recorded == [
        "sandbox.create",
        "sandbox.start",
        "exec.run",
        "snapshot.create",
        "sandbox.stop",
        "sandbox.destroy",
        "snapshot.delete",
    ]
    assert cli(target, "sandbox", "inspect", box["sandbox_id"]).exit_code == 0, (
        "a destroyed sandbox is still readable by id"
    )


def test_the_full_lifecycle_over_the_local_socket(host: RunningHost) -> None:
    lifecycle(host.unix_args(), peer="local-operator")


def test_the_full_lifecycle_over_mutual_tls_as_an_operator(tls_host: RunningHost) -> None:
    lifecycle(tls_host.tls_args("operator"), peer="tls-operator")


def test_the_full_lifecycle_over_mutual_tls_as_a_caller(tls_host: RunningHost) -> None:
    lifecycle([*tls_host.tls_args("caller"), "--scope", "team-a"], peer="tls-caller", scope="team-a")


def test_run_once_creates_starts_runs_and_destroys(host: RunningHost) -> None:
    target = host.unix_args()
    done = cli(target, "run", "once", "--image", "python", *SMALL, "--", "echo", "one", "shot")
    assert done.exit_code == 0, done.stderr
    assert done.stdout_bytes == b"echo one shot\n"
    assert "cleanup: destroyed sbx-" in done.stderr
    assert listed(target, "sandbox") == [], "nothing is left behind"
    document = ok(target, "run", "once", "--image", "python", *SMALL, "--command", "echo again")
    assert list(document["steps"]) == ["create", "start", "exec", "destroy"]
    assert document["cleanup"]["state"] == "destroyed"
    assert document["run"]["status"] == "EXITED"


def test_run_once_keep_leaves_a_started_sandbox(host: RunningHost) -> None:
    target = host.unix_args()
    document = ok(target, "run", "once", "--image", "python", *SMALL, "--name", "kept", "--keep", "--", "true")
    assert document["cleanup"]["state"] == "kept"
    assert [s["state"] for s in listed(target, "sandbox")] == ["COMPLETED"]
    result(target, "sandbox", "destroy", "kept", "--yes")


# ----------------------------------------------------------------------------- the process itself
def acf_local(*args: str) -> subprocess.CompletedProcess[bytes]:
    """The client as a real process, the way a script runs it."""
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": str(APP_DIR / "src"),
        "PYTHONDONTWRITEBYTECODE": "1",  # a test leaves nothing behind in the source tree
    }
    return subprocess.run(
        [sys.executable, "-m", "acf_cli", *args], capture_output=True, env=env, timeout=120, check=False
    )


def test_the_process_exit_codes_and_streams(host: RunningHost) -> None:
    target = host.unix_args()
    info = acf_local(*target, "host", "info", "--json")
    assert info.returncode == 0, info.stderr.decode()
    assert json.loads(info.stdout)["result"]["data"]["host_id"] == "test-host"
    assert info.stderr == b""

    assert acf_local(*target, "sandbox", "create", "--image", "python", *SMALL, "--name", "box").returncode == 0
    assert acf_local(*target, "sandbox", "start", "box").returncode == 0
    run = acf_local(*target, "sandbox", "exec", "box", "--", "echo", "from a process")
    assert run.returncode == 0
    assert run.stdout == b"echo from a process\n", "stdout carries the guest's stdout and nothing else"
    assert b"EXITED (exit 0)" in run.stderr

    refused = acf_local(*target, "sandbox", "start", "box")
    assert refused.returncode == 3
    assert b"refused: STATE_CONFLICT" in refused.stderr
    assert refused.stdout == b""

    usage = acf_local(*target, "sandbox", "create")
    assert usage.returncode == 2
    unreachable = acf_local("--socket", str(host.base / "no-such.sock"), "host", "info")
    assert unreachable.returncode == 6
    assert b"no host agent socket" in unreachable.stderr


# ----------------------------------------------------------------------------- roles and enrolment
def test_an_observer_may_call_host_info_and_host_metrics_and_nothing_else(tls_host: RunningHost) -> None:
    observer = tls_host.tls_args("observer")
    assert ok(observer, "host", "info")["result"]["data"]["mode"] == "SERVING"
    assert "gauges" in ok(observer, "host", "metrics")["result"]["data"]
    for command in (
        ["sandbox", "list"],
        ["snapshot", "list"],
        ["operation", "list"],
        ["sandbox", "inspect", "box"],
        ["sandbox", "create", "--image", "python", *SMALL],
        ["profile", "reload"],
        ["host", "set-mode", "draining"],
    ):
        refusal = cli(observer, *command, "--json").refusal()
        assert refusal["class"] == "AUTHORIZATION_DENIED", command
        assert refusal["retry"] == "NEVER"
    assert listed(tls_host.tls_args("operator"), "operation") == [], "a refusal leaves no record"


def test_a_caller_may_not_call_operator_methods(tls_host: RunningHost) -> None:
    caller = tls_host.tls_args("caller")
    for command in (
        ["profile", "reload"],
        ["host", "set-mode", "draining"],
        ["host", "acknowledge", "store-regression", "--yes"],
        ["quarantine", "release", "sbx-" + "0" * 32, "--generation", "1", "--mode", "declare-absent", "--yes"],
    ):
        assert cli(caller, *command, "--json").refusal()["class"] == "AUTHORIZATION_DENIED", command
    assert ok(caller, "host", "info")["result"]["data"]["mode"] == "SERVING"


def test_a_certificate_that_is_valid_but_not_enrolled_is_refused_with_authentication_failed(
    tls_host: RunningHost,
) -> None:
    stranger = tls_host.tls_args("stranger")
    for command in (["host", "info"], ["sandbox", "list"], ["sandbox", "create", "--image", "python", *SMALL]):
        done = cli(stranger, *command, "--json")
        refusal = done.refusal()
        assert refusal["class"] == "AUTHENTICATION_FAILED", command
        assert refusal["retry"] == "NEVER"
        assert done.json()["as_of"] is None, "refused before any state was consulted"
    human = cli(stranger, "host", "info")
    assert human.exit_code == 3
    assert "refused: AUTHENTICATION_FAILED" in human.stderr
    assert listed(tls_host.tls_args("operator"), "sandbox") == [], "nothing was created"


def test_a_client_without_a_certificate_cannot_connect(tls_host: RunningHost) -> None:
    """Mutual TLS is the only mode of the network endpoint: without a client certificate no frame is answered."""
    assert tls_host.tls_port is not None
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=str(tls_host.tls_dir / "ca.crt"))
    request = rq.read_envelope(rq.host_info(), owner_scope="default").encode()
    answer: bytes | None = None
    with (
        contextlib.suppress(ssl.SSLError, OSError),
        socket.create_connection(("127.0.0.1", tls_host.tls_port), timeout=10) as raw,
        context.wrap_socket(raw, server_hostname="127.0.0.1") as tls,
    ):
        send_frame(tls, request)
        answer = read_frame(tls)
    assert answer is None, "the host answered a peer that presented no certificate"
    # ...and the client does not even try: the network endpoint is always mutual TLS.
    done = cli(["--tls", f"127.0.0.1:{tls_host.tls_port}", "--ca", str(tls_host.tls_dir / "ca.crt")], "host", "info")
    assert done.exit_code == 2
    assert "--cert and --key" in done.stderr


def test_a_host_certificate_is_verified_against_the_given_authority_and_name(tls_host: RunningHost) -> None:
    operator = tls_host.tls_args("operator")
    by_name = [*operator, "--server-name", "localhost"]
    assert cli(by_name, "host", "info").exit_code == 0, "the host's certificate is valid for localhost too"
    wrong_name = cli([*operator, "--server-name", "another-host.example"], "host", "info")
    assert wrong_name.exit_code == 6
    assert "was not accepted" in wrong_name.stderr
    # A certificate that is not an authority at all (the operator's own) is not accepted as the trust anchor.
    wrong_anchor = [
        a if a != str(tls_host.tls_dir / "ca.crt") else str(tls_host.tls_dir / "operator.crt") for a in operator
    ]
    refused = cli(wrong_anchor, "host", "info")
    assert refused.exit_code == 6
    assert "was not accepted" in refused.stderr


# ----------------------------------------------------------------------------- idempotency
def test_repeating_a_command_with_the_same_operation_id_returns_the_same_operation_and_creates_nothing_twice(
    host: RunningHost,
) -> None:
    target = host.unix_args()
    command = ["sandbox", "create", "--image", "python", *SMALL, "--operation-id", "e2e-create-0001"]
    first = operation(target, *command)
    again = operation(target, *command)
    assert again["operation_id"] == first["operation_id"] == "e2e-create-0001"
    assert again["created"] == first["created"], "the same record, not a new one"
    assert again["result"]["data"]["sandbox_id"] == first["result"]["data"]["sandbox_id"]
    assert len(listed(target, "sandbox")) == 1, "nothing was created twice"
    assert [o["operation_type"] for o in listed(target, "operation")] == ["sandbox.create"]


def test_the_same_operation_id_with_a_different_request_is_an_idempotency_conflict(host: RunningHost) -> None:
    target = host.unix_args()
    operation(target, "sandbox", "create", "--image", "python", *SMALL, "--operation-id", "e2e-create-0002")
    other = cli(target, "sandbox", "create", "--image", "python", "--memory", "256", "--disk", "64",
                "--operation-id", "e2e-create-0002", "--json")  # fmt: skip
    refusal = other.refusal()
    assert refusal["class"] == "IDEMPOTENCY_CONFLICT"
    assert refusal["retry"] == "NEVER"
    assert len(listed(target, "sandbox")) == 1


class Lossy:
    """A transport that loses chosen answers, the way a dropped connection does.

    ``delivered=True``: the request reaches the host and its answer is thrown away.
    ``delivered=False``: the request never arrives. Either way the client sees the same thing.
    """

    def __init__(self, inner: Exchange, lose: set[int], *, delivered: bool) -> None:
        self._inner = inner
        self._lose = lose
        self._delivered = delivered
        self.requests: list[dict[str, Any]] = []

    def exchange(self, payload: bytes, *, read_timeout_s: float) -> bytes:
        index = len(self.requests)
        self.requests.append(json.loads(payload))
        if index in self._lose:
            if self._delivered:
                self._inner.exchange(payload, read_timeout_s=read_timeout_s)
            msg = "the answer was lost on the way"
            raise ResponseLost(msg)
        return self._inner.exchange(payload, read_timeout_s=read_timeout_s)

    def close(self) -> None:
        self._inner.close()


def a_sandbox() -> rq.Call:
    resources = rq.SandboxResources(vcpus=1, memory_mib=128, disk_mib=64, network=rq.NetworkNone())
    return rq.sandbox_create(rq.SandboxCreateParams(image="python", resources=resources))


def test_a_lost_response_is_resolved_by_the_same_operation_id_and_nothing_runs_twice(
    host: RunningHost, contract: Contract
) -> None:
    """The host accepted the request and the answer never arrived: the retry finds the operation that already exists."""
    lossy = Lossy(Checking(Connection(host.unix()), contract.check_request), {0}, delivered=True)
    client = HostClient(ClientConfig(endpoint=host.unix()), connection=lossy)
    outcome = client.submit(a_sandbox())
    client.close()
    view = require_success(outcome)
    first, again = lossy.requests
    assert again["retry"] is True
    assert (again["operation_id"], again["issued_at"]) == (first["operation_id"], first["issued_at"])
    assert view.operation_id == first["operation_id"]
    target = host.unix_args()
    assert [s["sandbox_id"] for s in listed(target, "sandbox")] == [view.target], "one sandbox, not two"
    assert [o["operation_id"] for o in listed(target, "operation")] == [first["operation_id"]]


def test_a_request_that_never_arrived_is_established_as_never_accepted_and_then_submitted_under_the_same_id(
    host: RunningHost, contract: Contract
) -> None:
    lossy = Lossy(Checking(Connection(host.unix()), contract.check_request), {0}, delivered=False)
    client = HostClient(ClientConfig(endpoint=host.unix()), connection=lossy)
    outcome = client.submit(a_sandbox())
    client.close()
    view = require_success(outcome)
    methods = [r["method"] for r in lossy.requests]
    assert methods == ["sandbox.create", "sandbox.create", "operation.get", "sandbox.create"]
    assert [r.get("retry", False) for r in lossy.requests] == [False, True, False, False]
    assert len({r["operation_id"] for r in lossy.requests if "operation_id" in r}) == 1
    assert isinstance(view.result, SandboxBody)
    assert len(listed(host.unix_args(), "sandbox")) == 1


def test_a_retry_for_an_operation_the_host_never_saw_is_not_treated_as_new(host: RunningHost) -> None:
    client = HostClient(ClientConfig(endpoint=host.unix()))
    envelope = rq.operation_envelope(
        a_sandbox(), operation_id=rq.new_operation_id(), issued_at=rq.utc_timestamp(), owner_scope="default", retry=True
    )
    answer = client.roundtrip(envelope)
    client.close()
    assert answer.refusal is not None
    assert answer.refusal.failure_class is FailureClass.NOT_FOUND
    assert listed(host.unix_args(), "sandbox") == []


def test_an_operation_is_followed_to_its_end_after_no_wait(host: RunningHost) -> None:
    target = host.unix_args()
    submitted = cli(target, "sandbox", "create", "--image", "python", *SMALL, "--no-wait", "--json")
    assert submitted.exit_code in (0, 8), submitted.stderr
    view = submitted.json()["operation"]
    assert view["state"] in {"ACCEPTED", "IN_PROGRESS", "SUCCEEDED"}
    followed = ok(target, "operation", "get", view["operation_id"], "--wait", "--timeout", "30s")
    assert followed["operation"]["state"] == "SUCCEEDED"
    assert followed["operation"]["effect"] == "APPLIED"


def test_the_host_never_heard_of_an_operation_id(host: RunningHost) -> None:
    done = cli(host.unix_args(), "operation", "get", "op-never-submitted", "--json")
    assert done.refusal()["class"] == "NOT_FOUND"


# ----------------------------------------------------------------------------- owner scopes
def test_a_caller_sees_only_its_own_scope_and_an_operator_sees_everything(tls_host: RunningHost) -> None:
    team_a = [*tls_host.tls_args("caller"), "--scope", "team-a"]
    team_b = [*tls_host.tls_args("caller"), "--scope", "team-b"]
    operator = tls_host.tls_args("operator")
    local = tls_host.unix_args()

    created = operation(team_a, "sandbox", "create", "--image", "python", *SMALL, "--name", "box")
    box = created["result"]["data"]
    sandbox_id = box["sandbox_id"]
    assert box["tags"] == {"peer_id": "tls-caller", "owner_scope": "team-a"}
    result(team_a, "sandbox", "start", "box")
    result(team_a, "snapshot", "create", "box", "--name", "base")

    # Another scope: the records do not exist, for reads and for mutations alike.
    assert cli(team_b, "sandbox", "inspect", sandbox_id, "--json").refusal()["class"] == "NOT_FOUND"
    assert cli(team_b, "sandbox", "inspect", "box", "--json").refusal()["class"] == "NOT_FOUND"
    assert listed(team_b, "sandbox") == []
    assert listed(team_b, "snapshot") == []
    assert listed(team_b, "operation") == []
    assert cli(team_b, "operation", "get", created["operation_id"], "--json").refusal()["class"] == "NOT_FOUND"
    for mutation in (
        ["sandbox", "stop", sandbox_id, "--expected-generation", "1"],
        ["sandbox", "destroy", sandbox_id, "--expected-generation", "1", "--yes"],
        ["sandbox", "exec", sandbox_id, "--expected-generation", "1", "--", "true"],
        ["snapshot", "create", sandbox_id, "--expected-generation", "1"],
    ):
        assert cli(team_b, *mutation, "--json").refusal()["class"] == "NOT_FOUND", mutation
    assert listed(team_a, "sandbox")[0]["state"] == "READY", "untouched"

    # The same name is free in another scope: an alias is unique among the caller's own sandboxes only.
    twin = create(team_b, "--name", "box")
    assert twin["sandbox_id"] != sandbox_id

    # An operator reaches every record, whatever scope it asks under.
    for target in (operator, local, [*operator, "--scope", "anything"]):
        assert ok(target, "sandbox", "inspect", sandbox_id)["result"]["data"]["tags"]["owner_scope"] == "team-a"
        assert {s["sandbox_id"] for s in listed(target, "sandbox")} == {sandbox_id, twin["sandbox_id"]}
        assert [s["name"] for s in listed(target, "snapshot")] == ["base"]
    assert ok(operator, "operation", "get", created["operation_id"])["operation"]["tags"]["owner_scope"] == "team-a"
    destroyed = result(operator, "sandbox", "destroy", sandbox_id, "--expected-generation", "1", "--yes")
    assert destroyed["state"] == "DESTROYED"
    assert [s["name"] for s in listed(team_a, "sandbox")] == []


def test_on_behalf_of_is_recorded_with_the_operation(host: RunningHost) -> None:
    target = [*host.unix_args(), "--on-behalf-of", "job:42"]
    view = operation(target, "sandbox", "create", "--image", "python", *SMALL)
    assert view["on_behalf_of"] == "job:42"


# ----------------------------------------------------------------------------- network intent
def test_an_allowlist_is_accepted_and_recorded_and_an_always_denied_destination_is_refused(host: RunningHost) -> None:
    target = host.unix_args()
    box = create(
        target, "--network", "allowlist", "--allow", "pypi.org:443", "--allow", "198.51.100.0/24:5432-5433,8443"
    )
    assert box["resources"]["network"] == {
        "mode": "allowlist",
        "entries": [
            {"destination": {"name": "pypi.org"}, "ports": [{"from": 443, "to": 443}]},
            {
                "destination": {"network": "198.51.100.0/24"},
                "ports": [{"from": 5432, "to": 5433}, {"from": 8443, "to": 8443}],
            },
        ],
    }
    human = cli(target, "sandbox", "inspect", box["sandbox_id"])
    assert "allowlist: pypi.org:443, 198.51.100.0/24:5432-5433,8443" in human.stdout

    def refused_for(*allow: str) -> dict[str, Any]:
        flags = [flag for entry in allow for flag in ("--allow", entry)]
        return cli(
            target, "sandbox", "create", "--image", "python", *SMALL, "--network", "allowlist", *flags, "--json"
        ).refusal()

    # Always denied, whatever the profile says: loopback, link-local (metadata), multicast, everything.
    for destination in ("127.0.0.1:80", "169.254.169.254/32:80", "224.0.0.0/4:443", "0.0.0.0/0:443"):
        assert refused_for(destination)["class"] == "INVALID_REQUEST", destination
    # Malformed for the host although well formed for this client.
    for destination in ("*.pypi.org:443", "localhost:443", "198.51.100.7/24:443"):
        assert refused_for(destination)["class"] == "INVALID_REQUEST", destination
    # Permitted in principle, not by this host's safety profile: never clamped, refused.
    assert refused_for("10.0.0.0/8:443")["class"] == "SAFETY_CONTROL_DENIED"
    too_many = [f"host{i}.example.org:443" for i in range(5)]
    assert refused_for(*too_many)["class"] == "SAFETY_CONTROL_DENIED"
    assert len(listed(target, "sandbox")) == 1, "a refusal reserves nothing"


def test_the_safety_profile_refuses_and_never_clamps(host: RunningHost) -> None:
    target = host.unix_args()
    for flags in (
        ["--image", "not-installed"],
        ["--image", "python", "--memory", "64Gi"],
        ["--image", "python", "--lifetime", "30d"],
    ):
        refusal = cli(target, "sandbox", "create", *flags, "--disk", "64", "--json").refusal()
        assert refusal["class"] == "SAFETY_CONTROL_DENIED", flags
        assert refusal["retry"] == "AFTER_CHANGE"
    assert (
        cli(target, "sandbox", "create", "--image", "python", "--cpu", "3", "--json").refusal()["class"]
        == "INVALID_REQUEST"
    )
    started(target, "box")
    denied = cli(target, "sandbox", "exec", "box", "-e", "LD_PRELOAD=/tmp/x.so", "--json", "--", "true").refusal()
    assert denied["class"] == "SAFETY_CONTROL_DENIED"
    assert (
        cli(target, "sandbox", "exec", "box", "--cwd", "/etc", "--json", "--", "true").refusal()["class"]
        == "SAFETY_CONTROL_DENIED"
    )
    assert listed(target, "sandbox")[0]["state"] == "READY", "nothing ran"


# ----------------------------------------------------------------------------- tokens and preconditions
def test_generation_and_revision_preconditions(host: RunningHost) -> None:
    target = host.unix_args()
    box = started(target, "box")
    sandbox_id = box["sandbox_id"]
    stale = cli(target, "sandbox", "stop", sandbox_id, "--expected-generation", "7", "--json").refusal()
    assert (stale["class"], stale["retry"]) == ("REVISION_CONFLICT", "AFTER_CHANGE")
    wrong = cli(
        target, "sandbox", "stop", sandbox_id, "--expected-generation", "1", "--if-revision", "1", "--json"
    ).refusal()
    assert wrong["class"] == "REVISION_CONFLICT"
    exact = result(
        target, "sandbox", "stop", sandbox_id, "--expected-generation", "1", "--if-revision", str(box["revision"])
    )
    assert exact["state"] == "STOPPED"
    restart = cli(target, "sandbox", "start", "box", "--json").refusal()
    assert restart["class"] == "STATE_CONFLICT", "a stopped generation is never started again"
    duplicate = cli(target, "sandbox", "create", "--image", "python", *SMALL, "--name", "box", "--json").refusal()
    assert duplicate["class"] == "STATE_CONFLICT"


def test_a_secret_is_named_by_reference_and_one_that_does_not_resolve_fails_the_operation(host: RunningHost) -> None:
    target = host.unix_args()
    started(target, "box")
    done = cli(target, "sandbox", "exec", "box", "--secret-env", "LANG=not-provisioned", "--json", "--", "true")
    assert done.exit_code == 4
    view = done.json()["operation"]
    assert (view["state"], view["effect"], view["cleanup"]) == ("FAILED", "NOT_APPLIED", "COMPLETE")
    assert view["failure"]["class"] == "DEPENDENCY_UNAVAILABLE"
    human = cli(target, "sandbox", "exec", "box", "--secret-env", "LANG=not-provisioned", "--", "true")
    assert human.exit_code == 4
    assert "NOT_APPLIED - nothing was applied" in human.stderr


# ----------------------------------------------------------------------------- snapshots and restore
def test_restore_in_place_makes_a_new_generation_and_restore_as_new_makes_a_new_sandbox(host: RunningHost) -> None:
    target = host.unix_args()
    box = started(target, "box")
    sandbox_id = box["sandbox_id"]
    assert cli(target, "sandbox", "exec", "box", "--", "touch", "state").exit_code == 0
    snapshot = result(target, "snapshot", "create", "box", "--name", "base")["snapshot"]

    in_place = result(target, "snapshot", "restore", "base", "--into", "box")
    assert in_place["sandbox_id"] == sandbox_id, "the same sandbox"
    assert in_place["generation"] == 2, "a new generation of it"
    assert in_place["state"] == "READY"
    assert in_place["source_snapshot"] == snapshot
    assert in_place["expires_at"] == box["expires_at"], "a restore in place keeps the sandbox's expiry"
    old = cli(target, "sandbox", "stop", sandbox_id, "--expected-generation", "1", "--json").refusal()
    assert old["class"] == "REVISION_CONFLICT", "the old generation is no longer the one to act on"

    as_new = result(target, "snapshot", "restore", "base", "--new", "--name", "copy", "--lifetime", "10m")
    assert as_new["sandbox_id"] != sandbox_id
    assert (as_new["generation"], as_new["state"], as_new["name"]) == (1, "READY", "copy")
    assert as_new["source_snapshot"] == snapshot

    by_id = result(
        target, "snapshot", "restore", snapshot["snapshot_id"], "--snapshot-generation", "1", "--into", sandbox_id,
        "--expected-generation", "2",
    )  # fmt: skip
    assert by_id["generation"] == 3
    (listed_snapshot,) = listed(target, "snapshot")
    assert listed_snapshot["restore_count"] == 3
    assert {s["name"]: s["generation"] for s in listed(target, "sandbox")} == {"box": 3, "copy": 1}
    assert cli(target, "sandbox", "exec", "copy", "--", "true").exit_code == 0, "a restored sandbox runs commands"


def test_a_snapshot_needs_an_idle_sandbox_and_a_restore_needs_a_target(host: RunningHost) -> None:
    target = host.unix_args()
    box = create(target, "--name", "box")
    not_started = cli(target, "snapshot", "create", "box", "--json").refusal()
    assert not_started["class"] == "STATE_CONFLICT"
    result(target, "sandbox", "start", "box")
    result(target, "snapshot", "create", "box", "--name", "base")
    assert cli(target, "snapshot", "restore", "base").exit_code == 2, "in place or as new: the client does not guess"
    missing = cli(target, "snapshot", "restore", "no-such-snapshot", "--new")
    assert missing.exit_code == 3
    assert "no snapshot with id or name" in missing.stderr
    result(target, "sandbox", "destroy", box["sandbox_id"], "--expected-generation", "1", "--yes")
    gone = cli(
        target, "snapshot", "restore", "base", "--into", box["sandbox_id"], "--expected-generation", "1", "--json"
    )
    assert gone.refusal()["class"] == "STATE_CONFLICT", "a destroyed sandbox accepts no restore in place"
    assert result(target, "snapshot", "restore", "base", "--new")["state"] == "READY", "...and the snapshot outlives it"


# ----------------------------------------------------------------------------- listings and cursors
def test_changed_since_returns_exactly_what_changed_including_tombstones(host: RunningHost) -> None:
    target = host.unix_args()
    kept = started(target, "kept")
    before = ok(target, "sandbox", "list")
    cursor = before["result"]["data"]["next"]
    since = f"{cursor['lineage']}:{cursor['sequence']}"
    assert before["as_of"] == cursor, "a complete listing stands at the state it was read from"

    assert listed(target, "sandbox", "--changed-since", since) == [], "nothing has changed yet"
    doomed = create(target, "--name", "doomed")
    result(target, "sandbox", "destroy", "doomed", "--yes")
    fresh = create(target, "--name", "fresh")

    changed = ok(target, "sandbox", "list", "--changed-since", since)["result"]["data"]
    states = {s["sandbox_id"]: s["state"] for s in changed["items"]}
    assert states == {doomed["sandbox_id"]: "DESTROYED", fresh["sandbox_id"]: "PROVISIONING"}, "the tombstone is listed"
    assert kept["sandbox_id"] not in states, "what did not change is not listed"
    assert changed["more"] is False
    assert changed["next"]["sequence"] > cursor["sequence"]

    full = {s["name"] for s in listed(target, "sandbox")}
    assert full == {"kept", "fresh"}, "a full listing shows what exists"
    paged = {s["name"] for s in listed(target, "sandbox", "--all", "--limit", "1")}
    assert paged == {"kept", "fresh"}, "following the cursor page by page gives the same answer"
    human = cli(target, "sandbox", "list", "--changed-since", since)
    assert "DESTROYED" in human.stdout
    assert "listing complete; cursor " in human.stderr


def test_snapshot_tombstones_and_operation_paging(host: RunningHost) -> None:
    target = host.unix_args()
    started(target, "box")
    cursor = ok(target, "snapshot", "list")["result"]["data"]["next"]
    since = f"{cursor['lineage']}:{cursor['sequence']}"
    result(target, "snapshot", "create", "box", "--name", "one")
    result(target, "snapshot", "create", "box", "--name", "two")
    result(target, "snapshot", "delete", "one", "--yes")
    changed = {s["name"]: s["state"] for s in listed(target, "snapshot", "--changed-since", since)}
    assert changed == {"one": "DELETED", "two": "READY"}
    assert [s["name"] for s in listed(target, "snapshot")] == ["two"]

    first = ok(target, "operation", "list", "--limit", "2")["result"]["data"]
    assert len(first["items"]) == 2
    assert first["more"] is True
    everything = listed(target, "operation", "--all", "--limit", "2")
    assert [o["operation_type"] for o in everything] == [
        "sandbox.create",
        "sandbox.start",
        "snapshot.create",
        "snapshot.create",
        "snapshot.delete",
    ]
    revisions = [o["revision"] for o in everything]
    assert revisions == sorted(revisions), "ascending revision order across pages"


def test_a_cursor_from_another_store_or_from_the_future_is_refused(host: RunningHost) -> None:
    target = host.unix_args()
    cursor = ok(target, "sandbox", "list")["result"]["data"]["next"]
    foreign = cli(target, "sandbox", "list", "--changed-since", f"{'0' * 32}:1", "--json").refusal()
    assert (foreign["class"], foreign["retry"]) == ("CURSOR_EXPIRED", "AFTER_CHANGE")
    ahead = cli(
        target, "operation", "list", "--changed-since", f"{cursor['lineage']}:{cursor['sequence'] + 1000}", "--json"
    )
    assert ahead.refusal()["class"] == "CURSOR_EXPIRED"


# ----------------------------------------------------------------------------- cancel
def test_cancelling_an_operation_that_already_finished_succeeds_and_changes_nothing(host: RunningHost) -> None:
    target = host.unix_args()
    started(target, "box")
    ran = operation(target, "sandbox", "exec", "box", "--", "true")
    cancel = operation(target, "operation", "cancel", ran["operation_id"])
    assert cancel["operation_type"] == "operation.cancel"
    assert cancel["operation_id"] != ran["operation_id"], "cancelling is an operation of its own"
    assert cancel["target"] == ran["operation_id"]
    assert cancel["result"] == {
        "type": "host",
        "data": {"mode": None, "profile": None, "note": "the execution ended Succeeded"},
    }
    after = ok(target, "operation", "get", ran["operation_id"])["operation"]
    assert (after["state"], after["cancelled_by"]) == ("SUCCEEDED", None), "the finished execution is untouched"
    human = cli(target, "operation", "cancel", ran["operation_id"])
    assert human.exit_code == 0
    assert "the execution ended Succeeded" in human.stdout
    unknown = cli(target, "operation", "cancel", "op-never-submitted", "--json").refusal()
    assert unknown["class"] == "NOT_FOUND"


# ----------------------------------------------------------------------------- host modes and operator methods
def test_a_draining_host_refuses_new_privilege_and_still_serves_destroy(host: RunningHost) -> None:
    target = host.unix_args()
    box = started(target, "box")
    drained = operation(target, "host", "set-mode", "draining")
    assert drained["result"]["data"]["mode"] == "DRAINING"
    assert drained["target"] == "host"
    assert ok(target, "host", "info")["result"]["data"]["mode"] == "DRAINING"
    assert "warning: the host is DRAINING" in cli(target, "host", "info").stdout

    for granting in (
        ["sandbox", "create", "--image", "python", *SMALL],
        ["sandbox", "exec", "box", "--", "true"],
        ["snapshot", "create", "box"],
        ["run", "once", "--image", "python", *SMALL, "--", "true"],
    ):
        done = cli(target, *granting, "--json")
        assert done.exit_code == 3, granting
        document = done.json()
        refusal = document.get("refusal") or document["steps"]["create"]["refusal"]
        assert (refusal["class"], refusal["retry"]) == ("HOST_NOT_SERVING", "SAME_REQUEST_LATER"), granting

    # Containment and reads are still served: a draining host keeps removing privilege.
    assert listed(target, "sandbox")[0]["state"] == "READY"
    assert result(target, "sandbox", "stop", "box")["state"] == "STOPPED"
    destroyed = result(target, "sandbox", "destroy", box["sandbox_id"], "--expected-generation", "1", "--yes")
    assert destroyed["state"] == "DESTROYED"

    assert operation(target, "host", "set-mode", "serving")["result"]["data"]["mode"] == "SERVING"
    assert create(target)["state"] == "PROVISIONING", "serving again"


def test_profile_reload_and_the_operator_methods_that_have_nothing_to_do(host: RunningHost) -> None:
    target = host.unix_args()
    in_force = ok(target, "host", "info")["result"]["data"]["profile"]
    reloaded = operation(target, "profile", "reload")
    assert reloaded["operation_type"] == "profile.reload"
    assert reloaded["result"]["data"]["profile"] == in_force, "the same file: the same digest"
    assert "profile in force" in cli(target, "profile", "reload").stdout

    nothing = cli(target, "host", "acknowledge", "store-regression", "--yes", "--json").refusal()
    assert nothing["class"] == "STATE_CONFLICT"
    box = started(target, "box")
    for mode in ("force-destroy", "declare-absent"):
        release = cli(
            target, "quarantine", "release", box["sandbox_id"], "--generation", "1", "--mode", mode, "--yes", "--json"
        )
        assert release.refusal()["class"] == "STATE_CONFLICT", "a generation that is not quarantined is not released"
    absent = cli(
        target,
        "quarantine",
        "release",
        "sbx-" + "0" * 32,
        "--generation",
        "1",
        "--mode",
        "declare-absent",
        "--yes",
        "--json",
    )
    assert absent.refusal()["class"] == "NOT_FOUND"
    assert listed(target, "sandbox")[0]["state"] == "READY", "untouched"


def test_host_metrics_show_activity_and_standing_state(host: RunningHost) -> None:
    target = host.unix_args()
    started(target, "box")
    gauges = ok(target, "host", "metrics")["result"]["data"]["gauges"]
    assert gauges["live_sandboxes"] == 1
    assert gauges["host_mode"] == 1
    human = cli(target, "host", "metrics")
    assert "gauges.live_sandboxes" in human.stdout


def test_a_terminal_operation_is_reported_the_same_way_every_time_it_is_asked_for(host: RunningHost) -> None:
    target = host.unix_args()
    created = operation(target, "sandbox", "create", "--image", "python", *SMALL)
    seen = [ok(target, "operation", "get", created["operation_id"])["operation"] for _ in range(2)]
    assert seen[0] == seen[1]
    assert seen[0]["state"] == OperationState.SUCCEEDED.value
    human = cli(target, "operation", "get", created["operation_id"])
    assert human.exit_code == 0
    assert "APPLIED - the operation's effect is in place" in human.stdout
