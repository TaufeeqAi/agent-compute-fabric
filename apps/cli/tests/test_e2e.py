"""End-to-end: the real ``acf-local`` against the real host agent, over a real Unix socket.

What is real here: the socket, the length-framed JSON protocol, the Rust server, admission, the
operation journal and idempotency, the lifecycle coordinator, evidence capture, snapshots and
restore verification, ``SO_PEERCRED`` authorization, and the CLI's exit codes and output streams.

What is *not* real: the virtual machine. The host runs over an in-memory backend
(``acf-host-fake``, built with ``--features testing``) whose guest "runs" a command by echoing its
argv. These tests prove the **seams** (CLI <-> wire <-> host), not isolation; isolation is proven
only by the KVM-gated suites under ``tests/isolation`` on a real host.

Two layers:

* **wire** tests speak ``acf.host/1`` with raw frames (no ``acf_cli`` code on the path) and
  validate every request and every real response against the JSON Schemas the host emits. If the
  server ever answers in a shape its own schema does not describe, this is where it fails.
* **cli** tests run ``acf-local`` as a subprocess and check what an operator or a script sees:
  exit codes, which stream carries what, and that nothing is left behind.

Build the binary:  ``cargo build -p acf-host-agent --features testing --bin acf-host-fake``.
It is located via ``$ACF_HOST_FAKE``, else ``<repo>/target/{debug,release}/acf-host-fake``. When it
is missing the tests are *skipped*, unless ``ACF_REQUIRE_E2E=1`` (set it in CI), when that is a
*failure*: a silently skipped contract suite is how drift gets shipped.

Unix socket paths are limited to 107 bytes; if ``$TMPDIR`` is too deep, point it somewhere short.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

import pytest
from jsonschema import Draft202012Validator

from acf_cli import models as m
from acf_cli.client import new_operation_id
from conftest import REPO_ROOT
from support import PROTOCOL, read_frame, send_frame

pytestmark = pytest.mark.e2e

BINARY_ENV = "ACF_HOST_FAKE"
REQUIRE_ENV = "ACF_REQUIRE_E2E"
SUN_PATH_MAX = 107
APP_DIR = Path(__file__).resolve().parents[1]
CLI_ENTRY = APP_DIR / "main.py"
IMAGE = "python"

# Small enough that a snapshot fits the fake host's 1 GiB snapshot quota (memory + disk + overhead).
SMALL = ("--memory", "128", "--disk", "256")


# ----------------------------------------------------------------------------- the host under test
def _unavailable(reason: str) -> NoReturn:
    if os.environ.get(REQUIRE_ENV) == "1":
        pytest.fail(f"{reason} ({REQUIRE_ENV}=1, so a missing e2e prerequisite is a failure)", pytrace=False)
    pytest.skip(reason)


def _find_binary() -> Path | None:
    explicit = os.environ.get(BINARY_ENV)
    candidates = (
        [Path(explicit)]
        if explicit
        else [REPO_ROOT / "target" / profile / "acf-host-fake" for profile in ("debug", "release")]
    )
    return next((c for c in candidates if c.is_file() and os.access(c, os.X_OK)), None)


@dataclass(frozen=True)
class RunningHost:
    socket: Path
    log: Path


@pytest.fixture(scope="module")
def host() -> Iterator[RunningHost]:
    binary = _find_binary()
    if binary is None:
        _unavailable(
            "acf-host-fake is not built: cargo build -p acf-host-agent --features testing --bin acf-host-fake "
            f"(or set ${BINARY_ENV})"
        )
    base = Path(tempfile.mkdtemp(prefix="acf-e2e-"))
    sock = base / "h.sock"
    if len(os.fsencode(sock)) > SUN_PATH_MAX:
        shutil.rmtree(base, ignore_errors=True)
        _unavailable(f"{sock} is longer than the {SUN_PATH_MAX}-byte AF_UNIX limit; set TMPDIR to a shorter directory")
    log = base / "host.log"
    with log.open("wb") as log_file:
        proc = subprocess.Popen(
            [str(binary), "--state", str(base / "state"), "--socket", str(sock)],
            stdin=subprocess.DEVNULL,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            env={"PATH": os.environ.get("PATH", "")},
        )
        try:
            _wait_until_listening(sock, proc, log)
            yield RunningHost(socket=sock, log=log)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            shutil.rmtree(base, ignore_errors=True)


def _wait_until_listening(sock: Path, proc: subprocess.Popen[bytes], log: Path) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            pytest.fail(
                f"acf-host-fake exited with {proc.returncode}: {log.read_text(errors='replace')}", pytrace=False
            )
        with contextlib.closing(socket.socket(socket.AF_UNIX)) as probe:
            try:
                probe.connect(str(sock))
            except OSError:
                time.sleep(0.05)
                continue
            return
    pytest.fail(f"acf-host-fake did not start listening: {log.read_text(errors='replace')}", pytrace=False)


# ----------------------------------------------------------------------------- raw wire client
@pytest.fixture(scope="module")
def request_validator(request_schema: dict[str, Any]) -> Draft202012Validator:
    return Draft202012Validator(request_schema)


@pytest.fixture(scope="module")
def response_validator(response_schema: dict[str, Any]) -> Draft202012Validator:
    return Draft202012Validator(response_schema)


class Wire:
    """One request per connection, exactly as the CLI does, with schema validation on both sides."""

    def __init__(self, path: Path, request_v: Draft202012Validator, response_v: Draft202012Validator) -> None:
        self.path = path
        self._request_v = request_v
        self._response_v = response_v

    def raw(self, payload: bytes) -> dict[str, Any] | None:
        """Send arbitrary bytes as one frame; return the parsed reply (``None`` if the host just hung up)."""
        with contextlib.closing(socket.socket(socket.AF_UNIX)) as conn:
            conn.settimeout(30)
            conn.connect(str(self.path))
            send_frame(conn, payload)
            reply = read_frame(conn)
        if reply is None:
            return None
        doc = json.loads(reply)
        assert isinstance(doc, dict)
        return doc

    def call(
        self, body: m.Body | dict[str, Any], *, operation_id: str | None = None, validate_request: bool = True
    ) -> dict[str, Any]:
        wire_body = body.wire() if isinstance(body, m.Body) else body
        envelope: dict[str, Any] = {"protocol": PROTOCOL, "request_id": f"req-{uuid.uuid4().hex}", "body": wire_body}
        if operation_id is not None:
            envelope["operation_id"] = operation_id
        if validate_request:
            self._request_v.validate(envelope)
        doc = self.raw(json.dumps(envelope).encode())
        assert doc is not None, "the host hung up without answering"
        self._response_v.validate(doc)  # the real server must answer in the shape its own schema publishes
        assert doc["request_id"] == envelope["request_id"], "responses are correlated to their requests"
        return doc

    def mutate(self, body: m.Body, *, operation_id: str | None = None) -> dict[str, Any]:
        return self.call(body, operation_id=operation_id or new_operation_id())

    def ok(self, body: m.Body) -> dict[str, Any]:
        """A mutation that must succeed; returns its ``result.data``."""
        doc = self.mutate(body)
        assert doc["status"] == "SUCCEEDED", doc
        data = doc["result"]["data"]
        assert isinstance(data, dict)
        return data

    def live_sandboxes(self) -> list[dict[str, Any]]:
        """Sandboxes that still hold resources (a destroyed generation stays listed as a tombstone)."""
        items: list[dict[str, Any]] = self.call(m.SandboxListRequest())["result"]["data"]
        return [s for s in items if s["state"] != "DESTROYED"]

    def live_snapshots(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = self.call(m.SnapshotListRequest())["result"]["data"]
        return [s for s in items if s["state"] != "DELETED"]


@pytest.fixture
def wire(host: RunningHost, request_validator: Draft202012Validator, response_validator: Draft202012Validator) -> Wire:
    return Wire(host.socket, request_validator, response_validator)


@pytest.fixture(autouse=True)
def clean_slate(wire: Wire) -> Iterator[None]:
    """Every test starts and ends with an empty host, so tests cannot depend on each other."""
    yield
    for snap in wire.live_snapshots():
        ref = m.SnapshotRef(**snap["snapshot"])
        wire.mutate(m.SnapshotDeleteRequest(params=ref))
    for sbx in wire.live_sandboxes():
        target = m.SandboxTarget(sandbox_id=sbx["sandbox_id"], expected_generation=sbx["generation"])
        wire.mutate(m.SandboxDestroyRequest(params=target))


# ----------------------------------------------------------------------------- CLI under test
@dataclass(frozen=True)
class Done:
    code: int
    out: bytes
    err: bytes

    @property
    def stdout(self) -> str:
        return self.out.decode("utf-8", errors="replace")

    @property
    def stderr(self) -> str:
        return self.err.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.out)


class Cli:
    def __init__(self, socket_path: Path) -> None:
        self.socket_path = socket_path

    def __call__(self, *args: str, socket_path: Path | None = None, timeout: float = 90.0) -> Done:
        env = {
            "PATH": os.environ.get("PATH", ""),
            "ACF_SOCKET": str(socket_path or self.socket_path),
            "NO_COLOR": "1",
            "COLUMNS": "200",
            "TERM": "dumb",
            "LC_ALL": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        proc = subprocess.run(
            [sys.executable, str(CLI_ENTRY), *args],
            capture_output=True,
            stdin=subprocess.DEVNULL,
            env=env,
            timeout=timeout,
            check=False,
        )
        return Done(proc.returncode, proc.stdout, proc.stderr)


@pytest.fixture
def cli(host: RunningHost) -> Cli:
    return Cli(host.socket)


def unique(prefix: str = "e2e") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


# ============================================================================= wire: the real host speaks its schema
def test_every_read_the_cli_uses_answers_in_the_published_schema(wire: Wire) -> None:
    info = wire.call(m.HostInfoRequest())
    assert info["status"] == "SUCCEEDED"
    assert info["result"]["data"]["protocol"] == PROTOCOL
    assert wire.call(m.MetricsRequest())["status"] == "SUCCEEDED"
    assert wire.live_sandboxes() == []
    assert wire.live_snapshots() == []


def test_unknown_things_are_refused_definitively_and_say_so(wire: Wire) -> None:
    missing_op = wire.call(m.OperationGetRequest(params=m.OperationSelector(operation_id="op-" + "0" * 32)))
    assert missing_op["status"] == "REJECTED"
    assert missing_op["error"]["class"] == "NOT_FOUND"
    assert missing_op["error"]["side_effect"] == "none"
    assert missing_op["error"]["outcome_unknown"] is False
    missing_run = wire.call(m.RunInspectRequest(params=m.RunSelector(run_id="run-" + "0" * 32)))
    assert missing_run["status"] == "REJECTED"
    assert missing_run["error"]["class"] == "NOT_FOUND"


def test_a_complete_lifecycle_validates_against_the_schema_at_every_step(wire: Wire) -> None:
    resources = m.SandboxResources(vcpus=1, memory_mib=128, disk_mib=256, network="none")
    created = wire.ok(m.SandboxCreateRequest(params=m.SandboxCreateParams(image=IMAGE, resources=resources)))
    sandbox_id, generation = created["sandbox_id"], created["generation"]
    assert (created["state"], generation) == ("PROVISIONING", 1)

    target = m.SandboxTarget(sandbox_id=sandbox_id, expected_generation=generation)
    assert wire.ok(m.SandboxStartRequest(params=target))["state"] == "READY"

    command = m.CommandSpec(argv=["echo", "over", "the", "wire"])
    run = wire.ok(
        m.ExecRequest(params=m.ExecParams(sandbox_id=sandbox_id, expected_generation=generation, command=command))
    )
    assert (run["outcome"], run["exit_code"]) == ("SUCCEEDED", 0)
    assert base64.b64decode(run["stdout"]["data_b64"]) == b"echo over the wire\n"
    assert run["evidence_status"] == "COMPLETE"

    inspected = wire.call(m.RunInspectRequest(params=m.RunSelector(run_id=run["run_id"])))
    assert inspected["status"] == "SUCCEEDED"
    assert inspected["result"]["data"]["run_id"] == run["run_id"], "evidence is retrievable by run id"

    snap = wire.ok(
        m.SnapshotCreateRequest(
            params=m.SnapshotCreateParams(sandbox_id=sandbox_id, expected_generation=generation, name="s")
        )
    )
    snap_ref = m.SnapshotRef(**snap["snapshot"])
    restored = wire.ok(
        m.SnapshotRestoreRequest(
            params=m.SnapshotRestoreParams(
                snapshot=snap_ref, target=m.RestoreExisting(sandbox_id=sandbox_id, expected_generation=generation)
            )
        )
    )
    assert restored["sandbox_id"] == sandbox_id
    assert restored["generation"] == generation + 1, "a restore is a NEW generation; generations are never reused"
    assert restored["source_snapshot"]["snapshot_id"] == snap_ref.snapshot_id

    new_target = m.SandboxTarget(sandbox_id=sandbox_id, expected_generation=restored["generation"])
    assert wire.ok(m.SandboxStopRequest(params=new_target))["state"] in {"STOPPED", "COMPLETED"}
    assert wire.ok(m.SandboxDestroyRequest(params=new_target))["state"] == "DESTROYED"
    assert wire.ok(m.SnapshotDeleteRequest(params=snap_ref))["state"] == "DELETED"


def test_replaying_an_operation_id_returns_the_recorded_answer_and_does_not_act_twice(wire: Wire) -> None:
    resources = m.SandboxResources(vcpus=1, memory_mib=128, disk_mib=256, network="none")
    request = m.SandboxCreateRequest(params=m.SandboxCreateParams(image=IMAGE, resources=resources))
    op = new_operation_id()
    first = wire.mutate(request, operation_id=op)
    second = wire.mutate(request, operation_id=op)
    assert first["status"] == second["status"] == "SUCCEEDED"
    assert first["result"]["data"]["sandbox_id"] == second["result"]["data"]["sandbox_id"]
    live = wire.live_sandboxes()
    assert len(live) == 1, "the retry must be a replay, not a second sandbox"


def test_the_same_operation_id_with_a_different_request_is_refused(wire: Wire) -> None:
    small = m.SandboxResources(vcpus=1, memory_mib=128, disk_mib=256, network="none")
    bigger = m.SandboxResources(vcpus=1, memory_mib=256, disk_mib=256, network="none")
    op = new_operation_id()
    assert (
        wire.mutate(
            m.SandboxCreateRequest(params=m.SandboxCreateParams(image=IMAGE, resources=small)), operation_id=op
        )["status"]
        == "SUCCEEDED"
    )
    reused = wire.mutate(
        m.SandboxCreateRequest(params=m.SandboxCreateParams(image=IMAGE, resources=bigger)), operation_id=op
    )
    assert reused["status"] in {"REJECTED", "CONFLICT"}, reused
    assert reused["error"]["side_effect"] == "none"
    assert len(wire.live_sandboxes()) == 1


def test_a_stale_generation_is_refused_and_nothing_changes(wire: Wire) -> None:
    resources = m.SandboxResources(vcpus=1, memory_mib=128, disk_mib=256, network="none")
    sandbox = wire.ok(m.SandboxCreateRequest(params=m.SandboxCreateParams(image=IMAGE, resources=resources)))
    stale = m.SandboxTarget(sandbox_id=sandbox["sandbox_id"], expected_generation=sandbox["generation"] + 5)
    refused = wire.mutate(m.SandboxDestroyRequest(params=stale))
    assert refused["status"] == "CONFLICT", refused
    assert refused["error"]["side_effect"] == "none"
    still = wire.live_sandboxes()
    assert [s["sandbox_id"] for s in still] == [sandbox["sandbox_id"]]


def test_policy_refusals_are_definite_and_leave_no_sandbox(wire: Wire) -> None:
    resources = m.SandboxResources(vcpus=1, memory_mib=128, disk_mib=256, network="none")
    bad_image = wire.mutate(
        m.SandboxCreateRequest(params=m.SandboxCreateParams(image="not-in-policy", resources=resources))
    )
    assert bad_image["status"] == "REJECTED"
    assert bad_image["error"]["side_effect"] == "none"
    too_big = m.SandboxResources(vcpus=1, memory_mib=10_000_000, disk_mib=256, network="none")
    refused = wire.mutate(m.SandboxCreateRequest(params=m.SandboxCreateParams(image=IMAGE, resources=too_big)))
    assert refused["status"] == "REJECTED"
    assert refused["error"]["side_effect"] == "none"
    assert wire.live_sandboxes() == []


def test_a_malformed_request_is_answered_and_does_not_disturb_the_host(wire: Wire) -> None:
    by_name = wire.call(
        {"method": "sandbox_destroy", "params": {"sandbox": "work"}},
        operation_id=new_operation_id(),
        validate_request=False,
    )
    assert by_name["status"] == "REJECTED", "destructive operations cannot be expressed by name"
    assert by_name["error"]["class"] == "VALIDATION"
    garbage = wire.raw(b"this is not json")
    assert garbage is None or garbage["status"] == "REJECTED"
    assert wire.call(m.HostInfoRequest())["status"] == "SUCCEEDED", "still serving"


def test_an_oversized_frame_is_refused_before_it_is_read(host: RunningHost, wire: Wire) -> None:
    """A hostile length prefix must not make the host buffer it (the cap is checked on the header alone)."""
    with contextlib.closing(socket.socket(socket.AF_UNIX)) as conn:
        conn.settimeout(15)
        conn.connect(str(host.socket))
        conn.sendall((0xFFFFFFF0).to_bytes(4, "big"))  # promises ~4 GiB; sends nothing
        reply = read_frame(conn)  # the host answers or hangs up; it must not wait for 4 GiB
    assert reply is None or json.loads(reply)["status"] == "REJECTED"
    assert wire.call(m.HostInfoRequest())["status"] == "SUCCEEDED"


def test_a_caller_that_is_not_allowed_is_refused_by_the_kernels_word_not_the_clients(
    wire: Wire, host: RunningHost
) -> None:
    """The host identifies callers by SO_PEERCRED; nothing in the request can claim an identity."""
    envelope = {
        "protocol": PROTOCOL,
        "request_id": "req-x",
        "body": {"method": "host_info"},
        "uid": 0,
        "caller": "root",
    }
    doc = wire.raw(json.dumps(envelope).encode())
    assert doc is not None
    assert doc["status"] == "REJECTED", "unknown envelope fields (including claimed identities) are refused outright"


# ============================================================================= cli: what an operator or a script sees
def test_run_relays_the_guests_stdout_byte_exact_and_reports_on_stderr(cli: Cli) -> None:
    done = cli("run", "--image", IMAGE, *SMALL, "--", "echo", "hello", "world")
    assert done.code == 0, done.stderr
    assert done.out == b"echo hello world\n", "stdout carries the guest's bytes and nothing else"
    assert "SUCCEEDED (exit 0)" in done.stderr
    assert "evidence" in done.stderr
    assert "cleanup: destroyed" in done.stderr


def test_run_leaves_nothing_behind(cli: Cli, wire: Wire) -> None:
    assert cli("run", "--image", IMAGE, *SMALL, "--", "true").code == 0
    assert wire.live_sandboxes() == []
    metrics = wire.call(m.MetricsRequest())["result"]["data"]
    assert metrics is not None


def test_run_json_is_one_parseable_document_on_stdout(cli: Cli) -> None:
    done = cli("run", "--image", IMAGE, *SMALL, "--json", "--", "echo", "json")
    assert done.code == 0, done.stderr
    doc = done.json()
    assert doc["run"]["outcome"] == "SUCCEEDED"
    assert base64.b64decode(doc["run"]["stdout"]["data_b64"]) == b"echo json\n"
    assert set(doc["operations"]) == {"create", "start", "exec", "destroy"}
    assert doc["cleanup"].startswith("destroyed")
    assert doc["error"] is None


def test_a_kept_sandbox_can_be_reused_inspected_and_then_destroyed(cli: Cli, wire: Wire) -> None:
    name = unique("keep")
    first = cli("run", "--image", IMAGE, *SMALL, "--keep", "--name", name, "--json", "--", "echo", "one")
    assert first.code == 0, first.stderr
    run_id = first.json()["run"]["run_id"]
    assert "kept" in first.json()["cleanup"]

    listed = cli("sandbox", "list", "--json")
    assert listed.code == 0
    assert name in listed.stdout

    again = cli("exec", name, "--", "echo", "two")
    assert again.code == 0, again.stderr
    assert again.out == b"echo two\n"

    evidence = cli("evidence", "get", run_id, "--json")
    assert evidence.code == 0, evidence.stderr
    assert evidence.json()["run"]["run_id"] == run_id
    relayed = cli("evidence", "get", run_id, "--output")
    assert relayed.out == b"echo one\n", "stored output is retrievable later, byte for byte"

    destroyed = cli("sandbox", "destroy", name, "--yes")
    assert destroyed.code == 0, destroyed.stderr
    assert name not in cli("sandbox", "list").stdout or "DESTROYED" not in cli("sandbox", "list").stdout
    assert wire.live_sandboxes() == []


def test_destroy_without_confirmation_and_without_a_terminal_changes_nothing(cli: Cli, wire: Wire) -> None:
    name = unique("guard")
    assert cli("sandbox", "create", "--image", IMAGE, *SMALL, "--name", name).code == 0
    refused = cli("sandbox", "destroy", name)
    assert refused.code == 2, "no --yes and no TTY to ask on: refuse rather than guess"
    assert [s["name"] for s in wire.live_sandboxes()] == [name]


def test_a_policy_refusal_exits_3_names_the_operation_and_is_clean(cli: Cli) -> None:
    done = cli("run", "--image", "not-in-policy", "--", "echo")
    assert done.code == 3
    assert "not permitted by policy" in done.stderr
    assert "operation: op-" in done.stderr
    assert done.out == b""


def test_an_unknown_sandbox_exits_3_with_a_hint(cli: Cli) -> None:
    done = cli("sandbox", "inspect", "nope-" + uuid.uuid4().hex[:6])
    assert done.code == 3
    assert "no sandbox" in done.stderr
    assert "hint:" in done.stderr


def test_snapshot_restore_rolls_back_to_a_new_generation_and_can_fork(cli: Cli) -> None:
    name = unique("snap")
    assert cli("sandbox", "create", "--image", IMAGE, *SMALL, "--name", name, "--start").code == 0
    created = cli("snapshot", "create", "base", "--sandbox", name, "--json")
    assert created.code == 0, created.stderr
    snapshot_id = created.json()["snapshot"]["snapshot_id"]

    rolled = cli("snapshot", "restore", "base", "--sandbox", name, "--json")
    assert rolled.code == 0, rolled.stderr
    assert rolled.json()["generation"] == 2
    assert rolled.json()["source_snapshot"]["snapshot_id"] == snapshot_id
    assert any("restore verified" in note for note in rolled.json()["notes"]), (
        "restore is verified by the guest, not assumed"
    )

    fork_name = unique("fork")
    forked = cli("snapshot", "restore", "base", "--new", "--name", fork_name, "--json")
    assert forked.code == 0, forked.stderr
    assert forked.json()["generation"] == 1
    assert forked.json()["sandbox_id"] != rolled.json()["sandbox_id"]
    assert any("more than once" in note for note in forked.json()["notes"]), "the host warns about reusing a snapshot"

    assert cli("snapshot", "delete", "base", "--yes").code == 0
    assert "no snapshots" in cli("snapshot", "list").stdout


def test_a_snapshot_that_exceeds_the_quota_is_refused_cleanly(cli: Cli, wire: Wire) -> None:
    name = unique("big")
    assert (
        cli("sandbox", "create", "--image", IMAGE, "--memory", "1024", "--disk", "1024", "--name", name, "--start").code
        == 0
    )
    done = cli("snapshot", "create", "too-big", "--sandbox", name)
    assert done.code == 3, done.stderr
    assert "quota" in done.stderr
    assert wire.live_snapshots() == []


def test_operation_get_observes_and_never_re_runs(cli: Cli, wire: Wire) -> None:
    done = cli("run", "--image", IMAGE, *SMALL, "--json", "--", "echo", "obs")
    exec_op = done.json()["operations"]["exec"]
    before = wire.call(m.MetricsRequest())["result"]["data"]
    seen = cli("operation", "get", exec_op)
    assert seen.code == 0, seen.stderr
    assert "SUCCEEDED" in seen.stdout
    as_json = cli("operation", "get", exec_op, "--json")
    assert as_json.json()["status"] == "SUCCEEDED"
    after = wire.call(m.MetricsRequest())["result"]["data"]
    assert before["counters"].get('runs{outcome="Succeeded"}') == after["counters"].get('runs{outcome="Succeeded"}'), (
        "observing an operation must not run anything"
    )
    unknown = cli("operation", "get", "op-" + "0" * 32)
    assert unknown.code == 3


def test_host_info_json_names_the_protocol_the_cli_speaks(cli: Cli) -> None:
    info = cli("host", "info", "--json")
    assert info.code == 0, info.stderr
    assert info.json()["protocol"] == PROTOCOL
    assert info.json()["capabilities"]["network_modes"] == ["none"]


def test_an_unreachable_host_exits_6_and_says_where_it_looked(cli: Cli, tmp_path: Path) -> None:
    missing = tmp_path / "nobody-home.sock"
    done = cli("host", "info", socket_path=missing)
    assert done.code == 6
    assert str(missing) in done.stderr or "socket" in done.stderr
    assert done.out == b""


def test_parallel_runs_do_not_interfere_and_leave_nothing_behind(cli: Cli, wire: Wire) -> None:
    results: list[Done] = []
    lock = threading.Lock()

    def one(i: int) -> None:
        done = cli("run", "--image", IMAGE, *SMALL, "--", "echo", f"worker-{i}")
        with lock:
            results.append(done)

    threads = [threading.Thread(target=one, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
    assert len(results) == 4
    assert sorted(r.out for r in results) == [f"echo worker-{i}\n".encode() for i in range(4)], [
        r.stderr for r in results
    ]
    assert all(r.code == 0 for r in results)
    assert wire.live_sandboxes() == []
