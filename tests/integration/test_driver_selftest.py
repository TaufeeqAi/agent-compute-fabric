"""The driver of the integration and isolation suites, proven against the real client and the test host.

The suites whose subject is a real guest cannot run without KVM, so nothing else would ever exercise the code that
builds their command lines, speaks the wire protocol for them, finds a process under ``/proc`` or decides whether a
machine is ready: a typo would surface on the first run on real hardware, as a confusing failure of a test that is
not at fault. This file closes that gap. It checks the *driver*, never isolation: the test host's guest "runs" a
command by echoing its argument vector, and nothing here pretends otherwise.

Needs ``acf-host-fake`` (``$ACF_HOST_FAKE``, ``make fake-host``) and the client (``$ACF_LOCAL``); run it with
``make driver-selftest``. When it is enabled and the binary is missing, the run FAILS: it does not skip.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Final

import pytest

from acf_driver import (
    BINARY_ENV,
    CLIENT_ENV,
    EXIT_OK,
    PROTOCOL,
    REPO,
    SHIPPED_CONFIG,
    SHIPPED_PROFILE,
    STATE_ENV,
    AcfLocal,
    Answer,
    Completed,
    DriverError,
    FakeHost,
    HostStartError,
    RawConnection,
    Settings,
    Spawned,
    Target,
    api_description,
    client_command,
    envelope,
    fake_host,
    find_binary,
    frame,
    netlab,
    new_fake_host,
    probe_as_uid,
    read_settings,
    state_base,
    untrusted_ancestor,
    wait_for,
    with_json,
)
from acf_driver.hosts import free_port
from acf_integration import (
    CONTROL_PLANE_SWITCH,
    INTEGRATION_SWITCH,
    SELFTEST_SWITCH,
    HostEnv,
    Mode,
    ModeError,
    edited_copy,
    host_problems,
    machine_problems,
    selected_mode,
)
from acf_proc import (
    children_of,
    confinement,
    executable,
    file_contains,
    memory_contains,
    parse_maps,
    proc_status,
    process_alive,
    start_time_ticks,
)

pytestmark = pytest.mark.driver_selftest

#: Small enough that several sandboxes and their snapshots fit the envelope of the test host's built-in configuration.
SMALL: Final[dict[str, Any]] = {"memory_mib": 128, "disk_mib": 64}
NOBODY = "sbx-" + "0" * 32


@pytest.fixture(scope="module")
def host() -> Iterator[FakeHost]:
    """One test host for this file: the built-in configuration, a network endpoint, four generated identities."""
    try:
        with fake_host(shipped=False, tls=True) as running:
            yield running
    except HostStartError as e:
        pytest.fail(str(e), pytrace=False)


@pytest.fixture
def acf(host: FakeHost) -> Iterator[AcfLocal]:
    driver = AcfLocal.for_target(Target(socket=host.socket))
    yield driver
    assert driver.purge() == [], "the test left something on the host"


# ================================================================================================ the client
def test_the_client_command_is_split_the_way_a_shell_would_split_it() -> None:
    assert client_command({CLIENT_ENV: "uv --directory 'apps/the cli' run --locked acf-local"}) == (
        "uv",
        "--directory",
        "apps/the cli",
        "run",
        "--locked",
        "acf-local",
    )
    assert client_command({}) == ("acf-local",), "without the variable the client is looked up on PATH"
    with pytest.raises(DriverError, match="is empty"):
        client_command({CLIENT_ENV: "   "})


def test_json_is_asked_for_before_the_guests_own_command_line() -> None:
    assert with_json(["sandbox", "list"]) == ["sandbox", "list", "--json"]
    assert with_json(["sandbox", "exec", "box", "--", "ls", "--json"]) == [
        "sandbox",
        "exec",
        "box",
        "--json",
        "--",
        "ls",
        "--json",
    ], "after the separator everything belongs to the guest"
    assert with_json(["sandbox", "exec", "box", "--json", "--", "true"]) == [
        "sandbox",
        "exec",
        "box",
        "--json",
        "--",
        "true",
    ]


def test_a_target_becomes_the_global_options_of_the_client(host: FakeHost) -> None:
    local = Target(socket=host.socket, scope="team-a", on_behalf_of="job:7")
    assert local.options() == ["--socket", str(host.socket), "--scope", "team-a", "--on-behalf-of", "job:7"]
    caller = host.identity("caller")
    assert Target(tls=caller).options() == [
        "--tls",
        f"127.0.0.1:{host.tls_port}",
        "--cert",
        str(host.tls_dir / "caller.crt"),
        "--key",
        str(host.tls_dir / "caller.key"),
        "--ca",
        str(host.tls_dir / "ca.crt"),
    ]
    with pytest.raises(DriverError, match="either the local socket or one identity"):
        Target()
    with pytest.raises(DriverError, match="either the local socket or one identity"):
        Target(socket=host.socket, tls=caller)
    with pytest.raises(DriverError, match="generates"):
        host.identity("root")


def test_a_lifecycle_through_the_client_is_read_through_the_views(acf: AcfLocal) -> None:
    box = acf.boot("walk", memory="128", disk="64")
    assert (box.state, box.generation) == ("READY", 1)
    assert box.name is not None
    assert box.name.startswith("it-")
    assert len(box.name) <= 63
    assert box.jail_id == f"{box.sandbox_id}-g1"
    assert box.vmm_identity is not None, "a started sandbox records its runtime process"
    assert box.owner == ("local-operator", "default")
    assert box.network == {"mode": "none"}

    done = acf.execute(box.name, ["echo", "a b", "$(id)"], options=["--time-limit", "30s", "--max-pids", "64"])
    assert done.returncode == EXIT_OK, done.completed.describe()
    run = done.run
    assert run.succeeded()
    assert (run.status, run.exit_code, run.signal) == ("EXITED", 0, None)
    assert run.stdout_text == "echo a b $(id)\n", "the test host's guest echoes the argument vector it was given"
    assert (run.stdout.status, run.stdout.kept_bytes, run.stdout.is_inline) == ("COMPLETE", 15, True)
    assert run.evidence("runtime_ms")["configured"] == 30_000, "--time-limit reached the host as the run time limit"
    assert run.evidence("guest_pids")["configured"] == 64
    with pytest.raises(DriverError, match="no resource evidence for 'nonsense'"):
        run.evidence("nonsense")
    assert done.operation.run_id == run.run_id
    assert done.operation.sandbox == (box.sandbox_id, 1)

    assert acf.inspect(box.name).state == "COMPLETED"
    assert acf.run_output(run.run_id) == b"echo a b $(id)\n", "`run output` writes the stored bytes and nothing else"
    assert acf.python(box.name, "print(1)").stdout_text == "python -c print(1)\n"
    assert acf.sh(box.name, "ls | wc -l").stdout_text == "/bin/sh -c ls | wc -l\n", (
        "--shell wraps the string in /bin/sh -c"
    )


def test_a_refusal_is_data_and_a_required_effect_raises_with_the_clients_own_words(acf: AcfLocal) -> None:
    refusal = acf.refused("sandbox", "inspect", NOBODY)
    assert (refusal.failure_class, refusal.retry) == ("NOT_FOUND", "NEVER")
    assert refusal.message
    with pytest.raises(DriverError, match=r"(?s)expected exit 0.*NOT_FOUND"):
        acf.ok("sandbox", "inspect", NOBODY)
    with pytest.raises(DriverError, match="expected exit 3"):
        acf.refused("host", "info")


def test_what_the_machine_exports_for_the_client_does_not_reach_it(
    acf: AcfLocal, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ACF_SCOPE", "someone-elses-scope")
    monkeypatch.setenv("ACF_TLS", "127.0.0.1:1")
    monkeypatch.setenv("ACF_TIMEOUT", "1ms")
    created = acf.ok("sandbox", "create", "--image", "python", "--memory", "128", "--disk", "64").succeeded()
    assert created.owner == ("local-operator", "default"), "the driver names the endpoint and the scope itself"


def test_a_finished_invocation_says_what_its_stdout_is_and_is_not() -> None:
    def said(stdout: str, code: int = 0) -> Completed:
        return Completed(("acf-local", "x"), code, stdout.encode(), b"the client's stderr")

    refused = said(
        json.dumps(
            {
                "protocol": PROTOCOL,
                "answer": "REFUSED",
                "refusal": {"class": "NOT_FOUND", "retry": "NEVER", "message": "no"},
            }
        ),
        3,
    )
    assert refused.refusal().failure_class == "NOT_FOUND"
    assert refused.answer().as_of is None
    with pytest.raises(DriverError, match="expected an accepted operation"):
        refused.operation()
    with pytest.raises(DriverError, match="does not say which committed state"):
        _ = refused.answer().sequence
    with pytest.raises(DriverError, match=r"(?s)not one JSON document.*two\nlines.*stderr:"):
        said("two\nlines").document()
    client_side = said(
        json.dumps(
            {"error": {"kind": "InvalidArgument", "message": "m", "hint": None, "operation_id": None, "exit_code": 2}}
        ),
        2,
    )
    assert client_side.client_error()["kind"] == "InvalidArgument"
    with pytest.raises(DriverError, match="not a host answer"):
        client_side.answer()
    with pytest.raises(DriverError, match="not a client-side error document"):
        refused.client_error()
    assert said("{}", 4).require_exit(4, 5).returncode == 4
    with pytest.raises(DriverError, match="expected exit 0 or 8"):
        said("{}", 4).require_exit(0, 8)


def test_an_interrupt_reaches_the_command_but_not_the_test_runner() -> None:
    """``interrupt()`` is Ctrl-C for the invocation's own process group: it must never signal the suite itself."""
    process = subprocess.Popen(["sleep", "60"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    running = Spawned(("sleep", "60"), process)
    assert running.poll() is None
    running.interrupt()
    done = running.wait(30)
    assert done.returncode == -signal.SIGINT, done.describe()
    assert running.wait(30) is done, "a finished invocation is the same object every time"
    running.kill()  # harmless once it has finished


def test_a_spawned_client_is_a_real_invocation(acf: AcfLocal) -> None:
    running = acf.spawn("host", "info", "--json")
    try:
        done = running.wait(300)
    finally:
        running.kill()
    assert done.returncode == EXIT_OK, done.describe()
    assert done.answer().host_info().backend_name == "fake"


# ================================================================================================ the wire
def test_the_api_description_is_the_published_one() -> None:
    api = api_description()
    assert api.protocol == PROTOCOL
    assert len(api.methods) == len({m.name for m in api.methods}) > 0
    assert api.creates_operation("sandbox.create")
    assert api.creates_operation("host.set_mode")
    assert not api.creates_operation("sandbox.list")
    assert api.creates_operation("no.such.method"), "an unknown method is sent the way a mutation would be"
    assert api.method("host.info").roles == ("observer", "caller", "operator")
    assert api.method("quarantine.release").method_class == "operator"
    assert api.retry_advice("HOST_NOT_SERVING") == "SAME_REQUEST_LATER"
    assert {"PROVISIONING", "READY", "DESTROYED"} <= set(api.lifecycle_states)
    with pytest.raises(KeyError):
        api.method("sandbox.teleport")


def test_an_envelope_is_what_a_well_behaved_caller_sends_unless_told_otherwise() -> None:
    mutation = envelope("sandbox.destroy", {"sandbox_id": NOBODY, "expected_generation": 1})
    assert set(mutation) == {"protocol", "owner_scope", "method", "request_id", "operation_id", "issued_at", "params"}
    assert (mutation["protocol"], mutation["owner_scope"]) == (PROTOCOL, "default")
    assert re.fullmatch(r"[A-Za-z0-9-]{8,64}", mutation["operation_id"])
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", mutation["issued_at"])
    assert set(envelope("host.info")) == {"protocol", "owner_scope", "method", "request_id"}, "a read needs no identity"
    bare = envelope(
        "sandbox.destroy", operation_id=None, issued_at=None, request_id=None, protocol="acf.host/1", scope="s"
    )
    assert bare == {"protocol": "acf.host/1", "owner_scope": "s", "method": "sandbox.destroy"}
    odd = envelope("host.info", retry=True, wait_ms=5, on_behalf_of="job:1", extra={"authority": {"x": 1}})
    assert (odd["retry"], odd["wait_ms"], odd["on_behalf_of"], odd["authority"]) == (True, 5, "job:1", {"x": 1})
    assert frame(b"abc") == b"\x00\x00\x00\x03abc"


def test_a_raw_request_is_answered_and_a_refusal_is_data(host: FakeHost) -> None:
    with host.connect() as conn:
        info = conn.request("host.info")
        assert (info.answer, info.protocol) == ("RESULT", PROTOCOL)
        assert info.host_info().backend_name == "fake"
        assert info.as_of is not None
        assert info.sequence >= 1
        refused = conn.request("sandbox.teleport", {}, request_id="req-selftest")
        assert refused.refused().failure_class == "INVALID_REQUEST", "the connection survives a refusal"
        assert refused.request_id == "req-selftest"
        with pytest.raises(DriverError, match="expected an accepted operation"):
            refused.accepted()
        with pytest.raises(DriverError, match="expected a refusal"):
            info.refused()
        with pytest.raises(DriverError, match="expected a `sandbox` result"):
            info.sandbox()


def test_raw_bytes_frame_boundaries_and_the_end_of_a_connection(host: FakeHost) -> None:
    with host.connect() as conn:
        conn.send(
            frame(json.dumps(envelope("host.info")).encode()) + frame(json.dumps(envelope("host.metrics")).encode())
        )
        first, second = conn.read(timeout=30), conn.read(timeout=30)
        assert first is not None
        assert second is not None
        assert (first.host_info().mode, "gauges" in second.metrics()) == ("SERVING", True), (
            "two frames, two answers, in order"
        )
        with pytest.raises(TimeoutError):
            conn.read(timeout=0.3)  # silence is not the end of the connection
        assert not conn.peer_closed(within=0.3)
    with host.connect() as conn:
        conn.send(b"\x00\x00\x00\x40half a frame")
        conn.finish_sending()
        said = conn.read(timeout=30)
        assert said is not None
        assert said.refused().failure_class == "INVALID_REQUEST", "the host says what was wrong with the frame"
        assert conn.peer_closed(within=30), "and then it closes: nothing can follow a broken frame"
        assert conn.read(timeout=5) is None, "the end of a connection on a frame boundary is not an answer"


def test_an_endpoint_that_does_not_exist_is_the_kernels_own_error(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        RawConnection.unix(tmp_path / "missing.sock")


def test_the_network_endpoint_is_reached_as_each_generated_identity(host: FakeHost) -> None:
    with host.identity("operator").connect() as conn:
        assert conn.request("host.info").host_info().host_id
    with host.identity("stranger").connect() as conn:
        said = conn.read(timeout=30)
        assert said is not None
        assert said.refused().failure_class == "AUTHENTICATION_FAILED", (
            "chain-valid but not enrolled: told why, unasked"
        )
        assert conn.peer_closed(within=30)


def test_the_arranging_hand_requires_every_step_and_tidies_up_everything(acf: AcfLocal, host: FakeHost) -> None:
    wire = acf.wire
    before = wire.sequence()
    box = wire.ready("arranged", **SMALL)
    assert (box.state, box.name, box.generation) == ("READY", "arranged", 1)
    assert wire.sequence() > before, "the commit sequence moves when something is recorded"
    assert wire.run(box, ["true"]).run_result().succeeded()
    assert wire.refresh(box).state == "COMPLETED"
    with pytest.raises(DriverError, match="STATE_CONFLICT"):
        wire.start(box)

    snapshot = wire.snapshot(box, "base")
    assert (snapshot.state, snapshot.name, snapshot.source_sandbox) == ("READY", "base", (box.sandbox_id, 1))
    again = wire.restore_into(snapshot, wire.refresh(box))
    assert (again.sandbox_id, again.generation, again.source_snapshot) == (box.sandbox_id, 2, snapshot.ref)
    copy = wire.restore_new(snapshot, "copy")
    assert (copy.generation, copy.name) == (1, "copy")
    wire.stop(copy)
    wire.create("third", **SMALL)

    one_at_a_time = wire.in_scope("default")
    one_at_a_time.page_size = 1
    assert {s.name for s in one_at_a_time.sandboxes()} == {"arranged", "copy", "third"}, (
        "a listing is followed to its end"
    )
    assert [s.name for s in wire.snapshots()] == ["base"]
    assert [o.operation_type for o in one_at_a_time.operations()].count("snapshot.restore") == 2

    # A generation whose ownership marker proves nothing is quarantined by the destroy that finds it out.
    marker = host.generation_dir(copy.sandbox_id, 1) / "OWNER.json"
    assert marker.is_file(), f"the test host keeps its generations where the layout says: {marker}"
    marker.write_text("{}")
    failed = wire.call("sandbox.destroy", {"sandbox_id": copy.sandbox_id, "expected_generation": 1}).accepted()
    assert (failed.state, failed.cleanup, failed.failure_class) == ("FAILED", "QUARANTINED", "QUARANTINED")
    assert wire.refresh(copy).quarantined is not None

    assert wire.purge() == [], "a quarantined generation is released, the rest destroyed, the snapshot deleted"
    assert wire.sandboxes() == []
    assert wire.snapshots() == []
    assert wire.info().quarantined == 0


def test_the_probe_that_can_run_as_another_user_reports_what_the_host_said(host: FakeHost) -> None:
    """Becoming another user needs root; as oneself, the probe and its report are the same code."""
    probe = probe_as_uid(host.socket, os.geteuid(), envelope("host.info"), patience=2.0)
    assert (probe.uid, probe.connect, probe.connected) == (os.geteuid(), "ok", True)
    assert [frame_.answer for frame_ in probe.frames] == ["RESULT"]
    assert not probe.closed, "the host keeps an enrolled peer's connection open; the probe stopped waiting"
    missing = probe_as_uid(host.base / "missing.sock", os.geteuid(), patience=1.0)
    assert (missing.connect, missing.connected, missing.frames) == ("FileNotFoundError", False, [])


# ================================================================================================ the test host
def test_a_directory_another_user_could_write_is_not_one_for_trusted_files() -> None:
    why = untrusted_ancestor(Path("/tmp") / "acf-selftest", os.geteuid())  # nothing is created there
    assert why is not None
    assert "/tmp" in why, why
    assert untrusted_ancestor(state_base(), os.geteuid()) is None, (
        "the directory the driver chose is one the host accepts"
    )


def test_a_state_directory_the_host_would_refuse_is_reported_with_the_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    refused = Path("/tmp") / f"acf-selftest-{os.getpid()}"
    monkeypatch.setenv(STATE_ENV, str(refused))
    with pytest.raises(HostStartError, match=rf"(?s){refused}.*writable by group or other.*{STATE_ENV}"):
        state_base()
    assert not refused.exists(), "a location the host would refuse is left exactly as it was"


def test_a_missing_binary_is_an_error_that_says_how_to_build_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv(BINARY_ENV, raising=False)
    with pytest.raises(HostStartError, match="make fake-host"):
        find_binary()
    monkeypatch.setenv(BINARY_ENV, str(tmp_path / "acf-host-fake"))
    with pytest.raises(HostStartError, match="not an executable file"):
        find_binary()


def test_the_test_host_restarts_over_its_store_and_its_roles_are_separate_processes() -> None:
    try:
        own = new_fake_host(shipped=False)
        own.start()
    except HostStartError as e:
        pytest.fail(str(e), pytrace=False)
    try:
        wire = AcfLocal.for_target(Target(socket=own.socket)).wire
        first = wire.info()
        created = wire.create("kept", **SMALL)
        assert own.generation_dir(created.sandbox_id, 1).is_dir()
        assert own.profile_path.is_file()
        assert own.enrolment_path.is_file()
        assert own.journal.is_file()

        if (
            os.geteuid() != 0
        ):  # as root the test host runs its edge inside the core: there is no second identity to give it
            edges = [pid for pid in children_of(own.pid) if executable(pid) == executable(own.pid)]
            assert len(edges) == 1, f"the edge is a child of the core running the same image: {children_of(own.pid)}"
            status = proc_status(edges[0])
            assert (status["NoNewPrivs"], int(status["CapEff"], 16)) == ("1", 0), "the edge can gain no privilege"
        started = start_time_ticks(own.pid)
        assert started is not None
        assert process_alive(own.pid, started)
        assert not process_alive(own.pid, started + 1), "the same pid with another start time is another process"

        old_pid = own.pid
        assert own.stop() == 0, f"a stop is clean:\n{own.log_text()}"
        assert not own.running
        assert not process_alive(old_pid, started)
        with pytest.raises((FileNotFoundError, ConnectionRefusedError)):
            own.connect()
        own.start()
        second = wire.info()
        assert (second.lineage, second.activation_epoch) == (first.lineage, first.activation_epoch + 1)
        assert [s.name for s in wire.sandboxes()] == ["kept"], "what was committed is still there"

        own.restart(hard=True)
        assert wire.info().activation_epoch == first.activation_epoch + 2, (
            "a killed host starts again over the same store"
        )
        assert own.pid != old_pid
        assert "serving on" in own.log_text()
    finally:
        own.destroy()
    assert not own.base.exists(), "nothing of a test host is left behind"


# ================================================================================================ the shipped files
def test_the_settings_reader_reads_the_subset_the_shipped_files_use() -> None:
    values = read_settings(
        "# a comment\n"
        "schema_version: 2\n"
        "host_id: host-1   # trailing comment\n"
        "paths:\n"
        "  state_root: /var/lib/acf\n"
        "edge:\n"
        '  socket_mode: "0660"\n'
        "  # uid: 990\n"
        "operations:\n"
        "  deadlines:                # a mapping with a comment\n"
        "    stop_ms: 60000\n"
        "  wait_max_ms: 30000\n"
        "capabilities:\n"
        "  network_modes: [none, allowlist]\n"
        "  secret_injection: false\n"
        "  empty: []\n"
        'version: "2.0.0"\n'
    )
    assert values == {
        "schema_version": 2,
        "host_id": "host-1",
        "paths.state_root": "/var/lib/acf",
        "edge.socket_mode": "0660",
        "operations.deadlines.stop_ms": 60000,
        "operations.wait_max_ms": 30000,
        "capabilities.network_modes": ["none", "allowlist"],
        "capabilities.secret_injection": False,
        "capabilities.empty": [],
        "version": "2.0.0",
    }


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("peers:\n  - peer_id: a\n", id="a-block-sequence"),
        pytest.param("match: { local_uid: 0 }\n", id="a-flow-mapping"),
        pytest.param("a:\n\tb: 1\n", id="a-tab"),
        pytest.param("a: 1\na: 2\n", id="a-key-set-twice"),
        pytest.param("a: [1, 2\n", id="an-open-list"),
        pytest.param("just words\n", id="not-a-mapping"),
        pytest.param("a: &anchor 1\n", id="an-anchor"),
    ],
)
def test_the_settings_reader_refuses_what_it_does_not_know(text: str) -> None:
    with pytest.raises(ValueError, match="line "):
        read_settings(text)


def test_every_bound_the_suites_read_is_in_the_shipped_files(tmp_path: Path) -> None:
    config, profile = Settings.load(SHIPPED_CONFIG), Settings.load(SHIPPED_PROFILE)
    integers = [
        "envelope.vcpus",
        "envelope.memory_mib",
        "envelope.disk_mib",
        "envelope.max_sandboxes",
        "envelope.max_snapshots",
        "firecracker.vmm_overhead_mib",
        "firecracker.uid_range_start",
        "firecracker.uid_range_size",
        "network.traffic_uid_start",
        "edge.max_request_bytes",
        "edge.enrolment_refresh_ms",
        "operations.acceptance_horizon_ms",
        "operations.clock_skew_tolerance_ms",
        "operations.rate_limit_per_minute",
        "operations.backstop_margin_ms",
        "operations.deadlines.stop_ms",
        "operations.deadlines.destroy_ms",
        "recovery.sweep_interval_ms",
        "recovery.runtime_loss_detection_ms",
        "recovery.posture_recheck_interval_ms",
        "lifetime.expiry_tolerance_ms",
    ]
    for key in integers:
        assert config.integer(key) > 0, key
    for key in (
        "paths.state_root",
        "paths.runtime_dir",
        "paths.socket_path",
        "paths.profile_path",
        "firecracker.pinned_version",
    ):
        assert config.text(key), key
    for key in (
        "firecracker.firecracker_bin",
        "firecracker.jailer_bin",
        "firecracker.cgroup_root",
        "firecracker.cgroup_parent",
    ):
        assert config.text(key), key
    for key in ("network.guest_segment", "network.ip_bin", "network.nft_bin", "network.nsenter_bin"):
        assert config.text(key), key
    limits = [
        "max_vcpus",
        "max_memory_mib",
        "max_disk_mib",
        "max_runtime_ms",
        "max_pids",
        "max_stdout_bytes",
        "max_stderr_bytes",
    ]
    for key in [*limits, "max_lifetime_secs", "max_allowlist_entries"]:
        assert profile.integer(f"limits.{key}") > 0, key
    for key in ("runtime_ms", "pids", "stdout_bytes", "stderr_bytes", "lifetime_secs"):
        assert profile.integer(f"defaults.{key}") > 0, key
    assert profile.words("capabilities.network_modes")
    assert profile.words("capabilities.images")
    assert profile.words("execution.env_allowlist")
    assert profile.words("execution.cwd_prefixes")
    assert isinstance(profile.flag("capabilities.secret_injection"), bool)
    assert isinstance(profile.flag("capabilities.private_destinations"), bool)
    assert profile.integer("execution.guest_uid") > 0
    assert len(profile.sha256()) == 64

    with pytest.raises(KeyError, match=r"does not set `envelope\.gpus`"):
        config.integer("envelope.gpus")
    with pytest.raises(TypeError, match="not an integer"):
        config.integer("host_id")
    partial = tmp_path / "host.yaml"
    partial.write_text("envelope:\n  vcpus: 2\n")
    installed = Settings.load(partial, defaults=config)
    assert installed.integer("envelope.vcpus") == 2, "the installed file answers first"
    assert installed.integer("envelope.memory_mib") == config.integer("envelope.memory_mib"), (
        "the shipped example answers for the rest"
    )

    edited = edited_copy(SHIPPED_PROFILE, tmp_path / "profile.yaml", {"max_pids: 1024": "max_pids: 512"})
    assert Settings.load(edited).integer("limits.max_pids") == 512
    with pytest.raises(DriverError, match="must be unambiguous"):
        edited_copy(SHIPPED_PROFILE, tmp_path / "other.yaml", {"max_": "min_"})


# ================================================================================================ modes and readiness
def test_the_mode_follows_the_switches_and_two_switches_are_an_error() -> None:
    assert selected_mode({}) is Mode.NONE
    assert selected_mode({INTEGRATION_SWITCH: "1"}) is Mode.INTEGRATION
    assert selected_mode({CONTROL_PLANE_SWITCH: "1"}) is Mode.CONTROL_PLANE
    assert selected_mode({CONTROL_PLANE_SWITCH: "0", INTEGRATION_SWITCH: "yes"}) is Mode.NONE, (
        "only `1` switches a mode on"
    )
    with pytest.raises(ModeError, match="mutually exclusive"):
        selected_mode({CONTROL_PLANE_SWITCH: "1", INTEGRATION_SWITCH: "1"})


def test_the_environment_of_a_test_host_is_the_shipped_files_and_its_own_directory(host: FakeHost) -> None:
    try:
        shipped = new_fake_host(shipped=True, tls=True)
    except HostStartError as e:
        pytest.fail(str(e), pytrace=False)
    try:
        env = HostEnv.for_test_host(shipped, {"ACF_TEST_IMAGE": "node"})
        assert (env.mode, env.control_plane, env.image) == (Mode.CONTROL_PLANE, True, "node")
        assert (env.config.path, env.profile.path) == (SHIPPED_CONFIG, SHIPPED_PROFILE)
        assert (env.socket, env.state_root) == (shipped.socket, shipped.state_root)
        assert env.test_host() is shipped
        fits = env.sandboxes_that_fit(vcpus=1, memory_mib=2048, disk_mib=1024)
        memory, overhead = env.config.integer("envelope.memory_mib"), env.vmm_overhead_mib
        assert fits == min(env.config.integer("envelope.vcpus"), memory // (2048 + overhead)), (
            "memory is budgeted with the overhead"
        )
    finally:
        shipped.destroy()
    with pytest.raises(DriverError, match="loads the shipped configuration"):
        HostEnv.for_test_host(host)


def test_what_a_machine_lacks_for_a_production_host_is_listed_one_entry_each(tmp_path: Path) -> None:
    """The list a run with ``ACF_INTEGRATION=1`` ends with on a machine that is not ready (it never skips)."""
    env = HostEnv.for_installed_host(
        {
            "ACF_HOST_CONFIG": str(tmp_path / "host.yaml"),
            "ACF_SOCKET": str(tmp_path / "host-agent.sock"),
            "ACF_HOST_BIN": str(tmp_path / "acf-host"),
            "ACF_TEST_IMAGE": "python",
        }
    )
    assert (env.mode, env.fake) == (Mode.INTEGRATION, None)
    assert env.state_root == Path(Settings.load(SHIPPED_CONFIG).text("paths.state_root")), (
        "until the file is there, the defaults answer"
    )
    # What is listed must not depend on whether this machine has a host of its own at the default state root.
    problems = machine_problems(dataclasses.replace(env, state_root=tmp_path / "state"), euid=1000)
    for needle in (
        "not root",
        f"{tmp_path / 'host.yaml'} does not exist",
        "no host is running",
        "image 'python' is not installed",
    ):
        assert len([p for p in problems if needle in p]) == 1, f"{needle!r} in {problems}"
    assert any(str(tmp_path / "acf-host") in p for p in problems), problems
    assert all("not root" not in p for p in machine_problems(env, euid=0))

    box = Answer(
        {
            "protocol": PROTOCOL,
            "answer": "RESULT",
            "result": {"type": "sandbox", "data": {"sandbox_id": NOBODY, "generation": 3}},
        }
    )
    sandbox = box.sandbox()
    jail = f"{NOBODY}-g3"
    assert env.generation_dir(sandbox) == env.state_root / "sandboxes" / NOBODY / "3"
    assert env.jail_root(sandbox) == env.generation_dir(sandbox) / "jail" / "firecracker" / jail / "root"
    assert env.cgroup_dir(sandbox) == Path("/sys/fs/cgroup/acf") / jail
    assert env.traffic_cgroup_dir(sandbox) == Path("/sys/fs/cgroup/acf") / f"{jail}-net"
    assert env.netns_handle(sandbox) == env.runtime_dir / "netns" / f"acf-{jail}"
    assert env.expiry_ticket(sandbox) == env.runtime_dir / "expiry" / f"{jail}.ticket"


def test_a_host_that_is_not_the_one_the_suites_expect_is_reported(acf: AcfLocal, host: FakeHost) -> None:
    try:
        shipped = new_fake_host(shipped=True)
    except HostStartError as e:
        pytest.fail(str(e), pytrace=False)
    try:
        env = HostEnv.for_test_host(shipped)
    finally:
        shipped.destroy()
    assert host_problems(acf, env) == [], "an idle, serving test host is ready"
    acf.wire.create("someone-elses", **SMALL)
    acf.wire.set_mode("DRAINING")
    problems = host_problems(acf, env)
    assert len(problems) == 2, problems
    assert problems[0] == "the host is DRAINING, not SERVING"
    assert "1 sandbox(es) already exist" in problems[1]
    unreachable = AcfLocal.for_target(Target(socket=host.base / "missing.sock"))
    assert "does not answer `host.info`" in host_problems(unreachable, env)[0]


def _inner_pytest(extra_env: dict[str, str], *selection: str) -> subprocess.CompletedProcess[str]:
    """Run the suites' own collection rules in a fresh interpreter, with exactly the given switches."""
    switches = (INTEGRATION_SWITCH, CONTROL_PLANE_SWITCH, SELFTEST_SWITCH, "ACF_REQUIRE_ROOT", "PYTEST_ADDOPTS")
    environment = {key: value for key, value in os.environ.items() if key not in switches}
    environment.update(extra_env)
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-q", "-rA", *selection],
        capture_output=True,
        text=True,
        env=environment,
        cwd=REPO,
        check=False,
        timeout=900,
    )


def _outcomes(report: subprocess.CompletedProcess[str]) -> dict[str, int]:
    """``{"passed": 1, "skipped": 2}`` from the last line of a pytest run."""
    lines = report.stdout.strip().splitlines()
    return {
        word: int(count)
        for count, word in re.findall(r"(\d+) (passed|failed|skipped|errors?|deselected)", lines[-1] if lines else "")
    }


def test_with_the_integration_switch_a_machine_that_is_not_ready_is_an_error_and_never_a_skip(tmp_path: Path) -> None:
    selection = (
        "tests/integration/vm_lifecycle/test_vm_lifecycle.py",
        "tests/isolation/network/test_guest_network.py",
    )
    not_ready = {
        INTEGRATION_SWITCH: "1",
        "ACF_HOST_CONFIG": str(tmp_path / "host.yaml"),
        "ACF_SOCKET": str(tmp_path / "host-agent.sock"),
        "ACF_HOST_BIN": str(tmp_path / "acf-host"),
    }
    report = _inner_pytest(not_ready, *selection)
    outcomes = _outcomes(report)
    errors = outcomes.get("errors", outcomes.get("error", 0))
    assert errors > 0, report.stdout[-3000:]
    assert {key: n for key, n in outcomes.items() if key not in {"errors", "error"}} == {}, (
        f"every test of the selection must ERROR, none may pass, fail or skip: {outcomes}\n{report.stdout[-3000:]}"
    )
    assert report.returncode != 0
    assert "this machine is not ready for the suites" in report.stdout
    assert f"{tmp_path / 'host.yaml'} does not exist" in report.stdout, "the report lists what is missing"
    assert "no host is running" in report.stdout

    quiet = _inner_pytest({}, *selection)
    outcomes = _outcomes(quiet)
    assert set(outcomes) == {"skipped"}, (
        f"without a switch every test is skipped, with the reason:\n{quiet.stdout[-3000:]}"
    )
    assert outcomes["skipped"] == errors, "the same tests, skipped instead"
    assert "ACF_INTEGRATION=1" in quiet.stdout, "the report says how to run them"


def test_the_host_and_the_helpers_it_started_are_gone_when_the_block_ends() -> None:
    try:
        with fake_host(shipped=False) as short_lived:
            pid, base = short_lived.pid, short_lived.base
            started = start_time_ticks(pid)
            assert started is not None
            assert AcfLocal.for_target(Target(socket=short_lived.socket)).wire.info().mode == "SERVING"
    except HostStartError as e:
        pytest.fail(str(e), pytrace=False)
    wait_for("the test host process to be gone", lambda: True if not process_alive(pid, started) else None, timeout=30)
    assert not base.exists()


# ================================================================================================ helpers of the L4 suites
# The suites that need a production host cannot run where this self-test runs. The parts of their helpers that do
# not need one are proven here: the lab's listeners, the probes a guest runs, and the readers of the kernel's tables.
def _guest_probe(source: str, *arguments: str) -> Any:
    """Run a guest probe on THIS machine, exactly as a guest would (``python -c SOURCE ARGUMENTS``)."""
    done = subprocess.run(
        [sys.executable, "-I", "-c", source, *arguments], capture_output=True, text=True, check=False, timeout=120
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def test_a_lab_listener_answers_with_its_token_and_logs_every_contact(tmp_path: Path) -> None:
    lab = netlab.FarSide(directory=tmp_path)
    try:
        port = free_port()
        listener = lab.tcp_on_host("127.0.0.1", port)
        silent = free_port()
        targets = [
            {"address": "127.0.0.1", "port": port},
            {"address": "127.0.0.1", "port": port, "server_name": "listed.example.org"},
            {"address": "127.0.0.1", "port": silent},
        ]
        plain, with_name, nobody_there = _guest_probe(netlab.GUEST_TCP_PROBE, json.dumps(targets))
        assert (plain["connected"], plain["received"]) == (True, listener.token)
        assert with_name["received"] == listener.token
        assert (nobody_there["connected"], nobody_there["received"]) == (False, "")
        assert nobody_there["error"].startswith("ConnectionRefusedError")

        contacts = [line.split() for line in listener.contacts()]
        assert [(peer, size) for peer, size, _ in contacts[:1]] == [("127.0.0.1", "13")], contacts
        hello = bytes.fromhex(contacts[1][2])
        assert hello[0] == 0x16, "the probe with a server name must open with a TLS handshake record"
        assert int(contacts[1][1]) > 100

        datagram = lab._listen("host", "udp", "127.0.0.1", free_port())
        report = _guest_probe(
            netlab.GUEST_DATAGRAM_PROBE, json.dumps({"udp": [["127.0.0.1", datagram.port], ["127.0.0.1", silent]]})
        )
        assert report["udp"][0] == {"sent": True, "reply": datagram.token, "error": None}
        assert report["udp"][1]["reply"] == ""
        assert len(datagram.contacts()) == 1
    finally:
        for started in lab.listeners:
            started.stop()
    assert all(started.process.poll() is not None for started in lab.listeners)


def test_the_name_probe_reads_the_code_and_the_addresses_of_an_answer() -> None:
    """A resolver of this test answers two questions the way the host's does: one address through a compression
    pointer, and ``REFUSED``."""
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    server.settimeout(30)
    port = server.getsockname()[1]

    def serve() -> None:
        for answer in ("address", "refused"):
            query, peer = server.recvfrom(2048)
            question = query[12:]
            if answer == "address":
                record = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton("198.51.100.10")
                server.sendto(query[:2] + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0) + question + record, peer)
            else:
                server.sendto(query[:2] + struct.pack(">HHHHH", 0x8185, 1, 0, 0, 0) + question, peer)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        questions = json.dumps([["listed.example.org", 1], ["unlisted.example.org", 1]])
        listed, unlisted = _guest_probe(netlab.GUEST_DNS_PROBE, questions, f"127.0.0.1:{port}")
    finally:
        thread.join(timeout=60)
        server.close()
    assert (listed["rcode"], listed["addresses"], listed["answers"]) == (0, ["198.51.100.10"], 1), listed
    assert (unlisted["rcode"], unlisted["addresses"], unlisted["answers"]) == (5, [], 0), unlisted


def test_a_guest_reports_the_network_facts_its_kernel_shows() -> None:
    facts = _guest_probe(netlab.GUEST_NETWORK_FACTS)
    assert "lo" in facts["interfaces"]
    assert set(facts) == {"interfaces", "routes", "ipv6", "resolv_conf"}
    assert all(set(route) == {"device", "destination", "gateway", "mask"} for route in facts["routes"])


def test_published_names_are_a_marked_block_that_is_removed_without_a_trace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hosts = tmp_path / "hosts"
    original = "127.0.0.1 localhost\n# a comment the operator wrote\n10.0.0.5 build-cache"
    hosts.write_text(original, encoding="utf-8")
    monkeypatch.setattr(netlab, "HOSTS_FILE", hosts)
    lab = netlab.FarSide(directory=tmp_path / "lab")

    lab.publish({"listed.example.org": "198.51.100.10"})
    lab.publish({"listed.example.org": "198.51.100.1", "other.example.org": "198.51.100.11"})
    lines = hosts.read_text(encoding="utf-8").splitlines()
    assert lines[:3] == original.splitlines(), "what the file held before must stay where it was"
    assert lines[3:] == [
        netlab.HOSTS_BEGIN,
        "198.51.100.1 listed.example.org",
        "198.51.100.11 other.example.org",
        netlab.HOSTS_END,
    ], "publishing again replaces the block"

    lab._remove_names()
    assert hosts.read_text(encoding="utf-8") == original + "\n"
    lab._remove_names()
    assert hosts.read_text(encoding="utf-8") == original + "\n", "removing twice changes nothing"


def test_the_lab_itself_needs_root_and_says_so() -> None:
    if os.geteuid() == 0:
        pytest.skip("as root the lab would really be built; that is what the network suites do on a production host")
    with pytest.raises(DriverError, match="needs root"), netlab.far_side():
        pytest.fail("the lab opened without root")


def test_bytes_are_found_in_a_file_and_in_the_memory_of_a_process(tmp_path: Path) -> None:
    needle = b"acf-it-needle-" + os.urandom(12).hex().encode()
    image = tmp_path / "disk.img"
    with image.open("wb") as stream:
        stream.write(b"\0" * ((8 << 20) - 5))  # the needle straddles the boundary between two chunks of the reader
        stream.write(needle)
        stream.write(b"\0" * 4096)
    assert file_contains(image, needle)
    assert not file_contains(image, needle + b"!")
    assert not file_contains(tmp_path / "disk.img", b"never written anywhere")

    holder = subprocess.Popen(
        [
            sys.executable,
            "-I",
            "-c",
            "import sys, time; kept = sys.argv[1] * 3; print('ready', flush=True); time.sleep(600)",
            needle.decode(),
        ],
        stdout=subprocess.PIPE,
    )
    try:
        assert holder.stdout is not None
        assert holder.stdout.readline().strip() == b"ready"
        assert memory_contains(holder.pid, needle), "the reader of a process's memory does not find what is there"
        assert not memory_contains(holder.pid, b"acf-it-never-" + os.urandom(12).hex().encode())
    finally:
        holder.kill()
        holder.wait()
    assert parse_maps("7f00-7fff r-xp 0 00:00 0 /x\nnot a mapping\n8000-9000 ---p 0 00:00 0\n") == [
        (0x7F00, 0x7FFF, "r-xp"),
        (0x8000, 0x9000, "---p"),
    ]


def test_an_ordinary_process_is_reported_as_unconfined_with_every_reason() -> None:
    child = subprocess.Popen(["sleep", "600"])
    try:
        facts = confinement(child.pid, compared_with=os.getpid())
        assert facts.uids == (os.getuid(),) * 4
        assert facts.machine_root
        assert set(facts.shared_namespaces) == {"net", "pid", "mnt"}
        reasons = facts.violations(uid_range=(100_000, 4096))
    finally:
        child.kill()
        child.wait()
    for expected in (
        "is not one unprivileged id in [100000, 104096)",
        "system-call filter",
        "PID namespace",
        "root directory",
        "shares these namespaces",
    ):
        assert any(expected in reason for reason in reasons), (expected, reasons)
    assert facts.violations(uid_range=(os.getuid(), 1)) != [], "being in the range alone is not confinement"
