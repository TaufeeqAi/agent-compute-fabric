"""The driver that the KVM-only suites use, proven against the real CLI and the real host server on an in-memory VM.

The integration and isolation tests cannot run without KVM, so nothing else would ever exercise the code that
builds their command lines and parses their answers: a typo in an option name would surface only on the first
real hardware run, as a confusing failure of a test that is not at fault. This file closes that gap. It checks the
*driver*, not isolation: the in-memory guest "runs" a command by echoing its argv and nothing here pretends
otherwise.

Needs ``acf-host-fake`` (``make fake-host``) and ``acf-local`` (``ACF_LOCAL``); run with ``make driver-selftest``.
When it is enabled but the binary is missing the run FAILS, it does not skip.
"""

from __future__ import annotations

import os
import shlex
import signal
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from acf_driver import (
    EXIT_OK,
    EXIT_REFUSED,
    AcfLocal,
    DriverError,
    Run,
    Sandbox,
    Snapshot,
    Spawned,
    new_operation_id,
    raw_call,
)
from acf_integration import fake_host

pytestmark = pytest.mark.driver_selftest


@pytest.fixture(scope="module")
def fake_socket() -> Iterator[Path]:
    with fake_host(shipped=False) as sock:
        yield sock


@pytest.fixture
def acf(fake_socket: Path) -> Iterator[AcfLocal]:
    driver = AcfLocal.from_environment(
        {"ACF_LOCAL": os.environ.get("ACF_LOCAL", "acf-local"), "ACF_SOCKET": str(fake_socket)}
    )
    assert shlex.split(os.environ.get("ACF_LOCAL", "acf-local")), "ACF_LOCAL must name the CLI"
    yield driver
    assert driver.purge() == [], "the test left something on the host"


def test_host_info_names_the_backend_and_the_phase_1_network_vocabulary(acf: AcfLocal) -> None:
    info = acf.host_info()
    assert info["protocol"] == "acf.host/1"
    assert info["backend"]["name"] == "fake"
    assert info["capabilities"]["network_modes"] == ["none"]
    assert info["mode"] == "normal"


def test_run_reports_the_milestone_shape_and_cleans_up(acf: AcfLocal) -> None:
    report = acf.run("echo hello world", cpu=2, memory="512")
    assert report.returncode == EXIT_OK, report.completed.describe()
    run = report.run
    assert (run.outcome, run.exit_code, run.signal) == ("SUCCEEDED", 0, None)
    assert run.succeeded()
    assert run.stdout == "echo hello world\n"
    assert run.stderr == ""
    assert run.stream("stdout")["status"] == "COMPLETE"
    assert run.evidence_status == "COMPLETE"
    assert run.run_id.startswith("run-")
    assert report.doc["sandbox"]["state"] == "DESTROYED"
    assert report.doc["cleanup_failed"] is False
    assert acf.sandbox_list() == []


def test_resource_evidence_is_addressable_by_resource_name(acf: AcfLocal) -> None:
    run = acf.run("true").run
    assert run.evidence("guest_pids")["mechanism"] == "guest cgroup v2 pids.max + cgroup.kill"
    assert run.evidence("runtime_ms")["violation"] is None
    with pytest.raises(DriverError, match="no resource evidence for 'nonsense'"):
        run.evidence("nonsense")


def test_an_argv_after_the_separator_is_passed_verbatim(acf: AcfLocal) -> None:
    run = acf.run(["echo", "a b", "c"]).run
    assert run.stdout == "echo a b c\n"  # the in-memory guest joins argv with spaces


def test_options_reach_the_cli_in_the_right_places(acf: AcfLocal) -> None:
    report = acf.run(
        "echo x", shell=True, timeout="30s", max_pids=64, max_stdout="2KiB", max_stderr="1KiB",
        env={"LANG": "C"}, cwd="/tmp",
    )  # fmt: skip
    assert report.returncode == EXIT_OK, report.completed.describe()
    evidence = report.run
    assert evidence.evidence("runtime_ms")["configured"] == 30_000
    assert evidence.evidence("guest_pids")["configured"] == 64
    assert evidence.evidence("stdout_bytes")["configured"] == 2048
    assert evidence.evidence("stderr_bytes")["configured"] == 1024
    assert evidence.stdout == "/bin/sh -c echo x\n"  # --shell: the host wraps the string in /bin/sh -c


def test_the_explicit_lifecycle_walks_the_documented_states(acf: AcfLocal) -> None:
    name = acf.name("lifecycle")
    created = acf.sandbox_create(name, cpu=2, memory="512")
    assert (created.state, created.generation, created.name) == ("PROVISIONING", 1, name)
    assert acf.sandbox_start(name).state == "READY"
    run = acf.sh(name, "echo inside")
    assert run.succeeded()
    assert run.sandbox_id == created.sandbox_id
    assert acf.sandbox_inspect(name).state == "COMPLETED"
    assert [s.name for s in acf.sandbox_list()] == [name]
    assert acf.sandbox_stop(name).state == "STOPPED"
    assert acf.sandbox_destroy(name).state == "DESTROYED"
    assert acf.sandbox_list() == []


def test_boot_returns_a_ready_named_sandbox(acf: AcfLocal) -> None:
    sandbox = acf.boot("boot", cpu=2, memory="512")
    assert sandbox.state == "READY"
    assert sandbox.name is not None
    assert sandbox.name.startswith("it-")
    assert len(sandbox.name) <= 63


def test_evidence_is_durable_and_readable_by_run_id(acf: AcfLocal) -> None:
    report = acf.run("echo remembered")
    again = acf.evidence_get(report.run.run_id)
    assert isinstance(again, Run)
    assert again.stdout == report.run.stdout
    assert again.outcome == "SUCCEEDED"


def test_snapshots_round_trip_through_restore_and_delete(acf: AcfLocal) -> None:
    sandbox = acf.boot("snap", cpu=2, memory="128", disk="256")  # a snapshot must fit the fake host's 1 GiB quota
    assert sandbox.name is not None
    snapshot = acf.snapshot_create(acf.name("baseline"), sandbox.name)
    assert isinstance(snapshot, Snapshot)
    assert (snapshot.state, snapshot.restore_count) == ("READY", 0)
    assert [s.snapshot_id for s in acf.snapshot_list()] == [snapshot.snapshot_id]

    rolled_back = acf.snapshot_restore(snapshot.snapshot_id, sandbox=sandbox.name)
    assert isinstance(rolled_back, Sandbox)
    assert rolled_back.sandbox_id == sandbox.sandbox_id
    assert rolled_back.generation == sandbox.generation + 1
    assert acf.snapshot_inspect(snapshot.snapshot_id).restore_count == 1

    clone = acf.snapshot_restore_new(snapshot.snapshot_id, acf.name("clone"))
    assert clone.sandbox_id != sandbox.sandbox_id
    assert clone.state == "READY"

    assert acf.snapshot_delete(snapshot.snapshot_id).state == "DELETED"
    assert acf.snapshot_list() == []


def test_a_refusal_is_exit_3_and_changes_nothing(acf: AcfLocal) -> None:
    gone = acf.call("sandbox", "destroy", "sbx-" + "0" * 32, "--yes", "--json")
    assert gone.returncode == EXIT_REFUSED, gone.describe()
    unknown_image = AcfLocal(command=acf.command, socket=acf.socket, image="no-such-image").run("true")
    assert unknown_image.returncode == EXIT_REFUSED, unknown_image.completed.describe()
    assert not unknown_image.has_run
    assert acf.sandbox_list() == []


def test_a_view_method_raises_with_the_clis_own_stderr_when_the_command_fails(acf: AcfLocal) -> None:
    with pytest.raises(DriverError, match="expected exit 0"):
        acf.sandbox_inspect("sbx-" + "0" * 32)


def test_purge_removes_everything_the_host_holds(acf: AcfLocal) -> None:
    keep = acf.run("true", name=acf.name("kept"), keep=True)
    assert keep.returncode == EXIT_OK, keep.completed.describe()
    sandbox = acf.boot("live", cpu=2, memory="128", disk="256")
    assert sandbox.name is not None
    acf.snapshot_create(acf.name("s"), sandbox.name)
    assert acf.sandbox_list()
    assert acf.snapshot_list()
    assert acf.purge() == []
    assert acf.sandbox_list() == []
    assert acf.snapshot_list() == []


# ------------------------------------------------------------------------------------------------ the raw protocol
def test_a_raw_client_speaks_the_wire_protocol_without_the_cli(fake_socket: Path) -> None:
    answer = raw_call(str(fake_socket), "host_info")
    assert answer.connected
    assert (answer.status, answer.reply["result"]["type"]) == ("SUCCEEDED", "host_info")
    assert answer.error is None
    assert answer.uid == os.getuid()


def test_a_raw_client_reports_what_the_host_refused_as_data(fake_socket: Path) -> None:
    answer = raw_call(str(fake_socket), "no_such_method", operation_id=new_operation_id())
    assert answer.status == "REJECTED"
    assert answer.error is not None
    assert (answer.error["class"], answer.error["side_effect"]) == ("VALIDATION", "none")


def test_a_raw_client_reports_an_unreachable_socket_as_data_not_as_an_exception(tmp_path: Path) -> None:
    answer = raw_call(str(tmp_path / "missing"), "host_info")
    assert answer.connect == "FileNotFoundError:2"
    assert not answer.connected
    assert answer.frames == []
    with pytest.raises(DriverError, match="expected exactly one response frame"):
        _ = answer.reply


def test_operation_ids_are_valid_and_unique() -> None:
    ids = {new_operation_id() for _ in range(50)}
    assert len(ids) == 50
    assert all(len(i) == 3 + 32 and i.startswith("op-") for i in ids)


def test_an_interrupt_reaches_the_command_but_not_the_test_runner() -> None:
    """``interrupt()`` is Ctrl-C for the background invocation's own process group: it must never signal us."""
    proc = subprocess.Popen(
        ["sleep", "60"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True
    )
    running = Spawned(("sleep", "60"), proc)
    assert running.poll() is None
    running.interrupt()
    done = running.wait(10)
    assert done.returncode == -signal.SIGINT, done.describe()
    assert running.wait(10) is done, "a finished invocation is reported as the same object every time"
