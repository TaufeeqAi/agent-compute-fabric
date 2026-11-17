"""Gate B: the VM lifecycle is deterministic (contract §11, §27.2; plan: "VM lifecycle deterministic").

On a real Firecracker host this proves that

* the milestone command (``run --cpu 2 --memory 4096 --network none --command ...``) gives the guest's real answer and
  leaves nothing behind;
* every sandbox walks the documented states in the documented order, and a VMM process exists exactly while the
  sandbox is running (stop and destroy end it, and the host's record agrees with the kernel's);
* the same command in fresh sandboxes gives the same evidence, and nothing leaks from one sandbox into the next;
* every illegal transition is refused (exit 3) and changes nothing.

Tests marked ``control_plane`` assert only what does not depend on what runs inside the guest. They also run under
``make control-plane`` against the in-memory host with the shipped configuration, so their expectations (names,
states, messages, exit codes) are checked in CI before the first KVM run.
"""

from __future__ import annotations

import pytest

from acf_driver import EXIT_OK, EXIT_REFUSED, AcfLocal, Run, process_alive

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("clean_host")]

BOOT_ID = "print(open('/proc/sys/kernel/random/boot_id').read().strip())"


# ------------------------------------------------------------------------------------------ the milestone
@pytest.mark.control_plane
def test_the_milestone_run_succeeds_and_leaves_nothing_behind(acf: AcfLocal) -> None:
    report = acf.run(["python", "-c", "print(6 * 7)"], cpu=2, memory="4096")
    assert report.returncode == EXIT_OK, report.completed.describe()
    run = report.run
    assert run.succeeded()
    assert run.evidence_status == "COMPLETE"
    assert run.run_id.startswith("run-")
    assert report.doc["sandbox"]["state"] == "DESTROYED"
    assert report.doc["cleanup_failed"] is False
    assert acf.sandbox_list() == []
    assert acf.host_info()["live_sandboxes"] == 0
    kept = acf.evidence_get(run.run_id)  # the evidence outlives the sandbox
    assert (kept.outcome, kept.stdout) == ("SUCCEEDED", run.stdout)


def test_the_guest_really_executed_the_command(acf: AcfLocal) -> None:
    run = acf.run(["python", "-c", "print(6 * 7)"], cpu=2, memory="4096").run
    assert run.succeeded()
    assert (run.stdout, run.stderr) == ("42\n", "")
    assert (run.exit_code, run.signal) == (0, None)
    assert run.stream("stdout")["status"] == "COMPLETE"
    assert run.stream("stdout")["total_bytes"] == run.stream("stdout")["kept_bytes"] == 3
    assert run.wall_ms > 0


# ------------------------------------------------------------------------------------------ the state walk
@pytest.mark.control_plane
def test_the_explicit_lifecycle_walks_the_documented_states(acf: AcfLocal) -> None:
    name = acf.name("walk")
    created = acf.sandbox_create(name, cpu=2, memory="512")
    assert (created.state, created.generation) == ("PROVISIONING", 1)
    assert acf.sandbox_start(name).state == "READY"
    run = acf.sh(name, "echo inside")
    assert run.succeeded()
    assert run.sandbox_id == created.sandbox_id
    assert acf.sandbox_inspect(name).state == "COMPLETED"
    assert acf.sandbox_stop(name).state == "STOPPED"
    assert acf.sandbox_destroy(name).state == "DESTROYED"
    assert acf.sandbox_list() == []


def test_the_vmm_process_lives_exactly_as_long_as_the_sandbox_runs(acf: AcfLocal) -> None:
    name = acf.name("vmm")
    acf.sandbox_create(name)
    assert acf.sandbox_inspect(name).vmm_identity is None, "a PROVISIONING sandbox has no VMM yet"

    running = acf.sandbox_start(name)
    identity = running.vmm_identity
    assert identity is not None, f"a READY sandbox must record its VMM process: {running}"
    assert process_alive(*identity), f"the host says pid {identity[0]} runs this sandbox, but no such process exists"

    stopped = acf.sandbox_stop(name)
    assert stopped.state == "STOPPED"
    assert not process_alive(*identity), "stop returned while the VMM was still running"
    assert acf.sandbox_destroy(name).state == "DESTROYED"
    assert not process_alive(*identity)


def test_the_disk_survives_between_commands_but_not_between_sandboxes(acf: AcfLocal) -> None:
    first = acf.boot("persist")
    assert first.name is not None
    assert acf.sh(first.name, "echo kept > /workspace/note").succeeded()
    assert acf.sh(first.name, "cat /workspace/note").stdout == "kept\n"
    assert acf.sandbox_destroy(first.name).state == "DESTROYED"

    second = acf.boot("fresh")
    assert second.name is not None
    gone = acf.sh(second.name, "test ! -e /workspace/note")
    assert gone.succeeded(), "a new sandbox saw a file written by a destroyed one"


def test_the_same_command_in_fresh_sandboxes_gives_the_same_evidence(acf: AcfLocal) -> None:
    def normalised(run: Run) -> list[tuple[object, ...]]:
        """The evidence minus what legitimately varies (peaks and CPU time)."""
        return [
            (e["resource"], e["configured"], e["effective"], e["violation"], e["action_taken"], e["mechanism"])
            for e in run["resource_evidence"]
            if e["resource"] != "cpu_usec"
        ]

    runs = [acf.run(["python", "-c", "print(sum(range(1000)))"]).run for _ in range(3)]
    assert [r.stdout for r in runs] == ["499500\n"] * 3
    assert {(r.outcome, r.exit_code, r.evidence_status) for r in runs} == {("SUCCEEDED", 0, "COMPLETE")}
    assert len({r.sandbox_id for r in runs}) == 3, "each run must get its own sandbox"
    assert len({r.run_id for r in runs}) == 3
    assert normalised(runs[0]) == normalised(runs[1]) == normalised(runs[2])
    limits = {
        name: runs[0].evidence(name)["configured"]
        for name in ("guest_pids", "runtime_ms", "stdout_bytes", "stderr_bytes")
    }
    assert limits == {"guest_pids": 256, "runtime_ms": 600_000, "stdout_bytes": 1_048_576, "stderr_bytes": 1_048_576}, (
        "with no limits requested a run reports the policy DEFAULTS, not the ceilings"
    )


def test_two_running_sandboxes_are_two_distinct_machines(acf: AcfLocal) -> None:
    one, two = acf.boot("one"), acf.boot("two")
    assert one.name is not None
    assert two.name is not None
    assert one.vmm_pid != two.vmm_pid
    assert acf.python(one.name, BOOT_ID).stdout != acf.python(two.name, BOOT_ID).stdout, "two sandboxes share a kernel"
    assert acf.sh(one.name, "echo mine > /workspace/who").succeeded()
    assert acf.sh(two.name, "test ! -e /workspace/who").succeeded(), (
        "a file written in one sandbox is visible in another"
    )


# ------------------------------------------------------------------------------------------ illegal transitions
@pytest.mark.control_plane
def test_names_are_unique_among_live_sandboxes_and_free_again_after_destroy(acf: AcfLocal) -> None:
    name = acf.name("unique")
    first = acf.sandbox_create(name)
    clash = acf.call("sandbox", "create", "--image", acf.image, "--name", name, "--json")
    assert clash.returncode == EXIT_REFUSED, clash.describe()
    assert "already exists" in clash.stderr
    assert [s.sandbox_id for s in acf.sandbox_list()] == [first.sandbox_id], "a refused create must change nothing"

    assert acf.sandbox_destroy(name).state == "DESTROYED"
    second = acf.sandbox_create(name)  # the name is free again
    assert second.sandbox_id != first.sandbox_id


@pytest.mark.control_plane
def test_start_is_legal_exactly_once_from_provisioning(acf: AcfLocal) -> None:
    name = acf.name("start")
    acf.sandbox_create(name)
    assert acf.sandbox_start(name).state == "READY"
    again = acf.call("sandbox", "start", name, "--json")
    assert again.returncode == EXIT_REFUSED, again.describe()
    assert "only a freshly provisioned sandbox can be started" in again.stderr
    assert acf.sandbox_inspect(name).state == "READY"

    assert acf.sandbox_stop(name).state == "STOPPED"
    revive = acf.call("sandbox", "start", name, "--json")
    assert revive.returncode == EXIT_REFUSED, (
        "a stopped sandbox cannot be started again: restore a snapshot or create a new one"
    )
    assert acf.sandbox_inspect(name).state == "STOPPED"


@pytest.mark.control_plane
def test_exec_needs_an_idle_sandbox_and_a_refusal_changes_nothing(acf: AcfLocal) -> None:
    name = acf.name("idle")
    acf.sandbox_create(name)
    before_start = acf.call("exec", name, "--json", "--", "true")
    assert before_start.returncode == EXIT_REFUSED, before_start.describe()
    assert "exec requires an idle (READY/COMPLETED) sandbox" in before_start.stderr
    assert acf.sandbox_inspect(name).state == "PROVISIONING"

    acf.sandbox_start(name)
    assert acf.sh(name, "true").succeeded()  # READY -> COMPLETED -> usable again
    assert acf.sh(name, "true").succeeded()
    acf.sandbox_stop(name)
    after_stop = acf.call("exec", name, "--json", "--", "true")
    assert after_stop.returncode == EXIT_REFUSED, after_stop.describe()
    assert acf.sandbox_inspect(name).state == "STOPPED"


@pytest.mark.control_plane
def test_stop_and_destroy_by_id_are_idempotent_but_a_destroyed_name_is_gone(acf: AcfLocal) -> None:
    box = acf.boot("idem")
    assert box.name is not None
    assert acf.sandbox_stop(box.name).state == "STOPPED"
    assert acf.sandbox_stop(box.name).state == "STOPPED", "stopping a stopped sandbox is a no-op, not an error"
    assert acf.sandbox_destroy(box.sandbox_id).state == "DESTROYED"
    assert acf.sandbox_destroy(box.sandbox_id).state == "DESTROYED", (
        "destroying twice by id reports the same final state"
    )
    by_name = acf.call("sandbox", "destroy", box.name, "--yes", "--json")
    assert by_name.returncode == EXIT_REFUSED, "the name is released by the first destroy"
    assert "no sandbox" in by_name.stderr


@pytest.mark.control_plane
def test_lookups_of_things_that_never_existed_fail_cleanly(acf: AcfLocal) -> None:
    ghost = "sbx-" + "0" * 32
    for args in (
        ("sandbox", "inspect", ghost),
        ("sandbox", "inspect", "no-such-name"),
        ("sandbox", "destroy", ghost, "--yes"),
    ):
        done = acf.call(*args, "--json")
        assert done.returncode == EXIT_REFUSED, done.describe()
        assert "no sandbox" in done.stderr
    assert acf.sandbox_list() == []
    assert acf.host_info()["live_sandboxes"] == 0
