"""Gate F: crash recovery works (contract §14, §24, §27.6; plan: "crash recovery works").

The host agent is *crash-only*: stopping it gracefully and killing it with SIGKILL lead to the same code path, a
fresh process that reads the journal, looks at what is really running and decides, for every record, what must have
happened. These tests crash the real agent (through its systemd unit) and check what the kernel and the CLI say
afterwards:

* an **idle** sandbox is adopted by the next agent process: same VMM (proved by pid AND start time), same
  generation, same disk, no reboot;
* a crash in the middle of a **command** never reports success: the run's outcome is UNKNOWN, the sandbox is retired
  (its state can no longer be trusted) and no VMM is left behind;
* a VMM that dies by itself is noticed, and the sandbox can still be cleaned up;
* a **snapshot** survives a crash and can be restored afterwards;
* while the agent is down the CLI says so (exit 6) and changes nothing.

Nothing here is marked ``control_plane``: crashing a real process and reading ``/proc`` is the whole point.
"""

from __future__ import annotations

import os
import signal
from pathlib import Path

import pytest

from acf_driver import (
    EXIT_FAILED,
    EXIT_OK,
    EXIT_REFUSED,
    EXIT_UNKNOWN,
    EXIT_UNREACHABLE,
    AcfLocal,
    Sandbox,
    operation_ids,
    process_alive,
    wait_for,
)
from acf_integration import HostUnit

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("clean_host")]

SETTLE_S = 60.0  # how long recovery may take to leave a sandbox in a final state, once the agent answers again


def firecracker_pids() -> list[int]:
    """Every process on this machine whose command name is ``firecracker`` (VMMs outlive the agent, so leaks show here)."""
    found: list[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if (entry / "comm").read_text().strip() == "firecracker":
                found.append(int(entry.name))
        except OSError:
            continue  # it exited while we were looking
    return found


def _final(acf: AcfLocal, name: str) -> Sandbox:
    def probe() -> Sandbox | None:
        box = acf.sandbox_inspect(name)
        return box if box.state in {"FAILED", "STOPPED"} else None

    return wait_for(f"{name} to reach FAILED or STOPPED", probe, timeout=SETTLE_S)


def _crash(host_unit: HostUnit, how: str) -> None:
    old = host_unit.main_pid()
    if how == "crash":
        host_unit.kill9()
    else:
        host_unit.restart()
    host_unit.wait_ready(not_pid=old)


# ================================================================================================ idle sandboxes
@pytest.mark.parametrize("how", ["crash", "graceful_restart"])
def test_an_idle_sandbox_is_adopted_by_the_next_agent_process(acf: AcfLocal, host_unit: HostUnit, how: str) -> None:
    box = acf.boot("adopt")
    assert box.name is not None
    assert acf.sh(box.name, "echo survived > /workspace/note").succeeded()
    before = acf.sandbox_inspect(box.name)
    identity = before.vmm_identity
    assert identity is not None
    assert process_alive(*identity)

    _crash(host_unit, how)

    after = acf.sandbox_inspect(box.name)
    assert (after.sandbox_id, after.generation, after.state) == (before.sandbox_id, before.generation, before.state)
    assert after.vmm_identity == identity, (
        "adoption must keep the SAME VMM: a different (pid, start time) is a different VM"
    )
    assert process_alive(*identity)
    assert acf.sh(box.name, "cat /workspace/note").stdout == "survived\n", "the guest must not have been rebooted"
    info = acf.host_info()
    assert info["mode"] == "normal"
    assert not str(info["journal_integrity"]).startswith("Corrupt"), info["journal_integrity"]
    assert info["live_sandboxes"] == 1


def test_repeated_crashes_converge_on_the_same_sandbox(acf: AcfLocal, host_unit: HostUnit) -> None:
    box = acf.boot("again")
    assert box.name is not None
    identity = box.vmm_identity
    assert identity is not None
    for _ in range(3):
        _crash(host_unit, "crash")
        assert acf.sandbox_inspect(box.name).vmm_identity == identity
    assert acf.sh(box.name, "true").succeeded()
    assert len(firecracker_pids()) == 1, "recovery must not have started a second VMM"


def test_a_snapshot_survives_a_crash_and_can_still_be_restored(acf: AcfLocal, host_unit: HostUnit) -> None:
    box = acf.boot("snapcrash", memory="128", disk="256")
    assert box.name is not None
    acf.sh(box.name, "echo v1 > /workspace/version")
    snap = acf.snapshot_create(acf.name("baseline"), box.name)
    acf.sh(box.name, "echo v2 > /workspace/version")

    _crash(host_unit, "crash")

    assert [s.snapshot_id for s in acf.snapshot_list()] == [snap.snapshot_id]
    restored = acf.snapshot_restore(snap.snapshot_id, sandbox=box.name)
    assert restored.state == "READY"
    assert acf.sh(box.name, "cat /workspace/version").stdout == "v1\n"


# ================================================================================================ a crash mid-command
def test_a_crash_during_a_command_never_reports_success_and_retires_the_sandbox(
    acf: AcfLocal, host_unit: HostUnit
) -> None:
    box = acf.boot("midrun")
    assert box.name is not None
    identity = box.vmm_identity
    assert identity is not None

    running = acf.spawn_exec(box.name, "sleep 120; echo finished", shell=True, timeout="300s")
    try:
        wait_for(
            "the command to be running",
            lambda: True if acf.sandbox_inspect(box.name or "").state == "RUNNING" else None,
            timeout=60,
        )
        old = host_unit.kill9()
        host_unit.wait_ready(not_pid=old)
        done = running.wait(timeout=300)
    finally:
        running.kill()

    assert done.returncode in {EXIT_FAILED, EXIT_UNKNOWN, EXIT_UNREACHABLE}, (
        f"a command cut short by a crash must not succeed:\n{done.describe()}"
    )
    assert "finished" not in done.stdout
    for operation in operation_ids(done.stderr)[:1]:
        observed = acf.operation_get(operation)
        assert observed.json()["status"] == "UNKNOWN", (
            f"the host cannot know how the run ended, and must say so:\n{observed.describe()}"
        )
        assert observed.returncode == EXIT_UNKNOWN

    final = _final(acf, box.name)
    assert final.state in {"FAILED", "STOPPED"}
    assert not process_alive(*identity), "the VMM of an untrustworthy sandbox must be stopped"
    assert firecracker_pids() == []
    refused = acf.call("exec", box.name, "--json", "--", "true")
    assert refused.returncode == EXIT_REFUSED, "a sandbox that lost a run in a crash must not be reused"
    assert acf.sandbox_destroy(box.name).state == "DESTROYED"


# ================================================================================================ the VMM dies by itself
def test_a_vmm_killed_from_outside_is_noticed_and_the_sandbox_can_be_cleaned_up(acf: AcfLocal) -> None:
    box = acf.boot("vmmdeath")
    assert box.name is not None
    identity = box.vmm_identity
    assert identity is not None
    os.kill(identity[0], signal.SIGKILL)
    wait_for("the VMM to be gone", lambda: True if not process_alive(*identity) else None, timeout=30)

    done = acf.exec(box.name, "true", shell=True)
    assert done.returncode != EXIT_OK, "a command cannot succeed in a VM that no longer exists"
    assert not done.run.succeeded() if done.has_run else True

    final = _final(acf, box.name)
    assert final.state in {"FAILED", "STOPPED"}
    assert acf.sandbox_destroy(box.name).state == "DESTROYED"
    assert firecracker_pids() == []


# ================================================================================================ the agent is down
def test_while_the_agent_is_down_the_cli_says_so_and_changes_nothing(acf: AcfLocal, host_unit: HostUnit) -> None:
    box = acf.boot("downtime")
    assert box.name is not None
    identity = box.vmm_identity
    assert identity is not None
    old = host_unit.main_pid()
    host_unit.stop()
    try:
        for args in (
            ("sandbox", "list"),
            ("host", "info"),
            ("exec", box.name, "--", "true"),
            ("sandbox", "create", "--image", acf.image),
        ):
            done = acf.call(*args, "--json")
            assert done.returncode == EXIT_UNREACHABLE, f"{args} with the agent down:\n{done.describe()}"
        assert process_alive(*identity), "stopping the agent must leave running VMs running (they are adopted on start)"
    finally:
        host_unit.start_if_stopped()
        host_unit.wait_ready(not_pid=old)
    assert acf.sandbox_inspect(box.name).vmm_identity == identity
    assert len(acf.sandbox_list()) == 1, "a refused-because-unreachable create must not have created anything"
