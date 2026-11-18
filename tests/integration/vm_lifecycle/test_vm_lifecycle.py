"""The sandbox lifecycle: the states of the contract, in the contract's order, and nothing in between.

Two kinds of test live here.

* Tests marked ``control_plane`` assert what does not depend on a guest: which method is admitted in which state,
  what a refusal says and that it records nothing, stale tokens, names, and the four-operation ``run once``. They
  go through the reference client and run under ``make control-plane`` against the test host with the shipped
  configuration and profile, and again against a production host.
* The others need a real VMM (evidence level L4). ``test_t_back_02_...`` is the catalog entry T-BACK-02 on
  Firecracker: every lifecycle step is checked against what the kernel of the host shows, not against what the
  host says about itself.
"""

from __future__ import annotations

import pytest

from acf_driver import (
    EXIT_OK,
    PROTOCOL,
    AcfLocal,
    Run,
    Sandbox,
    WireHost,
    api_description,
)
from acf_integration import HostEnv, require_root, seconds_until_gone, vmm_of
from acf_proc import cgroup_pids, pids_with_argument, process_alive

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("clean_host")]

GHOST_SANDBOX = "sbx-" + "0" * 32
BOOT_ID = "print(open('/proc/sys/kernel/random/boot_id').read().strip())"

# §12.2 of the contract: is the method admitted when the current generation is in this state?
#                 state          start  exec   snapshot
ADMISSION = {
    "PROVISIONING": (True, False, False),
    "READY": (False, True, True),
    "COMPLETED": (False, True, True),
    "STOPPED": (False, False, False),
    "DESTROYED": (False, False, False),
}


def _in_state(wire: WireHost, state: str) -> Sandbox:
    """A fresh sandbox whose current generation is in ``state``."""
    name = AcfLocal.name(state.lower())
    if state == "PROVISIONING":
        return wire.create(name)
    if state == "READY":
        return wire.ready(name)
    if state == "COMPLETED":
        return wire.completed(name)
    if state == "STOPPED":
        return wire.stop(wire.ready(name))
    assert state == "DESTROYED", state
    return wire.destroy(wire.ready(name))


# ============================================================================================ the host as shipped
@pytest.mark.control_plane
def test_the_host_serves_and_reports_exactly_the_bounds_of_the_files_it_loaded(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    info = acf.host_info()
    assert info.mode == "SERVING"
    assert list(info.containment_reasons) == [], "every mandatory check of the shipped configuration must pass"
    assert info.read_only_reason is None
    assert PROTOCOL in info.protocols
    assert set(info.features) <= set(api_description().features), "a feature outside the published description"

    profile, config = host_env.profile, host_env.config
    for name in (
        "max_vcpus",
        "max_memory_mib",
        "max_disk_mib",
        "max_runtime_ms",
        "max_pids",
        "max_stdout_bytes",
        "max_stderr_bytes",
        "max_lifetime_secs",
        "max_allowlist_entries",
    ):
        assert info.ceilings[name] == profile.integer(f"limits.{name}"), name
    for name in ("acceptance_horizon_ms", "clock_skew_tolerance_ms", "wait_max_ms"):
        assert info.parameters[name] == config.integer(f"operations.{name}"), name
    assert info.parameters["max_request_bytes"] == config.integer("edge.max_request_bytes")
    assert info.parameters["sandbox_lifetime_default_secs"] == profile.integer("defaults.lifetime_secs")
    assert info.capabilities["per_runtime_overhead_mib"] == host_env.vmm_overhead_mib
    assert set(info.network_modes) == set(profile.words("capabilities.network_modes"))
    assert (info.live_sandboxes, info.quarantined) == (0, 0)


# ============================================================================================ the state walk
@pytest.mark.control_plane
def test_the_lifecycle_walks_the_states_of_the_contract_through_the_client(acf: AcfLocal) -> None:
    name = acf.name("walk")
    created = acf.ok("sandbox", "create", "--image", acf.image, "--cpu", "2", "--memory", "512", "--name", name)
    operation = created.succeeded()
    assert (operation.operation_type, operation.effect) == ("sandbox.create", "APPLIED")
    box = operation.sandbox_result()
    assert (box.state, box.generation, box.name) == ("PROVISIONING", 1, name)
    assert box.vmm_identity is None, "a sandbox that was never started has no runtime"

    started = acf.ok("sandbox", "start", name).succeeded().sandbox_result()
    assert (started.sandbox_id, started.state, started.generation) == (box.sandbox_id, "READY", 1)
    assert started.vmm_identity is not None, "a READY sandbox records the identity of its runtime process"

    execution = acf.execute(name, ["true"])
    assert execution.returncode == EXIT_OK, execution.completed.describe()
    run = execution.run
    assert (run.sandbox_id, run.generation, run.status, run.exit_code) == (box.sandbox_id, 1, "EXITED", 0)
    after_run = acf.inspect(name)
    assert (after_run.state, after_run.last_run) == ("COMPLETED", run.run_id)

    stopped = acf.ok("sandbox", "stop", name).succeeded().sandbox_result()
    assert (stopped.state, stopped.vmm_identity) == ("STOPPED", None)
    destroyed = acf.ok("sandbox", "destroy", name, "--yes").succeeded().sandbox_result()
    assert (destroyed.state, destroyed.generation) == ("DESTROYED", 1)

    assert acf.wire.sandboxes() == []
    assert acf.host_info().live_sandboxes == 0


@pytest.mark.control_plane
@pytest.mark.parametrize("state", sorted(ADMISSION))
def test_t_state_02_each_method_is_admitted_exactly_in_the_states_of_the_contract(acf: AcfLocal, state: str) -> None:
    """T-STATE-02 (L2), for the states a healthy host can show: every granting method against §12.2.

    A method that is not admitted is refused with ``STATE_CONFLICT``, the generation stays where it was, and
    nothing is recorded. (``FAILED`` and the ``QUARANTINED`` condition are in the recovery suite.)
    """
    wire = acf.wire
    box = _in_state(wire, state)
    may_start, may_exec, may_snapshot = ADMISSION[state]
    requests = (
        (may_snapshot, ("snapshot", "create", box.sandbox_id, "--name", acf.name("s"))),
        (may_exec, ("sandbox", "exec", box.sandbox_id, "--", "true")),
        (may_start, ("sandbox", "start", box.sandbox_id)),
    )
    for admitted, args in requests:
        if admitted:
            acf.ok(*args).succeeded()
            continue
        before = wire.refresh(box)
        with wire.nothing_recorded(f"`{' '.join(args[:2])}` on a {state} sandbox"):
            refusal = acf.refused(*args)
        assert (refusal.failure_class, refusal.retry) == ("STATE_CONFLICT", "AFTER_CHANGE"), (args, refusal)
        after = wire.refresh(box)
        assert (after.state, after.generation, after.revision) == (before.state, before.generation, before.revision)


@pytest.mark.control_plane
def test_stop_and_destroy_are_admitted_everywhere_and_repeat_with_no_effect(acf: AcfLocal) -> None:
    wire = acf.wire
    for state in ("PROVISIONING", "READY", "COMPLETED"):
        box = _in_state(wire, state)
        assert acf.ok("sandbox", "stop", box.sandbox_id).succeeded().sandbox_result().state == "STOPPED", state

    box = _in_state(wire, "COMPLETED")
    first = acf.ok("sandbox", "stop", box.sandbox_id).succeeded().sandbox_result()
    again = acf.ok("sandbox", "stop", box.sandbox_id).succeeded().sandbox_result()
    assert (again.state, again.generation, again.expires_at) == ("STOPPED", first.generation, first.expires_at)

    assert acf.ok("sandbox", "destroy", box.sandbox_id, "--yes").succeeded().sandbox_result().state == "DESTROYED"
    repeat = acf.ok("sandbox", "destroy", box.sandbox_id, "--yes").succeeded().sandbox_result()
    assert (repeat.state, repeat.generation) == ("DESTROYED", first.generation)
    stop_after = acf.ok("sandbox", "stop", box.sandbox_id).succeeded().sandbox_result()
    assert stop_after.state == "DESTROYED", "a stop of a destroyed sandbox succeeds and changes nothing"

    unstarted = _in_state(wire, "PROVISIONING")
    assert acf.ok("sandbox", "destroy", unstarted.sandbox_id, "--yes").succeeded().sandbox_result().state == "DESTROYED"


@pytest.mark.control_plane
def test_t_conc_02_a_stale_generation_or_revision_is_refused_and_has_no_effect(acf: AcfLocal) -> None:
    """T-CONC-02 (L2): a stale generation or ``if_revision`` -> ``REVISION_CONFLICT``; no effect."""
    wire = acf.wire
    box = wire.ready(acf.name("tokens"))
    with wire.nothing_recorded("a request with a stale token"):
        stale_generation = acf.refused("sandbox", "stop", box.sandbox_id, "--expected-generation", "7")
        stale_revision = acf.refused("sandbox", "stop", box.sandbox_id, "--if-revision", "1")
        stale_exec = acf.refused("sandbox", "exec", box.sandbox_id, "--expected-generation", "2", "--", "true")
    for refusal in (stale_generation, stale_revision, stale_exec):
        assert (refusal.failure_class, refusal.retry) == ("REVISION_CONFLICT", "AFTER_CHANGE"), refusal
    current = wire.refresh(box)
    assert (current.state, current.revision) == ("READY", box.revision), "a refused request moved the sandbox"

    stopped = acf.ok(
        "sandbox", "stop", box.sandbox_id, "--expected-generation", "1", "--if-revision", str(current.revision)
    )
    assert stopped.succeeded().sandbox_result().state == "STOPPED", "the tokens of the current record are accepted"


@pytest.mark.control_plane
def test_a_name_is_unique_within_its_scope_and_free_again_after_destroy(acf: AcfLocal) -> None:
    wire = acf.wire
    name = acf.name("unique")
    first = wire.create(name)
    with wire.nothing_recorded("a create with a name that is taken"):
        clash = acf.refused("sandbox", "create", "--image", acf.image, "--name", name)
    assert (clash.failure_class, clash.retry) == ("STATE_CONFLICT", "AFTER_CHANGE")
    assert [s.sandbox_id for s in wire.sandboxes()] == [first.sandbox_id]

    wire.destroy(first)
    by_name = acf.refused("sandbox", "destroy", name, "--yes")
    assert by_name.failure_class == "NOT_FOUND", "the name is released by the destroy; only the id still names it"
    second = acf.ok("sandbox", "create", "--image", acf.image, "--name", name).succeeded().sandbox_result()
    assert second.sandbox_id != first.sandbox_id


@pytest.mark.control_plane
def test_what_never_existed_is_not_found_and_asking_changes_nothing(acf: AcfLocal) -> None:
    wire = acf.wire
    with wire.nothing_recorded("a lookup of something that does not exist"):
        refusals = [
            acf.refused("sandbox", "inspect", GHOST_SANDBOX),
            acf.refused("sandbox", "inspect", "no-such-name"),
            acf.refused("sandbox", "destroy", GHOST_SANDBOX, "--yes"),
            acf.refused("sandbox", "exec", GHOST_SANDBOX, "--", "true"),
            acf.refused("operation", "get", "op-" + "0" * 32),
            acf.refused("run", "inspect", "run-" + "0" * 32),
        ]
    assert [(r.failure_class, r.retry) for r in refusals] == [("NOT_FOUND", "NEVER")] * len(refusals), refusals
    assert wire.sandboxes() == []


@pytest.mark.control_plane
def test_t_conc_06_a_destroyed_sandbox_accepts_nothing_and_is_never_resurrected(acf: AcfLocal) -> None:
    """T-CONC-06 (L2): a destroyed sandbox accepts nothing; restore in place on it is refused; a generation is
    never reused."""
    wire = acf.wire
    name = acf.name("gone")
    box = wire.completed(name)
    snapshot = wire.snapshot(box, acf.name("before"))
    wire.destroy(box)

    with wire.nothing_recorded("a request on a destroyed sandbox"):
        refusals = [
            acf.refused("sandbox", "start", box.sandbox_id),
            acf.refused("sandbox", "exec", box.sandbox_id, "--", "true"),
            acf.refused("snapshot", "create", box.sandbox_id, "--name", acf.name("late")),
            acf.refused("snapshot", "restore", snapshot.snapshot_id, "--into", box.sandbox_id),
        ]
    assert [r.failure_class for r in refusals] == ["STATE_CONFLICT"] * len(refusals), refusals
    tombstone = acf.inspect(box.sandbox_id)
    assert (tombstone.state, tombstone.generation) == ("DESTROYED", box.generation)

    successor = wire.ready(name)
    assert successor.sandbox_id != box.sandbox_id, "a new sandbox with the old name is a new sandbox"
    assert acf.inspect(box.sandbox_id).state == "DESTROYED"
    assert wire.snapshots()[0].state == "READY", "destroying a sandbox does not delete its snapshots"


# ============================================================================================ run once
@pytest.mark.control_plane
def test_run_once_is_four_operations_and_its_record_outlives_the_sandbox(acf: AcfLocal) -> None:
    done = acf.json(
        "run", "once", "--image", acf.image, "--cpu", "2", "--memory", "4096", "--", "python", "-c", "print(6 * 7)"
    )
    report = done.require_exit(EXIT_OK).document()
    assert list(report["operations"]) == ["create", "start", "exec", "destroy"]
    assert (report["cleanup"]["state"], report["interrupted"], report["error"], report["exit_code"]) == (
        "destroyed",
        False,
        None,
        0,
    )
    run = Run(report["run"])
    assert run.succeeded()
    assert run.operation_id == report["operations"]["exec"]
    assert acf.wire.sandboxes() == [], "`run once` leaves no sandbox behind"
    assert acf.inspect(report["sandbox"]["sandbox_id"]).state == "DESTROYED"

    kept = acf.ok("run", "inspect", run.run_id).run()
    assert (kept.run_id, kept.status, kept.exit_code) == (run.run_id, "EXITED", 0), "the record outlives the sandbox"
    assert acf.run_output(run.run_id, "stdout") == run.stdout.inline(), "and so does the output it stored"


@pytest.mark.control_plane
def test_run_once_keep_leaves_the_sandbox_to_the_caller(acf: AcfLocal) -> None:
    report = acf.json("run", "once", "--image", acf.image, "--keep", "--", "true").require_exit(EXIT_OK).document()
    assert list(report["operations"]) == ["create", "start", "exec"]
    assert report["cleanup"]["state"] == "kept"
    kept = acf.inspect(report["sandbox"]["sandbox_id"])
    assert (kept.state, kept.generation) == ("COMPLETED", report["sandbox"]["generation"])


# ============================================================================================ a real VMM (L4)
def test_t_back_02_lifecycle_conformance_on_firecracker(acf: AcfLocal, host_env: HostEnv) -> None:
    """T-BACK-02, its L4 half: "the backend conformance suite passes ... on Firecracker".

    On the real host (as root, to read the host's 0700 state directory and the processes of other users) this walks
    one sandbox through create, start, exec, snapshot, restore in place, stop and destroy. After every step the
    host's record must agree with the kernel: a runtime process exists exactly in the states in which the contract
    says a runtime may exist, it is the process the host recorded, it sits in the control group and behind the
    namespace derived from the generation, and `DESTROYED` means proven absent: no process, no control group, no
    namespace, no directory.
    """
    require_root(host_env, "reading the host's state directory and other users' processes")
    wire = acf.wire
    name = acf.name("conformance")

    created = acf.ok("sandbox", "create", "--image", acf.image, "--name", name).succeeded().sandbox_result()
    assert (created.state, created.vmm_identity) == ("PROVISIONING", None)
    assert pids_with_argument(created.jail_id) == [], "a runtime exists before the sandbox was started"
    assert host_env.generation_dir(created).is_dir(), "PROVISIONING means the generation's storage is materialized"

    ready = acf.ok("sandbox", "start", name).succeeded().sandbox_result()
    first_vmm = vmm_of(ready)
    assert first_vmm[0] in cgroup_pids(host_env.cgroup_dir(ready)), "the runtime is not in its own control group"
    assert host_env.netns_handle(ready).exists(), "the runtime's network namespace has no handle"
    assert host_env.jail_root(ready).is_dir()

    run = acf.python(name, "print(6 * 7)")
    assert (run.succeeded(), run.stdout_text) == (True, "42\n"), "the guest did not execute the command"
    assert wire.refresh(ready).state == "COMPLETED"
    assert process_alive(*first_vmm)

    snapshot = acf.ok("snapshot", "create", name, "--name", acf.name("mid")).succeeded().snapshot_result()
    after_snapshot = wire.refresh(ready)
    assert (snapshot.state, after_snapshot.state) == ("READY", "COMPLETED"), "a snapshot returns the state it came from"
    assert after_snapshot.vmm_identity == first_vmm, "taking a snapshot must not replace the runtime"

    restored = acf.ok("snapshot", "restore", snapshot.snapshot_id, "--into", name).succeeded().sandbox_result()
    second_vmm = vmm_of(restored)
    assert (restored.state, restored.generation) == ("READY", ready.generation + 1)
    assert second_vmm != first_vmm, "a new generation must run in a new runtime instance"
    assert not process_alive(*first_vmm), "the superseded generation's runtime is still running"
    assert not host_env.generation_dir(ready).exists(), "the superseded generation's storage was not removed"
    assert not host_env.cgroup_dir(ready).exists()

    stopped = acf.ok("sandbox", "stop", name).succeeded().sandbox_result()
    assert (stopped.state, stopped.vmm_identity) == ("STOPPED", None)
    assert not process_alive(*second_vmm), "stop returned while the runtime was still running"
    assert pids_with_argument(restored.jail_id) == []
    assert host_env.generation_dir(restored).is_dir(), "STOPPED retains the generation's storage"

    destroyed = acf.ok("sandbox", "destroy", name, "--yes").succeeded().sandbox_result()
    assert destroyed.state == "DESTROYED"
    for leftover in (
        host_env.generation_dir(restored),
        host_env.cgroup_dir(restored),
        host_env.netns_handle(restored),
    ):
        assert not leftover.exists(), f"DESTROYED means proven absent, but {leftover} still exists"
    assert acf.host_info().live_sandboxes == 0
    wire.delete(snapshot)


def test_the_guest_really_executes_the_command(acf: AcfLocal) -> None:
    done = acf.json(
        "run", "once", "--image", acf.image, "--cpu", "2", "--memory", "4096", "--", "python", "-c", "print(6 * 7)"
    )
    run = Run(done.require_exit(EXIT_OK).document()["run"])
    assert (run.stdout_text, run.stderr_text) == ("42\n", "")
    assert (run.status, run.exit_code, run.signal) == ("EXITED", 0, None)
    assert (run.stdout.status, run.stdout.total_bytes, run.stdout.kept_bytes) == ("COMPLETE", 3, 3)
    assert run.evidence_status == "COMPLETE"


def test_a_stopped_runtime_is_gone_from_the_kernel_not_only_from_the_record(acf: AcfLocal, host_env: HostEnv) -> None:
    require_root(host_env, "seeing the processes of the runtime's user")
    box = acf.boot("vmm")
    identity = vmm_of(box)
    assert acf.ok("sandbox", "stop", box.sandbox_id).succeeded().sandbox_result().state == "STOPPED"
    took = seconds_until_gone(identity, within=1.0, what="stop answered before the runtime had ended")
    assert took < 1.0


def test_the_disk_survives_between_commands_but_not_between_sandboxes(acf: AcfLocal) -> None:
    first = acf.boot("persist")
    assert acf.sh(first.sandbox_id, "echo kept > /workspace/note").succeeded()
    assert acf.sh(first.sandbox_id, "cat /workspace/note").stdout_text == "kept\n"
    acf.wire.destroy(acf.wire.refresh(first))

    second = acf.boot("fresh")
    assert acf.sh(second.sandbox_id, "test ! -e /workspace/note").succeeded(), (
        "a new sandbox saw a file written by a destroyed one"
    )


def test_two_running_sandboxes_are_two_distinct_machines(acf: AcfLocal) -> None:
    one, two = acf.boot("one"), acf.boot("two")
    assert one.vmm_identity != two.vmm_identity
    boot_ids = {acf.python(box.sandbox_id, BOOT_ID).stdout_text for box in (one, two)}
    assert len(boot_ids) == 2, "two sandboxes share a kernel"
    assert acf.sh(one.sandbox_id, "echo mine > /workspace/who").succeeded()
    assert acf.sh(two.sandbox_id, "test ! -e /workspace/who").succeeded(), "a file written in one is visible in another"


def test_the_same_command_in_fresh_sandboxes_gives_the_same_evidence(acf: AcfLocal, host_env: HostEnv) -> None:
    def normalised(run: Run) -> list[tuple[object, ...]]:
        """The evidence minus what legitimately varies between runs (observed peaks)."""
        return [
            (e["resource"], e["configured"], e["effective"], e["violated"], e["action_taken"], e["mechanism"])
            for e in run["resource_evidence"]
        ]

    runs = []
    for _ in range(3):
        done = acf.json("run", "once", "--image", acf.image, "--", "python", "-c", "print(sum(range(1000)))")
        runs.append(Run(done.require_exit(EXIT_OK).document()["run"]))
    assert [r.stdout_text for r in runs] == ["499500\n"] * 3
    assert len({r.sandbox_id for r in runs}) == len({r.run_id for r in runs}) == 3, "each run gets its own sandbox"
    assert normalised(runs[0]) == normalised(runs[1]) == normalised(runs[2])
    defaults = {
        "guest_pids": host_env.profile.integer("defaults.pids"),
        "runtime_ms": host_env.profile.integer("defaults.runtime_ms"),
        "stdout_bytes": host_env.profile.integer("defaults.stdout_bytes"),
        "stderr_bytes": host_env.profile.integer("defaults.stderr_bytes"),
    }
    assert {name: runs[0].evidence(name)["configured"] for name in defaults} == defaults, (
        "with no limits requested a run is bound by the profile's DEFAULTS, not by its ceilings"
    )
