"""Recovery: what the host decides after something went away, and what it refuses to decide.

The rule under test is the same everywhere: the host believes the kernel and its own durable records, proves
ownership before it signals or deletes anything, keeps the lease of whatever it cannot prove absent, and says
``UNKNOWN`` or quarantines rather than guess.

* ``control_plane`` tests restart, corrupt and regress the store of a test host of their own, forge an ownership
  marker, and walk the operator's way out (``quarantine release``, ``host acknowledge``, ``host set-mode``). They
  implement T-REC-06, T-REC-10, T-RES-03, T-STATE-04, T-HOST-02 and T-HOST-03 at evidence level L2/L3.
* The L4 tests end real processes on a production host: the core (through its systemd unit) and the VMM. They are
  T-REC-04, T-REC-08, T-REC-11 and T-CONC-03, with the crash checks that go with them.
"""

from __future__ import annotations

import fcntl
import os
import shutil
import signal
import time
from pathlib import Path

import pytest

from acf_driver import (
    EXIT_FAILED,
    EXIT_OK,
    EXIT_TRANSPORT,
    EXIT_UNKNOWN,
    AcfLocal,
    Sandbox,
    WireHost,
    new_operation_id,
    resources,
    target_of,
)
from acf_integration import (
    OWNERSHIP_MARKER,
    HostEnv,
    HostUnit,
    await_sandbox,
    edited_copy,
    forge_ownership_marker,
    private_host,
    quarantine_by_forgery,
    require_root,
    seconds_until_gone,
    vmm_of,
)
from acf_proc import pids_with_argument, process_alive, start_time_ticks

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("clean_host")]

GHOST = "sbx-" + "0" * 32


def _create(acf: AcfLocal) -> dict[str, object]:
    return {"image": acf.image, "resources": resources()}


def _host_files(host_env: HostEnv) -> None:
    if not host_env.control_plane:
        require_root(host_env, "changing files in the host's state directory")


# ============================================================================================ a restart
@pytest.mark.control_plane
def test_t_res_03_a_failed_generation_keeps_its_lease_until_it_is_destroyed(acf: AcfLocal, host_env: HostEnv) -> None:
    """T-RES-03 (L2): a ``FAILED`` generation keeps its lease; release happens exactly at ``DESTROYED``.

    The runtimes of the test host live in its memory, so a restart is "every runtime was lost while the core was
    down": §16.2 part B says a generation whose runtime is absent is marked ``FAILED`` by a host-issued operation,
    and its lease is kept.
    """
    vcpus = host_env.config.integer("envelope.vcpus")
    with private_host(host_env, acf) as private:
        wire, client = private.acf.wire, private.acf
        before = wire.info()
        boxes = [wire.ready(acf.name(f"lost{i}")) for i in range(vcpus)]
        earlier = wire.run(boxes[0], ["true"])
        private.host.restart()

        after = wire.info()
        assert (after.mode, after.lineage) == ("SERVING", before.lineage)
        assert after.activation_epoch == before.activation_epoch + 1, "every activation of the core has its own epoch"
        assert after.instance_id != before.instance_id
        failed = [wire.refresh(box) for box in boxes]
        assert [box.state for box in failed] == ["FAILED"] * vcpus
        assert all(box.failure is not None for box in failed), "a FAILED generation says why"
        by_host = [op for op in wire.operations() if op.issuer == "HOST"]
        assert {op.target for op in by_host} == {box.sandbox_id for box in boxes}, (
            "the host records its own decisions as operations it issued"
        )
        assert wire.operation(earlier.operation_id).run_id == earlier.run_id, "records outlive the activation"

        assert after.live_sandboxes == vcpus, "a FAILED generation must keep its lease"
        with wire.nothing_recorded("a request on a FAILED generation"):
            full = client.refused("sandbox", "create", "--image", acf.image, "--cpu", "1", "--memory", "256")
            refusals = [
                client.refused("sandbox", "start", failed[0].sandbox_id),
                client.refused("sandbox", "exec", failed[0].sandbox_id, "--", "true"),
                client.refused("snapshot", "create", failed[0].sandbox_id, "--name", acf.name("s")),
            ]
        assert full.failure_class == "RESOURCE_EXHAUSTED", "capacity freed by a failure would hide a leaked runtime"
        assert [r.failure_class for r in refusals] == ["STATE_CONFLICT"] * 3, "a FAILED generation never runs again"

        gone = client.ok("sandbox", "destroy", failed[0].sandbox_id, "--yes").succeeded().sandbox_result()
        assert gone.state == "DESTROYED"
        assert wire.info().live_sandboxes == vcpus - 1, "the lease is released at DESTROYED"
        assert client.ok("sandbox", "create", "--image", acf.image, "--cpu", "1", "--memory", "256").succeeded()
        assert wire.stop(failed[1]).state == "STOPPED", "a FAILED generation can still be stopped"


@pytest.mark.control_plane
def test_a_sandbox_that_was_never_started_survives_a_restart_and_an_old_request_is_still_known(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    with private_host(host_env, acf) as private:
        wire = private.acf.wire
        operation_id, params = new_operation_id(), {**_create(acf), "name": acf.name("early")}
        created = wire.call("sandbox.create", params, operation_id=operation_id).succeeded().sandbox_result()
        private.host.restart(hard=True)

        survivor = wire.refresh(created)
        assert (survivor.state, survivor.generation) == ("PROVISIONING", 1), "nothing was running; nothing is lost"
        with wire.nothing_recorded("a retry of a request an earlier activation accepted"):
            again = wire.call("sandbox.create", params, operation_id=operation_id, retry=True).succeeded()
        assert again.sandbox_result().sandbox_id == created.sandbox_id
        assert wire.start(survivor).state == "READY"


# ============================================================================================ quarantine
@pytest.mark.control_plane
def test_t_state_02_a_quarantined_generation_accepts_nothing_but_its_release(acf: AcfLocal, host_env: HostEnv) -> None:
    """T-STATE-02 (L2), the quarantine row, and QR-1: a request on a ``QUARANTINED`` generation is refused with
    ``QUARANTINED``, except ``quarantine.release``. Quarantine is a condition, not a state: the generation keeps
    its state, lease and identifiers, and nothing of it is deleted."""
    _host_files(host_env)
    wire = acf.wire
    box = wire.ready(acf.name("forged"))
    snapshot = wire.snapshot(box, acf.name("before"))
    held = quarantine_by_forgery(acf, host_env, box)

    assert (held.state, held.generation) == ("READY", box.generation), "quarantine must not change the state"
    assert held.quarantined, "the record must say why the generation is quarantined"
    assert host_env.generation_dir(box).is_dir(), "a generation whose ownership is unproven must not be deleted"
    info = wire.info()
    assert (info.quarantined, info.live_sandboxes) == (1, 1), "a quarantined generation counts against capacity"

    with wire.nothing_recorded("a request on a quarantined generation"):
        refusals = [
            acf.refused("sandbox", "exec", box.sandbox_id, "--", "true"),
            acf.refused("sandbox", "stop", box.sandbox_id),
            acf.refused("sandbox", "destroy", box.sandbox_id, "--yes"),
            acf.refused("snapshot", "create", box.sandbox_id, "--name", acf.name("s")),
            acf.refused("snapshot", "restore", snapshot.snapshot_id, "--into", box.sandbox_id),
        ]
    assert [(r.failure_class, r.retry) for r in refusals] == [("QUARANTINED", "AFTER_CHANGE")] * len(refusals)


@pytest.mark.control_plane
def test_t_rec_06_force_destroy_releases_a_quarantined_generation_and_only_then_its_lease(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    """T-REC-06 (L2): ``quarantine.release`` in both modes; refused when observation contradicts the assertion;
    the lease is released only afterwards. This is ``FORCE_DESTROY`` and the contradicted ``DECLARE_ABSENT``."""
    _host_files(host_env)
    wire = acf.wire
    box = wire.ready(acf.name("held"))
    healthy = wire.ready(acf.name("healthy"))
    quarantine_by_forgery(acf, host_env, box)
    release = ("quarantine", "release", box.sandbox_id, "--generation", str(box.generation), "--yes", "--mode")

    with wire.nothing_recorded("a release the host does not admit"):
        not_quarantined = acf.refused(
            "quarantine", "release", healthy.sandbox_id, "--generation", "1", "--mode", "force-destroy", "--yes"
        )
        unknown = acf.refused("quarantine", "release", GHOST, "--generation", "1", "--mode", "declare-absent", "--yes")
        other_generation = acf.refused(
            "quarantine", "release", box.sandbox_id, "--generation", "2", "--mode", "force-destroy", "--yes"
        )
    assert not_quarantined.failure_class == "STATE_CONFLICT"
    assert (unknown.failure_class, other_generation.failure_class) == ("NOT_FOUND", "NOT_FOUND")

    contradicted = acf.json(*release, "declare-absent")
    assert contradicted.returncode == EXIT_FAILED, contradicted.describe()
    assert contradicted.operation().state == "FAILED", "the directory is still there: the assertion is contradicted"
    still = wire.refresh(box)
    assert still.quarantined, "a contradicted release must leave the generation quarantined"
    assert wire.info().live_sandboxes == 2, "and its lease held"
    assert host_env.generation_dir(box).is_dir()

    released = acf.ok(*release, "force-destroy").succeeded()
    assert (released.operation_type, released.owner[0]) == ("quarantine.release", "local-operator"), (
        "the release is an operation that records which operator made the assertion"
    )
    after = wire.refresh(box)
    assert (after.state, bool(after.quarantined)) == ("DESTROYED", False)
    assert not host_env.generation_dir(box).exists(), "FORCE_DESTROY tears the generation's resources down"
    info = wire.info()
    assert (info.quarantined, info.live_sandboxes) == (0, 1), "the lease is released when absence is observed"
    again = acf.refused(*release, "force-destroy")
    assert again.failure_class == "STATE_CONFLICT"


@pytest.mark.control_plane
def test_t_rec_06_declare_absent_is_believed_only_when_nothing_of_the_generation_remains(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    """T-REC-06 (L2), ``DECLARE_ABSENT``: the operator asserts that nothing remains, and the host verifies it."""
    with private_host(host_env, acf) as private:
        client, wire = private.acf, private.acf.wire
        private_env = HostEnv.for_test_host(private.host)
        box = wire.ready(acf.name("absent"))
        quarantine_by_forgery(client, private_env, box)
        private.host.restart()  # the test host's runtimes live in its memory: now no process of the generation exists
        assert wire.refresh(box).quarantined, "quarantine is durable: a restart must not lift it"
        release = (
            "quarantine", "release", box.sandbox_id, "--generation", str(box.generation), "--mode", "declare-absent",
            "--yes",
        )  # fmt: skip

        premature = client.json(*release)
        assert premature.returncode == EXIT_FAILED, "the generation's directory still exists"
        assert wire.refresh(box).quarantined

        shutil.rmtree(private_env.generation_dir(box))  # what an operator does by hand before declaring absence
        declared = client.ok(*release).succeeded()
        assert declared.operation_type == "quarantine.release"
        after = wire.refresh(box)
        assert (after.state, bool(after.quarantined)) == ("DESTROYED", False)
        assert wire.info().live_sandboxes == 0


@pytest.mark.control_plane
def test_only_an_operator_may_release_a_quarantined_generation(acf: AcfLocal, host_env: HostEnv) -> None:
    host_env.test_host()
    caller = host_env.peer(acf, "caller")
    box = caller.wire.ready(acf.name("mine"))
    quarantine_by_forgery(caller, host_env, box)
    with acf.wire.nothing_recorded("an operator method called by a caller"):
        denied = caller.refused(
            "quarantine", "release", box.sandbox_id, "--generation", "1", "--mode", "force-destroy", "--yes"
        )
    assert (denied.failure_class, denied.retry) == ("AUTHORIZATION_DENIED", "NEVER")
    assert caller.wire.refresh(box).quarantined


# ============================================================================================ the store
@pytest.mark.control_plane
def test_t_rec_10_a_store_older_than_the_markers_on_disk_means_containment_until_acknowledged(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    """T-REC-10 (L2): a store older than the markers on disk -> ``CONTAINMENT``; no destructive action;
    ``host.acknowledge`` leaves the mode."""
    with private_host(host_env, acf) as private:
        client, wire, host = private.acf, private.acf.wire, private.host
        private_env = HostEnv.for_test_host(host)
        known = wire.ready(acf.name("known"))
        older_store = host.journal.read_bytes()
        newer = wire.ready(acf.name("newer"))
        newer_dir = private_env.generation_dir(newer)
        host.stop()
        host.journal.write_bytes(older_store)
        host.start()

        info = wire.info()
        assert info.mode == "CONTAINMENT"
        assert [reason["reason"] for reason in info.containment_reasons] == ["store_regression"]
        assert newer_dir.is_dir(), "a host whose store is older than its disk must take no destructive action"
        assert wire.call("sandbox.inspect", {"sandbox": newer.sandbox_id}).refused().failure_class == "NOT_FOUND"

        with wire.nothing_recorded("a request a host in CONTAINMENT does not serve"):
            create = client.refused("sandbox", "create", "--image", acf.image)
            serving = client.refused("host", "set-mode", "serving")
        assert (create.failure_class, create.retry) == ("HOST_NOT_SERVING", "SAME_REQUEST_LATER")
        assert serving.failure_class == "STATE_CONFLICT", "the cause must be removed before the host serves again"
        unconfirmed = client.json("host", "acknowledge", "store-regression")
        assert (unconfirmed.returncode, wire.info().mode) == (2, "CONTAINMENT"), "the client sends nothing unconfirmed"

        acknowledged = client.ok("host", "acknowledge", "store-regression", "--yes").succeeded()
        assert acknowledged.operation_type == "host.acknowledge"
        assert wire.info().mode == "SERVING", "after the acknowledgement the store is authoritative again"
        assert newer_dir.is_dir(), "what the store does not describe is UNMANAGED: reported, never modified"
        assert wire.metrics()["gauges"]["unmanaged_resources"] >= 1
        assert client.refused("host", "acknowledge", "store-regression", "--yes").failure_class == "STATE_CONFLICT"
        assert wire.destroy(wire.refresh(known)).state == "DESTROYED"
        assert client.ok("sandbox", "create", "--image", acf.image).succeeded().state == "SUCCEEDED"


# ============================================================================================ host modes
def _classes_served(wire: WireHost, acf: AcfLocal, victim: Sandbox) -> dict[str, str]:
    """One request of each operation class; per class ``served`` or the class of the refusal."""

    def outcome(method: str, params: dict[str, object] | None) -> str:
        answer = wire.call(method, params)
        return "served" if answer.refusal is None else answer.refusal.failure_class

    return {
        "host.info": outcome("host.info", None),
        "read": outcome("sandbox.list", None),
        "granting": outcome("sandbox.create", _create(acf)),
        "operator": outcome("host.set_mode", {"mode": "DRAINING"}),
        "containment": outcome("sandbox.destroy", target_of(victim)),
    }


@pytest.mark.control_plane
def test_t_host_02_a_draining_host_refuses_granting_and_serves_everything_else(acf: AcfLocal) -> None:
    """T-HOST-02 and T-STATE-04 (L2), ``DRAINING``: granting refused; containment, reads and operator methods
    served. A request the host already accepted is still answered: draining never loses an outcome."""
    wire = acf.wire
    box = wire.ready(acf.name("drained"))
    accepted_id, params = new_operation_id(), {**_create(acf), "name": acf.name("before-drain")}
    wire.call("sandbox.create", params, operation_id=accepted_id).succeeded()

    drained = acf.ok("host", "set-mode", "draining").succeeded()
    assert (drained.operation_type, drained.host_change().mode) == ("host.set_mode", "DRAINING")
    assert acf.host_info().mode == "DRAINING"
    assert acf.ok("host", "set-mode", "draining").succeeded().host_change().mode == "DRAINING", "asking twice is fine"

    with wire.nothing_recorded("a granting request to a draining host"):
        refusals = [
            acf.refused("sandbox", "create", "--image", acf.image),
            acf.refused("sandbox", "exec", box.sandbox_id, "--", "true"),
            acf.refused("snapshot", "create", box.sandbox_id, "--name", acf.name("s")),
        ]
        known = wire.call("sandbox.create", params, operation_id=accepted_id, retry=True).succeeded()
    assert [(r.failure_class, r.retry) for r in refusals] == [("HOST_NOT_SERVING", "SAME_REQUEST_LATER")] * 3
    assert known.operation_id == accepted_id, "an operation accepted before the drain is still resolved"
    assert _classes_served(wire, acf, wire.refresh(box)) == {
        "host.info": "served",
        "read": "served",
        "granting": "HOST_NOT_SERVING",
        "operator": "served",
        "containment": "served",
    }

    assert acf.ok("host", "set-mode", "serving").succeeded().host_change().mode == "SERVING"
    assert acf.ok("sandbox", "create", "--image", acf.image).succeeded().state == "SUCCEEDED"


@pytest.mark.control_plane
def test_t_host_03_a_failed_mandatory_check_means_containment_and_the_host_does_not_exit(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    """T-HOST-03 (L2): a mandatory startup check fails with generations present -> ``CONTAINMENT``; destroy works;
    create is refused; the host does not exit. The failed check is T-OP-03's second half: a retention of finished
    operations shorter than the acceptance horizon."""
    with private_host(host_env, acf) as private:
        client, wire, host = private.acf, private.acf.wire, private.host
        box = wire.ready(acf.name("present"))
        horizon = host_env.config.integer("operations.acceptance_horizon_ms")
        retention = host_env.config.integer("operations.operation_retention_ms")
        assert host.config is not None
        broken = edited_copy(
            host.config,
            host.base / "host-with-short-retention.yaml",
            {
                f"operation_retention_ms: {retention}": f"operation_retention_ms: {horizon // 2}",
                f"output_retention_ms: {host_env.config.integer('operations.output_retention_ms')}": (
                    f"output_retention_ms: {horizon // 2}"
                ),
            },
        )
        host.stop()
        host.config = broken
        host.start()

        info = wire.info()
        assert host.running, "a failed mandatory check must not make the host exit while generations exist"
        assert info.mode == "CONTAINMENT"
        assert info.containment_reasons, "the host must say which check failed"
        assert _classes_served(wire, acf, wire.refresh(box)) == {
            "host.info": "served",
            "read": "served",
            "granting": "HOST_NOT_SERVING",
            "operator": "served",
            "containment": "served",
        }
        assert wire.refresh(box).state == "DESTROYED", "containment is served: the generation could be destroyed"
        assert client.refused("host", "set-mode", "serving").failure_class == "STATE_CONFLICT"


@pytest.mark.control_plane
def test_t_state_04_a_store_that_cannot_be_interpreted_means_read_only(acf: AcfLocal, host_env: HostEnv) -> None:
    """T-STATE-04 (L2), ``READ_ONLY``: reads and ``host.info`` served; granting, containment and operator methods
    refused with ``HOST_NOT_SERVING``. The host takes no action it cannot record."""
    with private_host(host_env, acf) as private:
        client, wire, host = private.acf, private.acf.wire, private.host
        box = wire.ready(acf.name("witness"))
        wire.run(box, ["true"])
        host.stop()
        damaged = bytearray(host.journal.read_bytes())
        damaged[len(damaged) // 2] ^= 0xFF
        host.journal.write_bytes(bytes(damaged))
        host.start()

        info = client.host_info()
        assert info.mode == "READ_ONLY"
        assert info.read_only_reason, "the host must say why it is read-only"
        listed = client.ok("sandbox", "list").sandboxes().items
        assert [s.sandbox_id for s in listed] == [box.sandbox_id], "what could be read is still served"
        assert _classes_served(wire, acf, listed[0]) == {
            "host.info": "served",
            "read": "served",
            "granting": "HOST_NOT_SERVING",
            "operator": "HOST_NOT_SERVING",
            "containment": "HOST_NOT_SERVING",
        }
        refused = client.refused("host", "set-mode", "draining")
        assert (refused.failure_class, refused.retry) == ("HOST_NOT_SERVING", "SAME_REQUEST_LATER")
        assert wire.metrics()["gauges"]["host_mode"] != 0, "the mode is reported as a measurement too"


# ============================================================================================ a real host (L4)
def _crash(host_unit: HostUnit, how: str) -> None:
    old = host_unit.main_pid()
    if how == "crash":
        host_unit.kill9()
    else:
        host_unit.restart()
    host_unit.wait_ready(not_pid=old)


@pytest.mark.parametrize("how", ["crash", "graceful_restart"])
def test_an_idle_sandbox_is_adopted_by_the_next_activation(
    acf: AcfLocal, host_env: HostEnv, host_unit: HostUnit, how: str
) -> None:
    """§16.2 part B, first row: ``READY``/``COMPLETED`` with the recorded runtime present and its enforcement
    intact -> adopt; no change. On the real host the core is killed (or restarted) under an idle sandbox."""
    require_root(host_env, "ending the core and seeing the VMM of another user")
    box = acf.boot("adopt")
    assert acf.sh(box.sandbox_id, "echo survived > /workspace/note").succeeded()
    before = acf.wire.refresh(box)
    identity = vmm_of(before)
    epoch = acf.wire.info().activation_epoch

    _crash(host_unit, how)

    after = acf.wire.refresh(box)
    assert (after.generation, after.state) == (before.generation, before.state)
    assert after.vmm_identity == identity, "adoption keeps the SAME runtime: another (pid, start time) is another VM"
    assert process_alive(*identity)
    assert acf.sh(box.sandbox_id, "cat /workspace/note").stdout_text == "survived\n", "the guest was rebooted"
    info = acf.wire.info()
    assert (info.mode, info.live_sandboxes, info.activation_epoch) == ("SERVING", 1, epoch + 1)
    assert len(pids_with_argument(before.jail_id)) == 1, "recovery started a second runtime for one generation"


def test_a_crash_during_a_command_ends_unknown_and_retires_the_generation(
    acf: AcfLocal, host_env: HostEnv, host_unit: HostUnit
) -> None:
    """§18.2, last row: an execution inherited by a later activation -> operation ``UNKNOWN``, run ``UNKNOWN``,
    generation ``FAILED``; the runtime is ended. The host never reports success for a command it lost sight of."""
    require_root(host_env, "ending the core and seeing the VMM of another user")
    box = acf.boot("midrun")
    identity = vmm_of(box)
    operation_id = new_operation_id()
    running = acf.spawn(
        "sandbox", "exec", box.sandbox_id, "--operation-id", operation_id, "--time-limit", "300s", "--json", "--",
        "sh", "-c", "sleep 120; echo finished",
    )  # fmt: skip
    try:
        await_sandbox(acf, box, lambda seen: seen.state == "RUNNING", within=60, what="the command starting")
        old = host_unit.kill9()
        host_unit.wait_ready(not_pid=old)
        done = running.wait(timeout=300)
    finally:
        running.kill()
    assert done.returncode != EXIT_OK, f"a command cut short by a crash must not succeed:\n{done.describe()}"
    assert "finished" not in done.stdout

    operation = acf.wire.operation(operation_id)
    assert operation.state == "UNKNOWN", "the host cannot know how the command ended, and must say so"
    resolved = acf.json("operation", "get", operation_id)
    assert resolved.returncode == EXIT_UNKNOWN, resolved.describe()
    failed = await_sandbox(acf, box, lambda seen: seen.state == "FAILED", within=60, what="retiring the generation")
    assert failed.state == "FAILED"
    assert seconds_until_gone(identity, within=30, what="the runtime of a generation that lost a command") <= 30
    assert acf.refused("sandbox", "exec", box.sandbox_id, "--", "true").failure_class == "STATE_CONFLICT"


def test_while_the_core_is_down_the_client_says_so_and_runtimes_keep_running(
    acf: AcfLocal, host_env: HostEnv, host_unit: HostUnit
) -> None:
    require_root(host_env, "stopping the core and seeing the VMM of another user")
    box = acf.boot("downtime")
    identity = vmm_of(box)
    old = host_unit.main_pid()
    host_unit.stop()
    try:
        for args in (
            ("sandbox", "list"),
            ("host", "info"),
            ("sandbox", "exec", box.sandbox_id, "--expected-generation", "1", "--", "true"),
            ("sandbox", "create", "--image", acf.image),
        ):
            done = acf.json(*args)
            assert done.returncode == EXIT_TRANSPORT, f"{args} with the core down:\n{done.describe()}"
        assert process_alive(*identity), "stopping the core must leave runtimes running: they are adopted at start"
    finally:
        host_unit.start_if_stopped()
        host_unit.wait_ready(not_pid=old)
    assert acf.wire.refresh(box).vmm_identity == identity
    assert len(acf.wire.sandboxes()) == 1, "a request that could not be delivered created something"


def test_t_rec_11_a_runtime_killed_while_the_host_serves_is_failed_within_the_bound_and_keeps_its_lease(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    """T-REC-11: "a runtime killed while the host serves -> generation ``FAILED`` within the detection bound; lease
    kept".

    On the real host, as root: the VMM process of an idle sandbox is sent SIGKILL. Pass: the host's record becomes
    ``FAILED`` within ``recovery.runtime_loss_detection_ms`` (one second is allowed for this test's own polling);
    the decision is an operation the host issued; the lease is still held; destroy then releases it and leaves no
    process, control group or directory.
    """
    require_root(host_env, "ending the VMM of another user")
    bound = host_env.config.integer("recovery.runtime_loss_detection_ms") / 1000
    box = acf.boot("vmmdeath")
    identity = vmm_of(box)

    os.kill(identity[0], signal.SIGKILL)
    killed = time.monotonic()
    failed = await_sandbox(
        acf, box, lambda seen: seen.state == "FAILED", within=bound + 1, what="noticing a lost runtime"
    )
    took = time.monotonic() - killed
    assert took <= bound + 1, f"the loss was noticed after {took:.1f}s; the bound is {bound:.1f}s"
    assert failed.failure is not None
    assert not process_alive(*identity)
    issued = [op for op in acf.wire.operations() if op.target == box.sandbox_id and op.issuer == "HOST"]
    assert issued, "the host must record its decision as an operation it issued"
    assert acf.wire.info().live_sandboxes == 1, "a FAILED generation keeps its lease"
    assert host_env.generation_dir(box).is_dir(), "FAILED is not DESTROYED: the residue stays until it is proven gone"

    assert acf.refused("sandbox", "exec", box.sandbox_id, "--", "true").failure_class == "STATE_CONFLICT"
    assert acf.ok("sandbox", "destroy", box.sandbox_id, "--yes").succeeded().sandbox_result().state == "DESTROYED"
    assert acf.wire.info().live_sandboxes == 0
    assert not host_env.generation_dir(box).exists()
    assert not host_env.cgroup_dir(box).exists()
    assert pids_with_argument(box.jail_id) == []


@pytest.mark.parametrize("method", ["stop", "destroy"])
def test_t_conc_03_stop_and_destroy_complete_within_their_bound_when_the_guest_no_longer_responds(
    acf: AcfLocal, host_env: HostEnv, method: str
) -> None:
    """T-CONC-03: "stop and destroy during an execution whose guest has stopped responding -> complete within their
    bound".

    On the real host, as root: a long command is running when the VMM process is sent SIGSTOP, so the guest
    answers nothing, not even a cancel. Then stop (or destroy) is asked for. Pass: it ends ``SUCCEEDED`` within
    ``operations.deadlines.stop_ms`` (``destroy_ms``); the runtime is gone; the execution it superseded ends
    ``CANCELLED`` by ``SUPERSEDED`` or ``UNKNOWN``, never ``SUCCEEDED``.
    """
    require_root(host_env, "stopping the VMM of another user")
    bound = host_env.config.integer(f"operations.deadlines.{method}_ms") / 1000
    box = acf.boot("unresponsive")
    identity = vmm_of(box)
    exec_id = new_operation_id()
    running = acf.spawn(
        "sandbox", "exec", box.sandbox_id, "--operation-id", exec_id, "--time-limit", "600s", "--json", "--", "sleep", "500"
    )  # fmt: skip
    try:
        await_sandbox(acf, box, lambda seen: seen.state == "RUNNING", within=60, what="the command starting")
        os.kill(identity[0], signal.SIGSTOP)
        asked = time.monotonic()
        extra = ("--yes",) if method == "destroy" else ()
        done = acf.json("sandbox", method, box.sandbox_id, *extra, timeout=bound + 60)
        took = time.monotonic() - asked
        superseded = running.wait(timeout=120)
    finally:
        running.kill()
        if process_alive(*identity):
            os.kill(identity[0], signal.SIGCONT)

    operation = done.require_exit(EXIT_OK).operation()
    assert operation.state == "SUCCEEDED"
    assert took <= bound, f"{method} took {took:.1f}s with an unresponsive guest; its bound is {bound:.0f}s"
    assert operation.sandbox_result().state == ("STOPPED" if method == "stop" else "DESTROYED")
    assert not process_alive(*identity), "the runtime outlived the operation that ends it"

    execution = acf.wire.operation(exec_id)
    assert execution.state in {"CANCELLED", "UNKNOWN"}, "an execution cut off by containment cannot have succeeded"
    if execution.state == "CANCELLED":
        assert (execution.cancelled_by, execution.effect) == ("SUPERSEDED", "MAY_BE_APPLIED")
    assert superseded.returncode in {EXIT_FAILED, EXIT_UNKNOWN}, superseded.describe()


def test_t_rec_08_an_interrupted_snapshot_leaves_no_partial_snapshot_and_releases_its_quota(
    acf: AcfLocal, host_env: HostEnv, host_unit: HostUnit
) -> None:
    """T-REC-08: "an interrupted snapshot -> the guest is resumed or the generation is ``FAILED``; no partial
    snapshot is listed; quota released".

    On the real host, as root: a snapshot of a guest with 2 GiB of memory is started, and while the guest is
    ``PAUSED`` for the capture the core is sent SIGKILL. After the next activation has recovered, pass: the
    snapshot operation ended ``FAILED``; the sandbox is back in the idle state it was captured from and executes a
    command, or it is ``FAILED``; no snapshot is listed; the host counts no snapshot; nothing of the capture is left
    in the snapshot store.
    """
    require_root(host_env, "ending the core and reading the snapshot store")
    box = acf.boot("capture", memory="2048")
    operation_id = new_operation_id()
    capture = acf.spawn(
        "snapshot", "create", box.sandbox_id, "--name", acf.name("partial"), "--operation-id", operation_id, "--json"
    )
    try:
        deadline = time.monotonic() + 120
        while acf.wire.refresh(box).state != "PAUSED":
            if capture.poll() is not None or time.monotonic() > deadline:
                pytest.fail(
                    "the snapshot ended before the core could be killed in the middle of it; "
                    f"this host captures 2 GiB too fast for the test:\n{capture.wait(timeout=30).describe()}",
                    pytrace=False,
                )
            time.sleep(0.02)
        old = host_unit.kill9()
        host_unit.wait_ready(not_pid=old)
        capture.wait(timeout=120)
    finally:
        capture.kill()

    assert acf.wire.operation(operation_id).state == "FAILED", "an inherited snapshot is never continued"
    after = await_sandbox(
        acf, box, lambda seen: seen.state in {"READY", "COMPLETED", "FAILED"}, within=60, what="settling the sandbox"
    )
    if after.state != "FAILED":
        assert after.state == box.state, "the guest must return to the state it was paused from"
        assert acf.sh(box.sandbox_id, "echo resumed").stdout_text == "resumed\n", "the guest was left paused"
    assert acf.wire.snapshots() == [], "a snapshot whose capture was interrupted must not be listed"
    assert acf.wire.info().snapshots == 0, "the quota of the interrupted capture was not released"
    leftovers = sorted(p.name for p in (host_env.state_root / "snapshots").glob("*/*/*"))
    assert leftovers == [], f"partial artifacts of the interrupted capture remain: {leftovers}"


@pytest.mark.parametrize("case", ["forged", "missing", "copied"])
def test_t_rec_04_an_ownership_marker_that_proves_nothing_means_quarantine_and_nothing_is_touched(
    acf: AcfLocal, host_env: HostEnv, case: str
) -> None:
    """T-REC-04: "a forged, missing or copied ownership marker -> nothing signalled or deleted; quarantine".

    On the real host, as root: the ownership marker of a running generation is replaced by an empty document,
    removed, or overwritten with the marker of another generation. Pass: within one observation
    (``recovery.sweep_interval_ms``) the generation is quarantined; its VMM process is still the same process and
    its directory still exists; a destroy is refused with ``QUARANTINED``. The marker is then put back and the
    generation released by an operator, which is the only way out.
    """
    require_root(host_env, "changing a generation's ownership marker and seeing its VMM")
    box = acf.boot("unowned")
    other = acf.boot("bystander")
    identity = vmm_of(box)
    marker = host_env.generation_dir(box) / OWNERSHIP_MARKER
    original = marker.read_text(encoding="utf-8")
    if case == "forged":
        forge_ownership_marker(host_env, box)
    elif case == "missing":
        marker.unlink()
    else:
        marker.write_text(
            (host_env.generation_dir(other) / OWNERSHIP_MARKER).read_text(encoding="utf-8"), encoding="utf-8"
        )

    bound = host_env.config.integer("recovery.sweep_interval_ms") / 1000 + 10
    held = await_sandbox(
        acf, box, lambda seen: bool(seen.quarantined), within=bound, what=f"quarantine ({case} marker)"
    )
    assert held.generation == box.generation
    assert process_alive(*identity), "a process whose ownership is unproven was signalled"
    assert host_env.generation_dir(box).is_dir(), "a directory whose ownership is unproven was deleted"
    assert acf.refused("sandbox", "destroy", box.sandbox_id, "--yes").failure_class == "QUARANTINED"
    assert process_alive(*identity)
    bystander = acf.wire.refresh(other)
    assert (bystander.state, bool(bystander.quarantined)) == ("READY", False), "another generation was affected"

    marker.write_text(original, encoding="utf-8")
    released = acf.ok(
        "quarantine", "release", box.sandbox_id, "--generation", str(box.generation), "--mode", "force-destroy", "--yes"
    )
    assert released.succeeded().state == "SUCCEEDED"
    assert seconds_until_gone(identity, within=30, what="the runtime of a released generation") <= 30
    assert acf.wire.refresh(box).state == "DESTROYED"


def _fork_with_pid(wanted: int) -> int:
    """Start a sleeping process whose pid is ``wanted``, or return 0 when the kernel gave another number.

    Writing ``N - 1`` to ``ns_last_pid`` makes the next process of this pid namespace number ``N`` (root only).
    """
    with Path("/proc/sys/kernel/ns_last_pid").open("r+") as last:
        fcntl.flock(last, fcntl.LOCK_EX)
        last.seek(0)
        last.write(str(wanted - 1))
        last.flush()
        child = os.fork()
        if child == 0:
            os.execv("/bin/sleep", ["sleep", "900"])  # noqa: S606 - a harmless stand-in for "another process"
    if child == wanted:
        return child
    os.kill(child, signal.SIGKILL)
    os.waitpid(child, 0)
    return 0


def test_t_rec_04_a_reused_process_id_is_not_the_runtime_and_is_never_signalled(
    acf: AcfLocal, host_env: HostEnv, host_unit: HostUnit
) -> None:
    """T-REC-04: "process-id reuse -> nothing signalled or deleted".

    On the real host, as root: with the core down, the VMM of a sandbox is ended and an unrelated process (a
    ``sleep``) is given the very same process id. The core is then started. Its record names that pid, but the
    process identity is (pid, start time), so what it observes is ``FOREIGN``. Pass: the unrelated process is still
    alive after recovery and after a further observation interval; the generation is ``FAILED`` or quarantined,
    never adopted; its lease is kept.
    """
    require_root(host_env, "ending the core and the VMM, and choosing the pid of a new process")
    box = acf.boot("reuse")
    pid, started_at = vmm_of(box)
    old = host_unit.kill_and_keep_down()
    decoy = 0
    try:
        os.kill(pid, signal.SIGKILL)
        seconds_until_gone((pid, started_at), within=30, what="the VMM ending")
        for _ in range(50):
            decoy = _fork_with_pid(pid)
            if decoy:
                break
        assert decoy == pid, f"could not give an unrelated process the pid {pid}"
        decoy_started = start_time_ticks(decoy)
        assert decoy_started is not None
        assert decoy_started != started_at

        host_unit.start()
        host_unit.wait_ready(not_pid=old)
        settled = await_sandbox(
            acf, box, lambda seen: seen.state == "FAILED" or bool(seen.quarantined), within=60, what="recovery"
        )
        assert settled.vmm_identity != (pid, decoy_started), "the host adopted a process it never started"
        time.sleep(host_env.config.integer("recovery.runtime_loss_detection_ms") / 1000 + 1)
        assert process_alive(decoy, decoy_started), "the host signalled a process that only shares the recorded pid"
        assert acf.wire.info().live_sandboxes == 1, "the lease must be kept"
    finally:
        if decoy:
            os.kill(decoy, signal.SIGKILL)
            os.waitpid(decoy, 0)
        host_unit.start_if_stopped()
        host_unit.wait_ready()
