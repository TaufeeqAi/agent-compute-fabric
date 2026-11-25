"""Every fault point of every public mutation: no second host operation, and never a guessed answer.

Proves ERR-1, ERR-7, ERR-8, RT-2, REC3-1 to REC3-6, IPS-3, IPS-10, IPS-14 and the catalog entries
T3-REC-01 to T3-REC-04, T3-ERR-02, T3-HB-01, T3-RED-19, T3-RED-26, T3-RED-32 and T3-RED-33, against
the model host.

The fault points are: before the claim; after the claim and before the host request is written; after
it is written and before the host applied it; after the host applied it and before its answer arrived;
after the answer and before the bind. The last hop, between core and edge, is covered by the tests of
the REST adapter.
"""

from __future__ import annotations

import shutil
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from acf_api.command import commands as c
from acf_api.command import model as m
from acf_api.command.answers import ErrorAnswer, ViewAnswer
from acf_api.core.store import ledger as lg
from tests.support.harness import Identity, Rig, sandbox_spec
from tests.support.model_host import Crash

Build = Callable[[Rig, Identity], Awaitable[c.Command]]


async def _sandbox(rig: Rig, dev: Identity, *, start: bool = True) -> str:
    created = await rig.view(dev, c.CreateSandbox(project=dev.project_id, spec=sandbox_spec()), "setup-create")
    sandbox_id = str(created["result"]["sandbox"]["sandbox_id"])
    if start:
        await rig.view(
            dev, c.StartSandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation=1), "setup-start"
        )
    return sandbox_id


async def _snapshot(rig: Rig, dev: Identity, sandbox_id: str) -> dict[str, Any]:
    op = await rig.view(
        dev,
        c.CreateSnapshot(project=dev.project_id, sandbox_id=sandbox_id, spec=m.SnapshotSpec(expected_generation=1)),
        "setup-snapshot",
    )
    return dict(op["result"]["snapshot"])


async def _create(rig: Rig, dev: Identity) -> c.Command:
    return c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(name="subject"))


async def _start(rig: Rig, dev: Identity) -> c.Command:
    return c.StartSandbox(
        project=dev.project_id, sandbox_id=await _sandbox(rig, dev, start=False), expected_generation=1
    )


async def _exec(rig: Rig, dev: Identity) -> c.Command:
    spec = m.ExecSpec(expected_generation=1, argv=["true"])
    return c.Exec(project=dev.project_id, sandbox_id=await _sandbox(rig, dev), spec=spec)


async def _snapshot_create(rig: Rig, dev: Identity) -> c.Command:
    spec = m.SnapshotSpec(expected_generation=1, name="subject")
    return c.CreateSnapshot(project=dev.project_id, sandbox_id=await _sandbox(rig, dev), spec=spec)


async def _restore(rig: Rig, dev: Identity) -> c.Command:
    sandbox_id = await _sandbox(rig, dev)
    ref = await _snapshot(rig, dev, sandbox_id)
    target = m.RestoreInPlace(kind="existing", sandbox_id=sandbox_id, expected_generation=1)
    spec = m.RestoreSpec(snapshot_generation=ref["snapshot_generation"], target=target)
    return c.RestoreSnapshot(project=dev.project_id, snapshot_id=ref["snapshot_id"], spec=spec)


async def _stop(rig: Rig, dev: Identity) -> c.Command:
    return c.StopSandbox(project=dev.project_id, sandbox_id=await _sandbox(rig, dev), expected_generation=1)


async def _destroy(rig: Rig, dev: Identity) -> c.Command:
    return c.DestroySandbox(project=dev.project_id, sandbox_id=await _sandbox(rig, dev), expected_generation=1)


async def _delete_snapshot(rig: Rig, dev: Identity) -> c.Command:
    ref = await _snapshot(rig, dev, await _sandbox(rig, dev))
    return c.DeleteSnapshot(
        project=dev.project_id, snapshot_id=ref["snapshot_id"], snapshot_generation=ref["snapshot_generation"]
    )


async def _cancel(rig: Rig, dev: Identity) -> c.Command:
    sandbox_id = await _sandbox(rig, dev)
    rig.host.hold.add("exec.run")
    spec = m.ExecSpec(expected_generation=1, argv=["sleep", "600"])
    running = await rig.view(
        dev, c.Exec(project=dev.project_id, sandbox_id=sandbox_id, spec=spec, wait=0), "setup-exec"
    )
    return c.CancelExecution(project=dev.project_id, execution_id=running["target"]["execution_id"])


MUTATIONS: dict[str, tuple[Build, str]] = {
    "create": (_create, "sandbox.create"),
    "start": (_start, "sandbox.start"),
    "exec": (_exec, "exec.run"),
    "snapshot": (_snapshot_create, "snapshot.create"),
    "restore": (_restore, "snapshot.restore"),
    "stop": (_stop, "sandbox.stop"),
    "destroy": (_destroy, "sandbox.destroy"),
    "delete_snapshot": (_delete_snapshot, "snapshot.delete"),
    "cancel": (_cancel, "operation.cancel"),
}
every_mutation = pytest.mark.parametrize("name", sorted(MUTATIONS))


def _subject(rig: Rig, host_method: str) -> list[Any]:
    """The submissions of the mutation under test (set-up requests use other keys and other methods or ids)."""
    return [s for s in rig.host.mutating() if s.method == host_method]


@every_mutation
async def test_answer_lost_after_the_host_accepted(rig: Rig, dev: Identity, name: str) -> None:
    """T3-REC-01, T3-HB-01: the platform reads the operation by its id and returns it. One host operation."""
    build, method = MUTATIONS[name]
    command = await build(rig, dev)
    before = len(_subject(rig, method))
    rig.host.fault("lost_after", method)
    answer = await rig.call(dev, command, "subject-key")
    assert isinstance(answer, ViewAnswer), getattr(answer, "error", None)
    assert answer.body["state"] in {"SUCCEEDED", "IN_PROGRESS"}
    # The operation was started by this request: it is not a replay.
    assert answer.replayed is False
    assert len(_subject(rig, method)) == before + 1


@every_mutation
async def test_request_written_and_never_applied(rig: Rig, dev: Identity, name: str) -> None:
    """RT-2: absence is proven, so the same envelope is sent once more inside the same request."""
    build, method = MUTATIONS[name]
    command = await build(rig, dev)
    before = len(_subject(rig, method))
    rig.host.fault("lost_before", method)
    answer = await rig.call(dev, command, "subject-key")
    assert isinstance(answer, ViewAnswer), getattr(answer, "error", None)
    sent = _subject(rig, method)[before:]
    assert len(sent) == 2
    # Nothing is ever sent twice with different content: the two envelopes are the same bytes.
    assert sent[0].raw == sent[1].raw
    assert sent[0].operation_id == sent[1].operation_id == answer.body["operation_id"]


@every_mutation
async def test_host_unreachable_before_the_request_was_written(rig: Rig, dev: Identity, name: str) -> None:
    """ERR-1: nothing was sent, so this is a refusal, and the same key then makes a fresh attempt."""
    build, method = MUTATIONS[name]
    command = await build(rig, dev)
    before = len(_subject(rig, method))
    rig.host.fault("unreachable", method, times=20)
    error = await rig.error(dev, command, "subject-key")
    assert (error.code, error.kind, error.retry) == ("UPSTREAM_UNAVAILABLE", "REFUSED", "SAME_REQUEST_LATER")
    assert len(_subject(rig, method)) == before
    counts = await rig.core.service.d.ledger.counts(0)
    assert counts["claimed"] == 0, "a refusal leaves no claim behind"
    rig.host.faults.clear()
    retried = await rig.call(dev, command, "subject-key")
    assert isinstance(retried, ViewAnswer), getattr(retried, "error", None)
    assert retried.replayed is False
    assert len(_subject(rig, method)) == before + 1


@every_mutation
async def test_a_loss_that_cannot_be_resolved_is_never_called_a_refusal(rig: Rig, dev: Identity, name: str) -> None:
    """T3-ERR-02: after the request was written, the answer is the operation or UNRESOLVED. The re-ask finds the truth."""
    build, method = MUTATIONS[name]
    command = await build(rig, dev)
    before = len(_subject(rig, method))
    rig.host.fault("lost_after", method)
    rig.host.fault("unreachable", "operation.get", times=50)
    error = await rig.error(dev, command, "subject-key")
    assert (error.code, error.kind, error.retry) == ("OUTCOME_UNRESOLVED", "UNRESOLVED", "SAME_REQUEST_LATER")
    assert error.idempotency_key == "subject-key"
    rig.host.faults.clear()
    resolved = await rig.call(dev, command, "subject-key")
    assert isinstance(resolved, ViewAnswer), getattr(resolved, "error", None)
    assert resolved.replayed is True
    assert len(_subject(rig, method)) == before + 1


@every_mutation
async def test_a_refusal_by_the_host_releases_the_claim_before_it_is_answered(
    rig: Rig, dev: Identity, name: str
) -> None:
    """ERR-8, IPS-3: the kind follows what the host proved."""
    build, _method = MUTATIONS[name]
    command = await build(rig, dev)
    rig.host.refuse_next = ("STATE_CONFLICT", "AFTER_CHANGE", "not now")
    error = await rig.error(dev, command, "subject-key")
    assert (error.code, error.kind, error.retry) == ("STATE_CONFLICT", "REFUSED", "AFTER_CHANGE")
    assert (await rig.core.service.d.ledger.counts(0))["claimed"] == 0


# ------------------------------------------------------------------------------- the recovery pass
async def _unresolved(rig: Rig, dev: Identity, fault: str) -> tuple[c.Command, str]:
    """Leave one entry CLAIMED: the request was written, and nothing could be learned about it."""
    command = c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(name="orphan"))
    rig.host.fault(fault, "sandbox.create")
    rig.host.fault("unreachable", "operation.get", times=50)
    error = await rig.error(dev, command, "orphan-key")
    assert error.code == "OUTCOME_UNRESOLVED"
    rig.host.faults.clear()
    return command, "orphan-key"


async def test_recovery_binds_what_the_host_holds(rig: Rig, dev: Identity) -> None:
    """T3-REC-02, REC3-1: a crash after the host accepted and before the bind."""
    command, key = await _unresolved(rig, dev, "lost_after")
    mutating_before = len(rig.host.mutating())
    fresh = await rig.restart(recover=False)
    try:
        assert fresh.core.service.d.standing.ready() is False
        totals = await fresh.core.recovery.startup_pass()
        assert totals == {"bound": 1, "released": 0, "lost": 0, "unreached": 0}
        assert fresh.core.service.d.standing.ready() is True
        # T3-RED-32: recovery read, and never submitted.
        assert len(fresh.host.mutating()) == mutating_before
        answer = await fresh.call(dev, command, key)
        assert isinstance(answer, ViewAnswer)
        assert answer.replayed is True
        assert answer.body["state"] == "SUCCEEDED"
    finally:
        await fresh.close()


async def test_recovery_releases_what_provably_never_existed(rig: Rig, dev: Identity) -> None:
    """T3-REC-02, REC3-5: the host holds nothing, its lineage and sequence are the expected ones, and it cannot have forgotten."""
    command, key = await _unresolved(rig, dev, "lost_before")
    fresh = await rig.restart(recover=False)
    try:
        totals = await fresh.core.recovery.startup_pass()
        assert totals == {"bound": 0, "released": 1, "lost": 0, "unreached": 0}
        answer = await fresh.call(dev, command, key)
        assert isinstance(answer, ViewAnswer)
        # A fresh attempt: this request started the operation.
        assert answer.replayed is False
    finally:
        await fresh.close()


async def test_recovery_loses_what_it_cannot_prove_absent(rig: Rig, dev: Identity) -> None:
    """REC3-5 (c), ERR-7: outside the acceptance horizon a NOT_FOUND proves nothing, and nothing is guessed."""
    command, key = await _unresolved(rig, dev, "lost_before")
    rig.clock.advance(rig.host.acceptance_horizon_ms / 1000 + 60)
    fresh = await rig.restart(recover=False)
    try:
        totals = await fresh.core.recovery.startup_pass()
        assert totals == {"bound": 0, "released": 0, "lost": 1, "unreached": 0}
        error = await fresh.error(dev, command, key)
        assert (error.code, error.kind, error.retry) == ("OUTCOME_LOST", "UNRESOLVED", "NEVER")
        # The key is never resubmitted, now or later.
        assert (await fresh.error(dev, command, key)).code == "OUTCOME_LOST"
        assert len([s for s in fresh.host.mutating() if s.method == "sandbox.create"]) == 1
    finally:
        await fresh.close()


async def test_an_entry_the_host_did_not_answer_for_does_not_hold_readiness_back(rig: Rig, dev: Identity) -> None:
    """REC3-3, REC3-4: it stays CLAIMED, a request that meets it is unresolved, and it converges once the host answers."""
    command, key = await _unresolved(rig, dev, "lost_after")
    fresh = await rig.restart(recover=False)
    try:
        fresh.host.fault("unreachable", "operation.get", times=3)
        totals = await fresh.core.recovery.startup_pass()
        assert totals["unreached"] == 1
        assert fresh.core.service.d.standing.recovered is True
        fresh.host.fault("unreachable", "operation.get", times=50)
        assert (await fresh.error(dev, command, key)).code == "OUTCOME_UNRESOLVED"
        fresh.host.faults.clear()
        fresh.clock.advance(fresh.config.parameters.claim_stale_after + 1)
        assert (await fresh.core.recovery.sweep())["bound"] == 1
    finally:
        await fresh.close()


async def test_granting_work_waits_for_the_first_pass_and_containment_does_not(rig: Rig, dev: Identity) -> None:
    """REC3-3, SVC-10."""
    sandbox_id = await _sandbox(rig, dev)
    fresh = await rig.restart(recover=False)
    try:
        refused = await fresh.error(dev, c.CreateSandbox(project=dev.project_id, spec=sandbox_spec()), "k-new")
        assert (refused.code, refused.kind, refused.reason) == (
            "UPSTREAM_UNAVAILABLE",
            "REFUSED",
            "recovery_pass_pending",
        )
        listed = await fresh.view(dev, c.ListSandboxes(project=dev.project_id))
        assert len(listed["items"]) == 1
        destroyed = await fresh.view(
            dev,
            c.DestroySandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation="current"),
            "k-destroy",
        )
        assert destroyed["result"]["sandbox"]["state"] == "DESTROYED"
    finally:
        await fresh.close()


async def test_a_forgotten_operation_is_answered_from_its_recorded_outcome(rig: Rig, dev: Identity) -> None:
    """T3-RED-19, ERR-7: the host compacted the operation away. No second execution; the recorded view, marked."""
    command = c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(name="kept"))
    first = await rig.view(dev, command, "key-kept")
    assert rig.host.forget_operations(keep=0) >= 1
    again = await rig.call(dev, command, "key-kept")
    assert isinstance(again, ViewAnswer), getattr(again, "error", None)
    assert again.body["operation_id"] == first["operation_id"]
    assert again.body["recorded"] is True
    assert again.body["replayed"] is True
    assert again.body["state"] == "SUCCEEDED"
    assert again.body["target"]["sandbox_id"] == first["result"]["sandbox"]["sandbox_id"]
    assert "result" not in again.body, "a recorded view holds identifiers, not a copy of the resource"
    assert len(rig.host.submissions(first["operation_id"])) == 1
    # Reading the operation by its id gives the same recorded view.
    by_id = await rig.view(dev, c.GetOperation(project=dev.project_id, operation_id=first["operation_id"]))
    assert by_id["recorded"] is True


async def test_a_forgotten_operation_without_a_recorded_outcome_is_lost(rig: Rig, dev: Identity) -> None:
    """ERR-7: the host forgot an operation the platform never saw end."""
    rig.host.hold.add("sandbox.create")
    command = c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(name="open"), wait=0)
    first = await rig.view(dev, command, "key-open")
    assert first["terminal"] is False
    rig.host.finish(first["operation_id"])
    rig.host.forget_operations(keep=0)
    error = await rig.error(dev, command, "key-open")
    assert (error.code, error.kind, error.retry) == ("OUTCOME_LOST", "UNRESOLVED", "NEVER")
    assert error.idempotency_key == "key-open"
    assert len(rig.host.submissions(first["operation_id"])) == 1


async def test_a_changed_lineage_stops_granting_work_until_it_is_acknowledged(rig: Rig, dev: Identity) -> None:
    """T3-REC-04, REC3-6: entries of the old lineage become LOST and are never resubmitted to the new one."""
    command = c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(name="before"))
    first = await rig.view(dev, command, "key-before")
    old = rig.core.service.d.standing.pinned_lineage
    rig.host.replace_lineage("lineage-2")
    # Any answer of the host reports the lineage. A read is enough for the platform to notice.
    await rig.view(dev, c.ListSandboxes(project=dev.project_id))
    refused = await rig.error(dev, c.CreateSandbox(project=dev.project_id, spec=sandbox_spec()), "key-after")
    assert (refused.code, refused.kind, refused.reason) == ("UPSTREAM_UNAVAILABLE", "REFUSED", "host_lineage_changed")
    health = await rig.admin("health")
    assert health["reported_lineage"] == "lineage-2"
    assert "host_lineage_changed" in health["not_ready_reasons"]
    assert rig.host.mutating()[-1].operation_id == first["operation_id"], "nothing was sent to the new lineage"
    # The operator's acknowledgement must name exactly what the host reports.
    with pytest.raises(Exception, match="not the lineage"):
        await rig.admin("host.acknowledge-lineage", lineage="lineage-3")
    acknowledged = await rig.admin("host.acknowledge-lineage", lineage="lineage-2")
    assert acknowledged == {"pinned_lineage": "lineage-2", "previous": old, "entries_lost": 1}
    lost = await rig.call(dev, command, "key-before")
    # The recorded outcome is still the answer for the old key.
    assert isinstance(lost, ViewAnswer)
    assert lost.body["recorded"] is True
    assert [s.operation_id for s in rig.host.mutating()].count(first["operation_id"]) == 1
    ready = await rig.view(dev, c.CreateSandbox(project=dev.project_id, spec=sandbox_spec()), "key-after")
    assert ready["state"] == "SUCCEEDED"


async def test_a_regressed_host_store_proves_no_absence(rig: Rig, dev: Identity) -> None:
    """REC3-5 (b): the host's commit sequence is lower than one the platform has seen, so NOT_FOUND proves nothing."""
    await rig.view(dev, c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(name="seen")), "key-seen")
    command, key = await _unresolved(rig, dev, "lost_before")
    rig.host.regress(0)
    entries = await rig.core.service.d.ledger.claimed()
    assert len(entries) == 1
    assert await rig.core.recovery.visit(entries[0]) == "lost"
    assert (await rig.error(dev, command, key)).code == "OUTCOME_LOST"


async def test_a_revocation_survives_a_restore_of_the_store(rig: Rig, dev: Identity) -> None:
    """T3-RED-33, T3-REC-03, IPS-10, IPS-14, CRD-12: the journal is replayed before the core serves."""
    command = c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(name="kept"))
    first = await rig.view(dev, command, "key-kept")
    backup = rig.root / "backup"
    await rig.core.close()
    shutil.copytree(rig.config.paths.store_dir, backup)
    rig.host.closed = False
    live = await rig.restart()
    await live.admin("key.revoke", credential_id=dev.credential_id)
    assert (await live.error(dev, c.WhoAmI())).code == "UNAUTHENTICATED"
    await live.core.close()
    # The store goes back to before the revocation. The journal is not part of the backup.
    shutil.rmtree(live.config.paths.store_dir)
    shutil.copytree(backup, live.config.paths.store_dir)
    live.host.closed = False
    restored = await live.restart()
    try:
        assert (await restored.error(dev, c.WhoAmI())).code == "UNAUTHENTICATED"
        assert restored.core.telemetry.get("operator_diagnostics", kind="journal_replayed_over_an_older_store") == 1
        # A key issued again by the operator reaches the same host operations for the same keys.
        key = await restored.admin("key.issue", principal_id=dev.principal_id, project_id=dev.project_id)
        again = await restored.call(key["secret"], command, "key-kept")
        assert isinstance(again, ViewAnswer)
        assert again.body["operation_id"] == first["operation_id"]
        assert len(restored.host.submissions(first["operation_id"])) == 1
    finally:
        await restored.close()


async def _killed(rig: Rig, dev: Identity, *, written: bool) -> tuple[c.Command, str]:
    """The core dies with one entry CLAIMED: before it wrote the request, or after the host accepted it."""
    if written:
        return await _unresolved(rig, dev, "lost_after")
    command = c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(name="orphan"))
    rig.host.fault("crash", "sandbox.create")
    with pytest.raises(Crash):
        await rig.call(dev, command, "orphan-key")
    assert [e.state for e in await rig.core.service.d.ledger.claimed()] == [lg.CLAIMED]
    return command, "orphan-key"


@pytest.mark.parametrize("written", [False, True], ids=["killed-before-the-write", "killed-after-the-write"])
@pytest.mark.parametrize("delay_s", [1, 60])
@pytest.mark.parametrize("passed", [False, True], ids=["before-the-pass", "after-the-pass"])
async def test_a_duplicate_after_a_restart_gets_the_stated_answer(
    rig: Rig, dev: Identity, written: bool, delay_s: int, passed: bool
) -> None:
    """T3-RED-26, T3-IPS-01, IDM-6, IPS-16: the stated answer in each cell, and one host operation at most.

    The two ways to die here are the crash during the claim (the entry is durable and nothing was written)
    and the crash before the bind (the host accepted and the entry does not know). The crash during the
    release is in test_pipeline_guarantees.py.

    The entry carries an earlier writer epoch, so it is known not to be in flight: the duplicate is a
    resolution, whether it arrives before the recovery pass has visited the entry or after.
    """
    command, key = await _killed(rig, dev, written=written)
    rig.clock.advance(delay_s)
    fresh = await rig.restart(recover=passed)
    try:
        answer = await fresh.call(dev, command, key)
        if written:
            # The host holds the operation: it is returned, and it is not this request's new work.
            assert isinstance(answer, ViewAnswer), getattr(answer, "error", None)
            assert answer.replayed is True
        elif passed:
            # Absence was proven and the entry released: a fresh attempt, which this request started.
            assert isinstance(answer, ViewAnswer), getattr(answer, "error", None)
            assert answer.replayed is False
        else:
            # Absence is proven, so this is new work, and new work waits for the first pass. Nothing is sent.
            assert isinstance(answer, ErrorAnswer)
            assert (answer.error.code, answer.error.kind) == ("UPSTREAM_UNAVAILABLE", "REFUSED")
            await fresh.core.recovery.startup_pass()
            retried = await fresh.call(dev, command, key)
            assert isinstance(retried, ViewAnswer), getattr(retried, "error", None)
            assert retried.replayed is False
        creates = [s for s in fresh.host.mutating() if s.method == "sandbox.create"]
        assert len(creates) == 1, "one submission reached the host for this key"
        assert len([o for o in fresh.host.operations.values() if o["operation_type"] == "sandbox.create"]) == 1
    finally:
        await fresh.close()


async def test_the_request_that_discovers_a_new_lineage_is_bound_under_it(rig: Rig, dev: Identity) -> None:
    """REC3-6, IPS-5: the host reports its lineage in its answers, so one request may learn of the change by being answered.

    Its operation exists in the new lineage, is bound under it, and is not lost by the acknowledgement. Every
    later granting request is refused until an operator acknowledges.
    """
    rig.host.replace_lineage("lineage-2")
    discovered = await rig.view(
        dev, c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(name="first")), "key-first"
    )
    assert discovered["state"] == "SUCCEEDED"
    refused = await rig.error(
        dev, c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(name="second")), "key-second"
    )
    assert refused.reason == "host_lineage_changed"
    acknowledged = await rig.admin("host.acknowledge-lineage", lineage="lineage-2")
    assert acknowledged["entries_lost"] == 0
    again = await rig.view(dev, c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(name="first")), "key-first")
    assert again["operation_id"] == discovered["operation_id"]
    assert again["recorded"] is False


async def test_an_unresolved_entry_is_still_claimed_and_carries_no_parameters(rig: Rig, dev: Identity) -> None:
    """SEC-113, T3-RED-32: the store holds no request body, so recovery could not submit even if it wanted to."""
    await _unresolved(rig, dev, "lost_after")
    entries = await rig.core.service.d.ledger.claimed()
    assert [e.state for e in entries] == [lg.CLAIMED]
    for name in ("state.db", "state.db-wal"):
        path = rig.config.paths.store_dir / name
        if path.exists():
            assert b"orphan" not in path.read_bytes(), "the sandbox name of the request is nowhere in the store"


async def test_the_answer_of_a_lost_entry_never_becomes_a_refusal(rig: Rig, dev: Identity) -> None:
    """INV-105: a caller who is told OUTCOME_LOST is never later told that nothing happened."""
    command, key = await _unresolved(rig, dev, "lost_after")
    rig.host.replace_lineage("lineage-9")
    await rig.core.service.host_info(force=True)
    await rig.admin("host.acknowledge-lineage", lineage="lineage-9")
    answers = [await rig.call(dev, command, key) for _ in range(3)]
    assert all(isinstance(a, ErrorAnswer) and a.error.code == "OUTCOME_LOST" for a in answers)
