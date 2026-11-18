//! T-OP: operations (contract §11). Idempotency, the acceptance horizon, deadlines, cancellation
//! and durability of what a response reports. The fault-point matrix (T-OP-05) is in `rec.rs`,
//! together with the recovery it is inseparable from; the fingerprint (T-OP-04, L1) is in
//! `domain/fingerprint.rs`.

use serde_json::{Value, json};

use crate::{
    api::OperationResult,
    domain::{CancelledBy, Cleanup, Effect, HostMode, LifecycleState, OperationState, OperationType, RunStatus},
    error::FailureClass,
    store::Journal,
    testing::rig::{
        Rig, alice, bob, calls, create_params, eventually, exec_params, footprint, ops, run_of, sandbox_of, snapshot_of, target,
    },
};

/// T-OP-01: an accepted operation whose response is lost is resolved by sending the request again
/// with the same id. It is the same operation, and nothing is executed again.
#[tokio::test]
async fn t_op_01_a_retried_request_is_the_same_operation_and_nothing_runs_again() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);

    let env = a.envelope("sandbox.create", create_params(Some("once")));
    let first = a.send(env.clone()).await.operation_view().cloned().unwrap(); // imagine this response never arrived
    assert_eq!(first.state, OperationState::Succeeded);
    let seq = host.journal.last_seq();

    let mut retry = env.clone();
    retry.retry = true;
    retry.request_id = Some("req-2".into());
    let again = a.send(retry).await.operation_view().cloned().unwrap();
    assert_eq!((&again.operation_id, again.state, again.revision), (&first.operation_id, first.state, first.revision));
    assert_eq!(sandbox_of(&again).sandbox_id, sandbox_of(&first).sandbox_id);
    // The retry flag is not needed for that: the id and the body are what identify an operation.
    let plain = a.send(env.clone()).await.operation_view().cloned().unwrap();
    assert_eq!(plain.operation_id, first.operation_id);
    assert_eq!(calls(&rig.world, "provision"), 1, "nothing was executed again");
    assert_eq!(host.journal.last_seq(), seq, "resolving a duplicate writes nothing");
    assert_eq!(a.sandboxes(json!({})).await.items.len(), 1);

    // An execution is never sent to a guest twice (RY-3).
    let sb = sandbox_of(&a.done("sandbox.start", target(&sandbox_of(&first))).await);
    let exec = a.envelope("exec.run", exec_params(&sb, &["/bin/echo", "hi"]));
    let ran = a.send(exec.clone()).await.operation_view().cloned().unwrap();
    let ran_again = a.send(exec).await.operation_view().cloned().unwrap();
    assert_eq!((run_of(&ran).run_id, ran.state), (run_of(&ran_again).run_id, OperationState::Succeeded));
    assert_eq!(calls(&rig.world, "exec"), 1);

    // Two concurrent requests with one operation id are one operation (§11.4).
    rig.world.hold("provision");
    let env = a.envelope("sandbox.create", create_params(Some("twice")));
    let in_flight = {
        let (a, env) = (a.clone(), env.clone());
        tokio::spawn(async move { a.send(env).await })
    };
    eventually("the first request reaches the backend", || rig.world.waiting("provision") == 1).await;
    let mut second = env.clone();
    second.wait_ms = Some(0);
    let concurrent = a.send(second).await.operation_view().cloned().unwrap();
    assert!(!concurrent.state.is_terminal(), "the duplicate sees the operation as it is: {:?}", concurrent.state);
    rig.world.release("provision");
    let finished = in_flight.await.unwrap().operation_view().cloned().unwrap();
    assert_eq!((finished.operation_id, finished.state), (concurrent.operation_id, OperationState::Succeeded));
    assert_eq!(calls(&rig.world, "provision"), 2, "one for each of the two operations, none for the duplicates");
}

/// T-OP-01 with §11.4 and RY-7: sending a request again is resolution of the operation it names, in
/// every mode that serves reads and however old the request has become. What refuses *new* work (the
/// host mode, the age of `issued_at`) does not refuse it, because it creates nothing. A caller whose
/// response was lost while the host began to drain must still be able to learn what happened.
#[tokio::test]
async fn t_op_01_a_retry_is_resolved_whatever_the_host_mode_and_however_old_the_request() {
    use crate::domain::ContainmentReason;
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let env = a.envelope("sandbox.create", create_params(Some("kept")));
    let first = a.send(env.clone()).await.operation_view().cloned().unwrap();
    assert_eq!(first.state, OperationState::Succeeded);
    let seq = host.journal.last_seq();

    // Both spellings: with `retry`, and as the plain request again.
    let resolves = async |what: &str| {
        let mut retry = env.clone();
        retry.retry = true;
        for request in [retry, env.clone()] {
            let answer = a.send(request).await;
            let view = answer.operation_view().unwrap_or_else(|| panic!("{what}: the retry was refused: {:?}", answer.refusal()));
            assert_eq!((&view.operation_id, view.state, view.revision), (&first.operation_id, first.state, first.revision), "{what}");
        }
    };

    // DRAINING refuses granting work. A retry is not work.
    ops(&host).done("host.set_mode", json!({"mode": "DRAINING"})).await;
    assert_eq!(host.mode(), HostMode::Draining);
    resolves("DRAINING").await;
    assert_eq!(a.refused("sandbox.create", create_params(Some("new"))).await.class, FailureClass::HostNotServing, "new work is refused");
    // A retry of something this host never accepted will never be accepted as a retry: NOT_FOUND, not "later".
    let mut never = a.envelope("sandbox.create", create_params(Some("never")));
    never.retry = true;
    assert_eq!(a.send(never).await.refusal().unwrap().class, FailureClass::NotFound);
    // The same id with another body is a conflict in any mode.
    let mut other = env.clone();
    other.params = Some(create_params(Some("different")));
    assert_eq!(a.send(other).await.refusal().unwrap().class, FailureClass::IdempotencyConflict);
    ops(&host).done("host.set_mode", json!({"mode": "SERVING"})).await;

    // CONTAINMENT: the same.
    host.contain(ContainmentReason::MandatoryCheck("a mandatory check failed".into()));
    assert_eq!(host.mode(), HostMode::Containment);
    resolves("CONTAINMENT").await;
    assert_eq!(host.clear_containment(|_| true), 1);

    // Past the acceptance horizon the request is too old to be accepted, and old enough to have been.
    let after_mode_changes = host.journal.last_seq();
    rig.clock.advance_ms(host.cfg.operations.acceptance_horizon_ms + 1_000);
    resolves("past the acceptance horizon").await;
    let mut stale = a.envelope("sandbox.create", create_params(Some("stale")));
    stale.issued_at = env.issued_at.clone();
    assert_eq!(a.send(stale).await.refusal().unwrap().class, FailureClass::ExpiredRequest, "a new request that old is refused");

    assert_eq!(calls(&rig.world, "provision"), 1, "nothing was executed again");
    assert_eq!(a.sandboxes(json!({})).await.items.len(), 1);
    assert!(seq < after_mode_changes && host.journal.last_seq() == after_mode_changes, "only the two mode changes wrote anything");
}

/// T-OP-02: the idempotency table of §11.4.
#[tokio::test]
async fn t_op_02_the_idempotency_table() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let env = a.envelope("sandbox.create", create_params(Some("box")));
    let id = env.operation_id.clone().unwrap();
    let first = a.send(env.clone()).await.operation_view().cloned().unwrap();
    let before = footprint(&host);

    // Same id, different request → IDEMPOTENCY_CONFLICT. One changed parameter is a different request...
    let mut changed = env.clone();
    changed.params = Some(create_params(Some("other")));
    assert_eq!(a.send(changed).await.refusal().map(|r| r.class), Some(FailureClass::IdempotencyConflict));
    let mut other_method = a.envelope("sandbox.destroy", target(&sandbox_of(&first)));
    other_method.operation_id = Some(id.clone());
    assert_eq!(a.send(other_method).await.refusal().map(|r| r.class), Some(FailureClass::IdempotencyConflict));
    // ...while key order, `request_id`, `retry`, `on_behalf_of` and an absent-versus-null field are not (OP-11).
    let mut reordered = env.clone();
    reordered.params = Some(
        json!({"lifetime_secs": null, "resources": {"network": {"mode": "none"}, "disk_mib": 128, "memory_mib": 256, "vcpus": 2}, "image": "python", "name": "box"}),
    );
    reordered.request_id = Some("another-request".into());
    reordered.on_behalf_of = Some("user:42".into());
    assert_eq!(a.send(reordered).await.operation_view().map(|v| v.operation_id.clone()), Some(id.clone()));

    // `retry` for an id the host has never seen → NOT_FOUND; it is never treated as a new request.
    let mut unknown = a.envelope("sandbox.create", create_params(None));
    unknown.retry = true;
    assert_eq!(a.send(unknown).await.refusal().map(|r| r.class), Some(FailureClass::NotFound));
    // No id, or no `issued_at`, on a method that needs them → INVALID_REQUEST.
    let mut no_id = a.envelope("sandbox.create", create_params(None));
    no_id.operation_id = None;
    assert_eq!(a.send(no_id).await.refusal().map(|r| r.class), Some(FailureClass::InvalidRequest));
    let mut no_time = a.envelope("sandbox.create", create_params(None));
    no_time.issued_at = None;
    assert_eq!(a.send(no_time).await.refusal().map(|r| r.class), Some(FailureClass::InvalidRequest));
    assert_eq!(footprint(&host), before, "none of these left a record");

    // Operation ids are namespaced by (peer, owner scope) (OP-10): the same id elsewhere is another operation.
    for other in [bob(&host), a.in_scope("team-other")] {
        let mut same_id = other.envelope("sandbox.create", create_params(Some("box")));
        same_id.operation_id = Some(id.clone());
        let theirs = other.send(same_id).await.operation_view().cloned().unwrap();
        assert_eq!(theirs.operation_id, id);
        assert_ne!(sandbox_of(&theirs).sandbox_id, sandbox_of(&first).sandbox_id);
    }

    // A request refused before BEGIN, sent again, is a fresh attempt: its id was never consumed.
    let refused = a.envelope("sandbox.start", json!({"sandbox_id": "sbx-00000000000000000000000000000000", "expected_generation": 1}));
    let reused_id = refused.operation_id.clone();
    assert_eq!(a.send(refused).await.refusal().map(|r| r.class), Some(FailureClass::NotFound));
    let mut fresh = a.envelope("sandbox.create", create_params(None));
    fresh.operation_id = reused_id;
    assert_eq!(a.send(fresh).await.operation_view().map(|v| v.state), Some(OperationState::Succeeded));
}

/// T-OP-03: `issued_at` outside the acceptance horizon → `EXPIRED_REQUEST`; a retention shorter
/// than the horizon is a failed mandatory check, and the host is in `CONTAINMENT`.
#[tokio::test]
async fn t_op_03_the_acceptance_horizon_and_the_retention_relation() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let (horizon, skew) = (host.cfg.operations.acceptance_horizon_ms as i64, host.cfg.operations.clock_skew_tolerance_ms as i64);
    let at = |offset_ms: i64| {
        let ms = host.clock.wall_ms() + offset_ms;
        crate::clock::rfc3339_utc(ms.div_euclid(1000), (ms.rem_euclid(1000) as u32) * 1_000_000)
    };
    let before = footprint(&host);
    for (what, offset) in [("older than the horizon", -horizon - 1_000), ("further ahead than the tolerance", skew + 1_000)] {
        let mut env = a.envelope("sandbox.create", create_params(None));
        env.issued_at = Some(at(offset));
        let r = a.send(env).await.refusal().cloned().unwrap();
        assert_eq!(r.class, FailureClass::ExpiredRequest, "{what}");
    }
    // Containment is subject to the horizon too: an old destroy must not be replayed.
    let mut stale_destroy =
        a.envelope("sandbox.destroy", json!({"sandbox_id": "sbx-00000000000000000000000000000000", "expected_generation": 1}));
    stale_destroy.issued_at = Some(at(-horizon - 1_000));
    assert_eq!(a.send(stale_destroy).await.refusal().map(|r| r.class), Some(FailureClass::ExpiredRequest));
    assert_eq!(footprint(&host), before);
    // Just inside, on both sides, is accepted.
    for offset in [-horizon + 1_000, skew - 1_000] {
        let mut env = a.envelope("sandbox.create", create_params(None));
        env.issued_at = Some(at(offset));
        assert!(a.send(env).await.operation_view().is_some(), "offset {offset} ms");
    }
    // A read needs no `issued_at` and is not subject to the horizon.
    assert_eq!(a.sandboxes(json!({})).await.items.len(), 2);

    // OP-12: retention must be at least the horizon, or a duplicate could arrive after its record is gone.
    let rig = Rig::with(|c| {
        c.operations.operation_retention_ms = 1_000;
        c.operations.output_retention_ms = 1_000;
    });
    let host = rig.serving().await;
    let info = ops(&host).info().await;
    assert_eq!(info.mode, HostMode::Containment, "the host runs, and creates no privilege");
    assert!(format!("{:?}", info.containment_reasons).contains("operation_retention_ms"), "{:?}", info.containment_reasons);
    assert_eq!(alice(&host).refused("sandbox.create", create_params(None)).await.class, FailureClass::HostNotServing);
}

/// T-OP-06: a granting operation that passes its deadline is undone and ends `FAILED`/`TIMEOUT`.
/// None ends `SUCCEEDED` after its deadline (OP-15).
#[tokio::test]
async fn t_op_06_a_granting_operation_past_its_deadline_is_undone_and_never_succeeds() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let deadlines = host.cfg.operations.deadlines.clone();
    let late = |method: &'static str, ms: u64| {
        let clock = rig.clock.clone();
        rig.world.on_call(method, move || clock.advance_ms(ms + 1));
    };

    // create: the step succeeds, too late. What it made is removed and the lease is released.
    late("provision", deadlines.create_ms);
    let op = a.op("sandbox.create", create_params(Some("late"))).await;
    rig.world.clear_hooks();
    assert_eq!((op.state, op.failure.as_ref().map(|f| f.class)), (OperationState::Failed, Some(FailureClass::Timeout)));
    assert_eq!((op.effect, op.cleanup), (Some(Effect::NotApplied), Some(Cleanup::Complete)));
    assert_eq!(footprint(&host).1, 0, "the reservation is released");
    assert!(a.sandboxes(json!({})).await.items.is_empty());
    assert!(
        !rig.layout.generation_path(&op.sandbox.clone().unwrap().0, op.sandbox.clone().unwrap().1).exists(),
        "the generation directory is gone"
    );

    // start: the runtime came up after the deadline. It is ended; the generation is FAILED and keeps its lease.
    let sb = a.create(None).await;
    late("start", deadlines.start_ms);
    let op = a.op("sandbox.start", target(&sb)).await;
    rig.world.clear_hooks();
    assert_eq!((op.state, op.failure.as_ref().map(|f| f.class)), (OperationState::Failed, Some(FailureClass::Timeout)));
    assert_eq!((op.effect, op.cleanup), (Some(Effect::MayBeApplied), Some(Cleanup::Pending)));
    assert_eq!(rig.world.vm_count(), 0, "the runtime that came up too late does not survive");
    assert_eq!(a.inspect(&sb.sandbox_id).await.state, LifecycleState::Failed);
    assert_eq!(footprint(&host).1, 1, "a FAILED generation keeps its lease (LS-1)");
    // Once the owner destroys it, the failed operation's cleanup is complete (OP-7 is derived, not stored).
    a.done("sandbox.destroy", target(&a.inspect(&sb.sandbox_id).await)).await;
    let op = a.get(&op.operation_id).await;
    assert_eq!((op.effect, op.cleanup), (Some(Effect::NotApplied), Some(Cleanup::Complete)));

    // exec: a result that arrives after the deadline is not a success. The command may have run.
    let sb = a.ready(None).await;
    late("exec", 60_000 + host.cfg.operations.backstop_margin_ms + 60_000);
    let op = a.op("exec.run", exec_params(&sb, &["/bin/true"])).await;
    rig.world.clear_hooks();
    assert_eq!((op.state, op.failure.as_ref().map(|f| f.class)), (OperationState::Failed, Some(FailureClass::Timeout)));
    assert_eq!(op.effect, Some(Effect::MayBeApplied), "an execution that reached the guest never reports NOT_APPLIED");
    assert_eq!(a.inspect(&sb.sandbox_id).await.state, LifecycleState::Failed);
    assert_eq!(rig.world.vm_count(), 0);

    // snapshot: too late. No snapshot is listed, the quota is released, and the guest runs again.
    let sb = a.ready(None).await;
    late("snapshot", deadlines.snapshot_ms);
    let op = a.op("snapshot.create", target(&sb)).await;
    rig.world.clear_hooks();
    assert_eq!((op.state, op.failure.as_ref().map(|f| f.class)), (OperationState::Failed, Some(FailureClass::Timeout)));
    assert!(a.snapshots(json!({})).await.items.is_empty());
    assert_eq!(footprint(&host).2, 0);
    assert_eq!(a.inspect(&sb.sandbox_id).await.state, LifecycleState::Ready);

    // restore as new: too late. The new sandbox does not exist.
    let snap = snapshot_of(&a.done("snapshot.create", target(&sb)).await);
    late("restore", deadlines.restore_ms);
    let op = a.op("snapshot.restore", json!({"snapshot": snap.snapshot, "target": {"kind": "new"}})).await;
    rig.world.clear_hooks();
    assert_eq!((op.state, op.failure.as_ref().map(|f| f.class)), (OperationState::Failed, Some(FailureClass::Timeout)));
    assert_eq!((op.effect, op.cleanup), (Some(Effect::NotApplied), Some(Cleanup::Complete)));
    assert_eq!(rig.world.vm_count(), 1, "only the source sandbox runs");
    let listed: Vec<_> = a.sandboxes(json!({})).await.items.into_iter().filter(|v| v.source_snapshot.is_some()).collect();
    assert!(listed.is_empty(), "the sandbox the restore was creating does not exist");
}

/// T-OP-07: cancel × {running execution, terminal, a type that cannot be cancelled, an earlier
/// activation, an unknown id}. Cancel is itself an operation (OP-21, OP-22).
#[tokio::test]
async fn t_op_07_cancellation() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let sb = a.ready(None).await;

    // A running execution: it ends CANCELLED by the caller, and the sandbox is usable again.
    rig.world.hold("exec");
    let env = a.envelope("exec.run", exec_params(&sb, &["/bin/sleep", "600"]));
    let exec_id = env.operation_id.clone().unwrap();
    let running = {
        let a = a.clone();
        tokio::spawn(async move { a.send(env).await })
    };
    eventually("the command reaches the guest", || rig.world.waiting("exec") == 1).await;
    let cancel = a.done("operation.cancel", json!({"operation_id": exec_id})).await;
    assert_eq!(cancel.operation_type, OperationType::OperationCancel);
    assert!(
        matches!(&cancel.result, Some(OperationResult::Host(h)) if h.note.as_deref().is_some_and(|n| n.contains("Cancelled"))),
        "{:?}",
        cancel.result
    );
    let exec = running.await.unwrap().operation_view().cloned().unwrap();
    assert_eq!((exec.state, exec.cancelled_by), (OperationState::Cancelled, Some(CancelledBy::Caller)));
    assert_eq!(exec.effect, Some(Effect::MayBeApplied), "the command had started: it may have had effects");
    assert_eq!(run_of(&exec).status, RunStatus::Cancelled);
    rig.world.release("exec");
    assert_eq!(a.inspect(&sb.sandbox_id).await.state, LifecycleState::Completed);
    assert_eq!(a.exec(&sb, &["/bin/true"]).await.state, OperationState::Succeeded);

    // A terminal target: the cancel succeeds with no effect.
    let cancel_done = a.done("operation.cancel", json!({"operation_id": exec_id})).await;
    assert_eq!(a.get(&exec_id).await.state, OperationState::Cancelled, "unchanged");
    assert!(
        a.operations(json!({})).await.items.iter().any(|o| o.operation_id == cancel_done.operation_id),
        "a cancel is a recorded operation"
    );

    // A type that cannot be cancelled: it is bounded by its deadline, and containment preempts it.
    rig.world.hold("provision");
    let create = a.envelope("sandbox.create", create_params(None));
    let create_id = create.operation_id.clone().unwrap();
    let creating = {
        let a = a.clone();
        tokio::spawn(async move { a.send(create).await })
    };
    eventually("the create reaches the backend", || rig.world.waiting("provision") == 1).await;
    let before = footprint(&host);
    assert_eq!(a.refused("operation.cancel", json!({"operation_id": create_id})).await.class, FailureClass::StateConflict);
    assert_eq!(footprint(&host), before);
    rig.world.release("provision");
    assert_eq!(creating.await.unwrap().operation_view().map(|v| v.state), Some(OperationState::Succeeded));

    // An unknown id, and an operation of another scope.
    assert_eq!(a.refused("operation.cancel", json!({"operation_id": "op-does-not-exist"})).await.class, FailureClass::NotFound);
    assert_eq!(bob(&host).refused("operation.cancel", json!({"operation_id": exec_id})).await.class, FailureClass::NotFound);

    // An execution of an earlier activation: this activation did not start it and cannot cancel it;
    // the host is establishing its outcome (OP-22). Shown on a host that has not recovered yet.
    rig.world.hold("exec");
    let env = a.envelope("exec.run", exec_params(&a.inspect(&sb.sandbox_id).await, &["/bin/sleep", "600"]));
    let inherited_id = env.operation_id.clone().unwrap();
    let _abandoned = {
        let a = a.clone();
        tokio::spawn(async move { a.send(env).await })
    };
    eventually("the command reaches the guest", || rig.world.waiting("exec") == 1).await;
    let next = rig.boot();
    next.finish_starting(); // serving without having recovered: only to reach the admission rule
    let refused = a.on(&next).refused("operation.cancel", json!({"operation_id": inherited_id})).await;
    assert_eq!(refused.class, FailureClass::StateConflict, "{}", refused.message);
    // Recovery then ends it UNKNOWN, and a cancel of it succeeds with no effect.
    next.recover().await.unwrap();
    assert_eq!(a.on(&next).get(&inherited_id).await.state, OperationState::Unknown);
    a.on(&next).done("operation.cancel", json!({"operation_id": inherited_id})).await;
}

/// T-OP-08: no response reports a state that a power cut then loses. Whatever a response says is
/// already durable: the store file as it is at that instant, opened alone, says the same.
#[tokio::test]
async fn t_op_08_a_response_never_reports_a_state_that_a_power_cut_would_lose() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let store = rig.cfg.journal_path();
    let survives_power_cut = |view: &crate::api::OperationView, step: usize| {
        let copy = rig.dir.path().join(format!("after-step-{step}.wal"));
        std::fs::copy(&store, &copy).unwrap();
        let (journal, report) = Journal::open(&copy).unwrap();
        assert!(matches!(report.integrity, crate::store::Integrity::Clean), "{:?}", report.integrity);
        let on_disk = journal.read(|s| s.operations.values().find(|o| o.operation_id == view.operation_id).cloned()).unwrap();
        let on_disk = on_disk.unwrap_or_else(|| panic!("{}: the operation the response reported is not on disk", view.operation_type));
        assert_eq!((on_disk.state, on_disk.revision), (view.state, view.revision), "{}", view.operation_type);
        if let Some(OperationResult::Sandbox(sb)) = &view.result {
            let g = journal.read(|s| s.generations.get(&(sb.sandbox_id.clone(), sb.generation)).cloned()).unwrap().unwrap();
            assert_eq!(g.state, sb.state, "{}: the sandbox state in the response is on disk", view.operation_type);
        }
    };

    let created = a.op("sandbox.create", create_params(None)).await;
    survives_power_cut(&created, 1);
    let sb = sandbox_of(&created);
    let started = a.op("sandbox.start", target(&sb)).await;
    survives_power_cut(&started, 2);
    let ran = a.exec(&sb, &["/bin/true"]).await;
    survives_power_cut(&ran, 3);
    let snapped = a.op("snapshot.create", target(&sb)).await;
    survives_power_cut(&snapped, 4);
    let restored = a.op("snapshot.restore", json!({"snapshot": snapshot_of(&snapped).snapshot, "target": {"kind": "existing", "sandbox_id": sb.sandbox_id, "expected_generation": sb.generation}})).await;
    survives_power_cut(&restored, 5);
    let sb = sandbox_of(&restored);
    let stopped = a.op("sandbox.stop", target(&sb)).await;
    survives_power_cut(&stopped, 6);
    let destroyed = a.op("sandbox.destroy", target(&sb)).await;
    survives_power_cut(&destroyed, 7);

    // An operation still in flight when the response is sent: the non-terminal state it reports is durable too.
    rig.world.hold("provision");
    let mut env = a.envelope("sandbox.create", create_params(None));
    env.wait_ms = Some(0);
    let pending = a.send(env).await.operation_view().cloned().unwrap();
    assert!(!pending.state.is_terminal());
    survives_power_cut(&pending, 8);
    rig.world.release("provision");
    eventually("the create finishes", || host.operations_in_flight() == 0).await;
    let _: Value = json!(null);
}
