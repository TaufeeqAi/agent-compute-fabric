//! T-CONC: concurrency (contract §15). Exclusivity is decided from committed state inside BEGIN, so
//! these tests hold one operation in flight at the backend and issue the next.

use serde_json::json;

use crate::{
    api::OperationResult,
    domain::{CancelledBy, Cleanup, Effect, LifecycleState, OperationState},
    error::FailureClass,
    testing::rig::{Rig, alice, calls, create_params, eventually, exec_params, footprint, sandbox_of, snapshot_of, target},
};

/// T-CONC-01: exec‖exec, exec‖snapshot, snapshot‖restore on one sandbox → one is admitted; the
/// others are `STATE_CONFLICT` and leave no record. Nothing is queued (CC-1).
#[tokio::test]
async fn t_conc_01_one_granting_operation_per_sandbox_and_nothing_is_queued() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let sb = a.ready(None).await;
    let other = a.ready(None).await;
    let snap = snapshot_of(&a.done("snapshot.create", target(&other)).await);
    let restore_in_place = json!({"snapshot": snap.snapshot, "target": {"kind": "existing", "sandbox_id": sb.sandbox_id, "expected_generation": sb.generation}});

    // An execution is in flight...
    rig.world.hold("exec");
    let running = {
        let (a, sb) = (a.clone(), sb.clone());
        tokio::spawn(async move { a.exec(&sb, &["/bin/sleep", "600"]).await })
    };
    eventually("the command reaches the guest", || rig.world.waiting("exec") == 1).await;
    let before = footprint(&host);
    for (method, params) in
        [("exec.run", exec_params(&sb, &["/bin/true"])), ("snapshot.create", target(&sb)), ("snapshot.restore", restore_in_place.clone())]
    {
        let r = a.refused(method, params).await;
        assert_eq!(r.class, FailureClass::StateConflict, "{method} beside an execution: {}", r.message);
        assert_eq!(footprint(&host), before, "{method}: no record, no reservation");
    }
    // ...while another sandbox is not affected at all (CC-6).
    a.done("snapshot.create", target(&other)).await;
    a.done("sandbox.stop", target(&other)).await;
    rig.world.release("exec");
    assert_eq!(running.await.unwrap().state, OperationState::Succeeded);

    // A snapshot is in flight: an execution and a restore in place are refused.
    rig.world.hold("snapshot");
    let snapshotting = {
        let (a, sb) = (a.clone(), sb.clone());
        tokio::spawn(async move { a.op("snapshot.create", target(&sb)).await })
    };
    eventually("the capture starts", || rig.world.waiting("snapshot") == 1).await;
    let before = footprint(&host);
    for (method, params) in
        [("exec.run", exec_params(&sb, &["/bin/true"])), ("snapshot.create", target(&sb)), ("snapshot.restore", restore_in_place.clone())]
    {
        assert_eq!(a.refused(method, params).await.class, FailureClass::StateConflict, "{method} beside a snapshot");
        assert_eq!(footprint(&host), before);
    }
    rig.world.release("snapshot");
    assert_eq!(snapshotting.await.unwrap().state, OperationState::Succeeded);

    // A restore in place is in flight: nothing else is admitted on that sandbox.
    rig.world.hold("restore");
    let restoring = {
        let (a, p) = (a.clone(), restore_in_place.clone());
        tokio::spawn(async move { a.op("snapshot.restore", p).await })
    };
    eventually("the restore reaches the backend", || rig.world.waiting("restore") == 1).await;
    let before = footprint(&host);
    for (method, params) in
        [("exec.run", exec_params(&sb, &["/bin/true"])), ("snapshot.create", target(&sb)), ("snapshot.restore", restore_in_place.clone())]
    {
        assert_eq!(a.refused(method, params).await.class, FailureClass::StateConflict, "{method} beside a restore");
        assert_eq!(footprint(&host), before);
    }
    // The snapshot is referenced by the restore: it cannot be deleted now (CC-9).
    assert_eq!(a.refused("snapshot.delete", json!({"snapshot": snap.snapshot})).await.class, FailureClass::StateConflict);
    rig.world.release("restore");
    assert_eq!(restoring.await.unwrap().state, OperationState::Succeeded);
    assert_eq!(calls(&rig.world, "exec"), 1, "only the one admitted execution ever reached a guest");
}

/// T-CONC-02: a stale generation or `if_revision` → `REVISION_CONFLICT`, with no effect (CC-2).
#[tokio::test]
async fn t_conc_02_a_stale_generation_or_revision_is_a_revision_conflict_with_no_effect() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let sb = a.ready(None).await;
    let seen = a.inspect(&sb.sandbox_id).await;

    // Someone else changes the sandbox after it was read.
    assert_eq!(a.exec(&seen, &["/bin/true"]).await.state, OperationState::Succeeded);
    let now = a.inspect(&sb.sandbox_id).await;
    assert!(now.revision > seen.revision);

    // `if_revision` from the earlier read is refused, for granting and for containment alike.
    let before = (footprint(&host), calls(&rig.world, "exec"), calls(&rig.world, "stop"));
    let with_rev = |rev: u64| json!({"sandbox_id": sb.sandbox_id, "expected_generation": sb.generation, "if_revision": rev});
    let mut exec = exec_params(&seen, &["/bin/true"]);
    exec["if_revision"] = json!(seen.revision);
    assert_eq!(a.refused("exec.run", exec).await.class, FailureClass::RevisionConflict);
    assert_eq!(a.refused("sandbox.stop", with_rev(seen.revision)).await.class, FailureClass::RevisionConflict);
    assert_eq!(a.refused("sandbox.destroy", with_rev(seen.revision)).await.class, FailureClass::RevisionConflict);
    assert_eq!((footprint(&host), calls(&rig.world, "exec"), calls(&rig.world, "stop")), before, "no effect");
    assert_eq!(a.inspect(&sb.sandbox_id).await.state, LifecycleState::Completed);
    // With the current revision it is accepted.
    assert_eq!(a.op("sandbox.stop", with_rev(now.revision)).await.state, OperationState::Succeeded);

    // A restore in place makes a new generation; a token for the old one is stale from then on.
    let sb = a.ready(None).await;
    let snap = snapshot_of(&a.done("snapshot.create", target(&sb)).await);
    let restored = sandbox_of(&a.done("snapshot.restore", json!({"snapshot": snap.snapshot, "target": {"kind": "existing", "sandbox_id": sb.sandbox_id, "expected_generation": sb.generation}})).await);
    assert_eq!(restored.generation, sb.generation.next());
    for method in ["sandbox.stop", "sandbox.destroy", "snapshot.create"] {
        assert_eq!(a.refused(method, target(&sb)).await.class, FailureClass::RevisionConflict, "{method} with the old generation");
    }
    assert_eq!(a.refused("exec.run", exec_params(&sb, &["/bin/true"])).await.class, FailureClass::RevisionConflict);
    assert_eq!(a.inspect(&sb.sandbox_id).await.state, LifecycleState::Ready, "the new generation is untouched");
}

/// T-CONC-03 (L2 analogue of the L4 entry): stop and destroy during an execution whose guest has
/// stopped responding complete without waiting for it (CC-3). The execution ends `CANCELLED`,
/// superseded, and never claims that it did not run.
#[tokio::test]
async fn t_conc_03_containment_preempts_an_execution_that_never_returns() {
    for containment in ["sandbox.stop", "sandbox.destroy"] {
        let rig = Rig::new();
        let host = rig.serving().await;
        let a = alice(&host);
        let sb = a.ready(None).await;
        rig.world.hold("exec"); // the guest never answers
        let env = a.envelope("exec.run", exec_params(&sb, &["/bin/sleep", "infinity"]));
        let exec_id = env.operation_id.clone().unwrap();
        let hung = {
            let a = a.clone();
            tokio::spawn(async move { a.send(env).await })
        };
        eventually("the command reaches the guest", || rig.world.waiting("exec") == 1).await;

        let started = std::time::Instant::now();
        let op = a.done(containment, target(&sb)).await;
        assert!(started.elapsed() < std::time::Duration::from_secs(2), "{containment} waited for the guest");
        assert_eq!(rig.world.vm_count(), 0, "{containment}: the runtime is gone");
        let expected = if containment == "sandbox.stop" { LifecycleState::Stopped } else { LifecycleState::Destroyed };
        assert_eq!(sandbox_state(&op), expected);

        // The request that was waiting on the execution gets its answer: the operation, as it ended.
        let answered = hung.await.unwrap().operation_view().cloned().unwrap();
        let exec = a.get(&exec_id).await;
        assert_eq!(answered.operation_id, exec.operation_id);
        assert_eq!((exec.state, exec.cancelled_by), (OperationState::Cancelled, Some(CancelledBy::Superseded)));
        assert_eq!(exec.effect, Some(Effect::MayBeApplied), "it reached the guest: it may have had effects");
        if containment == "sandbox.destroy" {
            assert_eq!(exec.cleanup, Some(Cleanup::Complete), "what it held is proven gone");
        }
        assert_eq!(rig.world.waiting("exec"), 0, "the host let go of the guest call");
        assert_eq!(host.operations_in_flight(), 0);
    }
}

fn sandbox_state(op: &crate::api::OperationView) -> LifecycleState {
    match &op.result {
        Some(OperationResult::Sandbox(v)) => v.state,
        other => panic!("{other:?}"),
    }
}

/// CC-3 for the other granting operations: a destroy during a create, a start, a snapshot and a
/// restore in place ends them, removes what they had built, and leaves nothing leased.
#[tokio::test]
async fn t_conc_03_destroy_preempts_every_kind_of_granting_operation() {
    for (held, method) in
        [("provision", "sandbox.create"), ("start", "sandbox.start"), ("snapshot", "snapshot.create"), ("restore", "snapshot.restore")]
    {
        let rig = Rig::new();
        let host = rig.serving().await;
        let a = alice(&host);
        // What each case needs before the operation under test.
        let (sb, params) = match method {
            "sandbox.create" => (None, create_params(Some("doomed"))),
            "sandbox.start" => {
                let sb = a.create(None).await;
                (Some(sb.clone()), target(&sb))
            }
            "snapshot.create" => {
                let sb = a.ready(None).await;
                (Some(sb.clone()), target(&sb))
            }
            _ => {
                let sb = a.ready(None).await;
                let snap = snapshot_of(&a.done("snapshot.create", target(&sb)).await);
                (
                    Some(sb.clone()),
                    json!({"snapshot": snap.snapshot, "target": {"kind": "existing", "sandbox_id": sb.sandbox_id, "expected_generation": sb.generation}}),
                )
            }
        };
        rig.world.hold(held);
        let env = a.envelope(method, params);
        let id = env.operation_id.clone().unwrap();
        let in_flight = {
            let a = a.clone();
            tokio::spawn(async move { a.send(env).await })
        };
        eventually("the operation reaches the backend", || rig.world.waiting(held) == 1).await;
        let sb = match sb {
            Some(sb) => a.inspect(&sb.sandbox_id).await,
            None => a.inspect(&a.get(&id).await.sandbox.unwrap().0).await, // the sandbox the create is building
        };

        a.done("sandbox.destroy", target(&sb)).await;
        let ended = in_flight.await.unwrap().operation_view().cloned().unwrap();
        assert_eq!((ended.state, ended.cancelled_by), (OperationState::Cancelled, Some(CancelledBy::Superseded)), "{method}");
        assert_eq!(
            (ended.effect, ended.cleanup),
            (Some(Effect::NotApplied), Some(Cleanup::Complete)),
            "{method}: everything it created is proven removed"
        );
        assert_eq!(rig.world.vm_count(), 0, "{method}: no runtime survives");
        assert_eq!(footprint(&host).1, 0, "{method}: nothing is leased");
        assert!(a.sandboxes(json!({})).await.items.is_empty(), "{method}");
        if method == "snapshot.create" {
            assert!(a.snapshots(json!({})).await.items.is_empty(), "the partial snapshot is not listed and holds no quota");
        }
        rig.world.release(held);
    }
}

/// T-CONC-04: destroy with capacity exhausted and under a request flood is admitted (CC-4).
#[tokio::test]
async fn t_conc_04_containment_is_admitted_with_capacity_exhausted_and_under_a_flood() {
    let rig = Rig::with(|c| c.operations.rate_limit_per_minute = 6);
    let host = rig.serving().await;
    let a = alice(&host);
    let mut sandboxes = Vec::new();
    for _ in 0..4 {
        sandboxes.push(a.create(None).await); // the host's limit is four sandboxes
    }
    // Capacity is exhausted...
    assert_eq!(a.refused("sandbox.create", create_params(None)).await.class, FailureClass::ResourceExhausted);
    // ...and so is this peer's operation budget.
    let mut flood = 0;
    while a.call("sandbox.start", target(&sandboxes[0])).await.refusal().is_none_or(|r| !r.message.contains("rate limit")) {
        flood += 1;
        assert!(flood < 20, "the rate limit never engaged");
    }
    let limited = a.refused("sandbox.start", target(&sandboxes[1])).await;
    assert_eq!(limited.class, FailureClass::ResourceExhausted);
    assert!(limited.message.contains("rate limit"), "{}", limited.message);

    // Containment is refused for neither reason.
    let stopped = a.done("sandbox.stop", target(&a.inspect(&sandboxes[0].sandbox_id).await)).await;
    assert_eq!(sandbox_state(&stopped), LifecycleState::Stopped);
    for sb in &sandboxes {
        a.done("sandbox.destroy", target(&a.inspect(&sb.sandbox_id).await)).await;
    }
    assert_eq!(footprint(&host).1, 0, "every lease is released");
    // Reads are served as well (they have their own budget).
    assert!(a.sandboxes(json!({})).await.items.is_empty());
}

/// T-CONC-05: concurrent creates for the last slot → exactly one is admitted. The capacity check
/// and the reservation are one transaction (CC-6).
#[tokio::test]
async fn t_conc_05_concurrent_creates_for_the_last_slot_admit_exactly_one() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    for _ in 0..3 {
        a.create(None).await;
    }
    // One slot is left. The first create is held at the backend, so it is still in flight when the
    // others arrive: what stops them is its reservation, which is already committed.
    rig.world.hold("provision");
    let first = {
        let a = a.clone();
        tokio::spawn(async move { a.op("sandbox.create", create_params(None)).await })
    };
    eventually("the first create reaches the backend", || rig.world.waiting("provision") == 1).await;
    let mut contenders = Vec::new();
    for _ in 0..8 {
        let a = a.clone();
        contenders.push(tokio::spawn(async move { a.call("sandbox.create", create_params(None)).await }));
    }
    for c in contenders {
        let resp = c.await.unwrap();
        assert_eq!(resp.refusal().map(|r| r.class), Some(FailureClass::ResourceExhausted), "{:?}", resp.answer);
    }
    rig.world.release("provision");
    assert_eq!(first.await.unwrap().state, OperationState::Succeeded);
    assert_eq!(a.sandboxes(json!({})).await.items.len(), 4);
    assert_eq!(calls(&rig.world, "provision"), 4, "the refused creates never reached the backend");
    let slots: std::collections::BTreeSet<u32> =
        host.journal.read(|s| s.live_generations().map(|g| g.reservation.uid_slot).collect()).unwrap();
    assert_eq!(slots.len(), 4, "four sandboxes, four distinct identifiers");
}

/// T-CONC-06: a destroyed sandbox accepts nothing; restore in place on it is refused; a generation
/// is never reused (CC-8).
#[tokio::test]
async fn t_conc_06_a_destroyed_sandbox_accepts_nothing_and_a_generation_is_never_reused() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let sb = a.ready(Some("gone")).await;
    let snap = snapshot_of(&a.done("snapshot.create", target(&sb)).await);
    a.done("sandbox.destroy", target(&sb)).await;
    let before = (footprint(&host), calls(&rig.world, "start"), calls(&rig.world, "exec"), calls(&rig.world, "restore"));

    for (method, params) in [
        ("sandbox.start", target(&sb)),
        ("exec.run", exec_params(&sb, &["/bin/true"])),
        ("snapshot.create", target(&sb)),
        (
            "snapshot.restore",
            json!({"snapshot": snap.snapshot, "target": {"kind": "existing", "sandbox_id": sb.sandbox_id, "expected_generation": sb.generation}}),
        ),
    ] {
        assert_eq!(a.refused(method, params).await.class, FailureClass::StateConflict, "{method} on a destroyed sandbox");
    }
    assert_eq!((footprint(&host), calls(&rig.world, "start"), calls(&rig.world, "exec"), calls(&rig.world, "restore")), before);
    // Stop and destroy on it succeed with no effect (§12.2): asking again for what is already so is not an error.
    let stops = calls(&rig.world, "stop");
    a.done("sandbox.stop", target(&sb)).await;
    a.done("sandbox.destroy", target(&sb)).await;
    assert_eq!(calls(&rig.world, "stop"), stops, "no effect");
    assert_eq!(a.inspect(&sb.sandbox_id).await.state, LifecycleState::Destroyed);
    // The name is free again, and the alias no longer resolves to the destroyed sandbox.
    assert_eq!(a.refused("sandbox.inspect", json!({"sandbox": "gone"})).await.class, FailureClass::NotFound);

    // Restore as new creates a different sandbox, at generation 1.
    let fresh =
        sandbox_of(&a.done("snapshot.restore", json!({"snapshot": snap.snapshot, "target": {"kind": "new", "name": "gone"}})).await);
    assert_ne!(fresh.sandbox_id, sb.sandbox_id);
    assert_eq!(fresh.generation.0, 1);

    // A generation is never reused: each restore in place allocates the next number, even after a failed one.
    rig.world.fail_next("restore", crate::testing::fake_backend::Fail::Before(crate::error::AcfError::unavailable("no")));
    let in_place =
        json!({"snapshot": snap.snapshot, "target": {"kind": "existing", "sandbox_id": fresh.sandbox_id, "expected_generation": 1}});
    assert_eq!(a.op("snapshot.restore", in_place.clone()).await.state, OperationState::Failed);
    assert_eq!(a.inspect(&fresh.sandbox_id).await.generation.0, 1, "the failed restore did not cost the sandbox (RE-6)");
    let second = sandbox_of(&a.done("snapshot.restore", in_place).await);
    assert_eq!(second.generation.0, 3, "generation 2 was allocated to the failed restore and is never handed out again");
    let generations: Vec<u64> =
        host.journal.read(|s| s.generations.keys().filter(|(id, _)| *id == fresh.sandbox_id).map(|(_, g)| g.0).collect()).unwrap();
    assert_eq!(generations, vec![1, 2, 3]);
}
