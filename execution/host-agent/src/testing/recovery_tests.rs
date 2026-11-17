//! Crash-recovery matrix (spec §22, §27.6). Each test: arm a crash point → run the flow until the
//! injected "process death" → build a **fresh** coordinator from the on-disk journal over the
//! **surviving** fake world → recover → assert the specific outcome and the global invariants.

use std::{collections::HashSet, sync::Arc};

use super::{
    fake_backend::Fail,
    fault::FaultPoint,
    rig::{Rig, caller, create_params, ctx, ready, sandbox_of, snapshot_of},
};
use crate::{
    backend::VmmState,
    domain::{CommandSpec, LifecycleState, OperationStatus, SnapshotState},
    error::{AcfError, FailureClass},
    ids::{Generation, OperationId},
    lifecycle::Host,
    protocol::{ExecParams, RestoreTarget, SandboxTarget, SnapshotCreateParams, SnapshotRestoreParams},
};

fn target(v: &crate::protocol::SandboxView) -> SandboxTarget {
    SandboxTarget { sandbox_id: v.sandbox_id.clone(), expected_generation: v.generation }
}

fn exec_p(v: &crate::protocol::SandboxView) -> ExecParams {
    ExecParams {
        sandbox_id: v.sandbox_id.clone(),
        expected_generation: v.generation,
        command: CommandSpec { argv: vec!["/bin/echo".into(), "x".into()], env: Default::default(), cwd: None, limits: Default::default() },
    }
}

fn snap_p(v: &crate::protocol::SandboxView, n: &str) -> SnapshotCreateParams {
    SnapshotCreateParams { sandbox_id: v.sandbox_id.clone(), expected_generation: v.generation, name: Some(n.into()) }
}

/// Simulated process death: the coordinator (and every in-memory structure) is gone.
fn die(h: Arc<Host>) {
    drop(h);
}

fn assert_crashed<T: std::fmt::Debug>(r: Result<T, AcfError>) {
    match r {
        Err(e) if e.is_simulated_crash() => {}
        other => panic!("expected an injected crash, got {other:?}"),
    }
}

/// Global invariants that must hold after *any* recovery (spec §22.2).
fn check_invariants(h: &Host, r: &Rig) {
    h.journal
        .read(|s| {
            // 1. nothing is left half-resolved
            let open: Vec<_> =
                s.operations.values().filter(|o| !o.is_terminal()).map(|o| (o.operation_id.to_string(), o.operation_type)).collect();
            assert!(open.is_empty(), "unresolved operations after recovery: {open:?}");
            // 2. generation numbers: monotonic high-water mark, `current` never ahead of it
            for sb in s.sandboxes.values() {
                assert!(sb.current <= sb.last_generation, "{sb:?}");
                assert!(s.generations.keys().filter(|(id, _)| *id == sb.sandbox_id).all(|(_, g)| *g <= sb.last_generation));
            }
            // 3. every running VMM belongs to a live generation (no leaked VMMs)
            let live_jails: HashSet<String> = s.live_generations().map(|g| format!("{}-g{}", g.sandbox_id, g.generation)).collect();
            for jail in r.world.jail_ids() {
                assert!(live_jails.contains(&jail), "VMM {jail} is running but no live generation owns it");
            }
            // 4. destroyed generations leave neither a VMM nor a directory behind
            for g in s.generations.values().filter(|g| g.state == LifecycleState::Destroyed) {
                assert!(
                    !h.layout.generation_path(&g.sandbox_id, g.generation).exists(),
                    "destroyed {}@{} still has a directory",
                    g.sandbox_id,
                    g.generation
                );
            }
            // 5. every directory on disk is accounted for by a journal record (or quarantined)
            let sbx_root = h.layout.root().join("sandboxes");
            if let Ok(rd) = std::fs::read_dir(&sbx_root) {
                for sbx in rd.flatten() {
                    for gd in std::fs::read_dir(sbx.path()).into_iter().flatten().flatten() {
                        let (Ok(id), Ok(n)) = (
                            crate::ids::SandboxId::parse(&sbx.file_name().to_string_lossy()),
                            gd.file_name().to_string_lossy().parse::<u64>(),
                        ) else {
                            continue;
                        };
                        let known = s.generations.contains_key(&(id.clone(), Generation(n)));
                        let quarantined = s.quarantines.iter().any(|q| q.resource_id == id.as_str() && q.generation == Some(Generation(n)));
                        assert!(known || quarantined, "orphan directory {id}/{n} is neither journaled nor quarantined");
                    }
                }
            }
        })
        .unwrap();
}

/// Recover, check invariants, and require the second pass to be a no-op (idempotency).
async fn recover_checked(r: &Rig) -> (Arc<Host>, crate::recovery::RecoveryReport) {
    let h = r.host();
    let rep = h.recover().await.unwrap();
    check_invariants(&h, r);
    let again = h.recover().await.unwrap();
    assert_eq!(again.examined, 0, "a second recovery pass must find nothing to do: {again:?}");
    assert_eq!(again.quarantined + again.unknown, 0);
    (h, rep)
}

fn latest_op(h: &Host, ty: crate::domain::OperationType) -> crate::operation::OperationRecord {
    h.journal
        .read(|s| {
            s.operations
                .values()
                .filter(|o| o.operation_type == ty)
                .max_by(|a, b| a.created_wall.cmp(&b.created_wall).then_with(|| a.operation_id.cmp(&b.operation_id)))
                .cloned()
        })
        .unwrap()
        .unwrap()
}

// ================================================================== create

#[tokio::test]
async fn create_crashes_leave_nothing_behind_and_free_their_reservation() {
    for (point, step) in [
        (FaultPoint::AfterJournalBeforeMutation, "create"),
        (FaultPoint::BeforeBackendStep, "provision"),
        (FaultPoint::AfterBackendMutationBeforeCommit, "provision"),
    ] {
        let r = Rig::new();
        let h = r.host();
        h.faults.arm(point, step);
        assert_crashed(h.sandbox_create(&ctx(&h), create_params(None)).await);
        die(h);
        let (h, rep) = recover_checked(&r).await;
        assert_eq!((rep.examined, rep.failed), (1, 1), "{point:?}/{step}: {rep:?}");
        let op = latest_op(&h, crate::domain::OperationType::SandboxCreate);
        assert_eq!(op.status, OperationStatus::Failed, "{point:?}/{step}");
        assert!(h.sandbox_list().unwrap().is_empty());
        assert_eq!(r.world.vm_count(), 0);
        for _ in 0..4 {
            h.sandbox_create(&ctx(&h), create_params(None)).await.unwrap(); // reservation released: all 4 slots free again
        }
    }
}

#[tokio::test]
async fn a_crash_before_the_journal_write_leaves_no_trace_and_the_id_stays_usable() {
    let r = Rig::new();
    let h = r.host();
    let op_id = OperationId::parse("op-before-journal-1").unwrap();
    h.faults.arm(FaultPoint::BeforeJournalWrite, "*");
    assert_crashed(h.sandbox_create(&h.ctx(caller(), Some(op_id.clone()), false), create_params(Some("s"))).await);
    die(h);
    let (h, rep) = recover_checked(&r).await;
    assert_eq!(rep.examined, 0, "nothing was ever recorded, so there is nothing to recover: {rep:?}");
    assert_eq!(h.operation_get(&op_id).unwrap_err().class, FailureClass::NotFound, "the request never became an operation");
    assert!(h.sandbox_list().unwrap().is_empty());
    assert_eq!(r.world.vm_count(), 0);
    // The id was never consumed: submitting it now is a fresh, successful request.
    let done = h.sandbox_create(&h.ctx(caller(), Some(op_id), false), create_params(Some("s"))).await.unwrap();
    assert_eq!(done.status, OperationStatus::Succeeded);
}

#[tokio::test]
async fn a_crash_after_the_result_was_persisted_loses_only_the_response() {
    let r = Rig::new();
    let h = r.host();
    let op_id = OperationId::parse("op-after-commit-1").unwrap();
    h.faults.arm(FaultPoint::AfterTerminalCommitBeforeResponse, "*");
    assert_crashed(h.sandbox_create(&h.ctx(caller(), Some(op_id.clone()), false), create_params(Some("s"))).await);
    die(h);
    let (h, _) = recover_checked(&r).await;
    let env = h.operation_get(&op_id).unwrap();
    assert_eq!(env.status, OperationStatus::Succeeded, "the terminal record was durable before the crash");
    assert!(matches!(env.result, Some(crate::protocol::ResponseBody::Sandbox(v)) if v.name.as_deref() == Some("s")));
    assert_eq!(h.sandbox_list().unwrap().len(), 1, "the sandbox exists exactly once");
    // Retrying the identical request returns the original result and creates nothing new.
    let again = h.sandbox_create(&h.ctx(caller(), Some(op_id), true), create_params(Some("s"))).await.unwrap();
    assert_eq!(again.status, OperationStatus::Succeeded);
    assert_eq!(h.sandbox_list().unwrap().len(), 1);
    assert_eq!(r.world.vm_count(), 0, "create provisions but never launches a VMM, so the replay leaked none");
}

// ================================================================== start

#[tokio::test]
async fn a_start_that_never_launched_leaves_the_sandbox_startable() {
    for (point, step) in [(FaultPoint::AfterJournalBeforeMutation, "start"), (FaultPoint::BeforeBackendStep, "launch")] {
        let r = Rig::new();
        let h = r.host();
        let c = sandbox_of(&h.sandbox_create(&ctx(&h), create_params(Some("s"))).await.unwrap());
        h.faults.arm(point, step);
        assert_crashed(h.sandbox_start(&ctx(&h), target(&c)).await);
        die(h);
        let (h, _) = recover_checked(&r).await;
        assert_eq!(latest_op(&h, crate::domain::OperationType::SandboxStart).status, OperationStatus::Failed);
        assert_eq!(h.sandbox_inspect("s").unwrap().state, LifecycleState::Provisioning, "resources intact");
        let again = h.sandbox_start(&ctx(&h), target(&c)).await.unwrap();
        assert_eq!(again.status, OperationStatus::Succeeded, "a fresh start succeeds: {:?}", again.failure);
    }
}

#[tokio::test]
async fn a_vmm_launched_but_never_recorded_ready_is_stopped_not_trusted() {
    let r = Rig::new();
    let h = r.host();
    let c = sandbox_of(&h.sandbox_create(&ctx(&h), create_params(Some("s"))).await.unwrap());
    h.faults.arm(FaultPoint::AfterBackendMutationBeforeCommit, "launch");
    assert_crashed(h.sandbox_start(&ctx(&h), target(&c)).await);
    assert_eq!(r.world.vm_count(), 1, "the VMM survived the crash");
    die(h);
    let (h, _) = recover_checked(&r).await;
    assert_eq!(r.world.vm_count(), 0, "a VMM whose boot cannot be proven must not keep running");
    assert_eq!(h.sandbox_inspect("s").unwrap().state, LifecycleState::Failed);
    assert_eq!(latest_op(&h, crate::domain::OperationType::SandboxStart).status, OperationStatus::Failed);
}

// ================================================================== exec

#[tokio::test]
async fn an_interrupted_run_is_unknown_and_its_sandbox_is_stopped_never_retried() {
    for (point, step) in [
        (FaultPoint::AfterJournalBeforeMutation, "exec"),
        (FaultPoint::BeforeBackendStep, "exec"),
        (FaultPoint::AfterBackendMutationBeforeCommit, "exec"),
    ] {
        let r = Rig::new();
        let h = r.host();
        let v = ready(&h, Some("s")).await;
        r.world.clear_calls();
        h.faults.arm(point, step);
        assert_crashed(h.exec(&ctx(&h), exec_p(&v)).await);
        die(h);
        let (h, rep) = recover_checked(&r).await;
        assert_eq!(rep.unknown, 1, "{point:?}/{step}: {rep:?}");
        let op = latest_op(&h, crate::domain::OperationType::Exec);
        assert_eq!(
            op.status,
            OperationStatus::Unknown,
            "{point:?}/{step}: the command may have run, so it is neither FAILED nor SUCCEEDED"
        );
        assert_eq!(h.sandbox_inspect("s").unwrap().state, LifecycleState::Failed);
        assert_eq!(r.world.vm_count(), 0);
        assert_eq!(
            r.world.calls().iter().filter(|c| *c == "exec").count(),
            usize::from(step == "exec" && point == FaultPoint::AfterBackendMutationBeforeCommit),
            "recovery must never re-run the command"
        );
    }
}

// ================================================================== stop / destroy

#[tokio::test]
async fn interrupted_stop_and_destroy_are_completed_by_recovery() {
    for (point, step) in [(FaultPoint::BeforeBackendStep, "stop_vmm"), (FaultPoint::AfterBackendMutationBeforeCommit, "stop_vmm")] {
        let r = Rig::new();
        let h = r.host();
        let v = ready(&h, Some("s")).await;
        h.faults.arm(point, step);
        assert_crashed(h.sandbox_stop(&ctx(&h), target(&v)).await);
        die(h);
        let (h, _) = recover_checked(&r).await;
        assert_eq!(latest_op(&h, crate::domain::OperationType::SandboxStop).status, OperationStatus::Succeeded, "{point:?}");
        assert_eq!(h.sandbox_inspect("s").unwrap().state, LifecycleState::Stopped);
        assert_eq!(r.world.vm_count(), 0);
    }
    for (point, step) in [
        (FaultPoint::AfterJournalBeforeMutation, "destroy"),
        (FaultPoint::BeforeBackendStep, "retire"),
        (FaultPoint::AfterBackendMutationBeforeCommit, "retire"),
    ] {
        let r = Rig::new();
        let h = r.host();
        let v = ready(&h, Some("s")).await;
        h.faults.arm(point, step);
        assert_crashed(h.sandbox_destroy(&ctx(&h), target(&v)).await);
        die(h);
        let (h, _) = recover_checked(&r).await;
        assert_eq!(latest_op(&h, crate::domain::OperationType::SandboxDestroy).status, OperationStatus::Succeeded, "{point:?}/{step}");
        assert!(h.sandbox_list().unwrap().is_empty());
        assert_eq!(r.world.vm_count(), 0);
        assert!(!h.layout.generation_path(&v.sandbox_id, v.generation).exists());
    }
}

// ================================================================== snapshots

#[tokio::test]
async fn an_interrupted_snapshot_returns_the_guest_to_service_and_releases_its_quota() {
    for (point, step) in [(FaultPoint::BeforeBackendStep, "snapshot"), (FaultPoint::AfterBackendMutationBeforeCommit, "snapshot")] {
        let r = Rig::new();
        let h = r.host();
        let v = ready(&h, Some("s")).await;
        h.faults.arm(point, step);
        assert_crashed(h.snapshot_create(&ctx(&h), snap_p(&v, "b")).await);
        // the crash left the guest frozen mid-snapshot
        r.world.set_phase(&format!("{}-g{}", v.sandbox_id, v.generation), VmmState::Paused);
        die(h);
        let (h, _) = recover_checked(&r).await;
        assert_eq!(latest_op(&h, crate::domain::OperationType::SnapshotCreate).status, OperationStatus::Failed, "{point:?}");
        assert_eq!(
            h.sandbox_inspect("s").unwrap().state,
            LifecycleState::Ready,
            "the frozen guest was resumed and returned to its prior state"
        );
        assert!(h.snapshot_list().unwrap().is_empty(), "no half-written snapshot is ever adopted");
        for i in 0..3 {
            assert_eq!(
                h.snapshot_create(&ctx(&h), snap_p(&h.sandbox_inspect("s").unwrap(), &format!("n{i}"))).await.unwrap().status,
                OperationStatus::Succeeded,
                "quota was released"
            );
        }
    }
}

#[tokio::test]
async fn a_restore_that_died_before_the_switch_keeps_the_old_generation_and_cleans_the_new() {
    for (point, step) in [(FaultPoint::BeforeBackendStep, "restore"), (FaultPoint::AfterBackendMutationBeforeCommit, "restore")] {
        let r = Rig::new();
        let h = r.host();
        let v = ready(&h, Some("s")).await;
        let sv = snapshot_of(&h.snapshot_create(&ctx(&h), snap_p(&v, "b")).await.unwrap());
        h.faults.arm(point, step);
        let p = SnapshotRestoreParams {
            snapshot: sv.snapshot.clone(),
            target: RestoreTarget::Existing { sandbox_id: v.sandbox_id.clone(), expected_generation: v.generation },
        };
        assert_crashed(h.snapshot_restore(&ctx(&h), p).await);
        die(h);
        let (h, _) = recover_checked(&r).await;
        let cur = h.sandbox_inspect("s").unwrap();
        assert_eq!((cur.generation, cur.state), (v.generation, LifecycleState::Ready), "{point:?}: the original is untouched");
        assert_eq!(r.world.vm_count(), 1, "{point:?}: the half-restored VMM was stopped");
        assert_eq!(latest_op(&h, crate::domain::OperationType::SnapshotRestore).status, OperationStatus::Failed);
        assert_eq!(h.exec(&ctx(&h), exec_p(&cur)).await.unwrap().status, OperationStatus::Succeeded);
    }
}

#[tokio::test]
async fn a_restore_that_died_after_the_switch_is_completed_and_the_old_generation_retired() {
    let r = Rig::new();
    let h = r.host();
    let v = ready(&h, Some("s")).await;
    let sv = snapshot_of(&h.snapshot_create(&ctx(&h), snap_p(&v, "b")).await.unwrap());
    h.faults.arm(FaultPoint::AfterBackendMutationBeforeCommit, "restore_switch");
    let p = SnapshotRestoreParams {
        snapshot: sv.snapshot.clone(),
        target: RestoreTarget::Existing { sandbox_id: v.sandbox_id.clone(), expected_generation: v.generation },
    };
    assert_crashed(h.snapshot_restore(&ctx(&h), p).await);
    assert_eq!(r.world.vm_count(), 2, "both generations are alive at the crash instant");
    die(h);
    let (h, _) = recover_checked(&r).await;
    let op = latest_op(&h, crate::domain::OperationType::SnapshotRestore);
    assert_eq!(op.status, OperationStatus::Succeeded, "the new generation was already current");
    let cur = h.sandbox_inspect("s").unwrap();
    assert_eq!((cur.generation, cur.state), (Generation(2), LifecycleState::Ready));
    assert_eq!(r.world.vm_count(), 1);
    assert!(!h.layout.generation_path(&v.sandbox_id, Generation(1)).exists(), "the superseded generation was retired");
    assert!(sandbox_of(&op).notes.iter().any(|n| n.contains("recovery")));
}

#[tokio::test]
async fn an_interrupted_snapshot_delete_is_completed() {
    let r = Rig::new();
    let h = r.host();
    let v = ready(&h, Some("s")).await;
    let sv = snapshot_of(&h.snapshot_create(&ctx(&h), snap_p(&v, "b")).await.unwrap());
    h.faults.arm(FaultPoint::AfterJournalBeforeMutation, "snapshot_delete");
    assert_crashed(h.snapshot_delete(&ctx(&h), sv.snapshot.clone()).await);
    die(h);
    let (h, _) = recover_checked(&r).await;
    assert!(h.snapshot_list().unwrap().is_empty());
    assert!(!h.layout.snapshot_path(&sv.snapshot.snapshot_id, sv.snapshot.snapshot_generation).exists());
}

// ================================================================== lost response / adoption

#[tokio::test]
async fn a_lost_response_is_resolved_by_operation_id_even_across_a_restart() {
    let r = Rig::new();
    let h = r.host();
    let op_id = OperationId::parse("op-lost-response-1").unwrap();
    let c = h.ctx(caller(), Some(op_id.clone()), false);
    let done = h.sandbox_create(&c, create_params(Some("s"))).await.unwrap();
    assert_eq!(done.status, OperationStatus::Succeeded);
    die(h); // the response never reached the client, and then the host restarted too
    let (h2, _) = recover_checked(&r).await;
    let env = h2.operation_get(&op_id).unwrap();
    assert_eq!(env.status, OperationStatus::Succeeded);
    assert!(matches!(env.result, Some(crate::protocol::ResponseBody::Sandbox(v)) if v.name.as_deref() == Some("s")));
    // and re-submitting the identical request is idempotent
    let again = h2.sandbox_create(&h2.ctx(caller(), Some(op_id), true), create_params(Some("s"))).await.unwrap();
    assert_eq!(h2.sandbox_list().unwrap().len(), 1);
    assert_eq!(again.status, OperationStatus::Succeeded);
}

#[tokio::test]
async fn a_healthy_survivor_is_adopted_and_remains_usable_after_a_restart() {
    let r = Rig::new();
    let h = r.host();
    let v = ready(&h, Some("s")).await;
    die(h);
    let (h, rep) = recover_checked(&r).await;
    assert_eq!((rep.adopted, rep.examined), (1, 0), "{rep:?}");
    let cur = h.sandbox_inspect("s").unwrap();
    assert_eq!((cur.state, cur.process.is_some()), (LifecycleState::Ready, true));
    assert_eq!(h.exec(&ctx(&h), exec_p(&v)).await.unwrap().status, OperationStatus::Succeeded);
}

#[tokio::test]
async fn a_vmm_that_vanished_while_the_host_was_down_is_reported_not_assumed_alive() {
    let r = Rig::new();
    let h = r.host();
    let v = ready(&h, Some("s")).await;
    die(h);
    r.world.set_phase(&format!("{}-g{}", v.sandbox_id, v.generation), VmmState::Absent);
    let (h, _) = recover_checked(&r).await;
    let cur = h.sandbox_inspect("s").unwrap();
    assert_eq!(cur.state, LifecycleState::Failed);
    assert!(cur.failure.unwrap().message.contains("disappeared"));
    assert_eq!(h.exec(&ctx(&h), exec_p(&v)).await.unwrap_err().class, FailureClass::StateConflict);
}

#[tokio::test]
async fn recovery_is_unaffected_by_a_host_reboot_voiding_monotonic_deadlines() {
    let r = Rig::new();
    let h = r.host();
    let c = sandbox_of(&h.sandbox_create(&ctx(&h), create_params(Some("s"))).await.unwrap());
    h.faults.arm(FaultPoint::AfterJournalBeforeMutation, "start");
    assert_crashed(h.sandbox_start(&ctx(&h), target(&c)).await);
    die(h);
    r.clock.reboot();
    let (h, rep) = recover_checked(&r).await;
    assert_eq!(rep.examined, 1);
    assert_eq!(latest_op(&h, crate::domain::OperationType::SandboxStart).status, OperationStatus::Failed);
}

// ================================================================== ownership / quarantine / bounds

#[tokio::test]
async fn a_forged_ownership_marker_is_quarantined_and_nothing_is_deleted() {
    let r = Rig::new();
    let h = r.host();
    h.faults.arm(FaultPoint::BeforeBackendStep, "provision");
    assert_crashed(h.sandbox_create(&ctx(&h), create_params(None)).await);
    let (sbx, gno) = h.journal.read(|s| s.generations.keys().next().cloned()).unwrap().unwrap();
    die(h);
    let dir = r.layout.generation_path(&sbx, gno);
    std::fs::write(dir.join("jail/precious"), b"do not delete").unwrap();
    let mut m: serde_json::Value = serde_json::from_slice(&std::fs::read(dir.join("OWNER.json")).unwrap()).unwrap();
    m["nonce"] = serde_json::json!("not-the-journals-nonce");
    std::fs::write(dir.join("OWNER.json"), serde_json::to_vec(&m).unwrap()).unwrap();

    let (h, rep) = recover_checked(&r).await;
    assert_eq!(rep.quarantined, 1, "{rep:?}");
    assert!(dir.join("jail/precious").exists(), "RT-030: ownership could not be proven, so NOTHING was deleted");
    let op = latest_op(&h, crate::domain::OperationType::SandboxCreate);
    assert_eq!(op.failure.as_ref().map(|f| f.class), Some(FailureClass::RecoveryQuarantined));
    assert!(h.journal.read(|s| s.quarantines.iter().any(|q| q.resource_id == sbx.as_str())).unwrap());
    let g = h.journal.read(|s| s.generations.get(&(sbx.clone(), gno)).cloned()).unwrap().unwrap();
    assert!(g.quarantined.is_some() && g.holds_reservation(), "quarantined resources keep their reservation");
    // an explicit destroy must refuse too
    let e = h.sandbox_destroy(&ctx(&h), SandboxTarget { sandbox_id: sbx, expected_generation: gno }).await;
    assert!(e.is_err() || e.unwrap().status == OperationStatus::Failed);
    assert!(dir.join("jail/precious").exists());
}

#[tokio::test]
async fn a_symlinked_generation_directory_is_never_followed_by_recovery() {
    let r = Rig::new();
    let h = r.host();
    h.faults.arm(FaultPoint::BeforeBackendStep, "provision");
    assert_crashed(h.sandbox_create(&ctx(&h), create_params(None)).await);
    let (sbx, gno) = h.journal.read(|s| s.generations.keys().next().cloned()).unwrap().unwrap();
    die(h);
    let victim = r.dir.path().join("victim");
    std::fs::create_dir(&victim).unwrap();
    std::fs::write(victim.join("precious"), b"keep").unwrap();
    let dir = r.layout.generation_path(&sbx, gno);
    std::fs::remove_dir_all(&dir).unwrap();
    std::os::unix::fs::symlink(&victim, &dir).unwrap();
    let (_h, rep) = recover_checked(&r).await;
    assert_eq!(rep.quarantined, 1);
    assert!(victim.join("precious").exists(), "the symlink target must survive");
}

#[tokio::test]
async fn recovery_is_bounded_and_quarantines_instead_of_looping() {
    let r = Rig::new();
    let h = r.host();
    let v = ready(&h, Some("s")).await;
    h.faults.arm(FaultPoint::BeforeBackendStep, "retire");
    assert_crashed(h.sandbox_destroy(&ctx(&h), target(&v)).await);
    die(h);
    let max = r.cfg.recovery.max_attempts;
    // teardown keeps failing: each restart gets one bounded attempt, then the record is quarantined
    for attempt in 1..=max {
        let h = r.host();
        r.world.fail_next(
            "teardown",
            Fail::Before(AcfError::new(FailureClass::BackendUnavailable, "cannot clean").with_possible_side_effect()),
        );
        let rep = h.recover().await.unwrap();
        assert_eq!((rep.pending, rep.quarantined), (1, 0), "attempt {attempt}: {rep:?}");
        die(h);
    }
    let h = r.host();
    let rep = h.recover().await.unwrap();
    assert_eq!(rep.quarantined, 1, "attempt {}: bound exceeded ⇒ quarantine, not another retry: {rep:?}", max + 1);
    let op = latest_op(&h, crate::domain::OperationType::SandboxDestroy);
    assert_eq!((op.status, op.failure.map(|f| f.class)), (OperationStatus::Failed, Some(FailureClass::RecoveryQuarantined)));
    let rec = h.journal.read(|s| s.recoveries.values().next().cloned()).unwrap().unwrap();
    assert_eq!(rec.attempt_count, max + 1, "the attempt count survived every restart");
}

#[tokio::test]
async fn orphan_directories_are_flagged_once_and_never_deleted() {
    let r = Rig::new();
    let stray = r.layout.generation_path(&crate::ids::SandboxId::generate(), Generation(1));
    std::fs::create_dir_all(&stray).unwrap();
    std::fs::write(stray.join("mystery"), b"?").unwrap();
    let h = r.host();
    let rep = h.recover().await.unwrap();
    assert_eq!(rep.orphans, 1);
    assert!(stray.join("mystery").exists());
    let again = h.recover().await.unwrap();
    assert_eq!(again.orphans, 1, "still reported");
    assert_eq!(h.journal.read(|s| s.quarantines.len()).unwrap(), 1, "…but quarantined exactly once");
}

#[tokio::test]
async fn a_corrupt_journal_puts_the_host_in_read_only_quarantine_and_recovery_mutates_nothing() {
    let r = Rig::new();
    let h = r.host();
    ready(&h, Some("a")).await;
    ready(&h, Some("b")).await;
    die(h);
    let p = r.cfg.journal_path();
    let mut bytes = std::fs::read(&p).unwrap();
    let nl = bytes.iter().position(|b| *b == b'\n').unwrap();
    bytes[nl + 25] ^= 0x7f; // corrupt the 2nd record, valid ones follow
    std::fs::write(&p, &bytes).unwrap();
    let h = r.host();
    assert_eq!(h.host_info().unwrap().mode, "read_only_quarantine");
    let rep = h.recover().await.unwrap();
    assert!(rep.notes.iter().any(|n| n.contains("quarantined")), "{rep:?}");
    let e = h.sandbox_create(&ctx(&h), create_params(None)).await.unwrap_err();
    assert_eq!(e.class, FailureClass::RecoveryQuarantined, "{e}");
    assert!(h.sandbox_list().is_ok(), "reads still work");
    let _ = SnapshotState::Ready;
}
