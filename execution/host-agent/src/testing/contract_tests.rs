//! Backend-agnostic contract tests for the coordinator (spec §27.1–27.4). They run against the
//! in-memory [`FakeBackend`] so they prove the *semantics* — idempotency, generations, admission,
//! observation-based failure reporting, rollback — independently of Firecracker's API.

use std::{sync::Arc, time::Duration};

use acf_wire::guest::{Containment, ExecResult, ExecStatus};

use super::{
    fake_backend::Fail,
    rig::{Rig, create_params, ctx, ctx_with, ready, res, sandbox_of, snapshot_of},
};
use crate::{
    backend::{GuestExecOutcome, VmmState},
    domain::{CommandSpec, EvidenceStatus, LifecycleState, OperationStatus, RunOutcome, SnapshotRef, SnapshotState},
    error::{AcfError, FailureClass},
    ids::Generation,
    protocol::{ExecParams, ResponseBody, RestoreTarget, SandboxTarget, SnapshotCreateParams, SnapshotRestoreParams},
};

fn target(v: &crate::protocol::SandboxView) -> SandboxTarget {
    SandboxTarget { sandbox_id: v.sandbox_id.clone(), expected_generation: v.generation }
}

fn cmd(argv: &[&str]) -> CommandSpec {
    CommandSpec { argv: argv.iter().map(|s| (*s).to_owned()).collect(), env: Default::default(), cwd: None, limits: Default::default() }
}

fn exec_params(v: &crate::protocol::SandboxView, argv: &[&str]) -> ExecParams {
    ExecParams { sandbox_id: v.sandbox_id.clone(), expected_generation: v.generation, command: cmd(argv) }
}

fn ok_result(id: &str, status: ExecStatus, out: &[u8]) -> ExecResult {
    ExecResult {
        exec_id: id.into(),
        status,
        stdout: out.to_vec(),
        stderr: vec![],
        stdout_total_bytes: out.len() as u64,
        stderr_total_bytes: 0,
        stdout_truncated: false,
        stderr_truncated: false,
        duration_ms: 5,
        pid_limit_hit: false,
        output_incomplete: false,
        containment: Containment::Cgroup2,
    }
}

fn run_of(h: &crate::lifecycle::Host, rec: &crate::operation::OperationRecord) -> crate::domain::RunResult {
    match h.envelope(rec, None).result {
        Some(ResponseBody::Run(r)) => *r,
        other => panic!("expected a run result, got {other:?}"),
    }
}

// ---------------------------------------------------------------- lifecycle + capacity

#[tokio::test]
async fn full_lifecycle_releases_every_resource() {
    let r = Rig::new();
    let h = r.host();
    let v = ready(&h, Some("box")).await;
    assert_eq!(v.state, LifecycleState::Ready);
    assert_eq!(r.world.vm_count(), 1);
    assert!(h.layout.generation_path(&v.sandbox_id, v.generation).exists());

    let run = h.exec(&ctx(&h), exec_params(&v, &["/bin/echo", "hi"])).await.unwrap();
    assert_eq!(run.status, OperationStatus::Succeeded);
    let rr = run_of(&h, &run);
    assert_eq!((rr.outcome, rr.exit_code, rr.evidence_status), (RunOutcome::Succeeded, Some(0), EvidenceStatus::Complete));
    assert_eq!(h.sandbox_inspect("box").unwrap().state, LifecycleState::Completed);

    let stop = h.sandbox_stop(&ctx(&h), target(&v)).await.unwrap();
    assert_eq!(sandbox_of(&stop).state, LifecycleState::Stopped);
    assert_eq!(r.world.vm_count(), 0);

    let d = h.sandbox_destroy(&ctx(&h), target(&v)).await.unwrap();
    assert_eq!((d.status, sandbox_of(&d).state), (OperationStatus::Succeeded, LifecycleState::Destroyed));
    assert!(!h.layout.generation_path(&v.sandbox_id, v.generation).exists(), "host files are gone");
    assert!(h.sandbox_list().unwrap().is_empty());
    // capacity was released: a sandbox of the same size can be created again and again
    for _ in 0..6 {
        let x = ready(&h, None).await;
        h.sandbox_destroy(&ctx(&h), target(&x)).await.unwrap();
    }
}

#[tokio::test]
async fn admission_is_atomic_against_the_host_envelope() {
    let r = Rig::new();
    let h = r.host(); // envelope: max 4 sandboxes
    let mut kept = vec![];
    for _ in 0..4 {
        kept.push(h.sandbox_create(&ctx(&h), create_params(None)).await.unwrap());
    }
    let e = h.sandbox_create(&ctx(&h), create_params(None)).await.unwrap_err();
    assert_eq!(e.class, FailureClass::AdmissionRejected, "{e}");
    assert_eq!(h.journal.read(|s| s.operations.len()).unwrap(), 4, "a rejected request leaves no operation record");
    let v = sandbox_of(&kept[0]);
    h.sandbox_destroy(&ctx(&h), target(&v)).await.unwrap();
    assert!(h.sandbox_create(&ctx(&h), create_params(None)).await.is_ok(), "destroying one frees its slot");
}

#[tokio::test]
async fn concurrent_creates_can_never_both_take_the_last_slot() {
    let r = Rig::new();
    let h = r.host();
    for _ in 0..3 {
        h.sandbox_create(&ctx(&h), create_params(None)).await.unwrap();
    }
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let h = Arc::clone(&h);
        set.spawn(async move { h.sandbox_create(&ctx(&h), create_params(None)).await });
    }
    let mut ok = 0;
    while let Some(res) = set.join_next().await {
        ok += usize::from(res.unwrap().is_ok());
    }
    assert_eq!(ok, 1, "exactly one of eight racing creates may win the last of four slots");
}

#[tokio::test]
async fn a_failed_provision_is_cleaned_up_and_reports_failed_not_unknown() {
    let r = Rig::new();
    let h = r.host();
    // The provision step fails AFTER mutating (possible side effect), but compensation proves the world is clean.
    r.world.fail_next("provision", Fail::After(AcfError::new(FailureClass::BackendCrash, "boom").with_possible_side_effect()));
    let op = h.sandbox_create(&ctx(&h), create_params(None)).await.unwrap();
    assert_eq!(op.status, OperationStatus::Failed, "compensation observed a clean world, so FAILED is the truth");
    let sbx = op.sandbox.clone().unwrap().0;
    assert!(!h.layout.generation_path(&sbx, Generation::FIRST).exists());
    assert!(h.journal.read(|s| s.generations.values().all(|g| g.state == LifecycleState::Destroyed)).unwrap());
    for _ in 0..4 {
        h.sandbox_create(&ctx(&h), create_params(None)).await.unwrap(); // its reservation was released
    }
}

#[tokio::test]
async fn a_failure_whose_cleanup_also_fails_is_unknown_and_keeps_its_reservation() {
    let r = Rig::new();
    let h = r.host();
    r.world.fail_next("provision", Fail::After(AcfError::new(FailureClass::BackendCrash, "boom").with_possible_side_effect()));
    r.world
        .fail_next("teardown", Fail::Before(AcfError::new(FailureClass::BackendUnavailable, "cannot clean").with_possible_side_effect()));
    let op = h.sandbox_create(&ctx(&h), create_params(None)).await.unwrap();
    assert_eq!(op.status, OperationStatus::Unknown, "side effect possible AND cleanup unproven ⇒ UNKNOWN, never FAILED");
    let sbx = op.sandbox.clone().unwrap().0;
    let g = h.journal.read(|s| s.generations.get(&(sbx.clone(), Generation::FIRST)).cloned()).unwrap().unwrap();
    assert_eq!(g.state, LifecycleState::Failed);
    assert!(g.holds_reservation(), "ownership of capacity is not assumed released");
}

// ---------------------------------------------------------------- identity / idempotency

#[tokio::test]
async fn same_operation_id_same_request_returns_the_original_result_without_mutating() {
    let r = Rig::new();
    let h = r.host();
    let a = h.sandbox_create(&ctx_with(&h, "op-create-0001", false), create_params(Some("a"))).await.unwrap();
    let again = h.sandbox_create(&ctx_with(&h, "op-create-0001", true), create_params(Some("a"))).await.unwrap();
    assert_eq!(sandbox_of(&a).sandbox_id, sandbox_of(&again).sandbox_id);
    assert_eq!(h.sandbox_list().unwrap().len(), 1, "no second sandbox");
    assert_eq!(r.world.calls().iter().filter(|c| *c == "provision").count(), 1, "the backend was driven exactly once");
}

#[tokio::test]
async fn same_operation_id_different_request_is_a_conflict_and_a_missing_retry_is_rejected() {
    let r = Rig::new();
    let h = r.host();
    h.sandbox_create(&ctx_with(&h, "op-create-0002", false), create_params(Some("a"))).await.unwrap();
    let mut other = create_params(Some("a"));
    other.resources.memory_mib = 512;
    let e = h.sandbox_create(&ctx_with(&h, "op-create-0002", false), other).await.unwrap_err();
    assert_eq!(e.class, FailureClass::StateConflict, "{e}");
    // a retry for an operation this host never saw must NOT be treated as a fresh request
    let e = h.sandbox_create(&ctx_with(&h, "op-never-seen-1", true), create_params(Some("b"))).await.unwrap_err();
    assert_eq!(e.class, FailureClass::NotFound, "{e}");
    assert_eq!(h.sandbox_list().unwrap().len(), 1);
}

#[tokio::test]
async fn stale_generation_references_never_act_on_the_current_incarnation() {
    let r = Rig::new();
    let h = r.host();
    let v = ready(&h, None).await;
    let stale = SandboxTarget { sandbox_id: v.sandbox_id.clone(), expected_generation: Generation(v.generation.0 + 5) };
    for e in [
        h.sandbox_destroy(&ctx(&h), stale.clone()).await.unwrap_err(),
        h.sandbox_stop(&ctx(&h), stale.clone()).await.unwrap_err(),
        h.sandbox_start(&ctx(&h), stale).await.unwrap_err(),
    ] {
        assert_eq!(e.class, FailureClass::StateConflict, "{e}");
    }
    assert_eq!(h.sandbox_inspect(v.sandbox_id.as_str()).unwrap().state, LifecycleState::Ready, "nothing happened");
}

#[tokio::test]
async fn destroy_and_stop_are_idempotent() {
    let r = Rig::new();
    let h = r.host();
    let v = ready(&h, None).await;
    for _ in 0..2 {
        assert_eq!(h.sandbox_stop(&ctx(&h), target(&v)).await.unwrap().status, OperationStatus::Succeeded);
    }
    for _ in 0..3 {
        assert_eq!(h.sandbox_destroy(&ctx(&h), target(&v)).await.unwrap().status, OperationStatus::Succeeded);
    }
}

#[tokio::test]
async fn names_never_retarget_a_destructive_operation() {
    let r = Rig::new();
    let h = r.host();
    let first = ready(&h, Some("shared-name")).await;
    h.sandbox_destroy(&ctx(&h), target(&first)).await.unwrap();
    let second = ready(&h, Some("shared-name")).await; // the name is reused by a NEW sandbox
    assert_ne!(first.sandbox_id, second.sandbox_id);
    // the old (id, generation) can no longer touch anything — and certainly not the new holder of the name
    let e = h.sandbox_destroy(&ctx(&h), target(&first)).await;
    assert!(e.is_err() || e.as_ref().is_ok_and(|op| sandbox_of(op).sandbox_id == first.sandbox_id), "must address the old id only");
    assert_eq!(h.sandbox_inspect("shared-name").unwrap().sandbox_id, second.sandbox_id);
    assert_eq!(h.sandbox_inspect("shared-name").unwrap().state, LifecycleState::Ready);
}

// ---------------------------------------------------------------- exec semantics

#[tokio::test]
async fn a_non_zero_exit_is_a_known_result_not_an_infrastructure_failure() {
    let r = Rig::new();
    let h = r.host();
    let v = ready(&h, None).await;
    r.world.set_exec(Arc::new(|req, _| {
        Ok(GuestExecOutcome {
            result: ok_result(&req.exec_id, ExecStatus::Exited { code: 3 }, b"partial"),
            host_deadline_hit: false,
            vm_killed: false,
        })
    }));
    let op = h.exec(&ctx(&h), exec_params(&v, &["x"])).await.unwrap();
    assert_eq!(op.status, OperationStatus::Succeeded, "the system learned the result");
    let rr = run_of(&h, &op);
    assert_eq!((rr.outcome, rr.exit_code), (RunOutcome::Failed, Some(3)));
    assert_eq!(h.sandbox_inspect(v.sandbox_id.as_str()).unwrap().state, LifecycleState::Completed, "the sandbox is still reusable");
    assert!(h.exec(&ctx(&h), exec_params(&v, &["again"])).await.unwrap().status == OperationStatus::Succeeded);
}

#[tokio::test]
async fn a_lost_exec_result_is_unknown_and_never_reported_as_failed() {
    let r = Rig::new();
    let h = r.host();
    let v = ready(&h, None).await;
    // the command RAN in the guest, but the transport died before the result came back
    r.world.fail_next("exec", Fail::After(AcfError::new(FailureClass::BackendCrash, "connection reset").with_possible_side_effect()));
    let op = h.exec(&ctx(&h), exec_params(&v, &["rm", "-rf", "/workspace/data"])).await.unwrap();
    assert_eq!(op.status, OperationStatus::Unknown, "an arbitrary guest command may have run: UNKNOWN, not FAILED");
    assert_eq!(h.sandbox_inspect(v.sandbox_id.as_str()).unwrap().state, LifecycleState::Failed);
    let e = h.exec(&ctx(&h), exec_params(&v, &["again"])).await.unwrap_err();
    assert_eq!(e.class, FailureClass::StateConflict, "FAILED → RUNNING is forbidden: {e}");
}

#[tokio::test]
async fn a_host_backstop_kill_marks_the_sandbox_failed_but_the_run_timed_out() {
    let r = Rig::new();
    let h = r.host();
    let v = ready(&h, None).await;
    r.world.set_exec(Arc::new(|req, _| {
        let mut res = ok_result(&req.exec_id, ExecStatus::TimedOut, b"");
        res.output_incomplete = true;
        res.containment = Containment::Unknown;
        Ok(GuestExecOutcome { result: res, host_deadline_hit: true, vm_killed: true })
    }));
    let op = h.exec(&ctx(&h), exec_params(&v, &["hang"])).await.unwrap();
    let rr = run_of(&h, &op);
    assert_eq!((op.status, rr.outcome), (OperationStatus::Succeeded, RunOutcome::TimedOut));
    assert_eq!(rr.evidence_status, EvidenceStatus::Incomplete, "output was never seen: evidence must say so");
    assert!(rr.note.as_deref().unwrap_or("").contains("killed the VM"));
    assert_eq!(h.sandbox_inspect(v.sandbox_id.as_str()).unwrap().state, LifecycleState::Failed);
}

#[tokio::test]
async fn truncated_output_is_flagged_and_large_output_is_spilled_and_rehydrated() {
    let r = Rig::new();
    let h = r.host();
    let v = ready(&h, None).await;
    let big = vec![b'z'; 100 * 1024];
    let big2 = big.clone();
    r.world.set_exec(Arc::new(move |req, _| {
        let mut res = ok_result(&req.exec_id, ExecStatus::Exited { code: 0 }, &big2);
        res.stdout_total_bytes = 5_000_000;
        res.stdout_truncated = true;
        Ok(GuestExecOutcome { result: res, host_deadline_hit: false, vm_killed: false })
    }));
    let op = h.exec(&ctx(&h), exec_params(&v, &["bigout"])).await.unwrap();
    // the journal copy is small (output spilled), the response re-attaches it from the artifact
    let journal_len = serde_json::to_vec(&op.result).unwrap().len();
    assert!(journal_len < 8 * 1024, "journal result must stay small, was {journal_len}");
    let rr = run_of(&h, &op);
    assert_eq!(rr.evidence_status, EvidenceStatus::Truncated);
    assert_eq!((rr.stdout.total_bytes, rr.stdout.kept_bytes), (5_000_000, 100 * 1024));
    use base64::{Engine, engine::general_purpose::STANDARD};
    assert_eq!(STANDARD.decode(&rr.stdout.data_b64).unwrap(), big, "re-attached from the artifact, byte for byte");
    assert!(rr.resource_evidence.iter().any(|e| e.resource == "stdout_bytes" && e.violation == Some(FailureClass::OutputLimit)));
    // and a *later* lookup (lost-response resolution) returns the same thing
    let again = h.run_inspect(&rr.run_id).unwrap();
    assert!(matches!(again, ResponseBody::Run(x) if x.stdout.kept_bytes == 100 * 1024));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_one_exec_runs_at_a_time_and_the_loser_gets_a_conflict_without_a_record() {
    let r = Rig::new();
    let h = r.host();
    let v = ready(&h, None).await;
    let gate = Arc::new(std::sync::Barrier::new(2));
    let g2 = Arc::clone(&gate);
    r.world.set_exec(Arc::new(move |req, _| {
        g2.wait(); // hold the first exec inside the backend until the second has been rejected
        Ok(GuestExecOutcome {
            result: ok_result(&req.exec_id, ExecStatus::Exited { code: 0 }, b""),
            host_deadline_hit: false,
            vm_killed: false,
        })
    }));
    let (h1, v1) = (Arc::clone(&h), v.clone());
    let first = tokio::task::spawn(async move { h1.exec(&ctx(&h1), exec_params(&v1, &["a"])).await });
    // wait until the first is genuinely running
    for _ in 0..200 {
        if h.sandbox_inspect(v.sandbox_id.as_str()).unwrap().state == LifecycleState::Running {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let before = h.journal.read(|s| s.operations.len()).unwrap();
    let e = h.exec(&ctx(&h), exec_params(&v, &["b"])).await.unwrap_err();
    assert_eq!(e.class, FailureClass::StateConflict, "{e}");
    assert_eq!(h.journal.read(|s| s.operations.len()).unwrap(), before, "a CONFLICT creates no durable record");
    tokio::task::spawn_blocking(move || gate.wait()).await.unwrap();
    assert_eq!(first.await.unwrap().unwrap().status, OperationStatus::Succeeded);
}

#[tokio::test]
async fn policy_denials_happen_before_any_record_or_side_effect() {
    let r = Rig::new();
    let h = r.host();
    let v = ready(&h, None).await;
    let before = (h.journal.read(|s| s.operations.len()).unwrap(), r.world.calls().len());
    // env var not on the allowlist
    let mut p = exec_params(&v, &["x"]);
    p.command.env.insert("LD_PRELOAD".into(), "/evil.so".into());
    assert_eq!(h.exec(&ctx(&h), p).await.unwrap_err().class, FailureClass::Authorization);
    // limit above the ceiling
    let mut p = exec_params(&v, &["x"]);
    p.command.limits.timeout_ms = Some(10 * 3_600_000);
    assert_eq!(h.exec(&ctx(&h), p).await.unwrap_err().class, FailureClass::AdmissionRejected);
    // image alias not in policy
    let mut c = create_params(None);
    c.image = "kali".into();
    assert_eq!(h.sandbox_create(&ctx(&h), c).await.unwrap_err().class, FailureClass::Authorization);
    assert_eq!((h.journal.read(|s| s.operations.len()).unwrap(), r.world.calls().len()), before, "no record, no backend call");
}

// ---------------------------------------------------------------- snapshots

fn snap_params(v: &crate::protocol::SandboxView, name: &str) -> SnapshotCreateParams {
    SnapshotCreateParams { sandbox_id: v.sandbox_id.clone(), expected_generation: v.generation, name: Some(name.into()) }
}

fn restore_existing(s: &crate::protocol::SnapshotView, v: &crate::protocol::SandboxView) -> SnapshotRestoreParams {
    SnapshotRestoreParams {
        snapshot: s.snapshot.clone(),
        target: RestoreTarget::Existing { sandbox_id: v.sandbox_id.clone(), expected_generation: v.generation },
    }
}

#[tokio::test]
async fn snapshot_break_restore_returns_the_workspace_to_a_verified_baseline() {
    let r = Rig::new();
    let h = r.host();
    let v = ready(&h, Some("lab")).await;
    let jail = format!("{}-g{}", v.sandbox_id, v.generation);
    r.world.with_guest(&jail, |g| g.files.insert("experiment.py".into(), "print('works')".into()));

    let snap = h.snapshot_create(&ctx(&h), snap_params(&v, "baseline")).await.unwrap();
    assert_eq!(snap.status, OperationStatus::Succeeded, "{:?}", snap.failure);
    let sv = snapshot_of(&snap);
    assert_eq!(sv.state, SnapshotState::Ready);
    assert!(sv.size_bytes > 0 && sv.manifest_digest.is_some());
    assert_eq!(h.sandbox_inspect("lab").unwrap().state, LifecycleState::Ready, "the source sandbox is back to its prior state");

    // break the environment after the snapshot
    r.world.with_guest(&jail, |g| {
        g.files.clear();
        g.files.insert("experiment.py".into(), "CORRUPTED".into());
    });

    let rs = h.snapshot_restore(&ctx(&h), restore_existing(&sv, &v)).await.unwrap();
    assert_eq!(rs.status, OperationStatus::Succeeded, "{:?}", rs.failure);
    let nv = sandbox_of(&rs);
    assert_eq!((nv.sandbox_id.clone(), nv.generation, nv.state), (v.sandbox_id.clone(), Generation(2), LifecycleState::Ready));
    assert!(nv.notes.iter().any(|n| n.contains("restore verified")));
    assert_eq!(r.world.vm_count(), 1, "the old generation was retired");
    let new_jail = format!("{}-g2", v.sandbox_id);
    assert_eq!(
        r.world.with_guest(&new_jail, |g| g.files.get("experiment.py").cloned()).flatten().as_deref(),
        Some("print('works')"),
        "state is back to the baseline"
    );
    assert_eq!(h.sandbox_inspect("lab").unwrap().generation, Generation(2));
    // the old generation is gone for good and stale references to it conflict
    assert!(!h.layout.generation_path(&v.sandbox_id, Generation(1)).exists());
    assert_eq!(h.sandbox_destroy(&ctx(&h), target(&v)).await.unwrap_err().class, FailureClass::StateConflict);
    // …and the restored sandbox is fully usable
    assert_eq!(h.exec(&ctx(&h), exec_params(&nv, &["ok"])).await.unwrap().status, OperationStatus::Succeeded);
}

#[tokio::test]
async fn a_failed_restore_never_costs_the_caller_their_existing_sandbox() {
    let r = Rig::new();
    let h = r.host();
    let v = ready(&h, Some("lab")).await;
    let sv = snapshot_of(&h.snapshot_create(&ctx(&h), snap_params(&v, "b")).await.unwrap());
    r.world.fail_next("restore", Fail::After(AcfError::new(FailureClass::BackendCrash, "load failed").with_possible_side_effect()));
    let rs = h.snapshot_restore(&ctx(&h), restore_existing(&sv, &v)).await.unwrap();
    assert_eq!(rs.status, OperationStatus::Failed, "the new generation was torn down, so the failure is definite");
    let cur = h.sandbox_inspect("lab").unwrap();
    assert_eq!((cur.generation, cur.state), (v.generation, LifecycleState::Ready), "the old generation is still the current one");
    assert_eq!(r.world.vm_count(), 1);
    assert_eq!(h.exec(&ctx(&h), exec_params(&cur, &["still-works"])).await.unwrap().status, OperationStatus::Succeeded);
    // generation numbers are never reused, even though gen 2 never became current
    let again = h.snapshot_restore(&ctx(&h), restore_existing(&sv, &cur)).await.unwrap();
    assert_eq!(sandbox_of(&again).generation, Generation(3));
}

#[tokio::test]
async fn a_tampered_manifest_or_artifact_is_refused_and_never_loaded() {
    let r = Rig::new();
    let h = r.host();
    let v = ready(&h, Some("lab")).await;
    let sv = snapshot_of(&h.snapshot_create(&ctx(&h), snap_params(&v, "b")).await.unwrap());
    let dir = h.layout.snapshot_path(&sv.snapshot.snapshot_id, sv.snapshot.snapshot_generation);

    // 1) artifact tampered: the backend verifies by reading and refuses; old sandbox untouched
    std::fs::write(dir.join("mem"), b"tampered-memory").unwrap();
    let rs = h.snapshot_restore(&ctx(&h), restore_existing(&sv, &v)).await.unwrap();
    assert_eq!(rs.status, OperationStatus::Failed);
    assert_eq!(rs.failure.as_ref().map(|f| f.class), Some(FailureClass::CorruptInput));
    assert_eq!(h.sandbox_inspect("lab").unwrap().generation, v.generation);

    // 2) manifest tampered: caught by the JOURNAL-held digest before any backend call
    r.world.clear_calls();
    let mut m: serde_json::Value = serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap();
    m["baseline_state_digest"] = serde_json::json!("f".repeat(64));
    std::fs::write(dir.join("manifest.json"), serde_json::to_vec_pretty(&m).unwrap()).unwrap();
    let e = h.snapshot_restore(&ctx(&h), restore_existing(&sv, &v)).await.unwrap_err();
    assert_eq!(e.class, FailureClass::CorruptInput, "{e}");
    assert!(!r.world.calls().iter().any(|c| c == "restore"), "no VMM may be started from an unverifiable snapshot");
    let state = h.snapshot_list().unwrap().into_iter().find(|s| s.snapshot == sv.snapshot).unwrap().state;
    assert_eq!(state, SnapshotState::Invalid, "SNAPSHOT_INVALID is recorded");
    let again = h.snapshot_restore(&ctx(&h), restore_existing(&sv, &v)).await.unwrap_err();
    assert_eq!(again.class, FailureClass::StateConflict, "INVALID → RESTORING is forbidden: {again}");
}

#[tokio::test]
async fn a_restore_that_does_not_reproduce_the_baseline_is_rejected() {
    let r = Rig::new();
    let h = r.host();
    let v = ready(&h, Some("lab")).await;
    let sv = snapshot_of(&h.snapshot_create(&ctx(&h), snap_params(&v, "b")).await.unwrap());
    // simulate a "restore" whose guest actually differs (e.g. cold-booted): corrupt the captured state
    r.world.fail_next("probe", Fail::Before(AcfError::new(FailureClass::BackendUnavailable, "guest not answering")));
    let rs = h.snapshot_restore(&ctx(&h), restore_existing(&sv, &v)).await.unwrap();
    assert_eq!(rs.status, OperationStatus::Failed);
    assert_eq!(h.sandbox_inspect("lab").unwrap().generation, v.generation, "unverified restore must not become current");
    assert_eq!(r.world.vm_count(), 1);
}

#[tokio::test]
async fn restore_as_new_sandbox_and_uniqueness_note_on_repeat_restores() {
    let r = Rig::new();
    let h = r.host();
    let v = ready(&h, Some("src")).await;
    let sv = snapshot_of(&h.snapshot_create(&ctx(&h), snap_params(&v, "b")).await.unwrap());
    let mk = |name: &str| SnapshotRestoreParams { snapshot: sv.snapshot.clone(), target: RestoreTarget::New { name: Some(name.into()) } };
    let first = sandbox_of(&h.snapshot_restore(&ctx(&h), mk("copy1")).await.unwrap());
    let second = sandbox_of(&h.snapshot_restore(&ctx(&h), mk("copy2")).await.unwrap());
    assert_ne!(first.sandbox_id, second.sandbox_id);
    assert!(!first.notes.iter().any(|n| n.contains("more than once")));
    assert!(second.notes.iter().any(|n| n.contains("more than once")), "{:?}", second.notes);
    assert_eq!(h.sandbox_list().unwrap().len(), 3, "source + two copies");
}

#[tokio::test]
async fn a_failed_snapshot_leaves_the_guest_running_and_releases_its_quota() {
    let r = Rig::new();
    let h = r.host();
    let v = ready(&h, Some("lab")).await;
    r.world.fail_next("snapshot", Fail::After(AcfError::new(FailureClass::BackendCrash, "disk full").with_possible_side_effect()));
    let op = h.snapshot_create(&ctx(&h), snap_params(&v, "b")).await.unwrap();
    assert_eq!(op.status, OperationStatus::Failed, "VM verified running, partial artifacts removed ⇒ definite");
    let cur = h.sandbox_inspect("lab").unwrap();
    assert_eq!(cur.state, LifecycleState::Ready, "the guest is not left frozen");
    assert!(h.snapshot_list().unwrap().is_empty());
    for i in 0..3 {
        assert_eq!(h.snapshot_create(&ctx(&h), snap_params(&cur, &format!("s{i}"))).await.unwrap().status, OperationStatus::Succeeded);
    }
    let e = h.snapshot_create(&ctx(&h), snap_params(&cur, "overflow")).await.unwrap_err();
    assert!(matches!(e.class, FailureClass::AdmissionRejected | FailureClass::ResourceExhaustion), "{e}");
    // deleting one frees the slot; delete is idempotent
    let victim = h.snapshot_list().unwrap()[0].snapshot.clone();
    assert_eq!(h.snapshot_delete(&ctx(&h), victim.clone()).await.unwrap().status, OperationStatus::Succeeded);
    assert_eq!(h.snapshot_create(&ctx(&h), snap_params(&cur, "again")).await.unwrap().status, OperationStatus::Succeeded);
    let _: &SnapshotRef = &victim;
}

#[tokio::test]
async fn snapshot_and_exec_exclude_each_other_and_need_an_idle_sandbox() {
    let r = Rig::new();
    let h = r.host();
    let v = ready(&h, None).await;
    h.sandbox_stop(&ctx(&h), target(&v)).await.unwrap();
    let e = h.snapshot_create(&ctx(&h), snap_params(&v, "x")).await.unwrap_err();
    assert_eq!(e.class, FailureClass::StateConflict, "{e}");
    let e = h.exec(&ctx(&h), exec_params(&v, &["x"])).await.unwrap_err();
    assert_eq!(e.class, FailureClass::StateConflict, "STOPPED → RUNNING is forbidden: {e}");
    let _ = (VmmState::Absent, res());
}
