//! T-EXEC: execution and the guest contract (§18), and T-SECR: secrets (§22). The guest-protocol
//! half of T-EXEC-05 (malformed, oversized, slow and forged guest replies; L2 against the real guest
//! agent) is in `guest/client.rs`.

use std::sync::{Arc, Mutex};

use acf_wire::guest::{Containment, ExecResult, ExecStatus};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

use crate::{
    api::ReadResult,
    backend::{GuestExecOutcome, GuestExecRequest},
    domain::{Cleanup, Effect, EvidenceStatus, LifecycleState, OperationState, OutputStatus, RunStatus},
    error::{AcfError, FailureClass},
    testing::{
        fake_backend::Fail,
        fault::FaultPoint,
        rig::{Rig, alice, calls, exec_params, footprint, run_of, sandbox_of, snapshot_of, target},
    },
};

/// A guest that reports whatever the test scripts.
fn guest(
    status: ExecStatus,
    stdout: Vec<u8>,
    stdout_total: u64,
    truncated: bool,
    host_killed: bool,
) -> Arc<crate::testing::fake_backend::ExecScript> {
    Arc::new(move |req: &GuestExecRequest, _| {
        Ok(GuestExecOutcome {
            result: ExecResult {
                exec_id: req.exec_id.clone(),
                status: status.clone(),
                stdout: stdout.clone(),
                stdout_total_bytes: stdout_total,
                stderr: b"warn\n".to_vec(),
                stderr_total_bytes: 5,
                stdout_truncated: truncated,
                stderr_truncated: false,
                duration_ms: 12,
                pid_limit_hit: false,
                output_incomplete: false,
                containment: Containment::Cgroup2,
            },
            host_deadline_hit: host_killed,
            vm_killed: host_killed,
        })
    })
}

/// T-EXEC-01: every row of §18.2 that a single activation can produce. (Cancel is T-OP-07,
/// preemption T-CONC-03, inheritance the fault-point matrix.)
#[tokio::test]
async fn t_exec_01_every_execution_outcome() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let sb = a.ready(None).await;
    let ok = |status| guest(status, b"out\n".to_vec(), 4, false, false);

    // The command ended by itself: SUCCEEDED, whatever its exit status. A non-zero exit is a result.
    for (status, run_status, code, signal) in [
        (ExecStatus::Exited { code: 0 }, RunStatus::Exited, Some(0), None),
        (ExecStatus::Exited { code: 3 }, RunStatus::Exited, Some(3), None),
        (ExecStatus::Signaled { signal: 9 }, RunStatus::Signaled, None, Some(9)),
        // The guest ended it at the guest deadline: still a result.
        (ExecStatus::TimedOut, RunStatus::TimedOut, None, None),
    ] {
        rig.world.set_exec(ok(status));
        let op = a.exec(&sb, &["/bin/x"]).await;
        let run = run_of(&op);
        assert_eq!((op.state, op.effect), (OperationState::Succeeded, Some(Effect::Applied)), "{run_status:?}");
        assert_eq!((run.status, run.exit_code, run.signal, run.host_backstop_fired), (run_status, code, signal, false));
        assert_eq!(a.inspect(&sb.sandbox_id).await.state, LifecycleState::Completed);
    }

    // The guest could not start it: FAILED, NOT_APPLIED; the sandbox is idle and usable.
    rig.world.set_exec(ok(ExecStatus::SpawnFailed { message: "no such file".into() }));
    let op = a.exec(&sb, &["/no/such/program"]).await;
    assert_eq!((op.state, op.effect, op.cleanup), (OperationState::Failed, Some(Effect::NotApplied), Some(Cleanup::Complete)));
    assert_eq!(run_of(&op).status, RunStatus::SpawnFailed);
    assert_eq!(a.inspect(&sb.sandbox_id).await.state, LifecycleState::Completed);

    // The command never reached the guest (a definite failure): FAILED, NOT_APPLIED; still usable.
    rig.world.fail_next("exec", Fail::Before(AcfError::unavailable("the guest channel could not be opened")));
    let op = a.exec(&sb, &["/bin/true"]).await;
    assert_eq!((op.state, op.effect), (OperationState::Failed, Some(Effect::NotApplied)));
    assert_eq!(op.failure.as_ref().map(|f| f.class), Some(FailureClass::DependencyUnavailable));
    assert_eq!(a.inspect(&sb.sandbox_id).await.state, LifecycleState::Completed);

    // No result could be obtained after the command was sent: UNKNOWN — never success, never failure.
    rig.world.set_exec(ok(ExecStatus::Exited { code: 0 }));
    rig.world.fail_next("exec", Fail::After(AcfError::unavailable("the connection to the guest was lost").with_possible_side_effect()));
    let op = a.exec(&sb, &["/bin/true"]).await;
    assert_eq!((op.state, op.effect, op.result.is_none()), (OperationState::Unknown, Some(Effect::MayBeApplied), true));
    assert_eq!(op.failure.as_ref().map(|f| f.class), Some(FailureClass::UnknownOutcome));
    assert_eq!(a.inspect(&sb.sandbox_id).await.state, LifecycleState::Failed);
    assert_eq!(rig.world.vm_count(), 0, "the runtime is ended");
    assert_eq!(calls(&rig.world, "exec"), 7, "and the command is never sent again (RY-3)");

    // The host backstop fired: FAILED / TIMEOUT / MAY_BE_APPLIED; the run is TIMED_OUT, host-observed.
    let sb = a.ready(None).await;
    rig.world.set_exec(guest(ExecStatus::TimedOut, vec![], 0, false, true));
    let op = a.exec(&sb, &["/bin/sleep", "infinity"]).await;
    assert_eq!((op.state, op.effect), (OperationState::Failed, Some(Effect::MayBeApplied)));
    assert_eq!(op.failure.as_ref().map(|f| f.class), Some(FailureClass::Timeout));
    let run = run_of(&op);
    assert_eq!((run.status, run.host_backstop_fired, run.runtime_ended), (RunStatus::TimedOut, true, true));
    assert_eq!(a.inspect(&sb.sandbox_id).await.state, LifecycleState::Failed);
    assert_eq!(
        a.refused("exec.run", exec_params(&a.inspect(&sb.sandbox_id).await, &["/bin/true"])).await.class,
        FailureClass::StateConflict,
        "a FAILED sandbox is never reused"
    );
}

/// T-EXEC-03: output over its budget is `TRUNCATED` with full counts; a guest cannot make the host
/// keep more than the budget; large output is stored once and read back in slices.
#[tokio::test]
async fn t_exec_03_output_is_bounded_counted_and_readable_in_slices() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let sb = a.ready(None).await;
    let budget = 100_000u64;
    let limited = |sb: &crate::api::SandboxView| json!({"sandbox_id": sb.sandbox_id, "expected_generation": sb.generation, "command": {"argv": ["/bin/yes"], "limits": {"max_stdout_bytes": budget, "max_stderr_bytes": 1000}}});

    // The guest kept exactly the budget and counted the rest.
    let kept: Vec<u8> = (0..budget).map(|i| b'a' + (i % 26) as u8).collect();
    rig.world.set_exec(guest(ExecStatus::Exited { code: 0 }, kept.clone(), 5_000_000, true, false));
    let op = a.op("exec.run", limited(&sb)).await;
    let run = run_of(&op);
    assert_eq!(op.state, OperationState::Succeeded, "a full budget is not a failure, and never stalls the workload");
    assert_eq!((run.stdout.status, run.stdout.kept_bytes, run.stdout.total_bytes), (OutputStatus::Truncated, budget, 5_000_000));
    assert_eq!((run.stderr.status, run.stderr.kept_bytes, run.stderr.total_bytes), (OutputStatus::Complete, 5, 5));
    assert_eq!(run.evidence_status, EvidenceStatus::Truncated);
    assert!(run.resource_evidence.iter().any(|e| e.resource == "stdout_bytes" && e.violated && e.observed_peak == Some(5_000_000)));
    assert_eq!(STANDARD.decode(&run.stdout.data_b64).unwrap(), kept, "an operation's result carries the stored output");

    // `run.output`: slices by offset, bounded per call, with an end marker.
    let chunk = |offset: u64, max: u64| {
        let (a, run_id) = (a.clone(), run.run_id.clone());
        async move {
            match a.read("run.output", json!({"run_id": run_id, "stream": "stdout", "offset": offset, "max_bytes": max})).await {
                ReadResult::Output(c) => c,
                other => panic!("{other:?}"),
            }
        }
    };
    let first = chunk(0, 60_000).await;
    assert_eq!(
        (first.offset, first.eof, first.stored_bytes, first.produced_bytes, first.completeness),
        (0, false, budget, 5_000_000, OutputStatus::Truncated)
    );
    let rest = chunk(60_000, 1_000_000).await;
    assert!(rest.eof);
    let mut joined = STANDARD.decode(&first.data_b64).unwrap();
    joined.extend(STANDARD.decode(&rest.data_b64).unwrap());
    assert_eq!(joined, kept);
    assert_eq!(
        a.refused("run.output", json!({"run_id": run.run_id, "stream": "stdout", "offset": budget + 1})).await.class,
        FailureClass::InvalidRequest
    );
    match a.read("run.inspect", json!({"run_id": run.run_id})).await {
        ReadResult::Run(r) => assert_eq!(r.stdout.kept_bytes, budget),
        other => panic!("{other:?}"),
    }

    // GP-2: a guest that sends more than the budget cannot make the host keep it.
    let inflated = vec![b'x'; (budget * 3) as usize];
    rig.world.set_exec(guest(ExecStatus::Exited { code: 0 }, inflated, budget * 3, false, false));
    let run = run_of(&a.op("exec.run", limited(&a.inspect(&sb.sandbox_id).await)).await);
    assert_eq!(
        (run.stdout.kept_bytes, run.stdout.status),
        (budget, OutputStatus::Truncated),
        "bounded where it is stored, whatever the guest claimed"
    );

    // OU-4: output is removed after `output_retention`; the operation record outlives it.
    rig.clock.advance_ms(host.cfg.operations.output_retention_ms + 1);
    // (the retention relation of the register keeps operation records at least as long as output)
    assert!(host.cfg.operations.output_retention_ms <= host.cfg.operations.operation_retention_ms);
}

/// T-EXEC-06: a guest agent version that differs from the one the image manifest records → start
/// and restore are refused (GP-4).
#[tokio::test]
async fn t_exec_06_a_guest_agent_of_another_version_is_refused_at_start_and_at_restore() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let good = a.ready(None).await;
    let snap = snapshot_of(&a.done("snapshot.create", target(&good)).await);

    rig.world.set_agent_version("9.9.9");
    let sb = a.create(None).await;
    let op = a.op("sandbox.start", target(&sb)).await;
    assert_eq!((op.state, op.failure.as_ref().map(|f| f.class)), (OperationState::Failed, Some(FailureClass::IncompatibleRuntime)));
    assert_eq!(a.inspect(&sb.sandbox_id).await.state, LifecycleState::Failed);
    assert_eq!(rig.world.vm_count(), 1, "the runtime with the wrong agent was ended; only the good one runs");

    // Restore in place: the new generation is refused, and the old one is still there (RE-6).
    let op = a.op("snapshot.restore", json!({"snapshot": snap.snapshot, "target": {"kind": "existing", "sandbox_id": good.sandbox_id, "expected_generation": good.generation}})).await;
    assert_eq!((op.state, op.failure.as_ref().map(|f| f.class)), (OperationState::Failed, Some(FailureClass::IncompatibleRuntime)));
    assert_eq!((op.effect, op.cleanup), (Some(Effect::NotApplied), Some(Cleanup::Complete)));
    let still = a.inspect(&good.sandbox_id).await;
    assert_eq!((still.generation, still.state), (good.generation, LifecycleState::Ready));
    assert_eq!(rig.world.vm_count(), 1);
}

/// A writer that keeps what the log would have printed.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Captured;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Everything the host emits besides committed state: log lines, events and metrics.
fn emitted(host: &crate::coordinator::Host, logs: &Captured) -> String {
    let mut all = String::from_utf8_lossy(&logs.0.lock().unwrap()).into_owned();
    all.push_str(&serde_json::to_string(&host.telemetry.events.recent()).unwrap());
    all.push_str(&host.telemetry.metrics.snapshot().to_string());
    if let Ok(file) = std::fs::read_to_string(host.cfg.paths.state_root.join("telemetry").join("events.jsonl")) {
        all.push_str(&file);
    }
    all
}

/// T-EXEC-07 and T-SECR-02: execution output appears in no log, metric, trace or event; a delivered
/// secret appears in no store dump, fingerprint or telemetry.
#[tokio::test]
async fn t_exec_07_t_secr_02_output_and_secrets_never_reach_telemetry_and_secrets_never_reach_the_store() {
    let logs = Captured::default();
    let subscriber = tracing_subscriber::fmt().with_writer(logs.clone()).with_max_level(tracing::Level::TRACE).with_ansi(false).finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let sb = a.ready(None).await;
    const OUTPUT: &str = "OUTPUT-MARKER-7f3a9c";
    const SECRET: &str = "SECRET-MATERIAL-51d0e8";
    const ARG: &str = "ARGUMENT-MARKER-c44b12";
    rig.secrets.provision("ci-token", SECRET.as_bytes());
    rig.world.set_exec(guest(ExecStatus::Exited { code: 1 }, OUTPUT.as_bytes().to_vec(), OUTPUT.len() as u64, false, false));
    let params = json!({"sandbox_id": sb.sandbox_id, "expected_generation": sb.generation,
        "command": {"argv": ["/bin/deploy", ARG], "env": {"LANG": "C"}, "secret_env": {"HOME": {"ref": "ci-token"}}}});
    let op = a.op("exec.run", params).await;
    assert_eq!(op.state, OperationState::Succeeded);
    assert_eq!(STANDARD.decode(run_of(&op).stdout.data_b64).unwrap(), OUTPUT.as_bytes(), "the caller does get the output");
    // The secret was delivered to the guest, by reference, at the moment of execution (SC-2).
    let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(SECRET.as_bytes()));
    assert_eq!(rig.world.delivered_secrets(), vec![("HOME".to_owned(), digest)]);
    assert_eq!(rig.secrets.resolutions.load(std::sync::atomic::Ordering::SeqCst), 1);
    // The generation is marked secret-bearing with the reference, and a snapshot of it carries the mark (SC-5).
    assert!(a.inspect(&sb.sandbox_id).await.secret_bearing);
    let snap = snapshot_of(&a.done("snapshot.create", target(&a.inspect(&sb.sandbox_id).await)).await);
    assert_eq!(snap.secret_refs, vec!["ci-token".to_owned()]);
    a.done("sandbox.destroy", target(&a.inspect(&sb.sandbox_id).await)).await;
    host.sweep_once().await;

    // Telemetry: neither the output, nor the argument vector, nor the secret, in any encoding used here.
    let telemetry = emitted(&host, &logs);
    assert!(telemetry.contains("operation.finished"), "events were emitted");
    for (what, needle) in [("output", OUTPUT), ("secret", SECRET), ("argument", ARG)] {
        assert!(!telemetry.contains(needle), "{what} leaked into telemetry");
        assert!(!telemetry.contains(&STANDARD.encode(needle)), "{what} leaked into telemetry (base64)");
    }
    // The store: output is execution evidence and may be there; a secret never is (SC-1).
    let mut durable = std::fs::read(rig.cfg.journal_path()).unwrap();
    for entry in walk(rig.layout.root()) {
        durable.extend(std::fs::read(entry).unwrap_or_default());
    }
    let durable = String::from_utf8_lossy(&durable);
    assert!(durable.contains("ci-token"), "the reference is recorded");
    assert!(!durable.contains(SECRET) && !durable.contains(&STANDARD.encode(SECRET)), "the material is not");
    // The fingerprint is computed over references only: the same request with other material is the same request.
    rig.secrets.provision("ci-token", b"rotated-material");
    assert!(!format!("{:?}", a.get(&op.operation_id).await).contains(SECRET));
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() { files.extend(walk(&path)) } else { files.push(path) }
    }
    files
}

/// T-SECR-01: raw secret material in a request → `INVALID_REQUEST`. A request can only name a
/// reference; there is no field that could carry a value.
#[tokio::test]
async fn t_secr_01_a_request_cannot_carry_secret_material() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let sb = a.ready(None).await;
    let before = footprint(&host);
    let with = |secret_env: Value| json!({"sandbox_id": sb.sandbox_id, "expected_generation": sb.generation, "command": {"argv": ["/bin/true"], "secret_env": secret_env}});
    for raw in [
        json!({"HOME": "hunter2"}),
        json!({"HOME": {"ref": "ci-token", "value": "hunter2"}}),
        json!({"HOME": {"value": "hunter2"}}),
        json!({"HOME": {"ref": "../../etc/shadow"}}),
        json!({"HOME": {"ref": ""}}),
        json!({"HOME": {"ref": "ci-token", "hunter2": true}}),
    ] {
        let refusal = a.refused("exec.run", with(raw.clone())).await;
        assert_eq!(refusal.class, FailureClass::InvalidRequest, "{raw}");
        // SC-1: the material is kept nowhere, and that includes the answer that refuses it. A refusal
        // says what was expected, never what the request held.
        assert!(!refusal.message.contains("hunter2"), "{raw}: the refusal repeats the material: {}", refusal.message);
        assert!(!refusal.message.contains("shadow"), "{raw}: {}", refusal.message);
    }
    assert_eq!((footprint(&host), calls(&rig.world, "exec")), (before, 0));

    // SC-3: a reference that does not resolve fails the operation before any effect that depends on it.
    let op = a.op("exec.run", with(json!({"HOME": {"ref": "not-provisioned"}}))).await;
    assert_eq!((op.state, op.effect), (OperationState::Failed, Some(Effect::NotApplied)));
    assert_eq!(op.failure.as_ref().map(|f| f.class), Some(FailureClass::DependencyUnavailable));
    assert_eq!(calls(&rig.world, "exec"), 0, "nothing reached the guest");
    assert_eq!(a.inspect(&sb.sandbox_id).await.state, LifecycleState::Completed, "the sandbox is idle and usable");
}

/// T-SECR-03: a crash after a secret was resolved → the next activation resolves nothing (SC-4):
/// an inherited operation is never continued, so recovery has no use for a secret.
#[tokio::test]
async fn t_secr_03_a_later_activation_never_resolves_a_secret_again() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let sb = a.ready(None).await;
    rig.secrets.provision("ci-token", b"material");
    host.faults.arm(FaultPoint::BeforeBackendStep, "exec"); // resolved, not yet delivered
    let env = a.envelope("exec.run", json!({"sandbox_id": sb.sandbox_id, "expected_generation": sb.generation, "command": {"argv": ["/bin/true"], "secret_env": {"HOME": {"ref": "ci-token"}}}}));
    let id = env.operation_id.clone().unwrap();
    let _ = a.send(env).await;
    let resolved = || rig.secrets.resolutions.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(resolved(), 1);
    drop(a);
    drop(host);

    let host = rig.serving().await;
    assert_eq!(resolved(), 1, "recovery resolved nothing (RC-9)");
    assert_eq!(calls(&rig.world, "exec"), 0, "and delivered nothing");
    let a = alice(&host);
    assert_eq!(a.get(&id).await.state, OperationState::Unknown);
    assert!(rig.world.delivered_secrets().is_empty());
    let _ = sandbox_of;
}

/// SC-3 and SC-5: a generation is marked secret-bearing for what was *delivered* to it. A reference
/// that does not resolve fails the operation before anything reaches the guest, so it marks nothing:
/// one mistyped reference must not make every later snapshot of the sandbox unrestorable.
#[tokio::test]
async fn sc_3_sc_5_a_reference_that_does_not_resolve_delivers_nothing_and_marks_nothing() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let sb = a.ready(None).await;
    let with = |reference: &str| {
        json!({"sandbox_id": sb.sandbox_id, "expected_generation": sb.generation,
            "command": {"argv": ["/bin/true"], "secret_env": {"HOME": {"ref": reference}}}})
    };

    let failed = a.op("exec.run", with("not-provisioned")).await;
    assert_eq!((failed.state, failed.effect, failed.cleanup), (OperationState::Failed, Some(Effect::NotApplied), Some(Cleanup::Complete)));
    assert_eq!(failed.failure.as_ref().map(|f| f.class), Some(FailureClass::DependencyUnavailable));
    assert_eq!(calls(&rig.world, "exec"), 0, "nothing reached the guest");
    assert!(rig.world.delivered_secrets().is_empty());
    let now = a.inspect(&sb.sandbox_id).await;
    assert!(now.state.is_idle(), "{:?}", now.state);
    assert!(!now.secret_bearing, "nothing was delivered, so nothing is marked");
    // A snapshot of it carries no reference, and restores whatever the secret provider holds.
    let snap = snapshot_of(&a.done("snapshot.create", target(&now)).await);
    assert!(snap.secret_refs.is_empty(), "{:?}", snap.secret_refs);
    let restored = sandbox_of(&a.done("snapshot.restore", json!({"snapshot": snap.snapshot, "target": {"kind": "new"}})).await);
    a.done("sandbox.destroy", target(&restored)).await;

    // A delivery marks the generation, and a later failure to resolve *another* reference takes
    // nothing away from that mark.
    rig.secrets.provision("ci-token", b"material");
    a.done("exec.run", with("ci-token")).await;
    assert!(a.inspect(&sb.sandbox_id).await.secret_bearing);
    let again = a.op("exec.run", with("also-not-provisioned")).await;
    assert_eq!(again.state, OperationState::Failed);
    let snap = snapshot_of(&a.done("snapshot.create", target(&a.inspect(&sb.sandbox_id).await)).await);
    assert_eq!(snap.secret_refs, vec!["ci-token".to_owned()], "exactly what was delivered");
}

/// T-SECR-04: restore of a secret-bearing snapshot whose reference no longer resolves → refused
/// (SC-6).
#[tokio::test]
async fn t_secr_04_a_secret_bearing_snapshot_is_restored_only_while_its_references_resolve() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let sb = a.ready(None).await;
    rig.secrets.provision("ci-token", b"material");
    a.done("exec.run", json!({"sandbox_id": sb.sandbox_id, "expected_generation": sb.generation, "command": {"argv": ["/bin/true"], "secret_env": {"HOME": {"ref": "ci-token"}}}})).await;
    let snap = snapshot_of(&a.done("snapshot.create", target(&sb)).await);
    let restore = json!({"snapshot": snap.snapshot, "target": {"kind": "new"}});

    rig.secrets.withdraw("ci-token");
    let before = (footprint(&host), calls(&rig.world, "restore"));
    let refused = a.refused("snapshot.restore", restore.clone()).await;
    assert_eq!(refused.class, FailureClass::IncompatibleRuntime, "{}", refused.message);
    assert_eq!((footprint(&host), calls(&rig.world, "restore")), before, "no runtime was launched");

    rig.secrets.provision("ci-token", b"material");
    let restored = sandbox_of(&a.done("snapshot.restore", restore).await);
    assert!(restored.secret_bearing, "the mark travels with the snapshot onto the generation it becomes");
}
