//! T-STATE: the state machines (contract §12). T-STATE-01 (every state × state pair, L1) is in
//! `domain/lifecycle.rs`; here are admission per state (§12.2), the joint-state invariants under
//! random operations and faults (§12.7) and the host modes (§12.6).

use std::sync::Arc;

use serde_json::{Value, json};

use crate::{
    api::{SandboxView, SnapshotView},
    coordinator::Host,
    domain::{ContainmentReason, HostMode, LifecycleState, Method, OperationClass, OperationState},
    error::FailureClass,
    testing::{
        fault::FaultPoint,
        rig::{Client, Rig, alice, create_params, eventually, exec_params, ops, sandbox_of, snapshot_of, target, valid_params},
    },
};

/// The states a sandbox can be observed in between operations, plus the two that only exist while
/// an operation is in flight (`RUNNING`, `PAUSED`) and the condition `QUARANTINED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Given {
    Provisioning,
    Ready,
    Completed,
    Running,
    Paused,
    Stopped,
    Failed,
    Destroyed,
    Quarantined,
}

const GIVEN: [Given; 9] = [
    Given::Provisioning,
    Given::Ready,
    Given::Completed,
    Given::Running,
    Given::Paused,
    Given::Stopped,
    Given::Failed,
    Given::Destroyed,
    Given::Quarantined,
];

struct Scene {
    rig: Rig,
    host: Arc<Host>,
    a: Client,
    sb: SandboxView,
    /// A `READY` snapshot of another sandbox of the same scope, for restores.
    snap: SnapshotView,
}

/// A sandbox in the given state, reached only through the API and the world.
async fn scene(given: Given) -> Scene {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let donor = a.ready(None).await;
    let snap = snapshot_of(&a.done("snapshot.create", target(&donor)).await);
    a.done("sandbox.destroy", target(&donor)).await;
    let sb = match given {
        Given::Provisioning => a.create(None).await,
        _ => a.ready(None).await,
    };
    match given {
        Given::Provisioning | Given::Ready => {}
        Given::Completed => assert_eq!(a.exec(&sb, &["/bin/true"]).await.state, OperationState::Succeeded),
        Given::Running => {
            rig.world.hold("exec");
            let (a2, sb2) = (a.clone(), sb.clone());
            tokio::spawn(async move { a2.exec(&sb2, &["/bin/sleep", "600"]).await });
            eventually("the command reaches the guest", || rig.world.waiting("exec") == 1).await;
        }
        Given::Paused => {
            rig.world.hold("snapshot");
            let (a2, sb2) = (a.clone(), sb.clone());
            tokio::spawn(async move { a2.op("snapshot.create", target(&sb2)).await });
            eventually("the capture starts", || rig.world.waiting("snapshot") == 1).await;
        }
        Given::Stopped => {
            a.done("sandbox.stop", target(&sb)).await;
        }
        Given::Failed => {
            // The runtime dies; the host notices and marks the generation FAILED (§16.2 Part B).
            rig.world.set_phase(&jail(&sb), crate::backend::VmmState::Absent);
            host.sweep_once().await;
        }
        Given::Destroyed => {
            a.done("sandbox.destroy", target(&sb)).await;
        }
        Given::Quarantined => {
            rig.forge_marker(&sb);
            assert_eq!(a.op("sandbox.destroy", target(&sb)).await.state, OperationState::Failed);
        }
    }
    let expected = match given {
        Given::Provisioning => LifecycleState::Provisioning,
        Given::Ready => LifecycleState::Ready,
        Given::Completed => LifecycleState::Completed,
        Given::Running => LifecycleState::Running,
        Given::Paused => LifecycleState::Paused,
        Given::Stopped => LifecycleState::Stopped,
        Given::Failed => LifecycleState::Failed,
        Given::Destroyed => LifecycleState::Destroyed,
        Given::Quarantined => a.inspect(&sb.sandbox_id).await.state,
    };
    let sb = a.inspect(&sb.sandbox_id).await;
    assert_eq!(sb.state, expected, "could not reach {given:?}");
    assert_eq!(sb.quarantined.is_some(), given == Given::Quarantined);
    Scene { rig, host, a, sb, snap }
}

fn jail(sb: &SandboxView) -> String {
    crate::ids::SandboxRef { sandbox_id: sb.sandbox_id.clone(), generation: sb.generation }.jail_id()
}

/// What §12.2 says about `method` on a sandbox in state `given`.
#[derive(Debug, PartialEq, Eq)]
enum Expect {
    Accepted,
    Refused(FailureClass),
}

fn expected(method: &str, given: Given) -> Expect {
    use Given::*;
    if given == Quarantined {
        return Expect::Refused(FailureClass::Quarantined); // every row; only `quarantine.release` is accepted
    }
    let conflict = Expect::Refused(FailureClass::StateConflict);
    match method {
        "sandbox.start" => {
            if given == Provisioning {
                Expect::Accepted
            } else {
                conflict
            }
        }
        // READY or COMPLETED. While RUNNING or PAUSED the sandbox is also busy (CC-1).
        "exec.run" | "snapshot.create" => {
            if matches!(given, Ready | Completed) {
                Expect::Accepted
            } else {
                conflict
            }
        }
        // Any state except REQUESTED, RUNNING and DESTROYED; PAUSED means a snapshot is in flight (CC-1).
        "snapshot.restore" => {
            if matches!(given, Running | Paused | Destroyed) {
                conflict
            } else {
                Expect::Accepted
            }
        }
        // Containment: any state. On STOPPED or DESTROYED it succeeds with no effect.
        "sandbox.stop" | "sandbox.destroy" => Expect::Accepted,
        other => panic!("{other}"),
    }
}

fn params(method: &str, s: &Scene) -> Value {
    match method {
        "exec.run" => exec_params(&s.sb, &["/bin/true"]),
        "snapshot.restore" => {
            json!({"snapshot": s.snap.snapshot, "target": {"kind": "existing", "sandbox_id": s.sb.sandbox_id, "expected_generation": s.sb.generation}})
        }
        _ => target(&s.sb),
    }
}

/// T-STATE-02: every lifecycle method × every state against §12.2, the quarantine rule and the
/// stale-token rule.
#[tokio::test]
async fn t_state_02_every_method_in_every_state_is_admitted_exactly_as_the_admission_table_says() {
    let methods = ["sandbox.start", "exec.run", "snapshot.create", "snapshot.restore", "sandbox.stop", "sandbox.destroy"];
    for given in GIVEN {
        for method in methods {
            let s = scene(given).await;
            // What is timed is the request itself: a refusal must not wait for whatever holds the sandbox.
            let began = std::time::Instant::now();
            let resp = s.a.call(method, params(method, &s)).await;
            assert!(
                began.elapsed() < std::time::Duration::from_secs(10),
                "{method} on {given:?} took {:?}: something waited",
                began.elapsed()
            );
            let got = match (resp.operation_view(), resp.refusal()) {
                (Some(op), _) => {
                    // An admitted operation on a healthy double runs to its end.
                    assert_eq!(op.state, OperationState::Succeeded, "{method} on {given:?}: {:?}", op.failure);
                    Expect::Accepted
                }
                (_, Some(r)) => Expect::Refused(r.class),
                _ => panic!("{method} on {given:?}: a read answer"),
            };
            assert_eq!(got, expected(method, given), "{method} on {given:?}");

            // The state the table says the sandbox ends in.
            let after = s.a.inspect(&s.sb.sandbox_id).await;
            if got == Expect::Accepted {
                let state = match method {
                    "sandbox.start" => LifecycleState::Ready,
                    "exec.run" => LifecycleState::Completed,
                    "snapshot.create" => s.sb.state, // back to the state it came from
                    "snapshot.restore" => LifecycleState::Ready,
                    "sandbox.stop" if given == Given::Destroyed => LifecycleState::Destroyed,
                    "sandbox.stop" => LifecycleState::Stopped,
                    _ => LifecycleState::Destroyed,
                };
                assert_eq!(after.state, state, "{method} on {given:?}");
                if method == "snapshot.restore" {
                    assert_eq!(after.generation, s.sb.generation.next(), "a restore in place makes a new generation");
                }
            } else {
                assert_eq!(
                    (after.state, after.generation),
                    (s.sb.state, s.sb.generation),
                    "{method} on {given:?}: a refusal changes nothing"
                );
            }
            s.rig.world.release("exec");
            s.rig.world.release("snapshot");
            eventually("held operations end", || s.host.operations_in_flight() == 0).await;
        }
    }
}

/// The two rules that apply to every row of §12.2: a stale token is `REVISION_CONFLICT`, and a
/// sandbox that does not exist is `NOT_FOUND`.
#[tokio::test]
async fn t_state_02_a_stale_token_is_a_revision_conflict_for_every_lifecycle_method() {
    let s = scene(Given::Ready).await;
    for method in ["sandbox.start", "exec.run", "snapshot.create", "snapshot.restore", "sandbox.stop", "sandbox.destroy"] {
        let mut stale = params(method, &s);
        let wrong = json!(s.sb.generation.0 + 1);
        if method == "snapshot.restore" {
            stale["target"]["expected_generation"] = wrong;
        } else {
            stale["expected_generation"] = wrong;
        }
        assert_eq!(s.a.refused(method, stale).await.class, FailureClass::RevisionConflict, "{method}");
        let mut absent = params(method, &s);
        let nobody = json!("sbx-00000000000000000000000000000000");
        if method == "snapshot.restore" {
            absent["target"]["sandbox_id"] = nobody;
        } else {
            absent["sandbox_id"] = nobody;
        }
        assert_eq!(s.a.refused(method, absent).await.class, FailureClass::NotFound, "{method}");
    }
    assert_eq!(s.a.inspect(&s.sb.sandbox_id).await.revision, s.sb.revision, "nothing changed");
}

/// A deterministic pseudo-random sequence (xorshift): the same seed replays the same history.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// T-STATE-03: J-1 … J-8 hold after every commit under random operations, random crashes at every
/// fault point, restarts with recovery, lost runtimes and sweeps. The rig checks the invariants
/// after **every commit** of every activation; this test supplies the history.
#[tokio::test]
async fn t_state_03_the_joint_state_invariants_hold_after_every_commit_under_random_operations_and_faults() {
    const POINTS: [FaultPoint; 5] = [
        FaultPoint::BeforeJournalWrite,
        FaultPoint::AfterJournalBeforeMutation,
        FaultPoint::BeforeBackendStep,
        FaultPoint::AfterBackendMutationBeforeCommit,
        FaultPoint::AfterTerminalCommitBeforeResponse,
    ];
    for seed in [0x9E37_79B9_7F4A_7C15u64, 0xD1B5_4A32_D192_ED03, 0x2545_F491_4F6C_DD1D] {
        let rig = Rig::new();
        let mut host = rig.serving().await;
        let mut rng = Rng(seed);
        let mut history = Vec::new();
        for step in 0..160 {
            let a = alice(&host);
            let sandboxes = a.sandboxes(json!({})).await.items;
            let snapshots = a.snapshots(json!({})).await.items;
            let pick = |rng: &mut Rng| (!sandboxes.is_empty()).then(|| sandboxes[rng.below(sandboxes.len())].clone());
            let action = rng.below(13);
            // One time in five the operation is cut short at a random fault point, and the core "dies".
            let crash = rng.below(5) == 0 && action < 9;
            if crash {
                host.faults.arm(POINTS[rng.below(POINTS.len())], "*");
            }
            let what = match (action, pick(&mut rng)) {
                (0 | 1, _) => {
                    a.call("sandbox.create", create_params(None)).await;
                    "create"
                }
                (2, Some(sb)) => {
                    a.call("sandbox.start", target(&sb)).await;
                    "start"
                }
                (3 | 4, Some(sb)) => {
                    a.call("exec.run", exec_params(&sb, &["/bin/true"])).await;
                    "exec"
                }
                (5, Some(sb)) => {
                    a.call("snapshot.create", target(&sb)).await;
                    "snapshot.create"
                }
                (6, Some(sb)) if !snapshots.is_empty() => {
                    let snap = &snapshots[rng.below(snapshots.len())];
                    let tgt = if rng.below(2) == 0 {
                        json!({"kind": "new"})
                    } else {
                        json!({"kind": "existing", "sandbox_id": sb.sandbox_id, "expected_generation": sb.generation})
                    };
                    a.call("snapshot.restore", json!({"snapshot": snap.snapshot, "target": tgt})).await;
                    "snapshot.restore"
                }
                (7, Some(sb)) => {
                    a.call("sandbox.stop", target(&sb)).await;
                    "stop"
                }
                (8, Some(sb)) => {
                    a.call("sandbox.destroy", target(&sb)).await;
                    "destroy"
                }
                (9, _) if !snapshots.is_empty() => {
                    a.call("snapshot.delete", json!({"snapshot": snapshots[rng.below(snapshots.len())].snapshot})).await;
                    "snapshot.delete"
                }
                (10, Some(sb)) => {
                    rig.world.set_phase(&jail(&sb), crate::backend::VmmState::Absent);
                    "runtime lost"
                }
                (11, _) => {
                    host.sweep_once().await;
                    "sweep"
                }
                _ => {
                    rig.clock.advance_ms(30_000);
                    "time passes"
                }
            };
            history.push(format!("{step}: {what}{}", if crash { " (crash)" } else { "" }));
            if crash {
                host.faults.disarm_all();
                drop(host);
                host = rig.serving().await;
                history.push(format!("{step}: restart and recover"));
            }
            let bad = host.journal.read(|s| crate::testing::invariants::violations(s, &host.cfg)).unwrap();
            assert!(bad.is_empty(), "seed {seed:#x}: {bad:?}\nhistory:\n  {}", history.join("\n  "));
        }
        // Whatever happened, the owner can still remove everything, and then nothing is leased.
        let a = alice(&host);
        host.sweep_once().await;
        for sb in a.sandboxes(json!({})).await.items {
            let resp = a.call("sandbox.destroy", target(&sb)).await;
            assert!(
                resp.operation_view().is_some() || resp.refusal().is_some_and(|r| r.class == FailureClass::Quarantined),
                "{:?}",
                resp.answer
            );
        }
        let quarantined = host.journal.read(|s| s.live_generations().filter(|g| g.quarantined.is_some()).count()).unwrap();
        let leased = host.journal.read(|s| s.live_generations().count()).unwrap();
        assert_eq!(
            leased,
            quarantined,
            "seed {seed:#x}: every lease that remains belongs to a quarantined generation\n  {}",
            history.join("\n  ")
        );
        rig.assert_invariants();
    }
}

fn not_serving(resp: &crate::api::ResponseEnvelope) -> bool {
    resp.refusal().is_some_and(|r| r.class == FailureClass::HostNotServing)
}

/// T-STATE-04: every host mode × every method against §12.6. A refusal caused by the mode has class
/// `HOST_NOT_SERVING` (HM-1); anything else — including another refusal — means the method was served.
#[tokio::test]
async fn t_state_04_every_host_mode_serves_exactly_the_classes_the_mode_table_says() {
    async fn check(host: &Arc<Host>, mode: HostMode) {
        assert_eq!(host.mode(), mode);
        for &method in Method::ALL {
            let resp = ops(host).call(method.name(), valid_params(method)).await;
            assert_eq!(not_serving(&resp), !mode.admits(method.class()), "{method} ({:?}) in {mode:?}: {:?}", method.class(), resp.answer);
        }
        assert_eq!(host.mode(), mode, "none of these changed the mode");
    }

    // STARTING: recovery has not finished. Nothing is served; no endpoint would even be open.
    let rig = Rig::new();
    let starting = rig.boot();
    check(&starting, HostMode::Starting).await;
    drop(starting);

    // DRAINING: asked for by an operator.
    let rig = Rig::new();
    let host = rig.serving().await;
    ops(&host).done("host.set_mode", json!({"mode": "DRAINING"})).await;
    check(&host, HostMode::Draining).await;
    assert_eq!(alice(&host).refused("sandbox.create", create_params(None)).await.class, FailureClass::HostNotServing);
    // ...and left again the same way.
    ops(&host).done("host.set_mode", json!({"mode": "SERVING"})).await;
    assert_eq!(host.mode(), HostMode::Serving);
    alice(&host).create(None).await;

    // CONTAINMENT: a failed mandatory check. It cannot be left by asking.
    let rig = Rig::new();
    let host = rig.boot_with(vec![ContainmentReason::MandatoryCheck("kvm: /dev/kvm is not accessible".into())]);
    host.recover().await.unwrap();
    host.finish_starting();
    check(&host, HostMode::Containment).await;
    assert_eq!(ops(&host).refused("host.set_mode", json!({"mode": "SERVING"})).await.class, FailureClass::StateConflict);
    let info = ops(&host).info().await;
    assert!(format!("{:?}", info.containment_reasons).contains("/dev/kvm"), "the host says why: {:?}", info.containment_reasons);

    // READ_ONLY: the store cannot be interpreted. Reads are served; nothing else is.
    let rig = Rig::new();
    let host = rig.serving().await;
    alice(&host).ready(None).await;
    drop(host);
    let store = rig.cfg.journal_path();
    let mut bytes = std::fs::read(&store).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0xFF; // corruption that is not a torn tail
    std::fs::write(&store, bytes).unwrap();
    let host = rig.boot();
    assert!(host.recover().await.unwrap().notes.iter().any(|n| n.contains("cannot be written")));
    host.finish_starting();
    check(&host, HostMode::ReadOnly).await;
    let info = ops(&host).info().await;
    assert!(info.read_only_reason.is_some(), "the host says why");

    // The table in one place, so a change to it is a change to this test.
    use OperationClass::{Containment, Granting, Operator, Read};
    let table = [
        (HostMode::Starting, [false, false, false, false]),
        (HostMode::Serving, [true, true, true, true]),
        (HostMode::Draining, [false, true, true, true]),
        (HostMode::Containment, [false, true, true, true]),
        (HostMode::ReadOnly, [false, false, true, false]),
    ];
    for (mode, row) in table {
        for (class, served) in [Granting, Containment, Read, Operator].into_iter().zip(row) {
            assert_eq!(mode.admits(class), served, "{mode:?} × {class:?}");
        }
    }
    let _ = sandbox_of;
}
