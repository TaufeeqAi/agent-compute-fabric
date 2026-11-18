//! T-REC: observation and recovery (contract §16), and T-OP-05: for every fault point of every
//! operation type, the terminal state, `effect` and `cleanup` are what §11.3, §13 and §16.2 say.
//!
//! A crash is modelled as the operation's task ending at a named point without running anything
//! that would have followed, after which the coordinator is dropped and a new activation is built
//! over the same store and the same world. T-REC-01 (every row of the decision table as a unit test
//! of the pure function) is in `recovery/decision.rs`.

use serde_json::{Value, json};

use crate::{
    api::{OperationResult, OperationView, SandboxView, SnapshotView},
    backend::VmmState,
    coordinator::Host,
    domain::{Cleanup, ContainmentReason, Effect, HostMode, Issuer, LifecycleState, OperationState, OperationType, SnapshotState},
    error::AcfError,
    error::FailureClass,
    ids::{Generation, OperationId, SandboxId, SandboxRef},
    testing::{
        fake_backend::Fail,
        fault::FaultPoint,
        rig::{Client, Rig, alice, calls, create_params, exec_params, footprint, ops, snapshot_of, target},
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Create,
    Start,
    Exec,
    SnapshotCreate,
    RestoreNew,
    RestoreInPlace,
    Stop,
    Destroy,
    SnapshotDelete,
}

const KINDS: [Kind; 9] = [
    Kind::Create,
    Kind::Start,
    Kind::Exec,
    Kind::SnapshotCreate,
    Kind::RestoreNew,
    Kind::RestoreInPlace,
    Kind::Stop,
    Kind::Destroy,
    Kind::SnapshotDelete,
];

use FaultPoint::{
    AfterBackendMutationBeforeCommit as AfterStep, AfterJournalBeforeMutation as AfterBegin,
    AfterTerminalCommitBeforeResponse as AfterFinish, BeforeBackendStep as BeforeStep, BeforeJournalWrite as BeforeBegin,
};

/// What is true after the crash, a restart and recovery.
#[derive(Debug, PartialEq, Eq)]
struct After {
    /// The operation: `None` when BEGIN never became durable.
    op: Option<(OperationState, Option<Effect>, Option<Cleanup>)>,
    /// State of the generation the operation was about (the new one for a create or a restore).
    generation: Option<LifecycleState>,
    /// For a restore in place: the sandbox's current generation number.
    current: Option<u64>,
    /// State of the snapshot the operation was about.
    snapshot: Option<SnapshotState>,
    /// Runtimes alive in the world.
    runtimes: usize,
}

/// The contract's answer for (operation type, fault point). `switched`: the restore had committed
/// its switch.
fn contract(kind: Kind, point: FaultPoint, switched: bool) -> After {
    use Cleanup::{Complete, Pending};
    use Effect::{Applied, MayBeApplied, NotApplied};
    use LifecycleState as L;
    use OperationState::{Failed, Succeeded, Unknown};
    let none = |generation, snapshot, runtimes| After { op: None, generation, current: None, snapshot, runtimes };
    let undone = |generation, snapshot, runtimes| After {
        op: Some((Failed, Some(NotApplied), Some(Complete))),
        generation,
        current: None,
        snapshot,
        runtimes,
    };
    let done = |generation, snapshot, runtimes| After {
        op: Some((Succeeded, Some(Applied), None)),
        generation,
        current: None,
        snapshot,
        runtimes,
    };
    let ready_snapshot = Some(SnapshotState::Ready);
    match (kind, point) {
        // BEGIN never became durable: there is no operation, and nothing changed.
        (Kind::Create, BeforeBegin) => none(None, None, 0),
        (Kind::Start, BeforeBegin) => none(Some(L::Provisioning), None, 0),
        (Kind::Exec | Kind::Stop | Kind::Destroy, BeforeBegin) => none(Some(L::Ready), None, 1),
        (Kind::SnapshotCreate, BeforeBegin) => none(Some(L::Ready), None, 1),
        (Kind::RestoreNew, BeforeBegin) => none(None, ready_snapshot, 1),
        (Kind::RestoreInPlace, BeforeBegin) => After { current: Some(1), ..none(Some(L::Ready), ready_snapshot, 1) },
        (Kind::SnapshotDelete, BeforeBegin) => none(None, ready_snapshot, 1),

        // The terminal record is durable; only the response was lost.
        (Kind::Create, AfterFinish) => done(Some(L::Provisioning), None, 0),
        (Kind::Start, AfterFinish) => done(Some(L::Ready), None, 1),
        (Kind::Exec, AfterFinish) => done(Some(L::Completed), None, 1),
        (Kind::SnapshotCreate, AfterFinish) => done(Some(L::Ready), ready_snapshot, 1),
        (Kind::RestoreNew, AfterFinish) => done(Some(L::Ready), ready_snapshot, 2),
        (Kind::RestoreInPlace, AfterFinish) => After { current: Some(2), ..done(Some(L::Ready), ready_snapshot, 1) },

        // Containment is re-driven to completion, wherever it stopped (OP-19).
        (Kind::Stop, _) => done(Some(L::Stopped), None, 0),
        (Kind::Destroy, _) => done(Some(L::Destroyed), None, 0),
        (Kind::SnapshotDelete, _) => done(None, Some(SnapshotState::Deleted), 1),

        // A granting operation is never continued (OP-18): it is undone to proven absence...
        (Kind::Create, _) => undone(Some(L::Destroyed), None, 0),
        (Kind::Start, AfterStep) => After { op: Some((Failed, Some(MayBeApplied), Some(Pending))), ..none(Some(L::Failed), None, 0) },
        (Kind::Start, _) => undone(Some(L::Provisioning), None, 0),
        // ...or, for an execution, ended UNKNOWN with the runtime stopped. The command is never run again.
        (Kind::Exec, _) => After { op: Some((Unknown, Some(MayBeApplied), None)), ..none(Some(L::Failed), None, 0) },
        (Kind::SnapshotCreate, _) => undone(Some(L::Ready), Some(SnapshotState::Deleted), 1),
        (Kind::RestoreNew, _) if switched => done(Some(L::Ready), ready_snapshot, 2),
        (Kind::RestoreNew, _) => undone(Some(L::Destroyed), ready_snapshot, 1),
        (Kind::RestoreInPlace, _) if switched => After { current: Some(2), ..done(Some(L::Ready), ready_snapshot, 1) },
        (Kind::RestoreInPlace, _) => After {
            op: Some((Failed, Some(NotApplied), Some(Complete))),
            generation: Some(L::Destroyed),
            current: Some(1),
            snapshot: ready_snapshot,
            runtimes: 1,
        },
    }
}

struct Prepared {
    method: &'static str,
    params: Value,
    /// The sandbox the operation acts on (not for a create or a restore as new).
    sandbox: Option<SandboxView>,
    snapshot: Option<SnapshotView>,
}

async fn prepare(kind: Kind, a: &Client) -> Prepared {
    let with_snapshot = |sb: SandboxView| async move {
        let snap = snapshot_of(&a.done("snapshot.create", target(&sb)).await);
        (sb, snap)
    };
    match kind {
        Kind::Create => Prepared { method: "sandbox.create", params: create_params(None), sandbox: None, snapshot: None },
        Kind::Start => {
            let sb = a.create(None).await;
            Prepared { method: "sandbox.start", params: target(&sb), sandbox: Some(sb), snapshot: None }
        }
        Kind::Exec => {
            let sb = a.ready(None).await;
            Prepared { method: "exec.run", params: exec_params(&sb, &["/bin/true"]), sandbox: Some(sb), snapshot: None }
        }
        Kind::SnapshotCreate => {
            let sb = a.ready(None).await;
            Prepared { method: "snapshot.create", params: target(&sb), sandbox: Some(sb), snapshot: None }
        }
        Kind::RestoreNew => {
            let (_, snap) = with_snapshot(a.ready(None).await).await;
            Prepared {
                method: "snapshot.restore",
                params: json!({"snapshot": snap.snapshot, "target": {"kind": "new"}}),
                sandbox: None,
                snapshot: Some(snap),
            }
        }
        Kind::RestoreInPlace => {
            let (sb, snap) = with_snapshot(a.ready(None).await).await;
            let params = json!({"snapshot": snap.snapshot, "target": {"kind": "existing", "sandbox_id": sb.sandbox_id, "expected_generation": sb.generation}});
            Prepared { method: "snapshot.restore", params, sandbox: Some(sb), snapshot: Some(snap) }
        }
        Kind::Stop => {
            let sb = a.ready(None).await;
            Prepared { method: "sandbox.stop", params: target(&sb), sandbox: Some(sb), snapshot: None }
        }
        Kind::Destroy => {
            let sb = a.ready(None).await;
            Prepared { method: "sandbox.destroy", params: target(&sb), sandbox: Some(sb), snapshot: None }
        }
        Kind::SnapshotDelete => {
            let (_, snap) = with_snapshot(a.ready(None).await).await;
            Prepared { method: "snapshot.delete", params: json!({"snapshot": snap.snapshot}), sandbox: None, snapshot: Some(snap) }
        }
    }
}

fn generation_state(host: &Host, id: &SandboxId, generation: Generation) -> Option<LifecycleState> {
    host.journal.read(|s| s.generations.get(&(id.clone(), generation)).map(|g| g.state)).unwrap()
}

fn operation(host: &Host, id: &OperationId) -> Option<crate::store::OperationRecord> {
    host.journal.read(|s| s.operations.values().find(|o| o.operation_id == *id).cloned()).unwrap()
}

/// Every runtime alive in the world belongs to a generation whose record says it may have one.
fn no_runtime_is_unaccounted_for(rig: &Rig, host: &Host, case: &str) {
    let allowed: Vec<String> = host
        .journal
        .read(|s| {
            s.generations
                .values()
                .filter(|g| matches!(g.state, LifecycleState::Ready | LifecycleState::Completed))
                .map(|g| SandboxRef { sandbox_id: g.sandbox_id.clone(), generation: g.generation }.jail_id())
                .collect()
        })
        .unwrap();
    for jail in rig.world.jail_ids() {
        assert!(allowed.contains(&jail), "{case}: runtime {jail} is alive but no READY or COMPLETED generation owns it");
    }
}

/// Crash `kind` at `point` (in `step`), restart, recover, and report what is true afterwards.
async fn crash_and_recover(kind: Kind, point: FaultPoint, step: &str) -> After {
    let case = format!("{kind:?} crashed at {point:?} ({step})");
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let p = prepare(kind, &a).await;
    let env = a.envelope(p.method, p.params.clone());
    let id = env.operation_id.clone().unwrap();

    host.faults.arm(point, step);
    let _lost = a.send(env).await; // whatever was answered is lost with the process
    assert!(host.journal.read(|s| s.open().count()).unwrap() <= 1, "{case}");
    rig.world.clear_calls();
    drop(a);
    drop(host);

    // A new activation over the same store and the same world.
    let host = rig.boot();
    let report = host.recover().await.unwrap_or_else(|e| panic!("{case}: recovery failed: {e}"));
    host.finish_starting();
    assert!(report.notes.is_empty(), "{case}: {:?}", report.notes);

    // T-REC-03: recovery issued no privilege-creating step for an inherited operation.
    for forbidden in ["provision", "start", "restore", "exec", "snapshot"] {
        assert_eq!(calls(&rig.world, forbidden), 0, "{case}: recovery called the backend's `{forbidden}`");
    }
    no_runtime_is_unaccounted_for(&rig, &host, &case);

    let record = operation(&host, &id);
    let view = match &record {
        Some(_) => Some(alice(&host).get(&id).await),
        None => {
            assert_eq!(alice(&host).refused("operation.get", json!({"operation_id": id})).await.class, FailureClass::NotFound, "{case}");
            None
        }
    };
    if let Some(v) = &view {
        assert!(v.state.is_terminal(), "{case}: recovery left the operation {:?}", v.state);
        // §11.3: `effect` follows from the terminal state and `cleanup`, whatever the path.
        let effect = match (v.state, v.cleanup) {
            (OperationState::Succeeded, _) => Effect::Applied,
            (OperationState::Unknown, _) => Effect::MayBeApplied,
            (_, Some(Cleanup::Complete)) if !(v.operation_type.is_execution() && record.as_ref().is_some_and(|r| r.execution_started)) => {
                Effect::NotApplied
            }
            _ => Effect::MayBeApplied,
        };
        assert_eq!(v.effect, Some(effect), "{case}");
        assert_ne!(
            (v.state, v.operation_type.is_execution()),
            (OperationState::Unknown, false),
            "{case}: only an execution may end UNKNOWN (FS-4)"
        );
    }

    // The generation and snapshot the operation was about.
    let about = match (&p.sandbox, &record, kind) {
        (_, Some(r), Kind::Create | Kind::RestoreNew) => r.sandbox.clone(),
        (Some(sb), _, Kind::RestoreInPlace) => Some((sb.sandbox_id.clone(), sb.generation.next())),
        (Some(sb), _, _) => Some((sb.sandbox_id.clone(), sb.generation)),
        _ => None,
    };
    let mut generation = about.as_ref().and_then(|(id, g)| generation_state(&host, id, *g));
    let mut current = None;
    if kind == Kind::RestoreInPlace {
        let sb = p.sandbox.as_ref().unwrap();
        let now = alice(&host).inspect(&sb.sandbox_id).await;
        current = Some(now.generation.0);
        if generation.is_none() {
            generation = Some(now.state); // BEGIN never happened: no new generation was allocated
        } else if now.generation == sb.generation {
            assert_eq!(now.state, LifecycleState::Ready, "{case}: the old generation is current and intact (RE-6)");
            assert_eq!(generation_state(&host, &sb.sandbox_id, sb.generation), Some(LifecycleState::Ready));
        } else {
            assert_eq!(
                generation_state(&host, &sb.sandbox_id, sb.generation),
                Some(LifecycleState::Destroyed),
                "{case}: the superseded generation is retired (RE-5)"
            );
        }
    }
    let snapshot = match (&p.snapshot, &record, kind) {
        (Some(s), _, _) => host
            .journal
            .read(|st| st.snapshots.get(&(s.snapshot.snapshot_id.clone(), s.snapshot.snapshot_generation)).map(|x| x.state))
            .unwrap(),
        (None, Some(r), Kind::SnapshotCreate) => r.snapshot.as_ref().and_then(|s| {
            host.journal.read(|st| st.snapshots.get(&(s.snapshot_id.clone(), s.snapshot_generation)).map(|x| x.state)).unwrap()
        }),
        _ => None,
    };
    if kind == Kind::SnapshotCreate && snapshot != Some(SnapshotState::Ready) {
        assert!(alice(&host).snapshots(json!({})).await.items.is_empty(), "{case}: a partial snapshot is never listed");
        assert_eq!(footprint(&host).2, 0, "{case}: its quota is released");
    }
    let after = After { op: view.map(|v| (v.state, v.effect, v.cleanup)), generation, current, snapshot, runtimes: rig.world.vm_count() };

    // RC-7 / idempotence: a second restart finds nothing left to resolve and changes nothing.
    let seq = host.journal.last_seq();
    drop(host);
    let host = rig.boot();
    let again = host.recover().await.unwrap();
    assert_eq!((again.examined, again.contained, again.quarantined), (0, 0, 0), "{case}: the second recovery found work: {again:?}");
    // The only records a quiet activation writes are its own activation and profile entries.
    assert!(host.journal.last_seq() <= seq + 1, "{case}: a quiet recovery wrote {} commits", host.journal.last_seq() - seq);
    after
}

/// T-OP-05 and T-REC-02: every operation type × every fault point.
#[tokio::test]
async fn t_op_05_t_rec_02_every_fault_point_of_every_operation_type_ends_as_the_contract_says() {
    for kind in KINDS {
        for point in [BeforeBegin, AfterBegin, BeforeStep, AfterStep, AfterFinish] {
            // `snapshot.delete` has no backend step: it removes files the coordinator owns.
            if kind == Kind::SnapshotDelete && matches!(point, BeforeStep | AfterStep) {
                continue;
            }
            // The restore's own step is named, because it has a second "after step" point (the switch).
            let step = if matches!(kind, Kind::RestoreNew | Kind::RestoreInPlace) && point == AfterStep { "restore" } else { "*" };
            let got = crash_and_recover(kind, point, step).await;
            assert_eq!(got, contract(kind, point, false), "{kind:?} crashed at {point:?}");
        }
    }
}

/// T-REC-09: a restore interrupted before the switch leaves the old generation current and intact;
/// interrupted after the switch, the restore has happened and the old generation is retired.
#[tokio::test]
async fn t_rec_09_a_restore_interrupted_before_or_after_its_switch() {
    for kind in [Kind::RestoreInPlace, Kind::RestoreNew] {
        let before = crash_and_recover(kind, AfterStep, "restore").await;
        assert_eq!(before, contract(kind, AfterStep, false), "{kind:?} before the switch");
        let after = crash_and_recover(kind, AfterStep, "restore_switch").await;
        assert_eq!(after, contract(kind, AfterStep, true), "{kind:?} after the switch");
    }
}

/// T-REC-03: observation writes nothing (OB-3). A sweep over a healthy host commits nothing and
/// asks the backend only to observe.
#[tokio::test]
async fn t_rec_03_observation_causes_no_write_and_no_backend_mutation() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    a.ready(None).await;
    let idle = a.ready(None).await;
    a.exec(&idle, &["/bin/true"]).await;
    a.create(None).await;
    let stopped = a.ready(None).await;
    a.done("sandbox.stop", target(&stopped)).await;

    let seq = host.journal.last_seq();
    rig.world.clear_calls();
    for _ in 0..3 {
        let report = host.sweep_once().await;
        assert_eq!((report.contained, report.quarantined, report.examined), (0, 0, 0), "{report:?}");
        assert_eq!(report.adopted, 2, "the READY and the COMPLETED generation are adopted as they are");
    }
    assert_eq!(host.journal.last_seq(), seq, "three sweeps of a healthy host wrote nothing");
    let asked: std::collections::BTreeSet<String> = rig.world.calls().into_iter().collect();
    assert!(asked.iter().all(|c| c == "observe"), "{asked:?}");
}

fn jail(sb: &SandboxView) -> String {
    SandboxRef { sandbox_id: sb.sandbox_id.clone(), generation: sb.generation }.jail_id()
}

/// T-REC-04 (L2 analogue): a recorded process id now held by something else, and a forged, missing
/// or copied ownership marker → nothing foreign is signalled, nothing is deleted, and the
/// generation is quarantined or failed with its lease kept.
#[tokio::test]
async fn t_rec_04_nothing_is_signalled_or_deleted_without_proof_of_ownership() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);

    // The recorded process id is held by another process (pid reuse): FOREIGN is never signalled.
    let reused = a.ready(None).await;
    rig.world.make_foreign(&jail(&reused));
    rig.world.clear_calls();
    host.sweep_once().await;
    assert_eq!(calls(&rig.world, "stop"), 0, "a process that is not the recorded runtime is never signalled");
    assert!(rig.world.foreign_alive(&jail(&reused)), "it is still running");
    let now = a.inspect(&reused.sandbox_id).await;
    assert_eq!(now.state, LifecycleState::Failed);
    assert_eq!(footprint(&host).1, 1, "the lease is kept (LS-1)");
    // A destroy removes what is provably ours (the directory, under its marker). The unrelated
    // process that holds the old pid is refused by identity and survives.
    a.done("sandbox.destroy", target(&now)).await;
    assert!(rig.world.foreign_alive(&jail(&reused)), "the foreign process survives the destroy of the sandbox whose pid it reused");
    assert!(!rig.layout.generation_path(&reused.sandbox_id, reused.generation).exists());

    // A forged, a copied and a missing marker.
    let donor = a.ready(None).await;
    for tamper in ["forged", "copied", "missing"] {
        let sb = a.ready(None).await;
        let dir = rig.layout.generation_path(&sb.sandbox_id, sb.generation);
        match tamper {
            "forged" => rig.forge_marker(&sb),
            "copied" => {
                std::fs::copy(rig.layout.generation_path(&donor.sandbox_id, donor.generation).join("OWNER.json"), dir.join("OWNER.json"))
                    .unwrap();
            }
            _ => std::fs::remove_file(dir.join("OWNER.json")).unwrap(),
        }
        std::fs::write(dir.join("precious"), b"not ours to delete").unwrap();
        let op = a.op("sandbox.destroy", target(&sb)).await;
        assert_eq!((op.state, op.cleanup), (OperationState::Failed, Some(Cleanup::Quarantined)), "{tamper}");
        assert_eq!(op.failure.as_ref().map(|f| f.class), Some(FailureClass::Quarantined), "{tamper}");
        assert!(dir.join("precious").exists(), "{tamper}: nothing was deleted");
        let q = a.inspect(&sb.sandbox_id).await;
        assert!(q.quarantined.is_some(), "{tamper}");
        assert_eq!(a.refused("sandbox.destroy", target(&q)).await.class, FailureClass::Quarantined, "{tamper}: QR-1");
    }
    assert_eq!(a.info().await.quarantined, 3);
    // Quarantined generations keep their leases and count against capacity (QR-5).
    assert_eq!(footprint(&host).1, 4);
    assert_eq!(a.refused("sandbox.create", create_params(None)).await.class, FailureClass::ResourceExhausted);
}

/// T-REC-05: a resource with no record, or with another lineage's marker, is `UNMANAGED`: reported,
/// never modified (RC-3, LN-3).
#[tokio::test]
async fn t_rec_05_a_resource_no_record_owns_is_reported_and_never_modified() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let mine = a.ready(None).await;
    drop(host);

    // A directory nobody recorded, one with a marker of another store, and a stray entry.
    let sandboxes = rig.layout.root().join("sandboxes");
    let unknown = sandboxes.join("sbx-11111111111111111111111111111111").join("1");
    std::fs::create_dir_all(&unknown).unwrap();
    std::fs::write(unknown.join("data"), b"whose?").unwrap();
    let foreign = sandboxes.join("sbx-22222222222222222222222222222222").join("3");
    std::fs::create_dir_all(&foreign).unwrap();
    let marker = std::fs::read_to_string(rig.layout.generation_path(&mine.sandbox_id, mine.generation).join("OWNER.json")).unwrap();
    let mut marker: Value = serde_json::from_str(&marker).unwrap();
    marker["sandbox_id"] = json!("sbx-22222222222222222222222222222222");
    marker["generation"] = json!(3);
    marker["lineage"] = json!("another-store-entirely");
    std::fs::write(foreign.join("OWNER.json"), marker.to_string()).unwrap();
    std::fs::create_dir_all(sandboxes.join("lost+found")).unwrap();

    let host = rig.boot();
    rig.world.clear_calls();
    let report = host.recover().await.unwrap();
    host.finish_starting();
    assert_eq!(report.unmanaged, 3, "{report:?}");
    assert!(
        unknown.join("data").exists() && foreign.join("OWNER.json").exists() && sandboxes.join("lost+found").exists(),
        "nothing was modified"
    );
    assert_eq!(calls(&rig.world, "teardown") + calls(&rig.world, "stop") + calls(&rig.world, "force_teardown"), 0);
    assert_eq!(host.mode(), HostMode::Serving, "unmanaged resources are reported; they do not stop the host");
    assert_eq!(ops(&host).metrics().await["gauges"]["unmanaged_resources"], json!(3));
    let reports = host.journal.read(|s| s.quarantines.iter().filter(|q| q.unmanaged).count()).unwrap();
    assert_eq!(reports, 3);
    // Reporting is idempotent: another pass adds nothing.
    drop(host);
    let host = rig.serving().await;
    assert_eq!(host.journal.read(|s| s.quarantines.iter().filter(|q| q.unmanaged).count()).unwrap(), 3);
    // The sandbox the store does own is untouched and usable.
    assert_eq!(alice(&host).exec(&mine, &["/bin/true"]).await.state, OperationState::Succeeded);
}

/// T-REC-06: `quarantine.release` in both modes; refused when observation contradicts the
/// assertion; the lease is released only when absence is observed (QR-2 – QR-4).
#[tokio::test]
async fn t_rec_06_quarantine_release_acts_on_the_assertion_and_then_observes() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let (a, operator) = (alice(&host), ops(&host));
    let quarantine = |sb: SandboxView| {
        let (a, rig) = (&a, &rig);
        async move {
            rig.forge_marker(&sb);
            assert_eq!(a.op("sandbox.destroy", target(&sb)).await.state, OperationState::Failed);
            a.inspect(&sb.sandbox_id).await
        }
    };
    let first = quarantine(a.ready(None).await).await;
    let second = quarantine(a.ready(None).await).await;
    let release = |sb: &SandboxView, mode: &str| json!({"sandbox_id": sb.sandbox_id, "generation": sb.generation, "mode": mode});
    assert_eq!(footprint(&host).1, 2);

    // Only an operator may release; and only a quarantined generation can be released.
    assert_eq!(a.refused("quarantine.release", release(&first, "FORCE_DESTROY")).await.class, FailureClass::AuthorizationDenied);
    let healthy = a.ready(None).await;
    assert_eq!(operator.refused("quarantine.release", release(&healthy, "FORCE_DESTROY")).await.class, FailureClass::StateConflict);

    // DECLARE_ABSENT while the directory is still there: observation contradicts the assertion.
    let contradicted = operator.op("quarantine.release", release(&first, "DECLARE_ABSENT")).await;
    assert_eq!((contradicted.state, contradicted.cleanup), (OperationState::Failed, Some(Cleanup::Quarantined)));
    assert_eq!(contradicted.failure.as_ref().map(|f| f.class), Some(FailureClass::Quarantined));
    assert!(
        matches!(&contradicted.result, Some(OperationResult::Host(h)) if h.note.as_deref().is_some_and(|n| n.contains("DeclareAbsent") && n.contains("generation directory"))),
        "{:?}",
        contradicted.result
    );
    assert!(a.inspect(&first.sandbox_id).await.quarantined.is_some(), "it stays quarantined");
    assert_eq!(footprint(&host).1, 3, "and keeps its lease");
    assert!(rig.layout.generation_path(&first.sandbox_id, first.generation).exists(), "nothing was removed on a false assertion");

    // FORCE_DESTROY: the operator asserts the resources are this host's; the host removes them and verifies.
    let forced = operator.done("quarantine.release", release(&first, "FORCE_DESTROY")).await;
    assert_eq!(forced.operation_type, OperationType::QuarantineRelease);
    assert_eq!(forced.tags.peer_id.as_str(), "ops", "the operator's peer id is recorded (QR-4)");
    assert!(
        matches!(&forced.result, Some(OperationResult::Host(h)) if h.note.as_deref().is_some_and(|n| n.contains("ForceDestroy") && n.contains("found after: nothing"))),
        "{:?}",
        forced.result
    );
    let released = operator.inspect(&first.sandbox_id).await;
    assert_eq!((released.state, released.quarantined.clone()), (LifecycleState::Destroyed, None));
    assert!(!rig.layout.generation_path(&first.sandbox_id, first.generation).exists());
    assert_eq!(footprint(&host).1, 2, "the lease is released only now");

    // DECLARE_ABSENT after the operator removed what was left: the host verifies, and agrees.
    std::fs::remove_dir_all(rig.layout.generation_path(&second.sandbox_id, second.generation)).unwrap();
    operator.done("quarantine.release", release(&second, "DECLARE_ABSENT")).await;
    assert_eq!(operator.inspect(&second.sandbox_id).await.state, LifecycleState::Destroyed);
    assert_eq!((footprint(&host).1, a.info().await.quarantined), (1, 0));

    // A release interrupted by a crash, on a generation whose ownership cannot be proven: the first
    // row of the decision table wins over every other (§16.2). Recovery does not act on the
    // assertion by itself; the operation ends FAILED, the generation stays quarantined, and the
    // operator issues the release again.
    let third = quarantine(a.ready(None).await).await;
    rig.world.fail_next("residue", Fail::Before(AcfError::simulated_crash("during the release")));
    let env = operator.envelope("quarantine.release", release(&third, "FORCE_DESTROY"));
    let id = env.operation_id.clone().unwrap();
    let _ = operator.send(env).await; // the core dies right after declaring the assertion
    let inherited = operator.get(&id).await;
    assert_eq!(
        (inherited.state, inherited.step.as_deref()),
        (OperationState::InProgress, Some("release_force_destroy")),
        "the assertion is durable before anything is done (QR-4)"
    );
    let next = rig.serving().await;
    let (a, operator) = (alice(&next), ops(&next));
    let ended = operator.get(&id).await;
    assert_eq!((ended.state, ended.failure.as_ref().map(|f| f.class)), (OperationState::Failed, Some(FailureClass::Quarantined)));
    assert!(operator.inspect(&third.sandbox_id).await.quarantined.is_some());
    assert!(rig.layout.generation_path(&third.sandbox_id, third.generation).exists(), "recovery removed nothing");
    operator.done("quarantine.release", release(&third, "FORCE_DESTROY")).await;
    assert_eq!(operator.inspect(&third.sandbox_id).await.state, LifecycleState::Destroyed);

    // A generation quarantined because it could not be observed (its marker is intact): an
    // interrupted release of it is re-driven in the mode the operator chose.
    let unseen = a.ready(None).await;
    rig.world.set_unobservable(&jail(&unseen), true);
    for _ in 0..=next.cfg.recovery.max_attempts {
        next.sweep_once().await;
    }
    assert!(a.inspect(&unseen.sandbox_id).await.quarantined.is_some(), "unobservable for too long: quarantined");
    rig.world.set_unobservable(&jail(&unseen), false);
    rig.world.fail_next("residue", Fail::Before(AcfError::simulated_crash("during the release")));
    let env = operator.envelope("quarantine.release", release(&unseen, "FORCE_DESTROY"));
    let id = env.operation_id.clone().unwrap();
    let _ = operator.send(env).await;
    let last = rig.serving().await;
    let operator = ops(&last);
    assert_eq!(operator.get(&id).await.state, OperationState::Succeeded);
    assert_eq!(operator.inspect(&unseen.sandbox_id).await.state, LifecycleState::Destroyed);
    assert_eq!(rig.world.vm_count(), 1, "only the healthy sandbox still runs");
}

/// T-REC-07: a record whose recovery crashes the core is quarantined after `recovery_max_attempts`,
/// across restarts; the host then serves (RC-4).
#[tokio::test]
async fn t_rec_07_a_record_whose_recovery_crashes_the_core_is_quarantined_after_the_bound() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let sb = a.ready(None).await;
    let healthy = a.ready(None).await;
    // An execution is interrupted by a crash.
    host.faults.arm(AfterStep, "exec");
    let env = a.envelope("exec.run", exec_params(&sb, &["/bin/true"]));
    let id = env.operation_id.clone().unwrap();
    let _ = a.send(env).await;
    drop(a);
    drop(host);

    // Every activation that tries to recover it dies while doing so.
    let max = rig.cfg.recovery.max_attempts;
    for attempt in 1..=max {
        let host = rig.boot();
        host.faults.arm(AfterBegin, "recover");
        let died = host.recover().await.unwrap_err();
        assert!(died.is_simulated_crash(), "attempt {attempt}: {died}");
        let rec = operation(&host, &id).unwrap();
        assert_eq!(rec.state, OperationState::Recovering, "attempt {attempt}");
        let attempts = host.journal.read(|s| s.recoveries.values().map(|r| r.attempt_count).max()).unwrap();
        assert_eq!(attempts, Some(attempt), "the attempt is counted durably before it is made");
    }

    // The next activation does not try again: it quarantines, and serves.
    let host = rig.boot();
    let report = host.recover().await.unwrap();
    host.finish_starting();
    assert_eq!((report.quarantined, host.mode()), (1, HostMode::Serving), "{report:?}");
    let a = alice(&host);
    let op = a.get(&id).await;
    assert_eq!(op.state, OperationState::Unknown, "an execution whose outcome cannot be established is UNKNOWN, quarantined or not");
    let q = a.inspect(&sb.sandbox_id).await;
    assert!(q.quarantined.as_deref().is_some_and(|r| r.contains("attempted")), "{:?}", q.quarantined);
    assert_eq!(footprint(&host).1, 2, "the quarantined generation keeps its lease");
    // Everything else works.
    assert_eq!(a.exec(&healthy, &["/bin/true"]).await.state, OperationState::Succeeded);
    a.create(None).await;
}

/// T-REC-08 (L2 analogue): an interrupted snapshot whose runtime also died → the generation is
/// `FAILED`; no partial snapshot is listed; the quota is released.
#[tokio::test]
async fn t_rec_08_an_interrupted_snapshot_whose_runtime_is_gone_fails_the_generation() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let sb = a.ready(None).await;
    host.faults.arm(AfterStep, "snapshot");
    let env = a.envelope("snapshot.create", target(&sb));
    let id = env.operation_id.clone().unwrap();
    let _ = a.send(env).await;
    assert_eq!(a.inspect(&sb.sandbox_id).await.state, LifecycleState::Paused);
    drop(a);
    drop(host);
    rig.world.set_phase(&jail(&sb), VmmState::Absent); // the VMM died with the host

    let host = rig.serving().await;
    let a = alice(&host);
    let op = a.get(&id).await;
    assert_eq!(op.state, OperationState::Failed);
    assert_eq!((op.effect, op.cleanup), (Some(Effect::MayBeApplied), Some(Cleanup::Pending)), "a FAILED generation remains");
    assert_eq!(a.inspect(&sb.sandbox_id).await.state, LifecycleState::Failed);
    assert!(a.snapshots(json!({})).await.items.is_empty());
    assert_eq!(footprint(&host), (footprint(&host).0, 1, 0), "the snapshot quota is released; the generation keeps its lease");
}

/// T-REC-10: a store older than the ownership markers on disk → `CONTAINMENT`, no destructive
/// action, and `host.acknowledge` leaves the mode (LN-1 – LN-4).
#[tokio::test]
async fn t_rec_10_a_store_older_than_the_system_it_describes() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let old = a.ready(Some("recorded")).await;
    let store = rig.cfg.journal_path();
    let backup = rig.dir.path().join("store.backup");
    std::fs::copy(&store, &backup).unwrap();
    let newer = a.ready(Some("after-the-backup")).await;
    drop(a);
    drop(host);

    // An operator restores yesterday's store. The sandbox created since then is still on the host.
    std::fs::copy(&backup, &store).unwrap();
    let host = rig.boot();
    rig.world.clear_calls();
    let report = host.recover().await.unwrap();
    host.finish_starting();
    assert_eq!(host.mode(), HostMode::Containment);
    assert!(
        host.containment_reasons().iter().any(|r| matches!(r, ContainmentReason::StoreRegression(_))),
        "{:?}",
        host.containment_reasons()
    );
    assert!(report.notes.iter().any(|n| n.contains("host.acknowledge")), "{:?}", report.notes);
    // No destructive action: nothing was stopped or removed, not even what the store does describe.
    assert_eq!(calls(&rig.world, "stop") + calls(&rig.world, "teardown"), 0);
    assert_eq!(rig.world.vm_count(), 2);
    assert!(rig.layout.generation_path(&newer.sandbox_id, newer.generation).exists());
    for _ in 0..2 {
        host.sweep_once().await; // the sweep takes no destructive action either
    }
    assert_eq!(calls(&rig.world, "stop") + calls(&rig.world, "teardown"), 0);
    let (a, operator) = (alice(&host), ops(&host));
    assert_eq!(a.refused("sandbox.create", create_params(None)).await.class, FailureClass::HostNotServing);
    assert_eq!(a.sandboxes(json!({})).await.items.len(), 1, "reads are served from the store as it is");
    // It cannot be left by asking for SERVING, and a caller cannot acknowledge.
    assert_eq!(operator.refused("host.set_mode", json!({"mode": "SERVING"})).await.class, FailureClass::StateConflict);
    assert_eq!(a.refused("host.acknowledge", json!({"condition": "store_regression"})).await.class, FailureClass::AuthorizationDenied);

    // The operator accepts the store as authoritative.
    let marker_seq = {
        let text = std::fs::read_to_string(rig.layout.generation_path(&newer.sandbox_id, newer.generation).join("OWNER.json")).unwrap();
        serde_json::from_str::<Value>(&text).unwrap()["created_seq"].as_u64().unwrap()
    };
    let ack = operator.done("host.acknowledge", json!({"condition": "store_regression"})).await;
    assert_eq!(ack.operation_type, OperationType::HostAcknowledge);
    assert!(
        matches!(&ack.result, Some(OperationResult::Host(h)) if h.mode == Some(HostMode::Serving) && h.note.as_deref().is_some_and(|n| n.contains("1 unmanaged"))),
        "{:?}",
        ack.result
    );
    assert_eq!(host.mode(), HostMode::Serving);
    assert!(host.journal.last_seq() > marker_seq, "every new record sorts after every marker on disk");
    // What the store does not describe is UNMANAGED: reported and untouched (LN-4).
    assert!(rig.layout.generation_path(&newer.sandbox_id, newer.generation).exists());
    assert_eq!(rig.world.vm_count(), 2, "its runtime is not signalled; it ends at its expiry");
    assert_eq!(operator.metrics().await["gauges"]["unmanaged_resources"], json!(1));
    // RS-3: the identifier the unmanaged runtime carries is not handed out again.
    assert_eq!(a.exec(&old, &["/bin/true"]).await.state, OperationState::Succeeded);
    assert_eq!(
        operator.refused("host.acknowledge", json!({"condition": "store_regression"})).await.class,
        FailureClass::StateConflict,
        "nothing left to acknowledge"
    );
    let _ = (Generation::FIRST, Issuer::Host);
}

/// T-REC-11 (L2 analogue): a runtime killed while the host serves → the generation is `FAILED` at
/// the next observation, by a host-issued operation the owner can see; the lease is kept.
#[tokio::test]
async fn t_rec_11_a_runtime_lost_while_serving_fails_the_generation_and_keeps_the_lease() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let sb = a.ready(None).await;
    let other = a.ready(None).await;
    rig.world.set_phase(&jail(&sb), VmmState::Absent);

    let report = host.sweep_once().await;
    assert_eq!(report.contained, 1, "{report:?}");
    let now = a.inspect(&sb.sandbox_id).await;
    assert_eq!(now.state, LifecycleState::Failed);
    assert_eq!(now.failure.as_ref().map(|f| f.class), Some(FailureClass::DependencyUnavailable));
    assert_eq!(footprint(&host).1, 2, "the lease is kept until the sandbox is destroyed (LS-1)");
    assert_eq!(a.inspect(&other.sandbox_id).await.state, LifecycleState::Ready, "the other sandbox is not affected");

    // OP-24: the change was committed as an operation issued by the host, under the sandbox's tags.
    let by_host: Vec<OperationView> = a.operations(json!({})).await.items.into_iter().filter(|o| o.issuer == Issuer::Host).collect();
    assert_eq!(by_host.len(), 1);
    assert_eq!((by_host[0].operation_type, by_host[0].state), (OperationType::SandboxFail, OperationState::Succeeded));
    assert_eq!(by_host[0].sandbox, Some((sb.sandbox_id.clone(), sb.generation)));
    assert_eq!(ops(&host).metrics().await["counters"]["runtime_losses_detected"], json!(1));
    // OP-25: the host issues only containment. A FAILED generation is never started or repaired.
    assert_eq!(a.refused("exec.run", exec_params(&now, &["/bin/true"])).await.class, FailureClass::StateConflict);
    assert_eq!(calls(&rig.world, "start"), 2, "nothing was started again");
    // The next sweep changes nothing, and a destroy releases the lease.
    let seq = host.journal.last_seq();
    host.sweep_once().await;
    assert_eq!(host.journal.last_seq(), seq);
    a.done("sandbox.destroy", target(&now)).await;
    assert_eq!(footprint(&host).1, 1);
}

/// T-SEC-05 (L2 analogue; the catalog entry itself needs a real VMM): a mandatory control that is no
/// longer in force after launch ends the runtime, and the generation is `FAILED` with
/// `SECURITY_CONTROL_FAILURE`. Nothing is repaired in place. This holds for an idle sandbox, which
/// the sweep observes, and for one an operation holds, which that operation observes for itself
/// (IS-3, RC-6): an execution may run for as long as the profile allows, and must not hide the loss.
#[tokio::test]
async fn t_sec_05_a_control_lost_after_launch_ends_the_runtime_whether_the_sandbox_is_idle_or_held() {
    use crate::testing::rig::eventually;
    let rig = Rig::with(|c| {
        c.recovery.sweep_interval_ms = 50;
        c.recovery.runtime_loss_detection_ms = 50;
        c.recovery.posture_recheck_interval_ms = 2_000; // an operation looks every 500 ms
    });
    let host = rig.serving().await;
    let a = alice(&host);
    let failed_for_the_control = |v: &SandboxView| {
        assert_eq!(v.state, LifecycleState::Failed);
        assert_eq!(v.failure.as_ref().map(|f| f.class), Some(FailureClass::SecurityControlFailure));
    };

    // Idle: the next observation by the sweep finds it.
    let idle = a.ready(None).await;
    rig.world.degrade(&jail(&idle), &["memory.max is not the configured limit"]);
    let report = host.sweep_once().await;
    assert_eq!(report.contained, 1, "{report:?}");
    failed_for_the_control(&a.inspect(&idle.sandbox_id).await);
    assert_eq!(rig.world.vm_count(), 0, "the runtime was ended, not repaired");
    assert_eq!(footprint(&host).1, 1, "the lease is kept until the sandbox is destroyed (LS-1)");
    a.done("sandbox.destroy", target(&idle)).await;

    // Held by an execution whose guest never answers.
    let busy = a.ready(None).await;
    rig.world.hold("exec");
    let env = a.envelope("exec.run", exec_params(&busy, &["/bin/sleep", "infinity"]));
    let exec_id = env.operation_id.clone().unwrap();
    let hung = {
        let a = a.clone();
        tokio::spawn(async move { a.send(env).await })
    };
    eventually("the command reaches the guest", || rig.world.waiting("exec") == 1).await;
    rig.world.degrade(&jail(&busy), &["the packet filter is not the one that was loaded"]);
    // The sweep does not decide a sandbox that an operation holds...
    assert_eq!(host.sweep_once().await.contained, 0);
    assert_eq!(a.inspect(&busy.sandbox_id).await.state, LifecycleState::Running);
    // ...the operation does, within its watch period, without any answer from the guest.
    let answered = hung.await.unwrap().operation_view().cloned().unwrap();
    let exec = a.get(&exec_id).await;
    assert_eq!(answered.operation_id, exec.operation_id);
    assert_eq!(exec.state, OperationState::Unknown, "no result was obtained: the command may have run");
    assert_eq!(exec.effect, Some(Effect::MayBeApplied));
    failed_for_the_control(&a.inspect(&busy.sandbox_id).await);
    assert_eq!(rig.world.vm_count(), 0);
    assert_eq!(rig.world.waiting("exec"), 0, "the host let go of the guest call");
    rig.world.release("exec");
    a.done("sandbox.destroy", target(&busy)).await;

    // Held by a snapshot: the guest is paused for the capture. It is ended, never resumed.
    let paused = a.ready(None).await;
    rig.world.hold("snapshot");
    let env = a.envelope("snapshot.create", target(&paused));
    let snap_id = env.operation_id.clone().unwrap();
    let capturing = {
        let a = a.clone();
        tokio::spawn(async move { a.send(env).await })
    };
    eventually("the capture reaches the backend", || rig.world.waiting("snapshot") == 1).await;
    rig.world.degrade(&jail(&paused), &["the VMM's seccomp filter is gone"]);
    capturing.await.unwrap();
    let snap = a.get(&snap_id).await;
    assert_eq!(snap.state, OperationState::Failed);
    assert_eq!(snap.failure.as_ref().map(|f| f.class), Some(FailureClass::SecurityControlFailure));
    failed_for_the_control(&a.inspect(&paused.sandbox_id).await);
    assert_eq!(rig.world.vm_count(), 0, "a runtime whose control is lost is not resumed");
    assert!(a.snapshots(json!({})).await.items.is_empty(), "no partial snapshot is listed");
    rig.world.release("snapshot");
    a.done("sandbox.destroy", target(&paused)).await;

    // Held by a restore in place: the generation that is still current is the one being watched.
    let old = a.ready(None).await;
    let taken = snapshot_of(&a.done("snapshot.create", target(&old)).await);
    rig.world.hold("restore");
    let env = a.envelope(
        "snapshot.restore",
        json!({"snapshot": taken.snapshot, "target": {"kind": "existing", "sandbox_id": old.sandbox_id, "expected_generation": old.generation}}),
    );
    let restore_id = env.operation_id.clone().unwrap();
    let restoring = {
        let a = a.clone();
        tokio::spawn(async move { a.send(env).await })
    };
    eventually("the restore reaches the backend", || rig.world.waiting("restore") == 1).await;
    rig.world.degrade(&jail(&old), &["pids.max is not the configured limit"]);
    restoring.await.unwrap();
    let restore = a.get(&restore_id).await;
    assert_eq!(restore.state, OperationState::Failed);
    assert_eq!(restore.failure.as_ref().map(|f| f.class), Some(FailureClass::SecurityControlFailure));
    let still = a.inspect(&old.sandbox_id).await;
    assert_eq!(still.generation, old.generation, "the restore was abandoned: the old generation is still the current one (RE-6)");
    // The sandbox is idle again, so the sweep ends it like any other idle generation.
    assert_eq!(host.sweep_once().await.contained, 1);
    failed_for_the_control(&a.inspect(&old.sandbox_id).await);
    assert_eq!(rig.world.vm_count(), 0);
    rig.world.release("restore");

    let counters = ops(&host).metrics().await["counters"].clone();
    assert_eq!(counters["posture_failures_after_launch"], json!(5), "idle, exec, snapshot, restore, and the idle one after it: {counters}");
    assert_eq!(host.operations_in_flight(), 0);
}

/// T-REC-12: when `startup_recovery_deadline` passes, what is not yet resolved is quarantined and
/// the host leaves `STARTING` (RC-5).
#[tokio::test]
async fn t_rec_12_when_the_startup_recovery_deadline_passes_the_rest_is_quarantined() {
    let rig = Rig::with(|c| c.recovery.startup_deadline_ms = 10_000);
    let host = rig.serving().await;
    let a = alice(&host);
    let interrupted: Vec<SandboxView> = [a.ready(None).await, a.ready(None).await].into();
    let idle = a.ready(None).await;
    let mut ids = Vec::new();
    for sb in &interrupted {
        host.faults.arm(AfterStep, "exec");
        let env = a.envelope("exec.run", exec_params(sb, &["/bin/true"]));
        ids.push(env.operation_id.clone().unwrap());
        let _ = a.send(env).await;
    }
    drop(a);
    drop(host);

    // The first observation of the new activation takes longer than the whole deadline.
    let clock = rig.clock.clone();
    let slow = std::sync::atomic::AtomicBool::new(true);
    rig.world.on_call("observe", move || {
        if slow.swap(false, std::sync::atomic::Ordering::SeqCst) {
            clock.advance_ms(11_000);
        }
    });
    let host = rig.boot();
    let report = host.recover().await.unwrap();
    host.finish_starting();
    rig.world.clear_hooks();
    assert_eq!(host.mode(), HostMode::Serving, "the host leaves STARTING");
    let a = alice(&host);
    let states: Vec<OperationState> = [a.get(&ids[0]).await.state, a.get(&ids[1]).await.state].into();
    assert_eq!(states, vec![OperationState::Unknown, OperationState::Unknown], "both executions are resolved, one way or the other");
    let quarantined: Vec<bool> = [
        a.inspect(&interrupted[0].sandbox_id).await.quarantined.is_some(),
        a.inspect(&interrupted[1].sandbox_id).await.quarantined.is_some(),
        a.inspect(&idle.sandbox_id).await.quarantined.is_some(),
    ]
    .into();
    assert_eq!(
        quarantined.iter().filter(|q| **q).count(),
        2,
        "what the deadline cut off is quarantined, not worked on: {quarantined:?} {report:?}"
    );
    assert_eq!(report.quarantined, 2, "{report:?}");
    // Quarantine is not deletion: an operator can release, and the host serves meanwhile.
    assert_eq!(a.info().await.quarantined, 2);
}
