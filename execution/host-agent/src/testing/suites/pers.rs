//! T-PERS: the persistence contract (§23). T-PERS-01 and T-PERS-05 (store conformance, torn tail,
//! corruption; L1) are in `store/journal.rs`; the migration itself (L1) is in `store/migrate.rs`.

use std::sync::{Arc, Mutex};

use serde_json::json;

use crate::{
    app::{self, Assembly, TrustedInputs},
    domain::{Cleanup, Effect, HostMode, LifecycleState, OperationState},
    error::FailureClass,
    store::{Entry, Journal, StoreMeta},
    testing::{
        fake_backend::FakeBackend,
        rig::{Rig, alice, create_params, exec_params, footprint, ops, snapshot_of, target},
    },
};

/// T-PERS-02: no privileged effect without a prior durable declaration (OP-3, PS-2). At the moment
/// the backend is asked to create privilege, the store already holds a non-terminal operation whose
/// declared step names exactly that effect.
#[tokio::test]
async fn t_pers_02_every_privileged_step_is_declared_durably_before_it_runs() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let undeclared: Arc<Mutex<Vec<String>>> = Arc::default();
    for (method, step) in
        [("provision", "provision"), ("start", "launch"), ("exec", "exec"), ("snapshot", "snapshot"), ("restore", "restore")]
    {
        let (journal, undeclared) = (Arc::clone(&host.journal), Arc::clone(&undeclared));
        rig.world.on_call(method, move || {
            // What a reader of the store file would see at this instant.
            let declared =
                journal.read(|s| s.open().any(|o| o.state == OperationState::InProgress && o.step.as_deref() == Some(step))).unwrap();
            if !declared {
                undeclared.lock().unwrap().push(format!("the backend's `{method}` ran with no durable `{step}` step"));
            }
        });
    }
    let sb = a.ready(None).await;
    a.exec(&sb, &["/bin/true"]).await;
    let snap = snapshot_of(&a.done("snapshot.create", target(&sb)).await);
    a.done("snapshot.restore", json!({"snapshot": snap.snapshot, "target": {"kind": "existing", "sandbox_id": sb.sandbox_id, "expected_generation": sb.generation}})).await;
    a.done("snapshot.restore", json!({"snapshot": snap.snapshot, "target": {"kind": "new"}})).await;
    rig.world.clear_hooks();
    assert_eq!(*undeclared.lock().unwrap(), Vec::<String>::new());
}

/// T-PERS-03: a commit that definitely did not happen leaves memory unchanged and the host
/// serving; a commit whose outcome is uncertain makes the core stop mutating (FS-9). A restart
/// recovers, and memory is never ahead of the store.
#[tokio::test]
async fn t_pers_03_a_failed_commit_changes_nothing_and_an_uncertain_one_is_a_fail_stop() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let sb = a.ready(None).await;
    let on_disk = |path: &std::path::Path| {
        let copy = rig.dir.path().join("probe.wal");
        std::fs::copy(path, &copy).unwrap();
        let (j, _) = Journal::open(&copy).unwrap();
        j.read(|s| (s.last_seq, s.operations.len(), s.generations.len())).unwrap()
    };
    let in_memory = |h: &crate::coordinator::Host| h.journal.read(|s| (s.last_seq, s.operations.len(), s.generations.len())).unwrap();
    let store = rig.cfg.journal_path();

    // The BEGIN commit fails cleanly: a refusal, nothing recorded, nothing in memory, and the host goes on.
    let before = in_memory(&host);
    host.journal.inject_append_failure_once();
    let refused = a.refused("sandbox.create", create_params(None)).await;
    assert_eq!(refused.class, FailureClass::InternalError, "{}", refused.message);
    assert_eq!((in_memory(&host), on_disk(&store)), (before, before), "memory and disk agree, and neither moved");
    assert_eq!(host.mode(), HostMode::Serving);
    a.create(None).await;

    // A commit in the middle of an operation fails cleanly: the operation fails, and undoes itself.
    let journal = Arc::clone(&host.journal);
    let once = std::sync::atomic::AtomicBool::new(true);
    rig.world.on_call("provision", move || {
        if once.swap(false, std::sync::atomic::Ordering::SeqCst) {
            journal.inject_append_failure_once(); // the commit after the step
        }
    });
    let op = a.op("sandbox.create", create_params(None)).await;
    rig.world.clear_hooks();
    assert_eq!(
        (op.state, op.effect, op.cleanup),
        (OperationState::Failed, Some(Effect::NotApplied), Some(Cleanup::Complete)),
        "{:?}",
        op.failure
    );
    assert_eq!(in_memory(&host), on_disk(&store), "memory is never ahead of the store");

    // An uncertain commit: the core stops mutating at once.
    let before = in_memory(&host);
    host.journal.inject_uncertain_append_once();
    let refused = a.refused("exec.run", exec_params(&sb, &["/bin/true"])).await;
    assert_eq!(refused.class, FailureClass::InternalError);
    assert!(host.fatal.is_cancelled(), "the activation asked to be ended");
    assert_eq!(host.mode(), HostMode::ReadOnly);
    assert_eq!(in_memory(&host), before, "nothing was applied to memory");
    assert_eq!(
        a.refused("sandbox.destroy", target(&sb)).await.class,
        FailureClass::HostNotServing,
        "even containment: it could not be recorded"
    );
    assert_eq!(a.sandboxes(json!({})).await.items.len(), 2, "reads are still served");
    assert!(a.info().await.read_only_reason.is_some());
    assert_eq!(crate::testing::rig::calls(&rig.world, "exec"), 0, "no effect followed the uncertain commit");

    // A restart re-establishes the state from the store and serves again.
    drop(host);
    let host = rig.serving().await;
    assert_eq!(host.mode(), HostMode::Serving);
    assert_eq!(in_memory(&host).1, before.1, "exactly the operations that were committed");
    assert_eq!(alice(&host).exec(&sb, &["/bin/true"]).await.state, OperationState::Succeeded);
}

/// T-PERS-04: a second instance on one store refuses to run (PS-5), and a writer from a stale
/// activation is rejected.
#[tokio::test]
async fn t_pers_04_one_writer_per_store() {
    let rig = Rig::new();
    let build = || {
        let world = Arc::clone(&rig.world);
        let inputs = TrustedInputs { profile: rig.profile(), enrolment: Rig::enrolment(), tls: None, reasons: vec![] };
        let assembly = Assembly {
            backend: Box::new(move |_cfg, layout, clock| Arc::new(FakeBackend::new(world, layout, clock))),
            lifetime: rig.lifetime.clone(),
            secrets: rig.secrets.clone(),
            clock: rig.clock.clone(),
        };
        app::build_host(Arc::clone(&rig.cfg), "test", inputs, assembly)
    };
    // The instance lock is taken before the store is read.
    let first = build().unwrap();
    let second = build().unwrap_err();
    assert_eq!(second.class, FailureClass::StateConflict, "{second}");
    assert!(second.message.contains("another host-agent instance"), "{second}");
    drop(first);
    drop(build().unwrap()); // once the first is gone, the next one starts

    // Without the lock (as if it had been bypassed): the older activation's next write is fenced.
    let stale = rig.serving().await;
    let sb = alice(&stale).ready(None).await;
    let current = rig.serving().await; // a newer activation writes to the same store
    let seq = current.journal.last_seq();
    let refused = alice(&stale).refused("exec.run", exec_params(&sb, &["/bin/true"])).await;
    assert_eq!(refused.class, FailureClass::HostNotServing, "{}", refused.message);
    assert!(refused.message.contains("another writer"), "{}", refused.message);
    assert!(stale.fatal.is_cancelled() && stale.mode() == HostMode::ReadOnly, "the stale activation stops");
    assert_eq!(crate::testing::rig::calls(&rig.world, "exec"), 0);
    // The current activation saw nothing of it, and works.
    assert_eq!(current.journal.last_seq(), seq);
    assert_eq!(alice(&current).exec(&sb, &["/bin/true"]).await.state, OperationState::Succeeded);
}

/// T-PERS-06: workload data filling the disk does not prevent recording a destroy (PS-9). While
/// the store runs on its reserve, no new privilege is created.
#[tokio::test]
async fn t_pers_06_a_full_disk_does_not_prevent_recording_containment() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let doomed = a.ready(None).await;
    let other = a.ready(None).await;
    assert!(!host.journal.reserve_released());

    // The filesystem is full when the destroy is recorded: the store's reserved space is used.
    host.journal.inject_append_error_once(std::io::ErrorKind::StorageFull);
    let destroyed = a.done("sandbox.destroy", target(&doomed)).await;
    assert_eq!(destroyed.state, OperationState::Succeeded);
    assert!(host.journal.reserve_released(), "the reserve was spent on it");
    assert_eq!(a.inspect(&doomed.sandbox_id).await.state, LifecycleState::Destroyed);

    // Until space returns: containment and reads, and nothing that creates privilege.
    let before = footprint(&host);
    for (method, params) in
        [("sandbox.create", create_params(None)), ("exec.run", exec_params(&other, &["/bin/true"])), ("snapshot.create", target(&other))]
    {
        let r = a.refused(method, params).await;
        assert_eq!(r.class, FailureClass::ResourceExhausted, "{method}: {}", r.message);
    }
    assert_eq!(footprint(&host), before);
    assert_eq!(ops(&host).metrics().await["gauges"]["store_reserve_released"], json!(1));
    a.done("sandbox.stop", target(&other)).await;

    // Space is back: the reserve is taken again at the next sweep, and privilege is created again.
    host.sweep_once().await;
    assert!(!host.journal.reserve_released());
    a.create(None).await;
}

/// PS-10: the store's file is bounded while the host serves, not only when it restarts. The file is
/// append-only, so every record a later one replaces stays in it until it is rewritten; a host that
/// only rewrote it at start would grow a file that its next start refuses to open. Nothing is lost
/// by the rewrite, and the activation that follows reads the same state.
#[tokio::test]
async fn ps_10_the_store_file_is_rewritten_while_the_host_serves_and_nothing_is_lost() {
    let rig = Rig::with(|c| c.store.compact_at_bytes = 48 * 1024);
    let host = rig.serving().await;
    let a = alice(&host);
    let sb = a.ready(Some("long-lived")).await;
    host.sweep_once().await;
    assert_eq!(ops(&host).metrics().await["counters"]["store_compactions"], json!(null), "a small store is left alone");

    // Ordinary work: every execution appends several records, and all but the last state of each
    // record is history.
    let mut runs = 0;
    while host.journal.len_bytes() <= 2 * 48 * 1024 {
        assert_eq!(a.exec(&sb, &["/bin/true"]).await.state, OperationState::Succeeded);
        runs += 1;
    }
    let (grown, seq, operations) = (host.journal.len_bytes(), host.journal.last_seq(), footprint(&host).0);
    let before = a.inspect(&sb.sandbox_id).await;

    host.sweep_once().await;
    let compacted = host.journal.len_bytes();
    assert!(compacted < grown, "{grown} -> {compacted} after {runs} executions");
    assert_eq!(ops(&host).metrics().await["counters"]["store_compactions"], json!(1));
    // Every operation is still there (forgetting them is retention's job), with the same revisions.
    assert_eq!(footprint(&host).0, operations);
    let after = a.inspect(&sb.sandbox_id).await;
    assert_eq!((after.revision, after.state), (before.revision, before.state));
    assert!(host.journal.last_seq() >= seq, "the commit sequence never goes backwards");
    // The host goes on working on the rewritten file...
    assert_eq!(a.exec(&sb, &["/bin/true"]).await.state, OperationState::Succeeded);
    drop(host);
    // ...and the next activation finds everything.
    let next = rig.serving().await;
    let a = alice(&next);
    assert_eq!(footprint(&next).0, operations + 1);
    assert_eq!(a.inspect(&sb.sandbox_id).await.sandbox_id, sb.sandbox_id);
    assert_eq!(a.exec(&a.inspect(&sb.sandbox_id).await, &["/bin/true"]).await.state, OperationState::Succeeded);
}

/// T-PERS-07: a store of a schema this version does not support → `READ_ONLY`, not exit; a store
/// of the previous schema is migrated with its non-terminal operations, which are then resolved
/// like any other inherited operation.
#[tokio::test]
async fn t_pers_07_schema_changes() {
    // A store from the future.
    let rig = Rig::new();
    let future = crate::store::journal::encode(&crate::store::journal::Batch {
        seq: 1,
        epoch: 1,
        jump: false,
        entries: vec![Entry::Meta(StoreMeta {
            schema_version: 99,
            lineage: "from-the-future".into(),
            created_wall: "2030-01-01T00:00:00Z".into(),
        })],
    })
    .unwrap();
    std::fs::create_dir_all(rig.cfg.journal_path().parent().unwrap()).unwrap();
    std::fs::write(rig.cfg.journal_path(), &future).unwrap();
    let host = rig.boot();
    host.recover().await.unwrap();
    host.finish_starting();
    assert_eq!(host.mode(), HostMode::ReadOnly, "the host runs; it neither writes nor interprets the store");
    let info = ops(&host).info().await;
    assert!(info.read_only_reason.as_deref().is_some_and(|r| r.contains("99")), "{:?}", info.read_only_reason);
    assert_eq!(alice(&host).refused("sandbox.create", create_params(None)).await.class, FailureClass::HostNotServing);
    assert_eq!(std::fs::read(rig.cfg.journal_path()).unwrap(), future, "the file was not touched");
    drop(host);

    // A store of the previous schema, with an execution in flight when the old version stopped.
    let rig = Rig::new();
    let old = crate::store::migrate::tests::v1_store();
    std::fs::create_dir_all(rig.cfg.journal_path().parent().unwrap()).unwrap();
    std::fs::write(rig.cfg.journal_path(), &old).unwrap();
    let host = rig.serving().await;
    assert_eq!(host.mode(), HostMode::Serving);
    assert_eq!(
        std::fs::read(rig.cfg.journal_path().with_extension("wal.schema1")).unwrap(),
        old,
        "the previous store is kept beside the new one"
    );
    // Migrated records belong to the local administrator's scope; an operator sees them.
    let operator = ops(&host);
    let all = operator.operations(json!({})).await.items;
    let exec = all.iter().find(|o| o.operation_id.as_str() == "op-exec0000").expect("the non-terminal operation was carried over");
    assert_eq!(exec.state, OperationState::Unknown, "inherited, so never continued: an execution ends UNKNOWN");
    let sandboxes = operator.sandboxes(json!({})).await.items;
    assert_eq!((sandboxes.len(), sandboxes[0].state), (1, LifecycleState::Failed));
    assert_eq!(sandboxes[0].tags.peer_id.as_str(), "local-root");
    // The migrated store is an ordinary store from now on.
    drop(host);
    let host = rig.serving().await;
    assert_eq!(ops(&host).operations(json!({})).await.items.len(), all.len());
}
