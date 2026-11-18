//! T-SNAP: snapshots and restore (§21). T-SNAP-05 (scopes) is part of T-AUTH-03; the manifest
//! compatibility rules (CPU, guest version, security profile; L1) are in
//! `storage/snapshots/manifest.rs`.

use std::os::unix::fs::PermissionsExt;

use serde_json::json;

use crate::{
    domain::{Cleanup, Effect, LifecycleState, Method, OperationState, SnapshotState},
    error::{AcfError, FailureClass},
    ids::{Generation, SandboxRef},
    testing::{
        fake_backend::Fail,
        rig::{Rig, alice, calls, eventually, footprint, sandbox_of, snapshot_of, target},
    },
};

fn jail(sb: &crate::api::SandboxView) -> String {
    SandboxRef { sandbox_id: sb.sandbox_id.clone(), generation: sb.generation }.jail_id()
}

/// T-SNAP-01: a changed artifact, a changed manifest, or both replaced together → refused before
/// any runtime is launched (RE-2).
#[tokio::test]
async fn t_snap_01_a_tampered_snapshot_is_refused_before_any_runtime_is_launched() {
    for tamper in ["artifact", "manifest", "both"] {
        let rig = Rig::new();
        let host = rig.serving().await;
        let a = alice(&host);
        let sb = a.ready(None).await;
        let snap = snapshot_of(&a.done("snapshot.create", target(&sb)).await);
        let dir = rig.layout.snapshot_path(&snap.snapshot.snapshot_id, snap.snapshot.snapshot_generation);
        let replaced = b"VMSTATE: attacker-chosen machine state".to_vec();
        if tamper != "manifest" {
            std::fs::write(dir.join("vmstate"), &replaced).unwrap();
        }
        if tamper != "artifact" {
            // A manifest that is consistent with the replaced artifact: only the digest the store
            // holds can tell that it is not the manifest that was written.
            let text = std::fs::read_to_string(rig.manifest_path(&snap)).unwrap();
            let mut manifest: serde_json::Value = serde_json::from_str(&text).unwrap();
            manifest["artifacts"]["vmstate"]["sha256"] = json!(hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&replaced)));
            manifest["artifacts"]["vmstate"]["bytes"] = json!(replaced.len());
            std::fs::write(rig.manifest_path(&snap), manifest.to_string()).unwrap();
        }
        let runtimes = rig.world.vm_count();
        let resp = a.call("snapshot.restore", json!({"snapshot": snap.snapshot, "target": {"kind": "new"}})).await;
        let class = match (resp.refusal(), resp.operation_view()) {
            (Some(r), _) => r.class,
            (_, Some(op)) => {
                assert_eq!(
                    (op.state, op.effect, op.cleanup),
                    (OperationState::Failed, Some(Effect::NotApplied), Some(Cleanup::Complete)),
                    "{tamper}"
                );
                op.failure.as_ref().unwrap().class
            }
            _ => panic!("{tamper}"),
        };
        assert_eq!(class, FailureClass::IntegrityFailure, "{tamper}");
        assert_eq!(rig.world.vm_count(), runtimes, "{tamper}: nothing unverified was ever loaded into a runtime");
        assert_eq!(footprint(&host).1, 1, "{tamper}: no lease is left behind");
        // Whichever file was changed, the snapshot is now known to be bad (SNP-3): it is INVALID, never
        // restorable again, and still deletable.
        let listed = a.snapshots(json!({})).await.items;
        assert_eq!(listed[0].state, SnapshotState::Invalid, "{tamper}");
        assert_eq!(
            a.refused("snapshot.restore", json!({"snapshot": snap.snapshot, "target": {"kind": "new"}})).await.class,
            FailureClass::StateConflict,
            "{tamper}"
        );
        a.done("snapshot.delete", json!({"snapshot": snap.snapshot})).await;
    }

    // Only the snapshot's own files decide that. A restore that fails on the integrity of something
    // else (a VMM binary that is no longer the pinned one, say) leaves an intact snapshot READY, and it
    // is restored once the cause is gone.
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let sb = a.ready(None).await;
    let snap = snapshot_of(&a.done("snapshot.create", target(&sb)).await);
    rig.world.fail_next("restore", Fail::Before(AcfError::corrupt("the VMM binary is not the one that was pinned")));
    let resp = a.call("snapshot.restore", json!({"snapshot": snap.snapshot, "target": {"kind": "new"}})).await;
    let failed = resp.operation_view().expect("the restore was accepted and then failed");
    assert_eq!(failed.failure.as_ref().unwrap().class, FailureClass::IntegrityFailure);
    assert_eq!(a.snapshots(json!({})).await.items[0].state, SnapshotState::Ready, "the snapshot's files still match");
    a.done("snapshot.restore", json!({"snapshot": snap.snapshot, "target": {"kind": "new"}})).await;
}

/// T-SNAP-02: a snapshot taken under another backend identity is `INCOMPATIBLE_RUNTIME`, and a
/// listing says so without anyone having to try (§21.6).
#[tokio::test]
async fn t_snap_02_a_snapshot_from_another_backend_identity_is_incompatible() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let sb = a.ready(None).await;
    let snap = snapshot_of(&a.done("snapshot.create", target(&sb)).await);
    assert!(a.snapshots(json!({})).await.items[0].incompatible.is_empty());
    drop(a);
    drop(host);

    rig.world.set_backend_version("v2.0.0"); // the VMM was upgraded
    let host = rig.serving().await;
    let a = alice(&host);
    let listed = a.snapshots(json!({})).await.items;
    assert_eq!(listed[0].state, SnapshotState::Ready, "validity is evaluated, not stored");
    assert!(listed[0].incompatible.iter().any(|w| w.contains("v2.0.0") || w.contains("version")), "{:?}", listed[0].incompatible);
    let before = (footprint(&host), calls(&rig.world, "restore"));
    for tgt in [json!({"kind": "new"}), json!({"kind": "existing", "sandbox_id": sb.sandbox_id, "expected_generation": sb.generation})] {
        let r = a.refused("snapshot.restore", json!({"snapshot": snap.snapshot, "target": tgt})).await;
        assert_eq!(r.class, FailureClass::IncompatibleRuntime, "{}", r.message);
    }
    assert_eq!((footprint(&host), calls(&rig.world, "restore")), before);
    // Back on the version that wrote it, it restores.
    drop(a);
    drop(host);
    rig.world.set_backend_version("v0.0.0");
    let host = rig.serving().await;
    alice(&host).done("snapshot.restore", json!({"snapshot": snap.snapshot, "target": {"kind": "new"}})).await;
}

/// T-SNAP-03 (L2 analogue): the restore oracle. A restore reproduces the state captured by the
/// snapshot; a guest that came up some other way (rebooted, or with a different disk) is detected
/// and the restore fails without costing the caller the sandbox they had (RE-4, RE-6).
#[tokio::test]
async fn t_snap_03_the_restore_oracle() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let sb = a.ready(None).await;
    rig.world.with_guest(&jail(&sb), |g| g.files.insert("/workspace/model.bin".into(), "trained".into()));
    let snap = snapshot_of(&a.done("snapshot.create", target(&sb)).await);
    // The environment is then broken.
    rig.world.with_guest(&jail(&sb), |g| {
        g.files.remove("/workspace/model.bin");
        g.files.insert("/etc/passwd".into(), "corrupted".into());
    });

    // A restore in place brings back exactly the captured state, as a new generation.
    let in_place = json!({"snapshot": snap.snapshot, "target": {"kind": "existing", "sandbox_id": sb.sandbox_id, "expected_generation": sb.generation}});
    let op = a.done("snapshot.restore", in_place).await;
    let restored = sandbox_of(&op);
    assert_eq!((restored.generation, restored.state), (sb.generation.next(), LifecycleState::Ready));
    assert_eq!(restored.source_snapshot, Some(snap.snapshot.clone()));
    assert!(restored.notes.iter().any(|n| n.contains("restore verified")), "{:?}", restored.notes);
    let files = rig.world.with_guest(&jail(&restored), |g| g.files.clone()).unwrap();
    assert_eq!(files.get("/workspace/model.bin").map(String::as_str), Some("trained"));
    assert!(!files.contains_key("/etc/passwd"));
    assert_eq!(rig.world.jail_ids(), vec![jail(&restored)], "the superseded runtime is gone");
    assert_eq!(rig.world.vm_count(), 1);

    // A second restore of the same snapshot says so: uniqueness is only guaranteed for the first.
    let again = sandbox_of(&a.done("snapshot.restore", json!({"snapshot": snap.snapshot, "target": {"kind": "new"}})).await);
    assert!(again.notes.iter().any(|n| n.contains("restored more than once")), "{:?}", again.notes);
    assert_eq!(a.snapshots(json!({})).await.items[0].restore_count, 2);

    // A guest that does not reproduce the baseline: here it "rebooted" between load and probe.
    let next = SandboxRef { sandbox_id: restored.sandbox_id.clone(), generation: Generation(restored.generation.0 + 1) }.jail_id();
    let world = std::sync::Arc::clone(&rig.world);
    rig.world.on_call("probe", move || {
        world.with_guest(&next, |g| g.boot_id = "a-different-boot".into());
    });
    let op = a
        .op("snapshot.restore", json!({"snapshot": snap.snapshot, "target": {"kind": "existing", "sandbox_id": restored.sandbox_id, "expected_generation": restored.generation}}))
        .await;
    rig.world.clear_hooks();
    assert_eq!((op.state, op.failure.as_ref().map(|f| f.class)), (OperationState::Failed, Some(FailureClass::IntegrityFailure)));
    assert_eq!((op.effect, op.cleanup), (Some(Effect::NotApplied), Some(Cleanup::Complete)));
    let still = a.inspect(&restored.sandbox_id).await;
    assert_eq!(
        (still.generation, still.state),
        (restored.generation, LifecycleState::Ready),
        "the generation the caller had is current and intact"
    );
    assert_eq!(rig.world.vm_count(), 2, "the unverified runtime was ended");
}

/// T-SNAP-04: a snapshot cannot be deleted while it is referenced; afterwards it can (RF-2).
#[tokio::test]
async fn t_snap_04_a_referenced_snapshot_cannot_be_deleted() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let sb = a.ready(None).await;
    let snap = snapshot_of(&a.done("snapshot.create", target(&sb)).await);
    let delete = json!({"snapshot": snap.snapshot});

    rig.world.hold("restore");
    let restoring = {
        let (a, p) = (a.clone(), json!({"snapshot": snap.snapshot, "target": {"kind": "new"}}));
        tokio::spawn(async move { a.op("snapshot.restore", p).await })
    };
    eventually("the restore reaches the backend", || rig.world.waiting("restore") == 1).await;
    let before = footprint(&host);
    let refused = a.refused("snapshot.delete", delete.clone()).await;
    assert_eq!(refused.class, FailureClass::StateConflict, "{}", refused.message);
    assert_eq!(footprint(&host), before);
    rig.world.release("restore");
    assert_eq!(restoring.await.unwrap().state, OperationState::Succeeded);

    // No reference is left (this backend copies what it restores), so the delete succeeds...
    let deleted = snapshot_of(&a.done("snapshot.delete", delete.clone()).await);
    assert_eq!(deleted.state, SnapshotState::Deleted);
    assert!(!rig.layout.snapshot_path(&snap.snapshot.snapshot_id, snap.snapshot.snapshot_generation).exists());
    assert_eq!(footprint(&host).2, 0, "its quota is released");
    // ...and it is idempotent: deleting what is already deleted is not an error.
    a.done("snapshot.delete", delete.clone()).await;
    // A deleted snapshot cannot be restored, and its name is free again.
    assert_eq!(
        a.refused("snapshot.restore", json!({"snapshot": snap.snapshot, "target": {"kind": "new"}})).await.class,
        FailureClass::StateConflict
    );
    assert!(a.snapshots(json!({})).await.items.is_empty());
}

/// T-SNAP-06: snapshot creates cannot exceed the count or the byte quota, an in-flight create
/// counts with its reservation, and a failed create releases it (LS-2).
#[tokio::test]
async fn t_snap_06_snapshot_quota_is_reserved_at_begin_and_released_on_failure() {
    // Quota: 1 GiB and three snapshots. One snapshot of the test sandbox is estimated at 448 MiB.
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let sandboxes = [a.ready(None).await, a.ready(None).await, a.ready(None).await];

    // Two creates are in flight; their reservations (2 × 448 MiB) leave no room for a third.
    rig.world.hold("snapshot");
    let mut in_flight = Vec::new();
    for sb in &sandboxes[..2] {
        let (a, sb) = (a.clone(), sb.clone());
        in_flight.push(tokio::spawn(async move { a.op("snapshot.create", target(&sb)).await }));
    }
    eventually("both captures start", || rig.world.waiting("snapshot") == 2).await;
    let before = footprint(&host);
    let refused = a.refused("snapshot.create", target(&sandboxes[2])).await;
    assert_eq!(refused.class, FailureClass::ResourceExhausted, "{}", refused.message);
    assert!(refused.message.contains("quota"), "{}", refused.message);
    assert_eq!(footprint(&host), before, "the refused create reserved nothing");
    rig.world.release("snapshot");
    for t in in_flight {
        assert_eq!(t.await.unwrap().state, OperationState::Succeeded);
    }

    // At READY the reservation becomes the actual size (far smaller here), so there is room again...
    let third = snapshot_of(&a.done("snapshot.create", target(&sandboxes[2])).await);
    assert!(third.size_bytes < 448 * 1024 * 1024);
    // ...until the count limit, which is independent of bytes.
    let refused = a.refused("snapshot.create", target(&sandboxes[0])).await;
    assert_eq!(refused.class, FailureClass::ResourceExhausted);
    assert!(refused.message.contains("3 snapshots"), "{}", refused.message);

    // A failed create releases its reservation and leaves nothing listed.
    a.done("snapshot.delete", json!({"snapshot": third.snapshot})).await;
    rig.world.fail_next("snapshot", Fail::After(AcfError::unavailable("the VMM stopped answering").with_possible_side_effect()));
    let failed = a.op("snapshot.create", target(&sandboxes[2])).await;
    assert_eq!((failed.state, failed.cleanup), (OperationState::Failed, Some(Cleanup::Complete)));
    assert_eq!((footprint(&host).2, a.snapshots(json!({})).await.items.len()), (2, 2));
    assert_eq!(a.inspect(&sandboxes[2].sandbox_id).await.state, LifecycleState::Ready, "the guest runs again (SNP-5)");
    a.done("snapshot.create", target(&sandboxes[2])).await;
}

/// T-SNAP-07: snapshot storage is readable only by the core's own identity, and the API has no
/// method that exports a snapshot (SNP-7).
#[tokio::test]
async fn t_snap_07_snapshot_storage_is_private_and_there_is_no_export_method() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let sb = a.ready(None).await;
    let snap = snapshot_of(&a.done("snapshot.create", target(&sb)).await);
    let dir = rig.layout.snapshot_path(&snap.snapshot.snapshot_id, snap.snapshot.snapshot_generation);
    let mut checked = 0;
    for path in [rig.layout.root().to_owned(), rig.layout.root().join("snapshots"), dir.clone()]
        .into_iter()
        .chain(std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.path()))
    {
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & 0o077, 0, "{} is accessible by group or other (mode {mode:o})", path.display());
        checked += 1;
    }
    assert!(checked >= 7, "the directory, the three artifacts and the manifest were all checked");
    // The command set is closed, and nothing in it reads snapshot bytes out of the host.
    for m in Method::ALL {
        let name = m.name();
        assert!(!["export", "download", "read", "copy", "import", "upload"].iter().any(|w| name.contains(w)), "{name}");
    }
    // A snapshot view carries identity, state and size: never a path, never content.
    let view = serde_json::to_string(&snap).unwrap();
    assert!(!view.contains(rig.layout.root().to_str().unwrap()), "{view}");
}
