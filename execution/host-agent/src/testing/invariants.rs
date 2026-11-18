//! The joint-state invariants J-1 … J-8 (contract §12.7) as one checker over committed state.
//!
//! "These hold after every commit" is a property of the *store*, so the checker takes a
//! [`JournalState`] and nothing else from the running host. The suites call it after every step
//! (T-STATE-03) and the fault-point matrix calls it after every crash and every recovery.

use std::collections::BTreeSet;

use crate::{
    config::HostConfig,
    domain::{LifecycleState, OperationClass, OperationType, SnapshotState},
    store::JournalState,
};

/// Every violation of J-1 … J-8 in `s`. Empty means the invariants hold.
pub(crate) fn violations(s: &JournalState, cfg: &HostConfig) -> Vec<String> {
    let mut bad = Vec::new();
    let open: Vec<_> = s.open().collect();
    let targets = |g: &crate::store::GenerationRecord, ty: OperationType| {
        open.iter().filter(|o| o.operation_type == ty && o.sandbox.as_ref() == Some(&(g.sandbox_id.clone(), g.generation))).count()
    };

    for g in s.generations.values() {
        let at = format!("{}@{}", g.sandbox_id, g.generation);
        // J-1
        let execs = targets(g, OperationType::ExecRun);
        if (g.state == LifecycleState::Running) != (execs == 1) {
            bad.push(format!("J-1: {at} is {:?} with {execs} non-terminal execution(s)", g.state));
        }
        // J-2
        let snaps = targets(g, OperationType::SnapshotCreate);
        if (g.state == LifecycleState::Paused) != (snaps == 1) {
            bad.push(format!("J-2: {at} is {:?} with {snaps} non-terminal snapshot.create", g.state));
        }
        // J-6
        if g.quarantined.is_some() {
            let others = open
                .iter()
                .filter(|o| {
                    o.sandbox.as_ref() == Some(&(g.sandbox_id.clone(), g.generation))
                        && o.operation_type != OperationType::QuarantineRelease
                })
                .count();
            if others > 0 {
                bad.push(format!("J-6: quarantined {at} has {others} non-terminal operation(s) other than a release"));
            }
        }
    }

    for sb in s.sandboxes.values() {
        let mine: Vec<_> = open.iter().filter(|o| o.sandbox.as_ref().is_some_and(|(id, _)| *id == sb.sandbox_id)).collect();
        // J-3
        let granting = mine.iter().filter(|o| o.operation_type.class() == OperationClass::Granting).count();
        let stops = mine.iter().filter(|o| o.operation_type == OperationType::SandboxStop).count();
        let destroys = mine.iter().filter(|o| o.operation_type == OperationType::SandboxDestroy).count();
        if granting > 1 || stops > 1 || destroys > 1 {
            bad.push(format!("J-3: {} has {granting} granting, {stops} stop and {destroys} destroy operation(s) in flight", sb.sandbox_id));
        }
        // J-4
        let alive: Vec<_> =
            s.generations.values().filter(|g| g.sandbox_id == sb.sandbox_id && g.state != LifecycleState::Destroyed).collect();
        let current_alive = alive.iter().any(|g| g.generation == sb.current);
        if sb.destroyed_ms.is_none()
            && !alive.is_empty()
            && !current_alive
            && !mine.iter().any(|o| o.operation_type == OperationType::SnapshotRestore)
        {
            bad.push(format!("J-4: {} has live generations but its current one ({}) is destroyed", sb.sandbox_id, sb.current));
        }
        let restoring = mine.iter().any(|o| o.operation_type == OperationType::SnapshotRestore);
        for g in alive.iter().filter(|g| g.generation != sb.current) {
            let being_retired =
                matches!(g.state, LifecycleState::Stopping | LifecycleState::Stopped | LifecycleState::Failed) || g.quarantined.is_some();
            if !restoring && !being_retired {
                bad.push(format!(
                    "J-4: {}@{} is {:?} beside the current generation {} with no restore in flight",
                    g.sandbox_id, g.generation, g.state, sb.current
                ));
            }
        }
        if alive.len() > 2 {
            bad.push(format!("J-4: {} has {} generations that are not destroyed", sb.sandbox_id, alive.len()));
        }
    }

    // J-5: a lease is "the generation is counted by admission". Identifiers are never shared.
    let live: Vec<_> = s.live_generations().collect();
    let slots: BTreeSet<u32> = live.iter().map(|g| g.reservation.uid_slot).collect();
    if slots.len() != live.len() {
        bad.push("J-5: two live generations carry the same identifier slot".to_owned());
    }
    for g in s.generations.values() {
        let leased = live.iter().any(|l| l.sandbox_id == g.sandbox_id && l.generation == g.generation);
        if leased == (g.state == LifecycleState::Destroyed) {
            bad.push(format!(
                "J-5: {}@{} is {:?} and its lease is {}",
                g.sandbox_id,
                g.generation,
                g.state,
                if leased { "held" } else { "released" }
            ));
        }
    }

    // J-7
    for snap in s.snapshots.values() {
        let creating = open
            .iter()
            .filter(|o| o.operation_type == OperationType::SnapshotCreate && o.snapshot.as_ref() == Some(&snap.snapshot_ref()))
            .count();
        if matches!(snap.state, SnapshotState::Snapshotting | SnapshotState::Verifying) && creating != 1 {
            bad.push(format!("J-7: snapshot {} is {:?} with {creating} non-terminal snapshot.create", snap.snapshot_id, snap.state));
        }
        if snap.state == SnapshotState::Ready && snap.manifest_digest.is_none() {
            bad.push(format!("J-7: READY snapshot {} has no store-held manifest digest", snap.snapshot_id));
        }
    }

    // J-8
    let env = &cfg.envelope;
    let (cpu, mem, disk) = live
        .iter()
        .fold((0u32, 0u64, 0u64), |(c, m, d), g| (c + g.reservation.vcpus, m + g.reservation.memory_mib, d + g.reservation.disk_mib));
    if cpu > env.vcpus || mem > env.memory_mib || disk > env.disk_mib || live.len() > env.max_sandboxes as usize {
        bad.push(format!("J-8: leases exceed the envelope: {cpu} vCPUs, {mem} MiB memory, {disk} MiB disk, {} sandboxes", live.len()));
    }
    let stored: Vec<_> = s.snapshots.values().filter(|x| x.holds_storage()).collect();
    let bytes: u64 = stored.iter().map(|x| if x.actual_bytes > 0 { x.actual_bytes } else { x.reserved_bytes }).sum();
    if stored.len() > env.max_snapshots as usize || bytes > env.snapshot_quota_bytes {
        bad.push(format!("J-8: snapshots exceed the quota: {} snapshots, {bytes} bytes", stored.len()));
    }
    bad
}
