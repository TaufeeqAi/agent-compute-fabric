//! Capacity admission (spec §13.2, §18.1–§18.9, DELTA-005).
//!
//! These are **pure functions over journal state**, called inside `Journal::commit_with`, so the
//! decision "is there room?" and the durable reservation that consumes the room are one atomic
//! step: two concurrent creates can never both be granted the last slot.
//!
//! Every resource follows `request -> admission -> reservation -> enforcement -> violation ->
//! evidence`; this module is the *admission → reservation* edge.

use crate::{
    config::Envelope,
    domain::{Reservation, SandboxResources},
    error::{AcfError, FailureClass, Result},
    operation::JournalState,
};

const MIB: u64 = 1024 * 1024;

fn rejected(msg: impl Into<String>) -> AcfError {
    AcfError::new(FailureClass::AdmissionRejected, msg)
}

pub fn reserve_sandbox(
    state: &JournalState,
    env: &Envelope,
    overhead_mib: u32,
    uid_pool: u32,
    res: &SandboxResources,
    free_disk_bytes: u64,
) -> Result<Reservation> {
    let live: Vec<_> = state.live_generations().collect();
    if live.len() >= env.max_sandboxes as usize {
        return Err(rejected(format!("host is at its limit of {} sandboxes", env.max_sandboxes)));
    }
    let want_mem = u64::from(res.memory_mib) + u64::from(overhead_mib);
    let (used_cpu, used_mem, used_disk) = live
        .iter()
        .fold((0u32, 0u64, 0u64), |(c, m, d), g| (c + g.reservation.vcpus, m + g.reservation.memory_mib, d + g.reservation.disk_mib));
    if used_cpu + u32::from(res.vcpus) > env.vcpus {
        return Err(rejected(format!("insufficient vCPUs: {used_cpu} of {} reserved, {} requested", env.vcpus, res.vcpus)));
    }
    if used_mem + want_mem > env.memory_mib {
        return Err(rejected(format!("insufficient memory: {used_mem} of {} MiB reserved, {want_mem} MiB requested", env.memory_mib)));
    }
    if used_disk + u64::from(res.disk_mib) > env.disk_mib {
        return Err(rejected(format!("insufficient disk: {used_disk} of {} MiB reserved, {} MiB requested", env.disk_mib, res.disk_mib)));
    }
    let need_free = (u64::from(res.disk_mib) + env.min_free_headroom_mib) * MIB;
    if free_disk_bytes < need_free {
        return Err(AcfError::new(
            FailureClass::ResourceExhaustion,
            format!("only {} MiB free on the state filesystem; {} MiB required including headroom", free_disk_bytes / MIB, need_free / MIB),
        ));
    }
    let taken: std::collections::BTreeSet<u32> = live.iter().map(|g| g.reservation.uid_slot).collect();
    let slot = (0..uid_pool).find(|s| !taken.contains(s)).ok_or_else(|| rejected("no free per-VM uid slot"))?;
    Ok(Reservation { vcpus: u32::from(res.vcpus), memory_mib: want_mem, disk_mib: u64::from(res.disk_mib), uid_slot: slot })
}

/// Bytes a snapshot of this sandbox may occupy: guest memory + disk + vmstate/manifest slack.
pub fn snapshot_estimate_bytes(res: &SandboxResources) -> u64 {
    (u64::from(res.memory_mib) + u64::from(res.disk_mib) + 64) * MIB
}

pub fn reserve_snapshot(state: &JournalState, env: &Envelope, est_bytes: u64, free_disk_bytes: u64) -> Result<u64> {
    let live: Vec<_> = state.snapshots.values().filter(|s| s.holds_storage()).collect();
    if live.len() >= env.max_snapshots as usize {
        return Err(rejected(format!("host is at its limit of {} snapshots", env.max_snapshots)));
    }
    let used: u64 = live.iter().map(|s| s.actual_bytes.max(if s.actual_bytes == 0 { s.reserved_bytes } else { 0 })).sum();
    if used.saturating_add(est_bytes) > env.snapshot_quota_bytes {
        return Err(AcfError::new(
            FailureClass::ResourceExhaustion,
            format!(
                "snapshot quota exceeded: {} MiB used + {} MiB needed > {} MiB quota",
                used / MIB,
                est_bytes / MIB,
                env.snapshot_quota_bytes / MIB
            ),
        ));
    }
    if free_disk_bytes < est_bytes + env.min_free_headroom_mib * MIB {
        return Err(AcfError::new(FailureClass::ResourceExhaustion, "not enough free disk for this snapshot plus headroom"));
    }
    Ok(est_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::{ImageRef, LifecycleState, NetworkMode, PolicyId},
        ids::{Generation, OperationId, SandboxId, SnapshotId},
        operation::{Entry, GenerationRecord, SnapshotRecord},
    };

    fn env() -> Envelope {
        Envelope {
            vcpus: 4,
            memory_mib: 2048,
            disk_mib: 4096,
            max_sandboxes: 3,
            snapshot_quota_bytes: 1 << 30,
            max_snapshots: 2,
            min_free_headroom_mib: 10,
        }
    }

    fn res(v: u8, m: u32, d: u32) -> SandboxResources {
        SandboxResources { vcpus: v, memory_mib: m, disk_mib: d, network: NetworkMode::None }
    }

    fn gen_rec(res_: Reservation, state: LifecycleState) -> GenerationRecord {
        GenerationRecord {
            sandbox_id: SandboxId::generate(),
            generation: Generation::FIRST,
            state,
            paused_from: None,
            resources: res(1, 128, 64),
            image: ImageRef {
                image_id: "sha256:i".into(),
                alias: None,
                architecture: "x".into(),
                kernel_identity: "k".into(),
                rootfs_identity: "r".into(),
                manifest_version: 1,
                provenance_reference: None,
            },
            reservation: res_,
            owner_nonce: "n".into(),
            handle: None,
            process: None,
            created_by: OperationId::parse("op-12345678").unwrap(),
            source_snapshot: None,
            last_run: None,
            policy_id: PolicyId { name: "p".into(), version: "1".into(), digest: "0".repeat(64) },
            security_profile_id: "sp".into(),
            failure: None,
            quarantined: None,
            updated_wall: String::new(),
        }
    }

    fn state_with(gens: Vec<GenerationRecord>) -> JournalState {
        let d = tempfile::tempdir().unwrap();
        let (j, _) = crate::operation::Journal::open(&d.path().join("j.wal")).unwrap();
        j.commit(gens.into_iter().map(|g| Entry::Generation(Box::new(g))).collect()).unwrap();
        j.read(Clone::clone).unwrap()
    }

    const FREE: u64 = 1 << 40;

    #[test]
    fn grants_the_lowest_free_uid_slot_and_adds_vmm_overhead_to_memory() {
        let s = state_with(vec![gen_rec(Reservation { vcpus: 1, memory_mib: 192, disk_mib: 64, uid_slot: 0 }, LifecycleState::Ready)]);
        let r = reserve_sandbox(&s, &env(), 64, 16, &res(1, 256, 128), FREE).unwrap();
        assert_eq!((r.uid_slot, r.memory_mib, r.vcpus), (1, 320, 1));
    }

    #[test]
    fn each_dimension_can_be_the_one_that_rejects() {
        let full =
            |c, m, d| state_with(vec![gen_rec(Reservation { vcpus: c, memory_mib: m, disk_mib: d, uid_slot: 0 }, LifecycleState::Running)]);
        let e = env();
        let attempt = |s: &JournalState| reserve_sandbox(s, &e, 0, 16, &res(2, 1024, 2048), FREE).unwrap_err();
        assert!(attempt(&full(3, 0, 0)).message.contains("vCPUs"));
        assert!(attempt(&full(0, 1500, 0)).message.contains("memory"));
        assert!(attempt(&full(0, 0, 3000)).message.contains("disk"));
        assert_eq!(
            reserve_sandbox(&full(0, 0, 0), &e, 0, 16, &res(2, 1024, 2048), 1024).unwrap_err().class,
            FailureClass::ResourceExhaustion,
            "no free space"
        );
        assert_eq!(attempt(&full(3, 0, 0)).class, FailureClass::AdmissionRejected);
    }

    #[test]
    fn sandbox_count_and_uid_pool_are_hard_limits() {
        let three: Vec<_> =
            (0..3).map(|i| gen_rec(Reservation { vcpus: 0, memory_mib: 0, disk_mib: 0, uid_slot: i }, LifecycleState::Ready)).collect();
        assert!(reserve_sandbox(&state_with(three), &env(), 0, 16, &res(1, 128, 64), FREE).unwrap_err().message.contains("limit of 3"));
        let mut e = env();
        e.max_sandboxes = 10;
        let two: Vec<_> =
            (0..2).map(|i| gen_rec(Reservation { vcpus: 0, memory_mib: 0, disk_mib: 0, uid_slot: i }, LifecycleState::Ready)).collect();
        assert!(reserve_sandbox(&state_with(two), &e, 0, 2, &res(1, 128, 64), FREE).unwrap_err().message.contains("uid slot"));
    }

    #[test]
    fn destroyed_generations_release_capacity_and_their_uid_slot() {
        let s =
            state_with(vec![gen_rec(Reservation { vcpus: 4, memory_mib: 2048, disk_mib: 4096, uid_slot: 0 }, LifecycleState::Destroyed)]);
        let r = reserve_sandbox(&s, &env(), 0, 16, &res(4, 2048, 4096), FREE).unwrap();
        assert_eq!(r.uid_slot, 0, "slot is reusable once the generation is destroyed");
    }

    #[test]
    fn failed_generations_keep_their_reservation_until_destroyed() {
        let s = state_with(vec![gen_rec(Reservation { vcpus: 4, memory_mib: 0, disk_mib: 0, uid_slot: 0 }, LifecycleState::Failed)]);
        assert!(
            reserve_sandbox(&s, &env(), 0, 16, &res(1, 128, 64), FREE).is_err(),
            "a failed sandbox still owns its capacity: ownership is not assumed released"
        );
    }

    #[test]
    fn snapshot_quota_count_and_free_space() {
        let snap = |bytes: u64, state| SnapshotRecord {
            snapshot_id: SnapshotId::generate(),
            generation: Generation::FIRST,
            name: None,
            state,
            manifest_digest: None,
            reserved_bytes: bytes,
            actual_bytes: 0,
            source: None,
            source_run: None,
            created_by: OperationId::parse("op-12345678").unwrap(),
            created_wall: String::new(),
            restore_count: 0,
            failure: None,
        };
        let d = tempfile::tempdir().unwrap();
        let (j, _) = crate::operation::Journal::open(&d.path().join("j.wal")).unwrap();
        j.commit(vec![
            Entry::Snapshot(Box::new(snap(600 << 20, crate::domain::SnapshotState::Ready))),
            Entry::Snapshot(Box::new(snap(1 << 40, crate::domain::SnapshotState::Deleted))),
        ])
        .unwrap();
        let s = j.read(Clone::clone).unwrap();
        let e = env();
        assert!(reserve_snapshot(&s, &e, 300 << 20, FREE).is_ok());
        assert_eq!(
            reserve_snapshot(&s, &e, 500 << 20, FREE).unwrap_err().class,
            FailureClass::ResourceExhaustion,
            "600+500 MiB > 1 GiB quota; the Deleted one must not count"
        );
        assert!(reserve_snapshot(&s, &e, 1 << 20, 1 << 20).is_err(), "free space + headroom");
        j.commit(vec![Entry::Snapshot(Box::new(snap(1 << 20, crate::domain::SnapshotState::Ready)))]).unwrap();
        let s = j.read(Clone::clone).unwrap();
        assert!(reserve_snapshot(&s, &e, 1, FREE).unwrap_err().message.contains("limit of 2"), "count limit");
        assert!(snapshot_estimate_bytes(&res(1, 512, 1024)) > (512 + 1024) * MIB);
    }
}
