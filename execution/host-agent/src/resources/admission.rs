//! Capacity admission (contract RS-1, RS-3, CC-6, LS-1, LS-2).
//!
//! These are **pure functions over committed state**, called inside the store's commit closure, so
//! the decision "is there room?" and the durable lease that consumes the room are one atomic step
//! (OP-2): two concurrent creates can never both be granted the last slot.
//!
//! Capacity is never overcommitted and a request is never reduced to fit. A generation that is
//! `FAILED` or quarantined keeps its lease and its identifiers until it is `DESTROYED`, so a leaked
//! runtime can never hide behind a free slot (LS-1).

use std::collections::BTreeSet;

use crate::{
    config::Envelope,
    domain::{Reservation, SandboxResources},
    error::{AcfError, Result},
    store::JournalState,
};

const MIB: u64 = 1024 * 1024;

/// What the identifier pool needs to know about the world (RS-3).
#[derive(Debug, Clone, Copy)]
pub struct Pool<'a> {
    /// Number of slots in the pool.
    pub size: u32,
    /// Slots that a live resource carries by **observation**, whatever the records say.
    pub busy: &'a BTreeSet<u32>,
}

/// Admit one generation against the host envelope and everything already leased (RS-1).
pub fn reserve_sandbox(
    state: &JournalState,
    env: &Envelope,
    overhead_mib: u32,
    pool: Pool<'_>,
    res: &SandboxResources,
    free_disk_bytes: u64,
) -> Result<Reservation> {
    let live: Vec<_> = state.live_generations().collect();
    if live.len() >= env.max_sandboxes as usize {
        return Err(AcfError::exhausted(format!("host is at its limit of {} sandboxes", env.max_sandboxes)));
    }
    let want_mem = u64::from(res.memory_mib) + u64::from(overhead_mib);
    let (used_cpu, used_mem, used_disk) = live
        .iter()
        .fold((0u32, 0u64, 0u64), |(c, m, d), g| (c + g.reservation.vcpus, m + g.reservation.memory_mib, d + g.reservation.disk_mib));
    if used_cpu + u32::from(res.vcpus) > env.vcpus {
        return Err(AcfError::exhausted(format!("insufficient vCPUs: {used_cpu} of {} leased, {} requested", env.vcpus, res.vcpus)));
    }
    if used_mem + want_mem > env.memory_mib {
        return Err(AcfError::exhausted(format!(
            "insufficient memory: {used_mem} of {} MiB leased, {want_mem} MiB requested",
            env.memory_mib
        )));
    }
    if used_disk + u64::from(res.disk_mib) > env.disk_mib {
        return Err(AcfError::exhausted(format!(
            "insufficient disk: {used_disk} of {} MiB leased, {} MiB requested",
            env.disk_mib, res.disk_mib
        )));
    }
    let need_free = (u64::from(res.disk_mib) + env.min_free_headroom_mib) * MIB;
    if free_disk_bytes < need_free {
        return Err(AcfError::exhausted(format!(
            "only {} MiB free on the state filesystem; {} MiB required including headroom",
            free_disk_bytes / MIB,
            need_free / MIB
        )));
    }
    // RS-3: an identifier is assigned only if records show it free AND no live resource carries it.
    let taken: BTreeSet<u32> = live.iter().map(|g| g.reservation.uid_slot).collect();
    let slot = (0..pool.size)
        .find(|s| !taken.contains(s) && !pool.busy.contains(s))
        .ok_or_else(|| AcfError::exhausted("no free identifier slot: every slot is leased or carried by a live resource"))?;
    Ok(Reservation { vcpus: u32::from(res.vcpus), memory_mib: want_mem, disk_mib: u64::from(res.disk_mib), uid_slot: slot })
}

/// Bytes a snapshot of this sandbox may occupy: guest memory + disk + state and manifest slack.
pub fn snapshot_estimate_bytes(res: &SandboxResources) -> u64 {
    (u64::from(res.memory_mib) + u64::from(res.disk_mib) + 64) * MIB
}

/// Reserve snapshot quota (LS-2): reserved at BEGIN, set to the actual size at `READY`, released at
/// `DELETED`.
pub fn reserve_snapshot(state: &JournalState, env: &Envelope, est_bytes: u64, free_disk_bytes: u64) -> Result<u64> {
    let live: Vec<_> = state.snapshots.values().filter(|s| s.holds_storage()).collect();
    if live.len() >= env.max_snapshots as usize {
        return Err(AcfError::exhausted(format!("host is at its limit of {} snapshots", env.max_snapshots)));
    }
    let used: u64 = live.iter().map(|s| s.actual_bytes.max(if s.actual_bytes == 0 { s.reserved_bytes } else { 0 })).sum();
    if used.saturating_add(est_bytes) > env.snapshot_quota_bytes {
        return Err(AcfError::exhausted(format!(
            "snapshot quota exceeded: {} MiB used + {} MiB needed > {} MiB quota",
            used / MIB,
            est_bytes / MIB,
            env.snapshot_quota_bytes / MIB
        )));
    }
    if free_disk_bytes < est_bytes + env.min_free_headroom_mib * MIB {
        return Err(AcfError::exhausted("not enough free disk for this snapshot plus headroom"));
    }
    Ok(est_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::{LifecycleState, SnapshotState},
        error::FailureClass,
        store::{Entry, GenerationRecord, Journal, fixtures},
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
            agent_memory_mib: 512,
        }
    }

    fn lease(vcpus: u32, memory_mib: u64, disk_mib: u64, uid_slot: u32) -> Reservation {
        Reservation { vcpus, memory_mib, disk_mib, uid_slot }
    }

    fn state_with(gens: Vec<GenerationRecord>) -> JournalState {
        let d = tempfile::tempdir().unwrap();
        let (j, _) = Journal::open(&d.path().join("j.wal")).unwrap();
        j.commit(gens.into_iter().map(|g| Entry::Generation(Box::new(g))).collect()).unwrap();
        j.read(Clone::clone).unwrap()
    }

    const FREE: u64 = 1 << 40;
    const NONE_BUSY: &BTreeSet<u32> = &BTreeSet::new();

    fn pool(size: u32) -> Pool<'static> {
        Pool { size, busy: NONE_BUSY }
    }

    #[test]
    fn grants_the_lowest_free_slot_and_adds_the_runtime_overhead_to_memory() {
        let s = state_with(vec![fixtures::generation(lease(1, 192, 64, 0), LifecycleState::Ready)]);
        let r = reserve_sandbox(&s, &env(), 64, pool(16), &fixtures::resources(1, 256, 128), FREE).unwrap();
        assert_eq!((r.uid_slot, r.memory_mib, r.vcpus), (1, 320, 1));
    }

    #[test]
    fn each_dimension_can_be_the_one_that_refuses_and_none_is_ever_clamped() {
        let full = |c, m, d| state_with(vec![fixtures::generation(lease(c, m, d, 0), LifecycleState::Running)]);
        let e = env();
        let attempt = |s: &JournalState| reserve_sandbox(s, &e, 0, pool(16), &fixtures::resources(2, 1024, 2048), FREE).unwrap_err();
        assert!(attempt(&full(3, 0, 0)).message.contains("vCPUs"));
        assert!(attempt(&full(0, 1500, 0)).message.contains("memory"));
        assert!(attempt(&full(0, 0, 3000)).message.contains("disk"));
        let no_space = reserve_sandbox(&full(0, 0, 0), &e, 0, pool(16), &fixtures::resources(2, 1024, 2048), 1024).unwrap_err();
        assert!(no_space.message.contains("headroom"), "{}", no_space.message);
        for err in [attempt(&full(3, 0, 0)), no_space] {
            assert_eq!(err.class, FailureClass::ResourceExhausted);
            assert!(err.is_definite(), "a refusal changed nothing");
        }
    }

    #[test]
    fn sandbox_count_and_the_identifier_pool_are_hard_limits() {
        let three: Vec<_> = (0..3).map(|i| fixtures::generation(lease(0, 0, 0, i), LifecycleState::Ready)).collect();
        assert!(
            reserve_sandbox(&state_with(three), &env(), 0, pool(16), &fixtures::resources(1, 128, 64), FREE)
                .unwrap_err()
                .message
                .contains("limit of 3")
        );
        let mut e = env();
        e.max_sandboxes = 10;
        let two: Vec<_> = (0..2).map(|i| fixtures::generation(lease(0, 0, 0, i), LifecycleState::Ready)).collect();
        assert!(
            reserve_sandbox(&state_with(two), &e, 0, pool(2), &fixtures::resources(1, 128, 64), FREE)
                .unwrap_err()
                .message
                .contains("identifier slot")
        );
    }

    #[test]
    fn a_slot_carried_by_a_live_resource_is_never_assigned_whatever_the_records_say() {
        // RS-3 / T-RES-04: the store shows every slot free (as it would after a store regression),
        // but a live process still carries slots 0 and 1.
        let busy: BTreeSet<u32> = [0, 1].into();
        let r = reserve_sandbox(&state_with(vec![]), &env(), 0, Pool { size: 16, busy: &busy }, &fixtures::resources(1, 128, 64), FREE)
            .unwrap();
        assert_eq!(r.uid_slot, 2);
        let all: BTreeSet<u32> = (0..4).collect();
        let e = reserve_sandbox(&state_with(vec![]), &env(), 0, Pool { size: 4, busy: &all }, &fixtures::resources(1, 128, 64), FREE)
            .unwrap_err();
        assert_eq!(e.class, FailureClass::ResourceExhausted);
    }

    #[test]
    fn destroyed_generations_release_capacity_and_their_slot() {
        let s = state_with(vec![fixtures::generation(lease(4, 2048, 4096, 0), LifecycleState::Destroyed)]);
        let r = reserve_sandbox(&s, &env(), 0, pool(16), &fixtures::resources(4, 2048, 4096), FREE).unwrap();
        assert_eq!(r.uid_slot, 0, "the slot is reusable once the generation is destroyed");
    }

    #[test]
    fn failed_and_quarantined_generations_keep_their_lease_until_destroyed() {
        let mut quarantined = fixtures::generation(lease(4, 0, 0, 1), LifecycleState::Failed);
        quarantined.quarantined = Some("ownership cannot be proven".into());
        for g in [fixtures::generation(lease(4, 0, 0, 0), LifecycleState::Failed), quarantined] {
            let s = state_with(vec![g]);
            assert!(
                reserve_sandbox(&s, &env(), 0, pool(16), &fixtures::resources(1, 128, 64), FREE).is_err(),
                "a failed or quarantined generation still holds its capacity (LS-1)"
            );
        }
    }

    #[test]
    fn snapshot_quota_count_and_free_space() {
        let d = tempfile::tempdir().unwrap();
        let (j, _) = Journal::open(&d.path().join("j.wal")).unwrap();
        j.commit(vec![
            Entry::Snapshot(Box::new(fixtures::snapshot(600 << 20, SnapshotState::Ready))),
            Entry::Snapshot(Box::new(fixtures::snapshot(1 << 40, SnapshotState::Deleted))),
        ])
        .unwrap();
        let s = j.read(Clone::clone).unwrap();
        let e = env();
        assert!(reserve_snapshot(&s, &e, 300 << 20, FREE).is_ok());
        assert_eq!(
            reserve_snapshot(&s, &e, 500 << 20, FREE).unwrap_err().class,
            FailureClass::ResourceExhausted,
            "600+500 MiB > 1 GiB quota; the deleted one must not count"
        );
        assert!(reserve_snapshot(&s, &e, 1 << 20, 1 << 20).is_err(), "free space + headroom");
        j.commit(vec![Entry::Snapshot(Box::new(fixtures::snapshot(1 << 20, SnapshotState::Ready)))]).unwrap();
        let s = j.read(Clone::clone).unwrap();
        assert!(reserve_snapshot(&s, &e, 1, FREE).unwrap_err().message.contains("limit of 2"), "count limit");
        assert!(snapshot_estimate_bytes(&fixtures::resources(1, 512, 1024)) > (512 + 1024) * MIB);
    }
}
