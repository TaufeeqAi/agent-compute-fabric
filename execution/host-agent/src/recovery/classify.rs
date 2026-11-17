//! The recovery decision table (spec §22.4) as a **pure function**, so every row is a unit test.

use crate::domain::{LifecycleState, OperationType};

/// What is actually running for the generation under examination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmObs {
    Absent,
    Running,
    Paused,
    NotStarted,
    /// A process holds the recorded pid but is not the recorded instance. Treated as gone: it is
    /// **never** signalled.
    Foreign,
    Unknown,
}

/// State of the generation directory relative to the journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirObs {
    Absent,
    /// The on-disk OWNER marker names this exact generation and the journal's nonce.
    Owned,
    NotOwned(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    pub vm: VmObs,
    pub dir: DirObs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// The operation never changed anything. Close it as failed; release what it reserved.
    AbandonUntouched,
    /// Partial host resources exist and are provably ours: tear down, then report failure.
    CleanupThenFail,
    /// Stop the VMM, mark the generation `FAILED`, report the *operation* failed (start).
    StopAndMarkFailed,
    /// The result of a guest command cannot be known: stop the VMM, mark `FAILED`, op `UNKNOWN`.
    FailSafeUnknown,
    /// Re-drive an idempotent stop/destroy/delete to completion; the operation then succeeded.
    RetryIdempotent,
    /// Restore had already switched generations: finish retiring the superseded one.
    RetireSuperseded,
    /// An interrupted snapshot: bring the guest back, discard partial artifacts, release quota.
    DiscardSnapshot,
    /// Ownership cannot be proven. Leave everything in place and flag it.
    Quarantine(String),
}

/// `step` is the last declared write-ahead step (if any). `switched` is true when a restore had
/// already made the new generation current.
pub fn classify(op: OperationType, gen_state: Option<LifecycleState>, has_handle: bool, obs: &Observed, switched: bool) -> Plan {
    use OperationType::*;
    if let DirObs::NotOwned(why) = &obs.dir {
        return Plan::Quarantine(format!("generation directory ownership cannot be proven: {why}"));
    }
    match op {
        SandboxCreate => {
            // Create only ever commits `handle` atomically with its terminal record, so a
            // non-terminal create always has a partial (or no) provisioning.
            if obs.dir == DirObs::Absent && matches!(obs.vm, VmObs::Absent | VmObs::Foreign) {
                Plan::AbandonUntouched
            } else {
                Plan::CleanupThenFail
            }
        }
        SandboxStart => {
            if matches!(obs.vm, VmObs::Absent | VmObs::Foreign) {
                Plan::AbandonUntouched
            } else {
                Plan::StopAndMarkFailed
            }
        }
        Exec => Plan::FailSafeUnknown,
        SandboxStop | SandboxDestroy | SnapshotDelete => Plan::RetryIdempotent,
        SnapshotCreate => Plan::DiscardSnapshot,
        SnapshotRestore => {
            if switched {
                Plan::RetireSuperseded
            } else if obs.dir == DirObs::Absent && matches!(obs.vm, VmObs::Absent | VmObs::Foreign) {
                Plan::AbandonUntouched
            } else {
                let _ = (gen_state, has_handle);
                Plan::CleanupThenFail
            }
        }
        PolicyReload => Plan::AbandonUntouched,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use LifecycleState as S;
    use OperationType as T;

    fn obs(vm: VmObs, dir: DirObs) -> Observed {
        Observed { vm, dir }
    }

    #[test]
    fn ownership_doubt_always_wins_over_every_other_rule() {
        for op in [
            T::SandboxCreate,
            T::SandboxStart,
            T::Exec,
            T::SandboxStop,
            T::SandboxDestroy,
            T::SnapshotCreate,
            T::SnapshotRestore,
            T::SnapshotDelete,
        ] {
            let p = classify(op, Some(S::Ready), true, &obs(VmObs::Running, DirObs::NotOwned("forged marker".into())), true);
            assert!(matches!(p, Plan::Quarantine(_)), "{op:?} must quarantine on ownership doubt, got {p:?}");
        }
    }

    #[test]
    fn create_decisions() {
        assert_eq!(
            classify(T::SandboxCreate, Some(S::Requested), false, &obs(VmObs::Absent, DirObs::Absent), false),
            Plan::AbandonUntouched
        );
        assert_eq!(
            classify(T::SandboxCreate, Some(S::Provisioning), false, &obs(VmObs::Absent, DirObs::Owned), false),
            Plan::CleanupThenFail
        );
        assert_eq!(
            classify(T::SandboxCreate, Some(S::Provisioning), false, &obs(VmObs::Running, DirObs::Absent), false),
            Plan::CleanupThenFail,
            "a stray VMM with no directory is still cleaned"
        );
    }

    #[test]
    fn start_decisions() {
        assert_eq!(
            classify(T::SandboxStart, Some(S::Provisioning), true, &obs(VmObs::Absent, DirObs::Owned), false),
            Plan::AbandonUntouched,
            "never launched: the sandbox stays startable"
        );
        for vm in [VmObs::Running, VmObs::Paused, VmObs::NotStarted, VmObs::Unknown] {
            assert_eq!(
                classify(T::SandboxStart, Some(S::Provisioning), true, &obs(vm, DirObs::Owned), false),
                Plan::StopAndMarkFailed,
                "{vm:?}: boot state is unprovable, so stop it"
            );
        }
        assert_eq!(
            classify(T::SandboxStart, Some(S::Provisioning), true, &obs(VmObs::Foreign, DirObs::Owned), false),
            Plan::AbandonUntouched,
            "a foreign pid is not ours and is never signalled"
        );
    }

    #[test]
    fn exec_is_always_unknown_whatever_the_vm_looks_like() {
        for vm in [VmObs::Absent, VmObs::Running, VmObs::Paused, VmObs::Foreign, VmObs::Unknown] {
            assert_eq!(classify(T::Exec, Some(S::Running), true, &obs(vm, DirObs::Owned), false), Plan::FailSafeUnknown, "{vm:?}");
        }
    }

    #[test]
    fn idempotent_operations_are_redriven() {
        for op in [T::SandboxStop, T::SandboxDestroy, T::SnapshotDelete] {
            assert_eq!(classify(op, Some(S::Stopping), true, &obs(VmObs::Running, DirObs::Owned), false), Plan::RetryIdempotent, "{op:?}");
        }
    }

    #[test]
    fn restore_before_and_after_the_switch() {
        assert_eq!(
            classify(T::SnapshotRestore, Some(S::Provisioning), false, &obs(VmObs::Running, DirObs::Owned), false),
            Plan::CleanupThenFail
        );
        assert_eq!(
            classify(T::SnapshotRestore, Some(S::Requested), false, &obs(VmObs::Absent, DirObs::Absent), false),
            Plan::AbandonUntouched
        );
        assert_eq!(
            classify(T::SnapshotRestore, Some(S::Ready), true, &obs(VmObs::Running, DirObs::Owned), true),
            Plan::RetireSuperseded,
            "the new generation is already current: only finish retiring the old"
        );
    }

    #[test]
    fn snapshot_create_is_always_discarded_not_adopted() {
        // The manifest digest is only journaled at READY, so a half-written snapshot cannot be bound.
        assert_eq!(classify(T::SnapshotCreate, Some(S::Paused), true, &obs(VmObs::Paused, DirObs::Owned), false), Plan::DiscardSnapshot);
    }
}
