//! The recovery decision table (contract §16.2) as **pure functions**, so every row is a unit test
//! (T-REC-01) and the coordinator that applies a decision contains no judgement of its own.
//!
//! Two questions, two functions:
//!
//! * [`decide_inherited`] — Part A: an operation that an earlier activation left unfinished. A
//!   granting operation is **never continued** (OP-18): it is undone to proven absence, or, for an
//!   execution, ended `UNKNOWN`. A containment operation is re-driven (OP-19).
//! * [`decide_idle`] — Part B: a generation that no operation holds. The host adopts what is healthy
//!   and contains what is not. It never repairs in place and never creates privilege (RC-9).
//!
//! **Any combination a table does not list is `Quarantine`.** Doubt is never resolved by deleting.

use crate::domain::{LifecycleState, OperationType};

/// Execution state of a runtime that is present (§16.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecState {
    NotStarted,
    Running,
    Paused,
}

/// Is the recorded runtime instance there? Assembled by the backend from host-side facts only (OB-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Runtime {
    Absent,
    /// The recorded instance (process id, start time and boot id all match).
    Present(ExecState),
    /// Something else holds the recorded process id. It is **never** signalled (OB-3).
    Foreign,
    /// The observation could not be completed within its deadline (OB-2).
    Unknown,
}

/// The generation's on-disk resources relative to the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnDisk {
    Absent,
    /// The ownership marker names this generation, this store lineage and the recorded nonce.
    Owned,
    NotOwned(String),
}

/// Whether the mandatory isolation controls of a present runtime are still in force (IS-3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Enforcement {
    Intact,
    Degraded(String),
    Unknown,
    /// There is no runtime to enforce anything on.
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    pub runtime: Runtime,
    pub on_disk: OnDisk,
    pub enforcement: Enforcement,
}

impl Observed {
    /// Nothing the operation could have created exists, and nothing foreign is in the way.
    fn nothing_exists(&self) -> bool {
        self.on_disk == OnDisk::Absent && matches!(self.runtime, Runtime::Absent | Runtime::Foreign)
    }
}

/// What to do with an operation inherited from an earlier activation (Part A).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InheritedPlan {
    /// Ownership cannot be proven. Nothing is deleted or signalled.
    Quarantine(String),
    /// The operation changed nothing that remains. It ends `FAILED`, `NOT_APPLIED`.
    Abandon,
    /// Partial resources exist and are provably ours: tear down, then fail.
    TearDownThenFail,
    /// A runtime that was never recorded `READY` is not trusted: stop it; generation `FAILED`.
    StopRuntimeThenFail,
    /// The effect of a guest command cannot be established: stop the runtime; operation `UNKNOWN`.
    StopRuntimeUnknown,
    /// Resume the guest if it is paused, remove partial artifacts, release the quota.
    DiscardSnapshot,
    /// The restore had already switched generations: finish retiring the superseded one.
    RetireSuperseded,
    /// Containment: drive it to completion again. It is idempotent.
    Redrive,
}

/// Part A. `switched` is true when a restore had already made its new generation current.
pub fn decide_inherited(op: OperationType, obs: &Observed, switched: bool) -> InheritedPlan {
    use OperationType::*;
    // This row wins over every other.
    if let OnDisk::NotOwned(why) = &obs.on_disk {
        return InheritedPlan::Quarantine(format!("ownership of the generation's resources cannot be proven: {why}"));
    }
    match op {
        SandboxCreate => undo_new_generation(obs),
        SnapshotRestore if switched => InheritedPlan::RetireSuperseded,
        SnapshotRestore => undo_new_generation(obs),
        SandboxStart => match obs.runtime {
            Runtime::Absent => InheritedPlan::Abandon,
            Runtime::Present(_) => InheritedPlan::StopRuntimeThenFail,
            Runtime::Foreign => {
                InheritedPlan::Quarantine("the recorded process id is held by something that is not this generation's runtime".into())
            }
            Runtime::Unknown => InheritedPlan::Quarantine("the runtime could not be observed".into()),
        },
        ExecRun => InheritedPlan::StopRuntimeUnknown,
        SnapshotCreate => InheritedPlan::DiscardSnapshot,
        SandboxStop | SandboxDestroy | SandboxFail | SnapshotDelete | QuarantineRelease => InheritedPlan::Redrive,
        OperationCancel | ProfileReload | HostSetMode | HostAcknowledge => InheritedPlan::Abandon,
    }
}

/// `sandbox.create`, and `snapshot.restore` before its switch: the generation the operation
/// allocated is undone, never completed.
fn undo_new_generation(obs: &Observed) -> InheritedPlan {
    if obs.nothing_exists() {
        return InheritedPlan::Abandon;
    }
    match (&obs.on_disk, obs.runtime) {
        // Resources exist and are ours (a directory with our marker, or the recorded runtime itself).
        (OnDisk::Owned, _) | (OnDisk::Absent, Runtime::Present(_)) => InheritedPlan::TearDownThenFail,
        _ => InheritedPlan::Quarantine("the runtime could not be observed, so absence cannot be proven".into()),
    }
}

/// What to do with a generation no operation holds (Part B).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdlePlan {
    /// Healthy, or nothing the host needs to do. No change.
    NoChange,
    /// Host operation: the runtime is gone; the generation is `FAILED` and keeps its lease (LS-1).
    MarkFailed(String),
    /// Host operation: a mandatory control is no longer in force; stop the runtime; `FAILED` with
    /// `SECURITY_CONTROL_FAILURE`. No repair in place.
    StopDegraded(String),
    /// Host operation: the record says no runtime should exist; make that true.
    StopStray,
    /// Host operation: the sandbox's expiry has passed (§19.2).
    Destroy,
    /// The observation could not be completed; try again at the next sweep (attempts are counted).
    Retry,
    Quarantine(String),
}

/// Facts about the generation that are not observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdleFacts {
    pub state: LifecycleState,
    pub quarantined: bool,
    pub expired: bool,
    /// Recovery attempts already recorded for this generation (RC-4).
    pub attempts: u32,
    pub max_attempts: u32,
}

/// Part B.
pub fn decide_idle(facts: IdleFacts, obs: &Observed) -> IdlePlan {
    use LifecycleState::*;
    // J-6: a quarantined generation is touched only by `quarantine.release`.
    if facts.quarantined || facts.state == Destroyed {
        return IdlePlan::NoChange;
    }
    if let OnDisk::NotOwned(why) = &obs.on_disk {
        return IdlePlan::Quarantine(format!("ownership of the generation's resources cannot be proven: {why}"));
    }
    if facts.expired {
        return IdlePlan::Destroy;
    }
    let unknown =
        matches!(obs.runtime, Runtime::Unknown) || (matches!(obs.runtime, Runtime::Present(_)) && obs.enforcement == Enforcement::Unknown);
    if unknown {
        return if facts.attempts >= facts.max_attempts {
            IdlePlan::Quarantine(format!("the runtime or its enforcement could not be observed in {} attempts", facts.attempts))
        } else {
            IdlePlan::Retry
        };
    }
    let present = matches!(obs.runtime, Runtime::Present(_));
    match facts.state {
        Ready | Completed => match (&obs.runtime, &obs.enforcement) {
            (Runtime::Present(_), Enforcement::Intact) => IdlePlan::NoChange,
            (Runtime::Present(_), Enforcement::Degraded(why)) => IdlePlan::StopDegraded(why.clone()),
            (Runtime::Absent | Runtime::Foreign, _) => IdlePlan::MarkFailed("the runtime is no longer present".into()),
            _ => IdlePlan::Quarantine("unlisted observation for an idle generation".into()),
        },
        // No runtime exists in these states unless an operation is in flight, and none is.
        Requested | Provisioning if !present => IdlePlan::NoChange,
        // The record says there is no usable runtime; a present one is stopped, never adopted.
        Stopped | Failed if present => match &obs.enforcement {
            Enforcement::Degraded(why) if facts.state == Failed => IdlePlan::StopDegraded(why.clone()),
            _ => IdlePlan::StopStray,
        },
        Stopped | Failed => IdlePlan::NoChange,
        // Transient states with no operation holding them: their runtime, if lost, makes them FAILED.
        Running | Paused | Stopping if !present => {
            IdlePlan::MarkFailed("no operation holds this state and its runtime is not present".into())
        }
        Running | Paused | Stopping => match &obs.enforcement {
            Enforcement::Degraded(why) => IdlePlan::StopDegraded(why.clone()),
            _ => IdlePlan::Quarantine(format!("generation is {:?} with a runtime present and no operation in flight", facts.state)),
        },
        Requested | Provisioning => {
            IdlePlan::Quarantine(format!("generation is {:?} with a runtime present and no operation in flight", facts.state))
        }
        Destroyed => IdlePlan::NoChange,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use LifecycleState as S;
    use OperationType as T;

    fn obs(runtime: Runtime, on_disk: OnDisk) -> Observed {
        let enforcement = if matches!(runtime, Runtime::Present(_)) { Enforcement::Intact } else { Enforcement::NotApplicable };
        Observed { runtime, on_disk, enforcement }
    }

    const RUNNING: Runtime = Runtime::Present(ExecState::Running);
    const ALL_RUNTIMES: [Runtime; 6] = [
        Runtime::Absent,
        Runtime::Present(ExecState::NotStarted),
        Runtime::Present(ExecState::Running),
        Runtime::Present(ExecState::Paused),
        Runtime::Foreign,
        Runtime::Unknown,
    ];
    const ALL_TYPES: [T; 14] = [
        T::SandboxCreate,
        T::SandboxStart,
        T::ExecRun,
        T::SnapshotCreate,
        T::SnapshotRestore,
        T::SandboxStop,
        T::SandboxDestroy,
        T::SandboxFail,
        T::SnapshotDelete,
        T::OperationCancel,
        T::ProfileReload,
        T::QuarantineRelease,
        T::HostSetMode,
        T::HostAcknowledge,
    ];

    // ------------------------------------------------------------------ Part A

    #[test]
    fn row_ownership_doubt_wins_over_every_other_row() {
        for op in ALL_TYPES {
            for rt in ALL_RUNTIMES {
                for switched in [false, true] {
                    let p = decide_inherited(op, &obs(rt, OnDisk::NotOwned("forged marker".into())), switched);
                    assert!(matches!(p, InheritedPlan::Quarantine(_)), "{op:?}/{rt:?}/{switched}: got {p:?}");
                }
            }
        }
    }

    #[test]
    fn row_create_with_nothing_existing_is_abandoned() {
        assert_eq!(decide_inherited(T::SandboxCreate, &obs(Runtime::Absent, OnDisk::Absent), false), InheritedPlan::Abandon);
        assert_eq!(
            decide_inherited(T::SandboxCreate, &obs(Runtime::Foreign, OnDisk::Absent), false),
            InheritedPlan::Abandon,
            "a foreign process is not ours: nothing of this generation exists, and it is never signalled"
        );
    }

    #[test]
    fn row_create_with_partial_owned_resources_is_torn_down() {
        for rt in ALL_RUNTIMES {
            assert_eq!(decide_inherited(T::SandboxCreate, &obs(rt, OnDisk::Owned), false), InheritedPlan::TearDownThenFail, "{rt:?}");
        }
        assert_eq!(
            decide_inherited(T::SandboxCreate, &obs(RUNNING, OnDisk::Absent), false),
            InheritedPlan::TearDownThenFail,
            "the recorded runtime with no directory is still a resource of this generation"
        );
    }

    #[test]
    fn create_whose_absence_cannot_be_proven_is_quarantined() {
        let p = decide_inherited(T::SandboxCreate, &obs(Runtime::Unknown, OnDisk::Absent), false);
        assert!(matches!(p, InheritedPlan::Quarantine(_)), "{p:?}");
    }

    #[test]
    fn row_start_with_the_runtime_absent_is_abandoned_and_the_sandbox_stays_startable() {
        assert_eq!(decide_inherited(T::SandboxStart, &obs(Runtime::Absent, OnDisk::Owned), false), InheritedPlan::Abandon);
    }

    #[test]
    fn row_start_with_the_runtime_present_is_stopped_never_adopted() {
        for st in [ExecState::NotStarted, ExecState::Running, ExecState::Paused] {
            assert_eq!(
                decide_inherited(T::SandboxStart, &obs(Runtime::Present(st), OnDisk::Owned), false),
                InheritedPlan::StopRuntimeThenFail,
                "{st:?}: a runtime never recorded READY is not trusted"
            );
        }
    }

    #[test]
    fn start_with_an_unlisted_observation_is_quarantined() {
        for rt in [Runtime::Foreign, Runtime::Unknown] {
            let p = decide_inherited(T::SandboxStart, &obs(rt, OnDisk::Owned), false);
            assert!(matches!(p, InheritedPlan::Quarantine(_)), "{rt:?}: {p:?}");
        }
    }

    #[test]
    fn row_an_execution_is_never_run_again_whatever_is_observed() {
        for rt in ALL_RUNTIMES {
            for disk in [OnDisk::Absent, OnDisk::Owned] {
                assert_eq!(
                    decide_inherited(T::ExecRun, &obs(rt, disk.clone()), false),
                    InheritedPlan::StopRuntimeUnknown,
                    "{rt:?}/{disk:?}"
                );
            }
        }
    }

    #[test]
    fn row_an_interrupted_snapshot_is_discarded_never_adopted() {
        for rt in ALL_RUNTIMES {
            assert_eq!(decide_inherited(T::SnapshotCreate, &obs(rt, OnDisk::Owned), false), InheritedPlan::DiscardSnapshot, "{rt:?}");
        }
    }

    #[test]
    fn row_restore_before_the_switch_is_abandoned_or_torn_down() {
        assert_eq!(decide_inherited(T::SnapshotRestore, &obs(Runtime::Absent, OnDisk::Absent), false), InheritedPlan::Abandon);
        assert_eq!(decide_inherited(T::SnapshotRestore, &obs(RUNNING, OnDisk::Owned), false), InheritedPlan::TearDownThenFail);
        assert_eq!(decide_inherited(T::SnapshotRestore, &obs(Runtime::Absent, OnDisk::Owned), false), InheritedPlan::TearDownThenFail);
    }

    #[test]
    fn row_restore_after_the_switch_only_retires_the_superseded_generation() {
        for rt in ALL_RUNTIMES {
            assert_eq!(decide_inherited(T::SnapshotRestore, &obs(rt, OnDisk::Owned), true), InheritedPlan::RetireSuperseded, "{rt:?}");
        }
    }

    #[test]
    fn row_containment_is_redriven() {
        for op in [T::SandboxStop, T::SandboxDestroy, T::SandboxFail, T::SnapshotDelete, T::QuarantineRelease] {
            for rt in ALL_RUNTIMES {
                assert_eq!(decide_inherited(op, &obs(rt, OnDisk::Owned), false), InheritedPlan::Redrive, "{op:?}/{rt:?}");
            }
        }
    }

    #[test]
    fn row_host_administration_is_abandoned() {
        for op in [T::OperationCancel, T::ProfileReload, T::HostSetMode, T::HostAcknowledge] {
            assert_eq!(decide_inherited(op, &obs(Runtime::Absent, OnDisk::Absent), false), InheritedPlan::Abandon, "{op:?}");
        }
    }

    #[test]
    fn no_inherited_granting_operation_is_ever_continued() {
        // INV-026: there is no plan that means "carry on". Every outcome for a granting type is an
        // undo, a stop, or a quarantine - except a restore that had already switched, whose only
        // remaining work is containment of the superseded generation.
        for op in [T::SandboxCreate, T::SandboxStart, T::ExecRun, T::SnapshotCreate, T::SnapshotRestore] {
            for rt in ALL_RUNTIMES {
                for disk in [OnDisk::Absent, OnDisk::Owned, OnDisk::NotOwned("x".into())] {
                    let p = decide_inherited(op, &obs(rt, disk.clone()), false);
                    assert_ne!(p, InheritedPlan::Redrive, "{op:?}/{rt:?}/{disk:?}");
                    assert_ne!(p, InheritedPlan::RetireSuperseded, "{op:?}/{rt:?}/{disk:?}");
                }
            }
        }
    }

    // ------------------------------------------------------------------ Part B

    fn facts(state: S) -> IdleFacts {
        IdleFacts { state, quarantined: false, expired: false, attempts: 0, max_attempts: 3 }
    }

    #[test]
    fn row_a_healthy_idle_generation_is_adopted_without_change() {
        for s in [S::Ready, S::Completed] {
            assert_eq!(decide_idle(facts(s), &obs(RUNNING, OnDisk::Owned)), IdlePlan::NoChange, "{s:?}");
        }
    }

    #[test]
    fn row_a_lost_runtime_makes_the_generation_failed() {
        for s in [S::Ready, S::Completed, S::Running, S::Paused, S::Stopping] {
            for rt in [Runtime::Absent, Runtime::Foreign] {
                let p = decide_idle(facts(s), &obs(rt, OnDisk::Owned));
                assert!(matches!(p, IdlePlan::MarkFailed(_)), "{s:?}/{rt:?}: {p:?}");
            }
        }
    }

    #[test]
    fn row_degraded_enforcement_stops_the_runtime_and_is_never_repaired() {
        for s in [S::Ready, S::Completed, S::Running, S::Paused, S::Stopping, S::Failed] {
            let o = Observed { runtime: RUNNING, on_disk: OnDisk::Owned, enforcement: Enforcement::Degraded("seccomp filter gone".into()) };
            assert_eq!(decide_idle(facts(s), &o), IdlePlan::StopDegraded("seccomp filter gone".into()), "{s:?}");
        }
    }

    #[test]
    fn row_a_runtime_that_should_not_exist_is_stopped() {
        for s in [S::Stopped, S::Failed] {
            assert_eq!(decide_idle(facts(s), &obs(RUNNING, OnDisk::Owned)), IdlePlan::StopStray, "{s:?}");
            assert_eq!(decide_idle(facts(s), &obs(Runtime::Absent, OnDisk::Owned)), IdlePlan::NoChange, "{s:?}");
        }
    }

    #[test]
    fn row_an_observation_that_stays_unknown_ends_in_quarantine_after_the_bound() {
        for s in [S::Ready, S::Completed, S::Failed, S::Stopped, S::Provisioning] {
            let o = obs(Runtime::Unknown, OnDisk::Owned);
            assert_eq!(decide_idle(IdleFacts { attempts: 2, ..facts(s) }, &o), IdlePlan::Retry, "{s:?}");
            let p = decide_idle(IdleFacts { attempts: 3, ..facts(s) }, &o);
            assert!(matches!(p, IdlePlan::Quarantine(_)), "{s:?}: {p:?}");
        }
        let o = Observed { runtime: RUNNING, on_disk: OnDisk::Owned, enforcement: Enforcement::Unknown };
        assert_eq!(decide_idle(facts(S::Ready), &o), IdlePlan::Retry, "unknown enforcement on a present runtime counts as unknown");
    }

    #[test]
    fn row_expiry_destroys_whatever_the_state() {
        for s in LifecycleState::ALL.into_iter().filter(|s| *s != S::Destroyed) {
            for rt in ALL_RUNTIMES {
                let p = decide_idle(IdleFacts { expired: true, ..facts(s) }, &obs(rt, OnDisk::Owned));
                assert_eq!(p, IdlePlan::Destroy, "{s:?}/{rt:?}");
            }
        }
    }

    #[test]
    fn a_quarantined_or_destroyed_generation_is_never_touched_by_the_sweep() {
        for rt in ALL_RUNTIMES {
            let q = IdleFacts { quarantined: true, expired: true, ..facts(S::Failed) };
            assert_eq!(decide_idle(q, &obs(rt, OnDisk::NotOwned("x".into()))), IdlePlan::NoChange, "{rt:?}");
            assert_eq!(decide_idle(IdleFacts { expired: true, ..facts(S::Destroyed) }, &obs(rt, OnDisk::Absent)), IdlePlan::NoChange);
        }
    }

    #[test]
    fn ownership_doubt_quarantines_before_anything_else_is_considered() {
        let p = decide_idle(
            IdleFacts { expired: true, ..facts(S::Ready) },
            &obs(RUNNING, OnDisk::NotOwned("marker of another lineage".into())),
        );
        assert!(matches!(p, IdlePlan::Quarantine(_)), "{p:?}");
    }

    #[test]
    fn a_generation_awaiting_start_has_no_runtime_and_is_left_alone() {
        for s in [S::Requested, S::Provisioning] {
            assert_eq!(decide_idle(facts(s), &obs(Runtime::Absent, OnDisk::Owned)), IdlePlan::NoChange, "{s:?}");
        }
    }

    #[test]
    fn unlisted_combinations_are_quarantined() {
        // A runtime present in a state that cannot have one without an operation in flight.
        for s in [S::Requested, S::Provisioning, S::Running, S::Paused, S::Stopping] {
            let p = decide_idle(facts(s), &obs(RUNNING, OnDisk::Owned));
            assert!(matches!(p, IdlePlan::Quarantine(_)), "{s:?}: {p:?}");
        }
    }

    #[test]
    fn the_idle_table_is_total_and_never_creates_privilege() {
        // Every (state, runtime, on-disk, enforcement, expired) combination has a plan, and no plan
        // starts, resumes or repairs anything: the only actions are fail, stop, destroy, quarantine.
        let enforcements = [Enforcement::Intact, Enforcement::Degraded("d".into()), Enforcement::Unknown, Enforcement::NotApplicable];
        for s in LifecycleState::ALL {
            for rt in ALL_RUNTIMES {
                for disk in [OnDisk::Absent, OnDisk::Owned, OnDisk::NotOwned("x".into())] {
                    for enf in &enforcements {
                        for expired in [false, true] {
                            let o = Observed { runtime: rt, on_disk: disk.clone(), enforcement: enf.clone() };
                            let _plan: IdlePlan = decide_idle(IdleFacts { expired, ..facts(s) }, &o);
                        }
                    }
                }
            }
        }
    }
}
