//! The generation lifecycle and the snapshot states (contract §12.1, §12.3).
//!
//! ```text
//! REQUESTED -> PROVISIONING -> READY -> RUNNING -> COMPLETED
//!                                 |        |  \-> FAILED
//!                                 +--------+--> PAUSED -> (back to the state it was paused from)
//!      any live state ----------------------> STOPPING -> STOPPED -> DESTROYED
//! ```
//!
//! `Ready` and `Completed` are the two *idle* states (guest agent up, no run in flight):
//! `Ready` before the first run, `Completed` after a run finished with a known result.
//! There is no snapshotting, restoring or destroying *state*: those are operations in flight over
//! the states above (contract Appendix B.2), and `QUARANTINED` is a condition, not a state.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{AcfError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LifecycleState {
    Requested,
    Provisioning,
    Ready,
    Running,
    Paused,
    Completed,
    Failed,
    Stopping,
    Stopped,
    Destroyed,
}

use LifecycleState::*;

impl LifecycleState {
    pub const ALL: [LifecycleState; 10] =
        [Requested, Provisioning, Ready, Running, Paused, Completed, Failed, Stopping, Stopped, Destroyed];

    /// The transition relation. Everything not listed is forbidden, which by construction
    /// includes the consequences stated in §12.1: `DESTROYED -> *`, `FAILED -> RUNNING`, `STOPPED -> RUNNING`.
    pub const fn can_transition_to(self, to: LifecycleState) -> bool {
        matches!(
            (self, to),
            (Requested, Provisioning | Failed | Destroyed)
                | (Provisioning, Ready | Failed | Stopping | Destroyed)
                | (Ready, Running | Paused | Stopping | Failed)
                | (Running, Completed | Failed | Paused | Stopping)
                | (Paused, Ready | Running | Completed | Stopping | Failed)
                | (Completed, Running | Paused | Stopping | Failed)
                | (Failed, Stopping | Stopped | Destroyed)
                | (Stopping, Stopped | Failed)
                | (Stopped, Destroyed)
        )
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Destroyed)
    }

    /// States in which a VMM process may legitimately exist.
    pub const fn may_have_vm(self) -> bool {
        matches!(self, Provisioning | Ready | Running | Paused | Completed | Failed | Stopping)
    }

    /// Guest agent up and no run in flight: the states in which exec/snapshot may begin.
    pub const fn is_idle(self) -> bool {
        matches!(self, Ready | Completed)
    }
}

/// Fail with a deterministic `STATE_CONFLICT` for an illegal transition.
pub fn require_transition(from: LifecycleState, to: LifecycleState) -> Result<()> {
    if from.can_transition_to(to) { Ok(()) } else { Err(AcfError::conflict(format!("illegal lifecycle transition {from:?} -> {to:?}"))) }
}

/// Snapshot artifact state (contract §12.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SnapshotState {
    Requested,
    Snapshotting,
    Verifying,
    Ready,
    Invalid,
    Deleted,
}

impl SnapshotState {
    pub const fn can_transition_to(self, to: SnapshotState) -> bool {
        use SnapshotState as S;
        matches!(
            (self, to),
            (S::Requested, S::Snapshotting | S::Invalid)
                | (S::Snapshotting, S::Verifying | S::Invalid)
                | (S::Verifying, S::Ready | S::Invalid)
                | (S::Ready, S::Invalid | S::Deleted)
                | (S::Invalid, S::Deleted)
        )
    }

    /// Only a `READY` snapshot can be restored (contract §12.3, RE-1).
    pub const fn is_restorable(self) -> bool {
        matches!(self, SnapshotState::Ready)
    }
}

/// Restore progress (contract §21.5). Carried in the operation's step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RestoreState {
    Requested,
    Restoring,
    Verifying,
    RestoredReady,
    RestoreFailed,
    /// Destination state is uncertain. Never auto-retried; resolved by observation (§11.3).
    RestoreUnknown,
}

impl RestoreState {
    pub const fn can_transition_to(self, to: RestoreState) -> bool {
        use RestoreState as R;
        matches!(
            (self, to),
            (R::Requested, R::Restoring | R::RestoreFailed)
                | (R::Restoring, R::Verifying | R::RestoreFailed | R::RestoreUnknown)
                | (R::Verifying, R::RestoredReady | R::RestoreFailed | R::RestoreUnknown)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T-STATE-01: every state × state pair against the relation of §12.1. The table is transcribed
    /// row by row, in the contract's own spelling, so that the two can be compared by eye; it is an
    /// oracle independent of the `matches!` above. Anything not listed is illegal and is refused
    /// with `STATE_CONFLICT`.
    #[test]
    fn every_pair_of_states_is_judged_exactly_as_the_contract_table_says() {
        const TABLE: &[(&str, &str)] = &[
            ("REQUESTED", "PROVISIONING, FAILED, DESTROYED"),
            ("PROVISIONING", "READY, FAILED, STOPPING, DESTROYED"),
            ("READY", "RUNNING, PAUSED, STOPPING, FAILED"),
            ("RUNNING", "COMPLETED, PAUSED, STOPPING, FAILED"),
            ("PAUSED", "READY, RUNNING, COMPLETED, STOPPING, FAILED"),
            ("COMPLETED", "RUNNING, PAUSED, STOPPING, FAILED"),
            ("STOPPING", "STOPPED, FAILED"),
            ("STOPPED", "DESTROYED"),
            ("FAILED", "STOPPING, STOPPED, DESTROYED"),
        ];
        let name = |s: LifecycleState| serde_json::to_value(s).unwrap().as_str().unwrap().to_owned();
        let names: Vec<String> = LifecycleState::ALL.iter().map(|s| name(*s)).collect();
        // A misspelt state in the transcription would silently read as "illegal": every word is a state.
        for (from, to) in TABLE {
            assert!(names.iter().any(|n| n == from), "{from} is not a state");
            assert!(to.split(", ").all(|t| names.iter().any(|n| n == t)), "{to}");
        }
        assert_eq!(TABLE.len(), LifecycleState::ALL.len() - 1, "DESTROYED has no row: nothing leaves it");

        let mut pairs = 0;
        for from in LifecycleState::ALL {
            let listed: Vec<&str> =
                TABLE.iter().find(|(f, _)| *f == name(from)).map(|(_, to)| to.split(", ").collect()).unwrap_or_default();
            for to in LifecycleState::ALL {
                let legal = listed.contains(&name(to).as_str());
                assert_eq!(from.can_transition_to(to), legal, "{} -> {}", name(from), name(to));
                match require_transition(from, to) {
                    Ok(()) => assert!(legal),
                    Err(e) => {
                        assert!(!legal);
                        assert_eq!(e.class, crate::error::FailureClass::StateConflict, "{} -> {}", name(from), name(to));
                    }
                }
                pairs += 1;
            }
        }
        assert_eq!(pairs, 100);
    }

    /// §12.3, pair by pair: the path to `READY`, `INVALID` from every state before `DELETED`, and
    /// nothing else.
    #[test]
    fn every_pair_of_snapshot_states_is_judged_as_the_contract_says() {
        use SnapshotState as S;
        const ALL: [S; 6] = [S::Requested, S::Snapshotting, S::Verifying, S::Ready, S::Invalid, S::Deleted];
        let legal = [
            (S::Requested, S::Snapshotting),
            (S::Snapshotting, S::Verifying),
            (S::Verifying, S::Ready),
            (S::Ready, S::Deleted),
            (S::Requested, S::Invalid),
            (S::Snapshotting, S::Invalid),
            (S::Verifying, S::Invalid),
            (S::Invalid, S::Deleted),
            (S::Ready, S::Invalid),
        ];
        for from in ALL {
            for to in ALL {
                assert_eq!(from.can_transition_to(to), legal.contains(&(from, to)), "{from:?} -> {to:?}");
            }
            assert_eq!(from.is_restorable(), from == S::Ready, "only a READY snapshot can be restored");
        }
    }

    #[test]
    fn spec_forbidden_transitions_are_forbidden() {
        // DESTROYED -> RUNNING (§11.3), FAILED -> RUNNING, plus the whole DESTROYED row.
        assert!(!Destroyed.can_transition_to(Running));
        assert!(!Failed.can_transition_to(Running));
        assert!(!Stopped.can_transition_to(Running));
        for to in LifecycleState::ALL {
            assert!(!Destroyed.can_transition_to(to), "DESTROYED must be absorbing, but allows {to:?}");
        }
        assert!(!SnapshotState::Invalid.can_transition_to(SnapshotState::Ready));
        assert!(!SnapshotState::Invalid.is_restorable());
        assert!(!RestoreState::RestoreUnknown.can_transition_to(RestoreState::Requested));
        assert!(!RestoreState::RestoreUnknown.can_transition_to(RestoreState::Restoring));
    }

    #[test]
    fn happy_path_is_legal() {
        let path = [Requested, Provisioning, Ready, Running, Completed, Running, Completed, Stopping, Stopped, Destroyed];
        for w in path.windows(2) {
            assert!(w[0].can_transition_to(w[1]), "{:?} -> {:?}", w[0], w[1]);
        }
    }

    #[test]
    fn no_state_transitions_to_itself_or_back_to_requested() {
        for s in LifecycleState::ALL {
            assert!(!s.can_transition_to(s), "{s:?} self-transition");
            assert!(!s.can_transition_to(Requested), "{s:?} -> REQUESTED");
        }
    }

    #[test]
    fn every_non_terminal_state_can_reach_destroyed() {
        // Liveness: a sandbox can never be wedged in a state with no way to clean it up.
        for start in LifecycleState::ALL.into_iter().filter(|s| !s.is_terminal()) {
            let mut seen = vec![start];
            let mut frontier = vec![start];
            while let Some(s) = frontier.pop() {
                for to in LifecycleState::ALL {
                    if s.can_transition_to(to) && !seen.contains(&to) {
                        seen.push(to);
                        frontier.push(to);
                    }
                }
            }
            assert!(seen.contains(&Destroyed), "{start:?} cannot reach DESTROYED");
        }
    }

    #[test]
    fn require_transition_yields_state_conflict() {
        let e = require_transition(Destroyed, Running).unwrap_err();
        assert_eq!(e.class, crate::error::FailureClass::StateConflict);
        assert!(e.is_definite());
    }
}
