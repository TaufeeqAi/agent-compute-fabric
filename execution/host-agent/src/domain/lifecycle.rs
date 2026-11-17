//! Phase 1 lifecycle state machine (spec §11).
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
//! `ROLLBACKING`, `SNAPSHOT`, `ARCHIVED` from the Master Plan are deliberately absent (§11.1).

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
    /// includes the spec §11.3 cases: `DESTROYED -> *`, `FAILED -> RUNNING`, `STOPPED -> RUNNING`.
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

/// Snapshot artifact state (spec §11.2, creation half).
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

    /// A snapshot can only be restored from `Ready` — `SNAPSHOT_INVALID -> RESTORING` is
    /// forbidden (spec §11.3).
    pub const fn is_restorable(self) -> bool {
        matches!(self, SnapshotState::Ready)
    }
}

/// Restore progress (spec §11.2, restore half). Carried in the operation's step.
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
