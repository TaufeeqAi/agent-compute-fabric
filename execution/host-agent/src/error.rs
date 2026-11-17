//! The failure taxonomy (spec §14.1) and the single error type used across the host agent.
//!
//! Every error carries a [`FailureClass`] *and* a [`SideEffect`] marker. The marker is what
//! lets the coordinator apply the post-failure observation protocol (spec §14.3): an error
//! that *may* have followed a mutation is never reported as a plain `FAILED`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Spec §14.1, plus three non-semantic additions the wire protocol needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FailureClass {
    Validation,
    Authorization,
    StateConflict,
    AdmissionRejected,
    ResourceExhaustion,
    TimeoutUnknown,
    BackendUnavailable,
    BackendCrash,
    CorruptInput,
    SchemaMismatch,
    CompatibilityFailure,
    PartialCompletion,
    LostResponse,
    SecurityControlFailure,
    EvidenceIncomplete,
    OutputLimit,
    RecoveryQuarantined,
    /// Stable capability result for operations a backend does not support (DELTA-018).
    Unsupported,
    NotFound,
    Internal,
}

/// Whether the failed step may already have changed host state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SideEffect {
    /// Failed before any mutation: safe to report as a definite failure.
    None,
    /// The mutation may or may not have happened. Must be reconciled by observation.
    Possible,
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("{class:?}: {message}")]
pub struct AcfError {
    pub class: FailureClass,
    pub message: String,
    pub side_effect: SideEffect,
    /// Set only by crash-point injection (tests): the operation must stop *immediately*, running
    /// neither compensation nor commit code, exactly as process death would.
    #[cfg(any(test, feature = "testing"))]
    pub simulated_crash: bool,
}

pub type Result<T, E = AcfError> = std::result::Result<T, E>;

impl AcfError {
    pub fn new(class: FailureClass, message: impl Into<String>) -> Self {
        Self {
            class,
            message: message.into(),
            side_effect: SideEffect::None,
            #[cfg(any(test, feature = "testing"))]
            simulated_crash: false,
        }
    }

    /// True when this error stands for injected process death (always false in release builds).
    pub fn is_simulated_crash(&self) -> bool {
        #[cfg(any(test, feature = "testing"))]
        {
            self.simulated_crash
        }
        #[cfg(not(any(test, feature = "testing")))]
        {
            false
        }
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn simulated_crash(point: &str) -> Self {
        let mut e = Self::new(FailureClass::Internal, format!("simulated crash at {point}")).with_possible_side_effect();
        e.simulated_crash = true;
        e
    }

    /// Mark that the failing step may have mutated host state.
    #[must_use]
    pub fn with_possible_side_effect(mut self) -> Self {
        self.side_effect = SideEffect::Possible;
        self
    }

    pub fn validation(m: impl Into<String>) -> Self {
        Self::new(FailureClass::Validation, m)
    }
    pub fn authorization(m: impl Into<String>) -> Self {
        Self::new(FailureClass::Authorization, m)
    }
    pub fn conflict(m: impl Into<String>) -> Self {
        Self::new(FailureClass::StateConflict, m)
    }
    pub fn not_found(m: impl Into<String>) -> Self {
        Self::new(FailureClass::NotFound, m)
    }
    pub fn internal(m: impl Into<String>) -> Self {
        Self::new(FailureClass::Internal, m)
    }
    pub fn corrupt(m: impl Into<String>) -> Self {
        Self::new(FailureClass::CorruptInput, m)
    }
    pub fn security(m: impl Into<String>) -> Self {
        Self::new(FailureClass::SecurityControlFailure, m)
    }
    pub fn unsupported(m: impl Into<String>) -> Self {
        Self::new(FailureClass::Unsupported, m)
    }

    /// True when the caller can be told "this definitely did not happen".
    pub fn is_definite(&self) -> bool {
        self.side_effect == SideEffect::None
    }
}

impl From<std::io::Error> for AcfError {
    fn from(e: std::io::Error) -> Self {
        // An I/O error mid-operation could follow a partial effect; callers that know better
        // (pre-mutation checks) construct a definite error instead.
        Self::new(FailureClass::Internal, format!("I/O error: {e}")).with_possible_side_effect()
    }
}

impl From<serde_json::Error> for AcfError {
    fn from(e: serde_json::Error) -> Self {
        Self::corrupt(format!("JSON error: {e}"))
    }
}

impl From<rustix::io::Errno> for AcfError {
    fn from(e: rustix::io::Errno) -> Self {
        Self::new(FailureClass::Internal, format!("syscall error: {e}")).with_possible_side_effect()
    }
}
