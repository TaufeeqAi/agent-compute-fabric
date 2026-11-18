//! The failure taxonomy (contract §10.5) and the single error type used across the host agent.
//!
//! Every error carries a [`FailureClass`] *and* a [`SideEffect`] marker (FS-2). The marker is what
//! lets the coordinator observe before deciding (FS-3): an error that *may* have followed a mutation
//! is never treated as "nothing happened".
//!
//! The class set is closed and is the wire vocabulary. Two columns of §10.5 are encoded here as
//! predicates so that tests can check them: a class may appear in a **refusal** (the request was not
//! accepted; no record exists), as the **failure of an operation** (a record exists), or both.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Contract §10.5. The wire names are the SCREAMING_SNAKE_CASE forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FailureClass {
    /// Malformed; unknown field or method; bound exceeded; raw secret material.
    InvalidRequest,
    /// Peer not authenticated or not enrolled.
    AuthenticationFailed,
    /// The peer's role does not permit the method.
    AuthorizationDenied,
    /// The safety profile forbids or caps the request. Never clamped.
    SafetyControlDenied,
    /// Target absent or outside the caller's tags; `retry` for an unknown operation.
    NotFound,
    /// Illegal for the current state; sandbox busy; equal or stronger containment in flight.
    StateConflict,
    /// Stale generation or revision precondition.
    RevisionConflict,
    /// Same operation id, different request.
    IdempotencyConflict,
    /// `issued_at` is outside the acceptance horizon.
    ExpiredRequest,
    /// Host capacity, quota or rate limit.
    ResourceExhausted,
    /// The host mode refuses this class of method.
    HostNotServing,
    /// A capability the backend, guest or host does not offer.
    Unsupported,
    /// The target generation is quarantined.
    Quarantined,
    /// A list cursor is older than the change retention window, or from another lineage.
    CursorExpired,
    /// Protocol major mismatch or framing violation, caller ↔ host or host ↔ guest.
    ProtocolError,
    /// Artifact or manifest digest mismatch; an input that fails the trusted-input rule.
    IntegrityFailure,
    /// Snapshot, image or guest agent incompatible with this host.
    IncompatibleRuntime,
    /// The operation's deadline passed.
    Timeout,
    /// Backend, guest or secret provider unavailable.
    DependencyUnavailable,
    /// A mandatory isolation control was missing at launch or later.
    SecurityControlFailure,
    /// The operation failed and what it created is not yet proven removed.
    PartialCompletion,
    /// The operation ended `UNKNOWN`.
    UnknownOutcome,
    /// None of the above.
    InternalError,
}

impl FailureClass {
    pub const ALL: [FailureClass; 23] = [
        Self::InvalidRequest,
        Self::AuthenticationFailed,
        Self::AuthorizationDenied,
        Self::SafetyControlDenied,
        Self::NotFound,
        Self::StateConflict,
        Self::RevisionConflict,
        Self::IdempotencyConflict,
        Self::ExpiredRequest,
        Self::ResourceExhausted,
        Self::HostNotServing,
        Self::Unsupported,
        Self::Quarantined,
        Self::CursorExpired,
        Self::ProtocolError,
        Self::IntegrityFailure,
        Self::IncompatibleRuntime,
        Self::Timeout,
        Self::DependencyUnavailable,
        Self::SecurityControlFailure,
        Self::PartialCompletion,
        Self::UnknownOutcome,
        Self::InternalError,
    ];

    /// Column `R` of §10.5: the class can appear in a refusal.
    pub const fn can_refuse(self) -> bool {
        !matches!(
            self,
            Self::Timeout | Self::DependencyUnavailable | Self::SecurityControlFailure | Self::PartialCompletion | Self::UnknownOutcome
        )
    }

    /// Column `F` of §10.5: the class can be the failure class of an operation.
    pub const fn can_fail_operation(self) -> bool {
        matches!(
            self,
            Self::ResourceExhausted
                | Self::Quarantined
                | Self::ProtocolError
                | Self::IntegrityFailure
                | Self::IncompatibleRuntime
                | Self::Timeout
                | Self::DependencyUnavailable
                | Self::SecurityControlFailure
                | Self::PartialCompletion
                | Self::UnknownOutcome
                | Self::InternalError
        )
    }

    /// What a refused caller should do (API-5).
    ///
    /// * `SameRequestLater` — nothing about the request is wrong; the host cannot take it now.
    /// * `AfterChange` — the request can be accepted once the target, the host or the request changes.
    /// * `Never` — this exact request will never be accepted.
    pub const fn retry_advice(self) -> RetryAdvice {
        match self {
            Self::ResourceExhausted | Self::HostNotServing | Self::DependencyUnavailable | Self::Timeout => RetryAdvice::SameRequestLater,
            Self::StateConflict
            | Self::RevisionConflict
            | Self::SafetyControlDenied
            | Self::Quarantined
            | Self::CursorExpired
            | Self::Unsupported
            | Self::IncompatibleRuntime
            | Self::IntegrityFailure
            | Self::SecurityControlFailure
            | Self::PartialCompletion
            | Self::UnknownOutcome
            | Self::InternalError => RetryAdvice::AfterChange,
            Self::InvalidRequest
            | Self::AuthenticationFailed
            | Self::AuthorizationDenied
            | Self::NotFound
            | Self::IdempotencyConflict
            | Self::ExpiredRequest
            | Self::ProtocolError => RetryAdvice::Never,
        }
    }

    /// RY-5: classes for which the coordinator never retries a step.
    pub const fn never_retried(self) -> bool {
        !matches!(self, Self::DependencyUnavailable | Self::ResourceExhausted | Self::InternalError)
    }
}

/// The `retry` field of a refusal (API-5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RetryAdvice {
    SameRequestLater,
    AfterChange,
    Never,
}

/// Whether the failed step may already have changed host state (FS-2). The default is `Possible`:
/// a backend reports `None` only when it can rule out any change to the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SideEffect {
    /// Failed before any mutation: the effect is definitely absent.
    None,
    /// The mutation may or may not have happened. Must be settled by observation.
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
    /// The operation lost its hold on the sandbox to a containment operation (CC-3): it must stop
    /// without writing anything. Its terminal record was already committed by the operation that
    /// superseded it.
    pub superseded: bool,
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
            superseded: false,
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
        let mut e = Self::new(FailureClass::InternalError, format!("simulated crash at {point}")).with_possible_side_effect();
        e.simulated_crash = true;
        e
    }

    /// The operation was ended by a containment operation and must write nothing more (CC-3).
    pub fn superseded() -> Self {
        let mut e =
            Self::new(FailureClass::StateConflict, "the operation was superseded by a containment operation").with_possible_side_effect();
        e.superseded = true;
        e
    }

    /// An operation must stop without any further write: process death (tests) or supersession.
    pub fn must_stop_silently(&self) -> bool {
        self.superseded || self.is_simulated_crash()
    }

    /// Mark that the failing step may have mutated host state.
    #[must_use]
    pub fn with_possible_side_effect(mut self) -> Self {
        self.side_effect = SideEffect::Possible;
        self
    }

    pub fn validation(m: impl Into<String>) -> Self {
        Self::new(FailureClass::InvalidRequest, m)
    }
    pub fn authentication(m: impl Into<String>) -> Self {
        Self::new(FailureClass::AuthenticationFailed, m)
    }
    pub fn authorization(m: impl Into<String>) -> Self {
        Self::new(FailureClass::AuthorizationDenied, m)
    }
    /// The safety profile forbids or caps the request (SP-3).
    pub fn denied(m: impl Into<String>) -> Self {
        Self::new(FailureClass::SafetyControlDenied, m)
    }
    pub fn conflict(m: impl Into<String>) -> Self {
        Self::new(FailureClass::StateConflict, m)
    }
    pub fn revision(m: impl Into<String>) -> Self {
        Self::new(FailureClass::RevisionConflict, m)
    }
    pub fn not_found(m: impl Into<String>) -> Self {
        Self::new(FailureClass::NotFound, m)
    }
    pub fn exhausted(m: impl Into<String>) -> Self {
        Self::new(FailureClass::ResourceExhausted, m)
    }
    pub fn quarantined(m: impl Into<String>) -> Self {
        Self::new(FailureClass::Quarantined, m)
    }
    pub fn incompatible(m: impl Into<String>) -> Self {
        Self::new(FailureClass::IncompatibleRuntime, m)
    }
    pub fn unavailable(m: impl Into<String>) -> Self {
        Self::new(FailureClass::DependencyUnavailable, m)
    }
    pub fn timeout(m: impl Into<String>) -> Self {
        Self::new(FailureClass::Timeout, m)
    }
    pub fn protocol(m: impl Into<String>) -> Self {
        Self::new(FailureClass::ProtocolError, m)
    }
    pub fn internal(m: impl Into<String>) -> Self {
        Self::new(FailureClass::InternalError, m)
    }
    /// An input that does not match its digest, or cannot be trusted or parsed as what it claims to be.
    pub fn corrupt(m: impl Into<String>) -> Self {
        Self::new(FailureClass::IntegrityFailure, m)
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
        Self::new(FailureClass::InternalError, format!("I/O error: {e}")).with_possible_side_effect()
    }
}

impl From<serde_json::Error> for AcfError {
    fn from(e: serde_json::Error) -> Self {
        Self::corrupt(format!("JSON error: {e}"))
    }
}

impl From<rustix::io::Errno> for AcfError {
    fn from(e: rustix::io::Errno) -> Self {
        Self::new(FailureClass::InternalError, format!("syscall error: {e}")).with_possible_side_effect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_class_set_and_its_two_columns_are_exactly_the_contract_table() {
        // §10.5, transcribed: (wire name, can appear in a refusal, can fail an operation).
        let table: [(&str, bool, bool); 23] = [
            ("INVALID_REQUEST", true, false),
            ("AUTHENTICATION_FAILED", true, false),
            ("AUTHORIZATION_DENIED", true, false),
            ("SAFETY_CONTROL_DENIED", true, false),
            ("NOT_FOUND", true, false),
            ("STATE_CONFLICT", true, false),
            ("REVISION_CONFLICT", true, false),
            ("IDEMPOTENCY_CONFLICT", true, false),
            ("EXPIRED_REQUEST", true, false),
            ("RESOURCE_EXHAUSTED", true, true),
            ("HOST_NOT_SERVING", true, false),
            ("UNSUPPORTED", true, false),
            ("QUARANTINED", true, true),
            ("CURSOR_EXPIRED", true, false),
            ("PROTOCOL_ERROR", true, true),
            ("INTEGRITY_FAILURE", true, true),
            ("INCOMPATIBLE_RUNTIME", true, true),
            ("TIMEOUT", false, true),
            ("DEPENDENCY_UNAVAILABLE", false, true),
            ("SECURITY_CONTROL_FAILURE", false, true),
            ("PARTIAL_COMPLETION", false, true),
            ("UNKNOWN_OUTCOME", false, true),
            ("INTERNAL_ERROR", true, true),
        ];
        for (class, (name, refusal, failure)) in FailureClass::ALL.into_iter().zip(table) {
            assert_eq!(serde_json::to_string(&class).unwrap(), format!("\"{name}\""));
            assert_eq!(class.can_refuse(), refusal, "{name}: refusal column");
            assert_eq!(class.can_fail_operation(), failure, "{name}: operation-failure column");
        }
    }

    #[test]
    fn every_class_has_exactly_one_piece_of_retry_advice_and_never_claims_transience_for_a_bad_request() {
        for c in FailureClass::ALL {
            let _ = c.retry_advice();
        }
        for c in [
            FailureClass::InvalidRequest,
            FailureClass::IdempotencyConflict,
            FailureClass::ExpiredRequest,
            FailureClass::AuthorizationDenied,
        ] {
            assert_eq!(c.retry_advice(), RetryAdvice::Never, "{c:?}");
        }
        assert_eq!(FailureClass::ResourceExhausted.retry_advice(), RetryAdvice::SameRequestLater);
        assert_eq!(FailureClass::StateConflict.retry_advice(), RetryAdvice::AfterChange);
    }

    #[test]
    fn the_classes_that_are_never_retried_include_every_security_and_validation_failure() {
        // RY-5.
        for c in [
            FailureClass::AuthenticationFailed,
            FailureClass::AuthorizationDenied,
            FailureClass::SafetyControlDenied,
            FailureClass::InvalidRequest,
            FailureClass::StateConflict,
            FailureClass::RevisionConflict,
            FailureClass::IntegrityFailure,
            FailureClass::IncompatibleRuntime,
            FailureClass::ProtocolError,
            FailureClass::SecurityControlFailure,
        ] {
            assert!(c.never_retried(), "{c:?}");
        }
        assert!(!FailureClass::DependencyUnavailable.never_retried());
    }

    #[test]
    fn io_and_syscall_errors_default_to_a_possible_side_effect() {
        let e: AcfError = std::io::Error::other("x").into();
        assert_eq!(e.side_effect, SideEffect::Possible, "the default marker is POSSIBLE (FS-2)");
        assert!(AcfError::validation("x").is_definite());
        assert!(AcfError::superseded().must_stop_silently());
    }
}
