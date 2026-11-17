use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    backend::{BackendIdentity, CapabilityProfile},
    domain::{
        FailureInfo, ImageRef, LifecycleState, OperationPhase, OperationStatus, OperationType, PolicyId, RunResult, SandboxResources,
        SnapshotRef, SnapshotState,
    },
    error::{AcfError, FailureClass, SideEffect},
    ids::{Generation, OperationId, RunId, SandboxId},
    operation::ProcessIdentity,
};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SandboxView {
    pub sandbox_id: SandboxId,
    pub generation: Generation,
    pub name: Option<String>,
    pub state: LifecycleState,
    pub resources: SandboxResources,
    pub image: ImageRef,
    pub process: Option<ProcessIdentity>,
    pub security_profile_id: String,
    pub last_run: Option<RunId>,
    pub source_snapshot: Option<SnapshotRef>,
    pub failure: Option<FailureInfo>,
    pub quarantined: Option<String>,
    /// Honest caveats attached to this result (e.g. restore uniqueness, retire warnings).
    #[serde(default)]
    pub notes: Vec<String>,
    pub updated: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotView {
    pub snapshot: SnapshotRef,
    pub name: Option<String>,
    pub state: SnapshotState,
    pub size_bytes: u64,
    pub source_sandbox: Option<(SandboxId, Generation)>,
    pub manifest_digest: Option<String>,
    pub restore_count: u32,
    pub created: String,
    pub failure: Option<FailureInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OperationView {
    pub operation_id: OperationId,
    pub operation_type: OperationType,
    pub status: OperationStatus,
    pub phase: OperationPhase,
    pub resource_id: String,
    pub failure: Option<FailureInfo>,
    pub result: Option<serde_json::Value>,
    pub run_id: Option<RunId>,
    pub updated: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HostInfo {
    pub version: String,
    pub protocol: String,
    pub instance_id: String,
    /// `normal`, or `read_only_quarantine` when the journal failed its integrity check.
    pub mode: String,
    pub backend: BackendIdentity,
    pub capabilities: CapabilityProfile,
    pub policy: PolicyId,
    pub journal_integrity: String,
    pub live_sandboxes: usize,
    pub snapshots: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ResponseBody {
    HostInfo(HostInfo),
    Sandbox(SandboxView),
    Sandboxes(Vec<SandboxView>),
    Run(Box<RunResult>),
    Snapshot(SnapshotView),
    Snapshots(Vec<SnapshotView>),
    Operation(OperationView),
    Metrics(serde_json::Value),
    Ack,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ErrorBody {
    pub class: FailureClass,
    pub message: String,
    pub side_effect: SideEffect,
    /// True only when the failure is definite *and* worth retrying with the same operation id.
    pub retryable: bool,
    /// True when the outcome is genuinely unknown: resolve with `operation_get`, never re-run.
    pub outcome_unknown: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResponseEnvelope {
    pub protocol: String,
    pub request_id: Option<String>,
    pub operation_id: Option<OperationId>,
    pub status: OperationStatus,
    pub result: Option<ResponseBody>,
    pub error: Option<ErrorBody>,
}

impl ErrorBody {
    pub fn from_failure(f: &FailureInfo) -> Self {
        Self {
            class: f.class,
            message: f.message.clone(),
            side_effect: f.side_effect,
            retryable: f.side_effect == SideEffect::None
                && matches!(f.class, FailureClass::BackendUnavailable | FailureClass::ResourceExhaustion | FailureClass::AdmissionRejected),
            outcome_unknown: f.side_effect == SideEffect::Possible
                && matches!(f.class, FailureClass::TimeoutUnknown | FailureClass::LostResponse | FailureClass::PartialCompletion),
        }
    }
}

/// Status for an error raised **before** any operation record exists (nothing was mutated).
pub fn status_for_pre_record_error(e: &AcfError) -> OperationStatus {
    match e.class {
        FailureClass::StateConflict => OperationStatus::Conflict,
        FailureClass::Validation
        | FailureClass::Authorization
        | FailureClass::AdmissionRejected
        | FailureClass::ResourceExhaustion
        | FailureClass::SchemaMismatch
        | FailureClass::NotFound
        | FailureClass::Unsupported
        | FailureClass::CompatibilityFailure
        | FailureClass::RecoveryQuarantined => OperationStatus::Rejected,
        _ if e.is_definite() => OperationStatus::Failed,
        _ => OperationStatus::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_record_errors_map_to_rejected_or_conflict_never_to_unknown_when_nothing_ran() {
        assert_eq!(status_for_pre_record_error(&AcfError::conflict("x")), OperationStatus::Conflict);
        assert_eq!(status_for_pre_record_error(&AcfError::validation("x")), OperationStatus::Rejected);
        assert_eq!(status_for_pre_record_error(&AcfError::authorization("x")), OperationStatus::Rejected);
        assert_eq!(status_for_pre_record_error(&AcfError::new(FailureClass::AdmissionRejected, "x")), OperationStatus::Rejected);
    }

    #[test]
    fn retryable_and_unknown_flags_are_mutually_exclusive_and_conservative() {
        let definite = ErrorBody::from_failure(&FailureInfo {
            class: FailureClass::BackendUnavailable,
            message: "m".into(),
            side_effect: SideEffect::None,
        });
        assert!(definite.retryable && !definite.outcome_unknown);
        let unknown = ErrorBody::from_failure(&FailureInfo {
            class: FailureClass::TimeoutUnknown,
            message: "m".into(),
            side_effect: SideEffect::Possible,
        });
        assert!(!unknown.retryable && unknown.outcome_unknown, "an ambiguous outcome must never be advertised as safely retryable");
        let possible_unavailable = ErrorBody::from_failure(&FailureInfo {
            class: FailureClass::BackendUnavailable,
            message: "m".into(),
            side_effect: SideEffect::Possible,
        });
        assert!(!possible_unavailable.retryable);
    }
}
