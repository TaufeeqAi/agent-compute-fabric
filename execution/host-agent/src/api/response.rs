//! The response model (contract §10.4, §10.6).
//!
//! A request to a granting, containment or operator method receives exactly one of two answers
//! (FS-1): `REFUSED` — nothing was accepted, no record exists — or `OPERATION` — a durable operation
//! record exists and `view` is its state as of the response. A read receives `RESULT` or `REFUSED`.
//! Every answer that reflects committed state says which state: `as_of` (API-10).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::command::{Cursor, OutputStream};
use crate::{
    authority::profile::ProfileLimits,
    backend::{BackendIdentity, CapabilityProfile},
    domain::{
        CancelledBy, Cleanup, ContainmentReason, Effect, FailureInfo, HostMode, ImageRef, Issuer, LifecycleState, OperationState,
        OperationType, OutputStatus, ProfileId, RunResult, SandboxResources, SnapshotRef, SnapshotState, Tags,
    },
    error::{AcfError, FailureClass, RetryAdvice},
    ids::{Generation, OperationId, RunId, SandboxId},
    store::ProcessIdentity,
};

/// The committed state an answer reflects (API-10): a store lineage and a commit sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AsOf {
    pub lineage: String,
    pub sequence: u64,
}

/// `REFUSED {class, retry}` (API-5): nothing was applied, and nothing was recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Refusal {
    pub class: FailureClass,
    pub retry: RetryAdvice,
    pub message: String,
}

impl Refusal {
    /// A refusal from an error raised before BEGIN. A class that cannot appear in a refusal (§10.5,
    /// column `R`) is reported as `INTERNAL_ERROR`: the request was not accepted, for a reason that
    /// is the host's.
    pub fn from_error(e: &AcfError) -> Self {
        let class = if e.class.can_refuse() { e.class } else { FailureClass::InternalError };
        Self { class, retry: class.retry_advice(), message: e.message.clone() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SandboxView {
    pub sandbox_id: SandboxId,
    pub generation: Generation,
    pub name: Option<String>,
    pub state: LifecycleState,
    pub resources: SandboxResources,
    pub image: ImageRef,
    /// Tags of the request that created the sandbox (AU-8).
    pub tags: Tags,
    /// When the sandbox ends (LT-1), wall clock, for display. The host enforces the monotonic one.
    pub expires_at: String,
    pub process: Option<ProcessIdentity>,
    pub security_profile_id: String,
    pub last_run: Option<RunId>,
    pub source_snapshot: Option<SnapshotRef>,
    pub failure: Option<FailureInfo>,
    /// The condition `QUARANTINED`, with its reason.
    pub quarantined: Option<String>,
    /// Secret material was delivered to this generation (SC-5).
    pub secret_bearing: bool,
    /// Honest caveats attached to this view (for example restore uniqueness).
    #[serde(default)]
    pub notes: Vec<String>,
    pub updated: String,
    /// Commit sequence of the last change to the sandbox's caller-visible state (ID-3).
    pub revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotView {
    pub snapshot: SnapshotRef,
    pub name: Option<String>,
    pub state: SnapshotState,
    pub tags: Tags,
    pub size_bytes: u64,
    pub source_sandbox: Option<(SandboxId, Generation)>,
    pub manifest_digest: Option<String>,
    pub restore_count: u32,
    /// References of the secrets live in the sandbox at capture (SC-5). Never material.
    #[serde(default)]
    pub secret_refs: Vec<String>,
    /// Why this snapshot cannot be restored on this host as it is now (§21.6). Empty: compatible.
    #[serde(default)]
    pub incompatible: Vec<String>,
    pub created: String,
    pub failure: Option<FailureInfo>,
    pub revision: u64,
}

/// What the host changed for an operator method.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HostChange {
    pub mode: Option<HostMode>,
    pub profile: Option<ProfileId>,
    pub note: Option<String>,
}

/// The typed result of an operation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant, reason = "one value per response; boxing each view would move the same bytes behind an allocation")]
pub enum OperationResult {
    Sandbox(SandboxView),
    Snapshot(SnapshotView),
    Run(Box<RunResult>),
    Host(HostChange),
}

/// An operation as of the response (API-6). Terminal only if it ended within the caller's `wait`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OperationView {
    pub operation_id: OperationId,
    pub operation_type: OperationType,
    pub state: OperationState,
    /// Present once terminal (API-9).
    pub effect: Option<Effect>,
    /// Present on a `FAILED` or `CANCELLED` operation (OP-7). Derived from committed state at the
    /// time of the response, so it becomes `COMPLETE` when what the operation left is later removed.
    pub cleanup: Option<Cleanup>,
    pub cancelled_by: Option<CancelledBy>,
    pub issuer: Issuer,
    pub tags: Tags,
    pub on_behalf_of: Option<String>,
    /// `sbx-…`, `snp-…` or `host`.
    pub target: String,
    /// The last privileged step declared.
    pub step: Option<String>,
    pub failure: Option<FailureInfo>,
    pub result: Option<OperationResult>,
    pub run_id: Option<RunId>,
    pub sandbox: Option<(SandboxId, Generation)>,
    pub snapshot: Option<SnapshotRef>,
    /// The safety profile the operation was admitted under (SP-2).
    pub profile_id: ProfileId,
    pub activation_epoch: u64,
    pub issued_at: String,
    pub created: String,
    pub updated: String,
    pub revision: u64,
}

/// Parameters a caller depends on (PR-3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CallerParameters {
    pub acceptance_horizon_ms: u64,
    pub clock_skew_tolerance_ms: u64,
    pub operation_retention_ms: u64,
    pub change_retention_ms: u64,
    pub output_retention_ms: u64,
    pub wait_max_ms: u64,
    pub max_request_bytes: u64,
    /// The profile's ceilings (PR-3).
    pub ceilings: ProfileLimits,
    pub sandbox_lifetime_default_secs: u64,
    pub sandbox_lifetime_max_secs: u64,
    pub allowlist_max_entries: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HostInfo {
    pub version: String,
    pub host_id: String,
    /// Protocol identifiers this host accepts (VR-3).
    pub protocols: Vec<String>,
    /// Features this host offers. A request using an unlisted feature is refused (VR-3).
    pub features: Vec<String>,
    pub mode: HostMode,
    /// Why the host is in `CONTAINMENT`, when it is.
    pub containment_reasons: Vec<ContainmentReason>,
    /// Why the host is in `READ_ONLY`, when it is.
    pub read_only_reason: Option<String>,
    pub lineage: String,
    pub activation_epoch: u64,
    pub instance_id: String,
    pub backend: BackendIdentity,
    pub capabilities: CapabilityProfile,
    pub profile: ProfileId,
    pub parameters: CallerParameters,
    pub store_integrity: String,
    pub live_sandboxes: usize,
    pub snapshots: usize,
    pub quarantined: usize,
    /// Operations that have not ended (what a drain waits for).
    pub operations_in_flight: usize,
}

/// One page of a list (API-11). `items` are in ascending revision order. Continue from `next`; when
/// `more` is false, `next` is the position the listing is complete up to.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub more: bool,
    pub next: Cursor,
}

/// A slice of one stream of an execution's stored output (OU-4).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OutputChunk {
    pub run_id: RunId,
    pub stream: OutputStream,
    pub offset: u64,
    pub data_b64: String,
    /// Bytes stored for the stream, and bytes the workload produced (OU-2).
    pub stored_bytes: u64,
    pub produced_bytes: u64,
    pub completeness: OutputStatus,
    /// No stored byte follows this slice.
    pub eof: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant, reason = "one value per response; boxing each view would move the same bytes behind an allocation")]
pub enum ReadResult {
    HostInfo(Box<HostInfo>),
    Metrics(serde_json::Value),
    Sandbox(SandboxView),
    Sandboxes(Page<SandboxView>),
    Snapshots(Page<SnapshotView>),
    Operation(Box<OperationView>),
    Operations(Page<OperationView>),
    Run(Box<RunResult>),
    Output(OutputChunk),
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "answer", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Answer {
    /// The request was not accepted. No operation record, no reservation, no effect.
    Refused { refusal: Refusal },
    /// The request was accepted. A durable operation record exists.
    Operation { operation: Box<OperationView> },
    /// A read, served from committed state.
    Result { result: Box<ReadResult> },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResponseEnvelope {
    pub protocol: String,
    /// Echo of the request's `request_id`.
    pub request_id: Option<String>,
    #[serde(flatten)]
    pub answer: Answer,
    /// The committed state this answer reflects. Absent only on a refusal that consulted no state.
    pub as_of: Option<AsOf>,
}

impl ResponseEnvelope {
    pub fn refused(request_id: Option<String>, e: &AcfError, as_of: Option<AsOf>) -> Self {
        Self { protocol: super::PROTOCOL.to_owned(), request_id, answer: Answer::Refused { refusal: Refusal::from_error(e) }, as_of }
    }

    pub fn operation(request_id: Option<String>, view: OperationView, as_of: AsOf) -> Self {
        Self {
            protocol: super::PROTOCOL.to_owned(),
            request_id,
            answer: Answer::Operation { operation: Box::new(view) },
            as_of: Some(as_of),
        }
    }

    pub fn result(request_id: Option<String>, result: ReadResult, as_of: AsOf) -> Self {
        Self { protocol: super::PROTOCOL.to_owned(), request_id, answer: Answer::Result { result: Box::new(result) }, as_of: Some(as_of) }
    }

    pub fn refusal(&self) -> Option<&Refusal> {
        match &self.answer {
            Answer::Refused { refusal } => Some(refusal),
            _ => None,
        }
    }

    pub fn operation_view(&self) -> Option<&OperationView> {
        match &self.answer {
            Answer::Operation { operation } => Some(operation),
            _ => None,
        }
    }

    pub fn read_result(&self) -> Option<&ReadResult> {
        match &self.answer {
            Answer::Result { result } => Some(result),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::SideEffect;

    #[test]
    fn a_refusal_carries_a_class_from_the_refusal_column_and_its_retry_advice() {
        for class in FailureClass::ALL {
            let r = Refusal::from_error(&AcfError::new(class, "m"));
            assert!(r.class.can_refuse(), "{class:?} surfaced in a refusal as {:?}", r.class);
            assert_eq!(r.retry, r.class.retry_advice());
            if class.can_refuse() {
                assert_eq!(r.class, class);
            } else {
                assert_eq!(r.class, FailureClass::InternalError, "{class:?} cannot appear in a refusal");
            }
        }
    }

    #[test]
    fn the_wire_form_of_the_three_answers() {
        let as_of = AsOf { lineage: "l".into(), sequence: 7 };
        let refused =
            serde_json::to_value(ResponseEnvelope::refused(Some("r-1".into()), &AcfError::conflict("busy"), Some(as_of.clone()))).unwrap();
        assert_eq!(refused["answer"], "REFUSED");
        assert_eq!(refused["refusal"]["class"], "STATE_CONFLICT");
        assert_eq!(refused["refusal"]["retry"], "AFTER_CHANGE");
        assert_eq!(refused["as_of"]["sequence"], 7);
        assert!(refused.get("operation").is_none() && refused.get("result").is_none(), "a refusal carries nothing else");

        let read = serde_json::to_value(ResponseEnvelope::result(None, ReadResult::Metrics(serde_json::json!({})), as_of)).unwrap();
        assert_eq!((read["answer"].as_str(), read["result"]["type"].as_str()), (Some("RESULT"), Some("metrics")));
        let back: ResponseEnvelope = serde_json::from_value(read).unwrap();
        assert!(back.read_result().is_some());
    }

    #[test]
    fn the_side_effect_marker_is_part_of_every_reported_failure() {
        let f = FailureInfo::new(FailureClass::DependencyUnavailable, "backend down", SideEffect::Possible);
        let v = serde_json::to_value(&f).unwrap();
        assert_eq!(v["side_effect"], "POSSIBLE");
    }
}
