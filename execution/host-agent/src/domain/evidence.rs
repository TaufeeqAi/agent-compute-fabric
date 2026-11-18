//! Run results and evidence (contract §18.2, §18.4, §18.7).
//!
//! Every field of a result is labelled in the schema with its **provenance** (GP-6): what the host
//! observed itself (`HOST_OBSERVED`) and what a guest merely told it (`GUEST_REPORTED`). Only
//! host-observed facts drive host decisions (GP-7); a guest's statements are reported, never trusted.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::refs::ArtifactRef;
use crate::{
    domain::operation::ProfileId,
    ids::{Generation, OperationId, RunId, SandboxId},
};

/// Schema label for a fact the host observed itself.
pub const HOST_OBSERVED: &str = "HOST_OBSERVED";
/// Schema label for a statement made by the guest agent. Never an input to a host decision.
pub const GUEST_REPORTED: &str = "GUEST_REPORTED";

/// Whether the evidence attached to a terminal result is whole (contract OU-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceStatus {
    Complete,
    Incomplete,
    Truncated,
    Unknown,
}

/// State of one captured stream (contract OU-1, OU-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OutputStatus {
    Complete,
    Truncated,
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OutputCapture {
    pub status: OutputStatus,
    /// Bytes the workload produced (>= `kept_bytes` when truncated).
    pub total_bytes: u64,
    pub kept_bytes: u64,
    /// Base64 of the kept bytes — binary-safe, and bounded by the run's output budget.
    pub data_b64: String,
    pub artifact: Option<ArtifactRef>,
}

/// Status of one execution (contract §18.2, "Run status"). A non-zero exit is a *result*, not an
/// operation failure: it is `EXITED` with its exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RunStatus {
    /// The command ended by itself with an exit code.
    Exited,
    /// The command was ended by a signal.
    Signaled,
    /// The guest ended it at the guest deadline, or the host backstop fired.
    TimedOut,
    /// The guest could not start it.
    SpawnFailed,
    /// Ended by `operation.cancel` or by a containment operation.
    Cancelled,
    /// No result could be obtained. Never reported as success or failure.
    Unknown,
}

/// Per-resource enforcement record (contract RS-2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResourceEvidence {
    pub resource: String,
    pub configured: Option<u64>,
    pub effective: Option<u64>,
    pub observed_peak: Option<u64>,
    /// The limit was reached and enforced.
    pub violated: bool,
    pub action_taken: String,
    /// The mechanism that actually enforced it — never claim a stronger one than was applied.
    pub mechanism: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RunMetrics {
    pub wall_ms: u64,
    /// Host-cgroup CPU time consumed by the VMM during the run (delta).
    pub cpu_usage_usec: Option<u64>,
    pub memory_peak_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RunResult {
    #[schemars(extend("x-provenance" = HOST_OBSERVED))]
    pub run_id: RunId,
    #[schemars(extend("x-provenance" = HOST_OBSERVED))]
    pub operation_id: OperationId,
    #[schemars(extend("x-provenance" = HOST_OBSERVED))]
    pub sandbox_id: SandboxId,
    #[schemars(extend("x-provenance" = HOST_OBSERVED))]
    pub generation: Generation,
    /// Guest-reported unless `host_backstop_fired` or `runtime_ended` is set.
    #[schemars(extend("x-provenance" = GUEST_REPORTED))]
    pub status: RunStatus,
    #[schemars(extend("x-provenance" = GUEST_REPORTED))]
    pub exit_code: Option<i32>,
    #[schemars(extend("x-provenance" = GUEST_REPORTED))]
    pub signal: Option<i32>,
    #[schemars(extend("x-provenance" = GUEST_REPORTED))]
    pub stdout: OutputCapture,
    #[schemars(extend("x-provenance" = GUEST_REPORTED))]
    pub stderr: OutputCapture,
    /// In-guest duration and the in-guest containment mechanism are the guest's statements.
    #[schemars(extend("x-provenance" = GUEST_REPORTED))]
    pub guest_duration_ms: u64,
    #[schemars(extend("x-provenance" = GUEST_REPORTED))]
    pub guest_containment: String,
    /// The host's own deadline passed without a result and the host ended the runtime (EX-5).
    #[schemars(extend("x-provenance" = HOST_OBSERVED))]
    pub host_backstop_fired: bool,
    /// The runtime was ended by the host as part of this execution.
    #[schemars(extend("x-provenance" = HOST_OBSERVED))]
    pub runtime_ended: bool,
    #[schemars(extend("x-provenance" = HOST_OBSERVED))]
    pub metrics: RunMetrics,
    #[schemars(extend("x-provenance" = HOST_OBSERVED))]
    pub evidence_status: EvidenceStatus,
    #[schemars(extend("x-provenance" = HOST_OBSERVED))]
    pub resource_evidence: Vec<ResourceEvidence>,
    #[schemars(extend("x-provenance" = HOST_OBSERVED))]
    pub artifacts: Vec<ArtifactRef>,
    #[schemars(extend("x-provenance" = HOST_OBSERVED))]
    pub profile_id: ProfileId,
    #[schemars(extend("x-provenance" = HOST_OBSERVED))]
    pub image_id: String,
    /// Honest note when the status is `UNKNOWN` or the runtime was ended for infrastructure reasons.
    #[schemars(extend("x-provenance" = HOST_OBSERVED))]
    pub note: Option<String>,
}

impl RunResult {
    /// Did the system learn a definite result?
    pub fn is_known(&self) -> bool {
        !matches!(self.status, RunStatus::Unknown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_result_field_is_labelled_with_its_provenance() {
        // GP-6: the schema says, per field, whether the host observed it or a guest reported it.
        let schema = serde_json::to_value(schemars::schema_for!(RunResult)).unwrap();
        let props = schema["properties"].as_object().unwrap();
        assert!(props.len() >= 20);
        for (name, p) in props {
            let label = p["x-provenance"].as_str().unwrap_or_else(|| panic!("field `{name}` has no provenance label"));
            assert!(label == HOST_OBSERVED || label == GUEST_REPORTED, "{name}: {label}");
        }
        for guest in ["status", "exit_code", "signal", "stdout", "stderr", "guest_duration_ms", "guest_containment"] {
            assert_eq!(props[guest]["x-provenance"], GUEST_REPORTED, "{guest}");
        }
        for host in ["host_backstop_fired", "runtime_ended", "metrics", "generation"] {
            assert_eq!(props[host]["x-provenance"], HOST_OBSERVED, "{host}");
        }
    }

    #[test]
    fn run_status_vocabulary_is_the_contract_table() {
        for (s, name) in [
            (RunStatus::Exited, "EXITED"),
            (RunStatus::Signaled, "SIGNALED"),
            (RunStatus::TimedOut, "TIMED_OUT"),
            (RunStatus::SpawnFailed, "SPAWN_FAILED"),
            (RunStatus::Cancelled, "CANCELLED"),
            (RunStatus::Unknown, "UNKNOWN"),
        ] {
            assert_eq!(serde_json::to_value(s).unwrap(), serde_json::json!(name));
        }
    }
}
