//! Run results and evidence (spec §18.8, §18.10, §23).
//!
//! Evidence has three classes with different failure effects (§23.2):
//! `REQUIRED_EXECUTION_EVIDENCE` (surfaced as incomplete), `SECURITY_EVIDENCE` (fail closed) and
//! `DIAGNOSTIC_TELEMETRY` (may degrade without touching lifecycle truth).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::refs::ArtifactRef;
use crate::{
    domain::operation::PolicyId,
    error::FailureClass,
    ids::{Generation, OperationId, RunId, SandboxId},
};

/// Whether the evidence attached to a terminal result is whole (spec §23.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceStatus {
    Complete,
    Incomplete,
    Truncated,
    Unknown,
}

/// State of one captured stream (spec §18.8).
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

/// Terminal classification of one run (spec §8.7). `Running` is observation-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RunOutcome {
    Running,
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,
    Unknown,
}

/// Per-resource enforcement record (spec §18.10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResourceEvidence {
    pub resource: String,
    pub configured: Option<u64>,
    pub effective: Option<u64>,
    pub observed_peak: Option<u64>,
    pub violation: Option<FailureClass>,
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
    pub run_id: RunId,
    pub operation_id: OperationId,
    pub sandbox_id: SandboxId,
    pub generation: Generation,
    pub outcome: RunOutcome,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout: OutputCapture,
    pub stderr: OutputCapture,
    pub metrics: RunMetrics,
    pub evidence_status: EvidenceStatus,
    pub resource_evidence: Vec<ResourceEvidence>,
    pub artifacts: Vec<ArtifactRef>,
    pub policy_id: PolicyId,
    pub image_id: String,
    /// Honest note when the outcome is `UNKNOWN`/`FAILED` for infrastructure reasons.
    pub note: Option<String>,
}

impl RunResult {
    /// The operation-level view of a run: did the system learn a definite result?
    pub fn is_known(&self) -> bool {
        !matches!(self.outcome, RunOutcome::Unknown | RunOutcome::Running)
    }
}
