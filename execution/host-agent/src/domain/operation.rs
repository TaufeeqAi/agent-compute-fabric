//! Operation vocabulary (spec §8.1–8.2, §12). `UNKNOWN` is a first-class status and is never
//! collapsed into `FAILED` or `SUCCEEDED` for convenience.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{AcfError, FailureClass, SideEffect};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationType {
    SandboxCreate,
    SandboxStart,
    SandboxStop,
    SandboxDestroy,
    Exec,
    SnapshotCreate,
    SnapshotRestore,
    SnapshotDelete,
    PolicyReload,
}

/// Spec §8.2. `Conflict` and `Rejected` never create durable mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationStatus {
    Accepted,
    InProgress,
    Succeeded,
    Failed,
    Cancelled,
    Unknown,
    Conflict,
    Rejected,
}

impl OperationStatus {
    /// Statuses after which the operation will not change again by itself.
    pub const fn is_final(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled | Self::Conflict | Self::Rejected)
    }
}

/// How far a durable operation has progressed. `step` names the *next* privileged step that
/// has been declared (write-ahead intent) — on a crash it tells recovery what may have run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum OperationPhase {
    Accepted,
    InProgress { step: String },
    Terminal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FailureInfo {
    pub class: FailureClass,
    pub message: String,
    pub side_effect: SideEffect,
}

impl From<&AcfError> for FailureInfo {
    fn from(e: &AcfError) -> Self {
        Self { class: e.class, message: e.message.clone(), side_effect: e.side_effect }
    }
}

/// Canonical request fingerprint (spec §12.2). See `operation::fingerprint` for the rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RequestFingerprint {
    pub schema_version: u32,
    pub algorithm: String,
    pub digest: String,
}

/// Who asked, as established by the OS (spec §16.2) — never self-asserted by the caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CallerIdentity {
    pub uid: u32,
    pub gid: u32,
    pub pid: Option<i32>,
}

/// Identity of the policy in force when an operation was admitted (spec §16.7).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct PolicyId {
    pub name: String,
    pub version: String,
    /// sha256 of the exact bytes that were verified and parsed.
    pub digest: String,
}

impl std::fmt::Display for PolicyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}#{}", self.name, self.version, &self.digest[..self.digest.len().min(12)])
    }
}
