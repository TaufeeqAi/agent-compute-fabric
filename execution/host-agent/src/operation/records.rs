//! Durable record shapes. Deliberately *small*: they hold identity, intent and committed
//! lifecycle state — not logs, not output bytes, not another database (spec §10.2, DELTA-016).
//! Specialised state (snapshot manifests, artifacts) lives in subsystem manifests on disk and
//! is only *located* from here.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    backend::BackendHandle,
    clock::MonotonicRef,
    domain::{
        CallerIdentity, FailureInfo, ImageRef, LifecycleState, OperationPhase, OperationStatus, OperationType, PolicyId,
        RequestFingerprint, Reservation, SandboxResources, SnapshotRef, SnapshotState,
    },
    ids::{Generation, OperationId, RecoveryId, RunId, SandboxId, SnapshotId},
};

/// Stronger-than-PID process identity (spec §13.5, DELTA-013).
///
/// `(pid, start_time_ticks, boot_id)` is stable for the life of one process and cannot be
/// reproduced by a different process that merely reuses the pid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProcessIdentity {
    pub pid: i32,
    /// Field 22 of /proc/<pid>/stat (clock ticks since boot).
    pub start_time_ticks: u64,
    pub boot_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OperationRecord {
    pub operation_id: OperationId,
    pub operation_type: OperationType,
    pub fingerprint: RequestFingerprint,
    pub request_schema_version: String,
    /// `sbx-…`, `snp-…` or `host`. Informational routing key, never a path.
    pub resource_id: String,
    pub expected_generation: Option<Generation>,
    pub created_wall: String,
    pub created_mono: MonotonicRef,
    /// Monotonic absolute deadline (spec §13.4).
    pub deadline: MonotonicRef,
    pub caller: CallerIdentity,
    pub policy_id: PolicyId,
    pub phase: OperationPhase,
    pub status: OperationStatus,
    pub failure: Option<FailureInfo>,
    /// Terminal result payload (bounded JSON). Large bytes live in artifacts.
    pub result: Option<serde_json::Value>,
    pub run_id: Option<RunId>,
    pub sandbox: Option<(SandboxId, Generation)>,
    pub snapshot: Option<SnapshotRef>,
    pub recovery_id: Option<RecoveryId>,
    pub updated_wall: String,
}

impl OperationRecord {
    pub fn is_terminal(&self) -> bool {
        matches!(self.phase, OperationPhase::Terminal)
    }
}

/// Identity of a sandbox across generations. Survives `DESTROYED` as a tombstone so that a
/// generation number is **never reused** (spec §11.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SandboxRecord {
    pub sandbox_id: SandboxId,
    pub name: Option<String>,
    pub created_wall: String,
    /// High-water mark of generations ever *allocated*. Only ever increases, so a generation
    /// number is never reused (spec §11.4), even if its incarnation failed or was destroyed.
    pub last_generation: Generation,
    /// The incarnation callers address and stale-reference checks compare against. Differs from
    /// `last_generation` only while a restore is in flight: if the restore fails, `current` still
    /// names the old, intact generation.
    pub current: Generation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GenerationRecord {
    pub sandbox_id: SandboxId,
    pub generation: Generation,
    pub state: LifecycleState,
    /// Only meaningful while `state == PAUSED`: where to return on resume.
    pub paused_from: Option<LifecycleState>,
    pub resources: SandboxResources,
    pub image: ImageRef,
    pub reservation: Reservation,
    /// Random token written to the generation directory's OWNER marker. Cleanup requires the
    /// on-disk marker to match this journal value (spec §19.3).
    pub owner_nonce: String,
    /// Everything the backend needs to find and control this generation (incl. the VMM's
    /// process identity once launched). `None` until provisioning completes.
    pub handle: Option<BackendHandle>,
    /// Identity of the VMM, journaled by the launch sink the instant it exists — before the
    /// backend handle may exist (restore) and before any configuration (spec §13.5).
    pub process: Option<ProcessIdentity>,
    pub created_by: OperationId,
    pub source_snapshot: Option<SnapshotRef>,
    pub last_run: Option<RunId>,
    pub policy_id: PolicyId,
    /// Identity of the security profile this generation was launched under (spec §17.4).
    pub security_profile_id: String,
    pub failure: Option<FailureInfo>,
    pub quarantined: Option<String>,
    pub updated_wall: String,
}

impl GenerationRecord {
    pub fn sandbox_ref(&self) -> crate::ids::SandboxRef {
        crate::ids::SandboxRef { sandbox_id: self.sandbox_id.clone(), generation: self.generation }
    }
    pub fn process(&self) -> Option<&ProcessIdentity> {
        self.process.as_ref()
    }

    /// The handle to pass to the backend: the stored one (or a minimal one for a generation that
    /// never finished provisioning), always carrying the journaled VMM identity.
    pub fn backend_handle(&self) -> BackendHandle {
        let mut h = self.handle.clone().unwrap_or_else(|| BackendHandle {
            sandbox: self.sandbox_ref(),
            uid: 0,
            gid: 0,
            resources: self.resources.clone(),
            boot_args: String::new(),
            process: None,
        });
        h.process = self.process.clone();
        h
    }
    /// A generation still owns host capacity until it is `DESTROYED`.
    pub fn holds_reservation(&self) -> bool {
        self.state != LifecycleState::Destroyed
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotRecord {
    pub snapshot_id: SnapshotId,
    pub generation: Generation,
    pub name: Option<String>,
    pub state: SnapshotState,
    /// sha256 of the canonical manifest bytes — the **journal-held** root of trust. A
    /// manifest on disk is only believed if it hashes to this value (exact-object binding).
    pub manifest_digest: Option<String>,
    /// Bytes set aside at admission (spec §18.9).
    pub reserved_bytes: u64,
    /// Bytes actually stored once `Ready`.
    pub actual_bytes: u64,
    pub source: Option<(SandboxId, Generation)>,
    pub source_run: Option<RunId>,
    pub created_by: OperationId,
    pub created_wall: String,
    pub restore_count: u32,
    pub failure: Option<FailureInfo>,
}

impl SnapshotRecord {
    pub fn snapshot_ref(&self) -> SnapshotRef {
        SnapshotRef { snapshot_id: self.snapshot_id.clone(), snapshot_generation: self.generation }
    }
    pub fn holds_storage(&self) -> bool {
        !matches!(self.state, SnapshotState::Deleted)
    }
}

/// Spec §14.5 / §22.8: what recovery saw, did, and concluded — bounded and restart-safe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RecoveryRecord {
    pub recovery_id: RecoveryId,
    pub operation_id: OperationId,
    pub resource_id: String,
    pub generation: Option<Generation>,
    pub initial_classification: String,
    pub observations: Vec<String>,
    pub actions: Vec<String>,
    /// Incremented every time recovery touches this record — across restarts. This is what
    /// makes "repeated restart must not loop destructively" (§22.7) enforceable.
    pub attempt_count: u32,
    pub final_classification: Option<String>,
    pub quarantine_reason: Option<String>,
    pub updated_wall: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QuarantineRecord {
    pub resource_id: String,
    pub generation: Option<Generation>,
    pub reason: String,
    pub at_wall: String,
}

/// The accepted runtime security profile (spec §17.4), recorded once per host-agent start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RuntimeManifestRecord {
    pub instance_id: String,
    pub profile_id: String,
    pub recorded_wall: String,
    pub manifest: serde_json::Value,
}

/// One unit of atomic durable change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Entry {
    Operation(Box<OperationRecord>),
    Sandbox(SandboxRecord),
    Generation(Box<GenerationRecord>),
    Snapshot(Box<SnapshotRecord>),
    Recovery(RecoveryRecord),
    Quarantine(QuarantineRecord),
    RuntimeManifest(RuntimeManifestRecord),
}
