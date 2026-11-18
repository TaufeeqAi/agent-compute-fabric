//! Durable record shapes (contract PS-13). Deliberately *small*: they hold identity, intent and
//! committed lifecycle state — not logs, not output bytes, not another database. Specialised state
//! (snapshot manifests, captured output) lives in subsystem files and is only *located* from here.
//!
//! Every caller-visible record carries the tags of the request that created it (AU-8) and a
//! `revision`: the commit sequence of its last change, stamped by the store (§8, ID-3).

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    backend::BackendHandle,
    clock::MonotonicRef,
    domain::{
        CancelledBy, Cleanup, Expiry, FailureInfo, ImageRef, Issuer, LifecycleState, OperationState, OperationType, OwnerScope, PeerId,
        ProfileId, RequestFingerprint, Reservation, Residue, SandboxResources, SnapshotRef, SnapshotState, Tags,
    },
    ids::{Generation, OperationId, RecoveryId, RunId, SandboxId, SnapshotId},
};

/// Schema of the store. A store written by a higher version is neither written nor interpreted (PS-11).
pub const STORE_SCHEMA_VERSION: u32 = 2;

/// Stronger-than-PID process identity (RC-1).
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

/// Operation ids are caller-generated and namespaced by `(peer_id, owner_scope)` (OP-10): two peers,
/// or one peer in two scopes, can use the same id without meeting each other.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
pub struct OpKey {
    pub peer_id: PeerId,
    pub owner_scope: OwnerScope,
    pub operation_id: OperationId,
}

impl OpKey {
    pub fn new(tags: &Tags, operation_id: &OperationId) -> Self {
        Self { peer_id: tags.peer_id.clone(), owner_scope: tags.owner_scope.clone(), operation_id: operation_id.clone() }
    }
}

impl std::fmt::Display for OpKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}/{}", self.peer_id, self.owner_scope, self.operation_id)
    }
}

/// First record of a store: what it is, so every sequence, revision and cursor can be qualified (ID-4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StoreMeta {
    pub schema_version: u32,
    /// Random, allocated when the store is created. Never changes.
    pub lineage: String,
    pub created_wall: String,
}

/// One start of the core on this store (PS-5). Also records the security posture the activation
/// accepted and the safety profile in force when it started (PS-13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ActivationRecord {
    /// Greater than every earlier epoch in this lineage.
    pub epoch: u64,
    pub instance_id: String,
    pub started_wall: String,
    pub started_ms: i64,
    pub started_mono: MonotonicRef,
    /// Free-form, bounded: backend identity, host fingerprint, version, configuration digest.
    pub manifest: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OperationRecord {
    pub operation_id: OperationId,
    pub tags: Tags,
    /// Recorded, never compared (AU-7).
    pub on_behalf_of: Option<String>,
    pub issuer: Issuer,
    pub operation_type: OperationType,
    pub fingerprint: RequestFingerprint,
    /// Protocol identifier the request was made under.
    pub protocol: String,
    /// `sbx-…`, `snp-…` or `host`. A routing label, never a path.
    pub target: String,
    pub expected_generation: Option<Generation>,
    /// When the caller says it first issued the request (RFC 3339). A statement, not a fact.
    pub issued_at: String,
    pub created_wall: String,
    pub created_ms: i64,
    pub created_mono: MonotonicRef,
    /// Absolute monotonic deadline (OP-14). One recorded in an earlier boot is treated as expired.
    pub deadline: MonotonicRef,
    /// The safety profile the operation was admitted under, and is governed by until it ends (SP-2).
    pub profile_id: ProfileId,
    /// Activation that ran BEGIN. An operation whose epoch is lower than the current one is
    /// *inherited* and is never continued (§11.6).
    pub epoch: u64,
    pub state: OperationState,
    /// The last privileged step declared before it ran (OP-3).
    pub step: Option<String>,
    pub cancelled_by: Option<CancelledBy>,
    pub failure: Option<FailureInfo>,
    /// As decided at FINISH. Reads upgrade `PENDING` to `COMPLETE` when `residue` is proven gone.
    pub cleanup: Option<Cleanup>,
    /// What a failed or cancelled operation may have left behind.
    pub residue: Option<Residue>,
    /// An execution whose command was handed to the guest (decides `effect`, §11.3).
    pub execution_started: bool,
    /// Terminal result payload (bounded JSON). Large bytes live in the output store.
    pub result: Option<serde_json::Value>,
    pub run_id: Option<RunId>,
    pub sandbox: Option<(SandboxId, Generation)>,
    pub snapshot: Option<SnapshotRef>,
    pub recovery_id: Option<RecoveryId>,
    pub finished_ms: Option<i64>,
    pub updated_wall: String,
    /// Commit sequence of this record's last change. Stamped by the store.
    #[serde(default)]
    pub revision: u64,
}

impl OperationRecord {
    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    pub fn key(&self) -> OpKey {
        OpKey::new(&self.tags, &self.operation_id)
    }

    /// Inherited from an earlier activation (§11.6).
    pub fn is_inherited(&self, current_epoch: u64) -> bool {
        self.epoch < current_epoch
    }
}

/// Identity of a sandbox across generations. Survives `DESTROYED` as a tombstone for
/// `change_retention`, so followers can learn of the destruction (API-11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SandboxRecord {
    pub sandbox_id: SandboxId,
    pub tags: Tags,
    /// An alias. Never a mechanism name and never the target of a mutation (ID-5).
    pub name: Option<String>,
    pub created_wall: String,
    pub created_ms: i64,
    /// High-water mark of generations ever *allocated*. Only ever increases, so a generation number
    /// is never reused (ID-1), even if its incarnation failed or was destroyed.
    pub last_generation: Generation,
    /// The incarnation callers address and stale-token checks compare against. Differs from
    /// `last_generation` only while a restore in place is in flight: if the restore fails,
    /// `current` still names the old, intact generation (RE-5).
    pub current: Generation,
    /// Every sandbox has an expiry (LT-1). Restore in place keeps it.
    pub expiry: Expiry,
    /// Set in the transaction that commits the current generation `DESTROYED`.
    pub destroyed_ms: Option<i64>,
    #[serde(default)]
    pub revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GenerationRecord {
    pub sandbox_id: SandboxId,
    pub generation: Generation,
    pub tags: Tags,
    pub state: LifecycleState,
    /// Only meaningful while `state == PAUSED`: where to return on resume.
    pub paused_from: Option<LifecycleState>,
    /// Includes the network intent, which is immutable for the generation (NW-3).
    pub resources: SandboxResources,
    pub image: ImageRef,
    /// The lease (§12.4). Held until the generation is `DESTROYED` (LS-1).
    pub reservation: Reservation,
    /// Host-generated nonce, recorded here before any resource is created and written into each
    /// resource's ownership marker (RC-1).
    pub owner_nonce: String,
    /// Everything the backend needs to find and control this generation. `None` until provisioned.
    pub handle: Option<BackendHandle>,
    /// Identity of the runtime, recorded the instant it exists and before it is configured (RC-1).
    pub process: Option<ProcessIdentity>,
    pub created_by: OperationId,
    /// Commit sequence at which the generation was created. Written into its ownership marker so a
    /// store older than the system it describes can be detected (LN-1). Stamped by the store.
    #[serde(default)]
    pub created_seq: u64,
    pub source_snapshot: Option<SnapshotRef>,
    pub last_run: Option<RunId>,
    pub profile_id: ProfileId,
    /// Digest of the isolation profile this generation was launched under (IS-2).
    pub security_profile_id: String,
    /// Guest agent version the image (or the snapshot) manifest records. The host refuses to
    /// complete a start or a restore when the guest reports a different one (GP-4).
    pub expected_agent_version: Option<String>,
    /// Guest agent version the guest reported at readiness. Guest-reported.
    pub guest_agent_version: Option<String>,
    /// References of the secrets delivered to this generation (SC-5). Never material.
    #[serde(default)]
    pub secret_refs: BTreeSet<String>,
    pub failure: Option<FailureInfo>,
    /// The condition `QUARANTINED` (§12.1): a reason, not a state.
    pub quarantined: Option<String>,
    pub quarantined_ms: Option<i64>,
    /// Observations of this generation that could not be completed (RC-4), counted durably.
    #[serde(default)]
    pub observe_attempts: u32,
    pub updated_wall: String,
    #[serde(default)]
    pub revision: u64,
}

impl GenerationRecord {
    pub fn sandbox_ref(&self) -> crate::ids::SandboxRef {
        crate::ids::SandboxRef { sandbox_id: self.sandbox_id.clone(), generation: self.generation }
    }
    pub fn process(&self) -> Option<&ProcessIdentity> {
        self.process.as_ref()
    }

    /// The handle to pass to the backend: the stored one (or a minimal one for a generation that
    /// never finished provisioning), always carrying the recorded runtime identity.
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

    /// A generation holds its lease and identifiers until it is `DESTROYED` (J-5).
    pub fn holds_reservation(&self) -> bool {
        self.state != LifecycleState::Destroyed
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotRecord {
    pub snapshot_id: SnapshotId,
    pub generation: Generation,
    /// Tags of the request that created it (SNP-6).
    pub tags: Tags,
    pub name: Option<String>,
    pub state: SnapshotState,
    /// sha256 of the canonical manifest bytes — the **store-held** root of trust (SNP-3). A manifest
    /// on disk is believed only if it hashes to this value.
    pub manifest_digest: Option<String>,
    /// Bytes set aside at admission (LS-2).
    pub reserved_bytes: u64,
    /// Bytes actually stored once `READY`.
    pub actual_bytes: u64,
    pub source: Option<(SandboxId, Generation)>,
    pub source_run: Option<RunId>,
    pub created_by: OperationId,
    pub created_wall: String,
    pub restore_count: u32,
    /// References of the secrets live in the sandbox at capture (SC-5).
    #[serde(default)]
    pub secret_refs: BTreeSet<String>,
    pub failure: Option<FailureInfo>,
    pub deleted_ms: Option<i64>,
    #[serde(default)]
    pub revision: u64,
}

impl SnapshotRecord {
    pub fn snapshot_ref(&self) -> SnapshotRef {
        SnapshotRef { snapshot_id: self.snapshot_id.clone(), snapshot_generation: self.generation }
    }
    pub fn holds_storage(&self) -> bool {
        !matches!(self.state, SnapshotState::Deleted)
    }
}

/// What recovery saw, did, and concluded — bounded and restart-safe (RC-4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RecoveryRecord {
    pub recovery_id: RecoveryId,
    pub operation: OpKey,
    pub target: String,
    pub generation: Option<Generation>,
    pub plan: String,
    pub observations: Vec<String>,
    pub actions: Vec<String>,
    /// Incremented durably *before* each attempt — across restarts — so a record whose recovery
    /// crashes the core is quarantined after the bound instead of looping (T-REC-07).
    pub attempt_count: u32,
    pub outcome: Option<String>,
    pub quarantine_reason: Option<String>,
    pub updated_wall: String,
}

/// A report: a generation was quarantined, or a resource that no record owns was found
/// (`UNMANAGED`, RC-3). The authoritative quarantine flag is on the generation record; this is the
/// bounded history an operator reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QuarantineRecord {
    pub resource_id: String,
    pub generation: Option<Generation>,
    pub reason: String,
    pub at_wall: String,
    /// True for a resource with no record: reported, never modified.
    #[serde(default)]
    pub unmanaged: bool,
}

/// The safety profile that came into force (SP-2): at each activation and at each reload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProfileRecord {
    pub profile_id: ProfileId,
    pub in_force_wall: String,
    /// Operation that reloaded it; `None` when loaded at startup.
    pub by_operation: Option<OpKey>,
}

/// Records removed by retention (PS-10). Durable, so a replay forgets the same records and the
/// change floor moves with it: a cursor older than the floor is refused with `CURSOR_EXPIRED`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ForgetRecord {
    pub operations: Vec<OpKey>,
    pub sandboxes: Vec<SandboxId>,
    pub snapshots: Vec<(SnapshotId, Generation)>,
    /// Highest revision among the tombstones removed. Cursors below it may have missed one.
    pub change_floor: u64,
}

/// One unit of atomic durable change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Entry {
    Meta(StoreMeta),
    Activation(ActivationRecord),
    Operation(Box<OperationRecord>),
    Sandbox(SandboxRecord),
    Generation(Box<GenerationRecord>),
    Snapshot(Box<SnapshotRecord>),
    Recovery(RecoveryRecord),
    Quarantine(QuarantineRecord),
    Profile(ProfileRecord),
    Forget(ForgetRecord),
}

impl Entry {
    /// Stamp the commit sequence on the record this entry carries (revision, and the creation
    /// sequence of a generation the first time it is written).
    pub(crate) fn stamp(&mut self, seq: u64) {
        match self {
            Entry::Operation(r) => r.revision = seq,
            Entry::Sandbox(r) => r.revision = seq,
            Entry::Generation(r) => {
                r.revision = seq;
                if r.created_seq == 0 {
                    r.created_seq = seq;
                }
            }
            Entry::Snapshot(r) => r.revision = seq,
            Entry::Meta(_) | Entry::Activation(_) | Entry::Recovery(_) | Entry::Quarantine(_) | Entry::Profile(_) | Entry::Forget(_) => {}
        }
    }
}
