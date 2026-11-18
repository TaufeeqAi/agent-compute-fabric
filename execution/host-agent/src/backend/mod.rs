//! The backend port (contract §26, boundaries B08 and B09).
//!
//! This is the **semantic** boundary between the coordinator and a VMM. Everything above it is
//! written against these types and never mentions Firecracker (BK-4); everything VMM-specific
//! (jailer argv, API bodies, vsock tunnelling, namespaces, the packet filter) lives strictly below
//! it, in `backend::firecracker`. The VMM, the isolation controls, the network plumbing and the
//! storage placement are **one replacement unit** (§26.4): they are replaced together or not at all.
//!
//! Conventions:
//! * Methods return [`AcfError`](crate::error::AcfError); its side-effect marker says whether the
//!   failing step may already have changed host state (BK-1, FS-2). A backend sets `POSSIBLE`
//!   whenever it cannot rule that out, and it never retries (RY-1).
//! * `stop` and `teardown` are idempotent: on an already-gone sandbox they succeed.
//! * A backend never decides lifecycle state. It reports; the coordinator commits (BK-2).
//! * A backend supports observation after an ambiguous mutation (BK-3): `observe`, `discover`,
//!   `residue` and `busy_slots` change nothing.

pub mod firecracker;
pub mod netns;
pub mod process;

use std::{collections::BTreeSet, path::PathBuf, time::Duration};

use acf_wire::guest::{ExecResult, ProbeReport};
use async_trait::async_trait;
use cap_std::fs::Dir;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::{
    backend::process::{IdentityCheck, SecurityPosture},
    domain::{NetworkMode, ResolvedCommand, SandboxResources},
    error::Result,
    ids::SandboxRef,
    network::NetworkEvidence,
    storage::ResolvedImage,
    store::ProcessIdentity,
};

/// What this backend *is*, recorded in the runtime manifest and in every snapshot manifest
/// (contract §26.2, IS-2): a snapshot is only restorable by a backend with an equivalent identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BackendIdentity {
    pub name: String,
    /// Exact VMM version, e.g. `v1.17.0`.
    pub version: String,
    /// Stable digest of the isolation profile (seccomp, cgroups, namespaces, uid policy, …).
    pub security_profile_id: String,
    /// Human-auditable detail behind `security_profile_id`.
    pub profile: serde_json::Value,
}

/// What the backend declares it can do (contract §26.3). A request that needs an undeclared
/// capability is refused with `UNSUPPORTED` before BEGIN; it is never silently skipped (BK-5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CapabilityProfile {
    pub backend: String,
    /// Used only inside a snapshot; never caller-visible.
    pub pause_resume: bool,
    pub snapshot: bool,
    pub restore: bool,
    pub guest_exec: bool,
    pub network_modes: Vec<NetworkMode>,
    pub max_vcpus: u8,
    /// Delivery of secret material to a guest at execution time (§22).
    pub secret_injection: bool,
    /// Reading captured output while an execution is in flight (OU-5).
    pub incremental_output: bool,
    /// Whether a restore reseeds guest entropy (RE-7). Evidence only.
    pub restore_reseeds_entropy: bool,
    /// Whether a running generation still depends on files of the snapshot it was restored from
    /// (RF-1). If it does, the snapshot stays referenced while the generation lives.
    pub runtime_depends_on_snapshot: bool,
    /// Whether a running generation still depends on the image store after provisioning (IM-4).
    pub runtime_depends_on_image: bool,
    /// Memory the runtime itself needs beyond guest memory; counted in admission (RS-1).
    pub per_runtime_overhead_mib: u32,
    /// Size of the identifier pool: how many generations can hold distinct identifiers at once (RS-3).
    pub identifier_slots: u32,
    /// How long the backend lets a runtime end by itself before it ends it by force.
    pub stop_grace_ms: u64,
}

/// Kernel-sourced usage of one runtime, with the per-resource evidence the backend derives from it
/// (RS-2): what was configured, what was effective, what was observed, and whether a limit was hit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeUsage {
    pub cpu_usage_usec: Option<u64>,
    pub memory_peak_bytes: Option<u64>,
    pub evidence: Vec<crate::domain::ResourceEvidence>,
}

/// Host resources a generation owns. Small and serialisable: all paths are re-derived from ids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BackendHandle {
    pub sandbox: SandboxRef,
    pub uid: u32,
    pub gid: u32,
    pub resources: SandboxResources,
    /// Kernel command line for a cold boot (empty for a restored generation).
    pub boot_args: String,
    pub process: Option<ProcessIdentity>,
}

/// What the backend tells the coordinator the instant a runtime process exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launched {
    pub process: ProcessIdentity,
    /// A file that ends the runtime when `1` is written to it (the control group's kill switch),
    /// if the backend has one. Opaque above the port: the lifetime enforcer writes to it at expiry.
    pub kill_switch: Option<PathBuf>,
}

/// Called the instant a runtime process exists and its identity is captured — *before* it is
/// configured. The coordinator records the identity durably and arms lifetime enforcement, so a
/// crash right after launch leaves a record that proves ownership (RC-1) and a runtime that still
/// ends at its expiry (PD-4). If the sink fails, the backend must end the runtime it just started
/// and return the error.
#[async_trait]
pub trait LaunchSink: Send + Sync {
    async fn launched(&self, launched: &Launched) -> Result<()>;
}

#[derive(Debug)]
pub struct ProvisionRequest<'a> {
    pub sandbox: SandboxRef,
    pub resources: &'a SandboxResources,
    pub image: &'a ResolvedImage,
    /// Index into the per-VM uid range; the backend maps it to a numeric uid/gid.
    pub uid_slot: u32,
}

/// Evidence gathered while booting (contract IS-1, IS-2, NW-2, GP-4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StartOutcome {
    pub process: ProcessIdentity,
    pub posture: SecurityPosture,
    pub network: NetworkEvidence,
    pub agent_version: String,
    pub guest_boot_id: String,
    pub boot_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum VmmState {
    NotStarted,
    Running,
    Paused,
    /// No VMM process exists.
    Absent,
    Unknown(String),
}

/// Whether the mandatory isolation controls of a present runtime are still in force (IS-3). The
/// backend knows what its isolation profile demands; the coordinator only needs the verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", content = "detail", rename_all = "snake_case")]
pub enum EnforcementObservation {
    Intact,
    /// At least one control is no longer in force. Never repaired in place (§16.2 Part B).
    Degraded(Vec<String>),
    /// It could not be established.
    Unknown(String),
    /// There is no runtime.
    NotApplicable,
}

/// A point-in-time, *non-mutating* look at a sandbox (contract §16.1), assembled from host-side
/// facts only (OB-1). Recovery decisions are made from this, never from the store alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Observation {
    pub vmm: VmmState,
    pub identity: Option<IdentityCheckView>,
    pub posture: Option<SecurityPosture>,
    pub enforcement: EnforcementObservation,
    pub jail_present: bool,
}

/// Serialisable mirror of [`IdentityCheck`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdentityCheckView {
    Match,
    Gone,
    Mismatch(String),
}

impl From<IdentityCheck> for IdentityCheckView {
    fn from(c: IdentityCheck) -> Self {
        match c {
            IdentityCheck::Match => Self::Match,
            IdentityCheck::Gone => Self::Gone,
            IdentityCheck::Mismatch(m) => Self::Mismatch(m),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FileDigest {
    pub name: String,
    pub bytes: u64,
    /// Lowercase hex sha256 of the bytes that were copied.
    pub sha256: String,
}

/// The three artifacts that together *are* a snapshot (contract SNP-2): CPU/device state, guest
/// memory, and the disk the guest was running on. Missing any one makes the others useless.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotArtifacts {
    pub vmstate: FileDigest,
    pub mem: FileDigest,
    pub disk: FileDigest,
    /// VMM version that wrote the snapshot (restore requires an identical one).
    pub vmm_version: String,
}

#[derive(Debug)]
pub struct SnapshotRequest<'a> {
    /// Directory capability the backend must place `vmstate`, `mem` and `disk` into, as
    /// **verified copies** (digest computed over the bytes copied).
    pub dest: &'a Dir,
    /// Upper bound per file; protects the host disk from a runaway artifact.
    pub max_file_bytes: u64,
}

#[derive(Debug)]
pub struct RestoreRequest<'a> {
    /// The *new* generation being created.
    pub sandbox: SandboxRef,
    pub resources: &'a SandboxResources,
    pub uid_slot: u32,
    /// Directory holding the snapshot artifacts.
    pub source: &'a Dir,
    /// Digests recorded in the verified manifest. The backend must refuse to load anything whose
    /// copied bytes do not hash to these (a corrupt `vmstate` would otherwise crash Firecracker).
    pub expected: &'a SnapshotArtifacts,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopOutcome {
    Stopped,
    AlreadyGone,
    /// A different process holds the recorded pid; nothing was signalled.
    Refused(String),
    StillAlive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TeardownOutcome {
    Removed,
    Absent,
    /// Ownership could not be proven; resources were left in place.
    Quarantine(String),
}

#[derive(Debug)]
pub struct GuestExecRequest {
    pub exec_id: String,
    pub command: ResolvedCommand,
    /// `backstop_margin`: time the host waits past the command's own deadline before it ends the
    /// runtime (EX-5).
    pub grace: Duration,
    /// Secret material resolved for this execution, by variable name (SC-2). Held in memory only for
    /// the delivery. A backend that does not declare `secret_injection` refuses a non-empty list.
    pub secrets: Vec<(String, crate::secrets::SecretMaterial)>,
}

#[derive(Debug)]
pub struct GuestExecOutcome {
    pub result: ExecResult,
    /// The host's deadline backstop fired (the guest did not honour its own deadline).
    pub host_deadline_hit: bool,
    /// The VMM was killed to enforce the deadline; the sandbox must not be reused.
    pub vm_killed: bool,
}

#[async_trait]
pub trait SandboxBackend: Send + Sync + std::fmt::Debug {
    fn identity(&self) -> &BackendIdentity;
    fn capabilities(&self) -> &CapabilityProfile;

    /// Create host resources for a generation (jail/dirs, verified image copies). No VM yet.
    async fn provision(&self, req: &ProvisionRequest<'_>) -> Result<BackendHandle>;

    /// Launch, configure, boot, and wait for the guest agent; verify confinement and network.
    async fn start(&self, handle: &BackendHandle, sink: &dyn LaunchSink) -> Result<StartOutcome>;

    async fn observe(&self, handle: &BackendHandle) -> Result<Observation>;
    async fn pause(&self, handle: &BackendHandle) -> Result<()>;
    async fn resume(&self, handle: &BackendHandle) -> Result<()>;

    /// Pause → snapshot → verified copy into `req.dest` → resume. Leaves the VM running.
    async fn snapshot(&self, handle: &BackendHandle, req: &SnapshotRequest<'_>) -> Result<SnapshotArtifacts>;

    /// Create a new generation from verified artifacts and bring it to a running, paused-free
    /// state. The caller then runs [`SandboxBackend::probe`] to verify it.
    async fn restore(&self, req: &RestoreRequest<'_>, sink: &dyn LaunchSink) -> Result<(BackendHandle, StartOutcome)>;

    /// Find a VMM that may exist for `sandbox` even though the journal has no process identity
    /// for it (crash between launch and commit). Ownership is proven by the jail id appearing in
    /// the process's argv — never by the pid file alone.
    async fn discover(&self, sandbox: &SandboxRef) -> Result<Option<ProcessIdentity>>;

    /// Terminate the VMM (identity-verified). Keeps files for forensics. Idempotent.
    async fn stop(&self, handle: &BackendHandle, grace: Duration) -> Result<StopOutcome>;

    /// Release everything the generation owns (cgroup, netns, directories), with ownership proof.
    /// Idempotent.
    async fn teardown(&self, sandbox: &SandboxRef, owner_nonce: &str) -> Result<TeardownOutcome>;

    async fn exec(&self, handle: &BackendHandle, req: &GuestExecRequest, cancel: CancellationToken) -> Result<GuestExecOutcome>;

    /// Deterministic state probe: the oracle of a restore (contract RE-4).
    async fn probe(&self, handle: &BackendHandle) -> Result<ProbeReport>;

    /// Kernel-sourced resource usage and evidence, if available.
    async fn stats(&self, handle: &BackendHandle) -> Result<Option<RuntimeUsage>>;

    /// Identifier slots that a **live resource** currently carries, whatever the store says (RS-3).
    /// A slot is assigned only if records show it free *and* it is not in this set.
    async fn busy_slots(&self) -> Result<BTreeSet<u32>>;

    /// What recorded resources of this generation still exist on the host: process, control group,
    /// namespace, interface, directory. Empty means proven absent. Changes nothing (QR-2, QR-3).
    async fn residue(&self, handle: &BackendHandle) -> Result<Vec<String>>;

    /// Remove the generation's recorded resources by their host-derived names **without** the
    /// ownership marker (`quarantine.release` in mode `FORCE_DESTROY`, QR-2): the operator's
    /// assertion replaces the proof. A process is signalled only if it is the recorded instance.
    async fn force_teardown(&self, handle: &BackendHandle) -> Result<()>;
}
