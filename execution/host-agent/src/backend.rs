//! BND-08 — The backend interface (spec §20, DELTA-007/-018).
//!
//! This is the **semantic** boundary between lifecycle logic and a VMM. Everything above it
//! (coordinator, snapshot manager, recovery) is written against these types and never mentions
//! Firecracker; everything Firecracker-specific (jailer argv, API bodies, vsock tunnelling) lives
//! strictly below it. A second backend is *not* a Phase 1 deliverable, but this interface plus
//! the in-memory test double (`testing::FakeBackend`) is what proves the contract is not
//! accidentally shaped like one VMM's API.
//!
//! Conventions:
//! * Methods return [`AcfError`]; its [`SideEffect`](crate::error::SideEffect) marker says
//!   whether the failing step may already have changed host state (spec §14.3). A backend must
//!   set `Possible` whenever it cannot rule that out.
//! * Operations are **idempotent where the spec requires it**: `stop` and `teardown` on an
//!   already-gone sandbox succeed.
//! * A backend never decides lifecycle state. It reports; the coordinator commits.

use std::time::Duration;

use acf_wire::guest::{ExecResult, ProbeReport};
use async_trait::async_trait;
use cap_std::fs::Dir;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::{
    domain::{NetworkMode, ResolvedCommand, SandboxResources},
    error::Result,
    filesystem::ResolvedImage,
    ids::SandboxRef,
    network::NetworkEvidence,
    operation::ProcessIdentity,
    process::{CgroupStats, IdentityCheck, SecurityPosture},
};

/// What this backend *is*, recorded in the runtime manifest and in every snapshot manifest
/// (spec §17.4): a snapshot is only restorable by a backend with an equivalent identity.
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

/// Which semantic operations the backend supports. Unsupported ones must fail with a stable
/// `UNSUPPORTED` result rather than being silently skipped (spec DELTA-018).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CapabilityProfile {
    pub backend: String,
    pub pause_resume: bool,
    pub snapshot: bool,
    pub restore: bool,
    pub guest_exec: bool,
    pub network_modes: Vec<NetworkMode>,
    pub max_vcpus: u8,
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

/// Called the instant a VMM process exists and its identity is captured — *before* it is
/// configured. The coordinator uses it to journal the identity immediately, so a crash right
/// after launch leaves a record that proves ownership (spec §13.5, §22.5). If the sink fails, the
/// backend must kill the VMM it just started and return the error.
#[async_trait]
pub trait LaunchSink: Send + Sync {
    async fn launched(&self, process: &ProcessIdentity) -> Result<()>;
}

#[derive(Debug)]
pub struct ProvisionRequest<'a> {
    pub sandbox: SandboxRef,
    pub resources: &'a SandboxResources,
    pub image: &'a ResolvedImage,
    /// Index into the per-VM uid range; the backend maps it to a numeric uid/gid.
    pub uid_slot: u32,
}

/// Evidence gathered while booting (spec §20.5 / §18.6 / §17.4).
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

/// A point-in-time, *non-mutating* look at a sandbox (spec §22.5). Recovery decisions are made
/// from this, never from the journal alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Observation {
    pub vmm: VmmState,
    pub identity: Option<IdentityCheckView>,
    pub posture: Option<SecurityPosture>,
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

/// The three artifacts that together *are* a snapshot (spec §20.3): CPU/device state, guest
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
    /// Extra time the host waits past the command's own deadline before it takes the VM down.
    pub grace: Duration,
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

    /// Deterministic state probe (spec §20.5 step 6).
    async fn probe(&self, handle: &BackendHandle) -> Result<ProbeReport>;

    /// Kernel-sourced resource counters for evidence, if available.
    async fn stats(&self, handle: &BackendHandle) -> Result<Option<CgroupStats>>;
}
