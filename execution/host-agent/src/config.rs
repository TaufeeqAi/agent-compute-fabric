//! Host configuration: *where things live, how big the machine is, and every bound* — as opposed to
//! the safety profile, which says what a request may consume. Both are trusted inputs (TI-1).
//!
//! # The parameter register (contract §30)
//! Every bound is a named, finite parameter with a documented default, validated at startup
//! (INV-034). No value means "unlimited". Validation has two tiers:
//!
//! * [`HostConfig::parse`] — structure. A file that does not parse, or that would point the host at
//!   unsafe paths or identities, cannot be used at all.
//! * [`HostConfig::mandatory_checks`] — the *relations* of §30 (for example `operation_retention ≥
//!   acceptance_horizon`). A violated relation is a failed mandatory check: the host starts in
//!   `CONTAINMENT`, serves containment and reads, and creates no privilege (HM-2). It does not exit.

use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    authority::SafetyProfile,
    error::{AcfError, Result},
};

pub const CONFIG_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Paths {
    pub state_root: PathBuf,
    pub runtime_dir: PathBuf,
    /// The local endpoint (operating-system peer credentials).
    pub socket_path: PathBuf,
    /// The safety profile (§9.4).
    pub profile_path: PathBuf,
    /// The enrolment table (§9.1).
    pub enrolment_path: PathBuf,
    /// Secrets the operator provisioned for the built-in provider (§22). One file per reference.
    pub secrets_dir: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            state_root: "/var/lib/acf".into(),
            runtime_dir: "/run/acf".into(),
            socket_path: "/run/acf/host-agent.sock".into(),
            profile_path: "/etc/acf/profile.yaml".into(),
            enrolment_path: "/etc/acf/enrolment.yaml".into(),
            secrets_dir: "/etc/acf/secrets".into(),
        }
    }
}

/// The network endpoint (AU-1, AU-3). Absent: the host has only its local endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// `address:port` to listen on.
    pub listen: String,
    /// The host's certificate chain (PEM), leaf first. The leaf must carry `host_id` as a subject
    /// alternative name (AU-4); otherwise the endpoint is not opened.
    pub certificate: PathBuf,
    /// The host's private key (PEM). Read by the core and handed to the edge; never readable by the edge user.
    pub private_key: PathBuf,
    /// Trust anchors for client certificates (PEM), listed explicitly. The system trust store is never used (AU-3).
    pub trust_anchors: PathBuf,
}

/// The edge domain (PD-1): ingress endpoints and their pre-authentication limits (PA-2).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct EdgeConfig {
    /// Unprivileged identity the edge role runs as. Required when the core runs as root.
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    /// Octal string, e.g. "0660". The socket is the first access-control layer of the local endpoint.
    pub socket_mode: String,
    pub socket_gid: Option<u32>,
    pub tls: Option<TlsConfig>,
    /// `max_connections`: concurrent connections over both endpoints.
    pub max_connections: usize,
    /// Per-source cap: connections from one peer address (network) or one uid (local).
    pub max_connections_per_source: usize,
    /// `max_request_bytes`: one request frame.
    pub max_request_bytes: usize,
    /// `handshake_deadline`: time to authenticate.
    pub handshake_deadline_ms: u64,
    /// `idle_timeout`: an idle connection.
    pub idle_timeout_ms: u64,
    /// `enrolment_refresh_bound`: delay before an enrolment change applies to open connections (AU-5).
    pub enrolment_refresh_ms: u64,
}

impl Default for EdgeConfig {
    fn default() -> Self {
        Self {
            uid: None,
            gid: None,
            socket_mode: "0660".into(),
            socket_gid: None,
            tls: None,
            max_connections: 32,
            max_connections_per_source: 8,
            max_request_bytes: 1024 * 1024,
            handshake_deadline_ms: 10_000,
            idle_timeout_ms: 300_000,
            enrolment_refresh_ms: 10_000,
        }
    }
}

impl EdgeConfig {
    pub fn socket_mode_bits(&self) -> Result<u32> {
        u32::from_str_radix(self.socket_mode.trim_start_matches("0o"), 8)
            .ok()
            .filter(|m| m & !0o777 == 0)
            .ok_or_else(|| AcfError::corrupt(format!("socket_mode `{}` is not a valid octal permission string", self.socket_mode)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct SecurityConfig {
    /// Owners trusted for the profile, the enrolment table, secrets and executables (TI-1).
    pub trusted_owner_uids: Vec<u32>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self { trusted_owner_uids: vec![0] }
    }
}

/// The machine's schedulable envelope (RS-1). Admission reserves against this.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Envelope {
    pub vcpus: u32,
    pub memory_mib: u64,
    pub disk_mib: u64,
    pub max_sandboxes: u32,
    pub snapshot_quota_bytes: u64,
    pub max_snapshots: u32,
    /// Free space that must remain on the state filesystem after a reservation.
    pub min_free_headroom_mib: u64,
    /// Memory set aside for the host agent itself. Execution output held in memory must fit (OU-3).
    pub agent_memory_mib: u64,
}

impl Default for Envelope {
    fn default() -> Self {
        Self {
            vcpus: 4,
            memory_mib: 8192,
            disk_mib: 65_536,
            max_sandboxes: 16,
            snapshot_quota_bytes: 32 * 1024 * 1024 * 1024,
            max_snapshots: 64,
            min_free_headroom_mib: 2048,
            agent_memory_mib: 512,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FirecrackerConfig {
    pub firecracker_bin: PathBuf,
    pub jailer_bin: PathBuf,
    /// Exact release the profile was validated against, e.g. `v1.17.0`. A mismatch at startup is a
    /// failed mandatory check: snapshots are only valid on the same version.
    pub pinned_version: String,
    /// The pinned identity of `firecracker_bin` (TI-2): the SHA-256 of the installed file, 64 lowercase
    /// hex characters. `scripts/install-firecracker.sh` prints it. The file is hashed at startup and
    /// again before every launch; an unset or different digest is a failed mandatory check.
    #[serde(default)]
    pub firecracker_sha256: Option<String>,
    /// The pinned identity of `jailer_bin`. As `firecracker_sha256`.
    #[serde(default)]
    pub jailer_sha256: Option<String>,
    #[serde(default = "default_cgroup_root")]
    pub cgroup_root: PathBuf,
    /// Pre-created cgroup v2 directory (under `cgroup_root`) with the cpu/memory/pids controllers
    /// delegated; the jailer creates one child per sandbox beneath it.
    #[serde(default = "default_cgroup_parent")]
    pub cgroup_parent: String,
    /// The identifier pool (RS-3): slot `i` runs its VMM as uid `uid_range_start + i`.
    #[serde(default = "default_uid_start")]
    pub uid_range_start: u32,
    #[serde(default = "default_uid_size")]
    pub uid_range_size: u32,
    /// Per-runtime memory overhead the backend declares; counted in admission and in `memory.max`.
    #[serde(default = "default_overhead")]
    pub vmm_overhead_mib: u32,
    /// Off by default: a log file is guest-influenced host disk growth.
    #[serde(default)]
    pub diagnostic_log: bool,
    #[serde(default = "default_boot_args")]
    pub boot_args: String,
    #[serde(default = "default_api_ready_ms")]
    pub api_ready_timeout_ms: u64,
    #[serde(default = "default_boot_ms")]
    pub guest_ready_timeout_ms: u64,
    #[serde(default = "default_grace_ms")]
    pub shutdown_grace_ms: u64,
}

fn default_cgroup_root() -> PathBuf {
    "/sys/fs/cgroup".into()
}
fn default_cgroup_parent() -> String {
    "acf".into()
}
fn default_uid_start() -> u32 {
    100_000
}
fn default_uid_size() -> u32 {
    4096
}
fn default_overhead() -> u32 {
    64
}
fn default_api_ready_ms() -> u64 {
    5_000
}
fn default_boot_ms() -> u64 {
    30_000
}
fn default_grace_ms() -> u64 {
    2_000
}
/// Firecracker's own documented default kernel command line (`docs/kernel-policy.md`, "Kernel command
/// line parameters"), with `pci=off` spelled out.
///
/// * `8250.nr_uarts=0` removes the serial device, which Firecracker's production guidance flags as an
///   unbounded, guest-controlled output channel when not rate limited.
/// * `swiotlb=noforce` disables software bounce buffers (memory the guest would otherwise reserve).
/// * `pci=off`: this host uses the MMIO virtio transport (it never passes `--enable-pci`), and
///   Firecracker adds the same flag itself when PCI is disabled; saying it here keeps the intent
///   visible and does not depend on that implicit append. If PCI transport is ever enabled this MUST
///   be removed (upstream: "Make sure that the kernel command line does NOT include pci=off").
///
/// Supplying `boot_args` (config or image manifest) *replaces* this string, so an override must carry
/// every flag it wants to keep.
pub fn default_boot_args() -> String {
    "reboot=k panic=1 pci=off nomodule 8250.nr_uarts=0 i8042.noaux i8042.nomux i8042.dumbkbd swiotlb=noforce".into()
}

/// Network mode `allowlist` (§20): the guest segment and the guest-traffic role's bounds.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct NetworkConfig {
    /// The private /30 every sandbox uses between its guest and the host side of its own network
    /// namespace. The same in every namespace: it is never routed, so it cannot collide, and a
    /// restored guest finds the addresses it was captured with.
    pub guest_segment: String,
    /// Slot `i` runs its guest-traffic process as uid `traffic_uid_start + i` (PD-3).
    pub traffic_uid_start: u32,
    pub ip_bin: PathBuf,
    pub nft_bin: PathBuf,
    /// Used to run `ip` and `nft` inside a sandbox's network namespace.
    pub nsenter_bin: PathBuf,
    /// Used to create every sandbox's network namespace, in both network modes.
    pub unshare_bin: PathBuf,
    /// `dns_binding_ttl`: validity of a resolved address for AL-4.
    pub dns_binding_ttl_ms: u64,
    /// Concurrent relayed connections per sandbox.
    pub relay_max_connections: usize,
    /// Time a guest has to present a TLS server name.
    pub server_name_deadline_ms: u64,
    pub connect_deadline_ms: u64,
    pub relay_idle_timeout_ms: u64,
    pub upstream_timeout_ms: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            guest_segment: "10.201.0.0/30".into(),
            traffic_uid_start: 200_000,
            ip_bin: "/usr/sbin/ip".into(),
            nft_bin: "/usr/sbin/nft".into(),
            nsenter_bin: "/usr/bin/nsenter".into(),
            unshare_bin: "/usr/bin/unshare".into(),
            dns_binding_ttl_ms: 300_000,
            relay_max_connections: 256,
            server_name_deadline_ms: 5_000,
            connect_deadline_ms: 10_000,
            relay_idle_timeout_ms: 300_000,
            upstream_timeout_ms: 5_000,
        }
    }
}

/// Operation deadlines, per type (§30). A granting deadline covers every step of the operation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct OperationDeadlines {
    pub create_ms: u64,
    pub start_ms: u64,
    pub stop_ms: u64,
    pub destroy_ms: u64,
    pub snapshot_ms: u64,
    pub restore_ms: u64,
    pub delete_ms: u64,
    pub operator_ms: u64,
}

impl Default for OperationDeadlines {
    fn default() -> Self {
        Self {
            create_ms: 300_000,
            start_ms: 120_000,
            stop_ms: 60_000,
            destroy_ms: 120_000,
            snapshot_ms: 600_000,
            restore_ms: 600_000,
            delete_ms: 120_000,
            operator_ms: 120_000,
        }
    }
}

impl OperationDeadlines {
    fn shortest(&self) -> u64 {
        [self.create_ms, self.start_ms, self.stop_ms, self.destroy_ms, self.snapshot_ms, self.restore_ms, self.delete_ms, self.operator_ms]
            .into_iter()
            .min()
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct OperationsConfig {
    /// `acceptance_horizon`: how old `issued_at` may be.
    pub acceptance_horizon_ms: u64,
    /// `clock_skew_tolerance`: how far in the future `issued_at` may be.
    pub clock_skew_tolerance_ms: u64,
    /// `operation_retention`: how long a terminal operation is kept.
    pub operation_retention_ms: u64,
    /// `change_retention`: how long tombstones of destroyed sandboxes and deleted snapshots are kept.
    pub change_retention_ms: u64,
    /// `output_retention`: how long execution output is kept.
    pub output_retention_ms: u64,
    /// `wait_max`: how long a response may be held.
    pub wait_max_ms: u64,
    /// `operation_rate_limit`: operations per peer per minute (granting and operator methods).
    pub rate_limit_per_minute: u32,
    /// Reads per peer per minute.
    pub read_rate_limit_per_minute: u32,
    pub deadlines: OperationDeadlines,
    /// `backstop_margin`: host deadline minus guest deadline for an execution.
    pub backstop_margin_ms: u64,
    /// `step_max_attempts`: attempts of one step whose failure was marked `NONE`.
    pub step_max_attempts: u32,
    /// `retry_budget`: host-wide concurrent step retries.
    pub retry_budget: u32,
    /// How long a containment operation waits for the operation it superseded to let go (CC-3).
    pub preempt_grace_ms: u64,
    /// `drain_timeout`: time in `DRAINING` before the core may stop.
    pub drain_timeout_ms: u64,
}

impl Default for OperationsConfig {
    fn default() -> Self {
        Self {
            acceptance_horizon_ms: 300_000,
            clock_skew_tolerance_ms: 30_000,
            operation_retention_ms: 24 * 3_600_000,
            change_retention_ms: 3_600_000,
            output_retention_ms: 24 * 3_600_000,
            wait_max_ms: 30_000,
            rate_limit_per_minute: 600,
            read_rate_limit_per_minute: 6_000,
            deadlines: OperationDeadlines::default(),
            backstop_margin_ms: 3_000,
            step_max_attempts: 3,
            retry_budget: 4,
            preempt_grace_ms: 5_000,
            drain_timeout_ms: 60_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct RecoveryConfig {
    /// `recovery_max_attempts`: a record recovery has touched this many times is quarantined (RC-4).
    pub max_attempts: u32,
    pub teardown_timeout_ms: u64,
    /// `startup_recovery_deadline`: time in `STARTING` (RC-5).
    pub startup_deadline_ms: u64,
    /// Deadline of one observation (OB-2).
    pub observe_timeout_ms: u64,
    /// `sweep_interval`: longest time between observations of a generation (RC-6).
    pub sweep_interval_ms: u64,
    /// `runtime_loss_detection_bound`: time to notice a lost runtime.
    pub runtime_loss_detection_ms: u64,
    /// `posture_recheck_interval`: the longest time between two verifications of any mandatory
    /// control of a live generation (IS-3). At least four times `sweep_interval_ms`; see
    /// [`RecoveryConfig::posture_due_after`].
    pub posture_recheck_interval_ms: u64,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            teardown_timeout_ms: 10_000,
            startup_deadline_ms: 120_000,
            observe_timeout_ms: 5_000,
            sweep_interval_ms: 15_000,
            runtime_loss_detection_ms: 5_000,
            posture_recheck_interval_ms: 60_000,
        }
    }
}

impl RecoveryConfig {
    /// IS-3 as arithmetic. A generation is observed by the sweep while it is idle and by the operation
    /// that holds it otherwise (RC-6). Two consecutive observations are never further apart than half
    /// the interval: a quarter while idle (the relation `sweep_interval ≤ interval / 4` is a mandatory
    /// check), a quarter while held ([`Self::posture_watch_period`]), and the sum of the two across a
    /// change from one to the other. A control that is costly to verify is verified at the first
    /// observation after half the interval has passed since it was last verified. Half plus half:
    /// no control goes unverified for longer than `posture_recheck_interval`.
    pub fn posture_due_after(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.posture_recheck_interval_ms / 2)
    }

    /// How often an operation that holds a generation observes it.
    pub fn posture_watch_period(&self) -> std::time::Duration {
        std::time::Duration::from_millis((self.posture_recheck_interval_ms / 4).max(1))
    }
}

/// Lifetime enforcement that does not depend on the core (PD-4, LT-4).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct LifetimeConfig {
    /// `expiry_tolerance`: lateness of lifetime enforcement.
    pub expiry_tolerance_ms: u64,
    /// How often the enforcer looks at its tickets. Must be well under the tolerance.
    pub enforcer_interval_ms: u64,
    /// The core treats an enforcer heartbeat older than this as "not running".
    pub heartbeat_max_age_ms: u64,
}

impl Default for LifetimeConfig {
    fn default() -> Self {
        Self { expiry_tolerance_ms: 5_000, enforcer_interval_ms: 500, heartbeat_max_age_ms: 5_000 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct StoreConfig {
    /// `control_store_reserve`: store capacity kept from workload data (PS-9).
    pub reserve_bytes: u64,
    /// The store's file is rewritten as current state once it has grown past this and at least half
    /// of it is no longer current (PS-10). At most half of the largest file the core opens.
    pub compact_at_bytes: u64,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self { reserve_bytes: 16 * 1024 * 1024, compact_at_bytes: crate::store::journal::COMPACT_AT_BYTES }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostConfig {
    pub schema_version: u32,
    /// Identity of this deployment (§8): the audience of commands and a label on events.
    pub host_id: String,
    #[serde(default)]
    pub paths: Paths,
    #[serde(default)]
    pub edge: EdgeConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub envelope: Envelope,
    pub firecracker: FirecrackerConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub operations: OperationsConfig,
    #[serde(default)]
    pub recovery: RecoveryConfig,
    #[serde(default)]
    pub lifetime: LifetimeConfig,
    #[serde(default)]
    pub store: StoreConfig,
}

impl HostConfig {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes).map_err(|_| AcfError::corrupt("host config is not valid UTF-8"))?;
        let cfg: HostConfig = serde_saphyr::from_str(text).map_err(|e| AcfError::corrupt(format!("host config YAML rejected: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Structural validity: what must hold for the host to be able to run safely at all.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(AcfError::incompatible(format!(
                "host config schema_version {} unsupported (expected {CONFIG_SCHEMA_VERSION})",
                self.schema_version
            )));
        }
        let id_ok = (1..=64).contains(&self.host_id.len())
            && self.host_id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            && !self.host_id.starts_with('.');
        if !id_ok {
            return Err(AcfError::corrupt("host_id must be 1..=64 characters of [A-Za-z0-9._-]"));
        }
        self.edge.socket_mode_bits()?;
        let p = &self.paths;
        for (what, path) in [
            ("state_root", &p.state_root),
            ("runtime_dir", &p.runtime_dir),
            ("socket_path", &p.socket_path),
            ("profile_path", &p.profile_path),
            ("enrolment_path", &p.enrolment_path),
            ("secrets_dir", &p.secrets_dir),
        ] {
            if !path.is_absolute() {
                return Err(AcfError::corrupt(format!("paths.{what} must be an absolute path")));
            }
        }
        let f = &self.firecracker;
        if !f.firecracker_bin.is_absolute() || !f.jailer_bin.is_absolute() {
            return Err(AcfError::corrupt("firecracker_bin and jailer_bin must be absolute paths"));
        }
        let n = &self.network;
        if [&n.ip_bin, &n.nft_bin, &n.nsenter_bin, &n.unshare_bin].iter().any(|bin| !bin.is_absolute()) {
            return Err(AcfError::corrupt(
                "network.ip_bin, network.nft_bin, network.nsenter_bin and network.unshare_bin must be absolute paths",
            ));
        }
        if !f.pinned_version.starts_with('v') || f.pinned_version.split('.').count() != 3 {
            return Err(AcfError::corrupt("firecracker.pinned_version must look like `v1.17.0`"));
        }
        for (key, digest) in [("firecracker_sha256", &f.firecracker_sha256), ("jailer_sha256", &f.jailer_sha256)] {
            let well_formed = |d: &str| d.len() == 64 && d.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
            if digest.as_deref().is_some_and(|d| !well_formed(d)) {
                return Err(AcfError::corrupt(format!("firecracker.{key} must be 64 lowercase hex characters")));
            }
        }
        if f.cgroup_parent.is_empty() || f.cgroup_parent.contains('/') || f.cgroup_parent.contains("..") {
            return Err(AcfError::corrupt("firecracker.cgroup_parent must be a single path component"));
        }
        if f.uid_range_size == 0 || f.uid_range_start.checked_add(f.uid_range_size).is_none() || f.uid_range_start < 1000 {
            return Err(AcfError::corrupt("uid range must be >= 1000 and not overflow; it must never include system uids"));
        }
        let t = self.network.traffic_uid_start;
        let overlap = t < f.uid_range_start.saturating_add(f.uid_range_size) && f.uid_range_start < t.saturating_add(f.uid_range_size);
        if t < 1000 || t.checked_add(f.uid_range_size).is_none() || overlap {
            return Err(AcfError::corrupt(
                "network.traffic_uid_start must be >= 1000, must not overflow and must not overlap the VMM uid range",
            ));
        }
        if let (Some(0), _) | (_, Some(0)) = (self.edge.uid, self.edge.gid) {
            return Err(AcfError::corrupt("edge.uid and edge.gid must not be 0: the edge holds no privilege (PD-1)"));
        }
        let e = &self.envelope;
        if e.vcpus == 0 || e.memory_mib == 0 || e.disk_mib == 0 || e.max_sandboxes == 0 {
            return Err(AcfError::corrupt("envelope values must be non-zero"));
        }
        Ok(())
    }

    /// The relations of §30 that are not structural. Each returned string is a failed mandatory
    /// check; any one of them puts the host in `CONTAINMENT` (INV-022, INV-034).
    pub fn mandatory_checks(&self, profile: Option<&SafetyProfile>) -> Vec<String> {
        let mut bad = Vec::new();
        let mut need = |ok: bool, msg: &str| {
            if !ok {
                bad.push(msg.to_owned());
            }
        };
        let (e, o, r, l, f, env) = (&self.edge, &self.operations, &self.recovery, &self.lifetime, &self.firecracker, &self.envelope);

        // PR-1: every bound finite and non-zero.
        let nonzero = [
            ("edge.max_connections", e.max_connections as u64),
            ("edge.max_connections_per_source", e.max_connections_per_source as u64),
            ("edge.max_request_bytes", e.max_request_bytes as u64),
            ("edge.handshake_deadline_ms", e.handshake_deadline_ms),
            ("edge.idle_timeout_ms", e.idle_timeout_ms),
            ("edge.enrolment_refresh_ms", e.enrolment_refresh_ms),
            ("operations.acceptance_horizon_ms", o.acceptance_horizon_ms),
            ("operations.operation_retention_ms", o.operation_retention_ms),
            ("operations.change_retention_ms", o.change_retention_ms),
            ("operations.output_retention_ms", o.output_retention_ms),
            ("operations.wait_max_ms", o.wait_max_ms),
            ("operations.rate_limit_per_minute", u64::from(o.rate_limit_per_minute)),
            ("operations.read_rate_limit_per_minute", u64::from(o.read_rate_limit_per_minute)),
            ("operations.backstop_margin_ms", o.backstop_margin_ms),
            ("operations.step_max_attempts", u64::from(o.step_max_attempts)),
            ("operations.retry_budget", u64::from(o.retry_budget)),
            ("operations.preempt_grace_ms", o.preempt_grace_ms),
            ("operations.drain_timeout_ms", o.drain_timeout_ms),
            ("operations.deadlines (shortest)", o.deadlines.shortest()),
            ("recovery.max_attempts", u64::from(r.max_attempts)),
            ("recovery.teardown_timeout_ms", r.teardown_timeout_ms),
            ("recovery.startup_deadline_ms", r.startup_deadline_ms),
            ("recovery.observe_timeout_ms", r.observe_timeout_ms),
            ("recovery.sweep_interval_ms", r.sweep_interval_ms),
            ("recovery.runtime_loss_detection_ms", r.runtime_loss_detection_ms),
            ("recovery.posture_recheck_interval_ms", r.posture_recheck_interval_ms),
            ("lifetime.expiry_tolerance_ms", l.expiry_tolerance_ms),
            ("lifetime.enforcer_interval_ms", l.enforcer_interval_ms),
            ("lifetime.heartbeat_max_age_ms", l.heartbeat_max_age_ms),
            ("store.reserve_bytes", self.store.reserve_bytes),
            ("store.compact_at_bytes", self.store.compact_at_bytes),
            ("network.dns_binding_ttl_ms", self.network.dns_binding_ttl_ms),
            ("network.relay_max_connections", self.network.relay_max_connections as u64),
            ("network.server_name_deadline_ms", self.network.server_name_deadline_ms),
            ("network.connect_deadline_ms", self.network.connect_deadline_ms),
            ("network.relay_idle_timeout_ms", self.network.relay_idle_timeout_ms),
            ("network.upstream_timeout_ms", self.network.upstream_timeout_ms),
            ("envelope.agent_memory_mib", env.agent_memory_mib),
        ];
        for (name, v) in nonzero {
            need(v > 0, &format!("{name} must be greater than zero: no bound means \"unlimited\""));
        }

        // The required relations, in the order of the register.
        need(e.max_connections_per_source <= e.max_connections, "edge.max_connections_per_source must not exceed edge.max_connections");
        need(e.handshake_deadline_ms < e.idle_timeout_ms, "edge.handshake_deadline_ms must be less than edge.idle_timeout_ms");
        need(o.wait_max_ms < o.deadlines.shortest(), "operations.wait_max_ms must be less than the shortest operation deadline");
        need(
            o.clock_skew_tolerance_ms < o.acceptance_horizon_ms,
            "operations.clock_skew_tolerance_ms must be less than acceptance_horizon_ms",
        );
        need(
            o.operation_retention_ms >= o.acceptance_horizon_ms,
            "operations.operation_retention_ms must be at least acceptance_horizon_ms (OP-12)",
        );
        need(o.output_retention_ms <= o.operation_retention_ms, "operations.output_retention_ms must not exceed operation_retention_ms");
        need(
            r.runtime_loss_detection_ms <= r.sweep_interval_ms,
            "recovery.runtime_loss_detection_ms must not exceed recovery.sweep_interval_ms",
        );
        need(
            r.sweep_interval_ms.saturating_mul(4) <= r.posture_recheck_interval_ms,
            "recovery.sweep_interval_ms must not exceed a quarter of recovery.posture_recheck_interval_ms (IS-3)",
        );
        need(
            l.enforcer_interval_ms < l.expiry_tolerance_ms,
            "lifetime.enforcer_interval_ms must be less than lifetime.expiry_tolerance_ms",
        );
        need(
            self.store.compact_at_bytes <= crate::store::journal::MAX_JOURNAL_BYTES / 2,
            "store.compact_at_bytes must be at most half of the largest store the core opens (PS-10)",
        );
        need(
            env.max_sandboxes <= f.uid_range_size,
            "envelope.max_sandboxes exceeds the identifier pool: every sandbox needs a distinct slot",
        );
        need(
            crate::network::GuestSegment::parse(&self.network.guest_segment).is_ok(),
            "network.guest_segment must be a private IPv4 /30 in CIDR form",
        );
        if let Some(p) = profile {
            let lim = p.limits();
            need(u32::from(lim.max_vcpus) <= env.vcpus, "the safety profile's max_vcpus exceeds the host envelope");
            need(u64::from(lim.max_memory_mib) <= env.memory_mib, "the safety profile's max_memory_mib exceeds the host envelope");
            need(u64::from(lim.max_disk_mib) <= env.disk_mib, "the safety profile's max_disk_mib exceeds the host envelope");
            // OU-3: with every sandbox executing, the output held in memory must fit the agent's budget.
            let worst = u64::from(env.max_sandboxes).saturating_mul(lim.max_stdout_bytes.saturating_add(lim.max_stderr_bytes));
            need(
                worst <= env.agent_memory_mib.saturating_mul(1024 * 1024),
                "envelope.max_sandboxes × (max_stdout_bytes + max_stderr_bytes) exceeds envelope.agent_memory_mib (OU-3)",
            );
        }
        bad
    }

    // ---- derived layout (the ONLY place layout paths are spelled) ----
    pub fn journal_path(&self) -> PathBuf {
        self.paths.state_root.join("state/journal.wal")
    }
    pub fn lock_path(&self) -> PathBuf {
        self.paths.state_root.join("state/host-agent.lock")
    }
    /// Expiry tickets for the lifetime enforcer. On the runtime filesystem: they do not outlive a boot.
    pub fn expiry_dir(&self) -> PathBuf {
        self.paths.runtime_dir.join("expiry")
    }
}

#[cfg(any(test, feature = "testing"))]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test doubles may fail loudly; never compiled into release builds"
)]
pub mod test_support {
    use super::*;

    pub fn config(root: &std::path::Path) -> HostConfig {
        let y = format!(
            r#"
schema_version: 2
host_id: test-host
paths:
  state_root: {root}/state-root
  runtime_dir: {root}/run
  socket_path: {root}/run/host.sock
  profile_path: {root}/profile.yaml
  enrolment_path: {root}/enrolment.yaml
  secrets_dir: {root}/secrets
security:
  trusted_owner_uids: [0, {uid}]
envelope:
  vcpus: 8
  memory_mib: 8192
  disk_mib: 32768
  max_sandboxes: 4
  snapshot_quota_bytes: 1073741824
  max_snapshots: 3
  min_free_headroom_mib: 1
firecracker:
  firecracker_bin: /opt/acf/bin/firecracker
  jailer_bin: /opt/acf/bin/jailer
  pinned_version: v1.17.0
store:
  reserve_bytes: 65536
"#,
            root = root.display(),
            uid = rustix::process::geteuid().as_raw()
        );
        HostConfig::parse(y.as_bytes()).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::profile::test_support::profile;

    const BASE: &str = "schema_version: 2\nhost_id: h1\nfirecracker:\n  firecracker_bin: /a\n  jailer_bin: /b\n  pinned_version: v1.17.0\n";

    #[test]
    fn minimal_config_parses_with_safe_defaults_and_passes_every_mandatory_check() {
        let d = tempfile::tempdir().unwrap();
        let c = test_support::config(d.path());
        assert_eq!(c.firecracker.uid_range_start, 100_000, "VM uids must never overlap system uids");
        assert!(!c.firecracker.diagnostic_log, "guest-influenced log growth is off by default");
        assert!(c.firecracker.boot_args.contains("8250.nr_uarts=0"));
        assert_eq!(c.edge.socket_mode_bits().unwrap(), 0o660);
        assert!(c.edge.tls.is_none(), "no network endpoint unless one is configured");
        assert_eq!(c.mandatory_checks(Some(&profile())), Vec::<String>::new());
        let shipped_defaults = HostConfig::parse(BASE.as_bytes()).unwrap();
        assert_eq!(shipped_defaults.mandatory_checks(None), Vec::<String>::new(), "the defaults satisfy every relation of the register");
    }

    #[test]
    fn structurally_invalid_configs_are_rejected() {
        assert!(HostConfig::parse(BASE.as_bytes()).is_ok());
        for (needle, repl) in [
            ("v1.17.0", "latest"),
            ("/a", "relative/fc"),
            ("schema_version: 2", "schema_version: 1"),
            ("host_id: h1", "host_id: \"has space\""),
            ("host_id: h1\n", ""),
        ] {
            assert!(HostConfig::parse(BASE.replacen(needle, repl, 1).as_bytes()).is_err(), "{needle}->{repl}");
        }
        let low_uids = format!("{BASE}  uid_range_start: 0\n");
        assert!(HostConfig::parse(low_uids.as_bytes()).is_err(), "VM uids inside the system range");
        let traversal = format!("{BASE}  cgroup_parent: ../escape\n");
        assert!(HostConfig::parse(traversal.as_bytes()).is_err());
        let sockmode = format!("{BASE}edge:\n  socket_mode: \"0o1777\"\n");
        assert!(HostConfig::parse(sockmode.as_bytes()).is_err());
        let unknown = format!("{BASE}mystery: 1\n");
        assert!(HostConfig::parse(unknown.as_bytes()).is_err());
        let root_edge = format!("{BASE}edge:\n  uid: 0\n");
        assert!(HostConfig::parse(root_edge.as_bytes()).is_err(), "the edge never runs as root");
        let overlap = format!("{BASE}network:\n  traffic_uid_start: 100100\n");
        assert!(HostConfig::parse(overlap.as_bytes()).is_err(), "the two identifier ranges must be disjoint");
    }

    /// TI-2: a pinned identity is a SHA-256 in one spelling, so that two configurations which pin the
    /// same bytes are equal. Whether the installed file matches is `doctor`'s question, not the parser's.
    #[test]
    fn a_binary_digest_is_optional_in_the_file_and_must_be_well_formed() {
        let unset = HostConfig::parse(BASE.as_bytes()).unwrap();
        assert_eq!((unset.firecracker.firecracker_sha256, unset.firecracker.jailer_sha256), (None, None));
        let digest = "0123456789abcdef".repeat(4);
        let pinned =
            HostConfig::parse(format!("{BASE}  firecracker_sha256: \"{digest}\"\n  jailer_sha256: \"{digest}\"\n").as_bytes()).unwrap();
        assert_eq!(pinned.firecracker.jailer_sha256.as_deref(), Some(digest.as_str()));
        for bad in
            [digest.to_uppercase(), digest[..63].to_owned(), format!("{digest}0"), format!("sha256:{}", &digest[..57]), String::new()]
        {
            for key in ["firecracker_sha256", "jailer_sha256"] {
                let text = format!("{BASE}  {key}: \"{bad}\"\n");
                assert!(HostConfig::parse(text.as_bytes()).is_err(), "{key}: `{bad}` must be refused");
            }
        }
    }

    #[test]
    fn every_violated_relation_of_the_register_is_a_failed_mandatory_check_not_a_parse_error() {
        let cases: [(&str, &str); 14] = [
            ("store:\n  compact_at_bytes: 268435456\n", "store.compact_at_bytes must be at most half"),
            ("recovery:\n  posture_recheck_interval_ms: 30000\n", "a quarter of recovery.posture_recheck_interval_ms"),
            ("operations:\n  operation_retention_ms: 1000\n  output_retention_ms: 500\n", "operation_retention_ms must be at least"),
            ("operations:\n  clock_skew_tolerance_ms: 300000\n", "clock_skew_tolerance_ms"),
            ("operations:\n  wait_max_ms: 60000\n", "wait_max_ms must be less than the shortest"),
            ("operations:\n  output_retention_ms: 999999999999\n", "output_retention_ms must not exceed"),
            ("operations:\n  backstop_margin_ms: 0\n", "backstop_margin_ms must be greater than zero"),
            ("edge:\n  handshake_deadline_ms: 300000\n", "handshake_deadline_ms must be less"),
            ("edge:\n  max_connections_per_source: 64\n", "max_connections_per_source"),
            ("recovery:\n  runtime_loss_detection_ms: 60000\n", "runtime_loss_detection_ms"),
            ("recovery:\n  max_attempts: 0\n", "recovery.max_attempts must be greater than zero"),
            ("lifetime:\n  enforcer_interval_ms: 5000\n", "enforcer_interval_ms"),
            ("store:\n  reserve_bytes: 0\n", "store.reserve_bytes must be greater than zero"),
            ("network:\n  guest_segment: 198.51.100.0/30\n", "guest_segment must be a private"),
        ];
        for (extra, expect) in cases {
            let c = HostConfig::parse(format!("{BASE}{extra}").as_bytes()).unwrap_or_else(|e| panic!("{extra}: must parse: {e}"));
            let bad = c.mandatory_checks(None);
            assert!(bad.iter().any(|m| m.contains(expect)), "{extra}: expected a check mentioning `{expect}`, got {bad:?}");
        }
    }

    #[test]
    fn sandbox_cap_cannot_exceed_the_identifier_pool() {
        let y = format!("{BASE}  uid_range_size: 16\nenvelope:\n  max_sandboxes: 9999\n");
        let c = HostConfig::parse(y.as_bytes()).unwrap();
        assert!(c.mandatory_checks(None).iter().any(|m| m.contains("identifier pool")));
    }

    #[test]
    fn profile_ceilings_must_fit_the_envelope_and_the_output_memory_bound() {
        let small = format!("{BASE}envelope:\n  vcpus: 2\n  memory_mib: 1024\n  disk_mib: 1024\n  agent_memory_mib: 1\n");
        let c = HostConfig::parse(small.as_bytes()).unwrap();
        let bad = c.mandatory_checks(Some(&profile()));
        for expect in ["max_vcpus exceeds", "max_memory_mib exceeds", "max_disk_mib exceeds", "OU-3"] {
            assert!(bad.iter().any(|m| m.contains(expect)), "{expect}: {bad:?}");
        }
    }
}
