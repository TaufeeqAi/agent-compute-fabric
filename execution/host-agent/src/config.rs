//! Host configuration: *where things live and how big the machine is* — as opposed to policy,
//! which says what callers may do. Both are loaded through `trusted_file` (spec §16.4).
//!
//! Every field has a safe default except the ones that must be a deliberate operator choice
//! (the Firecracker/Jailer binaries and the pinned version).

use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{AcfError, Result};

pub const CONFIG_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Paths {
    pub state_root: PathBuf,
    pub runtime_dir: PathBuf,
    pub socket_path: PathBuf,
    pub policy_path: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            state_root: "/var/lib/acf".into(),
            runtime_dir: "/run/acf".into(),
            socket_path: "/run/acf/host-agent.sock".into(),
            policy_path: "/etc/acf/policy.yaml".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct SecurityConfig {
    /// Callers allowed by uid. Empty list + empty gids = nobody (even root) may connect.
    pub allowed_uids: Vec<u32>,
    pub allowed_gids: Vec<u32>,
    /// Octal string, e.g. "0660". The socket is the first access-control layer (spec §16.1).
    pub socket_mode: String,
    pub socket_gid: Option<u32>,
    pub max_connections: usize,
    pub max_request_bytes: usize,
    pub idle_timeout_secs: u64,
    /// Owners trusted for policy/config files.
    pub trusted_owner_uids: Vec<u32>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            allowed_uids: vec![0],
            allowed_gids: vec![],
            socket_mode: "0660".into(),
            socket_gid: None,
            max_connections: 32,
            max_request_bytes: 1024 * 1024,
            idle_timeout_secs: 300,
            trusted_owner_uids: vec![0],
        }
    }
}

impl SecurityConfig {
    pub fn socket_mode_bits(&self) -> Result<u32> {
        u32::from_str_radix(self.socket_mode.trim_start_matches("0o"), 8)
            .ok()
            .filter(|m| m & !0o777 == 0)
            .ok_or_else(|| AcfError::corrupt(format!("socket_mode `{}` is not a valid octal permission string", self.socket_mode)))
    }
}

/// The machine's schedulable envelope (spec §18.1). Admission reserves against this.
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
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FirecrackerConfig {
    pub firecracker_bin: PathBuf,
    pub jailer_bin: PathBuf,
    /// Exact release the profile was validated against, e.g. `v1.17.0`. A mismatch at startup is
    /// a hard failure: Firecracker snapshots are only valid on the same version (spec §20.4).
    pub pinned_version: String,
    #[serde(default = "default_cgroup_root")]
    pub cgroup_root: PathBuf,
    /// Pre-created cgroup v2 directory (under `cgroup_root`) with the cpu/memory/pids controllers
    /// delegated; the jailer creates one child per sandbox beneath it.
    #[serde(default = "default_cgroup_parent")]
    pub cgroup_parent: String,
    #[serde(default = "default_uid_start")]
    pub uid_range_start: u32,
    #[serde(default = "default_uid_size")]
    pub uid_range_size: u32,
    /// Memory the VMM itself needs beyond guest RAM; budgeted in admission and in `memory.max`.
    #[serde(default = "default_overhead")]
    pub vmm_overhead_mib: u32,
    /// Off by default: a log file is guest-influenced host disk growth (Firecracker prod guidance).
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
/// Firecracker v1.17.0's own documented default kernel command line
/// (`docs/kernel-policy.md`, "Kernel command line parameters"), with `pci=off` spelled out.
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

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct RecoveryConfig {
    /// A record recovery has touched this many times is quarantined, not retried (spec §22.7).
    pub max_attempts: u32,
    pub teardown_timeout_ms: u64,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self { max_attempts: 3, teardown_timeout_ms: 10_000 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostConfig {
    pub schema_version: u32,
    #[serde(default)]
    pub paths: Paths,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub envelope: Envelope,
    pub firecracker: FirecrackerConfig,
    #[serde(default)]
    pub recovery: RecoveryConfig,
}

impl HostConfig {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes).map_err(|_| AcfError::corrupt("host config is not valid UTF-8"))?;
        let cfg: HostConfig = serde_saphyr::from_str(text).map_err(|e| AcfError::corrupt(format!("host config YAML rejected: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(AcfError::new(
                crate::error::FailureClass::SchemaMismatch,
                format!("host config schema_version {} unsupported (expected {CONFIG_SCHEMA_VERSION})", self.schema_version),
            ));
        }
        self.security.socket_mode_bits()?;
        let f = &self.firecracker;
        if !f.firecracker_bin.is_absolute() || !f.jailer_bin.is_absolute() {
            return Err(AcfError::corrupt("firecracker_bin and jailer_bin must be absolute paths"));
        }
        if !f.pinned_version.starts_with('v') || f.pinned_version.split('.').count() != 3 {
            return Err(AcfError::corrupt("firecracker.pinned_version must look like `v1.17.0`"));
        }
        if f.cgroup_parent.is_empty() || f.cgroup_parent.contains('/') || f.cgroup_parent.contains("..") {
            return Err(AcfError::corrupt("firecracker.cgroup_parent must be a single path component"));
        }
        if f.uid_range_size == 0 || f.uid_range_start.checked_add(f.uid_range_size).is_none() || f.uid_range_start < 1000 {
            return Err(AcfError::corrupt("uid range must be >= 1000 and not overflow; it must never include system uids"));
        }
        let e = &self.envelope;
        if e.vcpus == 0 || e.memory_mib == 0 || e.disk_mib == 0 || e.max_sandboxes == 0 {
            return Err(AcfError::corrupt("envelope values must be non-zero"));
        }
        if e.max_sandboxes > f.uid_range_size {
            return Err(AcfError::corrupt("envelope.max_sandboxes exceeds the per-VM uid range: every VM needs a distinct uid"));
        }
        Ok(())
    }

    // ---- derived layout (the ONLY place layout paths are spelled) ----
    pub fn journal_path(&self) -> PathBuf {
        self.paths.state_root.join("state/journal.wal")
    }
    pub fn lock_path(&self) -> PathBuf {
        self.paths.state_root.join("state/host-agent.lock")
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
schema_version: 1
paths:
  state_root: {root}/state-root
  runtime_dir: {root}/run
  socket_path: {root}/run/host.sock
  policy_path: {root}/policy.yaml
security:
  allowed_uids: [0, {uid}]
  trusted_owner_uids: [{uid}]
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

    #[test]
    fn minimal_config_parses_with_safe_defaults() {
        let d = tempfile::tempdir().unwrap();
        let c = test_support::config(d.path());
        assert_eq!(c.firecracker.uid_range_start, 100_000, "VM uids must never overlap system uids");
        assert!(!c.firecracker.diagnostic_log, "guest-influenced log growth is off by default");
        assert!(c.firecracker.boot_args.contains("8250.nr_uarts=0"));
        assert_eq!(c.security.socket_mode_bits().unwrap(), 0o660);
    }

    #[test]
    fn invalid_configs_are_rejected() {
        let base = "schema_version: 1\nfirecracker:\n  firecracker_bin: /a\n  jailer_bin: /b\n  pinned_version: v1.17.0\n";
        assert!(HostConfig::parse(base.as_bytes()).is_ok());
        for (needle, repl) in [("v1.17.0", "latest"), ("/a", "relative/fc"), ("schema_version: 1", "schema_version: 9")] {
            assert!(HostConfig::parse(base.replacen(needle, repl, 1).as_bytes()).is_err(), "{needle}->{repl}");
        }
        let low_uids = format!("{base}  uid_range_start: 0\n");
        assert!(HostConfig::parse(low_uids.as_bytes()).is_err(), "VM uids inside the system range");
        let traversal = format!("{base}  cgroup_parent: ../escape\n");
        assert!(HostConfig::parse(traversal.as_bytes()).is_err());
        let sockmode = format!("{base}security:\n  socket_mode: \"0o1777\"\n");
        assert!(HostConfig::parse(sockmode.as_bytes()).is_err());
        let unknown = format!("{base}mystery: 1\n");
        assert!(HostConfig::parse(unknown.as_bytes()).is_err());
    }

    #[test]
    fn sandbox_cap_cannot_exceed_the_uid_pool() {
        let y = "schema_version: 1\nenvelope:\n  max_sandboxes: 9999\nfirecracker:\n  firecracker_bin: /a\n  jailer_bin: /b\n  pinned_version: v1.17.0\n  uid_range_size: 16\n";
        assert!(HostConfig::parse(y.as_bytes()).is_err());
    }
}
