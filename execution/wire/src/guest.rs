//! Host <-> guest-agent protocol (spoken over AF_VSOCK, tunnelled through Firecracker's
//! vsock UDS on the host side).
//!
//! Design rules:
//! * **Host initiates, always.** The guest agent only *listens*; the host never binds a
//!   `uds_path_<PORT>` listener, so the guest has no path to initiate a connection to host
//!   control surfaces (spec SEC-001/SEC-014).
//! * **The guest is untrusted.** Every field the guest returns is bounded by the host
//!   before use; this crate only defines shapes.
//! * Unknown fields are rejected (`deny_unknown_fields`) so a version skew fails loudly
//!   instead of being silently reinterpreted (spec §24.3).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Bumped on any incompatible change to this module.
pub const GUEST_PROTOCOL_VERSION: u32 = 1;
/// vsock port the guest agent listens on.
pub const GUEST_VSOCK_PORT: u32 = 5252;
/// The only CID the guest agent accepts connections from (the host).
pub const HOST_CID: u32 = 2;
/// Default ceiling for frames the *guest* sends (responses). The host passes a tighter,
/// per-request bound derived from the run's output budget.
pub const MAX_FRAME_DEFAULT: usize = 48 * 1024 * 1024;

/// Serde helper: `Vec<u8>` <-> base64 string.
pub mod b64 {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s.as_bytes()).map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum GuestRequest {
    Hello {
        protocol_version: u32,
    },
    Ping {
        nonce: String,
    },
    Exec(ExecRequest),
    /// Cancel an in-flight exec. Sent on a *second* connection because the first is
    /// blocked awaiting the result.
    Cancel {
        exec_id: String,
    },
    /// Deterministic baseline probe used as the restore-verification oracle (spec §20.5 #6).
    Probe {
        nonce: String,
    },
    /// Report guest-visible network posture for `network=none` verification (spec §18.6).
    NetProbe,
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecRequest {
    pub exec_id: String,
    pub argv: Vec<String>,
    /// Complete environment; the agent does **not** inherit its own.
    pub env: BTreeMap<String, String>,
    pub cwd: String,
    /// Guest-side deadline. The host enforces its own, later, deadline as a backstop.
    pub timeout_ms: u64,
    pub max_stdout_bytes: u64,
    pub max_stderr_bytes: u64,
    /// Process budget for the command's process tree (spec §18.4).
    pub max_pids: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum GuestResponse {
    Hello { protocol_version: u32, agent_version: String, boot_id: String },
    Pong { nonce: String },
    ExecResult(ExecResult),
    Cancelled { exec_id: String, found: bool },
    Probe(ProbeReport),
    NetProbe(NetReport),
    ShutdownAck,
    Error { code: GuestErrorCode, message: String },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GuestErrorCode {
    UnsupportedVersion,
    Busy,
    BadRequest,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecStatus {
    Exited { code: i32 },
    Signaled { signal: i32 },
    TimedOut,
    Cancelled,
    SpawnFailed { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecResult {
    pub exec_id: String,
    pub status: ExecStatus,
    #[serde(with = "b64")]
    pub stdout: Vec<u8>,
    #[serde(with = "b64")]
    pub stderr: Vec<u8>,
    /// Total bytes the process produced (>= `stdout.len()` when truncated).
    pub stdout_total_bytes: u64,
    pub stderr_total_bytes: u64,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub duration_ms: u64,
    /// True if the process-count budget was hit (fork() returned EAGAIN) during the run.
    pub pid_limit_hit: bool,
    /// True if a descendant still held an output pipe open after the grace period, so the
    /// captured output may be missing a tail (spec §18.8 `INCOMPLETE`).
    pub output_incomplete: bool,
    /// Which mechanism actually enforced the process budget for this run (spec §18.10).
    pub containment: Containment,
}

/// Mechanism that bounded and tore down the command's process tree.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Containment {
    /// Per-exec cgroup v2: `pids.max`, `pids.events`, atomic `cgroup.kill`.
    Cgroup2,
    /// Fallback when the guest kernel lacks the cgroup v2 `pids` controller:
    /// `RLIMIT_NPROC` for a non-root uid plus uid-wide reaping. Weaker; reported as such.
    RlimitNproc,
    /// The guest never returned a result (host backstop fired), so the mechanism is unknown.
    /// Synthesised by the host; a guest agent never sends this.
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProbeReport {
    pub nonce: String,
    /// `/proc/sys/kernel/random/boot_id` — lives in guest *memory* state, so it is
    /// preserved by a true snapshot restore and changes on a reboot.
    pub boot_id: String,
    /// sha256 of the on-disk canary file — preserved by a disk-consistent restore.
    pub canary_sha256: String,
    pub agent_version: String,
    /// sha256(boot_id || 0x00 || canary || 0x00 || agent_version). Nonce-independent.
    pub state_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetReport {
    /// Every interface name under /sys/class/net.
    pub interfaces: Vec<String>,
    pub egress_attempts: Vec<EgressAttempt>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EgressAttempt {
    pub target: String,
    pub outcome: EgressOutcome,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EgressOutcome {
    /// Connection could not be established (expected under `network=none`).
    Blocked,
    /// A connection succeeded — a `network=none` violation.
    Connected,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_result_roundtrips_binary_output() {
        let r = ExecResult {
            exec_id: "e1".into(),
            status: ExecStatus::Exited { code: 3 },
            stdout: vec![0, 255, 10, 13],
            stderr: vec![],
            stdout_total_bytes: 4,
            stderr_total_bytes: 0,
            stdout_truncated: false,
            stderr_truncated: false,
            duration_ms: 7,
            pid_limit_hit: false,
            output_incomplete: false,
            containment: Containment::RlimitNproc,
        };
        let s = serde_json::to_string(&GuestResponse::ExecResult(r.clone())).unwrap();
        let back: GuestResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(back, GuestResponse::ExecResult(r));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let bad = r#"{"type":"ping","nonce":"x","surprise":1}"#;
        assert!(serde_json::from_str::<GuestRequest>(bad).is_err());
    }
}
