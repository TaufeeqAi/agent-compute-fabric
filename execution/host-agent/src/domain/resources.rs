//! Resource vocabulary (spec §8.8, §18). Every resource follows
//! `request -> admission -> reservation -> enforcement -> violation -> evidence`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{AcfError, Result};

/// Phase 1 network vocabulary: `none` only (spec §18.7, DELTA-015). The enum is
/// `non_exhaustive` so adding a mode later is a *minor* contract change that must ship with
/// its own semantic contract and adversarial tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NetworkMode {
    None,
}

/// What a sandbox is *given*. Immutable for the life of a generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SandboxResources {
    pub vcpus: u8,
    pub memory_mib: u32,
    pub disk_mib: u32,
    pub network: NetworkMode,
}

impl SandboxResources {
    /// Hardware-level validity (independent of any policy ceiling).
    pub fn validate_shape(&self) -> Result<()> {
        // Firecracker: "either 1 or an even number", 1..=32.
        if self.vcpus == 0 || self.vcpus > 32 || (self.vcpus != 1 && !self.vcpus.is_multiple_of(2)) {
            return Err(AcfError::validation("vcpus must be 1 or an even number up to 32"));
        }
        if !(128..=1_048_576).contains(&self.memory_mib) {
            return Err(AcfError::validation("memory_mib must be within 128..=1048576"));
        }
        if !(64..=1_048_576).contains(&self.disk_mib) {
            return Err(AcfError::validation("disk_mib must be within 64..=1048576"));
        }
        Ok(())
    }
}

/// Per-run limits (spec §18.3, §18.4, §18.8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunLimits {
    pub timeout_ms: u64,
    pub max_pids: u32,
    pub max_stdout_bytes: u64,
    pub max_stderr_bytes: u64,
}

impl RunLimits {
    pub fn validate_shape(&self) -> Result<()> {
        if self.timeout_ms == 0 || self.timeout_ms > 24 * 3600 * 1000 {
            return Err(AcfError::validation("timeout_ms must be within 1..=86400000"));
        }
        if self.max_pids == 0 || self.max_pids > 1 << 20 {
            return Err(AcfError::validation("max_pids must be within 1..=1048576"));
        }
        if self.max_stdout_bytes == 0 || self.max_stderr_bytes == 0 {
            return Err(AcfError::validation("output budgets must be non-zero"));
        }
        Ok(())
    }
}

/// What admission set aside for one sandbox generation. Persisted so ownership of capacity
/// survives a host-agent restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Reservation {
    pub vcpus: u32,
    /// Guest memory **plus** the per-VMM overhead the host budgets for.
    pub memory_mib: u64,
    pub disk_mib: u64,
    /// Index into the per-VM uid/gid range (Firecracker recommends a unique uid per VM).
    pub uid_slot: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(v: u8, m: u32, d: u32) -> SandboxResources {
        SandboxResources { vcpus: v, memory_mib: m, disk_mib: d, network: NetworkMode::None }
    }

    #[test]
    fn vcpu_rule_matches_firecracker() {
        for ok in [1, 2, 4, 32] {
            assert!(r(ok, 512, 512).validate_shape().is_ok(), "{ok}");
        }
        for bad in [0, 3, 5, 33] {
            assert!(r(bad, 512, 512).validate_shape().is_err(), "{bad}");
        }
    }

    #[test]
    fn memory_and_disk_floors() {
        assert!(r(1, 127, 512).validate_shape().is_err());
        assert!(r(1, 512, 63).validate_shape().is_err());
    }

    #[test]
    fn unknown_network_mode_is_rejected_at_the_wire() {
        // `restricted` was removed from the contract in v1.1.0 (DELTA-015).
        assert!(serde_json::from_str::<NetworkMode>("\"restricted\"").is_err());
        assert_eq!(serde_json::from_str::<NetworkMode>("\"none\"").unwrap(), NetworkMode::None);
    }
}
