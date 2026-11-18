//! Resource vocabulary (contract §19). Every resource follows
//! `request -> admission -> lease -> enforcement -> violation -> evidence`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::network::NetworkIntent;
use crate::error::{AcfError, Result};

/// What a sandbox is *given*. Immutable for the life of a generation (NW-3, RS-4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SandboxResources {
    pub vcpus: u8,
    pub memory_mib: u32,
    pub disk_mib: u32,
    pub network: NetworkIntent,
}

impl SandboxResources {
    /// Hardware-level validity (independent of any profile ceiling).
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

/// Per-run limits (contract §18.1, §18.4).
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

/// The lease of one generation (§12.4): what admission set aside and which identifiers it holds.
/// Persisted, so ownership of capacity survives a restart. It is released only in the transaction
/// that commits the generation `DESTROYED` (LS-1, INV-027).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Reservation {
    pub vcpus: u32,
    /// Guest memory **plus** the per-runtime overhead the backend declares (RS-1).
    pub memory_mib: u64,
    pub disk_mib: u64,
    /// Index into the host-wide identifier pool (RS-3). The VMM user id, the guest-traffic user id
    /// and the sandbox's network segment are all derived from this one slot, so one reservation
    /// holds every identifier of a generation.
    pub uid_slot: u32,
}

/// When a sandbox ends (contract §19.2). Both clocks are recorded: within one boot the monotonic
/// reading decides; across a reboot the remaining time is recomputed from the wall clock and can
/// only shrink (LT-2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Expiry {
    /// Boot in which `mono_ns` is meaningful.
    pub boot_id: String,
    /// Monotonic deadline, nanoseconds, in that boot.
    pub mono_ns: u64,
    /// The same instant on the wall clock, milliseconds since the Unix epoch.
    pub wall_ms: i64,
    /// The lifetime that was granted, for display and for bounding a recomputed remainder.
    pub lifetime_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(v: u8, m: u32, d: u32) -> SandboxResources {
        SandboxResources { vcpus: v, memory_mib: m, disk_mib: d, network: NetworkIntent::None }
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
    fn unknown_fields_are_refused() {
        let extra = r#"{"vcpus":1,"memory_mib":256,"disk_mib":128,"network":{"mode":"none"},"kernel_args":"x"}"#;
        assert!(serde_json::from_str::<SandboxResources>(extra).is_err(), "kernel and VMM parameters are not caller-settable (API-4)");
    }
}
