//! Host modes (contract §12.6).
//!
//! A mode says which *classes* of method the host serves. The rule that matters most is HM-2: a
//! failed mandatory check never makes the host exit while generations exist. It makes the host stop
//! creating privilege, and keep removing it.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::method::OperationClass;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostMode {
    /// From process start until startup recovery ends. No endpoint is open.
    Starting,
    /// Recovery complete and every mandatory check passed.
    Serving,
    /// An operator asked for it (planned restart): no new privilege, everything else served.
    Draining,
    /// A mandatory check failed, the safety profile is invalid, or the store is older than the
    /// system it describes: no new privilege, everything else served.
    Containment,
    /// The store cannot be written or interpreted: reads only.
    ReadOnly,
}

impl HostMode {
    pub const ALL: [HostMode; 5] = [HostMode::Starting, HostMode::Serving, HostMode::Draining, HostMode::Containment, HostMode::ReadOnly];

    /// The table of §12.6. A refusal caused by the mode has class `HOST_NOT_SERVING` (HM-1).
    pub const fn admits(self, class: OperationClass) -> bool {
        match (self, class) {
            (HostMode::Starting, _) => false,
            (HostMode::Serving, _) => true,
            (HostMode::Draining | HostMode::Containment, OperationClass::Granting) => false,
            (HostMode::Draining | HostMode::Containment, _) => true,
            // In READ_ONLY the host takes no action it cannot record (HM-4). `host.info` is a read.
            (HostMode::ReadOnly, OperationClass::Read) => true,
            (HostMode::ReadOnly, _) => false,
        }
    }
}

/// Why the host is in `CONTAINMENT`. Reasons accumulate; the mode holds while any remains.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "reason", content = "detail", rename_all = "snake_case")]
pub enum ContainmentReason {
    /// A mandatory startup check failed (configuration relation of §30, preflight, trust anchors).
    /// Cleared only by fixing the cause and restarting.
    MandatoryCheck(String),
    /// The safety profile could not be loaded or validated at startup.
    InvalidProfile(String),
    /// An ownership marker on disk is newer than the store (LN-2). Cleared by `host.acknowledge`.
    StoreRegression(String),
    /// The lifetime enforcer cannot be confirmed to be running (PD-4). Clears when it is seen again.
    LifetimeEnforcerUnavailable(String),
}

impl ContainmentReason {
    /// The `condition` an operator names in `host.acknowledge`, when the reason can be acknowledged.
    pub fn acknowledgeable(&self) -> bool {
        matches!(self, ContainmentReason::StoreRegression(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use OperationClass::*;

    #[test]
    fn every_mode_for_every_class_matches_the_table() {
        // §12.6, transcribed row by row: (mode, granting, containment, reads, operator).
        let table = [
            (HostMode::Starting, false, false, false, false),
            (HostMode::Serving, true, true, true, true),
            (HostMode::Draining, false, true, true, true),
            (HostMode::Containment, false, true, true, true),
            (HostMode::ReadOnly, false, false, true, false),
        ];
        assert_eq!(table.len(), HostMode::ALL.len());
        for (mode, granting, containment, reads, operator) in table {
            assert_eq!(mode.admits(Granting), granting, "{mode:?} × granting");
            assert_eq!(mode.admits(Containment), containment, "{mode:?} × containment");
            assert_eq!(mode.admits(Read), reads, "{mode:?} × read");
            assert_eq!(mode.admits(Operator), operator, "{mode:?} × operator");
        }
    }

    #[test]
    fn no_mode_other_than_serving_creates_privilege() {
        for m in HostMode::ALL {
            assert_eq!(m.admits(Granting), m == HostMode::Serving, "{m:?}");
        }
    }

    #[test]
    fn containment_is_served_in_every_mode_that_can_record_it() {
        for m in [HostMode::Serving, HostMode::Draining, HostMode::Containment] {
            assert!(m.admits(Containment), "{m:?} must still remove privilege");
        }
    }
}
