//! Evidence for `network=none` (spec §18.6, §18.10) — a pure function over observations, so the
//! decision logic is exhaustively unit-testable without a VM.

use acf_wire::guest::{EgressOutcome, NetReport};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NetworkStatus {
    /// Structure proves there is no NIC *and* the guest corroborates.
    Verified,
    /// Structure proves there is no NIC; the guest could not be asked.
    VerifiedHostOnly,
    /// Something contradicts `network=none`. The sandbox must be torn down (fail closed).
    Violation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct NetworkEvidence {
    pub mode: String,
    pub status: NetworkStatus,
    /// Layer 1: the Firecracker config had zero network interfaces.
    pub vmm_has_no_nic: bool,
    /// Layer 2: the VMM process was inside the dedicated empty namespace.
    pub vmm_in_empty_netns: bool,
    pub guest_interfaces: Option<Vec<String>>,
    pub guest_egress_blocked: Option<bool>,
    pub violations: Vec<String>,
}

/// `host_nic_count` comes from Firecracker's own `GET /vm/config`; `guest` from the agent.
pub fn evaluate_none(host_nic_count: usize, vmm_in_empty_netns: bool, guest: Option<&NetReport>) -> NetworkEvidence {
    let mut violations = Vec::new();
    let vmm_has_no_nic = host_nic_count == 0;
    if !vmm_has_no_nic {
        violations.push(format!("VMM is configured with {host_nic_count} network interface(s) under network=none"));
    }
    if !vmm_in_empty_netns {
        violations.push("VMM is not inside its dedicated empty network namespace".into());
    }

    let (mut guest_interfaces, mut guest_egress_blocked) = (None, None);
    if let Some(g) = guest {
        guest_interfaces = Some(g.interfaces.clone());
        let extra: Vec<&String> = g.interfaces.iter().filter(|i| i.as_str() != "lo").collect();
        if !extra.is_empty() {
            violations.push(format!("guest reports non-loopback interface(s): {extra:?}"));
        }
        let connected: Vec<&str> =
            g.egress_attempts.iter().filter(|a| a.outcome == EgressOutcome::Connected).map(|a| a.target.as_str()).collect();
        guest_egress_blocked = Some(connected.is_empty());
        if !connected.is_empty() {
            violations.push(format!("guest established egress connection(s) to {connected:?}"));
        }
    }

    let status = if !violations.is_empty() {
        NetworkStatus::Violation
    } else if guest.is_some() {
        NetworkStatus::Verified
    } else {
        NetworkStatus::VerifiedHostOnly
    };
    NetworkEvidence { mode: "none".into(), status, vmm_has_no_nic, vmm_in_empty_netns, guest_interfaces, guest_egress_blocked, violations }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acf_wire::guest::EgressAttempt;

    fn guest(ifaces: &[&str], connected: bool) -> NetReport {
        NetReport {
            interfaces: ifaces.iter().map(|s| s.to_string()).collect(),
            egress_attempts: vec![EgressAttempt {
                target: "1.1.1.1:53".into(),
                outcome: if connected { EgressOutcome::Connected } else { EgressOutcome::Blocked },
                detail: String::new(),
            }],
        }
    }

    #[test]
    fn clean_case_is_verified_and_host_only_when_guest_is_silent() {
        assert_eq!(evaluate_none(0, true, Some(&guest(&["lo"], false))).status, NetworkStatus::Verified);
        assert_eq!(evaluate_none(0, true, None).status, NetworkStatus::VerifiedHostOnly);
    }

    #[test]
    fn any_contradiction_is_a_violation() {
        assert_eq!(evaluate_none(1, true, None).status, NetworkStatus::Violation, "a configured NIC");
        assert_eq!(evaluate_none(0, false, None).status, NetworkStatus::Violation, "VMM outside the empty netns");
        assert_eq!(evaluate_none(0, true, Some(&guest(&["lo", "eth0"], false))).status, NetworkStatus::Violation);
        let c = evaluate_none(0, true, Some(&guest(&["lo"], true)));
        assert_eq!((c.status, c.guest_egress_blocked), (NetworkStatus::Violation, Some(false)));
    }

    #[test]
    fn a_lying_guest_cannot_clear_a_host_side_violation() {
        // Authoritative structure says a NIC exists; a clean guest report must not mask it.
        let e = evaluate_none(2, true, Some(&guest(&["lo"], false)));
        assert_eq!(e.status, NetworkStatus::Violation);
        assert!(!e.vmm_has_no_nic);
    }
}
