//! Admission-time validation of a network intent (contract §20.4) and the guest segment.
//!
//! The *meaning* of an allowlist — which connection it permits — lives in the guest-traffic crate
//! (`acf-traffic`), which is the only code that sees guest traffic (PD-3). This module answers the
//! earlier question: is this a well-formed intent that the safety profile permits? It asks the same
//! parser and the same address classification, so an entry that admission accepts is one the
//! enforcement point can load, and there is one definition of "always denied".

use std::net::Ipv4Addr;

use acf_traffic::policy::{
    AddressClass, Allowlist, DestinationSpec, EntrySpec, Ipv4Net, PolicyError, PortRange as WirePortRange, classify,
};

use crate::{
    domain::{AllowDestination, AllowEntry},
    error::{AcfError, Result},
};

/// The entries in the form the guest-traffic role takes them.
pub fn to_specs(entries: &[AllowEntry]) -> Vec<EntrySpec> {
    entries
        .iter()
        .map(|e| EntrySpec {
            destination: match &e.destination {
                AllowDestination::Name(n) => DestinationSpec::Name(n.clone()),
                AllowDestination::Network(c) => DestinationSpec::Network(c.clone()),
            },
            ports: e.ports.iter().map(|p| WirePortRange { from: p.from, to: p.to }).collect(),
        })
        .collect()
}

/// Validate allowlist entries (AL-1, AL-6).
///
/// * a malformed entry, an empty port set, or a network that touches an always-denied range →
///   `INVALID_REQUEST` (no profile could ever permit it);
/// * a private range while the profile's `private_destinations` switch is off →
///   `SAFETY_CONTROL_DENIED`.
pub fn validate_allowlist(entries: &[AllowEntry], private_destinations: bool) -> Result<()> {
    if entries.is_empty() {
        return Err(AcfError::validation("an allowlist needs at least one entry; use network mode `none` for no connectivity"));
    }
    match Allowlist::new(&to_specs(entries), private_destinations, usize::MAX) {
        Ok(_) => Ok(()),
        Err(e) => {
            let (index, cause) = match e {
                PolicyError::Entry { index, source } => (Some(index), *source),
                other => (None, other),
            };
            let at = index.map(|i| format!("allowlist entry {i}: ")).unwrap_or_default();
            // The messages are the parser's own fixed texts: nothing caller-supplied is echoed.
            Err(match cause {
                PolicyError::PrivateNetworkNotEnabled => {
                    AcfError::denied(format!("{at}the safety profile does not grant capability `private_destinations`"))
                }
                other => AcfError::validation(format!("{at}{other}")),
            })
        }
    }
}

/// Whether the admitted entries name a private range (decided at admission by the profile; the
/// guest-traffic role is told, so it loads exactly what was admitted).
pub fn names_private_destination(entries: &[AllowEntry]) -> bool {
    matches!(Allowlist::new(&to_specs(entries), false, usize::MAX), Err(PolicyError::Entry { source, .. }) if *source == PolicyError::PrivateNetworkNotEnabled)
}

/// The isolated segment between a guest and the host side of its namespace (§20.2).
///
/// Every sandbox uses the *same* addresses. That is safe because each lives in its own network
/// namespace with no route in or out: the only path out is the guest-traffic role. It is also what
/// makes a restored snapshot work unchanged, since the guest's captured network configuration is
/// valid in every namespace. The segment is never routed, so it cannot collide with a real network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestSegment {
    /// Host side: the resolver and the relay listen here, inside the namespace.
    pub gateway: Ipv4Addr,
    pub guest: Ipv4Addr,
    pub prefix: u8,
    net: Ipv4Net,
}

impl GuestSegment {
    /// `cidr` must be a private /30: network, gateway, guest, broadcast.
    pub fn parse(cidr: &str) -> Result<Self> {
        let bad = |why: &str| AcfError::corrupt(format!("network.guest_segment: {why}"));
        let net = Ipv4Net::parse(cidr).map_err(|e| bad(&e.to_string()))?;
        let (addr, prefix) = cidr.split_once('/').ok_or_else(|| bad("expected `address/30`"))?;
        if prefix != "30" {
            return Err(bad("the segment must be a /30"));
        }
        let base = u32::from(addr.parse::<Ipv4Addr>().map_err(|_| bad("not an IPv4 address"))?);
        let (gateway, guest) = (Ipv4Addr::from(base + 1), Ipv4Addr::from(base + 2));
        if classify(gateway) != AddressClass::Private || classify(guest) != AddressClass::Private {
            return Err(bad("the segment must lie in a private range"));
        }
        Ok(Self { gateway, guest, prefix: 30, net })
    }

    pub fn netmask(&self) -> Ipv4Addr {
        Ipv4Addr::new(255, 255, 255, 252)
    }

    pub fn cidr(&self) -> String {
        self.net.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{domain::PortRange, error::FailureClass};

    fn entry(dest: AllowDestination, from: u16, to: u16) -> AllowEntry {
        AllowEntry { destination: dest, ports: vec![PortRange { from, to }] }
    }
    fn net(cidr: &str) -> AllowEntry {
        entry(AllowDestination::Network(cidr.into()), 443, 443)
    }
    fn class_of(e: AllowEntry, private: bool) -> Option<FailureClass> {
        validate_allowlist(&[e], private).err().map(|e| e.class)
    }

    #[test]
    fn well_formed_entries_are_accepted() {
        assert!(validate_allowlist(&[entry(AllowDestination::Name("pypi.org".into()), 443, 443), net("198.51.100.0/24")], false).is_ok());
    }

    #[test]
    fn malformed_entries_are_invalid_requests() {
        let bad = [
            entry(AllowDestination::Name("pypi.org".into()), 0, 10),
            entry(AllowDestination::Name("pypi.org".into()), 500, 400),
            entry(AllowDestination::Name("*.pypi.org".into()), 443, 443),
            entry(AllowDestination::Name("localhost".into()), 443, 443),
            entry(AllowDestination::Name("192.0.2.1".into()), 443, 443),
            entry(AllowDestination::Name("has space.example".into()), 443, 443),
            net("198.51.100.7/24"),
            net("198.51.100.0/33"),
            net("2001:db8::/32"),
            net("not-a-network"),
            AllowEntry { destination: AllowDestination::Name("pypi.org".into()), ports: vec![] },
        ];
        for e in bad {
            assert_eq!(class_of(e.clone(), true), Some(FailureClass::InvalidRequest), "{e:?}");
        }
        assert_eq!(validate_allowlist(&[], true).unwrap_err().class, FailureClass::InvalidRequest);
    }

    #[test]
    fn a_refusal_never_echoes_what_the_caller_sent() {
        let hostile = entry(AllowDestination::Name("evil\n\"; drop table.example".into()), 443, 443);
        let e = validate_allowlist(&[hostile], true).unwrap_err();
        assert!(!e.message.contains("drop table"), "{}", e.message);
    }

    #[test]
    fn always_denied_ranges_can_never_be_listed() {
        for cidr in [
            "127.0.0.0/8",
            "127.0.0.1/32",
            "169.254.169.254/32",
            "169.254.0.0/16",
            "224.0.0.0/4",
            "240.0.0.0/4",
            "255.255.255.255/32",
            "0.0.0.0/0",
            "0.0.0.0/8",
            "168.0.0.0/6",
            "128.0.0.0/1",
        ] {
            assert_eq!(class_of(net(cidr), true), Some(FailureClass::InvalidRequest), "{cidr}");
        }
    }

    #[test]
    fn private_ranges_need_the_profile_switch() {
        for cidr in ["10.0.0.0/8", "10.20.30.0/24", "172.16.0.0/12", "192.168.1.0/24", "100.64.0.0/10", "8.0.0.0/5"] {
            assert_eq!(class_of(net(cidr), false), Some(FailureClass::SafetyControlDenied), "{cidr}");
            assert_eq!(class_of(net(cidr), true), None, "{cidr}");
            assert!(names_private_destination(&[net(cidr)]), "{cidr}");
        }
        assert_eq!(class_of(net("198.51.100.0/24"), false), None);
        assert!(!names_private_destination(&[net("198.51.100.0/24"), entry(AllowDestination::Name("pypi.org".into()), 443, 443)]));
    }

    #[test]
    fn the_guest_segment_is_a_private_slash_30() {
        let s = GuestSegment::parse("10.201.0.0/30").unwrap();
        assert_eq!((s.gateway, s.guest, s.prefix), (Ipv4Addr::new(10, 201, 0, 1), Ipv4Addr::new(10, 201, 0, 2), 30));
        assert_eq!(s.netmask(), Ipv4Addr::new(255, 255, 255, 252));
        assert_eq!(s.cidr(), "10.201.0.0/30");
        for bad in ["10.201.0.0/24", "10.201.0.1/30", "198.51.100.0/30", "169.254.0.0/30", "not-a-net", "10.201.0.0"] {
            assert!(GuestSegment::parse(bad).is_err(), "{bad}");
        }
    }
}
