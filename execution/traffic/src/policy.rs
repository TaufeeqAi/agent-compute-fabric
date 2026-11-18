//! The allowlist model and the pure verdicts (execution-plane contract 1.2.0, AL-1 .. AL-6).
//!
//! Nothing here performs I/O, reads a clock or keeps hidden state: every decision is a function of its
//! arguments, so each row of the decision table is unit-tested below and the I/O loops in [`crate::resolver`]
//! and [`crate::relay`] cannot widen it.
//!
//! Invariants:
//! * an address in an always-denied class, a host address or another sandbox's network is denied before any
//!   entry is consulted (AL-6), both as a connection destination and as a resolver answer;
//! * whatever no entry matches is denied (AL-2); there is no default-allow path;
//! * a name entry only ever allows an address this sandbox was handed for that name and that has not expired
//!   (AL-4), which is what defeats DNS rebinding;
//! * every table is bounded (AL-1): entries, port ranges per entry, bound names, addresses per name.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Longest DNS name in presentation form, without the trailing dot.
pub const MAX_NAME_LEN: usize = 253;
/// Longest DNS label.
pub const MAX_LABEL_LEN: usize = 63;
/// Most port ranges one entry may carry.
pub const MAX_PORT_RANGES_PER_ENTRY: usize = 16;
/// Most unexpired addresses remembered per name; older ones give way to newer ones.
pub const MAX_ADDRS_PER_NAME: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid DNS name: {0}")]
    InvalidName(&'static str),
    #[error("invalid IPv4 network: {0}")]
    InvalidNetwork(&'static str),
    #[error("invalid port range {from}-{to}: ports are 1..=65535 and `from` must not exceed `to`")]
    InvalidPortRange { from: u16, to: u16 },
    #[error("an entry needs between 1 and {MAX_PORT_RANGES_PER_ENTRY} port ranges, got {0}")]
    PortRangeCount(usize),
    #[error("the network overlaps a range that is always denied")]
    AlwaysDeniedNetwork,
    #[error("the network overlaps a private range and private destinations are not enabled")]
    PrivateNetworkNotEnabled,
    #[error("{count} entries exceed the limit of {max}")]
    TooManyEntries { count: usize, max: usize },
    #[error("entry {index}: {source}")]
    Entry { index: usize, source: Box<PolicyError> },
}

/// An exact DNS host name: lower-case ASCII, no trailing dot, at least two letter-digit-hyphen labels of
/// 1..=63 bytes, at most 253 bytes in total, and a last label that starts with a letter.
///
/// The last rule means no IPv4 literal, in any spelling a C library would accept (decimal, octal, hexadecimal),
/// is a `DnsName`; a guest cannot smuggle an address through a place that expects a name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DnsName(String);

impl DnsName {
    /// Validates and normalises to lower case. Never trims: a trailing dot is an (empty) label and is refused.
    pub fn parse(s: &str) -> Result<Self, PolicyError> {
        if s.is_empty() || s.len() > MAX_NAME_LEN {
            return Err(PolicyError::InvalidName("the length must be 1..=253 bytes"));
        }
        let mut labels = 0usize;
        let mut last = "";
        for label in s.split('.') {
            check_label(label)?;
            labels += 1;
            last = label;
        }
        if labels < 2 {
            return Err(PolicyError::InvalidName("at least two labels are required"));
        }
        if !last.starts_with(|c: char| c.is_ascii_alphabetic()) {
            return Err(PolicyError::InvalidName("the last label must start with a letter"));
        }
        Ok(Self(s.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn check_label(label: &str) -> Result<(), PolicyError> {
    if label.is_empty() || label.len() > MAX_LABEL_LEN {
        return Err(PolicyError::InvalidName("every label must be 1..=63 bytes"));
    }
    if !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(PolicyError::InvalidName("labels hold letters, digits and hyphens only"));
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Err(PolicyError::InvalidName("a label must not start or end with a hyphen"));
    }
    Ok(())
}

/// An IPv4 network in CIDR form whose host bits are zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Net {
    addr: u32,
    prefix: u8,
}

impl Ipv4Net {
    /// Parses `a.b.c.d/len`. The prefix length is mandatory and the host bits must be zero.
    pub fn parse(s: &str) -> Result<Self, PolicyError> {
        let (addr, prefix) = s.split_once('/').ok_or(PolicyError::InvalidNetwork("expected `address/prefix`"))?;
        let addr: Ipv4Addr = addr.parse().map_err(|_| PolicyError::InvalidNetwork("the address is not a dotted-quad IPv4 address"))?;
        let canonical = !prefix.is_empty() && prefix.bytes().all(|b| b.is_ascii_digit()) && (prefix.len() == 1 || !prefix.starts_with('0'));
        let prefix = prefix.parse::<u8>().ok().filter(|p| canonical && *p <= 32);
        let prefix = prefix.ok_or(PolicyError::InvalidNetwork("the prefix length must be 0..=32"))?;
        if u32::from(addr) & !mask(prefix) != 0 {
            return Err(PolicyError::InvalidNetwork("host bits must be zero"));
        }
        Ok(Self { addr: u32::from(addr), prefix })
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & mask(self.prefix) == self.addr
    }

    /// Two CIDR blocks share an address exactly when the shorter prefix covers the other block.
    pub fn overlaps(&self, other: &Self) -> bool {
        let common = mask(self.prefix.min(other.prefix));
        self.addr & common == other.addr & common
    }
}

impl fmt::Display for Ipv4Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", Ipv4Addr::from(self.addr), self.prefix)
    }
}

const fn mask(prefix: u8) -> u32 {
    if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) }
}

const fn net(a: u8, b: u8, c: u8, d: u8, prefix: u8) -> Ipv4Net {
    Ipv4Net { addr: u32::from_be_bytes([a, b, c, d]), prefix }
}

/// What kind of destination an address is. Only `Public` and `Private` can ever be allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressClass {
    Public,
    Private,
    Loopback,
    LinkLocal,
    Multicast,
    Broadcast,
    Unspecified,
    Reserved,
}

/// AL-6: ranges that are denied whatever the entries say. One table drives both [`classify`] and entry validation.
const ALWAYS_DENIED: [(Ipv4Net, AddressClass); 6] = [
    (net(0, 0, 0, 0, 8), AddressClass::Unspecified),
    (net(127, 0, 0, 0, 8), AddressClass::Loopback),
    (net(169, 254, 0, 0, 16), AddressClass::LinkLocal),
    (net(192, 0, 0, 0, 24), AddressClass::Reserved),
    (net(224, 0, 0, 0, 4), AddressClass::Multicast),
    (net(240, 0, 0, 0, 4), AddressClass::Reserved),
];

/// AL-6: private ranges (RFC 1918 and the RFC 6598 shared address space).
const PRIVATE: [Ipv4Net; 4] = [net(10, 0, 0, 0, 8), net(100, 64, 0, 0, 10), net(172, 16, 0, 0, 12), net(192, 168, 0, 0, 16)];

pub fn classify(ip: Ipv4Addr) -> AddressClass {
    if ip == Ipv4Addr::BROADCAST {
        return AddressClass::Broadcast;
    }
    if let Some((_, class)) = ALWAYS_DENIED.iter().find(|(range, _)| range.contains(ip)) {
        return *class;
    }
    if PRIVATE.iter().any(|range| range.contains(ip)) { AddressClass::Private } else { AddressClass::Public }
}

/// An inclusive port range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortRange {
    pub from: u16,
    pub to: u16,
}

impl PortRange {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.from == 0 || self.from > self.to {
            return Err(PolicyError::InvalidPortRange { from: self.from, to: self.to });
        }
        Ok(())
    }

    pub fn contains(&self, port: u16) -> bool {
        (self.from..=self.to).contains(&port)
    }
}

/// Wire form: `{"name":"example.com"}` or `{"network":"198.51.100.0/24"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum DestinationSpec {
    Name(String),
    Network(String),
}

/// One allowlist entry as configured: a destination and a non-empty set of ports (AL-1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntrySpec {
    pub destination: DestinationSpec,
    pub ports: Vec<PortRange>,
}

/// The validated allowlist of one sandbox. Entries naming the same destination add up.
#[derive(Debug, Clone)]
pub struct Allowlist {
    names: Vec<(DnsName, Vec<PortRange>)>,
    networks: Vec<(Ipv4Net, Vec<PortRange>)>,
    private_destinations: bool,
}

impl Allowlist {
    /// Validates every entry (AL-1): at most `max_entries` entries, each with a valid name or network and
    /// 1..=[`MAX_PORT_RANGES_PER_ENTRY`] valid port ranges. A network that overlaps an always-denied range is
    /// refused; one that overlaps a private range is refused unless `private_destinations` (AL-6).
    pub fn new(entries: &[EntrySpec], private_destinations: bool, max_entries: usize) -> Result<Self, PolicyError> {
        if entries.len() > max_entries {
            return Err(PolicyError::TooManyEntries { count: entries.len(), max: max_entries });
        }
        let mut allow = Self { names: Vec::new(), networks: Vec::new(), private_destinations };
        for (index, entry) in entries.iter().enumerate() {
            allow.add(entry).map_err(|source| PolicyError::Entry { index, source: Box::new(source) })?;
        }
        Ok(allow)
    }

    fn add(&mut self, entry: &EntrySpec) -> Result<(), PolicyError> {
        if entry.ports.is_empty() || entry.ports.len() > MAX_PORT_RANGES_PER_ENTRY {
            return Err(PolicyError::PortRangeCount(entry.ports.len()));
        }
        entry.ports.iter().try_for_each(PortRange::validate)?;
        match &entry.destination {
            DestinationSpec::Name(name) => self.names.push((DnsName::parse(name)?, entry.ports.clone())),
            DestinationSpec::Network(network) => {
                let network = Ipv4Net::parse(network)?;
                if network.contains(Ipv4Addr::BROADCAST) || ALWAYS_DENIED.iter().any(|(range, _)| range.overlaps(&network)) {
                    return Err(PolicyError::AlwaysDeniedNetwork);
                }
                if !self.private_destinations && PRIVATE.iter().any(|range| range.overlaps(&network)) {
                    return Err(PolicyError::PrivateNetworkNotEnabled);
                }
                self.networks.push((network, entry.ports.clone()));
            }
        }
        Ok(())
    }

    /// The names the resolver may answer for (AL-3).
    pub fn names(&self) -> impl Iterator<Item = &DnsName> {
        self.names.iter().map(|(name, _)| name)
    }

    fn network_contains(&self, ip: Ipv4Addr) -> bool {
        self.networks.iter().any(|(network, _)| network.contains(ip))
    }

    fn network_allows(&self, dst: SocketAddrV4) -> bool {
        self.networks.iter().any(|(network, ports)| network.contains(*dst.ip()) && lists(ports, dst.port()))
    }

    fn name_allows(&self, name: &DnsName, port: u16) -> bool {
        self.names.iter().any(|(entry, ports)| entry == name && lists(ports, port))
    }

    fn any_name_allows(&self, port: u16) -> bool {
        self.names.iter().any(|(_, ports)| lists(ports, port))
    }
}

fn lists(ports: &[PortRange], port: u16) -> bool {
    ports.iter().any(|range| range.contains(port))
}

/// AL-6 "the host's own addresses, other sandboxes": destinations that are denied whatever the entries say.
#[derive(Debug, Clone, Default)]
pub struct DenyContext {
    pub host_addresses: Vec<Ipv4Addr>,
    pub sandbox_networks: Vec<Ipv4Net>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowBasis {
    /// AL-5: a network entry lists the address and the port.
    NetworkEntry,
    /// AL-4: a name entry lists the port, the TLS server name equals the entry and the address is bound to it.
    NameEntry,
}

/// Why a connection is not relayed. A closed set with stable labels: the label is a metric key, so it never
/// carries guest-supplied data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    Loopback,
    LinkLocal,
    Multicast,
    Broadcast,
    Unspecified,
    Reserved,
    HostAddress,
    SandboxNetwork,
    /// A private address that the profile does not enable or that no network entry names.
    PrivateDestination,
    /// No entry can allow this address and port, whatever server name is presented (AL-2).
    NoMatchingEntry,
    /// Only a name entry could allow this, and no usable TLS server name was presented.
    NoServerName,
    NameNotListed,
    PortNotListed,
    /// The address is not one the resolver handed to this sandbox for the name within the binding lifetime.
    AddressNotBound,
    /// Reported by the relay, never by [`connect_verdict`]: the original destination could not be read.
    OriginalDestinationUnavailable,
    /// Reported by the relay, never by [`connect_verdict`]: the allowed destination did not accept the connection.
    UpstreamConnectFailed,
    /// Reported by the relay, never by [`connect_verdict`]: the allowed destination did not answer in time.
    UpstreamConnectTimedOut,
}

impl DenyReason {
    pub const ALL: [Self; 17] = [
        Self::Loopback,
        Self::LinkLocal,
        Self::Multicast,
        Self::Broadcast,
        Self::Unspecified,
        Self::Reserved,
        Self::HostAddress,
        Self::SandboxNetwork,
        Self::PrivateDestination,
        Self::NoMatchingEntry,
        Self::NoServerName,
        Self::NameNotListed,
        Self::PortNotListed,
        Self::AddressNotBound,
        Self::OriginalDestinationUnavailable,
        Self::UpstreamConnectFailed,
        Self::UpstreamConnectTimedOut,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::LinkLocal => "link_local",
            Self::Multicast => "multicast",
            Self::Broadcast => "broadcast",
            Self::Unspecified => "unspecified",
            Self::Reserved => "reserved",
            Self::HostAddress => "host_address",
            Self::SandboxNetwork => "sandbox_network",
            Self::PrivateDestination => "private_destination",
            Self::NoMatchingEntry => "no_matching_entry",
            Self::NoServerName => "no_server_name",
            Self::NameNotListed => "name_not_listed",
            Self::PortNotListed => "port_not_listed",
            Self::AddressNotBound => "address_not_bound",
            Self::OriginalDestinationUnavailable => "original_destination_unavailable",
            Self::UpstreamConnectFailed => "upstream_connect_failed",
            Self::UpstreamConnectTimedOut => "upstream_connect_timed_out",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow(AllowBasis),
    Deny(DenyReason),
}

/// AL-6, before any entry is consulted: why `ip` may not be a destination at all, if it may not.
fn address_denied(allow: &Allowlist, deny: &DenyContext, ip: Ipv4Addr) -> Option<DenyReason> {
    let class = classify(ip);
    let always = match class {
        AddressClass::Loopback => Some(DenyReason::Loopback),
        AddressClass::LinkLocal => Some(DenyReason::LinkLocal),
        AddressClass::Multicast => Some(DenyReason::Multicast),
        AddressClass::Broadcast => Some(DenyReason::Broadcast),
        AddressClass::Unspecified => Some(DenyReason::Unspecified),
        AddressClass::Reserved => Some(DenyReason::Reserved),
        AddressClass::Public | AddressClass::Private => None,
    };
    if always.is_some() {
        return always;
    }
    if deny.host_addresses.contains(&ip) {
        return Some(DenyReason::HostAddress);
    }
    if deny.sandbox_networks.iter().any(|network| network.contains(ip)) {
        return Some(DenyReason::SandboxNetwork);
    }
    let private_allowed = allow.private_destinations && allow.network_contains(ip);
    (class == AddressClass::Private && !private_allowed).then_some(DenyReason::PrivateDestination)
}

/// Does this destination need the TLS server name to be decided? False when a network entry already allows it
/// and when it is denied whatever the name, so the relay only waits for a ClientHello when one can matter.
pub fn needs_server_name(allow: &Allowlist, deny: &DenyContext, dst: SocketAddrV4) -> bool {
    address_denied(allow, deny, *dst.ip()).is_none() && !allow.network_allows(dst) && allow.any_name_allows(dst.port())
}

/// The connection verdict (AL-2, AL-4, AL-5, AL-6). `server_name` is `None` when no ClientHello or no server
/// name was presented. The order is fixed: always-denied destinations, the private rule, network entries, then
/// name entries; whatever falls through is denied.
pub fn connect_verdict(
    allow: &Allowlist,
    deny: &DenyContext,
    dst: SocketAddrV4,
    server_name: Option<&DnsName>,
    bindings: &Bindings,
    now: Instant,
) -> Verdict {
    if let Some(reason) = address_denied(allow, deny, *dst.ip()) {
        return Verdict::Deny(reason);
    }
    if allow.network_allows(dst) {
        return Verdict::Allow(AllowBasis::NetworkEntry);
    }
    let Some(name) = server_name else {
        let reason = if allow.any_name_allows(dst.port()) { DenyReason::NoServerName } else { DenyReason::NoMatchingEntry };
        return Verdict::Deny(reason);
    };
    if !may_resolve(allow, name) {
        return Verdict::Deny(DenyReason::NameNotListed);
    }
    if !allow.name_allows(name, dst.port()) {
        return Verdict::Deny(DenyReason::PortNotListed);
    }
    if !bindings.is_bound(name, *dst.ip(), now) {
        return Verdict::Deny(DenyReason::AddressNotBound);
    }
    Verdict::Allow(AllowBasis::NameEntry)
}

/// AL-3: may the resolver answer for this name at all?
pub fn may_resolve(allow: &Allowlist, name: &DnsName) -> bool {
    allow.names().any(|entry| entry == name)
}

/// Addresses the resolver may hand to the guest: every always-denied address and every private address that no
/// network entry names with private destinations enabled is dropped (AL-6), so an upstream answer such as
/// 127.0.0.1 or 169.254.169.254 never reaches the guest. Order is kept, duplicates are removed, and at most
/// [`MAX_ADDRS_PER_NAME`] addresses are returned, however long the upstream answer is.
pub fn filter_answers(allow: &Allowlist, deny: &DenyContext, addrs: &[Ipv4Addr]) -> Vec<Ipv4Addr> {
    let mut kept: Vec<Ipv4Addr> = Vec::new();
    for addr in addrs {
        if kept.len() == MAX_ADDRS_PER_NAME {
            break;
        }
        if address_denied(allow, deny, *addr).is_none() && !kept.contains(addr) {
            kept.push(*addr);
        }
    }
    kept
}

/// The (name, address, expiry) triples the resolver handed to THIS sandbox (AL-4).
///
/// Bounded: at most `capacity` names and [`MAX_ADDRS_PER_NAME`] addresses per name. When a bound is reached the
/// binding that expires soonest gives way, which can only turn a later verdict into a denial.
#[derive(Debug)]
pub struct Bindings {
    capacity: usize,
    names: BTreeMap<DnsName, Vec<Binding>>,
}

#[derive(Debug, Clone, Copy)]
struct Binding {
    addr: Ipv4Addr,
    expires: Instant,
}

impl Bindings {
    pub fn new(capacity: usize) -> Self {
        Self { capacity, names: BTreeMap::new() }
    }

    /// Binds `addrs` to `name` until `now + ttl`. Expired bindings are dropped first.
    pub fn record(&mut self, name: &DnsName, addrs: &[Ipv4Addr], now: Instant, ttl: Duration) {
        self.drop_expired(now);
        let Some(expires) = now.checked_add(ttl) else { return };
        if self.capacity == 0 || addrs.is_empty() || ttl.is_zero() {
            return;
        }
        if !self.names.contains_key(name) && self.names.len() >= self.capacity {
            self.evict_soonest_name();
        }
        let slots = self.names.entry(name.clone()).or_default();
        for addr in addrs.iter().take(MAX_ADDRS_PER_NAME) {
            if let Some(existing) = slots.iter_mut().find(|slot| slot.addr == *addr) {
                existing.expires = existing.expires.max(expires);
                continue;
            }
            let soonest = slots.iter().enumerate().min_by_key(|(_, slot)| slot.expires).map(|(index, _)| index);
            if slots.len() >= MAX_ADDRS_PER_NAME
                && let Some(soonest) = soonest
            {
                slots.swap_remove(soonest);
            }
            slots.push(Binding { addr: *addr, expires });
        }
    }

    pub fn is_bound(&self, name: &DnsName, addr: Ipv4Addr, now: Instant) -> bool {
        self.names.get(name).is_some_and(|slots| slots.iter().any(|slot| slot.addr == addr && slot.expires > now))
    }

    /// Number of names that currently hold a binding.
    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    fn drop_expired(&mut self, now: Instant) {
        self.names.retain(|_, slots| {
            slots.retain(|slot| slot.expires > now);
            !slots.is_empty()
        });
    }

    fn evict_soonest_name(&mut self) {
        let soonest = self.names.iter().min_by_key(|(_, slots)| slots.iter().map(|slot| slot.expires).max());
        if let Some(name) = soonest.map(|(name, _)| name.clone()) {
            self.names.remove(&name);
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const TTL: Duration = Duration::from_secs(30);

    fn name(s: &str) -> DnsName {
        DnsName::parse(s).unwrap()
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn ports(from: u16, to: u16) -> Vec<PortRange> {
        vec![PortRange { from, to }]
    }

    fn name_entry(n: &str, from: u16, to: u16) -> EntrySpec {
        EntrySpec { destination: DestinationSpec::Name(n.into()), ports: ports(from, to) }
    }

    fn net_entry(n: &str, from: u16, to: u16) -> EntrySpec {
        EntrySpec { destination: DestinationSpec::Network(n.into()), ports: ports(from, to) }
    }

    fn entry_error(entries: &[EntrySpec], private: bool) -> PolicyError {
        match Allowlist::new(entries, private, 8).unwrap_err() {
            PolicyError::Entry { index: 0, source } => *source,
            other => panic!("expected an entry error, got {other:?}"),
        }
    }

    #[test]
    fn dns_name_accepts_and_normalises() {
        assert_eq!(name("Example.COM").as_str(), "example.com");
        assert_eq!(name("a-b.c0.xn--p1ai").to_string(), "a-b.c0.xn--p1ai");
        let longest = format!("{0}.{0}.{0}.{1}.com", "a".repeat(63), "b".repeat(57));
        assert_eq!(longest.len(), MAX_NAME_LEN);
        assert_eq!(name(&longest).as_str(), longest);
    }

    #[test]
    fn dns_name_rejects_everything_else() {
        let too_long = format!("{0}.{0}.{0}.{1}.com", "a".repeat(63), "b".repeat(58));
        let long_label = format!("{}.com", "a".repeat(64));
        let rejected = "localhost example.com. .example.com a..com exa_mple.com -a.com a-.com a.-com bücher.example *.example.com
                        example.com:443 198.51.100.10 0x7f.1 1.0x7f example.123 example.1a";
        for candidate in rejected.split_whitespace().chain(["", "exa mple.com", &too_long, &long_label]) {
            assert!(matches!(DnsName::parse(candidate), Err(PolicyError::InvalidName(_))), "{candidate:?} must be rejected");
        }
    }

    #[test]
    fn ipv4_net_parse_contains_and_overlaps() {
        let network = Ipv4Net::parse("198.51.100.0/24").unwrap();
        assert!(network.contains(ip("198.51.100.0")) && network.contains(ip("198.51.100.255")));
        assert!(!network.contains(ip("198.51.101.0")) && !network.contains(ip("198.51.99.255")));
        assert_eq!(network.to_string(), "198.51.100.0/24");
        let host = Ipv4Net::parse("203.0.113.7/32").unwrap();
        assert!(host.contains(ip("203.0.113.7")) && !host.contains(ip("203.0.113.6")));
        let all = Ipv4Net::parse("0.0.0.0/0").unwrap();
        assert!(all.contains(ip("255.255.255.255")) && all.overlaps(&network) && network.overlaps(&all));
        assert!(network.overlaps(&Ipv4Net::parse("198.51.100.128/25").unwrap()));
        assert!(!network.overlaps(&host));
    }

    #[test]
    fn ipv4_net_rejects_malformed_input() {
        let rejected = "198.51.100.0 198.51.100.0/ 198.51.100.0/33 198.51.100.0/024 198.51.100.0/+24 198.51.100.1/24 198.51.100/24
                        198.051.100.0/24 0x0a.0.0.0/8 ::1/128 example.com/24 /24 198.51.100.0/24/1";
        for candidate in rejected.split_whitespace().chain(["", "198.51.100.0/2 4"]) {
            assert!(matches!(Ipv4Net::parse(candidate), Err(PolicyError::InvalidNetwork(_))), "{candidate:?} must be rejected");
        }
    }

    #[test]
    fn port_range_validation_and_containment() {
        assert!(PortRange { from: 1, to: 65535 }.validate().is_ok());
        assert!(PortRange { from: 443, to: 443 }.validate().is_ok());
        assert_eq!(PortRange { from: 0, to: 10 }.validate(), Err(PolicyError::InvalidPortRange { from: 0, to: 10 }));
        assert_eq!(PortRange { from: 11, to: 10 }.validate(), Err(PolicyError::InvalidPortRange { from: 11, to: 10 }));
        let range = PortRange { from: 8000, to: 8010 };
        assert!(range.contains(8000) && range.contains(8010) && !range.contains(7999) && !range.contains(8011));
    }

    /// The whole IPv4 space as consecutive ranges: every address has exactly one class, checked at both edges.
    #[test]
    fn classify_partitions_the_address_space() {
        use AddressClass::*;
        let ranges = [
            ("0.0.0.0", "0.255.255.255", Unspecified),
            ("1.0.0.0", "9.255.255.255", Public),
            ("10.0.0.0", "10.255.255.255", Private),
            ("11.0.0.0", "100.63.255.255", Public),
            ("100.64.0.0", "100.127.255.255", Private),
            ("100.128.0.0", "126.255.255.255", Public),
            ("127.0.0.0", "127.255.255.255", Loopback),
            ("128.0.0.0", "169.253.255.255", Public),
            ("169.254.0.0", "169.254.255.255", LinkLocal),
            ("169.255.0.0", "172.15.255.255", Public),
            ("172.16.0.0", "172.31.255.255", Private),
            ("172.32.0.0", "191.255.255.255", Public),
            ("192.0.0.0", "192.0.0.255", Reserved),
            ("192.0.1.0", "192.167.255.255", Public),
            ("192.168.0.0", "192.168.255.255", Private),
            ("192.169.0.0", "223.255.255.255", Public),
            ("224.0.0.0", "239.255.255.255", Multicast),
            ("240.0.0.0", "255.255.255.254", Reserved),
            ("255.255.255.255", "255.255.255.255", Broadcast),
        ];
        let mut next = 0u64;
        for (first, last, class) in ranges {
            let (first, last) = (ip(first), ip(last));
            assert_eq!(u64::from(u32::from(first)), next, "the ranges are consecutive at {first}");
            let middle = Ipv4Addr::from(u32::from(first) + (u32::from(last) - u32::from(first)) / 2);
            assert_eq!([classify(first), classify(middle), classify(last)], [class; 3], "{first}..={last}");
            next = u64::from(u32::from(last)) + 1;
        }
        assert_eq!(next, 1 << 32, "the ranges cover the whole space");
        // The documentation and benchmark networks are ordinary public addresses; the metadata address is not.
        assert_eq!(["192.0.2.1", "198.18.0.1", "198.51.100.10", "203.0.113.1"].map(|a| classify(ip(a))), [Public; 4]);
        assert_eq!(classify(ip("169.254.169.254")), LinkLocal);
    }

    #[test]
    fn allowlist_validation_rows() {
        let allow = Allowlist::new(&[name_entry("Example.com", 443, 443), net_entry("198.51.100.0/24", 1, 1024)], false, 2).unwrap();
        assert_eq!(allow.names().map(DnsName::as_str).collect::<Vec<_>>(), ["example.com"]);
        assert!(Allowlist::new(&[], false, 0).is_ok());

        let three = [name_entry("a.example", 1, 1), name_entry("b.example", 1, 1), name_entry("c.example", 1, 1)];
        assert_eq!(Allowlist::new(&three, false, 2).unwrap_err(), PolicyError::TooManyEntries { count: 3, max: 2 });

        let no_ports = EntrySpec { destination: DestinationSpec::Name("a.example".into()), ports: vec![] };
        assert_eq!(entry_error(&[no_ports], false), PolicyError::PortRangeCount(0));
        let many = vec![PortRange { from: 1, to: 1 }; MAX_PORT_RANGES_PER_ENTRY + 1];
        let many_ports = EntrySpec { destination: DestinationSpec::Name("a.example".into()), ports: many };
        assert_eq!(entry_error(&[many_ports], false), PolicyError::PortRangeCount(MAX_PORT_RANGES_PER_ENTRY + 1));
        assert_eq!(entry_error(&[name_entry("a.example", 0, 5)], false), PolicyError::InvalidPortRange { from: 0, to: 5 });
        assert!(matches!(entry_error(&[name_entry("localhost", 1, 1)], false), PolicyError::InvalidName(_)));
        assert!(matches!(entry_error(&[net_entry("198.51.100.1/24", 1, 1)], false), PolicyError::InvalidNetwork(_)));

        let second_is_bad = [name_entry("a.example", 1, 1), name_entry("b", 1, 1)];
        assert!(matches!(Allowlist::new(&second_is_bad, false, 8), Err(PolicyError::Entry { index: 1, .. })));
    }

    #[test]
    fn network_entries_may_not_name_denied_ranges() {
        let always_denied = "0.0.0.0/0 0.0.0.0/8 127.0.0.0/8 127.0.0.1/32 169.254.169.254/32 169.254.0.0/16 192.0.0.0/24 192.0.0.0/16
                             224.0.0.0/4 239.1.2.3/32 240.0.0.0/4 255.255.255.255/32 128.0.0.0/1";
        for network in always_denied.split_whitespace() {
            for private in [false, true] {
                assert_eq!(entry_error(&[net_entry(network, 1, 65535)], private), PolicyError::AlwaysDeniedNetwork, "{network}");
            }
        }
        for network in ["10.0.0.0/8", "10.1.2.3/32", "172.16.0.0/12", "192.168.1.0/24", "100.64.0.0/10", "8.0.0.0/6"] {
            assert_eq!(entry_error(&[net_entry(network, 1, 65535)], false), PolicyError::PrivateNetworkNotEnabled, "{network}");
            assert!(Allowlist::new(&[net_entry(network, 1, 65535)], true, 1).is_ok(), "{network}");
        }
    }

    #[test]
    fn destination_spec_wire_form() {
        let entry: EntrySpec = serde_json::from_str(r#"{"destination":{"name":"example.com"},"ports":[{"from":443,"to":443}]}"#).unwrap();
        assert_eq!(entry, name_entry("example.com", 443, 443));
        let entry: EntrySpec =
            serde_json::from_str(r#"{"destination":{"network":"198.51.100.0/24"},"ports":[{"from":1,"to":2}]}"#).unwrap();
        assert_eq!(entry, net_entry("198.51.100.0/24", 1, 2));
        assert_eq!(serde_json::to_string(&entry.destination).unwrap(), r#"{"network":"198.51.100.0/24"}"#);
        for bad in [
            r#"{"destination":{"host":"example.com"},"ports":[]}"#,
            r#"{"destination":{"name":"a.example","network":"198.51.100.0/24"},"ports":[]}"#,
            r#"{"destination":{"name":"a.example"},"ports":[{"from":1,"to":2,"step":1}]}"#,
            r#"{"destination":{"name":"a.example"},"ports":[],"extra":true}"#,
            r#"{"destination":{"name":"a.example"},"ports":[{"from":1,"to":70000}]}"#,
        ] {
            assert!(serde_json::from_str::<EntrySpec>(bad).is_err(), "{bad}");
        }
    }

    /// One fixture for the verdict table: two name entries, two network entries (one private), a host address
    /// and a neighbouring sandbox network that the public network entry happens to cover.
    struct Fixture {
        allow: Allowlist,
        deny: DenyContext,
        bindings: Bindings,
        now: Instant,
    }

    fn fixture() -> Fixture {
        let entries = [
            name_entry("api.example.com", 443, 443),
            name_entry("git.example.com", 22, 22),
            name_entry("api.example.com", 8443, 8443),
            net_entry("198.51.100.0/24", 5432, 5433),
            net_entry("10.20.0.0/16", 80, 80),
        ];
        let allow = Allowlist::new(&entries, true, 8).unwrap();
        let deny =
            DenyContext { host_addresses: vec![ip("198.51.100.1")], sandbox_networks: vec![Ipv4Net::parse("198.51.100.128/25").unwrap()] };
        let now = Instant::now();
        let mut bindings = Bindings::new(8);
        bindings.record(&name("api.example.com"), &[ip("203.0.113.10"), ip("10.20.0.9")], now, TTL);
        bindings.record(&name("git.example.com"), &[ip("203.0.113.20")], now, TTL);
        Fixture { allow, deny, bindings, now }
    }

    impl Fixture {
        fn verdict(&self, dst: &str, server_name: Option<&str>) -> Verdict {
            let server_name = server_name.map(name);
            connect_verdict(&self.allow, &self.deny, dst.parse().unwrap(), server_name.as_ref(), &self.bindings, self.now)
        }

        fn needs_name(&self, dst: &str) -> bool {
            needs_server_name(&self.allow, &self.deny, dst.parse().unwrap())
        }
    }

    #[test]
    fn connect_verdict_rows() {
        use DenyReason::*;
        let f = fixture();
        let api = Some("api.example.com");
        let allow_name = Verdict::Allow(AllowBasis::NameEntry);
        let allow_network = Verdict::Allow(AllowBasis::NetworkEntry);
        // (destination, server name, verdict, needs_server_name)
        let rows = [
            // (1) AL-6 comes first, even with a listed name, a bound-looking address or a covering network entry.
            ("127.0.0.1:443", api, Verdict::Deny(Loopback), false),
            ("169.254.169.254:443", api, Verdict::Deny(LinkLocal), false),
            ("224.0.0.1:443", api, Verdict::Deny(Multicast), false),
            ("255.255.255.255:443", api, Verdict::Deny(Broadcast), false),
            ("0.0.0.0:443", api, Verdict::Deny(Unspecified), false),
            ("240.0.0.1:443", api, Verdict::Deny(Reserved), false),
            ("192.0.0.8:443", api, Verdict::Deny(Reserved), false),
            ("198.51.100.1:5432", None, Verdict::Deny(HostAddress), false),
            ("198.51.100.200:5432", None, Verdict::Deny(SandboxNetwork), false),
            // (2) private addresses need the profile switch and a network entry that names them.
            ("10.99.0.1:80", None, Verdict::Deny(PrivateDestination), false),
            ("192.168.1.1:443", api, Verdict::Deny(PrivateDestination), false),
            ("100.64.0.1:443", api, Verdict::Deny(PrivateDestination), false),
            // (3) network entries: plain TCP, no server name needed (AL-5).
            ("198.51.100.10:5432", None, allow_network, false),
            ("198.51.100.10:5433", Some("other.example.net"), allow_network, false),
            ("10.20.0.9:80", None, allow_network, false),
            // (4) name entries (AL-4).
            ("203.0.113.10:443", api, allow_name, true),
            ("203.0.113.10:8443", api, allow_name, true),
            ("203.0.113.20:22", Some("git.example.com"), allow_name, true),
            ("10.20.0.9:443", api, allow_name, true),
            ("203.0.113.10:443", None, Verdict::Deny(NoServerName), true),
            ("203.0.113.10:443", Some("evil.example.net"), Verdict::Deny(NameNotListed), true),
            ("203.0.113.10:22", api, Verdict::Deny(PortNotListed), true),
            ("203.0.113.10:443", Some("git.example.com"), Verdict::Deny(PortNotListed), true),
            ("203.0.113.99:443", api, Verdict::Deny(AddressNotBound), true),
            ("203.0.113.20:443", api, Verdict::Deny(AddressNotBound), true),
            ("198.51.100.10:443", api, Verdict::Deny(AddressNotBound), true),
            // AL-2: nothing matches, whatever the name.
            ("203.0.113.10:80", api, Verdict::Deny(PortNotListed), false),
            ("203.0.113.10:80", None, Verdict::Deny(NoMatchingEntry), false),
            ("198.51.100.10:5434", None, Verdict::Deny(NoMatchingEntry), false),
            ("203.0.113.10:0", None, Verdict::Deny(NoMatchingEntry), false),
        ];
        for (dst, server_name, verdict, needs_name) in rows {
            assert_eq!(f.verdict(dst, server_name), verdict, "{dst} {server_name:?}");
            assert_eq!(f.needs_name(dst), needs_name, "needs_server_name {dst}");
        }
    }

    #[test]
    fn private_destinations_switch_off_denies_private_addresses() {
        let allow = Allowlist::new(&[name_entry("api.example.com", 443, 443)], false, 8).unwrap();
        let deny = DenyContext::default();
        let now = Instant::now();
        let mut bindings = Bindings::new(4);
        bindings.record(&name("api.example.com"), &[ip("10.20.0.9")], now, TTL);
        let verdict = connect_verdict(&allow, &deny, "10.20.0.9:443".parse().unwrap(), Some(&name("api.example.com")), &bindings, now);
        assert_eq!(verdict, Verdict::Deny(DenyReason::PrivateDestination));
    }

    #[test]
    fn expired_binding_is_denied() {
        let mut f = fixture();
        let api = Some("api.example.com");
        f.now += TTL - Duration::from_millis(1);
        assert_eq!(f.verdict("203.0.113.10:443", api), Verdict::Allow(AllowBasis::NameEntry));
        f.now += Duration::from_millis(1);
        assert_eq!(f.verdict("203.0.113.10:443", api), Verdict::Deny(DenyReason::AddressNotBound));
        // A network entry does not depend on bindings.
        assert_eq!(f.verdict("198.51.100.10:5432", None), Verdict::Allow(AllowBasis::NetworkEntry));
    }

    #[test]
    fn may_resolve_is_exact_match_only() {
        let f = fixture();
        assert!(may_resolve(&f.allow, &name("api.example.com")) && may_resolve(&f.allow, &name("API.Example.Com")));
        for other in ["example.com", "www.api.example.com", "api.example.com.evil.net", "git.example.net"] {
            assert!(!may_resolve(&f.allow, &name(other)), "{other}");
        }
    }

    #[test]
    fn filter_answers_drops_denied_addresses() {
        let f = fixture();
        let upstream = "203.0.113.10 127.0.0.1 169.254.169.254 10.0.0.5 10.20.0.9 198.51.100.1 198.51.100.200 0.0.0.0 224.0.0.251
                        255.255.255.255 192.0.0.1 203.0.113.10 198.51.100.10";
        let upstream: Vec<Ipv4Addr> = upstream.split_whitespace().map(ip).collect();
        assert_eq!(filter_answers(&f.allow, &f.deny, &upstream), [ip("203.0.113.10"), ip("10.20.0.9"), ip("198.51.100.10")]);
        let strict = Allowlist::new(&[name_entry("api.example.com", 443, 443)], false, 8).unwrap();
        assert_eq!(filter_answers(&strict, &f.deny, &upstream), [ip("203.0.113.10"), ip("198.51.100.10")]);
        assert!(filter_answers(&strict, &f.deny, &[ip("127.0.0.1"), ip("10.0.0.5")]).is_empty());
        // A huge upstream answer is cut to the per-name bound; denied addresses do not use up the bound.
        let loopback = (0..=255).map(|n| Ipv4Addr::new(127, 0, 0, n));
        let public = (0..=255).map(|n| Ipv4Addr::new(203, 0, 114, n));
        let huge: Vec<Ipv4Addr> = loopback.chain(public).collect();
        assert_eq!(filter_answers(&strict, &f.deny, &huge), huge[256..256 + MAX_ADDRS_PER_NAME]);
    }

    #[test]
    fn bindings_expire_refresh_and_stay_bounded() {
        let now = Instant::now();
        let (a, b, c) = (name("a.example"), name("b.example"), name("c.example"));
        let mut bindings = Bindings::new(2);
        assert!(bindings.is_empty());
        bindings.record(&a, &[ip("203.0.113.1")], now, TTL);
        assert!(bindings.is_bound(&a, ip("203.0.113.1"), now));
        assert!(!bindings.is_bound(&a, ip("203.0.113.2"), now) && !bindings.is_bound(&b, ip("203.0.113.1"), now));
        assert!(!bindings.is_bound(&a, ip("203.0.113.1"), now + TTL));

        // A later answer extends the lifetime of an address and never shortens it.
        bindings.record(&a, &[ip("203.0.113.1")], now + TTL / 2, TTL);
        assert!(bindings.is_bound(&a, ip("203.0.113.1"), now + TTL));
        bindings.record(&a, &[ip("203.0.113.1")], now + TTL / 2, Duration::from_secs(1));
        assert!(bindings.is_bound(&a, ip("203.0.113.1"), now + TTL));

        // Capacity: the name whose bindings expire soonest gives way.
        bindings.record(&b, &[ip("203.0.113.2")], now + TTL / 2, TTL * 2);
        bindings.record(&c, &[ip("203.0.113.3")], now + TTL / 2, TTL);
        assert_eq!(bindings.len(), 2);
        assert!(!bindings.is_bound(&a, ip("203.0.113.1"), now + TTL));
        assert!(bindings.is_bound(&b, ip("203.0.113.2"), now + TTL) && bindings.is_bound(&c, ip("203.0.113.3"), now + TTL));

        // Recording drops what expired.
        bindings.record(&a, &[], now + TTL * 10, TTL);
        assert!(bindings.is_empty());

        // Nothing is recorded with a zero lifetime, an overflowing lifetime or no capacity.
        bindings.record(&a, &[ip("203.0.113.1")], now, Duration::ZERO);
        bindings.record(&a, &[ip("203.0.113.1")], now, Duration::MAX);
        assert!(bindings.is_empty());
        let mut none = Bindings::new(0);
        none.record(&a, &[ip("203.0.113.1")], now, TTL);
        assert!(none.is_empty() && !none.is_bound(&a, ip("203.0.113.1"), now));
    }

    #[test]
    fn bindings_keep_at_most_the_per_name_bound() {
        let now = Instant::now();
        let a = name("a.example");
        let mut bindings = Bindings::new(1);
        let first: Vec<Ipv4Addr> = (0..MAX_ADDRS_PER_NAME as u8).map(|n| Ipv4Addr::new(203, 0, 113, n)).collect();
        bindings.record(&a, &first, now, TTL);
        let oversized: Vec<Ipv4Addr> = (0..=MAX_ADDRS_PER_NAME as u8).map(|n| Ipv4Addr::new(198, 51, 100, n)).collect();
        bindings.record(&a, &oversized, now + Duration::from_secs(1), TTL);
        let later = now + Duration::from_secs(2);
        assert!(first.iter().all(|addr| !bindings.is_bound(&a, *addr, later)), "older addresses give way");
        let bound = oversized.iter().filter(|addr| bindings.is_bound(&a, **addr, later)).count();
        assert_eq!(bound, MAX_ADDRS_PER_NAME);
        assert!(!bindings.is_bound(&a, oversized[MAX_ADDRS_PER_NAME], later), "addresses past the bound are not recorded");
    }

    #[test]
    fn deny_reason_labels_are_unique_and_plain() {
        let labels: std::collections::BTreeSet<&str> = DenyReason::ALL.iter().map(|reason| reason.as_str()).collect();
        assert_eq!(labels.len(), DenyReason::ALL.len());
        assert!(labels.iter().all(|label| label.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')));
    }

    fn arbitrary_entries() -> impl Strategy<Value = Vec<EntrySpec>> {
        let names = prop::sample::select(vec!["api.example.com", "git.example.com", "cdn.example.net"]);
        let name_entries = (names, 1u16..=65535, 0u16..=1000).prop_map(|(n, from, span)| name_entry(n, from, from.saturating_add(span)));
        let net_entries = (any::<u32>(), 8u8..=32, 1u16..=65535, 0u16..=65535).prop_map(|(addr, prefix, from, span)| {
            let network = format!("{}/{prefix}", Ipv4Addr::from(addr & mask(prefix)));
            net_entry(&network, from, from.saturating_add(span))
        });
        prop::collection::vec(prop_oneof![name_entries, net_entries], 0..12)
    }

    fn denied_address() -> impl Strategy<Value = Ipv4Addr> {
        let ranges = prop::sample::select(ALWAYS_DENIED.map(|(range, _)| range).to_vec());
        prop_oneof![
            (ranges, any::<u32>()).prop_map(|(range, bits)| Ipv4Addr::from(range.addr | (bits & !mask(range.prefix)))),
            Just(Ipv4Addr::BROADCAST),
            Just(Ipv4Addr::new(169, 254, 169, 254)),
        ]
    }

    /// Generated entries can be invalid (a network that overlaps a denied range, say); those are refused by
    /// validation, and the allowlist is built from the rest.
    fn allowlist_of_valid(entries: Vec<EntrySpec>, private: bool) -> Allowlist {
        let valid: Vec<EntrySpec> =
            entries.into_iter().filter(|entry| Allowlist::new(std::slice::from_ref(entry), private, 1).is_ok()).collect();
        Allowlist::new(&valid, private, valid.len()).unwrap()
    }

    proptest! {
        /// AL-6: no set of entries, binding or server name makes an always-denied address reachable.
        #[test]
        fn always_denied_addresses_are_never_allowed(
            entries in arbitrary_entries(),
            private in any::<bool>(),
            addr in denied_address(),
            port in any::<u16>(),
            with_name in any::<bool>(),
        ) {
            let allow = allowlist_of_valid(entries, private);
            let now = Instant::now();
            let server_name = name("api.example.com");
            let mut bindings = Bindings::new(4);
            bindings.record(&server_name, &[addr], now, TTL);
            let deny = DenyContext::default();
            let dst = SocketAddrV4::new(addr, port);
            let verdict = connect_verdict(&allow, &deny, dst, with_name.then_some(&server_name), &bindings, now);
            prop_assert!(matches!(verdict, Verdict::Deny(_)), "{dst} was allowed: {verdict:?}");
            prop_assert!(!needs_server_name(&allow, &deny, dst));
            prop_assert!(filter_answers(&allow, &deny, &[addr]).is_empty());
        }

        /// Host addresses and other sandboxes are denied whatever the entries say, and an allowed public
        /// destination is exactly one that an entry matches.
        #[test]
        fn verdict_never_exceeds_the_entries(entries in arbitrary_entries(), addr in any::<u32>(), port in 1u16..=65535) {
            let allow = allowlist_of_valid(entries, true);
            let addr = Ipv4Addr::from(addr);
            let dst = SocketAddrV4::new(addr, port);
            let now = Instant::now();
            let server_name = name("api.example.com");
            let mut bindings = Bindings::new(4);
            bindings.record(&server_name, &[addr], now, TTL);

            let host = DenyContext { host_addresses: vec![addr], sandbox_networks: vec![] };
            prop_assert!(matches!(connect_verdict(&allow, &host, dst, Some(&server_name), &bindings, now), Verdict::Deny(_)));
            let sandbox = DenyContext { host_addresses: vec![], sandbox_networks: vec![Ipv4Net { addr: u32::from(addr), prefix: 32 }] };
            prop_assert!(matches!(connect_verdict(&allow, &sandbox, dst, Some(&server_name), &bindings, now), Verdict::Deny(_)));

            let none = DenyContext::default();
            match connect_verdict(&allow, &none, dst, Some(&server_name), &bindings, now) {
                Verdict::Allow(AllowBasis::NetworkEntry) => prop_assert!(allow.network_allows(dst)),
                Verdict::Allow(AllowBasis::NameEntry) => prop_assert!(allow.name_allows(&server_name, port)),
                Verdict::Deny(_) => prop_assert!(!allow.network_allows(dst)),
            }
            // Without a server name only a network entry can allow.
            let unnamed = connect_verdict(&allow, &none, dst, None, &bindings, now);
            prop_assert_eq!(unnamed == Verdict::Allow(AllowBasis::NetworkEntry), allow.network_allows(dst));
            prop_assert!(unnamed != Verdict::Allow(AllowBasis::NameEntry));
        }
    }
}
