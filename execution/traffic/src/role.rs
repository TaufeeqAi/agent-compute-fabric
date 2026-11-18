//! The role: its configuration, the state the two loops share, its counters, and [`run`].
//!
//! The privileged core hands this role a validated [`RoleConfig`] and two sockets it opened inside the
//! sandbox's network namespace. The role owns nothing else: when [`run`] returns, for whatever reason, both
//! sockets and every relayed connection are closed and the guest has no connectivity left (NW-1, PD-3).

use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Semaphore, watch};

use crate::policy::{self, Allowlist, Bindings, DenyContext, DenyReason, DnsName, EntrySpec, Ipv4Net, PolicyError, Verdict};
use crate::relay::{self, Connector, DirectConnector, KernelOriginalDst, OriginalDst};
use crate::resolver::{self, SystemUpstream, Upstream};

/// Ceiling for `max_entries` (AL-1: the number of entries is bounded).
pub const MAX_ENTRIES: usize = 1024;
/// Ceiling for `max_bindings`.
pub const MAX_BINDINGS: usize = 4096;
/// Ceiling for `max_connections`.
pub const MAX_CONNECTIONS: usize = 65_536;
/// Ceiling for `max_pending_lookups`.
pub const MAX_PENDING_LOOKUPS: usize = 1024;
/// Ceiling for the number of host addresses and of sandbox networks.
pub const MAX_DENIED_DESTINATIONS: usize = 4096;
/// Ceiling for every deadline and lifetime: one day.
pub const MAX_DEADLINE_MS: u64 = 24 * 60 * 60 * 1000;
/// Longest TTL written into a DNS answer, whatever the binding lifetime.
pub const MAX_ANSWER_TTL: Duration = Duration::from_secs(60);
/// Consecutive socket errors a loop tolerates before it gives up, and with it the sandbox's connectivity.
pub(crate) const MAX_CONSECUTIVE_ERRORS: u32 = 16;
/// Pause after a socket error, so a persistent one cannot spin a loop.
pub(crate) const ERROR_BACKOFF: Duration = Duration::from_millis(50);

#[derive(Debug, thiserror::Error)]
pub enum RoleError {
    #[error("{field} must be between 1 and {max}, got {value}")]
    OutOfRange { field: &'static str, value: u64, max: u64 },
    #[error("{field} holds {count} items, more than the limit of {MAX_DENIED_DESTINATIONS}")]
    TooManyDeniedDestinations { field: &'static str, count: usize },
    #[error("allowlist: {0}")]
    Allowlist(#[source] PolicyError),
    #[error("sandbox network {index}: {source}")]
    SandboxNetwork { index: usize, source: PolicyError },
    #[error("the role configuration is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("cannot adopt the {socket} socket: {source}")]
    Socket { socket: &'static str, source: io::Error },
    #[error("the {role} loop failed: {source}")]
    Loop { role: &'static str, source: io::Error },
}

/// Everything the role needs, as the privileged core serialises it. Every bound is finite and non-zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleConfig {
    pub entries: Vec<EntrySpec>,
    pub private_destinations: bool,
    pub max_entries: usize,
    /// AL-6: the host's own addresses, the sandbox's gateway address included.
    pub host_addresses: Vec<Ipv4Addr>,
    /// AL-6: the networks other sandboxes live in, in CIDR form.
    pub sandbox_networks: Vec<String>,
    pub dns_binding_ttl_ms: u64,
    pub max_bindings: usize,
    pub max_connections: usize,
    pub max_pending_lookups: usize,
    pub sni_deadline_ms: u64,
    pub connect_deadline_ms: u64,
    pub idle_timeout_ms: u64,
    pub upstream_timeout_ms: u64,
}

impl RoleConfig {
    /// Parses and validates a configuration. Unknown fields are refused.
    pub fn from_json(json: &[u8]) -> Result<Self, RoleError> {
        let config: Self = serde_json::from_slice(json)?;
        config.validate()?;
        Ok(config)
    }

    /// Checks every bound (finite and non-zero), the allowlist (AL-1) and the sandbox networks.
    pub fn validate(&self) -> Result<(), RoleError> {
        self.limits()?;
        self.allowlist()?;
        self.deny_context()?;
        Ok(())
    }

    fn limits(&self) -> Result<Limits, RoleError> {
        count("max_entries", self.max_entries, MAX_ENTRIES)?;
        count("max_bindings", self.max_bindings, MAX_BINDINGS)?;
        count("max_connections", self.max_connections, MAX_CONNECTIONS)?;
        count("max_pending_lookups", self.max_pending_lookups, MAX_PENDING_LOOKUPS)?;
        let binding_ttl = deadline("dns_binding_ttl_ms", self.dns_binding_ttl_ms)?;
        Ok(Limits {
            binding_ttl,
            answer_ttl_secs: u32::try_from(binding_ttl.min(MAX_ANSWER_TTL).as_secs()).unwrap_or(0),
            sni_deadline: deadline("sni_deadline_ms", self.sni_deadline_ms)?,
            connect_deadline: deadline("connect_deadline_ms", self.connect_deadline_ms)?,
            idle_timeout: deadline("idle_timeout_ms", self.idle_timeout_ms)?,
            upstream_timeout: deadline("upstream_timeout_ms", self.upstream_timeout_ms)?,
        })
    }

    fn allowlist(&self) -> Result<Allowlist, RoleError> {
        Allowlist::new(&self.entries, self.private_destinations, self.max_entries).map_err(RoleError::Allowlist)
    }

    fn deny_context(&self) -> Result<DenyContext, RoleError> {
        for (field, len) in [("host_addresses", self.host_addresses.len()), ("sandbox_networks", self.sandbox_networks.len())] {
            if len > MAX_DENIED_DESTINATIONS {
                return Err(RoleError::TooManyDeniedDestinations { field, count: len });
            }
        }
        let parse =
            |(index, network): (usize, &String)| Ipv4Net::parse(network).map_err(|source| RoleError::SandboxNetwork { index, source });
        let sandbox_networks = self.sandbox_networks.iter().enumerate().map(parse).collect::<Result<Vec<_>, _>>()?;
        Ok(DenyContext { host_addresses: self.host_addresses.clone(), sandbox_networks })
    }
}

fn count(field: &'static str, value: usize, max: usize) -> Result<(), RoleError> {
    if (1..=max).contains(&value) {
        return Ok(());
    }
    let wide = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
    Err(RoleError::OutOfRange { field, value: wide(value), max: wide(max) })
}

fn deadline(field: &'static str, millis: u64) -> Result<Duration, RoleError> {
    if (1..=MAX_DEADLINE_MS).contains(&millis) {
        return Ok(Duration::from_millis(millis));
    }
    Err(RoleError::OutOfRange { field, value: millis, max: MAX_DEADLINE_MS })
}

/// The validated deadlines of a role.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    pub(crate) binding_ttl: Duration,
    /// min(binding lifetime, [`MAX_ANSWER_TTL`]) in whole seconds: the guest never caches an answer for
    /// longer than the binding that makes it usable.
    pub(crate) answer_ttl_secs: u32,
    pub(crate) sni_deadline: Duration,
    pub(crate) connect_deadline: Duration,
    pub(crate) idle_timeout: Duration,
    pub(crate) upstream_timeout: Duration,
}

/// What the resolver and the relay share: the policy, the bindings that tie them together, the bounds and
/// the counters.
#[derive(Debug)]
pub struct Shared {
    pub(crate) allowlist: Allowlist,
    pub(crate) deny: DenyContext,
    bindings: Mutex<Bindings>,
    pub(crate) limits: Limits,
    /// One permit per relayed connection.
    pub(crate) connections: Arc<Semaphore>,
    /// One permit per upstream lookup in flight.
    pub(crate) lookups: Arc<Semaphore>,
    pub(crate) stats: Stats,
}

impl Shared {
    pub fn new(config: &RoleConfig) -> Result<Arc<Self>, RoleError> {
        Ok(Arc::new(Self {
            limits: config.limits()?,
            allowlist: config.allowlist()?,
            deny: config.deny_context()?,
            bindings: Mutex::new(Bindings::new(config.max_bindings)),
            connections: Arc::new(Semaphore::new(config.max_connections)),
            lookups: Arc::new(Semaphore::new(config.max_pending_lookups)),
            stats: Stats::default(),
        }))
    }

    pub fn stats(&self) -> StatsSnapshot {
        self.stats.snapshot()
    }

    /// AL-4: remembers the addresses the resolver is about to hand to the guest for `name`.
    pub(crate) async fn bind(&self, name: &DnsName, addrs: &[Ipv4Addr]) {
        self.bindings.lock().await.record(name, addrs, now(), self.limits.binding_ttl);
    }

    /// The verdict for one connection against the bindings as they are at this instant.
    pub(crate) async fn verdict(&self, dst: SocketAddrV4, server_name: Option<&DnsName>) -> Verdict {
        let bindings = self.bindings.lock().await;
        policy::connect_verdict(&self.allowlist, &self.deny, dst, server_name, &bindings, now())
    }
}

/// The runtime's clock, so tests that pause time also age the bindings.
fn now() -> std::time::Instant {
    tokio::time::Instant::now().into_std()
}

/// Counters, updated lock-free from both loops.
#[derive(Debug, Default)]
pub(crate) struct Stats {
    pub(crate) queries: AtomicU64,
    pub(crate) queries_refused: AtomicU64,
    pub(crate) queries_answered: AtomicU64,
    pub(crate) upstream_failures: AtomicU64,
    pub(crate) connections: AtomicU64,
    pub(crate) connections_allowed: AtomicU64,
    pub(crate) connections_shed: AtomicU64,
    connections_denied: AtomicU64,
    /// One counter per [`DenyReason`], in the order of [`DenyReason::ALL`].
    denied_by_reason: [AtomicU64; DenyReason::ALL.len()],
}

pub(crate) fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

impl Stats {
    pub(crate) fn denied(&self, reason: DenyReason) {
        bump(&self.connections_denied);
        if let Some((_, counter)) = DenyReason::ALL.iter().zip(&self.denied_by_reason).find(|(known, _)| **known == reason) {
            bump(counter);
        }
    }

    fn snapshot(&self) -> StatsSnapshot {
        let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let by_reason =
            DenyReason::ALL.iter().zip(&self.denied_by_reason).map(|(reason, counter)| (reason.as_str().to_owned(), read(counter)));
        StatsSnapshot {
            queries: read(&self.queries),
            queries_refused: read(&self.queries_refused),
            queries_answered: read(&self.queries_answered),
            upstream_failures: read(&self.upstream_failures),
            connections: read(&self.connections),
            connections_allowed: read(&self.connections_allowed),
            connections_denied: read(&self.connections_denied),
            connections_shed: read(&self.connections_shed),
            denied_by_reason: by_reason.filter(|(_, count)| *count > 0).collect(),
        }
    }
}

/// A point-in-time copy of the counters. Labels are fixed strings; nothing here is guest-supplied.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
    /// Datagrams received by the resolver, including those dropped as oversized or unparseable.
    pub queries: u64,
    /// Queries answered REFUSED: the name is not on the allowlist (AL-3). No upstream was contacted.
    pub queries_refused: u64,
    /// Queries answered NOERROR, with or without address records.
    pub queries_answered: u64,
    /// Queries answered SERVFAIL: the upstream failed or timed out, or too many lookups were in flight.
    pub upstream_failures: u64,
    /// Connections accepted by the relay. Once all are settled this is allowed + denied + shed.
    pub connections: u64,
    /// Connections that passed the verdict and were connected to their destination.
    pub connections_allowed: u64,
    /// Connections closed without relaying a byte; `denied_by_reason` says why.
    pub connections_denied: u64,
    /// Connections closed at once because `max_connections` were already open.
    pub connections_shed: u64,
    /// Denied connections by [`DenyReason`] label; reasons that never occurred are absent.
    pub denied_by_reason: BTreeMap<String, u64>,
}

/// Resolves once the role is asked to stop, or once whoever could ask is gone.
pub(crate) async fn stopped(shutdown: &mut watch::Receiver<bool>) {
    // An error means the sender was dropped: nobody can stop the loop any more, so it stops itself.
    let _ = shutdown.wait_for(|stop| *stop).await;
}

/// Runs both loops until `shutdown` resolves or either loop fails; then returns, which drops both sockets
/// and ends all connectivity. The sockets must already be bound inside the sandbox's network namespace.
pub async fn run(
    config: RoleConfig,
    resolver: std::net::UdpSocket,
    relay: std::net::TcpListener,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<StatsSnapshot, RoleError> {
    let shared = Shared::new(&config)?;
    let adopt = |socket: &'static str| move |source: io::Error| RoleError::Socket { socket, source };
    resolver.set_nonblocking(true).map_err(adopt("resolver"))?;
    relay.set_nonblocking(true).map_err(adopt("relay"))?;
    let resolver = tokio::net::UdpSocket::from_std(resolver).map_err(adopt("resolver"))?;
    let relay = tokio::net::TcpListener::from_std(relay).map_err(adopt("relay"))?;
    let upstream = SystemUpstream { timeout: shared.limits.upstream_timeout };
    run_with(Arc::clone(&shared), resolver, relay, upstream, KernelOriginalDst, DirectConnector, shutdown).await?;
    Ok(shared.stats())
}

/// [`run`], generic over the three effects, so tests can stand in for the upstream resolver, the packet
/// filter's original destination and the outside world.
pub async fn run_with<U, O, C>(
    shared: Arc<Shared>,
    resolver: tokio::net::UdpSocket,
    relay: tokio::net::TcpListener,
    upstream: U,
    original: O,
    connector: C,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), RoleError>
where
    U: Upstream,
    O: OriginalDst,
    C: Connector,
{
    let (stop, stopping) = watch::channel(false);
    // Whichever ends first - the shutdown signal or a failed loop - stops the others. Joining them means
    // that on return both sockets are closed and every lookup and connection has been torn down.
    let resolver = async {
        let ended = resolver::serve_resolver(resolver, Arc::clone(&shared), upstream, stopping.clone()).await;
        stop.send_replace(true);
        ended.map_err(|source| RoleError::Loop { role: "resolver", source })
    };
    let relay = async {
        let ended = relay::serve_relay(relay, Arc::clone(&shared), original, connector, stopping.clone()).await;
        stop.send_replace(true);
        ended.map_err(|source| RoleError::Loop { role: "relay", source })
    };
    let signal = async {
        let mut stopping = stopping.clone();
        tokio::select! {
            () = shutdown => {}
            () = stopped(&mut stopping) => {}
        }
        stop.send_replace(true);
    };
    let (resolver, relay, ()) = tokio::join!(resolver, relay, signal);
    resolver.and(relay)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{DestinationSpec, PortRange};

    pub(crate) fn config() -> RoleConfig {
        RoleConfig {
            entries: vec![EntrySpec {
                destination: DestinationSpec::Name("api.example.com".into()),
                ports: vec![PortRange { from: 443, to: 443 }],
            }],
            private_destinations: false,
            max_entries: 16,
            host_addresses: vec![Ipv4Addr::new(10, 200, 0, 1)],
            sandbox_networks: vec!["10.200.0.0/16".into()],
            dns_binding_ttl_ms: 30_000,
            max_bindings: 64,
            max_connections: 32,
            max_pending_lookups: 8,
            sni_deadline_ms: 2_000,
            connect_deadline_ms: 5_000,
            idle_timeout_ms: 60_000,
            upstream_timeout_ms: 3_000,
        }
    }

    #[test]
    fn a_sound_configuration_validates_and_round_trips_through_json() {
        let config = config();
        config.validate().unwrap();
        let json = serde_json::to_vec(&config).unwrap();
        assert_eq!(RoleConfig::from_json(&json).unwrap(), config);
        let shared = Shared::new(&config).unwrap();
        assert_eq!(shared.limits.answer_ttl_secs, 30);
        assert_eq!(shared.stats(), StatsSnapshot::default());
    }

    #[test]
    fn every_bound_must_be_finite_and_non_zero() {
        type Set = fn(&mut RoleConfig, u64);
        let fields: [(&str, u64, Set); 9] = [
            ("max_entries", MAX_ENTRIES as u64, |c, v| c.max_entries = v as usize),
            ("max_bindings", MAX_BINDINGS as u64, |c, v| c.max_bindings = v as usize),
            ("max_connections", MAX_CONNECTIONS as u64, |c, v| c.max_connections = v as usize),
            ("max_pending_lookups", MAX_PENDING_LOOKUPS as u64, |c, v| c.max_pending_lookups = v as usize),
            ("dns_binding_ttl_ms", MAX_DEADLINE_MS, |c, v| c.dns_binding_ttl_ms = v),
            ("sni_deadline_ms", MAX_DEADLINE_MS, |c, v| c.sni_deadline_ms = v),
            ("connect_deadline_ms", MAX_DEADLINE_MS, |c, v| c.connect_deadline_ms = v),
            ("idle_timeout_ms", MAX_DEADLINE_MS, |c, v| c.idle_timeout_ms = v),
            ("upstream_timeout_ms", MAX_DEADLINE_MS, |c, v| c.upstream_timeout_ms = v),
        ];
        for (name, max, set) in fields {
            for bad in [0, max + 1, u64::MAX] {
                let mut config = config();
                set(&mut config, bad);
                match config.validate() {
                    Err(RoleError::OutOfRange { field, max: limit, .. }) => assert_eq!((field, limit), (name, max)),
                    other => panic!("{name} = {bad} must be out of range, got {other:?}"),
                }
                assert!(Shared::new(&config).is_err(), "{name} = {bad}");
            }
            let mut config = config();
            set(&mut config, max);
            config.validate().unwrap_or_else(|error| panic!("{name} = {max} is the largest valid value: {error}"));
        }
    }

    #[test]
    fn the_answer_ttl_never_exceeds_the_binding_lifetime_or_sixty_seconds() {
        for (binding_ms, answer_secs) in [(1, 0), (999, 0), (1_000, 1), (59_999, 59), (60_000, 60), (3_600_000, 60)] {
            let config = RoleConfig { dns_binding_ttl_ms: binding_ms, ..config() };
            assert_eq!(Shared::new(&config).unwrap().limits.answer_ttl_secs, answer_secs, "{binding_ms} ms");
        }
    }

    #[test]
    fn invalid_policy_is_refused() {
        let too_many = RoleConfig { max_entries: 1, entries: [config().entries, config().entries].concat(), ..config() };
        assert!(matches!(too_many.validate(), Err(RoleError::Allowlist(PolicyError::TooManyEntries { count: 2, max: 1 }))));

        let bad_entry =
            EntrySpec { destination: DestinationSpec::Network("127.0.0.0/8".into()), ports: vec![PortRange { from: 1, to: 1 }] };
        let denied = RoleConfig { entries: vec![bad_entry], ..config() };
        assert!(matches!(Shared::new(&denied), Err(RoleError::Allowlist(PolicyError::Entry { index: 0, .. }))));

        let bad_network = RoleConfig { sandbox_networks: vec!["10.200.0.0/16".into(), "10.200.0.1/16".into()], ..config() };
        assert!(matches!(bad_network.validate(), Err(RoleError::SandboxNetwork { index: 1, .. })));

        let crowded = RoleConfig { host_addresses: vec![Ipv4Addr::new(10, 200, 0, 1); MAX_DENIED_DESTINATIONS + 1], ..config() };
        assert!(matches!(crowded.validate(), Err(RoleError::TooManyDeniedDestinations { field: "host_addresses", .. })));
    }

    #[test]
    fn json_with_unknown_or_missing_fields_is_refused() {
        let mut value = serde_json::to_value(config()).unwrap();
        value["allow_everything"] = true.into();
        assert!(matches!(RoleConfig::from_json(value.to_string().as_bytes()), Err(RoleError::Json(_))));

        let mut value = serde_json::to_value(config()).unwrap();
        value.as_object_mut().unwrap().remove("max_connections");
        assert!(matches!(RoleConfig::from_json(value.to_string().as_bytes()), Err(RoleError::Json(_))));

        let mut value = serde_json::to_value(config()).unwrap();
        value["idle_timeout_ms"] = 0.into();
        assert!(matches!(RoleConfig::from_json(value.to_string().as_bytes()), Err(RoleError::OutOfRange { field: "idle_timeout_ms", .. })));
    }

    #[test]
    fn every_denial_is_counted_under_its_own_label() {
        let stats = Stats::default();
        for (times, reason) in DenyReason::ALL.iter().enumerate() {
            for _ in 0..=times {
                stats.denied(*reason);
            }
        }
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.denied_by_reason.len(), DenyReason::ALL.len());
        for (times, reason) in DenyReason::ALL.iter().enumerate() {
            assert_eq!(snapshot.denied_by_reason[reason.as_str()], times as u64 + 1, "{reason:?}");
        }
        assert_eq!(snapshot.connections_denied, snapshot.denied_by_reason.values().sum::<u64>());

        let json = serde_json::to_string(&snapshot).unwrap();
        assert_eq!(serde_json::from_str::<StatsSnapshot>(&json).unwrap(), snapshot);
    }

    #[tokio::test(start_paused = true)]
    async fn bindings_made_through_shared_age_with_the_runtime_clock() {
        let shared = Shared::new(&config()).unwrap();
        let name = DnsName::parse("api.example.com").unwrap();
        let dst = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 10), 443);
        assert_eq!(shared.verdict(dst, Some(&name)).await, Verdict::Deny(DenyReason::AddressNotBound));

        shared.bind(&name, &[*dst.ip()]).await;
        assert_eq!(shared.verdict(dst, Some(&name)).await, Verdict::Allow(policy::AllowBasis::NameEntry));
        tokio::time::advance(Duration::from_millis(29_999)).await;
        assert_eq!(shared.verdict(dst, Some(&name)).await, Verdict::Allow(policy::AllowBasis::NameEntry));
        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(shared.verdict(dst, Some(&name)).await, Verdict::Deny(DenyReason::AddressNotBound));
    }
}
