//! The resolver: DNS over UDP for the names on the sandbox's allowlist and for nothing else (AL-3).
//!
//! It is the only name service the guest can reach (AL-2). For a name that is not on the allowlist it answers
//! REFUSED from local state, without contacting any upstream, so a guest cannot use lookups as a channel to
//! the outside. For an allowlisted name it asks the upstream, drops every address the guest may never reach
//! (AL-6), records exactly the addresses it is about to return (AL-4) and returns `A` records only.
//!
//! Bounds: one fixed receive buffer, at most `max_pending_lookups` lookups in flight (more are answered
//! SERVFAIL), and no reply ever waits on the socket. A slow upstream therefore delays only its own query.

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::{OwnedSemaphorePermit, watch};
use tokio::task::JoinSet;

use crate::dns::{self, Query, Rcode};
use crate::policy::{self, DnsName};
use crate::role::{self, ERROR_BACKOFF, MAX_CONSECUTIVE_ERRORS, Shared, bump};

/// Where the addresses of an allowlisted name come from.
pub trait Upstream: Send + Sync + 'static {
    fn lookup_a(&self, name: &DnsName) -> impl Future<Output = io::Result<Vec<Ipv4Addr>>> + Send;
}

/// The host's own resolver, through the runtime's `lookup_host`. IPv4 results only.
///
/// The lookup runs on the runtime's blocking pool. `timeout` bounds how long the query waits, not how long
/// the pool thread is busy, so it should not be shorter than the host resolver's own timeout.
#[derive(Debug, Clone, Copy)]
pub struct SystemUpstream {
    pub timeout: Duration,
}

impl Upstream for SystemUpstream {
    async fn lookup_a(&self, name: &DnsName) -> io::Result<Vec<Ipv4Addr>> {
        let lookup = tokio::net::lookup_host((name.as_str(), 0));
        let found = tokio::time::timeout(self.timeout, lookup).await.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        Ok(found.filter_map(|addr| if let SocketAddr::V4(v4) = addr { Some(*v4.ip()) } else { None }).collect())
    }
}

/// What one datagram calls for, decided without any I/O.
#[derive(Debug)]
enum Step {
    /// Too broken to answer, or not a query at all.
    Ignore,
    Reply(Vec<u8>),
    /// An `A` question about an allowlisted name: the only case that reaches the upstream.
    Lookup(Query, DnsName),
}

/// Serves the guest's queries until `shutdown` fires. Returns an error only when the socket keeps failing.
pub async fn serve_resolver<U: Upstream>(
    socket: UdpSocket,
    shared: Arc<Shared>,
    upstream: U,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    let socket = Arc::new(socket);
    let upstream = Arc::new(upstream);
    let mut lookups = JoinSet::new();
    let mut failures = 0u32;
    // One byte more than the largest query, so an oversized datagram is recognised rather than truncated.
    let mut datagram = [0u8; dns::MAX_MESSAGE_LEN + 1];
    let ended = loop {
        let received = tokio::select! {
            biased;
            () = role::stopped(&mut shutdown) => break Ok(()),
            Some(_) = lookups.join_next() => continue,
            received = socket.recv_from(&mut datagram) => received,
        };
        let (len, peer) = match received {
            Ok(received) => received,
            Err(error) => {
                failures += 1;
                if failures > MAX_CONSECUTIVE_ERRORS {
                    break Err(error);
                }
                tracing::warn!(%error, "resolver receive failed");
                tokio::time::sleep(ERROR_BACKOFF).await;
                continue;
            }
        };
        failures = 0;
        bump(&shared.stats.queries);
        let Some(packet) = datagram.get(..len).filter(|packet| packet.len() <= dns::MAX_MESSAGE_LEN) else { continue };
        match triage(&shared, packet) {
            Step::Ignore => {}
            Step::Reply(response) => reply(&socket, &response, peer),
            Step::Lookup(query, name) => match Arc::clone(&shared.lookups).try_acquire_owned() {
                Ok(permit) => {
                    lookups.spawn(lookup(Arc::clone(&shared), Arc::clone(&upstream), Arc::clone(&socket), query, name, peer, permit));
                }
                Err(_) => reply(&socket, &server_failure(&shared, &query), peer),
            },
        }
    };
    lookups.shutdown().await;
    ended
}

/// Parses one datagram and settles everything that needs no upstream.
fn triage(shared: &Shared, packet: &[u8]) -> Step {
    let query = match dns::parse_query(packet) {
        Ok(query) => query,
        Err(error) => return error.response().map_or(Step::Ignore, Step::Reply),
    };
    // AL-3: a name that is not on the allowlist is refused here, from local state alone.
    let Some(name) = query.name.clone().filter(|name| policy::may_resolve(&shared.allowlist, name)) else {
        bump(&shared.stats.queries_refused);
        return Step::Reply(dns::build_response(&query, Rcode::Refused, &[], 0));
    };
    if query.qtype != dns::QTYPE_A {
        // IPv4 only: the name exists, but there is no AAAA (or any other) record for the guest.
        bump(&shared.stats.queries_answered);
        return Step::Reply(dns::build_response(&query, Rcode::NoError, &[], 0));
    }
    Step::Lookup(query, name)
}

/// One upstream lookup, in its own task. The permit is held until the reply is sent.
async fn lookup<U: Upstream>(
    shared: Arc<Shared>,
    upstream: Arc<U>,
    socket: Arc<UdpSocket>,
    query: Query,
    name: DnsName,
    peer: SocketAddr,
    _permit: OwnedSemaphorePermit,
) {
    let response = resolve(&shared, upstream.as_ref(), &query, &name).await;
    reply(&socket, &response, peer);
}

async fn resolve<U: Upstream>(shared: &Shared, upstream: &U, query: &Query, name: &DnsName) -> Vec<u8> {
    let found = match tokio::time::timeout(shared.limits.upstream_timeout, upstream.lookup_a(name)).await {
        Ok(Ok(found)) => found,
        Ok(Err(error)) => {
            tracing::debug!(%name, %error, "upstream lookup failed");
            return server_failure(shared, query);
        }
        Err(_) => {
            tracing::debug!(%name, "upstream lookup timed out");
            return server_failure(shared, query);
        }
    };
    // AL-6: an address the guest may never reach is not handed out, so a rebinding answer dies here.
    let mut answers = policy::filter_answers(&shared.allowlist, &shared.deny, &found);
    answers.truncate(dns::MAX_ANSWERS);
    // AL-4: bind exactly the addresses that are about to be returned, before they are returned.
    shared.bind(name, &answers).await;
    bump(&shared.stats.queries_answered);
    dns::build_response(query, Rcode::NoError, &answers, shared.limits.answer_ttl_secs)
}

fn server_failure(shared: &Shared, query: &Query) -> Vec<u8> {
    bump(&shared.stats.upstream_failures);
    dns::build_response(query, Rcode::ServFail, &[], 0)
}

/// Sends without waiting. If the socket cannot take the datagram now it is dropped and the guest retries.
fn reply(socket: &UdpSocket, response: &[u8], peer: SocketAddr) {
    if let Err(error) = socket.try_send_to(response, peer) {
        tracing::debug!(%error, "resolver reply dropped");
    }
}
