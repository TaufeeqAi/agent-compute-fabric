//! The relay: every TCP connection the guest opens is redirected here, and this is its only way out.
//!
//! For each connection the relay reads the destination the guest actually dialled, reads the TLS server name
//! when a name entry could allow it, and asks [`crate::policy::connect_verdict`]. On `Allow` it connects to
//! exactly the address and port the guest dialled - it never resolves a name itself, so the address stays the
//! one the resolver bound (AL-4) - and copies bytes both ways. On `Deny`, or on any failure, it closes the
//! guest connection and counts the reason. Nothing else is ever forwarded (AL-2).
//!
//! Bounds per connection: at most [`sni::MAX_BUFFERED_LEN`] bytes are held while looking for the server
//! name, for at most `sni_deadline`; the copy uses two fixed buffers of [`SPLICE_BUFFER_LEN`] bytes and ends
//! after `idle_timeout` without progress. At most `max_connections` connections exist; more are closed at
//! once. Guest bytes are never logged; a server name is logged only once it parsed as a `DnsName`.

use std::future::Future;
use std::io;
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::policy::{self, DenyReason, DnsName, Verdict};
use crate::role::{self, ERROR_BACKOFF, MAX_CONSECUTIVE_ERRORS, Shared, bump};
use crate::sni::{self, ClientHelloParser, SniStatus};

/// Size of each of the two copy buffers of a relayed connection.
pub const SPLICE_BUFFER_LEN: usize = 16 * 1024;
/// Most bytes taken from the guest in one read while looking for the server name.
const HELLO_READ_LEN: usize = 2048;

/// Where a redirected connection was really going.
pub trait OriginalDst: Send + Sync + 'static {
    fn original_dst(&self, stream: &TcpStream) -> io::Result<SocketAddrV4>;
}

/// Asks the kernel's connection tracking (`SO_ORIGINAL_DST`) for the destination before the redirect.
///
/// The answer only exists for a connection the packet filter redirected with connection tracking (a NAT
/// `redirect` or `dnat` rule). For any other connection the lookup fails or names the listener itself, and
/// either way the connection is refused.
#[derive(Debug, Clone, Copy, Default)]
pub struct KernelOriginalDst;

impl OriginalDst for KernelOriginalDst {
    fn original_dst(&self, stream: &TcpStream) -> io::Result<SocketAddrV4> {
        Ok(rustix::net::sockopt::ip_original_dst(stream)?)
    }
}

/// How an allowed connection reaches its destination.
pub trait Connector: Send + Sync + 'static {
    fn connect(&self, addr: SocketAddrV4) -> impl Future<Output = io::Result<TcpStream>> + Send;
}

/// A plain TCP connection from the role's own network namespace, and nothing else.
#[derive(Debug, Clone, Copy, Default)]
pub struct DirectConnector;

impl Connector for DirectConnector {
    async fn connect(&self, addr: SocketAddrV4) -> io::Result<TcpStream> {
        TcpStream::connect(SocketAddr::V4(addr)).await
    }
}

/// Accepts and relays guest connections until `shutdown` fires. Returns an error only when the listener
/// keeps failing. Every connection still open is closed before this returns.
pub async fn serve_relay<O: OriginalDst, C: Connector>(
    listener: TcpListener,
    shared: Arc<Shared>,
    original: O,
    connector: C,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    let original = Arc::new(original);
    let connector = Arc::new(connector);
    let mut connections = JoinSet::new();
    let mut failures = 0u32;
    let ended = loop {
        let accepted = tokio::select! {
            biased;
            () = role::stopped(&mut shutdown) => break Ok(()),
            Some(_) = connections.join_next() => continue,
            accepted = listener.accept() => accepted,
        };
        let guest = match accepted {
            Ok((guest, _)) => guest,
            // One incoming connection died before it was accepted. It is gone; the listener is fine.
            Err(error) if concerns_one_connection(&error) => continue,
            Err(error) => {
                failures += 1;
                if failures > MAX_CONSECUTIVE_ERRORS {
                    break Err(error);
                }
                tracing::warn!(%error, "relay accept failed");
                tokio::time::sleep(ERROR_BACKOFF).await;
                continue;
            }
        };
        failures = 0;
        bump(&shared.stats.connections);
        // The cap bounds tasks, sockets and buffers. A connection over it is dropped, which closes it.
        let Ok(permit) = Arc::clone(&shared.connections).try_acquire_owned() else {
            bump(&shared.stats.connections_shed);
            continue;
        };
        let (shared, original, connector) = (Arc::clone(&shared), Arc::clone(&original), Arc::clone(&connector));
        connections.spawn(async move {
            relay_connection(&shared, original.as_ref(), connector.as_ref(), guest).await;
            drop(permit);
        });
    };
    connections.shutdown().await;
    ended
}

/// Accept errors that belong to a single incoming connection (the kernel reports its pending network error
/// through `accept`). The guest can provoke these, so they must not count against the listener.
fn concerns_one_connection(error: &io::Error) -> bool {
    use io::ErrorKind::{ConnectionAborted, ConnectionRefused, ConnectionReset, HostUnreachable, NetworkDown, NetworkUnreachable};
    matches!(error.kind(), ConnectionAborted | ConnectionRefused | ConnectionReset | HostUnreachable | NetworkDown | NetworkUnreachable)
}

async fn relay_connection<O: OriginalDst, C: Connector>(shared: &Shared, original: &O, connector: &C, mut guest: TcpStream) {
    match admit(shared, original, connector, &mut guest).await {
        Ok((upstream, replay)) => {
            bump(&shared.stats.connections_allowed);
            splice(guest, upstream, replay, shared.limits.idle_timeout).await;
        }
        Err(reason) => shared.stats.denied(reason),
    }
}

/// Everything that must hold before a byte is relayed. Returns the connection to the destination and the
/// guest bytes already read, which the destination has yet to see.
async fn admit<O: OriginalDst, C: Connector>(
    shared: &Shared,
    original: &O,
    connector: &C,
    guest: &mut TcpStream,
) -> Result<(TcpStream, Vec<u8>), DenyReason> {
    let dst = original_destination(original, guest)?;
    let mut replay = Vec::new();
    let needs_name = policy::needs_server_name(&shared.allowlist, &shared.deny, dst);
    let server_name = if needs_name { read_server_name(guest, &mut replay, shared.limits.sni_deadline).await } else { None };
    let basis = match shared.verdict(dst, server_name.as_ref()).await {
        Verdict::Allow(basis) => basis,
        Verdict::Deny(reason) => {
            tracing::debug!(%dst, ?server_name, reason = reason.as_str(), "connection denied");
            return Err(reason);
        }
    };
    // The destination is the address the guest dialled, never a fresh lookup of the server name.
    match tokio::time::timeout(shared.limits.connect_deadline, connector.connect(dst)).await {
        Ok(Ok(upstream)) => {
            tracing::debug!(%dst, ?server_name, ?basis, "connection allowed");
            Ok((upstream, replay))
        }
        Ok(Err(error)) => {
            tracing::debug!(%dst, %error, "allowed destination refused the connection");
            Err(DenyReason::UpstreamConnectFailed)
        }
        Err(_) => Err(DenyReason::UpstreamConnectTimedOut),
    }
}

/// The destination the guest dialled. A connection that reached the listener without being redirected is
/// addressed to the relay itself; relaying it would only loop, and the relay is a host address (AL-6).
fn original_destination<O: OriginalDst>(original: &O, guest: &TcpStream) -> Result<SocketAddrV4, DenyReason> {
    let dst = original.original_dst(guest).map_err(|error| {
        tracing::debug!(%error, "original destination unavailable");
        DenyReason::OriginalDestinationUnavailable
    })?;
    match guest.local_addr() {
        Ok(SocketAddr::V4(local)) if local != dst => Ok(dst),
        Ok(SocketAddr::V4(_)) => Err(DenyReason::HostAddress),
        Ok(SocketAddr::V6(_)) | Err(_) => Err(DenyReason::OriginalDestinationUnavailable),
    }
}

/// Reads the guest's first bytes until the ClientHello parser settles or `deadline` passes. Everything read
/// is appended to `replay`, which the parser's own bound keeps below [`sni::MAX_BUFFERED_LEN`].
async fn read_server_name(guest: &mut TcpStream, replay: &mut Vec<u8>, deadline: Duration) -> Option<DnsName> {
    let hello = async {
        let mut parser = ClientHelloParser::new();
        let mut chunk = [0u8; HELLO_READ_LEN];
        loop {
            let room = sni::MAX_BUFFERED_LEN.saturating_sub(replay.len()).min(chunk.len());
            let window = chunk.get_mut(..room)?;
            let read = guest.read(window).await.ok()?;
            // An empty read is the guest closing before its hello was complete.
            let bytes = window.get(..read).filter(|bytes| !bytes.is_empty())?;
            replay.extend_from_slice(bytes);
            match parser.feed(bytes) {
                SniStatus::NeedMore => {}
                SniStatus::Done(name) => return name,
                SniStatus::NotTls | SniStatus::Malformed => return None,
            }
        }
    };
    tokio::time::timeout(deadline, hello).await.ok().flatten()
}

/// Copies both directions until both have ended, one fails, or nothing has moved for `idle`. Dropping the
/// halves on return closes both connections.
async fn splice(guest: TcpStream, upstream: TcpStream, replay: Vec<u8>, idle: Duration) {
    // A relay must not add latency of its own; failing to set the option only costs latency.
    let _ = guest.set_nodelay(true);
    let _ = upstream.set_nodelay(true);
    let activity = Activity::new();
    let (guest_read, guest_write) = guest.into_split();
    let (upstream_read, upstream_write) = upstream.into_split();
    let outbound = pump(guest_read, upstream_write, replay, &activity);
    let inbound = pump(upstream_read, guest_write, Vec::new(), &activity);
    tokio::select! {
        ended = async { tokio::try_join!(outbound, inbound) } => {
            if let Err(error) = ended {
                tracing::debug!(%error, "relayed connection failed");
            }
        }
        () = activity.idle_for(idle) => tracing::debug!("relayed connection idle, closing"),
    }
}

/// One direction of a relayed connection. `head` goes first: the bytes read while looking for the server
/// name. End of stream is passed on as a half-close, so the other direction can still finish.
async fn pump(mut from: OwnedReadHalf, mut to: OwnedWriteHalf, head: Vec<u8>, activity: &Activity) -> io::Result<()> {
    to.write_all(&head).await?;
    drop(head);
    let mut buffer = vec![0u8; SPLICE_BUFFER_LEN];
    loop {
        let read = from.read(&mut buffer).await?;
        let Some(bytes) = buffer.get(..read).filter(|bytes| !bytes.is_empty()) else { break };
        to.write_all(bytes).await?;
        activity.touch();
    }
    to.shutdown().await
}

/// When bytes last moved in either direction, in milliseconds since the copy began.
#[derive(Debug)]
struct Activity {
    started: Instant,
    last_ms: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self { started: Instant::now(), last_ms: AtomicU64::new(0) }
    }

    fn touch(&self) {
        let elapsed = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_ms.store(elapsed, Ordering::Relaxed);
    }

    /// Resolves once `limit` has passed since the last movement.
    async fn idle_for(&self, limit: Duration) {
        loop {
            let seen = self.last_ms.load(Ordering::Relaxed);
            let quiet_until = Duration::from_millis(seen).saturating_add(limit);
            tokio::time::sleep(quiet_until.saturating_sub(self.started.elapsed())).await;
            if self.last_ms.load(Ordering::Relaxed) == seen {
                return;
            }
        }
    }
}
