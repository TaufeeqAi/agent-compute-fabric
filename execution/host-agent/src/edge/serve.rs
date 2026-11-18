//! The edge role (contract PD-1, PA-1, PA-2): accept, limit, authenticate, decode, validate, relay.
//!
//! The edge holds no state the system needs. If it dies, every caller sees a lost response and
//! resolves its operation by id (FS-5); nothing is half-done, because nothing is done here.
//!
//! Admission order, per connection and per request:
//!
//! ```text
//! transport limits     max_connections, per-source cap                       drop, counted
//! authentication       TLS 1.3 + client certificate | kernel peer credentials  within handshake_deadline
//! enrolment            credential → (peer_id, role)                          AUTHENTICATION_FAILED, closed
//! size-bounded decode  one frame ≤ max_request_bytes, within idle_timeout
//! protocol version                                                           PROTOCOL_ERROR
//! schema validation    envelope + method + params, strictly                  INVALID_REQUEST
//! relay to the core    which checks all of it again (PD-2)
//! ```
//!
//! An unauthenticated peer costs at most: one connection slot until `handshake_deadline`, and the
//! memory of one TLS handshake. It never causes a frame to be read.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use acf_wire::frame::{FrameError, aio};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, UnixListener, UnixStream},
    sync::{Semaphore, mpsc, oneshot, watch},
    task::JoinSet,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use super::{
    channel::{CHANNEL_SLACK, CoreMessage, EdgeInit, EdgeLimits, EdgeMessage, EdgeStats, MAX_CONTROL_FRAME},
    tls,
};
use crate::{
    api::{MAX_RESPONSE_FRAME, RequestEnvelope, ResponseEnvelope, protocol_supported},
    authority::Enrolment,
    coordinator::PeerContext,
    domain::{MAX_REQUEST_ID_BYTES, Method, Transport, validate_label},
    error::{AcfError, Result},
};

/// The listeners the core bound and handed over.
#[derive(Debug, Default)]
pub struct EdgeListeners {
    pub local: Option<UnixListener>,
    pub network: Option<TcpListener>,
}

#[derive(Debug, Default)]
struct Counters {
    accepted: AtomicU64,
    shed: AtomicU64,
    per_source_refused: AtomicU64,
    handshake_failures: AtomicU64,
    auth_denied: AtomicU64,
    invalid_requests: AtomicU64,
    relayed: AtomicU64,
    unanswered: AtomicU64,
}

impl Counters {
    fn take(&self) -> EdgeStats {
        let t = |c: &AtomicU64| c.swap(0, Ordering::Relaxed);
        EdgeStats {
            accepted: t(&self.accepted),
            shed: t(&self.shed),
            per_source_refused: t(&self.per_source_refused),
            handshake_failures: t(&self.handshake_failures),
            auth_denied: t(&self.auth_denied),
            invalid_requests: t(&self.invalid_requests),
            relayed: t(&self.relayed),
            unanswered: t(&self.unanswered),
        }
    }
}

struct Shared {
    limits: EdgeLimits,
    enrolment: watch::Receiver<Arc<Enrolment>>,
    acceptor: Option<TlsAcceptor>,
    conns: Arc<Semaphore>,
    per_source: Mutex<HashMap<String, usize>>,
    counters: Counters,
    to_core: mpsc::Sender<EdgeMessage>,
    pending: Mutex<HashMap<u64, oneshot::Sender<ResponseEnvelope>>>,
    next_id: AtomicU64,
    shutdown: CancellationToken,
}

/// Holds one slot of a source's connection budget; gives it back when dropped.
struct SourceSlot<'a> {
    shared: &'a Shared,
    source: String,
}

impl Drop for SourceSlot<'_> {
    fn drop(&mut self) {
        if let Ok(mut m) = self.shared.per_source.lock()
            && let Some(n) = m.get_mut(&self.source)
        {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.source);
            }
        }
    }
}

impl Shared {
    /// The per-source cap (PA-2): one peer address, or one local uid, cannot take every slot.
    fn admit_source(&self, source: String) -> Option<SourceSlot<'_>> {
        let mut m = self.per_source.lock().ok()?;
        let n = m.entry(source.clone()).or_insert(0);
        if *n >= self.limits.max_connections_per_source {
            return None;
        }
        *n += 1;
        Some(SourceSlot { shared: self, source })
    }

    fn enrolled(&self) -> Arc<Enrolment> {
        Arc::clone(&self.enrolment.borrow())
    }

    /// Relay one validated request to the core and wait for its answer.
    async fn relay(&self, peer: &PeerContext, envelope: RequestEnvelope) -> Result<ResponseEnvelope> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().map_err(|_| AcfError::internal("edge table poisoned"))?.insert(id, tx);
        let lost = || AcfError::internal("the core did not answer");
        if self.to_core.send(EdgeMessage::Request { id, peer: peer.clone(), envelope: Box::new(envelope) }).await.is_err() {
            return Err(lost());
        }
        self.counters.relayed.fetch_add(1, Ordering::Relaxed);
        match timeout(Duration::from_millis(self.limits.response_deadline_ms), rx).await {
            Ok(Ok(resp)) => Ok(resp),
            _ => {
                if let Ok(mut p) = self.pending.lock() {
                    p.remove(&id);
                }
                Err(lost())
            }
        }
    }
}

/// Best effort: the `request_id` of a frame that failed typed decoding, so the refusal can be
/// matched to the request that caused it. Bounded and validated, so nothing hostile is reflected.
fn recover_request_id(frame: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(frame).ok()?;
    let id = value.get("request_id")?.as_str()?;
    validate_label("request_id", id, MAX_REQUEST_ID_BYTES).ok().map(|()| id.to_owned())
}

async fn write<S: AsyncWrite + Unpin>(stream: &mut S, resp: &ResponseEnvelope) -> std::result::Result<(), FrameError> {
    aio::send_json(stream, resp, MAX_RESPONSE_FRAME).await
}

async fn refuse<S: AsyncWrite + Unpin>(stream: &mut S, request_id: Option<String>, e: &AcfError) -> bool {
    write(stream, &ResponseEnvelope::refused(request_id, e, None)).await.is_ok()
}

/// One authenticated connection: read a request, validate it, relay it, answer; repeat.
async fn session<S: AsyncRead + AsyncWrite + Unpin>(shared: &Shared, mut stream: S, peer: PeerContext) {
    let idle = Duration::from_millis(shared.limits.idle_timeout_ms.max(1));
    let mut enrolment = shared.enrolment.clone();
    loop {
        // AU-5: resolves only when this peer is no longer enrolled. The connection is then closed,
        // so abandoning a half-read frame is harmless.
        let revoked = async {
            loop {
                if !enrolment.borrow_and_update().grants(&peer.peer_id, peer.role) {
                    return;
                }
                if enrolment.changed().await.is_err() {
                    std::future::pending::<()>().await;
                }
            }
        };
        let frame = tokio::select! {
            biased;
            () = shared.shutdown.cancelled() => return,
            () = revoked => {
                refuse(&mut stream, None, &AcfError::authentication("this peer is no longer enrolled on this host")).await;
                return;
            }
            r = timeout(idle, aio::read_frame(&mut stream, shared.limits.max_request_bytes)) => r,
        };
        let frame = match frame {
            Err(_) | Ok(Err(FrameError::Eof)) => return,
            Ok(Err(e @ (FrameError::TooLarge { .. } | FrameError::Truncated | FrameError::Io(_)))) => {
                shared.counters.invalid_requests.fetch_add(1, Ordering::Relaxed);
                refuse(&mut stream, None, &AcfError::validation(format!("bad frame: {e}"))).await;
                return;
            }
            Ok(Err(FrameError::Decode(_))) => return,
            Ok(Ok(f)) => f,
        };
        let envelope: RequestEnvelope = match serde_json::from_slice(&frame) {
            Ok(e) => e,
            Err(e) => {
                // Framing is intact, so keep the connection and say precisely what was wrong.
                shared.counters.invalid_requests.fetch_add(1, Ordering::Relaxed);
                let said = crate::api::decode_error(&e);
                if !refuse(&mut stream, recover_request_id(&frame), &AcfError::validation(format!("malformed request: {said}"))).await {
                    return;
                }
                continue;
            }
        };
        let request_id = envelope.request_id.clone().filter(|r| validate_label("request_id", r, MAX_REQUEST_ID_BYTES).is_ok());
        let creates_operation = Method::parse(&envelope.method).is_some_and(Method::requires_operation);
        let early = if !protocol_supported(&envelope.protocol) {
            Some(AcfError::protocol(format!("this host speaks `{}`", crate::api::PROTOCOL)))
        } else {
            // Schema validation happens here, without privilege (PD-1). The core repeats it.
            envelope.clone().validate().err()
        };
        let response = match early {
            Some(e) => {
                shared.counters.invalid_requests.fetch_add(1, Ordering::Relaxed);
                ResponseEnvelope::refused(request_id, &e, None)
            }
            None => match shared.relay(&peer, envelope).await {
                Ok(r) => r,
                // The core did not answer. It may have accepted the request all the same, and `REFUSED`
                // states that no operation record exists (§10.4): the edge cannot say that. It says
                // nothing and closes; the caller sees a lost response and resolves the operation by
                // its id (FS-5, API-8).
                Err(_) if creates_operation => {
                    shared.counters.unanswered.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                // A read created nothing whatever happened to it, so refusing it is the truth.
                Err(e) => ResponseEnvelope::refused(request_id, &e, None),
            },
        };
        if write(&mut stream, &response).await.is_err() {
            return; // the caller went away: an accepted operation is already durable (FS-6)
        }
    }
}

async fn serve_local(shared: &Shared, mut stream: UnixStream) {
    let cred = stream.peer_cred().ok();
    let Some(_slot) = shared.admit_source(format!("uid:{}", cred.as_ref().map_or(u32::MAX, tokio::net::unix::UCred::uid))) else {
        shared.counters.per_source_refused.fetch_add(1, Ordering::Relaxed);
        return;
    };
    // No credentials: fail closed. There is no anonymous mode.
    let entry = cred.and_then(|c| shared.enrolled().match_local(c.uid(), c.gid()).cloned());
    let Some(entry) = entry else {
        shared.counters.auth_denied.fetch_add(1, Ordering::Relaxed);
        refuse(&mut stream, None, &AcfError::authentication("this local caller is not enrolled on this host")).await;
        let _ = stream.shutdown().await;
        return;
    };
    session(shared, stream, PeerContext { peer_id: entry.peer_id, role: entry.role, transport: Transport::Local }).await;
}

async fn serve_network(shared: &Shared, tcp: tokio::net::TcpStream, source: std::net::IpAddr) {
    let Some(acceptor) = &shared.acceptor else { return };
    let Some(_slot) = shared.admit_source(format!("ip:{source}")) else {
        shared.counters.per_source_refused.fetch_add(1, Ordering::Relaxed);
        return;
    };
    // The handshake - including the client certificate - must finish within its deadline (PA-2).
    let deadline = Duration::from_millis(shared.limits.handshake_deadline_ms);
    let mut stream = match timeout(deadline, acceptor.accept(tcp)).await {
        Ok(Ok(s)) => s,
        _ => {
            shared.counters.handshake_failures.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    // Chain-valid is authentication. Authority needs an enrolment entry for this very credential (AU-2).
    let entry = stream.get_ref().1.peer_certificates().and_then(<[_]>::first).and_then(|leaf| {
        let (certificate, spki) = tls::fingerprints(leaf);
        shared.enrolled().match_mtls(&certificate, spki.as_deref()).cloned()
    });
    let Some(entry) = entry else {
        shared.counters.auth_denied.fetch_add(1, Ordering::Relaxed);
        refuse(&mut stream, None, &AcfError::authentication("this certificate is not enrolled on this host")).await;
        let _ = stream.shutdown().await;
        return;
    };
    session(shared, stream, PeerContext { peer_id: entry.peer_id, role: entry.role, transport: Transport::Mtls }).await;
}

async fn accept_local(listener: &Option<UnixListener>) -> Option<UnixStream> {
    match listener {
        Some(l) => l.accept().await.ok().map(|(s, _)| s),
        None => std::future::pending().await,
    }
}

async fn accept_network(listener: &Option<TcpListener>) -> Option<(tokio::net::TcpStream, std::net::SocketAddr)> {
    match listener {
        Some(l) => l.accept().await.ok(),
        None => std::future::pending().await,
    }
}

/// Run the edge until `shutdown`, the core says so, or the channel to the core closes.
pub async fn run(init: EdgeInit, listeners: EdgeListeners, core: UnixStream, shutdown: CancellationToken) -> Result<()> {
    let acceptor = match (&init.tls, &listeners.network) {
        (Some(material), Some(_)) => Some(TlsAcceptor::from(tls::server_config(material)?)),
        _ => None,
    };
    let enrolment = Enrolment::from_doc(init.enrolment, String::new())?;
    let (enrol_tx, enrol_rx) = watch::channel(Arc::new(enrolment));
    let (to_core, mut outbox) = mpsc::channel::<EdgeMessage>(init.limits.max_connections.max(1) * 2);
    let shared = Arc::new(Shared {
        conns: Arc::new(Semaphore::new(init.limits.max_connections.max(1))),
        limits: init.limits,
        enrolment: enrol_rx,
        acceptor,
        per_source: Mutex::default(),
        counters: Counters::default(),
        to_core,
        pending: Mutex::default(),
        next_id: AtomicU64::new(1),
        shutdown: shutdown.clone(),
    });
    let (mut from_core, mut into_core) = core.into_split();

    // Core → edge: answers, enrolment updates, shutdown.
    let reader = {
        let (shared, shutdown) = (Arc::clone(&shared), shutdown.clone());
        tokio::spawn(async move {
            loop {
                let msg: CoreMessage = match aio::recv_json(&mut from_core, MAX_RESPONSE_FRAME + CHANNEL_SLACK).await {
                    Ok(m) => m,
                    Err(_) => break, // the core is gone: nothing here is worth keeping
                };
                match msg {
                    CoreMessage::Response { id, response } => {
                        if let Some(tx) = shared.pending.lock().ok().and_then(|mut p| p.remove(&id)) {
                            let _ = tx.send(*response);
                        }
                    }
                    CoreMessage::Enrolment { doc } => match Enrolment::from_doc(doc, String::new()) {
                        Ok(e) => {
                            let _ = enrol_tx.send(Arc::new(e));
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "the core sent an enrolment table the edge cannot use; keeping the previous one")
                        }
                    },
                    CoreMessage::Shutdown => break,
                }
            }
            shutdown.cancel();
        })
    };
    // Edge → core: requests and periodic counters.
    let writer = {
        let (shared, shutdown) = (Arc::clone(&shared), shutdown.clone());
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(2));
            loop {
                let msg = tokio::select! {
                    () = shutdown.cancelled() => break,
                    m = outbox.recv() => match m { Some(m) => m, None => break },
                    _ = tick.tick() => {
                        let stats = shared.counters.take();
                        if stats.is_empty() { continue }
                        EdgeMessage::Stats { stats }
                    }
                };
                if aio::send_json(&mut into_core, &msg, shared.limits.max_request_bytes.max(MAX_CONTROL_FRAME) + CHANNEL_SLACK)
                    .await
                    .is_err()
                {
                    break;
                }
            }
            shutdown.cancel();
        })
    };

    let mut sessions: JoinSet<()> = JoinSet::new();
    loop {
        // Shed load rather than queue it: a connection beyond `max_connections` is dropped.
        let spawn = |sessions: &mut JoinSet<()>, fut: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>| match Arc::clone(
            &shared.conns,
        )
        .try_acquire_owned()
        {
            Ok(permit) => {
                shared.counters.accepted.fetch_add(1, Ordering::Relaxed);
                sessions.spawn(async move {
                    fut.await;
                    drop(permit);
                });
            }
            Err(_) => {
                shared.counters.shed.fetch_add(1, Ordering::Relaxed);
            }
        };
        tokio::select! {
            () = shutdown.cancelled() => break,
            Some(stream) = accept_local(&listeners.local) => {
                let s = Arc::clone(&shared);
                spawn(&mut sessions, Box::pin(async move { serve_local(&s, stream).await }));
            }
            Some((tcp, addr)) = accept_network(&listeners.network) => {
                let s = Arc::clone(&shared);
                spawn(&mut sessions, Box::pin(async move { serve_network(&s, tcp, addr.ip()).await }));
            }
            Some(_) = sessions.join_next(), if !sessions.is_empty() => {}
        }
    }
    // Operations already accepted are durable in the core; the sessions are only conversations.
    sessions.abort_all();
    reader.abort();
    writer.abort();
    Ok(())
}

/// Marker that accompanies the listeners' descriptors.
const INIT_MARKER: &[u8] = b"acf-edge-init";

/// Core side: hand the edge its listeners and its init document. The descriptors travel with a small
/// marker message; the document follows as an ordinary frame, so its size never matters to the
/// descriptor passing.
pub fn send_init(
    channel: &mut std::os::unix::net::UnixStream,
    init: &EdgeInit,
    local: Option<std::os::fd::BorrowedFd<'_>>,
    network: Option<std::os::fd::BorrowedFd<'_>>,
) -> Result<()> {
    if init.local != local.is_some() || init.network != network.is_some() {
        return Err(AcfError::internal("the init document and the listeners passed with it disagree"));
    }
    let fds: Vec<_> = local.into_iter().chain(network).collect();
    crate::privsep::send_with_fds(channel, INIT_MARKER, &fds)?;
    acf_wire::frame::send_json(channel, init, MAX_CONTROL_FRAME)
        .map_err(|e| AcfError::internal(format!("cannot send the edge its init document: {e}")))
}

/// Edge side: the first thing the edge does with its channel.
pub fn receive_init(
    channel: &mut std::os::unix::net::UnixStream,
) -> Result<(EdgeInit, Option<std::os::unix::net::UnixListener>, Option<std::net::TcpListener>)> {
    let (marker, fds) = crate::privsep::recv_with_fds(channel, INIT_MARKER.len())?;
    if marker != INIT_MARKER {
        return Err(AcfError::internal("the channel did not start with the core's init marker"));
    }
    let init: EdgeInit = acf_wire::frame::recv_json(channel, MAX_CONTROL_FRAME)
        .map_err(|e| AcfError::internal(format!("the core's init document is not valid: {e}")))?;
    let mut fds = fds.into_iter();
    let local = if init.local {
        Some(std::os::unix::net::UnixListener::from(fds.next().ok_or_else(|| AcfError::internal("the local listener was not passed"))?))
    } else {
        None
    };
    let network = if init.network {
        Some(std::net::TcpListener::from(fds.next().ok_or_else(|| AcfError::internal("the network listener was not passed"))?))
    } else {
        None
    };
    Ok((init, local, network))
}

/// The edge role's process entry point (`acf-host edge`). The process entered the role before it
/// had any thread ([`crate::privsep::enter_role`]); here the serving thread proves that it is
/// unprivileged before it reads anything (INV-025), then takes its listeners and configuration from
/// the channel the core started it with. It opens nothing by name.
pub async fn role_main(shutdown: CancellationToken) -> Result<()> {
    crate::privsep::verify_unprivileged("edge")?;
    let mut channel = crate::privsep::role_channel()?;
    let (init, local, network) = receive_init(&mut channel)?;
    channel.set_nonblocking(true)?;
    let listeners = EdgeListeners {
        local: local
            .map(|l| {
                l.set_nonblocking(true)?;
                UnixListener::from_std(l)
            })
            .transpose()?,
        network: network
            .map(|l| {
                l.set_nonblocking(true)?;
                TcpListener::from_std(l)
            })
            .transpose()?,
    };
    run(init, listeners, UnixStream::from_std(channel)?, shutdown).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api::PROTOCOL,
        domain::{PeerId, Role},
        error::FailureClass,
    };

    /// An edge whose core never answers. The receiver is returned so that the channel stays open.
    fn deaf_core(response_deadline_ms: u64) -> (Arc<Shared>, mpsc::Receiver<EdgeMessage>, watch::Sender<Arc<Enrolment>>) {
        let enrolment = Enrolment::parse(
            b"schema_version: 1\npeers:\n  - { peer_id: tester, role: operator, match: { local_uid: 4242 } }\n",
            String::new(),
        )
        .unwrap();
        let (enrol_tx, enrol_rx) = watch::channel(Arc::new(enrolment));
        let (to_core, outbox) = mpsc::channel(8);
        let shared = Shared {
            limits: EdgeLimits {
                max_connections: 4,
                max_connections_per_source: 4,
                max_request_bytes: 64 * 1024,
                handshake_deadline_ms: 1_000,
                idle_timeout_ms: 5_000,
                response_deadline_ms,
            },
            enrolment: enrol_rx,
            acceptor: None,
            conns: Arc::new(Semaphore::new(4)),
            per_source: Mutex::default(),
            counters: Counters::default(),
            to_core,
            pending: Mutex::default(),
            next_id: AtomicU64::new(1),
            shutdown: CancellationToken::new(),
        };
        (Arc::new(shared), outbox, enrol_tx)
    }

    fn request(method: &str, params: serde_json::Value) -> serde_json::Value {
        let mut env = serde_json::json!({"protocol": PROTOCOL, "request_id": "req-1", "owner_scope": "scope-a", "method": method});
        if !params.is_null() {
            env["params"] = params;
        }
        if Method::parse(method).is_some_and(Method::requires_operation) {
            env["operation_id"] = serde_json::json!("op-0123456789abcdef");
            env["issued_at"] = serde_json::json!("2026-01-01T00:00:00.000Z");
        }
        env
    }

    /// §10.4, FS-5: `REFUSED` says that no operation record exists. When the core does not answer, the
    /// edge cannot know that about a request that creates an operation, so it must not say it. The
    /// caller is left with a lost response, which it resolves by the operation's id.
    #[tokio::test]
    async fn an_unanswered_operation_request_gets_no_answer_and_an_unanswered_read_is_refused() {
        let peer = PeerContext { peer_id: PeerId::parse("tester").unwrap(), role: Role::Operator, transport: Transport::Local };

        // A method that creates an operation: no frame comes back, and the connection ends.
        let (shared, _outbox, _enrolment) = deaf_core(50);
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let serving = {
            let (shared, peer) = (Arc::clone(&shared), peer.clone());
            tokio::spawn(async move { session(&shared, server, peer).await })
        };
        let create = request(
            "sandbox.create",
            serde_json::json!({"image": "python", "resources": {"vcpus": 1, "memory_mib": 256, "disk_mib": 128, "network": {"mode": "none"}}}),
        );
        aio::send_json(&mut client, &create, 64 * 1024).await.unwrap();
        let answer = aio::recv_json::<_, serde_json::Value>(&mut client, MAX_RESPONSE_FRAME).await;
        assert!(matches!(answer, Err(FrameError::Eof)), "an answer was sent for a request the core may have accepted: {answer:?}");
        serving.await.unwrap();
        assert_eq!(shared.counters.take().unanswered, 1, "the lost response is counted");

        // A read creates nothing whatever happened to it: refusing it is the truth, and the connection stays.
        let (shared, _outbox, _enrolment) = deaf_core(50);
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let serving = {
            let (shared, peer) = (Arc::clone(&shared), peer.clone());
            tokio::spawn(async move { session(&shared, server, peer).await })
        };
        for _ in 0..2 {
            aio::send_json(&mut client, &request("host.info", serde_json::Value::Null), 64 * 1024).await.unwrap();
            let answer: ResponseEnvelope = aio::recv_json(&mut client, MAX_RESPONSE_FRAME).await.unwrap();
            assert_eq!(answer.refusal().map(|r| r.class), Some(FailureClass::InternalError), "{answer:?}");
        }
        assert_eq!(shared.counters.take().unanswered, 0);
        drop(client);
        serving.await.unwrap();
    }
}
