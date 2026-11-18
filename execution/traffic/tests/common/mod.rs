//! Shared fixtures for the loopback integration tests.
//!
//! The role runs for real on two 127.0.0.1 sockets. Its three effects are replaced: the upstream resolver by a
//! table, the packet filter's original destination by a table keyed on the client's source port, and the
//! outside world by a table that maps "public" addresses such as 198.51.100.10 to local test servers.

#![allow(dead_code)]

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use acf_traffic::policy::{DestinationSpec, DnsName, EntrySpec, PortRange};
use acf_traffic::relay::{Connector, OriginalDst};
use acf_traffic::resolver::Upstream;
use acf_traffic::role::{RoleConfig, RoleError, Shared, StatsSnapshot, run_with};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// Upper bound on every wait, so a failing test fails instead of hanging.
pub(crate) const TIMEOUT: Duration = Duration::from_secs(10);
/// What the echo server appends when its peer half-closes.
pub(crate) const TRAILER: &[u8] = b"<end of echo>";

pub(crate) const QTYPE_A: u16 = 1;
pub(crate) const QTYPE_AAAA: u16 = 28;
pub(crate) const NOERROR: u8 = 0;
pub(crate) const FORMERR: u8 = 1;
pub(crate) const SERVFAIL: u8 = 2;
pub(crate) const NOTIMP: u8 = 4;
pub(crate) const REFUSED: u8 = 5;

pub(crate) fn ip(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

pub(crate) fn v4(addr: SocketAddr) -> SocketAddrV4 {
    match addr {
        SocketAddr::V4(v4) => v4,
        SocketAddr::V6(_) => panic!("the tests only use IPv4"),
    }
}

pub(crate) fn name_entry(name: &str, port: u16) -> EntrySpec {
    EntrySpec { destination: DestinationSpec::Name(name.into()), ports: vec![PortRange { from: port, to: port }] }
}

pub(crate) fn network_entry(network: &str, port: u16) -> EntrySpec {
    EntrySpec { destination: DestinationSpec::Network(network.into()), ports: vec![PortRange { from: port, to: port }] }
}

/// Two name entries and one network entry. The network entry also covers a host address and another
/// sandbox's network, which must stay unreachable all the same.
pub(crate) fn config() -> RoleConfig {
    RoleConfig {
        entries: vec![name_entry("api.example.com", 443), name_entry("git.example.com", 22), network_entry("203.0.113.0/24", 5432)],
        private_destinations: false,
        max_entries: 16,
        host_addresses: vec![ip("203.0.113.1")],
        sandbox_networks: vec!["203.0.113.128/25".into()],
        dns_binding_ttl_ms: 30_000,
        max_bindings: 16,
        max_connections: 16,
        max_pending_lookups: 4,
        sni_deadline_ms: 5_000,
        connect_deadline_ms: 5_000,
        idle_timeout_ms: 30_000,
        upstream_timeout_ms: 5_000,
    }
}

#[derive(Clone)]
pub(crate) enum Answer {
    Addresses(Vec<Ipv4Addr>),
    Fail,
    Hang,
}

/// The upstream resolver: a table, and a count of how often it was consulted.
#[derive(Clone, Default)]
pub(crate) struct FakeUpstream {
    answers: Arc<Mutex<HashMap<String, Answer>>>,
    calls: Arc<AtomicUsize>,
}

impl FakeUpstream {
    pub(crate) fn set(&self, name: &str, answer: Answer) {
        self.answers.lock().unwrap().insert(name.to_owned(), answer);
    }

    pub(crate) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Upstream for FakeUpstream {
    async fn lookup_a(&self, name: &DnsName) -> io::Result<Vec<Ipv4Addr>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let answer = self.answers.lock().unwrap().get(name.as_str()).cloned();
        match answer {
            Some(Answer::Addresses(addresses)) => Ok(addresses),
            Some(Answer::Hang) => std::future::pending().await,
            Some(Answer::Fail) | None => Err(io::Error::other("upstream has no answer")),
        }
    }
}

/// The packet filter: the destination each client connection was "redirected" from, by client source port.
#[derive(Clone, Default)]
pub(crate) struct FakeOriginalDst {
    by_client_port: Arc<Mutex<HashMap<u16, SocketAddrV4>>>,
}

impl OriginalDst for FakeOriginalDst {
    fn original_dst(&self, stream: &TcpStream) -> io::Result<SocketAddrV4> {
        let client = stream.peer_addr()?;
        self.by_client_port.lock().unwrap().get(&client.port()).copied().ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Route {
    To(SocketAddr),
    Hang,
}

/// The outside world: which local server stands for which public address, and every connection attempted.
#[derive(Clone, Default)]
pub(crate) struct FakeConnector {
    routes: Arc<Mutex<HashMap<SocketAddrV4, Route>>>,
    attempts: Arc<Mutex<Vec<SocketAddrV4>>>,
}

impl FakeConnector {
    pub(crate) fn route(&self, public: &str, route: Route) {
        self.routes.lock().unwrap().insert(public.parse().unwrap(), route);
    }

    pub(crate) fn attempts(&self) -> Vec<SocketAddrV4> {
        self.attempts.lock().unwrap().clone()
    }
}

impl Connector for FakeConnector {
    async fn connect(&self, addr: SocketAddrV4) -> io::Result<TcpStream> {
        self.attempts.lock().unwrap().push(addr);
        let route = self.routes.lock().unwrap().get(&addr).copied();
        match route {
            Some(Route::To(local)) => TcpStream::connect(local).await,
            Some(Route::Hang) => std::future::pending().await,
            None => Err(io::Error::from(io::ErrorKind::ConnectionRefused)),
        }
    }
}

/// A destination that echoes what it receives and, once its peer half-closes, appends [`TRAILER`] and
/// closes. The trailer only arrives if the half-close was passed on and the return path stayed open.
pub(crate) async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(read) => {
                            if stream.write_all(&buffer[..read]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
                let _ = stream.write_all(TRAILER).await;
            });
        }
    });
    addr
}

pub(crate) struct Reply {
    pub(crate) id: u16,
    pub(crate) rcode: u8,
    pub(crate) answers: Vec<Ipv4Addr>,
    pub(crate) ttls: Vec<u32>,
    pub(crate) raw: Vec<u8>,
}

/// A standard query with recursion desired, as a stub resolver sends it.
pub(crate) fn dns_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    for word in [id, 0x0100, 1, 0, 0, 0] {
        packet.extend_from_slice(&word.to_be_bytes());
    }
    for label in name.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet
}

/// Reads a response whose question section is `question_len` bytes long (0 for a header-only response).
pub(crate) fn parse_reply(raw: &[u8], question_len: usize) -> Reply {
    let word = |at: usize| u16::from_be_bytes([raw[at], raw[at + 1]]);
    let (id, flags, questions, answer_count) = (word(0), word(2), word(4), word(6));
    assert!(flags & 0x8000 != 0, "the response bit is set");
    assert!(raw.len() <= 512, "responses fit in 512 bytes");
    assert_eq!(usize::from(questions), usize::from(question_len > 0));
    let mut records = &raw[12 + question_len..];
    let (mut answers, mut ttls) = (Vec::new(), Vec::new());
    for _ in 0..answer_count {
        assert_eq!(&records[..6], &[0xc0, 0x0c, 0, 1, 0, 1], "an A record named by a pointer to the question");
        assert_eq!(&records[10..12], &[0, 4]);
        ttls.push(u32::from_be_bytes([records[6], records[7], records[8], records[9]]));
        answers.push(Ipv4Addr::new(records[12], records[13], records[14], records[15]));
        records = &records[16..];
    }
    assert!(records.is_empty(), "nothing follows the answers");
    Reply { id, rcode: (flags & 0x000f) as u8, answers, ttls, raw: raw.to_vec() }
}

/// A small but well-formed TLS 1.3 ClientHello in one record, with an unknown extension before the name.
pub(crate) fn client_hello(server_name: &str) -> Vec<u8> {
    hello_record(Some(server_name))
}

/// The same hello with no `server_name` extension at all.
pub(crate) fn client_hello_without_name() -> Vec<u8> {
    hello_record(None)
}

fn hello_record(server_name: Option<&str>) -> Vec<u8> {
    let be16 = |len: usize| u16::try_from(len).unwrap().to_be_bytes();
    let mut extensions = vec![0x2a, 0x2a, 0, 0];
    if let Some(name) = server_name.map(str::as_bytes) {
        extensions.extend_from_slice(&[0, 0]);
        extensions.extend_from_slice(&be16(name.len() + 5));
        extensions.extend_from_slice(&be16(name.len() + 3));
        extensions.push(0);
        extensions.extend_from_slice(&be16(name.len()));
        extensions.extend_from_slice(name);
    }
    extensions.extend_from_slice(&[0x00, 0x2b, 0, 3, 2, 3, 4]);

    let mut body = vec![3, 3];
    body.extend_from_slice(&[7; 32]);
    body.push(0);
    body.extend_from_slice(&[0, 2, 0x13, 0x01]);
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&be16(extensions.len()));
    body.extend_from_slice(&extensions);

    let mut record = vec![22, 3, 1];
    record.extend_from_slice(&be16(body.len() + 4));
    record.extend_from_slice(&[1, 0]);
    record.extend_from_slice(&be16(body.len()));
    record.extend_from_slice(&body);
    record
}

/// A running role and the handles to steer its fakes.
pub(crate) struct Harness {
    pub(crate) shared: Arc<Shared>,
    pub(crate) resolver: SocketAddr,
    pub(crate) relay: SocketAddr,
    pub(crate) upstream: FakeUpstream,
    pub(crate) original: FakeOriginalDst,
    pub(crate) connector: FakeConnector,
    stop: oneshot::Sender<()>,
    role: JoinHandle<Result<(), RoleError>>,
}

impl Harness {
    pub(crate) async fn start(config: RoleConfig) -> Self {
        let shared = Shared::new(&config).unwrap();
        let resolver_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (resolver, relay) = (resolver_socket.local_addr().unwrap(), relay_listener.local_addr().unwrap());
        let (upstream, original, connector) = (FakeUpstream::default(), FakeOriginalDst::default(), FakeConnector::default());
        let (stop, stopped) = oneshot::channel::<()>();
        let shutdown = async move {
            let _ = stopped.await;
        };
        let role =
            run_with(Arc::clone(&shared), resolver_socket, relay_listener, upstream.clone(), original.clone(), connector.clone(), shutdown);
        Self { shared, resolver, relay, upstream, original, connector, stop, role: tokio::spawn(role) }
    }

    /// Asks the role to stop and waits until it has returned.
    pub(crate) async fn stop(self) -> Result<(), RoleError> {
        let _ = self.stop.send(());
        tokio::time::timeout(TIMEOUT, self.role).await.expect("the role stops promptly").expect("the role does not panic")
    }

    pub(crate) fn stats(&self) -> StatsSnapshot {
        self.shared.stats()
    }

    /// How often connections were denied for `reason`.
    pub(crate) fn denied(&self, reason: &str) -> u64 {
        self.stats().denied_by_reason.get(reason).copied().unwrap_or(0)
    }

    /// Sends `packet` from a fresh socket and returns the first datagram that comes back.
    pub(crate) async fn exchange(&self, packet: &[u8]) -> Vec<u8> {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.send_to(packet, self.resolver).await.unwrap();
        receive(&socket).await
    }

    /// Resolves `name` like a guest would and returns the parsed reply.
    pub(crate) async fn resolve(&self, name: &str, qtype: u16) -> Reply {
        let query = dns_query(0x4242, name, qtype);
        let reply = parse_reply(&self.exchange(&query).await, query.len() - 12);
        assert_eq!(reply.id, 0x4242);
        assert_eq!(&reply.raw[12..query.len()], &query[12..], "the question is echoed verbatim");
        reply
    }

    /// Makes the upstream answer `name` with `address`, resolves it as the guest, and so binds the pair.
    pub(crate) async fn bind(&self, name: &str, address: &str) {
        self.upstream.set(name, Answer::Addresses(vec![ip(address)]));
        let reply = self.resolve(name, QTYPE_A).await;
        assert_eq!((reply.rcode, reply.answers), (NOERROR, vec![ip(address)]));
    }

    /// Opens a guest connection that the packet filter "redirected" from `destination`.
    pub(crate) async fn dial(&self, destination: &str) -> TcpStream {
        self.dial_with(Some(destination.parse().unwrap())).await
    }

    pub(crate) async fn dial_with(&self, destination: Option<SocketAddrV4>) -> TcpStream {
        let socket = TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let port = socket.local_addr().unwrap().port();
        if let Some(destination) = destination {
            self.original.by_client_port.lock().unwrap().insert(port, destination);
        }
        tokio::time::timeout(TIMEOUT, socket.connect(self.relay)).await.expect("the relay accepts").unwrap()
    }
}

pub(crate) async fn receive(socket: &UdpSocket) -> Vec<u8> {
    let mut buffer = [0u8; 2048];
    let (len, _) = tokio::time::timeout(TIMEOUT, socket.recv_from(&mut buffer)).await.expect("a reply arrives").unwrap();
    buffer[..len].to_vec()
}

/// Reads until the peer closes; a reset counts as closed. Returns what arrived before.
pub(crate) async fn read_until_closed(stream: &mut TcpStream) -> Vec<u8> {
    let mut received = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        match tokio::time::timeout(TIMEOUT, stream.read(&mut buffer)).await.expect("the connection is closed in time") {
            Ok(0) | Err(_) => return received,
            Ok(read) => received.extend_from_slice(&buffer[..read]),
        }
    }
}

/// Reads exactly `len` bytes.
pub(crate) async fn read_exact(stream: &mut TcpStream, len: usize) -> Vec<u8> {
    let mut received = vec![0u8; len];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut received)).await.expect("the bytes arrive in time").unwrap();
    received
}
