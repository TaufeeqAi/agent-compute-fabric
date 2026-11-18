//! The relay on real TCP sockets: what an entry allows passes both ways (AL-4, AL-5), everything else is
//! closed (AL-2, AL-6), every wait and count is bounded, and nothing survives the role (NW-1).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::ErrorKind;
use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

use acf_traffic::relay::{Connector, DirectConnector};
use acf_traffic::role::{RoleConfig, StatsSnapshot, run};
use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// A role whose `api.example.com` is bound to 198.51.100.10, which stands for a local echo server.
async fn role_with_bound_api(config: RoleConfig) -> Harness {
    let role = Harness::start(config).await;
    role.connector.route("198.51.100.10:443", Route::To(echo_server().await));
    role.bind("api.example.com", "198.51.100.10").await;
    role
}

/// Sends `hello` to `destination` and expects the relay to close without a byte coming back.
async fn expect_denied(role: &Harness, destination: &str, hello: &[u8], reason: &str) {
    let before = role.denied(reason);
    let mut guest = role.dial(destination).await;
    // The relay may already have closed a destination it never needs to read from; then the write fails.
    let _ = guest.write_all(hello).await;
    assert!(read_until_closed(&mut guest).await.is_empty(), "{destination}: nothing is relayed back");
    assert_eq!(role.denied(reason), before + 1, "{destination} is denied as {reason}: {:?}", role.stats().denied_by_reason);
}

#[tokio::test]
async fn a_name_entry_relays_tls_both_ways_and_passes_on_the_half_close() {
    let role = role_with_bound_api(config()).await;
    let hello = client_hello("api.example.com");
    let payload = vec![0xabu8; 100_000];

    let mut guest = role.dial("198.51.100.10:443").await;
    // The hello arrives in three segments; the relay has to reassemble it before it can decide.
    for part in [&hello[..3], &hello[3..40], &hello[40..]] {
        guest.write_all(part).await.unwrap();
        guest.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(read_exact(&mut guest, hello.len()).await, hello, "the bytes read to find the name are replayed, once");

    let (mut read_half, mut write_half) = guest.split();
    let send = async {
        write_half.write_all(&payload).await.unwrap();
        write_half.shutdown().await.unwrap();
    };
    let receive = async {
        let mut echoed = Vec::new();
        tokio::time::timeout(TIMEOUT, read_half.read_to_end(&mut echoed)).await.unwrap().unwrap();
        echoed
    };
    let ((), echoed) = tokio::join!(send, receive);
    assert_eq!(echoed.len(), payload.len() + TRAILER.len());
    assert_eq!(&echoed[..payload.len()], &payload[..]);
    assert_eq!(&echoed[payload.len()..], TRAILER, "the destination saw the half-close and could still answer");

    assert_eq!(
        role.connector.attempts(),
        ["198.51.100.10:443".parse::<SocketAddrV4>().unwrap()],
        "connected to exactly the dialled address"
    );
    let stats = role.stats();
    assert_eq!((stats.connections, stats.connections_allowed, stats.connections_denied, stats.connections_shed), (1, 1, 0, 0));
    role.stop().await.unwrap();
}

#[tokio::test]
async fn a_different_server_name_on_a_bound_address_is_denied() {
    let role = role_with_bound_api(config()).await;
    role.bind("git.example.com", "198.51.100.20").await;
    expect_denied(&role, "198.51.100.10:443", &client_hello("evil.example.net"), "name_not_listed").await;
    // A listed name does not help either: the address is bound to another name, and the port is not its own.
    expect_denied(&role, "198.51.100.10:443", &client_hello("git.example.com"), "port_not_listed").await;
    expect_denied(&role, "198.51.100.10:22", &client_hello("git.example.com"), "address_not_bound").await;
    expect_denied(&role, "198.51.100.10:443", &client_hello("198.51.100.10"), "no_server_name").await;
    assert!(role.connector.attempts().is_empty(), "a denied connection never leaves the role");
    role.stop().await.unwrap();
}

#[tokio::test]
async fn an_address_the_resolver_never_returned_is_denied() {
    let role = role_with_bound_api(config()).await;
    role.connector.route("198.51.100.99:443", Route::To(echo_server().await));
    // DNS rebinding: the name is allowed and resolved, but not to this address.
    expect_denied(&role, "198.51.100.99:443", &client_hello("api.example.com"), "address_not_bound").await;
    // A name that was never resolved by this sandbox has no address at all.
    expect_denied(&role, "198.51.100.20:22", &client_hello("git.example.com"), "address_not_bound").await;
    assert!(role.connector.attempts().is_empty());
    role.stop().await.unwrap();
}

#[tokio::test]
async fn a_binding_that_expired_is_denied() {
    let role = role_with_bound_api(RoleConfig { dns_binding_ttl_ms: 50, ..config() }).await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    expect_denied(&role, "198.51.100.10:443", &client_hello("api.example.com"), "address_not_bound").await;
    assert!(role.connector.attempts().is_empty());
    role.stop().await.unwrap();
}

/// Reads `len` bytes, or less if the relay closes first.
async fn read_until_closed_or(stream: &mut TcpStream, len: usize) -> Vec<u8> {
    let mut received = vec![0u8; len];
    let read = tokio::time::timeout(TIMEOUT, stream.read_exact(&mut received)).await.unwrap();
    if read.is_ok() { received } else { Vec::new() }
}

#[tokio::test]
async fn an_unlisted_port_is_denied() {
    let role = role_with_bound_api(config()).await;
    // 22 is listed, but for another name; 8443 is listed for no name at all, so no hello is even awaited.
    expect_denied(&role, "198.51.100.10:22", &client_hello("api.example.com"), "port_not_listed").await;
    expect_denied(&role, "198.51.100.10:8443", &client_hello("api.example.com"), "no_matching_entry").await;
    expect_denied(&role, "203.0.113.5:5433", b"plain", "no_matching_entry").await;
    assert!(role.connector.attempts().is_empty());
    role.stop().await.unwrap();
}

#[tokio::test]
async fn a_network_entry_relays_plain_tcp() {
    let role = Harness::start(config()).await;
    role.connector.route("203.0.113.5:5432", Route::To(echo_server().await));
    let mut guest = role.dial("203.0.113.5:5432").await;
    // No TLS, no server name, no lookup: the entry names the address and the port (AL-5).
    guest.write_all(b"plain text, not a ClientHello").await.unwrap();
    assert_eq!(read_exact(&mut guest, 29).await, b"plain text, not a ClientHello");
    guest.shutdown().await.unwrap();
    assert_eq!(read_until_closed(&mut guest).await, TRAILER);
    assert_eq!((role.stats().connections_allowed, role.upstream.calls()), (1, 0));
    role.stop().await.unwrap();
}

#[tokio::test]
async fn always_denied_destinations_stay_denied_even_when_an_entry_names_them() {
    let role = Harness::start(config()).await;
    let echo = echo_server().await;
    // An upstream that answers with loopback and the metadata address: nothing is handed out or bound.
    role.upstream.set("api.example.com", Answer::Addresses(vec![ip("127.0.0.1"), ip("169.254.169.254")]));
    assert!(role.resolve("api.example.com", QTYPE_A).await.answers.is_empty());

    let hello = client_hello("api.example.com");
    let rows = [
        ("127.0.0.1:443", "loopback"),
        ("169.254.169.254:443", "link_local"),
        ("169.254.169.254:80", "link_local"),
        ("224.0.0.1:443", "multicast"),
        ("255.255.255.255:443", "broadcast"),
        ("0.0.0.0:443", "unspecified"),
        ("240.0.0.1:443", "reserved"),
        ("10.0.0.5:443", "private_destination"),
        ("192.168.1.1:5432", "private_destination"),
        // Inside the network entry 203.0.113.0/24, on its listed port - and still denied.
        ("203.0.113.1:5432", "host_address"),
        ("203.0.113.200:5432", "sandbox_network"),
    ];
    for (destination, reason) in rows {
        role.connector.route(destination, Route::To(echo));
        expect_denied(&role, destination, &hello, reason).await;
    }
    assert!(role.connector.attempts().is_empty(), "no denied destination was ever dialled");
    let stats = role.stats();
    assert_eq!((stats.connections, stats.connections_denied, stats.connections_allowed), (11, 11, 0));
    role.stop().await.unwrap();
}

#[tokio::test]
async fn a_client_that_sends_nothing_is_cut_off_at_the_sni_deadline() {
    let role = role_with_bound_api(RoleConfig { sni_deadline_ms: 300, ..config() }).await;
    let started = Instant::now();
    let mut silent = role.dial("198.51.100.10:443").await;
    assert!(read_until_closed(&mut silent).await.is_empty());
    assert!(started.elapsed() >= Duration::from_millis(250), "not before the deadline: {:?}", started.elapsed());

    // Half a hello and then silence is cut off the same way.
    let mut stalled = role.dial("198.51.100.10:443").await;
    stalled.write_all(&client_hello("api.example.com")[..30]).await.unwrap();
    assert!(read_until_closed(&mut stalled).await.is_empty());
    assert_eq!(role.denied("no_server_name"), 2);
    assert!(role.connector.attempts().is_empty());
    role.stop().await.unwrap();
}

#[tokio::test]
async fn traffic_that_is_not_a_client_hello_does_not_pass_a_name_entry() {
    let role = role_with_bound_api(config()).await;
    // With a five-second deadline, these are denied as soon as the bytes show what they are.
    let started = Instant::now();
    expect_denied(&role, "198.51.100.10:443", b"GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n", "no_server_name").await;
    expect_denied(&role, "198.51.100.10:443", &client_hello_without_name(), "no_server_name").await;
    let mut closes_early = role.dial("198.51.100.10:443").await;
    closes_early.write_all(&client_hello("api.example.com")[..20]).await.unwrap();
    closes_early.shutdown().await.unwrap();
    assert!(read_until_closed(&mut closes_early).await.is_empty());
    assert_eq!(role.denied("no_server_name"), 3);
    assert!(started.elapsed() < Duration::from_secs(4), "none of these waited for the deadline");
    role.stop().await.unwrap();
}

#[tokio::test]
async fn connections_over_the_cap_are_shed() {
    let role = Harness::start(RoleConfig { max_connections: 2, ..config() }).await;
    role.connector.route("203.0.113.5:5432", Route::To(echo_server().await));
    let mut held = Vec::new();
    for _ in 0..2 {
        let mut guest = role.dial("203.0.113.5:5432").await;
        guest.write_all(b"ping").await.unwrap();
        assert_eq!(read_exact(&mut guest, 4).await, b"ping");
        held.push(guest);
    }
    for _ in 0..3 {
        let mut over = role.dial("203.0.113.5:5432").await;
        let _ = over.write_all(b"ping").await;
        assert!(read_until_closed(&mut over).await.is_empty(), "the connection over the cap is closed at once");
    }
    let stats = role.stats();
    assert_eq!((stats.connections, stats.connections_allowed, stats.connections_shed, stats.connections_denied), (5, 2, 3, 0));
    assert_eq!(role.connector.attempts().len(), 2);

    // Closing one frees its slot.
    drop(held.pop());
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let mut guest = role.dial("203.0.113.5:5432").await;
        let _ = guest.write_all(b"ping").await;
        if read_until_closed_or(&mut guest, 4).await == b"ping" {
            break;
        }
        assert!(Instant::now() < deadline, "the freed slot is never reused");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    role.stop().await.unwrap();
}

#[tokio::test]
async fn an_idle_connection_is_closed() {
    let role = Harness::start(RoleConfig { idle_timeout_ms: 1_000, ..config() }).await;
    role.connector.route("203.0.113.5:5432", Route::To(echo_server().await));
    let mut guest = role.dial("203.0.113.5:5432").await;
    // Traffic keeps the connection open for longer than the timeout...
    let opened = Instant::now();
    for _ in 0..5 {
        guest.write_all(b"ping").await.unwrap();
        assert_eq!(read_exact(&mut guest, 4).await, b"ping");
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(opened.elapsed() > Duration::from_millis(1_000));
    // ...and silence closes it.
    assert!(read_until_closed(&mut guest).await.is_empty());
    assert_eq!(role.stats().connections_allowed, 1);
    role.stop().await.unwrap();
}

#[tokio::test]
async fn a_destination_that_cannot_be_reached_is_counted_not_relayed() {
    let role = Harness::start(RoleConfig { connect_deadline_ms: 200, ..config() }).await;
    expect_denied(&role, "203.0.113.5:5432", b"", "upstream_connect_failed").await;
    role.connector.route("203.0.113.6:5432", Route::Hang);
    expect_denied(&role, "203.0.113.6:5432", b"", "upstream_connect_timed_out").await;
    assert_eq!(role.connector.attempts().len(), 2);
    let stats = role.stats();
    assert_eq!((stats.connections_allowed, stats.connections_denied), (0, 2));
    role.stop().await.unwrap();
}

#[tokio::test]
async fn a_connection_without_a_usable_original_destination_is_refused() {
    let role = Harness::start(config()).await;
    // The packet filter has no record of this connection.
    let mut unknown = role.dial_with(None).await;
    assert!(read_until_closed(&mut unknown).await.is_empty());
    assert_eq!(role.denied("original_destination_unavailable"), 1);

    // A connection addressed to the relay itself was not redirected; relaying it would loop.
    let own = v4(role.relay);
    role.connector.route(&own.to_string(), Route::To(echo_server().await));
    let mut direct = role.dial_with(Some(own)).await;
    assert!(read_until_closed(&mut direct).await.is_empty());
    assert_eq!(role.denied("host_address"), 1);
    assert!(role.connector.attempts().is_empty());
    role.stop().await.unwrap();
}

#[tokio::test]
async fn nothing_survives_the_role() {
    let role = role_with_bound_api(config()).await;
    let (resolver, relay) = (role.resolver, role.relay);
    let hello = client_hello("api.example.com");
    let mut guest = role.dial("198.51.100.10:443").await;
    guest.write_all(&hello).await.unwrap();
    assert_eq!(read_exact(&mut guest, hello.len()).await, hello);
    let mut waiting = role.dial("198.51.100.10:443").await;

    role.stop().await.unwrap();

    // The relayed connection and the one still waiting for its hello are both gone...
    guest.write_all(b"more").await.ok();
    assert!(read_until_closed(&mut guest).await.is_empty());
    assert!(read_until_closed(&mut waiting).await.is_empty());
    // ...the listener no longer accepts, and the resolver's port is free again: both sockets are closed.
    let refused = TcpStream::connect(relay).await.unwrap_err();
    assert_eq!(refused.kind(), ErrorKind::ConnectionRefused);
    UdpSocket::bind(resolver).await.expect("the resolver socket was closed");
}

#[tokio::test]
async fn run_with_the_kernel_effects_refuses_what_was_not_redirected() {
    // On loopback nothing is redirected, so the kernel either has no original destination for a connection
    // or reports the relay's own address. Both are refusals.
    let resolver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let relay = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let (resolver_addr, relay_addr) = (resolver.local_addr().unwrap(), relay.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let role = tokio::spawn(run(config(), resolver, relay, async move {
        let _ = stopped.await;
    }));

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(&dns_query(9, "evil.example.net", QTYPE_A), resolver_addr).await.unwrap();
    let reply = parse_reply(&receive(&socket).await, dns_query(9, "evil.example.net", QTYPE_A).len() - 12);
    assert_eq!((reply.id, reply.rcode), (9, REFUSED));

    let mut guest = TcpStream::connect(relay_addr).await.unwrap();
    assert!(read_until_closed(&mut guest).await.is_empty());

    stop.send(()).unwrap();
    let stats: StatsSnapshot = tokio::time::timeout(TIMEOUT, role).await.unwrap().unwrap().unwrap();
    assert_eq!((stats.queries, stats.queries_refused, stats.connections, stats.connections_denied), (1, 1, 1, 1));
    let reasons: Vec<&str> = stats.denied_by_reason.keys().map(String::as_str).collect();
    assert!(reasons == ["original_destination_unavailable"] || reasons == ["host_address"], "{reasons:?}");
    assert_eq!(TcpStream::connect(relay_addr).await.unwrap_err().kind(), ErrorKind::ConnectionRefused);
}

#[tokio::test]
async fn an_invalid_configuration_never_serves() {
    let resolver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let relay = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let relay_addr = relay.local_addr().unwrap();
    let unbounded = RoleConfig { max_connections: 0, ..config() };
    assert!(run(unbounded, resolver, relay, std::future::pending()).await.is_err());
    assert_eq!(TcpStream::connect(relay_addr).await.unwrap_err().kind(), ErrorKind::ConnectionRefused, "the sockets were dropped");
}

#[tokio::test]
async fn the_direct_connector_connects_to_the_address_it_is_given() {
    let echo = v4(echo_server().await);
    let mut stream = DirectConnector.connect(echo).await.unwrap();
    assert_eq!(stream.peer_addr().unwrap(), std::net::SocketAddr::V4(echo));
    stream.write_all(b"ping").await.unwrap();
    assert_eq!(read_exact(&mut stream, 4).await, b"ping");
}
