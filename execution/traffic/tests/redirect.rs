//! The relay against the real kernel: a packet-filter REDIRECT, `SO_ORIGINAL_DST` and a direct connection.
//!
//! Ignored by default, because it needs a network namespace prepared the way a sandbox's is. No privilege is
//! required; as an ordinary user, from the repository root:
//!
//! ```text
//! unshare -Urn sh -c '
//!   ip link set lo up && ip addr add 198.51.100.10/32 dev lo &&
//!   nft add table ip acf &&
//!   nft "add chain ip acf out { type nat hook output priority -100 ; }" &&
//!   nft "add rule ip acf out ip saddr 127.0.0.2 tcp dport { 443, 8443, 9443 } redirect to :15001" &&
//!   cargo test --offline -p acf-traffic --test redirect -- --ignored'
//! ```
//!
//! The namespace has a loopback device and nothing else. 198.51.100.10 stands for a public destination and
//! 127.0.0.2 for the guest: what the guest sends to the three ports is redirected to the relay on port 15001,
//! as the sandbox's packet filter does it. The relay's own connections leave from another address and are
//! not redirected.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use acf_traffic::relay::{DirectConnector, KernelOriginalDst};
use acf_traffic::role::{RoleConfig, Shared, run_with};
use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};

const PREPARE: &str = "the network namespace is not prepared; see the comment at the top of tests/redirect.rs";

/// An echo server on the "public" address, which only exists inside the prepared namespace.
async fn public_echo(port: u16) {
    let listener = TcpListener::bind(("198.51.100.10", port)).await.expect(PREPARE);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                while let Ok(read @ 1..) = stream.read(&mut buffer).await {
                    if stream.write_all(&buffer[..read]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
}

/// A guest connection: it leaves from 127.0.0.2, so the packet filter redirects it to the relay.
async fn guest_dial(destination: &str) -> TcpStream {
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.2:0".parse().unwrap()).unwrap();
    let destination: SocketAddr = destination.parse().unwrap();
    tokio::time::timeout(TIMEOUT, socket.connect(destination)).await.expect("the connection is redirected to the relay").unwrap()
}

#[tokio::test]
#[ignore = "needs a prepared network namespace; see the comment at the top of this file"]
async fn redirected_connections_are_judged_by_their_original_destination() {
    for port in [443, 8443, 9443] {
        public_echo(port).await;
    }
    let config = RoleConfig {
        entries: vec![name_entry("api.example.com", 443), network_entry("198.51.100.10/32", 8443)],
        host_addresses: vec![],
        sandbox_networks: vec![],
        ..config()
    };
    let shared = Shared::new(&config).unwrap();
    let resolver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let resolver_addr = resolver.local_addr().unwrap();
    let relay = TcpListener::bind("127.0.0.1:15001").await.expect(PREPARE);
    let upstream = FakeUpstream::default();
    upstream.set("api.example.com", Answer::Addresses(vec![ip("198.51.100.10")]));
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let shutdown = async move {
        let _ = stopped.await;
    };
    let role = tokio::spawn(run_with(Arc::clone(&shared), resolver, relay, upstream, KernelOriginalDst, DirectConnector, shutdown));
    let denied = |reason: &str| shared.stats().denied_by_reason.get(reason).copied().unwrap_or(0);

    // A name entry: before the name is resolved the address is not bound, afterwards the hello passes.
    let hello = client_hello("api.example.com");
    let mut early = guest_dial("198.51.100.10:443").await;
    early.write_all(&hello).await.unwrap();
    assert!(read_until_closed(&mut early).await.is_empty());
    assert_eq!(denied("address_not_bound"), 1, "{:?}", shared.stats());

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = dns_query(1, "api.example.com", QTYPE_A);
    socket.send_to(&query, resolver_addr).await.unwrap();
    assert_eq!(parse_reply(&receive(&socket).await, query.len() - 12).answers, [ip("198.51.100.10")]);

    let mut tls = guest_dial("198.51.100.10:443").await;
    assert_eq!(tls.peer_addr().unwrap(), "198.51.100.10:443".parse().unwrap(), "the guest sees the address it dialled");
    tls.write_all(&hello).await.unwrap();
    assert_eq!(read_exact(&mut tls, hello.len()).await, hello);

    // A network entry: plain TCP to the listed port passes, the same address on another port does not.
    let mut plain = guest_dial("198.51.100.10:8443").await;
    plain.write_all(b"plain").await.unwrap();
    assert_eq!(read_exact(&mut plain, 5).await, b"plain");

    let mut unlisted = guest_dial("198.51.100.10:9443").await;
    let _ = unlisted.write_all(b"plain").await;
    assert!(read_until_closed(&mut unlisted).await.is_empty());
    assert_eq!(denied("no_matching_entry"), 1, "{:?}", shared.stats());

    // A connection straight to the relay's own port was not redirected and is refused.
    let mut direct = TcpStream::connect("127.0.0.1:15001").await.unwrap();
    assert!(read_until_closed(&mut direct).await.is_empty());
    assert_eq!(denied("host_address") + denied("original_destination_unavailable"), 1, "{:?}", shared.stats());

    let stats = shared.stats();
    assert_eq!((stats.connections, stats.connections_allowed, stats.connections_denied), (5, 2, 3));
    stop.send(()).unwrap();
    tokio::time::timeout(TIMEOUT, role).await.unwrap().unwrap().unwrap();
}
