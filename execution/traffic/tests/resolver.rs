//! The resolver on a real UDP socket: allowlisted names only (AL-3), unreachable answers filtered (AL-6),
//! IPv4 only, strict parsing, bounded lookups.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::Duration;

use acf_traffic::policy::DnsName;
use acf_traffic::resolver::{SystemUpstream, Upstream};
use acf_traffic::role::RoleConfig;
use common::*;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;

#[tokio::test]
async fn an_unlisted_name_is_refused_without_contacting_the_upstream() {
    let role = Harness::start(config()).await;
    // Even a name the upstream could answer is refused: the allowlist is consulted first and alone.
    role.upstream.set("evil.example.net", Answer::Addresses(vec![ip("198.51.100.66")]));
    let unlisted =
        ["evil.example.net", "example.com", "www.api.example.com", "api.example.com.evil.net", "localhost", "_srv.api.example.com"];
    for name in unlisted {
        for qtype in [QTYPE_A, QTYPE_AAAA, 16, 255] {
            let reply = role.resolve(name, qtype).await;
            assert_eq!((reply.rcode, reply.answers.len()), (REFUSED, 0), "{name} type {qtype}");
        }
    }
    assert_eq!(role.upstream.calls(), 0, "AL-3: a refusal never reaches the upstream");
    let stats = role.stats();
    assert_eq!((stats.queries, stats.queries_refused, stats.queries_answered), (24, 24, 0));

    // Nothing was bound either: the name cannot be used to reach the address the upstream knows.
    let mut guest = role.dial("198.51.100.66:443").await;
    guest.write_all(&client_hello("evil.example.net")).await.unwrap();
    assert!(read_until_closed(&mut guest).await.is_empty());
    assert_eq!(role.denied("name_not_listed"), 1);
    role.stop().await.unwrap();
}

#[tokio::test]
async fn a_listed_name_is_answered_with_address_records() {
    let role = Harness::start(config()).await;
    role.upstream.set("api.example.com", Answer::Addresses(vec![ip("198.51.100.10"), ip("198.51.100.11")]));

    let reply = role.resolve("api.example.com", QTYPE_A).await;
    assert_eq!(reply.rcode, NOERROR);
    assert_eq!(reply.answers, [ip("198.51.100.10"), ip("198.51.100.11")]);
    assert_eq!(reply.ttls, [30, 30], "the TTL is min(dns_binding_ttl, 60 s)");
    assert_eq!(reply.raw[3] & 0x80, 0x80, "recursion available");

    // DNS names are case-insensitive, and the question comes back exactly as it was asked.
    let reply = role.resolve("ApI.ExAmPlE.cOm", QTYPE_A).await;
    assert_eq!((reply.rcode, reply.answers.len()), (NOERROR, 2));
    assert_eq!(role.upstream.calls(), 2);
    let stats = role.stats();
    assert_eq!((stats.queries, stats.queries_answered, stats.queries_refused, stats.upstream_failures), (2, 2, 0, 0));
    role.stop().await.unwrap();
}

#[tokio::test]
async fn the_answer_ttl_is_capped_at_sixty_seconds() {
    let role = Harness::start(RoleConfig { dns_binding_ttl_ms: 600_000, ..config() }).await;
    role.upstream.set("api.example.com", Answer::Addresses(vec![ip("198.51.100.10")]));
    assert_eq!(role.resolve("api.example.com", QTYPE_A).await.ttls, [60]);
    role.stop().await.unwrap();
}

#[tokio::test]
async fn answers_the_guest_may_never_reach_are_filtered_out() {
    let role = Harness::start(config()).await;
    // Loopback, the metadata address, a private address, a host address, another sandbox, and one real answer.
    let rebinding = ["127.0.0.1", "169.254.169.254", "10.0.0.5", "203.0.113.1", "203.0.113.200", "198.51.100.10", "0.0.0.0", "224.0.0.1"];
    role.upstream.set("api.example.com", Answer::Addresses(rebinding.map(ip).to_vec()));
    let reply = role.resolve("api.example.com", QTYPE_A).await;
    assert_eq!((reply.rcode, reply.answers), (NOERROR, vec![ip("198.51.100.10")]));

    // When nothing survives the answer is empty, and nothing is bound.
    role.upstream.set("git.example.com", Answer::Addresses(vec![ip("127.0.0.1"), ip("169.254.169.254"), ip("10.0.0.5")]));
    let reply = role.resolve("git.example.com", QTYPE_A).await;
    assert_eq!((reply.rcode, reply.answers.len()), (NOERROR, 0));
    for filtered in ["127.0.0.1:22", "169.254.169.254:22", "10.0.0.5:22"] {
        let mut guest = role.dial(filtered).await;
        assert!(read_until_closed(&mut guest).await.is_empty(), "{filtered}");
    }
    assert_eq!((role.denied("loopback"), role.denied("link_local"), role.denied("private_destination")), (1, 1, 1));
    assert!(role.connector.attempts().is_empty());
    role.stop().await.unwrap();
}

#[tokio::test]
async fn more_answers_than_fit_are_truncated_to_the_bound() {
    let role = Harness::start(config()).await;
    let many: Vec<_> = (1..=40).map(|n| ip(&format!("198.51.100.{n}"))).collect();
    role.upstream.set("api.example.com", Answer::Addresses(many.clone()));
    let reply = role.resolve("api.example.com", QTYPE_A).await;
    assert_eq!(reply.answers, &many[..acf_traffic::dns::MAX_ANSWERS]);
    role.stop().await.unwrap();
}

#[tokio::test]
async fn an_aaaa_question_about_a_listed_name_is_empty_and_needs_no_upstream() {
    let role = Harness::start(config()).await;
    role.upstream.set("api.example.com", Answer::Addresses(vec![ip("198.51.100.10")]));
    for qtype in [QTYPE_AAAA, 16, 33, 65, 255] {
        let reply = role.resolve("api.example.com", qtype).await;
        assert_eq!((reply.rcode, reply.answers.len()), (NOERROR, 0), "type {qtype}");
    }
    assert_eq!(role.upstream.calls(), 0);
    assert_eq!(role.stats().queries_answered, 5);
    role.stop().await.unwrap();
}

#[tokio::test]
async fn malformed_input_gets_formerr_notimp_or_silence() {
    let role = Harness::start(config()).await;
    role.upstream.set("api.example.com", Answer::Addresses(vec![ip("198.51.100.10")]));
    let good = dns_query(0x0101, "api.example.com", QTYPE_A);

    // A readable header on a broken message: FORMERR with the id, nothing echoed.
    let mut two_questions = good.clone();
    two_questions[5] = 2;
    let mut compressed = dns_query(0x0202, "api.example.com", QTYPE_A);
    compressed[12] = 0xc0;
    let mut trailing = good.clone();
    trailing.push(0);
    for (broken, id) in [(two_questions, 0x0101), (compressed, 0x0202), (trailing, 0x0101), (good[..20].to_vec(), 0x0101)] {
        let reply = parse_reply(&role.exchange(&broken).await, 0);
        assert_eq!((reply.id, reply.rcode, reply.raw.len()), (id, FORMERR, 12));
    }
    // Any opcode but QUERY: NOTIMP.
    let mut status = good.clone();
    status[2] = 0x10;
    let reply = parse_reply(&role.exchange(&status).await, 0);
    assert_eq!((reply.id, reply.rcode), (0x0101, NOTIMP));

    // Silence: less than a header, a response instead of a query, and a datagram over 512 bytes. Each is
    // followed by a good query from the same socket; the first datagram back answers the good query.
    let mut response = good.clone();
    response[2] |= 0x80;
    let mut oversized = good.clone();
    oversized.resize(513, 0);
    for ignored in [vec![0x01, 0x01, 0x01, 0x00, 0x00], vec![], response, oversized] {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.send_to(&ignored, role.resolver).await.unwrap();
        socket.send_to(&dns_query(0x7777, "api.example.com", QTYPE_A), role.resolver).await.unwrap();
        let reply = parse_reply(&receive(&socket).await, good.len() - 12);
        assert_eq!((reply.id, reply.rcode, reply.answers.len()), (0x7777, NOERROR, 1), "{} bytes must be ignored", ignored.len());
    }
    assert_eq!(role.upstream.calls(), 4, "only the four good queries reached the upstream");
    role.stop().await.unwrap();
}

#[tokio::test]
async fn an_upstream_failure_or_timeout_is_servfail() {
    let role = Harness::start(RoleConfig { upstream_timeout_ms: 200, ..config() }).await;
    role.upstream.set("api.example.com", Answer::Fail);
    role.upstream.set("git.example.com", Answer::Hang);
    for name in ["api.example.com", "git.example.com"] {
        let reply = role.resolve(name, QTYPE_A).await;
        assert_eq!((reply.rcode, reply.answers.len()), (SERVFAIL, 0), "{name}");
    }
    let stats = role.stats();
    assert_eq!((stats.upstream_failures, stats.queries_answered, role.upstream.calls()), (2, 0, 2));

    // A failed lookup binds nothing.
    let mut guest = role.dial("198.51.100.10:443").await;
    guest.write_all(&client_hello("api.example.com")).await.unwrap();
    assert!(read_until_closed(&mut guest).await.is_empty());
    assert_eq!(role.denied("address_not_bound"), 1);
    role.stop().await.unwrap();
}

#[tokio::test]
async fn lookups_in_flight_are_bounded_and_do_not_block_other_queries() {
    let role = Harness::start(RoleConfig { max_pending_lookups: 2, upstream_timeout_ms: 1_000, ..config() }).await;
    role.upstream.set("api.example.com", Answer::Hang);
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for id in [1, 2, 3] {
        socket.send_to(&dns_query(id, "api.example.com", QTYPE_A), role.resolver).await.unwrap();
    }
    // While two lookups hang, the loop still serves: a refusal and an empty AAAA answer come back at once,
    // and so does the SERVFAIL for the third lookup, which found the bound reached.
    let refused = role.resolve("evil.example.net", QTYPE_A).await;
    assert_eq!(refused.rcode, REFUSED);
    let question_len = dns_query(0, "api.example.com", QTYPE_A).len() - 12;
    let shed = parse_reply(&receive(&socket).await, question_len);
    assert_eq!((shed.id, shed.rcode), (3, SERVFAIL), "the lookup over the bound fails first");

    // The two that were admitted time out and are answered SERVFAIL as well.
    let mut late: Vec<u16> = Vec::new();
    for _ in 0..2 {
        let reply = parse_reply(&receive(&socket).await, question_len);
        assert_eq!(reply.rcode, SERVFAIL);
        late.push(reply.id);
    }
    late.sort_unstable();
    assert_eq!(late, [1, 2]);
    assert_eq!(role.upstream.calls(), 2, "the lookup over the bound never reached the upstream");
    assert_eq!(role.stats().upstream_failures, 3);

    // Their permits are back: a lookup that can be answered now is.
    role.upstream.set("api.example.com", Answer::Addresses(vec![ip("198.51.100.10")]));
    assert_eq!(role.resolve("api.example.com", QTYPE_A).await.answers, [ip("198.51.100.10")]);
    role.stop().await.unwrap();
}

/// Not run by default: it needs the host's DNS. Run with `cargo test -p acf-traffic -- --ignored`.
#[tokio::test]
#[ignore = "needs the host's DNS resolver and network access"]
async fn the_system_upstream_returns_ipv4_addresses() {
    let upstream = SystemUpstream { timeout: Duration::from_secs(10) };
    let found = upstream.lookup_a(&DnsName::parse("example.com").unwrap()).await.unwrap();
    assert!(!found.is_empty(), "example.com has IPv4 addresses");
}
