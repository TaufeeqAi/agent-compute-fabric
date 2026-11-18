//! The transport half of T-AUTH-01, -04, -05 and T-SEC-01, -03: the real serving path
//! (`app::serve_host`: recovery, endpoints, the edge, the enrolment refresh, drain) over a real Unix
//! socket and real mutual TLS 1.3. The edge runs in this process here; that it also runs as a
//! separate unprivileged process is shown by `tests/process_roles.rs`.

use std::{sync::Arc, time::Duration};

use acf_wire::frame::aio;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UnixStream},
};
use tokio_util::sync::CancellationToken;

use crate::{
    api::{MAX_RESPONSE_FRAME, RequestEnvelope, ResponseEnvelope},
    app::{self, EdgeMode},
    authority::Enrolment,
    config::{HostConfig, TlsConfig},
    coordinator::Host,
    domain::{ContainmentReason, HostMode, OperationState},
    edge::tls::fingerprints,
    error::FailureClass,
    testing::{
        pki::{ClientIdentity, TestPki},
        rig::{Rig, create_params, ops},
    },
};

/// A host being served for real, with the test user enrolled locally and three identities over TLS.
struct Served {
    rig: Rig,
    host: Arc<Host>,
    pki: TestPki,
    operator: ClientIdentity,
    caller: ClientIdentity,
    stranger: ClientIdentity,
    stop: CancellationToken,
    serving: tokio::task::JoinHandle<crate::error::Result<()>>,
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

async fn soon(what: &str, mut cond: impl FnMut() -> bool) {
    for _ in 0..1200 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("timed out waiting for: {what}");
}

impl Served {
    async fn start(tweak: impl FnOnce(&mut HostConfig)) -> Self {
        let pki = TestPki::new();
        let (operator, caller, stranger) = (pki.client("operator"), pki.client("caller"), pki.client("stranger"));
        let listen = format!("127.0.0.1:{}", free_port());
        let rig = Rig::with(|c| {
            // Only the address is read from here; the material is handed over directly, as the core does.
            c.edge.tls =
                Some(TlsConfig { listen, certificate: "/unused".into(), private_key: "/unused".into(), trust_anchors: "/unused".into() });
            c.edge.enrolment_refresh_ms = 200;
            c.edge.socket_mode = "0600".into();
            tweak(c);
        });
        let me = rustix::process::geteuid().as_raw();
        let enrolment = format!(
            "schema_version: 1\npeers:\n  - {{ peer_id: me, role: operator, match: {{ local_uid: {me} }} }}\n  - {{ peer_id: tls-operator, role: operator, match: {{ spki_sha256: \"{}\" }} }}\n  - {{ peer_id: tls-caller, role: caller, match: {{ certificate_sha256: \"{}\" }} }}\n",
            fingerprints(&operator.der).1.unwrap(),
            fingerprints(&caller.der).0
        );
        std::fs::write(&rig.cfg.paths.enrolment_path, &enrolment).unwrap();
        let host = rig.boot();
        host.set_enrolment(Enrolment::parse(enrolment.as_bytes(), app::sha256_hex(enrolment.as_bytes())).unwrap());
        let stop = CancellationToken::new();
        let serving = tokio::spawn(app::serve_host(Arc::clone(&host), Some(pki.server_material()), EdgeMode::InProcess, stop.clone()));
        let socket = rig.cfg.paths.socket_path.clone();
        soon("the local endpoint opens", || socket.exists()).await;
        Self { rig, host, pki, operator, caller, stranger, stop, serving }
    }

    /// Remove every enrolment entry whose line contains `needle`, as an operator editing the file would.
    fn unenrol(&self, needle: &str) {
        let path = &self.rig.cfg.paths.enrolment_path;
        let text = std::fs::read_to_string(path).unwrap();
        let kept: Vec<&str> = text.lines().filter(|l| !l.contains(needle)).collect();
        assert!(kept.len() < text.lines().count(), "no entry matched `{needle}`");
        std::fs::write(path, kept.join("\n") + "\n").unwrap();
    }

    fn envelope(&self, method: &str, params: Value) -> RequestEnvelope {
        ops(&self.host).envelope(method, params)
    }

    async fn local(&self) -> UnixStream {
        UnixStream::connect(&self.rig.cfg.paths.socket_path).await.unwrap()
    }

    fn address(&self) -> String {
        self.rig.cfg.edge.tls.as_ref().unwrap().listen.clone()
    }

    fn client_config(&self, anchors_pem: &str, identity: Option<&ClientIdentity>) -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(anchors_pem.as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let builder = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots);
        Arc::new(match identity {
            Some(id) => {
                let chain = CertificateDer::pem_slice_iter(id.certificate_pem.as_bytes()).map(Result::unwrap).collect();
                builder.with_client_auth_cert(chain, PrivateKeyDer::from_pem_slice(id.private_key_pem.as_bytes()).unwrap()).unwrap()
            }
            None => builder.with_no_client_auth(),
        })
    }

    /// A mutual-TLS connection as `identity`, trusting this host's authority.
    async fn tls(&self, identity: Option<&ClientIdentity>) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let config = self.client_config(self.pki.ca_pem(), identity);
        let tcp = TcpStream::connect(self.address()).await?;
        tokio_rustls::TlsConnector::from(config).connect(ServerName::try_from("localhost").unwrap(), tcp).await
    }

    async fn stop(self) -> Rig {
        self.stop.cancel();
        self.serving.await.unwrap().unwrap();
        assert!(!self.rig.cfg.paths.socket_path.exists(), "the socket is removed on a clean stop");
        self.rig
    }
}

async fn ask<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    envelope: &RequestEnvelope,
) -> std::result::Result<ResponseEnvelope, acf_wire::FrameError> {
    aio::send_json(stream, envelope, 1 << 20).await?;
    aio::recv_json(stream, MAX_RESPONSE_FRAME).await
}

/// The next frame, if the peer sends one before it closes.
async fn next_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Option<ResponseEnvelope> {
    tokio::time::timeout(Duration::from_secs(5), aio::recv_json(stream, MAX_RESPONSE_FRAME)).await.ok()?.ok()
}

async fn closed<S: AsyncRead + Unpin>(stream: &mut S) -> bool {
    let mut byte = [0u8; 1];
    matches!(tokio::time::timeout(Duration::from_secs(5), stream.read(&mut byte)).await, Ok(Ok(0) | Err(_)))
}

/// T-AUTH-01: a local caller that is not enrolled, and a certificate that chains to the trusted
/// authority but is not enrolled, are `AUTHENTICATION_FAILED` and closed before any request is
/// read. Authority comes from enrolment, never from being able to connect (AU-2).
#[tokio::test]
async fn t_auth_01_a_credential_that_is_not_enrolled_is_refused_before_any_request_is_read() {
    let s = Served::start(|_| {}).await;

    // Enrolled peers are served, on both endpoints, under the identity enrolment gave them.
    let mut local = s.local().await;
    let info = ask(&mut local, &s.envelope("host.info", Value::Null)).await.unwrap();
    assert!(info.read_result().is_some(), "{:?}", info.answer);
    let mut tls = s.tls(Some(&s.caller)).await.unwrap();
    let created = ask(&mut tls, &s.envelope("sandbox.create", create_params(None))).await.unwrap();
    let op = created.operation_view().unwrap();
    assert_eq!(op.state, OperationState::Succeeded);
    assert_eq!(op.tags.peer_id.as_str(), "tls-caller", "the peer id is the enrolled one: nothing in the request can choose it");
    // The role is the enrolled one too: this certificate is a caller, not an operator.
    let denied = ask(&mut tls, &s.envelope("host.set_mode", json!({"mode": "DRAINING"}))).await.unwrap();
    assert_eq!(denied.refusal().map(|r| r.class), Some(FailureClass::AuthorizationDenied));
    // Enrolled by its public key: a re-issued certificate for the same key is the same peer.
    let reissued = s.pki.reissue(&s.operator);
    let mut again = s.tls(Some(&reissued)).await.unwrap();
    assert!(ask(&mut again, &s.envelope("host.set_mode", json!({"mode": "SERVING"}))).await.unwrap().operation_view().is_some());

    // Chain-valid, not enrolled: told why, then closed. It never got to send a request.
    let before = s.host.journal.last_seq();
    let mut stranger = s.tls(Some(&s.stranger)).await.unwrap();
    let refusal = next_frame(&mut stranger).await.expect("the edge says why before it closes");
    assert_eq!(refusal.refusal().map(|r| r.class), Some(FailureClass::AuthenticationFailed));
    assert!(closed(&mut stranger).await);
    // A request sent anyway goes nowhere.
    let _ = aio::send_json(&mut stranger, &s.envelope("sandbox.create", create_params(None)), 1 << 20).await;
    // No certificate at all, or one from another authority: the handshake does not complete.
    for attempt in [None, Some(TestPki::new().client("operator"))] {
        match s.tls(attempt.as_ref()).await {
            Err(_) => {}
            Ok(mut stream) => {
                let _ = aio::send_json(&mut stream, &s.envelope("host.info", Value::Null), 1 << 20).await;
                assert!(next_frame(&mut stream).await.is_none(), "an unauthenticated peer was answered");
            }
        }
    }
    // A client that does not trust this host's authority does not talk to it either (AU-4).
    let wrong_anchor = s.client_config(TestPki::new().ca_pem(), Some(&s.caller));
    let tcp = TcpStream::connect(s.address()).await.unwrap();
    assert!(tokio_rustls::TlsConnector::from(wrong_anchor).connect(ServerName::try_from("localhost").unwrap(), tcp).await.is_err());

    assert_eq!(s.host.journal.last_seq(), before, "none of them caused a single commit");
    soon("the refusals are counted", || {
        s.host.telemetry.metrics.get("auth_denied") >= 1 && s.host.telemetry.metrics.get("handshake_failures") >= 2
    })
    .await;
    assert!(s.host.telemetry.metrics.get("refusals_before_authentication") >= 3);

    // A local caller that is not enrolled: the same, on the local endpoint.
    s.unenrol("local_uid");
    soon("the table is re-read", || !s.host.enrolment().doc().peers.iter().any(|p| p.peer_id.as_str() == "me")).await;
    let mut local = s.local().await;
    let refusal = next_frame(&mut local).await.expect("the edge says why before it closes");
    assert_eq!(refusal.refusal().map(|r| r.class), Some(FailureClass::AuthenticationFailed));
    assert!(closed(&mut local).await);
    s.stop().await;
}

/// T-AUTH-04: the network endpoint is opened only with explicit trust anchors, a matching key and
/// TLS 1.3. Anything else is a failed mandatory check: the endpoint stays closed and the host is in
/// `CONTAINMENT`. It does not exit, and it does not fall back to the system trust store.
#[tokio::test]
async fn t_auth_04_the_network_endpoint_needs_explicit_anchors_and_tls_1_3() {
    // The trusted inputs, as the core loads them at startup.
    let pki = TestPki::new();
    let material = pki.server_material();
    let cases: [(&str, &str, &str); 5] = [
        ("no trust anchors file", "missing", "ok"),
        ("an anchors file with no certificate in it (the system store is never a fallback)", "empty", "ok"),
        ("an anchors file another user could have written", "writable", "ok"),
        ("a private key that does not belong to the certificate", "ok", "other"),
        ("a private key file that is missing", "ok", "missing"),
    ];
    for (what, anchors, key) in cases {
        let listen = format!("127.0.0.1:{}", free_port());
        let dir = crate::testing::private_tempdir();
        let (crt, key_path, ca) = (dir.path().join("host.crt"), dir.path().join("host.key"), dir.path().join("ca.crt"));
        std::fs::write(&crt, &material.certificate_pem).unwrap();
        match key {
            "ok" => std::fs::write(&key_path, &material.private_key_pem).unwrap(),
            "other" => std::fs::write(&key_path, TestPki::new().server_material().private_key_pem).unwrap(),
            _ => {}
        }
        match anchors {
            "ok" => std::fs::write(&ca, &material.trust_anchors_pem).unwrap(),
            "empty" => std::fs::write(&ca, "").unwrap(),
            "writable" => {
                std::fs::write(&ca, &material.trust_anchors_pem).unwrap();
                std::fs::set_permissions(&ca, <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o666)).unwrap();
            }
            _ => {}
        }
        let rig = Rig::with(|c| {
            c.edge.tls = Some(TlsConfig {
                listen: listen.clone(),
                certificate: crt.clone(),
                private_key: key_path.clone(),
                trust_anchors: ca.clone(),
            })
        });
        let inputs = app::load_trusted_inputs(&rig.cfg);
        assert!(inputs.tls.is_none(), "{what}: no material is handed to the edge");
        assert!(
            inputs.reasons.iter().any(|r| matches!(r, ContainmentReason::MandatoryCheck(m) if m.contains("network endpoint"))),
            "{what}: {:?}",
            inputs.reasons
        );
        // The host that starts from these inputs runs, in CONTAINMENT, with its network endpoint closed.
        let host = rig.boot_with(inputs.reasons);
        let stop = CancellationToken::new();
        let serving = tokio::spawn(app::serve_host(Arc::clone(&host), inputs.tls, EdgeMode::InProcess, stop.clone()));
        let socket = rig.cfg.paths.socket_path.clone();
        soon("the local endpoint opens", || socket.exists()).await;
        assert_eq!(host.mode(), HostMode::Containment, "{what}");
        assert!(TcpStream::connect(&listen).await.is_err(), "{what}: the network endpoint must not be listening");
        stop.cancel();
        serving.await.unwrap().unwrap();
    }
    // With complete material the same loader succeeds.
    let dir = crate::testing::private_tempdir();
    for (name, pem) in
        [("host.crt", &material.certificate_pem), ("host.key", &material.private_key_pem), ("ca.crt", &material.trust_anchors_pem)]
    {
        std::fs::write(dir.path().join(name), pem).unwrap();
    }
    let rig = Rig::with(|c| {
        c.edge.tls = Some(TlsConfig {
            listen: "127.0.0.1:1".into(),
            certificate: dir.path().join("host.crt"),
            private_key: dir.path().join("host.key"),
            trust_anchors: dir.path().join("ca.crt"),
        });
    });
    let inputs = app::load_trusted_inputs(&rig.cfg);
    assert!(inputs.tls.is_some() && inputs.reasons.is_empty(), "{:?}", inputs.reasons);

    // AU-4: complete, valid material whose certificate names another host is not used either.
    let elsewhere = TestPki::for_host(&["localhost", "another-host"]).server_material();
    for (name, pem) in
        [("host.crt", &elsewhere.certificate_pem), ("host.key", &elsewhere.private_key_pem), ("ca.crt", &elsewhere.trust_anchors_pem)]
    {
        std::fs::write(dir.path().join(name), pem).unwrap();
    }
    let inputs = app::load_trusted_inputs(&rig.cfg);
    assert!(inputs.tls.is_none());
    assert!(
        inputs.reasons.iter().any(|r| matches!(r, ContainmentReason::MandatoryCheck(m) if m.contains("does not name this host"))),
        "{:?}",
        inputs.reasons
    );

    // TLS below the floor: a TLS 1.2 ClientHello gets an alert, never a ServerHello.
    let s = Served::start(|_| {}).await;
    let mut tcp = TcpStream::connect(s.address()).await.unwrap();
    let mut hello = vec![0x03, 0x03]; // client_version: TLS 1.2, and no supported_versions extension
    hello.extend([0x5a; 32]); // random
    hello.push(0); // no session id
    hello.extend([0x00, 0x04, 0xc0, 0x2f, 0xc0, 0x30]); // two TLS 1.2 cipher suites
    hello.extend([0x01, 0x00]); // null compression
    let extensions: &[u8] = &[0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17];
    hello.extend(u16::try_from(extensions.len()).unwrap().to_be_bytes());
    hello.extend(extensions);
    let mut handshake = vec![0x01, 0x00];
    handshake.extend(u16::try_from(hello.len()).unwrap().to_be_bytes());
    handshake.extend(hello);
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend(u16::try_from(handshake.len()).unwrap().to_be_bytes());
    record.extend(handshake);
    tcp.write_all(&record).await.unwrap();
    let mut answer = [0u8; 7];
    let n = tokio::time::timeout(Duration::from_secs(5), tcp.read(&mut answer)).await.unwrap().unwrap_or(0);
    assert!(n == 0 || answer[0] == 0x15, "expected an alert or a close, got record type {:#x}", answer[0]);
    if n == 7 {
        assert_eq!(answer[6], 70, "the alert is protocol_version");
    }
    s.stop().await;
}

/// T-AUTH-05: when an enrolment entry is removed, a connection that is already open becomes
/// unusable within `enrolment_refresh_bound` (AU-5), and other peers are not affected.
#[tokio::test]
async fn t_auth_05_a_removed_enrolment_entry_ends_open_connections_within_the_bound() {
    let s = Served::start(|_| {}).await;
    let mut caller = s.tls(Some(&s.caller)).await.unwrap();
    let mut operator = s.tls(Some(&s.operator)).await.unwrap();
    assert!(ask(&mut caller, &s.envelope("sandbox.list", json!({}))).await.unwrap().read_result().is_some());
    assert!(ask(&mut operator, &s.envelope("sandbox.list", json!({}))).await.unwrap().read_result().is_some());

    let removed_at = std::time::Instant::now();
    s.unenrol("tls-caller");
    // The open connection is told, and closed, without the peer having to send anything.
    let notice = next_frame(&mut caller).await.expect("the edge says why before it closes");
    assert_eq!(notice.refusal().map(|r| r.class), Some(FailureClass::AuthenticationFailed));
    assert!(closed(&mut caller).await);
    let bound = Duration::from_millis(s.rig.cfg.edge.enrolment_refresh_ms);
    assert!(removed_at.elapsed() <= bound + Duration::from_millis(500), "it took {:?}; the bound is {bound:?}", removed_at.elapsed());
    // A new connection with the same certificate is refused at once.
    let mut again = s.tls(Some(&s.caller)).await.unwrap();
    assert_eq!(next_frame(&mut again).await.and_then(|r| r.refusal().map(|x| x.class)), Some(FailureClass::AuthenticationFailed));
    // The peer that is still enrolled never noticed.
    assert!(ask(&mut operator, &s.envelope("sandbox.list", json!({}))).await.unwrap().read_result().is_some());
    assert!(s.host.telemetry.metrics.get("enrolment_reloads") >= 1);

    // A table that cannot be used is not used: the previous one stays in force.
    std::fs::write(&s.rig.cfg.paths.enrolment_path, "schema_version: 1\npeers: [oops").unwrap();
    soon("the bad table is noticed", || s.host.telemetry.metrics.get("enrolment_reload_failures") >= 1).await;
    assert!(
        ask(&mut operator, &s.envelope("sandbox.list", json!({}))).await.unwrap().read_result().is_some(),
        "the operator is still enrolled"
    );
    s.stop().await;
}

/// T-SEC-01 (the in-process half): a peer's bytes are read, decoded and validated by the edge; the
/// core receives validated commands only. What is not a valid request never reaches the core.
#[tokio::test]
async fn t_sec_01_only_validated_commands_reach_the_core() {
    let s = Served::start(|_| {}).await;
    let mut conn = s.local().await;
    let reached_core = || s.host.telemetry.metrics.get("requests_relayed");
    let seq = s.host.journal.last_seq();

    // Garbage in a well-formed frame, an unknown field, an unknown method, another protocol.
    let mut bad: Vec<Value> = vec![json!("not an object"), json!({"protocol": "acf.host/2"}), json!([1, 2, 3])];
    let mut unknown_field = serde_json::to_value(s.envelope("host.info", Value::Null)).unwrap();
    unknown_field["priority"] = json!("high");
    bad.push(unknown_field);
    bad.push(serde_json::to_value(s.envelope("host.shutdown", Value::Null)).unwrap());
    let mut other_protocol = serde_json::to_value(s.envelope("host.info", Value::Null)).unwrap();
    other_protocol["protocol"] = json!("acf.host/9");
    bad.push(other_protocol);
    for wire in &bad {
        aio::send_json(&mut conn, wire, 1 << 20).await.unwrap();
        let resp: ResponseEnvelope = aio::recv_json(&mut conn, MAX_RESPONSE_FRAME).await.unwrap();
        let class = resp.refusal().map(|r| r.class);
        assert!(matches!(class, Some(FailureClass::InvalidRequest | FailureClass::ProtocolError)), "{wire}: {:?}", resp.answer);
        assert!(resp.as_of.is_none(), "the edge refused it: no committed state was consulted");
    }
    // The connection survived all of it (framing was intact), and a valid request now works.
    assert!(ask(&mut conn, &s.envelope("host.info", Value::Null)).await.unwrap().read_result().is_some());
    soon("the edge reports its counters", || s.host.telemetry.metrics.get("invalid_requests") >= bad.len() as u64).await;
    assert_eq!(reached_core(), 1, "exactly one request was relayed to the core: the valid one");
    assert_eq!(s.host.journal.last_seq(), seq);

    // A request id is echoed only if it is a valid label: nothing hostile is reflected.
    let mut hostile = serde_json::to_value(s.envelope("host.shutdown", Value::Null)).unwrap();
    hostile["request_id"] = json!("x\u{1b}[31m");
    aio::send_json(&mut conn, &hostile, 1 << 20).await.unwrap();
    let resp: ResponseEnvelope = aio::recv_json(&mut conn, MAX_RESPONSE_FRAME).await.unwrap();
    assert_eq!(resp.request_id, None);
    s.stop().await;
}

/// Whether an authenticated connection is still being served.
async fn works(s: &Served, conn: &mut UnixStream) -> bool {
    ask(conn, &s.envelope("host.info", Value::Null)).await.is_ok_and(|r| r.read_result().is_some())
}

/// T-SEC-03: half-open handshakes, an oversized frame and a slow peer cost the host a bounded
/// amount and never disturb authenticated traffic (PA-2).
#[tokio::test]
async fn t_sec_03_unauthenticated_and_misbehaving_peers_do_not_disturb_authenticated_traffic() {
    let s = Served::start(|c| {
        c.edge.max_connections = 12;
        c.edge.max_connections_per_source = 6;
        c.edge.handshake_deadline_ms = 400;
        c.edge.idle_timeout_ms = 800;
        c.edge.max_request_bytes = 64 * 1024;
    })
    .await;
    let mut good = s.local().await;
    assert!(works(&s, &mut good).await);

    // Half-open handshakes: connections that never speak TLS. More than one source may hold.
    let mut half_open = Vec::new();
    for _ in 0..10 {
        half_open.push(TcpStream::connect(s.address()).await.unwrap());
    }
    assert!(works(&s, &mut good).await, "authenticated traffic is not affected while they hang");
    // One source cannot take every slot: the cap holds six of them and drops the rest at once, so
    // the slots of other sources (here: the local endpoint) stay free.
    // They are dropped at the handshake deadline, and counted.
    for conn in &mut half_open[..6] {
        assert!(closed(conn).await, "a half-open connection outlived the handshake deadline");
    }
    soon("handshake failures are counted", || s.host.telemetry.metrics.get("handshake_failures") >= 6).await;
    assert!(s.host.telemetry.metrics.get("connections_shed") >= 4, "connections beyond the per-source cap were dropped at once");
    // Once they are gone, a peer from that same source authenticates and is served.
    let mut operator = s.tls(Some(&s.operator)).await.unwrap();
    assert!(ask(&mut operator, &s.envelope("host.info", Value::Null)).await.unwrap().read_result().is_some());

    // (The first authenticated connection sat idle past `idle_timeout` while the counters were
    // awaited, and was closed for it, as any idle connection is. A new one is opened.)
    let mut good = s.local().await;
    assert!(works(&s, &mut good).await);

    // An oversized frame: refused from its 4-byte header, before anything is allocated or read.
    let mut big = s.local().await;
    big.write_all(&(64u32 * 1024 * 1024).to_be_bytes()).await.unwrap();
    let refusal = next_frame(&mut big).await.expect("the edge answers a bad frame");
    assert_eq!(refusal.refusal().map(|r| r.class), Some(FailureClass::InvalidRequest));
    assert!(closed(&mut big).await, "framing is lost, so the connection is closed");

    // A slow peer: a frame that never completes is dropped at the idle timeout.
    let mut slow = s.local().await;
    slow.write_all(&100u32.to_be_bytes()).await.unwrap();
    slow.write_all(b"{\"protocol\":").await.unwrap();
    // The well-behaved connection keeps being served while the slow one stalls, and outlives it.
    let mut dropped = false;
    for _ in 0..25 {
        assert!(works(&s, &mut good).await, "authenticated traffic stopped while a slow peer stalled");
        let mut byte = [0u8; 1];
        if let Ok(Ok(0) | Err(_)) = tokio::time::timeout(Duration::from_millis(200), slow.read(&mut byte)).await {
            dropped = true;
            break;
        }
    }
    assert!(dropped, "the slow peer was not dropped at the idle timeout");
    assert!(works(&s, &mut good).await);
    s.stop().await;
}

/// The serving path itself: recovery runs before any endpoint opens (RC-5); a stop drains.
#[tokio::test]
async fn serving_recovers_first_and_drains_on_stop() {
    let rig = Rig::new();
    let host = rig.boot();
    assert_eq!(host.mode(), HostMode::Starting);
    assert!(!rig.cfg.paths.socket_path.exists(), "no endpoint exists before recovery");
    let stop = CancellationToken::new();
    let serving = tokio::spawn(app::serve_host(Arc::clone(&host), None, EdgeMode::InProcess, stop.clone()));
    let socket = rig.cfg.paths.socket_path.clone();
    soon("the local endpoint opens", || socket.exists()).await;
    assert_eq!(host.mode(), HostMode::Serving, "by the time an endpoint is open, recovery is over");
    let mode = std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&socket).unwrap().permissions()) & 0o777;
    assert_eq!(mode, 0o660, "the socket has exactly the configured mode");
    stop.cancel();
    serving.await.unwrap().unwrap();
    assert!(host.is_draining() && !socket.exists());
}
