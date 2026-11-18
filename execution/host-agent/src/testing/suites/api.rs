//! T-API: the host API semantic model (contract §10). T-API-01 (the schema agrees with the tables)
//! is in `api/schema.rs`, `domain/method.rs` and `error.rs`, beside the tables themselves.

use proptest::prelude::*;
use serde_json::{Value, json};

use crate::{
    api::{PROTOCOL, RequestEnvelope},
    domain::{LifecycleState, OperationState},
    error::{FailureClass, RetryAdvice},
    testing::{
        fake_backend::Fail,
        rig::{Rig, alice, bob, calls, create_params, exec_params, footprint, ops, sandbox_of, snapshot_of, target, watch},
    },
};

/// Decode a request exactly as an endpoint does: typed envelope first, then the shape checks.
fn decode(wire: Value) -> Result<(), String> {
    let envelope: RequestEnvelope = serde_json::from_value(wire).map_err(|e| e.to_string())?;
    envelope.validate().map(|_| ()).map_err(|e| e.message)
}

fn request(method: &str, params: Value) -> Value {
    json!({"protocol": PROTOCOL, "owner_scope": "team-a", "operation_id": "op-12345678", "issued_at": "2026-11-18T10:00:00Z", "method": method, "params": params})
}

/// T-API-02: an unknown field, an unknown method, an unsupported protocol major → refused, and
/// nothing is recorded.
#[tokio::test]
async fn t_api_02_unknown_fields_methods_and_protocol_majors_are_refused_and_nothing_is_recorded() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let before = (footprint(&host), host.journal.last_seq());

    // An unknown field anywhere: envelope, params, nested object.
    let mut unknown_envelope_field = request("sandbox.create", create_params(None));
    unknown_envelope_field["priority"] = json!("high");
    assert!(decode(unknown_envelope_field).is_err());
    let mut unknown_param = create_params(None);
    unknown_param["privileged"] = json!(true);
    assert_eq!(a.refused("sandbox.create", unknown_param).await.class, FailureClass::InvalidRequest);
    let mut unknown_nested = create_params(None);
    unknown_nested["resources"]["gpus"] = json!(1);
    assert_eq!(a.refused("sandbox.create", unknown_nested).await.class, FailureClass::InvalidRequest);
    let mut widened_network = create_params(None);
    widened_network["resources"]["network"] = json!({"mode": "none", "allow_all": true});
    assert_eq!(
        a.refused("sandbox.create", widened_network).await.class,
        FailureClass::InvalidRequest,
        "a field beside `mode: none` is never ignored"
    );

    // §20.1: a network mode word this host does not know is a capability it does not offer
    // (`UNSUPPORTED`), not a malformed request. A `mode` that is not a word at all is malformed.
    for word in ["host", "nat", "bridge", "restricted", "NONE", "", "mode-of-a-later-contract"] {
        let mut other_mode = create_params(None);
        other_mode["resources"]["network"] = json!({"mode": word});
        let r = a.refused("sandbox.create", other_mode).await;
        assert_eq!((r.class, r.retry), (FailureClass::Unsupported, RetryAdvice::AfterChange), "`{word}`: {}", r.message);
        assert!(!r.message.contains("later-contract"), "the refusal names the modes offered, not the request's word: {}", r.message);
    }
    for not_a_word in [json!(7), json!(null), json!(["none"]), json!({"mode": "none"})] {
        let mut malformed = create_params(None);
        malformed["resources"]["network"] = json!({"mode": not_a_word});
        assert_eq!(a.refused("sandbox.create", malformed).await.class, FailureClass::InvalidRequest, "{not_a_word}");
    }

    // An unknown method, including one from an earlier protocol.
    for method in ["sandbox.exec", "sandbox_create", "host.shutdown", ""] {
        let r = a.refused(method, json!({})).await;
        assert_eq!((r.class, r.retry), (FailureClass::InvalidRequest, RetryAdvice::Never), "`{method}`");
    }

    // An unsupported protocol major, in either direction, and garbage.
    for protocol in ["acf.host/1", "acf.host/3", "acf.host", "ACF.HOST/2", ""] {
        let mut env = a.envelope("sandbox.create", create_params(None));
        env.protocol = protocol.to_owned();
        let resp = a.send(env).await;
        assert_eq!(resp.refusal().map(|r| r.class), Some(FailureClass::ProtocolError), "`{protocol}`");
        assert_eq!(resp.protocol, PROTOCOL, "the refusal says what this host speaks");
    }

    assert_eq!((footprint(&host), host.journal.last_seq()), before, "not one record was written");
    assert_eq!(calls(&rig.world, "provision"), 0);
}

/// T-API-03: a refusal, of whatever class, leaves no operation record and no reservation.
#[tokio::test]
async fn t_api_03_every_refusal_class_leaves_no_operation_record_and_no_reservation() {
    // A small machine: three sandboxes of the largest admissible size fill its memory.
    let rig = Rig::with(|c| c.operations.rate_limit_per_minute = 1_000);
    rig.world.withhold("secret_injection");
    let host = rig.serving().await;
    let (a, operator) = (alice(&host), ops(&host));
    let sb = a.ready(Some("box")).await;
    let done = a.done("exec.run", exec_params(&sb, &["/bin/true"])).await;
    let snap = snapshot_of(
        &a.done("snapshot.create", json!({"sandbox_id": sb.sandbox_id, "expected_generation": sb.generation, "name": "base"})).await,
    );
    let big = json!({"image": "python", "resources": {"vcpus": 2, "memory_mib": 2048, "disk_mib": 128, "network": {"mode": "none"}}});
    let mut filler = Vec::new();
    for _ in 0..3 {
        filler.push(sandbox_of(&a.done("sandbox.create", big.clone()).await)); // the host's limit is four sandboxes
    }

    let mut seen = std::collections::BTreeSet::new();
    let mut check = |what: &str, class: FailureClass, got: crate::api::Refusal, before: (usize, usize, usize)| {
        assert_eq!(got.class, class, "{what}: {}", got.message);
        assert!(got.class.can_refuse());
        assert_eq!(got.retry, class.retry_advice(), "{what}");
        assert_eq!(footprint(&host), before, "{what}: a refusal must leave no operation record and no reservation");
        seen.insert(class);
    };

    let before = footprint(&host);
    check("unknown method", FailureClass::InvalidRequest, a.refused("sandbox.teleport", json!({})).await, before);
    let mut forged = a.clone();
    forged.peer.peer_id = crate::domain::PeerId::parse("mallory").unwrap();
    check("unenrolled peer", FailureClass::AuthenticationFailed, forged.refused("sandbox.list", json!({})).await, before);
    check("role", FailureClass::AuthorizationDenied, watch(&host).refused("sandbox.list", json!({})).await, before);
    let over = json!({"image": "python", "resources": {"vcpus": 8, "memory_mib": 256, "disk_mib": 128, "network": {"mode": "none"}}});
    check("above a ceiling", FailureClass::SafetyControlDenied, a.refused("sandbox.create", over).await, before);
    check("another scope", FailureClass::NotFound, bob(&host).refused("sandbox.destroy", target(&sb)).await, before);
    let current = a.inspect(&sb.sandbox_id).await;
    check("illegal for the state", FailureClass::StateConflict, a.refused("sandbox.start", target(&current)).await, before);
    let stale = json!({"sandbox_id": sb.sandbox_id, "expected_generation": 7});
    check("stale token", FailureClass::RevisionConflict, a.refused("sandbox.stop", stale).await, before);
    let mut reused = a.envelope("exec.run", exec_params(&current, &["/bin/false"]));
    reused.operation_id = Some(done.operation_id.clone());
    check("operation id reused", FailureClass::IdempotencyConflict, a.send(reused).await.refusal().cloned().unwrap(), before);
    let mut old = a.envelope("sandbox.create", create_params(None));
    old.issued_at = Some("2020-01-01T00:00:00Z".into());
    check("outside the horizon", FailureClass::ExpiredRequest, a.send(old).await.refusal().cloned().unwrap(), before);
    check("no capacity", FailureClass::ResourceExhausted, a.refused("sandbox.create", big.clone()).await, before);
    let with_secret = json!({"sandbox_id": sb.sandbox_id, "expected_generation": sb.generation,
        "command": {"argv": ["/bin/true"], "secret_env": {"HOME": {"ref": "token"}}}});
    check("capability the backend lacks", FailureClass::Unsupported, a.refused("exec.run", with_secret).await, before);
    let foreign = json!({"changed_since": {"lineage": "another-store", "sequence": 1}});
    check("foreign cursor", FailureClass::CursorExpired, a.refused("sandbox.list", foreign).await, before);
    let mut v3 = a.envelope("sandbox.list", json!({}));
    v3.protocol = "acf.host/3".into();
    check("protocol major", FailureClass::ProtocolError, a.send(v3).await.refusal().cloned().unwrap(), before);

    // Quarantine: a generation whose ownership cannot be proven. (The destroy that discovers it is
    // an accepted operation; the refusals that follow are what is measured.)
    let victim = filler.remove(0);
    rig.forge_marker(&victim);
    assert_eq!(a.op("sandbox.destroy", target(&victim)).await.state, OperationState::Failed);
    let before = footprint(&host);
    check("quarantined", FailureClass::Quarantined, a.refused("sandbox.start", target(&victim)).await, before);
    check("quarantined, destroy too", FailureClass::Quarantined, a.refused("sandbox.destroy", target(&victim)).await, before);

    // An incompatible snapshot: the same store, a backend of another version.
    drop(host);
    rig.world.set_backend_version("v9.9.9");
    let host = rig.serving().await;
    let a = alice(&host);
    let before = footprint(&host);
    let restore = json!({"snapshot": snap.snapshot, "target": {"kind": "new"}});
    let got = a.refused("snapshot.restore", restore).await;
    assert_eq!((got.class, footprint(&host)), (FailureClass::IncompatibleRuntime, before), "{}", got.message);
    seen.insert(got.class);

    // The host mode.
    operator.on(&host).done("host.set_mode", json!({"mode": "DRAINING"})).await;
    let before = footprint(&host);
    let got = a.refused("sandbox.create", create_params(None)).await;
    assert_eq!((got.class, got.retry, footprint(&host)), (FailureClass::HostNotServing, RetryAdvice::SameRequestLater, before));
    seen.insert(got.class);

    // An integrity failure is a refusal too (the snapshot is marked INVALID; no operation exists).
    drop(host);
    rig.world.set_backend_version("v0.0.0");
    let host = rig.serving().await;
    let a = alice(&host);
    let manifest = rig.manifest_path(&snap);
    let mut bytes = std::fs::read(&manifest).unwrap();
    bytes.push(b' ');
    std::fs::write(&manifest, bytes).unwrap();
    let (ops_before, leases_before, _) = footprint(&host);
    let got = a.refused("snapshot.restore", json!({"snapshot": snap.snapshot, "target": {"kind": "new"}})).await;
    assert_eq!(got.class, FailureClass::IntegrityFailure, "{}", got.message);
    let (ops_after, leases_after, _) = footprint(&host);
    assert_eq!((ops_after, leases_after), (ops_before, leases_before));
    seen.insert(got.class);

    // Every class that can appear in a refusal (column R of §10.5) was produced above.
    let refusable: std::collections::BTreeSet<_> =
        FailureClass::ALL.into_iter().filter(|c| c.can_refuse() && *c != FailureClass::InternalError).collect();
    assert_eq!(seen, refusable, "missing: {:?}", refusable.difference(&seen).collect::<Vec<_>>());
    let _ = Fail::Before(crate::error::AcfError::internal("unused"));
}

/// T-API-04: reads say which committed state they reflect; `changed_since` returns exactly what
/// changed, tombstones included; an old or foreign cursor is `CURSOR_EXPIRED`.
#[tokio::test]
async fn t_api_04_reads_carry_as_of_and_changed_since_returns_exactly_the_changes() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let first = a.ready(Some("first")).await;

    // API-10: every read names the store lineage and the commit sequence it was served from.
    let resp = a.call("sandbox.list", json!({})).await;
    let as_of = resp.as_of.clone().expect("a read carries as_of");
    assert_eq!((as_of.lineage.as_str(), as_of.sequence), (host.journal.lineage(), host.journal.last_seq()));
    let full = a.sandboxes(json!({})).await;
    assert_eq!((full.items.len(), full.more), (1, false));
    assert_eq!(full.next.sequence, as_of.sequence, "a complete listing is complete up to the sequence it was read at");
    let cursor = json!({"lineage": full.next.lineage, "sequence": full.next.sequence});

    // Nothing changed: the delta is empty.
    assert!(a.sandboxes(json!({"changed_since": cursor})).await.items.is_empty());

    // One sandbox is created, the first one is destroyed, and another scope does something too.
    let second = a.create(Some("second")).await;
    a.done("sandbox.destroy", target(&first)).await;
    bob(&host).create(None).await;
    let delta = a.sandboxes(json!({"changed_since": cursor})).await;
    let mut changed: Vec<_> = delta.items.iter().map(|v| (v.sandbox_id.clone(), v.state)).collect();
    changed.sort_by(|x, y| x.0.cmp(&y.0));
    let mut expected =
        vec![(first.sandbox_id.clone(), LifecycleState::Destroyed), (second.sandbox_id.clone(), LifecycleState::Provisioning)];
    expected.sort_by(|x, y| x.0.cmp(&y.0));
    assert_eq!(changed, expected, "exactly the changed records of this scope, with the tombstone");
    assert!(delta.items.windows(2).all(|w| w[0].revision <= w[1].revision), "ascending revision order");
    // A full listing shows what exists; it does not show tombstones.
    assert_eq!(
        a.sandboxes(json!({})).await.items.iter().map(|v| v.sandbox_id.clone()).collect::<Vec<_>>(),
        vec![second.sandbox_id.clone()]
    );

    // Paging through a delta loses nothing.
    let page = a.sandboxes(json!({"changed_since": cursor, "limit": 1})).await;
    assert_eq!((page.items.len(), page.more), (1, true));
    let rest = a.sandboxes(json!({"changed_since": {"lineage": page.next.lineage, "sequence": page.next.sequence}})).await;
    assert_eq!(page.items.len() + rest.items.len(), 2);

    // Operations and snapshots follow the same rule.
    let ops_delta = a.operations(json!({"changed_since": cursor})).await;
    assert_eq!(ops_delta.items.len(), 2, "the create and the destroy issued since the cursor");

    // A cursor of another lineage, from the future, or older than the retained changes.
    for bad in [
        json!({"lineage": "not-this-store", "sequence": 1}),
        json!({"lineage": host.journal.lineage(), "sequence": host.journal.last_seq() + 100}),
    ] {
        let r = a.refused("sandbox.list", json!({"changed_since": bad})).await;
        assert_eq!((r.class, r.retry), (FailureClass::CursorExpired, RetryAdvice::AfterChange));
    }
    rig.clock.advance_ms(host.cfg.operations.change_retention_ms + 1);
    assert!(host.retention().unwrap() >= 1, "the tombstone is past its retention");
    let r = a.refused("sandbox.list", json!({"changed_since": cursor})).await;
    assert_eq!(r.class, FailureClass::CursorExpired, "a follower that may have missed a tombstone must list again");
    assert_eq!(a.sandboxes(json!({})).await.items.len(), 1, "and listing again recovers the state");
}

/// T-API-05: boundary, overflow and oversize values → `INVALID_REQUEST`; the boundary itself is
/// accepted.
#[test]
fn t_api_05_boundary_overflow_and_oversize_values_are_refused() {
    let long = |n: usize| "a".repeat(n);
    let env = |field: &str, value: Value| {
        let mut r = request("sandbox.create", create_params(None));
        r[field] = value;
        r
    };
    let bad: Vec<(&str, Value)> = vec![
        ("owner scope too long", env("owner_scope", json!(long(129)))),
        ("empty owner scope", env("owner_scope", json!(""))),
        ("owner scope with a space", env("owner_scope", json!("team a"))),
        ("owner scope with a newline", env("owner_scope", json!("team\na"))),
        ("owner scope with a quote", env("owner_scope", json!("team\"a"))),
        ("owner scope is not a string", env("owner_scope", json!(7))),
        ("request id too long", env("request_id", json!(long(129)))),
        ("request id with a control character", env("request_id", json!("r\u{7}"))),
        ("on_behalf_of too long", env("on_behalf_of", json!(long(257)))),
        ("operation id too short", env("operation_id", json!("op-1"))),
        ("operation id too long", env("operation_id", json!(format!("op-{}", long(200))))),
        ("operation id with a path", env("operation_id", json!("op-../../etc"))),
        ("issued_at without a zone", env("issued_at", json!("2026-11-18T10:00:00"))),
        ("issued_at with an offset", env("issued_at", json!("2026-11-18T10:00:00+01:00"))),
        ("issued_at that is not a date", env("issued_at", json!("yesterday"))),
        ("issued_at month 13", env("issued_at", json!("2026-13-18T10:00:00Z"))),
        ("wait_ms negative", env("wait_ms", json!(-1))),
        (
            "wait_ms beyond u64",
            serde_json::from_str(
                &request("sandbox.list", json!({})).to_string().replace("\"method\"", "\"wait_ms\":18446744073709551616,\"method\""),
            )
            .unwrap(),
        ),
        ("retry is not a boolean", env("retry", json!("yes"))),
        ("params is an array", env("params", json!([]))),
        (
            "vcpus zero",
            request(
                "sandbox.create",
                json!({"image": "python", "resources": {"vcpus": 0, "memory_mib": 256, "disk_mib": 128, "network": {"mode": "none"}}}),
            ),
        ),
        (
            "vcpus beyond u8",
            request(
                "sandbox.create",
                json!({"image": "python", "resources": {"vcpus": 256, "memory_mib": 256, "disk_mib": 128, "network": {"mode": "none"}}}),
            ),
        ),
        (
            "memory beyond u32",
            request(
                "sandbox.create",
                json!({"image": "python", "resources": {"vcpus": 1, "memory_mib": 4294967296u64, "disk_mib": 128, "network": {"mode": "none"}}}),
            ),
        ),
        (
            "a fractional number",
            request(
                "sandbox.create",
                json!({"image": "python", "resources": {"vcpus": 1.5, "memory_mib": 256, "disk_mib": 128, "network": {"mode": "none"}}}),
            ),
        ),
        (
            "a sandbox name with a slash",
            request(
                "sandbox.create",
                json!({"name": "a/b", "image": "python", "resources": {"vcpus": 1, "memory_mib": 256, "disk_mib": 128, "network": {"mode": "none"}}}),
            ),
        ),
        (
            "generation zero",
            request("sandbox.stop", json!({"sandbox_id": "sbx-00000000000000000000000000000000", "expected_generation": 0})),
        ),
        ("a list limit of zero", request("sandbox.list", json!({"limit": 0}))),
        ("a list limit above the maximum", request("sandbox.list", json!({"limit": 1001}))),
    ];
    for (what, wire) in bad {
        assert!(decode(wire.clone()).is_err(), "{what} was accepted: {wire}");
    }
    let good: Vec<(&str, Value)> = vec![
        ("owner scope at its bound", env("owner_scope", json!(long(128)))),
        ("request id at its bound", env("request_id", json!(long(128)))),
        ("on_behalf_of at its bound", env("on_behalf_of", json!(long(256)))),
        ("issued_at with milliseconds", env("issued_at", json!("2026-11-18T10:00:00.123Z"))),
        ("wait_ms at u64::MAX (it is capped, not refused)", env("wait_ms", json!(u64::MAX))),
        ("a list limit at the maximum", request("sandbox.list", json!({"limit": 1000}))),
        (
            "the widest port range",
            request(
                "sandbox.create",
                json!({"image": "python", "resources": {"vcpus": 1, "memory_mib": 256, "disk_mib": 128,
            "network": {"mode": "allowlist", "entries": [{"destination": {"name": "a.example"}, "ports": [{"from": 1, "to": 65535}]}]}}}),
            ),
        ),
    ];
    for (what, wire) in good {
        assert!(decode(wire.clone()).is_ok(), "{what} was refused: {:?}", decode(wire));
    }
}

fn valid_wire_requests() -> Vec<String> {
    crate::domain::Method::ALL
        .iter()
        .map(|m| {
            let params = crate::testing::rig::valid_params(*m);
            request(m.name(), params).to_string()
        })
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    /// T-API-06: the request decoder never panics, on arbitrary bytes...
    #[test]
    fn t_api_06_the_request_decoder_survives_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        if let Ok(envelope) = serde_json::from_slice::<RequestEnvelope>(&bytes) {
            let _ = envelope.validate();
        }
    }

    /// ...or on a valid request with a few bytes changed. Whatever still decodes also still
    /// round-trips: what the edge validated is what the core validates (PD-2).
    #[test]
    fn t_api_06_the_request_decoder_survives_mutated_valid_requests(
        which in 0usize..22,
        edits in proptest::collection::vec((any::<proptest::sample::Index>(), any::<u8>()), 1..6),
    ) {
        let valid = valid_wire_requests();
        let mut bytes = valid[which % valid.len()].clone().into_bytes();
        for (at, byte) in edits {
            let i = at.index(bytes.len());
            bytes[i] = byte;
        }
        if let Ok(envelope) = serde_json::from_slice::<RequestEnvelope>(&bytes) {
            let again: RequestEnvelope = serde_json::from_slice(&serde_json::to_vec(&envelope).unwrap()).unwrap();
            prop_assert_eq!(envelope.validate().is_ok(), again.validate().is_ok());
        }
    }

    /// The guest-protocol decoder: a frame is size-bounded before it is allocated, and arbitrary
    /// bytes from a guest are an error, never a panic and never an unbounded allocation.
    #[test]
    fn t_api_06_the_guest_protocol_decoder_survives_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..512), max in 0usize..4096) {
        let mut reader = bytes.as_slice();
        if let Ok(payload) = acf_wire::frame::read_frame(&mut reader, max) {
            prop_assert!(payload.len() <= max);
            let _ = serde_json::from_slice::<acf_wire::guest::GuestResponse>(&payload);
        }
        let _ = serde_json::from_slice::<acf_wire::guest::GuestResponse>(&bytes);
    }
}

#[test]
fn t_api_06_every_valid_request_used_as_a_fuzzing_seed_does_decode() {
    for wire in valid_wire_requests() {
        assert!(decode(serde_json::from_str(&wire).unwrap()).is_ok(), "{wire}");
    }
}
