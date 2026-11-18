//! T-AUTH: authority (contract §9). Roles, scope tags and the safety profile, through the admission
//! pipeline. The transport half of T-AUTH-01, -04 and -05 is in `edge.rs`.

use serde_json::{Value, json};

use crate::{
    api::{OperationResult, ReadResult},
    coordinator::PeerContext,
    domain::{HostMode, Method, OperationState, OperationType, PeerId, Role, Transport},
    error::FailureClass,
    testing::rig::{
        Rig, alice, bob, calls, create_params, eventually, exec_params, footprint, ops, sandbox_of, snapshot_of, target, valid_params,
        watch,
    },
};

/// T-AUTH-01 (core half, PD-2): the core checks the edge's statement against the enrolment in force.
/// A peer the table does not list has no authority, whatever a compromised edge claims.
#[tokio::test]
async fn t_auth_01_a_peer_that_is_not_enrolled_has_no_authority_at_the_core() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let claims = [("mallory", Role::Caller), ("mallory", Role::Operator), ("alice", Role::Operator), ("watch", Role::Caller)];
    for (peer_id, role) in claims {
        let mut forged = alice(&host);
        forged.peer = PeerContext { peer_id: PeerId::parse(peer_id).unwrap(), role, transport: Transport::Mtls };
        let before = footprint(&host);
        for method in ["sandbox.create", "sandbox.list", "host.info", "host.set_mode"] {
            let m = Method::parse(method).unwrap();
            let r = forged.refused(method, valid_params(m)).await;
            assert_eq!(r.class, FailureClass::AuthenticationFailed, "{peer_id} as {role:?} calling {method}");
        }
        assert_eq!(footprint(&host), before);
    }
    assert_eq!(calls(&rig.world, "provision"), 0);
}

/// T-AUTH-02: every method × every role, against the role table of §9.2.
#[tokio::test]
async fn t_auth_02_every_method_for_every_role_is_allowed_exactly_as_the_role_table_says() {
    let rig = Rig::new();
    let host = rig.serving().await;
    for &method in Method::ALL {
        for client in [watch(&host), alice(&host), ops(&host)] {
            let resp = client.call(method.name(), valid_params(method)).await;
            let denied = resp.refusal().is_some_and(|r| r.class == FailureClass::AuthorizationDenied);
            assert_eq!(denied, !method.allowed_for(client.peer.role), "{method} as {:?}: {:?}", client.peer.role, resp.answer);
        }
    }
    // The table itself, stated once in words: an observer sees the host and nothing in it.
    assert!(matches!(watch(&host).read("host.info", Value::Null).await, ReadResult::HostInfo(_)));
    assert!(matches!(watch(&host).read("host.metrics", Value::Null).await, ReadResult::Metrics(_)));
    assert_eq!(watch(&host).refused("sandbox.list", json!({})).await.class, FailureClass::AuthorizationDenied);
    assert_eq!(alice(&host).refused("profile.reload", Value::Null).await.class, FailureClass::AuthorizationDenied);
}

/// T-AUTH-03: another owner scope, or another peer, sees nothing and can touch nothing: `NOT_FOUND`
/// on reads and on mutations, so not even existence is revealed (AU-9). An operator succeeds.
#[tokio::test]
async fn t_auth_03_another_scope_or_peer_gets_not_found_and_an_operator_succeeds() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let owner = alice(&host);
    let sb = owner.ready(Some("mine")).await;
    let run = owner.exec(&sb, &["/bin/true"]).await;
    let snap = snapshot_of(
        &owner.done("snapshot.create", json!({"sandbox_id": sb.sandbox_id, "expected_generation": sb.generation, "name": "base"})).await,
    );
    let sb = owner.inspect(&sb.sandbox_id).await;

    for stranger in [bob(&host), owner.in_scope("team-other")] {
        let who = format!("{}/{}", stranger.peer.peer_id, stranger.scope);
        let before = footprint(&host);
        let reads: [(&str, Value); 5] = [
            ("sandbox.inspect", json!({"sandbox": sb.sandbox_id})),
            ("sandbox.inspect", json!({"sandbox": "mine"})),
            ("operation.get", json!({"operation_id": run.operation_id})),
            ("run.inspect", json!({"run_id": run.run_id})),
            ("run.output", json!({"run_id": run.run_id, "stream": "stdout"})),
        ];
        for (method, params) in reads {
            assert_eq!(stranger.refused(method, params).await.class, FailureClass::NotFound, "{who}: {method}");
        }
        assert!(stranger.sandboxes(json!({})).await.items.is_empty(), "{who}: lists are filtered");
        assert!(stranger.snapshots(json!({})).await.items.is_empty());
        assert!(stranger.operations(json!({})).await.items.is_empty());
        let mutations: [(&str, Value); 8] = [
            ("sandbox.start", target(&sb)),
            ("exec.run", exec_params(&sb, &["/bin/true"])),
            ("snapshot.create", target(&sb)),
            ("sandbox.stop", target(&sb)),
            ("sandbox.destroy", target(&sb)),
            ("snapshot.restore", json!({"snapshot": snap.snapshot, "target": {"kind": "new"}})),
            ("snapshot.delete", json!({"snapshot": snap.snapshot})),
            ("operation.cancel", json!({"operation_id": run.operation_id})),
        ];
        for (method, params) in mutations {
            assert_eq!(stranger.refused(method, params).await.class, FailureClass::NotFound, "{who}: {method}");
        }
        assert_eq!(footprint(&host), before, "{who}: a refusal leaves nothing behind");
        // A name is only unique inside a scope: the stranger may use the same one.
        assert!(stranger.call("sandbox.create", create_params(Some("mine"))).await.operation_view().is_some());
    }

    // An operator may act on any record.
    let operator = ops(&host);
    assert_eq!(operator.inspect(&sb.sandbox_id).await.tags.owner_scope.as_str(), "team-a");
    assert_eq!(operator.get(&run.operation_id).await.operation_id, run.operation_id);
    // By name too (§9.2), while the name is unambiguous among the records it may read. A name that
    // several scopes use does not pick one of them: the operator is told to use the id. A caller of
    // another scope still learns nothing from a name.
    let unique = sandbox_of(&owner.done("sandbox.create", create_params(Some("only-here"))).await);
    match operator.read("sandbox.inspect", json!({"sandbox": "only-here"})).await {
        ReadResult::Sandbox(found) => assert_eq!(found.sandbox_id, unique.sandbox_id),
        other => panic!("{other:?}"),
    }
    let ambiguous = operator.refused("sandbox.inspect", json!({"sandbox": "mine"})).await;
    assert_eq!(ambiguous.class, FailureClass::InvalidRequest, "three scopes hold a sandbox of that name: {}", ambiguous.message);
    assert_eq!(bob(&host).refused("sandbox.inspect", json!({"sandbox": "only-here"})).await.class, FailureClass::NotFound);
    operator.done("sandbox.destroy", target(&unique)).await;
    operator.done("snapshot.delete", json!({"snapshot": snap.snapshot})).await;
    let destroyed = operator.done("sandbox.destroy", target(&sb)).await;
    assert_eq!(destroyed.tags.peer_id.as_str(), "ops", "the operation is recorded under the peer that issued it");
    assert_eq!(owner.sandboxes(json!({})).await.items.len(), 0, "the owner sees the result");
}

/// T-AUTH-06: above a ceiling, a capability that is not granted, a field the profile has no rule
/// for → `SAFETY_CONTROL_DENIED`. Never clamped, and nothing is recorded.
#[tokio::test]
async fn t_auth_06_the_safety_profile_refuses_and_never_clamps() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let sb = a.ready(None).await;
    let before = footprint(&host);
    let resources =
        |vcpus: u64, memory: u64, disk: u64| json!({"vcpus": vcpus, "memory_mib": memory, "disk_mib": disk, "network": {"mode": "none"}});
    let denied: Vec<(&str, &str, Value)> = vec![
        ("vcpus above the ceiling", "sandbox.create", json!({"image": "python", "resources": resources(8, 256, 128)})),
        ("memory above the ceiling", "sandbox.create", json!({"image": "python", "resources": resources(2, 4096, 128)})),
        ("disk above the ceiling", "sandbox.create", json!({"image": "python", "resources": resources(2, 256, 8192)})),
        ("an image that is not listed", "sandbox.create", json!({"image": "kali", "resources": resources(2, 256, 128)})),
        (
            "a lifetime above the ceiling",
            "sandbox.create",
            json!({"image": "python", "resources": resources(2, 256, 128), "lifetime_secs": 7201}),
        ),
        (
            "more allowlist entries than the ceiling",
            "sandbox.create",
            json!({"image": "python", "resources": {"vcpus": 1, "memory_mib": 256, "disk_mib": 128, "network": {"mode": "allowlist",
                "entries": (0..5).map(|i| json!({"destination": {"name": format!("h{i}.example.org")}, "ports": [{"from": 443, "to": 443}]})).collect::<Vec<_>>()}}}),
        ),
        (
            "a private destination without the switch",
            "sandbox.create",
            json!({"image": "python", "resources": {"vcpus": 1, "memory_mib": 256, "disk_mib": 128, "network": {"mode": "allowlist",
                "entries": [{"destination": {"network": "10.0.0.0/8"}, "ports": [{"from": 5432, "to": 5432}]}]}}}),
        ),
        (
            "an environment variable the profile has no rule for",
            "exec.run",
            json!({"sandbox_id": sb.sandbox_id, "expected_generation": sb.generation, "command": {"argv": ["/bin/true"], "env": {"LD_PRELOAD": "/x.so"}}}),
        ),
        (
            "a working directory outside the profile",
            "exec.run",
            json!({"sandbox_id": sb.sandbox_id, "expected_generation": sb.generation, "command": {"argv": ["/bin/true"], "cwd": "/etc"}}),
        ),
        (
            "a runtime above the ceiling",
            "exec.run",
            json!({"sandbox_id": sb.sandbox_id, "expected_generation": sb.generation, "command": {"argv": ["/bin/true"], "limits": {"timeout_ms": 60001}}}),
        ),
    ];
    for (what, method, params) in denied {
        let r = a.refused(method, params).await;
        assert_eq!(r.class, FailureClass::SafetyControlDenied, "{what}: {}", r.message);
        assert_eq!(footprint(&host), before, "{what}: nothing may be recorded or reserved");
    }
    assert_eq!(calls(&rig.world, "provision"), 1, "only the one sandbox that was admitted was ever provisioned");
    // Exactly at a ceiling is admitted, and it is admitted as asked.
    let at = sandbox_view(
        &a.done("sandbox.create", json!({"image": "python", "resources": resources(4, 2048, 4096), "lifetime_secs": 7200})).await,
    );
    assert_eq!((at.resources.vcpus, at.resources.memory_mib, at.resources.disk_mib), (4, 2048, 4096));
}

fn sandbox_view(op: &crate::api::OperationView) -> crate::api::SandboxView {
    crate::testing::rig::sandbox_of(op)
}

/// T-AUTH-07: a profile reload does not change an operation already admitted (SP-2); it is a
/// recorded operator operation; an invalid profile is refused and the previous one stays in force.
#[tokio::test]
async fn t_auth_07_profile_reload_is_recorded_affects_only_later_operations_and_refuses_an_invalid_profile() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let (a, operator) = (alice(&host), ops(&host));
    let sb = a.ready(None).await;
    let first_profile = a.info().await.profile;

    // An execution is in flight under the first profile...
    rig.world.hold("exec");
    let running = {
        let (a, sb) = (a.clone(), sb.clone());
        tokio::spawn(async move { a.exec(&sb, &["/bin/true"]).await })
    };
    eventually("the command reaches the guest", || rig.world.waiting("exec") == 1).await;

    // ...when the profile is changed to forbid execution, and reloaded.
    rig.edit_profile("exec: true", "exec: false");
    let reload = operator.done("profile.reload", Value::Null).await;
    assert_eq!(reload.operation_type, OperationType::ProfileReload);
    let installed = match &reload.result {
        Some(OperationResult::Host(change)) => change.profile.clone().expect("the reload reports the profile it installed"),
        other => panic!("{other:?}"),
    };
    assert_ne!(installed.digest, first_profile.digest);
    assert_eq!(a.info().await.profile, installed);
    assert!(
        operator.operations(json!({})).await.items.iter().any(|o| o.operation_id == reload.operation_id),
        "the reload is a recorded operation"
    );

    // The execution in flight is governed by the profile it was admitted under, and finishes.
    rig.world.release("exec");
    let finished = running.await.unwrap();
    assert_eq!(finished.state, OperationState::Succeeded);
    assert_eq!(finished.profile_id, first_profile);
    // A later one is governed by the new profile.
    let sb = a.inspect(&sb.sandbox_id).await;
    assert_eq!(a.refused("exec.run", exec_params(&sb, &["/bin/true"])).await.class, FailureClass::SafetyControlDenied);

    // An invalid profile is refused. Nothing is installed and nothing is recorded.
    rig.edit_profile("max_pids: 512", "max_pids: 0");
    let before = footprint(&host);
    let refused = operator.refused("profile.reload", Value::Null).await;
    assert_eq!(refused.class, FailureClass::IntegrityFailure);
    assert_eq!(footprint(&host), before);
    assert_eq!(a.info().await.profile, installed, "the previous profile stays in force");
    assert_eq!(a.info().await.mode, HostMode::Serving);
}

/// T-AUTH-08: `authority` is reserved for a signed decision. A host that does not advertise
/// `signed_decision` refuses a request that carries it. It never ignores it (AU-11).
#[tokio::test]
async fn t_auth_08_a_request_carrying_authority_is_refused_not_ignored() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    assert!(!a.info().await.features.iter().any(|f| f == "signed_decision"));
    let before = footprint(&host);
    for (method, params) in [("sandbox.create", create_params(None)), ("sandbox.list", json!({})), ("host.info", Value::Null)] {
        let mut env = a.envelope(method, params);
        env.authority = Some(json!({"decision": "allow", "signature": "AAAA"}));
        let resp = a.send(env).await;
        assert_eq!(resp.refusal().map(|r| r.class), Some(FailureClass::InvalidRequest), "{method}");
    }
    assert_eq!(footprint(&host), before);
    assert_eq!(calls(&rig.world, "provision"), 0);
}
