//! T-OBS, T-VER, T-BACK, T-RETRY and T-SCOPE: observability (§24), versioning (§25), the backend
//! port (§26), retries (§14) and scope hygiene. T-OBS-04 (label cardinality, L1) is in
//! `telemetry/metrics.rs`; the guest half of T-VER-01 is in `guest/client.rs`.

use std::path::Path;

use serde_json::{Value, json};

use crate::{
    domain::{HostMode, LifecycleState, Method, OperationState},
    error::{AcfError, FailureClass},
    ids::SandboxRef,
    testing::{
        fake_backend::Fail,
        rig::{Rig, alice, calls, create_params, eventually, exec_params, footprint, ops, snapshot_of, target},
    },
};

fn jail(sb: &crate::api::SandboxView) -> String {
    SandboxRef { sandbox_id: sb.sandbox_id.clone(), generation: sb.generation }.jail_id()
}

/// T-OBS-01 and T-OBS-02: when the telemetry sink fails no operation outcome changes (OB-6); the
/// loss is visible as a gap in the event sequence and as a counter; listing recovers the state.
#[tokio::test]
async fn t_obs_01_t_obs_02_a_failing_telemetry_sink_changes_no_outcome_and_the_loss_is_visible() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let sb = a.ready(None).await;
    let file = rig.cfg.paths.state_root.join("telemetry").join("events.jsonl");
    let written = || std::fs::read_to_string(&file).unwrap().lines().map(|l| serde_json::from_str::<Value>(l).unwrap()).collect::<Vec<_>>();
    let before = written();
    assert!(!before.is_empty());
    let seqs: Vec<u64> = before.iter().map(|e| e["seq"].as_u64().unwrap()).collect();
    assert!(seqs.windows(2).all(|w| w[1] == w[0] + 1), "the sequence is strictly increasing with no gap: {seqs:?}");
    // OB-5: an event that describes a committed change carries that change's commit sequence.
    assert!(before.iter().filter(|e| e["kind"] == "operation.finished").all(|e| e["commit_seq"].as_u64().is_some_and(|s| s > 0)));
    assert!(
        before.iter().all(|e| e["lineage"] == host.journal.lineage()
            && e["activation_epoch"] == host.journal.epoch()
            && e["host_id"] == "test-host")
    );
    assert_eq!(host.telemetry.metrics.get("events_dropped"), 0);

    // The sink breaks. Every operation still ends exactly as it would have.
    host.telemetry.events.break_file_for_test();
    assert_eq!(a.exec(&sb, &["/bin/true"]).await.state, OperationState::Succeeded);
    let snap = snapshot_of(&a.done("snapshot.create", target(&sb)).await);
    a.done("snapshot.delete", json!({"snapshot": snap.snapshot})).await;
    a.done("sandbox.destroy", target(&a.inspect(&sb.sandbox_id).await)).await;
    let dropped = host.telemetry.metrics.get("events_dropped");
    assert!(dropped > 0, "the loss is counted");
    assert_eq!(ops(&host).metrics().await["counters"]["events_dropped"], json!(dropped));
    assert_eq!(written().len(), before.len(), "nothing more reached the sink");

    // A consumer of the sink sees a gap: the sequence went on without it...
    let last_seen = *seqs.last().unwrap();
    let in_memory = host.telemetry.events.recent();
    assert_eq!(in_memory.last().unwrap().seq, last_seen + dropped, "one sequence number per event, written or lost");
    // ...and resynchronises from committed state, which never depended on telemetry (OB-4).
    let since =
        json!({"lineage": host.journal.lineage(), "sequence": before.iter().filter_map(|e| e["commit_seq"].as_u64()).max().unwrap()});
    let changed = a.sandboxes(json!({"changed_since": since})).await;
    assert_eq!(
        changed.items.iter().map(|v| v.state).collect::<Vec<_>>(),
        vec![LifecycleState::Destroyed],
        "the listing has what the lost events would have said"
    );
}

/// T-OBS-03: each standing-risk measurement (§24.3) moves under the condition it reports.
#[tokio::test]
async fn t_obs_03_every_standing_risk_measurement_moves_under_its_condition() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let (a, operator) = (alice(&host), ops(&host));
    let gauge = |m: &Value, name: &str| m["gauges"][name].as_i64().unwrap_or_else(|| panic!("no gauge `{name}`: {m}"));
    let healthy = a.ready(None).await;
    let m = operator.metrics().await;
    for (name, expected) in [
        ("live_sandboxes", 1),
        ("quarantined_generations", 0),
        ("oldest_quarantine_age_ms", 0),
        ("failed_generations_holding_leases", 0),
        ("unmanaged_resources", 0),
        ("operations_open", 0),
        ("oldest_open_operation_age_ms", 0),
        ("store_reserve_released", 0),
        ("host_mode", 1),
        ("ms_since_last_complete_sweep", -1),
    ] {
        assert_eq!(gauge(&m, name), expected, "{name} on a healthy, freshly started host");
    }
    assert!(gauge(&m, "store_bytes") > 0 && gauge(&m, "store_reserve_bytes") == 65_536);

    // A runtime is lost → a FAILED generation holds a lease.
    let lost = a.ready(None).await;
    rig.world.set_phase(&jail(&lost), crate::backend::VmmState::Absent);
    host.sweep_once().await;
    // A generation is quarantined, and ages.
    let doubtful = a.ready(None).await;
    rig.forge_marker(&doubtful);
    a.op("sandbox.destroy", target(&doubtful)).await;
    rig.clock.advance_ms(90_000);
    // An operation is in flight, and ages.
    rig.world.hold("exec");
    let (a2, sb2) = (a.clone(), healthy.clone());
    let running = tokio::spawn(async move { a2.exec(&sb2, &["/bin/work"]).await });
    eventually("the command reaches the guest", || rig.world.waiting("exec") == 1).await;
    rig.clock.advance_ms(45_000);
    // Something nobody recorded appears on disk.
    std::fs::create_dir_all(rig.layout.root().join("sandboxes").join("sbx-33333333333333333333333333333333").join("1")).unwrap();
    host.recover_generations().await.unwrap();
    // The store spends its reserve.
    host.journal.inject_append_error_once(std::io::ErrorKind::StorageFull);
    a.done("sandbox.stop", target(&a.inspect(&lost.sandbox_id).await)).await;
    // The host drains.
    operator.done("host.set_mode", json!({"mode": "DRAINING"})).await;

    let m = operator.metrics().await;
    assert_eq!(gauge(&m, "live_sandboxes"), 3);
    assert_eq!(gauge(&m, "quarantined_generations"), 1);
    assert!(gauge(&m, "oldest_quarantine_age_ms") >= 135_000, "{m}");
    assert_eq!(gauge(&m, "operations_open"), 1);
    assert!(gauge(&m, "oldest_open_operation_age_ms") >= 45_000);
    assert_eq!(gauge(&m, "operations_in_flight"), 1);
    assert_eq!(gauge(&m, "unmanaged_resources"), 1);
    assert_eq!(gauge(&m, "store_reserve_released"), 1);
    assert_eq!(gauge(&m, "host_mode"), 2);
    assert!(gauge(&m, "ms_since_last_complete_sweep") >= 0, "a sweep has completed");
    let counter = |name: &str| m["counters"][name].as_u64().unwrap_or(0);
    assert_eq!(counter("runtime_losses_detected"), 1);
    assert_eq!(counter("quarantines"), 1);
    assert!(counter("sweeps") >= 1 && counter("recovery_runs") >= 2);
    // FAILED-and-leased went up with the lost runtime and down again when it was stopped (STOPPED, still leased).
    assert_eq!(gauge(&m, "failed_generations_holding_leases"), 0);
    rig.world.release("exec");
    running.await.unwrap();

    // Refusals before authentication are counted by the edge and reported through the core.
    host.telemetry.metrics.incr("edge_refused_before_authentication", 0);
    assert!(operator.metrics().await["counters"].get("edge_refused_before_authentication").is_some());
}

/// T-VER-01 (caller ↔ host) and T-VER-02: a protocol major mismatch is refused before any
/// mutation; so is a request that uses a feature this host does not advertise (VR-1, VR-3).
#[tokio::test]
async fn t_ver_01_t_ver_02_unsupported_versions_and_unadvertised_features_are_refused() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let sb = a.ready(None).await;
    let info = a.info().await;
    assert_eq!(info.protocols, vec!["acf.host/2".to_owned()]);
    for deferred in ["signed_decision", "incremental_output"] {
        assert!(!info.features.iter().any(|f| f == deferred), "`{deferred}` is reserved, not offered");
    }
    assert!(!info.capabilities.incremental_output);
    let before = (footprint(&host), host.journal.last_seq());

    // A destroy in another protocol major is refused like anything else: before any mutation.
    let mut old = a.envelope("sandbox.destroy", target(&sb));
    old.protocol = "acf.host/1".into();
    assert_eq!(a.send(old).await.refusal().map(|r| r.class), Some(FailureClass::ProtocolError));
    // `signed_decision`: the field exists in the schema and is refused, never ignored.
    let mut signed = a.envelope("sandbox.destroy", target(&sb));
    signed.authority = Some(json!({"token": "x"}));
    assert_eq!(a.send(signed).await.refusal().map(|r| r.class), Some(FailureClass::InvalidRequest));
    assert_eq!((footprint(&host), host.journal.last_seq()), before);
    assert_eq!(a.inspect(&sb.sandbox_id).await.state, LifecycleState::Ready);

    // `incremental_output`: reading the output of an execution in flight needs the feature.
    rig.world.hold("exec");
    let mut env = a.envelope("exec.run", exec_params(&sb, &["/bin/work"]));
    env.wait_ms = Some(0);
    let pending = a.send(env).await.operation_view().cloned().unwrap();
    eventually("the command reaches the guest", || rig.world.waiting("exec") == 1).await;
    let refused = a.refused("run.output", json!({"run_id": pending.run_id, "stream": "stdout"})).await;
    assert_eq!(refused.class, FailureClass::Unsupported, "{}", refused.message);
    rig.world.release("exec");
    eventually("the execution ends", || host.operations_in_flight() == 0).await;
    assert!(
        matches!(a.read("run.output", json!({"run_id": pending.run_id, "stream": "stdout"})).await, crate::api::ReadResult::Output(_)),
        "once it has ended the output is readable"
    );
}

/// VR-3 with §20.1: a feature is advertised only while the host offers it. Mode `allowlist` is
/// offered only if the profile lists it **and** the backend supports it, and `host.info` says so
/// without anyone having to try. What the backend alone can do stays in `capabilities`.
#[tokio::test]
async fn t_ver_02_a_feature_is_advertised_only_while_the_host_offers_it() {
    use crate::domain::NetworkMode;
    let offered = |info: &crate::api::HostInfo| info.features.iter().any(|f| f == crate::api::ALLOWLIST_NETWORK);

    let rig = Rig::new();
    let host = rig.serving().await;
    assert!(offered(&alice(&host).info().await), "the profile lists the mode and the backend supports it");

    // The profile stops listing it: the reload changes what is advertised, and the request is refused.
    rig.edit_profile("network_modes: [none, allowlist]", "network_modes: [none]");
    ops(&host).done("profile.reload", Value::Null).await;
    let info = alice(&host).info().await;
    assert!(!offered(&info), "{:?}", info.features);
    assert!(info.capabilities.network_modes.contains(&NetworkMode::Allowlist), "the backend's own declaration is unchanged");
    let mut wanted = create_params(None);
    wanted["resources"]["network"] =
        json!({"mode": "allowlist", "entries": [{"destination": {"name": "pypi.org"}, "ports": [{"from": 443, "to": 443}]}]});
    assert_eq!(alice(&host).refused("sandbox.create", wanted.clone()).await.class, FailureClass::SafetyControlDenied);

    // The profile lists it again and the backend of the next activation does not support it.
    rig.edit_profile("network_modes: [none]", "network_modes: [none, allowlist]");
    rig.world.withhold("allowlist");
    drop(host);
    let host = rig.serving().await;
    let info = alice(&host).info().await;
    assert!(!offered(&info), "{:?}", info.features);
    assert!(!info.capabilities.network_modes.contains(&NetworkMode::Allowlist));
    assert_eq!(alice(&host).refused("sandbox.create", wanted).await.class, FailureClass::Unsupported);
    // Every other feature is advertised throughout, and the two deferred ones never.
    assert_eq!(info.features.len(), crate::api::FEATURES.len() - 1);
}

/// T-BACK-03: a request that needs a capability the backend does not declare → `UNSUPPORTED`,
/// before BEGIN, with no effect. It is never silently skipped (BK-5).
#[tokio::test]
async fn t_back_03_an_undeclared_capability_is_refused_with_no_effect() {
    let rig = Rig::new();
    for capability in ["snapshot", "restore", "guest_exec", "secret_injection", "allowlist"] {
        rig.world.withhold(capability);
    }
    let host = rig.serving().await;
    let a = alice(&host);
    let caps = a.info().await.capabilities;
    assert!(!caps.snapshot && !caps.restore && !caps.guest_exec && !caps.secret_injection, "the host says what it cannot do: {caps:?}");
    let sb = a.ready(None).await;
    let before = (footprint(&host), rig.world.calls().len());
    let allowlist = json!({"image": "python", "resources": {"vcpus": 1, "memory_mib": 256, "disk_mib": 128,
        "network": {"mode": "allowlist", "entries": [{"destination": {"name": "pypi.org"}, "ports": [{"from": 443, "to": 443}]}]}}});
    let needs: [(&str, Value); 3] =
        [("exec.run", exec_params(&sb, &["/bin/true"])), ("snapshot.create", target(&sb)), ("sandbox.create", allowlist)];
    for (method, params) in needs {
        let r = a.refused(method, params).await;
        assert_eq!(r.class, FailureClass::Unsupported, "{method}: {}", r.message);
    }
    assert_eq!((footprint(&host), rig.world.calls().len()), before, "no record, no reservation, no backend call");
    // What the backend does declare still works, and containment never depends on a capability.
    a.done("sandbox.destroy", target(&sb)).await;
}

/// T-RETRY-01: a dependency outage leads to bounded retries, not a storm (RY-2, RY-4, RY-6), and a
/// step whose effect may have happened is never issued again (RY-3).
#[tokio::test]
async fn t_retry_01_a_dependency_outage_is_retried_within_bounds_and_never_becomes_a_storm() {
    let rig = Rig::with(|c| {
        c.operations.step_max_attempts = 3;
        c.operations.retry_budget = 1;
    });
    let host = rig.serving().await;
    let a = alice(&host);
    let outage = || AcfError::unavailable("the VMM control socket is not answering"); // side effect NONE: provably nothing happened

    // One clean failure, then success: the step is retried and the operation succeeds.
    rig.world.fail_next("provision", Fail::Before(outage()));
    let op = a.op("sandbox.create", create_params(None)).await;
    assert_eq!(op.state, OperationState::Succeeded);
    assert_eq!(calls(&rig.world, "provision"), 2);
    assert_eq!(host.telemetry.metrics.get("step_retries"), 1);

    // An outage that persists: exactly `step_max_attempts` attempts, then FAILED and undone.
    let world = std::sync::Arc::clone(&rig.world);
    rig.world.on_call("provision", move || world.fail_next("provision", Fail::Before(AcfError::unavailable("still down"))));
    rig.world.clear_calls();
    let op = a.op("sandbox.create", create_params(None)).await;
    rig.world.clear_hooks();
    assert_eq!((op.state, op.failure.as_ref().map(|f| f.class)), (OperationState::Failed, Some(FailureClass::DependencyUnavailable)));
    assert_eq!(calls(&rig.world, "provision"), 3, "bounded by step_max_attempts");
    assert_eq!(footprint(&host).1, 1, "the failed create left no lease");

    // A failure that may have had an effect is never retried: the operation observes and undoes.
    rig.world.clear_calls();
    rig.world.fail_next("provision", Fail::After(AcfError::unavailable("the reply was lost").with_possible_side_effect()));
    let op = a.op("sandbox.create", create_params(None)).await;
    assert_eq!(op.state, OperationState::Failed);
    assert_eq!(calls(&rig.world, "provision"), 1, "a step that may have happened is not issued again");
    // Classes that are never retried, whatever their marker (RY-5).
    for never in
        [AcfError::corrupt("digest mismatch"), AcfError::security("seccomp filter missing"), AcfError::incompatible("guest too old")]
    {
        rig.world.clear_calls();
        rig.world.fail_next("provision", Fail::Before(never));
        assert_eq!(a.op("sandbox.create", create_params(None)).await.state, OperationState::Failed);
        assert_eq!(calls(&rig.world, "provision"), 1);
    }

    // The host-wide budget: with one retry slot taken, another operation's step is not retried at all.
    let _held = host.retry_budget.try_acquire().unwrap();
    rig.world.clear_calls();
    rig.world.fail_next("provision", Fail::Before(outage()));
    let op = a.op("sandbox.create", create_params(None)).await;
    assert_eq!(op.state, OperationState::Failed, "no budget, no retry: the caller is told now");
    assert_eq!(calls(&rig.world, "provision"), 1);
    assert_eq!(host.telemetry.metrics.get("retry_budget_exhausted"), 1);
    assert_eq!(host.mode(), HostMode::Serving);
}

fn rust_sources(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Lines of `path` that are code: not comments, and not inside the file's test module.
fn code_lines(path: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(path).unwrap();
    let code = text.split("#[cfg(test)]").next().unwrap_or_default();
    code.lines().map(str::trim).filter(|l| !l.starts_with("//")).map(str::to_owned).collect()
}

/// T-BACK-01: nothing above the backend port names a backend. The coordinator, the API, the
/// domain, the store, recovery, authority, the edge and telemetry are written against the port
/// alone, so that the VMM, its isolation controls and its plumbing can be replaced as one unit.
#[test]
fn t_back_01_nothing_above_the_backend_port_names_a_backend() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let above = ["coordinator", "api", "domain", "store", "recovery", "authority", "edge", "telemetry", "secrets"];
    let forbidden = [
        "backend::firecracker",
        "backend::process",
        "backend::netns",
        "cfg.firecracker",
        ".firecracker.",
        "FirecrackerConfig",
        "jailer",
        "Jailer",
    ];
    let mut files = Vec::new();
    for dir in above {
        rust_sources(&src.join(dir), &mut files);
    }
    assert!(files.len() > 40, "the scan found the sources: {}", files.len());
    let mut found = Vec::new();
    for file in &files {
        for line in code_lines(file) {
            if let Some(word) = forbidden.iter().find(|w| line.contains(**w)) {
                found.push(format!("{}: `{word}` in `{line}`", file.strip_prefix(&src).unwrap().display()));
            }
        }
    }
    assert!(found.is_empty(), "backend-specific names above the port:\n  {}", found.join("\n  "));
}

/// T-SCOPE-01: the host agent contains no tenant, billing, scheduler, evidence-ledger or
/// object-store code or schema. Those belong to other planes; a peer is not a tenant (INV-015).
#[test]
fn t_scope_01_the_host_agent_holds_no_tenant_billing_scheduler_or_object_store_concept() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_sources(&src, &mut files);
    let foreign =
        ["tenant", "billing", "invoice", "price", "scheduler", "placement", "object_store", "s3", "bucket", "evidence_ledger", "approval"];
    let mut found = Vec::new();
    for file in files.iter().filter(|f| !f.starts_with(src.join("testing"))) {
        for line in code_lines(file) {
            let lower = line.to_lowercase();
            let words: Vec<&str> = lower.split(|c: char| !c.is_ascii_alphanumeric() && c != '_').collect();
            if let Some(word) =
                foreign.iter().find(|w| words.iter().any(|x| x == *w || x.starts_with(&format!("{w}_")) || x.ends_with(&format!("_{w}"))))
            {
                found.push(format!("{}: `{word}` in `{line}`", file.strip_prefix(&src).unwrap().display()));
            }
        }
    }
    assert!(found.is_empty(), "concepts of another plane in the host agent:\n  {}", found.join("\n  "));
    // The API has no place for them either: the command set is the 22 methods of the contract.
    assert_eq!(Method::ALL.len(), 22);
    let api = crate::api::schema::host_api().unwrap().to_string().to_lowercase();
    for word in ["tenant", "billing", "price"] {
        assert!(!api.contains(word), "`{word}` appears in the published API");
    }
}
