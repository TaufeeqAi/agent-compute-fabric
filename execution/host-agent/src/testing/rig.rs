//! The test rig: the real coordinator over an on-disk store and a shared in-memory world, and a
//! client that talks to it through the one admission pipeline every endpoint feeds.
//!
//! * **A restart is modelled, not mocked.** [`Rig::boot`] opens the store again (a new activation
//!   epoch) over the same disk and the same world of still-running fake runtimes — exactly what a
//!   new core finds after its predecessor died.
//! * **Requests go in the front door.** [`Client`] builds a wire envelope and calls
//!   `Host::handle`, so every test exercises protocol, schema, enrolment, role, host mode, rate and
//!   acceptance checks, and reads the answer a real caller would get.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use serde_json::{Value, json};

use super::{
    fake_backend::{FakeBackend, FakeWorld},
    private_tempdir, trusted_owners,
};
use crate::{
    api::{
        HostInfo, OperationResult, OperationView, PROTOCOL, Page, ReadResult, Refusal, RequestEnvelope, ResponseEnvelope, SandboxView,
        SnapshotView,
    },
    app::{self, Assembly, TrustedInputs},
    authority::{Enrolment, SafetyProfile, profile::test_support::YAML as PROFILE_YAML},
    clock::{Clock, ManualClock},
    config::{HostConfig, test_support::config},
    coordinator::{Host, PeerContext},
    domain::{ContainmentReason, Method, OperationState, OwnerScope, PeerId, Role, RunResult, Transport},
    ids::{OperationId, SandboxId},
    resources::lifetime::MemoryLifetime,
    secrets::MemorySecrets,
    storage::{Layout, images::test_support as img},
};

/// The peers every rig enrols: two callers, an operator and an observer.
pub(crate) const ENROLMENT_YAML: &str = "schema_version: 1
peers:
  - { peer_id: alice, role: caller, match: { local_uid: 5001 } }
  - { peer_id: bob, role: caller, match: { local_uid: 5002 } }
  - { peer_id: ops, role: operator, match: { local_uid: 5003 } }
  - { peer_id: watch, role: observer, match: { local_uid: 5004 } }
";

pub(crate) struct Rig {
    pub dir: tempfile::TempDir,
    pub cfg: Arc<HostConfig>,
    pub layout: Arc<Layout>,
    pub world: Arc<FakeWorld>,
    pub clock: Arc<ManualClock>,
    pub lifetime: Arc<MemoryLifetime>,
    pub secrets: Arc<MemorySecrets>,
    activations: AtomicU64,
    /// Violations of J-1 … J-8 seen after any commit of any activation of this rig (T-STATE-03).
    violations: Arc<std::sync::Mutex<Vec<String>>>,
}

impl Drop for Rig {
    fn drop(&mut self) {
        // Every test that uses a rig also checks the joint-state invariants after every commit.
        if !std::thread::panicking() {
            self.assert_invariants();
        }
    }
}

impl Rig {
    pub(crate) fn new() -> Self {
        Self::with(|_| {})
    }

    /// A rig whose host configuration was adjusted before anything was built from it.
    pub(crate) fn with(tweak: impl FnOnce(&mut HostConfig)) -> Self {
        // The suites commit tens of thousands of times; none of them cuts the power.
        crate::durability::skip_in_tests(true);
        let dir = private_tempdir();
        let mut cfg = config(dir.path());
        cfg.security.trusted_owner_uids = trusted_owners();
        tweak(&mut cfg);
        std::fs::write(&cfg.paths.profile_path, PROFILE_YAML).unwrap();
        std::fs::write(&cfg.paths.enrolment_path, ENROLMENT_YAML).unwrap();
        let cfg = Arc::new(cfg);
        let layout = Arc::new(Layout::open(&cfg.paths.state_root).unwrap());
        img::install(&cfg.paths.state_root.join("images"), "python", b"kernel", b"rootfs");
        Self {
            dir,
            cfg,
            layout,
            world: FakeWorld::new(),
            clock: Arc::new(ManualClock::new()),
            lifetime: Arc::new(MemoryLifetime::default()),
            secrets: Arc::new(MemorySecrets::default()),
            activations: AtomicU64::new(0),
            violations: Arc::default(),
        }
    }

    /// Replace the ownership marker of `sb`'s generation with one that proves nothing (RC-1).
    pub(crate) fn forge_marker(&self, sb: &SandboxView) {
        std::fs::write(self.layout.generation_path(&sb.sandbox_id, sb.generation).join("OWNER.json"), b"{}").unwrap();
    }

    /// Where the manifest of `snap` is stored.
    pub(crate) fn manifest_path(&self, snap: &SnapshotView) -> std::path::PathBuf {
        self.layout.snapshot_path(&snap.snapshot.snapshot_id, snap.snapshot.snapshot_generation).join("manifest.json")
    }

    /// J-1 … J-8 held after every commit made so far.
    pub(crate) fn assert_invariants(&self) {
        let seen = self.violations.lock().unwrap();
        assert!(seen.is_empty(), "joint-state invariants were violated after a commit:\n  {}", seen.join("\n  "));
    }

    /// The safety profile as the profile file says it now.
    pub(crate) fn profile(&self) -> SafetyProfile {
        let bytes = std::fs::read(&self.cfg.paths.profile_path).unwrap();
        SafetyProfile::parse(&bytes, app::sha256_hex(&bytes)).unwrap()
    }

    /// Replace text in the profile file (for `profile.reload` and restart tests).
    pub(crate) fn edit_profile(&self, from: &str, to: &str) {
        let text = std::fs::read_to_string(&self.cfg.paths.profile_path).unwrap();
        assert!(text.contains(from), "the profile has no `{from}`");
        std::fs::write(&self.cfg.paths.profile_path, text.replace(from, to)).unwrap();
    }

    pub(crate) fn enrolment() -> Enrolment {
        Enrolment::parse(ENROLMENT_YAML.as_bytes(), app::sha256_hex(ENROLMENT_YAML.as_bytes())).unwrap()
    }

    /// A new activation over the same disk and the same world: what a restarted core is. It has not
    /// recovered yet, so it is `STARTING`.
    pub(crate) fn boot(&self) -> Arc<Host> {
        self.boot_with(vec![])
    }

    /// [`Rig::boot`] with additional failed mandatory checks: the host will be in `CONTAINMENT`.
    /// The relations of the parameter register are always checked, as at a real start.
    pub(crate) fn boot_with(&self, extra: Vec<ContainmentReason>) -> Arc<Host> {
        let n = self.activations.fetch_add(1, Ordering::SeqCst) + 1;
        let profile = self.profile();
        let mut reasons: Vec<ContainmentReason> =
            self.cfg.mandatory_checks(Some(&profile)).into_iter().map(ContainmentReason::MandatoryCheck).collect();
        reasons.extend(extra);
        let inputs = TrustedInputs { profile, enrolment: Self::enrolment(), tls: None, reasons };
        let world = Arc::clone(&self.world);
        let clock: Arc<dyn Clock> = self.clock.clone();
        let assembly = Assembly {
            backend: Box::new(move |_cfg, layout, clock| Arc::new(FakeBackend::new(world, layout, clock))),
            lifetime: self.lifetime.clone(),
            secrets: self.secrets.clone(),
            clock,
        };
        let host = app::assemble(
            Arc::clone(&self.cfg),
            Arc::clone(&self.layout),
            "test-config",
            inputs,
            assembly,
            None,
            format!("test-instance-{n}"),
        )
        .unwrap();
        let (cfg, seen) = (Arc::clone(&self.cfg), Arc::clone(&self.violations));
        host.journal.observe_commits(move |state| {
            let bad = super::invariants::violations(state, &cfg);
            if !bad.is_empty() {
                seen.lock().unwrap().push(format!("activation {n}, commit {}: {}", state.last_seq, bad.join("; ")));
            }
        });
        host
    }

    /// Boot, recover, and leave `STARTING`: a host that serves.
    pub(crate) async fn serving(&self) -> Arc<Host> {
        let h = self.boot();
        h.recover().await.unwrap();
        h.finish_starting();
        h
    }
}

/// One enrolled peer speaking to one host in one owner scope.
#[derive(Clone)]
pub(crate) struct Client {
    pub host: Arc<Host>,
    pub peer: PeerContext,
    pub scope: String,
}

fn client(host: &Arc<Host>, peer_id: &str, role: Role, scope: &str) -> Client {
    Client {
        host: Arc::clone(host),
        peer: PeerContext { peer_id: PeerId::parse(peer_id).unwrap(), role, transport: Transport::Local },
        scope: scope.to_owned(),
    }
}

/// Caller `alice` in scope `team-a`.
pub(crate) fn alice(host: &Arc<Host>) -> Client {
    client(host, "alice", Role::Caller, "team-a")
}

/// Caller `bob` in scope `team-b`.
pub(crate) fn bob(host: &Arc<Host>) -> Client {
    client(host, "bob", Role::Caller, "team-b")
}

/// Operator `ops`.
pub(crate) fn ops(host: &Arc<Host>) -> Client {
    client(host, "ops", Role::Operator, "ops")
}

/// Observer `watch`.
pub(crate) fn watch(host: &Arc<Host>) -> Client {
    client(host, "watch", Role::Observer, "watch")
}

impl Client {
    /// The same peer in another owner scope.
    pub(crate) fn in_scope(&self, scope: &str) -> Client {
        Client { scope: scope.to_owned(), ..self.clone() }
    }

    /// The same peer and scope, talking to another activation of the host.
    pub(crate) fn on(&self, host: &Arc<Host>) -> Client {
        Client { host: Arc::clone(host), ..self.clone() }
    }

    /// A well-formed request for `method`: a fresh operation id and the host's current time wherever
    /// the method needs them.
    pub(crate) fn envelope(&self, method: &str, params: Value) -> RequestEnvelope {
        let needs_operation = Method::parse(method).is_none_or(Method::requires_operation);
        RequestEnvelope {
            protocol: PROTOCOL.to_owned(),
            request_id: Some("req-1".to_owned()),
            operation_id: needs_operation.then(OperationId::generate),
            retry: false,
            issued_at: needs_operation.then(|| self.host.clock.wall_rfc3339()),
            owner_scope: OwnerScope::parse(&self.scope).unwrap(),
            on_behalf_of: None,
            authority: None,
            wait_ms: None,
            method: method.to_owned(),
            params: if params.is_null() { None } else { Some(params) },
        }
    }

    pub(crate) async fn send(&self, envelope: RequestEnvelope) -> ResponseEnvelope {
        self.host.handle(&self.peer, envelope).await
    }

    pub(crate) async fn call(&self, method: &str, params: Value) -> ResponseEnvelope {
        self.send(self.envelope(method, params)).await
    }

    /// The operation an accepted request created.
    pub(crate) async fn op(&self, method: &str, params: Value) -> OperationView {
        let resp = self.call(method, params).await;
        match resp.operation_view() {
            Some(v) => v.clone(),
            None => panic!("`{method}` was not accepted: {:?}", resp.answer),
        }
    }

    /// An operation that must have ended `SUCCEEDED` within the wait.
    pub(crate) async fn done(&self, method: &str, params: Value) -> OperationView {
        let v = self.op(method, params).await;
        assert_eq!(v.state, OperationState::Succeeded, "`{method}` ended {:?}: {:?}", v.state, v.failure);
        v
    }

    /// The refusal of a request that must not be accepted.
    pub(crate) async fn refused(&self, method: &str, params: Value) -> Refusal {
        let resp = self.call(method, params).await;
        match resp.refusal() {
            Some(r) => r.clone(),
            None => panic!("`{method}` was not refused: {:?}", resp.answer),
        }
    }

    pub(crate) async fn read(&self, method: &str, params: Value) -> ReadResult {
        let resp = self.call(method, params).await;
        match resp.read_result() {
            Some(r) => r.clone(),
            None => panic!("`{method}` returned no result: {:?}", resp.answer),
        }
    }

    // ---- conveniences for the common flows

    /// `sandbox.create`: a `PROVISIONING` sandbox.
    pub(crate) async fn create(&self, name: Option<&str>) -> SandboxView {
        sandbox_of(&self.done("sandbox.create", create_params(name)).await)
    }

    /// `sandbox.create` then `sandbox.start`: a `READY` sandbox.
    pub(crate) async fn ready(&self, name: Option<&str>) -> SandboxView {
        let created = self.create(name).await;
        sandbox_of(&self.done("sandbox.start", target(&created)).await)
    }

    pub(crate) async fn exec(&self, sb: &SandboxView, argv: &[&str]) -> OperationView {
        self.op("exec.run", exec_params(sb, argv)).await
    }

    pub(crate) async fn inspect(&self, id: &SandboxId) -> SandboxView {
        match self.read("sandbox.inspect", json!({ "sandbox": id })).await {
            ReadResult::Sandbox(v) => v,
            other => panic!("{other:?}"),
        }
    }

    pub(crate) async fn get(&self, id: &OperationId) -> OperationView {
        match self.read("operation.get", json!({ "operation_id": id })).await {
            ReadResult::Operation(v) => *v,
            other => panic!("{other:?}"),
        }
    }

    pub(crate) async fn info(&self) -> HostInfo {
        match self.read("host.info", Value::Null).await {
            ReadResult::HostInfo(i) => *i,
            other => panic!("{other:?}"),
        }
    }

    pub(crate) async fn sandboxes(&self, params: Value) -> Page<SandboxView> {
        match self.read("sandbox.list", params).await {
            ReadResult::Sandboxes(p) => p,
            other => panic!("{other:?}"),
        }
    }

    pub(crate) async fn snapshots(&self, params: Value) -> Page<SnapshotView> {
        match self.read("snapshot.list", params).await {
            ReadResult::Snapshots(p) => p,
            other => panic!("{other:?}"),
        }
    }

    pub(crate) async fn operations(&self, params: Value) -> Page<OperationView> {
        match self.read("operation.list", params).await {
            ReadResult::Operations(p) => p,
            other => panic!("{other:?}"),
        }
    }

    pub(crate) async fn metrics(&self) -> Value {
        match self.read("host.metrics", Value::Null).await {
            ReadResult::Metrics(m) => m,
            other => panic!("{other:?}"),
        }
    }
}

pub(crate) fn create_params(name: Option<&str>) -> Value {
    let mut p = json!({"image": "python", "resources": {"vcpus": 2, "memory_mib": 256, "disk_mib": 128, "network": {"mode": "none"}}});
    if let Some(n) = name {
        p["name"] = json!(n);
    }
    p
}

/// The target token of a lifecycle-changing method for the sandbox as `sb` shows it.
pub(crate) fn target(sb: &SandboxView) -> Value {
    json!({"sandbox_id": sb.sandbox_id, "expected_generation": sb.generation})
}

pub(crate) fn exec_params(sb: &SandboxView, argv: &[&str]) -> Value {
    json!({"sandbox_id": sb.sandbox_id, "expected_generation": sb.generation, "command": {"argv": argv}})
}

pub(crate) fn sandbox_of(op: &OperationView) -> SandboxView {
    match &op.result {
        Some(OperationResult::Sandbox(v)) => v.clone(),
        other => panic!("expected a sandbox result on {} ({:?}), got {other:?}", op.operation_type, op.state),
    }
}

pub(crate) fn snapshot_of(op: &OperationView) -> SnapshotView {
    match &op.result {
        Some(OperationResult::Snapshot(v)) => v.clone(),
        other => panic!("expected a snapshot result on {} ({:?}), got {other:?}", op.operation_type, op.state),
    }
}

pub(crate) fn run_of(op: &OperationView) -> RunResult {
    match &op.result {
        Some(OperationResult::Run(r)) => (**r).clone(),
        other => panic!("expected a run result on {} ({:?}), got {other:?}", op.operation_type, op.state),
    }
}

/// Poll `cond` (real time) until it holds. Panics after two seconds: a test never hangs.
pub(crate) async fn eventually(what: &str, mut cond: impl FnMut() -> bool) {
    for _ in 0..400 {
        if cond() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    panic!("timed out waiting for: {what}");
}

/// Minimal valid `params` for `method` (`Value::Null`: the method takes none). The ids name nothing.
pub(crate) fn valid_params(method: Method) -> Value {
    const SBX: &str = "sbx-00000000000000000000000000000000";
    const SNP: &str = "snp-00000000000000000000000000000000";
    const RUN: &str = "run-00000000000000000000000000000000";
    let snapshot = json!({"snapshot_id": SNP, "snapshot_generation": 1});
    match method {
        Method::SandboxCreate => create_params(None),
        Method::SandboxStart | Method::SandboxStop | Method::SandboxDestroy => json!({"sandbox_id": SBX, "expected_generation": 1}),
        Method::ExecRun => json!({"sandbox_id": SBX, "expected_generation": 1, "command": {"argv": ["/bin/true"]}}),
        Method::SnapshotCreate => json!({"sandbox_id": SBX, "expected_generation": 1}),
        Method::SnapshotRestore => json!({"snapshot": snapshot, "target": {"kind": "new"}}),
        Method::SnapshotDelete => json!({"snapshot": snapshot}),
        Method::OperationCancel | Method::OperationGet => json!({"operation_id": "op-00000000"}),
        Method::SandboxInspect => json!({"sandbox": SBX}),
        Method::SandboxList | Method::SnapshotList | Method::OperationList => json!({}),
        Method::RunInspect => json!({"run_id": RUN}),
        Method::RunOutput => json!({"run_id": RUN, "stream": "stdout"}),
        Method::HostInfo | Method::HostMetrics | Method::ProfileReload => Value::Null,
        Method::QuarantineRelease => json!({"sandbox_id": SBX, "generation": 1, "mode": "DECLARE_ABSENT"}),
        Method::HostSetMode => json!({"mode": "DRAINING"}),
        Method::HostAcknowledge => json!({"condition": "store_regression"}),
    }
}

/// What a refusal must leave behind: nothing. Operations, leases and stored snapshots, counted.
pub(crate) fn footprint(host: &Host) -> (usize, usize, usize) {
    host.journal
        .read(|s| (s.operations.len(), s.live_generations().count(), s.snapshots.values().filter(|x| x.holds_storage()).count()))
        .unwrap()
}

/// How many times the backend was asked to do `method` since the world was created or cleared.
pub(crate) fn calls(world: &FakeWorld, method: &str) -> usize {
    world.calls().iter().filter(|c| c.as_str() == method).count()
}
