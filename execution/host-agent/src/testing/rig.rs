//! Test rig: build a [`Host`] over an on-disk journal and a shared fake world, and *rebuild it* to
//! model a host-agent crash + restart (new process memory, same disk, same still-running VMMs).

use std::sync::Arc;

use super::fake_backend::{FakeBackend, FakeWorld};
use crate::{
    admission::{EffectivePolicy, policy::test_support},
    clock::{Clock, ManualClock},
    config::{HostConfig, test_support::config},
    domain::{CallerIdentity, NetworkMode, SandboxResources},
    filesystem::{Layout, images::test_support as img},
    ids::OperationId,
    lifecycle::{Ctx, Host, HostParts},
    operation::{Journal, OperationRecord},
    protocol::{ResponseBody, SandboxCreateParams, SandboxView, SnapshotView},
    telemetry::Telemetry,
};

pub(crate) struct Rig {
    pub dir: tempfile::TempDir,
    pub cfg: Arc<HostConfig>,
    pub layout: Arc<Layout>,
    pub world: Arc<FakeWorld>,
    pub clock: Arc<ManualClock>,
}

impl Rig {
    pub(crate) fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Arc::new(config(dir.path()));
        let layout = Arc::new(Layout::open(&cfg.paths.state_root).unwrap());
        img::install(&cfg.paths.state_root.join("images"), "python", b"kernel", b"rootfs");
        Self { dir, cfg, layout, world: FakeWorld::new(), clock: Arc::new(ManualClock::new()) }
    }

    pub(crate) fn policy(&self) -> EffectivePolicy {
        test_support::policy()
    }

    /// A fresh coordinator: journal re-read from disk, backend over the shared world.
    pub(crate) fn host(&self) -> Arc<Host> {
        let (journal, report) = Journal::open(&self.cfg.journal_path()).unwrap();
        let clock: Arc<dyn Clock> = self.clock.clone();
        let backend = Arc::new(FakeBackend::new(Arc::clone(&self.world), Arc::clone(&self.layout), Arc::clone(&clock)));
        Host::new(HostParts {
            cfg: Arc::clone(&self.cfg),
            clock,
            journal: Arc::new(journal),
            layout: Arc::clone(&self.layout),
            backend,
            policy: self.policy(),
            telemetry: Telemetry::memory(),
            instance_id: "test-instance".into(),
            journal_integrity: format!("{:?}", report.integrity),
            lock: None,
        })
        .unwrap()
    }
}

pub(crate) fn caller() -> CallerIdentity {
    CallerIdentity { uid: 0, gid: 0, pid: Some(1) }
}

pub(crate) fn ctx(h: &Host) -> Ctx {
    h.ctx(caller(), None, false)
}

pub(crate) fn ctx_with(h: &Host, op: &str, retry: bool) -> Ctx {
    h.ctx(caller(), Some(OperationId::parse(op).unwrap()), retry)
}

pub(crate) fn res() -> SandboxResources {
    SandboxResources { vcpus: 2, memory_mib: 256, disk_mib: 128, network: NetworkMode::None }
}

pub(crate) fn create_params(name: Option<&str>) -> SandboxCreateParams {
    SandboxCreateParams { name: name.map(str::to_owned), image: "python".into(), resources: res() }
}

pub(crate) fn sandbox_of(rec: &OperationRecord) -> SandboxView {
    match serde_json::from_value::<ResponseBody>(rec.result.clone().expect("operation has no result")).unwrap() {
        ResponseBody::Sandbox(v) => v,
        other => panic!("expected a sandbox result, got {other:?}"),
    }
}

pub(crate) fn snapshot_of(rec: &OperationRecord) -> SnapshotView {
    match serde_json::from_value::<ResponseBody>(rec.result.clone().expect("operation has no result")).unwrap() {
        ResponseBody::Snapshot(v) => v,
        other => panic!("expected a snapshot result, got {other:?}"),
    }
}

/// create + start; returns the READY sandbox.
pub(crate) async fn ready(h: &Host, name: Option<&str>) -> SandboxView {
    let c = h.sandbox_create(&ctx(h), create_params(name)).await.unwrap();
    let v = sandbox_of(&c);
    let s = h
        .sandbox_start(&ctx(h), crate::protocol::SandboxTarget { sandbox_id: v.sandbox_id.clone(), expected_generation: v.generation })
        .await
        .unwrap();
    assert_eq!(s.status, crate::domain::OperationStatus::Succeeded, "{:?}", s.failure);
    sandbox_of(&s)
}
