//! BND-03/BND-04 — the coordinator. One [`Host`] owns the journal, the backend and the stores and
//! exposes one method per semantic operation.
//!
//! **Operation protocol** (every mutating method follows it; spec §12, §14):
//!
//! ```text
//! validate + policy  (no record, no side effect)
//!   └─ begin  ── one atomic journal append: idempotency + precondition + admission + ACCEPTED
//!        └─ step("x")   write-ahead intent for a privileged step
//!             └─ backend call
//!                  └─ finish  ── one atomic append: terminal status + lifecycle commit
//! ```
//!
//! Failure handling is *observation-based*: an error after a possible side effect never becomes a
//! plain `FAILED`. Compensation (teardown) is attempted, and the terminal status reflects what was
//! **observed** afterwards — `FAILED` only when the world is provably clean, else `UNKNOWN`.

pub mod capacity;
mod exec;
mod ops;
mod query;
mod sandbox;
mod snapshots;

pub(crate) use sandbox::Retired;

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
};

use tokio::sync::OwnedMutexGuard;
use tokio_util::sync::CancellationToken;

use crate::{
    admission::EffectivePolicy,
    backend::SandboxBackend,
    clock::Clock,
    config::HostConfig,
    domain::CallerIdentity,
    error::{AcfError, Result},
    filesystem::{ArtifactStore, Layout},
    ids::OperationId,
    operation::{HostLock, Journal},
    snapshot::{HostFingerprint, SnapshotStore},
    telemetry::Telemetry,
};

#[cfg(any(test, feature = "testing"))]
use crate::testing::fault::FaultInjector;

/// Crash-point hook. Expands to nothing in release builds, so no fault point can be triggered
/// in production (spec §27.6).
macro_rules! fault {
    ($host:expr, $point:ident, $step:expr) => {{
        #[cfg(any(test, feature = "testing"))]
        {
            $host
                .faults
                .hit($crate::testing::fault::FaultPoint::$point, $step)
                .map_err(|c| $crate::error::AcfError::simulated_crash(&format!("{:?}", c.0)))?;
        }
    }};
}
pub(crate) use fault;

/// Per-request context: *who* asked, under *which policy*, with *which operation id*.
#[derive(Debug, Clone)]
pub struct Ctx {
    pub caller: CallerIdentity,
    pub policy: Arc<EffectivePolicy>,
    pub operation_id: OperationId,
    pub retry: bool,
}

/// Named in-memory locks: fail fast with `STATE_CONFLICT` instead of queueing (spec §11, §12).
#[derive(Debug, Default)]
pub(crate) struct Locks(Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>);

impl Locks {
    pub(crate) fn try_acquire(&self, key: &str) -> Result<OwnedMutexGuard<()>> {
        let m = {
            let mut g = self.0.lock().map_err(|_| AcfError::internal("lock table poisoned"))?;
            Arc::clone(g.entry(key.to_owned()).or_default())
        };
        m.try_lock_owned().map_err(|_| AcfError::conflict(format!("{key} is busy with another operation")))
    }

    pub(crate) fn prune(&self, key: &str) {
        if let Ok(mut g) = self.0.lock()
            && g.get(key).is_some_and(|m| Arc::strong_count(m) == 1)
        {
            g.remove(key);
        }
    }
}

impl std::fmt::Debug for HostParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostParts").field("instance_id", &self.instance_id).finish_non_exhaustive()
    }
}

pub struct HostParts {
    pub cfg: Arc<HostConfig>,
    pub clock: Arc<dyn Clock>,
    pub journal: Arc<Journal>,
    pub layout: Arc<Layout>,
    pub backend: Arc<dyn SandboxBackend>,
    pub policy: EffectivePolicy,
    pub telemetry: Telemetry,
    pub instance_id: String,
    pub journal_integrity: String,
    /// Held for the life of the host (single-writer exclusion). `None` only in unit tests.
    pub lock: Option<HostLock>,
}

pub struct Host {
    pub cfg: Arc<HostConfig>,
    pub clock: Arc<dyn Clock>,
    pub journal: Arc<Journal>,
    pub layout: Arc<Layout>,
    pub backend: Arc<dyn SandboxBackend>,
    pub telemetry: Telemetry,
    pub artifacts: ArtifactStore,
    pub snapshots: SnapshotStore,
    pub instance_id: String,
    pub journal_integrity: String,
    pub host_fp: HostFingerprint,
    policy: RwLock<Arc<EffectivePolicy>>,
    locks: Locks,
    runs: Mutex<HashMap<OperationId, CancellationToken>>,
    #[cfg(any(test, feature = "testing"))]
    pub faults: FaultInjector,
    _lock: Option<HostLock>,
}

impl std::fmt::Debug for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Host").field("instance_id", &self.instance_id).finish_non_exhaustive()
    }
}

impl Host {
    pub fn new(p: HostParts) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            artifacts: p.layout.artifact_store()?,
            snapshots: p.layout.snapshot_store()?,
            cfg: p.cfg,
            clock: p.clock,
            journal: p.journal,
            layout: p.layout,
            backend: p.backend,
            telemetry: p.telemetry,
            instance_id: p.instance_id,
            journal_integrity: p.journal_integrity,
            host_fp: HostFingerprint::capture(),
            policy: RwLock::new(Arc::new(p.policy)),
            locks: Locks::default(),
            runs: Mutex::default(),
            #[cfg(any(test, feature = "testing"))]
            faults: FaultInjector::default(),
            _lock: p.lock,
        }))
    }

    pub fn policy(&self) -> Arc<EffectivePolicy> {
        self.policy.read().map(|p| Arc::clone(&p)).unwrap_or_else(|e| Arc::clone(&e.into_inner()))
    }

    /// Install a freshly verified policy. In-flight operations keep the `Arc` they captured.
    pub fn set_policy(&self, p: EffectivePolicy) {
        let mut g = self.policy.write().unwrap_or_else(|e| e.into_inner());
        *g = Arc::new(p);
    }

    pub fn ctx(&self, caller: CallerIdentity, operation_id: Option<OperationId>, retry: bool) -> Ctx {
        Ctx { caller, policy: self.policy(), operation_id: operation_id.unwrap_or_else(OperationId::generate), retry }
    }

    pub(crate) fn wall(&self) -> String {
        self.clock.wall_rfc3339()
    }
}
