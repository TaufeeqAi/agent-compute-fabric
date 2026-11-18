//! The coordinator (contract §11, §15; boundaries B05 and B06). One [`Host`] is the **only writer**
//! of the store and the **only caller** of the backend.
//!
//! **Operation protocol** (every non-read method follows it; §11.1):
//!
//! ```text
//! refuse?   role · tags · safety profile · state · token · capacity · host mode   (no record, no effect)
//!   └─ BEGIN   one atomic commit: idempotency + exclusivity + admission + the reserved state + ACCEPTED
//!        └─ STEP    the name of a privileged step, durable before the step runs
//!             └─ BACKEND   the step: success, or a classified failure with a side-effect marker
//!                  └─ FINISH   one atomic commit: terminal state + lifecycle + lease changes
//! ```
//!
//! Three properties hold by construction rather than by care:
//!
//! * **Exclusivity is derived from committed state** (J-3). "Is this sandbox busy?" is answered by
//!   the non-terminal operations in the store, inside the BEGIN commit — not by an in-memory lock
//!   that a restart would forget.
//! * **Every write of an operation is fenced** (CC-2): STEP, FINISH and every intermediate commit
//!   first check, inside the commit, that the operation is still non-terminal. A containment
//!   operation supersedes a granting one by committing its terminal record (CC-3); from then on
//!   the superseded task can write nothing, and it is told to stop.
//! * **Failure handling is observation-based** (FS-3): an error after a possible side effect is
//!   followed by an attempt to undo, and the terminal record states what was *observed* afterwards.

mod exec;
pub mod link;
mod operator;
mod ops;
pub mod pipeline;
mod query;
pub mod recover;
mod sandbox;
mod snapshots;
pub mod sweep;

pub use pipeline::PeerContext;
pub(crate) use sandbox::Retired;

use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, Mutex, RwLock},
};

use tokio::sync::watch;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{
    authority::{Enrolment, SafetyProfile},
    backend::SandboxBackend,
    clock::Clock,
    config::HostConfig,
    domain::{AuthorityContext, ContainmentReason, HostMode, Issuer, PeerId, RequestFingerprint, Role, Tags},
    error::{AcfError, Result},
    ids::OperationId,
    resources::lifetime::LifetimeGuard,
    secrets::SecretProvider,
    storage::{
        ArtifactStore, Layout,
        snapshots::{HostFingerprint, SnapshotStore},
    },
    store::{HostLock, Journal, OpKey},
    telemetry::Telemetry,
};

#[cfg(any(test, feature = "testing"))]
use crate::testing::fault::FaultInjector;

/// Crash-point hook. Expands to nothing in release builds, so no fault point can be triggered in
/// production (TI-3).
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

/// Per-request context: *who* asked, in which scope, under *which profile*, with *which operation id*.
#[derive(Debug, Clone)]
pub struct Ctx {
    pub authority: AuthorityContext,
    pub issuer: Issuer,
    /// The safety profile in force at admission. The operation is governed by it until it ends (SP-2).
    pub profile: Arc<SafetyProfile>,
    pub operation_id: OperationId,
    pub retry: bool,
    pub issued_at: String,
    /// Digest of the canonical `method` + `params` (OP-11).
    pub fingerprint: RequestFingerprint,
    /// Told the operation's key the moment BEGIN is durable, so a waiting response can stop waiting
    /// for the *outcome* without ever answering before the *record* exists (API-7).
    pub(crate) begun: Option<Arc<watch::Sender<Option<OpKey>>>>,
}

impl Ctx {
    pub fn tags(&self) -> Tags {
        self.authority.tags()
    }

    pub fn key(&self) -> OpKey {
        OpKey::new(&self.tags(), &self.operation_id)
    }

    /// AU-9: a record outside the caller's tags is reported as absent.
    pub(crate) fn require_access(&self, tags: &Tags, what: &str) -> Result<()> {
        if self.authority.may_access(tags) { Ok(()) } else { Err(AcfError::not_found(format!("{what} does not exist"))) }
    }
}

/// A running operation of this activation: how to tell it to stop, and how to know it has.
#[derive(Debug, Clone)]
pub(crate) struct RunningTask {
    cancel: CancellationToken,
    done: watch::Receiver<bool>,
}

#[derive(Debug, Default)]
pub(crate) struct TaskTable(Mutex<HashMap<OpKey, RunningTask>>);

/// Held by an operation's task for as long as it runs. Dropping it (normal return, early return or
/// cancellation of the task) removes the entry and tells whoever waits that the task has let go.
#[derive(Debug)]
pub(crate) struct TaskGuard {
    table: Arc<TaskTable>,
    key: OpKey,
    pub(crate) cancel: CancellationToken,
    done: watch::Sender<bool>,
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        if let Ok(mut t) = self.table.0.lock() {
            t.remove(&self.key);
        }
        let _ = self.done.send(true);
    }
}

impl TaskTable {
    pub(crate) fn register(self: &Arc<Self>, key: OpKey) -> TaskGuard {
        let (tx, rx) = watch::channel(false);
        let cancel = CancellationToken::new();
        if let Ok(mut t) = self.0.lock() {
            t.insert(key.clone(), RunningTask { cancel: cancel.clone(), done: rx });
        }
        TaskGuard { table: Arc::clone(self), key, cancel, done: tx }
    }

    /// Tell the task of `key` to stop. Returns a receiver that turns `true` when it has let go.
    pub(crate) fn cancel(&self, key: &OpKey) -> Option<watch::Receiver<bool>> {
        let t = self.0.lock().ok()?.get(key).cloned()?;
        t.cancel.cancel();
        Some(t.done)
    }

    pub(crate) fn is_running(&self, key: &OpKey) -> bool {
        self.0.lock().map(|t| t.contains_key(key)).unwrap_or(false)
    }

    pub(crate) fn len(&self) -> usize {
        self.0.lock().map(|t| t.len()).unwrap_or(0)
    }
}

#[derive(Debug)]
struct ModeState {
    starting: bool,
    draining: bool,
    reasons: BTreeSet<ContainmentReason>,
}

/// `operation_rate_limit` (PS-10): a token bucket per peer, separately for operations and reads.
/// Containment is never subject to it (CC-4).
#[derive(Debug)]
pub(crate) struct RateLimiter {
    buckets: Mutex<HashMap<(PeerId, bool), (f64, u64)>>,
}

impl RateLimiter {
    fn new() -> Self {
        Self { buckets: Mutex::default() }
    }

    /// Take one token for `peer`. `per_minute` is both the burst and the sustained rate.
    pub(crate) fn allow(&self, peer: &PeerId, read: bool, per_minute: u32, now_ns: u64) -> bool {
        let Ok(mut b) = self.buckets.lock() else { return false };
        let cap = f64::from(per_minute.max(1));
        let (tokens, last) = b.entry((peer.clone(), read)).or_insert((cap, now_ns));
        let elapsed_s = now_ns.saturating_sub(*last) as f64 / 1e9;
        *tokens = (*tokens + elapsed_s * cap / 60.0).min(cap);
        *last = now_ns;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
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
    pub profile: SafetyProfile,
    pub enrolment: Enrolment,
    pub secrets: Arc<dyn SecretProvider>,
    pub lifetime: Arc<dyn LifetimeGuard>,
    pub telemetry: Telemetry,
    pub instance_id: String,
    pub store_integrity: String,
    /// The store's last commit sequence when it was opened, before this activation wrote anything.
    /// An ownership marker newer than this means the store is older than the system (LN-2).
    pub store_seq_at_open: u64,
    /// Held for the life of the host (single-writer exclusion, PS-5). `None` only in unit tests.
    pub lock: Option<HostLock>,
}

pub struct Host {
    pub cfg: Arc<HostConfig>,
    pub clock: Arc<dyn Clock>,
    pub journal: Arc<Journal>,
    pub layout: Arc<Layout>,
    pub backend: Arc<dyn SandboxBackend>,
    pub secrets: Arc<dyn SecretProvider>,
    pub lifetime: Arc<dyn LifetimeGuard>,
    pub telemetry: Telemetry,
    pub artifacts: ArtifactStore,
    pub snapshots: SnapshotStore,
    pub instance_id: String,
    pub store_integrity: String,
    pub store_seq_at_open: u64,
    pub host_fp: HostFingerprint,
    profile: RwLock<Arc<SafetyProfile>>,
    enrolment: RwLock<Arc<Enrolment>>,
    mode: Mutex<ModeState>,
    pub(crate) tasks: Arc<TaskTable>,
    /// Every operation task, so a drain can wait for them (HM-3).
    pub(crate) tracker: TaskTracker,
    pub(crate) rate: RateLimiter,
    /// `retry_budget`: host-wide concurrent step retries (RY-6).
    pub(crate) retry_budget: tokio::sync::Semaphore,
    /// Cancellation of the executions running in this activation, for `operation.cancel`.
    pub(crate) runs: Mutex<HashMap<OpKey, CancellationToken>>,
    /// Cancelled when the store demands a fail-stop (FS-9): the process must end and be restarted.
    pub fatal: CancellationToken,
    pub(crate) sweep: Mutex<sweep::SweepState>,
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
    /// Build the coordinator. It starts in `STARTING`: no endpoint may be opened until
    /// [`Host::recover`] has run and [`Host::finish_starting`] was called (RC-5).
    pub fn new(p: HostParts) -> Result<Arc<Self>> {
        let retry_budget = tokio::sync::Semaphore::new(p.cfg.operations.retry_budget.max(1) as usize);
        Ok(Arc::new(Self {
            artifacts: p.layout.artifact_store()?,
            snapshots: p.layout.snapshot_store()?,
            cfg: p.cfg,
            clock: p.clock,
            journal: p.journal,
            layout: p.layout,
            backend: p.backend,
            secrets: p.secrets,
            lifetime: p.lifetime,
            telemetry: p.telemetry,
            instance_id: p.instance_id,
            store_integrity: p.store_integrity,
            store_seq_at_open: p.store_seq_at_open,
            host_fp: HostFingerprint::capture(),
            retry_budget,
            runs: Mutex::default(),
            profile: RwLock::new(Arc::new(p.profile)),
            enrolment: RwLock::new(Arc::new(p.enrolment)),
            mode: Mutex::new(ModeState { starting: true, draining: false, reasons: BTreeSet::new() }),
            tasks: Arc::new(TaskTable::default()),
            tracker: TaskTracker::new(),
            rate: RateLimiter::new(),
            fatal: CancellationToken::new(),
            sweep: Mutex::new(sweep::SweepState::default()),
            #[cfg(any(test, feature = "testing"))]
            faults: FaultInjector::default(),
            _lock: p.lock,
        }))
    }

    // ------------------------------------------------------------------ profile and enrolment

    pub fn profile(&self) -> Arc<SafetyProfile> {
        self.profile.read().map(|p| Arc::clone(&p)).unwrap_or_else(|e| Arc::clone(&e.into_inner()))
    }

    /// Install a freshly verified profile. Operations in flight keep the `Arc` they captured (SP-2).
    pub fn set_profile(&self, p: SafetyProfile) {
        let mut g = self.profile.write().unwrap_or_else(|e| e.into_inner());
        *g = Arc::new(p);
    }

    pub fn enrolment(&self) -> Arc<Enrolment> {
        self.enrolment.read().map(|p| Arc::clone(&p)).unwrap_or_else(|e| Arc::clone(&e.into_inner()))
    }

    pub fn set_enrolment(&self, e: Enrolment) {
        let mut g = self.enrolment.write().unwrap_or_else(|e| e.into_inner());
        *g = Arc::new(e);
    }

    // ------------------------------------------------------------------ host mode (§12.6)

    pub fn mode(&self) -> HostMode {
        if self.journal.write_block().is_some() {
            return HostMode::ReadOnly;
        }
        let m = self.mode.lock().unwrap_or_else(|e| e.into_inner());
        if m.starting {
            HostMode::Starting
        } else if !m.reasons.is_empty() {
            HostMode::Containment
        } else if m.draining {
            HostMode::Draining
        } else {
            HostMode::Serving
        }
    }

    pub fn containment_reasons(&self) -> Vec<ContainmentReason> {
        self.mode.lock().unwrap_or_else(|e| e.into_inner()).reasons.iter().cloned().collect()
    }

    /// Enter (or stay in) `CONTAINMENT` for `reason`. The host stops creating privilege; it does
    /// not stop (HM-2).
    pub fn contain(&self, reason: ContainmentReason) {
        let fresh = self.mode.lock().unwrap_or_else(|e| e.into_inner()).reasons.insert(reason.clone());
        if fresh {
            tracing::error!(?reason, "host is in CONTAINMENT: no new privilege will be created");
            self.telemetry.metrics.incr("containment_entered", 1);
            self.telemetry.events.emit_simple(&self.wall(), "host.containment", serde_json::json!({ "reason": reason }));
        }
    }

    /// Remove every reason for which `drop` returns true. Returns how many were removed.
    pub fn clear_containment(&self, drop: impl Fn(&ContainmentReason) -> bool) -> usize {
        let mut m = self.mode.lock().unwrap_or_else(|e| e.into_inner());
        let before = m.reasons.len();
        m.reasons.retain(|r| !drop(r));
        before - m.reasons.len()
    }

    pub fn set_draining(&self, draining: bool) {
        self.mode.lock().unwrap_or_else(|e| e.into_inner()).draining = draining;
    }

    pub fn is_draining(&self) -> bool {
        self.mode.lock().unwrap_or_else(|e| e.into_inner()).draining
    }

    /// Startup recovery is over: the host leaves `STARTING` and endpoints may open (RC-5).
    pub fn finish_starting(&self) {
        self.mode.lock().unwrap_or_else(|e| e.into_inner()).starting = false;
    }

    // ------------------------------------------------------------------ contexts

    /// The context of an operation the host issues itself (OP-24): recorded under the tags of the
    /// sandbox it acts on, so the sandbox's owner can see what the host did and why.
    pub(crate) fn host_ctx(&self, tags: &Tags, fingerprint: RequestFingerprint) -> Ctx {
        Ctx {
            authority: AuthorityContext {
                peer_id: tags.peer_id.clone(),
                role: Role::Operator,
                owner_scope: tags.owner_scope.clone(),
                on_behalf_of: None,
            },
            issuer: Issuer::Host,
            profile: self.profile(),
            operation_id: OperationId::generate(),
            retry: false,
            issued_at: self.wall(),
            fingerprint,
            begun: None,
        }
    }

    pub(crate) fn wall(&self) -> String {
        self.clock.wall_rfc3339()
    }

    /// After any failed commit: if the store demands a fail-stop, tell the process to end (FS-9).
    pub(crate) fn check_store(&self) {
        if let Some(block) = self.journal.write_block()
            && block.is_fail_stop()
            && !self.fatal.is_cancelled()
        {
            tracing::error!(why = %block.message(), "the store demands a fail-stop: this activation must end");
            self.fatal.cancel();
        }
    }

    /// How long the backend lets a runtime end by itself before it ends it by force (declared by
    /// the backend: the coordinator knows nothing about how a runtime is stopped).
    pub(crate) fn stop_grace(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.backend.capabilities().stop_grace_ms)
    }

    /// Operations of this activation that have not ended.
    pub fn operations_in_flight(&self) -> usize {
        self.tasks.len()
    }
}

/// Tags for records that belong to the host itself.
#[cfg(test)]
pub(crate) fn host_tags() -> Result<Tags> {
    Ok(Tags { peer_id: PeerId::host(), owner_scope: crate::domain::OwnerScope::parse("host")? })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rate_limiter_allows_a_burst_then_the_sustained_rate_and_keeps_peers_apart() {
        let r = RateLimiter::new();
        let (a, b) = (PeerId::parse("a").unwrap(), PeerId::parse("b").unwrap());
        let allowed = (0..100).filter(|_| r.allow(&a, false, 60, 0)).count();
        assert_eq!(allowed, 60, "the burst is exactly the per-minute budget");
        assert!(!r.allow(&a, false, 60, 0));
        assert!(r.allow(&b, false, 60, 0), "one peer exhausting its budget does not starve another");
        assert!(r.allow(&a, true, 60, 0), "reads and operations have separate budgets");
        assert!(r.allow(&a, false, 60, 1_000_000_000), "one token returns each second at 60 per minute");
        assert!(!r.allow(&a, false, 60, 1_000_000_000));
        let refill = (0..200).filter(|_| r.allow(&a, false, 60, 3_600_000_000_000)).count();
        assert_eq!(refill, 60, "the bucket never holds more than its capacity");
    }

    #[test]
    fn a_task_guard_reports_completion_when_dropped_and_cancel_reaches_the_task() {
        let table = Arc::new(TaskTable::default());
        let key = OpKey::new(&host_tags().unwrap(), &OperationId::parse("op-12345678").unwrap());
        let guard = table.register(key.clone());
        assert!(table.is_running(&key));
        let done = table.cancel(&key).unwrap();
        assert!(guard.cancel.is_cancelled());
        assert!(!*done.borrow());
        drop(guard);
        assert!(*done.borrow(), "the waiter learns the task has let go");
        assert!(!table.is_running(&key) && table.cancel(&key).is_none());
    }
}
