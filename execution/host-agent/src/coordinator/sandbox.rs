//! Sandbox lifecycle flows: create → start → (exec) → stop → destroy (contract §12.2), and the
//! host's own containment operation `sandbox.fail` (OP-24).

use std::{collections::BTreeSet, future::Future, time::Duration};

use serde_json::json;
use tokio_util::sync::CancellationToken;

use super::{
    Ctx, Host, fault,
    ops::{BeginSpec, Begun, Outcome, admit_containment, admit_granting, supersede_entries},
};
use crate::{
    api::{SandboxCreateParams, SandboxTarget},
    backend::{EnforcementObservation, LaunchSink, Launched, ProvisionRequest, StopOutcome, TeardownOutcome, VmmState},
    domain::{FailureInfo, Issuer, LifecycleState, OperationType, Residue, Role, SnapshotState},
    error::{AcfError, FailureClass, Result, SideEffect},
    ids::{Generation, SandboxId, validate_alias},
    resources::{
        admission::{Pool, reserve_sandbox},
        lifetime::{ExpiryTicket, TICKET_SCHEMA_VERSION, new_expiry},
    },
    storage::{
        GenerationDir, ResolvedImage,
        generation::{OWNER_MARKER_SCHEMA_VERSION, OwnerMarker, new_nonce},
    },
    store::{Entry, GenerationRecord, JournalState, OpKey, OperationRecord, QuarantineRecord, SandboxRecord},
    telemetry::EventDraft,
};

/// What cleanup of a generation observed.
#[derive(Debug)]
pub(crate) enum Retired {
    /// Stopped and removed, with ownership proven.
    Clean,
    /// Ownership could not be proven. Everything was left in place.
    Quarantined(String),
    Unclean(AcfError),
}

/// Records the runtime's identity and arms lifetime enforcement the moment the backend has launched
/// it, before it is configured (RC-1, PD-4). Fenced like every other write of the operation.
pub(crate) struct IdentitySink<'a> {
    pub(crate) host: &'a Host,
    pub(crate) op: OpKey,
    pub(crate) sandbox: SandboxId,
    pub(crate) generation: Generation,
}

#[async_trait::async_trait]
impl LaunchSink for IdentitySink<'_> {
    async fn launched(&self, launched: &Launched) -> Result<()> {
        let key = (self.sandbox.clone(), self.generation);
        let wall = self.host.wall();
        let expiry = self.host.journal.commit_with(|state| {
            if state.operations.get(&self.op).is_none_or(OperationRecord::is_terminal) {
                return Err(AcfError::superseded());
            }
            let mut g = state.generations.get(&key).cloned().ok_or_else(|| AcfError::internal("generation record missing at launch"))?;
            let expiry = state
                .sandboxes
                .get(&self.sandbox)
                .map(|s| s.expiry.clone())
                .ok_or_else(|| AcfError::internal("sandbox record missing at launch"))?;
            g.process = Some(launched.process.clone());
            g.updated_wall = wall.clone();
            Ok((vec![Entry::Generation(Box::new(g))], expiry))
        })?;
        // A runtime that exists must already be on the enforcer's list. In another boot the expiry
        // has not been re-anchored yet; such a runtime gets no time at all.
        let boot_id = self.host.clock.boot_id();
        let expires_mono_ns = if expiry.boot_id == boot_id { expiry.mono_ns } else { 0 };
        self.host.lifetime.arm(&ExpiryTicket {
            schema_version: TICKET_SCHEMA_VERSION,
            jail_id: crate::ids::SandboxRef { sandbox_id: self.sandbox.clone(), generation: self.generation }.jail_id(),
            process: launched.process.clone(),
            kill_switch: launched.kill_switch.clone(),
            boot_id,
            expires_mono_ns: expires_mono_ns.saturating_add(self.host.cfg.lifetime.expiry_tolerance_ms.saturating_mul(1_000_000) / 2),
        })
    }
}

impl Host {
    /// Run a granting body under the operation's deadline (OP-15) and its supersession signal (CC-3).
    pub(crate) async fn bounded<T>(
        &self,
        remaining: Option<Duration>,
        cancel: &CancellationToken,
        body: impl Future<Output = Result<T>>,
    ) -> Result<T> {
        let Some(remaining) = remaining else {
            return Err(AcfError::timeout("the operation's deadline had already passed").with_possible_side_effect());
        };
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(AcfError::superseded()),
            r = tokio::time::timeout(remaining, body) => {
                r.unwrap_or_else(|_| Err(AcfError::timeout("the operation did not finish within its deadline").with_possible_side_effect()))
            }
        }
    }

    /// IS-3, RC-6: the sweep does not observe a sandbox while an operation holds it, so the operation
    /// observes for itself. This runs `step` and, every `posture_watch_period`, verifies again that
    /// the mandatory isolation controls of the generation's runtime are in force. If one is not,
    /// `step` is abandoned with `SECURITY_CONTROL_FAILURE` and the flow's failure path ends the
    /// runtime. Nothing is repaired in place.
    ///
    /// For a generation that has been `READY`: its posture was verified at launch (IS-1). A start in
    /// flight is not watched, because a runtime that is still being launched has not installed every
    /// control yet; its own verification, and its deadline, cover that window.
    pub(crate) async fn while_intact<T>(
        &self,
        sandbox_id: &SandboxId,
        generation: Generation,
        step: impl Future<Output = Result<T>>,
    ) -> Result<T> {
        let period = self.cfg.recovery.posture_watch_period();
        let limit = Duration::from_millis(self.cfg.recovery.observe_timeout_ms);
        tokio::pin!(step);
        loop {
            tokio::select! {
                r = &mut step => return r,
                () = tokio::time::sleep(period) => {}
            }
            let Ok(g) = self.gen_record(sandbox_id, generation) else { continue };
            if g.process.is_none() {
                continue;
            }
            // An observation that cannot be completed decides nothing here: the sweep counts those
            // once the operation has let go (RC-4).
            if let Ok(Ok(seen)) = tokio::time::timeout(limit, self.backend.observe(&g.backend_handle())).await
                && let EnforcementObservation::Degraded(why) = seen.enforcement
            {
                self.telemetry.metrics.incr("posture_failures_after_launch", 1);
                return Err(AcfError::security(format!("a mandatory isolation control is no longer in force: {}", why.join("; ")))
                    .with_possible_side_effect());
            }
        }
    }

    /// RY-2 / RY-4: retry a step whose failure was marked `NONE` and whose class is retryable,
    /// within the operation's deadline, `step_max_attempts` and the host-wide `retry_budget`, with
    /// jittered backoff. A step whose effect may have happened is never issued again (RY-3).
    pub(crate) async fn retry_step<T, F, Fut>(&self, op: &OperationRecord, step: &str, mut call: F) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let max = self.cfg.operations.step_max_attempts.max(1);
        let mut attempt = 1u32;
        loop {
            let e = match call().await {
                Ok(v) => return Ok(v),
                Err(e) => e,
            };
            let retryable = attempt < max && e.is_definite() && !e.class.never_retried() && !e.must_stop_silently();
            if !retryable {
                if attempt >= max && attempt > 1 {
                    self.telemetry.metrics.incr("step_retries_exhausted", 1);
                }
                return Err(e);
            }
            // RY-6: a dependency outage cannot turn into a storm. No budget, no retry.
            let Ok(_permit) = self.retry_budget.try_acquire() else {
                self.telemetry.metrics.incr("retry_budget_exhausted", 1);
                return Err(e);
            };
            let base = Duration::from_millis(100u64 << attempt.min(4));
            let jitter = Duration::from_millis(self.clock.monotonic_ns() % (base.as_millis() as u64 / 2 + 1));
            let backoff = base + jitter;
            if self.deadline_remaining(op).is_none_or(|r| r <= backoff) {
                return Err(e);
            }
            self.telemetry.metrics.incr("step_retries", 1);
            self.telemetry.events.emit(
                EventDraft::new(&self.wall(), "operation.step_retry").operation(op).attempt(attempt + 1).detail(json!({ "step": step })),
            );
            tokio::time::sleep(backoff).await;
            attempt += 1;
        }
    }

    /// Stop the runtime and release every host resource of `g`, with ownership proof (RC-2).
    pub(crate) async fn retire(&self, g: &GenerationRecord) -> Retired {
        let grace = self.stop_grace();
        match self.backend.stop(&g.backend_handle(), grace).await {
            Ok(StopOutcome::Stopped | StopOutcome::AlreadyGone | StopOutcome::Refused(_)) => {}
            Ok(StopOutcome::StillAlive) => {
                return Retired::Unclean(AcfError::unavailable("the runtime survived every attempt to end it").with_possible_side_effect());
            }
            Err(e) => return Retired::Unclean(e),
        }
        match self.backend.teardown(&g.sandbox_ref(), &g.owner_nonce).await {
            Ok(TeardownOutcome::Removed | TeardownOutcome::Absent) => {
                self.lifetime.disarm(&g.sandbox_ref().jail_id());
                Retired::Clean
            }
            Ok(TeardownOutcome::Quarantine(r)) => Retired::Quarantined(r),
            Err(e) => Retired::Unclean(e),
        }
    }

    /// `g` with the condition `QUARANTINED` (§12.1), and the report an operator reads.
    pub(crate) fn quarantine(&self, g: &GenerationRecord, reason: &str) -> Vec<Entry> {
        self.telemetry.metrics.incr("quarantines", 1);
        self.telemetry
            .events
            .emit(EventDraft::new(&self.wall(), "generation.quarantined").sandbox(g.sandbox_id.as_str(), Some(g.generation.0)));
        let mut q = g.clone();
        // The condition leaves the state alone (§12.1) — except that a generation is RUNNING or
        // PAUSED only while an operation holds it (J-1, J-2), and a quarantined generation has none
        // (J-6). One that is quarantined in either state is recorded FAILED: unusable, and a
        // runtime or residue may remain, which is exactly what FAILED means.
        if matches!(q.state, LifecycleState::Running | LifecycleState::Paused) {
            q.paused_from = None;
            q.state = LifecycleState::Failed;
        }
        q.quarantined = Some(reason.to_owned());
        q.quarantined_ms = Some(self.clock.wall_ms());
        q.updated_wall = self.wall();
        vec![
            Entry::Quarantine(QuarantineRecord {
                resource_id: g.sandbox_id.to_string(),
                generation: Some(g.generation),
                reason: reason.to_owned(),
                at_wall: self.wall(),
                unmanaged: false,
            }),
            Entry::Generation(Box::new(q)),
        ]
    }

    /// The sandbox record as a tombstone, when `g` is its current generation and is now destroyed.
    pub(crate) fn tombstone(&self, state_sb: Option<SandboxRecord>, g: &GenerationRecord) -> Option<Entry> {
        let mut sb = state_sb?;
        (sb.current == g.generation && g.state == LifecycleState::Destroyed).then(|| {
            sb.destroyed_ms = Some(self.clock.wall_ms());
            Entry::Sandbox(sb)
        })
    }

    /// After a containment BEGIN: tell every operation it superseded to stop, and wait (bounded by
    /// `preempt_grace`) for it to let go. Containment never waits for a guest (CC-3): the tasks drop
    /// their backend calls, they are not asked to finish them.
    pub(crate) async fn preempt(&self, superseded: &[OperationRecord]) {
        let grace = Duration::from_millis(self.cfg.operations.preempt_grace_ms);
        for op in superseded {
            self.telemetry.metrics.incr_labelled("operations_superseded", "type", op.operation_type.name(), 1);
            if let Some(mut done) = self.tasks.cancel(&op.key()) {
                let _ = tokio::time::timeout(grace, done.wait_for(|d| *d)).await;
            }
        }
    }

    /// BK-5: a request that needs a capability the backend does not declare is refused with
    /// `UNSUPPORTED` before BEGIN.
    pub(crate) fn require_network_capability(&self, res: &crate::domain::SandboxResources) -> Result<()> {
        if self.backend.capabilities().network_modes.contains(&res.network.mode()) {
            Ok(())
        } else {
            Err(AcfError::unsupported("this host's backend does not offer the requested network mode"))
        }
    }

    // ------------------------------------------------------------------ create

    pub async fn sandbox_create(&self, ctx: &Ctx, p: SandboxCreateParams) -> Result<OperationRecord> {
        if let Some(n) = &p.name {
            validate_alias(n)?;
        }
        let lifetime_ms = ctx.profile.authorize_create(&p.resources, &p.image, p.lifetime_secs)?;
        self.require_network_capability(&p.resources)?;
        let image = self.layout.image_store()?.resolve(&p.image)?;
        // RS-3: observe which identifiers a live resource carries, before the lease is decided.
        let busy = self.backend.busy_slots().await?;
        let (sandbox_id, nonce, free) = (SandboxId::generate(), new_nonce()?, self.layout.free_bytes()?);
        let spec = BeginSpec {
            op_type: OperationType::SandboxCreate,
            target: sandbox_id.to_string(),
            expected_generation: None,
            deadline_ms: self.cfg.operations.deadlines.create_ms,
            run_id: None,
            sandbox: Some((sandbox_id.clone(), Generation::FIRST)),
            snapshot: None,
        };
        let begun = self.begin(ctx, spec, |state| {
            let (sb, g) = self.new_sandbox_records(
                state,
                ctx,
                &sandbox_id,
                p.name.as_deref(),
                &p.resources,
                &image.image_ref,
                &busy,
                free,
                &nonce,
                lifetime_ms,
            )?;
            let mut g = g;
            g.expected_agent_version = Some(image.manifest.guest_agent_version.clone());
            Ok(vec![Entry::Sandbox(sb), Entry::Generation(Box::new(g))])
        })?;
        let (mut op, guard) = match begun {
            Begun::New(o, g) => (*o, g),
            Begun::Existing(r) => return Ok(*r),
        };
        let remaining = self.deadline_remaining(&op);
        match self.bounded(remaining, &guard.cancel, self.create_body(&mut op, &sandbox_id, &image, &p)).await {
            Ok(()) => Ok(op),
            Err(e) if e.must_stop_silently() => Err(e),
            Err(e) => self.abandon(&mut op, &sandbox_id, Generation::FIRST, e).await.map(|()| op),
        }
    }

    /// The records of a brand-new sandbox and its first generation, with its lease (OP-2).
    #[allow(clippy::too_many_arguments, reason = "one call site per creating operation; a struct would only rename the arguments")]
    pub(crate) fn new_sandbox_records(
        &self,
        state: &JournalState,
        ctx: &Ctx,
        sandbox_id: &SandboxId,
        name: Option<&str>,
        resources: &crate::domain::SandboxResources,
        image: &crate::domain::ImageRef,
        busy: &BTreeSet<u32>,
        free_disk_bytes: u64,
        nonce: &str,
        lifetime_ms: u64,
    ) -> Result<(SandboxRecord, GenerationRecord)> {
        let tags = ctx.tags();
        if let Some(n) = name
            && state.sandbox_by_name(&tags, n).is_some()
        {
            return Err(AcfError::conflict("a sandbox with that name already exists in this scope"));
        }
        let caps = self.backend.capabilities();
        let pool = Pool { size: caps.identifier_slots, busy };
        let reservation = reserve_sandbox(state, &self.cfg.envelope, caps.per_runtime_overhead_mib, pool, resources, free_disk_bytes)?;
        let now = self.wall();
        let sb = SandboxRecord {
            sandbox_id: sandbox_id.clone(),
            tags: tags.clone(),
            name: name.map(str::to_owned),
            created_wall: now.clone(),
            created_ms: self.clock.wall_ms(),
            last_generation: Generation::FIRST,
            current: Generation::FIRST,
            expiry: new_expiry(self.clock.as_ref(), lifetime_ms),
            destroyed_ms: None,
            revision: 0,
        };
        let g = self.new_generation(sandbox_id, Generation::FIRST, &tags, resources, image, reservation, nonce, ctx);
        Ok((sb, g))
    }

    #[allow(clippy::too_many_arguments, reason = "plain constructor of a record")]
    pub(crate) fn new_generation(
        &self,
        sandbox_id: &SandboxId,
        generation: Generation,
        tags: &crate::domain::Tags,
        resources: &crate::domain::SandboxResources,
        image: &crate::domain::ImageRef,
        reservation: crate::domain::Reservation,
        nonce: &str,
        ctx: &Ctx,
    ) -> GenerationRecord {
        GenerationRecord {
            sandbox_id: sandbox_id.clone(),
            generation,
            tags: tags.clone(),
            state: LifecycleState::Requested,
            paused_from: None,
            resources: resources.clone(),
            image: image.clone(),
            reservation,
            owner_nonce: nonce.to_owned(),
            handle: None,
            process: None,
            created_by: ctx.operation_id.clone(),
            created_seq: 0,
            source_snapshot: None,
            last_run: None,
            profile_id: ctx.profile.id().clone(),
            security_profile_id: self.backend.identity().security_profile_id.clone(),
            expected_agent_version: None,
            guest_agent_version: None,
            secret_refs: BTreeSet::new(),
            failure: None,
            quarantined: None,
            quarantined_ms: None,
            observe_attempts: 0,
            updated_wall: self.wall(),
            revision: 0,
        }
    }

    /// Create the generation's directory with its ownership marker (RC-1, LN-1) and move the
    /// generation to `PROVISIONING`.
    pub(crate) fn materialize(&self, op: &mut OperationRecord, sandbox_id: &SandboxId, generation: Generation) -> Result<GenerationRecord> {
        self.step(op, "create_generation_dir")?;
        let g0 = self.gen_record(sandbox_id, generation)?;
        GenerationDir::create(
            &self.layout,
            &OwnerMarker {
                schema_version: OWNER_MARKER_SCHEMA_VERSION,
                sandbox_id: sandbox_id.clone(),
                generation,
                nonce: g0.owner_nonce.clone(),
                created_by: op.operation_id.clone(),
                host_instance_id: self.instance_id.clone(),
                lineage: Some(self.journal.lineage().to_owned()),
                created_seq: Some(g0.created_seq),
            },
        )?;
        let g1 = self.moved(&g0, LifecycleState::Provisioning)?;
        self.commit_for(op, vec![Entry::Generation(Box::new(g1.clone()))])?;
        Ok(g1)
    }

    async fn create_body(
        &self,
        op: &mut OperationRecord,
        sandbox_id: &SandboxId,
        image: &ResolvedImage,
        p: &SandboxCreateParams,
    ) -> Result<()> {
        fault!(self, AfterJournalBeforeMutation, "create");
        let g1 = self.materialize(op, sandbox_id, Generation::FIRST)?;
        self.step(op, "provision")?;
        fault!(self, BeforeBackendStep, "provision");
        let req = ProvisionRequest { sandbox: g1.sandbox_ref(), resources: &p.resources, image, uid_slot: g1.reservation.uid_slot };
        let handle = self.retry_step(op, "provision", || self.backend.provision(&req)).await?;
        fault!(self, AfterBackendMutationBeforeCommit, "provision");
        let mut g2 = self.gen_record(sandbox_id, Generation::FIRST)?;
        g2.handle = Some(handle);
        g2.updated_wall = self.wall();
        self.ensure_within_deadline(op)?;
        self.finish(op, Outcome::succeeded(None), vec![Entry::Generation(Box::new(g2))])
    }

    /// Compensation for a failed create or restore: tear down what was made, then report what was
    /// **observed** (FS-3, FS-8). The operation is `FAILED`; `cleanup` says whether anything remains.
    pub(crate) async fn abandon(
        &self,
        op: &mut OperationRecord,
        sandbox_id: &SandboxId,
        generation: Generation,
        e: AcfError,
    ) -> Result<()> {
        let latest = self.gen_record(sandbox_id, generation)?;
        let info = self.failure_of(op, &e);
        let residue = Residue::Generation { sandbox_id: sandbox_id.clone(), generation };
        let (outcome, entries) = match self.retire(&latest).await {
            Retired::Clean => {
                let mut d = self.destroyed(&latest)?;
                d.failure = Some(info.clone());
                let mut entries = vec![];
                entries.extend(self.tombstone(self.sandbox_record(sandbox_id).ok(), &d));
                entries.push(Entry::Generation(Box::new(d)));
                (Outcome::failed(info, None), entries)
            }
            Retired::Quarantined(reason) => {
                let f = self.failed_generation(&latest, info.clone())?;
                (Outcome::failed(info, Some(residue)).quarantined(), self.quarantine(&f, &reason))
            }
            Retired::Unclean(_) => {
                let f = self.failed_generation(&latest, info.clone())?;
                (Outcome::failed(info, Some(residue)), vec![Entry::Generation(Box::new(f))])
            }
        };
        self.finish(op, outcome, entries)
    }

    // ------------------------------------------------------------------ start

    pub async fn sandbox_start(&self, ctx: &Ctx, t: SandboxTarget) -> Result<OperationRecord> {
        let spec = BeginSpec {
            op_type: OperationType::SandboxStart,
            target: t.sandbox_id.to_string(),
            expected_generation: Some(t.expected_generation),
            deadline_ms: self.cfg.operations.deadlines.start_ms,
            run_id: None,
            sandbox: Some((t.sandbox_id.clone(), t.expected_generation)),
            snapshot: None,
        };
        let begun = self.begin(ctx, spec, |state| {
            let (_, g) = Self::target_in(state, ctx, &t.sandbox_id, t.expected_generation, t.if_revision)?;
            if g.state != LifecycleState::Provisioning || g.handle.is_none() {
                return Err(AcfError::conflict(format!("sandbox is {:?}; only a freshly provisioned sandbox can be started", g.state)));
            }
            admit_granting(state, &t.sandbox_id)?;
            Ok(vec![])
        })?;
        let (mut op, guard) = match begun {
            Begun::New(o, g) => (*o, g),
            Begun::Existing(r) => return Ok(*r),
        };
        let remaining = self.deadline_remaining(&op);
        match self.bounded(remaining, &guard.cancel, self.start_body(&mut op, &t)).await {
            Ok(()) => Ok(op),
            Err(e) if e.must_stop_silently() => Err(e),
            Err(e) => {
                self.fail_start(&mut op, &t.sandbox_id, t.expected_generation, e).await?;
                Ok(op)
            }
        }
    }

    /// GP-4: the host refuses to complete a start or a restore when the guest reports an agent
    /// version other than the one its image (or snapshot) manifest records.
    pub(crate) fn check_agent_version(g: &GenerationRecord, reported: &str) -> Result<()> {
        match &g.expected_agent_version {
            Some(expected) if expected != reported => {
                Err(AcfError::incompatible("the guest agent reports a version that differs from the one recorded in the image manifest")
                    .with_possible_side_effect())
            }
            _ => Ok(()),
        }
    }

    async fn start_body(&self, op: &mut OperationRecord, t: &SandboxTarget) -> Result<()> {
        fault!(self, AfterJournalBeforeMutation, "start");
        let g = self.gen_record(&t.sandbox_id, t.expected_generation)?;
        let handle = g.backend_handle();
        self.step(op, "launch")?;
        fault!(self, BeforeBackendStep, "launch");
        let sink = IdentitySink { host: self, op: op.key(), sandbox: t.sandbox_id.clone(), generation: t.expected_generation };
        let out = self.retry_step(op, "launch", || self.backend.start(&handle, &sink)).await?;
        fault!(self, AfterBackendMutationBeforeCommit, "launch");
        Self::check_agent_version(&g, &out.agent_version)?;
        self.telemetry.metrics.set_gauge("last_boot_ms", i64::try_from(out.boot_ms).unwrap_or(i64::MAX));
        let mut ready = self.moved(&self.gen_record(&t.sandbox_id, t.expected_generation)?, LifecycleState::Ready)?;
        ready.process = Some(out.process.clone());
        ready.guest_agent_version = Some(out.agent_version.clone());
        self.ensure_within_deadline(op)?;
        self.finish(op, Outcome::succeeded(None), vec![Entry::Generation(Box::new(ready))])
    }

    /// Observation: is the generation's runtime proven absent? Doubt is `false`.
    async fn runtime_absent(&self, g: &GenerationRecord) -> bool {
        matches!(self.backend.observe(&g.backend_handle()).await, Ok(o) if o.vmm == VmmState::Absent)
    }

    /// A start failed. Observe (FS-3): if the failure was definite and no runtime exists, the
    /// generation is still `PROVISIONING` and can be started again; otherwise the runtime is ended
    /// and the generation is `FAILED`, keeping its lease (LS-1).
    async fn fail_start(&self, op: &mut OperationRecord, sandbox_id: &SandboxId, generation: Generation, e: AcfError) -> Result<()> {
        let g = self.gen_record(sandbox_id, generation)?;
        let info = self.failure_of(op, &e);
        let mut gone = self.runtime_absent(&g).await;
        if e.is_definite() && gone && info.class != FailureClass::Timeout {
            return self.finish(op, Outcome::failed(info, None), vec![]);
        }
        if !gone {
            // A runtime that never reached READY is not trusted: end it.
            let _ = self.backend.stop(&g.backend_handle(), self.stop_grace()).await;
            gone = self.runtime_absent(&self.gen_record(sandbox_id, generation)?).await;
        }
        if gone {
            self.lifetime.disarm(&g.sandbox_ref().jail_id());
        }
        if info.class == FailureClass::SecurityControlFailure {
            self.telemetry.metrics.incr("security_control_failures", 1);
            self.telemetry.events.emit(EventDraft::new(&self.wall(), "security.control_failure").operation(op));
        }
        let mut f = self.failed_generation(&self.gen_record(sandbox_id, generation)?, info.clone())?;
        if gone {
            f.process = None;
        }
        let residue = Residue::Generation { sandbox_id: sandbox_id.clone(), generation };
        self.finish(op, Outcome::failed(info, Some(residue)), vec![Entry::Generation(Box::new(f))])
    }

    // ------------------------------------------------------------------ containment: stop, destroy, fail

    /// The BEGIN of a containment operation on a sandbox (CC-3, CC-4): supersede whatever it
    /// preempts and reserve the state it moves the generation to, in one commit.
    fn begin_containment(
        &self,
        ctx: &Ctx,
        op_type: OperationType,
        t: &SandboxTarget,
        deadline_ms: u64,
        reserve: impl FnOnce(&GenerationRecord) -> Result<Option<GenerationRecord>>,
    ) -> Result<(Begun, Vec<OperationRecord>)> {
        let spec = BeginSpec {
            op_type,
            target: t.sandbox_id.to_string(),
            expected_generation: Some(t.expected_generation),
            deadline_ms,
            run_id: None,
            sandbox: Some((t.sandbox_id.clone(), t.expected_generation)),
            snapshot: None,
        };
        let mut superseded = Vec::new();
        let begun = self.begin(ctx, spec, |state| {
            let (_, g) = Self::target_in(state, ctx, &t.sandbox_id, t.expected_generation, t.if_revision)?;
            superseded = admit_containment(state, &t.sandbox_id, op_type)?;
            let mut entries = supersede_entries(state, &superseded, &self.wall(), self.clock.wall_ms());
            entries.extend(reserve(&g)?.map(|g| Entry::Generation(Box::new(g))));
            Ok(entries)
        })?;
        if matches!(begun, Begun::Existing(_)) {
            superseded.clear();
        }
        Ok((begun, superseded))
    }

    /// Remove what a superseded granting operation left on a sandbox other than its current
    /// generation: the new generation of a restore in place, and the partial files of a snapshot.
    async fn clear_superseded(
        &self,
        op: &OperationRecord,
        sandbox_id: &SandboxId,
        keep: Generation,
        superseded: &[OperationRecord],
    ) -> Result<()> {
        let strays: Vec<GenerationRecord> = self.journal.read(|s| {
            s.generations
                .values()
                .filter(|g| g.sandbox_id == *sandbox_id && g.generation != keep && g.state != LifecycleState::Destroyed)
                .cloned()
                .collect()
        })?;
        for g in strays {
            match self.retire(&g).await {
                Retired::Clean => self.commit_for(op, vec![Entry::Generation(Box::new(self.destroyed(&g)?))])?,
                Retired::Quarantined(r) => self.commit_for(op, self.quarantine(&g, &r))?,
                Retired::Unclean(e) => return Err(e),
            }
        }
        for s in superseded.iter().filter(|o| o.operation_type == OperationType::SnapshotCreate).filter_map(|o| o.snapshot.clone()) {
            let cleaned = self.snapshots.remove(&s.snapshot_id, s.snapshot_generation).is_ok();
            if let Some(mut rec) = self.journal.read(|st| st.snapshots.get(&(s.snapshot_id.clone(), s.snapshot_generation)).cloned())? {
                rec.state = if cleaned { SnapshotState::Deleted } else { SnapshotState::Invalid };
                if cleaned {
                    rec.reserved_bytes = 0;
                    rec.actual_bytes = 0;
                    rec.deleted_ms = Some(self.clock.wall_ms());
                }
                self.commit_for(op, vec![Entry::Snapshot(Box::new(rec))])?;
            }
        }
        Ok(())
    }

    pub async fn sandbox_stop(&self, ctx: &Ctx, t: SandboxTarget) -> Result<OperationRecord> {
        let (begun, superseded) =
            self.begin_containment(ctx, OperationType::SandboxStop, &t, self.cfg.operations.deadlines.stop_ms, |g| {
                // On STOPPED or DESTROYED: succeeds with no effect (§12.2).
                if matches!(g.state, LifecycleState::Stopped | LifecycleState::Destroyed | LifecycleState::Stopping) {
                    return Ok(None);
                }
                self.moved(g, LifecycleState::Stopping).map(Some)
            })?;
        let (mut op, _guard) = match begun {
            Begun::New(o, g) => (*o, g),
            Begun::Existing(r) => return Ok(*r),
        };
        self.preempt(&superseded).await;
        match self.stop_body(&mut op, &t, &superseded).await {
            Ok(()) => Ok(op),
            Err(e) if e.must_stop_silently() => Err(e),
            Err(e) => {
                let info = self.failure_of(&op, &e);
                self.finish(&mut op, Outcome::failed(info, None), vec![])?;
                Ok(op)
            }
        }
    }

    async fn stop_body(&self, op: &mut OperationRecord, t: &SandboxTarget, superseded: &[OperationRecord]) -> Result<()> {
        fault!(self, AfterJournalBeforeMutation, "stop");
        let g = self.gen_record(&t.sandbox_id, t.expected_generation)?;
        if matches!(g.state, LifecycleState::Stopped | LifecycleState::Destroyed) {
            return self.finish(op, Outcome::succeeded(None), vec![]);
        }
        self.step(op, "stop_runtime")?;
        fault!(self, BeforeBackendStep, "stop_runtime");
        let grace = self.stop_grace();
        let handle = g.backend_handle();
        let out = self.retry_step(op, "stop_runtime", || self.backend.stop(&handle, grace)).await?;
        fault!(self, AfterBackendMutationBeforeCommit, "stop_runtime");
        if matches!(out, StopOutcome::StillAlive) {
            return Err(AcfError::unavailable("the runtime survived every attempt to end it").with_possible_side_effect());
        }
        self.lifetime.disarm(&g.sandbox_ref().jail_id());
        self.clear_superseded(op, &t.sandbox_id, t.expected_generation, superseded).await?;
        let mut s = self.moved(&self.gen_record(&t.sandbox_id, t.expected_generation)?, LifecycleState::Stopped)?;
        s.process = None;
        self.finish(op, Outcome::succeeded(None), vec![Entry::Generation(Box::new(s))])
    }

    pub async fn sandbox_destroy(&self, ctx: &Ctx, t: SandboxTarget) -> Result<OperationRecord> {
        // The profile's `sandbox_destroy` switch governs callers. An operator and the host itself
        // are never refused containment by it (CC-4).
        if ctx.issuer == Issuer::Peer && ctx.authority.role == Role::Caller {
            ctx.profile.authorize_destroy()?;
        }
        let (begun, superseded) =
            self.begin_containment(ctx, OperationType::SandboxDestroy, &t, self.cfg.operations.deadlines.destroy_ms, |g| {
                // J-1, J-2: the commit that ends an execution or a snapshot in flight also takes the
                // generation out of RUNNING or PAUSED. The same hop reserves the destroy's first state.
                let live = matches!(
                    g.state,
                    LifecycleState::Provisioning
                        | LifecycleState::Ready
                        | LifecycleState::Running
                        | LifecycleState::Paused
                        | LifecycleState::Completed
                );
                if live { self.moved(g, LifecycleState::Stopping).map(Some) } else { Ok(None) }
            })?;
        let (mut op, _guard) = match begun {
            Begun::New(o, g) => (*o, g),
            Begun::Existing(r) => return Ok(*r),
        };
        self.preempt(&superseded).await;
        match self.destroy_body(&mut op, &t, &superseded).await {
            Ok(()) => Ok(op),
            Err(e) if e.must_stop_silently() => Err(e),
            Err(e) => {
                let info = self.failure_of(&op, &e);
                self.finish(&mut op, Outcome::failed(info, None), vec![])?;
                Ok(op)
            }
        }
    }

    pub(crate) async fn destroy_body(&self, op: &mut OperationRecord, t: &SandboxTarget, superseded: &[OperationRecord]) -> Result<()> {
        fault!(self, AfterJournalBeforeMutation, "destroy");
        let mut g = self.gen_record(&t.sandbox_id, t.expected_generation)?;
        if g.state == LifecycleState::Destroyed {
            return self.finish(op, Outcome::succeeded(None), vec![]); // idempotent
        }
        // Walk the legal path: * -> STOPPING -> STOPPED -> DESTROYED, committing the first hop so a
        // crash here leaves a state that says what was happening.
        if !matches!(g.state, LifecycleState::Stopping | LifecycleState::Stopped | LifecycleState::Requested | LifecycleState::Failed) {
            g = self.moved(&g, LifecycleState::Stopping)?;
            self.commit_for(op, vec![Entry::Generation(Box::new(g.clone()))])?;
        }
        self.step(op, "retire")?;
        fault!(self, BeforeBackendStep, "retire");
        self.clear_superseded(op, &t.sandbox_id, t.expected_generation, superseded).await?;
        let retired = self.retire(&g).await;
        fault!(self, AfterBackendMutationBeforeCommit, "retire");
        match retired {
            Retired::Clean => {
                let d = self.destroyed(&g)?;
                self.telemetry.events.emit(EventDraft::new(&self.wall(), "sandbox.destroyed").operation(op));
                let mut entries = vec![];
                entries.extend(self.tombstone(self.sandbox_record(&t.sandbox_id).ok(), &d));
                entries.push(Entry::Generation(Box::new(d)));
                self.finish(op, Outcome::succeeded(None), entries)
            }
            Retired::Quarantined(reason) => {
                let failure = FailureInfo::new(
                    FailureClass::Quarantined,
                    format!("ownership not provable, left in place: {reason}"),
                    SideEffect::Possible,
                );
                let residue = Residue::Generation { sandbox_id: t.sandbox_id.clone(), generation: t.expected_generation };
                self.finish(op, Outcome::failed(failure, Some(residue)).quarantined(), self.quarantine(&g, &reason))
            }
            Retired::Unclean(e) => Err(e),
        }
    }

    /// The host's own containment operation (OP-24, §16.2 Part B): the generation becomes `FAILED`
    /// and keeps its lease. With `stop_runtime`, the runtime is ended first.
    pub(crate) async fn sandbox_fail(
        &self,
        ctx: &Ctx,
        t: SandboxTarget,
        failure: FailureInfo,
        stop_runtime: bool,
    ) -> Result<OperationRecord> {
        let reserved_failure = failure.clone();
        let (begun, superseded) =
            self.begin_containment(ctx, OperationType::SandboxFail, &t, self.cfg.operations.deadlines.stop_ms, |g| {
                // J-1, J-2: if this preempts an execution or a snapshot, the generation leaves RUNNING or
                // PAUSED in the same commit.
                if matches!(g.state, LifecycleState::Running | LifecycleState::Paused) {
                    self.failed_generation(g, reserved_failure).map(Some)
                } else {
                    Ok(None)
                }
            })?;
        let (mut op, _guard) = match begun {
            Begun::New(o, g) => (*o, g),
            Begun::Existing(r) => return Ok(*r),
        };
        self.preempt(&superseded).await;
        let body = async {
            let g = self.gen_record(&t.sandbox_id, t.expected_generation)?;
            let mut gone = !stop_runtime;
            if stop_runtime {
                self.step(&mut op, "stop_runtime")?;
                let grace = self.stop_grace();
                match self.backend.stop(&g.backend_handle(), grace).await? {
                    StopOutcome::StillAlive => {
                        return Err(AcfError::unavailable("the runtime survived every attempt to end it").with_possible_side_effect());
                    }
                    StopOutcome::Stopped | StopOutcome::AlreadyGone | StopOutcome::Refused(_) => gone = true,
                }
            }
            if gone {
                self.lifetime.disarm(&g.sandbox_ref().jail_id());
            }
            let mut f = self.failed_generation(&self.gen_record(&t.sandbox_id, t.expected_generation)?, failure.clone())?;
            f.process = None;
            f.observe_attempts = 0;
            self.finish(&mut op, Outcome::succeeded(None), vec![Entry::Generation(Box::new(f))])
        };
        match body.await {
            Ok(()) => Ok(op),
            Err(e) if e.must_stop_silently() => Err(e),
            Err(e) => {
                let info = self.failure_of(&op, &e);
                self.finish(&mut op, Outcome::failed(info, None), vec![])?;
                Ok(op)
            }
        }
    }

    /// What a present runtime's enforcement looks like to the decision table.
    pub(crate) fn enforcement_of(obs: &EnforcementObservation) -> crate::recovery::decision::Enforcement {
        use crate::recovery::decision::Enforcement;
        match obs {
            EnforcementObservation::Intact => Enforcement::Intact,
            EnforcementObservation::Degraded(v) => Enforcement::Degraded(v.join("; ")),
            EnforcementObservation::Unknown(_) => Enforcement::Unknown,
            EnforcementObservation::NotApplicable => Enforcement::NotApplicable,
        }
    }
}
