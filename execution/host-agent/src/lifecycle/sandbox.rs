//! Sandbox lifecycle flows: create → start → (exec) → stop → destroy (spec §11, §12, §22).

use std::time::Duration;

use serde_json::json;

use super::{
    Ctx, Host, fault,
    ops::{BeginSpec, Begun},
};
use crate::{
    backend::{BackendHandle, LaunchSink, ProvisionRequest, StopOutcome, TeardownOutcome},
    domain::{FailureInfo, LifecycleState, OperationStatus, OperationType},
    error::{AcfError, Result},
    filesystem::{
        GenerationDir,
        generation::{OwnerMarker, new_nonce},
    },
    ids::{Generation, SandboxId, validate_alias},
    operation::{Entry, GenerationRecord, OperationRecord, ProcessIdentity, QuarantineRecord, SandboxRecord},
    protocol::{ResponseBody, SandboxCreateParams, SandboxTarget},
};

/// What cleanup of a generation observed.
#[derive(Debug)]
pub(crate) enum Retired {
    Clean,
    Quarantined(String),
    Unclean(AcfError),
}

/// Journals the VMM's identity the moment the backend has launched it (spec §13.5).
pub(crate) struct IdentitySink<'a> {
    pub(crate) host: &'a Host,
    pub(crate) sandbox: SandboxId,
    pub(crate) generation: Generation,
}

pub(crate) type IdentitySinkPublic<'a> = IdentitySink<'a>;

#[async_trait::async_trait]
impl LaunchSink for IdentitySink<'_> {
    async fn launched(&self, p: &ProcessIdentity) -> Result<()> {
        let mut g = self.host.gen_record(&self.sandbox, self.generation)?;
        g.process = Some(p.clone());
        g.updated_wall = self.host.wall();
        self.host.commit_gen(&g)
    }
}

pub(crate) fn minimal_handle(g: &GenerationRecord) -> BackendHandle {
    g.backend_handle()
}

impl Host {
    pub(crate) fn name_in_use(state: &crate::operation::JournalState, name: &str) -> bool {
        state.sandbox_by_name(name).is_some()
    }

    /// Stop the VMM and release every host resource of `g`, with ownership proof.
    pub(crate) async fn retire(&self, g: &GenerationRecord) -> Retired {
        let grace = Duration::from_millis(self.cfg.firecracker.shutdown_grace_ms);
        match self.backend.stop(&minimal_handle(g), grace).await {
            Ok(StopOutcome::Stopped | StopOutcome::AlreadyGone | StopOutcome::Refused(_)) => {}
            Ok(StopOutcome::StillAlive) => {
                return Retired::Unclean(
                    AcfError::new(crate::error::FailureClass::BackendCrash, "VMM survived SIGKILL").with_possible_side_effect(),
                );
            }
            Err(e) => return Retired::Unclean(e),
        }
        match self.backend.teardown(&g.sandbox_ref(), &g.owner_nonce).await {
            Ok(TeardownOutcome::Removed | TeardownOutcome::Absent) => Retired::Clean,
            Ok(TeardownOutcome::Quarantine(r)) => Retired::Quarantined(r),
            Err(e) => Retired::Unclean(e),
        }
    }

    pub(crate) fn quarantine_entry(&self, id: &str, g: Option<Generation>, reason: &str) -> Entry {
        self.telemetry.metrics.incr("quarantines", 1);
        self.telemetry.events.emit(&self.wall(), "resource.quarantined", None, Some(id), json!({"reason": reason}));
        Entry::Quarantine(QuarantineRecord { resource_id: id.to_owned(), generation: g, reason: reason.to_owned(), at_wall: self.wall() })
    }

    // ------------------------------------------------------------------ create

    pub async fn sandbox_create(&self, ctx: &Ctx, p: SandboxCreateParams) -> Result<OperationRecord> {
        if let Some(n) = &p.name {
            validate_alias(n)?;
        }
        ctx.policy.authorize_create(&p.resources, &p.image)?;
        let image = self.layout.image_store()?.resolve(&p.image)?;
        let (sandbox_id, nonce, free) = (SandboxId::generate(), new_nonce()?, self.layout.free_bytes()?);
        let now = self.wall();
        let spec = BeginSpec {
            op_type: OperationType::SandboxCreate,
            resource_id: sandbox_id.to_string(),
            expected_generation: None,
            body: json!({"name": p.name, "image": p.image, "image_id": image.image_ref.image_id, "resources": p.resources}),
            deadline_ms: 300_000,
            run_id: None,
            sandbox: Some((sandbox_id.clone(), Generation::FIRST)),
            snapshot: None,
        };
        let (cfg, id2, image_ref, policy_id) = (&self.cfg, sandbox_id.clone(), image.image_ref.clone(), ctx.policy.id().clone());
        let op_id = ctx.operation_id.clone();
        let backend_profile = self.backend.identity().security_profile_id.clone();
        let g0 = std::cell::RefCell::new(None);
        let begun = self.begin(ctx, spec, |state| {
            if let Some(n) = &p.name
                && Self::name_in_use(state, n)
            {
                return Err(AcfError::conflict(format!("a sandbox named `{n}` already exists")));
            }
            let reservation = super::capacity::reserve_sandbox(
                state,
                &cfg.envelope,
                cfg.firecracker.vmm_overhead_mib,
                cfg.firecracker.uid_range_size,
                &p.resources,
                free,
            )?;
            let g = GenerationRecord {
                sandbox_id: id2.clone(),
                generation: Generation::FIRST,
                state: LifecycleState::Requested,
                paused_from: None,
                resources: p.resources.clone(),
                image: image_ref.clone(),
                reservation,
                owner_nonce: nonce.clone(),
                handle: None,
                process: None,
                created_by: op_id.clone(),
                source_snapshot: None,
                last_run: None,
                policy_id: policy_id.clone(),
                security_profile_id: backend_profile.clone(),
                failure: None,
                quarantined: None,
                updated_wall: now.clone(),
            };
            *g0.borrow_mut() = Some(g.clone());
            Ok(vec![
                Entry::Sandbox(SandboxRecord {
                    sandbox_id: id2.clone(),
                    name: p.name.clone(),
                    created_wall: now.clone(),
                    last_generation: Generation::FIRST,
                    current: Generation::FIRST,
                }),
                Entry::Generation(Box::new(g)),
            ])
        })?;
        let mut op = match begun {
            Begun::New(o) => *o,
            Begun::Existing(r) => return Ok(*r),
        };
        let g0 = g0.into_inner().ok_or_else(|| AcfError::internal("create: generation record was not built"))?;
        match self.create_body(&mut op, g0.clone(), &image, &p).await {
            Ok(()) => Ok(op),
            Err(e) if e.is_simulated_crash() => Err(e),
            Err(e) => self.abandon(&mut op, g0, e).await.map(|()| op),
        }
    }

    async fn create_body(
        &self,
        op: &mut OperationRecord,
        g0: GenerationRecord,
        image: &crate::filesystem::ResolvedImage,
        p: &SandboxCreateParams,
    ) -> Result<()> {
        fault!(self, AfterJournalBeforeMutation, "create");
        self.step(op, "create_generation_dir")?;
        GenerationDir::create(
            &self.layout,
            &OwnerMarker {
                schema_version: 1,
                sandbox_id: g0.sandbox_id.clone(),
                generation: g0.generation,
                nonce: g0.owner_nonce.clone(),
                created_by: op.operation_id.clone(),
                host_instance_id: self.instance_id.clone(),
            },
        )?;
        let g1 = self.moved(&g0, LifecycleState::Provisioning)?;
        self.commit_gen(&g1)?;
        self.step(op, "provision")?;
        fault!(self, BeforeBackendStep, "provision");
        let handle = self
            .backend
            .provision(&ProvisionRequest { sandbox: g1.sandbox_ref(), resources: &p.resources, image, uid_slot: g1.reservation.uid_slot })
            .await?;
        fault!(self, AfterBackendMutationBeforeCommit, "provision");
        let mut g2 = g1;
        g2.handle = Some(handle);
        let view = self.sandbox_view(&g2, p.name.clone());
        self.finish(op, OperationStatus::Succeeded, None, Some(ResponseBody::Sandbox(view)), vec![Entry::Generation(Box::new(g2))])
    }

    /// Compensation for a failed create/restore: tear down what was made, then report what was
    /// **observed** (spec §14.3). `FAILED` only if the world is provably clean.
    pub(crate) async fn abandon(&self, op: &mut OperationRecord, g: GenerationRecord, e: AcfError) -> Result<()> {
        let latest = self.gen_record(&g.sandbox_id, g.generation).unwrap_or(g);
        let info = FailureInfo::from(&e);
        let (clean, mut extra) = match self.retire(&latest).await {
            Retired::Clean => {
                let mut d = latest.clone();
                d.state = LifecycleState::Destroyed;
                d.failure = Some(info.clone());
                d.updated_wall = self.wall();
                (true, vec![Entry::Generation(Box::new(d))])
            }
            Retired::Quarantined(reason) => {
                let mut f = latest.clone();
                f.state = LifecycleState::Failed;
                f.quarantined = Some(reason.clone());
                f.failure = Some(info.clone());
                (
                    false,
                    vec![
                        self.quarantine_entry(latest.sandbox_id.as_str(), Some(latest.generation), &reason),
                        Entry::Generation(Box::new(f)),
                    ],
                )
            }
            Retired::Unclean(_) => {
                let mut f = latest.clone();
                f.state = LifecycleState::Failed;
                f.failure = Some(info.clone());
                (false, vec![Entry::Generation(Box::new(f))])
            }
        };
        let status = Self::status_after_failure(&e, clean);
        extra.shrink_to_fit();
        self.finish(op, status, Some(info), None, extra)
    }

    // ------------------------------------------------------------------ start

    pub async fn sandbox_start(&self, ctx: &Ctx, t: SandboxTarget) -> Result<OperationRecord> {
        let mut guard = None;
        let spec = BeginSpec {
            op_type: OperationType::SandboxStart,
            resource_id: t.sandbox_id.to_string(),
            expected_generation: Some(t.expected_generation),
            body: json!({"sandbox_id": t.sandbox_id, "expected_generation": t.expected_generation}),
            deadline_ms: 120_000,
            run_id: None,
            sandbox: Some((t.sandbox_id.clone(), t.expected_generation)),
            snapshot: None,
        };
        let begun = self.begin(ctx, spec, |state| {
            let g = Self::gen_in(state, &t)?;
            if g.state != LifecycleState::Provisioning || g.handle.is_none() {
                return Err(AcfError::conflict(format!("sandbox is {:?}; only a freshly provisioned sandbox can be started", g.state)));
            }
            guard = Some(self.locks.try_acquire(t.sandbox_id.as_str())?);
            Ok(vec![])
        })?;
        let mut op = match begun {
            Begun::New(o) => *o,
            Begun::Existing(r) => return Ok(*r),
        };
        let _guard = guard;
        match self.start_body(&mut op, &t).await {
            Ok(()) => Ok(op),
            Err(e) if e.is_simulated_crash() => Err(e),
            Err(e) => {
                self.fail_generation(&mut op, &t, e).await?;
                Ok(op)
            }
        }
    }

    fn gen_in(state: &crate::operation::JournalState, t: &SandboxTarget) -> Result<GenerationRecord> {
        let sb =
            state.sandboxes.get(&t.sandbox_id).ok_or_else(|| AcfError::not_found(format!("sandbox {} does not exist", t.sandbox_id)))?;
        if sb.current != t.expected_generation {
            return Err(AcfError::conflict(format!(
                "sandbox {} is at generation {}, not {} (stale reference)",
                t.sandbox_id, sb.current, t.expected_generation
            )));
        }
        state
            .generations
            .get(&(t.sandbox_id.clone(), t.expected_generation))
            .cloned()
            .ok_or_else(|| AcfError::internal("generation record missing"))
    }

    async fn start_body(&self, op: &mut OperationRecord, t: &SandboxTarget) -> Result<()> {
        fault!(self, AfterJournalBeforeMutation, "start");
        let g = self.current_gen(&t.sandbox_id, t.expected_generation)?;
        let handle = g.backend_handle();
        if g.handle.is_none() {
            return Err(AcfError::internal("provisioned sandbox has no backend handle"));
        }
        self.step(op, "launch")?;
        fault!(self, BeforeBackendStep, "launch");
        let sink = IdentitySink { host: self, sandbox: t.sandbox_id.clone(), generation: t.expected_generation };
        let out = self.backend.start(&handle, &sink).await?;
        fault!(self, AfterBackendMutationBeforeCommit, "launch");
        self.telemetry.metrics.set_gauge("last_boot_ms", i64::try_from(out.boot_ms).unwrap_or(i64::MAX));
        let mut g2 = self.moved(&self.current_gen(&t.sandbox_id, t.expected_generation)?, LifecycleState::Ready)?;
        g2.process = Some(out.process.clone());
        let name = self.journal.read(|s| s.sandboxes.get(&t.sandbox_id).and_then(|x| x.name.clone()))?;
        let view = self.sandbox_view(&g2, name);
        self.finish(op, OperationStatus::Succeeded, None, Some(ResponseBody::Sandbox(view)), vec![Entry::Generation(Box::new(g2))])
    }

    /// A start/restore failed *after* resources exist: mark the generation `FAILED` (it keeps its
    /// reservation until destroyed) and report honestly.
    pub(crate) async fn fail_generation(&self, op: &mut OperationRecord, t: &SandboxTarget, e: AcfError) -> Result<()> {
        let g = self.current_gen(&t.sandbox_id, t.expected_generation)?;
        // The backend kills a VMM it could not finish booting; *observe* instead of assuming.
        let vmm_gone = match self.backend.observe(&minimal_handle(&g)).await {
            Ok(o) => matches!(o.vmm, crate::backend::VmmState::Absent),
            Err(_) => false,
        };
        if e.class == crate::error::FailureClass::SecurityControlFailure {
            self.telemetry.metrics.incr("security_control_failures", 1);
            self.telemetry.events.emit(
                &self.wall(),
                "security.control_failure",
                Some(op.operation_id.as_str()),
                Some(g.sandbox_id.as_str()),
                json!({"message": e.message}),
            );
        }
        let info = FailureInfo::from(&e);
        let mut f = if g.state.can_transition_to(LifecycleState::Failed) { self.moved(&g, LifecycleState::Failed)? } else { g };
        f.failure = Some(info.clone());
        let status = Self::status_after_failure(&e, vmm_gone);
        self.finish(op, status, Some(info), None, vec![Entry::Generation(Box::new(f))])
    }

    // ------------------------------------------------------------------ stop

    pub async fn sandbox_stop(&self, ctx: &Ctx, t: SandboxTarget) -> Result<OperationRecord> {
        let mut guard = None;
        let spec = BeginSpec {
            op_type: OperationType::SandboxStop,
            resource_id: t.sandbox_id.to_string(),
            expected_generation: Some(t.expected_generation),
            body: json!({"sandbox_id": t.sandbox_id, "expected_generation": t.expected_generation}),
            deadline_ms: 60_000,
            run_id: None,
            sandbox: Some((t.sandbox_id.clone(), t.expected_generation)),
            snapshot: None,
        };
        let me = self;
        let begun = self.begin(ctx, spec, |state| {
            let g = Self::gen_in(state, &t)?;
            guard = Some(me.locks.try_acquire(t.sandbox_id.as_str())?);
            if matches!(g.state, LifecycleState::Stopped | LifecycleState::Destroyed) {
                return Ok(vec![]); // idempotent no-op
            }
            if g.state == LifecycleState::Running {
                return Err(AcfError::conflict("a run is in flight; cancel it before stopping"));
            }
            Ok(vec![Entry::Generation(Box::new(me.moved(&g, LifecycleState::Stopping)?))])
        })?;
        let mut op = match begun {
            Begun::New(o) => *o,
            Begun::Existing(r) => return Ok(*r),
        };
        let _guard = guard;
        let r = self.stop_body(&mut op, &t).await;
        match r {
            Err(e) if e.is_simulated_crash() => Err(e),
            Err(e) => {
                let info = FailureInfo::from(&e);
                self.finish(&mut op, Self::status_after_failure(&e, false), Some(info), None, vec![])?;
                Ok(op)
            }
            Ok(()) => Ok(op),
        }
    }

    async fn stop_body(&self, op: &mut OperationRecord, t: &SandboxTarget) -> Result<()> {
        fault!(self, AfterJournalBeforeMutation, "stop");
        let g = self.current_gen(&t.sandbox_id, t.expected_generation)?;
        let name = self.journal.read(|s| s.sandboxes.get(&t.sandbox_id).and_then(|x| x.name.clone()))?;
        if matches!(g.state, LifecycleState::Stopped | LifecycleState::Destroyed) {
            let view = self.sandbox_view(&g, name);
            return self.finish(op, OperationStatus::Succeeded, None, Some(ResponseBody::Sandbox(view)), vec![]);
        }
        self.step(op, "stop_vmm")?;
        fault!(self, BeforeBackendStep, "stop_vmm");
        let out = self.backend.stop(&minimal_handle(&g), Duration::from_millis(self.cfg.firecracker.shutdown_grace_ms)).await?;
        fault!(self, AfterBackendMutationBeforeCommit, "stop_vmm");
        if matches!(out, StopOutcome::StillAlive) {
            return Err(AcfError::new(crate::error::FailureClass::BackendCrash, "VMM survived SIGKILL").with_possible_side_effect());
        }
        let mut s = self.moved(&g, LifecycleState::Stopped)?;
        s.process = None;
        let view = self.sandbox_view(&s, name);
        self.finish(op, OperationStatus::Succeeded, None, Some(ResponseBody::Sandbox(view)), vec![Entry::Generation(Box::new(s))])
    }

    // ------------------------------------------------------------------ destroy

    pub async fn sandbox_destroy(&self, ctx: &Ctx, t: SandboxTarget) -> Result<OperationRecord> {
        ctx.policy.authorize_destroy()?;
        let mut guard = None;
        let spec = BeginSpec {
            op_type: OperationType::SandboxDestroy,
            resource_id: t.sandbox_id.to_string(),
            expected_generation: Some(t.expected_generation),
            body: json!({"sandbox_id": t.sandbox_id, "expected_generation": t.expected_generation}),
            deadline_ms: 120_000,
            run_id: None,
            sandbox: Some((t.sandbox_id.clone(), t.expected_generation)),
            snapshot: None,
        };
        let me = self;
        let begun = self.begin(ctx, spec, |state| {
            let g = Self::gen_in(state, &t)?;
            guard = Some(me.locks.try_acquire(t.sandbox_id.as_str())?);
            if g.state == LifecycleState::Running {
                return Err(AcfError::conflict("a run is in flight; cancel it before destroying"));
            }
            Ok(vec![])
        })?;
        let mut op = match begun {
            Begun::New(o) => *o,
            Begun::Existing(r) => return Ok(*r),
        };
        let _guard = guard;
        match self.destroy_body(&mut op, &t).await {
            Ok(()) => {
                self.locks.prune(t.sandbox_id.as_str());
                Ok(op)
            }
            Err(e) if e.is_simulated_crash() => Err(e),
            Err(e) => {
                let info = FailureInfo::from(&e);
                self.finish(&mut op, Self::status_after_failure(&e, false), Some(info), None, vec![])?;
                Ok(op)
            }
        }
    }

    async fn destroy_body(&self, op: &mut OperationRecord, t: &SandboxTarget) -> Result<()> {
        fault!(self, AfterJournalBeforeMutation, "destroy");
        let mut g = self.current_gen(&t.sandbox_id, t.expected_generation)?;
        let name = self.journal.read(|s| s.sandboxes.get(&t.sandbox_id).and_then(|x| x.name.clone()))?;
        if g.state == LifecycleState::Destroyed {
            let view = self.sandbox_view(&g, name);
            return self.finish(op, OperationStatus::Succeeded, None, Some(ResponseBody::Sandbox(view)), vec![]); // idempotent
        }
        if g.quarantined.is_some() {
            return Err(AcfError::new(
                crate::error::FailureClass::RecoveryQuarantined,
                "this sandbox is quarantined: ownership of its resources could not be proven; an operator must intervene",
            ));
        }
        // Walk the legal path: * -> STOPPING -> STOPPED -> DESTROYED, committing each hop.
        if !matches!(g.state, LifecycleState::Stopping | LifecycleState::Stopped | LifecycleState::Requested) {
            g = self.moved(&g, LifecycleState::Stopping)?;
            self.commit_gen(&g)?;
        }
        self.step(op, "retire")?;
        fault!(self, BeforeBackendStep, "retire");
        let retired = self.retire(&g).await;
        fault!(self, AfterBackendMutationBeforeCommit, "retire");
        match retired {
            Retired::Clean => {
                let mut d = g.clone();
                d.state = LifecycleState::Destroyed;
                d.process = None;
                d.updated_wall = self.wall();
                let view = self.sandbox_view(&d, name);
                self.telemetry.events.emit(
                    &self.wall(),
                    "sandbox.destroyed",
                    Some(op.operation_id.as_str()),
                    Some(d.sandbox_id.as_str()),
                    json!({"generation": d.generation}),
                );
                self.finish(op, OperationStatus::Succeeded, None, Some(ResponseBody::Sandbox(view)), vec![Entry::Generation(Box::new(d))])
            }
            Retired::Quarantined(reason) => {
                let mut q = g.clone();
                q.quarantined = Some(reason.clone());
                let e = AcfError::new(
                    crate::error::FailureClass::RecoveryQuarantined,
                    format!("ownership not provable, left in place: {reason}"),
                );
                let entries =
                    vec![self.quarantine_entry(g.sandbox_id.as_str(), Some(g.generation), &reason), Entry::Generation(Box::new(q))];
                self.finish(op, OperationStatus::Failed, Some(FailureInfo::from(&e)), None, entries)
            }
            Retired::Unclean(e) => Err(e),
        }
    }
}
