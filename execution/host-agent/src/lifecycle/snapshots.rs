//! Snapshot create / restore / delete (spec §11.2, §20).
//!
//! Create:  probe → pause → snapshot+verified copy → write manifest → **re-hash** → READY.
//! Restore: journal-bound manifest → compatibility gate → admission → verified copy → load →
//!          **baseline probe must match** → switch `current` → retire the old generation.
//!
//! The old generation stays the addressable one until the new generation has been *verified*; a
//! failed restore therefore never costs the caller their existing sandbox.

use serde_json::json;

use super::{
    Ctx, Host, fault,
    ops::{BeginSpec, Begun},
    sandbox::Retired,
};
use crate::{
    backend::{BackendHandle, RestoreRequest, SnapshotRequest},
    domain::{FailureInfo, LifecycleState, OperationPhase, OperationStatus, OperationType, SnapshotRef, SnapshotState},
    error::{AcfError, FailureClass, Result},
    filesystem::{
        GenerationDir,
        generation::{OwnerMarker, new_nonce},
    },
    ids::{Generation, SandboxId, SnapshotId, validate_alias},
    operation::{Entry, GenerationRecord, OperationRecord, SandboxRecord, SnapshotRecord},
    protocol::{ResponseBody, RestoreTarget, SnapshotCreateParams, SnapshotRestoreParams},
    snapshot::{SnapshotManifest, check_compat},
};

const UNIQUENESS_NOTE: &str = "This snapshot has been restored more than once. Firecracker only guarantees guest-level uniqueness (RNG state, generated ids, UUIDs, tokens) for the first restore of a snapshot; treat secrets derived before the snapshot as shared across restores.";

fn snap_key(id: &SnapshotId) -> String {
    format!("snp:{id}")
}

impl Host {
    fn snapshot_record(&self, id: &SnapshotId, g: Generation) -> Result<SnapshotRecord> {
        self.journal
            .read(|s| s.snapshots.get(&(id.clone(), g)).cloned())?
            .ok_or_else(|| AcfError::not_found(format!("snapshot {id}@{g} does not exist")))
    }

    fn snap_to(&self, mut r: SnapshotRecord, to: SnapshotState) -> Result<SnapshotRecord> {
        if !r.state.can_transition_to(to) {
            return Err(AcfError::conflict(format!("illegal snapshot transition {:?} -> {to:?}", r.state)));
        }
        r.state = to;
        Ok(r)
    }

    // ------------------------------------------------------------------ create

    pub async fn snapshot_create(&self, ctx: &Ctx, p: SnapshotCreateParams) -> Result<OperationRecord> {
        ctx.policy.authorize_snapshot_create()?;
        if let Some(n) = &p.name {
            validate_alias(n)?;
        }
        let snap_id = SnapshotId::generate();
        let (free, wall, op_id) = (self.layout.free_bytes()?, self.wall(), ctx.operation_id.clone());
        let mut guard = None;
        let spec = BeginSpec {
            op_type: OperationType::SnapshotCreate,
            resource_id: snap_id.to_string(),
            expected_generation: Some(p.expected_generation),
            body: json!({"sandbox_id": p.sandbox_id, "expected_generation": p.expected_generation, "name": p.name}),
            deadline_ms: 600_000,
            run_id: None,
            sandbox: Some((p.sandbox_id.clone(), p.expected_generation)),
            snapshot: Some(SnapshotRef { snapshot_id: snap_id.clone(), snapshot_generation: Generation::FIRST }),
        };
        let me = self;
        let begun = self.begin(ctx, spec, |state| {
            let sb = state
                .sandboxes
                .get(&p.sandbox_id)
                .ok_or_else(|| AcfError::not_found(format!("sandbox {} does not exist", p.sandbox_id)))?;
            if sb.current != p.expected_generation {
                return Err(AcfError::conflict(format!(
                    "sandbox {} is at generation {}, not {} (stale reference)",
                    p.sandbox_id, sb.current, p.expected_generation
                )));
            }
            let g = state
                .generations
                .get(&(p.sandbox_id.clone(), sb.current))
                .ok_or_else(|| AcfError::internal("generation record missing"))?;
            guard = Some(me.locks.try_acquire(p.sandbox_id.as_str())?);
            if !g.state.is_idle() {
                return Err(AcfError::conflict(format!("sandbox is {:?}; a snapshot needs an idle (READY/COMPLETED) sandbox", g.state)));
            }
            if p.name.as_deref().is_some_and(|n| state.snapshot_by_name(n).is_some()) {
                return Err(AcfError::conflict("a snapshot with that name already exists"));
            }
            let reserved =
                super::capacity::reserve_snapshot(state, &me.cfg.envelope, super::capacity::snapshot_estimate_bytes(&g.resources), free)?;
            Ok(vec![Entry::Snapshot(Box::new(SnapshotRecord {
                snapshot_id: snap_id.clone(),
                generation: Generation::FIRST,
                name: p.name.clone(),
                state: SnapshotState::Requested,
                manifest_digest: None,
                reserved_bytes: reserved,
                actual_bytes: 0,
                source: Some((p.sandbox_id.clone(), p.expected_generation)),
                source_run: g.last_run.clone(),
                created_by: op_id.clone(),
                created_wall: wall.clone(),
                restore_count: 0,
                failure: None,
            }))])
        })?;
        let mut op = match begun {
            Begun::New(o) => *o,
            Begun::Existing(r) => return Ok(*r),
        };
        let _guard = guard;
        match self.snapshot_create_body(&mut op, &snap_id, &p).await {
            Ok(()) => Ok(op),
            Err(e) if e.is_simulated_crash() => Err(e),
            Err(e) => {
                self.snapshot_failed(&mut op, &snap_id, &p, e).await?;
                Ok(op)
            }
        }
    }

    async fn snapshot_create_body(&self, op: &mut OperationRecord, snap_id: &SnapshotId, p: &SnapshotCreateParams) -> Result<()> {
        fault!(self, AfterJournalBeforeMutation, "snapshot");
        let g = self.current_gen(&p.sandbox_id, p.expected_generation)?;
        let handle = g.backend_handle();

        // The probe is the restore oracle, so it is taken while the guest is still running.
        self.step(op, "probe")?;
        let probe = self.backend.probe(&handle).await?;

        let paused = self.moved(&g, LifecycleState::Paused)?;
        self.commit_gen(&paused)?;
        self.step(op, "snapshot")?;
        let dir = self.snapshots.create(snap_id, Generation::FIRST)?;
        let mut snap = self.snap_to(self.snapshot_record(snap_id, Generation::FIRST)?, SnapshotState::Snapshotting)?;
        self.journal.commit(vec![Entry::Snapshot(Box::new(snap.clone()))])?;

        fault!(self, BeforeBackendStep, "snapshot");
        let cap = (u64::from(g.resources.memory_mib.max(g.resources.disk_mib)) + 128) * 1024 * 1024;
        let art = self.backend.snapshot(&handle, &SnapshotRequest { dest: &dir, max_file_bytes: cap }).await?;
        fault!(self, AfterBackendMutationBeforeCommit, "snapshot");

        snap = self.snap_to(snap, SnapshotState::Verifying)?;
        self.journal.commit(vec![Entry::Snapshot(Box::new(snap.clone()))])?;
        let manifest = SnapshotManifest {
            schema_version: crate::snapshot::manifest::MANIFEST_SCHEMA_VERSION,
            snapshot_id: snap_id.clone(),
            snapshot_generation: Generation::FIRST,
            created_wall: self.wall(),
            source: g.sandbox_ref(),
            source_run: g.last_run.clone(),
            image: g.image.clone(),
            resources: g.resources.clone(),
            artifacts: art.clone(),
            backend: self.backend.identity().into(),
            host: self.host_fp.clone(),
            policy_id: op.policy_id.clone(),
            baseline_state_digest: probe.state_digest.clone(),
            guest_agent_version: probe.agent_version.clone(),
            acf_version: env!("CARGO_PKG_VERSION").to_owned(),
        };
        let (digest, manifest_len) = self.snapshots.write_manifest(&dir, &manifest)?;
        let stored = self.snapshots.verify_artifacts(&dir, &art)?; // re-hash from disk: VERIFYING is real

        snap = self.snap_to(snap, SnapshotState::Ready)?;
        snap.manifest_digest = Some(digest);
        snap.actual_bytes = stored + manifest_len;
        let back_to = paused.paused_from.unwrap_or(LifecycleState::Ready);
        let back = self.moved(&self.gen_record(&p.sandbox_id, p.expected_generation)?, back_to)?;
        let view = self.snapshot_view(&snap);
        self.finish(
            op,
            OperationStatus::Succeeded,
            None,
            Some(ResponseBody::Snapshot(view)),
            vec![Entry::Snapshot(Box::new(snap)), Entry::Generation(Box::new(back))],
        )
    }

    /// Bring the guest back to a usable state, remove partial artifacts, and report what was
    /// **observed** — `UNKNOWN` if we cannot show the VM is back in a known state.
    async fn snapshot_failed(&self, op: &mut OperationRecord, snap_id: &SnapshotId, p: &SnapshotCreateParams, e: AcfError) -> Result<()> {
        let info = FailureInfo::from(&e);
        let g = self.gen_record(&p.sandbox_id, p.expected_generation)?;
        let handle = g.backend_handle();
        let mut vm_ok = true;
        let g_new = if g.state == LifecycleState::Paused {
            let back = g.paused_from.unwrap_or(LifecycleState::Ready);
            let running = match self.backend.observe(&handle).await.map(|o| o.vmm) {
                Ok(crate::backend::VmmState::Running) => true,
                Ok(crate::backend::VmmState::Paused) => self.backend.resume(&handle).await.is_ok(),
                _ => false,
            };
            vm_ok = running;
            self.moved(&g, if running { back } else { LifecycleState::Failed })?
        } else {
            g.clone()
        };
        let cleaned = self.snapshots.remove(snap_id, Generation::FIRST).is_ok();
        let mut snap = self.snapshot_record(snap_id, Generation::FIRST)?;
        // The artifacts were created by *this* operation and are gone: record the tombstone so the
        // reserved quota is released. (Direct assignment: Requested→Deleted is not a normal edge.)
        snap.state = if cleaned { SnapshotState::Deleted } else { SnapshotState::Invalid };
        snap.failure = Some(info.clone());
        if cleaned {
            snap.reserved_bytes = 0;
            snap.actual_bytes = 0;
        }
        let status = Self::status_after_failure(&e, cleaned && vm_ok);
        self.telemetry.metrics.incr("snapshot_failures", 1);
        self.finish(op, status, Some(info), None, vec![Entry::Snapshot(Box::new(snap)), Entry::Generation(Box::new(g_new))])
    }

    // ------------------------------------------------------------------ restore

    fn invalidate_snapshot(&self, rec: &SnapshotRecord, why: &AcfError) {
        let mut r = rec.clone();
        r.state = SnapshotState::Invalid;
        r.failure = Some(FailureInfo::from(why));
        let _ = self.journal.commit(vec![Entry::Snapshot(Box::new(r))]);
        self.telemetry.events.emit(
            &self.wall(),
            "snapshot.invalidated",
            None,
            Some(rec.snapshot_id.as_str()),
            json!({"reason": why.message}),
        );
    }

    pub async fn snapshot_restore(&self, ctx: &Ctx, p: SnapshotRestoreParams) -> Result<OperationRecord> {
        ctx.policy.authorize_snapshot_restore()?;
        let rec = self.snapshot_record(&p.snapshot.snapshot_id, p.snapshot.snapshot_generation)?;
        if !rec.state.is_restorable() {
            return Err(AcfError::conflict(format!("snapshot is {:?}; only a READY snapshot can be restored", rec.state)));
        }
        let digest = rec.manifest_digest.clone().ok_or_else(|| AcfError::internal("READY snapshot without a manifest digest"))?;
        // Exact-object binding: journal digest → manifest bytes → (later) artifact bytes.
        let dir = match self.snapshots.open(&p.snapshot.snapshot_id, p.snapshot.snapshot_generation)? {
            Some(d) => d,
            None => {
                let e = AcfError::corrupt("snapshot directory is missing");
                self.invalidate_snapshot(&rec, &e);
                return Err(e);
            }
        };
        let manifest = match self.snapshots.read_verified_manifest(&dir, &digest) {
            Ok(m) => m,
            Err(e) => {
                self.invalidate_snapshot(&rec, &e);
                return Err(e);
            }
        };
        let why = check_compat(&manifest, self.backend.identity(), &self.host_fp);
        if !why.is_empty() {
            return Err(AcfError::new(
                FailureClass::CompatibilityFailure,
                format!("snapshot cannot be restored on this host: {}", why.join("; ")),
            ));
        }
        ctx.policy.authorize_create(&manifest.resources, manifest.image.alias.as_deref().unwrap_or(""))?;
        if let RestoreTarget::New { name: Some(n) } = &p.target {
            validate_alias(n)?;
        }

        let (new_sandbox, nonce, free, wall) = (SandboxId::generate(), new_nonce()?, self.layout.free_bytes()?, self.wall());
        let mut guards = Vec::new();
        let plan = std::cell::RefCell::new(None::<(SandboxId, Generation, Option<Generation>, Option<String>, u32)>);
        let (cfg, op_id, pol, prof) =
            (&self.cfg, ctx.operation_id.clone(), ctx.policy.id().clone(), self.backend.identity().security_profile_id.clone());
        let me = self;
        let spec = BeginSpec {
            op_type: OperationType::SnapshotRestore,
            resource_id: p.snapshot.snapshot_id.to_string(),
            expected_generation: match &p.target {
                RestoreTarget::Existing { expected_generation, .. } => Some(*expected_generation),
                RestoreTarget::New { .. } => None,
            },
            body: json!({"snapshot": p.snapshot, "target": p.target, "manifest_digest": digest}),
            deadline_ms: 600_000,
            run_id: None,
            sandbox: match &p.target {
                RestoreTarget::Existing { sandbox_id, expected_generation } => Some((sandbox_id.clone(), *expected_generation)),
                RestoreTarget::New { .. } => Some((new_sandbox.clone(), Generation::FIRST)),
            },
            snapshot: Some(p.snapshot.clone()),
        };
        let begun = self.begin(ctx, spec, |state| {
            guards.push(me.locks.try_acquire(&snap_key(&p.snapshot.snapshot_id))?);
            let mut entries = Vec::new();
            let (target_id, new_no, old_no, name) = match &p.target {
                RestoreTarget::Existing { sandbox_id, expected_generation } => {
                    let sb = state
                        .sandboxes
                        .get(sandbox_id)
                        .ok_or_else(|| AcfError::not_found(format!("sandbox {sandbox_id} does not exist")))?;
                    if sb.current != *expected_generation {
                        return Err(AcfError::conflict(format!(
                            "sandbox {sandbox_id} is at generation {}, not {expected_generation} (stale reference)",
                            sb.current
                        )));
                    }
                    let old = state
                        .generations
                        .get(&(sandbox_id.clone(), sb.current))
                        .ok_or_else(|| AcfError::internal("generation record missing"))?;
                    guards.push(me.locks.try_acquire(sandbox_id.as_str())?);
                    if matches!(old.state, LifecycleState::Running | LifecycleState::Destroyed | LifecycleState::Requested) {
                        return Err(AcfError::conflict(format!("sandbox is {:?}; it cannot be the target of a restore", old.state)));
                    }
                    let no = sb.last_generation.next();
                    entries.push(Entry::Sandbox(SandboxRecord { last_generation: no, ..sb.clone() }));
                    (sandbox_id.clone(), no, Some(sb.current), sb.name.clone())
                }
                RestoreTarget::New { name } => {
                    if name.as_deref().is_some_and(|n| Self::name_in_use(state, n)) {
                        return Err(AcfError::conflict("a sandbox with that name already exists"));
                    }
                    entries.push(Entry::Sandbox(SandboxRecord {
                        sandbox_id: new_sandbox.clone(),
                        name: name.clone(),
                        created_wall: wall.clone(),
                        last_generation: Generation::FIRST,
                        current: Generation::FIRST,
                    }));
                    (new_sandbox.clone(), Generation::FIRST, None, name.clone())
                }
            };
            // The old generation (if any) still holds its reservation: admission sees both.
            let reservation = super::capacity::reserve_sandbox(
                state,
                &cfg.envelope,
                cfg.firecracker.vmm_overhead_mib,
                cfg.firecracker.uid_range_size,
                &manifest.resources,
                free,
            )?;
            let slot = reservation.uid_slot;
            entries.push(Entry::Generation(Box::new(GenerationRecord {
                sandbox_id: target_id.clone(),
                generation: new_no,
                state: LifecycleState::Requested,
                paused_from: None,
                resources: manifest.resources.clone(),
                image: manifest.image.clone(),
                reservation,
                owner_nonce: nonce.clone(),
                handle: None,
                process: None,
                created_by: op_id.clone(),
                source_snapshot: Some(p.snapshot.clone()),
                last_run: None,
                policy_id: pol.clone(),
                security_profile_id: prof.clone(),
                failure: None,
                quarantined: None,
                updated_wall: wall.clone(),
            })));
            *plan.borrow_mut() = Some((target_id, new_no, old_no, name, slot));
            Ok(entries)
        })?;
        let mut op = match begun {
            Begun::New(o) => *o,
            Begun::Existing(r) => return Ok(*r),
        };
        let _guards = guards;
        let (target_id, new_no, old_no, name, slot) = plan.into_inner().ok_or_else(|| AcfError::internal("restore: plan was not built"))?;
        match self.restore_body(&mut op, &p, &manifest, &dir, (&target_id, new_no, old_no, name, slot)).await {
            Ok(()) => Ok(op),
            Err(e) if e.is_simulated_crash() => Err(e),
            Err(e) => {
                let g = self.gen_record(&target_id, new_no)?;
                self.abandon(&mut op, g, e).await?;
                Ok(op)
            }
        }
    }

    async fn restore_body(
        &self,
        op: &mut OperationRecord,
        p: &SnapshotRestoreParams,
        manifest: &SnapshotManifest,
        src: &cap_std::fs::Dir,
        plan: (&SandboxId, Generation, Option<Generation>, Option<String>, u32),
    ) -> Result<()> {
        let (sandbox_id, new_no, old_no, name, slot) = plan;
        fault!(self, AfterJournalBeforeMutation, "restore");
        self.step(op, "create_generation_dir")?;
        GenerationDir::create(
            &self.layout,
            &OwnerMarker {
                schema_version: 1,
                sandbox_id: sandbox_id.clone(),
                generation: new_no,
                nonce: self.gen_record(sandbox_id, new_no)?.owner_nonce,
                created_by: op.operation_id.clone(),
                host_instance_id: self.instance_id.clone(),
            },
        )?;
        let g1 = self.moved(&self.gen_record(sandbox_id, new_no)?, LifecycleState::Provisioning)?;
        self.commit_gen(&g1)?;

        self.step(op, "restore")?;
        fault!(self, BeforeBackendStep, "restore");
        let sink = super::sandbox::IdentitySinkPublic { host: self, sandbox: sandbox_id.clone(), generation: new_no };
        let (handle, out) = self
            .backend
            .restore(
                &RestoreRequest {
                    sandbox: g1.sandbox_ref(),
                    resources: &manifest.resources,
                    uid_slot: slot,
                    source: src,
                    expected: &manifest.artifacts,
                },
                &sink,
            )
            .await?;
        fault!(self, AfterBackendMutationBeforeCommit, "restore");

        // Verification: the restored guest must reproduce the probe taken just before the snapshot.
        let probe = self.backend.probe(&handle).await?;
        if probe.state_digest != manifest.baseline_state_digest {
            return Err(AcfError::new(
                FailureClass::CorruptInput,
                "restored guest does not reproduce the snapshot's baseline probe (state or disk differs, or the guest rebooted instead of resuming)",
            ));
        }

        // ---- switch: new generation becomes current; the old one is marked for retirement ----
        let mut ready = self.moved(&self.gen_record(sandbox_id, new_no)?, LifecycleState::Ready)?;
        ready.handle = Some(BackendHandle { process: None, ..handle });
        ready.process = Some(out.process.clone());
        let mut sb =
            self.journal.read(|s| s.sandboxes.get(sandbox_id).cloned())?.ok_or_else(|| AcfError::internal("sandbox record missing"))?;
        sb.current = new_no;
        let mut snap = self.snapshot_record(&p.snapshot.snapshot_id, p.snapshot.snapshot_generation)?;
        snap.restore_count += 1;
        let mut notes = vec![format!("restore verified: guest state digest {}…", &probe.state_digest[..12.min(probe.state_digest.len())])];
        if snap.restore_count > 1 {
            notes.push(UNIQUENESS_NOTE.to_owned());
        }
        let old = old_no.map(|g| self.gen_record(sandbox_id, g)).transpose()?;
        let mut entries = vec![Entry::Generation(Box::new(ready.clone())), Entry::Sandbox(sb), Entry::Snapshot(Box::new(snap))];
        let mut old_stopping = None;
        if let Some(o) = &old {
            let s = if matches!(o.state, LifecycleState::Stopping | LifecycleState::Stopped) {
                o.clone()
            } else {
                self.moved(o, LifecycleState::Stopping)?
            };
            entries.push(Entry::Generation(Box::new(s.clone())));
            old_stopping = Some(s);
        }
        op.phase = OperationPhase::InProgress { step: "retire_old".into() };
        op.status = OperationStatus::InProgress;
        op.updated_wall = self.wall();
        entries.push(Entry::Operation(Box::new(op.clone())));
        self.journal.commit(entries)?;
        fault!(self, AfterBackendMutationBeforeCommit, "restore_switch");

        // ---- retire the superseded generation (its failure does not undo the restore) ----
        let mut tail = Vec::new();
        if let Some(o) = old_stopping {
            match self.retire(&o).await {
                Retired::Clean => {
                    let stopped = if o.state == LifecycleState::Stopped { o.clone() } else { self.moved(&o, LifecycleState::Stopped)? };
                    let mut d = self.moved(&stopped, LifecycleState::Destroyed)?;
                    d.process = None;
                    tail.push(Entry::Generation(Box::new(d)));
                }
                Retired::Quarantined(r) => {
                    notes.push(format!("the previous generation could not be cleaned up and was quarantined: {r}"));
                    let mut q = o.clone();
                    q.quarantined = Some(r.clone());
                    tail.push(self.quarantine_entry(o.sandbox_id.as_str(), Some(o.generation), &r));
                    tail.push(Entry::Generation(Box::new(q)));
                }
                Retired::Unclean(e) => {
                    notes.push(format!("the previous generation could not be fully cleaned up ({}); recovery will retry", e.message))
                }
            }
        }
        let mut view = self.sandbox_view(&ready, name);
        view.notes = notes;
        self.telemetry.metrics.incr("restores", 1);
        self.finish(op, OperationStatus::Succeeded, None, Some(ResponseBody::Sandbox(view)), tail)
    }

    // ------------------------------------------------------------------ delete

    pub async fn snapshot_delete(&self, ctx: &Ctx, r: SnapshotRef) -> Result<OperationRecord> {
        ctx.policy.authorize_snapshot_delete()?;
        let mut guard = None;
        let spec = BeginSpec {
            op_type: OperationType::SnapshotDelete,
            resource_id: r.snapshot_id.to_string(),
            expected_generation: Some(r.snapshot_generation),
            body: json!({"snapshot": r}),
            deadline_ms: 120_000,
            run_id: None,
            sandbox: None,
            snapshot: Some(r.clone()),
        };
        let me = self;
        let begun = self.begin(ctx, spec, |state| {
            let rec = state
                .snapshots
                .get(&(r.snapshot_id.clone(), r.snapshot_generation))
                .ok_or_else(|| AcfError::not_found("snapshot does not exist"))?;
            guard = Some(me.locks.try_acquire(&snap_key(&r.snapshot_id))?);
            if !rec.state.can_transition_to(SnapshotState::Deleted) && rec.state != SnapshotState::Deleted {
                return Err(AcfError::conflict(format!("snapshot is {:?}; it cannot be deleted right now", rec.state)));
            }
            Ok(vec![])
        })?;
        let mut op = match begun {
            Begun::New(o) => *o,
            Begun::Existing(x) => return Ok(*x),
        };
        let _guard = guard;
        let res: Result<()> = (|| {
            fault!(self, AfterJournalBeforeMutation, "snapshot_delete");
            let rec = self.snapshot_record(&r.snapshot_id, r.snapshot_generation)?;
            if rec.state != SnapshotState::Deleted {
                self.step(&mut op, "remove")?;
                self.snapshots.remove(&r.snapshot_id, r.snapshot_generation)?;
            }
            let mut d = rec;
            d.state = SnapshotState::Deleted;
            d.reserved_bytes = 0;
            d.actual_bytes = 0;
            let view = self.snapshot_view(&d);
            self.finish(&mut op, OperationStatus::Succeeded, None, Some(ResponseBody::Snapshot(view)), vec![Entry::Snapshot(Box::new(d))])
        })();
        match res {
            Ok(()) => Ok(op),
            Err(e) if e.is_simulated_crash() => Err(e),
            Err(e) => {
                let info = FailureInfo::from(&e);
                self.finish(&mut op, Self::status_after_failure(&e, false), Some(info), None, vec![])?;
                Ok(op)
            }
        }
    }
}
