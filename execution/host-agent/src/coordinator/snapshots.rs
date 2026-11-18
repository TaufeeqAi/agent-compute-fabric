//! Snapshot create / restore / delete (contract §21).
//!
//! Create:  probe → pause → capture + verified copy → write manifest → **re-hash** → READY, and the
//!          guest is returned to the state it was paused from whether or not the capture succeeds
//!          (SNP-5).
//! Restore: store-held digest → manifest → compatibility gate → admission → verified copy → load →
//!          agent version → **baseline probe must match** (the oracle, RE-4) → switch → retire.
//!
//! The old generation stays the addressable one until the new generation has been *verified*; a
//! failed restore therefore never costs the caller their existing sandbox (RE-6).

use serde_json::json;

use super::{
    Ctx, Host, fault,
    ops::{BeginSpec, Begun, Outcome, admit_granting},
    sandbox::{IdentitySink, Retired},
};
use crate::{
    api::{RestoreTarget, SnapshotCreateParams, SnapshotDeleteParams, SnapshotRestoreParams},
    backend::{BackendHandle, RestoreRequest, SnapshotRequest, VmmState},
    domain::{FailureInfo, Issuer, LifecycleState, OperationState, OperationType, Residue, Role, SecretRef, SnapshotRef, SnapshotState},
    error::{AcfError, FailureClass, Result, SideEffect},
    ids::{Generation, SandboxId, SnapshotId, validate_alias},
    resources::admission::{Pool, reserve_sandbox, reserve_snapshot, snapshot_estimate_bytes},
    storage::{
        generation::new_nonce,
        snapshots::{MANIFEST_SCHEMA_VERSION, SnapshotManifest, check_compat},
    },
    store::{Entry, OperationRecord, SnapshotRecord},
};

const UNIQUENESS_NOTE: &str = "This snapshot has been restored more than once. The VMM only guarantees guest-level uniqueness (random state, generated ids, tokens) for the first restore of a snapshot; treat secrets derived before the snapshot as shared across restores.";

/// What a restore decided inside BEGIN.
struct RestorePlan {
    sandbox_id: SandboxId,
    new_generation: Generation,
    old_generation: Option<Generation>,
}

impl Host {
    fn snapshot_record(&self, id: &SnapshotId, g: Generation) -> Result<SnapshotRecord> {
        self.journal
            .read(|s| s.snapshots.get(&(id.clone(), g)).cloned())?
            .ok_or_else(|| AcfError::not_found(format!("snapshot {id}@{g} does not exist")))
    }

    /// The snapshot `r`, if the caller's tags reach it (SNP-6). Otherwise it does not exist (AU-9).
    fn snapshot_for(&self, ctx: &Ctx, r: &SnapshotRef) -> Result<SnapshotRecord> {
        let rec = self.snapshot_record(&r.snapshot_id, r.snapshot_generation)?;
        ctx.require_access(&rec.tags, &format!("snapshot {r}"))?;
        Ok(rec)
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
        ctx.profile.authorize_snapshot_create()?;
        if !self.backend.capabilities().snapshot {
            return Err(AcfError::unsupported("this host's backend does not offer snapshots"));
        }
        if let Some(n) = &p.name {
            validate_alias(n)?;
        }
        let snap_id = SnapshotId::generate();
        let sref = SnapshotRef { snapshot_id: snap_id.clone(), snapshot_generation: Generation::FIRST };
        let t = p.sandbox_target();
        let (free, wall) = (self.layout.free_bytes()?, self.wall());
        let spec = BeginSpec {
            op_type: OperationType::SnapshotCreate,
            target: snap_id.to_string(),
            expected_generation: Some(t.expected_generation),
            deadline_ms: self.cfg.operations.deadlines.snapshot_ms,
            run_id: None,
            sandbox: Some((t.sandbox_id.clone(), t.expected_generation)),
            snapshot: Some(sref.clone()),
        };
        let begun = self.begin(ctx, spec, |state| {
            let (_, g) = Self::target_in(state, ctx, &t.sandbox_id, t.expected_generation, t.if_revision)?;
            admit_granting(state, &t.sandbox_id)?;
            if !g.state.is_idle() {
                return Err(AcfError::conflict(format!("sandbox is {:?}; a snapshot needs an idle (READY or COMPLETED) sandbox", g.state)));
            }
            if p.name.as_deref().is_some_and(|n| state.snapshot_by_name(&ctx.tags(), n).is_some()) {
                return Err(AcfError::conflict("a snapshot with that name already exists in this scope"));
            }
            let reserved = reserve_snapshot(state, &self.cfg.envelope, snapshot_estimate_bytes(&g.resources), free)?;
            // J-2: the generation is PAUSED exactly while its snapshot operation is not terminal. The
            // state it returns to is recorded with it.
            let paused = self.moved(&g, LifecycleState::Paused)?;
            Ok(vec![
                Entry::Generation(Box::new(paused)),
                Entry::Snapshot(Box::new(SnapshotRecord {
                    snapshot_id: snap_id.clone(),
                    generation: Generation::FIRST,
                    tags: ctx.tags(),
                    name: p.name.clone(),
                    state: SnapshotState::Requested,
                    manifest_digest: None,
                    reserved_bytes: reserved,
                    actual_bytes: 0,
                    source: Some((t.sandbox_id.clone(), t.expected_generation)),
                    source_run: g.last_run.clone(),
                    created_by: ctx.operation_id.clone(),
                    created_wall: wall.clone(),
                    restore_count: 0,
                    secret_refs: g.secret_refs.clone(),
                    failure: None,
                    deleted_ms: None,
                    revision: 0,
                })),
            ])
        })?;
        let (mut op, guard) = match begun {
            Begun::New(o, g) => (*o, g),
            Begun::Existing(r) => return Ok(*r),
        };
        let remaining = self.deadline_remaining(&op);
        match self.bounded(remaining, &guard.cancel, self.snapshot_create_body(&mut op, &snap_id, &p)).await {
            Ok(()) => Ok(op),
            Err(e) if e.must_stop_silently() => Err(e),
            Err(e) => {
                self.snapshot_failed(&mut op, &snap_id, &p, e).await?;
                Ok(op)
            }
        }
    }

    async fn snapshot_create_body(&self, op: &mut OperationRecord, snap_id: &SnapshotId, p: &SnapshotCreateParams) -> Result<()> {
        fault!(self, AfterJournalBeforeMutation, "snapshot");
        let g = self.gen_record(&p.sandbox_id, p.expected_generation)?;
        let handle = g.backend_handle();

        // The probe is the restore oracle, so it is taken while the guest's vCPUs still run: the
        // record says PAUSED from BEGIN on, the backend pauses the guest for the capture itself.
        self.step(op, "probe")?;
        let probe = self.backend.probe(&handle).await?;

        self.step(op, "snapshot")?;
        let dir = self.snapshots.create(snap_id, Generation::FIRST)?;
        let mut snap = self.snap_to(self.snapshot_record(snap_id, Generation::FIRST)?, SnapshotState::Snapshotting)?;
        self.commit_for(op, vec![Entry::Snapshot(Box::new(snap.clone()))])?;

        fault!(self, BeforeBackendStep, "snapshot");
        let cap = (u64::from(g.resources.memory_mib.max(g.resources.disk_mib)) + 128) * 1024 * 1024;
        let request = SnapshotRequest { dest: &dir, max_file_bytes: cap };
        // RC-6: the capture holds the sandbox, so it keeps verifying the runtime's posture (IS-3).
        let art = self.while_intact(&p.sandbox_id, p.expected_generation, self.backend.snapshot(&handle, &request)).await?;
        fault!(self, AfterBackendMutationBeforeCommit, "snapshot");

        snap = self.snap_to(snap, SnapshotState::Verifying)?;
        self.commit_for(op, vec![Entry::Snapshot(Box::new(snap.clone()))])?;
        let manifest = SnapshotManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
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
            profile_id: op.profile_id.clone(),
            baseline_state_digest: probe.state_digest.clone(),
            guest_agent_version: probe.agent_version.clone(),
            guest_protocol_version: acf_wire::guest::GUEST_PROTOCOL_VERSION,
            tags: snap.tags.clone(),
            secret_refs: snap.secret_refs.iter().cloned().collect(),
            restore_reseeds_entropy: self.backend.capabilities().restore_reseeds_entropy,
            acf_version: env!("CARGO_PKG_VERSION").to_owned(),
        };
        let (digest, manifest_len) = self.snapshots.write_manifest(&dir, &manifest)?;
        let stored = self.snapshots.verify_artifacts(&dir, &art)?; // re-hash from disk: VERIFYING is real

        snap = self.snap_to(snap, SnapshotState::Ready)?;
        snap.manifest_digest = Some(digest);
        snap.actual_bytes = stored + manifest_len;
        let back_to = g.paused_from.unwrap_or(LifecycleState::Ready);
        let back = self.moved(&self.gen_record(&p.sandbox_id, p.expected_generation)?, back_to)?;
        self.ensure_within_deadline(op)?;
        self.finish(op, Outcome::succeeded(None), vec![Entry::Snapshot(Box::new(snap)), Entry::Generation(Box::new(back))])
    }

    /// Bring the guest back to the state it was paused from, remove partial artifacts, release the
    /// quota, and report what was **observed** (SNP-5, FS-8).
    async fn snapshot_failed(&self, op: &mut OperationRecord, snap_id: &SnapshotId, p: &SnapshotCreateParams, e: AcfError) -> Result<()> {
        let info = self.failure_of(op, &e);
        let g = self.gen_record(&p.sandbox_id, p.expected_generation)?;
        let handle = g.backend_handle();
        let control_lost = info.class == FailureClass::SecurityControlFailure;
        if control_lost {
            self.telemetry.metrics.incr("security_control_failures", 1);
            self.telemetry.events.emit(crate::telemetry::EventDraft::new(&self.wall(), "security.control_failure").operation(op));
        }
        let mut vm_ok = true;
        let g_new = if g.state == LifecycleState::Paused {
            let back = g.paused_from.unwrap_or(LifecycleState::Ready);
            let mut ended = false;
            let running = if control_lost {
                // IS-3: a runtime whose control is lost is ended. It is never resumed.
                let stopped = self.backend.stop(&handle, self.stop_grace()).await;
                ended = matches!(stopped, Ok(crate::backend::StopOutcome::Stopped | crate::backend::StopOutcome::AlreadyGone));
                if ended {
                    self.lifetime.disarm(&g.sandbox_ref().jail_id());
                }
                false
            } else {
                match self.backend.observe(&handle).await.map(|o| o.vmm) {
                    Ok(VmmState::Running) => true,
                    Ok(VmmState::Paused) => self.backend.resume(&handle).await.is_ok(),
                    _ => false,
                }
            };
            vm_ok = running;
            if running {
                self.moved(&g, back)?
            } else {
                let mut failed = self.failed_generation(&g, info.clone())?;
                if ended {
                    failed.process = None;
                }
                failed
            }
        } else {
            g.clone()
        };
        let cleaned = self.snapshots.remove(snap_id, Generation::FIRST).is_ok();
        let mut snap = self.snapshot_record(snap_id, Generation::FIRST)?;
        // The artifacts were created by *this* operation: when they are gone the record is a
        // tombstone and the quota is released. (Direct assignment: REQUESTED→DELETED is not an edge
        // a caller can take.)
        snap.state = if cleaned { SnapshotState::Deleted } else { SnapshotState::Invalid };
        snap.failure = Some(info.clone());
        if cleaned {
            snap.reserved_bytes = 0;
            snap.actual_bytes = 0;
            snap.deleted_ms = Some(self.clock.wall_ms());
        }
        let residue = match (cleaned, vm_ok) {
            (true, true) => None,
            (false, _) => Some(Residue::Snapshot { snapshot: snap.snapshot_ref() }),
            (true, false) => Some(Residue::Generation { sandbox_id: p.sandbox_id.clone(), generation: p.expected_generation }),
        };
        self.telemetry.metrics.incr("snapshot_failures", 1);
        self.finish(op, Outcome::failed(info, residue), vec![Entry::Snapshot(Box::new(snap)), Entry::Generation(Box::new(g_new))])
    }

    // ------------------------------------------------------------------ restore

    fn invalidate_snapshot(&self, rec: &SnapshotRecord, why: &AcfError) {
        let mut r = rec.clone();
        r.state = SnapshotState::Invalid;
        r.failure = Some(FailureInfo::from(why));
        let _ = self.journal.commit(vec![Entry::Snapshot(Box::new(r))]);
        self.telemetry.metrics.incr("snapshot_integrity_failures", 1);
        self.telemetry.events.emit_simple(&self.wall(), "snapshot.invalidated", json!({ "snapshot_id": rec.snapshot_id }));
    }

    pub async fn snapshot_restore(&self, ctx: &Ctx, p: SnapshotRestoreParams) -> Result<OperationRecord> {
        ctx.profile.authorize_snapshot_restore()?;
        if !self.backend.capabilities().restore {
            return Err(AcfError::unsupported("this host's backend does not offer restore"));
        }
        // RE-1: READY, tags equal, the profile permits it.
        let rec = self.snapshot_for(ctx, &p.snapshot)?;
        if !rec.state.is_restorable() {
            return Err(AcfError::conflict(format!("snapshot is {:?}; only a READY snapshot can be restored", rec.state)));
        }
        let digest = rec.manifest_digest.clone().ok_or_else(|| AcfError::internal("READY snapshot without a manifest digest"))?;
        // RE-2, fail closed. Exact-object binding: store digest → manifest bytes → (later) artifact bytes.
        let Some(dir) = self.snapshots.open(&p.snapshot.snapshot_id, p.snapshot.snapshot_generation)? else {
            let e = AcfError::corrupt("the snapshot's files are missing");
            self.invalidate_snapshot(&rec, &e);
            return Err(e);
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
            self.telemetry.metrics.incr("snapshot_compatibility_failures", 1);
            return Err(AcfError::incompatible(format!("snapshot cannot be restored on this host: {}", why.join("; "))));
        }
        // SC-6: every secret reference recorded in the snapshot must still resolve for this request.
        for name in &manifest.secret_refs {
            if self.secrets.resolve(&SecretRef { name: name.clone() }).await.is_err() {
                return Err(AcfError::incompatible(
                    "the snapshot is secret-bearing and one of its secret references no longer resolves on this host",
                ));
            }
        }
        ctx.profile.authorize_create(&manifest.resources, manifest.image.alias.as_deref().unwrap_or(""), None)?;
        self.require_network_capability(&manifest.resources)?;
        let lifetime_ms = match &p.target {
            RestoreTarget::New { name, lifetime_secs } => {
                if let Some(n) = name {
                    validate_alias(n)?;
                }
                Some(ctx.profile.authorize_lifetime(*lifetime_secs)?)
            }
            RestoreTarget::Existing { .. } => None, // LT-1: restore in place keeps the sandbox's expiry
        };

        let busy = self.backend.busy_slots().await?;
        let (new_sandbox, nonce, free) = (SandboxId::generate(), new_nonce()?, self.layout.free_bytes()?);
        let mut plan = None;
        let spec = BeginSpec {
            op_type: OperationType::SnapshotRestore,
            target: p.snapshot.snapshot_id.to_string(),
            expected_generation: match &p.target {
                RestoreTarget::Existing { expected_generation, .. } => Some(*expected_generation),
                RestoreTarget::New { .. } => None,
            },
            deadline_ms: self.cfg.operations.deadlines.restore_ms,
            run_id: None,
            sandbox: match &p.target {
                RestoreTarget::Existing { sandbox_id, expected_generation, .. } => Some((sandbox_id.clone(), *expected_generation)),
                RestoreTarget::New { .. } => Some((new_sandbox.clone(), Generation::FIRST)),
            },
            snapshot: Some(p.snapshot.clone()),
        };
        let begun = self.begin(ctx, spec, |state| {
            // The snapshot may have changed since it was read: check it again where it counts.
            let current = state.snapshots.get(&(p.snapshot.snapshot_id.clone(), p.snapshot.snapshot_generation));
            if !current.is_some_and(|s| s.state.is_restorable() && s.manifest_digest.as_deref() == Some(digest.as_str())) {
                return Err(AcfError::conflict("the snapshot is no longer READY"));
            }
            let caps = self.backend.capabilities();
            let mut entries = Vec::new();
            let (sandbox_id, new_generation, old_generation) = match &p.target {
                RestoreTarget::Existing { sandbox_id, expected_generation, if_revision } => {
                    let (sb, old) = Self::target_in(state, ctx, sandbox_id, *expected_generation, *if_revision)?;
                    admit_granting(state, sandbox_id)?;
                    // §12.2: any state except REQUESTED, RUNNING and DESTROYED.
                    if matches!(old.state, LifecycleState::Running | LifecycleState::Destroyed | LifecycleState::Requested) {
                        return Err(AcfError::conflict(format!("sandbox is {:?}; it cannot be the target of a restore", old.state)));
                    }
                    let no = sb.last_generation.next();
                    // RE-1: capacity for the new generation is reserved in addition to the old one's lease.
                    let pool = Pool { size: caps.identifier_slots, busy: &busy };
                    let reservation =
                        reserve_sandbox(state, &self.cfg.envelope, caps.per_runtime_overhead_mib, pool, &manifest.resources, free)?;
                    let mut g =
                        self.new_generation(sandbox_id, no, &sb.tags, &manifest.resources, &manifest.image, reservation, &nonce, ctx);
                    g.source_snapshot = Some(p.snapshot.clone());
                    entries.push(Entry::Sandbox(crate::store::SandboxRecord { last_generation: no, ..sb.clone() }));
                    entries.push(Entry::Generation(Box::new(g)));
                    (sandbox_id.clone(), no, Some(sb.current))
                }
                RestoreTarget::New { name, .. } => {
                    let lifetime_ms = lifetime_ms.ok_or_else(|| AcfError::internal("restore as new without a lifetime"))?;
                    let (sb, mut g) = self.new_sandbox_records(
                        state,
                        ctx,
                        &new_sandbox,
                        name.as_deref(),
                        &manifest.resources,
                        &manifest.image,
                        &busy,
                        free,
                        &nonce,
                        lifetime_ms,
                    )?;
                    g.source_snapshot = Some(p.snapshot.clone());
                    entries.push(Entry::Sandbox(sb));
                    entries.push(Entry::Generation(Box::new(g)));
                    (new_sandbox.clone(), Generation::FIRST, None)
                }
            };
            // GP-4 and SC-5 travel with the snapshot onto the generation it becomes.
            if let Some(Entry::Generation(g)) = entries.last_mut() {
                g.expected_agent_version = Some(manifest.guest_agent_version.clone());
                g.secret_refs = manifest.secret_refs.iter().cloned().collect();
            }
            plan = Some(RestorePlan { sandbox_id, new_generation, old_generation });
            Ok(entries)
        })?;
        let (mut op, guard) = match begun {
            Begun::New(o, g) => (*o, g),
            Begun::Existing(r) => return Ok(*r),
        };
        let plan = plan.ok_or_else(|| AcfError::internal("restore: the plan was not built"))?;
        let remaining = self.deadline_remaining(&op);
        match self.bounded(remaining, &guard.cancel, self.restore_body(&mut op, &p, &manifest, &dir, &plan)).await {
            Ok(()) => Ok(op),
            Err(e) if e.must_stop_silently() => Err(e),
            // After the switch the restore has happened; only the retirement of the old generation
            // is left, and its failure never undoes the restore (RE-5).
            Err(e) if op.step.as_deref() == Some("retire_old") => {
                let note = format!("the previous generation could not be retired yet: {}", e.message);
                self.finish(&mut op, Outcome::succeeded(Some(json!({ "notes": [note] }))), vec![])?;
                Ok(op)
            }
            Err(e) => {
                // SNP-3: an artifact that no longer matches its manifest can never be restored, so the
                // snapshot must stop being listed as restorable, as it does when its manifest changed.
                // Only the snapshot's own files decide that. An integrity failure of anything else (the
                // VMM binary, a guest that did not reproduce the baseline) says nothing about them.
                let unusable = if e.class == FailureClass::IntegrityFailure {
                    self.snapshots.verify_artifacts(&dir, &manifest.artifacts).err()
                } else {
                    None
                };
                self.abandon(&mut op, &plan.sandbox_id, plan.new_generation, e).await?;
                if let Some(why) = unusable
                    && let Ok(current) = self.snapshot_record(&p.snapshot.snapshot_id, p.snapshot.snapshot_generation)
                    && current.state.is_restorable()
                {
                    self.invalidate_snapshot(&current, &why);
                }
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
        plan: &RestorePlan,
    ) -> Result<()> {
        let (sandbox_id, new_no) = (&plan.sandbox_id, plan.new_generation);
        fault!(self, AfterJournalBeforeMutation, "restore");
        let g1 = self.materialize(op, sandbox_id, new_no)?;

        self.step(op, "restore")?;
        fault!(self, BeforeBackendStep, "restore");
        let sink = IdentitySink { host: self, op: op.key(), sandbox: sandbox_id.clone(), generation: new_no };
        let req = RestoreRequest {
            sandbox: g1.sandbox_ref(),
            resources: &manifest.resources,
            uid_slot: g1.reservation.uid_slot,
            source: src,
            expected: &manifest.artifacts,
        };
        // RC-6: a restore in place holds the sandbox while its current generation may still be running,
        // so the restore keeps verifying that generation's posture (IS-3). If a control is lost the
        // restore is abandoned, and the sweep then ends the generation as it would any idle one.
        let restore = self.backend.restore(&req, &sink);
        let (handle, out) = match plan.old_generation {
            Some(old) => self.while_intact(sandbox_id, old, restore).await?,
            None => restore.await?,
        };
        fault!(self, AfterBackendMutationBeforeCommit, "restore");

        // GP-4, then the oracle (RE-4): the restored guest must reproduce the probe taken just
        // before the snapshot. A guest that rebooted instead of resuming does not.
        Self::check_agent_version(&self.gen_record(sandbox_id, new_no)?, &out.agent_version)?;
        let probe = self.backend.probe(&handle).await?;
        if probe.state_digest != manifest.baseline_state_digest {
            return Err(AcfError::corrupt(
                "the restored guest does not reproduce the snapshot's baseline probe (state or disk differs, or the guest rebooted instead of resuming)",
            )
            .with_possible_side_effect());
        }
        self.ensure_within_deadline(op)?;

        // ---- the switch (RE-5): one commit makes the new generation current ----
        let mut ready = self.moved(&self.gen_record(sandbox_id, new_no)?, LifecycleState::Ready)?;
        ready.handle = Some(BackendHandle { process: None, ..handle });
        ready.process = Some(out.process.clone());
        ready.guest_agent_version = Some(out.agent_version.clone());
        let mut sb = self.sandbox_record(sandbox_id)?;
        sb.current = new_no;
        let mut snap = self.snapshot_record(&p.snapshot.snapshot_id, p.snapshot.snapshot_generation)?;
        snap.restore_count += 1;
        let mut notes = vec![
            format!("restore verified: guest state digest {}…", &probe.state_digest[..12.min(probe.state_digest.len())]),
            format!("guest entropy reseeded by the restore: {}", manifest.restore_reseeds_entropy),
        ];
        if snap.restore_count > 1 {
            notes.push(UNIQUENESS_NOTE.to_owned());
        }
        let old = plan.old_generation.map(|g| self.gen_record(sandbox_id, g)).transpose()?;
        let mut entries = vec![Entry::Generation(Box::new(ready)), Entry::Sandbox(sb), Entry::Snapshot(Box::new(snap))];
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
        op.step = Some("retire_old".into());
        op.state = OperationState::InProgress;
        op.updated_wall = self.wall();
        entries.push(Entry::Operation(Box::new(op.clone())));
        self.commit_for(op, entries)?;
        fault!(self, AfterBackendMutationBeforeCommit, "restore_switch");

        // ---- retire the superseded generation (its failure does not undo the restore) ----
        let mut tail = Vec::new();
        if let Some(o) = old_stopping {
            match self.retire(&o).await {
                Retired::Clean => tail.push(Entry::Generation(Box::new(self.destroyed(&o)?))),
                Retired::Quarantined(r) => {
                    notes.push(format!("the previous generation could not be cleaned up and was quarantined: {r}"));
                    tail.extend(self.quarantine(&o, &r));
                }
                Retired::Unclean(e) => notes
                    .push(format!("the previous generation could not be fully cleaned up yet ({}); the host will retire it", e.message)),
            }
        }
        self.telemetry.metrics.incr("restores", 1);
        self.finish(op, Outcome::succeeded(Some(json!({ "notes": notes }))), tail)
    }

    // ------------------------------------------------------------------ delete

    pub async fn snapshot_delete(&self, ctx: &Ctx, p: SnapshotDeleteParams) -> Result<OperationRecord> {
        // As for destroy: the profile switch governs callers, never an operator's containment.
        if ctx.issuer == Issuer::Peer && ctx.authority.role == Role::Caller {
            ctx.profile.authorize_snapshot_delete()?;
        }
        let r = p.snapshot;
        self.snapshot_for(ctx, &r)?;
        let depends = self.backend.capabilities().runtime_depends_on_snapshot;
        let spec = BeginSpec {
            op_type: OperationType::SnapshotDelete,
            target: r.snapshot_id.to_string(),
            expected_generation: Some(r.snapshot_generation),
            deadline_ms: self.cfg.operations.deadlines.delete_ms,
            run_id: None,
            sandbox: None,
            snapshot: Some(r.clone()),
        };
        let begun = self.begin(ctx, spec, |state| {
            let rec = state
                .snapshots
                .get(&(r.snapshot_id.clone(), r.snapshot_generation))
                .ok_or_else(|| AcfError::not_found("snapshot does not exist"))?;
            ctx.require_access(&rec.tags, &format!("snapshot {r}"))?;
            // RF-2: refused while a reference exists — a non-terminal operation that uses it (a
            // restore, a create still writing it, another delete), or a live generation whose
            // runtime still depends on its files.
            if let Some(o) = state.open_on_snapshot(&r).next() {
                return Err(AcfError::conflict(format!("the snapshot is referenced by `{}` in flight", o.operation_type)));
            }
            if depends && state.live_generations().any(|g| g.source_snapshot.as_ref() == Some(&r)) {
                return Err(AcfError::conflict("the snapshot is referenced by a live sandbox that was restored from it"));
            }
            if !rec.state.can_transition_to(SnapshotState::Deleted) && rec.state != SnapshotState::Deleted {
                return Err(AcfError::conflict(format!("snapshot is {:?}; it cannot be deleted right now", rec.state)));
            }
            Ok(vec![])
        })?;
        let (mut op, _guard) = match begun {
            Begun::New(o, g) => (*o, g),
            Begun::Existing(x) => return Ok(*x),
        };
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
            d.deleted_ms = d.deleted_ms.or(Some(self.clock.wall_ms()));
            self.finish(&mut op, Outcome::succeeded(None), vec![Entry::Snapshot(Box::new(d))])
        })();
        match res {
            Ok(()) => Ok(op),
            Err(e) if e.must_stop_silently() => Err(e),
            Err(e) => {
                // Files may be partly removed: the record stays, and the delete can be issued again.
                let info = FailureInfo::new(self.failure_of(&op, &e).class, e.message.clone(), SideEffect::Possible);
                let residue = Residue::Snapshot { snapshot: r.clone() };
                self.finish(&mut op, Outcome::failed(info, Some(residue)), vec![])?;
                Ok(op)
            }
        }
    }
}
