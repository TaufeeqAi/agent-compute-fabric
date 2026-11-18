//! BEGIN / STEP / FINISH — the operation protocol (contract §11), exclusivity (§15) and the views
//! built from committed state.

use std::time::Duration;

use serde_json::Value;

use super::{Ctx, Host, TaskGuard, fault};
use crate::{
    api::{AsOf, OperationResult, OperationView, SandboxView, SnapshotView},
    clock::rfc3339_utc,
    domain::{
        CancelledBy, Cleanup, FailureInfo, LifecycleState, OperationClass, OperationState, OperationType, Residue, RunResult, SnapshotRef,
        SnapshotState, digest_label, require_transition, terminal_effect,
    },
    error::{AcfError, FailureClass, Result, SideEffect},
    ids::{Generation, RunId, SandboxId},
    storage::snapshots::check_compat,
    store::{Entry, GenerationRecord, JournalState, OpKey, OperationRecord, SandboxRecord, SnapshotRecord},
    telemetry::EventDraft,
};

pub(crate) struct BeginSpec {
    pub op_type: OperationType,
    /// `sbx-…`, `snp-…` or `host`.
    pub target: String,
    pub expected_generation: Option<Generation>,
    pub deadline_ms: u64,
    pub run_id: Option<RunId>,
    pub sandbox: Option<(SandboxId, Generation)>,
    pub snapshot: Option<SnapshotRef>,
}

pub(crate) enum Begun {
    /// BEGIN is durable. The guard keeps the operation registered as running until it is dropped.
    New(Box<OperationRecord>, TaskGuard),
    /// Same operation id **and** same fingerprint: the existing operation; nothing runs again.
    Existing(Box<OperationRecord>),
}

/// How an operation ends (the FINISH transaction, OP-5).
#[derive(Debug, Default)]
pub(crate) struct Outcome {
    pub state: Option<OperationState>,
    pub failure: Option<FailureInfo>,
    pub cleanup: Option<Cleanup>,
    pub residue: Option<Residue>,
    pub cancelled_by: Option<CancelledBy>,
    pub result: Option<Value>,
}

impl Outcome {
    pub(crate) fn succeeded(result: Option<Value>) -> Self {
        Self { state: Some(OperationState::Succeeded), result, ..Self::default() }
    }

    /// `FAILED`. `residue` names what the operation may have left behind; `None` means nothing.
    pub(crate) fn failed(failure: FailureInfo, residue: Option<Residue>) -> Self {
        let cleanup = if residue.is_some() { Cleanup::Pending } else { Cleanup::Complete };
        Self { state: Some(OperationState::Failed), failure: Some(failure), cleanup: Some(cleanup), residue, ..Self::default() }
    }

    pub(crate) fn unknown(failure: FailureInfo, residue: Option<Residue>) -> Self {
        Self { state: Some(OperationState::Unknown), failure: Some(failure), residue, ..Self::default() }
    }

    pub(crate) fn cancelled(by: CancelledBy, residue: Option<Residue>, result: Option<Value>) -> Self {
        let cleanup = if residue.is_some() { Cleanup::Pending } else { Cleanup::Complete };
        Self { state: Some(OperationState::Cancelled), cancelled_by: Some(by), cleanup: Some(cleanup), residue, result, ..Self::default() }
    }

    #[must_use]
    pub(crate) fn quarantined(mut self) -> Self {
        self.cleanup = Some(Cleanup::Quarantined);
        self
    }
}

/// CC-1: a sandbox has at most one granting operation in flight. A second is refused with
/// `STATE_CONFLICT` and leaves no record. Nothing is queued.
pub(crate) fn admit_granting(state: &JournalState, sandbox: &SandboxId) -> Result<()> {
    match state.open_on_sandbox(sandbox).next() {
        Some(o) => Err(AcfError::conflict(format!("sandbox {sandbox} is busy with `{}`", o.operation_type))),
        None => Ok(()),
    }
}

/// CC-3 / CC-4: a containment operation is refused only when containment of equal or greater
/// strength is already in flight. Everything weaker — every granting operation and every weaker
/// containment — is superseded: returned here, and ended in the caller's BEGIN commit.
pub(crate) fn admit_containment(state: &JournalState, sandbox: &SandboxId, mine: OperationType) -> Result<Vec<OperationRecord>> {
    let mut superseded = Vec::new();
    for o in state.open_on_sandbox(sandbox) {
        let theirs = o.operation_type;
        if theirs.class() != OperationClass::Granting && theirs.containment_strength() >= mine.containment_strength() {
            return Err(AcfError::conflict(format!(
                "`{theirs}` is already in flight on sandbox {sandbox}; it contains at least as much as `{mine}`"
            )));
        }
        superseded.push(o.clone());
    }
    Ok(superseded)
}

/// The terminal record of an operation that a containment operation supersedes (CC-3).
pub(crate) fn supersede(op: &OperationRecord, wall: &str, now_ms: i64) -> OperationRecord {
    let mut o = op.clone();
    o.state = OperationState::Cancelled;
    o.cancelled_by = Some(CancelledBy::Superseded);
    // What it was creating is now the containment operation's to remove. Until that is proven, the
    // cleanup is pending; reads derive the final answer from the residue's committed state.
    o.residue = match (o.operation_type, &o.sandbox, &o.snapshot) {
        (OperationType::SnapshotCreate, _, Some(s)) => Some(Residue::Snapshot { snapshot: s.clone() }),
        (_, Some((sandbox_id, generation)), _) => Some(Residue::Generation { sandbox_id: sandbox_id.clone(), generation: *generation }),
        _ => None,
    };
    o.cleanup = Some(if o.residue.is_some() { Cleanup::Pending } else { Cleanup::Complete });
    o.execution_started = o.execution_started || (o.operation_type.is_execution() && o.step.is_some());
    o.finished_ms = Some(now_ms);
    o.updated_wall = wall.to_owned();
    o
}

/// Everything a containment BEGIN commits for the operations it supersedes (CC-3), so that the
/// joint-state invariants hold after that very commit and not only once the containment has run:
///
/// * each superseded operation's terminal record;
/// * a snapshot that was still being written becomes `INVALID` (J-7);
/// * the generation a restore in place was building becomes `FAILED` (J-4).
///
/// The containment operation then removes them and commits what it observed.
pub(crate) fn supersede_entries(state: &JournalState, superseded: &[OperationRecord], wall: &str, now_ms: i64) -> Vec<Entry> {
    let why = || {
        FailureInfo::new(FailureClass::PartialCompletion, "superseded by a containment operation before it finished", SideEffect::Possible)
    };
    let mut entries = Vec::new();
    for op in superseded {
        entries.push(Entry::Operation(Box::new(supersede(op, wall, now_ms))));
        match op.operation_type {
            OperationType::SnapshotCreate => {
                let unfinished = op
                    .snapshot
                    .as_ref()
                    .and_then(|s| state.snapshots.get(&(s.snapshot_id.clone(), s.snapshot_generation)))
                    .filter(|s| matches!(s.state, SnapshotState::Requested | SnapshotState::Snapshotting | SnapshotState::Verifying));
                if let Some(snap) = unfinished {
                    let mut invalid = snap.clone();
                    invalid.state = SnapshotState::Invalid;
                    invalid.failure = Some(why());
                    entries.push(Entry::Snapshot(Box::new(invalid)));
                }
            }
            OperationType::SnapshotRestore => {
                let Some(sb) = op.sandbox.as_ref().and_then(|(id, _)| state.sandboxes.get(id)) else { continue };
                // Before the switch the generation being built is not the current one.
                let building = state.generations.values().filter(|g| {
                    g.sandbox_id == sb.sandbox_id
                        && g.generation != sb.current
                        && matches!(g.state, LifecycleState::Requested | LifecycleState::Provisioning)
                });
                for g in building {
                    let mut failed = g.clone();
                    failed.state = LifecycleState::Failed;
                    failed.failure = Some(why());
                    failed.updated_wall = wall.to_owned();
                    entries.push(Entry::Generation(Box::new(failed)));
                }
            }
            _ => {}
        }
    }
    entries
}

/// OP-7: `cleanup` of a failed or cancelled operation, as of committed state now.
pub(crate) fn derived_cleanup(state: &JournalState, op: &OperationRecord) -> Option<Cleanup> {
    if !matches!(op.state, OperationState::Failed | OperationState::Cancelled) {
        return None;
    }
    Some(match &op.residue {
        Some(Residue::Generation { sandbox_id, generation }) => match state.generations.get(&(sandbox_id.clone(), *generation)) {
            // A record that retention removed was a tombstone: the generation was destroyed.
            None => Cleanup::Complete,
            Some(g) if g.state == LifecycleState::Destroyed => Cleanup::Complete,
            Some(g) if g.quarantined.is_some() => Cleanup::Quarantined,
            Some(_) => Cleanup::Pending,
        },
        Some(Residue::Snapshot { snapshot }) => match state.snapshots.get(&(snapshot.snapshot_id.clone(), snapshot.snapshot_generation)) {
            None => Cleanup::Complete,
            Some(s) if s.state == SnapshotState::Deleted => Cleanup::Complete,
            Some(_) => Cleanup::Pending,
        },
        None => op.cleanup.unwrap_or(Cleanup::Complete),
    })
}

impl Host {
    pub(crate) fn deadline_remaining(&self, op: &OperationRecord) -> Option<Duration> {
        self.clock.remaining_ns(&op.deadline).map(Duration::from_nanos)
    }

    /// OP-15: a granting operation never ends `SUCCEEDED` after its deadline. Called immediately
    /// before the success FINISH; an error routes the operation into its failure path, which undoes it.
    pub(crate) fn ensure_within_deadline(&self, op: &OperationRecord) -> Result<()> {
        if self.deadline_remaining(op).is_some() {
            Ok(())
        } else {
            Err(AcfError::timeout(format!("`{}` did not finish within its deadline; it is being undone", op.operation_type))
                .with_possible_side_effect())
        }
    }

    /// BEGIN (OP-2). Atomically: resolve a duplicate, refuse a `retry` whose record is missing, run
    /// `precheck` (state, token, exclusivity, capacity → the entries the operation reserves) and
    /// record the operation `ACCEPTED`.
    pub(crate) fn begin(&self, ctx: &Ctx, spec: BeginSpec, precheck: impl FnOnce(&JournalState) -> Result<Vec<Entry>>) -> Result<Begun> {
        // Process death with the request accepted but nothing durable: recovery must find nothing.
        fault!(self, BeforeJournalWrite, spec.op_type.name());
        let now = self.clock.now_ref();
        let wall = self.wall();
        let key = ctx.key();
        let rec = OperationRecord {
            operation_id: ctx.operation_id.clone(),
            tags: ctx.tags(),
            on_behalf_of: ctx.authority.on_behalf_of.clone(),
            issuer: ctx.issuer,
            operation_type: spec.op_type,
            fingerprint: ctx.fingerprint.clone(),
            protocol: crate::api::PROTOCOL.to_owned(),
            target: spec.target,
            expected_generation: spec.expected_generation,
            issued_at: ctx.issued_at.clone(),
            created_wall: wall.clone(),
            created_ms: self.clock.wall_ms(),
            created_mono: now,
            deadline: self.clock.after_ms(spec.deadline_ms),
            profile_id: ctx.profile.id().clone(),
            epoch: self.journal.epoch(),
            state: OperationState::Accepted,
            step: None,
            cancelled_by: None,
            failure: None,
            cleanup: None,
            residue: None,
            execution_started: false,
            result: None,
            run_id: spec.run_id,
            sandbox: spec.sandbox,
            snapshot: spec.snapshot,
            recovery_id: None,
            finished_ms: None,
            updated_wall: wall,
            revision: 0,
        };
        let retry = ctx.retry;
        let fp = &ctx.fingerprint;
        let committed = self.journal.commit_with(|state| {
            if let Some(existing) = state.operations.get(&key) {
                return if existing.fingerprint == *fp {
                    Ok((vec![], None))
                } else {
                    Err(AcfError::new(
                        FailureClass::IdempotencyConflict,
                        format!("operation id {} was already used for a different request", key.operation_id),
                    ))
                };
            }
            if retry {
                return Err(AcfError::not_found(format!(
                    "operation {} is not known to this host; a retry is never treated as a new request",
                    key.operation_id
                )));
            }
            let mut entries = precheck(state)?;
            entries.insert(0, Entry::Operation(Box::new(rec.clone())));
            Ok((entries, Some(())))
        });
        let committed = match committed {
            Ok(c) => c,
            Err(e) => {
                self.check_store();
                return Err(e);
            }
        };
        // Read the record back: it now carries its revision, and an existing one its current state.
        let stored = self.operation_record(&key)?;
        match committed {
            None => Ok(Begun::Existing(Box::new(stored))),
            Some(()) => {
                let guard = self.tasks.register(key.clone());
                if let Some(tx) = &ctx.begun {
                    let _ = tx.send(Some(key));
                }
                self.telemetry.metrics.incr_labelled("operations_accepted", "type", stored.operation_type.name(), 1);
                self.telemetry.events.emit(EventDraft::new(&self.wall(), "operation.accepted").operation(&stored));
                Ok(Begun::New(Box::new(stored), guard))
            }
        }
    }

    /// Commit `entries` on behalf of `op`, **only if `op` still holds its sandbox** (CC-2): if a
    /// containment operation has ended it, nothing is written and the caller must stop.
    pub(crate) fn commit_for(&self, op: &OperationRecord, entries: Vec<Entry>) -> Result<()> {
        let key = op.key();
        let r = self.journal.commit_with(|state| match state.operations.get(&key) {
            Some(cur) if !cur.is_terminal() => Ok((entries, ())),
            Some(_) => Err(AcfError::superseded()),
            None => Err(AcfError::internal(format!("operation {key} has no record"))),
        });
        if r.is_err() {
            self.check_store();
        }
        r
    }

    /// STEP (OP-3): the name of a privileged step is durable before the step runs. If the process
    /// dies after this record, recovery knows the step *may* have run.
    pub(crate) fn step(&self, op: &mut OperationRecord, name: &str) -> Result<()> {
        op.step = Some(name.to_owned());
        op.state = OperationState::InProgress;
        op.updated_wall = self.wall();
        self.commit_for(op, vec![Entry::Operation(Box::new(op.clone()))])?;
        self.telemetry.events.emit(EventDraft::new(&self.wall(), "operation.step").operation(op));
        Ok(())
    }

    /// FINISH (OP-5): the terminal state and every lifecycle and lease change in **one** commit.
    pub(crate) fn finish(&self, op: &mut OperationRecord, outcome: Outcome, mut extra: Vec<Entry>) -> Result<()> {
        op.state = outcome.state.unwrap_or(OperationState::Failed);
        op.failure = outcome.failure;
        op.cleanup = outcome.cleanup;
        op.residue = outcome.residue;
        op.cancelled_by = outcome.cancelled_by;
        op.result = outcome.result;
        op.finished_ms = Some(self.clock.wall_ms());
        op.updated_wall = self.wall();
        extra.insert(0, Entry::Operation(Box::new(op.clone())));
        self.commit_for(op, extra)?;
        // Process death with the result durable but unsent: the caller resolves it by id (FS-5).
        fault!(self, AfterTerminalCommitBeforeResponse, op.operation_type.name());
        let m = &self.telemetry.metrics;
        m.incr_labelled("operations_finished", "state", &format!("{:?}", op.state), 1);
        if let Some(f) = &op.failure {
            m.incr_labelled("operation_failures", "class", &format!("{:?}", f.class), 1);
        }
        let latency = u64::try_from(self.clock.wall_ms().saturating_sub(op.created_ms)).unwrap_or(0);
        self.telemetry.events.emit(EventDraft::new(&self.wall(), "operation.finished").operation(op).latency_ms(latency));
        Ok(())
    }

    /// A generation record moved to `to`, with `PAUSED` bookkeeping. Validates the transition (§12.1).
    pub(crate) fn moved(&self, g: &GenerationRecord, to: LifecycleState) -> Result<GenerationRecord> {
        require_transition(g.state, to)?;
        let mut n = g.clone();
        n.paused_from = (to == LifecycleState::Paused).then_some(g.state);
        n.state = to;
        n.updated_wall = self.wall();
        Ok(n)
    }

    /// The shortest legal path from `g`'s state to `DESTROYED`, taken in one record.
    pub(crate) fn destroyed(&self, g: &GenerationRecord) -> Result<GenerationRecord> {
        let mut cur = g.clone();
        for _ in 0..4 {
            if cur.state == LifecycleState::Destroyed {
                break;
            }
            let next = if cur.state.can_transition_to(LifecycleState::Destroyed) {
                LifecycleState::Destroyed
            } else if cur.state == LifecycleState::Stopping {
                LifecycleState::Stopped
            } else {
                LifecycleState::Stopping
            };
            cur = self.moved(&cur, next)?;
        }
        cur.process = None;
        Ok(cur)
    }

    /// `g` as `FAILED` (or unchanged in state if it cannot move there), with `failure` attached.
    pub(crate) fn failed_generation(&self, g: &GenerationRecord, failure: FailureInfo) -> Result<GenerationRecord> {
        let mut f = if g.state.can_transition_to(LifecycleState::Failed) { self.moved(g, LifecycleState::Failed)? } else { g.clone() };
        f.failure = Some(failure);
        f.updated_wall = self.wall();
        Ok(f)
    }

    /// The sandbox and its current generation, for a mutation: tags (AU-9), token (CC-2) and
    /// quarantine (QR-1) are checked here, inside the commit that will reserve the state.
    pub(crate) fn target_in(
        state: &JournalState,
        ctx: &Ctx,
        id: &SandboxId,
        expected: Generation,
        if_revision: Option<u64>,
    ) -> Result<(SandboxRecord, GenerationRecord)> {
        let absent = || AcfError::not_found(format!("sandbox {id} does not exist"));
        let sb = state.sandboxes.get(id).ok_or_else(absent)?;
        ctx.require_access(&sb.tags, &format!("sandbox {id}"))?;
        if sb.current != expected {
            return Err(AcfError::revision(format!("sandbox {id} is at generation {}, not {expected} (stale token)", sb.current)));
        }
        let g = state.generations.get(&(id.clone(), expected)).ok_or_else(|| AcfError::internal("generation record missing"))?;
        // The revision a caller holds is the one a view reports: the later of the two records.
        let revision = sb.revision.max(g.revision);
        if let Some(want) = if_revision
            && want != revision
        {
            return Err(AcfError::revision(format!("sandbox {id} is at revision {revision}, not {want}")));
        }
        if g.quarantined.is_some() {
            return Err(AcfError::quarantined(format!(
                "sandbox {id} generation {expected} is quarantined; only `quarantine.release` is accepted"
            )));
        }
        Ok((sb.clone(), g.clone()))
    }

    pub(crate) fn operation_record(&self, key: &OpKey) -> Result<OperationRecord> {
        self.journal
            .read(|s| s.operations.get(key).cloned())?
            .ok_or_else(|| AcfError::not_found(format!("operation {} does not exist", key.operation_id)))
    }

    /// Direct lookup of one generation (no token check) for internal flows.
    pub(crate) fn gen_record(&self, id: &SandboxId, g: Generation) -> Result<GenerationRecord> {
        self.journal
            .read(|s| s.generations.get(&(id.clone(), g)).cloned())?
            .ok_or_else(|| AcfError::internal(format!("generation record {id}@{g} is missing")))
    }

    pub(crate) fn sandbox_record(&self, id: &SandboxId) -> Result<SandboxRecord> {
        self.journal.read(|s| s.sandboxes.get(id).cloned())?.ok_or_else(|| AcfError::internal(format!("sandbox record {id} is missing")))
    }

    // ------------------------------------------------------------------ views (API-7: from committed state)

    pub(crate) fn as_of(&self) -> AsOf {
        AsOf { lineage: self.journal.lineage().to_owned(), sequence: self.journal.last_seq() }
    }

    pub(crate) fn sandbox_view_in(&self, sb: &SandboxRecord, g: &GenerationRecord) -> SandboxView {
        let (secs, millis) = (sb.expiry.wall_ms.div_euclid(1000), sb.expiry.wall_ms.rem_euclid(1000));
        SandboxView {
            sandbox_id: g.sandbox_id.clone(),
            generation: g.generation,
            name: sb.name.clone(),
            state: g.state,
            resources: g.resources.clone(),
            image: g.image.clone(),
            tags: sb.tags.clone(),
            expires_at: rfc3339_utc(secs, u32::try_from(millis).unwrap_or(0) * 1_000_000),
            process: g.process().cloned(),
            security_profile_id: g.security_profile_id.clone(),
            last_run: g.last_run.clone(),
            source_snapshot: g.source_snapshot.clone(),
            failure: g.failure.clone(),
            quarantined: g.quarantined.clone(),
            secret_bearing: !g.secret_refs.is_empty(),
            notes: vec![],
            updated: g.updated_wall.clone(),
            revision: sb.revision.max(g.revision),
        }
    }

    pub(crate) fn snapshot_view(&self, s: &SnapshotRecord, incompatible: Vec<String>) -> SnapshotView {
        SnapshotView {
            snapshot: s.snapshot_ref(),
            name: s.name.clone(),
            state: s.state,
            tags: s.tags.clone(),
            size_bytes: if s.actual_bytes > 0 { s.actual_bytes } else { s.reserved_bytes },
            source_sandbox: s.source.clone(),
            manifest_digest: s.manifest_digest.as_deref().map(digest_label),
            restore_count: s.restore_count,
            secret_refs: s.secret_refs.iter().cloned().collect(),
            incompatible,
            created: s.created_wall.clone(),
            failure: s.failure.clone(),
            revision: s.revision,
        }
    }

    /// §21.6: why a `READY` snapshot cannot be restored on this host as it is now.
    pub(crate) fn snapshot_incompatibility(&self, s: &SnapshotRecord) -> Vec<String> {
        if s.state != SnapshotState::Ready {
            return vec![];
        }
        let Some(digest) = s.manifest_digest.as_deref() else { return vec!["the snapshot has no manifest digest".into()] };
        let manifest = self
            .snapshots
            .open(&s.snapshot_id, s.generation)
            .and_then(|d| d.ok_or_else(|| AcfError::corrupt("the snapshot's files are missing")))
            .and_then(|d| self.snapshots.read_verified_manifest(&d, digest));
        match manifest {
            Ok(m) => check_compat(&m, self.backend.identity(), &self.host_fp),
            Err(e) => vec![e.message],
        }
    }

    /// The operation as of committed state now (API-6), with `effect` and `cleanup` derived (§11.3).
    pub(crate) fn operation_view(&self, state: &JournalState, rec: &OperationRecord) -> OperationView {
        let cleanup = derived_cleanup(state, rec);
        let result = match rec.operation_type {
            OperationType::ExecRun => rec.result.as_ref().and_then(|v| serde_json::from_value::<RunResult>(v.clone()).ok()).map(|mut r| {
                self.hydrate_run(&mut r);
                OperationResult::Run(Box::new(r))
            }),
            OperationType::SnapshotCreate | OperationType::SnapshotDelete => rec
                .snapshot
                .as_ref()
                .and_then(|s| state.snapshots.get(&(s.snapshot_id.clone(), s.snapshot_generation)))
                .map(|s| OperationResult::Snapshot(self.snapshot_view(s, vec![]))),
            // Operations whose result is a statement by the host, not a sandbox or a snapshot.
            OperationType::ProfileReload
            | OperationType::HostSetMode
            | OperationType::HostAcknowledge
            | OperationType::OperationCancel
            | OperationType::QuarantineRelease => {
                rec.result.as_ref().and_then(|v| serde_json::from_value(v.clone()).ok()).map(OperationResult::Host)
            }
            _ => rec.sandbox.as_ref().and_then(|(id, _)| {
                // The sandbox as it is now: for a restore that is the new current generation.
                let sb = state.sandboxes.get(id)?;
                let g = state.generations.get(&(id.clone(), sb.current))?;
                let mut view = self.sandbox_view_in(sb, g);
                if let Some(notes) = rec.result.as_ref().and_then(|v| v.get("notes")).and_then(|n| serde_json::from_value(n.clone()).ok()) {
                    view.notes = notes;
                }
                Some(OperationResult::Sandbox(view))
            }),
        };
        OperationView {
            operation_id: rec.operation_id.clone(),
            operation_type: rec.operation_type,
            state: rec.state,
            effect: terminal_effect(rec.state, cleanup, rec.execution_started),
            cleanup,
            cancelled_by: rec.cancelled_by,
            issuer: rec.issuer,
            tags: rec.tags.clone(),
            on_behalf_of: rec.on_behalf_of.clone(),
            target: rec.target.clone(),
            step: rec.step.clone(),
            failure: rec.failure.clone(),
            result,
            run_id: rec.run_id.clone(),
            sandbox: rec.sandbox.clone(),
            snapshot: rec.snapshot.clone(),
            profile_id: rec.profile_id.clone(),
            activation_epoch: rec.epoch,
            issued_at: rec.issued_at.clone(),
            created: rec.created_wall.clone(),
            updated: rec.updated_wall.clone(),
            revision: rec.revision,
        }
    }

    /// Re-attach output that was spilled to the output store so operation records stay small.
    pub(crate) fn hydrate_run(&self, r: &mut RunResult) {
        use base64::{Engine, engine::general_purpose::STANDARD};
        for cap in [&mut r.stdout, &mut r.stderr] {
            if cap.data_b64.is_empty()
                && cap.kept_bytes > 0
                && let Some(a) = &cap.artifact
            {
                match self.artifacts.get(&a.artifact_id, cap.kept_bytes + 16) {
                    Ok((_, bytes)) => cap.data_b64 = STANDARD.encode(bytes),
                    Err(_) => r.note = Some(format!("{} | stored output is no longer available", r.note.clone().unwrap_or_default())),
                }
            }
        }
    }

    /// The failure of a step, as the operation reports it. A deadline that passed is `TIMEOUT`
    /// whatever the step's own error said (OP-15).
    pub(crate) fn failure_of(&self, op: &OperationRecord, e: &AcfError) -> FailureInfo {
        if op.operation_type.class() == OperationClass::Granting
            && self.deadline_remaining(op).is_none()
            && e.class != FailureClass::Timeout
        {
            return FailureInfo::new(FailureClass::Timeout, format!("deadline passed; last error: {}", e.message), SideEffect::Possible);
        }
        // A class that can only be a refusal (column `R` of §10.5) reached us after BEGIN. The
        // operation did fail, and "none of the above" is the one class that is always honest for it;
        // the message says what happened.
        let class = if e.class.can_fail_operation() { e.class } else { FailureClass::InternalError };
        FailureInfo::new(class, e.message.clone(), e.side_effect)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{Journal, fixtures, journal::tests::op};

    fn state(entries: Vec<Entry>) -> JournalState {
        let d = tempfile::tempdir().unwrap();
        let (j, _) = Journal::open(&d.path().join("j.wal")).unwrap();
        j.commit(entries).unwrap();
        j.read(Clone::clone).unwrap()
    }

    fn open_op(id: &str, ty: OperationType, sbx: &SandboxId) -> OperationRecord {
        let mut o = op(id, false);
        o.operation_type = ty;
        o.sandbox = Some((sbx.clone(), Generation::FIRST));
        o
    }

    #[test]
    fn a_second_granting_operation_is_refused_and_nothing_is_queued() {
        let sbx = SandboxId::generate();
        let other = SandboxId::generate();
        let s = state(vec![Entry::Operation(Box::new(open_op("op-exec0000", OperationType::ExecRun, &sbx)))]);
        assert_eq!(admit_granting(&s, &sbx).unwrap_err().class, FailureClass::StateConflict);
        assert!(admit_granting(&s, &other).is_ok(), "different sandboxes proceed concurrently (CC-6)");
        let mut done = open_op("op-exec0000", OperationType::ExecRun, &sbx);
        done.state = OperationState::Succeeded;
        assert!(admit_granting(&state(vec![Entry::Operation(Box::new(done))]), &sbx).is_ok(), "a terminal operation holds nothing");
    }

    #[test]
    fn containment_preempts_everything_weaker_and_is_refused_only_by_equal_or_stronger_containment() {
        use OperationType::*;
        let sbx = SandboxId::generate();
        let with = |ty| state(vec![Entry::Operation(Box::new(open_op("op-inflight", ty, &sbx)))]);
        for granting in [SandboxCreate, SandboxStart, ExecRun, SnapshotCreate, SnapshotRestore] {
            for mine in [SandboxFail, SandboxStop, SandboxDestroy] {
                let superseded = admit_containment(&with(granting), &sbx, mine).unwrap();
                assert_eq!(superseded.len(), 1, "{mine} must supersede {granting}");
            }
        }
        // (in flight, arriving, admitted?)
        let table = [
            (SandboxStop, SandboxStop, false),
            (SandboxStop, SandboxDestroy, true),
            (SandboxDestroy, SandboxStop, false),
            (SandboxDestroy, SandboxDestroy, false),
            (SandboxFail, SandboxStop, true),
            (SandboxFail, SandboxDestroy, true),
            (SandboxStop, SandboxFail, false),
            (QuarantineRelease, SandboxDestroy, false),
        ];
        for (theirs, mine, admitted) in table {
            assert_eq!(admit_containment(&with(theirs), &sbx, mine).is_ok(), admitted, "{mine} while {theirs} is in flight");
        }
        assert!(admit_containment(&state(vec![]), &sbx, SandboxDestroy).unwrap().is_empty());
    }

    #[test]
    fn a_superseded_operation_ends_cancelled_and_its_effect_is_not_claimed_absent() {
        let sbx = SandboxId::generate();
        let mut exec = open_op("op-exec0000", OperationType::ExecRun, &sbx);
        exec.step = Some("exec".into());
        let ended = supersede(&exec, "t", 5);
        assert_eq!((ended.state, ended.cancelled_by), (OperationState::Cancelled, Some(CancelledBy::Superseded)));
        assert!(ended.execution_started, "a command that was handed to the guest may have run");
        assert_eq!(terminal_effect(ended.state, ended.cleanup, ended.execution_started), Some(crate::domain::Effect::MayBeApplied));
        let create = supersede(&open_op("op-create00", OperationType::SandboxCreate, &sbx), "t", 5);
        assert_eq!(create.cleanup, Some(Cleanup::Pending), "what it was creating is not yet proven removed");
        assert!(matches!(create.residue, Some(Residue::Generation { .. })));
    }

    #[test]
    fn cleanup_is_derived_from_what_the_residue_is_now() {
        let mut g =
            fixtures::generation(crate::domain::Reservation { vcpus: 1, memory_mib: 1, disk_mib: 1, uid_slot: 0 }, LifecycleState::Failed);
        let mut failed = op("op-start000", true);
        failed.state = OperationState::Failed;
        failed.cleanup = Some(Cleanup::Pending);
        failed.residue = Some(Residue::Generation { sandbox_id: g.sandbox_id.clone(), generation: g.generation });

        let s = state(vec![Entry::Generation(Box::new(g.clone())), Entry::Operation(Box::new(failed.clone()))]);
        assert_eq!(derived_cleanup(&s, &failed), Some(Cleanup::Pending), "a FAILED generation remains and holds its lease");
        g.quarantined = Some("ownership".into());
        let s = state(vec![Entry::Generation(Box::new(g.clone())), Entry::Operation(Box::new(failed.clone()))]);
        assert_eq!(derived_cleanup(&s, &failed), Some(Cleanup::Quarantined));
        g.quarantined = None;
        g.state = LifecycleState::Destroyed;
        let s = state(vec![Entry::Generation(Box::new(g)), Entry::Operation(Box::new(failed.clone()))]);
        assert_eq!(derived_cleanup(&s, &failed), Some(Cleanup::Complete), "once the generation is destroyed the cleanup is complete");
        assert_eq!(derived_cleanup(&state(vec![]), &failed), Some(Cleanup::Complete), "a tombstone that retention removed was destroyed");
        assert_eq!(derived_cleanup(&s, &op("op-ok000000", true)), None, "a succeeded operation has no cleanup");
    }
}
