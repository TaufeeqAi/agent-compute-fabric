//! Applying recovery decisions (contract §16). The decisions themselves are the pure functions of
//! `recovery::decision`; this module observes, asks, and applies the answer as the one writer.
//!
//! * **Observe, don't assume** (FS-3). Decisions come from the store *and* what is on the host.
//! * **Never continue** (OP-18, INV-026). An inherited granting operation is undone to proven
//!   absence, or — for an execution — ended `UNKNOWN`. No step that creates privilege is issued
//!   here, no secret is resolved, no authority is checked (RC-9).
//! * **Never delete what ownership cannot prove is ours** (RC-2) — quarantine instead.
//! * **Bounded** (RC-4). Every record's attempt count is incremented durably *before* the attempt,
//!   so a record whose recovery crashes the core is quarantined after the bound, across restarts.
//! * **Before any endpoint opens** (RC-5), within `startup_recovery_deadline`.

use std::time::Duration;

use serde::Serialize;
use serde_json::json;

use super::{Host, Retired, ops::Outcome};
use crate::{
    api::QuarantineReleaseParams,
    backend::{IdentityCheckView, StopOutcome, VmmState},
    domain::{ContainmentReason, FailureInfo, LifecycleState, OperationState, OperationType, Residue, SnapshotState},
    error::{AcfError, FailureClass, Result, SideEffect},
    ids::{Generation, RecoveryId, SandboxId},
    recovery::decision::{Enforcement, ExecState, InheritedPlan, Observed, OnDisk, Runtime, decide_inherited},
    resources::lifetime::reanchor,
    storage::GenerationDir,
    store::{Entry, GenerationRecord, OperationRecord, QuarantineRecord, RecoveryRecord},
    telemetry::EventDraft,
};

#[derive(Debug, Default, Clone, Serialize)]
pub struct RecoveryReport {
    pub examined: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub unknown: usize,
    pub quarantined: usize,
    /// Containment left non-terminal on purpose: it is re-driven at the next sweep (OP-19).
    pub pending: usize,
    pub adopted: usize,
    pub contained: usize,
    pub retired_superseded: usize,
    /// Resources no record owns: reported, never modified (RC-3).
    pub unmanaged: usize,
    pub notes: Vec<String>,
}

/// What the ownership markers on disk say (LN-1 – LN-3).
#[derive(Debug, Default, Clone)]
pub struct MarkerScan {
    /// Highest creation sequence among markers of this store's lineage.
    pub newest_seq_of_this_lineage: u64,
    /// Directories with no record, another lineage's marker, or no valid marker.
    pub unmanaged: Vec<(String, Option<Generation>, String)>,
}

enum Resolution {
    Done {
        outcome: Outcome,
        entries: Vec<Entry>,
        label: &'static str,
    },
    /// The re-driven flow committed the operation's terminal record itself.
    Finished {
        label: &'static str,
    },
    /// The containment could not be completed now. The operation stays `RECOVERING`.
    Pending {
        note: String,
    },
}

fn partial(msg: impl Into<String>, possible: bool) -> FailureInfo {
    FailureInfo::new(FailureClass::PartialCompletion, msg, if possible { SideEffect::Possible } else { SideEffect::None })
}

impl Host {
    /// Startup recovery. Safe to call repeatedly. Returns without touching anything if the store
    /// cannot be written, or if it is older than the system it describes (LN-2).
    pub async fn recover(&self) -> Result<RecoveryReport> {
        let mut report = RecoveryReport::default();
        if let Some(block) = self.journal.write_block() {
            report.notes.push(format!("the store cannot be written; recovery takes no action it cannot record: {}", block.message()));
            return Ok(report);
        }
        let scan = self.scan_markers()?;
        if scan.newest_seq_of_this_lineage > self.store_seq_at_open {
            let why = format!(
                "an ownership marker on disk was created at commit {} but this store ends at {}: the store is older than the system it describes",
                scan.newest_seq_of_this_lineage, self.store_seq_at_open
            );
            report.notes.push(format!("{why}; no destructive action is taken until an operator issues `host.acknowledge`"));
            self.contain(ContainmentReason::StoreRegression(why));
            return Ok(report);
        }
        let done = self.recover_generations().await?;
        Ok(done)
    }

    /// Everything recovery does once the store is trusted: resolve inherited operations (Part A),
    /// then observe every generation once (Part B). Also run after `host.acknowledge`.
    pub async fn recover_generations(&self) -> Result<RecoveryReport> {
        let mut report = RecoveryReport::default();
        self.reanchor_expiries()?;
        let deadline = self.clock.after_ms(self.cfg.recovery.startup_deadline_ms);
        let epoch = self.journal.epoch();
        // The instance lock proves no other core is running, so every non-terminal operation of an
        // earlier activation is inherited: no deadline needs to elapse first.
        let mut ops: Vec<OperationRecord> = self.journal.read(|s| s.open().filter(|o| o.is_inherited(epoch)).cloned().collect())?;
        ops.sort_by(|a, b| a.revision.cmp(&b.revision).then_with(|| a.operation_id.cmp(&b.operation_id)));
        // Generations whose inherited operation was resolved here: they have been observed and
        // decided in this activation, so the deadline has nothing left to cut off for them.
        let mut resolved = std::collections::BTreeSet::new();
        for op in ops {
            report.examined += 1;
            let id = op.operation_id.clone();
            let late = self.clock.remaining_ns(&deadline).is_none();
            let about = op.sandbox.as_ref().map(|(sandbox, _)| sandbox.clone());
            match self.recover_op(op, late, &mut report).await {
                Ok(()) => resolved.extend(about),
                Err(e) if e.is_simulated_crash() => return Err(e),
                Err(e) => report.notes.push(format!("{id}: recovery error: {}", e.message)),
            }
        }
        let late = self.clock.remaining_ns(&deadline).is_none();
        self.sweep_generations(&mut report, late.then_some(&resolved)).await?;
        self.report_unmanaged(&mut report)?;
        self.telemetry.metrics.incr("recovery_runs", 1);
        self.telemetry.events.emit_simple(&self.wall(), "recovery.finished", json!(report));
        Ok(report)
    }

    /// LT-2: after a reboot, every expiry is re-expressed in the current boot. It can only shrink.
    fn reanchor_expiries(&self) -> Result<()> {
        let boot = self.clock.boot_id();
        let entries: Vec<Entry> = self.journal.read(|s| {
            s.sandboxes
                .values()
                .filter(|sb| sb.expiry.boot_id != boot && sb.destroyed_ms.is_none())
                .map(|sb| {
                    let last_known =
                        s.activations.iter().rev().find(|a| a.started_mono.boot_id == sb.expiry.boot_id).map(|a| a.started_mono.ns);
                    let mut sb = sb.clone();
                    sb.expiry = reanchor(self.clock.as_ref(), &sb.expiry, last_known);
                    Entry::Sandbox(sb)
                })
                .collect()
        })?;
        if !entries.is_empty() {
            self.journal.commit(entries)?;
        }
        Ok(())
    }

    /// The generation an inherited operation was working on, and whether a restore had switched.
    fn recovery_target(&self, op: &OperationRecord) -> Result<(Option<GenerationRecord>, bool)> {
        let switched = op.step.as_deref() == Some("retire_old");
        if op.operation_type == OperationType::QuarantineRelease {
            let g = SandboxId::parse(&op.target)
                .ok()
                .zip(op.expected_generation)
                .and_then(|(id, generation)| self.journal.read(|s| s.generations.get(&(id, generation)).cloned()).ok().flatten());
            return Ok((g, false));
        }
        let Some((sbx, _)) = op.sandbox.clone() else { return Ok((None, false)) };
        let g = self.journal.read(|s| {
            let sb = s.sandboxes.get(&sbx)?;
            let no = match op.operation_type {
                OperationType::SandboxCreate => Generation::FIRST,
                // Before the switch: the generation this restore allocated. After it: the current one.
                OperationType::SnapshotRestore => sb.last_generation,
                _ => sb.current,
            };
            s.generations.get(&(sbx.clone(), no)).cloned()
        })?;
        Ok((g, switched))
    }

    /// The ownership of `g`'s on-disk resources (RC-1, LN-3).
    fn observe_on_disk(&self, g: &GenerationRecord) -> OnDisk {
        let sbx_dir = match self.layout.sandboxes.open_dir(g.sandbox_id.as_str()) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return OnDisk::Absent,
            Err(e) => return OnDisk::NotOwned(format!("cannot open the sandbox directory: {e}")),
        };
        match sbx_dir.symlink_metadata(g.generation.to_string()) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return OnDisk::Absent,
            Err(e) => return OnDisk::NotOwned(format!("cannot stat the generation directory: {e}")),
            Ok(m) if m.file_type().is_symlink() || !m.is_dir() => {
                return OnDisk::NotOwned("generation path is a symlink or not a directory".into());
            }
            Ok(_) => {}
        }
        match GenerationDir::open(&self.layout, &g.sandbox_id, g.generation) {
            Ok(Some(d)) => match d.read_marker() {
                Ok(m) if m.lineage.as_deref().is_some_and(|l| l != self.journal.lineage()) => {
                    OnDisk::NotOwned("the ownership marker belongs to another store lineage".into())
                }
                Ok(m) if m.sandbox_id == g.sandbox_id && m.generation == g.generation && m.nonce == g.owner_nonce => OnDisk::Owned,
                Ok(_) => OnDisk::NotOwned("the ownership marker names a different sandbox, generation or nonce".into()),
                Err(e) => OnDisk::NotOwned(format!("the ownership marker is unreadable: {}", e.message)),
            },
            Ok(None) => OnDisk::Absent,
            Err(e) => OnDisk::NotOwned(e.message),
        }
    }

    /// What is actually on the host for `g` (never trusts the store alone). Every observation has a
    /// host deadline; one that cannot complete is `UNKNOWN` (OB-2). Nothing is written (OB-3).
    pub(crate) async fn observe_generation(&self, g: &GenerationRecord) -> Observed {
        let look = async {
            let mut h = g.backend_handle();
            if h.process.is_none()
                && let Ok(Some(p)) = self.backend.discover(&g.sandbox_ref()).await
            {
                h.process = Some(p);
            }
            self.backend.observe(&h).await
        };
        let timeout = Duration::from_millis(self.cfg.recovery.observe_timeout_ms);
        let (runtime, enforcement) = match tokio::time::timeout(timeout, look).await {
            Ok(Ok(o)) => {
                let enforcement = Self::enforcement_of(&o.enforcement);
                match (o.identity, o.vmm) {
                    (Some(IdentityCheckView::Mismatch(_)), _) => (Runtime::Foreign, Enforcement::NotApplicable),
                    (_, VmmState::Absent) => (Runtime::Absent, Enforcement::NotApplicable),
                    (_, VmmState::Running) => (Runtime::Present(ExecState::Running), enforcement),
                    (_, VmmState::Paused) => (Runtime::Present(ExecState::Paused), enforcement),
                    (_, VmmState::NotStarted) => (Runtime::Present(ExecState::NotStarted), enforcement),
                    (_, VmmState::Unknown(_)) => (Runtime::Unknown, Enforcement::Unknown),
                }
            }
            _ => (Runtime::Unknown, Enforcement::Unknown),
        };
        Observed { runtime, on_disk: self.observe_on_disk(g), enforcement }
    }

    pub(crate) async fn stop_quietly(&self, g: &GenerationRecord) -> bool {
        let mut h = g.backend_handle();
        if h.process.is_none() {
            h.process = self.backend.discover(&g.sandbox_ref()).await.ok().flatten();
        }
        let stopped = matches!(
            self.backend.stop(&h, Duration::from_millis(self.cfg.recovery.teardown_timeout_ms)).await,
            Ok(StopOutcome::Stopped | StopOutcome::AlreadyGone | StopOutcome::Refused(_))
        );
        if stopped {
            self.lifetime.disarm(&g.sandbox_ref().jail_id());
        }
        stopped
    }

    /// Resolve one inherited operation. `late`: the startup recovery deadline has passed, so what is
    /// not yet resolved is quarantined instead of worked on (RC-5).
    pub(crate) async fn recover_op(&self, mut op: OperationRecord, late: bool, report: &mut RecoveryReport) -> Result<()> {
        let (target, switched) = self.recovery_target(&op)?;
        let mut rec =
            op.recovery_id.as_ref().and_then(|id| self.journal.read(|s| s.recoveries.get(id).cloned()).ok().flatten()).unwrap_or_else(
                || RecoveryRecord {
                    recovery_id: RecoveryId::generate(),
                    operation: op.key(),
                    target: op.target.clone(),
                    generation: target.as_ref().map(|g| g.generation),
                    plan: String::new(),
                    observations: vec![],
                    actions: vec![],
                    attempt_count: 0,
                    outcome: None,
                    quarantine_reason: None,
                    updated_wall: self.wall(),
                },
            );
        // RC-4: count the attempt durably *before* making it.
        rec.attempt_count += 1;
        rec.updated_wall = self.wall();
        op.recovery_id = Some(rec.recovery_id.clone());
        op.state = OperationState::Recovering;
        op.updated_wall = self.wall();
        self.commit_for(&op, vec![Entry::Operation(Box::new(op.clone())), Entry::Recovery(rec.clone())])?;
        crate::coordinator::fault!(self, AfterJournalBeforeMutation, "recover");

        let obs = match &target {
            Some(g) => self.observe_generation(g).await,
            None => Observed { runtime: Runtime::Absent, on_disk: OnDisk::Absent, enforcement: Enforcement::NotApplicable },
        };
        rec.observations = vec![format!(
            "runtime={:?} on_disk={:?} enforcement={:?} generation_state={:?} switched={switched}",
            obs.runtime,
            obs.on_disk,
            obs.enforcement,
            target.as_ref().map(|g| g.state)
        )];
        let plan = if rec.attempt_count > self.cfg.recovery.max_attempts {
            InheritedPlan::Quarantine(format!(
                "recovery has already attempted this operation {} times without resolving it",
                rec.attempt_count - 1
            ))
        } else if late {
            InheritedPlan::Quarantine("the startup recovery deadline passed before this operation could be resolved".into())
        } else {
            decide_inherited(op.operation_type, &obs, switched)
        };
        rec.plan = format!("{plan:?}").chars().take(80).collect();

        match self.apply_inherited(&mut op, &plan, target).await? {
            Resolution::Pending { note } => {
                rec.actions.push(note);
                report.pending += 1;
                self.commit_for(&op, vec![Entry::Recovery(rec)])?;
            }
            Resolution::Finished { label } => {
                rec.outcome = Some(label.to_owned());
                match op.state {
                    OperationState::Succeeded => report.succeeded += 1,
                    OperationState::Unknown => report.unknown += 1,
                    _ => report.failed += 1,
                }
                self.telemetry.metrics.incr_labelled("recovery_outcomes", "plan", label, 1);
                // The operation is terminal, so this is not one of its writes: record the recovery alone.
                self.journal.commit(vec![Entry::Recovery(rec)])?;
            }
            Resolution::Done { outcome, mut entries, label } => {
                rec.outcome = Some(label.to_owned());
                if let InheritedPlan::Quarantine(r) = &plan {
                    rec.quarantine_reason = Some(r.clone());
                    report.quarantined += 1;
                }
                match outcome.state {
                    Some(OperationState::Succeeded) => report.succeeded += 1,
                    Some(OperationState::Unknown) => report.unknown += 1,
                    _ => report.failed += 1,
                }
                entries.push(Entry::Recovery(rec));
                self.telemetry.metrics.incr_labelled("recovery_outcomes", "plan", label, 1);
                self.telemetry
                    .events
                    .emit(EventDraft::new(&self.wall(), "recovery.operation").operation(&op).detail(json!({ "plan": label })));
                self.finish(&mut op, outcome, entries)?;
            }
        }
        Ok(())
    }

    async fn apply_inherited(
        &self,
        op: &mut OperationRecord,
        plan: &InheritedPlan,
        target: Option<GenerationRecord>,
    ) -> Result<Resolution> {
        let residue_of = |g: &GenerationRecord| Residue::Generation { sandbox_id: g.sandbox_id.clone(), generation: g.generation };
        match plan {
            InheritedPlan::Quarantine(reason) => {
                let failure = FailureInfo::new(FailureClass::Quarantined, reason.clone(), SideEffect::Possible);
                let (entries, residue) = match &target {
                    Some(g) => (self.quarantine(g, reason), Some(residue_of(g))),
                    None => (vec![], None),
                };
                // An execution whose effect cannot be established is UNKNOWN, quarantined or not.
                let outcome = if op.operation_type.is_execution() {
                    Outcome::unknown(failure, residue)
                } else {
                    Outcome::failed(failure, residue).quarantined()
                };
                Ok(Resolution::Done { outcome, entries, label: "QUARANTINED" })
            }
            InheritedPlan::Abandon => {
                let mut entries = vec![];
                if let Some(g) = target.as_ref().filter(|g| {
                    matches!(op.operation_type, OperationType::SandboxCreate | OperationType::SnapshotRestore)
                        && matches!(g.state, LifecycleState::Requested | LifecycleState::Provisioning)
                }) {
                    // Nothing was materialised: close the generation and release its lease.
                    let mut d = self.destroyed(g)?;
                    d.failure = Some(partial("abandoned before anything was created", false));
                    entries.extend(self.tombstone(self.sandbox_record(&g.sandbox_id).ok(), &d));
                    entries.push(Entry::Generation(Box::new(d)));
                }
                let failure = partial("the host restarted before this operation changed anything that remains", false);
                Ok(Resolution::Done { outcome: Outcome::failed(failure, None), entries, label: "ABANDONED" })
            }
            InheritedPlan::TearDownThenFail => {
                let g = target.ok_or_else(|| AcfError::internal("teardown plan without a generation"))?;
                let failure = partial("the host restarted mid-operation; what the operation had created was removed", false);
                match self.retire(&g).await {
                    Retired::Clean => {
                        let mut d = self.destroyed(&g)?;
                        d.failure = Some(failure.clone());
                        let mut entries = vec![];
                        entries.extend(self.tombstone(self.sandbox_record(&g.sandbox_id).ok(), &d));
                        entries.push(Entry::Generation(Box::new(d)));
                        Ok(Resolution::Done { outcome: Outcome::failed(failure, None), entries, label: "TORN_DOWN" })
                    }
                    Retired::Quarantined(r) => {
                        let f = self.failed_generation(&g, failure.clone())?;
                        let failure = FailureInfo::new(FailureClass::Quarantined, r.clone(), SideEffect::Possible);
                        Ok(Resolution::Done {
                            outcome: Outcome::failed(failure, Some(residue_of(&g))).quarantined(),
                            entries: self.quarantine(&f, &r),
                            label: "QUARANTINED",
                        })
                    }
                    Retired::Unclean(e) => {
                        // Not proven absent: the generation is FAILED and keeps its lease (LS-1).
                        let failure = partial(format!("what the operation created could not be removed yet: {}", e.message), true);
                        let f = self.failed_generation(&g, failure.clone())?;
                        Ok(Resolution::Done {
                            outcome: Outcome::failed(failure, Some(residue_of(&g))),
                            entries: vec![Entry::Generation(Box::new(f))],
                            label: "TEARDOWN_PENDING",
                        })
                    }
                }
            }
            InheritedPlan::StopRuntimeThenFail => {
                let g = target.ok_or_else(|| AcfError::internal("start plan without a generation"))?;
                let stopped = self.stop_quietly(&g).await;
                let failure =
                    partial("the host restarted while this sandbox was starting; a runtime never recorded READY is not trusted", !stopped);
                let mut f = self.failed_generation(&g, failure.clone())?;
                if stopped {
                    f.process = None;
                }
                Ok(Resolution::Done {
                    outcome: Outcome::failed(failure, Some(residue_of(&g))),
                    entries: vec![Entry::Generation(Box::new(f))],
                    label: "START_ABORTED",
                })
            }
            InheritedPlan::StopRuntimeUnknown => {
                let g = target.ok_or_else(|| AcfError::internal("exec plan without a generation"))?;
                let stopped = self.stop_quietly(&g).await;
                let failure = FailureInfo::new(
                    FailureClass::UnknownOutcome,
                    "the host restarted while the command was in flight; whether it ran, and with what result, cannot be established",
                    SideEffect::Possible,
                );
                let mut f = self.failed_generation(&g, failure.clone())?;
                if stopped {
                    f.process = None;
                }
                op.execution_started = true;
                Ok(Resolution::Done {
                    outcome: Outcome::unknown(failure, Some(residue_of(&g))),
                    entries: vec![Entry::Generation(Box::new(f))],
                    label: "UNKNOWN_EXECUTION",
                })
            }
            InheritedPlan::DiscardSnapshot => self.discard_snapshot(op).await,
            InheritedPlan::RetireSuperseded => {
                let g = target.ok_or_else(|| AcfError::internal("restore plan without a generation"))?;
                let (entries, notes) = self.retire_superseded(&g.sandbox_id, g.generation).await?;
                Ok(Resolution::Done { outcome: Outcome::succeeded(Some(json!({ "notes": notes }))), entries, label: "RESTORE_COMPLETED" })
            }
            InheritedPlan::Redrive => self.redrive(op, target).await,
        }
    }

    /// Retire every generation of `sandbox` other than `keep` that is not destroyed (RE-5).
    pub(crate) async fn retire_superseded(&self, sandbox: &SandboxId, keep: Generation) -> Result<(Vec<Entry>, Vec<String>)> {
        let (mut entries, mut notes) = (vec![], vec!["the retirement of the previous generation was completed by the host".to_owned()]);
        let stale: Vec<GenerationRecord> = self.journal.read(|s| {
            s.generations
                .values()
                .filter(|x| {
                    x.sandbox_id == *sandbox && x.generation != keep && x.state != LifecycleState::Destroyed && x.quarantined.is_none()
                })
                .cloned()
                .collect()
        })?;
        for old in stale {
            match self.retire(&old).await {
                Retired::Clean => entries.push(Entry::Generation(Box::new(self.destroyed(&old)?))),
                Retired::Quarantined(r) => {
                    notes.push(format!("previous generation {} quarantined: {r}", old.generation));
                    entries.extend(self.quarantine(&old, &r));
                }
                Retired::Unclean(e) => {
                    notes.push(format!("previous generation {} could not be removed yet: {}", old.generation, e.message))
                }
            }
        }
        Ok((entries, notes))
    }

    /// OP-19: an inherited containment operation is re-driven to completion. It is idempotent.
    async fn redrive(&self, op: &mut OperationRecord, target: Option<GenerationRecord>) -> Result<Resolution> {
        match op.operation_type {
            OperationType::SnapshotDelete => {
                let r = op.snapshot.clone().ok_or_else(|| AcfError::internal("delete operation without a snapshot"))?;
                self.snapshots.remove(&r.snapshot_id, r.snapshot_generation)?;
                let mut rec = self
                    .journal
                    .read(|s| s.snapshots.get(&(r.snapshot_id.clone(), r.snapshot_generation)).cloned())?
                    .ok_or_else(|| AcfError::not_found("snapshot record missing"))?;
                rec.state = SnapshotState::Deleted;
                rec.reserved_bytes = 0;
                rec.actual_bytes = 0;
                rec.deleted_ms = rec.deleted_ms.or(Some(self.clock.wall_ms()));
                Ok(Resolution::Done { outcome: Outcome::succeeded(None), entries: vec![Entry::Snapshot(Box::new(rec))], label: "REDRIVEN" })
            }
            OperationType::QuarantineRelease => {
                let (Some(g), Some(mode)) = (target, Self::release_mode_of(op.step.as_deref())) else {
                    // The assertion was never declared: nothing was done on its strength.
                    return Ok(Resolution::Done {
                        outcome: Outcome::failed(partial("the release had not started", false), None),
                        entries: vec![],
                        label: "ABANDONED",
                    });
                };
                let params = QuarantineReleaseParams { sandbox_id: g.sandbox_id.clone(), generation: g.generation, mode };
                // `release_body` observes again and commits the operation's terminal record itself.
                self.release_body(op, &params).await?;
                Ok(Resolution::Finished { label: "REDRIVEN" })
            }
            OperationType::SandboxStop => {
                let g = target.ok_or_else(|| AcfError::internal("stop operation without a generation"))?;
                if !self.stop_quietly(&g).await {
                    return Ok(Resolution::Pending { note: "the runtime could not be ended yet; the stop will be re-driven".into() });
                }
                let mut s = if g.state == LifecycleState::Stopping { self.moved(&g, LifecycleState::Stopped)? } else { g.clone() };
                s.process = None;
                Ok(Resolution::Done { outcome: Outcome::succeeded(None), entries: vec![Entry::Generation(Box::new(s))], label: "REDRIVEN" })
            }
            OperationType::SandboxFail => {
                let g = target.ok_or_else(|| AcfError::internal("fail operation without a generation"))?;
                let stopped = self.stop_quietly(&g).await;
                let mut f = self.failed_generation(&g, g.failure.clone().unwrap_or_else(|| partial("contained by the host", !stopped)))?;
                if stopped {
                    f.process = None;
                }
                Ok(Resolution::Done { outcome: Outcome::succeeded(None), entries: vec![Entry::Generation(Box::new(f))], label: "REDRIVEN" })
            }
            _ => {
                let g = target.ok_or_else(|| AcfError::internal("destroy operation without a generation"))?;
                // A destroy also removes whatever a restore it superseded had started to build.
                let (mut entries, _) = self.retire_superseded(&g.sandbox_id, g.generation).await?;
                match self.retire(&g).await {
                    Retired::Clean => {
                        let d = self.destroyed(&g)?;
                        entries.extend(self.tombstone(self.sandbox_record(&g.sandbox_id).ok(), &d));
                        entries.push(Entry::Generation(Box::new(d)));
                        Ok(Resolution::Done { outcome: Outcome::succeeded(None), entries, label: "REDRIVEN" })
                    }
                    Retired::Quarantined(r) => {
                        let failure = FailureInfo::new(FailureClass::Quarantined, r.clone(), SideEffect::Possible);
                        let residue = Residue::Generation { sandbox_id: g.sandbox_id.clone(), generation: g.generation };
                        entries.extend(self.quarantine(&g, &r));
                        Ok(Resolution::Done {
                            outcome: Outcome::failed(failure, Some(residue)).quarantined(),
                            entries,
                            label: "QUARANTINED",
                        })
                    }
                    Retired::Unclean(e) => {
                        if !entries.is_empty() {
                            self.commit_for(op, entries)?;
                        }
                        Ok(Resolution::Pending { note: format!("the destroy is incomplete and will be re-driven: {}", e.message) })
                    }
                }
            }
        }
    }

    /// An interrupted snapshot never produced a store-held manifest digest, so it cannot be adopted:
    /// return the guest to the state it was paused from, delete the partial files, release the quota.
    async fn discard_snapshot(&self, op: &OperationRecord) -> Result<Resolution> {
        let sref = op.snapshot.clone().ok_or_else(|| AcfError::internal("snapshot operation without a snapshot"))?;
        let mut entries = vec![];
        let mut failed_generation = None;
        if let Some((sbx, _)) = op.sandbox.clone()
            && let Some(g) =
                self.journal.read(|s| s.sandboxes.get(&sbx).and_then(|sb| s.generations.get(&(sbx.clone(), sb.current)).cloned()))?
            && g.state == LifecycleState::Paused
        {
            let mut h = g.backend_handle();
            h.process = h.process.or(self.backend.discover(&g.sandbox_ref()).await.ok().flatten());
            let running = match self.backend.observe(&h).await.map(|o| o.vmm) {
                Ok(VmmState::Running) => true,
                Ok(VmmState::Paused) => self.backend.resume(&h).await.is_ok(),
                _ => false,
            };
            if running {
                entries.push(Entry::Generation(Box::new(self.moved(&g, g.paused_from.unwrap_or(LifecycleState::Ready))?)));
            } else {
                let f = self.failed_generation(&g, partial("the guest could not be resumed after an interrupted snapshot", true))?;
                failed_generation = Some(Residue::Generation { sandbox_id: g.sandbox_id.clone(), generation: g.generation });
                entries.push(Entry::Generation(Box::new(f)));
            }
        }
        let cleaned = self.snapshots.remove(&sref.snapshot_id, sref.snapshot_generation).is_ok();
        if let Some(mut s) = self.journal.read(|s| s.snapshots.get(&(sref.snapshot_id.clone(), sref.snapshot_generation)).cloned())? {
            s.state = if cleaned { SnapshotState::Deleted } else { SnapshotState::Invalid };
            s.failure = Some(partial("snapshot creation was interrupted by a restart of the host", false));
            if cleaned {
                s.reserved_bytes = 0;
                s.actual_bytes = 0;
                s.deleted_ms = Some(self.clock.wall_ms());
            }
            entries.push(Entry::Snapshot(Box::new(s)));
        }
        let residue = if cleaned { failed_generation } else { Some(Residue::Snapshot { snapshot: sref }) };
        let failure = partial("snapshot creation was interrupted; no snapshot was produced", residue.is_some());
        Ok(Resolution::Done { outcome: Outcome::failed(failure, residue), entries, label: "SNAPSHOT_DISCARDED" })
    }

    /// Read every ownership marker under the state root (LN-1). Changes nothing.
    pub(crate) fn scan_markers(&self) -> Result<MarkerScan> {
        let known =
            self.journal.read(|s| s.generations.keys().map(|(id, g)| (id.clone(), *g)).collect::<std::collections::HashSet<_>>())?;
        let mut scan = MarkerScan::default();
        for sbx in self.layout.sandboxes.entries()?.flatten() {
            let Some(name) = sbx.file_name().to_str().map(str::to_owned) else { continue };
            let Ok(id) = SandboxId::parse(&name) else {
                scan.unmanaged.push((name, None, "entry under sandboxes/ is not a sandbox id".into()));
                continue;
            };
            let Ok(dir) = self.layout.sandboxes.open_dir(&name) else { continue };
            for gd in dir.entries()?.flatten() {
                let Some(generation) = gd.file_name().to_str().and_then(|s| s.parse::<u64>().ok()).map(Generation) else { continue };
                let marker = GenerationDir::open(&self.layout, &id, generation).ok().flatten().and_then(|d| d.read_marker().ok());
                let ours = marker.as_ref().and_then(|m| m.lineage.as_deref()) == Some(self.journal.lineage());
                if ours && let Some(seq) = marker.as_ref().and_then(|m| m.created_seq) {
                    scan.newest_seq_of_this_lineage = scan.newest_seq_of_this_lineage.max(seq);
                }
                if !known.contains(&(id.clone(), generation)) {
                    let why = match &marker {
                        None => "directory has no valid ownership marker",
                        Some(m) if m.lineage.is_some() && !ours => "directory carries the marker of another store lineage",
                        Some(_) => "directory has no record in the store",
                    };
                    scan.unmanaged.push((id.to_string(), Some(generation), why.to_owned()));
                }
            }
        }
        Ok(scan)
    }

    /// RC-3: a resource that no record owns is `UNMANAGED`. It is reported and **never modified**.
    fn report_unmanaged(&self, report: &mut RecoveryReport) -> Result<()> {
        let scan = self.scan_markers()?;
        let existing = self.journal.read(|s| s.quarantines.clone())?;
        let mut entries = vec![];
        for (resource_id, generation, reason) in scan.unmanaged {
            report.unmanaged += 1;
            if !existing.iter().any(|q| q.unmanaged && q.resource_id == resource_id && q.generation == generation && q.reason == reason) {
                entries.push(Entry::Quarantine(QuarantineRecord {
                    resource_id,
                    generation,
                    reason,
                    at_wall: self.wall(),
                    unmanaged: true,
                }));
            }
        }
        self.telemetry.metrics.set_gauge("unmanaged_resources_seen", i64::try_from(report.unmanaged).unwrap_or(i64::MAX));
        if !entries.is_empty() {
            self.journal.commit(entries)?;
        }
        Ok(())
    }
}
