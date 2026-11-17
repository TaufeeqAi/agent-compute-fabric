//! Applying recovery decisions (spec §22). Everything here reuses the live flows' helpers.

use std::time::Duration;

use serde::Serialize;
use serde_json::json;

use super::classify::{DirObs, Observed, Plan, VmObs, classify};
use crate::{
    backend::{IdentityCheckView, StopOutcome, VmmState},
    domain::{FailureInfo, LifecycleState, OperationPhase, OperationStatus, OperationType, SnapshotState},
    error::{AcfError, FailureClass, Result, SideEffect},
    ids::{Generation, RecoveryId, SandboxId},
    lifecycle::{Host, Retired},
    operation::{Entry, GenerationRecord, OperationRecord, RecoveryRecord},
    protocol::ResponseBody,
};

#[derive(Debug, Default, Clone, Serialize)]
pub struct RecoveryReport {
    pub examined: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub unknown: usize,
    pub quarantined: usize,
    /// Left non-terminal on purpose (a retry on the next start is still within its bound).
    pub pending: usize,
    pub adopted: usize,
    pub retired_superseded: usize,
    pub orphans: usize,
    pub notes: Vec<String>,
}

#[allow(clippy::large_enum_variant, reason = "short-lived: built once per recovered operation; boxing would add noise, not savings")]
enum Resolution {
    Done {
        status: OperationStatus,
        failure: Option<FailureInfo>,
        body: Option<ResponseBody>,
        entries: Vec<Entry>,
        actions: Vec<String>,
        outcome: &'static str,
    },
    Pending {
        actions: Vec<String>,
    },
}

fn partial(msg: impl Into<String>, possible: bool) -> FailureInfo {
    FailureInfo {
        class: FailureClass::PartialCompletion,
        message: msg.into(),
        side_effect: if possible { SideEffect::Possible } else { SideEffect::None },
    }
}

impl Host {
    /// Resolve everything a crashed predecessor left behind. Safe to call repeatedly.
    pub async fn recover(&self) -> Result<RecoveryReport> {
        let mut report = RecoveryReport::default();
        if let Some(why) = self.journal.is_quarantined() {
            report.notes.push(format!("journal is quarantined; recovery performs no mutation: {why}"));
            return Ok(report);
        }
        // The single-writer lock proves no other host agent is running, so every non-terminal
        // operation is an orphan: no deadline needs to elapse first.
        let mut ops: Vec<OperationRecord> = self.journal.read(|s| s.operations.values().filter(|o| !o.is_terminal()).cloned().collect())?;
        ops.sort_by(|a, b| a.created_wall.cmp(&b.created_wall).then_with(|| a.operation_id.cmp(&b.operation_id)));
        for op in ops {
            report.examined += 1;
            let id = op.operation_id.clone();
            if let Err(e) = self.recover_op(op, &mut report).await {
                if e.is_simulated_crash() {
                    return Err(e);
                }
                report.notes.push(format!("{id}: recovery error: {}", e.message));
            }
        }
        self.reconcile_generations(&mut report).await?;
        self.scan_orphans(&mut report)?;
        self.telemetry.metrics.incr("recovery_runs", 1);
        self.telemetry.events.emit(&self.wall(), "recovery.finished", None, None, json!(report));
        Ok(report)
    }

    fn recovery_target(&self, op: &OperationRecord) -> Result<(Option<GenerationRecord>, bool)> {
        let Some((sbx, _)) = op.sandbox.clone() else { return Ok((None, false)) };
        let switched = matches!(&op.phase, OperationPhase::InProgress { step } if step == "retire_old");
        let g = self.journal.read(|s| {
            let sb = s.sandboxes.get(&sbx)?;
            let no = match op.operation_type {
                OperationType::SandboxCreate => Generation::FIRST,
                OperationType::SnapshotRestore => sb.last_generation, // the generation allocated by this restore
                _ => sb.current,
            };
            s.generations.get(&(sbx.clone(), no)).cloned()
        })?;
        Ok((g, switched))
    }

    /// What is actually on the host for `g` (never trusts the journal alone).
    pub(crate) async fn observe_for_recovery(&self, g: &GenerationRecord) -> Observed {
        let mut h = g.backend_handle();
        if h.process.is_none()
            && let Ok(Some(p)) = self.backend.discover(&g.sandbox_ref()).await
        {
            h.process = Some(p);
        }
        let vm = match self.backend.observe(&h).await {
            Ok(o) => match (o.identity, o.vmm) {
                (Some(IdentityCheckView::Mismatch(_)), _) => VmObs::Foreign,
                (_, VmmState::Absent) => VmObs::Absent,
                (_, VmmState::Running) => VmObs::Running,
                (_, VmmState::Paused) => VmObs::Paused,
                (_, VmmState::NotStarted) => VmObs::NotStarted,
                (_, VmmState::Unknown(_)) => VmObs::Unknown,
            },
            Err(_) => VmObs::Unknown,
        };
        let dir = (|| -> DirObs {
            let sbx_dir = match self.layout.sandboxes.open_dir(g.sandbox_id.as_str()) {
                Ok(d) => d,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return DirObs::Absent,
                Err(e) => return DirObs::NotOwned(format!("cannot open the sandbox directory: {e}")),
            };
            match sbx_dir.symlink_metadata(g.generation.to_string()) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return DirObs::Absent,
                Err(e) => return DirObs::NotOwned(format!("cannot stat the generation directory: {e}")),
                Ok(m) if m.file_type().is_symlink() || !m.is_dir() => {
                    return DirObs::NotOwned("generation path is a symlink or not a directory".into());
                }
                Ok(_) => {}
            }
            match crate::filesystem::GenerationDir::open(&self.layout, &g.sandbox_id, g.generation) {
                Ok(Some(d)) => match d.read_marker() {
                    Ok(m) if m.sandbox_id == g.sandbox_id && m.generation == g.generation && m.nonce == g.owner_nonce => DirObs::Owned,
                    Ok(_) => DirObs::NotOwned("OWNER marker names a different sandbox, generation or nonce".into()),
                    Err(e) => DirObs::NotOwned(format!("OWNER marker unreadable: {}", e.message)),
                },
                Ok(None) => DirObs::Absent,
                Err(e) => DirObs::NotOwned(e.message),
            }
        })();
        Observed { vm, dir }
    }

    fn path_to_destroyed(&self, g: &GenerationRecord) -> Result<GenerationRecord> {
        let mut cur = g.clone();
        for _ in 0..4 {
            if cur.state == LifecycleState::Destroyed {
                break;
            }
            if cur.state.can_transition_to(LifecycleState::Destroyed) {
                cur = self.moved(&cur, LifecycleState::Destroyed)?;
                break;
            }
            let next = if cur.state == LifecycleState::Stopping { LifecycleState::Stopped } else { LifecycleState::Stopping };
            cur = self.moved(&cur, next)?;
        }
        cur.process = None;
        Ok(cur)
    }

    async fn stop_quietly(&self, g: &GenerationRecord) -> bool {
        let mut h = g.backend_handle();
        if h.process.is_none() {
            h.process = self.backend.discover(&g.sandbox_ref()).await.ok().flatten();
        }
        matches!(
            self.backend.stop(&h, Duration::from_millis(self.cfg.recovery.teardown_timeout_ms)).await,
            Ok(StopOutcome::Stopped | StopOutcome::AlreadyGone | StopOutcome::Refused(_))
        )
    }

    async fn recover_op(&self, mut op: OperationRecord, report: &mut RecoveryReport) -> Result<()> {
        let (target, switched) = self.recovery_target(&op)?;
        let obs = match &target {
            Some(g) => self.observe_for_recovery(g).await,
            None => Observed { vm: VmObs::Absent, dir: DirObs::Absent },
        };
        let mut rec =
            op.recovery_id.as_ref().and_then(|id| self.journal.read(|s| s.recoveries.get(id).cloned()).ok().flatten()).unwrap_or_else(
                || RecoveryRecord {
                    recovery_id: RecoveryId::generate(),
                    operation_id: op.operation_id.clone(),
                    resource_id: op.resource_id.clone(),
                    generation: target.as_ref().map(|g| g.generation),
                    initial_classification: String::new(),
                    observations: vec![],
                    actions: vec![],
                    attempt_count: 0,
                    final_classification: None,
                    quarantine_reason: None,
                    updated_wall: self.wall(),
                },
            );
        rec.attempt_count += 1;
        rec.observations = vec![format!(
            "op={:?} vm={:?} dir={:?} generation_state={:?} switched={switched}",
            op.operation_type,
            obs.vm,
            obs.dir,
            target.as_ref().map(|g| g.state)
        )];
        let plan = if rec.attempt_count > self.cfg.recovery.max_attempts {
            Plan::Quarantine(format!("recovery has already touched this operation {} times without resolving it", rec.attempt_count - 1))
        } else {
            classify(
                op.operation_type,
                target.as_ref().map(|g| g.state),
                target.as_ref().is_some_and(|g| g.handle.is_some()),
                &obs,
                switched,
            )
        };
        rec.initial_classification = format!("{plan:?}").chars().take(60).collect();
        op.recovery_id = Some(rec.recovery_id.clone());
        rec.updated_wall = self.wall();

        match self.resolve(&op, &plan, target).await? {
            Resolution::Pending { actions } => {
                rec.actions.extend(actions);
                report.pending += 1;
                self.journal.commit(vec![Entry::Operation(Box::new(op)), Entry::Recovery(rec)])?;
            }
            Resolution::Done { status, failure, body, mut entries, actions, outcome } => {
                rec.actions.extend(actions);
                rec.final_classification = Some(outcome.to_owned());
                if let Plan::Quarantine(r) = &plan {
                    rec.quarantine_reason = Some(r.clone());
                    report.quarantined += 1;
                }
                match status {
                    OperationStatus::Succeeded => report.succeeded += 1,
                    OperationStatus::Unknown => report.unknown += 1,
                    _ => report.failed += 1,
                }
                entries.push(Entry::Recovery(rec));
                self.telemetry.events.emit(
                    &self.wall(),
                    "recovery.operation",
                    Some(op.operation_id.as_str()),
                    Some(&op.resource_id),
                    json!({"plan": outcome, "status": status}),
                );
                self.finish(&mut op, status, failure, body, entries)?;
            }
        }
        Ok(())
    }

    async fn resolve(&self, op: &OperationRecord, plan: &Plan, target: Option<GenerationRecord>) -> Result<Resolution> {
        let name_of =
            |g: &GenerationRecord| self.journal.read(|s| s.sandboxes.get(&g.sandbox_id).and_then(|x| x.name.clone())).ok().flatten();
        let mut actions = vec![];
        match plan {
            Plan::AbandonUntouched => {
                let mut entries = vec![];
                if let Some(g) = target.as_ref().filter(|g| {
                    matches!(op.operation_type, OperationType::SandboxCreate | OperationType::SnapshotRestore)
                        && matches!(g.state, LifecycleState::Requested | LifecycleState::Provisioning)
                }) {
                    // never provisioned: release the reservation by closing the generation
                    let mut d = self.moved(g, LifecycleState::Destroyed)?;
                    d.failure = Some(partial("abandoned by recovery before provisioning started", false));
                    entries.push(Entry::Generation(Box::new(d)));
                    actions.push("closed the never-provisioned generation and released its reservation".into());
                }
                Ok(Resolution::Done {
                    status: OperationStatus::Failed,
                    failure: Some(partial("the host agent restarted before this operation made progress; nothing was changed", false)),
                    body: None,
                    entries,
                    actions,
                    outcome: "ABANDONED_UNTOUCHED",
                })
            }
            Plan::CleanupThenFail => {
                let g = target.ok_or_else(|| AcfError::internal("cleanup plan without a generation"))?;
                match self.retire(&g).await {
                    Retired::Clean => {
                        let mut d = self.path_to_destroyed(&g)?;
                        d.failure = Some(partial("partial provisioning removed by recovery", false));
                        actions.push("stopped any VMM and removed the partial generation (ownership proven)".into());
                        Ok(Resolution::Done {
                            status: OperationStatus::Failed,
                            failure: Some(partial("the host agent restarted mid-operation; partial resources were removed", false)),
                            body: None,
                            entries: vec![Entry::Generation(Box::new(d))],
                            actions,
                            outcome: "CLEANED",
                        })
                    }
                    Retired::Quarantined(r) => {
                        let mut f = g.clone();
                        f.quarantined = Some(r.clone());
                        let f = if f.state.can_transition_to(LifecycleState::Failed) {
                            let mut x = self.moved(&f, LifecycleState::Failed)?;
                            x.quarantined = Some(r.clone());
                            x
                        } else {
                            f
                        };
                        actions.push(format!("ownership not provable; left in place: {r}"));
                        Ok(Resolution::Done {
                            status: OperationStatus::Unknown,
                            failure: Some(FailureInfo {
                                class: FailureClass::RecoveryQuarantined,
                                message: r.clone(),
                                side_effect: SideEffect::Possible,
                            }),
                            body: None,
                            entries: vec![
                                self.quarantine_entry(g.sandbox_id.as_str(), Some(g.generation), &r),
                                Entry::Generation(Box::new(f)),
                            ],
                            actions,
                            outcome: "QUARANTINED",
                        })
                    }
                    Retired::Unclean(e) => {
                        Ok(Resolution::Pending { actions: vec![format!("cleanup incomplete, will retry: {}", e.message)] })
                    }
                }
            }
            Plan::StopAndMarkFailed => {
                let g = target.ok_or_else(|| AcfError::internal("start plan without a generation"))?;
                let stopped = self.stop_quietly(&g).await;
                let mut f =
                    if g.state.can_transition_to(LifecycleState::Failed) { self.moved(&g, LifecycleState::Failed)? } else { g.clone() };
                f.failure = Some(partial("start interrupted by a host-agent restart; the VMM was stopped", !stopped));
                f.process = None;
                actions.push(format!("stopped the half-booted VMM (stopped={stopped})"));
                Ok(Resolution::Done {
                    status: if stopped { OperationStatus::Failed } else { OperationStatus::Unknown },
                    failure: Some(partial("the host agent restarted while this sandbox was starting", !stopped)),
                    body: None,
                    entries: vec![Entry::Generation(Box::new(f))],
                    actions,
                    outcome: "START_ABORTED",
                })
            }
            Plan::FailSafeUnknown => {
                let g = target.ok_or_else(|| AcfError::internal("exec plan without a generation"))?;
                let stopped = self.stop_quietly(&g).await;
                let mut f =
                    if g.state.can_transition_to(LifecycleState::Failed) { self.moved(&g, LifecycleState::Failed)? } else { g.clone() };
                f.failure = Some(partial(
                    "a run was in flight when the host agent restarted; the sandbox was stopped and must not be reused",
                    true,
                ));
                f.process = None;
                actions.push(format!("stopped the VMM (stopped={stopped}); the run's result cannot be known"));
                Ok(Resolution::Done {
                    status: OperationStatus::Unknown,
                    failure: Some(partial(
                        "the host agent restarted while the command was running; whether it ran, and with what result, cannot be known",
                        true,
                    )),
                    body: None,
                    entries: vec![Entry::Generation(Box::new(f))],
                    actions,
                    outcome: "UNKNOWN_RUN",
                })
            }
            Plan::RetryIdempotent => self.retry_idempotent(op, target, name_of).await,
            Plan::RetireSuperseded => {
                let g = target.ok_or_else(|| AcfError::internal("restore plan without a generation"))?;
                let (mut entries, mut notes) = (vec![], vec!["completed by recovery after a host-agent restart".to_owned()]);
                let stale: Vec<GenerationRecord> = self.journal.read(|s| {
                    s.generations
                        .values()
                        .filter(|x| x.sandbox_id == g.sandbox_id && x.generation != g.generation && x.state != LifecycleState::Destroyed)
                        .cloned()
                        .collect()
                })?;
                for old in stale {
                    match self.retire(&old).await {
                        Retired::Clean => {
                            entries.push(Entry::Generation(Box::new(self.path_to_destroyed(&old)?)));
                            actions.push(format!("retired superseded generation {}", old.generation));
                        }
                        Retired::Quarantined(r) => {
                            notes.push(format!("previous generation {} quarantined: {r}", old.generation));
                            entries.push(self.quarantine_entry(old.sandbox_id.as_str(), Some(old.generation), &r));
                        }
                        Retired::Unclean(e) => {
                            notes.push(format!("previous generation {} could not be cleaned: {}", old.generation, e.message))
                        }
                    }
                }
                let mut view = self.sandbox_view(&g, name_of(&g));
                view.notes = notes;
                Ok(Resolution::Done {
                    status: OperationStatus::Succeeded,
                    failure: None,
                    body: Some(ResponseBody::Sandbox(view)),
                    entries,
                    actions,
                    outcome: "COMPLETED_UNRECORDED",
                })
            }
            Plan::DiscardSnapshot => self.discard_snapshot(op).await,
            Plan::Quarantine(reason) => {
                let mut entries = vec![];
                if let Some(g) = target {
                    entries.push(self.quarantine_entry(g.sandbox_id.as_str(), Some(g.generation), reason));
                    let mut q = g.clone();
                    q.quarantined = Some(reason.clone());
                    entries.push(Entry::Generation(Box::new(q)));
                } else {
                    entries.push(self.quarantine_entry(&op.resource_id, None, reason));
                }
                actions.push("left every resource in place; flagged for an operator".into());
                Ok(Resolution::Done {
                    status: OperationStatus::Failed,
                    failure: Some(FailureInfo {
                        class: FailureClass::RecoveryQuarantined,
                        message: reason.clone(),
                        side_effect: SideEffect::Possible,
                    }),
                    body: None,
                    entries,
                    actions,
                    outcome: "QUARANTINED",
                })
            }
        }
    }

    async fn retry_idempotent(
        &self,
        op: &OperationRecord,
        target: Option<GenerationRecord>,
        name_of: impl Fn(&GenerationRecord) -> Option<String>,
    ) -> Result<Resolution> {
        let mut actions = vec![];
        match op.operation_type {
            OperationType::SnapshotDelete => {
                let r = op.snapshot.clone().ok_or_else(|| AcfError::internal("delete op without a snapshot ref"))?;
                self.snapshots.remove(&r.snapshot_id, r.snapshot_generation)?;
                let mut rec = self
                    .journal
                    .read(|s| s.snapshots.get(&(r.snapshot_id.clone(), r.snapshot_generation)).cloned())?
                    .ok_or_else(|| AcfError::not_found("snapshot record missing"))?;
                rec.state = SnapshotState::Deleted;
                rec.reserved_bytes = 0;
                rec.actual_bytes = 0;
                actions.push("completed the snapshot deletion".into());
                let view = self.snapshot_view(&rec);
                Ok(Resolution::Done {
                    status: OperationStatus::Succeeded,
                    failure: None,
                    body: Some(ResponseBody::Snapshot(view)),
                    entries: vec![Entry::Snapshot(Box::new(rec))],
                    actions,
                    outcome: "COMPLETED_UNRECORDED",
                })
            }
            OperationType::SandboxStop => {
                let g = target.ok_or_else(|| AcfError::internal("stop op without a generation"))?;
                if !self.stop_quietly(&g).await {
                    return Ok(Resolution::Pending { actions: vec!["VMM could not be stopped yet; will retry".into()] });
                }
                let mut s = if g.state == LifecycleState::Stopping { self.moved(&g, LifecycleState::Stopped)? } else { g.clone() };
                s.process = None;
                actions.push("completed the interrupted stop".into());
                let view = self.sandbox_view(&s, name_of(&s));
                Ok(Resolution::Done {
                    status: OperationStatus::Succeeded,
                    failure: None,
                    body: Some(ResponseBody::Sandbox(view)),
                    entries: vec![Entry::Generation(Box::new(s))],
                    actions,
                    outcome: "COMPLETED_UNRECORDED",
                })
            }
            _ => {
                let g = target.ok_or_else(|| AcfError::internal("destroy op without a generation"))?;
                match self.retire(&g).await {
                    Retired::Clean => {
                        let d = self.path_to_destroyed(&g)?;
                        actions.push("completed the interrupted destroy".into());
                        let view = self.sandbox_view(&d, name_of(&d));
                        Ok(Resolution::Done {
                            status: OperationStatus::Succeeded,
                            failure: None,
                            body: Some(ResponseBody::Sandbox(view)),
                            entries: vec![Entry::Generation(Box::new(d))],
                            actions,
                            outcome: "COMPLETED_UNRECORDED",
                        })
                    }
                    Retired::Quarantined(r) => {
                        let mut q = g.clone();
                        q.quarantined = Some(r.clone());
                        actions.push(format!("ownership not provable; left in place: {r}"));
                        Ok(Resolution::Done {
                            status: OperationStatus::Failed,
                            failure: Some(FailureInfo {
                                class: FailureClass::RecoveryQuarantined,
                                message: r.clone(),
                                side_effect: SideEffect::Possible,
                            }),
                            body: None,
                            entries: vec![
                                self.quarantine_entry(g.sandbox_id.as_str(), Some(g.generation), &r),
                                Entry::Generation(Box::new(q)),
                            ],
                            actions,
                            outcome: "QUARANTINED",
                        })
                    }
                    Retired::Unclean(e) => {
                        Ok(Resolution::Pending { actions: vec![format!("destroy incomplete, will retry: {}", e.message)] })
                    }
                }
            }
        }
    }

    /// An interrupted snapshot never produced a journal-bound manifest, so it cannot be adopted:
    /// bring the guest back to a usable state, delete the partial artifacts, release the quota.
    async fn discard_snapshot(&self, op: &OperationRecord) -> Result<Resolution> {
        let sref = op.snapshot.clone().ok_or_else(|| AcfError::internal("snapshot op without a snapshot ref"))?;
        let mut actions = vec![];
        let mut entries = vec![];
        let mut vm_ok = true;
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
            vm_ok = running;
            let back = g.paused_from.unwrap_or(LifecycleState::Ready);
            entries.push(Entry::Generation(Box::new(self.moved(&g, if running { back } else { LifecycleState::Failed })?)));
            actions.push(format!(
                "guest {}",
                if running { "resumed and returned to its prior state" } else { "could not be resumed; marked FAILED" }
            ));
        }
        let cleaned = self.snapshots.remove(&sref.snapshot_id, sref.snapshot_generation).is_ok();
        if let Some(mut s) = self.journal.read(|s| s.snapshots.get(&(sref.snapshot_id.clone(), sref.snapshot_generation)).cloned())? {
            s.state = if cleaned { SnapshotState::Deleted } else { SnapshotState::Invalid };
            s.failure = Some(partial("snapshot creation was interrupted by a host-agent restart", false));
            if cleaned {
                s.reserved_bytes = 0;
                s.actual_bytes = 0;
            }
            entries.push(Entry::Snapshot(Box::new(s)));
        }
        actions.push(format!("partial snapshot artifacts removed={cleaned}"));
        Ok(Resolution::Done {
            status: if cleaned && vm_ok { OperationStatus::Failed } else { OperationStatus::Unknown },
            failure: Some(partial("snapshot creation was interrupted; no snapshot was produced", !(cleaned && vm_ok))),
            body: None,
            entries,
            actions,
            outcome: "SNAPSHOT_DISCARDED",
        })
    }

    /// Sweep every generation: adopt healthy survivors, fail the ones whose VMM vanished, retire
    /// superseded leftovers, and never leave a VMM running for a generation that should not have one.
    async fn reconcile_generations(&self, report: &mut RecoveryReport) -> Result<()> {
        let gens: Vec<GenerationRecord> =
            self.journal.read(|s| s.generations.values().filter(|g| g.state != LifecycleState::Destroyed).cloned().collect())?;
        for g in gens {
            let current = self.journal.read(|s| s.sandboxes.get(&g.sandbox_id).map(|sb| sb.current))?;
            let is_current = current == Some(g.generation);
            let res: Result<()> = async {
                if !is_current {
                    // A superseded generation (restore switched, crash before retirement).
                    if let Retired::Clean = self.retire(&g).await {
                        self.commit_gen(&self.path_to_destroyed(&g)?)?;
                        report.retired_superseded += 1;
                    }
                    return Ok(());
                }
                let mark_failed = |reason: &str| -> Result<()> {
                    let mut f =
                        if g.state.can_transition_to(LifecycleState::Failed) { self.moved(&g, LifecycleState::Failed)? } else { g.clone() };
                    f.failure = Some(partial(reason.to_owned(), false));
                    f.process = None;
                    self.commit_gen(&f)
                };
                match g.state {
                    LifecycleState::Ready | LifecycleState::Completed => {
                        let mut h = g.backend_handle();
                        if h.process.is_none() {
                            h.process = self.backend.discover(&g.sandbox_ref()).await?;
                        }
                        let o = self.backend.observe(&h).await?;
                        let matched = matches!(o.identity, Some(IdentityCheckView::Match));
                        match o.vmm {
                            VmmState::Running if matched => {
                                // Adopt only what still satisfies the security profile.
                                let bad = o.posture.as_ref().map(|p| p.violations(h.uid)).filter(|v| !v.is_empty());
                                if let Some(v) = bad {
                                    self.stop_quietly(&g).await;
                                    self.telemetry.metrics.incr("security_control_failures", 1);
                                    mark_failed(&format!("surviving VMM no longer satisfies the security profile: {}", v.join("; ")))?;
                                } else {
                                    report.adopted += 1;
                                }
                            }
                            VmmState::Absent => mark_failed("the VMM disappeared while the host agent was not running")?,
                            _ => {
                                self.stop_quietly(&g).await;
                                mark_failed("the VMM's state could not be verified after a host-agent restart; it was stopped")?;
                            }
                        }
                    }
                    LifecycleState::Running | LifecycleState::Paused => {
                        // No operation owns this state any more: anomaly ⇒ fail safe.
                        self.stop_quietly(&g).await;
                        mark_failed("no operation owns this transient state after a restart; the sandbox was stopped")?;
                    }
                    LifecycleState::Stopping => {
                        if self.stop_quietly(&g).await {
                            let mut s = self.moved(&g, LifecycleState::Stopped)?;
                            s.process = None;
                            self.commit_gen(&s)?;
                        }
                    }
                    LifecycleState::Stopped | LifecycleState::Failed => {
                        // The record says there is no VMM; make that true.
                        if g.process().is_some() || self.backend.discover(&g.sandbox_ref()).await?.is_some() {
                            self.stop_quietly(&g).await;
                            report.notes.push(format!("stopped a stray VMM for {}@{}", g.sandbox_id, g.generation));
                        }
                    }
                    LifecycleState::Requested | LifecycleState::Provisioning | LifecycleState::Destroyed => {}
                }
                Ok(())
            }
            .await;
            if let Err(e) = res {
                if e.is_simulated_crash() {
                    return Err(e);
                }
                report.notes.push(format!("{}@{}: reconcile error: {}", g.sandbox_id, g.generation, e.message));
            }
        }
        Ok(())
    }

    /// Directories under `sandboxes/` that no journal record accounts for. They are *reported and
    /// quarantined, never deleted*: with no record there is no ownership proof.
    fn scan_orphans(&self, report: &mut RecoveryReport) -> Result<()> {
        let known =
            self.journal.read(|s| s.generations.keys().map(|(id, g)| (id.clone(), *g)).collect::<std::collections::HashSet<_>>())?;
        let existing_q = self.journal.read(|s| s.quarantines.clone())?;
        let mut entries = vec![];
        for sbx in self.layout.sandboxes.entries()?.flatten() {
            let Some(name) = sbx.file_name().to_str().map(str::to_owned) else { continue };
            let Ok(id) = SandboxId::parse(&name) else {
                report.notes.push(format!("ignored unexpected entry `{name}` under sandboxes/"));
                continue;
            };
            let Ok(dir) = self.layout.sandboxes.open_dir(&name) else { continue };
            for gd in dir.entries()?.flatten() {
                let Some(g) = gd.file_name().to_str().and_then(|s| s.parse::<u64>().ok()).map(Generation) else { continue };
                if !known.contains(&(id.clone(), g)) {
                    let reason = "directory has no journal record; ownership cannot be proven".to_owned();
                    if !existing_q.iter().any(|q| q.resource_id == id.as_str() && q.generation == Some(g) && q.reason == reason) {
                        entries.push(self.quarantine_entry(id.as_str(), Some(g), &reason));
                    }
                    report.orphans += 1;
                }
            }
        }
        if !entries.is_empty() {
            self.journal.commit(entries)?;
        }
        Ok(())
    }
}
