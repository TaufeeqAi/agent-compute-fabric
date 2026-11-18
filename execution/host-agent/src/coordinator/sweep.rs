//! The sweep (contract RC-6, IS-3, LT-3, PS-10): what the host does on its own initiative.
//!
//! Every pass observes each generation that no operation holds and asks the pure decision table
//! (§16.2 Part B) what to do. Whatever it answers is applied as a **host-issued containment
//! operation** (OP-24, OP-25): it has a record, an identity and the same exclusivity as any other,
//! and it is applied only if the generation is still the one, and in the state, that was observed
//! (RC-7). The sweep never starts, resumes or repairs anything.
//!
//! The same pass re-drives containment an earlier activation left unfinished (OP-19), ends sandboxes
//! at their expiry (LT-3), applies retention (PS-10, OU-4) and refreshes the host's own health: the
//! lifetime enforcer's heartbeat (PD-4) and the store's reserve (PS-9).

use std::{sync::Arc, time::Duration};

use serde_json::json;
use tokio_util::sync::CancellationToken;

use super::{
    Host,
    ops::{BeginSpec, Begun, Outcome, admit_containment, supersede_entries},
    recover::RecoveryReport,
};
use crate::{
    api::SandboxTarget,
    domain::{ContainmentReason, FailureInfo, LifecycleState, OperationType, Tags, fingerprint::fingerprint},
    error::{AcfError, FailureClass, Result, SideEffect},
    ids::{Generation, SandboxId},
    recovery::decision::{IdleFacts, IdlePlan, decide_idle},
    resources::lifetime::is_expired,
    store::{Entry, ForgetRecord, GenerationRecord, OperationRecord},
};

#[derive(Debug, Default)]
pub struct SweepState {
    /// Wall-clock time of the last pass that observed every generation.
    pub last_complete_ms: Option<i64>,
    last_retention_ms: i64,
}

const ENFORCER_DOWN: &str = "the lifetime enforcer is not reporting; a runtime launched now could outlive its expiry";

impl Host {
    fn target(g: &GenerationRecord) -> SandboxTarget {
        SandboxTarget { sandbox_id: g.sandbox_id.clone(), expected_generation: g.generation, if_revision: None }
    }

    fn host_op_ctx(
        &self,
        tags: &Tags,
        op_type: OperationType,
        sandbox: &SandboxId,
        generation: Generation,
        why: &str,
    ) -> Result<super::Ctx> {
        let params = json!({ "sandbox_id": sandbox, "expected_generation": generation, "reason": why });
        Ok(self.host_ctx(tags, fingerprint(op_type, &params)?))
    }

    /// RC-4: count an attempt on `g` durably, before making it.
    fn count_attempt(&self, g: &GenerationRecord) -> Result<()> {
        let key = (g.sandbox_id.clone(), g.generation);
        self.journal.commit_with(|s| {
            let Some(cur) = s.generations.get(&key).filter(|c| c.state == g.state && c.quarantined.is_none()) else {
                return Ok((vec![], ()));
            };
            let mut n = cur.clone();
            n.observe_attempts += 1;
            Ok((vec![Entry::Generation(Box::new(n))], ()))
        })
    }

    /// A host-issued operation that only changes records: quarantine a generation, or retire the
    /// generations a restore superseded. `apply` runs after BEGIN and returns the FINISH entries.
    async fn host_operation<F, Fut>(&self, tags: &Tags, g: &GenerationRecord, why: &str, apply: F) -> Result<OperationRecord>
    where
        F: FnOnce(OperationRecord) -> Fut,
        Fut: std::future::Future<Output = Result<Vec<Entry>>>,
    {
        let ctx = self.host_op_ctx(tags, OperationType::SandboxFail, &g.sandbox_id, g.generation, why)?;
        let spec = BeginSpec {
            op_type: OperationType::SandboxFail,
            target: g.sandbox_id.to_string(),
            expected_generation: Some(g.generation),
            deadline_ms: self.cfg.operations.deadlines.stop_ms,
            run_id: None,
            sandbox: Some((g.sandbox_id.clone(), g.generation)),
            snapshot: None,
        };
        let observed = g.state;
        let mut superseded = vec![];
        let begun = self.begin(&ctx, spec, |state| {
            // RC-7: only if the generation and its state are those that were observed.
            let cur =
                state.generations.get(&(g.sandbox_id.clone(), g.generation)).ok_or_else(|| AcfError::not_found("generation is gone"))?;
            if cur.state != observed || cur.quarantined.is_some() {
                return Err(AcfError::conflict("the generation changed since it was observed"));
            }
            superseded = admit_containment(state, &g.sandbox_id, OperationType::SandboxFail)?;
            Ok(supersede_entries(state, &superseded, &self.wall(), self.clock.wall_ms()))
        })?;
        let (mut op, _guard) = match begun {
            Begun::New(o, guard) => (*o, guard),
            Begun::Existing(r) => return Ok(*r),
        };
        self.preempt(&superseded).await;
        match apply(op.clone()).await {
            Ok(entries) => self.finish(&mut op, Outcome::succeeded(Some(json!({ "notes": [why] }))), entries)?,
            Err(e) if e.must_stop_silently() => return Err(e),
            Err(e) => {
                let info = self.failure_of(&op, &e);
                self.finish(&mut op, Outcome::failed(info, None), vec![])?;
            }
        }
        Ok(op)
    }

    /// Apply the plan for one generation. Errors are reported, never propagated: one generation the
    /// host cannot contain must not stop it from containing the next.
    async fn apply_idle(&self, tags: &Tags, g: &GenerationRecord, plan: IdlePlan, report: &mut RecoveryReport) {
        let res: Result<()> = async {
            match plan {
                IdlePlan::NoChange => {
                    if g.state.is_idle() {
                        report.adopted += 1;
                    }
                    if g.observe_attempts > 0 && g.quarantined.is_none() {
                        // A complete observation ends the run of failed ones.
                        let mut n = g.clone();
                        n.observe_attempts = 0;
                        self.journal.commit(vec![Entry::Generation(Box::new(n))])?;
                    }
                }
                IdlePlan::Retry => self.count_attempt(g)?,
                IdlePlan::MarkFailed(why) => {
                    let ctx = self.host_op_ctx(tags, OperationType::SandboxFail, &g.sandbox_id, g.generation, &why)?;
                    let failure = FailureInfo::new(FailureClass::DependencyUnavailable, why, SideEffect::None);
                    self.sandbox_fail(&ctx, Self::target(g), failure, false).await?;
                    self.telemetry.metrics.incr("runtime_losses_detected", 1);
                    report.contained += 1;
                }
                IdlePlan::StopDegraded(why) => {
                    // IS-3: a control that is no longer in force. No repair in place.
                    self.telemetry.metrics.incr("posture_failures_after_launch", 1);
                    self.telemetry.metrics.incr("security_control_failures", 1);
                    self.count_attempt(g)?;
                    let ctx = self.host_op_ctx(tags, OperationType::SandboxFail, &g.sandbox_id, g.generation, &why)?;
                    let failure = FailureInfo::new(
                        FailureClass::SecurityControlFailure,
                        format!("a mandatory isolation control is no longer in force: {why}"),
                        SideEffect::None,
                    );
                    self.sandbox_fail(&ctx, Self::target(g), failure, true).await?;
                    report.contained += 1;
                }
                IdlePlan::StopStray => {
                    self.count_attempt(g)?;
                    let why = "a runtime existed for a generation whose record says it has none; it was ended";
                    let ctx = self.host_op_ctx(tags, OperationType::SandboxFail, &g.sandbox_id, g.generation, why)?;
                    let failure =
                        g.failure.clone().unwrap_or_else(|| FailureInfo::new(FailureClass::PartialCompletion, why, SideEffect::None));
                    self.sandbox_fail(&ctx, Self::target(g), failure, true).await?;
                    report.contained += 1;
                }
                IdlePlan::Destroy => {
                    // LT-3: at expiry the host issues `sandbox.destroy`.
                    self.count_attempt(g)?;
                    let ctx = self.host_op_ctx(
                        tags,
                        OperationType::SandboxDestroy,
                        &g.sandbox_id,
                        g.generation,
                        "the sandbox's expiry has passed",
                    )?;
                    let op = self.sandbox_destroy(&ctx, Self::target(g)).await?;
                    self.telemetry.metrics.incr("sandboxes_expired", 1);
                    if op.state == crate::domain::OperationState::Succeeded {
                        report.contained += 1;
                    }
                }
                IdlePlan::Quarantine(reason) => {
                    let entries = self.quarantine(g, &reason);
                    self.host_operation(tags, g, &reason, |_| async move { Ok(entries) }).await?;
                    report.quarantined += 1;
                }
            }
            Ok(())
        }
        .await;
        if let Err(e) = res
            && e.class != FailureClass::StateConflict
        {
            report.notes.push(format!("{}@{}: {}", g.sandbox_id, g.generation, e.message));
        }
    }

    /// Observe every generation that no operation holds, once (§16.2 Part B). `late` is `Some`
    /// when the startup recovery deadline has passed: a generation that still needs observing is
    /// quarantined instead (RC-5), except those of the sandboxes listed, which this activation has
    /// already resolved.
    pub(crate) async fn sweep_generations(
        &self,
        report: &mut RecoveryReport,
        late: Option<&std::collections::BTreeSet<SandboxId>>,
    ) -> Result<()> {
        let gens: Vec<GenerationRecord> =
            self.journal.read(|s| s.generations.values().filter(|g| g.state != LifecycleState::Destroyed).cloned().collect())?;
        let max_attempts = self.cfg.recovery.max_attempts;
        for g in gens {
            let found = self.journal.read(|s| {
                // RC-6: a sandbox with a non-terminal operation is not decided by the sweep; its
                // operation observes for itself.
                let busy = s.open_on_sandbox(&g.sandbox_id).next().is_some();
                let fresh = s.generations.get(&(g.sandbox_id.clone(), g.generation)).cloned();
                s.sandboxes.get(&g.sandbox_id).map(|sb| (busy, fresh, sb.current, sb.expiry.clone(), sb.tags.clone()))
            })?;
            let Some((false, Some(g), current, expiry, tags)) = found else { continue };
            if g.state == LifecycleState::Destroyed {
                continue;
            }
            if current != g.generation {
                // Left behind by a restore that switched (RE-5): finish retiring it.
                if g.quarantined.is_none()
                    && let Ok(Some(cur)) = self.journal.read(|s| s.generations.get(&(g.sandbox_id.clone(), current)).cloned())
                {
                    let (sandbox, keep) = (g.sandbox_id.clone(), current);
                    let why = "retiring the generation a restore superseded";
                    let done = self
                        .host_operation(&tags, &cur, why, |_| async move {
                            self.retire_superseded(&sandbox, keep).await.map(|(entries, _)| entries)
                        })
                        .await;
                    if done.is_ok() {
                        report.retired_superseded += 1;
                    }
                }
                continue;
            }
            let facts = IdleFacts {
                state: g.state,
                quarantined: g.quarantined.is_some(),
                expired: is_expired(self.clock.as_ref(), &expiry),
                attempts: g.observe_attempts,
                max_attempts,
            };
            let cut_off = late.is_some_and(|resolved| !resolved.contains(&g.sandbox_id));
            let plan = if cut_off && g.quarantined.is_none() && g.state.may_have_vm() && g.state != LifecycleState::Provisioning {
                IdlePlan::Quarantine("the startup recovery deadline passed before this generation could be observed".into())
            } else {
                let obs = self.observe_generation(&g).await;
                // Containment that keeps failing is not retried forever: after the bound, quarantine.
                match decide_idle(facts, &obs) {
                    IdlePlan::StopStray | IdlePlan::StopDegraded(_) | IdlePlan::Destroy if g.observe_attempts >= max_attempts => {
                        IdlePlan::Quarantine(format!("the host could not contain this generation in {} attempts", g.observe_attempts))
                    }
                    plan => plan,
                }
            };
            self.apply_idle(&tags, &g, plan, report).await;
        }
        Ok(())
    }

    /// PS-10, OU-4: remove what retention no longer keeps. A non-terminal operation is never removed.
    pub(crate) fn retention(&self) -> Result<usize> {
        let now = self.clock.wall_ms();
        let ops = &self.cfg.operations;
        let older = |t: Option<i64>, keep_ms: u64| t.is_some_and(|t| now.saturating_sub(t) > i64::try_from(keep_ms).unwrap_or(i64::MAX));
        let (forget, expired_output) = self.journal.read(|s| {
            let mut f = ForgetRecord::default();
            let mut output = vec![];
            for o in s.operations.values().filter(|o| o.is_terminal()) {
                if older(o.finished_ms, ops.operation_retention_ms) {
                    f.operations.push(o.key());
                }
                if older(o.finished_ms, ops.output_retention_ms) {
                    output.extend(
                        o.result
                            .as_ref()
                            .and_then(|v| serde_json::from_value::<crate::domain::RunResult>(v.clone()).ok())
                            .into_iter()
                            .flat_map(|r| r.artifacts),
                    );
                }
            }
            for sb in s.sandboxes.values().filter(|sb| older(sb.destroyed_ms, ops.change_retention_ms)) {
                let gens: Vec<_> = s.generations.values().filter(|g| g.sandbox_id == sb.sandbox_id).collect();
                let quiet = s.open_on_sandbox(&sb.sandbox_id).next().is_none() && gens.iter().all(|g| g.state == LifecycleState::Destroyed);
                if quiet {
                    f.change_floor = gens.iter().map(|g| g.revision).chain([sb.revision]).fold(f.change_floor, u64::max);
                    f.sandboxes.push(sb.sandbox_id.clone());
                }
            }
            for sn in s.snapshots.values().filter(|sn| older(sn.deleted_ms, ops.change_retention_ms)) {
                if s.open_on_snapshot(&sn.snapshot_ref()).next().is_none() {
                    f.change_floor = f.change_floor.max(sn.revision);
                    f.snapshots.push((sn.snapshot_id.clone(), sn.generation));
                }
            }
            (f, output)
        })?;
        // Output first: an operation record may outlive its output, never the reverse.
        for a in &expired_output {
            let _ = self.artifacts.remove(&a.artifact_id);
        }
        let removed = forget.operations.len() + forget.sandboxes.len() + forget.snapshots.len();
        if removed > 0 {
            self.journal.commit(vec![Entry::Forget(forget)])?;
            self.telemetry.metrics.incr("records_forgotten", removed as u64);
        }
        Ok(removed)
    }

    /// One pass while serving.
    pub async fn sweep_once(&self) -> RecoveryReport {
        let mut report = RecoveryReport::default();
        // PD-4: without a live enforcer, a runtime launched now could outlive its expiry.
        match self.lifetime.unavailable() {
            Some(_) => self.contain(ContainmentReason::LifetimeEnforcerUnavailable(ENFORCER_DOWN.into())),
            None => {
                self.clear_containment(|r| matches!(r, ContainmentReason::LifetimeEnforcerUnavailable(_)));
            }
        }
        self.journal.restore_reserve();
        self.check_store();
        if self.journal.write_block().is_some() {
            // HM-4: in READ_ONLY the host takes no action it cannot record.
            return report;
        }
        if self.containment_reasons().iter().any(|r| matches!(r, ContainmentReason::StoreRegression(_))) {
            // LN-2: no destructive action until an operator acknowledges the store.
            return report;
        }
        // OP-19: containment an earlier activation left unfinished is re-driven until proven.
        let epoch = self.journal.epoch();
        let pending: Vec<OperationRecord> =
            self.journal.read(|s| s.open().filter(|o| o.is_inherited(epoch)).cloned().collect()).unwrap_or_default();
        for op in pending {
            report.examined += 1;
            if let Err(e) = self.recover_op(op, false, &mut report).await {
                report.notes.push(e.message);
            }
        }
        if let Err(e) = self.sweep_generations(&mut report, None).await {
            report.notes.push(e.message);
            return report;
        }
        let now = self.clock.wall_ms();
        if let Ok(mut st) = self.sweep.lock() {
            st.last_complete_ms = Some(now);
            if now.saturating_sub(st.last_retention_ms) >= 60_000 {
                st.last_retention_ms = now;
                drop(st);
                if let Err(e) = self.retention() {
                    report.notes.push(format!("retention: {}", e.message));
                }
            }
        }
        // PS-10: what retention forgot, and what later records replaced, leaves the file only when the
        // file is rewritten. Without this the store of a host that serves long enough outgrows what
        // its next start is willing to open.
        match self.journal.compact_if_grown() {
            Ok(true) => self.telemetry.metrics.incr("store_compactions", 1),
            Ok(false) => {}
            Err(e) => {
                report.notes.push(format!("store compaction: {}", e.message));
                self.check_store();
            }
        }
        self.telemetry.metrics.incr("sweeps", 1);
        for n in &report.notes {
            tracing::warn!("sweep: {n}");
        }
        report
    }

    /// The sweeper's loop. A lost runtime is noticed within `runtime_loss_detection_bound`, which is
    /// no longer than `sweep_interval` (§30), so every generation is observed at least that often.
    pub async fn run_sweeper(self: Arc<Self>, shutdown: CancellationToken) {
        let every = Duration::from_millis(self.cfg.recovery.runtime_loss_detection_ms.min(self.cfg.recovery.sweep_interval_ms).max(100));
        loop {
            tokio::select! {
                () = shutdown.cancelled() => return,
                () = tokio::time::sleep(every) => {}
            }
            self.sweep_once().await;
        }
    }
}
