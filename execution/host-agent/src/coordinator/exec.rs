//! Execution (contract §18) and `operation.cancel` (§11.7).
//!
//! The outcome table of §18.2 is implemented here row by row. Two rules shape everything:
//!
//! * a command handed to a guest may have run whatever the host did afterwards, so its operation
//!   never reports `NOT_APPLIED` (§11.3) and is never sent to a guest twice (RY-3);
//! * when the host cannot obtain a result it ends the runtime and the operation is `UNKNOWN` —
//!   never `FAILED`, never `SUCCEEDED` (OP-9).

use std::time::Duration;

use acf_wire::guest::{Containment, ExecResult, ExecStatus};
use base64::{Engine, engine::general_purpose::STANDARD};
use tokio_util::sync::CancellationToken;

use super::{
    Ctx, Host, fault,
    ops::{BeginSpec, Begun, Outcome, admit_granting},
};
use crate::{
    api::{ExecParams, OperationSelector},
    backend::{GuestExecOutcome, GuestExecRequest},
    domain::{
        ArtifactKind, CancelledBy, EvidenceStatus, FailureInfo, LifecycleState, OperationState, OperationType, OutputCapture, OutputStatus,
        Residue, ResolvedCommand, ResourceEvidence, RunMetrics, RunResult, RunStatus,
    },
    error::{AcfError, FailureClass, Result, SideEffect},
    ids::RunId,
    storage::artifacts::ArtifactContext,
    store::{Entry, GenerationRecord, OperationRecord},
};

/// Output up to this size travels inline in the (small) operation record; more is stored only.
pub(crate) const INLINE_OUTPUT_MAX: usize = 16 * 1024;
/// Time added to an execution's operation deadline for everything around the command itself.
const EXEC_OVERHEAD_MS: u64 = 60_000;

/// What the guest reported for one output stream, before it is bounded and stored.
struct RawStream<'a> {
    name: &'a str,
    kind: ArtifactKind,
    data: Vec<u8>,
    total: u64,
    truncated: bool,
    incomplete: bool,
    /// The budget the request was admitted with. Whatever the guest sent, no more is kept (GP-2).
    budget: u64,
}

impl Host {
    pub async fn exec(&self, ctx: &Ctx, p: ExecParams) -> Result<OperationRecord> {
        let cmd = ctx.profile.authorize_exec(&p.command)?;
        let caps = self.backend.capabilities();
        if !caps.guest_exec {
            return Err(AcfError::unsupported("this host's backend does not offer guest execution"));
        }
        if !cmd.secret_env.is_empty() && !caps.secret_injection {
            // BK-5: refused before BEGIN, never silently skipped.
            return Err(AcfError::unsupported("this host's backend does not offer secret injection"));
        }
        let run_id = RunId::generate();
        let t = p.sandbox_target();
        let margin = self.cfg.operations.backstop_margin_ms;
        let spec = BeginSpec {
            op_type: OperationType::ExecRun,
            target: t.sandbox_id.to_string(),
            expected_generation: Some(t.expected_generation),
            deadline_ms: cmd.limits.timeout_ms.saturating_add(margin).saturating_add(EXEC_OVERHEAD_MS),
            run_id: Some(run_id.clone()),
            sandbox: Some((t.sandbox_id.clone(), t.expected_generation)),
            snapshot: None,
        };
        // The secret references this operation adds to the generation's mark (see below).
        let mut marked: Vec<String> = Vec::new();
        let begun = self.begin(ctx, spec, |state| {
            let (_, g) = Self::target_in(state, ctx, &t.sandbox_id, t.expected_generation, t.if_revision)?;
            admit_granting(state, &t.sandbox_id)?;
            if !g.state.is_idle() {
                return Err(AcfError::conflict(format!(
                    "sandbox is {:?}; an execution needs an idle (READY or COMPLETED) sandbox",
                    g.state
                )));
            }
            let mut running = self.moved(&g, LifecycleState::Running)?;
            running.last_run = Some(run_id.clone());
            // SC-5: a generation to which secret material is delivered is marked secret-bearing, with
            // the set of references. The mark is written here, before the delivery, so that a crash
            // after a delivery cannot lose it. If the operation then establishes that nothing was
            // delivered, its FINISH takes back exactly the references it added here (`unmarked`).
            marked = cmd.secret_env.values().filter(|r| running.secret_refs.insert(r.name.clone())).map(|r| r.name.clone()).collect();
            Ok(vec![Entry::Generation(Box::new(running))])
        })?;
        let (mut op, guard) = match begun {
            Begun::New(o, g) => (*o, g),
            Begun::Existing(r) => return Ok(*r),
        };
        let remaining = self.deadline_remaining(&op);
        let res = self.bounded(remaining, &guard.cancel, self.exec_body(&mut op, &run_id, &cmd, &p, &marked)).await;
        if let Ok(mut r) = self.runs.lock() {
            r.remove(&op.key());
        }
        match res {
            Ok(()) => Ok(op),
            Err(e) if e.must_stop_silently() => Err(e),
            Err(e) => {
                self.exec_failed(&mut op, &run_id, &p, e, &marked).await?;
                Ok(op)
            }
        }
    }

    /// `g` without the secret references this operation added at BEGIN. Used only where the operation
    /// has established that no material reached the guest (SC-3, SC-5): a generation is marked for
    /// what was delivered to it, not for what was asked.
    fn unmarked(mut g: GenerationRecord, added: &[String]) -> GenerationRecord {
        for name in added {
            g.secret_refs.remove(name);
        }
        g
    }

    async fn exec_body(
        &self,
        op: &mut OperationRecord,
        run_id: &RunId,
        cmd: &ResolvedCommand,
        p: &ExecParams,
        marked: &[String],
    ) -> Result<()> {
        fault!(self, AfterJournalBeforeMutation, "exec");
        let g = self.gen_record(&p.sandbox_id, p.expected_generation)?;
        let handle = g.backend_handle();

        // SC-2, SC-3: resolve at the moment of delivery; a reference that does not resolve fails the
        // operation before any effect that depends on it. Nothing has reached the guest yet.
        let mut secrets = Vec::with_capacity(cmd.secret_env.len());
        if !cmd.secret_env.is_empty() {
            self.step(op, "resolve_secrets")?;
            for (name, reference) in &cmd.secret_env {
                match self.secrets.resolve(reference).await {
                    Ok(material) => secrets.push((name.clone(), material)),
                    Err(e) => {
                        let failure = FailureInfo::new(
                            FailureClass::DependencyUnavailable,
                            format!("a secret reference did not resolve: {}", e.message),
                            SideEffect::None,
                        );
                        // Nothing was delivered, so nothing is marked. (`RUNNING → READY` is not a transition
                        // of §12.1: the generation is idle again as `COMPLETED`.)
                        let idle = self.moved(&self.gen_record(&p.sandbox_id, p.expected_generation)?, LifecycleState::Completed)?;
                        let idle = Self::unmarked(idle, marked);
                        return self.finish(op, Outcome::failed(failure, None), vec![Entry::Generation(Box::new(idle))]);
                    }
                }
            }
        }

        // From this record on the command may have reached the guest (§11.3).
        op.execution_started = true;
        self.step(op, "exec")?;
        fault!(self, BeforeBackendStep, "exec");

        let token = CancellationToken::new();
        self.runs.lock().map_err(|_| AcfError::internal("runs table poisoned"))?.insert(op.key(), token.clone());
        let grace = Duration::from_millis(self.cfg.operations.backstop_margin_ms);
        let request = GuestExecRequest { exec_id: run_id.to_string(), command: cmd.clone(), grace, secrets };
        // RC-6: for as long as the command runs this operation holds the sandbox, so it is this
        // operation that keeps verifying the runtime's posture (IS-3).
        let outcome = self.while_intact(&p.sandbox_id, p.expected_generation, self.backend.exec(&handle, &request, token)).await?;
        fault!(self, AfterBackendMutationBeforeCommit, "exec");
        // OP-15: a result that arrives after the deadline is not a success.
        self.ensure_within_deadline(op)?;

        let stats = self.backend.stats(&handle).await.ok().flatten();
        let result = self.build_run_result(op, &g, run_id, cmd, &outcome, stats.as_ref())?;
        let stored = serde_json::to_value(Self::strip_large_output(result.clone()))?;
        self.telemetry.metrics.incr_labelled("runs", "status", &format!("{:?}", result.status), 1);
        let current = self.gen_record(&p.sandbox_id, p.expected_generation)?;

        // §18.2, row by row.
        if outcome.vm_killed || outcome.host_deadline_hit {
            // The host backstop fired: FAILED / TIMEOUT / MAY_BE_APPLIED; generation FAILED.
            self.telemetry.metrics.incr("exec_backstop_fired", 1);
            let failure = FailureInfo::new(
                FailureClass::Timeout,
                "the host deadline backstop ended the runtime; the sandbox must not be reused",
                SideEffect::Possible,
            );
            let mut failed = self.failed_generation(&current, failure.clone())?;
            if outcome.vm_killed {
                failed.process = None;
                self.lifetime.disarm(&current.sandbox_ref().jail_id());
            }
            let residue = Residue::Generation { sandbox_id: p.sandbox_id.clone(), generation: p.expected_generation };
            let mut out = Outcome::failed(failure, Some(residue));
            out.result = Some(stored);
            return self.finish(op, out, vec![Entry::Generation(Box::new(failed))]);
        }
        let idle = self.moved(&current, LifecycleState::Completed)?;
        let outcome = match result.status {
            RunStatus::Exited | RunStatus::Signaled | RunStatus::TimedOut => Outcome::succeeded(Some(stored)),
            RunStatus::SpawnFailed => {
                // The guest could not start it: nothing ran.
                op.execution_started = false;
                let failure =
                    FailureInfo::new(FailureClass::DependencyUnavailable, "the guest could not start the command", SideEffect::None);
                let mut out = Outcome::failed(failure, None);
                out.result = Some(stored);
                out
            }
            RunStatus::Cancelled => Outcome::cancelled(CancelledBy::Caller, None, Some(stored)),
            RunStatus::Unknown => return Err(AcfError::unavailable("the guest returned no result").with_possible_side_effect()),
        };
        self.finish(op, outcome, vec![Entry::Generation(Box::new(idle))])
    }

    /// No result could be obtained. If the failure was definite — the command never reached the
    /// guest — the operation is `FAILED`, `NOT_APPLIED`. Otherwise the runtime is ended, the
    /// generation is `FAILED`, and the operation is `UNKNOWN` (or `FAILED`/`TIMEOUT` when it was the
    /// host's own deadline that passed).
    async fn exec_failed(&self, op: &mut OperationRecord, run_id: &RunId, p: &ExecParams, e: AcfError, marked: &[String]) -> Result<()> {
        let g = self.gen_record(&p.sandbox_id, p.expected_generation)?;
        if e.is_definite() && e.class != FailureClass::Timeout {
            op.execution_started = false;
            let info = self.failure_of(op, &e);
            let idle = if g.state == LifecycleState::Running { self.moved(&g, LifecycleState::Completed)? } else { g };
            // The command never reached the guest, so neither did any secret.
            let idle = Self::unmarked(idle, marked);
            return self.finish(op, Outcome::failed(info, None), vec![Entry::Generation(Box::new(idle))]);
        }
        // The runtime may still be executing the command: end it (EX-6: with no guest cooperation).
        let stopped = matches!(
            self.backend.stop(&g.backend_handle(), self.stop_grace()).await,
            Ok(crate::backend::StopOutcome::Stopped | crate::backend::StopOutcome::AlreadyGone | crate::backend::StopOutcome::Refused(_))
        );
        if stopped {
            self.lifetime.disarm(&g.sandbox_ref().jail_id());
        }
        let timed_out = e.class == FailureClass::Timeout;
        let control_lost = e.class == FailureClass::SecurityControlFailure;
        if control_lost {
            self.telemetry.metrics.incr("security_control_failures", 1);
            self.telemetry.events.emit(crate::telemetry::EventDraft::new(&self.wall(), "security.control_failure").operation(op));
        }
        let info = if timed_out {
            FailureInfo::new(FailureClass::Timeout, e.message.clone(), SideEffect::Possible)
        } else {
            FailureInfo::new(FailureClass::UnknownOutcome, format!("no result could be obtained: {}", e.message), SideEffect::Possible)
        };
        // The operation says what is known about the command: nothing. The generation says why its
        // runtime was ended.
        let why_ended = if control_lost {
            FailureInfo::new(FailureClass::SecurityControlFailure, e.message.clone(), SideEffect::Possible)
        } else {
            info.clone()
        };
        let mut failed = self.failed_generation(&g, why_ended)?;
        if stopped {
            failed.process = None;
        }
        let residue = Some(Residue::Generation { sandbox_id: p.sandbox_id.clone(), generation: p.expected_generation });
        self.telemetry.metrics.incr_labelled("runs", "status", if timed_out { "TimedOut" } else { "Unknown" }, 1);
        let _ = run_id;
        let outcome = if timed_out { Outcome::failed(info, residue) } else { Outcome::unknown(info, residue) };
        self.finish(op, outcome, vec![Entry::Generation(Box::new(failed))])
    }

    fn capture(&self, raw: RawStream<'_>, ctx: &ArtifactContext) -> OutputCapture {
        let RawStream { name, kind, mut data, total, mut truncated, incomplete, budget } = raw;
        if data.len() as u64 > budget {
            // The backend bounds a result before it parses it; this is the same bound held again
            // where the result is stored, so that no backend can make the host keep more.
            data.truncate(usize::try_from(budget).unwrap_or(usize::MAX));
            truncated = true;
        }
        let total = total.max(data.len() as u64);
        let kept = data.len() as u64;
        let mut status = if incomplete {
            OutputStatus::Incomplete
        } else if truncated {
            OutputStatus::Truncated
        } else {
            OutputStatus::Complete
        };
        let mut artifact = None;
        if !data.is_empty() {
            match self.artifacts.put(kind, name, &data, ctx) {
                Ok(a) => artifact = Some(a),
                // Required execution evidence: surface the gap instead of hiding it.
                Err(_) => status = OutputStatus::Incomplete,
            }
        }
        OutputCapture { status, total_bytes: total, kept_bytes: kept, data_b64: STANDARD.encode(&data), artifact }
    }

    pub(crate) fn build_run_result(
        &self,
        op: &OperationRecord,
        g: &GenerationRecord,
        run_id: &RunId,
        cmd: &ResolvedCommand,
        out: &GuestExecOutcome,
        usage: Option<&crate::backend::RuntimeUsage>,
    ) -> Result<RunResult> {
        let r: &ExecResult = &out.result;
        let ctx = ArtifactContext { operation_id: op.operation_id.clone(), sandbox_id: g.sandbox_id.clone(), run_id: Some(run_id.clone()) };
        let backstop = out.vm_killed || out.host_deadline_hit;
        let (status, exit_code, signal, note) = match &r.status {
            _ if backstop => {
                (RunStatus::TimedOut, None, None, Some("the guest did not honour its deadline; the host ended the runtime".to_owned()))
            }
            ExecStatus::Exited { code } => (RunStatus::Exited, Some(*code), None, None),
            ExecStatus::Signaled { signal } => (RunStatus::Signaled, None, Some(*signal), None),
            ExecStatus::TimedOut => (RunStatus::TimedOut, None, None, None),
            ExecStatus::Cancelled => (RunStatus::Cancelled, None, None, None),
            ExecStatus::SpawnFailed { .. } => {
                (RunStatus::SpawnFailed, None, None, Some("the command could not be started in the guest".to_owned()))
            }
        };
        let stream = |name: &'static str, kind, data: &Vec<u8>, total, truncated, budget| RawStream {
            name,
            kind,
            data: data.clone(),
            total,
            truncated,
            incomplete: r.output_incomplete,
            budget,
        };
        let stdout = self.capture(
            stream("stdout", ArtifactKind::Stdout, &r.stdout, r.stdout_total_bytes, r.stdout_truncated, cmd.limits.max_stdout_bytes),
            &ctx,
        );
        let stderr = self.capture(
            stream("stderr", ArtifactKind::Stderr, &r.stderr, r.stderr_total_bytes, r.stderr_truncated, cmd.limits.max_stderr_bytes),
            &ctx,
        );
        let evidence_status = if matches!(stdout.status, OutputStatus::Incomplete) || matches!(stderr.status, OutputStatus::Incomplete) {
            EvidenceStatus::Incomplete
        } else if matches!(stdout.status, OutputStatus::Truncated) || matches!(stderr.status, OutputStatus::Truncated) {
            EvidenceStatus::Truncated
        } else {
            EvidenceStatus::Complete
        };
        let containment = match r.containment {
            Containment::Cgroup2 => "guest cgroup v2 pids.max + cgroup.kill",
            Containment::RlimitNproc => "guest RLIMIT_NPROC + uid reaping (weaker fallback)",
            Containment::Unknown => "unknown (guest returned no result)",
        };
        let timed_out = matches!(status, RunStatus::TimedOut);
        let mut resource_evidence = vec![
            ResourceEvidence {
                resource: "guest_pids".into(),
                configured: Some(u64::from(cmd.limits.max_pids)),
                effective: Some(u64::from(cmd.limits.max_pids)),
                observed_peak: None,
                violated: r.pid_limit_hit,
                action_taken: if r.pid_limit_hit { "fork refused / tree terminated at run end".into() } else { "none".into() },
                mechanism: containment.into(),
            },
            ResourceEvidence {
                resource: "runtime_ms".into(),
                configured: Some(cmd.limits.timeout_ms),
                effective: Some(cmd.limits.timeout_ms),
                observed_peak: Some(r.duration_ms),
                violated: timed_out,
                action_taken: match (timed_out, backstop) {
                    (true, true) => "runtime ended by the host backstop".into(),
                    (true, false) => "process group killed at the guest deadline".into(),
                    _ => "none".into(),
                },
                mechanism: "guest deadline + host backstop (monotonic)".into(),
            },
            ResourceEvidence {
                resource: "stdout_bytes".into(),
                configured: Some(cmd.limits.max_stdout_bytes),
                effective: Some(cmd.limits.max_stdout_bytes),
                observed_peak: Some(r.stdout_total_bytes),
                violated: r.stdout_truncated,
                action_taken: if r.stdout_truncated { "truncated; remainder drained and counted".into() } else { "none".into() },
                mechanism: "guest capture cap, re-enforced by host".into(),
            },
            ResourceEvidence {
                resource: "stderr_bytes".into(),
                configured: Some(cmd.limits.max_stderr_bytes),
                effective: Some(cmd.limits.max_stderr_bytes),
                observed_peak: Some(r.stderr_total_bytes),
                violated: r.stderr_truncated,
                action_taken: if r.stderr_truncated { "truncated; remainder drained and counted".into() } else { "none".into() },
                mechanism: "guest capture cap, re-enforced by host".into(),
            },
        ];
        if let Some(usage) = usage {
            resource_evidence.extend(usage.evidence.iter().cloned());
        }
        let artifacts = [&stdout, &stderr].iter().filter_map(|c| c.artifact.clone()).collect();
        Ok(RunResult {
            run_id: run_id.clone(),
            operation_id: op.operation_id.clone(),
            sandbox_id: g.sandbox_id.clone(),
            generation: g.generation,
            status,
            exit_code,
            signal,
            stdout,
            stderr,
            guest_duration_ms: r.duration_ms,
            guest_containment: containment.to_owned(),
            host_backstop_fired: backstop,
            runtime_ended: out.vm_killed,
            metrics: RunMetrics {
                wall_ms: r.duration_ms,
                cpu_usage_usec: usage.and_then(|u| u.cpu_usage_usec),
                memory_peak_bytes: usage.and_then(|u| u.memory_peak_bytes),
            },
            evidence_status,
            resource_evidence,
            artifacts,
            profile_id: op.profile_id.clone(),
            image_id: g.image.image_id.clone(),
            note,
        })
    }

    /// Operation records stay small: large output lives in the output store and is re-attached on read.
    pub(crate) fn strip_large_output(mut r: RunResult) -> RunResult {
        for c in [&mut r.stdout, &mut r.stderr] {
            if c.kept_bytes as usize > INLINE_OUTPUT_MAX && c.artifact.is_some() {
                c.data_b64.clear();
            }
        }
        r
    }

    /// `operation.cancel` (OP-21 – OP-23). It is itself an operation, of containment class. It
    /// applies to an execution that is `IN_PROGRESS` in the current activation.
    pub async fn operation_cancel(&self, ctx: &Ctx, sel: OperationSelector) -> Result<OperationRecord> {
        let target = self.resolve_operation(&ctx.authority, &sel.operation_id)?;
        let target_key = target.key();
        let spec = BeginSpec {
            op_type: OperationType::OperationCancel,
            target: sel.operation_id.to_string(),
            expected_generation: None,
            deadline_ms: self.cfg.operations.deadlines.stop_ms,
            run_id: target.run_id.clone(),
            sandbox: None,
            snapshot: None,
        };
        let epoch = self.journal.epoch();
        let begun = self.begin(ctx, spec, |state| {
            let t = state.operations.get(&target_key).ok_or_else(|| AcfError::not_found("the operation to cancel does not exist"))?;
            if t.is_terminal() {
                return Ok(vec![]); // the cancel will end SUCCEEDED with no effect
            }
            if !t.operation_type.is_execution() {
                return Err(AcfError::conflict(format!(
                    "`{}` cannot be cancelled: it is bounded by its deadline, and a containment operation on the sandbox preempts it",
                    t.operation_type
                )));
            }
            if t.is_inherited(epoch) || !self.tasks.is_running(&target_key) {
                return Err(AcfError::conflict("the execution belongs to an earlier activation; the host is establishing its outcome"));
            }
            Ok(vec![])
        })?;
        let (mut op, _guard) = match begun {
            Begun::New(o, g) => (*o, g),
            Begun::Existing(r) => return Ok(*r),
        };
        let body = async {
            self.step(&mut op, "cancel")?;
            if let Some(token) = self.runs.lock().map_err(|_| AcfError::internal("runs table poisoned"))?.get(&target_key).cloned() {
                token.cancel();
            }
            // Wait for the execution to end (the guest confirms, or the backstop fires). Bounded by
            // this operation's own deadline.
            let deadline = self.deadline_remaining(&op).unwrap_or_default();
            let ended = tokio::time::timeout(deadline, async {
                loop {
                    if self.operation_record(&target_key).map(|t| t.is_terminal()).unwrap_or(true) {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .is_ok();
            if !ended {
                return Err(AcfError::timeout("the execution did not end within the cancel's deadline").with_possible_side_effect());
            }
            let state = self.operation_record(&target_key).map(|t| t.state).unwrap_or(OperationState::Unknown);
            self.finish(&mut op, Outcome::succeeded(Some(serde_json::json!({ "note": format!("the execution ended {state:?}") }))), vec![])
        };
        let res = body.await;
        match res {
            Ok(()) => Ok(op),
            Err(e) if e.must_stop_silently() => Err(e),
            Err(e) => {
                let info = self.failure_of(&op, &e);
                self.finish(&mut op, Outcome::failed(info, None), vec![])?;
                Ok(op)
            }
        }
    }
}
