//! Run execution flow (spec §8.7, §18.3, §18.8, §18.10, §23).

use std::time::Duration;

use acf_wire::guest::{Containment, ExecResult, ExecStatus};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::json;
use tokio_util::sync::CancellationToken;

use super::{
    Ctx, Host, fault,
    ops::{BeginSpec, Begun},
};
use crate::{
    backend::{GuestExecOutcome, GuestExecRequest},
    domain::{
        ArtifactKind, EvidenceStatus, FailureInfo, LifecycleState, OperationStatus, OperationType, OutputCapture, OutputStatus,
        ResolvedCommand, ResourceEvidence, RunMetrics, RunOutcome, RunResult,
    },
    error::{AcfError, FailureClass, Result},
    filesystem::artifacts::ArtifactContext,
    ids::{OperationId, RunId},
    operation::{Entry, GenerationRecord, OperationRecord},
    process::CgroupSpec,
    protocol::{ExecParams, ResponseBody},
};

/// Output up to this size travels inline in the (small) journal record; more is artifact-only.
pub(crate) const INLINE_OUTPUT_MAX: usize = 16 * 1024;
const HOST_GRACE_MS: u64 = 3_000;

/// What the guest reported for one output stream, before it is bounded/spilled to an artifact.
struct RawStream<'a> {
    name: &'a str,
    kind: ArtifactKind,
    data: Vec<u8>,
    total: u64,
    truncated: bool,
    incomplete: bool,
}

impl Host {
    pub async fn exec(&self, ctx: &Ctx, p: ExecParams) -> Result<OperationRecord> {
        let cmd = ctx.policy.authorize_exec(&p.command)?;
        let run_id = RunId::generate();
        let mut guard = None;
        let spec = BeginSpec {
            op_type: OperationType::Exec,
            resource_id: p.sandbox_id.to_string(),
            expected_generation: Some(p.expected_generation),
            body: json!({"sandbox_id": p.sandbox_id, "expected_generation": p.expected_generation, "command": p.command}),
            deadline_ms: cmd.limits.timeout_ms + HOST_GRACE_MS + 60_000,
            run_id: Some(run_id.clone()),
            sandbox: Some((p.sandbox_id.clone(), p.expected_generation)),
            snapshot: None,
        };
        let me = self;
        let rid = run_id.clone();
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
                .get(&(p.sandbox_id.clone(), p.expected_generation))
                .ok_or_else(|| AcfError::internal("generation record missing"))?;
            guard = Some(me.locks.try_acquire(p.sandbox_id.as_str())?);
            if !g.state.is_idle() {
                return Err(AcfError::conflict(format!("sandbox is {:?}; exec requires an idle (READY/COMPLETED) sandbox", g.state)));
            }
            let mut running = me.moved(g, LifecycleState::Running)?;
            running.last_run = Some(rid.clone());
            Ok(vec![Entry::Generation(Box::new(running))])
        })?;
        let mut op = match begun {
            Begun::New(o) => *o,
            Begun::Existing(r) => return Ok(*r),
        };
        let _guard = guard;
        match self.exec_body(&mut op, &run_id, &cmd, &p).await {
            Ok(()) => Ok(op),
            Err(e) if e.is_simulated_crash() => Err(e),
            Err(e) => {
                self.exec_failed(&mut op, &run_id, &p, e).await?;
                Ok(op)
            }
        }
    }

    async fn exec_body(&self, op: &mut OperationRecord, run_id: &RunId, cmd: &ResolvedCommand, p: &ExecParams) -> Result<()> {
        fault!(self, AfterJournalBeforeMutation, "exec");
        let g = self.current_gen(&p.sandbox_id, p.expected_generation)?;
        let handle = g.backend_handle();
        self.step(op, "exec")?;
        fault!(self, BeforeBackendStep, "exec");

        let token = CancellationToken::new();
        self.runs.lock().map_err(|_| AcfError::internal("runs table poisoned"))?.insert(op.operation_id.clone(), token.clone());
        let res = self
            .backend
            .exec(
                &handle,
                &GuestExecRequest { exec_id: run_id.to_string(), command: cmd.clone(), grace: Duration::from_millis(HOST_GRACE_MS) },
                token,
            )
            .await;
        if let Ok(mut r) = self.runs.lock() {
            r.remove(&op.operation_id);
        }
        let outcome = res?;
        fault!(self, AfterBackendMutationBeforeCommit, "exec");

        let stats = self.backend.stats(&handle).await.ok().flatten();
        let result = self.build_run_result(op, &g, run_id, cmd, &outcome, stats.as_ref())?;
        let mut next = self.current_gen(&p.sandbox_id, p.expected_generation)?;
        let bad = outcome.vm_killed;
        next = self.moved(&next, if bad { LifecycleState::Failed } else { LifecycleState::Completed })?;
        if bad {
            next.failure = Some(FailureInfo {
                class: FailureClass::TimeoutUnknown,
                message: "the host deadline backstop terminated the VM; the sandbox must not be reused".into(),
                side_effect: crate::error::SideEffect::None,
            });
        }
        let journal_copy = Self::strip_large_output(result);
        self.telemetry.metrics.incr_labelled("runs", "outcome", &format!("{:?}", journal_copy.outcome), 1);
        self.finish(
            op,
            OperationStatus::Succeeded,
            None,
            Some(ResponseBody::Run(Box::new(journal_copy))),
            vec![Entry::Generation(Box::new(next))],
        )
    }

    /// The run's result is **unknown**: the backend failed mid-flight. Never report `FAILED` for a
    /// command that may have executed (spec §12.4: arbitrary guest commands stay `UNKNOWN`).
    async fn exec_failed(&self, op: &mut OperationRecord, run_id: &RunId, p: &ExecParams, e: AcfError) -> Result<()> {
        if let Ok(mut r) = self.runs.lock() {
            r.remove(&op.operation_id);
        }
        let g = self.current_gen(&p.sandbox_id, p.expected_generation)?;
        let info = FailureInfo::from(&e);
        let mut f = if g.state.can_transition_to(LifecycleState::Failed) { self.moved(&g, LifecycleState::Failed)? } else { g };
        f.failure = Some(info.clone());
        let status = Self::status_after_failure(&e, false);
        self.telemetry.metrics.incr_labelled("runs", "outcome", "Unknown", 1);
        let _ = run_id;
        self.finish(op, status, Some(info), None, vec![Entry::Generation(Box::new(f))])
    }

    fn capture(&self, raw: RawStream<'_>, ctx: &ArtifactContext) -> OutputCapture {
        let RawStream { name, kind, data, total, truncated, incomplete } = raw;
        let kept = data.len() as u64;
        let status = if incomplete {
            OutputStatus::Incomplete
        } else if truncated {
            OutputStatus::Truncated
        } else {
            OutputStatus::Complete
        };
        let mut artifact = None;
        let mut status = status;
        if !data.is_empty() {
            match self.artifacts.put(kind, name, &data, ctx) {
                Ok(a) => artifact = Some(a),
                // REQUIRED_EXECUTION_EVIDENCE: surface the gap instead of hiding it.
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
        stats: Option<&crate::process::CgroupStats>,
    ) -> Result<RunResult> {
        let r: &ExecResult = &out.result;
        let ctx = ArtifactContext { operation_id: op.operation_id.clone(), sandbox_id: g.sandbox_id.clone(), run_id: Some(run_id.clone()) };
        let (outcome, exit_code, signal, note) = match &r.status {
            ExecStatus::Exited { code } => (if *code == 0 { RunOutcome::Succeeded } else { RunOutcome::Failed }, Some(*code), None, None),
            ExecStatus::Signaled { signal } => (RunOutcome::Failed, None, Some(*signal), None),
            ExecStatus::TimedOut => (
                RunOutcome::TimedOut,
                None,
                None,
                out.vm_killed.then(|| "the guest ignored its deadline; the host killed the VM".to_owned()),
            ),
            ExecStatus::Cancelled => (RunOutcome::Cancelled, None, None, None),
            ExecStatus::SpawnFailed { message } => {
                (RunOutcome::Failed, None, None, Some(format!("command could not be started: {message}")))
            }
        };
        let stdout = self.capture(
            RawStream {
                name: "stdout",
                kind: ArtifactKind::Stdout,
                data: r.stdout.clone(),
                total: r.stdout_total_bytes,
                truncated: r.stdout_truncated,
                incomplete: r.output_incomplete,
            },
            &ctx,
        );
        let stderr = self.capture(
            RawStream {
                name: "stderr",
                kind: ArtifactKind::Stderr,
                data: r.stderr.clone(),
                total: r.stderr_total_bytes,
                truncated: r.stderr_truncated,
                incomplete: r.output_incomplete,
            },
            &ctx,
        );
        let evidence_status = if matches!(stdout.status, OutputStatus::Incomplete) || matches!(stderr.status, OutputStatus::Incomplete) {
            EvidenceStatus::Incomplete
        } else if matches!(stdout.status, OutputStatus::Truncated) || matches!(stderr.status, OutputStatus::Truncated) {
            EvidenceStatus::Truncated
        } else {
            EvidenceStatus::Complete
        };

        let mechanism = match r.containment {
            Containment::Cgroup2 => "guest cgroup v2 pids.max + cgroup.kill",
            Containment::RlimitNproc => "guest RLIMIT_NPROC + uid reaping (weaker fallback)",
            Containment::Unknown => "unknown (guest returned no result)",
        };
        let mut resource_evidence = vec![
            ResourceEvidence {
                resource: "guest_pids".into(),
                configured: Some(u64::from(cmd.limits.max_pids)),
                effective: Some(u64::from(cmd.limits.max_pids)),
                observed_peak: None,
                violation: r.pid_limit_hit.then_some(FailureClass::ResourceExhaustion),
                action_taken: if r.pid_limit_hit { "fork refused / tree terminated at run end".into() } else { "none".into() },
                mechanism: mechanism.into(),
            },
            ResourceEvidence {
                resource: "runtime_ms".into(),
                configured: Some(cmd.limits.timeout_ms),
                effective: Some(cmd.limits.timeout_ms),
                observed_peak: Some(r.duration_ms),
                violation: matches!(r.status, ExecStatus::TimedOut).then_some(FailureClass::ResourceExhaustion),
                action_taken: if matches!(r.status, ExecStatus::TimedOut) {
                    if out.vm_killed { "VM killed by host backstop".into() } else { "process group killed at deadline".into() }
                } else {
                    "none".into()
                },
                mechanism: "guest deadline + host backstop (monotonic)".into(),
            },
            ResourceEvidence {
                resource: "stdout_bytes".into(),
                configured: Some(cmd.limits.max_stdout_bytes),
                effective: Some(cmd.limits.max_stdout_bytes),
                observed_peak: Some(r.stdout_total_bytes),
                violation: r.stdout_truncated.then_some(FailureClass::OutputLimit),
                action_taken: if r.stdout_truncated { "truncated; remainder drained and counted".into() } else { "none".into() },
                mechanism: "guest capture cap, re-enforced by host".into(),
            },
            ResourceEvidence {
                resource: "stderr_bytes".into(),
                configured: Some(cmd.limits.max_stderr_bytes),
                effective: Some(cmd.limits.max_stderr_bytes),
                observed_peak: Some(r.stderr_total_bytes),
                violation: r.stderr_truncated.then_some(FailureClass::OutputLimit),
                action_taken: if r.stderr_truncated { "truncated; remainder drained and counted".into() } else { "none".into() },
                mechanism: "guest capture cap, re-enforced by host".into(),
            },
        ];
        if let Some(st) = stats {
            resource_evidence
                .extend(st.evidence(&CgroupSpec::for_sandbox(&g.resources, self.cfg.firecracker.vmm_overhead_mib), &g.resources));
        }
        let artifacts = [&stdout, &stderr].iter().filter_map(|c| c.artifact.clone()).collect();
        Ok(RunResult {
            run_id: run_id.clone(),
            operation_id: op.operation_id.clone(),
            sandbox_id: g.sandbox_id.clone(),
            generation: g.generation,
            outcome,
            exit_code,
            signal,
            stdout,
            stderr,
            metrics: RunMetrics {
                wall_ms: r.duration_ms,
                cpu_usage_usec: stats.and_then(|s| s.cpu_usage_usec),
                memory_peak_bytes: stats.and_then(|s| s.memory_peak_bytes),
            },
            evidence_status,
            resource_evidence,
            artifacts,
            policy_id: op.policy_id.clone(),
            image_id: g.image.image_id.clone(),
            note,
        })
    }

    /// Journal records stay small: large output lives in artifacts and is re-attached on read.
    pub(crate) fn strip_large_output(mut r: RunResult) -> RunResult {
        for c in [&mut r.stdout, &mut r.stderr] {
            if c.kept_bytes as usize > INLINE_OUTPUT_MAX && c.artifact.is_some() {
                c.data_b64.clear();
            }
        }
        r
    }

    /// Cancel an in-flight run. Never creates an operation of its own: it acts on another one.
    pub fn operation_cancel(&self, id: &OperationId) -> Result<OperationRecord> {
        let rec = self
            .journal
            .read(|s| s.operations.get(id).cloned())?
            .ok_or_else(|| AcfError::not_found(format!("operation {id} does not exist")))?;
        if rec.is_terminal() {
            return Ok(rec);
        }
        if rec.operation_type != OperationType::Exec {
            return Err(AcfError::conflict(format!("{:?} cannot be cancelled in Phase 1; only exec runs can", rec.operation_type)));
        }
        let token = self.runs.lock().map_err(|_| AcfError::internal("runs table poisoned"))?.get(id).cloned();
        match token {
            Some(t) => {
                t.cancel();
                Ok(rec)
            }
            // Non-terminal but not running in this process: orphaned by a crash. Recovery owns it.
            None => Err(AcfError::conflict("operation is not running in this host-agent instance; recovery will resolve it")),
        }
    }
}
