//! begin / step / finish — the operation protocol (spec §12–§14).

use serde_json::Value;

use super::{Ctx, Host, fault};
use crate::{
    clock::MonotonicRef,
    domain::{
        FailureInfo, LifecycleState, OperationPhase, OperationStatus, OperationType, RunResult, SnapshotRef, digest_label,
        require_transition,
    },
    error::{AcfError, Result},
    ids::{Generation, RunId, SandboxId},
    operation::{Entry, GenerationRecord, JournalState, OperationRecord, fingerprint},
    protocol::{ErrorBody, PROTOCOL, ResponseBody, ResponseEnvelope, SandboxView, SnapshotView, status_for_pre_record_error},
};

pub(crate) struct BeginSpec {
    pub op_type: OperationType,
    pub resource_id: String,
    pub expected_generation: Option<Generation>,
    /// The semantic request body (no operation id / retry flag / timestamps) — fingerprinted.
    pub body: Value,
    pub deadline_ms: u64,
    pub run_id: Option<RunId>,
    pub sandbox: Option<(SandboxId, Generation)>,
    pub snapshot: Option<SnapshotRef>,
}

pub(crate) enum Begun {
    New(Box<OperationRecord>),
    /// Same operation id **and** same fingerprint: return what exists, mutate nothing.
    Existing(Box<OperationRecord>),
}

impl Host {
    /// Atomically: reject a reused id with a different request, reject a `retry` whose record is
    /// missing, run `precheck` (preconditions + admission → extra entries) and append `ACCEPTED`.
    pub(crate) fn begin(&self, ctx: &Ctx, spec: BeginSpec, precheck: impl FnOnce(&JournalState) -> Result<Vec<Entry>>) -> Result<Begun> {
        // Process death with the request accepted but nothing durable: recovery must find nothing.
        fault!(self, BeforeJournalWrite, &format!("{:?}", spec.op_type));
        let fp = fingerprint(spec.op_type, &spec.body)?;
        let now = self.clock.now_ref();
        let deadline = MonotonicRef { boot_id: now.boot_id.clone(), ns: now.ns.saturating_add(spec.deadline_ms.saturating_mul(1_000_000)) };
        let wall = self.wall();
        let id = ctx.operation_id.clone();
        let rec = OperationRecord {
            operation_id: id.clone(),
            operation_type: spec.op_type,
            fingerprint: fp.clone(),
            request_schema_version: PROTOCOL.to_owned(),
            resource_id: spec.resource_id,
            expected_generation: spec.expected_generation,
            created_wall: wall.clone(),
            created_mono: now,
            deadline,
            caller: ctx.caller.clone(),
            policy_id: ctx.policy.id().clone(),
            phase: OperationPhase::Accepted,
            status: OperationStatus::Accepted,
            failure: None,
            result: None,
            run_id: spec.run_id,
            sandbox: spec.sandbox,
            snapshot: spec.snapshot,
            recovery_id: None,
            updated_wall: wall,
        };
        let retry = ctx.retry;
        let begun = self.journal.commit_with(|state| {
            if let Some(existing) = state.operations.get(&id) {
                return if existing.fingerprint == fp {
                    Ok((vec![], Begun::Existing(Box::new(existing.clone()))))
                } else {
                    Err(AcfError::conflict(format!("operation id {id} was already used for a different request")))
                };
            }
            if retry {
                return Err(AcfError::not_found(format!(
                    "operation {id} is not known to this host; a retry will not be reinterpreted as a new request"
                )));
            }
            let mut entries = precheck(state)?;
            entries.insert(0, Entry::Operation(Box::new(rec.clone())));
            Ok((entries, Begun::New(Box::new(rec.clone()))))
        })?;
        if let Begun::New(r) = &begun {
            self.telemetry.metrics.incr_labelled("operations_accepted", "type", &format!("{:?}", r.operation_type), 1);
            self.telemetry.events.emit(
                &self.wall(),
                "operation.accepted",
                Some(r.operation_id.as_str()),
                Some(&r.resource_id),
                serde_json::json!({"type": r.operation_type}),
            );
        }
        Ok(begun)
    }

    /// Write-ahead intent for a privileged step: if we crash after this record, recovery knows the
    /// step *may* have run.
    pub(crate) fn step(&self, op: &mut OperationRecord, name: &str) -> Result<()> {
        op.phase = OperationPhase::InProgress { step: name.to_owned() };
        op.status = OperationStatus::InProgress;
        op.updated_wall = self.wall();
        self.journal.commit(vec![Entry::Operation(Box::new(op.clone()))])?;
        self.telemetry.events.emit(
            &self.wall(),
            "operation.step",
            Some(op.operation_id.as_str()),
            Some(&op.resource_id),
            serde_json::json!({"step": name}),
        );
        Ok(())
    }

    /// Terminal commit: operation + any lifecycle/snapshot records in **one** atomic append.
    pub(crate) fn finish(
        &self,
        op: &mut OperationRecord,
        status: OperationStatus,
        failure: Option<FailureInfo>,
        body: Option<ResponseBody>,
        mut extra: Vec<Entry>,
    ) -> Result<()> {
        op.phase = OperationPhase::Terminal;
        op.status = status;
        op.failure = failure;
        op.result = body.map(|b| serde_json::to_value(&b)).transpose()?;
        op.updated_wall = self.wall();
        extra.insert(0, Entry::Operation(Box::new(op.clone())));
        self.journal.commit(extra)?;
        // Process death with the result durable but unsent: the client can still resolve it by id.
        fault!(self, AfterTerminalCommitBeforeResponse, &format!("{:?}", op.operation_type));
        let m = &self.telemetry.metrics;
        m.incr_labelled("operations_finished", "status", &format!("{status:?}"), 1);
        if let Some(f) = &op.failure {
            m.incr_labelled("operation_failures", "class", &format!("{:?}", f.class), 1);
        }
        self.telemetry.events.emit(
            &self.wall(),
            "operation.finished",
            Some(op.operation_id.as_str()),
            Some(&op.resource_id),
            serde_json::json!({"status": status, "failure": op.failure}),
        );
        Ok(())
    }

    /// A generation record moved to `to`, with `Paused` bookkeeping. Validates the transition.
    pub(crate) fn moved(&self, g: &GenerationRecord, to: LifecycleState) -> Result<GenerationRecord> {
        require_transition(g.state, to)?;
        let mut n = g.clone();
        n.paused_from = (to == LifecycleState::Paused).then_some(g.state);
        n.state = to;
        n.updated_wall = self.wall();
        Ok(n)
    }

    pub(crate) fn commit_gen(&self, g: &GenerationRecord) -> Result<()> {
        self.journal.commit(vec![Entry::Generation(Box::new(g.clone()))])
    }

    pub(crate) fn current_gen(&self, id: &SandboxId, expect: Generation) -> Result<GenerationRecord> {
        self.journal.read(|s| {
            let sb = s.sandboxes.get(id).ok_or_else(|| AcfError::not_found(format!("sandbox {id} does not exist")))?;
            if sb.current != expect {
                return Err(AcfError::conflict(format!("sandbox {id} is at generation {}, not {expect} (stale reference)", sb.current)));
            }
            s.generations
                .get(&(id.clone(), expect))
                .cloned()
                .ok_or_else(|| AcfError::internal(format!("generation record {id}@{expect} is missing")))
        })?
    }

    /// Direct lookup of one generation (no staleness check) for internal flows.
    pub(crate) fn gen_record(&self, id: &SandboxId, g: Generation) -> Result<GenerationRecord> {
        self.journal
            .read(|s| s.generations.get(&(id.clone(), g)).cloned())?
            .ok_or_else(|| AcfError::internal(format!("generation record {id}@{g} is missing")))
    }

    /// Build the response for an operation record (terminal or not).
    pub(crate) fn envelope(&self, rec: &OperationRecord, request_id: Option<String>) -> ResponseEnvelope {
        let body = rec.result.as_ref().and_then(|v| serde_json::from_value::<ResponseBody>(v.clone()).ok()).map(|b| self.hydrate(b));
        ResponseEnvelope {
            protocol: PROTOCOL.to_owned(),
            request_id,
            operation_id: Some(rec.operation_id.clone()),
            status: rec.status,
            result: body,
            error: rec.failure.as_ref().map(ErrorBody::from_failure),
        }
    }

    pub(crate) fn error_envelope(&self, e: &AcfError, request_id: Option<String>, op: Option<crate::ids::OperationId>) -> ResponseEnvelope {
        let info = FailureInfo::from(e);
        ResponseEnvelope {
            protocol: PROTOCOL.to_owned(),
            request_id,
            operation_id: op,
            status: status_for_pre_record_error(e),
            result: None,
            error: Some(ErrorBody::from_failure(&info)),
        }
    }

    /// Re-attach large output that was spilled to artifacts so journal records stay small.
    fn hydrate(&self, body: ResponseBody) -> ResponseBody {
        match body {
            ResponseBody::Run(mut r) => {
                self.hydrate_run(&mut r);
                ResponseBody::Run(r)
            }
            other => other,
        }
    }

    pub(crate) fn hydrate_run(&self, r: &mut RunResult) {
        use base64::{Engine, engine::general_purpose::STANDARD};
        for cap in [&mut r.stdout, &mut r.stderr] {
            if cap.data_b64.is_empty()
                && cap.kept_bytes > 0
                && let Some(a) = &cap.artifact
            {
                match self.artifacts.get(&a.artifact_id, cap.kept_bytes + 16) {
                    Ok((_, bytes)) => cap.data_b64 = STANDARD.encode(bytes),
                    Err(e) => r.note = Some(format!("{} | output artifact unreadable: {}", r.note.clone().unwrap_or_default(), e.message)),
                }
            }
        }
    }

    pub(crate) fn sandbox_view(&self, g: &GenerationRecord, name: Option<String>) -> SandboxView {
        SandboxView {
            sandbox_id: g.sandbox_id.clone(),
            generation: g.generation,
            name,
            state: g.state,
            resources: g.resources.clone(),
            image: g.image.clone(),
            process: g.process().cloned(),
            security_profile_id: g.security_profile_id.clone(),
            last_run: g.last_run.clone(),
            source_snapshot: g.source_snapshot.clone(),
            failure: g.failure.clone(),
            quarantined: g.quarantined.clone(),
            notes: vec![],
            updated: g.updated_wall.clone(),
        }
    }

    pub(crate) fn snapshot_view(&self, s: &crate::operation::SnapshotRecord) -> SnapshotView {
        SnapshotView {
            snapshot: s.snapshot_ref(),
            name: s.name.clone(),
            state: s.state,
            size_bytes: if s.actual_bytes > 0 { s.actual_bytes } else { s.reserved_bytes },
            source_sandbox: s.source.clone(),
            manifest_digest: s.manifest_digest.as_deref().map(digest_label),
            restore_count: s.restore_count,
            created: s.created_wall.clone(),
            failure: s.failure.clone(),
        }
    }

    /// Decide the terminal status after a failure *and* an attempted compensation.
    ///
    /// `world_clean` is what we **observed** (teardown reported `Removed`/`Absent`). A definite
    /// error is `FAILED`; a possibly-side-effecting error is `FAILED` only if the world is
    /// provably clean, else `UNKNOWN` (spec §14.3).
    pub(crate) fn status_after_failure(e: &AcfError, world_clean: bool) -> OperationStatus {
        if e.is_definite() || world_clean { OperationStatus::Failed } else { OperationStatus::Unknown }
    }
}
