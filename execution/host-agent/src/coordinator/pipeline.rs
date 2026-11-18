//! The admission pipeline of the core (contract §17.4, PA-1). Every ingress endpoint feeds this one
//! function (AU-1, SEC-012); nothing reaches a flow any other way.
//!
//! ```text
//! protocol version → schema → enrolment re-check → role → known operation? → host mode → rate
//!        → acceptance horizon → (flow) tags · safety profile · state · token · capacity → BEGIN
//! ```
//!
//! *Known operation?* A request that names an operation this host already holds is answered with
//! that operation (§11.4). It creates nothing, so nothing that refuses new work can refuse it.
//!
//! The edge has already authenticated the peer and validated the request once. The core trusts the
//! edge for the peer's enrolled identity and role **and for nothing else** (PD-2): it validates the
//! request again and checks that the claimed `(peer_id, role)` is enrolled *now*, so a compromised
//! edge gains the authority of an enrolled peer, bounded by the safety profile, and no more.

use std::{sync::Arc, time::Duration};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use super::{Ctx, Host};
use crate::{
    api::{Command, ReadResult, RequestEnvelope, ResponseEnvelope, ValidatedRequest, protocol_supported, within_acceptance_horizon},
    domain::{
        AuthorityContext, HostMode, Issuer, Method, OperationClass, OperationType, PeerId, Role, Transport, fingerprint::fingerprint,
    },
    error::{AcfError, FailureClass, Result},
    store::{OpKey, OperationRecord},
};

/// What the edge states about the peer behind a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PeerContext {
    pub peer_id: PeerId,
    pub role: Role,
    pub transport: Transport,
}

impl Host {
    /// Handle one request from an authenticated peer. Never fails: every outcome is a response.
    pub async fn handle(self: &Arc<Self>, peer: &PeerContext, env: RequestEnvelope) -> ResponseEnvelope {
        // The request id is echoed only if it is a valid label: nothing unbounded is reflected.
        let rid =
            env.request_id.clone().filter(|r| crate::domain::validate_label("request_id", r, crate::domain::MAX_REQUEST_ID_BYTES).is_ok());
        match self.admit(peer, env).await {
            Ok(resp) => resp,
            Err(e) => {
                self.telemetry.metrics.incr_labelled("refusals", "class", &format!("{:?}", e.class), 1);
                ResponseEnvelope::refused(rid, &e, Some(self.as_of()))
            }
        }
    }

    async fn admit(self: &Arc<Self>, peer: &PeerContext, env: RequestEnvelope) -> Result<ResponseEnvelope> {
        // VR-1: an unsupported protocol major is refused before anything else is looked at.
        if !protocol_supported(&env.protocol) {
            self.telemetry.metrics.incr("protocol_errors", 1);
            return Err(AcfError::protocol(format!("this host speaks `{}`", crate::api::PROTOCOL)));
        }
        let req = env.validate()?;
        // PD-2 / AU-5: the edge's statement is checked against the enrolment in force now.
        if !self.enrolment().grants(&peer.peer_id, peer.role) {
            self.telemetry.metrics.incr("auth_denied", 1);
            return Err(AcfError::authentication("the peer is not enrolled on this host"));
        }
        let method = req.command.method();
        if !method.allowed_for(peer.role) {
            self.telemetry.metrics.incr("authorization_denied", 1);
            return Err(AcfError::authorization(format!("role `{}` may not call `{method}`", role_name(peer.role))));
        }
        let mode = self.mode();
        let authority = AuthorityContext {
            peer_id: peer.peer_id.clone(),
            role: peer.role,
            owner_scope: req.owner_scope.clone(),
            on_behalf_of: req.on_behalf_of.clone(),
        };
        let rid = req.request_id.clone();
        let ops = &self.cfg.operations;
        // §11.4, RY-7, API-8: a request that names an operation this host already holds is resolution
        // of that operation, never a second attempt. It creates nothing, so it is served wherever a
        // read is served: the host mode, the operation rate and the age of `issued_at` refuse new
        // work, and this is not new work. A caller whose response was lost while the host began to
        // drain must still be able to learn what happened.
        if mode.admits(OperationClass::Read)
            && let Some(key) = self.known_operation(&authority, &req)?
        {
            // A lookup is bounded like a read, except for containment, which load never refuses (CC-4).
            if method.class() != OperationClass::Containment
                && !self.rate.allow(&peer.peer_id, true, ops.read_rate_limit_per_minute, self.clock.monotonic_ns())
            {
                return Err(AcfError::exhausted("read rate limit reached for this peer"));
            }
            return self.operation_response(rid, &key);
        }
        if !mode.admits(method.class()) {
            return Err(self.not_serving(mode, method));
        }
        match method.class() {
            OperationClass::Read => {
                if !self.rate.allow(&peer.peer_id, true, ops.read_rate_limit_per_minute, self.clock.monotonic_ns()) {
                    return Err(AcfError::exhausted("read rate limit reached for this peer"));
                }
                let result = self.read(&authority, req.command)?;
                Ok(ResponseEnvelope::result(rid, result, self.as_of()))
            }
            class => {
                // CC-4: a containment request is never refused for rate or load.
                if class != OperationClass::Containment
                    && !self.rate.allow(&peer.peer_id, false, ops.rate_limit_per_minute, self.clock.monotonic_ns())
                {
                    return Err(AcfError::exhausted("operation rate limit reached for this peer (operation_rate_limit)"));
                }
                // PS-9: while the store runs on its reserve, no new privilege is created.
                if class == OperationClass::Granting && self.journal.reserve_released() {
                    return Err(AcfError::exhausted("the state filesystem is full; the store is running on its reserved capacity"));
                }
                let issued_at_ms = req.issued_at_ms.ok_or_else(|| AcfError::validation("issued_at is required"))?;
                if !within_acceptance_horizon(issued_at_ms, self.clock.wall_ms(), ops.acceptance_horizon_ms, ops.clock_skew_tolerance_ms) {
                    return Err(AcfError::new(
                        FailureClass::ExpiredRequest,
                        "issued_at is outside the acceptance horizon; resolve the operation with `operation.get`, or issue a new one",
                    ));
                }
                let key = self.operate(authority, req).await?;
                self.operation_response(rid, &key)
            }
        }
    }

    /// §11.4: the operation a request names, if this host already holds it. Same id and same
    /// fingerprint: it *is* that operation. Same id, another fingerprint: a conflict. A `retry` for
    /// an id the host does not hold: `NOT_FOUND`, never a new operation (API-8). The same three
    /// answers are given again inside the BEGIN commit, which is what decides between two requests
    /// that arrive at once; this is the path of the caller who asks again later.
    fn known_operation(&self, authority: &AuthorityContext, req: &ValidatedRequest) -> Result<Option<OpKey>> {
        let (Some(op_type), Some(operation_id)) = (OperationType::of(req.command.method()), req.operation_id.as_ref()) else {
            return Ok(None);
        };
        let key = OpKey::new(&authority.tags(), operation_id);
        let fp = fingerprint(op_type, &req.command.params_value()?)?;
        match self.journal.read(|s| s.operations.get(&key).map(|o| o.fingerprint == fp))? {
            Some(true) => Ok(Some(key)),
            Some(false) => Err(AcfError::new(
                FailureClass::IdempotencyConflict,
                format!("operation id {} was already used for a different request", key.operation_id),
            )),
            None if req.retry => Err(AcfError::not_found(format!(
                "operation {} is not known to this host; a retry is never treated as a new request",
                key.operation_id
            ))),
            None => Ok(None),
        }
    }

    fn not_serving(&self, mode: HostMode, method: Method) -> AcfError {
        let why = match mode {
            HostMode::ReadOnly => self.journal.write_block().map(|b| b.message()).unwrap_or_default(),
            HostMode::Containment => self.containment_reasons().iter().map(|r| format!("{r:?}")).collect::<Vec<_>>().join("; "),
            _ => String::new(),
        };
        AcfError::new(
            FailureClass::HostNotServing,
            format!("the host is {mode:?} and does not serve `{method}` ({:?} class). {why}", method.class()),
        )
    }

    /// The answer to an accepted request: the operation as of committed state (API-6, API-7).
    pub(crate) fn operation_response(&self, request_id: Option<String>, key: &OpKey) -> Result<ResponseEnvelope> {
        let (view, as_of) = self.journal.read(|s| {
            let rec = s.operations.get(key).ok_or_else(|| AcfError::internal("an accepted operation has no record"))?;
            Ok::<_, AcfError>((
                self.operation_view(s, rec),
                crate::api::AsOf { lineage: self.journal.lineage().to_owned(), sequence: s.last_seq },
            ))
        })??;
        Ok(ResponseEnvelope::operation(request_id, view, as_of))
    }

    /// Run a non-read command. Returns the key of the operation once BEGIN is durable **and** either
    /// the operation has ended or the caller's `wait` has elapsed (API-6). An `Err` is a refusal:
    /// nothing was recorded.
    ///
    /// The operation runs in its own task, so neither a slow caller, nor a disconnect, nor the end
    /// of the wait changes what happens to it (OP-16, FS-6).
    async fn operate(self: &Arc<Self>, authority: AuthorityContext, req: ValidatedRequest) -> Result<OpKey> {
        let method = req.command.method();
        let op_type = OperationType::of(method).ok_or_else(|| AcfError::internal("a read reached the operation path"))?;
        let operation_id = req.operation_id.clone().ok_or_else(|| AcfError::validation("operation_id is required"))?;
        let (tx, mut begun) = watch::channel(None);
        let ctx = Ctx {
            authority,
            issuer: Issuer::Peer,
            profile: self.profile(),
            operation_id,
            retry: req.retry,
            issued_at: req.issued_at.clone().unwrap_or_default(),
            fingerprint: fingerprint(op_type, &req.command.params_value()?)?,
            begun: Some(Arc::new(tx)),
        };
        let key = ctx.key();
        let wait_max = self.cfg.operations.wait_max_ms;
        let wait = Duration::from_millis(req.wait_ms.unwrap_or(wait_max).min(wait_max));
        let me = Arc::clone(self);
        let command = req.command;
        let mut task = self.tracker.spawn(async move { me.run(&ctx, command).await });

        let finished = tokio::select! {
            r = &mut task => Some(r),
            () = tokio::time::sleep(wait) => None,
        };
        let outcome = match finished {
            Some(r) => r,
            // The wait is over. Answer as soon as there is a durable record to answer with; until
            // BEGIN the request can still be refused, and that refusal is the answer.
            None => {
                tokio::select! {
                    r = &mut task => r,
                    _ = begun.wait_for(Option::is_some) => return Ok(key),
                }
            }
        };
        match outcome {
            Ok(Ok(rec)) => Ok(rec.key()),
            // Superseded (or, in tests, a simulated crash): the record says how it ended.
            Ok(Err(e)) if e.must_stop_silently() && self.operation_record(&key).is_ok() => Ok(key),
            Ok(Err(e)) => {
                // A refusal leaves no record. If a record exists the failure came after BEGIN from a
                // path that could not finish the operation; the caller is told the truth: it exists.
                if self.operation_record(&key).is_ok() && begun.borrow().is_some() { Ok(key) } else { Err(e) }
            }
            Err(join) => {
                tracing::error!(error = %join, "an operation task ended abnormally");
                if self.operation_record(&key).is_ok() { Ok(key) } else { Err(AcfError::internal("the operation could not be started")) }
            }
        }
    }

    /// Route a command to its flow.
    pub(crate) async fn run(&self, ctx: &Ctx, command: Command) -> Result<OperationRecord> {
        match command {
            Command::SandboxCreate(p) => self.sandbox_create(ctx, p).await,
            Command::SandboxStart(t) => self.sandbox_start(ctx, t).await,
            Command::ExecRun(p) => self.exec(ctx, p).await,
            Command::SnapshotCreate(p) => self.snapshot_create(ctx, p).await,
            Command::SnapshotRestore(p) => self.snapshot_restore(ctx, p).await,
            Command::SandboxStop(t) => self.sandbox_stop(ctx, t).await,
            Command::SandboxDestroy(t) => self.sandbox_destroy(ctx, t).await,
            Command::SnapshotDelete(p) => self.snapshot_delete(ctx, p).await,
            Command::OperationCancel(s) => self.operation_cancel(ctx, s).await,
            Command::ProfileReload => self.profile_reload(ctx).await,
            Command::QuarantineRelease(p) => self.quarantine_release(ctx, p).await,
            Command::HostSetMode(p) => self.host_set_mode(ctx, p).await,
            Command::HostAcknowledge(p) => self.host_acknowledge(ctx, p).await,
            Command::SandboxInspect(_)
            | Command::SandboxList(_)
            | Command::SnapshotList(_)
            | Command::OperationGet(_)
            | Command::OperationList(_)
            | Command::RunInspect(_)
            | Command::RunOutput(_)
            | Command::HostInfo
            | Command::HostMetrics => Err(AcfError::internal("a read reached the operation path")),
        }
    }

    /// Serve a read from committed state (API-10, API-12).
    fn read(&self, authority: &AuthorityContext, command: Command) -> Result<ReadResult> {
        match command {
            Command::HostInfo => self.host_info().map(|i| ReadResult::HostInfo(Box::new(i))),
            Command::HostMetrics => Ok(ReadResult::Metrics(self.metrics())),
            Command::SandboxInspect(s) => self.sandbox_inspect(authority, &s.sandbox).map(ReadResult::Sandbox),
            Command::SandboxList(p) => self.sandbox_list(authority, &p).map(ReadResult::Sandboxes),
            Command::SnapshotList(p) => self.snapshot_list(authority, &p).map(ReadResult::Snapshots),
            Command::OperationGet(s) => self.operation_get(authority, &s.operation_id).map(|v| ReadResult::Operation(Box::new(v))),
            Command::OperationList(p) => self.operation_list(authority, &p).map(ReadResult::Operations),
            Command::RunInspect(s) => self.run_inspect(authority, &s.run_id),
            Command::RunOutput(p) => self.run_output(authority, &p).map(ReadResult::Output),
            _ => Err(AcfError::internal("an operation reached the read path")),
        }
    }
}

fn role_name(role: Role) -> &'static str {
    match role {
        Role::Observer => "observer",
        Role::Caller => "caller",
        Role::Operator => "operator",
    }
}
