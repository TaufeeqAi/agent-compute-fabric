//! Read-only queries (no operation record, no mutation).

use super::Host;
use crate::{
    domain::{OperationPhase, RunOutcome},
    error::{AcfError, Result},
    ids::{OperationId, RunId},
    operation::OperationRecord,
    protocol::{HostInfo, OperationView, PROTOCOL, ResponseBody, SandboxView, SnapshotView},
};

impl Host {
    pub fn host_info(&self) -> Result<HostInfo> {
        let (live, snaps) =
            self.journal.read(|s| (s.live_generations().count(), s.snapshots.values().filter(|x| x.holds_storage()).count()))?;
        Ok(HostInfo {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            protocol: PROTOCOL.to_owned(),
            instance_id: self.instance_id.clone(),
            mode: if self.journal.is_quarantined().is_some() { "read_only_quarantine".into() } else { "normal".into() },
            backend: self.backend.identity().clone(),
            capabilities: self.backend.capabilities().clone(),
            policy: self.policy().id().clone(),
            journal_integrity: self.journal_integrity.clone(),
            live_sandboxes: live,
            snapshots: snaps,
        })
    }

    pub fn metrics(&self) -> serde_json::Value {
        let m = &self.telemetry.metrics;
        if let Ok((live, snaps)) =
            self.journal.read(|s| (s.live_generations().count(), s.snapshots.values().filter(|x| x.holds_storage()).count()))
        {
            m.set_gauge("live_sandboxes", i64::try_from(live).unwrap_or(i64::MAX));
            m.set_gauge("snapshots", i64::try_from(snaps).unwrap_or(i64::MAX));
        }
        m.snapshot()
    }

    /// By id or by name. Names resolve only here, for reads (spec §12.5).
    pub fn sandbox_inspect(&self, selector: &str) -> Result<SandboxView> {
        self.journal.read(|s| {
            let sb = match crate::ids::SandboxId::parse(selector) {
                Ok(id) => s.sandboxes.get(&id),
                Err(_) => s.sandbox_by_name(selector),
            }
            .ok_or_else(|| AcfError::not_found(format!("no sandbox `{selector}`")))?;
            let g =
                s.generations.get(&(sb.sandbox_id.clone(), sb.current)).ok_or_else(|| AcfError::internal("generation record missing"))?;
            Ok(self.sandbox_view(g, sb.name.clone()))
        })?
    }

    pub fn sandbox_list(&self) -> Result<Vec<SandboxView>> {
        self.journal.read(|s| {
            let mut v: Vec<SandboxView> = s
                .sandboxes
                .values()
                .filter_map(|sb| s.generations.get(&(sb.sandbox_id.clone(), sb.current)).map(|g| self.sandbox_view(g, sb.name.clone())))
                .filter(|v| v.state != crate::domain::LifecycleState::Destroyed)
                .collect();
            v.sort_by(|a, b| a.updated.cmp(&b.updated).then_with(|| a.sandbox_id.cmp(&b.sandbox_id)));
            v
        })
    }

    pub fn snapshot_list(&self) -> Result<Vec<SnapshotView>> {
        self.journal.read(|s| {
            let mut v: Vec<SnapshotView> = s.snapshots.values().filter(|x| x.holds_storage()).map(|x| self.snapshot_view(x)).collect();
            v.sort_by(|a, b| a.created.cmp(&b.created).then_with(|| a.snapshot.snapshot_id.cmp(&b.snapshot.snapshot_id)));
            v
        })
    }

    pub fn operation_record(&self, id: &OperationId) -> Result<OperationRecord> {
        self.journal.read(|s| s.operations.get(id).cloned())?.ok_or_else(|| AcfError::not_found(format!("operation {id} does not exist")))
    }

    /// Resolve an operation by id — the way a client recovers from a lost response (spec §8.4).
    pub fn operation_get(&self, id: &OperationId) -> Result<crate::protocol::ResponseEnvelope> {
        Ok(self.envelope(&self.operation_record(id)?, None))
    }

    pub fn operation_view(&self, rec: &OperationRecord) -> OperationView {
        OperationView {
            operation_id: rec.operation_id.clone(),
            operation_type: rec.operation_type,
            status: rec.status,
            phase: rec.phase.clone(),
            resource_id: rec.resource_id.clone(),
            failure: rec.failure.clone(),
            result: rec.result.clone(),
            run_id: rec.run_id.clone(),
            updated: rec.updated_wall.clone(),
        }
    }

    /// A finished run's full result (output re-attached from artifacts), or the operation view
    /// while it is still running.
    pub fn run_inspect(&self, run_id: &RunId) -> Result<ResponseBody> {
        let rec = self
            .journal
            .read(|s| s.operations.values().find(|o| o.run_id.as_ref() == Some(run_id)).cloned())?
            .ok_or_else(|| AcfError::not_found(format!("run {run_id} does not exist")))?;
        if matches!(rec.phase, OperationPhase::Terminal)
            && let Some(ResponseBody::Run(mut r)) = rec.result.as_ref().and_then(|v| serde_json::from_value::<ResponseBody>(v.clone()).ok())
        {
            self.hydrate_run(&mut r);
            return Ok(ResponseBody::Run(r));
        }
        let _ = RunOutcome::Running;
        Ok(ResponseBody::Operation(self.operation_view(&rec)))
    }
}
