//! Operator methods (contract §10.3, class `operator`): `profile.reload`, `quarantine.release`,
//! `host.set_mode`, `host.acknowledge`. Each is a recorded operation; one runs at a time for the host.

use std::time::Duration;

use serde_json::json;

use super::{
    Ctx, Host,
    ops::{BeginSpec, Begun, Outcome},
};
use crate::{
    api::{AckCondition, AcknowledgeParams, HostChange, QuarantineReleaseParams, ReleaseMode, RequestedMode, SetModeParams},
    authority::{SafetyProfile, trusted_file::read_trusted},
    domain::{ContainmentReason, FailureInfo, HostMode, LifecycleState, OperationClass, OperationType, Residue},
    error::{AcfError, FailureClass, Result, SideEffect},
    store::{Entry, JournalState, OperationRecord, ProfileRecord},
    telemetry::EventDraft,
};

/// §11.2: operator operations run one at a time for the host.
fn one_at_a_time(state: &JournalState) -> Result<()> {
    match state.open().find(|o| o.operation_type.class() == OperationClass::Operator) {
        Some(o) => Err(AcfError::conflict(format!("operator operation `{}` is already in flight", o.operation_type))),
        None => Ok(()),
    }
}

impl Host {
    fn operator_spec(&self, op_type: OperationType, target: String) -> BeginSpec {
        BeginSpec {
            op_type,
            target,
            expected_generation: None,
            deadline_ms: self.cfg.operations.deadlines.operator_ms,
            run_id: None,
            sandbox: None,
            snapshot: None,
        }
    }

    /// End an operator operation whose body failed.
    fn operator_failed(&self, op: &mut OperationRecord, e: &AcfError) -> Result<()> {
        let info = self.failure_of(op, e);
        self.finish(op, Outcome::failed(info, None), vec![])
    }

    /// Load and verify the safety profile from its trusted file (SP-1).
    pub fn load_profile_file(&self) -> Result<SafetyProfile> {
        let t = read_trusted(&self.cfg.paths.profile_path, &self.cfg.security.trusted_owner_uids)
            .map_err(|e| AcfError::corrupt(format!("the safety profile is not a trusted input: {}", e.message)))?;
        let p = SafetyProfile::parse(&t.bytes, t.sha256)?;
        let bad = self.cfg.mandatory_checks(Some(&p));
        if !bad.is_empty() {
            return Err(AcfError::corrupt(format!("the safety profile does not fit this host: {}", bad.join("; "))));
        }
        Ok(p)
    }

    // ------------------------------------------------------------------ profile.reload

    /// SP-2: reloading is an operator operation and affects only later operations. An invalid
    /// profile is **refused** and the previous one stays in force.
    pub async fn profile_reload(&self, ctx: &Ctx) -> Result<OperationRecord> {
        let new = self.load_profile_file()?;
        let begun = self.begin(ctx, self.operator_spec(OperationType::ProfileReload, "host".into()), |state| {
            one_at_a_time(state)?;
            Ok(vec![])
        })?;
        let (mut op, _guard) = match begun {
            Begun::New(o, g) => (*o, g),
            Begun::Existing(r) => return Ok(*r),
        };
        let res: Result<()> = (|| {
            self.step(&mut op, "install_profile")?;
            let id = new.id().clone();
            // Operations in flight keep the profile they captured; only later ones see this one.
            self.set_profile(new);
            self.clear_containment(|r| matches!(r, ContainmentReason::InvalidProfile(_)));
            self.telemetry.events.emit(EventDraft::new(&self.wall(), "profile.reloaded").operation(&op));
            let record = ProfileRecord { profile_id: id.clone(), in_force_wall: self.wall(), by_operation: Some(op.key()) };
            let change = HostChange { profile: Some(id), ..HostChange::default() };
            self.finish(&mut op, Outcome::succeeded(Some(serde_json::to_value(change)?)), vec![Entry::Profile(record)])
        })();
        match res {
            Ok(()) => Ok(op),
            Err(e) if e.must_stop_silently() => Err(e),
            Err(e) => self.operator_failed(&mut op, &e).map(|()| op),
        }
    }

    // ------------------------------------------------------------------ host.set_mode

    /// HM-3: `DRAINING` exists for planned restarts. Operations in flight continue; no new privilege
    /// is created. `SERVING` leaves it. No other mode can be requested: the host enters those itself.
    pub async fn host_set_mode(&self, ctx: &Ctx, p: SetModeParams) -> Result<OperationRecord> {
        if p.mode == RequestedMode::Serving && self.mode() == HostMode::Containment {
            return Err(AcfError::conflict(format!(
                "the host is in CONTAINMENT and cannot be set to SERVING; the cause must be removed first: {:?}",
                self.containment_reasons()
            )));
        }
        let begun = self.begin(ctx, self.operator_spec(OperationType::HostSetMode, "host".into()), |state| {
            one_at_a_time(state)?;
            Ok(vec![])
        })?;
        let (mut op, _guard) = match begun {
            Begun::New(o, g) => (*o, g),
            Begun::Existing(r) => return Ok(*r),
        };
        let res: Result<()> = (|| {
            self.step(&mut op, "set_mode")?;
            self.set_draining(p.mode == RequestedMode::Draining);
            let mode = self.mode();
            self.telemetry.events.emit(EventDraft::new(&self.wall(), "host.mode").operation(&op).detail(json!({ "mode": mode })));
            let change = HostChange { mode: Some(mode), ..HostChange::default() };
            self.finish(&mut op, Outcome::succeeded(Some(serde_json::to_value(change)?)), vec![])
        })();
        match res {
            Ok(()) => Ok(op),
            Err(e) if e.must_stop_silently() => Err(e),
            Err(e) => self.operator_failed(&mut op, &e).map(|()| op),
        }
    }

    /// Wait until every operation of this activation has ended, or `drain_timeout` passes (HM-3).
    /// Returns how many were still in flight. Correctness never depends on this: whatever is in
    /// flight when the core stops is resolved by the next activation (§11.6).
    pub async fn drain(&self) -> usize {
        self.set_draining(true);
        let timeout = Duration::from_millis(self.cfg.operations.drain_timeout_ms);
        let _ = tokio::time::timeout(timeout, async {
            while self.operations_in_flight() > 0 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        self.operations_in_flight()
    }

    // ------------------------------------------------------------------ host.acknowledge

    /// LN-2 / LN-4: leave `CONTAINMENT` after a store regression. The operator accepts the store as
    /// authoritative; resources it does not describe stay `UNMANAGED` and are never modified. The
    /// commit sequence is advanced past every ownership marker on disk, so nothing the store writes
    /// from now on can be mistaken for something older than those markers.
    pub async fn host_acknowledge(&self, ctx: &Ctx, p: AcknowledgeParams) -> Result<OperationRecord> {
        let AckCondition::StoreRegression = p.condition;
        if !self.containment_reasons().iter().any(|r| matches!(r, ContainmentReason::StoreRegression(_))) {
            return Err(AcfError::conflict("there is no store regression to acknowledge"));
        }
        let begun = self.begin(ctx, self.operator_spec(OperationType::HostAcknowledge, "host".into()), |state| {
            one_at_a_time(state)?;
            Ok(vec![])
        })?;
        let (mut op, _guard) = match begun {
            Begun::New(o, g) => (*o, g),
            Begun::Existing(r) => return Ok(*r),
        };
        let res: Result<()> = async {
            let newest_marker = self.scan_markers()?.newest_seq_of_this_lineage;
            op.step = Some("acknowledge".into());
            op.state = crate::domain::OperationState::InProgress;
            op.updated_wall = self.wall();
            self.journal.jump_sequence(newest_marker, vec![Entry::Operation(Box::new(op.clone()))])?;
            self.clear_containment(|r| matches!(r, ContainmentReason::StoreRegression(_)));
            // The recovery that the regression suspended runs now, under the acknowledged store.
            let report = self.recover_generations().await?;
            self.telemetry.events.emit(EventDraft::new(&self.wall(), "host.acknowledged").operation(&op));
            let change = HostChange {
                mode: Some(self.mode()),
                note: Some(format!(
                    "store accepted as authoritative; {} unmanaged resource(s) are reported and left untouched",
                    report.unmanaged
                )),
                ..HostChange::default()
            };
            self.finish(&mut op, Outcome::succeeded(Some(serde_json::to_value(change)?)), vec![])
        }
        .await;
        match res {
            Ok(()) => Ok(op),
            Err(e) if e.must_stop_silently() => Err(e),
            Err(e) => self.operator_failed(&mut op, &e).map(|()| op),
        }
    }

    // ------------------------------------------------------------------ quarantine.release

    /// QR-2 – QR-4. The operator asserts something about a quarantined generation; the host acts on
    /// the assertion and then **observes**. Only observed absence makes the generation `DESTROYED`
    /// and releases its lease. If observation contradicts the assertion the release ends `FAILED`
    /// and the generation stays quarantined.
    pub async fn quarantine_release(&self, ctx: &Ctx, p: QuarantineReleaseParams) -> Result<OperationRecord> {
        let key = (p.sandbox_id.clone(), p.generation);
        let target = p.sandbox_id.to_string();
        let mut spec = self.operator_spec(OperationType::QuarantineRelease, target.clone());
        spec.expected_generation = Some(p.generation);
        let begun = self.begin(ctx, spec, |state| {
            let g = state.generations.get(&key).ok_or_else(|| AcfError::not_found("no such sandbox generation"))?;
            if g.quarantined.is_none() {
                return Err(AcfError::conflict("the generation is not quarantined; use `sandbox.destroy`"));
            }
            one_at_a_time(state)?;
            Ok(vec![])
        })?;
        let (mut op, _guard) = match begun {
            Begun::New(o, g) => (*o, g),
            Begun::Existing(r) => return Ok(*r),
        };
        let res = self.release_body(&mut op, &p).await;
        match res {
            Ok(()) => Ok(op),
            Err(e) if e.must_stop_silently() => Err(e),
            Err(e) => self.operator_failed(&mut op, &e).map(|()| op),
        }
    }

    /// The step name records the assertion durably before anything is done (QR-4, OP-3), so an
    /// inherited release can be re-driven in the mode the operator chose.
    pub(crate) fn release_step(mode: ReleaseMode) -> &'static str {
        match mode {
            ReleaseMode::ForceDestroy => "release_force_destroy",
            ReleaseMode::DeclareAbsent => "release_declare_absent",
        }
    }

    pub(crate) fn release_mode_of(step: Option<&str>) -> Option<ReleaseMode> {
        match step {
            Some("release_force_destroy") => Some(ReleaseMode::ForceDestroy),
            Some("release_declare_absent") => Some(ReleaseMode::DeclareAbsent),
            _ => None,
        }
    }

    pub(crate) async fn release_body(&self, op: &mut OperationRecord, p: &QuarantineReleaseParams) -> Result<()> {
        self.step(op, Self::release_step(p.mode))?;
        let g = self.gen_record(&p.sandbox_id, p.generation)?;
        let handle = g.backend_handle();
        let before = self.backend.residue(&handle).await?;
        if p.mode == ReleaseMode::ForceDestroy {
            // The assertion replaces the ownership marker, never the process identity: something that
            // is not the recorded instance is still never signalled (OB-3).
            let grace = self.stop_grace();
            let _ = self.backend.stop(&handle, grace).await;
            self.backend.force_teardown(&handle).await?;
        }
        let after = self.backend.residue(&handle).await?;
        // What the host observed, in the operation's result: the assertion is the operator's, the
        // observation is the host's (QR-4).
        let list = |found: &[String]| if found.is_empty() { "nothing".to_owned() } else { found.join(", ") };
        let observed = serde_json::to_value(HostChange {
            note: Some(format!("assertion {:?}; found before: {}; found after: {}", p.mode, list(&before), list(&after))),
            ..HostChange::default()
        })?;
        if !after.is_empty() {
            let failure = FailureInfo::new(
                FailureClass::Quarantined,
                format!("observation contradicts the assertion; these recorded resources still exist: {}", after.join(", ")),
                SideEffect::Possible,
            );
            let residue = Residue::Generation { sandbox_id: p.sandbox_id.clone(), generation: p.generation };
            let mut out = Outcome::failed(failure, Some(residue)).quarantined();
            out.result = Some(observed);
            return self.finish(op, out, vec![]);
        }
        // Proven absent: the generation is DESTROYED and its lease and identifiers are released (QR-3).
        self.lifetime.disarm(&g.sandbox_ref().jail_id());
        let mut d = g.clone();
        d.state = LifecycleState::Destroyed; // a quarantined generation may be in any state; release is the one way out
        d.quarantined = None;
        d.quarantined_ms = None;
        d.process = None;
        d.updated_wall = self.wall();
        let mut entries = vec![];
        if let Ok(mut sb) = self.sandbox_record(&p.sandbox_id)
            && sb.current == p.generation
        {
            sb.destroyed_ms = Some(self.clock.wall_ms());
            entries.push(Entry::Sandbox(sb));
        }
        entries.push(Entry::Generation(Box::new(d)));
        self.telemetry.metrics.incr("quarantine_releases", 1);
        self.finish(op, Outcome::succeeded(Some(observed)), entries)
    }
}
