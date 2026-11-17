//! Request routing. One arm per method; mutating methods return the operation's envelope, reads
//! return their body directly. Authorization of *capabilities* is the policy's job (inside the
//! flows); this layer only adds the one extra gate that has no sandbox to hang off: policy reload.

use std::sync::Arc;

use crate::{
    admission::{EffectivePolicy, trusted_file::read_trusted},
    config::SecurityConfig,
    domain::{CallerIdentity, OperationStatus},
    error::{AcfError, Result},
    lifecycle::Host,
    operation::OperationRecord,
    protocol::{PROTOCOL, Request, RequestEnvelope, ResponseBody, ResponseEnvelope},
};

fn reload_policy(host: &Host, sec: &SecurityConfig, caller: &CallerIdentity) -> Result<ResponseBody> {
    // Changing what every caller may do is an administrative act, not a caller capability.
    if !sec.trusted_owner_uids.contains(&caller.uid) {
        return Err(AcfError::authorization("policy reload is restricted to trusted administrators"));
    }
    let t = read_trusted(&host.cfg.paths.policy_path, &sec.trusted_owner_uids)?;
    let p = EffectivePolicy::parse(&t.bytes, t.sha256)?;
    let id = p.id().clone();
    host.set_policy(p); // in-flight operations keep the policy they were admitted under
    host.telemetry.events.emit(
        &host.clock.wall_rfc3339(),
        "policy.reloaded",
        None,
        None,
        serde_json::json!({"policy": id.to_string(), "by_uid": caller.uid}),
    );
    Ok(ResponseBody::HostInfo(host.host_info()?))
}

pub(crate) async fn dispatch(host: &Arc<Host>, sec: &SecurityConfig, caller: CallerIdentity, env: RequestEnvelope) -> ResponseEnvelope {
    let rid = env.request_id.clone();
    let op_id = env.operation_id.clone();
    let ctx = || host.ctx(caller.clone(), env.operation_id.clone(), env.retry);
    let op = |r: Result<OperationRecord>| match r {
        Ok(rec) => host.envelope(&rec, rid.clone()),
        Err(e) => host.error_envelope(&e, rid.clone(), op_id.clone()),
    };
    let read = |r: Result<ResponseBody>| match r {
        Ok(b) => ResponseEnvelope {
            protocol: PROTOCOL.to_owned(),
            request_id: rid.clone(),
            operation_id: None,
            status: OperationStatus::Succeeded,
            result: Some(b),
            error: None,
        },
        Err(e) => host.error_envelope(&e, rid.clone(), None),
    };
    match env.body.clone() {
        Request::HostInfo => read(host.host_info().map(ResponseBody::HostInfo)),
        Request::Metrics => read(Ok(ResponseBody::Metrics(host.metrics()))),
        Request::PolicyReload => read(reload_policy(host, sec, &caller)),
        Request::SandboxInspect(s) => read(host.sandbox_inspect(&s.sandbox).map(ResponseBody::Sandbox)),
        Request::SandboxList => read(host.sandbox_list().map(ResponseBody::Sandboxes)),
        Request::SnapshotList => read(host.snapshot_list().map(ResponseBody::Snapshots)),
        Request::RunInspect(s) => read(host.run_inspect(&s.run_id)),
        Request::OperationGet(s) => match host.operation_get(&s.operation_id) {
            Ok(mut e) => {
                e.request_id = rid.clone();
                e
            }
            Err(e) => host.error_envelope(&e, rid.clone(), Some(s.operation_id)),
        },
        Request::OperationCancel(s) => op(host.operation_cancel(&s.operation_id)),
        Request::SandboxCreate(p) => op(host.sandbox_create(&ctx(), p).await),
        Request::SandboxStart(t) => op(host.sandbox_start(&ctx(), t).await),
        Request::SandboxStop(t) => op(host.sandbox_stop(&ctx(), t).await),
        Request::SandboxDestroy(t) => op(host.sandbox_destroy(&ctx(), t).await),
        Request::Exec(p) => op(host.exec(&ctx(), p).await),
        Request::SnapshotCreate(p) => op(host.snapshot_create(&ctx(), p).await),
        Request::SnapshotRestore(p) => op(host.snapshot_restore(&ctx(), p).await),
        Request::SnapshotDelete(r) => op(host.snapshot_delete(&ctx(), r).await),
    }
}
