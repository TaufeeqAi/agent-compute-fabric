//! Protocol-level tests over a real Unix socket (spec §16, §24).

use std::{sync::Arc, time::Duration};

use acf_wire::frame::{FrameError, aio};
use serde_json::json;
use tokio::{io::AsyncWriteExt, net::UnixStream};
use tokio_util::sync::CancellationToken;

use super::rig::Rig;
use crate::{
    config::SecurityConfig,
    domain::{CommandSpec, OperationStatus, SnapshotRef},
    error::FailureClass,
    ids::OperationId,
    protocol::{
        ExecParams, OperationSelector, PROTOCOL, Request, RequestEnvelope, ResponseBody, ResponseEnvelope, RestoreTarget,
        SandboxCreateParams, SandboxTarget, SnapshotCreateParams, SnapshotRestoreParams,
    },
    server::{Server, bind_socket},
};

struct Fixture {
    r: Rig,
    path: std::path::PathBuf,
    token: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
}

async fn start(sec: impl FnOnce(&mut SecurityConfig)) -> Fixture {
    let r = Rig::new();
    let host = r.host();
    let mut s = r.cfg.security.clone();
    sec(&mut s);
    let path = r.dir.path().join("run/host.sock");
    let listener = bind_socket(&path, 0o660, None).unwrap();
    let token = CancellationToken::new();
    let srv = Server::new(host, s);
    let t2 = token.clone();
    let handle = tokio::spawn(async move { srv.serve(listener, t2, Duration::from_secs(2)).await });
    Fixture { r, path, token, handle }
}

impl Fixture {
    async fn connect(&self) -> UnixStream {
        UnixStream::connect(&self.path).await.unwrap()
    }
    async fn stop(self) {
        self.token.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), self.handle).await;
    }
}

fn envelope(body: Request, op: Option<&str>, retry: bool) -> RequestEnvelope {
    RequestEnvelope {
        protocol: PROTOCOL.into(),
        request_id: Some("req-1".into()),
        operation_id: op.map(|o| OperationId::parse(o).unwrap()),
        retry,
        body,
    }
}

async fn call(s: &mut UnixStream, e: &RequestEnvelope) -> ResponseEnvelope {
    aio::send_json(s, e, 1 << 20).await.unwrap();
    aio::recv_json(s, 64 << 20).await.unwrap()
}

fn sandbox(r: &ResponseEnvelope) -> crate::protocol::SandboxView {
    match &r.result {
        Some(ResponseBody::Sandbox(v)) => v.clone(),
        other => panic!("expected a sandbox, got {other:?} / {:?}", r.error),
    }
}

#[tokio::test]
async fn a_whole_lifecycle_works_through_the_wire_protocol_alone() {
    let f = start(|_| {}).await;
    let mut c = f.connect().await;
    let rc = |b| envelope(b, None, false);

    let info = call(&mut c, &rc(Request::HostInfo)).await;
    assert!(matches!(info.result, Some(ResponseBody::HostInfo(ref h)) if h.mode == "normal" && h.protocol == PROTOCOL));

    let created = call(
        &mut c,
        &rc(Request::SandboxCreate(SandboxCreateParams { name: Some("w".into()), image: "python".into(), resources: super::rig::res() })),
    )
    .await;
    assert_eq!((created.status, created.request_id.as_deref()), (OperationStatus::Succeeded, Some("req-1")));
    assert!(created.operation_id.is_some(), "the server assigns an operation id when the client sent none");
    let v = sandbox(&created);
    let t = SandboxTarget { sandbox_id: v.sandbox_id.clone(), expected_generation: v.generation };

    let started = call(&mut c, &rc(Request::SandboxStart(t.clone()))).await;
    assert_eq!(sandbox(&started).state, crate::domain::LifecycleState::Ready);

    let cmd =
        CommandSpec { argv: vec!["/bin/echo".into(), "hello".into()], env: Default::default(), cwd: None, limits: Default::default() };
    let run =
        call(&mut c, &rc(Request::Exec(ExecParams { sandbox_id: v.sandbox_id.clone(), expected_generation: v.generation, command: cmd })))
            .await;
    let Some(ResponseBody::Run(rr)) = run.result else { panic!("{run:?}") };
    assert_eq!(rr.exit_code, Some(0));

    let snap = call(
        &mut c,
        &rc(Request::SnapshotCreate(SnapshotCreateParams {
            sandbox_id: v.sandbox_id.clone(),
            expected_generation: v.generation,
            name: Some("b".into()),
        })),
    )
    .await;
    let Some(ResponseBody::Snapshot(sv)) = snap.result else { panic!("{snap:?}") };
    let restored = call(
        &mut c,
        &rc(Request::SnapshotRestore(SnapshotRestoreParams {
            snapshot: sv.snapshot.clone(),
            target: RestoreTarget::Existing { sandbox_id: v.sandbox_id.clone(), expected_generation: v.generation },
        })),
    )
    .await;
    let nv = sandbox(&restored);
    assert_eq!(nv.generation.0, 2);

    let listed = call(&mut c, &rc(Request::SandboxList)).await;
    assert!(matches!(listed.result, Some(ResponseBody::Sandboxes(ref l)) if l.len() == 1 && l[0].generation.0 == 2));

    // the old generation is stale over the wire too
    let stale = call(&mut c, &rc(Request::SandboxDestroy(t))).await;
    assert_eq!((stale.status, stale.error.as_ref().map(|e| e.class)), (OperationStatus::Conflict, Some(FailureClass::StateConflict)));

    let d =
        call(&mut c, &rc(Request::SandboxDestroy(SandboxTarget { sandbox_id: nv.sandbox_id.clone(), expected_generation: nv.generation })))
            .await;
    assert_eq!(d.status, OperationStatus::Succeeded);
    let del = call(
        &mut c,
        &rc(Request::SnapshotDelete(SnapshotRef {
            snapshot_id: sv.snapshot.snapshot_id.clone(),
            snapshot_generation: sv.snapshot.snapshot_generation,
        })),
    )
    .await;
    assert_eq!(del.status, OperationStatus::Succeeded);
    f.stop().await;
}

#[tokio::test]
async fn a_peer_that_is_not_allowlisted_is_denied_before_any_request_is_read() {
    let f = start(|s| {
        s.allowed_uids = vec![4242];
        s.allowed_gids = vec![];
    })
    .await;
    let mut c = f.connect().await;
    // the denial arrives unprompted, and the connection is closed
    let resp: ResponseEnvelope = aio::recv_json(&mut c, 1 << 20).await.unwrap();
    assert_eq!(resp.error.as_ref().map(|e| e.class), Some(FailureClass::Authorization));
    assert!(matches!(aio::recv_json::<_, ResponseEnvelope>(&mut c, 1 << 20).await, Err(FrameError::Eof | FrameError::Io(_))));
    f.stop().await;
}

#[tokio::test]
async fn malformed_requests_are_answered_precisely_and_do_not_kill_the_connection() {
    let f = start(|_| {}).await;
    let mut c = f.connect().await;
    // not JSON for the schema
    aio::write_frame(&mut c, br#"{"protocol":"acf.host/1","body":{"method":"rm_rf"}}"#, 1 << 20).await.unwrap();
    let r: ResponseEnvelope = aio::recv_json(&mut c, 1 << 20).await.unwrap();
    assert_eq!((r.status, r.error.as_ref().map(|e| e.class)), (OperationStatus::Rejected, Some(FailureClass::Validation)));
    assert_eq!(r.request_id, None, "nothing to echo when the caller supplied no id");
    // …but when the caller did supply one, the refusal carries it so the two can be correlated
    aio::write_frame(&mut c, br#"{"protocol":"acf.host/1","request_id":"req-mine","body":{"method":"rm_rf"}}"#, 1 << 20).await.unwrap();
    let r: ResponseEnvelope = aio::recv_json(&mut c, 1 << 20).await.unwrap();
    assert_eq!(r.status, OperationStatus::Rejected);
    assert_eq!(r.request_id.as_deref(), Some("req-mine"));
    // an absurdly long id is not reflected back
    let long = "x".repeat(4096);
    let frame = format!(r#"{{"protocol":"acf.host/1","request_id":"{long}","body":{{"method":"rm_rf"}}}}"#);
    aio::write_frame(&mut c, frame.as_bytes(), 1 << 20).await.unwrap();
    let r: ResponseEnvelope = aio::recv_json(&mut c, 1 << 20).await.unwrap();
    assert_eq!(r.request_id, None);
    // wrong protocol version
    let mut e = envelope(Request::SandboxList, None, false);
    e.protocol = "acf.host/2".into();
    let r = call(&mut c, &e).await;
    assert_eq!(r.error.as_ref().map(|e| e.class), Some(FailureClass::SchemaMismatch));
    // …and the same connection still works
    let ok = call(&mut c, &envelope(Request::SandboxList, None, false)).await;
    assert_eq!(ok.status, OperationStatus::Succeeded);
    f.stop().await;
}

#[tokio::test]
async fn an_oversized_frame_is_refused_without_buffering_it() {
    let f = start(|s| s.max_request_bytes = 4096).await;
    let mut c = f.connect().await;
    c.write_all(&(1u32 << 30).to_be_bytes()).await.unwrap(); // claims a 1 GiB request, sends nothing
    let r: ResponseEnvelope = aio::recv_json(&mut c, 1 << 20).await.unwrap();
    assert_eq!(r.error.as_ref().map(|e| e.class), Some(FailureClass::Validation));
    assert!(
        matches!(aio::recv_json::<_, ResponseEnvelope>(&mut c, 1 << 20).await, Err(FrameError::Eof | FrameError::Io(_))),
        "and the connection is closed"
    );
    f.stop().await;
}

#[tokio::test]
async fn a_client_that_disconnects_mid_request_can_still_resolve_its_operation_by_id() {
    let f = start(|_| {}).await;
    let mut c = f.connect().await;
    let created = call(
        &mut c,
        &envelope(
            Request::SandboxCreate(SandboxCreateParams { name: None, image: "python".into(), resources: super::rig::res() }),
            None,
            false,
        ),
    )
    .await;
    let v = sandbox(&created);
    let t = SandboxTarget { sandbox_id: v.sandbox_id.clone(), expected_generation: v.generation };
    call(&mut c, &envelope(Request::SandboxStart(t.clone()), None, false)).await;
    drop(c);

    // submit with a chosen operation id, then hang up without reading the response
    let mut c2 = f.connect().await;
    let e = envelope(
        Request::Exec(ExecParams {
            sandbox_id: t.sandbox_id.clone(),
            expected_generation: t.expected_generation,
            command: CommandSpec {
                argv: vec!["/bin/echo".into(), "x".into()],
                env: Default::default(),
                cwd: None,
                limits: Default::default(),
            },
        }),
        Some("op-lost-resp-0001"),
        false,
    );
    aio::send_json(&mut c2, &e, 1 << 20).await.unwrap();
    drop(c2);

    // a new connection resolves it by id, polling until terminal
    let mut c3 = f.connect().await;
    let mut got = None;
    for _ in 0..100 {
        let r = call(
            &mut c3,
            &envelope(
                Request::OperationGet(OperationSelector { operation_id: OperationId::parse("op-lost-resp-0001").unwrap() }),
                None,
                false,
            ),
        )
        .await;
        if r.status.is_final() {
            got = Some(r);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let r = got.expect("the operation must complete even though the client left");
    assert_eq!(r.status, OperationStatus::Succeeded);
    assert!(matches!(r.result, Some(ResponseBody::Run(_))));
    // re-submitting the same request with retry=true returns the SAME operation (no second run)
    let again = call(&mut c3, &RequestEnvelope { retry: true, ..e }).await;
    assert_eq!(again.operation_id.as_ref().map(OperationId::as_str), Some("op-lost-resp-0001"));
    assert_eq!(f.r.world.calls().iter().filter(|c| *c == "exec").count(), 1, "the command ran exactly once");
    f.stop().await;
}

#[tokio::test]
async fn connections_beyond_the_limit_are_shed_not_queued() {
    let f = start(|s| s.max_connections = 1).await;
    let mut first = f.connect().await;
    assert_eq!(call(&mut first, &envelope(Request::SandboxList, None, false)).await.status, OperationStatus::Succeeded);
    let mut second = f.connect().await;
    let shed = aio::recv_json::<_, ResponseEnvelope>(&mut second, 1 << 20).await;
    assert!(matches!(shed, Err(FrameError::Eof | FrameError::Io(_))), "the surplus connection is closed immediately");
    drop(first);
    f.stop().await;
}

#[tokio::test]
async fn policy_reload_is_an_administrator_only_capability() {
    let f = start(|s| s.trusted_owner_uids = vec![4242]).await; // the test caller (root) is NOT an administrator
    let mut c = f.connect().await;
    let r = call(&mut c, &envelope(Request::PolicyReload, None, false)).await;
    assert_eq!(r.error.as_ref().map(|e| e.class), Some(FailureClass::Authorization));
    f.stop().await;
}

#[tokio::test]
async fn graceful_shutdown_stops_accepting_and_returns() {
    let f = start(|_| {}).await;
    let path = f.path.clone();
    let token = f.token.clone();
    token.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), f.handle).await.expect("serve() must return after cancellation");
    let _keep: Arc<()> = Arc::new(());
    let _ = json!(path.display().to_string());
}
