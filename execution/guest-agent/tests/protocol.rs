//! End-to-end tests of the guest agent over a real socket pair (no VM required).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    collections::BTreeMap,
    os::unix::net::UnixStream,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use acf_guest::server::{Agent, AgentConfig};
use acf_wire::{
    frame::{recv_json, send_json},
    guest::{Containment, ExecRequest, ExecStatus, GUEST_PROTOCOL_VERSION, GuestErrorCode, GuestRequest, GuestResponse, MAX_FRAME_DEFAULT},
};

fn agent(dir: &std::path::Path) -> Arc<Agent> {
    std::fs::write(dir.join("boot_id"), "boot-xyz\n").unwrap();
    Arc::new(Agent::new(AgentConfig {
        boot_id_path: dir.join("boot_id"),
        canary_path: dir.join("canary"),
        allow_shutdown: false,
        cgroup_root: None, // force the rlimit fallback: the only mechanism testable on this host
        net_probe_targets: vec![],
        net_class_dir: dir.join("net"),
    }))
}

fn connect(a: &Arc<Agent>) -> UnixStream {
    let (client, mut server) = UnixStream::pair().unwrap();
    let a = Arc::clone(a);
    thread::spawn(move || a.serve(&mut server));
    client
}

fn rpc(c: &mut UnixStream, r: &GuestRequest) -> GuestResponse {
    send_json(c, r, 1 << 20).unwrap();
    recv_json(c, MAX_FRAME_DEFAULT).unwrap()
}

fn hello(c: &mut UnixStream) {
    let r = rpc(c, &GuestRequest::Hello { protocol_version: GUEST_PROTOCOL_VERSION });
    assert!(matches!(r, GuestResponse::Hello { ref boot_id, .. } if boot_id == "boot-xyz"), "{r:?}");
}

fn exec_req(id: &str, script: &str, uid: u32) -> ExecRequest {
    ExecRequest {
        exec_id: id.into(),
        argv: vec!["/bin/sh".into(), "-c".into(), script.into()],
        env: BTreeMap::from([("PATH".into(), "/usr/bin:/bin".into())]),
        cwd: "/".into(),
        timeout_ms: 5_000,
        max_stdout_bytes: 1 << 16,
        max_stderr_bytes: 1 << 16,
        max_pids: 4096,
        uid,
        gid: uid,
    }
}

#[test]
fn first_message_must_be_hello() {
    let d = tempfile::tempdir().unwrap();
    let a = agent(d.path());
    let mut c = connect(&a);
    let r = rpc(&mut c, &GuestRequest::Ping { nonce: "n".into() });
    assert!(matches!(r, GuestResponse::Error { code: GuestErrorCode::BadRequest, .. }), "{r:?}");
}

#[test]
fn wrong_protocol_version_is_rejected_not_negotiated_silently() {
    let d = tempfile::tempdir().unwrap();
    let mut c = connect(&agent(d.path()));
    let r = rpc(&mut c, &GuestRequest::Hello { protocol_version: GUEST_PROTOCOL_VERSION + 1 });
    assert!(matches!(r, GuestResponse::Error { code: GuestErrorCode::UnsupportedVersion, .. }), "{r:?}");
}

#[test]
fn unknown_request_fields_close_the_connection_with_an_error() {
    use std::io::Write;
    let d = tempfile::tempdir().unwrap();
    let mut c = connect(&agent(d.path()));
    let bad = br#"{"type":"hello","protocol_version":1,"sneaky":true}"#;
    c.write_all(&(bad.len() as u32).to_be_bytes()).unwrap();
    c.write_all(bad).unwrap();
    let r: GuestResponse = recv_json(&mut c, MAX_FRAME_DEFAULT).unwrap();
    assert!(matches!(r, GuestResponse::Error { code: GuestErrorCode::BadRequest, .. }), "{r:?}");
}

#[test]
fn probe_is_deterministic_across_connections() {
    let d = tempfile::tempdir().unwrap();
    let a = agent(d.path());
    let (mut c1, mut c2) = (connect(&a), connect(&a));
    hello(&mut c1);
    hello(&mut c2);
    let p = |c: &mut UnixStream, n: &str| match rpc(c, &GuestRequest::Probe { nonce: n.into() }) {
        GuestResponse::Probe(p) => p,
        other => panic!("{other:?}"),
    };
    let (p1, p2) = (p(&mut c1, "a"), p(&mut c2, "b"));
    assert_eq!(p1.state_digest, p2.state_digest);
    assert_eq!((p1.nonce.as_str(), p2.nonce.as_str()), ("a", "b"));
}

#[test]
fn second_exec_while_one_is_running_gets_busy_and_cancel_reaches_the_first() {
    let d = tempfile::tempdir().unwrap();
    let a = agent(d.path());
    let (mut c1, mut c2, mut c3) = (connect(&a), connect(&a), connect(&a));
    for c in [&mut c1, &mut c2, &mut c3] {
        hello(c);
    }
    let long = exec_req("long", "sleep 30", 0);
    send_json(&mut c1, &GuestRequest::Exec(long), 1 << 20).unwrap();
    thread::sleep(Duration::from_millis(300));

    let busy = rpc(&mut c2, &GuestRequest::Exec(exec_req("second", "true", 0)));
    assert!(matches!(busy, GuestResponse::Error { code: GuestErrorCode::Busy, .. }), "{busy:?}");

    let c = rpc(&mut c3, &GuestRequest::Cancel { exec_id: "long".into() });
    assert!(matches!(c, GuestResponse::Cancelled { found: true, .. }), "{c:?}");
    let miss = rpc(&mut c3, &GuestRequest::Cancel { exec_id: "nope".into() });
    assert!(matches!(miss, GuestResponse::Cancelled { found: false, .. }), "{miss:?}");

    let r: GuestResponse = recv_json(&mut c1, MAX_FRAME_DEFAULT).unwrap();
    match r {
        GuestResponse::ExecResult(er) => assert_eq!(er.status, ExecStatus::Cancelled),
        other => panic!("{other:?}"),
    }
}

/// Spec §18.4 / §27.5 "process-tree abuse": a fork loop as an unprivileged uid must be
/// contained by the process budget, terminate at the deadline, and leave nothing behind.
/// Requires running as root so the agent can drop to an unprivileged uid.
#[test]
fn fork_bomb_is_contained_by_the_process_budget() {
    if !rustix::process::getuid().is_root() {
        eprintln!("skipping: needs root to switch uid");
        return;
    }
    const UID: u32 = 64_321;
    let d = tempfile::tempdir().unwrap();
    let mut c = connect(&agent(d.path()));
    hello(&mut c);

    let mut q = exec_req("bomb", "while true; do sleep 60 & done", UID);
    q.max_pids = 24;
    q.timeout_ms = 1_500;
    let t = Instant::now();
    let r = rpc(&mut c, &GuestRequest::Exec(q));
    let GuestResponse::ExecResult(er) = r else { panic!("{r:?}") };

    // dash aborts with status 2 as soon as fork() fails, bash would spin until the deadline:
    // either is "contained". What must hold is termination, evidence and no leakage.
    assert!(matches!(er.status, ExecStatus::TimedOut | ExecStatus::Exited { .. }), "bomb must terminate: {:?}", er.status);
    assert!(er.pid_limit_hit, "pressure against the process budget must be reported: {er:?}");
    assert_eq!(er.containment, Containment::RlimitNproc, "evidence must name the weaker mechanism");
    assert!(t.elapsed() < Duration::from_secs(10), "took {:?}", t.elapsed());

    // Nothing owned by the exec uid may survive the kill. Zombies (state Z) are already dead and
    // only await reaping by PID 1 (`tini` in the real guest image), so they are not "alive".
    thread::sleep(Duration::from_millis(300));
    let status_field = |pid: u32, key: &str| -> Option<String> {
        let st = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        st.lines().find(|l| l.starts_with(key))?.split_whitespace().nth(1).map(str::to_owned)
    };
    let leftover = std::fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter(|&pid| status_field(pid, "Uid:").as_deref() == Some(&UID.to_string()))
        .filter(|&pid| status_field(pid, "State:").as_deref() != Some("Z"))
        .count();
    assert_eq!(leftover, 0, "no live fork-bomb descendant may survive the run");
}
