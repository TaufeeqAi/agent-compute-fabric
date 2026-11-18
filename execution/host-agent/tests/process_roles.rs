//! T-SEC-01 at the level of processes (contract PD-1, INV-024, INV-025).
//!
//! The roles of the one host binary are separate processes. This test starts the test host binary
//! exactly as an operator would start the real one, and looks at what the kernel says about it:
//!
//! * the edge is a child process of the core, running the same binary image in the `edge` role;
//! * every thread of the edge has `no_new_privs` set and holds no capability;
//! * the edge has opened nothing by name: no descriptor of it points into the state directory;
//! * a peer's connection is accepted by the edge, never by the core;
//! * if the edge dies the core starts another, and nothing that was accepted is lost (FS-5).
//!
//! The test host uses the in-memory backend; everything else — the edge, the admission pipeline,
//! the coordinator, the store — is the code that ships.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use acf_wire::frame::{recv_json, send_json};
use serde_json::{Value, json};

struct TestHost {
    child: Child,
    dir: tempfile::TempDir,
    socket: PathBuf,
}

impl Drop for TestHost {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if cond() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("timed out waiting for: {what}");
}

fn start() -> TestHost {
    let dir = acf_host::testing::private_tempdir();
    let socket = dir.path().join("host.sock");
    let child = Command::new(env!("CARGO_BIN_EXE_acf-host-fake"))
        .arg("--state")
        .arg(dir.path().join("state"))
        .arg("--socket")
        .arg(&socket)
        .args(["--edge", "process"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the test host binary starts");
    let host = TestHost { child, dir, socket };
    wait_for("the local endpoint", || host.socket.exists());
    host
}

fn request(method: &str, params: Value) -> Value {
    let needs_operation = !matches!(method.split('.').nth(1), Some("info" | "list" | "inspect" | "get" | "metrics" | "output"));
    let mut env = json!({"protocol": "acf.host/2", "request_id": "req-1", "owner_scope": "ops", "method": method});
    if !params.is_null() {
        env["params"] = params;
    }
    if needs_operation {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
        env["operation_id"] = json!(format!("op-{:016x}", nanos.as_nanos() as u64));
        env["issued_at"] = json!(acf_host::clock::rfc3339_utc(nanos.as_secs() as i64, 0));
    }
    env
}

fn ask(socket: &Path, method: &str, params: Value) -> Value {
    let mut conn = UnixStream::connect(socket).expect("connect to the local endpoint");
    conn.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    send_json(&mut conn, &request(method, params), 1 << 20).unwrap();
    recv_json(&mut conn, 64 << 20).unwrap()
}

fn children_of(parent: u32) -> Vec<u32> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir("/proc").unwrap().flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else { continue };
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else { continue };
        // "pid (comm) state ppid ..." — the command may contain spaces, so split after the last ')'.
        let ppid = stat.rsplit_once(')').and_then(|(_, rest)| rest.split_whitespace().nth(1)).and_then(|p| p.parse::<u32>().ok());
        if ppid == Some(parent) {
            out.push(pid);
        }
    }
    out
}

fn edge_of(core: u32) -> Option<u32> {
    children_of(core)
        .into_iter()
        .find(|pid| std::fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|c| c.split(|b| *b == 0).any(|a| a == b"edge")))
}

fn descriptors(pid: u32) -> Vec<String> {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .map(|d| d.flatten().filter_map(|e| std::fs::read_link(e.path()).ok()).map(|p| p.to_string_lossy().into_owned()).collect())
        .unwrap_or_default()
}

fn sockets(pid: u32) -> usize {
    descriptors(pid).iter().filter(|d| d.starts_with("socket:")).count()
}

fn field<'a>(status: &'a str, key: &str) -> &'a str {
    status.lines().find_map(|l| l.strip_prefix(key)).map(str::trim).unwrap_or_else(|| panic!("no `{key}` in the status"))
}

#[test]
fn t_sec_01_the_edge_is_a_separate_unprivileged_process_and_the_core_reads_no_peer_bytes() {
    if rustix::process::geteuid().is_root() {
        // A root core must give its edge another identity; the test host has none to give.
        eprintln!("skipped: run as an unprivileged user (as root the production binary is the one to test)");
        return;
    }
    let host = start();
    let core = host.child.id();
    let state = host.dir.path().join("state");

    // The host answers, and the answer comes through the edge.
    let info = ask(&host.socket, "host.info", Value::Null);
    assert_eq!(info["answer"], "RESULT", "{info}");
    assert_eq!(info["result"]["data"]["mode"], "SERVING");
    let edge = edge_of(core).expect("the edge is a child process of the core");
    assert_ne!(edge, core);
    assert_eq!(
        std::fs::read_link(format!("/proc/{edge}/exe")).unwrap(),
        std::fs::read_link(format!("/proc/{core}/exe")).unwrap(),
        "one binary, several roles (INV-024)"
    );

    // INV-025: every thread of the edge has given up the ability to gain privilege, and holds none.
    let threads: Vec<_> = std::fs::read_dir(format!("/proc/{edge}/task")).unwrap().flatten().collect();
    assert!(threads.len() > 1, "the edge runs a multi-threaded runtime; all of its threads are checked");
    for thread in &threads {
        let status = std::fs::read_to_string(thread.path().join("status")).unwrap();
        assert_eq!(field(&status, "NoNewPrivs:"), "1", "a thread of the edge without no_new_privs: {}", thread.path().display());
        for set in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
            assert_eq!(u64::from_str_radix(field(&status, set), 16).unwrap(), 0, "{set} of an edge thread");
        }
    }
    // The core did not need to: it is the privileged role.
    assert_eq!(field(&std::fs::read_to_string(format!("/proc/{core}/status")).unwrap(), "NoNewPrivs:"), "0");

    // PD-1: the edge opened nothing by name. The store, the profile and telemetry are the core's.
    let state_prefix = state.to_string_lossy().into_owned();
    let edge_fds = descriptors(edge);
    assert!(!edge_fds.is_empty());
    assert!(edge_fds.iter().all(|d| !d.starts_with(&state_prefix)), "the edge holds a descriptor inside the state directory: {edge_fds:?}");
    assert!(
        descriptors(core).iter().any(|d| d.starts_with(&state_prefix) && d.ends_with("journal.wal")),
        "the core holds the store (which makes the check above meaningful)"
    );
    assert!(
        std::fs::read(format!("/proc/{edge}/environ")).is_ok_and(|e| !e.windows(4).any(|w| w == b"HOME")),
        "the edge starts with an empty environment"
    );

    // A peer's connection is accepted by the edge; the core's descriptor table does not change.
    let (edge_before, core_before) = (sockets(edge), sockets(core));
    let peers: Vec<UnixStream> = (0..3).map(|_| UnixStream::connect(&host.socket).unwrap()).collect();
    wait_for("the edge accepts the connections", || sockets(edge) == edge_before + 3);
    assert_eq!(sockets(core), core_before, "the core accepted no connection: it reads no bytes from a peer");
    drop(peers);

    // An operation is accepted and recorded.
    let created = ask(
        &host.socket,
        "sandbox.create",
        json!({"image": "python", "resources": {"vcpus": 1, "memory_mib": 256, "disk_mib": 128, "network": {"mode": "none"}}}),
    );
    assert_eq!(created["operation"]["state"], "SUCCEEDED", "{created}");
    let sandbox = created["operation"]["result"]["data"]["sandbox_id"].as_str().unwrap().to_owned();

    // The edge dies. It held no state: the core starts another with the same listeners, and what
    // was accepted is still there.
    rustix::process::kill_process(rustix::process::Pid::from_raw(edge as i32).unwrap(), rustix::process::Signal::KILL).unwrap();
    wait_for("the core starts a new edge", || edge_of(core).is_some_and(|pid| pid != edge));
    let mut answer = Value::Null;
    wait_for("the new edge serves", || {
        UnixStream::connect(&host.socket).ok().is_some_and(|mut conn| {
            conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            send_json(&mut conn, &request("sandbox.list", json!({})), 1 << 20).is_ok()
                && recv_json::<_, Value>(&mut conn, 64 << 20).is_ok_and(|v| {
                    answer = v;
                    true
                })
        })
    });
    assert_eq!(answer["result"]["data"]["items"][0]["sandbox_id"], json!(sandbox), "{answer}");
    let metrics = ask(&host.socket, "host.metrics", Value::Null);
    assert_eq!(metrics["result"]["data"]["counters"]["edge_restarts"], 1, "{metrics}");

    // A clean stop: the core drains, ends its edge, and removes the socket.
    let mut host = host;
    rustix::process::kill_process(rustix::process::Pid::from_raw(core as i32).unwrap(), rustix::process::Signal::TERM).unwrap();
    let status = host.child.wait().unwrap();
    assert!(status.success(), "{status:?}");
    assert!(!host.socket.exists());
    assert!(edge_of(core).is_none());
}

#[test]
fn a_role_refuses_to_run_outside_its_channel() {
    // Started by hand, with no channel from a core, a role has nothing to serve and must not linger.
    for role in ["edge", "guest-traffic"] {
        let out = Command::new(env!("CARGO_BIN_EXE_acf-host-fake")).arg(role).stdin(Stdio::null()).output().unwrap();
        assert!(!out.status.success(), "{role} ran without a channel");
        let said = String::from_utf8_lossy(&out.stderr);
        assert!(!said.is_empty(), "{role} must say why it stopped");
    }
}
