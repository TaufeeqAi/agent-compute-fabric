//! A fake Firecracker **API server** that enforces the VMM's real state-machine rules, so the
//! adapter's request *ordering* and *file placement* are tested without KVM:
//!
//! * configuration (`machine-config`, `boot-source`, `drives`, `vsock`) is accepted only before boot;
//! * `InstanceStart` requires machine, boot source and a root drive;
//! * `PATCH /vm` pause/resume only from the matching state;
//! * `snapshot/create` only while paused; `snapshot/load` only on a fresh VMM, and only if the
//!   snapshot files actually exist **inside the jail** (this is what catches missing hard-links);
//! * `kernel_image_path` / `path_on_host` must resolve to files in the jail.
//!
//! The vsock device is emulated too: `PUT /vsock` binds `<jail>/v.sock`, answers
//! `CONNECT <port>` with `OK`, then bridges to the **real** guest agent.

use std::{
    collections::HashMap,
    io::Write,
    os::fd::{AsRawFd, OwnedFd},
    sync::{Arc, Mutex},
};

use acf_guest::server::Agent;
use cap_std::fs::Dir;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};

#[derive(Debug, Default)]
pub struct FakeFcState {
    pub phase: String,
    pub machine: Option<Value>,
    pub boot: Option<Value>,
    pub drives: Vec<Value>,
    pub vsock: Option<Value>,
    pub nics: Vec<Value>,
    pub version: String,
    /// Every request seen, in order: `(method, path, body)`.
    pub log: Vec<(String, String, Value)>,
    /// `"PUT /snapshot/load"` -> `(status, fault_message)` to inject.
    pub fail: HashMap<String, (u16, String)>,
}

#[derive(Debug)]
pub struct FakeFc {
    pub state: Arc<Mutex<FakeFcState>>,
    root_fd: Arc<OwnedFd>,
    root: Dir,
    agent: Option<Arc<Agent>>,
}

fn bad(msg: &str) -> (u16, String) {
    (400, json!({ "fault_message": msg }).to_string())
}

const NOT_AFTER_BOOT: &str = "The requested operation is not supported after starting the microVM.";

impl FakeFc {
    pub fn new(root: Dir, version: &str, agent: Option<Arc<Agent>>) -> Arc<Self> {
        let fd = OwnedFd::from(root.try_clone().unwrap().into_std_file());
        let state = FakeFcState { phase: "Not started".into(), version: version.into(), ..Default::default() };
        Arc::new(Self { state: Arc::new(Mutex::new(state)), root_fd: Arc::new(fd), root, agent })
    }

    fn fd_path(&self, name: &str) -> String {
        format!("/proc/self/fd/{}/{name}", self.root_fd.as_raw_fd())
    }

    fn exists(&self, jail_path: &str) -> bool {
        self.root.symlink_metadata(jail_path.trim_start_matches('/')).is_ok()
    }

    fn handle(self: &Arc<Self>, method: &str, path: &str, body: Value) -> (u16, String) {
        let mut st = self.state.lock().unwrap();
        st.log.push((method.into(), path.into(), body.clone()));
        if let Some((code, msg)) = st.fail.get(&format!("{method} {path}")) {
            return bad_code(*code, msg);
        }
        let pre_boot = st.phase == "Not started";
        match (method, path) {
            ("GET", "/") => {
                (200, json!({"app_name":"Firecracker","id":"anonymous-instance","state":st.phase,"vmm_version":st.version}).to_string())
            }
            ("GET", "/vm/config") => {
                (200, json!({"drives":st.drives,"machine-config":st.machine,"network-interfaces":st.nics}).to_string())
            }
            ("PUT", "/machine-config") if pre_boot => {
                st.machine = Some(body);
                (204, String::new())
            }
            ("PUT", "/boot-source") if pre_boot => {
                let k = body["kernel_image_path"].as_str().unwrap_or("");
                if !self.exists(k) {
                    return bad("Invalid kernel file path: not found in the jail");
                }
                st.boot = Some(body);
                (204, String::new())
            }
            ("PUT", p) if p.starts_with("/drives/") && pre_boot => {
                let f = body["path_on_host"].as_str().unwrap_or("");
                if !self.exists(f) {
                    return bad("Invalid drive path: not found in the jail");
                }
                st.drives.push(body);
                (204, String::new())
            }
            ("PUT", "/vsock") if pre_boot => {
                st.vsock = Some(body);
                drop(st);
                self.start_vsock();
                (204, String::new())
            }
            ("PUT", "/machine-config" | "/boot-source" | "/vsock") => bad(NOT_AFTER_BOOT),
            ("PUT", p) if p.starts_with("/drives/") => bad(NOT_AFTER_BOOT),
            ("PUT", "/actions") => {
                if body["action_type"] != "InstanceStart" || !pre_boot {
                    return bad("unsupported action in this state");
                }
                if st.machine.is_none() || st.boot.is_none() || st.drives.is_empty() {
                    return bad("The microVM is missing machine config, boot source, or a root drive.");
                }
                st.phase = "Running".into();
                (204, String::new())
            }
            ("PATCH", "/vm") => match (body["state"].as_str(), st.phase.as_str()) {
                (Some("Paused"), "Running") => {
                    st.phase = "Paused".into();
                    (204, String::new())
                }
                (Some("Resumed"), "Paused") => {
                    st.phase = "Running".into();
                    (204, String::new())
                }
                _ => bad("Invalid state transition"),
            },
            ("PUT", "/snapshot/create") => {
                if st.phase != "Paused" {
                    return bad("Snapshot can only be created when the microVM is paused");
                }
                for (key, content) in [("snapshot_path", &b"VMSTATE\n"[..]), ("mem_file_path", &[0u8, 0, 0, 7, 0, 0][..])] {
                    let p = body[key].as_str().unwrap_or("").trim_start_matches('/').to_owned();
                    if p.is_empty() || p.contains('/') {
                        return bad("bad snapshot path");
                    }
                    let mut f = self.root.create(&p).unwrap().into_std();
                    f.write_all(content).unwrap();
                }
                (204, String::new())
            }
            ("PUT", "/snapshot/load") => {
                if !pre_boot || st.machine.is_some() {
                    return bad("Loading a snapshot is not allowed after boot or manual configuration");
                }
                let (sp, mp) = (body["snapshot_path"].as_str().unwrap_or(""), body["mem_backend"]["backend_path"].as_str().unwrap_or(""));
                if body.get("mem_file_path").is_some() {
                    return bad("mem_file_path is deprecated on load; use mem_backend");
                }
                if !self.exists(sp) || !self.exists(mp) {
                    return bad("Cannot open snapshot file: not found in the jail");
                }
                st.phase = if body["resume_vm"] == json!(true) { "Running".into() } else { "Paused".into() };
                st.machine = Some(json!({"restored": true}));
                drop(st);
                // Firecracker recreates the vsock device (and its UDS) from the snapshot state.
                self.start_vsock();
                (204, String::new())
            }
            _ => (404, json!({"fault_message": format!("unknown route {method} {path}")}).to_string()),
        }
    }

    fn start_vsock(self: &Arc<Self>) {
        let Some(agent) = self.agent.clone() else { return };
        let Ok(l) = std::os::unix::net::UnixListener::bind(self.fd_path("v.sock")) else { return };
        l.set_nonblocking(true).ok();
        let l = UnixListener::from_std(l).unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let agent = Arc::clone(&agent);
                tokio::spawn(async move {
                    // host side of Firecracker vsock: "CONNECT <port>\n" -> "OK <n>\n"
                    let mut line = Vec::new();
                    let mut b = [0u8; 1];
                    while s.read_exact(&mut b).await.is_ok() {
                        if b[0] == b'\n' {
                            break;
                        }
                        line.push(b[0]);
                    }
                    if !line.starts_with(b"CONNECT ") || s.write_all(b"OK 1073741824\n").await.is_err() {
                        return;
                    }
                    let mut std_s = s.into_std().unwrap();
                    std_s.set_nonblocking(false).unwrap();
                    tokio::task::spawn_blocking(move || agent.serve(&mut std_s));
                });
            }
        });
    }

    /// Serve the API on `<jail>/api.sock`.
    pub fn serve_api(self: &Arc<Self>) -> std::io::Result<tokio::task::JoinHandle<()>> {
        let l = std::os::unix::net::UnixListener::bind(self.fd_path("api.sock"))?;
        l.set_nonblocking(true)?;
        let l = UnixListener::from_std(l)?;
        let me = Arc::clone(self);
        Ok(tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let me = Arc::clone(&me);
                tokio::spawn(async move { me.http(s).await });
            }
        }))
    }

    async fn http(self: Arc<Self>, mut s: UnixStream) {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        let header_end = loop {
            let Ok(n) = s.read(&mut tmp).await else { return };
            if n == 0 {
                return;
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
        };
        let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
        let mut lines = head.lines();
        let mut rl = lines.next().unwrap_or("").split_whitespace();
        let (method, path) = (rl.next().unwrap_or("").to_owned(), rl.next().unwrap_or("").to_owned());
        let len: usize = lines
            .filter_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").and_then(|v| v.trim().parse().ok()))
            .next()
            .unwrap_or(0);
        while buf.len() < header_end + len {
            let Ok(n) = s.read(&mut tmp).await else { return };
            if n == 0 {
                return;
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        let body: Value = serde_json::from_slice(&buf[header_end..header_end + len]).unwrap_or(Value::Null);
        let (code, text) = self.handle(&method, &path, body);
        let reason = if code == 204 {
            "No Content"
        } else if code < 300 {
            "OK"
        } else {
            "Error"
        };
        let resp = format!(
            "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
            text.len()
        );
        let _ = s.write_all(resp.as_bytes()).await;
    }
}

fn bad_code(code: u16, msg: &str) -> (u16, String) {
    (code, json!({ "fault_message": msg }).to_string())
}
