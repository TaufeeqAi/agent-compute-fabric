//! Connection handling for the guest agent. Transport-agnostic (`Read + Write`) so the same
//! code serves AF_VSOCK in production and a Unix socket in tests.

use std::{
    io::{Read, Write},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use acf_wire::{
    frame::{FrameError, read_frame, send_json},
    guest::{GUEST_PROTOCOL_VERSION, GuestErrorCode, GuestRequest, GuestResponse, MAX_FRAME_DEFAULT},
};

use crate::{
    exec, netprobe,
    probe::{self, AGENT_VERSION, DEFAULT_BOOT_ID_PATH, DEFAULT_CANARY_PATH},
};

/// Requests are small (argv + env). Anything bigger is a protocol violation.
const MAX_REQUEST_FRAME: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub boot_id_path: PathBuf,
    pub canary_path: PathBuf,
    /// Tests must never power off the machine running them.
    pub allow_shutdown: bool,
    /// cgroup v2 mount used for per-exec process-tree containment; `None` forces the
    /// rlimit fallback. The agent probes this once at startup (see `detect_cgroup_root`).
    pub cgroup_root: Option<PathBuf>,
    /// `host:port` destinations the `NetProbe` request tries to connect to.
    pub net_probe_targets: Vec<String>,
    /// Where interface names are listed (`/sys/class/net`; injectable for tests).
    pub net_class_dir: PathBuf,
}

/// Use the guest's cgroup v2 root only if it actually offers the `pids` controller.
pub fn detect_cgroup_root() -> Option<PathBuf> {
    let root = PathBuf::from("/sys/fs/cgroup");
    std::fs::read_to_string(root.join("cgroup.controllers")).ok().filter(|c| c.split_whitespace().any(|x| x == "pids")).map(|_| root)
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            boot_id_path: DEFAULT_BOOT_ID_PATH.into(),
            canary_path: DEFAULT_CANARY_PATH.into(),
            allow_shutdown: false,
            cgroup_root: detect_cgroup_root(),
            net_probe_targets: netprobe::DEFAULT_TARGETS.iter().map(|s| (*s).to_owned()).collect(),
            net_class_dir: netprobe::DEFAULT_CLASS_DIR.into(),
        }
    }
}

#[derive(Debug)]
struct Active {
    exec_id: String,
    cancel: Arc<AtomicBool>,
}

#[derive(Debug)]
pub struct Agent {
    cfg: AgentConfig,
    active: Mutex<Option<Active>>,
}

fn boot_id(cfg: &AgentConfig) -> String {
    std::fs::read_to_string(&cfg.boot_id_path).map(|s| s.trim().to_owned()).unwrap_or_default()
}

impl Agent {
    pub fn new(cfg: AgentConfig) -> Self {
        Self { cfg, active: Mutex::new(None) }
    }

    fn err(code: GuestErrorCode, message: impl Into<String>) -> GuestResponse {
        GuestResponse::Error { code, message: message.into() }
    }

    /// Serve one connection until the peer closes it or violates the protocol.
    pub fn serve<S: Read + Write>(&self, stream: &mut S) {
        let mut said_hello = false;
        loop {
            let req: GuestRequest =
                match read_frame(stream, MAX_REQUEST_FRAME).and_then(|b| serde_json::from_slice(&b).map_err(FrameError::from)) {
                    Ok(r) => r,
                    Err(FrameError::Eof) => return,
                    Err(e) => {
                        let _ = send_json(stream, &Self::err(GuestErrorCode::BadRequest, e.to_string()), MAX_FRAME_DEFAULT);
                        return;
                    }
                };
            if !said_hello && !matches!(req, GuestRequest::Hello { .. }) {
                let _ = send_json(stream, &Self::err(GuestErrorCode::BadRequest, "Hello must be the first message"), MAX_FRAME_DEFAULT);
                return;
            }
            let resp = self.dispatch(req, &mut said_hello);
            let shutting = matches!(resp, GuestResponse::ShutdownAck);
            if send_json(stream, &resp, MAX_FRAME_DEFAULT).is_err() {
                return;
            }
            if shutting {
                self.power_off();
                return;
            }
        }
    }

    fn dispatch(&self, req: GuestRequest, said_hello: &mut bool) -> GuestResponse {
        match req {
            GuestRequest::Hello { protocol_version } if protocol_version == GUEST_PROTOCOL_VERSION => {
                *said_hello = true;
                GuestResponse::Hello {
                    protocol_version: GUEST_PROTOCOL_VERSION,
                    agent_version: AGENT_VERSION.to_owned(),
                    boot_id: boot_id(&self.cfg),
                }
            }
            GuestRequest::Hello { protocol_version } => Self::err(
                GuestErrorCode::UnsupportedVersion,
                format!("agent speaks {GUEST_PROTOCOL_VERSION}, peer sent {protocol_version}"),
            ),
            GuestRequest::Ping { nonce } => GuestResponse::Pong { nonce },
            GuestRequest::Probe { nonce } => match probe::probe(&nonce, &self.cfg.boot_id_path, &self.cfg.canary_path) {
                Ok(p) => GuestResponse::Probe(p),
                Err(e) => Self::err(GuestErrorCode::Internal, format!("probe failed: {e}")),
            },
            GuestRequest::NetProbe => GuestResponse::NetProbe(netprobe::probe(&self.cfg.net_probe_targets, &self.cfg.net_class_dir)),
            GuestRequest::Cancel { exec_id } => {
                let guard = self.active.lock().unwrap_or_else(|p| p.into_inner());
                let found = guard.as_ref().is_some_and(|a| a.exec_id == exec_id);
                if found && let Some(a) = guard.as_ref() {
                    a.cancel.store(true, Ordering::Relaxed);
                }
                GuestResponse::Cancelled { exec_id, found }
            }
            GuestRequest::Exec(r) => {
                let cancel = Arc::new(AtomicBool::new(false));
                {
                    let mut g = self.active.lock().unwrap_or_else(|p| p.into_inner());
                    if g.is_some() {
                        return Self::err(GuestErrorCode::Busy, "another exec is in flight");
                    }
                    *g = Some(Active { exec_id: r.exec_id.clone(), cancel: Arc::clone(&cancel) });
                }
                let result = exec::run(&r, &cancel, &exec::ExecEnv { cgroup_root: self.cfg.cgroup_root.clone() });
                *self.active.lock().unwrap_or_else(|p| p.into_inner()) = None;
                GuestResponse::ExecResult(result)
            }
            GuestRequest::Shutdown if self.cfg.allow_shutdown => GuestResponse::ShutdownAck,
            GuestRequest::Shutdown => Self::err(GuestErrorCode::BadRequest, "shutdown disabled"),
        }
    }

    /// End the microVM: flush, then ask the kernel to *reboot*.
    ///
    /// Not `poweroff`, on purpose. Firecracker virtualizes no power management, so on x86_64 a guest
    /// `poweroff` leaves the VMM process running ("the guest has no way of requesting a power-off",
    /// Firecracker FAQ). A `reboot` with `reboot=k` on the kernel command line (the host's default
    /// boot args) resets the CPU through the emulated i8042, which Firecracker intercepts and turns
    /// into a clean process exit; on aarch64 either command ends the VMM. The host still kills the
    /// VMM after its shutdown grace if this never takes effect, so a failure here costs time, not safety.
    fn power_off(&self) {
        rustix::fs::sync();
        let _ = rustix::system::reboot(rustix::system::RebootCommand::Restart);
    }
}
