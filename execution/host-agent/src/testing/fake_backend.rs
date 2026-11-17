//! An in-memory [`SandboxBackend`] with *real semantics*, used for contract and recovery tests.
//!
//! * **World vs backend.** All state lives in a shared [`FakeWorld`]. Dropping the coordinator (a
//!   simulated host-agent crash) leaves the world intact — like a real VMM that outlives its
//!   manager — and a fresh coordinator + fresh backend over the same world models a restart.
//! * **Guest state is real enough to test rollback:** it has a boot id and a canary (what the
//!   probe digests) and arbitrary files. A snapshot *captures* it; a restore *resets* the guest to
//!   the captured state (so "break the environment, restore, verify" is a genuine test), and a
//!   "reboot" changes the boot id (so a fake restore that cold-boots is detectable).
//! * **Scriptable failure:** any method can be made to fail once, either before or after its
//!   effect, with a chosen error — the knob recovery tests need.
//!
//! It deliberately does **not** pretend to be Firecracker: it implements only the backend
//! contract. Firecracker-specific behaviour is covered by `fc_backend_tests`.

use std::{
    collections::{BTreeMap, HashMap},
    io::Write,
    sync::{
        Arc, Mutex,
        atomic::{AtomicI32, AtomicU64, Ordering},
    },
    time::Duration,
};

use acf_wire::guest::{Containment, ExecResult, ExecStatus, ProbeReport};
use async_trait::async_trait;
use cap_std::fs::OpenOptionsExt;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::{
    backend::*,
    clock::Clock,
    domain::NetworkMode,
    error::{AcfError, FailureClass, Result},
    filesystem::{GenerationDir, Layout, generation::remove_generation},
    ids::SandboxRef,
    network::evaluate_none,
    operation::ProcessIdentity,
    process::{CgroupStats, SecurityPosture},
};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GuestState {
    pub boot_id: String,
    pub canary: String,
    pub files: BTreeMap<String, String>,
}

impl GuestState {
    fn digest(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.boot_id.as_bytes());
        h.update([0]);
        h.update(self.canary.as_bytes());
        h.update([0]);
        for (k, v) in &self.files {
            h.update(k.as_bytes());
            h.update([1]);
            h.update(v.as_bytes());
        }
        hex::encode(h.finalize())
    }
}

#[derive(Debug, Clone)]
pub struct FakeVm {
    pub process: ProcessIdentity,
    pub phase: VmmState,
    pub guest: GuestState,
}

/// When an injected failure fires relative to the method's effect.
#[derive(Debug, Clone)]
pub enum Fail {
    /// Fail *before* doing anything (the world is unchanged).
    Before(AcfError),
    /// Do the effect, then report failure (the classic "lost ack").
    After(AcfError),
}

#[derive(Default)]
pub struct FakeWorld {
    pub vms: Mutex<HashMap<String, FakeVm>>,
    /// guest state captured by snapshots, keyed by sha256 of the vmstate file.
    captured: Mutex<HashMap<String, GuestState>>,
    calls: Mutex<Vec<String>>,
    fail: Mutex<HashMap<String, Fail>>,
    next_pid: AtomicI32,
    boots: AtomicU64,
    exec: Mutex<Option<Arc<ExecScript>>>,
}

pub type ExecScript = dyn Fn(&GuestExecRequest, &mut GuestState) -> Result<GuestExecOutcome> + Send + Sync;

impl std::fmt::Debug for FakeWorld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FakeWorld")
    }
}

impl FakeWorld {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { next_pid: AtomicI32::new(40_000), ..Default::default() })
    }

    pub fn fail_next(&self, method: &str, f: Fail) {
        self.fail.lock().unwrap_or_else(|e| e.into_inner()).insert(method.to_owned(), f);
    }

    pub fn set_exec(&self, s: Arc<ExecScript>) {
        *self.exec.lock().unwrap_or_else(|e| e.into_inner()) = Some(s);
    }

    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn clear_calls(&self) {
        self.calls.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    pub fn vm_count(&self) -> usize {
        self.vms.lock().unwrap_or_else(|e| e.into_inner()).values().filter(|v| v.phase != VmmState::Absent).count()
    }

    /// Mutate the guest of the VM with this jail id (e.g. "break the environment").
    pub fn with_guest<R>(&self, jail_id: &str, f: impl FnOnce(&mut GuestState) -> R) -> Option<R> {
        self.vms.lock().unwrap_or_else(|e| e.into_inner()).get_mut(jail_id).map(|v| f(&mut v.guest))
    }

    pub fn set_phase(&self, jail_id: &str, phase: VmmState) {
        if let Some(v) = self.vms.lock().unwrap_or_else(|e| e.into_inner()).get_mut(jail_id) {
            v.phase = phase;
        }
    }

    pub fn jail_ids(&self) -> Vec<String> {
        let mut v: Vec<_> = self
            .vms
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(_, x)| x.phase != VmmState::Absent)
            .map(|(k, _)| k.clone())
            .collect();
        v.sort();
        v
    }

    fn take_fail(&self, method: &str) -> Option<Fail> {
        self.fail.lock().unwrap_or_else(|e| e.into_inner()).remove(method)
    }
}

#[derive(Debug)]
pub struct FakeBackend {
    world: Arc<FakeWorld>,
    layout: Arc<Layout>,
    clock: Arc<dyn Clock>,
    identity: BackendIdentity,
    caps: CapabilityProfile,
}

fn sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

impl FakeBackend {
    pub fn new(world: Arc<FakeWorld>, layout: Arc<Layout>, clock: Arc<dyn Clock>) -> Self {
        Self {
            world,
            layout,
            clock,
            identity: BackendIdentity {
                name: "fake".into(),
                version: "v0.0.0".into(),
                security_profile_id: "fake-profile".into(),
                profile: serde_json::json!({"fake": true}),
            },
            caps: CapabilityProfile {
                backend: "fake".into(),
                pause_resume: true,
                snapshot: true,
                restore: true,
                guest_exec: true,
                network_modes: vec![NetworkMode::None],
                max_vcpus: 32,
            },
        }
    }

    fn log(&self, what: impl Into<String>) {
        self.world.calls.lock().unwrap_or_else(|e| e.into_inner()).push(what.into());
    }

    /// Run `effect`, honouring a scripted failure for `method`.
    fn guarded<T>(&self, method: &str, effect: impl FnOnce() -> Result<T>) -> Result<T> {
        self.log(method);
        match self.world.take_fail(method) {
            Some(Fail::Before(e)) => Err(e),
            Some(Fail::After(e)) => {
                effect()?;
                Err(e)
            }
            None => effect(),
        }
    }

    fn new_process(&self) -> ProcessIdentity {
        let pid = self.world.next_pid.fetch_add(1, Ordering::SeqCst);
        ProcessIdentity { pid, start_time_ticks: pid as u64 * 7, boot_id: self.clock.boot_id() }
    }

    fn fresh_guest(&self, jail: &str) -> GuestState {
        let n = self.world.boots.fetch_add(1, Ordering::SeqCst);
        GuestState { boot_id: format!("boot-{jail}-{n}"), canary: format!("canary-{jail}"), files: BTreeMap::new() }
    }

    fn outcome(&self, p: ProcessIdentity) -> StartOutcome {
        let posture =
            SecurityPosture { uid: 100_000, gid: 100_000, seccomp_mode: 2, no_new_privs: true, caps_dropped: true, chrooted: true };
        StartOutcome {
            process: p,
            posture,
            network: evaluate_none(0, true, None),
            agent_version: "fake-0".into(),
            guest_boot_id: "fake".into(),
            boot_ms: 1,
        }
    }

    fn kill_vm(&self, jail: &str) {
        if let Some(v) = self.world.vms.lock().unwrap_or_else(|e| e.into_inner()).get_mut(jail) {
            v.phase = VmmState::Absent;
        }
    }
}

#[async_trait]
impl SandboxBackend for FakeBackend {
    fn identity(&self) -> &BackendIdentity {
        &self.identity
    }
    fn capabilities(&self) -> &CapabilityProfile {
        &self.caps
    }

    async fn provision(&self, req: &ProvisionRequest<'_>) -> Result<BackendHandle> {
        self.guarded("provision", || {
            if GenerationDir::open(&self.layout, &req.sandbox.sandbox_id, req.sandbox.generation)?.is_none() {
                return Err(AcfError::internal("coordinator must create the generation directory before provisioning"));
            }
            Ok(BackendHandle {
                sandbox: req.sandbox.clone(),
                uid: 100_000 + req.uid_slot,
                gid: 100_000 + req.uid_slot,
                resources: req.resources.clone(),
                boot_args: "fake".into(),
                process: None,
            })
        })
    }

    async fn start(&self, h: &BackendHandle, sink: &dyn LaunchSink) -> Result<StartOutcome> {
        self.log("start");
        let jail = h.sandbox.jail_id();
        let planned = self.world.take_fail("start");
        if let Some(Fail::Before(e)) = &planned {
            return Err(e.clone());
        }
        let p = self.new_process();
        let guest = self.fresh_guest(&jail);
        self.world
            .vms
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(jail.clone(), FakeVm { process: p.clone(), phase: VmmState::Running, guest });
        if let Err(e) = sink.launched(&p).await {
            self.kill_vm(&jail);
            return Err(e);
        }
        if let Some(Fail::After(e)) = planned {
            // like the real backend: a VMM that could not finish booting is killed before the error returns
            self.kill_vm(&jail);
            return Err(e);
        }
        Ok(self.outcome(p))
    }

    async fn observe(&self, h: &BackendHandle) -> Result<Observation> {
        self.log("observe");
        let jail = h.sandbox.jail_id();
        let jail_present = GenerationDir::open(&self.layout, &h.sandbox.sandbox_id, h.sandbox.generation)?.is_some();
        let vms = self.world.vms.lock().unwrap_or_else(|e| e.into_inner());
        Ok(match vms.get(&jail) {
            Some(v) if v.phase != VmmState::Absent => {
                let same = h.process.as_ref().is_none_or(|p| *p == v.process);
                Observation {
                    vmm: if same { v.phase.clone() } else { VmmState::Unknown("pid held by another process".into()) },
                    identity: Some(if same { IdentityCheckView::Match } else { IdentityCheckView::Mismatch("different process".into()) }),
                    posture: None,
                    jail_present,
                }
            }
            _ => Observation { vmm: VmmState::Absent, identity: Some(IdentityCheckView::Gone), posture: None, jail_present },
        })
    }

    async fn pause(&self, h: &BackendHandle) -> Result<()> {
        self.guarded("pause", || {
            self.world
                .vms
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get_mut(&h.sandbox.jail_id())
                .ok_or_else(|| AcfError::conflict("no VMM"))?
                .phase = VmmState::Paused;
            Ok(())
        })
    }

    async fn resume(&self, h: &BackendHandle) -> Result<()> {
        self.guarded("resume", || {
            self.world
                .vms
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get_mut(&h.sandbox.jail_id())
                .ok_or_else(|| AcfError::conflict("no VMM"))?
                .phase = VmmState::Running;
            Ok(())
        })
    }

    async fn snapshot(&self, h: &BackendHandle, req: &SnapshotRequest<'_>) -> Result<SnapshotArtifacts> {
        self.guarded("snapshot", || {
            let jail = h.sandbox.jail_id();
            let guest = self
                .world
                .vms
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&jail)
                .ok_or_else(|| AcfError::conflict("no VMM"))?
                .guest
                .clone();
            let write = |name: &str, bytes: &[u8]| -> Result<FileDigest> {
                let mut o = cap_std::fs::OpenOptions::new();
                o.write(true).create_new(true).mode(0o600);
                let mut f = req.dest.open_with(name, &o)?.into_std();
                f.write_all(bytes)?;
                f.sync_all()?;
                Ok(FileDigest { name: name.into(), bytes: bytes.len() as u64, sha256: sha(bytes) })
            };
            // vmstate content is unique per snapshot so the captured guest can be found on restore
            let n = self.world.captured.lock().unwrap_or_else(|e| e.into_inner()).len();
            let vmstate = write("vmstate", format!("VMSTATE:{jail}:{n}:{}", guest.digest()).as_bytes())?;
            let mem = write("mem", &[7u8; 4096])?;
            let disk = write("disk", format!("DISK:{jail}:{}", guest.digest()).as_bytes())?;
            self.world.captured.lock().unwrap_or_else(|e| e.into_inner()).insert(vmstate.sha256.clone(), guest);
            Ok(SnapshotArtifacts { vmstate, mem, disk, vmm_version: "v0.0.0".into() })
        })
    }

    async fn restore(&self, req: &RestoreRequest<'_>, sink: &dyn LaunchSink) -> Result<(BackendHandle, StartOutcome)> {
        self.log("restore");
        let planned = self.world.take_fail("restore");
        if let Some(Fail::Before(e)) = &planned {
            return Err(e.clone());
        }
        // Verify-by-reading, like the real backend: nothing unverified is loaded.
        for (name, d) in [("vmstate", &req.expected.vmstate), ("mem", &req.expected.mem), ("disk", &req.expected.disk)] {
            let mut f = req.source.open(name)?.into_std();
            let c = crate::filesystem::hashcopy::hash_reader(&mut f, d.bytes + 1)?;
            if c.sha256 != d.sha256 {
                return Err(AcfError::corrupt(format!("{name}: bytes do not match the manifest digest")));
            }
        }
        let guest = self
            .world
            .captured
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&req.expected.vmstate.sha256)
            .cloned()
            .ok_or_else(|| AcfError::corrupt("no captured guest state for this snapshot"))?;
        let jail = req.sandbox.jail_id();
        let p = self.new_process();
        self.world
            .vms
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(jail.clone(), FakeVm { process: p.clone(), phase: VmmState::Running, guest });
        sink.launched(&p).await?;
        if let Some(Fail::After(e)) = planned {
            self.kill_vm(&jail);
            return Err(e);
        }
        let handle = BackendHandle {
            sandbox: req.sandbox.clone(),
            uid: 100_000 + req.uid_slot,
            gid: 100_000 + req.uid_slot,
            resources: req.resources.clone(),
            boot_args: String::new(),
            process: Some(p.clone()),
        };
        Ok((handle, self.outcome(p)))
    }

    async fn discover(&self, s: &SandboxRef) -> Result<Option<ProcessIdentity>> {
        Ok(self
            .world
            .vms
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&s.jail_id())
            .filter(|v| v.phase != VmmState::Absent)
            .map(|v| v.process.clone()))
    }

    async fn stop(&self, h: &BackendHandle, _grace: Duration) -> Result<StopOutcome> {
        self.guarded("stop", || {
            let mut vms = self.world.vms.lock().unwrap_or_else(|e| e.into_inner());
            match vms.get_mut(&h.sandbox.jail_id()) {
                Some(v) if v.phase != VmmState::Absent => {
                    // identity-verified: a recorded identity that does not match is "someone else's pid"
                    if h.process.as_ref().is_some_and(|p| *p != v.process) {
                        return Ok(StopOutcome::Refused("pid belongs to another process".into()));
                    }
                    v.phase = VmmState::Absent;
                    Ok(StopOutcome::Stopped)
                }
                _ => Ok(StopOutcome::AlreadyGone),
            }
        })
    }

    async fn teardown(&self, s: &SandboxRef, nonce: &str) -> Result<TeardownOutcome> {
        self.guarded("teardown", || {
            if self.world.vms.lock().unwrap_or_else(|e| e.into_inner()).get(&s.jail_id()).is_some_and(|v| v.phase != VmmState::Absent) {
                return Err(AcfError::conflict("VMM still running; stop it before teardown"));
            }
            Ok(match remove_generation(&self.layout, &s.sandbox_id, s.generation, nonce)? {
                crate::filesystem::CleanupOutcome::Removed => TeardownOutcome::Removed,
                crate::filesystem::CleanupOutcome::Absent => TeardownOutcome::Absent,
                crate::filesystem::CleanupOutcome::Quarantine { reason } => TeardownOutcome::Quarantine(reason),
            })
        })
    }

    async fn exec(&self, h: &BackendHandle, req: &GuestExecRequest, cancel: CancellationToken) -> Result<GuestExecOutcome> {
        self.log("exec");
        match self.world.take_fail("exec") {
            Some(Fail::Before(e)) => return Err(e),
            Some(Fail::After(e)) => {
                // the command ran in the guest, but the result was lost
                if let Some(v) = self.world.vms.lock().unwrap_or_else(|e| e.into_inner()).get_mut(&h.sandbox.jail_id()) {
                    v.guest.files.insert("ran".into(), req.exec_id.clone());
                }
                return Err(e);
            }
            None => {}
        }
        if cancel.is_cancelled() {
            return Err(AcfError::internal("cancelled before start"));
        }
        let script = self.world.exec.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let mut vms = self.world.vms.lock().unwrap_or_else(|e| e.into_inner());
        let v = vms.get_mut(&h.sandbox.jail_id()).ok_or_else(|| AcfError::new(FailureClass::BackendCrash, "no VMM"))?;
        match script {
            Some(s) => s(req, &mut v.guest),
            None => {
                let out = format!("{}\n", req.command.argv.join(" ")).into_bytes();
                Ok(GuestExecOutcome {
                    result: ExecResult {
                        exec_id: req.exec_id.clone(),
                        status: ExecStatus::Exited { code: 0 },
                        stdout_total_bytes: out.len() as u64,
                        stdout: out,
                        stderr: vec![],
                        stderr_total_bytes: 0,
                        stdout_truncated: false,
                        stderr_truncated: false,
                        duration_ms: 1,
                        pid_limit_hit: false,
                        output_incomplete: false,
                        containment: Containment::Cgroup2,
                    },
                    host_deadline_hit: false,
                    vm_killed: false,
                })
            }
        }
    }

    async fn probe(&self, h: &BackendHandle) -> Result<ProbeReport> {
        self.guarded("probe", || {
            let vms = self.world.vms.lock().unwrap_or_else(|e| e.into_inner());
            let v = vms
                .get(&h.sandbox.jail_id())
                .filter(|v| v.phase != VmmState::Absent)
                .ok_or_else(|| AcfError::new(FailureClass::BackendUnavailable, "no VMM"))?;
            Ok(ProbeReport {
                nonce: "n".into(),
                boot_id: v.guest.boot_id.clone(),
                canary_sha256: sha(v.guest.canary.as_bytes()),
                agent_version: "fake-0".into(),
                state_digest: v.guest.digest(),
            })
        })
    }

    async fn stats(&self, _h: &BackendHandle) -> Result<Option<CgroupStats>> {
        Ok(None)
    }
}
