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
    collections::{BTreeMap, BTreeSet, HashMap},
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
    backend::process::SecurityPosture,
    backend::*,
    clock::Clock,
    domain::NetworkMode,
    error::{AcfError, FailureClass, Result},
    ids::SandboxRef,
    network::evaluate_none,
    storage::{GenerationDir, Layout, generation::remove_generation},
    store::ProcessIdentity,
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
    /// The runtime is gone and its process id is now held by something that is not ours (pid reuse).
    /// It is observed as a mismatch and must never be signalled.
    pub foreign: bool,
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
    /// Jail ids whose isolation controls are reported as no longer in force (posture drift).
    degraded: Mutex<HashMap<String, Vec<String>>>,
    /// Jail ids whose observation cannot be completed.
    unobservable: Mutex<BTreeSet<String>>,
    /// Identifier slots a live resource carries, whatever the store says (RS-3).
    busy_slots: Mutex<BTreeSet<u32>>,
    /// Agent version the guests report (GP-4). `None`: the version the test image records.
    agent_version: Mutex<Option<String>>,
    /// `(variable, sha256 of the material)` for every secret delivered to a guest. Never the material.
    delivered_secrets: Mutex<Vec<(String, String)>>,
    /// Jail ids whose runtime cannot be ended (a stop reports `StillAlive`).
    unkillable: Mutex<BTreeSet<String>>,
    /// Methods that wait at their start until released: how a test holds an operation in flight.
    gates: Mutex<HashMap<String, Arc<tokio::sync::Semaphore>>>,
    /// Calls waiting at a gate right now, per method.
    waiting: Mutex<HashMap<String, u64>>,
    /// Run when a method is called: how a test makes time pass in the middle of an operation.
    hooks: Mutex<HashMap<String, Hook>>,
    /// Capabilities the next backend built over this world does not declare (BK-5).
    withheld: Mutex<BTreeSet<String>>,
    /// The version the next backend built over this world identifies as (§26.2).
    backend_version: Mutex<Option<String>>,
    /// Size of the identifier pool the next backend built over this world declares.
    identifier_slots: Mutex<Option<u32>>,
}

type Hook = Arc<dyn Fn() + Send + Sync>;

/// Counts one call as waiting at a gate for as long as it lives. A guard, because the host may drop
/// the call (preemption) instead of letting it return.
struct Waiting<'a> {
    world: &'a FakeWorld,
    method: &'a str,
}

impl<'a> Waiting<'a> {
    fn enter(world: &'a FakeWorld, method: &'a str) -> Self {
        *world.waiting.lock().unwrap_or_else(|e| e.into_inner()).entry(method.to_owned()).or_insert(0) += 1;
        Self { world, method }
    }
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        if let Some(n) = self.world.waiting.lock().unwrap_or_else(|e| e.into_inner()).get_mut(self.method) {
            *n = n.saturating_sub(1);
        }
    }
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

    pub fn degrade(&self, jail_id: &str, violations: &[&str]) {
        self.degraded
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(jail_id.to_owned(), violations.iter().map(|v| (*v).to_owned()).collect());
    }

    pub fn set_unobservable(&self, jail_id: &str, on: bool) {
        let mut u = self.unobservable.lock().unwrap_or_else(|e| e.into_inner());
        if on {
            u.insert(jail_id.to_owned());
        } else {
            u.remove(jail_id);
        }
    }

    pub fn set_unkillable(&self, jail_id: &str, on: bool) {
        let mut u = self.unkillable.lock().unwrap_or_else(|e| e.into_inner());
        if on {
            u.insert(jail_id.to_owned());
        } else {
            u.remove(jail_id);
        }
    }

    pub fn set_busy_slots(&self, slots: &[u32]) {
        *self.busy_slots.lock().unwrap_or_else(|e| e.into_inner()) = slots.iter().copied().collect();
    }

    pub fn set_agent_version(&self, v: &str) {
        *self.agent_version.lock().unwrap_or_else(|e| e.into_inner()) = Some(v.to_owned());
    }

    pub fn delivered_secrets(&self) -> Vec<(String, String)> {
        self.delivered_secrets.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// From now on a call of `method` waits at its start until [`FakeWorld::release`]. An execution
    /// (`"exec"`) also ends, as `Cancelled`, when the host cancels it.
    pub fn hold(&self, method: &str) {
        self.gates.lock().unwrap_or_else(|e| e.into_inner()).insert(method.to_owned(), Arc::new(tokio::sync::Semaphore::new(0)));
    }

    /// Let every call held at `method` proceed, and stop holding later ones.
    pub fn release(&self, method: &str) {
        if let Some(gate) = self.gates.lock().unwrap_or_else(|e| e.into_inner()).remove(method) {
            gate.add_permits(tokio::sync::Semaphore::MAX_PERMITS / 2);
        }
    }

    /// Calls of `method` that are waiting at its gate right now.
    pub fn waiting(&self, method: &str) -> u64 {
        self.waiting.lock().unwrap_or_else(|e| e.into_inner()).get(method).copied().unwrap_or(0)
    }

    /// Run `hook` every time `method` is called, before its effect.
    pub fn on_call(&self, method: &str, hook: impl Fn() + Send + Sync + 'static) {
        self.hooks.lock().unwrap_or_else(|e| e.into_inner()).insert(method.to_owned(), Arc::new(hook));
    }

    pub fn clear_hooks(&self) {
        self.hooks.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    /// The next backend built over this world (the next activation) does not declare `capability`:
    /// one of `snapshot`, `restore`, `guest_exec`, `secret_injection`, `allowlist`.
    pub fn withhold(&self, capability: &str) {
        self.withheld.lock().unwrap_or_else(|e| e.into_inner()).insert(capability.to_owned());
    }

    /// The next backend built over this world has an identifier pool of `slots`.
    pub fn set_identifier_slots(&self, slots: u32) {
        *self.identifier_slots.lock().unwrap_or_else(|e| e.into_inner()) = Some(slots);
    }

    /// The next backend built over this world identifies as `version`.
    pub fn set_backend_version(&self, version: &str) {
        *self.backend_version.lock().unwrap_or_else(|e| e.into_inner()) = Some(version.to_owned());
    }

    fn gate_of(&self, method: &str) -> Option<Arc<tokio::sync::Semaphore>> {
        self.gates.lock().unwrap_or_else(|e| e.into_inner()).get(method).cloned()
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
        self.vms.lock().unwrap_or_else(|e| e.into_inner()).values().filter(|v| v.phase != VmmState::Absent && !v.foreign).count()
    }

    /// Mutate the guest of the VM with this jail id (e.g. "break the environment").
    pub fn with_guest<R>(&self, jail_id: &str, f: impl FnOnce(&mut GuestState) -> R) -> Option<R> {
        self.vms.lock().unwrap_or_else(|e| e.into_inner()).get_mut(jail_id).map(|v| f(&mut v.guest))
    }

    /// The runtime of `jail_id` died and an unrelated process now holds its process id.
    pub fn make_foreign(&self, jail_id: &str) {
        if let Some(v) = self.vms.lock().unwrap_or_else(|e| e.into_inner()).get_mut(jail_id) {
            v.foreign = true;
        }
    }

    /// Whether the unrelated process that took over `jail_id`'s process id is still alive.
    pub fn foreign_alive(&self, jail_id: &str) -> bool {
        self.vms.lock().unwrap_or_else(|e| e.into_inner()).get(jail_id).is_some_and(|v| v.foreign && v.phase != VmmState::Absent)
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
            .filter(|(_, x)| x.phase != VmmState::Absent && !x.foreign)
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
        let withheld = world.withheld.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let has = |capability: &str| !withheld.contains(capability);
        let version = world.backend_version.lock().unwrap_or_else(|e| e.into_inner()).clone().unwrap_or_else(|| "v0.0.0".to_owned());
        let network_modes = if has("allowlist") { vec![NetworkMode::None, NetworkMode::Allowlist] } else { vec![NetworkMode::None] };
        let identifier_slots = world.identifier_slots.lock().unwrap_or_else(|e| e.into_inner()).unwrap_or(4096);
        Self {
            world,
            layout,
            clock,
            identity: BackendIdentity {
                name: "fake".into(),
                version,
                security_profile_id: "fake-profile".into(),
                profile: serde_json::json!({"fake": true}),
            },
            caps: CapabilityProfile {
                backend: "fake".into(),
                pause_resume: true,
                snapshot: has("snapshot"),
                restore: has("restore"),
                guest_exec: has("guest_exec"),
                network_modes,
                max_vcpus: 32,
                secret_injection: has("secret_injection"),
                incremental_output: false,
                restore_reseeds_entropy: false,
                runtime_depends_on_snapshot: false,
                runtime_depends_on_image: false,
                per_runtime_overhead_mib: 64,
                identifier_slots,
                stop_grace_ms: 100,
            },
        }
    }

    fn log(&self, what: impl Into<String>) {
        let what = what.into();
        let hook = self.world.hooks.lock().unwrap_or_else(|e| e.into_inner()).get(&what).cloned();
        self.world.calls.lock().unwrap_or_else(|e| e.into_inner()).push(what);
        if let Some(hook) = hook {
            hook();
        }
    }

    /// Wait at the gate of `method`, if a test is holding it.
    async fn gate(&self, method: &str) {
        if let Some(gate) = self.world.gate_of(method) {
            let _waiting = Waiting::enter(&self.world, method);
            let _ = gate.acquire().await;
        }
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
        let posture = SecurityPosture {
            uid: 100_000,
            gid: 100_000,
            seccomp_mode: 2,
            no_new_privs: true,
            caps_dropped: true,
            seccomp_own_filter: true,
            seccomp_own_filter_at_launch: true,
            chrooted: true,
        };
        StartOutcome {
            process: p,
            posture,
            network: evaluate_none(0, true, None),
            agent_version: self.agent_version(),
            guest_boot_id: "fake".into(),
            boot_ms: 1,
        }
    }

    /// The version the guest reports: by default the one `images::test_support::install` records.
    fn agent_version(&self) -> String {
        self.world.agent_version.lock().unwrap_or_else(|e| e.into_inner()).clone().unwrap_or_else(|| "0.1.0".to_owned())
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
        self.gate("provision").await;
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
        self.gate("start").await;
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
            .insert(jail.clone(), FakeVm { process: p.clone(), phase: VmmState::Running, guest, foreign: false });
        if let Err(e) = sink.launched(&Launched { process: p.clone(), kill_switch: None }).await {
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
        if self.world.unobservable.lock().unwrap_or_else(|e| e.into_inner()).contains(&jail) {
            return Err(AcfError::unavailable("observation could not be completed").with_possible_side_effect());
        }
        let jail_present = GenerationDir::open(&self.layout, &h.sandbox.sandbox_id, h.sandbox.generation)?.is_some();
        let degraded = self.world.degraded.lock().unwrap_or_else(|e| e.into_inner()).get(&jail).cloned();
        let vms = self.world.vms.lock().unwrap_or_else(|e| e.into_inner());
        Ok(match vms.get(&jail) {
            Some(v) if v.phase != VmmState::Absent => {
                let same = !v.foreign && h.process.as_ref().is_none_or(|p| *p == v.process);
                Observation {
                    vmm: if same { v.phase.clone() } else { VmmState::Unknown("pid held by another process".into()) },
                    identity: Some(if same { IdentityCheckView::Match } else { IdentityCheckView::Mismatch("different process".into()) }),
                    posture: None,
                    enforcement: match degraded {
                        Some(v) => EnforcementObservation::Degraded(v),
                        None => EnforcementObservation::Intact,
                    },
                    jail_present,
                }
            }
            _ => Observation {
                vmm: VmmState::Absent,
                identity: Some(IdentityCheckView::Gone),
                posture: None,
                enforcement: EnforcementObservation::NotApplicable,
                jail_present,
            },
        })
    }

    async fn pause(&self, h: &BackendHandle) -> Result<()> {
        self.gate("pause").await;
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
        self.gate("resume").await;
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
        self.gate("snapshot").await;
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
        self.gate("restore").await;
        self.log("restore");
        let planned = self.world.take_fail("restore");
        if let Some(Fail::Before(e)) = &planned {
            return Err(e.clone());
        }
        // Verify-by-reading, like the real backend: nothing unverified is loaded.
        for (name, d) in [("vmstate", &req.expected.vmstate), ("mem", &req.expected.mem), ("disk", &req.expected.disk)] {
            let mut f = req.source.open(name)?.into_std();
            let c = crate::storage::hashcopy::hash_reader(&mut f, d.bytes + 1)?;
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
            .insert(jail.clone(), FakeVm { process: p.clone(), phase: VmmState::Running, guest, foreign: false });
        if let Err(e) = sink.launched(&Launched { process: p.clone(), kill_switch: None }).await {
            self.kill_vm(&jail);
            return Err(e);
        }
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
            .filter(|v| v.phase != VmmState::Absent && !v.foreign)
            .map(|v| v.process.clone()))
    }

    async fn stop(&self, h: &BackendHandle, _grace: Duration) -> Result<StopOutcome> {
        self.gate("stop").await;
        self.guarded("stop", || {
            let mut vms = self.world.vms.lock().unwrap_or_else(|e| e.into_inner());
            match vms.get_mut(&h.sandbox.jail_id()) {
                Some(v) if v.phase != VmmState::Absent => {
                    // identity-verified: a recorded identity that does not match is "someone else's pid"
                    if v.foreign || h.process.as_ref().is_some_and(|p| *p != v.process) {
                        return Ok(StopOutcome::Refused("pid belongs to another process".into()));
                    }
                    if self.world.unkillable.lock().unwrap_or_else(|e| e.into_inner()).contains(&h.sandbox.jail_id()) {
                        return Ok(StopOutcome::StillAlive);
                    }
                    v.phase = VmmState::Absent;
                    Ok(StopOutcome::Stopped)
                }
                _ => Ok(StopOutcome::AlreadyGone),
            }
        })
    }

    async fn teardown(&self, s: &SandboxRef, nonce: &str) -> Result<TeardownOutcome> {
        self.gate("teardown").await;
        self.guarded("teardown", || {
            if self
                .world
                .vms
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&s.jail_id())
                .is_some_and(|v| v.phase != VmmState::Absent && !v.foreign)
            {
                return Err(AcfError::conflict("VMM still running; stop it before teardown"));
            }
            Ok(match remove_generation(&self.layout, &s.sandbox_id, s.generation, nonce)? {
                crate::storage::CleanupOutcome::Removed => TeardownOutcome::Removed,
                crate::storage::CleanupOutcome::Absent => TeardownOutcome::Absent,
                crate::storage::CleanupOutcome::Quarantine { reason } => TeardownOutcome::Quarantine(reason),
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
        if !req.secrets.is_empty() && !self.caps.secret_injection {
            // The port's rule for every backend: material it does not declare delivery of is refused.
            return Err(AcfError::unsupported("this backend does not deliver secret material to a guest"));
        }
        // Delivery of secret material: the double keeps only a digest of what it was handed.
        for (name, material) in &req.secrets {
            self.world.delivered_secrets.lock().unwrap_or_else(|e| e.into_inner()).push((name.clone(), sha(material.expose())));
        }
        if let Some(gate) = self.world.gate_of("exec") {
            // The command is in the guest until the test releases it or the host cancels it.
            let _waiting = Waiting::enter(&self.world, "exec");
            tokio::select! {
                _ = gate.acquire() => {}
                () = cancel.cancelled() => {
                    return Ok(GuestExecOutcome {
                        result: ExecResult {
                            exec_id: req.exec_id.clone(),
                            status: ExecStatus::Cancelled,
                            stdout: vec![],
                            stdout_total_bytes: 0,
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
                    });
                }
            }
        }
        let script = self.world.exec.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let mut vms = self.world.vms.lock().unwrap_or_else(|e| e.into_inner());
        let v = vms.get_mut(&h.sandbox.jail_id()).ok_or_else(|| AcfError::new(FailureClass::DependencyUnavailable, "no VMM"))?;
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
        self.gate("probe").await;
        self.guarded("probe", || {
            let vms = self.world.vms.lock().unwrap_or_else(|e| e.into_inner());
            let v = vms
                .get(&h.sandbox.jail_id())
                .filter(|v| v.phase != VmmState::Absent)
                .ok_or_else(|| AcfError::new(FailureClass::DependencyUnavailable, "no VMM"))?;
            Ok(ProbeReport {
                nonce: "n".into(),
                boot_id: v.guest.boot_id.clone(),
                canary_sha256: sha(v.guest.canary.as_bytes()),
                agent_version: self.agent_version(),
                state_digest: v.guest.digest(),
            })
        })
    }

    async fn stats(&self, _h: &BackendHandle) -> Result<Option<RuntimeUsage>> {
        Ok(None)
    }

    async fn busy_slots(&self) -> Result<BTreeSet<u32>> {
        self.guarded("busy_slots", || Ok(self.world.busy_slots.lock().unwrap_or_else(|e| e.into_inner()).clone()))
    }

    async fn residue(&self, h: &BackendHandle) -> Result<Vec<String>> {
        self.guarded("residue", || {
            let mut found = Vec::new();
            if self
                .world
                .vms
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&h.sandbox.jail_id())
                .is_some_and(|v| v.phase != VmmState::Absent && !v.foreign)
            {
                found.push("runtime process".to_owned());
            }
            if self.layout.generation_path(&h.sandbox.sandbox_id, h.sandbox.generation).exists() {
                found.push("generation directory".to_owned());
            }
            Ok(found)
        })
    }

    async fn force_teardown(&self, h: &BackendHandle) -> Result<()> {
        self.guarded("force_teardown", || {
            let path = self.layout.generation_path(&h.sandbox.sandbox_id, h.sandbox.generation);
            match std::fs::remove_dir_all(&path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e.into()),
            }
        })
    }
}
