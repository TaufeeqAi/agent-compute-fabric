//! `FirecrackerBackend`: the backend port (contract §26) implemented for Firecracker driven through
//! the jailer. Everything VMM-specific lives in this directory and nowhere else (BK-4).
//!
//! Boot sequence, each step fail-closed (IS-1, NW-2):
//!
//! ```text
//! provision  verified copies of kernel+rootfs -> payload/, the sandbox's own network namespace
//! network    (mode allowlist only) device, packet filter, sockets, guest-traffic role  [netplumb]
//! launch     jailer (chroot, pid-ns, cgroup v2, unique uid, netns)  --> identity captured+recorded
//! prove      jail id in argv  ->  seccomp/no_new_privs/caps/chroot/uid  ->  inside its namespace
//! configure  link payload into jail -> machine-config, boot-source, drive, vsock, (interface)
//! assert     GET /vm/config shows ZERO network interfaces (mode none) or exactly ONE (allowlist)
//! boot       InstanceStart -> Running -> guest agent Hello -> network verdict
//! ```
//!
//! If *any* step fails after the VMM exists, the VMM is killed before the error is returned, so a
//! failed start never leaves a live, half-configured VM behind.

use std::{
    collections::BTreeSet,
    os::fd::OwnedFd,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use acf_wire::guest::{GUEST_VSOCK_PORT, ProbeReport};
use async_trait::async_trait;
use cap_std::fs::{Dir, OpenOptions, OpenOptionsExt};
use sha2::{Digest, Sha256};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

use super::{
    client::FcClient,
    jailer::{self, API_SOCK, JailerArgs, PID_FILE, ProcessInspector, VSOCK_SOCK},
    models::{
        BootSource, Drive, FullVmConfig, InstanceAction, InstanceInfo, MachineConfig, MemBackend, NetworkInterface, SnapshotCreate,
        SnapshotLoad, VmState, Vsock,
    },
    netplumb,
    verify::{self, trusted_executable},
};
use crate::{
    backend::netns::Netns,
    backend::process::{CgroupSpec, IdentityCheck, TerminateOutcome, VmProcess, limits},
    backend::*,
    clock::Clock,
    config::HostConfig,
    domain::{NetworkIntent, NetworkMode},
    error::{AcfError, FailureClass, Result},
    guest::{GuestClient, UdsTarget, VmBackstop, VsockUdsConnector},
    ids::SandboxRef,
    network::{GuestSegment, NetworkStatus, evaluate_allowlist, evaluate_none, traffic},
    privsep::RoleIdentity,
    storage::{CleanupOutcome, GenerationDir, Layout, generation::remove_generation, hashcopy::copy_hashed},
    store::ProcessIdentity,
};

const MIB: u64 = 1024 * 1024;
const PAYLOAD: &str = "payload";
const GUEST_CID: u32 = 3;
const FC_CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// A full snapshot writes the guest's memory to disk inside one API call, and a load reads its
/// state back. Those two calls get a deadline that grows with the memory size: one minute, or the
/// time a disk writing 10 MiB/s needs, whichever is longer. The operation's own deadline bounds
/// both from above.
fn snapshot_call_timeout(memory_mib: u64) -> Duration {
    Duration::from_secs(60).max(Duration::from_millis(memory_mib.saturating_mul(100)))
}
const MAX_KERNEL_BYTES: u64 = 256 * MIB;
/// Where the digest of a generation's packet filter is kept (in the generation's directory, outside the jail).
const NET_DIGEST_FILE: &str = "net.digest";

#[derive(Debug)]
pub struct FirecrackerBackend {
    cfg: Arc<HostConfig>,
    layout: Arc<Layout>,
    clock: Arc<dyn Clock>,
    inspector: Arc<dyn ProcessInspector>,
    identity: BackendIdentity,
    caps: CapabilityProfile,
    /// The guest segment, when network mode `allowlist` is offered on this host.
    segment: Option<GuestSegment>,
    /// When each generation's packet filter was last compared with what was loaded (IS-3).
    filter_checked: std::sync::Mutex<std::collections::HashMap<String, Instant>>,
}

fn fc_name(path: &Path) -> String {
    path.file_name().map_or_else(|| "firecracker".into(), |n| n.to_string_lossy().into_owned())
}

impl FirecrackerBackend {
    pub fn new(cfg: Arc<HostConfig>, layout: Arc<Layout>, clock: Arc<dyn Clock>, inspector: Arc<dyn ProcessInspector>) -> Self {
        // Mode `allowlist` is declared only where it can be built: a valid guest segment, and the
        // three executables the plumbing runs as root, each a trusted input (TI-1). Otherwise a
        // request for it is refused with UNSUPPORTED (BK-5); mode `none` is unaffected.
        let net = &cfg.network;
        let tools_trusted = [&net.ip_bin, &net.nft_bin, &net.nsenter_bin]
            .iter()
            .all(|bin| trusted_executable(bin, &cfg.security.trusted_owner_uids).is_ok());
        let segment = GuestSegment::parse(&net.guest_segment).ok().filter(|_| tools_trusted);
        let network_modes = if segment.is_some() { vec![NetworkMode::None, NetworkMode::Allowlist] } else { vec![NetworkMode::None] };
        let profile = serde_json::json!({
            "vmm": "firecracker",
            "version": cfg.firecracker.pinned_version,
            "jailer": {"chroot": true, "new_pid_ns": true, "daemonize": true, "cgroup_version": 2,
                       "per_vm_uid_gid": true, "uid_range": [cfg.firecracker.uid_range_start, cfg.firecracker.uid_range_size]},
            "seccomp": "firecracker-default-filters",
            "cgroup_controls": ["cpu.max", "memory.max", "memory.swap.max=0", "memory.oom.group=1", "pids.max"],
            "network": {"modes": network_modes, "vmm_netns": "dedicated-per-sandbox", "routes_out": false,
                        "allowlist": {"filter": "nftables: redirect all guest TCP to the relay; drop everything else", "relay": "unprivileged role, own uid and control group"}},
            "machine": {"smt": false, "serial": "disabled(8250.nr_uarts=0)", "drive_cache": "Unsafe", "io_engine": "Sync"},
            "boot_args_digest": hex::encode(Sha256::digest(cfg.firecracker.boot_args.as_bytes()))[..16].to_owned(),
            "diagnostic_log": cfg.firecracker.diagnostic_log,
        });
        let id = hex::encode(Sha256::digest(profile.to_string().as_bytes()))[..16].to_owned();
        let identity = BackendIdentity {
            name: "firecracker".into(),
            version: cfg.firecracker.pinned_version.clone(),
            security_profile_id: id,
            profile,
        };
        let caps = CapabilityProfile {
            backend: "firecracker".into(),
            pause_resume: true,
            snapshot: true,
            restore: true,
            guest_exec: true,
            network_modes,
            max_vcpus: 32,
            // Not offered by this backend: a request that needs one is refused with UNSUPPORTED (BK-5).
            secret_injection: false,
            incremental_output: false,
            // A restore resumes the captured memory image; nothing reseeds the guest's entropy pool.
            restore_reseeds_entropy: false,
            // Snapshot and image files are copied, and verified while copied, into the generation's
            // own directory: a running generation depends on neither store afterwards (RF-1, IM-4).
            runtime_depends_on_snapshot: false,
            runtime_depends_on_image: false,
            per_runtime_overhead_mib: cfg.firecracker.vmm_overhead_mib,
            identifier_slots: cfg.firecracker.uid_range_size,
            stop_grace_ms: cfg.firecracker.shutdown_grace_ms,
        };
        Self { cfg, layout, clock, inspector, identity, caps, segment, filter_checked: std::sync::Mutex::default() }
    }

    // ---------- network mode `allowlist` ----------

    fn relay_cgroup(&self, jail_id: &str) -> PathBuf {
        netplumb::relay_cgroup(&self.cfg.firecracker.cgroup_root.join(&self.cfg.firecracker.cgroup_parent), jail_id)
    }

    /// End the guest-traffic role of a generation, if it has one. Idempotent.
    fn stop_relay(&self, jail_id: &str) {
        netplumb::kill_cgroup(&self.relay_cgroup(jail_id));
    }

    /// NW-2: everything the guest's connectivity depends on exists **before** the VMM does. A
    /// failure here means the generation never runs.
    async fn plumb_network(&self, h: &BackendHandle) -> Result<()> {
        let NetworkIntent::Allowlist { entries } = &h.resources.network else { return Ok(()) };
        let segment = self.segment.ok_or_else(|| AcfError::unsupported("network mode `allowlist` is not offered on this host"))?;
        let (net, jail_id) = (&self.cfg.network, h.sandbox.jail_id());
        let ns_path = Netns::path_for(&self.netns_dir(), &jail_id);
        let digest = netplumb::configure(net, &ns_path, &segment, h.uid, h.gid).await?;
        crate::storage::layout::write_atomic(self.open_generation(&h.sandbox)?.dir(), NET_DIGEST_FILE, digest.as_bytes())
            .map_err(AcfError::with_possible_side_effect)?;

        // The sockets are bound inside the sandbox's namespace; the role that serves them is not in it.
        let gateway = segment.gateway;
        let bind_in = ns_path.clone();
        let (resolver, relay) = tokio::task::spawn_blocking(move || traffic::sockets_in_namespace(&bind_in, gateway))
            .await
            .map_err(|e| AcfError::internal(format!("the namespace worker did not finish: {e}")))??;
        let config = traffic::role_config(net, entries, &segment, netplumb::host_addresses(net).await?);
        let cgroup = self.relay_cgroup(&jail_id);
        netplumb::create_relay_cgroup(&cgroup).map_err(AcfError::with_possible_side_effect)?;
        // The role's identity is the generation's own, from the second identifier range (PD-3, RS-3).
        let slot = h.uid.saturating_sub(self.cfg.firecracker.uid_range_start);
        let id = net.traffic_uid_start + slot;
        let mut child = traffic::spawn(Some(RoleIdentity { uid: id, gid: id }), &jail_id, &config, &resolver, &relay)
            .map_err(AcfError::with_possible_side_effect)?;
        if let Err(e) = std::fs::write(cgroup.join("cgroup.procs"), child.id().to_string()) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(
                AcfError::unavailable(format!("cannot place the guest-traffic role in its control group: {e}")).with_possible_side_effect()
            );
        }
        // Reaped when it ends; found again, by any later activation, through its control group.
        tokio::task::spawn_blocking(move || child.wait());
        // The role proves it is unprivileged before it serves; one that refused to run is gone by now.
        sleep(Duration::from_millis(150)).await;
        if !netplumb::cgroup_has_processes(&cgroup) {
            return Err(AcfError::security("the guest-traffic role did not start (it refuses to run with any privilege)")
                .with_possible_side_effect());
        }
        Ok(())
    }

    /// IS-3 for mode `allowlist`: the role is running, and the packet filter is what was loaded.
    async fn network_violations(&self, h: &BackendHandle) -> Vec<String> {
        if h.resources.network.mode() != NetworkMode::Allowlist {
            return Vec::new();
        }
        let jail_id = h.sandbox.jail_id();
        let mut v = Vec::new();
        if !netplumb::cgroup_has_processes(&self.relay_cgroup(&jail_id)) {
            v.push("the guest-traffic role is no longer running".to_owned());
        }
        // Listing the filter starts a process, so it is not done at every observation. It is done often
        // enough that the filter never goes unverified for longer than the recheck interval (IS-3).
        let interval = self.cfg.recovery.posture_due_after();
        let due = self.filter_checked.lock().is_ok_and(|mut seen| {
            let due = seen.get(&jail_id).is_none_or(|at| at.elapsed() >= interval);
            if due {
                seen.insert(jail_id.clone(), Instant::now());
            }
            due
        });
        if due {
            let loaded = self
                .open_generation(&h.sandbox)
                .ok()
                .and_then(|g| g.dir().read(NET_DIGEST_FILE).ok())
                .and_then(|b| String::from_utf8(b).ok());
            let now = netplumb::ruleset_digest(&self.cfg.network, &Netns::path_for(&self.netns_dir(), &jail_id)).await.ok();
            match (loaded, now) {
                (Some(a), Some(b)) if a == b => {}
                (Some(_), Some(_)) => v.push("the packet filter of the sandbox's namespace is not the one that was loaded".to_owned()),
                _ => v.push("the packet filter of the sandbox's namespace could not be compared with the one that was loaded".to_owned()),
            }
        }
        v
    }

    // ---------- derived locations (all from validated ids; never from persisted paths) ----------

    fn uid(&self, slot: u32) -> u32 {
        self.cfg.firecracker.uid_range_start + slot
    }

    fn netns_dir(&self) -> PathBuf {
        self.cfg.paths.runtime_dir.join("netns")
    }

    /// Every generation gets a network namespace of its own, whatever its network mode. The tool
    /// that creates it is verified as a trusted executable before each use (TI-1).
    async fn create_netns(&self, jail_id: &str) -> Result<Netns> {
        Netns::create(&self.cfg.network.unshare_bin, &self.cfg.security.trusted_owner_uids, &self.netns_dir(), jail_id).await
    }

    fn cgroup_dir(&self, jail_id: &str) -> PathBuf {
        self.cfg.firecracker.cgroup_root.join(&self.cfg.firecracker.cgroup_parent).join(jail_id)
    }

    fn root_path(&self, s: &SandboxRef) -> PathBuf {
        jailer::chroot_root(&self.layout.jail_base(&s.sandbox_id, s.generation), &self.cfg.firecracker.firecracker_bin, &s.jail_id())
    }

    fn open_generation(&self, s: &SandboxRef) -> Result<GenerationDir> {
        GenerationDir::open(&self.layout, &s.sandbox_id, s.generation)?
            .ok_or_else(|| AcfError::internal(format!("generation directory for {s} does not exist")))
    }

    fn open_root(&self, s: &SandboxRef) -> Result<Dir> {
        let g = self.open_generation(s)?;
        let exec_name = fc_name(&self.cfg.firecracker.firecracker_bin);
        Ok(g.dir().open_dir("jail")?.open_dir(&exec_name)?.open_dir(s.jail_id())?.open_dir("root")?)
    }

    fn uds(&self, s: &SandboxRef, name: &str) -> Result<UdsTarget> {
        Ok(UdsTarget::in_dir(OwnedFd::from(self.open_root(s)?.into_std_file()), name))
    }

    fn fc(&self, s: &SandboxRef) -> Result<FcClient> {
        Ok(FcClient::new(self.uds(s, API_SOCK.trim_start_matches('/'))?, FC_CALL_TIMEOUT))
    }

    /// The API client for the calls that capture or load a snapshot of a guest with `memory_mib`.
    fn fc_snapshot(&self, s: &SandboxRef, memory_mib: u64) -> Result<FcClient> {
        Ok(FcClient::new(self.uds(s, API_SOCK.trim_start_matches('/'))?, snapshot_call_timeout(memory_mib)))
    }

    fn guest(&self, s: &SandboxRef) -> Result<GuestClient> {
        let c = VsockUdsConnector {
            target: self.uds(s, VSOCK_SOCK.trim_start_matches('/'))?,
            port: GUEST_VSOCK_PORT,
            connect_timeout: Duration::from_secs(3),
        };
        Ok(GuestClient::new(Arc::new(c)))
    }

    // ---------- file staging: hash the bytes we copy, compare, then use ----------

    #[allow(clippy::too_many_arguments)]
    fn stage_file(
        &self,
        src: &mut std::fs::File,
        want_sha: &str,
        max: u64,
        dir: &Dir,
        name: &str,
        mode: u32,
        uid: u32,
        gid: u32,
        grow_to: Option<u64>,
    ) -> Result<FileDigest> {
        let mut o = OpenOptions::new();
        o.write(true).create_new(true).mode(mode);
        let mut f = dir.open_with(name, &o)?.into_std();
        let c = match copy_hashed(src, &mut f, max) {
            Ok(c) => c,
            Err(e) => {
                let _ = dir.remove_file(name);
                return Err(e);
            }
        };
        if c.sha256 != want_sha {
            let _ = dir.remove_file(name);
            return Err(AcfError::corrupt(format!("{name}: copied bytes hash to {} but the manifest says {want_sha}", c.sha256)));
        }
        f.set_len(grow_to.map_or(c.bytes, |g| g.max(c.bytes)))?;
        crate::durability::sync_all(&f)?;
        std::os::unix::fs::fchown(&f, Some(uid), Some(gid))?;
        Ok(FileDigest { name: name.to_owned(), bytes: c.bytes, sha256: c.sha256 })
    }

    fn payload_dir(&self, g: &GenerationDir) -> Result<Dir> {
        use cap_std::fs::{DirBuilder, DirBuilderExt};
        let mut b = DirBuilder::new();
        b.mode(0o700);
        match g.dir().create_dir_with(PAYLOAD, &b) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        Ok(g.dir().open_dir(PAYLOAD)?)
    }

    /// IS-3: are the mandatory controls of a present runtime still in force? Read from the kernel,
    /// never from what was asked for at launch.
    async fn enforcement(
        &self,
        h: &BackendHandle,
        p: &ProcessIdentity,
        posture: Option<&crate::backend::process::SecurityPosture>,
    ) -> EnforcementObservation {
        let Some(posture) = posture else {
            return EnforcementObservation::Unknown("the runtime's confinement could not be read".into());
        };
        let jail_id = h.sandbox.jail_id();
        let mut v = posture.violations(h.uid);
        if !self.inspector.in_netns(p.pid, &Netns::path_for(&self.netns_dir(), &jail_id)) {
            v.push("the runtime is not inside its network namespace".into());
        }
        let spec = CgroupSpec::for_sandbox(&h.resources, self.cfg.firecracker.vmm_overhead_mib);
        v.extend(self.inspector.limit_drift(&self.cgroup_dir(&jail_id), &spec));
        v.extend(self.network_violations(h).await);
        if v.is_empty() { EnforcementObservation::Intact } else { EnforcementObservation::Degraded(v) }
    }

    fn fsize(&self, h: &BackendHandle) -> u64 {
        (u64::from(h.resources.disk_mib).max(u64::from(h.resources.memory_mib)) + 256) * MIB
    }

    // ---------- VMM lifecycle helpers ----------

    async fn kill(&self, p: &ProcessIdentity) {
        let _ =
            VmProcess::new(p.clone()).terminate(&self.clock.boot_id(), Duration::from_millis(self.cfg.firecracker.shutdown_grace_ms)).await;
    }

    /// Steps launch→prove. Returns the VMM identity and its (verified) security posture.
    async fn launch_vmm(
        &self,
        h: &BackendHandle,
        sink: &dyn LaunchSink,
    ) -> Result<(ProcessIdentity, crate::backend::process::SecurityPosture, bool)> {
        let s = &h.sandbox;
        let jail_id = s.jail_id();
        let fcfg = &self.cfg.firecracker;
        let ns_path = Netns::path_for(&self.netns_dir(), &jail_id);
        let base = self.layout.jail_base(&s.sandbox_id, s.generation);
        let cg = CgroupSpec::for_sandbox(&h.resources, fcfg.vmm_overhead_mib);
        let args = JailerArgs {
            cfg: fcfg,
            jail_id: &jail_id,
            uid: h.uid,
            gid: h.gid,
            chroot_base: &base,
            netns: Some(&ns_path),
            cgroup_args: cg.jailer_args(),
            nofile: 1024,
            fsize_bytes: self.fsize(h),
        };
        jailer::launch(fcfg, &args).await?;

        // Wait for the VMM to publish its pid file and API socket.
        let deadline = Instant::now() + Duration::from_millis(fcfg.api_ready_timeout_ms);
        let pid = loop {
            if let Ok(root) = self.open_root(s) {
                let sock = root.symlink_metadata(API_SOCK.trim_start_matches('/')).is_ok();
                let pid = root.read(PID_FILE).ok().and_then(|b| String::from_utf8(b).ok()).and_then(|t| t.trim().parse::<i32>().ok());
                if let (true, Some(p)) = (sock, pid) {
                    break p;
                }
            }
            if Instant::now() >= deadline {
                return Err(AcfError::new(FailureClass::DependencyUnavailable, "VMM did not publish its API socket and pid file in time")
                    .with_possible_side_effect());
            }
            sleep(Duration::from_millis(20)).await;
        };

        let boot = self.clock.boot_id();
        let ident = self.inspector.identity(pid, &boot).map_err(|e| e.with_possible_side_effect())?;
        // Ownership proof: the pid file is only a hint. Our unguessable jail id must be in argv.
        if !self.inspector.cmdline_has(pid, &jail_id) {
            return Err(AcfError::security(format!(
                "pid {pid} from the jail's pid file is not the VMM for {jail_id}; refusing to adopt or signal it"
            ))
            .with_possible_side_effect());
        }
        // Record the identity and arm lifetime enforcement now, before anything else can fail. The
        // kill switch is the runtime's own control group: writing `1` to it ends every process in it.
        let launched = Launched { process: ident.clone(), kill_switch: Some(self.cgroup_dir(&jail_id).join("cgroup.kill")) };
        if let Err(e) = sink.launched(&launched).await {
            self.kill(&ident).await;
            return Err(e.with_possible_side_effect());
        }
        // Confinement must be what the profile claims — as reported by the kernel, not by us.
        let posture = match self.inspector.posture(pid, &self.root_path(s)) {
            Ok(p) => p,
            Err(e) => {
                self.kill(&ident).await;
                return Err(e.with_possible_side_effect());
            }
        };
        let violations = posture.violations(h.uid);
        let in_ns = self.inspector.in_netns(pid, &ns_path);
        if !violations.is_empty() || !in_ns {
            self.kill(&ident).await;
            let mut v = violations;
            if !in_ns {
                v.push("VMM is not inside its dedicated empty network namespace".into());
            }
            return Err(AcfError::security(format!("VMM confinement check failed: {}", v.join("; "))).with_possible_side_effect());
        }
        Ok((ident, posture, in_ns))
    }

    fn link_payload(&self, g: &GenerationDir, root: &Dir, names: &[&str]) -> Result<()> {
        let payload = g.dir().open_dir(PAYLOAD)?;
        for n in names {
            payload.hard_link(n, root, n)?;
        }
        Ok(())
    }

    async fn wait_state(&self, fc: &FcClient, want: &str, within: Duration) -> Result<InstanceInfo> {
        let deadline = Instant::now() + within;
        loop {
            let info: InstanceInfo = fc.get("/").await.map_err(|e| e.into_acf("GET /", false))?;
            if info.state == want {
                return Ok(info);
            }
            if Instant::now() >= deadline {
                return Err(AcfError::new(FailureClass::Timeout, format!("VMM state is `{}` but `{want}` was expected", info.state))
                    .with_possible_side_effect());
            }
            sleep(Duration::from_millis(25)).await;
        }
    }

    fn check_version(&self, v: &str) -> Result<()> {
        let pinned = self.cfg.firecracker.pinned_version.trim_start_matches('v');
        if v.trim_start_matches('v') == pinned {
            Ok(())
        } else {
            Err(AcfError::new(
                FailureClass::IncompatibleRuntime,
                format!("running Firecracker is {v} but the profile is pinned to {pinned}"),
            ))
        }
    }

    /// guest agent Hello + guest-side net probe + verdict. Violation => the caller kills the VMM.
    /// NW-2, IS-4: the host-side evidence for the generation's network mode must hold **before** any
    /// vCPU runs, at a cold start and after a snapshot is loaded. What the guest itself reports can
    /// only add a violation, and is collected once the guest runs ([`Self::finish_boot`]).
    fn network_gate(&self, h: &BackendHandle, nic_count: usize, in_ns: bool) -> Result<()> {
        let evidence = match h.resources.network.mode() {
            NetworkMode::None => evaluate_none(nic_count, in_ns, None),
            NetworkMode::Allowlist => {
                evaluate_allowlist(nic_count, in_ns, netplumb::cgroup_has_processes(&self.relay_cgroup(&h.sandbox.jail_id())))
            }
        };
        if evidence.status == NetworkStatus::Violation {
            return Err(AcfError::security(format!(
                "network mode `{}` is not in force, so no vCPU was started: {}",
                evidence.mode,
                evidence.violations.join("; ")
            ))
            .with_possible_side_effect());
        }
        Ok(())
    }

    async fn finish_boot(
        &self,
        h: &BackendHandle,
        ident: ProcessIdentity,
        posture: crate::backend::process::SecurityPosture,
        in_ns: bool,
        nic_count: usize,
        started: Instant,
    ) -> Result<StartOutcome> {
        let guest = self.guest(&h.sandbox)?;
        let hello = guest
            .wait_ready(Duration::from_millis(self.cfg.firecracker.guest_ready_timeout_ms))
            .await
            .map_err(|e| e.with_possible_side_effect())?;
        let network = match h.resources.network.mode() {
            NetworkMode::None => {
                // The guest report only ever *adds* evidence; if it cannot be obtained we say so.
                let report = guest.net_probe().await.ok();
                evaluate_none(nic_count, in_ns, report.as_ref())
            }
            NetworkMode::Allowlist => {
                evaluate_allowlist(nic_count, in_ns, netplumb::cgroup_has_processes(&self.relay_cgroup(&h.sandbox.jail_id())))
            }
        };
        if network.status == NetworkStatus::Violation {
            return Err(AcfError::security(format!("network mode `{}` violated: {}", network.mode, network.violations.join("; ")))
                .with_possible_side_effect());
        }
        Ok(StartOutcome {
            process: ident,
            posture,
            network,
            agent_version: hello.agent_version,
            guest_boot_id: hello.boot_id,
            boot_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }
}

struct Backstop<'a> {
    backend: &'a FirecrackerBackend,
    handle: &'a BackendHandle,
}

#[async_trait]
impl VmBackstop for Backstop<'_> {
    async fn kill_vm(&self) -> Result<()> {
        match self.backend.stop(self.handle, Duration::from_secs(5)).await? {
            StopOutcome::Stopped | StopOutcome::AlreadyGone => Ok(()),
            other => Err(AcfError::new(FailureClass::DependencyUnavailable, format!("could not stop the VMM: {other:?}"))
                .with_possible_side_effect()),
        }
    }
}

#[async_trait]
impl SandboxBackend for FirecrackerBackend {
    fn identity(&self) -> &BackendIdentity {
        &self.identity
    }

    fn capabilities(&self) -> &CapabilityProfile {
        &self.caps
    }

    async fn provision(&self, req: &ProvisionRequest<'_>) -> Result<BackendHandle> {
        let s = &req.sandbox;
        let (uid, jail_id) = (self.uid(req.uid_slot), s.jail_id());
        let g = self.open_generation(s)?;
        let payload = self.payload_dir(&g)?;
        let disk_bytes = u64::from(req.resources.disk_mib) * MIB;
        let (mut kf, k) = req.image.open_kernel()?;
        let (mut rf, r) = req.image.open_rootfs()?;
        if disk_bytes < r.size {
            return Err(AcfError::validation(format!(
                "disk_mib {} is smaller than the image's root filesystem ({} bytes)",
                req.resources.disk_mib, r.size
            )));
        }
        let staged = (|| -> Result<()> {
            self.stage_file(&mut kf, &k.sha256, MAX_KERNEL_BYTES.max(k.size), &payload, "vmlinux", 0o400, uid, uid, None)?;
            self.stage_file(&mut rf, &r.sha256, r.size, &payload, "rootfs.ext4", 0o600, uid, uid, Some(disk_bytes))?;
            Ok(())
        })();
        if let Err(e) = staged {
            return Err(e.with_possible_side_effect());
        }
        if let Err(e) = self.create_netns(&jail_id).await {
            return Err(e.with_possible_side_effect());
        }
        let mut boot_args = req.image.manifest.boot_args.clone().unwrap_or_else(|| self.cfg.firecracker.boot_args.clone());
        if req.resources.network.mode() == NetworkMode::Allowlist {
            // The guest's address, gateway and resolver, fixed at boot: there is no DHCP to trust.
            let segment = self.segment.ok_or_else(|| AcfError::unsupported("network mode `allowlist` is not offered on this host"))?;
            boot_args = format!("{boot_args} {}", netplumb::boot_arg(&segment));
        }
        Ok(BackendHandle { sandbox: s.clone(), uid, gid: uid, resources: req.resources.clone(), boot_args, process: None })
    }

    async fn start(&self, h: &BackendHandle, sink: &dyn LaunchSink) -> Result<StartOutcome> {
        if h.process.is_some() {
            return Err(AcfError::conflict("sandbox already has a VMM process"));
        }
        // TI-2: what is about to be run is what was pinned. Before anything is created for the launch.
        verify::verify_pinned(&self.cfg.firecracker)?;
        let started = Instant::now();
        if let Err(e) = self.plumb_network(h).await {
            self.stop_relay(&h.sandbox.jail_id());
            return Err(e);
        }
        let (ident, posture, in_ns) = match self.launch_vmm(h, sink).await {
            Ok(launched) => launched,
            Err(e) => {
                self.stop_relay(&h.sandbox.jail_id());
                return Err(e);
            }
        };
        let run = async {
            let (g, root, fc) = (self.open_generation(&h.sandbox)?, self.open_root(&h.sandbox)?, self.fc(&h.sandbox)?);
            self.link_payload(&g, &root, &["vmlinux", "rootfs.ext4"])?;
            let info: InstanceInfo = fc.get("/").await.map_err(|e| e.into_acf("GET /", false))?;
            self.check_version(&info.vmm_version)?;
            if info.state != "Not started" {
                return Err(AcfError::conflict(format!("VMM is already `{}`", info.state)));
            }
            let r = &h.resources;
            fc.put(
                "/machine-config",
                &MachineConfig { vcpu_count: r.vcpus, mem_size_mib: r.memory_mib, smt: false, track_dirty_pages: false },
            )
            .await
            .map_err(|e| e.into_acf("PUT /machine-config", false))?;
            fc.put("/boot-source", &BootSource { kernel_image_path: "/vmlinux".into(), boot_args: h.boot_args.clone() })
                .await
                .map_err(|e| e.into_acf("PUT /boot-source", false))?;
            fc.put(
                "/drives/rootfs",
                &Drive {
                    drive_id: "rootfs".into(),
                    path_on_host: "/rootfs.ext4".into(),
                    is_root_device: true,
                    is_read_only: false,
                    cache_type: "Unsafe",
                    io_engine: "Sync",
                },
            )
            .await
            .map_err(|e| e.into_acf("PUT /drives/rootfs", false))?;
            fc.put("/vsock", &Vsock { guest_cid: GUEST_CID, uds_path: VSOCK_SOCK.into() })
                .await
                .map_err(|e| e.into_acf("PUT /vsock", false))?;
            if h.resources.network.mode() == NetworkMode::Allowlist {
                let nic = NetworkInterface {
                    iface_id: netplumb::GUEST_IFACE.into(),
                    host_dev_name: netplumb::TAP.into(),
                    guest_mac: netplumb::guest_mac(&h.sandbox.jail_id()),
                };
                fc.put(&format!("/network-interfaces/{}", netplumb::GUEST_IFACE), &nic)
                    .await
                    .map_err(|e| e.into_acf("PUT /network-interfaces", false))?;
            }
            // Structural proof of the mode: Firecracker itself reports how many NICs it has.
            let cfg: FullVmConfig = fc.get("/vm/config").await.map_err(|e| e.into_acf("GET /vm/config", false))?;
            self.network_gate(h, cfg.network_interfaces.len(), in_ns)?;
            fc.put("/actions", &InstanceAction::START).await.map_err(|e| e.into_acf("PUT /actions", true))?;
            self.wait_state(&fc, "Running", Duration::from_secs(10)).await?;
            self.finish_boot(h, ident.clone(), posture, in_ns, cfg.network_interfaces.len(), started).await
        };
        match run.await {
            Ok(o) => Ok(o),
            Err(e) => {
                self.kill(&ident).await;
                self.stop_relay(&h.sandbox.jail_id());
                Err(e.with_possible_side_effect())
            }
        }
    }

    async fn observe(&self, h: &BackendHandle) -> Result<Observation> {
        let jail_present = self.open_root(&h.sandbox).is_ok();
        let none = EnforcementObservation::NotApplicable;
        let Some(p) = &h.process else {
            return Ok(Observation { vmm: VmmState::Absent, identity: None, posture: None, enforcement: none, jail_present });
        };
        let check = crate::backend::process::identity::check(p, &self.clock.boot_id());
        match check {
            IdentityCheck::Gone => {
                Ok(Observation { vmm: VmmState::Absent, identity: Some(check.into()), posture: None, enforcement: none, jail_present })
            }
            IdentityCheck::Mismatch(_) => Ok(Observation {
                vmm: VmmState::Unknown("pid held by another process".into()),
                identity: Some(check.into()),
                posture: None,
                enforcement: none,
                jail_present,
            }),
            IdentityCheck::Match => {
                let posture = self.inspector.posture(p.pid, &self.root_path(&h.sandbox)).ok();
                let vmm = match self.fc(&h.sandbox) {
                    Ok(fc) => match tokio::time::timeout(Duration::from_secs(2), fc.get::<InstanceInfo>("/")).await {
                        Ok(Ok(i)) => match i.state.as_str() {
                            "Not started" => VmmState::NotStarted,
                            "Running" => VmmState::Running,
                            "Paused" => VmmState::Paused,
                            other => VmmState::Unknown(other.to_owned()),
                        },
                        _ => VmmState::Unknown("API unreachable".into()),
                    },
                    Err(_) => VmmState::Unknown("jail not found".into()),
                };
                let enforcement = self.enforcement(h, p, posture.as_ref()).await;
                Ok(Observation { vmm, identity: Some(IdentityCheckView::Match), posture, enforcement, jail_present })
            }
        }
    }

    async fn pause(&self, h: &BackendHandle) -> Result<()> {
        self.fc(&h.sandbox)?.patch("/vm", &VmState::PAUSED).await.map_err(|e| e.into_acf("PATCH /vm (pause)", true))
    }

    async fn resume(&self, h: &BackendHandle) -> Result<()> {
        self.fc(&h.sandbox)?.patch("/vm", &VmState::RESUMED).await.map_err(|e| e.into_acf("PATCH /vm (resume)", true))
    }

    async fn snapshot(&self, h: &BackendHandle, req: &SnapshotRequest<'_>) -> Result<SnapshotArtifacts> {
        let fc = self.fc(&h.sandbox)?;
        let root = self.open_root(&h.sandbox)?;
        let info: InstanceInfo = fc.get("/").await.map_err(|e| e.into_acf("GET /", false))?;
        self.check_version(&info.vmm_version)?;
        fc.patch("/vm", &VmState::PAUSED).await.map_err(|e| e.into_acf("PATCH /vm (pause)", true))?;

        let slow = self.fc_snapshot(&h.sandbox, u64::from(h.resources.memory_mib))?;
        let create = async {
            slow.put(
                "/snapshot/create",
                &SnapshotCreate {
                    snapshot_type: "Full",
                    snapshot_path: "/snap.vmstate".into(),
                    mem_file_path: "/snap.mem".into(),
                    sync_snapshot_files: true,
                },
            )
            .await
            .map_err(|e| e.into_acf("PUT /snapshot/create", true))?;
            let copy = |src: &str, dst: &str| -> Result<FileDigest> {
                let mut f = root.open(src)?.into_std();
                let mut o = OpenOptions::new();
                o.write(true).create_new(true).mode(0o600);
                let mut out = req.dest.open_with(dst, &o)?.into_std();
                let c = copy_hashed(&mut f, &mut out, req.max_file_bytes)?;
                out.set_len(c.bytes)?;
                crate::durability::sync_all(&out)?;
                Ok(FileDigest { name: dst.to_owned(), bytes: c.bytes, sha256: c.sha256 })
            };
            let art = SnapshotArtifacts {
                vmstate: copy("snap.vmstate", "vmstate")?,
                mem: copy("snap.mem", "mem")?,
                disk: copy("rootfs.ext4", "disk")?,
                vmm_version: info.vmm_version.clone(),
            };
            // The jail copies are scratch; drop them so the next snapshot starts clean.
            let _ = root.remove_file("snap.vmstate");
            let _ = root.remove_file("snap.mem");
            Ok::<_, AcfError>(art)
        }
        .await;

        // Resume in every path: a failed snapshot must not leave the guest frozen.
        let resumed = fc.patch("/vm", &VmState::RESUMED).await.map_err(|e| e.into_acf("PATCH /vm (resume)", true));
        match (create, resumed) {
            (Ok(a), Ok(())) => Ok(a),
            (Ok(_), Err(e)) => Err(e),
            (Err(e), _) => Err(e.with_possible_side_effect()),
        }
    }

    async fn restore(&self, req: &RestoreRequest<'_>, sink: &dyn LaunchSink) -> Result<(BackendHandle, StartOutcome)> {
        let s = &req.sandbox;
        let (uid, jail_id) = (self.uid(req.uid_slot), s.jail_id());
        // TI-2, as in `start`: before a byte of the snapshot is staged.
        verify::verify_pinned(&self.cfg.firecracker)?;
        let g = self.open_generation(s)?;
        let payload = self.payload_dir(&g)?;
        let e = req.expected;
        // Verify-by-copying: a corrupt vmstate would terminate Firecracker (CRC failure), and a
        // swapped file must never be loaded, so nothing is used that did not hash to the manifest.
        for (src_name, dst, d, mode) in
            [("vmstate", "snap.vmstate", &e.vmstate, 0o400), ("mem", "snap.mem", &e.mem, 0o400), ("disk", "rootfs.ext4", &e.disk, 0o600)]
        {
            let mut f = req.source.open(src_name)?.into_std();
            self.stage_file(&mut f, &d.sha256, d.bytes.max(1), &payload, dst, mode, uid, uid, None)
                .map_err(|er| er.with_possible_side_effect())?;
        }
        self.create_netns(&jail_id).await.map_err(|er| er.with_possible_side_effect())?;
        let handle =
            BackendHandle { sandbox: s.clone(), uid, gid: uid, resources: req.resources.clone(), boot_args: String::new(), process: None };

        let started = Instant::now();
        // The restored guest expects the device and the addresses it was captured with: the device
        // has the same name in every sandbox's namespace, and every namespace uses the same segment.
        if let Err(er) = self.plumb_network(&handle).await {
            self.stop_relay(&jail_id);
            return Err(er);
        }
        let (ident, posture, in_ns) = match self.launch_vmm(&handle, sink).await {
            Ok(launched) => launched,
            Err(er) => {
                self.stop_relay(&jail_id);
                return Err(er);
            }
        };
        let run = async {
            let (root, fc) = (self.open_root(s)?, self.fc(s)?);
            self.link_payload(&g, &root, &["snap.vmstate", "snap.mem", "rootfs.ext4"])?;
            let info: InstanceInfo = fc.get("/").await.map_err(|er| er.into_acf("GET /", false))?;
            self.check_version(&info.vmm_version)?;
            if info.vmm_version.trim_start_matches('v') != e.vmm_version.trim_start_matches('v') {
                return Err(AcfError::new(
                    FailureClass::IncompatibleRuntime,
                    format!("snapshot was written by Firecracker {} but {} is running", e.vmm_version, info.vmm_version),
                ));
            }
            let slow = self.fc_snapshot(s, u64::from(req.resources.memory_mib))?;
            slow.put(
                "/snapshot/load",
                &SnapshotLoad {
                    snapshot_path: "/snap.vmstate".into(),
                    mem_backend: MemBackend { backend_type: "File", backend_path: "/snap.mem".into() },
                    track_dirty_pages: false,
                    resume_vm: false,
                },
            )
            .await
            .map_err(|er| er.into_acf("PUT /snapshot/load", true).with_possible_side_effect())?;
            self.wait_state(&fc, "Paused", Duration::from_secs(10)).await?;
            let cfg: FullVmConfig = fc.get("/vm/config").await.map_err(|er| er.into_acf("GET /vm/config", false))?;
            self.network_gate(&handle, cfg.network_interfaces.len(), in_ns)?;
            fc.patch("/vm", &VmState::RESUMED).await.map_err(|er| er.into_acf("PATCH /vm (resume)", true))?;
            self.wait_state(&fc, "Running", Duration::from_secs(10)).await?;
            self.finish_boot(&handle, ident.clone(), posture, in_ns, cfg.network_interfaces.len(), started).await
        };
        match run.await {
            Ok(o) => Ok((BackendHandle { process: Some(o.process.clone()), ..handle }, o)),
            Err(er) => {
                self.kill(&ident).await;
                self.stop_relay(&jail_id);
                Err(er.with_possible_side_effect())
            }
        }
    }

    async fn discover(&self, s: &SandboxRef) -> Result<Option<ProcessIdentity>> {
        let Ok(root) = self.open_root(s) else { return Ok(None) };
        let Some(pid) = root.read(PID_FILE).ok().and_then(|b| String::from_utf8(b).ok()).and_then(|t| t.trim().parse::<i32>().ok()) else {
            return Ok(None);
        };
        if !self.inspector.cmdline_has(pid, &s.jail_id()) {
            return Ok(None);
        }
        Ok(Some(self.inspector.identity(pid, &self.clock.boot_id())?))
    }

    async fn stop(&self, h: &BackendHandle, grace: Duration) -> Result<StopOutcome> {
        // A stopped runtime needs no connectivity: its guest-traffic role ends with it.
        self.stop_relay(&h.sandbox.jail_id());
        let p = match &h.process {
            Some(p) => p.clone(),
            None => match self.discover(&h.sandbox).await? {
                Some(p) => p,
                None => return Ok(StopOutcome::AlreadyGone),
            },
        };
        Ok(match VmProcess::new(p).terminate(&self.clock.boot_id(), grace).await? {
            TerminateOutcome::Killed => StopOutcome::Stopped,
            TerminateOutcome::AlreadyGone => StopOutcome::AlreadyGone,
            TerminateOutcome::Refused(why) => StopOutcome::Refused(why),
            TerminateOutcome::StillAlive => StopOutcome::StillAlive,
        })
    }

    async fn teardown(&self, s: &SandboxRef, owner_nonce: &str) -> Result<TeardownOutcome> {
        let jail_id = s.jail_id();
        // A live VMM means the caller skipped `stop`. Refuse rather than delete files under it.
        if let Some(p) = self.discover(s).await?
            && crate::backend::process::identity::check(&p, &self.clock.boot_id()) == IdentityCheck::Match
        {
            return Err(AcfError::conflict(format!("VMM for {s} is still running; stop it before teardown")));
        }
        let parent = self.cfg.firecracker.cgroup_root.join(&self.cfg.firecracker.cgroup_parent);
        self.stop_relay(&jail_id);
        let _ = limits::remove_cgroup_dir(&parent, &format!("{jail_id}{}", netplumb::RELAY_CGROUP_SUFFIX)).await;
        let _ = limits::remove_cgroup_dir(&parent, &jail_id).await;
        // Removing the namespace removes its device and its packet filter with it.
        Netns::remove(&self.netns_dir(), &jail_id)?;
        if let Ok(mut seen) = self.filter_checked.lock() {
            seen.remove(&jail_id);
        }
        Ok(match remove_generation(&self.layout, &s.sandbox_id, s.generation, owner_nonce)? {
            CleanupOutcome::Removed => TeardownOutcome::Removed,
            CleanupOutcome::Absent => TeardownOutcome::Absent,
            CleanupOutcome::Quarantine { reason } => TeardownOutcome::Quarantine(reason),
        })
    }

    async fn exec(&self, h: &BackendHandle, req: &GuestExecRequest, cancel: CancellationToken) -> Result<GuestExecOutcome> {
        if !req.secrets.is_empty() {
            // Defence in depth: the coordinator already refused this before BEGIN (BK-5).
            return Err(AcfError::unsupported("this backend does not deliver secret material to a guest"));
        }
        let g = self.guest(&h.sandbox)?;
        g.exec(req, cancel, &Backstop { backend: self, handle: h }).await
    }

    async fn probe(&self, h: &BackendHandle) -> Result<ProbeReport> {
        let nonce = hex::encode(Sha256::digest(format!("{}-{}", h.sandbox, self.clock.monotonic_ns())))[..16].to_owned();
        self.guest(&h.sandbox)?.probe(&nonce).await
    }

    async fn stats(&self, h: &BackendHandle) -> Result<Option<RuntimeUsage>> {
        let dir = self.cgroup_dir(&h.sandbox.jail_id());
        Ok(dir.is_dir().then(|| {
            let stats = limits::read_stats(&dir);
            let spec = CgroupSpec::for_sandbox(&h.resources, self.cfg.firecracker.vmm_overhead_mib);
            RuntimeUsage {
                cpu_usage_usec: stats.cpu_usage_usec,
                memory_peak_bytes: stats.memory_peak_bytes,
                evidence: stats.evidence(&spec, &h.resources),
            }
        }))
    }

    async fn busy_slots(&self) -> Result<BTreeSet<u32>> {
        // RS-3: a slot is busy if any live process runs as one of the user ids derived from it.
        let (fc, net) = (&self.cfg.firecracker, &self.cfg.network);
        let slot_of = |uid: u32, start: u32| uid.checked_sub(start).filter(|s| *s < fc.uid_range_size);
        Ok(self
            .inspector
            .live_uids()?
            .into_iter()
            .filter_map(|uid| slot_of(uid, fc.uid_range_start).or_else(|| slot_of(uid, net.traffic_uid_start)))
            .collect())
    }

    async fn residue(&self, h: &BackendHandle) -> Result<Vec<String>> {
        let (s, jail_id) = (&h.sandbox, h.sandbox.jail_id());
        let mut found = Vec::new();
        let recorded =
            h.process.as_ref().is_some_and(|p| crate::backend::process::identity::check(p, &self.clock.boot_id()) == IdentityCheck::Match);
        if recorded || self.discover(s).await?.is_some() {
            found.push("runtime process".to_owned());
        }
        if h.uid != 0 && self.inspector.live_uids()?.contains(&h.uid) {
            found.push(format!("a process running as user id {}", h.uid));
        }
        for (what, path) in [
            ("control group", self.cgroup_dir(&jail_id)),
            ("guest-traffic control group", self.relay_cgroup(&jail_id)),
            ("network namespace", Netns::path_for(&self.netns_dir(), &jail_id)),
            ("generation directory", self.layout.generation_path(&s.sandbox_id, s.generation)),
        ] {
            if std::fs::symlink_metadata(&path).is_ok() {
                found.push(what.to_owned());
            }
        }
        Ok(found)
    }

    async fn force_teardown(&self, h: &BackendHandle) -> Result<()> {
        let (s, jail_id) = (&h.sandbox, h.sandbox.jail_id());
        // Every name below is derived from the generation's host-allocated id (ID-5). The operator
        // asserted these resources are this host's; the ownership marker is not consulted (QR-2).
        let parent = self.cfg.firecracker.cgroup_root.join(&self.cfg.firecracker.cgroup_parent);
        self.stop_relay(&jail_id);
        let _ = limits::remove_cgroup_dir(&parent, &format!("{jail_id}{}", netplumb::RELAY_CGROUP_SUFFIX)).await;
        let _ = limits::remove_cgroup_dir(&parent, &jail_id).await;
        Netns::remove(&self.netns_dir(), &jail_id)?;
        let dir = self.layout.generation_path(&s.sandbox_id, s.generation);
        match std::fs::symlink_metadata(&dir) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
            // Never follow a link out of the state root, whatever was asserted.
            Ok(m) if m.file_type().is_symlink() || !m.is_dir() => {
                Err(AcfError::security("the generation path is not a directory; refusing to remove it"))
            }
            Ok(_) => std::fs::remove_dir_all(&dir).map_err(|e| AcfError::from(e).with_possible_side_effect()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        backend::firecracker::ProcInspector,
        clock::SystemClock,
        config::test_support::config,
        domain::{NetworkIntent, SandboxResources},
        ids::{Generation, SandboxId},
        store::fixtures::resources,
    };

    fn backend(dir: &Path) -> FirecrackerBackend {
        let cfg = Arc::new(config(dir));
        let layout = Arc::new(Layout::open(&cfg.paths.state_root).unwrap());
        FirecrackerBackend::new(cfg, layout, Arc::new(SystemClock), Arc::new(ProcInspector))
    }

    fn handle(network: NetworkIntent) -> BackendHandle {
        BackendHandle {
            sandbox: SandboxRef { sandbox_id: SandboxId::generate(), generation: Generation::FIRST },
            uid: 100_000,
            gid: 100_000,
            resources: SandboxResources { network, ..resources(1, 128, 64) },
            boot_args: String::new(),
            process: None,
        }
    }

    #[test]
    fn a_snapshot_call_waits_longer_for_a_larger_guest_and_never_less_than_a_minute() {
        assert_eq!(snapshot_call_timeout(128), Duration::from_secs(60));
        assert_eq!(snapshot_call_timeout(600), Duration::from_secs(60));
        assert_eq!(snapshot_call_timeout(4096), Duration::from_millis(409_600));
        assert!(snapshot_call_timeout(u64::MAX) >= Duration::from_secs(60), "the arithmetic saturates");
        assert!(snapshot_call_timeout(4096) > FC_CALL_TIMEOUT, "an ordinary call's deadline is too short for a guest's memory");
    }

    /// TI-2 (T-SEC-07): identity is verified on the bytes that are staged for the VMM, not on a path
    /// that was checked earlier. A file that changed after its digest was recorded is refused and the
    /// copy being made of it does not survive; so is one over its size bound.
    #[test]
    fn a_file_swapped_after_its_digest_was_recorded_is_never_staged() {
        let d = tempfile::tempdir().unwrap();
        let b = backend(d.path());
        std::fs::create_dir(d.path().join("staging")).unwrap();
        let staging = Dir::open_ambient_dir(d.path().join("staging"), cap_std::ambient_authority()).unwrap();
        let (uid, gid) = (rustix::process::geteuid().as_raw(), rustix::process::getegid().as_raw());
        let measured: &[u8] = b"the bytes that were measured";
        let recorded = hex::encode(Sha256::digest(measured));
        let source = d.path().join("rootfs.img");
        let stage = |name: &str, max: u64, grow_to: Option<u64>| {
            let mut f = std::fs::File::open(&source).unwrap();
            b.stage_file(&mut f, &recorded, max, &staging, name, 0o600, uid, gid, grow_to)
        };
        let staged = |name: &str| d.path().join("staging").join(name);

        // The swap: the same path and the same length, other bytes.
        std::fs::write(&source, b"the bytes that were SWAPPED.").unwrap();
        let e = stage("swapped", 1 << 20, None).expect_err("bytes that do not hash to the recorded digest");
        assert_eq!(e.class, FailureClass::IntegrityFailure, "{}", e.message);
        assert!(!staged("swapped").exists(), "a copy that does not match is deleted, not left behind");

        std::fs::write(&source, measured).unwrap();
        let e = stage("bounded", 4, None).expect_err("a source over its size bound");
        assert_eq!(e.class, FailureClass::IntegrityFailure, "{}", e.message);
        assert!(!staged("bounded").exists());

        let copy = stage("good", 1 << 20, Some(4096)).expect("the measured bytes are staged");
        assert_eq!((copy.sha256.as_str(), copy.bytes), (recorded.as_str(), measured.len() as u64));
        let on_disk = std::fs::read(staged("good")).unwrap();
        assert_eq!(on_disk.len(), 4096, "the disk is grown to the size that was asked for");
        assert_eq!(&on_disk[..measured.len()], measured);
        assert!(stage("good", 1 << 20, None).is_err(), "an existing file is never reused (RC-2)");
    }

    /// TI-2 at the moment of use: a VMM or jailer binary that is not the pinned bytes, or has no pin,
    /// is refused before anything is created for the launch and is never executed. The jailer here
    /// leaves a file behind if it is ever run.
    #[tokio::test]
    async fn a_binary_replaced_while_the_host_runs_is_never_launched() {
        use std::os::unix::fs::PermissionsExt;

        #[derive(Default)]
        struct Seen(std::sync::Mutex<usize>);
        #[async_trait]
        impl LaunchSink for Seen {
            async fn launched(&self, _: &Launched) -> Result<()> {
                *self.0.lock().unwrap() += 1;
                Ok(())
            }
        }

        let d = tempfile::tempdir().unwrap();
        let ran = d.path().join("the-jailer-was-run");
        let (vmm, jailer) = (d.path().join("firecracker"), d.path().join("jailer"));
        std::fs::write(&vmm, b"the pinned VMM").unwrap();
        std::fs::write(&jailer, format!("#!/bin/sh\n: > '{}'\nexit 1\n", ran.display())).unwrap();
        std::fs::set_permissions(&jailer, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut cfg = config(d.path());
        cfg.firecracker.firecracker_bin = vmm.clone();
        cfg.firecracker.jailer_bin = jailer.clone();
        let backend_with = |cfg: &HostConfig| {
            let cfg = Arc::new(cfg.clone());
            let layout = Arc::new(Layout::open(&cfg.paths.state_root).unwrap());
            FirecrackerBackend::new(cfg, layout, Arc::new(SystemClock), Arc::new(ProcInspector))
        };
        let h = handle(NetworkIntent::None);
        let sink = Seen::default();

        // No pinned identity.
        let e = backend_with(&cfg).start(&h, &sink).await.expect_err("a binary with no pinned identity");
        assert_eq!(e.class, FailureClass::SecurityControlFailure, "{}", e.message);
        assert!(e.is_definite());

        // Pinned, then replaced: first the VMM, then the jailer.
        verify::test_support::pin(&mut cfg.firecracker);
        let b = backend_with(&cfg);
        for replaced in [&vmm, &jailer] {
            let original = std::fs::read(replaced).unwrap();
            std::fs::write(replaced, b"#!/bin/sh\n# other bytes at the same path\n").unwrap();
            let e = b.start(&h, &sink).await.expect_err("bytes that are not the pinned ones");
            assert_eq!(e.class, FailureClass::IntegrityFailure, "{}", e.message);
            assert!(e.is_definite(), "refused before anything was created for the launch");
            std::fs::write(replaced, original).unwrap();
        }
        assert!(!ran.exists(), "the jailer was never executed");
        assert_eq!(*sink.0.lock().unwrap(), 0, "nothing was launched");
    }

    /// NW-2: the verdict on the host-side evidence comes before the first vCPU instruction, so a
    /// violation here means the guest never ran.
    #[test]
    fn no_vcpu_is_started_unless_the_host_side_network_evidence_holds() {
        let d = tempfile::tempdir().unwrap();
        let b = backend(d.path());
        let none = handle(NetworkIntent::None);
        b.network_gate(&none, 0, true).expect("no device, and the VMM is inside its own namespace");
        for (devices, in_namespace) in [(1, true), (2, true), (0, false)] {
            let e = b.network_gate(&none, devices, in_namespace).expect_err("a violation of mode `none`");
            assert_eq!(e.class, FailureClass::SecurityControlFailure, "{}", e.message);
            assert_eq!(e.side_effect, crate::error::SideEffect::Possible, "a VMM exists: the caller must end it");
        }
        // Mode `allowlist` needs exactly one device and a running guest-traffic role. No role was started
        // for this handle, so even the right device count is refused: the guest would have no filter.
        let allowlist = handle(NetworkIntent::Allowlist { entries: Vec::new() });
        for devices in [0, 1, 2] {
            let e = b.network_gate(&allowlist, devices, true).expect_err("no guest-traffic role is running");
            assert_eq!(e.class, FailureClass::SecurityControlFailure, "{}", e.message);
        }
    }
}
