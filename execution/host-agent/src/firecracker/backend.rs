//! `FirecrackerBackend`: the BND-08 implementation for Firecracker v1.17 driven through the jailer.
//!
//! Boot sequence (spec §20.5), each step fail-closed:
//!
//! ```text
//! provision  verified copies of kernel+rootfs -> payload/, empty netns
//! launch     jailer (chroot, pid-ns, cgroup v2, unique uid, netns)  --> identity captured+journaled
//! prove      jail id in argv  ->  seccomp/no_new_privs/caps/chroot/uid  ->  inside empty netns
//! configure  link payload into jail -> machine-config, boot-source, drive, vsock
//! assert     GET /vm/config shows ZERO network interfaces
//! boot       InstanceStart -> Running -> guest agent Hello -> guest net probe
//! ```
//!
//! If *any* step fails after the VMM exists, the VMM is killed before the error is returned, so a
//! failed start never leaves a live, half-configured VM behind.

use std::{
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
        BootSource, Drive, FullVmConfig, InstanceAction, InstanceInfo, MachineConfig, MemBackend, SnapshotCreate, SnapshotLoad, VmState,
        Vsock,
    },
};
use crate::{
    backend::*,
    clock::Clock,
    config::HostConfig,
    error::{AcfError, FailureClass, Result},
    filesystem::{CleanupOutcome, GenerationDir, Layout, generation::remove_generation, hashcopy::copy_hashed},
    guest::{GuestClient, UdsTarget, VmBackstop, VsockUdsConnector},
    ids::SandboxRef,
    network::{Netns, NetworkStatus, evaluate_none},
    operation::ProcessIdentity,
    process::{CgroupSpec, CgroupStats, IdentityCheck, TerminateOutcome, VmProcess, limits},
};

const MIB: u64 = 1024 * 1024;
const PAYLOAD: &str = "payload";
const GUEST_CID: u32 = 3;
const FC_CALL_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_KERNEL_BYTES: u64 = 256 * MIB;

#[derive(Debug)]
pub struct FirecrackerBackend {
    cfg: Arc<HostConfig>,
    layout: Arc<Layout>,
    clock: Arc<dyn Clock>,
    inspector: Arc<dyn ProcessInspector>,
    identity: BackendIdentity,
    caps: CapabilityProfile,
}

fn fc_name(path: &Path) -> String {
    path.file_name().map_or_else(|| "firecracker".into(), |n| n.to_string_lossy().into_owned())
}

impl FirecrackerBackend {
    pub fn new(cfg: Arc<HostConfig>, layout: Arc<Layout>, clock: Arc<dyn Clock>, inspector: Arc<dyn ProcessInspector>) -> Self {
        let profile = serde_json::json!({
            "vmm": "firecracker",
            "version": cfg.firecracker.pinned_version,
            "jailer": {"chroot": true, "new_pid_ns": true, "daemonize": true, "cgroup_version": 2,
                       "per_vm_uid_gid": true, "uid_range": [cfg.firecracker.uid_range_start, cfg.firecracker.uid_range_size]},
            "seccomp": "firecracker-default-filters",
            "cgroup_controls": ["cpu.max", "memory.max", "memory.swap.max=0", "memory.oom.group=1", "pids.max"],
            "network": {"mode": "none", "vmm_netns": "dedicated-empty", "guest_nic": false},
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
            network_modes: vec![crate::domain::NetworkMode::None],
            max_vcpus: 32,
        };
        Self { cfg, layout, clock, inspector, identity, caps }
    }

    // ---------- derived locations (all from validated ids; never from persisted paths) ----------

    fn uid(&self, slot: u32) -> u32 {
        self.cfg.firecracker.uid_range_start + slot
    }

    fn netns_dir(&self) -> PathBuf {
        self.cfg.paths.runtime_dir.join("netns")
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
        f.sync_all()?;
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
    ) -> Result<(ProcessIdentity, crate::process::SecurityPosture, bool)> {
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
                return Err(AcfError::new(FailureClass::BackendCrash, "VMM did not publish its API socket and pid file in time")
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
        // Journal the identity now, before anything else can fail.
        if let Err(e) = sink.launched(&ident).await {
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
                return Err(AcfError::new(
                    FailureClass::TimeoutUnknown,
                    format!("VMM state is `{}` but `{want}` was expected", info.state),
                )
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
                FailureClass::CompatibilityFailure,
                format!("running Firecracker is {v} but the profile is pinned to {pinned}"),
            ))
        }
    }

    /// guest agent Hello + guest-side net probe + verdict. Violation => the caller kills the VMM.
    async fn finish_boot(
        &self,
        h: &BackendHandle,
        ident: ProcessIdentity,
        posture: crate::process::SecurityPosture,
        in_ns: bool,
        nic_count: usize,
        started: Instant,
    ) -> Result<StartOutcome> {
        let guest = self.guest(&h.sandbox)?;
        let hello = guest
            .wait_ready(Duration::from_millis(self.cfg.firecracker.guest_ready_timeout_ms))
            .await
            .map_err(|e| e.with_possible_side_effect())?;
        // The guest report only ever *adds* evidence; if it cannot be obtained we say so.
        let report = guest.net_probe().await.ok();
        let network = evaluate_none(nic_count, in_ns, report.as_ref());
        if network.status == NetworkStatus::Violation {
            return Err(AcfError::security(format!("network=none violated: {}", network.violations.join("; "))).with_possible_side_effect());
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
            other => {
                Err(AcfError::new(FailureClass::BackendCrash, format!("could not stop the VMM: {other:?}")).with_possible_side_effect())
            }
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
        if let Err(e) = Netns::create(&self.netns_dir(), &jail_id).await {
            return Err(e.with_possible_side_effect());
        }
        let boot_args = req.image.manifest.boot_args.clone().unwrap_or_else(|| self.cfg.firecracker.boot_args.clone());
        Ok(BackendHandle { sandbox: s.clone(), uid, gid: uid, resources: req.resources.clone(), boot_args, process: None })
    }

    async fn start(&self, h: &BackendHandle, sink: &dyn LaunchSink) -> Result<StartOutcome> {
        if h.process.is_some() {
            return Err(AcfError::conflict("sandbox already has a VMM process"));
        }
        let started = Instant::now();
        let (ident, posture, in_ns) = self.launch_vmm(h, sink).await?;
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
            // Structural proof of network=none: Firecracker itself reports zero NICs.
            let cfg: FullVmConfig = fc.get("/vm/config").await.map_err(|e| e.into_acf("GET /vm/config", false))?;
            fc.put("/actions", &InstanceAction::START).await.map_err(|e| e.into_acf("PUT /actions", true))?;
            self.wait_state(&fc, "Running", Duration::from_secs(10)).await?;
            self.finish_boot(h, ident.clone(), posture, in_ns, cfg.network_interfaces.len(), started).await
        };
        match run.await {
            Ok(o) => Ok(o),
            Err(e) => {
                self.kill(&ident).await;
                Err(e.with_possible_side_effect())
            }
        }
    }

    async fn observe(&self, h: &BackendHandle) -> Result<Observation> {
        let jail_present = self.open_root(&h.sandbox).is_ok();
        let Some(p) = &h.process else {
            return Ok(Observation { vmm: VmmState::Absent, identity: None, posture: None, jail_present });
        };
        let check = crate::process::identity::check(p, &self.clock.boot_id());
        match check {
            IdentityCheck::Gone => Ok(Observation { vmm: VmmState::Absent, identity: Some(check.into()), posture: None, jail_present }),
            IdentityCheck::Mismatch(_) => Ok(Observation {
                vmm: VmmState::Unknown("pid held by another process".into()),
                identity: Some(check.into()),
                posture: None,
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
                Ok(Observation { vmm, identity: Some(IdentityCheckView::Match), posture, jail_present })
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

        let create = async {
            fc.put(
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
                out.sync_all()?;
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
        Netns::create(&self.netns_dir(), &jail_id).await.map_err(|er| er.with_possible_side_effect())?;
        let handle =
            BackendHandle { sandbox: s.clone(), uid, gid: uid, resources: req.resources.clone(), boot_args: String::new(), process: None };

        let started = Instant::now();
        let (ident, posture, in_ns) = self.launch_vmm(&handle, sink).await?;
        let run = async {
            let (root, fc) = (self.open_root(s)?, self.fc(s)?);
            self.link_payload(&g, &root, &["snap.vmstate", "snap.mem", "rootfs.ext4"])?;
            let info: InstanceInfo = fc.get("/").await.map_err(|er| er.into_acf("GET /", false))?;
            self.check_version(&info.vmm_version)?;
            if info.vmm_version.trim_start_matches('v') != e.vmm_version.trim_start_matches('v') {
                return Err(AcfError::new(
                    FailureClass::CompatibilityFailure,
                    format!("snapshot was written by Firecracker {} but {} is running", e.vmm_version, info.vmm_version),
                ));
            }
            fc.put(
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
            fc.patch("/vm", &VmState::RESUMED).await.map_err(|er| er.into_acf("PATCH /vm (resume)", true))?;
            self.wait_state(&fc, "Running", Duration::from_secs(10)).await?;
            self.finish_boot(&handle, ident.clone(), posture, in_ns, cfg.network_interfaces.len(), started).await
        };
        match run.await {
            Ok(o) => Ok((BackendHandle { process: Some(o.process.clone()), ..handle }, o)),
            Err(er) => {
                self.kill(&ident).await;
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
            && crate::process::identity::check(&p, &self.clock.boot_id()) == IdentityCheck::Match
        {
            return Err(AcfError::conflict(format!("VMM for {s} is still running; stop it before teardown")));
        }
        let _ = limits::remove_cgroup_dir(&self.cfg.firecracker.cgroup_root.join(&self.cfg.firecracker.cgroup_parent), &jail_id).await;
        Netns::remove(&self.netns_dir(), &jail_id)?;
        Ok(match remove_generation(&self.layout, &s.sandbox_id, s.generation, owner_nonce)? {
            CleanupOutcome::Removed => TeardownOutcome::Removed,
            CleanupOutcome::Absent => TeardownOutcome::Absent,
            CleanupOutcome::Quarantine { reason } => TeardownOutcome::Quarantine(reason),
        })
    }

    async fn exec(&self, h: &BackendHandle, req: &GuestExecRequest, cancel: CancellationToken) -> Result<GuestExecOutcome> {
        let g = self.guest(&h.sandbox)?;
        g.exec(req, cancel, &Backstop { backend: self, handle: h }).await
    }

    async fn probe(&self, h: &BackendHandle) -> Result<ProbeReport> {
        let nonce = hex::encode(Sha256::digest(format!("{}-{}", h.sandbox, self.clock.monotonic_ns())))[..16].to_owned();
        self.guest(&h.sandbox)?.probe(&nonce).await
    }

    async fn stats(&self, h: &BackendHandle) -> Result<Option<CgroupStats>> {
        let dir = self.cgroup_dir(&h.sandbox.jail_id());
        Ok(dir.is_dir().then(|| limits::read_stats(&dir)))
    }
}
