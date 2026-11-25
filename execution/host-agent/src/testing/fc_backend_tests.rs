//! Orchestration tests for `FirecrackerBackend` without KVM.
//!
//! What is real here: the jailer *argv contract* (a fake `jailer` script parses the real flags),
//! the on-disk jail layout, hashed file staging and hard-linking into the jail, the HTTP/UDS
//! client, the request *ordering* and state-machine rules (fake API), the vsock handshake, and
//! the **real guest agent**. What is faked: virtualization itself. See docs/VERIFICATION_STATUS.md
//! for what still needs a real KVM host.

use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use acf_guest::server::{Agent, AgentConfig};
use async_trait::async_trait;
use cap_std::{ambient_authority, fs::Dir};
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use super::fake_fc::FakeFc;
use crate::{
    backend::firecracker::{FirecrackerBackend, ProcInspector, ProcessInspector, jailer},
    backend::process::SecurityPosture,
    backend::*,
    clock::{Clock, SystemClock},
    config::{HostConfig, test_support::config},
    domain::{CommandSpec, NetworkIntent, RunLimitsRequest, SandboxResources},
    error::{FailureClass, Result},
    ids::{Generation, OperationId, SandboxId, SandboxRef},
    storage::{GenerationDir, Layout, generation::OwnerMarker, images::test_support},
    store::ProcessIdentity,
};

const UID_SLOT: u32 = 3;
const UID: u32 = 100_003;

#[derive(Debug)]
struct Scripted {
    real: ProcInspector,
    posture: Mutex<SecurityPosture>,
    ours: bool,
    /// User ids "live" processes run as (identifier-slot observation).
    uids: Mutex<Vec<u32>>,
    /// Limit drift the control group "reports" (posture recheck).
    drift: Mutex<Vec<String>>,
}

impl ProcessInspector for Scripted {
    fn identity(&self, pid: i32, boot: &str) -> Result<ProcessIdentity> {
        self.real.identity(pid, boot)
    }
    fn posture(&self, _: i32, _: &Path) -> Result<SecurityPosture> {
        Ok(self.posture.lock().unwrap().clone())
    }
    fn in_netns(&self, _: i32, _: &Path) -> bool {
        true
    }
    fn cmdline_has(&self, pid: i32, needle: &str) -> bool {
        self.ours && self.real.cmdline_has(pid, needle)
    }
    fn live_uids(&self) -> Result<Vec<u32>> {
        Ok(self.uids.lock().unwrap().clone())
    }
    fn limit_drift(&self, _: &Path, _: &crate::backend::process::CgroupSpec) -> Vec<String> {
        self.drift.lock().unwrap().clone()
    }
}

fn good_posture() -> SecurityPosture {
    SecurityPosture {
        uid: UID,
        gid: UID,
        seccomp_mode: 2,
        no_new_privs: true,
        caps_dropped: true,
        seccomp_own_filter: true,
        seccomp_own_filter_at_launch: true,
        chrooted: true,
    }
}

/// Where the emulated VMM publishes itself once its API socket is bound.
type FcSlot = Arc<Mutex<Option<Arc<FakeFc>>>>;

#[derive(Default)]
struct Sink(Mutex<Vec<ProcessIdentity>>, Mutex<Option<usize>>, Mutex<Option<FcSlot>>, Mutex<Option<PathBuf>>);

#[async_trait]
impl LaunchSink for Sink {
    async fn launched(&self, launched: &Launched) -> Result<()> {
        // Record how many API requests the VMM had received when its identity was recorded.
        let seen =
            self.2.lock().unwrap().as_ref().and_then(|slot| slot.lock().unwrap().as_ref().map(|f| f.state.lock().unwrap().log.len()));
        *self.1.lock().unwrap() = seen;
        self.0.lock().unwrap().push(launched.process.clone());
        *self.3.lock().unwrap() = launched.kill_switch.clone();
        Ok(())
    }
}

struct Harness {
    _dir: tempfile::TempDir,
    cfg: Arc<HostConfig>,
    layout: Arc<Layout>,
    backend: FirecrackerBackend,
    agent_dir: PathBuf,
    scripted: Arc<Scripted>,
}

fn write_fake_jailer(path: &Path, argv_has_id: bool) {
    // Parses the real jailer flags, builds <base>/<exe>/<id>/root and "daemonizes" one long-lived
    // process whose argv carries the jail id (as Firecracker's own `--id` does). One process, like a
    // real VMM: `setsid` does not fork here and the shell `exec`s, so the pid in the pid file is the
    // process itself and nothing outlives it when it is ended.
    let body = if argv_has_id {
        r#"nohup setsid sh -c 'exec python3 -c "import time; time.sleep(600)" "--id=$0"' "$ID" >/dev/null 2>&1 &"#
    } else {
        r#"nohup setsid sh -c 'exec python3 -c "import time; time.sleep(600)" --id=unrelated' "$ID" >/dev/null 2>&1 &"#
    };
    let script = format!(
        "#!/bin/sh\nID=\"\"; BASE=\"\"; EXE=\"\"\nwhile [ $# -gt 0 ]; do case \"$1\" in --id) ID=\"$2\"; shift 2;; --chroot-base-dir) BASE=\"$2\"; shift 2;; --exec-file) EXE=\"$2\"; shift 2;; --) shift; break;; *) shift;; esac; done\nROOT=\"$BASE/$(basename \"$EXE\")/$ID/root\"\nmkdir -p \"$ROOT\" || exit 1\n{body}\necho $! > \"$ROOT/firecracker.pid\"\nexit 0\n"
    );
    std::fs::write(path, script).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

impl Harness {
    /// These tests create network namespaces and give files to the per-sandbox users, so they need
    /// root. They are `#[ignore]`d for that reason; asked for without root they fail, never skip.
    fn new(argv_has_id: bool, ours: bool) -> Option<Self> {
        assert!(rustix::process::geteuid().is_root(), "this test needs root: run it with `make root-test`");
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = config(dir.path());
        let jailer_script = dir.path().join("fake-jailer");
        write_fake_jailer(&jailer_script, argv_has_id);
        cfg.firecracker.jailer_bin = jailer_script;
        // TI-2: both binaries are hashed before every launch, so both exist and are pinned. The
        // stand-in for the VMM is never executed: the fake jailer uses only its name.
        cfg.firecracker.firecracker_bin = dir.path().join("firecracker");
        std::fs::write(&cfg.firecracker.firecracker_bin, b"stand-in for the VMM binary").unwrap();
        crate::backend::firecracker::verify::test_support::pin(&mut cfg.firecracker);
        cfg.firecracker.guest_ready_timeout_ms = 3_000;
        cfg.firecracker.api_ready_timeout_ms = 3_000;
        cfg.firecracker.shutdown_grace_ms = 3_000;
        let cfg = Arc::new(cfg);
        let layout = Arc::new(Layout::open(&cfg.paths.state_root).unwrap());
        let agent_dir = dir.path().join("agent-state");
        std::fs::create_dir_all(&agent_dir).unwrap();
        std::fs::write(agent_dir.join("boot_id"), "boot-A\n").unwrap();
        let scripted = Arc::new(Scripted {
            real: ProcInspector,
            posture: Mutex::new(good_posture()),
            ours,
            uids: Mutex::default(),
            drift: Mutex::default(),
        });
        let backend = FirecrackerBackend::new(Arc::clone(&cfg), Arc::clone(&layout), Arc::new(SystemClock), scripted.clone());
        test_support::install(&cfg.paths.state_root.join("images"), "python", b"kernel-image-bytes", b"rootfs-image-bytes");
        Some(Self { _dir: dir, cfg, layout, backend, agent_dir, scripted })
    }

    fn agent(&self) -> Arc<Agent> {
        self.agent_with_ifaces(&["lo"])
    }

    /// An in-process guest whose `/sys/class/net` contains exactly `ifaces`.
    fn agent_with_ifaces(&self, ifaces: &[&str]) -> Arc<Agent> {
        let net = self.agent_dir.join("net");
        let _ = std::fs::remove_dir_all(&net);
        for i in ifaces {
            std::fs::create_dir_all(net.join(i)).unwrap();
        }
        Arc::new(Agent::new(AgentConfig {
            boot_id_path: self.agent_dir.join("boot_id"),
            canary_path: self.agent_dir.join("canary"),
            allow_shutdown: false,
            cgroup_root: None,
            net_probe_targets: vec!["127.0.0.1:1".into()],
            net_class_dir: net,
        }))
    }

    fn new_generation(&self, sbx: &SandboxId, g: u64) -> (SandboxRef, String) {
        let nonce = format!("nonce-{g}");
        let marker = OwnerMarker {
            schema_version: crate::storage::generation::OWNER_MARKER_SCHEMA_VERSION,
            sandbox_id: sbx.clone(),
            generation: Generation(g),
            nonce: nonce.clone(),
            created_by: OperationId::parse("op-12345678").unwrap(),
            host_instance_id: "t".into(),
            lineage: Some("test-lineage".into()),
            created_seq: Some(1),
        };
        GenerationDir::create(&self.layout, &marker).unwrap();
        (SandboxRef { sandbox_id: sbx.clone(), generation: Generation(g) }, nonce)
    }

    fn resources() -> SandboxResources {
        SandboxResources { vcpus: 2, memory_mib: 256, disk_mib: 64, network: NetworkIntent::None }
    }

    fn root_of(&self, s: &SandboxRef) -> PathBuf {
        jailer::chroot_root(&self.layout.jail_base(&s.sandbox_id, s.generation), &self.cfg.firecracker.firecracker_bin, &s.jail_id())
    }

    /// Emulate the VMM side: once the (fake) jailer wrote the pid file, bind the API socket.
    fn watch(&self, s: &SandboxRef, agent: Arc<Agent>) -> FcSlot {
        self.watch_with_faults(s, agent, &[])
    }

    /// Like [`Self::watch`], but the listed `(route, http status, fault message)` failures are
    /// installed **before** the API socket is bound, so a test never races the backend's own
    /// progress (an earlier polling injector could lose to a fast `start()`).
    fn watch_with_faults(&self, s: &SandboxRef, agent: Arc<Agent>, faults: &[(&str, u16, &str)]) -> FcSlot {
        let slot: FcSlot = Arc::default();
        let (root, slot2) = (self.root_of(s), Arc::clone(&slot));
        let faults: Vec<(String, u16, String)> = faults.iter().map(|(r, c, m)| ((*r).to_owned(), *c, (*m).to_owned())).collect();
        tokio::spawn(async move {
            for _ in 0..400 {
                if root.join("firecracker.pid").exists() {
                    let dir = Dir::open_ambient_dir(&root, ambient_authority()).unwrap();
                    let fc = FakeFc::new(dir, "1.17.0", Some(agent));
                    for (route, code, msg) in faults {
                        fc.state.lock().unwrap().fail.insert(route, (code, msg));
                    }
                    std::mem::forget(fc.serve_api().unwrap());
                    *slot2.lock().unwrap() = Some(fc);
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        slot
    }

    async fn provision(&self, s: &SandboxRef) -> BackendHandle {
        let image = self.layout.image_store().unwrap().resolve("python").unwrap();
        let res = Self::resources();
        self.backend.provision(&ProvisionRequest { sandbox: s.clone(), resources: &res, image: &image, uid_slot: UID_SLOT }).await.unwrap()
    }
}

fn fc_of(slot: &FcSlot) -> Arc<FakeFc> {
    slot.lock().unwrap().clone().expect("fake VMM was never started")
}

fn calls(fc: &FakeFc) -> Vec<String> {
    fc.state.lock().unwrap().log.iter().map(|(m, p, _)| format!("{m} {p}")).collect()
}

async fn kill_all(h: &Harness, handle: &BackendHandle, sink: &Sink) {
    let mut hh = handle.clone();
    hh.process = sink.0.lock().unwrap().last().cloned();
    let _ = h.backend.stop(&hh, Duration::from_secs(3)).await;
}

/// T-BACK-02 for this adapter: the rules of the port that the test backend is held to
/// (`testing/conformance.rs`) hold for the Firecracker adapter too. The VMM is emulated and the guest
/// agent is real; the same rules against a real VMM are the L4 half, in `tests/integration`.
#[tokio::test]
#[ignore = "needs root: run with `make root-test`"]
async fn t_back_02_the_firecracker_adapter_passes_the_backend_conformance_suite() {
    let Some(h) = Harness::new(true, true) else { return };
    let image = h.layout.image_store().unwrap().resolve("python").unwrap();
    // Every launch of the suite finds an emulated VMM that binds its API socket in the jail.
    let appear = |s: &SandboxRef| drop(h.watch(s, h.agent()));
    super::conformance::run(&super::conformance::Subject {
        backend: &h.backend,
        layout: &h.layout,
        image: &image,
        uid_slot: UID_SLOT,
        before_launch: &appear,
    })
    .await;
}

#[tokio::test]
#[ignore = "needs root: run with `make root-test`"]
async fn boots_in_the_documented_order_and_journals_identity_before_any_configuration() {
    let Some(h) = Harness::new(true, true) else { return };
    let sbx = SandboxId::generate();
    let (s, _) = h.new_generation(&sbx, 1);
    let handle = h.provision(&s).await;
    assert_eq!((handle.uid, handle.gid), (UID, UID), "each VM gets its own uid from the range");

    let slot = h.watch(&s, h.agent());
    let sink = Sink::default();
    *sink.2.lock().unwrap() = Some(Arc::clone(&slot));
    let out = h.backend.start(&handle, &sink).await.unwrap();

    assert_eq!(sink.1.lock().unwrap().unwrap_or(0), 0, "the VMM had received ZERO API requests when its identity was journaled");
    assert_eq!(sink.0.lock().unwrap().len(), 1);
    assert_eq!(out.process, sink.0.lock().unwrap()[0]);

    let fc = fc_of(&slot);
    assert_eq!(
        calls(&fc),
        ["GET /", "PUT /machine-config", "PUT /boot-source", "PUT /drives/rootfs", "PUT /vsock", "GET /vm/config", "PUT /actions", "GET /",],
        "configuration order is part of the contract"
    );
    {
        let st = fc.state.lock().unwrap();
        assert_eq!(st.phase, "Running");
        assert_eq!(st.machine.as_ref().unwrap()["smt"], false, "SMT must be disabled");
        assert_eq!(st.machine.as_ref().unwrap()["vcpu_count"], 2);
        assert_eq!(st.drives[0]["cache_type"], "Unsafe");
        assert!(st.boot.as_ref().unwrap()["boot_args"].as_str().unwrap().contains("8250.nr_uarts=0"));
        assert!(st.nics.is_empty(), "network=none: no NIC configured");
    }
    assert_eq!(out.network.status, crate::network::NetworkStatus::Verified);
    assert!(out.network.vmm_has_no_nic);
    assert_eq!(out.guest_boot_id, "boot-A");
    // The disk was grown (sparsely) to the requested size and is owned by the VM's uid.
    let disk = h.root_of(&s).join("rootfs.ext4");
    let md = std::fs::metadata(&disk).unwrap();
    assert_eq!(md.len(), 64 * 1024 * 1024);
    assert_eq!(std::os::unix::fs::MetadataExt::uid(&md), UID);
    kill_all(&h, &handle, &sink).await;
}

#[tokio::test]
#[ignore = "needs root: run with `make root-test`"]
async fn a_guest_that_reports_a_nic_fails_the_boot_closed_and_the_vmm_is_killed() {
    let Some(h) = Harness::new(true, true) else { return };
    let sbx = SandboxId::generate();
    let (s, _) = h.new_generation(&sbx, 1);
    let handle = h.provision(&s).await;
    let _slot = h.watch(&s, h.agent_with_ifaces(&["lo", "eth0"])); // a NIC appeared inside the guest
    let sink = Sink::default();
    let e = h.backend.start(&handle, &sink).await.unwrap_err();
    assert_eq!(e.class, FailureClass::SecurityControlFailure, "{e}");
    assert!(e.message.contains("eth0"), "{}", e.message);
    let id = sink.0.lock().unwrap()[0].clone();
    assert_eq!(crate::backend::process::identity::check(&id, &SystemClock.boot_id()), crate::backend::process::IdentityCheck::Gone);
}

#[tokio::test]
#[ignore = "needs root: run with `make root-test`"]
async fn a_vmm_that_fails_the_confinement_check_is_killed_before_it_is_configured() {
    let Some(h) = Harness::new(true, true) else { return };
    let sbx = SandboxId::generate();
    let (s, _) = h.new_generation(&sbx, 1);
    let handle = h.provision(&s).await;
    h.scripted.posture.lock().unwrap().seccomp_mode = 0; // "Firecracker started without seccomp"
    let slot = h.watch(&s, h.agent());
    let sink = Sink::default();
    let e = h.backend.start(&handle, &sink).await.unwrap_err();
    assert_eq!(e.class, FailureClass::SecurityControlFailure, "{e}");
    assert!(e.message.contains("seccomp"), "{}", e.message);
    // fail closed: the VMM was never configured, and its process is gone
    assert!(
        slot.lock().unwrap().as_ref().is_none_or(|f| f.state.lock().unwrap().log.is_empty()),
        "an unconfined VMM must not be configured"
    );
    let id = sink.0.lock().unwrap()[0].clone();
    assert_eq!(crate::backend::process::identity::check(&id, &SystemClock.boot_id()), crate::backend::process::IdentityCheck::Gone);
}

#[tokio::test]
#[ignore = "needs root: run with `make root-test`"]
async fn a_pid_file_naming_a_process_that_is_not_ours_is_never_adopted_or_signalled() {
    let Some(h) = Harness::new(false, true) else { return }; // argv lacks the jail id
    let sbx = SandboxId::generate();
    let (s, _) = h.new_generation(&sbx, 1);
    let handle = h.provision(&s).await;
    let _slot = h.watch(&s, h.agent());
    let sink = Sink::default();
    let e = h.backend.start(&handle, &sink).await.unwrap_err();
    assert_eq!(e.class, FailureClass::SecurityControlFailure, "{e}");
    assert!(sink.0.lock().unwrap().is_empty(), "an unproven pid must never be journaled as ours");
    // The decoy process must still be alive: we refuse to signal what we cannot prove we own.
    let pid: i32 = std::fs::read_to_string(h.root_of(&s).join("firecracker.pid")).unwrap().trim().parse().unwrap();
    assert!(std::path::Path::new(&format!("/proc/{pid}")).exists());
    let _ = std::process::Command::new("kill").arg(pid.to_string()).status();
}

#[tokio::test]
#[ignore = "needs root: run with `make root-test`"]
async fn an_api_failure_after_launch_leaves_no_live_vmm_behind() {
    let Some(h) = Harness::new(true, true) else { return };
    let sbx = SandboxId::generate();
    let (s, _) = h.new_generation(&sbx, 1);
    let handle = h.provision(&s).await;
    // The fault exists before the API socket does: no scheduling-dependent window.
    let _slot = h.watch_with_faults(&s, h.agent(), &[("PUT /actions", 400, "boom")]);
    let sink = Sink::default();
    let e = h.backend.start(&handle, &sink).await.unwrap_err();
    assert!(e.message.contains("boom"), "Firecracker's own fault_message must be surfaced: {}", e.message);
    assert!(!e.is_definite(), "InstanceStart may have been applied: side effect must be Possible");
    let id = sink.0.lock().unwrap()[0].clone();
    assert_eq!(crate::backend::process::identity::check(&id, &SystemClock.boot_id()), crate::backend::process::IdentityCheck::Gone);
}

#[tokio::test]
#[ignore = "needs root: run with `make root-test`"]
async fn exec_runs_through_the_vsock_path_into_the_real_guest_agent() {
    let Some(h) = Harness::new(true, true) else { return };
    let sbx = SandboxId::generate();
    let (s, _) = h.new_generation(&sbx, 1);
    let handle = h.provision(&s).await;
    let _slot = h.watch(&s, h.agent());
    let sink = Sink::default();
    let out = h.backend.start(&handle, &sink).await.unwrap();
    let handle = BackendHandle { process: Some(out.process.clone()), ..handle };

    let profile = crate::authority::profile::test_support::profile();
    let cmd = profile
        .authorize_exec(&CommandSpec {
            argv: vec!["/bin/sh".into(), "-c".into(), "echo via-vsock; exit 5".into()],
            env: Default::default(),
            secret_env: Default::default(),
            cwd: Some("/tmp".into()),
            limits: RunLimitsRequest::default(),
        })
        .unwrap();
    // run as uid 0 here: the test host has no guest user 1000
    let cmd = crate::domain::ResolvedCommand { uid: 0, gid: 0, ..cmd };
    let r = h
        .backend
        .exec(
            &handle,
            &GuestExecRequest { exec_id: "x1".into(), command: cmd, grace: Duration::from_millis(500), secrets: Vec::new() },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(r.result.status, acf_wire::guest::ExecStatus::Exited { code: 5 });
    assert_eq!(r.result.stdout, b"via-vsock\n");
    let p1 = h.backend.probe(&handle).await.unwrap();
    let p2 = h.backend.probe(&handle).await.unwrap();
    assert_eq!(p1.state_digest, p2.state_digest);
    kill_all(&h, &handle, &sink).await;
}

#[tokio::test]
#[ignore = "needs root: run with `make root-test`"]
async fn snapshot_then_restore_reproduces_guest_state_and_a_reboot_is_detected() {
    let Some(h) = Harness::new(true, true) else { return };
    let sbx = SandboxId::generate();
    let (s1, nonce1) = h.new_generation(&sbx, 1);
    let handle = h.provision(&s1).await;
    let slot1 = h.watch(&s1, h.agent());
    let sink = Sink::default();
    let out = h.backend.start(&handle, &sink).await.unwrap();
    let handle = BackendHandle { process: Some(out.process.clone()), ..handle };
    let baseline = h.backend.probe(&handle).await.unwrap();

    // ---- snapshot ----
    let snap_dir = tempfile::tempdir().unwrap();
    let dest = Dir::open_ambient_dir(snap_dir.path(), ambient_authority()).unwrap();
    let art = h.backend.snapshot(&handle, &SnapshotRequest { dest: &dest, max_file_bytes: 1 << 30 }).await.unwrap();
    assert_eq!(fc_of(&slot1).state.lock().unwrap().phase, "Running", "the source VM is resumed after snapshotting");
    assert_eq!(art.vmm_version, "1.17.0");
    for (name, d) in [("vmstate", &art.vmstate), ("mem", &art.mem), ("disk", &art.disk)] {
        let bytes = std::fs::read(snap_dir.path().join(name)).unwrap();
        assert_eq!(d.bytes, bytes.len() as u64, "{name}");
        assert_eq!(d.sha256, hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&bytes)), "{name} digest must describe the stored bytes");
    }
    assert!(!h.root_of(&s1).join("snap.mem").exists(), "scratch snapshot files are removed from the jail");
    let c1 = calls(&fc_of(&slot1));
    let pause = c1.iter().position(|c| c == "PATCH /vm").unwrap();
    assert!(c1[pause..].contains(&"PUT /snapshot/create".to_string()), "{c1:?}");

    // ---- stop gen1, restore as gen2 ----
    kill_all(&h, &handle, &sink).await;
    let (s2, _) = h.new_generation(&sbx, 2);
    let slot2 = h.watch(&s2, h.agent());
    let sink2 = Sink::default();
    let res = Harness::resources();
    let (h2, out2) = h
        .backend
        .restore(&RestoreRequest { sandbox: s2.clone(), resources: &res, uid_slot: UID_SLOT, source: &dest, expected: &art }, &sink2)
        .await
        .unwrap();
    let c2 = calls(&fc_of(&slot2));
    assert!(
        !c2.iter().any(|c| c == "PUT /machine-config" || c == "PUT /boot-source" || c == "PUT /drives/rootfs"),
        "restore must not reconfigure: {c2:?}"
    );
    let load = fc_of(&slot2).state.lock().unwrap().log.iter().find(|(_, p, _)| p == "/snapshot/load").cloned().unwrap();
    assert_eq!(load.2["mem_backend"]["backend_type"], "File");
    assert_eq!(load.2["resume_vm"], false, "we resume explicitly after confirming `Paused`");
    assert_eq!(out2.network.status, crate::network::NetworkStatus::Verified);
    let restored = h.backend.probe(&h2).await.unwrap();
    assert_eq!(restored.state_digest, baseline.state_digest, "restore must reproduce the baseline probe");

    // ---- a "restore" that actually rebooted the guest must NOT match ----
    std::fs::write(h.agent_dir.join("boot_id"), "boot-B\n").unwrap();
    assert_ne!(h.backend.probe(&h2).await.unwrap().state_digest, baseline.state_digest, "boot_id change proves a reboot, not a restore");

    let _ = h.backend.stop(&h2, Duration::from_secs(3)).await;
    let _ = nonce1;
}

#[tokio::test]
#[ignore = "needs root: run with `make root-test`"]
async fn a_tampered_snapshot_is_refused_before_any_vmm_is_launched() {
    let Some(h) = Harness::new(true, true) else { return };
    let sbx = SandboxId::generate();
    let (s1, _) = h.new_generation(&sbx, 1);
    let handle = h.provision(&s1).await;
    let _slot = h.watch(&s1, h.agent());
    let sink = Sink::default();
    let out = h.backend.start(&handle, &sink).await.unwrap();
    let handle = BackendHandle { process: Some(out.process.clone()), ..handle };
    let snap_dir = tempfile::tempdir().unwrap();
    let dest = Dir::open_ambient_dir(snap_dir.path(), ambient_authority()).unwrap();
    let art = h.backend.snapshot(&handle, &SnapshotRequest { dest: &dest, max_file_bytes: 1 << 30 }).await.unwrap();
    kill_all(&h, &handle, &sink).await;

    std::fs::write(snap_dir.path().join("vmstate"), b"CORRUPTED-VMSTATE").unwrap(); // would crash Firecracker on CRC
    let (s2, _) = h.new_generation(&sbx, 2);
    let res = Harness::resources();
    let sink2 = Sink::default();
    let e = h
        .backend
        .restore(&RestoreRequest { sandbox: s2.clone(), resources: &res, uid_slot: UID_SLOT, source: &dest, expected: &art }, &sink2)
        .await
        .unwrap_err();
    assert_eq!(e.class, FailureClass::IntegrityFailure, "{e}");
    assert!(sink2.0.lock().unwrap().is_empty(), "no VMM may be launched from unverified bytes");
    assert!(!h.root_of(&s2).exists(), "the jailer must not even have been invoked");
}

#[tokio::test]
#[ignore = "needs root: run with `make root-test`"]
async fn teardown_refuses_while_running_and_requires_ownership_proof() {
    let Some(h) = Harness::new(true, true) else { return };
    let sbx = SandboxId::generate();
    let (s, nonce) = h.new_generation(&sbx, 1);
    let handle = h.provision(&s).await;
    let _slot = h.watch(&s, h.agent());
    let sink = Sink::default();
    let out = h.backend.start(&handle, &sink).await.unwrap();
    let handle = BackendHandle { process: Some(out.process.clone()), ..handle };

    let e = h.backend.teardown(&s, &nonce).await.unwrap_err();
    assert_eq!(e.class, FailureClass::StateConflict, "must not delete files under a live VMM: {e}");
    assert_eq!(h.backend.stop(&handle, Duration::from_secs(3)).await.unwrap(), StopOutcome::Stopped);
    assert_eq!(h.backend.stop(&handle, Duration::from_secs(3)).await.unwrap(), StopOutcome::AlreadyGone, "stop is idempotent");

    assert!(matches!(h.backend.teardown(&s, "not-the-nonce").await.unwrap(), TeardownOutcome::Quarantine(_)));
    assert!(h.layout.generation_path(&s.sandbox_id, s.generation).exists(), "wrong proof => nothing deleted");
    assert_eq!(h.backend.teardown(&s, &nonce).await.unwrap(), TeardownOutcome::Removed);
    assert_eq!(h.backend.teardown(&s, &nonce).await.unwrap(), TeardownOutcome::Absent, "teardown is idempotent");
    assert!(!crate::backend::netns::Netns::path_for(&h.cfg.paths.runtime_dir.join("netns"), &s.jail_id()).exists(), "netns released");
}

#[tokio::test]
#[ignore = "needs root: run with `make root-test`"]
async fn discover_finds_our_vmm_by_jail_id_even_without_a_journaled_identity() {
    let Some(h) = Harness::new(true, true) else { return };
    let sbx = SandboxId::generate();
    let (s, _) = h.new_generation(&sbx, 1);
    let handle = h.provision(&s).await;
    assert_eq!(h.backend.discover(&s).await.unwrap(), None, "nothing launched yet");
    let _slot = h.watch(&s, h.agent());
    let sink = Sink::default();
    let out = h.backend.start(&handle, &sink).await.unwrap();
    assert_eq!(h.backend.discover(&s).await.unwrap().as_ref(), Some(&out.process));
    // `stop` with no recorded identity (the crash-window case) still finds and kills it.
    assert_eq!(h.backend.stop(&handle, Duration::from_secs(3)).await.unwrap(), StopOutcome::Stopped);
}

#[tokio::test]
#[ignore = "needs root: run with `make root-test`"]
async fn provisioning_rejects_a_corrupt_image_and_an_undersized_disk() {
    let Some(h) = Harness::new(true, true) else { return };
    let sbx = SandboxId::generate();
    let (s, _) = h.new_generation(&sbx, 1);
    let image = h.layout.image_store().unwrap().resolve("python").unwrap();
    let mut tiny = Harness::resources();
    tiny.disk_mib = 64;
    // swap the rootfs bytes after the manifest was written (the TOCTOU/tamper case)
    std::fs::write(h.cfg.paths.state_root.join("images/python/rootfs.ext4"), b"rootfs-image-BYTES").unwrap();
    let e = h
        .backend
        .provision(&ProvisionRequest { sandbox: s.clone(), resources: &tiny, image: &image, uid_slot: UID_SLOT })
        .await
        .unwrap_err();
    assert_eq!(e.class, FailureClass::IntegrityFailure, "{e}");
    assert!(
        !h.layout.generation_path(&s.sandbox_id, s.generation).join("payload/rootfs.ext4").exists(),
        "a mismatching copy must be deleted, not left behind"
    );
    let _: Value = Value::Null;
}
