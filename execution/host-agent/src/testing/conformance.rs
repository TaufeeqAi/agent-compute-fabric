//! T-BACK-02: the backend conformance suite (contract §26.5).
//!
//! "An interface is not evidence of replaceability." This is one body of assertions about the
//! backend *port* (`backend/mod.rs`), written against `dyn SandboxBackend` and nothing else, and run
//! against every adapter there is:
//!
//! * the in-memory test backend, in this file (evidence level L2, every `cargo test`);
//! * the Firecracker adapter over an emulated VMM and the real guest agent, in `fc_backend_tests`
//!   (needs root: `make root-test`);
//! * a real VMM, through the host API, in `tests/integration` (L4).
//!
//! It asserts what the coordinator relies on, and nothing an adapter is free to choose: no residue
//! names, no paths, no API order. Where a capability is not declared (§26.3) its section is not run;
//! whether an undeclared capability is refused is the coordinator's rule and has its own test
//! (T-BACK-03).
//!
//! The rules, in the order [`run`] checks them:
//!
//! | # | Rule | Source |
//! |---|---|---|
//! | 1 | identity and capability profile are declared and belong together | §26.2, §26.3 |
//! | 2 | a launch whose record cannot be written leaves no runtime | `LaunchSink`, RC-1 |
//! | 3 | provisioning creates no runtime | §26.1 |
//! | 4 | a launch is recorded exactly once, with the identity the answer carries | RC-1, PD-4 |
//! | 5 | observation changes nothing and is repeatable | BK-3, OB-1 |
//! | 6 | another process instance is never taken for the runtime, and never signalled | RC-1, RC-2 |
//! | 7 | teardown refuses under a live runtime | port convention |
//! | 8 | pause and resume are observable | §26.1 |
//! | 9 | an execution answers for the request it was given; undeclared secret delivery is refused | BK-5, SC-2 |
//! | 10 | the probe is a function of guest state | RE-4 |
//! | 11 | a snapshot's digests describe the bytes stored, and the guest runs again | SNP-2, SNP-5 |
//! | 12 | stop is idempotent | port convention |
//! | 13 | teardown needs the proof of ownership, is idempotent, and leaves no residue | RC-2, QR-3 |
//! | 14 | bytes that do not match the manifest are never launched | TI-2, SNP-3, RE-2 |
//! | 15 | a restore is a new runtime that reproduces the captured state | RE-3, RE-4 |
//!
//! BK-2 (a backend never decides lifecycle state) is structural: the port gives a backend no way to
//! write a record. BK-4 has its own test (T-BACK-01).

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use acf_wire::guest::ExecStatus;
use async_trait::async_trait;
use cap_std::{ambient_authority, fs::Dir};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use super::{
    fake_backend::{FakeBackend, FakeWorld},
    private_tempdir,
};
use crate::{
    backend::*,
    clock::SystemClock,
    config::test_support::config,
    domain::{CommandSpec, NetworkIntent, NetworkMode, ResolvedCommand, RunLimitsRequest, SandboxResources},
    error::{AcfError, FailureClass, Result},
    ids::{Generation, OperationId, SandboxId, SandboxRef},
    network::NetworkStatus,
    secrets::SecretMaterial,
    storage::{
        GenerationDir, Layout, ResolvedImage,
        generation::{OWNER_MARKER_SCHEMA_VERSION, OwnerMarker, new_nonce},
        images::test_support as img,
    },
    store::ProcessIdentity,
};

/// One adapter under test, and the little the suite needs from whoever built it.
pub(crate) struct Subject<'a> {
    pub backend: &'a dyn SandboxBackend,
    /// The state root the adapter was built over. The suite creates generation directories in it,
    /// which is what the coordinator does before it asks a backend to provision.
    pub layout: &'a Layout,
    /// The image generations are provisioned from.
    pub image: &'a ResolvedImage,
    /// The identifier slot the generations use (one runtime lives at a time).
    pub uid_slot: u32,
    /// Runs before every launch that is meant to succeed or to reach the launch record. An adapter
    /// driven over an emulated VMM makes that VMM appear here; any other adapter needs nothing.
    pub before_launch: &'a dyn Fn(&SandboxRef),
}

/// Records what a backend reports at launch, and can stand for a store that refuses the record.
#[derive(Default)]
struct Launches {
    seen: Mutex<Vec<Launched>>,
    refuse: bool,
}

impl Launches {
    fn processes(&self) -> Vec<ProcessIdentity> {
        self.seen.lock().unwrap().iter().map(|l| l.process.clone()).collect()
    }
}

#[async_trait]
impl LaunchSink for Launches {
    async fn launched(&self, launched: &Launched) -> Result<()> {
        self.seen.lock().unwrap().push(launched.clone());
        if self.refuse { Err(AcfError::unavailable("the launch record could not be written")) } else { Ok(()) }
    }
}

const GRACE: Duration = Duration::from_secs(3);

fn resources() -> SandboxResources {
    SandboxResources { vcpus: 2, memory_mib: 256, disk_mib: 64, network: NetworkIntent::None }
}

/// What the coordinator does before `provision` and before `restore`: a generation directory with
/// its ownership marker. Returns the generation and the nonce that proves ownership of it.
fn new_generation(layout: &Layout, sandbox_id: &SandboxId, generation: u64) -> (SandboxRef, String) {
    let nonce = new_nonce().unwrap();
    let marker = OwnerMarker {
        schema_version: OWNER_MARKER_SCHEMA_VERSION,
        sandbox_id: sandbox_id.clone(),
        generation: Generation(generation),
        nonce: nonce.clone(),
        created_by: OperationId::parse("op-12345678").unwrap(),
        host_instance_id: "conformance".into(),
        lineage: Some("conformance".into()),
        created_seq: Some(generation),
    };
    GenerationDir::create(layout, &marker).unwrap();
    (SandboxRef { sandbox_id: sandbox_id.clone(), generation: Generation(generation) }, nonce)
}

async fn provision(s: &Subject<'_>, sandbox: &SandboxRef, res: &SandboxResources) -> BackendHandle {
    let handle = s
        .backend
        .provision(&ProvisionRequest { sandbox: sandbox.clone(), resources: res, image: s.image, uid_slot: s.uid_slot })
        .await
        .unwrap();
    assert_eq!(&handle.sandbox, sandbox, "the handle is for the generation that was asked for");
    assert_eq!(&handle.resources, res, "the handle carries the resources that were asked for, unchanged");
    assert_eq!(handle.process, None, "provisioning launches nothing");
    handle
}

/// A command that exits 0 in any guest that has a shell. It runs as uid 0 because the guest of an
/// emulated VMM is the test host, which has no sandbox user.
fn exec_request(exec_id: &str, secrets: Vec<(String, SecretMaterial)>) -> GuestExecRequest {
    let command = crate::authority::profile::test_support::profile()
        .authorize_exec(&CommandSpec {
            argv: vec!["/bin/sh".into(), "-c".into(), "exit 0".into()],
            env: Default::default(),
            secret_env: Default::default(),
            cwd: Some("/tmp".into()),
            limits: RunLimitsRequest::default(),
        })
        .unwrap();
    GuestExecRequest {
        exec_id: exec_id.to_owned(),
        command: ResolvedCommand { uid: 0, gid: 0, ..command },
        grace: Duration::from_millis(500),
        secrets,
    }
}

fn declaration(b: &dyn SandboxBackend) {
    let (id, caps) = (b.identity(), b.capabilities());
    assert!(
        !id.name.is_empty() && !id.version.is_empty() && !id.security_profile_id.is_empty(),
        "§26.2: a backend identity is a name, an exact version and the digest of the isolation profile: {id:?}"
    );
    assert_eq!(caps.backend, id.name, "§26.3: the capability profile is this backend's");
    assert!(caps.network_modes.contains(&NetworkMode::None), "mode `none` needs no mechanism: every backend offers it");
    assert!(caps.max_vcpus >= 1, "a backend that can run nothing declares nothing");
    assert!(caps.identifier_slots >= 1, "RS-3: the identifier pool is not empty");
}

/// Run every rule of the module's table against `s`. Panics, with the rule, at the first one broken.
pub(crate) async fn run(s: &Subject<'_>) {
    let b = s.backend;
    let caps = b.capabilities().clone();
    let res = resources();
    let sandbox_id = SandboxId::generate();
    let exists = |g: &SandboxRef| s.layout.generation_path(&g.sandbox_id, g.generation).exists();

    // 1. Identity and capability profile.
    declaration(b);

    // 2. A launch whose record cannot be written leaves no runtime behind: without the record nothing
    //    would prove ownership of it after a crash (RC-1), and nothing would end it at its expiry (PD-4).
    let (unrecorded, unrecorded_nonce) = new_generation(s.layout, &sandbox_id, 1);
    let handle = provision(s, &unrecorded, &res).await;
    (s.before_launch)(&unrecorded);
    let sink = Launches { refuse: true, ..Default::default() };
    let e = b.start(&handle, &sink).await.expect_err("a launch that could not be recorded must fail");
    assert_eq!(e.class, FailureClass::DependencyUnavailable, "the failure returned is the recorder's own: {e}");
    assert_eq!(sink.processes().len(), 1, "the backend reported the launch once, before it failed");
    assert_eq!(b.discover(&unrecorded).await.unwrap(), None, "the runtime that could not be recorded was ended");
    assert_eq!(b.stop(&handle, GRACE).await.unwrap(), StopOutcome::AlreadyGone);
    assert_eq!(b.teardown(&unrecorded, &unrecorded_nonce).await.unwrap(), TeardownOutcome::Removed);

    // 3. Provisioning creates no runtime.
    let (first, nonce) = new_generation(s.layout, &sandbox_id, 2);
    let handle = provision(s, &first, &res).await;
    let idle = b.observe(&handle).await.unwrap();
    assert_eq!(idle.vmm, VmmState::Absent, "nothing runs before a start");
    assert_eq!(idle.enforcement, EnforcementObservation::NotApplicable, "there is no runtime whose controls could be judged");
    assert_eq!(b.discover(&first).await.unwrap(), None);

    // 4. A launch is recorded exactly once, with the identity the answer carries.
    (s.before_launch)(&first);
    let sink = Launches::default();
    let out = b.start(&handle, &sink).await.unwrap();
    assert_eq!(sink.processes(), vec![out.process.clone()], "one launch record, for the process the outcome names");
    assert!(!out.agent_version.is_empty(), "GP-4: the guest agent's version is part of the launch evidence");
    assert_ne!(out.network.status, NetworkStatus::Violation, "{:?}", out.network.violations);
    let handle = BackendHandle { process: Some(out.process.clone()), ..handle };
    let running = b.observe(&handle).await.unwrap();
    assert_eq!(running.vmm, VmmState::Running);
    assert_eq!(running.identity, Some(IdentityCheckView::Match));
    assert_eq!(running.enforcement, EnforcementObservation::Intact);
    assert!(running.jail_present);
    assert_eq!(b.discover(&first).await.unwrap(), Some(out.process.clone()), "a runtime is found without its record");

    // 5. Observation changes nothing, so it can be repeated after an ambiguous mutation (BK-3).
    assert_eq!(b.observe(&handle).await.unwrap(), running);
    let residue = b.residue(&handle).await.unwrap();
    assert!(!residue.is_empty(), "a running generation is not proven absent");
    assert_eq!(b.residue(&handle).await.unwrap(), residue);
    assert_eq!(b.busy_slots().await.unwrap(), b.busy_slots().await.unwrap());
    assert_eq!(b.observe(&handle).await.unwrap(), running, "looking for residue and busy identifiers changed nothing");

    // 6. A record that names another process instance (the same process id, started at another
    //    time) proves nothing: that instance is not the runtime, and it is never signalled.
    let other = ProcessIdentity { start_time_ticks: out.process.start_time_ticks.wrapping_add(1), ..out.process.clone() };
    let impostor = BackendHandle { process: Some(other), ..handle.clone() };
    let seen = b.observe(&impostor).await.unwrap();
    assert!(matches!(seen.identity, Some(IdentityCheckView::Mismatch(_))), "{seen:?}");
    assert!(matches!(seen.vmm, VmmState::Unknown(_)), "{seen:?}");
    assert!(matches!(b.stop(&impostor, GRACE).await.unwrap(), StopOutcome::Refused(_)));
    assert_eq!(b.observe(&handle).await.unwrap().vmm, VmmState::Running, "a refused stop signalled nothing");

    // 7. Teardown refuses under a live runtime, and removes nothing.
    let e = b.teardown(&first, &nonce).await.expect_err("teardown under a live runtime must be refused");
    assert_eq!(e.class, FailureClass::StateConflict, "{e}");
    assert!(exists(&first));

    // 8. Pause and resume are observable.
    if caps.pause_resume {
        b.pause(&handle).await.unwrap();
        assert_eq!(b.observe(&handle).await.unwrap().vmm, VmmState::Paused);
        b.resume(&handle).await.unwrap();
        assert_eq!(b.observe(&handle).await.unwrap().vmm, VmmState::Running);
    }

    // 9. An execution answers for the request it was given.
    if caps.guest_exec {
        let done = b.exec(&handle, &exec_request("conformance-1", Vec::new()), CancellationToken::new()).await.unwrap();
        assert_eq!(done.result.exec_id, "conformance-1");
        assert_eq!(done.result.status, ExecStatus::Exited { code: 0 });
        assert!(!done.host_deadline_hit && !done.vm_killed);
        if !caps.secret_injection {
            let material = vec![("TOKEN".to_owned(), SecretMaterial::new(b"conformance-material".to_vec()))];
            let e = b
                .exec(&handle, &exec_request("conformance-2", material), CancellationToken::new())
                .await
                .expect_err("a backend that does not declare secret delivery must refuse material");
            assert_eq!(e.class, FailureClass::Unsupported, "{e}");
            assert!(e.is_definite(), "nothing was delivered and nothing ran");
        }
        assert_eq!(b.observe(&handle).await.unwrap().vmm, VmmState::Running);
    }

    // 10. The probe is a function of guest state: asked twice of an unchanged guest, it answers the same.
    let baseline = b.probe(&handle).await.unwrap();
    assert_eq!(b.probe(&handle).await.unwrap().state_digest, baseline.state_digest);

    // 11. A snapshot's digests describe the bytes that were stored, and the guest runs again.
    let captured = tempfile::tempdir().unwrap();
    let dest = Dir::open_ambient_dir(captured.path(), ambient_authority()).unwrap();
    let artifacts = if caps.snapshot {
        let art = b.snapshot(&handle, &SnapshotRequest { dest: &dest, max_file_bytes: 1 << 30 }).await.unwrap();
        for (name, d) in [("vmstate", &art.vmstate), ("mem", &art.mem), ("disk", &art.disk)] {
            let bytes = std::fs::read(captured.path().join(name)).unwrap();
            assert_eq!(d.name, name);
            assert_eq!(d.bytes, bytes.len() as u64, "{name}: the recorded size is the stored size");
            assert_eq!(d.sha256, hex::encode(Sha256::digest(&bytes)), "{name}: the recorded digest is of the stored bytes");
        }
        assert!(!art.vmm_version.is_empty());
        assert_eq!(b.observe(&handle).await.unwrap().vmm, VmmState::Running, "SNP-5: the guest runs again after a capture");
        assert_eq!(b.probe(&handle).await.unwrap().state_digest, baseline.state_digest, "a capture does not change the guest");
        Some(art)
    } else {
        None
    };

    // 12. Stop ends the runtime, and is idempotent.
    assert_eq!(b.stop(&handle, GRACE).await.unwrap(), StopOutcome::Stopped);
    assert_eq!(b.stop(&handle, GRACE).await.unwrap(), StopOutcome::AlreadyGone, "stop is idempotent");
    let gone = b.observe(&handle).await.unwrap();
    assert_eq!(gone.vmm, VmmState::Absent);
    assert_eq!(gone.identity, Some(IdentityCheckView::Gone));
    assert_eq!(gone.enforcement, EnforcementObservation::NotApplicable);
    assert_eq!(b.discover(&first).await.unwrap(), None);

    // 13. Teardown needs the proof of ownership, is idempotent, and leaves the generation proven absent.
    assert!(matches!(b.teardown(&first, "not-the-nonce").await.unwrap(), TeardownOutcome::Quarantine(_)));
    assert!(exists(&first), "without the proof nothing is deleted");
    assert_eq!(b.teardown(&first, &nonce).await.unwrap(), TeardownOutcome::Removed);
    assert!(!exists(&first));
    assert_eq!(b.teardown(&first, &nonce).await.unwrap(), TeardownOutcome::Absent, "teardown is idempotent");
    assert_eq!(b.residue(&handle).await.unwrap(), Vec::<String>::new(), "QR-3: nothing of the generation is left");

    let Some(art) = artifacts.filter(|_| caps.restore) else { return };

    // 14. Bytes that do not hash to the manifest are never launched. One byte is changed and the
    //     length kept, so that only the digest can tell.
    let swapped = tempfile::tempdir().unwrap();
    for name in ["vmstate", "mem", "disk"] {
        std::fs::copy(captured.path().join(name), swapped.path().join(name)).unwrap();
    }
    let mut bytes = std::fs::read(swapped.path().join("vmstate")).unwrap();
    bytes[0] ^= 0xff;
    std::fs::write(swapped.path().join("vmstate"), &bytes).unwrap();
    let source = Dir::open_ambient_dir(swapped.path(), ambient_authority()).unwrap();
    let (refused, refused_nonce) = new_generation(s.layout, &sandbox_id, 3);
    let sink = Launches::default();
    let request = RestoreRequest { sandbox: refused.clone(), resources: &res, uid_slot: s.uid_slot, source: &source, expected: &art };
    let e = b.restore(&request, &sink).await.expect_err("a changed artifact must be refused");
    assert_eq!(e.class, FailureClass::IntegrityFailure, "{e}");
    assert!(sink.processes().is_empty(), "nothing is launched from bytes that were not verified");
    assert_eq!(b.discover(&refused).await.unwrap(), None);
    assert_eq!(b.teardown(&refused, &refused_nonce).await.unwrap(), TeardownOutcome::Removed);

    // 15. A restore is a new runtime, recorded like any launch, that reproduces the captured state.
    let (second, second_nonce) = new_generation(s.layout, &sandbox_id, 4);
    (s.before_launch)(&second);
    let sink = Launches::default();
    let request = RestoreRequest { sandbox: second.clone(), resources: &res, uid_slot: s.uid_slot, source: &dest, expected: &art };
    let (restored, out2) = b.restore(&request, &sink).await.unwrap();
    assert_eq!(restored.sandbox, second);
    assert_eq!(restored.process.as_ref(), Some(&out2.process));
    assert_eq!(sink.processes(), vec![out2.process.clone()], "a restore is recorded like any launch");
    assert_ne!(out2.process, out.process, "a restored generation is a new runtime");
    assert_ne!(out2.network.status, NetworkStatus::Violation, "{:?}", out2.network.violations);
    assert_eq!(b.observe(&restored).await.unwrap().vmm, VmmState::Running);
    assert_eq!(b.probe(&restored).await.unwrap().state_digest, baseline.state_digest, "RE-4: the restore reproduces the baseline");
    assert_eq!(b.stop(&restored, GRACE).await.unwrap(), StopOutcome::Stopped);
    assert_eq!(b.teardown(&second, &second_nonce).await.unwrap(), TeardownOutcome::Removed);
    assert_eq!(b.residue(&restored).await.unwrap(), Vec::<String>::new());
}

/// The in-memory test backend over a state root of its own.
async fn test_backend_conforms(withhold: &[&str]) {
    let dir = private_tempdir();
    let cfg = config(dir.path());
    let layout = Arc::new(Layout::open(&cfg.paths.state_root).unwrap());
    img::install(&cfg.paths.state_root.join("images"), "python", b"kernel", b"rootfs");
    let image = layout.image_store().unwrap().resolve("python").unwrap();
    let world = FakeWorld::new();
    for capability in withhold {
        world.withhold(capability);
    }
    let backend = FakeBackend::new(Arc::clone(&world), Arc::clone(&layout), Arc::new(SystemClock));
    run(&Subject { backend: &backend, layout: &layout, image: &image, uid_slot: 3, before_launch: &|_| {} }).await;
    assert_eq!(world.vm_count(), 0, "the suite leaves no runtime behind");
}

/// T-BACK-02, its L2 half. The suites of this crate judge the coordinator through the test backend;
/// this judges the test backend through the port, by the rules the Firecracker adapter is judged by.
#[tokio::test]
async fn t_back_02_the_test_backend_passes_the_backend_conformance_suite() {
    test_backend_conforms(&[]).await;
}

/// A backend that declares less is still a backend: the sections of what it does not declare are
/// not run, and material it does not deliver is refused, never dropped.
#[tokio::test]
async fn t_back_02_a_backend_that_declares_less_still_conforms() {
    test_backend_conforms(&["secret_injection"]).await;
    test_backend_conforms(&["snapshot", "restore"]).await;
}
