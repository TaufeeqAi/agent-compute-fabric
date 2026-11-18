//! TEST-ONLY. The real edge, admission pipeline, coordinator, store and recovery over the in-memory
//! backend, so a client can be tested end to end — over the local socket and over mutual TLS —
//! without KVM and without root. Built only with `--features testing`; it is never part of a release.
//!
//! ```text
//! acf-host-fake --state <dir> --socket <path>
//!     [--config <host.yaml>] [--profile <profile.yaml>] [--enrolment <enrolment.yaml>]
//!     [--tls-listen <addr:port> --tls-dir <dir>]
//!     [--edge process|in-process]
//! ```
//!
//! * `--config` / `--profile` load the SHIPPED files instead of the small built-in pair, so client
//!   tests check their numeric assumptions against exactly what an operator installs. Only the paths
//!   are rewritten to live under `--state`.
//! * Without `--enrolment`, the user who started the double is enrolled as `operator` on the local
//!   socket. The table is written to the state directory and re-read while the double runs, exactly
//!   as the real host does, so a test can remove an entry and watch it stop working.
//! * `--tls-listen` opens the network endpoint with a throwaway authority. `--tls-dir` receives the
//!   authority's certificate and four client identities: `operator`, `caller` and `observer` are
//!   enrolled (the first by its public key, the others by certificate); `stranger` is signed by the
//!   same authority and **not** enrolled.
//! * `--edge process` runs the edge as a separate process of this binary, as production does.
//!   It is the default unless the double runs as root (a root core must give its edge another
//!   identity, and a test double has none to give).
//!
//! For the trusted-input rule to accept the files the double writes, `--state` must not live under a
//! world-writable directory such as `/tmp`.

use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
};

use acf_host::{
    app::{self, Assembly, EdgeMode, TrustedInputs},
    authority::{Enrolment, SafetyProfile, profile::test_support as profiles},
    clock::SystemClock,
    config::{HostConfig, TlsConfig, test_support as configs},
    edge::{self, TlsMaterial, tls::fingerprints},
    error::{AcfError, Result},
    network::traffic,
    privsep,
    resources::lifetime::MemoryLifetime,
    secrets::MemorySecrets,
    storage::images::test_support as images,
    testing::{
        fake_backend::{FakeBackend, FakeWorld},
        pki::{ClientIdentity, TestPki},
        trusted_owners,
    },
};
use tokio_util::sync::CancellationToken;

const USAGE: &str = "usage: acf-host-fake --state <dir> --socket <path> [--config <host.yaml>] [--profile <profile.yaml>] \
                     [--enrolment <enrolment.yaml>] [--tls-listen <addr:port> --tls-dir <dir>] [--edge process|in-process]";

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}

fn write_private(path: &Path, text: &str, mode: u32) -> Result<()> {
    std::fs::write(path, text)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn shutdown_on_signal() -> CancellationToken {
    let token = CancellationToken::new();
    let t2 = token.clone();
    tokio::spawn(async move {
        use tokio::signal::unix::{SignalKind, signal};
        let (Ok(mut term), Ok(mut int)) = (signal(SignalKind::terminate()), signal(SignalKind::interrupt())) else { return };
        tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
        t2.cancel();
    });
    token
}

/// The network endpoint's material and the enrolment entries of the generated client identities.
fn generate_tls(dir: &Path, listen: &str, host_id: &str) -> Result<(TlsConfig, TlsMaterial, String)> {
    std::fs::create_dir_all(dir)?;
    // As in production, the certificate names the host: a client may verify `host_id`, or the
    // loopback name it dialled.
    let pki = TestPki::for_host(&["localhost", "127.0.0.1", host_id]);
    let material = pki.server_material();
    edge::tls::bound_to_host(&material, host_id)?;
    write_private(&dir.join("ca.crt"), pki.ca_pem(), 0o644)?;
    write_private(&dir.join("host.crt"), &material.certificate_pem, 0o644)?;
    write_private(&dir.join("host.key"), &material.private_key_pem, 0o600)?;
    let save = |c: &ClientIdentity| -> Result<()> {
        write_private(&dir.join(format!("{}.crt", c.name)), &c.certificate_pem, 0o644)?;
        write_private(&dir.join(format!("{}.key", c.name)), &c.private_key_pem, 0o600)
    };
    let (operator, caller, observer, stranger) =
        (pki.client("operator"), pki.client("caller"), pki.client("observer"), pki.client("stranger"));
    for c in [&operator, &caller, &observer, &stranger] {
        save(c)?;
    }
    let spki = fingerprints(&operator.der).1.ok_or_else(|| AcfError::internal("the generated certificate has no readable public key"))?;
    let entries = format!(
        "  - {{ peer_id: tls-operator, role: operator, match: {{ spki_sha256: \"{spki}\" }} }}\n  - {{ peer_id: tls-caller, role: caller, match: {{ certificate_sha256: \"{}\" }} }}\n  - {{ peer_id: tls-observer, role: observer, match: {{ certificate_sha256: \"{}\" }} }}\n",
        fingerprints(&caller.der).0,
        fingerprints(&observer.der).0
    );
    let config = TlsConfig {
        listen: listen.to_owned(),
        certificate: dir.join("host.crt"),
        private_key: dir.join("host.key"),
        trust_anchors: dir.join("ca.crt"),
    };
    Ok((config, material, entries))
}

async fn serve(state: PathBuf, socket: PathBuf) -> Result<()> {
    // A test double: nobody cuts its power, and its clients' tests should not wait for a disk.
    acf_host::durability::skip_in_tests(true);
    std::fs::create_dir_all(&state)?;
    let mut cfg: HostConfig = match arg("--config") {
        Some(path) => HostConfig::parse(&std::fs::read(path)?)?,
        None => {
            let mut small = configs::config(&state);
            small.envelope.max_sandboxes = 8;
            small
        }
    };
    cfg.paths.socket_path = socket;
    cfg.paths.state_root = state.join("state-root");
    cfg.paths.runtime_dir = state.join("run");
    cfg.paths.profile_path = state.join("profile.yaml");
    cfg.paths.enrolment_path = state.join("enrolment.yaml");
    cfg.paths.secrets_dir = state.join("secrets");
    cfg.security.trusted_owner_uids = trusted_owners();
    // The double is reachable by whoever started it: no group, no identity to switch to.
    cfg.edge.uid = None;
    cfg.edge.gid = None;
    cfg.edge.socket_gid = None;
    cfg.edge.socket_mode = "0600".into();
    std::fs::create_dir_all(&cfg.paths.runtime_dir)?;

    let profile_text = match arg("--profile") {
        Some(path) => std::fs::read_to_string(path)?,
        None => profiles::YAML.to_owned(),
    };
    write_private(&cfg.paths.profile_path, &profile_text, 0o644)?;
    let profile = SafetyProfile::parse(profile_text.as_bytes(), app::sha256_hex(profile_text.as_bytes()))?;

    let mut tls = None;
    let mut tls_entries = String::new();
    if let Some(listen) = arg("--tls-listen") {
        let dir = arg("--tls-dir").map(PathBuf::from).ok_or_else(|| AcfError::validation("--tls-listen needs --tls-dir"))?;
        let (config, material, entries) = generate_tls(&dir, &listen, &cfg.host_id)?;
        cfg.edge.tls = Some(config);
        tls = Some(material);
        tls_entries = entries;
    }
    let enrolment_text = match arg("--enrolment") {
        Some(path) => std::fs::read_to_string(path)?,
        None => format!(
            "schema_version: 1\npeers:\n  - {{ peer_id: local-operator, role: operator, match: {{ local_uid: {} }} }}\n{tls_entries}",
            rustix::process::geteuid().as_raw()
        ),
    };
    write_private(&cfg.paths.enrolment_path, &enrolment_text, 0o644)?;
    let enrolment = Enrolment::parse(enrolment_text.as_bytes(), app::sha256_hex(enrolment_text.as_bytes()))?;

    let cfg = Arc::new(cfg);
    images::install(&cfg.paths.state_root.join("images"), "python", b"kernel", b"rootfs");
    let reasons = cfg.mandatory_checks(Some(&profile)).into_iter().map(acf_host::domain::ContainmentReason::MandatoryCheck).collect();
    let inputs = TrustedInputs { profile, enrolment, tls: tls.clone(), reasons };
    let world = FakeWorld::new();
    let assembly = Assembly {
        backend: Box::new(move |_cfg, layout, clock| Arc::new(FakeBackend::new(world, layout, clock))),
        lifetime: Arc::new(MemoryLifetime::default()),
        secrets: Arc::new(MemorySecrets::default()),
        clock: Arc::new(SystemClock),
    };
    let host = app::build_host(Arc::clone(&cfg), "fake", inputs, assembly)?;
    let root = rustix::process::geteuid().is_root();
    let mode = match arg("--edge").as_deref() {
        Some("process") => EdgeMode::Process(None),
        Some("in-process") => EdgeMode::InProcess,
        Some(other) => return Err(AcfError::validation(format!("--edge {other}: expected `process` or `in-process`"))),
        None if root => EdgeMode::InProcess,
        None => EdgeMode::Process(None),
    };
    eprintln!("acf-host-fake: serving on {} (edge: {mode:?})", cfg.paths.socket_path.display());
    app::serve_host(host, tls, mode, shutdown_on_signal()).await
}

async fn run(role: Option<String>) -> ExitCode {
    // The roles of the one binary (INV-024): the core starts them by re-executing itself.
    let outcome = match role.as_deref() {
        Some("edge") => edge::role_main(shutdown_on_signal()).await,
        Some("guest-traffic") => traffic::role_main().await,
        _ => match (arg("--state").map(PathBuf::from), arg("--socket").map(PathBuf::from)) {
            (Some(state), Some(socket)) => serve(state, socket).await,
            _ => {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
        },
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("acf-host-fake: {e}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let role = std::env::args().nth(1);
    // Exactly as the real binary: a role enters before the process has a second thread.
    if let Some(r) = role.as_deref().filter(|r| privsep::is_untrusted_input_role(r))
        && let Err(e) = privsep::enter_role(r)
    {
        eprintln!("acf-host-fake: {e}");
        return ExitCode::FAILURE;
    }
    match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime.block_on(run(role)),
        Err(e) => {
            eprintln!("acf-host-fake: cannot start the runtime: {e}");
            ExitCode::FAILURE
        }
    }
}
