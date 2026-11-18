//! Startup and serving, shared by the production binary and the test-only in-memory host so both
//! exercise the *same* path:
//!
//! ```text
//! trusted inputs → mandatory checks → instance lock → store (new activation epoch) → coordinator
//!     → recovery (STARTING: no endpoint is open) → endpoints → edge → serve → drain → stop
//! ```
//!
//! A failed mandatory check never ends the process (HM-2). It is recorded as a reason for
//! `CONTAINMENT`: the host serves containment and reads, and creates no privilege.

use std::{os::fd::AsFd, path::Path, sync::Arc, time::Duration};

use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{
    authority::{Enrolment, SafetyProfile, trusted_file::read_trusted},
    backend::SandboxBackend,
    clock::Clock,
    config::HostConfig,
    coordinator::{Host, HostParts},
    domain::{ContainmentReason, OwnerScope, PeerId},
    edge::{self, EdgeInit, EdgeLimits, EdgeListeners, TlsMaterial},
    error::{AcfError, Result},
    privsep::{self, RoleIdentity},
    resources::lifetime::LifetimeGuard,
    secrets::SecretProvider,
    storage::{Layout, snapshots::HostFingerprint},
    store::{ActivationRecord, Entry, HostLock, Integrity, Journal, MigrationDefaults, ProfileRecord, StoreOptions},
    telemetry::{EventIdentity, Telemetry},
};

/// Load the host configuration. The file must be owned by one of `owners` (`[0]` in production).
pub fn load_config(path: &Path, owners: &[u32]) -> Result<(HostConfig, String)> {
    let t = read_trusted(path, owners)?;
    Ok((HostConfig::parse(&t.bytes)?, t.sha256))
}

pub fn load_profile(cfg: &HostConfig) -> Result<SafetyProfile> {
    let t = read_trusted(&cfg.paths.profile_path, &cfg.security.trusted_owner_uids)?;
    SafetyProfile::parse(&t.bytes, t.sha256)
}

pub fn load_enrolment(cfg: &HostConfig) -> Result<Enrolment> {
    let t = read_trusted(&cfg.paths.enrolment_path, &cfg.security.trusted_owner_uids)?;
    Enrolment::parse(&t.bytes, t.sha256)
}

/// The network endpoint's TLS material, each file through the trusted-input rule (TI-1). `None`
/// when no network endpoint is configured.
pub fn load_tls(cfg: &HostConfig) -> Result<Option<TlsMaterial>> {
    let Some(tls) = &cfg.edge.tls else { return Ok(None) };
    let read = |p: &Path| -> Result<String> {
        let t = read_trusted(p, &cfg.security.trusted_owner_uids)?;
        String::from_utf8(t.bytes).map_err(|_| AcfError::corrupt(format!("{} is not PEM text", p.display())))
    };
    let material = TlsMaterial {
        certificate_pem: read(&tls.certificate)?,
        private_key_pem: read(&tls.private_key)?,
        trust_anchors_pem: read(&tls.trust_anchors)?,
    };
    // Validate now, in the core, so a bad certificate is a failed mandatory check and not an edge crash.
    edge::tls::server_config(&material)?;
    edge::tls::bound_to_host(&material, &cfg.host_id)?;
    Ok(Some(material))
}

/// The enrolment used when the enrolment file cannot be loaded: the host's own root, locally, as
/// operator. Root already controls the host; this only keeps the host administrable while it is in
/// `CONTAINMENT` for the unusable file.
pub fn fallback_enrolment() -> Enrolment {
    let yaml = "schema_version: 1\npeers:\n  - peer_id: local-root\n    role: operator\n    match: { local_uid: 0 }\n";
    Enrolment::parse(yaml.as_bytes(), String::new()).unwrap_or_else(|_| Enrolment::empty())
}

/// Everything startup decided before the store is opened.
#[derive(Debug)]
pub struct TrustedInputs {
    pub profile: SafetyProfile,
    pub enrolment: Enrolment,
    pub tls: Option<TlsMaterial>,
    /// Why the host must start in `CONTAINMENT`, if it must.
    pub reasons: Vec<ContainmentReason>,
}

/// Load the trusted inputs. Nothing here ends the process: an input that cannot be trusted is not
/// used, and the host starts in `CONTAINMENT` saying why (INV-022).
pub fn load_trusted_inputs(cfg: &HostConfig) -> TrustedInputs {
    let mut reasons = Vec::new();
    let profile = load_profile(cfg).unwrap_or_else(|e| {
        reasons.push(ContainmentReason::InvalidProfile(e.message));
        SafetyProfile::deny_all()
    });
    let enrolment = load_enrolment(cfg).unwrap_or_else(|e| {
        reasons.push(ContainmentReason::MandatoryCheck(format!("the enrolment table cannot be used: {}", e.message)));
        fallback_enrolment()
    });
    let tls = load_tls(cfg).unwrap_or_else(|e| {
        reasons.push(ContainmentReason::MandatoryCheck(format!("the network endpoint cannot be opened: {}", e.message)));
        None
    });
    reasons.extend(cfg.mandatory_checks(Some(&profile)).into_iter().map(ContainmentReason::MandatoryCheck));
    TrustedInputs { profile, enrolment, tls, reasons }
}

pub type BackendFactory<'a> = Box<dyn FnOnce(Arc<HostConfig>, Arc<Layout>, Arc<dyn Clock>) -> Arc<dyn SandboxBackend> + 'a>;

/// The parts of the host that differ between production and tests.
pub struct Assembly<'a> {
    pub backend: BackendFactory<'a>,
    pub lifetime: Arc<dyn LifetimeGuard>,
    pub secrets: Arc<dyn SecretProvider>,
    pub clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for Assembly<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Assembly").finish_non_exhaustive()
    }
}

/// Build the coordinator. Takes the instance lock **before** reading the store (PS-5), and starts a
/// new activation: a new epoch, recorded with the posture this activation accepted (PS-13).
pub fn build_host(cfg: Arc<HostConfig>, config_digest: &str, inputs: TrustedInputs, assembly: Assembly<'_>) -> Result<Arc<Host>> {
    let layout = Arc::new(Layout::open(&cfg.paths.state_root)?);
    let instance_id = format!("inst-{}", uuid::Uuid::now_v7().simple());
    let lock = HostLock::acquire(&cfg.lock_path(), &instance_id)?;
    assemble(cfg, layout, config_digest, inputs, assembly, Some(lock), instance_id)
}

/// Open the store and start a new activation over it. `lock` is `None` only in tests that model a
/// restart inside one process; production always holds the instance lock ([`build_host`]).
pub fn assemble(
    cfg: Arc<HostConfig>,
    layout: Arc<Layout>,
    config_digest: &str,
    inputs: TrustedInputs,
    assembly: Assembly<'_>,
    lock: Option<HostLock>,
    instance_id: String,
) -> Result<Arc<Host>> {
    let clock = Arc::clone(&assembly.clock);
    let options = StoreOptions {
        reserve_bytes: cfg.store.reserve_bytes,
        compact_at_bytes: cfg.store.compact_at_bytes,
        // Records written before scope tags existed belong to the local administrator.
        migration: Some(MigrationDefaults {
            peer_id: PeerId::parse("local-root")?,
            owner_scope: OwnerScope::parse("default")?,
            lifetime_ms: inputs.profile.limits().max_lifetime_secs.saturating_mul(1000),
            now_wall: clock.wall_rfc3339(),
            now_wall_ms: clock.wall_ms(),
            now_mono: clock.now_ref(),
        }),
        ..StoreOptions::default()
    };
    let (journal, report) = Journal::open_with(&cfg.journal_path(), &options)?;
    match &report.integrity {
        Integrity::Clean => tracing::info!(batches = report.batches, bytes = report.bytes, epoch = report.epoch, "store opened"),
        Integrity::TornTailRepaired { dropped_bytes } => tracing::warn!(dropped_bytes, "store: a torn tail from a crash was repaired"),
        Integrity::Corrupt { line, reason } => {
            tracing::error!(line, %reason, "STORE CORRUPT: the host is READ_ONLY; no mutation will be accepted")
        }
        Integrity::UnsupportedSchema { found } => {
            tracing::error!(found, "STORE SCHEMA UNSUPPORTED: the host is READ_ONLY; the store is neither written nor interpreted")
        }
    }
    if let Some(from) = report.migrated_from {
        tracing::warn!(from, "the store was migrated from an earlier schema; the previous file is kept beside it");
    }
    let backend = (assembly.backend)(Arc::clone(&cfg), Arc::clone(&layout), Arc::clone(&clock));
    let telemetry = Telemetry::open(&cfg.paths.state_root.join("telemetry"));
    telemetry.events.set_identity(EventIdentity {
        host_id: cfg.host_id.clone(),
        lineage: journal.lineage().to_owned(),
        activation_epoch: journal.epoch(),
    });
    let manifest = serde_json::json!({
        "backend": backend.identity(),
        "host": HostFingerprint::capture(),
        "acf_version": env!("CARGO_PKG_VERSION"),
        "profile": inputs.profile.id(),
        "enrolment_sha256": inputs.enrolment.digest(),
        "config_sha256": config_digest,
        "store": format!("{:?}", report.integrity),
    });
    let profile_id = inputs.profile.id().clone();
    let reasons = inputs.reasons;
    let host = Host::new(HostParts {
        telemetry,
        store_integrity: format!("{:?}", report.integrity),
        store_seq_at_open: report.last_seq,
        journal: Arc::new(journal),
        layout,
        backend,
        profile: inputs.profile,
        enrolment: inputs.enrolment,
        secrets: assembly.secrets,
        lifetime: assembly.lifetime,
        clock: Arc::clone(&clock),
        instance_id: instance_id.clone(),
        lock,
        cfg,
    })?;
    for r in reasons {
        host.contain(r);
    }
    if host.journal.write_block().is_none() {
        host.journal.commit(vec![
            Entry::Activation(ActivationRecord {
                epoch: host.journal.epoch(),
                instance_id,
                started_wall: clock.wall_rfc3339(),
                started_ms: clock.wall_ms(),
                started_mono: clock.now_ref(),
                manifest,
            }),
            Entry::Profile(ProfileRecord { profile_id, in_force_wall: clock.wall_rfc3339(), by_operation: None }),
        ])?;
    }
    Ok(host)
}

/// How the edge role is run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeMode {
    /// A separate, unprivileged process of this binary (production, PD-1).
    Process(Option<RoleIdentity>),
    /// A task in this process. Test-only: there is no privilege boundary.
    InProcess,
}

fn edge_init(cfg: &HostConfig, host: &Host, tls: Option<TlsMaterial>, network: bool) -> EdgeInit {
    let e = &cfg.edge;
    EdgeInit {
        limits: EdgeLimits {
            max_connections: e.max_connections,
            max_connections_per_source: e.max_connections_per_source,
            max_request_bytes: e.max_request_bytes,
            handshake_deadline_ms: e.handshake_deadline_ms,
            idle_timeout_ms: e.idle_timeout_ms,
            // The core answers within `wait_max`; beyond that plus a margin the answer is lost.
            response_deadline_ms: cfg.operations.wait_max_ms.saturating_add(30_000),
        },
        enrolment: host.enrolment().doc().clone(),
        tls: tls.filter(|_| network),
        local: true,
        network,
    }
}

/// AU-5: re-read the enrolment table, at least twice per `enrolment_refresh_bound`. A table that
/// cannot be used is not used: the previous one stays in force, and the failure is counted.
async fn refresh_enrolment(host: Arc<Host>, changed: mpsc::Sender<()>, shutdown: CancellationToken) {
    let every = Duration::from_millis((host.cfg.edge.enrolment_refresh_ms / 2).max(100));
    loop {
        tokio::select! {
            () = shutdown.cancelled() => return,
            () = tokio::time::sleep(every) => {}
        }
        match load_enrolment(&host.cfg) {
            Ok(new) if new.digest() != host.enrolment().digest() => {
                tracing::info!(peers = new.doc().peers.len(), "enrolment table changed");
                host.set_enrolment(new);
                host.telemetry.metrics.incr("enrolment_reloads", 1);
                let _ = changed.try_send(());
            }
            Ok(_) => {}
            Err(e) => {
                host.telemetry.metrics.incr("enrolment_reload_failures", 1);
                tracing::warn!(error = %e, "the enrolment table could not be re-read; the previous one stays in force");
            }
        }
    }
}

/// Recover, open the endpoints, serve until `shutdown`, drain.
pub async fn serve_host(host: Arc<Host>, tls: Option<TlsMaterial>, mode: EdgeMode, shutdown: CancellationToken) -> Result<()> {
    let cfg = Arc::clone(&host.cfg);
    // RC-5: recovery of inherited operations and the first observation of every generation complete
    // before any endpoint is opened.
    let rep = host.recover().await?;
    tracing::info!(
        examined = rep.examined,
        succeeded = rep.succeeded,
        failed = rep.failed,
        unknown = rep.unknown,
        quarantined = rep.quarantined,
        pending = rep.pending,
        adopted = rep.adopted,
        unmanaged = rep.unmanaged,
        "recovery finished"
    );
    for n in &rep.notes {
        tracing::warn!("recovery: {n}");
    }
    if let Some(why) = host.lifetime.unavailable() {
        host.contain(ContainmentReason::LifetimeEnforcerUnavailable(why));
    }
    host.finish_starting();
    tracing::info!(mode = ?host.mode(), reasons = ?host.containment_reasons(), "host mode");

    let socket_mode = cfg.edge.socket_mode_bits()?;
    let local = edge::bind_socket(&cfg.paths.socket_path, socket_mode, cfg.edge.socket_gid)?;
    let network = match (&cfg.edge.tls, &tls) {
        (Some(t), Some(_)) => match std::net::TcpListener::bind(&t.listen).and_then(|l| l.set_nonblocking(true).map(|()| l)) {
            Ok(l) => Some(l),
            Err(e) => {
                host.contain(ContainmentReason::MandatoryCheck(format!("cannot listen on {}: {e}", t.listen)));
                None
            }
        },
        _ => None,
    };
    tracing::info!(socket = %cfg.paths.socket_path.display(), network = network.is_some(), "endpoints open");

    let stop = CancellationToken::new();
    let sweeper = tokio::spawn(Arc::clone(&host).run_sweeper(stop.clone()));

    // The edge is supervised: it holds no state, so if it dies it is simply started again with the
    // same listeners. Callers see lost responses and resolve their operations by id (FS-5).
    let mut restarts = 0u32;
    let outcome: Result<()> = loop {
        let init = edge_init(&cfg, &host, tls.clone(), network.is_some());
        let (local_dup, network_dup) = (local.try_clone()?, network.as_ref().map(std::net::TcpListener::try_clone).transpose()?);
        let session = stop.child_token();
        let (core_end, mut child) = match mode {
            EdgeMode::Process(identity) => {
                let (child, mut channel) = privsep::spawn_role("edge", &[], identity)?;
                edge::send_init(&mut channel, &init, Some(local_dup.as_fd()), network_dup.as_ref().map(AsFd::as_fd))?;
                channel.set_nonblocking(true)?;
                (tokio::net::UnixStream::from_std(channel)?, Some(child))
            }
            EdgeMode::InProcess => {
                let (core_end, edge_end) = tokio::net::UnixStream::pair()?;
                let listeners = EdgeListeners {
                    local: Some(tokio::net::UnixListener::from_std(local_dup)?),
                    network: network_dup.map(tokio::net::TcpListener::from_std).transpose()?,
                };
                let edge_stop = session.clone();
                tokio::spawn(async move {
                    if let Err(e) = edge::run(init, listeners, edge_end, edge_stop).await {
                        tracing::error!(error = %e, "the in-process edge stopped");
                    }
                });
                (core_end, None)
            }
        };
        // Each edge session gets its own enrolment feed: the init above carried the table in force.
        let (changed_tx, changed_rx) = mpsc::channel::<()>(4);
        let refresher = tokio::spawn(refresh_enrolment(Arc::clone(&host), changed_tx, session.clone()));
        let mut link = tokio::spawn(Arc::clone(&host).serve_edge(core_end, changed_rx, session.clone()));
        let ended = tokio::select! {
            () = shutdown.cancelled() => Some(Ok(())),
            () = host.fatal.cancelled() => Some(Err(AcfError::internal("the store demanded a fail-stop; this activation ends and must be restarted"))),
            _ = &mut link => None,
        };
        if let Some(Ok(())) = ended {
            // HM-3: stop creating privilege, let what is in flight end, then stop.
            let left = host.drain().await;
            tracing::info!(still_in_flight = left, "drained");
        }
        session.cancel();
        // `None`: the link task is what ended (the edge went away), so there is nothing left to wait for.
        if ended.is_some() {
            let _ = tokio::time::timeout(Duration::from_secs(5), &mut link).await;
        }
        let _ = refresher.await;
        if let Some(c) = child.as_mut() {
            let _ = c.kill();
            let _ = c.wait();
        }
        if let Some(result) = ended {
            break result;
        }
        // The channel closed without a shutdown: the edge died.
        restarts += 1;
        host.telemetry.metrics.incr("edge_restarts", 1);
        if mode == EdgeMode::InProcess || restarts > 100 {
            break Err(AcfError::internal("the edge stopped and cannot be restarted"));
        }
        tracing::error!(restarts, "the edge stopped; starting it again");
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    stop.cancel();
    let _ = sweeper.await;
    let _ = std::fs::remove_file(&cfg.paths.socket_path);
    outcome
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

pub fn require_root() -> Result<()> {
    if rustix::process::geteuid().is_root() || std::env::var_os("ACF_ALLOW_NON_ROOT").is_some() {
        Ok(())
    } else {
        Err(AcfError::authorization("the core must run as root: it manages /dev/kvm, control groups, namespaces and the jailer"))
    }
}
