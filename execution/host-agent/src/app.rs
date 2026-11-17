//! Startup sequence shared by the production binary and the test-only fake server, so both
//! exercise the *same* path: single-writer lock → journal → host → runtime manifest → recovery →
//! socket → serve.

use std::{path::Path, sync::Arc, time::Duration};

use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::{
    admission::{EffectivePolicy, trusted_file::read_trusted},
    backend::SandboxBackend,
    clock::{Clock, SystemClock},
    config::HostConfig,
    error::{AcfError, Result},
    filesystem::Layout,
    lifecycle::{Host, HostParts},
    operation::{Entry, HostLock, Integrity, Journal, RuntimeManifestRecord},
    server::{Server, bind_socket},
    snapshot::HostFingerprint,
    telemetry::Telemetry,
};

/// Load the host config. The file must be owned by one of `owners` (`[0]` in production).
pub fn load_config(path: &Path, owners: &[u32]) -> Result<(HostConfig, String)> {
    let t = read_trusted(path, owners)?;
    Ok((HostConfig::parse(&t.bytes)?, t.sha256))
}

pub fn load_policy(cfg: &HostConfig) -> Result<EffectivePolicy> {
    let t = read_trusted(&cfg.paths.policy_path, &cfg.security.trusted_owner_uids)?;
    EffectivePolicy::parse(&t.bytes, t.sha256)
}

pub type BackendFactory<'a> = Box<dyn FnOnce(Arc<HostConfig>, Arc<Layout>, Arc<dyn Clock>) -> Arc<dyn SandboxBackend> + 'a>;

/// Build the coordinator. Takes the single-writer lock **before** reading the journal.
pub fn build_host(cfg: Arc<HostConfig>, config_digest: &str, policy: EffectivePolicy, backend: BackendFactory<'_>) -> Result<Arc<Host>> {
    let layout = Arc::new(Layout::open(&cfg.paths.state_root)?);
    let instance_id = format!("inst-{}", uuid::Uuid::now_v7().simple());
    let lock = HostLock::acquire(&cfg.lock_path(), &instance_id)?;
    let (journal, report) = Journal::open(&cfg.journal_path())?;
    match &report.integrity {
        Integrity::Clean => tracing::info!(batches = report.batches, bytes = report.bytes, "journal opened"),
        Integrity::TornTailRepaired { dropped_bytes } => tracing::warn!(dropped_bytes, "journal: a torn tail from a crash was repaired"),
        Integrity::Corrupt { line, reason } => {
            tracing::error!(line, %reason, "JOURNAL CORRUPT: entering read-only quarantine; no mutation will be accepted")
        }
    }
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let backend = backend(Arc::clone(&cfg), Arc::clone(&layout), Arc::clone(&clock));
    let manifest = serde_json::json!({
        "backend": backend.identity(),
        "host": HostFingerprint::capture(),
        "acf_version": env!("CARGO_PKG_VERSION"),
        "policy": policy.id(),
        "config_sha256": config_digest,
        "journal": format!("{:?}", report.integrity),
    });
    let profile_id = backend.identity().security_profile_id.clone();
    let host = Host::new(HostParts {
        telemetry: Telemetry::open(&cfg.paths.state_root.join("telemetry")),
        journal_integrity: format!("{:?}", report.integrity),
        journal: Arc::new(journal),
        layout,
        backend,
        policy,
        clock: Arc::clone(&clock),
        instance_id: instance_id.clone(),
        lock: Some(lock),
        cfg,
    })?;
    if host.journal.is_quarantined().is_none() {
        host.journal.commit(vec![Entry::RuntimeManifest(RuntimeManifestRecord {
            instance_id,
            profile_id,
            recorded_wall: clock.wall_rfc3339(),
            manifest,
        })])?;
    }
    Ok(host)
}

/// Recover, then serve until `shutdown` is cancelled.
pub async fn serve_host(cfg: &HostConfig, host: Arc<Host>, shutdown: CancellationToken) -> Result<()> {
    let rep = host.recover().await?;
    tracing::info!(
        examined = rep.examined,
        succeeded = rep.succeeded,
        failed = rep.failed,
        unknown = rep.unknown,
        quarantined = rep.quarantined,
        adopted = rep.adopted,
        orphans = rep.orphans,
        "recovery finished"
    );
    for n in &rep.notes {
        tracing::warn!("recovery: {n}");
    }
    let mode = cfg.security.socket_mode_bits()?;
    let listener = bind_socket(&cfg.paths.socket_path, mode, cfg.security.socket_gid)?;
    tracing::info!(socket = %cfg.paths.socket_path.display(), mode = format!("{mode:o}"), "listening");
    Server::new(host, cfg.security.clone()).serve(listener, shutdown, Duration::from_secs(30)).await;
    let _ = std::fs::remove_file(&cfg.paths.socket_path);
    Ok(())
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

pub fn require_root() -> Result<()> {
    if rustix::process::geteuid().is_root() || std::env::var_os("ACF_ALLOW_NON_ROOT").is_some() {
        Ok(())
    } else {
        Err(AcfError::authorization("acf-host must run as root: it manages /dev/kvm, cgroups, namespaces and the jailer"))
    }
}
