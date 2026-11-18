//! `acf-host` — the host agent. One binary, several roles (contract §6.1, INV-024):
//!
//! * `serve`          the privileged **core**: the coordinator, the store, the backend. It starts the edge.
//! * `edge`           the unprivileged **edge** role (started by `serve`; not for direct use).
//! * `guest-traffic`  the unprivileged **guest-traffic** role (started by the backend; not for direct use).
//! * `lifetime`       the **lifetime enforcer**: ends runtimes at their expiry, with or without the core.
//!
//! and the operator tools `doctor`, `schema` and `journal`.

use std::{path::PathBuf, process::ExitCode, sync::Arc, time::Duration};

use acf_host::{
    api::schema,
    app::{self, Assembly, EdgeMode},
    backend::firecracker::{FirecrackerBackend, ProcInspector},
    clock::SystemClock,
    doctor,
    domain::ContainmentReason,
    edge,
    error::{AcfError, Result},
    network::traffic,
    privsep::{self, RoleIdentity},
    resources::lifetime::{TicketDir, run_enforcer},
    secrets::FileSecretProvider,
    store::{HostLock, Integrity, Journal, StoreOptions},
};
use clap::{Parser, Subcommand};
use tokio_util::sync::CancellationToken;

const DEFAULT_CONFIG: &str = "/etc/acf/host.yaml";

#[derive(Parser)]
#[command(name = "acf-host", version, about = "Agent Compute Fabric — host agent (execution plane)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the core: recover first, then open the endpoints and serve.
    Serve {
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    },
    /// Internal role: the unprivileged edge. Started by `serve` with its channel on standard input.
    #[command(hide = true)]
    Edge,
    /// Internal role: guest-traffic for one sandbox. Started by the backend.
    #[command(hide = true)]
    GuestTraffic,
    /// Run the lifetime enforcer: end every runtime at its expiry, whether or not the core runs.
    Lifetime {
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    },
    /// Preflight: will the isolation profile actually hold on this machine?
    Doctor {
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Write the JSON Schema of every contract: the host API and event schemas, and the file formats.
    Schema {
        /// Directory for `host-api.json` and `event-schema.json`.
        #[arg(long)]
        contracts: PathBuf,
        /// Directory for the configuration, profile, enrolment and manifest schemas.
        #[arg(long)]
        out: PathBuf,
    },
    /// Inspect or compact the durable store (the core must be stopped).
    Journal {
        #[command(subcommand)]
        cmd: JournalCmd,
    },
}

#[derive(Subcommand)]
enum JournalCmd {
    /// Open the store and report its integrity, lineage and last commit sequence.
    Verify {
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    },
    /// Rewrite the store as live state only, keeping the newest terminal operations.
    Compact {
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
        #[arg(long, default_value_t = 10_000)]
        keep_terminal: usize,
    },
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let b = tracing_subscriber::fmt().with_env_filter(filter).with_target(false).with_writer(std::io::stderr);
    if std::env::var("ACF_LOG_FORMAT").as_deref() == Ok("json") { b.json().init() } else { b.init() }
}

/// Cancelled on SIGTERM or SIGINT.
fn shutdown_on_signal() -> CancellationToken {
    let shutdown = CancellationToken::new();
    let s2 = shutdown.clone();
    tokio::spawn(async move {
        use tokio::signal::unix::{SignalKind, signal};
        let (Ok(mut term), Ok(mut int)) = (signal(SignalKind::terminate()), signal(SignalKind::interrupt())) else { return };
        tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
        tracing::info!("shutdown requested");
        s2.cancel();
    });
    shutdown
}

async fn serve(config: PathBuf) -> Result<()> {
    app::require_root()?;
    let (cfg, digest) = app::load_config(&config, &[0])?;
    let cfg = Arc::new(cfg);
    // The edge needs an identity of its own (PD-1). Without one the host has no way to serve anyone.
    let edge_identity = match (cfg.edge.uid, cfg.edge.gid) {
        (Some(uid), gid) => Some(RoleIdentity { uid, gid: gid.unwrap_or(uid) }),
        (None, _) if rustix::process::geteuid().is_root() => {
            return Err(AcfError::corrupt("edge.uid is not set: the edge must run as an unprivileged user of its own"));
        }
        (None, _) => None,
    };
    let mut inputs = app::load_trusted_inputs(&cfg);
    // Preflight (KVM, control groups, identifier range, state directory, binaries). A failure is a
    // failed mandatory check: the host starts in CONTAINMENT, it does not exit (HM-2).
    inputs.reasons.extend(doctor::machine_failures(&doctor::run(&cfg).await).into_iter().map(ContainmentReason::MandatoryCheck));
    let lifetime = Arc::new(TicketDir::open(&cfg.expiry_dir(), Duration::from_millis(cfg.lifetime.heartbeat_max_age_ms))?);
    let secrets = Arc::new(FileSecretProvider::new(cfg.paths.secrets_dir.clone(), cfg.security.trusted_owner_uids.clone()));
    let tls = inputs.tls.clone();
    let backend = Box::new(|cfg, layout, clock| -> Arc<dyn acf_host::backend::SandboxBackend> {
        Arc::new(FirecrackerBackend::new(cfg, layout, clock, Arc::new(ProcInspector)))
    });
    let host = app::build_host(Arc::clone(&cfg), &digest, inputs, Assembly { backend, lifetime, secrets, clock: Arc::new(SystemClock) })?;
    app::serve_host(host, tls, EdgeMode::Process(edge_identity), shutdown_on_signal()).await?;
    tracing::info!("stopped cleanly");
    Ok(())
}

async fn lifetime_role(config: PathBuf) -> Result<()> {
    app::require_root()?;
    let (cfg, _) = app::load_config(&config, &[0])?;
    let shutdown = shutdown_on_signal();
    tracing::info!(dir = %cfg.expiry_dir().display(), "lifetime enforcer running");
    run_enforcer(
        cfg.expiry_dir(),
        Arc::new(SystemClock),
        cfg.firecracker.cgroup_root.clone(),
        Duration::from_millis(cfg.lifetime.enforcer_interval_ms),
        async move { shutdown.cancelled().await },
    )
    .await
}

async fn run(cli: Cli) -> Result<ExitCode> {
    match cli.cmd {
        Cmd::Serve { config } => serve(config).await.map(|()| ExitCode::SUCCESS),
        Cmd::Edge => edge::role_main(shutdown_on_signal()).await.map(|()| ExitCode::SUCCESS),
        Cmd::GuestTraffic => traffic::role_main().await.map(|()| ExitCode::SUCCESS),
        Cmd::Lifetime { config } => lifetime_role(config).await.map(|()| ExitCode::SUCCESS),
        Cmd::Doctor { config, json } => {
            let (cfg, _) = app::load_config(&config, &[0])?;
            let checks = doctor::run(&cfg).await;
            let failed = checks.iter().any(|c| c.status == doctor::Status::Fail);
            if json {
                println!("{}", serde_json::to_string_pretty(&checks)?);
            } else {
                for c in &checks {
                    let tag = match c.status {
                        doctor::Status::Pass => "PASS",
                        doctor::Status::Warn => "WARN",
                        doctor::Status::Fail => "FAIL",
                    };
                    println!("[{tag}] {:<14} {}", c.name, c.detail);
                }
            }
            Ok(if failed { ExitCode::from(1) } else { ExitCode::SUCCESS })
        }
        Cmd::Schema { contracts, out } => {
            for p in schema::write_contracts(&contracts)?.into_iter().chain(schema::write_all(&out)?) {
                println!("{}", p.display());
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Journal { cmd } => {
            let (config, keep) = match &cmd {
                JournalCmd::Verify { config } => (config.clone(), None),
                JournalCmd::Compact { config, keep_terminal } => (config.clone(), Some(*keep_terminal)),
            };
            let (cfg, _) = app::load_config(&config, &[0])?;
            // Take the instance lock, so this never races a running core.
            let _lock = HostLock::acquire(&cfg.lock_path(), "journal-tool")?;
            // The tools open a store of any size and do not rewrite it by opening it: `verify` only
            // looks, and `compact` is how a store that outgrew the core's limit is brought back.
            let (j, rep) = Journal::open_with(&cfg.journal_path(), &StoreOptions::maintenance())?;
            println!(
                "lineage={} batches={} bytes={} last_seq={} next_epoch={} integrity={:?}",
                rep.lineage, rep.batches, rep.bytes, rep.last_seq, rep.epoch, rep.integrity
            );
            if !matches!(rep.integrity, Integrity::Clean | Integrity::TornTailRepaired { .. }) {
                return Ok(ExitCode::from(2));
            }
            if let Some(k) = keep {
                println!("dropped {} terminal operation records", j.compact(k)?);
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn main() -> ExitCode {
    // A role that reads untrusted bytes gives up the ability to gain privilege while the process
    // still has a single thread, so that every thread it starts afterwards inherits that (INV-025).
    if let Some(role) = std::env::args().nth(1).filter(|r| privsep::is_untrusted_input_role(r))
        && let Err(e) = privsep::enter_role(&role)
    {
        eprintln!("acf-host: {e}");
        return ExitCode::FAILURE;
    }
    init_tracing();
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("acf-host: cannot start the runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async {
        match run(Cli::parse()).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("acf-host: {e}");
                ExitCode::FAILURE
            }
        }
    })
}
