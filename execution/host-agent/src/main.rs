//! `acf-host` — the Phase 1 privileged host agent.

use std::{path::PathBuf, process::ExitCode, sync::Arc};

use acf_host::{
    app, doctor,
    firecracker::{FirecrackerBackend, ProcInspector, verify},
    operation::{Integrity, Journal},
    schema,
};
use clap::{Parser, Subcommand};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(name = "acf-host", version, about = "Agent Compute Fabric — Phase 1 host agent (Firecracker/Jailer)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the host agent (recovers first, then serves the control socket).
    Serve {
        #[arg(long, default_value = "/etc/acf/host.yaml")]
        config: PathBuf,
    },
    /// Preflight: will the isolation profile actually hold on this machine?
    Doctor {
        #[arg(long, default_value = "/etc/acf/host.yaml")]
        config: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Write the JSON Schema of every wire contract.
    Schema {
        #[arg(long)]
        out: PathBuf,
    },
    /// Inspect or compact the durable journal (the agent must be stopped).
    Journal {
        #[command(subcommand)]
        cmd: JournalCmd,
    },
}

#[derive(Subcommand)]
enum JournalCmd {
    /// Open the journal read-only-ish and report its integrity class.
    Verify {
        #[arg(long, default_value = "/etc/acf/host.yaml")]
        config: PathBuf,
    },
    /// Rewrite the journal as live state only, keeping the newest terminal operations.
    Compact {
        #[arg(long, default_value = "/etc/acf/host.yaml")]
        config: PathBuf,
        #[arg(long, default_value_t = 10_000)]
        keep_terminal: usize,
    },
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let b = tracing_subscriber::fmt().with_env_filter(filter).with_target(false);
    if std::env::var("ACF_LOG_FORMAT").as_deref() == Ok("json") { b.json().init() } else { b.init() }
}

async fn serve(config: PathBuf) -> acf_host::error::Result<()> {
    app::require_root()?;
    let (cfg, digest) = app::load_config(&config, &[0])?;
    let cfg = Arc::new(cfg);
    // Refuse to run a profile this machine cannot honour (KVM, cgroup delegation, uid range, state
    // directory mode, policy, binaries). Every FAIL is fatal; `acf-host doctor` prints the full report.
    doctor::enforce(&doctor::run(&cfg).await)?;
    let policy = app::load_policy(&cfg)?;
    // Versions are logged for the record (the doctor above already proved they match the pin).
    let bins = verify::verify_binaries(&cfg.firecracker, &cfg.security.trusted_owner_uids).await?;
    tracing::info!(firecracker = %bins.firecracker_version, jailer = %bins.jailer_version, policy = %policy.id(), "profile verified");
    let host = app::build_host(
        Arc::clone(&cfg),
        &digest,
        policy,
        Box::new(|cfg, layout, clock| Arc::new(FirecrackerBackend::new(cfg, layout, clock, Arc::new(ProcInspector)))),
    )?;
    let shutdown = CancellationToken::new();
    let s2 = shutdown.clone();
    tokio::spawn(async move {
        use tokio::signal::unix::{SignalKind, signal};
        let (Ok(mut term), Ok(mut int)) = (signal(SignalKind::terminate()), signal(SignalKind::interrupt())) else { return };
        tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
        tracing::info!("shutdown requested");
        s2.cancel();
    });
    app::serve_host(&cfg, host, shutdown).await?;
    tracing::info!("stopped cleanly");
    Ok(())
}

async fn run(cli: Cli) -> acf_host::error::Result<ExitCode> {
    match cli.cmd {
        Cmd::Serve { config } => serve(config).await.map(|()| ExitCode::SUCCESS),
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
        Cmd::Schema { out } => {
            for p in schema::write_all(&out)? {
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
            // take the single-writer lock so we never race a running agent
            let _lock = acf_host::operation::HostLock::acquire(&cfg.lock_path(), "journal-tool")?;
            let (j, rep) = Journal::open(&cfg.journal_path())?;
            println!("batches={} bytes={} integrity={:?}", rep.batches, rep.bytes, rep.integrity);
            if matches!(rep.integrity, Integrity::Corrupt { .. }) {
                return Ok(ExitCode::from(2));
            }
            if let Some(k) = keep {
                println!("dropped {} terminal operation records", j.compact(k)?);
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();
    match run(Cli::parse()).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("acf-host: {e}");
            ExitCode::FAILURE
        }
    }
}
