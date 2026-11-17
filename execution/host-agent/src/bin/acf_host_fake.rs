//! TEST-ONLY. The real server and coordinator over the in-memory `FakeBackend`, so the Python CLI
//! can be tested end-to-end against a real socket without KVM. Requires `--features testing`.
//!
//! usage: acf-host-fake --state <dir> --socket <path> [--config <host.yaml>] [--policy <policy.yaml>]
//!
//! `--config` and `--policy` load the SHIPPED files (`config/host.example.yaml`, `policies/default.yaml`) instead
//! of the small built-in test pair, so the control-plane half of the KVM suites (`make control-plane`) checks its
//! numeric assumptions (ceilings, envelope, overhead) against exactly what an operator installs. Only the paths
//! are rewritten to live under `--state`, and the caller's own uid is added to `allowed_uids` (a test double has
//! to be reachable by whoever started it). Neither file goes through the trusted-file loader: this is a test
//! double, the loader has its own tests.

use std::{path::PathBuf, process::ExitCode, sync::Arc};

use acf_host::{
    admission::{EffectivePolicy, policy::test_support as pol},
    app,
    config::{HostConfig, test_support as cfgs},
    filesystem::images::test_support as img,
    testing::fake_backend::{FakeBackend, FakeWorld},
};
use tokio_util::sync::CancellationToken;

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}

#[tokio::main]
async fn main() -> ExitCode {
    let (Some(state), Some(socket)) = (arg("--state").map(PathBuf::from), arg("--socket").map(PathBuf::from)) else {
        eprintln!("usage: acf-host-fake --state <dir> --socket <path> [--config <host.yaml>] [--policy <policy.yaml>]");
        return ExitCode::from(2);
    };
    let run = async {
        std::fs::create_dir_all(&state)?;
        let mut cfg: HostConfig = match arg("--config") {
            Some(path) => {
                let mut shipped = HostConfig::parse(&std::fs::read(path)?)?;
                let me = rustix::process::geteuid().as_raw();
                if !shipped.security.allowed_uids.contains(&me) {
                    shipped.security.allowed_uids.push(me);
                }
                shipped
            }
            None => {
                let mut small = cfgs::config(&state);
                small.envelope.max_sandboxes = 8;
                small
            }
        };
        cfg.paths.socket_path = socket;
        cfg.paths.state_root = state.join("state-root");
        cfg.paths.runtime_dir = state.join("run");
        let cfg = Arc::new(cfg);
        img::install(&cfg.paths.state_root.join("images"), "python", b"kernel", b"rootfs");
        let policy_bytes = match arg("--policy") {
            Some(path) => std::fs::read(path)?,
            None => pol::YAML.as_bytes().to_vec(),
        };
        let policy = EffectivePolicy::parse(&policy_bytes, app::sha256_hex(&policy_bytes))?;
        let world = FakeWorld::new();
        let host = app::build_host(
            Arc::clone(&cfg),
            "fake",
            policy,
            Box::new(move |_c, layout, clock| Arc::new(FakeBackend::new(world, layout, clock))),
        )?;
        let token = CancellationToken::new();
        let t2 = token.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            if let Ok(mut term) = signal(SignalKind::terminate()) {
                term.recv().await;
            }
            t2.cancel();
        });
        app::serve_host(&cfg, host, token).await
    };
    match run.await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("acf-host-fake: {e}");
            ExitCode::FAILURE
        }
    }
}
