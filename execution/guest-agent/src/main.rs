//! `acf-guest-agent` entry point.
//!
//! Usage: `acf-guest-agent [--listen vsock:<port>|unix:<path>] [--canary <path>] [--allow-shutdown]`

use std::{
    os::unix::net::UnixListener,
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
};

use acf_guest::server::{Agent, AgentConfig};
use acf_wire::guest::{GUEST_VSOCK_PORT, HOST_CID};

const MAX_CONNECTIONS: usize = 16;

fn usage() -> ExitCode {
    eprintln!("usage: acf-guest-agent [--listen vsock:<port>|unix:<path>] [--canary <path>] [--boot-id <path>] [--allow-shutdown]");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let mut listen = format!("vsock:{GUEST_VSOCK_PORT}");
    let mut cfg = AgentConfig::default();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--listen" => match args.next() {
                Some(v) => listen = v,
                None => return usage(),
            },
            "--canary" => match args.next() {
                Some(v) => cfg.canary_path = v.into(),
                None => return usage(),
            },
            "--boot-id" => match args.next() {
                Some(v) => cfg.boot_id_path = v.into(),
                None => return usage(),
            },
            "--allow-shutdown" => cfg.allow_shutdown = true,
            _ => return usage(),
        }
    }
    let agent = Arc::new(Agent::new(cfg));
    let live = Arc::new(AtomicUsize::new(0));

    if let Some(path) = listen.strip_prefix("unix:") {
        let _ = std::fs::remove_file(path);
        let l = match UnixListener::bind(path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("bind {path}: {e}");
                return ExitCode::FAILURE;
            }
        };
        eprintln!("acf-guest-agent listening on unix:{path}");
        for conn in l.incoming().flatten() {
            spawn_conn(&agent, &live, conn);
        }
        return ExitCode::SUCCESS;
    }

    let Some(port) = listen.strip_prefix("vsock:").and_then(|p| p.parse::<u32>().ok()) else {
        return usage();
    };
    let l = match vsock::VsockListener::bind(&vsock::VsockAddr::new(vsock::VMADDR_CID_ANY, port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("vsock bind {port}: {e}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!("acf-guest-agent listening on vsock:{port}");
    for conn in l.incoming().flatten() {
        // Only the host may talk to us. Anything else is dropped without a byte exchanged.
        match conn.peer_addr() {
            Ok(peer) if peer.cid() == HOST_CID => spawn_conn(&agent, &live, conn),
            _ => drop(conn),
        }
    }
    ExitCode::SUCCESS
}

fn spawn_conn<S>(agent: &Arc<Agent>, live: &Arc<AtomicUsize>, mut conn: S)
where
    S: std::io::Read + std::io::Write + Send + 'static,
{
    if live.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
        live.fetch_sub(1, Ordering::SeqCst);
        return; // shed load rather than spawn unbounded threads
    }
    let (agent, live) = (Arc::clone(agent), Arc::clone(live));
    thread::spawn(move || {
        agent.serve(&mut conn);
        live.fetch_sub(1, Ordering::SeqCst);
    });
}
