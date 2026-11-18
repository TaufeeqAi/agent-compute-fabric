//! Guest-side corroboration of `network=none`: the third verification layer of contract §20.2. It can
//! only add a violation; nothing the guest says here makes a start succeed (GP-7).
//!
//! This is *corroborating* evidence only: the authoritative proof that no NIC exists is the
//! host-side Firecracker configuration (no `network-interfaces` entry). A compromised guest
//! can lie here, which is exactly why the host never treats this as an authority.

use std::{
    fs,
    net::{SocketAddr, TcpStream},
    time::Duration,
};

use acf_wire::guest::{EgressAttempt, EgressOutcome, NetReport};

/// Default egress targets: a public resolver (v4 and v6) and the cloud metadata address — the
/// three destinations a sandbox escaping `network=none` would reach for first.
pub const DEFAULT_TARGETS: &[&str] = &["1.1.1.1:53", "[2606:4700:4700::1111]:53", "169.254.169.254:80"];

pub const DEFAULT_CLASS_DIR: &str = "/sys/class/net";

pub fn probe(targets: &[String], class_dir: &std::path::Path) -> NetReport {
    let mut interfaces: Vec<String> =
        fs::read_dir(class_dir).map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();
    interfaces.sort();

    let egress_attempts = targets
        .iter()
        .map(|t| {
            let (outcome, detail) = match t.as_str().parse::<SocketAddr>() {
                Ok(addr) => match TcpStream::connect_timeout(&addr, Duration::from_millis(800)) {
                    Ok(_) => (EgressOutcome::Connected, "connected".to_owned()),
                    Err(e) => (EgressOutcome::Blocked, e.to_string()),
                },
                Err(e) => (EgressOutcome::Blocked, format!("bad target: {e}")),
            };
            EgressAttempt { target: t.clone(), outcome, detail }
        })
        .collect();

    NetReport { interfaces, egress_attempts }
}
