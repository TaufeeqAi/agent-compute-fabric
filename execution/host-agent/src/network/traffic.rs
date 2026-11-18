//! The guest-traffic role (contract PD-3, NW-5): the host side of launching it, and the role's own
//! process entry point. The code that actually reads guest traffic is the `acf-traffic` crate, which
//! contains no host-mutation code at all.
//!
//! One role process per sandbox generation in network mode `allowlist`:
//!
//! ```text
//! core (privileged)                                  role (unprivileged, in the HOST namespace)
//!   creates the sandbox's network namespace
//!   binds, inside it:  UDP gateway:53  (resolver)
//!                      TCP gateway:relay_port (relay)
//!   spawns the role under the generation's own traffic uid ─────►  proves it is unprivileged
//!   passes both sockets and the configuration  ────────────────►  serves until told to stop
//! ```
//!
//! The sockets live in the sandbox's namespace; the process lives in the host's, so the connections
//! it opens can reach the outside. The namespace itself has no route out. If the role stops, the
//! guest has no connectivity (NW-1): there is nothing else that would carry a packet.

use std::{
    io::Write,
    net::{Ipv4Addr, SocketAddrV4, TcpListener, UdpSocket},
    os::fd::{AsFd, OwnedFd},
    path::Path,
    process::Child,
};

use acf_traffic::role::RoleConfig;

use super::intent::{GuestSegment, names_private_destination, to_specs};
use crate::{
    config::NetworkConfig,
    domain::AllowEntry,
    error::{AcfError, Result},
    privsep::{self, RoleIdentity},
};

/// TCP port, on the gateway address inside the namespace, that every guest TCP connection is
/// redirected to.
pub const RELAY_PORT: u16 = 15_001;
const INIT_MARKER: &[u8] = b"acf-traffic-init";
const MAX_CONFIG_BYTES: usize = 1024 * 1024;

/// The role's configuration for one generation: its recorded intent and the host's bounds (§30).
pub fn role_config(net: &NetworkConfig, entries: &[AllowEntry], segment: &GuestSegment, host_addresses: Vec<Ipv4Addr>) -> RoleConfig {
    let mut host_addresses = host_addresses;
    host_addresses.push(segment.gateway);
    RoleConfig {
        entries: to_specs(entries),
        // Admission already decided this against the safety profile; the role loads what was admitted.
        private_destinations: names_private_destination(entries),
        max_entries: entries.len().max(1),
        host_addresses,
        // Other sandboxes use the same segment in their own namespaces; it is never a destination.
        sandbox_networks: vec![segment.cidr()],
        dns_binding_ttl_ms: net.dns_binding_ttl_ms,
        max_bindings: (entries.len() * 4).clamp(16, 4096),
        max_connections: net.relay_max_connections,
        max_pending_lookups: 64,
        sni_deadline_ms: net.server_name_deadline_ms,
        connect_deadline_ms: net.connect_deadline_ms,
        idle_timeout_ms: net.relay_idle_timeout_ms,
        upstream_timeout_ms: net.upstream_timeout_ms,
    }
}

/// Bind the resolver and relay sockets **inside** the namespace at `ns_path`.
///
/// Joining a namespace affects only the calling thread, so this runs on a thread created for the
/// purpose and never reused: no other code can find itself in the sandbox's namespace afterwards.
pub fn sockets_in_namespace(ns_path: &Path, gateway: Ipv4Addr) -> Result<(UdpSocket, TcpListener)> {
    let ns = std::fs::File::open(ns_path).map_err(|e| AcfError::internal(format!("cannot open the network namespace: {e}")))?;
    let worker = std::thread::Builder::new().name("acf-netns-bind".into()).spawn(move || -> Result<(UdpSocket, TcpListener)> {
        rustix::thread::move_into_link_name_space(ns.as_fd(), Some(rustix::thread::LinkNameSpaceType::Network))
            .map_err(|e| AcfError::internal(format!("cannot enter the network namespace: {e}")).with_possible_side_effect())?;
        let udp = UdpSocket::bind(SocketAddrV4::new(gateway, 53))?;
        let tcp = TcpListener::bind(SocketAddrV4::new(gateway, RELAY_PORT))?;
        Ok((udp, tcp))
    })?;
    worker.join().map_err(|_| AcfError::internal("the namespace worker thread panicked"))?
}

/// Start the role for one generation and hand it its sockets and configuration.
pub fn spawn(
    identity: Option<RoleIdentity>,
    jail_id: &str,
    config: &RoleConfig,
    resolver: &UdpSocket,
    relay: &TcpListener,
) -> Result<Child> {
    // The jail id on the command line is how a later activation finds this process again.
    let (child, mut channel) = privsep::spawn_role("guest-traffic", &[jail_id], identity)?;
    privsep::send_with_fds(&channel, INIT_MARKER, &[resolver.as_fd(), relay.as_fd()])?;
    let body = serde_json::to_vec(config)?;
    acf_wire::frame::write_frame(&mut channel, &body, MAX_CONFIG_BYTES)
        .map_err(|e| AcfError::internal(format!("cannot configure the guest-traffic role: {e}")))?;
    channel.flush()?;
    Ok(child)
}

/// The role's process entry point: `acf-host guest-traffic <jail-id>`. The process entered the
/// role before it had any thread; the serving thread checks again before it touches a socket.
pub async fn role_main() -> Result<()> {
    privsep::verify_unprivileged("guest-traffic")?;
    let mut channel = privsep::role_channel()?;
    let (marker, fds) = privsep::recv_with_fds(&channel, INIT_MARKER.len())?;
    let mut fds = fds.into_iter();
    let (Some(resolver), Some(relay), true) = (fds.next(), fds.next(), marker == INIT_MARKER) else {
        return Err(AcfError::internal("the guest-traffic role was not handed its two sockets"));
    };
    let body = acf_wire::frame::read_frame(&mut channel, MAX_CONFIG_BYTES)
        .map_err(|e| AcfError::internal(format!("no configuration arrived: {e}")))?;
    let config = RoleConfig::from_json(&body).map_err(|e| AcfError::internal(format!("the configuration is not valid: {e}")))?;
    drop(channel);

    // The role stops when it is told to (SIGTERM from the core, or the end of its control group).
    let stop = async {
        use tokio::signal::unix::{SignalKind, signal};
        match (signal(SignalKind::terminate()), signal(SignalKind::interrupt())) {
            (Ok(mut term), Ok(mut int)) => {
                tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
            }
            _ => std::future::pending::<()>().await,
        }
    };
    let (resolver, relay): (OwnedFd, OwnedFd) = (resolver, relay);
    let stats = acf_traffic::role::run(config, UdpSocket::from(resolver), TcpListener::from(relay), stop)
        .await
        .map_err(|e| AcfError::internal(format!("the guest-traffic role stopped: {e}")))?;
    tracing::info!(queries = stats.queries, connections = stats.connections, denied = stats.connections_denied, "guest-traffic role ended");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{AllowDestination, PortRange};

    fn entries() -> Vec<AllowEntry> {
        vec![
            AllowEntry { destination: AllowDestination::Name("pypi.org".into()), ports: vec![PortRange { from: 443, to: 443 }] },
            AllowEntry { destination: AllowDestination::Network("10.9.0.0/16".into()), ports: vec![PortRange { from: 5432, to: 5432 }] },
        ]
    }

    #[test]
    fn the_role_configuration_is_valid_and_denies_the_host_and_the_segment() {
        let segment = GuestSegment::parse("10.201.0.0/30").unwrap();
        let cfg = role_config(&NetworkConfig::default(), &entries(), &segment, vec![Ipv4Addr::new(203, 0, 113, 7)]);
        cfg.validate().unwrap();
        assert!(cfg.private_destinations, "a private network entry was admitted, so the role must load it");
        assert!(cfg.host_addresses.contains(&segment.gateway) && cfg.host_addresses.contains(&Ipv4Addr::new(203, 0, 113, 7)));
        assert_eq!(cfg.sandbox_networks, vec!["10.201.0.0/30".to_owned()]);
        // The wire form the role parses is exactly what the core serialises.
        let again = RoleConfig::from_json(&serde_json::to_vec(&cfg).unwrap()).unwrap();
        assert_eq!(again, cfg);
    }

    #[test]
    fn a_public_only_allowlist_does_not_enable_private_destinations() {
        let segment = GuestSegment::parse("10.201.0.0/30").unwrap();
        let only_public = &entries()[..1];
        let cfg = role_config(&NetworkConfig::default(), only_public, &segment, vec![]);
        assert!(!cfg.private_destinations);
        cfg.validate().unwrap();
    }
}
