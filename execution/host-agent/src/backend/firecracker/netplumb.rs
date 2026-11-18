//! Network plumbing for mode `allowlist` (contract §20.2, NW-1 … NW-6). Part of the backend's
//! replacement unit (§26.4): another VMM would bring its own.
//!
//! ```text
//!   guest ── eth0 ══ tap0 (gateway address) ── [ sandbox network namespace ] ── no route out
//!                       │
//!                       ├─ UDP gateway:53      resolver socket ─┐  both sockets are bound inside the
//!                       └─ TCP gateway:15001   relay socket ────┤  namespace and served by the
//!                          ▲ every guest TCP connection is      │  guest-traffic role, which runs in
//!                            redirected here by the packet      │  the HOST namespace as its own
//!                            filter                             ┘  unprivileged user
//! ```
//!
//! The namespace has no route and forwards nothing, so the guest-traffic role is the only way out.
//! If the role stops, or the filtering state is flushed, the guest has no connectivity (NW-1): the
//! failure mode of every part is "nothing passes".
//!
//! Everything here is created **before** the VMM is launched. If any step fails the generation
//! never runs (NW-2, T-NET-08).

use std::{
    ffi::OsString,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use sha2::{Digest, Sha256};
use tokio::{io::AsyncWriteExt, process::Command};

use crate::{
    config::NetworkConfig,
    error::{AcfError, Result},
    network::{GuestSegment, traffic::RELAY_PORT},
};

/// Host side of the guest's interface, inside the sandbox's namespace. Constant: the namespace is
/// private, and a restored guest expects the device it was captured with.
pub(super) const TAP: &str = "tap0";
/// The guest's interface, as Firecracker names it.
pub(super) const GUEST_IFACE: &str = "eth0";
/// Suffix of the control group the guest-traffic role of a generation runs in.
pub(super) const RELAY_CGROUP_SUFFIX: &str = "-net";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
/// Limits of the guest-traffic role's control group: it relays bytes and holds no workload data.
const RELAY_MEMORY_MAX_BYTES: u64 = 256 * 1024 * 1024;
const RELAY_PIDS_MAX: u32 = 64;

/// The packet filter of one sandbox namespace. Deterministic text: its listing is hashed after it
/// is loaded, and re-hashed at every posture recheck (IS-3).
///
/// * every TCP connection the guest opens is redirected to the relay, whatever its destination;
/// * the guest may send DNS queries to the resolver socket, and nothing else to the host side;
/// * nothing is forwarded, and nothing leaves that is not the answer to something admitted;
/// * IPv6, ICMP and every other UDP are dropped by the default policies (AL-6).
pub(super) fn ruleset(segment: &GuestSegment) -> String {
    let gw = segment.gateway;
    format!(
        "flush ruleset\n\
         table inet acf {{\n\
         \tchain prerouting {{\n\
         \t\ttype nat hook prerouting priority dstnat; policy accept;\n\
         \t\tiifname \"{TAP}\" meta l4proto tcp redirect to :{RELAY_PORT}\n\
         \t}}\n\
         \tchain input {{\n\
         \t\ttype filter hook input priority filter; policy drop;\n\
         \t\tiifname \"lo\" accept\n\
         \t\tct state established,related accept\n\
         \t\tiifname \"{TAP}\" ip daddr {gw} udp dport 53 accept\n\
         \t\tiifname \"{TAP}\" ip daddr {gw} tcp dport {RELAY_PORT} accept\n\
         \t}}\n\
         \tchain forward {{\n\
         \t\ttype filter hook forward priority filter; policy drop;\n\
         \t}}\n\
         \tchain output {{\n\
         \t\ttype filter hook output priority filter; policy drop;\n\
         \t\toifname \"lo\" accept\n\
         \t\tct state established,related accept\n\
         \t}}\n\
         }}\n"
    )
}

/// A locally administered, unicast MAC address derived from the generation's host-allocated id.
pub(super) fn guest_mac(jail_id: &str) -> String {
    let d = Sha256::digest(jail_id.as_bytes());
    format!("06:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", d[0], d[1], d[2], d[3], d[4])
}

/// The kernel command-line argument that configures the guest's interface on a cold boot:
/// `ip=<client>:<server>:<gateway>:<netmask>:<hostname>:<device>:<autoconf>:<dns0>`. The resolver
/// is the gateway address, which is also the only address the guest can reach.
pub(super) fn boot_arg(segment: &GuestSegment) -> String {
    format!("ip={}::{}:{}::{GUEST_IFACE}:off:{}", segment.guest, segment.gateway, segment.netmask(), segment.gateway)
}

/// Run one trusted executable with an empty environment, bounded in time. `inside` runs it in the
/// network namespace at that path.
async fn run(net: &NetworkConfig, inside: Option<&Path>, bin: &Path, args: &[&str], stdin: Option<&str>) -> Result<String> {
    let mut cmd = match inside {
        Some(ns) => {
            let mut c = Command::new(&net.nsenter_bin);
            let mut target = OsString::from("--net=");
            target.push(ns);
            c.arg(target).arg("--").arg(bin);
            c
        }
        None => Command::new(bin),
    };
    cmd.args(args)
        .env_clear()
        .current_dir("/")
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let what = format!("{} {}", bin.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(), args.join(" "));
    let failed = |why: String| AcfError::unavailable(format!("network setup: `{what}` {why}")).with_possible_side_effect();
    let mut child = cmd.spawn().map_err(|e| failed(format!("could not be started: {e}")))?;
    if let (Some(text), Some(mut pipe)) = (stdin, child.stdin.take()) {
        pipe.write_all(text.as_bytes()).await.map_err(|e| failed(format!("did not take its input: {e}")))?;
        drop(pipe);
    }
    let out = tokio::time::timeout(COMMAND_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| failed("timed out".into()))?
        .map_err(|e| failed(format!("failed: {e}")))?;
    if !out.status.success() {
        return Err(failed(format!("exited with {}: {}", out.status, String::from_utf8_lossy(&out.stderr).trim())));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Digest of the filtering state as the kernel lists it now.
pub(super) async fn ruleset_digest(net: &NetworkConfig, ns: &Path) -> Result<String> {
    let listing = run(net, Some(ns), &net.nft_bin, &["list", "ruleset"], None).await?;
    Ok(hex::encode(Sha256::digest(listing.as_bytes())))
}

/// Build the inside of a sandbox's namespace: loopback, the device for the VMM (owned by the
/// generation's own identity, so only its VMM can attach to it), the gateway address, and the
/// packet filter. Returns the digest of the filter as loaded.
pub(super) async fn configure(net: &NetworkConfig, ns: &Path, segment: &GuestSegment, uid: u32, gid: u32) -> Result<String> {
    let (uid, gid) = (uid.to_string(), gid.to_string());
    let address = format!("{}/{}", segment.gateway, segment.prefix);
    // The filter goes in first: there is no moment at which the device exists without it.
    run(net, Some(ns), &net.nft_bin, &["-f", "-"], Some(&ruleset(segment))).await?;
    run(net, Some(ns), &net.ip_bin, &["link", "set", "dev", "lo", "up"], None).await?;
    run(net, Some(ns), &net.ip_bin, &["tuntap", "add", "dev", TAP, "mode", "tap", "user", &uid, "group", &gid], None).await?;
    run(net, Some(ns), &net.ip_bin, &["addr", "add", &address, "dev", TAP], None).await?;
    run(net, Some(ns), &net.ip_bin, &["link", "set", "dev", TAP, "up"], None).await?;
    ruleset_digest(net, ns).await
}

/// The host's own IPv4 addresses: never a destination for a guest (AL-6).
pub(super) async fn host_addresses(net: &NetworkConfig) -> Result<Vec<Ipv4Addr>> {
    let listing = run(net, None, &net.ip_bin, &["-4", "-o", "addr", "show"], None).await?;
    Ok(parse_addresses(&listing))
}

/// `ip -4 -o addr show`: one line per address, `<n>: <dev>    inet <addr>/<prefix> …`.
fn parse_addresses(listing: &str) -> Vec<Ipv4Addr> {
    listing
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            words.find(|w| *w == "inet")?;
            words.next()?.split('/').next()?.parse().ok()
        })
        .collect()
}

/// The control group of a generation's guest-traffic role.
pub(super) fn relay_cgroup(parent: &Path, jail_id: &str) -> PathBuf {
    parent.join(format!("{jail_id}{RELAY_CGROUP_SUFFIX}"))
}

/// Create the role's control group with its limits. Fails closed: a role that cannot be bounded
/// and found again is not started.
pub(super) fn create_relay_cgroup(dir: &Path) -> Result<()> {
    std::fs::create_dir(dir)?;
    for (file, value) in [("pids.max", RELAY_PIDS_MAX.to_string()), ("memory.max", RELAY_MEMORY_MAX_BYTES.to_string())] {
        std::fs::write(dir.join(file), value)
            .map_err(|e| AcfError::unavailable(format!("cannot limit the guest-traffic role ({file}): {e}")).with_possible_side_effect())?;
    }
    // Swap is refused where the controller offers the knob; where it does not, memory.max still holds.
    let _ = std::fs::write(dir.join("memory.swap.max"), "0");
    Ok(())
}

/// Whether any process lives in the control group at `dir`.
pub(super) fn cgroup_has_processes(dir: &Path) -> bool {
    std::fs::read_to_string(dir.join("cgroup.procs")).is_ok_and(|p| p.lines().any(|l| !l.trim().is_empty()))
}

/// End every process in the control group at `dir`. Idempotent; a missing group is success.
pub(super) fn kill_cgroup(dir: &Path) {
    let _ = std::fs::write(dir.join("cgroup.kill"), "1");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment() -> GuestSegment {
        GuestSegment::parse("10.201.0.0/30").unwrap()
    }

    #[test]
    fn the_ruleset_redirects_every_guest_connection_and_drops_everything_else() {
        let r = ruleset(&segment());
        assert!(r.starts_with("flush ruleset\n"), "no rule of an earlier owner of the namespace survives");
        assert!(r.contains("iifname \"tap0\" meta l4proto tcp redirect to :15001"), "{r}");
        assert!(r.contains("iifname \"tap0\" ip daddr 10.201.0.1 udp dport 53 accept"));
        assert!(r.contains("iifname \"tap0\" ip daddr 10.201.0.1 tcp dport 15001 accept"));
        // Three filter chains, all dropping by default; nothing is forwarded at all.
        assert_eq!(r.matches("policy drop;").count(), 3);
        let forward = r.split("chain forward {").nth(1).unwrap().split('}').next().unwrap();
        assert_eq!(forward.trim(), "type filter hook forward priority filter; policy drop;");
        // The only accepts: loopback, replies, the resolver and the relay.
        assert_eq!(r.matches(" accept\n").count(), 6, "{r}");
        assert!(!r.contains("icmp") && !r.contains("ip6"), "ICMP and IPv6 have no rule: the default policy drops them");
        // Deterministic: the same segment always yields byte-identical text.
        assert_eq!(r, ruleset(&segment()));
    }

    #[test]
    fn the_guest_is_configured_to_use_the_gateway_as_its_only_resolver() {
        assert_eq!(boot_arg(&segment()), "ip=10.201.0.2::10.201.0.1:255.255.255.252::eth0:off:10.201.0.1");
    }

    #[test]
    fn the_mac_address_is_local_unicast_and_derived_from_the_host_allocated_id() {
        let a = guest_mac("sbx-00000000000000000000000000000001-g1");
        let b = guest_mac("sbx-00000000000000000000000000000001-g2");
        assert_ne!(a, b);
        assert_eq!(a, guest_mac("sbx-00000000000000000000000000000001-g1"));
        assert!(a.starts_with("06:") && a.len() == 17, "{a}");
        let first = u8::from_str_radix(&a[..2], 16).unwrap();
        assert_eq!((first & 0b01, first & 0b10), (0, 0b10), "unicast, locally administered");
    }

    #[test]
    fn host_addresses_are_read_from_the_address_listing() {
        let listing = "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever\n\
                       2: eth0    inet 203.0.113.7/24 brd 203.0.113.255 scope global eth0\\       valid_lft forever\n\
                       3: docker0    inet 172.17.0.1/16 scope global docker0\n\
                       garbage line\n";
        assert_eq!(
            parse_addresses(listing),
            vec![Ipv4Addr::new(127, 0, 0, 1), Ipv4Addr::new(203, 0, 113, 7), Ipv4Addr::new(172, 17, 0, 1)]
        );
        assert!(parse_addresses("").is_empty());
    }

    #[test]
    fn the_relay_control_group_is_a_sibling_named_after_the_generation() {
        let d = tempfile::tempdir().unwrap();
        let dir = relay_cgroup(d.path(), "sbx-aaaa-g1");
        assert_eq!(dir, d.path().join("sbx-aaaa-g1-net"));
        assert!(!cgroup_has_processes(&dir), "a group that does not exist has no processes");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("cgroup.procs"), "\n").unwrap();
        assert!(!cgroup_has_processes(&dir));
        std::fs::write(dir.join("cgroup.procs"), "4242\n").unwrap();
        assert!(cgroup_has_processes(&dir));
        kill_cgroup(&dir);
        assert_eq!(std::fs::read_to_string(dir.join("cgroup.kill")).unwrap(), "1");
    }

    /// The real thing, where the test may build a network namespace: as root, or inside
    /// `unshare --user --map-root-user --net --mount` (see `make net-plumbing-test`). Asked for
    /// anywhere else it fails; it never passes without having built the namespace.
    #[tokio::test]
    #[ignore = "needs a network namespace of its own: run with `make net-plumbing-test`"]
    async fn the_plumbing_builds_a_namespace_with_no_way_out_but_the_two_sockets() {
        let net = NetworkConfig::default();
        assert!(rustix::process::geteuid().is_root(), "this test needs root (or `make net-plumbing-test`)");
        for tool in [&net.ip_bin, &net.nft_bin, &net.nsenter_bin, &net.unshare_bin] {
            assert!(tool.exists(), "{} is needed for network mode `allowlist`", tool.display());
        }
        let d = tempfile::tempdir().unwrap();
        // Inside a user namespace the system's files belong to an unmapped owner, so the test names the
        // owner it finds: what is under test here is the plumbing, not the trusted-input rule.
        let owners = crate::testing::system_owners();
        let ns = crate::backend::netns::Netns::create(&net.unshare_bin, &owners, d.path(), "plumb-test")
            .await
            .expect("a persistent network namespace can be created");
        let seg = segment();
        let uid = rustix::process::geteuid().as_raw();
        let digest = match configure(&net, ns.path(), &seg, uid, uid).await {
            Ok(d) => d,
            Err(e) => {
                crate::backend::netns::Netns::remove(d.path(), "plumb-test").unwrap();
                panic!("the packet filter or the device could not be created: {e}");
            }
        };
        // The filter is what was loaded, and listing it again gives the same digest.
        assert_eq!(ruleset_digest(&net, ns.path()).await.unwrap(), digest);
        let listing = run(&net, Some(ns.path()), &net.nft_bin, &["list", "ruleset"], None).await.unwrap();
        assert!(listing.contains("redirect to :15001") && listing.matches("policy drop").count() == 3, "{listing}");
        // The device exists with the gateway address; there is no default route.
        let addrs = run(&net, Some(ns.path()), &net.ip_bin, &["-4", "-o", "addr", "show", "dev", TAP], None).await.unwrap();
        assert_eq!(parse_addresses(&addrs), vec![seg.gateway]);
        let routes = run(&net, Some(ns.path()), &net.ip_bin, &["route", "show", "default"], None).await.unwrap();
        assert!(routes.trim().is_empty(), "the namespace must have no way out: {routes}");
        // The two sockets can be bound inside it, from a process that stays outside.
        let (udp, tcp) = crate::network::traffic::sockets_in_namespace(ns.path(), seg.gateway).unwrap();
        assert_eq!(udp.local_addr().unwrap().to_string(), "10.201.0.1:53");
        assert_eq!(tcp.local_addr().unwrap().to_string(), "10.201.0.1:15001");
        // Flushing the filter is detected (IS-3, T-NET-07).
        run(&net, Some(ns.path()), &net.nft_bin, &["flush", "ruleset"], None).await.unwrap();
        assert_ne!(ruleset_digest(&net, ns.path()).await.unwrap(), digest);
        drop((udp, tcp));
        crate::backend::netns::Netns::remove(d.path(), "plumb-test").unwrap();
    }
}
