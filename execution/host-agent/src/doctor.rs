//! `acf-host doctor`: a preflight that answers *"will the isolation profile actually hold on this
//! machine?"* before any sandbox is created (contract §17.2, IS-1).
//!
//! Each check is independent, has a stable name, and is `PASS`, `WARN` (works, but weaker than the
//! profile assumes) or `FAIL`. A `FAIL` is a failed mandatory check: the core starts in
//! `CONTAINMENT`, where it serves containment and reads and creates no privilege (HM-2). It does not
//! exit, because a host that will not start cannot destroy what it already runs.

use std::{os::unix::fs::PermissionsExt, path::Path};

use serde::Serialize;

use crate::{
    authority::{Enrolment, SafetyProfile, trusted_file::read_trusted},
    backend::firecracker::verify::{trusted_executable, verify_binaries},
    config::HostConfig,
    resources::lifetime::{LifetimeGuard, TicketDir},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
}

fn c(name: &'static str, status: Status, detail: impl Into<String>) -> Check {
    Check { name, status, detail: detail.into() }
}

pub fn check_kvm(path: &Path) -> Check {
    match std::fs::OpenOptions::new().read(true).write(true).open(path) {
        Ok(_) => c("kvm", Status::Pass, format!("{} is accessible", path.display())),
        Err(e) => c("kvm", Status::Fail, format!("cannot open {} read-write: {e} (is KVM enabled and are you root?)", path.display())),
    }
}

pub fn check_cgroups(root: &Path, parent: &str) -> Check {
    let Ok(controllers) = std::fs::read_to_string(root.join("cgroup.controllers")) else {
        return c("cgroup_v2", Status::Fail, format!("{} is not a cgroup v2 (unified) mount", root.display()));
    };
    let have: Vec<&str> = controllers.split_whitespace().collect();
    let missing: Vec<&str> = ["cpu", "memory", "pids"].into_iter().filter(|x| !have.contains(x)).collect();
    if !missing.is_empty() {
        return c("cgroup_v2", Status::Fail, format!("controllers missing at the root: {missing:?}"));
    }
    let pdir = root.join(parent);
    match std::fs::read_to_string(pdir.join("cgroup.subtree_control")) {
        Err(_) => c("cgroup_parent", Status::Fail, format!("{} does not exist; run scripts/host-setup.sh", pdir.display())),
        Ok(sub) => {
            let enabled: Vec<&str> = sub.split_whitespace().collect();
            let off: Vec<&str> = ["cpu", "memory", "pids"].into_iter().filter(|x| !enabled.contains(x)).collect();
            if off.is_empty() {
                c("cgroup_parent", Status::Pass, format!("{} delegates cpu, memory, pids", pdir.display()))
            } else {
                c("cgroup_parent", Status::Fail, format!("{} does not delegate {off:?} to children", pdir.display()))
            }
        }
    }
}

pub fn check_swap(proc_swaps: &Path) -> Check {
    match std::fs::read_to_string(proc_swaps) {
        Ok(s) if s.lines().count() <= 1 => c("swap", Status::Pass, "no swap is active"),
        Ok(_) => c(
            "swap",
            Status::Warn,
            "swap is active; guest memory could be paged to disk. Per-VM memory.swap.max=0 mitigates, but disabling swap is recommended",
        ),
        Err(e) => c("swap", Status::Warn, format!("cannot read swap state: {e}")),
    }
}

pub fn check_smt(path: &Path) -> Check {
    match std::fs::read_to_string(path).map(|s| s.trim().to_owned()) {
        Ok(s) if s == "0" || s == "notsupported" || s == "forceoff" => c("smt", Status::Pass, "SMT is off or unsupported"),
        Ok(_) => c(
            "smt",
            Status::Warn,
            "SMT is on: sibling hyperthreads of different sandboxes share a core (side-channel risk). Firecracker recommends disabling it on hosts that run mutually untrusting workloads",
        ),
        Err(_) => c("smt", Status::Warn, "cannot determine SMT state"),
    }
}

/// Kernel same-page merging deduplicates identical memory pages across processes, and therefore
/// across sandboxes: a timing side channel between workloads that do not trust each other.
/// Firecracker's production guidance is to keep it off on such hosts.
pub fn check_ksm(path: &Path) -> Check {
    match std::fs::read_to_string(path).map(|s| s.trim().to_owned()) {
        Ok(s) if s == "0" => c("ksm", Status::Pass, "kernel same-page merging is off"),
        Ok(_) => c(
            "ksm",
            Status::Warn,
            "kernel same-page merging is on: identical pages of different sandboxes are shared (side-channel risk). Turn it off: echo 0 > /sys/kernel/mm/ksm/run",
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => c("ksm", Status::Pass, "this kernel has no same-page merging"),
        Err(e) => c("ksm", Status::Warn, format!("cannot determine whether same-page merging is on: {e}")),
    }
}

pub fn check_kernel(release: &str) -> Check {
    let mut it = release.split(|ch: char| !ch.is_ascii_digit()).filter(|s| !s.is_empty()).map(|s| s.parse::<u32>().unwrap_or(0));
    let (maj, min) = (it.next().unwrap_or(0), it.next().unwrap_or(0));
    if (maj, min) >= (5, 10) {
        c("kernel", Status::Pass, format!("{release} (pidfd, openat2, cgroup v2 available)"))
    } else {
        c("kernel", Status::Fail, format!("{release} is older than 5.10; pidfd/openat2 are required"))
    }
}

/// The edge must have an identity of its own that is neither root nor one of the per-sandbox
/// identities (PD-1): a sandbox process must never be able to signal or trace the edge.
pub fn check_edge_identity(cfg: &HostConfig, core_is_root: bool) -> Check {
    let f = &cfg.firecracker;
    let in_range = |uid: u32, start: u32| uid >= start && uid < start.saturating_add(f.uid_range_size);
    match cfg.edge.uid {
        None if core_is_root => c("edge_identity", Status::Fail, "edge.uid is not set: the edge needs an unprivileged identity of its own"),
        None => c("edge_identity", Status::Warn, "edge.uid is not set; the edge will run as the core's own (unprivileged) user"),
        Some(uid) if in_range(uid, f.uid_range_start) || in_range(uid, cfg.network.traffic_uid_start) => {
            c("edge_identity", Status::Fail, format!("edge.uid {uid} lies inside a per-sandbox identifier range"))
        }
        Some(uid) => c("edge_identity", Status::Pass, format!("the edge runs as uid {uid}, outside every per-sandbox range")),
    }
}

pub fn check_uid_range(name: &'static str, passwd: &Path, start: u32, size: u32) -> Check {
    let clash: Vec<String> = std::fs::read_to_string(passwd)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            let uid: u32 = f.get(2)?.parse().ok()?;
            let name = (*f.first()?).to_owned();
            (uid >= start && uid < start.saturating_add(size)).then_some(name)
        })
        .collect();
    if clash.is_empty() {
        c(name, Status::Pass, format!("uids {start}..{} are unused by any local account", start.saturating_add(size)))
    } else {
        c(name, Status::Fail, format!("local accounts {clash:?} fall inside a per-sandbox uid range: a sandbox would run as a real user"))
    }
}

/// Network mode `allowlist` needs `ip`, `nft` and `nsenter`, each a trusted executable (TI-1).
/// Without them the mode is not offered; mode `none` is unaffected.
pub fn check_network_tools(cfg: &HostConfig) -> Check {
    let n = &cfg.network;
    let bad: Vec<String> = [&n.ip_bin, &n.nft_bin, &n.nsenter_bin]
        .into_iter()
        .filter_map(|bin| trusted_executable(bin, &cfg.security.trusted_owner_uids).err().map(|e| e.message))
        .collect();
    if bad.is_empty() {
        c("network_tools", Status::Pass, "ip, nft and nsenter are trusted executables: network mode `allowlist` can be offered")
    } else {
        c("network_tools", Status::Warn, format!("network mode `allowlist` is not offered: {}", bad.join("; ")))
    }
}

/// PD-4: is a lifetime enforcer reporting? At preflight time this is advice; the core checks again
/// when it starts and enters `CONTAINMENT` if no enforcer is running.
pub fn check_lifetime_enforcer(cfg: &HostConfig) -> Check {
    let guard = TicketDir::open(&cfg.expiry_dir(), std::time::Duration::from_millis(cfg.lifetime.heartbeat_max_age_ms));
    match guard.map(|g| g.unavailable()) {
        Ok(None) => c("lifetime", Status::Pass, "the lifetime enforcer is running"),
        Ok(Some(why)) => c("lifetime", Status::Warn, format!("{why}; start the lifetime enforcer before the core")),
        Err(e) => c("lifetime", Status::Fail, format!("the expiry ticket directory cannot be used: {}", e.message)),
    }
}

pub fn check_state_root(root: &Path, headroom_mib: u64) -> Check {
    match std::fs::metadata(root) {
        Err(_) => c("state_root", Status::Warn, format!("{} does not exist yet; it will be created 0700", root.display())),
        Ok(m) if m.permissions().mode() & 0o077 != 0 => c(
            "state_root",
            Status::Fail,
            format!("{} is accessible by group/other (mode {:o})", root.display(), m.permissions().mode() & 0o777),
        ),
        Ok(_) => match rustix::fs::statvfs(root) {
            Ok(s) if s.f_bavail.saturating_mul(s.f_frsize) / (1024 * 1024) >= headroom_mib => {
                c("state_root", Status::Pass, format!("{} is private and has ≥ {headroom_mib} MiB free", root.display()))
            }
            Ok(_) => c("state_root", Status::Warn, "less free space than the configured headroom"),
            Err(e) => c("state_root", Status::Warn, format!("statvfs failed: {e}")),
        },
    }
}

pub async fn run(cfg: &HostConfig) -> Vec<Check> {
    let uts = rustix::system::uname();
    let mut v = vec![
        check_kvm(Path::new("/dev/kvm")),
        check_kernel(&uts.release().to_string_lossy()),
        check_cgroups(&cfg.firecracker.cgroup_root, &cfg.firecracker.cgroup_parent),
        check_swap(Path::new("/proc/swaps")),
        check_smt(Path::new("/sys/devices/system/cpu/smt/active")),
        check_ksm(Path::new("/sys/kernel/mm/ksm/run")),
        check_uid_range("uid_range", Path::new("/etc/passwd"), cfg.firecracker.uid_range_start, cfg.firecracker.uid_range_size),
        check_uid_range("traffic_uid_range", Path::new("/etc/passwd"), cfg.network.traffic_uid_start, cfg.firecracker.uid_range_size),
        check_edge_identity(cfg, rustix::process::geteuid().is_root()),
        check_state_root(&cfg.paths.state_root, cfg.envelope.min_free_headroom_mib),
        check_network_tools(cfg),
        check_lifetime_enforcer(cfg),
    ];
    let owners = &cfg.security.trusted_owner_uids;
    v.push(match read_trusted(&cfg.paths.profile_path, owners).and_then(|t| SafetyProfile::parse(&t.bytes, t.sha256)) {
        Ok(p) => {
            let relations = cfg.mandatory_checks(Some(&p));
            if relations.is_empty() {
                c(PROFILE_CHECK, Status::Pass, format!("{} loaded and verified", p.id()))
            } else {
                c(PROFILE_CHECK, Status::Fail, relations.join("; "))
            }
        }
        Err(e) => c(PROFILE_CHECK, Status::Fail, e.message),
    });
    v.push(match read_trusted(&cfg.paths.enrolment_path, owners).and_then(|t| Enrolment::parse(&t.bytes, t.sha256)) {
        Ok(e) if e.doc().peers.is_empty() => c(ENROLMENT_CHECK, Status::Warn, "the enrolment table is empty: no peer can call this host"),
        Ok(e) => c(ENROLMENT_CHECK, Status::Pass, format!("{} enrolled peer(s)", e.doc().peers.len())),
        Err(e) => c(ENROLMENT_CHECK, Status::Fail, e.message),
    });
    v.push(match verify_binaries(&cfg.firecracker, &cfg.security.trusted_owner_uids).await {
        Ok(r) => c(
            "firecracker",
            Status::Pass,
            format!(
                "firecracker {} and jailer {} are the pinned bytes ({}…, {}…) of the pinned version",
                r.firecracker_version,
                r.jailer_version,
                &r.firecracker_sha256[..12],
                &r.jailer_sha256[..12]
            ),
        ),
        Err(e) => c("firecracker", Status::Fail, e.message),
    });
    v.push(check_unshare(cfg));
    v
}

/// Names of the checks whose subject the core loads itself at startup (and can reload while
/// running), so the core does not also record them as machine checks.
pub const PROFILE_CHECK: &str = "profile";
pub const ENROLMENT_CHECK: &str = "enrolment";

/// The failed mandatory checks of a report about the *machine*: one line per `FAIL`, all of them,
/// so an operator can fix the host in one pass. `WARN`s are logged and tolerated (the profile
/// holds, with less margin than recommended).
pub fn machine_failures(checks: &[Check]) -> Vec<String> {
    for w in checks.iter().filter(|c| c.status == Status::Warn) {
        tracing::warn!(check = w.name, "{}", w.detail);
    }
    checks
        .iter()
        .filter(|c| c.status == Status::Fail && c.name != PROFILE_CHECK && c.name != ENROLMENT_CHECK)
        .map(|c| format!("{}: {}", c.name, c.detail))
        .collect()
}

/// Every sandbox gets a network namespace of its own, in both network modes, and `unshare` is what
/// creates it. It runs as root, so it must be a trusted input (TI-1): without it no sandbox starts.
pub fn check_unshare(cfg: &HostConfig) -> Check {
    let bin = &cfg.network.unshare_bin;
    match trusted_executable(bin, &cfg.security.trusted_owner_uids) {
        Ok(()) => c("unshare", Status::Pass, format!("{} is a trusted executable (network namespaces)", bin.display())),
        Err(e) => c("unshare", Status::Fail, format!("`unshare` (util-linux) is required to create network namespaces: {}", e.message)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_checks_name_exactly_what_is_missing() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(check_cgroups(d.path(), "acf").status, Status::Fail, "not a cgroup mount");
        std::fs::write(d.path().join("cgroup.controllers"), "cpu memory").unwrap();
        assert!(check_cgroups(d.path(), "acf").detail.contains("pids"));
        std::fs::write(d.path().join("cgroup.controllers"), "cpu memory pids io").unwrap();
        assert_eq!(check_cgroups(d.path(), "acf").status, Status::Fail, "parent missing");
        std::fs::create_dir(d.path().join("acf")).unwrap();
        std::fs::write(d.path().join("acf/cgroup.subtree_control"), "cpu memory").unwrap();
        assert!(check_cgroups(d.path(), "acf").detail.contains("pids"));
        std::fs::write(d.path().join("acf/cgroup.subtree_control"), "cpu memory pids").unwrap();
        assert_eq!(check_cgroups(d.path(), "acf").status, Status::Pass);
    }

    #[test]
    fn kernel_swap_smt_and_uid_range() {
        assert_eq!(check_kernel("6.1.0-fc").status, Status::Pass);
        assert_eq!(check_kernel("5.4.0").status, Status::Fail);
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("swaps"), "Filename Type Size Used Priority\n").unwrap();
        assert_eq!(check_swap(&d.path().join("swaps")).status, Status::Pass);
        std::fs::write(d.path().join("swaps"), "Filename Type Size Used Priority\n/swap file 1 0 -2\n").unwrap();
        assert_eq!(check_swap(&d.path().join("swaps")).status, Status::Warn);
        std::fs::write(d.path().join("smt"), "1\n").unwrap();
        assert_eq!(check_smt(&d.path().join("smt")).status, Status::Warn);
        assert_eq!(check_ksm(&d.path().join("ksm")).status, Status::Pass, "a kernel without same-page merging");
        for (run, status) in [("0\n", Status::Pass), ("1\n", Status::Warn), ("2\n", Status::Warn)] {
            std::fs::write(d.path().join("ksm"), run).unwrap();
            assert_eq!(check_ksm(&d.path().join("ksm")).status, status, "ksm/run = {run:?}");
        }
        std::fs::write(d.path().join("passwd"), "root:x:0:0::/root:/bin/sh\nsvc:x:100005:100005::/:/bin/false\n").unwrap();
        assert_eq!(
            check_uid_range("uid_range", &d.path().join("passwd"), 100_000, 4096).status,
            Status::Fail,
            "a real account inside the VM uid range"
        );
        assert_eq!(check_uid_range("uid_range", &d.path().join("passwd"), 200_000, 4096).status, Status::Pass);
    }

    #[test]
    fn the_edge_needs_an_identity_outside_every_sandbox_range() {
        let d = tempfile::tempdir().unwrap();
        let mut cfg = crate::config::test_support::config(d.path());
        assert_eq!(check_edge_identity(&cfg, true).status, Status::Fail, "a root core cannot start an edge without an identity");
        assert_eq!(check_edge_identity(&cfg, false).status, Status::Warn);
        cfg.edge.uid = Some(990);
        assert_eq!(check_edge_identity(&cfg, true).status, Status::Pass);
        cfg.edge.uid = Some(cfg.firecracker.uid_range_start + 3);
        assert_eq!(check_edge_identity(&cfg, true).status, Status::Fail, "the edge must not share an identity with a VMM");
        cfg.edge.uid = Some(cfg.network.traffic_uid_start);
        assert_eq!(check_edge_identity(&cfg, true).status, Status::Fail, "nor with a guest-traffic process");
    }

    #[test]
    fn missing_network_tools_withdraw_the_allowlist_mode_and_nothing_else() {
        let d = tempfile::tempdir().unwrap();
        let mut cfg = crate::config::test_support::config(d.path());
        cfg.network.nft_bin = d.path().join("no-such-nft");
        let check = check_network_tools(&cfg);
        assert_eq!(check.status, Status::Warn, "mode `none` still works, so this is not a failed mandatory check");
        assert!(check.detail.contains("allowlist"), "{}", check.detail);
    }

    #[test]
    fn the_lifetime_enforcer_check_reports_a_missing_heartbeat() {
        let d = tempfile::tempdir().unwrap();
        let cfg = crate::config::test_support::config(d.path());
        assert_eq!(check_lifetime_enforcer(&cfg).status, Status::Warn);
        std::fs::write(cfg.expiry_dir().join("enforcer.alive"), b"now").unwrap();
        assert_eq!(check_lifetime_enforcer(&cfg).status, Status::Pass);
    }

    #[test]
    fn every_machine_failure_is_named_and_warnings_are_tolerated() {
        let ok = vec![c("kvm", Status::Pass, "fine"), c("swap", Status::Warn, "swap is on")];
        assert!(machine_failures(&ok).is_empty(), "a warning is not a failed mandatory check");
        assert!(machine_failures(&[]).is_empty());

        let two = vec![c("kvm", Status::Fail, "no /dev/kvm"), c("cgroup_parent", Status::Fail, "missing"), c("swap", Status::Warn, "w")];
        assert_eq!(machine_failures(&two), vec!["kvm: no /dev/kvm".to_owned(), "cgroup_parent: missing".to_owned()]);

        // The profile and the enrolment table are loaded (and reloaded) by the core itself, which
        // records their own reason; reporting them here too would leave a reason no reload can clear.
        let inputs = vec![c(PROFILE_CHECK, Status::Fail, "bad"), c(ENROLMENT_CHECK, Status::Fail, "bad")];
        assert!(machine_failures(&inputs).is_empty());
    }

    #[test]
    fn state_root_must_be_private() {
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(check_state_root(d.path(), 1).status, Status::Fail);
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(check_state_root(d.path(), 1).status, Status::Pass);
    }
}
