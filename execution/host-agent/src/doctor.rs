//! `acf-host doctor`: a preflight that answers *"will the isolation profile actually hold on this
//! machine?"* before any sandbox is created (spec §17.5, Firecracker production host setup).
//!
//! Each check is independent, has a stable name, and is `PASS`, `WARN` (works, but weaker than the
//! profile assumes) or `FAIL` (the profile cannot be honoured; the agent refuses to start).

use std::{os::unix::fs::PermissionsExt, path::Path};

use serde::Serialize;

use crate::{
    admission::trusted_file::read_trusted,
    config::HostConfig,
    error::{AcfError, FailureClass, Result},
    firecracker::verify::verify_binaries,
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
            "SMT is on: sibling hyperthreads of different sandboxes share a core (side-channel risk). Firecracker recommends disabling it for multi-tenant hosts",
        ),
        Err(_) => c("smt", Status::Warn, "cannot determine SMT state"),
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

pub fn check_uid_range(passwd: &Path, start: u32, size: u32) -> Check {
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
        c("uid_range", Status::Pass, format!("uids {start}..{} are unused by any local account", start.saturating_add(size)))
    } else {
        c(
            "uid_range",
            Status::Fail,
            format!("local accounts {clash:?} fall inside the per-VM uid range: a sandbox would run as a real user"),
        )
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
        check_uid_range(Path::new("/etc/passwd"), cfg.firecracker.uid_range_start, cfg.firecracker.uid_range_size),
        check_state_root(&cfg.paths.state_root, cfg.envelope.min_free_headroom_mib),
    ];
    v.push(
        match read_trusted(&cfg.paths.policy_path, &cfg.security.trusted_owner_uids)
            .and_then(|t| crate::admission::EffectivePolicy::parse(&t.bytes, t.sha256))
        {
            Ok(p) => c("policy", Status::Pass, format!("{} loaded and verified", p.id())),
            Err(e) => c("policy", Status::Fail, e.message),
        },
    );
    v.push(match verify_binaries(&cfg.firecracker, &cfg.security.trusted_owner_uids).await {
        Ok(r) => c(
            "firecracker",
            Status::Pass,
            format!("firecracker {} and jailer {} match the pinned profile", r.firecracker_version, r.jailer_version),
        ),
        Err(e) => c("firecracker", Status::Fail, e.message),
    });
    v.push(if which("unshare") {
        c("unshare", Status::Pass, "util-linux unshare is available (network namespaces)")
    } else {
        c("unshare", Status::Fail, "`unshare` (util-linux) is required to create network namespaces")
    });
    v
}

/// Turn a report into a start / do-not-start decision. Every `FAIL` is fatal and *all* of them are
/// named at once, so an operator can fix the machine in one pass; `WARN`s are logged and tolerated
/// (the profile holds, just with less margin than recommended).
pub fn enforce(checks: &[Check]) -> Result<()> {
    for w in checks.iter().filter(|c| c.status == Status::Warn) {
        tracing::warn!(check = w.name, "{}", w.detail);
    }
    let failed: Vec<String> = checks.iter().filter(|c| c.status == Status::Fail).map(|c| format!("{}: {}", c.name, c.detail)).collect();
    if failed.is_empty() {
        return Ok(());
    }
    Err(AcfError::new(
        FailureClass::BackendUnavailable,
        format!(
            "the isolation profile cannot be honoured on this machine ({} failed check{}; run `acf-host doctor`): {}",
            failed.len(),
            if failed.len() == 1 { "" } else { "s" },
            failed.join("; ")
        ),
    ))
}

fn which(bin: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
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
        std::fs::write(d.path().join("passwd"), "root:x:0:0::/root:/bin/sh\nsvc:x:100005:100005::/:/bin/false\n").unwrap();
        assert_eq!(check_uid_range(&d.path().join("passwd"), 100_000, 4096).status, Status::Fail, "a real account inside the VM uid range");
        assert_eq!(check_uid_range(&d.path().join("passwd"), 200_000, 4096).status, Status::Pass);
    }

    #[test]
    fn enforce_refuses_on_any_failure_names_every_one_and_tolerates_warnings() {
        let ok = vec![c("kvm", Status::Pass, "fine"), c("swap", Status::Warn, "swap is on")];
        assert!(enforce(&ok).is_ok(), "a warning must not stop the agent");
        assert!(enforce(&[]).is_ok());

        let one = vec![c("kvm", Status::Fail, "no /dev/kvm")];
        let e = enforce(&one).unwrap_err();
        assert_eq!(e.class, FailureClass::BackendUnavailable);
        assert!(e.message.contains("1 failed check;") && e.message.contains("kvm: no /dev/kvm"), "{}", e.message);

        let two = vec![c("kvm", Status::Fail, "no /dev/kvm"), c("cgroup_parent", Status::Fail, "missing"), c("swap", Status::Warn, "w")];
        let e = enforce(&two).unwrap_err();
        assert!(e.message.contains("2 failed checks"), "{}", e.message);
        assert!(e.message.contains("kvm") && e.message.contains("cgroup_parent"), "every failure is named: {}", e.message);
        assert!(!e.message.contains("swap"), "a warning is not a failure: {}", e.message);
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
