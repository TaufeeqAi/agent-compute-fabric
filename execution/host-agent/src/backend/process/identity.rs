//! Process identity that survives PID reuse: the "runtime identity" of contract §8, the ownership
//! proof recovery relies on (RC-1, OB-3).
//!
//! `(pid, start_time_ticks, boot_id)` identifies one process instance: a different process that
//! merely reuses the pid has a different start time, and a pid from before a reboot has a
//! different boot id. Additionally the VMM's `cmdline` contains the unguessable jail id, which is
//! independent evidence that "this pid is *our* firecracker for *this* generation".

use std::{fs, path::Path};

use crate::{
    error::{AcfError, Result},
    store::ProcessIdentity,
};

/// Outcome of comparing a recorded identity with what is running now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityCheck {
    /// Same process instance.
    Match,
    /// No such process (it exited).
    Gone,
    /// A process holds the pid but it is not the recorded instance. **Do not signal it.**
    Mismatch(String),
}

/// Field 22 (`starttime`) of `/proc/<pid>/stat`. The `comm` field may contain spaces and
/// parentheses, so parse from the *last* `)`.
pub fn parse_stat_start_ticks(stat: &str) -> Option<u64> {
    let after = &stat[stat.rfind(')')? + 1..];
    // after: " S ppid pgrp ... " ; fields are numbered from 3 (state) so starttime is index 19.
    after.split_whitespace().nth(19)?.parse().ok()
}

pub fn read_start_ticks(pid: i32) -> Option<u64> {
    parse_stat_start_ticks(&fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

/// State letter of `/proc/<pid>/stat` (`R`, `S`, `Z` …), parsed from after the last `)`.
pub fn parse_stat_state(stat: &str) -> Option<char> {
    stat[stat.rfind(')')? + 1..].split_whitespace().next()?.chars().next()
}

/// A zombie (`Z`) or dead (`X`) process has already exited; only its table entry lingers until
/// its parent reaps it. For ownership/liveness purposes it is **gone**.
fn is_exited(pid: i32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/stat")).ok().and_then(|s| parse_stat_state(&s)).is_none_or(|c| matches!(c, 'Z' | 'X'))
}

pub fn capture(pid: i32, boot_id: &str) -> Result<ProcessIdentity> {
    let start_time_ticks = read_start_ticks(pid).ok_or_else(|| AcfError::internal(format!("process {pid} is not readable under /proc")))?;
    Ok(ProcessIdentity { pid, start_time_ticks, boot_id: boot_id.to_owned() })
}

pub fn check(id: &ProcessIdentity, current_boot_id: &str) -> IdentityCheck {
    if is_exited(id.pid) {
        return IdentityCheck::Gone;
    }
    if id.boot_id != current_boot_id {
        // The recorded process cannot exist in this boot; any holder of the pid is unrelated.
        return match read_start_ticks(id.pid) {
            None => IdentityCheck::Gone,
            Some(_) => IdentityCheck::Mismatch("identity recorded in a previous boot".into()),
        };
    }
    match read_start_ticks(id.pid) {
        None => IdentityCheck::Gone,
        Some(t) if t == id.start_time_ticks => IdentityCheck::Match,
        Some(t) => IdentityCheck::Mismatch(format!("pid reused: start time {t} != recorded {}", id.start_time_ticks)),
    }
}

/// True if the process's argv contains `needle` as a full argument or `--key=needle` value.
pub fn cmdline_has(pid: i32, needle: &str) -> bool {
    fs::read(format!("/proc/{pid}/cmdline"))
        .map(|b| b.split(|c| *c == 0).any(|a| a == needle.as_bytes() || a.ends_with(format!("={needle}").as_bytes())))
        .unwrap_or(false)
}

/// Every effective user id that a live process currently runs as (RS-3). One pass over `/proc`;
/// a process that exits while it is being read is simply not counted.
pub fn live_uids() -> Result<Vec<u32>> {
    let mut uids = std::collections::BTreeSet::new();
    for entry in fs::read_dir("/proc")?.flatten() {
        let name = entry.file_name();
        if !name.to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(status) = fs::read_to_string(entry.path().join("status")) else { continue };
        // `Uid:` lists real, effective, saved and filesystem ids; any of them carries the identifier.
        if let Some(line) = status.lines().find_map(|l| l.strip_prefix("Uid:")) {
            uids.extend(line.split_whitespace().filter_map(|f| f.parse::<u32>().ok()));
        }
    }
    Ok(uids.into_iter().collect())
}

/// Kernel-reported confinement of a process (N2, IS-1): what the VMM is *actually* running under,
/// as opposed to what the jailer was asked for.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct SecurityPosture {
    pub uid: u32,
    pub gid: u32,
    /// `Seccomp:` — 2 means a BPF filter is installed.
    pub seccomp_mode: u32,
    /// Every thread of the VMM carries a seccomp filter of its own: more filters than the host
    /// process that started it. Mode 2 alone proves nothing under a service manager, because filters
    /// are inherited: a VMM started with its own filtering turned off still reports mode 2, with
    /// exactly the filters it inherited from the core's unit. (Found the first time a VMM started with
    /// `--no-seccomp` ran under the shipped unit, and was accepted.)
    #[serde(default)]
    pub seccomp_own_filter: bool,
    /// The same, at launch: every thread except the first carries a filter of its own, and there is
    /// at least one. Firecracker's API thread installs its filter before it serves, and the main and
    /// vCPU threads install theirs when the instance starts, so before configuration the first thread
    /// still has only what it inherited. (Measured on a real VMM: core 14 filters, API thread 15, main
    /// thread 14 until the instance starts.)
    #[serde(default)]
    pub seccomp_own_filter_at_launch: bool,
    pub no_new_privs: bool,
    /// Effective capability set is empty (privileges were dropped).
    pub caps_dropped: bool,
    /// `/proc/<pid>/root` resolves to the expected jail root.
    pub chrooted: bool,
}

impl SecurityPosture {
    /// The posture floor of a VMM that has just been launched and is not configured yet (IS-1): as
    /// [`Self::violations`], with the seccomp rule of that moment ([`Self::seccomp_own_filter_at_launch`]).
    pub fn launch_violations(&self, expect_uid: u32) -> Vec<String> {
        Self { seccomp_own_filter: self.seccomp_own_filter_at_launch, ..self.clone() }.violations(expect_uid)
    }

    /// The posture floor item N2 requires of a running VMM. Any miss fails closed (IS-1, IS-3).
    pub fn violations(&self, expect_uid: u32) -> Vec<String> {
        let mut v = Vec::new();
        if self.uid == 0 || self.uid != expect_uid {
            v.push(format!("VMM runs as uid {} (expected unprivileged uid {expect_uid})", self.uid));
        }
        if self.seccomp_mode != 2 {
            v.push(format!("seccomp filter not installed (mode {})", self.seccomp_mode));
        } else if !self.seccomp_own_filter {
            v.push("seccomp filter of the VMM's own not installed: a thread carries only the filters it inherited from the host".into());
        }
        if !self.no_new_privs {
            v.push("no_new_privs is not set".into());
        }
        if !self.caps_dropped {
            v.push("effective capabilities were not dropped".into());
        }
        if !self.chrooted {
            v.push("process is not confined to its jail root".into());
        }
        v
    }
}

/// Pure parser over `/proc/<pid>/status` text (so it is unit-testable without a VMM). `host_filters`
/// is how many seccomp filters the host process itself carries (see [`own_filter`]).
pub fn parse_status(status: &str, chrooted: bool, host_filters: u32) -> Option<SecurityPosture> {
    let field = |k: &str| status.lines().find_map(|l| l.strip_prefix(k)).map(str::trim);
    let uid = field("Uid:")?.split_whitespace().next()?.parse().ok()?;
    let gid = field("Gid:")?.split_whitespace().next()?.parse().ok()?;
    let seccomp_mode = field("Seccomp:")?.parse().ok()?;
    let no_new_privs = field("NoNewPrivs:")? == "1";
    let caps_dropped = u64::from_str_radix(field("CapEff:")?, 16).ok()? == 0;
    let seccomp_own_filter = own_filter(status, host_filters);
    Some(SecurityPosture {
        uid,
        gid,
        seccomp_mode,
        no_new_privs,
        caps_dropped,
        seccomp_own_filter,
        seccomp_own_filter_at_launch: seccomp_own_filter,
        chrooted,
    })
}

/// Whether one thread (its `/proc/.../status` text) carries a seccomp filter of its own: mode 2, and
/// more filters than the `host_filters` it could have inherited. Without a `Seccomp_filters:` line
/// (kernels before 5.9) that cannot be told, and the answer is no: the check fails closed.
pub fn own_filter(status: &str, host_filters: u32) -> bool {
    let field = |k: &str| status.lines().find_map(|l| l.strip_prefix(k)).map(str::trim);
    let mode = field("Seccomp:").and_then(|m| m.parse::<u32>().ok());
    let filters = field("Seccomp_filters:").and_then(|n| n.parse::<u32>().ok());
    mode == Some(2) && filters.is_some_and(|n| n > host_filters)
}

/// `ESRCH`, as the number `std::io::Error::raw_os_error` reports it.
fn libc_esrch() -> i32 {
    rustix::io::Errno::SRCH.raw_os_error()
}

/// How many seccomp filters this process's own thread carries: what any process it starts inherits.
pub fn host_seccomp_filters() -> u32 {
    let status = fs::read_to_string("/proc/thread-self/status").unwrap_or_default();
    status.lines().find_map(|l| l.strip_prefix("Seccomp_filters:")).and_then(|n| n.trim().parse().ok()).unwrap_or(0)
}

pub fn read_posture(pid: i32, expected_root: &Path) -> Result<SecurityPosture> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    let chrooted = same_directory(Path::new(&format!("/proc/{pid}/root")), expected_root);
    let host = host_seccomp_filters();
    let mut posture = parse_status(&status, chrooted, host).ok_or_else(|| AcfError::internal("could not parse /proc/<pid>/status"))?;
    // Every thread, not only the first: each thread of a process carries its own filter set.
    let (mut all, mut others, mut other_threads) = (true, true, 0_usize);
    for task in fs::read_dir(format!("/proc/{pid}/task"))?.flatten() {
        let first = task.file_name().to_str().and_then(|t| t.parse::<i32>().ok()) == Some(pid);
        match fs::read_to_string(task.path().join("status")) {
            Ok(text) => {
                let own = own_filter(&text, host);
                all &= own;
                if !first {
                    others &= own;
                    other_threads += 1;
                }
            }
            // A thread that ended between the listing and the read has nothing left to judge: the
            // kernel says so with ENOENT or, for a thread caught while it exits, ESRCH.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound || e.raw_os_error() == Some(libc_esrch()) => {}
            Err(e) => return Err(e.into()),
        }
    }
    posture.seccomp_own_filter = all;
    posture.seccomp_own_filter_at_launch = others && other_threads > 0;
    Ok(posture)
}

/// Whether `a` and `b` are the same directory: the same device and inode, followed through links.
///
/// This, and not the text of `readlink /proc/<pid>/root`, is how a VMM's root is compared with its jail:
/// the jailer gives the VMM a mount namespace of its own and moves its root there with `pivot_root`,
/// and seen from the host's namespace the link then reads `/`, whatever directory it is. Following the
/// link reaches the directory itself, which keeps its device and inode through the bind mount the jailer
/// makes. A process that was not confined reaches the host's `/`, which is not the jail. (Found the
/// first time a real jailer ran: a text comparison refused every correctly confined VMM.)
pub fn same_directory(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (fs::metadata(a), fs::metadata(b)) {
        (Ok(x), Ok(y)) => x.is_dir() && y.is_dir() && (x.dev(), x.ino()) == (y.dev(), y.ino()),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS_GOOD: &str = "Name:\tfirecracker\nUid:\t100003\t100003\t100003\t100003\nGid:\t100003\t100003\t100003\t100003\nCapEff:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n";

    /// A process's root is judged by what it is, not by how its link reads.
    #[test]
    fn a_root_directory_is_compared_by_device_and_inode_not_by_its_path() {
        let d = tempfile::tempdir().unwrap();
        let me = Path::new("/proc/self/root");
        assert!(same_directory(me, Path::new("/")), "this test process is not confined: its root is the host's");
        assert!(!same_directory(me, d.path()), "a directory is not the root just because it exists");
        // Two names for one directory are the same directory; a file is never a root.
        let link = d.path().join("link");
        std::os::unix::fs::symlink(d.path(), &link).unwrap();
        assert!(same_directory(&link, d.path()));
        std::fs::write(d.path().join("file"), b"x").unwrap();
        assert!(!same_directory(&d.path().join("file"), &d.path().join("file")));
        assert!(!same_directory(&d.path().join("missing"), d.path()));
    }

    #[test]
    fn stat_parsing_survives_hostile_comm_fields() {
        // comm may itself contain ") R 1 2 3" — only the LAST ')' ends it.
        let stat = "1234 (evil) R 1 2 3) S 1 1 1 0 -1 4194560 100 0 0 0 0 0 0 0 20 0 1 0 987654 12345 100 18446744073709551615";
        assert_eq!(parse_stat_start_ticks(stat), Some(987_654));
        assert_eq!(parse_stat_start_ticks("garbage"), None);
    }

    #[test]
    fn identity_of_a_real_process_matches_and_a_forged_start_time_does_not() {
        let mut child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id() as i32;
        let boot = crate::clock::Clock::boot_id(&crate::clock::SystemClock);
        let id = capture(pid, &boot).unwrap();
        assert_eq!(check(&id, &boot), IdentityCheck::Match);

        let forged = ProcessIdentity { start_time_ticks: id.start_time_ticks + 1, ..id.clone() };
        assert!(matches!(check(&forged, &boot), IdentityCheck::Mismatch(_)), "pid reuse must be detected");
        let other_boot = ProcessIdentity { boot_id: "other-boot".into(), ..id.clone() };
        assert!(matches!(check(&other_boot, &boot), IdentityCheck::Mismatch(_)));

        child.kill().unwrap();
        // killed but NOT yet reaped: a zombie must already count as gone
        for _ in 0..200 {
            if check(&id, &boot) == IdentityCheck::Gone {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(check(&id, &boot), IdentityCheck::Gone, "zombie counts as gone");
        child.wait().unwrap();
        assert!(!cmdline_has(std::process::id() as i32, "--nonexistent-needle"));
    }

    #[test]
    fn posture_parsing_and_policy() {
        let p = parse_status(STATUS_GOOD, true, 0).unwrap();
        assert!(p.violations(100_003).is_empty(), "{:?}", p.violations(100_003));
        let root = parse_status(&STATUS_GOOD.replace("100003\t100003\t100003\t100003", "0\t0\t0\t0"), true, 0).unwrap();
        assert!(!root.violations(100_003).is_empty(), "a root VMM must be a violation");
        let no_seccomp = parse_status(&STATUS_GOOD.replace("Seccomp:\t2", "Seccomp:\t0"), true, 0).unwrap();
        assert!(no_seccomp.violations(100_003).iter().any(|v| v.contains("seccomp")));
        let caps = parse_status(&STATUS_GOOD.replace("0000000000000000", "00000000000001ff"), true, 0).unwrap();
        assert!(caps.violations(100_003).iter().any(|v| v.contains("capabilities")));
        let no_chroot = parse_status(STATUS_GOOD, false, 0).unwrap();
        assert!(no_chroot.violations(100_003).iter().any(|v| v.contains("jail root")));
        assert!(parse_status("Name:\tx\n", true, 0).is_none());
    }

    /// The case found on a real host: the core runs under its unit with 14 seccomp filters; a VMM
    /// started with its own filtering turned off inherits exactly those 14 and still reports mode 2.
    #[test]
    fn a_seccomp_filter_counts_only_if_it_is_the_vmms_own() {
        let with = |n: u32| STATUS_GOOD.replace("Seccomp_filters:\t1", &format!("Seccomp_filters:\t{n}"));
        let inherited_only = parse_status(&with(14), true, 14).unwrap();
        assert_eq!(inherited_only.seccomp_mode, 2);
        assert!(
            inherited_only.violations(100_003).iter().any(|v| v.contains("of the VMM's own")),
            "{:?}",
            inherited_only.violations(100_003)
        );
        assert!(parse_status(&with(15), true, 14).unwrap().violations(100_003).is_empty(), "14 inherited and 1 of its own");
        assert!(own_filter(&with(1), 0), "a host with no filter: any filter is the VMM's own");
        let no_count = STATUS_GOOD.replace("Seccomp_filters:\t1\n", "");
        assert!(!own_filter(&no_count, 0), "a kernel that does not say how many filters cannot prove it: fail closed");
        assert!(!own_filter(&with(15).replace("Seccomp:\t2", "Seccomp:\t1"), 0), "strict mode is not a filter");
    }

    /// The two moments of the seccomp rule, as a real Firecracker behaves: before configuration only
    /// the API thread has installed its filter; once the instance runs, every thread has.
    #[test]
    fn at_launch_the_first_thread_may_still_be_unfiltered_and_once_running_no_thread_may() {
        let launched = SecurityPosture {
            uid: 100_003,
            gid: 100_003,
            seccomp_mode: 2,
            no_new_privs: true,
            caps_dropped: true,
            seccomp_own_filter: false,
            seccomp_own_filter_at_launch: true,
            chrooted: true,
        };
        assert!(launched.launch_violations(100_003).is_empty(), "{:?}", launched.launch_violations(100_003));
        assert!(!launched.violations(100_003).is_empty(), "a running VMM whose first thread has no filter of its own");
        let no_seccomp = SecurityPosture { seccomp_own_filter_at_launch: false, ..launched.clone() };
        assert!(
            no_seccomp.launch_violations(100_003).iter().any(|v| v.contains("of the VMM's own")),
            "`--no-seccomp`: the API thread carries only inherited filters, refused before configuration"
        );
        let running = SecurityPosture { seccomp_own_filter: true, ..launched };
        assert!(running.violations(100_003).is_empty());
    }

    #[test]
    fn this_test_process_reports_how_many_filters_it_carries() {
        // Unconfined under cargo, confined under a service manager; never more than a few dozen.
        assert!(host_seccomp_filters() < 64);
        let me = read_posture(std::process::id() as i32, Path::new("/")).unwrap();
        assert!(me.chrooted, "the test process's root is the host's root");
    }
}
