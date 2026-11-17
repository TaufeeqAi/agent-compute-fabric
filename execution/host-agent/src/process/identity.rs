//! Process identity that survives PID reuse (spec §13.5, DELTA-013).
//!
//! `(pid, start_time_ticks, boot_id)` identifies one process instance: a different process that
//! merely reuses the pid has a different start time, and a pid from before a reboot has a
//! different boot id. Additionally the VMM's `cmdline` contains the unguessable jail id, which is
//! independent evidence that "this pid is *our* firecracker for *this* generation".

use std::{fs, path::Path};

use crate::{
    error::{AcfError, Result},
    operation::ProcessIdentity,
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

/// Kernel-reported confinement of a process (spec §17.4, SEC-004): what the VMM is *actually*
/// running under, as opposed to what we asked the jailer for.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct SecurityPosture {
    pub uid: u32,
    pub gid: u32,
    /// `Seccomp:` — 2 means a BPF filter is installed.
    pub seccomp_mode: u32,
    pub no_new_privs: bool,
    /// Effective capability set is empty (privileges were dropped).
    pub caps_dropped: bool,
    /// `/proc/<pid>/root` resolves to the expected jail root.
    pub chrooted: bool,
}

impl SecurityPosture {
    /// The posture the Phase 1 profile requires of a running VMM (fail closed otherwise).
    pub fn violations(&self, expect_uid: u32) -> Vec<String> {
        let mut v = Vec::new();
        if self.uid == 0 || self.uid != expect_uid {
            v.push(format!("VMM runs as uid {} (expected unprivileged uid {expect_uid})", self.uid));
        }
        if self.seccomp_mode != 2 {
            v.push(format!("seccomp filter not installed (mode {})", self.seccomp_mode));
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

/// Pure parser over `/proc/<pid>/status` text (so it is unit-testable without a VMM).
pub fn parse_status(status: &str, chrooted: bool) -> Option<SecurityPosture> {
    let field = |k: &str| status.lines().find_map(|l| l.strip_prefix(k)).map(str::trim);
    let uid = field("Uid:")?.split_whitespace().next()?.parse().ok()?;
    let gid = field("Gid:")?.split_whitespace().next()?.parse().ok()?;
    let seccomp_mode = field("Seccomp:")?.parse().ok()?;
    let no_new_privs = field("NoNewPrivs:")? == "1";
    let caps_dropped = u64::from_str_radix(field("CapEff:")?, 16).ok()? == 0;
    Some(SecurityPosture { uid, gid, seccomp_mode, no_new_privs, caps_dropped, chrooted })
}

pub fn read_posture(pid: i32, expected_root: &Path) -> Result<SecurityPosture> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    let root = fs::read_link(format!("/proc/{pid}/root"))?;
    let chrooted = root == expected_root || fs::canonicalize(expected_root).map(|c| c == root).unwrap_or(false);
    parse_status(&status, chrooted).ok_or_else(|| AcfError::internal("could not parse /proc/<pid>/status"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS_GOOD: &str = "Name:\tfirecracker\nUid:\t100003\t100003\t100003\t100003\nGid:\t100003\t100003\t100003\t100003\nCapEff:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n";

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
        let p = parse_status(STATUS_GOOD, true).unwrap();
        assert!(p.violations(100_003).is_empty(), "{:?}", p.violations(100_003));
        let root = parse_status(&STATUS_GOOD.replace("100003\t100003\t100003\t100003", "0\t0\t0\t0"), true).unwrap();
        assert!(!root.violations(100_003).is_empty(), "a root VMM must be a violation");
        let no_seccomp = parse_status(&STATUS_GOOD.replace("Seccomp:\t2", "Seccomp:\t0"), true).unwrap();
        assert!(no_seccomp.violations(100_003).iter().any(|v| v.contains("seccomp")));
        let caps = parse_status(&STATUS_GOOD.replace("0000000000000000", "00000000000001ff"), true).unwrap();
        assert!(caps.violations(100_003).iter().any(|v| v.contains("capabilities")));
        let no_chroot = parse_status(STATUS_GOOD, false).unwrap();
        assert!(no_chroot.violations(100_003).iter().any(|v| v.contains("jail root")));
        assert!(parse_status("Name:\tx\n", true).is_none());
    }
}
