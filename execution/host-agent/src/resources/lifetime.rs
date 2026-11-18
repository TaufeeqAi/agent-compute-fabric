//! Sandbox lifetime (contract §19.2) and its enforcement without the core (PD-4, INV-030).
//!
//! Two mechanisms, deliberately independent:
//!
//! 1. **The coordinator** issues `sandbox.destroy` at expiry (LT-3) — the orderly path, which
//!    releases the lease and removes every resource.
//! 2. **The lifetime enforcer** — a separate process whose only input is a directory of *expiry
//!    tickets*. A ticket is written the instant a runtime process exists, before it is configured.
//!    At a ticket's expiry the enforcer ends the runtime it names: by the recorded process identity
//!    and by the runtime's kill switch. It needs no store, no backend and no core, so no generation
//!    executes past its expiry by more than `expiry_tolerance` whether or not the core runs (LT-4).
//!
//! Tickets live on the runtime filesystem: they do not survive a reboot, and neither does any
//! runtime (RC-8). The enforcer holds nothing in memory that it cannot rebuild from the directory,
//! so it can be restarted at any time. It reads no bytes from a peer or a guest.

use std::{
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};

use crate::{
    backend::process::{TerminateOutcome, VmProcess},
    clock::Clock,
    domain::Expiry,
    error::{AcfError, Result},
    store::ProcessIdentity,
};

pub const TICKET_SCHEMA_VERSION: u32 = 1;
const TICKET_SUFFIX: &str = ".ticket";
const HEARTBEAT_FILE: &str = "enforcer.alive";
const MAX_TICKET_BYTES: u64 = 4096;

// ------------------------------------------------------------------ expiry arithmetic (pure)

/// LT-1: the expiry of a sandbox created now with `lifetime_ms`.
pub fn new_expiry(clock: &dyn Clock, lifetime_ms: u64) -> Expiry {
    let at = clock.after_ms(lifetime_ms);
    Expiry {
        boot_id: at.boot_id,
        mono_ns: at.ns,
        wall_ms: clock.wall_ms().saturating_add(i64::try_from(lifetime_ms).unwrap_or(i64::MAX)),
        lifetime_ms,
    }
}

/// Milliseconds until `e`, zero once it has passed. Within the boot that recorded it the monotonic
/// clock decides; in any other boot only the wall clock is left (LT-2).
pub fn remaining_ms(clock: &dyn Clock, e: &Expiry) -> u64 {
    if e.boot_id == clock.boot_id() {
        e.mono_ns.saturating_sub(clock.monotonic_ns()) / 1_000_000
    } else {
        u64::try_from(e.wall_ms.saturating_sub(clock.wall_ms())).unwrap_or(0)
    }
}

pub fn is_expired(clock: &dyn Clock, e: &Expiry) -> bool {
    remaining_ms(clock, e) == 0
}

/// LT-2: after a reboot, express `e` in the current boot. The remaining time is recomputed from the
/// wall clock and **never exceeds what remained before**: it is capped by the lifetime, and by what
/// was left at the latest moment of the old boot the store knows about (`last_known_old_mono_ns`).
/// A wall clock that jumped backwards therefore cannot extend a sandbox.
pub fn reanchor(clock: &dyn Clock, e: &Expiry, last_known_old_mono_ns: Option<u64>) -> Expiry {
    if e.boot_id == clock.boot_id() {
        return e.clone();
    }
    let by_wall = u64::try_from(e.wall_ms.saturating_sub(clock.wall_ms())).unwrap_or(0);
    let before = last_known_old_mono_ns.map(|then| e.mono_ns.saturating_sub(then) / 1_000_000).unwrap_or(e.lifetime_ms);
    let remaining = by_wall.min(before).min(e.lifetime_ms);
    let at = clock.after_ms(remaining);
    Expiry {
        boot_id: at.boot_id,
        mono_ns: at.ns,
        wall_ms: clock.wall_ms().saturating_add(i64::try_from(remaining).unwrap_or(i64::MAX)),
        lifetime_ms: e.lifetime_ms,
    }
}

// ------------------------------------------------------------------ tickets

/// Everything the enforcer needs to end one runtime, and nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpiryTicket {
    pub schema_version: u32,
    /// Host-derived name of the generation (`sbx-…-g<n>`). Also the ticket's file name.
    pub jail_id: String,
    /// The runtime process, by its stronger-than-pid identity (RC-1).
    pub process: ProcessIdentity,
    /// A file that ends the runtime when `1` is written to it, if the backend has one.
    pub kill_switch: Option<PathBuf>,
    /// Boot in which `expires_mono_ns` is meaningful. A ticket from another boot names nothing.
    pub boot_id: String,
    pub expires_mono_ns: u64,
}

/// The coordinator's handle on lifetime enforcement.
pub trait LifetimeGuard: Send + Sync + std::fmt::Debug {
    /// From now on, the runtime named by `ticket` ends at its expiry whether or not the core runs.
    /// Called before the runtime is configured; a failure ends the runtime (fail closed).
    fn arm(&self, ticket: &ExpiryTicket) -> Result<()>;
    /// The runtime is proven gone (stopped or destroyed).
    fn disarm(&self, jail_id: &str);
    /// `Some(why)` when enforcement cannot be confirmed to be running. The host then stops creating
    /// privilege (`CONTAINMENT`), because a runtime it launched could outlive its expiry.
    fn unavailable(&self) -> Option<String>;
}

fn safe_jail_id(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// The production guard: tickets are files in a private directory that the enforcer watches.
#[derive(Debug)]
pub struct TicketDir {
    dir: PathBuf,
    heartbeat_max_age: Duration,
}

impl TicketDir {
    pub fn open(dir: &Path, heartbeat_max_age: Duration) -> Result<Self> {
        fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        Ok(Self { dir: dir.to_owned(), heartbeat_max_age })
    }

    fn path(&self, jail_id: &str) -> PathBuf {
        self.dir.join(format!("{jail_id}{TICKET_SUFFIX}"))
    }
}

impl LifetimeGuard for TicketDir {
    fn arm(&self, ticket: &ExpiryTicket) -> Result<()> {
        if !safe_jail_id(&ticket.jail_id) {
            return Err(AcfError::internal("refusing to write an expiry ticket for a name that is not a host-derived jail id"));
        }
        let bytes = serde_json::to_vec(ticket)?;
        let tmp = self.dir.join(format!(".{}.tmp", ticket.jail_id));
        let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(&bytes)?;
        crate::durability::sync_all(&f)?;
        fs::rename(&tmp, self.path(&ticket.jail_id))?;
        Ok(())
    }

    fn disarm(&self, jail_id: &str) {
        if safe_jail_id(jail_id) {
            let _ = fs::remove_file(self.path(jail_id));
        }
    }

    fn unavailable(&self) -> Option<String> {
        let beat = self.dir.join(HEARTBEAT_FILE);
        let age = fs::metadata(&beat).and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok());
        match age {
            Some(a) if a <= self.heartbeat_max_age => None,
            Some(a) => Some(format!(
                "the lifetime enforcer last reported {} ms ago (limit {} ms)",
                a.as_millis(),
                self.heartbeat_max_age.as_millis()
            )),
            None => Some(format!("the lifetime enforcer has never reported in {}", self.dir.display())),
        }
    }
}

/// A guard for tests and for the in-memory test host: tickets are kept in memory and nothing is
/// enforced. Compiled only into test builds, so a release cannot run without real enforcement.
#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Default)]
pub struct MemoryLifetime {
    pub tickets: std::sync::Mutex<std::collections::BTreeMap<String, ExpiryTicket>>,
    pub down: std::sync::atomic::AtomicBool,
}

#[cfg(any(test, feature = "testing"))]
impl LifetimeGuard for MemoryLifetime {
    fn arm(&self, ticket: &ExpiryTicket) -> Result<()> {
        self.tickets.lock().map_err(|_| AcfError::internal("ticket table poisoned"))?.insert(ticket.jail_id.clone(), ticket.clone());
        Ok(())
    }
    fn disarm(&self, jail_id: &str) {
        if let Ok(mut t) = self.tickets.lock() {
            t.remove(jail_id);
        }
    }
    fn unavailable(&self) -> Option<String> {
        self.down.load(std::sync::atomic::Ordering::SeqCst).then(|| "the lifetime enforcer is down (test)".to_owned())
    }
}

// ------------------------------------------------------------------ the enforcer role

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EnforceReport {
    /// Tickets whose expiry has not passed.
    pub armed: usize,
    /// Runtimes ended in this pass.
    pub ended: usize,
    /// Tickets removed because their runtime is gone or they belong to an earlier boot.
    pub cleared: usize,
    /// Tickets that could not be read or enforced. They are kept and retried.
    pub errors: usize,
}

/// A kill switch is honoured only if it is exactly a control group's `cgroup.kill` under the
/// configured root: the enforcer writes to no other path, whatever a ticket says.
fn kill_switch_is_safe(path: &Path, cgroup_root: &Path) -> bool {
    path.is_absolute()
        && path.starts_with(cgroup_root)
        && path.file_name().is_some_and(|n| n == "cgroup.kill")
        && path.components().all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}

fn read_ticket(path: &Path) -> std::result::Result<ExpiryTicket, String> {
    let md = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !md.is_file() || md.len() > MAX_TICKET_BYTES || md.uid() != rustix::process::geteuid().as_raw() {
        return Err("not a regular file of the expected owner and size".into());
    }
    let t: ExpiryTicket = serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    if t.schema_version != TICKET_SCHEMA_VERSION || !safe_jail_id(&t.jail_id) {
        return Err("unsupported ticket".into());
    }
    Ok(t)
}

/// One pass over the ticket directory. Idempotent and restart-safe.
pub async fn enforce_once(dir: &Path, clock: &dyn Clock, cgroup_root: &Path, kill_wait: Duration) -> EnforceReport {
    let mut report = EnforceReport::default();
    let Ok(entries) = fs::read_dir(dir) else {
        report.errors += 1;
        return report;
    };
    let boot_id = clock.boot_id();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.ends_with(TICKET_SUFFIX)) {
            continue;
        }
        let ticket = match read_ticket(&path) {
            Ok(t) => t,
            Err(why) => {
                tracing::error!(ticket = %path.display(), %why, "unreadable expiry ticket; it is kept and reported");
                report.errors += 1;
                continue;
            }
        };
        if ticket.boot_id != boot_id {
            // RC-8: after a reboot no runtime is present. The ticket names nothing.
            let _ = fs::remove_file(&path);
            report.cleared += 1;
            continue;
        }
        if clock.monotonic_ns() < ticket.expires_mono_ns {
            report.armed += 1;
            continue;
        }
        // Expired. End the runtime by every means the ticket gives, then prove it is gone.
        if let Some(switch) = ticket.kill_switch.as_deref().filter(|p| kill_switch_is_safe(p, cgroup_root))
            && let Err(e) = fs::write(switch, b"1")
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(jail = %ticket.jail_id, error = %e, "kill switch could not be written");
        }
        match VmProcess::new(ticket.process.clone()).terminate(&boot_id, kill_wait).await {
            Ok(TerminateOutcome::Killed) => {
                tracing::warn!(jail = %ticket.jail_id, "runtime ended at its expiry by the lifetime enforcer");
                let _ = fs::remove_file(&path);
                report.ended += 1;
            }
            // Gone already, or the pid now belongs to something else (which is never signalled).
            Ok(TerminateOutcome::AlreadyGone | TerminateOutcome::Refused(_)) => {
                let _ = fs::remove_file(&path);
                report.cleared += 1;
            }
            Ok(TerminateOutcome::StillAlive) | Err(_) => {
                tracing::error!(jail = %ticket.jail_id, "runtime is past its expiry and could not be ended; will retry");
                report.errors += 1;
            }
        }
    }
    report
}

/// The enforcer's loop: enforce, report liveness, sleep. Runs until `shutdown` resolves.
pub async fn run_enforcer(
    dir: PathBuf,
    clock: std::sync::Arc<dyn Clock>,
    cgroup_root: PathBuf,
    interval: Duration,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
    tokio::pin!(shutdown);
    loop {
        let report = enforce_once(&dir, clock.as_ref(), &cgroup_root, Duration::from_secs(2)).await;
        if report.ended + report.errors > 0 {
            tracing::info!(?report, "lifetime enforcement pass");
        }
        // The heartbeat is what the core reads to know enforcement is alive (PD-4).
        if let Err(e) = fs::write(dir.join(HEARTBEAT_FILE), clock.wall_rfc3339()) {
            tracing::error!(error = %e, "cannot write the enforcer heartbeat");
        }
        tokio::select! {
            () = &mut shutdown => return Ok(()),
            () = tokio::time::sleep(interval) => {}
        }
    }
}

/// Serialises tests that spawn child processes whose pids are inspected.
#[cfg(test)]
static CHILD_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        backend::process::identity,
        clock::{ManualClock, SystemClock},
    };

    #[test]
    fn expiry_is_measured_on_the_monotonic_clock_within_a_boot() {
        let c = ManualClock::new();
        let e = new_expiry(&c, 10_000);
        assert_eq!(remaining_ms(&c, &e), 10_000);
        c.advance_ms(9_999);
        assert!(!is_expired(&c, &e));
        c.advance_ms(1);
        assert!(is_expired(&c, &e), "expired exactly at the lifetime");
        c.advance_ms(60_000);
        assert_eq!(remaining_ms(&c, &e), 0, "never negative");
    }

    #[test]
    fn across_a_reboot_the_remainder_comes_from_the_wall_clock_and_can_only_shrink() {
        let c = ManualClock::new();
        let e = new_expiry(&c, 600_000);
        c.advance_ms(100_000); // 100 s pass in the old boot; then the host is down for 50 s
        let last_known = c.monotonic_ns();
        c.reboot_after(50_000);
        let re = reanchor(&c, &e, Some(last_known));
        assert_eq!(re.boot_id, c.boot_id());
        assert_eq!(remaining_ms(&c, &re), 450_000, "the time the host was down counts against the lifetime");
        assert_eq!(reanchor(&c, &re, None), re, "re-anchoring in the same boot changes nothing");

        // A wall clock stepped backwards while the host was down would seem to leave more than the
        // whole lifetime. The remainder is capped by what was left when the store last knew the time.
        c.step_wall_ms(-3_600_000);
        let stepped = reanchor(&c, &e, Some(last_known));
        assert_eq!(remaining_ms(&c, &stepped), 500_000, "capped by what remained at the last moment the store knew of");
        let unknown = reanchor(&c, &e, None);
        assert_eq!(remaining_ms(&c, &unknown), 600_000, "with no knowledge of the old boot it is capped by the lifetime, never more");
    }

    #[test]
    fn a_wall_clock_that_ran_ahead_ends_the_sandbox_no_later() {
        let c = ManualClock::new();
        let e = new_expiry(&c, 60_000);
        c.reboot();
        c.advance_ms(3_600_000); // an hour has passed on the wall clock of the new boot
        let re = reanchor(&c, &e, None);
        assert!(is_expired(&c, &re));
    }

    fn ticket(jail: &str, pid: i32, expires_mono_ns: u64, clock: &dyn Clock) -> ExpiryTicket {
        let process = identity::capture(pid, &clock.boot_id()).unwrap();
        ExpiryTicket {
            schema_version: TICKET_SCHEMA_VERSION,
            jail_id: jail.into(),
            process,
            kill_switch: None,
            boot_id: clock.boot_id(),
            expires_mono_ns,
        }
    }

    fn alive(pid: i32) -> bool {
        identity::read_start_ticks(pid).is_some()
            && fs::read_to_string(format!("/proc/{pid}/stat")).ok().and_then(|s| identity::parse_stat_state(&s)).is_some_and(|st| st != 'Z')
    }

    #[tokio::test]
    async fn with_no_core_running_a_runtime_ends_at_its_expiry_and_not_before() {
        // T-HOST-01 at the mechanism level: the "runtime" is a child process; the only thing alive
        // besides it is the enforcer pass. No coordinator, no store, no backend exists in this test.
        // The clock is the test's own, so "before" and "after" do not depend on how busy the machine is.
        let _serial = CHILD_TESTS.lock().await;
        let d = tempfile::tempdir().unwrap();
        let guard = TicketDir::open(d.path(), Duration::from_secs(5)).unwrap();
        let clock = ManualClock::new();
        let mut child = std::process::Command::new("sleep").arg("300").spawn().unwrap();
        let pid = child.id() as i32;
        let expires = clock.monotonic_ns() + 400_000_000; // 400 ms from now
        guard.arm(&ticket("sbx-00000000000000000000000000000001-g1", pid, expires, &clock)).unwrap();

        let before = enforce_once(d.path(), &clock, Path::new("/sys/fs/cgroup"), Duration::from_secs(2)).await;
        assert_eq!((before.armed, before.ended), (1, 0));
        clock.advance_ms(399);
        let just_before = enforce_once(d.path(), &clock, Path::new("/sys/fs/cgroup"), Duration::from_secs(2)).await;
        assert_eq!((just_before.armed, just_before.ended), (1, 0));
        assert!(alive(pid), "a runtime is never ended before its expiry");

        clock.advance_ms(1);
        let after = enforce_once(d.path(), &clock, Path::new("/sys/fs/cgroup"), Duration::from_secs(2)).await;
        assert_eq!(after.ended, 1, "{after:?}");
        let _ = child.wait();
        assert!(!alive(pid));
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 0, "the ticket is removed once the runtime is proven gone");
    }

    #[tokio::test]
    async fn a_reused_pid_is_never_signalled_and_a_ticket_from_another_boot_is_cleared() {
        let _serial = CHILD_TESTS.lock().await;
        let d = tempfile::tempdir().unwrap();
        let guard = TicketDir::open(d.path(), Duration::from_secs(5)).unwrap();
        let clock = SystemClock;
        let mut child = std::process::Command::new("sleep").arg("300").spawn().unwrap();
        let pid = child.id() as i32;
        // The ticket names this pid with a *different* start time: a different process instance.
        let mut forged = ticket("sbx-00000000000000000000000000000002-g1", pid, 0, &clock);
        forged.process.start_time_ticks += 1;
        guard.arm(&forged).unwrap();
        let mut old_boot = ticket("sbx-00000000000000000000000000000003-g1", pid, 0, &clock);
        old_boot.boot_id = "an-earlier-boot".into();
        guard.arm(&old_boot).unwrap();

        let r = enforce_once(d.path(), &clock, Path::new("/sys/fs/cgroup"), Duration::from_millis(200)).await;
        assert_eq!((r.ended, r.cleared), (0, 2), "{r:?}");
        assert!(alive(pid), "a process that is not the recorded instance must not be touched");
        child.kill().unwrap();
        let _ = child.wait();
    }

    #[tokio::test]
    async fn unreadable_tickets_are_kept_and_counted_never_guessed_at() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("sbx-x-g1.ticket"), b"{\"schema_version\":1,\"jail_id\":\"sbx-x-g1\",\"surprise\":true}").unwrap();
        fs::write(d.path().join("notes.txt"), b"ignored").unwrap();
        let r = enforce_once(d.path(), &SystemClock, Path::new("/sys/fs/cgroup"), Duration::from_millis(50)).await;
        assert_eq!((r.errors, r.armed, r.ended, r.cleared), (1, 0, 0, 0));
        assert!(d.path().join("sbx-x-g1.ticket").exists());
    }

    #[test]
    fn the_kill_switch_is_written_only_if_it_is_a_cgroup_kill_file_under_the_root() {
        let root = Path::new("/sys/fs/cgroup");
        assert!(kill_switch_is_safe(Path::new("/sys/fs/cgroup/acf/sbx-1-g1/cgroup.kill"), root));
        for bad in [
            "/etc/passwd",
            "/sys/fs/cgroup/acf/sbx-1-g1/cgroup.procs",
            "/sys/fs/cgroup/../../etc/cgroup.kill",
            "sys/fs/cgroup/acf/x/cgroup.kill",
            "/sys/fs/cgroupx/acf/x/cgroup.kill",
        ] {
            assert!(!kill_switch_is_safe(Path::new(bad), root), "{bad}");
        }
    }

    #[test]
    fn the_core_sees_enforcement_as_unavailable_until_the_enforcer_reports_and_again_when_it_stops() {
        let d = tempfile::tempdir().unwrap();
        let guard = TicketDir::open(d.path(), Duration::from_millis(300)).unwrap();
        assert!(guard.unavailable().is_some(), "never reported");
        fs::write(d.path().join(HEARTBEAT_FILE), b"now").unwrap();
        assert_eq!(guard.unavailable(), None);
        std::thread::sleep(Duration::from_millis(400));
        assert!(guard.unavailable().is_some(), "a stale heartbeat is not liveness");
    }

    #[test]
    fn tickets_are_private_files_named_only_by_host_derived_ids() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let guard = TicketDir::open(&d.path().join("expiry"), Duration::from_secs(1)).unwrap();
        let clock = SystemClock;
        let t = ticket("sbx-00000000000000000000000000000009-g7", std::process::id() as i32, u64::MAX, &clock);
        guard.arm(&t).unwrap();
        let p = d.path().join("expiry/sbx-00000000000000000000000000000009-g7.ticket");
        assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(d.path().join("expiry")).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(read_ticket(&p).unwrap(), t);
        let mut evil = t.clone();
        evil.jail_id = "../../etc/cron.d/x".into();
        assert!(guard.arm(&evil).is_err(), "a ticket name is never a path");
        guard.disarm(&t.jail_id);
        assert!(!p.exists());
        guard.disarm(&t.jail_id); // idempotent
    }
}
