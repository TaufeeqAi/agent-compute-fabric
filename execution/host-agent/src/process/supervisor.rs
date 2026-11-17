//! Verified signalling of a VMM process (spec §22.5: *"cleanup must verify stable process
//! identity, not only a PID"*).
//!
//! Order matters: open a **pidfd first**, *then* verify identity, *then* signal through the pidfd.
//! A pidfd names one specific process instance, so even if the pid is recycled after the check,
//! the signal cannot reach the newcomer.

use std::time::Duration;

use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};
use tokio::time::{Instant, sleep};

use super::identity::{self, IdentityCheck};
use crate::{
    error::{AcfError, Result},
    operation::ProcessIdentity,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminateOutcome {
    AlreadyGone,
    Killed,
    /// A *different* process holds the pid. Nothing was signalled.
    Refused(String),
    /// Signalled but still present after the timeout (e.g. uninterruptible I/O).
    StillAlive,
}

#[derive(Debug, Clone)]
pub struct VmProcess {
    pub identity: ProcessIdentity,
}

impl VmProcess {
    pub fn new(identity: ProcessIdentity) -> Self {
        Self { identity }
    }

    pub fn check(&self, boot_id: &str) -> IdentityCheck {
        identity::check(&self.identity, boot_id)
    }

    pub async fn terminate(&self, boot_id: &str, wait: Duration) -> Result<TerminateOutcome> {
        let Some(pid) = Pid::from_raw(self.identity.pid) else {
            return Ok(TerminateOutcome::Refused("invalid pid".into()));
        };
        let pidfd = match pidfd_open(pid, PidfdFlags::empty()) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::SRCH) => return Ok(TerminateOutcome::AlreadyGone),
            Err(e) => return Err(AcfError::internal(format!("pidfd_open({pid:?}) failed: {e}"))),
        };
        match self.check(boot_id) {
            IdentityCheck::Gone => return Ok(TerminateOutcome::AlreadyGone),
            IdentityCheck::Mismatch(why) => return Ok(TerminateOutcome::Refused(why)),
            IdentityCheck::Match => {}
        }
        match pidfd_send_signal(&pidfd, Signal::KILL) {
            Ok(()) => {}
            Err(rustix::io::Errno::SRCH) => return Ok(TerminateOutcome::AlreadyGone),
            Err(e) => return Err(AcfError::internal(format!("pidfd_send_signal failed: {e}")).with_possible_side_effect()),
        }
        let deadline = Instant::now() + wait;
        loop {
            if self.check(boot_id) == IdentityCheck::Gone {
                return Ok(TerminateOutcome::Killed);
            }
            if Instant::now() >= deadline {
                return Ok(TerminateOutcome::StillAlive);
            }
            sleep(Duration::from_millis(10)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{Clock, SystemClock};

    #[tokio::test]
    async fn kills_the_recorded_process_and_reports_it() {
        let mut child = std::process::Command::new("sleep").arg("60").spawn().unwrap();
        let boot = SystemClock.boot_id();
        let id = identity::capture(child.id() as i32, &boot).unwrap();
        let out = VmProcess::new(id).terminate(&boot, Duration::from_secs(3)).await.unwrap();
        assert_eq!(out, TerminateOutcome::Killed);
        child.wait().unwrap();
    }

    #[tokio::test]
    async fn refuses_to_signal_a_process_whose_identity_does_not_match() {
        let mut child = std::process::Command::new("sleep").arg("60").spawn().unwrap();
        let boot = SystemClock.boot_id();
        let mut id = identity::capture(child.id() as i32, &boot).unwrap();
        id.start_time_ticks += 7; // simulates "the pid now belongs to someone else"
        let out = VmProcess::new(id).terminate(&boot, Duration::from_millis(200)).await.unwrap();
        assert!(matches!(out, TerminateOutcome::Refused(_)), "{out:?}");
        assert!(child.try_wait().unwrap().is_none(), "the innocent process must still be running");
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[tokio::test]
    async fn gone_process_is_reported_as_already_gone() {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let boot = SystemClock.boot_id();
        let id = ProcessIdentity { pid: child.id() as i32, start_time_ticks: 1, boot_id: boot.clone() };
        child.wait().unwrap();
        assert_eq!(VmProcess::new(id).terminate(&boot, Duration::from_millis(100)).await.unwrap(), TerminateOutcome::AlreadyGone);
    }
}
