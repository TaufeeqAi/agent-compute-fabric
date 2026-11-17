//! Time sources (spec §13.4).
//!
//! Deadlines, timeouts and stale-operation detection use the **monotonic** clock. Wall-clock
//! timestamps are for audit/correlation only and never participate in a decision.
//!
//! A monotonic reading is only comparable within one host boot, so persisted deadlines carry a
//! [`MonotonicRef`] `{boot_id, ns}`. After a reboot (e.g. power loss) a persisted deadline from
//! the previous boot is *void*, and recovery must treat it as expired rather than compare it.

use std::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MonotonicRef {
    pub boot_id: String,
    pub ns: u64,
}

pub trait Clock: Send + Sync + fmt::Debug {
    /// CLOCK_MONOTONIC in nanoseconds.
    fn monotonic_ns(&self) -> u64;
    /// Seconds + nanos since the Unix epoch. Informational only.
    fn wall(&self) -> (i64, u32);
    /// Identifies the current host boot (monotonic readings are comparable only within one).
    fn boot_id(&self) -> String;

    fn now_ref(&self) -> MonotonicRef {
        MonotonicRef { boot_id: self.boot_id(), ns: self.monotonic_ns() }
    }

    fn wall_rfc3339(&self) -> String {
        let (s, n) = self.wall();
        rfc3339_utc(s, n)
    }

    /// Nanoseconds until `deadline`, `None` if already past or from another boot.
    fn remaining_ns(&self, deadline: &MonotonicRef) -> Option<u64> {
        if deadline.boot_id != self.boot_id() {
            return None;
        }
        deadline.ns.checked_sub(self.monotonic_ns()).filter(|r| *r > 0)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn monotonic_ns(&self) -> u64 {
        let ts = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
        (ts.tv_sec as u64).saturating_mul(1_000_000_000).saturating_add(ts.tv_nsec as u64)
    }

    fn wall(&self) -> (i64, u32) {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => (d.as_secs() as i64, d.subsec_nanos()),
            Err(_) => (0, 0),
        }
    }

    fn boot_id(&self) -> String {
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map(|s| s.trim().to_owned())
            .unwrap_or_else(|_| "unknown-boot".to_owned())
    }
}

/// Deterministic clock for tests: time only moves when told to.
#[derive(Debug)]
pub struct ManualClock {
    mono: AtomicU64,
    boot: std::sync::Mutex<String>,
}

impl ManualClock {
    pub fn new() -> Self {
        Self { mono: AtomicU64::new(1_000_000_000), boot: std::sync::Mutex::new("test-boot-1".into()) }
    }
    pub fn advance_ms(&self, ms: u64) {
        self.mono.fetch_add(ms * 1_000_000, Ordering::SeqCst);
    }
    /// Simulate a host reboot: monotonic readings from before are no longer comparable.
    pub fn reboot(&self) {
        if let Ok(mut b) = self.boot.lock() {
            *b = format!("{}-rebooted", *b);
        }
        self.mono.store(1_000_000_000, Ordering::SeqCst);
    }
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for ManualClock {
    fn monotonic_ns(&self) -> u64 {
        self.mono.load(Ordering::SeqCst)
    }
    fn wall(&self) -> (i64, u32) {
        (1_760_000_000 + (self.mono.load(Ordering::SeqCst) / 1_000_000_000) as i64, 0)
    }
    fn boot_id(&self) -> String {
        self.boot.lock().map(|b| b.clone()).unwrap_or_default()
    }
}

/// RFC 3339 UTC formatting without a calendar dependency (Howard Hinnant's civil-from-days).
pub fn rfc3339_utc(secs: i64, nanos: u32) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{:03}Z", nanos / 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_known_values() {
        assert_eq!(rfc3339_utc(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339_utc(951_782_400, 0), "2000-02-29T00:00:00.000Z"); // leap day
        assert_eq!(rfc3339_utc(1_791_158_400, 123_000_000), "2026-10-05T00:00:00.123Z");
    }

    #[test]
    fn remaining_is_none_across_a_reboot_even_if_numerically_in_the_future() {
        let c = ManualClock::new();
        let deadline = MonotonicRef { boot_id: c.boot_id(), ns: c.monotonic_ns() + 5_000_000_000 };
        assert!(c.remaining_ns(&deadline).is_some());
        c.reboot();
        assert_eq!(c.remaining_ns(&deadline), None, "a deadline from a previous boot is void");
    }

    #[test]
    fn system_monotonic_is_non_decreasing() {
        let c = SystemClock;
        let a = c.monotonic_ns();
        assert!(c.monotonic_ns() >= a);
    }
}
