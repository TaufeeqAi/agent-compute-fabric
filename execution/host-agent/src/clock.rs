//! Time sources (contract OP-14, OP-17, LT-2).
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

    /// Milliseconds since the Unix epoch. Wall time is used only where the contract allows it
    /// (OP-17): `issued_at`, sandbox expiry across reboots, retention and labels.
    fn wall_ms(&self) -> i64 {
        let (s, n) = self.wall();
        s.saturating_mul(1000).saturating_add(i64::from(n / 1_000_000))
    }

    /// The monotonic instant `ms` from now, in this boot.
    fn after_ms(&self, ms: u64) -> MonotonicRef {
        MonotonicRef { boot_id: self.boot_id(), ns: self.monotonic_ns().saturating_add(ms.saturating_mul(1_000_000)) }
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
    /// Wall clock in milliseconds. Separate from `mono`: a reboot resets one and not the other, and
    /// a test can step the wall clock without time having passed.
    wall_ms: std::sync::atomic::AtomicI64,
    boot: std::sync::Mutex<String>,
}

impl ManualClock {
    pub fn new() -> Self {
        Self {
            mono: AtomicU64::new(1_000_000_000),
            wall_ms: std::sync::atomic::AtomicI64::new(1_760_000_000_000),
            boot: std::sync::Mutex::new("test-boot-1".into()),
        }
    }
    /// Time passes: both clocks move.
    pub fn advance_ms(&self, ms: u64) {
        self.mono.fetch_add(ms * 1_000_000, Ordering::SeqCst);
        self.wall_ms.fetch_add(i64::try_from(ms).unwrap_or(i64::MAX), Ordering::SeqCst);
    }
    /// The wall clock is stepped (an operator or NTP changed it). No time passes.
    pub fn step_wall_ms(&self, delta_ms: i64) {
        self.wall_ms.fetch_add(delta_ms, Ordering::SeqCst);
    }
    /// Simulate a host reboot: monotonic readings from before are no longer comparable. The wall
    /// clock carries on, `downtime_ms` later.
    pub fn reboot_after(&self, downtime_ms: u64) {
        if let Ok(mut b) = self.boot.lock() {
            *b = format!("{}-rebooted", *b);
        }
        self.mono.store(1_000_000_000, Ordering::SeqCst);
        self.wall_ms.fetch_add(i64::try_from(downtime_ms).unwrap_or(i64::MAX), Ordering::SeqCst);
    }
    pub fn reboot(&self) {
        self.reboot_after(0);
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
        let ms = self.wall_ms.load(Ordering::SeqCst);
        (ms.div_euclid(1000), u32::try_from(ms.rem_euclid(1000)).unwrap_or(0) * 1_000_000)
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

/// The current wall-clock time, formatted. For labels only.
pub fn rfc3339_now() -> String {
    SystemClock.wall_rfc3339()
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parse `YYYY-MM-DDTHH:MM:SS[.fraction]Z` to milliseconds since the Unix epoch.
///
/// Deliberately strict: UTC with a literal `Z` only, so a timestamp has exactly one spelling and the
/// acceptance-horizon check (OP-11, §11.4) cannot be confused by offsets. Returns `None` for
/// anything else; the caller refuses the request with `INVALID_REQUEST`.
pub fn parse_rfc3339_utc_ms(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if !(20..=30).contains(&b.len()) || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let part = b.get(r)?;
        part.iter().all(u8::is_ascii_digit).then(|| part.iter().fold(0i64, |acc, d| acc * 10 + i64::from(d - b'0')))
    };
    let (y, mo, d, h, mi, sec) = (num(0..4)?, num(5..7)?, num(8..10)?, num(11..13)?, num(14..16)?, num(17..19)?);
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = match mo {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if d < 1 || d > dim || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let mut millis = 0i64;
    let rest = &b[19..];
    let tail = if rest.first() == Some(&b'.') {
        let digits = rest[1..].iter().take_while(|c| c.is_ascii_digit()).count();
        if digits == 0 || digits > 9 {
            return None;
        }
        for (i, c) in rest[1..=digits].iter().enumerate().take(3) {
            millis += i64::from(c - b'0') * [100, 10, 1][i];
        }
        &rest[1 + digits..]
    } else {
        rest
    };
    if tail != b"Z" {
        return None;
    }
    let secs = days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + sec.min(59);
    Some(secs * 1000 + millis)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing_is_the_inverse_of_formatting_and_refuses_every_other_spelling() {
        for (secs, nanos) in [(0i64, 0u32), (951_782_400, 0), (1_791_158_400, 123_000_000), (1_795_000_000, 999_000_000)] {
            let text = rfc3339_utc(secs, nanos);
            assert_eq!(parse_rfc3339_utc_ms(&text), Some(secs * 1000 + i64::from(nanos / 1_000_000)), "{text}");
        }
        assert_eq!(parse_rfc3339_utc_ms("2026-11-18T10:00:00Z"), Some(1_794_996_000_000));
        assert_eq!(parse_rfc3339_utc_ms("2026-11-18T10:00:00.5Z"), Some(1_794_996_000_500));
        for bad in [
            "2026-11-18T10:00:00+00:00",
            "2026-11-18T10:00:00",
            "2026-11-18 10:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-02-30T00:00:00Z",
            "2026-11-18T24:00:00Z",
            "2026-11-18T10:00:00.Z",
            "2026-11-18T10:00:00.1234567890Z",
            "20261118T100000Z",
            "",
            "2026-11-18T10:00:00Zjunk",
        ] {
            assert_eq!(parse_rfc3339_utc_ms(bad), None, "{bad:?}");
        }
    }

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
