//! BND-10 — Recovery (spec §22). On every start, before serving any request, the host agent
//! resolves everything a crashed predecessor left half-done.
//!
//! Principles (each is tested):
//! * **Observe, don't assume.** Decisions come from the journal *and* what is actually on the
//!   host (VMM present? directory present? marker proves ownership?).
//! * **Fail safe.** When a guest command's result cannot be proven, the operation is `UNKNOWN` and
//!   the VMM is stopped — never "retried", never reported `FAILED`/`SUCCEEDED` by guesswork.
//! * **Never delete what ownership cannot prove is ours** — quarantine instead.
//! * **Bounded.** Every record carries an attempt count that survives restarts; exceeding the bound
//!   quarantines rather than looping destructively.
//! * **Idempotent.** Running recovery twice is a no-op the second time.

pub mod actuate;
pub mod classify;

pub use actuate::RecoveryReport;
pub use classify::{DirObs, Observed, Plan, VmObs, classify};
