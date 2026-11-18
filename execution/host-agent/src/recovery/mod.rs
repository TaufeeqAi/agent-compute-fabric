//! Recovery (contract §16): before the host serves anything, it resolves everything an earlier
//! activation left unfinished, and it keeps reconciling for as long as it runs.
//!
//! The principles, each of which has tests:
//!
//! * **Observe, do not assume (OB-1..3).** A decision uses the store *and* what is on the host: is
//!   the recorded runtime instance there, does the ownership marker prove the files are ours, are
//!   the mandatory controls still in force.
//! * **Never continue (OP-18).** An inherited granting operation is undone to proven absence, or,
//!   when a guest command may have run, ended `UNKNOWN`. Only containment is re-driven (OP-19).
//! * **Never delete on doubt (RC-4).** What ownership cannot prove is quarantined, and stays so
//!   until an operator releases it.
//! * **Bounded (RC-6).** Attempt counts are durable; exceeding the bound quarantines.
//! * **Idempotent (RC-7).** Recovery that finds nothing to do changes nothing.
//!
//! [`decision`] is the decision table as pure functions; `coordinator::recover` observes and applies.

pub mod decision;

pub use crate::coordinator::recover::RecoveryReport;
pub use decision::{Enforcement, ExecState, IdleFacts, IdlePlan, InheritedPlan, Observed, OnDisk, Runtime, decide_idle, decide_inherited};
