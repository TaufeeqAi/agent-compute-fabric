//! BND-05 — Process supervision: stronger-than-PID identity, verified signalling, cgroup limits
//! and observed resource evidence (spec §13.5, §18, §22.5).

pub mod identity;
pub mod limits;
pub mod supervisor;

pub use identity::{IdentityCheck, SecurityPosture};
pub use limits::{CgroupSpec, CgroupStats};
pub use supervisor::{TerminateOutcome, VmProcess};
