//! Process supervision: stronger-than-PID identity, verified signalling, cgroup limits and observed
//! resource evidence (contract §8, OB-3, RS-2).

pub mod identity;
pub mod limits;
pub mod supervisor;

pub use identity::{IdentityCheck, SecurityPosture};
pub use limits::{CgroupSpec, CgroupStats};
pub use supervisor::{TerminateOutcome, VmProcess};
