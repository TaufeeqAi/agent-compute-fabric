//! BND-08 implementation: Firecracker + Jailer (spec §17, §20). Everything Firecracker-specific
//! lives here; nothing above `crate::backend` mentions it.

pub mod backend;
pub mod client;
pub mod jailer;
pub mod models;
pub mod verify;

pub use backend::FirecrackerBackend;
pub use jailer::{ProcInspector, ProcessInspector};
