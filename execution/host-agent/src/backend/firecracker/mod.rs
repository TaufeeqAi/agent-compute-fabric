//! The Firecracker + jailer backend (contract §26; boundaries B08, B09 and the mechanism halves of
//! B11, B12 and B13: one replacement unit). Everything Firecracker-specific
//! lives here; nothing above `crate::backend` mentions it.

pub mod backend;
pub mod client;
pub mod jailer;
pub mod models;
mod netplumb;
pub mod verify;

pub use backend::FirecrackerBackend;
pub use jailer::{ProcInspector, ProcessInspector};
