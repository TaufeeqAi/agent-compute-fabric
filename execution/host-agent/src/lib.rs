//! ACF Phase 1 host agent.
//!
//! One privileged process that owns Firecracker/Jailer, durable operation state and recovery.
//! See `docs/` and the Phase 1 Contract Specification v1.1.0 for the normative semantics each
//! module cites by section number.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod admission;
pub mod app;
pub mod backend;
pub mod clock;
pub mod config;
pub mod doctor;
pub mod domain;
pub mod error;
pub mod filesystem;
pub mod firecracker;
pub mod guest;
pub mod ids;
pub mod lifecycle;
pub mod network;
pub mod operation;
pub mod process;
pub mod protocol;
pub mod recovery;
pub mod schema;
pub mod server;
pub mod snapshot;
pub mod telemetry;

#[cfg(any(test, feature = "testing"))]
pub mod testing;
