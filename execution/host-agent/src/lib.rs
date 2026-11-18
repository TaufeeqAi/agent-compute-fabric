//! Agent Compute Fabric — the Rust execution plane (host agent).
//!
//! One binary, several roles (contract §6.1): an unprivileged **edge** that terminates every ingress
//! endpoint, a privileged **core** that is the only writer of durable state and the only caller of
//! the backend, an unprivileged **guest-traffic** role that parses guest network traffic, and a
//! **lifetime enforcer** that ends runtimes at their expiry even when the core is not running.
//!
//! The module tree follows the contract's projection (§29). `domain` imports no edge, store-engine
//! or backend type; `backend` is the only place that knows the VMM. Each module cites the contract
//! clauses it implements by id (for example `OP-2`, `RC-4`, `AL-3`).
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod api;
pub mod app;
pub mod authority;
pub mod backend;
pub mod clock;
pub mod config;
pub mod coordinator;
pub mod doctor;
pub mod domain;
pub mod durability;
pub mod edge;
pub mod error;
pub mod guest;
pub mod ids;
pub mod network;
pub mod privsep;
pub mod recovery;
pub mod resources;
pub mod secrets;
pub mod storage;
pub mod store;
pub mod telemetry;

#[cfg(any(test, feature = "testing"))]
pub mod testing;
