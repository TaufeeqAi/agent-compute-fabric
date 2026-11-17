//! ACF guest agent.
//!
//! Runs *inside* the untrusted microVM. Its trust level is therefore "untrusted by the
//! host": nothing it reports is used as an authority for host decisions. It exists so the
//! host can (a) run bounded commands, (b) obtain a deterministic restore-verification
//! probe, and (c) corroborate `network=none` from the inside.
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod exec;
pub mod netprobe;
pub mod probe;
pub mod server;
