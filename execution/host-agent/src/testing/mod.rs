//! Test doubles and crash-point injection. Compiled only under `cfg(test)` or the `testing`
//! feature; the release build never includes any of it (see `Makefile: release`), so there is no
//! code path by which an operator or a request could trigger a fault point in production.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test doubles may fail loudly; never compiled into release builds"
)]

pub mod fake_backend;
pub mod fake_fc;
pub mod fault;

#[cfg(test)]
mod contract_tests;
#[cfg(test)]
mod fc_backend_tests;
#[cfg(test)]
mod recovery_tests;
#[cfg(test)]
pub(crate) mod rig;
#[cfg(test)]
mod server_tests;
#[cfg(test)]
mod shipped_files_tests;
