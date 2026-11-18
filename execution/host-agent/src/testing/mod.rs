//! Test doubles, crash-point injection and the suites named after the contract's test catalog (§31).
//!
//! Compiled only under `cfg(test)` or the `testing` feature. A release build never includes any of
//! it (see `Makefile: release`), so there is no code path by which an operator or a request could
//! trigger a fault point, mint a test credential or select the in-memory backend in production.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test doubles may fail loudly; never compiled into release builds"
)]

pub mod fake_backend;
pub mod fake_fc;
pub mod fault;
pub mod pki;

#[cfg(test)]
pub(crate) mod conformance;
#[cfg(test)]
mod fc_backend_tests;
#[cfg(test)]
pub(crate) mod invariants;
#[cfg(test)]
pub(crate) mod rig;
#[cfg(test)]
mod shipped_files_tests;
#[cfg(test)]
mod suites;

use std::path::PathBuf;

/// A temporary directory that the trusted-input rule accepts: private, and with no ancestor that
/// another user could write.
///
/// The system temp directory is world-writable, and the rule (TI-1) rightly refuses any file beneath
/// such a directory. Tests that exercise the rule therefore need a home for their files where every
/// ancestor is owned by root or by the test user. `ACF_TEST_DIR` overrides the location.
pub fn private_tempdir() -> tempfile::TempDir {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let base = std::env::var_os("ACF_TEST_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache").join("acf-test")))
        .unwrap_or_else(std::env::temp_dir);
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&base).unwrap();
    let dir = tempfile::Builder::new().prefix("t-").tempdir_in(&base).unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

/// Owners the trusted-input rule accepts in tests: root (which owns `/` and `/home`) and the user
/// running the tests.
pub fn trusted_owners() -> Vec<u32> {
    let me = rustix::process::geteuid().as_raw();
    if me == 0 { vec![0] } else { vec![0, me] }
}

/// [`trusted_owners`], plus whoever owns the system's own directories *as this process sees them*.
///
/// Inside a user namespace (`unshare --user --map-root-user`) the real root is not mapped, so `/usr/bin`
/// and the tools in it appear to belong to the overflow uid. Tests that drive a system tool from inside
/// such a namespace are about the tool's effect, not about the trusted-input rule, and name that owner.
pub fn system_owners() -> Vec<u32> {
    use std::os::unix::fs::MetadataExt;
    let mut owners = trusted_owners();
    for dir in ["/", "/usr", "/usr/bin", "/usr/sbin"] {
        if let Ok(md) = std::fs::metadata(dir)
            && !owners.contains(&md.uid())
        {
            owners.push(md.uid());
        }
    }
    owners
}
