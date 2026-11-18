//! The one place a file is made durable (contract PS-2: nothing is acknowledged before it is
//! durable).
//!
//! Every `fsync` of the host goes through these two functions, so the question "does the release
//! build wait for the disk?" has one answer that is easy to audit: **always**. The switch below
//! exists only in test builds. A release build contains neither the switch nor a code path that
//! reads it (see `scripts/check-release-purity.sh`).
//!
//! Why a switch at all: the suites commit tens of thousands of times, and on some filesystems
//! (network or virtual disks) one `fsync` takes tens of milliseconds. Skipping the wait changes
//! nothing a test can observe — no test cuts the power — and the properties that depend on what is
//! on disk are tested by truncating and corrupting the store file, not by timing.

use std::io;

/// Anything with the two `fsync` flavours: `std::fs::File` and `cap_std::fs::File`.
pub(crate) trait Syncable {
    fn fsync(&self) -> io::Result<()>;
    fn fdatasync(&self) -> io::Result<()>;
}

impl Syncable for std::fs::File {
    fn fsync(&self) -> io::Result<()> {
        std::fs::File::sync_all(self)
    }
    fn fdatasync(&self) -> io::Result<()> {
        std::fs::File::sync_data(self)
    }
}

impl Syncable for cap_std::fs::File {
    fn fsync(&self) -> io::Result<()> {
        cap_std::fs::File::sync_all(self)
    }
    fn fdatasync(&self) -> io::Result<()> {
        cap_std::fs::File::sync_data(self)
    }
}

#[cfg(any(test, feature = "testing"))]
static SKIP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Test builds only: stop waiting for the disk, process-wide.
#[cfg(any(test, feature = "testing"))]
pub fn skip_in_tests(skip: bool) {
    SKIP.store(skip, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(any(test, feature = "testing"))]
fn skipped() -> bool {
    SKIP.load(std::sync::atomic::Ordering::SeqCst)
}

#[cfg(not(any(test, feature = "testing")))]
const fn skipped() -> bool {
    false
}

/// Make the file's data and metadata durable.
pub(crate) fn sync_all(f: &impl Syncable) -> io::Result<()> {
    if skipped() { Ok(()) } else { f.fsync() }
}

/// Make the file's data durable (and the metadata needed to read it back).
pub(crate) fn sync_data(f: &impl Syncable) -> io::Result<()> {
    if skipped() { Ok(()) } else { f.fdatasync() }
}
