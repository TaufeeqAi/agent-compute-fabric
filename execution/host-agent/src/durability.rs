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
///
/// A flush waits for whatever the filesystem must write first, which on a filesystem shared with
/// sandbox payloads can be hundreds of megabytes: it is disk-bound work ([`blocking`]).
pub(crate) fn sync_all(f: &impl Syncable) -> io::Result<()> {
    if skipped() { Ok(()) } else { blocking(|| f.fsync()) }
}

/// Make the file's data durable (and the metadata needed to read it back). Disk-bound, as above.
pub(crate) fn sync_data(f: &impl Syncable) -> io::Result<()> {
    if skipped() { Ok(()) } else { blocking(|| f.fdatasync()) }
}

/// Run disk-bound work that can take long (copying, hashing and flushing a root filesystem or a
/// guest's memory: hundreds of megabytes, and as long as the disk needs) from async code.
///
/// On the multi-threaded runtime the other tasks waiting on this worker are first handed to
/// another one ([`tokio::task::block_in_place`]), so no answer to anyone else waits for this disk.
/// The work still runs to its end before the caller goes on: unlike a detached blocking task, an
/// operation that is cancelled or times out meanwhile never has a copy still being written behind
/// the cleanup that follows it. Elsewhere (a single-threaded test runtime, or no runtime) it runs
/// in place.
pub(crate) fn blocking<T>(work: impl FnOnce() -> T) -> T {
    use tokio::runtime::{Handle, RuntimeFlavor};
    match Handle::try_current() {
        Ok(h) if h.runtime_flavor() == RuntimeFlavor::MultiThread => tokio::task::block_in_place(work),
        _ => work(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test code")]
mod tests {
    use super::blocking;

    #[test]
    fn disk_work_runs_in_place_outside_a_runtime() {
        assert_eq!(blocking(|| 7), 7);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn disk_work_runs_in_place_on_a_single_threaded_runtime() {
        assert_eq!(blocking(|| 7), 7, "block_in_place would panic here");
    }

    /// While one task is inside the disk work, another task that was queued on the same worker
    /// still runs: the work does not hold the worker's queue.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn disk_work_does_not_hold_up_the_other_tasks_of_its_worker() {
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let (ran_tx, ran_rx) = tokio::sync::oneshot::channel::<()>();
        let worker = tokio::spawn(async move {
            // Queued behind this task on the same worker (the slot a just-spawned task takes).
            let other = tokio::spawn(async move {
                let _ = ran_tx.send(());
            });
            blocking(move || wait.recv().unwrap());
            other.await.unwrap();
        });
        let ran = tokio::time::timeout(std::time::Duration::from_secs(10), ran_rx).await;
        release.send(()).unwrap();
        worker.await.unwrap();
        assert!(ran.is_ok(), "a task queued on the busy worker ran while the disk work was in progress");
    }
}
