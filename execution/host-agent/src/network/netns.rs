//! Empty network namespaces for VMM containment.
//!
//! Creation uses util-linux `unshare --net=<file>`, which makes the namespace persistent by
//! bind-mounting it onto `<file>` — the same mechanism `ip netns add` uses, without needing
//! iproute2. Teardown is a safe `rustix` lazy-unmount plus unlink. The path is **derived from the
//! jail id**, never read back from persisted state.

use std::{
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Duration,
};

use rustix::mount::{UnmountFlags, unmount};
use tokio::{process::Command, time::timeout};

use crate::error::{AcfError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Netns {
    path: PathBuf,
}

impl Netns {
    /// Where the namespace for `jail_id` lives beneath `dir`.
    pub fn path_for(dir: &Path, jail_id: &str) -> PathBuf {
        dir.join(format!("acf-{jail_id}"))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn create(dir: &Path, jail_id: &str) -> Result<Self> {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        let path = Self::path_for(dir, jail_id);
        // The mount target must exist as a regular file; O_EXCL refuses to reuse anything.
        std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path)?;
        let run = Command::new("unshare").arg(format!("--net={}", path.display())).arg("true").output();
        let out = match timeout(Duration::from_secs(5), run).await {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => {
                let _ = std::fs::remove_file(&path);
                return Err(AcfError::internal(format!("cannot run `unshare`: {e}")));
            }
            Err(_) => {
                let _ = std::fs::remove_file(&path);
                return Err(AcfError::internal("`unshare --net` timed out"));
            }
        };
        if !out.status.success() {
            let _ = std::fs::remove_file(&path);
            return Err(AcfError::internal(format!("`unshare --net` failed: {}", String::from_utf8_lossy(&out.stderr).trim())));
        }
        Ok(Self { path })
    }

    /// Idempotent: a missing namespace is success.
    pub fn remove(dir: &Path, jail_id: &str) -> Result<()> {
        let path = Self::path_for(dir, jail_id);
        match unmount(&path, UnmountFlags::DETACH) {
            Ok(()) | Err(rustix::io::Errno::INVAL | rustix::io::Errno::NOENT) => {}
            Err(e) => return Err(AcfError::internal(format!("unmount {} failed: {e}", path.display())).with_possible_side_effect()),
        }
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Does `pid` live in the namespace at `ns_path`? (Same nsfs inode.) This is how we prove the
    /// VMM was actually placed in the empty namespace rather than trusting that we asked.
    pub fn process_is_inside(pid: i32, ns_path: &Path) -> bool {
        match (std::fs::metadata(format!("/proc/{pid}/ns/net")), std::fs::metadata(ns_path)) {
            (Ok(a), Ok(b)) => a.ino() == b.ino() && a.dev() == b.dev(),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_root() -> bool {
        rustix::process::geteuid().is_root()
    }

    #[tokio::test]
    async fn creates_an_empty_namespace_proves_membership_and_cleans_up_idempotently() {
        if !is_root() {
            eprintln!("skip: needs root");
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let ns = Netns::create(d.path(), "sbx-test-g1").await.unwrap();
        assert!(ns.path().exists());

        // A process placed in the namespace sees only loopback in /proc/net/dev.
        let mut child =
            std::process::Command::new("nsenter").arg(format!("--net={}", ns.path().display())).args(["sleep", "30"]).spawn().unwrap();
        std::thread::sleep(Duration::from_millis(150));
        let dev = std::process::Command::new("nsenter")
            .arg(format!("--net={}", ns.path().display()))
            .args(["cat", "/proc/net/dev"])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&dev.stdout);
        let ifaces: Vec<&str> = text.lines().skip(2).filter_map(|l| l.split(':').next()).map(str::trim).collect();
        assert_eq!(ifaces, vec!["lo"], "namespace must contain only loopback, got {ifaces:?}");

        // membership: the child is inside, this test process is not.
        let kid = child.id() as i32;
        let mut inside = false;
        for _ in 0..50 {
            // `nsenter` execs `sleep`, so the pid is stable once exec has happened
            inside = Netns::process_is_inside(kid, ns.path());
            if inside {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(inside, "child must be inside the namespace");
        assert!(!Netns::process_is_inside(std::process::id() as i32, ns.path()));

        child.kill().unwrap();
        child.wait().unwrap();
        Netns::remove(d.path(), "sbx-test-g1").unwrap();
        assert!(!ns.path().exists());
        Netns::remove(d.path(), "sbx-test-g1").unwrap(); // idempotent
    }

    #[tokio::test]
    async fn refuses_to_reuse_an_existing_path() {
        if !is_root() {
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let _ns = Netns::create(d.path(), "dup").await.unwrap();
        assert!(Netns::create(d.path(), "dup").await.is_err(), "O_EXCL must refuse to reuse a namespace path");
        Netns::remove(d.path(), "dup").unwrap();
    }
}
