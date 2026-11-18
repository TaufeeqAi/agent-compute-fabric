//! The on-disk layout, rooted at `state_root` (one place that spells every directory).
//!
//! ```text
//! <state_root>/
//!   state/            journal.wal, host-agent.lock          (0700)
//!   images/<alias>/   manifest.json, <kernel>, <rootfs>     (operator-installed, read-only to us)
//!   sandboxes/<sbx>/<gen>/   OWNER.json, jail/…             (0700)
//!   snapshots/<snp>/<gen>/   manifest.json, vmstate, mem, disk
//!   artifacts/<art>/         content, meta.json
//! ```

use std::path::{Path, PathBuf};

use cap_std::{ambient_authority, fs::Dir};

use crate::{
    error::{AcfError, Result},
    ids::{ArtifactId, Generation, SandboxId, SnapshotId},
};

#[derive(Debug)]
pub struct Layout {
    root: PathBuf,
    #[allow(dead_code)] // reserved for per-host state files (journal dir is created through it)
    pub(crate) state: Dir,
    pub(crate) images: Dir,
    pub(crate) sandboxes: Dir,
    pub(crate) snapshots: Dir,
    pub(crate) artifacts: Dir,
}

fn open_private(root: &Dir, name: &str) -> Result<Dir> {
    use cap_std::fs::{DirBuilder, DirBuilderExt};
    let mut b = DirBuilder::new();
    b.mode(0o700);
    match root.create_dir_with(name, &b) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    Ok(root.open_dir(name)?)
}

impl Layout {
    /// Create (if needed) and open the layout. `root` itself is created 0700.
    pub fn open(root: &Path) -> Result<Self> {
        std::fs::create_dir_all(root)?;
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
        }
        let r = Dir::open_ambient_dir(root, ambient_authority())?;
        Ok(Self {
            root: root.to_owned(),
            state: open_private(&r, "state")?,
            images: open_private(&r, "images")?,
            sandboxes: open_private(&r, "sandboxes")?,
            snapshots: open_private(&r, "snapshots")?,
            artifacts: open_private(&r, "artifacts")?,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    // ---- derived absolute paths (for jailer argv, logs and evidence only; never re-read) ----

    pub fn generation_path(&self, sbx: &SandboxId, generation: Generation) -> PathBuf {
        self.root.join("sandboxes").join(sbx.as_str()).join(generation.to_string())
    }

    pub fn jail_base(&self, sbx: &SandboxId, generation: Generation) -> PathBuf {
        self.generation_path(sbx, generation).join("jail")
    }

    pub fn snapshot_path(&self, snp: &SnapshotId, generation: Generation) -> PathBuf {
        self.root.join("snapshots").join(snp.as_str()).join(generation.to_string())
    }

    pub fn artifact_path(&self, art: &ArtifactId) -> PathBuf {
        self.root.join("artifacts").join(art.as_str())
    }

    /// Free bytes on the filesystem holding the state root.
    pub fn free_bytes(&self) -> Result<u64> {
        let st = rustix::fs::statvfs(&self.root).map_err(|e| AcfError::internal(format!("statvfs failed: {e}")))?;
        Ok(st.f_bavail.saturating_mul(st.f_frsize))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn layout_is_private_and_idempotent() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("acf");
        let l = Layout::open(&root).unwrap();
        for sub in ["state", "images", "sandboxes", "snapshots", "artifacts"] {
            let mode = std::fs::metadata(root.join(sub)).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{sub}");
        }
        assert_eq!(std::fs::metadata(&root).unwrap().permissions().mode() & 0o777, 0o700);
        drop(l);
        Layout::open(&root).unwrap();
    }

    #[test]
    fn derived_paths_contain_only_validated_components() {
        let d = tempfile::tempdir().unwrap();
        let l = Layout::open(&d.path().join("acf")).unwrap();
        let sbx = SandboxId::generate();
        let p = l.jail_base(&sbx, Generation(7));
        assert!(p.ends_with(format!("sandboxes/{sbx}/7/jail")));
        assert!(l.free_bytes().unwrap() > 0);
    }
}

// ---- small confined-I/O helpers shared by the stores ----

use std::io::{Read, Write};

/// fsync a directory so that renames/creates inside it are durable. (`cap-std` opens `Dir`
/// handles `O_PATH`, which `fsync` rejects with EBADF, so open `.` as a real read-only fd.)
pub(crate) fn fsync_dir(dir: &Dir) -> Result<()> {
    crate::durability::sync_all(&dir.open(".")?)?;
    Ok(())
}

/// Crash-safe replace: write `.name.tmp`, fsync, rename over `name`, fsync the directory.
/// A reader (or recovery) therefore sees either the old content or the new — never a mix.
pub(crate) fn write_atomic(dir: &Dir, name: &str, bytes: &[u8]) -> Result<()> {
    use cap_std::fs::{OpenOptions, OpenOptionsExt};
    let tmp = format!(".{name}.tmp");
    let mut o = OpenOptions::new();
    o.write(true).create(true).truncate(true).mode(0o600);
    let mut f = dir.open_with(&tmp, &o)?;
    f.write_all(bytes)?;
    crate::durability::sync_all(&f)?;
    drop(f);
    dir.rename(&tmp, dir, name)?;
    fsync_dir(dir)?;
    Ok(())
}

/// Read at most `max` bytes; fail (rather than truncate) if the file is larger.
pub(crate) fn read_bounded(dir: &Dir, name: &str, max: u64) -> Result<Vec<u8>> {
    let f = dir.open(name)?.into_std();
    let mut out = Vec::new();
    f.take(max + 1).read_to_end(&mut out)?;
    if out.len() as u64 > max {
        return Err(AcfError::corrupt(format!("{name} is larger than {max} bytes")));
    }
    Ok(out)
}

#[cfg(test)]
mod io_tests {
    use super::*;

    #[test]
    fn write_atomic_replaces_and_leaves_no_temp_file() {
        let d = tempfile::tempdir().unwrap();
        let dir = Dir::open_ambient_dir(d.path(), ambient_authority()).unwrap();
        write_atomic(&dir, "a.json", b"one").unwrap();
        write_atomic(&dir, "a.json", b"two").unwrap();
        assert_eq!(read_bounded(&dir, "a.json", 16).unwrap(), b"two");
        assert!(!d.path().join(".a.json.tmp").exists());
    }

    #[test]
    fn read_bounded_refuses_rather_than_truncates() {
        let d = tempfile::tempdir().unwrap();
        let dir = Dir::open_ambient_dir(d.path(), ambient_authority()).unwrap();
        write_atomic(&dir, "big", &[b'x'; 100]).unwrap();
        assert!(read_bounded(&dir, "big", 99).is_err());
        assert_eq!(read_bounded(&dir, "big", 100).unwrap().len(), 100);
    }

    #[test]
    fn capability_dir_cannot_be_escaped_with_dotdot_or_absolute_paths() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("secret"), b"s").unwrap();
        std::fs::create_dir(d.path().join("jail")).unwrap();
        let jail = Dir::open_ambient_dir(d.path().join("jail"), ambient_authority()).unwrap();
        assert!(jail.read("../secret").is_err(), "`..` must not escape the capability");
        let abs = d.path().join("secret");
        assert!(jail.read(abs.to_str().unwrap()).is_err(), "absolute paths must not escape");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(d.path().join("secret"), d.path().join("jail/link")).unwrap();
            assert!(jail.read("link").is_err(), "a symlink pointing outside must not be followed");
        }
    }
}

impl Layout {
    pub fn image_store(&self) -> Result<super::images::ImageStore> {
        Ok(super::images::ImageStore::new(self.images.try_clone()?))
    }
    pub fn snapshot_store(&self) -> Result<crate::storage::snapshots::SnapshotStore> {
        Ok(crate::storage::snapshots::SnapshotStore::new(self.snapshots.try_clone()?))
    }
    pub fn artifact_store(&self) -> Result<super::artifacts::ArtifactStore> {
        Ok(super::artifacts::ArtifactStore::new(self.artifacts.try_clone()?))
    }
}
