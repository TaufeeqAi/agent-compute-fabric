//! On-disk snapshot store: `snapshots/<snp>/<gen>/{manifest.json, vmstate, mem, disk}`.

use cap_std::fs::{Dir, DirBuilder, DirBuilderExt};

use super::manifest::SnapshotManifest;
use crate::{
    backend::SnapshotArtifacts,
    error::{AcfError, Result},
    ids::{Generation, SnapshotId},
    storage::{
        hashcopy::hash_reader,
        layout::{fsync_dir, read_bounded, write_atomic},
    },
};

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
pub const MANIFEST_FILE: &str = "manifest.json";

#[derive(Debug)]
pub struct SnapshotStore {
    root: Dir,
}

impl SnapshotStore {
    pub(crate) fn new(root: Dir) -> Self {
        Self { root }
    }

    /// Create the (new, empty) directory for one snapshot generation. Refuses to reuse.
    pub fn create(&self, id: &SnapshotId, generation: Generation) -> Result<Dir> {
        let mut b = DirBuilder::new();
        b.mode(0o700);
        match self.root.create_dir_with(id.as_str(), &b) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        let parent = self.root.open_dir(id.as_str())?;
        parent.create_dir_with(generation.to_string(), &b).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                AcfError::conflict(format!("snapshot directory {id}/{generation} already exists; snapshot generations are never reused"))
            } else {
                e.into()
            }
        })?;
        Ok(parent.open_dir(generation.to_string())?)
    }

    pub fn open(&self, id: &SnapshotId, generation: Generation) -> Result<Option<Dir>> {
        let parent = match self.root.open_dir(id.as_str()) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        match parent.open_dir(generation.to_string()) {
            Ok(d) => Ok(Some(d)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Persist the manifest atomically and return `sha256(bytes written)` — the value the
    /// journal will hold as the root of trust.
    pub fn write_manifest(&self, dir: &Dir, m: &SnapshotManifest) -> Result<(String, u64)> {
        let bytes = serde_json::to_vec_pretty(m)?;
        write_atomic(dir, MANIFEST_FILE, &bytes)?;
        fsync_dir(dir)?;
        Ok((hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&bytes)), bytes.len() as u64))
    }

    /// Read the manifest and require its bytes to hash to `expected_digest` (from the journal).
    pub fn read_verified_manifest(&self, dir: &Dir, expected_digest: &str) -> Result<SnapshotManifest> {
        let bytes = read_bounded(dir, MANIFEST_FILE, MAX_MANIFEST_BYTES)?;
        let got = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&bytes));
        if got != expected_digest {
            return Err(AcfError::corrupt(format!("snapshot manifest hashes to {got}, but the journal recorded {expected_digest}")));
        }
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Re-hash every artifact from disk (post-write verification: state `VERIFYING` of contract §12.3).
    /// A guest's memory is as large as the guest, so this is disk-bound work (see
    /// [`crate::durability::blocking`]).
    pub fn verify_artifacts(&self, dir: &Dir, a: &SnapshotArtifacts) -> Result<u64> {
        crate::durability::blocking(|| {
            let mut total = 0;
            for f in [&a.vmstate, &a.mem, &a.disk] {
                let mut r = dir.open(&f.name)?.into_std();
                let c = hash_reader(&mut r, f.bytes.saturating_add(1))?;
                if c.bytes != f.bytes || c.sha256 != f.sha256 {
                    return Err(AcfError::corrupt(format!("snapshot artifact `{}` does not match its recorded digest/size", f.name)));
                }
                total += c.bytes;
            }
            Ok(total)
        })
    }

    /// Remove one snapshot generation (and the per-snapshot directory if now empty).
    pub fn remove(&self, id: &SnapshotId, generation: Generation) -> Result<()> {
        let parent = match self.root.open_dir(id.as_str()) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        match parent.remove_dir_all(generation.to_string()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let _ = self.root.remove_dir(id.as_str());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{super::manifest::test_support::manifest, *};
    use crate::{backend::FileDigest, storage::Layout};
    use sha2::{Digest, Sha256};
    use std::io::Write;

    fn store() -> (tempfile::TempDir, SnapshotStore) {
        let d = tempfile::tempdir().unwrap();
        let l = Layout::open(&d.path().join("acf")).unwrap();
        let s = SnapshotStore::new(l.snapshots.try_clone().unwrap());
        (d, s)
    }

    fn put(dir: &Dir, name: &str, bytes: &[u8]) -> FileDigest {
        let mut f = dir.create(name).unwrap().into_std();
        f.write_all(bytes).unwrap();
        FileDigest { name: name.into(), bytes: bytes.len() as u64, sha256: hex::encode(Sha256::digest(bytes)) }
    }

    #[test]
    fn manifest_is_bound_to_the_journal_digest() {
        let (_d, s) = store();
        let m = manifest();
        let dir = s.create(&m.snapshot_id, m.snapshot_generation).unwrap();
        let (digest, _) = s.write_manifest(&dir, &m).unwrap();
        assert_eq!(s.read_verified_manifest(&dir, &digest).unwrap(), m);
        // An attacker (or bit-rot) rewrites the manifest on disk: its hash no longer matches the
        // digest the journal holds, so it must not be believed.
        let tampered = serde_json::to_vec_pretty(&{
            let mut t = m.clone();
            t.baseline_state_digest = "c".repeat(64);
            t
        })
        .unwrap();
        crate::storage::layout::write_atomic(&dir, MANIFEST_FILE, &tampered).unwrap();
        assert_eq!(s.read_verified_manifest(&dir, &digest).unwrap_err().class, crate::error::FailureClass::IntegrityFailure);
    }

    #[test]
    fn artifacts_are_reverified_from_disk() {
        let (_d, s) = store();
        let (id, g) = (SnapshotId::generate(), Generation::FIRST);
        let dir = s.create(&id, g).unwrap();
        let a = SnapshotArtifacts {
            vmstate: put(&dir, "vmstate", b"state"),
            mem: put(&dir, "mem", b"memory!"),
            disk: put(&dir, "disk", b"diskdisk"),
            vmm_version: "1.17.0".into(),
        };
        assert_eq!(s.verify_artifacts(&dir, &a).unwrap(), 5 + 7 + 8);
        // flip one byte in `mem`
        let mut f = dir.open_with("mem", cap_std::fs::OpenOptions::new().write(true)).unwrap().into_std();
        f.write_all(b"M").unwrap();
        drop(f);
        assert!(s.verify_artifacts(&dir, &a).is_err());
    }

    #[test]
    fn generations_are_never_reused_and_remove_is_idempotent() {
        let (_d, s) = store();
        let (id, g) = (SnapshotId::generate(), Generation::FIRST);
        s.create(&id, g).unwrap();
        assert_eq!(s.create(&id, g).unwrap_err().class, crate::error::FailureClass::StateConflict);
        assert!(s.open(&id, g).unwrap().is_some());
        s.remove(&id, g).unwrap();
        s.remove(&id, g).unwrap();
        assert!(s.open(&id, g).unwrap().is_none());
    }
}
