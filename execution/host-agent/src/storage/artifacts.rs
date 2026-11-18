//! Artifact store for captured execution output (contract §18.4, OU-4): content-addressed-by-digest, id-addressed-by-ref.
//!
//! Output bytes never travel through the journal. They are written here — content first, then
//! `meta.json` — so an artifact is *visible* only once complete; a crash leaves a directory
//! without `meta.json`, which readers treat as nonexistent.

use cap_std::fs::{Dir, DirBuilder, DirBuilderExt};
use sha2::{Digest, Sha256};

use super::layout::{fsync_dir, read_bounded, write_atomic};
use crate::{
    domain::{ArtifactKind, ArtifactRef, digest_label},
    error::{AcfError, Result},
    ids::{ArtifactId, OperationId, RunId, SandboxId},
};

const MAX_META_BYTES: u64 = 16 * 1024;

#[derive(Debug, Clone)]
pub struct ArtifactContext {
    pub operation_id: OperationId,
    pub sandbox_id: SandboxId,
    pub run_id: Option<RunId>,
}

#[derive(Debug)]
pub struct ArtifactStore {
    dir: Dir,
}

impl ArtifactStore {
    pub(crate) fn new(dir: Dir) -> Self {
        Self { dir }
    }

    pub fn put(&self, kind: ArtifactKind, logical_name: &str, bytes: &[u8], ctx: &ArtifactContext) -> Result<ArtifactRef> {
        let id = ArtifactId::generate();
        let mut b = DirBuilder::new();
        b.mode(0o700);
        self.dir.create_dir_with(id.as_str(), &b)?;
        let adir = self.dir.open_dir(id.as_str())?;
        write_atomic(&adir, "content", bytes)?;
        let r = ArtifactRef {
            artifact_id: id,
            kind,
            logical_name: logical_name.to_owned(),
            schema_version: 1,
            content_digest: Some(digest_label(&hex::encode(Sha256::digest(bytes)))),
            byte_size: Some(bytes.len() as u64),
            source_operation_id: ctx.operation_id.clone(),
            sandbox_id: ctx.sandbox_id.clone(),
            run_id: ctx.run_id.clone(),
        };
        // meta.json last: its presence is the commit point.
        write_atomic(&adir, "meta.json", &serde_json::to_vec(&r)?)?;
        fsync_dir(&self.dir)?;
        Ok(r)
    }

    /// Read and **verify** an artifact against the digest in its own metadata.
    pub fn get(&self, id: &ArtifactId, max_bytes: u64) -> Result<(ArtifactRef, Vec<u8>)> {
        let adir = self.dir.open_dir(id.as_str()).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound { AcfError::not_found(format!("artifact {id} not found")) } else { e.into() }
        })?;
        let meta: ArtifactRef = serde_json::from_slice(
            &read_bounded(&adir, "meta.json", MAX_META_BYTES).map_err(|_| AcfError::not_found(format!("artifact {id} is incomplete")))?,
        )?;
        let bytes = read_bounded(&adir, "content", max_bytes)?;
        let want = meta.content_digest.clone().unwrap_or_default();
        if digest_label(&hex::encode(Sha256::digest(&bytes))) != want {
            return Err(AcfError::corrupt(format!("artifact {id} content does not match its recorded digest")));
        }
        Ok((meta, bytes))
    }

    /// Remove a stored artifact (output retention, OU-4). The directory name is a validated id, so
    /// nothing outside the store can be named. Idempotent.
    pub fn remove(&self, id: &ArtifactId) -> Result<()> {
        match self.dir.remove_dir_all(id.as_str()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std::ambient_authority;

    fn store() -> (tempfile::TempDir, ArtifactStore) {
        let d = tempfile::tempdir().unwrap();
        let s = ArtifactStore::new(Dir::open_ambient_dir(d.path(), ambient_authority()).unwrap());
        (d, s)
    }

    fn ctx() -> ArtifactContext {
        ArtifactContext { operation_id: OperationId::parse("op-12345678").unwrap(), sandbox_id: SandboxId::generate(), run_id: None }
    }

    #[test]
    fn roundtrip_verifies_digest() {
        let (_d, s) = store();
        let r = s.put(ArtifactKind::Stdout, "stdout", b"hello", &ctx()).unwrap();
        assert_eq!(r.byte_size, Some(5));
        let (meta, bytes) = s.get(&r.artifact_id, 1024).unwrap();
        assert_eq!((meta.kind, bytes.as_slice()), (ArtifactKind::Stdout, &b"hello"[..]));
    }

    #[test]
    fn removal_is_idempotent_and_leaves_other_artifacts_alone() {
        let (_d, s) = store();
        let a = s.put(ArtifactKind::Stdout, "stdout", b"a", &ctx()).unwrap();
        let b = s.put(ArtifactKind::Stderr, "stderr", b"b", &ctx()).unwrap();
        s.remove(&a.artifact_id).unwrap();
        s.remove(&a.artifact_id).unwrap();
        assert_eq!(s.get(&a.artifact_id, 16).unwrap_err().class, crate::error::FailureClass::NotFound);
        assert!(s.get(&b.artifact_id, 16).is_ok());
    }

    #[test]
    fn tampered_content_is_detected() {
        let (d, s) = store();
        let r = s.put(ArtifactKind::Stdout, "stdout", b"hello", &ctx()).unwrap();
        std::fs::write(d.path().join(r.artifact_id.as_str()).join("content"), b"HELLO").unwrap();
        assert_eq!(s.get(&r.artifact_id, 1024).unwrap_err().class, crate::error::FailureClass::IntegrityFailure);
    }

    #[test]
    fn artifact_without_meta_is_invisible() {
        let (d, s) = store();
        let r = s.put(ArtifactKind::Evidence, "e", b"{}", &ctx()).unwrap();
        std::fs::remove_file(d.path().join(r.artifact_id.as_str()).join("meta.json")).unwrap();
        assert_eq!(s.get(&r.artifact_id, 1024).unwrap_err().class, crate::error::FailureClass::NotFound);
        assert_eq!(s.get(&ArtifactId::generate(), 1024).unwrap_err().class, crate::error::FailureClass::NotFound);
    }
}
