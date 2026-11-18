//! Per-generation host directories, ownership markers and *proven-ownership* cleanup
//! (contract ST-2, RC-2).
//!
//! The danger being defended: cleanup that deletes a path because some record says so. Here the
//! path is **derived from validated ids**, the directory must be a real directory (not a symlink),
//! and an `OWNER.json` marker inside it must carry the same random nonce the journal holds. If any
//! check fails the directory is **quarantined (left in place), never deleted**.

use cap_std::fs::Dir;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::layout::{Layout, read_bounded, write_atomic};
use crate::{
    error::{AcfError, Result},
    ids::{Generation, OperationId, SandboxId},
};

const OWNER_FILE: &str = "OWNER.json";
/// Markers written by this version. Schema 1 markers (no lineage) are still read: their nonce is the
/// ownership proof, and they predate lineage tracking.
pub const OWNER_MARKER_SCHEMA_VERSION: u32 = 2;
const MAX_OWNER_BYTES: u64 = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerMarker {
    pub schema_version: u32,
    pub sandbox_id: SandboxId,
    pub generation: Generation,
    pub nonce: String,
    pub created_by: OperationId,
    pub host_instance_id: String,
    /// Lineage of the store that recorded this generation (LN-1). A marker of another lineage, or
    /// a resource with no valid marker, is `UNMANAGED` (LN-3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lineage: Option<String>,
    /// Commit sequence at which the generation was created. A marker of this lineage with a
    /// sequence beyond the store's last one means the store is older than the system (LN-2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_seq: Option<u64>,
}

/// 128 bits from the kernel CSPRNG, hex-encoded: the host-generated half of the ownership proof (RC-1).
pub fn new_nonce() -> Result<String> {
    crate::ids::random_token()
}

#[derive(Debug)]
pub struct GenerationDir {
    dir: Dir,
}

impl GenerationDir {
    /// Create `sandboxes/<sbx>/<gen>/` (0700) with its OWNER marker and an empty `jail/`.
    /// Fails with `STATE_CONFLICT` if the generation directory already exists: a generation is
    /// never reused (contract ID-1).
    pub fn create(layout: &Layout, marker: &OwnerMarker) -> Result<Self> {
        use cap_std::fs::{DirBuilder, DirBuilderExt};
        let mut b = DirBuilder::new();
        b.mode(0o700);
        let sbx = marker.sandbox_id.as_str();
        match layout.sandboxes.create_dir_with(sbx, &b) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        let sbx_dir = layout.sandboxes.open_dir(sbx)?;
        let gen_name = marker.generation.to_string();
        sbx_dir.create_dir_with(&gen_name, &b).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                AcfError::conflict(format!("generation directory {}/{} already exists; generations are never reused", sbx, gen_name))
            } else {
                AcfError::from(e)
            }
        })?;
        let dir = sbx_dir.open_dir(&gen_name)?;
        write_atomic(&dir, OWNER_FILE, &serde_json::to_vec_pretty(marker)?)?;
        dir.create_dir_with("jail", &b)?;
        Ok(Self { dir })
    }

    pub fn open(layout: &Layout, sbx: &SandboxId, generation: Generation) -> Result<Option<Self>> {
        let sbx_dir = match layout.sandboxes.open_dir(sbx.as_str()) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        match sbx_dir.open_dir(generation.to_string()) {
            Ok(dir) => Ok(Some(Self { dir })),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn read_marker(&self) -> Result<OwnerMarker> {
        Ok(serde_json::from_slice(&read_bounded(&self.dir, OWNER_FILE, MAX_OWNER_BYTES)?)?)
    }

    pub fn dir(&self) -> &Dir {
        &self.dir
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanupOutcome {
    Removed,
    /// Nothing there — cleanup is idempotent.
    Absent,
    /// Ownership could not be proven. The directory was left untouched.
    Quarantine {
        reason: String,
    },
}

/// Remove a generation directory **only if** its on-disk marker proves it is ours.
pub fn remove_generation(layout: &Layout, sbx: &SandboxId, generation: Generation, expected_nonce: &str) -> Result<CleanupOutcome> {
    let sbx_dir = match layout.sandboxes.open_dir(sbx.as_str()) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(CleanupOutcome::Absent),
        Err(e) => return Err(e.into()),
    };
    let name = generation.to_string();
    let md = match sbx_dir.symlink_metadata(&name) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(CleanupOutcome::Absent),
        Err(e) => return Err(e.into()),
    };
    if md.file_type().is_symlink() || !md.is_dir() {
        return Ok(CleanupOutcome::Quarantine { reason: "generation path is not a plain directory (symlink or file)".into() });
    }
    let gdir = GenerationDir { dir: sbx_dir.open_dir(&name)? };
    let marker = match gdir.read_marker() {
        Ok(m) => m,
        Err(e) => return Ok(CleanupOutcome::Quarantine { reason: format!("ownership marker unreadable: {}", e.message) }),
    };
    if marker.sandbox_id != *sbx || marker.generation != generation {
        return Ok(CleanupOutcome::Quarantine { reason: "ownership marker names a different sandbox/generation".into() });
    }
    if marker.nonce != expected_nonce {
        return Ok(CleanupOutcome::Quarantine { reason: "ownership nonce does not match the journal".into() });
    }
    drop(gdir);
    sbx_dir.remove_dir_all(&name)?;
    // Best effort: drop the now-empty per-sandbox directory.
    let _ = layout.sandboxes.remove_dir(sbx.as_str());
    Ok(CleanupOutcome::Removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker(sbx: &SandboxId, g: u64, nonce: &str) -> OwnerMarker {
        OwnerMarker {
            schema_version: 1,
            sandbox_id: sbx.clone(),
            generation: Generation(g),
            nonce: nonce.into(),
            created_by: OperationId::parse("op-12345678").unwrap(),
            host_instance_id: "inst".into(),
            lineage: None,
            created_seq: None,
        }
    }

    #[test]
    fn a_marker_records_lineage_and_creation_sequence_and_an_older_marker_is_still_readable() {
        let (_d, l) = layout();
        let sbx = SandboxId::generate();
        let mut m = marker(&sbx, 1, "nonce");
        m.schema_version = OWNER_MARKER_SCHEMA_VERSION;
        m.lineage = Some("f".repeat(32));
        m.created_seq = Some(41);
        let dir = GenerationDir::create(&l, &m).unwrap();
        assert_eq!(dir.read_marker().unwrap(), m);
        // A marker written before lineage existed has neither field.
        let legacy = serde_json::to_value(marker(&sbx, 2, "n2")).unwrap();
        assert!(legacy.get("lineage").is_none() && legacy.get("created_seq").is_none());
        let parsed: OwnerMarker = serde_json::from_value(legacy).unwrap();
        assert_eq!((parsed.lineage, parsed.created_seq), (None, None));
    }

    fn layout() -> (tempfile::TempDir, Layout) {
        let d = tempfile::tempdir().unwrap();
        let l = Layout::open(&d.path().join("acf")).unwrap();
        (d, l)
    }

    #[test]
    fn create_writes_marker_and_refuses_reuse() {
        let (_d, l) = layout();
        let sbx = SandboxId::generate();
        let g = GenerationDir::create(&l, &marker(&sbx, 1, "n1")).unwrap();
        assert_eq!(g.read_marker().unwrap().nonce, "n1");
        assert!(l.generation_path(&sbx, Generation(1)).join("jail").is_dir());
        let again = GenerationDir::create(&l, &marker(&sbx, 1, "n2")).unwrap_err();
        assert_eq!(again.class, crate::error::FailureClass::StateConflict);
        assert!(GenerationDir::create(&l, &marker(&sbx, 2, "n3")).is_ok(), "next generation is fine");
    }

    #[test]
    fn cleanup_removes_only_with_matching_nonce_and_is_idempotent() {
        let (_d, l) = layout();
        let sbx = SandboxId::generate();
        GenerationDir::create(&l, &marker(&sbx, 1, "right")).unwrap();
        std::fs::write(l.generation_path(&sbx, Generation(1)).join("jail/artifact"), b"x").unwrap();

        let wrong = remove_generation(&l, &sbx, Generation(1), "wrong").unwrap();
        assert!(matches!(wrong, CleanupOutcome::Quarantine { .. }), "{wrong:?}");
        assert!(l.generation_path(&sbx, Generation(1)).exists(), "must NOT delete on a nonce mismatch");

        assert_eq!(remove_generation(&l, &sbx, Generation(1), "right").unwrap(), CleanupOutcome::Removed);
        assert!(!l.generation_path(&sbx, Generation(1)).exists());
        assert_eq!(remove_generation(&l, &sbx, Generation(1), "right").unwrap(), CleanupOutcome::Absent);
    }

    #[test]
    fn cleanup_refuses_a_symlinked_generation_and_never_follows_it() {
        let (d, l) = layout();
        let sbx = SandboxId::generate();
        let victim = d.path().join("victim");
        std::fs::create_dir(&victim).unwrap();
        std::fs::write(victim.join("precious"), b"keep me").unwrap();
        std::fs::create_dir_all(l.generation_path(&sbx, Generation(1)).parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&victim, l.generation_path(&sbx, Generation(1))).unwrap();

        let out = remove_generation(&l, &sbx, Generation(1), "anything").unwrap();
        assert!(matches!(out, CleanupOutcome::Quarantine { .. }), "{out:?}");
        assert!(victim.join("precious").exists(), "ST-2: the symlink target must survive");
    }

    #[test]
    fn marker_naming_another_generation_is_not_trusted() {
        let (_d, l) = layout();
        let sbx = SandboxId::generate();
        GenerationDir::create(&l, &marker(&sbx, 1, "n")).unwrap();
        // forge: gen 2 directory containing gen 1's marker
        let g2 = l.generation_path(&sbx, Generation(2));
        std::fs::create_dir_all(&g2).unwrap();
        std::fs::copy(l.generation_path(&sbx, Generation(1)).join("OWNER.json"), g2.join("OWNER.json")).unwrap();
        assert!(matches!(remove_generation(&l, &sbx, Generation(2), "n").unwrap(), CleanupOutcome::Quarantine { .. }));
        assert!(g2.exists());
    }

    #[test]
    fn missing_marker_means_quarantine_not_delete() {
        let (_d, l) = layout();
        let sbx = SandboxId::generate();
        std::fs::create_dir_all(l.generation_path(&sbx, Generation(1))).unwrap();
        assert!(matches!(remove_generation(&l, &sbx, Generation(1), "n").unwrap(), CleanupOutcome::Quarantine { .. }));
    }
}
