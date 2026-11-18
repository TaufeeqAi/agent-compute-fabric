//! Logical, immutable identities (contract §8, IM-1, SNP-1).
//!
//! A raw host path is an implementation detail, never a portable identity: refs name *what*
//! something is (digests, ids), and the filesystem manager maps them to paths privately.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{ArtifactId, Generation, OperationId, RunId, SandboxId, SnapshotId};

/// Immutable execution identity. The alias is a *mutable human label* and is never sufficient
/// on its own (contract IM-1): `image_id` is the digest of the image manifest.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ImageRef {
    /// `sha256:<hex>` of the canonical image manifest.
    pub image_id: String,
    pub alias: Option<String>,
    pub architecture: String,
    /// `sha256:<hex>` of the kernel file's bytes.
    pub kernel_identity: String,
    /// `sha256:<hex>` of the rootfs file's bytes.
    pub rootfs_identity: String,
    pub manifest_version: u32,
    pub provenance_reference: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotRef {
    pub snapshot_id: SnapshotId,
    pub snapshot_generation: Generation,
}

impl std::fmt::Display for SnapshotRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.snapshot_id, self.snapshot_generation)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Stdout,
    Stderr,
    Evidence,
    SnapshotVmstate,
    SnapshotMemory,
    SnapshotDisk,
    SnapshotManifest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactRef {
    pub artifact_id: ArtifactId,
    pub kind: ArtifactKind,
    pub logical_name: String,
    pub schema_version: u32,
    /// `sha256:<hex>`; present once the artifact is materialised.
    pub content_digest: Option<String>,
    pub byte_size: Option<u64>,
    pub source_operation_id: OperationId,
    pub sandbox_id: SandboxId,
    pub run_id: Option<RunId>,
}

/// Format a raw sha256 hex digest the way every ref in this system spells it.
pub fn digest_label(hex: &str) -> String {
    format!("sha256:{hex}")
}
