//! Snapshot manager (contract §21.3–§21.6): manifest, compatibility gate, store.
//!
//! **Exact-object binding.** The journal records `sha256(manifest bytes)`; the manifest records
//! the digest of each artifact. A restore therefore trusts nothing it has not re-hashed:
//! journal → manifest (hash must match) → artifacts (hash must match, verified *while copying*).

pub mod manifest;
pub mod store;

pub use manifest::{HostFingerprint, MANIFEST_SCHEMA_VERSION, SnapshotManifest, check_compat};
pub use store::SnapshotStore;
