//! BND-06 — Filesystem manager: confinement, image store, hashed copies, generation directories
//! with ownership markers, and the artifact store (spec §19).
//!
//! **Rule:** persisted records never supply a path. Paths are *derived* here from validated typed
//! ids ([`crate::ids`]), whose charset makes `..`, `/` and NUL unrepresentable, and every access
//! goes through a `cap-std` directory capability that the kernel prevents from escaping.

pub mod artifacts;
pub mod generation;
pub mod hashcopy;
pub mod images;
pub mod layout;

pub use artifacts::ArtifactStore;
pub use generation::{CleanupOutcome, GenerationDir};
pub use images::{ImageManifest, ImageStore, ResolvedImage};
pub use layout::Layout;
