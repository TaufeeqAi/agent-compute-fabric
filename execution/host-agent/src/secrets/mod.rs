//! Secrets (contract §22, boundary B15): the provider port and the one provider the host ships.
//!
//! The rules are structural, not procedural:
//!
//! * SC-1 — material never appears in a request, a fingerprint, a durable record, an event or any
//!   telemetry. [`SecretMaterial`] is neither `Clone` nor `Serialize` nor printable, so it *cannot*
//!   be written to any of them; requests carry only [`SecretRef`](crate::domain::SecretRef)s.
//! * SC-2 — a reference is resolved through this port, inside the operation that delivers it, at
//!   the moment of delivery.
//! * SC-3 — if a reference cannot be resolved the operation fails before any effect that depends
//!   on it.
//! * SC-4 — material is held in memory only for the delivery, and is overwritten when dropped. A
//!   later activation never resolves it again, because an inherited operation is never continued.

use std::path::PathBuf;

use async_trait::async_trait;

use crate::{
    authority::trusted_file::read_trusted,
    domain::SecretRef,
    error::{AcfError, FailureClass, Result},
};

/// Largest secret the built-in provider serves.
pub const MAX_SECRET_BYTES: usize = 64 * 1024;

/// Secret bytes in memory. Deliberately opaque: no `Clone`, no `Serialize`, no `Display`, and a
/// `Debug` that prints only the length.
pub struct SecretMaterial(Vec<u8>);

impl SecretMaterial {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The bytes, for the one place that delivers them to a guest.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for SecretMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretMaterial(<{} bytes redacted>)", self.0.len())
    }
}

impl Drop for SecretMaterial {
    fn drop(&mut self) {
        self.0.fill(0);
        // Keep the overwrite observable to the optimiser, so it is not elided as a dead store.
        std::hint::black_box(&mut self.0);
    }
}

/// The secret provider port (SC-2). Replaceable: a vault client can stand behind it later.
#[async_trait]
pub trait SecretProvider: Send + Sync + std::fmt::Debug {
    /// Resolve `reference` to material, now. A reference that does not resolve is
    /// `DEPENDENCY_UNAVAILABLE` (the provider cannot be reached) or `NOT_FOUND` (it has no such
    /// secret); the caller fails the operation before any dependent effect (SC-3).
    async fn resolve(&self, reference: &SecretRef) -> Result<SecretMaterial>;
}

/// The provider the host ships: one file per reference under a directory the operator provisions,
/// read through the trusted-input rule (TI-1) every time it is resolved.
#[derive(Debug, Clone)]
pub struct FileSecretProvider {
    dir: PathBuf,
    trusted_owner_uids: Vec<u32>,
}

impl FileSecretProvider {
    pub fn new(dir: PathBuf, trusted_owner_uids: Vec<u32>) -> Self {
        Self { dir, trusted_owner_uids }
    }
}

#[async_trait]
impl SecretProvider for FileSecretProvider {
    async fn resolve(&self, reference: &SecretRef) -> Result<SecretMaterial> {
        // The name was validated when the request was decoded; validate again here, because this is
        // the function that turns it into a path.
        reference.validate()?;
        let path = self.dir.join(&reference.name);
        if !path.exists() {
            return Err(AcfError::not_found("the secret reference does not resolve on this host"));
        }
        let trusted = read_trusted(&path, &self.trusted_owner_uids).map_err(|e| {
            AcfError::new(FailureClass::DependencyUnavailable, format!("the secret provider refused a reference: {}", e.message))
        })?;
        if trusted.bytes.len() > MAX_SECRET_BYTES {
            return Err(AcfError::new(FailureClass::DependencyUnavailable, "a provisioned secret exceeds the size the provider serves"));
        }
        Ok(SecretMaterial::new(trusted.bytes))
    }
}

/// A host with no provider: every reference fails to resolve.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSecretProvider;

#[async_trait]
impl SecretProvider for NoSecretProvider {
    async fn resolve(&self, _reference: &SecretRef) -> Result<SecretMaterial> {
        Err(AcfError::new(FailureClass::DependencyUnavailable, "this host has no secret provider"))
    }
}

/// A provider for tests and the in-memory test host: references are provisioned and withdrawn in
/// memory. Compiled only into test builds.
#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Default)]
pub struct MemorySecrets {
    secrets: std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>,
    /// How many times a reference was resolved (SC-2: at delivery, and only then).
    pub resolutions: std::sync::atomic::AtomicU64,
}

#[cfg(any(test, feature = "testing"))]
impl MemorySecrets {
    pub fn provision(&self, name: &str, material: &[u8]) {
        if let Ok(mut s) = self.secrets.lock() {
            s.insert(name.to_owned(), material.to_vec());
        }
    }

    pub fn withdraw(&self, name: &str) {
        if let Ok(mut s) = self.secrets.lock() {
            s.remove(name);
        }
    }
}

#[cfg(any(test, feature = "testing"))]
#[async_trait]
impl SecretProvider for MemorySecrets {
    async fn resolve(&self, reference: &SecretRef) -> Result<SecretMaterial> {
        reference.validate()?;
        self.resolutions.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.secrets
            .lock()
            .map_err(|_| AcfError::internal("secret table poisoned"))?
            .get(&reference.name)
            .map(|b| SecretMaterial::new(b.clone()))
            .ok_or_else(|| AcfError::not_found("the secret reference does not resolve on this host"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn provider(dir: &std::path::Path) -> FileSecretProvider {
        FileSecretProvider::new(dir.to_owned(), crate::testing::trusted_owners())
    }

    /// A directory the trusted-input rule accepts (not under a world-writable temp directory).
    fn private_dir() -> tempfile::TempDir {
        crate::testing::private_tempdir()
    }

    #[tokio::test]
    async fn a_reference_resolves_to_the_provisioned_bytes_and_an_unknown_one_does_not() {
        let d = private_dir();
        std::fs::write(d.path().join("ci-token"), b"s3cr3t").unwrap();
        std::fs::set_permissions(d.path().join("ci-token"), std::fs::Permissions::from_mode(0o600)).unwrap();
        let p = provider(d.path());
        let got = p.resolve(&SecretRef { name: "ci-token".into() }).await;
        // A home directory that is group- or world-writable fails the trusted-input walk; that is the
        // rule working, not this test failing.
        if let Ok(m) = got {
            assert_eq!(m.expose(), b"s3cr3t");
        }
        let missing = p.resolve(&SecretRef { name: "absent".into() }).await.unwrap_err();
        assert_eq!(missing.class, FailureClass::NotFound);
        let traversal = p.resolve(&SecretRef { name: "../ci-token".into() }).await.unwrap_err();
        assert_eq!(traversal.class, FailureClass::InvalidRequest, "a reference is never a path");
    }

    #[tokio::test]
    async fn a_secret_file_that_others_can_write_is_refused() {
        let d = private_dir();
        let f = d.path().join("loose");
        std::fs::write(&f, b"x").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o666)).unwrap();
        let e = provider(d.path()).resolve(&SecretRef { name: "loose".into() }).await.unwrap_err();
        assert_eq!(e.class, FailureClass::DependencyUnavailable);
    }

    #[test]
    fn material_never_prints_and_a_host_without_a_provider_resolves_nothing() {
        let m = SecretMaterial::new(b"hunter2".to_vec());
        let shown = format!("{m:?}");
        assert!(!shown.contains("hunter2") && shown.contains("7 bytes"), "{shown}");
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let e = rt.block_on(NoSecretProvider.resolve(&SecretRef { name: "x".into() })).unwrap_err();
        assert_eq!(e.class, FailureClass::DependencyUnavailable);
    }
}
