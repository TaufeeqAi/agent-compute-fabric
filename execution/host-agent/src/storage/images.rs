//! Image store and manifest (contract §21.2).
//!
//! An image is a directory `images/<alias>/` holding `manifest.json`, a kernel and a rootfs.
//! The *alias* is a mutable human label; the **identity** is `image_id = sha256(manifest bytes)`,
//! and the manifest binds the exact kernel and rootfs digests. Images are installed by the
//! operator (`scripts/build-image.sh`); the host agent only reads them.

use std::fs::File;

use cap_std::fs::Dir;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::layout::read_bounded;
use crate::{
    domain::{ImageRef, digest_label},
    error::{AcfError, FailureClass, Result},
    ids::validate_alias,
};

pub const IMAGE_MANIFEST_VERSION: u32 = 1;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    pub file: String,
    /// Lowercase hex sha256.
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImageManifest {
    pub schema_version: u32,
    pub name: String,
    pub architecture: String,
    pub kernel: FileEntry,
    pub rootfs: FileEntry,
    /// Overrides the host default boot args. Part of the image identity.
    pub boot_args: Option<String>,
    pub guest_agent_version: String,
    pub provenance: Option<String>,
}

fn plain_file_name(n: &str) -> bool {
    (1..=64).contains(&n.len()) && !n.starts_with('.') && n.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl ImageManifest {
    fn validate(&self, alias: &str) -> Result<()> {
        if self.schema_version != IMAGE_MANIFEST_VERSION {
            return Err(AcfError::new(
                FailureClass::IncompatibleRuntime,
                format!("image manifest version {} unsupported", self.schema_version),
            ));
        }
        if self.name != alias {
            return Err(AcfError::corrupt(format!("manifest name `{}` does not match directory `{alias}`", self.name)));
        }
        if self.architecture != std::env::consts::ARCH {
            return Err(AcfError::new(
                FailureClass::IncompatibleRuntime,
                format!("image architecture `{}` does not match host `{}`", self.architecture, std::env::consts::ARCH),
            ));
        }
        for (what, e) in [("kernel", &self.kernel), ("rootfs", &self.rootfs)] {
            if !plain_file_name(&e.file) {
                return Err(AcfError::corrupt(format!("{what} file name `{}` is not a plain file name", e.file)));
            }
            if !is_sha256_hex(&e.sha256) || e.size == 0 {
                return Err(AcfError::corrupt(format!("{what} entry has an invalid digest or size")));
            }
        }
        if self.kernel.file == self.rootfs.file {
            return Err(AcfError::corrupt("kernel and rootfs must be distinct files"));
        }
        if let Some(a) = &self.boot_args
            && (a.len() > 2048 || a.contains('\0') || a.contains('\n'))
        {
            return Err(AcfError::corrupt("boot_args is too long or contains control characters"));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct ImageStore {
    dir: Dir,
}

/// A manifest-verified image whose files can be opened as descriptors.
#[derive(Debug)]
pub struct ResolvedImage {
    pub image_ref: ImageRef,
    pub manifest: ImageManifest,
    dir: Dir,
}

impl ImageStore {
    pub(crate) fn new(dir: Dir) -> Self {
        Self { dir }
    }

    pub fn resolve(&self, alias: &str) -> Result<ResolvedImage> {
        validate_alias(alias)?;
        let idir = self.dir.open_dir(alias).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AcfError::not_found(format!("image `{alias}` is not installed"))
            } else {
                AcfError::from(e)
            }
        })?;
        let bytes = read_bounded(&idir, "manifest.json", MAX_MANIFEST_BYTES)?;
        let manifest: ImageManifest = serde_json::from_slice(&bytes)?;
        manifest.validate(alias)?;
        let image_id = digest_label(&hex::encode(Sha256::digest(&bytes)));
        let image_ref = ImageRef {
            image_id,
            alias: Some(alias.to_owned()),
            architecture: manifest.architecture.clone(),
            kernel_identity: digest_label(&manifest.kernel.sha256),
            rootfs_identity: digest_label(&manifest.rootfs.sha256),
            manifest_version: manifest.schema_version,
            provenance_reference: manifest.provenance.clone(),
        };
        Ok(ResolvedImage { image_ref, manifest, dir: idir })
    }

    pub fn list(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for e in self.dir.entries()? {
            let e = e?;
            if let Some(n) = e.file_name().to_str()
                && validate_alias(n).is_ok()
            {
                out.push(n.to_owned());
            }
        }
        out.sort();
        Ok(out)
    }
}

impl ResolvedImage {
    /// Open the kernel for a hashed copy. The caller verifies the digest of the bytes it copies.
    pub fn open_kernel(&self) -> Result<(File, &FileEntry)> {
        Ok((self.dir.open(&self.manifest.kernel.file)?.into_std(), &self.manifest.kernel))
    }

    pub fn open_rootfs(&self) -> Result<(File, &FileEntry)> {
        Ok((self.dir.open(&self.manifest.rootfs.file)?.into_std(), &self.manifest.rootfs))
    }
}

#[cfg(any(test, feature = "testing"))]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test doubles may fail loudly; never compiled into release builds"
)]
pub mod test_support {
    use super::*;
    use cap_std::{ambient_authority, fs::Dir};

    /// Install a tiny fake image (`kernel` and `rootfs` are small byte strings).
    pub fn install(images_root: &std::path::Path, alias: &str, kernel: &[u8], rootfs: &[u8]) -> ImageStore {
        let dir = images_root.join(alias);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("vmlinux"), kernel).unwrap();
        std::fs::write(dir.join("rootfs.ext4"), rootfs).unwrap();
        let m = ImageManifest {
            schema_version: 1,
            name: alias.into(),
            architecture: std::env::consts::ARCH.into(),
            kernel: FileEntry { file: "vmlinux".into(), sha256: hex::encode(Sha256::digest(kernel)), size: kernel.len() as u64 },
            rootfs: FileEntry { file: "rootfs.ext4".into(), sha256: hex::encode(Sha256::digest(rootfs)), size: rootfs.len() as u64 },
            boot_args: None,
            guest_agent_version: "0.1.0".into(),
            provenance: Some("test".into()),
        };
        std::fs::write(dir.join("manifest.json"), serde_json::to_vec_pretty(&m).unwrap()).unwrap();
        ImageStore::new(Dir::open_ambient_dir(images_root, ambient_authority()).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_with_identity_bound_to_manifest_bytes() {
        let d = tempfile::tempdir().unwrap();
        let s = test_support::install(d.path(), "python", b"kernel-bytes", b"rootfs-bytes");
        let r = s.resolve("python").unwrap();
        assert!(r.image_ref.image_id.starts_with("sha256:"));
        assert_eq!(r.image_ref.alias.as_deref(), Some("python"));
        assert_eq!(r.image_ref.kernel_identity, format!("sha256:{}", hex::encode(Sha256::digest(b"kernel-bytes"))));
        // Editing the manifest (even whitespace) changes the image identity.
        let before = r.image_ref.image_id.clone();
        let p = d.path().join("python/manifest.json");
        let mut b = std::fs::read(&p).unwrap();
        b.push(b'\n');
        std::fs::write(&p, b).unwrap();
        assert_ne!(s.resolve("python").unwrap().image_ref.image_id, before);
        assert_eq!(s.list().unwrap(), vec!["python".to_string()]);
    }

    /// The manifest *writer* is Python (tools/write_image_manifest.py); the *reader* is this file. The
    /// golden file is what the writer emits for fixed input, byte for byte (tests/tools pins that side).
    /// This test pins the other side: whatever the writer emits, the host accepts, and the identity it
    /// computes is that of the exact bytes on disk. If either language changes the format, one of the two
    /// tests fails — before an operator finds out by installing an image the host then refuses.
    #[test]
    fn the_python_writers_golden_manifest_is_accepted() {
        use cap_std::ambient_authority;

        const GOLDEN: &str = include_str!("../../../../tests/fixtures/image-manifest.golden.json");
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("golden");
        std::fs::create_dir_all(&dir).unwrap();
        // The fixture is written for x86_64; the host (rightly) refuses an image for another architecture.
        let adapted = GOLDEN.replacen("\"architecture\": \"x86_64\"", &format!("\"architecture\": \"{}\"", std::env::consts::ARCH), 1);
        std::fs::write(dir.join("manifest.json"), &adapted).unwrap();

        let store = ImageStore::new(Dir::open_ambient_dir(d.path(), ambient_authority()).unwrap());
        let r = store.resolve("golden").unwrap();
        assert_eq!((r.manifest.name.as_str(), r.manifest.schema_version), ("golden", IMAGE_MANIFEST_VERSION));
        assert_eq!((r.manifest.kernel.file.as_str(), r.manifest.rootfs.file.as_str()), ("vmlinux", "rootfs.ext4"));
        assert_eq!((r.manifest.kernel.size, r.manifest.rootfs.size), (14, 14));
        assert_eq!(r.manifest.guest_agent_version, "0.1.0");
        assert_eq!(r.manifest.boot_args, None);
        assert!(r.manifest.provenance.as_deref().is_some_and(|p| p.starts_with("acf-image-build/1;")));
        assert_eq!(r.image_ref.image_id, format!("sha256:{}", hex::encode(Sha256::digest(adapted.as_bytes()))));
    }

    #[test]
    fn missing_mismatched_and_hostile_manifests_are_rejected() {
        let d = tempfile::tempdir().unwrap();
        let s = test_support::install(d.path(), "python", b"k", b"r");
        assert_eq!(s.resolve("nope").unwrap_err().class, FailureClass::NotFound);
        assert!(s.resolve("../etc").is_err());
        assert!(s.resolve("a/b").is_err());

        let p = d.path().join("python/manifest.json");
        let good = std::fs::read_to_string(&p).unwrap();
        for (from, to) in
            [("vmlinux\"", "../vmlinux\""), (std::env::consts::ARCH, "riscv64"), ("\"name\": \"python\"", "\"name\": \"other\"")]
        {
            std::fs::write(&p, good.replacen(from, to, 1)).unwrap();
            assert!(s.resolve("python").is_err(), "{from} -> {to}");
        }
    }
}
