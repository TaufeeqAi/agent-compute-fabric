//! Verifying the Firecracker and Jailer binaries before they are executed as root (TI-1, TI-2, IS-1).
//!
//! Three questions, in this order. Each must be answered yes before the next is asked, and before
//! the file is run for any purpose, including to ask it for its version.
//!
//! 1. **Could anyone but the trusted owner have put this file here?** The trusted-input rule (TI-1):
//!    owner and mode of the file and of every directory on the way to it.
//! 2. **Are these the bytes that were pinned?** (TI-2) The SHA-256 of the file, read from an open
//!    descriptor, equals the digest in the host configuration. A version is what a binary says about
//!    itself; a digest is what it is. A binary with no pinned digest is not run.
//! 3. **Is it the release the isolation profile and the snapshots were validated against?** The
//!    exact pinned version.
//!
//! All three are asked at startup and by `doctor` ([`verify_binaries`]). The second is asked again
//! before every launch ([`verify_pinned`]), so a file replaced while the host runs is refused instead
//! of executed. Between that hash and the `execve` the file is protected by the first rule only: the
//! path is one that nobody but the trusted owner can write.

use std::{path::Path, process::Stdio, time::Duration};

use tokio::{process::Command, time::timeout};

pub(crate) use crate::authority::trusted_file::trusted_executable;
use crate::{
    config::FirecrackerConfig,
    error::{AcfError, FailureClass, Result},
    storage::hashcopy::hash_reader,
};

/// Larger than any VMM build, small enough that hashing it cannot be turned into a stall.
const MAX_BINARY_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryReport {
    pub firecracker_version: String,
    pub jailer_version: String,
    pub firecracker_sha256: String,
    pub jailer_sha256: String,
}

/// `Firecracker v1.17.0` / `Jailer v1.17.0` → `v1.17.0`.
pub fn parse_version_line(out: &str) -> Option<String> {
    out.split_whitespace().find(|w| w.starts_with('v') && w[1..].split('.').count() == 3).map(str::to_owned)
}

async fn version_of(bin: &Path) -> Result<String> {
    let out = timeout(Duration::from_secs(5), Command::new(bin).arg("--version").stdin(Stdio::null()).output())
        .await
        .map_err(|_| AcfError::new(FailureClass::DependencyUnavailable, format!("{} --version timed out", bin.display())))?
        .map_err(|e| AcfError::new(FailureClass::DependencyUnavailable, format!("cannot run {}: {e}", bin.display())))?;
    let text = String::from_utf8_lossy(&out.stdout);
    parse_version_line(&text).ok_or_else(|| {
        AcfError::new(FailureClass::IncompatibleRuntime, format!("cannot parse a version from `{}`", text.lines().next().unwrap_or("")))
    })
}

/// TI-2 for one binary: its bytes hash to the digest pinned under `firecracker.<key>`. Returns the
/// digest. Nothing is executed, and both refusals are definite: nothing was changed.
fn pinned_bytes(key: &str, bin: &Path, pinned: Option<&str>) -> Result<String> {
    let mut file = std::fs::File::open(bin).map_err(|e| AcfError::security(format!("cannot open {}: {e}", bin.display())))?;
    let measured = hash_reader(&mut file, MAX_BINARY_BYTES)?.sha256;
    match pinned {
        Some(want) if want == measured => Ok(measured),
        Some(want) => Err(AcfError::corrupt(format!(
            "{} hashes to {measured} but firecracker.{key} pins {want}: the file is not the one that was pinned, and it is not run",
            bin.display()
        ))),
        None => Err(AcfError::security(format!(
            "{} has no pinned identity: firecracker.{key} is not set. The file hashes to {measured}; pin that value only if it is \
             the digest the installer printed for this file",
            bin.display()
        ))),
    }
}

/// TI-2 at the moment of use: both binaries still are the bytes that were pinned. Called before every
/// launch, before anything is created for it.
pub fn verify_pinned(cfg: &FirecrackerConfig) -> Result<(String, String)> {
    Ok((
        pinned_bytes("firecracker_sha256", &cfg.firecracker_bin, cfg.firecracker_sha256.as_deref())?,
        pinned_bytes("jailer_sha256", &cfg.jailer_bin, cfg.jailer_sha256.as_deref())?,
    ))
}

pub async fn verify_binaries(cfg: &FirecrackerConfig, trusted_owners: &[u32]) -> Result<BinaryReport> {
    trusted_executable(&cfg.firecracker_bin, trusted_owners)?;
    trusted_executable(&cfg.jailer_bin, trusted_owners)?;
    // Before either file is run, even for its version: what is run as root is what was pinned.
    let (firecracker_sha256, jailer_sha256) = verify_pinned(cfg)?;
    let (fv, jv) = (version_of(&cfg.firecracker_bin).await?, version_of(&cfg.jailer_bin).await?);
    for (what, v) in [("firecracker", &fv), ("jailer", &jv)] {
        if *v != cfg.pinned_version {
            return Err(AcfError::new(
                FailureClass::IncompatibleRuntime,
                format!("{what} is {v} but the profile is pinned to {}", cfg.pinned_version),
            ));
        }
    }
    Ok(BinaryReport { firecracker_version: fv, jailer_version: jv, firecracker_sha256, jailer_sha256 })
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::path::Path;

    use sha2::{Digest, Sha256};

    use crate::config::FirecrackerConfig;

    /// Pin both binaries of `cfg` to the bytes they hold now.
    pub(crate) fn pin(cfg: &mut FirecrackerConfig) {
        let digest = |p: &Path| hex::encode(Sha256::digest(std::fs::read(p).unwrap()));
        cfg.firecracker_sha256 = Some(digest(&cfg.firecracker_bin));
        cfg.jailer_sha256 = Some(digest(&cfg.jailer_bin));
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::{
        config::test_support::config,
        testing::{private_tempdir, trusted_owners},
    };

    #[test]
    fn version_parsing() {
        assert_eq!(parse_version_line("Firecracker v1.17.0\n"), Some("v1.17.0".into()));
        assert_eq!(parse_version_line("Jailer v1.17.0"), Some("v1.17.0".into()));
        assert_eq!(parse_version_line("garbage"), None);
    }

    fn script(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    /// The three questions, each answered no in turn, and each refusal identified by its class: a test
    /// that only asked "was it refused?" would pass for the wrong reason. The files live in a directory
    /// that the trusted-input rule accepts, so the rule under test is the one that speaks.
    #[tokio::test]
    async fn a_binary_is_run_only_from_a_trusted_path_with_the_pinned_bytes_and_the_pinned_version() {
        let d = private_tempdir();
        let owners = trusted_owners();
        let mut cfg = config(d.path()).firecracker;
        let ran = d.path().join("the-jailer-was-run");
        let jailer = |version: &str| format!("#!/bin/sh\n: > '{}'\necho 'Jailer {version}'\n", ran.display());
        cfg.firecracker_bin = script(d.path(), "firecracker", "#!/bin/sh\necho 'Firecracker v1.17.0'\n");
        cfg.jailer_bin = script(d.path(), "jailer", &jailer("v1.17.0"));

        // 2, unset: a binary with no pinned identity is refused, and is not run to ask its version.
        let e = verify_binaries(&cfg, &owners).await.unwrap_err();
        assert_eq!(e.class, FailureClass::SecurityControlFailure, "{}", e.message);
        assert!(e.message.contains("firecracker_sha256"), "{}", e.message);
        assert!(e.is_definite());
        assert!(!ran.exists(), "nothing unpinned is executed");

        // All three hold.
        test_support::pin(&mut cfg);
        let report = verify_binaries(&cfg, &owners).await.unwrap();
        assert_eq!((report.firecracker_version.as_str(), report.jailer_version.as_str()), ("v1.17.0", "v1.17.0"));
        assert_eq!(Some(&report.jailer_sha256), cfg.jailer_sha256.as_ref());
        assert!(ran.exists(), "a pinned binary is run for its version");
        std::fs::remove_file(&ran).unwrap();

        // 2, changed: the same path, the same version line, other bytes. Refused by its digest and
        // never run, at startup and at the moment of use.
        script(d.path(), "jailer", &jailer("v1.17.0").replace("echo", "echo  "));
        for e in [verify_binaries(&cfg, &owners).await.unwrap_err(), verify_pinned(&cfg).unwrap_err()] {
            assert_eq!(e.class, FailureClass::IntegrityFailure, "{}", e.message);
            assert!(e.message.contains("jailer_sha256"), "{}", e.message);
            assert!(e.is_definite());
        }
        assert!(!ran.exists(), "bytes that are not the pinned ones are never executed");

        // 3: pinned bytes of another release.
        script(d.path(), "jailer", &jailer("v1.16.0"));
        test_support::pin(&mut cfg);
        let e = verify_binaries(&cfg, &owners).await.unwrap_err();
        assert_eq!(e.class, FailureClass::IncompatibleRuntime, "{}", e.message);

        // 1: a file that someone else could write is refused before it is hashed or run.
        script(d.path(), "jailer", &jailer("v1.17.0"));
        test_support::pin(&mut cfg);
        verify_binaries(&cfg, &owners).await.unwrap();
        std::fs::remove_file(&ran).unwrap();
        std::fs::set_permissions(&cfg.jailer_bin, std::fs::Permissions::from_mode(0o777)).unwrap();
        let e = verify_binaries(&cfg, &owners).await.unwrap_err();
        assert_eq!(e.class, FailureClass::SecurityControlFailure, "{}", e.message);
        assert!(!e.message.contains("pinned"), "the trusted-input rule spoke, not the digest: {}", e.message);
        assert!(!ran.exists());
    }
}
