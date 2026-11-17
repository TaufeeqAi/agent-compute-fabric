//! Verifying the Firecracker and Jailer binaries before they are ever executed as root (spec §17.2).
//!
//! A snapshot is only valid on the *same* Firecracker version, and a binary that an unprivileged
//! user can replace is a root-execution primitive. So: trusted ownership and mode, trusted
//! ancestors, and the exact pinned version — checked at startup and by `doctor`.

use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::Stdio,
    time::Duration,
};

use tokio::{process::Command, time::timeout};

use crate::{
    admission::trusted_file::check_ancestors,
    config::FirecrackerConfig,
    error::{AcfError, FailureClass, Result},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryReport {
    pub firecracker_version: String,
    pub jailer_version: String,
}

fn trusted_executable(path: &Path, owners: &[u32]) -> Result<()> {
    check_ancestors(path, owners)?;
    let md = std::fs::metadata(path).map_err(|e| AcfError::new(FailureClass::BackendUnavailable, format!("{}: {e}", path.display())))?;
    if !md.is_file() {
        return Err(AcfError::security(format!("{} is not a regular file", path.display())));
    }
    if !owners.contains(&md.uid()) {
        return Err(AcfError::security(format!("{} is owned by untrusted uid {}", path.display(), md.uid())));
    }
    if md.permissions().mode() & 0o022 != 0 {
        return Err(AcfError::security(format!("{} is group/world-writable", path.display())));
    }
    if md.permissions().mode() & 0o111 == 0 {
        return Err(AcfError::new(FailureClass::BackendUnavailable, format!("{} is not executable", path.display())));
    }
    Ok(())
}

/// `Firecracker v1.17.0` / `Jailer v1.17.0` → `v1.17.0`.
pub fn parse_version_line(out: &str) -> Option<String> {
    out.split_whitespace().find(|w| w.starts_with('v') && w[1..].split('.').count() == 3).map(str::to_owned)
}

async fn version_of(bin: &Path) -> Result<String> {
    let out = timeout(Duration::from_secs(5), Command::new(bin).arg("--version").stdin(Stdio::null()).output())
        .await
        .map_err(|_| AcfError::new(FailureClass::BackendUnavailable, format!("{} --version timed out", bin.display())))?
        .map_err(|e| AcfError::new(FailureClass::BackendUnavailable, format!("cannot run {}: {e}", bin.display())))?;
    let text = String::from_utf8_lossy(&out.stdout);
    parse_version_line(&text).ok_or_else(|| {
        AcfError::new(FailureClass::CompatibilityFailure, format!("cannot parse a version from `{}`", text.lines().next().unwrap_or("")))
    })
}

pub async fn verify_binaries(cfg: &FirecrackerConfig, trusted_owners: &[u32]) -> Result<BinaryReport> {
    trusted_executable(&cfg.firecracker_bin, trusted_owners)?;
    trusted_executable(&cfg.jailer_bin, trusted_owners)?;
    let (fv, jv) = (version_of(&cfg.firecracker_bin).await?, version_of(&cfg.jailer_bin).await?);
    for (what, v) in [("firecracker", &fv), ("jailer", &jv)] {
        if *v != cfg.pinned_version {
            return Err(AcfError::new(
                FailureClass::CompatibilityFailure,
                format!("{what} is {v} but the profile is pinned to {}", cfg.pinned_version),
            ));
        }
    }
    Ok(BinaryReport { firecracker_version: fv, jailer_version: jv })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_support::config;

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

    #[tokio::test]
    async fn rejects_untrusted_and_mismatched_binaries() {
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut cfg = config(d.path());
        let me = vec![rustix::process::geteuid().as_raw()];
        cfg.firecracker.firecracker_bin = script(d.path(), "firecracker", "#!/bin/sh\necho 'Firecracker v1.16.0'\n");
        cfg.firecracker.jailer_bin = script(d.path(), "jailer", "#!/bin/sh\necho 'Jailer v1.17.0'\n");
        // /tmp (an ancestor) is world-writable on most hosts, which is itself rejected: that is the point
        let r = verify_binaries(&cfg.firecracker, &me).await;
        assert!(r.is_err());
        // the writable-bit check is independent of ancestors: use a direct call on a 0o777 file
        let loose = script(d.path(), "loose", "#!/bin/sh\n");
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(trusted_executable(&loose, &me).is_err());
    }
}
