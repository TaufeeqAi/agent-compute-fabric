//! Deterministic baseline probe (spec §20.5 step 6).
//!
//! `state_digest` binds two independent pieces of guest state:
//! * `boot_id` — kernel *memory* state. A genuine snapshot restore preserves it; a reboot
//!   (e.g. a restore that silently cold-booted) changes it.
//! * the canary file — *disk* state. Detects a restore that paired the wrong disk image.

use std::{fs, io, path::Path};

use acf_wire::guest::ProbeReport;
use sha2::{Digest, Sha256};

pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const DEFAULT_BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
pub const DEFAULT_CANARY_PATH: &str = "/var/lib/acf/canary";

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Create the canary on first use (32 bytes from the kernel CSPRNG), else read it.
fn ensure_canary(path: &Path) -> io::Result<Vec<u8>> {
    match fs::read(path) {
        Ok(b) if !b.is_empty() => Ok(b),
        _ => {
            let mut buf = [0u8; 32];
            io::Read::read_exact(&mut fs::File::open("/dev/urandom")?, &mut buf)?;
            if let Some(dir) = path.parent() {
                fs::create_dir_all(dir)?;
            }
            fs::write(path, buf)?;
            fs::File::open(path)?.sync_all()?;
            Ok(buf.to_vec())
        }
    }
}

pub fn probe(nonce: &str, boot_id_path: &Path, canary_path: &Path) -> io::Result<ProbeReport> {
    let boot_id = fs::read_to_string(boot_id_path)?.trim().to_owned();
    let canary_sha256 = sha256_hex(&ensure_canary(canary_path)?);
    let mut h = Sha256::new();
    h.update(boot_id.as_bytes());
    h.update([0]);
    h.update(canary_sha256.as_bytes());
    h.update([0]);
    h.update(AGENT_VERSION.as_bytes());
    Ok(ProbeReport {
        nonce: nonce.to_owned(),
        boot_id,
        canary_sha256,
        agent_version: AGENT_VERSION.to_owned(),
        state_digest: hex::encode(h.finalize()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_stable_and_nonce_independent() {
        let d = tempfile::tempdir().unwrap();
        let boot = d.path().join("boot_id");
        fs::write(&boot, "abc-123\n").unwrap();
        let canary = d.path().join("c/canary");
        let a = probe("n1", &boot, &canary).unwrap();
        let b = probe("n2", &boot, &canary).unwrap();
        assert_eq!(a.state_digest, b.state_digest, "digest must not depend on the nonce");
        assert_eq!(a.nonce, "n1");
    }

    #[test]
    fn reboot_or_wrong_disk_changes_digest() {
        let d = tempfile::tempdir().unwrap();
        let boot = d.path().join("boot_id");
        let canary = d.path().join("canary");
        fs::write(&boot, "boot-A").unwrap();
        let before = probe("n", &boot, &canary).unwrap();

        fs::write(&boot, "boot-B").unwrap(); // simulated reboot
        assert_ne!(before.state_digest, probe("n", &boot, &canary).unwrap().state_digest);

        fs::write(&boot, "boot-A").unwrap();
        fs::write(&canary, b"different disk").unwrap(); // simulated wrong disk
        assert_ne!(before.state_digest, probe("n", &boot, &canary).unwrap().state_digest);
    }
}
