//! Single-writer exclusion for the host agent's durable state (spec §13.1, §21.4).
//!
//! `flock(2)` is advisory but is released by the kernel on process death, so a crashed agent
//! never leaves a stale lock — unlike a pid file. The file *contents* are informational only
//! (who holds it), never an authority.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

use rustix::fs::{FlockOperation, flock};

use crate::error::{AcfError, FailureClass, Result};

#[derive(Debug)]
pub struct HostLock {
    _file: File,
}

impl HostLock {
    pub fn acquire(path: &Path, instance_id: &str) -> Result<Self> {
        let mut f = OpenOptions::new().read(true).write(true).create(true).truncate(false).mode(0o600).open(path)?;
        if let Err(e) = flock(&f, FlockOperation::NonBlockingLockExclusive) {
            let mut holder = String::new();
            let _ = f.read_to_string(&mut holder);
            return Err(AcfError::new(
                FailureClass::StateConflict,
                format!("another host-agent instance holds {} ({e}); holder info: {}", path.display(), holder.trim()),
            ));
        }
        f.set_len(0)?;
        let info = serde_json::json!({"pid": std::process::id(), "instance_id": instance_id});
        f.write_all(info.to_string().as_bytes())?;
        f.sync_all()?;
        let _ = fs::metadata(path)?;
        Ok(Self { _file: f })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_acquire_fails_until_first_is_dropped() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("lock");
        let first = HostLock::acquire(&p, "a").unwrap();
        let err = HostLock::acquire(&p, "b").unwrap_err();
        assert_eq!(err.class, FailureClass::StateConflict);
        assert!(err.message.contains("\"instance_id\":\"a\""), "{}", err.message);
        drop(first);
        assert!(HostLock::acquire(&p, "b").is_ok(), "released on drop, as it is on process death");
    }
}
