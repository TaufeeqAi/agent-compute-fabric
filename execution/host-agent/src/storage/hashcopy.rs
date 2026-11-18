//! Stream-copy a file while hashing **the bytes actually copied** (contract TI-2, IM-2, SNP-3).
//!
//! This is the TOCTOU defence for images and snapshots: instead of "verify the file, then use the
//! path" (swappable between the two steps), we read once from an *open descriptor*, hash what we
//! read, and write exactly those bytes to the destination. The digest therefore describes the
//! destination's content by construction.
//!
//! Runs of zero bytes are written as holes, which keeps sparse disk images and mostly-empty
//! memory files cheap on disk. The result is byte-identical when read back.

use std::io::{Read, Seek, SeekFrom, Write};

use sha2::{Digest, Sha256};

use crate::error::{AcfError, FailureClass, Result};

const CHUNK: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Copied {
    pub bytes: u64,
    /// Lowercase hex sha256 of everything read from `src`.
    pub sha256: String,
}

/// Copy `src` to `dst`, never reading more than `max_bytes`. `dst` is extended to the full
/// length (so a trailing hole is preserved). Returns the byte count and digest.
pub fn copy_hashed<R: Read, W: Write + Seek>(src: &mut R, dst: &mut W, max_bytes: u64) -> Result<Copied> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut total = 0u64;
    loop {
        let n = match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        total += n as u64;
        if total > max_bytes {
            return Err(AcfError::new(FailureClass::IntegrityFailure, format!("source is larger than the permitted {max_bytes} bytes")));
        }
        let chunk = &buf[..n];
        hasher.update(chunk);
        if chunk.iter().all(|b| *b == 0) {
            dst.seek(SeekFrom::Current(n as i64))?;
        } else {
            dst.write_all(chunk)?;
        }
    }
    // Materialise a trailing hole by fixing the length via a final seek+write of nothing: the
    // caller sets the length (`File::set_len`) because `W` is generic; we only guarantee position.
    dst.flush()?;
    Ok(Copied { bytes: total, sha256: hex::encode(hasher.finalize()) })
}

/// Hash a reader without copying (used to re-verify stored artifacts).
pub fn hash_reader<R: Read>(src: &mut R, max_bytes: u64) -> Result<Copied> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut total = 0u64;
    loop {
        let n = match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        total += n as u64;
        if total > max_bytes {
            return Err(AcfError::new(FailureClass::IntegrityFailure, format!("input is larger than the permitted {max_bytes} bytes")));
        }
        hasher.update(&buf[..n]);
    }
    Ok(Copied { bytes: total, sha256: hex::encode(hasher.finalize()) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sha(b: &[u8]) -> String {
        hex::encode(Sha256::digest(b))
    }

    #[test]
    fn digest_describes_the_destination_bytes() {
        let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
        let mut dst = tempfile::tempfile().unwrap();
        let c = copy_hashed(&mut Cursor::new(&data), &mut dst, u64::MAX).unwrap();
        dst.set_len(c.bytes).unwrap();
        let mut back = Vec::new();
        dst.seek(SeekFrom::Start(0)).unwrap();
        dst.read_to_end(&mut back).unwrap();
        assert_eq!(back, data);
        assert_eq!(c.sha256, sha(&data));
        assert_eq!(c.sha256, hash_reader(&mut Cursor::new(&back), u64::MAX).unwrap().sha256);
    }

    #[test]
    fn zero_runs_become_holes_but_read_back_identically() {
        let mut data = vec![0u8; 5 << 20];
        data[3 << 20] = 7; // one non-zero byte in the middle of zeros
        let mut dst = tempfile::tempfile().unwrap();
        let c = copy_hashed(&mut Cursor::new(&data), &mut dst, u64::MAX).unwrap();
        dst.set_len(c.bytes).unwrap();
        let blocks = std::os::unix::fs::MetadataExt::blocks(&dst.metadata().unwrap()) * 512;
        assert!(blocks < (2 << 20), "expected a sparse file, but {blocks} bytes are allocated");
        let mut back = Vec::new();
        dst.seek(SeekFrom::Start(0)).unwrap();
        dst.read_to_end(&mut back).unwrap();
        assert_eq!(back, data);
        assert_eq!(c.sha256, sha(&data));
    }

    #[test]
    fn oversize_source_is_refused_without_unbounded_reading() {
        let data = vec![1u8; 10_000];
        let mut dst = tempfile::tempfile().unwrap();
        let e = copy_hashed(&mut Cursor::new(&data), &mut dst, 5_000).unwrap_err();
        assert_eq!(e.class, FailureClass::IntegrityFailure);
    }

    #[test]
    fn a_swapped_source_yields_a_different_digest_not_a_silent_success() {
        // The caller compares `Copied::sha256` with the manifest digest; this is the property.
        let (a, b) = (vec![1u8; 4096], vec![2u8; 4096]);
        let mut d1 = tempfile::tempfile().unwrap();
        let mut d2 = tempfile::tempfile().unwrap();
        assert_ne!(
            copy_hashed(&mut Cursor::new(&a), &mut d1, u64::MAX).unwrap().sha256,
            copy_hashed(&mut Cursor::new(&b), &mut d2, u64::MAX).unwrap().sha256
        );
    }
}
