//! Length-delimited framing: `u32` big-endian length followed by that many payload bytes.
//!
//! Security properties (all covered by tests):
//! * a declared length above the caller-supplied `max` is rejected **before** any
//!   allocation, so a hostile peer cannot make us allocate more than `max`;
//! * `max` itself is clamped to [`MAX_FRAME_HARD_CAP`] so a misconfigured caller cannot
//!   disable the bound;
//! * clean EOF on a frame boundary is distinguishable from a truncated frame.

use std::io::{self, Read, Write};

use serde::{Serialize, de::DeserializeOwned};

/// Absolute upper bound on any frame, regardless of caller configuration (64 MiB).
pub const MAX_FRAME_HARD_CAP: usize = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("peer closed the connection on a frame boundary")]
    Eof,
    #[error("peer closed the connection in the middle of a frame")]
    Truncated,
    #[error("frame of {len} bytes exceeds the permitted maximum of {max} bytes")]
    TooLarge { len: usize, max: usize },
    #[error("frame payload is not valid JSON for the expected type: {0}")]
    Decode(#[from] serde_json::Error),
}

fn clamp(max: usize) -> usize {
    max.min(MAX_FRAME_HARD_CAP)
}

/// Encode one frame into a fresh buffer.
pub fn encode_frame(payload: &[u8], max: usize) -> Result<Vec<u8>, FrameError> {
    let max = clamp(max);
    if payload.len() > max {
        return Err(FrameError::TooLarge { len: payload.len(), max });
    }
    let len = u32::try_from(payload.len()).map_err(|_| FrameError::TooLarge { len: payload.len(), max })?;
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Blocking read of a single frame.
pub fn read_frame<R: Read>(r: &mut R, max: usize) -> Result<Vec<u8>, FrameError> {
    let max = clamp(max);
    let mut hdr = [0u8; 4];
    let mut got = 0;
    while got < hdr.len() {
        match r.read(&mut hdr[got..]) {
            Ok(0) if got == 0 => return Err(FrameError::Eof),
            Ok(0) => return Err(FrameError::Truncated),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    let len = u32::from_be_bytes(hdr) as usize;
    if len > max {
        return Err(FrameError::TooLarge { len, max });
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).map_err(|e| if e.kind() == io::ErrorKind::UnexpectedEof { FrameError::Truncated } else { e.into() })?;
    Ok(buf)
}

/// Blocking write of a single frame (header + payload in one `write_all` to avoid
/// interleaving on shared sockets).
pub fn write_frame<W: Write>(w: &mut W, payload: &[u8], max: usize) -> Result<(), FrameError> {
    let buf = encode_frame(payload, max)?;
    w.write_all(&buf)?;
    w.flush()?;
    Ok(())
}

pub fn send_json<W: Write, T: Serialize>(w: &mut W, v: &T, max: usize) -> Result<(), FrameError> {
    write_frame(w, &serde_json::to_vec(v)?, max)
}

pub fn recv_json<R: Read, T: DeserializeOwned>(r: &mut R, max: usize) -> Result<T, FrameError> {
    Ok(serde_json::from_slice(&read_frame(r, max)?)?)
}

#[cfg(feature = "tokio")]
pub mod aio {
    //! Async equivalents used by the host-agent.
    use super::{FrameError, MAX_FRAME_HARD_CAP, clamp, encode_frame};
    use serde::{Serialize, de::DeserializeOwned};
    use std::io;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> Result<Vec<u8>, FrameError> {
        let max = clamp(max);
        let mut hdr = [0u8; 4];
        let mut got = 0;
        while got < hdr.len() {
            match r.read(&mut hdr[got..]).await {
                Ok(0) if got == 0 => return Err(FrameError::Eof),
                Ok(0) => return Err(FrameError::Truncated),
                Ok(n) => got += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }
        let len = u32::from_be_bytes(hdr) as usize;
        if len > max {
            return Err(FrameError::TooLarge { len, max });
        }
        let mut buf = vec![0u8; len];
        r.read_exact(&mut buf).await.map_err(
            |e| {
                if e.kind() == io::ErrorKind::UnexpectedEof { FrameError::Truncated } else { e.into() }
            },
        )?;
        Ok(buf)
    }

    pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8], max: usize) -> Result<(), FrameError> {
        let buf = encode_frame(payload, max)?;
        w.write_all(&buf).await?;
        w.flush().await?;
        Ok(())
    }

    pub async fn send_json<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, v: &T, max: usize) -> Result<(), FrameError> {
        write_frame(w, &serde_json::to_vec(v)?, max).await
    }

    pub async fn recv_json<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R, max: usize) -> Result<T, FrameError> {
        Ok(serde_json::from_slice(&read_frame(r, max).await?)?)
    }

    #[allow(dead_code)]
    const _: usize = MAX_FRAME_HARD_CAP;
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::io::Cursor;

    #[test]
    fn roundtrip() {
        let enc = encode_frame(b"hello", 1024).unwrap_or_default();
        let got = read_frame(&mut Cursor::new(enc), 1024).unwrap_or_default();
        assert_eq!(got, b"hello");
    }

    #[test]
    fn oversize_declared_length_rejected_before_allocation() {
        // Declares a 3 GiB frame but supplies no body: must fail on the header alone.
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&(3u32 << 30).to_be_bytes());
        let err = read_frame(&mut Cursor::new(hdr), 1024).err();
        assert!(matches!(err, Some(FrameError::TooLarge { max: 1024, .. })), "{err:?}");
    }

    #[test]
    fn caller_cannot_raise_the_hard_cap() {
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&((MAX_FRAME_HARD_CAP as u32) + 1).to_be_bytes());
        let err = read_frame(&mut Cursor::new(hdr), usize::MAX).err();
        assert!(matches!(err, Some(FrameError::TooLarge { .. })), "{err:?}");
    }

    #[test]
    fn eof_vs_truncated_are_distinguishable() {
        assert!(matches!(read_frame(&mut Cursor::new(Vec::new()), 16), Err(FrameError::Eof)));
        assert!(matches!(read_frame(&mut Cursor::new(vec![0, 0]), 16), Err(FrameError::Truncated)));
        let mut half = Vec::new();
        half.extend_from_slice(&10u32.to_be_bytes());
        half.extend_from_slice(b"abc");
        assert!(matches!(read_frame(&mut Cursor::new(half), 16), Err(FrameError::Truncated)));
    }

    proptest! {
        #[test]
        fn arbitrary_payloads_roundtrip(payload in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let enc = encode_frame(&payload, 8192).unwrap_or_default();
            let got = read_frame(&mut Cursor::new(enc), 8192).unwrap_or_default();
            prop_assert_eq!(got, payload);
        }

        #[test]
        fn garbage_never_panics_or_overallocates(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = read_frame(&mut Cursor::new(bytes), 32);
        }
    }
}
