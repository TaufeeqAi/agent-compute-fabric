//! Connecting to the guest agent.

use std::{
    os::fd::{AsRawFd, OwnedFd},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};

use crate::error::{AcfError, FailureClass, Result};

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}
pub type BoxedStream = Box<dyn AsyncStream>;

#[async_trait]
pub trait GuestConnector: Send + Sync + std::fmt::Debug {
    async fn connect(&self) -> Result<BoxedStream>;
}

/// A Unix-socket address that is safe from the 108-byte `sun_path` limit.
///
/// Jail paths (`…/sandboxes/<sbx>/<gen>/jail/firecracker/<id>/root/v.sock`) routinely exceed it.
/// The fix is to address the socket *relative to an open directory descriptor* through procfs:
/// `/proc/self/fd/<N>/v.sock` is short, and resolves through the descriptor — which also means
/// the lookup cannot be redirected by renaming path components after the directory was opened.
#[derive(Debug, Clone)]
pub struct UdsTarget {
    // Keep the directory fd alive for as long as the target is used.
    dir: Option<Arc<OwnedFd>>,
    name: String,
    direct: Option<PathBuf>,
}

impl UdsTarget {
    pub fn in_dir(dir: OwnedFd, name: &str) -> Self {
        Self { dir: Some(Arc::new(dir)), name: name.to_owned(), direct: None }
    }

    pub fn direct(path: impl Into<PathBuf>) -> Self {
        Self { dir: None, name: String::new(), direct: Some(path.into()) }
    }

    pub fn resolve(&self) -> PathBuf {
        match (&self.dir, &self.direct) {
            (Some(fd), _) => PathBuf::from(format!("/proc/self/fd/{}/{}", fd.as_raw_fd(), self.name)),
            (None, Some(p)) => p.clone(),
            (None, None) => PathBuf::new(),
        }
    }
}

fn unavailable(msg: impl Into<String>) -> AcfError {
    AcfError::new(FailureClass::BackendUnavailable, msg)
}

/// Plain Unix socket (tests, and any future non-vsock transport).
#[derive(Debug, Clone)]
pub struct UnixConnector {
    pub target: UdsTarget,
    pub connect_timeout: Duration,
}

#[async_trait]
impl GuestConnector for UnixConnector {
    async fn connect(&self) -> Result<BoxedStream> {
        let s = timeout(self.connect_timeout, UnixStream::connect(self.target.resolve()))
            .await
            .map_err(|_| unavailable("timed out connecting to the guest socket"))?
            .map_err(|e| unavailable(format!("cannot connect to the guest socket: {e}")))?;
        Ok(Box::new(s))
    }
}

/// Firecracker's host side of vsock: connect to the device's UDS, send `CONNECT <port>\n`, and
/// expect `OK <n>\n`; after that the stream is a transparent pipe to the guest port.
///
/// The host **never listens** on a `uds_path_<PORT>` socket, so the guest has no way to open a
/// connection to the host over vsock (spec SEC-001/SEC-014): host-initiated only.
#[derive(Debug, Clone)]
pub struct VsockUdsConnector {
    pub target: UdsTarget,
    pub port: u32,
    pub connect_timeout: Duration,
}

const MAX_HANDSHAKE_LINE: usize = 64;

#[async_trait]
impl GuestConnector for VsockUdsConnector {
    async fn connect(&self) -> Result<BoxedStream> {
        let mut s = timeout(self.connect_timeout, UnixStream::connect(self.target.resolve()))
            .await
            .map_err(|_| unavailable("timed out connecting to the vsock socket"))?
            .map_err(|e| unavailable(format!("cannot connect to the vsock socket: {e}")))?;
        let hs = async {
            s.write_all(format!("CONNECT {}\n", self.port).as_bytes()).await?;
            // Byte-at-a-time so we never consume protocol bytes that follow the handshake line.
            let mut line = Vec::with_capacity(MAX_HANDSHAKE_LINE);
            let mut b = [0u8; 1];
            loop {
                s.read_exact(&mut b).await?;
                if b[0] == b'\n' {
                    break;
                }
                line.push(b[0]);
                if line.len() > MAX_HANDSHAKE_LINE {
                    return Err(std::io::Error::other("vsock handshake line too long"));
                }
            }
            Ok::<_, std::io::Error>(line)
        };
        let line = timeout(self.connect_timeout, hs)
            .await
            .map_err(|_| unavailable("vsock handshake timed out (guest agent not listening yet?)"))?
            .map_err(|e| unavailable(format!("vsock handshake failed: {e}")))?;
        if !line.starts_with(b"OK ") {
            return Err(unavailable(format!("vsock handshake rejected: {:?}", String::from_utf8_lossy(&line))));
        }
        Ok(Box::new(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    #[tokio::test]
    async fn vsock_handshake_sends_connect_and_requires_ok() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("v.sock");
        let l = UnixListener::bind(&p).unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut got = [0u8; 12];
            s.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"CONNECT 5252");
            let mut nl = [0u8; 1];
            s.read_exact(&mut nl).await.unwrap();
            s.write_all(b"OK 1073741824\nPAYLOAD").await.unwrap();
        });
        let c = VsockUdsConnector { target: UdsTarget::direct(&p), port: 5252, connect_timeout: Duration::from_secs(2) };
        let mut st = c.connect().await.unwrap();
        // the bytes after the handshake line belong to the protocol and must not be swallowed
        let mut rest = [0u8; 7];
        st.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"PAYLOAD");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn rejected_handshake_and_missing_socket_are_backend_unavailable() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("v.sock");
        let l = UnixListener::bind(&p).unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut sink = [0u8; 13];
            let _ = s.read_exact(&mut sink).await;
            let _ = s.write_all(b"NOPE\n").await;
        });
        let c = VsockUdsConnector { target: UdsTarget::direct(&p), port: 5252, connect_timeout: Duration::from_secs(2) };
        assert_eq!(c.connect().await.err().unwrap().class, FailureClass::BackendUnavailable);
        let missing = UnixConnector { target: UdsTarget::direct(d.path().join("none")), connect_timeout: Duration::from_millis(200) };
        assert_eq!(missing.connect().await.err().unwrap().class, FailureClass::BackendUnavailable);
    }

    #[tokio::test]
    async fn fd_relative_target_beats_the_sun_path_limit() {
        // Build a directory path far longer than 108 bytes, put a socket in it, and connect anyway.
        let d = tempfile::tempdir().unwrap();
        let mut deep = d.path().to_path_buf();
        for _ in 0..8 {
            deep.push("a-very-long-directory-name-to-blow-the-limit");
        }
        std::fs::create_dir_all(&deep).unwrap();
        assert!(deep.join("v.sock").as_os_str().len() > 108);
        // Bind via a short fd-relative path as well (bind has the same limit).
        let dirfd: OwnedFd = rustix::fs::open(
            &deep,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let t = UdsTarget::in_dir(dirfd, "v.sock");
        let l = UnixListener::bind(t.resolve()).unwrap();
        tokio::spawn(async move {
            let _ = l.accept().await;
        });
        let c = UnixConnector { target: t.clone(), connect_timeout: Duration::from_secs(2) };
        assert!(c.connect().await.is_ok(), "fd-relative address must connect where the absolute path cannot");
        assert!(t.resolve().as_os_str().len() < 60);
    }
}
