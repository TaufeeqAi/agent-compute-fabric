//! The local endpoint (contract AU-1): a Unix-domain socket authenticated by the peer credentials
//! the kernel reports. Bound by the core, served by the edge.
//!
//! The socket file is the first access-control layer, so there must be no moment at which it is
//! more accessible than configured. On Linux the mode of a socket file is taken from the socket's
//! own inode at `bind`, so the socket is given mode `0600` *before* it is bound and widened
//! deliberately afterwards. The process umask is never touched (it is process-wide state; changing
//! it would race with every other thread that creates a file).

use std::{
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::Path,
};

use rustix::{
    fs::{Mode, fchmod},
    net::{AddressFamily, SocketAddrUnix, SocketType, bind, listen, socket},
};

use crate::error::{AcfError, Result};

/// `sockaddr_un.sun_path` is 108 bytes on Linux, one of which is the terminating NUL.
pub const MAX_SOCKET_PATH_BYTES: usize = 107;

/// Create the listening socket with no insecure window, replacing only a *dead* stale socket.
pub fn bind_socket(path: &Path, mode: u32, gid: Option<u32>) -> Result<std::os::unix::net::UnixListener> {
    use std::os::unix::ffi::OsStrExt;
    let len = path.as_os_str().as_bytes().len();
    if len > MAX_SOCKET_PATH_BYTES {
        // Say so up front: the kernel's own error names no path.
        return Err(AcfError::validation(format!(
            "socket path {} is {len} bytes; a Unix socket path may be at most {MAX_SOCKET_PATH_BYTES} bytes (set paths.socket_path to a shorter path)",
            path.display()
        )));
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => {
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                return Err(AcfError::conflict(format!("another process is already listening on {}", path.display())));
            }
            std::fs::remove_file(path)?;
        }
        Ok(_) => return Err(AcfError::conflict(format!("{} exists and is not a socket; refusing to replace it", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let fd = socket(AddressFamily::UNIX, SocketType::STREAM, None)?;
    // Born 0600, whatever the umask: nobody else can connect before the mode is set on purpose.
    fchmod(&fd, Mode::from_raw_mode(0o600))?;
    let addr = SocketAddrUnix::new(path).map_err(|e| AcfError::validation(format!("invalid socket path: {e}")))?;
    bind(&fd, &addr)?;
    if let Some(g) = gid {
        std::os::unix::fs::chown(path, None, Some(g))?;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    listen(&fd, 128)?;
    let listener = std::os::unix::net::UnixListener::from(fd);
    listener.set_nonblocking(true)?;
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::FailureClass;

    fn mode_of(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn socket_is_created_with_the_requested_mode_and_not_replaced_while_live() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("run/h.sock");
        let l = bind_socket(&p, 0o660, None).unwrap();
        assert_eq!(mode_of(&p), 0o660);
        let e = bind_socket(&p, 0o660, None).unwrap_err();
        assert_eq!(e.class, FailureClass::StateConflict, "a live listener must not be hijacked: {e}");
        drop(l);
        assert!(bind_socket(&p, 0o600, None).is_ok(), "a dead stale socket is replaced");
        assert_eq!(mode_of(&p), 0o600);
    }

    #[test]
    fn the_socket_accepts_connections_once_bound() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("h.sock");
        let l = bind_socket(&p, 0o600, None).unwrap();
        let client = std::os::unix::net::UnixStream::connect(&p).unwrap();
        l.set_nonblocking(false).unwrap();
        let (_served, _) = l.accept().unwrap();
        drop(client);
    }

    #[test]
    fn an_over_long_socket_path_is_refused_with_an_actionable_message_and_creates_nothing() {
        let d = tempfile::tempdir().unwrap();
        let mut p = d.path().to_path_buf();
        while p.as_os_str().len() <= MAX_SOCKET_PATH_BYTES {
            p.push("a-deliberately-long-directory-name");
        }
        p.push("h.sock");
        let e = bind_socket(&p, 0o600, None).unwrap_err();
        assert_eq!(e.class, FailureClass::InvalidRequest);
        assert!(e.message.contains("at most 107 bytes"), "{}", e.message);
        assert!(!d.path().join("a-deliberately-long-directory-name").exists(), "must fail before touching the disk");
    }

    #[test]
    fn a_path_of_exactly_the_limit_is_accepted() {
        // 107 bytes is the longest address the kernel takes; build one ending at exactly that length.
        let d = tempfile::tempdir().unwrap();
        let base = d.path().as_os_str().len() + 1; // "<dir>/"
        if base + 1 > MAX_SOCKET_PATH_BYTES {
            return; // the temp dir is itself too deep for this check on this machine
        }
        let name = "s".repeat(MAX_SOCKET_PATH_BYTES - base);
        let p = d.path().join(&name);
        assert_eq!(p.as_os_str().len(), MAX_SOCKET_PATH_BYTES);
        assert!(bind_socket(&p, 0o600, None).is_ok());
    }

    #[test]
    fn a_regular_file_at_the_socket_path_is_never_deleted() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("h.sock");
        std::fs::write(&p, b"precious").unwrap();
        assert!(bind_socket(&p, 0o600, None).is_err());
        assert_eq!(std::fs::read(&p).unwrap(), b"precious");
    }
}
