use std::{
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::Path,
    sync::Arc,
    time::Duration,
};

use acf_wire::frame::{FrameError, aio};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

use super::dispatch::dispatch;
use crate::{
    admission::{Authorizer, PeerCred},
    config::SecurityConfig,
    error::{AcfError, FailureClass, Result},
    lifecycle::Host,
    protocol::{ErrorBody, MAX_RESPONSE_FRAME, PROTOCOL, RequestEnvelope, ResponseEnvelope},
};

/// Longest `request_id` the host will echo back from a request it could not decode.
const MAX_ECHOED_REQUEST_ID: usize = 128;

/// Best effort: the `request_id` of a frame that failed *typed* decoding, so that the refusal can be
/// matched to the request that caused it (a connection may carry many). Bounded, so a hostile peer
/// cannot make the host reflect an arbitrarily large string.
fn recover_request_id(frame: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(frame).ok()?;
    let id = value.get("request_id")?.as_str()?;
    (id.len() <= MAX_ECHOED_REQUEST_ID).then(|| id.to_owned())
}

/// `sockaddr_un.sun_path` is 108 bytes on Linux, one of which is the terminating NUL.
const MAX_SOCKET_PATH_BYTES: usize = 107;

/// Create the listening socket with no insecure window and replace only a *dead* stale socket.
pub fn bind_socket(path: &Path, mode: u32, gid: Option<u32>) -> Result<UnixListener> {
    use std::os::unix::ffi::OsStrExt;
    let len = path.as_os_str().as_bytes().len();
    if len > MAX_SOCKET_PATH_BYTES {
        // Say so up front: the kernel's own error ("path must be shorter than SUN_LEN") names no path.
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
    // Bind under a restrictive umask so the socket is born 0600, then widen deliberately.
    let old = rustix::process::umask(rustix::fs::Mode::from_bits_truncate(0o177));
    let bound = std::os::unix::net::UnixListener::bind(path);
    rustix::process::umask(old);
    let l = bound?;
    if let Some(g) = gid {
        std::os::unix::fs::chown(path, None, Some(g))?;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    l.set_nonblocking(true)?;
    Ok(UnixListener::from_std(l)?)
}

#[derive(Debug)]
pub struct Server {
    host: Arc<Host>,
    auth: Authorizer,
    sec: SecurityConfig,
    conns: Arc<Semaphore>,
}

impl Server {
    pub fn new(host: Arc<Host>, sec: SecurityConfig) -> Arc<Self> {
        let auth = Authorizer::new(sec.allowed_uids.clone(), sec.allowed_gids.clone());
        let conns = Arc::new(Semaphore::new(sec.max_connections.max(1)));
        Arc::new(Self { host, auth, sec, conns })
    }

    /// Accept until `shutdown`, then give in-flight connections `drain` to finish.
    pub async fn serve(self: Arc<Self>, listener: UnixListener, shutdown: CancellationToken, drain: Duration) {
        let mut tasks: JoinSet<()> = JoinSet::new();
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { continue };
                    // Shed load rather than queue unboundedly.
                    let Ok(permit) = Arc::clone(&self.conns).try_acquire_owned() else {
                        self.host.telemetry.metrics.incr("connections_shed", 1);
                        continue;
                    };
                    let me = Arc::clone(&self);
                    tasks.spawn(async move {
                        me.handle(stream).await;
                        drop(permit);
                    });
                }
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
        // Drain: in-flight operations are crash-safe, so aborting after the grace period is
        // safe — recovery resolves whatever was mid-flight on the next start.
        let _ = timeout(drain, async { while tasks.join_next().await.is_some() {} }).await;
        tasks.abort_all();
    }

    fn peer(stream: &UnixStream) -> Option<PeerCred> {
        stream.peer_cred().ok().map(|c| PeerCred { uid: c.uid(), gid: c.gid(), pid: c.pid() })
    }

    pub(crate) async fn handle(&self, mut stream: UnixStream) {
        let caller = match self.auth.authorize(Self::peer(&stream)) {
            Ok(c) => c,
            Err(e) => {
                self.host.telemetry.metrics.incr("auth_denied", 1);
                self.host.telemetry.events.emit(
                    &self.host.clock.wall_rfc3339(),
                    "auth.denied",
                    None,
                    None,
                    serde_json::json!({"reason": e.message}),
                );
                let _ = Self::write(&mut stream, &Self::err_envelope(&e, None)).await;
                return;
            }
        };
        let idle = Duration::from_secs(self.sec.idle_timeout_secs.max(1));
        loop {
            let frame = match timeout(idle, aio::read_frame(&mut stream, self.sec.max_request_bytes)).await {
                Err(_) | Ok(Err(FrameError::Eof)) => return,
                Ok(Err(e @ (FrameError::TooLarge { .. } | FrameError::Truncated | FrameError::Io(_)))) => {
                    let _ = Self::write(&mut stream, &Self::err_envelope(&AcfError::validation(format!("bad frame: {e}")), None)).await;
                    return;
                }
                Ok(Err(FrameError::Decode(_))) => return,
                Ok(Ok(f)) => f,
            };
            let env: RequestEnvelope = match serde_json::from_slice(&frame) {
                Ok(e) => e,
                Err(e) => {
                    // Framing is intact, so keep the connection: report precisely what was wrong, and
                    // echo the caller's request id (when it can be recovered) so the refusal correlates.
                    let id = recover_request_id(&frame);
                    if Self::write(&mut stream, &Self::err_envelope(&AcfError::validation(format!("malformed request: {e}")), id))
                        .await
                        .is_err()
                    {
                        return;
                    }
                    continue;
                }
            };
            let resp = if env.protocol == PROTOCOL {
                dispatch(&self.host, &self.sec, caller.clone(), env).await
            } else {
                let e = AcfError::new(
                    FailureClass::SchemaMismatch,
                    format!("this host speaks `{PROTOCOL}`, the request was `{}`", env.protocol),
                );
                Self::err_envelope(&e, env.request_id)
            };
            if Self::write(&mut stream, &resp).await.is_err() {
                return; // the client went away: the operation itself is already durable
            }
        }
    }

    async fn write(stream: &mut UnixStream, resp: &ResponseEnvelope) -> std::result::Result<(), FrameError> {
        aio::send_json(stream, resp, MAX_RESPONSE_FRAME).await
    }

    fn err_envelope(e: &AcfError, request_id: Option<String>) -> ResponseEnvelope {
        ResponseEnvelope {
            protocol: PROTOCOL.to_owned(),
            request_id,
            operation_id: None,
            status: crate::protocol::status_for_pre_record_error(e),
            result: None,
            error: Some(ErrorBody::from_failure(&crate::domain::FailureInfo::from(e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn socket_is_created_with_the_requested_mode_and_not_replaced_while_live() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("run/h.sock");
        let l = bind_socket(&p, 0o660, None).unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o660);
        let e = bind_socket(&p, 0o660, None).unwrap_err();
        assert_eq!(e.class, FailureClass::StateConflict, "a live listener must not be hijacked: {e}");
        drop(l);
        assert!(bind_socket(&p, 0o600, None).is_ok(), "a dead stale socket is replaced");
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
        assert_eq!(e.class, FailureClass::Validation);
        assert!(e.message.contains("at most 107 bytes"), "{}", e.message);
        assert!(!d.path().join("a-deliberately-long-directory-name").exists(), "must fail before touching the disk");
    }

    #[tokio::test]
    async fn a_path_of_exactly_the_limit_is_accepted() {
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
