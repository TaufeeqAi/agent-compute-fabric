//! Host-side guest-agent client.
//!
//! **Trust model.** The guest is untrusted. This client therefore:
//! * bounds every frame it will read *before* allocating (`max_frame` derived from the run's own
//!   output budget), so a hostile guest cannot make the host allocate more than the policy allows;
//! * re-enforces the output caps on whatever comes back ([`enforce_bounds`]) instead of trusting
//!   the guest to have honoured them;
//! * enforces its **own, later, deadline** (spec §18.3): the guest is told to stop at
//!   `timeout`, but if it does not, the host sends `Cancel`, waits a grace period, and then takes
//!   the VM down through the [`VmBackstop`]. A guest that ignores its deadline cannot hold a
//!   sandbox hostage.

use std::{sync::Arc, time::Duration};

use acf_wire::{
    frame::{FrameError, MAX_FRAME_HARD_CAP, aio},
    guest::{
        Containment, ExecRequest, ExecResult, ExecStatus, GUEST_PROTOCOL_VERSION, GuestRequest, GuestResponse, NetReport, ProbeReport,
    },
};
use async_trait::async_trait;
use tokio::time::{Instant, sleep, sleep_until, timeout};
use tokio_util::sync::CancellationToken;

use super::connector::{BoxedStream, GuestConnector};
use crate::{
    backend::{GuestExecOutcome, GuestExecRequest},
    domain::RunLimits,
    error::{AcfError, FailureClass, Result},
};

const REQUEST_FRAME_MAX: usize = 1024 * 1024;
const SHORT_RPC: Duration = Duration::from_secs(5);
/// Base64 inflates by 4/3; JSON framing and the other fields need a little more.
const FRAME_SLACK: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestHello {
    pub agent_version: String,
    pub boot_id: String,
}

/// How the client takes a VM down when the guest ignores its deadline.
#[async_trait]
pub trait VmBackstop: Send + Sync {
    async fn kill_vm(&self) -> Result<()>;
}

#[derive(Debug, Clone)]
pub struct GuestClient {
    connector: Arc<dyn GuestConnector>,
}

fn map_frame(e: FrameError) -> AcfError {
    match e {
        FrameError::TooLarge { len, max } => {
            AcfError::new(FailureClass::OutputLimit, format!("guest sent a {len}-byte frame, above the {max}-byte bound"))
                .with_possible_side_effect()
        }
        FrameError::Decode(e) => {
            AcfError::new(FailureClass::CorruptInput, format!("undecodable guest response: {e}")).with_possible_side_effect()
        }
        FrameError::Eof | FrameError::Truncated => {
            AcfError::new(FailureClass::BackendCrash, "guest connection closed unexpectedly").with_possible_side_effect()
        }
        FrameError::Io(e) => AcfError::new(FailureClass::BackendCrash, format!("guest connection error: {e}")).with_possible_side_effect(),
    }
}

/// Largest frame an exec result for these limits may legitimately occupy.
pub fn exec_frame_bound(limits: &RunLimits) -> usize {
    let raw = limits.max_stdout_bytes.saturating_add(limits.max_stderr_bytes);
    let b64 = raw.saturating_mul(4) / 3 + 8;
    usize::try_from(b64.saturating_add(FRAME_SLACK)).unwrap_or(MAX_FRAME_HARD_CAP).min(MAX_FRAME_HARD_CAP)
}

/// Re-impose the caps on a result the guest produced. Returns the corrected result and a list of
/// anomalies (an honest guest produces none).
pub fn enforce_bounds(mut r: ExecResult, limits: &RunLimits) -> (ExecResult, Vec<String>) {
    let mut anomalies = Vec::new();
    let clamp = |v: &mut Vec<u8>, total: &mut u64, truncated: &mut bool, cap: u64, name: &str, anomalies: &mut Vec<String>| {
        // Record what was actually *received* before any truncation: it is a hard lower bound on
        // what the workload produced, whatever the guest claims.
        let observed = v.len() as u64;
        if *total < observed {
            anomalies.push(format!("guest reported {name}_total_bytes={total} below the {observed} bytes it returned"));
            *total = observed;
        }
        if observed > cap {
            anomalies.push(format!("guest returned {observed} {name} bytes, above the {cap}-byte cap"));
            v.truncate(usize::try_from(cap).unwrap_or(usize::MAX));
        }
        // Derived, not trusted: truncated exactly when more was produced than is kept.
        *truncated = *total > v.len() as u64;
    };
    clamp(&mut r.stdout, &mut r.stdout_total_bytes, &mut r.stdout_truncated, limits.max_stdout_bytes, "stdout", &mut anomalies);
    clamp(&mut r.stderr, &mut r.stderr_total_bytes, &mut r.stderr_truncated, limits.max_stderr_bytes, "stderr", &mut anomalies);
    (r, anomalies)
}

fn synthesized(exec_id: &str, status: ExecStatus, duration: Duration) -> ExecResult {
    ExecResult {
        exec_id: exec_id.to_owned(),
        status,
        stdout: vec![],
        stderr: vec![],
        stdout_total_bytes: 0,
        stderr_total_bytes: 0,
        stdout_truncated: false,
        stderr_truncated: false,
        duration_ms: u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
        pid_limit_hit: false,
        // We never saw the guest's output, so by definition the capture is incomplete.
        output_incomplete: true,
        containment: Containment::Unknown,
    }
}

impl GuestClient {
    pub fn new(connector: Arc<dyn GuestConnector>) -> Self {
        Self { connector }
    }

    async fn rpc(&self, stream: &mut BoxedStream, req: &GuestRequest, max_resp: usize) -> Result<GuestResponse> {
        aio::send_json(stream, req, REQUEST_FRAME_MAX).await.map_err(map_frame)?;
        aio::recv_json(stream, max_resp).await.map_err(map_frame)
    }

    async fn connect_hello(&self) -> Result<(BoxedStream, GuestHello)> {
        let mut s = self.connector.connect().await?;
        let resp = timeout(SHORT_RPC, self.rpc(&mut s, &GuestRequest::Hello { protocol_version: GUEST_PROTOCOL_VERSION }, 64 * 1024))
            .await
            .map_err(|_| AcfError::new(FailureClass::BackendUnavailable, "guest agent did not answer Hello in time"))??;
        match resp {
            GuestResponse::Hello { protocol_version, agent_version, boot_id } if protocol_version == GUEST_PROTOCOL_VERSION => {
                Ok((s, GuestHello { agent_version, boot_id }))
            }
            GuestResponse::Hello { protocol_version, .. } => Err(AcfError::new(
                FailureClass::SchemaMismatch,
                format!("guest agent speaks protocol {protocol_version}, host speaks {GUEST_PROTOCOL_VERSION}"),
            )),
            GuestResponse::Error { message, .. } => {
                Err(AcfError::new(FailureClass::SchemaMismatch, format!("guest rejected Hello: {message}")))
            }
            other => Err(AcfError::new(FailureClass::CorruptInput, format!("unexpected reply to Hello: {other:?}"))),
        }
    }

    pub async fn hello(&self) -> Result<GuestHello> {
        Ok(self.connect_hello().await?.1)
    }

    /// Retry `Hello` until the agent answers or `total` elapses (the guest is still booting).
    pub async fn wait_ready(&self, total: Duration) -> Result<GuestHello> {
        let deadline = Instant::now() + total;
        let mut backoff = Duration::from_millis(40);
        loop {
            let err = match self.hello().await {
                Ok(h) => return Ok(h),
                // A version mismatch will not fix itself by waiting.
                Err(e) if e.class == FailureClass::SchemaMismatch => return Err(e),
                Err(e) => e,
            };
            if Instant::now() + backoff >= deadline {
                return Err(AcfError::new(
                    FailureClass::BackendUnavailable,
                    format!("guest agent not ready within {total:?}: {}", err.message),
                ));
            }
            sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_millis(400));
        }
    }

    pub async fn probe(&self, nonce: &str) -> Result<ProbeReport> {
        let (mut s, _) = self.connect_hello().await?;
        match timeout(SHORT_RPC, self.rpc(&mut s, &GuestRequest::Probe { nonce: nonce.to_owned() }, 64 * 1024))
            .await
            .map_err(|_| AcfError::new(FailureClass::TimeoutUnknown, "guest probe timed out"))??
        {
            GuestResponse::Probe(p) if p.nonce == nonce => Ok(p),
            GuestResponse::Probe(_) => Err(AcfError::new(FailureClass::CorruptInput, "guest probe echoed the wrong nonce")),
            other => Err(AcfError::new(FailureClass::CorruptInput, format!("unexpected reply to Probe: {other:?}"))),
        }
    }

    pub async fn net_probe(&self) -> Result<NetReport> {
        let (mut s, _) = self.connect_hello().await?;
        match timeout(Duration::from_secs(15), self.rpc(&mut s, &GuestRequest::NetProbe, 64 * 1024))
            .await
            .map_err(|_| AcfError::new(FailureClass::TimeoutUnknown, "guest net probe timed out"))??
        {
            GuestResponse::NetProbe(r) => Ok(r),
            other => Err(AcfError::new(FailureClass::CorruptInput, format!("unexpected reply to NetProbe: {other:?}"))),
        }
    }

    async fn send_cancel(&self, exec_id: &str) {
        // Best effort on a *second* connection (the first is blocked awaiting the result).
        if let Ok((mut s, _)) = self.connect_hello().await {
            let _ = timeout(SHORT_RPC, self.rpc(&mut s, &GuestRequest::Cancel { exec_id: exec_id.to_owned() }, 64 * 1024)).await;
        }
    }

    pub async fn exec(&self, req: &GuestExecRequest, cancel: CancellationToken, backstop: &dyn VmBackstop) -> Result<GuestExecOutcome> {
        let cmd = &req.command;
        let max_frame = exec_frame_bound(&cmd.limits);
        let started = Instant::now();
        let host_deadline = started + Duration::from_millis(cmd.limits.timeout_ms) + req.grace;

        let (mut conn, _) = self.connect_hello().await?;
        let wire = GuestRequest::Exec(ExecRequest {
            exec_id: req.exec_id.clone(),
            argv: cmd.argv.clone(),
            env: cmd.env.clone(),
            cwd: cmd.cwd.clone(),
            timeout_ms: cmd.limits.timeout_ms,
            max_stdout_bytes: cmd.limits.max_stdout_bytes,
            max_stderr_bytes: cmd.limits.max_stderr_bytes,
            max_pids: cmd.limits.max_pids,
            uid: cmd.uid,
            gid: cmd.gid,
        });
        aio::send_json(&mut conn, &wire, REQUEST_FRAME_MAX).await.map_err(map_frame)?;

        // The response future must survive across select iterations (a partially read frame is
        // lost if it is dropped), so it is pinned once and polled by reference.
        let mut result_fut = Box::pin(aio::recv_json::<_, GuestResponse>(&mut conn, max_frame));
        let mut cancel_sent_at: Option<Instant> = None;
        let mut host_deadline_hit = false;
        let mut caller_cancelled = false;

        loop {
            let wake = cancel_sent_at.map_or(host_deadline, |t| t + req.grace);
            tokio::select! {
                r = &mut result_fut => {
                    let resp = r.map_err(map_frame)?;
                    return match resp {
                        GuestResponse::ExecResult(er) if er.exec_id == req.exec_id => {
                            let (er, _anomalies) = enforce_bounds(er, &cmd.limits);
                            Ok(GuestExecOutcome { result: er, host_deadline_hit, vm_killed: false })
                        }
                        GuestResponse::ExecResult(er) => Err(AcfError::new(
                            FailureClass::CorruptInput,
                            format!("guest answered exec `{}` while `{}` was in flight", er.exec_id, req.exec_id),
                        ).with_possible_side_effect()),
                        GuestResponse::Error { code, message } => Err(AcfError::new(
                            FailureClass::BackendUnavailable,
                            format!("guest refused exec ({code:?}): {message}"),
                        )),
                        other => Err(AcfError::new(FailureClass::CorruptInput, format!("unexpected reply to Exec: {other:?}")).with_possible_side_effect()),
                    };
                }
                () = cancel.cancelled(), if cancel_sent_at.is_none() => {
                    caller_cancelled = true;
                    self.send_cancel(&req.exec_id).await;
                    cancel_sent_at = Some(Instant::now());
                }
                () = sleep_until(wake) => {
                    if cancel_sent_at.is_none() {
                        // The guest should already have stopped itself at `timeout`; it has not.
                        host_deadline_hit = true;
                        self.send_cancel(&req.exec_id).await;
                        cancel_sent_at = Some(Instant::now());
                    } else {
                        // Cancel was sent and the grace period is over: the guest is not honouring
                        // anything. Take the VM down; the sandbox is no longer trustworthy.
                        drop(result_fut);
                        backstop.kill_vm().await.map_err(|e| e.with_possible_side_effect())?;
                        let status = if caller_cancelled && !host_deadline_hit { ExecStatus::Cancelled } else { ExecStatus::TimedOut };
                        return Ok(GuestExecOutcome {
                            result: synthesized(&req.exec_id, status, started.elapsed()),
                            host_deadline_hit,
                            vm_killed: true,
                        });
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::ResolvedCommand,
        guest::connector::{UdsTarget, UnixConnector},
    };
    use acf_guest::server::{Agent, AgentConfig};
    use acf_wire::frame::{recv_json, send_json};
    use std::{
        collections::BTreeMap,
        os::unix::net::UnixListener,
        path::{Path, PathBuf},
        sync::atomic::{AtomicBool, Ordering},
    };

    /// Run the *real* guest agent in-process on a Unix socket.
    fn real_agent(dir: &Path) -> PathBuf {
        std::fs::write(dir.join("boot_id"), "test-boot-id\n").unwrap();
        let path = dir.join("agent.sock");
        let l = UnixListener::bind(&path).unwrap();
        let agent = Arc::new(Agent::new(AgentConfig {
            boot_id_path: dir.join("boot_id"),
            canary_path: dir.join("canary"),
            allow_shutdown: false,
            cgroup_root: None,
            net_probe_targets: vec!["127.0.0.1:1".into()], // refused locally => Blocked, deterministic
            net_class_dir: dir.join("net"),
        }));
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let a = Arc::clone(&agent);
                std::thread::spawn(move || {
                    let mut c = c;
                    a.serve(&mut c);
                });
            }
        });
        path
    }

    fn client(path: &Path) -> GuestClient {
        GuestClient::new(Arc::new(UnixConnector { target: UdsTarget::direct(path), connect_timeout: Duration::from_secs(2) }))
    }

    fn req(id: &str, script: &str, timeout_ms: u64, grace_ms: u64) -> GuestExecRequest {
        GuestExecRequest {
            exec_id: id.into(),
            command: ResolvedCommand {
                argv: vec!["/bin/sh".into(), "-c".into(), script.into()],
                env: BTreeMap::from([("PATH".into(), "/usr/bin:/bin".into())]),
                cwd: "/".into(),
                limits: RunLimits { timeout_ms, max_pids: 4096, max_stdout_bytes: 4096, max_stderr_bytes: 4096 },
                uid: 0,
                gid: 0,
            },
            grace: Duration::from_millis(grace_ms),
        }
    }

    #[derive(Default)]
    struct Killer(AtomicBool);
    #[async_trait]
    impl VmBackstop for Killer {
        async fn kill_vm(&self) -> Result<()> {
            self.0.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn exec_roundtrip_against_the_real_agent() {
        let d = tempfile::tempdir().unwrap();
        let c = client(&real_agent(d.path()));
        let hello = c.wait_ready(Duration::from_secs(2)).await.unwrap();
        assert_eq!(hello.boot_id, "test-boot-id");
        let k = Killer::default();
        let out = c.exec(&req("e1", "echo hi; echo oops >&2; exit 3", 5000, 500), CancellationToken::new(), &k).await.unwrap();
        assert_eq!(out.result.status, ExecStatus::Exited { code: 3 });
        assert_eq!((out.result.stdout.as_slice(), out.result.stderr.as_slice()), (&b"hi\n"[..], &b"oops\n"[..]));
        assert!(!out.vm_killed && !out.host_deadline_hit && !k.0.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn output_is_truncated_at_the_cap_and_flagged() {
        let d = tempfile::tempdir().unwrap();
        let c = client(&real_agent(d.path()));
        let out = c
            .exec(&req("e2", "head -c 100000 /dev/zero | tr '\\0' x", 5000, 500), CancellationToken::new(), &Killer::default())
            .await
            .unwrap();
        assert_eq!(out.result.stdout.len(), 4096);
        assert!(out.result.stdout_truncated);
        assert_eq!(out.result.stdout_total_bytes, 100_000);
    }

    #[tokio::test]
    async fn guest_enforced_timeout_needs_no_backstop() {
        let d = tempfile::tempdir().unwrap();
        let c = client(&real_agent(d.path()));
        let k = Killer::default();
        let out = c.exec(&req("e3", "sleep 30", 300, 2000), CancellationToken::new(), &k).await.unwrap();
        assert_eq!(out.result.status, ExecStatus::TimedOut);
        assert!(!out.vm_killed && !k.0.load(Ordering::SeqCst), "an honest guest must not cost us the VM");
    }

    #[tokio::test]
    async fn caller_cancel_reaches_the_guest() {
        let d = tempfile::tempdir().unwrap();
        let c = client(&real_agent(d.path()));
        let token = CancellationToken::new();
        let t2 = token.clone();
        tokio::spawn(async move {
            sleep(Duration::from_millis(300)).await;
            t2.cancel();
        });
        let out = c.exec(&req("e4", "sleep 30", 60_000, 2000), token, &Killer::default()).await.unwrap();
        assert_eq!(out.result.status, ExecStatus::Cancelled);
        assert!(!out.vm_killed);
    }

    /// A guest that accepts Exec and then ignores the deadline and every Cancel.
    fn hung_agent(dir: &Path) -> PathBuf {
        let path = dir.join("hung.sock");
        let l = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                std::thread::spawn(move || {
                    let mut c = c;
                    loop {
                        let Ok(r) = recv_json::<_, GuestRequest>(&mut c, 1 << 20) else { return };
                        match r {
                            GuestRequest::Hello { .. } => {
                                let _ = send_json(
                                    &mut c,
                                    &GuestResponse::Hello {
                                        protocol_version: GUEST_PROTOCOL_VERSION,
                                        agent_version: "x".into(),
                                        boot_id: "b".into(),
                                    },
                                    1 << 20,
                                );
                            }
                            GuestRequest::Cancel { exec_id } => {
                                // acknowledges but does nothing — a hostile/hung guest
                                let _ = send_json(&mut c, &GuestResponse::Cancelled { exec_id, found: true }, 1 << 20);
                            }
                            _ => std::thread::sleep(Duration::from_secs(60)), // Exec: never answer
                        }
                    }
                });
            }
        });
        path
    }

    #[tokio::test]
    async fn host_backstop_kills_the_vm_when_the_guest_ignores_its_deadline() {
        let d = tempfile::tempdir().unwrap();
        let c = client(&hung_agent(d.path()));
        let k = Killer::default();
        let t = std::time::Instant::now();
        let out = c.exec(&req("e5", "ignored", 200, 300), CancellationToken::new(), &k).await.unwrap();
        assert!(out.vm_killed && out.host_deadline_hit && k.0.load(Ordering::SeqCst));
        assert_eq!(out.result.status, ExecStatus::TimedOut);
        assert!(out.result.output_incomplete, "we never saw the output, so it must say so");
        assert_eq!(out.result.containment, Containment::Unknown, "must not claim a mechanism it never observed");
        assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    }

    #[test]
    fn enforce_bounds_distrusts_a_lying_guest() {
        let limits = RunLimits { timeout_ms: 1, max_pids: 1, max_stdout_bytes: 10, max_stderr_bytes: 10 };
        let lying = ExecResult {
            exec_id: "x".into(),
            status: ExecStatus::Exited { code: 0 },
            stdout: vec![b'a'; 1000],
            stderr: vec![],
            stdout_total_bytes: 5, // claims fewer total bytes than it returned
            stderr_total_bytes: 0,
            stdout_truncated: false,
            stderr_truncated: false,
            duration_ms: 0,
            pid_limit_hit: false,
            output_incomplete: false,
            containment: Containment::Cgroup2,
        };
        let (fixed, anomalies) = enforce_bounds(lying, &limits);
        assert_eq!(fixed.stdout.len(), 10);
        assert!(fixed.stdout_truncated && fixed.stdout_total_bytes >= 1000);
        assert_eq!(anomalies.len(), 2, "{anomalies:?}");
    }

    #[test]
    fn frame_bound_scales_with_the_budget_and_never_exceeds_the_hard_cap() {
        let small = RunLimits { timeout_ms: 1, max_pids: 1, max_stdout_bytes: 100, max_stderr_bytes: 100 };
        let huge = RunLimits { timeout_ms: 1, max_pids: 1, max_stdout_bytes: u64::MAX / 2, max_stderr_bytes: u64::MAX / 2 };
        assert!(exec_frame_bound(&small) < 100_000);
        assert_eq!(exec_frame_bound(&huge), MAX_FRAME_HARD_CAP);
    }

    #[tokio::test]
    async fn oversized_guest_frame_is_rejected_by_the_bound_not_buffered() {
        // A server that answers Exec with a frame claiming 2 GiB.
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("evil.sock");
        let l = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                std::thread::spawn(move || {
                    use std::io::Write;
                    let mut c = c;
                    while let Ok(r) = recv_json::<_, GuestRequest>(&mut c, 1 << 20) {
                        match r {
                            GuestRequest::Hello { .. } => {
                                let _ = send_json(
                                    &mut c,
                                    &GuestResponse::Hello {
                                        protocol_version: GUEST_PROTOCOL_VERSION,
                                        agent_version: "x".into(),
                                        boot_id: "b".into(),
                                    },
                                    1 << 20,
                                );
                            }
                            _ => {
                                let _ = c.write_all(&(2u32 << 30).to_be_bytes());
                                return;
                            }
                        }
                    }
                });
            }
        });
        let e = client(&path).exec(&req("e6", "x", 5000, 500), CancellationToken::new(), &Killer::default()).await.unwrap_err();
        assert_eq!(e.class, FailureClass::OutputLimit);
        assert!(!e.is_definite(), "a command may have run, so the side effect is Possible");
    }
}
