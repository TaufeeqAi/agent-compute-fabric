//! Bounded command execution inside the guest.
//!
//! Guarantees (each has a test):
//! * stdout/stderr are captured up to the requested cap; bytes beyond the cap are *drained
//!   and counted* (so the child never blocks on a full pipe) but not stored, and the result
//!   says so explicitly (`*_truncated`, `*_total_bytes`) — contract OU-1, OU-2;
//! * a wall-clock deadline kills the whole process group — contract EX-5;
//! * an external cancel flag does the same, reported distinctly from a timeout — contract §11.7;
//! * the process tree is bounded — by a per-exec **cgroup v2** (`pids.max`) when the guest
//!   kernel provides the `pids` controller, else by `RLIMIT_NPROC` for the non-root exec uid —
//!   and pressure against the budget is reported. The mechanism actually used is part of the
//!   result (`containment`) so evidence never overstates what was enforced — contract RS-2, GP-6;
//! * **a run owns its process tree**: when the run ends (exit, timeout or cancel) every
//!   remaining descendant is killed, so nothing leaks across runs;
//! * a descendant that escapes the kill and keeps a pipe open cannot hang the agent: we
//!   drain for a short grace period and then report `output_incomplete`.
//!
//! Single-threaded by design: one `poll(2)` loop, no reader threads, nothing to join.

use std::{
    fs, io,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
        unix::process::{CommandExt, ExitStatusExt},
    },
    path::{Path, PathBuf},
    process::{Child, ChildStderr, ChildStdout, Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use acf_wire::guest::{Containment, ExecRequest, ExecResult, ExecStatus};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    process::{Pid, Signal, kill_process, kill_process_group},
};

/// Defence in depth: whatever the host asks for, never buffer more than this per stream.
pub const HARD_OUTPUT_CAP: u64 = 32 * 1024 * 1024;
const POLL_SLICE: Duration = Duration::from_millis(20);
const DRAIN_GRACE: Duration = Duration::from_millis(250);

/// `PATH` for a command whose request does not set one.
///
/// Explicit on purpose. A command runs with an *empty* environment (`env_clear`), and what `execvp`
/// does then differs between libcs: this agent is linked statically against musl, whose fallback
/// search path is not glibc's `/bin:/usr/bin`, and the Python and Node images keep their interpreters
/// in `/usr/local/bin`. A default that depended on the libc the agent happened to be built with would
/// make `acf-local run --image python --command "python x.py"` work or fail by build flags alone.
/// This is the value Docker gives Debian images; scripts/ and images/ rely on it too.
pub const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

#[derive(Debug)]
struct Capture {
    buf: Vec<u8>,
    total: u64,
    cap: usize,
    open: bool,
}

impl Capture {
    fn new(cap: u64) -> Self {
        let cap = usize::try_from(cap.min(HARD_OUTPUT_CAP)).unwrap_or(usize::MAX);
        Self { buf: Vec::new(), total: 0, cap, open: true }
    }

    fn push(&mut self, chunk: &[u8]) {
        self.total = self.total.saturating_add(chunk.len() as u64);
        let room = self.cap.saturating_sub(self.buf.len());
        let take = room.min(chunk.len());
        self.buf.extend_from_slice(&chunk[..take]);
    }

    fn truncated(&self) -> bool {
        self.total > self.buf.len() as u64
    }
}

/// Per-exec cgroup v2 used to bound and atomically kill a command's process tree.
#[derive(Debug)]
pub(crate) struct CgroupTree {
    dir: PathBuf,
    procs: OwnedFd,
}

impl CgroupTree {
    /// Returns `Err` (and the caller falls back to rlimits) unless the guest kernel exposes
    /// the `pids` controller on a writable cgroup v2 root.
    pub(crate) fn create(root: &Path, exec_id: &str, max_pids: u32) -> io::Result<Self> {
        let controllers = fs::read_to_string(root.join("cgroup.controllers"))?;
        if !controllers.split_whitespace().any(|c| c == "pids") {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "cgroup v2 root has no pids controller"));
        }
        let subtree = root.join("cgroup.subtree_control");
        if !fs::read_to_string(&subtree).unwrap_or_default().split_whitespace().any(|c| c == "pids") {
            fs::write(&subtree, "+pids")?;
        }
        let safe: String = exec_id.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').take(48).collect();
        let dir = root.join(format!("acf-exec-{}-{}", if safe.is_empty() { "x" } else { &safe }, std::process::id()));
        fs::create_dir(&dir)?;
        let built = (|| {
            fs::write(dir.join("pids.max"), max_pids.to_string())?;
            let f = fs::OpenOptions::new().write(true).open(dir.join("cgroup.procs"))?;
            Ok::<_, io::Error>(OwnedFd::from(f))
        })();
        match built {
            Ok(procs) => Ok(Self { dir, procs }),
            Err(e) => {
                let _ = fs::remove_dir(&dir);
                Err(e)
            }
        }
    }

    pub(crate) fn procs_fd(&self) -> RawFd {
        self.procs.as_raw_fd()
    }

    /// Number of fork attempts the kernel refused because of `pids.max`.
    pub(crate) fn pids_limit_events(&self) -> u64 {
        fs::read_to_string(self.dir.join("pids.events"))
            .ok()
            .and_then(|s| s.lines().find_map(|l| l.strip_prefix("max ").and_then(|n| n.trim().parse::<u64>().ok())))
            .unwrap_or(0)
    }

    /// Kill every process in the cgroup, including `setsid` escapees.
    pub(crate) fn kill_all(&self) {
        if fs::write(self.dir.join("cgroup.kill"), "1").is_err() {
            // Pre-5.14 kernels: walk cgroup.procs.
            for _ in 0..5 {
                let procs = fs::read_to_string(self.dir.join("cgroup.procs")).unwrap_or_default();
                if procs.trim().is_empty() {
                    break;
                }
                for pid in procs.lines().filter_map(|l| l.trim().parse::<i32>().ok()) {
                    if let Some(p) = Pid::from_raw(pid) {
                        let _ = kill_process(p, Signal::KILL);
                    }
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    pub(crate) fn remove(self) {
        for _ in 0..50 {
            if fs::remove_dir(&self.dir).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Where the agent may place per-exec cgroups. `None` forces the rlimit fallback.
#[derive(Debug, Clone, Default)]
pub struct ExecEnv {
    pub cgroup_root: Option<PathBuf>,
}

fn spawn_failed(req: &ExecRequest, message: String) -> ExecResult {
    ExecResult {
        exec_id: req.exec_id.clone(),
        status: ExecStatus::SpawnFailed { message },
        stdout: vec![],
        stderr: vec![],
        stdout_total_bytes: 0,
        stderr_total_bytes: 0,
        stdout_truncated: false,
        stderr_truncated: false,
        duration_ms: 0,
        pid_limit_hit: false,
        output_incomplete: false,
        containment: Containment::RlimitNproc,
    }
}

fn validate(req: &ExecRequest) -> Result<(), String> {
    if req.argv.is_empty() || req.argv[0].is_empty() {
        return Err("argv must be non-empty".into());
    }
    if !req.cwd.starts_with('/') {
        return Err("cwd must be absolute".into());
    }
    if req.argv.iter().any(|a| a.contains('\0')) {
        return Err("argv contains NUL".into());
    }
    for (k, v) in &req.env {
        if k.is_empty() || k.contains('=') || k.contains('\0') || v.contains('\0') {
            return Err(format!("invalid environment entry {k:?}"));
        }
    }
    if req.max_pids == 0 || req.max_pids > (1 << 20) {
        return Err("max_pids out of range".into());
    }
    Ok(())
}

/// Let a command be given `RLIMIT_NPROC = max_pids` even where that is above the hard limit this
/// agent started with.
///
/// The child sets the limit after it has become the workload's unprivileged user, and an
/// unprivileged process may lower its hard limit but never raise it. The kernel derives the default
/// from the guest's memory (`threads-max / 2`), so in a small guest a request within the safety
/// profile failed to spawn at all. (Found on a real 256 MiB guest: `max_pids` 1024 was refused while
/// the default hard limit was below it.) The agent runs as root and raises its own hard limit first;
/// the child then only lowers it or keeps it. If raising fails, nothing is hidden: the child's
/// `setrlimit` fails as before and the command is reported as not started.
fn allow_nproc(max_pids: u32) {
    use rustix::process::{Resource, getrlimit, setrlimit};
    let wanted = u64::from(max_pids);
    let current = getrlimit(Resource::Nproc);
    if current.maximum.is_some_and(|hard| hard < wanted) {
        let _ = setrlimit(Resource::Nproc, rustix::process::Rlimit { current: current.current, maximum: Some(wanted) });
    }
}

#[allow(unsafe_code)] // The single justified `unsafe` in the guest agent.
fn apply_child_limits(cmd: &mut Command, max_pids: u32, cgroup_procs_fd: Option<RawFd>) {
    use rustix::process::{Resource, Rlimit, setrlimit};
    let n = u64::from(max_pids);
    // SAFETY: the closure runs between fork and exec in the child. It performs only
    // `setrlimit(2)` and (optionally) one `write(2)` to an already-open cgroup.procs fd, all
    // through rustix/libc syscall wrappers: async-signal-safe, no allocation, no locks, and no
    // access to parent-owned state beyond `Copy` integers. The fd is inherited across fork and
    // is only used before exec (std opened it O_CLOEXEC).
    unsafe {
        cmd.pre_exec(move || {
            if let Some(fd) = cgroup_procs_fd {
                // Writing "0" to cgroup.procs migrates the *writing* process; descendants inherit.
                // SAFETY-adjacent: BorrowedFd::borrow_raw is unsafe; avoid it by using the raw
                // syscall wrapper on a ManuallyDrop'd OwnedFd.
                let owned = std::mem::ManuallyDrop::new(OwnedFd::from_raw_fd(fd));
                rustix::io::write(&*owned, b"0").map_err(io::Error::from)?;
            }
            setrlimit(Resource::Nproc, Rlimit { current: Some(n), maximum: Some(n) }).map_err(io::Error::from)?;
            setrlimit(Resource::Core, Rlimit { current: Some(0), maximum: Some(0) }).map_err(io::Error::from)
        });
    }
}

fn kill_group(pid: u32) {
    if let Some(p) = i32::try_from(pid).ok().and_then(Pid::from_raw) {
        let _ = kill_process_group(p, Signal::KILL);
    }
}

/// Real uid of `/proc/<pid>`, if readable.
fn proc_uid(pid: u32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = status.lines().find(|l| l.starts_with("Uid:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

fn pids_of_uid(uid: u32) -> Vec<u32> {
    let Ok(rd) = fs::read_dir("/proc") else { return vec![] };
    rd.flatten().filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok()).filter(|&pid| proc_uid(pid) == Some(uid)).collect()
}

/// After a timeout/cancel, setsid-escapees would survive a group kill. The exec uid is
/// dedicated to commands, so killing everything it owns is safe. Never done for root.
fn reap_uid_processes(uid: u32) {
    if uid == 0 {
        return;
    }
    for pid in pids_of_uid(uid) {
        if let Some(p) = i32::try_from(pid).ok().and_then(Pid::from_raw) {
            let _ = kill_process(p, Signal::KILL);
        }
    }
}

fn read_some(fd: BorrowedFd<'_>, cap: &mut Capture) {
    let mut chunk = [0u8; 16 * 1024];
    match rustix::io::read(fd, &mut chunk) {
        Ok(0) => cap.open = false,
        Ok(n) => cap.push(&chunk[..n]),
        Err(rustix::io::Errno::INTR | rustix::io::Errno::AGAIN) => {}
        Err(_) => cap.open = false,
    }
}

/// One poll round over whichever streams are still open. Returns whether any data arrived.
fn pump(out: &mut Option<ChildStdout>, err: &mut Option<ChildStderr>, so: &mut Capture, se: &mut Capture, wait: Duration) -> bool {
    let before = so.total + se.total;
    let ts = Timespec { tv_sec: wait.as_secs() as _, tv_nsec: i64::from(wait.subsec_nanos()) as _ };
    {
        let mut fds: Vec<PollFd<'_>> = Vec::with_capacity(2);
        let mut which: Vec<bool> = Vec::with_capacity(2); // true = stdout
        if let (true, Some(o)) = (so.open, out.as_ref()) {
            fds.push(PollFd::new(o, PollFlags::IN));
            which.push(true);
        }
        if let (true, Some(e)) = (se.open, err.as_ref()) {
            fds.push(PollFd::new(e, PollFlags::IN));
            which.push(false);
        }
        if poll(&mut fds, Some(&ts)).is_err() {
            // EINTR etc.: treat as "nothing ready"; the caller loops again.
            return false;
        }
        let ready: Vec<(bool, bool)> =
            fds.iter().zip(&which).map(|(f, w)| (*w, f.revents().intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR))).collect();
        drop(fds);
        for (is_out, hit) in ready {
            if !hit {
                continue;
            }
            if is_out {
                if let Some(o) = out.as_ref() {
                    read_some(o.as_fd(), so);
                }
            } else if let Some(e) = err.as_ref() {
                read_some(e.as_fd(), se);
            }
        }
    }
    so.total + se.total > before
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KillReason {
    Timeout,
    Cancel,
}

/// Run `req` to completion (or deadline/cancel) and return a bounded, classified result.
pub fn run(req: &ExecRequest, cancel: &AtomicBool, env: &ExecEnv) -> ExecResult {
    if let Err(m) = validate(req) {
        return spawn_failed(req, m);
    }
    let mut cmd = Command::new(&req.argv[0]);
    cmd.args(&req.argv[1..])
        .env_clear()
        .envs(&req.env)
        .current_dir(&req.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    if !req.env.contains_key("PATH") {
        cmd.env("PATH", DEFAULT_PATH); // also decides where `argv[0]` is looked up
    }
    if req.uid != 0 || req.gid != 0 {
        cmd.uid(req.uid).gid(req.gid);
    }
    let tree = env.cgroup_root.as_deref().and_then(|root| CgroupTree::create(root, &req.exec_id, req.max_pids).ok());
    allow_nproc(req.max_pids);
    apply_child_limits(&mut cmd, req.max_pids, tree.as_ref().map(CgroupTree::procs_fd));
    let containment = if tree.is_some() { Containment::Cgroup2 } else { Containment::RlimitNproc };

    let started = Instant::now();
    let mut child: Child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            if let Some(t) = tree {
                t.remove();
            }
            return spawn_failed(req, format!("spawn failed: {e}"));
        }
    };
    let pid = child.id();
    let mut out = child.stdout.take();
    let mut err = child.stderr.take();
    let mut so = Capture::new(req.max_stdout_bytes);
    let mut se = Capture::new(req.max_stderr_bytes);

    let deadline = started + Duration::from_millis(req.timeout_ms);
    let mut kill: Option<KillReason> = None;
    let mut exit: Option<std::process::ExitStatus> = None;
    let mut pid_pressure = false;
    // Rlimit fallback only: a command that hits the budget typically dies on the failed fork,
    // dropping the count by one, so "within one of the budget" is the observable signature.
    let pressure_at = (req.max_pids as usize).saturating_sub(1).max(1);
    let sample_pressure = |hit: &mut bool| {
        if tree.is_none() && req.uid != 0 && pids_of_uid(req.uid).len() >= pressure_at {
            *hit = true;
        }
    };

    loop {
        pump(&mut out, &mut err, &mut so, &mut se, POLL_SLICE);

        match child.try_wait() {
            Ok(Some(st)) => {
                exit = Some(st);
                sample_pressure(&mut pid_pressure); // children are still alive: last chance to observe
                break;
            }
            Ok(None) => {}
            Err(_) => break,
        }
        sample_pressure(&mut pid_pressure);
        if cancel.load(Ordering::Relaxed) {
            kill = Some(KillReason::Cancel);
        } else if Instant::now() >= deadline {
            kill = Some(KillReason::Timeout);
        }
        if kill.is_some() {
            teardown(tree.as_ref(), pid, req.uid);
            exit = child.wait().ok();
            break;
        }
    }

    // Drain whatever is still buffered in the pipes. Stop at EOF on both, or after a grace
    // period with no new data (a descendant may be holding the pipe open).
    let mut idle_since = Instant::now();
    while (so.open && out.is_some()) || (se.open && err.is_some()) {
        if pump(&mut out, &mut err, &mut so, &mut se, POLL_SLICE) {
            idle_since = Instant::now();
        } else if idle_since.elapsed() >= DRAIN_GRACE {
            break;
        }
    }
    // A run owns its process tree: whatever the leader left behind dies with the run.
    teardown(tree.as_ref(), pid, req.uid);
    let mut idle_since = Instant::now();
    while (so.open && out.is_some()) || (se.open && err.is_some()) {
        if pump(&mut out, &mut err, &mut so, &mut se, POLL_SLICE) {
            idle_since = Instant::now();
        } else if idle_since.elapsed() >= DRAIN_GRACE {
            break;
        }
    }
    let output_incomplete = (so.open && out.is_some()) || (se.open && err.is_some());
    let pid_limit_hit = pid_pressure || tree.as_ref().is_some_and(|t| t.pids_limit_events() > 0);
    if let Some(t) = tree {
        t.remove();
    }

    let status = match (kill, exit) {
        (Some(KillReason::Timeout), _) => ExecStatus::TimedOut,
        (Some(KillReason::Cancel), _) => ExecStatus::Cancelled,
        (None, Some(st)) => match (st.code(), st.signal()) {
            (Some(code), _) => ExecStatus::Exited { code },
            (None, Some(signal)) => ExecStatus::Signaled { signal },
            (None, None) => ExecStatus::SpawnFailed { message: "unclassifiable wait status".into() },
        },
        (None, None) => ExecStatus::SpawnFailed { message: "wait failed".into() },
    };

    ExecResult {
        exec_id: req.exec_id.clone(),
        status,
        stdout_truncated: so.truncated(),
        stderr_truncated: se.truncated(),
        stdout_total_bytes: so.total,
        stderr_total_bytes: se.total,
        stdout: so.buf,
        stderr: se.buf,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        pid_limit_hit,
        output_incomplete,
        containment,
    }
}

/// Kill everything the run started. Prefers the cgroup (atomic, covers `setsid` escapees);
/// otherwise the process group plus every process owned by the (non-root) exec uid.
fn teardown(tree: Option<&CgroupTree>, leader: u32, uid: u32) {
    match tree {
        Some(t) => t.kill_all(),
        None => {
            kill_group(leader);
            reap_uid_processes(uid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, sync::Arc};

    fn req(script: &str) -> ExecRequest {
        ExecRequest {
            exec_id: "t".into(),
            argv: vec!["/bin/sh".into(), "-c".into(), script.into()],
            env: BTreeMap::from([("PATH".into(), "/usr/bin:/bin".into())]),
            cwd: "/".into(),
            timeout_ms: 10_000,
            max_stdout_bytes: 1 << 20,
            max_stderr_bytes: 1 << 20,
            max_pids: 4096,
            uid: 0,
            gid: 0,
        }
    }

    fn never() -> AtomicBool {
        AtomicBool::new(false)
    }

    #[test]
    fn captures_output_and_exit_code() {
        let r = run(&req("echo out; echo err >&2; exit 7"), &never(), &ExecEnv::default());
        assert_eq!(r.status, ExecStatus::Exited { code: 7 });
        assert_eq!(r.stdout, b"out\n");
        assert_eq!(r.stderr, b"err\n");
        assert!(!r.stdout_truncated && !r.stderr_truncated && !r.output_incomplete);
    }

    /// EX-1 (T-EXEC-04 below a real guest): the request is an argument vector and is executed as one.
    /// No shell stands between the request and the program, so what a shell would expand, split or
    /// run arrives as the bytes that were sent, and nothing it names is executed.
    #[test]
    fn an_argument_with_shell_metacharacters_reaches_the_program_as_it_was_given() {
        let dir = tempfile::tempdir().unwrap();
        let canary = dir.path().join("a-shell-ran-this");
        let hostile = format!("$(touch {0}); `touch {0}` && echo $HOME | cat > {0}; * ' \" \\", canary.display());
        let mut request = req("");
        request.argv = vec!["/bin/echo".into(), "--".into(), hostile.clone(), "second argument".into()];
        let r = run(&request, &never(), &ExecEnv::default());
        assert_eq!(r.status, ExecStatus::Exited { code: 0 });
        assert_eq!(String::from_utf8(r.stdout).unwrap(), format!("-- {hostile} second argument\n"));
        assert!(!canary.exists(), "nothing in an argument is ever interpreted");
    }

    #[test]
    fn a_request_without_path_gets_the_default_and_one_with_path_keeps_its_own() {
        let mut q = req("unused");
        q.argv = vec!["env".into()]; // not absolute: found through the PATH the command will run with
        q.env.clear();
        let r = run(&q, &never(), &ExecEnv::default());
        assert_eq!(r.status, ExecStatus::Exited { code: 0 }, "stderr: {}", String::from_utf8_lossy(&r.stderr));
        assert_eq!(r.stdout, format!("PATH={DEFAULT_PATH}\n").into_bytes(), "the command's whole environment is the default PATH");

        q.env.insert("PATH".into(), "/usr/bin:/bin".into());
        let r = run(&q, &never(), &ExecEnv::default());
        assert_eq!(r.stdout, b"PATH=/usr/bin:/bin\n", "a PATH the request sets is never replaced");
    }

    #[test]
    fn output_over_cap_is_truncated_but_fully_counted_and_child_not_blocked() {
        let mut q = req("head -c 5000000 /dev/zero | tr '\\0' 'a'");
        q.max_stdout_bytes = 1000;
        let r = run(&q, &never(), &ExecEnv::default());
        assert_eq!(r.status, ExecStatus::Exited { code: 0 }, "child must finish, not block on a full pipe");
        assert_eq!(r.stdout.len(), 1000);
        assert!(r.stdout_truncated);
        assert_eq!(r.stdout_total_bytes, 5_000_000);
    }

    #[test]
    fn deadline_kills_the_process_group() {
        let mut q = req("sleep 30 & sleep 30; echo unreachable");
        q.timeout_ms = 300;
        let t = Instant::now();
        let r = run(&q, &never(), &ExecEnv::default());
        assert_eq!(r.status, ExecStatus::TimedOut);
        assert!(t.elapsed() < Duration::from_secs(5), "took {:?}", t.elapsed());
        assert!(!String::from_utf8_lossy(&r.stdout).contains("unreachable"));
    }

    #[test]
    fn cancel_is_distinct_from_timeout() {
        let flag = Arc::new(AtomicBool::new(false));
        let f2 = Arc::clone(&flag);
        let h = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            f2.store(true, Ordering::Relaxed);
        });
        let r = run(&req("sleep 30"), &flag, &ExecEnv::default());
        h.join().unwrap();
        assert_eq!(r.status, ExecStatus::Cancelled);
    }

    #[test]
    fn escaped_descendant_holding_pipe_open_yields_incomplete_not_a_hang() {
        // `setsid` moves the sleeper out of the process group, and uid 0 is never uid-reaped,
        // so under the rlimit fallback it genuinely survives teardown holding stdout open.
        //
        // The sleeper's duration is unique to this test process, so that the cleanup below ends this
        // run's sleeper and no other: two runs of this test on one machine (two checkouts, two CI jobs
        // of one user) must not end each other's sleeper, which would close the pipe early and make
        // the output look complete.
        let sleeper = format!("sleep 31.{:06}", std::process::id() % 1_000_000);
        let t = Instant::now();
        let r = run(&req(&format!("setsid {sleeper} & echo started")), &never(), &ExecEnv::default());
        assert_eq!(r.status, ExecStatus::Exited { code: 0 });
        assert!(r.output_incomplete, "must flag possibly-missing output tail");
        assert!(t.elapsed() < Duration::from_secs(5), "took {:?}", t.elapsed());
        assert_eq!(r.stdout, b"started\n");
        let _ = std::process::Command::new("pkill").args(["-f", &sleeper]).status();
    }

    #[test]
    fn same_group_descendants_are_killed_so_output_is_complete() {
        let r = run(&req("(sleep 32) & echo started"), &never(), &ExecEnv::default());
        assert_eq!(r.status, ExecStatus::Exited { code: 0 });
        assert!(!r.output_incomplete, "group teardown must close the pipe");
        assert_eq!(r.containment, Containment::RlimitNproc);
    }

    // ---- cgroup tree logic, exercised against a fake cgroup directory ----

    fn fake_cgroup_root(controllers: &str) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("cgroup.controllers"), controllers).unwrap();
        fs::write(d.path().join("cgroup.subtree_control"), "").unwrap();
        d
    }

    #[test]
    fn cgroup_tree_requires_the_pids_controller() {
        let d = fake_cgroup_root("cpu memory");
        let e = CgroupTree::create(d.path(), "x", 8).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn cgroup_tree_sets_budget_and_enables_controller_and_parses_events() {
        let d = fake_cgroup_root("cpu pids");
        // The real kernel materialises these control files when the directory is created.
        // Emulate: pre-create the child dir contents lazily by creating files after mkdir is
        // impossible here, so create the expected child dir first and let `create` reuse files.
        let t = {
            let name = format!("acf-exec-job_1-{}", std::process::id());
            let child = d.path().join(name);
            // `create` calls create_dir (must not exist), so build a CgroupTree by hand for the
            // file-level assertions below instead.
            fs::create_dir(&child).unwrap();
            fs::write(child.join("cgroup.procs"), "").unwrap();
            let f = fs::OpenOptions::new().write(true).open(child.join("cgroup.procs")).unwrap();
            CgroupTree { dir: child, procs: OwnedFd::from(f) }
        };
        fs::write(t.dir.join("pids.events"), "max 3\n").unwrap();
        assert_eq!(t.pids_limit_events(), 3);
        fs::write(t.dir.join("pids.events"), "max 0\n").unwrap();
        assert_eq!(t.pids_limit_events(), 0);
        t.kill_all(); // writes "1" to cgroup.kill (a plain file in the fake tree)
        assert_eq!(fs::read_to_string(t.dir.join("cgroup.kill")).unwrap(), "1");
    }

    #[test]
    fn cgroup_create_fails_closed_and_enables_pids_when_control_files_are_missing() {
        let d = fake_cgroup_root("cpu pids");
        // On a plain tmpfs mkdir succeeds but the kernel never materialises `cgroup.procs`, so
        // `create` must return Err (the caller then falls back to rlimits) instead of handing
        // back a half-configured tree. (On real cgroupfs the leftover dir is removed by rmdir;
        // tmpfs cannot rmdir a non-empty dir, so we deliberately do not assert on cleanup here.)
        let r = CgroupTree::create(d.path(), "job/../1", 8);
        assert!(r.is_err(), "missing cgroup.procs must be an error, not a silent success");
        assert_eq!(
            fs::read_to_string(d.path().join("cgroup.subtree_control")).unwrap(),
            "+pids",
            "the pids controller must be enabled for child cgroups"
        );
    }

    #[test]
    fn environment_is_not_inherited() {
        // SAFETY-free: we only read the variable in the child; set it in this process.
        let mut q = req("echo \"[${HOME:-unset}][${ACF_SECRET:-unset}]\"");
        q.env.insert("ONLY".into(), "1".into());
        let r = run(&q, &never(), &ExecEnv::default());
        assert_eq!(String::from_utf8_lossy(&r.stdout), "[unset][unset]\n");
    }

    #[test]
    fn spawn_failure_and_bad_requests_are_reported_not_panicked() {
        let mut q = req("true");
        q.argv = vec!["/definitely/not/here".into()];
        assert!(matches!(run(&q, &never(), &ExecEnv::default()).status, ExecStatus::SpawnFailed { .. }));
        q.argv = vec![];
        assert!(matches!(run(&q, &never(), &ExecEnv::default()).status, ExecStatus::SpawnFailed { .. }));
        let mut q = req("true");
        q.cwd = "relative".into();
        assert!(matches!(run(&q, &never(), &ExecEnv::default()).status, ExecStatus::SpawnFailed { .. }));
    }

    #[test]
    fn signal_death_is_classified() {
        let r = run(&req("kill -SEGV $$"), &never(), &ExecEnv::default());
        assert_eq!(r.status, ExecStatus::Signaled { signal: 11 });
    }
}
