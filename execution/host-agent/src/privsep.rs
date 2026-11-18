//! Privilege separation (contract §6.1): the roles of the one host binary are separate processes
//! with different privileges, connected by channels the privileged core created.
//!
//! * The **edge** (PD-1) and the **guest-traffic** role (PD-3) read bytes from parties the host does
//!   not trust. They run as unprivileged users with no capabilities and `no_new_privs`, and they
//!   *verify that about themselves* before reading a single byte ([`assert_unprivileged`]): a role
//!   started with privilege by mistake refuses to run.
//! * The core spawns a role by re-executing its own binary image (`/proc/self/exe`, so an upgrade of
//!   the file on disk cannot make two roles of one activation run different code), with an empty
//!   environment, and hands it what it needs — configuration and already-open sockets — over a
//!   socket pair. The role opens nothing by name.
//!
//! No `unsafe` is needed: identity is dropped by the standard library's `Command::uid/gid` (which
//! also clears supplementary groups when the parent is root), and descriptors travel as
//! `SCM_RIGHTS` through `rustix`.

use std::{
    io::{IoSlice, IoSliceMut},
    mem::MaybeUninit,
    os::{
        fd::{AsFd, BorrowedFd, OwnedFd},
        unix::{net::UnixStream, process::CommandExt},
    },
    process::{Child, Command, Stdio},
};

use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer, SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};

use crate::error::{AcfError, Result};

/// Most descriptors one message carries.
pub const MAX_PASSED_FDS: usize = 4;

/// The unprivileged identity a role runs as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleIdentity {
    pub uid: u32,
    pub gid: u32,
}

/// Spawn `role` (a subcommand of this binary) and return it with the core's end of its channel.
///
/// `identity` is required when the caller is root; when the caller is itself unprivileged (tests,
/// the in-memory test host) the role simply inherits that identity.
pub fn spawn_role(role: &str, args: &[&str], identity: Option<RoleIdentity>) -> Result<(Child, UnixStream)> {
    let (core_end, role_end) = UnixStream::pair()?;
    let mut cmd = Command::new("/proc/self/exe");
    cmd.arg(role).args(args).env_clear().current_dir("/").stdin(Stdio::from(OwnedFd::from(role_end)));
    // Diagnostics only: the role's stdout and stderr go where the core's go.
    for var in ["ACF_LOG_FORMAT", "RUST_LOG"] {
        if let Some(v) = std::env::var_os(var) {
            cmd.env(var, v);
        }
    }
    if let Some(id) = identity_to_assume(role, identity, rustix::process::geteuid().is_root())? {
        // With a root parent the standard library also calls `setgroups(0)`: no supplementary
        // group survives. The kernel then clears every capability set at the uid change.
        cmd.uid(id.uid).gid(id.gid);
    }
    let child = cmd.spawn().map_err(|e| AcfError::internal(format!("cannot start role `{role}`: {e}")))?;
    Ok((child, core_end))
}

/// The identity a role must switch to, if any. A root core never starts a role as root: it needs an
/// identity for it, and that identity is neither uid 0 nor gid 0. A core that is itself unprivileged
/// (tests, the in-memory test host) cannot switch, and the role inherits its identity.
fn identity_to_assume(role: &str, identity: Option<RoleIdentity>, core_is_root: bool) -> Result<Option<RoleIdentity>> {
    match (identity, core_is_root) {
        (Some(id), true) if id.uid == 0 || id.gid == 0 => Err(AcfError::security(format!("role `{role}` must not run as uid or gid 0"))),
        (Some(id), true) => Ok(Some(id)),
        (None, true) => Err(AcfError::security(format!("role `{role}` needs an unprivileged identity: the core runs as root"))),
        (_, false) => Ok(None),
    }
}

/// The channel a role was started with: its standard input.
pub fn role_channel() -> Result<UnixStream> {
    let fd = std::io::stdin().as_fd().try_clone_to_owned()?;
    Ok(UnixStream::from(fd))
}

fn hex_field(status: &str, key: &str) -> Option<u64> {
    status.lines().find_map(|l| l.strip_prefix(key)).and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
}

/// What `/proc/self/status` says about privilege. Pure, so it is unit-tested with fixture text.
pub fn privilege_violations(status: &str, euid: u32) -> Vec<String> {
    let mut v = Vec::new();
    if euid == 0 {
        v.push("the process runs as uid 0".to_owned());
    }
    for set in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
        match hex_field(status, set) {
            Some(0) => {}
            Some(bits) => v.push(format!("{} is {bits:#x}, not empty", set.trim_end_matches(':'))),
            None => v.push(format!("{} could not be read", set.trim_end_matches(':'))),
        }
    }
    let nnp = status.lines().find_map(|l| l.strip_prefix("NoNewPrivs:")).map(str::trim);
    if nnp != Some("1") {
        v.push("no_new_privs is not set".to_owned());
    }
    v
}

/// The calling thread's own status. `no_new_privs` and the capability sets are per thread, so
/// the process-wide `/proc/self/status` (the main thread's) would answer a different question.
fn thread_status() -> Result<String> {
    std::fs::read_to_string("/proc/thread-self/status").map_err(|e| AcfError::security(format!("cannot read own status: {e}")))
}

/// PD-1 / PD-3: the calling thread proves, by observation, that it holds nothing needed for host
/// mutation. Changes nothing.
pub fn verify_unprivileged(role: &str) -> Result<()> {
    let bad = privilege_violations(&thread_status()?, rustix::process::geteuid().as_raw());
    if bad.is_empty() {
        Ok(())
    } else {
        Err(AcfError::security(format!("role `{role}` refuses to run with privilege: {}", bad.join("; "))))
    }
}

/// Set `no_new_privs` on the calling thread (irreversible), then [`verify_unprivileged`].
pub fn assert_unprivileged(role: &str) -> Result<()> {
    rustix::thread::set_no_new_privs(true).map_err(|e| AcfError::security(format!("cannot set no_new_privs: {e}")))?;
    verify_unprivileged(role)
}

/// The **first** thing a role's process does, before it starts a runtime or any other thread.
///
/// `no_new_privs` is inherited by threads created afterwards and by no thread that already exists.
/// A role therefore sets it while it is still single-threaded, so that every thread it will ever
/// have carries it; started any later, a worker thread could be left without it. The role checks
/// again, on the thread that serves, before it reads a byte ([`verify_unprivileged`]).
pub fn enter_role(role: &str) -> Result<()> {
    let status = thread_status()?;
    let threads = status.lines().find_map(|l| l.strip_prefix("Threads:")).and_then(|v| v.trim().parse::<u32>().ok());
    if threads != Some(1) {
        return Err(AcfError::security(format!("role `{role}` must drop privilege before any other thread exists (threads: {threads:?})")));
    }
    assert_unprivileged(role)
}

/// The roles of the one binary that read untrusted bytes (INV-024, INV-025).
pub fn is_untrusted_input_role(role: &str) -> bool {
    matches!(role, "edge" | "guest-traffic")
}

/// Send `payload` and `fds` in one message.
pub fn send_with_fds(sock: &UnixStream, payload: &[u8], fds: &[BorrowedFd<'_>]) -> Result<()> {
    if fds.len() > MAX_PASSED_FDS || payload.is_empty() {
        return Err(AcfError::internal("a descriptor message needs a payload and at most a few descriptors"));
    }
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_PASSED_FDS))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    if !fds.is_empty() && !control.push(SendAncillaryMessage::ScmRights(fds)) {
        return Err(AcfError::internal("descriptors do not fit the control buffer"));
    }
    let sent = sendmsg(sock, &[IoSlice::new(payload)], &mut control, SendFlags::empty())?;
    if sent != payload.len() {
        return Err(AcfError::internal("a descriptor message was sent short"));
    }
    Ok(())
}

/// Receive one message of at most `max_payload` bytes and the descriptors that came with it.
pub fn recv_with_fds(sock: &UnixStream, max_payload: usize) -> Result<(Vec<u8>, Vec<OwnedFd>)> {
    let mut buf = vec![0u8; max_payload];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_PASSED_FDS))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let got = recvmsg(sock, &mut [IoSliceMut::new(&mut buf)], &mut control, RecvFlags::CMSG_CLOEXEC)?;
    let mut fds = Vec::new();
    for msg in control.drain() {
        if let RecvAncillaryMessage::ScmRights(received) = msg {
            fds.extend(received);
        }
    }
    if got.bytes == 0 {
        return Err(AcfError::internal("the channel closed before the descriptors arrived"));
    }
    buf.truncate(got.bytes);
    Ok((buf, fds))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    const UNPRIVILEGED: &str = "Name:\tacf-host\nUid:\t1000\t1000\t1000\t1000\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t0\n";

    #[test]
    fn an_unprivileged_process_with_no_new_privs_passes() {
        assert_eq!(privilege_violations(UNPRIVILEGED, 1000), Vec::<String>::new());
    }

    #[test]
    fn every_kind_of_privilege_is_a_violation() {
        assert!(privilege_violations(UNPRIVILEGED, 0).iter().any(|v| v.contains("uid 0")));
        for set in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
            let with_cap = UNPRIVILEGED.replace(&format!("{set}:\t0000000000000000"), &format!("{set}:\t0000000000200000"));
            let bad = privilege_violations(&with_cap, 1000);
            assert!(bad.iter().any(|v| v.contains(set)), "{set}: {bad:?}");
        }
        let no_nnp = UNPRIVILEGED.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0");
        assert!(privilege_violations(&no_nnp, 1000).iter().any(|v| v.contains("no_new_privs")));
        let unreadable = privilege_violations("Name:\tx\n", 1000);
        assert_eq!(unreadable.len(), 5, "what cannot be read is not assumed safe: {unreadable:?}");
    }

    #[test]
    fn this_test_thread_can_prove_itself_unprivileged_or_is_refused() {
        // As an ordinary user the check passes; as root (or with capabilities) it must refuse.
        let privileged = rustix::process::geteuid().is_root();
        assert_eq!(assert_unprivileged("test").is_err(), privileged);
        assert_eq!(verify_unprivileged("test").is_err(), privileged, "the check alone agrees once the flag is set");
    }

    #[test]
    fn no_new_privs_is_per_thread_which_is_why_a_role_sets_it_before_it_has_threads() {
        // A thread that never set the flag does not have it, whatever another thread did...
        let fresh = std::thread::spawn(|| privilege_violations(&thread_status().unwrap(), 1000)).join().unwrap();
        assert!(fresh.iter().any(|v| v.contains("no_new_privs")), "{fresh:?}");
        // ...and a thread created by one that set it inherits it.
        let inherited = std::thread::spawn(|| {
            rustix::thread::set_no_new_privs(true).unwrap();
            std::thread::spawn(|| privilege_violations(&thread_status().unwrap(), 1000)).join().unwrap()
        })
        .join()
        .unwrap();
        assert!(!inherited.iter().any(|v| v.contains("no_new_privs")), "{inherited:?}");
        // A process that already has threads (this test process does) cannot enter a role.
        assert!(enter_role("edge").is_err());
        assert!(is_untrusted_input_role("edge") && is_untrusted_input_role("guest-traffic") && !is_untrusted_input_role("serve"));
    }

    #[test]
    fn descriptors_travel_with_their_message() {
        let (a, b) = UnixStream::pair().unwrap();
        let (mut carried_a, carried_b) = UnixStream::pair().unwrap();
        send_with_fds(&a, b"listener", &[carried_b.as_fd()]).unwrap();
        drop(carried_b);
        let (payload, mut fds) = recv_with_fds(&b, 64).unwrap();
        assert_eq!(payload, b"listener");
        assert_eq!(fds.len(), 1);
        // The received descriptor is the same socket: what is written on one end arrives on it.
        let mut received = UnixStream::from(fds.remove(0));
        carried_a.write_all(b"ping").unwrap();
        let mut got = [0u8; 4];
        received.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"ping");
    }

    #[test]
    fn a_closed_channel_is_an_error_not_an_empty_message() {
        let (a, b) = UnixStream::pair().unwrap();
        drop(a);
        assert!(recv_with_fds(&b, 16).is_err());
        let (a, _b) = UnixStream::pair().unwrap();
        assert!(send_with_fds(&a, b"", &[]).is_err(), "an empty payload cannot carry descriptors");
    }

    #[test]
    fn a_root_core_never_starts_a_role_as_root_or_without_an_identity() {
        let edge = RoleIdentity { uid: 990, gid: 990 };
        assert_eq!(identity_to_assume("edge", Some(edge), true).unwrap(), Some(edge));
        assert!(identity_to_assume("edge", None, true).is_err(), "a root core must give the role an identity");
        for id in [RoleIdentity { uid: 0, gid: 0 }, RoleIdentity { uid: 0, gid: 990 }, RoleIdentity { uid: 990, gid: 0 }] {
            assert!(identity_to_assume("edge", Some(id), true).is_err(), "{id:?} is root");
        }
        // An unprivileged core cannot change identity: the role runs as the core does.
        assert_eq!(identity_to_assume("edge", Some(edge), false).unwrap(), None);
        assert_eq!(identity_to_assume("edge", None, false).unwrap(), None);
    }
}
