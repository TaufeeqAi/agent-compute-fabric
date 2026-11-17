//! Building and launching the Firecracker **jailer** (spec §17).
//!
//! The jailer is what turns "a VMM process" into a contained one: it chroots, creates a PID
//! namespace, joins the (empty) network namespace, creates the per-VM cgroup, drops to a unique
//! unprivileged uid/gid, and only then execs Firecracker (which installs its own seccomp filters).
//! We never bypass it and never pass `--no-seccomp`.

use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use tokio::{process::Command, time::timeout};

use crate::{
    config::FirecrackerConfig,
    error::{AcfError, FailureClass, Result},
    operation::ProcessIdentity,
    process::{SecurityPosture, identity},
};

/// API socket path **inside** the jail (the VMM sees `/` as the jail root).
pub const API_SOCK: &str = "/api.sock";
/// Vsock device UDS path inside the jail.
pub const VSOCK_SOCK: &str = "/v.sock";
pub const PID_FILE: &str = "firecracker.pid";

#[derive(Debug, Clone)]
pub struct JailerArgs<'a> {
    pub cfg: &'a FirecrackerConfig,
    pub jail_id: &'a str,
    pub uid: u32,
    pub gid: u32,
    pub chroot_base: &'a Path,
    pub netns: Option<&'a Path>,
    /// Pre-built `--cgroup k=v` flag tokens (see `process::limits::CgroupSpec::jailer_args`).
    pub cgroup_args: Vec<String>,
    pub nofile: u64,
    /// Caps the size of any file the VMM may write (log/metrics/snapshot growth).
    pub fsize_bytes: u64,
}

impl JailerArgs<'_> {
    /// Exact argv (excluding the program). Order is stable so tests can pin it.
    pub fn argv(&self) -> Vec<String> {
        let s = |x: &str| x.to_owned();
        let mut a = vec![
            s("--id"),
            s(self.jail_id),
            s("--exec-file"),
            self.cfg.firecracker_bin.display().to_string(),
            s("--uid"),
            self.uid.to_string(),
            s("--gid"),
            self.gid.to_string(),
            s("--chroot-base-dir"),
            self.chroot_base.display().to_string(),
            s("--cgroup-version"),
            s("2"),
            s("--parent-cgroup"),
            self.cfg.cgroup_parent.clone(),
        ];
        a.extend(self.cgroup_args.iter().cloned());
        if let Some(ns) = self.netns {
            a.push(s("--netns"));
            a.push(ns.display().to_string());
        }
        a.extend([
            s("--resource-limit"),
            format!("no-file={}", self.nofile),
            s("--resource-limit"),
            format!("fsize={}", self.fsize_bytes),
            s("--new-pid-ns"),
            s("--daemonize"),
            s("--"),
            s("--api-sock"),
            s(API_SOCK),
        ]);
        a
    }
}

/// `<base>/<basename(exec-file)>/<id>/root` — the layout the jailer creates.
pub fn chroot_root(base: &Path, firecracker_bin: &Path, jail_id: &str) -> PathBuf {
    let exec_name = firecracker_bin.file_name().map_or_else(|| "firecracker".into(), |n| n.to_os_string());
    base.join(exec_name).join(jail_id).join("root")
}

/// Run the jailer. With `--daemonize` it returns as soon as the VMM has been forked off.
pub async fn launch(cfg: &FirecrackerConfig, args: &JailerArgs<'_>) -> Result<()> {
    let mut cmd = Command::new(&cfg.jailer_bin);
    cmd.args(args.argv()).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).kill_on_drop(true);
    let child = cmd
        .spawn()
        .map_err(|e| AcfError::new(FailureClass::BackendUnavailable, format!("cannot execute jailer {}: {e}", cfg.jailer_bin.display())))?;
    let out = match timeout(Duration::from_millis(cfg.api_ready_timeout_ms.max(10_000)), child.wait_with_output()).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return Err(AcfError::new(FailureClass::BackendCrash, format!("jailer wait failed: {e}")).with_possible_side_effect()),
        Err(_) => return Err(AcfError::new(FailureClass::TimeoutUnknown, "jailer did not return in time").with_possible_side_effect()),
    };
    if out.status.success() {
        return Ok(());
    }
    let stderr: String = String::from_utf8_lossy(&out.stderr).chars().take(1500).collect();
    // The jailer may have created the chroot/cgroup before failing; cleanup is idempotent.
    Err(AcfError::new(FailureClass::BackendCrash, format!("jailer exited with {}: {}", out.status, stderr.trim()))
        .with_possible_side_effect())
}

/// Reading `/proc` about the VMM — behind a trait so tests can script it, while production uses
/// the real kernel view.
pub trait ProcessInspector: Send + Sync + std::fmt::Debug {
    fn identity(&self, pid: i32, boot_id: &str) -> Result<ProcessIdentity>;
    fn posture(&self, pid: i32, jail_root: &Path) -> Result<SecurityPosture>;
    fn in_netns(&self, pid: i32, ns_path: &Path) -> bool;
    fn cmdline_has(&self, pid: i32, needle: &str) -> bool;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ProcInspector;

impl ProcessInspector for ProcInspector {
    fn identity(&self, pid: i32, boot_id: &str) -> Result<ProcessIdentity> {
        identity::capture(pid, boot_id)
    }
    fn posture(&self, pid: i32, jail_root: &Path) -> Result<SecurityPosture> {
        identity::read_posture(pid, jail_root)
    }
    fn in_netns(&self, pid: i32, ns_path: &Path) -> bool {
        crate::network::Netns::process_is_inside(pid, ns_path)
    }
    fn cmdline_has(&self, pid: i32, needle: &str) -> bool {
        identity::cmdline_has(pid, needle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::test_support::config,
        domain::{NetworkMode, SandboxResources},
        process::CgroupSpec,
    };

    #[test]
    fn argv_is_exact_and_never_disables_security_controls() {
        let d = tempfile::tempdir().unwrap();
        let cfg = config(d.path());
        let cg = CgroupSpec::for_sandbox(&SandboxResources { vcpus: 2, memory_mib: 512, disk_mib: 1024, network: NetworkMode::None }, 64);
        let ns = PathBuf::from("/run/acf/netns/acf-x");
        let args = JailerArgs {
            cfg: &cfg.firecracker,
            jail_id: "sbx-aaaa-g1",
            uid: 100_003,
            gid: 100_003,
            chroot_base: Path::new("/var/lib/acf/sandboxes/s/1/jail"),
            netns: Some(&ns),
            cgroup_args: cg.jailer_args(),
            nofile: 1024,
            fsize_bytes: 2_000_000_000,
        };
        let a = args.argv();
        let joined = a.join(" ");
        let must = [
            "--id sbx-aaaa-g1",
            "--exec-file /opt/acf/bin/firecracker",
            "--uid 100003 --gid 100003",
            "--chroot-base-dir /var/lib/acf/sandboxes/s/1/jail",
            "--cgroup-version 2 --parent-cgroup acf",
            "--cgroup cpu.max=225000 100000",
            "--cgroup memory.swap.max=0",
            "--netns /run/acf/netns/acf-x",
            "--resource-limit no-file=1024 --resource-limit fsize=2000000000",
            "--new-pid-ns --daemonize -- --api-sock /api.sock",
        ];
        for m in must {
            assert!(joined.contains(m), "missing `{m}` in `{joined}`");
        }
        for forbidden in ["--no-seccomp", "--seccomp-filter", "--seccomp-level", "--no-api"] {
            assert!(!joined.contains(forbidden), "{forbidden} must never be passed");
        }
        assert_eq!(a.last().map(String::as_str), Some("/api.sock"));
        // Everything after `--` belongs to Firecracker; nothing security-relevant may hide there.
        let after: Vec<_> = a.iter().skip_while(|x| *x != "--").skip(1).collect();
        assert_eq!(after, ["--api-sock", "/api.sock"]);
    }

    #[test]
    fn root_path_matches_the_jailer_layout() {
        let p = chroot_root(Path::new("/b"), Path::new("/opt/acf/bin/firecracker"), "id1");
        assert_eq!(p, PathBuf::from("/b/firecracker/id1/root"));
    }

    #[test]
    fn netns_flag_is_omitted_when_there_is_none() {
        let d = tempfile::tempdir().unwrap();
        let cfg = config(d.path());
        let a = JailerArgs {
            cfg: &cfg.firecracker,
            jail_id: "x",
            uid: 1,
            gid: 1,
            chroot_base: Path::new("/b"),
            netns: None,
            cgroup_args: vec![],
            nofile: 1,
            fsize_bytes: 1,
        }
        .argv();
        assert!(!a.iter().any(|x| x == "--netns"));
    }

    #[tokio::test]
    async fn launch_surfaces_a_failing_jailer_with_its_stderr_and_marks_side_effect_possible() {
        let d = tempfile::tempdir().unwrap();
        let script = d.path().join("jailer");
        std::fs::write(&script, "#!/bin/sh\necho 'cgroup parent missing' >&2\nexit 3\n").unwrap();
        std::os::unix::fs::PermissionsExt::set_mode(&mut std::fs::metadata(&script).unwrap().permissions(), 0o755);
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let mut cfg = config(d.path());
        cfg.firecracker.jailer_bin = script;
        let args = JailerArgs {
            cfg: &cfg.firecracker,
            jail_id: "x",
            uid: 1,
            gid: 1,
            chroot_base: Path::new("/b"),
            netns: None,
            cgroup_args: vec![],
            nofile: 1,
            fsize_bytes: 1,
        };
        let e = launch(&cfg.firecracker, &args).await.unwrap_err();
        assert_eq!(e.class, FailureClass::BackendCrash);
        assert!(e.message.contains("cgroup parent missing"), "{}", e.message);
        assert!(!e.is_definite(), "the jailer may have created a chroot/cgroup before failing");
    }
}
