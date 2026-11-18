//! Host-enforced resource limits and observed evidence (contract RS-2).
//!
//! CPU, memory and process count are bounded by a **per-sandbox cgroup v2** created by the
//! jailer from the flags built here, in addition to the hard VM boundary Firecracker gives
//! (`vcpu_count`, `mem_size_mib`). Disk is bounded by the fixed-size backing file. Evidence is
//! read back from the same cgroup afterwards, so "the limit was X and the peak was Y" comes from
//! the kernel, not from the guest.

use std::{fs, path::Path};

use sha2::{Digest, Sha256};

use crate::domain::{ResourceEvidence, SandboxResources};

const CPU_PERIOD_US: u64 = 100_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupSpec {
    /// `cpu.max` value, e.g. `"200000 100000"`.
    pub cpu_max: String,
    pub memory_max_bytes: u64,
    pub pids_max: u32,
}

impl CgroupSpec {
    /// Guest memory is bounded by `mem_size_mib`; the cgroup must also allow the VMM's own
    /// overhead or the OOM killer would hit Firecracker itself under normal load.
    pub fn for_sandbox(res: &SandboxResources, vmm_overhead_mib: u32) -> Self {
        let vcpus = u64::from(res.vcpus);
        Self {
            // vCPU threads plus a quarter core for the VMM's device-emulation threads.
            cpu_max: format!("{} {CPU_PERIOD_US}", vcpus * CPU_PERIOD_US + CPU_PERIOD_US / 4),
            memory_max_bytes: (u64::from(res.memory_mib) + u64::from(vmm_overhead_mib)) * 1024 * 1024,
            // vCPU threads + API + emulation + seccomp/housekeeping headroom.
            pids_max: u32::from(res.vcpus) + 32,
        }
    }

    /// `--cgroup <file>=<value>` flags for the jailer (cgroup v2 file names).
    pub fn jailer_args(&self) -> Vec<String> {
        let mut a = Vec::new();
        for kv in [
            format!("cpu.max={}", self.cpu_max),
            format!("memory.max={}", self.memory_max_bytes),
            "memory.swap.max=0".to_owned(),  // never page guest memory to host swap
            "memory.oom.group=1".to_owned(), // an OOM takes the whole VMM, not a random thread
            format!("pids.max={}", self.pids_max),
        ] {
            a.push("--cgroup".to_owned());
            a.push(kv);
        }
        a
    }

    /// Stable identity of these settings, recorded in the runtime manifest (contract IS-2).
    pub fn identity(&self) -> String {
        let mut h = Sha256::new();
        for a in self.jailer_args() {
            h.update(a.as_bytes());
            h.update([0]);
        }
        hex::encode(h.finalize())[..16].to_owned()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CgroupStats {
    pub cpu_usage_usec: Option<u64>,
    pub memory_peak_bytes: Option<u64>,
    pub memory_current_bytes: Option<u64>,
    pub oom_kills: u64,
    pub pids_limit_hits: u64,
}

fn read_u64(dir: &Path, file: &str) -> Option<u64> {
    fs::read_to_string(dir.join(file)).ok()?.trim().parse().ok()
}

/// Find `key N` in a flat-keyed cgroup file (`cpu.stat`, `memory.events`, `pids.events`).
fn keyed(dir: &Path, file: &str, key: &str) -> Option<u64> {
    fs::read_to_string(dir.join(file)).ok()?.lines().find_map(|l| l.strip_prefix(key)?.strip_prefix(' ')?.trim().parse().ok())
}

/// IS-3: how the limits in force in a runtime's control group differ from the ones it was launched
/// with. A limit that was raised, or a control group that is gone, is a control no longer in force.
pub fn drift(dir: &Path, spec: &CgroupSpec) -> Vec<String> {
    if !dir.is_dir() {
        return vec!["the runtime's control group no longer exists".into()];
    }
    let read = |file: &str| fs::read_to_string(dir.join(file)).map(|s| s.trim().to_owned()).unwrap_or_default();
    let mut v = Vec::new();
    for (file, want) in [
        ("cpu.max", spec.cpu_max.clone()),
        ("memory.max", spec.memory_max_bytes.to_string()),
        ("memory.swap.max", "0".to_owned()),
        ("pids.max", spec.pids_max.to_string()),
    ] {
        let got = read(file);
        if got != want {
            v.push(format!("{file} is `{got}`, the runtime was launched with `{want}`"));
        }
    }
    v
}

pub fn read_stats(dir: &Path) -> CgroupStats {
    CgroupStats {
        cpu_usage_usec: keyed(dir, "cpu.stat", "usage_usec"),
        memory_peak_bytes: read_u64(dir, "memory.peak"),
        memory_current_bytes: read_u64(dir, "memory.current"),
        oom_kills: keyed(dir, "memory.events", "oom_kill").unwrap_or(0),
        pids_limit_hits: keyed(dir, "pids.events", "max").unwrap_or(0),
    }
}

impl CgroupStats {
    /// Translate kernel counters into per-resource evidence (contract RS-2).
    pub fn evidence(&self, spec: &CgroupSpec, res: &SandboxResources) -> Vec<ResourceEvidence> {
        let mech = "cgroup-v2 + firecracker machine-config";
        vec![
            ResourceEvidence {
                resource: "memory".into(),
                configured: Some(u64::from(res.memory_mib) * 1024 * 1024),
                effective: Some(spec.memory_max_bytes),
                observed_peak: self.memory_peak_bytes,
                violated: self.oom_kills > 0,
                action_taken: if self.oom_kills > 0 { "VMM OOM-killed by cgroup".into() } else { "none".into() },
                mechanism: mech.into(),
            },
            ResourceEvidence {
                resource: "cpu_usec".into(),
                configured: Some(u64::from(res.vcpus)),
                effective: Some(u64::from(res.vcpus)),
                observed_peak: self.cpu_usage_usec,
                violated: false,
                action_taken: "none".into(),
                mechanism: mech.into(),
            },
            ResourceEvidence {
                resource: "host_pids".into(),
                configured: Some(u64::from(spec.pids_max)),
                effective: Some(u64::from(spec.pids_max)),
                observed_peak: None,
                violated: self.pids_limit_hits > 0,
                action_taken: if self.pids_limit_hits > 0 { "fork refused by pids.max".into() } else { "none".into() },
                mechanism: mech.into(),
            },
        ]
    }
}

/// Remove a (now empty) cgroup directory. Bounded retries: the kernel releases it a moment after
/// the last process exits. Never recurses and never touches a path that is not a plain directory
/// directly beneath the configured parent.
pub async fn remove_cgroup_dir(parent: &Path, jail_id: &str) -> std::io::Result<bool> {
    let dir = parent.join(jail_id);
    for _ in 0..50 {
        match fs::remove_dir(&dir) {
            Ok(()) => return Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
        }
    }
    fs::remove_dir(&dir).map(|()| true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::NetworkIntent;

    fn res(v: u8, m: u32) -> SandboxResources {
        SandboxResources { vcpus: v, memory_mib: m, disk_mib: 512, network: NetworkIntent::None }
    }

    #[test]
    fn spec_budgets_vmm_overhead_on_top_of_guest_memory() {
        let s = CgroupSpec::for_sandbox(&res(2, 512), 64);
        assert_eq!(s.memory_max_bytes, (512 + 64) * 1024 * 1024);
        assert_eq!(s.cpu_max, "225000 100000");
        assert_eq!(s.pids_max, 34);
    }

    #[test]
    fn jailer_args_use_v2_file_names_and_disable_swap() {
        let a = CgroupSpec::for_sandbox(&res(1, 256), 64).jailer_args();
        let joined = a.join(" ");
        for must in ["cpu.max=125000 100000", "memory.swap.max=0", "memory.oom.group=1", "pids.max=33"] {
            assert!(joined.contains(must), "missing {must} in {joined}");
        }
        assert_eq!(a.iter().filter(|x| *x == "--cgroup").count(), 5);
    }

    #[test]
    fn identity_changes_when_any_setting_changes() {
        let a = CgroupSpec::for_sandbox(&res(2, 512), 64).identity();
        assert_eq!(a, CgroupSpec::for_sandbox(&res(2, 512), 64).identity());
        assert_ne!(a, CgroupSpec::for_sandbox(&res(2, 1024), 64).identity());
    }

    #[test]
    fn stats_are_parsed_from_kernel_files_and_become_evidence() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("cpu.stat"), "usage_usec 4242\nuser_usec 4000\nsystem_usec 242\n").unwrap();
        fs::write(d.path().join("memory.peak"), "123456\n").unwrap();
        fs::write(d.path().join("memory.events"), "low 0\nhigh 0\nmax 0\noom 1\noom_kill 1\n").unwrap();
        fs::write(d.path().join("pids.events"), "max 5\n").unwrap();
        let st = read_stats(d.path());
        assert_eq!((st.cpu_usage_usec, st.memory_peak_bytes, st.oom_kills, st.pids_limit_hits), (Some(4242), Some(123_456), 1, 5));
        let spec = CgroupSpec::for_sandbox(&res(2, 512), 64);
        let ev = st.evidence(&spec, &res(2, 512));
        assert!(ev[0].violated, "an OOM kill must surface as a violation");
        assert!(ev[2].violated);
        assert!(ev.iter().all(|e| e.mechanism.contains("cgroup")), "evidence must name its mechanism");
    }

    #[test]
    fn missing_files_degrade_to_none_not_to_a_panic() {
        let st = read_stats(Path::new("/definitely/not/a/cgroup"));
        assert_eq!(st, CgroupStats::default());
    }
}
