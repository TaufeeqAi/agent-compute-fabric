//! The snapshot manifest and the compatibility gate.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    backend::{BackendIdentity, SnapshotArtifacts},
    domain::{ImageRef, ProfileId, SandboxResources, Tags},
    ids::{RunId, SandboxRef, SnapshotId},
};

pub const MANIFEST_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HostFingerprint {
    pub arch: String,
    pub cpu_model: String,
    /// sha256 of the sorted CPU feature flags. A snapshot restored onto a CPU with *fewer*
    /// features can crash the guest; the host requires the identical set (contract RE-2, §21.6).
    pub cpu_flags_digest: String,
    pub kernel_release: String,
}

impl HostFingerprint {
    /// Pure parser so it is testable with fixture text from any architecture.
    pub fn from_cpuinfo(text: &str, arch: &str, kernel_release: &str) -> Self {
        let first = |keys: &[&str]| {
            text.lines().find_map(|l| {
                let (k, v) = l.split_once(':')?;
                keys.contains(&k.trim()).then(|| v.trim().to_owned())
            })
        };
        let cpu_model = first(&["model name", "Model", "CPU part", "cpu model"]).unwrap_or_else(|| "unknown".into());
        let flags = first(&["flags", "Features"]).unwrap_or_default();
        let mut f: Vec<&str> = flags.split_whitespace().collect();
        f.sort_unstable();
        f.dedup();
        Self {
            arch: arch.to_owned(),
            cpu_model,
            cpu_flags_digest: hex::encode(Sha256::digest(f.join(" ").as_bytes()))[..16].to_owned(),
            kernel_release: kernel_release.to_owned(),
        }
    }

    pub fn capture() -> Self {
        let text = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
        let uts = rustix::system::uname();
        Self::from_cpuinfo(&text, std::env::consts::ARCH, &uts.release().to_string_lossy())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BackendSummary {
    pub name: String,
    pub version: String,
    pub security_profile_id: String,
}

impl From<&BackendIdentity> for BackendSummary {
    fn from(b: &BackendIdentity) -> Self {
        Self { name: b.name.clone(), version: b.version.clone(), security_profile_id: b.security_profile_id.clone() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnapshotManifest {
    pub schema_version: u32,
    pub snapshot_id: SnapshotId,
    pub snapshot_generation: crate::ids::Generation,
    pub created_wall: String,
    pub source: SandboxRef,
    pub source_run: Option<RunId>,
    pub image: ImageRef,
    pub resources: SandboxResources,
    pub artifacts: SnapshotArtifacts,
    pub backend: BackendSummary,
    pub host: HostFingerprint,
    pub profile_id: ProfileId,
    /// The deterministic guest probe taken just before the snapshot (restore oracle).
    pub baseline_state_digest: String,
    pub guest_agent_version: String,
    /// Host ↔ guest protocol version the snapshot's agent speaks (GP-4).
    pub guest_protocol_version: u32,
    /// Tags of the request that created the snapshot (SNP-6).
    pub tags: Tags,
    /// References of the secrets live in the sandbox at capture (SC-5). Never material.
    pub secret_refs: Vec<String>,
    /// Whether a restore of this snapshot reseeds guest entropy (RE-7). Evidence only.
    pub restore_reseeds_entropy: bool,
    pub acf_version: String,
}

/// Why this snapshot cannot be restored here. Empty = compatible.
pub fn check_compat(m: &SnapshotManifest, backend: &BackendIdentity, host: &HostFingerprint) -> Vec<String> {
    let mut why = Vec::new();
    if m.schema_version != MANIFEST_SCHEMA_VERSION {
        why.push(format!("manifest schema {} is not supported (expected {MANIFEST_SCHEMA_VERSION})", m.schema_version));
    }
    if m.backend.name != backend.name {
        why.push(format!("written by backend `{}`, this host runs `{}`", m.backend.name, backend.name));
    }
    if m.backend.version.trim_start_matches('v') != backend.version.trim_start_matches('v') {
        why.push(format!(
            "written by {} {}, this host runs {} (snapshots require the identical VMM version)",
            m.backend.name, m.backend.version, backend.version
        ));
    }
    if m.backend.security_profile_id != backend.security_profile_id {
        why.push("the isolation profile differs from the one the snapshot was taken under".into());
    }
    if m.host.arch != host.arch {
        why.push(format!("CPU architecture {} != {}", m.host.arch, host.arch));
    }
    if m.host.cpu_model != host.cpu_model || m.host.cpu_flags_digest != host.cpu_flags_digest {
        why.push("host CPU model/feature set differs from the one the snapshot was taken on".into());
    }
    if m.guest_protocol_version != acf_wire::guest::GUEST_PROTOCOL_VERSION {
        why.push(format!(
            "the snapshot's guest agent speaks protocol {}, this host speaks {}",
            m.guest_protocol_version,
            acf_wire::guest::GUEST_PROTOCOL_VERSION
        ));
    }
    why
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::{backend::FileDigest, domain::NetworkIntent, ids::Generation, store::fixtures};

    pub(crate) fn manifest() -> SnapshotManifest {
        let fd = |n: &str| FileDigest { name: n.into(), bytes: 10, sha256: "a".repeat(64) };
        SnapshotManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            snapshot_id: SnapshotId::generate(),
            snapshot_generation: Generation::FIRST,
            created_wall: "2026-10-05T00:00:00.000Z".into(),
            source: SandboxRef { sandbox_id: crate::ids::SandboxId::generate(), generation: Generation::FIRST },
            source_run: None,
            image: ImageRef {
                image_id: "sha256:i".into(),
                alias: Some("python".into()),
                architecture: "x86_64".into(),
                kernel_identity: "sha256:k".into(),
                rootfs_identity: "sha256:r".into(),
                manifest_version: 1,
                provenance_reference: None,
            },
            resources: SandboxResources { vcpus: 2, memory_mib: 256, disk_mib: 64, network: NetworkIntent::None },
            artifacts: SnapshotArtifacts { vmstate: fd("vmstate"), mem: fd("mem"), disk: fd("disk"), vmm_version: "1.17.0".into() },
            backend: BackendSummary { name: "firecracker".into(), version: "v1.17.0".into(), security_profile_id: "prof".into() },
            host: HostFingerprint::from_cpuinfo("model name\t: Test CPU\nflags\t\t: fpu sse avx2\n", "x86_64", "6.1.0"),
            profile_id: ProfileId { name: "p".into(), version: "1".into(), digest: "0".repeat(64) },
            baseline_state_digest: "b".repeat(64),
            guest_agent_version: "0.1.0".into(),
            guest_protocol_version: acf_wire::guest::GUEST_PROTOCOL_VERSION,
            tags: fixtures::tags("scope-a"),
            secret_refs: vec![],
            restore_reseeds_entropy: false,
            acf_version: "0.2.0".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{test_support::manifest, *};

    fn backend(version: &str, prof: &str) -> BackendIdentity {
        BackendIdentity {
            name: "firecracker".into(),
            version: version.into(),
            security_profile_id: prof.into(),
            profile: serde_json::json!({}),
        }
    }

    #[test]
    fn cpuinfo_fingerprint_ignores_flag_order_and_duplicates_but_not_content() {
        let a = HostFingerprint::from_cpuinfo("model name : X\nflags : b a c a\n", "x86_64", "k");
        let b = HostFingerprint::from_cpuinfo("model name : X\nflags : c a b\n", "x86_64", "k");
        let c = HostFingerprint::from_cpuinfo("model name : X\nflags : c a b avx512\n", "x86_64", "k");
        assert_eq!(a.cpu_flags_digest, b.cpu_flags_digest);
        assert_ne!(a.cpu_flags_digest, c.cpu_flags_digest);
        let arm = HostFingerprint::from_cpuinfo("Features : fp asimd\nCPU part : 0xd0c\n", "aarch64", "k");
        assert_eq!(arm.cpu_model, "0xd0c");
    }

    #[test]
    fn compatible_when_everything_matches_and_each_difference_is_named() {
        let m = manifest();
        assert!(check_compat(&m, &backend("v1.17.0", "prof"), &m.host).is_empty());
        assert!(check_compat(&m, &backend("1.17.0", "prof"), &m.host).is_empty(), "`v` prefix is not a difference");
        let r = check_compat(
            &m,
            &backend("v1.18.0", "prof2"),
            &HostFingerprint::from_cpuinfo("model name : Other\nflags : fpu\n", "aarch64", "k"),
        );
        assert!(r.iter().any(|x| x.contains("identical VMM version")), "{r:?}");
        assert!(r.iter().any(|x| x.contains("isolation profile")));
        assert!(r.iter().any(|x| x.contains("architecture")));
        assert!(r.iter().any(|x| x.contains("CPU model")));
        let mut old_agent = manifest();
        old_agent.guest_protocol_version += 1;
        let r = check_compat(&old_agent, &backend("v1.17.0", "prof"), &old_agent.host);
        assert!(r.iter().any(|x| x.contains("protocol")), "a guest protocol mismatch is an incompatibility (GP-4): {r:?}");
    }

    #[test]
    fn manifest_rejects_unknown_fields_and_roundtrips() {
        let m = manifest();
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(serde_json::from_str::<SnapshotManifest>(&json).unwrap(), m);
        let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
        v["injected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<SnapshotManifest>(v).is_err());
    }
}
