//! The files this repository *ships* for operators must work with the real parsers, and must agree
//! with each other. The first thing an operator does is copy `policies/default.yaml` and
//! `config/host.example.yaml`; if either were wrong, the first experience of the product would be a
//! startup failure, and a policy that permits more than the example machine can schedule would turn
//! every clear "above policy" refusal into a confusing "no capacity" one.

use std::collections::BTreeMap;

use crate::{
    admission::{EffectivePolicy, policy::PolicyLimits},
    app::sha256_hex,
    config::{Envelope, HostConfig, Paths, RecoveryConfig, SecurityConfig},
    domain::{CommandSpec, NetworkMode, RunLimitsRequest, SandboxResources},
    error::FailureClass,
};

const POLICY_YAML: &str = include_str!("../../../../policies/default.yaml");
const CONFIG_YAML: &str = include_str!("../../../../config/host.example.yaml");

fn policy() -> EffectivePolicy {
    EffectivePolicy::parse(POLICY_YAML.as_bytes(), sha256_hex(POLICY_YAML.as_bytes())).expect("policies/default.yaml must parse")
}

fn config() -> HostConfig {
    HostConfig::parse(CONFIG_YAML.as_bytes()).expect("config/host.example.yaml must parse")
}

fn res(vcpus: u8, memory_mib: u32, disk_mib: u32) -> SandboxResources {
    SandboxResources { vcpus, memory_mib, disk_mib, network: NetworkMode::None }
}

fn cmd(argv: &[&str]) -> CommandSpec {
    CommandSpec {
        argv: argv.iter().map(|s| (*s).to_owned()).collect(),
        env: BTreeMap::new(),
        cwd: None,
        limits: RunLimitsRequest::default(),
    }
}

fn json<T: serde::Serialize>(v: &T) -> serde_json::Value {
    serde_json::to_value(v).unwrap()
}

#[test]
fn the_default_policy_serves_the_phase_1_milestone_command() {
    // acf-local run --image python --cpu 2 --memory 4096 --network none --command "python experiment.py"
    let p = policy();
    assert_eq!((p.id().name.as_str(), p.id().version.as_str()), ("default", "1.0.0"));
    p.authorize_create(&res(2, 4096, 1024), "python").expect("the milestone sandbox must be admitted");
    for image in ["base", "python", "node", "browser"] {
        p.authorize_create(&res(1, 512, 1024), image).unwrap_or_else(|e| panic!("image `{image}` must be allowed: {e}"));
    }
    let r = p.authorize_exec(&cmd(&["python", "experiment.py"])).expect("the milestone command must be admitted");
    assert_eq!((r.cwd.as_str(), r.uid, r.gid), ("/workspace", 1000, 1000), "commands run as the unprivileged guest user");
    assert_eq!(r.limits.timeout_ms, 600_000, "the documented default runtime");
    assert_eq!(r.limits.max_pids, 256);
    assert_eq!((r.limits.max_stdout_bytes, r.limits.max_stderr_bytes), (1 << 20, 1 << 20));
    p.authorize_snapshot_create().unwrap();
    p.authorize_snapshot_restore().unwrap();
    p.authorize_snapshot_delete().unwrap();
    p.authorize_destroy().unwrap();
}

#[test]
fn the_default_policy_denies_what_must_stay_denied() {
    let p = policy();
    // an image that is not on the allow-list
    assert_eq!(p.authorize_create(&res(2, 1024, 1024), "kali").unwrap_err().class, FailureClass::Authorization);
    // ceilings: refused, never clamped
    assert_eq!(p.authorize_create(&res(8, 1024, 1024), "python").unwrap_err().class, FailureClass::AdmissionRejected);
    assert_eq!(p.authorize_create(&res(2, 8192, 1024), "python").unwrap_err().class, FailureClass::AdmissionRejected);
    assert_eq!(p.authorize_create(&res(2, 1024, 16_384), "python").unwrap_err().class, FailureClass::AdmissionRejected);
    // environment variables that turn "set a variable" into "run code of my choosing"
    for var in ["LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "NODE_OPTIONS", "BASH_ENV", "PYTHONSTARTUP", "LD_AUDIT"] {
        let mut c = cmd(&["/bin/true"]);
        c.env.insert(var.into(), "x".into());
        assert_eq!(p.authorize_exec(&c).unwrap_err().class, FailureClass::Authorization, "{var} must not be settable");
    }
    // the allow-listed ones are accepted
    let mut c = cmd(&["/bin/true"]);
    for var in ["PATH", "HOME", "LANG", "LC_ALL", "TZ", "PYTHONUNBUFFERED", "PYTHONHASHSEED", "NODE_ENV", "CI"] {
        c.env.insert(var.into(), "x".into());
    }
    p.authorize_exec(&c).expect("every allow-listed variable is accepted");
    // working directories outside the permitted prefixes, and traversal
    for cwd in ["/", "/etc", "/proc/1", "/workspace/../etc", "relative", "/workspacefoo", "/tmpfile"] {
        let mut c = cmd(&["/bin/true"]);
        c.cwd = Some(cwd.into());
        assert!(p.authorize_exec(&c).is_err(), "cwd `{cwd}` must be refused");
    }
    for cwd in ["/workspace", "/workspace/proj/src", "/tmp", "/tmp/x"] {
        let mut c = cmd(&["/bin/true"]);
        c.cwd = Some(cwd.into());
        assert!(p.authorize_exec(&c).is_ok(), "cwd `{cwd}` must be allowed");
    }
    // a command may not ask for more than the ceiling
    let mut c = cmd(&["/bin/true"]);
    c.limits.timeout_ms = Some(3_600_001);
    assert_eq!(p.authorize_exec(&c).unwrap_err().class, FailureClass::AdmissionRejected);
    let mut c = cmd(&["/bin/true"]);
    c.limits.max_pids = Some(1025);
    assert_eq!(p.authorize_exec(&c).unwrap_err().class, FailureClass::AdmissionRejected);
}

#[test]
fn the_default_policy_only_offers_the_phase_1_network_mode() {
    assert_eq!(policy().doc().capabilities.network_modes, vec![NetworkMode::None]);
}

#[test]
fn the_example_config_parses_and_spells_out_exactly_the_built_in_defaults() {
    // The example documents the defaults; if the two ever diverge, the document is lying.
    let c = config();
    assert_eq!(json(&c.paths), json(&Paths::default()), "paths");
    assert_eq!(json(&c.security), json(&SecurityConfig::default()), "security");
    assert_eq!(json(&c.envelope), json(&Envelope::default()), "envelope");
    assert_eq!(json(&c.recovery), json(&RecoveryConfig::default()), "recovery");

    // `firecracker` has no `Default` (the binaries and the pin are a deliberate operator choice):
    // compare against a document that sets only the three required keys.
    let minimal = "schema_version: 1\nfirecracker:\n  firecracker_bin: /opt/acf/bin/firecracker\n  jailer_bin: /opt/acf/bin/jailer\n  pinned_version: v1.17.0\n";
    let m = HostConfig::parse(minimal.as_bytes()).unwrap();
    assert_eq!(json(&c.firecracker), json(&m.firecracker), "firecracker");

    assert_eq!(c.firecracker.pinned_version, "v1.17.0");
    assert!(!c.firecracker.diagnostic_log);
    assert!(c.firecracker.boot_args.contains("8250.nr_uarts=0"));
}

#[test]
fn the_shipped_policy_fits_inside_the_shipped_machine_envelope() {
    let (p, c) = (policy(), config());
    let l: &PolicyLimits = &p.doc().limits;
    let e = &c.envelope;
    assert!(u32::from(l.max_vcpus) <= e.vcpus, "one sandbox at the policy ceiling must fit: {} vCPUs vs envelope {}", l.max_vcpus, e.vcpus);
    assert!(
        u64::from(l.max_memory_mib) + u64::from(c.firecracker.vmm_overhead_mib) <= e.memory_mib,
        "one sandbox at the policy ceiling (plus VMM overhead) must fit in the envelope's memory"
    );
    assert!(u64::from(l.max_disk_mib) <= e.disk_mib, "one sandbox at the policy ceiling must fit in the envelope's disk");
    assert!(e.max_sandboxes <= c.firecracker.uid_range_size, "every running VM needs its own uid");
}
