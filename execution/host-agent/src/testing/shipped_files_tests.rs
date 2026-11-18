//! The files this repository *ships* for operators must work with the real parsers, and must agree
//! with each other. The first thing an operator does is copy `profiles/default.yaml`,
//! `config/host.example.yaml` and `config/enrolment.example.yaml`. If one of them were wrong, the
//! first experience of the product would be a host in `CONTAINMENT`.

use std::collections::BTreeMap;

use crate::{
    app::sha256_hex,
    authority::{Enrolment, SafetyProfile},
    config::{
        EdgeConfig, Envelope, HostConfig, LifetimeConfig, NetworkConfig, OperationsConfig, Paths, RecoveryConfig, SecurityConfig,
        StoreConfig,
    },
    domain::{
        AllowDestination, AllowEntry, CommandSpec, NetworkIntent, NetworkMode, PortRange, Role, RunLimitsRequest, SandboxResources,
        SecretRef,
    },
    error::FailureClass,
};

const PROFILE_YAML: &str = include_str!("../../../../profiles/default.yaml");
const CONFIG_YAML: &str = include_str!("../../../../config/host.example.yaml");
const ENROLMENT_YAML: &str = include_str!("../../../../config/enrolment.example.yaml");

fn profile() -> SafetyProfile {
    SafetyProfile::parse(PROFILE_YAML.as_bytes(), sha256_hex(PROFILE_YAML.as_bytes())).expect("profiles/default.yaml must parse")
}

fn config() -> HostConfig {
    HostConfig::parse(CONFIG_YAML.as_bytes()).expect("config/host.example.yaml must parse")
}

fn res(vcpus: u8, memory_mib: u32, disk_mib: u32) -> SandboxResources {
    SandboxResources { vcpus, memory_mib, disk_mib, network: NetworkIntent::None }
}

fn cmd(argv: &[&str]) -> CommandSpec {
    CommandSpec {
        argv: argv.iter().map(|s| (*s).to_owned()).collect(),
        env: BTreeMap::new(),
        secret_env: BTreeMap::new(),
        cwd: None,
        limits: RunLimitsRequest::default(),
    }
}

fn json<T: serde::Serialize>(v: &T) -> serde_json::Value {
    serde_json::to_value(v).unwrap()
}

#[test]
fn the_default_profile_admits_an_ordinary_sandbox_and_command() {
    let p = profile();
    assert_eq!((p.id().name.as_str(), p.id().version.as_str()), ("default", "2.0.0"));
    assert_eq!(
        p.authorize_create(&res(2, 4096, 1024), "python", None).expect("an ordinary sandbox is admitted"),
        3_600_000,
        "the default lifetime: one hour"
    );
    for image in ["base", "python", "node", "browser"] {
        p.authorize_create(&res(1, 512, 1024), image, None).unwrap_or_else(|e| panic!("image `{image}` must be allowed: {e}"));
    }
    let r = p.authorize_exec(&cmd(&["python", "experiment.py"])).expect("an ordinary command is admitted");
    assert_eq!((r.cwd.as_str(), r.uid, r.gid), ("/workspace", 1000, 1000), "commands run as the unprivileged guest user");
    assert_eq!((r.limits.timeout_ms, r.limits.max_pids), (600_000, 256), "the documented defaults");
    assert_eq!((r.limits.max_stdout_bytes, r.limits.max_stderr_bytes), (1 << 20, 1 << 20));
    p.authorize_snapshot_create().unwrap();
    p.authorize_snapshot_restore().unwrap();
    p.authorize_snapshot_delete().unwrap();
    p.authorize_destroy().unwrap();
}

#[test]
fn the_default_profile_denies_what_must_stay_denied_and_never_clamps() {
    let p = profile();
    let denied = FailureClass::SafetyControlDenied;
    assert_eq!(p.authorize_create(&res(2, 1024, 1024), "kali", None).unwrap_err().class, denied, "an image that is not listed");
    assert_eq!(p.authorize_create(&res(8, 1024, 1024), "python", None).unwrap_err().class, denied);
    assert_eq!(p.authorize_create(&res(2, 8192, 1024), "python", None).unwrap_err().class, denied);
    assert_eq!(p.authorize_create(&res(2, 1024, 16_384), "python", None).unwrap_err().class, denied);
    assert_eq!(p.authorize_create(&res(2, 1024, 1024), "python", Some(86_401)).unwrap_err().class, denied, "a lifetime above the ceiling");
    assert_eq!(p.authorize_create(&res(2, 1024, 1024), "python", Some(86_400)).unwrap(), 86_400_000);
    // Variables that turn "set a variable" into "run code of my choosing".
    for var in ["LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "NODE_OPTIONS", "BASH_ENV", "PYTHONSTARTUP", "LD_AUDIT"] {
        let mut c = cmd(&["/bin/true"]);
        c.env.insert(var.into(), "x".into());
        assert_eq!(p.authorize_exec(&c).unwrap_err().class, denied, "{var} must not be settable");
    }
    let mut c = cmd(&["/bin/true"]);
    for var in ["PATH", "HOME", "LANG", "LC_ALL", "TZ", "PYTHONUNBUFFERED", "PYTHONHASHSEED", "NODE_ENV", "CI"] {
        c.env.insert(var.into(), "x".into());
    }
    p.authorize_exec(&c).expect("every listed variable is accepted");
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
    let mut c = cmd(&["/bin/true"]);
    c.limits.timeout_ms = Some(3_600_001);
    assert_eq!(p.authorize_exec(&c).unwrap_err().class, denied);
    let mut c = cmd(&["/bin/true"]);
    c.limits.max_pids = Some(1025);
    assert_eq!(p.authorize_exec(&c).unwrap_err().class, denied);
    // Secret delivery is off in the shipped profile: turning it on is a decision, not a default.
    let mut c = cmd(&["/bin/true"]);
    c.secret_env.insert("HOME".into(), SecretRef { name: "token".into() });
    assert_eq!(p.authorize_exec(&c).unwrap_err().class, denied);
}

#[test]
fn the_default_profile_offers_both_network_modes_and_no_private_destinations() {
    let p = profile();
    assert_eq!(p.doc().capabilities.network_modes, vec![NetworkMode::None, NetworkMode::Allowlist]);
    assert!(!p.doc().capabilities.private_destinations);
    let allow = |dest: AllowDestination| SandboxResources {
        network: NetworkIntent::Allowlist {
            entries: vec![AllowEntry { destination: dest, ports: vec![PortRange { from: 443, to: 443 }] }],
        },
        ..res(1, 512, 1024)
    };
    p.authorize_create(&allow(AllowDestination::Name("pypi.org".into())), "python", None).expect("a public name is admitted");
    let private = p.authorize_create(&allow(AllowDestination::Network("10.0.0.0/8".into())), "python", None).unwrap_err();
    assert_eq!(private.class, FailureClass::SafetyControlDenied);
    let metadata = p.authorize_create(&allow(AllowDestination::Network("169.254.169.254/32".into())), "python", None).unwrap_err();
    assert_eq!(metadata.class, FailureClass::InvalidRequest, "always denied: no profile can list it");
}

#[test]
fn the_example_config_parses_and_spells_out_exactly_the_built_in_defaults() {
    // The example documents the defaults. If the two ever diverge, the document is lying.
    let c = config();
    assert_eq!(json(&c.paths), json(&Paths::default()), "paths");
    assert_eq!(json(&c.edge), json(&EdgeConfig::default()), "edge");
    assert_eq!(json(&c.security), json(&SecurityConfig::default()), "security");
    assert_eq!(json(&c.envelope), json(&Envelope::default()), "envelope");
    assert_eq!(json(&c.network), json(&NetworkConfig::default()), "network");
    assert_eq!(json(&c.operations), json(&OperationsConfig::default()), "operations");
    assert_eq!(json(&c.recovery), json(&RecoveryConfig::default()), "recovery");
    assert_eq!(json(&c.lifetime), json(&LifetimeConfig::default()), "lifetime");
    assert_eq!(json(&c.store), json(&StoreConfig::default()), "store");

    // `firecracker` has no `Default` (the binaries and the pin are a deliberate operator choice):
    // compare against a document that sets only the required keys.
    let minimal = "schema_version: 2\nhost_id: h\nfirecracker:\n  firecracker_bin: /opt/acf/bin/firecracker\n  jailer_bin: /opt/acf/bin/jailer\n  pinned_version: v1.17.0\n";
    let m = HostConfig::parse(minimal.as_bytes()).unwrap();
    assert_eq!(json(&c.firecracker), json(&m.firecracker), "firecracker");
    assert_eq!(c.host_id, "host-1");
    assert!(c.edge.tls.is_none(), "the network endpoint is opt-in");
}

#[test]
fn the_shipped_profile_and_config_pass_every_mandatory_check_together() {
    let (p, c) = (profile(), config());
    assert_eq!(c.mandatory_checks(Some(&p)), Vec::<String>::new(), "the shipped pair must not put a host in CONTAINMENT");
    let (l, e) = (p.limits(), &c.envelope);
    assert!(
        u64::from(l.max_memory_mib) + u64::from(c.firecracker.vmm_overhead_mib) <= e.memory_mib,
        "one sandbox at the profile ceiling (plus VMM overhead) must fit in the envelope's memory"
    );
    assert!(p.defaults().lifetime_secs <= l.max_lifetime_secs);
}

#[test]
fn the_example_enrolment_parses_and_enrols_only_the_local_administrator() {
    let e = Enrolment::parse(ENROLMENT_YAML.as_bytes(), sha256_hex(ENROLMENT_YAML.as_bytes()))
        .expect("config/enrolment.example.yaml must parse");
    assert_eq!(e.doc().peers.len(), 1);
    let root = e.match_local(0, 0).expect("uid 0 is enrolled");
    assert_eq!((root.peer_id.as_str(), root.role), ("local-root", Role::Operator));
    assert!(e.match_local(1000, 1000).is_none(), "nobody else has authority by default");
    assert!(!e.has_network_peers());
}
