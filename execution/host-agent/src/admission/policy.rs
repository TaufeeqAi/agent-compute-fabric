//! Phase-1 local policy (spec §16.3–16.7).
//!
//! Policy answers *what a caller may do and how much it may consume*. It is loaded from an
//! integrity-checked file, validated, and then frozen into an immutable [`EffectivePolicy`] whose
//! identity is the sha256 of the verified bytes. An operation captures the `Arc<EffectivePolicy>`
//! at admission, so editing or reloading the file mid-run cannot change a run already admitted.
//!
//! Denial classes: a *capability* that is not granted is `AUTHORIZATION`; a request that exceeds a
//! *ceiling* is `ADMISSION_REJECTED`; a malformed request is `VALIDATION`.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    domain::{CommandSpec, NetworkMode, PolicyId, ResolvedCommand, RunLimits, SandboxResources},
    error::{AcfError, FailureClass, Result},
    protocol::MAX_RESULT_OUTPUT_BYTES,
};

pub const POLICY_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyLimits {
    pub max_vcpus: u8,
    pub max_memory_mib: u32,
    pub max_disk_mib: u32,
    pub max_runtime_ms: u64,
    pub max_pids: u32,
    pub max_stdout_bytes: u64,
    pub max_stderr_bytes: u64,
    pub max_argv_items: usize,
    pub max_argv_bytes: usize,
    pub max_env_entries: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyDefaults {
    pub runtime_ms: u64,
    pub pids: u32,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
}

impl PolicyDefaults {
    /// Built-in defaults, capped by the policy's own ceilings so that an omitted `defaults:`
    /// section can never produce a default the policy would then reject.
    fn derived_from(l: &PolicyLimits) -> Self {
        Self {
            runtime_ms: 600_000.min(l.max_runtime_ms),
            pids: 256.min(l.max_pids),
            stdout_bytes: (1u64 << 20).min(l.max_stdout_bytes),
            stderr_bytes: (1u64 << 20).min(l.max_stderr_bytes),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    pub network_modes: Vec<NetworkMode>,
    /// Image *aliases* a caller may select. Empty = no images = nothing can be created.
    pub images: Vec<String>,
    pub exec: bool,
    pub snapshot_create: bool,
    pub snapshot_restore: bool,
    pub snapshot_delete: bool,
    pub sandbox_destroy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPolicy {
    /// Exact environment variable names a caller may set. Everything else is rejected.
    pub env_allowlist: Vec<String>,
    /// A command's cwd must be one of these directories or beneath one.
    pub cwd_prefixes: Vec<String>,
    pub default_cwd: String,
    /// Unprivileged identity commands run as inside the guest.
    pub guest_uid: u32,
    pub guest_gid: u32,
}

impl Default for ExecutionPolicy {
    fn default() -> Self {
        Self {
            env_allowlist: ["PATH", "HOME", "LANG", "LC_ALL", "TZ", "PYTHONUNBUFFERED"].map(String::from).to_vec(),
            cwd_prefixes: vec!["/workspace".into(), "/tmp".into()],
            default_cwd: "/workspace".into(),
            guest_uid: 1000,
            guest_gid: 1000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyDoc {
    pub schema_version: u32,
    pub name: String,
    pub version: String,
    pub limits: PolicyLimits,
    /// Optional. When omitted, defaults are derived as `min(built-in, ceiling)`; when present
    /// they are validated against the ceilings (an explicit inconsistency is an error).
    #[serde(default)]
    pub defaults: Option<PolicyDefaults>,
    pub capabilities: Capabilities,
    #[serde(default)]
    pub execution: ExecutionPolicy,
}

#[derive(Debug, Clone)]
pub struct EffectivePolicy {
    id: PolicyId,
    doc: PolicyDoc,
    defaults: PolicyDefaults,
}

fn denied(cap: &str) -> AcfError {
    AcfError::new(FailureClass::Authorization, format!("policy does not grant capability `{cap}`"))
}

fn over(what: &str, asked: impl std::fmt::Display, ceiling: impl std::fmt::Display) -> AcfError {
    AcfError::new(FailureClass::AdmissionRejected, format!("{what} {asked} exceeds the policy ceiling of {ceiling}"))
}

impl EffectivePolicy {
    /// Parse **and validate**. `digest` is the sha256 hex of exactly `bytes`.
    pub fn parse(bytes: &[u8], digest: String) -> Result<Self> {
        let text = std::str::from_utf8(bytes).map_err(|_| AcfError::corrupt("policy file is not valid UTF-8"))?;
        let doc: PolicyDoc = serde_saphyr::from_str(text).map_err(|e| AcfError::corrupt(format!("policy YAML rejected: {e}")))?;
        Self::from_doc(doc, digest)
    }

    pub fn from_doc(doc: PolicyDoc, digest: String) -> Result<Self> {
        if doc.schema_version != POLICY_SCHEMA_VERSION {
            return Err(AcfError::new(
                FailureClass::SchemaMismatch,
                format!("policy schema_version {} is not supported (expected {POLICY_SCHEMA_VERSION})", doc.schema_version),
            ));
        }
        let l = &doc.limits;
        let derived;
        let d = match &doc.defaults {
            Some(d) => d,
            None => {
                derived = PolicyDefaults::derived_from(l);
                &derived
            }
        };
        let sane = l.max_vcpus > 0
            && l.max_memory_mib >= 128
            && l.max_disk_mib >= 64
            && l.max_runtime_ms > 0
            && l.max_pids > 0
            && l.max_stdout_bytes > 0
            && l.max_stderr_bytes > 0
            && l.max_argv_items > 0
            && l.max_argv_bytes > 0
            && d.runtime_ms > 0
            && d.runtime_ms <= l.max_runtime_ms
            && d.pids > 0
            && d.pids <= l.max_pids
            && d.stdout_bytes > 0
            && d.stdout_bytes <= l.max_stdout_bytes
            && d.stderr_bytes > 0
            && d.stderr_bytes <= l.max_stderr_bytes;
        if !sane {
            return Err(AcfError::corrupt("policy limits/defaults are inconsistent (zero values or defaults above ceilings)"));
        }
        // A run that stays inside the ceilings must produce a result that fits in one response frame.
        if l.max_stdout_bytes.saturating_add(l.max_stderr_bytes) > MAX_RESULT_OUTPUT_BYTES {
            return Err(AcfError::corrupt(format!(
                "policy output ceilings (max_stdout_bytes + max_stderr_bytes = {} bytes) exceed the {MAX_RESULT_OUTPUT_BYTES} bytes \
                 one response can carry; a run could succeed and its result still be undeliverable",
                l.max_stdout_bytes.saturating_add(l.max_stderr_bytes)
            )));
        }
        if doc.execution.guest_uid == 0 {
            return Err(AcfError::corrupt("policy.execution.guest_uid must not be 0: commands must not run as guest root"));
        }
        if !doc.execution.default_cwd.starts_with('/') || doc.execution.cwd_prefixes.iter().any(|p| !p.starts_with('/')) {
            return Err(AcfError::corrupt("policy cwd values must be absolute paths"));
        }
        let defaults = d.clone();
        let id = PolicyId { name: doc.name.clone(), version: doc.version.clone(), digest };
        Ok(Self { id, doc, defaults })
    }

    pub fn id(&self) -> &PolicyId {
        &self.id
    }

    pub fn doc(&self) -> &PolicyDoc {
        &self.doc
    }

    pub fn authorize_create(&self, res: &SandboxResources, image_alias: &str) -> Result<()> {
        res.validate_shape()?;
        if !self.doc.capabilities.images.iter().any(|i| i == image_alias) {
            return Err(AcfError::new(FailureClass::Authorization, format!("image alias `{image_alias}` is not permitted by policy")));
        }
        if !self.doc.capabilities.network_modes.contains(&res.network) {
            return Err(denied("network mode"));
        }
        let l = &self.doc.limits;
        if res.vcpus > l.max_vcpus {
            return Err(over("vcpus", res.vcpus, l.max_vcpus));
        }
        if res.memory_mib > l.max_memory_mib {
            return Err(over("memory_mib", res.memory_mib, l.max_memory_mib));
        }
        if res.disk_mib > l.max_disk_mib {
            return Err(over("disk_mib", res.disk_mib, l.max_disk_mib));
        }
        Ok(())
    }

    /// Validate a command and resolve it to explicit, in-policy values.
    pub fn authorize_exec(&self, cmd: &CommandSpec) -> Result<ResolvedCommand> {
        if !self.doc.capabilities.exec {
            return Err(denied("exec"));
        }
        let (l, d, x) = (&self.doc.limits, &self.defaults, &self.doc.execution);

        if cmd.argv.is_empty() || cmd.argv[0].is_empty() {
            return Err(AcfError::validation("argv must contain a program"));
        }
        if cmd.argv.len() > l.max_argv_items {
            return Err(over("argv item count", cmd.argv.len(), l.max_argv_items));
        }
        let argv_bytes: usize = cmd.argv.iter().map(String::len).sum();
        if argv_bytes > l.max_argv_bytes {
            return Err(over("argv size (bytes)", argv_bytes, l.max_argv_bytes));
        }
        if cmd.argv.iter().any(|a| a.contains('\0')) {
            return Err(AcfError::validation("argv must not contain NUL"));
        }
        if cmd.env.len() > l.max_env_entries {
            return Err(over("environment entries", cmd.env.len(), l.max_env_entries));
        }
        let mut env = BTreeMap::new();
        for (k, v) in &cmd.env {
            if !x.env_allowlist.iter().any(|a| a == k) {
                return Err(AcfError::new(
                    FailureClass::Authorization,
                    format!("environment variable `{k}` is not on the policy allowlist"),
                ));
            }
            if v.contains('\0') {
                return Err(AcfError::validation(format!("environment variable `{k}` contains NUL")));
            }
            env.insert(k.clone(), v.clone());
        }

        let cwd = cmd.cwd.clone().unwrap_or_else(|| x.default_cwd.clone());
        let under = |prefix: &str| cwd == prefix || cwd.strip_prefix(prefix).is_some_and(|r| r.starts_with('/'));
        if cwd.contains('\0') || cwd.split('/').any(|c| c == "..") || !x.cwd_prefixes.iter().any(|p| under(p)) {
            return Err(AcfError::new(FailureClass::Authorization, format!("cwd `{cwd}` is outside the permitted directories")));
        }

        let req = &cmd.limits;
        let limits = RunLimits {
            timeout_ms: req.timeout_ms.unwrap_or(d.runtime_ms),
            max_pids: req.max_pids.unwrap_or(d.pids),
            max_stdout_bytes: req.max_stdout_bytes.unwrap_or(d.stdout_bytes),
            max_stderr_bytes: req.max_stderr_bytes.unwrap_or(d.stderr_bytes),
        };
        limits.validate_shape()?;
        if limits.timeout_ms > l.max_runtime_ms {
            return Err(over("timeout_ms", limits.timeout_ms, l.max_runtime_ms));
        }
        if limits.max_pids > l.max_pids {
            return Err(over("max_pids", limits.max_pids, l.max_pids));
        }
        if limits.max_stdout_bytes > l.max_stdout_bytes {
            return Err(over("max_stdout_bytes", limits.max_stdout_bytes, l.max_stdout_bytes));
        }
        if limits.max_stderr_bytes > l.max_stderr_bytes {
            return Err(over("max_stderr_bytes", limits.max_stderr_bytes, l.max_stderr_bytes));
        }
        Ok(ResolvedCommand { argv: cmd.argv.clone(), env, cwd, limits, uid: x.guest_uid, gid: x.guest_gid })
    }

    pub fn authorize_snapshot_create(&self) -> Result<()> {
        self.doc.capabilities.snapshot_create.then_some(()).ok_or_else(|| denied("snapshot_create"))
    }
    pub fn authorize_snapshot_restore(&self) -> Result<()> {
        self.doc.capabilities.snapshot_restore.then_some(()).ok_or_else(|| denied("snapshot_restore"))
    }
    pub fn authorize_snapshot_delete(&self) -> Result<()> {
        self.doc.capabilities.snapshot_delete.then_some(()).ok_or_else(|| denied("snapshot_delete"))
    }
    pub fn authorize_destroy(&self) -> Result<()> {
        self.doc.capabilities.sandbox_destroy.then_some(()).ok_or_else(|| denied("sandbox_destroy"))
    }
}

#[cfg(any(test, feature = "testing"))]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test doubles may fail loudly; never compiled into release builds"
)]
pub mod test_support {
    use super::*;

    pub const YAML: &str = r#"
schema_version: 1
name: test
version: "1.0.0"
limits:
  max_vcpus: 4
  max_memory_mib: 2048
  max_disk_mib: 4096
  max_runtime_ms: 60000
  max_pids: 512
  max_stdout_bytes: 1048576
  max_stderr_bytes: 1048576
  max_argv_items: 16
  max_argv_bytes: 4096
  max_env_entries: 8
capabilities:
  network_modes: [none]
  images: [python]
  exec: true
  snapshot_create: true
  snapshot_restore: true
  snapshot_delete: true
  sandbox_destroy: true
"#;

    pub fn policy() -> EffectivePolicy {
        EffectivePolicy::parse(YAML.as_bytes(), "a".repeat(64)).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::{test_support::*, *};
    use crate::domain::RunLimitsRequest;

    fn cmd(argv: &[&str]) -> CommandSpec {
        CommandSpec {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            env: BTreeMap::new(),
            cwd: None,
            limits: RunLimitsRequest::default(),
        }
    }

    fn res(v: u8, m: u32, d: u32) -> SandboxResources {
        SandboxResources { vcpus: v, memory_mib: m, disk_mib: d, network: NetworkMode::None }
    }

    #[test]
    fn parses_and_binds_identity_to_the_verified_digest() {
        let p = policy();
        assert_eq!((p.id().name.as_str(), p.id().version.as_str()), ("test", "1.0.0"));
        assert_eq!(p.id().digest, "a".repeat(64));
    }

    #[test]
    fn unknown_keys_and_wrong_schema_are_rejected() {
        let extra = format!("{YAML}\nsurprise: true\n");
        assert!(EffectivePolicy::parse(extra.as_bytes(), "d".into()).is_err(), "deny_unknown_fields");
        let v2 = YAML.replace("schema_version: 1", "schema_version: 2");
        assert_eq!(EffectivePolicy::parse(v2.as_bytes(), "d".into()).unwrap_err().class, FailureClass::SchemaMismatch);
        assert!(EffectivePolicy::parse(b"not: [valid", "d".into()).is_err());
    }

    #[test]
    fn output_ceilings_that_could_not_fit_in_one_response_are_refused_at_load() {
        let half = MAX_RESULT_OUTPUT_BYTES / 2;
        let at_budget = YAML
            .replace("max_stdout_bytes: 1048576", &format!("max_stdout_bytes: {half}"))
            .replace("max_stderr_bytes: 1048576", &format!("max_stderr_bytes: {half}"));
        assert!(EffectivePolicy::parse(at_budget.as_bytes(), "d".into()).is_ok(), "exactly the budget is allowed");
        let over_budget = at_budget.replace(&format!("max_stderr_bytes: {half}"), &format!("max_stderr_bytes: {}", half + 1));
        let e = EffectivePolicy::parse(over_budget.as_bytes(), "d".into()).unwrap_err();
        assert_eq!(e.class, FailureClass::CorruptInput);
        assert!(e.message.contains("one response can carry"), "{}", e.message);
        // and a sum that would overflow u64 is refused, not wrapped
        let huge = YAML
            .replace("max_stdout_bytes: 1048576", "max_stdout_bytes: 18446744073709551615")
            .replace("max_stderr_bytes: 1048576", "max_stderr_bytes: 18446744073709551615");
        assert!(EffectivePolicy::parse(huge.as_bytes(), "d".into()).is_err());
    }

    #[test]
    fn guest_root_and_inconsistent_defaults_are_refused_at_load() {
        let root = format!(
            "{YAML}\nexecution:\n  env_allowlist: []\n  cwd_prefixes: [/workspace]\n  default_cwd: /workspace\n  guest_uid: 0\n  guest_gid: 0\n"
        );
        assert!(EffectivePolicy::parse(root.as_bytes(), "d".into()).is_err());
        let bad = format!("{YAML}\ndefaults:\n  runtime_ms: 999999999\n  pids: 1\n  stdout_bytes: 1\n  stderr_bytes: 1\n");
        assert!(EffectivePolicy::parse(bad.as_bytes(), "d".into()).is_err(), "default above its own ceiling");
    }

    #[test]
    fn create_enforces_image_shape_and_ceilings_with_distinct_classes() {
        let p = policy();
        assert!(p.authorize_create(&res(2, 1024, 2048), "python").is_ok());
        assert_eq!(p.authorize_create(&res(2, 1024, 2048), "kali").unwrap_err().class, FailureClass::Authorization);
        assert_eq!(p.authorize_create(&res(8, 1024, 2048), "python").unwrap_err().class, FailureClass::AdmissionRejected);
        assert_eq!(p.authorize_create(&res(3, 1024, 2048), "python").unwrap_err().class, FailureClass::Validation);
        assert_eq!(p.authorize_create(&res(2, 4096, 2048), "python").unwrap_err().class, FailureClass::AdmissionRejected);
    }

    #[test]
    fn exec_applies_defaults_and_never_clamps_silently() {
        let p = policy();
        let r = p.authorize_exec(&cmd(&["/bin/echo", "hi"])).unwrap();
        // fixture ceiling is 60s, so the derived default is capped to it (built-in would be 600s)
        assert_eq!((r.limits.timeout_ms, r.limits.max_pids, r.cwd.as_str(), r.uid), (60_000, 256, "/workspace", 1000));
        let mut c = cmd(&["/bin/true"]);
        c.limits.timeout_ms = Some(61_000);
        assert_eq!(p.authorize_exec(&c).unwrap_err().class, FailureClass::AdmissionRejected);
    }

    #[test]
    fn exec_env_cwd_and_argv_rules() {
        let p = policy();
        let mut c = cmd(&["/bin/true"]);
        c.env.insert("LD_PRELOAD".into(), "/x.so".into());
        assert_eq!(p.authorize_exec(&c).unwrap_err().class, FailureClass::Authorization, "LD_PRELOAD must not be settable");
        let mut c = cmd(&["/bin/true"]);
        for bad in ["/etc", "/workspace/../etc", "relative", "/workspacefoo"] {
            c.cwd = Some(bad.into());
            assert!(p.authorize_exec(&c).is_err(), "{bad}");
        }
        c.cwd = Some("/workspace/proj".into());
        assert!(p.authorize_exec(&c).is_ok());
        assert!(p.authorize_exec(&cmd(&[])).is_err());
        assert!(p.authorize_exec(&cmd(&["a\0b"])).is_err());
        let many: Vec<&str> = std::iter::repeat_n("x", 17).collect();
        assert_eq!(p.authorize_exec(&cmd(&many)).unwrap_err().class, FailureClass::AdmissionRejected);
    }

    #[test]
    fn denied_capabilities_are_authorization_failures() {
        let off = YAML.replace("snapshot_create: true", "snapshot_create: false").replace("exec: true", "exec: false");
        let p = EffectivePolicy::parse(off.as_bytes(), "d".into()).unwrap();
        assert_eq!(p.authorize_snapshot_create().unwrap_err().class, FailureClass::Authorization);
        assert_eq!(p.authorize_exec(&cmd(&["/bin/true"])).unwrap_err().class, FailureClass::Authorization);
        assert!(p.authorize_snapshot_restore().is_ok());
    }
}
