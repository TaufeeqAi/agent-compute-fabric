//! The host safety profile (contract §9.4): the mandatory local safety floor.
//!
//! The profile answers *how much a request may consume and which capabilities exist on this host*.
//! It contains no rule about tenants, users, approvals or pricing (SP-4): those are decided on the
//! control-plane side. The host enforces the profile even when a request asks for more (INV-004):
//!
//! * a request above a **ceiling**, or using a **capability** the profile does not grant, is refused
//!   with `SAFETY_CONTROL_DENIED`. It is never reduced to fit (SP-3, N4);
//! * a request field the profile has **no rule for** is refused, not allowed (SP-5);
//! * a malformed request is `INVALID_REQUEST`.
//!
//! The file is loaded only through the trusted-input rule (SP-1), validated, and frozen into an
//! immutable [`SafetyProfile`] whose identity is the sha256 of the verified bytes. An operation
//! captures the `Arc<SafetyProfile>` at admission and is governed by it until it ends, so reloading
//! the file cannot change an operation already admitted (SP-2).
//!
//! The floor items N1–N9 are not in this file and cannot be: no profile, configuration or request
//! can disable them. The loader refuses a profile that tries (`guest_uid: 0`, a zero bound).

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    api::MAX_RESULT_OUTPUT_BYTES,
    domain::{CommandSpec, NetworkIntent, NetworkMode, ProfileId, ResolvedCommand, RunLimits, SandboxResources},
    error::{AcfError, FailureClass, Result},
    network::intent::validate_allowlist,
};

pub const PROFILE_SCHEMA_VERSION: u32 = 2;

/// Ceilings (§9.4, "Items the profile sets"). Every one is finite (N9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfileLimits {
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
    /// Longest sandbox lifetime a request may ask for (LT-1).
    pub max_lifetime_secs: u64,
    /// Most allowlist entries one sandbox may have (AL-1).
    pub max_allowlist_entries: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfileDefaults {
    pub runtime_ms: u64,
    pub pids: u32,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    /// Lifetime of a sandbox whose request names none.
    pub lifetime_secs: u64,
}

impl ProfileDefaults {
    /// Built-in defaults, capped by the profile's own ceilings so that an omitted `defaults:`
    /// section can never produce a default the profile would then refuse.
    fn derived_from(l: &ProfileLimits) -> Self {
        Self {
            runtime_ms: 600_000.min(l.max_runtime_ms),
            pids: 256.min(l.max_pids),
            stdout_bytes: (1u64 << 20).min(l.max_stdout_bytes),
            stderr_bytes: (1u64 << 20).min(l.max_stderr_bytes),
            lifetime_secs: 3600.min(l.max_lifetime_secs),
        }
    }
}

/// Capability switches (§9.4). A switch that is off, or a word that is not listed, is a denial.
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
    /// Delivery of secrets by reference (§22). Also requires the backend to declare it.
    pub secret_injection: bool,
    /// Whether an allowlist entry may name a private address range (AL-6).
    pub private_destinations: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRules {
    /// Exact environment variable names a caller may set. Everything else is refused.
    pub env_allowlist: Vec<String>,
    /// A command's cwd must be one of these directories or beneath one.
    pub cwd_prefixes: Vec<String>,
    pub default_cwd: String,
    /// Unprivileged identity commands run as inside the guest. Never 0 (N3).
    pub guest_uid: u32,
    pub guest_gid: u32,
}

impl Default for ExecutionRules {
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
pub struct ProfileDoc {
    pub schema_version: u32,
    pub name: String,
    pub version: String,
    pub limits: ProfileLimits,
    /// Optional. When omitted, defaults are derived as `min(built-in, ceiling)`; when present they
    /// are validated against the ceilings (an explicit inconsistency is an error).
    #[serde(default)]
    pub defaults: Option<ProfileDefaults>,
    pub capabilities: Capabilities,
    #[serde(default)]
    pub execution: ExecutionRules,
}

#[derive(Debug, Clone)]
pub struct SafetyProfile {
    id: ProfileId,
    doc: ProfileDoc,
    defaults: ProfileDefaults,
}

fn denied(cap: &str) -> AcfError {
    AcfError::denied(format!("the safety profile does not grant capability `{cap}`"))
}

fn over(what: &str, asked: impl std::fmt::Display, ceiling: impl std::fmt::Display) -> AcfError {
    AcfError::denied(format!("{what} {asked} exceeds the safety-profile ceiling of {ceiling}"))
}

impl SafetyProfile {
    /// Parse **and validate**. `digest` is the sha256 hex of exactly `bytes`.
    pub fn parse(bytes: &[u8], digest: String) -> Result<Self> {
        let text = std::str::from_utf8(bytes).map_err(|_| AcfError::corrupt("safety profile is not valid UTF-8"))?;
        let doc: ProfileDoc = serde_saphyr::from_str(text).map_err(|e| AcfError::corrupt(format!("safety profile YAML rejected: {e}")))?;
        Self::from_doc(doc, digest)
    }

    pub fn from_doc(doc: ProfileDoc, digest: String) -> Result<Self> {
        if doc.schema_version != PROFILE_SCHEMA_VERSION {
            return Err(AcfError::incompatible(format!(
                "safety profile schema_version {} is not supported (expected {PROFILE_SCHEMA_VERSION})",
                doc.schema_version
            )));
        }
        let l = &doc.limits;
        let derived;
        let d = match &doc.defaults {
            Some(d) => d,
            None => {
                derived = ProfileDefaults::derived_from(l);
                &derived
            }
        };
        // N9: every bound is finite and none is zero. Defaults never exceed their ceilings (§30).
        let sane = l.max_vcpus > 0
            && l.max_memory_mib >= 128
            && l.max_disk_mib >= 64
            && l.max_runtime_ms > 0
            && l.max_pids > 0
            && l.max_stdout_bytes > 0
            && l.max_stderr_bytes > 0
            && l.max_argv_items > 0
            && l.max_argv_bytes > 0
            && l.max_lifetime_secs > 0
            && l.max_lifetime_secs <= 365 * 24 * 3600
            && d.runtime_ms > 0
            && d.runtime_ms <= l.max_runtime_ms
            && d.pids > 0
            && d.pids <= l.max_pids
            && d.stdout_bytes > 0
            && d.stdout_bytes <= l.max_stdout_bytes
            && d.stderr_bytes > 0
            && d.stderr_bytes <= l.max_stderr_bytes
            && d.lifetime_secs > 0
            && d.lifetime_secs <= l.max_lifetime_secs;
        if !sane {
            return Err(AcfError::corrupt("safety-profile limits/defaults are inconsistent (zero values or defaults above ceilings)"));
        }
        if doc.capabilities.network_modes.contains(&NetworkMode::Allowlist) && l.max_allowlist_entries == 0 {
            return Err(AcfError::corrupt("the profile offers network mode `allowlist` with max_allowlist_entries = 0"));
        }
        // A run that stays inside the ceilings must produce a result that fits in one response frame.
        if l.max_stdout_bytes.saturating_add(l.max_stderr_bytes) > MAX_RESULT_OUTPUT_BYTES {
            return Err(AcfError::corrupt(format!(
                "safety-profile output ceilings (max_stdout_bytes + max_stderr_bytes = {} bytes) exceed the {MAX_RESULT_OUTPUT_BYTES} bytes \
                 one response can carry; a run could succeed and its result still be undeliverable",
                l.max_stdout_bytes.saturating_add(l.max_stderr_bytes)
            )));
        }
        if doc.execution.guest_uid == 0 {
            return Err(AcfError::corrupt("execution.guest_uid must not be 0: a guest command never runs as guest root (N3)"));
        }
        if !doc.execution.default_cwd.starts_with('/') || doc.execution.cwd_prefixes.iter().any(|p| !p.starts_with('/')) {
            return Err(AcfError::corrupt("safety-profile cwd values must be absolute paths"));
        }
        let defaults = d.clone();
        let id = ProfileId { name: doc.name.clone(), version: doc.version.clone(), digest };
        Ok(Self { id, doc, defaults })
    }

    /// The profile in force when the profile file cannot be trusted or is invalid (INV-022).
    ///
    /// It grants nothing that creates privilege: no image, no network mode, no execution, no
    /// snapshot. It does permit what only removes privilege (destroying a sandbox, deleting a
    /// snapshot), because containment is never refused. The host is in `CONTAINMENT` for the same
    /// reason, so no granting request reaches a profile check anyway; this value makes the
    /// fail-closed posture a property of the data and not only of the mode.
    pub fn deny_all() -> Self {
        let limits = ProfileLimits {
            max_vcpus: 1,
            max_memory_mib: 128,
            max_disk_mib: 64,
            max_runtime_ms: 1,
            max_pids: 1,
            max_stdout_bytes: 1,
            max_stderr_bytes: 1,
            max_argv_items: 1,
            max_argv_bytes: 1,
            max_env_entries: 0,
            max_lifetime_secs: 1,
            max_allowlist_entries: 0,
        };
        let defaults = ProfileDefaults::derived_from(&limits);
        let doc = ProfileDoc {
            schema_version: PROFILE_SCHEMA_VERSION,
            name: "deny-all".into(),
            version: "0".into(),
            limits,
            defaults: Some(defaults.clone()),
            capabilities: Capabilities {
                network_modes: Vec::new(),
                images: Vec::new(),
                exec: false,
                snapshot_create: false,
                snapshot_restore: false,
                snapshot_delete: true,
                sandbox_destroy: true,
                secret_injection: false,
                private_destinations: false,
            },
            execution: ExecutionRules { env_allowlist: Vec::new(), ..ExecutionRules::default() },
        };
        let id = ProfileId { name: doc.name.clone(), version: doc.version.clone(), digest: "0".repeat(64) };
        Self { id, doc, defaults }
    }

    /// Whether this is the built-in fail-closed profile.
    pub fn is_deny_all(&self) -> bool {
        self.id.name == "deny-all" && self.doc.capabilities.images.is_empty() && self.doc.capabilities.network_modes.is_empty()
    }

    pub fn id(&self) -> &ProfileId {
        &self.id
    }

    pub fn doc(&self) -> &ProfileDoc {
        &self.doc
    }

    pub fn limits(&self) -> &ProfileLimits {
        &self.doc.limits
    }

    /// Whether the profile lists `mode`. A mode is offered only if the profile lists it and the
    /// backend supports it (§20.1); this is the profile's half.
    pub fn lists_network_mode(&self, mode: NetworkMode) -> bool {
        self.doc.capabilities.network_modes.contains(&mode)
    }

    pub fn defaults(&self) -> &ProfileDefaults {
        &self.defaults
    }

    /// Check a sandbox request and resolve its lifetime. Returns the lifetime in milliseconds.
    pub fn authorize_create(&self, res: &SandboxResources, image_alias: &str, lifetime_secs: Option<u64>) -> Result<u64> {
        res.validate_shape()?;
        let (caps, l) = (&self.doc.capabilities, &self.doc.limits);
        if !caps.images.iter().any(|i| i == image_alias) {
            return Err(AcfError::denied(format!("image alias `{}` is not permitted by the safety profile", image_alias.escape_default())));
        }
        if !caps.network_modes.contains(&res.network.mode()) {
            return Err(denied("network mode"));
        }
        if let NetworkIntent::Allowlist { entries } = &res.network {
            if entries.len() > l.max_allowlist_entries as usize {
                return Err(over("allowlist entry count", entries.len(), l.max_allowlist_entries));
            }
            validate_allowlist(entries, caps.private_destinations)?;
        }
        if res.vcpus > l.max_vcpus {
            return Err(over("vcpus", res.vcpus, l.max_vcpus));
        }
        if res.memory_mib > l.max_memory_mib {
            return Err(over("memory_mib", res.memory_mib, l.max_memory_mib));
        }
        if res.disk_mib > l.max_disk_mib {
            return Err(over("disk_mib", res.disk_mib, l.max_disk_mib));
        }
        self.authorize_lifetime(lifetime_secs)
    }

    /// LT-1: the lifetime is the request's or the profile's default, and never beyond the ceiling.
    pub fn authorize_lifetime(&self, lifetime_secs: Option<u64>) -> Result<u64> {
        let secs = lifetime_secs.unwrap_or(self.defaults.lifetime_secs);
        if secs == 0 {
            return Err(AcfError::validation("lifetime_secs must be at least 1"));
        }
        if secs > self.doc.limits.max_lifetime_secs {
            return Err(over("lifetime_secs", secs, self.doc.limits.max_lifetime_secs));
        }
        Ok(secs.saturating_mul(1000))
    }

    /// Validate a command and resolve it to explicit, in-profile values (EX-2).
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
        if cmd.env.len() + cmd.secret_env.len() > l.max_env_entries {
            return Err(over("environment entries", cmd.env.len() + cmd.secret_env.len(), l.max_env_entries));
        }
        // SP-5: a variable the profile has no rule for is refused, not allowed.
        let allowed = |k: &str| x.env_allowlist.iter().any(|a| a == k);
        let mut env = BTreeMap::new();
        for (k, v) in &cmd.env {
            if !allowed(k) {
                return Err(AcfError::denied(format!(
                    "environment variable `{}` is not on the safety-profile allowlist",
                    k.escape_default()
                )));
            }
            if v.contains('\0') {
                return Err(AcfError::validation("an environment value contains NUL"));
            }
            env.insert(k.clone(), v.clone());
        }
        if !cmd.secret_env.is_empty() && !self.doc.capabilities.secret_injection {
            return Err(denied("secret_injection"));
        }
        for (k, r) in &cmd.secret_env {
            if !allowed(k) {
                return Err(AcfError::denied(format!(
                    "environment variable `{}` is not on the safety-profile allowlist",
                    k.escape_default()
                )));
            }
            if cmd.env.contains_key(k) {
                return Err(AcfError::validation("a variable is set both as a value and as a secret reference"));
            }
            r.validate()?;
        }

        let cwd = cmd.cwd.clone().unwrap_or_else(|| x.default_cwd.clone());
        let under = |prefix: &str| cwd == prefix || cwd.strip_prefix(prefix).is_some_and(|r| r.starts_with('/'));
        if cwd.contains('\0') || cwd.split('/').any(|c| c == "..") {
            return Err(AcfError::validation("cwd must be a normalised absolute path"));
        }
        if !x.cwd_prefixes.iter().any(|p| under(p)) {
            return Err(AcfError::denied("cwd is outside the directories the safety profile permits"));
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
        Ok(ResolvedCommand {
            argv: cmd.argv.clone(),
            env,
            secret_env: cmd.secret_env.clone(),
            cwd,
            limits,
            uid: x.guest_uid,
            gid: x.guest_gid,
        })
    }

    fn capability(&self, on: bool, name: &str) -> Result<()> {
        on.then_some(()).ok_or_else(|| denied(name))
    }

    pub fn authorize_snapshot_create(&self) -> Result<()> {
        self.capability(self.doc.capabilities.snapshot_create, "snapshot_create")
    }
    pub fn authorize_snapshot_restore(&self) -> Result<()> {
        self.capability(self.doc.capabilities.snapshot_restore, "snapshot_restore")
    }
    pub fn authorize_snapshot_delete(&self) -> Result<()> {
        self.capability(self.doc.capabilities.snapshot_delete, "snapshot_delete")
    }
    pub fn authorize_destroy(&self) -> Result<()> {
        self.capability(self.doc.capabilities.sandbox_destroy, "sandbox_destroy")
    }
}

/// True for the classes a profile check may produce (used by tests of the pipeline).
pub fn is_profile_denial(class: FailureClass) -> bool {
    matches!(class, FailureClass::SafetyControlDenied)
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
schema_version: 2
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
  max_lifetime_secs: 7200
  max_allowlist_entries: 4
capabilities:
  network_modes: [none, allowlist]
  images: [python]
  exec: true
  snapshot_create: true
  snapshot_restore: true
  snapshot_delete: true
  sandbox_destroy: true
  secret_injection: true
  private_destinations: false
"#;

    pub fn profile() -> SafetyProfile {
        SafetyProfile::parse(YAML.as_bytes(), "a".repeat(64)).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::{test_support::*, *};
    use crate::domain::{AllowDestination, AllowEntry, PortRange, RunLimitsRequest, SecretRef};

    fn cmd(argv: &[&str]) -> CommandSpec {
        CommandSpec {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            env: BTreeMap::new(),
            secret_env: BTreeMap::new(),
            cwd: None,
            limits: RunLimitsRequest::default(),
        }
    }

    fn res(v: u8, m: u32, d: u32) -> SandboxResources {
        SandboxResources { vcpus: v, memory_mib: m, disk_mib: d, network: NetworkIntent::None }
    }

    fn entry(dest: AllowDestination, port: u16) -> AllowEntry {
        AllowEntry { destination: dest, ports: vec![PortRange { from: port, to: port }] }
    }

    #[test]
    fn parses_and_binds_identity_to_the_verified_digest() {
        let p = profile();
        assert_eq!((p.id().name.as_str(), p.id().version.as_str()), ("test", "1.0.0"));
        assert_eq!(p.id().digest, "a".repeat(64));
    }

    #[test]
    fn unknown_keys_and_wrong_schema_are_rejected() {
        let extra = format!("{YAML}\nsurprise: true\n");
        assert!(SafetyProfile::parse(extra.as_bytes(), "d".into()).is_err(), "deny_unknown_fields");
        let v1 = YAML.replace("schema_version: 2", "schema_version: 1");
        assert_eq!(SafetyProfile::parse(v1.as_bytes(), "d".into()).unwrap_err().class, FailureClass::IncompatibleRuntime);
        assert!(SafetyProfile::parse(b"not: [valid", "d".into()).is_err());
        // SP-4: the profile has no place for a rule about a tenant or a user.
        let tenant = YAML.replace("capabilities:", "tenants:\n  acme: {max_vcpus: 2}\ncapabilities:");
        assert!(SafetyProfile::parse(tenant.as_bytes(), "d".into()).is_err());
    }

    #[test]
    fn output_ceilings_that_could_not_fit_in_one_response_are_refused_at_load() {
        let half = MAX_RESULT_OUTPUT_BYTES / 2;
        let at_budget = YAML
            .replace("max_stdout_bytes: 1048576", &format!("max_stdout_bytes: {half}"))
            .replace("max_stderr_bytes: 1048576", &format!("max_stderr_bytes: {half}"));
        assert!(SafetyProfile::parse(at_budget.as_bytes(), "d".into()).is_ok(), "exactly the budget is allowed");
        let over_budget = at_budget.replace(&format!("max_stderr_bytes: {half}"), &format!("max_stderr_bytes: {}", half + 1));
        let e = SafetyProfile::parse(over_budget.as_bytes(), "d".into()).unwrap_err();
        assert_eq!(e.class, FailureClass::IntegrityFailure);
        assert!(e.message.contains("one response can carry"), "{}", e.message);
        // and a sum that would overflow u64 is refused, not wrapped
        let huge = YAML
            .replace("max_stdout_bytes: 1048576", "max_stdout_bytes: 18446744073709551615")
            .replace("max_stderr_bytes: 1048576", "max_stderr_bytes: 18446744073709551615");
        assert!(SafetyProfile::parse(huge.as_bytes(), "d".into()).is_err());
    }

    #[test]
    fn no_profile_can_disable_a_floor_item() {
        // N3: guest root. N9: a zero ("unlimited") bound.
        let root = format!(
            "{YAML}\nexecution:\n  env_allowlist: []\n  cwd_prefixes: [/workspace]\n  default_cwd: /workspace\n  guest_uid: 0\n  guest_gid: 0\n"
        );
        assert!(SafetyProfile::parse(root.as_bytes(), "d".into()).is_err());
        for zero in ["max_runtime_ms: 60000", "max_pids: 512", "max_lifetime_secs: 7200", "max_argv_items: 16"] {
            let name = zero.split(':').next().unwrap();
            let y = YAML.replace(zero, &format!("{name}: 0"));
            assert!(SafetyProfile::parse(y.as_bytes(), "d".into()).is_err(), "{name}: 0 must not mean unlimited");
        }
        let bad =
            format!("{YAML}\ndefaults:\n  runtime_ms: 999999999\n  pids: 1\n  stdout_bytes: 1\n  stderr_bytes: 1\n  lifetime_secs: 60\n");
        assert!(SafetyProfile::parse(bad.as_bytes(), "d".into()).is_err(), "default above its own ceiling");
        let allow0 = YAML.replace("max_allowlist_entries: 4", "max_allowlist_entries: 0");
        assert!(SafetyProfile::parse(allow0.as_bytes(), "d".into()).is_err(), "allowlist offered with no entries allowed");
    }

    #[test]
    fn create_enforces_image_shape_and_ceilings_and_never_clamps() {
        let p = profile();
        assert_eq!(p.authorize_create(&res(2, 1024, 2048), "python", None).unwrap(), 3_600_000, "the default lifetime");
        assert_eq!(p.authorize_create(&res(2, 1024, 2048), "kali", None).unwrap_err().class, FailureClass::SafetyControlDenied);
        assert_eq!(p.authorize_create(&res(8, 1024, 2048), "python", None).unwrap_err().class, FailureClass::SafetyControlDenied);
        assert_eq!(p.authorize_create(&res(3, 1024, 2048), "python", None).unwrap_err().class, FailureClass::InvalidRequest);
        assert_eq!(p.authorize_create(&res(2, 4096, 2048), "python", None).unwrap_err().class, FailureClass::SafetyControlDenied);
    }

    #[test]
    fn lifetime_takes_the_default_and_is_refused_above_the_ceiling() {
        let p = profile();
        assert_eq!(p.authorize_lifetime(None).unwrap(), 3_600_000);
        assert_eq!(p.authorize_lifetime(Some(7200)).unwrap(), 7_200_000, "exactly the ceiling");
        assert_eq!(p.authorize_lifetime(Some(7201)).unwrap_err().class, FailureClass::SafetyControlDenied, "refused, never clamped");
        assert_eq!(p.authorize_lifetime(Some(0)).unwrap_err().class, FailureClass::InvalidRequest);
    }

    #[test]
    fn network_intent_needs_the_mode_the_entry_ceiling_and_the_private_switch() {
        let p = profile();
        let name = |n: &str| entry(AllowDestination::Name(n.into()), 443);
        let allow = |entries: Vec<AllowEntry>| SandboxResources { network: NetworkIntent::Allowlist { entries }, ..res(1, 256, 128) };
        assert!(p.authorize_create(&allow(vec![name("pypi.org")]), "python", None).is_ok());
        let five = (0..5).map(|i| name(&format!("h{i}.example.org"))).collect();
        assert_eq!(p.authorize_create(&allow(five), "python", None).unwrap_err().class, FailureClass::SafetyControlDenied);
        let private = vec![entry(AllowDestination::Network("10.1.0.0/16".into()), 5432)];
        assert_eq!(
            p.authorize_create(&allow(private.clone()), "python", None).unwrap_err().class,
            FailureClass::SafetyControlDenied,
            "a private range needs the private_destinations switch"
        );
        let on =
            SafetyProfile::parse(YAML.replace("private_destinations: false", "private_destinations: true").as_bytes(), "d".into()).unwrap();
        assert!(on.authorize_create(&allow(private), "python", None).is_ok());
        let metadata = vec![entry(AllowDestination::Network("169.254.169.254/32".into()), 80)];
        assert_eq!(
            on.authorize_create(&allow(metadata), "python", None).unwrap_err().class,
            FailureClass::InvalidRequest,
            "an always-denied range cannot be listed whatever the profile says (AL-6)"
        );
        let off =
            SafetyProfile::parse(YAML.replace("network_modes: [none, allowlist]", "network_modes: [none]").as_bytes(), "d".into()).unwrap();
        assert_eq!(
            off.authorize_create(&allow(vec![name("pypi.org")]), "python", None).unwrap_err().class,
            FailureClass::SafetyControlDenied
        );
    }

    #[test]
    fn exec_applies_defaults_and_never_clamps_silently() {
        let p = profile();
        let r = p.authorize_exec(&cmd(&["/bin/echo", "hi"])).unwrap();
        // fixture ceiling is 60s, so the derived default is capped to it (built-in would be 600s)
        assert_eq!((r.limits.timeout_ms, r.limits.max_pids, r.cwd.as_str(), r.uid), (60_000, 256, "/workspace", 1000));
        let mut c = cmd(&["/bin/true"]);
        c.limits.timeout_ms = Some(61_000);
        assert_eq!(p.authorize_exec(&c).unwrap_err().class, FailureClass::SafetyControlDenied);
    }

    #[test]
    fn exec_env_cwd_and_argv_rules() {
        let p = profile();
        let mut c = cmd(&["/bin/true"]);
        c.env.insert("LD_PRELOAD".into(), "/x.so".into());
        assert_eq!(
            p.authorize_exec(&c).unwrap_err().class,
            FailureClass::SafetyControlDenied,
            "a name the profile has no rule for is refused"
        );
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
        assert_eq!(p.authorize_exec(&cmd(&many)).unwrap_err().class, FailureClass::SafetyControlDenied);
    }

    #[test]
    fn secret_references_need_the_capability_and_an_allowlisted_name() {
        let p = profile();
        let mut c = cmd(&["/bin/true"]);
        c.secret_env.insert("HOME".into(), SecretRef { name: "ci-token".into() });
        assert_eq!(p.authorize_exec(&c).unwrap().secret_env.len(), 1);
        c.env.insert("HOME".into(), "/root".into());
        assert_eq!(p.authorize_exec(&c).unwrap_err().class, FailureClass::InvalidRequest, "one variable, two sources");
        let mut c = cmd(&["/bin/true"]);
        c.secret_env.insert("AWS_SECRET".into(), SecretRef { name: "x".into() });
        assert_eq!(p.authorize_exec(&c).unwrap_err().class, FailureClass::SafetyControlDenied, "the name must be on the allowlist");
        let off = SafetyProfile::parse(YAML.replace("secret_injection: true", "secret_injection: false").as_bytes(), "d".into()).unwrap();
        let mut c = cmd(&["/bin/true"]);
        c.secret_env.insert("HOME".into(), SecretRef { name: "ci-token".into() });
        assert_eq!(off.authorize_exec(&c).unwrap_err().class, FailureClass::SafetyControlDenied);
    }

    #[test]
    fn denied_capabilities_are_safety_control_denials() {
        let off = YAML.replace("snapshot_create: true", "snapshot_create: false").replace("exec: true", "exec: false");
        let p = SafetyProfile::parse(off.as_bytes(), "d".into()).unwrap();
        assert_eq!(p.authorize_snapshot_create().unwrap_err().class, FailureClass::SafetyControlDenied);
        assert_eq!(p.authorize_exec(&cmd(&["/bin/true"])).unwrap_err().class, FailureClass::SafetyControlDenied);
        assert!(p.authorize_snapshot_restore().is_ok());
        assert!(is_profile_denial(p.authorize_snapshot_create().unwrap_err().class));
    }

    #[test]
    fn the_fail_closed_profile_grants_no_privilege_and_still_permits_containment() {
        let p = SafetyProfile::deny_all();
        assert!(p.is_deny_all() && !profile().is_deny_all());
        assert_eq!(p.authorize_create(&res(1, 128, 64), "python", None).unwrap_err().class, FailureClass::SafetyControlDenied);
        assert_eq!(p.authorize_exec(&cmd(&["/bin/true"])).unwrap_err().class, FailureClass::SafetyControlDenied);
        assert!(p.authorize_snapshot_create().is_err() && p.authorize_snapshot_restore().is_err());
        assert!(p.authorize_destroy().is_ok() && p.authorize_snapshot_delete().is_ok(), "containment is never refused");
    }
}
