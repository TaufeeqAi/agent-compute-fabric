//! What a caller may ask to run (contract §18.1). Requests are *proposals*: nothing here is trusted
//! until the safety profile has resolved it (`authority::profile`).

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::resources::RunLimits;
use crate::error::{AcfError, Result};

/// Limits a caller may *ask for*. Anything omitted takes the profile default; anything above a
/// profile ceiling is refused (never silently clamped, N4).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunLimitsRequest {
    pub timeout_ms: Option<u64>,
    pub max_pids: Option<u32>,
    pub max_stdout_bytes: Option<u64>,
    pub max_stderr_bytes: Option<u64>,
}

/// A secret named by reference (SC-1). The only shape a request may use: there is no field that
/// carries material, so raw material in a request cannot be expressed and is refused by the schema.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretRef {
    /// Name of a secret the operator provisioned on the host. `[A-Za-z0-9._-]`, 1..=64.
    #[serde(rename = "ref")]
    pub name: String,
}

impl SecretRef {
    pub fn validate(&self) -> Result<()> {
        let ok = (1..=64).contains(&self.name.len())
            && !self.name.starts_with('.')
            && self.name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if ok {
            Ok(())
        } else {
            Err(AcfError::validation("a secret reference must be 1..=64 characters of [A-Za-z0-9._-] and not start with '.'"))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommandSpec {
    /// Executed directly: an argument vector, never a shell string (EX-1). Use
    /// `["/bin/sh","-c","..."]` to opt into a shell *inside the guest*.
    pub argv: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Environment variables whose values are delivered from the host's secret provider (§22).
    /// Requires the `secret_injection` capability of the profile and of the backend.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secret_env: BTreeMap<String, SecretRef>,
    pub cwd: Option<String>,
    #[serde(default)]
    pub limits: RunLimitsRequest,
}

/// A command after the safety profile resolved it: every field is explicit and within the profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCommand {
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
    /// Variable name → reference. Material is resolved only at the moment of delivery (SC-2).
    pub secret_env: BTreeMap<String, SecretRef>,
    pub cwd: String,
    pub limits: RunLimits,
    pub uid: u32,
    pub gid: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_is_expressible_only_as_a_reference() {
        let ok: CommandSpec = serde_json::from_str(r#"{"argv":["/bin/true"],"secret_env":{"API_TOKEN":{"ref":"ci-token"}}}"#).unwrap();
        assert_eq!(ok.secret_env["API_TOKEN"].name, "ci-token");
        // SC-1 / T-SECR-01: raw material has no representation.
        for raw in [
            r#"{"argv":["/bin/true"],"secret_env":{"API_TOKEN":"hunter2"}}"#,
            r#"{"argv":["/bin/true"],"secret_env":{"API_TOKEN":{"value":"hunter2"}}}"#,
            r#"{"argv":["/bin/true"],"secret_env":{"API_TOKEN":{"ref":"ci-token","value":"hunter2"}}}"#,
            r#"{"argv":["/bin/true"],"secrets":{"API_TOKEN":"hunter2"}}"#,
        ] {
            assert!(serde_json::from_str::<CommandSpec>(raw).is_err(), "{raw}");
        }
    }

    #[test]
    fn reference_names_are_bounded_and_path_safe() {
        assert!(SecretRef { name: "ci-token_v2.prod".into() }.validate().is_ok());
        for bad in ["", "../etc/shadow", "a/b", ".hidden", "has space", &"x".repeat(65)] {
            assert!(SecretRef { name: bad.to_owned() }.validate().is_err(), "{bad}");
        }
    }
}
