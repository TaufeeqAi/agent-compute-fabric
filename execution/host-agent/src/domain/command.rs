//! What a caller may ask to run (spec §8.7). Requests are *proposals*: nothing here is trusted
//! until `admission::policy` has resolved it against the policy in force.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::resources::RunLimits;

/// Limits a caller may *ask for*. Anything omitted takes the policy default; anything above a
/// policy ceiling is rejected (never silently clamped).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunLimitsRequest {
    pub timeout_ms: Option<u64>,
    pub max_pids: Option<u32>,
    pub max_stdout_bytes: Option<u64>,
    pub max_stderr_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommandSpec {
    /// Executed directly (no shell). Use `["/bin/sh","-c","..."]` to opt into a shell.
    pub argv: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    pub cwd: Option<String>,
    #[serde(default)]
    pub limits: RunLimitsRequest,
}

/// A command after policy resolution: every field is now explicit and within policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCommand {
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: String,
    pub limits: RunLimits,
    pub uid: u32,
    pub gid: u32,
}
