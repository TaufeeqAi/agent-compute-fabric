//! The typed command set (contract §10.3). One variant per method; every parameter struct denies
//! unknown fields and bounds every value.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::{
    domain::{CommandSpec, Method, NetworkMode, SandboxResources, SnapshotRef},
    error::{AcfError, Result},
    ids::{Generation, OperationId, RunId, SandboxId, validate_alias},
};

/// Largest page a list method returns.
pub const MAX_LIST_LIMIT: u32 = 1000;
/// Largest slice of captured output one `run.output` call returns.
pub const MAX_OUTPUT_CHUNK_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SandboxCreateParams {
    /// An alias, unique among the caller's own live sandboxes. Never an identity (ID-5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Image alias (the safety profile lists which are allowed). The resolved identity is recorded.
    pub image: String,
    pub resources: SandboxResources,
    /// Lifetime in seconds from creation (LT-1). Absent: the profile's default. Above the profile's
    /// ceiling: refused, never clamped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifetime_secs: Option<u64>,
}

/// The target token of a lifecycle-changing method (CC-2).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SandboxTarget {
    pub sandbox_id: SandboxId,
    /// Must be the sandbox's current generation, or the request is refused with `REVISION_CONFLICT`.
    pub expected_generation: Generation,
    /// Optional stronger precondition: the sandbox's revision must equal this (§10.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub if_revision: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SandboxSelector {
    /// Sandbox id **or** alias. Read-only lookups only.
    pub sandbox: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecParams {
    pub sandbox_id: SandboxId,
    pub expected_generation: Generation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub if_revision: Option<u64>,
    pub command: CommandSpec,
}

impl ExecParams {
    pub fn sandbox_target(&self) -> SandboxTarget {
        SandboxTarget { sandbox_id: self.sandbox_id.clone(), expected_generation: self.expected_generation, if_revision: self.if_revision }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnapshotCreateParams {
    pub sandbox_id: SandboxId,
    pub expected_generation: Generation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub if_revision: Option<u64>,
    /// An alias, unique among the caller's own snapshots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl SnapshotCreateParams {
    pub fn sandbox_target(&self) -> SandboxTarget {
        SandboxTarget { sandbox_id: self.sandbox_id.clone(), expected_generation: self.expected_generation, if_revision: self.if_revision }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RestoreTarget {
    /// Restore in place: a **new generation** of the same sandbox (RE-3). Keeps the sandbox's expiry.
    Existing {
        sandbox_id: SandboxId,
        expected_generation: Generation,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        if_revision: Option<u64>,
    },
    /// Restore as a brand-new sandbox, generation 1.
    New {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        lifetime_secs: Option<u64>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRestoreParams {
    pub snapshot: SnapshotRef,
    pub target: RestoreTarget,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnapshotDeleteParams {
    pub snapshot: SnapshotRef,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationSelector {
    pub operation_id: OperationId,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunSelector {
    pub run_id: RunId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OutputStream {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunOutputParams {
    pub run_id: RunId,
    pub stream: OutputStream,
    /// Byte offset into the stored output of the stream.
    #[serde(default)]
    pub offset: u64,
    /// At most this many bytes (capped by the host).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
}

/// A position in one store's history (ID-4): meaningful only with its lineage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Cursor {
    pub lineage: String,
    pub sequence: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListParams {
    /// Return only records that changed after this position, including tombstones (API-11).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed_since: Option<Cursor>,
    /// Page size, 1..=1000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

impl ListParams {
    pub fn page_size(&self) -> Result<usize> {
        match self.limit {
            None => Ok(MAX_LIST_LIMIT as usize),
            Some(n) if (1..=MAX_LIST_LIMIT).contains(&n) => Ok(n as usize),
            Some(_) => Err(AcfError::validation(format!("limit must be within 1..={MAX_LIST_LIMIT}"))),
        }
    }
}

/// QR-2: what the operator asserts when releasing a quarantined generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReleaseMode {
    /// "The generation's recorded resources belong to this host." The host tears them down and
    /// verifies absence.
    ForceDestroy,
    /// "Nothing remains." The host only verifies that nothing recorded for the generation exists.
    DeclareAbsent,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuarantineReleaseParams {
    pub sandbox_id: SandboxId,
    pub generation: Generation,
    pub mode: ReleaseMode,
}

/// The two modes an operator may ask for (§12.6). Every other mode is entered by the host itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequestedMode {
    Draining,
    Serving,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetModeParams {
    pub mode: RequestedMode,
}

/// A condition an operator can acknowledge (LN-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AckCondition {
    /// "The store is older than the system it describes, and I accept it as authoritative."
    StoreRegression,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AcknowledgeParams {
    pub condition: AckCondition,
}

/// A decoded request body.
#[derive(Debug, Clone)]
pub enum Command {
    SandboxCreate(SandboxCreateParams),
    SandboxStart(SandboxTarget),
    ExecRun(ExecParams),
    SnapshotCreate(SnapshotCreateParams),
    SnapshotRestore(SnapshotRestoreParams),
    SandboxStop(SandboxTarget),
    SandboxDestroy(SandboxTarget),
    SnapshotDelete(SnapshotDeleteParams),
    OperationCancel(OperationSelector),
    SandboxInspect(SandboxSelector),
    SandboxList(ListParams),
    SnapshotList(ListParams),
    OperationGet(OperationSelector),
    OperationList(ListParams),
    RunInspect(RunSelector),
    RunOutput(RunOutputParams),
    HostInfo,
    HostMetrics,
    ProfileReload,
    QuarantineRelease(QuarantineReleaseParams),
    HostSetMode(SetModeParams),
    HostAcknowledge(AcknowledgeParams),
}

fn typed<T: DeserializeOwned>(method: Method, params: Option<Value>) -> Result<T> {
    let v = params.ok_or_else(|| AcfError::validation(format!("`{method}` requires params")))?;
    serde_json::from_value(v).map_err(|e| AcfError::validation(format!("invalid params for `{method}`: {}", super::decode_error(&e))))
}

/// §20.1: "Any other value is refused with `UNSUPPORTED`." A mode word this host does not know is a
/// capability it does not offer, not a malformed request: a caller written for a later contract
/// learns exactly that, before anything else about its request is judged. A `mode` that is not a
/// string at all is malformed and is left to the decoder.
fn unknown_network_mode(method: Method, params: Option<&Value>) -> Result<()> {
    if method != Method::SandboxCreate {
        return Ok(());
    }
    match params.and_then(|p| p.pointer("/resources/network/mode")) {
        Some(Value::String(word)) if serde_json::from_value::<NetworkMode>(Value::String(word.clone())).is_err() => {
            Err(AcfError::unsupported("this host does not offer that network mode: the modes are `none` and `allowlist`"))
        }
        _ => Ok(()),
    }
}

fn none(method: Method, params: Option<Value>) -> Result<()> {
    match params {
        None | Some(Value::Null) => Ok(()),
        Some(Value::Object(m)) if m.is_empty() => Ok(()),
        Some(_) => Err(AcfError::validation(format!("`{method}` takes no params"))),
    }
}

fn list(method: Method, params: Option<Value>) -> Result<ListParams> {
    match params {
        None | Some(Value::Null) => Ok(ListParams::default()),
        some => {
            let p: ListParams = typed(method, some)?;
            p.page_size()?;
            Ok(p)
        }
    }
}

impl Command {
    /// Decode `params` for `method`. Strict: an unknown field anywhere is `INVALID_REQUEST`, and so
    /// is a value outside the bounds that hold whatever the host's profile says.
    pub fn decode(method: Method, params: Option<Value>) -> Result<Self> {
        unknown_network_mode(method, params.as_ref())?;
        let command = Self::decode_typed(method, params)?;
        command.validate_shape()?;
        Ok(command)
    }

    /// Checks that need nothing but the request itself (API-3). They run at the edge, without
    /// privilege, and again in the core.
    fn validate_shape(&self) -> Result<()> {
        let generation = |g: Generation| if g.0 == 0 { Err(AcfError::validation("generations start at 1")) } else { Ok(()) };
        let alias = |name: &Option<String>| name.as_deref().map(validate_alias).transpose().map(|_| ());
        let lifetime =
            |secs: &Option<u64>| if *secs == Some(0) { Err(AcfError::validation("lifetime_secs must be at least 1")) } else { Ok(()) };
        match self {
            Self::SandboxCreate(p) => {
                validate_alias(&p.image)
                    .map_err(|_| AcfError::validation("image must be an alias of 1..=63 characters of [A-Za-z0-9._-]"))?;
                p.resources.validate_shape()?;
                alias(&p.name)?;
                lifetime(&p.lifetime_secs)
            }
            Self::SandboxStart(t) | Self::SandboxStop(t) | Self::SandboxDestroy(t) => generation(t.expected_generation),
            Self::ExecRun(p) => {
                generation(p.expected_generation)?;
                if p.command.argv.first().is_none_or(String::is_empty) {
                    return Err(AcfError::validation("argv must contain a program"));
                }
                Ok(())
            }
            Self::SnapshotCreate(p) => {
                generation(p.expected_generation)?;
                alias(&p.name)
            }
            Self::SnapshotRestore(p) => {
                generation(p.snapshot.snapshot_generation)?;
                match &p.target {
                    RestoreTarget::Existing { expected_generation, .. } => generation(*expected_generation),
                    RestoreTarget::New { name, lifetime_secs } => {
                        alias(name)?;
                        lifetime(lifetime_secs)
                    }
                }
            }
            Self::SnapshotDelete(p) => generation(p.snapshot.snapshot_generation),
            Self::QuarantineRelease(p) => generation(p.generation),
            _ => Ok(()),
        }
    }

    fn decode_typed(method: Method, params: Option<Value>) -> Result<Self> {
        Ok(match method {
            Method::SandboxCreate => Self::SandboxCreate(typed(method, params)?),
            Method::SandboxStart => Self::SandboxStart(typed(method, params)?),
            Method::ExecRun => Self::ExecRun(typed(method, params)?),
            Method::SnapshotCreate => Self::SnapshotCreate(typed(method, params)?),
            Method::SnapshotRestore => Self::SnapshotRestore(typed(method, params)?),
            Method::SandboxStop => Self::SandboxStop(typed(method, params)?),
            Method::SandboxDestroy => Self::SandboxDestroy(typed(method, params)?),
            Method::SnapshotDelete => Self::SnapshotDelete(typed(method, params)?),
            Method::OperationCancel => Self::OperationCancel(typed(method, params)?),
            Method::SandboxInspect => Self::SandboxInspect(typed(method, params)?),
            Method::SandboxList => Self::SandboxList(list(method, params)?),
            Method::SnapshotList => Self::SnapshotList(list(method, params)?),
            Method::OperationGet => Self::OperationGet(typed(method, params)?),
            Method::OperationList => Self::OperationList(list(method, params)?),
            Method::RunInspect => Self::RunInspect(typed(method, params)?),
            Method::RunOutput => Self::RunOutput(typed(method, params)?),
            Method::HostInfo => none(method, params).map(|()| Self::HostInfo)?,
            Method::HostMetrics => none(method, params).map(|()| Self::HostMetrics)?,
            Method::ProfileReload => none(method, params).map(|()| Self::ProfileReload)?,
            Method::QuarantineRelease => Self::QuarantineRelease(typed(method, params)?),
            Method::HostSetMode => Self::HostSetMode(typed(method, params)?),
            Method::HostAcknowledge => Self::HostAcknowledge(typed(method, params)?),
        })
    }

    pub fn method(&self) -> Method {
        match self {
            Self::SandboxCreate(_) => Method::SandboxCreate,
            Self::SandboxStart(_) => Method::SandboxStart,
            Self::ExecRun(_) => Method::ExecRun,
            Self::SnapshotCreate(_) => Method::SnapshotCreate,
            Self::SnapshotRestore(_) => Method::SnapshotRestore,
            Self::SandboxStop(_) => Method::SandboxStop,
            Self::SandboxDestroy(_) => Method::SandboxDestroy,
            Self::SnapshotDelete(_) => Method::SnapshotDelete,
            Self::OperationCancel(_) => Method::OperationCancel,
            Self::SandboxInspect(_) => Method::SandboxInspect,
            Self::SandboxList(_) => Method::SandboxList,
            Self::SnapshotList(_) => Method::SnapshotList,
            Self::OperationGet(_) => Method::OperationGet,
            Self::OperationList(_) => Method::OperationList,
            Self::RunInspect(_) => Method::RunInspect,
            Self::RunOutput(_) => Method::RunOutput,
            Self::HostInfo => Method::HostInfo,
            Self::HostMetrics => Method::HostMetrics,
            Self::ProfileReload => Method::ProfileReload,
            Self::QuarantineRelease(_) => Method::QuarantineRelease,
            Self::HostSetMode(_) => Method::HostSetMode,
            Self::HostAcknowledge(_) => Method::HostAcknowledge,
        }
    }

    /// The canonical `params` of the command: the input of the request fingerprint (OP-11).
    pub fn params_value(&self) -> Result<Value> {
        Ok(match self {
            Self::SandboxCreate(p) => serde_json::to_value(p)?,
            Self::SandboxStart(p) | Self::SandboxStop(p) | Self::SandboxDestroy(p) => serde_json::to_value(p)?,
            Self::ExecRun(p) => serde_json::to_value(p)?,
            Self::SnapshotCreate(p) => serde_json::to_value(p)?,
            Self::SnapshotRestore(p) => serde_json::to_value(p)?,
            Self::SnapshotDelete(p) => serde_json::to_value(p)?,
            Self::OperationCancel(p) | Self::OperationGet(p) => serde_json::to_value(p)?,
            Self::SandboxInspect(p) => serde_json::to_value(p)?,
            Self::SandboxList(p) | Self::SnapshotList(p) | Self::OperationList(p) => serde_json::to_value(p)?,
            Self::RunInspect(p) => serde_json::to_value(p)?,
            Self::RunOutput(p) => serde_json::to_value(p)?,
            Self::HostInfo | Self::HostMetrics | Self::ProfileReload => Value::Object(serde_json::Map::new()),
            Self::QuarantineRelease(p) => serde_json::to_value(p)?,
            Self::HostSetMode(p) => serde_json::to_value(p)?,
            Self::HostAcknowledge(p) => serde_json::to_value(p)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SBX: &str = "sbx-00000000000000000000000000000000";
    const SNP: &str = "snp-00000000000000000000000000000000";
    const RUN: &str = "run-00000000000000000000000000000000";

    /// A minimal valid `params` for every method (`None`: the method takes none).
    fn valid(method: Method) -> Option<Value> {
        let target = json!({"sandbox_id": SBX, "expected_generation": 1});
        let snap = json!({"snapshot_id": SNP, "snapshot_generation": 1});
        Some(match method {
            Method::SandboxCreate => {
                json!({"image": "python", "resources": {"vcpus": 1, "memory_mib": 256, "disk_mib": 128, "network": {"mode": "none"}}})
            }
            Method::SandboxStart | Method::SandboxStop | Method::SandboxDestroy => target,
            Method::ExecRun => json!({"sandbox_id": SBX, "expected_generation": 1, "command": {"argv": ["/bin/true"]}}),
            Method::SnapshotCreate => json!({"sandbox_id": SBX, "expected_generation": 1, "name": "base"}),
            Method::SnapshotRestore => json!({"snapshot": snap, "target": {"kind": "new"}}),
            Method::SnapshotDelete => json!({"snapshot": snap}),
            Method::OperationCancel | Method::OperationGet => json!({"operation_id": "op-12345678"}),
            Method::SandboxInspect => json!({"sandbox": "baseline"}),
            Method::SandboxList | Method::SnapshotList | Method::OperationList => {
                json!({"changed_since": {"lineage": "l", "sequence": 3}, "limit": 10})
            }
            Method::RunInspect => json!({"run_id": RUN}),
            Method::RunOutput => json!({"run_id": RUN, "stream": "stdout"}),
            Method::HostInfo | Method::HostMetrics | Method::ProfileReload => return None,
            Method::QuarantineRelease => json!({"sandbox_id": SBX, "generation": 1, "mode": "FORCE_DESTROY"}),
            Method::HostSetMode => json!({"mode": "DRAINING"}),
            Method::HostAcknowledge => json!({"condition": "store_regression"}),
        })
    }

    #[test]
    fn every_method_decodes_its_params_and_round_trips_them() {
        for &m in Method::ALL {
            let c = Command::decode(m, valid(m)).unwrap_or_else(|e| panic!("{m}: {e}"));
            assert_eq!(c.method(), m);
            let again = Command::decode(m, Some(c.params_value().unwrap())).unwrap_or_else(|e| panic!("{m}: re-decode: {e}"));
            assert_eq!(again.params_value().unwrap(), c.params_value().unwrap(), "{m}: the canonical params are stable");
        }
    }

    #[test]
    fn every_method_refuses_an_unknown_field_in_its_params() {
        for &m in Method::ALL {
            let mut p = valid(m).unwrap_or_else(|| json!({}));
            p["unexpected"] = json!(1);
            assert!(Command::decode(m, Some(p)).is_err(), "{m} accepted an unknown field");
        }
        // nested objects are strict too
        let mut exec = valid(Method::ExecRun).unwrap();
        exec["command"]["shell"] = json!(true);
        assert!(Command::decode(Method::ExecRun, Some(exec)).is_err());
        let mut restore = valid(Method::SnapshotRestore).unwrap();
        restore["target"]["force"] = json!(true);
        assert!(Command::decode(Method::SnapshotRestore, Some(restore)).is_err());
    }

    #[test]
    fn methods_without_params_accept_absent_null_or_empty_only() {
        for m in [Method::HostInfo, Method::HostMetrics, Method::ProfileReload] {
            for ok in [None, Some(Value::Null), Some(json!({}))] {
                assert!(Command::decode(m, ok).is_ok(), "{m}");
            }
            assert!(Command::decode(m, Some(json!({"x": 1}))).is_err(), "{m}");
            assert!(Command::decode(m, Some(json!([]))).is_err(), "{m}");
        }
        assert!(Command::decode(Method::SandboxDestroy, None).is_err(), "a method with params requires them");
    }

    #[test]
    fn out_of_range_values_are_refused() {
        let bad: [(Method, Value); 9] = [
            (Method::SandboxList, json!({"limit": 0})),
            (Method::SandboxList, json!({"limit": 1001})),
            (Method::SandboxDestroy, json!({"sandbox_id": "sbx-../../etc", "expected_generation": 1})),
            (Method::SandboxDestroy, json!({"sandbox_id": SBX, "expected_generation": -1})),
            (
                Method::SandboxDestroy,
                serde_json::from_str(&format!(r#"{{"sandbox_id": "{SBX}", "expected_generation": 18446744073709551616}}"#)).unwrap(),
            ),
            (Method::HostSetMode, json!({"mode": "READ_ONLY"})),
            (Method::HostSetMode, json!({"mode": "CONTAINMENT"})),
            (Method::QuarantineRelease, json!({"sandbox_id": SBX, "generation": 1, "mode": "JUST_DELETE"})),
            (Method::RunOutput, json!({"run_id": RUN, "stream": "stdin"})),
        ];
        for (m, p) in bad {
            assert!(Command::decode(m, Some(p.clone())).is_err(), "{m}: {p}");
        }
    }

    #[test]
    fn restore_in_place_and_as_new_are_distinct_shapes() {
        let existing = json!({"snapshot": {"snapshot_id": SNP, "snapshot_generation": 1},
            "target": {"kind": "existing", "sandbox_id": SBX, "expected_generation": 2, "if_revision": 9}});
        match Command::decode(Method::SnapshotRestore, Some(existing)).unwrap() {
            Command::SnapshotRestore(p) => assert!(matches!(p.target, RestoreTarget::Existing { if_revision: Some(9), .. })),
            other => panic!("{other:?}"),
        }
        let mixed = json!({"snapshot": {"snapshot_id": SNP, "snapshot_generation": 1},
            "target": {"kind": "new", "sandbox_id": SBX, "expected_generation": 2}});
        assert!(Command::decode(Method::SnapshotRestore, Some(mixed)).is_err(), "a new sandbox cannot name an existing one");
    }
}
