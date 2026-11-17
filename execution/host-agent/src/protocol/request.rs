use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    domain::{CommandSpec, SandboxResources, SnapshotRef},
    ids::{Generation, OperationId, RunId, SandboxId},
};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelope {
    pub protocol: String,
    /// Client correlation id (opaque, echoed back).
    pub request_id: Option<String>,
    /// Supplying one makes a mutating request resolvable after a lost response (§8.4, §12).
    pub operation_id: Option<OperationId>,
    /// "I am retrying/resolving an operation I already submitted." A retry whose record is
    /// missing is **rejected**, never re-interpreted as a fresh request (§12.4).
    #[serde(default)]
    pub retry: bool,
    pub body: Request,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SandboxCreateParams {
    pub name: Option<String>,
    /// Image alias (policy-allowlisted). The resolved immutable identity is recorded.
    pub image: String,
    pub resources: SandboxResources,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SandboxTarget {
    pub sandbox_id: SandboxId,
    pub expected_generation: Generation,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SandboxSelector {
    /// Sandbox id **or** name. Read-only lookups only.
    pub sandbox: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecParams {
    pub sandbox_id: SandboxId,
    pub expected_generation: Generation,
    pub command: CommandSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnapshotCreateParams {
    pub sandbox_id: SandboxId,
    pub expected_generation: Generation,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RestoreTarget {
    /// Replace an existing sandbox with a **new generation** of the same id (rollback).
    Existing { sandbox_id: SandboxId, expected_generation: Generation },
    /// Materialise the snapshot as a brand-new sandbox.
    New { name: Option<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRestoreParams {
    pub snapshot: SnapshotRef,
    pub target: RestoreTarget,
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

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum Request {
    HostInfo,
    Metrics,
    PolicyReload,
    SandboxCreate(SandboxCreateParams),
    SandboxStart(SandboxTarget),
    SandboxStop(SandboxTarget),
    SandboxDestroy(SandboxTarget),
    SandboxInspect(SandboxSelector),
    SandboxList,
    Exec(ExecParams),
    SnapshotCreate(SnapshotCreateParams),
    SnapshotRestore(SnapshotRestoreParams),
    SnapshotDelete(SnapshotRef),
    SnapshotList,
    OperationGet(OperationSelector),
    OperationCancel(OperationSelector),
    RunInspect(RunSelector),
}

impl Request {
    /// Mutating requests create (or resolve) a durable operation; the rest are pure reads.
    pub fn is_mutating(&self) -> bool {
        !matches!(
            self,
            Request::HostInfo
                | Request::Metrics
                | Request::SandboxInspect(_)
                | Request::SandboxList
                | Request::SnapshotList
                | Request::OperationGet(_)
                | Request::RunInspect(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_fields_and_unknown_methods_are_rejected() {
        let bad = r#"{"protocol":"acf.host/1","body":{"method":"sandbox_list"},"sneaky":1}"#;
        assert!(serde_json::from_str::<RequestEnvelope>(bad).is_err());
        let unknown = r#"{"protocol":"acf.host/1","body":{"method":"rm_rf","params":{}}}"#;
        assert!(serde_json::from_str::<RequestEnvelope>(unknown).is_err());
        let params = r#"{"protocol":"acf.host/1","body":{"method":"sandbox_destroy","params":{"sandbox_id":"sbx-00000000000000000000000000000000","expected_generation":1,"force":true}}}"#;
        assert!(serde_json::from_str::<RequestEnvelope>(params).is_err(), "params must be strict too");
    }

    #[test]
    fn destructive_requests_cannot_be_expressed_with_a_name() {
        let by_name = r#"{"protocol":"acf.host/1","body":{"method":"sandbox_destroy","params":{"sandbox":"baseline"}}}"#;
        assert!(serde_json::from_str::<RequestEnvelope>(by_name).is_err());
        let by_id = r#"{"protocol":"acf.host/1","body":{"method":"sandbox_destroy","params":{"sandbox_id":"sbx-00000000000000000000000000000000","expected_generation":3}}}"#;
        assert!(serde_json::from_str::<RequestEnvelope>(by_id).is_ok());
    }

    #[test]
    fn mutating_classification() {
        assert!(!Request::SandboxList.is_mutating());
        assert!(Request::PolicyReload.is_mutating());
        assert!(Request::OperationCancel(OperationSelector { operation_id: OperationId::generate() }).is_mutating());
    }
}
