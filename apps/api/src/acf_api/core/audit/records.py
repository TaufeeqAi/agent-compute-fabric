"""Audit records: who asked for what, where, how, with which decision and which result, and when.

One record for every mutation the core admits past its rate and in-flight bounds (accepted, refused or
unresolved), every authorization denial, every issuance, minting and revocation of a credential, every
read of execution output, and every operator action on the platform. A request that fails before it
becomes a command, or that is refused for rate, leaves no record: it is counted.

A record holds identifiers, enumerations and digests. It never holds a credential, an argument or
environment *value*, or output. Of an execution it holds a keyed digest of the argument vector and of
the environment, and the network intent of the sandbox it ran in; of a create or a restore, the image,
the resources and the network intent that were asked for. With the fingerprint key an operator can
confirm what ran; without it the digests reveal nothing.

The record is evidence, never truth: it is not consulted for any decision, and what a workload did and
for how long are facts of the host.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final

from acf_api.command.answers import RequestContext
from acf_api.core.clock import rfc3339

AUDIT_SCHEMA_VERSION: Final = 1

#: The members a record may carry. A test checks that nothing else is ever written.
FIELDS: Final = frozenset(
    {
        "schema_version",
        "at",
        "event",
        "request_id",
        "trace_id",
        "interface",
        "interface_version",
        "client_name",
        "client_version",
        "principal_id",
        "credential_id",
        "credential_kind",
        "agent_label",
        "project_id",
        "method",
        "tool",
        "class",
        "sandbox_id",
        "execution_id",
        "snapshot_id",
        "operation_id",
        "idempotency_key_digest",
        "decision_id",
        "policy_version",
        "outcome",
        "code",
        "reason",
        "retry",
        "replayed",
        "host_lineage",
        "host_sequence",
        "details",
    }
)
#: Members allowed under ``details``: bounded identifiers, enumerations and keyed digests only.
DETAIL_FIELDS: Final = frozenset(
    {
        "argv_digest",
        "env_digest",
        "argv_items",
        "env_entries",
        "image",
        "vcpus",
        "memory_mib",
        "disk_mib",
        "network_mode",
        "network_destinations",
        "lifetime_seconds",
        "timeout_seconds",
        "generation",
        "stream",
        "offset",
        "bytes",
        "subject_credential_id",
        "subject_kind",
        "label",
        "expires_at",
        "developer_credential_via_agent_interface",
        "operator_action",
        "subject_project_id",
        "subject_principal_id",
        "revoked",
    }
)


@dataclass(slots=True)
class AuditEvent:
    """One record under construction. The pipeline fills it as a request moves through its steps."""

    event: str
    at_ms: int
    request_id: str | None = None
    trace_id: str | None = None
    interface: str | None = None
    interface_version: str | None = None
    client_name: str | None = None
    client_version: str | None = None
    principal_id: str | None = None
    credential_id: str | None = None
    credential_kind: str | None = None
    agent_label: str | None = None
    project_id: str | None = None
    method: str | None = None
    tool: str | None = None
    operation_class: str | None = None
    sandbox_id: str | None = None
    execution_id: str | None = None
    snapshot_id: str | None = None
    operation_id: str | None = None
    idempotency_key_digest: str | None = None
    decision_id: str | None = None
    policy_version: str | None = None
    outcome: str | None = None
    code: str | None = None
    reason: str | None = None
    retry: str | None = None
    replayed: bool | None = None
    host_lineage: str | None = None
    host_sequence: int | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def from_context(self, ctx: RequestContext) -> AuditEvent:
        self.request_id = ctx.request_id
        self.trace_id = ctx.traceparent.split("-")[1] if ctx.traceparent else None
        self.interface = ctx.interface
        self.interface_version = ctx.interface_version
        self.client_name = ctx.client.name or None
        self.client_version = ctx.client.version or None
        return self

    def to_record(self) -> dict[str, Any]:
        unknown = set(self.details) - DETAIL_FIELDS
        if unknown:
            msg = f"audit details outside the schema: {sorted(unknown)}"
            raise ValueError(msg)
        body: dict[str, Any] = {
            "schema_version": AUDIT_SCHEMA_VERSION,
            "at": rfc3339(self.at_ms),
            "event": self.event,
            "request_id": self.request_id,
            "trace_id": self.trace_id,
            "interface": self.interface,
            "interface_version": self.interface_version,
            "client_name": self.client_name,
            "client_version": self.client_version,
            "principal_id": self.principal_id,
            "credential_id": self.credential_id,
            "credential_kind": self.credential_kind,
            "agent_label": self.agent_label,
            "project_id": self.project_id,
            "method": self.method,
            "tool": self.tool,
            "class": self.operation_class,
            "sandbox_id": self.sandbox_id,
            "execution_id": self.execution_id,
            "snapshot_id": self.snapshot_id,
            "operation_id": self.operation_id,
            "idempotency_key_digest": self.idempotency_key_digest,
            "decision_id": self.decision_id,
            "policy_version": self.policy_version,
            "outcome": self.outcome,
            "code": self.code,
            "reason": self.reason,
            "retry": self.retry,
            "replayed": self.replayed,
            "host_lineage": self.host_lineage,
            "host_sequence": self.host_sequence,
            "details": self.details or None,
        }
        return {k: v for k, v in body.items() if v is not None}
