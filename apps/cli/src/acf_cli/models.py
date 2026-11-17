"""Typed projections of the ``acf.host/1`` wire contract.

The Rust host is the single source of truth: ``acf-host schema`` emits JSON Schemas (committed in
the repository's top-level ``schemas/``). These models are the *client's* view of that contract,
and ``tests/test_contract.py`` proves they cannot drift from it:

* every request this module can build validates against ``request.schema.json``;
* every field the schema declares for a response type is modelled here;
* every real response captured from the host parses and validates against ``response.schema.json``.

Robustness rules (the classic "be strict in what you send, tolerant in what you accept"):

* **requests** forbid unknown fields, so a typo in a builder fails in our tests, not in production;
* **responses** ignore unknown fields (an additive host change must not break an older CLI) —
  *except* where a value drives control flow: an unknown ``status`` is a protocol violation,
  because we could not decide what to do next.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

PROTOCOL = "acf.host/1"

SandboxId = Annotated[str, StringConstraints(pattern=r"^sbx-[0-9a-f]{32}$")]
RunId = Annotated[str, StringConstraints(pattern=r"^run-[0-9a-f]{32}$")]
SnapshotId = Annotated[str, StringConstraints(pattern=r"^snp-[0-9a-f]{32}$")]
OperationId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9-]{8,64}$")]
Generation = Annotated[int, Field(ge=1)]


class _Strict(BaseModel):
    """Requests: unknown fields are an error."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class _Lenient(BaseModel):
    """Responses: unknown fields are ignored (forward compatible)."""

    model_config = ConfigDict(extra="ignore", frozen=True, populate_by_name=True)


# ----------------------------------------------------------------------------- shared vocabulary
class OperationStatus(StrEnum):
    """Spec §8.2. ``UNKNOWN`` is first-class and never collapsed into ``FAILED``."""

    ACCEPTED = "ACCEPTED"
    IN_PROGRESS = "IN_PROGRESS"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    UNKNOWN = "UNKNOWN"
    CONFLICT = "CONFLICT"
    REJECTED = "REJECTED"

    @property
    def is_final(self) -> bool:
        """The operation will not change again by itself (mirrors ``OperationStatus::is_final``)."""
        return self in {
            OperationStatus.SUCCEEDED,
            OperationStatus.FAILED,
            OperationStatus.CANCELLED,
            OperationStatus.CONFLICT,
            OperationStatus.REJECTED,
        }


class SandboxResources(_Lenient):
    """What a sandbox is *given* (immutable for the life of a generation). Phase 1: ``network`` is ``none``."""

    vcpus: int
    memory_mib: int
    disk_mib: int
    network: Literal["none"]


class SnapshotRef(_Lenient):
    snapshot_id: SnapshotId
    snapshot_generation: Generation


class ProcessIdentity(_Lenient):
    pid: int
    start_time_ticks: int
    boot_id: str


class PolicyId(_Lenient):
    name: str
    version: str
    digest: str

    def short(self) -> str:
        return f"{self.name}@{self.version}#{self.digest[:12]}"


class ImageRef(_Lenient):
    image_id: str
    alias: str | None = None
    architecture: str
    kernel_identity: str
    rootfs_identity: str
    manifest_version: int
    provenance_reference: str | None = None


class FailureInfo(_Lenient):
    error_class: str = Field(alias="class")
    message: str
    side_effect: str


class ArtifactRef(_Lenient):
    artifact_id: str
    kind: str
    logical_name: str
    schema_version: int
    content_digest: str | None = None
    byte_size: int | None = None
    source_operation_id: str
    sandbox_id: str
    run_id: str | None = None


# ----------------------------------------------------------------------------- response bodies
class OutputCapture(_Lenient):
    status: str  # COMPLETE | TRUNCATED | INCOMPLETE
    total_bytes: int
    kept_bytes: int
    data_b64: str
    artifact: ArtifactRef | None = None


class RunMetrics(_Lenient):
    wall_ms: int
    cpu_usage_usec: int | None = None
    memory_peak_bytes: int | None = None


class ResourceEvidence(_Lenient):
    resource: str
    configured: int | None = None
    effective: int | None = None
    observed_peak: int | None = None
    violation: str | None = None
    action_taken: str
    mechanism: str


class RunResult(_Lenient):
    run_id: RunId
    operation_id: str
    sandbox_id: SandboxId
    generation: Generation
    outcome: str  # RUNNING | SUCCEEDED | FAILED | CANCELLED | TIMED_OUT | UNKNOWN
    exit_code: int | None = None
    signal: int | None = None
    stdout: OutputCapture
    stderr: OutputCapture
    metrics: RunMetrics
    evidence_status: str  # COMPLETE | INCOMPLETE | TRUNCATED | UNKNOWN
    resource_evidence: list[ResourceEvidence] = Field(default_factory=list)
    artifacts: list[ArtifactRef] = Field(default_factory=list)
    policy_id: PolicyId
    image_id: str
    note: str | None = None


class SandboxView(_Lenient):
    sandbox_id: SandboxId
    generation: Generation
    name: str | None = None
    state: str
    resources: SandboxResources
    image: ImageRef
    process: ProcessIdentity | None = None
    security_profile_id: str
    last_run: str | None = None
    source_snapshot: SnapshotRef | None = None
    failure: FailureInfo | None = None
    quarantined: str | None = None
    notes: list[str] = Field(default_factory=list)
    updated: str


class SnapshotView(_Lenient):
    snapshot: SnapshotRef
    name: str | None = None
    state: str
    size_bytes: int
    source_sandbox: tuple[SandboxId, Generation] | None = None
    manifest_digest: str | None = None
    restore_count: int
    created: str
    failure: FailureInfo | None = None


class OperationView(_Lenient):
    operation_id: str
    operation_type: str
    status: OperationStatus
    phase: dict[str, Any]
    resource_id: str
    failure: FailureInfo | None = None
    result: dict[str, Any] | None = None
    run_id: str | None = None
    updated: str


class BackendIdentity(_Lenient):
    name: str
    version: str
    security_profile_id: str
    profile: Any = None


class CapabilityProfile(_Lenient):
    backend: str
    pause_resume: bool
    snapshot: bool
    restore: bool
    guest_exec: bool
    network_modes: list[str]
    max_vcpus: int


class HostInfo(_Lenient):
    version: str
    protocol: str
    instance_id: str
    mode: str  # "normal" | "read_only_quarantine"
    backend: BackendIdentity
    capabilities: CapabilityProfile
    policy: PolicyId
    journal_integrity: str
    live_sandboxes: int
    snapshots: int


class _HostInfoBody(_Lenient):
    type: Literal["host_info"]
    data: HostInfo


class _SandboxBody(_Lenient):
    type: Literal["sandbox"]
    data: SandboxView


class _SandboxesBody(_Lenient):
    type: Literal["sandboxes"]
    data: list[SandboxView]


class _RunBody(_Lenient):
    type: Literal["run"]
    data: RunResult


class _SnapshotBody(_Lenient):
    type: Literal["snapshot"]
    data: SnapshotView


class _SnapshotsBody(_Lenient):
    type: Literal["snapshots"]
    data: list[SnapshotView]


class _OperationBody(_Lenient):
    type: Literal["operation"]
    data: OperationView


class _MetricsBody(_Lenient):
    type: Literal["metrics"]
    data: dict[str, Any]


class _AckBody(_Lenient):
    type: Literal["ack"]


ResponseBody = Annotated[
    _HostInfoBody
    | _SandboxBody
    | _SandboxesBody
    | _RunBody
    | _SnapshotBody
    | _SnapshotsBody
    | _OperationBody
    | _MetricsBody
    | _AckBody,
    Field(discriminator="type"),
]


class ErrorBody(_Lenient):
    error_class: str = Field(alias="class")
    message: str
    side_effect: str  # "none" | "possible"
    retryable: bool
    outcome_unknown: bool


class ResponseEnvelope(_Lenient):
    protocol: str
    request_id: str | None = None
    operation_id: str | None = None
    status: OperationStatus
    result: ResponseBody | None = None
    error: ErrorBody | None = None

    def body(self) -> Any:  # noqa: ANN401 - the payload type is selected by the discriminator
        """The typed ``data`` payload (``None`` for ``ack``/no result)."""
        return getattr(self.result, "data", None) if self.result is not None else None


# ----------------------------------------------------------------------------- requests
class RunLimitsRequest(_Strict):
    """Limits a caller may *ask for*; anything omitted takes the policy default (never silently clamped)."""

    timeout_ms: int | None = None
    max_pids: int | None = None
    max_stdout_bytes: int | None = None
    max_stderr_bytes: int | None = None


class CommandSpec(_Strict):
    """Executed directly (no shell). Use ``["/bin/sh", "-c", "..."]`` to opt into one."""

    argv: list[str]
    env: dict[str, str] = Field(default_factory=dict)
    cwd: str | None = None
    limits: RunLimitsRequest = Field(default_factory=RunLimitsRequest)


class SandboxCreateParams(_Strict):
    name: str | None = None
    image: str
    resources: SandboxResources


class SandboxTarget(_Strict):
    """Destructive and stateful operations name a sandbox by id **and** the generation they saw (§12.5)."""

    sandbox_id: SandboxId
    expected_generation: Generation


class SandboxSelector(_Strict):
    """Read-only lookup by id or name."""

    sandbox: str


class ExecParams(_Strict):
    sandbox_id: SandboxId
    expected_generation: Generation
    command: CommandSpec


class SnapshotCreateParams(_Strict):
    sandbox_id: SandboxId
    expected_generation: Generation
    name: str | None = None


class RestoreExisting(_Strict):
    """Replace a sandbox with a **new generation** of itself (rollback)."""

    kind: Literal["existing"] = "existing"
    sandbox_id: SandboxId
    expected_generation: Generation


class RestoreNew(_Strict):
    """Materialise the snapshot as a brand-new sandbox."""

    kind: Literal["new"] = "new"
    name: str | None = None


class SnapshotRestoreParams(_Strict):
    snapshot: SnapshotRef
    target: RestoreExisting | RestoreNew


class OperationSelector(_Strict):
    operation_id: OperationId


class RunSelector(_Strict):
    run_id: RunId


class Body(_Strict):
    """One request body: ``{"method": ..., "params": ...}`` (no ``params`` key for parameterless methods).

    ``mutating`` means *"creates a durable operation that must be driven to a final answer under an
    operation id"* — i.e. it goes through :meth:`HostClient.mutate`. It is deliberately **not**
    "changes something": ``policy_reload`` and ``operation_cancel`` are answered directly by the
    host (no operation record is created for the request itself) and are safe to repeat, so they
    use a plain round trip.
    """

    method: ClassVar[str]
    mutating: ClassVar[bool] = False

    def params_dump(self) -> dict[str, Any] | None:
        return None

    def wire(self) -> dict[str, Any]:
        out: dict[str, Any] = {"method": self.method}
        params = self.params_dump()
        if params is not None:
            out["params"] = params
        return out


class _Parameterless(Body):
    pass


class _WithParams(Body):
    params: BaseModel

    def params_dump(self) -> dict[str, Any] | None:
        return self.params.model_dump(mode="json", exclude_none=True)


class HostInfoRequest(_Parameterless):
    method: ClassVar[str] = "host_info"


class MetricsRequest(_Parameterless):
    method: ClassVar[str] = "metrics"


class PolicyReloadRequest(_Parameterless):
    method: ClassVar[str] = "policy_reload"


class SandboxListRequest(_Parameterless):
    method: ClassVar[str] = "sandbox_list"


class SnapshotListRequest(_Parameterless):
    method: ClassVar[str] = "snapshot_list"


class SandboxCreateRequest(_WithParams):
    method: ClassVar[str] = "sandbox_create"
    mutating: ClassVar[bool] = True
    params: SandboxCreateParams


class SandboxStartRequest(_WithParams):
    method: ClassVar[str] = "sandbox_start"
    mutating: ClassVar[bool] = True
    params: SandboxTarget


class SandboxStopRequest(_WithParams):
    method: ClassVar[str] = "sandbox_stop"
    mutating: ClassVar[bool] = True
    params: SandboxTarget


class SandboxDestroyRequest(_WithParams):
    method: ClassVar[str] = "sandbox_destroy"
    mutating: ClassVar[bool] = True
    params: SandboxTarget


class SandboxInspectRequest(_WithParams):
    method: ClassVar[str] = "sandbox_inspect"
    params: SandboxSelector


class ExecRequest(_WithParams):
    method: ClassVar[str] = "exec"
    mutating: ClassVar[bool] = True
    params: ExecParams


class SnapshotCreateRequest(_WithParams):
    method: ClassVar[str] = "snapshot_create"
    mutating: ClassVar[bool] = True
    params: SnapshotCreateParams


class SnapshotRestoreRequest(_WithParams):
    method: ClassVar[str] = "snapshot_restore"
    mutating: ClassVar[bool] = True
    params: SnapshotRestoreParams


class SnapshotDeleteRequest(_WithParams):
    method: ClassVar[str] = "snapshot_delete"
    mutating: ClassVar[bool] = True
    params: SnapshotRef


class OperationGetRequest(_WithParams):
    method: ClassVar[str] = "operation_get"
    params: OperationSelector


class OperationCancelRequest(_WithParams):
    method: ClassVar[str] = "operation_cancel"
    params: OperationSelector


class RunInspectRequest(_WithParams):
    method: ClassVar[str] = "run_inspect"
    params: RunSelector


#: Every request type this client can build, for the contract tests to enumerate.
ALL_REQUEST_TYPES: tuple[type[Body], ...] = (
    HostInfoRequest,
    MetricsRequest,
    PolicyReloadRequest,
    SandboxListRequest,
    SnapshotListRequest,
    SandboxCreateRequest,
    SandboxStartRequest,
    SandboxStopRequest,
    SandboxDestroyRequest,
    SandboxInspectRequest,
    ExecRequest,
    SnapshotCreateRequest,
    SnapshotRestoreRequest,
    SnapshotDeleteRequest,
    OperationGetRequest,
    OperationCancelRequest,
    RunInspectRequest,
)
