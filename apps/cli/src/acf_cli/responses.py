"""Responses: the three answers of protocol ``acf.host/2`` and every type they carry.

Where requests are strict, responses are **tolerant** — in two precise ways and no others:

* an **unknown field** is kept, not refused (``extra="allow"``), so an additive change on the host
  neither breaks this client nor disappears from its ``--json`` output;
* an **unknown word of a closed vocabulary** (a state, a failure class, an answer kind, a result
  type, ...) is kept as an :class:`~acf_cli.wire.Unrecognized` value. It is surfaced as unknown and
  is never mapped to a known member, so nothing downstream can mistake it for success or failure.

Tolerance stops there: a *known* field of the wrong type, or a known result type whose payload does
not have its shape, is a protocol violation and fails validation.

Serialising a model with :func:`to_wire` gives back exactly what the host sent, unknown fields
included; ``tests/test_contract.py`` proves it on recorded answers of the real host.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Discriminator, Field, Tag, model_validator

from acf_cli.wire import (
    Answer,
    ArtifactKind,
    CancelledBy,
    Cleanup,
    Effect,
    EvidenceStatus,
    FailureClass,
    HostMode,
    Issuer,
    LifecycleState,
    NetworkMode,
    OperationState,
    OperationType,
    OutputStatus,
    OutputStream,
    RetryAdvice,
    RunStatus,
    SideEffect,
    SnapshotState,
    Unrecognized,
)


def _open() -> Any:  # noqa: ANN401 - pydantic's FieldInfo, used as Annotated metadata
    """Try the vocabulary first; keep anything else verbatim as :class:`Unrecognized`."""
    return Field(union_mode="left_to_right")


OpenAnswer = Annotated[Answer | Unrecognized, _open()]
OpenFailureClass = Annotated[FailureClass | Unrecognized, _open()]
OpenRetryAdvice = Annotated[RetryAdvice | Unrecognized, _open()]
OpenSideEffect = Annotated[SideEffect | Unrecognized, _open()]
OpenOperationState = Annotated[OperationState | Unrecognized, _open()]
OpenOperationType = Annotated[OperationType | Unrecognized, _open()]
OpenEffect = Annotated[Effect | Unrecognized, _open()]
OpenCleanup = Annotated[Cleanup | Unrecognized, _open()]
OpenCancelledBy = Annotated[CancelledBy | Unrecognized, _open()]
OpenIssuer = Annotated[Issuer | Unrecognized, _open()]
OpenHostMode = Annotated[HostMode | Unrecognized, _open()]
OpenLifecycleState = Annotated[LifecycleState | Unrecognized, _open()]
OpenSnapshotState = Annotated[SnapshotState | Unrecognized, _open()]
OpenRunStatus = Annotated[RunStatus | Unrecognized, _open()]
OpenEvidenceStatus = Annotated[EvidenceStatus | Unrecognized, _open()]
OpenOutputStatus = Annotated[OutputStatus | Unrecognized, _open()]
OpenArtifactKind = Annotated[ArtifactKind | Unrecognized, _open()]
OpenNetworkMode = Annotated[NetworkMode | Unrecognized, _open()]
OpenOutputStream = Annotated[OutputStream | Unrecognized, _open()]


class _View(BaseModel):
    """A response type: immutable, and tolerant of fields this client does not know."""

    model_config = ConfigDict(extra="allow", frozen=True)


def to_wire(model: BaseModel) -> dict[str, Any]:
    """The JSON object the host sent for ``model``: wire field names, nothing added, nothing dropped."""
    dumped: dict[str, Any] = model.model_dump(mode="json", by_alias=True, exclude_unset=True)
    return dumped


# ----------------------------------------------------------------------------- shared pieces
class AsOf(_View):
    """The committed state an answer reflects: a store lineage and a commit sequence."""

    lineage: str
    sequence: int

    def __str__(self) -> str:
        return f"{self.lineage}:{self.sequence}"


class Refusal(_View):
    """``REFUSED``: the request was not accepted. Nothing was applied and nothing was recorded."""

    failure_class: OpenFailureClass = Field(alias="class")
    retry: OpenRetryAdvice
    message: str


class FailureInfo(_View):
    failure_class: OpenFailureClass = Field(alias="class")
    message: str
    side_effect: OpenSideEffect


class Tags(_View):
    """``(peer_id, owner_scope)`` of the request that created a record."""

    peer_id: str
    owner_scope: str

    def __str__(self) -> str:
        return f"{self.peer_id}/{self.owner_scope}"


class ProfileId(_View):
    name: str
    version: str
    digest: str

    def short(self) -> str:
        return f"{self.name}@{self.version}#{self.digest[:12]}"


class ImageRef(_View):
    image_id: str
    alias: str | None = None
    architecture: str
    kernel_identity: str
    rootfs_identity: str
    manifest_version: int
    provenance_reference: str | None = None


class ProcessIdentity(_View):
    pid: int
    start_time_ticks: int
    boot_id: str


class SnapshotRefView(_View):
    snapshot_id: str
    snapshot_generation: int

    def __str__(self) -> str:
        return f"{self.snapshot_id}@{self.snapshot_generation}"


class CursorView(_View):
    """A position in one store's history. Pass it back as ``changed_since`` to continue a listing."""

    lineage: str
    sequence: int

    def __str__(self) -> str:
        return f"{self.lineage}:{self.sequence}"


# ----------------------------------------------------------------------------- sandboxes and snapshots
class PortRangeView(_View):
    low: int = Field(alias="from")
    high: int = Field(alias="to")

    def __str__(self) -> str:
        return str(self.low) if self.low == self.high else f"{self.low}-{self.high}"


class AllowDestinationView(_View):
    """Exactly one of the two is set by a host of this protocol version."""

    name: str | None = None
    network: str | None = None

    def __str__(self) -> str:
        return self.name or self.network or "?"


class AllowEntryView(_View):
    destination: AllowDestinationView
    ports: list[PortRangeView]

    def __str__(self) -> str:
        return f"{self.destination}:{','.join(str(p) for p in self.ports)}"


class NetworkIntentView(_View):
    mode: OpenNetworkMode
    entries: list[AllowEntryView] | None = None


class SandboxResourcesView(_View):
    vcpus: int
    memory_mib: int
    disk_mib: int
    network: NetworkIntentView


class SandboxView(_View):
    sandbox_id: str
    generation: int
    name: str | None = None
    state: OpenLifecycleState
    resources: SandboxResourcesView
    image: ImageRef
    tags: Tags
    #: When the sandbox ends, wall clock, for display. The host enforces it.
    expires_at: str
    process: ProcessIdentity | None = None
    security_profile_id: str
    last_run: str | None = None
    source_snapshot: SnapshotRefView | None = None
    failure: FailureInfo | None = None
    #: The condition ``QUARANTINED``, with its reason.
    quarantined: str | None = None
    secret_bearing: bool
    notes: list[str] = Field(default_factory=list)
    updated: str
    #: Commit sequence of the last change to the sandbox's caller-visible state.
    revision: int


class SnapshotView(_View):
    snapshot: SnapshotRefView
    name: str | None = None
    state: OpenSnapshotState
    tags: Tags
    size_bytes: int
    source_sandbox: tuple[str, int] | None = None
    manifest_digest: str | None = None
    restore_count: int
    #: References of the secrets live in the sandbox at capture. Never material.
    secret_refs: list[str] = Field(default_factory=list)
    #: Why this snapshot cannot be restored on this host as it is now. Empty: compatible.
    incompatible: list[str] = Field(default_factory=list)
    created: str
    failure: FailureInfo | None = None
    revision: int


# ----------------------------------------------------------------------------- executions
class ArtifactRef(_View):
    artifact_id: str
    kind: OpenArtifactKind
    logical_name: str
    schema_version: int
    content_digest: str | None = None
    byte_size: int | None = None
    source_operation_id: str
    sandbox_id: str
    run_id: str | None = None


class OutputCapture(_View):
    status: OpenOutputStatus
    #: Bytes the workload produced (more than ``kept_bytes`` when truncated).
    total_bytes: int
    kept_bytes: int
    data_b64: str
    artifact: ArtifactRef | None = None


class RunMetrics(_View):
    wall_ms: int
    cpu_usage_usec: int | None = None
    memory_peak_bytes: int | None = None


class ResourceEvidence(_View):
    resource: str
    configured: int | None = None
    effective: int | None = None
    observed_peak: int | None = None
    violated: bool
    action_taken: str
    mechanism: str


class RunResult(_View):
    """The result of one execution. Exit status and output are what the guest reported."""

    run_id: str
    operation_id: str
    sandbox_id: str
    generation: int
    status: OpenRunStatus
    exit_code: int | None = None
    signal: int | None = None
    stdout: OutputCapture
    stderr: OutputCapture
    guest_duration_ms: int
    guest_containment: str
    #: The host's own deadline passed without a result and the host ended the runtime.
    host_backstop_fired: bool
    runtime_ended: bool
    metrics: RunMetrics
    evidence_status: OpenEvidenceStatus
    resource_evidence: list[ResourceEvidence]
    artifacts: list[ArtifactRef]
    profile_id: ProfileId
    image_id: str
    note: str | None = None

    @property
    def exited_cleanly(self) -> bool:
        """The command ended by itself with exit status 0. Anything else — including a status this client does
        not know — is not a clean exit."""
        return self.status is RunStatus.EXITED and self.exit_code == 0


class OutputChunk(_View):
    """A slice of one stream of an execution's stored output."""

    run_id: str
    stream: OpenOutputStream
    offset: int
    data_b64: str
    stored_bytes: int
    produced_bytes: int
    completeness: OpenOutputStatus
    #: No stored byte follows this slice.
    eof: bool


# ----------------------------------------------------------------------------- the host
class HostChange(_View):
    """What the host changed for an operator method, or what it observed."""

    mode: OpenHostMode | None = None
    profile: ProfileId | None = None
    note: str | None = None


class ProfileLimits(_View):
    max_vcpus: int
    max_memory_mib: int
    max_disk_mib: int
    max_runtime_ms: int
    max_pids: int
    max_stdout_bytes: int
    max_stderr_bytes: int
    max_argv_items: int
    max_argv_bytes: int
    max_env_entries: int
    max_lifetime_secs: int
    max_allowlist_entries: int


class CallerParameters(_View):
    """The host's parameters a caller depends on."""

    acceptance_horizon_ms: int
    clock_skew_tolerance_ms: int
    operation_retention_ms: int
    change_retention_ms: int
    output_retention_ms: int
    wait_max_ms: int
    max_request_bytes: int
    ceilings: ProfileLimits
    sandbox_lifetime_default_secs: int
    sandbox_lifetime_max_secs: int
    allowlist_max_entries: int


class BackendIdentity(_View):
    name: str
    version: str
    security_profile_id: str
    #: Human-auditable detail behind ``security_profile_id``. Free-form.
    profile: Any


class CapabilityProfile(_View):
    """What the backend declares it can do.

    ``identifier_slots`` and ``stop_grace_ms`` describe the backend and drive nothing in this
    client. They joined the capability profile after the first hosts of this protocol were
    built, so a host that predates them is still read: they are optional here.
    """

    backend: str
    pause_resume: bool
    snapshot: bool
    restore: bool
    guest_exec: bool
    network_modes: list[OpenNetworkMode]
    max_vcpus: int
    secret_injection: bool
    incremental_output: bool
    restore_reseeds_entropy: bool
    runtime_depends_on_snapshot: bool
    runtime_depends_on_image: bool
    per_runtime_overhead_mib: int
    #: How many generations can hold distinct identifiers at once.
    identifier_slots: int | None = None
    #: How long the backend lets a runtime end by itself before it ends it by force.
    stop_grace_ms: int | None = None


class ContainmentReason(_View):
    reason: str
    detail: str


class HostInfo(_View):
    version: str
    host_id: str
    protocols: list[str]
    features: list[str]
    mode: OpenHostMode
    containment_reasons: list[ContainmentReason]
    read_only_reason: str | None = None
    lineage: str
    activation_epoch: int
    instance_id: str
    backend: BackendIdentity
    capabilities: CapabilityProfile
    profile: ProfileId
    parameters: CallerParameters
    store_integrity: str
    live_sandboxes: int
    snapshots: int
    quarantined: int
    operations_in_flight: int


# ----------------------------------------------------------------------------- typed results
class SandboxBody(_View):
    type: Literal["sandbox"]
    data: SandboxView


class SnapshotBody(_View):
    type: Literal["snapshot"]
    data: SnapshotView


class RunBody(_View):
    type: Literal["run"]
    data: RunResult


class HostChangeBody(_View):
    type: Literal["host"]
    data: HostChange


class UnrecognizedBody(_View):
    """A result of a type this client does not know. Its payload is kept as the host sent it."""

    type: Unrecognized
    data: Any = None


def _tag_among(known: frozenset[str]) -> Discriminator:
    def tag(value: Any) -> str:  # noqa: ANN401 - raw input or an already validated model
        kind = value.get("type") if isinstance(value, dict) else getattr(value, "type", None)
        return kind if isinstance(kind, str) and kind in known else "unrecognized"

    return Discriminator(tag)


OperationResult = Annotated[
    Annotated[SandboxBody, Tag("sandbox")]
    | Annotated[SnapshotBody, Tag("snapshot")]
    | Annotated[RunBody, Tag("run")]
    | Annotated[HostChangeBody, Tag("host")]
    | Annotated[UnrecognizedBody, Tag("unrecognized")],
    _tag_among(frozenset({"sandbox", "snapshot", "run", "host"})),
]


class OperationView(_View):
    """An operation as of the response. Terminal only if it ended within the caller's wait."""

    operation_id: str
    operation_type: OpenOperationType
    state: OpenOperationState
    #: Present once terminal.
    effect: OpenEffect | None = None
    #: Present on a ``FAILED`` or ``CANCELLED`` operation.
    cleanup: OpenCleanup | None = None
    cancelled_by: OpenCancelledBy | None = None
    issuer: OpenIssuer
    tags: Tags
    on_behalf_of: str | None = None
    #: ``sbx-...``, ``snp-...``, an operation id or ``host``.
    target: str
    #: The last privileged step declared.
    step: str | None = None
    failure: FailureInfo | None = None
    result: OperationResult | None = None
    run_id: str | None = None
    sandbox: tuple[str, int] | None = None
    snapshot: SnapshotRefView | None = None
    profile_id: ProfileId
    activation_epoch: int
    issued_at: str
    created: str
    updated: str
    revision: int

    @property
    def is_terminal(self) -> bool:
        """Whether the operation has ended.

        A state this client does not know is terminal exactly when the host states an ``effect``,
        because an effect is stated once an operation is terminal and never before.
        """
        if isinstance(self.state, OperationState):
            return self.state.is_terminal
        return self.effect is not None

    @property
    def succeeded(self) -> bool:
        return self.state is OperationState.SUCCEEDED


class Page[T](_View):
    """One page of a list, in ascending revision order.

    Continue from ``next``; when ``more`` is false, ``next`` is the position the listing is
    complete up to.
    """

    items: list[T]
    more: bool
    next: CursorView


class HostInfoBody(_View):
    type: Literal["host_info"]
    data: HostInfo


class MetricsBody(_View):
    type: Literal["metrics"]
    data: Any = None


class SandboxesBody(_View):
    type: Literal["sandboxes"]
    data: Page[SandboxView]


class SnapshotsBody(_View):
    type: Literal["snapshots"]
    data: Page[SnapshotView]


class OperationBody(_View):
    type: Literal["operation"]
    data: OperationView


class OperationsBody(_View):
    type: Literal["operations"]
    data: Page[OperationView]


class OutputBody(_View):
    type: Literal["output"]
    data: OutputChunk


ReadResult = Annotated[
    Annotated[HostInfoBody, Tag("host_info")]
    | Annotated[MetricsBody, Tag("metrics")]
    | Annotated[SandboxBody, Tag("sandbox")]
    | Annotated[SandboxesBody, Tag("sandboxes")]
    | Annotated[SnapshotsBody, Tag("snapshots")]
    | Annotated[OperationBody, Tag("operation")]
    | Annotated[OperationsBody, Tag("operations")]
    | Annotated[RunBody, Tag("run")]
    | Annotated[OutputBody, Tag("output")]
    | Annotated[UnrecognizedBody, Tag("unrecognized")],
    _tag_among(
        frozenset(
            {"host_info", "metrics", "sandbox", "sandboxes", "snapshots", "operation", "operations", "run", "output"}
        )
    ),
]


# ----------------------------------------------------------------------------- the envelope
class ResponseEnvelope(_View):
    """One response frame: ``REFUSED``, ``OPERATION`` or ``RESULT``, and the state it reflects."""

    protocol: str
    #: Echo of the request's ``request_id``; absent on a refusal issued before a request was read.
    request_id: str | None = None
    answer: OpenAnswer
    refusal: Refusal | None = None
    operation: OperationView | None = None
    result: ReadResult | None = None
    #: The committed state this answer reflects. Absent only on a refusal that consulted no state.
    as_of: AsOf | None = None

    @model_validator(mode="after")
    def _answer_carries_its_body(self) -> Self:
        missing = {
            Answer.REFUSED: self.refusal is None,
            Answer.OPERATION: self.operation is None,
            Answer.RESULT: self.result is None,
        }
        if isinstance(self.answer, Answer) and missing[self.answer]:
            body = {Answer.REFUSED: "refusal", Answer.OPERATION: "operation", Answer.RESULT: "result"}[self.answer]
            msg = f"answer {self.answer.value} without its `{body}`"
            raise ValueError(msg)
        return self
