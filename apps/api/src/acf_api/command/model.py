"""The public resource model, version ``v1``.

This is the model a developer and an agent see: sandboxes, executions, snapshots, operations, agent
credentials. It is owned by the platform. Its vocabularies have, in this version, the same values as
the host's, and the correspondence is the mapping table loaded by the core, never an identity assumed
in code. No type of the host protocol is imported here or anywhere above the host binding.

Two families of types:

* ``RequestModel``: what a caller may send. Strict: no type coercion, and a member the schema does not
  define is refused, so a field that narrows a request can never be silently ignored.
* ``ViewModel``: what the platform renders. A host value the mapping table does not hold is shown as
  ``UNRECOGNIZED`` with the raw value beside it, and is never mapped onto a known value.

Fields that carry text the platform did not write are labelled in the schema (``x-provenance``):
``GUEST_REPORTED`` for what a guest produced, ``THIRD_PARTY`` for what another principal chose, and
``HOST_OBSERVED`` for what the host measured. The agent interface relies on those labels.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

API_VERSION: Final = "v1"

GUEST_REPORTED: Final = "GUEST_REPORTED"
HOST_OBSERVED: Final = "HOST_OBSERVED"
THIRD_PARTY: Final = "THIRD_PARTY"
UNRECOGNIZED: Final = "UNRECOGNIZED"

#: Longest sandbox or snapshot name. The host's rule for an alias; stated here so that a bad name is
#: refused with a precise message. The host's verdict stays the one that counts.
NAME_PATTERN: Final = r"^[A-Za-z0-9_-][A-Za-z0-9._-]{0,62}$"
SANDBOX_ID_PATTERN: Final = r"^sbx-[0-9a-f]{32}$"
SNAPSHOT_ID_PATTERN: Final = r"^snp-[0-9a-f]{32}$"
EXECUTION_ID_PATTERN: Final = r"^exe-[0-9a-f]{32}$"
OPERATION_ID_PATTERN: Final = r"^[A-Za-z0-9-]{8,64}$"
PROJECT_ID_PATTERN: Final = r"^prj_[0-9A-Za-z]{16,32}$"
CREDENTIAL_ID_PATTERN: Final = r"^crd_[0-9A-Za-z]{16,32}$"
AGENT_LABEL_PATTERN: Final = r"^[A-Za-z0-9_.-]{1,64}$"
SECRET_REF_PATTERN: Final = r"^[A-Za-z0-9._-]{1,64}$"  # noqa: S105 - the syntax of a secret's reference, not a secret
ENV_NAME_PATTERN: Final = r"^[A-Za-z_][A-Za-z0-9_]{0,254}$"

MAX_ALLOWLIST_ENTRIES: Final = 256
MAX_PORT_RANGES: Final = 64
MAX_ARGV_ITEMS: Final = 4096
MAX_ENV_ENTRIES: Final = 1024
MAX_PAGE_SIZE: Final = 1000


def _provenance(label: str) -> dict[str, Any]:
    return {"x-provenance": label}


class RequestModel(BaseModel):
    """Base of everything a caller sends."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ViewModel(BaseModel):
    """Base of everything the platform renders."""

    model_config = ConfigDict(extra="forbid", frozen=True)


# ------------------------------------------------------------------------------- vocabularies
class SandboxState(StrEnum):
    REQUESTED = "REQUESTED"
    PROVISIONING = "PROVISIONING"
    READY = "READY"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    DESTROYED = "DESTROYED"
    UNRECOGNIZED = "UNRECOGNIZED"


class OperationState(StrEnum):
    ACCEPTED = "ACCEPTED"
    IN_PROGRESS = "IN_PROGRESS"
    RECOVERING = "RECOVERING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    UNKNOWN = "UNKNOWN"
    UNRECOGNIZED = "UNRECOGNIZED"


#: The states in which an operation has ended. A state that is not listed, ``UNRECOGNIZED`` included,
#: is neither terminal nor success.
TERMINAL_OPERATION_STATES: Final = frozenset(
    {OperationState.SUCCEEDED, OperationState.FAILED, OperationState.CANCELLED, OperationState.UNKNOWN}
)


class Effect(StrEnum):
    APPLIED = "APPLIED"
    NOT_APPLIED = "NOT_APPLIED"
    MAY_BE_APPLIED = "MAY_BE_APPLIED"
    UNRECOGNIZED = "UNRECOGNIZED"


class Cleanup(StrEnum):
    COMPLETE = "COMPLETE"
    PENDING = "PENDING"
    QUARANTINED = "QUARANTINED"
    UNRECOGNIZED = "UNRECOGNIZED"


class CancelledBy(StrEnum):
    CALLER = "CALLER"
    SUPERSEDED = "SUPERSEDED"
    UNRECOGNIZED = "UNRECOGNIZED"


class ExecutionStatus(StrEnum):
    EXITED = "EXITED"
    SIGNALED = "SIGNALED"
    TIMED_OUT = "TIMED_OUT"
    SPAWN_FAILED = "SPAWN_FAILED"
    CANCELLED = "CANCELLED"
    UNKNOWN = "UNKNOWN"
    UNRECOGNIZED = "UNRECOGNIZED"


class SnapshotState(StrEnum):
    REQUESTED = "REQUESTED"
    SNAPSHOTTING = "SNAPSHOTTING"
    VERIFYING = "VERIFYING"
    READY = "READY"
    INVALID = "INVALID"
    DELETED = "DELETED"
    UNRECOGNIZED = "UNRECOGNIZED"


class OutputCompleteness(StrEnum):
    COMPLETE = "COMPLETE"
    TRUNCATED = "TRUNCATED"
    INCOMPLETE = "INCOMPLETE"
    UNRECOGNIZED = "UNRECOGNIZED"


class EvidenceStatus(StrEnum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    TRUNCATED = "TRUNCATED"
    UNKNOWN = "UNKNOWN"
    UNRECOGNIZED = "UNRECOGNIZED"


class SideEffect(StrEnum):
    NONE = "NONE"
    POSSIBLE = "POSSIBLE"
    UNRECOGNIZED = "UNRECOGNIZED"


class InitiatedBy(StrEnum):
    """Who caused an operation: a caller of the platform, or the host acting by itself."""

    CALLER = "CALLER"
    HOST = "HOST"
    UNRECOGNIZED = "UNRECOGNIZED"


class NetworkMode(StrEnum):
    NONE = "none"
    ALLOWLIST = "allowlist"


class OutputStream(StrEnum):
    STDOUT = "stdout"
    STDERR = "stderr"


class CredentialKind(StrEnum):
    DEVELOPER = "developer"
    AGENT = "agent"


class CredentialStatus(StrEnum):
    ISSUED = "ISSUED"
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class Reversibility(StrEnum):
    """The rollback class an operation states before a caller acts."""

    REVERSIBLE = "REVERSIBLE"
    COMPENSATABLE = "COMPENSATABLE"
    IRREVERSIBLE = "IRREVERSIBLE"


# ------------------------------------------------------------------------------- shared shapes
ExpectedGeneration = Annotated[
    Annotated[int, Field(ge=1)] | Literal["current"],
    Field(
        description=(
            "The generation the request acts on. An integer: the request acts on that generation or is refused "
            "with REVISION_CONFLICT. The literal `current`: the caller chooses, explicitly, to act on whatever "
            "generation is current when the platform reads it; the value read is recorded with the request."
        )
    ),
]


class PortRange(RequestModel):
    """One inclusive range of TCP ports."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, populate_by_name=True)

    first: int = Field(alias="from", ge=1, le=65535)
    last: int = Field(alias="to", ge=1, le=65535)

    @model_validator(mode="after")
    def _ordered(self) -> PortRange:
        if self.first > self.last:
            msg = "`from` must not be greater than `to`"
            raise ValueError(msg)
        return self


class AllowName(RequestModel):
    """Outbound TLS to an exact DNS name, on the listed ports."""

    name: str = Field(min_length=1, max_length=253)
    ports: list[PortRange] = Field(min_length=1, max_length=MAX_PORT_RANGES)


class AllowNetwork(RequestModel):
    """Outbound TCP to an IPv4 network in CIDR form, on the listed ports."""

    network: str = Field(min_length=9, max_length=18)
    ports: list[PortRange] = Field(min_length=1, max_length=MAX_PORT_RANGES)


AllowEntry = AllowName | AllowNetwork


class NetworkNone(RequestModel):
    """No network device exists in the sandbox."""

    mode: Literal["none"] = "none"


class NetworkAllowlist(RequestModel):
    """Outbound connections to the listed destinations only."""

    mode: Literal["allowlist"]
    entries: list[AllowEntry] = Field(max_length=MAX_ALLOWLIST_ENTRIES)


Network = Annotated[NetworkNone | NetworkAllowlist, Field(discriminator="mode")]


class Resources(RequestModel):
    """What a sandbox is given. Integers: vCPUs and MiB."""

    vcpus: int = Field(ge=1, le=255)
    memory_mib: int = Field(ge=1, le=4_194_304)
    disk_mib: int = Field(ge=1, le=268_435_456)


class SecretReference(RequestModel):
    """A secret named by reference. No field of the public model carries secret material."""

    ref: str = Field(pattern=SECRET_REF_PATTERN)


# ------------------------------------------------------------------------------- request bodies
class SandboxSpec(RequestModel):
    """Body of ``POST /v1/projects/{project}/sandboxes``. Creates a sandbox and does not start it."""

    image: str = Field(min_length=1, max_length=128, description="Image alias. The host lists which are allowed.")
    resources: Resources
    network: Network = Field(default_factory=NetworkNone)
    name: str | None = Field(default=None, pattern=NAME_PATTERN, description="An alias, unique in the project.")
    lifetime_seconds: int | None = Field(
        default=None, ge=1, le=31_536_000, description="Lifetime from creation. Absent: the host's default."
    )
    start: bool = Field(
        default=False,
        description=(
            "Create and start as one operation. Accepted only when the platform advertises the feature "
            "`create_with_start`; otherwise refused with UNSUPPORTED."
        ),
    )


class TargetBody(RequestModel):
    """Body of start and stop: the generation the request acts on."""

    expected_generation: ExpectedGeneration


class ExecSpec(RequestModel):
    """Body of ``POST …/sandboxes/{sandbox}/executions``: one command, as an argument vector."""

    expected_generation: ExpectedGeneration
    argv: list[str] = Field(
        min_length=1,
        max_length=MAX_ARGV_ITEMS,
        description='Executed directly, never through a shell. Use ["/bin/sh", "-c", "…"] to ask for one.',
    )
    cwd: str | None = Field(default=None, min_length=1, max_length=4096)
    env: dict[Annotated[str, Field(pattern=ENV_NAME_PATTERN)], str] = Field(
        default_factory=dict, max_length=MAX_ENV_ENTRIES
    )
    secret_env: dict[Annotated[str, Field(pattern=ENV_NAME_PATTERN)], SecretReference] = Field(
        default_factory=dict,
        max_length=MAX_ENV_ENTRIES,
        description="Environment variables delivered by reference. Needs the feature `secret_injection`.",
    )
    timeout_seconds: int | None = Field(default=None, ge=1, le=604_800)
    max_pids: int | None = Field(default=None, ge=1, le=4_194_304)
    max_stdout_bytes: int | None = Field(default=None, ge=0, le=1_073_741_824)
    max_stderr_bytes: int | None = Field(default=None, ge=0, le=1_073_741_824)


class SnapshotSpec(RequestModel):
    """Body of ``POST …/sandboxes/{sandbox}/snapshots``."""

    expected_generation: ExpectedGeneration
    name: str | None = Field(default=None, pattern=NAME_PATTERN, description="An alias, unique in the project.")


class RestoreInPlace(RequestModel):
    """Restore into an existing sandbox: a new generation of the same sandbox."""

    kind: Literal["existing"]
    sandbox_id: str = Field(pattern=SANDBOX_ID_PATTERN)
    expected_generation: ExpectedGeneration


class RestoreAsNew(RequestModel):
    """Restore as a new sandbox, generation 1."""

    kind: Literal["new"]
    name: str | None = Field(default=None, pattern=NAME_PATTERN)
    lifetime_seconds: int | None = Field(default=None, ge=1, le=31_536_000)


RestoreTarget = Annotated[RestoreInPlace | RestoreAsNew, Field(discriminator="kind")]


class RestoreSpec(RequestModel):
    """Body of ``POST …/snapshots/{snapshot}/restore``."""

    snapshot_generation: int = Field(ge=1)
    target: RestoreTarget


class GrantDestination(RequestModel):
    """One destination a grant allows: an exact name, a suffix rule ``*.<suffix>``, or an IPv4 network."""

    name: str | None = Field(default=None, min_length=1, max_length=253)
    suffix: str | None = Field(default=None, min_length=3, max_length=255, pattern=r"^\*\.[A-Za-z0-9.-]+$")
    network: str | None = Field(default=None, min_length=9, max_length=18)
    ports: list[PortRange] = Field(min_length=1, max_length=MAX_PORT_RANGES)

    @model_validator(mode="after")
    def _one_form(self) -> GrantDestination:
        if sum(v is not None for v in (self.name, self.suffix, self.network)) != 1:
            msg = "exactly one of `name`, `suffix` and `network` is required"
            raise ValueError(msg)
        return self


class GrantNetwork(RequestModel):
    modes: list[NetworkMode] = Field(default_factory=list, max_length=2)
    destinations: list[GrantDestination] = Field(default_factory=list, max_length=MAX_ALLOWLIST_ENTRIES)


class GrantCeilings(RequestModel):
    """Ceilings below the host's. A ceiling above the host's is legal and simply never reached."""

    vcpus: int = Field(ge=1, le=255)
    memory_mib: int = Field(ge=1, le=4_194_304)
    disk_mib: int = Field(ge=1, le=268_435_456)
    execution_timeout_seconds: int = Field(ge=1, le=604_800)
    sandbox_lifetime_seconds: int = Field(ge=1, le=31_536_000)


class Grant(RequestModel):
    """What a role allows, or what a credential narrows it to. Whatever is not mentioned is denied."""

    schema_version: Literal[1] = 1
    methods: list[str] = Field(default_factory=list, max_length=64)
    images: list[str] = Field(
        default_factory=list, max_length=256, description="Image aliases; `*` allows every image."
    )
    network: GrantNetwork = Field(default_factory=GrantNetwork)
    ceilings: GrantCeilings
    mint_agent_credentials: bool = False


class MintAgentCredentialSpec(RequestModel):
    """Body of ``POST …/agent-credentials``."""

    label: str = Field(pattern=AGENT_LABEL_PATTERN, description="Fixed for the life of the credential.")
    lifetime_seconds: int = Field(ge=60, le=31_536_000)
    narrowing: Grant | None = Field(
        default=None,
        description="A subset of the minting credential's effective grants. Absent: the `agent` template.",
    )


# ------------------------------------------------------------------------------- views
class Failure(ViewModel):
    """Why an operation, a sandbox or a snapshot failed, as the host reported it."""

    code: str = Field(description="A failure class of the public vocabulary, or UNRECOGNIZED.")
    code_raw: str | None = Field(default=None, description="The host's value, when `code` is UNRECOGNIZED.")
    retry: str
    message: str
    side_effect: str | None = None
    side_effect_raw: str | None = Field(
        default=None, description="The host's value, when `side_effect` is UNRECOGNIZED."
    )


class Image(ViewModel):
    alias: str | None = None
    digest: str = Field(description="Identity of the image the sandbox runs.")


class ResourcesView(ViewModel):
    vcpus: int
    memory_mib: int
    disk_mib: int


class PortRangeView(ViewModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    first: int = Field(alias="from")
    last: int = Field(alias="to")


class AllowEntryView(ViewModel):
    name: str | None = None
    network: str | None = None
    ports: list[PortRangeView]


class NetworkView(ViewModel):
    mode: str
    mode_raw: str | None = None
    entries: list[AllowEntryView] = Field(default_factory=list)


class SnapshotRef(ViewModel):
    snapshot_id: str
    snapshot_generation: int


class SandboxRef(ViewModel):
    sandbox_id: str
    generation: int


class Sandbox(ViewModel):
    sandbox_id: str
    project: str
    name: str | None = Field(default=None, json_schema_extra=_provenance(THIRD_PARTY))
    state: str
    state_raw: str | None = None
    generation: int
    revision: str = Field(description="Opaque validator, also sent as ETag. Compare for equality only.")
    image: Image
    resources: ResourcesView
    network: NetworkView
    expires_at: str
    last_execution: str | None = None
    quarantined: str | None = None
    failure: Failure | None = None
    source_snapshot: SnapshotRef | None = None
    notes: list[str] = Field(default_factory=list, json_schema_extra=_provenance(HOST_OBSERVED))
    updated_at: str


class OutputSummary(ViewModel):
    stored_bytes: int
    produced_bytes: int
    completeness: str
    completeness_raw: str | None = None


class Durations(ViewModel):
    guest_ms: int | None = Field(default=None, json_schema_extra=_provenance(GUEST_REPORTED))
    wall_ms: int | None = Field(default=None, json_schema_extra=_provenance(HOST_OBSERVED))


class Execution(ViewModel):
    """One command run in one generation of one sandbox."""

    execution_id: str
    operation_id: str
    project: str
    sandbox_id: str | None = None
    generation: int | None = None
    state: str = Field(description="State of the operation that runs the command.")
    state_raw: str | None = None
    terminal: bool
    status: str | None = Field(default=None, json_schema_extra=_provenance(GUEST_REPORTED))
    status_raw: str | None = None
    exit_code: int | None = Field(default=None, json_schema_extra=_provenance(GUEST_REPORTED))
    signal: int | None = Field(default=None, json_schema_extra=_provenance(GUEST_REPORTED))
    durations: Durations | None = None
    stdout: OutputSummary | None = Field(default=None, json_schema_extra=_provenance(GUEST_REPORTED))
    stderr: OutputSummary | None = Field(default=None, json_schema_extra=_provenance(GUEST_REPORTED))
    host_backstop_fired: bool | None = Field(default=None, json_schema_extra=_provenance(HOST_OBSERVED))
    runtime_ended: bool | None = Field(default=None, json_schema_extra=_provenance(HOST_OBSERVED))
    evidence_status: str | None = Field(default=None, json_schema_extra=_provenance(HOST_OBSERVED))
    evidence_status_raw: str | None = None
    note: str | None = Field(default=None, json_schema_extra=_provenance(HOST_OBSERVED))
    provenance: dict[str, str] = Field(
        default_factory=dict,
        description="The provenance label of each field of this result: HOST_OBSERVED or GUEST_REPORTED.",
    )


class OutputChunk(ViewModel):
    """A slice of one stream of an execution's stored output. The bytes are guest data."""

    execution_id: str
    stream: str
    offset: int
    data_base64: str = Field(json_schema_extra=_provenance(GUEST_REPORTED))
    next_offset: int
    eof: bool
    stored_bytes: int
    produced_bytes: int
    completeness: str
    completeness_raw: str | None = None
    provenance: Literal["GUEST_REPORTED"] = "GUEST_REPORTED"


class Snapshot(ViewModel):
    snapshot_id: str
    snapshot_generation: int
    project: str
    name: str | None = Field(default=None, json_schema_extra=_provenance(THIRD_PARTY))
    state: str
    state_raw: str | None = None
    revision: str
    source_sandbox: SandboxRef | None = None
    size_bytes: int
    restore_count: int
    incompatible: list[str] = Field(default_factory=list, json_schema_extra=_provenance(HOST_OBSERVED))
    failure: Failure | None = None
    created_at: str


class Actor(ViewModel):
    """Who asked for an operation, as the host recorded it."""

    principal_id: str | None = None
    agent_label: str | None = Field(default=None, json_schema_extra=_provenance(THIRD_PARTY))


class OperationTarget(ViewModel):
    """Identifiers of what an operation acts on and of what it produced."""

    sandbox_id: str | None = None
    generation: int | None = None
    snapshot_id: str | None = None
    snapshot_generation: int | None = None
    execution_id: str | None = None


class OperationResult(ViewModel):
    """The resource an operation produced, as of this answer. Absent in a recorded view."""

    sandbox: Sandbox | None = None
    snapshot: Snapshot | None = None
    execution: Execution | None = None


class Operation(ViewModel):
    """One accepted mutation. Exactly one host operation stands behind it."""

    operation_id: str
    project: str
    type: str
    type_raw: str | None = None
    state: str
    state_raw: str | None = None
    terminal: bool = Field(description="False for every state this version does not know.")
    effect: str | None = None
    effect_raw: str | None = None
    failure: Failure | None = None
    cleanup: str | None = None
    cleanup_raw: str | None = None
    cancelled_by: str | None = None
    cancelled_by_raw: str | None = None
    target: OperationTarget
    result: OperationResult | None = None
    initiated_by: str
    initiated_by_raw: str | None = None
    actor: Actor | None = None
    created_at: str | None = None
    updated_at: str | None = None
    replayed: bool = Field(
        default=False,
        description="True when this answer reports work that existed before the request that received it.",
    )
    recorded: bool = Field(
        default=False,
        description=(
            "True when the host no longer holds the operation and this is the terminal outcome the platform "
            "recorded while it did."
        ),
    )
    idempotency_key_digest: str | None = None


class Page(ViewModel):
    next_cursor: str = Field(description="Opaque. Pass it back as `cursor` to continue.")
    more: bool


class SandboxList(Page):
    items: list[Sandbox]


class SnapshotList(Page):
    items: list[Snapshot]


class OperationList(Page):
    items: list[Operation]


class AgentCredential(ViewModel):
    credential_id: str
    kind: str
    label: str | None = Field(default=None, json_schema_extra=_provenance(THIRD_PARTY))
    display_prefix: str
    status: str
    issued_at: str
    expires_at: str
    narrowing: dict[str, Any] | None = None
    secret: str | None = Field(
        default=None, description="The credential itself. Present once, in the answer to minting, and never again."
    )


class AgentCredentialList(ViewModel):
    items: list[AgentCredential]


class CredentialView(ViewModel):
    credential_id: str
    kind: str
    agent_label: str | None = None
    expires_at: str


class WhoAmI(ViewModel):
    principal_id: str
    project_id: str
    credential: CredentialView
    grants: dict[str, Any] = Field(description="The effective grants of this credential, and of no other.")
    policy_version: str


class Ceilings(ViewModel):
    vcpus: int
    memory_mib: int
    disk_mib: int
    execution_timeout_seconds: int
    sandbox_lifetime_seconds: int
    allowlist_entries: int


class Info(ViewModel):
    """Platform info. Without a credential: the API versions and whether the platform itself serves."""

    api_versions: list[str]
    serving: bool
    ready: bool | None = Field(default=None, description="Whether the platform accepts granting work now.")
    not_ready_reasons: list[str] | None = None
    platform_features: list[str] | None = None
    host_features: list[str] | None = None
    parameters: dict[str, int | float | bool] | None = None
    ceilings: Ceilings | None = None


class ErrorBody(ViewModel):
    """The members every error answer carries, on every interface."""

    code: str
    kind: str
    retry: str
    message: str = Field(description="Human-readable. Never repeats request content. Never parsed.")
    request_id: str
    idempotency_key: str | None = Field(
        default=None, description="Present on UNRESOLVED: the key to ask again with, unchanged."
    )
    reason: str | None = Field(default=None, description="A bounded reason code that refines `code`.")
    code_raw: str | None = None


class Problem(ErrorBody):
    """An RFC 9457 problem document: the REST encoding of an error answer."""

    type: str
    title: str
    status: int
    detail: str
    instance: str


def is_terminal(state: str) -> bool:
    """Whether an operation state is one in which the operation has ended."""
    try:
        return OperationState(state) in TERMINAL_OPERATION_STATES
    except ValueError:
        return False
