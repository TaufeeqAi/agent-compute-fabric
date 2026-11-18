"""Requests: the method table, the parameter types and the request envelope.

Everything this client can send is built here, and nothing else. The models are **strict** (unknown
fields are an error) because the host is: it refuses a request with a field it does not know, so a
typo in a builder must fail in this client's tests, not in production.

Three properties of the envelope carry the operation semantics and are therefore enforced by the
model itself rather than left to callers:

* a method that creates an operation always carries a caller-generated ``operation_id`` and the
  ``issued_at`` of its *first* submission; a read never does, and never carries ``retry``;
* a request never carries ``authority`` (the field is reserved for a signed decision, and a host
  that does not advertise that feature refuses any request that has it): there is no such field;
* a secret is expressible only as a reference. There is no field that could hold secret material.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_serializer, model_validator

from acf_cli.wire import (
    ALIAS_PATTERN,
    LABEL_PATTERN,
    MAX_ON_BEHALF_OF_CHARS,
    MAX_OWNER_SCOPE_CHARS,
    MAX_REQUEST_ID_CHARS,
    OPERATION_ID_PATTERN,
    PROTOCOL,
    REFERENCE_NAME_PATTERN,
    RUN_ID_PATTERN,
    SANDBOX_ID_PATTERN,
    SNAPSHOT_ID_PATTERN,
    AckCondition,
    OperationClass,
    OutputStream,
    ReleaseMode,
    RequestedMode,
)

SandboxId = Annotated[str, StringConstraints(pattern=SANDBOX_ID_PATTERN)]
SnapshotId = Annotated[str, StringConstraints(pattern=SNAPSHOT_ID_PATTERN)]
RunId = Annotated[str, StringConstraints(pattern=RUN_ID_PATTERN)]
OperationId = Annotated[str, StringConstraints(pattern=OPERATION_ID_PATTERN)]
Alias = Annotated[str, StringConstraints(pattern=ALIAS_PATTERN)]
OwnerScope = Annotated[str, StringConstraints(pattern=LABEL_PATTERN, min_length=1, max_length=MAX_OWNER_SCOPE_CHARS)]
OnBehalfOf = Annotated[str, StringConstraints(pattern=LABEL_PATTERN, min_length=1, max_length=MAX_ON_BEHALF_OF_CHARS)]
RequestId = Annotated[str, StringConstraints(pattern=LABEL_PATTERN, min_length=1, max_length=MAX_REQUEST_ID_CHARS)]
#: Generations start at 1 and are never reused.
Generation = Annotated[int, Field(ge=1, le=2**64 - 1)]
Uint64 = Annotated[int, Field(ge=0, le=2**64 - 1)]
Uint32 = Annotated[int, Field(ge=0, le=2**32 - 1)]
Port = Annotated[int, Field(ge=1, le=65535)]

#: Largest page a list method returns.
MAX_LIST_LIMIT = 1000


class _Params(BaseModel):
    """A request type: strict and immutable."""

    model_config = ConfigDict(extra="forbid", frozen=True)


# ----------------------------------------------------------------------------- network intent
class PortRange(_Params):
    """One inclusive port range. On the wire: ``{"from": low, "to": high}``."""

    low: Port
    high: Port

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if self.low > self.high:
            msg = f"port range {self.low}-{self.high} is empty"
            raise ValueError(msg)
        return self

    @model_serializer
    def _wire(self) -> dict[str, int]:
        return {"from": self.low, "to": self.high}


class NameDestination(_Params):
    """An exact DNS name: TLS whose server name equals it, to an address the host resolver returned for it."""

    name: str = Field(min_length=1, max_length=253)


class NetworkDestination(_Params):
    """An IPv4 network in CIDR form: TCP to its addresses."""

    network: str = Field(min_length=1, max_length=18)


class AllowEntry(_Params):
    destination: NameDestination | NetworkDestination
    ports: list[PortRange] = Field(min_length=1)


class NetworkNone(_Params):
    """No network device exists in the guest."""

    mode: Literal["none"] = "none"


class NetworkAllowlist(_Params):
    """Outbound TCP to the listed destinations only."""

    mode: Literal["allowlist"] = "allowlist"
    entries: list[AllowEntry] = Field(min_length=1)


NetworkIntent = NetworkNone | NetworkAllowlist


# ----------------------------------------------------------------------------- parameter types
class SandboxResources(_Params):
    """What a sandbox is given. Immutable for the life of a generation."""

    vcpus: int = Field(ge=1, le=255)
    memory_mib: Uint32
    disk_mib: Uint32
    network: NetworkIntent


class SandboxCreateParams(_Params):
    name: Alias | None = None
    image: Alias
    resources: SandboxResources
    #: Lifetime from creation. Absent: the profile's default. Above its ceiling: refused, never clamped.
    lifetime_secs: Annotated[int, Field(ge=1, le=2**64 - 1)] | None = None


class SandboxTarget(_Params):
    """The target token of a lifecycle-changing method: an id and the generation the caller saw, never a name."""

    sandbox_id: SandboxId
    expected_generation: Generation
    #: Optional stronger precondition: the sandbox's revision must equal this.
    if_revision: Uint64 | None = None


class SandboxSelector(_Params):
    """Sandbox id **or** alias. Read-only lookups only."""

    sandbox: str = Field(min_length=1, max_length=64)


class RunLimitsRequest(_Params):
    """Limits a caller may ask for. Anything omitted takes the profile default."""

    timeout_ms: Uint64 | None = None
    max_pids: Uint32 | None = None
    max_stdout_bytes: Uint64 | None = None
    max_stderr_bytes: Uint64 | None = None


class SecretRef(_Params):
    """A secret named by reference: the name of a secret the operator provisioned on the host."""

    ref: Annotated[str, StringConstraints(pattern=REFERENCE_NAME_PATTERN)]


class CommandSpec(_Params):
    """Executed directly, never by a shell. Use ``["/bin/sh", "-c", "..."]`` to opt into one inside the guest."""

    argv: list[str] = Field(min_length=1)
    env: dict[str, str] = Field(default_factory=dict)
    #: Variables whose values the host delivers from its secret provider. References only.
    secret_env: dict[str, SecretRef] = Field(default_factory=dict)
    cwd: str | None = None
    limits: RunLimitsRequest = Field(default_factory=RunLimitsRequest)

    @model_validator(mode="after")
    def _well_formed(self) -> Self:
        if not self.argv[0]:
            msg = "argv must contain a program"
            raise ValueError(msg)
        both = sorted(set(self.env) & set(self.secret_env))
        if both:
            msg = f"{', '.join(both)}: a variable is either a value or a secret reference, not both"
            raise ValueError(msg)
        return self


class ExecParams(_Params):
    sandbox_id: SandboxId
    expected_generation: Generation
    if_revision: Uint64 | None = None
    command: CommandSpec


class SnapshotCreateParams(_Params):
    sandbox_id: SandboxId
    expected_generation: Generation
    if_revision: Uint64 | None = None
    name: Alias | None = None


class SnapshotRef(_Params):
    snapshot_id: SnapshotId
    snapshot_generation: Generation


class RestoreExisting(_Params):
    """Restore in place: a **new generation** of the same sandbox. Keeps the sandbox's expiry."""

    kind: Literal["existing"] = "existing"
    sandbox_id: SandboxId
    expected_generation: Generation
    if_revision: Uint64 | None = None


class RestoreNew(_Params):
    """Restore as a brand-new sandbox, generation 1."""

    kind: Literal["new"] = "new"
    name: Alias | None = None
    lifetime_secs: Annotated[int, Field(ge=1, le=2**64 - 1)] | None = None


class SnapshotRestoreParams(_Params):
    snapshot: SnapshotRef
    target: RestoreExisting | RestoreNew


class SnapshotDeleteParams(_Params):
    snapshot: SnapshotRef


class OperationSelector(_Params):
    operation_id: OperationId


class RunSelector(_Params):
    run_id: RunId


class RunOutputParams(_Params):
    run_id: RunId
    stream: OutputStream
    #: Byte offset into the stored output of the stream.
    offset: Uint64 = 0
    #: At most this many bytes (the host caps it).
    max_bytes: Uint64 | None = None


class Cursor(_Params):
    """A position in one store's history: meaningful only with its lineage."""

    lineage: str = Field(min_length=1)
    sequence: Uint64


class ListParams(_Params):
    #: Return only records that changed after this position, including tombstones.
    changed_since: Cursor | None = None
    limit: Annotated[int, Field(ge=1, le=MAX_LIST_LIMIT)] | None = None


class QuarantineReleaseParams(_Params):
    sandbox_id: SandboxId
    generation: Generation
    mode: ReleaseMode


class SetModeParams(_Params):
    mode: RequestedMode


class AcknowledgeParams(_Params):
    condition: AckCondition


# ----------------------------------------------------------------------------- the method table
@dataclass(frozen=True, slots=True)
class Method:
    """One method of the host API: its wire name, its class and the type of its ``params``."""

    name: str
    operation_class: OperationClass
    #: ``None``: the method takes no params.
    params: type[_Params] | None
    params_required: bool

    @property
    def creates_operation(self) -> bool:
        """Granting, containment and operator methods create a durable operation; reads leave no record."""
        return self.operation_class is not OperationClass.READ

    def __str__(self) -> str:
        return self.name


_G, _C, _R, _O = OperationClass.GRANTING, OperationClass.CONTAINMENT, OperationClass.READ, OperationClass.OPERATOR

SANDBOX_CREATE = Method("sandbox.create", _G, SandboxCreateParams, params_required=True)
SANDBOX_START = Method("sandbox.start", _G, SandboxTarget, params_required=True)
EXEC_RUN = Method("exec.run", _G, ExecParams, params_required=True)
SNAPSHOT_CREATE = Method("snapshot.create", _G, SnapshotCreateParams, params_required=True)
SNAPSHOT_RESTORE = Method("snapshot.restore", _G, SnapshotRestoreParams, params_required=True)
SANDBOX_STOP = Method("sandbox.stop", _C, SandboxTarget, params_required=True)
SANDBOX_DESTROY = Method("sandbox.destroy", _C, SandboxTarget, params_required=True)
SNAPSHOT_DELETE = Method("snapshot.delete", _C, SnapshotDeleteParams, params_required=True)
OPERATION_CANCEL = Method("operation.cancel", _C, OperationSelector, params_required=True)
SANDBOX_INSPECT = Method("sandbox.inspect", _R, SandboxSelector, params_required=True)
SANDBOX_LIST = Method("sandbox.list", _R, ListParams, params_required=False)
SNAPSHOT_LIST = Method("snapshot.list", _R, ListParams, params_required=False)
OPERATION_GET = Method("operation.get", _R, OperationSelector, params_required=True)
OPERATION_LIST = Method("operation.list", _R, ListParams, params_required=False)
RUN_INSPECT = Method("run.inspect", _R, RunSelector, params_required=True)
RUN_OUTPUT = Method("run.output", _R, RunOutputParams, params_required=True)
HOST_INFO = Method("host.info", _R, None, params_required=False)
HOST_METRICS = Method("host.metrics", _R, None, params_required=False)
PROFILE_RELOAD = Method("profile.reload", _O, None, params_required=False)
QUARANTINE_RELEASE = Method("quarantine.release", _O, QuarantineReleaseParams, params_required=True)
HOST_SET_MODE = Method("host.set_mode", _O, SetModeParams, params_required=True)
HOST_ACKNOWLEDGE = Method("host.acknowledge", _O, AcknowledgeParams, params_required=True)

#: Every method of the host API, by wire name, in the order of the contract's command table.
METHODS: Mapping[str, Method] = MappingProxyType(
    {
        m.name: m
        for m in (
            SANDBOX_CREATE,
            SANDBOX_START,
            EXEC_RUN,
            SNAPSHOT_CREATE,
            SNAPSHOT_RESTORE,
            SANDBOX_STOP,
            SANDBOX_DESTROY,
            SNAPSHOT_DELETE,
            OPERATION_CANCEL,
            SANDBOX_INSPECT,
            SANDBOX_LIST,
            SNAPSHOT_LIST,
            OPERATION_GET,
            OPERATION_LIST,
            RUN_INSPECT,
            RUN_OUTPUT,
            HOST_INFO,
            HOST_METRICS,
            PROFILE_RELOAD,
            QUARANTINE_RELEASE,
            HOST_SET_MODE,
            HOST_ACKNOWLEDGE,
        )
    }
)


@dataclass(frozen=True, slots=True)
class Call:
    """A method together with its parameters: *what* is asked, independent of who asks and when."""

    method: Method
    params: _Params | None = None

    def __post_init__(self) -> None:
        expected = self.method.params
        if self.params is None:
            if self.method.params_required:
                msg = f"`{self.method}` requires params"
                raise TypeError(msg)
        elif expected is None or type(self.params) is not expected:
            wanted = expected.__name__ if expected is not None else "no params"
            msg = f"`{self.method}` takes {wanted}, not {type(self.params).__name__}"
            raise TypeError(msg)

    def params_wire(self) -> dict[str, Any] | None:
        """``params`` as the host reads them. Absent fields are omitted: to the host, absent equals null."""
        if self.params is None:
            return None
        dumped: dict[str, Any] = self.params.model_dump(mode="json", exclude_none=True)
        return dumped


def sandbox_create(params: SandboxCreateParams) -> Call:
    return Call(SANDBOX_CREATE, params)


def sandbox_start(target: SandboxTarget) -> Call:
    return Call(SANDBOX_START, target)


def exec_run(params: ExecParams) -> Call:
    return Call(EXEC_RUN, params)


def snapshot_create(params: SnapshotCreateParams) -> Call:
    return Call(SNAPSHOT_CREATE, params)


def snapshot_restore(params: SnapshotRestoreParams) -> Call:
    return Call(SNAPSHOT_RESTORE, params)


def sandbox_stop(target: SandboxTarget) -> Call:
    return Call(SANDBOX_STOP, target)


def sandbox_destroy(target: SandboxTarget) -> Call:
    return Call(SANDBOX_DESTROY, target)


def snapshot_delete(snapshot: SnapshotRef) -> Call:
    return Call(SNAPSHOT_DELETE, SnapshotDeleteParams(snapshot=snapshot))


def operation_cancel(operation_id: str) -> Call:
    return Call(OPERATION_CANCEL, OperationSelector(operation_id=operation_id))


def sandbox_inspect(sandbox: str) -> Call:
    return Call(SANDBOX_INSPECT, SandboxSelector(sandbox=sandbox))


def sandbox_list(params: ListParams | None = None) -> Call:
    return Call(SANDBOX_LIST, params)


def snapshot_list(params: ListParams | None = None) -> Call:
    return Call(SNAPSHOT_LIST, params)


def operation_get(operation_id: str) -> Call:
    return Call(OPERATION_GET, OperationSelector(operation_id=operation_id))


def operation_list(params: ListParams | None = None) -> Call:
    return Call(OPERATION_LIST, params)


def run_inspect(run_id: str) -> Call:
    return Call(RUN_INSPECT, RunSelector(run_id=run_id))


def run_output(params: RunOutputParams) -> Call:
    return Call(RUN_OUTPUT, params)


def host_info() -> Call:
    return Call(HOST_INFO)


def host_metrics() -> Call:
    return Call(HOST_METRICS)


def profile_reload() -> Call:
    return Call(PROFILE_RELOAD)


def quarantine_release(params: QuarantineReleaseParams) -> Call:
    return Call(QUARANTINE_RELEASE, params)


def host_set_mode(mode: RequestedMode) -> Call:
    return Call(HOST_SET_MODE, SetModeParams(mode=mode))


def host_acknowledge(condition: AckCondition) -> Call:
    return Call(HOST_ACKNOWLEDGE, AcknowledgeParams(condition=condition))


# ----------------------------------------------------------------------------- the envelope
def new_operation_id() -> str:
    """``op-`` + 32 lowercase hex: unguessable, and within the host's ``[A-Za-z0-9-]{8,64}`` grammar."""
    return f"op-{uuid.uuid4().hex}"


def new_request_id() -> str:
    """Correlation only: echoed by the host, never an identity."""
    return f"req-{uuid.uuid4().hex[:16]}"


def utc_timestamp(moment: datetime | None = None) -> str:
    """``YYYY-MM-DDTHH:MM:SS.mmmZ``: UTC with a literal ``Z``, the one spelling the host accepts."""
    at = (moment or datetime.now(UTC)).astimezone(UTC)
    return f"{at:%Y-%m-%dT%H:%M:%S}.{at.microsecond // 1000:03d}Z"


class RequestEnvelope(_Params):
    """One request frame. The field set is exactly the contract's envelope table, minus ``authority``."""

    protocol: Literal["acf.host/2"] = PROTOCOL
    request_id: RequestId
    #: Caller-generated idempotency identity. Present exactly when the method creates an operation.
    operation_id: OperationId | None = None
    #: "I already submitted this operation." The host then never treats the request as new.
    retry: bool = False
    #: When the caller *first* issued the request. Never re-stamped on a retry.
    issued_at: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$")
    owner_scope: OwnerScope
    on_behalf_of: OnBehalfOf | None = None
    #: How long the caller is willing to wait for the operation to end before the host answers.
    wait_ms: Uint64 | None = None
    method: str
    params: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _operation_identity(self) -> Self:
        method = METHODS.get(self.method)
        if method is None:
            msg = f"`{self.method}` is not a method of {PROTOCOL}"
            raise ValueError(msg)
        if method.creates_operation:
            if self.operation_id is None or self.issued_at is None:
                msg = f"`{method}` creates an operation: it needs an operation_id and issued_at"
                raise ValueError(msg)
        elif self.operation_id is not None or self.issued_at is not None or self.retry or self.wait_ms is not None:
            msg = f"`{method}` is a read: it carries no operation_id, issued_at, retry or wait_ms"
            raise ValueError(msg)
        return self

    def wire(self) -> dict[str, Any]:
        """The frame's JSON object. ``retry`` is sent only when it is asserted."""
        out: dict[str, Any] = self.model_dump(mode="json", exclude_none=True)
        if not self.retry:
            del out["retry"]
        return out

    def encode(self) -> bytes:
        return json.dumps(self.wire(), separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def read_envelope(call: Call, *, owner_scope: str, on_behalf_of: str | None = None) -> RequestEnvelope:
    """The envelope of a read."""
    return RequestEnvelope(
        request_id=new_request_id(),
        owner_scope=owner_scope,
        on_behalf_of=on_behalf_of,
        method=call.method.name,
        params=call.params_wire(),
    )


def operation_envelope(
    call: Call,
    *,
    operation_id: str,
    issued_at: str,
    owner_scope: str,
    on_behalf_of: str | None = None,
    retry: bool = False,
    wait_ms: int | None = None,
) -> RequestEnvelope:
    """The envelope of a method that creates an operation.

    ``operation_id`` and ``issued_at`` belong to the operation, not to the attempt: a retry sends
    the same two values with ``retry=True`` and a fresh ``request_id``.
    """
    return RequestEnvelope(
        request_id=new_request_id(),
        operation_id=operation_id,
        retry=retry,
        issued_at=issued_at,
        owner_scope=owner_scope,
        on_behalf_of=on_behalf_of,
        wait_ms=wait_ms,
        method=call.method.name,
        params=call.params_wire(),
    )
