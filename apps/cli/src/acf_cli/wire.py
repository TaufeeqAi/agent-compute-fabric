"""The closed vocabularies of protocol ``acf.host/2``, as this client knows them.

Every enumeration here is transcribed from the host's published API description
(``execution/contracts/host-api.json``); ``tests/test_contract.py`` fails when one of them drifts.

A vocabulary is *closed on the host* and *open on the client*: the host refuses a word it does not
know, while a receiver must treat a word it does not know **as unknown, never as a default** (the
versioning rule for results). Response models therefore type such fields as ``Known | Unrecognized``:
a value outside the enumeration is kept verbatim as an :class:`Unrecognized` string, shown as
unrecognized, and never compared equal to a known member by accident.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Final

from pydantic import GetCoreSchemaHandler
from pydantic_core import core_schema

#: The protocol identifier this client speaks: family and major version.
PROTOCOL: Final = "acf.host/2"

#: Identifier grammars published by the host (``$defs`` of the API description).
SANDBOX_ID_PATTERN = r"^sbx-[0-9a-f]{32}$"
SNAPSHOT_ID_PATTERN = r"^snp-[0-9a-f]{32}$"
RUN_ID_PATTERN = r"^run-[0-9a-f]{32}$"
OPERATION_ID_PATTERN = r"^[A-Za-z0-9-]{8,64}$"
#: Caller-supplied labels (``owner_scope``, ``on_behalf_of``, ``request_id``).
LABEL_PATTERN = r"^[A-Za-z0-9._:/@=+-]+$"
MAX_OWNER_SCOPE_CHARS = 128
MAX_ON_BEHALF_OF_CHARS = 256
MAX_REQUEST_ID_CHARS = 128
#: Aliases (sandbox and snapshot names, image aliases) and secret reference names.
ALIAS_PATTERN = r"^[A-Za-z0-9_-][A-Za-z0-9._-]{0,62}$"
REFERENCE_NAME_PATTERN = r"^[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}$"


class Unrecognized(str):
    """A value of a wire vocabulary that this client does not know.

    It is an ordinary string (so it prints and serialises as what the host sent), but it is never
    an enumeration member: ``isinstance(value, OperationState)`` is how code asks "do I know what
    this means?", and the answer for an :class:`Unrecognized` value is always no.
    """

    __slots__ = ()

    @classmethod
    def __get_pydantic_core_schema__(cls, source: Any, handler: GetCoreSchemaHandler) -> core_schema.CoreSchema:  # noqa: ANN401
        return core_schema.no_info_after_validator_function(cls, core_schema.str_schema(strict=True))


class Answer(StrEnum):
    """The three answers of the response model."""

    REFUSED = "REFUSED"
    OPERATION = "OPERATION"
    RESULT = "RESULT"


class OperationClass(StrEnum):
    GRANTING = "granting"
    CONTAINMENT = "containment"
    READ = "read"
    OPERATOR = "operator"


class Role(StrEnum):
    OBSERVER = "observer"
    CALLER = "caller"
    OPERATOR = "operator"


class FailureClass(StrEnum):
    INVALID_REQUEST = "INVALID_REQUEST"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    AUTHORIZATION_DENIED = "AUTHORIZATION_DENIED"
    SAFETY_CONTROL_DENIED = "SAFETY_CONTROL_DENIED"
    NOT_FOUND = "NOT_FOUND"
    STATE_CONFLICT = "STATE_CONFLICT"
    REVISION_CONFLICT = "REVISION_CONFLICT"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    EXPIRED_REQUEST = "EXPIRED_REQUEST"
    RESOURCE_EXHAUSTED = "RESOURCE_EXHAUSTED"
    HOST_NOT_SERVING = "HOST_NOT_SERVING"
    UNSUPPORTED = "UNSUPPORTED"
    QUARANTINED = "QUARANTINED"
    CURSOR_EXPIRED = "CURSOR_EXPIRED"
    PROTOCOL_ERROR = "PROTOCOL_ERROR"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
    INCOMPATIBLE_RUNTIME = "INCOMPATIBLE_RUNTIME"
    TIMEOUT = "TIMEOUT"
    DEPENDENCY_UNAVAILABLE = "DEPENDENCY_UNAVAILABLE"
    SECURITY_CONTROL_FAILURE = "SECURITY_CONTROL_FAILURE"
    PARTIAL_COMPLETION = "PARTIAL_COMPLETION"
    UNKNOWN_OUTCOME = "UNKNOWN_OUTCOME"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class RetryAdvice(StrEnum):
    """What a refused caller should do."""

    SAME_REQUEST_LATER = "SAME_REQUEST_LATER"
    AFTER_CHANGE = "AFTER_CHANGE"
    NEVER = "NEVER"


class SideEffect(StrEnum):
    NONE = "NONE"
    POSSIBLE = "POSSIBLE"


class OperationState(StrEnum):
    """``UNKNOWN`` is a first-class terminal state: never success, never failure."""

    ACCEPTED = "ACCEPTED"
    IN_PROGRESS = "IN_PROGRESS"
    RECOVERING = "RECOVERING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    UNKNOWN = "UNKNOWN"

    @property
    def is_terminal(self) -> bool:
        return self in _TERMINAL_STATES


_TERMINAL_STATES = frozenset(
    {OperationState.SUCCEEDED, OperationState.FAILED, OperationState.CANCELLED, OperationState.UNKNOWN}
)


class OperationType(StrEnum):
    """Every method that is not a read, plus ``sandbox.fail``, which only the host itself issues."""

    SANDBOX_CREATE = "sandbox.create"
    SANDBOX_START = "sandbox.start"
    EXEC_RUN = "exec.run"
    SNAPSHOT_CREATE = "snapshot.create"
    SNAPSHOT_RESTORE = "snapshot.restore"
    SANDBOX_STOP = "sandbox.stop"
    SANDBOX_DESTROY = "sandbox.destroy"
    SANDBOX_FAIL = "sandbox.fail"
    SNAPSHOT_DELETE = "snapshot.delete"
    OPERATION_CANCEL = "operation.cancel"
    PROFILE_RELOAD = "profile.reload"
    QUARANTINE_RELEASE = "quarantine.release"
    HOST_SET_MODE = "host.set_mode"
    HOST_ACKNOWLEDGE = "host.acknowledge"


class Effect(StrEnum):
    """What a terminal operation did. A *new* operation for the same intent is safe only after ``NOT_APPLIED``."""

    APPLIED = "APPLIED"
    NOT_APPLIED = "NOT_APPLIED"
    MAY_BE_APPLIED = "MAY_BE_APPLIED"


class Cleanup(StrEnum):
    """Whether what a ``FAILED`` or ``CANCELLED`` operation created is gone."""

    COMPLETE = "COMPLETE"
    PENDING = "PENDING"
    QUARANTINED = "QUARANTINED"


class CancelledBy(StrEnum):
    CALLER = "CALLER"
    SUPERSEDED = "SUPERSEDED"


class Issuer(StrEnum):
    PEER = "PEER"
    HOST = "HOST"


class HostMode(StrEnum):
    STARTING = "STARTING"
    SERVING = "SERVING"
    DRAINING = "DRAINING"
    CONTAINMENT = "CONTAINMENT"
    READ_ONLY = "READ_ONLY"


class LifecycleState(StrEnum):
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


class SnapshotState(StrEnum):
    REQUESTED = "REQUESTED"
    SNAPSHOTTING = "SNAPSHOTTING"
    VERIFYING = "VERIFYING"
    READY = "READY"
    INVALID = "INVALID"
    DELETED = "DELETED"


class RunStatus(StrEnum):
    """How one execution ended. A non-zero exit is a result (``EXITED``), not an operation failure."""

    EXITED = "EXITED"
    SIGNALED = "SIGNALED"
    TIMED_OUT = "TIMED_OUT"
    SPAWN_FAILED = "SPAWN_FAILED"
    CANCELLED = "CANCELLED"
    UNKNOWN = "UNKNOWN"


class EvidenceStatus(StrEnum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    TRUNCATED = "TRUNCATED"
    UNKNOWN = "UNKNOWN"


class OutputStatus(StrEnum):
    COMPLETE = "COMPLETE"
    TRUNCATED = "TRUNCATED"
    INCOMPLETE = "INCOMPLETE"


class ArtifactKind(StrEnum):
    STDOUT = "stdout"
    STDERR = "stderr"
    EVIDENCE = "evidence"
    SNAPSHOT_VMSTATE = "snapshot_vmstate"
    SNAPSHOT_MEMORY = "snapshot_memory"
    SNAPSHOT_DISK = "snapshot_disk"
    SNAPSHOT_MANIFEST = "snapshot_manifest"


class NetworkMode(StrEnum):
    """The network vocabulary has exactly two modes."""

    NONE = "none"
    ALLOWLIST = "allowlist"


class OutputStream(StrEnum):
    STDOUT = "stdout"
    STDERR = "stderr"


class ReleaseMode(StrEnum):
    """What an operator asserts when releasing a quarantined generation."""

    FORCE_DESTROY = "FORCE_DESTROY"
    DECLARE_ABSENT = "DECLARE_ABSENT"


class RequestedMode(StrEnum):
    """The two host modes an operator may ask for; every other mode is entered by the host itself."""

    DRAINING = "DRAINING"
    SERVING = "SERVING"


class AckCondition(StrEnum):
    STORE_REGRESSION = "store_regression"
