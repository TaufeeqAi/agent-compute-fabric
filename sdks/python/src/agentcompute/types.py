"""Views: thin typed objects over the JSON the server sent.

A view keeps the JSON exactly as it was received in ``raw`` and reads its members from there. Nothing
is copied, renamed or converted, with two exceptions that Python forces: the members ``from`` and ``to``
of a port range are read as ``first`` and ``last``, and the bytes of an output chunk are also available
decoded, as ``data``.

Three rules follow from the API's versioning, and every view keeps them:

* a member this version does not know is ignored (it is still in ``raw``);
* every vocabulary (states, statuses, codes, modes) is a plain string, so a value this version has never
  seen is shown as it came and is never mapped onto a known one;
* an optional member that is absent reads as ``None`` (or as an empty tuple for a list).

A member that the API requires and that is missing, or that has the wrong JSON type, raises
:class:`~agentcompute.errors.UnexpectedResponseError` when it is read: the answer is not a view of this API.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, ClassVar, Final, Self, overload

from agentcompute.errors import FabricError, UnexpectedResponseError

__all__ = [
    "Actor",
    "AgentCredential",
    "AllowEntryView",
    "Ceilings",
    "ContainmentFailure",
    "CredentialView",
    "Durations",
    "ExecutionView",
    "Failure",
    "Image",
    "Info",
    "NetworkView",
    "Operation",
    "OperationResult",
    "OperationTarget",
    "OutputChunk",
    "OutputSummary",
    "PortRangeView",
    "ResourcesView",
    "SandboxRef",
    "SandboxView",
    "SnapshotRef",
    "SnapshotView",
    "View",
    "WhoAmI",
]

#: The states in which an operation has ended. A state that is not listed here has not ended, whatever
#: else an answer says about it: a state this version does not know is neither terminal nor success.
ENDED_STATES: Final = frozenset({"SUCCEEDED", "FAILED", "CANCELLED", "UNKNOWN"})

_NOT_IDENTIFIERS: Final = frozenset({"", ".", ".."})

type _Json = Mapping[str, Any]
type _Reader[T] = Callable[[_Json, str], T]


def has_ended(state: str) -> bool:
    """Whether an operation state is one in which the operation has ended."""
    return state in ENDED_STATES


def _malformed(key: str, expected: str) -> UnexpectedResponseError:
    # The value itself is never repeated: it may be guest data.
    return UnexpectedResponseError(f"member {key!r} of this view is missing or is not {expected}")


def _text(raw: _Json, key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str):
        raise _malformed(key, "a string")
    return value


def _opt_text(raw: _Json, key: str) -> str | None:
    value = raw.get(key)
    if value is not None and not isinstance(value, str):
        raise _malformed(key, "a string or null")
    return value


def _identifier(raw: _Json, key: str) -> str:
    """An identifier: it becomes a path segment, so it is never empty and never a dot segment."""
    value = raw.get(key)
    if not isinstance(value, str) or value in _NOT_IDENTIFIERS:
        raise _malformed(key, "an identifier")
    return value


def _whole(raw: _Json, key: str) -> int:
    value = raw.get(key)
    # bool is a subclass of int in Python and is not a JSON number.
    if isinstance(value, bool) or not isinstance(value, int):
        raise _malformed(key, "an integer")
    return value


def _opt_whole(raw: _Json, key: str) -> int | None:
    value = raw.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise _malformed(key, "an integer or null")
    return value


def _flag(raw: _Json, key: str) -> bool:
    value = raw.get(key)
    if not isinstance(value, bool):
        raise _malformed(key, "a boolean")
    return value


def _opt_flag(raw: _Json, key: str) -> bool | None:
    value = raw.get(key)
    if value is not None and not isinstance(value, bool):
        raise _malformed(key, "a boolean or null")
    return value


def _flag_or_false(raw: _Json, key: str) -> bool:
    """A boolean whose absence means ``False`` (``replayed``, ``recorded``)."""
    return _opt_flag(raw, key) or False


def _texts(raw: _Json, key: str) -> tuple[str, ...]:
    """A list of strings. Absent or null reads as empty."""
    value = raw.get(key)
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise _malformed(key, "a list of strings")
    return tuple(value)


def _opt_texts(raw: _Json, key: str) -> tuple[str, ...] | None:
    """A list of strings where absence carries meaning (the caller may not be shown the member at all)."""
    return None if raw.get(key) is None else _texts(raw, key)


def _table(raw: _Json, key: str) -> Mapping[str, Any]:
    """A JSON object, returned as received. Absent or null reads as empty."""
    value = raw.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise _malformed(key, "an object")
    return value


def _opt_table(raw: _Json, key: str) -> Mapping[str, Any] | None:
    return None if raw.get(key) is None else _table(raw, key)


def _part[V: View](view: type[V]) -> _Reader[V]:
    def read(raw: _Json, key: str) -> V:
        value = raw.get(key)
        if not isinstance(value, dict):
            raise _malformed(key, "an object")
        return view(value)

    return read


def _opt_part[V: View](view: type[V]) -> _Reader[V | None]:
    def read(raw: _Json, key: str) -> V | None:
        value = raw.get(key)
        if value is None:
            return None
        if not isinstance(value, dict):
            raise _malformed(key, "an object or null")
        return view(value)

    return read


def _parts[V: View](view: type[V]) -> _Reader[tuple[V, ...]]:
    def read(raw: _Json, key: str) -> tuple[V, ...]:
        value = raw.get(key)
        if value is None:
            return ()
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            raise _malformed(key, "a list of objects")
        return tuple(view(item) for item in value)

    return read


def _required[T](read: _Reader[T], expected: str) -> _Reader[T]:
    """A list or an object the API always sends: its absence is a malformed view, not an empty value."""

    def strict(raw: _Json, key: str) -> T:
        if raw.get(key) is None:
            raise _malformed(key, expected)
        return read(raw, key)

    return strict


class Member[T]:
    """One member of a view: read from ``raw`` each time, under the attribute's name unless ``key`` names another."""

    __slots__ = ("_key", "_read")

    def __init__(self, read: _Reader[T], *, key: str | None = None) -> None:
        self._read = read
        self._key = key

    def __set_name__(self, owner: type, name: str) -> None:
        if self._key is None:
            self._key = name

    @overload
    def __get__(self, view: None, owner: type) -> Self: ...
    @overload
    def __get__(self, view: View, owner: type) -> T: ...
    def __get__(self, view: View | None, owner: type) -> Self | T:
        if view is None:
            return self
        return self._read(view.raw, self._key or "")


class View:
    """Base of every view. ``raw`` is the JSON object exactly as the server sent it."""

    __slots__ = ("raw", "request_id")

    #: The members ``repr`` shows. Never one that can hold a secret or guest data.
    _shown: ClassVar[tuple[str, ...]] = ()

    def __init__(self, raw: dict[str, Any], *, request_id: str | None = None) -> None:
        self.raw = raw
        #: Identifier of the request whose answer carried this view. ``None`` for a part of another view.
        self.request_id = request_id

    def __repr__(self) -> str:
        shown = ", ".join(f"{key}={self.raw[key]!r}" for key in self._shown if self.raw.get(key) is not None)
        return f"{type(self).__name__}({shown})"

    def __eq__(self, other: object) -> bool:
        return type(other) is type(self) and isinstance(other, View) and other.raw == self.raw

    # A handle is a view that is updated in place, so views are not hashable.
    __hash__ = None  # type: ignore[assignment]


class Failure(View):
    """Why an operation, a sandbox or a snapshot failed, as the host reported it."""

    __slots__ = ()
    _shown = ("code", "retry")

    code = Member(_text)
    #: The host's own value, when ``code`` is ``UNRECOGNIZED``.
    code_raw = Member(_opt_text)
    retry = Member(_text)
    message = Member(_text)
    side_effect = Member(_opt_text)
    #: The host's own value, when ``side_effect`` is ``UNRECOGNIZED``.
    side_effect_raw = Member(_opt_text)


class Image(View):
    __slots__ = ()
    _shown = ("alias", "digest")

    alias = Member(_opt_text)
    digest = Member(_text)


class ResourcesView(View):
    """What a sandbox was given: vCPUs and MiB."""

    __slots__ = ()
    _shown = ("vcpus", "memory_mib", "disk_mib")

    vcpus = Member(_whole)
    memory_mib = Member(_whole)
    disk_mib = Member(_whole)


class PortRangeView(View):
    """One inclusive range of TCP ports. The API calls its ends ``from`` and ``to``."""

    __slots__ = ()
    _shown = ("from", "to")

    first = Member(_whole, key="from")
    last = Member(_whole, key="to")


class AllowEntryView(View):
    """One destination of an allowlist: an exact DNS name or an IPv4 network, and its ports."""

    __slots__ = ()
    _shown = ("name", "network")

    name = Member(_opt_text)
    network = Member(_opt_text)
    ports = Member(_required(_parts(PortRangeView), "a list of objects"))


class NetworkView(View):
    __slots__ = ()
    _shown = ("mode",)

    mode = Member(_text)
    mode_raw = Member(_opt_text)
    entries = Member(_parts(AllowEntryView))


class SnapshotRef(View):
    __slots__ = ()
    _shown = ("snapshot_id", "snapshot_generation")

    snapshot_id = Member(_identifier)
    snapshot_generation = Member(_whole)


class SandboxRef(View):
    __slots__ = ()
    _shown = ("sandbox_id", "generation")

    sandbox_id = Member(_identifier)
    generation = Member(_whole)


class SandboxView(View):
    """A sandbox, as one answer showed it."""

    __slots__ = ()
    _shown = ("sandbox_id", "name", "state", "generation")

    sandbox_id = Member(_identifier)
    project = Member(_text)
    #: An alias chosen by whoever created the sandbox. Treat it as text someone else wrote.
    name = Member(_opt_text)
    state = Member(_text)
    state_raw = Member(_opt_text)
    generation = Member(_whole)
    #: Opaque validator. Compare for equality only.
    revision = Member(_text)
    image = Member(_part(Image))
    resources = Member(_part(ResourcesView))
    network = Member(_part(NetworkView))
    expires_at = Member(_text)
    last_execution = Member(_opt_text)
    quarantined = Member(_opt_text)
    failure = Member(_opt_part(Failure))
    source_snapshot = Member(_opt_part(SnapshotRef))
    notes = Member(_texts)
    updated_at = Member(_text)


class OutputSummary(View):
    """How much one stream of an execution produced, and how much of it was stored."""

    __slots__ = ()
    _shown = ("stored_bytes", "produced_bytes", "completeness")

    stored_bytes = Member(_whole)
    produced_bytes = Member(_whole)
    completeness = Member(_text)
    completeness_raw = Member(_opt_text)


class Durations(View):
    __slots__ = ()
    _shown = ("guest_ms", "wall_ms")

    #: Reported by the guest.
    guest_ms = Member(_opt_whole)
    #: Observed by the host.
    wall_ms = Member(_opt_whole)


class ExecutionView(View):
    """One command run in one generation of one sandbox, as one answer showed it.

    ``provenance`` labels each field of the result ``HOST_OBSERVED`` or ``GUEST_REPORTED``. Whatever
    the guest reported (status, exit code, output) is data, not a statement by the platform.
    """

    __slots__ = ()
    _shown = ("execution_id", "state", "status", "exit_code")

    execution_id = Member(_identifier)
    operation_id = Member(_identifier)
    project = Member(_text)
    sandbox_id = Member(_opt_text)
    generation = Member(_opt_whole)
    #: State of the operation that runs the command.
    state = Member(_text)
    state_raw = Member(_opt_text)
    #: What the server says about ``state``. A client decides from ``state`` itself.
    terminal = Member(_flag)
    status = Member(_opt_text)
    status_raw = Member(_opt_text)
    exit_code = Member(_opt_whole)
    signal = Member(_opt_whole)
    durations = Member(_opt_part(Durations))
    stdout = Member(_opt_part(OutputSummary))
    stderr = Member(_opt_part(OutputSummary))
    host_backstop_fired = Member(_opt_flag)
    runtime_ended = Member(_opt_flag)
    evidence_status = Member(_opt_text)
    evidence_status_raw = Member(_opt_text)
    note = Member(_opt_text)
    provenance = Member(_table)


class OutputChunk(View):
    """A slice of one stream of an execution's stored output. The bytes are guest data."""

    __slots__ = ("_data",)
    _shown = ("execution_id", "stream", "offset", "next_offset", "eof")

    execution_id = Member(_identifier)
    stream = Member(_text)
    offset = Member(_whole)
    data_base64 = Member(_text)
    next_offset = Member(_whole)
    eof = Member(_flag)
    stored_bytes = Member(_whole)
    produced_bytes = Member(_whole)
    #: ``COMPLETE``, ``TRUNCATED`` or ``INCOMPLETE``: whether the stored stream is all the command wrote.
    completeness = Member(_text)
    completeness_raw = Member(_opt_text)
    provenance = Member(_opt_text)

    def __init__(self, raw: dict[str, Any], *, request_id: str | None = None) -> None:
        super().__init__(raw, request_id=request_id)
        self._data: bytes | None = None

    @property
    def data(self) -> bytes:
        """The bytes of the slice, decoded from ``data_base64``."""
        if self._data is None:
            try:
                self._data = base64.b64decode(self.data_base64, validate=True)
            except binascii.Error:
                raise _malformed("data_base64", "base64") from None
        return self._data


class SnapshotView(View):
    """A snapshot, as one answer showed it."""

    __slots__ = ()
    _shown = ("snapshot_id", "name", "state", "snapshot_generation")

    snapshot_id = Member(_identifier)
    snapshot_generation = Member(_whole)
    project = Member(_text)
    #: An alias chosen by whoever took the snapshot. Treat it as text someone else wrote.
    name = Member(_opt_text)
    state = Member(_text)
    state_raw = Member(_opt_text)
    revision = Member(_text)
    source_sandbox = Member(_opt_part(SandboxRef))
    size_bytes = Member(_whole)
    restore_count = Member(_whole)
    #: Why the snapshot cannot be restored on this host, if it cannot.
    incompatible = Member(_texts)
    failure = Member(_opt_part(Failure))
    created_at = Member(_text)


class Actor(View):
    """Who asked for an operation, as the host recorded it."""

    __slots__ = ()
    _shown = ("principal_id", "agent_label")

    principal_id = Member(_opt_text)
    #: The label of the agent credential that asked, when one did.
    agent_label = Member(_opt_text)


class OperationTarget(View):
    """Identifiers of what an operation acts on and of what it produced."""

    __slots__ = ()
    _shown = ("sandbox_id", "generation", "snapshot_id", "snapshot_generation", "execution_id")

    sandbox_id = Member(_opt_text)
    generation = Member(_opt_whole)
    snapshot_id = Member(_opt_text)
    snapshot_generation = Member(_opt_whole)
    execution_id = Member(_opt_text)


class OperationResult(View):
    """The resource an operation produced, as of the answer that carried it."""

    __slots__ = ()

    sandbox = Member(_opt_part(SandboxView))
    snapshot = Member(_opt_part(SnapshotView))
    execution = Member(_opt_part(ExecutionView))


class Operation(View):
    """One accepted mutation. Exactly one operation of the host stands behind it.

    ``state`` decides: ``SUCCEEDED``, ``FAILED``, ``CANCELLED`` and ``UNKNOWN`` are the states in which an
    operation has ended, and ``UNKNOWN`` is neither success nor failure. Any other state, including one
    this version has never seen, has not ended.
    """

    __slots__ = ()
    _shown = ("operation_id", "type", "state", "effect")

    operation_id = Member(_identifier)
    project = Member(_text)
    type = Member(_text)
    type_raw = Member(_opt_text)
    state = Member(_text)
    state_raw = Member(_opt_text)
    #: What the server says about ``state``. A client decides from ``state`` itself.
    terminal = Member(_flag)
    #: ``APPLIED``, ``NOT_APPLIED`` or ``MAY_BE_APPLIED``, once the operation has ended.
    effect = Member(_opt_text)
    effect_raw = Member(_opt_text)
    failure = Member(_opt_part(Failure))
    cleanup = Member(_opt_text)
    cleanup_raw = Member(_opt_text)
    cancelled_by = Member(_opt_text)
    cancelled_by_raw = Member(_opt_text)
    target = Member(_part(OperationTarget))
    #: Absent while the operation runs, when it produced nothing, and in a recorded view.
    result = Member(_opt_part(OperationResult))
    initiated_by = Member(_text)
    initiated_by_raw = Member(_opt_text)
    actor = Member(_opt_part(Actor))
    created_at = Member(_opt_text)
    updated_at = Member(_opt_text)
    #: True when the answer reports work that existed before the request that received it.
    replayed = Member(_flag_or_false)
    #: True when the host no longer holds the operation and this is the outcome the platform recorded.
    recorded = Member(_flag_or_false)
    idempotency_key_digest = Member(_opt_text)


class CredentialView(View):
    """The credential a request was made with. Never the credential itself."""

    __slots__ = ()
    _shown = ("credential_id", "kind", "agent_label")

    credential_id = Member(_identifier)
    kind = Member(_text)
    agent_label = Member(_opt_text)
    expires_at = Member(_text)


class WhoAmI(View):
    """The calling credential's principal, project and effective grants."""

    __slots__ = ()
    _shown = ("principal_id", "project_id")

    principal_id = Member(_identifier)
    project_id = Member(_identifier)
    credential = Member(_part(CredentialView))
    grants = Member(_required(_table, "an object"))
    policy_version = Member(_text)


class Ceilings(View):
    """The ceilings that apply to the caller's project."""

    __slots__ = ()
    _shown = ("vcpus", "memory_mib", "disk_mib")

    vcpus = Member(_whole)
    memory_mib = Member(_whole)
    disk_mib = Member(_whole)
    execution_timeout_seconds = Member(_whole)
    sandbox_lifetime_seconds = Member(_whole)
    allowlist_entries = Member(_whole)


class Info(View):
    """Platform info. Everything but ``api_versions`` and ``serving`` is shown to an authenticated caller only."""

    __slots__ = ()
    _shown = ("api_versions", "serving", "ready")

    api_versions = Member(_required(_texts, "a list of strings"))
    serving = Member(_flag)
    #: Whether the platform accepts work that creates something, now.
    ready = Member(_opt_flag)
    not_ready_reasons = Member(_opt_texts)
    platform_features = Member(_opt_texts)
    host_features = Member(_opt_texts)
    parameters = Member(_opt_table)
    ceilings = Member(_opt_part(Ceilings))


@dataclass(frozen=True, slots=True)
class ContainmentFailure:
    """One cancel that did not succeed while containing a revoked agent credential."""

    #: The execution that may still be running. ``None`` if the operation did not name it.
    execution_id: str | None
    #: The operation that started it.
    operation_id: str
    error: FabricError


class AgentCredential(View):
    """An agent credential. ``secret`` is present once, in the answer to minting, and never again.

    ``repr`` never shows the secret. ``raw`` holds it, because ``raw`` is the answer as received: do not
    log the ``raw`` of a credential that was just minted.
    """

    __slots__ = ("contained", "containment_errors")
    _shown = ("credential_id", "label", "status")

    credential_id = Member(_identifier)
    kind = Member(_text)
    label = Member(_opt_text)
    display_prefix = Member(_text)
    status = Member(_text)
    issued_at = Member(_text)
    expires_at = Member(_text)
    narrowing = Member(_opt_table)
    secret = Member(_opt_text)

    def __init__(self, raw: dict[str, Any], *, request_id: str | None = None) -> None:
        super().__init__(raw, request_id=request_id)
        #: After a revocation with ``contain=True``: the executions whose cancel succeeded.
        self.contained: tuple[str, ...] = ()
        #: After a revocation with ``contain=True``: the cancels that did not succeed.
        self.containment_errors: tuple[ContainmentFailure, ...] = ()
