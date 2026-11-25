"""The caller's half of host protocol ``acf.host/2``, as the host binding speaks it.

This module and its neighbours in :mod:`acf_api.core.host` are the only code in the platform that
knows the host's wire contract. Nothing above the binding imports a name of that contract; the pipeline
receives decoded answers and maps them through the mapping table.

The envelope admits no field the host does not define, so nothing is added to it: no trace context, no
credential of a caller. The platform's request id is sent as the host's ``request_id``, which the host
echoes into its own events; that is what joins the two traces.

One thing here is a rule and not an encoding: an envelope is never altered between two submissions of
it. The binding sends what it is given.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any, Final

PROTOCOL: Final = "acf.host/2"

# Read methods the binding may call. Operator methods and `host.metrics` are not among them.
READ_METHODS: Final = frozenset(
    {
        "sandbox.inspect",
        "sandbox.list",
        "snapshot.list",
        "operation.get",
        "operation.list",
        "run.inspect",
        "run.output",
        "host.info",
    }
)
MUTATING_METHODS: Final = frozenset(
    {
        "sandbox.create",
        "sandbox.start",
        "exec.run",
        "snapshot.create",
        "snapshot.restore",
        "sandbox.stop",
        "sandbox.destroy",
        "snapshot.delete",
        "operation.cancel",
    }
)
FORBIDDEN_METHODS: Final = frozenset({"profile.reload", "quarantine.release", "host.set_mode", "host.acknowledge"})

# Host failure classes the binding and the pipeline name directly.
NOT_FOUND: Final = "NOT_FOUND"
IDEMPOTENCY_CONFLICT: Final = "IDEMPOTENCY_CONFLICT"
EXPIRED_REQUEST: Final = "EXPIRED_REQUEST"
REVISION_CONFLICT: Final = "REVISION_CONFLICT"

TERMINAL_STATES: Final = frozenset({"SUCCEEDED", "FAILED", "CANCELLED", "UNKNOWN"})


class HostError(Exception):
    """Base class of failures of an exchange with the host."""


class Unreachable(HostError):
    """Nothing was written to the host: connecting, authenticating or building the request failed."""


class LostAnswer(HostError):
    """The request was written and no usable answer came back. The host may have acted."""


class HostIdentityError(Unreachable):
    """The endpoint is not the host this deployment is bound to. Nothing was sent to it."""


@dataclass(frozen=True, slots=True)
class AsOf:
    """The committed state an answer reflects: a store lineage and a commit sequence."""

    lineage: str
    sequence: int


@dataclass(frozen=True, slots=True)
class HostRequest:
    """One request envelope. Built once by the pipeline from the ledger entry and never changed."""

    method: str
    owner_scope: str
    params: dict[str, Any] | None = None
    operation_id: str | None = None
    issued_at: str | None = None
    on_behalf_of: str | None = None
    request_id: str | None = None
    wait_ms: int | None = None

    def encode(self) -> bytes:
        body: dict[str, Any] = {"protocol": PROTOCOL, "owner_scope": self.owner_scope, "method": self.method}
        if self.params is not None:
            body["params"] = self.params
        for name in ("operation_id", "issued_at", "on_behalf_of", "request_id", "wait_ms"):
            value = getattr(self, name)
            if value is not None:
                body[name] = value
        return json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True, slots=True)
class HostRefusal:
    """``REFUSED``: nothing was applied and nothing was recorded."""

    failure_class: str
    retry: str
    message: str
    as_of: AsOf | None


@dataclass(frozen=True, slots=True)
class HostOperation:
    """``OPERATION``: a durable operation record exists. ``view`` is the host's operation view, decoded."""

    view: dict[str, Any]
    as_of: AsOf | None

    @property
    def operation_id(self) -> str:
        return str(self.view.get("operation_id", ""))

    @property
    def state(self) -> str:
        return str(self.view.get("state", ""))

    @property
    def terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    @property
    def issued_at(self) -> str | None:
        value = self.view.get("issued_at")
        return value if isinstance(value, str) else None

    @property
    def peer_id(self) -> str | None:
        return _peer_id(self.view)


@dataclass(frozen=True, slots=True)
class HostResult:
    """``RESULT``: a read served from committed state."""

    type: str
    data: Any
    as_of: AsOf | None


HostAnswer = HostRefusal | HostOperation | HostResult


def _peer_id(view: object) -> str | None:
    tags = view.get("tags") if isinstance(view, dict) else None
    peer = tags.get("peer_id") if isinstance(tags, dict) else None
    return peer if isinstance(peer, str) else None


def peer_id_of(answer: HostAnswer) -> str | None:
    """The platform's own peer id as the host recorded it on a view, when the answer carries a tagged view."""
    if isinstance(answer, HostOperation):
        return answer.peer_id
    if isinstance(answer, HostResult):
        data = answer.data
        if isinstance(data, dict):
            direct = _peer_id(data)
            if direct is not None:
                return direct
            items = data.get("items")
            if isinstance(items, list) and items:
                return _peer_id(items[0])
    return None


#: Members of a request whose *names* the caller chose as well as their values: the environment mappings.
_CALLER_NAMED: Final = frozenset({"env", "secret_env"})
#: From this length on, a string the caller sent is looked for anywhere in a message, not only as a word.
_LONG_ENOUGH_TO_BE_A_SECRET: Final = 8


def said(params: object) -> Iterator[str]:
    """Every string of a request's parameters that the caller chose.

    That is each string value at any depth, and the names in the environment mappings. The other
    names are the host's own vocabulary and say nothing about the caller.
    """
    if isinstance(params, str):
        yield params
    elif isinstance(params, dict):
        for name, value in params.items():
            if name in _CALLER_NAMED and isinstance(value, dict):
                yield from (str(key) for key in value)
            yield from said(value)
    elif isinstance(params, list | tuple):
        for item in params:
            yield from said(item)


def repeats(message: str, strings: Iterable[str]) -> bool:
    """Whether a host message quotes something the caller sent.

    The host explains some refusals with the caller's own words: the image alias it does not permit,
    the environment variable that is not on its allowlist, the identifier it does not hold. An error
    answer of the platform never repeats request content, so such an explanation is not passed on.

    A long string counts wherever it appears. A short one counts only as a whole word, so that a
    one-letter argument does not make every sentence a quotation.
    """
    for text in strings:
        if not text:
            continue
        if len(text) >= _LONG_ENOUGH_TO_BE_A_SECRET:
            if text in message:
                return True
            continue
        start = message.find(text)
        while start >= 0:
            end = start + len(text)
            before = message[start - 1] if start > 0 else " "
            after = message[end] if end < len(message) else " "
            if not (before.isalnum() or before == "_") and not (after.isalnum() or after == "_"):
                return True
            start = message.find(text, start + 1)
    return False


def _as_of(body: dict[str, Any]) -> AsOf | None:
    raw = body.get("as_of")
    if isinstance(raw, dict) and isinstance(raw.get("lineage"), str) and isinstance(raw.get("sequence"), int):
        return AsOf(raw["lineage"], raw["sequence"])
    return None


def decode_answer(payload: bytes) -> HostAnswer:
    """Decode one response envelope. Raises ``ValueError`` when it is not one."""
    body = json.loads(payload)
    if not isinstance(body, dict):
        msg = "the response is not a JSON object"
        raise ValueError(msg)  # noqa: TRY004 - ``ValueError`` is what this function raises for every bad envelope
    protocol = body.get("protocol")
    if not isinstance(protocol, str) or protocol.split("/")[0] != PROTOCOL.split("/", maxsplit=1)[0]:
        msg = "the response names another protocol"
        raise ValueError(msg)
    answer = body.get("answer")
    as_of = _as_of(body)
    if answer == "REFUSED":
        refusal = body.get("refusal")
        if not isinstance(refusal, dict):
            msg = "a refusal without its body"
            raise ValueError(msg)
        return HostRefusal(
            str(refusal.get("class", "")), str(refusal.get("retry", "")), str(refusal.get("message", "")), as_of
        )
    if answer == "OPERATION":
        view = body.get("operation")
        if not isinstance(view, dict) or not isinstance(view.get("operation_id"), str):
            msg = "an operation answer without its view"
            raise ValueError(msg)
        return HostOperation(view, as_of)
    if answer == "RESULT":
        result = body.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("type"), str):
            msg = "a result answer without its body"
            raise ValueError(msg)
        return HostResult(result["type"], result.get("data"), as_of)
    msg = "the response carries an answer kind this version does not know"
    raise ValueError(msg)
