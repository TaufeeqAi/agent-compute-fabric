"""What every handle is made of, and the flows more than one kind of handle needs.

A handle is a view plus the means to act on what it shows. It is built from a :class:`Seed`: the JSON of
the view as received, the identifier of the request that carried it, and the operation that produced
it, when one did.

The reads of single records live here, and not with the handles they belong to, because one kind of
handle hands out another: a sandbox takes a snapshot and runs an execution, and a revocation cancels
executions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final, Literal

from agentcompute._transport import Answer, Engine, Flow, Request, segment
from agentcompute._units import whole
from agentcompute.errors import KIND_REFUSED, RETRY_NEVER, NotFoundError, UnexpectedResponseError
from agentcompute.types import Operation

__all__ = [
    "CURRENT",
    "Generation",
    "Seed",
    "cancel_execution",
    "expected_generation",
    "find_snapshot",
    "produced",
    "read_execution",
    "read_sandbox",
    "received",
    "target_identifier",
]

#: A generation the caller states: a number, or the explicit word for "whatever is current".
type Generation = int | Literal["current"]

CURRENT: Final = "current"


@dataclass(frozen=True, slots=True)
class Seed:
    """One view as the server sent it, and where it came from."""

    raw: dict[str, Any]
    request_id: str | None
    #: The operation whose answer carried the view. ``None`` when the view was read.
    operation: Operation | None = None


def received(answer: Answer) -> Seed:
    """The view a read answered with."""
    return Seed(answer.body, answer.request_id)


# ------------------------------------------------------------------------------------------ single records
def read_sandbox(engine: Engine, sandbox: str) -> Flow[Seed]:
    """Read one sandbox. A read accepts an identifier or a name; the answer says which sandbox it is."""
    path = (yield from engine.project_path()) + "/sandboxes/" + segment(sandbox)
    return received((yield from engine.perform(Request("GET", path))))


def read_execution(engine: Engine, execution_id: str) -> Flow[Seed]:
    """Read one execution by its identifier."""
    path = (yield from engine.project_path()) + "/executions/" + segment(execution_id)
    return received((yield from engine.perform(Request("GET", path))))


def find_snapshot(engine: Engine, wanted: str) -> Flow[Seed]:
    """Find one snapshot by its identifier or its name.

    The API has no route for one snapshot, so the snapshot is found in the listing. An identifier wins
    over a name, in case someone named a snapshot like the identifier of another.
    """
    named: Seed | None = None
    for raw, request_id in (yield from engine.collect("/snapshots")):
        if raw.get("snapshot_id") == wanted:
            return Seed(raw, request_id)
        if named is None and raw.get("name") == wanted:
            named = Seed(raw, request_id)
    if named is None:
        raise NotFoundError(
            f"the project lists no snapshot with the identifier or the name {wanted!r}",
            code="NOT_FOUND",
            kind=KIND_REFUSED,
            retry=RETRY_NEVER,
        )
    return named


def cancel_execution(engine: Engine, execution_id: str, *, key: str, within: float) -> Flow[Operation]:
    """Cancel one execution and return the operation that did it, once it has succeeded."""
    path = (yield from engine.project_path()) + "/executions/" + segment(execution_id) + "/cancel"
    operation = yield from engine.operate(Request("POST", path, key=key), within=within)
    engine.settle(operation, key=key)
    return operation


# ------------------------------------------------------------------------------------- results of operations
def target_identifier(operation: Operation, member: str) -> str:
    """The identifier of what an operation acted on or produced, from its ``target``."""
    target = operation.raw.get("target")
    value = target.get(member) if isinstance(target, dict) else None
    if not isinstance(value, str) or not value:
        raise UnexpectedResponseError(
            f"operation {operation.operation_id} names no {member} in its target",
            request_id=operation.request_id,
        )
    return value


def produced(engine: Engine, operation: Operation, member: str) -> Seed:
    """The resource a succeeded operation carries in ``result``.

    An answer carries none when the platform shows an outcome it recorded for an operation the host no
    longer holds. The operation succeeded all the same; what is missing is the view, and this client
    does not make one up or go and read one on its own: it says where the record is to be found.
    """
    result = operation.raw.get("result")
    view = result.get(member) if isinstance(result, dict) else None
    if isinstance(view, dict):
        return Seed(view, operation.request_id, operation)
    recorded = (
        ": the platform shows a recorded outcome, because the host no longer holds the operation"
        if operation.recorded
        else ""
    )
    raise UnexpectedResponseError(
        engine.redact(
            f"operation {operation.operation_id} ({operation.type}) succeeded, and its answer carries no "
            f"{member}{recorded}. Read the {member} by its identifier, which the operation names in its target"
        ),
        request_id=operation.request_id,
    )


# ------------------------------------------------------------------------------------------- generations
def expected_generation(stated: Generation | None, observed: object) -> int | str:
    """The ``expected_generation`` of a mutation.

    A handle states what it saw: unless the caller says otherwise, that is the generation of the view
    the handle holds, so that a sandbox that was restored in the meantime refuses the request instead of
    running it against a state the caller never looked at. ``"current"`` is sent only when the caller
    passes that word, which is an explicit choice to act on whatever is there.
    """
    if stated is None:
        seen = whole(observed)
        if seen is None:
            raise ValueError(
                "this handle has not seen a generation of the sandbox: call refresh() first, "
                'or pass generation= (a number, or "current" to act on whatever is current)'
            )
        return seen
    if stated == CURRENT:
        return CURRENT
    number = whole(stated)
    if number is None or number < 1:
        raise ValueError(f'generation must be a positive integer or "current", not {stated!r}')
    return number
