"""The error hierarchy: what is a kind of what, what each error carries, and that errors survive a process boundary."""

from __future__ import annotations

import copy
import pickle
from typing import Any

import pytest

import agentcompute
from agentcompute import (
    APIConnectionError,
    APIError,
    APITimeoutError,
    ConfigurationError,
    ConflictError,
    FabricError,
    IncompatibleServerError,
    NameReboundError,
    Operation,
    OperationError,
    OperationFailedError,
    OperationStillRunningError,
    OutcomeUnknownError,
    PermissionDeniedError,
    RefusedError,
    SandboxStartError,
    UnexpectedResponseError,
    UnresolvedError,
)
from agentcompute.errors import error_class
from support import OP, REGISTRY_ROWS, REQ, SBX, Harness, ex, failure, operation, refusal, reply

#: The hierarchy, as the contract of the two SDKs draws it: each class and its direct parent.
_PARENTS: dict[str, str] = {
    "ConfigurationError": "FabricError",
    "IncompatibleServerError": "ConfigurationError",
    "APIConnectionError": "FabricError",
    "APITimeoutError": "APIConnectionError",
    "UnexpectedResponseError": "FabricError",
    "APIError": "FabricError",
    "RefusedError": "APIError",
    "InvalidRequestError": "RefusedError",
    "AuthenticationError": "RefusedError",
    "PermissionDeniedError": "RefusedError",
    "SafetyControlDeniedError": "RefusedError",
    "NotFoundError": "RefusedError",
    "RevisionConflictError": "RefusedError",
    "IdempotencyConflictError": "RefusedError",
    "RateLimitError": "RefusedError",
    "CapacityError": "RefusedError",
    "ServiceUnavailableError": "RefusedError",
    "UnsupportedFeatureError": "RefusedError",
    "CursorExpiredError": "RefusedError",
    "InternalError": "RefusedError",
    "ConflictError": "RefusedError",
    "StateConflictError": "ConflictError",
    "QuarantinedError": "ConflictError",
    "IntegrityFailureError": "ConflictError",
    "IncompatibleRuntimeError": "ConflictError",
    "UnresolvedError": "APIError",
    "RequestInProgressError": "UnresolvedError",
    "OutcomeUnresolvedError": "UnresolvedError",
    "OutcomeLostError": "UnresolvedError",
    "OperationError": "FabricError",
    "OperationFailedError": "OperationError",
    "OutcomeUnknownError": "OperationError",
    "OperationStillRunningError": "OperationError",
    "SandboxStartError": "FabricError",
    "NameReboundError": "FabricError",
}


def test_the_hierarchy_is_the_one_both_sdks_share() -> None:
    assert FabricError.__bases__ == (Exception,)
    for name, parent in _PARENTS.items():
        assert getattr(agentcompute, name).__bases__ == (getattr(agentcompute, parent),), name
    exported = {name for name in agentcompute.__all__ if name.endswith("Error")}
    assert exported == {"FabricError", *_PARENTS}
    assert set(agentcompute.errors.__all__) == exported


def test_an_outcome_that_is_not_established_is_never_a_kind_of_refusal() -> None:
    """A caller that catches refusals must never catch "we do not know" with them."""
    for unsettled in (UnresolvedError, OperationError, APIConnectionError, UnexpectedResponseError):
        assert not issubclass(unsettled, RefusedError)
        assert not issubclass(RefusedError, unsettled)
    assert not issubclass(OutcomeUnknownError, OperationFailedError)
    assert not issubclass(OperationFailedError, OutcomeUnknownError)
    assert not issubclass(OperationStillRunningError, OperationFailedError | OutcomeUnknownError)


@pytest.mark.parametrize("code", sorted(REGISTRY_ROWS))
def test_every_code_of_the_registry_has_its_exception(code: str) -> None:
    row = REGISTRY_ROWS[code]
    named = getattr(agentcompute, row["sdk_exception"])
    if not row["error_answer"]:
        # A class of the host that only ever ends an operation: never the code of an error answer.
        assert issubclass(named, OperationError)
        assert error_class(code, "REFUSED") is RefusedError
        return
    found = error_class(code, row["kind"])
    assert found is named
    assert issubclass(found, UnresolvedError if row["kind"] == "UNRESOLVED" else RefusedError)
    # A known code decides its class, whatever kind an answer claims for it.
    assert error_class(code, "SOMETHING_ELSE") is named


@pytest.mark.parametrize(
    ("kind", "expected"),
    [("REFUSED", RefusedError), ("UNRESOLVED", UnresolvedError), ("", RefusedError), ("refused", RefusedError)],
)
def test_an_unknown_code_is_classed_by_its_kind(kind: str, expected: type[APIError]) -> None:
    assert error_class("FUTURE_CODE", kind) is expected


def test_an_api_error_carries_what_the_problem_document_said(harness: Harness) -> None:
    answer = refusal("PERMISSION_DENIED", reason="quota", retry_after=4)
    script = harness.script(ex("GET", f"/sandboxes/{SBX}", answer))
    with pytest.raises(PermissionDeniedError) as raised:
        harness.run(harness.client(script).sandboxes.get(SBX))
    error = raised.value
    assert (error.status, error.code, error.kind, error.retry) == (403, "PERMISSION_DENIED", "REFUSED", "NEVER")
    assert (error.message, error.reason, error.retry_after) == ("Permission denied", "quota", 4.0)
    assert (error.request_id, error.idempotency_key) == (REQ, None)
    assert str(error) == f"PERMISSION_DENIED: Permission denied (request {REQ})"
    assert error.args == (str(error),)


def test_every_error_has_a_request_id_even_when_no_answer_carried_one() -> None:
    assert FabricError("x").request_id is None
    assert ConfigurationError("x").request_id is None
    assert APIConnectionError("x").request_id is None
    assert UnexpectedResponseError("x").request_id is None
    assert NameReboundError("x", name="web", sandbox_id="a", rebound_to="b").request_id is None
    assert IncompatibleServerError("x", status=404, request_id=REQ).request_id == REQ


def _samples() -> list[FabricError]:
    ended = Operation(
        operation("sandbox.start", "FAILED", effect="NOT_APPLIED", failure=failure("TIMEOUT")), request_id=REQ
    )
    refused = PermissionDeniedError(
        "no",
        code="PERMISSION_DENIED",
        kind="REFUSED",
        retry="NEVER",
        status=403,
        request_id=REQ,
        reason="quota",
        retry_after=2.0,
    )
    failed = OperationFailedError("it failed", operation=ended, idempotency_key="key-1:start")
    noted = APIConnectionError("unreachable")
    noted.add_note("try again later")
    return [
        ConfigurationError("no key"),
        IncompatibleServerError("not v1", status=404, request_id=REQ),
        noted,
        APITimeoutError("too slow"),
        UnexpectedResponseError("odd", status=502, request_id=REQ),
        refused,
        failed,
        OutcomeUnknownError("unknown", operation=ended, idempotency_key=None),
        OperationStillRunningError("running", operation=ended, idempotency_key="key-1"),
        SandboxStartError(
            "start failed", sandbox_id=SBX, start_error=failed, cleanup="destroy_failed", destroy_error=refused
        ),
        NameReboundError("rebound", name="web", sandbox_id=SBX, rebound_to="sbx-2"),
    ]


def _state(error: BaseException) -> dict[str, Any]:
    """What an error says about itself, with nested errors and views flattened to what they say."""
    state: dict[str, Any] = {"type": type(error).__name__, "text": str(error), "args": error.args}
    for name, value in vars(error).items():
        if isinstance(value, BaseException):
            state[name] = _state(value)
        elif isinstance(value, Operation):
            state[name] = value.raw
        else:
            state[name] = value
    return state


@pytest.mark.parametrize("error", _samples(), ids=lambda error: type(error).__name__)
def test_an_error_survives_being_sent_to_another_process(error: FabricError) -> None:
    """Pickling is how an exception crosses to a worker pool or a task queue."""
    for protocol in range(2, pickle.HIGHEST_PROTOCOL + 1):
        restored = pickle.loads(pickle.dumps(error, protocol))  # noqa: S301 - bytes this test has just made
        assert type(restored) is type(error)
        assert _state(restored) == _state(error)
    assert _state(copy.copy(error)) == _state(error)
    assert _state(copy.deepcopy(error)) == _state(error)


def test_an_operation_error_carries_the_operation_and_its_failure_code() -> None:
    ended = Operation(
        operation("sandbox.start", "FAILED", effect="NOT_APPLIED", failure=failure("TIMEOUT")), request_id=REQ
    )
    error = OperationFailedError("it failed", operation=ended, idempotency_key="key-1")
    assert error.operation is ended
    assert (error.operation_id, error.idempotency_key, error.code, error.request_id) == (OP, "key-1", "TIMEOUT", REQ)
    assert (
        OperationStillRunningError("r", operation=Operation(operation(state="ACCEPTED")), idempotency_key=None).code
        is None
    )


def test_a_start_error_takes_its_code_from_the_start_failure_whichever_kind_it_was() -> None:
    refused = agentcompute.StateConflictError("no", code="STATE_CONFLICT", kind="REFUSED", retry="AFTER_CHANGE")
    kept = SandboxStartError("x", sandbox_id=SBX, start_error=refused, cleanup="kept")
    assert (kept.code, kept.cleanup, kept.destroy_error, kept.sandbox_id) == ("STATE_CONFLICT", "kept", None, SBX)
    assert isinstance(kept.start_error, ConflictError)


def test_an_error_raised_by_a_call_can_be_pickled_too(harness: Harness) -> None:
    ended = operation("execution.create", "UNKNOWN", effect="MAY_BE_APPLIED", failure=failure("UNKNOWN_OUTCOME"))
    script = harness.script(ex("POST", f"/sandboxes/{SBX}/executions", reply(200, ended)))
    with pytest.raises(OutcomeUnknownError) as raised:
        harness.run(harness.client(script).sandboxes.handle(SBX).exec(["true"], generation=1, idempotency_key="k"))
    restored = pickle.loads(pickle.dumps(raised.value))  # noqa: S301 - bytes this test has just made
    assert isinstance(restored, OutcomeUnknownError)
    assert (restored.code, restored.idempotency_key, restored.operation.state) == ("UNKNOWN_OUTCOME", "k", "UNKNOWN")
    assert str(restored) == str(raised.value)
