"""``sandboxes.create()``: create, then start, and what happens to the sandbox when the start fails.

The platform creates and starts in two operations, so this client drives both, under the caller's key
and that key with the suffix ``:start``. The sequence has one more step, a destroy under ``:destroy``,
taken only when the start was refused or ended without success and the caller did not ask to keep the
sandbox. Nothing is destroyed when the start's outcome is merely not established.
"""

from __future__ import annotations

from typing import Any

import pytest

from agentcompute import (
    AsyncFabric,
    Fabric,
    OperationError,
    OperationFailedError,
    OperationStillRunningError,
    OutcomeLostError,
    OutcomeUnknownError,
    OutcomeUnresolvedError,
    PermissionDeniedError,
    RateLimitError,
    SandboxStartError,
    StateConflictError,
)
from support import (
    OP,
    OP2,
    OP3,
    SBX,
    Exchange,
    Harness,
    Json,
    done,
    ex,
    failure,
    fault,
    operation,
    refusal,
    reply,
    sandbox,
)

_KEY = "key-0002"
_BODY = {"image": "python", "resources": {"vcpus": 1, "memory_mib": 512, "disk_mib": 1024}}


def _create_exchange(response: Json | None = None) -> Exchange:
    answer = response or reply(200, done("sandbox.create", "sandbox", sandbox("READY", generation=3)))
    return ex("POST", "/sandboxes", answer, json=_BODY, headers={"idempotency-key": _KEY})


def _start_exchange(response: Json) -> Exchange:
    return ex(
        "POST",
        f"/sandboxes/{SBX}/start",
        response,
        json={"expected_generation": 3},
        headers={"idempotency-key": f"{_KEY}:start"},
    )


def _destroy_exchange(response: Json) -> Exchange:
    return ex(
        "DELETE",
        f"/sandboxes/{SBX}",
        response,
        query={"expected_generation": "3"},
        headers={"idempotency-key": f"{_KEY}:destroy"},
        json=None,
    )


def _started() -> Json:
    return reply(200, done("sandbox.start", "sandbox", sandbox("RUNNING", generation=3), operation_id=OP2))


def _destroyed() -> Json:
    return reply(200, done("sandbox.destroy", "sandbox", sandbox("DESTROYED", generation=3), operation_id=OP3))


def _start_failed(state: str = "FAILED", effect: str | None = "NOT_APPLIED") -> Json:
    ended = operation("sandbox.start", state, operation_id=OP2, effect=effect, failure=failure("RESOURCE_EXHAUSTED"))
    return reply(200, ended)


def _create(harness: Harness, fabric: Fabric | AsyncFabric, **options: Any) -> Any:
    options.setdefault("idempotency_key", _KEY)
    return harness.run(fabric.sandboxes.create("python", cpu=1, memory=512, disk=1024, **options))


# ---------------------------------------------------------------------------------------- the two operations
def test_create_issues_create_then_start_and_returns_the_started_sandbox(harness: Harness) -> None:
    script = harness.script(_create_exchange(), _start_exchange(_started()))
    created = _create(harness, harness.client(script))
    assert created.state == "RUNNING"
    assert created.generation == 3
    assert created.operation.type == "sandbox.start"
    assert [seen.key for seen in script.seen] == [_KEY, f"{_KEY}:start"]


def test_the_start_states_the_generation_of_the_created_sandbox_not_current(harness: Harness) -> None:
    script = harness.script(_create_exchange(), _start_exchange(_started()))
    _create(harness, harness.client(script))
    assert script.seen[1].json == {"expected_generation": 3}


def test_with_start_false_only_the_create_is_issued(harness: Harness) -> None:
    script = harness.script(_create_exchange())
    created = _create(harness, harness.client(script), start=False)
    assert created.state == "READY"
    assert created.operation.type == "sandbox.create"
    assert len(script.seen) == 1


def test_start_is_never_a_member_of_the_create_body(harness: Harness) -> None:
    script = harness.script(_create_exchange(), _start_exchange(_started()), _create_exchange())
    fabric = harness.client(script)
    _create(harness, fabric, start=True)
    _create(harness, fabric, start=False)
    assert script.seen[0].body == script.seen[2].body
    assert "start" not in script.seen[0].json


def test_both_operations_are_followed(harness: Harness) -> None:
    creating = reply(202, operation("sandbox.create", "ACCEPTED"), retry_after="1")
    starting = reply(202, operation("sandbox.start", "IN_PROGRESS", operation_id=OP2), retry_after="2")
    script = harness.script(
        _create_exchange(creating),
        ex("GET", f"/operations/{OP}", reply(200, done("sandbox.create", "sandbox", sandbox("READY", generation=3)))),
        _start_exchange(starting),
        ex("GET", f"/operations/{OP2}", _started()),
    )
    assert _create(harness, harness.client(script)).state == "RUNNING"
    assert harness.clock.slept == [1.0, 2.0]


def test_a_generated_key_is_shared_by_the_whole_sequence(harness: Harness) -> None:
    script = harness.script(
        ex("POST", "/sandboxes", reply(200, done("sandbox.create", "sandbox", sandbox("READY", generation=3)))),
        ex("POST", f"/sandboxes/{SBX}/start", _start_failed()),
        ex("DELETE", f"/sandboxes/{SBX}", _destroyed()),
    )
    with pytest.raises(SandboxStartError):
        _create(harness, harness.client(script), idempotency_key=None)
    key = script.seen[0].key
    assert key is not None
    assert len(key) == 36
    assert [seen.key for seen in script.seen] == [key, f"{key}:start", f"{key}:destroy"]


def test_the_longest_key_create_accepts_still_fits_its_derived_keys(harness: Harness) -> None:
    key = "k" * 247
    script = harness.script(
        ex("POST", "/sandboxes", reply(200, done("sandbox.create", "sandbox", sandbox("READY", generation=3)))),
        ex("POST", f"/sandboxes/{SBX}/start", _start_failed()),
        ex("DELETE", f"/sandboxes/{SBX}", _destroyed()),
    )
    with pytest.raises(SandboxStartError):
        _create(harness, harness.client(script), idempotency_key=key)
    assert [len(seen.key or "") for seen in script.seen] == [247, 253, 255]


# --------------------------------------------------------------------------------------- the create fails
@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        (refusal("PERMISSION_DENIED", reason="quota"), PermissionDeniedError),
        (
            reply(200, operation("sandbox.create", "FAILED", effect="NOT_APPLIED", failure=failure("TIMEOUT"))),
            OperationFailedError,
        ),
        (reply(200, operation("sandbox.create", "UNKNOWN", effect="MAY_BE_APPLIED")), OutcomeUnknownError),
        (refusal("OUTCOME_LOST", idempotency_key=_KEY), OutcomeLostError),
    ],
)
def test_if_the_create_fails_its_error_is_raised_and_nothing_else_is_sent(
    harness: Harness, answer: Json, expected: type[Exception]
) -> None:
    script = harness.script(_create_exchange(answer))
    with pytest.raises(expected) as raised:
        _create(harness, harness.client(script))
    assert not isinstance(raised.value, SandboxStartError)
    assert len(script.seen) == 1


def test_a_create_that_is_still_running_at_the_bound_is_not_started(harness: Harness) -> None:
    script = harness.script(_create_exchange(reply(202, operation("sandbox.create", "ACCEPTED"), retry_after="5")))
    with pytest.raises(OperationStillRunningError) as raised:
        _create(harness, harness.client(script), follow_max=3)
    assert raised.value.idempotency_key == _KEY
    assert len(script.seen) == 1


# ------------------------------------------------------------- the start fails: on_start_failure="destroy"
@pytest.mark.parametrize(
    ("start_answer", "error_type", "code"),
    [
        (_start_failed("FAILED", "NOT_APPLIED"), OperationFailedError, "RESOURCE_EXHAUSTED"),
        (_start_failed("CANCELLED", "NOT_APPLIED"), OperationFailedError, "RESOURCE_EXHAUSTED"),
        (_start_failed("FAILED", "MAY_BE_APPLIED"), OutcomeUnknownError, "RESOURCE_EXHAUSTED"),
        (_start_failed("UNKNOWN", "MAY_BE_APPLIED"), OutcomeUnknownError, "RESOURCE_EXHAUSTED"),
        (refusal("STATE_CONFLICT"), StateConflictError, "STATE_CONFLICT"),
        (refusal("PERMISSION_DENIED"), PermissionDeniedError, "PERMISSION_DENIED"),
        (refusal("RATE_LIMITED", retry_after=600), RateLimitError, "RATE_LIMITED"),
    ],
)
def test_by_default_a_failed_start_destroys_the_sandbox_and_the_error_names_both_outcomes(
    harness: Harness, start_answer: Json, error_type: type[Exception], code: str
) -> None:
    script = harness.script(_create_exchange(), _start_exchange(start_answer), _destroy_exchange(_destroyed()))
    with pytest.raises(SandboxStartError) as raised:
        _create(harness, harness.client(script))
    error = raised.value
    assert error.sandbox_id == SBX
    assert error.cleanup == "destroyed"
    assert error.destroy_error is None
    assert type(error.start_error) is error_type
    assert error.code == code
    assert error.__cause__ is error.start_error
    # An operation that ended carries the key it was asked under. A refusal left nothing to come back for.
    asked_under = f"{_KEY}:start" if isinstance(error.start_error, OperationError) else None
    assert error.start_error.idempotency_key == asked_under
    assert SBX in str(error)
    assert "It was destroyed" in str(error)
    # The destroy states the generation the client saw, under the third key of the sequence.
    assert script.seen[2].query == {"expected_generation": "3"}
    assert script.seen[2].key == f"{_KEY}:destroy"


def test_the_destroy_is_followed_to_its_end(harness: Harness) -> None:
    destroying = reply(202, operation("sandbox.destroy", "IN_PROGRESS", operation_id=OP3), retry_after="1")
    script = harness.script(
        _create_exchange(),
        _start_exchange(_start_failed()),
        _destroy_exchange(destroying),
        ex("GET", f"/operations/{OP3}", _destroyed()),
    )
    with pytest.raises(SandboxStartError) as raised:
        _create(harness, harness.client(script))
    assert raised.value.cleanup == "destroyed"


@pytest.mark.parametrize(
    ("destroy_answers", "destroy_error"),
    [
        ([refusal("REVISION_CONFLICT")], "RevisionConflictError"),
        (
            [reply(200, operation("sandbox.destroy", "FAILED", operation_id=OP3, effect="NOT_APPLIED"))],
            "OperationFailedError",
        ),
        ([reply(200, operation("sandbox.destroy", "UNKNOWN", operation_id=OP3))], "OutcomeUnknownError"),
        ([fault(), fault(), fault()], "OutcomeUnresolvedError"),
        ([fault("connect_error")] * 3, "OutcomeUnresolvedError"),
        (
            [reply(202, operation("sandbox.destroy", "IN_PROGRESS", operation_id=OP3), retry_after="9999")],
            "OperationStillRunningError",
        ),
    ],
)
def test_if_the_destroy_fails_too_the_error_says_the_sandbox_may_still_exist(
    harness: Harness, destroy_answers: list[Json], destroy_error: str
) -> None:
    script = harness.script(
        _create_exchange(),
        _start_exchange(_start_failed()),
        *[_destroy_exchange(answer) for answer in destroy_answers],
    )
    with pytest.raises(SandboxStartError) as raised:
        _create(harness, harness.client(script))
    error = raised.value
    assert error.cleanup == "destroy_failed"
    assert type(error.destroy_error).__name__ == destroy_error
    assert type(error.start_error) is OperationFailedError
    assert error.code == "RESOURCE_EXHAUSTED"
    assert error.sandbox_id == SBX
    assert "it may exist" in str(error)
    assert {seen.key for seen in script.seen[2:]} == {f"{_KEY}:destroy"}


# ---------------------------------------------------------------- the start fails: on_start_failure="keep"
@pytest.mark.parametrize("start_answer", [_start_failed(), _start_failed("UNKNOWN", None), refusal("STATE_CONFLICT")])
def test_with_keep_a_failed_start_leaves_the_sandbox_and_the_error_names_it(
    harness: Harness, start_answer: Json
) -> None:
    script = harness.script(_create_exchange(), _start_exchange(start_answer))
    with pytest.raises(SandboxStartError) as raised:
        _create(harness, harness.client(script), on_start_failure="keep")
    error = raised.value
    assert error.cleanup == "kept"
    assert error.sandbox_id == SBX
    assert error.destroy_error is None
    assert error.code == error.start_error.code
    assert "It was kept" in str(error)
    assert [seen.method for seen in script.seen] == ["POST", "POST"]


# ---------------------------------------------------- the start's outcome is not established: no clean-up
@pytest.mark.parametrize("policy", ["destroy", "keep"])
@pytest.mark.parametrize(
    ("start_answers", "expected"),
    [
        ([fault(), fault(), fault()], OutcomeUnresolvedError),
        ([refusal("OUTCOME_UNRESOLVED", retry_after=1, idempotency_key=f"{_KEY}:start")] * 3, OutcomeUnresolvedError),
        ([refusal("OUTCOME_LOST", idempotency_key=f"{_KEY}:start")], OutcomeLostError),
        ([fault("connect_error")] * 3, OutcomeUnresolvedError),
        ([reply(502, content_type="text/html")] * 3, OutcomeUnresolvedError),
        (
            [reply(202, operation("sandbox.start", "IN_PROGRESS", operation_id=OP2), retry_after="9999")],
            OperationStillRunningError,
        ),
    ],
)
def test_a_start_that_was_neither_refused_nor_ended_destroys_nothing_and_can_be_resumed(
    harness: Harness, policy: str, start_answers: list[Json], expected: type[Exception]
) -> None:
    script = harness.script(_create_exchange(), *[_start_exchange(answer) for answer in start_answers])
    with pytest.raises(expected) as raised:
        _create(harness, harness.client(script), on_start_failure=policy)
    assert not isinstance(raised.value, SandboxStartError)
    assert all(seen.method == "POST" for seen in script.seen)
    note = " ".join(raised.value.__notes__)
    assert SBX in note
    assert f"idempotency_key='{_KEY}'" in note


def test_the_same_key_resumes_the_sequence_where_it_stopped(harness: Harness) -> None:
    """A second call with the same key and arguments replays the create and resolves the start."""
    replayed = done("sandbox.create", "sandbox", sandbox("READY", generation=3), replayed=True)
    script = harness.script(
        _create_exchange(),
        _start_exchange(fault()),
        _start_exchange(fault()),
        _start_exchange(fault()),
        _create_exchange(reply(200, replayed, idempotent_replayed="true")),
        _start_exchange(_started()),
    )
    fabric = harness.client(script)
    with pytest.raises(OutcomeUnresolvedError) as raised:
        _create(harness, fabric)
    assert raised.value.idempotency_key == f"{_KEY}:start"
    resumed = _create(harness, fabric)
    assert resumed.state == "RUNNING"
    assert script.seen[0].body == script.seen[4].body
    assert {seen.key for seen in script.seen} == {_KEY, f"{_KEY}:start"}
