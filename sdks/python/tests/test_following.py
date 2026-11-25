"""Following an operation to its end, and what each way of ending means.

The algorithm is fixed by the conformance suite, so that the requests of any client are determined:
after an answer in which the operation has not ended, wait ``Retry-After`` seconds if the answer carried
it, else the backoff (0.5 s, doubling, capped at 5 s); if that wait would reach the follow bound, report
the operation as still running; otherwise read the operation with ``wait`` equal to the smaller of 30
and the whole seconds left before the bound.
"""

from __future__ import annotations

from typing import Any

import pytest

from agentcompute import (
    AsyncFabric,
    Fabric,
    NotFoundError,
    OperationFailedError,
    OperationStillRunningError,
    OutcomeUnknownError,
    ServiceUnavailableError,
    UnexpectedResponseError,
)
from support import (
    EXE,
    OP,
    OP3,
    REQ,
    SBX,
    Exchange,
    Harness,
    Json,
    done,
    ex,
    execution,
    failure,
    operation,
    refusal,
    reply,
    sandbox,
)

_KEY = "key-0100"
_TARGET = {"sandbox_id": SBX, "generation": 2, "execution_id": EXE}


def _running(state: str = "IN_PROGRESS", **extra: Any) -> Json:
    return operation("execution.create", state, operation_id=OP3, target=_TARGET, **extra)


def _ended(state: str, **extra: Any) -> Json:
    return operation("execution.create", state, operation_id=OP3, target=_TARGET, **extra)


def _succeeded() -> Json:
    return done("execution.create", "execution", execution(), operation_id=OP3, target=_TARGET)


def _submit(response: Json) -> Exchange:
    return ex("POST", f"/sandboxes/{SBX}/executions", response, headers={"idempotency-key": _KEY})


def _poll(wait: int, response: Json) -> Exchange:
    return ex("GET", f"/operations/{OP3}", response, query={"wait": str(wait)}, absent_headers=["idempotency-key"])


def _accepted(retry_after: int | None = None, state: str = "ACCEPTED") -> Json:
    headers = {"location": f"/v1/projects/prj_0000000000000001/operations/{OP3}"}
    if retry_after is not None:
        headers["retry_after"] = str(retry_after)
    return reply(202, _running(state), **headers)


def _still(retry_after: int | None = None, state: str = "IN_PROGRESS") -> Json:
    return (
        reply(200, _running(state))
        if retry_after is None
        else reply(200, _running(state), retry_after=str(retry_after))
    )


def _exec(harness: Harness, fabric: Fabric | AsyncFabric, **options: Any) -> Any:
    handle = fabric.sandboxes.handle(SBX)
    return harness.run(handle.exec(["python", "-V"], generation=2, idempotency_key=_KEY, **options))


# ------------------------------------------------------------------------------------------ the cadence
def test_the_wait_between_reads_is_what_the_server_asks_for(harness: Harness) -> None:
    script = harness.script(
        _submit(_accepted(2)), _poll(30, _still(3)), _poll(30, _still(1)), _poll(30, reply(200, _succeeded()))
    )
    result = _exec(harness, harness.client(script))
    assert result.execution_id == EXE
    assert harness.clock.slept == [2.0, 3.0, 1.0]


def test_without_retry_after_the_backoff_starts_at_half_a_second_doubles_and_is_capped_at_five(
    harness: Harness,
) -> None:
    script = harness.script(_submit(_accepted()), *[_poll(30, _still())] * 6, _poll(30, reply(200, _succeeded())))
    _exec(harness, harness.client(script))
    assert harness.clock.slept == [0.5, 1.0, 2.0, 4.0, 5.0, 5.0, 5.0]


def test_the_backoff_only_advances_when_it_is_used(harness: Harness) -> None:
    script = harness.script(
        _submit(_accepted()),  # backoff: 0.5
        _poll(30, _still(7)),  # the server's advice
        _poll(30, _still()),  # backoff: 1
        _poll(30, _still(2)),
        _poll(30, _still()),  # backoff: 2
        _poll(30, reply(200, _succeeded())),
    )
    _exec(harness, harness.client(script))
    assert harness.clock.slept == [0.5, 7.0, 1.0, 2.0, 2.0]


def test_the_read_waits_for_the_smaller_of_thirty_and_the_whole_seconds_left(harness: Harness) -> None:
    script = harness.script(
        _submit(_accepted(1)),  # 1 s waited, 39.5 s left
        _poll(30, _still(20)),  # 21 s waited, 19.5 s left
        _poll(19, _still(10)),  # 31 s waited, 9.5 s left
        _poll(9, _still(9)),  # 40 s waited, 0.5 s left: no whole second
        _poll(0, _still(1)),  # one more second would pass the bound
    )
    with pytest.raises(OperationStillRunningError):
        _exec(harness, harness.client(script), follow_max=40.5)
    assert harness.clock.slept == [1.0, 20.0, 10.0, 9.0]


def test_a_wait_that_would_reach_the_bound_is_not_started(harness: Harness) -> None:
    script = harness.script(_submit(_accepted(5)))
    with pytest.raises(OperationStillRunningError):
        _exec(harness, harness.client(script), follow_max=5)
    assert harness.clock.slept == []


# ------------------------------------------------------------------------------------- at the follow bound
def test_at_the_bound_the_error_carries_the_operation_its_identifier_and_the_key(harness: Harness) -> None:
    script = harness.script(_submit(_accepted(1)), _poll(2, _still(1)), _poll(1, _still(1, "RECOVERING")))
    with pytest.raises(OperationStillRunningError) as raised:
        _exec(harness, harness.client(script), follow_max=3)
    error = raised.value
    assert error.operation_id == OP3
    assert error.operation.state == "RECOVERING"
    assert error.operation.target.execution_id == EXE
    assert error.idempotency_key == _KEY
    assert error.request_id == REQ
    assert error.code is None
    assert "Nothing was cancelled" in str(error)
    assert f"idempotency key {_KEY}" in str(error)
    # Nothing was sent after the last read: giving up cancels nothing.
    assert [seen.method for seen in script.seen] == ["POST", "GET", "GET"]


def test_a_bound_of_zero_submits_and_does_not_wait(harness: Harness) -> None:
    script = harness.script(_submit(_accepted(1)))
    with pytest.raises(OperationStillRunningError) as raised:
        _exec(harness, harness.client(script), follow_max=0)
    assert raised.value.idempotency_key == _KEY
    assert harness.clock.slept == []


@pytest.mark.parametrize(("bound", "said"), [(0, "0"), (0.9, "0"), (1, "1"), (5.9, "5"), (29.99, "29")])
def test_a_bound_shorter_than_the_servers_own_wait_is_said_to_the_server(
    harness: Harness, bound: float, said: str
) -> None:
    """A mutation that names no wait is held for 30 seconds. A shorter bound would be spent on the first answer."""
    submit = ex(
        "POST", f"/sandboxes/{SBX}/executions", _accepted(60), headers={"idempotency-key": _KEY}, query={"wait": said}
    )
    with pytest.raises(OperationStillRunningError):
        _exec(harness, harness.client(harness.script(submit)), follow_max=bound)
    assert harness.clock.slept == []


@pytest.mark.parametrize("bound", [30, 30.5, 1800, None])
def test_a_bound_of_the_servers_wait_or_more_leaves_the_wait_to_the_server(
    harness: Harness, bound: float | None
) -> None:
    submit = ex(
        "POST",
        f"/sandboxes/{SBX}/executions",
        reply(200, _succeeded()),
        headers={"idempotency-key": _KEY},
        absent_query=["wait"],
    )
    options = {} if bound is None else {"follow_max": bound}
    assert _exec(harness, harness.client(harness.script(submit)), **options).exit_code == 0


def test_the_wait_said_to_the_server_is_the_same_on_every_attempt(harness: Harness) -> None:
    """A retry is the same request: the same key, the same body and the same query."""
    request = {"headers": {"idempotency-key": _KEY}, "query": {"wait": "3"}}
    lost = ex("POST", f"/sandboxes/{SBX}/executions", {"fault": "connection_reset"}, **request)
    again = ex("POST", f"/sandboxes/{SBX}/executions", reply(200, _succeeded()), **request)
    assert _exec(harness, harness.client(harness.script(lost, again)), follow_max=3).exit_code == 0


def test_a_bound_of_zero_still_returns_what_ended_inside_the_request(harness: Harness) -> None:
    script = harness.script(_submit(reply(200, _succeeded())))
    assert _exec(harness, harness.client(script), follow_max=0).exit_code == 0


def test_the_bound_of_a_call_replaces_the_bound_of_the_client(harness: Harness) -> None:
    script = harness.script(_submit(_accepted(1)), _poll(8, _still(60)))
    with pytest.raises(OperationStillRunningError):
        _exec(harness, harness.client(script, follow_max=3), follow_max=9)


def test_the_default_bound_is_thirty_minutes(harness: Harness) -> None:
    script = harness.script(_submit(_accepted(900)), _poll(30, _still(899)), _poll(1, _still(1)))
    with pytest.raises(OperationStillRunningError):
        _exec(harness, harness.client(script))
    assert harness.clock.waited == 1799.0


# --------------------------------------------------------------------- states this version has never seen
@pytest.mark.parametrize("state", ["AWAITING_PLACEMENT", "UNRECOGNIZED", "Succeeded", "succeeded", "DONE", ""])
def test_a_state_never_seen_is_neither_terminal_nor_success(harness: Harness, state: str) -> None:
    script = harness.script(_submit(_accepted(1, state)), _poll(2, _still(1, state)), _poll(1, _still(1, state)))
    with pytest.raises(OperationStillRunningError) as raised:
        _exec(harness, harness.client(script), follow_max=3)
    assert raised.value.operation.state == state


def test_a_state_never_seen_is_followed_even_if_the_answer_calls_it_terminal(harness: Harness) -> None:
    claimed = _running("ARCHIVED", terminal=True, result={"execution": execution()})
    script = harness.script(
        _submit(reply(200, claimed, retry_after="1")),
        _poll(30, reply(200, _succeeded())),
    )
    assert _exec(harness, harness.client(script)).execution_id == EXE


def test_a_known_final_state_has_ended_whatever_the_terminal_member_says(harness: Harness) -> None:
    ended = _succeeded()
    ended["terminal"] = False
    script = harness.script(_submit(reply(200, ended)))
    assert _exec(harness, harness.client(script)).execution_id == EXE


# ------------------------------------------------------------------------------------------- the outcomes
@pytest.mark.parametrize(
    ("state", "effect", "expected"),
    [
        ("FAILED", "NOT_APPLIED", OperationFailedError),
        ("CANCELLED", "NOT_APPLIED", OperationFailedError),
        ("FAILED", "MAY_BE_APPLIED", OutcomeUnknownError),
        ("CANCELLED", "MAY_BE_APPLIED", OutcomeUnknownError),
        ("FAILED", "APPLIED", OutcomeUnknownError),
        ("FAILED", "UNRECOGNIZED", OutcomeUnknownError),
        ("FAILED", "SOMETHING_NEW", OutcomeUnknownError),
        ("FAILED", None, OutcomeUnknownError),
        ("CANCELLED", None, OutcomeUnknownError),
        ("UNKNOWN", "MAY_BE_APPLIED", OutcomeUnknownError),
        ("UNKNOWN", "NOT_APPLIED", OutcomeUnknownError),  # UNKNOWN is never a clean failure
        ("UNKNOWN", None, OutcomeUnknownError),
    ],
)
def test_an_operation_that_ended_without_success_is_a_failure_only_if_nothing_was_applied(
    harness: Harness, state: str, effect: str | None, expected: type[Exception]
) -> None:
    ended = _ended(state, effect=effect, failure=failure("DEPENDENCY_UNAVAILABLE", retry="SAME_REQUEST_LATER"))
    script = harness.script(_submit(reply(200, ended)))
    with pytest.raises((OperationFailedError, OutcomeUnknownError)) as raised:
        _exec(harness, harness.client(script))
    error = raised.value
    assert type(error) is expected
    assert error.code == "DEPENDENCY_UNAVAILABLE"
    assert error.operation.state == state
    assert error.operation_id == OP3
    assert error.idempotency_key == _KEY
    assert error.request_id == REQ
    # An operation that ended is never repeated, with this key or with another.
    assert len(script.seen) == 1


def test_an_operation_that_failed_without_saying_why_has_no_code(harness: Harness) -> None:
    script = harness.script(_submit(reply(200, _ended("FAILED", effect="NOT_APPLIED"))))
    with pytest.raises(OperationFailedError) as raised:
        _exec(harness, harness.client(script))
    assert raised.value.code is None


def test_unknown_is_reported_as_unknown_even_when_it_carries_a_result(harness: Harness) -> None:
    ended = _ended("UNKNOWN", effect="MAY_BE_APPLIED", result={"execution": execution("UNKNOWN", state="UNKNOWN")})
    script = harness.script(_submit(_accepted(1)), _poll(30, reply(200, ended)))
    with pytest.raises(OutcomeUnknownError, match="Inspect the target") as raised:
        _exec(harness, harness.client(script))
    result = raised.value.operation.result
    assert result is not None
    assert result.execution is not None
    assert result.execution.status == "UNKNOWN"


def test_a_command_that_exits_with_a_status_other_than_zero_is_a_result(harness: Harness) -> None:
    ran = done("execution.create", "execution", execution("EXITED", exit_code=3), operation_id=OP3)
    script = harness.script(_submit(reply(200, ran)))
    result = _exec(harness, harness.client(script))
    assert (result.status, result.exit_code) == ("EXITED", 3)
    assert result.operation.state == "SUCCEEDED"


# ------------------------------------------------------------------------------------ reads while following
def test_a_read_of_the_operation_is_retried_like_any_read(harness: Harness) -> None:
    script = harness.script(
        _submit(_accepted(1)),
        _poll(30, refusal("UPSTREAM_UNAVAILABLE", retry_after=1)),
        _poll(30, {"fault": "connection_reset"}),
        _poll(30, reply(200, _succeeded())),
    )
    assert _exec(harness, harness.client(script)).execution_id == EXE


def test_a_read_of_the_operation_that_is_refused_ends_the_following_with_that_refusal(harness: Harness) -> None:
    script = harness.script(_submit(_accepted(1)), _poll(30, refusal("NOT_FOUND")))
    with pytest.raises(NotFoundError):
        _exec(harness, harness.client(script))
    assert [seen.method for seen in script.seen] == ["POST", "GET"]


def test_a_read_of_the_operation_that_stays_unavailable_surfaces_and_cancels_nothing(harness: Harness) -> None:
    script = harness.script(_submit(_accepted(1)), *[_poll(30, refusal("UPSTREAM_UNAVAILABLE", retry_after=1))] * 3)
    with pytest.raises(ServiceUnavailableError):
        _exec(harness, harness.client(script))
    assert [seen.method for seen in script.seen] == ["POST", "GET", "GET", "GET"]


def test_a_recorded_outcome_carries_no_result_and_the_client_does_not_make_one_up(harness: Harness) -> None:
    """The operation succeeded and its view is gone: the caller is told where the record is, and nothing is read."""
    recorded = _ended("SUCCEEDED", effect="APPLIED", recorded=True, replayed=True)
    script = harness.script(_submit(reply(200, recorded)))
    with pytest.raises(UnexpectedResponseError, match="carries no execution: the platform shows a recorded outcome"):
        _exec(harness, harness.client(script))
    assert len(script.seen) == 1


def test_a_succeeded_operation_without_a_result_names_itself_and_the_request(harness: Harness) -> None:
    script = harness.script(_submit(reply(200, _ended("SUCCEEDED", effect="APPLIED"))))
    with pytest.raises(UnexpectedResponseError) as raised:
        _exec(harness, harness.client(script))
    assert OP3 in str(raised.value)
    assert "recorded" not in str(raised.value)
    assert raised.value.request_id == REQ


def test_the_follow_bound_counts_from_the_answer_that_showed_the_operation(harness: Harness) -> None:
    """The bound is on the following. Time spent getting the first request answered is not following."""
    harness.jitter = 0.0
    script = harness.script(
        _submit(refusal("RATE_LIMITED", retry_after=8)),
        _submit(refusal("UPSTREAM_UNAVAILABLE", retry_after=8)),
        _submit(_accepted(1)),
        _poll(2, _still(1)),
        _poll(1, _still(1)),
    )
    with pytest.raises(OperationStillRunningError):
        _exec(harness, harness.client(script), follow_max=3)
    assert harness.clock.slept == [8.0, 8.0, 1.0, 1.0]


# ------------------------------------------------------------------------------------------ operations.wait
def test_waiting_for_an_operation_reads_it_at_once_and_follows_it(harness: Harness) -> None:
    script = harness.script(
        ex(
            "GET",
            f"/operations/{OP}",
            reply(200, operation("sandbox.create", "IN_PROGRESS"), retry_after="2"),
            query={"wait": "30"},
        ),
        ex(
            "GET",
            f"/operations/{OP}",
            reply(200, done("sandbox.create", "sandbox", sandbox("READY"))),
            query={"wait": "30"},
        ),
    )
    ended = harness.run(harness.client(script).operations.wait(OP))
    assert ended.state == "SUCCEEDED"
    assert harness.clock.slept == [2.0]


@pytest.mark.parametrize(
    ("state", "effect"), [("FAILED", "NOT_APPLIED"), ("CANCELLED", "MAY_BE_APPLIED"), ("UNKNOWN", None)]
)
def test_waiting_for_an_operation_returns_it_however_it_ended(harness: Harness, state: str, effect: str | None) -> None:
    ended = operation("sandbox.start", state, effect=effect, failure=failure("TIMEOUT"))
    script = harness.script(ex("GET", f"/operations/{OP}", reply(200, ended), query={"wait": "30"}))
    result = harness.run(harness.client(script).operations.wait(OP))
    assert (result.state, result.effect) == (state, effect)
    assert result.failure is not None
    assert result.failure.code == "TIMEOUT"


def test_waiting_for_an_operation_stops_at_the_bound_with_no_key_to_name(harness: Harness) -> None:
    running = reply(200, operation("sandbox.create", "IN_PROGRESS"), retry_after="1")
    script = harness.script(
        ex("GET", f"/operations/{OP}", running, query={"wait": "2"}),
        ex("GET", f"/operations/{OP}", running, query={"wait": "1"}),
    )
    with pytest.raises(OperationStillRunningError) as raised:
        harness.run(harness.client(script).operations.wait(OP, follow_max=2))
    assert raised.value.operation_id == OP
    assert raised.value.idempotency_key is None
