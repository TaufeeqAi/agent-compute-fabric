"""The caller's half of the operation protocol, against a scripted in-process transport.

What is under test is *what the client sends next* after each thing a host — or a broken
connection — can do, and what it reports at the end:

* one ``operation_id`` and one ``issued_at`` per intent, on every request about it;
* a lost response is resolved by the same id with ``retry: true``, never by a new id;
* a refused retry is not believed until ``operation.get`` has been asked;
* a non-terminal operation is followed with ``operation.get``;
* ``UNKNOWN`` is reported as unknown — not success, not failure.

Every request the client sends here is also validated against the published API description.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest

import factories as f
from acf_cli import requests as rq
from acf_cli.client import (
    MAX_SUBMISSIONS_NEVER_RECORDED,
    ClientConfig,
    HostClient,
    Outcome,
    answer_document,
    exit_code_for,
    parse_response,
    require_success,
)
from acf_cli.errors import (
    ExitCode,
    HostUnreachable,
    MutationInterrupted,
    NotFinished,
    OperationFailed,
    OutcomeUnknown,
    OutcomeUnresolved,
    ProtocolViolation,
    Refused,
    ResponseLost,
)
from acf_cli.responses import OperationView, SandboxBody
from acf_cli.wire import PROTOCOL, FailureClass, OperationState
from support import FakeClock, ScriptedConnection, accepted, answered, op, refused

Scripted = Callable[..., ScriptedConnection]
ClientFor = Callable[[ScriptedConnection], HostClient]

TARGET = rq.SandboxTarget(sandbox_id=f.SANDBOX_ID, expected_generation=1)
START = rq.sandbox_start(TARGET)
LOST = ResponseLost("the host closed the connection without answering")
DOWN = HostUnreachable("nothing is listening")
NOT_KNOWN = refused("NOT_FOUND", "operation is not known to this host; a retry is never treated as a new request")


def identities(connection: ScriptedConnection) -> set[tuple[str, str]]:
    """The ``(operation_id, issued_at)`` pairs of every operation-creating request that was sent."""
    return {(r["operation_id"], r["issued_at"]) for r in connection.requests if "operation_id" in r}


# ----------------------------------------------------------------------------- reads
def test_a_read_is_one_round_trip_without_operation_identity(scripted: Scripted, client_for: ClientFor) -> None:
    connection = scripted(answered("host_info", f.host_info()))
    answer = client_for(connection).read(rq.host_info())
    assert answer.result is not None
    (request,) = connection.requests
    assert request["method"] == "host.info"
    assert request["protocol"] == PROTOCOL
    assert request["owner_scope"] == "team-a", "the configured owner scope is on every request"
    assert not {"operation_id", "issued_at", "retry", "wait_ms", "authority"} & set(request)


def test_on_behalf_of_is_sent_when_configured(scripted: Scripted, clock: FakeClock) -> None:
    connection = scripted(answered("metrics", {}), op("SUCCEEDED", f.sandbox_body()))
    client = HostClient(
        ClientConfig(owner_scope="team-a", on_behalf_of="job:42"),
        connection=connection,
        sleep=clock.sleep,
        monotonic=clock.monotonic,
    )
    client.read(rq.host_metrics())
    client.submit(START)
    assert [r["on_behalf_of"] for r in connection.requests] == ["job:42", "job:42"]


def test_a_read_whose_answer_is_lost_is_asked_again_once(scripted: Scripted, client_for: ClientFor) -> None:
    connection = scripted(LOST, answered("metrics", {"counters": {}}))
    assert client_for(connection).read(rq.host_metrics()).result is not None
    assert connection.methods == ["host.metrics", "host.metrics"]
    first, second = connection.requests
    assert first["request_id"] != second["request_id"]


def test_a_read_that_is_lost_twice_is_a_transport_failure(scripted: Scripted, client_for: ClientFor) -> None:
    connection = scripted(LOST, LOST)
    with pytest.raises(ResponseLost) as caught:
        client_for(connection).read(rq.host_metrics())
    assert caught.value.exit_code is ExitCode.TRANSPORT


def test_an_unreachable_host_fails_a_read_at_once(scripted: Scripted, client_for: ClientFor) -> None:
    connection = scripted(DOWN)
    with pytest.raises(HostUnreachable):
        client_for(connection).read(rq.host_info())
    assert len(connection.requests) == 1


def test_a_refused_read_is_returned_by_read_and_raised_by_result(scripted: Scripted, client_for: ClientFor) -> None:
    connection = scripted(refused("NOT_FOUND", "no such sandbox"), refused("NOT_FOUND", "no such sandbox"))
    client = client_for(connection)
    answer = client.read(rq.sandbox_inspect("ghost"))
    assert answer.refusal is not None
    assert answer.refusal.failure_class is FailureClass.NOT_FOUND
    with pytest.raises(Refused) as caught:
        client.result(rq.sandbox_inspect("ghost"))
    assert caught.value.exit_code is ExitCode.REFUSED
    assert "NOT_FOUND: no such sandbox" in caught.value.message
    assert caught.value.envelope.refusal is not None


def test_read_and_submit_refuse_the_wrong_kind_of_method(scripted: Scripted, client_for: ClientFor) -> None:
    client = client_for(scripted())
    with pytest.raises(ValueError, match="creates an operation"):
        client.read(START)
    with pytest.raises(ValueError, match="is a read"):
        client.submit(rq.host_info())


# ----------------------------------------------------------------------------- submit: answered at once
def test_a_terminal_answer_is_final_and_nothing_else_is_sent(scripted: Scripted, client_for: ClientFor) -> None:
    connection = scripted(op("SUCCEEDED", f.sandbox_body()))
    outcome = client_for(connection).submit(START)
    view = require_success(outcome)
    assert isinstance(view.result, SandboxBody)
    assert outcome.submissions == 1
    assert str(outcome.as_of) == f"{f.LINEAGE}:41"
    (request,) = connection.requests
    assert request["method"] == "sandbox.start"
    assert request["params"] == {"sandbox_id": f.SANDBOX_ID, "expected_generation": 1}
    assert request["operation_id"] == outcome.operation_id
    assert "retry" not in request, "a first submission does not claim to be a retry"
    assert "authority" not in request


def test_the_operation_id_is_generated_by_the_caller_and_announced_before_sending(
    scripted: Scripted, client_for: ClientFor
) -> None:
    seen: list[tuple[str, int]] = []
    connection = scripted(op("SUCCEEDED", f.sandbox_body()))
    outcome = client_for(connection).submit(
        START, on_operation=lambda op_id: seen.append((op_id, len(connection.requests)))
    )
    assert seen == [(outcome.operation_id, 0)], "known before the first byte is sent"
    assert outcome.operation_id.startswith("op-")


def test_an_explicit_operation_id_is_used_verbatim(scripted: Scripted, client_for: ClientFor) -> None:
    connection = scripted(op("SUCCEEDED", f.sandbox_body()))
    outcome = client_for(connection).submit(START, operation_id="deploy-2026-11-18-a")
    assert connection.requests[0]["operation_id"] == "deploy-2026-11-18-a" == outcome.operation_id


def test_issued_at_is_the_wall_clock_in_utc(scripted: Scripted, clock: FakeClock) -> None:
    connection = scripted(op("SUCCEEDED", f.sandbox_body()))
    client = HostClient(
        ClientConfig(),
        connection=connection,
        sleep=clock.sleep,
        monotonic=clock.monotonic,
        wall_clock=lambda: datetime(2026, 11, 18, 10, 0, 0, 250_000, tzinfo=UTC),
    )
    client.submit(START)
    assert connection.requests[0]["issued_at"] == "2026-11-18T10:00:00.250Z"


def test_a_refusal_is_final_nothing_was_applied_and_nothing_is_asked(scripted: Scripted, client_for: ClientFor) -> None:
    connection = scripted(refused("STATE_CONFLICT", "sandbox is busy with `exec.run`", "AFTER_CHANGE"))
    outcome = client_for(connection).submit(START)
    assert outcome.operation is None
    assert outcome.refusal is not None
    assert len(connection.requests) == 1
    with pytest.raises(Refused) as caught:
        require_success(outcome)
    assert caught.value.exit_code is ExitCode.REFUSED
    assert caught.value.operation_id == outcome.operation_id
    assert caught.value.envelope.refusal is not None
    assert caught.value.envelope.refusal.retry == "AFTER_CHANGE"


UNEXPLAINED = refused(
    "INTERNAL_ERROR", "the core did not answer; resolve the operation by its id", "AFTER_CHANGE", as_of=None
)


def test_a_refusal_the_host_cannot_explain_is_checked_against_the_record_and_the_operation_may_exist(
    scripted: Scripted, client_for: ClientFor
) -> None:
    """A host that does not know what went wrong may not know that it had accepted the request either."""
    connection = scripted(UNEXPLAINED, op("IN_PROGRESS"), op("SUCCEEDED", f.sandbox_body()))
    outcome = client_for(connection).submit(START)
    assert require_success(outcome).succeeded
    assert connection.methods == ["sandbox.start", "operation.get", "operation.get"]
    assert connection.requests[1]["params"] == {"operation_id": outcome.operation_id}


def test_a_refusal_the_host_cannot_explain_stands_once_the_host_confirms_it_holds_no_record(
    scripted: Scripted, client_for: ClientFor
) -> None:
    connection = scripted(UNEXPLAINED, refused("NOT_FOUND", "operation does not exist"))
    outcome = client_for(connection).submit(START)
    assert outcome.refusal is not None
    assert outcome.refusal.failure_class is FailureClass.INTERNAL_ERROR
    assert connection.methods == ["sandbox.start", "operation.get"]
    assert len(identities(connection)) == 1, "it is not submitted again"


@pytest.mark.parametrize("lookup", [DOWN, LOST, refused("AUTHENTICATION_FAILED", "no longer enrolled")])
def test_a_refusal_the_host_cannot_explain_and_cannot_be_asked_about_is_not_reported_as_nothing_applied(
    scripted: Scripted, client_for: ClientFor, lookup: Any
) -> None:
    connection = scripted(UNEXPLAINED, lookup, default=lookup)
    with pytest.raises(OutcomeUnresolved) as caught:
        client_for(connection).submit(START)
    assert caught.value.exit_code is ExitCode.UNRESOLVED
    assert "INTERNAL_ERROR" in caught.value.message
    assert caught.value.operation_id == connection.requests[0]["operation_id"]
    assert "may have been accepted" in (caught.value.hint or "")


def test_every_other_refusal_of_a_first_submission_is_believed_without_asking(
    scripted: Scripted, client_for: ClientFor
) -> None:
    for failure_class in (
        "INVALID_REQUEST",
        "SAFETY_CONTROL_DENIED",
        "NOT_FOUND",
        "RESOURCE_EXHAUSTED",
        "QUOTA_EXCEEDED",
    ):
        connection = scripted(refused(failure_class, "no"))
        outcome = client_for(connection).submit(START)
        assert outcome.refusal is not None
        assert connection.methods == ["sandbox.start"], failure_class


def test_the_wait_asked_of_the_host_and_the_time_the_client_listens(scripted: Scripted, client_for: ClientFor) -> None:
    connection = scripted(op("SUCCEEDED", f.sandbox_body()))
    client_for(connection).submit(START)
    assert connection.requests[0]["wait_ms"] == 20_000
    assert connection.read_timeouts == [30.0], "the wait that was asked for, plus a margin"


# ----------------------------------------------------------------------------- submit: following an operation
def test_a_non_terminal_answer_is_followed_with_operation_get_until_terminal(
    scripted: Scripted, client_for: ClientFor, clock: FakeClock
) -> None:
    connection = scripted(
        op("ACCEPTED", step=None),
        op("IN_PROGRESS"),
        op("RECOVERING"),
        op("SUCCEEDED", f.sandbox_body(), revision=20),
    )
    outcome = client_for(connection).submit(START)
    view = require_success(outcome)
    assert view.revision == 20
    assert connection.methods == ["sandbox.start", "operation.get", "operation.get", "operation.get"]
    polled = {r["params"]["operation_id"] for r in connection.requests[1:]}
    assert polled == {outcome.operation_id}, "the operation is observed by the id it was submitted under"
    assert clock.sleeps == [0.1, 0.2, 0.4], "polls are spaced out, starting short"
    assert outcome.submissions == 1, "observing is not submitting"


def test_polling_backs_off_to_a_ceiling(scripted: Scripted, client_for: ClientFor, clock: FakeClock) -> None:
    connection = scripted(op("IN_PROGRESS"), *[op("IN_PROGRESS")] * 7, op("SUCCEEDED", f.sandbox_body()))
    require_success(client_for(connection).submit(START))
    assert clock.sleeps == [0.1, 0.2, 0.4, 0.8, 1.6, 2.0, 2.0, 2.0]


def test_the_client_stops_following_at_its_timeout_and_reports_the_last_state(
    scripted: Scripted, client_for: ClientFor, clock: FakeClock
) -> None:
    connection = scripted(op("IN_PROGRESS"), default=op("IN_PROGRESS", step="launch"))
    outcome = client_for(connection).submit(START, timeout_s=5.0)
    assert outcome.operation is not None
    assert outcome.operation.state is OperationState.IN_PROGRESS
    assert sum(clock.sleeps) == pytest.approx(5.0), "it waited exactly as long as it was told to"
    with pytest.raises(NotFinished) as caught:
        require_success(outcome)
    assert caught.value.exit_code is ExitCode.UNRESOLVED
    assert f"acf-local operation get {outcome.operation_id} --wait" in (caught.value.hint or "")


def test_the_wait_asked_of_the_host_never_exceeds_the_time_the_caller_has(
    scripted: Scripted, client_for: ClientFor
) -> None:
    connection = scripted(op("SUCCEEDED", f.sandbox_body()))
    client_for(connection).submit(START, timeout_s=3.0)
    assert connection.requests[0]["wait_ms"] == 3_000
    assert connection.read_timeouts == [13.0]


def test_no_wait_asks_the_host_to_answer_at_once_and_does_not_follow(scripted: Scripted, client_for: ClientFor) -> None:
    connection = scripted(op("ACCEPTED", step=None))
    outcome = client_for(connection).submit(START, wait=False)
    assert connection.requests[0]["wait_ms"] == 0
    assert connection.methods == ["sandbox.start"], "no operation.get follows"
    assert outcome.operation is not None
    assert not outcome.operation.is_terminal
    assert exit_code_for(outcome.operation) is ExitCode.UNRESOLVED


def test_no_wait_still_reports_an_operation_that_ended_immediately(scripted: Scripted, client_for: ClientFor) -> None:
    connection = scripted(op("SUCCEEDED", f.sandbox_body()))
    assert require_success(client_for(connection).submit(START, wait=False)).succeeded


def test_the_host_being_away_while_following_is_ridden_out(
    scripted: Scripted, client_for: ClientFor, clock: FakeClock
) -> None:
    connection = scripted(op("IN_PROGRESS"), DOWN, LOST, DOWN, op("SUCCEEDED", f.sandbox_body()))
    outcome = client_for(connection).submit(START)
    assert require_success(outcome).succeeded
    assert connection.methods == ["sandbox.start", *["operation.get"] * 4]
    assert outcome.submissions == 1, "the operation is durable: it is observed again, never submitted again"


def test_following_gives_up_when_the_host_stays_away_and_says_the_operation_continues(
    scripted: Scripted, client_for: ClientFor, clock: FakeClock
) -> None:
    connection = scripted(op("IN_PROGRESS"), default=DOWN)
    with pytest.raises(OutcomeUnresolved) as caught:
        client_for(connection).submit(START)
    assert caught.value.exit_code is ExitCode.UNRESOLVED
    assert caught.value.operation_id == connection.requests[0]["operation_id"]
    assert "operation get" in (caught.value.hint or "")
    assert 60.0 <= sum(clock.sleeps) < 65.0, "it tried for the outage patience, not forever"
    assert set(connection.methods[1:]) == {"operation.get"}


def test_a_rate_limited_poll_is_simply_asked_again(scripted: Scripted, client_for: ClientFor) -> None:
    busy = refused("RESOURCE_EXHAUSTED", "read rate limit reached for this peer", "SAME_REQUEST_LATER")
    connection = scripted(op("IN_PROGRESS"), busy, busy, op("SUCCEEDED", f.sandbox_body()))
    assert require_success(client_for(connection).submit(START)).succeeded


def test_a_poll_the_host_refuses_for_good_leaves_the_outcome_unresolved(
    scripted: Scripted, client_for: ClientFor
) -> None:
    connection = scripted(op("IN_PROGRESS"), refused("AUTHENTICATION_FAILED", "this peer is no longer enrolled"))
    with pytest.raises(OutcomeUnresolved, match="AUTHENTICATION_FAILED"):
        client_for(connection).submit(START)


# ----------------------------------------------------------------------------- submit: a lost response
def test_a_lost_response_is_resolved_with_the_same_id_and_retry_true(
    scripted: Scripted, client_for: ClientFor, clock: FakeClock
) -> None:
    connection = scripted(LOST, op("SUCCEEDED", f.sandbox_body()))
    outcome = client_for(connection).submit(START)
    assert require_success(outcome).succeeded
    first, again = connection.requests
    assert again["method"] == "sandbox.start", "the same request, not a different question"
    assert again["retry"] is True
    assert "retry" not in first
    assert again["operation_id"] == first["operation_id"] == outcome.operation_id
    assert again["issued_at"] == first["issued_at"], "issued_at is when the caller FIRST issued it"
    assert again["params"] == first["params"]
    assert again["request_id"] != first["request_id"], "only the correlation id is new"
    assert outcome.submissions == 2
    assert clock.sleeps == [0.1], "it paused before asking again"


def test_every_request_about_one_intent_carries_one_identity_however_long_it_takes(
    scripted: Scripted, client_for: ClientFor
) -> None:
    connection = scripted(LOST, DOWN, LOST, DOWN, op("IN_PROGRESS"), op("SUCCEEDED", f.sandbox_body()))
    outcome = client_for(connection).submit(START)
    assert require_success(outcome).succeeded
    assert len(identities(connection)) == 1, "never a new operation id, never a new issued_at"
    assert [r.get("retry", False) for r in connection.requests[:5]] == [False, True, True, True, True]
    assert connection.methods == [*["sandbox.start"] * 5, "operation.get"]


def test_a_retry_that_finds_the_operation_still_running_follows_it(scripted: Scripted, client_for: ClientFor) -> None:
    connection = scripted(LOST, op("IN_PROGRESS"), op("SUCCEEDED", f.sandbox_body()))
    assert require_success(client_for(connection).submit(START)).succeeded
    assert connection.methods == ["sandbox.start", "sandbox.start", "operation.get"]


def test_a_retry_the_host_has_never_heard_of_was_never_accepted_and_is_submitted_afresh_under_the_same_id(
    scripted: Scripted, client_for: ClientFor
) -> None:
    """The response was lost because the request never arrived. The host says so twice; then it is submitted afresh."""
    connection = scripted(
        LOST, NOT_KNOWN, refused("NOT_FOUND", "operation does not exist"), op("SUCCEEDED", f.sandbox_body())
    )
    outcome = client_for(connection).submit(START)
    assert require_success(outcome).succeeded
    assert connection.methods == ["sandbox.start", "sandbox.start", "operation.get", "sandbox.start"]
    assert [r.get("retry", False) for r in connection.requests] == [False, True, False, False]
    assert len(identities(connection)) == 1, "afresh, but under the same operation id and issued_at"


def test_a_refused_retry_is_not_believed_when_the_operation_exists(scripted: Scripted, client_for: ClientFor) -> None:
    """The host checks its mode before it looks for the record: draining refuses the retry of an accepted create."""
    draining = refused(
        "HOST_NOT_SERVING", "the host is Draining and does not serve `sandbox.start`", "SAME_REQUEST_LATER"
    )
    connection = scripted(LOST, draining, op("SUCCEEDED", f.sandbox_body()))
    outcome = client_for(connection).submit(START)
    assert require_success(outcome).succeeded, "the operation had been accepted; the refusal was about the retry"
    assert connection.methods == ["sandbox.start", "sandbox.start", "operation.get"]


def test_a_refused_retry_is_the_answer_once_the_host_confirms_it_holds_no_record(
    scripted: Scripted, client_for: ClientFor
) -> None:
    expired = refused("EXPIRED_REQUEST", "issued_at is outside the acceptance horizon")
    connection = scripted(LOST, expired, refused("NOT_FOUND", "operation does not exist"))
    outcome = client_for(connection).submit(START)
    assert outcome.refusal is not None
    assert outcome.refusal.failure_class is FailureClass.EXPIRED_REQUEST
    assert connection.methods == ["sandbox.start", "sandbox.start", "operation.get"]
    assert len(identities(connection)) == 1, "an expired request is not re-stamped and sent again"
    with pytest.raises(Refused):
        require_success(outcome)


def test_a_lookup_the_host_will_not_answer_leaves_the_outcome_unresolved(
    scripted: Scripted, client_for: ClientFor
) -> None:
    gone = refused("AUTHENTICATION_FAILED", "this peer is no longer enrolled on this host", as_of=None)
    connection = scripted(LOST, gone, gone)
    with pytest.raises(OutcomeUnresolved) as caught:
        client_for(connection).submit(START)
    assert caught.value.exit_code is ExitCode.UNRESOLVED
    assert "would not say whether" in caught.value.message
    assert caught.value.operation_id == connection.requests[0]["operation_id"]


def test_a_rate_limited_lookup_is_asked_again(scripted: Scripted, client_for: ClientFor) -> None:
    busy = refused("RESOURCE_EXHAUSTED", "read rate limit", "SAME_REQUEST_LATER")
    connection = scripted(LOST, NOT_KNOWN, busy, NOT_KNOWN, op("SUCCEEDED", f.sandbox_body()))
    assert require_success(client_for(connection).submit(START)).succeeded
    assert connection.methods == ["sandbox.start", "sandbox.start", "operation.get", "sandbox.start", "operation.get"]


def test_contact_lost_for_good_is_unresolved_never_success_and_never_a_new_id(
    scripted: Scripted, client_for: ClientFor, clock: FakeClock
) -> None:
    connection = scripted(LOST, default=DOWN)
    with pytest.raises(OutcomeUnresolved) as caught:
        client_for(connection).submit(START)
    error = caught.value
    assert error.exit_code is ExitCode.UNRESOLVED
    assert error.operation_id == connection.requests[0]["operation_id"]
    assert "may have been accepted" in (error.hint or "")
    assert "new id" in (error.hint or "")
    assert len(identities(connection)) == 1
    assert all(r.get("retry") is True for r in connection.requests[1:])
    assert 60.0 <= sum(clock.sleeps) < 65.0


def test_the_callers_timeout_also_bounds_the_resolution(
    scripted: Scripted, client_for: ClientFor, clock: FakeClock
) -> None:
    connection = scripted(LOST, default=DOWN)
    with pytest.raises(OutcomeUnresolved):
        client_for(connection).submit(START, timeout_s=3.0)
    assert sum(clock.sleeps) == pytest.approx(3.0)


def test_a_first_submission_that_never_left_is_a_plain_transport_failure(
    scripted: Scripted, client_for: ClientFor
) -> None:
    connection = scripted(DOWN)
    with pytest.raises(HostUnreachable) as caught:
        client_for(connection).submit(START)
    assert caught.value.exit_code is ExitCode.TRANSPORT
    assert len(connection.requests) == 1, "nothing was sent, so there is nothing to resolve"


def test_submissions_the_host_never_recorded_are_bounded_and_end_as_nothing_applied(
    scripted: Scripted, client_for: ClientFor
) -> None:
    never = [LOST, NOT_KNOWN, refused("NOT_FOUND", "operation does not exist")]
    connection = scripted(*never * MAX_SUBMISSIONS_NEVER_RECORDED)
    with pytest.raises(HostUnreachable) as caught:
        client_for(connection).submit(START)
    assert "Nothing was applied" in caught.value.message
    assert caught.value.exit_code is ExitCode.TRANSPORT
    assert len(identities(connection)) == 1
    first_submissions = [r for r in connection.requests if r["method"] == "sandbox.start" and "retry" not in r]
    assert len(first_submissions) == MAX_SUBMISSIONS_NEVER_RECORDED


def test_an_unusable_answer_to_an_operation_says_it_may_have_been_accepted(
    scripted: Scripted, client_for: ClientFor
) -> None:
    connection = scripted(b"this is not json")
    with pytest.raises(ProtocolViolation) as caught:
        client_for(connection).submit(START)
    assert caught.value.exit_code is ExitCode.PROTOCOL
    assert caught.value.operation_id == connection.requests[0]["operation_id"]
    assert "may have been accepted" in (caught.value.hint or "")


def test_a_read_result_in_answer_to_an_operation_is_a_violation(scripted: Scripted, client_for: ClientFor) -> None:
    connection = scripted(answered("sandbox", f.sandbox_view()))
    with pytest.raises(ProtocolViolation, match="with a read result"):
        client_for(connection).submit(START)


def test_an_operation_in_answer_to_a_read_is_a_violation(scripted: Scripted, client_for: ClientFor) -> None:
    connection = scripted(accepted(f.operation_view()))
    with pytest.raises(ProtocolViolation, match="with an operation"):
        client_for(connection).read(rq.host_info())


def test_ctrl_c_in_flight_is_reported_with_the_operation_id(scripted: Scripted, client_for: ClientFor) -> None:
    connection = scripted(KeyboardInterrupt())
    with pytest.raises(MutationInterrupted) as caught:
        client_for(connection).submit(START)
    assert caught.value.operation_id == connection.requests[0]["operation_id"]
    assert isinstance(caught.value, KeyboardInterrupt)


# ----------------------------------------------------------------------------- observe and follow
def test_observe_asks_once_and_reports_whatever_the_host_says(scripted: Scripted, client_for: ClientFor) -> None:
    connection = scripted(op("IN_PROGRESS"), refused("NOT_FOUND", "operation does not exist"))
    client = client_for(connection)
    seen = client.observe(f.OPERATION_ID)
    assert seen.operation is not None
    assert seen.operation.state is OperationState.IN_PROGRESS
    missing = client.observe(f.OPERATION_ID)
    assert missing.refusal is not None
    assert connection.methods == ["operation.get", "operation.get"]
    assert connection.requests[0]["params"] == {"operation_id": f.OPERATION_ID}


def test_follow_observes_until_terminal(scripted: Scripted, client_for: ClientFor) -> None:
    connection = scripted(op("IN_PROGRESS"), op("IN_PROGRESS"), op("FAILED"))
    outcome = client_for(connection).follow(f.OPERATION_ID)
    assert outcome.operation is not None
    assert outcome.operation.state is OperationState.FAILED
    assert connection.methods == ["operation.get"] * 3


def test_follow_of_an_operation_the_host_does_not_hold_is_a_refusal(scripted: Scripted, client_for: ClientFor) -> None:
    connection = scripted(refused("NOT_FOUND", "operation does not exist"))
    outcome = client_for(connection).follow(f.OPERATION_ID)
    assert outcome.refusal is not None
    assert len(connection.requests) == 1


# ----------------------------------------------------------------------------- what an outcome means
def view_of(state: str, **over: Any) -> OperationView:
    return OperationView.model_validate(f.operation_view(state, **over))


@pytest.mark.parametrize(
    ("state", "code"),
    [
        ("SUCCEEDED", ExitCode.OK),
        ("FAILED", ExitCode.FAILED),
        ("CANCELLED", ExitCode.FAILED),
        ("UNKNOWN", ExitCode.UNKNOWN),
        ("ACCEPTED", ExitCode.UNRESOLVED),
        ("IN_PROGRESS", ExitCode.UNRESOLVED),
        ("RECOVERING", ExitCode.UNRESOLVED),
    ],
)
def test_the_exit_code_states_the_operation_condition(state: str, code: ExitCode) -> None:
    assert exit_code_for(view_of(state)) is code


def test_unknown_is_reported_as_unknown(scripted: Scripted, client_for: ClientFor) -> None:
    connection = scripted(op("UNKNOWN", failure=f.failure("UNKNOWN_OUTCOME", "no result could be obtained")))
    outcome = client_for(connection).submit(START)
    assert len(connection.requests) == 1, "UNKNOWN is terminal: nothing is retried and nothing is polled"
    with pytest.raises(OutcomeUnknown) as caught:
        require_success(outcome)
    error = caught.value
    assert error.exit_code is ExitCode.UNKNOWN
    assert not isinstance(error, OperationFailed), "not a failure"
    assert "UNKNOWN" in error.message
    assert "neither as success nor as failure" in (error.hint or "")
    assert error.envelope.operation is not None
    assert error.envelope.operation.effect == "MAY_BE_APPLIED"


def test_failed_and_cancelled_are_failures_that_carry_the_operation(scripted: Scripted, client_for: ClientFor) -> None:
    for state in ("FAILED", "CANCELLED"):
        connection = scripted(op(state, failure=f.failure("TIMEOUT", "deadline passed")))
        with pytest.raises(OperationFailed) as caught:
            require_success(client_for(connection).submit(START))
        assert caught.value.exit_code is ExitCode.FAILED
        assert f"ended {state}" in caught.value.message
        assert "TIMEOUT: deadline passed" in caught.value.message
        assert caught.value.envelope.operation is not None


def test_a_state_this_client_does_not_know_is_never_success(scripted: Scripted, client_for: ClientFor) -> None:
    ended = scripted(op("ABANDONED", effect="NOT_APPLIED", cleanup="COMPLETE"))
    with pytest.raises(OutcomeUnknown) as caught:
        require_success(client_for(ended).submit(START))
    assert "ABANDONED" in caught.value.message
    pending = scripted(op("SUSPENDED", effect=None), default=op("SUSPENDED", effect=None))
    with pytest.raises(NotFinished):
        require_success(client_for(pending).submit(START, timeout_s=1.0))


def test_an_outcome_is_a_refusal_or_an_operation_never_both_never_neither() -> None:
    with pytest.raises(ValueError, match="either a refusal or an operation"):
        Outcome("op-12345678")


def test_an_outcome_serialises_as_the_answer_it_is(scripted: Scripted, client_for: ClientFor) -> None:
    connection = scripted(op("IN_PROGRESS"), op("SUCCEEDED", f.sandbox_body()), refused("STATE_CONFLICT", "busy"))
    client = client_for(connection)
    followed = client.submit(START).to_wire()
    assert followed["answer"] == "OPERATION", "even when the last word came from operation.get"
    assert followed["operation"]["state"] == "SUCCEEDED"
    assert followed["as_of"] == f.AS_OF
    assert "request_id" not in followed
    refusal = client.submit(START).to_wire()
    assert (refusal["answer"], refusal["refusal"]["class"]) == ("REFUSED", "STATE_CONFLICT")


# ----------------------------------------------------------------------------- answers, one frame at a time
def frame(body: dict[str, Any], *, request_id: str | None = "req-1", protocol: str = PROTOCOL) -> bytes:
    return json.dumps({"protocol": protocol, "request_id": request_id, **body}).encode()


def test_an_answer_must_belong_to_the_request() -> None:
    assert parse_response(frame(accepted(f.operation_view())), "req-1").operation is not None
    with pytest.raises(ProtocolViolation, match="request_id mismatch"):
        parse_response(frame(accepted(f.operation_view()), request_id="req-other"), "req-1")
    with pytest.raises(ProtocolViolation, match="no request_id"):
        parse_response(frame(answered("metrics", {}), request_id=None), "req-1")


def test_a_refusal_issued_before_any_request_was_read_is_still_a_refusal() -> None:
    early = parse_response(
        frame(refused("AUTHENTICATION_FAILED", "not enrolled", as_of=None), request_id=None), "req-1"
    )
    assert early.refusal is not None
    assert early.refusal.failure_class is FailureClass.AUTHENTICATION_FAILED


def test_a_refusal_from_a_host_of_another_protocol_version_is_reported_as_the_refusal_it_is() -> None:
    answer = parse_response(
        frame(refused("PROTOCOL_ERROR", "this host speaks `acf.host/3`"), protocol="acf.host/3"), "req-1"
    )
    assert answer.refusal is not None
    assert answer.refusal.failure_class is FailureClass.PROTOCOL_ERROR


def test_a_non_refusal_in_another_protocol_version_is_a_violation() -> None:
    with pytest.raises(ProtocolViolation, match=r"speaks 'acf\.host/3'"):
        parse_response(frame(answered("metrics", {}), protocol="acf.host/3"), "req-1")


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"not json",
        b"[]",
        b'{"protocol": "acf.host/2"}',
        json.dumps({"protocol": PROTOCOL, "request_id": "req-1", "answer": "OPERATION"}).encode(),
        json.dumps({"protocol": PROTOCOL, "request_id": "req-1", **accepted({"operation_id": "x"})}).encode(),
    ],
)
def test_a_malformed_answer_is_a_violation_that_does_not_echo_the_payload(raw: bytes) -> None:
    with pytest.raises(ProtocolViolation) as caught:
        parse_response(raw, "req-1")
    assert caught.value.exit_code is ExitCode.PROTOCOL
    assert "not a valid acf.host/2 response" in caught.value.message
    assert raw.decode() not in caught.value.message or not raw


def test_an_answer_kind_this_client_does_not_know_is_a_violation_that_names_it() -> None:
    with pytest.raises(ProtocolViolation, match="DEFERRED"):
        parse_response(frame({"answer": "DEFERRED"}), "req-1")


def test_an_answer_document_is_the_answer_without_the_correlation_id() -> None:
    answer = parse_response(frame(answered("sandbox", f.sandbox_view())), "req-1")
    document = answer_document(answer)
    assert "request_id" not in document
    assert document["result"]["data"]["sandbox_id"] == f.SANDBOX_ID
    assert document["as_of"] == f.AS_OF


def test_closing_the_client_closes_its_connection(scripted: Scripted, client_for: ClientFor) -> None:
    connection = scripted()
    client_for(connection).close()
    assert connection.closed == 1
