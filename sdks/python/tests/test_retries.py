"""Retries: only what is safe to repeat, with the same key and the same bytes, within three bounds.

The rule that matters most here is the one that keeps one idempotency key equal to one operation: a
request is repeated exactly as it was, and no failure is ever escaped by making a new key.
"""

from __future__ import annotations

import json
from typing import Any

import httpx2
import pytest

import agentcompute
from agentcompute import (
    APIConnectionError,
    APITimeoutError,
    AsyncFabric,
    Fabric,
    IncompatibleServerError,
    OutcomeLostError,
    OutcomeUnresolvedError,
    RateLimitError,
    RefusedError,
    ServiceUnavailableError,
    UnexpectedResponseError,
    UnresolvedError,
)
from support import (
    CRD,
    REGISTRY_ROWS,
    SBX,
    Exchange,
    Handler,
    Harness,
    Json,
    done,
    ex,
    fault,
    refusal,
    reply,
    sandbox,
)

_KEY = "key-0001"
_BODY = {"image": "python", "resources": {"vcpus": 1, "memory_mib": 512, "disk_mib": 1024}}
_ERROR_CODES = sorted(code for code, row in REGISTRY_ROWS.items() if row["error_answer"])


def _created() -> Json:
    return reply(200, done("sandbox.create", "sandbox", sandbox("READY")))


def _post(response: Json) -> Exchange:
    return ex("POST", "/sandboxes", response, json=_BODY)


def _get(response: Json) -> Exchange:
    return ex("GET", f"/sandboxes/{SBX}", response)


def _create(harness: Harness, fabric: Fabric | AsyncFabric, key: str | None = _KEY) -> Any:
    """One mutation: a create that is not followed by a start."""
    return harness.run(
        fabric.sandboxes.create("python", cpu=1, memory=512, disk=1024, start=False, idempotency_key=key)
    )


def _read(harness: Harness, fabric: Fabric | AsyncFabric) -> Any:
    return harness.run(fabric.sandboxes.get(SBX))


# ------------------------------------------------------------------------------- what is retried, and what not
@pytest.mark.parametrize("code", _ERROR_CODES)
@pytest.mark.parametrize("mutation", [True, False], ids=["mutation", "read"])
def test_an_error_answer_is_retried_only_if_it_says_same_request_later(
    harness: Harness, code: str, mutation: bool
) -> None:
    """Every code of the registry: the retry advice decides, never the status, and OUTCOME_LOST is never repeated."""
    row = REGISTRY_ROWS[code]
    answer = refusal(code, retry_after=1 if row["retry_after"] else None)
    retried = row["retry"] == "SAME_REQUEST_LATER" and code != "OUTCOME_LOST"
    first, second = (_post(answer), _post(_created())) if mutation else (_get(answer), _get(reply(200, sandbox())))
    script = harness.script(first, second) if retried else harness.script(first)
    fabric = harness.client(script)
    call = _create if mutation else _read

    if retried:
        assert call(harness, fabric).sandbox_id == SBX
        assert len(script.seen) == 2
        return
    with pytest.raises(agentcompute.APIError) as raised:
        call(harness, fabric)
    error = raised.value
    assert type(error).__name__ == row["sdk_exception"]
    assert (error.code, error.kind, error.retry) == (code, row["kind"], row["retry"])
    assert error.status == row["http_status"] or row["http_status"] is None
    assert len(script.seen) == 1


def test_the_registry_and_the_error_classes_of_this_package_agree() -> None:
    for code, row in REGISTRY_ROWS.items():
        if row["error_answer"]:
            assert agentcompute.errors.error_class(code, row["kind"]).__name__ == row["sdk_exception"], code
        assert hasattr(agentcompute, row["sdk_exception"]), row["sdk_exception"]


@pytest.mark.parametrize(
    ("kind", "retry", "expected"),
    [
        ("REFUSED", "NEVER", RefusedError),
        ("REFUSED", "AFTER_CHANGE", RefusedError),
        ("UNRESOLVED", "NEVER", UnresolvedError),
        ("SOMETHING_NEW", "NEVER", RefusedError),
        ("REFUSED", "WHEN_THE_MOON_IS_FULL", RefusedError),
    ],
)
def test_an_unknown_code_is_handled_by_its_kind_and_is_not_retried_unless_it_says_so(
    harness: Harness, kind: str, retry: str, expected: type[agentcompute.APIError]
) -> None:
    script = harness.script(_post(refusal("FUTURE_CODE", kind=kind, retry=retry, status=409)))
    with pytest.raises(agentcompute.APIError) as raised:
        _create(harness, harness.client(script))
    assert type(raised.value) is expected
    assert (raised.value.code, raised.value.kind, raised.value.retry) == ("FUTURE_CODE", kind, retry)
    assert len(script.seen) == 1


def test_an_unknown_code_that_says_same_request_later_is_retried(harness: Harness) -> None:
    script = harness.script(
        _post(refusal("FUTURE_CODE", kind="UNRESOLVED", retry="SAME_REQUEST_LATER", status=418)),
        _post(_created()),
    )
    assert _create(harness, harness.client(script)).sandbox_id == SBX


def test_outcome_lost_is_not_retried_even_if_an_answer_said_so(harness: Harness) -> None:
    script = harness.script(_post(refusal("OUTCOME_LOST", retry="SAME_REQUEST_LATER", retry_after=1)))
    with pytest.raises(OutcomeLostError) as raised:
        _create(harness, harness.client(script))
    assert raised.value.idempotency_key == _KEY
    assert len(script.seen) == 1


def test_a_problem_without_retry_advice_is_not_retried(harness: Harness) -> None:
    body = {"code": "RATE_LIMITED", "message": "slow down"}
    script = harness.script(_post(reply(429, body, content_type="application/problem+json")))
    with pytest.raises(RateLimitError) as raised:
        _create(harness, harness.client(script))
    assert (raised.value.kind, raised.value.retry, raised.value.message) == ("", "", "slow down")
    assert len(script.seen) == 1


def test_the_status_alone_decides_nothing(harness: Harness) -> None:
    """The same status, 409: one answer is retried and the other is not."""
    script = harness.script(
        _post(refusal("REQUEST_IN_PROGRESS", retry_after=1)),
        _post(refusal("STATE_CONFLICT")),
    )
    with pytest.raises(agentcompute.StateConflictError):
        _create(harness, harness.client(script))
    assert [seen.key for seen in script.seen] == [_KEY, _KEY]


@pytest.mark.parametrize("max_retries", [0, 1, 2, 5])
def test_a_request_is_retried_at_most_max_retries_times(harness: Harness, max_retries: int) -> None:
    harness.jitter = 0.0  # so that the only delay is the one second the server asks for
    script = harness.script(*[_get(refusal("UPSTREAM_UNAVAILABLE", retry_after=1))] * (max_retries + 1))
    with pytest.raises(ServiceUnavailableError):
        _read(harness, harness.client(script, max_retries=max_retries))
    assert len(script.seen) == max_retries + 1
    assert harness.clock.slept == [1.0] * max_retries


# --------------------------------------------------------------------- the same key and the same body bytes
def test_every_attempt_carries_the_same_key_and_the_same_body_byte_for_byte(harness: Harness) -> None:
    script = harness.script(
        _post(fault("connection_reset")),
        _post(reply(502, content_type="text/html")),
        _post(refusal("OUTCOME_UNRESOLVED", retry_after=1, idempotency_key=_KEY)),
        _post(refusal("REQUEST_IN_PROGRESS", retry_after=1, idempotency_key=_KEY)),
        _post(refusal("RATE_LIMITED", retry_after=2)),
        _post(fault("timeout")),
        _post(_created()),
    )
    fabric = harness.client(script, max_retries=6)
    assert _create(harness, fabric).sandbox_id == SBX

    assert len(script.seen) == 7
    assert {seen.key for seen in script.seen} == {_KEY}
    assert len({seen.body for seen in script.seen}) == 1
    assert {(seen.method, seen.path, tuple(seen.query.items())) for seen in script.seen} == {
        ("POST", "/v1/projects/prj_0000000000000001/sandboxes", ())
    }
    assert {seen.headers["content-type"] for seen in script.seen} == {"application/json"}


def test_a_generated_key_is_made_once_and_reused_by_every_retry(harness: Harness) -> None:
    script = harness.script(_post(fault()), _post(fault("timeout")), _post(_created()))
    _create(harness, harness.client(script), key=None)
    keys = {seen.key for seen in script.seen}
    assert len(keys) == 1
    (key,) = keys
    assert key is not None
    assert len(key) == 36
    assert key[14] == "4"


def test_two_calls_never_share_a_generated_key(harness: Harness) -> None:
    script = harness.script(_post(_created()), _post(_created()))
    fabric = harness.client(script)
    _create(harness, fabric, key=None)
    _create(harness, fabric, key=None)
    assert script.seen[0].key != script.seen[1].key


@pytest.mark.parametrize("code", ["IDEMPOTENCY_CONFLICT", "REQUEST_IN_PROGRESS", "OUTCOME_UNRESOLVED", "OUTCOME_LOST"])
def test_no_failure_is_escaped_with_a_new_key(harness: Harness, code: str) -> None:
    row = REGISTRY_ROWS[code]
    retried = row["retry"] == "SAME_REQUEST_LATER" and code != "OUTCOME_LOST"
    attempts = 3 if retried else 1
    script = harness.script(*[_post(refusal(code, retry_after=1 if row["retry_after"] else None))] * attempts)
    with pytest.raises(agentcompute.APIError) as raised:
        _create(harness, harness.client(script))
    assert raised.value.code == code
    # What is unresolved names the key to come back with. A refusal left nothing behind.
    assert raised.value.idempotency_key == (_KEY if row["kind"] == "UNRESOLVED" else None)
    assert [seen.key for seen in script.seen] == [_KEY] * attempts


def test_a_read_carries_no_key_and_no_body(harness: Harness) -> None:
    script = harness.script(
        ex(
            "GET",
            f"/sandboxes/{SBX}",
            reply(200, sandbox()),
            json=None,
            absent_headers=["idempotency-key", "content-type"],
        )
    )
    _read(harness, harness.client(script))


# ----------------------------------------------------------------------------------------------- the delays
@pytest.mark.parametrize(
    ("jitter", "expected"),
    [
        (0.999_999, [0.5, 1.0, 2.0, 4.0, 8.0, 8.0, 8.0]),  # the ceilings: 0.5 * 2**n, capped at 8
        (0.5, [0.25, 0.5, 1.0, 2.0, 4.0, 4.0, 4.0]),
        (0.0, [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]),  # full jitter: the interval starts at zero
    ],
)
def test_the_backoff_is_exponential_with_full_jitter_and_capped(
    harness: Harness, jitter: float, expected: list[float]
) -> None:
    harness.jitter = jitter
    script = harness.script(*[_get(fault())] * 7, _get(reply(200, sandbox())))
    _read(harness, harness.client(script, max_retries=7))
    assert harness.clock.slept == pytest.approx(expected, rel=1e-4)


@pytest.mark.parametrize(
    ("retry_after", "jitter", "waited"),
    [
        (3, 0.5, 3.0),  # the server's advice is longer than the computed delay: it replaces it
        (8, 0.5, 8.0),  # exactly the cap is still waited for
        (0, 0.5, 0.25),  # shorter than the computed delay: the computed delay stands
        (1, 0.999_999, 1.0),
    ],
)
def test_retry_after_replaces_the_computed_delay_when_it_is_longer(
    harness: Harness, retry_after: int, jitter: float, waited: float
) -> None:
    harness.jitter = jitter
    script = harness.script(_post(refusal("RATE_LIMITED", retry_after=retry_after)), _post(_created()))
    _create(harness, harness.client(script))
    assert harness.clock.slept == pytest.approx([waited], rel=1e-4)


@pytest.mark.parametrize("retry_after", [9, 60, 600, 86_400])
def test_a_retry_after_beyond_the_cap_is_not_waited_for_and_the_advice_is_surfaced(
    harness: Harness, retry_after: int
) -> None:
    script = harness.script(_post(refusal("RATE_LIMITED", retry_after=retry_after)))
    with pytest.raises(RateLimitError) as raised:
        _create(harness, harness.client(script))
    assert raised.value.retry_after == retry_after
    assert raised.value.retry == "SAME_REQUEST_LATER"
    assert raised.value.idempotency_key is None  # a refusal leaves nothing behind to come back for
    assert harness.clock.slept == []
    assert len(script.seen) == 1


@pytest.mark.parametrize("header", ["soon", "1.5", "-1", "Wed, 21 Oct 2026 07:28:00 GMT", ""])
def test_a_retry_after_that_is_not_whole_seconds_is_not_advice(harness: Harness, header: str) -> None:
    answer = refusal("RATE_LIMITED")
    answer["headers"]["retry-after"] = header
    script = harness.script(_post(answer), _post(_created()))
    _create(harness, harness.client(script))
    assert harness.clock.slept == [0.25]


# ----------------------------------------------------------------------------------------------- the budget
def _flaky_server(counter: dict[str, int]) -> Handler:
    """Answers the first attempt of every call with a retryable refusal and the second with the sandbox."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        counter["requests"] += 1
        counter["odd"] = 1 - counter.get("odd", 0)
        if counter["odd"]:
            body = refusal("UPSTREAM_UNAVAILABLE")["json"]
            headers = {"content-type": "application/problem+json", "x-request-id": "req_budget"}
            return httpx2.Response(503, headers=headers, content=json.dumps(body).encode())
        return httpx2.Response(200, json=sandbox())

    return handler


def test_the_budget_stops_a_retry_storm_and_refills_with_time(harness: Harness) -> None:
    """A retry is allowed while the retries of the last 60 s are fewer than 10 + 0.2 * requests of the last 60 s."""
    counter = {"requests": 0}
    fabric = harness.client(_flaky_server(counter))

    # Call k has seen k - 1 retries and 2k - 1 requests when it asks for its retry: allowed while
    # k - 1 < 10 + 0.2 * (2k - 1), which holds up to k = 17.
    for _ in range(17):
        assert _read(harness, fabric).sandbox_id == SBX
    assert counter["requests"] == 34

    with pytest.raises(ServiceUnavailableError) as raised:
        _read(harness, fabric)
    assert raised.value.retry == "SAME_REQUEST_LATER"
    assert counter["requests"] == 35

    counter["odd"] = 0
    harness.clock.now += 61
    assert _read(harness, fabric).sandbox_id == SBX


def test_the_budget_belongs_to_one_client(harness: Harness) -> None:
    spent, fresh = {"requests": 0}, {"requests": 0}
    first = harness.client(_flaky_server(spent))
    for _ in range(17):
        _read(harness, first)
    with pytest.raises(ServiceUnavailableError):
        _read(harness, first)
    assert _read(harness, harness.client(_flaky_server(fresh))).sandbox_id == SBX


def test_a_mutation_without_an_answer_that_the_budget_does_not_let_retry_is_unresolved(harness: Harness) -> None:
    """A spent budget changes whether a request is repeated, never what an unanswered mutation is called."""
    script = harness.script(_post(fault()))
    fabric = harness.client(script)
    budget = fabric._driver.engine._budget
    while budget.take(harness.clock.time()):
        pass
    # One more request raises the allowance by a fifth of a retry: spend what that would allow as well.
    budget._retries.append(harness.clock.time())

    with pytest.raises(OutcomeUnresolvedError) as raised:
        _create(harness, fabric)
    assert raised.value.idempotency_key == _KEY
    assert len(script.seen) == 1
    assert harness.clock.slept == []


# ------------------------------------------------------------------------------------------- the total cap
def test_the_time_spent_retrying_one_request_is_capped(harness: Harness) -> None:
    harness.jitter = 0.999_999
    script = harness.script(*[_post(fault())] * 5)
    fabric = harness.client(script, max_retries=50, retry_total_max=10)
    with pytest.raises(OutcomeUnresolvedError) as raised:
        _create(harness, fabric)
    # 0.5 + 1 + 2 + 4 were waited; the next delay, 8 s, would end after the cap.
    assert harness.clock.waited == pytest.approx(7.5, rel=1e-4)
    assert len(script.seen) == 5
    assert raised.value.idempotency_key == _KEY


def test_the_default_cap_is_a_day_less_an_hour(harness: Harness) -> None:
    fabric = harness.client(harness.script())
    assert fabric._driver.engine.retry_total_max == 23 * 3600


# -------------------------------------------------------------------------- how a call ends without an answer
def test_a_mutation_that_was_sent_and_never_answered_is_unresolved_and_exposes_its_key(harness: Harness) -> None:
    script = harness.script(_post(fault()), _post(fault("timeout")), _post(fault("protocol_error")))
    with pytest.raises(OutcomeUnresolvedError) as raised:
        _create(harness, harness.client(script))
    error = raised.value
    assert error.idempotency_key == _KEY
    assert (error.code, error.kind, error.retry) == ("OUTCOME_UNRESOLVED", "UNRESOLVED", "SAME_REQUEST_LATER")
    assert error.status is None
    assert not isinstance(error, RefusedError)
    assert len(script.seen) == 3


@pytest.mark.parametrize(
    "kind",
    [
        "connect_error",
        "connect_timeout",
        "pool_timeout",
        "connection_reset",
        "timeout",
        "write_error",
        "decoding_error",
    ],
)
def test_a_mutation_under_a_key_that_ends_without_an_answer_is_unresolved_whatever_the_failure(
    harness: Harness, kind: str
) -> None:
    """Even when nothing seems to have left: the key is what settles it, and it costs nothing to ask with it."""
    script = harness.script(*[_post(fault(kind))] * 3)
    with pytest.raises(OutcomeUnresolvedError) as raised:
        _create(harness, harness.client(script))
    assert raised.value.idempotency_key == _KEY
    assert raised.value.status is None
    assert isinstance(raised.value.__cause__, httpx2.RequestError)
    assert len(script.seen) == 3


@pytest.mark.parametrize(
    ("kind", "expected"),
    [("connect_error", APIConnectionError), ("connect_timeout", APITimeoutError), ("pool_timeout", APITimeoutError)],
)
def test_a_mutation_without_a_key_that_never_left_is_a_connection_error(
    harness: Harness, kind: str, expected: type[APIConnectionError]
) -> None:
    script = harness.script(*[ex("DELETE", f"/agent-credentials/{CRD}", fault(kind))] * 3)
    with pytest.raises(APIConnectionError) as raised:
        harness.run(harness.client(script).auth.revoke_agent_credential(CRD))
    assert type(raised.value) is expected
    assert not isinstance(raised.value, agentcompute.APIError)
    assert "may have received" not in str(raised.value)
    assert len(script.seen) == 3


@pytest.mark.parametrize(
    "first",
    [fault("connection_reset"), fault("write_error"), fault("decoding_error"), reply(503, content_type="text/plain")],
)
def test_one_lost_answer_is_enough_to_make_the_outcome_unresolved(harness: Harness, first: Json) -> None:
    script = harness.script(_post(first), _post(fault("connect_error")), _post(fault("connect_error")))
    with pytest.raises(OutcomeUnresolvedError) as raised:
        _create(harness, harness.client(script))
    assert raised.value.idempotency_key == _KEY


def test_an_unresolved_answer_followed_by_silence_stays_unresolved(harness: Harness) -> None:
    script = harness.script(
        _post(refusal("OUTCOME_UNRESOLVED", retry_after=1, idempotency_key=_KEY)),
        _post(fault("connect_error")),
        _post(fault("connect_error")),
    )
    with pytest.raises(OutcomeUnresolvedError) as raised:
        _create(harness, harness.client(script))
    assert raised.value.status is None
    assert raised.value.idempotency_key == _KEY


@pytest.mark.parametrize(
    ("kind", "expected"),
    [("connection_reset", APIConnectionError), ("timeout", APITimeoutError), ("connect_error", APIConnectionError)],
)
def test_a_read_that_is_never_answered_is_a_connection_error(
    harness: Harness, kind: str, expected: type[APIConnectionError]
) -> None:
    script = harness.script(*[_get(fault(kind))] * 3)
    with pytest.raises(APIConnectionError) as raised:
        _read(harness, harness.client(script))
    assert type(raised.value) is expected
    assert len(script.seen) == 3


def test_a_read_that_keeps_being_refused_surfaces_the_last_error_received(harness: Harness) -> None:
    script = harness.script(
        _get(fault()),
        _get(refusal("RATE_LIMITED", retry_after=1)),
        _get(refusal("UPSTREAM_UNAVAILABLE", retry_after=1)),
    )
    with pytest.raises(ServiceUnavailableError) as raised:
        _read(harness, harness.client(script))
    assert raised.value.idempotency_key is None


# -------------------------------------------------------------------- answers that are not problem documents
@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_a_5xx_without_a_problem_document_is_no_answer_for_a_mutation(harness: Harness, status: int) -> None:
    script = harness.script(_post(reply(status, content_type="text/html")), _post(_created()))
    assert _create(harness, harness.client(script)).sandbox_id == SBX
    assert [seen.key for seen in script.seen] == [_KEY, _KEY]


def test_a_5xx_without_a_problem_document_on_every_attempt_is_unresolved(harness: Harness) -> None:
    html = {
        "status": 502,
        "headers": {"content-type": "text/html", "x-request-id": "req_gateway"},
        "content": b"<html>Bad Gateway</html>",
    }
    script = harness.script(*[_post(html)] * 3)
    with pytest.raises(OutcomeUnresolvedError) as raised:
        _create(harness, harness.client(script))
    assert raised.value.idempotency_key == _KEY
    assert (raised.value.status, raised.value.request_id) == (502, "req_gateway")
    assert not isinstance(raised.value, RefusedError)


@pytest.mark.parametrize("status", [500, 502, 503])
def test_a_5xx_without_a_problem_document_is_unexpected_for_a_read_and_not_retried(
    harness: Harness, status: int
) -> None:
    script = harness.script(_get(reply(status, content_type="text/html")))
    with pytest.raises(UnexpectedResponseError) as raised:
        _read(harness, harness.client(script))
    assert raised.value.status == status
    assert raised.value.request_id == "req_000000000000000000000001"
    assert len(script.seen) == 1


@pytest.mark.parametrize("mutation", [True, False], ids=["mutation", "read"])
@pytest.mark.parametrize(
    "answer",
    [
        reply(404),
        reply(404, {"detail": "Not Found"}),
        {"status": 404, "headers": {"content-type": "text/html"}, "content": b"<h1>404</h1>"},
        reply(404, {"code": 404, "message": "no route"}),  # `code` is not a string: not a problem of this API
    ],
)
def test_a_404_without_a_code_means_the_server_does_not_speak_v1(
    harness: Harness, mutation: bool, answer: Json
) -> None:
    script = harness.script(_post(answer) if mutation else _get(answer))
    with pytest.raises(IncompatibleServerError, match="does not speak version v1") as raised:
        (_create if mutation else _read)(harness, harness.client(script))
    assert isinstance(raised.value, agentcompute.ConfigurationError)
    assert raised.value.status == 404
    assert len(script.seen) == 1


@pytest.mark.parametrize("mutation", [True, False], ids=["mutation", "read"])
@pytest.mark.parametrize(
    "answer",
    [
        {"status": 200, "headers": {"content-type": "text/html"}, "content": b"<html>login</html>"},
        {"status": 200, "headers": {}, "content": b""},
        reply(200, body=None),
        {"status": 200, "headers": {"content-type": "application/json"}, "content": b"[1, 2]"},
        {"status": 200, "headers": {"content-type": "application/json"}, "content": b'{"truncated": '},
        {"status": 204, "headers": {}, "content": b""},
        {"status": 302, "headers": {"location": "https://elsewhere.example/v1"}, "content": b""},
        {"status": 400, "headers": {"content-type": "text/plain"}, "content": b"bad request"},
        {"status": 401, "headers": {"content-type": "application/json"}, "content": b'{"error": "unauthorized"}'},
        {"status": 200, "headers": {"content-type": "application/problem+json"}, "content": b'{"title": "odd"}'},
    ],
)
def test_any_other_answer_that_is_not_of_this_api_is_unexpected_and_not_retried(
    harness: Harness, mutation: bool, answer: Json
) -> None:
    script = harness.script(_post(answer) if mutation else _get(answer))
    with pytest.raises(UnexpectedResponseError) as raised:
        (_create if mutation else _read)(harness, harness.client(script))
    assert raised.value.status == answer["status"]
    assert len(script.seen) == 1


def test_a_problem_document_decides_even_when_its_status_says_success(harness: Harness) -> None:
    answer = refusal("PERMISSION_DENIED", status=200)
    script = harness.script(_post(answer))
    with pytest.raises(agentcompute.PermissionDeniedError):
        _create(harness, harness.client(script))


# ---------------------------------------------------------------------------- mutations that carry no key
def test_minting_is_not_repeated_after_it_may_have_been_received(harness: Harness) -> None:
    """Without a key, a second request that follows a received one would mint a second credential."""
    script = harness.script(ex("POST", "/agent-credentials", fault("connection_reset")))
    fabric = harness.client(script)
    with pytest.raises(APIConnectionError, match="may have received") as raised:
        harness.run(fabric.auth.mint_agent_credential("agent-1", lifetime="1h"))
    assert not isinstance(raised.value, agentcompute.APIError)
    assert any("List the agent credentials" in note for note in raised.value.__notes__)
    assert len(script.seen) == 1
    assert script.seen[0].key is None


def test_minting_is_repeated_when_nothing_was_sent_or_the_server_says_later(harness: Harness) -> None:
    minted = {
        "credential_id": CRD,
        "kind": "agent",
        "label": "agent-1",
        "display_prefix": "acf1_agt_abcd",
        "status": "ACTIVE",
        "issued_at": "2026-11-19T10:00:00.000Z",
        "expires_at": "2026-11-19T11:00:00.000Z",
    }
    body = {"label": "agent-1", "lifetime_seconds": 3600}
    script = harness.script(
        ex("POST", "/agent-credentials", fault("connect_error"), json=body),
        ex("POST", "/agent-credentials", refusal("UPSTREAM_UNAVAILABLE", retry_after=1), json=body),
        ex("POST", "/agent-credentials", reply(201, minted), json=body, absent_headers=["idempotency-key"]),
    )
    fabric = harness.client(script)
    credential = harness.run(fabric.auth.mint_agent_credential("agent-1", lifetime="1h"))
    assert credential.credential_id == CRD


def test_a_5xx_without_a_problem_document_is_no_answer_for_minting_and_is_not_repeated(harness: Harness) -> None:
    script = harness.script(ex("POST", "/agent-credentials", reply(502, content_type="text/html")))
    with pytest.raises(UnexpectedResponseError, match="whether the request was received is not known") as raised:
        harness.run(harness.client(script).auth.mint_agent_credential("agent-1", lifetime="1h"))
    assert raised.value.status == 502
    assert any("List the agent credentials" in note for note in raised.value.__notes__)
    assert len(script.seen) == 1


def test_a_5xx_without_a_problem_document_is_no_answer_for_revoking_and_is_asked_again(harness: Harness) -> None:
    script = harness.script(*[ex("DELETE", f"/agent-credentials/{CRD}", reply(503, content_type="text/html"))] * 3)
    with pytest.raises(UnexpectedResponseError) as raised:
        harness.run(harness.client(script).auth.revoke_agent_credential(CRD))
    assert raised.value.status == 503
    assert len(script.seen) == 3


def test_an_unresolved_answer_names_the_key_even_when_the_server_did_not(harness: Harness) -> None:
    unnamed = refusal("FUTURE_CODE", kind="UNRESOLVED", retry="NEVER", status=409)
    named = refusal("FUTURE_CODE", kind="UNRESOLVED", retry="NEVER", status=409, idempotency_key="the-servers-word")
    refused = refusal("FUTURE_CODE", kind="REFUSED", retry="NEVER", status=409)
    script = harness.script(_post(unnamed), _post(named), _post(refused))
    fabric = harness.client(script)
    keys = []
    for _ in range(3):
        with pytest.raises(agentcompute.APIError) as raised:
            _create(harness, fabric)
        keys.append(raised.value.idempotency_key)
    assert keys == [_KEY, "the-servers-word", None]


def test_revoking_twice_is_revoking_once_so_a_lost_answer_is_asked_for_again(harness: Harness) -> None:
    revoked = {
        "credential_id": CRD,
        "kind": "agent",
        "label": "agent-1",
        "display_prefix": "acf1_agt_abcd",
        "status": "REVOKED",
        "issued_at": "2026-11-19T10:00:00.000Z",
        "expires_at": "2026-11-19T11:00:00.000Z",
    }
    script = harness.script(
        ex("DELETE", f"/agent-credentials/{CRD}", fault("connection_reset")),
        ex("DELETE", f"/agent-credentials/{CRD}", reply(200, revoked), absent_headers=["idempotency-key"]),
    )
    credential = harness.run(harness.client(script).auth.revoke_agent_credential(CRD))
    assert credential.status == "REVOKED"
