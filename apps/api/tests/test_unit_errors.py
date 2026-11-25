"""The public failure vocabulary: every code, the kind of answer it is, and how it is rendered.

Proves the table of failure classes on the public surface row by row (code, who decides, kind, HTTP
status, whether `Retry-After` is sent, the SDK exception), the two kinds of unsuccessful answer and
what each carries (ERR-6), ERR-4 (a class the host decides keeps the host's name, meaning and retry
advice; the platform maps none onto another and invents none) and the naming half of ERR-5 (the host's
refusals of the platform itself have no public name). Catalog entry: T3-ERR-01.

The table below is the contract's, written out as data. The code table, the generated problem
registry and the host's own contract are each compared with it, so none of them can move alone.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml
from hypothesis import given
from hypothesis import strategies as st

from acf_api.command import errors as e
from acf_api.command import model as m
from acf_api.command.errors import CODES, Code, Kind, Retry

REPO = Path(__file__).resolve().parents[3]
REGISTRY = REPO / "protocols" / "api" / "problems" / "registry.yaml"
HOST_API = REPO / "execution" / "contracts" / "host-api.json"

P, H, EITHER = "platform", "host", "either"
REFUSED, UNRESOLVED = "REFUSED", "UNRESOLVED"
LATER, CHANGE, NEVER = "SAME_REQUEST_LATER", "AFTER_CHANGE", "NEVER"
#: The contract names no class for these four: "`ConflictError` subclasses". Each has a name of its own.
CONFLICT = "a ConflictError subclass"


@dataclass(frozen=True)
class Row:
    code: str
    decided_by: str
    #: ``None``: never an error answer, only the failure class of an operation.
    kind: str | None
    status: int | None
    retry_after: bool
    sdk_exception: str
    #: The retry advice the contract states for the code. ``None``: the host's own advice, checked against the host.
    retry: str | None


#: The table of failure classes on the public surface, in the order of the contract.
TABLE = [
    Row("INVALID_REQUEST", EITHER, REFUSED, 400, False, "InvalidRequestError", NEVER),
    Row("UNAUTHENTICATED", P, REFUSED, 401, False, "AuthenticationError", NEVER),
    Row("PERMISSION_DENIED", P, REFUSED, 403, False, "PermissionDeniedError", NEVER),
    Row("SAFETY_CONTROL_DENIED", H, REFUSED, 403, False, "SafetyControlDeniedError", None),
    Row("NOT_FOUND", EITHER, REFUSED, 404, False, "NotFoundError", NEVER),
    Row("STATE_CONFLICT", H, REFUSED, 409, False, CONFLICT, None),
    Row("QUARANTINED", H, REFUSED, 409, False, CONFLICT, None),
    Row("REVISION_CONFLICT", H, REFUSED, 412, False, "RevisionConflictError", None),
    Row("IDEMPOTENCY_CONFLICT", P, REFUSED, 422, False, "IdempotencyConflictError", NEVER),
    Row("REQUEST_IN_PROGRESS", P, UNRESOLVED, 409, True, "RequestInProgressError", LATER),
    Row("RATE_LIMITED", P, REFUSED, 429, True, "RateLimitError", LATER),
    Row("RESOURCE_EXHAUSTED", H, REFUSED, 503, True, "CapacityError", LATER),
    Row("HOST_NOT_SERVING", H, REFUSED, 503, True, "ServiceUnavailableError", LATER),
    Row("UNSUPPORTED", EITHER, REFUSED, 422, False, "UnsupportedFeatureError", None),
    Row("REQUEST_TOO_LARGE", P, REFUSED, 413, False, "InvalidRequestError", NEVER),
    Row("CURSOR_EXPIRED", H, REFUSED, 410, False, "CursorExpiredError", None),
    Row("INTEGRITY_FAILURE", H, REFUSED, 409, False, CONFLICT, None),
    Row("INCOMPATIBLE_RUNTIME", H, REFUSED, 409, False, CONFLICT, None),
    Row("CLOCK_SKEW", P, REFUSED, 503, True, "ServiceUnavailableError", LATER),
    Row("UPSTREAM_UNAVAILABLE", P, REFUSED, 503, True, "ServiceUnavailableError", LATER),
    Row("OUTCOME_UNRESOLVED", P, UNRESOLVED, 503, True, "OutcomeUnresolvedError", LATER),
    Row("OUTCOME_LOST", P, UNRESOLVED, 410, False, "OutcomeLostError", NEVER),
    Row("INTERNAL_ERROR", EITHER, REFUSED, 500, False, "InternalError", None),
    Row("TIMEOUT", H, None, None, False, "OperationFailedError", None),
    Row("DEPENDENCY_UNAVAILABLE", H, None, None, False, "OperationFailedError", None),
    Row("SECURITY_CONTROL_FAILURE", H, None, None, False, "OperationFailedError", None),
    Row("PARTIAL_COMPLETION", H, None, None, False, "OperationFailedError", None),
    Row("UNKNOWN_OUTCOME", H, None, None, False, "OutcomeUnknownError", None),
]
BY_CODE = {row.code: row for row in TABLE}
OPERATION_ONLY = [
    "TIMEOUT",
    "DEPENDENCY_UNAVAILABLE",
    "SECURITY_CONTROL_FAILURE",
    "PARTIAL_COMPLETION",
    "UNKNOWN_OUTCOME",
]
#: Host refusals that concern the platform's own identity or request. Faults of the platform, with no public name.
PLATFORM_FAULTS = ["AUTHENTICATION_FAILED", "AUTHORIZATION_DENIED", "PROTOCOL_ERROR"]


def host_classes() -> dict[str, dict[str, Any]]:
    host_api = json.loads(HOST_API.read_text(encoding="utf-8"))
    return {entry["class"]: entry for entry in host_api["failure_classes"]}


def registry() -> dict[str, Any]:
    loaded = yaml.safe_load(REGISTRY.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


# ------------------------------------------------------------------------------- the table
@pytest.mark.proves("T3-ERR-01")
def test_the_code_table_holds_the_rows_of_the_contract_and_the_one_code_for_what_is_unknown() -> None:
    assert len(TABLE) == len(BY_CODE) == 28
    assert {code.value for code in CODES} == {*BY_CODE, "UNRECOGNIZED"}
    assert {code.value for code in Code} == {code.value for code in CODES}
    assert all(code.name == code.value for code in Code)
    assert all(CODES[code].code is code for code in CODES)


@pytest.mark.proves("T3-ERR-01")
@pytest.mark.parametrize("row", TABLE, ids=lambda row: row.code)
def test_a_row_of_the_contract_is_the_row_of_the_code(row: Row) -> None:
    info = CODES[Code(row.code)]
    assert info.decided_by == row.decided_by
    assert (info.kind.value if info.kind is not None else None) == row.kind
    assert info.http_status == row.status
    assert info.retry_after is row.retry_after
    if row.sdk_exception == CONFLICT:
        assert re.fullmatch(r"[A-Z][A-Za-z]+Error", info.sdk_exception)
        assert info.sdk_exception not in {"ConflictError", "RefusedError"}
    else:
        assert info.sdk_exception == row.sdk_exception
    if row.retry is not None:
        assert info.retry.value == row.retry
    assert info.title
    assert info.title[0].isupper()
    assert not info.title.endswith(".")


@pytest.mark.proves("T3-ERR-01")
def test_the_four_conflict_classes_have_four_names() -> None:
    names = [CODES[Code(row.code)].sdk_exception for row in TABLE if row.sdk_exception == CONFLICT]
    assert len(names) == len(set(names)) == 4
    assert not set(names) & {row.sdk_exception for row in TABLE}


@pytest.mark.proves("T3-ERR-01")
def test_there_are_two_kinds_and_three_pieces_of_retry_advice() -> None:
    assert [kind.value for kind in Kind] == ["REFUSED", "UNRESOLVED"]
    assert [retry.value for retry in Retry] == ["SAME_REQUEST_LATER", "AFTER_CHANGE", "NEVER"]


@pytest.mark.proves("T3-ERR-01")
def test_exactly_three_codes_are_unresolved_and_each_is_decided_by_the_platform() -> None:
    """An answer says REFUSED only when nothing exists. Only the platform can be in doubt about its own request."""
    unresolved = {code.value for code, info in CODES.items() if info.kind is Kind.UNRESOLVED}
    assert unresolved == {"REQUEST_IN_PROGRESS", "OUTCOME_UNRESOLVED", "OUTCOME_LOST"}
    for code in unresolved:
        assert CODES[Code(code)].decided_by == P
    # Two are resolved by asking again with the same key. The third never is: the caller inspects the target.
    assert CODES[Code.REQUEST_IN_PROGRESS].retry is Retry.SAME_REQUEST_LATER
    assert CODES[Code.OUTCOME_UNRESOLVED].retry is Retry.SAME_REQUEST_LATER
    assert CODES[Code.OUTCOME_LOST].retry is Retry.NEVER
    assert CODES[Code.OUTCOME_LOST].retry_after is False


@pytest.mark.proves("T3-ERR-01")
def test_retry_after_is_sent_exactly_with_the_codes_that_say_later() -> None:
    for code, info in CODES.items():
        if info.kind is None or code is Code.UNRECOGNIZED:
            continue
        assert info.retry_after is (info.retry is Retry.SAME_REQUEST_LATER), code
        if info.retry_after:
            assert info.http_status in {409, 429, 503}, code
    later = {
        code.value for code, info in CODES.items() if info.kind is not None and info.retry is Retry.SAME_REQUEST_LATER
    }
    assert later == {
        "REQUEST_IN_PROGRESS",
        "RATE_LIMITED",
        "RESOURCE_EXHAUSTED",
        "HOST_NOT_SERVING",
        "CLOCK_SKEW",
        "UPSTREAM_UNAVAILABLE",
        "OUTCOME_UNRESOLVED",
    }


@pytest.mark.proves("T3-ERR-01")
def test_a_status_is_shared_by_codes_that_mean_different_things() -> None:
    """Why `code` is authoritative: 409 is a state conflict to change and a request in progress to repeat."""
    by_status: dict[int, set[str]] = {}
    for code, info in CODES.items():
        if info.http_status is not None:
            by_status.setdefault(info.http_status, set()).add(code.value)
    assert by_status == {
        400: {"INVALID_REQUEST"},
        401: {"UNAUTHENTICATED"},
        403: {"PERMISSION_DENIED", "SAFETY_CONTROL_DENIED"},
        404: {"NOT_FOUND"},
        409: {"STATE_CONFLICT", "QUARANTINED", "REQUEST_IN_PROGRESS", "INTEGRITY_FAILURE", "INCOMPATIBLE_RUNTIME"},
        410: {"CURSOR_EXPIRED", "OUTCOME_LOST"},
        412: {"REVISION_CONFLICT"},
        413: {"REQUEST_TOO_LARGE"},
        422: {"IDEMPOTENCY_CONFLICT", "UNSUPPORTED"},
        429: {"RATE_LIMITED"},
        500: {"INTERNAL_ERROR"},
        503: {"RESOURCE_EXHAUSTED", "HOST_NOT_SERVING", "CLOCK_SKEW", "UPSTREAM_UNAVAILABLE", "OUTCOME_UNRESOLVED"},
    }
    kinds_of_409 = {CODES[Code(code)].kind for code in by_status[409]}
    assert kinds_of_409 == {Kind.REFUSED, Kind.UNRESOLVED}


# ------------------------------------------------------------------------------- classes that only end an operation
@pytest.mark.proves("T3-ERR-01")
@pytest.mark.parametrize("code", OPERATION_ONLY)
def test_a_class_that_only_ends_an_operation_is_never_an_error_answer(code: str) -> None:
    """An accepted request never produces an error answer: its outcome is the operation's, with status 200."""
    info = CODES[Code(code)]
    assert info.kind is None
    assert info.http_status is None
    assert info.retry_after is False
    assert info.decided_by == H
    assert Code(code) not in e.error_codes()
    assert Code(code) in e.operation_failure_codes()
    assert info.sdk_exception in {"OperationFailedError", "OutcomeUnknownError"}


@pytest.mark.proves("T3-ERR-01")
def test_the_two_lists_of_codes_divide_the_table_as_the_contract_does() -> None:
    answers, failures = set(e.error_codes()), set(e.operation_failure_codes())
    assert {code.value for code in CODES if code not in answers} == set(OPERATION_ONLY)
    # The failure class of an operation is always the host's: no code the platform alone decides is one.
    assert not {code.value for code in failures if CODES[code].decided_by == P}
    assert {code.value for code in CODES if CODES[code].decided_by in {H, EITHER}} == {code.value for code in failures}
    assert CODES[Code.UNKNOWN_OUTCOME].sdk_exception == "OutcomeUnknownError", "UNKNOWN is never shown as a failure"
    assert {CODES[Code(code)].sdk_exception for code in OPERATION_ONLY if code != "UNKNOWN_OUTCOME"} == {
        "OperationFailedError"
    }


# ------------------------------------------------------------------------------- against the host's own contract
@pytest.mark.proves("T3-ERR-01")
def test_every_failure_class_of_the_host_is_accounted_for() -> None:
    """Each host class keeps its name on the public surface, or is one of the five the contract handles by a rule."""
    host = host_classes()
    assert len(host) == 23
    public = {name for name in host if name in Code.__members__ and CODES[Code(name)].decided_by in {H, EITHER}}
    by_rule = {"EXPIRED_REQUEST", "IDEMPOTENCY_CONFLICT"}
    assert public | set(PLATFORM_FAULTS) | by_rule == set(host)
    assert not public & set(PLATFORM_FAULTS)
    assert not public & by_rule
    # The platform invents no host class: every code it says the host decides is a class of the host.
    assert {
        code.value for code, info in CODES.items() if info.decided_by in {H, EITHER} and code is not Code.UNRECOGNIZED
    } == public


@pytest.mark.proves("T3-ERR-01")
def test_a_class_the_host_decides_keeps_the_hosts_retry_advice() -> None:
    host = host_classes()
    for code, info in CODES.items():
        if info.decided_by in {H, EITHER} and code is not Code.UNRECOGNIZED:
            assert info.retry.value == host[code.value]["retry"], code
    assert {entry["retry"] for entry in host.values()} == {retry.value for retry in Retry}


@pytest.mark.proves("T3-ERR-01")
def test_the_classes_the_host_never_refuses_with_are_the_ones_that_are_never_an_error_answer() -> None:
    host = host_classes()
    never_refuses = {name for name, entry in host.items() if not entry["may_refuse"]}
    assert never_refuses == set(OPERATION_ONLY)
    assert {name for name in never_refuses if CODES[Code(name)].kind is None} == never_refuses
    for name, entry in host.items():
        if entry["may_fail_operation"] and name in Code.__members__:
            assert Code(name) in e.operation_failure_codes(), name


@pytest.mark.proves("T3-ERR-01")
@pytest.mark.parametrize("fault", [*PLATFORM_FAULTS, "EXPIRED_REQUEST"])
def test_a_refusal_of_the_platform_itself_has_no_public_name(fault: str) -> None:
    """ERR-5: such a refusal is the platform's fault, answered UPSTREAM_UNAVAILABLE. It can never be the caller's 401 or 403."""
    assert fault in host_classes()
    assert fault not in Code.__members__
    assert fault not in {code.value for code in Code}
    upstream = CODES[Code.UPSTREAM_UNAVAILABLE]
    assert (upstream.kind, upstream.retry, upstream.http_status, upstream.retry_after) == (
        Kind.REFUSED,
        Retry.SAME_REQUEST_LATER,
        503,
        True,
    )
    # The caller's own two are decided by the platform alone, so no host refusal can be passed on as one.
    assert CODES[Code.UNAUTHENTICATED].decided_by == P
    assert CODES[Code.PERMISSION_DENIED].decided_by == P


@pytest.mark.proves("T3-ERR-01")
def test_the_hosts_conflict_on_an_operation_id_is_not_the_public_conflict() -> None:
    """The public IDEMPOTENCY_CONFLICT is the platform's: same key, different request. The host's never reaches a caller."""
    assert host_classes()["IDEMPOTENCY_CONFLICT"]["may_refuse"] is True
    assert CODES[Code.IDEMPOTENCY_CONFLICT].decided_by == P


# ------------------------------------------------------------------------------- the HTTP status
@pytest.mark.proves("T3-ERR-01")
@pytest.mark.parametrize("row", [row for row in TABLE if row.status is not None], ids=lambda row: row.code)
def test_the_status_of_a_known_code_is_the_contracts_whatever_the_retry_advice_is(row: Row) -> None:
    for retry in ("SAME_REQUEST_LATER", "AFTER_CHANGE", "NEVER", "", "SOMETHING_NEW"):
        assert e.http_status(row.code, retry) == row.status


@pytest.mark.proves("T3-ERR-01")
@pytest.mark.parametrize(
    "code", ["UNRECOGNIZED", "FUTURE_REFUSAL", "", "invalid_request", "INVALID_REQUEST ", *OPERATION_ONLY]
)
def test_the_status_of_a_code_without_one_follows_from_its_retry_advice(code: str) -> None:
    """All that is known of such a refusal is its kind and its advice. The status says as much and no more."""
    assert e.http_status(code, "NEVER") == 400
    assert e.http_status(code, "AFTER_CHANGE") == 409
    assert e.http_status(code, "SAME_REQUEST_LATER") == 503
    assert e.http_status(code, "SOMETHING_NEW") == 400
    assert e.http_status(code, "") == 400


@pytest.mark.proves("T3-ERR-01")
@given(st.text(max_size=40), st.text(max_size=40))
def test_an_error_answer_never_gets_a_status_of_success(code: str, retry: str) -> None:
    status = e.http_status(code, retry)
    assert 400 <= status <= 599
    if code not in Code.__members__ and retry == "SAME_REQUEST_LATER":
        assert status == 503


# ------------------------------------------------------------------------------- the problem type
URN = re.compile(r"^urn:[a-z0-9][a-z0-9-]{0,31}:[a-z0-9()+,\-.:=@;$_!*'%/?#]+$")


@pytest.mark.proves("T3-ERR-01")
def test_the_problem_type_of_a_code_is_a_urn() -> None:
    """A URN: nothing is dereferenced, and no domain has to be owned for it."""
    types = {code: e.problem_type(code.value) for code in Code}
    assert len(set(types.values())) == len(types)
    for code, problem_type in types.items():
        assert URN.fullmatch(problem_type), problem_type
        assert problem_type == "urn:acf:problem:" + code.value.lower().replace("_", "-")
        assert "://" not in problem_type
        assert "." not in problem_type
    assert e.problem_type("INVALID_REQUEST") == "urn:acf:problem:invalid-request"
    assert e.problem_type("FUTURE_REFUSAL") == "urn:acf:problem:future-refusal"
    assert e.PROBLEM_TYPE_PREFIX == "urn:acf:problem:"


# ------------------------------------------------------------------------------- what an error answer carries
@pytest.mark.proves("T3-ERR-01")
def test_an_error_answer_carries_the_members_the_contract_lists() -> None:
    """ERR-6: code, kind, retry, a message, the request id, and for UNRESOLVED the idempotency key to ask again with."""
    assert {"code", "kind", "retry", "message", "request_id", "idempotency_key"} <= set(m.ErrorBody.model_fields)
    for required in ("code", "kind", "retry", "message", "request_id"):
        assert m.ErrorBody.model_fields[required].is_required(), required
    assert not m.ErrorBody.model_fields["idempotency_key"].is_required()
    # The REST encoding is an RFC 9457 problem document with those as extension members.
    assert set(m.Problem.model_fields) - set(m.ErrorBody.model_fields) == {
        "type",
        "title",
        "status",
        "detail",
        "instance",
    }
    body = m.ErrorBody(
        code="OUTCOME_UNRESOLVED",
        kind="UNRESOLVED",
        retry="SAME_REQUEST_LATER",
        message="x",
        request_id="req_1",
        idempotency_key="k",
    )
    assert body.model_dump(exclude_none=True) == {
        "code": "OUTCOME_UNRESOLVED",
        "kind": "UNRESOLVED",
        "retry": "SAME_REQUEST_LATER",
        "message": "x",
        "request_id": "req_1",
        "idempotency_key": "k",
    }


# ------------------------------------------------------------------------------- the generated registry
@pytest.mark.proves("T3-ERR-01", "T3-API-01")
def test_the_problem_registry_is_the_table() -> None:
    document = registry()
    assert document["schema_version"] == 1
    assert set(document["kinds"]) == {"REFUSED", "UNRESOLVED"}
    assert set(document["retry"]) == {"SAME_REQUEST_LATER", "AFTER_CHANGE", "NEVER"}
    entries = {entry["code"]: entry for entry in document["codes"]}
    assert len(entries) == len(document["codes"]), "a code is listed twice"
    assert set(entries) == {*BY_CODE, "UNRECOGNIZED"}
    for row in TABLE:
        entry = entries[row.code]
        assert entry["decided_by"] == row.decided_by, row.code
        assert entry["kind"] == row.kind, row.code
        assert entry["http_status"] == row.status, row.code
        assert entry["retry_after"] is row.retry_after, row.code
        assert entry["error_answer"] is (row.kind is not None), row.code
        if row.sdk_exception != CONFLICT:
            assert entry["sdk_exception"] == row.sdk_exception, row.code
        if row.retry is not None:
            assert entry["retry"] == row.retry, row.code
        assert set(entry) == {
            "code",
            "type",
            "title",
            "decided_by",
            "kind",
            "retry",
            "http_status",
            "retry_after",
            "sdk_exception",
            "error_answer",
        }


@pytest.mark.proves("T3-ERR-01", "T3-API-01")
def test_the_problem_registry_is_what_the_code_table_says() -> None:
    entries = {entry["code"]: entry for entry in registry()["codes"]}
    for code, info in CODES.items():
        entry = entries[code.value]
        assert entry == {
            "code": code.value,
            "type": e.problem_type(code.value),
            "title": info.title,
            "decided_by": info.decided_by,
            "kind": info.kind.value if info.kind is not None else None,
            "retry": info.retry.value,
            "http_status": info.http_status,
            "retry_after": info.retry_after,
            "sdk_exception": info.sdk_exception,
            "error_answer": info.kind is not None,
        }
        assert URN.fullmatch(entry["type"])


@pytest.mark.proves("T3-ERR-01")
def test_a_class_the_table_does_not_hold_is_handled_by_its_kind_and_its_retry_advice() -> None:
    """A host class this version does not know is UNRECOGNIZED: a refusal, with no status of its own."""
    unknown = CODES[Code.UNRECOGNIZED]
    assert unknown.kind is Kind.REFUSED
    assert unknown.http_status is None
    assert unknown.retry is Retry.NEVER, "not retried unless the answer itself says so"
    assert unknown.retry_after is False
    assert Code.UNRECOGNIZED.value == m.UNRECOGNIZED
    assert Code.UNRECOGNIZED in e.error_codes()
