"""The public failure vocabulary: codes, the two kinds of unsuccessful answer, and retry advice.

Every unsuccessful answer of the public surface is one of two kinds and says which:

* ``REFUSED``: the request was not accepted. Nothing exists on the host: no operation, no reservation.
* ``UNRESOLVED``: the platform could not establish whether the request was accepted. An operation may
  exist. The caller asks again with the same idempotency key, never with a new one.

The ``code`` is authoritative. The HTTP status is a coarse hint that the REST adapter derives from this
table, and no client decides from it alone.

This module is the single definition of the table. The REST adapter, the agent interface, the problem
registry under ``protocols/api/problems`` and both SDKs are checked against it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final


class Kind(StrEnum):
    """Which of the two kinds an unsuccessful answer is."""

    REFUSED = "REFUSED"
    UNRESOLVED = "UNRESOLVED"


class Retry(StrEnum):
    """What a caller may do after an unsuccessful answer."""

    SAME_REQUEST_LATER = "SAME_REQUEST_LATER"
    AFTER_CHANGE = "AFTER_CHANGE"
    NEVER = "NEVER"


class Code(StrEnum):
    """Every code an error answer or an operation failure can carry on the public surface."""

    # Decided by the platform, or by the host with the same name and meaning.
    INVALID_REQUEST = "INVALID_REQUEST"
    UNAUTHENTICATED = "UNAUTHENTICATED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    NOT_FOUND = "NOT_FOUND"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    REQUEST_IN_PROGRESS = "REQUEST_IN_PROGRESS"
    RATE_LIMITED = "RATE_LIMITED"
    UNSUPPORTED = "UNSUPPORTED"
    REQUEST_TOO_LARGE = "REQUEST_TOO_LARGE"
    CLOCK_SKEW = "CLOCK_SKEW"
    UPSTREAM_UNAVAILABLE = "UPSTREAM_UNAVAILABLE"
    OUTCOME_UNRESOLVED = "OUTCOME_UNRESOLVED"
    OUTCOME_LOST = "OUTCOME_LOST"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    # Decided by the host only. The name and the meaning are the host's.
    SAFETY_CONTROL_DENIED = "SAFETY_CONTROL_DENIED"
    STATE_CONFLICT = "STATE_CONFLICT"
    QUARANTINED = "QUARANTINED"
    REVISION_CONFLICT = "REVISION_CONFLICT"
    RESOURCE_EXHAUSTED = "RESOURCE_EXHAUSTED"
    HOST_NOT_SERVING = "HOST_NOT_SERVING"
    CURSOR_EXPIRED = "CURSOR_EXPIRED"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
    INCOMPATIBLE_RUNTIME = "INCOMPATIBLE_RUNTIME"
    # Host classes that only ever end an operation. They are never the code of an error answer.
    TIMEOUT = "TIMEOUT"
    DEPENDENCY_UNAVAILABLE = "DEPENDENCY_UNAVAILABLE"
    SECURITY_CONTROL_FAILURE = "SECURITY_CONTROL_FAILURE"
    PARTIAL_COMPLETION = "PARTIAL_COMPLETION"
    UNKNOWN_OUTCOME = "UNKNOWN_OUTCOME"
    # A host class this version's mapping table does not hold. Handled by its kind and its retry advice.
    UNRECOGNIZED = "UNRECOGNIZED"


@dataclass(frozen=True, slots=True)
class CodeInfo:
    """One row of the failure table."""

    code: Code
    #: ``platform``, ``host`` or ``either``.
    decided_by: str
    #: The kind of an error answer with this code. ``None``: the code never appears in an error answer.
    kind: Kind | None
    #: The retry advice when the platform decides. A host refusal carries the host's own advice.
    retry: Retry
    #: The HTTP status the REST adapter uses. ``None`` for a code that is never an error answer.
    http_status: int | None
    #: Whether the answer carries ``Retry-After``.
    retry_after: bool
    title: str
    #: Name of the exception both SDKs raise for it.
    sdk_exception: str


def _row(
    code: Code,
    decided_by: str,
    kind: Kind | None,
    retry: Retry,
    http_status: int | None,
    title: str,
    sdk_exception: str,
    *,
    retry_after: bool = False,
) -> tuple[Code, CodeInfo]:
    return code, CodeInfo(code, decided_by, kind, retry, http_status, retry_after, title, sdk_exception)


CODES: Final[dict[Code, CodeInfo]] = dict(
    [
        _row(Code.INVALID_REQUEST, "either", Kind.REFUSED, Retry.NEVER, 400, "Invalid request", "InvalidRequestError"),
        _row(
            Code.UNAUTHENTICATED, "platform", Kind.REFUSED, Retry.NEVER, 401, "Unauthenticated", "AuthenticationError"
        ),
        _row(
            Code.PERMISSION_DENIED,
            "platform",
            Kind.REFUSED,
            Retry.NEVER,
            403,
            "Permission denied",
            "PermissionDeniedError",
        ),
        _row(
            Code.SAFETY_CONTROL_DENIED,
            "host",
            Kind.REFUSED,
            Retry.AFTER_CHANGE,
            403,
            "Denied by the host safety profile",
            "SafetyControlDeniedError",
        ),
        _row(Code.NOT_FOUND, "either", Kind.REFUSED, Retry.NEVER, 404, "Not found", "NotFoundError"),
        _row(
            Code.STATE_CONFLICT, "host", Kind.REFUSED, Retry.AFTER_CHANGE, 409, "State conflict", "StateConflictError"
        ),
        _row(Code.QUARANTINED, "host", Kind.REFUSED, Retry.AFTER_CHANGE, 409, "Quarantined", "QuarantinedError"),
        _row(
            Code.REVISION_CONFLICT,
            "host",
            Kind.REFUSED,
            Retry.AFTER_CHANGE,
            412,
            "Revision conflict",
            "RevisionConflictError",
        ),
        _row(
            Code.IDEMPOTENCY_CONFLICT,
            "platform",
            Kind.REFUSED,
            Retry.NEVER,
            422,
            "Idempotency key reused for a different request",
            "IdempotencyConflictError",
        ),
        _row(
            Code.REQUEST_IN_PROGRESS,
            "platform",
            Kind.UNRESOLVED,
            Retry.SAME_REQUEST_LATER,
            409,
            "An earlier request with this idempotency key is still being decided",
            "RequestInProgressError",
            retry_after=True,
        ),
        _row(
            Code.RATE_LIMITED,
            "platform",
            Kind.REFUSED,
            Retry.SAME_REQUEST_LATER,
            429,
            "Rate limited",
            "RateLimitError",
            retry_after=True,
        ),
        _row(
            Code.RESOURCE_EXHAUSTED,
            "host",
            Kind.REFUSED,
            Retry.SAME_REQUEST_LATER,
            503,
            "The host has no capacity for this request",
            "CapacityError",
            retry_after=True,
        ),
        _row(
            Code.HOST_NOT_SERVING,
            "host",
            Kind.REFUSED,
            Retry.SAME_REQUEST_LATER,
            503,
            "The host is not serving this kind of request",
            "ServiceUnavailableError",
            retry_after=True,
        ),
        _row(
            Code.UNSUPPORTED, "either", Kind.REFUSED, Retry.AFTER_CHANGE, 422, "Unsupported", "UnsupportedFeatureError"
        ),
        _row(
            Code.REQUEST_TOO_LARGE,
            "platform",
            Kind.REFUSED,
            Retry.NEVER,
            413,
            "Request too large",
            "InvalidRequestError",
        ),
        _row(
            Code.CURSOR_EXPIRED, "host", Kind.REFUSED, Retry.AFTER_CHANGE, 410, "Cursor expired", "CursorExpiredError"
        ),
        _row(
            Code.INTEGRITY_FAILURE,
            "host",
            Kind.REFUSED,
            Retry.AFTER_CHANGE,
            409,
            "Integrity failure",
            "IntegrityFailureError",
        ),
        _row(
            Code.INCOMPATIBLE_RUNTIME,
            "host",
            Kind.REFUSED,
            Retry.AFTER_CHANGE,
            409,
            "Incompatible runtime",
            "IncompatibleRuntimeError",
        ),
        _row(
            Code.CLOCK_SKEW,
            "platform",
            Kind.REFUSED,
            Retry.SAME_REQUEST_LATER,
            503,
            "The platform's clock and the host's differ beyond tolerance",
            "ServiceUnavailableError",
            retry_after=True,
        ),
        _row(
            Code.UPSTREAM_UNAVAILABLE,
            "platform",
            Kind.REFUSED,
            Retry.SAME_REQUEST_LATER,
            503,
            "A dependency of the platform is unavailable; nothing was sent",
            "ServiceUnavailableError",
            retry_after=True,
        ),
        _row(
            Code.OUTCOME_UNRESOLVED,
            "platform",
            Kind.UNRESOLVED,
            Retry.SAME_REQUEST_LATER,
            503,
            "The outcome of the request could not be established",
            "OutcomeUnresolvedError",
            retry_after=True,
        ),
        _row(
            Code.OUTCOME_LOST,
            "platform",
            Kind.UNRESOLVED,
            Retry.NEVER,
            410,
            "The outcome of the request is lost; inspect the target before acting again",
            "OutcomeLostError",
        ),
        _row(Code.INTERNAL_ERROR, "either", Kind.REFUSED, Retry.AFTER_CHANGE, 500, "Internal error", "InternalError"),
        _row(Code.TIMEOUT, "host", None, Retry.SAME_REQUEST_LATER, None, "Timed out", "OperationFailedError"),
        _row(
            Code.DEPENDENCY_UNAVAILABLE,
            "host",
            None,
            Retry.SAME_REQUEST_LATER,
            None,
            "A dependency of the host was unavailable",
            "OperationFailedError",
        ),
        _row(
            Code.SECURITY_CONTROL_FAILURE,
            "host",
            None,
            Retry.AFTER_CHANGE,
            None,
            "A security control could not be confirmed",
            "OperationFailedError",
        ),
        _row(
            Code.PARTIAL_COMPLETION,
            "host",
            None,
            Retry.AFTER_CHANGE,
            None,
            "The operation completed in part",
            "OperationFailedError",
        ),
        _row(
            Code.UNKNOWN_OUTCOME,
            "host",
            None,
            Retry.AFTER_CHANGE,
            None,
            "The outcome of the operation is unknown",
            "OutcomeUnknownError",
        ),
        _row(
            Code.UNRECOGNIZED,
            "host",
            Kind.REFUSED,
            Retry.NEVER,
            None,
            "A failure class this version does not know",
            "RefusedError",
        ),
    ]
)

#: HTTP status of an ``UNRECOGNIZED`` refusal, chosen from the only thing known about it: its retry advice.
_UNRECOGNIZED_STATUS: Final[dict[Retry, int]] = {
    Retry.NEVER: 400,
    Retry.AFTER_CHANGE: 409,
    Retry.SAME_REQUEST_LATER: 503,
}

PROBLEM_TYPE_PREFIX: Final = "urn:acf:problem:"


def problem_type(code: str) -> str:
    """The RFC 9457 ``type`` of a code. A URN: nothing is dereferenced, and no domain has to be owned."""
    return PROBLEM_TYPE_PREFIX + code.lower().replace("_", "-")


def http_status(code: str, retry: str) -> int:
    """The HTTP status for an error answer. A hint only; ``code`` decides."""
    try:
        info = CODES[Code(code)]
    except ValueError:
        info = CODES[Code.UNRECOGNIZED]
    if info.http_status is not None:
        return info.http_status
    try:
        return _UNRECOGNIZED_STATUS[Retry(retry)]
    except ValueError:
        return 400


def error_codes() -> tuple[Code, ...]:
    """Codes that can be the ``code`` of an error answer."""
    return tuple(c for c, info in CODES.items() if info.kind is not None)


def operation_failure_codes() -> tuple[Code, ...]:
    """Codes that can be the failure class of an operation that ended without success."""
    host = {c for c, info in CODES.items() if info.decided_by in {"host", "either"}}
    return tuple(c for c in CODES if c in host)
