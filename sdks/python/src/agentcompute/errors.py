"""Everything this package raises on purpose.

The hierarchy keeps apart the outcomes a caller must treat differently:

* the platform **refused** the request: nothing exists (:class:`RefusedError`);
* the platform could **not establish** whether the request was accepted: an operation may exist, and the
  same idempotency key resolves it (:class:`UnresolvedError`);
* an operation was accepted and **ended without success**, cleanly (:class:`OperationFailedError`) or in
  a way that may have been applied (:class:`OutcomeUnknownError`, which is neither success nor failure);
* an operation was accepted and has **not ended** yet (:class:`OperationStillRunningError`);
* the server could **not be reached**, or answered something that is not this API.

A refused argument (a size without a unit, an idempotency key with a space, a string where an argument
vector is required) is a plain :class:`ValueError`, raised before any request is made.

No message, ``repr`` or argument of these exceptions ever holds a credential.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final, Literal

if TYPE_CHECKING:
    from agentcompute.types import Operation

__all__ = [
    "APIConnectionError",
    "APIError",
    "APITimeoutError",
    "AuthenticationError",
    "CapacityError",
    "ConfigurationError",
    "ConflictError",
    "CursorExpiredError",
    "FabricError",
    "IdempotencyConflictError",
    "IncompatibleRuntimeError",
    "IncompatibleServerError",
    "IntegrityFailureError",
    "InternalError",
    "InvalidRequestError",
    "NameReboundError",
    "NotFoundError",
    "OperationError",
    "OperationFailedError",
    "OperationStillRunningError",
    "OutcomeLostError",
    "OutcomeUnknownError",
    "OutcomeUnresolvedError",
    "PermissionDeniedError",
    "QuarantinedError",
    "RateLimitError",
    "RefusedError",
    "RequestInProgressError",
    "RevisionConflictError",
    "SafetyControlDeniedError",
    "SandboxStartError",
    "ServiceUnavailableError",
    "StateConflictError",
    "UnexpectedResponseError",
    "UnresolvedError",
    "UnsupportedFeatureError",
]

KIND_REFUSED: Final = "REFUSED"
KIND_UNRESOLVED: Final = "UNRESOLVED"
RETRY_SAME_REQUEST_LATER: Final = "SAME_REQUEST_LATER"
RETRY_AFTER_CHANGE: Final = "AFTER_CHANGE"
RETRY_NEVER: Final = "NEVER"


class FabricError(Exception):
    """Base of every error of this package."""

    #: Identifier of the request the error belongs to, when an answer carried one. Quote it when asking for help.
    request_id: str | None = None

    def __reduce__(self) -> tuple[Any, ...]:
        # An exception is pickled when it crosses to another process. The default way calls the
        # constructor with the positional arguments alone, and these constructors take keywords.
        return _restore, (type(self), self.args, dict(vars(self)))


def _restore(kind: type[FabricError], args: tuple[object, ...], state: dict[str, object]) -> FabricError:
    """Rebuild an error from its pickled parts, without calling its constructor."""
    error = kind.__new__(kind)
    error.args = args
    vars(error).update(state)
    return error


class ConfigurationError(FabricError):
    """The client cannot be built, or cannot talk to this server, as configured. No request was made."""


class IncompatibleServerError(ConfigurationError):
    """The server at the base URL does not speak version ``v1`` of the public API.

    Raised when a ``/v1`` route answers 404 without a problem document: whatever is listening there is
    not this API. The base URL is what has to change, so this is a configuration error.
    """

    def __init__(self, message: str, *, status: int, request_id: str | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.request_id = request_id


class APIConnectionError(FabricError):
    """The server was not reached, or a request that carries no idempotency key was not answered.

    Nothing can be said about the server's state from this error alone. It is never raised for a
    mutation under an idempotency key: that one ends as :class:`OutcomeUnresolvedError`, because its
    key can settle later what this error cannot.
    """


class APITimeoutError(APIConnectionError):
    """The same, and the last attempt ended because the per-request timeout passed."""


class UnexpectedResponseError(FabricError):
    """The server answered, and the answer is neither a view nor a problem document of this API."""

    def __init__(self, message: str, *, status: int | None = None, request_id: str | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.request_id = request_id


class APIError(FabricError):
    """An error answer: a problem document with ``code``, ``kind`` and ``retry``.

    ``code`` is authoritative and ``status`` is only a hint. ``kind`` says whether anything can exist
    (``REFUSED``: nothing; ``UNRESOLVED``: possibly an operation). ``retry`` is the server's advice:
    ``SAME_REQUEST_LATER``, ``AFTER_CHANGE`` or ``NEVER``. Every one of them is a plain string, and a
    value this version has never seen is kept as it came.
    """

    def __init__(
        self,
        message: str,
        *,
        code: str,
        kind: str,
        retry: str,
        status: int | None = None,
        request_id: str | None = None,
        idempotency_key: str | None = None,
        reason: str | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(_describe(code, message, request_id))
        #: The server's human-readable message. It never repeats request content and is never parsed.
        self.message = message
        self.code = code
        self.kind = kind
        self.retry = retry
        #: HTTP status of the answer. ``None`` when the client itself established the error.
        self.status = status
        self.request_id = request_id
        #: The key of the call. Ask again with it, unchanged, to resolve or to repeat the same request.
        self.idempotency_key = idempotency_key
        #: A bounded word that refines ``code``, for example ``quota``.
        self.reason = reason
        #: Seconds the server asked the caller to wait before asking again, when it said so.
        self.retry_after = retry_after


def _describe(code: str, message: str, request_id: str | None) -> str:
    text = f"{code}: {message}" if message else code
    return f"{text} (request {request_id})" if request_id else text


class RefusedError(APIError):
    """``REFUSED``: the request was not accepted, and nothing exists because of it.

    Also raised as it is for a code this version does not know, unless the answer says ``UNRESOLVED``.
    """


class InvalidRequestError(RefusedError):
    """``INVALID_REQUEST`` or ``REQUEST_TOO_LARGE``: the request is malformed or too large."""


class AuthenticationError(RefusedError):
    """``UNAUTHENTICATED``: the credential is missing, invalid, expired or revoked."""


class PermissionDeniedError(RefusedError):
    """``PERMISSION_DENIED``: the credential's grants do not allow this, or a quota is reached."""


class SafetyControlDeniedError(RefusedError):
    """``SAFETY_CONTROL_DENIED``: the host's safety profile does not allow this."""


class NotFoundError(RefusedError):
    """``NOT_FOUND``: no such record in this project."""


class RevisionConflictError(RefusedError):
    """``REVISION_CONFLICT``: the sandbox is not at the generation the request stated.

    Refresh the handle, look at what changed, and decide whether to ask again.
    """


class IdempotencyConflictError(RefusedError):
    """``IDEMPOTENCY_CONFLICT``: the key was already used for a different request.

    The key belongs to that other request. This package never tries another key for the same call.
    """


class RateLimitError(RefusedError):
    """``RATE_LIMITED``: too many requests. ``retry_after`` says when to ask again."""


class CapacityError(RefusedError):
    """``RESOURCE_EXHAUSTED``: the host has no capacity for this request now."""


class ServiceUnavailableError(RefusedError):
    """``HOST_NOT_SERVING``, ``CLOCK_SKEW`` or ``UPSTREAM_UNAVAILABLE``: nothing was sent to the host."""


class UnsupportedFeatureError(RefusedError):
    """``UNSUPPORTED``: the platform or the host does not offer what the request asks for."""


class CursorExpiredError(RefusedError):
    """``CURSOR_EXPIRED``: the position of a listing is no longer valid. List again from the start."""


class InternalError(RefusedError):
    """``INTERNAL_ERROR``: a fault of the platform or of the host, and nothing was sent on."""


class ConflictError(RefusedError):
    """The record is in a condition that does not allow the request."""


class StateConflictError(ConflictError):
    """``STATE_CONFLICT``: the state of the record does not allow the request."""


class QuarantinedError(ConflictError):
    """``QUARANTINED``: the host has quarantined the record."""


class IntegrityFailureError(ConflictError):
    """``INTEGRITY_FAILURE``: stored data failed its integrity check."""


class IncompatibleRuntimeError(ConflictError):
    """``INCOMPATIBLE_RUNTIME``: the snapshot cannot run on this host."""


class UnresolvedError(APIError):
    """``UNRESOLVED``: the platform could not establish whether the request was accepted.

    An operation may exist. ``idempotency_key`` is the key to ask again with. A new key is never the
    way out: it could create a second operation.
    """


class RequestInProgressError(UnresolvedError):
    """``REQUEST_IN_PROGRESS``: an earlier request with this key is still being decided."""


class OutcomeUnresolvedError(UnresolvedError):
    """``OUTCOME_UNRESOLVED``: whether the request was accepted is not known yet.

    The server says so itself, or the client says it for a mutation that was sent and never answered.
    Ask again later with ``idempotency_key``, with the same arguments.
    """


class OutcomeLostError(UnresolvedError):
    """``OUTCOME_LOST``: the platform accepted the key and can no longer tell what became of it.

    It is never retried, with this key or with another. Inspect the target before acting again.
    """


class OperationError(FabricError):
    """An operation was accepted, and the call cannot return its result."""

    def __init__(self, message: str, *, operation: Operation, idempotency_key: str | None) -> None:
        super().__init__(message)
        #: The operation as the server last showed it.
        self.operation = operation
        self.operation_id = operation.operation_id
        #: The key of the call that created the operation. ``None`` when the call followed an existing one.
        self.idempotency_key = idempotency_key
        self.request_id = operation.request_id
        failure = operation.failure
        #: The failure class the host gave the operation, when it gave one.
        self.code: str | None = failure.code if failure is not None else None


class OperationFailedError(OperationError):
    """The operation ended ``FAILED`` or ``CANCELLED``, and nothing was applied.

    Because nothing was applied, the same intent may be submitted again as a new call.
    """


class OutcomeUnknownError(OperationError):
    """The operation ended ``UNKNOWN``, or ended without success and may have been applied.

    This is neither success nor failure. Inspect the target before deciding what to do next.
    """


class OperationStillRunningError(OperationError):
    """The follow bound passed and the operation has not ended. Nothing is assumed, nothing is cancelled.

    Follow it later by ``operation_id``, or make the same call again with ``idempotency_key``.
    """


class SandboxStartError(FabricError):
    """``sandboxes.create()`` created the sandbox, and its start was refused or ended without success.

    ``cleanup`` says what became of the sandbox: ``"destroyed"``, ``"kept"`` (the caller asked for
    that), or ``"destroy_failed"``, in which case ``destroy_error`` says why and the sandbox may still
    exist until its lifetime ends.
    """

    def __init__(
        self,
        message: str,
        *,
        sandbox_id: str,
        start_error: APIError | OperationError,
        cleanup: Literal["destroyed", "kept", "destroy_failed"],
        destroy_error: FabricError | None = None,
    ) -> None:
        super().__init__(message)
        self.sandbox_id = sandbox_id
        self.start_error = start_error
        self.cleanup = cleanup
        self.destroy_error = destroy_error
        #: The code of the start failure: of the refusal, or of the operation that ended without success.
        self.code: str | None = start_error.code
        self.request_id = start_error.request_id


class NameReboundError(FabricError):
    """The name a handle was obtained by now belongs to another sandbox.

    The handle still acts on the sandbox it resolved, by identifier. Pass ``rebind=True`` to
    ``refresh()`` to move the handle to the sandbox that holds the name now.
    """

    def __init__(self, message: str, *, name: str, sandbox_id: str, rebound_to: str) -> None:
        super().__init__(message)
        self.name = name
        #: The sandbox the handle acts on.
        self.sandbox_id = sandbox_id
        #: The sandbox the name belongs to now.
        self.rebound_to = rebound_to


#: The exception of every code that an error answer can carry, as the problem registry of the API states it.
_BY_CODE: Final[dict[str, type[APIError]]] = {
    "INVALID_REQUEST": InvalidRequestError,
    "UNAUTHENTICATED": AuthenticationError,
    "PERMISSION_DENIED": PermissionDeniedError,
    "SAFETY_CONTROL_DENIED": SafetyControlDeniedError,
    "NOT_FOUND": NotFoundError,
    "STATE_CONFLICT": StateConflictError,
    "QUARANTINED": QuarantinedError,
    "REVISION_CONFLICT": RevisionConflictError,
    "IDEMPOTENCY_CONFLICT": IdempotencyConflictError,
    "REQUEST_IN_PROGRESS": RequestInProgressError,
    "RATE_LIMITED": RateLimitError,
    "RESOURCE_EXHAUSTED": CapacityError,
    "HOST_NOT_SERVING": ServiceUnavailableError,
    "UNSUPPORTED": UnsupportedFeatureError,
    "REQUEST_TOO_LARGE": InvalidRequestError,
    "CURSOR_EXPIRED": CursorExpiredError,
    "INTEGRITY_FAILURE": IntegrityFailureError,
    "INCOMPATIBLE_RUNTIME": IncompatibleRuntimeError,
    "CLOCK_SKEW": ServiceUnavailableError,
    "UPSTREAM_UNAVAILABLE": ServiceUnavailableError,
    "OUTCOME_UNRESOLVED": OutcomeUnresolvedError,
    "OUTCOME_LOST": OutcomeLostError,
    "INTERNAL_ERROR": InternalError,
    "UNRECOGNIZED": RefusedError,
}


def error_class(code: str, kind: str) -> type[APIError]:
    """The exception for an error answer.

    A known code decides. A code this version does not know is handled by its kind: ``UNRESOLVED`` is
    an :class:`UnresolvedError`, and ``REFUSED`` or a kind it does not know either is a :class:`RefusedError`.
    """
    known = _BY_CODE.get(code)
    if known is not None:
        return known
    return UnresolvedError if kind == KIND_UNRESOLVED else RefusedError
