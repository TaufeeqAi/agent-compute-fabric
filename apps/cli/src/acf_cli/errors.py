"""The CLI's failure vocabulary and its process exit codes.

Exit codes are part of the public contract: scripts and CI branch on them. They deliberately
keep *"the workload failed"* (the sandbox did its job; your command did not succeed) apart from
*"the platform failed"* and, most importantly, from *"the outcome is unknown"* — the one result
that must never be answered with a blind retry (spec §12.4, §14.2).
"""

from __future__ import annotations

import enum


class ExitCode(enum.IntEnum):
    """Process exit status of ``acf-local``."""

    OK = 0
    #: The command ran to a definite end but did not succeed (non-zero exit, signal, timeout…).
    WORKLOAD_FAILED = 1
    #: Reserved for usage errors; this is the status Click/Typer already use.
    USAGE = 2
    #: The host refused the request (validation / authorization / admission / conflict). Nothing changed.
    REJECTED = 3
    #: The host accepted the operation and it definitively failed.
    FAILED = 4
    #: The host may or may not have applied the operation. Resolve it; never re-run it.
    UNKNOWN = 5
    #: The host agent could not be reached (socket missing, permission denied, connection refused).
    UNREACHABLE = 6
    #: The peer broke the wire contract (bad frame, wrong protocol version, malformed envelope).
    PROTOCOL = 7
    #: Interrupted by the operator (SIGINT).
    INTERRUPTED = 130


class AcfCliError(Exception):
    """Base class. Carries everything needed to render an actionable message and pick an exit code."""

    exit_code: ExitCode = ExitCode.FAILED

    def __init__(self, message: str, *, hint: str | None = None, operation_id: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint
        self.operation_id = operation_id

    def __str__(self) -> str:
        return self.message


class InvalidArgument(AcfCliError):
    """A command-line value could not be understood. Raised before anything is sent anywhere."""

    exit_code = ExitCode.USAGE


class HostUnreachable(AcfCliError):
    """Could not connect, or the connection died before the request was written: nothing was sent."""

    exit_code = ExitCode.UNREACHABLE


class TransportError(AcfCliError):
    """The connection failed mid-conversation.

    ``request_sent`` is the single fact the retry logic depends on: if the request frame was fully
    written, the host may have acted on it, and the operation must be *resolved*, not repeated.
    """

    exit_code = ExitCode.UNREACHABLE

    def __init__(self, message: str, *, request_sent: bool, hint: str | None = None) -> None:
        super().__init__(message, hint=hint)
        self.request_sent = request_sent


class ProtocolViolation(AcfCliError):
    """The host (or whatever is on the socket) did not speak ``acf.host/1``."""

    exit_code = ExitCode.PROTOCOL


class Rejected(AcfCliError):
    """The host refused the request before changing anything (REJECTED / CONFLICT)."""

    exit_code = ExitCode.REJECTED

    def __init__(
        self,
        message: str,
        *,
        failure_class: str | None = None,
        retryable: bool = False,
        hint: str | None = None,
        operation_id: str | None = None,
    ) -> None:
        super().__init__(message, hint=hint, operation_id=operation_id)
        self.failure_class = failure_class
        self.retryable = retryable


class OperationFailed(AcfCliError):
    """The host accepted the operation and it ended in FAILED or CANCELLED."""

    exit_code = ExitCode.FAILED

    def __init__(
        self,
        message: str,
        *,
        failure_class: str | None = None,
        status: str | None = None,
        hint: str | None = None,
        operation_id: str | None = None,
    ) -> None:
        super().__init__(message, hint=hint, operation_id=operation_id)
        self.failure_class = failure_class
        self.status = status


class OutcomeUnknown(AcfCliError):
    """The operation may or may not have happened. The only safe next step is to observe it."""

    exit_code = ExitCode.UNKNOWN


class LookupFailure(AcfCliError):
    """A name or id did not resolve to exactly one resource. Nothing was changed."""

    exit_code = ExitCode.REJECTED


class MutationInterrupted(KeyboardInterrupt):
    """Ctrl-C arrived while a mutation was in flight.

    It *is* a ``KeyboardInterrupt``, so every existing handler (the ``run`` cleanup logic, ``exec``'s
    cancel-and-settle) keeps working unchanged. What it adds is the operation id: the host journals
    what it accepted and may still complete it, so the operator has to be told which operation to
    **observe** — never to repeat.
    """

    def __init__(self, operation_id: str) -> None:
        super().__init__(operation_id)
        self.operation_id = operation_id
