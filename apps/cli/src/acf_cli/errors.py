"""The client's failure vocabulary and its process exit codes.

Exit codes are part of the public contract: scripts and CI branch on them. They keep apart the
outcomes a caller must treat differently:

* the host **refused** the request (nothing was applied, nothing was recorded);
* the host accepted an operation and it **failed** or was **cancelled**;
* the operation ended **UNKNOWN** — it may have been applied and the host cannot establish it. That
  is neither success nor failure, and it is never reported as either;
* the client **could not establish** how an accepted (or possibly accepted) operation ended;
* the host could not be reached at all, so nothing was sent.
"""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from acf_cli.responses import ResponseEnvelope


class ExitCode(enum.IntEnum):
    """Process exit status of ``acf-local``."""

    OK = 0
    #: ``exec`` / ``run once`` only: the operation succeeded, but the command did not exit with status 0.
    WORKLOAD_FAILED = 1
    #: Usage error. Nothing was sent.
    USAGE = 2
    #: The host refused the request. Nothing was applied; no operation record exists.
    REFUSED = 3
    #: The host accepted the operation and it ended ``FAILED`` or ``CANCELLED``.
    FAILED = 4
    #: The operation ended ``UNKNOWN``: it may have been applied. Neither success nor failure.
    UNKNOWN = 5
    #: The host could not be reached, or a read was not answered. Nothing was changed by this command.
    TRANSPORT = 6
    #: The peer answered something that is not protocol ``acf.host/2``.
    PROTOCOL = 7
    #: The outcome is not established *yet*: the operation is still in progress, or contact with the
    #: host was lost after the request may have been sent. Observe the operation by its id.
    UNRESOLVED = 8
    #: Interrupted by the operator (SIGINT).
    INTERRUPTED = 130
    #: The reader of stdout went away (`acf-local ... | head`): 128 + SIGPIPE.
    READER_GONE = 141


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
    """The request did not reach the host: connecting, authenticating or writing the frame failed.

    The host acts only on complete frames, so this always means *the host did not act*.
    """

    exit_code = ExitCode.TRANSPORT


class ResponseLost(AcfCliError):
    """The request frame was written and no usable answer came back.

    For a read this is only a failed read. For a method that creates an operation it is the one
    situation that must never be answered with a new operation id: the host may have accepted the
    request, so the client asks again with the *same* id and ``retry: true``.
    """

    exit_code = ExitCode.TRANSPORT


class ProtocolViolation(AcfCliError):
    """The peer did not answer in protocol ``acf.host/2``."""

    exit_code = ExitCode.PROTOCOL


class LookupFailure(AcfCliError):
    """A name or id did not resolve to exactly one resource. Nothing was changed."""

    exit_code = ExitCode.REFUSED


class OutcomeUnresolved(AcfCliError):
    """Contact with the host was lost while an operation was, or may have been, in flight.

    The client could not learn whether the request was accepted or how the operation ended. The
    operation id is the handle: ``acf-local operation get <id>`` answers it once the host is back.
    """

    exit_code = ExitCode.UNRESOLVED


class HostAnswer(AcfCliError):
    """The host's final answer was not a success. The answer itself is carried, for ``--json``."""

    def __init__(
        self, message: str, envelope: ResponseEnvelope, *, hint: str | None = None, operation_id: str | None = None
    ) -> None:
        super().__init__(message, hint=hint, operation_id=operation_id)
        self.envelope = envelope


class Refused(HostAnswer):
    """``REFUSED``: the request was not accepted. Nothing was applied."""

    exit_code = ExitCode.REFUSED


class OperationFailed(HostAnswer):
    """The operation ended ``FAILED`` or ``CANCELLED``."""

    exit_code = ExitCode.FAILED


class OutcomeUnknown(HostAnswer):
    """The operation ended ``UNKNOWN`` (or in a terminal state this client does not know)."""

    exit_code = ExitCode.UNKNOWN


class NotFinished(HostAnswer):
    """The operation exists and had not ended when the client stopped waiting."""

    exit_code = ExitCode.UNRESOLVED


class MutationInterrupted(KeyboardInterrupt):
    """Ctrl-C arrived while an operation was in flight.

    It *is* a ``KeyboardInterrupt``, so every handler of one keeps working. What it adds is the
    operation id: the host records what it accepted and finishes it whether or not anyone is
    listening, so the operator has to be told which operation to **observe**.
    """

    def __init__(self, operation_id: str) -> None:
        super().__init__(operation_id)
        self.operation_id = operation_id
