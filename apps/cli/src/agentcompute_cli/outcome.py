"""How a command ends: its exit status, and the words that go with it.

Scripts and CI branch on the exit status, so it is part of the contract of this tool and is decided in
one place, :func:`exit_code_for`. It keeps apart the outcomes a caller must treat differently:

* the platform **refused** the request: nothing exists because of it;
* an operation was accepted and **failed cleanly**: nothing was applied, and a new request is allowed;
* the outcome is **unknown**: the operation may have been applied. This is neither success nor failure
  and is never reported as either;
* the request is **unresolved**: whether it was accepted is not known yet, and the same idempotency key
  settles it later;
* the outcome is **lost**: it will never be known through this key;
* the operation is **still running**: the tool stopped following it and assumes nothing.

Every message ends with what the person can do next, and names the idempotency key when asking again
with it is that next step. The key it names is the one this tool gave the call: a call of the SDK can
be more than one request, each under a key derived from that one, and only the first resumes the whole.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any, Final

from agentcompute import (
    APIConnectionError,
    APIError,
    ConfigurationError,
    FabricError,
    IncompatibleServerError,
    OperationError,
    OperationFailedError,
    OperationStillRunningError,
    OutcomeLostError,
    OutcomeUnknownError,
    RefusedError,
    SandboxStartError,
    UnexpectedResponseError,
    UnresolvedError,
)

__all__ = [
    "ArgumentError",
    "CliError",
    "ExitCode",
    "Report",
    "UsageError",
    "condition_of",
    "describe",
    "exit_code_for",
]


class ExitCode(enum.IntEnum):
    """Process exit status of ``acf``."""

    #: Done.
    OK = 0
    #: ``acf exec run`` only: the operation succeeded, and the command it ran did not exit with status 0.
    COMMAND_FAILED = 1
    #: Usage or configuration error. Nothing that changes anything was sent.
    USAGE = 2
    #: The platform refused the request. Nothing exists because of it.
    REFUSED = 3
    #: The operation failed and nothing was applied.
    OPERATION_FAILED = 4
    #: The outcome is unknown, or the operation may have been applied. Neither success nor failure.
    OUTCOME_UNKNOWN = 5
    #: The platform could not be reached, or a read got no answer.
    UNREACHABLE = 6
    #: What answered does not speak this API.
    INCOMPATIBLE = 7
    #: A request that changes something got no usable answer. The same idempotency key resolves it.
    UNRESOLVED = 8
    #: The outcome is lost for good.
    OUTCOME_LOST = 9
    #: The operation had not ended when the tool stopped following it.
    STILL_RUNNING = 10
    #: Interrupted (Ctrl-C). Nothing was cancelled.
    INTERRUPTED = 130
    #: The reader of standard output went away: 128 + SIGPIPE.
    READER_GONE = 141


class CliError(Exception):
    """A failure this tool established itself. It says what to do next, like every other."""

    def __init__(self, message: str, *, exit_code: ExitCode, next_step: str) -> None:
        super().__init__(message)
        self.message = message
        self.exit_code = exit_code
        self.next_step = next_step


class UsageError(CliError):
    """The command line, the environment or a file it names cannot be used as given. Nothing was sent.

    Raised before the first request only: the words say that nothing was sent, and they have to be true.
    """

    def __init__(self, message: str, *, next_step: str = "Run the command with --help to see what it takes.") -> None:
        super().__init__(message, exit_code=ExitCode.USAGE, next_step=f"Nothing was sent. {next_step}")


class ArgumentError(CliError):
    """The SDK refused an argument of a call, before it sent that request. Its words are fit to be shown.

    A command may have read something by then (the sandbox a name belongs to, for one), so what is said
    is what is known: the request that was refused was not sent.
    """

    def __init__(self, message: str) -> None:
        super().__init__(
            message,
            exit_code=ExitCode.USAGE,
            next_step="The request was not sent. Run the command with --help to see what it takes.",
        )


#: The exit status of each kind of error, first match first. A class stands before the classes it is a
#: kind of: a server that does not speak the API is also a configuration error, and a lost outcome is
#: also an unresolved one.
_RULES: Final[tuple[tuple[type[BaseException], ExitCode], ...]] = (
    (IncompatibleServerError, ExitCode.INCOMPATIBLE),
    (ConfigurationError, ExitCode.USAGE),
    (UnexpectedResponseError, ExitCode.INCOMPATIBLE),
    (APIConnectionError, ExitCode.UNREACHABLE),
    (OutcomeLostError, ExitCode.OUTCOME_LOST),
    (UnresolvedError, ExitCode.UNRESOLVED),
    (RefusedError, ExitCode.REFUSED),
    (OperationFailedError, ExitCode.OPERATION_FAILED),
    (OperationStillRunningError, ExitCode.STILL_RUNNING),
    (OutcomeUnknownError, ExitCode.OUTCOME_UNKNOWN),
    (KeyboardInterrupt, ExitCode.INTERRUPTED),
    (BrokenPipeError, ExitCode.READER_GONE),
)


def exit_code_for(error: BaseException) -> ExitCode:
    """The exit status an error ends the process with. The one place that decides it.

    An error this version has no rule for is reported as an unknown outcome, whether it is an error of
    the SDK that is newer than this tool or a defect: it is not known what it means, so nothing is
    assumed, and it never exits 0. It never exits 1 either, which is what the interpreter would make of
    an exception nobody caught: for ``acf exec run`` that status says that the command ran.
    """
    if isinstance(error, CliError):
        return error.exit_code
    if isinstance(error, SandboxStartError):
        # Whatever became of the sandbox, the command asked for a started one: its status is the start's.
        return exit_code_for(error.start_error)
    for kind, code in _RULES:
        if isinstance(error, kind):
            return code
    return ExitCode.OUTCOME_UNKNOWN


# ------------------------------------------------------------------------------------------ operations
_SUCCEEDED: Final = "SUCCEEDED"
_UNKNOWN: Final = "UNKNOWN"
_NOT_APPLIED: Final = "NOT_APPLIED"
#: The states in which an operation has ended. Any other state, one this version has never seen
#: included, has not ended.
_ENDED: Final = frozenset({_SUCCEEDED, "FAILED", "CANCELLED", _UNKNOWN})


def condition_of(state: str, effect: str | None) -> ExitCode:
    """The exit status that states the condition of an operation someone asked to see.

    The same judgement the SDK makes of an operation it followed: success only when it says so, a clean
    failure only when the host says nothing was applied, and unknown otherwise.
    """
    if state == _SUCCEEDED:
        return ExitCode.OK
    if state not in _ENDED:
        return ExitCode.STILL_RUNNING
    if state != _UNKNOWN and effect == _NOT_APPLIED:
        return ExitCode.OPERATION_FAILED
    return ExitCode.OUTCOME_UNKNOWN


# --------------------------------------------------------------------------------------------- reports
@dataclass(frozen=True, slots=True)
class Report:
    """Everything that is said about one failure."""

    exit_code: ExitCode
    #: What happened, in one line.
    headline: str
    #: What is known because of it.
    details: tuple[str, ...]
    #: What the person can do next.
    next_step: str
    #: The API's own representation of the failure, when it sent one: for ``--json``.
    document: dict[str, Any] | None = None
    request_id: str | None = None


_RETRY_LATER: Final = "SAME_REQUEST_LATER"
_RETRY_AFTER_CHANGE: Final = "AFTER_CHANGE"
_RETRY_NEVER: Final = "NEVER"

_NOTHING_EXISTS: Final = "The platform did not accept the request: nothing was created or changed."
_INSPECT: Final = (
    "Inspect the target before acting again: `acf operation list` shows what the platform holds, "
    "`acf sandbox inspect SANDBOX` what became of a sandbox. Do not run the command again blindly."
)

#: What to do about a refusal, for the codes where more can be said than the retry advice says.
_REFUSAL_ADVICE: Final[dict[str, str]] = {
    "UNAUTHENTICATED": (
        "The key is missing, invalid, expired or revoked. Store a valid one with `acf auth login`, or set ACF_API_KEY."
    ),
    "PERMISSION_DENIED": "This credential may not do that. `acf policy inspect` shows what it may do.",
    "NOT_FOUND": (
        "There is no such record in this project. Check the identifier or the name: "
        "`acf sandbox list`, `acf snapshot list` and `acf operation list` show what exists."
    ),
    "REVISION_CONFLICT": (
        "The sandbox is not at the generation the request named. `acf sandbox inspect SANDBOX` shows the "
        "current one: look at what changed, then ask again."
    ),
    "IDEMPOTENCY_CONFLICT": (
        "This idempotency key belongs to a different request. Use it only with the command and the arguments "
        "it was first used with, and leave --idempotency-key out for a new request."
    ),
    "QUARANTINED": "The host has quarantined the record. An operator has to release it on the host.",
}


def _refusal_advice(error: APIError) -> str:
    known = _REFUSAL_ADVICE.get(error.code)
    if known is not None:
        return known
    if error.retry == _RETRY_LATER:
        wait = "" if error.retry_after is None else f", not before {error.retry_after:g} s from now"
        return f"Nothing is wrong with the request: the platform cannot take it now. Run the same command again{wait}."
    if error.retry == _RETRY_AFTER_CHANGE:
        return (
            "It can be accepted once something changes: the state of the target, the request or the platform. "
            "Look at what is there, then ask again."
        )
    if error.retry == _RETRY_NEVER:
        return "This request will not be accepted as it is. Change it before asking again."
    return "The platform gave retry advice this version does not know. Do not repeat the request unchanged."


def _again_with(key: str | None) -> str:
    if key is None:
        return "Run the same command again later."
    return (
        f"Run the same command again later, with the same arguments and --idempotency-key {key}. "
        "Never with another key: that could start a second operation."
    )


def _problem(error: APIError) -> dict[str, Any]:
    """The members of the problem document that the SDK keeps, under the names the API gave them."""
    document: dict[str, Any] = {
        "code": error.code,
        "kind": error.kind,
        "retry": error.retry,
        "message": error.message,
        "request_id": error.request_id,
    }
    optional = {"idempotency_key": error.idempotency_key, "reason": error.reason, "status": error.status}
    document.update({name: value for name, value in optional.items() if value is not None})
    return document


def _api_error(error: APIError, key: str | None) -> Report:
    said = f"{error.code}: {error.message}" if error.message else error.code
    code = exit_code_for(error)
    document = _problem(error)
    if isinstance(error, OutcomeLostError):
        return Report(
            code,
            f"outcome lost: {said}",
            (
                "The platform accepted this request and can no longer tell what became of it.",
                "This is neither success nor failure.",
            ),
            f"{_INSPECT} This idempotency key is finished: a new request needs a new one.",
            document,
            error.request_id,
        )
    if isinstance(error, UnresolvedError):
        # A code this version does not know is handled by its kind and by its retry advice.
        advice = _INSPECT if error.retry == _RETRY_NEVER else _again_with(key or error.idempotency_key)
        return Report(
            code,
            f"unresolved: {said}",
            ("Whether the platform accepted the request is not known: an operation may exist because of it.",),
            advice,
            document,
            error.request_id,
        )
    details = [_NOTHING_EXISTS]
    if error.reason is not None:
        details.append(f"Reason: {error.reason}.")
    return Report(code, f"refused: {said}", tuple(details), _refusal_advice(error), document, error.request_id)


def _member(raw: dict[str, Any], name: str) -> str:
    """One member of a view for a message. A view that lacks it is still reported, with a dash."""
    value = raw.get(name)
    return value if isinstance(value, str) and value else "-"


def _operation_error(error: OperationError, key: str | None) -> Report:
    raw = error.operation.raw
    operation_id = error.operation_id
    subject = f"operation {operation_id} ({_member(raw, 'type')})"
    state = _member(raw, "state")
    failure = raw.get("failure")
    because = f": {_member(failure, 'code')}: {_member(failure, 'message')}" if isinstance(failure, dict) else ""
    code = exit_code_for(error)
    if isinstance(error, OperationStillRunningError):
        target = raw.get("target")
        execution = target.get("execution_id") if isinstance(target, dict) else None
        steps = [f"Follow it: acf operation get {operation_id} --wait 30."]
        if key is not None:
            steps.append(
                f"Or run the same command again with the same arguments and --idempotency-key {key}: "
                "it picks the call up where it stopped and starts nothing twice."
            )
        if isinstance(execution, str):
            steps.append(f"Its output, once it has ended: acf exec output {execution}.")
        return Report(
            code,
            f"still running: {subject} is {state}",
            ("The tool stopped following it. Nothing was cancelled and nothing is assumed: the operation goes on.",),
            " ".join(steps),
            raw,
            error.request_id,
        )
    if isinstance(error, OperationFailedError):
        return Report(
            code,
            f"failed: {subject} ended {state}{because}",
            ("Nothing was applied.",),
            "The command may be run again as a new request: leave --idempotency-key out, or give a new key. "
            "With the old key the platform answers with this same operation.",
            raw,
            error.request_id,
        )
    return Report(
        code,
        f"outcome unknown: {subject} ended {state} with effect {_member(raw, 'effect')}{because}",
        ("It may have been applied. This is neither success nor failure.",),
        f"{_INSPECT} `acf operation get {operation_id}` shows this operation.",
        raw,
        error.request_id,
    )


def _start_error(error: SandboxStartError, key: str | None) -> Report:
    sandbox = error.sandbox_id
    start = describe(error.start_error, key=key)
    details = [f"Its start: {start.headline}."]
    if error.cleanup == "destroyed":
        details.append("The sandbox was destroyed: nothing is left of it.")
        advice = "Run the command again as a new request once the cause is gone, or pass --keep-on-start-failure."
    elif error.cleanup == "kept":
        details.append("The sandbox was kept, as asked. It exists until it is destroyed or its lifetime ends.")
        advice = f"Start it: acf sandbox start {sandbox}. Or remove it: acf sandbox destroy {sandbox}."
    else:
        destroyed = "" if error.destroy_error is None else f" ({describe(error.destroy_error, key=None).headline})"
        details.append(f"Destroying it did not succeed either{destroyed}. It may exist until its lifetime ends.")
        advice = f"Look at it: acf sandbox inspect {sandbox}. Then remove it: acf sandbox destroy {sandbox}."
    return Report(
        exit_code_for(error),
        f"sandbox {sandbox} was created and could not be started",
        tuple(details),
        advice,
        start.document,
        error.request_id,
    )


def _interrupted(key: str | None) -> Report:
    if key is None:
        advice = "Run the command again when you are ready: it changed nothing."
    else:
        advice = (
            f"To pick this call up: run the same command again with the same arguments and --idempotency-key {key}. "
            "To stop a command that runs in a sandbox: acf exec cancel EXECUTION (acf operation list finds it). "
            "Anything else ends with acf sandbox stop or acf sandbox destroy."
        )
    return Report(
        ExitCode.INTERRUPTED,
        "interrupted",
        ("The tool stopped waiting. Nothing was cancelled: whatever this command asked for goes on on the platform.",),
        advice,
    )


def _resolve_with(key: str | None) -> str:
    """How a call whose end nobody saw is picked up again, when it was made under a key."""
    if key is None:
        return ""
    return f" If the command changes something, run it again with --idempotency-key {key} to see what became of it."


def _defect(error: BaseException, key: str | None) -> Report:
    """An exception nobody meant to raise. Its traceback is the caller's to show; these are the words after it."""
    return Report(
        exit_code_for(error),
        f"acf failed in a way it has no rule for ({type(error).__name__}): this is a defect of the tool, "
        "not an answer of the platform",
        ("Nothing is assumed about the outcome: a request may have been sent before the tool failed.",),
        f"{_INSPECT}{_resolve_with(key)} Please report the lines above.",
    )


def _other(error: FabricError, key: str | None) -> Report:
    code = exit_code_for(error)
    said = str(error)
    request_id = error.request_id
    resolve = _resolve_with(key)
    if isinstance(error, IncompatibleServerError):
        return Report(
            code,
            said,
            (),
            "Check the address: --base-url, ACF_BASE_URL or the stored profile has to name the platform's public API.",
            request_id=request_id,
        )
    if isinstance(error, ConfigurationError):
        return Report(
            code,
            said,
            ("Nothing was sent.",),
            "Correct the configuration. Flags come first, then ACF_API_KEY, ACF_BASE_URL and ACF_PROJECT, "
            "then the profile stored by `acf auth login`.",
        )
    if isinstance(error, UnexpectedResponseError):
        return Report(
            code,
            f"unexpected answer: {said}",
            ("What answered is not this API, or did not answer as this API does.",),
            f"Check the address, and quote the request id when asking for help.{resolve}",
            request_id=request_id,
        )
    if isinstance(error, APIConnectionError):
        return Report(
            code,
            f"unreachable: {said}",
            ("Nothing can be said about the platform's state from here.",),
            "Check the address (--base-url, ACF_BASE_URL or the stored profile) and the network, "
            "then run the command again.",
        )
    return Report(
        code,
        f"{type(error).__name__}: {said}",
        ("This version of the tool has no rule for this error, so nothing is assumed about the outcome.",),
        _INSPECT,
        request_id=request_id,
    )


def describe(error: BaseException, *, key: str | None) -> Report:
    """What to say about an error. ``key`` is the idempotency key of the call the command made, if it made one."""
    if isinstance(error, CliError):
        return Report(error.exit_code, error.message, (), error.next_step)
    if isinstance(error, KeyboardInterrupt):
        return _interrupted(key)
    if not isinstance(error, FabricError):
        return _defect(error, key)
    if isinstance(error, SandboxStartError):
        report = _start_error(error, key)
    elif isinstance(error, RefusedError | UnresolvedError):
        report = _api_error(error, key)
    elif isinstance(error, OperationFailedError | OutcomeUnknownError | OperationStillRunningError):
        report = _operation_error(error, key)
    else:
        report = _other(error, key)
    # The SDK attaches what else it knows as notes: that a sandbox was created before its start failed,
    # that a credential may exist whose secret nobody saw.
    notes = tuple(getattr(error, "__notes__", ()))
    return report if not notes else _with_details(report, notes)


def _with_details(report: Report, more: tuple[str, ...]) -> Report:
    return Report(
        report.exit_code,
        report.headline,
        report.details + more,
        report.next_step,
        report.document,
        report.request_id,
    )
