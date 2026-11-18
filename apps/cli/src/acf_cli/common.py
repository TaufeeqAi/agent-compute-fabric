"""Shared CLI plumbing: application state, reusable options, the error guard, output helpers."""

from __future__ import annotations

import contextlib
import functools
import os
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Any

import typer
from pydantic import ValidationError

from acf_cli.client import ClientConfig, HostClient, Outcome, answer_document, require_success
from acf_cli.errors import AcfCliError, ExitCode, HostAnswer, InvalidArgument, MutationInterrupted
from acf_cli.render import print_json, render_error, render_operation, render_refusal
from acf_cli.requests import MAX_LIST_LIMIT
from acf_cli.responses import OperationView
from acf_cli.units import parse_duration_s
from acf_cli.wire import ALIAS_PATTERN, OPERATION_ID_PATTERN

JsonOption = Annotated[
    bool, typer.Option("--json", help="One JSON document on stdout: the host's answer in wire form.")
]
WaitOption = Annotated[
    bool,
    typer.Option(
        "--wait/--no-wait",
        help="Follow the operation until it ends (default), or return as soon as the host has recorded it.",
    ),
]
TimeoutOption = Annotated[
    str | None,
    typer.Option(
        "--timeout",
        envvar="ACF_TIMEOUT",
        help="Stop following after this long (90, 90s, 5m). Default: until the operation ends. "
        "The operation itself is not affected.",
        show_default=False,
    ),
]
OperationIdOption = Annotated[
    str | None,
    typer.Option(
        "--operation-id",
        help="Use this operation id instead of a generated one (8-64 of [A-Za-z0-9-]). "
        "Repeating a command with the same id returns the same operation; nothing runs twice.",
        show_default=False,
    ),
]
ExpectedGenerationOption = Annotated[
    int | None,
    typer.Option(
        "--expected-generation",
        min=1,
        help="Act only if this is the sandbox's current generation. Default: the generation read just before.",
        show_default=False,
    ),
]
IfRevisionOption = Annotated[
    int | None,
    typer.Option(
        "--if-revision",
        min=0,
        help="Act only if the sandbox's revision still equals this (as printed by `sandbox inspect`).",
        show_default=False,
    ),
]
ChangedSinceOption = Annotated[
    str | None,
    typer.Option(
        "--changed-since",
        help="List only records that changed after this cursor (LINEAGE:SEQUENCE), tombstones included.",
        show_default=False,
    ),
]
LimitOption = Annotated[
    int | None,
    typer.Option("--limit", min=1, max=MAX_LIST_LIMIT, help="Page size. Default: the host's.", show_default=False),
]
AllOption = Annotated[
    bool, typer.Option("--all", help="Follow the listing to its end instead of stopping at one page.")
]
YesOption = Annotated[bool, typer.Option("--yes", "-y", help="Do not ask for confirmation.")]

_OPERATION_ID = re.compile(OPERATION_ID_PATTERN)
_ALIAS = re.compile(ALIAS_PATTERN)


@dataclass(slots=True)
class AppState:
    config: ClientConfig
    verbose: bool = False
    client: HostClient | None = None


def state_of(ctx: typer.Context) -> AppState:
    obj = ctx.find_object(AppState)
    if obj is None:  # pragma: no cover - the root callback always installs it
        msg = "CLI state was not initialised"
        raise RuntimeError(msg)
    return obj


def new_client(config: ClientConfig) -> HostClient:
    """The one place a client is built, so tests can substitute its transport."""
    return HostClient(config)


def client_of(ctx: typer.Context) -> HostClient:
    """The invocation's client. It keeps one connection for all of the command's requests."""
    state = state_of(ctx)
    if state.client is None:
        state.client = new_client(state.config)
        ctx.find_root().call_on_close(state.client.close)
    return state.client


def progress_of(ctx: typer.Context) -> Callable[[str], None]:
    """Progress lines go to stderr, and only with ``-v`` — stdout stays clean for data."""
    if not state_of(ctx).verbose:
        return lambda _msg: None

    def say(msg: str) -> None:
        sys.stderr.write(f"acf-local: {msg}\n")
        sys.stderr.flush()

    return say


def timeout_of(text: str | None) -> float | None:
    """``--timeout`` in seconds; ``None`` follows an operation until it ends."""
    return parse_duration_s(text) if text is not None else None


def operation_id_of(text: str | None) -> str | None:
    if text is not None and not _OPERATION_ID.fullmatch(text):
        raise InvalidArgument(f"{text!r} is not an operation id", hint="an operation id is 8-64 letters, digits or '-'")
    return text


def alias_of(text: str | None, option: str) -> str | None:
    """A name given on the command line, checked before anything is sent."""
    if text is not None and not _ALIAS.fullmatch(text):
        raise InvalidArgument(
            f"invalid {option} {text!r}",
            hint="a name is 1-63 characters of [A-Za-z0-9._-] and does not start with a dot",
        )
    return text


def unsendable(error: ValidationError) -> InvalidArgument:
    """A request that could not be built from the command line. The offending value is not repeated."""
    first = error.errors(include_input=False, include_url=False)[0]
    where = ".".join(str(part) for part in first["loc"])
    return InvalidArgument(f"the request cannot be sent: {where}: {first['msg']}" if where else first["msg"])


def error_document(err: AcfCliError) -> dict[str, Any]:
    """A client-side failure for ``--json``: there is no host answer to print, so this says why."""
    return {
        "error": {
            "kind": type(err).__name__,
            "message": err.message,
            "hint": err.hint,
            "operation_id": err.operation_id,
            "exit_code": int(err.exit_code),
        }
    }


def render_host_answer(err: HostAnswer) -> None:
    """A host answer that was not a success, on stderr."""
    envelope = err.envelope
    if envelope.refusal is not None:
        render_refusal(envelope.refusal, envelope.as_of)
        return
    if envelope.operation is not None:
        render_operation(envelope.operation, envelope.as_of, to_stderr=True)
    render_error(err)


def guard[**P, R](fn: Callable[P, R]) -> Callable[P, R]:
    """Turn the client's failure vocabulary into messages and stable exit codes.

    With ``--json`` stdout still carries exactly one document: the host's answer when there is one
    (a refusal, or the operation as last stated), otherwise an ``error`` object.

    Unexpected exceptions are *not* caught: a defect should look like one (traceback, exit 1), not
    be dressed up as an operational error.
    """

    def reported(*args: P.args, **kwargs: P.kwargs) -> R:
        as_json = bool(kwargs.get("as_json", False))
        try:
            return fn(*args, **kwargs)
        except HostAnswer as e:
            if as_json:
                print_json(answer_document(e.envelope))
            render_host_answer(e)
            raise typer.Exit(int(e.exit_code)) from e
        except (AcfCliError, ValidationError) as e:
            # Answers are validated where they are read, so a validation error that reaches this
            # point came from building a request: a usage error, and nothing was sent for it.
            err = unsendable(e) if isinstance(e, ValidationError) else e
            if as_json:
                print_json(error_document(err))
            render_error(err)
            raise typer.Exit(int(err.exit_code)) from e
        except KeyboardInterrupt as e:
            sys.stderr.write("\ninterrupted\n")
            if isinstance(e, MutationInterrupted):
                # The host records what it accepted and finishes it: ask, never submit again.
                sys.stderr.write(
                    f"operation {e.operation_id} was already sent and may still complete; "
                    f"ask the host: acf-local operation get {e.operation_id}\n"
                )
            raise typer.Exit(int(ExitCode.INTERRUPTED)) from e

    @functools.wraps(fn)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            try:
                return reported(*args, **kwargs)
            finally:
                sys.stdout.flush()  # a reader that went away is noticed here, not at interpreter exit
        except BrokenPipeError as e:
            # `acf-local ... | head`: stop quietly with the conventional status, as Unix tools do,
            # and make sure the interpreter's own flush at exit does not fail a second time.
            _discard_stdout()
            raise typer.Exit(int(ExitCode.READER_GONE)) from e

    return wrapper


def _discard_stdout() -> None:
    with contextlib.suppress(OSError, ValueError):
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        os.close(devnull)


def interactive() -> bool:
    """Whether a human is at the keyboard to be asked."""
    return sys.stdin.isatty() and sys.stderr.isatty()


def confirm_destructive(what: str, *, assume_yes: bool) -> None:
    """Destructive commands need ``--yes`` unless a human is at the keyboard to say so."""
    if assume_yes:
        return
    if interactive():
        if not typer.confirm(f"{what}?", default=False, err=True):
            raise typer.Abort
        return
    raise InvalidArgument(
        f"refusing to {what} without confirmation", hint="pass --yes to confirm in non-interactive use"
    )


def conclude(outcome: Outcome, *, as_json: bool, show: Callable[[OperationView], None]) -> OperationView:
    """Report a successful operation; anything else is raised for :func:`guard` to report.

    Human output is what the operation produced (``show``) followed by the operation itself: its
    state, its ``effect`` and, when the host states one, its ``cleanup``.
    """
    view = require_success(outcome)
    if as_json:
        print_json(outcome.to_wire())
    else:
        show(view)
        sys.stdout.write("\n")
        render_operation(view, outcome.as_of)
    return view
