"""Shared CLI plumbing: application state, reusable options, the error guard, confirmation."""

from __future__ import annotations

import functools
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated

import typer

from acf_cli.client import ClientConfig, HostClient
from acf_cli.errors import AcfCliError, ExitCode, InvalidArgument, MutationInterrupted
from acf_cli.render import render_error

JsonOption = Annotated[
    bool, typer.Option("--json", help="Machine-readable JSON on stdout (human text goes to stderr).")
]


@dataclass(slots=True)
class AppState:
    config: ClientConfig
    verbose: bool = False


def state_of(ctx: typer.Context) -> AppState:
    obj = ctx.find_object(AppState)
    if obj is None:  # pragma: no cover - the root callback always installs it
        msg = "CLI state was not initialised"
        raise RuntimeError(msg)
    return obj


def client_of(ctx: typer.Context) -> HostClient:
    return HostClient(state_of(ctx).config)


def progress_of(ctx: typer.Context) -> Callable[[str], None]:
    """Progress lines go to stderr, and only with ``-v`` — stdout stays clean for data."""
    if not state_of(ctx).verbose:
        return lambda _msg: None

    def say(msg: str) -> None:
        sys.stderr.write(f"acf-local: {msg}\n")
        sys.stderr.flush()

    return say


def guard[**P, R](fn: Callable[P, R]) -> Callable[P, R]:
    """Turn the CLI's failure vocabulary into messages and stable exit codes.

    Unexpected exceptions are *not* caught: a bug should look like a bug (traceback, exit 1),
    not be dressed up as an operational error.
    """

    @functools.wraps(fn)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return fn(*args, **kwargs)
        except AcfCliError as e:
            render_error(e)
            raise typer.Exit(int(e.exit_code)) from e
        except KeyboardInterrupt as e:
            sys.stderr.write("\ninterrupted\n")
            if isinstance(e, MutationInterrupted):
                # The host journals what it accepted and finishes it: observe, never repeat.
                sys.stderr.write(
                    f"operation {e.operation_id} was already sent and may still complete; "
                    f"check it with: acf-local operation get {e.operation_id}\n"
                )
            raise typer.Exit(int(ExitCode.INTERRUPTED)) from e

    return wrapper


def confirm_destructive(what: str, *, assume_yes: bool) -> None:
    """Destructive commands need ``--yes`` unless a human is at the keyboard to say so."""
    if assume_yes:
        return
    if sys.stdin.isatty() and sys.stderr.isatty():
        if not typer.confirm(f"{what}?", default=False, err=True):
            raise typer.Abort
        return
    raise InvalidArgument(
        f"refusing to {what} without confirmation", hint="pass --yes to confirm in non-interactive use"
    )
