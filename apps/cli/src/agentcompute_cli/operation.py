"""``acf operation ...``: read one operation, or list them.

Everything that changes something is an operation, and an operation can outlive the command that
started it. ``acf operation get`` is how such a command is followed afterwards: asking by identifier
never submits anything.

Its exit status states the operation's condition, by the rule the SDK applies to an operation it
followed itself: ``0`` it succeeded, ``4`` it ended and nothing was applied, ``5`` its outcome is unknown
or it may have been applied, ``10`` it has not ended. The operation is printed in every one of those
cases: it is what was asked for.
"""

from __future__ import annotations

import functools
import sys
from typing import Annotated

import typer

from agentcompute_cli import render, views
from agentcompute_cli.common import (
    BaseUrlOpt,
    Common,
    JsonOpt,
    ProfileOpt,
    ProjectOpt,
    TimeoutOpt,
    VerboseOpt,
    connect,
    guard,
    note,
)
from agentcompute_cli.outcome import ExitCode, condition_of

__all__ = ["app"]

app = typer.Typer(help="Read one operation, or list the operations of the project.", no_args_is_help=True)

_CONDITIONS = {
    ExitCode.OPERATION_FAILED: "it ended and nothing was applied: the same request may be made again as a new one",
    ExitCode.OUTCOME_UNKNOWN: (
        "its outcome is not known, or it may have been applied: this is neither success nor failure. "
        "Inspect the target before acting again"
    ),
}


@app.command("get")
@guard
def get(
    operation: Annotated[str, typer.Argument(metavar="OPERATION", help="An operation identifier (op-...).")],
    wait: Annotated[
        int | None,
        typer.Option(
            "--wait",
            min=0,
            metavar="SECONDS",
            help="Let the platform wait up to this many seconds for the operation to end. Default: answer at once.",
            show_default=False,
        ),
    ] = None,
    as_json: JsonOpt = False,
    profile: ProfileOpt = None,
    base_url: BaseUrlOpt = None,
    project: ProjectOpt = None,
    verbose: VerboseOpt = False,
    timeout: TimeoutOpt = None,
) -> None:
    """Show an operation as it is now. The exit status states its condition: 0, 4, 5 or 10."""
    with connect(Common(as_json, profile, base_url, project, verbose, timeout)) as session:
        found = session.call(session.fabric.operations.get, operation, wait=wait)
        session.show(found, functools.partial(views.show_operation, found))
        condition = condition_of(found.state, found.effect)
        if condition is ExitCode.OK:
            return
        identifier = render.safe_line(found.operation_id, limit=render.IDENTIFIER_MAX)
        if condition is ExitCode.STILL_RUNNING:
            note(f"operation {identifier} has not ended. Follow it: acf operation get {identifier} --wait 30")
        else:
            note(f"operation {identifier}: {_CONDITIONS[condition]}")
        sys.stdout.flush()
        raise typer.Exit(int(condition))


@app.command("list")
@guard
def list_(
    as_json: JsonOpt = False,
    profile: ProfileOpt = None,
    base_url: BaseUrlOpt = None,
    project: ProjectOpt = None,
    verbose: VerboseOpt = False,
    timeout: TimeoutOpt = None,
) -> None:
    """List the operations of the project."""
    with connect(Common(as_json, profile, base_url, project, verbose, timeout)) as session:
        operations = session.call(lambda: list(session.fabric.operations.list()))
        session.show_all(operations, functools.partial(views.show_operations, operations))
