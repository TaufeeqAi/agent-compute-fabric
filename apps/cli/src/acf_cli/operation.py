"""``acf-local operation ...`` — observe, list and cancel operations.

``operation get`` is how a lost response is resolved after the fact: the operation id is the handle
on everything the host accepted, and asking by id never submits anything.

    acf-local operation get op-0123...           # what does the host say happened?
    acf-local operation get op-0123... --wait    # ... and follow it until it has ended

Its exit status states the operation's condition: ``0`` succeeded, ``4`` failed or cancelled,
``5`` unknown (it may have been applied), ``8`` not ended yet, ``3`` the host holds no such
operation for this caller — which, within the host's operation retention, means the request was
never accepted.
"""

from __future__ import annotations

from typing import Annotated

import typer

from acf_cli.client import Outcome, as_refused, exit_code_for
from acf_cli.common import (
    AllOption,
    ChangedSinceOption,
    JsonOption,
    LimitOption,
    OperationIdOption,
    TimeoutOption,
    WaitOption,
    client_of,
    conclude,
    guard,
    operation_id_of,
    timeout_of,
)
from acf_cli.errors import ExitCode, InvalidArgument
from acf_cli.render import print_json, render_host_change, render_listing_footer, render_operation, render_operations
from acf_cli.requests import operation_cancel
from acf_cli.resolve import list_operations
from acf_cli.responses import HostChangeBody, OperationView
from acf_cli.units import parse_cursor

app = typer.Typer(help="Observe, list and cancel operations.", no_args_is_help=True)

OperationArg = Annotated[str, typer.Argument(help="Operation id, as printed by the command that created it.")]


def _required_id(text: str) -> str:
    checked = operation_id_of(text)
    if checked is None:  # pragma: no cover - a positional argument is never None
        raise InvalidArgument("an operation id is required")
    return checked


def _report(outcome: Outcome, *, as_json: bool) -> None:
    """State what the host said and leave with the exit code that mirrors it."""
    view = outcome.operation
    if view is None:
        raise as_refused(outcome)
    if as_json:
        print_json(outcome.to_wire())
    else:
        render_operation(view, outcome.as_of)
    code = exit_code_for(view)
    if code is not ExitCode.OK:
        raise typer.Exit(int(code))


@app.command("get")
@guard
def get(
    ctx: typer.Context,
    operation_id: OperationArg,
    wait: Annotated[
        bool, typer.Option("--wait/--no-wait", help="Follow the operation until it ends. Default: ask once.")
    ] = False,
    timeout: TimeoutOption = None,
    as_json: JsonOption = False,
) -> None:
    """Ask the host what happened to an operation. Never submits anything."""
    op_id = _required_id(operation_id)
    client = client_of(ctx)
    outcome = client.follow(op_id, timeout_s=timeout_of(timeout)) if wait else client.observe(op_id)
    _report(outcome, as_json=as_json)


@app.command("list")
@guard
def list_(
    ctx: typer.Context,
    changed_since: ChangedSinceOption = None,
    limit: LimitOption = None,
    all_pages: AllOption = False,
    as_json: JsonOption = False,
) -> None:
    """List the operations the host holds for this caller, oldest change first."""
    cursor = parse_cursor(changed_since) if changed_since is not None else None
    listing = list_operations(client_of(ctx), changed_since=cursor, limit=limit, follow=all_pages)
    if as_json:
        print_json(listing.to_wire())
    else:
        render_operations(listing.items)
        render_listing_footer(len(listing.items), listing.cursor, more=listing.more, as_of=listing.as_of)


def _cancel_result(view: OperationView) -> None:
    if isinstance(view.result, HostChangeBody):
        render_host_change(view.result.data)


@app.command("cancel")
@guard
def cancel(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Operation id of the execution to cancel.")],
    operation_id: OperationIdOption = None,
    wait: WaitOption = True,
    timeout: TimeoutOption = None,
    as_json: JsonOption = False,
) -> None:
    """Ask the host to cancel a running execution.

    Cancelling is itself an operation. It succeeds when the execution has ended — cancelled, or
    because it had already finished, in which case nothing changes. Only an execution in progress
    can be cancelled; any other operation is refused with STATE_CONFLICT: it is bounded by its own
    deadline, and stopping or destroying the sandbox preempts it.
    """
    outcome = client_of(ctx).submit(
        operation_cancel(_required_id(target)),
        operation_id=operation_id_of(operation_id),
        wait=wait,
        timeout_s=timeout_of(timeout),
    )
    conclude(outcome, as_json=as_json, show=_cancel_result)
