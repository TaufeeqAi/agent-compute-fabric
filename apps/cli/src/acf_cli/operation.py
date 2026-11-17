"""``acf-local operation ...`` — observe or cancel an operation by id.

This is the recovery tool for the one situation the CLI refuses to guess about: a mutation whose
response was lost (spec §8.4). The rule is *observe, never repeat*:

    acf-local operation get op-0123...           # what does the host say happened?
    acf-local operation get op-0123... --wait    # ... and wait until it is final

Exit status mirrors the operation: ``0`` succeeded, ``3`` refused (never started; includes "the
host has no record of that id"), ``4`` failed or cancelled, ``5`` not final / unknown.
"""

from __future__ import annotations

from typing import Annotated

import typer
from pydantic import ValidationError

from acf_cli.client import exit_code_for_status
from acf_cli.common import JsonOption, client_of, guard
from acf_cli.errors import ExitCode, InvalidArgument
from acf_cli.models import OperationGetRequest, OperationSelector, OperationStatus, ResponseEnvelope
from acf_cli.render import print_json, render_operation
from acf_cli.units import parse_duration_ms

app = typer.Typer(help="Observe or cancel operations by id.", no_args_is_help=True)

DEFAULT_WAIT_S = 60.0
DEFAULT_CANCEL_SETTLE_S = 30.0


def parse_operation_id(text: str) -> OperationSelector:
    try:
        return OperationSelector(operation_id=text)
    except ValidationError as e:
        raise InvalidArgument(
            f"{text!r} is not an operation id",
            hint="operation ids are 8-64 letters, digits or '-'; `run` prints them on failure and with -v",
        ) from e


def _emit(env: ResponseEnvelope, *, as_json: bool) -> None:
    if as_json:
        print_json(env)
    else:
        render_operation(env)


@app.command("get")
@guard
def get(
    ctx: typer.Context,
    operation_id: Annotated[str, typer.Argument(help="Operation id (the one printed on failure, or `run -v`).")],
    wait: Annotated[bool, typer.Option("--wait", help="Keep observing until the operation is final.")] = False,
    wait_timeout: Annotated[
        str | None, typer.Option("--wait-timeout", help="With --wait: give up after e.g. 90, 90s, 5m (default 60s).")
    ] = None,
    as_json: JsonOption = False,
) -> None:
    """Ask the host what happened to an operation. Never re-runs anything."""
    selector = parse_operation_id(operation_id)
    client = client_of(ctx)
    if wait:
        seconds = parse_duration_ms(wait_timeout) / 1000 if wait_timeout else DEFAULT_WAIT_S
        env = client.wait_final(selector.operation_id, timeout_s=seconds)
    else:
        env = client.roundtrip(OperationGetRequest(params=selector))
    _emit(env, as_json=as_json)
    code = exit_code_for_status(env.status)
    if code != ExitCode.OK:
        raise typer.Exit(int(code))


@app.command("cancel")
@guard
def cancel(
    ctx: typer.Context,
    operation_id: Annotated[str, typer.Argument(help="Operation id of a running `exec`.")],
    wait_timeout: Annotated[
        str | None,
        typer.Option("--wait-timeout", help="How long to wait for the cancellation to take effect (default 30s)."),
    ] = None,
    as_json: JsonOption = False,
) -> None:
    """Ask the host to cancel a running command, then report how it ended.

    Cancellation is a *request*: the run ends when the host has stopped the workload and recorded
    the result, and that is what is reported. Exit status is ``0`` once the operation is final
    (cancelled, or it finished first), ``3`` if the host refused, ``5`` if it is still not final.
    """
    selector = parse_operation_id(operation_id)
    client = client_of(ctx)
    first = client.cancel(selector.operation_id)
    if first.status in {OperationStatus.REJECTED, OperationStatus.CONFLICT}:
        # The host refused the cancellation itself (unknown id, not cancellable, not running here).
        _emit(first, as_json=as_json)
        raise typer.Exit(int(exit_code_for_status(first.status)))
    seconds = parse_duration_ms(wait_timeout) / 1000 if wait_timeout else DEFAULT_CANCEL_SETTLE_S
    final = first if first.status.is_final else client.wait_final(selector.operation_id, timeout_s=seconds)
    _emit(final, as_json=as_json)
    if not final.status.is_final:
        raise typer.Exit(int(ExitCode.UNKNOWN))
