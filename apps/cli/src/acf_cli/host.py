"""``acf-local host ...`` — what the host is, what it is doing, and its two operator switches.

``host info`` and ``host metrics`` are reads, open to every enrolled role. ``host set-mode`` and
``host acknowledge`` are operator methods: each is a recorded operation, and one runs at a time.
"""

from __future__ import annotations

import enum
from typing import Annotated

import typer

from acf_cli.client import answer_document, expect
from acf_cli.common import (
    JsonOption,
    OperationIdOption,
    TimeoutOption,
    WaitOption,
    YesOption,
    client_of,
    conclude,
    confirm_destructive,
    guard,
    operation_id_of,
    timeout_of,
)
from acf_cli.render import print_json, render_host_change, render_host_info, render_metrics, render_note
from acf_cli.requests import host_acknowledge, host_info, host_metrics, host_set_mode
from acf_cli.responses import HostChangeBody, HostInfoBody, MetricsBody, OperationView
from acf_cli.wire import AckCondition, RequestedMode

app = typer.Typer(help="Inspect the host agent and set its mode.", no_args_is_help=True)


class ModeChoice(enum.StrEnum):
    """The two modes an operator may ask for. Every other mode is entered by the host itself."""

    DRAINING = "draining"
    SERVING = "serving"


class ConditionChoice(enum.StrEnum):
    STORE_REGRESSION = "store-regression"


_MODES = {ModeChoice.DRAINING: RequestedMode.DRAINING, ModeChoice.SERVING: RequestedMode.SERVING}
_CONDITIONS = {ConditionChoice.STORE_REGRESSION: AckCondition.STORE_REGRESSION}


def host_change_of(view: OperationView) -> None:
    """Show what an operator method changed."""
    render_host_change(expect(view.result, HostChangeBody).data)


@app.command("info")
@guard
def info(ctx: typer.Context, as_json: JsonOption = False) -> None:
    """Version, protocols, features, mode, store lineage, safety profile and the bounds a caller depends on."""
    answer = client_of(ctx).result(host_info())
    data = expect(answer.result, HostInfoBody).data
    if as_json:
        print_json(answer_document(answer))
    else:
        render_host_info(data)
        if answer.as_of is not None:
            render_note("as of", str(answer.as_of))


@app.command("metrics")
@guard
def metrics(ctx: typer.Context, as_json: JsonOption = False) -> None:
    """Counters and gauges: activity, and what is wrong right now (quarantines, failed generations, mode)."""
    answer = client_of(ctx).result(host_metrics())
    data = expect(answer.result, MetricsBody).data
    if as_json:
        print_json(answer_document(answer))
    else:
        render_metrics(data)


@app.command("set-mode")
@guard
def set_mode(
    ctx: typer.Context,
    mode: Annotated[
        ModeChoice,
        typer.Argument(
            help="`draining`: create no new privilege (for a planned restart). `serving`: leave draining.",
            case_sensitive=False,
        ),
    ],
    operation_id: OperationIdOption = None,
    wait: WaitOption = True,
    timeout: TimeoutOption = None,
    as_json: JsonOption = False,
) -> None:
    """Put the host into DRAINING, or back into SERVING. Operator only.

    While draining the host refuses every request that creates privilege (create, start, exec,
    snapshot, restore) and keeps serving stop, destroy, cancel and reads.
    """
    outcome = client_of(ctx).submit(
        host_set_mode(_MODES[mode]),
        operation_id=operation_id_of(operation_id),
        wait=wait,
        timeout_s=timeout_of(timeout),
    )
    conclude(outcome, as_json=as_json, show=host_change_of)


@app.command("acknowledge")
@guard
def acknowledge(
    ctx: typer.Context,
    condition: Annotated[
        ConditionChoice,
        typer.Argument(
            help="`store-regression`: the store is older than the system it describes, "
            "and you accept it as authoritative.",
            case_sensitive=False,
        ),
    ],
    yes: YesOption = False,
    operation_id: OperationIdOption = None,
    wait: WaitOption = True,
    timeout: TimeoutOption = None,
    as_json: JsonOption = False,
) -> None:
    """Acknowledge a condition that holds the host in CONTAINMENT. Operator only.

    After a store regression the host takes no destructive action until an operator states that
    the store it has is the one to trust. Resources that store does not describe stay untouched.
    """
    confirm_destructive(f"acknowledge {condition.value} and accept the host's store as authoritative", assume_yes=yes)
    outcome = client_of(ctx).submit(
        host_acknowledge(_CONDITIONS[condition]),
        operation_id=operation_id_of(operation_id),
        wait=wait,
        timeout_s=timeout_of(timeout),
    )
    conclude(outcome, as_json=as_json, show=host_change_of)
