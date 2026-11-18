"""``acf-local profile ...`` — the host's safety profile."""

from __future__ import annotations

import typer

from acf_cli.common import (
    JsonOption,
    OperationIdOption,
    TimeoutOption,
    WaitOption,
    client_of,
    conclude,
    guard,
    operation_id_of,
    timeout_of,
)
from acf_cli.host import host_change_of
from acf_cli.requests import profile_reload

app = typer.Typer(help="Reload the host's safety profile.", no_args_is_help=True)


@app.command("reload")
@guard
def reload(
    ctx: typer.Context,
    operation_id: OperationIdOption = None,
    wait: WaitOption = True,
    timeout: TimeoutOption = None,
    as_json: JsonOption = False,
) -> None:
    """Re-read the safety profile file. Operator only.

    The host verifies the file as a trusted input and validates it before anything changes: an
    invalid profile is refused and the previous one stays in force. Operations already admitted
    keep the profile they were admitted under; only later ones see the new one.
    """
    outcome = client_of(ctx).submit(
        profile_reload(), operation_id=operation_id_of(operation_id), wait=wait, timeout_s=timeout_of(timeout)
    )
    conclude(outcome, as_json=as_json, show=host_change_of)
