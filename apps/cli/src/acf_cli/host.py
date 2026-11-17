"""``acf-local host ...`` — what is the host agent, and what is it enforcing?"""

from __future__ import annotations

from typing import Any

import typer

from acf_cli.common import JsonOption, client_of, guard
from acf_cli.models import HostInfo, HostInfoRequest, MetricsRequest, PolicyReloadRequest
from acf_cli.render import print_json, render_host_info, render_metrics
from acf_cli.resolve import expect

app = typer.Typer(help="Inspect the host agent: version, backend, policy in force, metrics.", no_args_is_help=True)


@app.command("info")
@guard
def info(ctx: typer.Context, as_json: JsonOption = False) -> None:
    """Version, protocol, backend, security profile, policy in force, journal integrity."""
    host = expect(client_of(ctx).read(HostInfoRequest()), HostInfo)
    if as_json:
        print_json(host)
    else:
        render_host_info(host)


@app.command("metrics")
@guard
def metrics(ctx: typer.Context, as_json: JsonOption = False) -> None:
    """Counters and gauges the host keeps (operations by status, live sandboxes, ...)."""
    data = expect(client_of(ctx).read(MetricsRequest()), dict)
    payload: dict[str, Any] = data
    if as_json:
        print_json(payload)
    else:
        render_metrics(payload)


@app.command("reload-policy")
@guard
def reload_policy(
    ctx: typer.Context,
    as_json: JsonOption = False,
) -> None:
    """Re-read the policy file. Administrators only; operations already admitted keep their policy.

    The host re-validates the file (ownership, permissions, schema) and swaps the policy
    atomically. A bad file is refused and the previous policy stays in force.
    """
    host = expect(client_of(ctx).read(PolicyReloadRequest()), HostInfo)
    if as_json:
        print_json(host)
    else:
        render_host_info(host)
        typer.echo(f"policy now in force: {host.policy.short()}", err=True)
