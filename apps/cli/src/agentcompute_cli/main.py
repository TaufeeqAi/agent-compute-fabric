"""The ``acf`` command line: the root application and the entry point.

Command map:

    acf auth       login | logout | agent-key create | agent-key list | agent-key revoke
    acf policy     inspect
    acf info
    acf sandbox    create | list | inspect | start | stop | destroy
    acf exec       run | status | cancel | output
    acf snapshot   create | list | restore | delete
    acf operation  get | list
    acf mcp

This program is a client of the platform's public interfaces and of nothing else: the public API,
through the Python SDK, and for ``acf mcp`` the platform's MCP endpoint. It never talks to a host. It
sends nothing anywhere but to the configured platform: no update check and no telemetry.
"""

from __future__ import annotations

import sys
from typing import Annotated

import agentcompute
import typer

from agentcompute_cli import about, auth, execution, operation, render, sandbox, snapshot
from agentcompute_cli import mcp as relay_command
from agentcompute_cli._version import __version__

__all__ = ["app", "main"]

app = typer.Typer(
    name="acf",
    no_args_is_help=True,
    add_completion=False,
    # A pretty traceback can show the values of local variables, and one of them is the key.
    pretty_exceptions_enable=False,
    # Help text is data, not markup.
    rich_markup_mode=None,
    context_settings={"help_option_names": ["-h", "--help"]},
)


def _print_version(value: bool) -> None:
    if value:
        # The SDK is named by what it is, not by a package name: a name is a thing someone could go and install.
        typer.echo(f"acf {__version__} (SDK {agentcompute.__version__})")
        raise typer.Exit


@app.callback()
def root(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_print_version, is_eager=True, help="Show the version and exit."),
    ] = False,
) -> None:
    """Command-line client of Agent Compute Fabric: sandboxes, commands in them, snapshots and operations.

    Every command takes --help. A command that calls the platform takes --json, --profile, --base-url,
    --project, --verbose and --timeout. The exit status says how the command ended: 0 done, 2 usage,
    3 refused, 4 failed with nothing applied, 5 outcome unknown, 6 unreachable, 7 not this API,
    8 unresolved, 9 outcome lost, 10 still running.
    """
    _ = version  # handled by the eager callback


app.add_typer(auth.app, name="auth")
app.add_typer(about.policy, name="policy")
app.command("info", short_help="Show what the platform speaks and offers.")(about.info)
app.add_typer(sandbox.app, name="sandbox")
app.add_typer(execution.app, name="exec")
app.add_typer(snapshot.app, name="snapshot")
app.add_typer(operation.app, name="operation")
app.command("mcp", short_help="Relay the agent protocol over stdio.")(relay_command.mcp)


def main() -> None:
    """Console-script entry point."""
    for stream in (sys.stdout, sys.stderr):
        render.lenient(stream)
    app(prog_name="acf")


if __name__ == "__main__":  # pragma: no cover
    main()
