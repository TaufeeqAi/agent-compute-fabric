"""The ``acf-local`` command line: root application and entry point.

Command map (every command takes ``--json``):

    acf-local run     --image python --cpu 2 --memory 4096 --network none --command "python experiment.py"
    acf-local exec    NAME -- python train.py
    acf-local sandbox create|start|stop|destroy|list|inspect
    acf-local snapshot create|restore|list|inspect|delete
    acf-local evidence get RUN_ID
    acf-local operation get|cancel OPERATION_ID
    acf-local host info|metrics|reload-policy

This process is a *client*. It parses syntax, resolves names to ids, renders results and picks exit
codes (BND-01). Every decision about what is allowed, whether a transition is legal, and what
actually happened belongs to the host agent, and nothing here is trusted to enforce it.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Annotated

import typer

from acf_cli import __version__, evidence, host, operation, sandbox, snapshot
from acf_cli.client import DEFAULT_SOCKET, ClientConfig
from acf_cli.common import AppState
from acf_cli.run import exec_command, run_command

app = typer.Typer(
    name="acf-local",
    help="Run untrusted code in local, network-less microVM sandboxes — and get evidence of what happened.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,  # a traceback here would print the argv, which may carry secrets
    rich_markup_mode=None,  # help text is data, not markup
    context_settings={"help_option_names": ["-h", "--help"]},
)


def _print_version(value: bool) -> None:
    if value:
        typer.echo(f"acf-local {__version__}")
        raise typer.Exit


@app.callback()
def root(
    ctx: typer.Context,
    socket: Annotated[
        Path,
        typer.Option(
            "--socket", envvar="ACF_SOCKET", help="Control socket of the host agent.", show_default=DEFAULT_SOCKET
        ),
    ] = Path(DEFAULT_SOCKET),
    io_timeout: Annotated[
        float,
        typer.Option(
            "--io-timeout",
            envvar="ACF_IO_TIMEOUT",
            min=0.1,
            help="Seconds to wait for a prompt reply (not for `run`/`exec`, which wait for the command).",
        ),
    ] = 30.0,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Progress and extra detail on stderr.")] = False,
    version: Annotated[
        bool,
        typer.Option("--version", callback=_print_version, is_eager=True, help="Show the version and exit."),
    ] = False,
) -> None:
    _ = version  # handled by the eager callback
    ctx.obj = AppState(config=ClientConfig(socket_path=socket, io_timeout_s=io_timeout), verbose=verbose)


app.command("run")(run_command)
app.command("exec")(exec_command)
app.add_typer(sandbox.app, name="sandbox")
app.add_typer(snapshot.app, name="snapshot")
app.add_typer(evidence.app, name="evidence")
app.add_typer(operation.app, name="operation")
app.add_typer(host.app, name="host")


def run() -> None:
    """Console-script entry point."""
    try:
        app(prog_name="acf-local")
    except BrokenPipeError:
        # The reader went away (`acf-local ... | head`). Do what well-behaved Unix tools do: stop
        # quietly, and make sure the interpreter's shutdown flush does not fail a second time.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(141)  # 128 + SIGPIPE


if __name__ == "__main__":  # pragma: no cover
    run()
