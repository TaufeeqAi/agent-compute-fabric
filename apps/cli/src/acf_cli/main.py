"""The ``acf-local`` command line: root application and entry point.

Command map (every command takes ``--json``):

    acf-local sandbox    create | start | exec | stop | destroy | inspect | list
    acf-local snapshot   create | restore | delete | list
    acf-local operation  get | list | cancel
    acf-local run        once | inspect | output
    acf-local host       info | metrics | set-mode | acknowledge
    acf-local profile    reload
    acf-local quarantine release

This process is a *client* of the host agent, speaking protocol ``acf.host/2`` over the host's
local socket or its mutual TLS endpoint. It parses syntax, resolves names to ids, follows
operations, renders answers and picks exit codes. Every decision about who may ask, what is
allowed, whether a transition is legal and what actually happened belongs to the host, and nothing
here is trusted to enforce it.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated

import typer

from acf_cli import __version__, host, operation, profile, quarantine, run, sandbox, snapshot
from acf_cli.client import DEFAULT_SCOPE, ClientConfig
from acf_cli.common import AppState
from acf_cli.transport import DEFAULT_SOCKET, Endpoint, TlsEndpoint, UnixEndpoint
from acf_cli.wire import LABEL_PATTERN, MAX_ON_BEHALF_OF_CHARS, MAX_OWNER_SCOPE_CHARS

app = typer.Typer(
    name="acf-local",
    help="Reference client of the Agent Compute Fabric host agent: sandboxes, snapshots, executions and operations.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,  # a traceback here would print the argv, which may carry sensitive values
    rich_markup_mode=None,  # help text is data, not markup
    context_settings={"help_option_names": ["-h", "--help"]},
)

_LABEL = re.compile(LABEL_PATTERN)
_MAX_PORT = 65535


def _print_version(value: bool) -> None:
    if value:
        typer.echo(f"acf-local {__version__}")
        raise typer.Exit


def _label(value: str, option: str, limit: int) -> str:
    if not _LABEL.fullmatch(value) or len(value) > limit:
        raise typer.BadParameter(f"must be 1-{limit} characters of [A-Za-z0-9._:/@=+-]", param_hint=option)
    return value


def _host_and_port(address: str) -> tuple[str, int]:
    """``host:port``, ``[v6-address]:port``."""
    host_part, sep, port = address.rpartition(":")
    name = host_part.removeprefix("[").removesuffix("]")
    if not sep or not name or not port.isdecimal() or not 0 < int(port) <= _MAX_PORT:
        raise typer.BadParameter("must be HOST:PORT, for example host-1.example:7443", param_hint="--tls")
    return name, int(port)


def _typed(ctx: typer.Context, parameter: str) -> bool:
    """Whether an option was given on the command line, as opposed to the environment or a default."""
    source = ctx.get_parameter_source(parameter)
    return source is not None and source.name == "COMMANDLINE"


def _endpoint(
    ctx: typer.Context,
    socket: Path,
    tls: str | None,
    cert: Path | None,
    key: Path | None,
    ca: Path | None,
    server_name: str | None,
) -> Endpoint:
    """The endpoint the options name.

    What is typed on the command line is a statement, and it has to be consistent. What comes from
    the environment is a default, and a default that does not apply is not an error: ``--socket``
    on the command line reaches the local socket although ``$ACF_TLS`` is set, and the TLS file
    variables are ignored when no TLS endpoint is named.
    """
    socket_typed = _typed(ctx, "socket")
    if socket_typed and _typed(ctx, "tls"):
        raise typer.BadParameter("--socket and --tls name two different endpoints; give one", param_hint="--tls")
    if tls is None or socket_typed:
        for option, parameter in (
            ("--cert", "cert"),
            ("--key", "key"),
            ("--ca", "ca"),
            ("--server-name", "server_name"),
        ):
            if _typed(ctx, parameter):
                raise typer.BadParameter("only applies together with --tls", param_hint=option)
        return UnixEndpoint(socket)
    if cert is None or key is None:
        raise typer.BadParameter(
            "the host's network endpoint is mutual TLS: --cert and --key "
            "(your client certificate and its private key) are required",
            param_hint="--tls",
        )
    host_name, port = _host_and_port(tls)
    return TlsEndpoint(
        host=host_name, port=port, certificate=cert, private_key=key, trust_anchors=ca, server_name=server_name
    )


@app.callback()
def root(
    ctx: typer.Context,
    socket: Annotated[
        Path,
        typer.Option(
            "--socket",
            envvar="ACF_SOCKET",
            help="The host's local socket. The host identifies you by the credentials the kernel reports.",
            show_default=DEFAULT_SOCKET,
        ),
    ] = Path(DEFAULT_SOCKET),
    tls: Annotated[
        str | None,
        typer.Option(
            "--tls",
            envvar="ACF_TLS",
            help="HOST:PORT of the host's network endpoint (mutual TLS 1.3), instead of the local socket.",
            show_default=False,
        ),
    ] = None,
    cert: Annotated[
        Path | None,
        typer.Option(
            "--cert", envvar="ACF_TLS_CERT", help="With --tls: your client certificate (PEM).", show_default=False
        ),
    ] = None,
    key: Annotated[
        Path | None,
        typer.Option(
            "--key", envvar="ACF_TLS_KEY", help="With --tls: its private key (PEM, no passphrase).", show_default=False
        ),
    ] = None,
    ca: Annotated[
        Path | None,
        typer.Option(
            "--ca",
            envvar="ACF_TLS_CA",
            help="With --tls: PEM file of the authority that signed the host's certificate. "
            "When given, the system trust store is not used.",
            show_default=False,
        ),
    ] = None,
    server_name: Annotated[
        str | None,
        typer.Option(
            "--server-name",
            envvar="ACF_TLS_SERVER_NAME",
            help="With --tls: the name the host's certificate must be valid for. Default: the HOST of --tls.",
            show_default=False,
        ),
    ] = None,
    scope: Annotated[
        str,
        typer.Option(
            "--scope",
            envvar="ACF_SCOPE",
            help="Owner scope: an opaque label attached to everything you create. As a caller you see "
            "and act on records of your own scope only.",
        ),
    ] = DEFAULT_SCOPE,
    on_behalf_of: Annotated[
        str | None,
        typer.Option(
            "--on-behalf-of",
            envvar="ACF_ON_BEHALF_OF",
            help="Opaque label recorded with every operation (for example the user or job you act for). "
            "Never compared.",
            show_default=False,
        ),
    ] = None,
    connect_timeout: Annotated[
        float,
        typer.Option(
            "--connect-timeout", envvar="ACF_CONNECT_TIMEOUT", min=0.1, help="Seconds to connect and authenticate."
        ),
    ] = 5.0,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Progress and extra detail on stderr.")] = False,
    version: Annotated[
        bool,
        typer.Option("--version", callback=_print_version, is_eager=True, help="Show the version and exit."),
    ] = False,
) -> None:
    _ = version  # handled by the eager callback
    config = ClientConfig(
        endpoint=_endpoint(ctx, socket, tls, cert, key, ca, server_name),
        owner_scope=_label(scope, "--scope", MAX_OWNER_SCOPE_CHARS),
        on_behalf_of=_label(on_behalf_of, "--on-behalf-of", MAX_ON_BEHALF_OF_CHARS)
        if on_behalf_of is not None
        else None,
        connect_timeout_s=connect_timeout,
    )
    ctx.obj = AppState(config=config, verbose=verbose)


app.add_typer(sandbox.app, name="sandbox")
app.add_typer(snapshot.app, name="snapshot")
app.add_typer(operation.app, name="operation")
app.add_typer(run.app, name="run")
app.add_typer(host.app, name="host")
app.add_typer(profile.app, name="profile")
app.add_typer(quarantine.app, name="quarantine")


def main() -> None:
    """Console-script entry point."""
    app(prog_name="acf-local")


if __name__ == "__main__":  # pragma: no cover
    main()
