"""``acf auth ...``: store a key on this machine, and mint keys for agents.

**The key is never shown.** ``login`` asks for it without echo, or reads it from standard input; it
checks it with the platform and stores it. It prints who the key is and where it was stored, and at no
point the key. There is no option that takes a key: a key on a command line ends up in shell history.

**An agent gets a key of its own.** ``agent-key create`` mints one that is narrower and shorter-lived
than the developer's. Its secret is printed once, on standard output, by that command and by no other:
the platform never shows it again.
"""

from __future__ import annotations

import functools
import getpass
import sys
from pathlib import Path
from typing import Annotated

import typer
from agentcompute import AgentCredential

from agentcompute_cli import common, credentials, render, units, views
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
from agentcompute_cli.outcome import CliError, ExitCode, UsageError, describe, exit_code_for

__all__ = ["app"]

app = typer.Typer(help="Store a key on this machine, and mint keys for agents.", no_args_is_help=True)
agent_key = typer.Typer(help="Mint, list and revoke the keys of agents.", no_args_is_help=True)
app.add_typer(agent_key, name="agent-key")


def _typed_key(*, from_stdin: bool) -> str:
    """The key the person gives: read without echo, or from standard input when asked to."""
    if from_stdin:
        key = sys.stdin.read().strip()
    elif sys.stdin.isatty():
        try:
            key = getpass.getpass("API key (it is not shown): ").strip()
        except EOFError:
            # The input was closed at the prompt: that is an answer, and it is "none".
            key = ""
    else:
        raise UsageError(
            "there is no terminal to ask for the key",
            next_step="Pipe the key in and pass --key-stdin.",
        )
    if not key:
        raise UsageError("no key was given")
    return key


@app.command("login")
@guard
def login(
    key_stdin: Annotated[
        bool, typer.Option("--key-stdin", help="Read the key from standard input instead of asking for it.")
    ] = False,
    mcp_url: Annotated[
        str | None,
        typer.Option(
            "--mcp-url",
            metavar="URL",
            help="Also store the address of the platform's MCP endpoint with the profile, for `acf mcp`.",
            show_default=False,
        ),
    ] = None,
    ca_file: Annotated[
        str | None,
        typer.Option(
            "--ca-file",
            metavar="FILE",
            help="A PEM file of certificate authorities: the only ones to believe about this platform's "
            "certificate. Stored with the profile. Default: $ACF_CA_FILE, else what is stored for this address.",
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
    """Check a key with the platform and store it on this machine. The key is never printed."""
    seconds = None if timeout is None else units.duration(timeout, option="--timeout")
    name = credentials.profile_name(
        profile or credentials.environment(credentials.ENV_PROFILE) or credentials.DEFAULT_PROFILE
    )
    store = credentials.CredentialStore()
    stored = store.get(name)
    address = base_url or credentials.environment(credentials.ENV_BASE_URL) or (stored.base_url if stored else None)
    if address is None:
        raise UsageError(
            "the address of the platform is not known",
            next_step=f"Pass --base-url, or set {credentials.ENV_BASE_URL}.",
        )
    credentials.api_address(address)
    relay = credentials.endpoint_address(mcp_url) if mcp_url is not None else None
    if relay is None and stored is not None and stored.base_url == address:
        relay = stored.mcp_url
    named = ca_file or credentials.environment(credentials.ENV_CA_FILE)
    if named is None and stored is not None and stored.base_url == address:
        named = stored.ca_file
    authorities = None if named is None else credentials.ca_file_path(named)
    key = _typed_key(from_stdin=key_stdin)
    render.protect(key)
    with common.new_fabric(credentials.Settings(key, address, None, {}, authorities), timeout=seconds) as fabric:
        whoami = fabric.whoami()
    wanted = project or credentials.environment(credentials.ENV_PROJECT)
    if wanted is not None and wanted != whoami.project_id:
        # Not a UsageError: the platform was asked who the key is, so "nothing was sent" would not be true.
        raise CliError(
            f"this key belongs to project {render.safe_line(whoami.project_id, limit=render.IDENTIFIER_MAX)}, "
            "which is not the project that was named",
            exit_code=ExitCode.USAGE,
            next_step="Nothing was stored. Leave --project out, or log in with a key of that project.",
        )
    store.put(name, credentials.Profile(key, address, whoami.project_id, relay, authorities))
    if verbose:
        note(f"request {render.safe_line(whoami.request_id or '-', limit=render.IDENTIFIER_MAX)}")
    if as_json:
        render.write_json(whoami.raw)
    else:
        views.show_whoami(whoami)
    note(f"stored in {render.safe_line(store.path)}, profile {name}. The key itself was not printed.")


@app.command("logout")
@guard
def logout(profile: ProfileOpt = None) -> None:
    """Remove the stored credential of a profile from this machine.

    The key itself stays valid until it expires or is revoked: an agent key with
    `acf auth agent-key revoke`, a developer key by the operator of the platform.
    """
    name = credentials.profile_name(
        profile or credentials.environment(credentials.ENV_PROFILE) or credentials.DEFAULT_PROFILE
    )
    store = credentials.CredentialStore()
    if store.remove(name):
        note(f"removed profile {name} from {render.safe_line(store.path)}. The key itself is still valid.")
    else:
        note(f"there is no profile {name} in {render.safe_line(store.path)}: nothing was removed")


# ------------------------------------------------------------------------------------------ agent keys
@agent_key.command("create")
@guard
def create(
    label: Annotated[
        str,
        typer.Option("--label", metavar="LABEL", help="A name for the agent. Recorded with everything it does."),
    ],
    lifetime: Annotated[
        str, typer.Option("--lifetime", metavar="DURATION", help="How long the key is valid: 3600, 90m, 2h, 1d.")
    ],
    narrowing: Annotated[
        Path | None,
        typer.Option(
            "--narrowing",
            metavar="FILE",
            help="A JSON file holding a grant: a subset of what your own key may do. "
            "Default: the platform's template for agents.",
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
    """Mint a key for an agent. Its secret is printed once, on standard output, and can never be shown again."""
    grant = None if narrowing is None else units.json_file(narrowing, option="--narrowing")
    with connect(Common(as_json, profile, base_url, project, verbose, timeout)) as session:
        minted = session.call(
            session.fabric.auth.mint_agent_credential, label, lifetime=units.quantity(lifetime), narrowing=grant
        )
        session.trace(minted.request_id)
        if session.as_json:
            render.write_json(minted.raw)
            return
        secret = minted.secret
        if secret is None:
            raise CliError(
                "the platform answered the mint without the secret of the new key",
                exit_code=ExitCode.INCOMPATIBLE,
                next_step="A key may exist that nobody can use: find it with `acf auth agent-key list` and "
                "revoke it with `acf auth agent-key revoke`.",
            )
        # The one line of standard output: `KEY=$(acf auth agent-key create ...)` holds the secret and nothing else.
        render.line(render.safe_line(secret))
        views.show_credential(minted, err=True)
        note("this is the only time the secret is shown: keep it now")


@agent_key.command("list")
@guard
def list_(
    as_json: JsonOpt = False,
    profile: ProfileOpt = None,
    base_url: BaseUrlOpt = None,
    project: ProjectOpt = None,
    verbose: VerboseOpt = False,
    timeout: TimeoutOpt = None,
) -> None:
    """List the agent keys this key minted. None of them shows a secret."""
    with connect(Common(as_json, profile, base_url, project, verbose, timeout)) as session:
        minted = session.call(session.fabric.auth.agent_credentials)
        session.show_all(minted, functools.partial(views.show_credentials, minted))


def _contained(credential: AgentCredential) -> None:
    """Say what containment did, and leave with a status other than 0 if any cancel did not succeed."""
    for execution_id in credential.contained:
        note(f"cancelled execution {render.safe_line(execution_id, limit=render.IDENTIFIER_MAX)}")
    failures = credential.containment_errors
    if not credential.contained and not failures:
        note("the key had no execution in progress")
    for failure in failures:
        which = failure.execution_id or f"of operation {failure.operation_id}"
        said = describe(failure.error, key=None).headline
        note(f"could not cancel execution {render.safe_line(which)}: {render.safe_line(said)}")
    if failures:
        note(
            "next: the key is revoked, and what it started may still be running. "
            "Cancel each with `acf exec cancel EXECUTION`, or run this command again with --contain"
        )
        sys.stdout.flush()
        raise typer.Exit(int(exit_code_for(failures[0].error)))


@agent_key.command("revoke")
@guard
def revoke(
    credential_id: Annotated[
        str, typer.Argument(metavar="CREDENTIAL", help="The identifier of the agent key (crd_...).")
    ],
    contain: Annotated[
        bool,
        typer.Option(
            "--contain",
            help="Also cancel every execution the key started that has not ended. "
            "Revoking alone ends what the key may ask for, not what it already started.",
        ),
    ] = False,
    as_json: JsonOpt = False,
    profile: ProfileOpt = None,
    base_url: BaseUrlOpt = None,
    project: ProjectOpt = None,
    verbose: VerboseOpt = False,
    timeout: TimeoutOpt = None,
) -> None:
    """Revoke an agent key. Revoking twice is the same as revoking once."""
    with connect(Common(as_json, profile, base_url, project, verbose, timeout)) as session:
        revoked = session.call(session.fabric.auth.revoke_agent_credential, credential_id, contain=contain)
        session.show(revoked, functools.partial(views.show_credential, revoked))
        if contain:
            _contained(revoked)
