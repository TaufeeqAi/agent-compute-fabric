"""``acf policy inspect`` and ``acf info``: what the credential may do, and what the platform offers.

Both are reads that change nothing. ``policy inspect`` shows the caller's own principal, project,
credential kind and effective grants, and never another credential's.
"""

from __future__ import annotations

import functools

import typer

from agentcompute_cli import views
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
)

__all__ = ["info", "policy"]

policy = typer.Typer(help="Show what the credential in use may do.", no_args_is_help=True)


@policy.command("inspect")
@guard
def inspect(
    as_json: JsonOpt = False,
    profile: ProfileOpt = None,
    base_url: BaseUrlOpt = None,
    project: ProjectOpt = None,
    verbose: VerboseOpt = False,
    timeout: TimeoutOpt = None,
) -> None:
    """Show the principal, the project, the kind and the effective grants of the credential in use."""
    with connect(Common(as_json, profile, base_url, project, verbose, timeout)) as session:
        whoami = session.call(session.fabric.whoami)
        session.show(whoami, functools.partial(views.show_whoami, whoami))


@guard
def info(
    as_json: JsonOpt = False,
    profile: ProfileOpt = None,
    base_url: BaseUrlOpt = None,
    project: ProjectOpt = None,
    verbose: VerboseOpt = False,
    timeout: TimeoutOpt = None,
) -> None:
    """Show the API versions the platform speaks, whether it serves, and what it offers this credential."""
    with connect(Common(as_json, profile, base_url, project, verbose, timeout)) as session:
        answer = session.call(session.fabric.info)
        session.show(answer, functools.partial(views.show_info, answer))
