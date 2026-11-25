"""``acf snapshot ...``: create, list, restore, delete.

A snapshot is named by its identifier or by its name. The API has no route for one snapshot, so the SDK
finds it in the listing, once, and the command acts on the identifier and the generation it found.

``restore`` has two forms, and they are different requests: ``--into SANDBOX`` replaces what that
sandbox is with a new generation of it, and without it the snapshot becomes a sandbox of its own.
"""

from __future__ import annotations

import functools
from typing import Annotated

import typer
from agentcompute import Sandbox

from agentcompute_cli import units, views
from agentcompute_cli.common import (
    BaseUrlOpt,
    Common,
    FollowMaxOpt,
    GenerationOpt,
    JsonOpt,
    KeyOpt,
    NoWaitOpt,
    ProfileOpt,
    ProjectOpt,
    TimeoutOpt,
    VerboseOpt,
    connect,
    guard,
)
from agentcompute_cli.outcome import UsageError
from agentcompute_cli.sandbox import SandboxArg, acting_on

__all__ = ["app"]

app = typer.Typer(help="Take, list, restore and delete snapshots.", no_args_is_help=True)

SnapshotArg = Annotated[str, typer.Argument(metavar="SNAPSHOT", help="A snapshot identifier (snp-...) or a name.")]


@app.command("create")
@guard
def create(
    sandbox: SandboxArg,
    name: Annotated[
        str | None,
        typer.Option(
            "--name", metavar="NAME", help="An alias for the snapshot, unique in the project.", show_default=False
        ),
    ] = None,
    generation: GenerationOpt = None,
    idempotency_key: KeyOpt = None,
    follow_max: FollowMaxOpt = None,
    no_wait: NoWaitOpt = False,
    as_json: JsonOpt = False,
    profile: ProfileOpt = None,
    base_url: BaseUrlOpt = None,
    project: ProjectOpt = None,
    verbose: VerboseOpt = False,
    timeout: TimeoutOpt = None,
) -> None:
    """Take a snapshot of a sandbox."""
    stated = units.generation(generation)
    with connect(Common(as_json, profile, base_url, project, verbose, timeout)) as session:
        intent = session.intend(idempotency_key, follow_max, no_wait)
        handle = acting_on(session, sandbox, stated)
        taken = session.issue(
            intent,
            lambda: handle.snapshot(name, generation=stated, idempotency_key=intent.key, follow_max=intent.follow_max),
        )
        if taken is not None:
            session.conclude(intent, taken, taken.operation, functools.partial(views.show_snapshot, taken))


@app.command("list")
@guard
def list_(
    as_json: JsonOpt = False,
    profile: ProfileOpt = None,
    base_url: BaseUrlOpt = None,
    project: ProjectOpt = None,
    verbose: VerboseOpt = False,
    timeout: TimeoutOpt = None,
) -> None:
    """List the snapshots of the project."""
    with connect(Common(as_json, profile, base_url, project, verbose, timeout)) as session:
        snapshots = session.call(lambda: list(session.fabric.snapshots.list()))
        session.show_all(snapshots, functools.partial(views.show_snapshots, snapshots))


@app.command("restore")
@guard
def restore(
    snapshot: SnapshotArg,
    into: Annotated[
        str | None,
        typer.Option(
            "--into",
            metavar="SANDBOX",
            help="Restore into this sandbox, in place: it gets a new generation. Default: restore as a new sandbox.",
            show_default=False,
        ),
    ] = None,
    name: Annotated[
        str | None,
        typer.Option(
            "--name", metavar="NAME", help="Without --into: an alias for the new sandbox.", show_default=False
        ),
    ] = None,
    lifetime: Annotated[
        str | None,
        typer.Option(
            "--lifetime",
            metavar="DURATION",
            help="Without --into: how long the new sandbox may exist: 3600, 90m, 2h. Default: the platform's.",
            show_default=False,
        ),
    ] = None,
    generation: GenerationOpt = None,
    idempotency_key: KeyOpt = None,
    follow_max: FollowMaxOpt = None,
    no_wait: NoWaitOpt = False,
    as_json: JsonOpt = False,
    profile: ProfileOpt = None,
    base_url: BaseUrlOpt = None,
    project: ProjectOpt = None,
    verbose: VerboseOpt = False,
    timeout: TimeoutOpt = None,
) -> None:
    """Restore a snapshot: into a sandbox with --into, or as a new sandbox."""
    if into is not None and (name is not None or lifetime is not None):
        raise UsageError(
            "--name and --lifetime describe a new sandbox, and --into restores into one that exists: "
            "give --into, or the other two"
        )
    if into is None and generation is not None:
        raise UsageError("--generation is the generation of the sandbox named by --into, and there is none")
    stated = units.generation(generation)
    with connect(Common(as_json, profile, base_url, project, verbose, timeout)) as session:
        intent = session.intend(idempotency_key, follow_max, no_wait)
        found = session.call(session.fabric.snapshots.get, snapshot)

        def call() -> Sandbox:
            if into is None:
                return found.restore_as_new(
                    name=name,
                    lifetime=None if lifetime is None else units.quantity(lifetime),
                    idempotency_key=intent.key,
                    follow_max=intent.follow_max,
                )
            target = acting_on(session, into, stated)
            return target.restore(found, generation=stated, idempotency_key=intent.key, follow_max=intent.follow_max)

        restored = session.issue(intent, call)
        if restored is not None:
            session.conclude(intent, restored, restored.operation, functools.partial(views.show_sandbox, restored))


@app.command("delete")
@guard
def delete(
    snapshot: SnapshotArg,
    idempotency_key: KeyOpt = None,
    follow_max: FollowMaxOpt = None,
    no_wait: NoWaitOpt = False,
    as_json: JsonOpt = False,
    profile: ProfileOpt = None,
    base_url: BaseUrlOpt = None,
    project: ProjectOpt = None,
    verbose: VerboseOpt = False,
    timeout: TimeoutOpt = None,
) -> None:
    """Delete a snapshot. It is never resurrected."""
    with connect(Common(as_json, profile, base_url, project, verbose, timeout)) as session:
        intent = session.intend(idempotency_key, follow_max, no_wait)
        found = session.call(session.fabric.snapshots.get, snapshot)
        deleted = session.issue(intent, lambda: found.delete(idempotency_key=intent.key, follow_max=intent.follow_max))
        if deleted is not None:
            session.conclude(intent, deleted, deleted.operation, functools.partial(views.show_snapshot, deleted))
