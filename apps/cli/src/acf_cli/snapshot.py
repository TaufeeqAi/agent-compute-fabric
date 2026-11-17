"""``acf-local snapshot ...`` — create, restore, list, delete.

Restore is a *rollback with proof*: the host replaces the sandbox with a **new generation** built
from the snapshot's exact objects, and answers only after a deterministic guest probe confirmed the
restored state (spec §20). The CLI's job is just to name the right things and say what happened,
including the honest caveat the host attaches about restored-clone uniqueness.
"""

from __future__ import annotations

from typing import Annotated

import typer

from acf_cli.client import raise_for_status
from acf_cli.common import JsonOption, client_of, confirm_destructive, guard
from acf_cli.errors import InvalidArgument, LookupFailure, Rejected
from acf_cli.models import (
    RestoreExisting,
    RestoreNew,
    SandboxView,
    SnapshotCreateParams,
    SnapshotCreateRequest,
    SnapshotDeleteRequest,
    SnapshotRestoreParams,
    SnapshotRestoreRequest,
    SnapshotView,
)
from acf_cli.render import print_json, render_sandbox, render_snapshot, render_snapshots
from acf_cli.resolve import expect, list_snapshots, only_live_sandbox, resolve_sandbox, resolve_snapshot

app = typer.Typer(help="Create, restore, list and delete snapshots.", no_args_is_help=True)


@app.command("create")
@guard
def create(
    ctx: typer.Context,
    name: Annotated[str | None, typer.Argument(help="Snapshot name (unique). Omit for an unnamed snapshot.")] = None,
    sandbox: Annotated[
        str | None, typer.Option("--sandbox", "-s", help="Sandbox id or name. Default: the only running sandbox.")
    ] = None,
    as_json: JsonOption = False,
) -> None:
    """Snapshot a running sandbox (its memory, device state and disk)."""
    client = client_of(ctx)
    view = resolve_sandbox(client, sandbox) if sandbox else only_live_sandbox(client)
    params = SnapshotCreateParams(sandbox_id=view.sandbox_id, expected_generation=view.generation, name=name)
    snap = expect(raise_for_status(client.mutate_slow(SnapshotCreateRequest(params=params))), SnapshotView)
    if as_json:
        print_json(snap)
    else:
        render_snapshot(snap)


@app.command("restore")
@guard
def restore(
    ctx: typer.Context,
    snapshot: Annotated[str, typer.Argument(help="Snapshot id or name.")],
    sandbox: Annotated[
        str | None,
        typer.Option("--sandbox", "-s", help="Roll this sandbox back (default: the snapshot's source sandbox)."),
    ] = None,
    new: Annotated[
        bool, typer.Option("--new", help="Restore into a brand-new sandbox instead of rolling one back.")
    ] = False,
    name: Annotated[str | None, typer.Option("--name", help="Name for the new sandbox (with --new).")] = None,
    as_json: JsonOption = False,
) -> None:
    """Return a sandbox to a snapshot and verify it (a new generation of the same sandbox)."""
    if new and sandbox:
        raise InvalidArgument("--new and --sandbox are mutually exclusive")
    if name and not new:
        raise InvalidArgument("--name only applies with --new")
    client = client_of(ctx)
    snap = resolve_snapshot(client, snapshot)
    target: RestoreExisting | RestoreNew
    if new:
        target = RestoreNew(name=name)
    else:
        view = _rollback_target(ctx, snap, sandbox)
        target = RestoreExisting(sandbox_id=view.sandbox_id, expected_generation=view.generation)
    params = SnapshotRestoreParams(snapshot=snap.snapshot, target=target)
    result = expect(raise_for_status(client.mutate_slow(SnapshotRestoreRequest(params=params))), SandboxView)
    if as_json:
        print_json(result)
    else:
        render_sandbox(result)


def _rollback_target(ctx: typer.Context, snap: SnapshotView, sandbox: str | None) -> SandboxView:
    client = client_of(ctx)
    if sandbox:
        return resolve_sandbox(client, sandbox)
    if snap.source_sandbox is None:
        raise LookupFailure("this snapshot has no recorded source sandbox", hint="pass --sandbox <name-or-id> or --new")
    source_id = snap.source_sandbox[0]
    try:
        return resolve_sandbox(client, source_id)
    except Rejected as e:
        if e.failure_class == "NOT_FOUND":
            raise LookupFailure(
                f"the snapshot's source sandbox {source_id} no longer exists",
                hint="restore into a new sandbox with --new (or name another sandbox with --sandbox)",
            ) from e
        raise


@app.command("list")
@guard
def list_(ctx: typer.Context, as_json: JsonOption = False) -> None:
    """List snapshots."""
    items = list_snapshots(client_of(ctx))
    if as_json:
        print_json(items)
    else:
        render_snapshots(items)


@app.command("inspect")
@guard
def inspect(
    ctx: typer.Context,
    snapshot: Annotated[str, typer.Argument(help="Snapshot id or name.")],
    as_json: JsonOption = False,
) -> None:
    """Show one snapshot in detail."""
    snap = resolve_snapshot(client_of(ctx), snapshot)
    if as_json:
        print_json(snap)
    else:
        render_snapshot(snap)


@app.command("delete")
@guard
def delete(
    ctx: typer.Context,
    snapshot: Annotated[str, typer.Argument(help="Snapshot id or name.")],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Do not ask for confirmation.")] = False,
    as_json: JsonOption = False,
) -> None:
    """Delete a snapshot and its stored state. Irreversible."""
    client = client_of(ctx)
    snap = resolve_snapshot(client, snapshot)
    confirm_destructive(f"delete snapshot {snap.snapshot.snapshot_id} ({snap.name or 'unnamed'})", assume_yes=yes)
    result = expect(raise_for_status(client.mutate_slow(SnapshotDeleteRequest(params=snap.snapshot))), SnapshotView)
    if as_json:
        print_json(result)
    else:
        render_snapshot(result)
