"""``acf-local snapshot ...`` — create, restore, delete, list.

A snapshot is identified by ``snapshot_id`` + ``snapshot_generation``; its name is an alias.

Restore has two distinct forms, and the command line makes the choice explicit:

* ``--into SANDBOX`` restores **in place**: the host builds a *new generation* of that sandbox from
  the snapshot, verifies it, and only then makes it current. A failed restore never costs the
  caller the sandbox they had. The sandbox keeps its expiry.
* ``--new`` restores **as a new sandbox** (generation 1), with its own name and lifetime.
"""

from __future__ import annotations

from typing import Annotated

import typer

from acf_cli.client import expect
from acf_cli.common import (
    AllOption,
    ChangedSinceOption,
    ExpectedGenerationOption,
    IfRevisionOption,
    JsonOption,
    LimitOption,
    OperationIdOption,
    TimeoutOption,
    WaitOption,
    YesOption,
    alias_of,
    client_of,
    conclude,
    confirm_destructive,
    guard,
    operation_id_of,
    timeout_of,
)
from acf_cli.errors import InvalidArgument
from acf_cli.render import print_json, render_listing_footer, render_snapshot, render_snapshots
from acf_cli.requests import (
    RestoreExisting,
    RestoreNew,
    SnapshotCreateParams,
    SnapshotRestoreParams,
    snapshot_create,
    snapshot_delete,
    snapshot_restore,
)
from acf_cli.resolve import list_snapshots, resolve_snapshot, sandbox_target
from acf_cli.responses import OperationView, SnapshotBody
from acf_cli.sandbox import LifetimeOpt, sandbox_of
from acf_cli.units import parse_cursor, parse_whole_seconds

app = typer.Typer(help="Create, restore, delete and list snapshots.", no_args_is_help=True)

SnapshotArg = Annotated[str, typer.Argument(help="Snapshot id (snp-...) or name.")]
SnapshotGenerationOpt = Annotated[
    int | None,
    typer.Option(
        "--snapshot-generation",
        min=1,
        help="The snapshot's generation. Default: looked up. With an id, giving it avoids the lookup.",
        show_default=False,
    ),
]


def snapshot_of(view: OperationView) -> None:
    """Show the snapshot an operation produced."""
    render_snapshot(expect(view.result, SnapshotBody).data)


@app.command("create")
@guard
def create(
    ctx: typer.Context,
    sandbox: Annotated[str, typer.Argument(help="Sandbox id (sbx-...) or name. It must be idle.")],
    name: Annotated[
        str | None, typer.Option("--name", help="Alias for the snapshot, unique among your own snapshots.")
    ] = None,
    expected_generation: ExpectedGenerationOption = None,
    if_revision: IfRevisionOption = None,
    operation_id: OperationIdOption = None,
    wait: WaitOption = True,
    timeout: TimeoutOption = None,
    as_json: JsonOption = False,
) -> None:
    """Snapshot an idle sandbox: its memory, device state and disk. The guest is paused for the capture."""
    alias = alias_of(name, "--name")
    client = client_of(ctx)
    target = sandbox_target(client, sandbox, expected_generation=expected_generation, if_revision=if_revision)
    params = SnapshotCreateParams(
        sandbox_id=target.sandbox_id,
        expected_generation=target.expected_generation,
        if_revision=target.if_revision,
        name=alias,
    )
    outcome = client.submit(
        snapshot_create(params), operation_id=operation_id_of(operation_id), wait=wait, timeout_s=timeout_of(timeout)
    )
    conclude(outcome, as_json=as_json, show=snapshot_of)


@app.command("restore")
@guard
def restore(
    ctx: typer.Context,
    snapshot: SnapshotArg,
    into: Annotated[
        str | None,
        typer.Option("--into", help="Restore in place: a new generation of this sandbox (id or name)."),
    ] = None,
    new: Annotated[bool, typer.Option("--new", help="Restore as a brand-new sandbox.")] = False,
    name: Annotated[str | None, typer.Option("--name", help="With --new: alias of the new sandbox.")] = None,
    lifetime: LifetimeOpt = None,
    snapshot_generation: SnapshotGenerationOpt = None,
    expected_generation: ExpectedGenerationOption = None,
    if_revision: IfRevisionOption = None,
    operation_id: OperationIdOption = None,
    wait: WaitOption = True,
    timeout: TimeoutOption = None,
    as_json: JsonOption = False,
) -> None:
    """Restore a snapshot, in place (--into) or as a new sandbox (--new), and verify the result."""
    if new == (into is not None):
        raise InvalidArgument(
            "say where to restore: --into SANDBOX (in place, a new generation) or --new (a new sandbox)"
        )
    if not new and (name is not None or lifetime is not None):
        raise InvalidArgument("--name and --lifetime apply to --new; a restore in place keeps the sandbox's own")
    if new and (expected_generation is not None or if_revision is not None):
        raise InvalidArgument("--expected-generation and --if-revision apply to --into")
    alias = alias_of(name, "--name")
    seconds = parse_whole_seconds(lifetime, what="--lifetime") if lifetime else None
    client = client_of(ctx)
    ref = resolve_snapshot(client, snapshot, generation=snapshot_generation)
    target: RestoreExisting | RestoreNew
    if into is not None:
        token = sandbox_target(client, into, expected_generation=expected_generation, if_revision=if_revision)
        target = RestoreExisting(
            sandbox_id=token.sandbox_id,
            expected_generation=token.expected_generation,
            if_revision=token.if_revision,
        )
    else:
        target = RestoreNew(name=alias, lifetime_secs=seconds)
    outcome = client.submit(
        snapshot_restore(SnapshotRestoreParams(snapshot=ref, target=target)),
        operation_id=operation_id_of(operation_id),
        wait=wait,
        timeout_s=timeout_of(timeout),
    )
    conclude(outcome, as_json=as_json, show=sandbox_of)


@app.command("delete")
@guard
def delete(
    ctx: typer.Context,
    snapshot: SnapshotArg,
    snapshot_generation: SnapshotGenerationOpt = None,
    yes: YesOption = False,
    operation_id: OperationIdOption = None,
    wait: WaitOption = True,
    timeout: TimeoutOption = None,
    as_json: JsonOption = False,
) -> None:
    """Delete a snapshot and its stored state. Irreversible. Refused while something still depends on it."""
    client = client_of(ctx)
    ref = resolve_snapshot(client, snapshot, generation=snapshot_generation)
    confirm_destructive(f"delete snapshot {ref.snapshot_id} (generation {ref.snapshot_generation})", assume_yes=yes)
    outcome = client.submit(
        snapshot_delete(ref), operation_id=operation_id_of(operation_id), wait=wait, timeout_s=timeout_of(timeout)
    )
    conclude(outcome, as_json=as_json, show=snapshot_of)


@app.command("list")
@guard
def list_(
    ctx: typer.Context,
    changed_since: ChangedSinceOption = None,
    limit: LimitOption = None,
    all_pages: AllOption = False,
    as_json: JsonOption = False,
) -> None:
    """List snapshots. With --changed-since: only what changed after that cursor, deleted ones included."""
    cursor = parse_cursor(changed_since) if changed_since is not None else None
    listing = list_snapshots(client_of(ctx), changed_since=cursor, limit=limit, follow=all_pages)
    if as_json:
        print_json(listing.to_wire())
    else:
        render_snapshots(listing.items)
        render_listing_footer(len(listing.items), listing.cursor, more=listing.more, as_of=listing.as_of)
