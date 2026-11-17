"""``acf-local sandbox ...`` — lifecycle commands.

A sandbox is referred to by **id or name** on the command line. Names exist only to be resolved
by a read; every mutation then carries the resolved ``(sandbox_id, generation)`` so that acting on
something that changed in the meantime is a ``CONFLICT``, not an accident (spec §12.5).
"""

from __future__ import annotations

import enum
from typing import Annotated

import typer

from acf_cli.client import raise_for_status
from acf_cli.common import JsonOption, client_of, confirm_destructive, guard
from acf_cli.models import (
    SandboxCreateParams,
    SandboxCreateRequest,
    SandboxDestroyRequest,
    SandboxResources,
    SandboxStartRequest,
    SandboxStopRequest,
    SandboxTarget,
    SandboxView,
)
from acf_cli.render import print_json, render_sandbox, render_sandboxes
from acf_cli.resolve import expect, list_sandboxes, resolve_sandbox
from acf_cli.units import parse_memory_mib

app = typer.Typer(help="Create, start, stop, inspect and destroy sandboxes.", no_args_is_help=True)


class NetworkChoice(enum.StrEnum):
    """Phase 1 vocabulary: ``none`` only (spec §18.7). Other modes are *absent*, not 'disabled'."""

    NONE = "none"


@app.command("create")
@guard
def create(
    ctx: typer.Context,
    image: Annotated[str, typer.Option("--image", help="Image alias; must be allowed by the host policy.")],
    cpu: Annotated[int, typer.Option("--cpu", min=1, max=32, help="vCPUs: 1 or an even number up to 32.")] = 1,
    memory: Annotated[str, typer.Option("--memory", help="RAM: 4096 (MiB), 512Mi or 4Gi.")] = "512",
    disk: Annotated[str, typer.Option("--disk", help="Scratch disk: 1024 (MiB), 512Mi or 2Gi.")] = "1024",
    network: Annotated[
        NetworkChoice, typer.Option("--network", help="Phase 1 supports only `none`.")
    ] = NetworkChoice.NONE,
    name: Annotated[
        str | None, typer.Option("--name", help="Optional human name (unique among live sandboxes).")
    ] = None,
    start: Annotated[bool, typer.Option("--start", help="Also start it (boot the microVM).")] = False,
    as_json: JsonOption = False,
) -> None:
    """Create a sandbox (resources reserved, not yet booted). Add --start to boot it too."""
    client = client_of(ctx)
    _ = network  # validated by the enum; Phase 1 has only `none`, which the request model pins as a literal
    params = SandboxCreateParams(
        name=name,
        image=image,
        resources=SandboxResources(
            vcpus=cpu, memory_mib=parse_memory_mib(memory), disk_mib=parse_memory_mib(disk), network="none"
        ),
    )
    view = expect(raise_for_status(client.mutate_slow(SandboxCreateRequest(params=params))), SandboxView)
    if start:
        view = _transition(ctx, SandboxStartRequest, view)
    _emit(view, as_json)


@app.command("start")
@guard
def start(
    ctx: typer.Context, sandbox: Annotated[str, typer.Argument(help="Sandbox id or name.")], as_json: JsonOption = False
) -> None:
    """Boot a created sandbox and wait until its guest agent answers."""
    client = client_of(ctx)
    _emit(_transition(ctx, SandboxStartRequest, resolve_sandbox(client, sandbox)), as_json)


@app.command("stop")
@guard
def stop(
    ctx: typer.Context, sandbox: Annotated[str, typer.Argument(help="Sandbox id or name.")], as_json: JsonOption = False
) -> None:
    """Stop a sandbox (graceful shutdown, then kill). Its disk state is kept."""
    client = client_of(ctx)
    _emit(_transition(ctx, SandboxStopRequest, resolve_sandbox(client, sandbox)), as_json)


@app.command("destroy")
@guard
def destroy(
    ctx: typer.Context,
    sandbox: Annotated[str, typer.Argument(help="Sandbox id or name.")],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Do not ask for confirmation.")] = False,
    as_json: JsonOption = False,
) -> None:
    """Destroy a sandbox and everything the host holds for it. Irreversible."""
    client = client_of(ctx)
    view = resolve_sandbox(client, sandbox)
    confirm_destructive(
        f"destroy sandbox {view.sandbox_id} ({view.name or 'unnamed'}, generation {view.generation})", assume_yes=yes
    )
    _emit(_transition(ctx, SandboxDestroyRequest, view), as_json)


@app.command("list")
@guard
def list_(ctx: typer.Context, as_json: JsonOption = False) -> None:
    """List live sandboxes."""
    items = list_sandboxes(client_of(ctx))
    if as_json:
        print_json(items)
    else:
        render_sandboxes(items)


@app.command("inspect")
@guard
def inspect(
    ctx: typer.Context, sandbox: Annotated[str, typer.Argument(help="Sandbox id or name.")], as_json: JsonOption = False
) -> None:
    """Show one sandbox in detail."""
    _emit(resolve_sandbox(client_of(ctx), sandbox), as_json)


def _transition(
    ctx: typer.Context,
    request_type: type[SandboxStartRequest] | type[SandboxStopRequest] | type[SandboxDestroyRequest],
    view: SandboxView,
) -> SandboxView:
    target = SandboxTarget(sandbox_id=view.sandbox_id, expected_generation=view.generation)
    return expect(raise_for_status(client_of(ctx).mutate_slow(request_type(params=target))), SandboxView)


def _emit(view: SandboxView, as_json: bool) -> None:
    if as_json:
        print_json(view)
    else:
        render_sandbox(view)
