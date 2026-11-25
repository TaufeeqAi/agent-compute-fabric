"""``acf sandbox ...``: create, list, inspect, start, stop, destroy.

A sandbox is named on the command line by its identifier or by its name. A name is only ever used to
find the sandbox, once: the command then acts on the identifier it found, and states the generation it
saw, so that a sandbox that was restored in the meantime refuses the request instead of running it
against a state nobody looked at.
"""

from __future__ import annotations

import functools
import re
from typing import Annotated, Final, Literal

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
    Session,
    TimeoutOpt,
    VerboseOpt,
    connect,
    guard,
)
from agentcompute_cli.outcome import UsageError
from agentcompute_cli.units import Generation

__all__ = ["SandboxArg", "acting_on", "app"]

app = typer.Typer(help="Create, list, inspect, start, stop and destroy sandboxes.", no_args_is_help=True)

SandboxArg = Annotated[str, typer.Argument(metavar="SANDBOX", help="A sandbox identifier (sbx-...) or a name.")]

#: The form of a sandbox identifier, as the API's description of itself gives it.
_SANDBOX_ID: Final = re.compile(r"sbx-[0-9a-f]{32}", re.ASCII)


def acting_on(session: Session, sandbox: str, generation: Generation | None) -> Sandbox:
    """The handle a command acts through.

    The sandbox is read first, which is where a name becomes an identifier and where the generation is
    seen. The one case without a read is a caller who states both an identifier and a generation: there
    is then nothing left to find out, and a command that removes privilege does not depend on a read.
    """
    if generation is not None and _SANDBOX_ID.fullmatch(sandbox):
        return session.call(session.fabric.sandboxes.handle, sandbox)
    return session.call(session.fabric.sandboxes.get, sandbox)


@app.command("create")
@guard
def create(
    image: Annotated[str, typer.Option("--image", metavar="IMAGE", help="Image alias, as the platform offers them.")],
    cpu: Annotated[int, typer.Option("--cpu", min=1, metavar="N", help="vCPUs.")],
    memory: Annotated[
        str, typer.Option("--memory", metavar="SIZE", help="Memory: 512 (MiB), 512MiB or 4GiB. Binary units only.")
    ],
    disk: Annotated[
        str, typer.Option("--disk", metavar="SIZE", help="Disk: 1024 (MiB), 1GiB or 20GiB. Binary units only.")
    ],
    network: Annotated[
        str | None,
        typer.Option(
            "--network",
            metavar="none|FILE",
            help="`none`: no network device. Or a JSON file holding an allowlist: "
            '{"mode": "allowlist", "entries": [{"name": "host.example", "ports": [443]}]}. Default: none.',
            show_default=False,
        ),
    ] = None,
    name: Annotated[
        str | None,
        typer.Option("--name", metavar="NAME", help="An alias, unique in the project.", show_default=False),
    ] = None,
    lifetime: Annotated[
        str | None,
        typer.Option(
            "--lifetime",
            metavar="DURATION",
            help="How long the sandbox may exist: 3600, 90m, 2h, 1d. Default: the platform's.",
            show_default=False,
        ),
    ] = None,
    no_start: Annotated[bool, typer.Option("--no-start", help="Create the sandbox and do not start it.")] = False,
    keep_on_start_failure: Annotated[
        bool,
        typer.Option(
            "--keep-on-start-failure",
            help="If the start does not succeed, keep the sandbox. Default: destroy it.",
        ),
    ] = False,
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
    """Create a sandbox and start it.

    That is two operations on the platform, issued one after the other under one idempotency key: the
    same command with the same key picks the sequence up wherever it stopped.
    """
    if no_wait and not no_start:
        raise UsageError(
            "--no-wait issues one operation and does not follow it, and creating a started sandbox is two",
            next_step="Add --no-start, and start the sandbox with `acf sandbox start` once the create has ended.",
        )
    if no_start and keep_on_start_failure:
        raise UsageError("--keep-on-start-failure says what to do when a start fails, and --no-start asks for none")
    policy: Literal["destroy", "keep"] = "keep" if keep_on_start_failure else "destroy"
    with connect(Common(as_json, profile, base_url, project, verbose, timeout)) as session:
        intent = session.intend(idempotency_key, follow_max, no_wait)
        intended_network = units.network(network)
        created = session.issue(
            intent,
            lambda: session.fabric.sandboxes.create(
                image,
                cpu=cpu,
                memory=units.quantity(memory),
                disk=units.quantity(disk),
                network=intended_network,
                name=name,
                lifetime=None if lifetime is None else units.quantity(lifetime),
                start=not no_start,
                on_start_failure=policy,
                idempotency_key=intent.key,
                follow_max=intent.follow_max,
            ),
        )
        if created is not None:
            session.conclude(intent, created, created.operation, functools.partial(views.show_sandbox, created))


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
    """List the sandboxes of the project."""
    with connect(Common(as_json, profile, base_url, project, verbose, timeout)) as session:
        sandboxes = session.call(lambda: list(session.fabric.sandboxes.list()))
        session.show_all(sandboxes, functools.partial(views.show_sandboxes, sandboxes))


@app.command("inspect")
@guard
def inspect(
    sandbox: SandboxArg,
    as_json: JsonOpt = False,
    profile: ProfileOpt = None,
    base_url: BaseUrlOpt = None,
    project: ProjectOpt = None,
    verbose: VerboseOpt = False,
    timeout: TimeoutOpt = None,
) -> None:
    """Show one sandbox, by identifier or by name."""
    with connect(Common(as_json, profile, base_url, project, verbose, timeout)) as session:
        found = session.call(session.fabric.sandboxes.get, sandbox)
        session.show(found, functools.partial(views.show_sandbox, found))


def _change(
    action: Literal["start", "stop", "destroy"],
    sandbox: str,
    generation: str | None,
    idempotency_key: str | None,
    follow_max: str | None,
    no_wait: bool,
    common: Common,
) -> None:
    """Start, stop or destroy: one operation on one sandbox, at the generation the command states."""
    stated = units.generation(generation)
    with connect(common) as session:
        intent = session.intend(idempotency_key, follow_max, no_wait)
        handle = acting_on(session, sandbox, stated)
        call = {"start": handle.start, "stop": handle.stop, "destroy": handle.destroy}[action]
        changed = session.issue(
            intent, lambda: call(generation=stated, idempotency_key=intent.key, follow_max=intent.follow_max)
        )
        if changed is not None:
            session.conclude(intent, changed, changed.operation, functools.partial(views.show_sandbox, changed))


@app.command("start")
@guard
def start(
    sandbox: SandboxArg,
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
    """Start a created or stopped sandbox."""
    common = Common(as_json, profile, base_url, project, verbose, timeout)
    _change("start", sandbox, generation, idempotency_key, follow_max, no_wait, common)


@app.command("stop")
@guard
def stop(
    sandbox: SandboxArg,
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
    """Stop a sandbox. A command that is running in it is cancelled."""
    common = Common(as_json, profile, base_url, project, verbose, timeout)
    _change("stop", sandbox, generation, idempotency_key, follow_max, no_wait, common)


@app.command("destroy")
@guard
def destroy(
    sandbox: SandboxArg,
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
    """Destroy a sandbox. It is never resurrected; its snapshots are kept."""
    common = Common(as_json, profile, base_url, project, verbose, timeout)
    _change("destroy", sandbox, generation, idempotency_key, follow_max, no_wait, common)
