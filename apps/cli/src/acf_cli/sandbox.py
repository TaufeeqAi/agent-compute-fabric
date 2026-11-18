"""``acf-local sandbox ...`` — create, start, exec, stop, destroy, inspect, list.

A sandbox is referred to by **id or name** on the command line. Names exist only to be resolved by
a read; every mutation then carries ``(sandbox_id, expected_generation)``, so acting on a sandbox
that changed in the meantime is a ``REVISION_CONFLICT``, not an accident.
"""

from __future__ import annotations

from typing import Annotated

import typer

from acf_cli.client import answer_document, expect
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
    state_of,
    timeout_of,
)
from acf_cli.errors import ExitCode, InvalidArgument, MutationInterrupted
from acf_cli.execution import (
    ArgvArg,
    CommandOpt,
    CwdOpt,
    EnvOpt,
    MaxPidsOpt,
    MaxStderrOpt,
    MaxStdoutOpt,
    PropagateOpt,
    RawOpt,
    SecretEnvOpt,
    ShellOpt,
    TimeLimitOpt,
    build_command,
    cancel_and_settle,
    present_execution,
    report_interrupted,
)
from acf_cli.render import print_json, render_listing_footer, render_note, render_sandbox, render_sandboxes
from acf_cli.requests import (
    ExecParams,
    NetworkAllowlist,
    NetworkIntent,
    NetworkNone,
    SandboxCreateParams,
    SandboxResources,
    SandboxTarget,
    exec_run,
    sandbox_create,
    sandbox_destroy,
    sandbox_inspect,
    sandbox_start,
    sandbox_stop,
)
from acf_cli.resolve import inspect_sandbox, is_sandbox_id, list_sandboxes, sandbox_target, target_of
from acf_cli.responses import OperationView, SandboxBody
from acf_cli.units import parse_allow, parse_cursor, parse_memory_mib, parse_whole_seconds
from acf_cli.wire import NetworkMode

app = typer.Typer(help="Create, start, exec, stop, destroy, inspect and list sandboxes.", no_args_is_help=True)

ImageOpt = Annotated[str, typer.Option("--image", help="Image alias; must be allowed by the safety profile.")]
CpuOpt = Annotated[int, typer.Option("--cpu", min=1, help="vCPUs: 1 or an even number.")]
MemoryOpt = Annotated[str, typer.Option("--memory", help="RAM: 4096 (MiB), 512Mi or 4Gi.")]
DiskOpt = Annotated[str, typer.Option("--disk", help="Scratch disk: 1024 (MiB), 512Mi or 2Gi.")]
NetworkOpt = Annotated[
    NetworkMode,
    typer.Option("--network", help="`none`: no network device. `allowlist`: outbound TCP to --allow entries only."),
]
AllowOpt = Annotated[
    list[str] | None,
    typer.Option(
        "--allow",
        help="Allowlist entry (repeatable, with --network allowlist): NAME:PORTS or CIDR:PORTS, "
        "e.g. pypi.org:443 or 198.51.100.0/24:5432-5433,8443.",
    ),
]
LifetimeOpt = Annotated[
    str | None,
    typer.Option(
        "--lifetime",
        help="How long the sandbox may live: 3600, 90m, 2h. Default: the profile's. The host destroys it at expiry.",
    ),
]
NameOpt = Annotated[
    str | None, typer.Option("--name", help="Alias, unique among your own live sandboxes. Never an identity.")
]
SandboxArg = Annotated[str, typer.Argument(help="Sandbox id (sbx-...) or name.")]


def network_intent(mode: NetworkMode, allow: list[str] | None) -> NetworkIntent:
    """The network a sandbox is given. There is no fallback and no implied mode: both flags must agree."""
    if mode is NetworkMode.ALLOWLIST:
        if not allow:
            raise InvalidArgument(
                "--network allowlist needs at least one --allow entry", hint="use --network none for no connectivity"
            )
        return NetworkAllowlist(entries=parse_allow(allow))
    if allow:
        raise InvalidArgument("--allow only applies with --network allowlist")
    return NetworkNone()


def create_params(
    *,
    image: str,
    cpu: int,
    memory: str,
    disk: str,
    network: NetworkMode,
    allow: list[str] | None,
    lifetime: str | None,
    name: str | None,
) -> SandboxCreateParams:
    return SandboxCreateParams(
        name=alias_of(name, "--name"),
        image=alias_of(image, "--image") or image,
        resources=SandboxResources(
            vcpus=cpu,
            memory_mib=parse_memory_mib(memory),
            disk_mib=parse_memory_mib(disk),
            network=network_intent(network, allow),
        ),
        lifetime_secs=parse_whole_seconds(lifetime, what="--lifetime") if lifetime else None,
    )


def sandbox_of(view: OperationView) -> None:
    """Show the sandbox an operation produced."""
    render_sandbox(expect(view.result, SandboxBody).data)


@app.command("create")
@guard
def create(
    ctx: typer.Context,
    image: ImageOpt,
    cpu: CpuOpt = 1,
    memory: MemoryOpt = "512",
    disk: DiskOpt = "1024",
    network: NetworkOpt = NetworkMode.NONE,
    allow: AllowOpt = None,
    lifetime: LifetimeOpt = None,
    name: NameOpt = None,
    operation_id: OperationIdOption = None,
    wait: WaitOption = True,
    timeout: TimeoutOption = None,
    as_json: JsonOption = False,
) -> None:
    """Create a sandbox: resources reserved and storage provisioned, not yet started."""
    params = create_params(
        image=image, cpu=cpu, memory=memory, disk=disk, network=network, allow=allow, lifetime=lifetime, name=name
    )
    outcome = client_of(ctx).submit(
        sandbox_create(params), operation_id=operation_id_of(operation_id), wait=wait, timeout_s=timeout_of(timeout)
    )
    conclude(outcome, as_json=as_json, show=sandbox_of)


@app.command("start")
@guard
def start(
    ctx: typer.Context,
    sandbox: SandboxArg,
    expected_generation: ExpectedGenerationOption = None,
    if_revision: IfRevisionOption = None,
    operation_id: OperationIdOption = None,
    wait: WaitOption = True,
    timeout: TimeoutOption = None,
    as_json: JsonOption = False,
) -> None:
    """Start a created sandbox: launch its runtime and wait until the guest is ready."""
    target = sandbox_target(client_of(ctx), sandbox, expected_generation=expected_generation, if_revision=if_revision)
    outcome = client_of(ctx).submit(
        sandbox_start(target), operation_id=operation_id_of(operation_id), wait=wait, timeout_s=timeout_of(timeout)
    )
    conclude(outcome, as_json=as_json, show=sandbox_of)


@app.command("exec")
@guard
def exec_(
    ctx: typer.Context,
    sandbox: SandboxArg,
    argv: ArgvArg = None,
    command: CommandOpt = None,
    shell: ShellOpt = False,
    env: EnvOpt = None,
    secret_env: SecretEnvOpt = None,
    cwd: CwdOpt = None,
    time_limit: TimeLimitOpt = None,
    max_pids: MaxPidsOpt = None,
    max_stdout: MaxStdoutOpt = None,
    max_stderr: MaxStderrOpt = None,
    expected_generation: ExpectedGenerationOption = None,
    if_revision: IfRevisionOption = None,
    operation_id: OperationIdOption = None,
    wait: WaitOption = True,
    timeout: TimeoutOption = None,
    raw: RawOpt = False,
    propagate_exit_code: PropagateOpt = False,
    as_json: JsonOption = False,
) -> None:
    """Run one command in a started sandbox:  acf-local sandbox exec NAME -- python train.py"""
    spec = build_command(
        command=command,
        shell=shell,
        argv=argv,
        env=env,
        secret_env=secret_env,
        cwd=cwd,
        time_limit=time_limit,
        max_pids=max_pids,
        max_stdout=max_stdout,
        max_stderr=max_stderr,
    )
    client = client_of(ctx)
    target = sandbox_target(client, sandbox, expected_generation=expected_generation, if_revision=if_revision)
    params = ExecParams(
        sandbox_id=target.sandbox_id,
        expected_generation=target.expected_generation,
        if_revision=target.if_revision,
        command=spec,
    )
    verbose = state_of(ctx).verbose
    try:
        outcome = client.submit(
            exec_run(params), operation_id=operation_id_of(operation_id), wait=wait, timeout_s=timeout_of(timeout)
        )
    except MutationInterrupted as e:
        # Ctrl-C cancels the command. Cancelling is a request: report how the execution really ended.
        settled = cancel_and_settle(client, e.operation_id)
        report_interrupted(settled, e.operation_id, as_json=as_json, raw=raw, verbose=verbose)
        raise typer.Exit(int(ExitCode.INTERRUPTED)) from None
    present_execution(outcome, as_json=as_json, raw=raw, verbose=verbose, propagate=propagate_exit_code)


@app.command("stop")
@guard
def stop(
    ctx: typer.Context,
    sandbox: SandboxArg,
    expected_generation: ExpectedGenerationOption = None,
    if_revision: IfRevisionOption = None,
    operation_id: OperationIdOption = None,
    wait: WaitOption = True,
    timeout: TimeoutOption = None,
    as_json: JsonOption = False,
) -> None:
    """Stop a sandbox: end its runtime and keep its storage. A stopped generation is never started again."""
    target = sandbox_target(client_of(ctx), sandbox, expected_generation=expected_generation, if_revision=if_revision)
    outcome = client_of(ctx).submit(
        sandbox_stop(target), operation_id=operation_id_of(operation_id), wait=wait, timeout_s=timeout_of(timeout)
    )
    conclude(outcome, as_json=as_json, show=sandbox_of)


@app.command("destroy")
@guard
def destroy(
    ctx: typer.Context,
    sandbox: SandboxArg,
    expected_generation: ExpectedGenerationOption = None,
    if_revision: IfRevisionOption = None,
    yes: YesOption = False,
    operation_id: OperationIdOption = None,
    wait: WaitOption = True,
    timeout: TimeoutOption = None,
    as_json: JsonOption = False,
) -> None:
    """Destroy a sandbox and everything the host holds for it. Irreversible. Its snapshots are kept."""
    client = client_of(ctx)
    if yes and is_sandbox_id(sandbox) and expected_generation is not None:
        target = SandboxTarget(sandbox_id=sandbox, expected_generation=expected_generation, if_revision=if_revision)
    else:
        view = inspect_sandbox(client, sandbox)
        target = target_of(view, expected_generation=expected_generation, if_revision=if_revision)
        confirm_destructive(
            f"destroy sandbox {view.sandbox_id} ({view.name or 'unnamed'}, generation {target.expected_generation})",
            assume_yes=yes,
        )
    outcome = client.submit(
        sandbox_destroy(target), operation_id=operation_id_of(operation_id), wait=wait, timeout_s=timeout_of(timeout)
    )
    conclude(outcome, as_json=as_json, show=sandbox_of)


@app.command("inspect")
@guard
def inspect(ctx: typer.Context, sandbox: SandboxArg, as_json: JsonOption = False) -> None:
    """Show one sandbox in detail (a read: served from committed state)."""
    answer = client_of(ctx).result(sandbox_inspect(sandbox))
    view = expect(answer.result, SandboxBody).data
    if as_json:
        print_json(answer_document(answer))
    else:
        render_sandbox(view)
        if answer.as_of is not None:
            render_note("as of", str(answer.as_of))


@app.command("list")
@guard
def list_(
    ctx: typer.Context,
    changed_since: ChangedSinceOption = None,
    limit: LimitOption = None,
    all_pages: AllOption = False,
    as_json: JsonOption = False,
) -> None:
    """List sandboxes. With --changed-since: only what changed after that cursor, destroyed ones included."""
    cursor = parse_cursor(changed_since) if changed_since is not None else None
    listing = list_sandboxes(client_of(ctx), changed_since=cursor, limit=limit, follow=all_pages)
    if as_json:
        print_json(listing.to_wire())
    else:
        render_sandboxes(listing.items)
        render_listing_footer(len(listing.items), listing.cursor, more=listing.more, as_of=listing.as_of)
