"""``acf-local run`` (the Phase 1 milestone) and ``acf-local exec``.

    acf-local run --image python --cpu 2 --memory 4096 --network none --command "python experiment.py"

produces ``run_id``, exit code, stdout, stderr, metrics and artifact references, then tears the
sandbox down. ``--json`` gives all of it as one JSON document on stdout; without it the guest's
own stdout/stderr are relayed to this process's stdout/stderr (so the command composes in
pipelines) and the structured report goes to stderr.

The host does **not** run the command in a shell. ``--command "a b"`` is split POSIX-style into
``argv``; use ``--shell`` (or ``-- sh -c '...'``) to opt into shell semantics explicitly.
"""

from __future__ import annotations

import shlex
from typing import Annotated, Any

import typer

from acf_cli.client import HostClient, raise_for_status
from acf_cli.common import JsonOption, client_of, guard, progress_of, state_of
from acf_cli.errors import AcfCliError, ExitCode, InvalidArgument, OutcomeUnknown
from acf_cli.models import CommandSpec, ExecParams, ExecRequest, RunLimitsRequest, RunResult
from acf_cli.render import (
    decode_capture,
    print_json,
    render_cleanup,
    render_error,
    render_operation_lines,
    render_run_report,
    write_stream,
)
from acf_cli.resolve import expect, resolve_sandbox
from acf_cli.runner import EXEC_MARGIN_S, EXEC_UNBOUNDED_S, Runner, RunReport, RunSpec, cancel_and_settle
from acf_cli.sandbox import NetworkChoice
from acf_cli.units import parse_bytes, parse_duration_ms, parse_env, parse_memory_mib

CommandOpt = Annotated[
    str | None, typer.Option("--command", "-c", help="Command line, split POSIX-style into argv (no shell).")
]
ShellOpt = Annotated[
    bool, typer.Option("--shell", help="Run --command via /bin/sh -c (shell syntax: pipes, globs, &&).")
]
ArgvArg = Annotated[
    list[str] | None,
    typer.Argument(help="Command and arguments, after `--` (alternative to --command).", show_default=False),
]
EnvOpt = Annotated[
    list[str] | None,
    typer.Option("--env", "-e", help="KEY=VALUE (repeatable). The name must be on the policy allowlist."),
]
CwdOpt = Annotated[
    str | None, typer.Option("--cwd", help="Working directory inside the guest (must be allowed by policy).")
]
TimeoutOpt = Annotated[
    str | None, typer.Option("--timeout", help="Run time limit: 90, 90s, 1500ms, 2m. Default: the policy default.")
]
MaxPidsOpt = Annotated[int | None, typer.Option("--max-pids", min=1, help="Process/thread limit inside the guest.")]
MaxStdoutOpt = Annotated[str | None, typer.Option("--max-stdout", help="Captured stdout limit: 65536, 64KiB, 1MiB.")]
MaxStderrOpt = Annotated[str | None, typer.Option("--max-stderr", help="Captured stderr limit.")]
RawOpt = Annotated[
    bool,
    typer.Option(
        "--raw", help="Relay guest output byte-for-byte even to a terminal (unsanitized: escape sequences take effect)."
    ),
]
PropagateOpt = Annotated[
    bool,
    typer.Option(
        "--propagate-exit-code",
        help="Exit with the command's own exit status (128+N if killed by signal N) instead of 1.",
    ),
]


def build_command(
    *,
    command: str | None,
    shell: bool,
    argv: list[str] | None,
    env: list[str] | None,
    cwd: str | None,
    timeout: str | None,
    max_pids: int | None,
    max_stdout: str | None,
    max_stderr: str | None,
) -> CommandSpec:
    """Assemble the request's :class:`CommandSpec`, rejecting ambiguity before anything is sent."""
    if command is not None and argv:
        raise InvalidArgument("give either --command or arguments after `--`, not both")
    if command is None and not argv:
        raise InvalidArgument(
            "nothing to run", hint='use --command "python experiment.py" or put the command after `--`'
        )
    if command is not None:
        if shell:
            parts = ["/bin/sh", "-c", command]
        else:
            try:
                parts = shlex.split(command)
            except ValueError as e:
                raise InvalidArgument(f"cannot parse --command: {e}", hint="balance your quotes, or use --shell") from e
    else:
        if shell:
            raise InvalidArgument("--shell applies to --command, not to an explicit argv")
        parts = list(argv or [])
    if not parts:
        raise InvalidArgument("the command is empty")
    return CommandSpec(
        argv=parts,
        env=parse_env(env or []),
        cwd=cwd,
        limits=RunLimitsRequest(
            timeout_ms=parse_duration_ms(timeout) if timeout else None,
            max_pids=max_pids,
            max_stdout_bytes=parse_bytes(max_stdout) if max_stdout else None,
            max_stderr_bytes=parse_bytes(max_stderr) if max_stderr else None,
        ),
    )


def exit_code_for(run: RunResult, *, propagate: bool) -> int:
    """0 on success; otherwise 1, or the workload's own status with ``--propagate-exit-code``."""
    if run.outcome == "SUCCEEDED":
        return int(ExitCode.OK)
    if propagate:
        if run.exit_code is not None and 0 < run.exit_code < 256:  # noqa: PLR2004
            return run.exit_code
        if run.signal is not None:
            return 128 + run.signal
    return int(ExitCode.WORKLOAD_FAILED)


def relay_output(run: RunResult, *, raw: bool) -> None:
    write_stream(decode_capture(run.stdout), to_stderr=False, raw=raw)
    write_stream(decode_capture(run.stderr), to_stderr=True, raw=raw)


def error_json(err: AcfCliError | None) -> dict[str, Any] | None:
    if err is None:
        return None
    return {
        "type": type(err).__name__,
        "message": err.message,
        "hint": err.hint,
        "operation_id": err.operation_id,
        "exit_code": int(err.exit_code),
    }


@guard
def run_command(
    ctx: typer.Context,
    image: Annotated[str, typer.Option("--image", help="Image alias; must be allowed by the host policy.")],
    command: CommandOpt = None,
    argv: ArgvArg = None,
    cpu: Annotated[int, typer.Option("--cpu", min=1, max=32, help="vCPUs: 1 or an even number up to 32.")] = 1,
    memory: Annotated[str, typer.Option("--memory", help="RAM: 4096 (MiB), 512Mi or 4Gi.")] = "512",
    disk: Annotated[str, typer.Option("--disk", help="Scratch disk: 1024 (MiB), 512Mi or 2Gi.")] = "1024",
    network: Annotated[
        NetworkChoice, typer.Option("--network", help="Phase 1 supports only `none`.")
    ] = NetworkChoice.NONE,
    shell: ShellOpt = False,
    env: EnvOpt = None,
    cwd: CwdOpt = None,
    timeout: TimeoutOpt = None,
    max_pids: MaxPidsOpt = None,
    max_stdout: MaxStdoutOpt = None,
    max_stderr: MaxStderrOpt = None,
    name: Annotated[str | None, typer.Option("--name", help="Name the sandbox (useful with --keep).")] = None,
    keep: Annotated[
        bool, typer.Option("--keep", help="Do not destroy the sandbox afterwards (for snapshots / follow-up exec).")
    ] = False,
    raw: RawOpt = False,
    propagate_exit_code: PropagateOpt = False,
    as_json: JsonOption = False,
) -> None:
    """Run a command in a fresh, network-less microVM and report what happened."""
    spec = RunSpec(
        image=image,
        vcpus=cpu,
        memory_mib=parse_memory_mib(memory),
        disk_mib=parse_memory_mib(disk),
        command=build_command(
            command=command,
            shell=shell,
            argv=argv,
            env=env,
            cwd=cwd,
            timeout=timeout,
            max_pids=max_pids,
            max_stdout=max_stdout,
            max_stderr=max_stderr,
        ),
        name=name,
        keep=keep,
    )
    _ = network  # validated by the enum; Phase 1 only has `none`
    report = Runner(client_of(ctx), progress_of(ctx)).run(spec)
    _present_run(report, as_json=as_json, raw=raw, verbose=state_of(ctx).verbose, propagate=propagate_exit_code)


def _present_run(report: RunReport, *, as_json: bool, raw: bool, verbose: bool, propagate: bool) -> None:
    if as_json:
        print_json(
            {
                "run": report.run,
                "sandbox": report.sandbox,
                "cleanup": report.cleanup,
                "operations": report.operations,
                "interrupted": report.interrupted,
                "unresolved": report.unresolved,
                "cleanup_failed": report.cleanup_failed,
                "error": error_json(report.error),
            }
        )
    else:
        if report.run is not None:
            relay_output(report.run, raw=raw)
            render_run_report(report.run, verbose=verbose)
        render_operation_lines(report.operations)
        render_cleanup(report.cleanup)
        if report.error is not None:
            render_error(report.error)
    if report.error is not None:
        raise typer.Exit(int(report.error.exit_code))
    if report.interrupted:
        raise typer.Exit(int(ExitCode.INTERRUPTED))
    if report.run is None:
        # Interrupted-and-unresolved or otherwise without a result: say so; never claim success.
        render_error(
            OutcomeUnknown("the run finished without a result", hint="inspect the sandbox and operations listed above")
        )
        raise typer.Exit(int(ExitCode.UNKNOWN))
    code = exit_code_for(report.run, propagate=propagate)
    if code == 0 and report.cleanup_failed:
        # The run succeeded but the sandbox it created may still exist: that is a platform failure the
        # caller must hear about (a leaked VM in a loop is how a host runs out of capacity).
        code = int(ExitCode.FAILED)
    if code != 0:
        raise typer.Exit(code)


@guard
def exec_command(
    ctx: typer.Context,
    sandbox: Annotated[str, typer.Argument(help="Sandbox id or name (must be READY or COMPLETED).")],
    argv: ArgvArg = None,
    command: CommandOpt = None,
    shell: ShellOpt = False,
    env: EnvOpt = None,
    cwd: CwdOpt = None,
    timeout: TimeoutOpt = None,
    max_pids: MaxPidsOpt = None,
    max_stdout: MaxStdoutOpt = None,
    max_stderr: MaxStderrOpt = None,
    raw: RawOpt = False,
    propagate_exit_code: PropagateOpt = False,
    as_json: JsonOption = False,
) -> None:
    """Run a command in an existing sandbox:  acf-local exec NAME -- python train.py"""
    spec = build_command(
        command=command,
        shell=shell,
        argv=argv,
        env=env,
        cwd=cwd,
        timeout=timeout,
        max_pids=max_pids,
        max_stdout=max_stdout,
        max_stderr=max_stderr,
    )
    client = client_of(ctx)
    view = resolve_sandbox(client, sandbox)
    timeout_ms = spec.limits.timeout_ms
    wait_s = timeout_ms / 1000 + EXEC_MARGIN_S if timeout_ms is not None else EXEC_UNBOUNDED_S
    request = ExecRequest(
        params=ExecParams(sandbox_id=view.sandbox_id, expected_generation=view.generation, command=spec)
    )
    holder: dict[str, str] = {}
    try:
        env_out = client.mutate(
            request, io_timeout_s=wait_s, resolve_deadline_s=wait_s, on_operation=lambda op: holder.update(exec=op)
        )
    except KeyboardInterrupt:
        _report_interrupted_exec(ctx, client, holder.get("exec"), raw=raw, as_json=as_json)
        raise typer.Exit(int(ExitCode.INTERRUPTED)) from None
    run = expect(raise_for_status(env_out), RunResult)
    if as_json:
        print_json({"run": run})
    else:
        relay_output(run, raw=raw)
        render_run_report(run, verbose=state_of(ctx).verbose)
    code = exit_code_for(run, propagate=propagate_exit_code)
    if code != 0:
        raise typer.Exit(code)


def _report_interrupted_exec(
    ctx: typer.Context, client: HostClient, op_id: str | None, *, raw: bool, as_json: bool
) -> None:
    """Ctrl-C during ``exec``: cancel, learn how it ended, and say so — never leave the operator guessing."""
    if op_id is None:
        return
    settled = cancel_and_settle(client, op_id)
    if as_json:
        print_json({"run": settled.run, "interrupted": True, "operation_id": op_id, "resolved": settled.resolved})
    elif settled.run is not None:
        relay_output(settled.run, raw=raw)
        render_run_report(settled.run, verbose=state_of(ctx).verbose)
    if not settled.resolved:
        render_error(
            OutcomeUnknown(
                "interrupted, and the host did not confirm how the run ended",
                hint=f"observe it, do NOT re-run it: acf-local operation get {op_id}",
                operation_id=op_id,
            )
        )
