"""What ``sandbox exec`` and ``run once`` share: describing a command, and presenting its result.

The host does **not** run the command in a shell. ``--command "a b"`` is split POSIX-style into an
argument vector; ``--shell`` (or ``-- sh -c '...'``) opts into a shell *inside the guest*.

Two different questions are kept apart everywhere:

* *did the operation succeed?* — the host ran the command and recorded its result. That is the
  operation's state, and it decides exit codes 3 to 8;
* *did the workload succeed?* — the command exited with status 0. A non-zero exit, a signal or a
  guest-side timeout is a **result** of a successful operation, and it is exit code 1.
"""

from __future__ import annotations

import shlex
from typing import Annotated

import typer

from acf_cli.client import HostClient, Outcome, require_success
from acf_cli.errors import AcfCliError, ExitCode, InvalidArgument, ProtocolViolation
from acf_cli.render import (
    decode_base64,
    print_json,
    render_error,
    render_note,
    render_operation,
    render_refusal,
    render_run_report,
    write_stream,
)
from acf_cli.requests import CommandSpec, RunLimitsRequest, operation_cancel
from acf_cli.responses import OperationView, RunBody, RunResult
from acf_cli.units import parse_bytes, parse_duration_ms, parse_env, parse_secret_env

CommandOpt = Annotated[
    str | None, typer.Option("--command", "-c", help="Command line, split POSIX-style into argv (no shell).")
]
ShellOpt = Annotated[
    bool, typer.Option("--shell", help="Run --command via /bin/sh -c inside the guest (pipes, globs, &&).")
]
ArgvArg = Annotated[
    list[str] | None,
    typer.Argument(help="Command and arguments, after `--` (alternative to --command).", show_default=False),
]
EnvOpt = Annotated[
    list[str] | None,
    typer.Option("--env", "-e", help="KEY=VALUE (repeatable). The name must be on the safety profile's allowlist."),
]
SecretEnvOpt = Annotated[
    list[str] | None,
    typer.Option(
        "--secret-env",
        help="VARIABLE=REFERENCE (repeatable): the host delivers the secret named REFERENCE as VARIABLE. "
        "REFERENCE is the name of a secret provisioned on the host, never the secret itself.",
    ),
]
CwdOpt = Annotated[
    str | None, typer.Option("--cwd", help="Working directory inside the guest (must be permitted by the profile).")
]
TimeLimitOpt = Annotated[
    str | None,
    typer.Option("--time-limit", help="Run time limit of the command: 90, 90s, 1500ms, 2m. Default: the profile's."),
]
MaxPidsOpt = Annotated[int | None, typer.Option("--max-pids", min=1, help="Process limit inside the guest.")]
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

#: How long an interrupted execution is given to end after the host was asked to cancel it.
INTERRUPT_SETTLE_S = 30.0
_MAX_EXIT_STATUS = 255


def build_command(
    *,
    command: str | None,
    shell: bool,
    argv: list[str] | None,
    env: list[str] | None,
    secret_env: list[str] | None,
    cwd: str | None,
    time_limit: str | None,
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
    if not parts or not parts[0]:
        raise InvalidArgument("the command is empty")
    values = parse_env(env or [])
    references = parse_secret_env(secret_env or [])
    both = sorted(set(values) & set(references))
    if both:
        raise InvalidArgument(
            f"{', '.join(both)}: a variable is either a value (--env) or a secret reference, not both"
        )
    return CommandSpec(
        argv=parts,
        env=values,
        secret_env=references,
        cwd=cwd,
        limits=RunLimitsRequest(
            timeout_ms=parse_duration_ms(time_limit) if time_limit else None,
            max_pids=max_pids,
            max_stdout_bytes=parse_bytes(max_stdout) if max_stdout else None,
            max_stderr_bytes=parse_bytes(max_stderr) if max_stderr else None,
        ),
    )


def run_of(view: OperationView) -> RunResult | None:
    """The execution's result, when the operation carries one."""
    return view.result.data if isinstance(view.result, RunBody) else None


def workload_exit_code(run: RunResult, *, propagate: bool) -> int:
    """0 only for a command that exited by itself with status 0; otherwise 1, or its own status when asked."""
    if run.exited_cleanly:
        return int(ExitCode.OK)
    if propagate:
        if run.exit_code is not None and 0 < run.exit_code <= _MAX_EXIT_STATUS:
            return run.exit_code
        if run.signal is not None and 0 < run.signal < _MAX_EXIT_STATUS - 128:
            return 128 + run.signal
    return int(ExitCode.WORKLOAD_FAILED)


def relay_output(run: RunResult, *, raw: bool) -> None:
    """The guest's stdout on stdout and its stderr on stderr."""
    write_stream(decode_base64(run.stdout.data_b64), to_stderr=False, raw=raw)
    write_stream(decode_base64(run.stderr.data_b64), to_stderr=True, raw=raw)


def present_execution(outcome: Outcome, *, as_json: bool, raw: bool, verbose: bool, propagate: bool) -> None:
    """Report one execution and leave with the exit code that states both answers.

    Output that the host captured is relayed whenever there is any — a cancelled or timed-out
    execution still has output — before the operation's own condition is reported.
    """
    run = run_of(outcome.operation) if outcome.operation is not None else None
    if run is not None and not as_json:
        relay_output(run, raw=raw)
        render_run_report(run, verbose=verbose)
    view = require_success(outcome)
    if run is None:
        raise ProtocolViolation(
            f"operation {view.operation_id} succeeded without the result of an execution",
            operation_id=view.operation_id,
        )
    if as_json:
        print_json(outcome.to_wire())
    else:
        render_operation(view, outcome.as_of, to_stderr=True)
    code = workload_exit_code(run, propagate=propagate)
    if code:
        raise typer.Exit(code)


def cancel_and_settle(
    client: HostClient, operation_id: str, *, timeout_s: float = INTERRUPT_SETTLE_S
) -> Outcome | None:
    """Ask the host to cancel an execution and observe how it ended. Never raises: the caller is unwinding.

    Cancellation is itself an operation, and a *request*: the execution ends when the host has
    stopped the workload and recorded the outcome. What is returned is that record as read back —
    ``None`` when the host could not be asked.
    """
    try:
        client.submit(operation_cancel(operation_id), timeout_s=timeout_s)
        return client.follow(operation_id, timeout_s=timeout_s)
    except AcfCliError:
        return None


def report_interrupted(settled: Outcome | None, operation_id: str, *, as_json: bool, raw: bool, verbose: bool) -> None:
    """Ctrl-C during an execution: say how it ended, or say plainly that this is not known."""
    if settled is None:
        render_error(
            AcfCliError(
                "interrupted, and the host could not be asked how the execution ended",
                hint=f"it may still be running. Ask the host: acf-local operation get {operation_id}",
                operation_id=operation_id,
            )
        )
        return
    if as_json:
        print_json(settled.to_wire())
    if settled.refusal is not None:
        render_refusal(settled.refusal, settled.as_of)
        render_note("interrupted", f"the host holds no usable record of operation {operation_id}")
        return
    if settled.operation is not None:
        run = run_of(settled.operation)
        if run is not None and not as_json:
            relay_output(run, raw=raw)
            render_run_report(run, verbose=verbose)
        render_operation(settled.operation, settled.as_of, to_stderr=True)
