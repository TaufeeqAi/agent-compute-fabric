"""``acf-local run ...`` — executions: run one in a throwaway sandbox, inspect one, read its output.

    acf-local run once --image python --cpu 2 --memory 4096 -- python experiment.py
    acf-local run inspect run-0123...
    acf-local run output run-0123... --stream stderr

``run once`` relays the guest's own stdout and stderr to this process's stdout and stderr (so it
composes in pipelines) and writes the structured report to stderr; ``--json`` gives all of it as
one document on stdout instead. Execution output is readable only through ``run inspect`` and
``run output``, by the caller that owns the execution.
"""

from __future__ import annotations

import base64
import re
from typing import Annotated, Any

import typer

from acf_cli.client import answer_document, exit_code_for, expect
from acf_cli.common import (
    JsonOption,
    TimeoutOption,
    client_of,
    error_document,
    guard,
    progress_of,
    state_of,
    timeout_of,
)
from acf_cli.errors import ExitCode, InvalidArgument
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
    relay_output,
    workload_exit_code,
)
from acf_cli.render import (
    decode_base64,
    print_json,
    render_error,
    render_note,
    render_operation,
    render_run_report,
    shown,
    write_stream,
)
from acf_cli.requests import RunOutputParams, run_inspect, run_output
from acf_cli.responses import OperationBody, OutputBody, OutputChunk, RunBody, to_wire
from acf_cli.runner import STEPS, Runner, RunReport, RunSpec
from acf_cli.sandbox import (
    AllowOpt,
    CpuOpt,
    DiskOpt,
    ImageOpt,
    LifetimeOpt,
    MemoryOpt,
    NameOpt,
    NetworkOpt,
    create_params,
)
from acf_cli.units import format_bytes
from acf_cli.wire import RUN_ID_PATTERN, NetworkMode, OutputStream

app = typer.Typer(
    help="Executions: run a command in a throwaway sandbox, inspect an execution, read its output.",
    no_args_is_help=True,
)

RunArg = Annotated[str, typer.Argument(help="Run id (run-...), as printed with the result of an execution.")]
_RUN_ID = re.compile(RUN_ID_PATTERN)


def _run_id(text: str) -> str:
    if not _RUN_ID.fullmatch(text):
        raise InvalidArgument(f"{text!r} is not a run id", hint="a run id is `run-` followed by 32 hex digits")
    return text


# ----------------------------------------------------------------------------- run once
@app.command("once")
@guard
def once(
    ctx: typer.Context,
    image: ImageOpt,
    command: CommandOpt = None,
    argv: ArgvArg = None,
    cpu: CpuOpt = 1,
    memory: MemoryOpt = "512",
    disk: DiskOpt = "1024",
    network: NetworkOpt = NetworkMode.NONE,
    allow: AllowOpt = None,
    lifetime: LifetimeOpt = None,
    name: NameOpt = None,
    shell: ShellOpt = False,
    env: EnvOpt = None,
    secret_env: SecretEnvOpt = None,
    cwd: CwdOpt = None,
    time_limit: TimeLimitOpt = None,
    max_pids: MaxPidsOpt = None,
    max_stdout: MaxStdoutOpt = None,
    max_stderr: MaxStderrOpt = None,
    keep: Annotated[
        bool, typer.Option("--keep", help="Do not destroy the sandbox afterwards (for snapshots or more commands).")
    ] = False,
    timeout: TimeoutOption = None,
    raw: RawOpt = False,
    propagate_exit_code: PropagateOpt = False,
    as_json: JsonOption = False,
) -> None:
    """Create a sandbox, start it, run one command in it and destroy it."""
    spec = RunSpec(
        create=create_params(
            image=image, cpu=cpu, memory=memory, disk=disk, network=network, allow=allow, lifetime=lifetime, name=name
        ),
        command=build_command(
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
        ),
        keep=keep,
        timeout_s=timeout_of(timeout),
    )
    report = Runner(client_of(ctx), progress_of(ctx)).run(spec)
    code = run_exit_code(report, propagate=propagate_exit_code)
    if as_json:
        print_json(run_document(report, code))
    else:
        _present_run(report, raw=raw, verbose=state_of(ctx).verbose)
    if code:
        raise typer.Exit(code)


def run_exit_code(report: RunReport, *, propagate: bool) -> int:
    """One exit code for four operations: the first thing that went wrong decides it."""
    if report.interrupted:
        return int(ExitCode.INTERRUPTED)
    if report.error is not None:
        return int(report.error.exit_code)
    if report.run is None:
        return int(ExitCode.UNRESOLVED)
    code = workload_exit_code(report.run, propagate=propagate)
    if code == 0 and report.cleanup_failed:
        # The command succeeded but the sandbox it ran in may still exist: the caller must hear about
        # that (a leaked sandbox in a loop is how a host runs out of capacity).
        return int(ExitCode.FAILED)
    return code


def run_document(report: RunReport, exit_code: int) -> dict[str, Any]:
    """``run once --json``: every step's answer, the execution's result, and what became of the sandbox."""
    return {
        "operations": dict(report.operations),
        "steps": {name: report.steps[name].to_wire() for name in STEPS if name in report.steps},
        "run": to_wire(report.run) if report.run is not None else None,
        "sandbox": (
            {"sandbox_id": report.sandbox[0], "generation": report.sandbox[1]} if report.sandbox is not None else None
        ),
        "cleanup": {"state": report.cleanup_state, "detail": report.cleanup},
        "interrupted": report.interrupted,
        "error": error_document(report.error)["error"] if report.error is not None else None,
        "exit_code": exit_code,
    }


def _present_run(report: RunReport, *, raw: bool, verbose: bool) -> None:
    if report.run is not None:
        relay_output(report.run, raw=raw)
        render_run_report(report.run, verbose=verbose)
    for name in STEPS:
        operation_id = report.operations.get(name)
        if operation_id is None:
            continue
        outcome = report.steps.get(name)
        render_note(name, f"{operation_id}  {_step_state(report, name) if outcome is not None else 'not established'}")
    render_note("cleanup", report.cleanup, alarming=report.cleanup_failed)
    if report.interrupted:
        render_note("interrupted", "the steps above are what the host had recorded when it was last asked")
    if report.error is not None:
        render_error(report.error)


def _step_state(report: RunReport, name: str) -> str:
    outcome = report.steps[name]
    if outcome.operation is None:
        refusal = outcome.refusal
        return f"REFUSED {shown(refusal.failure_class)}" if refusal is not None else "REFUSED"
    view = outcome.operation
    parts = [shown(view.state)]
    if view.effect is not None:
        parts.append(f"effect {shown(view.effect)}")
    if view.cleanup is not None:
        parts.append(f"cleanup {shown(view.cleanup)}")
    if view.cancelled_by is not None:
        parts.append(f"cancelled by {shown(view.cancelled_by)}")
    return ", ".join(parts)


# ----------------------------------------------------------------------------- run inspect
@app.command("inspect")
@guard
def inspect(ctx: typer.Context, run_id: RunArg, as_json: JsonOption = False) -> None:
    """Show the record of an execution: status, metrics, limits, artifacts.

    An execution that has not ended has no result yet; the host answers with its operation instead,
    and the exit status then states that operation's condition (8 while it is in progress).
    """
    answer = client_of(ctx).result(run_inspect(_run_id(run_id)))
    body = answer.result
    if isinstance(body, RunBody):
        if as_json:
            print_json(answer_document(answer))
        else:
            render_run_report(body.data, verbose=state_of(ctx).verbose, to_stderr=False)
        return
    view = expect(body, OperationBody).data
    if as_json:
        print_json(answer_document(answer))
    else:
        render_operation(view, answer.as_of)
        render_note("note", "this execution has no result to show; the operation above is what the host recorded")
    code = exit_code_for(view)
    if code is not ExitCode.OK:
        raise typer.Exit(int(code))


# ----------------------------------------------------------------------------- run output
@app.command("output")
@guard
def output(
    ctx: typer.Context,
    run_id: RunArg,
    stream: Annotated[OutputStream, typer.Option("--stream", help="Which stream to read.")] = OutputStream.STDOUT,
    offset: Annotated[int, typer.Option("--offset", min=0, help="Byte offset into the stored output.")] = 0,
    max_bytes: Annotated[
        int | None,
        typer.Option(
            "--max-bytes", min=1, help="Read at most this many bytes. Default: to the end.", show_default=False
        ),
    ] = None,
    raw: RawOpt = False,
    as_json: JsonOption = False,
) -> None:
    """Write the stored output of one stream of an execution to stdout.

    The host returns output in slices; this command asks for them in turn until the end of the
    stream or --max-bytes. With --json the slices are joined into one `output` result.
    """
    client = client_of(ctx)
    run = _run_id(run_id)
    data = bytearray()
    position = offset
    while True:
        want = max_bytes - len(data) if max_bytes is not None else None
        answer = client.result(run_output(RunOutputParams(run_id=run, stream=stream, offset=position, max_bytes=want)))
        chunk = expect(answer.result, OutputBody).data
        piece = decode_base64(chunk.data_b64)
        data += piece
        position += len(piece)
        if chunk.eof or not piece or (max_bytes is not None and len(data) >= max_bytes):
            break
    if as_json:
        document = answer_document(answer)
        document["result"]["data"] = _joined(chunk, offset, bytes(data))
        print_json(document)
        return
    write_stream(bytes(data), to_stderr=False, raw=raw)
    render_note(
        f"{shown(chunk.stream)} of {chunk.run_id}",
        f"bytes {offset}-{position} of {format_bytes(chunk.stored_bytes)} stored "
        f"({format_bytes(chunk.produced_bytes)} produced; {shown(chunk.completeness)})"
        + ("" if chunk.eof else "; more follows: continue with --offset " + str(position)),
    )


def _joined(last: OutputChunk, offset: int, data: bytes) -> dict[str, Any]:
    """Several slices as the one slice they add up to."""
    document = to_wire(last)
    document["offset"] = offset
    document["data_b64"] = base64.b64encode(data).decode("ascii")
    return document
