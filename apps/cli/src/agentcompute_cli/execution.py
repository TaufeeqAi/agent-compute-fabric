"""``acf exec ...``: run one command in a sandbox, look at it, read what it wrote, cancel it.

**The command is an argument vector.** It is everything after ``--``, passed as the list it is: no shell
is involved and nothing is joined or split. ``--shell 'text'`` is the one way to hand over a command
line, and it says what it does: it sends ``/bin/sh -c text``.

**Two questions are kept apart.** Whether the operation succeeded decides exit statuses 3 to 10. Whether
the command it ran exited with status 0 is a *result* of a successful operation: ``acf exec run`` exits
1 when it did not, and the command's own status and signal are in the view.

**Nothing here cancels anything by itself.** Ctrl-C, the follow bound and a closed pipe stop the waiting
and nothing more. ``acf exec cancel`` is the explicit request.
"""

from __future__ import annotations

import enum
import functools
import sys
from typing import Annotated, Final, cast

import typer
from agentcompute import Execution, OutputSummary
from typer.core import TyperCommand

from agentcompute_cli import render, units, views
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
    note,
)
from agentcompute_cli.outcome import ExitCode, UsageError
from agentcompute_cli.sandbox import SandboxArg, acting_on

__all__ = ["app"]

app = typer.Typer(help="Run a command in a sandbox, read its output, cancel it.", no_args_is_help=True)

ExecutionArg = Annotated[str, typer.Argument(metavar="EXECUTION", help="An execution identifier (exe-...).")]

_SEPARATOR: Final = "--"
_SEPARATED: Final = "agentcompute_cli.execution.separated"
_EXITED: Final = "EXITED"
_UNKNOWN: Final = "UNKNOWN"
_COMPLETE: Final = "COMPLETE"


class Stream(enum.StrEnum):
    STDOUT = "stdout"
    STDERR = "stderr"


class _Separated(TyperCommand):
    """A command that knows whether its command line had the ``--`` that ends this tool's own options.

    The parser consumes the separator without a trace. Without it, an option of the command to run
    could be taken for an option of this tool, silently: ``acf exec run box tool --verbose`` would run
    ``tool`` without its flag.
    """

    def parse_args(self, ctx: object, args: list[str]) -> list[str]:
        context = cast("typer.Context", ctx)
        context.meta[_SEPARATED] = _SEPARATOR in args
        return super().parse_args(context, args)


def _exited_cleanly(execution: Execution) -> bool:
    """The command ended by itself with status 0. A status this version does not know is not that."""
    return execution.status == _EXITED and execution.exit_code == 0


def _relay(session: Session, execution: Execution, stream: Stream, summary: OutputSummary | None) -> None:
    """Write one stream of what the command wrote to the stream of the same name."""
    if summary is not None and summary.stored_bytes == 0:
        return
    render.write_guest_bytes(session.call(execution.read, stream.value), err=stream is Stream.STDERR)
    if summary is not None and summary.completeness != _COMPLETE:
        note(
            f"{stream.value} is {render.safe_line(summary.completeness, limit=render.CELL_MAX)}: "
            f"{summary.stored_bytes} of {summary.produced_bytes} bytes were stored"
        )


@app.command("run", cls=_Separated)
@guard
def run(
    ctx: typer.Context,
    sandbox: SandboxArg,
    argv: Annotated[
        list[str] | None,
        typer.Argument(
            metavar="ARGV",
            help="The command and its arguments, after `--`. Passed as they are: no shell, no joining.",
            show_default=False,
        ),
    ] = None,
    shell: Annotated[
        str | None,
        typer.Option(
            "--shell",
            metavar="TEXT",
            help="Run this command line through the sandbox's shell instead: sends /bin/sh -c TEXT.",
            show_default=False,
        ),
    ] = None,
    cwd: Annotated[
        str | None,
        typer.Option("--cwd", metavar="PATH", help="Working directory inside the sandbox.", show_default=False),
    ] = None,
    env: Annotated[
        list[str] | None,
        typer.Option("--env", metavar="NAME=VALUE", help="An environment variable of the command. Repeatable."),
    ] = None,
    timeout: Annotated[
        str | None,
        typer.Option(
            "--timeout",
            metavar="DURATION",
            help="How long the command may run on the host: 90, 90s, 10m. Default: the platform's. "
            "It has nothing to do with how long this tool waits.",
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
    request_timeout: Annotated[
        str | None,
        typer.Option(
            "--request-timeout",
            metavar="DURATION",
            help="How long one HTTP request may take: 90, 90s, 2m. Default: 120s. "
            "(On this command --timeout bounds the command itself.)",
            show_default=False,
        ),
    ] = None,
) -> None:
    """Run one command in a started sandbox:  acf exec run SANDBOX -- python -V

    Its standard output is written to standard output and its standard error to standard error. The
    exit status is 0 if the command exited with status 0, and 1 if it did not.
    """
    if argv and shell is not None:
        raise UsageError("give either a command after `--` or --shell, not both")
    if not argv and shell is None:
        raise UsageError(
            "there is nothing to run", next_step="Put the command after `--`: acf exec run SANDBOX -- python -V"
        )
    if argv and not ctx.meta.get(_SEPARATED, False):
        raise UsageError(
            "the command to run goes after `--`",
            next_step="Write: acf exec run SANDBOX [OPTIONS] -- COMMAND [ARGUMENTS]. Without the `--`, an option "
            "of your command could be taken for an option of this tool.",
        )
    stated = units.generation(generation)
    variables = units.environment(env)
    limit = None if timeout is None else units.quantity(timeout)
    with connect(Common(as_json, profile, base_url, project, verbose, request_timeout)) as session:
        intent = session.intend(idempotency_key, follow_max, no_wait)
        handle = acting_on(session, sandbox, stated)

        def start() -> Execution:
            if shell is not None:
                return handle.exec_shell(
                    shell,
                    cwd=cwd,
                    env=variables,
                    timeout=limit,
                    generation=stated,
                    idempotency_key=intent.key,
                    follow_max=intent.follow_max,
                )
            return handle.exec(
                argv or [],
                cwd=cwd,
                env=variables,
                timeout=limit,
                generation=stated,
                idempotency_key=intent.key,
                follow_max=intent.follow_max,
            )

        execution = session.issue(intent, start)
        if execution is None:
            return
        if intent.no_wait or session.as_json:
            # One JSON document, or the operation alone: what the command wrote is read with `acf exec output`.
            session.conclude(intent, execution, execution.operation, functools.partial(views.show_execution, execution))
        else:
            session.trace(execution.request_id)
            _relay(session, execution, Stream.STDOUT, execution.stdout)
            _relay(session, execution, Stream.STDERR, execution.stderr)
        if intent.no_wait or _exited_cleanly(execution):
            return
        if not session.as_json:
            note(
                f"the command did not exit with status 0: status {render.safe_line(execution.status or '-')}, "
                f"exit code {render.safe_line(execution.exit_code if execution.exit_code is not None else '-')} "
                f"(execution {render.safe_line(execution.execution_id, limit=render.IDENTIFIER_MAX)})"
            )
        sys.stdout.flush()
        raise typer.Exit(int(ExitCode.COMMAND_FAILED))


@app.command("status")
@guard
def status(
    execution: ExecutionArg,
    as_json: JsonOpt = False,
    profile: ProfileOpt = None,
    base_url: BaseUrlOpt = None,
    project: ProjectOpt = None,
    verbose: VerboseOpt = False,
    timeout: TimeoutOpt = None,
) -> None:
    """Show the state of an execution and, once it has ended, its result.

    A read: it exits 0 when the platform answered, whatever the execution's state, with one exception.
    An execution whose state is UNKNOWN exits 5, because an unknown outcome never exits 0.
    """
    with connect(Common(as_json, profile, base_url, project, verbose, timeout)) as session:
        found = session.call(session.fabric.executions.get, execution)
        session.show(found, functools.partial(views.show_execution, found))
        if found.state == _UNKNOWN:
            note(
                "the outcome of this execution is not known: it is neither success nor failure. "
                "Inspect the sandbox before acting again"
            )
            sys.stdout.flush()
            raise typer.Exit(int(ExitCode.OUTCOME_UNKNOWN))


@app.command("cancel")
@guard
def cancel(
    execution: ExecutionArg,
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
    """Cancel a running execution on the host. The only way to stop a command without stopping its sandbox.

    The cancel is the first and only request: nothing is read before it. Stopping a command takes a
    privilege away, and must not wait behind a read that a rate limit could refuse.
    """
    with connect(Common(as_json, profile, base_url, project, verbose, timeout)) as session:
        intent = session.intend(idempotency_key, follow_max, no_wait)
        named = session.call(session.fabric.executions.handle, execution)
        cancelled = session.issue(
            intent, lambda: named.cancel(idempotency_key=intent.key, follow_max=intent.follow_max)
        )
        if cancelled is not None:
            session.conclude(intent, cancelled, cancelled.operation, functools.partial(views.show_execution, cancelled))


@app.command("output")
@guard
def output(
    execution: ExecutionArg,
    stream: Annotated[Stream, typer.Option("--stream", help="Which stream to read.")] = Stream.STDOUT,
    offset: Annotated[int, typer.Option("--offset", min=0, metavar="N", help="Byte offset to read from.")] = 0,
    max_bytes: Annotated[
        int | None,
        typer.Option(
            "--max-bytes",
            min=1,
            metavar="N",
            help="Read at most this many bytes. Default: one chunk.",
            show_default=False,
        ),
    ] = None,
    raw: Annotated[
        bool,
        typer.Option(
            "--raw",
            help="Write the bytes exactly as they are. Refused when standard output is a terminal, unless --force.",
        ),
    ] = False,
    force: Annotated[
        bool,
        typer.Option(
            "--force", help="With --raw: write the bytes to a terminal as they are, escape sequences included."
        ),
    ] = False,
    as_json: JsonOpt = False,
    profile: ProfileOpt = None,
    base_url: BaseUrlOpt = None,
    project: ProjectOpt = None,
    verbose: VerboseOpt = False,
    timeout: TimeoutOpt = None,
) -> None:
    """Read a slice of what an execution wrote, by stream and byte offset.

    To a terminal the bytes are shown as safe text. To a pipe or a file they are written exactly as they
    are. Where the slice stands in its stream, and how to continue, is said on standard error.
    """
    if force and not raw:
        raise UsageError("--force only applies together with --raw")
    if raw and as_json:
        raise UsageError("--raw writes bytes and --json writes a document: give one of them")
    if raw and not force and sys.stdout.isatty():
        raise UsageError(
            "--raw would write what a sandbox produced to this terminal as it is, escape sequences included",
            next_step="Send it to a file or a pipe, leave --raw out to see it as safe text, or add --force.",
        )
    with connect(Common(as_json, profile, base_url, project, verbose, timeout)) as session:
        # The slice is asked for by the identifier. Whether the execution exists, and whether it has
        # output to read yet, is the platform's answer to that one request.
        named = session.call(session.fabric.executions.handle, execution)
        chunk = session.call(named.output, stream.value, offset=offset, max_bytes=max_bytes)
        session.trace(chunk.request_id)
        if session.as_json:
            render.write_json(chunk.raw)
            return
        render.write_guest_bytes(chunk.data, raw=raw)
        views.show_chunk_status(chunk)
