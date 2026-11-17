"""``acf-local evidence ...`` — the durable record of what a run did.

Every run leaves an *evidence record* in the host's journal: outcome, exit status or signal,
metrics, the resource limits that applied and what the host observed against them, and the
captured output (spilled to content-addressed artifacts when large). ``evidence get RUN_ID``
reads it back — the same record ``acf-local run`` printed, available later and from anywhere
the socket is reachable.

Exit status says whether the record could be fetched and the run is finished: ``0``. It does
**not** say whether the run succeeded unless you ask (``--propagate-exit-code``). A run that is
still going has no evidence yet; that is reported as an *unresolved* outcome (exit ``5``), never
as success.
"""

from __future__ import annotations

from typing import Annotated

import typer
from pydantic import ValidationError

from acf_cli.common import JsonOption, client_of, guard, state_of
from acf_cli.errors import ExitCode, InvalidArgument, ProtocolViolation
from acf_cli.models import OperationView, RunInspectRequest, RunResult, RunSelector
from acf_cli.render import print_json, render_pending_run, render_run_report
from acf_cli.run import PropagateOpt, RawOpt, exit_code_for, relay_output

app = typer.Typer(help="Inspect the evidence record of runs.", no_args_is_help=True)


def parse_run_id(text: str) -> RunSelector:
    try:
        return RunSelector(run_id=text)
    except ValidationError as e:
        raise InvalidArgument(
            f"{text!r} is not a run id", hint="run ids look like run-<32 hex digits> and are printed by `acf-local run`"
        ) from e


@app.command("get")
@guard
def get(
    ctx: typer.Context,
    run_id: Annotated[str, typer.Argument(help="Run id (run-...) as printed by `acf-local run`.")],
    output: Annotated[
        bool, typer.Option("--output", help="Also relay the captured stdout/stderr (stdout/stderr of this process).")
    ] = False,
    raw: RawOpt = False,
    propagate_exit_code: PropagateOpt = False,
    as_json: JsonOption = False,
) -> None:
    """Show the evidence record of a run: outcome, metrics, limits, artifacts, captured output."""
    env = client_of(ctx).read(RunInspectRequest(params=parse_run_id(run_id)))
    data = env.body()
    if isinstance(data, RunResult):
        if as_json:
            print_json({"finished": True, "run": data})
        else:
            if output:
                relay_output(data, raw=raw)
            render_run_report(data, verbose=state_of(ctx).verbose)
        code = exit_code_for(data, propagate=True) if propagate_exit_code else int(ExitCode.OK)
        if code != 0:
            raise typer.Exit(code)
        return
    if isinstance(data, OperationView):
        if as_json:
            print_json({"finished": False, "run": None, "operation": data})
        else:
            render_pending_run(data)
        raise typer.Exit(int(ExitCode.UNKNOWN))
    raise ProtocolViolation("expected a run or an operation from the host")
