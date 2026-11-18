"""``acf-local quarantine ...`` — supervised release of a quarantined generation.

The host quarantines a generation when it cannot prove that what it would remove is its own. A
quarantined generation accepts no operation except this one, and keeps its capacity until an
operator releases it. The operator asserts; the host acts on the assertion and then *observes*:
only observed absence destroys the generation and returns its capacity.
"""

from __future__ import annotations

import enum
from typing import Annotated

import typer

from acf_cli.common import (
    JsonOption,
    OperationIdOption,
    TimeoutOption,
    WaitOption,
    YesOption,
    client_of,
    conclude,
    confirm_destructive,
    guard,
    operation_id_of,
    timeout_of,
)
from acf_cli.errors import InvalidArgument
from acf_cli.host import host_change_of
from acf_cli.requests import QuarantineReleaseParams, quarantine_release
from acf_cli.resolve import is_sandbox_id
from acf_cli.wire import ReleaseMode

app = typer.Typer(help="Release a quarantined sandbox generation.", no_args_is_help=True)


class ReleaseChoice(enum.StrEnum):
    FORCE_DESTROY = "force-destroy"
    DECLARE_ABSENT = "declare-absent"


_MODES = {
    ReleaseChoice.FORCE_DESTROY: ReleaseMode.FORCE_DESTROY,
    ReleaseChoice.DECLARE_ABSENT: ReleaseMode.DECLARE_ABSENT,
}
_ASSERTION = {
    ReleaseChoice.FORCE_DESTROY: "assert that its recorded resources belong to this host, and have them torn down",
    ReleaseChoice.DECLARE_ABSENT: "assert that nothing of it remains",
}


@app.command("release")
@guard
def release(
    ctx: typer.Context,
    sandbox_id: Annotated[str, typer.Argument(help="Sandbox id (sbx-...). An id, never a name.")],
    generation: Annotated[int, typer.Option("--generation", min=1, help="The quarantined generation.")],
    mode: Annotated[
        ReleaseChoice,
        typer.Option(
            "--mode",
            case_sensitive=False,
            help="`force-destroy`: the recorded resources are this host's; tear them down and verify absence. "
            "`declare-absent`: nothing remains; only verify.",
        ),
    ],
    yes: YesOption = False,
    operation_id: OperationIdOption = None,
    wait: WaitOption = True,
    timeout: TimeoutOption = None,
    as_json: JsonOption = False,
) -> None:
    """Release a quarantined generation. Operator only.

    If what the host observes contradicts the assertion, the release ends FAILED and the
    generation stays quarantined. The assertion, the operator and the observation are recorded.
    """
    if not is_sandbox_id(sandbox_id):
        raise InvalidArgument(
            f"{sandbox_id!r} is not a sandbox id", hint="a sandbox id is `sbx-` followed by 32 hex digits"
        )
    params = QuarantineReleaseParams(sandbox_id=sandbox_id, generation=generation, mode=_MODES[mode])
    confirm_destructive(
        f"release {sandbox_id} generation {generation} from quarantine: {_ASSERTION[mode]}", assume_yes=yes
    )
    outcome = client_of(ctx).submit(
        quarantine_release(params), operation_id=operation_id_of(operation_id), wait=wait, timeout_s=timeout_of(timeout)
    )
    conclude(outcome, as_json=as_json, show=host_change_of)
