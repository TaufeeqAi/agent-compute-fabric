"""``run once``: create -> start -> exec -> destroy, and what becomes of the sandbox when something goes wrong.

The command is composed from four public operations. The interesting behaviour is the cleanup:

* the sandbox is destroyed whatever happened — destroying is containment, and it preempts whatever
  is still in flight — unless ``--keep``;
* nothing is destroyed when nothing can exist (a refusal; an operation whose effect is ``NOT_APPLIED``);
* when it is not established whether ``create`` was accepted there is no id to act on, and the
  report says exactly that;
* a cleanup that fails is never swallowed.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest

import factories as f
from acf_cli import requests as rq
from acf_cli.client import HostClient
from acf_cli.errors import (
    ExitCode,
    HostUnreachable,
    NotFinished,
    OperationFailed,
    OutcomeUnknown,
    OutcomeUnresolved,
    Refused,
    ResponseLost,
)
from acf_cli.run import run_exit_code
from acf_cli.runner import Runner, RunReport, RunSpec
from acf_cli.wire import OperationState
from conftest import Invocation
from support import Contract, ScriptedConnection, op, refused

Scripted = Callable[..., ScriptedConnection]
ClientFor = Callable[[ScriptedConnection], HostClient]
Invoke = Callable[..., Invocation]

SBX = f.SANDBOX_ID
CREATED = op("SUCCEEDED", f.sandbox_body(state="PROVISIONING"))
STARTED = op("SUCCEEDED", f.sandbox_body(state="READY"))
RAN = op("SUCCEEDED", f.run_body(stdout=b"result\n"), operation_type="exec.run", run_id=f.RUN_ID)
DESTROYED = op("SUCCEEDED", f.sandbox_body(state="DESTROYED"), operation_type="sandbox.destroy")
LOST = ResponseLost("the host closed the connection without answering")
DOWN = HostUnreachable("nothing is listening")


def spec(*, keep: bool = False, timeout_s: float | None = None) -> RunSpec:
    resources = rq.SandboxResources(vcpus=1, memory_mib=256, disk_mib=128, network=rq.NetworkNone())
    return RunSpec(
        create=rq.SandboxCreateParams(image="python", resources=resources),
        command=rq.CommandSpec(argv=["python", "experiment.py"]),
        keep=keep,
        timeout_s=timeout_s,
    )


def run(client_for: ClientFor, connection: ScriptedConnection, **kw: Any) -> RunReport:
    return Runner(client_for(connection)).run(spec(**kw))


# ----------------------------------------------------------------------------- the happy path
def test_four_operations_each_under_its_own_id(scripted: Scripted, client_for: ClientFor) -> None:
    connection = scripted(CREATED, STARTED, RAN, DESTROYED)
    report = run(client_for, connection)
    assert connection.methods == ["sandbox.create", "sandbox.start", "exec.run", "sandbox.destroy"]
    assert list(report.operations) == ["create", "start", "exec", "destroy"]
    sent_ids = [r["operation_id"] for r in connection.requests]
    assert sent_ids == list(report.operations.values())
    assert len(set(sent_ids)) == 4, "one operation id per step"
    assert report.error is None
    assert report.run is not None
    assert report.run.exited_cleanly
    assert (report.cleanup_state, report.cleanup) == ("destroyed", f"destroyed {SBX}")
    assert run_exit_code(report, propagate=False) == 0


def test_every_step_acts_on_the_sandbox_and_generation_the_host_named(
    scripted: Scripted, client_for: ClientFor
) -> None:
    connection = scripted(CREATED, STARTED, RAN, DESTROYED)
    run(client_for, connection)
    create, start, execute, destroy = (r["params"] for r in connection.requests)
    assert create["image"] == "python"
    assert start == {"sandbox_id": SBX, "expected_generation": 1}
    assert execute["sandbox_id"] == SBX
    assert execute["command"]["argv"] == ["python", "experiment.py"]
    assert destroy == {"sandbox_id": SBX, "expected_generation": 1}


def test_keep_leaves_the_sandbox_and_says_how_to_destroy_it(scripted: Scripted, client_for: ClientFor) -> None:
    connection = scripted(CREATED, STARTED, RAN)
    report = run(client_for, connection, keep=True)
    assert connection.methods == ["sandbox.create", "sandbox.start", "exec.run"]
    assert report.cleanup_state == "kept"
    assert f"acf-local sandbox destroy {SBX} --yes" in report.cleanup
    assert not report.cleanup_failed


def test_steps_are_followed_like_any_other_operation(scripted: Scripted, client_for: ClientFor) -> None:
    connection = scripted(CREATED, op("IN_PROGRESS"), STARTED, RAN, DESTROYED)
    report = run(client_for, connection)
    assert connection.methods == ["sandbox.create", "sandbox.start", "operation.get", "exec.run", "sandbox.destroy"]
    assert report.error is None


def test_progress_is_reported_without_the_command_line(scripted: Scripted, client_for: ClientFor) -> None:
    said: list[str] = []
    Runner(client_for(scripted(CREATED, STARTED, RAN, DESTROYED)), said.append).run(spec())
    assert said == [
        "creating the sandbox",
        f"starting {SBX}",
        f"running the command in {SBX}",
        f"destroying {SBX}",
    ]
    assert not any("experiment.py" in line for line in said), "arguments may carry sensitive values"


# ----------------------------------------------------------------------------- nothing to clean up
def test_a_refused_create_stops_there_and_there_is_nothing_to_clean_up(
    scripted: Scripted, client_for: ClientFor
) -> None:
    connection = scripted(refused("SAFETY_CONTROL_DENIED", "image alias `python` is not permitted", "AFTER_CHANGE"))
    report = run(client_for, connection)
    assert connection.methods == ["sandbox.create"]
    assert isinstance(report.error, Refused)
    assert (report.cleanup_state, report.cleanup) == ("none", "nothing to clean up")
    assert run_exit_code(report, propagate=False) == ExitCode.REFUSED


def test_a_create_that_never_left_is_a_transport_failure_with_nothing_to_clean_up(
    scripted: Scripted, client_for: ClientFor
) -> None:
    connection = scripted(DOWN)
    report = run(client_for, connection)
    assert isinstance(report.error, HostUnreachable)
    assert report.cleanup_state == "none"
    assert run_exit_code(report, propagate=False) == ExitCode.TRANSPORT


def test_a_failed_create_that_left_nothing_behind_is_not_destroyed(scripted: Scripted, client_for: ClientFor) -> None:
    connection = scripted(op("FAILED", effect="NOT_APPLIED", cleanup="COMPLETE"))
    report = run(client_for, connection)
    assert connection.methods == ["sandbox.create"]
    assert isinstance(report.error, OperationFailed)
    assert "left nothing behind" in report.cleanup
    assert not report.cleanup_failed


# ----------------------------------------------------------------------------- destroyed whatever happened
def test_a_failed_create_that_may_have_left_something_is_destroyed(scripted: Scripted, client_for: ClientFor) -> None:
    connection = scripted(op("FAILED", effect="MAY_BE_APPLIED", cleanup="PENDING"), DESTROYED)
    report = run(client_for, connection)
    assert connection.methods == ["sandbox.create", "sandbox.destroy"]
    assert connection.requests[1]["params"] == {"sandbox_id": SBX, "expected_generation": 1}, "named by the operation"
    assert report.cleanup_state == "destroyed"
    assert run_exit_code(report, propagate=False) == ExitCode.FAILED


@pytest.mark.parametrize(
    ("start", "error", "code"),
    [
        (refused("STATE_CONFLICT", "sandbox is busy", "AFTER_CHANGE"), Refused, ExitCode.REFUSED),
        (op("FAILED", cleanup="PENDING", effect="MAY_BE_APPLIED"), OperationFailed, ExitCode.FAILED),
    ],
)
def test_a_start_that_does_not_succeed_still_ends_in_destroy(
    scripted: Scripted, client_for: ClientFor, start: Any, error: type[Exception], code: ExitCode
) -> None:
    connection = scripted(CREATED, start, DESTROYED)
    report = run(client_for, connection)
    assert connection.methods == ["sandbox.create", "sandbox.start", "sandbox.destroy"]
    assert isinstance(report.error, error)
    assert report.cleanup_state == "destroyed"
    assert run_exit_code(report, propagate=False) == code


def test_a_failed_execution_keeps_its_output_and_the_sandbox_is_destroyed(
    scripted: Scripted, client_for: ClientFor
) -> None:
    backstop = op(
        "FAILED",
        f.run_body(status="TIMED_OUT", exit_code=None, stdout=b"partial\n", host_backstop_fired=True),
        operation_type="exec.run",
        failure=f.failure("TIMEOUT", "the host deadline backstop ended the runtime"),
        effect="MAY_BE_APPLIED",
        cleanup="PENDING",
    )
    connection = scripted(CREATED, STARTED, backstop, DESTROYED)
    report = run(client_for, connection)
    assert isinstance(report.error, OperationFailed)
    assert report.run is not None, "a failed execution still has output and metrics"
    assert report.run.host_backstop_fired
    assert report.cleanup_state == "destroyed"
    assert run_exit_code(report, propagate=False) == ExitCode.FAILED


def test_an_unknown_execution_is_reported_as_unknown_and_the_sandbox_is_still_destroyed(
    scripted: Scripted, client_for: ClientFor
) -> None:
    """Destroying is containment: it is the right thing to do with a sandbox whose command may still be running."""
    unknown = op(
        "UNKNOWN", operation_type="exec.run", failure=f.failure("UNKNOWN_OUTCOME", "no result could be obtained")
    )
    connection = scripted(CREATED, STARTED, unknown, DESTROYED)
    report = run(client_for, connection)
    assert isinstance(report.error, OutcomeUnknown)
    assert connection.methods[-1] == "sandbox.destroy"
    assert report.cleanup_state == "destroyed"
    assert run_exit_code(report, propagate=False) == ExitCode.UNKNOWN
    assert report.steps["exec"].operation is not None
    assert report.steps["exec"].operation.state is OperationState.UNKNOWN, "still UNKNOWN in the report"


def test_an_execution_the_client_stopped_waiting_for_is_ended_by_the_destroy_and_reported_as_it_ended(
    scripted: Scripted, client_for: ClientFor
) -> None:
    running = op("IN_PROGRESS", operation_type="exec.run")
    superseded = op("CANCELLED", operation_type="exec.run", cancelled_by="SUPERSEDED", effect="MAY_BE_APPLIED")
    connection = scripted(CREATED, STARTED, running, running, DESTROYED, superseded)
    report = run(client_for, connection, timeout_s=0.1)
    assert connection.methods == [
        "sandbox.create",
        "sandbox.start",
        "exec.run",
        "operation.get",  # followed until the client's patience ran out
        "sandbox.destroy",
        "operation.get",  # ...and asked once more after the destroy, to report how it really ended
    ]
    assert isinstance(report.error, NotFinished)
    final = report.steps["exec"].operation
    assert final is not None
    assert (final.state, final.cancelled_by) == (OperationState.CANCELLED, "SUPERSEDED")
    assert report.cleanup_state == "destroyed"
    assert run_exit_code(report, propagate=False) == ExitCode.UNRESOLVED


# ----------------------------------------------------------------------------- not established
def test_when_it_is_not_established_whether_create_was_accepted_there_is_no_sandbox_to_address(
    scripted: Scripted, client_for: ClientFor
) -> None:
    connection = scripted(LOST, default=DOWN)
    report = run(client_for, connection)
    assert isinstance(report.error, OutcomeUnresolved)
    assert set(connection.methods) == {"sandbox.create"}, "resolved by the same request, never by a destroy of a guess"
    assert report.sandbox is None
    assert report.cleanup_state == "unknown"
    assert report.cleanup_failed
    create_id = report.operations["create"]
    assert f"acf-local operation get {create_id}" in report.cleanup
    assert "If it did, a sandbox exists" in report.cleanup
    assert run_exit_code(report, propagate=False) == ExitCode.UNRESOLVED


def test_a_create_whose_response_was_lost_is_resolved_and_the_run_goes_on(
    scripted: Scripted, client_for: ClientFor
) -> None:
    connection = scripted(LOST, CREATED, STARTED, RAN, DESTROYED)
    report = run(client_for, connection)
    assert connection.methods == ["sandbox.create", "sandbox.create", "sandbox.start", "exec.run", "sandbox.destroy"]
    assert connection.requests[1]["retry"] is True
    assert connection.requests[1]["operation_id"] == connection.requests[0]["operation_id"]
    assert report.error is None
    assert report.cleanup_state == "destroyed"


# ----------------------------------------------------------------------------- a cleanup that fails
def test_a_cleanup_that_fails_is_loud_and_gives_the_command_that_finishes_it(
    scripted: Scripted, client_for: ClientFor
) -> None:
    quarantined = op(
        "FAILED",
        operation_type="sandbox.destroy",
        failure=f.failure("QUARANTINED", "ownership not provable, left in place"),
        cleanup="QUARANTINED",
        effect="MAY_BE_APPLIED",
    )
    connection = scripted(CREATED, STARTED, RAN, quarantined)
    report = run(client_for, connection)
    assert report.error is None, "the run itself succeeded"
    assert report.cleanup_state == "failed"
    assert report.cleanup.startswith("FAILED: ")
    assert "QUARANTINED" in report.cleanup
    assert f"acf-local sandbox destroy {SBX} --yes" in report.cleanup
    assert run_exit_code(report, propagate=False) == ExitCode.FAILED, "a leaked sandbox is not exit 0"


def test_a_destroy_that_cannot_be_delivered_is_a_failed_cleanup(scripted: Scripted, client_for: ClientFor) -> None:
    connection = scripted(CREATED, STARTED, RAN, DOWN)
    report = run(client_for, connection)
    assert report.cleanup_state == "failed"
    assert "nothing is listening" in report.cleanup
    assert run_exit_code(report, propagate=False) == ExitCode.FAILED


def test_the_first_failure_decides_the_exit_code_not_the_cleanup(scripted: Scripted, client_for: ClientFor) -> None:
    connection = scripted(CREATED, refused("RESOURCE_EXHAUSTED", "no capacity", "SAME_REQUEST_LATER"), DOWN)
    report = run(client_for, connection)
    assert report.cleanup_state == "failed"
    assert run_exit_code(report, propagate=False) == ExitCode.REFUSED


# ----------------------------------------------------------------------------- Ctrl-C
def test_ctrl_c_during_the_command_asks_what_was_recorded_and_destroys_the_sandbox(
    scripted: Scripted, client_for: ClientFor
) -> None:
    running = op("IN_PROGRESS", operation_type="exec.run")
    superseded = op(
        "CANCELLED",
        f.run_body(status="CANCELLED", exit_code=None),
        operation_type="exec.run",
        cancelled_by="SUPERSEDED",
    )
    connection = scripted(CREATED, STARTED, KeyboardInterrupt(), running, DESTROYED, superseded)
    report = run(client_for, connection)
    assert connection.methods == [
        "sandbox.create",
        "sandbox.start",
        "exec.run",
        "operation.get",
        "sandbox.destroy",
        "operation.get",
    ]
    assert report.interrupted
    assert report.cleanup_state == "destroyed"
    assert report.steps["exec"].operation is not None
    assert report.steps["exec"].operation.state is OperationState.CANCELLED
    assert run_exit_code(report, propagate=False) == ExitCode.INTERRUPTED


def test_ctrl_c_while_create_is_in_flight_learns_the_sandbox_from_the_host_and_destroys_it(
    scripted: Scripted, client_for: ClientFor
) -> None:
    connection = scripted(KeyboardInterrupt(), op("IN_PROGRESS"), DESTROYED)
    report = run(client_for, connection)
    assert connection.methods == ["sandbox.create", "operation.get", "sandbox.destroy"]
    assert connection.requests[1]["params"] == {"operation_id": connection.requests[0]["operation_id"]}
    assert connection.requests[2]["params"] == {"sandbox_id": SBX, "expected_generation": 1}
    assert report.interrupted
    assert report.cleanup_state == "destroyed"


def test_ctrl_c_before_the_host_recorded_create_leaves_nothing_behind(
    scripted: Scripted, client_for: ClientFor
) -> None:
    connection = scripted(KeyboardInterrupt(), refused("NOT_FOUND", "operation does not exist"))
    report = run(client_for, connection)
    assert connection.methods == ["sandbox.create", "operation.get"]
    assert report.interrupted
    assert (report.cleanup_state, report.cleanup) == ("none", "nothing to clean up")


def test_ctrl_c_when_the_host_cannot_be_asked_reports_that_a_sandbox_may_exist(
    scripted: Scripted, client_for: ClientFor
) -> None:
    connection = scripted(KeyboardInterrupt(), DOWN)
    report = run(client_for, connection)
    assert report.interrupted
    assert report.cleanup_state == "unknown"
    assert "not established" in report.cleanup


def test_ctrl_c_during_the_destroy_says_the_host_finishes_what_it_accepted(
    scripted: Scripted, client_for: ClientFor
) -> None:
    connection = scripted(CREATED, STARTED, RAN, KeyboardInterrupt())
    report = run(client_for, connection)
    assert report.interrupted
    assert report.cleanup_state == "unknown"
    assert f"acf-local operation get {report.operations['destroy']}" in report.cleanup
    assert run_exit_code(report, propagate=False) == ExitCode.INTERRUPTED


# ----------------------------------------------------------------------------- the workload's own result
@pytest.mark.parametrize(
    ("over", "plain", "propagated"),
    [
        ({"exit_code": 0}, 0, 0),
        ({"exit_code": 7}, 1, 7),
        ({"status": "SIGNALED", "exit_code": None, "signal": 15}, 1, 143),
    ],
)
def test_the_exit_code_of_a_run_that_worked_is_the_workloads(
    scripted: Scripted, client_for: ClientFor, over: dict[str, Any], plain: int, propagated: int
) -> None:
    ran = op("SUCCEEDED", f.run_body(**over), operation_type="exec.run")
    report = run(client_for, scripted(CREATED, STARTED, ran, DESTROYED))
    assert run_exit_code(report, propagate=False) == plain
    assert run_exit_code(report, propagate=True) == propagated


# ----------------------------------------------------------------------------- the command
ONCE = ["run", "once", "--image", "python", "--memory", "256", "--disk", "128"]


def test_run_once_relays_output_and_reports_every_step(invoke: Invoke) -> None:
    inv = invoke([*ONCE, "--", "python", "experiment.py"], CREATED, STARTED, RAN, DESTROYED)
    assert inv.exit_code == 0
    assert inv.result.stdout_bytes == b"result\n", "the guest's stdout and nothing else"
    for step in ("create", "start", "exec", "destroy"):
        assert f"{step}: op-" in inv.stderr
    assert "SUCCEEDED, effect APPLIED" in inv.stderr
    assert f"cleanup: destroyed {SBX}" in inv.stderr
    assert f.RUN_ID in inv.stderr


def test_run_once_sends_the_sandbox_and_the_command_its_flags_describe(invoke: Invoke) -> None:
    inv = invoke(
        [*ONCE, "--cpu", "2", "--network", "allowlist", "--allow", "pypi.org:443", "--lifetime", "10m", "--name", "job",
         "-e", "LANG=C", "--cwd", "/workspace", "--time-limit", "30s", "--command", "pip install requests"],
        CREATED, STARTED, RAN, DESTROYED,
    )  # fmt: skip
    create, _, execute, _ = (r["params"] for r in inv.connection.requests)
    assert create == {
        "name": "job",
        "image": "python",
        "resources": {
            "vcpus": 2,
            "memory_mib": 256,
            "disk_mib": 128,
            "network": {
                "mode": "allowlist",
                "entries": [{"destination": {"name": "pypi.org"}, "ports": [{"from": 443, "to": 443}]}],
            },
        },
        "lifetime_secs": 600,
    }
    assert execute["command"] == {
        "argv": ["pip", "install", "requests"],
        "env": {"LANG": "C"},
        "secret_env": {},
        "cwd": "/workspace",
        "limits": {"timeout_ms": 30_000},
    }


def test_run_once_json_is_one_document_with_every_answer(invoke: Invoke, contract: Contract) -> None:
    inv = invoke([*ONCE, "--json", "--", "true"], CREATED, STARTED, RAN, DESTROYED)
    assert inv.exit_code == 0
    assert inv.stderr == ""
    document = json.loads(inv.stdout)
    assert list(document["steps"]) == ["create", "start", "exec", "destroy"]
    for answer in document["steps"].values():
        contract.check_response(answer)
    assert document["operations"] == {
        name: step["operation"]["operation_id"] for name, step in document["steps"].items()
    }
    assert document["run"]["run_id"] == f.RUN_ID
    assert document["sandbox"] == {"sandbox_id": SBX, "generation": 1}
    assert document["cleanup"] == {"state": "destroyed", "detail": f"destroyed {SBX}"}
    assert (document["interrupted"], document["error"], document["exit_code"]) == (False, None, 0)


def test_run_once_json_carries_the_failure_and_the_exit_code(invoke: Invoke) -> None:
    inv = invoke([*ONCE, "--json", "--", "true"], CREATED, refused("STATE_CONFLICT", "busy", "AFTER_CHANGE"), DESTROYED)
    assert inv.exit_code == 3
    document = json.loads(inv.stdout)
    assert document["steps"]["start"]["refusal"]["class"] == "STATE_CONFLICT"
    assert document["error"]["kind"] == "Refused"
    assert document["exit_code"] == 3
    assert document["run"] is None
    assert document["cleanup"]["state"] == "destroyed"


def test_run_once_shows_a_failed_cleanup_as_an_alarm(invoke: Invoke) -> None:
    inv = invoke([*ONCE, "--", "true"], CREATED, STARTED, RAN, HostUnreachable("nothing is listening"))
    assert inv.exit_code == 4
    assert "cleanup: FAILED: nothing is listening" in inv.stderr
    assert f"acf-local sandbox destroy {SBX} --yes" in inv.stderr


def test_run_once_keep(invoke: Invoke) -> None:
    inv = invoke([*ONCE, "--keep", "--", "true"], CREATED, STARTED, RAN)
    assert inv.exit_code == 0
    assert f"cleanup: kept {SBX}" in inv.stderr


def test_run_once_rejects_a_bad_command_line_before_sending_anything(invoke: Invoke) -> None:
    for args in (
        ONCE,
        [*ONCE, "--allow", "pypi.org:443", "--", "true"],
        [*ONCE, "--secret-env", "T=not a reference", "--", "x"],
    ):
        inv = invoke(args)
        assert inv.exit_code == 2
        assert inv.connection.requests == []


def test_ctrl_c_between_two_steps_still_cleans_up(scripted: Scripted, client_for: ClientFor) -> None:
    def interrupt_before_start(message: str) -> None:
        if message.startswith("starting"):
            raise KeyboardInterrupt

    connection = scripted(CREATED, DESTROYED)
    report = Runner(client_for(connection), interrupt_before_start).run(spec())
    assert connection.methods == ["sandbox.create", "sandbox.destroy"]
    assert report.interrupted
    assert report.cleanup_state == "destroyed"


def test_a_sandbox_id_the_client_cannot_address_is_a_failed_cleanup_not_a_crash(
    scripted: Scripted, client_for: ClientFor
) -> None:
    odd = op("FAILED", effect="MAY_BE_APPLIED", cleanup="PENDING", sandbox=["sandbox-in-another-grammar", 1])
    report = run(client_for, scripted(odd))
    assert report.cleanup_state == "failed"
    assert "cannot address" in report.cleanup


def test_the_execution_is_reported_as_last_seen_when_the_host_cannot_be_asked_again(
    scripted: Scripted, client_for: ClientFor
) -> None:
    running = op("IN_PROGRESS", operation_type="exec.run")
    connection = scripted(CREATED, STARTED, running, running, DESTROYED, DOWN)
    report = run(client_for, connection, timeout_s=0.1)
    assert report.cleanup_state == "destroyed"
    last = report.steps["exec"].operation
    assert last is not None
    assert last.state is OperationState.IN_PROGRESS, "what was last heard, not a guess"
