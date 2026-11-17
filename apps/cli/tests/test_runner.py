"""``acf-local run``'s cleanup rules, one test per rule.

The runner composes four independently idempotent operations (create, start, exec, destroy). What
it must get right is not the happy path — it is **what it does to the sandbox when something goes
wrong**: destroy it only when it is *known* to be safe to, never when an outcome is unknown (that
would erase the evidence), and never silently when destroying fails.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

import factories as f
from acf_cli.client import ClientConfig, HostClient
from acf_cli.errors import HostUnreachable, OperationFailed, OutcomeUnknown, ProtocolViolation, Rejected
from acf_cli.models import Body, CommandSpec, ResponseEnvelope, RunResult, SandboxView
from acf_cli.runner import INTERRUPT_SETTLE_S, Runner, RunReport, RunSpec, Settled, cancel_and_settle
from support import error_body, respond

Step = ResponseEnvelope | BaseException


class FakeClient(HostClient):
    """Replays scripted answers per method and records every call, in order."""

    def __init__(self, script: dict[str, list[Step]]) -> None:
        super().__init__(ClientConfig())
        self._script = {method: list(steps) for method, steps in script.items()}
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.cancelled: list[str] = []
        self.waited: list[tuple[str, float | None]] = []
        self.exec_waits: tuple[float | None, float | None] | None = None
        self._count = 0

    def _take(self, method: str) -> ResponseEnvelope:
        queue = self._script.get(method)
        assert queue, f"unexpected call: {method}"
        step = queue.pop(0)
        if isinstance(step, BaseException):
            raise step
        return step

    def _mutation(self, body: Body, on_operation: Callable[[str], None] | None) -> ResponseEnvelope:
        self._count += 1
        op_id = f"op-fake-{self._count:04d}"
        if on_operation is not None:
            on_operation(op_id)
        self.calls.append((body.method, body.params_dump() or {}))
        return self._take(body.method).model_copy(update={"operation_id": op_id})

    def mutate(
        self,
        body: Body,
        *,
        operation_id: str | None = None,
        io_timeout_s: float | None = None,
        resolve_deadline_s: float | None = None,
        on_operation: Callable[[str], None] | None = None,
    ) -> ResponseEnvelope:
        self.exec_waits = (io_timeout_s, resolve_deadline_s)
        return self._mutation(body, on_operation)

    def mutate_slow(
        self,
        body: Body,
        *,
        operation_id: str | None = None,
        on_operation: Callable[[str], None] | None = None,
    ) -> ResponseEnvelope:
        return self._mutation(body, on_operation)

    def cancel(self, operation_id: str) -> ResponseEnvelope:
        self.cancelled.append(operation_id)
        return self._take("operation_cancel")

    def wait_final(self, operation_id: str, *, timeout_s: float | None = None) -> ResponseEnvelope:
        self.waited.append((operation_id, timeout_s))
        return self._take("operation_get")

    def methods(self) -> list[str]:
        return [m for m, _ in self.calls]


# ----------------------------------------------------------------------------- scripted answers
def env(
    status: str, kind: str | None = None, data: Any = None, error: dict[str, Any] | None = None
) -> ResponseEnvelope:
    result = f.body(kind, data) if kind else None
    return ResponseEnvelope.model_validate(respond({"request_id": "r"}, status, result=result, error=error))


def created(generation: int = 1) -> ResponseEnvelope:
    return env("SUCCEEDED", "sandbox", f.sandbox_view(generation=generation, state="READY"))


def started(generation: int = 2) -> ResponseEnvelope:
    return env("SUCCEEDED", "sandbox", f.sandbox_view(generation=generation, state="READY"))


def ran(**over: Any) -> ResponseEnvelope:
    return env("SUCCEEDED", "run", f.run_result(**over))


def destroyed(generation: int = 2) -> ResponseEnvelope:
    return env("SUCCEEDED", "sandbox", f.sandbox_view(generation=generation, state="DESTROYED"))


def refused(failure_class: str, message: str = "no") -> ResponseEnvelope:
    return env("REJECTED", error=error_body(failure_class, message))


def unknown() -> ResponseEnvelope:
    return env("UNKNOWN", error=error_body("TIMEOUT_UNKNOWN", "deadline", side_effect="possible", outcome_unknown=True))


def happy(**overrides: list[Step]) -> dict[str, list[Step]]:
    script: dict[str, list[Step]] = {
        "sandbox_create": [created()],
        "sandbox_start": [started()],
        "exec": [ran()],
        "sandbox_destroy": [destroyed()],
    }
    script.update(overrides)
    return script


SPEC = RunSpec(
    image="python",
    vcpus=2,
    memory_mib=4096,
    disk_mib=1024,
    command=CommandSpec(argv=["python", "experiment.py"]),
)


def run(script: dict[str, list[Step]], spec: RunSpec = SPEC) -> tuple[RunReport, FakeClient]:
    client = FakeClient(script)
    return Runner(client).run(spec), client


# ----------------------------------------------------------------------------- the happy path
def test_the_milestone_flow_creates_starts_runs_and_tears_down() -> None:
    report, client = run(happy())
    assert client.methods() == ["sandbox_create", "sandbox_start", "exec", "sandbox_destroy"]
    assert isinstance(report.run, RunResult)
    assert report.run.outcome == "SUCCEEDED"
    assert report.error is None
    assert not report.interrupted
    assert not report.unresolved
    assert not report.cleanup_failed
    assert report.cleanup == f"destroyed ({f.SANDBOX_ID})"
    assert list(report.operations) == ["create", "start", "exec", "destroy"], "evidence: every step's operation id"
    assert len(set(report.operations.values())) == 4


def test_the_create_request_asks_for_what_the_user_asked_for_and_nothing_more() -> None:
    _, client = run(happy())
    assert client.calls[0] == (
        "sandbox_create",
        {"image": "python", "resources": {"vcpus": 2, "memory_mib": 4096, "disk_mib": 1024, "network": "none"}},
    )


def test_each_step_acts_on_the_generation_the_previous_step_reported() -> None:
    script = happy(sandbox_create=[created(generation=1)], sandbox_start=[started(generation=2)])
    _, client = run(script)
    by_method = dict(client.calls)
    assert by_method["sandbox_start"] == {"sandbox_id": f.SANDBOX_ID, "expected_generation": 1}
    assert by_method["exec"]["expected_generation"] == 2
    assert by_method["exec"]["command"]["argv"] == ["python", "experiment.py"]
    assert by_method["sandbox_destroy"] == {"sandbox_id": f.SANDBOX_ID, "expected_generation": 2}


def test_progress_is_reported_in_order() -> None:
    lines: list[str] = []
    Runner(FakeClient(happy()), lines.append).run(SPEC)
    assert [line.split()[0] for line in lines] == ["creating", "starting", "running:", "destroying"]
    assert "network none" in lines[0]


def test_the_exec_wait_covers_the_hosts_own_deadline() -> None:
    spec = RunSpec(
        image="python",
        vcpus=1,
        memory_mib=512,
        disk_mib=1024,
        command=CommandSpec.model_validate({"argv": ["x"], "limits": {"timeout_ms": 90_000}}),
    )
    _, client = run(happy(), spec)
    assert client.exec_waits is not None
    io_wait, resolve_wait = client.exec_waits
    assert io_wait == resolve_wait
    assert io_wait is not None
    assert io_wait >= 90 + 63, "must outlast the host's timeout + 3s grace + 60s operation deadline"


# ----------------------------------------------------------------------------- when the workload fails
def test_a_failed_workload_is_a_result_not_an_error_and_the_sandbox_is_still_destroyed() -> None:
    report, client = run(happy(exec=[ran(outcome="FAILED", exit_code=3)]))
    assert report.error is None
    assert report.run is not None
    assert (report.run.outcome, report.run.exit_code) == ("FAILED", 3)
    assert client.methods()[-1] == "sandbox_destroy"
    assert report.cleanup.startswith("destroyed")


def test_keep_leaves_the_sandbox_for_follow_up_work() -> None:
    spec = RunSpec(
        image=SPEC.image,
        vcpus=SPEC.vcpus,
        memory_mib=SPEC.memory_mib,
        disk_mib=SPEC.disk_mib,
        command=SPEC.command,
        keep=True,
    )
    report, client = run(happy(), spec)
    assert "sandbox_destroy" not in client.methods()
    assert report.cleanup == f"kept ({f.SANDBOX_ID}, generation 2)"


# ----------------------------------------------------------------------------- refusals and failures
def test_a_policy_refusal_at_create_leaves_nothing_behind_and_nothing_to_clean() -> None:
    report, client = run({"sandbox_create": [refused("ADMISSION_REJECTED", "memory exceeds the ceiling")]})
    assert isinstance(report.error, Rejected)
    assert report.error.failure_class == "ADMISSION_REJECTED"
    assert client.methods() == ["sandbox_create"]
    assert report.cleanup == "nothing to clean up"
    assert not report.unresolved


def test_a_refusal_at_exec_still_destroys_the_sandbox_it_created() -> None:
    report, client = run(happy(exec=[refused("AUTHORIZATION", "env var not allowed")]))
    assert isinstance(report.error, Rejected)
    assert client.methods() == ["sandbox_create", "sandbox_start", "exec", "sandbox_destroy"]
    assert report.cleanup.startswith("destroyed")


def test_a_start_that_definitely_failed_destroys_the_half_made_sandbox() -> None:
    failed = env("FAILED", error=error_body("BACKEND_CRASH", "vmm exited"))
    report, client = run({"sandbox_create": [created()], "sandbox_start": [failed], "sandbox_destroy": [destroyed(1)]})
    assert isinstance(report.error, OperationFailed)
    assert client.calls[-1] == ("sandbox_destroy", {"sandbox_id": f.SANDBOX_ID, "expected_generation": 1})
    assert report.cleanup.startswith("destroyed")
    assert not report.unresolved


# ----------------------------------------------------------------------------- unknown outcomes
def test_an_unknown_exec_leaves_the_sandbox_in_place_because_destroying_it_would_erase_the_evidence() -> None:
    report, client = run(happy(exec=[unknown()]))
    assert isinstance(report.error, OutcomeUnknown)
    assert report.unresolved
    assert "sandbox_destroy" not in client.methods(), "never destroy what you cannot account for"
    assert report.cleanup.startswith("skipped")
    assert f.SANDBOX_ID in report.cleanup
    assert report.error.operation_id == report.operations["exec"]


def test_an_unknown_start_also_leaves_the_sandbox() -> None:
    report, client = run({"sandbox_create": [created()], "sandbox_start": [unknown()]})
    assert report.unresolved
    assert client.methods() == ["sandbox_create", "sandbox_start"]


def test_an_unknown_create_says_a_sandbox_may_exist() -> None:
    report, client = run({"sandbox_create": [unknown()]})
    assert report.unresolved
    assert report.sandbox is None
    assert client.methods() == ["sandbox_create"]
    assert "may exist" in report.cleanup


def test_a_protocol_violation_is_not_treated_as_unknown_by_the_runner_but_carries_its_operation() -> None:
    boom = ProtocolViolation("garbled", hint="look it up", operation_id="op-abcdefgh")
    report, _ = run({"sandbox_create": [boom]})
    assert report.error is boom
    assert report.cleanup == "nothing to clean up"


def test_an_unreachable_host_is_an_error_with_nothing_to_clean() -> None:
    report, _ = run({"sandbox_create": [HostUnreachable("no socket")]})
    assert isinstance(report.error, HostUnreachable)
    assert report.cleanup == "nothing to clean up"


# ----------------------------------------------------------------------------- failed cleanup is loud
def test_a_failed_destroy_is_reported_with_the_exact_command_to_finish_the_job() -> None:
    report, _ = run(happy(sandbox_destroy=[refused("STATE_CONFLICT", "sandbox is busy")]))
    assert report.error is None, "the run itself succeeded; the cleanup failure is its own fact"
    assert report.cleanup_failed
    assert report.cleanup.startswith("FAILED:")
    assert f"acf-local sandbox destroy {f.SANDBOX_ID}" in report.cleanup
    assert report.run is not None, "the evidence of the run is still delivered"


def test_a_destroy_whose_outcome_is_unknown_is_also_reported_as_a_failed_cleanup() -> None:
    report, _ = run(happy(sandbox_destroy=[unknown()]))
    assert report.cleanup_failed
    assert "may still exist" in report.cleanup


# ----------------------------------------------------------------------------- interrupts
def test_ctrl_c_during_exec_cancels_it_reads_back_the_result_and_then_cleans_up() -> None:
    cancelled = ran(outcome="CANCELLED", exit_code=None, signal=15, stdout=f.capture(b"partial\n"))
    report, client = run(
        happy(exec=[KeyboardInterrupt()]) | {"operation_cancel": [env("IN_PROGRESS")], "operation_get": [cancelled]}
    )
    assert report.interrupted
    assert report.run is not None
    assert report.run.outcome == "CANCELLED"
    assert client.cancelled == [report.operations["exec"]]
    assert client.waited[0][0] == report.operations["exec"]
    assert client.waited[0][1] == INTERRUPT_SETTLE_S
    assert client.methods()[-1] == "sandbox_destroy"
    assert report.cleanup.startswith("destroyed")
    assert not report.unresolved


def test_ctrl_c_during_exec_with_an_unreachable_host_leaves_the_sandbox() -> None:
    report, client = run(
        happy(exec=[KeyboardInterrupt()]) | {"operation_cancel": [HostUnreachable("gone")], "operation_get": []}
    )
    assert report.interrupted
    assert report.unresolved
    assert report.run is None
    assert "sandbox_destroy" not in client.methods()
    assert report.cleanup.startswith("skipped")


def test_ctrl_c_during_exec_when_the_run_has_not_stopped_yet_is_unresolved_not_cancelled() -> None:
    report, client = run(
        happy(exec=[KeyboardInterrupt()])
        | {"operation_cancel": [env("IN_PROGRESS")], "operation_get": [env("IN_PROGRESS")]}
    )
    assert report.interrupted
    assert report.unresolved
    assert "sandbox_destroy" not in client.methods()


@pytest.mark.parametrize(
    ("step", "script", "expected_destroy_generation"),
    [
        ("create", {"sandbox_create": [KeyboardInterrupt()], "operation_get": [created(generation=1)]}, 1),
        (
            "start",
            {"sandbox_create": [created(1)], "sandbox_start": [KeyboardInterrupt()], "operation_get": [started(2)]},
            2,
        ),
    ],
)
def test_ctrl_c_during_create_or_start_observes_that_step_and_cleans_up_what_it_made(
    step: str, script: dict[str, list[Step]], expected_destroy_generation: int
) -> None:
    report, client = run(script | {"sandbox_destroy": [destroyed(expected_destroy_generation)]})
    assert report.interrupted
    assert not report.unresolved
    assert client.cancelled == [], "only exec can be cancelled; create/start are observed to completion"
    assert client.calls[-1] == (
        "sandbox_destroy",
        {"sandbox_id": f.SANDBOX_ID, "expected_generation": expected_destroy_generation},
    )
    assert step in report.operations


def test_ctrl_c_during_create_when_the_outcome_cannot_be_learned_leaves_a_warning_not_a_guess() -> None:
    report, client = run({"sandbox_create": [KeyboardInterrupt()], "operation_get": [OutcomeUnknown("cannot observe")]})
    assert report.interrupted
    assert report.unresolved
    assert client.methods() == ["sandbox_create"]
    assert "may exist" in report.cleanup


def test_ctrl_c_while_destroying_reports_the_operation_to_confirm() -> None:
    report, _ = run(happy(sandbox_destroy=[KeyboardInterrupt()]))
    assert report.interrupted
    assert report.unresolved
    assert "interrupted while destroying" in report.cleanup
    assert f"acf-local operation get {report.operations['destroy']}" in report.cleanup


# ----------------------------------------------------------------------------- cancel_and_settle
def test_settling_returns_the_recorded_run_when_the_host_finishes_it() -> None:
    client = FakeClient({"operation_cancel": [env("IN_PROGRESS")], "operation_get": [ran(outcome="CANCELLED")]})
    settled = cancel_and_settle(client, "op-abcdefgh")
    assert settled.resolved
    assert settled.run is not None
    assert settled.run.outcome == "CANCELLED"


def test_settling_a_failed_operation_is_resolved_without_a_run() -> None:
    client = FakeClient(
        {
            "operation_cancel": [env("IN_PROGRESS")],
            "operation_get": [env("FAILED", error=error_body("BACKEND_CRASH", "x"))],
        }
    )
    assert cancel_and_settle(client, "op-abcdefgh") == Settled(run=None, resolved=True)


def test_settling_never_raises_it_reports_unresolved() -> None:
    assert cancel_and_settle(FakeClient({"operation_cancel": [HostUnreachable("gone")]}), "op-abcdefgh") == Settled(
        run=None, resolved=False
    )
    assert cancel_and_settle(
        FakeClient({"operation_cancel": [refused("NOT_FOUND")], "operation_get": [env("IN_PROGRESS")]}), "op-abcdefgh"
    ) == Settled(run=None, resolved=False)


def test_the_view_types_the_runner_hands_back_are_the_typed_models() -> None:
    report, _ = run(happy())
    assert isinstance(report.sandbox, SandboxView)
    assert report.sandbox.state == "DESTROYED"
