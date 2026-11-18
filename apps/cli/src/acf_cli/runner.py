"""``acf-local run once``: create -> start -> exec -> destroy, with honest cleanup.

The host has no "run in a throwaway sandbox" primitive. This command is *composed from the public
methods*, so each step is its own operation with its own operation id, and the report names them
all.

Cleanup rules (each one is tested):

* the sandbox is destroyed whatever happened before — success, failure, an unknown outcome, a
  client-side timeout, Ctrl-C — unless ``--keep``. Destroying is containment: the host never
  refuses it for load, and it preempts whatever is still in flight on the sandbox. The record of
  every operation, and the captured output, outlive the sandbox;
* nothing is destroyed when the host states that creating the sandbox left nothing behind
  (``effect: NOT_APPLIED``), or refused to create it;
* if it is *not established* whether the host accepted ``create``, there is no sandbox id to act
  on: the report says so and names the operation to ask about;
* a failed cleanup is reported loudly, with the exact command that finishes the job.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from acf_cli.client import HostClient, Outcome, expect, require_success
from acf_cli.errors import AcfCliError, HostUnreachable, MutationInterrupted, Refused
from acf_cli.execution import run_of
from acf_cli.requests import (
    Call,
    CommandSpec,
    ExecParams,
    SandboxCreateParams,
    SandboxTarget,
    exec_run,
    sandbox_create,
    sandbox_destroy,
    sandbox_start,
)
from acf_cli.resolve import target_of
from acf_cli.responses import OperationView, RunResult, SandboxBody
from acf_cli.wire import Effect

STEPS = ("create", "start", "exec", "destroy")


@dataclass(frozen=True, slots=True)
class RunSpec:
    create: SandboxCreateParams
    command: CommandSpec
    keep: bool = False
    #: Client-side patience per step. ``None``: until each operation ends.
    timeout_s: float | None = None


@dataclass(slots=True)
class RunReport:
    """Everything the command layer needs to render a result *or* an incident, whichever happened."""

    #: step -> operation id, known before the step's request is sent.
    operations: dict[str, str] = field(default_factory=dict)
    #: step -> the host's last word on that operation, for the steps that were answered.
    steps: dict[str, Outcome] = field(default_factory=dict)
    run: RunResult | None = None
    #: The sandbox the run is about, once the host has named it: ``(sandbox_id, generation)``.
    sandbox: tuple[str, int] | None = None
    #: ``destroyed`` | ``kept`` | ``none`` | ``failed`` | ``unknown``
    cleanup_state: str = "none"
    cleanup: str = "nothing to clean up"
    #: The first step that did not succeed, as the exception that states why.
    error: AcfCliError | None = None
    interrupted: bool = False

    @property
    def cleanup_failed(self) -> bool:
        return self.cleanup_state in {"failed", "unknown"}


class Runner:
    def __init__(self, client: HostClient, progress: Callable[[str], None] | None = None) -> None:
        self._client = client
        self._say = progress or (lambda _msg: None)

    # ------------------------------------------------------------------ public
    def run(self, spec: RunSpec) -> RunReport:
        rep = RunReport()
        try:
            self._say("creating the sandbox")
            created = self._step(rep, "create", sandbox_create(spec.create), spec)
            target = target_of(expect(created.result, SandboxBody).data)
            self._say(f"starting {target.sandbox_id}")
            self._step(rep, "start", sandbox_start(target), spec)
            self._say(f"running the command in {target.sandbox_id}")
            params = ExecParams(
                sandbox_id=target.sandbox_id, expected_generation=target.expected_generation, command=spec.command
            )
            self._step(rep, "exec", exec_run(params), spec)
        except AcfCliError as e:
            rep.error = e
        except MutationInterrupted as e:
            rep.interrupted = True
            self._learn_what_was_in_flight(rep, e.operation_id)
        except KeyboardInterrupt:
            rep.interrupted = True
        self._cleanup(spec, rep)
        return rep

    # ------------------------------------------------------------------ steps
    def _step(self, rep: RunReport, name: str, call: Call, spec: RunSpec) -> OperationView:
        def record(operation_id: str) -> None:
            rep.operations[name] = operation_id

        outcome = self._client.submit(call, timeout_s=spec.timeout_s, on_operation=record)
        self._note(rep, name, outcome)
        if outcome.operation is not None and name == "exec":
            # A cancelled or timed-out execution still has output and metrics: keep them.
            rep.run = run_of(outcome.operation)
        return require_success(outcome)

    @staticmethod
    def _note(rep: RunReport, name: str, outcome: Outcome) -> None:
        rep.steps[name] = outcome
        if outcome.operation is not None and outcome.operation.sandbox is not None:
            # Whatever became of the operation, it names the sandbox it was about. Cleanup needs that.
            rep.sandbox = outcome.operation.sandbox

    def _learn_what_was_in_flight(self, rep: RunReport, operation_id: str) -> None:
        """Ctrl-C arrived mid-step: ask once what the host recorded, so cleanup acts on facts."""
        step = next((name for name, op in rep.operations.items() if op == operation_id), None)
        if step is None:
            return
        try:
            self._note(rep, step, self._client.observe(operation_id))
        except AcfCliError:
            return

    # ------------------------------------------------------------------ cleanup
    def _cleanup(self, spec: RunSpec, rep: RunReport) -> None:
        if rep.sandbox is None:
            self._nothing_to_address(rep)
            return
        sandbox_id, generation = rep.sandbox
        created = rep.steps.get("create")
        if created is not None and created.operation is not None and created.operation.effect is Effect.NOT_APPLIED:
            rep.cleanup = "nothing to clean up: the host states that creating the sandbox left nothing behind"
            return
        if spec.keep:
            rep.cleanup_state = "kept"
            rep.cleanup = f"kept {sandbox_id} (generation {generation}); destroy it with: " + _destroy_command(
                sandbox_id
            )
            return
        try:
            target = SandboxTarget(sandbox_id=sandbox_id, expected_generation=generation)
        except ValueError:
            rep.cleanup_state = "failed"
            rep.cleanup = f"FAILED: the host named a sandbox this client cannot address ({sandbox_id!r})"
            return
        self._say(f"destroying {sandbox_id}")
        try:
            require_success(self._destroy(rep, target, spec))
        except AcfCliError as e:
            rep.cleanup_state = "failed"
            rep.cleanup = (
                f"FAILED: {e.message}. {sandbox_id} may still exist; finish with: {_destroy_command(sandbox_id)}"
            )
        except KeyboardInterrupt:
            rep.interrupted = True
            rep.cleanup_state = "unknown"
            operation = rep.operations.get("destroy", "<operation-id>")
            rep.cleanup = (
                f"interrupted while destroying {sandbox_id}; the host finishes what it accepted. "
                f"Ask it: acf-local operation get {operation}"
            )
        else:
            rep.cleanup_state = "destroyed"
            rep.cleanup = f"destroyed {sandbox_id}"
        self._refresh_superseded_execution(rep)

    def _destroy(self, rep: RunReport, target: SandboxTarget, spec: RunSpec) -> Outcome:
        def record(operation_id: str) -> None:
            rep.operations["destroy"] = operation_id

        outcome = self._client.submit(sandbox_destroy(target), timeout_s=spec.timeout_s, on_operation=record)
        rep.steps["destroy"] = outcome
        return outcome

    def _nothing_to_address(self, rep: RunReport) -> None:
        """No sandbox id is known. Either none exists, or it is not established whether one does."""
        operation = rep.operations.get("create")
        sent_nothing = operation is None or isinstance(rep.error, HostUnreachable | Refused)
        if sent_nothing or "create" in rep.steps:
            return
        rep.cleanup_state = "unknown"
        rep.cleanup = (
            f"not attempted: it is not established whether the host accepted `create` (operation {operation}). "
            f"If it did, a sandbox exists. Ask the host: acf-local operation get {operation}"
        )

    def _refresh_superseded_execution(self, rep: RunReport) -> None:
        """Destroying the sandbox ends an execution that was still in flight. Report how it really ended."""
        operation = rep.operations.get("exec")
        last = rep.steps.get("exec")
        if operation is None or (last is not None and last.operation is not None and last.operation.is_terminal):
            return
        try:
            now = self._client.observe(operation)
        except AcfCliError:
            return
        if now.operation is not None:
            rep.steps["exec"] = now
            rep.run = run_of(now.operation) or rep.run


def _destroy_command(sandbox_id: str) -> str:
    return f"acf-local sandbox destroy {sandbox_id} --yes"
