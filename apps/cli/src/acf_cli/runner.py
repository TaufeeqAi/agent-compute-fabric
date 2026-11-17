"""``acf-local run``: create -> start -> exec -> (destroy), with honest cleanup.

This is the Phase 1 milestone command. It is deliberately *composed from public operations* — the
host has no "run in a throwaway sandbox" primitive — so each step is an independently idempotent,
journaled operation with its own operation id, and the report lists them all (evidence).

Cleanup rules (each one is tested):

* a successful or definitively failed run destroys the sandbox it created, unless ``--keep``;
* **if any step's outcome is unknown, the sandbox is left in place** and its identity is printed:
  destroying it would erase the very evidence needed to learn what happened;
* an interrupt settles whatever step is in flight (an ``exec`` is cancelled; ``create``/``start`` are
  observed to completion), then cleans up as above — or leaves the sandbox alone if it cannot tell;
* a failed cleanup is reported loudly with the exact command to finish it — never swallowed.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from acf_cli.client import HostClient, raise_for_status
from acf_cli.errors import AcfCliError, OutcomeUnknown
from acf_cli.models import (
    Body,
    CommandSpec,
    ExecParams,
    ExecRequest,
    OperationStatus,
    ResponseEnvelope,
    RunResult,
    SandboxCreateParams,
    SandboxCreateRequest,
    SandboxDestroyRequest,
    SandboxResources,
    SandboxStartRequest,
    SandboxTarget,
    SandboxView,
)
from acf_cli.resolve import expect

#: Client-side patience for ``exec`` beyond the command's own timeout. The host's own operation
#: deadline is the command timeout + 3 s grace + 60 s (``HOST_GRACE_MS`` and ``deadline_ms`` in
#: ``execution/host-agent/src/lifecycle/exec.rs``); waiting slightly longer than that means we only
#: ever give up *after* the host has resolved the run one way or the other.
EXEC_MARGIN_S = 70.0
#: With no explicit ``--timeout`` we cannot know the policy default, so we simply wait for the
#: host (which always answers: its own deadline backstop kills the VM). Ctrl-C is the escape hatch.
EXEC_UNBOUNDED_S = 24 * 3600.0
INTERRUPT_SETTLE_S = 30.0


@dataclass(frozen=True, slots=True)
class RunSpec:
    image: str
    vcpus: int
    memory_mib: int
    disk_mib: int
    command: CommandSpec
    name: str | None = None
    keep: bool = False


@dataclass(slots=True)
class RunReport:
    """Everything the command layer needs to render a result *or* an incident, whichever happened."""

    run: RunResult | None = None
    sandbox: SandboxView | None = None
    cleanup: str = "not started"
    #: step name -> operation id, in submission order (``create``, ``start``, ``exec``, ``destroy``).
    operations: dict[str, str] = field(default_factory=dict)
    error: AcfCliError | None = None
    interrupted: bool = False
    #: True when some step's outcome is unknown: the sandbox was deliberately left in place.
    unresolved: bool = False
    #: True when destroying the sandbox failed: it may still exist and the operator must finish the job.
    cleanup_failed: bool = False
    #: The step whose mutation has been submitted but not yet answered (what an interrupt must settle).
    in_flight: str | None = None


@dataclass(frozen=True, slots=True)
class Settled:
    """What became of an interrupted ``exec`` after asking the host to cancel it."""

    #: The run's evidence, if the host recorded one (a cancelled run still has output and metrics).
    run: RunResult | None
    #: False when we could not learn how it ended: the operation is *unknown*, not "cancelled".
    resolved: bool


def cancel_and_settle(client: HostClient, op_id: str, *, timeout_s: float = INTERRUPT_SETTLE_S) -> Settled:
    """Ask the host to cancel ``op_id`` and observe how it ended. Never raises: the caller is unwinding.

    Cancellation is a *request*. The run ends when the host has stopped the workload and journaled
    the outcome, so the result is read back by observation (``operation_get``), not assumed.
    """
    try:
        client.cancel(op_id)
        final = client.wait_final(op_id, timeout_s=timeout_s)
    except AcfCliError:
        return Settled(run=None, resolved=False)
    if not final.status.is_final:
        return Settled(run=None, resolved=False)
    data = final.body() if final.status == OperationStatus.SUCCEEDED else None
    return Settled(run=data if isinstance(data, RunResult) else None, resolved=True)


class Runner:
    def __init__(self, client: HostClient, progress: Callable[[str], None] | None = None) -> None:
        self._client = client
        self._say = progress or (lambda _msg: None)

    # ------------------------------------------------------------------ public
    def run(self, spec: RunSpec) -> RunReport:
        rep = RunReport()
        try:
            self._create(spec, rep)
            self._start(rep)
            self._exec(spec, rep)
        except AcfCliError as e:
            rep.error = e
            if isinstance(e, OutcomeUnknown):
                rep.unresolved = True
        except KeyboardInterrupt:
            rep.interrupted = True
            self._settle_in_flight(rep)
        self._cleanup(spec, rep)
        return rep

    # ------------------------------------------------------------------ steps
    def _submit(self, rep: RunReport, step: str, body: Body, *, wait_s: float | None = None) -> ResponseEnvelope:
        """Send one mutation, remembering which step is in flight (so an interrupt knows what to settle)."""
        rep.in_flight = step

        def record(op_id: str) -> None:
            rep.operations[step] = op_id

        if wait_s is None:
            env = self._client.mutate_slow(body, on_operation=record)
        else:
            env = self._client.mutate(body, io_timeout_s=wait_s, resolve_deadline_s=wait_s, on_operation=record)
        rep.in_flight = None
        return env

    def _create(self, spec: RunSpec, rep: RunReport) -> None:
        self._say(f"creating sandbox ({spec.image}, {spec.vcpus} vCPU, {spec.memory_mib} MiB, network none)")
        params = SandboxCreateParams(
            name=spec.name,
            image=spec.image,
            resources=SandboxResources(
                vcpus=spec.vcpus, memory_mib=spec.memory_mib, disk_mib=spec.disk_mib, network="none"
            ),
        )
        env = raise_for_status(self._submit(rep, "create", SandboxCreateRequest(params=params)))
        rep.sandbox = expect(env, SandboxView)

    def _start(self, rep: RunReport) -> None:
        sandbox = self._need_sandbox(rep)
        self._say(f"starting {sandbox.sandbox_id}")
        target = SandboxTarget(sandbox_id=sandbox.sandbox_id, expected_generation=sandbox.generation)
        env = raise_for_status(self._submit(rep, "start", SandboxStartRequest(params=target)))
        rep.sandbox = expect(env, SandboxView)

    def _exec(self, spec: RunSpec, rep: RunReport) -> None:
        sandbox = self._need_sandbox(rep)
        self._say(f"running: {' '.join(spec.command.argv)}")
        timeout_ms = spec.command.limits.timeout_ms
        wait_s = timeout_ms / 1000 + EXEC_MARGIN_S if timeout_ms is not None else EXEC_UNBOUNDED_S
        request = ExecRequest(
            params=ExecParams(
                sandbox_id=sandbox.sandbox_id, expected_generation=sandbox.generation, command=spec.command
            )
        )
        env = raise_for_status(self._submit(rep, "exec", request, wait_s=wait_s))
        rep.run = expect(env, RunResult)

    def _need_sandbox(self, rep: RunReport) -> SandboxView:
        if rep.sandbox is None:  # pragma: no cover - guarded by control flow
            msg = "internal error: no sandbox"
            raise AssertionError(msg)
        return rep.sandbox

    # ------------------------------------------------------------------ interrupt
    def _settle_in_flight(self, rep: RunReport) -> None:
        """Ctrl-C arrived mid-step: learn how that step ended so cleanup can act on facts.

        ``exec`` can be cancelled; ``create``/``start`` cannot (Phase 1), so they are simply
        *observed* to completion. Anything we cannot resolve is marked unresolved, which makes
        cleanup leave the sandbox alone.
        """
        step = rep.in_flight
        rep.in_flight = None
        op_id = rep.operations.get(step) if step is not None else None
        if step is None or op_id is None:
            return
        self._say(f"interrupted during '{step}': resolving it before cleaning up")
        if step == "exec":
            settled = cancel_and_settle(self._client, op_id)
            rep.run = settled.run
            rep.unresolved = not settled.resolved
            return
        try:
            final = self._client.wait_final(op_id, timeout_s=INTERRUPT_SETTLE_S)
        except AcfCliError:
            rep.unresolved = True
            return
        if not final.status.is_final:
            rep.unresolved = True
            return
        data = final.body() if final.status == OperationStatus.SUCCEEDED else None
        if isinstance(data, SandboxView):
            rep.sandbox = data

    # ------------------------------------------------------------------ cleanup
    def _cleanup(self, spec: RunSpec, rep: RunReport) -> None:
        sandbox = rep.sandbox
        if sandbox is None:
            rep.cleanup = (
                "skipped: the outcome of 'create' is unknown, a sandbox may exist"
                if rep.unresolved
                else "nothing to clean up"
            )
            return
        if rep.unresolved:
            rep.cleanup = (
                f"skipped: an operation's outcome is unknown, so {sandbox.sandbox_id} was left in place for inspection"
            )
            return
        if spec.keep:
            rep.cleanup = f"kept ({sandbox.sandbox_id}, generation {sandbox.generation})"
            return
        self._say(f"destroying {sandbox.sandbox_id}")
        target = SandboxTarget(sandbox_id=sandbox.sandbox_id, expected_generation=sandbox.generation)
        try:
            env = raise_for_status(self._submit(rep, "destroy", SandboxDestroyRequest(params=target)))
        except AcfCliError as e:
            rep.cleanup_failed = True
            rep.cleanup = (
                f"FAILED: {e.message}. {sandbox.sandbox_id} may still exist; finish with: "
                f"acf-local sandbox destroy {sandbox.sandbox_id}"
            )
            return
        except KeyboardInterrupt:
            rep.interrupted = True
            rep.unresolved = True
            op = rep.operations.get("destroy", "<operation-id>")
            rep.cleanup = (
                f"interrupted while destroying {sandbox.sandbox_id}; the host finishes what it accepted. "
                f"Confirm with: acf-local operation get {op}"
            )
            return
        rep.sandbox = expect(env, SandboxView)
        rep.cleanup = f"destroyed ({sandbox.sandbox_id})"
