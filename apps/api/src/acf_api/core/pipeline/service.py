"""The Runtime Service: the single admission pipeline of the platform.

Every public request passes through here, whichever interface it arrived through, in this order, and a
step never runs before the one listed above it::

    authenticate -> project entitlement -> operation class (containment continues in its own lane)
      -> ledger lookup: a known key leaves here as a resolution
      -> rate and in-flight bounds -> readiness
      -> fix the request -> access policy, with the target's recorded intent
      -> quota, under the project's admission lock
      -> ledger claim -> host binding -> bind or release, durable -> render

What the pipeline owns: identity, authorization, idempotency, bounds and the mapping to and from the
host. What it never does: decide lifecycle legality, capacity or ceilings (the host does); re-run an
ended operation; compose two host operations into one; submit anything outside a caller's own request.

Two rules shape most of the code below:

* an answer is ``REFUSED`` only when the platform knows that the request recorded nothing on the host
  or never left the platform. Otherwise it is ``UNRESOLVED``. A platform that cannot tell must say so;
* every value the platform adds to a request (``issued_at``, a generation read for ``current``, a
  lifetime, a timeout, a minted key) is chosen once, recorded with the claim, and sent unchanged on
  every later submission, so a retry is the same request and the host's duplicate detection does the rest.

The class is cut into layers, one module each. Every layer extends the one below it and calls only
what is beneath it, so the modules can be read one at a time, from the bottom::

    ground        what a service is built from, its state, the builders of answers
    observation   the host as an observation, and one read of it
    credentials   platform operations: agent credentials; they reach no host
    resolution    what the host holds for an entry of the ledger, and what the entry then becomes
    reads         the commands that change nothing
    admission     capabilities, the fixed request, the access policy, the quota
    exchange      the claim, the submission, the bind
    containment   the lane of stop, destroy, cancel and delete
    service       this module: the entry of every interface, and the order of the steps
"""

from __future__ import annotations

import asyncio
import hmac
import logging
from collections.abc import Iterator
from typing import Any, Protocol

from acf_api.command import commands as c
from acf_api.command import model as m
from acf_api.command.answers import AckAnswer, Answer, ErrorAnswer, RequestContext, VerifiedAnswer
from acf_api.command.errors import Code, Kind
from acf_api.command.surface import BY_COMMAND, BY_TOOL, OperationClass, PublicOperation
from acf_api.core.host.binding import Lane
from acf_api.core.identity import keys
from acf_api.core.identity.authenticator import AuthFailure, Principal, RegistryUnavailable
from acf_api.core.pipeline import envelope, tracing
from acf_api.core.pipeline.containment import Containment
from acf_api.core.pipeline.derivation import DERIVATION_VERSION
from acf_api.core.pipeline.ground import Deps, Refuse, _Call
from acf_api.core.policy import authorizer as az
from acf_api.core.store.engine import StoreError

#: What other modules import from here. ``Deps`` and ``Refuse`` are defined on the shared ground, and
#: ``DERIVATION_VERSION`` with the derivation; they are named here because this module is where the
#: rest of the core finds the pipeline.
__all__ = ["DERIVATION_VERSION", "AgentHandler", "Deps", "Refuse", "RuntimeService"]


class AgentHandler(Protocol):
    """What the pipeline asks of the agent-interaction module. Set once, when the core is assembled."""

    async def list_tools(self, principal: Principal) -> Answer: ...

    async def discover(self, principal: Principal) -> Answer: ...

    async def call_tool(
        self, principal: Principal, ctx: RequestContext, name: str, arguments: dict[str, Any]
    ) -> Answer: ...

    async def delivered(self, principal: Principal, token: str) -> None: ...


class RuntimeService(Containment):
    def __init__(self, deps: Deps) -> None:
        super().__init__(deps)
        #: The handler of agent calls. It is set here and not with the rest of the state, on the shared
        #: ground, because no layer below this one calls it.
        self.agent: AgentHandler | None = None

    # ============================================================== the three calls of the interface
    async def verify(self, credential: str | None, ctx: RequestContext) -> Answer:
        """The check an edge asks for before it reads a request body. Tells the edge nothing about the principal."""
        try:
            await self.d.authenticator.authenticate(credential)
        except AuthFailure:
            return self._unauthenticated(ctx).answer
        except RegistryUnavailable:
            return self._error(
                ctx, Code.UPSTREAM_UNAVAILABLE, "the credential cannot be verified right now; nothing was done"
            ).answer
        return VerifiedAnswer()

    async def handle(self, credential: str | None, ctx: RequestContext, command: c.Command, key: str | None) -> Answer:
        """One command. Returns an answer for every expected outcome; never raises one."""
        started = self.d.clock.monotonic()
        self._active += 1
        self._idle.clear()
        outcome = "error"
        try:
            name, attributes = tracing.span_of(ctx, command)
            with self.d.telemetry.span(name, parent=ctx.traceparent, server=True, **attributes) as span:
                answer = await self._handle(credential, ctx, command, key)
                failed = tracing.error_type(answer)
                if failed is not None:
                    span.set("error.type", failed)
            outcome = answer.kind if not isinstance(answer, ErrorAnswer) else answer.error.code
            return answer
        except Refuse as r:
            outcome = r.answer.error.code
            return r.answer
        except asyncio.CancelledError:
            outcome = "abandoned"
            raise
        except Exception:
            self.d.telemetry.log(logging.ERROR, "unexpected_error", request_id=ctx.request_id, command=command.type)
            self.d.telemetry.count("internal_errors", command=command.type)
            return self._error(ctx, Code.INTERNAL_ERROR, "the platform failed while handling the request").answer
        finally:
            self._active -= 1
            if self._active == 0:
                self._idle.set()
            self.d.telemetry.count("requests", command=command.type, interface=ctx.interface, outcome=outcome)
            self.d.telemetry.observe("request_seconds", self.d.clock.monotonic() - started, command=command.type)

    async def _handle(self, credential: str | None, ctx: RequestContext, command: c.Command, key: str | None) -> Answer:
        if isinstance(command, c.Info) and not credential:
            return self._view("Info", m.Info(api_versions=[m.API_VERSION], serving=self.d.standing.serving()))
        if isinstance(command, c.ListTools | c.CallTool | c.Discover):
            return await self._agent(credential, ctx, command)
        op = BY_COMMAND[command.type]
        containment = op.operation_class is OperationClass.CONTAINMENT
        principal = await self.authenticate(credential, ctx, containment=containment)
        return await self.dispatch(principal, ctx, command, key)

    async def _agent(
        self, credential: str | None, ctx: RequestContext, command: c.ListTools | c.CallTool | c.Discover
    ) -> Answer:
        """A command of an agent-protocol adapter. The adapter framed it; what it means is the core's."""
        if self.agent is None:
            raise self._error(ctx, Code.UNSUPPORTED, "this deployment serves no agent interface")
        containment = False
        if isinstance(command, c.CallTool):
            tool = BY_TOOL.get(command.name)
            containment = tool is not None and tool.operation_class is OperationClass.CONTAINMENT
        principal = await self.authenticate(credential, ctx, containment=containment)
        if isinstance(command, c.ListTools):
            return await self.agent.list_tools(principal)
        if isinstance(command, c.Discover):
            return await self.agent.discover(principal)
        return await self.agent.call_tool(principal, ctx, command.name, command.arguments)

    async def delivered(self, credential: str | None, ctx: RequestContext, delivery_token: str) -> Answer:
        """An adapter reports that a result was written in full to its transport."""
        try:
            principal = await self.authenticate(credential, ctx)
        except Refuse as r:
            return r.answer
        if self.agent is not None:
            await self.agent.delivered(principal, delivery_token)
        return AckAnswer()

    async def authenticate(
        self, credential: str | None, ctx: RequestContext, *, containment: bool = False
    ) -> Principal:
        try:
            return await self.d.authenticator.authenticate(credential, containment=containment)
        except AuthFailure as e:
            raise self._unauthenticated(ctx) from e
        except RegistryUnavailable as e:
            raise self._error(
                ctx, Code.UPSTREAM_UNAVAILABLE, "the credential cannot be verified right now; nothing was sent"
            ) from e

    async def dispatch(
        self,
        principal: Principal,
        ctx: RequestContext,
        command: c.Command,
        key: str | None,
        *,
        wait_s: float | None = None,
        minted_key: str | None = None,
        tool: str | None = None,
        args_digest: str | None = None,
        default_timeout: bool = False,
    ) -> Answer:
        """An authenticated command, through the rest of the pipeline. Also the entry of the agent interface."""
        op = BY_COMMAND[command.type]
        project = getattr(command, "project", None)
        if project is not None and not hmac.compare_digest(str(project), principal.project_id):
            # The resource name states a project this credential is not bound to. Nothing of it is visible.
            await self._audit_denial(principal, ctx, op, Code.NOT_FOUND, "project")
            raise self._error(ctx, Code.NOT_FOUND, "no such resource in the project this credential acts in")
        if op.operation_class in {OperationClass.CONTAINMENT, OperationClass.GRANTING}:
            return await self._mutate(
                principal,
                ctx,
                op,
                command,  # type: ignore[arg-type]
                key,
                wait_s,
                containment=op.operation_class is OperationClass.CONTAINMENT,
                minted_key=minted_key,
                tool=tool,
                args_digest=args_digest,
                default_timeout=default_timeout,
            )
        if op.operation_class is OperationClass.PLATFORM:
            return await self._platform(principal, ctx, op, command)
        return await self._read(principal, ctx, op, command, wait_s)

    # ============================================================== mutations
    async def _mutate(  # noqa: PLR0912 - the pipeline, top to bottom
        self,
        principal: Principal,
        ctx: RequestContext,
        op: PublicOperation,
        command: envelope.MutatingCommand,
        key: str | None,
        wait_s: float | None,
        *,
        containment: bool,
        minted_key: str | None = None,
        tool: str | None = None,
        args_digest: str | None = None,
        default_timeout: bool = False,
    ) -> Answer:
        p = self.d.params
        if key is None:
            raise self._error(
                ctx,
                Code.INVALID_REQUEST,
                "a request that can create an operation needs an idempotency key",
                reason="idempotency_key",
            )
        if len(key) > p.idempotency_key_max_len:
            raise self._error(ctx, Code.INVALID_REQUEST, "the idempotency key is too long", reason="idempotency_key")
        if _carries_credential(command):
            # Exact: the credential format and its checksum decide. Random text is never mistaken for one.
            raise self._error(
                ctx,
                Code.INVALID_REQUEST,
                "the request contains a platform credential; secrets are named by reference",
                reason="credential_in_request",
            )
        fp = self.d.fingerprint
        call = _Call(
            principal=principal,
            ctx=ctx,
            op=op,
            command=command,
            key=key,
            key_digest=fp.key_digest(key),
            fingerprint=fp.fingerprint(op.method, command),
            audit=self._event("mutation", principal, ctx, op),
            wait_s=self._wait(getattr(command, "wait", None) if wait_s is None else wait_s, ctx),
            decide_within_s=max(0.0, ctx.budget_ms / 1000 - p.edge_core_deadline_margin),
            minted_key=minted_key,
            tool=tool,
            args_digest=args_digest,
            default_timeout=default_timeout,
        )
        call.audit.idempotency_key_digest = call.key_digest
        call.audit.tool = tool
        if containment:
            return await self._containment(call)

        # ---- ledger lookup: a key the ledger already holds is a resolution, not new work.
        try:
            existing = await self.d.ledger.find(principal.project_id, principal.principal_id, call.key_digest)
        except StoreError as e:
            raise self._error(
                ctx, Code.UPSTREAM_UNAVAILABLE, "the request ledger is unavailable; nothing was sent"
            ) from e
        if existing is not None:
            resolved = await self._resolve(call, existing)
            if resolved is not None:
                return resolved
            # Absence was proven and the entry released: the request proceeds as a fresh attempt.

        # ---- bounds, then readiness. A request refused here leaves a counter and nothing durable.
        refused = self._ops.admit(principal.project_id, principal.principal_id)
        if refused is not None:
            self.d.telemetry.count("rate_limited", bound=refused.bound, kind="granting")
            raise self._error(
                ctx,
                Code.RATE_LIMITED,
                "too many requests; ask again later",
                reason=refused.bound,
                retry_after_s=refused.retry_after_s,
            )
        refused = self._in_flight.enter(principal.project_id, principal.principal_id)
        if refused is not None:
            self.d.telemetry.count("rate_limited", bound=refused.bound, kind="in_flight")
            raise self._error(
                ctx, Code.RATE_LIMITED, "too many requests in flight; ask again later", reason=refused.bound
            )
        try:
            return await self._granting(call)
        except Refuse as r:
            call.audit.outcome, call.audit.code, call.audit.reason = (
                r.answer.error.kind,
                r.answer.error.code,
                r.answer.error.reason,
            )
            call.audit.retry = r.answer.error.retry
            raise
        except Exception:
            # A failure of the platform itself. Whether the caller may be told "refused" depends on one fact only.
            self.d.telemetry.log(logging.ERROR, "unexpected_error", request_id=ctx.request_id, command=command.type)
            raise (
                self._unresolved(ctx, key)
                if call.sent
                else self._error(ctx, Code.INTERNAL_ERROR, "the platform failed before anything was sent")
            ) from None
        finally:
            self._in_flight.leave(principal.project_id, principal.principal_id)
            if call.entry is not None:
                self._entries_in_flight.discard(call.entry.entry_id)
            if call.audit.outcome is not None:
                await self.d.audit.record(call.audit)

    async def _granting(self, call: _Call) -> Answer:
        principal, ctx, op, command, p = call.principal, call.ctx, call.op, call.command, self.d.params
        s = self.d.standing
        if self._draining:
            raise self._error(ctx, Code.UPSTREAM_UNAVAILABLE, "the platform is stopping; nothing was sent")
        call.audit.outcome = Kind.REFUSED.value  # until something better is known
        if not principal.accepts_granting:
            raise self._error(
                ctx,
                Code.PERMISSION_DENIED,
                "the project is being deleted and accepts no new work",
                reason="project_deleting",
            )
        info = await self.host_info()
        if s.clock_offset and self.d.clock.monotonic() < s.probe_at:
            raise self._error(
                ctx, Code.CLOCK_SKEW, "the platform's clock and the host's differ; new work is refused until they agree"
            )
        reasons = s.not_ready_reasons()
        if reasons or info is None:
            raise self._error(
                ctx,
                Code.UPSTREAM_UNAVAILABLE,
                "the platform is not ready to accept new work; nothing was sent",
                reason=(reasons[0] if reasons else "host_not_yet_reached")[:64],
            )
        if p.audit_required and not self.d.audit.writable:
            raise self._error(
                ctx,
                Code.UPSTREAM_UNAVAILABLE,
                "the audit trail cannot be written; new work is refused",
                reason="audit_required",
            )
        if s.clock_offset:
            # One granting request in every period is let through as a probe.
            s.probe_at = self.d.clock.monotonic() + p.host_info_ttl

        # ---- a capability is offered only when the component that implements it advertises it.
        self._capabilities(call, info)

        # ---- fix the request: every value the platform adds is chosen here, once.
        chosen, fixed = await self._fix(call, info, lane=Lane.GENERAL)

        # ---- access policy, after the request is fixed and before the claim.
        decision = await self._decide(call, info, chosen)
        call.audit.decision_id, call.audit.policy_version = decision.decision_id, decision.policy_version
        if not decision.allowed:
            self.d.telemetry.count("authorization_denials", reason=decision.reason or "unknown")
            if decision.code is Code.UPSTREAM_UNAVAILABLE:
                raise self._error(
                    ctx,
                    Code.UPSTREAM_UNAVAILABLE,
                    "no access decision could be reached; nothing was sent",
                    reason=decision.reason,
                )
            raise self._permission_denied(principal, ctx, op.method, decision.reason or az.R_METHOD, decision.retry)

        # ---- quota under the project's admission lock, then claim, send and bind.
        counted = self._quota_kind(command)
        if counted is None:
            return await self._claim_and_send(call, chosen, fixed, decision, info, lane=Lane.GENERAL)
        lock = self._admission.setdefault(principal.project_id, asyncio.Lock())
        async with lock:
            await self._check_quota(call, counted)
            # The lock is held until the host has answered, or the request has ended unresolved.
            return await self._claim_and_send(call, chosen, fixed, decision, info, lane=Lane.GENERAL)

    # ============================================================== lifecycle
    def entry_in_flight(self, entry_id: int) -> bool:
        return entry_id in self._entries_in_flight

    def set_project_share(self, project_id: str, share: float | None) -> None:
        p = self.d.params
        share_value = share if share is not None else p.project_default_share
        self._ops.set_project_rate(project_id, p.usable_ops_per_minute() * share_value)
        self._reads.set_project_rate(project_id, p.usable_reads_per_minute() * share_value)

    async def drain(self) -> bool:
        """Refuse new granting work, then let the requests in flight finish or bind. ``False``: the bound passed."""
        self._draining = True
        try:
            await asyncio.wait_for(self._idle.wait(), self.d.params.drain_timeout)
        except TimeoutError:
            return False
        return True

    def metrics(self) -> dict[str, Any]:
        return {
            "requests_in_flight": self._in_flight.snapshot(),
            "entries_in_flight": len(self._entries_in_flight),
            "followed_operations": self.d.follower.followed(),
            "waiters": self.d.follower.waiters(),
        }


def _strings(value: object) -> Iterator[str]:
    """Every string inside a decoded value, keys included."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _strings(item)
    elif isinstance(value, list | tuple):
        for item in value:
            yield from _strings(item)


def _carries_credential(command: c.Command) -> bool:
    """Whether any string of a command is, or contains, a platform credential."""
    body = command.model_dump(mode="json", by_alias=True, exclude_none=True)
    return any(keys.contains_key(text) for text in _strings(body))
