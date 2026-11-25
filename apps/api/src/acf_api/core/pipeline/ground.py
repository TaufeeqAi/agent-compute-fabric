"""The shared ground of the Runtime Service: what every layer of the pipeline stands on.

The Runtime Service is one class, cut into layers. Each layer is a module with one class, and each
class extends the layer below it, so that a layer can call only what is beneath it::

    ground -> observation -> credentials -> resolution -> reads -> admission -> exchange
      -> containment -> service

This is the lowest layer. It calls no other layer, and it reads neither the host nor the ledger.

What is here: everything the pipeline is built from (``Deps``), one mutation on its way through the
pipeline (``_Call``), an unsuccessful outcome on its way to the caller (``Refuse``), the state one
service keeps in memory, the builders of answers and of audit events, and the bound of a wait.

The rules it carries:

* every error answer of the pipeline is built by ``_error``, from the error table: its kind, its
  retry advice and its pause are the table's unless the place that refuses knows better;
* an error answer names the idempotency key only when its kind is ``UNRESOLVED``: the key then says
  which request it is whose outcome is not known;
* the two answers for an outcome the platform does not know, ``OUTCOME_UNRESOLVED`` and
  ``OUTCOME_LOST``, are worded here once, so that every layer says the same thing;
* a denial for a token whose scopes left the method out carries the challenge that asks for a wider
  token;
* a wait is never longer than the public bound, nor than the caller's own budget less the margin the
  edge keeps for carrying the answer back.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Final

from acf_api.command import model as m
from acf_api.command.answers import Challenge, ErrorAnswer, RequestContext, ViewAnswer
from acf_api.command.errors import CODES, Code, Kind, Retry
from acf_api.command.surface import PublicOperation
from acf_api.core.audit.records import AuditEvent
from acf_api.core.audit.sink import AuditSink
from acf_api.core.clock import Clock
from acf_api.core.host.binding import HostBinding
from acf_api.core.identity.authenticator import Authenticator, Principal
from acf_api.core.identity.oauth import scope_for
from acf_api.core.parameters import Parameters
from acf_api.core.pipeline import envelope, mapping
from acf_api.core.pipeline.fingerprint import FingerprintKey
from acf_api.core.pipeline.follower import Follower
from acf_api.core.pipeline.limits import InFlight, RateLimiter, RetryBudget
from acf_api.core.pipeline.standing import Standing
from acf_api.core.policy import authorizer as az
from acf_api.core.policy import grants as g
from acf_api.core.store import journal as j
from acf_api.core.store import ledger as lg
from acf_api.core.store.registry import Registry
from acf_api.core.telemetry import Telemetry

_RETRY_AFTER_S: Final = 1


class Refuse(Exception):
    """An expected unsuccessful outcome on its way to the caller. Never crosses the command interface."""

    def __init__(self, answer: ErrorAnswer) -> None:
        super().__init__(answer.error.code)
        self.answer = answer


@dataclass(slots=True)
class Deps:
    """Everything the pipeline is built from. One set per core."""

    deployment_id: str
    params: Parameters
    clock: Clock
    registry: Registry
    ledger: lg.Ledger
    journal: j.SecurityJournal
    authenticator: Authenticator
    authorizer: az.Authorizer
    binding: HostBinding
    table: mapping.MappingTable
    fingerprint: FingerprintKey
    audit: AuditSink
    telemetry: Telemetry
    standing: Standing
    follower: Follower
    writer_epoch: int
    templates: dict[str, g.EffectiveGrant]
    #: The value of ``resource_metadata`` in a challenge, when the OAuth mode is configured.
    resource_metadata_url: str | None = None
    oauth_resource: str | None = None


@dataclass(slots=True)
class _Call:
    """One mutation on its way through the pipeline."""

    principal: Principal
    ctx: RequestContext
    op: PublicOperation
    command: envelope.MutatingCommand
    key: str
    key_digest: str
    fingerprint: str
    audit: AuditEvent
    wait_s: float
    #: Seconds this request has for a decision about it, counted on the event loop: the caller's budget,
    #: less the margin the edge keeps for carrying the answer back.
    decide_within_s: float
    #: Set when the request left the platform: from then on no answer may say "refused" on inference.
    sent: bool = False
    minted_key: str | None = None
    tool: str | None = None
    args_digest: str | None = None
    #: The agent interface supplies a runtime when the caller gave none.
    default_timeout: bool = False
    entry: lg.Entry | None = None
    sandbox_views: dict[str, dict[str, Any]] = field(default_factory=dict)


class Ground:
    """The state of one service, and the builders every layer above uses."""

    def __init__(self, deps: Deps) -> None:
        self.d = deps
        p = deps.params
        self._ops = RateLimiter(
            deps.clock,
            total_per_minute=p.usable_ops_per_minute(),
            project_per_minute=p.project_ops_per_minute(),
            principal_per_minute=p.principal_ops_per_minute(),
        )
        self._reads = RateLimiter(
            deps.clock,
            total_per_minute=p.usable_reads_per_minute(),
            project_per_minute=p.project_reads_per_minute(),
            principal_per_minute=p.project_reads_per_minute(),
        )
        self._in_flight = InFlight(principal_max=p.principal_max_in_flight, project_max=p.project_max_in_flight)
        self._retry_budget = RetryBudget(deps.clock, ratio=p.retry_budget_ratio)
        self._admission: dict[str, asyncio.Lock] = {}
        #: Ledger entries a live request of this process is working on.
        self._entries_in_flight: set[int] = set()
        self._draining = False
        self._active = 0
        self._idle = asyncio.Event()
        self._idle.set()

    # ============================================================== answers
    def _error(
        self,
        ctx: RequestContext,
        code: Code,
        message: str,
        *,
        retry: Retry | str | None = None,
        reason: str | None = None,
        retry_after_s: int | None = None,
        key: str | None = None,
        kind: Kind | None = None,
        code_text: str | None = None,
        code_raw: str | None = None,
        challenge: Challenge | None = None,
    ) -> Refuse:
        info = CODES[code]
        the_kind = kind or info.kind or Kind.REFUSED
        the_retry = retry if retry is not None else info.retry
        after = retry_after_s if retry_after_s is not None else (_RETRY_AFTER_S if info.retry_after else None)
        self.d.telemetry.count("answers", code=code.value, kind=the_kind.value)
        return Refuse(
            ErrorAnswer(
                error=m.ErrorBody(
                    code=code_text or code.value,
                    kind=the_kind.value,
                    retry=str(the_retry.value if isinstance(the_retry, Retry) else the_retry),
                    message=message,
                    request_id=ctx.request_id,
                    idempotency_key=key if the_kind is Kind.UNRESOLVED else None,
                    reason=reason,
                    code_raw=code_raw,
                ),
                retry_after_s=after,
                challenge=challenge,
            )
        )

    def _unauthenticated(self, ctx: RequestContext) -> Refuse:
        challenge = "Bearer"
        if self.d.resource_metadata_url is not None and ctx.interface != "rest":
            challenge = f'Bearer resource_metadata="{self.d.resource_metadata_url}"'
        return self._error(
            ctx,
            Code.UNAUTHENTICATED,
            "the request carries no credential that authenticates",
            challenge=Challenge(www_authenticate=challenge),
        )

    def _unresolved(self, ctx: RequestContext, key: str | None) -> Refuse:
        return self._error(
            ctx,
            Code.OUTCOME_UNRESOLVED,
            "the platform could not establish whether the request was accepted; ask again with the same "
            "idempotency key",
            key=key,
        )

    def _lost(self, ctx: RequestContext, key: str | None) -> Refuse:
        return self._error(
            ctx,
            Code.OUTCOME_LOST,
            "the outcome of this request is lost: the host holds no operation for it and its absence cannot be "
            "proven; inspect the target before acting again, and use a new key for a new intent",
            key=key,
        )

    def _view(
        self,
        name: str,
        view: m.ViewModel,
        *,
        terminal: bool | None = None,
        replayed: bool = False,
        retry_after_s: int | None = None,
        etag: str | None = None,
        created: bool = False,
    ) -> ViewAnswer:
        return ViewAnswer(
            view=name,
            body=view.model_dump(mode="json", by_alias=True, exclude_none=True),
            terminal=terminal,
            replayed=replayed,
            retry_after_s=retry_after_s,
            etag=etag,
            created=created,
        )

    # ============================================================== audit helpers
    def _event(self, name: str, principal: Principal, ctx: RequestContext, op: PublicOperation) -> AuditEvent:
        event = AuditEvent(event=name, at_ms=self.d.clock.wall_ms()).from_context(ctx)
        event.principal_id = principal.principal_id
        event.credential_id = principal.credential_id
        event.credential_kind = principal.kind
        event.agent_label = principal.agent_label
        event.project_id = principal.project_id
        event.method = op.method
        event.operation_class = op.operation_class.value
        return event

    async def _audit_denial(
        self, principal: Principal, ctx: RequestContext, op: PublicOperation, code: Code, reason: str
    ) -> None:
        event = self._event("authorization.denied", principal, ctx, op)
        event.outcome, event.code, event.reason = Kind.REFUSED.value, code.value, reason
        self.d.telemetry.count("authorization_denials", reason=reason)
        await self.d.audit.record(event)

    async def _audit_output(
        self,
        principal: Principal,
        ctx: RequestContext,
        op: PublicOperation,
        execution_id: str,
        stream: str,
        offset: int,
        size: int,
    ) -> None:
        event = self._event("execution.output.read", principal, ctx, op)
        event.execution_id, event.outcome = execution_id, "served"
        event.details = {"stream": stream, "offset": offset, "bytes": size}
        await self.d.audit.record(event)

    def _permission_denied(
        self, principal: Principal, ctx: RequestContext, method: str, reason: str, retry: Retry = Retry.NEVER
    ) -> Refuse:
        """A denial. For a token whose scopes left the method out, the challenge that asks for a wider token."""
        challenge = None
        if reason == az.R_METHOD and method in principal.scoped_out and self.d.resource_metadata_url is not None:
            challenge = Challenge(
                www_authenticate=(
                    f'Bearer error="insufficient_scope", scope="{scope_for(method)}", '
                    f'resource_metadata="{self.d.resource_metadata_url}"'
                )
            )
        return self._error(
            ctx,
            Code.PERMISSION_DENIED,
            "the credential's grant does not allow this",
            reason=reason,
            retry=retry,
            challenge=challenge,
        )

    # ============================================================== waits
    def _wait(self, asked: float | None, ctx: RequestContext, *, default: float | None = None) -> float:
        """How long this request waits for its operation: what was asked, capped by the bound and by the budget."""
        p = self.d.params
        wanted = asked if asked is not None else (p.public_wait_max if default is None else default)
        budget = ctx.budget_ms / 1000 - p.edge_core_deadline_margin
        return max(0.0, min(float(wanted), p.public_wait_max, budget))


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}
