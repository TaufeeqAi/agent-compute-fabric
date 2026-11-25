"""Resolution: what the host holds for an entry of the ledger, and what the entry then becomes.

The fourth layer of the Runtime Service. It extends the platform operations and calls the layer that
observes the host and the shared ground. The reads, the exchange with the host and the containment
lane are built on it.

What is here: the read of an entry's operation, the rule that decides whether the absence of an
operation is proven, the three ways an entry leaves CLAIMED (bound, released, lost), the record of a
terminal outcome, the wait for an operation and its rendering, and the answer for a request whose key
the ledger already holds.

The rules it carries:

* an outcome is resolved by reading the host, never by guessing. A read says that the host holds the
  operation, or that it holds none, or nothing, and nothing is concluded from the third;
* NOT_FOUND proves that an operation never existed only when the three conditions of
  ``absence_proven`` hold. Then the entry is released and its key is free for a fresh attempt.
  Otherwise the entry becomes LOST;
* the terminal outcome of an operation is recorded once, while the host still holds the operation. An
  operation the host no longer holds is answered with that record, and with ``OUTCOME_LOST`` where
  there is none;
* a key the ledger holds is a resolution and not new work. It is answered from the entry and the
  host directly: no access policy, no rate or quota bound, no readiness gate;
* a key that was used for a different request is ``IDEMPOTENCY_CONFLICT``;
* a bind that a claim stands behind is durable before the answer. If it cannot be made durable the
  answer is ``OUTCOME_UNRESOLVED``: the caller asks again and finds the operation.
"""

from __future__ import annotations

import asyncio
import hmac
from dataclasses import dataclass
from typing import Final

from acf_api.command import model as m
from acf_api.command.answers import Answer, RequestContext
from acf_api.command.errors import Code, Retry
from acf_api.core.host import wire
from acf_api.core.host.binding import HostInfo, Lane
from acf_api.core.host.wire import HostOperation, HostRefusal, HostRequest, HostResult, Unreachable
from acf_api.core.identity.authenticator import Principal
from acf_api.core.pipeline import envelope, mapping
from acf_api.core.pipeline.credentials import AgentCredentials
from acf_api.core.pipeline.ground import _RETRY_AFTER_S, _Call, _dict
from acf_api.core.pipeline.observation import _lineage
from acf_api.core.store import ledger as lg
from acf_api.core.store.engine import StoreError

_RESOLVE_PAUSE_S: Final = 0.2


@dataclass(frozen=True, slots=True)
class _Absent:
    """The host answered NOT_FOUND for an operation id. ``as_of``: the committed state that answer reflects."""

    as_of: wire.AsOf | None


class Resolution(AgentCredentials):
    """An entry of the ledger, brought to what the host holds for it."""

    async def _resolve_by_reading(
        self, call: _Call, source: lg.NewEntry | lg.Entry, lane: Lane
    ) -> HostOperation | _Absent | None:
        """Read the operation of an entry: the operation, or that the host holds none, or ``None`` (not known)."""
        request = HostRequest(
            method="operation.get",
            owner_scope=call.principal.scope,
            params={"operation_id": source.operation_id},
            request_id=call.ctx.request_id,
        )
        read_lane = Lane.CONTAINMENT if lane is Lane.CONTAINMENT else Lane.RESOLUTION
        attempts = self.d.params.host_resolve_attempts
        for attempt in range(attempts):
            try:
                answer = await self.d.binding.read(request, lane=read_lane)
            except Unreachable:
                if attempt + 1 < attempts:
                    # A pause before the next attempt. After the last one there is nothing to wait for.
                    await asyncio.sleep(_RESOLVE_PAUSE_S * (attempt + 1))
                continue
            self.d.telemetry.count("host_resolutions")
            await self.observe(answer)
            if isinstance(answer, HostResult) and answer.type == "operation" and isinstance(answer.data, dict):
                return HostOperation(answer.data, answer.as_of)
            if isinstance(answer, HostRefusal) and answer.failure_class == wire.NOT_FOUND:
                return _Absent(answer.as_of)
            return None
        return None

    def absence_proven(self, entry: lg.Entry, info: HostInfo | None, as_of: wire.AsOf | None) -> bool:
        """Whether a NOT_FOUND for this entry's operation proves that the operation never existed.

        All three must hold: the entry was never bound; the host's lineage is the entry's and its commit
        sequence is not lower than any the platform has seen from it; and the host cannot have forgotten
        the operation, because it advertises a forgetting floor older than the entry's ``issued_at`` or,
        where it advertises none, the entry's ``issued_at`` is still inside its acceptance horizon.
        """
        s = self.d.standing
        if entry.state != lg.CLAIMED or entry.bound_seq is not None:
            return False
        if (
            as_of is None
            or entry.lineage is None
            or as_of.lineage != entry.lineage
            or as_of.lineage != s.pinned_lineage
        ):
            return False
        if s.reported_lineage is not None or as_of.sequence < s.sequence_high_water:
            return False
        if info is None:
            return False
        if info.forgetting_floor_ms is not None:
            return info.forgetting_floor_ms < entry.issued_at_ms
        return self.d.clock.wall_ms() - entry.issued_at_ms < info.acceptance_horizon_ms

    async def _bind(self, call: _Call, entry: lg.Entry | None, host_op: HostOperation, *, required: bool) -> None:
        if entry is None:
            return
        try:
            await self.d.ledger.bind(
                entry.entry_id,
                lineage=host_op.as_of.lineage if host_op.as_of else None,
                seq=host_op.as_of.sequence if host_op.as_of else None,
                peer_id=host_op.peer_id,
                at_ms=self.d.clock.wall_ms(),
            )
        except StoreError:
            if required:
                # The operation exists and the bind is not durable: the caller asks again and finds it.
                raise self._unresolved(call.ctx, call.key) from None
            return
        if host_op.terminal:
            await self.record_summary(entry, host_op)

    async def _release(self, entry: lg.Entry | None) -> None:
        if entry is None:
            return
        try:
            await self.d.ledger.release(entry.entry_id)
        except StoreError:
            # The entry stays CLAIMED. A later read finds nothing on the host, and the recovery rule decides.
            self.d.telemetry.count("ledger_release_failures")

    async def _lose(self, entry: lg.Entry) -> None:
        try:
            await self.d.ledger.lose(entry.entry_id, self.d.clock.wall_ms())
        except StoreError:
            self.d.telemetry.count("ledger_lose_failures")
        self.d.telemetry.count("outcomes_lost")

    async def record_summary(self, entry: lg.Entry, host_op: HostOperation) -> None:
        """Record the terminal outcome once, while the host still holds the operation."""
        if entry.summary is not None or not host_op.terminal or entry.state == lg.LOST:
            return
        view = host_op.view
        failure = _dict(view.get("failure"))
        table = self.d.table
        failure_class = failure.get("class") if isinstance(failure.get("class"), str) else None
        summary = lg.Summary(
            state=table.value("operation_state", view.get("state"))[0],
            effect=table.value("effect", view.get("effect"))[0] if view.get("effect") is not None else None,
            failure_code=table.value("failure_class", failure_class)[0] if failure_class else None,
            failure_retry=table.retry_for(failure_class) if failure_class else None,
            cleanup=table.value("cleanup", view.get("cleanup"))[0] if view.get("cleanup") is not None else None,
            operation_type=table.value("operation_type", view.get("operation_type"))[0],
            produced=envelope.produced(view),
            created_at=view.get("created") if isinstance(view.get("created"), str) else None,
            updated_at=view.get("updated") if isinstance(view.get("updated"), str) else None,
            initiated_by=table.value("issuer", view.get("issuer"))[0],
            actor=view.get("on_behalf_of") if isinstance(view.get("on_behalf_of"), str) else None,
        )
        try:
            await self.d.ledger.record_summary(entry.entry_id, summary, self.d.clock.wall_ms())
        except StoreError:
            self.d.telemetry.count("ledger_summary_failures")

    async def _finish(self, call: _Call, entry: lg.Entry | None, host_op: HostOperation, *, replayed: bool) -> Answer:
        """Wait as long as the caller asked, then render the operation as the host holds it now."""
        if not host_op.terminal and call.wait_s > 0:
            # The state in hand was read from the host a moment ago, so the first poll waits a full interval.
            followed = await self.d.follower.wait(
                call.principal.scope, host_op.operation_id, call.wait_s, call.ctx.request_id, fresh=True
            )
            if isinstance(followed, HostOperation):
                host_op = followed
                if entry is not None:
                    await self.record_summary(entry, host_op)
        view = mapping.operation(
            self.d.table,
            host_op.view,
            call.principal.project_id,
            _lineage(host_op, self.d.standing.pinned_lineage or ""),
            replayed=replayed,
            key_digest=call.key_digest,
        )
        call.audit.outcome = "accepted"
        call.audit.code = None
        call.audit.replayed = replayed
        call.audit.operation_id = host_op.operation_id
        if host_op.as_of is not None:
            call.audit.host_lineage, call.audit.host_sequence = host_op.as_of.lineage, host_op.as_of.sequence
        if view.target.execution_id:
            call.audit.execution_id = view.target.execution_id
        if replayed:
            self.d.telemetry.count("idempotent_replays")
        return self._view(
            "Operation",
            view,
            terminal=view.terminal,
            replayed=replayed,
            retry_after_s=None if view.terminal else _RETRY_AFTER_S,
        )

    # -------------------------------------------------------------- a key the ledger already holds
    async def _resolve(self, call: _Call, entry: lg.Entry) -> Answer | None:
        """Answer a request whose key the ledger holds. ``None``: the entry was released; proceed as new work.

        A resolution is not new work. It is answered from the entry and the host directly: no access
        policy, no rate or quota bound, no readiness gate.
        """
        ctx = call.ctx
        if not hmac.compare_digest(entry.fingerprint, call.fingerprint):
            self.d.telemetry.count("idempotency_conflicts")
            raise self._error(ctx, Code.IDEMPOTENCY_CONFLICT, "this idempotency key was used for a different request")
        call.audit.operation_id = entry.operation_id
        if entry.state == lg.LOST:
            return await self._answer_forgotten(call.principal, ctx, entry, key=call.key)
        if (
            entry.state == lg.CLAIMED
            and entry.owner_epoch == self.d.writer_epoch
            and entry.entry_id in self._entries_in_flight
        ):
            raise self._error(
                ctx,
                Code.REQUEST_IN_PROGRESS,
                "an earlier request with this idempotency key is still being decided",
                key=call.key,
            )
        found = await self._resolve_by_reading(call, entry, Lane.RESOLUTION)
        if isinstance(found, HostOperation):
            if entry.state == lg.CLAIMED:
                await self._bind(call, entry, found, required=False)
            else:
                await self.record_summary(entry, found)
            call.audit.event = "mutation.resolved"
            return await self._finish(call, entry, found, replayed=True)
        if isinstance(found, _Absent):
            if entry.state == lg.BOUND:
                # The host no longer holds a bound operation.
                await self._lose(entry)
                return await self._answer_forgotten(call.principal, ctx, entry, key=call.key)
            info = await self.host_info()
            if self.absence_proven(entry, info, found.as_of):
                await self._release(entry)
                return None
            await self._lose(entry)
            raise self._lost(ctx, call.key)
        raise self._unresolved(ctx, call.key)

    async def _answer_forgotten(
        self, principal: Principal, ctx: RequestContext, entry: lg.Entry, *, key: str | None
    ) -> Answer:
        """The answer for an operation the host no longer holds: the recorded terminal view, or OUTCOME_LOST."""
        if entry.state != lg.LOST:
            await self._lose(entry)
        summary = entry.summary
        if summary is None:
            raise self._lost(ctx, key)
        produced = summary.produced
        view = m.Operation(
            operation_id=entry.operation_id,
            project=principal.project_id,
            type=summary.operation_type,
            state=summary.state,
            terminal=m.is_terminal(summary.state),
            effect=summary.effect,
            failure=(
                m.Failure(
                    code=summary.failure_code,
                    retry=summary.failure_retry or Retry.NEVER.value,
                    message="recorded when the host reported this operation as ended",
                )
                if summary.failure_code
                else None
            ),
            cleanup=summary.cleanup,
            target=m.OperationTarget(
                sandbox_id=produced.get("sandbox_id"),
                generation=produced.get("generation"),
                snapshot_id=produced.get("snapshot_id"),
                snapshot_generation=produced.get("snapshot_generation"),
                execution_id=produced.get("execution_id"),
            ),
            initiated_by=summary.initiated_by,
            actor=mapping.parse_actor(summary.actor),
            created_at=summary.created_at,
            updated_at=summary.updated_at,
            replayed=True,
            recorded=True,
            idempotency_key_digest=entry.key_digest,
        )
        self.d.telemetry.count("recorded_views_served")
        return self._view("Operation", view, terminal=view.terminal, replayed=True)
