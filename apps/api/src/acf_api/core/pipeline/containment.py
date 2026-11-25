"""The containment lane: stop, destroy, cancel and delete.

The eighth layer of the Runtime Service. It extends the exchange with the host and calls it, the
resolution layer, the fixing of a request from the admission layer, and the shared ground.

What is here: the one path of a containment request, from the check of the grant to the answer.

The rules it carries:

* containment is never behind a rate, a quota, the readiness gate or a durable claim: what stops
  granting work must not stop a caller from stopping work;
* the grant is checked by a local rule that needs no read, and the access policy's port is not asked;
* the ledger lookup and the claim are attempted, and a failure of either does not stop the request.
  Idempotency still holds, because the derived operation id is the same on every attempt and the host
  deduplicates;
* a caller who states ``current`` chose whatever generation there is, so a restore that lands in
  between is tried again until the request's deadline. A validator the caller pinned with
  ``If-Match`` is never tried again;
* containment is never refused for audit: a record that cannot be written is counted.
"""

from __future__ import annotations

import asyncio
import logging

from acf_api.command.answers import Answer
from acf_api.command.errors import Code
from acf_api.core.host import wire
from acf_api.core.host.binding import Lane
from acf_api.core.pipeline import envelope
from acf_api.core.pipeline.exchange import Exchange
from acf_api.core.pipeline.ground import Refuse, _Call
from acf_api.core.policy import authorizer as az
from acf_api.core.store import ledger as lg
from acf_api.core.store.engine import StoreError


class Containment(Exchange):
    """The lane that nothing of the platform's own state may close."""

    # -------------------------------------------------------------- the containment lane
    async def _containment(self, call: _Call) -> Answer:  # noqa: PLR0912, PLR0915 - the lane, top to bottom
        """Stop, destroy, cancel, delete: never behind a rate, a quota, the readiness gate or a durable claim.

        The request was authenticated (from memory if the registry is unavailable) and its project was
        checked. Here the grant is checked by a local rule that needs no read, and the request is sent.
        The ledger lookup and the claim are attempted; a failure of either does not stop the request.
        Idempotency still holds, because the derived operation id is the same on every attempt and the
        host deduplicates.
        """
        principal, ctx, op, command = call.principal, call.ctx, call.op, call.command
        call.audit.event = "containment"
        deadline = self.d.clock.monotonic() + ctx.budget_ms / 1000 - self.d.params.edge_core_deadline_margin
        try:
            if not az.allows_containment(principal.grant, op.method):
                self.d.telemetry.count("authorization_denials", reason=az.R_METHOD)
                raise self._permission_denied(principal, ctx, op.method, az.R_METHOD)
            try:
                existing = await self.d.ledger.find(principal.project_id, principal.principal_id, call.key_digest)
            except StoreError:
                existing = None
            if existing is not None:
                resolved = await self._resolve(call, existing)
                if resolved is not None:
                    return resolved
            # A caller who states "current" chose whatever generation there is, so a restore that lands in
            # between is tried again. A validator the caller pinned with `If-Match` can never become valid
            # again: trying again would only repeat the same refused request until the deadline.
            current = envelope.stated_generation(command) == "current" and getattr(command, "if_match", None) is None
            while True:
                chosen, fixed = await self._fix(call, None, lane=Lane.CONTAINMENT)
                new = self._new_entry(call, chosen, None)
                self._describe(call, chosen)
                entry: lg.Entry | None
                try:
                    entry = await self.d.ledger.claim(new)
                except StoreError:
                    entry = None
                call.entry = entry
                if entry is not None:
                    self._entries_in_flight.add(entry.entry_id)
                call.audit.operation_id = new.operation_id
                try:
                    host_op, replayed = await asyncio.shield(
                        self._send(
                            call, entry, fixed, self.d.standing.info, lane=Lane.CONTAINMENT, required=False, new=new
                        )
                    )
                except Refuse as r:
                    conflict = r.answer.error.code == wire.REVISION_CONFLICT
                    if conflict and current and self.d.clock.monotonic() < deadline:
                        # The caller chose "whatever is current", and a restore landed in between. The refusal
                        # proved that nothing existed, so the next attempt is a fresh one.
                        if entry is not None:
                            self._entries_in_flight.discard(entry.entry_id)
                        call.sandbox_views.clear()
                        self.d.telemetry.count("containment_generation_retries")
                        continue
                    raise
                return await self._finish(call, entry, host_op, replayed=replayed)
        except Refuse as r:
            call.audit.outcome, call.audit.code, call.audit.reason = (
                r.answer.error.kind,
                r.answer.error.code,
                r.answer.error.reason,
            )
            raise
        except Exception:
            self.d.telemetry.log(logging.ERROR, "unexpected_error", request_id=ctx.request_id, command=command.type)
            raise (
                self._unresolved(ctx, call.key)
                if call.sent
                else self._error(ctx, Code.INTERNAL_ERROR, "the platform failed before anything was sent")
            ) from None
        finally:
            if call.entry is not None:
                self._entries_in_flight.discard(call.entry.entry_id)
            if call.audit.outcome is not None:
                # Containment is never refused for audit: a record that cannot be written is counted.
                await self.d.audit.record(call.audit)
