"""The exchange with the host: the claim, the submission and the bind.

The seventh layer of the Runtime Service. It extends the admission of granting work and calls the
resolution layer, the layer that observes the host and the shared ground. It decides nothing about
whether a request may be sent: what reaches it has been admitted.

What is here: the ledger entry of a request and the host request built from it, the description of
what ran for the audit record, the claim, and one exchange with the host with every way it can end.

The rules it carries:

* the operation id is derived from the deployment, the project, the principal, the step and the key,
  and ``issued_at`` is chosen once, with the entry. The host request is built from the entry's
  recorded values, so that it is the same request on every submission;
* for granting work the claim is durable before anything is sent, and a key is claimed once: a
  concurrent request with the same key is answered ``REQUEST_IN_PROGRESS``;
* from the claim to the bind the work runs to its end even if the caller goes away;
* an answer is ``REFUSED`` only when the platform knows that the request recorded nothing on the host
  or never left the platform. Only the binding can say that a request was not written. Any other
  failure leaves a doubt, and a doubt is resolved by reading and never answered "refused";
* a submission is retried only when the host could not be reached, which proves that nothing was
  written, and within the retry budget. A request whose absence on the host is proven is submitted
  once more, unchanged;
* a conflict on a derived id proves that an operation with that id exists. It never reaches a caller;
* a host refusal proves that the request created nothing: the entry is released before the answer;
* a request issued a moment ago that the host refuses as expired says that the two clocks differ. The
  answer is ``CLOCK_SKEW``, and granting work is held back, but for one probe in every period, until
  the host accepts a submission again;
* the audit record says what ran in identifiers, enumerations and keyed digests, never in a value.
"""

from __future__ import annotations

import asyncio
from typing import Any, Final

from acf_api.command import commands as c
from acf_api.command import model as m
from acf_api.command.answers import Answer
from acf_api.command.errors import Code
from acf_api.core.clock import rfc3339
from acf_api.core.host import wire
from acf_api.core.host.binding import HostInfo, Lane, RequestTooLarge
from acf_api.core.host.wire import HostOperation, HostRefusal, HostRequest, LostAnswer, Unreachable
from acf_api.core.pipeline import derivation, envelope
from acf_api.core.pipeline.admission import Admission
from acf_api.core.pipeline.ground import _Call, _dict
from acf_api.core.pipeline.resolution import _Absent
from acf_api.core.policy import authorizer as az
from acf_api.core.store import ledger as lg
from acf_api.core.store.engine import StoreError

_CONNECT_RETRY_PAUSES: Final = (0.1, 0.3)


class Exchange(Admission):
    """One claim, one submission, one bind."""

    def _new_entry(
        self, call: _Call, chosen: lg.Chosen, decision: az.Decision | None, *, version: str | None = None
    ) -> lg.NewEntry:
        """The entry of this request. ``version``: derive its operation id as an earlier release did."""
        principal, op = call.principal, call.op
        now = self.d.clock.wall_ms()
        derived_by = version if version is not None else derivation.DERIVATION_VERSION
        return lg.NewEntry(
            project_id=principal.project_id,
            principal_id=principal.principal_id,
            credential_id=principal.credential_id,
            key_digest=call.key_digest,
            fingerprint=call.fingerprint,
            derivation_version=derived_by,
            operation_id=derivation.derive_operation_id(
                deployment_id=self.d.deployment_id,
                project_id=principal.project_id,
                principal_id=principal.principal_id,
                step=op.host_method or op.method,
                key=call.key,
                version=derived_by,
            ),
            host_id=self.d.binding.host_id,
            op_class=op.operation_class.value,
            method=op.method,
            issued_at=rfc3339(now),
            issued_at_ms=now,
            chosen=chosen,
            owner_epoch=self.d.writer_epoch,
            lineage=self.d.standing.pinned_lineage,
            peer_id=self.d.standing.pinned_peer_id,
            decision_id=decision.decision_id if decision is not None else "local",
            policy_version=decision.policy_version if decision is not None else principal.policy_version,
            minted_key=call.minted_key,
            tool=call.tool,
            args_digest=call.args_digest,
            created_at_ms=now,
        )

    def _request(self, call: _Call, entry_like: lg.NewEntry | lg.Entry, fixed: envelope.Fixed) -> HostRequest:
        """The host request of an entry. Built from the entry's recorded values, the same on every submission."""
        return HostRequest(
            method=call.op.host_method or "",
            owner_scope=call.principal.scope,
            params=envelope.host_params(call.command, entry_like.chosen, fixed),
            operation_id=entry_like.operation_id,
            issued_at=entry_like.issued_at,
            on_behalf_of=call.principal.on_behalf_of,
            request_id=call.ctx.request_id,
            wait_ms=int(self.d.params.host_call_wait * 1000),
        )

    async def _claim_and_send(
        self,
        call: _Call,
        chosen: lg.Chosen,
        fixed: envelope.Fixed,
        decision: az.Decision,
        info: HostInfo,
        *,
        lane: Lane,
    ) -> Answer:
        new = self._new_entry(call, chosen, decision)
        held = await self._held_under_an_earlier_derivation(call, chosen, decision, lane)
        if held is not None:
            # The key was accepted before an upgrade. Its entry names the operation the host holds.
            new = held[0]
        self._describe(call, chosen)
        try:
            entry = await self.d.ledger.claim(new)
        except StoreError as e:
            raise self._error(
                call.ctx, Code.UPSTREAM_UNAVAILABLE, "the request ledger is unavailable; nothing was sent"
            ) from e
        if entry is None:
            # A concurrent request with this key claimed it between the lookup and here.
            raise self._error(
                call.ctx,
                Code.REQUEST_IN_PROGRESS,
                "an earlier request with this idempotency key is still being decided",
                key=call.key,
            )
        call.entry = entry
        self._entries_in_flight.add(entry.entry_id)
        call.audit.operation_id = entry.operation_id
        self.d.telemetry.count("ledger_claims")
        if held is not None:
            # Nothing is sent: the operation exists. The entry is bound to it, and the answer reports work
            # that was there before this request.
            await asyncio.shield(self._bind(call, entry, held[1], required=True))
            return await self._finish(call, entry, held[1], replayed=True)
        # From the claim to the bind the work runs to its end even if the caller goes away: abandoning a
        # wait cancels nothing, and an entry is not left CLAIMED for want of a listener.
        host_op, replayed = await asyncio.shield(self._send(call, entry, fixed, info, lane=lane, required=True))
        return await self._finish(call, entry, host_op, replayed=replayed)

    async def _held_under_an_earlier_derivation(
        self, call: _Call, chosen: lg.Chosen, decision: az.Decision, lane: Lane
    ) -> tuple[lg.NewEntry, HostOperation] | None:
        """The operation the host holds for this key under an earlier way of deriving ids, with its entry.

        While a release still names earlier derivation versions, a key the ledger does not know may have
        been accepted before the upgrade, under another operation id: a store that was restored to an
        earlier state has forgotten it, and the host's own duplicate detection cannot see it under the id
        of today. So every earlier id is read on the host before anything is submitted under the current
        one, and one key never becomes two host operations across an upgrade.

        Nothing has been claimed or sent when this runs. A host that cannot be asked therefore refuses the
        request: to go on would be to submit on a guess.
        """
        for version in derivation.PREVIOUS_VERSIONS:
            candidate = self._new_entry(call, chosen, decision, version=version)
            found = await self._resolve_by_reading(call, candidate, lane)
            if isinstance(found, HostOperation):
                self.d.telemetry.count("keys_found_under_an_earlier_derivation")
                return candidate, found
            if not isinstance(found, _Absent):
                raise self._error(
                    call.ctx,
                    Code.UPSTREAM_UNAVAILABLE,
                    "the host could not be asked whether this key was accepted before an upgrade; nothing was sent",
                )
        return None

    def _describe(self, call: _Call, chosen: lg.Chosen) -> None:
        """What ran, for the audit record: identifiers, enumerations and keyed digests. Never a value."""
        command, fp = call.command, self.d.fingerprint
        details: dict[str, Any] = {}
        if isinstance(command, c.CreateSandbox):
            spec = command.spec
            details = {
                "image": spec.image[:128],
                "vcpus": spec.resources.vcpus,
                "memory_mib": spec.resources.memory_mib,
                "disk_mib": spec.resources.disk_mib,
                "network_mode": spec.network.mode,
                "network_destinations": len(spec.network.entries)
                if isinstance(spec.network, m.NetworkAllowlist)
                else 0,
            }
        elif isinstance(command, c.Exec):
            call.audit.sandbox_id = command.sandbox_id
            view = call.sandbox_views.get(command.sandbox_id) or {}
            resources = _dict(view.get("resources"))
            network = _dict(resources.get("network"))
            details = {
                "argv_digest": fp.audit_digest(list(command.spec.argv)),
                "env_digest": fp.audit_digest(dict(command.spec.env)),
                "argv_items": len(command.spec.argv),
                "env_entries": len(command.spec.env),
                "network_mode": str(network.get("mode", ""))[:16] or None,
                "network_destinations": len(network.get("entries") or [])
                if isinstance(network.get("entries"), list)
                else 0,
            }
        elif isinstance(command, c.RestoreSnapshot):
            call.audit.snapshot_id = command.snapshot_id
        target = envelope.target_sandbox(command)
        if target is not None:
            call.audit.sandbox_id = target
        if isinstance(command, c.CancelExecution):
            call.audit.execution_id = command.execution_id
        if isinstance(command, c.DeleteSnapshot):
            call.audit.snapshot_id = command.snapshot_id
        for name, value in (
            ("generation", chosen.generation),
            ("lifetime_seconds", chosen.lifetime_seconds),
            ("timeout_seconds", chosen.timeout_seconds),
        ):
            if value is not None:
                details[name] = value
        if call.principal.kind == "developer" and call.ctx.interface != "rest":
            details["developer_credential_via_agent_interface"] = True
        call.audit.details = {k: v for k, v in details.items() if v is not None}

    # -------------------------------------------------------------- the exchange with the host
    async def _send(  # noqa: PLR0912, PLR0915 - every outcome of one exchange
        self,
        call: _Call,
        entry: lg.Entry | None,
        fixed: envelope.Fixed,
        info: HostInfo | None,
        *,
        lane: Lane,
        required: bool,
        new: lg.NewEntry | None = None,
    ) -> tuple[HostOperation, bool]:
        """Submit an entry and bring it to BOUND, or release it and raise the refusal.

        Returns the host's operation and whether it existed before this request. ``required``: a claim
        stands behind the request, and its bind must be durable before the answer. For containment the
        entry may be absent; the request is sent anyway.
        """
        ctx = call.ctx
        source = entry if entry is not None else new
        if source is None:  # pragma: no cover - the caller passes one of the two
            raise self._error(ctx, Code.INTERNAL_ERROR, "the platform failed before anything was sent")
        request = self._request(call, source, fixed)
        resubmitted = False
        answer: HostOperation | HostRefusal | None = None
        for attempt in range(len(_CONNECT_RETRY_PAUSES) + 1):
            self._retry_budget.request()
            # From here the request is in the binding's hands. Only the binding can say that it was not
            # written, and it says so with one of three exceptions. Any other failure leaves a doubt, and
            # a doubt is never answered "refused".
            call.sent = True
            try:
                answer = await self.d.binding.submit(request, lane=lane, principal_id=call.principal.principal_id)
                break
            except RequestTooLarge as e:
                call.sent = False
                await self._release(entry)
                raise self._error(ctx, Code.REQUEST_TOO_LARGE, "the request is larger than the host accepts") from e
            except wire.HostIdentityError as e:
                call.sent = False
                self.d.standing.identity_error = str(e)
                await self._release(entry)
                raise self._error(
                    ctx, Code.UPSTREAM_UNAVAILABLE, "the host's identity could not be verified; nothing was sent"
                ) from e
            except Unreachable as e:
                # The request was not written. This is the one failure a submission is retried on.
                call.sent = False
                self.d.telemetry.count("host_calls", method=request.method, outcome="unreachable")
                if attempt < len(_CONNECT_RETRY_PAUSES) and self._retry_budget.allow_retry():
                    await asyncio.sleep(_CONNECT_RETRY_PAUSES[attempt])
                    continue
                await self._release(entry)
                raise self._error(
                    ctx, Code.UPSTREAM_UNAVAILABLE, "the host could not be reached; nothing was sent"
                ) from e
            except LostAnswer:
                self.d.telemetry.count("host_lost_answers", method=request.method)
                break

        while answer is None:
            # The request was written and no answer came back: resolve by reading, never by guessing.
            found = await self._resolve_by_reading(call, source, lane)
            if isinstance(found, HostOperation):
                answer = found
                break
            if isinstance(found, _Absent) and entry is not None:
                if not self.absence_proven(entry, info, found.as_of):
                    await self._lose(entry)
                    raise self._lost(ctx, call.key)
                if not resubmitted:
                    # The same envelope, with the entry's recorded values, once more inside the same request.
                    resubmitted = True
                    try:
                        answer = await self.d.binding.submit(
                            request, lane=lane, principal_id=call.principal.principal_id
                        )
                    except (Unreachable, LostAnswer):
                        answer = None
                        again = await self._resolve_by_reading(call, source, lane)
                        if isinstance(again, HostOperation):
                            answer = again
                            break
                        raise self._unresolved(ctx, call.key) from None
                    break
            raise self._unresolved(ctx, call.key)

        await self.observe(answer)
        if isinstance(answer, HostRefusal):
            self.d.telemetry.count("host_calls", method=request.method, outcome=answer.failure_class[:40])
            if answer.failure_class == wire.IDEMPOTENCY_CONFLICT:
                # A conflict on a derived id proves that an operation with that id exists. It never reaches a caller.
                self.d.telemetry.diagnostic("host_conflict_on_derived_id")
                found = await self._resolve_by_reading(call, source, lane)
                if isinstance(found, HostOperation):
                    await self._bind(call, entry, found, required=required)
                    return found, True
                raise self._unresolved(ctx, call.key)
            # The refusal proves that this request created nothing: the entry is released before the answer.
            await self._release(entry)
            if answer.failure_class == wire.EXPIRED_REQUEST:
                # The request was issued moments ago, so the cause is the two clocks and not the request.
                self.d.standing.clock_offset = True
                self.d.standing.probe_at = self.d.clock.monotonic() + self.d.params.host_info_ttl
                self.d.telemetry.diagnostic("clock_offset_suspected")
                raise self._error(
                    ctx, Code.CLOCK_SKEW, "the platform's clock and the host's differ; nothing was created"
                )
            raise self._host_refusal(ctx, answer, said=wire.said(request.params))

        self.d.telemetry.count("host_calls", method=request.method, outcome="operation")
        if self.d.standing.clock_offset:
            # The host accepted a submission again: the offset is over.
            self.d.standing.clock_offset = False
        # An operation whose issued_at is not the entry's existed before this request.
        replayed = answer.issued_at is not None and answer.issued_at != source.issued_at
        await self._bind(call, entry, answer, required=required)
        return answer, replayed
