"""The host, as an observation: what the platform knows of the host, and one read of it.

The second layer of the Runtime Service. It extends the shared ground and calls nothing else of the
pipeline. Every layer above it reads the host through here.

What is here: ``host.info`` and what it says the host offers, the pinning of the host's store lineage
and of the platform's own peer id, one read of the host under a principal's project scope, the
translation of a host refusal to the public surface, and the rate bound of reads.

The rules it carries:

* ``host.info`` is an observation, at most ``host_info_ttl`` old, and a read of it that fails keeps the
  last one. It decides what the platform offers. It is never used to skip a check the host makes;
* the first lineage and the first peer id the host shows are written to the security journal. Any
  other value is noted in the platform's standing, where it stops granting work;
* a host refusal reaches the caller with the host's class and advice, unchanged in name and meaning.
  A class this version does not know is passed on as ``UNRECOGNIZED`` with the host's own value, and
  a refusal of the platform itself is answered as the platform's fault, ``UPSTREAM_UNAVAILABLE``;
* an error answer never repeats request content: an explanation of the host that quotes the caller's
  own words is withheld;
* the platform offers a host feature only when the host advertises it, and never more. One-step
  create is not among what the platform itself implements (CG-3, LRO-10).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from acf_api.command.answers import RequestContext
from acf_api.command.errors import Code, Kind, Retry
from acf_api.command.surface import FEATURE_ALLOWLIST_NETWORK, FEATURE_SECRET_INJECTION, PLATFORM_FEATURES
from acf_api.core.host import wire
from acf_api.core.host.binding import HostInfo, HostRefused, Lane, RequestTooLarge
from acf_api.core.host.wire import HostOperation, HostRefusal, HostRequest, HostResult, Unreachable
from acf_api.core.identity.authenticator import Principal
from acf_api.core.parameters import host_violations
from acf_api.core.pipeline.ground import Ground, Refuse
from acf_api.core.store import journal as j


class HostObservation(Ground):
    """What the platform knows of the host, and the one way every layer above reads it."""

    # ============================================================== the host, as an observation
    async def host_info(self, *, force: bool = False) -> HostInfo | None:
        """``host.info``, at most ``host_info_ttl`` old. A failure keeps the last observation."""
        s = self.d.standing
        now = self.d.clock.monotonic()
        if not force and s.info is not None and s.info_at is not None and now - s.info_at < self.d.params.host_info_ttl:
            return s.info
        try:
            info = await self.d.binding.info()
        except wire.HostIdentityError as e:
            s.identity_error = str(e)
            self.d.telemetry.diagnostic("host_identity_unverified")
            return s.info
        except HostRefused as e:
            if e.refusal.failure_class in self.d.table.platform_faults:
                s.refused_by_host = e.refusal.failure_class
                self.d.telemetry.diagnostic("host_refuses_the_platform", host_class=e.refusal.failure_class)
            return s.info
        except Unreachable:
            self.d.telemetry.count("host_info_unreachable")
            return s.info
        if info.host_id != self.d.binding.host_id:
            s.identity_error = "the host reports another host_id than the configured one"
            self.d.telemetry.diagnostic("host_identity_unverified")
            return s.info
        s.identity_error = None
        # The host answered the platform: whatever made it refuse the platform itself is over.
        s.refused_by_host = None
        s.info, s.info_at = info, now
        await self._observe_lineage(info.lineage, None)
        if info.peer_id is not None:
            await self._observe_peer(info.peer_id)
        s.host_parameter_violations = host_violations(
            self.d.params,
            host_wait_max_s=info.wait_max_ms / 1000,
            host_operation_retention_s=info.operation_retention_ms / 1000,
            host_acceptance_horizon_s=info.acceptance_horizon_ms / 1000,
            host_max_request_bytes=info.max_request_bytes,
            host_identifier_slots=info.identifier_slots,
        )
        return info

    async def _observe_lineage(self, lineage: str, sequence: int | None) -> None:
        s = self.d.standing
        if not lineage:
            return
        if s.pinned_lineage is None:
            await self.d.journal.aappend(j.LINEAGE_PINNED, {"lineage": lineage, "host_id": self.d.binding.host_id})
            s.pinned_lineage = lineage
        if not s.observe_lineage(lineage, sequence) and s.reported_lineage is not None:
            self.d.telemetry.diagnostic("host_lineage_changed")

    async def _observe_peer(self, peer_id: str) -> None:
        s = self.d.standing
        if s.pinned_peer_id is None:
            await self.d.journal.aappend(j.PEER_RECORDED, {"peer_id": peer_id})
            s.pinned_peer_id = peer_id
        if not s.observe_peer(peer_id):
            self.d.telemetry.diagnostic("platform_peer_id_changed")

    async def observe(self, answer: wire.HostAnswer) -> None:
        """Note what an answer says about the host's lineage and about the platform's own peer id."""
        if answer.as_of is not None:
            await self._observe_lineage(answer.as_of.lineage, answer.as_of.sequence)
        peer = wire.peer_id_of(answer)
        if peer is not None:
            await self._observe_peer(peer)

    # ============================================================== reads
    async def _host_read(
        self,
        principal: Principal,
        ctx: RequestContext,
        method: str,
        params: dict[str, Any] | None,
        *,
        lane: Lane = Lane.GENERAL,
    ) -> HostResult:
        """One read of the host under the principal's project scope. A refusal is carried faithfully."""
        request = HostRequest(method=method, owner_scope=principal.scope, params=params, request_id=ctx.request_id)
        try:
            answer = await self.d.binding.read(request, lane=lane, principal_id=principal.principal_id)
        except RequestTooLarge as e:
            raise self._error(ctx, Code.REQUEST_TOO_LARGE, "the request is larger than the host accepts") from e
        except Unreachable as e:
            self.d.telemetry.count("host_calls", method=method, outcome="unreachable")
            raise self._error(
                ctx, Code.UPSTREAM_UNAVAILABLE, "the host could not be reached; the read can be repeated"
            ) from e
        await self.observe(answer)
        if isinstance(answer, HostRefusal):
            self.d.telemetry.count("host_calls", method=method, outcome=answer.failure_class[:40])
            raise self._host_refusal(ctx, answer, said=wire.said(params))
        self.d.telemetry.count("host_calls", method=method, outcome="result")
        return answer

    def _host_refusal(
        self, ctx: RequestContext, refusal: HostRefusal, key: str | None = None, *, said: Iterable[str] = ()
    ) -> Refuse:
        """A host refusal on the public surface: the host's class and advice, unchanged in name and meaning.

        ``said``: the strings the caller chose that the refused request carried. The host's explanation is
        passed on unless it quotes one of them.
        """
        table = self.d.table
        if refusal.failure_class in table.platform_faults:
            self.d.standing.refused_by_host = refusal.failure_class
            self.d.telemetry.diagnostic("host_refuses_the_platform", host_class=refusal.failure_class)
            return self._error(
                ctx,
                Code.UPSTREAM_UNAVAILABLE,
                "the platform cannot reach the execution plane right now; nothing was done",
            )
        public, raw = table.value("failure_class", refusal.failure_class)
        retry = refusal.retry if refusal.retry in {r.value for r in Retry} else Retry.NEVER.value
        try:
            code = Code(public)
        except ValueError:
            code = Code.UNRECOGNIZED
        if code is Code.UNRECOGNIZED:
            return self._error(
                ctx,
                Code.UNRECOGNIZED,
                "the host refused the request with a class this version does not know",
                retry=retry,
                code_raw=raw,
                kind=Kind.REFUSED,
            )
        message = refusal.message[:1000] or "the host refused the request"
        if wire.repeats(message, said):
            # The host explains some refusals in the caller's own words (an image alias, the name of an
            # environment variable, an identifier). An error answer never repeats request content, so
            # the class and the advice are passed on and that explanation is not.
            self.d.telemetry.count("host_messages_withheld", host_class=public[:40])
            message = "the host refused the request; its explanation quotes the request and is not repeated here"
        return self._error(ctx, code, message, retry=retry, key=key)

    def _bounds_for_read(self, principal: Principal, ctx: RequestContext) -> None:
        refused = self._reads.admit(principal.project_id, principal.principal_id)
        if refused is not None:
            self.d.telemetry.count("rate_limited", bound=refused.bound, kind="read")
            raise self._error(
                ctx,
                Code.RATE_LIMITED,
                "too many requests; ask again later",
                reason=refused.bound,
                retry_after_s=refused.retry_after_s,
            )

    def platform_features(self) -> set[str]:
        """What the platform itself implements, whatever the host offers.

        One-step create is not among it. It is one host operation or nothing (CG-3, LRO-10), and the host
        protocol this version speaks has no such operation: a host that began to advertise one would be
        asking for a request this version does not know how to write.
        """
        return set(PLATFORM_FEATURES)

    def offered_host_features(self, info: HostInfo) -> set[str]:
        """The host features the platform offers through its own surface. Never more than the host advertises."""
        offered: set[str] = set()
        if FEATURE_ALLOWLIST_NETWORK in info.features and "allowlist" in info.network_modes:
            offered.add(FEATURE_ALLOWLIST_NETWORK)
        if info.secret_injection:
            offered.add(FEATURE_SECRET_INJECTION)
        return offered


def _lineage(answer: HostOperation | HostResult, fallback: str) -> str:
    return answer.as_of.lineage if answer.as_of is not None else fallback
