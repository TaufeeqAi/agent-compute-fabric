"""Admission of granting work: what is decided between readiness and the claim.

The sixth layer of the Runtime Service. It extends the reads and calls the layer that observes the
host and the shared ground. The service runs these steps in their order; the containment lane uses
the fixing of a request and nothing else of them.

What is here: the check that a capability is offered, the fixing of a request, the recorded intent of
what a request targets, the decision of the access policy, and the quota.

The rules it carries:

* a capability is offered only when the component that implements it advertises it. Create and start
  as one operation is refused before anything is sent, and never built from a create and a start;
* a value the platform adds to a request (a generation read for ``current``, a lifetime, a timeout) is
  chosen here, once. It is recorded with the claim and sent unchanged on every later submission;
* fixing a request decides nothing about its legality: the host does that;
* the access policy judges the request after it is fixed, together with the recorded intent of its
  target. An intent that cannot be read is unreadable; it is never assumed;
* a decision is taken within the request's own deadline. A failure and a deadline are the same answer:
  no decision, and granting work is refused with nothing sent;
* a quota is counted on the host, while the service holds the project's admission lock. No counter is
  stored: the host's count is the only one.
"""

from __future__ import annotations

import asyncio
import math
from typing import Any, Final

from acf_api.command import commands as c
from acf_api.command import model as m
from acf_api.command.errors import Code, Retry
from acf_api.command.surface import FEATURE_ALLOWLIST_NETWORK, FEATURE_CREATE_WITH_START, FEATURE_SECRET_INJECTION
from acf_api.core.host.binding import HostInfo, Lane
from acf_api.core.pipeline import envelope, mapping
from acf_api.core.pipeline.ground import Refuse, _Call, _dict
from acf_api.core.pipeline.reads import Reads
from acf_api.core.policy import authorizer as az
from acf_api.core.store import ledger as lg

_LIST_PAGE: Final = 1000
_MAX_COUNT_PAGES: Final = 64


class Admission(Reads):
    """The steps of granting work that come before the claim."""

    def _capabilities(self, call: _Call, info: HostInfo) -> None:
        command, ctx = call.command, call.ctx
        if isinstance(command, c.CreateSandbox):
            if command.spec.start:
                # Refused before anything is sent, and never built from a create and a start.
                raise self._error(
                    ctx,
                    Code.UNSUPPORTED,
                    "create and start as one operation is not offered; create the sandbox, then start it",
                    reason=FEATURE_CREATE_WITH_START,
                )
            if isinstance(
                command.spec.network, m.NetworkAllowlist
            ) and FEATURE_ALLOWLIST_NETWORK not in self.offered_host_features(info):
                raise self._error(
                    ctx,
                    Code.UNSUPPORTED,
                    "the host does not offer the allowlist network mode",
                    reason=FEATURE_ALLOWLIST_NETWORK,
                )
        if isinstance(command, c.Exec) and command.spec.secret_env and not info.secret_injection:
            raise self._error(
                ctx, Code.UNSUPPORTED, "the host does not offer secret injection", reason=FEATURE_SECRET_INJECTION
            )

    async def _sandbox_view(self, call: _Call, sandbox_id: str, lane: Lane) -> dict[str, Any]:
        """The host's view of a sandbox, read at most once per request."""
        cached = call.sandbox_views.get(sandbox_id)
        if cached is not None:
            return cached
        result = await self._host_read(call.principal, call.ctx, "sandbox.inspect", {"sandbox": sandbox_id}, lane=lane)
        view = _dict(result.data)
        call.sandbox_views[sandbox_id] = view
        return view

    async def _fix(self, call: _Call, info: HostInfo | None, *, lane: Lane) -> tuple[lg.Chosen, envelope.Fixed]:
        """Choose every value the platform adds. Read what must be read; decide nothing about legality."""
        principal, ctx, command, p = call.principal, call.ctx, call.command, self.d.params
        generation: int | None = None
        lifetime: int | None = None
        timeout: int | None = None
        if_revision: int | None = None
        cancel_operation: str | None = None

        target = envelope.target_sandbox(command)
        if envelope.stated_generation(command) == "current" and target is not None:
            view = await self._sandbox_view(call, target, lane)
            number = view.get("generation")
            if not isinstance(number, int) or isinstance(number, bool):
                raise self._error(ctx, Code.UPSTREAM_UNAVAILABLE, "the host did not report the sandbox's generation")
            generation = number

        validator = getattr(command, "if_match", None)
        if validator is not None:
            if_revision = mapping.parse_revision(validator, self.d.standing.pinned_lineage or "")
            if if_revision is None:
                raise self._error(
                    ctx,
                    Code.INVALID_REQUEST,
                    "the If-Match value is not a validator of the resource as the host holds it now; read it again",
                    reason="if_match",
                    retry=Retry.AFTER_CHANGE,
                )

        creates_sandbox = isinstance(command, c.CreateSandbox) or (
            isinstance(command, c.RestoreSnapshot) and isinstance(command.spec.target, m.RestoreAsNew)
        )
        if creates_sandbox and principal.kind == "agent" and info is not None:
            # What an agent creates expires with it: no later than the credential, plus a grace.
            requested = (
                command.spec.lifetime_seconds
                if isinstance(command, c.CreateSandbox)
                else command.spec.target.lifetime_seconds  # type: ignore[union-attr]
            )
            wanted = requested if requested is not None else info.lifetime_default_secs
            remaining = math.ceil((principal.expires_at_ms - self.d.clock.wall_ms()) / 1000 + p.agent_expiry_grace)
            lifetime = max(1, min(wanted, remaining))

        if isinstance(command, c.Exec) and call.default_timeout and command.spec.timeout_seconds is None:
            timeout = max(1, min(p.mcp_exec_default_timeout, principal.grant.ceilings.execution_timeout_seconds))

        if isinstance(command, c.CancelExecution):
            result = await self._host_read(
                principal, ctx, "run.inspect", {"run_id": mapping.host_run_id(command.execution_id)}, lane=lane
            )
            data = _dict(result.data)
            found = data.get("operation_id")
            if not isinstance(found, str):
                raise self._error(ctx, Code.NOT_FOUND, "no such execution in this project")
            cancel_operation = found

        return lg.Chosen(generation, lifetime, timeout), envelope.Fixed(if_revision, cancel_operation)

    async def _snapshot_intent(self, call: _Call, command: c.RestoreSnapshot) -> az.Intent:  # noqa: PLR0912 - the search for the snapshot, then the two cases in which its intent is readable
        """The recorded intent of a snapshot, read through a sandbox that still carries it.

        The snapshot view shows the sandbox and generation it was taken from, and no resources and no
        network intent. Its intent is readable in two cases only: the generation it was taken from is
        still the current generation of its source sandbox; or the sandbox the restore targets, or the
        source sandbox, shows this snapshot as the one its current generation was restored from.
        """
        principal, ctx = call.principal, call.ctx
        wanted = (command.snapshot_id, command.spec.snapshot_generation)
        source: tuple[str, int] | None = None
        found = False
        cursor: Any = None
        for _ in range(_MAX_COUNT_PAGES):
            params: dict[str, Any] = {"limit": _LIST_PAGE}
            if cursor is not None:
                params["changed_since"] = cursor
            page = _dict((await self._host_read(principal, ctx, "snapshot.list", params)).data)
            for item in page.get("items") or []:
                ref = item.get("snapshot") if isinstance(item, dict) else None
                if isinstance(ref, dict) and (ref.get("snapshot_id"), ref.get("snapshot_generation")) == wanted:
                    found = True
                    raw = item.get("source_sandbox")
                    if isinstance(raw, list) and len(raw) == 2 and isinstance(raw[0], str) and isinstance(raw[1], int):  # noqa: PLR2004
                        source = (raw[0], raw[1])
                    break
            if found or not page.get("more"):
                break
            cursor = page.get("next")
        if not found:
            raise self._error(ctx, Code.NOT_FOUND, "no such snapshot in this project")

        candidates: list[str] = []
        if isinstance(command.spec.target, m.RestoreInPlace):
            candidates.append(command.spec.target.sandbox_id)
        if source is not None and source[0] not in candidates:
            candidates.append(source[0])
        for sandbox_id in candidates:
            try:
                view = await self._sandbox_view(call, sandbox_id, Lane.GENERAL)
            except Refuse as r:
                if r.answer.error.code == Code.NOT_FOUND.value:
                    continue
                raise
            restored_from = view.get("source_snapshot")
            carries = (
                isinstance(restored_from, dict)
                and (
                    restored_from.get("snapshot_id"),
                    restored_from.get("snapshot_generation"),
                )
                == wanted
            )
            same_generation = source is not None and sandbox_id == source[0] and view.get("generation") == source[1]
            if carries or same_generation:
                return envelope.intent_of(view)
        return az.UNREADABLE

    async def _decide(self, call: _Call, info: HostInfo, chosen: lg.Chosen) -> az.Decision:
        principal, command, op = call.principal, call.command, call.op
        subject = az.Subject(
            principal.principal_id, principal.project_id, principal.kind, principal.grant, principal.policy_version
        )
        limits = az.HostLimits(
            network_modes=info.network_modes,
            max_vcpus=info.max_vcpus,
            max_memory_mib=info.max_memory_mib,
            max_disk_mib=info.max_disk_mib,
            max_runtime_seconds=info.max_runtime_ms // 1000,
            lifetime_default_seconds=info.lifetime_default_secs,
            lifetime_max_seconds=info.lifetime_max_secs,
        )
        request: az.PolicyRequest
        if isinstance(command, c.CreateSandbox):
            spec = command.spec
            lifetime = chosen.lifetime_seconds or spec.lifetime_seconds or info.lifetime_default_secs
            request = az.PolicyRequest(
                method=op.method,
                image=spec.image,
                vcpus=spec.resources.vcpus,
                memory_mib=spec.resources.memory_mib,
                disk_mib=spec.resources.disk_mib,
                network_mode=spec.network.mode,
                entries=envelope.requested_entries(spec.network),
                lifetime_seconds=lifetime,
            )
        elif isinstance(command, c.Exec):
            timeout = chosen.timeout_seconds or command.spec.timeout_seconds or limits.max_runtime_seconds
            view = await self._sandbox_view(call, command.sandbox_id, Lane.GENERAL)
            request = az.PolicyRequest(method=op.method, timeout_seconds=timeout, targets=(envelope.intent_of(view),))
        elif isinstance(command, c.StartSandbox | c.CreateSnapshot):
            view = await self._sandbox_view(call, command.sandbox_id, Lane.GENERAL)
            request = az.PolicyRequest(method=op.method, targets=(envelope.intent_of(view),))
        elif isinstance(command, c.RestoreSnapshot):
            intent = await self._snapshot_intent(call, command)
            lifetime_new = None
            if isinstance(command.spec.target, m.RestoreAsNew):
                lifetime_new = (
                    chosen.lifetime_seconds or command.spec.target.lifetime_seconds or info.lifetime_default_secs
                )
            request = az.PolicyRequest(method=op.method, lifetime_seconds=lifetime_new, targets=(intent,))
        else:
            request = az.PolicyRequest(method=op.method)
        try:
            # A decision is taken within the request's own deadline. Whatever fills the port may be slow or
            # may fail; either way no decision was reached, and granting work is refused with nothing sent.
            # Containment never comes here: it is decided by a local rule that depends on nothing.
            return await asyncio.wait_for(self.d.authorizer.decide(subject, request, limits), call.decide_within_s)
        except Exception:  # a failure and a deadline are the same answer: no decision
            self.d.telemetry.count("policy_unavailable")
            return az.unavailable(subject)

    def _quota_kind(self, command: envelope.MutatingCommand) -> str | None:
        if isinstance(command, c.CreateSandbox):
            return "sandboxes"
        if isinstance(command, c.RestoreSnapshot) and isinstance(command.spec.target, m.RestoreAsNew):
            return "sandboxes"
        if isinstance(command, c.CreateSnapshot):
            return "snapshots"
        return None

    async def _check_quota(self, call: _Call, kind: str) -> None:
        """Count on the host, inside the lock. No counter is stored: the host's count is the only one."""
        p = self.d.params
        quota = p.quota_sandboxes() if kind == "sandboxes" else p.quota_snapshots()
        method = "sandbox.list" if kind == "sandboxes" else "snapshot.list"
        gone = "DESTROYED" if kind == "sandboxes" else "DELETED"
        count = 0
        cursor: Any = None
        for _ in range(_MAX_COUNT_PAGES):
            params: dict[str, Any] = {"limit": _LIST_PAGE}
            if cursor is not None:
                params["changed_since"] = cursor
            page = _dict((await self._host_read(call.principal, call.ctx, method, params)).data)
            count += sum(1 for item in page.get("items") or [] if isinstance(item, dict) and item.get("state") != gone)
            if count >= quota or not page.get("more"):
                break
            cursor = page.get("next")
        if count >= quota:
            self.d.telemetry.count("quota_refusals", kind=kind)
            raise self._error(
                call.ctx,
                Code.PERMISSION_DENIED,
                f"the project has reached its quota of {kind}",
                reason=az.R_QUOTA,
                retry=Retry.AFTER_CHANGE,
            )
