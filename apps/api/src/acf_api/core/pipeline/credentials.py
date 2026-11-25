"""Platform operations: the agent credentials a developer credential mints, lists and revokes.

The third layer of the Runtime Service. These operations reach no host: this layer extends the one
that observes the host, as every layer extends the one below it, and calls nothing of it. It calls
the shared ground only.

What is here: the rate bound of platform operations, the mint, the list and the revocation of agent
credentials, and the view of one.

The rules it carries:

* an agent credential is never wider than the credential that mints it: a narrowing the caller asks
  for is decided by the access policy, and without one the agent template applies, cut down to what
  the parent may do;
* an agent credential cannot outlive the platform's bound for one, nor the credential that mints it;
* the platform keeps a digest of an agent's key. The key itself is in the answer to the mint and
  nowhere else;
* a credential another credential minted, or one of another project, is reported as absent;
* a revocation is answered as done only when it is durable, and the authenticator forgets the
  credential at once;
* a mint and a revocation leave an audit record whatever their outcome.
"""

from __future__ import annotations

from dataclasses import replace

from acf_api.command import commands as c
from acf_api.command import model as m
from acf_api.command.answers import Answer, RequestContext
from acf_api.command.errors import Code, Retry
from acf_api.command.surface import PublicOperation
from acf_api.core.clock import rfc3339
from acf_api.core.identity import keys
from acf_api.core.identity.authenticator import Principal
from acf_api.core.pipeline.ground import Refuse
from acf_api.core.pipeline.observation import HostObservation
from acf_api.core.policy import authorizer as az
from acf_api.core.policy import grants as g
from acf_api.core.store import journal as j
from acf_api.core.store.engine import StoreError
from acf_api.core.store.registry import Credential, RegistryConflict


class AgentCredentials(HostObservation):
    """The operations of the platform itself. Nothing here reads or changes the host."""

    # ============================================================== platform operations (reach no host)
    async def _platform(
        self, principal: Principal, ctx: RequestContext, op: PublicOperation, command: c.Command
    ) -> Answer:
        refused = self._ops.admit(principal.project_id, principal.principal_id)
        if refused is not None:
            raise self._error(
                ctx,
                Code.RATE_LIMITED,
                "too many requests; ask again later",
                reason=refused.bound,
                retry_after_s=refused.retry_after_s,
            )
        if isinstance(command, c.MintAgentCredential):
            return await self._mint(principal, ctx, op, command)
        if isinstance(command, c.RevokeAgentCredential):
            return await self._revoke(principal, ctx, op, command)
        raise self._error(ctx, Code.UNSUPPORTED, "this version does not serve the command")

    def _credential_view(self, record: Credential, *, secret: str | None = None) -> m.AgentCredential:
        return m.AgentCredential(
            credential_id=record.credential_id,
            kind=record.kind,
            label=record.agent_label,
            display_prefix=record.display_prefix,
            status=record.status(self.d.clock.wall_ms()),
            issued_at=rfc3339(record.issued_at_ms),
            expires_at=rfc3339(record.expires_at_ms),
            narrowing=g.parse(record.narrowing_json).to_view() if record.narrowing_json else None,
            secret=secret,
        )

    async def _mint(
        self, principal: Principal, ctx: RequestContext, op: PublicOperation, command: c.MintAgentCredential
    ) -> Answer:
        event = self._event("credential.mint", principal, ctx, op)
        try:
            spec = command.spec
            if len(spec.label) > self.d.params.agent_label_max_len:
                raise self._error(ctx, Code.INVALID_REQUEST, "the label is too long", reason="label")
            template = self.d.templates["agent"]
            asked = g.normalize(spec.narrowing) if spec.narrowing is not None else None
            subject = az.Subject(
                principal.principal_id, principal.project_id, principal.kind, principal.grant, principal.policy_version
            )
            decision = await self.d.authorizer.decide(
                subject, az.PolicyRequest(method=op.method, narrowing=asked), None
            )
            event.decision_id, event.policy_version = decision.decision_id, decision.policy_version
            if not decision.allowed:
                raise self._permission_denied(principal, ctx, op.method, decision.reason or az.R_MINT)
            # Without a narrowing the agent template applies, and it too is cut down to what the parent may do.
            narrowing = asked if asked is not None else g.narrow(principal.grant, template)
            now = self.d.clock.wall_ms()
            lifetime_ms = spec.lifetime_seconds * 1000
            if (
                lifetime_ms > self.d.params.agent_credential_max_lifetime * 1000
                or now + lifetime_ms > principal.expires_at_ms
            ):
                raise self._error(
                    ctx,
                    Code.INVALID_REQUEST,
                    "an agent credential cannot outlive the platform's bound for one, nor the credential that mints it",
                    reason="lifetime",
                    retry=Retry.AFTER_CHANGE,
                )
            secret = keys.generate_key("agent")
            record = Credential(
                credential_id=keys.new_id("crd"),
                key_digest=keys.key_digest(secret),
                display_prefix=keys.display_prefix(secret),
                principal_id=principal.principal_id,
                project_id=principal.project_id,
                kind="agent",
                parent_credential_id=principal.credential_id,
                narrowing_json=narrowing.to_json(),
                agent_label=spec.label,
                issued_at_ms=now,
                expires_at_ms=now + lifetime_ms,
                first_used_at_ms=None,
                revoked_at_ms=None,
            )
            try:
                await self.d.registry.insert_credential(record)
            except RegistryConflict as e:
                raise self._error(
                    ctx,
                    Code.INVALID_REQUEST,
                    "a live agent credential of this principal already carries this label",
                    reason="label_in_use",
                    retry=Retry.AFTER_CHANGE,
                ) from e
            except StoreError as e:
                raise self._error(
                    ctx, Code.UPSTREAM_UNAVAILABLE, "the registry cannot be written right now; nothing was minted"
                ) from e
            event.outcome, event.code = "accepted", None
            event.details = {
                "subject_credential_id": record.credential_id,
                "subject_kind": "agent",
                "label": spec.label,
                "expires_at": rfc3339(record.expires_at_ms),
            }
            return self._view("AgentCredential", self._credential_view(record, secret=secret), created=True)
        except Refuse as r:
            event.outcome, event.code, event.reason = r.answer.error.kind, r.answer.error.code, r.answer.error.reason
            raise
        finally:
            await self.d.audit.record(event)

    async def _list_agent_credentials(self, principal: Principal, ctx: RequestContext) -> Answer:
        try:
            records = await self.d.registry.credentials(
                project_id=principal.project_id, parent=principal.credential_id, kind="agent"
            )
        except StoreError as e:
            raise self._error(ctx, Code.UPSTREAM_UNAVAILABLE, "the registry cannot be read right now") from e
        return self._view(
            "AgentCredentialList", m.AgentCredentialList(items=[self._credential_view(r) for r in records])
        )

    async def _revoke(
        self, principal: Principal, ctx: RequestContext, op: PublicOperation, command: c.RevokeAgentCredential
    ) -> Answer:
        if not az.allows_method(principal.grant, op.method):
            await self._audit_denial(principal, ctx, op, Code.PERMISSION_DENIED, az.R_METHOD)
            raise self._permission_denied(principal, ctx, op.method, az.R_METHOD)
        event = self._event("credential.revoke", principal, ctx, op)
        try:
            try:
                record = await self.d.registry.credential(command.credential_id)
            except StoreError as e:
                raise self._error(
                    ctx, Code.UPSTREAM_UNAVAILABLE, "the registry cannot be read right now; nothing was revoked"
                ) from e
            # A credential another credential minted, or of another project, is reported as absent.
            if (
                record is None
                or record.parent_credential_id != principal.credential_id
                or record.project_id != principal.project_id
            ):
                raise self._error(ctx, Code.NOT_FOUND, "no such agent credential among those this credential minted")
            try:
                revoked = await self.d.registry.revoke_credential(record.credential_id, self.d.clock.wall_ms())
            except (StoreError, j.JournalError) as e:
                raise self._error(
                    ctx, Code.UPSTREAM_UNAVAILABLE, "the revocation could not be made durable; ask again"
                ) from e
            self.d.authenticator.forget([record.credential_id])
            # From here on the revocation is durable and in force. Whatever fails below, the answer is that it
            # was done: a refusal would say that nothing happened.
            at_ms = self.d.clock.wall_ms()
            try:
                fresh = await self.d.registry.credential(record.credential_id)
            except StoreError:
                fresh = None
            if fresh is None or fresh.revoked_at_ms is None:
                fresh = replace(record, revoked_at_ms=at_ms)
            event.outcome = "accepted"
            event.details = {
                "subject_credential_id": record.credential_id,
                "subject_kind": "agent",
                "revoked": bool(revoked),
            }
            return self._view("AgentCredential", self._credential_view(fresh))
        except Refuse as r:
            event.outcome, event.code, event.reason = r.answer.error.kind, r.answer.error.code, r.answer.error.reason
            raise
        finally:
            await self.d.audit.record(event)
