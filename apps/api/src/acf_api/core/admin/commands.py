"""Operator commands: projects, principals, roles, developer keys, subject bindings, acknowledgements.

These are the actions that are *never* reachable through a public interface. They arrive on the admin
socket, which admits only the core's own operating-system identity and root, and each of them is
audited as an operator action.

A project is the unit of isolation: its scope string is the owner scope of every host request made in
it, and the host cannot check that scope. So the rules here are strict:

* a scope string comes from the random source, is journaled before the project can be used, and is
  never reused or changed;
* a project becomes ACTIVE only after the host was listed under its scope and nothing was found;
* a project is DELETED only when the host holds no sandbox and no snapshot under its scope, and its
  scope is then retired for good;
* revoking the last credential of a project deletes nothing.
"""

from __future__ import annotations

import json
from typing import Any, Final

from pydantic import ValidationError

from acf_api.command import model as m
from acf_api.core.audit.records import AuditEvent
from acf_api.core.clock import rfc3339
from acf_api.core.host.binding import Lane
from acf_api.core.host.wire import HostRefusal, HostRequest, Unreachable
from acf_api.core.identity import keys
from acf_api.core.pipeline.recovery import Recovery
from acf_api.core.pipeline.service import RuntimeService
from acf_api.core.policy import grants as g
from acf_api.core.store import journal as j
from acf_api.core.store import registry as reg
from acf_api.core.store.engine import Store
from acf_api.core.store.outbox import AuditOutbox

_DAY_MS: Final = 24 * 3600 * 1000
_PAGE: Final = 1000
_MAX_PAGES: Final = 64


class AdminError(Exception):
    """An operator command cannot be carried out. The message is for the operator."""


class Admin:
    def __init__(self, service: RuntimeService, store: Store, outbox: AuditOutbox, recovery: Recovery) -> None:
        self._service = service
        self._d = service.d
        self._store = store
        self._outbox = outbox
        self._recovery = recovery

    async def run(self, op: str, args: dict[str, Any]) -> Any:  # noqa: ANN401 - any JSON value: each operation's own
        handler = getattr(self, "_op_" + op.replace(".", "_").replace("-", "_"), None)
        if handler is None:
            raise AdminError(f"unknown admin operation `{op}`")
        result = await handler(args)
        if op not in _READ_ONLY:
            event = AuditEvent(
                event="operator.action", at_ms=self._d.clock.wall_ms(), interface="admin", outcome="accepted"
            )
            event.details = {"operator_action": op[:64]}
            for name in ("project_id", "principal_id", "credential_id"):
                value = args.get(name)
                if isinstance(value, str):
                    event.details["subject_" + name] = value[:64]
            await self._d.audit.record(event)
        return result

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _text(args: dict[str, Any], name: str, *, maximum: int = 128) -> str:
        value = args.get(name)
        if not isinstance(value, str) or not value or len(value) > maximum:
            raise AdminError(f"`{name}` must be a string of 1 to {maximum} characters")
        return value

    def _grant(self, args: dict[str, Any], default_template: str | None) -> g.EffectiveGrant | None:
        """A grant from ``grants`` (a document) or ``template`` (a name). ``None``: neither was given."""
        if args.get("grants") is not None:
            try:
                return g.parse(args["grants"])
            except g.GrantError as e:
                raise AdminError(str(e)) from e
        template = args.get("template", default_template)
        if template is None:
            return None
        if template not in self._d.templates:
            raise AdminError(f"no grant template named `{template}`; there are: {', '.join(sorted(self._d.templates))}")
        return self._d.templates[template]

    async def _count(self, scope: str, method: str, gone: str | None) -> int | None:
        """How many records the host holds under a scope. ``None``: the host could not be asked."""
        total = 0
        cursor: Any = None
        for _ in range(_MAX_PAGES):
            params: dict[str, Any] = {"limit": _PAGE}
            if cursor is not None:
                params["changed_since"] = cursor
            try:
                answer = await self._d.binding.read(
                    HostRequest(method=method, owner_scope=scope, params=params), lane=Lane.RESOLUTION
                )
            except Unreachable:
                return None
            if isinstance(answer, HostRefusal) or not isinstance(answer.data, dict):
                return None
            await self._service.observe(answer)
            items = [i for i in answer.data.get("items") or [] if isinstance(i, dict)]
            total += sum(1 for i in items if gone is None or i.get("state") != gone)
            if not answer.data.get("more"):
                return total
            cursor = answer.data.get("next")
        return total

    async def _holdings(self, scope: str) -> dict[str, int | None]:
        return {
            "sandboxes": await self._count(scope, "sandbox.list", "DESTROYED"),
            "snapshots": await self._count(scope, "snapshot.list", "DELETED"),
            "operations": await self._count(scope, "operation.list", None),
        }

    def _project_view(self, project: reg.Project) -> dict[str, Any]:
        return {
            "project_id": project.project_id,
            "label": project.label,
            "state": project.state,
            "share": project.share,
            "created_at": project.created_at,
            "updated_at": project.updated_at,
        }

    def _credential_view(self, c: reg.Credential) -> dict[str, Any]:
        return {
            "credential_id": c.credential_id,
            "kind": c.kind,
            "display_prefix": c.display_prefix,
            "principal_id": c.principal_id,
            "project_id": c.project_id,
            "parent_credential_id": c.parent_credential_id,
            "agent_label": c.agent_label,
            "status": c.status(self._d.clock.wall_ms()),
            "issued_at": rfc3339(c.issued_at_ms),
            "expires_at": rfc3339(c.expires_at_ms),
        }

    # ------------------------------------------------------------------ health
    async def _op_health(self, _: dict[str, Any]) -> dict[str, Any]:
        await self._service.host_info()
        stale = self._d.clock.wall_ms() - int(self._d.params.claim_stale_after * 1000)
        return {
            **self._d.standing.health(),
            "deployment_id": self._d.deployment_id,
            "writer_epoch": self._d.writer_epoch,
            "store": await self._store.sizes(),
            "ledger": await self._d.ledger.counts(stale),
            "audit": await self._outbox.counts(),
            "registry": await self._d.registry.counts(),
            "audit_writable": self._d.audit.writable,
            "journal_records": self._d.journal.last_seq,
            "journal_mirror_failures": self._d.journal.mirror_failures,
        }

    async def _op_metrics(self, _: dict[str, Any]) -> dict[str, Any]:
        return {
            **self._d.telemetry.snapshot(),
            "state": self._service.metrics(),
            "host_connections": _in_use(self._d.binding),
        }

    # ------------------------------------------------------------------ projects
    async def _op_project_create(self, args: dict[str, Any]) -> dict[str, Any]:
        label = self._text(args, "label")
        project = await self._d.registry.create_project(keys.new_id("prj"), label, keys.new_scope())
        return await self._activate(project)

    async def _activate(self, project: reg.Project) -> dict[str, Any]:
        """Activate a project only on an empty scope. A scope that is not empty is never activated."""
        holdings = await self._holdings(project.scope)
        view = self._project_view(project)
        if any(v is None for v in holdings.values()):
            return {**view, "activation": "pending: the host could not be asked; run `project activate` again"}
        if any(holdings.values()):
            self._d.telemetry.diagnostic("project_scope_not_empty", project_id=project.project_id)
            return {**view, "activation": "refused: the host holds records under this scope", "host_records": holdings}
        await self._d.registry.set_project_state(project.project_id, reg.ACTIVE)
        return {**view, "state": reg.ACTIVE, "activation": "active"}

    async def _op_project_activate(self, args: dict[str, Any]) -> dict[str, Any]:
        project = await self._d.registry.project(self._text(args, "project_id"))
        if project is None or project.state != reg.PENDING:
            raise AdminError("no PENDING project with that id")
        return await self._activate(project)

    async def _op_project_list(self, _: dict[str, Any]) -> list[dict[str, Any]]:
        now = self._d.clock.wall_ms()
        out: list[dict[str, Any]] = []
        for project in await self._d.registry.projects():
            credentials = await self._d.registry.credentials(project_id=project.project_id, kind="developer")
            holdings = await self._holdings(project.scope) if project.state != reg.DELETED else {}
            out.append(
                {
                    **self._project_view(project),
                    # A project outlives its credentials: one without a valid key is shown, not hidden.
                    "has_valid_developer_credential": any(c.live(now) for c in credentials),
                    "host_records": holdings,
                }
            )
        return out

    async def _op_project_delete(self, args: dict[str, Any]) -> dict[str, Any]:
        project = await self._d.registry.project(self._text(args, "project_id"))
        if project is None:
            raise AdminError("no project with that id")
        if project.state == reg.DELETED:
            return {**self._project_view(project), "deletion": "deleted"}
        if project.state != reg.DELETING:
            # Granting work is refused from here on; containment stays allowed.
            await self._d.registry.set_project_state(project.project_id, reg.DELETING)
        holdings = await self._holdings(project.scope)
        view = {**self._project_view(project), "state": reg.DELETING, "host_records": holdings}
        if holdings["sandboxes"] is None or holdings["snapshots"] is None:
            return {**view, "deletion": "waiting: the host could not be asked"}
        if holdings["sandboxes"] or holdings["snapshots"]:
            return {**view, "deletion": "waiting: the host still holds sandboxes or snapshots under this scope"}
        await self._d.registry.set_project_state(project.project_id, reg.DELETED)
        return {**view, "state": reg.DELETED, "deletion": "deleted"}

    async def _op_project_share(self, args: dict[str, Any]) -> dict[str, Any]:
        project_id = self._text(args, "project_id")
        share = args.get("share")
        if share is not None and (
            not isinstance(share, int | float) or isinstance(share, bool) or not 0 < float(share) < 1
        ):
            raise AdminError("`share` must be a number above 0 and below 1, or null for the default")
        if await self._d.registry.project(project_id) is None:
            raise AdminError("no project with that id")
        value = float(share) if share is not None else None
        await self._d.registry.set_project_share(project_id, value)
        self._service.set_project_share(project_id, value)
        return {"project_id": project_id, "share": value}

    # ------------------------------------------------------------------ principals and roles
    async def _op_principal_create(self, args: dict[str, Any]) -> dict[str, Any]:
        principal = await self._d.registry.create_principal(keys.new_id("prn"), self._text(args, "label"))
        return {"principal_id": principal.principal_id, "label": principal.label, "created_at": principal.created_at}

    async def _op_principal_list(self, _: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            {"principal_id": p.principal_id, "label": p.label, "created_at": p.created_at}
            for p in await self._d.registry.principals()
        ]

    async def _op_role_set(self, args: dict[str, Any]) -> dict[str, Any]:
        principal_id, project_id = self._text(args, "principal_id"), self._text(args, "project_id")
        if await self._d.registry.principal(principal_id) is None:
            raise AdminError("no principal with that id")
        if await self._d.registry.project(project_id) is None:
            raise AdminError("no project with that id")
        grant = self._grant(args, "developer")
        if grant is None:  # pragma: no cover - a default template is always given
            raise AdminError("a role needs grants")
        text = grant.to_json()
        version = g.policy_version(text)
        await self._d.registry.set_role(principal_id, project_id, text, version)
        return {
            "principal_id": principal_id,
            "project_id": project_id,
            "policy_version": version,
            "grants": grant.to_view(),
        }

    # ------------------------------------------------------------------ developer keys
    async def _op_key_issue(self, args: dict[str, Any]) -> dict[str, Any]:
        principal_id, project_id = self._text(args, "principal_id"), self._text(args, "project_id")
        if await self._d.registry.role(principal_id, project_id) is None:
            raise AdminError("the principal has no role in that project; set one first")
        project = await self._d.registry.project(project_id)
        if project is None or project.state != reg.ACTIVE:
            raise AdminError("the project is not ACTIVE")
        maximum = self._d.params.credential_max_lifetime
        days = args.get("lifetime_days", 90)
        if not isinstance(days, int | float) or isinstance(days, bool) or days <= 0 or days * 86400 > maximum:
            raise AdminError(f"`lifetime_days` must be above 0 and at most {int(maximum // 86400)}")
        narrowing = self._grant(args, None)
        role = await self._d.registry.role(principal_id, project_id)
        if narrowing is not None and role is not None and g.widens(narrowing, g.parse(role.grants_json)):
            raise AdminError("the narrowing allows something the role does not")
        now = self._d.clock.wall_ms()
        secret = keys.generate_key("developer")
        record = reg.Credential(
            credential_id=keys.new_id("crd"),
            key_digest=keys.key_digest(secret),
            display_prefix=keys.display_prefix(secret),
            principal_id=principal_id,
            project_id=project_id,
            kind="developer",
            parent_credential_id=None,
            narrowing_json=narrowing.to_json() if narrowing is not None else None,
            agent_label=None,
            issued_at_ms=now,
            expires_at_ms=now + int(days * _DAY_MS),
            first_used_at_ms=None,
            revoked_at_ms=None,
        )
        await self._d.registry.insert_credential(record)
        # The key is shown once, here, and is stored nowhere.
        return {**self._credential_view(record), "secret": secret}

    async def _op_key_list(self, args: dict[str, Any]) -> list[dict[str, Any]]:
        project_id = args.get("project_id")
        records = await self._d.registry.credentials(project_id=project_id if isinstance(project_id, str) else None)
        return [self._credential_view(c) for c in records]

    async def _op_key_revoke(self, args: dict[str, Any]) -> dict[str, Any]:
        credential_id = self._text(args, "credential_id")
        if await self._d.registry.credential(credential_id) is None:
            raise AdminError("no credential with that id")
        revoked = await self._d.registry.revoke_credential(credential_id, self._d.clock.wall_ms())
        self._d.authenticator.forget([credential_id, *revoked])
        return {"credential_id": credential_id, "revoked": revoked}

    # ------------------------------------------------------------------ OAuth subject bindings
    async def _op_oauth_bind(self, args: dict[str, Any]) -> dict[str, Any]:
        principal_id, project_id = self._text(args, "principal_id"), self._text(args, "project_id")
        kind = args.get("kind", "agent")
        if kind not in {"agent", "developer"}:
            raise AdminError("`kind` must be `agent` or `developer`")
        if await self._d.registry.role(principal_id, project_id) is None:
            raise AdminError("the principal has no role in that project; set one first")
        narrowing = self._grant(args, "agent" if kind == "agent" else None)
        label = args.get("agent_label")
        if kind == "agent":
            try:
                m.MintAgentCredentialSpec(label=label or "", lifetime_seconds=60)
            except ValidationError as e:
                raise AdminError(
                    "an agent binding needs an `agent_label` of 1 to 64 characters of [A-Za-z0-9_.-]"
                ) from e
        binding = reg.Binding(
            binding_id=keys.new_id("bnd"),
            issuer=self._text(args, "issuer", maximum=512),
            subject=self._text(args, "subject", maximum=512),
            principal_id=principal_id,
            project_id=project_id,
            kind=kind,
            narrowing_json=narrowing.to_json() if narrowing is not None else None,
            agent_label=label if kind == "agent" else None,
            created_at_ms=self._d.clock.wall_ms(),
            revoked_at_ms=None,
        )
        try:
            await self._d.registry.insert_binding(binding)
        except reg.RegistryConflict as e:
            raise AdminError(str(e)) from e
        return _binding_view(binding)

    async def _op_oauth_list(self, _: dict[str, Any]) -> list[dict[str, Any]]:
        return [_binding_view(b) for b in await self._d.registry.bindings()]

    async def _op_oauth_unbind(self, args: dict[str, Any]) -> dict[str, Any]:
        binding_id = self._text(args, "binding_id")
        changed = await self._d.registry.revoke_binding(binding_id, self._d.clock.wall_ms())
        self._d.authenticator.forget([binding_id])
        return {"binding_id": binding_id, "revoked": changed}

    # ------------------------------------------------------------------ acknowledgements
    async def _op_host_acknowledge_lineage(self, args: dict[str, Any]) -> dict[str, Any]:
        """Accept the lineage the host reports now. Entries of the old lineage become LOST; nothing is resubmitted."""
        s = self._d.standing
        lineage = self._text(args, "lineage")
        if s.reported_lineage is None or lineage != s.reported_lineage:
            raise AdminError("that is not the lineage the host reports; read `health` and repeat it exactly")
        old = s.pinned_lineage
        await self._d.journal.aappend(
            j.LINEAGE_ACKNOWLEDGED, {"lineage": lineage, "previous": old, "host_id": self._d.binding.host_id}
        )
        lost = await self._d.ledger.lose_lineage(old, self._d.clock.wall_ms()) if old is not None else 0
        s.pinned_lineage, s.reported_lineage, s.sequence_high_water = lineage, None, 0
        return {"pinned_lineage": lineage, "previous": old, "entries_lost": lost}

    async def _op_host_acknowledge_peer(self, args: dict[str, Any]) -> dict[str, Any]:
        """Accept the peer id the host reports for the platform now. Entries under the old one become LOST."""
        s = self._d.standing
        peer_id = self._text(args, "peer_id", maximum=64)
        if s.reported_peer_id is None or peer_id != s.reported_peer_id:
            raise AdminError("that is not the peer id the host reports; read `health` and repeat it exactly")
        old = s.pinned_peer_id
        await self._d.journal.aappend(j.PEER_ACKNOWLEDGED, {"peer_id": peer_id, "previous": old})
        lost = await self._d.ledger.lose_peer(old, self._d.clock.wall_ms()) if old is not None else 0
        s.pinned_peer_id, s.reported_peer_id = peer_id, None
        return {"pinned_peer_id": peer_id, "previous": old, "entries_lost": lost}

    # ------------------------------------------------------------------ audit and recovery
    async def _op_audit_read(self, args: dict[str, Any]) -> list[dict[str, Any]]:
        after = args.get("after_seq", 0)
        limit = args.get("limit", 200)
        if not isinstance(after, int) or not isinstance(limit, int) or not 1 <= limit <= 1000:  # noqa: PLR2004
            raise AdminError("`after_seq` and `limit` (1 to 1000) must be integers")
        return await self._outbox.read(after_seq=after, limit=limit)

    async def _op_recovery_sweep(self, _: dict[str, Any]) -> dict[str, int]:
        return await self._recovery.sweep()

    async def _op_policy_templates(self, _: dict[str, Any]) -> dict[str, Any]:
        return {name: grant.to_view() for name, grant in sorted(self._d.templates.items())}


_READ_ONLY: Final = frozenset(
    {"health", "metrics", "project.list", "principal.list", "key.list", "oauth.list", "audit.read", "policy.templates"}
)


def _binding_view(b: reg.Binding) -> dict[str, Any]:
    return {
        "binding_id": b.binding_id,
        "issuer": b.issuer,
        "subject": b.subject,
        "principal_id": b.principal_id,
        "project_id": b.project_id,
        "kind": b.kind,
        "agent_label": b.agent_label,
        "narrowing": json.loads(b.narrowing_json) if b.narrowing_json else None,
        "status": "REVOKED" if b.revoked_at_ms is not None else "ACTIVE",
    }


def _in_use(binding: object) -> dict[str, int]:
    probe = getattr(binding, "in_use", None)
    return probe() if callable(probe) else {}
