"""The security registry: principals, projects and their scope strings, roles, credentials, bindings.

The registry is the source of truth for who may authenticate and what their role grants. It holds a
digest and a display prefix of each key, never the key. Grants are stored on the role, the pair of a
principal and a project; a credential only refers to them and may narrow them.

Three kinds of change are written to the security journal *before* they are written here, so that a
restore of the store cannot undo them: a scope allocation, a revocation and a project deletion. The
functions below that make such a change take the journal and write to it first.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any, Final

from acf_api.core.clock import rfc3339
from acf_api.core.store import journal as j
from acf_api.core.store.engine import Store, now_ms

PENDING: Final = "PENDING"
ACTIVE: Final = "ACTIVE"
DELETING: Final = "DELETING"
DELETED: Final = "DELETED"


class RegistryConflict(Exception):
    """The change collides with a record that exists: a label in use, a scope issued before."""


@dataclass(frozen=True, slots=True)
class Project:
    project_id: str
    label: str
    scope: str
    state: str
    share: float | None
    created_at: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class Principal:
    principal_id: str
    label: str
    created_at: str


@dataclass(frozen=True, slots=True)
class Role:
    principal_id: str
    project_id: str
    grants_json: str
    policy_version: str


@dataclass(frozen=True, slots=True)
class Credential:
    credential_id: str
    key_digest: str
    display_prefix: str
    principal_id: str
    project_id: str
    kind: str
    parent_credential_id: str | None
    narrowing_json: str | None
    agent_label: str | None
    issued_at_ms: int
    expires_at_ms: int
    first_used_at_ms: int | None
    revoked_at_ms: int | None

    def status(self, at_ms: int) -> str:
        if self.revoked_at_ms is not None:
            return "REVOKED"
        if at_ms >= self.expires_at_ms:
            return "EXPIRED"
        return "ACTIVE" if self.first_used_at_ms is not None else "ISSUED"

    def live(self, at_ms: int) -> bool:
        return self.revoked_at_ms is None and at_ms < self.expires_at_ms


@dataclass(frozen=True, slots=True)
class Binding:
    binding_id: str
    issuer: str
    subject: str
    principal_id: str
    project_id: str
    kind: str
    narrowing_json: str | None
    agent_label: str | None
    created_at_ms: int
    revoked_at_ms: int | None


def _project(row: sqlite3.Row) -> Project:
    return Project(
        row["project_id"], row["label"], row["scope"], row["state"], row["share"], row["created_at"], row["updated_at"]
    )


def _credential(row: sqlite3.Row) -> Credential:
    return Credential(
        row["credential_id"],
        row["key_digest"],
        row["display_prefix"],
        row["principal_id"],
        row["project_id"],
        row["kind"],
        row["parent_credential_id"],
        row["narrowing_json"],
        row["agent_label"],
        row["issued_at_ms"],
        row["expires_at_ms"],
        row["first_used_at_ms"],
        row["revoked_at_ms"],
    )


def _binding(row: sqlite3.Row) -> Binding:
    return Binding(
        row["binding_id"],
        row["issuer"],
        row["subject"],
        row["principal_id"],
        row["project_id"],
        row["kind"],
        row["narrowing_json"],
        row["agent_label"],
        row["created_at_ms"],
        row["revoked_at_ms"],
    )


class Registry:
    def __init__(self, store: Store, journal: j.SecurityJournal) -> None:
        self._store = store
        self._journal = journal

    # ------------------------------------------------------------------ principals and roles
    async def create_principal(self, principal_id: str, label: str) -> Principal:
        created = rfc3339(now_ms())

        def write(conn: sqlite3.Connection) -> None:
            conn.execute(
                "INSERT INTO principals(principal_id, label, created_at) VALUES (?, ?, ?)",
                (principal_id, label, created),
            )

        await self._store.state(write, write=True)
        return Principal(principal_id, label, created)

    async def principal(self, principal_id: str) -> Principal | None:
        def read(conn: sqlite3.Connection) -> Principal | None:
            row = conn.execute("SELECT * FROM principals WHERE principal_id = ?", (principal_id,)).fetchone()
            return None if row is None else Principal(row["principal_id"], row["label"], row["created_at"])

        return await self._store.state(read)

    async def principals(self) -> list[Principal]:
        def read(conn: sqlite3.Connection) -> list[Principal]:
            rows = conn.execute("SELECT * FROM principals ORDER BY created_at, principal_id").fetchall()
            return [Principal(r["principal_id"], r["label"], r["created_at"]) for r in rows]

        return await self._store.state(read)

    async def set_role(self, principal_id: str, project_id: str, grants_json: str, policy_version: str) -> None:
        stamp = rfc3339(now_ms())

        def write(conn: sqlite3.Connection) -> None:
            conn.execute(
                "INSERT INTO roles(principal_id, project_id, grants_json, policy_version, updated_at) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT(principal_id, project_id) DO UPDATE SET "
                "grants_json = excluded.grants_json, policy_version = excluded.policy_version, "
                "updated_at = excluded.updated_at",
                (principal_id, project_id, grants_json, policy_version, stamp),
            )

        await self._store.state(write, write=True)

    async def role(self, principal_id: str, project_id: str) -> Role | None:
        def read(conn: sqlite3.Connection) -> Role | None:
            row = conn.execute(
                "SELECT * FROM roles WHERE principal_id = ? AND project_id = ?", (principal_id, project_id)
            ).fetchone()
            if row is None:
                return None
            return Role(row["principal_id"], row["project_id"], row["grants_json"], row["policy_version"])

        return await self._store.state(read)

    # ------------------------------------------------------------------ projects and scopes
    async def create_project(self, project_id: str, label: str, scope: str) -> Project:
        """Allocate a scope and record the project as PENDING. The allocation is journaled first."""

        def taken(conn: sqlite3.Connection) -> bool:
            used = conn.execute(
                "SELECT 1 FROM projects WHERE scope = ? OR project_id = ?", (scope, project_id)
            ).fetchone()
            retired = conn.execute("SELECT 1 FROM retired_scopes WHERE scope = ?", (scope,)).fetchone()
            return used is not None or retired is not None

        if await self._store.state(taken) or scope in j.fold(self._journal.records).allocated:
            raise RegistryConflict("the scope or the project id was issued before")
        await self._journal.aappend(j.SCOPE_ALLOCATED, {"project_id": project_id, "scope": scope})
        stamp = rfc3339(now_ms())

        def write(conn: sqlite3.Connection) -> None:
            conn.execute(
                "INSERT INTO projects(project_id, label, scope, state, share, created_at, updated_at) "
                "VALUES (?, ?, ?, 'PENDING', NULL, ?, ?)",
                (project_id, label, scope, stamp, stamp),
            )

        await self._store.state(write, write=True)
        await self._store.set_journal_applied(self._journal.last_seq)
        return Project(project_id, label, scope, PENDING, None, stamp, stamp)

    async def project(self, project_id: str) -> Project | None:
        def read(conn: sqlite3.Connection) -> Project | None:
            row = conn.execute("SELECT * FROM projects WHERE project_id = ?", (project_id,)).fetchone()
            return None if row is None else _project(row)

        return await self._store.state(read)

    async def projects(self) -> list[Project]:
        def read(conn: sqlite3.Connection) -> list[Project]:
            return [_project(r) for r in conn.execute("SELECT * FROM projects ORDER BY created_at, project_id")]

        return await self._store.state(read)

    async def set_project_state(self, project_id: str, state: str) -> None:
        """Move a project. DELETED is journaled first, and retires the scope for good."""
        project = await self.project(project_id)
        if project is None:
            raise KeyError(project_id)
        if state == DELETED:
            await self._journal.aappend(j.PROJECT_DELETED, {"project_id": project_id})
            await self._journal.aappend(j.SCOPE_RETIRED, {"scope": project.scope})
        stamp = rfc3339(now_ms())

        def write(conn: sqlite3.Connection) -> None:
            conn.execute(
                "UPDATE projects SET state = ?, updated_at = ? WHERE project_id = ?", (state, stamp, project_id)
            )
            if state == DELETED:
                conn.execute(
                    "INSERT OR IGNORE INTO retired_scopes(scope, retired_at) VALUES (?, ?)", (project.scope, stamp)
                )

        await self._store.state(write, write=True)
        if state == DELETED:
            await self._store.set_journal_applied(self._journal.last_seq)

    async def set_project_share(self, project_id: str, share: float | None) -> None:
        stamp = rfc3339(now_ms())

        def write(conn: sqlite3.Connection) -> None:
            conn.execute(
                "UPDATE projects SET share = ?, updated_at = ? WHERE project_id = ?", (share, stamp, project_id)
            )

        await self._store.state(write, write=True)

    # ------------------------------------------------------------------ credentials
    async def insert_credential(self, credential: Credential) -> None:
        def write(conn: sqlite3.Connection) -> None:
            if credential.kind == "agent":
                clash = conn.execute(
                    "SELECT 1 FROM credentials WHERE principal_id = ? AND project_id = ? AND kind = 'agent' "
                    "AND agent_label = ? AND revoked_at_ms IS NULL AND expires_at_ms > ?",
                    (credential.principal_id, credential.project_id, credential.agent_label, credential.issued_at_ms),
                ).fetchone()
                if clash is not None:
                    raise RegistryConflict("a live agent credential of this principal already carries this label")
            conn.execute(
                "INSERT INTO credentials(credential_id, key_digest, display_prefix, principal_id, project_id, kind, "
                "parent_credential_id, narrowing_json, agent_label, issued_at_ms, expires_at_ms, first_used_at_ms, "
                "revoked_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
                (
                    credential.credential_id,
                    credential.key_digest,
                    credential.display_prefix,
                    credential.principal_id,
                    credential.project_id,
                    credential.kind,
                    credential.parent_credential_id,
                    credential.narrowing_json,
                    credential.agent_label,
                    credential.issued_at_ms,
                    credential.expires_at_ms,
                ),
            )

        await self._store.state(write, write=True)

    async def credential_by_digest(self, key_digest: str) -> Credential | None:
        def read(conn: sqlite3.Connection) -> Credential | None:
            row = conn.execute("SELECT * FROM credentials WHERE key_digest = ?", (key_digest,)).fetchone()
            return None if row is None else _credential(row)

        return await self._store.state(read)

    async def credential(self, credential_id: str) -> Credential | None:
        def read(conn: sqlite3.Connection) -> Credential | None:
            row = conn.execute("SELECT * FROM credentials WHERE credential_id = ?", (credential_id,)).fetchone()
            return None if row is None else _credential(row)

        return await self._store.state(read)

    async def credentials(
        self, *, project_id: str | None = None, parent: str | None = None, kind: str | None = None
    ) -> list[Credential]:
        def read(conn: sqlite3.Connection) -> list[Credential]:
            clauses, args = ["1 = 1"], []
            for column, value in (("project_id", project_id), ("parent_credential_id", parent), ("kind", kind)):
                if value is not None:
                    clauses.append(f"{column} = ?")
                    args.append(value)
            sql = "SELECT * FROM credentials WHERE " + " AND ".join(clauses) + " ORDER BY issued_at_ms, credential_id"  # noqa: S608
            return [_credential(r) for r in conn.execute(sql, args)]

        return await self._store.state(read)

    async def mark_first_use(self, credential_id: str, at_ms: int) -> None:
        def write(conn: sqlite3.Connection) -> None:
            conn.execute(
                "UPDATE credentials SET first_used_at_ms = ? WHERE credential_id = ? AND first_used_at_ms IS NULL",
                (at_ms, credential_id),
            )

        await self._store.state(write, write=True)

    async def revoke_credential(self, credential_id: str, at_ms: int) -> list[str]:
        """Revoke a credential and every agent credential it minted. Journal first, then the registry.

        Idempotent. Returns the ids revoked by this call.
        """

        def family(conn: sqlite3.Connection) -> list[str]:
            rows = conn.execute(
                "SELECT credential_id FROM credentials WHERE (credential_id = ? OR parent_credential_id = ?) "
                "AND revoked_at_ms IS NULL",
                (credential_id, credential_id),
            ).fetchall()
            return [str(r["credential_id"]) for r in rows]

        ids = await self._store.state(family)
        for cid in ids:
            await self._journal.aappend(j.CREDENTIAL_REVOKED, {"credential_id": cid, "at_ms": at_ms})

        def write(conn: sqlite3.Connection) -> None:
            conn.executemany(
                "UPDATE credentials SET revoked_at_ms = ? WHERE credential_id = ? AND revoked_at_ms IS NULL",
                [(at_ms, cid) for cid in ids],
            )

        if ids:
            await self._store.state(write, write=True)
            await self._store.set_journal_applied(self._journal.last_seq)
        return ids

    async def purge_credentials(self, before_ms: int) -> int:
        """Remove revoked and expired credential records older than the audit retention."""

        def write(conn: sqlite3.Connection) -> int:
            cur = conn.execute(
                "DELETE FROM credentials WHERE (revoked_at_ms IS NOT NULL AND revoked_at_ms < ?) OR expires_at_ms < ?",
                (before_ms, before_ms),
            )
            return cur.rowcount

        return await self._store.state(write, write=True)

    # ------------------------------------------------------------------ OAuth subject bindings
    async def insert_binding(self, binding: Binding) -> None:
        def write(conn: sqlite3.Connection) -> None:
            conn.execute(
                "INSERT INTO oauth_bindings(binding_id, issuer, subject, principal_id, project_id, kind, "
                "narrowing_json, agent_label, created_at_ms, revoked_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                (
                    binding.binding_id,
                    binding.issuer,
                    binding.subject,
                    binding.principal_id,
                    binding.project_id,
                    binding.kind,
                    binding.narrowing_json,
                    binding.agent_label,
                    binding.created_at_ms,
                ),
            )

        try:
            await self._store.state(write, write=True)
        except sqlite3.IntegrityError as e:
            raise RegistryConflict("this issuer and subject are already bound") from e

    async def binding(self, issuer: str, subject: str) -> Binding | None:
        def read(conn: sqlite3.Connection) -> Binding | None:
            row = conn.execute(
                "SELECT * FROM oauth_bindings WHERE issuer = ? AND subject = ?", (issuer, subject)
            ).fetchone()
            return None if row is None else _binding(row)

        return await self._store.state(read)

    async def bindings(self) -> list[Binding]:
        def read(conn: sqlite3.Connection) -> list[Binding]:
            return [
                _binding(r) for r in conn.execute("SELECT * FROM oauth_bindings ORDER BY created_at_ms, binding_id")
            ]

        return await self._store.state(read)

    async def revoke_binding(self, binding_id: str, at_ms: int) -> bool:
        await self._journal.aappend(j.BINDING_REVOKED, {"binding_id": binding_id, "at_ms": at_ms})

        def write(conn: sqlite3.Connection) -> bool:
            cur = conn.execute(
                "UPDATE oauth_bindings SET revoked_at_ms = ? WHERE binding_id = ? AND revoked_at_ms IS NULL",
                (at_ms, binding_id),
            )
            return cur.rowcount > 0

        changed = await self._store.state(write, write=True)
        await self._store.set_journal_applied(self._journal.last_seq)
        return changed

    # ------------------------------------------------------------------ after a restore
    async def replay(self, state: j.JournalState) -> dict[str, Any]:
        """Make the registry agree with the journal. Run before the core serves, after every start.

        Every revocation recorded in the journal is applied; every scope it retired is marked; every
        deleted project stays deleted. Returns what was re-applied and every scope the journal allocated
        that the registry does not know, because the host may still hold records under it.
        """

        def write(conn: sqlite3.Connection) -> dict[str, Any]:
            stamp = rfc3339(now_ms())
            revived = 0
            for cid, at_ms in state.revoked_credentials.items():
                cur = conn.execute(
                    "UPDATE credentials SET revoked_at_ms = ? WHERE credential_id = ? AND revoked_at_ms IS NULL",
                    (at_ms, cid),
                )
                revived += cur.rowcount
            bindings = 0
            for bid, at_ms in state.revoked_bindings.items():
                cur = conn.execute(
                    "UPDATE oauth_bindings SET revoked_at_ms = ? WHERE binding_id = ? AND revoked_at_ms IS NULL",
                    (at_ms, bid),
                )
                bindings += cur.rowcount
            undeleted = 0
            for pid in state.deleted_projects:
                cur = conn.execute(
                    "UPDATE projects SET state = 'DELETED', updated_at = ? WHERE project_id = ? AND state != 'DELETED'",
                    (stamp, pid),
                )
                undeleted += cur.rowcount
            for scope in state.retired_scopes:
                conn.execute("INSERT OR IGNORE INTO retired_scopes(scope, retired_at) VALUES (?, ?)", (scope, stamp))
            known = {str(r["scope"]) for r in conn.execute("SELECT scope FROM projects")}
            unknown = sorted(s for s in state.allocated if s not in known and s not in state.retired_scopes)
            for scope in unknown:
                # The scope was issued and the restored registry has forgotten it: it is never issued again.
                conn.execute("INSERT OR IGNORE INTO retired_scopes(scope, retired_at) VALUES (?, ?)", (scope, stamp))
            return {
                "revocations_reapplied": revived,
                "bindings_reapplied": bindings,
                "deletions_reapplied": undeleted,
                "unknown_scopes": unknown,
            }

        report = await self._store.state(write, write=True)
        await self._store.set_journal_applied(self._journal.last_seq)
        return report

    async def counts(self) -> dict[str, int]:
        def read(conn: sqlite3.Connection) -> dict[str, int]:
            horizon = now_ms() + 7 * 24 * 3600 * 1000
            return {
                "projects": int(conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0]),
                "principals": int(conn.execute("SELECT COUNT(*) FROM principals").fetchone()[0]),
                "credentials_live": int(
                    conn.execute(
                        "SELECT COUNT(*) FROM credentials WHERE revoked_at_ms IS NULL AND expires_at_ms > ?",
                        (now_ms(),),
                    ).fetchone()[0]
                ),
                "credentials_expiring_7d": int(
                    conn.execute(
                        "SELECT COUNT(*) FROM credentials WHERE revoked_at_ms IS NULL AND expires_at_ms > ? "
                        "AND expires_at_ms <= ?",
                        (now_ms(), horizon),
                    ).fetchone()[0]
                ),
            }

        return await self._store.state(read)
