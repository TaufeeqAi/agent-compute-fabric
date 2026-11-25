"""The request ledger: the platform's record of each public request that may create a host operation.

An entry records a *request*: its key (as a keyed digest), its fingerprint, the host operation id
derived for it, the ``issued_at`` and every other value the platform chose for it, the host it was
sent to, and the epoch of the core process that claimed it. It is not a record of an outcome. While
the host holds the operation, the host's record decides what happened, and an entry that disagrees is
wrong.

States::

    ABSENT --claim--> CLAIMED --host answered OPERATION, or a read found it--> BOUND
                         |                                                       |
                         +--host refused, or absence proven: release--> ABSENT   +--host no longer holds it--> LOST
                         +--absence cannot be proven, or the lineage changed--> LOST

    BOUND and LOST --retention--> ABSENT

Forbidden, and impossible through this module: BOUND -> CLAIMED; LOST -> anything but ABSENT; storing a
refusal as a result; changing the fingerprint, the derived operation id, ``issued_at`` or a chosen
value of an existing entry.

The claim is a unique insert on ``(project, principal, key digest)``: it succeeds for exactly one of
any number of concurrent callers. The entry holds no request parameters; the caller sends them again.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Final

from acf_api.core.store.engine import Store

CLAIMED: Final = "CLAIMED"
BOUND: Final = "BOUND"
LOST: Final = "LOST"


@dataclass(frozen=True, slots=True)
class Chosen:
    """The values the platform adds to a request. Each is decided once and sent unchanged afterwards."""

    #: The target generation, when the caller sent ``current``.
    generation: int | None = None
    #: The sandbox lifetime, when an agent credential bounds it.
    lifetime_seconds: int | None = None
    #: The execution timeout, when the agent interface supplies one.
    timeout_seconds: int | None = None

    def to_json(self) -> str:
        body = {
            k: v
            for k, v in (("g", self.generation), ("l", self.lifetime_seconds), ("t", self.timeout_seconds))
            if v is not None
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def from_json(text: str) -> Chosen:
        body = json.loads(text)
        return Chosen(body.get("g"), body.get("l"), body.get("t"))


@dataclass(frozen=True, slots=True)
class Summary:
    """The terminal outcome of an operation as the host last reported it. Immutable once recorded.

    Used only when the host no longer holds the operation, and shown as recorded.
    """

    state: str
    effect: str | None
    failure_code: str | None
    failure_retry: str | None
    cleanup: str | None
    operation_type: str
    produced: dict[str, Any]
    created_at: str | None
    updated_at: str | None
    initiated_by: str
    actor: str | None

    def to_json(self) -> str:
        return json.dumps(
            {
                "state": self.state,
                "effect": self.effect,
                "failure_code": self.failure_code,
                "failure_retry": self.failure_retry,
                "cleanup": self.cleanup,
                "operation_type": self.operation_type,
                "produced": self.produced,
                "created_at": self.created_at,
                "updated_at": self.updated_at,
                "initiated_by": self.initiated_by,
                "actor": self.actor,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    @staticmethod
    def from_json(text: str) -> Summary:
        b = json.loads(text)
        return Summary(
            b["state"],
            b.get("effect"),
            b.get("failure_code"),
            b.get("failure_retry"),
            b.get("cleanup"),
            b["operation_type"],
            dict(b.get("produced") or {}),
            b.get("created_at"),
            b.get("updated_at"),
            b.get("initiated_by", "CALLER"),
            b.get("actor"),
        )


@dataclass(frozen=True, slots=True)
class NewEntry:
    """Everything a claim commits. After the claim, a later submission needs nothing else from the store."""

    project_id: str
    principal_id: str
    credential_id: str
    key_digest: str
    fingerprint: str
    derivation_version: str
    operation_id: str
    host_id: str
    op_class: str
    method: str
    issued_at: str
    issued_at_ms: int
    chosen: Chosen
    owner_epoch: int
    lineage: str | None
    peer_id: str | None
    decision_id: str
    policy_version: str
    minted_key: str | None = None
    tool: str | None = None
    args_digest: str | None = None
    created_at_ms: int = 0


@dataclass(frozen=True, slots=True)
class Entry:
    entry_id: int
    project_id: str
    principal_id: str
    credential_id: str
    key_digest: str
    fingerprint: str
    derivation_version: str
    operation_id: str
    host_id: str
    op_class: str
    method: str
    issued_at: str
    issued_at_ms: int
    chosen: Chosen
    owner_epoch: int
    state: str
    lineage: str | None
    peer_id: str | None
    bound_seq: int | None
    decision_id: str
    policy_version: str
    minted_key: str | None
    delivered: bool
    tool: str | None
    args_digest: str | None
    summary: Summary | None
    created_at_ms: int
    updated_at_ms: int
    extra: dict[str, Any] = field(default_factory=dict)


def _entry(row: sqlite3.Row) -> Entry:
    return Entry(
        entry_id=row["entry_id"],
        project_id=row["project_id"],
        principal_id=row["principal_id"],
        credential_id=row["credential_id"],
        key_digest=row["key_digest"],
        fingerprint=row["fingerprint"],
        derivation_version=row["derivation_version"],
        operation_id=row["operation_id"],
        host_id=row["host_id"],
        op_class=row["op_class"],
        method=row["method"],
        issued_at=row["issued_at"],
        issued_at_ms=row["issued_at_ms"],
        chosen=Chosen.from_json(row["chosen_json"]),
        owner_epoch=row["owner_epoch"],
        state=row["state"],
        lineage=row["lineage"],
        peer_id=row["peer_id"],
        bound_seq=row["bound_seq"],
        decision_id=row["decision_id"],
        policy_version=row["policy_version"],
        minted_key=row["minted_key"],
        delivered=bool(row["delivered"]),
        tool=row["tool"],
        args_digest=row["args_digest"],
        summary=Summary.from_json(row["summary_json"]) if row["summary_json"] else None,
        created_at_ms=row["created_at_ms"],
        updated_at_ms=row["updated_at_ms"],
    )


class Ledger:
    def __init__(self, store: Store) -> None:
        self._store = store

    async def find(self, project_id: str, principal_id: str, key_digest: str) -> Entry | None:
        def read(conn: sqlite3.Connection) -> Entry | None:
            row = conn.execute(
                "SELECT * FROM entries WHERE project_id = ? AND principal_id = ? AND key_digest = ?",
                (project_id, principal_id, key_digest),
            ).fetchone()
            return None if row is None else _entry(row)

        return await self._store.state(read)

    async def by_operation(self, project_id: str, operation_id: str) -> Entry | None:
        def read(conn: sqlite3.Connection) -> Entry | None:
            row = conn.execute(
                "SELECT * FROM entries WHERE project_id = ? AND operation_id = ? ORDER BY entry_id DESC LIMIT 1",
                (project_id, operation_id),
            ).fetchone()
            return None if row is None else _entry(row)

        return await self._store.state(read)

    async def claim(self, new: NewEntry) -> Entry | None:
        """Commit a CLAIMED entry. ``None``: another request holds this key, and nothing was written."""

        def write(conn: sqlite3.Connection) -> Entry | None:
            try:
                cur = conn.execute(
                    "INSERT INTO entries(project_id, principal_id, credential_id, key_digest, fingerprint, "
                    "derivation_version, operation_id, host_id, op_class, method, issued_at, issued_at_ms, "
                    "chosen_json, owner_epoch, state, lineage, peer_id, bound_seq, decision_id, policy_version, "
                    "minted_key, delivered, tool, args_digest, summary_json, created_at_ms, updated_at_ms) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'CLAIMED', ?, ?, NULL, ?, ?, ?, ?, ?, ?, "
                    "NULL, ?, ?)",
                    (
                        new.project_id,
                        new.principal_id,
                        new.credential_id,
                        new.key_digest,
                        new.fingerprint,
                        new.derivation_version,
                        new.operation_id,
                        new.host_id,
                        new.op_class,
                        new.method,
                        new.issued_at,
                        new.issued_at_ms,
                        new.chosen.to_json(),
                        new.owner_epoch,
                        new.lineage,
                        new.peer_id,
                        new.decision_id,
                        new.policy_version,
                        new.minted_key,
                        0 if new.minted_key is not None else 1,
                        new.tool,
                        new.args_digest,
                        new.created_at_ms,
                        new.created_at_ms,
                    ),
                )
            except sqlite3.IntegrityError:
                return None
            row = conn.execute("SELECT * FROM entries WHERE entry_id = ?", (cur.lastrowid,)).fetchone()
            return _entry(row)

        return await self._store.state(write, write=True)

    async def bind(
        self, entry_id: int, *, lineage: str | None, seq: int | None, peer_id: str | None, at_ms: int
    ) -> bool:
        """CLAIMED -> BOUND. Durable before the answer is returned. Idempotent for an entry already BOUND."""

        def write(conn: sqlite3.Connection) -> bool:
            cur = conn.execute(
                "UPDATE entries SET state = 'BOUND', lineage = COALESCE(?, lineage), bound_seq = ?, "
                "peer_id = COALESCE(?, peer_id), updated_at_ms = ? WHERE entry_id = ? AND state = 'CLAIMED'",
                (lineage, seq, peer_id, at_ms, entry_id),
            )
            if cur.rowcount:
                return True
            row = conn.execute("SELECT state FROM entries WHERE entry_id = ?", (entry_id,)).fetchone()
            return row is not None and row["state"] == BOUND

        return await self._store.state(write, write=True)

    async def release(self, entry_id: int) -> bool:
        """CLAIMED -> ABSENT. Durable before the refusal is answered. Never removes a BOUND or LOST entry."""

        def write(conn: sqlite3.Connection) -> bool:
            cur = conn.execute("DELETE FROM entries WHERE entry_id = ? AND state = 'CLAIMED'", (entry_id,))
            return cur.rowcount > 0

        return await self._store.state(write, write=True)

    async def lose(self, entry_id: int, at_ms: int) -> bool:
        """CLAIMED or BOUND -> LOST. Never back."""

        def write(conn: sqlite3.Connection) -> bool:
            cur = conn.execute(
                "UPDATE entries SET state = 'LOST', updated_at_ms = ? "
                "WHERE entry_id = ? AND state IN ('CLAIMED', 'BOUND')",
                (at_ms, entry_id),
            )
            return cur.rowcount > 0

        return await self._store.state(write, write=True)

    async def record_summary(self, entry_id: int, summary: Summary, at_ms: int) -> bool:
        """Record the terminal outcome once. A terminal operation never changes, so the copy cannot go stale."""

        def write(conn: sqlite3.Connection) -> bool:
            cur = conn.execute(
                "UPDATE entries SET summary_json = ?, updated_at_ms = ? WHERE entry_id = ? AND summary_json IS NULL "
                "AND state = 'BOUND'",
                (summary.to_json(), at_ms, entry_id),
            )
            return cur.rowcount > 0

        return await self._store.state(write, write=True)

    async def mark_delivered(self, entry_id: int, at_ms: int) -> None:
        def write(conn: sqlite3.Connection) -> None:
            conn.execute(
                "UPDATE entries SET delivered = 1, updated_at_ms = ? WHERE entry_id = ? AND delivered = 0",
                (at_ms, entry_id),
            )

        await self._store.state(write, write=True)

    async def adoptable(self, credential_id: str, tool: str, args_digest: str, not_before_ms: int) -> Entry | None:
        """The youngest undelivered call of this credential and tool with these arguments, inside the window."""

        def read(conn: sqlite3.Connection) -> Entry | None:
            row = conn.execute(
                "SELECT * FROM entries WHERE credential_id = ? AND tool = ? AND args_digest = ? AND delivered = 0 "
                "AND minted_key IS NOT NULL AND created_at_ms >= ? ORDER BY created_at_ms DESC, entry_id DESC LIMIT 1",
                (credential_id, tool, args_digest, not_before_ms),
            ).fetchone()
            return None if row is None else _entry(row)

        return await self._store.state(read)

    async def claimed(
        self, *, before_epoch: int | None = None, older_than_ms: int | None = None, limit: int = 500
    ) -> list[Entry]:
        """CLAIMED entries the recovery pass visits: of an earlier epoch, or older than the stale bound."""

        def read(conn: sqlite3.Connection) -> list[Entry]:
            clauses, args = ["state = 'CLAIMED'"], []
            if before_epoch is not None:
                clauses.append("owner_epoch < ?")
                args.append(before_epoch)
            if older_than_ms is not None:
                clauses.append("created_at_ms < ?")
                args.append(older_than_ms)
            sql = "SELECT * FROM entries WHERE " + " AND ".join(clauses) + " ORDER BY entry_id LIMIT ?"  # noqa: S608
            return [_entry(r) for r in conn.execute(sql, [*args, limit])]

        return await self._store.state(read)

    async def lose_lineage(self, lineage: str, at_ms: int) -> int:
        """Every CLAIMED or BOUND entry of a lineage that is no longer the host's becomes LOST."""

        def write(conn: sqlite3.Connection) -> int:
            cur = conn.execute(
                "UPDATE entries SET state = 'LOST', updated_at_ms = ? WHERE state IN ('CLAIMED', 'BOUND') "
                "AND (lineage = ? OR lineage IS NULL)",
                (at_ms, lineage),
            )
            return cur.rowcount

        return await self._store.state(write, write=True)

    async def lose_peer(self, peer_id: str, at_ms: int) -> int:
        """Every entry made under a peer id the platform no longer has becomes LOST."""

        def write(conn: sqlite3.Connection) -> int:
            cur = conn.execute(
                "UPDATE entries SET state = 'LOST', updated_at_ms = ? WHERE state IN ('CLAIMED', 'BOUND') "
                "AND (peer_id = ? OR peer_id IS NULL)",
                (at_ms, peer_id),
            )
            return cur.rowcount

        return await self._store.state(write, write=True)

    async def expire(self, before_ms: int) -> int:
        """Retention: remove BOUND entries whose operation has ended, and LOST entries, older than the bound.

        Never removes a CLAIMED entry, nor a BOUND entry whose operation is not known to have ended.
        """

        def write(conn: sqlite3.Connection) -> int:
            cur = conn.execute(
                "DELETE FROM entries WHERE updated_at_ms < ? AND created_at_ms < ? "
                "AND (state = 'LOST' OR (state = 'BOUND' AND summary_json IS NOT NULL))",
                (before_ms, before_ms),
            )
            return cur.rowcount

        return await self._store.state(write, write=True)

    async def high_water(self, lineage: str) -> int:
        """The highest commit sequence of the host the platform has recorded under this lineage."""

        def read(conn: sqlite3.Connection) -> int:
            row = conn.execute("SELECT MAX(bound_seq) AS s FROM entries WHERE lineage = ?", (lineage,)).fetchone()
            return int(row["s"]) if row is not None and row["s"] is not None else 0

        return await self._store.state(read)

    async def counts(self, stale_before_ms: int) -> dict[str, int]:
        def read(conn: sqlite3.Connection) -> dict[str, int]:
            out = {"CLAIMED": 0, "BOUND": 0, "LOST": 0}
            for row in conn.execute("SELECT state, COUNT(*) AS n FROM entries GROUP BY state"):
                out[str(row["state"])] = int(row["n"])
            stale = conn.execute(
                "SELECT COUNT(*) FROM entries WHERE state = 'CLAIMED' AND created_at_ms < ?", (stale_before_ms,)
            ).fetchone()[0]
            return {"claimed": out["CLAIMED"], "bound": out["BOUND"], "lost": out["LOST"], "claimed_stale": int(stale)}

        return await self._store.state(read)
