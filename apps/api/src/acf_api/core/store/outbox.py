"""The audit outbox: durable audit records on their way to the operator's sink.

The outbox has a size budget of its own and can never use the space kept for the registry and the
ledger. When it is full, what happens is the operator's choice (``audit_required``); a claim, a bind, a
revocation and a containment request are written regardless, because they do not go through here.

A record is evidence of what was asked, by whom and with what result. It is never consulted for a
decision, and it never holds a credential, an argument value or output.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from acf_api.core.store.engine import Store, now_ms


class AuditOutbox:
    def __init__(self, store: Store) -> None:
        self._store = store

    async def append(self, record: dict[str, Any]) -> int:
        """Append one record. Raises :class:`~acf_api.core.store.engine.OutboxFull` when the budget is used."""
        text = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

        def write(conn: sqlite3.Connection) -> int:
            cur = conn.execute("INSERT INTO records(created_at_ms, record_json) VALUES (?, ?)", (now_ms(), text))
            return int(cur.lastrowid or 0)

        return await self._store.audit(write, write=True)

    async def undelivered(self, limit: int = 200) -> list[tuple[int, str]]:
        def read(conn: sqlite3.Connection) -> list[tuple[int, str]]:
            rows = conn.execute(
                "SELECT seq, record_json FROM records WHERE delivered = 0 ORDER BY seq LIMIT ?", (limit,)
            ).fetchall()
            return [(int(r["seq"]), str(r["record_json"])) for r in rows]

        return await self._store.audit(read)

    async def mark_delivered(self, up_to_seq: int) -> None:
        def write(conn: sqlite3.Connection) -> None:
            conn.execute("UPDATE records SET delivered = 1 WHERE delivered = 0 AND seq <= ?", (up_to_seq,))

        await self._store.audit(write, write=True)

    async def expire(self, before_ms: int, *, delivered_only: bool = False) -> int:
        """Remove records older than the retention. Deleting frees pages for new records."""

        def write(conn: sqlite3.Connection) -> int:
            sql = "DELETE FROM records WHERE created_at_ms < ?" + (" AND delivered = 1" if delivered_only else "")  # noqa: S608 - two constant texts; the one value is bound as a parameter
            return conn.execute(sql, (before_ms,)).rowcount

        return await self._store.audit(write, write=True)

    async def read(self, *, after_seq: int = 0, limit: int = 200) -> list[dict[str, Any]]:
        """Records for an operator, oldest first."""

        def read(conn: sqlite3.Connection) -> list[dict[str, Any]]:
            rows = conn.execute(
                "SELECT seq, created_at_ms, record_json, delivered FROM records WHERE seq > ? ORDER BY seq LIMIT ?",
                (after_seq, limit),
            ).fetchall()
            return [
                {"seq": int(r["seq"]), "delivered": bool(r["delivered"]), "record": json.loads(r["record_json"])}
                for r in rows
            ]

        return await self._store.audit(read)

    async def counts(self) -> dict[str, int]:
        def read(conn: sqlite3.Connection) -> dict[str, int]:
            total = int(conn.execute("SELECT COUNT(*) FROM records").fetchone()[0])
            pending = int(conn.execute("SELECT COUNT(*) FROM records WHERE delivered = 0").fetchone()[0])
            return {"records": total, "undelivered": pending}

        return await self._store.audit(read)
