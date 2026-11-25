"""The interface store's engine: two SQLite files, one writer, an exclusive lock and a writer epoch.

What the store is: durable truth for what the interface plane alone knows. The security registry and
the request ledger live in ``state.db``; the audit outbox lives in ``audit.db``, so that it has a size
budget of its own and can never use the space kept for the other two.

What it is not: it never holds sandbox, execution or snapshot state, output, guest data, secret
material, a plaintext credential, the host peer credential or the fingerprint key.

Rules enforced here:

* exactly one core opens a store: an exclusive lock on ``LOCK`` is held for the life of the process;
* a store carries a deployment id, created with it and never changed; a core serves only the store
  whose id its configuration names;
* the schema version is explicit; a store with a newer schema is neither written nor interpreted;
* each start takes a new writer epoch under the lock; every claim carries the epoch of the process
  that made it, so an entry claimed by an earlier process is known not to be in flight;
* every operation runs on one dedicated thread, so the event loop never waits on a disk, and is
  bounded by ``store_deadline``.
"""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import os
import queue
import sqlite3
import threading
import time
from collections.abc import Callable
from concurrent.futures import Future
from dataclasses import dataclass
from pathlib import Path
from typing import Final, TypeVar

SCHEMA_VERSION: Final = 1
STATE_FILE: Final = "state.db"
AUDIT_FILE: Final = "audit.db"
LOCK_FILE: Final = "LOCK"

T = TypeVar("T")


class StoreError(Exception):
    """Base class of store failures."""


class StoreUnavailable(StoreError):
    """The store did not answer within its deadline, or cannot be used right now."""


class StoreLocked(StoreError):
    """Another core holds the store."""


class StoreMismatch(StoreError):
    """The store is not the one this core was configured to serve, or its schema is not supported."""


class OutboxFull(StoreError):
    """The audit outbox has used its budget, or writing to it would use the space kept for the rest."""


_STATE_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS principals (
    principal_id TEXT PRIMARY KEY,
    label        TEXT NOT NULL,
    created_at   TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS projects (
    project_id TEXT PRIMARY KEY,
    label      TEXT NOT NULL,
    scope      TEXT NOT NULL UNIQUE,
    state      TEXT NOT NULL CHECK (state IN ('PENDING', 'ACTIVE', 'DELETING', 'DELETED')),
    share      REAL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS retired_scopes (
    scope      TEXT PRIMARY KEY,
    retired_at TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS roles (
    principal_id   TEXT NOT NULL REFERENCES principals(principal_id),
    project_id     TEXT NOT NULL REFERENCES projects(project_id),
    grants_json    TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    PRIMARY KEY (principal_id, project_id)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS credentials (
    credential_id        TEXT PRIMARY KEY,
    key_digest           TEXT NOT NULL UNIQUE,
    display_prefix       TEXT NOT NULL,
    principal_id         TEXT NOT NULL REFERENCES principals(principal_id),
    project_id           TEXT NOT NULL REFERENCES projects(project_id),
    kind                 TEXT NOT NULL CHECK (kind IN ('developer', 'agent')),
    parent_credential_id TEXT REFERENCES credentials(credential_id),
    narrowing_json       TEXT,
    agent_label          TEXT,
    issued_at_ms         INTEGER NOT NULL,
    expires_at_ms        INTEGER NOT NULL,
    first_used_at_ms     INTEGER,
    revoked_at_ms        INTEGER
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS credentials_parent ON credentials(parent_credential_id);
CREATE INDEX IF NOT EXISTS credentials_project ON credentials(project_id);

CREATE TABLE IF NOT EXISTS oauth_bindings (
    binding_id     TEXT PRIMARY KEY,
    issuer         TEXT NOT NULL,
    subject        TEXT NOT NULL,
    principal_id   TEXT NOT NULL REFERENCES principals(principal_id),
    project_id     TEXT NOT NULL REFERENCES projects(project_id),
    kind           TEXT NOT NULL CHECK (kind IN ('developer', 'agent')),
    narrowing_json TEXT,
    agent_label    TEXT,
    created_at_ms  INTEGER NOT NULL,
    revoked_at_ms  INTEGER,
    UNIQUE (issuer, subject)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS entries (
    -- AUTOINCREMENT: the id of a released or expired entry is never given to another. Bind, release,
    -- lose and the recorded outcome address an entry by its id, some of them after a read of the host.
    entry_id           INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id         TEXT NOT NULL,
    principal_id       TEXT NOT NULL,
    credential_id      TEXT NOT NULL,
    key_digest         TEXT NOT NULL,
    fingerprint        TEXT NOT NULL,
    derivation_version TEXT NOT NULL,
    operation_id       TEXT NOT NULL,
    host_id            TEXT NOT NULL,
    op_class           TEXT NOT NULL,
    method             TEXT NOT NULL,
    issued_at          TEXT NOT NULL,
    issued_at_ms       INTEGER NOT NULL,
    chosen_json        TEXT NOT NULL,
    owner_epoch        INTEGER NOT NULL,
    state              TEXT NOT NULL CHECK (state IN ('CLAIMED', 'BOUND', 'LOST')),
    lineage            TEXT,
    peer_id            TEXT,
    bound_seq          INTEGER,
    decision_id        TEXT NOT NULL,
    policy_version     TEXT NOT NULL,
    minted_key         TEXT,
    delivered          INTEGER NOT NULL DEFAULT 1,
    tool               TEXT,
    args_digest        TEXT,
    summary_json       TEXT,
    created_at_ms      INTEGER NOT NULL,
    updated_at_ms      INTEGER NOT NULL,
    UNIQUE (project_id, principal_id, key_digest)
);
CREATE INDEX IF NOT EXISTS entries_operation ON entries(project_id, operation_id);
CREATE INDEX IF NOT EXISTS entries_state ON entries(state, owner_epoch);
CREATE INDEX IF NOT EXISTS entries_adoption ON entries(credential_id, tool, args_digest, delivered);
CREATE INDEX IF NOT EXISTS entries_updated ON entries(updated_at_ms);
"""

_AUDIT_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS records (
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at_ms INTEGER NOT NULL,
    record_json   TEXT NOT NULL,
    delivered     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS records_delivery ON records(delivered, seq);
CREATE INDEX IF NOT EXISTS records_created ON records(created_at_ms);
"""


@dataclass(frozen=True, slots=True)
class StoreIdentity:
    deployment_id: str
    schema_version: int
    writer_epoch: int
    #: Sequence of the last security-journal record this store has applied.
    journal_applied: int


def _connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path, isolation_level=None, check_same_thread=True, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    # A commit is durable when it returns: a claim must be on disk before anything is sent to the host.
    conn.execute("PRAGMA synchronous = FULL")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA trusted_schema = OFF")
    return conn


def _meta(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return None if row is None else str(row["value"])


def _rollback(conn: sqlite3.Connection) -> None:
    """Undo the open transaction, if there still is one.

    After some failures, a database that is full among them, SQLite has undone the transaction by
    itself. Rolling back again would fail and would put that failure in the place of the one to report.
    """
    if conn.in_transaction:
        conn.execute("ROLLBACK")


def _set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


class _Lock:
    """An exclusive advisory lock, held for the life of the process."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._fd: int | None = None

    def acquire(self) -> None:
        fd = os.open(self._path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            os.close(fd)
            raise StoreLocked(f"{self._path.parent} is held by another core") from e
        self._fd = fd

    def release(self) -> None:
        fd, self._fd = self._fd, None
        if fd is not None:
            with contextlib.suppress(OSError):
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def create_store(store_dir: Path, deployment_id: str) -> None:
    """Create an empty store for a new deployment. Refuses a directory that already holds one."""
    store_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(store_dir, 0o700)
    if (store_dir / STATE_FILE).exists() or (store_dir / AUDIT_FILE).exists():
        raise StoreError(f"{store_dir} already holds a store")
    lock = _Lock(store_dir / LOCK_FILE)
    lock.acquire()
    try:
        state = _connect(store_dir / STATE_FILE)
        try:
            state.executescript(_STATE_SCHEMA)
            state.execute("BEGIN IMMEDIATE")
            _set_meta(state, "schema_version", str(SCHEMA_VERSION))
            _set_meta(state, "deployment_id", deployment_id)
            _set_meta(state, "writer_epoch", "0")
            _set_meta(state, "journal_applied", "0")
            state.execute("COMMIT")
        finally:
            state.close()
        audit = _connect(store_dir / AUDIT_FILE)
        try:
            audit.executescript(_AUDIT_SCHEMA)
        finally:
            audit.close()
        for name in (STATE_FILE, AUDIT_FILE):
            os.chmod(store_dir / name, 0o600)
    finally:
        lock.release()


class Store:
    """The open store of one core. Every access goes through :meth:`state` or :meth:`audit`."""

    def __init__(self, store_dir: Path, *, deadline_s: float, audit_budget_bytes: int, reserve_bytes: int) -> None:
        self._dir = store_dir
        self._deadline_s = deadline_s
        self._audit_budget = audit_budget_bytes
        self._reserve = reserve_bytes
        self._lock = _Lock(store_dir / LOCK_FILE)
        self._jobs: queue.SimpleQueue[tuple[Callable[[], object], Future[object]] | None] = queue.SimpleQueue()
        self._thread: threading.Thread | None = None
        self._state: sqlite3.Connection | None = None
        self._audit: sqlite3.Connection | None = None
        self.identity: StoreIdentity | None = None
        self.usable = False

    # ------------------------------------------------------------------ opening
    def open(self, deployment_id: str, *, journal_seq: int | None = None) -> StoreIdentity:
        """Lock the store, check that it is the configured one, and take a new writer epoch.

        ``journal_seq``: the sequence of the last record of the security journal this store is opened beside.
        A store that has applied a later record than the journal holds is refused, and is left as it was.
        """
        if not (self._dir / STATE_FILE).is_file():
            raise StoreMismatch(f"{self._dir} holds no store; create one with `acf-api init`")
        self._lock.acquire()
        started = threading.Event()
        outcome: list[StoreIdentity | BaseException] = []

        def run() -> None:
            try:
                outcome.append(self._open_on_thread(deployment_id, journal_seq))
            except BaseException as e:  # reported to the opener, which re-raises it
                outcome.append(e)
                started.set()
                return
            started.set()
            self._serve()

        self._thread = threading.Thread(target=run, name="acf-store", daemon=True)
        self._thread.start()
        started.wait()
        result = outcome[0]
        if isinstance(result, BaseException):
            self._lock.release()
            raise result
        self.identity = result
        self.usable = True
        return result

    def _open_on_thread(self, deployment_id: str, journal_seq: int | None) -> StoreIdentity:
        try:
            state = _connect(self._dir / STATE_FILE)
        except sqlite3.DatabaseError as e:
            raise StoreMismatch(f"{self._dir} is not a readable store: {type(e).__name__}") from e
        try:
            version_text = _meta(state, "schema_version")
        except sqlite3.DatabaseError as e:
            state.close()
            raise StoreMismatch(f"{self._dir} is not a readable store: {type(e).__name__}") from e
        if version_text is None or not (version_text.isascii() and version_text.isdigit()):
            state.close()
            raise StoreMismatch(f"{self._dir} carries no schema version")
        version = int(version_text)
        if version > SCHEMA_VERSION:
            state.close()
            raise StoreMismatch(
                f"the store has schema {version}; this version supports up to {SCHEMA_VERSION} and will not write it"
            )
        stored_id = _meta(state, "deployment_id")
        if stored_id != deployment_id:
            state.close()
            raise StoreMismatch("the store belongs to another deployment than the one the configuration names")
        check = state.execute("PRAGMA quick_check").fetchone()
        if check is None or str(check[0]) != "ok":
            state.close()
            raise StoreMismatch(f"{self._dir} fails its integrity check")
        applied = int(_meta(state, "journal_applied") or "0")
        if journal_seq is not None and applied > journal_seq:
            # The journal's chain proves that no record in it was changed. It cannot prove that none is
            # missing at its end: only what the store remembers of it can. A journal that has lost records
            # the store acted on has lost revocations, and a later restore of the store would undo them.
            state.close()
            raise StoreMismatch(
                f"the store has applied record {applied} of the security journal, and the journal ends at "
                f"record {journal_seq}: the journal is older than the store. It is the record that a restore "
                "must never undo, so nothing is served from the two; put the journal's own copy back"
            )
        # A migration runs here, at a start, under the exclusive lock, before any request is served.
        state.executescript(_STATE_SCHEMA)
        state.execute("BEGIN IMMEDIATE")
        epoch = int(_meta(state, "writer_epoch") or "0") + 1
        _set_meta(state, "writer_epoch", str(epoch))
        _set_meta(state, "schema_version", str(SCHEMA_VERSION))
        state.execute("COMMIT")
        audit = _connect(self._dir / AUDIT_FILE)
        audit.executescript(_AUDIT_SCHEMA)
        page_size = int(audit.execute("PRAGMA page_size").fetchone()[0])
        audit.execute(f"PRAGMA max_page_count = {max(16, self._audit_budget // page_size)}")
        self._state, self._audit = state, audit
        return StoreIdentity(deployment_id, SCHEMA_VERSION, epoch, applied)

    def _serve(self) -> None:
        while True:
            job = self._jobs.get()
            if job is None:
                break
            fn, future = job
            if not future.set_running_or_notify_cancel():
                continue
            try:
                future.set_result(fn())
            except BaseException as e:  # delivered to the awaiting caller
                future.set_exception(e)
        for conn in (self._state, self._audit):
            if conn is not None:
                with contextlib.suppress(sqlite3.Error):
                    conn.close()
        self._state = self._audit = None

    def close(self) -> None:
        self.usable = False
        if self._thread is not None:
            self._jobs.put(None)
            self._thread.join(timeout=10)
            self._thread = None
        self._lock.release()

    # ------------------------------------------------------------------ running work
    async def _run(self, fn: Callable[[], T]) -> T:
        if not self.usable:
            raise StoreUnavailable("the store is not open")
        future: Future[object] = Future()
        self._jobs.put((fn, future))
        try:
            result = await asyncio.wait_for(asyncio.wrap_future(future), self._deadline_s)
        except TimeoutError as e:
            future.cancel()
            raise StoreUnavailable("the store did not answer within its deadline") from e
        except sqlite3.OperationalError as e:
            raise StoreUnavailable(f"the store cannot be used: {type(e).__name__}") from e
        return result  # type: ignore[return-value]

    async def state(self, fn: Callable[[sqlite3.Connection], T], *, write: bool = False) -> T:
        """Run ``fn`` against the registry and the ledger. ``write``: inside one transaction."""

        def job() -> T:
            conn = self._state
            if conn is None:
                raise StoreUnavailable("the store is closed")
            if not write:
                return fn(conn)
            conn.execute("BEGIN IMMEDIATE")
            try:
                result = fn(conn)
            except BaseException:
                _rollback(conn)
                raise
            conn.execute("COMMIT")
            return result

        return await self._run(job)

    async def audit(self, fn: Callable[[sqlite3.Connection], T], *, write: bool = False) -> T:
        """Run ``fn`` against the audit outbox, inside its own budget."""

        def job() -> T:
            conn = self._audit
            if conn is None:
                raise StoreUnavailable("the store is closed")
            if not write:
                return fn(conn)
            if self._free_bytes() <= self._reserve:
                raise OutboxFull("writing an audit record would use the space kept for the registry and the ledger")
            conn.execute("BEGIN IMMEDIATE")
            try:
                result = fn(conn)
            except sqlite3.OperationalError as e:
                _rollback(conn)
                if "full" in str(e).lower():
                    raise OutboxFull("the audit outbox has used its budget") from e
                raise
            except BaseException:
                _rollback(conn)
                raise
            conn.execute("COMMIT")
            return result

        return await self._run(job)

    def _free_bytes(self) -> int:
        usage = os.statvfs(self._dir)
        return usage.f_bavail * usage.f_frsize

    # ------------------------------------------------------------------ measurements
    async def sizes(self) -> dict[str, int]:
        """Size of each part against its budget, for health and metrics."""

        def job() -> dict[str, int]:
            def size(name: str) -> int:
                total = 0
                for suffix in ("", "-wal"):
                    with contextlib.suppress(OSError):
                        total += (self._dir / (name + suffix)).stat().st_size
                return total

            return {
                "state_bytes": size(STATE_FILE),
                "audit_bytes": size(AUDIT_FILE),
                "audit_budget_bytes": self._audit_budget,
                "free_bytes": self._free_bytes(),
                "reserve_bytes": self._reserve,
            }

        return await self._run(job)

    async def set_journal_applied(self, seq: int) -> None:
        def write(conn: sqlite3.Connection) -> None:
            _set_meta(conn, "journal_applied", str(seq))

        await self.state(write, write=True)


def now_ms() -> int:
    return time.time_ns() // 1_000_000
