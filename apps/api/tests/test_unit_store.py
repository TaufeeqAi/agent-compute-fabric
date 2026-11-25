"""The interface store: its engine, the request ledger and the security registry.

Proves, for the engine: IPS-8 and EC-6 (one writer: a second core cannot open the store), IPS-12 (a
store carries a deployment id and is served only under it), IPS-6 (the schema version is explicit; a
store of a newer schema is neither written nor interpreted), IPS-16 (each start takes a new writer
epoch), IPS-13 (the audit outbox has a budget and a reserve of its own, and a full outbox stops no
claim) and the bound every store operation has (`store_deadline`).

For the ledger: IDM-5 and IPS-8 (the claim is unique: of any number of concurrent claims of one key
exactly one wins), IPS-7 (each transition is one transaction), the transitions the contract forbids
(a BOUND entry is never released, a LOST entry never returns, a recorded outcome is never changed),
IDM-9 (retention never removes an entry that is CLAIMED or whose operation is not known to have ended),
IDM-11 (a key is scoped by project and principal) and the schema half of IPS-2 and SEC-113 (an entry
has no place for a request parameter or a key).

For the registry: CRD-9 (the label of an agent credential is unique among the live agent credentials
of its principal; revoking a credential revokes the agent credentials it minted; revoking is
idempotent), CRD-6, PRJ-2 and PRJ-4 (a revocation, a scope allocation and a project deletion are in the
journal before they are in the registry), CRD-4 (the registry holds a digest and a display prefix of a
key, never the key) and IPS-10 with CRD-12 (after a restore the journal is applied again).

Catalog entries: T3-IPS-02 as far as it can be proven while there is one schema version (a newer
schema is not written, by the store alone and by the whole core as it starts; there is no migration
yet whose atomicity could be tested), the schema review of T3-IPS-03, the unit halves of T3-EC-03 and
T3-CRD-01. The crash, restart and whole-pipeline halves are proven by the pipeline suites.
"""

from __future__ import annotations

import asyncio
import itertools
import shutil
import sqlite3
import stat
import subprocess
import sys
import threading
import time
from collections.abc import AsyncIterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from acf_api.core import app
from acf_api.core.identity import keys
from acf_api.core.store import engine, registry
from acf_api.core.store import journal as j
from acf_api.core.store import ledger as lg
from acf_api.core.store.engine import OutboxFull, Store, StoreError, StoreLocked, StoreMismatch, StoreUnavailable
from acf_api.core.store.outbox import AuditOutbox
from tests.support.harness import build_rig

DEPLOYMENT = "dep_7Q2M9K4T1V8X3B6N"
OTHER_DEPLOYMENT = "dep_0A0B0C0D0E0F0G0H"
MIB = 1024 * 1024
NOW = 1_800_000_000_000
HOUR_MS = 3_600_000


def present[T](value: T | None) -> T:
    """What a test expects the store to hold: the row itself, or the failure of the test where it is absent."""
    assert value is not None
    return value


class Deployment:
    """A store and a journal on disk, and every handle a test opened on them."""

    def __init__(self, root: Path) -> None:
        self.dir = root / "store"
        self.journal_path = root / "journal" / "security.journal"
        self._stores: list[Store] = []
        self._journals: list[j.SecurityJournal] = []

    def store(self, **settings: Any) -> Store:
        """A handle on the store, not yet open."""
        made = Store(
            self.dir,
            deadline_s=settings.pop("deadline_s", 5.0),
            audit_budget_bytes=settings.pop("audit_budget_bytes", 64 * MIB),
            reserve_bytes=settings.pop("reserve_bytes", 1),
        )
        assert not settings
        self._stores.append(made)
        return made

    def open(self, **settings: Any) -> Store:
        store = self.store(**settings)
        store.open(DEPLOYMENT)
        return store

    def journal(self) -> j.SecurityJournal:
        journal = j.SecurityJournal(self.journal_path)
        journal.open(DEPLOYMENT)
        self._journals.append(journal)
        return journal

    def close(self) -> None:
        for store in self._stores:
            store.close()
        for journal in self._journals:
            journal.close()

    def meta(self, key: str) -> str | None:
        """A value of the store's own record of itself, read without the engine."""
        conn = sqlite3.connect(self.dir / engine.STATE_FILE)
        try:
            row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
            return None if row is None else str(row[0])
        finally:
            conn.close()

    def set_meta(self, key: str, value: str | None) -> None:
        conn = sqlite3.connect(self.dir / engine.STATE_FILE)
        try:
            if value is None:
                conn.execute("DELETE FROM meta WHERE key = ?", (key,))
            else:
                conn.execute(
                    "INSERT INTO meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (key, value),
                )
            conn.commit()
        finally:
            conn.close()

    def dump(self) -> list[str]:
        """Everything the two database files hold, as text."""
        out: list[str] = []
        for name in (engine.STATE_FILE, engine.AUDIT_FILE):
            conn = sqlite3.connect(self.dir / name)
            try:
                out.extend(conn.iterdump())
            finally:
                conn.close()
        return out


@pytest.fixture
async def deployment(tmp_path: Path) -> AsyncIterator[Deployment]:
    made = Deployment(tmp_path)
    engine.create_store(made.dir, DEPLOYMENT)
    j.create_journal(made.journal_path, DEPLOYMENT)
    try:
        yield made
    finally:
        made.close()


# =============================================================================== the engine
def test_a_new_store_carries_its_deployment_and_is_private(deployment: Deployment) -> None:
    assert sorted(path.name for path in deployment.dir.iterdir() if not path.name.endswith(("-wal", "-shm"))) == [
        "LOCK",
        "audit.db",
        "state.db",
    ]
    assert stat.S_IMODE(deployment.dir.stat().st_mode) == 0o700
    for name in (engine.STATE_FILE, engine.AUDIT_FILE, engine.LOCK_FILE):
        assert stat.S_IMODE((deployment.dir / name).stat().st_mode) == 0o600, name
    assert deployment.meta("deployment_id") == DEPLOYMENT
    assert deployment.meta("schema_version") == str(engine.SCHEMA_VERSION) == "1"
    assert deployment.meta("writer_epoch") == "0"
    assert deployment.meta("journal_applied") == "0"


def test_a_store_is_never_created_over_one_that_exists(deployment: Deployment) -> None:
    before = deployment.dump()
    for other in (DEPLOYMENT, OTHER_DEPLOYMENT):
        with pytest.raises(StoreError, match="already holds a store"):
            engine.create_store(deployment.dir, other)
    assert deployment.dump() == before
    assert deployment.meta("deployment_id") == DEPLOYMENT


async def test_an_open_store_says_what_it_is(deployment: Deployment) -> None:
    store = deployment.store()
    assert (store.usable, store.identity) == (False, None)
    identity = store.open(DEPLOYMENT)
    assert identity == engine.StoreIdentity(DEPLOYMENT, engine.SCHEMA_VERSION, 1, 0)
    assert (store.usable, store.identity) == (True, identity)
    assert await store.state(lambda conn: conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]) == 0
    assert await store.audit(lambda conn: conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]) == 0
    store.close()
    assert store.usable is False
    with pytest.raises(StoreUnavailable, match="not open"):
        await store.state(lambda conn: 1)
    with pytest.raises(StoreUnavailable, match="not open"):
        await store.audit(lambda conn: 1)


async def test_a_store_is_not_opened_beside_a_journal_that_ends_before_what_the_store_applied(
    deployment: Deployment,
) -> None:
    """IPS-14: the store remembers the last journal record it applied, and that is what shows a journal cut short."""
    store = deployment.open()
    await store.set_journal_applied(7)
    store.close()

    journal_ends_at: int | None
    for journal_ends_at in (0, 1, 6):
        refused = deployment.store()
        with pytest.raises(StoreMismatch, match="the journal is older than the store") as mismatch:
            refused.open(DEPLOYMENT, journal_seq=journal_ends_at)
        assert f"applied record 7 of the security journal, and the journal ends at record {journal_ends_at}" in str(
            mismatch.value
        )
        assert (refused.usable, refused.identity) == (False, None)
    # A refusal takes no writer epoch and leaves the lock free: the store is as it was.
    assert deployment.meta("writer_epoch") == "1"
    assert deployment.meta("journal_applied") == "7"

    # A journal that holds the record, or more than the store has applied, is the ordinary case.
    for journal_ends_at, epoch in ((7, 2), (8, 3), (None, 4)):
        opened = deployment.store()
        identity = opened.open(DEPLOYMENT, journal_seq=journal_ends_at)
        assert (identity.journal_applied, identity.writer_epoch) == (7, epoch)
        opened.close()


@pytest.mark.proves("T3-EC-03")
async def test_a_second_open_on_the_same_directory_is_refused(deployment: Deployment) -> None:
    """One core serves a deployment. A second one cannot lock the store, and so does not serve it."""
    first = deployment.open()
    for _attempt in range(3):
        second = deployment.store()
        with pytest.raises(StoreLocked, match="held by another core"):
            second.open(DEPLOYMENT)
        assert second.usable is False
        assert second.identity is None
        with pytest.raises(StoreUnavailable):
            await second.state(lambda conn: 1)
    # The refusals took nothing from the one that holds the store, and no epoch from the store.
    assert (
        await first.state(lambda conn: conn.execute("SELECT value FROM meta WHERE key = 'writer_epoch'").fetchone()[0])
        == "1"
    )
    with pytest.raises(StoreError):
        engine.create_store(deployment.dir, DEPLOYMENT)

    first.close()
    third = deployment.store()
    assert third.open(DEPLOYMENT).writer_epoch == 2


@pytest.mark.proves("T3-EC-03")
def test_a_second_process_cannot_open_the_store_either(deployment: Deployment) -> None:
    """The lock is the operating system's, on the file: it holds between processes, which is where it matters."""
    attempt = (
        "import sys\n"
        "from pathlib import Path\n"
        "from acf_api.core.store.engine import Store, StoreLocked\n"
        "store = Store(Path(sys.argv[1]), deadline_s=5.0, audit_budget_bytes=1 << 20, reserve_bytes=1)\n"
        "try:\n"
        "    store.open(sys.argv[2])\n"
        "except StoreLocked:\n"
        "    sys.exit(7)\n"
        "store.close()\n"
    )
    first = deployment.open()
    refused = subprocess.run(
        [sys.executable, "-c", attempt, str(deployment.dir), DEPLOYMENT], capture_output=True, timeout=60, check=False
    )
    assert refused.returncode == 7, refused.stderr.decode("utf-8", "replace")[-400:]
    first.close()
    allowed = subprocess.run(
        [sys.executable, "-c", attempt, str(deployment.dir), DEPLOYMENT], capture_output=True, timeout=60, check=False
    )
    assert allowed.returncode == 0, allowed.stderr.decode("utf-8", "replace")[-400:]
    assert deployment.meta("writer_epoch") == "2"


@pytest.mark.proves("T3-EC-03")
@pytest.mark.parametrize("configured", [OTHER_DEPLOYMENT, "", "dep_7Q2M9K4T1V8X3B6n", DEPLOYMENT + "0"])
def test_a_store_of_another_deployment_is_not_served(deployment: Deployment, configured: str) -> None:
    before = deployment.dump()
    store = deployment.store()
    with pytest.raises(StoreMismatch, match="another deployment"):
        store.open(configured)
    assert store.usable is False
    assert store.identity is None
    assert deployment.dump() == before, "a store that is not served is not written"
    assert deployment.meta("writer_epoch") == "0", "a refused start takes no epoch"
    # The lock was given back: the core that is configured for this store opens it.
    assert deployment.open().identity == engine.StoreIdentity(DEPLOYMENT, 1, 1, 0)


@pytest.mark.proves("T3-IPS-02")
@pytest.mark.parametrize("newer", [engine.SCHEMA_VERSION + 1, engine.SCHEMA_VERSION + 2, 999])
async def test_a_store_of_a_newer_schema_is_neither_written_nor_interpreted(deployment: Deployment, newer: int) -> None:
    earlier = deployment.open()
    await lg.Ledger(earlier).claim(new_entry())
    earlier.close()
    deployment.set_meta("schema_version", str(newer))
    before = deployment.dump()
    files_before = {path.name: path.read_bytes() for path in deployment.dir.iterdir() if path.name.endswith(".db")}

    store = deployment.store()
    with pytest.raises(StoreMismatch, match=f"schema {newer}") as refused:
        store.open(DEPLOYMENT)
    assert "will not write" in str(refused.value)
    # Not written: no epoch taken, no version put back, no table touched, not one byte of either file.
    assert deployment.dump() == before
    assert deployment.meta("schema_version") == str(newer)
    assert deployment.meta("writer_epoch") == "1"
    assert {
        path.name: path.read_bytes() for path in deployment.dir.iterdir() if path.name.endswith(".db")
    } == files_before
    # Not interpreted: nothing can be asked of it.
    assert store.usable is False
    assert store.identity is None
    with pytest.raises(StoreUnavailable):
        await lg.Ledger(store).find("prj_1", "prn_1", "digest-1")
    with pytest.raises(StoreUnavailable):
        await registry.Registry(store, j.SecurityJournal(deployment.journal_path)).projects()

    # The same store with its own version is served again: the refusal was for the version, and left the lock free.
    deployment.set_meta("schema_version", str(engine.SCHEMA_VERSION))
    assert deployment.open().identity == engine.StoreIdentity(DEPLOYMENT, 1, 2, 0)


@pytest.mark.proves("T3-IPS-02")
@pytest.mark.parametrize("version", [None, "", "one", "1.5", "-1", "v1", " 1", "\u00b2", "\u0661"])
def test_a_store_without_a_readable_schema_version_is_not_served(deployment: Deployment, version: str | None) -> None:
    deployment.set_meta("schema_version", version)
    before = deployment.dump()
    store = deployment.store()
    with pytest.raises(StoreMismatch, match="schema version"):
        store.open(DEPLOYMENT)
    assert store.usable is False
    assert deployment.dump() == before


@pytest.mark.proves("T3-IPS-02", level="L2")
async def test_a_core_does_not_start_on_a_store_of_a_newer_schema_and_writes_nothing_of_it(tmp_path: Path) -> None:
    """The same refusal where a deployment meets it: the whole core as it starts, over the model host."""
    rig = await build_rig(tmp_path)
    developer = await rig.developer()
    await rig.close()
    on_disk = Deployment(tmp_path)
    on_disk.dir, on_disk.journal_path = rig.config.paths.store_dir, rig.config.paths.journal
    newer = engine.SCHEMA_VERSION + 1
    on_disk.set_meta("schema_version", str(newer))

    def databases() -> dict[str, bytes]:
        return {path.name: path.read_bytes() for path in on_disk.dir.iterdir() if path.name.endswith(".db")}

    before, journal_before, epoch = databases(), on_disk.journal_path.read_bytes(), on_disk.meta("writer_epoch")
    assert set(before) == {engine.STATE_FILE, engine.AUDIT_FILE}

    rig.host.closed = False
    with pytest.raises(app.StartupError, match=f"schema {newer}") as refused:
        await build_rig(tmp_path, host=rig.host, clock=rig.clock)
    assert "will not write" in str(refused.value)
    assert databases() == before, "a start that was refused for the schema changed a byte of the store"
    assert on_disk.journal_path.read_bytes() == journal_before
    assert (on_disk.meta("schema_version"), on_disk.meta("writer_epoch")) == (str(newer), epoch)

    # The control: with the schema this version writes, the same deployment starts and holds what it held.
    on_disk.set_meta("schema_version", str(engine.SCHEMA_VERSION))
    rig.host.closed = False
    again = await build_rig(tmp_path, host=rig.host, clock=rig.clock)
    try:
        assert present(await again.core.service.d.registry.project(developer.project_id)).scope == developer.scope
        assert on_disk.meta("writer_epoch") == str(int(present(epoch)) + 1)
    finally:
        await again.close()


def test_what_is_not_a_store_is_not_served(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(StoreMismatch, match="holds no store"):
        Store(empty, deadline_s=1.0, audit_budget_bytes=MIB, reserve_bytes=1).open(DEPLOYMENT)
    with pytest.raises(StoreMismatch, match="holds no store"):
        Store(tmp_path / "absent", deadline_s=1.0, audit_budget_bytes=MIB, reserve_bytes=1).open(DEPLOYMENT)
    assert not (tmp_path / "absent").exists(), "looking for a store creates none"

    garbage = tmp_path / "garbage"
    garbage.mkdir()
    (garbage / engine.STATE_FILE).write_bytes(
        b"this is not a database file, and it is long enough to be read as one" * 100
    )
    store = Store(garbage, deadline_s=1.0, audit_budget_bytes=MIB, reserve_bytes=1)
    with pytest.raises(StoreMismatch):
        store.open(DEPLOYMENT)
    assert store.usable is False
    # The lock was given back, so a later look at the same directory is refused for what it is, not for a lock.
    with pytest.raises(StoreMismatch):
        Store(garbage, deadline_s=1.0, audit_budget_bytes=MIB, reserve_bytes=1).open(DEPLOYMENT)


async def test_the_writer_epoch_increases_on_every_open(deployment: Deployment) -> None:
    """Every start of the core is told apart from every earlier one, by a number the store keeps."""
    epochs = []
    for _start in range(5):
        store = deployment.open()
        assert store.identity is not None
        epochs.append(store.identity.writer_epoch)
        assert deployment.meta("writer_epoch") == str(epochs[-1]), "the epoch is recorded before anything is served"
        store.close()
    assert epochs == [1, 2, 3, 4, 5]


async def test_what_the_store_has_applied_of_the_journal_is_kept_across_starts(deployment: Deployment) -> None:
    store = deployment.open()
    await store.set_journal_applied(17)
    store.close()
    assert deployment.open().identity == engine.StoreIdentity(DEPLOYMENT, 1, 2, 17)


async def test_every_store_operation_runs_on_one_thread_that_is_not_the_event_loop(deployment: Deployment) -> None:
    store = deployment.open()
    loop_thread = threading.current_thread()
    seen = set()
    for run in (store.state, store.audit):
        for write in (False, True):
            seen.add(await run(lambda conn: threading.current_thread(), write=write))
    assert len(seen) == 1
    (thread,) = seen
    assert thread is not loop_thread
    assert thread.name == "acf-store"


@pytest.mark.proves("T3-EC-03")
async def test_a_store_operation_that_exceeds_its_deadline_is_unavailable(deployment: Deployment) -> None:
    store = deployment.open(deadline_s=0.05)
    started = time.monotonic()
    with pytest.raises(StoreUnavailable, match="deadline"):
        await store.state(lambda conn: time.sleep(0.4))
    assert time.monotonic() - started < 0.3, "the caller is answered at the deadline, not when the disk is done"
    await asyncio.sleep(0.5)
    # The store is unavailable for that operation, not for good.
    assert await store.state(lambda conn: 41 + 1) == 42


async def test_an_operation_that_timed_out_before_it_started_is_never_run(deployment: Deployment) -> None:
    """A write the caller was told did not happen must not happen later, behind the caller's back."""
    store = deployment.open(deadline_s=0.05)

    def slow(conn: sqlite3.Connection) -> None:
        time.sleep(0.4)

    def late_write(conn: sqlite3.Connection) -> None:
        conn.execute("INSERT INTO meta(key, value) VALUES ('written_late', 'yes')")

    blocking = asyncio.ensure_future(store.state(slow))
    await asyncio.sleep(0.01)
    with pytest.raises(StoreUnavailable):
        await store.state(late_write, write=True)
    with pytest.raises(StoreUnavailable):
        await blocking
    await asyncio.sleep(0.6)
    assert (
        await store.state(
            lambda conn: conn.execute("SELECT COUNT(*) FROM meta WHERE key = 'written_late'").fetchone()[0]
        )
        == 0
    )


async def test_a_failed_write_leaves_nothing_behind_and_the_failure_keeps_its_name(deployment: Deployment) -> None:
    store = deployment.open()

    def half_done(conn: sqlite3.Connection) -> None:
        conn.execute("INSERT INTO meta(key, value) VALUES ('half', 'done')")
        raise ValueError("the second half failed")

    with pytest.raises(ValueError, match="second half"):
        await store.state(half_done, write=True)
    with pytest.raises(sqlite3.IntegrityError):
        await store.state(
            lambda conn: conn.execute("INSERT INTO meta(key, value) VALUES ('schema_version', 'again')"), write=True
        )
    with pytest.raises(StoreUnavailable, match="cannot be used"):
        await store.state(lambda conn: conn.execute("SELECT * FROM no_such_table"))
    assert (
        await store.state(lambda conn: conn.execute("SELECT COUNT(*) FROM meta WHERE key = 'half'").fetchone()[0]) == 0
    )
    assert (
        await store.state(
            lambda conn: conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0]
        )
        == "1"
    )
    # The transaction that failed did not leave the connection inside one.
    await store.state(lambda conn: conn.execute("INSERT INTO meta(key, value) VALUES ('after', 'fine')"), write=True)


# ------------------------------------------------------------------------------- the audit outbox and its budget
async def _fill(outbox: AuditOutbox, size: int = 2000, limit: int = 100_000) -> int:
    """Append records of ``size`` bytes until the outbox refuses one. Returns how many it took."""
    for written in range(limit):
        try:
            await outbox.append({"n": written, "pad": "x" * size})
        except OutboxFull:
            return written
    pytest.fail("the outbox never filled")


@pytest.mark.proves("T3-RED-51", level="L1")
async def test_a_full_outbox_refuses_a_record_and_stops_no_claim(deployment: Deployment) -> None:
    """IPS-13: when the outbox is full, a claim, a bind, a revocation and a containment record are still written."""
    store = deployment.open(audit_budget_bytes=256 * 1024)
    outbox, ledger = AuditOutbox(store), lg.Ledger(store)
    written = await _fill(outbox)
    assert 20 < written < 200, "the budget of 256 KiB holds some records of 2 KiB, and not many more than 128"
    for _again in range(3):
        with pytest.raises(OutboxFull, match="budget"):
            await outbox.append({"pad": "x" * 2000})
    assert (await outbox.counts())["records"] == written

    entry = await ledger.claim(new_entry())
    assert entry is not None
    assert entry.state == lg.CLAIMED
    assert await ledger.bind(entry.entry_id, lineage="l1", seq=1, peer_id="p", at_ms=NOW) is True
    reg = registry.Registry(store, deployment.journal())
    await reg.create_principal("prn_0000000000000001", "someone")
    await reg.create_project("prj_0000000000000001", "a project", "scp-" + "1" * 32)
    await reg.insert_credential(credential("crd_0000000000000001"))
    assert await reg.revoke_credential("crd_0000000000000001", NOW) == ["crd_0000000000000001"]

    # The budget is the outbox's own: the registry and the ledger grew, and the outbox is exactly as full.
    with pytest.raises(OutboxFull):
        await outbox.append({"pad": "x" * 2000})
    assert (deployment.dir / engine.AUDIT_FILE).stat().st_size <= 256 * 1024


@pytest.mark.proves("T3-RED-51", level="L1")
async def test_records_that_leave_the_outbox_make_room_for_new_ones(deployment: Deployment) -> None:
    store = deployment.open(audit_budget_bytes=256 * 1024)
    outbox = AuditOutbox(store)
    written = await _fill(outbox)
    assert await outbox.expire(engine.now_ms() + 1) == written
    assert await _fill(outbox) >= written - 2
    assert await outbox.read(limit=1) != []


@pytest.mark.proves("T3-RED-51", level="L1")
async def test_the_outbox_never_uses_the_space_kept_for_the_registry_and_the_ledger(deployment: Deployment) -> None:
    """`store_reserve_bytes`: with less free space than the reserve, the outbox takes nothing. The rest goes on."""
    free = shutil.disk_usage(deployment.dir).free
    store = deployment.open(audit_budget_bytes=64 * MIB, reserve_bytes=free * 4)
    outbox, ledger = AuditOutbox(store), lg.Ledger(store)
    with pytest.raises(OutboxFull, match="space kept for the registry and the ledger"):
        await outbox.append({"small": True})
    assert (await outbox.counts()) == {"records": 0, "undelivered": 0}
    assert await outbox.undelivered() == []
    assert await ledger.claim(new_entry()) is not None
    sizes = await store.sizes()
    assert sizes["reserve_bytes"] == free * 4
    assert sizes["audit_budget_bytes"] == 64 * MIB
    assert sizes["free_bytes"] < sizes["reserve_bytes"]


async def test_the_outbox_keeps_records_in_order_until_they_are_delivered(deployment: Deployment) -> None:
    outbox = AuditOutbox(deployment.open())
    first = await outbox.append({"what": "first", "text": "caf\u00e9"})
    second = await outbox.append({"what": "second"})
    assert second == first + 1
    assert [json_text for _, json_text in await outbox.undelivered()] == [
        '{"text":"caf\u00e9","what":"first"}',
        '{"what":"second"}',
    ]
    await outbox.mark_delivered(first)
    assert [seq for seq, _ in await outbox.undelivered()] == [second]
    assert await outbox.counts() == {"records": 2, "undelivered": 1}
    assert [(row["seq"], row["delivered"], row["record"]["what"]) for row in await outbox.read()] == [
        (first, True, "first"),
        (second, False, "second"),
    ]
    assert await outbox.expire(engine.now_ms() + 1, delivered_only=True) == 1
    assert await outbox.counts() == {"records": 1, "undelivered": 1}


# =============================================================================== the ledger
_serial = itertools.count(1)


def new_entry(**changes: Any) -> lg.NewEntry:
    """A claim of a key nobody used before, unless a test names the key."""
    number = next(_serial)
    base = lg.NewEntry(
        project_id="prj_0000000000000001",
        principal_id="prn_0000000000000001",
        credential_id="crd_0000000000000001",
        key_digest=f"digest-{number}",
        fingerprint=f"fingerprint-{number}",
        derivation_version="1",
        operation_id=f"op-{number:032x}",
        host_id="host-model",
        op_class="granting",
        method="sandbox.create",
        issued_at="2027-01-15T08:00:00.000Z",
        issued_at_ms=NOW,
        chosen=lg.Chosen(),
        owner_epoch=1,
        lineage="lineage-1",
        peer_id="platform",
        decision_id="dec_0001",
        policy_version="pv_0001",
        created_at_ms=NOW,
    )
    return replace(base, **changes)


def summary(state: str = "SUCCEEDED") -> lg.Summary:
    return lg.Summary(
        state=state,
        effect="APPLIED",
        failure_code=None,
        failure_retry=None,
        cleanup=None,
        operation_type="sandbox.create",
        produced={"sandbox_id": "sbx-" + "0" * 32, "generation": 1},
        created_at="2027-01-15T08:00:00.000Z",
        updated_at="2027-01-15T08:00:01.000Z",
        initiated_by="CALLER",
        actor="prn_0000000000000001",
    )


#: What a claim commits and nothing may change afterwards.
IMMUTABLE = (
    "entry_id",
    "project_id",
    "principal_id",
    "credential_id",
    "key_digest",
    "fingerprint",
    "derivation_version",
    "operation_id",
    "host_id",
    "op_class",
    "method",
    "issued_at",
    "issued_at_ms",
    "chosen",
    "owner_epoch",
    "decision_id",
    "policy_version",
    "minted_key",
    "tool",
    "args_digest",
    "created_at_ms",
)


def same_request(one: lg.Entry, other: lg.Entry) -> bool:
    return all(getattr(one, field) == getattr(other, field) for field in IMMUTABLE)


async def test_a_claim_commits_everything_a_later_submission_needs(deployment: Deployment) -> None:
    ledger = lg.Ledger(deployment.open())
    asked = new_entry(
        chosen=lg.Chosen(generation=3, lifetime_seconds=900, timeout_seconds=600),
        minted_key="mk_" + "A" * 32,
        tool="sandbox_exec",
        args_digest="args-1",
        owner_epoch=7,
    )
    entry = await ledger.claim(asked)
    assert entry is not None
    for field in (
        "project_id",
        "principal_id",
        "credential_id",
        "key_digest",
        "fingerprint",
        "derivation_version",
        "operation_id",
        "host_id",
        "op_class",
        "method",
        "issued_at",
        "issued_at_ms",
        "chosen",
        "owner_epoch",
        "lineage",
        "peer_id",
        "decision_id",
        "policy_version",
        "minted_key",
        "tool",
        "args_digest",
        "created_at_ms",
    ):
        assert getattr(entry, field) == getattr(asked, field), field
    assert (entry.state, entry.bound_seq, entry.summary, entry.updated_at_ms) == (lg.CLAIMED, None, None, NOW)
    assert entry.delivered is False, "a minted key is undelivered until the adapter says its result was written"
    assert present(await ledger.claim(new_entry())).delivered is True
    assert await ledger.find(asked.project_id, asked.principal_id, asked.key_digest) == entry
    assert await ledger.by_operation(asked.project_id, asked.operation_id) == entry
    assert await ledger.find(asked.project_id, asked.principal_id, "another-digest") is None
    assert await ledger.by_operation("prj_other", asked.operation_id) is None


async def test_of_two_concurrent_claims_of_one_key_exactly_one_wins(deployment: Deployment) -> None:
    """The claim is a unique insert: whatever the two requests say, one of them holds the key and the other does not."""
    ledger = lg.Ledger(deployment.open())
    one = new_entry(key_digest="the-key", fingerprint="fp-one", operation_id="op-" + "1" * 32)
    other = replace(one, fingerprint="fp-other", operation_id="op-" + "2" * 32, issued_at_ms=NOW + 5)
    won = [entry for entry in await asyncio.gather(ledger.claim(one), ledger.claim(other)) if entry is not None]
    assert len(won) == 1
    stored = await ledger.find(one.project_id, one.principal_id, "the-key")
    assert stored == won[0]
    assert (stored.fingerprint, stored.operation_id) in {("fp-one", "op-" + "1" * 32), ("fp-other", "op-" + "2" * 32)}
    assert await ledger.counts(NOW) == {"claimed": 1, "bound": 0, "lost": 0, "claimed_stale": 0}


async def test_of_many_concurrent_claims_of_one_key_exactly_one_wins(deployment: Deployment) -> None:
    ledger = lg.Ledger(deployment.open())
    claims = [new_entry(key_digest="contended", fingerprint=f"fp-{n}", operation_id=f"op-{n:032x}") for n in range(64)]
    results = await asyncio.gather(*(ledger.claim(claim) for claim in claims))
    assert sum(result is not None for result in results) == 1
    assert (await ledger.counts(NOW))["claimed"] == 1
    # Nobody who lost changed what the winner committed.
    winner = next(result for result in results if result is not None)
    assert await ledger.find(winner.project_id, winner.principal_id, "contended") == winner


async def test_a_key_is_scoped_by_project_and_principal(deployment: Deployment) -> None:
    """The same key under two projects, or under two principals, names two independent requests."""
    ledger = lg.Ledger(deployment.open())
    claims = [
        new_entry(key_digest="shared", project_id=project, principal_id=principal)
        for project in ("prj_0000000000000001", "prj_0000000000000002")
        for principal in ("prn_0000000000000001", "prn_0000000000000002")
    ]
    entries = await asyncio.gather(*(ledger.claim(claim) for claim in claims))
    assert all(entry is not None for entry in entries)
    assert len({entry.entry_id for entry in entries if entry is not None}) == 4
    assert await ledger.claim(replace(claims[0], fingerprint="again")) is None


async def test_bind_makes_a_claimed_entry_bound_once(deployment: Deployment) -> None:
    ledger = lg.Ledger(deployment.open())
    claimed = await ledger.claim(new_entry(lineage=None, peer_id=None))
    assert claimed is not None
    assert await ledger.bind(claimed.entry_id, lineage="lineage-9", seq=41, peer_id="platform", at_ms=NOW + 10) is True
    bound = await ledger.find(claimed.project_id, claimed.principal_id, claimed.key_digest)
    assert bound is not None
    assert (bound.state, bound.lineage, bound.bound_seq, bound.peer_id, bound.updated_at_ms) == (
        lg.BOUND,
        "lineage-9",
        41,
        "platform",
        NOW + 10,
    )
    assert same_request(bound, claimed)
    # Binding again is the answer "it is bound", and changes nothing of what was bound.
    assert (
        await ledger.bind(claimed.entry_id, lineage="lineage-other", seq=99, peer_id="someone", at_ms=NOW + 99) is True
    )
    assert await ledger.find(claimed.project_id, claimed.principal_id, claimed.key_digest) == bound
    assert await ledger.bind(claimed.entry_id + 1000, lineage="l", seq=1, peer_id="p", at_ms=NOW) is False
    assert await ledger.high_water("lineage-9") == 41
    assert await ledger.high_water("lineage-unknown") == 0


async def test_a_bind_without_a_lineage_keeps_the_one_the_claim_recorded(deployment: Deployment) -> None:
    ledger = lg.Ledger(deployment.open())
    claimed = await ledger.claim(new_entry(lineage="lineage-of-the-claim", peer_id="peer-of-the-claim"))
    assert claimed is not None
    assert await ledger.bind(claimed.entry_id, lineage=None, seq=None, peer_id=None, at_ms=NOW) is True
    bound = await ledger.find(claimed.project_id, claimed.principal_id, claimed.key_digest)
    assert bound is not None
    assert (bound.lineage, bound.peer_id, bound.bound_seq) == ("lineage-of-the-claim", "peer-of-the-claim", None)


async def test_release_removes_a_claimed_entry_and_only_a_claimed_one(deployment: Deployment) -> None:
    """A refusal by the host proves nothing exists: the entry goes, and the key is free for a fresh attempt."""
    ledger = lg.Ledger(deployment.open())
    claimed = await ledger.claim(new_entry(key_digest="refused"))
    assert claimed is not None
    assert await ledger.release(claimed.entry_id) is True
    assert await ledger.find(claimed.project_id, claimed.principal_id, "refused") is None
    assert await ledger.release(claimed.entry_id) is False
    fresh = await ledger.claim(new_entry(key_digest="refused", issued_at_ms=NOW + 60_000, created_at_ms=NOW + 60_000))
    assert fresh is not None
    assert fresh.issued_at_ms == NOW + 60_000
    # The fresh attempt is another entry under another id: whoever still holds the id of the released
    # one, a recovery pass that read it a moment ago for instance, acts on nothing.
    assert fresh.entry_id != claimed.entry_id
    assert await ledger.bind(claimed.entry_id, lineage="stale", seq=1, peer_id="p", at_ms=NOW) is False
    assert await ledger.lose(claimed.entry_id, NOW) is False
    assert await ledger.find(fresh.project_id, fresh.principal_id, "refused") == fresh

    # A BOUND entry is not released: its operation exists, and the key must keep naming it.
    assert await ledger.bind(fresh.entry_id, lineage="l", seq=1, peer_id="p", at_ms=NOW) is True
    assert await ledger.release(fresh.entry_id) is False
    still = await ledger.find(fresh.project_id, fresh.principal_id, "refused")
    assert still is not None
    assert still.state == lg.BOUND
    # Nor a LOST one.
    assert await ledger.lose(fresh.entry_id, NOW) is True
    assert await ledger.release(fresh.entry_id) is False
    assert present(await ledger.find(fresh.project_id, fresh.principal_id, "refused")).state == lg.LOST


async def test_a_lost_entry_never_returns(deployment: Deployment) -> None:
    """LOST is final within retention: the key is never resubmitted, never rebound and never claimed again."""
    ledger = lg.Ledger(deployment.open())
    for start in ("claimed", "bound"):
        claimed = await ledger.claim(new_entry(key_digest=f"lost-from-{start}"))
        assert claimed is not None
        if start == "bound":
            await ledger.bind(claimed.entry_id, lineage="l", seq=3, peer_id="p", at_ms=NOW)
        assert await ledger.lose(claimed.entry_id, NOW + 1) is True
        lost = await ledger.find(claimed.project_id, claimed.principal_id, claimed.key_digest)
        assert lost is not None
        assert lost.state == lg.LOST
        assert lost.updated_at_ms == NOW + 1
        assert same_request(lost, claimed)

        assert await ledger.bind(claimed.entry_id, lineage="l2", seq=9, peer_id="p", at_ms=NOW + 2) is False
        assert await ledger.release(claimed.entry_id) is False
        assert await ledger.lose(claimed.entry_id, NOW + 3) is False
        assert await ledger.record_summary(claimed.entry_id, summary(), NOW + 4) is False
        assert await ledger.claim(new_entry(key_digest=claimed.key_digest, fingerprint="a new attempt")) is None
        assert await ledger.find(claimed.project_id, claimed.principal_id, claimed.key_digest) == lost
    assert await ledger.lose(10_000, NOW) is False


async def test_a_terminal_outcome_is_recorded_once_and_never_changed(deployment: Deployment) -> None:
    ledger = lg.Ledger(deployment.open())
    claimed = await ledger.claim(new_entry())
    assert claimed is not None
    # Only an operation the host holds has an outcome to record: not a claim, and not a lost entry.
    assert await ledger.record_summary(claimed.entry_id, summary(), NOW) is False
    await ledger.bind(claimed.entry_id, lineage="l", seq=1, peer_id="p", at_ms=NOW)
    first = summary("FAILED")
    assert await ledger.record_summary(claimed.entry_id, first, NOW + 5) is True
    for attempt in (summary("SUCCEEDED"), summary("UNKNOWN"), first):
        assert await ledger.record_summary(claimed.entry_id, attempt, NOW + 50) is False
    stored = await ledger.find(claimed.project_id, claimed.principal_id, claimed.key_digest)
    assert stored is not None
    assert stored.summary == first
    assert stored.updated_at_ms == NOW + 5
    # The recorded outcome is what remains when the host forgets the operation.
    assert await ledger.lose(claimed.entry_id, NOW + 60) is True
    lost = await ledger.find(claimed.project_id, claimed.principal_id, claimed.key_digest)
    assert lost is not None
    assert (lost.state, lost.summary) == (lg.LOST, first)
    assert await ledger.record_summary(claimed.entry_id, summary("SUCCEEDED"), NOW + 70) is False
    assert present(await ledger.find(claimed.project_id, claimed.principal_id, claimed.key_digest)).summary == first
    assert lg.Summary.from_json(first.to_json()) == first


@pytest.mark.timeout(120)
async def test_every_sequence_of_four_steps_follows_the_state_diagram(deployment: Deployment) -> None:
    """Exhaustive: claim, bind, release, lose and record an outcome, in every order of four, against a model.

    Forbidden and impossible: BOUND to CLAIMED; LOST to anything; an outcome on anything but a BOUND
    entry, or a second one; and any change of what the claim committed.
    """
    ledger = lg.Ledger(deployment.open())
    steps = ("claim", "bind", "release", "lose", "summary")
    for number, sequence in enumerate(itertools.product(steps, repeat=4)):
        key = f"walk-{number}"
        state, recorded, entry_id, committed = "ABSENT", False, 0, None
        for step in ("claim", *sequence):
            if step == "claim":
                claimed = await ledger.claim(new_entry(key_digest=key, fingerprint=f"{key}-{entry_id}"))
                assert (claimed is not None) is (state == "ABSENT"), (sequence, step)
                if claimed is not None:
                    state, recorded, entry_id, committed = lg.CLAIMED, False, claimed.entry_id, claimed
            elif step == "bind":
                assert await ledger.bind(entry_id, lineage="l", seq=1, peer_id="p", at_ms=NOW) is (
                    state in {lg.CLAIMED, lg.BOUND}
                ), (sequence, step)
                state = lg.BOUND if state == lg.CLAIMED else state
            elif step == "release":
                assert await ledger.release(entry_id) is (state == lg.CLAIMED), (sequence, step)
                state = "ABSENT" if state == lg.CLAIMED else state
            elif step == "lose":
                assert await ledger.lose(entry_id, NOW) is (state in {lg.CLAIMED, lg.BOUND}), (sequence, step)
                state = lg.LOST if state in {lg.CLAIMED, lg.BOUND} else state
            else:
                assert await ledger.record_summary(entry_id, summary(), NOW) is (state == lg.BOUND and not recorded), (
                    sequence,
                    step,
                )
                recorded = recorded or state == lg.BOUND
            stored = await ledger.find("prj_0000000000000001", "prn_0000000000000001", key)
            if state == "ABSENT":
                assert stored is None, (sequence, step)
            else:
                assert stored is not None
                assert committed is not None
                assert (stored.state, stored.summary is not None) == (state, recorded), (sequence, step)
                assert same_request(stored, committed), (sequence, step)


@pytest.mark.proves("T3-IDM-05", level="L1")
async def test_retention_removes_what_has_ended_and_nothing_else(deployment: Deployment) -> None:
    """An entry is never removed while it is CLAIMED, or while its operation is not known to have ended."""
    ledger = lg.Ledger(deployment.open())
    old, young = NOW - 30 * HOUR_MS, NOW - 1
    horizon = NOW - 25 * HOUR_MS

    async def make(label: str, state: str, *, at_ms: int, with_outcome: bool = False) -> None:
        entry = await ledger.claim(new_entry(key_digest=label, created_at_ms=at_ms, issued_at_ms=at_ms))
        assert entry is not None
        if state in {lg.BOUND, lg.LOST}:
            await ledger.bind(entry.entry_id, lineage="l", seq=1, peer_id="p", at_ms=at_ms)
        if with_outcome:
            assert await ledger.record_summary(entry.entry_id, summary(), at_ms)
        if state == lg.LOST:
            await ledger.lose(entry.entry_id, at_ms)

    await make("old-claimed", lg.CLAIMED, at_ms=old)
    await make("old-bound-running", lg.BOUND, at_ms=old)
    await make("old-bound-ended", lg.BOUND, at_ms=old, with_outcome=True)
    await make("old-lost", lg.LOST, at_ms=old)
    await make("old-lost-with-outcome", lg.LOST, at_ms=old, with_outcome=True)
    await make("young-claimed", lg.CLAIMED, at_ms=young)
    await make("young-bound-ended", lg.BOUND, at_ms=young, with_outcome=True)
    await make("young-lost", lg.LOST, at_ms=young)
    # Claimed long ago, and its operation ended only now: retention counts from the last change.
    late = await ledger.claim(new_entry(key_digest="old-claim-ended-late", created_at_ms=old, issued_at_ms=old))
    assert late is not None
    await ledger.bind(late.entry_id, lineage="l", seq=1, peer_id="p", at_ms=old)
    await ledger.record_summary(late.entry_id, summary(), young)

    assert await ledger.expire(horizon) == 3

    async def kept(label: str) -> bool:
        return await ledger.find("prj_0000000000000001", "prn_0000000000000001", label) is not None

    assert not await kept("old-bound-ended")
    assert not await kept("old-lost")
    assert not await kept("old-lost-with-outcome")
    for label in (
        "old-claimed",
        "old-bound-running",
        "young-claimed",
        "young-bound-ended",
        "young-lost",
        "old-claim-ended-late",
    ):
        assert await kept(label), label
    # However often retention runs, and however far in the future, the two that have not ended stay.
    assert await ledger.expire(NOW + 10_000 * HOUR_MS) == 3
    assert await kept("old-claimed")
    assert await kept("old-bound-running")
    assert await kept("young-claimed")
    assert await ledger.counts(NOW) == {"claimed": 2, "bound": 1, "lost": 0, "claimed_stale": 2}
    # After retention a key starts a new operation.
    assert await ledger.claim(new_entry(key_digest="old-lost")) is not None


async def test_the_recovery_pass_is_given_the_claims_of_earlier_starts_and_the_stale_ones(
    deployment: Deployment,
) -> None:
    ledger = lg.Ledger(deployment.open())
    for label, epoch, created in (
        ("earlier-start", 1, NOW),
        ("this-start-stale", 2, NOW - 600_000),
        ("this-start-fresh", 2, NOW),
        ("bound", 1, NOW - 600_000),
    ):
        entry = await ledger.claim(new_entry(key_digest=label, owner_epoch=epoch, created_at_ms=created))
        assert entry is not None
        if label == "bound":
            await ledger.bind(entry.entry_id, lineage="l", seq=1, peer_id="p", at_ms=NOW)
    assert [e.key_digest for e in await ledger.claimed(before_epoch=2)] == ["earlier-start"]
    assert [e.key_digest for e in await ledger.claimed(older_than_ms=NOW - 120_000)] == ["this-start-stale"]
    assert [e.key_digest for e in await ledger.claimed()] == ["earlier-start", "this-start-stale", "this-start-fresh"]
    assert [e.key_digest for e in await ledger.claimed(limit=2)] == ["earlier-start", "this-start-stale"]
    assert await ledger.counts(NOW - 120_000) == {"claimed": 3, "bound": 1, "lost": 0, "claimed_stale": 1}


async def test_the_entries_of_a_lineage_or_of_a_peer_that_is_gone_become_lost(deployment: Deployment) -> None:
    ledger = lg.Ledger(deployment.open())
    for label, lineage, peer, bound in (
        ("old-claimed", "old", "platform", False),
        ("old-bound", "old", "platform", True),
        ("new-bound", "new", "platform", True),
        ("unknown-lineage", None, None, False),
    ):
        entry = await ledger.claim(new_entry(key_digest=label, lineage=lineage, peer_id=peer))
        assert entry is not None
        if bound:
            await ledger.bind(entry.entry_id, lineage=None, seq=1, peer_id=None, at_ms=NOW)

    async def states() -> dict[str, str]:
        found: dict[str, str] = {}
        for label in ("old-claimed", "old-bound", "new-bound", "unknown-lineage"):
            entry = await ledger.find("prj_0000000000000001", "prn_0000000000000001", label)
            assert entry is not None, label
            found[label] = entry.state
        return found

    assert await ledger.lose_lineage("old", NOW + 1) == 3
    assert await states() == {
        "old-claimed": lg.LOST,
        "old-bound": lg.LOST,
        "new-bound": lg.BOUND,
        "unknown-lineage": lg.LOST,
    }
    assert await ledger.lose_lineage("old", NOW + 2) == 0
    assert await ledger.lose_peer("platform", NOW + 3) == 1
    assert (await states())["new-bound"] == lg.LOST
    assert await ledger.lose_peer("platform", NOW + 4) == 0


async def test_an_undelivered_call_is_found_for_adoption_until_it_is_delivered_or_too_old(
    deployment: Deployment,
) -> None:
    ledger = lg.Ledger(deployment.open())

    async def call(label: str, **changes: Any) -> lg.Entry:
        base = {
            "credential_id": "crd_agent",
            "tool": "sandbox_exec",
            "args_digest": "args",
            "minted_key": f"mk_{label}",
            "created_at_ms": NOW,
        }
        entry = await ledger.claim(new_entry(key_digest=label, **{**base, **changes}))
        assert entry is not None
        return entry

    first = await call("first")
    second = await call("second", created_at_ms=NOW + 10)
    await call("other-credential", credential_id="crd_other")
    await call("other-tool", tool="sandbox_create")
    await call("other-arguments", args_digest="other")
    not_minted = await ledger.claim(
        new_entry(key_digest="supplied", credential_id="crd_agent", tool="sandbox_exec", args_digest="args")
    )
    assert not_minted is not None
    assert not_minted.delivered is True

    assert (await ledger.adoptable("crd_agent", "sandbox_exec", "args", NOW - 1000)) == second
    assert await ledger.adoptable("crd_agent", "sandbox_exec", "args", NOW + 11) is None, (
        "an undelivered call older than the window is new work"
    )
    await ledger.mark_delivered(second.entry_id, NOW + 20)
    assert (await ledger.adoptable("crd_agent", "sandbox_exec", "args", NOW - 1000)) == first
    await ledger.mark_delivered(first.entry_id, NOW + 30)
    assert await ledger.adoptable("crd_agent", "sandbox_exec", "args", NOW - 1000) is None
    assert await ledger.adoptable("crd_nobody", "sandbox_exec", "args", 0) is None


@pytest.mark.proves("T3-IPS-03", level="L0")
async def test_an_entry_has_no_place_for_a_request_parameter_or_a_key(deployment: Deployment) -> None:
    """The ledger records a request, not its content: a keyed digest of the key, a fingerprint, and what the platform chose."""
    store = deployment.open()
    columns = await store.state(lambda conn: [row["name"] for row in conn.execute("PRAGMA table_info(entries)")])
    assert set(columns) == {
        "entry_id", "project_id", "principal_id", "credential_id", "key_digest", "fingerprint", "derivation_version",
        "operation_id", "host_id", "op_class", "method", "issued_at", "issued_at_ms", "chosen_json", "owner_epoch", "state",
        "lineage", "peer_id", "bound_seq", "decision_id", "policy_version", "minted_key", "delivered", "tool", "args_digest",
        "summary_json", "created_at_ms", "updated_at_ms",
    }  # fmt: skip
    assert not {
        name
        for name in columns
        if any(
            word in name for word in ("argv", "env", "body", "params", "request", "secret", "output", "image", "name")
        )
    }
    assert (
        set(lg.NewEntry.__dataclass_fields__) & {"key", "idempotency_key", "body", "command", "arguments", "params"}
        == set()
    )
    # The values the platform adds are three numbers. Nothing a caller wrote is among them.
    assert lg.Chosen(generation=3, lifetime_seconds=900, timeout_seconds=600).to_json() == '{"g":3,"l":900,"t":600}'
    assert lg.Chosen().to_json() == "{}"
    assert lg.Chosen.from_json('{"g":3}') == lg.Chosen(generation=3)
    assert set(lg.Chosen.__dataclass_fields__) == {"generation", "lifetime_seconds", "timeout_seconds"}
    # The recorded outcome holds identifiers and vocabulary values: no output, and no message of the host.
    assert set(lg.Summary.__dataclass_fields__) == {
        "state",
        "effect",
        "failure_code",
        "failure_retry",
        "cleanup",
        "operation_type",
        "produced",
        "created_at",
        "updated_at",
        "initiated_by",
        "actor",
    }
    tables = await store.state(
        lambda conn: sorted(
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
        )
    )
    assert tables == [
        "credentials",
        "entries",
        "meta",
        "oauth_bindings",
        "principals",
        "projects",
        "retired_scopes",
        "roles",
    ]
    audit_tables = await store.audit(
        lambda conn: sorted(
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
        )
    )
    assert audit_tables == ["records"]


# =============================================================================== the registry
PRINCIPAL = "prn_0000000000000001"
OTHER_PRINCIPAL = "prn_0000000000000002"
PROJECT = "prj_0000000000000001"
OTHER_PROJECT = "prj_0000000000000002"
SCOPE = "scp-" + "1" * 32
OTHER_SCOPE = "scp-" + "2" * 32
DAY_MS = 24 * HOUR_MS


def credential(credential_id: str, **changes: Any) -> registry.Credential:
    base = registry.Credential(
        credential_id=credential_id,
        key_digest=f"digest-of-{credential_id}",
        display_prefix="acf1_dev_AbCd",
        principal_id=PRINCIPAL,
        project_id=PROJECT,
        kind="developer",
        parent_credential_id=None,
        narrowing_json=None,
        agent_label=None,
        issued_at_ms=NOW,
        expires_at_ms=NOW + DAY_MS,
        first_used_at_ms=None,
        revoked_at_ms=None,
    )
    return replace(base, **changes)


def agent(credential_id: str, label: str, **changes: Any) -> registry.Credential:
    members: dict[str, Any] = {
        "kind": "agent",
        "parent_credential_id": "crd_parent",
        "agent_label": label,
        "display_prefix": "acf1_agt_AbCd",
    }
    members.update(changes)
    return credential(credential_id, **members)


class Site:
    """A registry over an open store and journal, with two principals and two projects in it."""

    def __init__(self, store: Store, journal: j.SecurityJournal, journal_path: Path) -> None:
        self.store, self.journal, self.journal_path = store, journal, journal_path
        self.registry = registry.Registry(store, journal)

    async def populate(self) -> None:
        r = self.registry
        await r.create_principal(PRINCIPAL, "ada")
        await r.create_principal(OTHER_PRINCIPAL, "grace")
        await r.create_project(PROJECT, "first", SCOPE)
        await r.create_project(OTHER_PROJECT, "second", OTHER_SCOPE)
        await r.insert_credential(credential("crd_parent"))

    def journaled(self, record_type: str) -> list[dict[str, Any]]:
        return [record.data for record in j.read_records(self.journal_path) if record.type == record_type]


@pytest.fixture
async def site(deployment: Deployment) -> Site:
    made = Site(deployment.open(), deployment.journal(), deployment.journal_path)
    await made.populate()
    return made


async def test_a_project_is_pending_until_it_is_activated_and_its_scope_is_journaled_first(site: Site) -> None:
    project = await site.registry.project(PROJECT)
    assert project is not None
    assert (project.project_id, project.label, project.scope, project.state, project.share) == (
        PROJECT,
        "first",
        SCOPE,
        registry.PENDING,
        None,
    )
    assert site.journaled(j.SCOPE_ALLOCATED) == [
        {"project_id": PROJECT, "scope": SCOPE},
        {"project_id": OTHER_PROJECT, "scope": OTHER_SCOPE},
    ]
    assert [p.project_id for p in await site.registry.projects()] == [PROJECT, OTHER_PROJECT]
    assert await site.registry.project("prj_unknown") is None
    assert site.store.identity is not None
    assert await site.store.state(
        lambda conn: conn.execute("SELECT value FROM meta WHERE key = 'journal_applied'").fetchone()[0]
    ) == str(site.journal.last_seq)


@pytest.mark.proves("T3-PRJ-01", level="L1")
async def test_a_scope_string_is_never_issued_twice(site: Site) -> None:
    """Not to another project, not after its project was deleted, and not when only the journal remembers it."""
    r = site.registry
    with pytest.raises(registry.RegistryConflict):
        await r.create_project("prj_0000000000000003", "third", SCOPE)
    with pytest.raises(registry.RegistryConflict):
        await r.create_project(PROJECT, "first again", "scp-" + "3" * 32)
    await r.set_project_state(PROJECT, registry.ACTIVE)
    await r.set_project_state(PROJECT, registry.DELETING)
    await r.set_project_state(PROJECT, registry.DELETED)
    with pytest.raises(registry.RegistryConflict):
        await r.create_project("prj_0000000000000003", "third", SCOPE)
    # A scope the journal allocated and the registry never heard of: the write to the registry was lost.
    forgotten = "scp-" + "9" * 32
    site.journal.append(j.SCOPE_ALLOCATED, {"project_id": "prj_0000000000000009", "scope": forgotten})
    with pytest.raises(registry.RegistryConflict):
        await r.create_project("prj_0000000000000003", "third", forgotten)
    before = len(site.journaled(j.SCOPE_ALLOCATED))
    assert await r.project("prj_0000000000000003") is None
    assert len(site.journaled(j.SCOPE_ALLOCATED)) == before, "a refused allocation is not journaled"
    assert (await r.create_project("prj_0000000000000003", "third", "scp-" + "3" * 32)).state == registry.PENDING


@pytest.mark.proves("T3-PRJ-01", level="L1")
async def test_a_deleted_project_is_journaled_and_its_scope_retired_for_good(site: Site) -> None:
    r = site.registry
    for state in (registry.ACTIVE, registry.DELETING):
        await r.set_project_state(PROJECT, state)
        assert present(await r.project(PROJECT)).state == state
    assert site.journaled(j.PROJECT_DELETED) == []
    assert site.journaled(j.SCOPE_RETIRED) == []
    await r.set_project_state(PROJECT, registry.DELETED)
    assert present(await r.project(PROJECT)).state == registry.DELETED
    assert site.journaled(j.PROJECT_DELETED) == [{"project_id": PROJECT}]
    assert site.journaled(j.SCOPE_RETIRED) == [{"scope": SCOPE}]
    assert await site.store.state(
        lambda conn: [row["scope"] for row in conn.execute("SELECT scope FROM retired_scopes")]
    ) == [SCOPE]
    assert present(await r.project(OTHER_PROJECT)).state == registry.PENDING
    with pytest.raises(KeyError):
        await r.set_project_state("prj_unknown", registry.ACTIVE)


async def test_the_journal_is_written_before_the_registry(site: Site) -> None:
    """If the journal cannot take the record, the action does not take effect: nothing is revoked, allocated or deleted."""
    r = site.registry
    await r.insert_credential(agent("crd_agent", "worker"))
    await r.insert_binding(binding("bnd_1"))
    await r.set_project_state(PROJECT, registry.DELETING)
    site.journal.close()

    with pytest.raises(j.JournalError):
        await r.revoke_credential("crd_parent", NOW)
    assert present(await r.credential("crd_parent")).revoked_at_ms is None
    assert present(await r.credential("crd_agent")).revoked_at_ms is None
    with pytest.raises(j.JournalError):
        await r.create_project("prj_0000000000000003", "third", "scp-" + "3" * 32)
    assert await r.project("prj_0000000000000003") is None
    with pytest.raises(j.JournalError):
        await r.set_project_state(PROJECT, registry.DELETED)
    assert present(await r.project(PROJECT)).state == registry.DELETING
    with pytest.raises(j.JournalError):
        await r.revoke_binding("bnd_1", NOW)
    assert present(await r.binding("https://issuer.example", "subject-1")).revoked_at_ms is None

    # With the journal back, each of them is journaled and then takes effect.
    site.journal.open(DEPLOYMENT)
    assert sorted(await r.revoke_credential("crd_parent", NOW)) == ["crd_agent", "crd_parent"]
    await r.set_project_state(PROJECT, registry.DELETED)
    assert await r.revoke_binding("bnd_1", NOW) is True
    assert len(site.journaled(j.CREDENTIAL_REVOKED)) == 2
    assert len(site.journaled(j.PROJECT_DELETED)) == 1
    assert len(site.journaled(j.BINDING_REVOKED)) == 1


@pytest.mark.proves("T3-CRD-01", level="L1")
async def test_the_label_of_an_agent_credential_is_unique_among_the_live_ones_of_its_principal(site: Site) -> None:
    r = site.registry
    await r.insert_credential(agent("crd_agent_1", "worker"))
    with pytest.raises(registry.RegistryConflict, match="already carries this label"):
        await r.insert_credential(agent("crd_agent_2", "worker"))
    assert await r.credential("crd_agent_2") is None
    # Another label, another principal and another project are each another name.
    await r.insert_credential(agent("crd_agent_3", "Worker"))
    await r.insert_credential(agent("crd_agent_4", "worker-2"))
    await r.insert_credential(agent("crd_agent_5", "worker", principal_id=OTHER_PRINCIPAL))
    await r.insert_credential(agent("crd_agent_6", "worker", project_id=OTHER_PROJECT))
    # A developer credential has no label and is no party to the rule.
    await r.insert_credential(credential("crd_developer_2"))
    await r.insert_credential(credential("crd_developer_3"))
    assert len(await r.credentials(kind="agent")) == 5


@pytest.mark.proves("T3-CRD-01", level="L1")
async def test_a_label_is_free_again_once_its_credential_is_revoked_or_expired(site: Site) -> None:
    r = site.registry
    await r.insert_credential(agent("crd_agent_1", "worker", expires_at_ms=NOW + HOUR_MS))
    # One millisecond before the first expires it is still live, and the label is still taken.
    with pytest.raises(registry.RegistryConflict):
        await r.insert_credential(
            agent("crd_agent_early", "worker", issued_at_ms=NOW + HOUR_MS - 1, expires_at_ms=NOW + 2 * HOUR_MS)
        )
    # Expired by the time the next one is issued: no longer live, so the label is free.
    await r.insert_credential(
        agent("crd_agent_2", "worker", issued_at_ms=NOW + HOUR_MS, expires_at_ms=NOW + 2 * HOUR_MS)
    )
    with pytest.raises(registry.RegistryConflict):
        await r.insert_credential(
            agent("crd_agent_3", "worker", issued_at_ms=NOW + HOUR_MS + 1, expires_at_ms=NOW + 3 * HOUR_MS)
        )
    assert await r.revoke_credential("crd_agent_2", NOW + HOUR_MS + 5) == ["crd_agent_2"]
    await r.insert_credential(
        agent("crd_agent_5", "worker", issued_at_ms=NOW + HOUR_MS + 6, expires_at_ms=NOW + 3 * HOUR_MS)
    )
    live = [
        c.credential_id
        for c in await r.credentials(kind="agent")
        if c.live(NOW + HOUR_MS + 7) and c.agent_label == "worker"
    ]
    assert live == ["crd_agent_5"]


@pytest.mark.proves("T3-CRD-01", level="L1")
async def test_revoking_a_credential_revokes_the_agent_credentials_it_minted_and_is_idempotent(site: Site) -> None:
    r = site.registry
    await r.insert_credential(agent("crd_child_1", "one"))
    await r.insert_credential(agent("crd_child_2", "two"))
    await r.insert_credential(credential("crd_sibling"))
    await r.insert_credential(agent("crd_of_sibling", "three", parent_credential_id="crd_sibling"))

    assert sorted(await r.revoke_credential("crd_parent", NOW + 7)) == ["crd_child_1", "crd_child_2", "crd_parent"]
    for revoked in ("crd_parent", "crd_child_1", "crd_child_2"):
        stored = await r.credential(revoked)
        assert stored is not None
        assert stored.revoked_at_ms == NOW + 7
        assert stored.status(NOW + 8) == "REVOKED"
        assert stored.live(NOW + 8) is False
    for untouched in ("crd_sibling", "crd_of_sibling"):
        assert present(await r.credential(untouched)).revoked_at_ms is None
    assert sorted(record["credential_id"] for record in site.journaled(j.CREDENTIAL_REVOKED)) == [
        "crd_child_1",
        "crd_child_2",
        "crd_parent",
    ]

    # Revoking twice is revoking once: nothing more is journaled, and the time of the revocation stands.
    for _again in range(3):
        assert await r.revoke_credential("crd_parent", NOW + 999) == []
        assert await r.revoke_credential("crd_child_1", NOW + 999) == []
    assert len(site.journaled(j.CREDENTIAL_REVOKED)) == 3
    assert present(await r.credential("crd_parent")).revoked_at_ms == NOW + 7
    assert await r.revoke_credential("crd_unknown", NOW) == []
    # A child revoked alone leaves its parent and its siblings.
    assert await r.revoke_credential("crd_of_sibling", NOW + 9) == ["crd_of_sibling"]
    assert present(await r.credential("crd_sibling")).revoked_at_ms is None


async def test_a_credential_is_found_by_its_digest_and_says_whether_it_is_live(site: Site) -> None:
    r = site.registry
    found = await r.credential_by_digest("digest-of-crd_parent")
    assert found == credential("crd_parent")
    assert await r.credential_by_digest("digest-of-nobody") is None
    assert found is not None
    assert (found.status(NOW), found.live(NOW)) == ("ISSUED", True)
    await r.mark_first_use("crd_parent", NOW + 5)
    await r.mark_first_use("crd_parent", NOW + 50)
    used = await r.credential("crd_parent")
    assert used is not None
    assert used.first_used_at_ms == NOW + 5
    assert used.status(NOW + 6) == "ACTIVE"
    assert (used.status(NOW + DAY_MS), used.live(NOW + DAY_MS)) == ("EXPIRED", False)
    assert used.live(NOW + DAY_MS - 1) is True
    with pytest.raises(sqlite3.IntegrityError):
        await r.insert_credential(credential("crd_copy", key_digest="digest-of-crd_parent"))
    assert [c.credential_id for c in await r.credentials(project_id=PROJECT)] == ["crd_parent"]
    assert await r.credentials(parent="crd_parent") == []
    assert (await r.counts())["projects"] == 2
    assert (await r.counts())["principals"] == 2


@pytest.mark.proves("T3-AUTH-01", level="L1")
async def test_the_registry_holds_a_digest_and_a_prefix_of_a_key_and_never_the_key(
    deployment: Deployment, site: Site
) -> None:
    key = keys.generate_key("developer")
    random_part = key.split("_")[2]
    await site.registry.insert_credential(
        credential("crd_real", key_digest=keys.key_digest(key), display_prefix=keys.display_prefix(key))
    )
    columns = await site.store.state(
        lambda conn: [row["name"] for row in conn.execute("PRAGMA table_info(credentials)")]
    )
    assert set(columns) == {
        "credential_id", "key_digest", "display_prefix", "principal_id", "project_id", "kind", "parent_credential_id",
        "narrowing_json", "agent_label", "issued_at_ms", "expires_at_ms", "first_used_at_ms", "revoked_at_ms",
    }  # fmt: skip
    assert set(registry.Credential.__dataclass_fields__) == set(columns)
    await site.registry.revoke_credential("crd_real", NOW)
    site.store.close()
    site.journal.close()
    held = (
        b"".join(path.read_bytes() for path in sorted(deployment.dir.iterdir())) + deployment.journal_path.read_bytes()
    )
    assert keys.key_digest(key).encode() in held
    assert keys.display_prefix(key).encode() in held
    assert key.encode() not in held
    assert random_part.encode() not in held
    assert random_part[4:].encode() not in held


def binding(binding_id: str, **changes: Any) -> registry.Binding:
    base = registry.Binding(
        binding_id=binding_id,
        issuer="https://issuer.example",
        subject="subject-1",
        principal_id=PRINCIPAL,
        project_id=PROJECT,
        kind="agent",
        narrowing_json=None,
        agent_label="oauth-agent",
        created_at_ms=NOW,
        revoked_at_ms=None,
    )
    return replace(base, **changes)


async def test_a_subject_is_bound_once_and_a_revoked_binding_is_journaled(site: Site) -> None:
    r = site.registry
    await r.insert_binding(binding("bnd_1"))
    with pytest.raises(registry.RegistryConflict, match="already bound"):
        await r.insert_binding(binding("bnd_2"))
    await r.insert_binding(binding("bnd_3", subject="subject-2"))
    await r.insert_binding(binding("bnd_4", issuer="https://other.example"))
    assert await r.binding("https://issuer.example", "subject-1") == binding("bnd_1")
    assert await r.binding("https://issuer.example", "nobody") is None
    assert [b.binding_id for b in await r.bindings()] == ["bnd_1", "bnd_3", "bnd_4"]
    assert await r.revoke_binding("bnd_1", NOW + 3) is True
    assert await r.revoke_binding("bnd_1", NOW + 9) is False
    assert present(await r.binding("https://issuer.example", "subject-1")).revoked_at_ms == NOW + 3
    assert site.journaled(j.BINDING_REVOKED)[0] == {"binding_id": "bnd_1", "at_ms": NOW + 3}


async def test_a_role_is_the_grant_of_a_principal_in_a_project(site: Site) -> None:
    r = site.registry
    assert await r.role(PRINCIPAL, PROJECT) is None
    await r.set_role(PRINCIPAL, PROJECT, '{"methods":[]}', "pv_1")
    await r.set_role(PRINCIPAL, OTHER_PROJECT, '{"methods":["sandbox.get"]}', "pv_2")
    assert await r.role(PRINCIPAL, PROJECT) == registry.Role(PRINCIPAL, PROJECT, '{"methods":[]}', "pv_1")
    await r.set_role(PRINCIPAL, PROJECT, '{"methods":["sandbox.list"]}', "pv_3")
    assert await r.role(PRINCIPAL, PROJECT) == registry.Role(PRINCIPAL, PROJECT, '{"methods":["sandbox.list"]}', "pv_3")
    assert present(await r.role(PRINCIPAL, OTHER_PROJECT)).policy_version == "pv_2"
    assert await r.role(OTHER_PRINCIPAL, PROJECT) is None
    with pytest.raises(sqlite3.IntegrityError):
        await r.set_role("prn_unknown", PROJECT, "{}", "pv")
    await r.set_project_share(PROJECT, 0.25)
    assert present(await r.project(PROJECT)).share == 0.25
    assert [p.principal_id for p in await r.principals()] == [PRINCIPAL, OTHER_PRINCIPAL]
    assert present(await r.principal(PRINCIPAL)).label == "ada"


@pytest.mark.proves("T3-RED-33", level="L1")
@pytest.mark.proves("T3-RED-01", level="L1")
async def test_the_journal_is_applied_again_over_an_older_registry(deployment: Deployment, tmp_path: Path) -> None:
    """A restore of the store brings back a registry that knows less. The journal knows everything since."""
    store, journal = deployment.open(), deployment.journal()
    site = Site(store, journal, deployment.journal_path)
    await site.populate()
    r = site.registry
    await r.set_project_state(PROJECT, registry.ACTIVE)
    await r.insert_credential(agent("crd_agent", "worker"))
    await r.insert_binding(binding("bnd_1"))
    store.close()
    backup = tmp_path / "backup"
    shutil.copytree(deployment.dir, backup)

    # After the backup: a revocation with its cascade, a new project, a deleted project, a revoked binding.
    store = deployment.open()
    r = registry.Registry(store, journal)
    assert sorted(await r.revoke_credential("crd_parent", NOW + 100)) == ["crd_agent", "crd_parent"]
    later_scope = "scp-" + "7" * 32
    await r.create_project("prj_0000000000000007", "made after the backup", later_scope)
    await r.set_project_state(PROJECT, registry.DELETING)
    await r.set_project_state(PROJECT, registry.DELETED)
    assert await r.revoke_binding("bnd_1", NOW + 200) is True
    store.close()

    shutil.rmtree(deployment.dir)
    shutil.copytree(backup, deployment.dir)
    store = deployment.open()
    r = registry.Registry(store, journal)
    # What the restore revived, before the journal is applied.
    assert present(await r.credential("crd_parent")).revoked_at_ms is None
    assert present(await r.project(PROJECT)).state == registry.ACTIVE
    assert await r.project("prj_0000000000000007") is None

    report = await r.replay(j.fold(journal.records))
    assert report == {
        "revocations_reapplied": 2,
        "bindings_reapplied": 1,
        "deletions_reapplied": 1,
        "unknown_scopes": [later_scope],
    }
    for revoked in ("crd_parent", "crd_agent"):
        assert present(await r.credential(revoked)).revoked_at_ms == NOW + 100, (
            "the revocation is dated as the journal dates it"
        )
    assert present(await r.binding("https://issuer.example", "subject-1")).revoked_at_ms == NOW + 200
    assert present(await r.project(PROJECT)).state == registry.DELETED
    assert present(await r.project(OTHER_PROJECT)).state == registry.PENDING
    # Every scope the journal issued stays used: the retired one, and the one the registry no longer knows.
    for used in (SCOPE, later_scope, OTHER_SCOPE):
        with pytest.raises(registry.RegistryConflict):
            await r.create_project("prj_0000000000000008", "new", used)
    assert await store.state(
        lambda conn: sorted(row["scope"] for row in conn.execute("SELECT scope FROM retired_scopes"))
    ) == sorted([SCOPE, later_scope])
    assert await store.state(
        lambda conn: conn.execute("SELECT value FROM meta WHERE key = 'journal_applied'").fetchone()[0]
    ) == str(journal.last_seq)

    # Applying it again changes nothing, and the scope the registry does not know is still reported.
    again = await r.replay(j.fold(journal.records))
    assert again == {
        "revocations_reapplied": 0,
        "bindings_reapplied": 0,
        "deletions_reapplied": 0,
        "unknown_scopes": [later_scope],
    }
    # A registry that is up to date has nothing applied to it at all.
    assert (await r.replay(j.fold([])))["unknown_scopes"] == []


async def test_records_of_credentials_that_ended_long_ago_are_removed_and_live_ones_never(site: Site) -> None:
    r = site.registry
    await r.insert_credential(
        credential("crd_expired", expires_at_ms=NOW - 100 * DAY_MS, issued_at_ms=NOW - 200 * DAY_MS)
    )
    await r.insert_credential(
        credential("crd_revoked_long_ago", issued_at_ms=NOW - 200 * DAY_MS, expires_at_ms=NOW + DAY_MS)
    )
    await r.revoke_credential("crd_revoked_long_ago", NOW - 100 * DAY_MS)
    await r.insert_credential(credential("crd_revoked_recently"))
    await r.revoke_credential("crd_revoked_recently", NOW - DAY_MS)
    assert await r.purge_credentials(NOW - 90 * DAY_MS) == 2
    assert [c.credential_id for c in await r.credentials()] == ["crd_parent", "crd_revoked_recently"]
