"""The security journal: what a restore of the store must never undo.

An append-only file of JSON lines, kept where the store's backup and restore never overwrite it. It
holds scope allocations and retirements, project deletions, revocations, the deployment id, and the
peer id and host lineage the platform recorded. A record is durable here *before* the action it
describes takes effect, so the journal is never behind the store.

After any restore of the store, the journal is replayed before the core serves: every revocation is
applied again, every scope it allocated is marked used, every deleted project stays deleted.

Each line carries the SHA-256 of the line before it. A line that was changed, removed or reordered
breaks the chain at the line after it, and the core refuses to start on a broken chain. A record is
also accepted in the journal's own spelling only. The chain detects damage and careless edits; it is
not a defence against someone who can rewrite the whole file, and the file's ownership and mode are
what keep such a person out. Nor can a chain see what has nothing after it: the content of the last
record, and a file cut back to an earlier end.
"""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import hashlib
import json
import os
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

GENESIS: Final = "0" * 64

# Record types.
DEPLOYMENT: Final = "deployment"
SCOPE_ALLOCATED: Final = "scope_allocated"
SCOPE_RETIRED: Final = "scope_retired"
PROJECT_DELETED: Final = "project_deleted"
CREDENTIAL_REVOKED: Final = "credential_revoked"
BINDING_REVOKED: Final = "binding_revoked"
PEER_RECORDED: Final = "peer_recorded"
LINEAGE_PINNED: Final = "lineage_pinned"
LINEAGE_ACKNOWLEDGED: Final = "lineage_acknowledged"
PEER_ACKNOWLEDGED: Final = "peer_acknowledged"

KNOWN_TYPES: Final = frozenset(
    {
        DEPLOYMENT,
        SCOPE_ALLOCATED,
        SCOPE_RETIRED,
        PROJECT_DELETED,
        CREDENTIAL_REVOKED,
        BINDING_REVOKED,
        PEER_RECORDED,
        LINEAGE_PINNED,
        LINEAGE_ACKNOWLEDGED,
        PEER_ACKNOWLEDGED,
    }
)


class JournalError(Exception):
    """The journal cannot be used: missing, damaged, locked, or of another deployment."""


@dataclass(frozen=True, slots=True)
class Record:
    seq: int
    at: str
    type: str
    data: dict[str, Any]
    prev: str


def _line(record: Record) -> bytes:
    body = {"seq": record.seq, "at": record.at, "type": record.type, "data": record.data, "prev": record.prev}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"


def _digest(line: bytes) -> str:
    return hashlib.sha256(line.rstrip(b"\n")).hexdigest()


def _now() -> str:
    moment = datetime.now(UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read_records(path: Path) -> list[Record]:
    """Every record of the journal, with the chain verified. Raises on the first line that breaks it."""
    try:
        raw = path.read_bytes()
    except FileNotFoundError as e:
        raise JournalError(f"{path}: the security journal does not exist") from e
    except OSError as e:
        raise JournalError(f"{path}: cannot be read ({e.strerror})") from e
    records: list[Record] = []
    prev = GENESIS
    lines = raw.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    else:
        # The last append was cut short before its newline: the record never became durable, so the action
        # it described never took effect. Everything before it stands.
        lines = lines[:-1]
    for number, line in enumerate(lines, start=1):
        try:
            body = json.loads(line)
            record = Record(int(body["seq"]), str(body["at"]), str(body["type"]), dict(body["data"]), str(body["prev"]))
        except (ValueError, KeyError, TypeError) as e:
            raise JournalError(f"{path}: line {number} is not a journal record") from e
        if _line(record) != line + b"\n":
            # The same record in another spelling. The chain is computed over the bytes of a line and the
            # file is measured by them, so only the journal's own spelling of a record is a line of it.
            raise JournalError(f"{path}: line {number} is not written the way the journal writes a record")
        if record.seq != number or record.prev != prev:
            raise JournalError(f"{path}: the chain is broken at line {number}")
        prev = _digest(line)
        records.append(record)
    return records


def create_journal(path: Path, deployment_id: str) -> None:
    """Create the journal of a new deployment. Refuses a path that already exists."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    first = Record(1, _now(), DEPLOYMENT, {"deployment_id": deployment_id}, GENESIS)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | os.O_CLOEXEC, 0o600)
    except FileExistsError as e:
        raise JournalError(f"{path} already exists") from e
    try:
        os.write(fd, _line(first))
        os.fsync(fd)
    finally:
        os.close(fd)
    _fsync_dir(path.parent)


class SecurityJournal:
    """The open journal of one core. Appends are serialized and durable before they return."""

    def __init__(self, path: Path, mirror: Path | None = None) -> None:
        self._path = path
        self._mirror = mirror
        self._fd: int | None = None
        self._mutex = threading.Lock()
        self._seq = 0
        self._prev = GENESIS
        #: Bytes of the file that are whole records.
        self._size = 0
        #: Bytes of the copy on the operator's sink that are known to be the start of the journal.
        self._copied = 0
        self.records: list[Record] = []
        self.mirror_failures = 0

    def open(self, deployment_id: str) -> list[Record]:
        """Verify the chain, check the deployment, and take the journal for this process alone."""
        records = read_records(self._path)
        if not records or records[0].type != DEPLOYMENT:
            raise JournalError(f"{self._path}: does not start with a deployment record")
        if records[0].data.get("deployment_id") != deployment_id:
            raise JournalError(f"{self._path}: belongs to another deployment than the one the configuration names")
        fd = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            os.close(fd)
            raise JournalError(f"{self._path}: held by another core") from e
        self._fd = fd
        self.records = records
        self._seq = records[-1].seq
        self._prev = _digest(_line(records[-1]))
        # A torn last line, if there was one, is cut off so that the next append starts on a line boundary.
        durable = sum(len(_line(r)) for r in records)
        if os.fstat(fd).st_size != durable:
            os.ftruncate(fd, durable)
            os.fsync(fd)
        self._size = durable
        self._copy()
        return records

    def close(self) -> None:
        fd, self._fd = self._fd, None
        if fd is not None:
            with contextlib.suppress(OSError):
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    @property
    def last_seq(self) -> int:
        return self._seq

    def append(self, record_type: str, data: dict[str, Any]) -> Record:
        """Append one record. Returns only after it is durable in the journal."""
        if record_type not in KNOWN_TYPES:
            raise JournalError(f"unknown journal record type {record_type!r}")
        with self._mutex:
            if self._fd is None:
                raise JournalError("the security journal is not open")
            record = Record(self._seq + 1, _now(), record_type, data, self._prev)
            line = _line(record)
            try:
                os.write(self._fd, line)
                os.fsync(self._fd)
            except OSError as e:
                raise JournalError(f"{self._path}: append failed ({e.strerror})") from e
            self._seq = record.seq
            self._prev = _digest(line)
            self._size += len(line)
            self.records.append(record)
            self._copy()
            return record

    async def aappend(self, record_type: str, data: dict[str, Any]) -> Record:
        """:meth:`append` off the event loop: the write waits for the disk, and the loop must not."""
        return await asyncio.get_running_loop().run_in_executor(None, self.append, record_type, data)

    def _copy(self) -> None:
        """Bring the copy on the operator's sink up to the journal. A failure is counted; it undoes nothing.

        The copy is the journal from its first record on, so that it can be read as one. Whatever it
        lacks is written: the records of before it was configured, and those it missed while it could
        not be written. A file that holds more than the journal, or something else than its start, is
        not a copy of this journal: it is left alone, and counted.
        """
        mirror = self._mirror
        if mirror is None:
            return
        try:
            fd = os.open(mirror, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC, 0o600)
            try:
                have = os.fstat(fd).st_size
                if have > self._size or (have > self._copied and not self._starts_alike(mirror, have)):
                    self.mirror_failures += 1
                    return
                self._copied = have
                if have < self._size:
                    with self._path.open("rb") as source:
                        source.seek(have)
                        os.write(fd, source.read(self._size - have))
                    os.fsync(fd)
                    self._copied = self._size
            finally:
                os.close(fd)
        except OSError:
            self.mirror_failures += 1

    def _starts_alike(self, mirror: Path, length: int) -> bool:
        """Whether the first ``length`` bytes of the copy are the first ``length`` bytes of the journal."""
        with mirror.open("rb") as copy, self._path.open("rb") as source:
            return copy.read(length) == source.read(length)

    def of_type(self, *types: str) -> Iterator[Record]:
        wanted = set(types)
        return (r for r in self.records if r.type in wanted)


@dataclass(frozen=True, slots=True)
class JournalState:
    """What the journal says must be true of the registry, whatever the store was restored to."""

    #: scope -> project id, for every scope ever allocated.
    allocated: dict[str, str]
    retired_scopes: frozenset[str]
    deleted_projects: frozenset[str]
    #: credential id -> revocation time in milliseconds.
    revoked_credentials: dict[str, int]
    revoked_bindings: dict[str, int]
    peer_id: str | None
    lineage: str | None
    host_id: str | None


def fold(records: list[Record]) -> JournalState:
    """The state the journal describes, from its records in order."""
    allocated: dict[str, str] = {}
    retired: set[str] = set()
    deleted: set[str] = set()
    revoked: dict[str, int] = {}
    bindings: dict[str, int] = {}
    peer_id: str | None = None
    lineage: str | None = None
    host_id: str | None = None
    for r in records:
        d = r.data
        if r.type == SCOPE_ALLOCATED:
            allocated[str(d["scope"])] = str(d["project_id"])
        elif r.type == SCOPE_RETIRED:
            retired.add(str(d["scope"]))
        elif r.type == PROJECT_DELETED:
            deleted.add(str(d["project_id"]))
        elif r.type == CREDENTIAL_REVOKED:
            revoked.setdefault(str(d["credential_id"]), int(d["at_ms"]))
        elif r.type == BINDING_REVOKED:
            bindings.setdefault(str(d["binding_id"]), int(d["at_ms"]))
        elif r.type in {PEER_RECORDED, PEER_ACKNOWLEDGED}:
            peer_id = str(d["peer_id"])
        elif r.type in {LINEAGE_PINNED, LINEAGE_ACKNOWLEDGED}:
            lineage = str(d["lineage"])
            host_id = str(d.get("host_id", host_id or "")) or host_id
    return JournalState(allocated, frozenset(retired), frozenset(deleted), revoked, bindings, peer_id, lineage, host_id)
