"""The security journal: what a restore of the store must never undo.

Proves IPS-14 at the level of the file: the journal is append-only; it holds scope allocations and
retirements, project deletions, revocations, the deployment id, and the peer id and host lineage the
platform recorded; a record is in the file before :meth:`append` returns; a journal that does not
exist, belongs to another deployment or is held by another core is not opened; and the records are
copied to the sink the operator configured. It proves the journal's half of IPS-10: :func:`fold` gives
the state a restored registry is brought up to. No catalog entry names this module alone; T3-RED-33
and T3-RED-01 rest on it and are proven by the pipeline suite.

The chain is this implementation's protection of the file, not a clause of the contract. Each line
carries the digest of the line before it, so the tests show that a changed, removed, reordered or
duplicated line is detected wherever a later line vouches for it, and that a record in any spelling but
the journal's own is refused. What no chain can see is said here once: the content of the last record,
and a file cut back to an earlier end, have nothing after them to disagree. Only a comparison with what
the store has applied could tell, and that is outside this module.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from acf_api.core.store import journal as j
from acf_api.core.store.journal import GENESIS, JournalError, JournalState, Record, SecurityJournal, fold, read_records

DEPLOYMENT = "dep_7Q2M9K4T1V8X3B6N"
OTHER_DEPLOYMENT = "dep_0A0B0C0D0E0F0G0H"
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


class Journals:
    """Opens journals for a test and closes every one of them afterwards."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._open: list[SecurityJournal] = []

    def make(self, mirror: Path | None = None, path: Path | None = None) -> SecurityJournal:
        journal = SecurityJournal(path or self.path, mirror)
        self._open.append(journal)
        return journal

    def open(self, mirror: Path | None = None, deployment_id: str = DEPLOYMENT) -> SecurityJournal:
        journal = self.make(mirror)
        journal.open(deployment_id)
        return journal

    def close(self) -> None:
        for journal in self._open:
            journal.close()


@pytest.fixture
def journals(tmp_path: Path) -> Iterator[Journals]:
    made = Journals(tmp_path / "journal" / "security.journal")
    j.create_journal(made.path, DEPLOYMENT)
    try:
        yield made
    finally:
        made.close()


def lines_of(path: Path) -> list[bytes]:
    return path.read_bytes().splitlines(keepends=True)


def filled(journals: Journals, count: int = 5) -> list[bytes]:
    """A journal with ``count`` records after the first, closed again. Returns its lines."""
    journal = journals.open()
    for number in range(count):
        journal.append(
            j.CREDENTIAL_REVOKED, {"credential_id": f"crd_{number:016d}", "at_ms": 1_800_000_000_000 + number}
        )
    journal.close()
    return lines_of(journals.path)


def refused(journals: Journals) -> str:
    """The journal as it now is on disk is opened by nobody, and reading it says why."""
    before = journals.path.read_bytes()
    with pytest.raises(JournalError) as read:
        read_records(journals.path)
    with pytest.raises(JournalError):
        journals.open()
    assert journals.path.read_bytes() == before, "a journal that is refused is not touched"
    return str(read.value)


# ------------------------------------------------------------------------------- create, append, reopen
def test_a_new_journal_holds_the_deployment_id_and_is_private(journals: Journals) -> None:
    (line,) = lines_of(journals.path)
    record = json.loads(line)
    assert record["seq"] == 1
    assert record["type"] == j.DEPLOYMENT
    assert record["data"] == {"deployment_id": DEPLOYMENT}
    assert record["prev"] == GENESIS == "0" * 64
    assert TIMESTAMP.fullmatch(record["at"])
    assert set(record) == {"seq", "at", "type", "data", "prev"}
    assert stat.S_IMODE(journals.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(journals.path.parent.stat().st_mode) == 0o700
    assert read_records(journals.path) == [
        Record(1, record["at"], j.DEPLOYMENT, {"deployment_id": DEPLOYMENT}, GENESIS)
    ]


def test_a_journal_is_never_created_over_one_that_exists(journals: Journals) -> None:
    before = journals.path.read_bytes()
    for deployment in (DEPLOYMENT, OTHER_DEPLOYMENT):
        with pytest.raises(JournalError, match="already exists"):
            j.create_journal(journals.path, deployment)
    assert journals.path.read_bytes() == before


def test_a_record_is_in_the_file_when_append_returns(journals: Journals) -> None:
    journal = journals.open()
    assert journal.last_seq == 1
    previous = lines_of(journals.path)[-1]
    appended: list[tuple[str, dict[str, Any]]] = [
        (j.SCOPE_ALLOCATED, {"project_id": "prj_0000000000000001", "scope": "scp-" + "1" * 32}),
        (j.CREDENTIAL_REVOKED, {"credential_id": "crd_0000000000000001", "at_ms": 1_800_000_000_000}),
        (j.PROJECT_DELETED, {"project_id": "prj_0000000000000001"}),
    ]
    for number, (record_type, data) in enumerate(appended, start=2):
        record = journal.append(record_type, data)
        # Read by another reader, from the file: the record is there, whole, and vouches for the line before it.
        written = lines_of(journals.path)
        assert len(written) == number
        assert json.loads(written[-1]) == {
            "seq": number,
            "at": record.at,
            "type": record_type,
            "data": data,
            "prev": record.prev,
        }
        assert record.prev == hashlib.sha256(previous.rstrip(b"\n")).hexdigest()
        assert (record.seq, record.type, record.data) == (number, record_type, data)
        assert TIMESTAMP.fullmatch(record.at)
        assert journal.last_seq == number
        assert read_records(journals.path)[-1] == record
        previous = written[-1]
    assert journal.records == read_records(journals.path)


def test_a_reopened_journal_has_every_record_and_continues_the_chain(journals: Journals) -> None:
    filled(journals, 4)
    first = journals.open()
    assert [record.seq for record in first.records] == [1, 2, 3, 4, 5]
    assert first.last_seq == 5
    appended = first.append(j.SCOPE_RETIRED, {"scope": "scp-" + "2" * 32})
    first.close()

    second = journals.open()
    assert second.records[-1] == appended
    assert second.append(j.PEER_RECORDED, {"peer_id": "platform"}).seq == 7
    second.close()
    records = read_records(journals.path)
    assert [record.seq for record in records] == list(range(1, 8))
    assert [record.type for record in records][-2:] == [j.SCOPE_RETIRED, j.PEER_RECORDED]


def test_the_journal_is_only_ever_appended_to(journals: Journals) -> None:
    """Whatever is appended, every byte that was in the file stays where it was."""
    journal = journals.open()
    content = journals.path.read_bytes()
    for number in range(20):
        journal.append(j.BINDING_REVOKED, {"binding_id": f"bnd_{number}", "at_ms": number})
        grown = journals.path.read_bytes()
        assert grown.startswith(content)
        assert len(grown) > len(content)
        content = grown
    journal.close()
    journals.open().close()
    assert journals.path.read_bytes() == content, "opening a whole journal changes nothing"


def test_every_kind_of_record_the_contract_lists_can_be_written_and_nothing_else(journals: Journals) -> None:
    assert {
        "deployment",
        "scope_allocated",
        "scope_retired",
        "project_deleted",
        "credential_revoked",
        "binding_revoked",
        "peer_recorded",
        "lineage_pinned",
        "lineage_acknowledged",
        "peer_acknowledged",
    } == j.KNOWN_TYPES
    journal = journals.open()
    before = journals.path.read_bytes()
    for unknown in ("", "revocation", "CREDENTIAL_REVOKED", "credential_revoked ", "note"):
        with pytest.raises(JournalError, match="unknown journal record type"):
            journal.append(unknown, {})
    assert journals.path.read_bytes() == before
    assert journal.last_seq == 1


def test_a_journal_that_is_not_open_takes_no_record(journals: Journals) -> None:
    never_opened = journals.make()
    with pytest.raises(JournalError, match="not open"):
        never_opened.append(j.PEER_RECORDED, {"peer_id": "platform"})
    journal = journals.open()
    journal.close()
    with pytest.raises(JournalError, match="not open"):
        journal.append(j.PEER_RECORDED, {"peer_id": "platform"})
    journal.close()
    assert len(lines_of(journals.path)) == 1


def test_text_that_is_not_ascii_is_written_as_escapes_and_read_back(journals: Journals) -> None:
    journal = journals.open()
    data = {
        "project_id": "prj_0000000000000001",
        "scope": "scp-" + "3" * 32,
        "label": "caf\u00e9 \u4e2d\u6587 \U0001f600",
    }
    journal.append(j.SCOPE_ALLOCATED, data)
    journal.append(j.PEER_RECORDED, {"peer_id": "p"})
    journal.close()
    assert journals.path.read_bytes().isascii()
    reopened = journals.open()
    assert reopened.records[1].data == data
    assert reopened.append(j.PEER_RECORDED, {"peer_id": "q"}).seq == 4


def test_records_of_chosen_kinds_are_found_in_order(journals: Journals) -> None:
    journal = journals.open()
    journal.append(j.PEER_RECORDED, {"peer_id": "a"})
    journal.append(j.CREDENTIAL_REVOKED, {"credential_id": "crd_1", "at_ms": 1})
    journal.append(j.PEER_ACKNOWLEDGED, {"peer_id": "b"})
    assert [record.data["peer_id"] for record in journal.of_type(j.PEER_RECORDED, j.PEER_ACKNOWLEDGED)] == ["a", "b"]
    assert [record.seq for record in journal.of_type(j.DEPLOYMENT)] == [1]
    assert list(journal.of_type(j.SCOPE_RETIRED)) == []


async def test_an_append_from_the_event_loop_is_as_durable_as_any(journals: Journals) -> None:
    journal = journals.open()
    record = await journal.aappend(j.CREDENTIAL_REVOKED, {"credential_id": "crd_1", "at_ms": 5})
    assert record.seq == 2
    assert read_records(journals.path)[-1] == record
    with pytest.raises(JournalError):
        await journal.aappend("unknown", {})


def test_appends_from_many_threads_make_one_chain(journals: Journals) -> None:
    journal = journals.open()
    errors: list[BaseException] = []

    def work(worker: int) -> None:
        try:
            for number in range(25):
                journal.append(j.CREDENTIAL_REVOKED, {"credential_id": f"crd_{worker}_{number}", "at_ms": number})
        except BaseException as e:
            errors.append(e)

    threads = [threading.Thread(target=work, args=(worker,)) for worker in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    journal.close()
    records = read_records(journals.path)
    assert [record.seq for record in records] == list(range(1, 202))
    assert len({record.data["credential_id"] for record in records[1:]}) == 200


# ------------------------------------------------------------------------------- the chain
def test_the_lines_of_an_untouched_journal_vouch_for_each_other(journals: Journals) -> None:
    lines = filled(journals, 5)
    assert len(lines) == 6
    previous = GENESIS
    for number, line in enumerate(lines, start=1):
        record = json.loads(line)
        assert (record["seq"], record["prev"]) == (number, previous)
        previous = hashlib.sha256(line.rstrip(b"\n")).hexdigest()
    assert len(read_records(journals.path)) == 6


@pytest.mark.parametrize("index", range(5))
def test_a_changed_line_is_detected_by_the_line_after_it(journals: Journals, index: int) -> None:
    """Every record but the last has a line after it. One changed character in it breaks the chain there."""
    lines = filled(journals, 5)
    original = lines[index]
    for changed in (
        original.replace(b'"at_ms":1800000000', b'"at_ms":1800000001')
        if index
        else original.replace(DEPLOYMENT.encode(), OTHER_DEPLOYMENT.encode()),
        original.replace(b'"seq":', b'"seq": '),
        original.replace(b"credential_revoked", b"binding_revoked")
        if index
        else original.replace(b"deployment", b"Deployment", 1),
    ):
        assert changed != original
        journals.path.write_bytes(b"".join([*lines[:index], changed, *lines[index + 1 :]]))
        refused(journals)
    journals.path.write_bytes(b"".join(lines))
    assert len(read_records(journals.path)) == 6


@pytest.mark.parametrize("index", range(5))
def test_a_removed_line_is_detected(journals: Journals, index: int) -> None:
    lines = filled(journals, 5)
    journals.path.write_bytes(b"".join([*lines[:index], *lines[index + 1 :]]))
    refused(journals)


@pytest.mark.parametrize("index", range(5))
def test_reordered_lines_are_detected(journals: Journals, index: int) -> None:
    lines = filled(journals, 5)
    swapped = list(lines)
    swapped[index], swapped[index + 1] = swapped[index + 1], swapped[index]
    journals.path.write_bytes(b"".join(swapped))
    refused(journals)
    journals.path.write_bytes(b"".join(reversed(lines)))
    refused(journals)


@pytest.mark.parametrize("index", range(6))
def test_a_duplicated_line_is_detected(journals: Journals, index: int) -> None:
    lines = filled(journals, 5)
    journals.path.write_bytes(b"".join([*lines[: index + 1], lines[index], *lines[index + 1 :]]))
    refused(journals)
    # The same line at the very end: a replayed record is not a new one.
    journals.path.write_bytes(b"".join([*lines, lines[index]]))
    refused(journals)


def test_a_line_that_does_not_continue_the_chain_is_detected(journals: Journals) -> None:
    lines = filled(journals, 3)

    def forged(**members: Any) -> bytes:
        body = {
            "seq": 5,
            "at": "2026-11-19T10:00:00.000Z",
            "type": j.CREDENTIAL_REVOKED,
            "data": {"credential_id": "crd_x", "at_ms": 1},
            "prev": hashlib.sha256(lines[-1].rstrip(b"\n")).hexdigest(),
        }
        body.update(members)
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"

    journals.path.write_bytes(b"".join([*lines, forged()]))
    assert len(read_records(journals.path)) == 5, "the forged line is well formed when it continues the chain"
    for wrong in (
        forged(prev=GENESIS),
        forged(prev="f" * 64),
        forged(seq=4),
        forged(seq=6),
        forged(seq=1),
        forged(prev=hashlib.sha256(lines[-2].rstrip(b"\n")).hexdigest()),
    ):
        journals.path.write_bytes(b"".join([*lines, wrong]))
        assert "chain is broken at line 5" in refused(journals)


@pytest.mark.parametrize(
    "junk",
    [
        b"\n",
        b"not a record\n",
        b"{}\n",
        b"[]\n",
        b"null\n",
        b'{"seq":2}\n',
        b"\x00\n",
        b"\xff\xfe\n",
        b" \n",
        b'{"seq":2,"at":"x","type":"peer_recorded","data":[],"prev":""}\n',
    ],
)
def test_a_line_that_is_not_a_record_is_detected_wherever_it_stands(journals: Journals, junk: bytes) -> None:
    lines = filled(journals, 3)
    for position in range(len(lines) + 1):
        journals.path.write_bytes(b"".join([*lines[:position], junk, *lines[position:]]))
        refused(journals)


@pytest.mark.parametrize("index", range(4))
def test_a_record_in_another_spelling_is_not_a_record_of_the_journal(journals: Journals, index: int) -> None:
    """The same record written another way: spaces, another order of members, a number as text.

    For the last line no later line vouches, so this is the only check there is. Without it the core
    would take the line, measure the file by its own spelling of the record, and cut the file short.
    """
    lines = filled(journals, 3)
    record = json.loads(lines[index])
    for respelled in (
        json.dumps(record, sort_keys=True).encode("ascii") + b"\n",
        json.dumps(record, sort_keys=True, separators=(",", ":")).encode("ascii") + b" \n",
        b" " + lines[index],
        json.dumps(dict(reversed(list(record.items()))), separators=(",", ":")).encode("ascii") + b"\n",
        json.dumps({**record, "seq": str(record["seq"])}, sort_keys=True, separators=(",", ":")).encode("ascii")
        + b"\n",
        json.dumps({**record, "extra": 1}, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n",
        lines[index].replace(b"\n", b"\r\n"),
    ):
        assert respelled != lines[index]
        journals.path.write_bytes(b"".join([*lines[:index], respelled, *lines[index + 1 :]]))
        refused(journals)


# ------------------------------------------------------------------------------- a torn last line
def test_a_torn_last_line_is_dropped_wherever_it_was_cut(journals: Journals) -> None:
    """An append that was cut short never returned, so the action it described never took effect."""
    journal = journals.open()
    journal.append(j.CREDENTIAL_REVOKED, {"credential_id": "crd_kept", "at_ms": 1})
    journal.close()
    whole = journals.path.read_bytes()
    journal = journals.open()
    journal.append(j.CREDENTIAL_REVOKED, {"credential_id": "crd_torn", "at_ms": 2})
    journal.close()
    next_line = journals.path.read_bytes()[len(whole) :]
    assert next_line.endswith(b"\n")

    for cut in range(1, len(next_line)):
        journals.path.write_bytes(whole + next_line[:cut])
        assert [record.seq for record in read_records(journals.path)] == [1, 2]
        reopened = journals.open()
        assert [record.data.get("credential_id") for record in reopened.records] == [None, "crd_kept"]
        assert journals.path.read_bytes() == whole, "the torn bytes are cut off, and nothing else"
        reopened.close()


def test_a_journal_with_a_torn_line_stays_appendable(journals: Journals) -> None:
    lines = filled(journals, 2)
    journals.path.write_bytes(b"".join(lines) + b'{"at":"2026-11-19T10:00:00.000Z","data":{"credential_id":"crd_to')
    journal = journals.open()
    assert journal.last_seq == 3
    record = journal.append(j.CREDENTIAL_REVOKED, {"credential_id": "crd_after", "at_ms": 9})
    assert record.seq == 4
    journal.close()
    records = read_records(journals.path)
    assert [r.seq for r in records] == [1, 2, 3, 4]
    assert records[-1].data["credential_id"] == "crd_after"
    assert b"crd_to" not in journals.path.read_bytes()
    assert journals.path.read_bytes().endswith(b"\n")
    journals.open().close()


def test_a_journal_whose_first_record_never_became_durable_is_no_journal(journals: Journals) -> None:
    first = journals.path.read_bytes()
    for content in (b"", first[:-1], first[:10], b"\n"):
        journals.path.write_bytes(content)
        with pytest.raises(JournalError):
            journals.open()
        assert journals.path.read_bytes() == content, "a journal that is refused is not touched"
    for torn in (b"", first[:-1], first[:10]):
        journals.path.write_bytes(torn)
        assert read_records(journals.path) == []


def test_a_journal_that_does_not_start_with_its_deployment_is_refused(journals: Journals) -> None:
    lines = filled(journals, 2)
    body = json.loads(lines[1])
    body.update(seq=1, prev=GENESIS)
    journals.path.write_bytes(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n")
    assert len(read_records(journals.path)) == 1
    with pytest.raises(JournalError, match="does not start with a deployment record"):
        journals.open()


def test_a_journal_that_does_not_exist_is_not_opened(tmp_path: Path) -> None:
    """The core refuses to start when the store exists and the journal does not. Nothing creates one on the way."""
    missing = tmp_path / "journal" / "security.journal"
    with pytest.raises(JournalError, match="does not exist"):
        read_records(missing)
    with pytest.raises(JournalError, match="does not exist"):
        SecurityJournal(missing).open(DEPLOYMENT)
    assert not missing.exists()
    assert not missing.parent.exists()
    directory = tmp_path / "a-directory"
    directory.mkdir()
    with pytest.raises(JournalError):
        SecurityJournal(directory).open(DEPLOYMENT)


# ------------------------------------------------------------------------------- one deployment, one core
def test_the_journal_of_another_deployment_is_refused(journals: Journals) -> None:
    filled(journals, 2)
    before = journals.path.read_bytes()
    with pytest.raises(JournalError, match="another deployment"):
        journals.open(deployment_id=OTHER_DEPLOYMENT)
    with pytest.raises(JournalError, match="another deployment"):
        journals.open(deployment_id="")
    assert journals.path.read_bytes() == before
    # The refusal held nothing back: the deployment the journal belongs to still opens it.
    assert journals.open().last_seq == 3


def test_a_second_opener_is_refused_while_the_first_holds_the_journal(journals: Journals) -> None:
    first = journals.open()
    second = journals.make()
    with pytest.raises(JournalError, match="held by another core"):
        second.open(DEPLOYMENT)
    with pytest.raises(JournalError, match="not open"):
        second.append(j.PEER_RECORDED, {"peer_id": "intruder"})
    assert first.append(j.PEER_RECORDED, {"peer_id": "platform"}).seq == 2

    first.close()
    second.open(DEPLOYMENT)
    assert second.last_seq == 2
    third = journals.make()
    with pytest.raises(JournalError, match="held by another core"):
        third.open(DEPLOYMENT)
    assert second.append(j.PEER_ACKNOWLEDGED, {"peer_id": "platform"}).seq == 3


def test_closing_twice_is_harmless(journals: Journals) -> None:
    journal = journals.open()
    journal.close()
    journal.close()
    journals.open().close()


# ------------------------------------------------------------------------------- what the journal says must be true
def rec(seq: int, record_type: str, **data: Any) -> Record:
    return Record(seq, "2026-11-19T10:00:00.000Z", record_type, data, "0" * 64)


def test_an_empty_journal_says_nothing() -> None:
    assert fold([]) == JournalState({}, frozenset(), frozenset(), {}, {}, None, None, None)
    assert fold([rec(1, j.DEPLOYMENT, deployment_id=DEPLOYMENT)]) == fold([])


def test_the_state_the_journal_describes() -> None:
    state = fold(
        [
            rec(1, j.DEPLOYMENT, deployment_id=DEPLOYMENT),
            rec(2, j.PEER_RECORDED, peer_id="platform-a"),
            rec(3, j.LINEAGE_PINNED, lineage="lineage-1", host_id="host-1"),
            rec(4, j.SCOPE_ALLOCATED, project_id="prj_1", scope="scp-1"),
            rec(5, j.SCOPE_ALLOCATED, project_id="prj_2", scope="scp-2"),
            rec(6, j.SCOPE_ALLOCATED, project_id="prj_3", scope="scp-3"),
            rec(7, j.CREDENTIAL_REVOKED, credential_id="crd_1", at_ms=100),
            rec(8, j.CREDENTIAL_REVOKED, credential_id="crd_2", at_ms=200),
            rec(9, j.BINDING_REVOKED, binding_id="bnd_1", at_ms=300),
            rec(10, j.PROJECT_DELETED, project_id="prj_2"),
            rec(11, j.SCOPE_RETIRED, scope="scp-2"),
            rec(12, j.LINEAGE_ACKNOWLEDGED, lineage="lineage-2"),
            rec(13, j.PEER_ACKNOWLEDGED, peer_id="platform-b"),
        ]
    )
    assert state == JournalState(
        allocated={"scp-1": "prj_1", "scp-2": "prj_2", "scp-3": "prj_3"},
        retired_scopes=frozenset({"scp-2"}),
        deleted_projects=frozenset({"prj_2"}),
        revoked_credentials={"crd_1": 100, "crd_2": 200},
        revoked_bindings={"bnd_1": 300},
        peer_id="platform-b",
        lineage="lineage-2",
        host_id="host-1",
    )


def test_a_revocation_is_dated_by_its_first_record_and_is_never_taken_back() -> None:
    state = fold(
        [
            rec(1, j.CREDENTIAL_REVOKED, credential_id="crd_1", at_ms=100),
            rec(2, j.CREDENTIAL_REVOKED, credential_id="crd_1", at_ms=900),
            rec(3, j.BINDING_REVOKED, binding_id="bnd_1", at_ms=5),
            rec(4, j.BINDING_REVOKED, binding_id="bnd_1", at_ms=1),
        ]
    )
    assert state.revoked_credentials == {"crd_1": 100}
    assert state.revoked_bindings == {"bnd_1": 5}
    # No kind of record un-revokes, un-retires or un-deletes: the journal has no word for it.
    assert not {
        kind
        for kind in j.KNOWN_TYPES
        if any(word in kind for word in ("restore", "reinstate", "undo", "unrevoke", "revive"))
    }


def test_a_scope_stays_allocated_after_it_is_retired() -> None:
    """Retiring does not free a scope string. It was issued, so it is never issued again."""
    state = fold(
        [
            rec(1, j.SCOPE_ALLOCATED, project_id="prj_1", scope="scp-1"),
            rec(2, j.PROJECT_DELETED, project_id="prj_1"),
            rec(3, j.SCOPE_RETIRED, scope="scp-1"),
        ]
    )
    assert state.allocated == {"scp-1": "prj_1"}
    assert state.retired_scopes == {"scp-1"}
    assert state.deleted_projects == {"prj_1"}


def test_the_last_recorded_peer_and_lineage_are_the_pinned_ones() -> None:
    pinned = fold([rec(1, j.PEER_RECORDED, peer_id="a"), rec(2, j.LINEAGE_PINNED, lineage="l1", host_id="h1")])
    assert (pinned.peer_id, pinned.lineage, pinned.host_id) == ("a", "l1", "h1")
    acknowledged = fold(
        [
            rec(1, j.PEER_RECORDED, peer_id="a"),
            rec(2, j.LINEAGE_PINNED, lineage="l1", host_id="h1"),
            rec(3, j.LINEAGE_ACKNOWLEDGED, lineage="l2"),
            rec(4, j.LINEAGE_ACKNOWLEDGED, lineage="l3", host_id="h2"),
            rec(5, j.PEER_ACKNOWLEDGED, peer_id="b"),
            rec(6, j.PEER_ACKNOWLEDGED, peer_id="c"),
        ]
    )
    assert (acknowledged.peer_id, acknowledged.lineage, acknowledged.host_id) == ("c", "l3", "h2")
    without_host = fold([rec(1, j.LINEAGE_PINNED, lineage="l1")])
    assert (without_host.lineage, without_host.host_id) == ("l1", None)
    kept = fold([rec(1, j.LINEAGE_PINNED, lineage="l1", host_id="h1"), rec(2, j.LINEAGE_ACKNOWLEDGED, lineage="l2")])
    assert (kept.lineage, kept.host_id) == ("l2", "h1")


def test_the_state_is_the_same_whether_folded_from_memory_or_from_the_file(journals: Journals) -> None:
    journal = journals.open()
    journal.append(j.PEER_RECORDED, {"peer_id": "platform"})
    journal.append(j.LINEAGE_PINNED, {"lineage": "l1", "host_id": "host-model"})
    journal.append(j.SCOPE_ALLOCATED, {"project_id": "prj_1", "scope": "scp-" + "a" * 32})
    journal.append(j.CREDENTIAL_REVOKED, {"credential_id": "crd_1", "at_ms": 42})
    journal.append(j.PROJECT_DELETED, {"project_id": "prj_1"})
    journal.append(j.SCOPE_RETIRED, {"scope": "scp-" + "a" * 32})
    in_memory = fold(journal.records)
    journal.close()
    assert fold(read_records(journals.path)) == in_memory
    assert fold(journals.open().records) == in_memory
    assert in_memory.revoked_credentials == {"crd_1": 42}
    assert in_memory.retired_scopes == {"scp-" + "a" * 32}


# ------------------------------------------------------------------------------- the copy on the operator's sink
def test_the_mirror_holds_every_record_of_the_journal(journals: Journals, tmp_path: Path) -> None:
    """The copy is a journal too: the deployment record and everything after it, byte for byte."""
    mirror = tmp_path / "sink" / "security.journal.copy"
    mirror.parent.mkdir()
    journal = journals.open(mirror)
    for number in range(5):
        journal.append(j.CREDENTIAL_REVOKED, {"credential_id": f"crd_{number}", "at_ms": number})
        assert mirror.read_bytes() == journals.path.read_bytes()
    assert journal.mirror_failures == 0
    assert read_records(mirror) == journal.records
    assert stat.S_IMODE(mirror.stat().st_mode) == 0o600


def test_a_mirror_that_was_configured_later_is_brought_up_to_the_journal(journals: Journals, tmp_path: Path) -> None:
    filled(journals, 3)
    mirror = tmp_path / "late.copy"
    journal = journals.open(mirror)
    assert mirror.read_bytes() == journals.path.read_bytes(), "the copy is whole before the first new record"
    journal.append(j.PEER_RECORDED, {"peer_id": "platform"})
    assert mirror.read_bytes() == journals.path.read_bytes()
    assert journal.mirror_failures == 0
    assert read_records(mirror) == journal.records


def test_a_failing_mirror_is_counted_and_undoes_nothing(journals: Journals, tmp_path: Path) -> None:
    mirror = tmp_path / "missing-directory" / "security.journal.copy"
    journal = journals.open(mirror)
    assert journal.mirror_failures == 1, "the copy could not be brought up to the journal at the start"
    first = journal.append(j.CREDENTIAL_REVOKED, {"credential_id": "crd_1", "at_ms": 1})
    second = journal.append(j.CREDENTIAL_REVOKED, {"credential_id": "crd_2", "at_ms": 2})
    assert journal.mirror_failures == 3
    assert not mirror.exists()
    # Both records are durable in the journal: the action each describes may take effect.
    assert (first.seq, second.seq) == (2, 3)
    assert read_records(journals.path)[1:] == [first, second]
    assert journal.records[1:] == [first, second]

    # The sink comes back: it receives what it missed, and the count stays what it was.
    mirror.parent.mkdir()
    third = journal.append(j.CREDENTIAL_REVOKED, {"credential_id": "crd_3", "at_ms": 3})
    assert journal.mirror_failures == 3
    assert mirror.read_bytes() == journals.path.read_bytes()
    assert read_records(mirror)[-1] == third


def test_a_mirror_that_cannot_be_written_never_stops_an_append(journals: Journals, tmp_path: Path) -> None:
    a_directory = tmp_path / "copy-is-a-directory"
    a_directory.mkdir()
    journal = journals.open(a_directory)
    for number in range(3):
        assert journal.append(j.BINDING_REVOKED, {"binding_id": f"bnd_{number}", "at_ms": number}).seq == number + 2
    assert journal.mirror_failures == 4, "once at the start and once for each record"
    assert len(read_records(journals.path)) == 4


def test_a_copy_that_is_ahead_of_the_journal_is_not_written_and_is_counted(journals: Journals, tmp_path: Path) -> None:
    """A copy with more in it than the journal is not a copy of this journal. Nothing is appended to it."""
    lines = filled(journals, 3)
    mirror = tmp_path / "ahead.copy"
    mirror.write_bytes(b"".join(lines) + b"something the journal does not hold\n")
    ahead = mirror.read_bytes()
    journal = journals.open(mirror)
    assert journal.mirror_failures == 1
    journal.append(j.PEER_RECORDED, {"peer_id": "platform"})
    assert journal.mirror_failures == 2
    assert mirror.read_bytes() == ahead
    assert len(read_records(journals.path)) == 5


def test_a_file_that_is_not_the_start_of_the_journal_is_never_appended_to(journals: Journals, tmp_path: Path) -> None:
    """The sink already holds something else under that name: the journal of another deployment, or a note."""
    filled(journals, 3)
    for other in (
        b"x\n",
        b"not this journal\n" * 3,
        journals.path.read_bytes().replace(DEPLOYMENT.encode(), OTHER_DEPLOYMENT.encode())[:200],
    ):
        mirror = tmp_path / "other.copy"
        mirror.write_bytes(other)
        journal = journals.open(mirror)
        assert journal.mirror_failures == 1
        journal.append(j.PEER_RECORDED, {"peer_id": "platform"})
        assert journal.mirror_failures == 2
        assert mirror.read_bytes() == other
        journal.close()
    assert len(read_records(journals.path)) == 7


def test_a_mirror_that_is_the_journal_itself_does_no_damage(journals: Journals) -> None:
    """A copy configured onto the journal's own path must not write every record twice."""
    journal = journals.open(journals.path)
    for number in range(3):
        journal.append(j.CREDENTIAL_REVOKED, {"credential_id": f"crd_{number}", "at_ms": number})
    journal.close()
    assert [r.seq for r in read_records(journals.path)] == [1, 2, 3, 4]
    journals.open().close()


def test_a_journal_without_a_mirror_counts_no_failure(journals: Journals) -> None:
    journal = journals.open()
    journal.append(j.PEER_RECORDED, {"peer_id": "platform"})
    assert journal.mirror_failures == 0
    assert sorted(path.name for path in journals.path.parent.iterdir()) == ["security.journal"]


def test_the_journal_file_keeps_its_owner_only_mode_across_appends(journals: Journals) -> None:
    journal = journals.open()
    journal.append(j.PEER_RECORDED, {"peer_id": "platform"})
    journal.close()
    assert stat.S_IMODE(journals.path.stat().st_mode) == 0o600
    assert journals.path.stat().st_uid == os.geteuid()
