"""What the core checks before it serves anything, and what makes it refuse to start.

The core alone holds the host peer credential, the fingerprint key, the store and the security
journal. Before it opens any of them it checks that the two secrets are trusted inputs, and that no
configured edge identity could read a secret or open the store. If a check fails the core does not
start, and it has opened nothing.

These tests run as one operating-system user, so "another identity could read this" is constructed
from ownership and mode bits with identities that are not the test's own: that is exactly what the
core's check reads. What cannot be shown here is an edge process of another user actually failing to
open the files; that is for a deployment with two accounts.

The deployment lives in a private directory under no directory anyone else can write. In a temporary
directory every case below would be refused for the directory alone, and would prove nothing.

Proves SEC-112, SEC-122, EC-2 and IPS-14, and the catalog entries T3-SEC-09 and T3-EC-01 (the part
about the files of a deployment).
"""

from __future__ import annotations

import contextlib
import os
import pwd
import shutil
import sqlite3
import stat
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from acf_api.core import app
from acf_api.core import config as cfg
from acf_api.core.store import journal as j
from tests.support.deploy import private_dir, write_platform_identity
from tests.support.harness import DEPLOYMENT, FakeClock, config_dict, create_deployment
from tests.support.model_host import ModelHost


def _an_identity_without_an_account() -> int:
    """A user id that is neither this process, nor root, nor an account of this machine."""
    for uid in range(61_000, 65_000):
        try:
            pwd.getpwuid(uid)
        except KeyError:
            if uid != os.geteuid():
                return uid
    raise AssertionError("every user id of the range has an account")


EDGE_UID = _an_identity_without_an_account()


@pytest.fixture(scope="module")
def deployment() -> Iterator[Path]:
    """One deployment for the module. Every test leaves its files as it found them."""
    with private_dir("u") as root:
        # Made where the disk is memory, then copied: a store holds no path, so it can be moved.
        scratch = Path(tempfile.mkdtemp(prefix="acf-"))
        try:
            create_deployment(scratch)
            shutil.copytree(scratch, root, dirs_exist_ok=True)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
        write_platform_identity(root)
        # The two secrets in directories of their own, so that each one's directory can be judged alone.
        (root / "keys").mkdir(mode=0o700)
        (root / "secrets" / "fingerprint.key").rename(root / "keys" / "fingerprint.key")
        yield root


def document(root: Path, **changes: Any) -> dict[str, Any]:
    """A configuration as a deployment has it: an edge identity of its own, and no shared identity allowed."""
    data = config_dict(root)
    data["paths"]["fingerprint_key"] = str(root / "keys" / "fingerprint.key")
    data["edge"] = {"uids": [EDGE_UID]}
    data["security"] = {"allow_shared_identity": False}
    data.update(changes)
    return data


async def start(data: dict[str, Any]) -> app.Core:
    """Assemble a core with every startup check on, over the model host."""
    return await app.build_core(cfg.parse_config(data), binding=ModelHost(), clock=FakeClock())


def writer_epoch(root: Path) -> int:
    """How many times a core has opened the store. A refused start must not have."""
    with contextlib.closing(sqlite3.connect(f"file:{root / 'store' / 'state.db'}?mode=ro", uri=True)) as conn:
        return int(conn.execute("SELECT value FROM meta WHERE key = 'writer_epoch'").fetchone()[0])


@contextlib.contextmanager
def mode(path: Path, bits: int) -> Iterator[None]:
    before = stat.S_IMODE(path.stat().st_mode)
    path.chmod(bits)
    try:
        yield
    finally:
        path.chmod(before)


@contextlib.contextmanager
def a_symbolic_link(path: Path) -> Iterator[None]:
    """Put a symbolic link where the file was, pointing at the file itself."""
    real = path.with_name(path.name + ".real")
    path.rename(real)
    path.symlink_to(real)
    try:
        yield
    finally:
        path.unlink()
        real.rename(path)


@contextlib.contextmanager
def a_directory(path: Path) -> Iterator[None]:
    real = path.with_name(path.name + ".real")
    path.rename(real)
    path.mkdir(mode=0o700)
    try:
        yield
    finally:
        path.rmdir()
        real.rename(path)


@contextlib.contextmanager
def absent(path: Path) -> Iterator[None]:
    real = path.with_name(path.name + ".real")
    path.rename(real)
    try:
        yield
    finally:
        real.rename(path)


def secret(root: Path, name: str) -> Path:
    return {
        "host-private-key": root / "secrets" / "platform.key",
        "fingerprint-key": root / "keys" / "fingerprint.key",
    }[name]


SECRETS = ["host-private-key", "fingerprint-key"]


# =============================================================================== a deployment that starts
async def test_a_deployment_as_init_leaves_it_starts_and_keeps_its_edge_apart(deployment: Path) -> None:
    """The control of every refusal below: with nothing changed, the same configuration starts."""
    before = writer_epoch(deployment)
    core = await start(document(deployment))
    try:
        health = await core.admin.run("health", {})
        assert (health["serving"], health["edge_shares_core_identity"]) == (True, False)
        assert core.telemetry.get("operator_diagnostics", kind="edge_shares_core_identity") == 0
    finally:
        await core.close()
    assert writer_epoch(deployment) == before + 1


@pytest.mark.proves("T3-EC-01", level="L3")
def test_nothing_a_new_deployment_holds_is_open_to_anyone_but_its_owner(deployment: Path) -> None:
    """EC-2, SEC-112, T3-EC-01: the store, the journal and the two secrets carry no permission for group or others."""
    closed = [
        deployment / "store",
        *(deployment / "store").iterdir(),
        deployment / "journal",
        deployment / "journal" / "security.journal",
        deployment / "keys" / "fingerprint.key",
        deployment / "secrets" / "platform.key",
    ]
    assert len(closed) >= 7
    for path in closed:
        assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0, path
        assert path.stat().st_uid == os.geteuid()
    assert cfg.check_separation(cfg.parse_config(document(deployment))) == []


def test_the_host_credential_is_never_copied_into_the_store(deployment: Path) -> None:
    """SEC-112, SEC-113: the store holds key digests and nothing of the host peer credential."""
    key_lines = (deployment / "secrets" / "platform.key").read_text(encoding="ascii").splitlines()[1:-1]
    fingerprint = (deployment / "keys" / "fingerprint.key").read_text(encoding="ascii").strip()
    assert key_lines
    assert len(fingerprint) == 64
    stored = b"".join(path.read_bytes() for path in (deployment / "store").iterdir() if path.is_file())
    stored += (deployment / "journal" / "security.journal").read_bytes()
    assert stored
    for needle in (*key_lines, fingerprint):
        assert needle.encode("ascii") not in stored


# =============================================================================== trusted inputs
@pytest.mark.parametrize("bits", [0o640, 0o604, 0o644, 0o660, 0o602, 0o610, 0o601], ids=oct)
@pytest.mark.parametrize("name", SECRETS)
@pytest.mark.proves("T3-SEC-09")
async def test_a_secret_that_anyone_else_may_read_or_write_refuses_the_start(
    deployment: Path, name: str, bits: int
) -> None:
    """SEC-112, T3-SEC-09: the host private key and the fingerprint key are readable by the core's identity alone."""
    path, before = secret(deployment, name), writer_epoch(deployment)
    with mode(path, bits), pytest.raises(app.StartupError, match="not a trusted input") as refused:
        await start(document(deployment))
    assert str(path) in str(refused.value)
    assert "its group or by others" in str(refused.value)
    assert writer_epoch(deployment) == before, "the core opened the store before it refused"


@pytest.mark.parametrize("name", SECRETS)
@pytest.mark.proves("T3-SEC-09")
async def test_a_secret_that_is_a_symbolic_link_refuses_the_start(deployment: Path, name: str) -> None:
    """A link can be pointed elsewhere by whoever owns its directory entry: the secret must be the file itself."""
    path, before = secret(deployment, name), writer_epoch(deployment)
    with a_symbolic_link(path), pytest.raises(app.StartupError, match="is a symbolic link") as refused:
        await start(document(deployment))
    assert str(path) in str(refused.value)
    assert writer_epoch(deployment) == before


@pytest.mark.parametrize("name", SECRETS)
@pytest.mark.proves("T3-SEC-09")
async def test_a_secret_that_is_missing_or_is_not_a_file_refuses_the_start(deployment: Path, name: str) -> None:
    path = secret(deployment, name)
    with a_directory(path), pytest.raises(app.StartupError, match="is not a regular file"):
        await start(document(deployment))
    with absent(path), pytest.raises(app.StartupError, match="not a trusted input") as refused:
        await start(document(deployment))
    assert str(path) in str(refused.value)


@pytest.mark.parametrize("bits", [0o770, 0o707, 0o777, 0o1777, 0o720, 0o702], ids=oct)
@pytest.mark.parametrize("name", SECRETS)
@pytest.mark.proves("T3-SEC-09")
async def test_a_secret_in_a_directory_that_others_can_write_refuses_the_start(
    deployment: Path, name: str, bits: int
) -> None:
    """Whoever can write the directory can replace the file, so the rule holds for every directory above it."""
    path, before = secret(deployment, name), writer_epoch(deployment)
    with mode(path.parent, bits), pytest.raises(app.StartupError, match="not a trusted input") as refused:
        await start(document(deployment))
    assert f"{path.parent}: writable by its group or by others" in str(refused.value)
    assert writer_epoch(deployment) == before


@pytest.mark.proves("T3-SEC-09")
async def test_a_directory_further_up_that_others_can_write_refuses_the_start_too(deployment: Path) -> None:
    with mode(deployment, 0o777), pytest.raises(app.StartupError, match="not a trusted input") as refused:
        await start(document(deployment))
    assert f"{deployment}: writable by its group or by others" in str(refused.value)


async def test_a_temporary_directory_is_not_a_place_for_the_secrets(tmp_path: Path) -> None:
    """The reason this module does not use one: everything beneath a world-writable directory is refused."""
    create_deployment(tmp_path)
    write_platform_identity(tmp_path)
    data = config_dict(tmp_path)
    data["edge"], data["security"] = {"uids": [EDGE_UID]}, {"allow_shared_identity": False}
    with pytest.raises(app.StartupError, match="writable by its group or by others"):
        await start(data)


@pytest.mark.parametrize("name", ["ca.crt", "platform.crt"])
async def test_what_decides_whom_the_core_believes_may_be_read_by_all_and_written_by_none(
    deployment: Path, name: str
) -> None:
    """SEC-125 rests on it: whoever can write the trust anchors chooses which host the platform talks to."""
    path = deployment / "secrets" / name
    assert stat.S_IMODE(path.stat().st_mode) == 0o644, "readable by all is fine: it is not a secret"
    for bits in (0o664, 0o646):
        with mode(path, bits), pytest.raises(app.StartupError, match="writable by its group or by others") as refused:
            await start(document(deployment))
        assert str(path) in str(refused.value)
    with a_symbolic_link(path), pytest.raises(app.StartupError, match="is a symbolic link"):
        await start(document(deployment))


async def test_a_host_credential_that_cannot_be_used_refuses_the_start_and_releases_the_store(deployment: Path) -> None:
    """A key that is a trusted input and no key: refused without its content, and with nothing left locked."""
    path = deployment / "secrets" / "platform.key"
    original = path.read_bytes()
    path.write_bytes(b"-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5IGF0IGFsbA==\n-----END PRIVATE KEY-----\n")
    try:
        with pytest.raises(app.StartupError, match="the host credential cannot be used") as refused:
            await app.build_core(cfg.parse_config(document(deployment)), clock=FakeClock())
        assert "bm90IGEga2V5" not in str(refused.value)
    finally:
        path.write_bytes(original)
        path.chmod(0o600)
    core = await start(document(deployment))
    await core.close()


# =============================================================================== the journal
async def test_a_store_without_its_journal_is_never_served(deployment: Path) -> None:
    """IPS-14: the core refuses to start when the store exists and the journal does not."""
    before = writer_epoch(deployment)
    with absent(deployment / "journal" / "security.journal"), pytest.raises(app.StartupError, match="does not exist"):
        await start(document(deployment))
    assert writer_epoch(deployment) == before, "the store was opened without its journal"


def _journal_with_records(root: Path, count: int) -> Path:
    """A journal of this deployment, on a path of its own, with ``count`` records after the first."""
    path = root / "tampered" / "security.journal"
    shutil.rmtree(path.parent, ignore_errors=True)
    j.create_journal(path, DEPLOYMENT)
    journal = j.SecurityJournal(path)
    journal.open(DEPLOYMENT)
    try:
        for number in range(count):
            journal.append(
                j.CREDENTIAL_REVOKED, {"credential_id": f"crd_{number:020d}", "at_ms": 1_800_000_000_000 + number}
            )
    finally:
        journal.close()
    return path


def _lines(path: Path) -> list[bytes]:
    return path.read_bytes().splitlines(keepends=True)


@pytest.mark.parametrize(
    "damage",
    [
        "a-record-changed",
        "a-record-removed",
        "two-records-swapped",
        "a-line-that-is-no-record",
        "the-first-record-removed",
    ],
)
async def test_a_journal_whose_chain_is_broken_refuses_the_start(deployment: Path, damage: str) -> None:
    """Each record carries the digest of the one before it: a changed, removed or reordered record is found."""
    path = _journal_with_records(deployment, 3)
    lines = _lines(path)
    assert len(lines) == 4
    if damage == "a-record-changed":
        lines[1] = lines[1].replace(b"crd_00000000000000000000", b"crd_99999999999999999999")
    elif damage == "a-record-removed":
        del lines[2]
    elif damage == "two-records-swapped":
        lines[1], lines[2] = lines[2], lines[1]
    elif damage == "a-line-that-is-no-record":
        lines[2] = b'{"not":"a record"}\n'
    else:
        del lines[0]
    path.write_bytes(b"".join(lines))

    data, before = document(deployment), writer_epoch(deployment)
    data["paths"]["journal"] = str(path)
    with pytest.raises(
        app.StartupError, match=r"chain is broken|is not a journal record|does not start with"
    ) as refused:
        await start(data)
    assert str(path) in str(refused.value)
    assert writer_epoch(deployment) == before


async def test_a_record_whose_last_write_was_cut_short_never_took_effect_and_does_not_stop_the_start(
    deployment: Path,
) -> None:
    """A record is durable before its action takes effect, so a torn last line describes nothing that happened."""
    path = _journal_with_records(deployment, 2)
    whole = path.read_bytes()
    path.write_bytes(whole + b'{"seq":4,"at":"2026-11-20T00:00:00.000Z","type":"credential_rev')
    data = document(deployment)
    data["paths"]["journal"] = str(path)
    # A store of its own: the one of the module must not remember a journal that only this test has.
    data["paths"]["store_dir"] = str(_a_copy_of_the_store(deployment))
    core = await start(data)
    try:
        assert core.journal.last_seq == 3
    finally:
        await core.close()
    assert path.read_bytes() == whole, "the torn line was left in the way of the next record"


def _a_copy_of_the_store(root: Path) -> Path:
    copy = root / "tampered" / "store"
    shutil.rmtree(copy, ignore_errors=True)
    shutil.copytree(root / "store", copy)
    return copy


def _applied(store_dir: Path) -> int:
    with contextlib.closing(sqlite3.connect(f"file:{store_dir / 'state.db'}?mode=ro", uri=True)) as conn:
        return int(conn.execute("SELECT value FROM meta WHERE key = 'journal_applied'").fetchone()[0])


@pytest.mark.parametrize("loss", ["the-last-record", "the-last-two-records", "the-end-of-the-last-line"])
async def test_a_journal_that_has_lost_records_the_store_acted_on_is_never_served(deployment: Path, loss: str) -> None:
    """IPS-14, CRD-12: the journal is what a restore must never undo, so a journal with its end missing is refused.

    The chain cannot show this: what is left of a journal that was cut at a record boundary is a valid
    journal. The store can, because it remembers the last record it applied. Here the lost records are
    revocations: served from this pair, a later restore of the store would bring the credentials back.
    """
    path = _journal_with_records(deployment, 3)
    whole = path.read_bytes()
    data = document(deployment)
    data["paths"]["journal"] = str(path)
    store_dir = _a_copy_of_the_store(deployment)
    data["paths"]["store_dir"] = str(store_dir)
    core = await start(data)
    await core.close()
    assert _applied(store_dir) == 4, "the store has applied the whole journal"

    lines = _lines(path)
    if loss == "the-last-record":
        kept, ends_at = b"".join(lines[:-1]), 3
    elif loss == "the-last-two-records":
        kept, ends_at = b"".join(lines[:-2]), 2
    else:
        # Without its end the last line is a write that was cut short, which describes nothing that happened.
        kept, ends_at = whole[:-1], 3
    path.write_bytes(kept)
    epoch = writer_epoch(store_dir.parent)

    with pytest.raises(app.StartupError, match="the journal is older than the store") as refused:
        await start(data)
    assert f"applied record 4 of the security journal, and the journal ends at record {ends_at}" in str(refused.value)
    assert writer_epoch(store_dir.parent) == epoch, "a refused start took a writer epoch"
    assert _applied(store_dir) == 4, "a refused start changed what the store remembers"

    # With the journal's own copy back, the same store is served again.
    path.write_bytes(whole)
    core = await start(data)
    try:
        assert core.journal.last_seq == 4
    finally:
        await core.close()


async def test_a_store_that_is_older_than_its_journal_is_brought_up_to_it_and_served(deployment: Path) -> None:
    """IPS-10: the other direction is a restore of the store, which the replay of the journal exists for."""
    path = _journal_with_records(deployment, 3)
    data = document(deployment)
    data["paths"]["journal"] = str(path)
    store_dir = _a_copy_of_the_store(deployment)
    data["paths"]["store_dir"] = str(store_dir)
    assert _applied(store_dir) < 4
    core = await start(data)
    await core.close()
    assert _applied(store_dir) == 4


# =============================================================================== the edge kept apart
@pytest.mark.proves("T3-EC-01", level="L3")
async def test_an_edge_that_is_the_core_itself_refuses_the_start(deployment: Path) -> None:
    """EC-2, SEC-122: the edge runs under an identity different from the core's."""
    before = writer_epoch(deployment)
    with pytest.raises(app.StartupError, match="the edge is not separated") as refused:
        await start(document(deployment, edge={"uids": [EDGE_UID, os.geteuid()]}))
    assert f"edge uid {os.geteuid()} is the core's own identity" in str(refused.value)
    with pytest.raises(app.StartupError, match="an edge process must not run as root"):
        await start(document(deployment, edge={"uids": [0]}))
    assert writer_epoch(deployment) == before


GUARDED = {
    "the host private key": ("secrets/platform.key", 0o604),
    "the fingerprint key": ("keys/fingerprint.key", 0o604),
    "the store": ("store", 0o705),
    "the security journal": ("journal/security.journal", 0o604),
}


@pytest.mark.parametrize("what", sorted(GUARDED))
@pytest.mark.proves("T3-EC-01", level="L3")
async def test_an_edge_identity_that_could_read_what_only_the_core_may_hold_refuses_the_start(
    deployment: Path, what: str
) -> None:
    """SEC-122, T3-EC-01: the core refuses to start if the edge's identity can read the host credential or open the store."""
    relative, bits = GUARDED[what]
    path, before = deployment / relative, writer_epoch(deployment)
    config = cfg.parse_config(document(deployment))
    assert cfg.check_separation(config) == []
    with mode(path, bits):
        assert cfg.check_separation(config) == [f"edge uid {EDGE_UID} could read {what} ({path})"]
        # With the trusted-input rule switched off, the separation rule alone still refuses.
        with pytest.raises(app.StartupError, match="the edge is not separated") as refused:
            await app.build_core(config, binding=ModelHost(), clock=FakeClock(), check_files=False)
        assert f"could read {what}" in str(refused.value)
        # And as a deployment starts, with every check on, it is refused by one rule or the other.
        with pytest.raises(app.StartupError):
            await start(document(deployment))
    assert writer_epoch(deployment) == before


@pytest.mark.proves("T3-EC-01", level="L3")
async def test_an_edge_identity_that_could_read_through_one_of_its_groups_refuses_the_start(
    deployment: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The edge's own id is not the only way in: a group the account database gives it counts as well."""
    store, before = deployment / "store", writer_epoch(deployment)
    monkeypatch.setattr(
        cfg, "groups_of", lambda uid: frozenset({store.stat().st_gid}) if uid == EDGE_UID else frozenset()
    )
    with mode(store, 0o750), pytest.raises(app.StartupError, match="the edge is not separated") as refused:
        await start(document(deployment))
    assert f"edge uid {EDGE_UID} could read the store" in str(refused.value)
    assert writer_epoch(deployment) == before
    # The same mode is no way in for an identity outside the group.
    monkeypatch.setattr(cfg, "groups_of", lambda uid: frozenset())
    with mode(store, 0o750):
        assert cfg.check_separation(cfg.parse_config(document(deployment))) == []


def test_could_read_follows_ownership_and_mode_bits_and_nothing_else(tmp_path: Path) -> None:
    """The rule the separation check applies, case by case, with identities that are not this process."""
    path = tmp_path / "guarded"
    path.write_text("x", encoding="ascii")
    owner, group = path.stat().st_uid, path.stat().st_gid
    other, others_groups, members = EDGE_UID, frozenset({group + 1}), frozenset({group})
    cases = [
        # mode, uid, gids, expected
        (0o600, other, others_groups, False),
        (0o640, other, others_groups, False),
        (0o640, other, members, True),
        (0o604, other, others_groups, True),
        (0o604, other, members, False),  # the group's bits decide for a member, as the kernel decides
        (0o060, other, members, True),
        (0o000, owner, members, False),
        (0o400, owner, frozenset(), True),
        (0o000, 0, frozenset(), True),  # root reads everything
    ]
    for bits, uid, gids, expected in cases:
        path.chmod(bits)
        assert cfg.could_read(path, uid, gids) is expected, (oct(bits), uid, sorted(gids))
    path.chmod(0o600)
    assert cfg.could_read(tmp_path / "absent", other, members) is False


async def test_a_shared_identity_starts_only_when_it_is_allowed_and_then_says_so(deployment: Path) -> None:
    """Development only: the core starts, and reports through health that the separation does not hold."""
    shared = document(deployment, edge={"uids": [os.geteuid()]})
    with pytest.raises(app.StartupError, match="is the core's own identity"):
        await start(shared)
    core = await start({**shared, "security": {"allow_shared_identity": True}})
    try:
        health = await core.admin.run("health", {})
        assert health["edge_shares_core_identity"] is True
        assert core.telemetry.get("operator_diagnostics", kind="edge_shares_core_identity") == 1
    finally:
        await core.close()


async def test_allowing_a_shared_identity_admits_that_and_nothing_else(deployment: Path) -> None:
    """The switch is for one machine with one account. It does not open the secrets to an edge account of its own."""
    allowed = {"security": {"allow_shared_identity": True}}
    both = document(deployment, edge={"uids": [os.geteuid(), EDGE_UID]}, **allowed)
    store, before = deployment / "store", writer_epoch(deployment)
    with mode(store, 0o705):
        config = cfg.parse_config(both)
        assert cfg.check_separation(config, shared_identity_allowed=True) == [
            f"edge uid {EDGE_UID} could read the store ({store})"
        ]
        with pytest.raises(app.StartupError, match="the edge is not separated") as refused:
            await app.build_core(config, binding=ModelHost(), clock=FakeClock(), check_files=False)
        assert f"edge uid {EDGE_UID} could read the store" in str(refused.value)
        assert "is the core's own identity" not in str(refused.value), "what is admitted is not given as a reason"
    with pytest.raises(app.StartupError, match="an edge process must not run as root"):
        await start(document(deployment, edge={"uids": [os.geteuid(), 0]}, **allowed))
    assert writer_epoch(deployment) == before
    # With nothing but the shared identity in the way, the same configuration starts.
    core = await start(both)
    try:
        assert (await core.admin.run("health", {}))["edge_shares_core_identity"] is True
    finally:
        await core.close()


def test_an_edge_account_this_machine_does_not_know_stops_the_start(deployment: Path) -> None:
    """A name is looked up when the core starts; one that names nobody admits nobody, and is not passed over."""
    config = cfg.parse_config(document(deployment, edge={"users": ["acf-no-such-account"]}))
    with pytest.raises(cfg.ConfigError, match="not an account of this machine"):
        cfg.check_separation(config)
    with pytest.raises(cfg.ConfigError, match="names no identity"):
        cfg.parse_config(document(deployment, edge={}))
