"""Gate E: snapshot and restore are verified (contract §20, §27.5; plan: "snapshot-restore verified").

The promise is stronger than "a restore returns READY": after ``snapshot create`` and ``snapshot restore`` the guest
must be *the same machine at the same moment*, disk and memory, and the host must prove it before it says so (it
probes the restored guest and compares the answer with the probe it took just before the snapshot). Here that is
checked from outside, and then attacked: a snapshot whose bytes were changed on the host must never become a running
sandbox, and the failed attempt must leave the sandbox it targeted exactly as it was.

Tests marked ``control_plane`` assert only the state machine, naming and refusals; they also run under
``make control-plane`` against the in-memory host with the shipped configuration.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from acf_driver import EXIT_FAILED, EXIT_OK, EXIT_REFUSED, AcfLocal, Sandbox, Snapshot
from acf_integration import HostEnv

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("clean_host")]

BOOT_ID = "print(open('/proc/sys/kernel/random/boot_id').read().strip())"


def _boot_small(acf: AcfLocal, label: str) -> Sandbox:
    """A started sandbox as small as the policy allows: a snapshot is as big as the guest's memory plus its disk."""
    box = acf.boot(label, cpu=1, memory="128", disk="256")
    assert box.name is not None
    return box


def _flip_one_byte(path: Path) -> None:
    """Invert the byte at offset 4096 (or append one, in a file shorter than that): the digest can no longer match."""
    with path.open("r+b") as f:
        f.seek(4096)
        original = f.read(1)
        f.seek(4096)
        f.write(bytes([original[0] ^ 0xFF]) if original else b"\xff")


# ============================================================================================ the state machine
@pytest.mark.control_plane
def test_a_snapshot_needs_an_idle_sandbox(acf: AcfLocal) -> None:
    name = acf.name("unstarted")
    acf.sandbox_create(name, cpu=1, memory="128", disk="256")
    done = acf.call("snapshot", "create", acf.name("early"), "--sandbox", name, "--json")
    assert done.returncode == EXIT_REFUSED, done.describe()
    assert "a snapshot needs an idle (READY/COMPLETED) sandbox" in done.stderr
    assert acf.snapshot_list() == []
    assert acf.sandbox_inspect(name).state == "PROVISIONING"


@pytest.mark.control_plane
def test_snapshot_names_are_unique_while_the_snapshot_exists(acf: AcfLocal) -> None:
    box = _boot_small(acf, "names")
    assert box.name is not None
    name = acf.name("baseline")
    first = acf.snapshot_create(name, box.name)
    clash = acf.call("snapshot", "create", name, "--sandbox", box.name, "--json")
    assert clash.returncode == EXIT_REFUSED, clash.describe()
    assert "a snapshot with that name already exists" in clash.stderr
    assert [s.snapshot_id for s in acf.snapshot_list()] == [first.snapshot_id], "a refused create must change nothing"
    assert acf.snapshot_delete(first.snapshot_id).state == "DELETED"
    assert acf.snapshot_create(name, box.name).snapshot_id != first.snapshot_id  # the name is free again


@pytest.mark.control_plane
def test_restore_in_place_is_a_new_generation_of_the_same_sandbox(acf: AcfLocal) -> None:
    box = _boot_small(acf, "gens")
    assert box.name is not None
    snap = acf.snapshot_create(acf.name("baseline"), box.name)
    assert isinstance(snap, Snapshot)
    assert (snap.state, snap.restore_count) == ("READY", 0)
    assert snap.size_bytes > 0

    first = acf.snapshot_restore(snap.snapshot_id, sandbox=box.name)
    assert (first.sandbox_id, first.state, first.generation) == (box.sandbox_id, "READY", box.generation + 1)
    assert any(n.startswith("restore verified") for n in first.notes), "the host must say that it verified the restore"
    assert not any("more than once" in n for n in first.notes)

    second = acf.snapshot_restore(snap.snapshot_id, sandbox=box.name)
    assert (second.sandbox_id, second.generation) == (box.sandbox_id, box.generation + 2)
    assert any("restored more than once" in n for n in second.notes), (
        "restoring twice must warn about shared guest secrets"
    )
    assert acf.snapshot_inspect(snap.snapshot_id).restore_count == 2
    assert acf.sh(box.name, "true").succeeded(), "the restored sandbox must be usable"
    assert [s.sandbox_id for s in acf.sandbox_list()] == [box.sandbox_id], "the superseded generation must be retired"


@pytest.mark.control_plane
def test_restore_as_new_is_an_independent_sandbox_that_outlives_its_source(acf: AcfLocal) -> None:
    box = _boot_small(acf, "origin")
    assert box.name is not None
    snap = acf.snapshot_create(acf.name("baseline"), box.name)
    clone_name = acf.name("clone")
    clone = acf.snapshot_restore_new(snap.snapshot_id, clone_name)
    assert clone.sandbox_id != box.sandbox_id
    assert (clone.state, clone.generation, clone.name) == ("READY", 1, clone_name)
    assert clone.raw["source_snapshot"]["snapshot_id"] == snap.snapshot_id

    again = acf.call("snapshot", "restore", snap.snapshot_id, "--new", "--name", clone_name, "--json")
    assert again.returncode == EXIT_REFUSED, "a name is unique among live sandboxes"
    assert "already exists" in again.stderr

    assert acf.sandbox_destroy(box.name).state == "DESTROYED"
    assert acf.sh(clone_name, "true").succeeded(), "the clone must not depend on the sandbox it came from"
    assert acf.snapshot_inspect(snap.snapshot_id).state == "READY", (
        "destroying the source must not destroy the snapshot"
    )


@pytest.mark.control_plane
def test_a_deleted_or_unknown_snapshot_cannot_be_restored(acf: AcfLocal) -> None:
    box = _boot_small(acf, "gone")
    assert box.name is not None
    snap = acf.snapshot_create(acf.name("baseline"), box.name)
    assert acf.snapshot_delete(snap.snapshot_id).state == "DELETED"
    assert acf.snapshot_list() == []

    for target in (snap.snapshot_id, "snp-" + "0" * 32, "never-existed"):
        done = acf.call("snapshot", "restore", target, "--sandbox", box.name, "--json")
        assert done.returncode == EXIT_REFUSED, done.describe()
        assert "no snapshot with id or name" in done.stderr
    after = acf.sandbox_inspect(box.name)
    assert (after.generation, after.state) == (box.generation, "READY"), (
        "a refused restore must leave the sandbox alone"
    )


@pytest.mark.control_plane
def test_a_restore_cannot_target_a_destroyed_sandbox(acf: AcfLocal) -> None:
    box = _boot_small(acf, "target")
    assert box.name is not None
    snap = acf.snapshot_create(acf.name("baseline"), box.name)
    acf.sandbox_destroy(box.sandbox_id)
    done = acf.call("snapshot", "restore", snap.snapshot_id, "--sandbox", box.sandbox_id, "--json")
    assert done.returncode == EXIT_REFUSED, done.describe()
    assert acf.sandbox_list() == [], "a refused restore must not resurrect anything"


# ============================================================================================ the real thing
def test_restore_rolls_a_running_sandbox_back_disk_and_memory(acf: AcfLocal) -> None:
    """The phase milestone: ``snapshot create baseline`` ... change things ... ``snapshot restore baseline``."""
    box = acf.boot("rollback", cpu=2, memory="512", disk="1024")
    assert box.name is not None
    assert acf.sh(box.name, "echo before > /workspace/disk.txt && echo before > /dev/shm/ram.txt").succeeded()
    boot_before = acf.python(box.name, BOOT_ID).stdout

    baseline = acf.snapshot_create(acf.name("baseline"), box.name)
    assert acf.sh(
        box.name,
        "echo after > /workspace/disk.txt && echo after > /dev/shm/ram.txt && echo extra > /workspace/extra.txt",
    ).succeeded()
    assert acf.sh(box.name, "cat /workspace/disk.txt /dev/shm/ram.txt").stdout == "after\nafter\n"

    restored = acf.snapshot_restore(baseline.snapshot_id, sandbox=box.name)
    assert (restored.state, restored.generation) == ("READY", box.generation + 1)

    state = acf.sh(box.name, "cat /workspace/disk.txt /dev/shm/ram.txt; test ! -e /workspace/extra.txt && echo gone")
    assert state.stdout == "before\nbefore\ngone\n", (
        f"the guest is not the machine that was snapshotted: {state.stdout!r}"
    )
    assert acf.python(box.name, BOOT_ID).stdout == boot_before, "restore must RESUME the guest, not boot a new one"
    assert acf.snapshot_inspect(baseline.snapshot_id).restore_count == 1


def test_a_snapshot_can_be_restored_by_name(acf: AcfLocal) -> None:
    box = _boot_small(acf, "byname")
    assert box.name is not None
    name = acf.name("baseline")
    acf.snapshot_create(name, box.name)
    restored = acf.snapshot_restore(name, sandbox=box.name)
    assert restored.state == "READY"


def test_each_snapshot_is_the_moment_it_was_taken(acf: AcfLocal) -> None:
    box = _boot_small(acf, "moments")
    assert box.name is not None
    acf.sh(box.name, "echo v1 > /workspace/version")
    one = acf.snapshot_create(acf.name("one"), box.name)
    acf.sh(box.name, "echo v2 > /workspace/version")
    two = acf.snapshot_create(acf.name("two"), box.name)
    acf.sh(box.name, "echo v3 > /workspace/version")

    acf.snapshot_restore(one.snapshot_id, sandbox=box.name)
    assert acf.sh(box.name, "cat /workspace/version").stdout == "v1\n"
    acf.snapshot_restore(two.snapshot_id, sandbox=box.name)
    assert acf.sh(box.name, "cat /workspace/version").stdout == "v2\n"
    acf.snapshot_restore(one.snapshot_id, sandbox=box.name)
    assert acf.sh(box.name, "cat /workspace/version").stdout == "v1\n", "a snapshot must be restorable more than once"


def test_a_clone_shares_the_snapshots_past_but_not_its_future(acf: AcfLocal) -> None:
    box = _boot_small(acf, "source")
    assert box.name is not None
    acf.sh(box.name, "echo shared > /workspace/history")
    snap = acf.snapshot_create(acf.name("baseline"), box.name)
    clone = acf.snapshot_restore_new(snap.snapshot_id, acf.name("clone"))
    assert clone.name is not None

    assert acf.sh(clone.name, "cat /workspace/history").stdout == "shared\n"
    acf.sh(clone.name, "echo clone-only > /workspace/future")
    acf.sh(box.name, "echo source-only > /workspace/future")
    assert acf.sh(clone.name, "cat /workspace/future").stdout == "clone-only\n"
    assert acf.sh(box.name, "cat /workspace/future").stdout == "source-only\n"
    # Both resumed from the same memory image, so they share a boot id: exactly what the uniqueness note warns about.
    assert acf.python(clone.name, BOOT_ID).stdout == acf.python(box.name, BOOT_ID).stdout


def test_a_snapshot_is_at_least_as_big_as_the_memory_it_holds(acf: AcfLocal) -> None:
    box = acf.boot("size", memory="256", disk="256")
    assert box.name is not None
    snap = acf.snapshot_create(acf.name("baseline"), box.name)
    assert snap.size_bytes >= 256 * 1024 * 1024
    assert len(snap.raw["manifest_digest"]) == 64


# ============================================================================================ tampering
def _setup_tamper(acf: AcfLocal, host_env: HostEnv, label: str) -> tuple[Sandbox, Snapshot, Path]:
    box = _boot_small(acf, label)
    assert box.name is not None
    assert acf.sh(box.name, "echo intact > /workspace/state").succeeded()
    snap = acf.snapshot_create(acf.name("baseline"), box.name)
    where = host_env.snapshot_dir(snap.snapshot_id, snap.snapshot_generation)
    assert (where / "manifest.json").is_file(), f"the snapshot is not where the layout says: {where}"
    return box, snap, where


def _assert_sandbox_untouched(acf: AcfLocal, box: Sandbox) -> None:
    assert box.name is not None
    after = acf.sandbox_inspect(box.name)
    assert (after.generation, after.state, after.vmm_identity) == (box.generation, "READY", box.vmm_identity), (
        "a failed restore must leave the sandbox it targeted running, in the same generation, on the same VMM"
    )
    assert acf.sh(box.name, "cat /workspace/state").stdout == "intact\n"
    assert len(acf.sandbox_list()) == 1, "a failed restore must not leave a half-built sandbox behind"


@pytest.mark.parametrize("artifact", ["mem", "vmstate", "disk"])
def test_a_snapshot_artifact_changed_on_the_host_is_never_restored(
    acf: AcfLocal, host_env: HostEnv, artifact: str
) -> None:
    box, snap, where = _setup_tamper(acf, host_env, f"tamper-{artifact}")
    _flip_one_byte(where / artifact)
    assert box.name is not None
    done = acf.call("snapshot", "restore", snap.snapshot_id, "--sandbox", box.name, "--json")
    assert done.returncode in {EXIT_REFUSED, EXIT_FAILED}, (
        f"a corrupted {artifact} must not restore:\n{done.describe()}"
    )
    _assert_sandbox_untouched(acf, box)


def test_a_missing_snapshot_artifact_is_never_restored(acf: AcfLocal, host_env: HostEnv) -> None:
    box, snap, where = _setup_tamper(acf, host_env, "tamper-missing")
    assert box.name is not None
    (where / "vmstate").unlink()
    done = acf.call("snapshot", "restore", snap.snapshot_id, "--sandbox", box.name, "--json")
    assert done.returncode in {EXIT_REFUSED, EXIT_FAILED}, done.describe()
    _assert_sandbox_untouched(acf, box)


def test_a_manifest_changed_on_the_host_invalidates_the_snapshot(acf: AcfLocal, host_env: HostEnv) -> None:
    box, snap, where = _setup_tamper(acf, host_env, "tamper-manifest")
    assert box.name is not None
    manifest = json.loads((where / "manifest.json").read_text())
    manifest["resources"]["memory_mib"] = 4096
    (where / "manifest.json").write_text(json.dumps(manifest))

    done = acf.call("snapshot", "restore", snap.snapshot_id, "--sandbox", box.name, "--json")
    assert done.returncode == EXIT_REFUSED, done.describe()
    assert "manifest hashes to" in done.stderr, "the manifest is bound to the digest the host journalled"
    assert acf.snapshot_inspect(snap.snapshot_id).state == "INVALID"
    _assert_sandbox_untouched(acf, box)

    again = acf.call("snapshot", "restore", snap.snapshot_id, "--sandbox", box.name, "--json")
    assert again.returncode == EXIT_REFUSED
    assert "only a READY snapshot can be restored" in again.stderr, "an INVALID snapshot stays invalid"


def test_a_snapshot_directory_deleted_on_the_host_invalidates_the_snapshot(acf: AcfLocal, host_env: HostEnv) -> None:
    box, snap, where = _setup_tamper(acf, host_env, "tamper-dir")
    assert box.name is not None
    shutil.rmtree(where)
    done = acf.call("snapshot", "restore", snap.snapshot_id, "--sandbox", box.name, "--json")
    assert done.returncode == EXIT_REFUSED, done.describe()
    assert "snapshot directory is missing" in done.stderr
    assert acf.snapshot_inspect(snap.snapshot_id).state == "INVALID"
    _assert_sandbox_untouched(acf, box)
    assert acf.call("snapshot", "delete", snap.snapshot_id, "--yes", "--json").returncode == EXIT_OK, (
        "an invalid snapshot must still be deletable, or its record would stay forever"
    )


# ============================================================================================ quota
def test_the_snapshot_count_limit_is_enforced(acf: AcfLocal, host_env: HostEnv) -> None:
    if host_env.snapshot_limit is None:
        pytest.skip("set ACF_TEST_SNAPSHOT_LIMIT to the host's envelope.max_snapshots (use a small value) to run this")
    box = _boot_small(acf, "quota")
    assert box.name is not None
    made = [acf.snapshot_create(acf.name(f"s{i}"), box.name) for i in range(host_env.snapshot_limit)]
    assert len({s.snapshot_id for s in made}) == host_env.snapshot_limit
    over = acf.call("snapshot", "create", acf.name("over"), "--sandbox", box.name, "--json")
    assert over.returncode == EXIT_REFUSED, over.describe()
    assert f"limit of {host_env.snapshot_limit} snapshots" in over.stderr
    assert len(acf.snapshot_list()) == host_env.snapshot_limit
    acf.snapshot_delete(made[0].snapshot_id)  # deleting one makes room again
    assert acf.snapshot_create(acf.name("again"), box.name).state == "READY"
