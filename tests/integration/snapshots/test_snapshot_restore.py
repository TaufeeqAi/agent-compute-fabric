"""Snapshots: what may be captured, what a restore must prove, and what must never become a running sandbox.

* ``control_plane`` tests cover admission and references: names, generations, expiry, scopes, deleted and unknown
  snapshots, the count limit, and what happens when the bytes of a snapshot are changed on the host behind the
  host's back (catalog entries T-SNAP-01, T-SNAP-05, T-SNAP-06 at evidence level L2/L3).
* T-SNAP-03 and T-RES-05 need a real VMM (L4): the guest that comes back must be the machine that was captured,
  and nothing the superseded generation wrote may be readable by the new one, on disk or in memory.
"""

from __future__ import annotations

import json
import secrets
import shutil
import threading
from datetime import UTC, datetime, timedelta
from typing import Any, Final

import pytest

from acf_driver import (
    EXIT_FAILED,
    EXIT_REFUSED,
    AcfLocal,
    DriverError,
    Sandbox,
    Snapshot,
    WireHost,
    snapshot_ref,
    target_of,
)
from acf_integration import HostEnv, require_root, vmm_of
from acf_proc import file_contains, memory_contains, process_alive

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("clean_host")]

GHOST_SNAPSHOT = "snp-" + "0" * 32
BOOT_ID = "print(open('/proc/sys/kernel/random/boot_id').read().strip())"
#: A snapshot is as big as the guest's memory plus its disk, so the sandboxes here are as small as a guest boots in.
SMALL: Final[dict[str, Any]] = {"memory_mib": 128, "disk_mib": 256}


def _expiry(sandbox: Sandbox) -> datetime:
    return datetime.fromisoformat(sandbox.expires_at.replace("Z", "+00:00")).astimezone(UTC)


def _host_files(host_env: HostEnv) -> None:
    """These checks change the host's own files: the test host's belong to the test, a production host's to root."""
    if not host_env.control_plane:
        require_root(host_env, "changing the host's snapshot files")


# ============================================================================================ names and generations
@pytest.mark.control_plane
def test_a_snapshot_name_is_unique_within_its_scope_while_the_snapshot_exists(acf: AcfLocal) -> None:
    wire = acf.wire
    box = wire.ready(acf.name("names"), **SMALL)
    name = acf.name("baseline")
    first = acf.ok("snapshot", "create", box.sandbox_id, "--name", name).succeeded().snapshot_result()
    assert (first.state, first.name, first.snapshot_generation, first.restore_count) == ("READY", name, 1, 0)
    assert first.source_sandbox == (box.sandbox_id, box.generation)
    assert first.size_bytes > 0
    assert wire.refresh(box).state == "READY", "a snapshot returns the sandbox to the state it was taken from"

    with wire.nothing_recorded("a snapshot with a name that is taken"):
        clash = acf.refused("snapshot", "create", box.sandbox_id, "--name", name)
    assert (clash.failure_class, clash.retry) == ("STATE_CONFLICT", "AFTER_CHANGE")
    assert [s.snapshot_id for s in wire.snapshots()] == [first.snapshot_id]

    assert acf.ok("snapshot", "delete", name, "--yes").succeeded().snapshot_result().state == "DELETED"
    again = acf.ok("snapshot", "create", box.sandbox_id, "--name", name).succeeded().snapshot_result()
    assert again.snapshot_id != first.snapshot_id, "the name is free again; the identity is never reused"


@pytest.mark.control_plane
def test_restore_in_place_is_a_new_generation_that_keeps_the_sandboxs_expiry(acf: AcfLocal, host_env: HostEnv) -> None:
    """RE-3/RE-5 and LT-1 of the contract: a new generation becomes current, the old one is retired, and restore in
    place keeps the sandbox's expiry."""
    wire = acf.wire
    box = wire.completed(acf.name("gens"), **SMALL)
    snapshot = wire.snapshot(box, acf.name("baseline"))

    first = acf.ok("snapshot", "restore", snapshot.snapshot_id, "--into", box.sandbox_id).succeeded().sandbox_result()
    assert (first.sandbox_id, first.state, first.generation) == (box.sandbox_id, "READY", box.generation + 1)
    assert first.expires_at == box.expires_at, "restore in place must keep the sandbox's expiry"
    assert first.source_snapshot == (snapshot.snapshot_id, snapshot.snapshot_generation)
    assert first.last_run is None, "the new generation has run nothing"
    verified = [note for note in first.notes if note.startswith("restore verified")]
    assert verified, "the host must say that it verified the restore"
    manifest = (
        json.loads((host_env.snapshot_dir(snapshot) / "manifest.json").read_text()) if host_env.control_plane else None
    )
    if manifest is not None:
        shown = verified[0].rsplit(" ", 1)[-1].rstrip("…")
        assert shown, verified
        assert shown in manifest["baseline_state_digest"], "the restore was verified against another baseline"
    assert not any("more than once" in note for note in first.notes)

    second = wire.restore_into(wire.snapshots()[0], first)
    assert (second.generation, second.expires_at) == (box.generation + 2, box.expires_at)
    assert any("restored more than once" in note for note in second.notes), (
        "a second restore of one snapshot must say that guest-level uniqueness is no longer guaranteed"
    )
    assert wire.snapshots()[0].restore_count == 2
    assert [s.sandbox_id for s in wire.sandboxes()] == [box.sandbox_id], "the superseded generations must be retired"
    stale = acf.refused("sandbox", "exec", box.sandbox_id, "--expected-generation", str(box.generation), "--", "true")
    assert stale.failure_class == "REVISION_CONFLICT", "a token of a superseded generation must not act on the new one"


@pytest.mark.control_plane
@pytest.mark.parametrize("state", ["PROVISIONING", "STOPPED"])
def test_restore_in_place_gives_a_sandbox_without_a_runtime_a_new_generation(acf: AcfLocal, state: str) -> None:
    """§12.2: restore in place is admitted in any state except ``REQUESTED``, ``RUNNING`` and ``DESTROYED``; a
    stopped sandbox continues only through a new generation created by restore."""
    wire = acf.wire
    source = wire.ready(acf.name("source"), **SMALL)
    snapshot = wire.snapshot(source, acf.name("baseline"))
    target = (
        wire.create(acf.name("target"), **SMALL)
        if state == "PROVISIONING"
        else wire.stop(wire.ready(acf.name("target"), **SMALL))
    )
    assert target.state == state
    restored = (
        acf.ok("snapshot", "restore", snapshot.snapshot_id, "--into", target.sandbox_id).succeeded().sandbox_result()
    )
    assert (restored.sandbox_id, restored.state, restored.generation) == (
        target.sandbox_id,
        "READY",
        target.generation + 1,
    )
    assert restored.expires_at == target.expires_at


@pytest.mark.control_plane
def test_restore_as_new_is_an_independent_sandbox_with_an_expiry_of_its_own(acf: AcfLocal, host_env: HostEnv) -> None:
    wire = acf.wire
    box = wire.ready(acf.name("origin"), **SMALL)
    snapshot = wire.snapshot(box, acf.name("baseline"))
    clone_name = acf.name("clone")
    asked = datetime.now(UTC)
    restored = acf.ok("snapshot", "restore", snapshot.snapshot_id, "--new", "--name", clone_name, "--lifetime", "10m")
    clone = restored.succeeded().sandbox_result()
    assert clone.sandbox_id != box.sandbox_id
    assert (clone.state, clone.generation, clone.name) == ("READY", 1, clone_name)
    assert clone.source_snapshot == (snapshot.snapshot_id, snapshot.snapshot_generation)
    assert clone.resources == box.resources, "a restore cannot change what the snapshot was taken with"
    assert timedelta(minutes=9) < _expiry(clone) - asked < timedelta(minutes=11), "the lifetime that was asked for"

    with wire.nothing_recorded("a restore the host does not admit"):
        taken = acf.refused("snapshot", "restore", snapshot.snapshot_id, "--new", "--name", clone_name)
        too_long = acf.refused(
            "snapshot", "restore", snapshot.snapshot_id, "--new", "--lifetime",
            f"{host_env.profile.integer('limits.max_lifetime_secs') + 1}s",
        )  # fmt: skip
    assert taken.failure_class == "STATE_CONFLICT"
    assert too_long.failure_class == "SAFETY_CONTROL_DENIED"

    wire.destroy(box)
    assert acf.execute(clone_name, ["true"]).operation.state == "SUCCEEDED", "the clone depends on its source sandbox"
    assert wire.snapshots()[0].state == "READY", "destroying a sandbox does not delete its snapshots"


@pytest.mark.control_plane
def test_a_deleted_or_unknown_snapshot_is_never_restored_and_delete_repeats_with_no_effect(acf: AcfLocal) -> None:
    wire = acf.wire
    box = wire.ready(acf.name("gone"), **SMALL)
    name = acf.name("baseline")
    snapshot = wire.snapshot(box, name)
    assert wire.delete(snapshot).state == "DELETED"
    assert wire.snapshots() == []
    assert wire.info().snapshots == 0

    with wire.nothing_recorded("a restore of a snapshot that cannot be restored"):
        deleted = acf.refused(
            "snapshot", "restore", snapshot.snapshot_id, "--snapshot-generation", "1", "--into", box.sandbox_id
        )
        unknown = acf.refused("snapshot", "restore", GHOST_SNAPSHOT, "--snapshot-generation", "1", "--new")
        other_generation = wire.call(
            "snapshot.restore",
            {"snapshot": {"snapshot_id": snapshot.snapshot_id, "snapshot_generation": 2}, "target": {"kind": "new"}},
        ).refused()
    assert (deleted.failure_class, deleted.retry) == ("STATE_CONFLICT", "AFTER_CHANGE"), "only READY is restorable"
    assert (unknown.failure_class, unknown.retry) == ("NOT_FOUND", "NEVER")
    assert other_generation.failure_class == "NOT_FOUND", "a snapshot is its id AND its generation"
    by_name = acf.json("snapshot", "restore", name, "--new")
    assert by_name.returncode == EXIT_REFUSED, by_name.describe()
    assert by_name.client_error()["kind"] == "LookupFailure", "a deleted snapshot's name no longer resolves"

    after = wire.refresh(box)
    assert (after.generation, after.state) == (box.generation, "READY"), "a refused restore must leave its target alone"
    assert wire.delete(snapshot).state == "DELETED", "deleting a deleted snapshot succeeds and changes nothing"


@pytest.mark.control_plane
def test_a_snapshot_no_runtime_depends_on_can_be_deleted_while_its_restores_live(acf: AcfLocal) -> None:
    """RF-1/RF-2: a live generation references a snapshot only if its runtime still depends on the snapshot's
    files, which the backend declares. This backend's declaration decides which of the two outcomes is right."""
    wire = acf.wire
    box = wire.ready(acf.name("ref"), **SMALL)
    snapshot = wire.snapshot(box, acf.name("baseline"))
    clone = wire.restore_new(snapshot, acf.name("clone"))
    depends = bool(wire.info().capabilities["runtime_depends_on_snapshot"])
    answer = acf.json("snapshot", "delete", snapshot.snapshot_id, "--yes").answer()
    if depends:
        assert answer.refused().failure_class == "STATE_CONFLICT", "a referenced snapshot must not be deleted"
        wire.destroy(clone)
        assert wire.delete(snapshot).state == "DELETED", "afterwards the delete succeeds"
    else:
        assert answer.succeeded().snapshot_result().state == "DELETED"
        assert wire.run(clone, ["true"]).state == "SUCCEEDED", "the restored sandbox needed the deleted snapshot"


# ============================================================================================ scopes
@pytest.mark.control_plane
def test_t_snap_05_restore_delete_and_list_across_scopes_are_not_found(acf: AcfLocal, host_env: HostEnv) -> None:
    """T-SNAP-05 (L2): restore, delete and list across scopes -> ``NOT_FOUND``."""
    owner = host_env.peer(acf, "caller", scope="it-team-a")
    outsider = host_env.peer(acf, "caller", scope="it-team-b")
    box = owner.wire.ready(acf.name("owned"), **SMALL)
    snapshot = owner.wire.snapshot(box, acf.name("private"))
    assert snapshot.owner == ("tls-caller", "it-team-a")

    with acf.wire.nothing_recorded("a request across owner scopes"):
        restore = outsider.refused("snapshot", "restore", snapshot.snapshot_id, "--snapshot-generation", "1", "--new")
        delete = outsider.wire.call("snapshot.delete", {"snapshot": snapshot_ref(snapshot)}).refused()
        into_theirs = outsider.wire.call(
            "snapshot.restore", {"snapshot": snapshot_ref(snapshot), "target": {"kind": "existing", **target_of(box)}}
        ).refused()
        of_theirs = outsider.wire.call("snapshot.create", target_of(box)).refused()
    for refusal in (restore, delete, into_theirs, of_theirs):
        assert (refusal.failure_class, refusal.retry) == ("NOT_FOUND", "NEVER"), refusal
    assert outsider.ok("snapshot", "list").snapshots().items == [], "another scope's snapshot must not be listed"
    assert [s.snapshot_id for s in owner.ok("snapshot", "list").snapshots().items] == [snapshot.snapshot_id]
    assert [s.snapshot_id for s in acf.wire.snapshots()] == [snapshot.snapshot_id], "an operator sees every scope"


# ============================================================================================ tampering
def _tamper_setup(acf: AcfLocal, host_env: HostEnv, label: str) -> tuple[WireHost, Sandbox, Snapshot]:
    _host_files(host_env)
    wire = acf.wire
    box = wire.ready(acf.name(label), **SMALL)
    snapshot = wire.snapshot(box, acf.name("baseline"))
    assert (host_env.snapshot_dir(snapshot) / "manifest.json").is_file(), "the snapshot is not where the layout says"
    return wire, box, snapshot


def _assert_untouched(wire: WireHost, box: Sandbox) -> None:
    after = wire.refresh(box)
    assert (after.generation, after.state, after.vmm_identity) == (box.generation, box.state, box.vmm_identity), (
        "a restore that failed must leave the sandbox it targeted current, in the same generation, on the same runtime"
    )
    assert [s.sandbox_id for s in wire.sandboxes()] == [box.sandbox_id], "a failed restore left a sandbox behind"
    assert wire.info().live_sandboxes == 1, "a failed restore kept a reservation"


@pytest.mark.control_plane
@pytest.mark.parametrize("artifact", ["mem", "vmstate", "disk"])
def test_t_snap_01_a_changed_artifact_is_refused_before_any_runtime_is_launched(
    acf: AcfLocal, host_env: HostEnv, artifact: str
) -> None:
    """T-SNAP-01 (L2): a changed artifact -> refused before any runtime is launched."""
    wire, box, snapshot = _tamper_setup(acf, host_env, f"tamper-{artifact}")
    path = host_env.snapshot_dir(snapshot) / artifact
    original = path.read_bytes()
    path.write_bytes(original + b"\x00" if len(original) < 4096 else original[:-1] + bytes([original[-1] ^ 0xFF]))

    done = acf.json("snapshot", "restore", snapshot.snapshot_id, "--into", box.sandbox_id)
    assert done.returncode in {EXIT_REFUSED, EXIT_FAILED}, f"a corrupted {artifact} was restored:\n{done.describe()}"
    answer = done.answer()
    if answer.refusal is not None:
        assert answer.refusal.failure_class == "INTEGRITY_FAILURE"
    else:
        failed = answer.accepted()
        assert (failed.state, failed.failure_class, failed.effect) == ("FAILED", "INTEGRITY_FAILURE", "NOT_APPLIED")
    _assert_untouched(wire, box)
    as_new = acf.json("snapshot", "restore", snapshot.snapshot_id, "--new")
    assert as_new.returncode in {EXIT_REFUSED, EXIT_FAILED}, as_new.describe()
    _assert_untouched(wire, box)


@pytest.mark.control_plane
def test_t_snap_01_a_changed_manifest_invalidates_the_snapshot(acf: AcfLocal, host_env: HostEnv) -> None:
    """T-SNAP-01 (L2): a changed manifest -> refused; the manifest is believed only if it matches the digest the
    store holds (SNP-3)."""
    wire, box, snapshot = _tamper_setup(acf, host_env, "tamper-manifest")
    manifest = host_env.snapshot_dir(snapshot) / "manifest.json"
    manifest.write_bytes(manifest.read_bytes() + b" ")

    refusal = acf.refused("snapshot", "restore", snapshot.snapshot_id, "--into", box.sandbox_id)
    assert refusal.failure_class == "INTEGRITY_FAILURE"
    assert wire.snapshots()[0].state == "INVALID"
    _assert_untouched(wire, box)

    again = acf.refused("snapshot", "restore", snapshot.snapshot_id, "--new")
    assert again.failure_class == "STATE_CONFLICT", "an INVALID snapshot stays unrestorable"
    assert (
        acf.ok("snapshot", "delete", snapshot.snapshot_id, "--yes").succeeded().snapshot_result().state == "DELETED"
    ), "an invalid snapshot must still be deletable, or its record and its quota would stay forever"


@pytest.mark.control_plane
def test_t_snap_01_a_manifest_and_its_artifacts_replaced_together_are_refused(acf: AcfLocal, host_env: HostEnv) -> None:
    """T-SNAP-01 (L2): both replaced together -> refused. A set of files that is consistent in itself (another
    snapshot's manifest with its own artifacts) is still not the snapshot the store recorded."""
    wire, box, snapshot = _tamper_setup(acf, host_env, "tamper-both")
    other_box = wire.completed(acf.name("other"), **SMALL)
    other = wire.snapshot(other_box, acf.name("other"))
    target_dir, source_dir = host_env.snapshot_dir(snapshot), host_env.snapshot_dir(other)
    for item in sorted(source_dir.iterdir()):
        shutil.copyfile(item, target_dir / item.name)

    done = acf.json("snapshot", "restore", snapshot.snapshot_id, "--new")
    assert done.returncode == EXIT_REFUSED, done.describe()
    assert done.refusal().failure_class == "INTEGRITY_FAILURE"
    assert {s.sandbox_id for s in wire.sandboxes()} == {box.sandbox_id, other_box.sandbox_id}
    assert {s.name: s.state for s in wire.snapshots()} == {snapshot.name: "INVALID", other.name: "READY"}


# ============================================================================================ quota
@pytest.mark.control_plane
def test_t_snap_06_concurrent_snapshot_creates_cannot_exceed_the_count_limit(acf: AcfLocal, host_env: HostEnv) -> None:
    """T-SNAP-06 (L2): concurrent snapshot creates cannot exceed the count; a refused create holds no quota."""
    host_env.test_host()  # hundreds of megabytes per snapshot on a real backend: this is a check of the arithmetic
    limit = host_env.config.integer("envelope.max_snapshots")
    wire = acf.wire
    boxes = [wire.ready(acf.name(f"q{i}"), **SMALL) for i in range(4)]
    made: list[Snapshot] = []
    refusals: list[str] = []
    lock = threading.Lock()

    def take_until_refused(box: Sandbox) -> None:
        for _ in range(limit + 1):
            answer = wire.call("snapshot.create", target_of(box))
            with lock:
                if answer.refusal is not None:
                    refusals.append(answer.refusal.failure_class)
                    return
                made.append(answer.succeeded().snapshot_result())
        raise DriverError(f"one sandbox took {limit + 1} snapshots on a host limited to {limit}")

    threads = [threading.Thread(target=take_until_refused, args=(box,)) for box in boxes]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=600)
    assert not any(thread.is_alive() for thread in threads)
    assert len(made) == limit, f"{len(made)} snapshots exist on a host limited to {limit}"
    assert refusals == ["RESOURCE_EXHAUSTED"] * len(boxes)
    assert wire.info().snapshots == limit

    wire.delete(made[0])
    assert wire.snapshot(boxes[0]).state == "READY", "deleting a snapshot gives its place back"
    assert wire.info().snapshots == limit


# ============================================================================================ a real VMM (L4)
def test_t_snap_03_the_restore_oracle_reproduces_the_baseline(acf: AcfLocal, host_env: HostEnv) -> None:
    """T-SNAP-03: "the restore oracle: the baseline is reproduced; a reboot is detected".

    On the real host (as root, to read the snapshot's manifest): a guest writes one marker to its disk and one to
    memory, is captured, changes both and adds a file, and is restored in place. Pass: the restored guest is the
    captured machine at the captured moment: both markers read as before the capture, the later file does not
    exist, and its boot id is the captured one (it was resumed, not booted). The host states that it verified the
    restore against the baseline the manifest recorded. The oracle's witness distinguishes a resumed guest from a
    booted one: a fresh sandbox of the same image has another boot id.
    """
    require_root(host_env, "reading the snapshot's manifest")
    box = acf.boot("oracle", cpu=2, memory="512", disk="1024")
    name = box.sandbox_id
    assert acf.sh(name, "echo before > /workspace/disk.txt && echo before > /dev/shm/ram.txt && sync").succeeded()
    boot_before = acf.python(name, BOOT_ID).stdout_text

    snapshot = acf.ok("snapshot", "create", name, "--name", acf.name("baseline")).succeeded().snapshot_result()
    assert snapshot.size_bytes >= 512 * (1 << 20), "a snapshot holds at least the guest's memory"
    changed = acf.sh(
        name, "echo after > /workspace/disk.txt && echo after > /dev/shm/ram.txt && echo extra > /workspace/extra.txt"
    )
    assert changed.succeeded()
    assert acf.sh(name, "cat /workspace/disk.txt /dev/shm/ram.txt").stdout_text == "after\nafter\n"

    restored = acf.ok("snapshot", "restore", snapshot.snapshot_id, "--into", name).succeeded().sandbox_result()
    assert (restored.state, restored.generation) == ("READY", box.generation + 1)
    state = acf.sh(name, "cat /workspace/disk.txt /dev/shm/ram.txt; test ! -e /workspace/extra.txt && echo gone")
    assert state.stdout_text == "before\nbefore\ngone\n", f"the guest is not the machine that was captured: {state!r}"
    assert acf.python(name, BOOT_ID).stdout_text == boot_before, "a restore must RESUME the guest, not boot a new one"

    manifest = json.loads((host_env.snapshot_dir(snapshot) / "manifest.json").read_text())
    verified = [note for note in restored.notes if note.startswith("restore verified")]
    assert verified, f"the host does not say that it verified the restore: {restored.notes}"
    shown = verified[0].rsplit(" ", 1)[-1].rstrip("…")
    assert shown, verified
    assert shown in manifest["baseline_state_digest"], "the restore was verified against another baseline"

    fresh = acf.boot("booted", memory="256")
    assert acf.python(fresh.sandbox_id, BOOT_ID).stdout_text != boot_before, (
        "the boot id cannot tell a resumed guest from a booted one on this image"
    )


def test_t_res_05_a_marker_written_by_one_generation_is_unreadable_by_the_next(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    """T-RES-05: "a marker written by one generation is unreadable by the next, on disk and in memory backing".

    On the real host, as root (it reads the disk image in a generation's jail and the memory of the VMM process):
    generation 1 is captured clean and then writes a random marker to its disk and into memory. As a control the
    marker is first FOUND in generation 1's disk image and in its VMM's memory, so a search that finds nothing
    means something. Then the sandbox is restored in place. Pass: generation 1's directory and runtime are gone;
    the marker is neither in generation 2's disk image, nor in the memory file it was resumed from, nor in the
    memory of its VMM, nor in a file the guest of generation 2 can read.
    """
    require_root(host_env, "reading a generation's disk image and the memory of its VMM")
    marker = f"acf-it-marker-{secrets.token_hex(24)}"
    needle = marker.encode()
    box = acf.boot("residue", memory="128", disk="256")
    name = box.sandbox_id
    clean = acf.ok("snapshot", "create", name, "--name", acf.name("clean")).succeeded().snapshot_result()

    written = acf.sh(name, f"echo {marker} > /workspace/marker && echo {marker} > /dev/shm/marker && sync")
    assert written.succeeded()
    first = acf.wire.refresh(box)
    first_vmm = vmm_of(first)
    first_disk = host_env.jail_root(first) / "rootfs.ext4"
    assert file_contains(first_disk, needle), (
        "control: the marker is not in the disk image of the generation that wrote it"
    )
    assert memory_contains(first_vmm[0], needle), "control: the marker is not in the memory of the VMM that holds it"

    second = acf.ok("snapshot", "restore", clean.snapshot_id, "--into", name).succeeded().sandbox_result()
    second_vmm = vmm_of(second)
    assert second.generation == first.generation + 1
    assert not process_alive(*first_vmm), "the runtime of the superseded generation was reused or left running"
    assert not host_env.generation_dir(first).exists(), "the storage of the superseded generation still exists"

    jail = host_env.jail_root(second)
    assert not file_contains(jail / "rootfs.ext4", needle), "the new generation's disk holds the old one's marker"
    memory_file = jail / "snap.mem"
    if memory_file.exists():
        assert not file_contains(memory_file, needle), "the new generation's memory backing holds the old one's marker"
    assert not memory_contains(second_vmm[0], needle), "the new generation's guest memory holds the old one's marker"
    seen = acf.sh(name, "cat /workspace/marker /dev/shm/marker 2>/dev/null; echo end")
    assert seen.stdout_text == "end\n", "the guest of the new generation can read what the old one wrote"
