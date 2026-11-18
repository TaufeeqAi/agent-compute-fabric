"""T-ENTRY-01: the entry conditions of the contract, observed on a real VMM and recorded.

The contract builds on boundaries of the substrate that hold "only to the extent they have been observed to
hold". Its three entry conditions are checked here against the installed release, on a production host:

E-1  the real-VMM suites have been executed on a KVM host and the results recorded. This test is part of those
     suites; what it observed goes into the test report (``record_property``) and, if ``ACF_ENTRY_RECORD`` names a
     file, into that file as JSON.
E-2  build inputs are pinned: the repository's own gate (``tools/check_pins.py --require-pinned``) passes, and the
     VMM that is installed is the release the configuration pins.
E-3  substrate behaviours the contract relies on are verified against that release: the VM is paused while a
     snapshot is taken; a restored VM does not depend on the snapshot's files afterwards; the jailer applies the
     confinement the host verifies.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from acf_driver import REPO, AcfLocal
from acf_integration import ENTRY_RECORD, HostEnv, require_root, vmm_of
from acf_proc import confinement, file_identities

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("clean_host")]


def _vm_state(api_socket: Path) -> str | None:
    """What the VMM itself says its state is (``GET /`` on its control socket), or ``None`` when it does not answer."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(15)
            connection.connect(str(api_socket))
            connection.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n\r\n")
            received = b""
            while b"\r\n\r\n" not in received or not received.rstrip().endswith(b"}"):
                chunk = connection.recv(4096)
                if not chunk:
                    break
                received += chunk
    except OSError:
        return None
    _, _, body = received.partition(b"\r\n\r\n")
    try:
        document = json.loads(body)
    except json.JSONDecodeError:
        return None
    return str(document.get("state")) if isinstance(document, dict) else None


def test_t_entry_01_the_entry_conditions_are_met_and_recorded(
    acf: AcfLocal, host_env: HostEnv, record_property: Callable[[str, object], None]
) -> None:
    """T-ENTRY-01: "E-1 to E-3 of §4.1 are met and recorded".

    On the real host, as root. It runs the repository's pin gate and the installed VMM's ``--version``; it asks
    the VMM of a sandbox for its own state through its control socket while a snapshot of a 1 GiB guest is taken;
    it compares the files a restored VMM holds open or mapped with the files of the snapshot it was restored from,
    deletes the snapshot and uses the restored guest again; and it reads the confinement of the VMM process from
    the kernel. Pass: the gate passes and the version is the pinned one; the VMM reports ``Paused`` during the
    capture and ``Running`` before and after; the restored VMM holds no file of the snapshot and works after the
    snapshot is deleted, as the backend declares; the VMM is confined (an unprivileged user of its own, no
    capabilities, a system-call filter on every thread, its own root directory and namespaces).
    """
    require_root(host_env, "reading the VMM's control socket, descriptors and status")
    record: dict[str, Any] = {
        "recorded_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "kernel": os.uname().release,
        "architecture": os.uname().machine,
    }

    # ---- E-2: pinned build inputs
    pins = subprocess.run(
        [sys.executable, "-I", str(REPO / "tools" / "check_pins.py"), "--require-pinned"],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    record["E-2"] = {"check_pins_exit": pins.returncode, "check_pins_output": (pins.stdout + pins.stderr)[-2000:]}
    assert pins.returncode == 0, f"build inputs are not pinned:\n{pins.stdout}{pins.stderr}"
    pinned = host_env.config.text("firecracker.pinned_version")
    version = subprocess.run(
        [host_env.config.text("firecracker.firecracker_bin"), "--version"],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    record["E-2"]["vmm_version"] = version.stdout.strip().splitlines()[:1]
    assert pinned.lstrip("v") in version.stdout, f"the installed VMM is not the pinned {pinned}: {version.stdout!r}"

    # ---- E-3: the VM is paused while a snapshot is taken
    box = acf.boot("entry", memory="1024")
    name = box.sandbox_id
    assert acf.sh(name, "echo kept > /dev/shm/kept").succeeded()
    api = host_env.jail_root(box) / "api.sock"
    assert _vm_state(api) == "Running", "control: the VMM does not report its state"
    states: list[str] = []
    capturing = threading.Event()

    def watch() -> None:
        while not capturing.is_set():
            state = _vm_state(api)
            if state is not None:
                states.append(state)
            time.sleep(0.01)

    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()
    try:
        snapshot = acf.ok("snapshot", "create", name, "--name", acf.name("entry")).succeeded().snapshot_result()
    finally:
        capturing.set()
        watcher.join(timeout=60)
    record["E-3"] = {"vmm_states_during_snapshot": sorted(set(states)), "observations": len(states)}
    assert "Paused" in states, f"the VMM was never seen paused while its snapshot was taken: {sorted(set(states))}"
    assert _vm_state(api) == "Running", "the guest was not resumed after the capture"

    # ---- E-3: a restored VM does not depend on the snapshot's files
    restored = acf.ok("snapshot", "restore", snapshot.snapshot_id, "--new", "--name", acf.name("restored"))
    clone = restored.succeeded().sandbox_result()
    clone_vmm = vmm_of(clone)[0]
    snapshot_files = {
        (item.stat().st_dev, item.stat().st_ino): item.name for item in host_env.snapshot_dir(snapshot).iterdir()
    }
    assert len(snapshot_files) >= 3, f"control: the snapshot has too few files to compare: {snapshot_files}"
    held = file_identities(clone_vmm)
    shared = sorted(snapshot_files[identity] for identity in snapshot_files if identity in held)
    declared = bool(acf.wire.info().capabilities["runtime_depends_on_snapshot"])
    record["E-3"]["restored_vmm_holds_snapshot_files"] = shared
    record["E-3"]["backend_declares_dependency"] = declared
    assert bool(shared) == declared, (
        f"the backend declares runtime_depends_on_snapshot={declared}, but the restored VMM holds {shared or 'none'} "
        "of the snapshot's files"
    )
    if not declared:
        assert (
            acf.ok("snapshot", "delete", snapshot.snapshot_id, "--yes").succeeded().snapshot_result().state == "DELETED"
        )
        assert not host_env.snapshot_dir(snapshot).exists()
        after = acf.sh(clone.sandbox_id, "cat /dev/shm/kept")
        assert after.stdout_text == "kept\n", "the restored guest lost memory when its snapshot was deleted"

    # ---- E-3: the confinement the jailer applies
    uid_range = (
        host_env.config.integer("firecracker.uid_range_start"),
        host_env.config.integer("firecracker.uid_range_size"),
    )
    facts = confinement(vmm_of(acf.wire.refresh(box))[0], compared_with=os.getpid())
    record["E-3"]["confinement"] = {
        "uids": facts.uids,
        "gids": facts.gids,
        "effective_capabilities": facts.effective_capabilities,
        "no_new_privs": facts.no_new_privs,
        "seccomp_by_thread": facts.seccomp_by_thread,
        "pid_namespace_depth": facts.pid_namespace_depth,
        "root": str(facts.root),
        "shared_namespaces": facts.shared_namespaces,
    }
    assert facts.violations(uid_range=uid_range) == [], f"the jailer's confinement does not hold: {facts}"
    assert facts.root == host_env.jail_root(box)

    # ---- E-1: recorded
    record["E-1"] = "observed by the real-VMM suites of this run; see the test report this record is part of"
    record_property("entry_conditions", json.dumps(record, sort_keys=True))
    destination = os.environ.get(ENTRY_RECORD)
    if destination:
        Path(destination).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
