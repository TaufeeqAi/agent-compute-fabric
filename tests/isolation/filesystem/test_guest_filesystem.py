"""Isolation, filesystem: the guest sees its own disk and nothing of the host's.

The claim is *absence*: there is no path from the workload to a host file, however clever the workload. Each test
asks the guest kernel (``/proc``, ``/sys``) what it has, because that is the only view the workload has too:

* exactly one block device (its own root disk) and no shared filesystem (9p, virtiofs, fuse, nfs ...);
* a canary file planted on the host is nowhere in the guest, and the guest is not the host (hostname differs);
* whatever the workload does to its disk, the installed image on the host stays byte-for-byte what its manifest
  says (the host never mounts, parses or resolves paths inside a guest-writable filesystem);
* the workload can write its workspace and scratch space and nothing else;
* nothing in the image lets the workload become root (no setuid/setgid files).

Everything here needs a real guest (evidence level L4). The probes are small Python programs run inside the guest
(``python -c``); each prints one JSON document.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from acf_driver import REPO, AcfLocal
from acf_integration import HostEnv, require_root

pytestmark = [pytest.mark.isolation, pytest.mark.usefixtures("clean_host")]

SHARING_FILESYSTEMS = {
    "9p",
    "virtiofs",
    "fuse",
    "fuseblk",
    "nfs",
    "nfs4",
    "cifs",
    "smb3",
    "vboxsf",
    "vmhgfs",
    "overlay",
}

GUEST_STORAGE = """
import json, os
mounts = [line.split() for line in open('/proc/mounts')]
print(json.dumps({
    'blocks': sorted(os.listdir('/sys/block')),
    'device_mounts': [[m[0], m[1], m[2]] for m in mounts if m[0].startswith('/dev/')],
    'fs_types': sorted({m[2] for m in mounts}),
    'hostname': os.uname().nodename,
    'dev_kvm': os.path.exists('/dev/kvm'),
    'serial': [p for p in ('/dev/ttyS0', '/dev/console') if os.path.exists(p) and os.access(p, os.R_OK | os.W_OK)],
}))
"""

# Looks for `sys.argv[1]` (a token that exists only on the host) in every file NAME below / and as an exact path.
GUEST_FIND_CANARY = """
import json, os, sys
token, host_path = sys.argv[1], sys.argv[2]
hits = []
for root, dirs, files in os.walk('/'):
    if root in ('/proc', '/sys', '/dev'):
        dirs[:] = []
        continue
    for name in dirs + files:
        if token in name:
            hits.append(os.path.join(root, name))
print(json.dumps({'hits': hits, 'host_path_exists': os.path.exists(host_path)}))
"""

# What the workload may and may not write.
GUEST_WRITES = """
import json, os
def attempt(path, how):
    try:
        if how == 'file':
            with open(path, 'w') as f:
                f.write('x')
            os.unlink(path)
        else:
            os.mkdir(path)
            os.rmdir(path)
        return 'ok'
    except OSError as e:
        return e.__class__.__name__
targets = {
    'workspace': ('/workspace/probe', 'file'),
    'tmp': ('/tmp/probe', 'file'),
    'shm': ('/dev/shm/probe', 'file'),
    'usr': ('/usr/local/bin/probe', 'file'),
    'etc': ('/etc/probe', 'file'),
    'passwd': ('/etc/passwd', 'file'),
    'boot': ('/boot/probe', 'file'),
    'root_dir': ('/probe', 'file'),
    'cgroup': ('/sys/fs/cgroup/probe', 'dir'),
    'hostname': ('/proc/sys/kernel/hostname', 'file'),
    'dev_node': ('/dev/probe', 'file'),
}
print(json.dumps({name: attempt(*spec) for name, spec in targets.items()}))
"""

GUEST_SETID_FILES = """
import json, os, stat
found = []
for top in ('/usr', '/bin', '/sbin', '/lib', '/lib64', '/opt', '/etc', '/var', '/home', '/root', '/srv', '/workspace'):
    for root, _dirs, files in os.walk(top):
        for name in files:
            path = os.path.join(root, name)
            try:
                mode = os.lstat(path).st_mode
            except OSError:
                continue
            if stat.S_ISREG(mode) and mode & (stat.S_ISUID | stat.S_ISGID):
                found.append(path)
print(json.dumps(found))
"""

# Scribbles as hard as an unprivileged workload can: deletes, truncates, floods the disk and tries the raw device.
GUEST_VANDAL = """
import os
for root, dirs, files in os.walk('/workspace'):
    for name in files:
        try:
            os.unlink(os.path.join(root, name))
        except OSError:
            pass
try:
    with open('/workspace/flood', 'wb') as f:
        for _ in range(64):
            f.write(b'\\x00' * (1 << 20))
except OSError:
    pass
for path in ('/dev/vda', '/dev/vda1', '/usr/bin/python3', '/usr/local/bin/python'):
    try:
        open(path, 'r+b').write(b'vandalised')
    except OSError:
        pass
print('done')
"""


def test_the_guest_has_one_block_device_and_no_shared_filesystem(acf: AcfLocal) -> None:
    box = acf.boot("storage")
    seen = acf.python(box.sandbox_id, GUEST_STORAGE).stdout_json()
    real_blocks = [b for b in seen["blocks"] if not b.startswith(("ram", "loop", "zram"))]
    assert real_blocks == ["vda"], f"the guest must see exactly its own virtio disk, not {seen['blocks']}"
    assert [(m[1], m[2]) for m in seen["device_mounts"]] == [("/", "ext4")], (
        f"the only filesystem backed by a device must be the root ext4: {seen['device_mounts']}"
    )
    assert not set(seen["fs_types"]) & SHARING_FILESYSTEMS, (
        f"a filesystem that can reach outside the VM is mounted: {seen['fs_types']}"
    )
    assert seen["dev_kvm"] is False, "the guest must not be able to start VMs of its own"
    assert seen["serial"] == [], f"the guest must have no serial channel to the VMM: {seen['serial']}"


def test_a_file_on_the_host_is_nowhere_in_the_guest(acf: AcfLocal, host_env: HostEnv, tmp_path: Path) -> None:
    require_root(host_env, "planting a canary in root's home directory")
    token = f"acf-canary-{uuid.uuid4().hex}"
    canary = tmp_path / token
    canary.write_text(token)
    other = Path("/root") / token  # a second place, in a directory the workload could never list anyway
    other.write_text(token)
    try:
        box = acf.boot("canary")
        seen = acf.python(
            box.sandbox_id, GUEST_FIND_CANARY, token, str(canary), options=["--time-limit", "120s"]
        ).stdout_json()
        assert seen["hits"] == [], f"a host file name appears in the guest: {seen['hits']}"
        assert seen["host_path_exists"] is False
        guest_name = acf.python(box.sandbox_id, "import os; print(os.uname().nodename)").stdout_text.strip()
        assert guest_name, "the guest must report a hostname"
        assert guest_name != socket.gethostname(), "the guest must not share the host's identity"
    finally:
        other.unlink(missing_ok=True)


def test_nothing_the_guest_does_to_its_disk_changes_the_installed_image(acf: AcfLocal, host_env: HostEnv) -> None:
    manifest = host_env.image_dir / "manifest.json"
    before = {p.name: (p.stat().st_size, p.stat().st_mtime_ns) for p in sorted(host_env.image_dir.iterdir())}
    manifest_bytes = manifest.read_bytes()

    box = acf.boot("vandal", disk="512")
    assert acf.python(box.sandbox_id, GUEST_VANDAL, options=["--time-limit", "120s"]).stdout_text == "done\n"
    acf.wire.destroy(acf.wire.refresh(box))

    assert manifest.read_bytes() == manifest_bytes
    assert {p.name: (p.stat().st_size, p.stat().st_mtime_ns) for p in sorted(host_env.image_dir.iterdir())} == before, (
        "the pristine image must never be opened for writing: sandboxes get a COPY"
    )
    verify = subprocess.run(
        [
            sys.executable,
            "-I",
            str(REPO / "tools" / "write_image_manifest.py"),
            "verify",
            "--dir",
            str(host_env.image_dir),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert verify.returncode == 0, (
        f"the installed image no longer matches its manifest:\n{verify.stdout}{verify.stderr}"
    )


def test_the_workload_writes_its_workspace_and_scratch_space_and_nothing_else(acf: AcfLocal) -> None:
    box = acf.boot("writes")
    seen = acf.python(box.sandbox_id, GUEST_WRITES).stdout_json()
    assert {k: seen[k] for k in ("workspace", "tmp", "shm")} == {"workspace": "ok", "tmp": "ok", "shm": "ok"}
    denied = {k: v for k, v in seen.items() if k not in {"workspace", "tmp", "shm"}}
    assert all(v in {"PermissionError", "FileNotFoundError", "OSError"} for v in denied.values()), (
        f"a path outside the workspace was writable: {denied}"
    )
    assert "ok" not in denied.values()


def test_the_image_contains_no_setuid_or_setgid_file(acf: AcfLocal) -> None:
    box = acf.boot("setid")
    found = acf.python(box.sandbox_id, GUEST_SETID_FILES, options=["--time-limit", "180s"]).stdout_json()
    assert found == [], f"the guest layer must strip every setuid/setgid bit, but these remain: {found}"
