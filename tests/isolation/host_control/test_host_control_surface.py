"""Isolation, host control surface: who may steer the host agent, and what the guest can reach of it
(contract §16, §17.2, §17.3, §27.5, §27.9; SEC-001 to SEC-004, SEC-008 to SEC-010, SEC-014).

Two directions, tested separately because they fail separately.

INWARD: who may give the host orders (``control_plane``: these also run, in CI, against the in-memory host loaded
with the shipped configuration and policy)
    The kernel, not the request, says who a caller is (SO_PEERCRED). A local process that cannot open the socket
    cannot connect; one that can is still refused by identity; the policy the host enforces is the file on disk and
    every run records its digest; a request the policy does not grant is refused before anything exists and is not
    a durable operation; the same operation id is idempotent for the same request and a conflict for another one;
    a peer speaking another protocol is refused rather than guessed at. The "other process" is a real client run
    as another uid (needs root), talking the wire protocol directly: the CLI is not the thing under test.

OUTWARD: what the guest can reach, and what the host-side confinement really is (a real microVM, white-box on the
host through ``/proc`` and cgroupfs, because the kernel is the only witness that cannot be talked into agreeing)
    The VMM runs as an unprivileged per-VM uid, jailed (chroot, PID, mount and empty network namespaces), under
    seccomp, in its own cgroup with the limits the contract promises; nothing of ACF listens on a network port;
    the state directory and the VMM's sockets are closed to other local users; the VMM holds no descriptor for the
    host's own state; and from inside the guest there is no path to the host agent, the Firecracker API, the host's
    vsock services or any device that is a control channel. The policy file's integrity is enforced at reload and a
    policy edit never changes a run that was already admitted.

Probes that run in the guest are small Python programs (``python -c``); each prints one JSON document.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from acf_driver import (
    EXIT_OK,
    EXIT_REFUSED,
    AcfLocal,
    new_operation_id,
    operation_ids,
    raw_call,
    wait_for,
)
from acf_integration import HostEnv, HostUnit
from acf_proc import (
    CGROUP_ROOT,
    cgroup_dir,
    cgroup_value,
    host_path,
    ids,
    inet_sockets,
    interfaces_in_namespace_of,
    namespace,
    proc_status,
    thread_statuses,
    unix_socket_paths,
)

pytestmark = [pytest.mark.isolation, pytest.mark.usefixtures("clean_host")]

UNPRIVILEGED = 65534  # "nobody": a local account that is neither root nor in any group the host agent trusts
NO_CAPABILITIES = "0000000000000000"
RESOURCES = {"vcpus": 1, "memory_mib": 256, "disk_mib": 1024, "network": "none"}
HOST_CID = 2

# What the guest may legitimately open read-write under /dev. Anything else is a way out or a way to attack the guest.
# `vsock` is the guest agent's own channel; the workload's use of it is attacked in the tests below.
HARMLESS_DEVICES = {"null", "zero", "full", "random", "urandom", "tty", "ptmx", "vsock"}

GUEST_REACH_THE_HOST = """
import errno, json, os, socket, stat, sys
host_socket = sys.argv[1]
def name(e):
    return errno.errorcode.get(e.errno or 0, type(e).__name__)
def connect(family, address):
    try:
        s = socket.socket(family, socket.SOCK_STREAM)
    except OSError as e:
        return 'socket:' + name(e)
    s.settimeout(3)
    try:
        s.connect(address)
        return 'CONNECTED'
    except OSError as e:
        return name(e)
    finally:
        s.close()
vsock = {}
if hasattr(socket, 'AF_VSOCK'):
    for port in (1, 22, 80, 443, 1024, 2049, 4000, 5000, 5252, 5253, 6000, 8080, 9999, 65535):
        vsock[str(port)] = connect(socket.AF_VSOCK, (2, port))  # CID 2 is the host
unix = {p: connect(socket.AF_UNIX, p) for p in (host_socket, '/run/acf/host-agent.sock', '/run/firecracker.socket')}
sockets = []
for top in ('/run', '/var', '/tmp', '/srv', '/opt', '/mnt', '/home', '/root', '/workspace', '/etc'):
    for root, _dirs, files in os.walk(top):
        for entry in _dirs + files:
            path = os.path.join(root, entry)
            try:
                if stat.S_ISSOCK(os.lstat(path).st_mode):
                    sockets.append(path)
            except OSError:
                pass
print(json.dumps({'vsock': vsock, 'unix': unix, 'sockets': sorted(sockets)}))
"""

GUEST_SELF_AGENT = """
import errno, fcntl, json, socket, struct
def local_cid():
    try:
        with open('/dev/vsock', 'rb') as device:
            buf = bytearray(4)
            fcntl.ioctl(device.fileno(), 0x7B9, buf, True)  # IOCTL_VM_SOCKETS_GET_LOCAL_CID
            return struct.unpack('I', buf)[0]
    except OSError:
        return None
result = {}
for label, cid in (('loopback_cid', getattr(socket, 'VMADDR_CID_LOCAL', 1)), ('own_cid', local_cid())):
    if cid is None:
        result[label] = 'no-cid'
        continue
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect((cid, 5252))  # the guest agent's own port
    except OSError as e:
        result[label] = 'blocked:' + errno.errorcode.get(e.errno or 0, type(e).__name__)
        continue
    request = json.dumps({'type': 'ping', 'nonce': 'intruder'}).encode()
    try:
        s.sendall(struct.pack('>I', len(request)) + request)
        reply = s.recv(4)
    except OSError as e:
        result[label] = 'dropped:' + errno.errorcode.get(e.errno or 0, type(e).__name__)
        continue
    finally:
        s.close()
    result[label] = 'SERVED' if reply else 'dropped:eof'
print(json.dumps(result))
"""

GUEST_DEVICES = """
import json, os, stat
DANGEROUS = ['kvm', 'mem', 'kmem', 'port', 'vhost-net', 'vhost-vsock', 'fuse', 'net/tun', 'vda', 'vdb', 'sda',
             'loop-control', 'uinput']
accessible = []
for name in sorted(os.listdir('/dev')):
    path = '/dev/' + name
    try:
        mode = os.lstat(path).st_mode
    except OSError:
        continue
    if (stat.S_ISCHR(mode) or stat.S_ISBLK(mode)) and os.access(path, os.R_OK | os.W_OK):
        accessible.append(name)
dangerous = [d for d in DANGEROUS if os.path.exists('/dev/' + d) and os.access('/dev/' + d, os.R_OK | os.W_OK)]
print(json.dumps({'accessible': accessible, 'dangerous': dangerous}))
"""


# ====================================================================================== INWARD: who may give orders
@pytest.mark.control_plane
def test_a_local_process_without_access_to_the_socket_cannot_even_connect(acf: AcfLocal) -> None:
    _needs_root()
    assert acf.socket is not None
    for method in ("host_info", "sandbox_list"):
        answer = raw_call(acf.socket, method, user=UNPRIVILEGED)
        assert answer.connect == "PermissionError:13", f"uid {UNPRIVILEGED} must not be able to connect: {answer}"
        assert answer.frames == []


@pytest.mark.control_plane
def test_a_local_process_that_reaches_the_socket_is_still_refused_by_the_hosts_own_identity_check(
    acf: AcfLocal,
) -> None:
    """Layer two: the file permissions are loosened for the duration of the test so that only the host's check stands."""
    _needs_root()
    assert acf.socket is not None
    before = int(acf.metrics()["counters"].get("auth_denied", 0))
    create = {"image": acf.image, "resources": RESOURCES}
    with _reachable_by_everyone(acf.socket):
        answers = {
            "sandbox_create": raw_call(
                acf.socket, "sandbox_create", create, operation_id=new_operation_id(), user=UNPRIVILEGED
            ),
            "host_info": raw_call(acf.socket, "host_info", user=UNPRIVILEGED),
            "policy_reload": raw_call(acf.socket, "policy_reload", user=UNPRIVILEGED),
        }
    for method, answer in answers.items():
        assert answer.connected, f"{method}: the test must reach the host for this to mean anything: {answer}"
        assert answer.status == "REJECTED", f"{method}: {answer.frames}"
        assert answer.error is not None
        assert answer.error["class"] == "AUTHORIZATION", f"{method}: {answer.error}"
        assert answer.error["side_effect"] == "none"
        assert f"uid {UNPRIVILEGED}" in answer.error["message"]
        assert answer.reply["result"] is None, f"{method}: a refused caller must receive no data"
    assert acf.sandbox_list() == [], "a refused caller created something"
    assert acf.host_info()["live_sandboxes"] == 0
    assert int(acf.metrics()["counters"]["auth_denied"]) == before + len(answers), "every refusal must be counted"


@pytest.mark.control_plane
def test_the_policy_in_force_is_the_file_on_disk_and_every_run_records_its_digest(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    digest = hashlib.sha256(host_env.policy_path.read_bytes()).hexdigest()
    policy = acf.host_info()["policy"]
    assert policy["digest"] == digest, "the host must be running the policy file it says it loaded"
    assert policy["name"]
    assert policy["version"]
    run = acf.run(["true"]).run
    assert run["policy_id"]["digest"] == digest, "a run must record the policy it was admitted under"


@pytest.mark.control_plane
@pytest.mark.parametrize(
    ("options", "message"),
    [
        pytest.param(["--env", "LD_PRELOAD=/tmp/x.so"], "is not on the policy allowlist", id="env-ld-preload"),
        pytest.param(["--env", "PYTHONPATH=/tmp"], "is not on the policy allowlist", id="env-pythonpath"),
        pytest.param(["--cwd", "/etc"], "outside the permitted directories", id="cwd-outside-the-prefixes"),
        pytest.param(["--cwd", "../x"], "outside the permitted directories", id="cwd-relative"),
        pytest.param(["--timeout", "2h"], "exceeds the policy ceiling", id="timeout-above-the-ceiling"),
    ],
)
def test_a_command_the_policy_does_not_grant_is_refused_before_anything_exists(
    acf: AcfLocal, options: list[str], message: str
) -> None:
    box = acf.boot("deny")
    assert box.name is not None
    before = acf.sandbox_inspect(box.name)
    refused = acf.call("exec", box.name, *options, "--json", "--", "true")
    assert refused.returncode == EXIT_REFUSED, refused.describe()
    assert message in refused.stderr, refused.describe()

    after = acf.sandbox_inspect(box.name)
    assert (after.state, after.generation, after.get("last_run")) == (
        before.state,
        before.generation,
        before.get("last_run"),
    ), "a refused command must not change the sandbox"
    named = operation_ids(refused.stderr)
    assert named, "the refusal should name the operation id it was sent under"
    for operation in named:
        gone = acf.operation_get(operation)
        assert gone.returncode == EXIT_REFUSED, f"a refused request must not be a durable operation: {gone.describe()}"


@pytest.mark.control_plane
def test_a_create_the_policy_does_not_grant_is_refused_before_anything_exists(acf: AcfLocal) -> None:
    assert acf.socket is not None
    operation = new_operation_id()
    unlisted = raw_call(
        acf.socket,
        "sandbox_create",
        {"image": "no-such-image", "resources": RESOURCES},
        operation_id=operation,
    )
    assert unlisted.status == "REJECTED"
    assert unlisted.error is not None
    assert unlisted.error["class"] == "AUTHORIZATION"
    assert unlisted.error["side_effect"] == "none"
    assert "not permitted by policy" in unlisted.error["message"]
    assert acf.operation_get(operation).returncode == EXIT_REFUSED, "a refusal must not leave an operation record"

    too_big = raw_call(
        acf.socket,
        "sandbox_create",
        {"image": acf.image, "resources": {**RESOURCES, "vcpus": 8}},
        operation_id=new_operation_id(),
    )
    assert too_big.status == "REJECTED"
    assert too_big.error is not None
    assert too_big.error["class"] == "ADMISSION_REJECTED", "above a ceiling is an admission refusal, never a clamp"
    assert acf.sandbox_list() == []


@pytest.mark.control_plane
def test_an_operation_id_is_idempotent_for_one_request_and_a_conflict_for_any_other(acf: AcfLocal) -> None:
    assert acf.socket is not None
    params = {"image": acf.image, "resources": RESOURCES}
    operation = new_operation_id()
    first = raw_call(acf.socket, "sandbox_create", params, operation_id=operation)
    assert first.status == "SUCCEEDED", first.frames
    sandbox_id = first.reply["result"]["data"]["sandbox_id"]

    again = raw_call(acf.socket, "sandbox_create", params, operation_id=operation)
    assert again.status == "SUCCEEDED", again.frames
    assert again.reply["result"]["data"]["sandbox_id"] == sandbox_id, "a replay must return the original result"
    assert [s.sandbox_id for s in acf.sandbox_list()] == [sandbox_id], "a replay must not create a second sandbox"

    different = raw_call(
        acf.socket,
        "sandbox_create",
        {**params, "resources": {**RESOURCES, "vcpus": 2}},
        operation_id=operation,
    )
    assert different.status == "CONFLICT", different.frames
    assert different.error is not None
    assert different.error["class"] == "STATE_CONFLICT"
    assert "already used for a different request" in different.error["message"]
    assert [s.sandbox_id for s in acf.sandbox_list()] == [sandbox_id], "a conflicting request must change nothing"
    assert acf.operation_get(operation).returncode == EXIT_OK, "the original operation stays on record"


@pytest.mark.control_plane
def test_a_peer_speaking_another_protocol_version_is_refused_not_guessed_at(acf: AcfLocal) -> None:
    assert acf.socket is not None
    other = raw_call(acf.socket, "host_info", protocol="acf.host/2")
    assert other.status == "REJECTED"
    assert other.error is not None
    assert other.error["class"] == "SCHEMA_MISMATCH"
    assert "acf.host/1" in other.error["message"], "the refusal must say which version the host does speak"
    assert raw_call(acf.socket, "host_info").status == "SUCCEEDED", "a refused peer must not harm the host"


# =============================================================== OUTWARD, host side: what confines the VMM (real host)
def test_the_vmm_runs_unprivileged_in_its_own_jail_and_without_a_network(acf: AcfLocal) -> None:
    low, size = _uid_range()
    boxes = [acf.boot("jail-a"), acf.boot("jail-b")]
    seen: list[int] = []
    for box in boxes:
        assert box.vmm_identity is not None
        pid = box.vmm_identity[0]
        status = proc_status(pid)
        uid, gid = ids(status, "Uid"), ids(status, "Gid")
        assert len(set(uid)) == 1, f"real, effective, saved and filesystem uid of the VMM must agree: {uid}"
        assert low <= uid[0] < low + size, f"the VMM must run as a per-VM uid in [{low}, {low + size}): {uid}"
        assert gid == uid, f"the per-VM gid must equal its uid: uid {uid}, gid {gid}"
        assert status["CapEff"] == NO_CAPABILITIES
        assert status["CapPrm"] == NO_CAPABILITIES
        assert status["NoNewPrivs"] == "1"
        filtered = {t["Name"]: t["Seccomp"] for t in thread_statuses(pid).values() if t["Name"].startswith("fc_")}
        assert filtered, f"no fc_* thread: is pid {pid} really Firecracker? threads: {thread_statuses(pid)}"
        assert {n: s for n, s in filtered.items() if s != "2"} == {}, (
            f"every Firecracker thread needs seccomp: {filtered}"
        )
        assert len(status["NSpid"].split()) >= 2, "the VMM must live in a PID namespace of its own"
        assert Path(f"/proc/{pid}/root").readlink() != Path("/"), "the VMM must be chrooted"
        for kind in ("net", "pid", "mnt"):
            assert namespace(pid, kind) != namespace(os.getpid(), kind), f"the VMM shares our {kind} namespace"
        assert interfaces_in_namespace_of(pid) == ["lo"], "its network namespace must hold loopback and nothing else"
        seen.append(uid[0])
    assert seen[0] != seen[1], "two VMs must never share a uid"


def test_the_vmm_is_confined_by_its_own_cgroup(acf: AcfLocal, host_env: HostEnv) -> None:
    first, second = acf.boot("cg-a", cpu=2, memory="512"), acf.boot("cg-b", cpu=2, memory="512")
    assert first.vmm_identity is not None
    assert second.vmm_identity is not None
    one, other = cgroup_dir(first.vmm_identity[0]), cgroup_dir(second.vmm_identity[0])
    assert one != other, "two VMs must not share a cgroup"
    for directory in (one, other):
        assert directory != CGROUP_ROOT
        expected = {
            "memory.max": str((512 + host_env.vmm_overhead_mib) * 1024 * 1024),
            "memory.swap.max": "0",
            "memory.oom.group": "1",
            "pids.max": str(2 + 32),
            "cpu.max": f"{2 * 100_000 + 25_000} 100000",
        }
        assert {name: cgroup_value(directory, name) for name in expected} == expected, directory


def test_no_acf_process_listens_on_a_network_port(acf: AcfLocal, host_unit: HostUnit) -> None:
    box = acf.boot("ports")
    assert box.vmm_identity is not None
    host_pid, vmm_pid = host_unit.main_pid(), box.vmm_identity[0]
    assert acf.socket is not None
    assert acf.socket in unix_socket_paths(host_pid), (
        "the probe must see the host agent's control socket, or it would also see 'nothing' on a broken reader"
    )
    found = {"acf-host": [str(s) for s in inet_sockets(host_pid)], "vmm": [str(s) for s in inet_sockets(vmm_pid)]}
    assert found == {"acf-host": [], "vmm": []}, f"ACF must not open a TCP/UDP/raw socket anywhere: {found}"


def test_the_state_directory_is_closed_to_other_users(acf: AcfLocal, host_env: HostEnv) -> None:
    box = acf.boot("modes")
    assert box.name is not None
    acf.snapshot_create(acf.name("modes-snap"), box.name)  # so that a snapshot directory exists too
    root = host_env.state_root
    assert (root.stat().st_uid, stat.S_IMODE(root.stat().st_mode)) == (0, 0o700), f"{root} must be 0700 root-owned"

    loose: list[str] = []
    for directory, dirs, _files in os.walk(root):
        here = Path(directory)
        if here.name == "images":  # operator-installed inputs; the host only reads them
            dirs[:] = []
            continue
        if here.name == "jail":  # the VMM's own chroot: its modes are the jailer's, and the tests above check it
            dirs[:] = []
        mode = stat.S_IMODE(here.stat().st_mode)
        if mode & 0o077:
            loose.append(f"{here} {mode:04o}")
    assert loose == [], "directories the host keeps must be closed to group and others:\n  " + "\n  ".join(loose)

    for private in (root / "state" / "journal.wal", root / "state" / "host-agent.lock"):
        if private.exists():
            assert stat.S_IMODE(private.stat().st_mode) & 0o077 == 0, f"{private} must be 0600"
    control = Path(acf.socket or "")
    assert stat.S_ISSOCK(control.stat().st_mode)
    assert control.stat().st_mode & 0o007 == 0, "the control socket must not be open to everyone"


def test_the_vmms_sockets_are_unreachable_to_other_local_users(acf: AcfLocal) -> None:
    _needs_root()
    box = acf.boot("sockets")
    assert box.vmm_identity is not None
    pid = box.vmm_identity[0]
    inside = [p for p in unix_socket_paths(pid) if p.startswith("/")]
    assert inside, f"the VMM must bind its API socket; saw {unix_socket_paths(pid)}"
    verdict = {
        str(host_path(pid, p)): raw_call(str(host_path(pid, p)), "host_info", user=UNPRIVILEGED, patience=3).connect
        for p in inside
    }
    assert set(verdict.values()) == {"PermissionError:13"}, f"another local user could reach a VMM socket: {verdict}"


def test_the_vmm_holds_no_descriptor_for_the_hosts_own_state(acf: AcfLocal, host_env: HostEnv) -> None:
    box = acf.boot("inherit")
    assert box.vmm_identity is not None
    pid = box.vmm_identity[0]
    config = Path(os.environ.get("ACF_HOST_CONFIG", "/etc/acf/host.yaml"))
    secrets = [
        host_env.state_root,
        host_env.state_root / "state",
        host_env.state_root / "state" / "journal.wal",
        host_env.state_root / "state" / "host-agent.lock",
        host_env.state_root / "images",
        host_env.state_root / "snapshots",
        host_env.state_root / "artifacts",
        host_env.policy_path,
        config,
    ]
    forbidden = {(p.stat().st_dev, p.stat().st_ino): str(p) for p in secrets if p.exists()}
    assert forbidden, "the probe found none of the host's files to look for: wrong ACF_STATE_ROOT?"
    leaked: list[str] = []
    for fd in sorted((Path("/proc") / str(pid) / "fd").iterdir(), key=lambda p: int(p.name)):
        try:
            seen = fd.stat()
        except OSError:
            continue  # a socket or pipe has no path to stat, or the descriptor closed meanwhile
        found = forbidden.get((seen.st_dev, seen.st_ino))
        if found:
            leaked.append(f"fd {fd.name} -> {found}")
    assert leaked == [], f"the VMM inherited descriptors for the host's own state: {leaked}"


# ====================================================================== OUTWARD, guest side: what the guest can reach
def test_the_guest_cannot_reach_the_host_agent_the_vmm_api_or_the_hosts_vsock_services(acf: AcfLocal) -> None:
    box = acf.boot("reach")
    assert box.name is not None
    assert acf.socket is not None
    seen = acf.python(box.name, GUEST_REACH_THE_HOST, acf.socket, timeout="180s").stdout_json()
    assert "CONNECTED" not in seen["vsock"].values(), f"the guest connected to a service on the host: {seen['vsock']}"
    assert set(seen["unix"].values()) == {"ENOENT"}, (
        f"the host's sockets must not exist in the guest's filesystem: {seen['unix']}"
    )
    named_like_ours = [p for p in seen["sockets"] if "host-agent" in p or "firecracker" in p]
    assert named_like_ours == [], f"a control socket appears in the guest's filesystem: {named_like_ours}"


def test_the_guest_agent_obeys_only_the_host(acf: AcfLocal) -> None:
    """The agent accepts a connection only from the host's vsock CID; the workload, inside the guest, is not the host."""
    box = acf.boot("agent-peer")
    assert box.name is not None
    seen = acf.python(box.name, GUEST_SELF_AGENT, timeout="120s").stdout_json()
    assert "SERVED" not in seen.values(), f"the guest agent served a request from inside the guest: {seen}"
    assert acf.sh(box.name, "echo alive").stdout == "alive\n"


def test_the_guest_has_no_device_that_is_a_control_channel(acf: AcfLocal) -> None:
    box = acf.boot("devices")
    assert box.name is not None
    seen = acf.python(box.name, GUEST_DEVICES).stdout_json()
    assert seen["dangerous"] == [], (
        f"the workload can open a device that reaches the host or the disk: {seen['dangerous']}"
    )
    unexpected = sorted(set(seen["accessible"]) - HARMLESS_DEVICES)
    assert unexpected == [], (
        f"device nodes the workload can read and write beyond {sorted(HARMLESS_DEVICES)}: {unexpected}. If one is "
        "harmless, add it to HARMLESS_DEVICES with the reason; if not, the image must not ship it."
    )


# ============================================================ the policy file: integrity and immutability (real host)
def test_a_policy_file_that_fails_its_integrity_check_is_never_loaded(acf: AcfLocal, host_env: HostEnv) -> None:
    _needs_root()
    path = host_env.policy_path
    original = path.stat()
    parked = path.with_name(path.name + ".acf-test-parked")
    digest = acf.host_info()["policy"]["digest"]

    def refused(fragment: str) -> None:
        reload = acf.call("host", "reload-policy", "--json")
        assert reload.returncode != EXIT_OK, f"a policy that fails its integrity check was loaded: {reload.describe()}"
        assert fragment in reload.stderr, reload.describe()
        assert acf.host_info()["policy"]["digest"] == digest, "a refused reload must leave the old policy in force"

    try:
        os.chmod(path, stat.S_IMODE(original.st_mode) | 0o022)
        refused("writable")
        os.chmod(path, stat.S_IMODE(original.st_mode))

        os.chown(path, UNPRIVILEGED, UNPRIVILEGED)
        refused("not trusted")
        os.chown(path, original.st_uid, original.st_gid)

        path.rename(parked)
        path.symlink_to(parked)
        refused("safely")
        path.unlink()
        parked.rename(path)

        assert acf.call("host", "reload-policy", "--json").returncode == EXIT_OK, "the untouched file must load again"
    finally:
        if path.is_symlink():
            path.unlink()
        if parked.exists():
            parked.rename(path)
        os.chown(path, original.st_uid, original.st_gid)
        os.chmod(path, stat.S_IMODE(original.st_mode))


def test_a_policy_edit_never_changes_a_run_that_was_already_admitted(acf: AcfLocal, host_env: HostEnv) -> None:
    path = host_env.policy_path
    original = path.read_bytes()
    admitted_under = hashlib.sha256(original).hexdigest()
    box = acf.boot("policy-edit")
    assert box.name is not None
    running = acf.spawn_exec(box.name, "sleep 8; echo finished", shell=True)
    try:
        wait_for(
            "the command to be running",
            lambda: True if acf.sandbox_inspect(box.name or "").state == "RUNNING" else None,
            timeout=60,
        )
        edited = original + f"\n# edited while a run was in flight: {uuid.uuid4().hex}\n".encode()
        path.write_bytes(edited)  # same inode, same owner and mode: only the content changes
        reloaded = acf.call("host", "reload-policy", "--json").require_exit(EXIT_OK).json()
        now = hashlib.sha256(edited).hexdigest()
        assert reloaded["policy"]["digest"] == now, (
            "an administrator's reload must switch the policy for NEW operations"
        )
        done = running.wait(120)
        later = acf.sh(box.name, "true")
    finally:
        running.kill()
        path.write_bytes(original)
        acf.call(
            "host", "reload-policy", "--json"
        )  # best effort: leave the machine on the policy it was installed with
    assert done.returncode == EXIT_OK, done.describe()
    assert done.json()["run"]["policy_id"]["digest"] == admitted_under, (
        "the run in flight must keep the policy it was admitted under"
    )
    assert later["policy_id"]["digest"] == now, "an operation admitted after the reload must use the new policy"
    assert admitted_under != now


# ------------------------------------------------------------------------------------------------------- helpers
def _needs_root() -> None:
    """These tests run a client as another uid. Unprivileged they skip, unless ``ACF_REQUIRE_ROOT=1`` (CI) makes that a failure."""
    if os.geteuid() == 0:
        return
    if os.environ.get("ACF_REQUIRE_ROOT") == "1":
        pytest.fail("ACF_REQUIRE_ROOT=1, but this process is not root: run it with sudo", pytrace=False)
    pytest.skip("this test runs a client as another uid, which needs root")


@contextmanager
def _reachable_by_everyone(socket_path: str) -> Iterator[None]:
    """Let any local user ``connect()`` to the socket for a moment, so the host's own identity check is what is tested.

    The socket (read and write for others) and every directory above it that others cannot search are loosened, and
    restored exactly in ``finally``.
    """
    path = Path(socket_path)
    saved: list[tuple[Path, int]] = []
    for target in (path, *path.parents):
        mode = stat.S_IMODE(target.stat().st_mode)
        needed = 0o006 if target == path else 0o001
        if mode & needed != needed:
            saved.append((target, mode))
            target.chmod(mode | needed)
    try:
        yield
    finally:
        for target, mode in reversed(saved):
            target.chmod(mode)


def _uid_range() -> tuple[int, int]:
    """(first uid, how many) of the per-VM uid range, from the host's config (shipped defaults when unreadable)."""
    config = Path(os.environ.get("ACF_HOST_CONFIG", "/etc/acf/host.yaml"))
    text = config.read_text() if config.is_file() else ""
    start = re.search(r"^\s*uid_range_start:\s*(\d+)", text, re.MULTILINE)
    size = re.search(r"^\s*uid_range_size:\s*(\d+)", text, re.MULTILINE)
    return (int(start.group(1)) if start else 100_000, int(size.group(1)) if size else 4096)
