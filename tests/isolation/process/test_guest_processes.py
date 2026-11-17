"""Isolation, processes: the workload is an unprivileged guest and stays one (contract §18.4, §27.5, SEC-001, SEC-007).

``tests/integration/execution`` proves the limits: a fork bomb stops at ``pids.max``, a deadline kills the whole
tree, a daemonised child does not outlive its run. This suite proves the other half of "process-tree abuse": what a
hostile workload can reach *inside* the guest, because that is what stands between it and the guest agent, and the
guest agent is what the host trusts.

* it is uid/gid 1000 with no capabilities and cannot change that (no ``setuid``, ``chroot``, ``mount``, ``mknod``);
* it cannot signal, read or trace the guest's privileged processes (PID 1, the guest agent);
* it cannot lift or leave the cgroup that bounds it;
* its environment is exactly what the request gave it: the host's environment never reaches it;
* it inherits nothing from the agent but its three standard streams (no socket, no vsock, no leaked descriptor);
* whatever it does to the other processes it is allowed to signal, the guest stays usable;
* Ctrl-C on the CLI cancels the command *and* its whole tree.

Everything here needs a real guest (the in-memory host runs no processes), so none of it is ``control_plane``.
The probes are small Python programs run inside the guest (``python -c``); each prints one JSON document.
"""

from __future__ import annotations

import json
import time
import uuid

import pytest

from acf_driver import EXIT_INTERRUPTED, AcfLocal, wait_for

pytestmark = [pytest.mark.isolation, pytest.mark.usefixtures("clean_host")]

WORKLOAD_UID = 1000
NO_CAPABILITIES = "0000000000000000"
DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"  # execution/guest-agent/src/exec.rs

GUEST_IDENTITY = """
import ctypes, errno, json, os, stat
def status():
    return dict(line.split(':', 1) for line in open('/proc/self/status').read().splitlines() if ':' in line)
def tried(call):
    try:
        call()
        return 'allowed'
    except OSError as e:
        return errno.errorcode.get(e.errno or 0, type(e).__name__)
libc = ctypes.CDLL(None, use_errno=True)
def mount():
    if libc.mount(b'none', b'/tmp', b'tmpfs', 0, None) != 0:
        raise OSError(ctypes.get_errno(), 'mount')
st = status()
print(json.dumps({
    'ids': [os.getuid(), os.geteuid(), os.getgid(), os.getegid()],
    'uid_all': st['Uid'].split(),
    'gid_all': st['Gid'].split(),
    'groups': os.getgroups(),
    'caps': {k: st[k].strip() for k in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')},
    'setuid_root': tried(lambda: os.setuid(0)),
    'setgid_root': tried(lambda: os.setgid(0)),
    'setgroups': tried(lambda: os.setgroups([0])),
    'chroot': tried(lambda: os.chroot('/')),
    'mount': tried(mount),
    'mknod': tried(lambda: os.mknod('/tmp/acf-null', 0o600 | stat.S_IFCHR, os.makedev(1, 3))),
    'sysrq': tried(lambda: open('/proc/sysrq-trigger', 'w').write('h')),
    'kernel_log': tried(lambda: open('/dev/kmsg').read(1)),
    'dmesg_restrict': open('/proc/sys/kernel/dmesg_restrict').read().strip(),
    'kptr_restrict': open('/proc/sys/kernel/kptr_restrict').read().strip(),
}))
"""

GUEST_PRIVILEGED_PROCESSES = """
import errno, json, os, signal
def tried(call):
    try:
        call()
        return 'allowed'
    except OSError as e:
        return errno.errorcode.get(e.errno or 0, type(e).__name__)
def comm(pid):
    try:
        return open(f'/proc/{pid}/comm').read().strip()
    except OSError:
        return '?'
roots = [1]
for entry in os.listdir('/proc'):
    if not entry.isdigit() or int(entry) in (1, os.getpid()):
        continue
    try:
        owner = open(f'/proc/{entry}/status').read().split('Uid:')[1].split()[0]
    except (OSError, IndexError):
        continue
    if owner == '0':
        roots.append(int(entry))
result = {}
for pid in roots:
    result[str(pid)] = {
        'comm': comm(pid),
        'kill': tried(lambda: os.kill(pid, signal.SIGKILL)),
        'mem': tried(lambda: open(f'/proc/{pid}/mem', 'rb').read(1)),
        'environ': tried(lambda: open(f'/proc/{pid}/environ', 'rb').read(1)),
        'exe': tried(lambda: os.readlink(f'/proc/{pid}/exe')),
        'cwd': tried(lambda: os.readlink(f'/proc/{pid}/cwd')),
        'fds': tried(lambda: os.listdir(f'/proc/{pid}/fd')),
    }
print(json.dumps(result))
"""

GUEST_CGROUP_ESCAPE = """
import errno, json, os
def tried(call):
    try:
        call()
        return 'allowed'
    except OSError as e:
        return errno.errorcode.get(e.errno or 0, type(e).__name__)
mine = open('/proc/self/cgroup').read().strip().split(':', 2)[-1]
here = '/sys/fs/cgroup' + mine
print(json.dumps({
    'cgroup': mine,
    'lift_pids_max': tried(lambda: open(here + '/pids.max', 'w').write('max')),
    'leave_for_root': tried(lambda: open('/sys/fs/cgroup/cgroup.procs', 'w').write(str(os.getpid()))),
    'make_cgroup': tried(lambda: os.mkdir('/sys/fs/cgroup/escape')),
    'make_child_cgroup': tried(lambda: os.mkdir(here + '/escape')),
}))
"""

GUEST_ENVIRONMENT = "import json, os; print(json.dumps(dict(os.environ)))"

GUEST_DESCRIPTORS = """
import json, os
found = []
for name in os.listdir('/proc/self/fd'):
    try:
        found.append([int(name), os.readlink('/proc/self/fd/' + name)])
    except OSError:
        continue  # the descriptor of this very directory listing is already closed
print(json.dumps(sorted(found)))
"""

GUEST_KILL_EVERYTHING = """
import json, os, signal, subprocess
children = [subprocess.Popen(['sleep', '600']) for _ in range(3)]
os.kill(-1, signal.SIGKILL)  # every process this user may signal, except this one and PID 1
codes = [child.wait(timeout=30) for child in children]
print(json.dumps({'children_killed_by': codes}))
"""


def test_the_workload_is_an_unprivileged_user_with_no_capabilities(acf: AcfLocal) -> None:
    box = acf.boot("identity")
    assert box.name is not None
    seen = acf.python(box.name, GUEST_IDENTITY).stdout_json()
    assert seen["ids"] == [WORKLOAD_UID] * 4, f"the workload must run as uid/gid {WORKLOAD_UID}: {seen['ids']}"
    assert seen["uid_all"] == [str(WORKLOAD_UID)] * 4, "real, effective, saved and filesystem uid must all be the same"
    assert seen["gid_all"] == [str(WORKLOAD_UID)] * 4
    assert set(seen["groups"]) <= {WORKLOAD_UID}, f"no supplementary groups (disk, root, wheel ...): {seen['groups']}"
    assert seen["caps"] == dict.fromkeys(("CapInh", "CapPrm", "CapEff", "CapAmb"), NO_CAPABILITIES), seen["caps"]
    for attempt in ("setuid_root", "setgid_root", "setgroups", "chroot", "mount", "mknod", "sysrq"):
        assert seen[attempt] in {"EPERM", "EACCES"}, f"the workload could `{attempt}`: {seen[attempt]}"
    assert seen["kernel_log"] in {"EPERM", "EACCES", "ENOENT"}, f"the workload could read the kernel log: {seen}"
    assert seen["dmesg_restrict"] == "1", "acf-init must restrict the kernel log"
    assert seen["kptr_restrict"] == "2", "acf-init must hide kernel addresses"


def test_the_workload_cannot_signal_read_or_trace_the_guests_privileged_processes(acf: AcfLocal) -> None:
    box = acf.boot("privileged")
    assert box.name is not None
    seen = acf.python(box.name, GUEST_PRIVILEGED_PROCESSES).stdout_json()
    assert len(seen) >= 2, f"expected PID 1 and the guest agent among the root processes, saw only {seen}"
    # ESRCH/ENOENT: the process exited between being listed and being probed: it is not a way in
    safe = {"EPERM", "EACCES", "ESRCH", "ENOENT"}
    for pid, probes in seen.items():
        for what in ("kill", "mem", "environ", "exe", "cwd", "fds"):
            assert probes[what] in safe, f"the workload could {what} pid {pid} ({probes['comm']}): {probes[what]}"
    assert acf.sh(box.name, "echo alive").stdout == "alive\n", "the guest must still answer after the attempts"


def test_the_workload_cannot_lift_or_leave_the_cgroup_that_bounds_it(acf: AcfLocal) -> None:
    box = acf.boot("cgroup")
    assert box.name is not None
    seen = acf.python(box.name, GUEST_CGROUP_ESCAPE).stdout_json()
    assert seen["cgroup"] not in {"", "/"}, (
        "the command must run in a cgroup of its own (cgroup v2 containment); in the root cgroup there is no "
        f"pids.max to lift and this test proves nothing: {seen}"
    )
    for attempt in ("lift_pids_max", "leave_for_root", "make_cgroup", "make_child_cgroup"):
        assert seen[attempt] in {"EACCES", "EPERM", "EROFS"}, f"the workload could `{attempt}`: {seen[attempt]}"


def test_the_workload_environment_is_exactly_what_the_request_gave_it(
    acf: AcfLocal, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = f"acf-secret-{uuid.uuid4().hex}"
    monkeypatch.setenv("ACF_CANARY_SECRET", secret)  # in the CLI's environment: it must stay on the host
    box = acf.boot("environment")
    assert box.name is not None

    bare = acf.python(box.name, GUEST_ENVIRONMENT).stdout_json()
    assert bare == {"PATH": DEFAULT_PATH}, f"a command with no environment gets a default PATH and nothing else: {bare}"

    asked = acf.python(box.name, GUEST_ENVIRONMENT, env={"LANG": "C.UTF-8", "TZ": "UTC"}).stdout_json()
    assert asked == {"PATH": DEFAULT_PATH, "LANG": "C.UTF-8", "TZ": "UTC"}
    assert secret not in json.dumps([bare, asked]), "the host's environment reached the guest"

    custom = acf.python(box.name, GUEST_ENVIRONMENT, env={"PATH": "/usr/bin:/bin"}).stdout_json()
    assert custom == {"PATH": "/usr/bin:/bin"}, "a PATH the request sets must never be replaced"


def test_the_workload_inherits_nothing_from_the_guest_agent_but_its_standard_streams(acf: AcfLocal) -> None:
    box = acf.boot("descriptors")
    assert box.name is not None
    found = acf.python(box.name, GUEST_DESCRIPTORS).stdout_json()
    by_fd = dict(found)
    assert sorted(by_fd) == [0, 1, 2], f"the workload holds descriptors beyond stdin/stdout/stderr: {found}"
    assert by_fd[0] == "/dev/null", "stdin must be /dev/null: a workload has no terminal and no input channel"
    for fd in (1, 2):
        assert by_fd[fd].startswith("pipe:"), f"fd {fd} must be a pipe to the agent, not {by_fd[fd]}"
    assert not [t for t in by_fd.values() if t.startswith(("socket:", "anon_inode:"))], (
        "a socket or an eventfd leaked from the guest agent (a vsock connection to the host would be a control channel)"
    )


def test_a_workload_that_kills_everything_it_may_signal_only_hurts_itself(acf: AcfLocal) -> None:
    box = acf.boot("killall")
    assert box.name is not None
    seen = acf.python(box.name, GUEST_KILL_EVERYTHING, timeout="60s").stdout_json()
    assert seen["children_killed_by"] == [-9, -9, -9], (
        f"kill(-1, SIGKILL) must reach the workload's own processes: {seen}"
    )
    assert acf.workload_processes(box.name) == []
    assert acf.sh(box.name, "echo alive").stdout == "alive\n", "init and the guest agent must survive kill(-1)"
    assert acf.sandbox_inspect(box.name).state == "COMPLETED"


def test_an_interrupted_command_is_cancelled_with_its_whole_tree_and_the_sandbox_stays_usable(acf: AcfLocal) -> None:
    box = acf.boot("cancel")
    assert box.name is not None
    running = acf.spawn_exec(box.name, "sleep 600 & sleep 600 & wait", shell=True)
    try:
        wait_for(
            "the sandbox to be RUNNING the command",
            lambda: True if acf.sandbox_inspect(box.name or "").state == "RUNNING" else None,
            timeout=60,
        )
        time.sleep(2)  # a black-box test cannot ask a busy guest whether the command has started; give it a moment
        running.interrupt()
        done = running.wait(120)
    finally:
        running.kill()
    assert done.returncode == EXIT_INTERRUPTED, done.describe()
    doc = done.json()
    assert doc["interrupted"] is True
    assert doc["resolved"] is True, f"the CLI must learn how the cancelled run ended, not leave it unknown: {doc}"
    assert doc["run"]["outcome"] == "CANCELLED"
    assert acf.workload_processes(box.name) == [], "cancelling must kill the whole tree, not just the shell"
    assert acf.sh(box.name, "echo alive").stdout == "alive\n"
    assert acf.sandbox_inspect(box.name).state == "COMPLETED"
