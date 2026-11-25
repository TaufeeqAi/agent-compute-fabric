"""Isolation, processes: the workload is an unprivileged guest and stays one, and its VMM stays confined.

``tests/integration/execution`` proves the limits: a fork bomb stops at its process limit, a deadline ends the whole
tree, a daemonised child does not outlive its execution. This suite proves the other half of "process-tree abuse":
what a hostile workload can reach *inside* the guest, because that is what stands between it and the guest agent,
and what happens on the HOST when one of the controls around its VMM is missing or is taken away.

* the workload runs as the unprivileged identity the profile names, with no capabilities, and cannot change that
  (no ``setuid``, ``chroot``, ``mount``, ``mknod``);
* it cannot signal, read or trace the guest's privileged processes (PID 1, the guest agent);
* it cannot lift or leave the control group that bounds it;
* its environment is exactly what the request gave it: the host's environment never reaches it;
* it inherits nothing from the agent but its three standard streams;
* whatever it does to the processes it may signal, the guest stays usable;
* an interrupted client cancels the command *and* its whole tree;
* T-SEC-04: a mandatory control missing at launch ends the VMM before it is configured;
* T-SEC-07, for the jailer: one replaced under a running host is refused before it is run;
* T-SEC-05: a limit raised or a filter removed after launch stops the generation within the recheck interval.

Everything here needs a real guest and a real VMM (evidence level L4). The guest-side probes are small Python
programs run inside the guest (``python -c``); each prints one JSON document.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from acf_driver import EXIT_FAILED, EXIT_INTERRUPTED, AcfLocal, new_operation_id
from acf_integration import (
    DEFAULT_CONFIG,
    HostEnv,
    HostUnit,
    await_sandbox,
    in_namespace,
    require_root,
    seconds_until_gone,
    vmm_of,
)
from acf_proc import pids_with_argument

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

# The environment the command was started with, as the kernel recorded it at exec: not `os.environ`, which
# Python changes at startup (in the C locale it adds LC_CTYPE=C.UTF-8 itself, PEP 538). Found on a real guest.
GUEST_ENVIRONMENT = (
    "import json; raw = open('/proc/self/environ', 'rb').read().decode(); "
    "print(json.dumps(dict(e.split('=', 1) for e in raw.split(chr(0)) if e)))"
)

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


def test_the_workload_is_an_unprivileged_user_with_no_capabilities(acf: AcfLocal, host_env: HostEnv) -> None:
    assert host_env.profile.integer("execution.guest_uid") == WORKLOAD_UID, "this suite assumes the shipped identity"
    assert host_env.profile.integer("execution.guest_gid") == WORKLOAD_UID
    box = acf.boot("identity")
    seen = acf.python(box.sandbox_id, GUEST_IDENTITY).stdout_json()
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
    seen = acf.python(box.sandbox_id, GUEST_PRIVILEGED_PROCESSES).stdout_json()
    assert len(seen) >= 2, f"expected PID 1 and the guest agent among the root processes, saw only {seen}"
    # ESRCH/ENOENT: the process exited between being listed and being probed: it is not a way in
    safe = {"EPERM", "EACCES", "ESRCH", "ENOENT"}
    for pid, probes in seen.items():
        for what in ("kill", "mem", "environ", "exe", "cwd", "fds"):
            assert probes[what] in safe, f"the workload could {what} pid {pid} ({probes['comm']}): {probes[what]}"
    assert acf.sh(box.sandbox_id, "echo alive").stdout_text == "alive\n", (
        "the guest must still answer after the attempts"
    )


def test_the_workload_cannot_lift_or_leave_the_cgroup_that_bounds_it(acf: AcfLocal) -> None:
    box = acf.boot("cgroup")
    seen = acf.python(box.sandbox_id, GUEST_CGROUP_ESCAPE).stdout_json()
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
    monkeypatch.setenv("ACF_CANARY_SECRET", secret)  # in the client's environment: it must stay on the host
    box = acf.boot("environment")

    bare = acf.python(box.sandbox_id, GUEST_ENVIRONMENT).stdout_json()
    assert bare == {"PATH": DEFAULT_PATH}, f"a command with no environment gets a default PATH and nothing else: {bare}"

    asked = acf.python(
        box.sandbox_id, GUEST_ENVIRONMENT, options=["--env", "LANG=C.UTF-8", "--env", "TZ=UTC"]
    ).stdout_json()
    assert asked == {"PATH": DEFAULT_PATH, "LANG": "C.UTF-8", "TZ": "UTC"}
    assert secret not in json.dumps([bare, asked]), "the host's environment reached the guest"

    custom = acf.python(
        box.sandbox_id, GUEST_ENVIRONMENT, options=["--env", "PATH=/usr/local/bin:/usr/bin"]
    ).stdout_json()
    assert custom == {"PATH": "/usr/local/bin:/usr/bin"}, "a PATH the request sets must never be replaced"


def test_the_workload_inherits_nothing_from_the_guest_agent_but_its_standard_streams(acf: AcfLocal) -> None:
    box = acf.boot("descriptors")
    found = acf.python(box.sandbox_id, GUEST_DESCRIPTORS).stdout_json()
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
    seen = acf.python(box.sandbox_id, GUEST_KILL_EVERYTHING, options=["--time-limit", "60s"]).stdout_json()
    assert seen["children_killed_by"] == [-9, -9, -9], (
        f"kill(-1, SIGKILL) must reach the workload's own processes: {seen}"
    )
    assert acf.workload_processes(box.sandbox_id) == []
    assert acf.sh(box.sandbox_id, "echo alive").stdout_text == "alive\n", (
        "init and the guest agent must survive kill(-1)"
    )
    assert acf.wire.refresh(box).state == "COMPLETED"


def test_an_interrupted_command_is_cancelled_with_its_whole_tree_and_the_sandbox_stays_usable(acf: AcfLocal) -> None:
    """§18.2 of the contract: a cancel confirmed by the guest -> operation ``CANCELLED`` by ``CALLER``, run
    ``CANCELLED``, generation ``COMPLETED``. An interrupted client asks for exactly that cancel."""
    box = acf.boot("cancel")
    operation_id = new_operation_id()
    running = acf.spawn(
        "sandbox", "exec", box.sandbox_id, "--operation-id", operation_id, "--shell", "--command",
        "sleep 600 & sleep 600 & wait",
    )  # fmt: skip
    try:
        await_sandbox(acf, box, lambda seen: seen.state == "RUNNING", within=60, what="the command starting")
        time.sleep(2)  # a black-box test cannot ask a busy guest whether the shell has forked yet; give it a moment
        running.interrupt()
        done = running.wait(120)
    finally:
        running.kill()
    assert done.returncode == EXIT_INTERRUPTED, done.describe()
    # The client asks for the cancel and exits; the host completes it once the guest confirms.
    deadline = time.monotonic() + 60
    operation = acf.wire.operation(operation_id)
    while operation.state in {"ACCEPTED", "IN_PROGRESS"} and time.monotonic() < deadline:
        time.sleep(0.5)
        operation = acf.wire.operation(operation_id)
    assert (operation.state, operation.cancelled_by) == ("CANCELLED", "CALLER"), operation
    assert operation.run_id is not None
    assert acf.ok("run", "inspect", operation.run_id).run().status == "CANCELLED"
    assert acf.workload_processes(box.sandbox_id) == [], "cancelling must end the whole tree, not just the shell"
    assert acf.sh(box.sandbox_id, "echo alive").stdout_text == "alive\n"
    assert acf.wire.refresh(box).state == "COMPLETED"


# ============================================================================================ the VMM's confinement
#: Each wrapper stands in for the jailer and takes one mandatory control away from the VMM it launches.
JAILER_WRAPPERS = {
    # the VMM's own flag for running without its system-call filter, appended to the VMM's arguments
    "no_seccomp": """#!/bin/sh
# acf integration suites, T-SEC-04: removed when the test ends
for a in "$@"; do
    if [ "$a" = "--" ]; then exec "{real}" "$@" --no-seccomp; fi
done
exec "{real}" "$@" -- --no-seccomp
""",
    # another user than the one the host reserved for this generation
    "other_uid": """#!/bin/sh
# acf integration suites, T-SEC-04: removed when the test ends
n=$#
swap=0
for a in "$@"; do
    if [ "$swap" = 1 ]; then
        set -- "$@" 65534
        swap=0
    else
        set -- "$@" "$a"
        if [ "$a" = "--uid" ]; then swap=1; fi
    fi
done
shift "$n"
exec "{real}" "$@"
""",
}


#: A stand-in for the jailer that records that it was run and then behaves like the real one. The host must never
#: run it: its bytes are not the pinned ones.
JAILER_CANARY = """#!/bin/sh
# acf integration suites, T-SEC-07: removed when the test ends
: > "{ran}"
exec "{real}" "$@"
"""

#: The one line of the host configuration that pins the jailer (``firecracker.jailer_sha256``).
_JAILER_PIN = re.compile(r'^(?P<key>[ \t]*jailer_sha256:[ \t]*)"?[0-9a-f]{64}"?[ \t]*$', re.MULTILINE)


def _restart(unit: HostUnit) -> None:
    """Restart the core and wait until the new process answers: its startup recovery has finished."""
    before = unit.main_pid()
    unit.restart()
    unit.wait_ready(not_pid=before)


@contextmanager
def _jailer_replaced_by(
    host_env: HostEnv, script: str, *, pinned_through: HostUnit | None, ran: Path | None = None
) -> Iterator[None]:
    """Put ``script`` in the place of the configured jailer; the real one is back when the block ends.

    The host runs the jailer only while its bytes hash to ``firecracker.jailer_sha256``, and it hashes them at
    startup and before every launch. With ``pinned_through`` the replacement is made the pinned jailer for the
    duration of the block: its digest is written into the host's configuration and the core is restarted through
    that unit; afterwards the configuration is put back and the core restarted again. Without it the replacement
    stays unpinned, which is what a jailer swapped under a running host is.
    """
    jailer = Path(host_env.config.text("firecracker.jailer_bin"))
    aside = jailer.with_name(jailer.name + ".acf-it-real")
    if aside.exists():
        pytest.fail(f"{aside} exists: an earlier run did not put the jailer back; move it to {jailer}", pytrace=False)
    config = Path(os.environ.get("ACF_HOST_CONFIG", DEFAULT_CONFIG))
    original = config.read_text(encoding="utf-8")
    if pinned_through is not None and len(_JAILER_PIN.findall(original)) != 1:
        pytest.fail(
            f"{config} must pin firecracker.jailer_sha256 on one line of its own: the test rewrites that line",
            pytrace=False,
        )
    shutil.move(jailer, aside)
    try:
        jailer.write_text(script.format(real=aside, ran=ran), encoding="utf-8")
        os.chown(jailer, 0, 0)
        jailer.chmod(stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
        if pinned_through is not None:
            digest = hashlib.sha256(jailer.read_bytes()).hexdigest()
            config.write_text(_JAILER_PIN.sub(rf'\g<key>"{digest}"', original), encoding="utf-8")
            _restart(pinned_through)
        yield
    finally:
        jailer.unlink(missing_ok=True)
        shutil.move(aside, jailer)
        if pinned_through is not None:
            config.write_text(original, encoding="utf-8")
            _restart(pinned_through)


@pytest.mark.parametrize("missing", sorted(JAILER_WRAPPERS))
def test_t_sec_04_a_mandatory_control_missing_at_launch_ends_the_vmm_before_it_is_configured(
    acf: AcfLocal, host_env: HostEnv, host_unit: HostUnit, missing: str
) -> None:
    """T-SEC-04: "any mandatory control missing at launch -> the VMM is ended before it is configured".

    On the real host, as root: for the duration of the test the configured jailer is replaced by a root-owned
    wrapper that launches the VMM with one control taken away (without its system-call filter, or as another user
    than the one reserved for the generation). The host runs a jailer only if its bytes are the pinned ones, so the
    wrapper is pinned in the host's configuration and the core is restarted; the real jailer and the configuration
    are put back afterwards, whatever happens, and the core is restarted again. Pass: the start does not succeed
    (the operation ends ``FAILED`` with class ``SECURITY_CONTROL_FAILURE``); the sandbox never becomes ``READY``;
    no VMM process of the generation is left; and the VMM was never given a kernel or a disk: its jail holds
    neither.
    """
    require_root(host_env, "replacing the jailer, rewriting its pin and restarting the core")
    box = acf.wire.create(acf.name("unconfined"))
    with _jailer_replaced_by(host_env, JAILER_WRAPPERS[missing], pinned_through=host_unit):
        done = acf.json("sandbox", "start", box.sandbox_id)
        after = acf.wire.refresh(box)
        left = pids_with_argument(box.jail_id)
        jail = host_env.jail_root(box)
        configured = [name for name in ("vmlinux", "rootfs.ext4") if (jail / name).exists()]

    assert done.returncode == EXIT_FAILED, f"a VMM without `{missing}` was accepted:\n{done.describe()}"
    operation = done.operation()
    assert operation.state == "FAILED"
    assert operation.failure_class == "SECURITY_CONTROL_FAILURE", operation.failure
    assert after.state != "READY", "a generation whose VMM lacks a mandatory control must never be ready"
    assert left == [], f"the VMM of the refused launch is still running: pids {left}"
    assert configured == [], f"the VMM was given {configured} before its confinement was verified"

    acf.wire.purge()
    healthy = acf.boot("confined-again")
    assert healthy.state == "READY", "with the real jailer back, a sandbox starts"


def test_t_sec_07_a_jailer_replaced_under_a_running_host_is_refused_and_never_run(
    acf: AcfLocal, host_env: HostEnv, tmp_path: Path
) -> None:
    """T-SEC-07, for the jailer: "a binary ... swapped between check and use -> refused".

    On the real host, as root: while the host runs, the configured jailer is replaced by a root-owned script that
    would record that it was run and then behave exactly like the real one. Nothing is restarted and the pin in
    the configuration is left alone. Pass: the start ends ``FAILED`` with class ``INTEGRITY_FAILURE``; the script
    was never run; the sandbox never becomes ``READY`` and no VMM process exists; and with the real jailer back a
    sandbox starts, without the host having been restarted.
    """
    require_root(host_env, "replacing the jailer")
    ran = tmp_path / "the-replaced-jailer-was-run"
    box = acf.wire.create(acf.name("swapped"))
    with _jailer_replaced_by(host_env, JAILER_CANARY, pinned_through=None, ran=ran):
        done = acf.json("sandbox", "start", box.sandbox_id)
        after = acf.wire.refresh(box)
        left = pids_with_argument(box.jail_id)

    assert done.returncode == EXIT_FAILED, f"a jailer that is not the pinned one was accepted:\n{done.describe()}"
    operation = done.operation()
    assert operation.state == "FAILED"
    assert operation.failure_class == "INTEGRITY_FAILURE", operation.failure
    assert not ran.exists(), "the host ran a jailer whose bytes were not the pinned ones"
    assert after.state != "READY"
    assert left == [], f"a VMM was launched through the replaced jailer: pids {left}"

    acf.wire.purge()
    assert acf.boot("pinned-again").state == "READY", "with the pinned jailer back, a sandbox starts"


@pytest.mark.parametrize("control", ["memory_limit", "process_limit", "packet_filter"])
def test_t_sec_05_a_control_taken_away_after_launch_stops_the_generation_within_the_recheck_interval(
    acf: AcfLocal, host_env: HostEnv, control: str
) -> None:
    """T-SEC-05: "a limit raised or a filter removed after launch -> the generation is stopped within the recheck
    interval".

    On the real host, as root: a running sandbox has one of its controls taken away from outside: the memory limit
    or the task limit of its VMM's control group is raised to ``max``, or the packet filter of its network
    namespace is flushed (network mode ``allowlist``). Nothing is asked of the host. Pass: within
    ``recovery.posture_recheck_interval_ms`` the generation is ``FAILED`` with class ``SECURITY_CONTROL_FAILURE``
    and its VMM process is gone: the runtime is stopped, never repaired in place. Its lease is kept.
    """
    require_root(host_env, "writing a control-group file, entering a network namespace and seeing the VMM")
    interval = host_env.config.integer("recovery.posture_recheck_interval_ms") / 1000
    allow = ["198.51.100.10:8443"] if control == "packet_filter" else []
    box = acf.boot("drift", allow=allow)
    identity = vmm_of(box)
    group = host_env.cgroup_dir(box)

    if control == "memory_limit":
        (group / "memory.max").write_text("max")
    elif control == "process_limit":
        (group / "pids.max").write_text("max")
    else:
        before = in_namespace(host_env, box, "nft", "list", "ruleset")
        assert before.returncode == 0, before.stderr
        assert before.stdout.strip(), "control: the namespace of an allowlist sandbox has no packet filter to remove"
        flushed = in_namespace(host_env, box, "nft", "flush", "ruleset")
        assert flushed.returncode == 0, flushed.stderr
    changed = time.monotonic()

    failed = await_sandbox(
        acf, box, lambda seen: seen.state == "FAILED", within=interval + 5, what=f"noticing the lost {control}"
    )
    took = time.monotonic() - changed
    assert took <= interval + 5, f"the drift was acted on after {took:.0f}s; the recheck interval is {interval:.0f}s"
    assert failed.failure is not None
    assert failed.failure.failure_class == "SECURITY_CONTROL_FAILURE", failed.failure
    assert seconds_until_gone(identity, within=10, what="stopping a runtime whose enforcement is degraded") <= 10
    assert acf.wire.info().live_sandboxes == 1, "the generation keeps its lease until it is destroyed"
    assert acf.refused("sandbox", "exec", box.sandbox_id, "--", "true").failure_class == "STATE_CONFLICT"
