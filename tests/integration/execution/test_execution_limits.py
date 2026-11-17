"""Gate D: resource limits are enforced, and every enforcement leaves evidence (contract §18, §27.8).

Each resource follows ``request -> admission -> reservation -> enforcement -> violation -> evidence``. The tests here
walk that chain from the outside:

* **admission** (``control_plane``): a request above a policy ceiling is REFUSED, never silently clamped; the
  envelope admits exactly what fits and refuses the rest, also under concurrency; a destroyed sandbox gives its
  reservation back;
* **enforcement** (real guest): the guest sees the CPUs, RAM and disk it was promised and no more; a command past its
  deadline is killed, its whole tree with it; a fork bomb is bounded by the process limit; a memory hog dies without
  taking the sandbox down; output beyond the cap is truncated, counted and flagged;
* **evidence** (real guest): each of those leaves a resource-evidence entry that says what was configured, what
  happened and which mechanism did it.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from acf_driver import EXIT_OK, EXIT_REFUSED, EXIT_WORKLOAD_FAILED, AcfLocal
from acf_integration import HostEnv

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("clean_host")]

GUEST_CPU_AND_MEMORY = """
import json, os
mem_kib = next(int(line.split()[1]) for line in open('/proc/meminfo') if line.startswith('MemTotal'))
print(json.dumps({'cpus': os.cpu_count(), 'mem_mib': mem_kib // 1024}))
"""

GUEST_DISK = """
import json, os
st = os.statvfs('/workspace')
print(json.dumps({'total_mib': st.f_blocks * st.f_frsize >> 20, 'free_mib': st.f_bavail * st.f_frsize >> 20}))
"""

# Writes 1 MiB at a time until the filesystem says no (capped at 4 GiB so a missing limit cannot run forever).
GUEST_FILL_DISK = """
import json, os
chunk = b'x' * (1 << 20)
written, err = 0, None
fd = os.open('/workspace/fill', os.O_WRONLY | os.O_CREAT)
try:
    while written < (4 << 30):
        os.write(fd, chunk)
        written += len(chunk)
        if written % (64 << 20) == 0:
            os.fsync(fd)
    os.fsync(fd)
except OSError as e:
    err = e.errno
print(json.dumps({'written_mib': written >> 20, 'errno': err}))
"""

# Allocates and TOUCHES `sys.argv[1]` MiB, so the pages are really resident.
GUEST_MEMORY_HOG = """
import sys
blocks = [bytearray(b'\\x01') * (1 << 20) for _ in range(int(sys.argv[1]))]
print('allocated', len(blocks), 'MiB')
"""

GUEST_FORK_BOMB = """
import os, time
children = []
while len(children) < 500:
    try:
        pid = os.fork()
    except OSError:
        break
    if pid == 0:
        time.sleep(600)
        os._exit(0)
    children.append(pid)
print(len(children))
"""


# =========================================================================================== admission
CEILINGS = [
    # (what to ask for, the policy ceiling it exceeds) — policies/default.yaml
    pytest.param(("--memory", "8192"), "memory_mib 8192 exceeds the policy ceiling of 4096", id="memory"),
    pytest.param(("--cpu", "8"), "vcpus 8 exceeds the policy ceiling of 4", id="vcpus"),
    pytest.param(("--disk", "65536"), "disk_mib 65536 exceeds the policy ceiling of 8192", id="disk"),
]


@pytest.mark.control_plane
@pytest.mark.parametrize(("option", "message"), CEILINGS)
def test_a_sandbox_above_a_policy_ceiling_is_refused_and_nothing_is_created(
    acf: AcfLocal, option: tuple[str, str], message: str
) -> None:
    done = acf.call("sandbox", "create", "--image", acf.image, *option, "--json")
    assert done.returncode == EXIT_REFUSED, done.describe()
    assert message in done.stderr, done.describe()
    assert acf.sandbox_list() == []
    assert acf.host_info()["live_sandboxes"] == 0


@pytest.mark.control_plane
def test_a_vcpu_count_firecracker_cannot_honour_is_refused(acf: AcfLocal) -> None:
    done = acf.call("sandbox", "create", "--image", acf.image, "--cpu", "3", "--json")
    assert done.returncode == EXIT_REFUSED, done.describe()
    assert "vcpus must be 1 or an even number" in done.stderr
    assert acf.sandbox_list() == []


@pytest.mark.control_plane
@pytest.mark.parametrize(
    ("option", "message"),
    [
        pytest.param(("--timeout", "3601s"), "timeout_ms 3601000 exceeds the policy ceiling of 3600000", id="timeout"),
        pytest.param(("--max-pids", "1025"), "exceeds the policy ceiling of 1024", id="pids"),
        pytest.param(("--max-stdout", "9MiB"), "exceeds the policy ceiling of 8388608", id="stdout"),
        pytest.param(("--max-stderr", "9MiB"), "exceeds the policy ceiling of 8388608", id="stderr"),
    ],
)
def test_a_run_limit_above_its_ceiling_is_refused_not_clamped(
    acf: AcfLocal, option: tuple[str, str], message: str
) -> None:
    box = acf.boot("ceiling")
    assert box.name is not None
    done = acf.call("exec", box.name, *option, "--json", "--", "true")
    assert done.returncode == EXIT_REFUSED, done.describe()
    assert message in done.stderr, done.describe()
    assert acf.sandbox_inspect(box.name).state == "READY", "a refused command must not move the sandbox"
    assert acf.sh(box.name, "true").succeeded(), "and the sandbox must still work"


@pytest.mark.control_plane
def test_the_envelope_admits_exactly_what_fits_and_refuses_the_rest(acf: AcfLocal, host_env: HostEnv) -> None:
    fits = host_env.sandboxes_that_fit(vcpus=1, memory_mib=2048, disk_mib=1024)
    assert 1 <= fits < host_env.max_sandboxes, "the shipped envelope makes memory the binding limit for 2 GiB sandboxes"
    made = [acf.sandbox_create(acf.name(f"fit{i}"), memory="2048") for i in range(fits)]
    assert len({s.sandbox_id for s in made}) == fits
    assert acf.host_info()["live_sandboxes"] == fits

    over = acf.call("sandbox", "create", "--image", acf.image, "--memory", "2048", "--json")
    assert over.returncode == EXIT_REFUSED, over.describe()
    assert "insufficient memory" in over.stderr, over.describe()
    reserved = fits * (2048 + host_env.vmm_overhead_mib)
    assert f"{reserved} of {host_env.envelope_memory_mib} MiB reserved" in over.stderr, (
        "the refusal must name the arithmetic"
    )
    assert len(acf.sandbox_list()) == fits, "a refused create must change nothing"

    acf.sandbox_destroy(made[0].sandbox_id)  # a destroyed sandbox gives its reservation back
    again = acf.sandbox_create(acf.name("refill"), memory="2048")
    assert again.state == "PROVISIONING"
    assert len(acf.sandbox_list()) == fits


@pytest.mark.control_plane
def test_the_vcpu_budget_is_shared_across_sandboxes(acf: AcfLocal, host_env: HostEnv) -> None:
    biggest = 4  # policies/default.yaml: limits.max_vcpus
    if host_env.envelope_vcpus > biggest:
        pytest.skip("one sandbox cannot take the whole vCPU envelope under this policy; nothing to exhaust")
    acf.sandbox_create(acf.name("allcpus"), cpu=host_env.envelope_vcpus, memory="256")
    over = acf.call("sandbox", "create", "--image", acf.image, "--cpu", "1", "--memory", "256", "--json")
    assert over.returncode == EXIT_REFUSED, over.describe()
    assert "insufficient vCPUs" in over.stderr, over.describe()
    assert len(acf.sandbox_list()) == 1


@pytest.mark.control_plane
def test_concurrent_creates_never_overcommit_the_envelope(acf: AcfLocal, host_env: HostEnv) -> None:
    fits = host_env.sandboxes_that_fit(vcpus=1, memory_mib=2048, disk_mib=1024)
    attempts = fits + 5
    args = ("sandbox", "create", "--image", acf.image, "--memory", "2048", "--json")
    with ThreadPoolExecutor(max_workers=attempts) as pool:
        codes = [f.result().returncode for f in [pool.submit(acf.call, *args) for _ in range(attempts)]]
    assert set(codes) <= {EXIT_OK, EXIT_REFUSED}, f"unexpected exit codes: {codes}"
    assert codes.count(EXIT_OK) == fits, (
        f"{attempts} concurrent creates must yield exactly {fits} sandboxes, got {codes}"
    )
    assert len(acf.sandbox_list()) == fits


# =========================================================================================== enforcement
@pytest.mark.parametrize(("cpu", "memory"), [(1, 256), (2, 512)])
def test_the_guest_sees_the_cpus_and_memory_it_was_promised(acf: AcfLocal, cpu: int, memory: int) -> None:
    box = acf.boot("shape", cpu=cpu, memory=str(memory))
    assert box.name is not None
    seen = acf.python(box.name, GUEST_CPU_AND_MEMORY).stdout_json()
    assert seen["cpus"] == cpu
    # The kernel keeps some RAM for itself (and the image's init): what the guest reports must be close to,
    # and never above, what was asked for.
    assert 0.70 * memory <= seen["mem_mib"] <= memory, seen


def test_the_guest_disk_is_as_big_as_requested(acf: AcfLocal) -> None:
    box = acf.boot("disk", disk="2048")
    assert box.name is not None
    seen = acf.python(box.name, GUEST_DISK).stdout_json()
    # ext4 metadata and the image's own files take some: the filesystem must still be about the size that was asked for.
    assert 0.90 * 2048 <= seen["total_mib"] <= 2048, seen
    assert seen["free_mib"] > 512, seen


def test_filling_the_disk_ends_with_enospc_and_leaves_a_working_sandbox(acf: AcfLocal) -> None:
    box = acf.boot("full", disk="1024")
    assert box.name is not None
    filled = acf.python(box.name, GUEST_FILL_DISK, timeout="300s").stdout_json()
    assert filled["errno"] == 28, f"expected ENOSPC (28), the write ended with {filled}"  # errno.ENOSPC on Linux
    assert 256 <= filled["written_mib"] < 1024, f"the limit is the disk's size, not something smaller: {filled}"
    assert acf.sh(box.name, "rm -f /workspace/fill && echo ok").stdout == "ok\n"


def test_a_command_past_its_deadline_is_killed_with_its_whole_tree(acf: AcfLocal) -> None:
    box = acf.boot("deadline")
    assert box.name is not None
    report = acf.exec(box.name, "sleep 300 & sleep 300", shell=True, timeout="3s")
    assert report.returncode == EXIT_WORKLOAD_FAILED, report.completed.describe()
    run = report.run
    assert run.outcome == "TIMED_OUT"
    assert run.exit_code is None
    assert 2_500 <= run.wall_ms <= 15_000, f"a 3 s deadline took {run.wall_ms} ms"
    evidence = run.evidence("runtime_ms")
    assert evidence["configured"] == 3000
    assert evidence["violation"] == "RESOURCE_EXHAUSTION"
    assert evidence["action_taken"] == "process group killed at deadline", (
        "the GUEST must enforce its own deadline; the host's VM kill is only a backstop"
    )
    assert acf.workload_processes(box.name) == [], "the deadline left processes of the workload behind"
    assert acf.sh(box.name, "echo alive").stdout == "alive\n"


def test_a_fork_bomb_is_bounded_by_the_process_limit_and_cleaned_up(acf: AcfLocal) -> None:
    box = acf.boot("forks")
    assert box.name is not None
    run = acf.python(box.name, GUEST_FORK_BOMB, max_pids=32, timeout="60s")
    assert run.succeeded(), f"the bomb's parent should survive its refused forks: {run}"
    forked = int(run.stdout.strip())
    assert 1 <= forked < 32, f"pids.max=32 must stop the tree below 32 processes, {forked} children were created"
    evidence = run.evidence("guest_pids")
    assert evidence["configured"] == 32
    assert evidence["violation"] == "RESOURCE_EXHAUSTION"
    assert evidence["mechanism"] == "guest cgroup v2 pids.max + cgroup.kill", (
        "the shipped image must give the agent cgroup v2; the RLIMIT fallback is weaker and must not be the norm"
    )
    assert acf.workload_processes(box.name) == [], "the sleeping children outlived the run that created them"


def test_a_process_that_escapes_its_group_is_still_killed_when_the_run_ends(acf: AcfLocal) -> None:
    box = acf.boot("escape")
    assert box.name is not None
    run = acf.sh(
        box.name, "setsid sleep 600 >/dev/null 2>&1 < /dev/null & nohup sleep 600 >/dev/null 2>&1 & echo started"
    )
    assert run.stdout == "started\n"
    assert acf.workload_processes(box.name) == [], "a daemonised child survived the end of the command that started it"


def test_a_memory_hog_dies_and_the_sandbox_survives(acf: AcfLocal) -> None:
    box = acf.boot("hog", memory="256")
    assert box.name is not None
    fits = acf.python(box.name, GUEST_MEMORY_HOG, timeout="60s")
    assert fits.succeeded(), f"a 64 MiB allocation must fit in a 256 MiB guest: {fits}"

    hog = acf.exec(box.name, ["python", "-c", GUEST_MEMORY_HOG, "700"], timeout="120s")
    assert hog.returncode != EXIT_OK, "700 MiB cannot be resident in a 256 MiB guest"
    assert hog.run.outcome == "FAILED"
    assert hog.run.signal == 9 or hog.run.exit_code not in (None, 0), (
        f"the hog must be killed by the guest kernel: {hog.run}"
    )
    assert acf.sandbox_inspect(box.name).state in {"READY", "COMPLETED"}, "the OOM must not take the sandbox with it"
    assert acf.sh(box.name, "echo alive").stdout == "alive\n"
    assert acf.workload_processes(box.name) == []


def test_output_beyond_the_cap_is_truncated_counted_and_flagged(acf: AcfLocal) -> None:
    run = acf.run(["python", "-c", "import sys; sys.stdout.write('x' * 3_000_000)"], max_stdout="1KiB").run
    assert run.outcome == "SUCCEEDED", "producing a lot of output is not a failure of the command"
    out = run.stream("stdout")
    assert (out["status"], out["kept_bytes"], out["total_bytes"]) == ("TRUNCATED", 1024, 3_000_000)
    assert len(run.stdout_bytes()) == 1024
    assert run.evidence_status == "TRUNCATED"
    evidence = run.evidence("stdout_bytes")
    assert (evidence["configured"], evidence["observed_peak"], evidence["violation"]) == (
        1024,
        3_000_000,
        "OUTPUT_LIMIT",
    )
    assert evidence["action_taken"] == "truncated; remainder drained and counted"


def test_the_default_output_cap_is_one_mebibyte(acf: AcfLocal) -> None:
    run = acf.run(["python", "-c", "import sys; sys.stderr.write('e' * 2_000_000)"]).run
    err = run.stream("stderr")
    assert (err["status"], err["kept_bytes"], err["total_bytes"]) == ("TRUNCATED", 1_048_576, 2_000_000)
    assert run.stream("stdout")["status"] == "COMPLETE"
    assert run.evidence("stderr_bytes")["violation"] == "OUTPUT_LIMIT"


def test_a_run_reports_what_the_vmm_really_consumed(acf: AcfLocal) -> None:
    started = time.monotonic()
    run = acf.run(["python", "-c", "sum(i * i for i in range(2_000_000))"], cpu=2, memory="512").run
    assert run.succeeded()
    assert run.wall_ms <= (time.monotonic() - started) * 1000
    memory = run.evidence("memory")
    assert memory["configured"] == 512 * 1024 * 1024
    assert memory["effective"] == (512 + 64) * 1024 * 1024, "the cgroup limit is guest RAM plus the VMM's own overhead"
    assert memory["violation"] is None
    assert (memory["observed_peak"] or 0) > 0, "cgroup memory.peak must be read and reported"
    assert (run["metrics"]["cpu_usage_usec"] or 0) > 0, "cgroup cpu.stat must be read and reported"
    assert run.evidence("host_pids")["violation"] is None
