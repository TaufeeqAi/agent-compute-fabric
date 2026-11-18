"""Limits: what a caller may ask for, what the host admits, and what the kernel then enforces.

* **Admission** (``control_plane``): a request above a ceiling of the safety profile is REFUSED, never reduced to
  fit, and leaves no record; a request at the ceiling is admitted exactly as asked; the host envelope admits what
  fits, counted with the per-runtime overhead, and refuses the rest, also under concurrency; a destroyed sandbox
  gives its lease back. The bounds are read from the shipped profile and configuration, never copied here.
* **Enforcement** (a real VMM, evidence level L4): the catalog entries T-EXEC-02, T-EXEC-04 and T-RES-02, and the
  guest-side checks that go with them: deadlines, process limits, memory, disk and output budgets.
"""

from __future__ import annotations

import os
import signal
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from acf_driver import (
    EXIT_FAILED,
    EXIT_OK,
    EXIT_REFUSED,
    EXIT_WORKLOAD_FAILED,
    AcfLocal,
    Run,
    resources,
    target_of,
)
from acf_integration import HostEnv, await_sandbox, private_host, require_root, seconds_until_gone, vmm_of
from acf_proc import cgroup_value, process_alive

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("clean_host")]

MIB = 1 << 20

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

GUEST_ARGV = "import json, sys; print(json.dumps(sys.argv[1:]))"


def _ceiling(host_env: HostEnv, name: str) -> int:
    return host_env.profile.integer(f"limits.{name}")


# =========================================================================================== admission: ceilings
@pytest.mark.control_plane
@pytest.mark.parametrize("dimension", ["memory", "vcpus", "disk", "lifetime"])
def test_t_auth_06_a_sandbox_above_a_ceiling_is_refused_never_clamped_and_leaves_no_record(
    acf: AcfLocal, host_env: HostEnv, dimension: str
) -> None:
    """T-AUTH-06 (L2, with the shipped profile): above a ceiling -> ``SAFETY_CONTROL_DENIED``; never clamped; no
    record."""
    memory, vcpus = _ceiling(host_env, "max_memory_mib"), _ceiling(host_env, "max_vcpus")
    disk, lifetime = _ceiling(host_env, "max_disk_mib"), _ceiling(host_env, "max_lifetime_secs")
    option, field, asked, ceiling = {
        "memory": ("--memory", "memory_mib", memory + 1, memory),
        "vcpus": ("--cpu", "vcpus", vcpus + 2, vcpus),  # the VMM takes 1 or an even number
        "disk": ("--disk", "disk_mib", disk + 1, disk),
        "lifetime": ("--lifetime", "lifetime_secs", lifetime + 1, lifetime),
    }[dimension]
    value = f"{asked}s" if dimension == "lifetime" else str(asked)
    wire = acf.wire
    with wire.nothing_recorded("a request above a ceiling"):
        refusal = acf.refused("sandbox", "create", "--image", acf.image, option, value)
    assert (refusal.failure_class, refusal.retry) == ("SAFETY_CONTROL_DENIED", "AFTER_CHANGE")
    assert f"{field} {asked} exceeds the safety-profile ceiling of {ceiling}" in refusal.message
    assert wire.sandboxes() == [], "a request above a ceiling must not be reduced to fit"
    assert wire.info().live_sandboxes == 0


@pytest.mark.control_plane
def test_a_sandbox_exactly_at_the_ceilings_is_admitted_exactly_as_asked(acf: AcfLocal, host_env: HostEnv) -> None:
    memory, vcpus = _ceiling(host_env, "max_memory_mib"), _ceiling(host_env, "max_vcpus")
    disk, lifetime = _ceiling(host_env, "max_disk_mib"), _ceiling(host_env, "max_lifetime_secs")
    created = acf.ok(
        "sandbox", "create", "--image", acf.image, "--cpu", str(vcpus), "--memory", str(memory), "--disk", str(disk),
        "--lifetime", f"{lifetime}s",
    )  # fmt: skip
    box = created.succeeded().sandbox_result()
    asked = {"vcpus": vcpus, "memory_mib": memory, "disk_mib": disk}
    assert {name: box.resources[name] for name in asked} == asked


@pytest.mark.control_plane
def test_requests_the_host_cannot_honour_at_all_are_invalid_not_adjusted(acf: AcfLocal) -> None:
    wire = acf.wire
    with wire.nothing_recorded("an invalid request"):
        odd = acf.json("sandbox", "create", "--image", acf.image, "--cpu", "3").answer()
        unknown_image = acf.refused("sandbox", "create", "--image", "no-such-image")
    assert (odd.refused().failure_class, odd.refused().retry) == ("INVALID_REQUEST", "NEVER")
    assert odd.as_of is None, "a request refused for its shape consulted no state"
    assert (unknown_image.failure_class, unknown_image.retry) == ("SAFETY_CONTROL_DENIED", "AFTER_CHANGE"), (
        "an image alias the profile does not list is not permitted, whether or not it is installed"
    )
    assert wire.sandboxes() == []


@pytest.mark.control_plane
def test_an_image_the_profile_permits_but_the_operator_did_not_install_is_not_found(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    host_env.test_host()  # the test host installs exactly one image
    permitted = set(host_env.profile.words("capabilities.images")) - {acf.image}
    assert permitted, "the shipped profile permits more than one image alias"
    refusal = acf.refused("sandbox", "create", "--image", sorted(permitted)[0])
    assert (refusal.failure_class, refusal.retry) == ("NOT_FOUND", "NEVER")


@pytest.mark.control_plane
@pytest.mark.parametrize("limit", ["runtime", "pids", "stdout", "stderr"])
def test_an_execution_limit_above_its_ceiling_is_refused_and_the_sandbox_is_untouched(
    acf: AcfLocal, host_env: HostEnv, limit: str
) -> None:
    runtime_ms, pids = _ceiling(host_env, "max_runtime_ms"), _ceiling(host_env, "max_pids")
    out, err = _ceiling(host_env, "max_stdout_bytes"), _ceiling(host_env, "max_stderr_bytes")
    option, value, ceiling = {
        "runtime": ("--time-limit", f"{runtime_ms // 1000 + 1}s", runtime_ms),
        "pids": ("--max-pids", str(pids + 1), pids),
        "stdout": ("--max-stdout", str(out + 1), out),
        "stderr": ("--max-stderr", str(err + 1), err),
    }[limit]
    wire = acf.wire
    box = wire.ready(acf.name("ceiling"))
    with wire.nothing_recorded("an execution above a ceiling"):
        refusal = acf.refused("sandbox", "exec", box.sandbox_id, option, value, "--", "true")
    assert (refusal.failure_class, refusal.retry) == ("SAFETY_CONTROL_DENIED", "AFTER_CHANGE")
    assert f"exceeds the safety-profile ceiling of {ceiling}" in refusal.message
    after = wire.refresh(box)
    assert (after.state, after.last_run) == ("READY", None), "a refused command must not have run"


@pytest.mark.control_plane
def test_an_execution_is_bound_by_what_was_asked_or_by_the_profiles_defaults(acf: AcfLocal, host_env: HostEnv) -> None:
    profile = host_env.profile
    box = acf.wire.ready(acf.name("bounds"))

    def configured(run: Run) -> dict[str, int]:
        return {
            name: run.evidence(name)["configured"]
            for name in ("runtime_ms", "guest_pids", "stdout_bytes", "stderr_bytes")
        }

    unasked = acf.execute(box.sandbox_id, ["true"])
    assert unasked.returncode == EXIT_OK, unasked.completed.describe()
    assert configured(unasked.run) == {
        "runtime_ms": profile.integer("defaults.runtime_ms"),
        "guest_pids": profile.integer("defaults.pids"),
        "stdout_bytes": profile.integer("defaults.stdout_bytes"),
        "stderr_bytes": profile.integer("defaults.stderr_bytes"),
    }, "with no limits asked, the DEFAULTS bind the command, not the ceilings"

    ceilings = {
        "runtime_ms": _ceiling(host_env, "max_runtime_ms"),
        "guest_pids": _ceiling(host_env, "max_pids"),
        "stdout_bytes": _ceiling(host_env, "max_stdout_bytes"),
        "stderr_bytes": _ceiling(host_env, "max_stderr_bytes"),
    }
    options = [
        "--time-limit", f"{ceilings['runtime_ms'] // 1000}s", "--max-pids", str(ceilings["guest_pids"]),
        "--max-stdout", str(ceilings["stdout_bytes"]), "--max-stderr", str(ceilings["stderr_bytes"]),
    ]  # fmt: skip
    at_ceiling = acf.execute(box.sandbox_id, ["true"], options=options)
    assert at_ceiling.returncode == EXIT_OK, at_ceiling.completed.describe()
    assert configured(at_ceiling.run) == ceilings, "a limit at its ceiling is admitted as asked"


@pytest.mark.control_plane
def test_environment_names_and_working_directories_outside_the_profile_are_refused(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    """EX-2 of the contract, at admission: only the environment names the profile allows, and a working directory
    under a permitted prefix."""
    wire = acf.wire
    box = wire.ready(acf.name("ex2"))
    assert "LD_PRELOAD" not in host_env.profile.words("execution.env_allowlist")
    with wire.nothing_recorded("an execution the profile does not permit"):
        env = acf.refused("sandbox", "exec", box.sandbox_id, "--env", "LD_PRELOAD=/tmp/x.so", "--", "true")
        cwd = acf.refused("sandbox", "exec", box.sandbox_id, "--cwd", "/etc", "--", "true")
        secret = acf.refused("sandbox", "exec", box.sandbox_id, "--secret-env", "HOME=some-reference", "--", "true")
        dotted = wire.call(
            "exec.run", {**target_of(box), "command": {"argv": ["true"], "cwd": "/workspace/../etc"}}
        ).refused()
    for refusal in (env, cwd, secret):
        assert (refusal.failure_class, refusal.retry) == ("SAFETY_CONTROL_DENIED", "AFTER_CHANGE"), refusal
    assert "LD_PRELOAD" in env.message
    assert "secret_injection" in secret.message, "the shipped profile does not grant secret injection"
    assert dotted.failure_class == "INVALID_REQUEST", "a path that is not normalised is not compared with a prefix"
    assert wire.refresh(box).last_run is None

    allowed_name = host_env.profile.words("execution.env_allowlist")[0]
    allowed_dir = host_env.profile.words("execution.cwd_prefixes")[-1]
    permitted = acf.execute(
        box.sandbox_id, ["true"], options=["--env", f"{allowed_name}=/usr/bin:/bin", "--cwd", allowed_dir]
    )
    assert permitted.operation.state == "SUCCEEDED", permitted.completed.describe()


@pytest.mark.control_plane
def test_an_argument_vector_reaches_the_guest_as_it_was_given(acf: AcfLocal, host_env: HostEnv) -> None:
    """EX-1, host side: no shell touches the argument vector on its way to the guest. The test guest echoes what it
    was handed; what a real guest does with it is T-EXEC-04."""
    host_env.test_host()
    box = acf.wire.ready(acf.name("argv"))
    arguments = ["a b", "$(id)", ";", "`id`", "*", ">", "/nonexistent"]
    run = acf.execute(box.sandbox_id, ["echo", *arguments]).run
    assert run.stdout_text == " ".join(["echo", *arguments]) + "\n"


# =========================================================================================== admission: envelope
@pytest.mark.control_plane
def test_admission_counts_memory_with_the_per_runtime_overhead_and_gives_a_lease_back_at_destroy(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    wire = acf.wire
    fits = host_env.sandboxes_that_fit(vcpus=1, memory_mib=2048, disk_mib=1024)
    assert 1 <= fits < host_env.config.integer("envelope.max_sandboxes"), "memory must be the binding dimension here"
    made = [wire.create(acf.name(f"fit{i}"), memory_mib=2048) for i in range(fits)]
    assert wire.info().live_sandboxes == fits

    with wire.nothing_recorded("a request the envelope cannot hold"):
        over = acf.refused("sandbox", "create", "--image", acf.image, "--memory", "2048")
    assert (over.failure_class, over.retry) == ("RESOURCE_EXHAUSTED", "SAME_REQUEST_LATER")
    leased = fits * (2048 + host_env.vmm_overhead_mib)
    assert f"{leased} of {host_env.config.integer('envelope.memory_mib')} MiB" in over.message, (
        "each sandbox is counted with the memory its runtime needs beyond the guest's"
    )
    assert len(wire.sandboxes()) == fits

    wire.destroy(made[0])
    refill = acf.ok("sandbox", "create", "--image", acf.image, "--memory", "2048").succeeded().sandbox_result()
    assert refill.state == "PROVISIONING", "a destroyed sandbox gives its lease back"
    assert len(wire.sandboxes()) == fits


@pytest.mark.control_plane
def test_the_vcpu_budget_is_shared_by_all_sandboxes(acf: AcfLocal, host_env: HostEnv) -> None:
    wire = acf.wire
    envelope = host_env.config.integer("envelope.vcpus")
    if envelope > _ceiling(host_env, "max_vcpus"):
        pytest.skip("one sandbox cannot take the whole vCPU envelope under this profile; nothing to exhaust")
    wire.create(acf.name("allcpus"), vcpus=envelope)
    with wire.nothing_recorded("a request the envelope cannot hold"):
        over = acf.refused("sandbox", "create", "--image", acf.image, "--cpu", "1", "--memory", "256")
    assert (over.failure_class, over.retry) == ("RESOURCE_EXHAUSTED", "SAME_REQUEST_LATER")
    assert "vCPU" in over.message
    assert len(wire.sandboxes()) == 1


@pytest.mark.control_plane
def test_t_conc_05_concurrent_creates_for_the_last_slot_admit_exactly_one(acf: AcfLocal, host_env: HostEnv) -> None:
    """T-CONC-05 (L2): concurrent creates for the last slot -> exactly one admitted."""
    wire = acf.wire
    fits = host_env.sandboxes_that_fit(vcpus=1, memory_mib=2048, disk_mib=1024)
    for i in range(fits - 1):
        wire.create(acf.name(f"held{i}"), memory_mib=2048)
    contenders = 6
    args = ("sandbox", "create", "--image", acf.image, "--memory", "2048")
    with ThreadPoolExecutor(max_workers=contenders) as pool:
        done = [future.result() for future in [pool.submit(acf.json, *args) for _ in range(contenders)]]
    codes = sorted(d.returncode for d in done)
    assert codes == [EXIT_OK] + [EXIT_REFUSED] * (contenders - 1), [d.describe() for d in done]
    losers = {d.refusal().failure_class for d in done if d.returncode == EXIT_REFUSED}
    assert losers == {"RESOURCE_EXHAUSTED"}
    assert len(wire.sandboxes()) == fits, "the envelope was overcommitted"


@pytest.mark.control_plane
def test_t_conc_04_destroy_is_admitted_with_capacity_exhausted_and_under_a_request_flood(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    """T-CONC-04 (L2): destroy with capacity exhausted and under a request flood -> admitted.

    The flood is one peer spending its whole operation budget (``operations.rate_limit_per_minute``), on a test
    host of this test's own so that no other test meets an empty budget.
    """
    budget = host_env.config.integer("operations.rate_limit_per_minute")
    with private_host(host_env, acf) as private:
        wire = private.acf.wire
        vcpus = host_env.config.integer("envelope.vcpus")
        boxes = [wire.ready(acf.name(f"full{i}")) for i in range(vcpus)]
        full = wire.call("sandbox.create", {"image": acf.image, "resources": resources()}).refused()
        assert full.failure_class == "RESOURCE_EXHAUSTED"

        limited = None
        ghost = {"sandbox_id": "sbx-" + "0" * 32, "expected_generation": 1}
        with private.host.connect() as flood:
            for _ in range(2 * budget):
                refusal = flood.request("sandbox.start", ghost).refused()
                if refusal.failure_class != "NOT_FOUND":
                    limited = refusal
                    break
        assert limited is not None, f"{2 * budget} operations in one burst never met the rate limit of {budget}/min"
        assert (limited.failure_class, limited.retry) == ("RESOURCE_EXHAUSTED", "SAME_REQUEST_LATER")
        still = wire.call("sandbox.start", ghost).refused()
        assert still.failure_class == "RESOURCE_EXHAUSTED", "the budget is spent for granting requests"

        destroyed = private.acf.ok("sandbox", "destroy", boxes[0].sandbox_id, "--yes").succeeded().sandbox_result()
        assert destroyed.state == "DESTROYED", "a containment request is never refused for rate or load"
        assert wire.stop(boxes[1]).state == "STOPPED"
        assert wire.info().live_sandboxes == vcpus - 1, "reads have a budget of their own"


# =========================================================================================== enforcement (L4)
def test_t_exec_02_a_guest_that_ignores_its_deadline_and_cancel_is_ended_by_the_host_backstop(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    """T-EXEC-02: "a guest that ignores its deadline and cancel -> the backstop fires; run ``TIMED_OUT``; generation
    ``FAILED``".

    On the real host, as root: a command with a 5 s limit is started, and while it runs the VMM process is sent
    SIGSTOP, so the guest (its agent included) executes nothing and can honour neither its own deadline nor a
    cancel. The host must not depend on the guest: when its own deadline passes (the limit plus
    ``operations.backstop_margin_ms``) it ends the runtime. Pass: the operation ends ``FAILED`` with class
    ``TIMEOUT`` and effect ``MAY_BE_APPLIED``; the run is ``TIMED_OUT`` with the backstop recorded as fired; the
    generation is ``FAILED``; the VMM process is gone.
    """
    require_root(host_env, "stopping the VMM process of another user")
    limit_s = 5
    margin_s = host_env.config.integer("operations.backstop_margin_ms") / 1000
    grace_s = host_env.config.integer("operations.preempt_grace_ms") / 1000
    teardown_s = host_env.config.integer("recovery.teardown_timeout_ms") / 1000
    box = acf.boot("frozen")
    identity = vmm_of(box)

    started = time.monotonic()
    client = acf.spawn("sandbox", "exec", box.sandbox_id, "--time-limit", f"{limit_s}s", "--json", "--", "sleep", "600")
    try:
        await_sandbox(acf, box, lambda seen: seen.state == "RUNNING", within=30, what="the command starting")
        os.kill(identity[0], signal.SIGSTOP)
        done = client.wait(timeout=limit_s + margin_s + grace_s + teardown_s + 60)
    finally:
        client.kill()
        if process_alive(*identity):
            os.kill(identity[0], signal.SIGCONT)
    took = time.monotonic() - started

    operation = done.require_exit(EXIT_FAILED).operation()
    assert (operation.state, operation.failure_class, operation.effect) == ("FAILED", "TIMEOUT", "MAY_BE_APPLIED")
    assert took >= limit_s + margin_s, f"the backstop fired after {took:.1f}s, before the host's own deadline"
    assert operation.run_id is not None
    run = acf.ok("run", "inspect", operation.run_id).run()
    assert (run.status, run.host_backstop_fired, run.runtime_ended) == ("TIMED_OUT", True, True)
    assert run.exit_code is None, "a host-observed timeout has no exit status reported by the guest"

    failed = acf.wire.refresh(box)
    assert failed.state == "FAILED", "after the backstop the generation is unusable"
    assert seconds_until_gone(identity, within=5, what="the runtime of a generation the backstop ended") <= 5
    refused = acf.refused("sandbox", "exec", box.sandbox_id, "--", "true")
    assert refused.failure_class == "STATE_CONFLICT"


def test_t_exec_04_arguments_run_literally_in_the_guest_and_nothing_runs_on_the_host(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    """T-EXEC-04: "an argument with shell metacharacters runs literally; an environment name or working directory
    outside the profile is refused; nothing runs on the host".

    On the real host: the command's arguments contain every way a shell would be asked to do something else, among
    them a command substitution that would create a canary file. Pass: the guest's own process sees exactly the
    arguments that were sent; the canary exists neither on the host nor in the guest; requests outside the
    profile's environment names and directories are refused with ``SAFETY_CONTROL_DENIED`` and run nothing.
    """
    canary = Path(f"/tmp/acf-it-canary-{uuid.uuid4().hex}")
    hostile = [
        "two words",
        f"$(touch {canary})",
        f"`touch {canary}`",
        f"; touch {canary}",
        f"| touch {canary}",
        f"&& touch {canary}",
        f"> {canary}",
        "*",
        "~",
        "$HOME",
        "\\n",
        "'quoted'",
        '"double"',
    ]
    box = acf.boot("literal")
    run = acf.python(box.sandbox_id, GUEST_ARGV, *hostile)
    assert run.succeeded(), run
    assert run.stdout_json() == hostile, "the guest's process did not receive the arguments as they were sent"
    assert not canary.exists(), "an argument was executed ON THE HOST"
    assert acf.sh(box.sandbox_id, f"test ! -e {canary}").succeeded(), (
        "an argument was interpreted by a shell in the guest"
    )

    before = acf.wire.refresh(box)
    env = acf.refused("sandbox", "exec", box.sandbox_id, "--env", "LD_PRELOAD=/tmp/x.so", "--", "true")
    cwd = acf.refused("sandbox", "exec", box.sandbox_id, "--cwd", "/root", "--", "true")
    assert {env.failure_class, cwd.failure_class} == {"SAFETY_CONTROL_DENIED"}
    assert acf.wire.refresh(box).last_run == before.last_run, "a refused command ran"

    identity = acf.python(box.sandbox_id, "import os; print(os.getuid(), os.getgid(), os.getcwd())")
    uid, gid = host_env.profile.integer("execution.guest_uid"), host_env.profile.integer("execution.guest_gid")
    assert identity.stdout_text == f"{uid} {gid} {host_env.profile.text('execution.default_cwd')}\n", (
        "a command runs as the unprivileged identity the profile names, never as guest root"
    )


def test_t_res_02_memory_cpu_and_process_limits_are_enforced_by_the_kernel(acf: AcfLocal, host_env: HostEnv) -> None:
    """T-RES-02: "memory, CPU and process limits are enforced by the kernel".

    On the real host, as root: the limits are read from the control group that holds the VMM (the kernel's own
    files, not the host's report), and then leaned on from inside the guest. Pass: the group bounds memory at guest
    memory plus the per-runtime overhead with no swap, bounds CPU and the VMM's own task count; the guest sees the
    CPUs and memory it was promised and no more; a fork bomb stops below the process limit of its execution; a
    process that outgrows guest memory dies and the sandbox survives it.
    """
    require_root(host_env, "reading the control group of the runtime")
    vcpus, memory = 2, 512
    box = acf.boot("limits", cpu=vcpus, memory=str(memory))
    group = host_env.cgroup_dir(box)
    assert int(cgroup_value(group, "memory.max")) == (memory + host_env.vmm_overhead_mib) * MIB
    assert cgroup_value(group, "memory.swap.max") == "0"
    assert cgroup_value(group, "memory.oom.group") == "1"
    quota, period = cgroup_value(group, "cpu.max").split()
    assert quota != "max", "the runtime's CPU time is unbounded"
    assert vcpus * int(period) <= int(quota) < (vcpus + 1) * int(period), (
        f"cpu.max is {quota} {period} for {vcpus} vCPUs"
    )
    assert cgroup_value(group, "pids.max") != "max", "the runtime's task count is unbounded"

    seen = acf.python(box.sandbox_id, GUEST_CPU_AND_MEMORY).stdout_json()
    assert seen["cpus"] == vcpus
    assert 0.70 * memory <= seen["mem_mib"] <= memory, f"the guest reports {seen['mem_mib']} MiB of {memory}"

    bomb = acf.python(box.sandbox_id, GUEST_FORK_BOMB, options=["--max-pids", "32", "--time-limit", "60s"])
    assert bomb.succeeded(), f"the bomb's parent should survive its refused forks: {bomb!r}"
    assert 1 <= int(bomb.stdout_text.strip()) < 32, "the process limit of the execution did not stop the tree"
    assert bomb.evidence("guest_pids")["configured"] == 32
    assert bomb.guest_containment == "guest cgroup v2 pids.max + cgroup.kill"
    assert acf.workload_processes(box.sandbox_id) == [], "children outlived the execution that created them"

    hog = acf.execute(
        box.sandbox_id, ["python", "-c", GUEST_MEMORY_HOG, str(memory * 3)], options=["--time-limit", "120s"]
    )
    assert hog.returncode == EXIT_WORKLOAD_FAILED, f"{memory * 3} MiB cannot be resident in a {memory} MiB guest"
    assert hog.run.signal == signal.SIGKILL or hog.run.exit_code not in (None, 0), hog.run
    if (group / "memory.peak").exists():  # kernels before 5.19 do not keep the peak
        assert int(cgroup_value(group, "memory.peak")) <= (memory + host_env.vmm_overhead_mib) * MIB
    assert acf.wire.refresh(box).state == "COMPLETED", "an out-of-memory kill in the guest must not take the sandbox"
    assert acf.sh(box.sandbox_id, "echo alive").stdout_text == "alive\n"


def test_the_guest_disk_is_as_big_as_requested_and_filling_it_ends_with_enospc(acf: AcfLocal) -> None:
    box = acf.boot("disk", disk="1024")
    seen = acf.python(box.sandbox_id, GUEST_DISK).stdout_json()
    assert 0.90 * 1024 <= seen["total_mib"] <= 1024, seen
    filled = acf.python(box.sandbox_id, GUEST_FILL_DISK, options=["--time-limit", "300s"]).stdout_json()
    assert filled["errno"] == 28, f"expected ENOSPC (28), the write ended with {filled}"
    assert 256 <= filled["written_mib"] < 1024, f"the limit is the disk's size, not something smaller: {filled}"
    assert acf.sh(box.sandbox_id, "rm -f /workspace/fill && echo ok").stdout_text == "ok\n"


def test_a_command_past_its_deadline_is_ended_by_the_guest_with_its_whole_tree(acf: AcfLocal) -> None:
    box = acf.boot("deadline")
    done = acf.call(
        "sandbox",
        "exec",
        box.sandbox_id,
        "--shell",
        "--command",
        "sleep 300 & sleep 300",
        "--time-limit",
        "3s",
        "--json",
    )
    assert done.returncode == EXIT_WORKLOAD_FAILED, done.describe()
    operation = done.operation()
    run = operation.run_result()
    assert (operation.state, run.status, run.exit_code) == ("SUCCEEDED", "TIMED_OUT", None), (
        "a guest-side timeout is a result of a successful operation"
    )
    assert run.host_backstop_fired is False, (
        "the GUEST enforces its own deadline; the backstop is for a guest that cannot"
    )
    evidence = run.evidence("runtime_ms")
    assert (evidence["configured"], evidence["violated"]) == (3000, True)
    assert evidence["action_taken"] == "process group killed at the guest deadline"
    assert acf.workload_processes(box.sandbox_id) == [], "the deadline left processes of the workload behind"
    assert acf.wire.refresh(box).state == "COMPLETED"


def test_a_process_that_leaves_its_group_is_still_ended_with_its_execution(acf: AcfLocal) -> None:
    box = acf.boot("escape")
    run = acf.sh(
        box.sandbox_id, "setsid sleep 600 >/dev/null 2>&1 < /dev/null & nohup sleep 600 >/dev/null 2>&1 & echo started"
    )
    assert run.stdout_text == "started\n"
    assert acf.workload_processes(box.sandbox_id) == [], "a daemonised child survived the command that started it"


def test_output_beyond_its_budget_is_truncated_counted_and_never_stalls_the_command(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    box = acf.boot("output")
    flood = "import sys; sys.stdout.write('x' * 3_000_000)"
    run = acf.python(box.sandbox_id, flood, options=["--max-stdout", "1024"])
    assert run.succeeded(), "producing more output than the budget is not a failure of the command"
    assert (run.stdout.status, run.stdout.kept_bytes, run.stdout.total_bytes) == ("TRUNCATED", 1024, 3_000_000)
    assert acf.run_output(run.run_id, "stdout") == b"x" * 1024
    evidence = run.evidence("stdout_bytes")
    assert (evidence["configured"], evidence["observed_peak"], evidence["violated"]) == (1024, 3_000_000, True)
    assert evidence["action_taken"] == "truncated; remainder drained and counted"

    default_budget = host_env.profile.integer("defaults.stderr_bytes")
    loud = acf.python(box.sandbox_id, f"import sys; sys.stderr.write('e' * {2 * default_budget})")
    assert (loud.stderr.status, loud.stderr.kept_bytes, loud.stderr.total_bytes) == (
        "TRUNCATED",
        default_budget,
        2 * default_budget,
    )
    assert loud.stdout.status == "COMPLETE"


def test_a_run_reports_what_the_runtime_really_consumed(acf: AcfLocal, host_env: HostEnv) -> None:
    box = acf.boot("usage", cpu=2, memory="512")
    run = acf.python(box.sandbox_id, "sum(i * i for i in range(2_000_000))")
    assert run.succeeded()
    memory = run.evidence("memory")
    assert memory["configured"] == 512 * MIB
    assert memory["effective"] == (512 + host_env.vmm_overhead_mib) * MIB, "the limit is guest memory plus the overhead"
    assert (memory["violated"], (memory["observed_peak"] or 0) > 0) == (False, True)
    assert (run.evidence("cpu_usec")["observed_peak"] or 0) > 0, "the runtime's CPU time must be read and reported"
    assert run.evidence("host_pids")["violated"] is False
