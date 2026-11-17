"""Fixtures and gating for the KVM-only suites: ``tests/integration`` and ``tests/isolation``.

Those suites boot real Firecracker microVMs through a RUNNING ``acf-host`` and attack them. They cannot run on a
laptop or in ordinary CI, so they are gated, and there are exactly two ways to run them:

* ``ACF_INTEGRATION=1`` (``make integration``): the whole suite, against the real host on a KVM machine. The machine
  is *required* to be ready: if it is not, the run FAILS with a list of what is missing. A suite that quietly skips
  when its environment is broken would report success on exactly the machines where the isolation claims matter.
  (Same rule as ``ACF_REQUIRE_E2E`` for the CLI.)
* ``ACF_CONTROL_PLANE=1`` (``make control-plane``): only the tests marked ``control_plane``, against the in-memory
  host (``acf-host-fake``) loaded with the SHIPPED ``config/host.example.yaml`` and ``policies/default.yaml``. No KVM,
  no root. These are the assertions about admission, ceilings, the state machine and the exit codes, which do not
  depend on what runs inside a guest; checking them against the shipped files means the numbers the KVM run will rely
  on were already proven once, in CI. Everything else is skipped, and says why.

With neither switch every test is *skipped*, with the reason in the report.

Environment (all optional except the switch):

=============================  ====================================================  ============================
``ACF_INTEGRATION``            ``1``: the real suites (needs KVM)                     unset: skip
``ACF_CONTROL_PLANE``          ``1``: the ``control_plane`` subset on the in-memory   unset: skip
                               host (needs ``ACF_HOST_FAKE``)
``ACF_LOCAL``                  the CLI command line                                   ``acf-local``
``ACF_SOCKET``                 the host agent's control socket                        ``/run/acf/host-agent.sock``
``ACF_TEST_IMAGE``             image alias the tests boot                             ``python``
``ACF_STATE_ROOT``             the host's state directory (white-box checks)          ``/var/lib/acf``
``ACF_HOST_UNIT``              systemd unit of the host agent (recovery tests)        ``acf-host.service``
``ACF_POLICY_PATH``            the policy file the host loaded                        ``/etc/acf/policy.yaml``
``ACF_TEST_ENVELOPE_VCPUS``    ``envelope.vcpus`` of /etc/acf/host.yaml               ``4`` (the shipped config)
``ACF_TEST_ENVELOPE_MEMORY_MIB``  ``envelope.memory_mib``                             ``8192``
``ACF_TEST_VMM_OVERHEAD_MIB``  ``firecracker.vmm_overhead_mib``                       ``64``
``ACF_TEST_MAX_SANDBOXES``     ``envelope.max_sandboxes``                             ``16``
``ACF_TEST_SNAPSHOT_LIMIT``    ``envelope.max_snapshots`` if you lowered it           unset: the quota test skips
``ACF_HOST_CONFIG``            the host's config file (uid range for the white-box checks)  ``/etc/acf/host.yaml``
``ACF_REQUIRE_ROOT``           ``1``: tests that need root FAIL instead of skipping       unset: skip
=============================  ====================================================  ============================

The suites assume they OWN the host: they refuse to start while sandboxes or snapshots exist, and after every test
they destroy whatever is live.
"""

from __future__ import annotations

import os
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import pytest

from acf_driver import EXIT_OK, AcfLocal, DriverError

INTEGRATION_SWITCH = "ACF_INTEGRATION"
CONTROL_PLANE_SWITCH = "ACF_CONTROL_PLANE"
SELFTEST_SWITCH = "ACF_DRIVER_SELFTEST"

REPO = Path(__file__).resolve().parent.parent.parent
MAX_SOCKET_PATH = 100  # the kernel limit is 107 bytes; leave room for the CLI's own handling


def integration_enabled() -> bool:
    return os.environ.get(INTEGRATION_SWITCH) == "1"


def control_plane_enabled() -> bool:
    return os.environ.get(CONTROL_PLANE_SWITCH) == "1"


def selftest_enabled() -> bool:
    return os.environ.get(SELFTEST_SWITCH) == "1"


@contextmanager
def fake_host(*, shipped: bool) -> Iterator[Path]:
    """Run ``acf-host-fake`` (the real server over in-memory VMs) and yield its socket path; stop it afterwards.

    ``shipped=True`` loads ``config/host.example.yaml`` and ``policies/default.yaml`` instead of the small built-in
    test pair. A missing binary FAILS the run: it never skips.
    """
    binary = Path(os.environ.get("ACF_HOST_FAKE", "target/debug/acf-host-fake"))
    if not binary.is_file():
        pytest.fail(f"acf-host-fake is not built ({binary}): `make fake-host`", pytrace=False)
    base = Path(tempfile.mkdtemp(prefix="acf-st-"))
    sock = base / "s"
    if len(str(sock)) > MAX_SOCKET_PATH:
        shutil.rmtree(base, ignore_errors=True)
        pytest.fail(f"$TMPDIR is too deep for a Unix socket ({sock}); run with TMPDIR=/tmp", pytrace=False)
    argv = [str(binary), "--state", str(base / "state"), "--socket", str(sock)]
    if shipped:
        argv += [
            "--config",
            str(REPO / "config" / "host.example.yaml"),
            "--policy",
            str(REPO / "policies" / "default.yaml"),
        ]
    log = (base / "host.log").open("wb")
    proc = subprocess.Popen(argv, stdout=log, stderr=log)
    try:
        deadline = time.monotonic() + 15
        while not sock.exists():
            if proc.poll() is not None or time.monotonic() > deadline:
                pytest.fail(f"the fake host did not start listening:\n{(base / 'host.log').read_text()}", pytrace=False)
            time.sleep(0.05)
        yield sock
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()
        shutil.rmtree(base, ignore_errors=True)


@dataclass(frozen=True)
class HostEnv:
    """Where the host under test keeps things, and how big its envelope is (what the admission tests count against)."""

    state_root: Path
    unit: str
    socket: str
    policy_path: Path
    image: str
    envelope_vcpus: int
    envelope_memory_mib: int
    vmm_overhead_mib: int
    max_sandboxes: int
    snapshot_limit: int | None
    control_plane: bool

    @classmethod
    def from_environment(cls) -> HostEnv:
        env = os.environ
        limit = env.get("ACF_TEST_SNAPSHOT_LIMIT")
        return cls(
            state_root=Path(env.get("ACF_STATE_ROOT", "/var/lib/acf")),
            unit=env.get("ACF_HOST_UNIT", "acf-host.service"),
            socket=env.get("ACF_SOCKET", "/run/acf/host-agent.sock"),
            policy_path=Path(
                env.get(
                    "ACF_POLICY_PATH",
                    str(REPO / "policies" / "default.yaml") if control_plane_enabled() else "/etc/acf/policy.yaml",
                )
            ),
            image=env.get("ACF_TEST_IMAGE", "python"),
            envelope_vcpus=int(env.get("ACF_TEST_ENVELOPE_VCPUS", "4")),
            envelope_memory_mib=int(env.get("ACF_TEST_ENVELOPE_MEMORY_MIB", "8192")),
            vmm_overhead_mib=int(env.get("ACF_TEST_VMM_OVERHEAD_MIB", "64")),
            max_sandboxes=int(env.get("ACF_TEST_MAX_SANDBOXES", "16")),
            snapshot_limit=int(limit) if limit else None,
            control_plane=control_plane_enabled(),
        )

    @property
    def image_dir(self) -> Path:
        return self.state_root / "images" / self.image

    def snapshot_dir(self, snapshot_id: str, generation: int) -> Path:
        return self.state_root / "snapshots" / snapshot_id / str(generation)

    def sandboxes_that_fit(self, *, vcpus: int, memory_mib: int, disk_mib: int, envelope_disk_mib: int = 65536) -> int:
        """How many sandboxes of this size the envelope admits (memory is budgeted WITH the per-VMM overhead)."""
        return min(
            self.max_sandboxes,
            self.envelope_vcpus // vcpus,
            self.envelope_memory_mib // (memory_mib + self.vmm_overhead_mib),
            envelope_disk_mib // disk_mib,
        )


class HostUnit:
    """The systemd unit of the host agent: what the recovery tests crash and restart."""

    def __init__(self, unit: str, acf: AcfLocal) -> None:
        self.unit = unit
        self.acf = acf

    def _systemctl(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["systemctl", *args], capture_output=True, text=True, check=False, timeout=180)

    def main_pid(self) -> int:
        out = self._systemctl("show", "--property=MainPID", "--value", self.unit).stdout.strip()
        return int(out) if out.isdigit() else 0

    def is_active(self) -> bool:
        return self._systemctl("is-active", self.unit).stdout.strip() == "active"

    def reset_start_limit(self) -> None:
        """Forget earlier starts: the unit allows 5 starts per 120 s, and a suite that crashes the agent on purpose
        would otherwise trip systemd's rate limit and see a failed unit instead of a recovering one."""
        self._systemctl("reset-failed", self.unit)

    def kill9(self) -> int:
        """SIGKILL the host agent's main process (not the VMMs: they are not its children) and return its old pid."""
        pid = self.main_pid()
        if pid <= 1:
            raise DriverError(f"{self.unit} has no main process to kill (is it running?)")
        self.reset_start_limit()
        os.kill(pid, signal.SIGKILL)
        return pid

    def restart(self) -> None:
        self.reset_start_limit()
        done = self._systemctl("restart", self.unit)
        if done.returncode != 0:
            raise DriverError(f"systemctl restart {self.unit} failed: {done.stderr}")

    def stop(self) -> None:
        done = self._systemctl("stop", self.unit)
        if done.returncode != 0:
            raise DriverError(f"systemctl stop {self.unit} failed: {done.stderr}")

    def start_if_stopped(self) -> None:
        if not self.is_active():
            self.reset_start_limit()
            self._systemctl("start", self.unit)

    def wait_ready(self, *, not_pid: int = 0, timeout: float = 120.0) -> None:
        """Until the unit is active under a NEW main pid and the agent answers a request (recovery has finished).

        ``Restart=on-failure`` revives it after ``RestartSec``; the unit's ExecStartPost holds `active` back until
        the socket exists, which the agent binds only after recovery completed.
        """
        deadline = time.monotonic() + timeout
        last = "never became active"
        while time.monotonic() < deadline:
            if self.is_active() and self.main_pid() not in (0, not_pid):
                answer = self.acf.call("host", "info", "--json", timeout=15)
                if answer.returncode == EXIT_OK:
                    return
                last = f"active but `host info` exits {answer.returncode}: {answer.stderr.strip()[-300:]}"
            time.sleep(0.5)
        raise DriverError(f"{self.unit} was not ready within {timeout:.0f}s ({last})")


def problems_with_the_host(acf: AcfLocal, host: HostEnv) -> list[str]:
    """Everything that stops the suites from meaning anything on this machine (empty = ready)."""
    problems: list[str] = []
    if not host.control_plane:
        if os.geteuid() != 0:
            problems.append(
                "run as root: the default policy admits uid 0 only, and the white-box checks read the 0700 state directory"
            )
        kvm = Path("/dev/kvm")
        if not kvm.exists():
            problems.append(
                "/dev/kvm does not exist: this machine cannot run microVMs (enable virtualisation / nested KVM)"
            )
        elif not os.access(kvm, os.R_OK | os.W_OK):
            problems.append("/dev/kvm is not readable and writable by this user")
        try:
            mode = Path(host.socket).stat().st_mode
        except OSError:
            problems.append(
                f"the host agent's socket {host.socket} does not exist: `systemctl enable --now acf-host.service`"
            )
        else:
            if not stat.S_ISSOCK(mode):
                problems.append(f"{host.socket} exists but is not a socket")
        if not (host.image_dir / "manifest.json").is_file():
            problems.append(
                f"image {host.image!r} is not installed ({host.image_dir}/manifest.json): scripts/build-image.sh --install"
            )
        if problems:
            return problems  # nothing below can work

    info = acf.call("host", "info", "--json", timeout=30)
    if info.returncode != EXIT_OK:
        return [f"`acf-local host info` failed:\n{info.describe()}"]
    doc = info.json()
    expected = "fake" if host.control_plane else "firecracker"
    if doc["backend"]["name"] != expected:
        problems.append(f"the host runs the {doc['backend']['name']!r} backend, expected {expected!r}")
    if doc["mode"] != "normal":
        problems.append(f"the host is in {doc['mode']!r} mode (a quarantined journal?): recover it before testing")
    if acf.sandbox_list():
        problems.append("sandboxes already exist: these suites own the host and refuse to touch someone else's")
    if acf.snapshot_list():
        problems.append("snapshots already exist: these suites own the host and refuse to touch someone else's")
    return problems


# ------------------------------------------------------------------------------------------------- fixtures
@pytest.fixture(scope="session")
def host_env() -> HostEnv:
    return HostEnv.from_environment()


@pytest.fixture(scope="session")
def acf(host_env: HostEnv) -> Iterator[AcfLocal]:
    """The CLI driver, after proving that this is a ready, idle ACF host (or failing the run with why)."""
    if host_env.control_plane and integration_enabled():
        pytest.fail(
            f"{INTEGRATION_SWITCH}=1 and {CONTROL_PLANE_SWITCH}=1 are mutually exclusive: pick one", pytrace=False
        )
    if host_env.control_plane:
        with fake_host(shipped=True) as sock:
            driver = AcfLocal.from_environment({**os.environ, "ACF_SOCKET": str(sock)})
            problems = problems_with_the_host(driver, host_env)
            if problems:
                pytest.fail("the in-memory host is not usable:\n  - " + "\n  - ".join(problems), pytrace=False)
            yield driver
        return
    driver = AcfLocal.from_environment()
    problems = problems_with_the_host(driver, host_env)
    if problems:
        pytest.fail(
            "this machine is not ready for the integration suites:\n  - " + "\n  - ".join(problems), pytrace=False
        )
    yield driver


@pytest.fixture
def clean_host(acf: AcfLocal, host_env: HostEnv) -> Iterator[AcfLocal]:
    """The driver, with the host brought back to idle after the test (whatever the test did or failed to do)."""
    unit = None if host_env.control_plane else HostUnit(host_env.unit, acf)
    if unit is not None:
        unit.start_if_stopped()  # a crash test must not strand the next one
    yield acf
    if unit is not None:  # a test that crashed the host and then failed must not leave it down
        unit.start_if_stopped()
        unit.wait_ready(timeout=180)
    leftovers = acf.purge()
    if leftovers:
        pytest.fail("the test left things on the host that could not be removed:\n  " + "\n  ".join(leftovers))


@pytest.fixture
def host_unit(acf: AcfLocal, host_env: HostEnv) -> HostUnit:
    return HostUnit(host_env.unit, acf)
