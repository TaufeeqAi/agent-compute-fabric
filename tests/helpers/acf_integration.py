"""Modes, environment and fixtures of ``tests/integration`` and ``tests/isolation``.

Those suites exist in two halves, and there are exactly two ways to run them:

* ``ACF_INTEGRATION=1`` (``make integration``): everything, against a RUNNING production ``acf-host`` on a KVM host.
  The machine is *required* to be ready. If it is not, the run ERRORS with a list of what is missing: a suite that
  quietly skips when its environment is broken would report success on exactly the machines where the isolation
  claims matter. Tests whose subject is a real guest or a real VMM are named after the entry of the contract's test
  catalog they implement (``test_t_net_04_...``) and need root on that host.
* ``ACF_CONTROL_PLANE=1`` (``make control-plane``): only the tests marked ``control_plane``, against the test host
  (``acf-host-fake``) started with the SHIPPED ``config/host.example.yaml`` and ``profiles/default.yaml``. No KVM, no
  root. These are the checks that do not depend on what runs inside a guest (admission per state, idempotency,
  scopes and roles, ceilings, network admission, snapshots, host modes, quarantine, the protocol's refusals), made
  through the real client and the real wire against the files an operator installs. Everything else is skipped,
  and says why.

With neither switch every test is *skipped*, with the reason in the report. With both, the run fails: pick one.
``ACF_DRIVER_SELFTEST=1`` (``make driver-selftest``) enables ``tests/integration/test_driver_selftest.py``, which
proves the driver these suites use against the test host.

Environment (all optional except the switch):

=========================  ==========================================================  =============================
``ACF_INTEGRATION``        ``1``: the whole suites, against a running host on KVM      unset: skip
``ACF_CONTROL_PLANE``      ``1``: the ``control_plane`` subset on the test host         unset: skip
``ACF_DRIVER_SELFTEST``    ``1``: the driver's own tests                                unset: skip
``ACF_LOCAL``              the reference client's command line, split like a shell      ``acf-local``
``ACF_HOST_FAKE``          the test host binary (control-plane and self-test)           none: the run fails
``ACF_E2E_STATE_DIR``      a private directory for the test hosts' state                ``~/.cache/acf-test``
``ACF_TEST_IMAGE``         the image alias the suites create sandboxes from             ``python``
``ACF_HOST_CONFIG``        the configuration the running host was started with          ``/etc/acf/host.yaml``
``ACF_SOCKET``             the running host's local endpoint                            ``paths.socket_path`` of it
``ACF_HOST_UNIT``          systemd unit of the core                                     ``acf-host.service``
``ACF_LIFETIME_UNIT``      systemd unit of the lifetime enforcer                        ``acf-lifetime.service``
``ACF_HOST_BIN``           the installed ``acf-host`` (its ``doctor`` is the preflight)  ``/opt/acf/bin/acf-host``
``ACF_REQUIRE_ROOT``       ``1``: a control-plane test that needs root FAILS without it  unset: it skips
``ACF_ENTRY_RECORD``       where the entry-conditions test writes its record (JSON)     unset: not written
=========================  ==========================================================  =============================

Where the running host keeps things (its state directory, its runtime directory, its control groups, its safety
profile) is read from ``ACF_HOST_CONFIG``; the bounds the suites assert on are read from the same file and from the
profile it names, never copied into a test.

The suites assume they OWN the host: they refuse to start while sandboxes or snapshots exist, and after every test
they remove whatever is live.
"""

from __future__ import annotations

import contextlib
import enum
import json
import os
import shutil
import signal
import stat
import subprocess
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import pytest

from acf_driver import (
    SHIPPED_CONFIG,
    SHIPPED_PROFILE,
    AcfLocal,
    DriverError,
    FakeHost,
    HostStartError,
    Sandbox,
    Settings,
    Snapshot,
    Target,
    new_fake_host,
)
from acf_proc import process_alive

INTEGRATION_SWITCH: Final = "ACF_INTEGRATION"
CONTROL_PLANE_SWITCH: Final = "ACF_CONTROL_PLANE"
SELFTEST_SWITCH: Final = "ACF_DRIVER_SELFTEST"
REQUIRE_ROOT_SWITCH: Final = "ACF_REQUIRE_ROOT"
ENTRY_RECORD: Final = "ACF_ENTRY_RECORD"

DEFAULT_CONFIG: Final = "/etc/acf/host.yaml"
DEFAULT_HOST_BINARY: Final = "/opt/acf/bin/acf-host"
TEST_HOST_ONLY: Final = (
    "this check uses the test host's own files or identities; it runs under `make control-plane` "
    f"({CONTROL_PLANE_SWITCH}=1), not against a production host"
)


def integration_enabled(environ: Mapping[str, str] | None = None) -> bool:
    return (os.environ if environ is None else environ).get(INTEGRATION_SWITCH) == "1"


def control_plane_enabled(environ: Mapping[str, str] | None = None) -> bool:
    return (os.environ if environ is None else environ).get(CONTROL_PLANE_SWITCH) == "1"


def selftest_enabled(environ: Mapping[str, str] | None = None) -> bool:
    return (os.environ if environ is None else environ).get(SELFTEST_SWITCH) == "1"


class Mode(enum.Enum):
    """Which host the suites run against."""

    INTEGRATION = "a running production host on KVM"
    CONTROL_PLANE = "the test host with the shipped configuration and profile"
    NONE = "none"


class ModeError(Exception):
    """The switches contradict each other."""


def selected_mode(environ: Mapping[str, str] | None = None) -> Mode:
    integration, control_plane = integration_enabled(environ), control_plane_enabled(environ)
    if integration and control_plane:
        raise ModeError(f"{INTEGRATION_SWITCH}=1 and {CONTROL_PLANE_SWITCH}=1 are mutually exclusive: pick one")
    if integration:
        return Mode.INTEGRATION
    return Mode.CONTROL_PLANE if control_plane else Mode.NONE


# ----------------------------------------------------------------------------------------------- the host under test
@dataclass(frozen=True)
class HostEnv:
    """The host the suites run against: where it keeps things, and the files its bounds come from."""

    mode: Mode
    image: str
    socket: Path
    #: The host configuration in force (the shipped example, under the test host).
    config: Settings
    #: The safety profile in force.
    profile: Settings
    state_root: Path
    runtime_dir: Path
    unit: str = "acf-host.service"
    lifetime_unit: str = "acf-lifetime.service"
    host_binary: Path = Path(DEFAULT_HOST_BINARY)
    #: The session's test host, in control-plane mode.
    fake: FakeHost | None = None

    @classmethod
    def for_test_host(cls, host: FakeHost, environ: Mapping[str, str] | None = None) -> HostEnv:
        """The test host: it loads the shipped files and rewrites only the paths, into its own directory."""
        source = os.environ if environ is None else environ
        if host.config is None or host.profile is None:
            raise DriverError("the suites run against a test host that loads the shipped configuration and profile")
        return cls(
            mode=Mode.CONTROL_PLANE,
            image=source.get("ACF_TEST_IMAGE", "python"),
            socket=host.socket,
            config=Settings.load(host.config),
            profile=Settings.load(host.profile),
            state_root=host.state_root,
            runtime_dir=host.state_dir / "run",
            fake=host,
        )

    @classmethod
    def for_installed_host(cls, environ: Mapping[str, str] | None = None) -> HostEnv:
        """A production host, described by the configuration file it was started with.

        A file that cannot be read does not raise here: what is missing on the machine is reported as one list by
        :func:`machine_problems`. Until then the shipped example (the built-in defaults) answers.
        """
        source = os.environ if environ is None else environ
        shipped_config, shipped_profile = Settings.load(SHIPPED_CONFIG), Settings.load(SHIPPED_PROFILE)
        config = _load_or_empty(Path(source.get("ACF_HOST_CONFIG", DEFAULT_CONFIG)), shipped_config)
        profile = _load_or_empty(Path(config.text("paths.profile_path")), shipped_profile)
        return cls(
            mode=Mode.INTEGRATION,
            image=source.get("ACF_TEST_IMAGE", "python"),
            socket=Path(source.get("ACF_SOCKET") or config.text("paths.socket_path")),
            config=config,
            profile=profile,
            state_root=Path(config.text("paths.state_root")),
            runtime_dir=Path(config.text("paths.runtime_dir")),
            unit=source.get("ACF_HOST_UNIT", "acf-host.service"),
            lifetime_unit=source.get("ACF_LIFETIME_UNIT", "acf-lifetime.service"),
            host_binary=Path(source.get("ACF_HOST_BIN", DEFAULT_HOST_BINARY)),
        )

    @property
    def control_plane(self) -> bool:
        return self.mode is Mode.CONTROL_PLANE

    # ---- bounds, from the files
    @property
    def vmm_overhead_mib(self) -> int:
        """Memory the runtime itself needs beyond guest memory: counted in admission."""
        return self.config.integer("firecracker.vmm_overhead_mib")

    def sandboxes_that_fit(self, *, vcpus: int, memory_mib: int, disk_mib: int) -> int:
        """How many sandboxes of this size the envelope admits (memory is budgeted WITH the per-runtime overhead)."""
        cfg = self.config
        return min(
            cfg.integer("envelope.max_sandboxes"),
            cfg.integer("envelope.vcpus") // vcpus,
            cfg.integer("envelope.memory_mib") // (memory_mib + self.vmm_overhead_mib),
            cfg.integer("envelope.disk_mib") // disk_mib,
        )

    # ---- where the host keeps what belongs to one generation (docs/ARCHITECTURE.md, "state on disk")
    @property
    def image_dir(self) -> Path:
        return self.state_root / "images" / self.image

    def generation_dir(self, sandbox: Sandbox) -> Path:
        return self.state_root / "sandboxes" / sandbox.sandbox_id / str(sandbox.generation)

    def snapshot_dir(self, snapshot: Snapshot) -> Path:
        return self.state_root / "snapshots" / snapshot.snapshot_id / str(snapshot.snapshot_generation)

    def jail_root(self, sandbox: Sandbox) -> Path:
        """What the runtime of ``sandbox`` sees as ``/`` (the jailer's layout beneath the generation directory)."""
        vmm = Path(self.config.text("firecracker.firecracker_bin")).name
        return self.generation_dir(sandbox) / "jail" / vmm / sandbox.jail_id / "root"

    @property
    def cgroup_parent(self) -> Path:
        return Path(self.config.text("firecracker.cgroup_root")) / self.config.text("firecracker.cgroup_parent")

    def cgroup_dir(self, sandbox: Sandbox) -> Path:
        """The control group that bounds the runtime of ``sandbox``."""
        return self.cgroup_parent / sandbox.jail_id

    def traffic_cgroup_dir(self, sandbox: Sandbox) -> Path:
        """The control group of the guest-traffic process of ``sandbox`` (network mode ``allowlist``)."""
        return self.cgroup_parent / f"{sandbox.jail_id}-net"

    def netns_handle(self, sandbox: Sandbox) -> Path:
        """The file that keeps the network namespace of ``sandbox`` alive."""
        return self.runtime_dir / "netns" / f"acf-{sandbox.jail_id}"

    def expiry_ticket(self, sandbox: Sandbox) -> Path:
        """What the lifetime enforcer reads to end the runtime of ``sandbox`` at its expiry."""
        return self.runtime_dir / "expiry" / f"{sandbox.jail_id}.ticket"

    # ---- the test host's own files and identities
    def test_host(self) -> FakeHost:
        """The session's test host; a check that needs it is not one for a production host."""
        if self.fake is None:
            pytest.skip(TEST_HOST_ONLY)
        return self.fake

    def peer(self, acf: AcfLocal, identity: str, scope: str | None = None) -> AcfLocal:
        """The client as one of the identities the test host generated: operator, caller, observer or stranger."""
        return acf.as_peer(Target(tls=self.test_host().identity(identity), scope=scope))


def _load_or_empty(path: Path, defaults: Settings) -> Settings:
    try:
        return Settings.load(path, defaults=defaults)
    except (OSError, ValueError):
        return Settings(path=path, values={}, defaults=defaults)


@dataclass(frozen=True)
class PrivateHost:
    """A test host of one test's own, and the client as the user who started it (``local-operator``)."""

    host: FakeHost
    acf: AcfLocal

    def peer(self, identity: str, scope: str | None = None) -> AcfLocal:
        return self.acf.as_peer(Target(tls=self.host.identity(identity), scope=scope))


@contextlib.contextmanager
def private_host(
    env: HostEnv,
    acf: AcfLocal,
    *,
    tls: bool = False,
    config: Path | None = None,
    profile: Path | None = None,
    enrolment: Path | None = None,
) -> Iterator[PrivateHost]:
    """A second test host with the shipped files, for a check that changes what a host is: its mode for good, its
    profile or enrolment file, its store, or its life. The session's host is shared by every test and stays as it is.
    """
    if not env.control_plane:
        pytest.skip(TEST_HOST_ONLY)
    try:
        host = new_fake_host(shipped=True, tls=tls, config=config, profile=profile, enrolment=enrolment)
    except HostStartError as e:
        pytest.fail(str(e), pytrace=False)
    try:
        try:
            host.start()
        except HostStartError as e:
            pytest.fail(str(e), pytrace=False)
        yield PrivateHost(host=host, acf=acf.as_peer(Target(socket=host.socket)))
    finally:
        host.destroy()


def edited_copy(source: Path, destination: Path, replacements: Mapping[str, str]) -> Path:
    """A copy of ``source`` in which each key of ``replacements`` (which must occur exactly once) is replaced."""
    text = source.read_text(encoding="utf-8")
    for old, new in replacements.items():
        if text.count(old) != 1:
            raise DriverError(f"{source} contains {old!r} {text.count(old)} times; a replacement must be unambiguous")
        text = text.replace(old, new)
    destination.write_text(text, encoding="utf-8")
    destination.chmod(0o644)
    return destination


def require_root(env: HostEnv, what: str) -> None:
    """A check that needs uid 0 on this machine (``what`` says for what).

    Against a production host a missing root is an error of the environment. Against the test host it is a skip,
    unless ``ACF_REQUIRE_ROOT=1`` (CI's second pass) makes that a failure, so the gate cannot go green without it.
    """
    if os.geteuid() == 0:
        return
    if env.mode is Mode.INTEGRATION or os.environ.get(REQUIRE_ROOT_SWITCH) == "1":
        pytest.fail(f"this check needs root ({what}), and this process is uid {os.geteuid()}", pytrace=False)
    pytest.skip(f"needs root: {what} ({REQUIRE_ROOT_SWITCH}=1 makes this a failure)")


# ----------------------------------------------------------------------------------------------- systemd
class SystemdUnit:
    """One unit of the production host, as systemd sees it."""

    def __init__(self, name: str) -> None:
        self.name = name

    def _systemctl(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["systemctl", *args], capture_output=True, text=True, check=False, timeout=300)

    def main_pid(self) -> int:
        out = self._systemctl("show", "--property=MainPID", "--value", self.name).stdout.strip()
        return int(out) if out.isdigit() else 0

    def is_active(self) -> bool:
        return self._systemctl("is-active", self.name).stdout.strip() == "active"

    def reset_start_limit(self) -> None:
        """Forget earlier starts: a suite that ends the core on purpose would otherwise trip systemd's start limit
        (5 starts in 120 s) and find a failed unit where it expects a recovering one."""
        self._systemctl("reset-failed", self.name)

    def kill9(self) -> int:
        """SIGKILL the unit's main process and return the pid it had. Its runtimes are not its children."""
        pid = self.main_pid()
        if pid <= 1:
            raise DriverError(f"{self.name} has no main process to kill (is it running?)")
        self.reset_start_limit()
        os.kill(pid, signal.SIGKILL)
        return pid

    def restart(self) -> None:
        self.reset_start_limit()
        done = self._systemctl("restart", self.name)
        if done.returncode != 0:
            raise DriverError(f"systemctl restart {self.name} failed: {done.stderr}")

    def stop(self) -> None:
        done = self._systemctl("stop", self.name)
        if done.returncode != 0:
            raise DriverError(f"systemctl stop {self.name} failed: {done.stderr}")

    def start(self) -> None:
        self.reset_start_limit()
        done = self._systemctl("start", self.name)
        if done.returncode != 0:
            raise DriverError(f"systemctl start {self.name} failed: {done.stderr}")

    def start_if_stopped(self) -> None:
        if not self.is_active():
            self.start()


class HostUnit(SystemdUnit):
    """The unit of the core: what the recovery tests end, and wait for."""

    def __init__(self, name: str, acf: AcfLocal) -> None:
        super().__init__(name)
        self.acf = acf

    def kill_and_keep_down(self) -> int:
        """SIGKILL the core and keep systemd from starting it again; returns the pid it had."""
        pid = self.kill9()
        self.stop()  # the unit would restart after RestartSec; a stop withdraws that
        return pid

    def wait_ready(self, *, not_pid: int = 0, timeout: float = 180.0) -> None:
        """Until the unit is active under a NEW main pid and the host answers a request.

        The unit counts as started only when a process listens on the local endpoint, which the core opens after
        its startup recovery: an answer therefore means recovery has finished.
        """
        deadline = time.monotonic() + timeout
        last = "never became active"
        while time.monotonic() < deadline:
            if self.is_active() and self.main_pid() not in (0, not_pid):
                try:
                    self.acf.wire.info()
                except (OSError, DriverError) as e:
                    last = f"active, but it does not answer host.info: {e}"
                else:
                    return
            time.sleep(0.5)
        raise DriverError(f"{self.name} was not ready within {timeout:.0f}s ({last})")


# ----------------------------------------------------------------------------------------------- is it ready?
def machine_problems(env: HostEnv, *, euid: int | None = None) -> list[str]:
    """Everything about THIS MACHINE that stops the suites from meaning anything against a production host.

    Each entry names one missing thing and what provides it. An empty list means: go on and ask the host itself.
    """
    problems: list[str] = []
    if (os.geteuid() if euid is None else euid) != 0:
        problems.append(
            "not root: the suites end and inspect processes of other users, write control-group files, enter network "
            "namespaces and read the host's 0700 state directory (run them with sudo)"
        )
    kvm = Path("/dev/kvm")
    if not kvm.exists():
        problems.append(
            "/dev/kvm does not exist: this machine cannot run microVMs (enable virtualisation or nested KVM)"
        )
    elif not os.access(kvm, os.R_OK | os.W_OK):
        problems.append("/dev/kvm is not readable and writable by this user")
    if not env.config.path.is_file():
        problems.append(
            f"the host configuration {env.config.path} does not exist: `scripts/host-setup.sh install` "
            "(or set ACF_HOST_CONFIG to the file the host was started with)"
        )
    if not env.profile.path.is_file():
        problems.append(f"the safety profile {env.profile.path} does not exist: `scripts/host-setup.sh install`")
    try:
        mode = env.socket.stat().st_mode
    except OSError:
        problems.append(
            f"no host is running: its local endpoint {env.socket} does not exist "
            f"(`systemctl enable --now acf-cgroup.service {env.lifetime_unit} {env.unit}`)"
        )
    else:
        if not stat.S_ISSOCK(mode):
            problems.append(f"{env.socket} exists but is not a socket")
    if not (env.image_dir / "manifest.json").is_file():
        problems.append(
            f"image {env.image!r} is not installed ({env.image_dir}/manifest.json): "
            f"`scripts/build-image.sh --image {env.image} --kernel <vmlinux> --install`"
        )
    if shutil.which("systemctl") is None:
        problems.append("systemctl is not on PATH: the recovery tests end and restart the host through its units")
    else:
        problems += [
            f"unit {unit.name} is not active: `systemctl start {unit.name}`"
            for unit in (SystemdUnit(env.unit), SystemdUnit(env.lifetime_unit))
            if not unit.is_active()
        ]
    problems += _doctor_failures(env)
    return problems


def _doctor_failures(env: HostEnv) -> list[str]:
    """What the host's own preflight (``acf-host doctor --json``) says cannot hold on this machine."""
    if not env.host_binary.is_file():
        return [f"the host binary {env.host_binary} does not exist (set ACF_HOST_BIN): its `doctor` is the preflight"]
    if not env.config.path.is_file():
        return []
    done = subprocess.run(
        [str(env.host_binary), "doctor", "--config", str(env.config.path), "--json"],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    try:
        checks = json.loads(done.stdout)
    except json.JSONDecodeError:
        return [
            f"`{env.host_binary} doctor --json` printed no report (exit {done.returncode}): {done.stderr.strip()[-400:]}"
        ]
    return [
        f"doctor: {check.get('name')}: {check.get('detail')}"
        for check in checks
        if isinstance(check, dict) and str(check.get("status", "")).upper() == "FAIL"
    ]


def host_problems(acf: AcfLocal, env: HostEnv) -> list[str]:
    """What the host itself says that stops the suites from meaning anything (empty: ready)."""
    try:
        info = acf.wire.info()
    except (OSError, DriverError) as e:
        return [f"the host at {env.socket} does not answer `host.info`: {e}"]
    problems: list[str] = []
    expected = "fake" if env.control_plane else "firecracker"
    if info.backend_name != expected:
        problems.append(f"the host runs the {info.backend_name!r} backend, expected {expected!r}")
    if info.mode != "SERVING":
        reasons = [f"{r.get('reason')}: {r.get('detail')}" for r in info.containment_reasons]
        if info.read_only_reason:
            reasons.append(info.read_only_reason)
        problems.append(f"the host is {info.mode}, not SERVING" + (f": {'; '.join(reasons)}" if reasons else ""))
    if not env.control_plane and "allowlist" not in info.network_modes:
        problems.append(
            "the host does not offer network mode `allowlist`: iproute2, nftables and util-linux (`ip`, `nft`, "
            "`nsenter`) must be trusted executables at the configured paths (doctor: network_tools)"
        )
    if info.quarantined:
        problems.append(f"{info.quarantined} generation(s) are quarantined: release them before testing")
    try:
        sandboxes, snapshots = acf.wire.sandboxes(), acf.wire.snapshots()
    except DriverError as e:
        return [*problems, f"the suite's peer cannot list what the host holds: {e}"]
    if sandboxes:
        problems.append(f"{len(sandboxes)} sandbox(es) already exist: these suites own the host and touch nothing else")
    if snapshots:
        problems.append(f"{len(snapshots)} snapshot(s) already exist: these suites own the host and touch nothing else")
    return problems


# ----------------------------------------------------------------------------------------------- one generation
OWNERSHIP_MARKER: Final = "OWNER.json"


def await_sandbox(
    acf: AcfLocal, sandbox: Sandbox, accept: Callable[[Sandbox], bool], *, within: float, what: str
) -> Sandbox:
    """Poll the host's record of ``sandbox`` until ``accept`` holds; the error names the last record seen."""
    deadline = time.monotonic() + within
    while True:
        seen = acf.wire.refresh(sandbox)
        if accept(seen):
            return seen
        if time.monotonic() >= deadline:
            raise DriverError(f"{what}: not within {within:.1f}s; the host's record is {seen!r}")
        time.sleep(0.2)


def forge_ownership_marker(env: HostEnv, sandbox: Sandbox, content: str = "{}") -> tuple[Path, str]:
    """Replace the ownership marker of the generation with ``content``; returns its path and what it held.

    The marker is how the host proves that a directory, a process or a namespace is its own before it signals or
    deletes anything. A marker that proves nothing must leave the generation untouched and quarantined.
    """
    marker = env.generation_dir(sandbox) / OWNERSHIP_MARKER
    original = marker.read_text(encoding="utf-8")
    marker.write_text(content, encoding="utf-8")
    return marker, original


def quarantine_by_forgery(acf: AcfLocal, env: HostEnv, sandbox: Sandbox) -> Sandbox:
    """Forge the ownership marker of ``sandbox`` and wait until the host has noticed; returns the quarantined record.

    Nothing is asked of the host: its own observation of every generation (at least every
    ``recovery.sweep_interval_ms``) must find that the generation's resources are no longer provably its own.
    """
    forge_ownership_marker(env, sandbox)
    bound = env.config.integer("recovery.sweep_interval_ms") / 1000 + 10
    return await_sandbox(
        acf, sandbox, lambda seen: bool(seen.quarantined), within=bound, what="quarantine of a forged generation"
    )


# ----------------------------------------------------------------------------------------------- a real runtime
def vmm_of(sandbox: Sandbox) -> tuple[int, int]:
    """The runtime process the host recorded for ``sandbox`` as ``(pid, start time)``, proven to exist here."""
    identity = sandbox.vmm_identity
    if identity is None:
        raise DriverError(f"the host records no runtime process for {sandbox.sandbox_id} ({sandbox.state})")
    if not process_alive(*identity):
        raise DriverError(
            f"the host says pid {identity[0]} (started at tick {identity[1]}) runs {sandbox.sandbox_id}, "
            "but this machine has no such process"
        )
    return identity


def seconds_until_gone(identity: tuple[int, int], *, within: float, what: str) -> float:
    """Wait for the process ``identity`` to end; returns how long it took, or fails after ``within`` seconds."""
    started = time.monotonic()
    while process_alive(*identity):
        if time.monotonic() - started > within:
            raise DriverError(f"{what}: pid {identity[0]} was still running after {within:.1f}s")
        time.sleep(0.05)
    return time.monotonic() - started


def in_namespace(env: HostEnv, sandbox: Sandbox, *argv: str) -> subprocess.CompletedProcess[str]:
    """Run ``argv`` inside the network namespace of ``sandbox`` (through the file that keeps it alive)."""
    handle = env.netns_handle(sandbox)
    return subprocess.run(
        ["nsenter", f"--net={handle}", "--", *argv], capture_output=True, text=True, check=False, timeout=60
    )


# ----------------------------------------------------------------------------------------------- fixtures
@pytest.fixture(scope="session")
def host_env() -> Iterator[HostEnv]:
    """The host the suites run against. In control-plane mode this starts it, with the shipped files."""
    try:
        mode = selected_mode()
    except ModeError as e:
        pytest.fail(str(e), pytrace=False)
    if mode is Mode.NONE:
        pytest.skip(f"needs {INTEGRATION_SWITCH}=1 (a KVM host) or {CONTROL_PLANE_SWITCH}=1 (the test host)")
    if mode is Mode.INTEGRATION:
        yield HostEnv.for_installed_host()
        return
    try:
        host = new_fake_host(shipped=True, tls=True)
    except HostStartError as e:
        pytest.fail(str(e), pytrace=False)
    try:
        try:
            host.start()
        except HostStartError as e:
            pytest.fail(str(e), pytrace=False)
        yield HostEnv.for_test_host(host)
    finally:
        host.destroy()


@pytest.fixture(scope="session")
def acf(host_env: HostEnv) -> AcfLocal:
    """The client, as the suites' own peer (an operator on the local endpoint), after proving the host is ready."""
    driver = AcfLocal.for_target(Target(socket=host_env.socket), image=host_env.image)
    problems = [] if host_env.control_plane else machine_problems(host_env)
    if not problems:
        problems = host_problems(driver, host_env)
    if problems:
        what = "the test host is not usable" if host_env.control_plane else "this machine is not ready for the suites"
        pytest.fail(f"{what}:\n  - " + "\n  - ".join(problems), pytrace=False)
    return driver


@pytest.fixture
def clean_host(acf: AcfLocal, host_env: HostEnv) -> Iterator[AcfLocal]:
    """The client, with the host brought back to idle and serving after the test, whatever the test did."""
    unit = None if host_env.control_plane else HostUnit(host_env.unit, acf)
    if unit is not None:
        unit.start_if_stopped()  # a test that ended the core and then failed must not strand the next one
        unit.wait_ready()
    yield acf
    if unit is not None:
        unit.start_if_stopped()
        unit.wait_ready()
    elif host_env.fake is not None and not host_env.fake.running:
        pytest.fail(f"the test host is no longer running:\n{host_env.fake.log_text()[-2000:]}", pytrace=False)
    try:
        leftovers = acf.purge()
    except (OSError, DriverError) as e:
        pytest.fail(f"the host could not be tidied up after the test: {e}", pytrace=False)
    if leftovers:
        pytest.fail(
            "the test left things on the host that could not be removed:\n  " + "\n  ".join(leftovers), pytrace=False
        )


@pytest.fixture
def host_unit(acf: AcfLocal, host_env: HostEnv) -> HostUnit:
    """The systemd unit of the core of a production host."""
    if host_env.control_plane:
        pytest.fail(
            "the test host is not a systemd unit: this fixture is for tests that need a production host", pytrace=False
        )
    return HostUnit(host_env.unit, acf)
