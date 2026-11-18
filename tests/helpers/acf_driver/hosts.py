"""Starting, stopping and restarting the test host (``acf-host-fake``), and looking at the files it keeps.

The binary runs the host's real edge, admission pipeline, coordinator, store and recovery over an in-memory
backend, so it needs neither KVM nor root. Its "guest" echoes the argument vector and exits 0: nothing about a real
guest can be learned from it, and no helper here pretends otherwise.

Two constraints of the host shape this module:

* it refuses trusted files beneath a directory that another user could write, so its state lives in a private
  directory (mode 0700) under ``$ACF_E2E_STATE_DIR`` or ``~/.cache/acf-test`` - never under ``/tmp``. Which
  directory is usable depends on who runs the suite (:func:`state_base` checks, and says why not);
* a Unix socket path is limited to 107 bytes, so the directory names are kept short.
"""

from __future__ import annotations

import contextlib
import os
import pwd
import shutil
import signal
import socket
import stat
import subprocess
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from acf_driver.base import DriverError, tail
from acf_driver.wire import REPO, RawConnection

BINARY_ENV: Final = "ACF_HOST_FAKE"
STATE_ENV: Final = "ACF_E2E_STATE_DIR"
SUN_PATH_MAX: Final = 107
#: The client identities the test host generates with ``--tls-dir``: three are enrolled, ``stranger`` is not.
IDENTITIES: Final = ("operator", "caller", "observer", "stranger")
#: The peer ids the test host enrols them under, and the user who started it.
PEER_IDS: Final = {
    "operator": "tls-operator",
    "caller": "tls-caller",
    "observer": "tls-observer",
    "local": "local-operator",
}
SHIPPED_CONFIG: Final = REPO / "config" / "host.example.yaml"
SHIPPED_PROFILE: Final = REPO / "profiles" / "default.yaml"
SHIPPED_ENROLMENT: Final = REPO / "config" / "enrolment.example.yaml"
_START_TIMEOUT_S: Final = 120.0
_STOP_TIMEOUT_S: Final = 90.0


class HostStartError(Exception):
    """The test host cannot be started here (no binary, or no directory it would accept)."""


def find_binary() -> Path:
    explicit = os.environ.get(BINARY_ENV)
    if not explicit:
        raise HostStartError(
            f"${BINARY_ENV} does not name the test host binary; build it with `make fake-host` "
            "(cargo build --locked -p acf-host-agent --features testing --bin acf-host-fake)"
        )
    path = Path(explicit)
    if not (path.is_file() and os.access(path, os.X_OK)):
        raise HostStartError(f"${BINARY_ENV} names {path}, which is not an executable file: `make fake-host`")
    return path


def untrusted_ancestor(path: Path, euid: int) -> str | None:
    """Why the host would refuse a trusted file inside ``path``, or ``None`` if it would not.

    The host uses a file only if every directory on the way to it is owned by root or by the user the host runs
    as, and is not writable by group or other. (Root trusts only root.) This is the same rule, applied before the
    host is started, so that a wrong location is reported as what it is instead of as a host that will not reload
    its profile.
    """
    trusted = {0, euid}
    current = path.resolve()
    for directory in (current, *current.parents):
        try:
            info = directory.stat()
        except OSError as e:
            return f"{directory} cannot be examined: {e}"
        if info.st_uid not in trusted:
            return f"{directory} is owned by uid {info.st_uid}, which the host (running as uid {euid}) does not trust"
        if stat.S_IMODE(info.st_mode) & 0o022:
            return f"{directory} is writable by group or other (mode {stat.S_IMODE(info.st_mode):04o})"
    return None


def _candidates() -> list[Path]:
    """Where a test host's state may live, in order of preference."""
    found: list[Path] = []
    explicit = os.environ.get(STATE_ENV)
    if explicit:
        return [Path(explicit)]
    home = os.environ.get("HOME")
    if home:
        found.append(Path(home) / ".cache" / "acf-test")
    # Under `sudo --preserve-env=HOME` the variable names another user's home, which root does not trust.
    account = Path(pwd.getpwuid(os.geteuid()).pw_dir) / ".cache" / "acf-test"
    if account not in found:
        found.append(account)
    return found


def state_base() -> Path:
    """The private directory beneath which test hosts keep their state; created 0700 if it does not exist."""
    euid = os.geteuid()
    refused: list[str] = []
    for candidate in _candidates():
        # Judge what exists before creating anything: a location the host would refuse is left exactly as it was.
        existing = next(path for path in (candidate, *candidate.parents) if path.exists())
        why = untrusted_ancestor(existing, euid)
        if why is None:
            try:
                candidate.mkdir(parents=True, exist_ok=True, mode=0o700)
            except OSError as e:
                refused.append(f"{candidate}: cannot be created ({e})")
                continue
            why = untrusted_ancestor(candidate, euid)
            if why is None and not os.access(candidate, os.W_OK | os.X_OK):
                why = f"it is not writable by uid {euid}"
        if why is None:
            return candidate
        refused.append(f"{candidate}: {why}")
    raise HostStartError(
        "no directory the test host would accept its trusted files in:\n  "
        + "\n  ".join(refused)
        + f"\nset ${STATE_ENV} to a short path whose every directory is owned by root or by you and is not "
        "writable by group or other (never /tmp)"
    )


def free_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
        return port


@dataclass(frozen=True)
class TlsIdentity:
    """One generated client identity of a test host, and where its network endpoint listens."""

    name: str
    host: str
    port: int
    certificate: Path
    private_key: Path
    ca: Path

    def options(self) -> list[str]:
        """The global options that point ``acf-local`` at the network endpoint as this identity."""
        return [
            "--tls",
            f"{self.host}:{self.port}",
            "--cert",
            str(self.certificate),
            "--key",
            str(self.private_key),
            "--ca",
            str(self.ca),
        ]

    def connect(self) -> RawConnection:
        return RawConnection.tls(
            self.host,
            self.port,
            certificate=self.certificate,
            private_key=self.private_key,
            ca=self.ca,
            server_name="localhost",
        )


@dataclass
class FakeHost:
    """One test host and the directory it owns. Not started until :meth:`start`."""

    binary: Path
    base: Path
    config: Path | None = None
    profile: Path | None = None
    enrolment: Path | None = None
    tls_port: int | None = None
    edge: str | None = None
    _process: subprocess.Popen[bytes] | None = field(default=None, repr=False)

    # ---- where things are (the layout is the host's own: docs/ARCHITECTURE.md, "Configuration and state on disk")
    @property
    def socket(self) -> Path:
        return self.base / "h.sock"

    @property
    def log(self) -> Path:
        return self.base / "host.log"

    @property
    def tls_dir(self) -> Path:
        return self.base / "tls"

    @property
    def state_dir(self) -> Path:
        """What is passed as ``--state``: the host writes its profile and enrolment copies here."""
        return self.base / "state"

    @property
    def state_root(self) -> Path:
        """The host's ``paths.state_root``: store, sandboxes, snapshots, artifacts, telemetry."""
        return self.state_dir / "state-root"

    @property
    def profile_path(self) -> Path:
        """The safety profile file the host re-reads on ``profile.reload``."""
        return self.state_dir / "profile.yaml"

    @property
    def enrolment_path(self) -> Path:
        """The enrolment table the host re-reads while it runs."""
        return self.state_dir / "enrolment.yaml"

    @property
    def journal(self) -> Path:
        return self.state_root / "state" / "journal.wal"

    def generation_dir(self, sandbox_id: str, generation: int) -> Path:
        return self.state_root / "sandboxes" / sandbox_id / str(generation)

    def snapshot_dir(self, snapshot_id: str, generation: int) -> Path:
        return self.state_root / "snapshots" / snapshot_id / str(generation)

    # ---- its life
    @property
    def pid(self) -> int:
        if self._process is None or self._process.poll() is not None:
            raise DriverError("the test host is not running")
        return self._process.pid

    @property
    def running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def log_text(self) -> str:
        try:
            return self.log.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def _argv(self) -> list[str]:
        argv = [str(self.binary), "--state", str(self.state_dir), "--socket", str(self.socket)]
        if self.config is not None:
            argv += ["--config", str(self.config)]
        if self.profile is not None:
            argv += ["--profile", str(self.profile)]
        if self.enrolment is not None:
            argv += ["--enrolment", str(self.enrolment)]
        if self.tls_port is not None:
            argv += ["--tls-listen", f"127.0.0.1:{self.tls_port}", "--tls-dir", str(self.tls_dir)]
        if self.edge is not None:
            argv += ["--edge", self.edge]
        return argv

    def start(self, *, timeout: float = _START_TIMEOUT_S) -> None:
        """Start the host over whatever its directory already holds, and wait until it serves (recovery is done)."""
        if self.running:
            raise DriverError("the test host is already running")
        environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        for passthrough in ("RUST_LOG", "ACF_LOG_FORMAT"):
            if passthrough in os.environ:
                environment[passthrough] = os.environ[passthrough]
        with self.log.open("ab") as log:
            self._process = subprocess.Popen(
                self._argv(), stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, env=environment
            )
        deadline = time.monotonic() + timeout
        while not self._serving():
            if self._process.poll() is not None:
                raise HostStartError(
                    f"acf-host-fake exited with status {self._process.returncode}:\n{tail(self.log_text())}"
                )
            if time.monotonic() >= deadline:
                self.kill()
                raise HostStartError(f"acf-host-fake did not serve within {timeout:.0f} s:\n{tail(self.log_text())}")
            time.sleep(0.05)

    def _serving(self) -> bool:
        return _accepts(socket.AF_UNIX, str(self.socket)) and (
            self.tls_port is None or _accepts(socket.AF_INET, ("127.0.0.1", self.tls_port))
        )

    def stop(self, *, timeout: float = _STOP_TIMEOUT_S) -> int:
        """Ask the host to stop (SIGTERM: it drains, then exits) and return its exit status."""
        process = self._process
        if process is None:
            raise DriverError("the test host was never started")
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired as e:
                process.kill()
                process.wait()
                raise DriverError(
                    f"the test host did not stop within {timeout:.0f} s of SIGTERM:\n{tail(self.log_text())}"
                ) from e
        return process.returncode

    def kill(self) -> None:
        """End the host with SIGKILL: no drain, no clean shutdown. Harmless when it is not running.

        A killed core cannot end its edge. The edge ends by itself when it sees its channel to the core close, and
        until then it still holds the listening socket: a new activation started in that moment would find "another
        process listening" and refuse to start. So this returns only once nothing accepts on the socket any more.
        The socket *file* is left where it is: replacing a dead socket is the next activation's own job.
        """
        process = self._process
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        deadline = time.monotonic() + 15.0
        while _accepts(socket.AF_UNIX, str(self.socket)):
            if time.monotonic() >= deadline:
                raise DriverError(
                    f"something still accepts on {self.socket} 15 s after the core was killed (its edge?)"
                )
            time.sleep(0.05)

    def restart(self, *, hard: bool = False) -> None:
        """A new activation over the same store. The in-memory runtimes of the old one are gone with it."""
        if hard:
            self.kill()
        else:
            self.stop()
        self.start()

    def destroy(self) -> None:
        """Stop the host and remove everything it owns."""
        self.kill()
        shutil.rmtree(self.base, ignore_errors=True)

    # ---- how to reach it
    def connect(self) -> RawConnection:
        """A raw connection to the local endpoint, as the user who started the host (``local-operator``)."""
        return RawConnection.unix(self.socket)

    def identity(self, name: str) -> TlsIdentity:
        if self.tls_port is None:
            raise DriverError("this test host was started without a network endpoint")
        if name not in IDENTITIES:
            raise DriverError(f"the test host generates {IDENTITIES}, not {name!r}")
        return TlsIdentity(
            name=name,
            host="127.0.0.1",
            port=self.tls_port,
            certificate=self.tls_dir / f"{name}.crt",
            private_key=self.tls_dir / f"{name}.key",
            ca=self.tls_dir / "ca.crt",
        )


def _accepts(family: socket.AddressFamily, address: str | tuple[str, int]) -> bool:
    with contextlib.closing(socket.socket(family, socket.SOCK_STREAM)) as probe:
        probe.settimeout(1.0)
        try:
            probe.connect(address)
        except OSError:
            return False
        return True


def new_fake_host(
    *,
    shipped: bool,
    tls: bool = False,
    config: Path | None = None,
    profile: Path | None = None,
    enrolment: Path | None = None,
    edge: str | None = None,
) -> FakeHost:
    """A test host with a directory of its own, not yet started.

    ``shipped=True`` loads ``config/host.example.yaml`` and ``profiles/default.yaml`` (the files an operator
    installs) instead of the small pair built into the binary; ``config`` and ``profile`` name other files. Without
    ``enrolment`` the user who starts the host is enrolled as ``local-operator``.
    """
    binary = find_binary()
    base = state_base() / f"h-{uuid.uuid4().hex[:10]}"
    base.mkdir(mode=0o700)
    host = FakeHost(
        binary=binary,
        base=base,
        config=config or (SHIPPED_CONFIG if shipped else None),
        profile=profile or (SHIPPED_PROFILE if shipped else None),
        enrolment=enrolment,
        tls_port=free_port() if tls else None,
        edge=edge,
    )
    if len(os.fsencode(host.socket)) > SUN_PATH_MAX:
        shutil.rmtree(base, ignore_errors=True)
        raise HostStartError(f"{host.socket} is longer than {SUN_PATH_MAX} bytes; set ${STATE_ENV} to a shorter path")
    return host


@contextlib.contextmanager
def fake_host(
    *,
    shipped: bool,
    tls: bool = False,
    config: Path | None = None,
    profile: Path | None = None,
    enrolment: Path | None = None,
    edge: str | None = None,
) -> Iterator[FakeHost]:
    """A running test host for the duration of the block; stopped and removed afterwards, whatever happened."""
    host = new_fake_host(shipped=shipped, tls=tls, config=config, profile=profile, enrolment=enrolment, edge=edge)
    try:
        host.start()
        yield host
    finally:
        host.destroy()
