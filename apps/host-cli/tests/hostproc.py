"""Start and stop the real test host (``acf-host-fake``) for end-to-end tests.

The binary runs the host's real edge, admission pipeline, coordinator, store and recovery over an
in-memory backend, so no KVM and no root are needed. It is located through ``$ACF_HOST_FAKE``.

Two constraints of the host shape this module:

* it refuses trusted files beneath a world-writable directory, so its state lives in a private
  directory (mode 0700) under ``$ACF_E2E_STATE_DIR`` or ``~/.cache/acf-test`` — never under ``/tmp``;
* a Unix socket path is limited to 107 bytes, so the directory names are kept short.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import socket
import subprocess
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from acf_cli.transport import TlsEndpoint, UnixEndpoint

BINARY_ENV = "ACF_HOST_FAKE"
REQUIRE_ENV = "ACF_REQUIRE_E2E"
STATE_ENV = "ACF_E2E_STATE_DIR"
SUN_PATH_MAX = 107
#: The client identities the test host generates: three are enrolled, ``stranger`` is not.
IDENTITIES = ("operator", "caller", "observer", "stranger")
_START_TIMEOUT_S = 30.0


class HostUnavailable(Exception):
    """The test host cannot be started here (no binary, or no usable state directory)."""


def find_binary() -> Path | None:
    explicit = os.environ.get(BINARY_ENV)
    if not explicit:
        return None
    path = Path(explicit)
    return path if path.is_file() and os.access(path, os.X_OK) else None


def required() -> bool:
    """CI sets ``ACF_REQUIRE_E2E=1`` so that a missing host binary is a failure, not a quiet skip."""
    return os.environ.get(REQUIRE_ENV) == "1"


@dataclass(frozen=True)
class RunningHost:
    base: Path
    socket: Path
    log: Path
    tls_port: int | None

    @property
    def tls_dir(self) -> Path:
        return self.base / "tls"

    def unix(self) -> UnixEndpoint:
        return UnixEndpoint(self.socket)

    def tls(self, identity: str) -> TlsEndpoint:
        """The network endpoint, as the generated client identity ``identity``."""
        assert self.tls_port is not None, "this host was started without a network endpoint"
        return TlsEndpoint(
            host="127.0.0.1",
            port=self.tls_port,
            certificate=self.tls_dir / f"{identity}.crt",
            private_key=self.tls_dir / f"{identity}.key",
            trust_anchors=self.tls_dir / "ca.crt",
        )

    def unix_args(self) -> list[str]:
        """Global options that point ``acf-local`` at the local socket."""
        return ["--socket", str(self.socket)]

    def tls_args(self, identity: str) -> list[str]:
        """Global options that point ``acf-local`` at the network endpoint as ``identity``."""
        endpoint = self.tls(identity)
        return [
            "--tls",
            f"{endpoint.host}:{endpoint.port}",
            "--cert",
            str(endpoint.certificate),
            "--key",
            str(endpoint.private_key),
            "--ca",
            str(endpoint.trust_anchors),
        ]

    def log_text(self) -> str:
        return self.log.read_text(encoding="utf-8", errors="replace")


def _state_root() -> Path:
    root = Path(os.environ.get(STATE_ENV) or Path.home() / ".cache" / "acf-test")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    return root


def _free_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
        return port


def _accepting(family: socket.AddressFamily, address: str | tuple[str, int]) -> bool:
    with contextlib.closing(socket.socket(family, socket.SOCK_STREAM)) as probe:
        probe.settimeout(1.0)
        try:
            probe.connect(address)
        except OSError:
            return False
        return True


def _wait_until_serving(host: RunningHost, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + _START_TIMEOUT_S
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise HostUnavailable(f"acf-host-fake exited with status {process.returncode}:\n{host.log_text()}")
        local = _accepting(socket.AF_UNIX, str(host.socket))
        network = host.tls_port is None or _accepting(socket.AF_INET, ("127.0.0.1", host.tls_port))
        if local and network:
            return
        time.sleep(0.05)
    raise HostUnavailable(f"acf-host-fake did not start serving within {_START_TIMEOUT_S:.0f} s:\n{host.log_text()}")


@contextlib.contextmanager
def running_host(*, tls: bool = False) -> Iterator[RunningHost]:
    """A host of its own, in a private state directory, for the duration of the block."""
    binary = find_binary()
    if binary is None:
        raise HostUnavailable(
            f"${BINARY_ENV} does not name the test host binary; build it with "
            "`cargo build -p acf-host-agent --features testing --bin acf-host-fake`"
        )
    base = _state_root() / f"e2e-{uuid.uuid4().hex[:10]}"
    base.mkdir(mode=0o700)
    host = RunningHost(base=base, socket=base / "h.sock", log=base / "host.log", tls_port=_free_port() if tls else None)
    if len(os.fsencode(host.socket)) > SUN_PATH_MAX:
        shutil.rmtree(base, ignore_errors=True)
        raise HostUnavailable(f"{host.socket} is longer than {SUN_PATH_MAX} bytes; set ${STATE_ENV} to a shorter path")
    command = [str(binary), "--state", str(base / "state"), "--socket", str(host.socket)]
    if host.tls_port is not None:
        command += ["--tls-listen", f"127.0.0.1:{host.tls_port}", "--tls-dir", str(host.tls_dir)]
    with host.log.open("wb") as log:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            env={"PATH": os.environ.get("PATH", "")},
        )
    try:
        _wait_until_serving(host, process)
        yield host
    finally:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        shutil.rmtree(base, ignore_errors=True)
