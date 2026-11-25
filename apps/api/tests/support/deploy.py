"""Deployments on disk, for the tests that run the platform as its operator would: files, sockets, processes.

Three things here are shaped by rules of the code under test and of the host:

* a file the core depends on must be a *trusted input*: no ancestor directory may be writable by anyone
  else. ``/tmp`` is, so a deployment whose files are checked lives in a private directory (mode 0700)
  under ``$ACF_TEST_STATE_DIR`` or ``~/.cache/acf-test``. The test host has the same rule for its state;
* a Unix socket path is limited to 107 bytes, so directory names are kept short;
* every process a test starts is stopped by the block that started it, whatever the test did.

The certificates made here come from a throwaway authority that exists for one test. Nothing here is
imported from the host operator's client: the platform's tests bring their own launcher for the test
host, with the same approach.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import ipaddress
import json
import os
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tests.support.harness import config_dict

HOST_BINARY_ENV = "ACF_HOST_FAKE"
REQUIRE_HOST_ENV = "ACF_REQUIRE_HOST"
STATE_ENV = "ACF_TEST_STATE_DIR"
SUN_PATH_MAX = 107
#: The `host_id` of the test host's built-in configuration (`execution/host-agent/src/config.rs`, `test_support`).
TEST_HOST_ID = "test-host"
#: The peer id under which the test host enrols its generated `caller` identity.
TEST_HOST_CALLER_PEER = "tls-caller"
_START_TIMEOUT_S = 30.0
_HEADER = struct.Struct(">I")


# ------------------------------------------------------------------------------- directories
def state_root() -> Path:
    root = Path(os.environ.get(STATE_ENV) or Path.home() / ".cache" / "acf-test")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    return root


@contextlib.contextmanager
def private_dir(prefix: str = "d") -> Iterator[Path]:
    """A directory of this test alone, under no directory that anyone else can write. Removed afterwards."""
    base = state_root() / f"{prefix}-{uuid.uuid4().hex[:8]}"
    base.mkdir(mode=0o700)
    try:
        yield base
    finally:
        # A test may have taken permissions away to prove a refusal; give them back so the tree can go.
        for path in [base, *base.rglob("*")]:
            if path.is_dir() and not path.is_symlink():
                with contextlib.suppress(OSError):
                    path.chmod(0o700)
        shutil.rmtree(base, ignore_errors=True)


def free_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
        return port


# ------------------------------------------------------------------------------- certificates
class Authority:
    """A certificate authority that exists for one test."""

    def __init__(self, name: str = "acf test authority") -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())
        self._name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        now = dt.datetime.now(dt.UTC)
        self._certificate = (
            x509.CertificateBuilder()
            .subject_name(self._name)
            .issuer_name(self._name)
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .sign(self._key, hashes.SHA256())
        )

    def write_anchor(self, path: Path) -> Path:
        path.write_bytes(self._certificate.public_bytes(serialization.Encoding.PEM))
        path.chmod(0o644)
        return path

    def issue(
        self, directory: Path, name: str, *, names: tuple[str, ...] = (), server: bool = False
    ) -> tuple[Path, Path]:
        """Write ``<name>.crt`` and ``<name>.key`` (mode 0600) into ``directory`` and return both paths.

        ``names``: the DNS names and IP addresses a server certificate carries.
        """
        key = ec.generate_private_key(ec.SECP256R1())
        now = dt.datetime.now(dt.UTC)
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(self._name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
        )
        if names:
            alternative: list[x509.GeneralName] = []
            for value in names:
                try:
                    alternative.append(x509.IPAddress(ipaddress.ip_address(value)))
                except ValueError:
                    alternative.append(x509.DNSName(value))
            builder = builder.add_extension(x509.SubjectAlternativeName(alternative), critical=False)
        certificate = builder.sign(self._key, hashes.SHA256())
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        crt, pem = directory / f"{name}.crt", directory / f"{name}.key"
        crt.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        crt.chmod(0o644)
        pem.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )
        pem.chmod(0o600)
        return crt, pem


# ------------------------------------------------------------------------------- configuration files
def core_document(root: Path, **parameters: Any) -> dict[str, Any]:
    """The configuration of a core whose every file lives under ``root``, as the document an operator writes."""
    return config_dict(root, **parameters)


def write_platform_identity(root: Path, authority: Authority | None = None) -> Authority:
    """The three files of the host section that must be trusted inputs: anchors, certificate and private key."""
    authority = authority or Authority()
    secrets_dir = root / "secrets"
    secrets_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    authority.write_anchor(secrets_dir / "ca.crt")
    authority.issue(secrets_dir, "platform")
    return authority


def write_yaml(path: Path, document: dict[str, Any]) -> Path:
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    path.chmod(0o600)
    return path


def edge_document(command_socket: Path, port: int, **limits: Any) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "listen": {"host": "127.0.0.1", "port": port},
        "command_socket": str(command_socket),
        "limits": limits,
        "log_level": "WARNING",
    }


# ------------------------------------------------------------------------------- processes
@dataclass
class Process:
    """A process of the platform, started by a test. Its output goes to a file the test can read."""

    popen: subprocess.Popen[bytes]
    log: Path

    @property
    def pid(self) -> int:
        return self.popen.pid

    def output(self) -> str:
        return self.log.read_text(encoding="utf-8", errors="replace")

    def stop(self, sig: int = signal.SIGTERM, timeout_s: float = 20.0) -> int:
        """Send ``sig`` and wait for the exit status. A process that does not end in time fails the test."""
        if self.popen.poll() is None:
            self.popen.send_signal(sig)
        try:
            return self.popen.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            self.popen.kill()
            self.popen.wait()
            raise AssertionError(
                f"the process did not end within {timeout_s:.0f} s of signal {sig}:\n{self.output()}"
            ) from None

    def kill(self) -> None:
        if self.popen.poll() is None:
            self.popen.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            self.popen.wait(timeout=10)


def _clean_environment() -> dict[str, str]:
    """What a started process inherits: where programs are, and where the user's home is. No test settings."""
    return {name: os.environ[name] for name in ("PATH", "HOME", "LANG", "LC_ALL") if name in os.environ}


@contextlib.contextmanager
def started(command: list[str], log: Path) -> Iterator[Process]:
    """Run ``command`` for the duration of the block. It is killed at the end if the block left it running."""
    with log.open("wb") as sink:
        popen = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=sink, stderr=subprocess.STDOUT, env=_clean_environment()
        )
    process = Process(popen, log)
    try:
        yield process
    finally:
        process.kill()


def platform_command(role: str, config: Path) -> list[str]:
    """The command line of one role of the platform, run by the interpreter that runs the tests."""
    return [sys.executable, "-m", "acf_api.cli", role, "--config", str(config)]


def accepting_unix(path: Path) -> bool:
    with contextlib.closing(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)) as probe:
        probe.settimeout(1.0)
        try:
            probe.connect(str(path))
        except OSError:
            return False
        return True


def accepting_tcp(port: int) -> bool:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as probe:
        probe.settimeout(1.0)
        try:
            probe.connect(("127.0.0.1", port))
        except OSError:
            return False
        return True


def wait_until_serving(process: Process, *, sockets: tuple[Path, ...] = (), ports: tuple[int, ...] = ()) -> None:
    """Wait until the process accepts on every socket and port named, or fail with its output."""
    deadline = time.monotonic() + _START_TIMEOUT_S
    while time.monotonic() < deadline:
        if process.popen.poll() is not None:
            raise AssertionError(f"the process exited with status {process.popen.returncode}:\n{process.output()}")
        if all(accepting_unix(path) for path in sockets) and all(accepting_tcp(port) for port in ports):
            return
        time.sleep(0.02)
    raise AssertionError(f"the process did not start serving within {_START_TIMEOUT_S:.0f} s:\n{process.output()}")


# ------------------------------------------------------------------------------- the real test host
def host_binary() -> Path | None:
    """The test host binary that ``$ACF_HOST_FAKE`` names, if it names an executable file."""
    explicit = os.environ.get(HOST_BINARY_ENV)
    if not explicit:
        return None
    path = Path(explicit)
    return path if path.is_file() and os.access(path, os.X_OK) else None


def host_required() -> bool:
    """``ACF_REQUIRE_HOST=1``: a missing test host is a failure, never a quiet skip."""
    return os.environ.get(REQUIRE_HOST_ENV) == "1"


@dataclass(frozen=True)
class RealHost:
    """The running test host: the real edge, admission, coordinator and store over an in-memory backend."""

    base: Path
    port: int
    process: Process

    @property
    def address(self) -> str:
        return f"127.0.0.1:{self.port}"

    @property
    def tls_dir(self) -> Path:
        return self.base / "tls"

    @property
    def anchors(self) -> Path:
        return self.tls_dir / "ca.crt"

    def certificate(self, identity: str) -> Path:
        return self.tls_dir / f"{identity}.crt"

    def private_key(self, identity: str) -> Path:
        return self.tls_dir / f"{identity}.key"

    def context(self, identity: str) -> ssl.SSLContext:
        """Mutual TLS 1.3 as one of the identities the test host generated, trusting its authority only."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cafile=str(self.anchors))
        context.load_cert_chain(str(self.certificate(identity)), str(self.private_key(identity)))
        return context


@contextlib.contextmanager
def running_host() -> Iterator[RealHost]:
    """A test host of its own, with its network endpoint, in a private state directory."""
    binary = host_binary()
    assert binary is not None, f"${HOST_BINARY_ENV} names no executable test host"
    with private_dir("h") as base:
        port = free_port()
        local = base / "h.sock"
        assert len(os.fsencode(local)) <= SUN_PATH_MAX, (
            f"{local} is too long for a socket; set ${STATE_ENV} to a shorter path"
        )
        command = [
            str(binary),
            "--state",
            str(base / "state"),
            "--socket",
            str(local),
            "--tls-listen",
            f"127.0.0.1:{port}",
            "--tls-dir",
            str(base / "tls"),
        ]
        with started(command, base / "host.log") as process:
            wait_until_serving(process, sockets=(local,), ports=(port,))
            yield RealHost(base, port, process)


class RawHostClient:
    """One connection to the host that speaks its protocol directly, with the binding's framing and nothing else.

    It exists so that a test can act on the host beside the platform: as the ``operator`` identity, to
    change a state the platform must then report, or to look at what the platform left on the host.
    It blocks, so that a test without an event loop can use it; every call is one short local exchange.
    """

    def __init__(self, host: RealHost, identity: str) -> None:
        raw = socket.create_connection(("127.0.0.1", host.port), timeout=15.0)
        self._socket = host.context(identity).wrap_socket(raw, server_hostname=TEST_HOST_ID)

    def __enter__(self) -> RawHostClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self._socket.close()

    def _read(self, count: int) -> bytes:
        data = b""
        while len(data) < count:
            chunk = self._socket.recv(count - len(data))
            if not chunk:
                raise ConnectionError("the host closed the connection")
            data += chunk
        return data

    def call(
        self, method: str, owner_scope: str, params: dict[str, Any] | None = None, **envelope: Any
    ) -> dict[str, Any]:
        """One request envelope, one response envelope, decoded."""
        body: dict[str, Any] = {"protocol": "acf.host/2", "owner_scope": owner_scope, "method": method, **envelope}
        if params is not None:
            body["params"] = params
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        self._socket.sendall(_HEADER.pack(len(payload)) + payload)
        (length,) = _HEADER.unpack(self._read(_HEADER.size))
        answer = json.loads(self._read(length))
        assert isinstance(answer, dict)
        return answer

    def mutate(self, method: str, owner_scope: str, params: dict[str, Any], *, wait_ms: int = 5000) -> dict[str, Any]:
        """A mutation under an operation id of this client's own, issued now. Returns the host's operation view."""
        now = dt.datetime.now(dt.UTC)
        issued_at = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
        answer = self.call(
            method, owner_scope, params, operation_id="op-" + uuid.uuid4().hex, issued_at=issued_at, wait_ms=wait_ms
        )
        assert answer.get("answer") == "OPERATION", answer
        operation = answer["operation"]
        assert isinstance(operation, dict)
        return operation

    def read(self, method: str, owner_scope: str, params: dict[str, Any] | None = None) -> Any:
        """A read. Returns the data of the host's result."""
        answer = self.call(method, owner_scope, params)
        assert answer.get("answer") == "RESULT", answer
        return answer["result"]["data"]


# ------------------------------------------------------------------------------- between the platform and the host
Rewrite = Callable[[dict[str, Any], dict[str, Any]], dict[str, Any] | None]


class Interposer:
    """A relay between the platform and the real test host that a test can make drop, change or record.

    The platform is configured to trust this relay's authority and to reach the host at its port; the
    relay speaks to the real host as the enrolled ``caller``. Everything the platform sends to the host
    therefore passes through here, frame by frame, which gives a test two things the host binary does
    not offer by itself: the traffic as it was sent, and faults at a chosen point of a chosen exchange.

    ``rewrite`` is called with each request and the host's answer to it. It returns the answer to pass
    on, changed or not, or ``None`` to lose it: the host has acted, and the platform hears nothing.
    ``refuse`` is called with each request before it is forwarded; when it returns true the connection
    is closed and the host never sees the request.

    It runs on a thread with an event loop of its own, so that tests without one can use it.
    """

    def __init__(self, host: RealHost, directory: Path) -> None:
        self._host = host
        self._authority = Authority("acf test interposer")
        self.anchors = self._authority.write_anchor(directory / "interposer-ca.crt")
        certificate, key = self._authority.issue(
            directory, "interposer", names=(TEST_HOST_ID, "127.0.0.1", "localhost"), server=True
        )
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.minimum_version = ssl.TLSVersion.TLSv1_3
        self._context.load_cert_chain(str(certificate), str(key))
        self.port = 0
        #: Every request the platform sent, decoded, in the order it arrived.
        self.requests: list[dict[str, Any]] = []
        #: The same requests as the bytes that crossed, for searches that must not depend on decoding.
        self.frames: list[bytes] = []
        self.rewrite: Rewrite | None = None
        self.refuse: Callable[[dict[str, Any]], bool] | None = None
        #: How many connections the platform opened to the host, over the life of this relay.
        self.connections = 0
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, name="acf-interposer", daemon=True)
        self._server: asyncio.Server | None = None

    @property
    def address(self) -> str:
        return f"127.0.0.1:{self.port}"

    def start(self) -> None:
        self._thread.start()
        self._server = asyncio.run_coroutine_threadsafe(self._listen(), self._loop).result(timeout=10)
        self.port = self._server.sockets[0].getsockname()[1]

    async def _listen(self) -> asyncio.Server:
        return await asyncio.start_server(self._serve, "127.0.0.1", 0, ssl=self._context)

    def stop(self) -> None:
        async def close() -> None:
            if self._server is not None:
                self._server.close()
            for task in asyncio.all_tasks(self._loop):
                if task is not asyncio.current_task():
                    task.cancel()

        with contextlib.suppress(Exception):
            asyncio.run_coroutine_threadsafe(close(), self._loop).result(timeout=10)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=10)

    def methods(self) -> list[str]:
        return [str(request.get("method")) for request in self.requests]

    @staticmethod
    async def _frame(reader: asyncio.StreamReader) -> bytes:
        (length,) = _HEADER.unpack(await reader.readexactly(_HEADER.size))
        return await reader.readexactly(length)

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        upstream: asyncio.StreamWriter | None = None
        self.connections += 1
        try:
            from_host, upstream = await asyncio.open_connection(
                "127.0.0.1", self._host.port, ssl=self._host.context("caller"), server_hostname=TEST_HOST_ID
            )
            while True:
                payload = await self._frame(reader)
                request = json.loads(payload)
                self.frames.append(payload)
                self.requests.append(request)
                if self.refuse is not None and self.refuse(request):
                    return
                upstream.write(_HEADER.pack(len(payload)) + payload)
                await upstream.drain()
                answer = await self._frame(from_host)
                if self.rewrite is not None:
                    changed = self.rewrite(request, json.loads(answer))
                    if changed is None:
                        return
                    answer = json.dumps(changed, separators=(",", ":")).encode("utf-8")
                writer.write(_HEADER.pack(len(answer)) + answer)
                await writer.drain()
        except (asyncio.IncompleteReadError, OSError, asyncio.CancelledError):
            pass
        finally:
            for stream in (writer, upstream):
                if stream is not None:
                    with contextlib.suppress(Exception):
                        stream.close()


@contextlib.contextmanager
def interposed(host: RealHost, directory: Path) -> Iterator[Interposer]:
    relay = Interposer(host, directory)
    relay.start()
    try:
        yield relay
    finally:
        relay.stop()
