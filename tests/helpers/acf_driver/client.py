"""The reference client as a subprocess: how the suites run ``acf-local`` and read what it says.

The suites know nothing about the client's Python package. They run the command named by ``$ACF_LOCAL``, look at
its exit status, its two output streams and, with ``--json``, the one document it prints, and assert on the
contract: answers, states, classes, exit codes (``apps/cli/README.md``).

Two rules shape the API:

* :meth:`AcfLocal.call` never raises on a non-zero exit, because refusals, failed operations and usage errors are
  things the suites assert on;
* the helpers that name an effect (:meth:`AcfLocal.boot`, :meth:`AcfLocal.python` ...) REQUIRE it and raise
  :class:`~acf_driver.base.DriverError` with the client's own stderr otherwise, so a failure points at the cause.

Arrangement that is not the subject of a check goes through :attr:`AcfLocal.wire`, which talks to the same endpoint
as the same peer without starting a process for each step.
"""

from __future__ import annotations

import json
import os
import shlex
import signal
import subprocess
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Final

from acf_driver.base import EXIT_OK, EXIT_REFUSED, DriverError, tail
from acf_driver.hosts import TlsIdentity
from acf_driver.views import Answer, HostInfo, Operation, Refusal, Run, Sandbox
from acf_driver.wire import REPO, RawConnection, WireHost

CLIENT_ENV: Final = "ACF_LOCAL"
DEFAULT_SOCKET: Final = "/run/acf/host-agent.sock"
NAME_PREFIX: Final = "it-"
# Every variable acf-local itself reads (apps/cli/README.md, "Connecting"). The driver states the endpoint, the scope
# and the timeouts on the command line; what the machine running the suites happens to export must not reach the
# client, or a test would pass on one machine and fail on the next.
CLIENT_VARIABLES: Final = (
    "ACF_SOCKET",
    "ACF_TLS",
    "ACF_TLS_CERT",
    "ACF_TLS_KEY",
    "ACF_TLS_CA",
    "ACF_TLS_SERVER_NAME",
    "ACF_SCOPE",
    "ACF_ON_BEHALF_OF",
    "ACF_CONNECT_TIMEOUT",
    "ACF_TIMEOUT",
)


def client_command(environ: Mapping[str, str] | None = None) -> tuple[str, ...]:
    """``$ACF_LOCAL`` split the way a shell would split it (``acf-local`` when it is not set)."""
    source = os.environ if environ is None else environ
    command = tuple(shlex.split(source.get(CLIENT_ENV, "acf-local")))
    if not command:
        raise DriverError(f"${CLIENT_ENV} is empty: it must be the command line of the reference client")
    return command


@dataclass(frozen=True)
class Target:
    """Which endpoint a client talks to, as whom, and in which owner scope."""

    socket: Path | None = None
    tls: TlsIdentity | None = None
    scope: str | None = None
    on_behalf_of: str | None = None

    def __post_init__(self) -> None:
        if (self.socket is None) == (self.tls is None):
            raise DriverError("a target is either the local socket or one identity on the network endpoint")

    def options(self) -> list[str]:
        """The global options of ``acf-local`` for this target; they come before the command."""
        options = ["--socket", str(self.socket)] if self.tls is None else self.tls.options()
        if self.scope is not None:
            options += ["--scope", self.scope]
        if self.on_behalf_of is not None:
            options += ["--on-behalf-of", self.on_behalf_of]
        return options

    def connect(self) -> RawConnection:
        """A raw connection to the same endpoint, as the same peer."""
        if self.tls is not None:
            return self.tls.connect()
        if self.socket is None:  # pragma: no cover - excluded by __post_init__
            raise DriverError("a target without an endpoint")
        return RawConnection.unix(self.socket)


@dataclass(frozen=True)
class Completed:
    """One finished invocation of the client."""

    argv: tuple[str, ...]
    returncode: int
    stdout_bytes: bytes
    stderr_bytes: bytes

    @property
    def stdout(self) -> str:
        return self.stdout_bytes.decode("utf-8", errors="replace")

    @property
    def stderr(self) -> str:
        return self.stderr_bytes.decode("utf-8", errors="replace")

    def describe(self) -> str:
        return (
            f"{' '.join(shlex.quote(a) for a in self.argv)} -> exit {self.returncode}\n"
            f"stdout: {tail(self.stdout, 1500)}\nstderr: {tail(self.stderr, 1500)}"
        )

    def require_exit(self, *codes: int) -> Completed:
        wanted = codes or (EXIT_OK,)
        if self.returncode not in wanted:
            raise DriverError(f"expected exit {' or '.join(map(str, wanted))}: {self.describe()}")
        return self

    def document(self) -> Any:
        """The one JSON document on stdout (``--json`` promises exactly one, and nothing else)."""
        try:
            return json.loads(self.stdout_bytes)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise DriverError(f"stdout is not one JSON document ({e}): {self.describe()}") from e

    def answer(self) -> Answer:
        """The host's answer in wire form, as ``--json`` prints it for one command."""
        document = self.document()
        if not isinstance(document, Mapping) or "answer" not in document:
            raise DriverError(f"stdout is not a host answer: {self.describe()}")
        return Answer(document)

    def refusal(self) -> Refusal:
        """The refusal this invocation ended with: exit 3, and a ``REFUSED`` answer on stdout."""
        self.require_exit(EXIT_REFUSED)
        return self.answer().refused()

    def operation(self) -> Operation:
        """The operation as the client last saw it, whatever state it is in."""
        return self.answer().accepted()

    def client_error(self) -> Mapping[str, Any]:
        """The ``error`` object the client prints when there is no host answer to print."""
        document = self.document()
        if not isinstance(document, Mapping) or not isinstance(document.get("error"), Mapping):
            raise DriverError(f"stdout is not a client-side error document: {self.describe()}")
        error: Mapping[str, Any] = document["error"]
        return error


@dataclass
class Spawned:
    """An invocation of the client that is still running."""

    argv: tuple[str, ...]
    process: subprocess.Popen[bytes]
    _done: Completed | None = field(default=None, repr=False)

    def poll(self) -> int | None:
        return self.process.poll()

    def interrupt(self) -> None:
        """SIGINT to its whole process group, as Ctrl-C on a terminal does (the client may run under a wrapper)."""
        os.killpg(self.process.pid, signal.SIGINT)

    def wait(self, timeout: float) -> Completed:
        """The finished invocation (the same object on every call once it has finished)."""
        if self._done is None:
            try:
                out, err = self.process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired as e:
                self.kill()
                raise DriverError(f"still running after {timeout:.0f}s: {' '.join(self.argv)}") from e
            self._done = Completed(self.argv, self.process.returncode, out, err)
        return self._done

    def kill(self) -> None:
        """Stop it if it is still running; harmless when it has finished."""
        if self._done is None:
            if self.process.poll() is None:
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    self.process.kill()
            out, err = self.process.communicate()
            self._done = Completed(self.argv, self.process.returncode, out, err)


@dataclass(frozen=True)
class Execution:
    """What ``sandbox exec --json`` said about one command."""

    completed: Completed

    @property
    def returncode(self) -> int:
        return self.completed.returncode

    @property
    def operation(self) -> Operation:
        return self.completed.operation()

    @property
    def run(self) -> Run:
        """The execution's record. A command that was refused, or whose operation carries no result, has none."""
        return self.operation.run_result()


def with_json(args: Sequence[str]) -> list[str]:
    """``args`` with ``--json`` added where the client reads it: before a ``--`` that starts the guest's command."""
    argv = list(args)
    if "--json" in (argv[: argv.index("--")] if "--" in argv else argv):
        return argv
    if "--" in argv:
        argv.insert(argv.index("--"), "--json")
    else:
        argv.append("--json")
    return argv


@dataclass(frozen=True)
class AcfLocal:
    """Runs the reference client against one endpoint, as one peer. It remembers nothing about the host."""

    command: tuple[str, ...]
    target: Target
    image: str = "python"
    timeout: float = 900.0

    @classmethod
    def for_target(cls, target: Target, *, image: str = "python", environ: Mapping[str, str] | None = None) -> AcfLocal:
        return cls(command=client_command(environ), target=target, image=image)

    def as_peer(self, target: Target) -> AcfLocal:
        """The same client, talking as another peer or to another endpoint."""
        return replace(self, target=target)

    def in_scope(self, scope: str) -> AcfLocal:
        return replace(self, target=replace(self.target, scope=scope))

    @property
    def wire(self) -> WireHost:
        """The arranging hand: the same endpoint, the same peer and the same owner scope, without a process per step."""
        return WireHost(self.target.connect, scope=self.target.scope or "default", image=self.image)

    # ------------------------------------------------------------------------------------------ plumbing
    def argv(self, args: Sequence[str]) -> list[str]:
        return [*self.command, *self.target.options(), *args]

    @staticmethod
    def _environment(extra: Mapping[str, str] | None) -> dict[str, str]:
        environment = {key: value for key, value in os.environ.items() if key not in CLIENT_VARIABLES}
        environment.update(extra or {})
        return environment

    def call(
        self,
        *args: str,
        timeout: float | None = None,
        input_text: str | None = None,
        env: Mapping[str, str] | None = None,
    ) -> Completed:
        """Run ``acf-local <target options> ARGS`` and return what happened; a non-zero exit is NOT an error here."""
        argv = self.argv(args)
        try:
            done = subprocess.run(
                argv,
                capture_output=True,
                timeout=timeout or self.timeout,
                env=self._environment(env),
                input=None if input_text is None else input_text.encode(),
                stdin=subprocess.DEVNULL if input_text is None else None,
                cwd=REPO,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise DriverError(f"timed out after {e.timeout}s: {' '.join(argv)}") from e
        return Completed(tuple(argv), done.returncode, done.stdout, done.stderr)

    def spawn(self, *args: str, env: Mapping[str, str] | None = None) -> Spawned:
        """Start ``acf-local ARGS`` and return at once (a test then does something to the host underneath it)."""
        argv = self.argv(args)
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._environment(env),
            cwd=REPO,
            start_new_session=True,  # its own process group: `interrupt()` must not reach the test runner
        )
        return Spawned(tuple(argv), process)

    def json(self, *args: str, timeout: float | None = None) -> Completed:
        """:meth:`call` with ``--json``."""
        return self.call(*with_json(args), timeout=timeout)

    def ok(self, *args: str, timeout: float | None = None) -> Answer:
        """A command that must exit 0 with ``--json``; returns the answer it printed."""
        return self.json(*args, timeout=timeout).require_exit(EXIT_OK).answer()

    def refused(self, *args: str) -> Refusal:
        """A command the host must refuse: exit 3, a ``REFUSED`` answer on stdout."""
        return self.json(*args).refusal()

    @staticmethod
    def name(label: str) -> str:
        """A fresh, valid sandbox or snapshot name (1 to 63 characters of ``[A-Za-z0-9._-]``)."""
        return f"{NAME_PREFIX}{uuid.uuid4().hex[:8]}-{label}"[:63]

    # ------------------------------------------------------------------------------------------ reads
    def host_info(self) -> HostInfo:
        return self.ok("host", "info").host_info()

    def inspect(self, sandbox: str) -> Sandbox:
        return self.ok("sandbox", "inspect", sandbox).sandbox()

    def run_output(self, run_id: str, stream: str = "stdout") -> bytes:
        """The stored bytes of one stream of an execution (``run output`` writes them to stdout, and nothing else)."""
        return self.call("run", "output", run_id, "--stream", stream).require_exit(EXIT_OK).stdout_bytes

    # ------------------------------------------------------------------------------------------ sandboxes
    def boot(
        self,
        label: str,
        *,
        cpu: int = 1,
        memory: str = "256",
        disk: str = "1024",
        allow: Sequence[str] = (),
        lifetime: str | None = None,
    ) -> Sandbox:
        """A named, started sandbox (``READY``), created and started through the client.

        With ``allow`` entries its network mode is ``allowlist``; without, ``none``.
        """
        name = self.name(label)
        args = ["sandbox", "create", "--image", self.image, "--cpu", str(cpu), "--memory", memory, "--disk", disk]
        args += ["--name", name]
        if allow:
            args += ["--network", "allowlist"]
            for entry in allow:
                args += ["--allow", entry]
        if lifetime is not None:
            args += ["--lifetime", lifetime]
        self.ok(*args).succeeded()
        started = self.ok("sandbox", "start", name).succeeded().sandbox_result()
        if started.state != "READY":
            raise DriverError(f"sandbox {name} is {started.state} after start, expected READY: {started!r}")
        return started

    # ------------------------------------------------------------------------------------------ commands
    def execute(
        self,
        sandbox: str,
        command: Sequence[str],
        *,
        options: Sequence[str] = (),
        timeout: float | None = None,
    ) -> Execution:
        """``sandbox exec SANDBOX OPTIONS --json -- COMMAND``: one command in a started sandbox, as an argument vector."""
        return Execution(self.call("sandbox", "exec", sandbox, *options, "--json", "--", *command, timeout=timeout))

    def _run_of(self, execution: Execution) -> Run:
        operation = execution.operation
        if operation.state != "SUCCEEDED":
            raise DriverError(f"the command's operation is {operation.state}: {execution.completed.describe()}")
        return operation.run_result()

    def python(
        self, sandbox: str, script: str, *args: str, options: Sequence[str] = (), timeout: float | None = None
    ) -> Run:
        """Run a Python ``script`` in ``sandbox`` (``python -c SCRIPT ARGS``) and return its record.

        The guest-side probes are Python because the guest kernel's ``/proc`` and ``/sys`` are the ground truth, and
        reading them directly does not depend on which tools the image happens to ship. The operation must succeed;
        whether the *script* did is the caller's question (``Run.succeeded``, ``Run.stdout_json``).
        """
        return self._run_of(self.execute(sandbox, ["python", "-c", script, *args], options=options, timeout=timeout))

    def sh(self, sandbox: str, script: str, *, options: Sequence[str] = (), timeout: float | None = None) -> Run:
        """Run ``script`` under ``/bin/sh -c`` inside the guest (``--shell``) and return its record."""
        done = self.call(
            "sandbox", "exec", sandbox, "--command", script, "--shell", *options, "--json", timeout=timeout
        )
        return self._run_of(Execution(done))

    def workload_processes(self, sandbox: str, uid: int = 1000) -> list[str]:
        """``pid:name`` of every process in the guest running as ``uid`` (the workload user), except the probe itself.

        After a command has ended this must be empty: an execution owns its whole process tree, however it was
        started. The probe reads ``/proc`` because that is what the guest kernel says.
        """
        script = (
            "import os\n"
            f"want = {uid}\n"
            "found = []\n"
            "for pid in os.listdir('/proc'):\n"
            "    if not pid.isdigit() or int(pid) == os.getpid():\n"
            "        continue\n"
            "    try:\n"
            "        status = open(f'/proc/{pid}/status').read().splitlines()\n"
            "    except OSError:\n"
            "        continue\n"
            "    fields = dict(line.split(':', 1) for line in status if ':' in line)\n"
            "    if int(fields['Uid'].split()[0]) == want and not fields['State'].strip().startswith('Z'):\n"
            "        found.append(pid + ':' + fields['Name'].strip())\n"
            "print('\\n'.join(found))\n"
        )
        run = self.python(sandbox, script)
        if not run.succeeded():
            raise DriverError(f"could not list the workload's processes in {sandbox}: {run!r}")
        return run.stdout_text.split()

    # ------------------------------------------------------------------------------------------ housekeeping
    def purge(self) -> list[str]:
        """Remove everything this peer can see on the host; returns what could not be removed (see ``WireHost.purge``)."""
        return self.wire.purge()
