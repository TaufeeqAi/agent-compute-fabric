"""A black-box driver for ``acf-local --json``: how the integration and isolation tests talk to the system.

The tests know nothing about the Rust types or the CLI's Python package. They run the installed command, parse
its JSON and assert on the *contract* (spec §8, §11, §18, §20, §22): states, outcomes, exit codes, evidence.
That is deliberate: a test that imported the CLI's models would pass whenever the CLI and its own models agree,
which is exactly the failure a black-box test exists to catch.

Two rules shape the API:

* the methods that return a view (``sandbox_create``, ``snapshot_create`` ...) REQUIRE success and raise
  :class:`DriverError` with the CLI's own stderr otherwise, so a failure points at the cause;
* ``call`` never raises on a non-zero exit, because the failure paths (refusals, unknown outcomes) are things the
  tests assert on.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

# Exit codes of acf-local (apps/cli/README.md). Named so a test reads as a sentence.
EXIT_OK: Final = 0
EXIT_WORKLOAD_FAILED: Final = 1
EXIT_USAGE: Final = 2
EXIT_REFUSED: Final = 3  # the host refused: nothing changed
EXIT_FAILED: Final = 4  # accepted, then definitively failed
EXIT_UNKNOWN: Final = 5  # outcome unknown: observe, never re-run
EXIT_UNREACHABLE: Final = 6  # host agent not reachable
EXIT_PROTOCOL: Final = 7
EXIT_INTERRUPTED: Final = 130  # Ctrl-C (SIGINT), the shell's convention

DEFAULT_SOCKET: Final = "/run/acf/host-agent.sock"
NAME_PREFIX: Final = "it-"
OPERATION_ID: Final = re.compile(r"op-[0-9a-f]{32}")


class DriverError(AssertionError):
    """The command did not do what the test needed (the message carries the command and its stderr)."""


def _tail(text: str, limit: int = 2000) -> str:
    return text if len(text) <= limit else "..." + text[-limit:]


def wait_for[T](what: str, probe: Callable[[], T | None], *, timeout: float, interval: float = 0.5) -> T:
    """Poll ``probe`` until it returns something other than ``None``; fail with ``what`` after ``timeout`` seconds.

    The tests use this for the one thing a black-box test cannot know in advance: how long the host takes to
    notice a crash and settle. The bound is the assertion ("recovery finishes within a minute"), not a sleep.
    """
    deadline = time.monotonic() + timeout
    while True:
        found = probe()
        if found is not None:
            return found
        if time.monotonic() >= deadline:
            raise DriverError(f"timed out after {timeout:.0f}s waiting for: {what}")
        time.sleep(interval)


def process_alive(pid: int, start_time_ticks: int) -> bool:
    """Is the process with exactly this identity still running on THIS machine?

    The host identifies a process by ``(pid, start_time_ticks)`` because a pid alone can be recycled: a different
    process that reuses the number is not the one we asked about. A zombie has exited and counts as gone.
    """
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return False
    # The command name (field 2) may contain spaces and parentheses; the rest starts after the LAST ')'.
    fields = stat.rpartition(")")[2].split()
    if len(fields) < 20 or fields[0] in {"Z", "X"}:
        return False
    return int(fields[19]) == start_time_ticks


def operation_ids(text: str) -> list[str]:
    """Every operation id (``op-`` + 32 hex) the CLI printed in ``text``, in order, without duplicates."""
    seen: list[str] = []
    for found in OPERATION_ID.findall(text):
        if found not in seen:
            seen.append(found)
    return seen


# ---------------------------------------------------------------------------------------------- the raw protocol
# A client that speaks the host's wire protocol WITHOUT the CLI: u32 big-endian length + one JSON envelope.
# It exists because some claims are about the host, not about the CLI ("a client that bypasses the CLI still cannot
# ...", "a process that is not authorised is refused"), and the CLI would be the wrong thing to test them through.
# The script is a string so it can run as ANOTHER user (`python3 -I -c`): it needs nothing from this repository.
RAW_CLIENT: Final = r"""
import json, os, socket, struct, sys
path, request, patience = sys.argv[1], json.loads(sys.argv[2]), float(sys.argv[3])
out = {"uid": os.getuid(), "connect": "ok", "send": None, "recv": None, "frames": []}
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(patience)
try:
    sock.connect(path)
except OSError as e:
    out["connect"] = f"{type(e).__name__}:{e.errno}"
    print(json.dumps(out))
    sys.exit(0)
raw = json.dumps(request, separators=(",", ":")).encode()
try:
    sock.sendall(struct.pack(">I", len(raw)) + raw)
    sock.shutdown(socket.SHUT_WR)  # one request: the host answers it and then sees the end of the stream
except OSError as e:
    out["send"] = f"{type(e).__name__}:{e.errno}"  # a host that has already refused us may have closed on us
buf = b""
try:
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf += chunk
except OSError as e:
    out["recv"] = f"{type(e).__name__}:{e.errno}"
while len(buf) >= 4:
    (size,) = struct.unpack(">I", buf[:4])
    if len(buf) < 4 + size:
        break
    out["frames"].append(json.loads(buf[4 : 4 + size]))
    buf = buf[4 + size :]
print(json.dumps(out))
"""

PROTOCOL: Final = "acf.host/1"


@dataclass(frozen=True)
class RawAnswer:
    """What the host said to one raw request (or why we never got that far)."""

    uid: int
    connect: str  # "ok", or "PermissionError:13" / "FileNotFoundError:2" ...
    frames: list[dict[str, Any]]
    send: str | None = None
    recv: str | None = None

    @property
    def connected(self) -> bool:
        return self.connect == "ok"

    @property
    def reply(self) -> dict[str, Any]:
        """The one response envelope; fails the test with what happened instead when there is none."""
        if len(self.frames) != 1:
            raise DriverError(f"expected exactly one response frame, got {len(self.frames)}: {self}")
        return self.frames[0]

    @property
    def error(self) -> dict[str, Any] | None:
        found = self.reply.get("error")
        return found if isinstance(found, dict) else None

    @property
    def status(self) -> str:
        return str(self.reply["status"])


def system_python() -> str:
    """A Python any user can run: ``-I`` ignores site and environment, but the executable must be reachable."""
    for candidate in ("/usr/bin/python3", "/usr/local/bin/python3"):
        if os.access(candidate, os.X_OK):
            return candidate
    return shutil.which("python3") or sys.executable


def raw_call(
    socket_path: str,
    method: str,
    params: Mapping[str, Any] | None = None,
    *,
    operation_id: str | None = None,
    protocol: str = PROTOCOL,
    user: int | None = None,
    patience: float = 10.0,
) -> RawAnswer:
    """Send ONE request straight to the host agent's socket and return its answer.

    ``user`` runs the client as that numeric uid/gid with no supplementary groups (needs root); that is how the
    tests become "a local process that is not authorised". The kernel reports the uid to the host (SO_PEERCRED),
    so the client cannot claim a different one.
    """
    body: dict[str, Any] = {"method": method}
    if params is not None:
        body["params"] = dict(params)
    envelope: dict[str, Any] = {"protocol": protocol, "request_id": "req-" + uuid.uuid4().hex[:16], "body": body}
    if operation_id is not None:
        envelope["operation_id"] = operation_id
    identity: dict[str, Any] = {} if user is None else {"user": user, "group": user, "extra_groups": []}
    done = subprocess.run(  # noqa: PLW1510 - a client that failed to run is reported below with its stderr
        [system_python(), "-I", "-c", RAW_CLIENT, socket_path, json.dumps(envelope), str(patience)],
        capture_output=True,
        text=True,
        timeout=patience + 30,
        cwd="/",
        **identity,
    )
    if done.returncode != 0:
        raise DriverError(f"the raw client failed (exit {done.returncode}): {_tail(done.stderr)}")
    doc = json.loads(done.stdout)
    return RawAnswer(uid=doc["uid"], connect=doc["connect"], frames=doc["frames"], send=doc["send"], recv=doc["recv"])


def new_operation_id() -> str:
    """A fresh, valid operation id: ``op-`` + 32 hex digits."""
    return "op-" + uuid.uuid4().hex


@dataclass(frozen=True)
class Completed:
    """One finished ``acf-local`` invocation."""

    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    def describe(self) -> str:
        return f"{' '.join(shlex.quote(a) for a in self.args)} -> exit {self.returncode}\n{_tail(self.stderr)}"

    def json(self) -> Any:
        try:
            return json.loads(self.stdout)
        except json.JSONDecodeError as e:
            raise DriverError(f"stdout is not JSON ({e}): {self.describe()}") from e

    def require_exit(self, *codes: int) -> Completed:
        wanted = codes or (EXIT_OK,)
        if self.returncode not in wanted:
            raise DriverError(f"expected exit {' or '.join(map(str, wanted))}: {self.describe()}")
        return self


class View(Mapping[str, Any]):
    """A read-only wrapper over one JSON object, with the few fields every test needs as attributes."""

    def __init__(self, raw: Mapping[str, Any]) -> None:
        self.raw: Mapping[str, Any] = raw

    def __getitem__(self, key: str) -> Any:
        return self.raw[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.raw)

    def __len__(self) -> int:
        return len(self.raw)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({json.dumps(self.raw, sort_keys=True)[:600]})"


class Sandbox(View):
    @property
    def sandbox_id(self) -> str:
        return str(self.raw["sandbox_id"])

    @property
    def generation(self) -> int:
        return int(self.raw["generation"])

    @property
    def state(self) -> str:
        return str(self.raw["state"])

    @property
    def name(self) -> str | None:
        name = self.raw.get("name")
        return None if name is None else str(name)

    @property
    def vmm_pid(self) -> int | None:
        process = self.raw.get("process")
        return None if not process else int(process["pid"])

    @property
    def vmm_identity(self) -> tuple[int, int] | None:
        """``(pid, start_time_ticks)`` of the VMM process the host recorded, or ``None`` when it records none."""
        process = self.raw.get("process")
        return None if not process else (int(process["pid"]), int(process["start_time_ticks"]))

    @property
    def notes(self) -> list[str]:
        return [str(n) for n in self.raw.get("notes", [])]


class Snapshot(View):
    @property
    def snapshot_id(self) -> str:
        return str(self.raw["snapshot"]["snapshot_id"])

    @property
    def snapshot_generation(self) -> int:
        return int(self.raw["snapshot"]["snapshot_generation"])

    @property
    def state(self) -> str:
        return str(self.raw["state"])

    @property
    def restore_count(self) -> int:
        return int(self.raw["restore_count"])

    @property
    def size_bytes(self) -> int:
        return int(self.raw["size_bytes"])


class Run(View):
    """The evidence record of one command (``RunResult``)."""

    @property
    def run_id(self) -> str:
        return str(self.raw["run_id"])

    @property
    def sandbox_id(self) -> str:
        return str(self.raw["sandbox_id"])

    @property
    def outcome(self) -> str:
        """RUNNING | SUCCEEDED | FAILED | CANCELLED | TIMED_OUT | UNKNOWN."""
        return str(self.raw["outcome"])

    @property
    def exit_code(self) -> int | None:
        value = self.raw.get("exit_code")
        return None if value is None else int(value)

    @property
    def signal(self) -> int | None:
        value = self.raw.get("signal")
        return None if value is None else int(value)

    @property
    def evidence_status(self) -> str:
        """COMPLETE | INCOMPLETE | TRUNCATED | UNKNOWN."""
        return str(self.raw["evidence_status"])

    @property
    def wall_ms(self) -> int:
        return int(self.raw["metrics"]["wall_ms"])

    def stream(self, name: str) -> Mapping[str, Any]:
        return self.raw[name]  # type: ignore[no-any-return]

    def stdout_bytes(self) -> bytes:
        return base64.b64decode(self.raw["stdout"]["data_b64"])

    def stderr_bytes(self) -> bytes:
        return base64.b64decode(self.raw["stderr"]["data_b64"])

    @property
    def stdout(self) -> str:
        return self.stdout_bytes().decode("utf-8", errors="replace")

    @property
    def stderr(self) -> str:
        return self.stderr_bytes().decode("utf-8", errors="replace")

    def stdout_json(self) -> Any:
        """The captured stdout parsed as JSON (for guest-side probes that print one document)."""
        try:
            return json.loads(self.stdout)
        except json.JSONDecodeError as e:
            raise DriverError(
                f"run {self.run_id}: stdout is not JSON ({e}); outcome {self.outcome}, "
                f"stdout={self.stdout[:300]!r}, stderr={self.stderr[:300]!r}"
            ) from e

    def evidence(self, resource: str) -> Mapping[str, Any]:
        """The resource-evidence entry for ``resource`` (``guest_pids``, ``runtime_ms``, ``stdout_bytes`` ...)."""
        for entry in self.raw.get("resource_evidence", []):
            if entry["resource"] == resource:
                return entry  # type: ignore[no-any-return]
        names = [e["resource"] for e in self.raw.get("resource_evidence", [])]
        raise DriverError(f"run {self.run_id} has no resource evidence for {resource!r} (it has: {names})")

    def succeeded(self) -> bool:
        return self.outcome == "SUCCEEDED" and self.exit_code == 0


@dataclass(frozen=True)
class RunReport:
    """What ``acf-local run --json`` printed."""

    completed: Completed
    doc: Mapping[str, Any]

    @property
    def run(self) -> Run:
        raw = self.doc.get("run")
        if raw is None:
            raise DriverError(f"the command produced no run result: {self.completed.describe()}\n{self.doc}")
        return Run(raw)

    @property
    def has_run(self) -> bool:
        return self.doc.get("run") is not None

    @property
    def returncode(self) -> int:
        return self.completed.returncode


@dataclass
class Spawned:
    """An ``acf-local`` invocation running in the background."""

    args: tuple[str, ...]
    proc: subprocess.Popen[str]
    _done: Completed | None = field(default=None, repr=False)

    def poll(self) -> int | None:
        return self.proc.poll()

    def interrupt(self) -> None:
        """Send SIGINT to its whole process group, as a terminal's Ctrl-C does (the CLI may be a ``uv run`` wrapper)."""
        os.killpg(self.proc.pid, signal.SIGINT)

    def wait(self, timeout: float) -> Completed:
        """The finished invocation (the same object on every call once it has finished)."""
        if self._done is None:
            try:
                out, err = self.proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired as e:
                self.kill()
                raise DriverError(f"still running after {timeout:.0f}s: {' '.join(self.args)}") from e
            self._done = Completed(self.args, self.proc.returncode, out, err)
        return self._done

    def kill(self) -> None:
        """Stop it if it is still running; harmless when it has finished."""
        if self._done is None:
            if self.proc.poll() is None:
                self.proc.kill()
            out, err = self.proc.communicate()
            self._done = Completed(self.args, self.proc.returncode, out, err)


@dataclass
class AcfLocal:
    """Runs ``acf-local`` against one host agent and remembers nothing about the host's state."""

    command: Sequence[str] = ("acf-local",)
    socket: str | None = None
    image: str = "python"
    timeout: float = 900.0
    env: Mapping[str, str] = field(default_factory=dict)
    _names: list[str] = field(default_factory=list, repr=False)

    @classmethod
    def from_environment(cls, environ: Mapping[str, str] | None = None) -> AcfLocal:
        """``ACF_LOCAL`` (a command line, split like a shell would), ``ACF_SOCKET``, ``ACF_TEST_IMAGE``."""
        source = os.environ if environ is None else environ
        return cls(
            command=tuple(shlex.split(source.get("ACF_LOCAL", "acf-local"))),
            socket=source.get("ACF_SOCKET", DEFAULT_SOCKET),
            image=source.get("ACF_TEST_IMAGE", "python"),
        )

    # ------------------------------------------------------------------------------------------ plumbing
    def call(self, *args: str, timeout: float | None = None, input_text: str | None = None) -> Completed:
        """Run ``acf-local [--socket S] ARGS`` and return what happened; a non-zero exit is NOT an error here."""
        argv = self._argv(args)
        try:
            proc = subprocess.run(  # noqa: PLW1510 - the exit status is what the tests assert on
                argv,
                capture_output=True,
                text=True,
                timeout=timeout or self.timeout,
                env={**os.environ, **self.env},
                input=input_text,
            )
        except subprocess.TimeoutExpired as e:
            raise DriverError(f"timed out after {e.timeout}s: {' '.join(argv)}") from e
        return Completed(tuple(argv), proc.returncode, proc.stdout, proc.stderr)

    def _argv(self, args: Sequence[str]) -> list[str]:
        return [*self.command, *(["--socket", self.socket] if self.socket else []), *args]

    def spawn(self, *args: str) -> Spawned:
        """Start ``acf-local ARGS`` in the background (the recovery tests crash the host underneath a running command)."""
        argv = self._argv(args)
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, **self.env},
            start_new_session=True,  # its own process group: `interrupt()` must not reach the test runner
        )
        return Spawned(tuple(argv), proc)

    def _doc(self, *args: str, timeout: float | None = None) -> Any:
        return self.call(*args, "--json", timeout=timeout).require_exit(EXIT_OK).json()

    def name(self, label: str) -> str:
        """A fresh, valid sandbox/snapshot name (1..63 chars of [A-Za-z0-9._-]); the cleanup fixture finds it again."""
        name = f"{NAME_PREFIX}{uuid.uuid4().hex[:8]}-{label}"[:63]
        self._names.append(name)
        return name

    # ------------------------------------------------------------------------------------------ host
    def host_info(self) -> View:
        return View(self._doc("host", "info"))

    def metrics(self) -> Mapping[str, Any]:
        doc: Mapping[str, Any] = self._doc("host", "metrics")
        return doc

    # ------------------------------------------------------------------------------------------ sandboxes
    def sandbox_list(self) -> list[Sandbox]:
        return [Sandbox(item) for item in self._doc("sandbox", "list") if item["state"] != "DESTROYED"]

    def sandbox_inspect(self, sandbox: str) -> Sandbox:
        return Sandbox(self._doc("sandbox", "inspect", sandbox))

    def sandbox_create(
        self, name: str | None = None, *, cpu: int = 1, memory: str = "256", disk: str = "1024", start: bool = False
    ) -> Sandbox:
        args = ["sandbox", "create", "--image", self.image, "--cpu", str(cpu), "--memory", memory, "--disk", disk]
        if name:
            args += ["--name", name]
        if start:
            args.append("--start")
        return Sandbox(self._doc(*args))

    def sandbox_start(self, sandbox: str) -> Sandbox:
        return Sandbox(self._doc("sandbox", "start", sandbox))

    def sandbox_stop(self, sandbox: str) -> Sandbox:
        return Sandbox(self._doc("sandbox", "stop", sandbox))

    def sandbox_destroy(self, sandbox: str) -> Sandbox:
        return Sandbox(self._doc("sandbox", "destroy", sandbox, "--yes"))

    def boot(self, label: str, *, cpu: int = 1, memory: str = "256", disk: str = "1024") -> Sandbox:
        """A named, started sandbox (READY): the starting point of most tests."""
        sandbox = self.sandbox_create(self.name(label), cpu=cpu, memory=memory, disk=disk, start=True)
        if sandbox.state != "READY":
            raise DriverError(f"sandbox {sandbox.name} is {sandbox.state} after start, expected READY: {sandbox}")
        return sandbox

    # ------------------------------------------------------------------------------------------ commands
    @staticmethod
    def _command_args(
        command: str | Sequence[str],
        *,
        shell: bool,
        timeout: str | None,
        max_pids: int | None,
        max_stdout: str | None,
        max_stderr: str | None,
        env: Mapping[str, str] | None,
        cwd: str | None,
    ) -> tuple[list[str], list[str]]:
        """(options, trailing argv): the trailing part goes after ``--json --``."""
        options: list[str] = []
        trailing: list[str] = []
        if isinstance(command, str):
            options += ["--command", command]
            if shell:
                options.append("--shell")
        else:
            if shell:
                raise ValueError("shell=True applies to a command string, not to an argv")
            trailing = list(command)
        if timeout:
            options += ["--timeout", timeout]
        if max_pids is not None:
            options += ["--max-pids", str(max_pids)]
        if max_stdout:
            options += ["--max-stdout", max_stdout]
        if max_stderr:
            options += ["--max-stderr", max_stderr]
        for key, value in (env or {}).items():
            options += ["--env", f"{key}={value}"]
        if cwd:
            options += ["--cwd", cwd]
        return options, trailing

    def run(
        self,
        command: str | Sequence[str],
        *,
        cpu: int = 1,
        memory: str = "256",
        disk: str = "1024",
        shell: bool = False,
        timeout: str | None = None,
        max_pids: int | None = None,
        max_stdout: str | None = None,
        max_stderr: str | None = None,
        env: Mapping[str, str] | None = None,
        cwd: str | None = None,
        name: str | None = None,
        keep: bool = False,
        wait: float | None = None,
    ) -> RunReport:
        """``acf-local run``: a fresh sandbox, one command, then (unless ``keep``) destruction."""
        options, trailing = self._command_args(
            command, shell=shell, timeout=timeout, max_pids=max_pids, max_stdout=max_stdout,
            max_stderr=max_stderr, env=env, cwd=cwd,
        )  # fmt: skip
        args = [
            "run",
            "--image",
            self.image,
            "--cpu",
            str(cpu),
            "--memory",
            memory,
            "--disk",
            disk,
            "--network",
            "none",
        ]
        if name:
            args += ["--name", name]
        if keep:
            args.append("--keep")
        completed = self.call(*args, *options, "--json", *(["--", *trailing] if trailing else []), timeout=wait)
        return RunReport(completed, self._parse_report(completed))

    def exec(
        self,
        sandbox: str,
        command: str | Sequence[str],
        *,
        shell: bool = False,
        timeout: str | None = None,
        max_pids: int | None = None,
        max_stdout: str | None = None,
        max_stderr: str | None = None,
        env: Mapping[str, str] | None = None,
        cwd: str | None = None,
        wait: float | None = None,
    ) -> RunReport:
        """``acf-local exec SANDBOX``: one more command in a sandbox that is already running."""
        options, trailing = self._command_args(
            command, shell=shell, timeout=timeout, max_pids=max_pids, max_stdout=max_stdout,
            max_stderr=max_stderr, env=env, cwd=cwd,
        )  # fmt: skip
        completed = self.call(
            "exec", sandbox, *options, "--json", *(["--", *trailing] if trailing else []), timeout=wait
        )
        return RunReport(completed, self._parse_report(completed))

    def sh(self, sandbox: str, script: str, **kwargs: Any) -> Run:
        """Run ``script`` under ``/bin/sh -c`` in ``sandbox`` and return its evidence record (never raises on exit != 0)."""
        return self.exec(sandbox, script, shell=True, **kwargs).run

    def python(self, sandbox: str, script: str, *args: str, **kwargs: Any) -> Run:
        """Run a Python ``script`` in ``sandbox`` (``python -c SCRIPT ARGS``); ``args`` arrive as ``sys.argv[1:]``.

        Guest-side probes are Python because the guest kernel's ``/proc`` and ``/sys`` are the ground truth, and
        reading them directly does not depend on which tools the image happens to ship.
        """
        return self.exec(sandbox, ["python", "-c", script, *args], **kwargs).run

    def workload_processes(self, sandbox: str, uid: int = 1000) -> list[str]:
        """``pid:name`` of every process in the guest running as ``uid`` (the workload user), except the probe itself.

        After a command has ended this must be empty: a run owns its whole process tree, however it was started.
        The probe reads ``/proc`` because that is what the guest kernel says; it does not trust any tool's view.
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
            raise DriverError(f"could not list the workload's processes in {sandbox}: {run}")
        return run.stdout.split()

    def spawn_exec(
        self, sandbox: str, command: str | Sequence[str], *, shell: bool = False, timeout: str | None = None
    ) -> Spawned:
        """``exec`` in the background: returns at once; ``.wait()`` gives the finished invocation."""
        options, trailing = self._command_args(
            command, shell=shell, timeout=timeout, max_pids=None, max_stdout=None, max_stderr=None, env=None, cwd=None
        )
        return self.spawn("exec", sandbox, *options, "--json", *(["--", *trailing] if trailing else []))

    @staticmethod
    def _parse_report(completed: Completed) -> Mapping[str, Any]:
        if not completed.stdout.strip():
            return {}
        doc = completed.json()
        if not isinstance(doc, dict):
            raise DriverError(f"expected one JSON object: {completed.describe()}")
        return doc

    # ------------------------------------------------------------------------------------------ snapshots
    def snapshot_list(self) -> list[Snapshot]:
        return [Snapshot(item) for item in self._doc("snapshot", "list") if item["state"] != "DELETED"]

    def snapshot_inspect(self, snapshot: str) -> Snapshot:
        return Snapshot(self._doc("snapshot", "inspect", snapshot))

    def snapshot_create(self, name: str, sandbox: str) -> Snapshot:
        return Snapshot(self._doc("snapshot", "create", name, "--sandbox", sandbox))

    def snapshot_restore(self, snapshot: str, *, sandbox: str | None = None) -> Sandbox:
        args = ["snapshot", "restore", snapshot]
        if sandbox:
            args += ["--sandbox", sandbox]
        return Sandbox(self._doc(*args))

    def snapshot_restore_new(self, snapshot: str, name: str) -> Sandbox:
        return Sandbox(self._doc("snapshot", "restore", snapshot, "--new", "--name", name))

    def snapshot_delete(self, snapshot: str) -> Snapshot:
        return Snapshot(self._doc("snapshot", "delete", snapshot, "--yes"))

    # ------------------------------------------------------------------------------------------ evidence
    def evidence_get(self, run_id: str) -> Run:
        doc = self._doc("evidence", "get", run_id)
        if not doc.get("finished"):
            raise DriverError(f"run {run_id} is not finished: {doc}")
        return Run(doc["run"])

    def operation_get(self, operation_id: str) -> Completed:
        """The raw answer: its exit code mirrors the operation's status (0 succeeded, 4 failed, 5 unknown ...)."""
        return self.call("operation", "get", operation_id, "--json")

    # ------------------------------------------------------------------------------------------ housekeeping
    def purge(self) -> list[str]:
        """Best-effort removal of everything this test could have left on the host; returns what could not be removed.

        The suite assumes it owns the host (it asserts the host is idle before it starts), so "everything that
        is live now" is "everything a test created".
        """
        leftovers: list[str] = []
        for sandbox in self.sandbox_list():
            done = self.call("sandbox", "destroy", sandbox.sandbox_id, "--yes", "--json")
            if done.returncode != EXIT_OK:
                leftovers.append(f"sandbox {sandbox.sandbox_id} ({sandbox.state}): {_tail(done.stderr, 300)}")
        for snapshot in self.snapshot_list():
            done = self.call("snapshot", "delete", snapshot.snapshot_id, "--yes", "--json")
            if done.returncode != EXIT_OK:
                leftovers.append(f"snapshot {snapshot.snapshot_id}: {_tail(done.stderr, 300)}")
        self._names.clear()
        return leftovers
