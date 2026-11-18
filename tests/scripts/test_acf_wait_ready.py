"""scripts/acf-wait-ready — the readiness check of deploy/systemd/acf-host.service.

"Ready" means that a process is LISTENING on the core's local socket: the core binds it only after startup
recovery. The tests use real Unix sockets, because the difference that matters (a listener, a socket that is only
bound, a socket file whose owner died) exists only in the kernel's socket table. Nothing here needs root.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/acf-wait-ready"

Runner = Callable[..., "subprocess.CompletedProcess[str]"]

LISTENING = "0000000000000000: 00000002 00000000 00010000 0001 01 4242 {path}\n"
HEADER = "Num       RefCount Protocol Flags    Type St Inode Path\n"


@pytest.fixture
def short_dir() -> Iterator[Path]:
    """A Unix socket path holds at most 107 bytes; pytest's own temporary directories can be longer than that."""
    path = Path(tempfile.mkdtemp(prefix="acf-", dir="/tmp"))
    yield path
    shutil.rmtree(path, ignore_errors=True)


def listener(path: Path, *, listen: bool = True) -> socket.socket:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(str(path))
    if listen:
        sock.listen(8)
    return sock


def wait_ready(run: Runner, *args: str | Path, **env: str) -> subprocess.CompletedProcess[str]:
    return run(["sh", SCRIPT, *args], env=env)


def test_a_listening_socket_is_ready_at_once(run: Runner, short_dir: Path) -> None:
    path = short_dir / "host-agent.sock"
    with listener(path):
        started = time.monotonic()
        result = wait_ready(run, path, "30")
        assert result.returncode == 0, result.stderr
        assert time.monotonic() - started < 5
        assert result.stdout == ""
        assert result.stderr == ""


def test_it_waits_for_the_listener_to_appear(short_dir: Path, clean_env: dict[str, str]) -> None:
    path = short_dir / "host-agent.sock"
    waiting = subprocess.Popen(["sh", str(SCRIPT), str(path), "30"], env=clean_env, stderr=subprocess.PIPE, text=True)
    try:
        time.sleep(0.7)
        assert waiting.poll() is None, "nothing listens yet, so it must still be waiting"
        with listener(path):
            assert waiting.wait(timeout=10) == 0
    finally:
        waiting.kill()
        waiting.communicate()


def test_a_socket_that_is_bound_but_not_yet_listening_is_not_ready(run: Runner, short_dir: Path) -> None:
    """The core binds, sets the socket's owner and mode, and only then listens."""
    path = short_dir / "host-agent.sock"
    with listener(path, listen=False):
        result = wait_ready(run, path, "1")
    assert result.returncode == 1
    assert f"nothing listens on {path} after 1s" in result.stderr


def test_a_socket_file_left_behind_by_a_dead_core_is_not_ready(run: Runner, short_dir: Path) -> None:
    path = short_dir / "host-agent.sock"
    listener(path).close()
    assert path.is_socket(), "the premise: closing a listener leaves its file behind"
    result = wait_ready(run, path, "1")
    assert result.returncode == 1
    assert "nothing listens" in result.stderr
    assert "left by an earlier core" in result.stderr
    assert path.is_socket(), "the helper reads; it never removes"


def test_a_socket_that_never_appears_times_out_and_names_the_bound(run: Runner, short_dir: Path) -> None:
    path = short_dir / "host-agent.sock"
    started = time.monotonic()
    result = wait_ready(run, path, "1")
    assert result.returncode == 1
    assert 0.9 < time.monotonic() - started < 10
    assert f"{path} did not appear within 1s" in result.stderr
    assert "recovery.startup_deadline_ms" in result.stderr


def test_zero_seconds_means_look_once(run: Runner, short_dir: Path) -> None:
    path = short_dir / "host-agent.sock"
    assert wait_ready(run, path, "0").returncode == 1
    with listener(path):
        assert wait_ready(run, path, "0").returncode == 0


def test_the_wait_ends_at_once_when_the_core_has_exited(run: Runner, short_dir: Path) -> None:
    core = subprocess.Popen(["true"])
    core.wait()
    started = time.monotonic()
    result = wait_ready(run, short_dir / "host-agent.sock", "30", MAINPID=str(core.pid))
    assert result.returncode == 1
    assert time.monotonic() - started < 10, "it must not wait out the 30 seconds for a core that is gone"
    assert f"the core (pid {core.pid}) exited before it listened" in result.stderr


def test_a_core_that_is_alive_is_waited_for_and_found_ready(run: Runner, short_dir: Path) -> None:
    path = short_dir / "host-agent.sock"
    with listener(path):
        assert wait_ready(run, path, "5", MAINPID=str(os.getpid())).returncode == 0
    result = wait_ready(run, path, "1", MAINPID=str(os.getpid()))
    assert result.returncode == 1
    assert "exited before it listened" not in result.stderr, "this process is alive: only the time ran out"


def test_only_a_listener_on_exactly_this_path_counts(run: Runner, short_dir: Path) -> None:
    wanted = short_dir / "host agent.sock"  # a space: the path is the rest of the table's line, not one field
    with listener(short_dir / "host agent.sock.other"), listener(short_dir / "agent.sock"):
        listener(wanted).close()
        assert wait_ready(run, wanted, "1").returncode == 1
    wanted.unlink()
    with listener(wanted):
        assert wait_ready(run, wanted, "5").returncode == 0


@pytest.mark.parametrize(
    ("table", "ready"),
    [
        (HEADER + LISTENING, True),
        (HEADER + LISTENING.replace("00010000", "00000000"), False),  # bound or connected, not listening
        (HEADER + LISTENING.replace("{path}", "{path}.old"), False),
        (HEADER + LISTENING.replace("{path}", "@{path}"), False),  # an abstract socket of the same name
        (HEADER, False),
        ("", False),
    ],
)
def test_the_socket_table_is_read_by_flags_and_whole_path(
    run: Runner, short_dir: Path, tmp_path: Path, table: str, ready: bool
) -> None:
    path = short_dir / "host-agent.sock"
    listener(path).close()  # the file exists; whether anyone listens is what the table says
    fake = tmp_path / "unix"
    fake.write_text(table.replace("{path}", str(path)))
    result = wait_ready(run, path, "0", ACF_PROC_NET_UNIX=str(fake))
    assert (result.returncode == 0) == ready, result.stderr


def test_a_listener_in_the_table_without_a_socket_file_is_not_ready(
    run: Runner, short_dir: Path, tmp_path: Path
) -> None:
    path = short_dir / "host-agent.sock"
    fake = tmp_path / "unix"
    fake.write_text(HEADER + LISTENING.replace("{path}", str(path)))
    assert wait_ready(run, path, "0", ACF_PROC_NET_UNIX=str(fake)).returncode == 1
    path.write_text("a regular file is not a socket")
    assert wait_ready(run, path, "0", ACF_PROC_NET_UNIX=str(fake)).returncode == 1


def test_without_a_socket_table_it_says_so_instead_of_guessing(run: Runner, short_dir: Path, tmp_path: Path) -> None:
    path = short_dir / "host-agent.sock"
    with listener(path):
        result = wait_ready(run, path, "5", ACF_PROC_NET_UNIX=str(tmp_path / "absent"))
    assert result.returncode == 1
    assert "a listener cannot be told from a stale socket file" in result.stderr


@pytest.mark.parametrize(
    ("args", "message"),
    [
        ([], "Usage: acf-wait-ready SOCKET [SECONDS]"),
        (["/run/a.sock", "5", "extra"], "Usage: acf-wait-ready SOCKET [SECONDS]"),
        (["relative.sock"], "SOCKET must be an absolute path"),
        (["/run/a.sock", "soon"], "SECONDS must be a whole number"),
        (["/run/a.sock", "1.5"], "SECONDS must be a whole number"),
        (["/run/a.sock", "-1"], "SECONDS must be a whole number"),
    ],
)
def test_usage_errors_exit_2(run: Runner, args: list[str], message: str) -> None:
    result = wait_ready(run, *args)
    assert result.returncode == 2
    assert message in result.stderr


@pytest.mark.skipif(shutil.which("dash") is None, reason="dash is not installed")
def test_it_runs_under_dash_the_shell_a_minimal_host_has(run: Runner, short_dir: Path) -> None:
    path = short_dir / "host-agent.sock"
    with listener(path):
        assert run(["dash", SCRIPT, path, "5"]).returncode == 0
    assert run(["dash", SCRIPT, short_dir / "absent.sock", "0"]).returncode == 1
