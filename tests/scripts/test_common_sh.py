"""scripts/lib/common.sh — the helpers every operator script is built on.

The contract these tests pin (it is what the other scripts' own tests lean on):

* exit codes: 0 ok | 1 error | 2 usage | 3 NOT PINNED;
* stdout is data, stderr is messages;
* lock files are read by a strict KEY=VALUE parser — never sourced, and either entirely well-formed or refused;
* a private work directory is removed on every way out (success, `die`, SIGTERM).
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import signal
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path

import pytest

COMMON = Path(__file__).resolve().parents[2] / "scripts/lib/common.sh"

Runner = Callable[..., "subprocess.CompletedProcess[str]"]


@pytest.fixture
def bash(run: Runner) -> Callable[..., subprocess.CompletedProcess[str]]:
    """bash(body, *args, env=None): run `body` with common.sh sourced; ``$1..`` are *args."""

    def _bash(body: str, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return run(["bash", "-c", f'ACF_SCRIPT_NAME=t.sh; source "{COMMON}"\n{body}', "t.sh", *args], env=env)

    return _bash


# ------------------------------------------------------------------------------------ exit codes and streams


def test_log_and_warn_go_to_stderr_and_never_stdout(bash: Callable[..., subprocess.CompletedProcess[str]]) -> None:
    result = bash('log "hello"; warn "careful"')
    assert result.stdout == ""
    assert result.stderr == "t.sh: hello\nt.sh: WARNING: careful\n"


@pytest.mark.parametrize(
    ("call", "status", "stderr"),
    [
        ('die "broken"', 1, "t.sh: ERROR: broken\n"),
        ('die_usage "bad flag"', 2, "t.sh: bad flag\nTry 't.sh --help'.\n"),
        ('die_unpinned "X is UNSET"', 3, "t.sh: NOT PINNED: X is UNSET\n"),
    ],
)
def test_the_three_ways_to_stop_have_distinct_exit_codes(
    bash: Callable[..., subprocess.CompletedProcess[str]], call: str, status: int, stderr: str
) -> None:
    result = bash(f"{call}; echo not-reached")
    assert (result.returncode, result.stdout, result.stderr) == (status, "", stderr)


def test_sourcing_twice_is_harmless_and_keeps_strict_mode(
    bash: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    result = bash(f'source "{COMMON}"; echo "$-"; true')
    assert result.returncode == 0
    flags = result.stdout.strip()
    assert "e" in flags
    assert "u" in flags


def test_unset_variables_are_errors_in_scripts_that_use_it(
    bash: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    result = bash('echo "$definitely_not_set"; echo not-reached')
    assert result.returncode != 0
    assert "not-reached" not in result.stdout


# ------------------------------------------------------------------------------------------------ small helpers


@pytest.mark.parametrize(
    ("value", "valid"),
    [
        ("0" * 64, True),
        ("0123456789abcdef" * 4, True),
        ("A" * 64, False),
        ("a" * 63, False),
        ("a" * 65, False),
        ("g" * 64, False),
        ("", False),
        ("a" * 64 + "\n", False),
        (" " + "a" * 63, False),
    ],
)
def test_is_sha256_accepts_exactly_64_lowercase_hex_digits(
    bash: Callable[..., subprocess.CompletedProcess[str]], value: str, valid: bool
) -> None:
    result = bash('if is_sha256 "$1"; then echo yes; else echo no; fi', value)
    assert result.stdout.strip() == ("yes" if valid else "no")


@pytest.mark.parametrize(
    ("nbytes", "mib"),
    [(0, 0), (1, 1), (1048575, 1), (1048576, 1), (1048577, 2), (10 * 1048576, 10), (10 * 1048576 + 1, 11)],
)
def test_human_mib_rounds_up(bash: Callable[..., subprocess.CompletedProcess[str]], nbytes: int, mib: int) -> None:
    assert bash('human_mib "$1"', str(nbytes)).stdout == str(mib)


def test_sha256_file_is_the_hex_digest_and_nothing_else(
    bash: Callable[..., subprocess.CompletedProcess[str]], tmp_path: Path
) -> None:
    f = tmp_path / "data"
    f.write_bytes(b"agent compute fabric\n")
    result = bash('sha256_file "$1"', str(f))
    assert result.stdout == hashlib.sha256(b"agent compute fabric\n").hexdigest() + "\n"


def test_sha256_file_of_a_missing_file_is_an_error(
    bash: Callable[..., subprocess.CompletedProcess[str]], tmp_path: Path
) -> None:
    result = bash('sha256_file "$1"', str(tmp_path / "absent"))
    assert result.returncode == 1
    assert "cannot hash" in result.stderr


def test_need_cmd_names_the_missing_tool_and_the_hint(bash: Callable[..., subprocess.CompletedProcess[str]]) -> None:
    ok = bash("need_cmd sh")
    assert ok.returncode == 0
    missing = bash('need_cmd definitely-not-a-command "install it"')
    assert missing.returncode == 1
    assert "required command not found: definitely-not-a-command (install it)" in missing.stderr


def test_repo_root_is_the_directory_that_holds_scripts(bash: Callable[..., subprocess.CompletedProcess[str]]) -> None:
    assert bash("repo_root").stdout.strip() == str(COMMON.parents[2])


@pytest.mark.parametrize(
    ("machine", "ok"), [("x86_64", True), ("aarch64", True), ("riscv64", False), ("armv7l", False)]
)
def test_host_arch_supports_exactly_what_firecracker_supports(
    bash: Callable[..., subprocess.CompletedProcess[str]], tmp_path: Path, machine: str, ok: bool
) -> None:
    fake = tmp_path / "bin"
    fake.mkdir()
    uname = fake / "uname"
    uname.write_text(f"#!/bin/sh\necho {machine}\n")
    uname.chmod(0o755)
    result = bash("host_arch", env={"PATH": f"{fake}:{os.environ.get('PATH', '/usr/bin:/bin')}"})
    if ok:
        assert result.stdout.strip() == machine
    else:
        assert result.returncode == 1
        assert "unsupported architecture" in result.stderr


def test_require_root_passes_for_root_and_refuses_everyone_else(
    bash: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    result = bash("require_root; echo allowed")
    if os.geteuid() == 0:
        assert (result.returncode, result.stdout) == (0, "allowed\n")
    else:
        assert result.returncode == 1
        assert "must run as root" in result.stderr


@pytest.mark.skipif(
    os.geteuid() != 0 or shutil.which("setpriv") is None, reason="needs root and setpriv to drop privileges"
)
def test_require_root_refuses_an_unprivileged_caller(run: Runner) -> None:
    with tempfile.TemporaryDirectory() as d:  # world-traversable, unlike pytest's tmp_path
        os.chmod(d, 0o755)
        copy = Path(d) / "common.sh"
        shutil.copy(COMMON, copy)
        copy.chmod(0o644)
        result = run(
            [
                "setpriv",
                "--reuid=65534",
                "--regid=65534",
                "--clear-groups",
                "bash",
                "-c",
                f'ACF_SCRIPT_NAME=t.sh; source "{copy}"; require_root; echo allowed',
            ]
        )
    if "must run as root" not in result.stderr:
        pytest.skip(f"could not run bash as an unprivileged user here: {result.stderr.strip()}")
    assert result.returncode == 1
    assert "allowed" not in result.stdout


# ----------------------------------------------------------------------------------------- require_free_mib


def test_require_free_mib_passes_when_there_is_room_and_says_how_much_is_missing_when_there_is_not(
    bash: Callable[..., subprocess.CompletedProcess[str]], tmp_path: Path
) -> None:
    assert bash('require_free_mib "$1" 1 "a test"', str(tmp_path)).returncode == 0
    result = bash('require_free_mib "$1" 999999999999 "a test"', str(tmp_path))
    assert result.returncode == 1
    assert re.search(r"a test needs about 999999999999 MiB free in .*, but only \d+ MiB is available", result.stderr)
    assert "TMPDIR" in result.stderr


def test_require_free_mib_on_a_missing_directory_is_a_clear_error(
    bash: Callable[..., subprocess.CompletedProcess[str]], tmp_path: Path
) -> None:
    result = bash('require_free_mib "$1" 1 "a test"', str(tmp_path / "absent"))
    assert result.returncode == 1
    assert "cannot determine the free space" in result.stderr


# -------------------------------------------------------------------------------------------- make_workdir


def test_make_workdir_creates_a_private_directory_and_removes_it_on_exit(
    bash: Callable[..., subprocess.CompletedProcess[str]], tmp_path: Path
) -> None:
    result = bash(
        'make_workdir acf-test; echo "$ACF_WORKDIR"; touch "$ACF_WORKDIR/file"; stat -c %a "$ACF_WORKDIR"',
        env={"TMPDIR": str(tmp_path)},
    )
    workdir, mode = result.stdout.split()
    assert Path(workdir).parent == tmp_path
    assert Path(workdir).name.startswith("acf-test.")
    assert mode == "700"
    assert not Path(workdir).exists()


def test_make_workdir_is_removed_when_the_script_dies(
    bash: Callable[..., subprocess.CompletedProcess[str]], tmp_path: Path
) -> None:
    result = bash(
        'make_workdir acf-test; echo "$ACF_WORKDIR"; touch "$ACF_WORKDIR/f"; die "boom"', env={"TMPDIR": str(tmp_path)}
    )
    assert result.returncode == 1
    assert not Path(result.stdout.strip()).exists()


@pytest.mark.parametrize(("sig", "status"), [(signal.SIGTERM, 143), (signal.SIGINT, 130)])
def test_make_workdir_is_removed_on_a_signal_and_the_status_says_which(
    bash: Callable[..., subprocess.CompletedProcess[str]], tmp_path: Path, sig: signal.Signals, status: int
) -> None:
    if sig == signal.SIGINT and signal.getsignal(signal.SIGINT) is signal.SIG_IGN:
        pytest.skip(
            "SIGINT is ignored in this process tree (started in the background?); a shell cannot trap an inherited ignore"
        )
    result = bash(
        f'make_workdir acf-test; echo "$ACF_WORKDIR"; touch "$ACF_WORKDIR/f"; kill -{sig.name[3:]} $$; sleep 5',
        env={"TMPDIR": str(tmp_path)},
    )
    assert result.returncode == status
    assert not Path(result.stdout.strip()).exists()


# ---------------------------------------------------------------------------------------------- lock files


def lock(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "x.lock"
    path.write_text(text)
    return path


def test_lock_get_reads_values_comments_and_blank_lines(
    bash: Callable[..., subprocess.CompletedProcess[str]], tmp_path: Path
) -> None:
    f = lock(tmp_path, "# header\n\nA=1   # trailing\n\tB=two\t\nC=\n")
    assert bash('lock_get "$1" A', str(f)).stdout == "1\n"
    assert bash('lock_get "$1" B', str(f)).stdout == "two\n"
    assert bash('lock_get "$1" C', str(f)).stdout == "\n"


def test_lock_get_of_an_absent_key_is_an_error(
    bash: Callable[..., subprocess.CompletedProcess[str]], tmp_path: Path
) -> None:
    result = bash('lock_get "$1" Z', str(lock(tmp_path, "A=1\n")))
    assert result.returncode == 1
    assert "key not found: Z" in result.stderr


def test_lock_get_on_a_missing_file_is_an_error(
    bash: Callable[..., subprocess.CompletedProcess[str]], tmp_path: Path
) -> None:
    result = bash('lock_get "$1" A', str(tmp_path / "absent.lock"))
    assert result.returncode == 1
    assert "lock file not readable" in result.stderr


def test_a_lock_file_cannot_execute_code(bash: Callable[..., subprocess.CompletedProcess[str]], tmp_path: Path) -> None:
    marker = tmp_path / "pwned"
    f = lock(tmp_path, f"A=$(touch {marker})\n")
    result = bash('lock_get "$1" A', str(f))
    assert result.returncode == 1
    assert not marker.exists()
    f2 = lock(tmp_path, f"A=1\n`touch {marker}`\n")
    assert bash('lock_get "$1" A', str(f2)).returncode == 1
    assert not marker.exists()


def test_a_bad_line_after_the_requested_key_still_refuses_the_file(
    bash: Callable[..., subprocess.CompletedProcess[str]], tmp_path: Path
) -> None:
    """A lock file is entirely well-formed or not trusted: finding KEY on line 1 does not excuse line 2."""
    f = lock(tmp_path, "A=1\nthis line is garbage\n")
    result = bash('lock_get "$1" A', str(f))
    assert result.returncode == 1
    assert "malformed line" in result.stderr
    assert ":2:" in result.stderr, "the message must point at the offending line"


def test_a_repeated_key_is_refused_even_after_the_first_match(
    bash: Callable[..., subprocess.CompletedProcess[str]], tmp_path: Path
) -> None:
    f = lock(tmp_path, "A=1\nB=2\nA=3\n")
    result = bash('lock_get "$1" A', str(f))
    assert result.returncode == 1
    assert "duplicate key: A" in result.stderr
    assert ":3:" in result.stderr


def test_lock_keys_lists_keys_in_file_order_filtered_by_prefix(
    bash: Callable[..., subprocess.CompletedProcess[str]], tmp_path: Path
) -> None:
    f = lock(tmp_path, "BASE_REF_python=x\nBASE_DIGEST_python=UNSET\nBASE_REF_base=y\nKERNEL_SHA256_x86_64=UNSET\n")
    assert bash('lock_keys "$1" BASE_REF_', str(f)).stdout == "BASE_REF_python\nBASE_REF_base\n"
    assert bash('lock_keys "$1"', str(f)).stdout.splitlines() == [
        "BASE_REF_python",
        "BASE_DIGEST_python",
        "BASE_REF_base",
        "KERNEL_SHA256_x86_64",
    ]
    assert bash('lock_keys "$1" NOTHING_', str(f)).stdout == ""


def test_lock_get_pinned_turns_unset_and_empty_into_exit_code_3(
    bash: Callable[..., subprocess.CompletedProcess[str]], tmp_path: Path
) -> None:
    f = lock(tmp_path, "PINNED=sha256:abc\nUNPINNED=UNSET\nEMPTY=\n")
    assert bash('lock_get_pinned "$1" PINNED "the thing"', str(f)).stdout == "sha256:abc\n"
    for key in ("UNPINNED", "EMPTY"):
        result = bash('lock_get_pinned "$1" "$2" "the thing"', str(f), key)
        assert result.returncode == 3, result.stderr
        assert f"NOT PINNED: {key} is UNSET" in result.stderr
        assert "the thing" in result.stderr
        assert result.stdout == ""


def test_lock_get_pinned_on_an_absent_key_is_a_plain_error_not_unpinned(
    bash: Callable[..., subprocess.CompletedProcess[str]], tmp_path: Path
) -> None:
    result = bash('lock_get_pinned "$1" NOPE "the thing"', str(lock(tmp_path, "A=1\n")))
    assert result.returncode == 1


def test_the_shipped_lock_files_parse(bash: Callable[..., subprocess.CompletedProcess[str]]) -> None:
    repo = COMMON.parents[2]
    for rel in ("scripts/firecracker.lock", "images/images.lock"):
        result = bash('lock_keys "$1"', str(repo / rel))
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip()
