"""scripts/root-test.sh — what `make root-test` runs.

The script builds two Rust test binaries as the invoking user and runs their root-only tests as root. Neither a
build nor root belongs in a unit test, so ``cargo`` and ``sudo`` are stubs that record how they were called, and the
"test binaries" are scripts that print what the Rust test harness prints. What is tested is the script's own
decisions: what it builds, what it runs as root and how, and that neither a missing root nor an empty run can look
like a pass. (`make root-test` itself is the real thing; CI runs it.)
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

Runner = Callable[..., "subprocess.CompletedProcess[str]"]

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts/root-test.sh"
BASH = shutil.which("bash") or "/bin/bash"
AS_ROOT = os.geteuid() == 0
BUILD = "cargo test --no-run --locked --message-format=json-render-diagnostics"
REASON = "needs root: run with `make root-test`"

CARGO = """\
printf 'cargo %s\\n' "$*" >>"$CALLS"
if [ -n "${STUB_CARGO_FAIL:-}" ]; then echo "error: could not compile" >&2; exit 101; fi
case " $* " in
    *" -p acf-host-agent "*) exe="$STUB_BACKEND" ;;
    *) exe="$STUB_GUEST" ;;
esac
printf '{"reason":"compiler-artifact","target":{"kind":["lib"],"name":"t"},"profile":{"test":true},"executable":"%s"}\\n' "$exe"
"""
SUDO = """\
printf 'sudo %s\\n' "$*" >>"$CALLS"
[ "$1" = "--" ] && shift
exec "$@"
"""
TEST_BINARY = """\
printf '{name} args=[%s] cwd=%s\\n' "$*" "$PWD" >>"$CALLS"
echo "running ${{STUB_{upper}_TESTS:-1}} tests"
if [ "${{STUB_{upper}_TESTS:-1}}" != 0 ]; then
    if [ "${{STUB_{upper}_RC:-0}}" = 0 ]; then echo "test some::test ... ok"; else echo "test some::test ... FAILED"; fi
fi
exit "${{STUB_{upper}_RC:-0}}"
"""


class Stage:
    def __init__(self, tmp_path: Path, *, sudo: bool = True) -> None:
        self.calls = tmp_path / "calls.log"
        self.bin = tmp_path / "stubs"
        self.bin.mkdir()
        self.backend = tmp_path / "acf_host-0123456789abcdef"
        self.guest = tmp_path / "protocol-0123456789abcdef"
        self._write(self.bin / "cargo", CARGO)
        if sudo:
            self._write(self.bin / "sudo", SUDO)
        self._write(self.backend, TEST_BINARY.format(name="backend", upper="BACKEND"))
        self._write(self.guest, TEST_BINARY.format(name="guest", upper="GUEST"))
        # Everything else the script needs, and nothing more: a machine's real sudo must stay out of reach.
        for tool in ("bash", "dirname", "cat", "id", "mktemp", "rm", "tee", "grep", "python3"):
            real = shutil.which(tool)
            assert real is not None, tool
            (self.bin / tool).symlink_to(real)

    @staticmethod
    def _write(path: Path, body: str) -> None:
        path.write_text(f"#!{BASH}\n{body}")
        path.chmod(0o755)

    def env(self, **extra: str) -> dict[str, str]:
        return {
            "PATH": str(self.bin),
            "CALLS": str(self.calls),
            "STUB_BACKEND": str(self.backend),
            "STUB_GUEST": str(self.guest),
            **extra,
        }

    def called(self) -> list[str]:
        return self.calls.read_text().splitlines() if self.calls.exists() else []


def root_test(run: Runner, stage: Stage, *args: str, **env: str) -> subprocess.CompletedProcess[str]:
    return run(["bash", SCRIPT, *args], env=stage.env(**env))


def test_it_builds_as_the_invoking_user_and_runs_only_the_two_test_binaries_as_root(
    run: Runner, tmp_path: Path
) -> None:
    stage = Stage(tmp_path)
    result = root_test(run, stage)
    assert result.returncode == 0, result.stderr
    through_sudo = [] if AS_ROOT else ["sudo -- "]
    prefix = "".join(through_sudo)
    expected = [
        f"{BUILD} -p acf-host-agent --all-features --lib",  # never through sudo
        f"{BUILD} -p acf-guest-agent --test protocol",
        *([f"{prefix}{stage.backend} fc_backend_tests --ignored"] if not AS_ROOT else []),
        f"backend args=[fc_backend_tests --ignored] cwd={REPO}/execution/host-agent",
        *([f"{prefix}{stage.guest} --ignored"] if not AS_ROOT else []),
        f"guest args=[--ignored] cwd={REPO}/execution/guest-agent",
    ]
    assert stage.called() == expected
    assert "ok: the tests that need root ran and passed" in result.stderr
    assert "test some::test ... ok" in result.stdout


@pytest.mark.skipif(AS_ROOT, reason="root needs no sudo")
def test_without_root_and_without_sudo_it_fails_and_builds_nothing(run: Runner, tmp_path: Path) -> None:
    stage = Stage(tmp_path, sudo=False)
    result = root_test(run, stage)
    assert result.returncode == 1
    assert "these tests need root and there is no `sudo`" in result.stderr
    assert stage.called() == []
    assert "ok:" not in result.stderr


@pytest.mark.needs_root
def test_root_runs_the_binaries_directly(run: Runner, tmp_path: Path) -> None:
    stage = Stage(tmp_path, sudo=False)
    result = root_test(run, stage)
    assert result.returncode == 0, result.stderr
    assert not any(call.startswith("sudo") for call in stage.called())
    assert f"backend args=[fc_backend_tests --ignored] cwd={REPO}/execution/host-agent" in stage.called()


def test_a_build_failure_is_an_error_and_nothing_runs_as_root(run: Runner, tmp_path: Path) -> None:
    stage = Stage(tmp_path)
    result = root_test(run, stage, STUB_CARGO_FAIL="1")
    assert result.returncode == 1
    assert "cargo could not build the tests of acf-host-agent" in result.stderr
    assert not any(call.startswith(("sudo", "backend", "guest")) for call in stage.called())


@pytest.mark.parametrize(
    ("which", "message", "guest_ran"),
    [("BACKEND", "the Firecracker backend tests failed", False), ("GUEST", "the guest agent tests failed", True)],
)
def test_a_failing_test_fails_the_run(run: Runner, tmp_path: Path, which: str, message: str, guest_ran: bool) -> None:
    stage = Stage(tmp_path)
    result = root_test(run, stage, **{f"STUB_{which}_RC": "101"})
    assert result.returncode == 1
    assert message in result.stderr
    assert "test some::test ... FAILED" in result.stdout
    assert any(call.startswith("guest ") for call in stage.called()) == guest_ran


@pytest.mark.parametrize("which", ["BACKEND", "GUEST"])
def test_a_run_in_which_no_test_ran_is_a_failure_not_a_pass(run: Runner, tmp_path: Path, which: str) -> None:
    """`--ignored` selects the tests that are ignored. If they stop being ignored, or are renamed, nothing runs."""
    stage = Stage(tmp_path)
    result = root_test(run, stage, **{f"STUB_{which}_TESTS": "0"})
    assert result.returncode == 1
    assert "no test ran" in result.stderr
    assert "ok: the tests that need root ran" not in result.stderr


def test_usage(run: Runner, tmp_path: Path) -> None:
    stage = Stage(tmp_path)
    helped = root_test(run, stage, "--help")
    assert helped.returncode == 0
    assert "Usage: root-test.sh" in helped.stdout
    assert root_test(run, stage, "--all").returncode == 2
    assert stage.called() == []


def test_every_rust_test_that_asks_for_this_target_is_in_a_binary_the_script_runs() -> None:
    """The ignore reason is the contract: a test that says "run with `make root-test`" must be run by it.

    The script selects by test binary and, in the host agent, by module. A test with this reason anywhere else would
    be ignored by `cargo test` and never run by anything.
    """
    asking = sorted(
        path.relative_to(REPO / "execution").as_posix()
        for path in (REPO / "execution").rglob("*.rs")
        if REASON in path.read_text(encoding="utf-8")
    )
    assert asking == ["guest-agent/tests/protocol.rs", "host-agent/src/testing/fc_backend_tests.rs"], (
        "scripts/root-test.sh must be taught about every file listed here"
    )
    script = SCRIPT.read_text()
    assert 'cargo_test_binary acf-host-agent --all-features --lib)"' in script
    assert '"$backend" fc_backend_tests --ignored' in script
    assert 'cargo_test_binary acf-guest-agent --test protocol)"' in script
    assert '"$guest" --ignored' in script
    assert REASON in script, "the script quotes the reason it answers"
