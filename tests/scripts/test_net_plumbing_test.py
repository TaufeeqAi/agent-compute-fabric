"""scripts/net-plumbing-test.sh — what `make net-plumbing-test` runs.

The script builds two Rust test binaries and runs them where they may create a network namespace. Building and
namespaces are exactly what a unit test must not depend on, so here ``cargo``, ``unshare``, ``ip`` and ``nft`` are
stubs that record how they were called, and the "test binaries" are scripts that print what the Rust test harness
prints. What is tested is the script's own decisions: what it builds, what it runs inside the namespace and in
which order, when it skips, and that a skip or an empty run can never look like a pass where the run is required.
(`make net-plumbing-test` itself is the real thing; CI runs it.)
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

Runner = Callable[..., "subprocess.CompletedProcess[str]"]

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts/net-plumbing-test.sh"
BASH = shutil.which("bash") or "/bin/bash"

# As root there is no need for a user namespace; as anyone else it is what makes the rest possible.
NAMESPACE = "unshare --net --mount --" if os.geteuid() == 0 else "unshare --user --map-root-user --net --mount --"
BUILD = "cargo test --no-run --locked --message-format=json-render-diagnostics"

CARGO = """\
printf 'cargo %s\\n' "$*" >>"$CALLS"
if [ -n "${STUB_CARGO_FAIL:-}" ]; then echo "error: could not compile" >&2; exit 101; fi
case " $* " in
    *" -p acf-host-agent "*) exe="$STUB_PLUMBING" ;;
    *) exe="$STUB_REDIRECT" ;;
esac
echo "   Compiling something v0.2.0" >&2
printf '{"reason":"compiler-artifact","target":{"kind":["lib"],"name":"dep"},"profile":{"test":false},"executable":null}\\n'
printf '{"reason":"compiler-artifact","target":{"kind":["lib"],"name":"t"},"profile":{"test":true},"executable":"%s"}\\n' "$exe"
if [ -n "${STUB_CARGO_TWO:-}" ]; then
    printf '{"reason":"compiler-artifact","target":{"kind":["bin"],"name":"u"},"profile":{"test":true},"executable":"%s"}\\n' "$exe"
fi
printf '{"reason":"build-finished","success":true}\\n'
"""
UNSHARE = """\
all="$*"
printf 'unshare %s\\n' "${all//$'\\n'/ }" >>"$CALLS"  # one line per call, whatever `sh -c` is given
if [ -n "${STUB_UNSHARE_FAIL:-}" ]; then echo "unshare: unshare failed: Operation not permitted" >&2; exit 1; fi
while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done
shift
exec "$@"
"""
TOOL = """\
printf '{name} %s\\n' "$*" >>"$CALLS"
case "${{STUB_{upper}_FAIL:-}}" in
    '') ;;
    *) case "$*" in *"$STUB_{upper}_FAIL"*) echo "{name}: Error: Operation not supported" >&2; exit 1 ;; esac ;;
esac
"""
TEST_BINARY = """\
printf '{name} args=[%s] cwd=%s\\n' "$*" "$PWD" >>"$CALLS"
echo
echo "running ${{STUB_{upper}_TESTS:-1}} tests"
if [ "${{STUB_{upper}_TESTS:-1}}" != 0 ]; then
    if [ "${{STUB_{upper}_RC:-0}}" = 0 ]; then echo "test some::test ... ok"; else echo "test some::test ... FAILED"; fi
fi
echo
echo "test result: done."
exit "${{STUB_{upper}_RC:-0}}"
"""


class Stage:
    def __init__(self, tmp_path: Path) -> None:
        self.calls = tmp_path / "calls.log"
        self.bin = tmp_path / "stubs"
        self.bin.mkdir()
        self.plumbing = tmp_path / "acf_host-0123456789abcdef"
        self.redirect = tmp_path / "redirect-0123456789abcdef"
        self._write(self.bin / "cargo", CARGO)
        self._write(self.bin / "unshare", UNSHARE)
        self._write(self.bin / "ip", TOOL.format(name="ip", upper="IP"))
        self._write(self.bin / "nft", TOOL.format(name="nft", upper="NFT"))
        self._write(self.plumbing, TEST_BINARY.format(name="plumbing", upper="PLUMBING"))
        self._write(self.redirect, TEST_BINARY.format(name="redirect", upper="REDIRECT"))

    @staticmethod
    def _write(path: Path, body: str) -> None:
        path.write_text(f"#!{BASH}\n{body}")
        path.chmod(0o755)

    def env(self, **extra: str) -> dict[str, str]:
        return {
            "PATH": f"{self.bin}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            "CALLS": str(self.calls),
            "STUB_PLUMBING": str(self.plumbing),
            "STUB_REDIRECT": str(self.redirect),
            **extra,
        }

    def called(self) -> list[str]:
        return self.calls.read_text().splitlines() if self.calls.exists() else []


@pytest.fixture
def stage(tmp_path: Path) -> Stage:
    return Stage(tmp_path)


def net_plumbing_test(run: Runner, stage: Stage, *args: str, **env: str) -> subprocess.CompletedProcess[str]:
    return run(["bash", SCRIPT, *args], env=stage.env(**env))


def prepare_commands() -> list[str]:
    """The namespace preparation the script runs before tests/redirect.rs, one command per entry."""
    block = re.search(r"readonly PREPARE_REDIRECT='\n(.*?)'\n", SCRIPT.read_text(), re.DOTALL)
    assert block is not None
    return [line.removesuffix(" &&") for line in block.group(1).splitlines()]


def test_it_builds_both_test_binaries_then_runs_each_in_a_namespace_of_its_own(run: Runner, stage: Stage) -> None:
    result = net_plumbing_test(run, stage)
    assert result.returncode == 0, result.stderr
    calls = stage.called()
    assert calls[:3] == [
        f"{NAMESPACE} true",  # can this user have a namespace at all? asked before anything is built
        f"{BUILD} -p acf-host-agent --all-features --lib",
        f"{BUILD} -p acf-traffic --test redirect",
    ]
    # 1. The host agent's plumbing tests, by filter, with the ignored ones included.
    assert calls[3] == f"{NAMESPACE} {stage.plumbing} netplumb netns --include-ignored"
    assert calls[4] == f"plumbing args=[netplumb netns --include-ignored] cwd={REPO}/execution/host-agent"
    # 2. The redirect test: a second namespace, prepared first, then the test binary.
    assert calls[5].startswith(f"{NAMESPACE} sh -c ")
    assert calls[5].endswith(f" {stage.redirect} --include-ignored")
    assert calls[6:11] == [
        "ip link set lo up",
        "ip addr add 198.51.100.10/32 dev lo",
        "nft add table ip acf",
        "nft add chain ip acf out { type nat hook output priority -100 ; }",
        "nft add rule ip acf out ip saddr 127.0.0.2 tcp dport { 443, 8443, 9443 } redirect to :15001",
    ]
    assert calls[11] == f"redirect args=[--include-ignored] cwd={REPO}/execution/traffic"
    assert len(calls) == 12
    assert "ok: the namespace tests ran and passed" in result.stderr
    assert "test some::test ... ok" in result.stdout, "what the tests print is shown, not swallowed"


def test_where_a_namespace_cannot_be_created_it_skips_with_a_message_and_builds_nothing(
    run: Runner, stage: Stage
) -> None:
    result = net_plumbing_test(run, stage, STUB_UNSHARE_FAIL="1")
    assert result.returncode == 0, result.stderr
    assert "net-plumbing-test.sh: skipped: " in result.stderr
    assert "cannot create a" in result.stderr
    assert stage.called() == [f"{NAMESPACE} true"], "no build, no test: only the question was asked"
    assert "ok:" not in result.stderr, "a skip must never read like a pass"


def test_a_required_run_that_would_be_skipped_is_a_failure(run: Runner, stage: Stage) -> None:
    result = net_plumbing_test(run, stage, STUB_UNSHARE_FAIL="1", ACF_REQUIRE_NETNS="1")
    assert result.returncode == 1
    assert "ACF_REQUIRE_NETNS=1: a skip is a failure" in result.stderr
    assert stage.called() == [f"{NAMESPACE} true"]


def test_a_build_failure_is_an_error_and_nothing_is_run(run: Runner, stage: Stage) -> None:
    result = net_plumbing_test(run, stage, STUB_CARGO_FAIL="1")
    assert result.returncode == 1
    assert "cargo could not build the tests of acf-host-agent" in result.stderr
    assert "error: could not compile" in result.stderr, "cargo's own diagnostics reach the terminal"
    assert not any(call.startswith(("plumbing ", "redirect ")) for call in stage.called())


def test_a_build_that_yields_more_than_one_test_executable_is_not_guessed_at(run: Runner, stage: Stage) -> None:
    result = net_plumbing_test(run, stage, STUB_CARGO_TWO="1")
    assert result.returncode == 1
    assert "expected exactly one test executable, cargo reported 2" in result.stderr
    assert "cannot tell which test executable cargo built for acf-host-agent" in result.stderr


def test_a_failing_plumbing_test_fails_the_run_before_the_redirect_test(run: Runner, stage: Stage) -> None:
    result = net_plumbing_test(run, stage, STUB_PLUMBING_RC="101")
    assert result.returncode == 1
    assert "the network plumbing tests failed" in result.stderr
    assert "test some::test ... FAILED" in result.stdout
    assert not any(call.startswith("redirect ") for call in stage.called())


def test_a_failing_redirect_test_fails_the_run(run: Runner, stage: Stage) -> None:
    result = net_plumbing_test(run, stage, STUB_REDIRECT_RC="101")
    assert result.returncode == 1
    assert "the redirect test failed" in result.stderr
    assert "skipped" not in result.stderr, "the namespace was prepared: this is a failure, not a skip"


def test_a_namespace_that_cannot_be_prepared_is_a_skip_and_a_failure_where_the_run_is_required(
    run: Runner, stage: Stage
) -> None:
    skipped = net_plumbing_test(run, stage, STUB_NFT_FAIL="add chain")
    assert skipped.returncode == 0, skipped.stderr
    assert "skipped: the namespace for tests/redirect.rs could not be prepared" in skipped.stderr
    assert "nft: Error: Operation not supported" in skipped.stdout, "the command that failed is shown"
    assert not any(call.startswith("redirect ") for call in stage.called()), "the test never ran unprepared"

    required = net_plumbing_test(run, stage, STUB_NFT_FAIL="add chain", ACF_REQUIRE_NETNS="1")
    assert required.returncode == 1
    assert "a skip is a failure" in required.stderr


@pytest.mark.parametrize("which", ["PLUMBING", "REDIRECT"])
def test_a_run_in_which_no_test_ran_is_a_failure_not_a_pass(run: Runner, stage: Stage, which: str) -> None:
    result = net_plumbing_test(run, stage, **{f"STUB_{which}_TESTS": "0"})
    assert result.returncode == 1
    assert "no test ran" in result.stderr
    assert "ok: the namespace tests ran" not in result.stderr


def test_usage(run: Runner, stage: Stage) -> None:
    helped = net_plumbing_test(run, stage, "--help")
    assert helped.returncode == 0
    assert "Usage: net-plumbing-test.sh" in helped.stdout
    assert "ACF_REQUIRE_NETNS" in helped.stdout
    assert net_plumbing_test(run, stage, "--fast").returncode == 2
    bad = net_plumbing_test(run, stage, ACF_REQUIRE_NETNS="yes")
    assert bad.returncode == 2
    assert "ACF_REQUIRE_NETNS must be 0 or 1" in bad.stderr
    assert stage.called() == []


def test_the_namespace_is_prepared_exactly_as_the_redirect_test_says_it_must_be() -> None:
    """tests/redirect.rs documents the namespace it needs. If that changes, this script must change with it."""
    header = (REPO / "execution/traffic/tests/redirect.rs").read_text().split("#![allow", 1)[0]
    documented = " ".join(line.removeprefix("//!").strip() for line in header.splitlines())
    commands = prepare_commands()
    assert commands[-2:] == [': >"$ACF_NETNS_PREPARED"', 'exec "$0" "$@"']
    assert len(commands) == 7
    for command in commands[:-2]:
        assert command in documented, f"not in the header of tests/redirect.rs: {command}"
    assert "-- --ignored" in documented, "the test is ignored by default; the script runs it with the ignored included"


def test_the_filters_name_test_modules_that_exist_and_whose_tests_ask_for_this_target() -> None:
    """The filters are substrings of test paths. A renamed module would make them match nothing."""
    backend = REPO / "execution/host-agent/src/backend"
    for module in (backend / "firecracker/netplumb.rs", backend / "netns.rs"):
        assert module.is_file(), module
        assert "make net-plumbing-test" in module.read_text(), f"{module.name} no longer points at this target"
    script = SCRIPT.read_text()
    assert '"$plumbing" netplumb netns --include-ignored' in script
