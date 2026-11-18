"""scripts/check-release-purity.sh — prove a release `acf-host` carries no test-only code.

A check that finds nothing proves nothing unless it CAN find something, so most tests here come in pairs: the
sentinels are absent from a clean file, present in a file that has them, and the script notices the difference.
The last tests tie the sentinel list to the real Rust binaries when they have been built (``make release`` builds
both; ``CARGO_TARGET_DIR`` is honoured, as the Makefile honours it).
"""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts/check-release-purity.sh"

# What the `testing` feature of the host agent compiles in, by the strings it leaves in a binary. The first four
# sit in the coordinator's and the store's own code paths: they are what a release `acf-host` that was built with
# the feature by mistake contains. The others belong to test doubles that only `acf-host-fake` links.
REACHABLE_FROM_THE_CORE = [
    "simulated crash at",
    "AfterBackendMutationBeforeCommit",
    "AfterTerminalCommitBeforeResponse",
    "injected store append failure",
]
TEST_DOUBLES = [
    "FakeBackend",
    "the lifetime enforcer is down (test)",
    "acf test authority",
    "rcgen",
    "acf-host-fake",
]
SENTINELS = [*REACHABLE_FROM_THE_CORE, *TEST_DOUBLES]

Runner = Callable[..., "subprocess.CompletedProcess[str]"]


def binary(path: Path, *, with_sentinels: tuple[str, ...] = (), noise: int = 4096) -> Path:
    """An executable-looking blob: NUL-laden noise, with the given sentinels buried in it."""
    # No accidental sentinel from random bytes: every sentinel contains a lower-case "a", "c" or "e".
    scrub = bytes.maketrans(b"ace", b"\0\0\0")
    chunks = [os.urandom(noise).translate(scrub)]
    for s in with_sentinels:
        chunks += [b"\0\0", s.encode(), b"\0", os.urandom(64).translate(scrub)]
    path.write_bytes(b"\x7fELF" + b"".join(chunks))
    return path


def purity(run: Runner, *args: str | Path) -> subprocess.CompletedProcess[str]:
    return run(["bash", SCRIPT, *args])


def test_the_sentinels_tested_here_are_exactly_the_ones_the_script_looks_for() -> None:
    """Removing a sentinel from the script must be a decision made in two places, not an accident in one."""
    block = re.search(r"^SENTINELS=\(\n(.*?)^\)\n", SCRIPT.read_text(), re.MULTILINE | re.DOTALL)
    assert block is not None
    in_script = re.findall(r'^\s+"([^"]+)"', block.group(1), re.MULTILINE)
    assert in_script == SENTINELS
    assert all(set(s) & set("ace") for s in SENTINELS), "the noise in `binary()` relies on this"


def test_a_clean_binary_passes_and_says_the_method_was_not_validated_without_a_control(
    run: Runner, tmp_path: Path
) -> None:
    result = purity(run, binary(tmp_path / "acf-host"))
    assert result.returncode == 0, result.stderr
    assert "is free of test-only code" in result.stderr
    assert "no --control given" in result.stderr
    assert result.stdout == ""


@pytest.mark.parametrize("sentinel", SENTINELS)
def test_each_sentinel_on_its_own_fails_the_binary_and_is_named(run: Runner, tmp_path: Path, sentinel: str) -> None:
    result = purity(run, binary(tmp_path / "acf-host", with_sentinels=(sentinel,)))
    assert result.returncode == 1
    assert "contains test-only code" in result.stderr
    assert f"`{sentinel}`" in result.stderr
    assert "--features testing" in result.stderr


def test_all_sentinels_are_listed_when_several_are_present(run: Runner, tmp_path: Path) -> None:
    result = purity(run, binary(tmp_path / "acf-host", with_sentinels=tuple(SENTINELS)))
    assert result.returncode == 1
    for s in SENTINELS:
        assert f"`{s}`" in result.stderr


def test_what_a_mistaken_release_build_contains_is_enough_to_fail_it(run: Runner, tmp_path: Path) -> None:
    """A release `acf-host` built with the feature links none of the test doubles: only these strings give it away."""
    control = binary(tmp_path / "acf-host-fake", with_sentinels=tuple(SENTINELS))
    mistaken = binary(tmp_path / "acf-host", with_sentinels=tuple(REACHABLE_FROM_THE_CORE))
    result = purity(run, mistaken, "--control", control)
    assert result.returncode == 1
    assert "contains test-only code" in result.stderr
    for s in TEST_DOUBLES:
        assert f"`{s}`" not in result.stderr


def test_a_control_that_contains_every_sentinel_validates_the_method(run: Runner, tmp_path: Path) -> None:
    control = binary(tmp_path / "acf-host-fake", with_sentinels=tuple(SENTINELS))
    result = purity(run, binary(tmp_path / "acf-host"), "--control", control)
    assert result.returncode == 0, result.stderr
    assert "method validated against" in result.stderr


def test_a_blind_control_is_an_error_because_the_check_could_not_have_found_anything(
    run: Runner, tmp_path: Path
) -> None:
    control = binary(tmp_path / "acf-host-fake", with_sentinels=tuple(SENTINELS[:2]))
    result = purity(run, binary(tmp_path / "acf-host"), "--control", control)
    assert result.returncode == 1
    assert "this check cannot see test-only code" in result.stderr
    for missing in SENTINELS[2:]:
        assert f"`{missing}`" in result.stderr
    for present in SENTINELS[:2]:
        assert f"`{present}`" not in result.stderr


def test_a_dirty_binary_fails_even_when_the_control_is_fine(run: Runner, tmp_path: Path) -> None:
    control = binary(tmp_path / "acf-host-fake", with_sentinels=tuple(SENTINELS))
    result = purity(run, binary(tmp_path / "acf-host", with_sentinels=("FakeBackend",)), "--control", control)
    assert result.returncode == 1
    assert "contains test-only code" in result.stderr


def test_the_control_option_may_come_before_the_binary(run: Runner, tmp_path: Path) -> None:
    control = binary(tmp_path / "acf-host-fake", with_sentinels=tuple(SENTINELS))
    result = purity(run, "--control", control, binary(tmp_path / "acf-host"))
    assert result.returncode == 0, result.stderr


def test_binary_content_with_nul_bytes_and_newlines_is_searched_as_data(run: Runner, tmp_path: Path) -> None:
    path = tmp_path / "acf-host"
    path.write_bytes(b"\x7fELF\0\0\n\n\xff\xfe" + b"AfterTerminalCommitBeforeResponse" + b"\0\n")
    assert purity(run, path).returncode == 1


def test_a_sentinel_must_match_literally_not_as_a_pattern(run: Runner, tmp_path: Path) -> None:
    path = binary(tmp_path / "acf-host")
    # `.` would match any character, `(` and `)` would group, and a sentinel split across a NUL is not one.
    path.write_bytes(
        path.read_bytes()
        + b"acf.host.fake acf_host_fake simulated crash-at the lifetime enforcer is down [test] rc\0gen"
    )
    assert purity(run, path).returncode == 0


@pytest.mark.parametrize(
    ("args", "status", "message"),
    [
        ([], 2, "missing BINARY"),
        (["a", "b"], 2, "only one BINARY"),
        (["--bogus"], 2, "unknown option"),
        (["--control"], 1, "--control needs a file"),
    ],
)
def test_usage_errors(run: Runner, args: list[str], status: int, message: str) -> None:
    result = purity(run, *args)
    assert result.returncode == status
    assert message in result.stderr


def test_help_goes_to_stdout_and_succeeds(run: Runner) -> None:
    result = purity(run, "--help")
    assert result.returncode == 0
    assert "Usage: check-release-purity.sh" in result.stdout


def test_a_path_that_is_not_a_file_is_an_error(run: Runner, tmp_path: Path) -> None:
    assert "not a file" in purity(run, tmp_path / "nope").stderr
    assert purity(run, tmp_path).returncode == 1
    clean = binary(tmp_path / "acf-host")
    result = purity(run, clean, "--control", tmp_path / "no-control")
    assert result.returncode == 1
    assert "control is not a file" in result.stderr


# ------------------------------------------------------------------------- against the real Rust binaries

TARGET = Path(os.environ.get("CARGO_TARGET_DIR") or REPO / "target")
FAKE = TARGET / "debug/acf-host-fake"
RELEASE = TARGET / "release/acf-host"


@pytest.mark.skipif(not FAKE.exists(), reason="build the control first: make fake-host")
def test_every_sentinel_is_present_in_the_real_test_build(run: Runner) -> None:
    """If a sentinel string is renamed in the Rust source, this fails: the purity check would have gone blind."""
    dirty = purity(run, FAKE)
    assert dirty.returncode == 1
    for s in SENTINELS:
        assert f"`{s}`" in dirty.stderr, f"{s!r} not found in {FAKE}"


@pytest.mark.skipif(not RELEASE.exists(), reason="build the release binary first: make release")
def test_the_real_release_binary_is_pure(run: Runner) -> None:
    args: list[str | Path] = [RELEASE]
    if FAKE.exists():
        args += ["--control", FAKE]
    result = purity(run, *args)
    assert result.returncode == 0, result.stderr
