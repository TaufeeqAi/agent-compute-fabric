"""Shared fixtures for the repository's tests.

``tests/tools`` and ``tests/scripts`` run without KVM and without network. Tests that need root (they extract
tarballs or build filesystems with real ownership) carry the ``needs_root`` marker and are skipped for other users.

``tests/integration`` and ``tests/isolation`` boot real microVMs: they carry the ``integration`` / ``isolation``
markers and are skipped unless ``ACF_INTEGRATION=1`` (see ``tests/helpers/acf_integration.py``, whose fixtures are
re-exported below). The subset marked ``control_plane`` (admission, ceilings, state machine, exit codes: nothing that
depends on what runs inside a guest) can instead run against the in-memory host with ``ACF_CONTROL_PLANE=1``
(``make control-plane``); everything else is skipped in that mode. ``tests/integration/test_driver_selftest.py``
proves the driver those suites use, against the in-memory host, and is enabled by ``ACF_DRIVER_SELFTEST=1``
(``make driver-selftest``).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

import pytest

from acf_integration import (
    acf,
    clean_host,
    control_plane_enabled,
    host_env,
    host_unit,
    integration_enabled,
    selftest_enabled,
)

REPO = Path(__file__).resolve().parent.parent

# Fixtures for tests/integration and tests/isolation (imported so that pytest finds them from both directories).
__all__ = ["acf", "clean_host", "host_env", "host_unit"]

# The parts of the repository the scripts read at run time. A test that needs to edit a lock file, a
# Dockerfile, a unit or one of the shipped trusted files works on a private copy of exactly these.
TREE_PARTS = ("scripts", "tools", "images", "config", "profiles", "deploy", "schemas", "Cargo.toml")

Runner = Callable[..., "subprocess.CompletedProcess[str]"]


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    not_root = os.geteuid() != 0
    skip_root = pytest.mark.skip(reason="needs root (it builds filesystems / extracts tarballs with real ownership)")
    skip_kvm = pytest.mark.skip(
        reason="needs a running host: a KVM host with acf-host running (ACF_INTEGRATION=1; docs/OPERATIONS.md), "
        "or, for the tests that need no guest, the in-memory host (ACF_CONTROL_PLANE=1; `make control-plane`)"
    )
    skip_real_guest = pytest.mark.skip(
        reason="needs a real guest: it asserts on what runs inside a microVM (ACF_INTEGRATION=1 on a KVM host)"
    )
    skip_selftest = pytest.mark.skip(
        reason="needs the in-memory host and the CLI (ACF_DRIVER_SELFTEST=1; `make driver-selftest`)"
    )
    for item in items:
        # get_closest_marker, not `in item.keywords`: keywords also hold the NAMES of parent directories, and the
        # tests live in directories called "integration" and "isolation".
        if not_root and item.get_closest_marker("needs_root"):
            item.add_marker(skip_root)
        if item.get_closest_marker("integration") or item.get_closest_marker("isolation"):
            if control_plane_enabled():
                if not item.get_closest_marker("control_plane"):
                    item.add_marker(skip_real_guest)
            elif not integration_enabled():
                item.add_marker(skip_kvm)
        if item.get_closest_marker("driver_selftest") and not selftest_enabled():
            item.add_marker(skip_selftest)


@pytest.fixture(scope="session")
def repo() -> Path:
    return REPO


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """A private, editable copy of the repository's non-Rust parts (scripts find the repo relative to themselves)."""
    dst = tmp_path / "repo"
    dst.mkdir()
    for part in TREE_PARTS:
        src = REPO / part
        if src.is_dir():
            shutil.copytree(src, dst / part, symlinks=True, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        elif src.is_file():
            shutil.copy2(src, dst / part)
    return dst


@pytest.fixture
def clean_env(tmp_path: Path) -> dict[str, str]:
    """A minimal environment: no SOURCE_DATE_EPOCH, ACF_* or TMPDIR from the machine running the tests."""
    scratch = tmp_path / "tmp"
    scratch.mkdir(exist_ok=True)
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home), "LC_ALL": "C", "TMPDIR": str(scratch)}


@pytest.fixture
def run(clean_env: dict[str, str]) -> Runner:
    """Run a program, capture text output, never raise on a non-zero status."""

    def _run(
        args: Sequence[str | os.PathLike[str]],
        *,
        env: Mapping[str, str] | None = None,
        cwd: Path | None = None,
        input_text: str | None = None,
        timeout: float = 180,
    ) -> subprocess.CompletedProcess[str]:
        merged = {**clean_env, **(env or {})}
        return subprocess.run(  # noqa: PLW1510 - the status is the thing under test
            [str(a) for a in args],
            capture_output=True,
            text=True,
            env=merged,
            cwd=cwd,
            input=input_text,
            timeout=timeout,
        )

    return _run


@pytest.fixture
def py(run: Runner) -> Runner:
    """Run a Python script of this repository in isolated mode, the way the shell scripts do (`python3 -I`)."""

    def _py(
        script: str | os.PathLike[str], *args: str | os.PathLike[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        return run([sys.executable, "-I", script, *args], **kwargs)

    return _py


def have(command: str) -> bool:
    return shutil.which(command) is not None
