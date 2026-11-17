"""scripts/acf-setup-cgroup — create the cgroup v2 parent the jailer places one child cgroup per VM under.

The script is POSIX sh and takes the cgroup mount point from ``ACF_CGROUP_ROOT``, so it runs here against a
directory that imitates one. A plain directory cannot imitate the kernel's cgroup.subtree_control (a write there
REPLACES the file's content instead of enabling a controller), so these tests read the file as "the controller
written last": starting a level with two of the three controllers enabled must leave exactly the missing one
written, which proves the script wrote only what was missing.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/acf-setup-cgroup"

Runner = Callable[..., "subprocess.CompletedProcess[str]"]

ALL = "cpuset cpu io memory pids\n"


def fake_cgroup_root(tmp_path: Path, controllers: str = ALL, enabled: str | None = None) -> Path:
    root = tmp_path / "cgroup"
    root.mkdir()
    (root / "cgroup.controllers").write_text(controllers)
    if enabled is not None:
        (root / "cgroup.subtree_control").write_text(enabled)
    return root


def setup(run: Runner, root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return run(["sh", SCRIPT, *args], env={"ACF_CGROUP_ROOT": str(root)})


def test_a_fresh_host_gets_the_parent_directory_with_all_three_controllers_delegated(
    run: Runner, tmp_path: Path
) -> None:
    root = fake_cgroup_root(tmp_path)
    result = setup(run, root)
    assert result.returncode == 0, result.stderr
    assert (root / "acf").is_dir()
    # "+pids" is the last controller written at each level: the root's and the parent's own.
    assert (root / "cgroup.subtree_control").read_text() == "+pids"
    assert (root / "acf" / "cgroup.subtree_control").read_text() == "+pids"
    assert f"{root / 'acf'} delegates: cpu memory pids" in result.stderr + result.stdout


def test_a_custom_parent_name_is_used(run: Runner, tmp_path: Path) -> None:
    root = fake_cgroup_root(tmp_path)
    assert setup(run, root, "sandboxes").returncode == 0
    assert (root / "sandboxes").is_dir()
    assert not (root / "acf").exists()


def test_a_second_run_changes_nothing_when_everything_is_already_delegated(run: Runner, tmp_path: Path) -> None:
    root = fake_cgroup_root(tmp_path, enabled="cpu memory pids\n")
    (root / "acf").mkdir()
    (root / "acf" / "cgroup.subtree_control").write_text("cpu memory pids\n")
    before = {
        p: (p.read_text(), p.stat().st_mtime_ns)
        for p in (root / "cgroup.subtree_control", root / "acf" / "cgroup.subtree_control")
    }
    result = setup(run, root)
    assert result.returncode == 0, result.stderr
    after = {p: (p.read_text(), p.stat().st_mtime_ns) for p in before}
    assert after == before, "an already-correct host must not be written to"


@pytest.mark.parametrize(
    ("enabled", "written_last"),
    [("memory pids\n", "+cpu"), ("cpu pids\n", "+memory"), ("cpu memory\n", "+pids"), ("pids\n", "+memory")],
)
def test_only_the_missing_controllers_are_enabled(run: Runner, tmp_path: Path, enabled: str, written_last: str) -> None:
    root = fake_cgroup_root(tmp_path, enabled=enabled)
    (root / "acf").mkdir()
    (root / "acf" / "cgroup.subtree_control").write_text("cpu memory pids\n")
    assert setup(run, root).returncode == 0
    assert (root / "cgroup.subtree_control").read_text() == written_last
    assert (root / "acf" / "cgroup.subtree_control").read_text() == "cpu memory pids\n", (
        "the level that was complete is untouched"
    )


def test_an_existing_parent_directory_is_reused_not_recreated(run: Runner, tmp_path: Path) -> None:
    root = fake_cgroup_root(tmp_path)
    (root / "acf").mkdir()
    (root / "acf" / "marker").write_text("keep me")
    assert setup(run, root).returncode == 0
    assert (root / "acf" / "marker").read_text() == "keep me"


@pytest.mark.parametrize("missing", ["cpu", "memory", "pids"])
def test_a_host_without_a_needed_controller_is_refused_naming_it(run: Runner, tmp_path: Path, missing: str) -> None:
    available = " ".join(c for c in ("cpuset", "cpu", "io", "memory", "pids") if c != missing) + "\n"
    root = fake_cgroup_root(tmp_path, controllers=available)
    result = setup(run, root)
    assert result.returncode == 1
    assert f"the '{missing}' controller is not available" in result.stderr
    assert not (root / "acf").exists(), "nothing may be created on a host that cannot honour the profile"


def test_a_controller_whose_name_merely_contains_a_needed_one_does_not_count(run: Runner, tmp_path: Path) -> None:
    root = fake_cgroup_root(tmp_path, controllers="cpuset io memory_extra pids\n")
    result = setup(run, root)
    assert result.returncode == 1
    assert "the 'cpu' controller is not available" in result.stderr


def test_a_cgroup_v1_or_hybrid_layout_is_refused_with_the_boot_parameter_to_fix_it(run: Runner, tmp_path: Path) -> None:
    root = tmp_path / "cgroup"
    root.mkdir()  # no cgroup.controllers: not a unified hierarchy
    result = setup(run, root)
    assert result.returncode == 1
    assert "not a cgroup v2" in result.stderr
    assert "systemd.unified_cgroup_hierarchy=1" in result.stderr


@pytest.mark.parametrize("name", [".", "..", "a/b", "../escape", "/abs", "-x", "--help"])
def test_a_parent_name_that_could_leave_the_cgroup_root_or_look_like_an_option_is_a_usage_error(
    run: Runner, tmp_path: Path, name: str
) -> None:
    root = fake_cgroup_root(tmp_path)
    result = setup(run, root, name)
    assert result.returncode == 2, result.stderr
    assert "invalid cgroup name" in result.stderr
    assert sorted(p.name for p in root.iterdir()) == ["cgroup.controllers"], "nothing created, nothing written"
    assert not (tmp_path / "escape").exists()


def test_an_unwritable_controller_file_is_an_error_that_names_the_file(run: Runner, tmp_path: Path) -> None:
    root = fake_cgroup_root(tmp_path)
    (root / "cgroup.subtree_control").mkdir()  # a directory: reading yields nothing, writing fails
    result = setup(run, root)
    assert result.returncode == 1
    assert "cannot enable" in result.stderr
    assert str(root / "cgroup.subtree_control") in result.stderr


def test_a_parent_path_that_is_a_file_is_an_error(run: Runner, tmp_path: Path) -> None:
    root = fake_cgroup_root(tmp_path, enabled="cpu memory pids\n")
    (root / "acf").write_text("not a directory")
    result = setup(run, root)
    assert result.returncode == 1
    assert "cannot create" in result.stderr


def test_the_script_is_posix_sh_and_runs_under_dash_and_bash_alike(run: Runner, tmp_path: Path) -> None:
    for shell in ("dash", "bash"):
        root = tmp_path / shell
        root.mkdir()
        fake = fake_cgroup_root(root)
        result = run([shell, str(SCRIPT)], env={"ACF_CGROUP_ROOT": str(fake)})
        assert result.returncode == 0, (shell, result.stderr)
        assert (fake / "acf").is_dir()
