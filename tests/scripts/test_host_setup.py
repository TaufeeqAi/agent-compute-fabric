"""scripts/host-setup.sh — install the host agent, its configuration and its units on a machine.

Everything runs with ``--destdir`` into a temporary directory, which also skips ``systemctl`` and
``systemd-tmpfiles``, so nothing here touches the machine running the tests. The script finds the repository
relative to itself, so each test works on a private copy of the repository's non-Rust parts (the ``tree`` fixture)
and can edit what the script reads.
"""

from __future__ import annotations

import os
import stat
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

Runner = Callable[..., "subprocess.CompletedProcess[str]"]

pytestmark = pytest.mark.needs_root  # `install -o root -g root` and the script's own require_root


def acf_host(tmp_path: Path, *, extra: bytes = b"") -> Path:
    path = tmp_path / "acf-host"
    path.write_bytes(b"#!/bin/sh\necho acf-host fake\n" + extra)
    path.chmod(0o755)
    return path


def install(run: Runner, tree: Path, dest: Path, binary: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return run(["bash", tree / "scripts/host-setup.sh", "install", "--acf-host", binary, "--destdir", dest, *extra])


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_install_creates_the_documented_layout_with_root_owned_unwritable_files(
    run: Runner, tree: Path, tmp_path: Path
) -> None:
    dest = tmp_path / "dest"
    result = install(run, tree, dest, acf_host(tmp_path))
    assert result.returncode == 0, result.stderr

    expected_dirs = {
        "opt/acf": 0o755,
        "opt/acf/bin": 0o755,
        "opt/acf/libexec": 0o755,
        "etc/acf": 0o755,
        "var/lib/acf": 0o700,
        "var/lib/acf/images": 0o755,
        "etc/systemd/system": 0o755,
        "etc/tmpfiles.d": 0o755,
    }
    for rel, want in expected_dirs.items():
        path = dest / rel
        assert path.is_dir(), rel
        assert mode(path) == want, f"{rel}: {mode(path):o}"
        assert (path.stat().st_uid, path.stat().st_gid) == (0, 0), rel

    expected_files = {
        "opt/acf/bin/acf-host": (tmp_path / "acf-host", 0o755),
        "opt/acf/libexec/acf-setup-cgroup": (tree / "scripts/acf-setup-cgroup", 0o755),
        "etc/acf/host.yaml": (tree / "config/host.example.yaml", 0o644),
        "etc/acf/policy.yaml": (tree / "policies/default.yaml", 0o644),
        "etc/systemd/system/acf-cgroup.service": (tree / "deploy/systemd/acf-cgroup.service", 0o644),
        "etc/systemd/system/acf-host.service": (tree / "deploy/systemd/acf-host.service", 0o644),
        "etc/tmpfiles.d/acf.conf": (tree / "deploy/tmpfiles.d/acf.conf", 0o644),
    }
    for rel, (source, want) in expected_files.items():
        path = dest / rel
        assert path.is_file(), rel
        assert path.read_bytes() == source.read_bytes(), rel
        assert mode(path) == want, f"{rel}: {mode(path):o}"
        assert (path.stat().st_uid, path.stat().st_gid) == (0, 0), rel

    leftovers = [p for p in dest.rglob("*") if ".new." in p.name]
    assert leftovers == [], "atomic-replace temporaries must not survive"
    assert "Installed. Next steps (nothing has been started)" in result.stderr
    assert "systemctl enable --now acf-host.service" in result.stderr


def test_nothing_is_started_or_enabled_in_destdir_mode(run: Runner, tree: Path, tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "calls.log"
    for name in ("systemctl", "systemd-tmpfiles"):
        stub = bin_dir / name
        stub.write_text(f'#!/bin/sh\necho "{name} $*" >>"{log}"\n')
        stub.chmod(0o755)
    env = {"PATH": f"{bin_dir}:{os.environ.get('PATH', '/usr/bin:/bin')}"}
    result = run(
        [
            "bash",
            tree / "scripts/host-setup.sh",
            "install",
            "--acf-host",
            acf_host(tmp_path),
            "--destdir",
            tmp_path / "dest",
        ],
        env=env,
    )
    assert result.returncode == 0, result.stderr
    assert not log.exists(), "--destdir must skip systemctl and tmpfiles"


def test_a_second_install_succeeds_and_keeps_everything(run: Runner, tree: Path, tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    binary = acf_host(tmp_path)
    assert install(run, tree, dest, binary).returncode == 0
    before = {p.relative_to(dest): p.read_bytes() for p in dest.rglob("*") if p.is_file()}
    again = install(run, tree, dest, binary)
    assert again.returncode == 0, again.stderr
    after = {p.relative_to(dest): p.read_bytes() for p in dest.rglob("*") if p.is_file()}
    assert after == before
    assert "is already the shipped version" in again.stderr
    assert "WARNING" not in again.stderr


def test_an_operators_edited_config_is_never_overwritten_the_shipped_one_is_offered_beside_it(
    run: Runner, tree: Path, tmp_path: Path
) -> None:
    dest = tmp_path / "dest"
    binary = acf_host(tmp_path)
    assert install(run, tree, dest, binary).returncode == 0
    for name in ("host.yaml", "policy.yaml"):
        (dest / "etc/acf" / name).write_text(f"# edited by the operator: {name}\n")
    again = install(run, tree, dest, binary)
    assert again.returncode == 0, again.stderr
    assert (dest / "etc/acf/host.yaml").read_text() == "# edited by the operator: host.yaml\n"
    assert (dest / "etc/acf/policy.yaml").read_text() == "# edited by the operator: policy.yaml\n"
    assert (dest / "etc/acf/host.yaml.dist").read_bytes() == (tree / "config/host.example.yaml").read_bytes()
    assert (dest / "etc/acf/policy.yaml.dist").read_bytes() == (tree / "policies/default.yaml").read_bytes()
    assert "kept yours, wrote" in again.stderr


def test_force_config_replaces_the_operators_files_with_the_shipped_ones(
    run: Runner, tree: Path, tmp_path: Path
) -> None:
    dest = tmp_path / "dest"
    binary = acf_host(tmp_path)
    assert install(run, tree, dest, binary).returncode == 0
    (dest / "etc/acf/host.yaml").write_text("# edited\n")
    assert install(run, tree, dest, binary, "--force-config").returncode == 0
    assert (dest / "etc/acf/host.yaml").read_bytes() == (tree / "config/host.example.yaml").read_bytes()


def test_an_upgrade_replaces_the_binary_atomically_and_leaves_state_alone(
    run: Runner, tree: Path, tmp_path: Path
) -> None:
    dest = tmp_path / "dest"
    assert install(run, tree, dest, acf_host(tmp_path)).returncode == 0
    (dest / "var/lib/acf/images").joinpath("keep-me").write_text("an installed image would be here")
    (dest / "var/lib/acf/wal").write_text("state")
    newer = acf_host(tmp_path, extra=b"# a newer build\n")
    assert install(run, tree, dest, newer).returncode == 0
    assert (dest / "opt/acf/bin/acf-host").read_bytes() == newer.read_bytes()
    assert (dest / "var/lib/acf/images/keep-me").read_text() == "an installed image would be here"
    assert (dest / "var/lib/acf/wal").read_text() == "state"


@pytest.mark.parametrize("sentinel", ["fake-profile", "AfterBackendMutationBeforeCommit"])
def test_a_binary_with_test_only_code_is_refused_before_anything_is_installed(
    run: Runner, tree: Path, tmp_path: Path, sentinel: str
) -> None:
    dest = tmp_path / "dest"
    result = install(run, tree, dest, acf_host(tmp_path, extra=sentinel.encode()))
    assert result.returncode == 1
    assert "contains test-only code" in result.stderr
    assert not dest.exists() or list(dest.rglob("*")) == [], "a refused binary must leave the machine untouched"


def test_a_missing_or_non_executable_binary_is_refused_with_the_way_to_build_it(
    run: Runner, tree: Path, tmp_path: Path
) -> None:
    missing = install(run, tree, tmp_path / "dest", tmp_path / "absent")
    assert missing.returncode == 1
    assert "no acf-host binary at" in missing.stderr
    assert "make release" in missing.stderr
    plain = tmp_path / "plain"
    plain.write_text("not executable")
    assert install(run, tree, tmp_path / "dest", plain).returncode == 1


def test_no_systemd_skips_the_units_but_installs_the_rest(run: Runner, tree: Path, tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    assert install(run, tree, dest, acf_host(tmp_path), "--no-systemd").returncode == 0
    assert (dest / "opt/acf/bin/acf-host").is_file()
    assert not (dest / "etc/systemd").exists()
    assert not (dest / "etc/tmpfiles.d").exists()


def test_prefix_and_state_root_are_honoured_and_reflected_in_the_next_steps(
    run: Runner, tree: Path, tmp_path: Path
) -> None:
    dest = tmp_path / "dest"
    result = install(
        run, tree, dest, acf_host(tmp_path), "--prefix", "/usr/local/acf", "--state-root", "/srv/acf-state"
    )
    assert result.returncode == 0, result.stderr
    assert (dest / "usr/local/acf/bin/acf-host").is_file()
    assert (dest / "usr/local/acf/libexec/acf-setup-cgroup").is_file()
    assert mode(dest / "srv/acf-state") == 0o700
    assert mode(dest / "srv/acf-state/images") == 0o755
    assert "/usr/local/acf/bin/acf-host doctor" in result.stderr
    assert not (dest / "opt").exists()


@pytest.mark.parametrize(
    "extra",
    [
        ["--prefix", "relative/dir"],
        ["--state-root", "relative"],
        ["--destdir", "relative"],
        ["--bogus"],
    ],
)
def test_bad_arguments_are_usage_errors_and_touch_nothing(
    run: Runner, tree: Path, tmp_path: Path, extra: list[str]
) -> None:
    result = run(["bash", tree / "scripts/host-setup.sh", "install", "--acf-host", acf_host(tmp_path), *extra])
    assert result.returncode == 2, result.stderr
    assert not (tmp_path / "relative").exists()


def test_the_subcommands_and_their_exit_codes(run: Runner, tree: Path) -> None:
    script = tree / "scripts/host-setup.sh"
    assert run(["bash", script]).returncode == 2
    assert "Usage:" in run(["bash", script]).stderr
    unknown = run(["bash", script, "frobnicate"])
    assert unknown.returncode == 2
    assert "unknown command: frobnicate" in unknown.stderr
    for flag in ("--help", "-h", "help"):
        helped = run(["bash", script, flag])
        assert helped.returncode == 0
        assert "host-setup.sh install" in helped.stdout


def test_cgroup_hands_its_arguments_to_acf_setup_cgroup(run: Runner, tree: Path, tmp_path: Path) -> None:
    fake = tmp_path / "cgroup"
    fake.mkdir()
    (fake / "cgroup.controllers").write_text("cpuset cpu io memory pids\n")
    result = run(["bash", tree / "scripts/host-setup.sh", "cgroup", "mygroup"], env={"ACF_CGROUP_ROOT": str(fake)})
    assert result.returncode == 0, result.stderr
    assert (fake / "mygroup").is_dir()


@pytest.mark.skipif(
    Path("/opt/acf/bin/acf-host").exists(), reason="this machine has a real acf-host installed; `check` would run it"
)
def test_check_without_an_installed_agent_says_how_to_install_one(run: Runner, tree: Path) -> None:
    result = run(["bash", tree / "scripts/host-setup.sh", "check"])
    assert result.returncode == 1
    assert "acf-host is not installed" in result.stderr
    assert "host-setup.sh install" in result.stderr
