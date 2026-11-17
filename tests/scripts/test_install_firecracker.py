"""scripts/install-firecracker.sh — install the pinned Firecracker and jailer, trusting nothing by name.

No network: the "release" is a tarball the tests build (its two binaries are shell scripts that answer
``--version`` like the real ones), and the one test of the download path puts a stub ``curl`` first on PATH.

The properties that matter, each pinned below: an UNSET digest is exit 3 and installs nothing; the digest is
verified BEFORE anything is extracted; only the two binaries are extracted, by exact name; each must report exactly
the pinned version; installation is root-owned, 0755 and atomic.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

from acf_testkit import firecracker_tarball, host_machine

Runner = Callable[..., "subprocess.CompletedProcess[str]"]

ARCH = host_machine()
pytestmark = pytest.mark.skipif(not ARCH, reason="ACF supports x86_64 and aarch64 hosts only")

VERSION = "v1.17.0"
TARBALL_NAME = f"firecracker-{VERSION}-{ARCH}.tgz"
OTHER_ARCH = "aarch64" if ARCH == "x86_64" else "x86_64"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def set_lock(tree: Path, **values: str) -> None:
    lock = tree / "scripts/firecracker.lock"
    text = lock.read_text()
    for key, value in values.items():
        text, n = re.subn(rf"^{key}=.*$", f"{key}={value}", text, flags=re.MULTILINE)
        assert n == 1, key
    lock.write_text(text)


@pytest.fixture
def release(tmp_path: Path) -> Path:
    return firecracker_tarball(tmp_path / "release.tgz", version=VERSION, arch=ARCH)


def run_installer(
    run: Runner, tree: Path, *args: str | Path, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return run(["bash", tree / "scripts/install-firecracker.sh", *args], env=env)


def installed(dest: Path, prefix: str = "/opt/acf") -> list[Path]:
    bindir = dest / prefix.lstrip("/") / "bin"
    return sorted(bindir.glob("*")) if bindir.exists() else []


# ------------------------------------------------------------------------------------------ print-digest


def test_print_digest_prints_what_it_measured_and_installs_nothing(
    run: Runner, tree: Path, release: Path, tmp_path: Path
) -> None:
    result = run_installer(run, tree, "--print-digest", "--from-tarball", release, "--destdir", tmp_path / "dest")
    assert result.returncode == 0, result.stderr
    assert result.stdout == f"{sha256(release)}  {TARBALL_NAME}\n"
    assert "compare this with" in result.stderr
    assert not (tmp_path / "dest").exists()


def test_the_download_is_https_only_tls_1_2_bounded_and_aims_at_the_pinned_release(
    run: Runner, tree: Path, release: Path, tmp_path: Path
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "curl.log"
    curl = bin_dir / "curl"
    curl.write_text(
        "#!/bin/sh\n"
        f'echo "$*" >>"{log}"\n'
        'out=""\n'
        'while [ $# -gt 0 ]; do case "$1" in --output) out=$2; shift 2 ;; *) shift ;; esac; done\n'
        f'cp "{release}" "$out"\n'
    )
    curl.chmod(0o755)
    result = run_installer(
        run, tree, "--print-digest", env={"PATH": f"{bin_dir}:{os.environ.get('PATH', '/usr/bin:/bin')}"}
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == f"{sha256(release)}  {TARBALL_NAME}\n"
    (call,) = log.read_text().splitlines()
    for flag in ("--fail", "--proto =https", "--tlsv1.2", "--retry 3", f"--max-filesize {256 * 1024 * 1024}"):
        assert flag in call, f"{flag!r} missing from: {call}"
    assert call.endswith(
        f"-- https://github.com/firecracker-microvm/firecracker/releases/download/{VERSION}/{TARBALL_NAME}"
    )


def test_a_failed_download_is_an_error_that_suggests_the_offline_route(run: Runner, tree: Path, tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    curl = bin_dir / "curl"
    curl.write_text("#!/bin/sh\nexit 22\n")
    curl.chmod(0o755)
    result = run_installer(
        run, tree, "--print-digest", env={"PATH": f"{bin_dir}:{os.environ.get('PATH', '/usr/bin:/bin')}"}
    )
    assert result.returncode == 1
    assert "download failed" in result.stderr
    assert "--from-tarball" in result.stderr


# ------------------------------------------------------------------------------------------- installing


@pytest.mark.needs_root
def test_an_unset_digest_stops_with_exit_3_names_the_measured_digest_and_installs_nothing(
    run: Runner, tree: Path, release: Path, tmp_path: Path
) -> None:
    set_lock(tree, **{f"SHA256_{OTHER_ARCH}": "ab" * 32})  # a pin for ANOTHER architecture must not count
    result = run_installer(run, tree, "--from-tarball", release, "--destdir", tmp_path / "dest")
    assert result.returncode == 3, result.stderr
    assert f"NOT PINNED: SHA256_{ARCH} is UNSET" in result.stderr
    assert sha256(release) in result.stderr, "the message must give the digest it measured, to compare out-of-band"
    assert "Refusing to install an unverified root-executed binary" in result.stderr
    assert installed(tmp_path / "dest") == []


@pytest.mark.needs_root
def test_a_matching_digest_in_the_lock_installs_both_binaries_root_owned_and_executable(
    run: Runner, tree: Path, release: Path, tmp_path: Path
) -> None:
    set_lock(tree, **{f"SHA256_{ARCH}": sha256(release)})
    dest = tmp_path / "dest"
    result = run_installer(run, tree, "--from-tarball", release, "--destdir", dest)
    assert result.returncode == 0, result.stderr
    assert "digest verified" in result.stderr
    assert [p.name for p in installed(dest)] == ["firecracker", "jailer"], (
        "only the two binaries — not the .debug member"
    )
    for p in installed(dest):
        st = p.stat()
        assert stat.S_IMODE(st.st_mode) == 0o755
        assert (st.st_uid, st.st_gid) == (0, 0)
    assert (
        subprocess.run(
            [str(dest / "opt/acf/bin/firecracker"), "--version"], capture_output=True, text=True, check=False
        ).stdout.strip()
        == f"Firecracker {VERSION}"
    )
    for d in (dest / "opt/acf", dest / "opt/acf/bin"):
        assert stat.S_IMODE(d.stat().st_mode) == 0o755
        assert (d.stat().st_uid, d.stat().st_gid) == (0, 0)


@pytest.mark.needs_root
def test_sha256_on_the_command_line_stands_in_for_the_lock_for_one_run_and_does_not_edit_it(
    run: Runner, tree: Path, release: Path, tmp_path: Path
) -> None:
    lock_before = (tree / "scripts/firecracker.lock").read_bytes()
    result = run_installer(
        run, tree, "--from-tarball", release, "--sha256", sha256(release), "--destdir", tmp_path / "dest"
    )
    assert result.returncode == 0, result.stderr
    assert len(installed(tmp_path / "dest")) == 2
    assert (tree / "scripts/firecracker.lock").read_bytes() == lock_before


@pytest.mark.needs_root
def test_a_digest_mismatch_extracts_and_installs_nothing(
    run: Runner, tree: Path, release: Path, tmp_path: Path
) -> None:
    set_lock(tree, **{f"SHA256_{ARCH}": "0" * 64})
    result = run_installer(run, tree, "--from-tarball", release, "--destdir", tmp_path / "dest")
    assert result.returncode == 1
    assert "sha256 mismatch" in result.stderr
    assert "Nothing was extracted or installed" in result.stderr
    assert installed(tmp_path / "dest") == []


@pytest.mark.needs_root
def test_the_command_line_digest_overrides_a_correct_lock_so_a_wrong_one_is_caught(
    run: Runner, tree: Path, release: Path, tmp_path: Path
) -> None:
    set_lock(tree, **{f"SHA256_{ARCH}": sha256(release)})
    result = run_installer(run, tree, "--from-tarball", release, "--sha256", "1" * 64, "--destdir", tmp_path / "dest")
    assert result.returncode == 1
    assert "sha256 mismatch" in result.stderr


@pytest.mark.needs_root
@pytest.mark.parametrize("which", ["firecracker", "jailer"])
def test_a_binary_that_reports_another_version_is_refused_before_it_is_installed(
    run: Runner, tree: Path, tmp_path: Path, which: str
) -> None:
    release = firecracker_tarball(
        tmp_path / "wrong.tgz",
        version=VERSION,
        arch=ARCH,
        firecracker_reports="Firecracker v1.16.1" if which == "firecracker" else None,
        jailer_reports="Jailer v1.16.1" if which == "jailer" else None,
    )
    result = run_installer(
        run, tree, "--from-tarball", release, "--sha256", sha256(release), "--destdir", tmp_path / "dest"
    )
    assert result.returncode == 1
    assert f"{which} reports" in result.stderr
    assert f"the pin is {VERSION}" in result.stderr
    assert installed(tmp_path / "dest") == []


@pytest.mark.needs_root
def test_a_release_archive_missing_the_jailer_is_refused(run: Runner, tree: Path, tmp_path: Path) -> None:
    release = firecracker_tarball(tmp_path / "nojailer.tgz", version=VERSION, arch=ARCH, omit_jailer=True)
    result = run_installer(
        run, tree, "--from-tarball", release, "--sha256", sha256(release), "--destdir", tmp_path / "dest"
    )
    assert result.returncode == 1
    assert "has no member" in result.stderr
    assert installed(tmp_path / "dest") == []


@pytest.mark.needs_root
def test_only_the_two_named_members_are_extracted_whatever_else_the_archive_carries(
    run: Runner, tree: Path, tmp_path: Path
) -> None:
    evil = {
        "../evil.txt": b"escape",
        "/tmp/acf-abs-evil": b"absolute",
        f"release-{VERSION}-{ARCH}/extra-tool": b"#!/bin/sh\n",
    }
    release = firecracker_tarball(tmp_path / "evil.tgz", version=VERSION, arch=ARCH, extra_members=evil)
    dest = tmp_path / "dest"
    result = run_installer(run, tree, "--from-tarball", release, "--sha256", sha256(release), "--destdir", dest)
    assert result.returncode == 0, result.stderr
    assert sorted(p.relative_to(dest).as_posix() for p in dest.rglob("*") if p.is_file()) == [
        "opt/acf/bin/firecracker",
        "opt/acf/bin/jailer",
    ]
    assert not (tmp_path / "evil.txt").exists()
    assert not Path("/tmp/acf-abs-evil").exists()


@pytest.mark.needs_root
def test_something_that_is_not_a_gzip_tarball_is_refused_even_with_a_matching_digest(
    run: Runner, tree: Path, tmp_path: Path
) -> None:
    junk = tmp_path / "junk.tgz"
    junk.write_bytes(b"this is not an archive\n")
    result = run_installer(run, tree, "--from-tarball", junk, "--sha256", sha256(junk), "--destdir", tmp_path / "dest")
    assert result.returncode == 1
    assert "not a readable gzip tarball" in result.stderr


@pytest.mark.needs_root
def test_installing_twice_replaces_the_binaries_and_leaves_no_temporaries(
    run: Runner, tree: Path, tmp_path: Path
) -> None:
    dest = tmp_path / "dest"
    first = firecracker_tarball(tmp_path / "a.tgz", version=VERSION, arch=ARCH)
    assert (
        run_installer(run, tree, "--from-tarball", first, "--sha256", sha256(first), "--destdir", dest).returncode == 0
    )
    second = firecracker_tarball(
        tmp_path / "b.tgz", version=VERSION, arch=ARCH, extra_members={f"release-{VERSION}-{ARCH}/README": b"x"}
    )
    again = run_installer(run, tree, "--from-tarball", second, "--sha256", sha256(second), "--destdir", dest)
    assert again.returncode == 0, again.stderr
    assert [p.name for p in installed(dest)] == ["firecracker", "jailer"]


@pytest.mark.needs_root
def test_prefix_is_honoured(run: Runner, tree: Path, release: Path, tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    result = run_installer(
        run,
        tree,
        "--from-tarball",
        release,
        "--sha256",
        sha256(release),
        "--prefix",
        "/usr/local/fc",
        "--destdir",
        dest,
    )
    assert result.returncode == 0, result.stderr
    assert [p.name for p in installed(dest, "/usr/local/fc")] == ["firecracker", "jailer"]
    assert installed(dest) == []


@pytest.mark.needs_root
def test_the_version_comes_from_the_lock_not_from_the_script(run: Runner, tree: Path, tmp_path: Path) -> None:
    set_lock(tree, VERSION="v1.17.1")
    release = firecracker_tarball(tmp_path / "next.tgz", version="v1.17.1", arch=ARCH)
    dest = tmp_path / "dest"
    result = run_installer(run, tree, "--from-tarball", release, "--sha256", sha256(release), "--destdir", dest)
    assert result.returncode == 0, result.stderr
    assert "v1.17.1" in result.stderr


# -------------------------------------------------------------------------------------------- bad input


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--bogus"], "unknown option"),
        (["--prefix", "relative"], "--prefix must be an absolute path"),
        (["--destdir", "relative"], "--destdir must be an absolute path"),
        (["--sha256", "ABC"], "--sha256 must be 64 lowercase hex characters"),
        (["--sha256", "A" * 64], "--sha256 must be 64 lowercase hex characters"),
    ],
)
def test_usage_errors_exit_2(run: Runner, tree: Path, args: list[str], message: str) -> None:
    result = run_installer(run, tree, *args)
    assert result.returncode == 2, result.stderr
    assert message in result.stderr


def test_a_malformed_version_in_the_lock_is_refused(run: Runner, tree: Path, release: Path) -> None:
    set_lock(tree, VERSION="1.17")
    result = run_installer(run, tree, "--print-digest", "--from-tarball", release)
    assert result.returncode == 1
    assert "VERSION must look like v1.17.0" in result.stderr


def test_a_tarball_path_that_does_not_exist_is_an_error(run: Runner, tree: Path, tmp_path: Path) -> None:
    result = run_installer(run, tree, "--print-digest", "--from-tarball", tmp_path / "absent.tgz")
    assert result.returncode == 1
    assert "not a file" in result.stderr


def test_help_goes_to_stdout(run: Runner, tree: Path) -> None:
    result = run_installer(run, tree, "--help")
    assert result.returncode == 0
    assert "Usage:" in result.stdout
    assert "--print-digest" in result.stdout
