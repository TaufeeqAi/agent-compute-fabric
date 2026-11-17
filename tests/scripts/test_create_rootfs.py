"""scripts/create-rootfs.sh — a filesystem tarball in, a small, bootable, growable ext4 image out.

The tarball is built here to look like a merged-/usr Debian guest image (``acf_testkit.rootfs_tarball``); the
script extracts it as root, checks the guest's requirements against the extracted tree, sizes and builds the
filesystem with the pinned ``mke2fs.conf``, and runs ``e2fsck``. The result is inspected with ``dumpe2fs`` and
``debugfs`` — no mount, no loop device, no guest binary is ever run.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

from acf_testkit import rootfs_tarball

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts/create-rootfs.sh"

Runner = Callable[..., "subprocess.CompletedProcess[str]"]

pytestmark = [
    pytest.mark.needs_root,
    pytest.mark.skipif(
        any(shutil.which(c) is None for c in ("mkfs.ext4", "e2fsck", "dumpe2fs", "debugfs", "resize2fs")),
        reason="needs e2fsprogs (mkfs.ext4, e2fsck, dumpe2fs, debugfs, resize2fs)",
    ),
]

REQUIREMENTS = [
    "--exec", "/sbin/init",
    "--exec", "/usr/local/sbin/acf-init",
    "--exec", "/usr/local/bin/acf-guest-agent",
    "--exec", "/sbin/resize2fs",
    "--exec", "/bin/mount",
    "--dir", "/workspace",
    "--dir", "/var/lib",
    "--owner", "/workspace=1000:1000",
]  # fmt: skip

# What mke2fs.conf asks for, and what must never appear: features a Firecracker guest kernel (5.10 and up) may not
# know. An unknown ro_compat feature mounts the root filesystem read-only.
EXPECTED_FEATURES = {
    "has_journal", "ext_attr", "resize_inode", "dir_index", "filetype", "extent", "64bit", "flex_bg",
    "sparse_super", "large_file", "huge_file", "dir_nlink", "extra_isize", "metadata_csum",
}  # fmt: skip
FORBIDDEN_FEATURES = {
    "orphan_file",
    "ea_inode",
    "encrypt",
    "casefold",
    "large_dir",
    "stable_inodes",
    "verity",
    "project",
    "quota",
    "mmp",
}


def build(
    run: Runner, tar: Path, out: Path, *extra: str, requirements: bool = True
) -> subprocess.CompletedProcess[str]:
    args = [
        "bash",
        SCRIPT,
        "--tar",
        tar,
        "--out",
        out,
        "--slack-mib",
        "8",
        *(REQUIREMENTS if requirements else []),
        *extra,
    ]
    return run(args)


def dumpe2fs(image: Path) -> dict[str, str]:
    out = subprocess.run(["dumpe2fs", "-h", str(image)], capture_output=True, text=True, check=True).stdout
    return {k.strip(): v.strip() for k, _, v in (line.partition(":") for line in out.splitlines()) if v}


def debugfs(image: Path, command: str) -> str:
    done = subprocess.run(["debugfs", "-R", command, str(image)], capture_output=True, text=True, check=False)
    return done.stdout  # the banner ("debugfs 1.47.0") is on stderr


@pytest.fixture
def image(run: Runner, tmp_path: Path) -> Path:
    tar = rootfs_tarball(
        tmp_path / "rootfs.tar",
        dockerenv=True,
        owned_files={"srv/secret": (b"s3cret\n", 4242, 4343, 0o640), "usr/bin/su-like": (b"#!/bin/sh\n", 0, 0, 0o4755)},
    )
    out = tmp_path / "rootfs.ext4"
    result = build(run, tar, out)
    assert result.returncode == 0, result.stderr
    return out


# ------------------------------------------------------------------------------------------- the result


def test_the_image_is_a_clean_ext4_filesystem_with_exactly_the_pinned_features(image: Path) -> None:
    fsck = subprocess.run(["e2fsck", "-fn", str(image)], capture_output=True, text=True, check=False)
    assert fsck.returncode == 0, fsck.stdout + fsck.stderr
    info = dumpe2fs(image)
    features = set(info["Filesystem features"].split())
    assert features == EXPECTED_FEATURES
    assert not features & FORBIDDEN_FEATURES
    assert info["Block size"] == "4096"
    assert info["Filesystem volume name"] == "acf-rootfs"
    assert info["Reserved block count"] == "0"
    assert int(info["Reserved GDT blocks"]) > 0, (
        "resize_inode must reserve room for the guest to grow the filesystem online"
    )


def test_the_image_grows_to_a_much_larger_disk_the_way_the_guest_will_need_it_to(image: Path, tmp_path: Path) -> None:
    grown = tmp_path / "grown.ext4"
    shutil.copy(image, grown)
    before = int(dumpe2fs(grown)["Block count"])
    subprocess.run(["truncate", "-s", "2G", str(grown)], check=True)
    subprocess.run(
        ["e2fsck", "-fy", str(grown)], capture_output=True, check=False
    )  # resize2fs insists on a recent check
    done = subprocess.run(["resize2fs", str(grown)], capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stderr
    after = int(dumpe2fs(grown)["Block count"])
    assert after >= 2 * 1024 * 1024 * 1024 // 4096 - 1024
    assert after > before * 10
    assert subprocess.run(["e2fsck", "-fn", str(grown)], capture_output=True, check=False).returncode == 0


def test_the_image_is_small_content_plus_slack_not_a_disk(run: Runner, tmp_path: Path) -> None:
    tar = rootfs_tarball(tmp_path / "rootfs.tar", padding_bytes=20 * 1024 * 1024)
    out = tmp_path / "rootfs.ext4"
    assert build(run, tar, out).returncode == 0
    size_mib = out.stat().st_size / (1024 * 1024)
    assert 30 <= size_mib <= 80, f"{size_mib:.0f} MiB for ~21 MiB of content and 8 MiB of slack"


def test_ownership_is_numeric_and_modes_survive_the_build(image: Path) -> None:
    secret = debugfs(image, "stat /srv/secret")
    assert re.search(r"User:\s+4242\s+Group:\s+4343", secret), secret
    assert re.search(r"Mode:\s+0*640\b", secret), secret
    workspace = debugfs(image, "stat /workspace")
    assert re.search(r"User:\s+1000\s+Group:\s+1000", workspace), workspace
    root = debugfs(image, "stat /")
    assert re.search(r"User:\s+0\s+Group:\s+0", root), root
    # The build preserves what the tarball says; stripping setuid bits is the Dockerfile's job, not this script's.
    assert re.search(r"Mode:\s+0*4755\b", debugfs(image, "stat /usr/bin/su-like"))


def test_the_tree_the_guest_needs_is_in_the_image(image: Path) -> None:
    listing = debugfs(image, "ls -l /")
    for name in ("dev", "proc", "sys", "run", "tmp", "usr", "workspace", "var", "etc"):
        assert re.search(rf"\s{name}\s*$", listing, re.MULTILINE), f"/{name} missing:\n{listing}"
    assert ".dockerenv" not in listing
    assert re.search(r"Mode:\s+0*1777\b", debugfs(image, "stat /tmp"))
    link = debugfs(image, "stat /usr/sbin/init")
    assert '"/usr/local/sbin/acf-init"' in link, link
    assert debugfs(image, "cat /usr/local/share/acf/clock-epoch").strip().splitlines()[-1] == "1700000000"


def test_a_long_label_is_cut_to_the_16_bytes_ext4_allows(run: Runner, tmp_path: Path) -> None:
    out = tmp_path / "rootfs.ext4"
    result = build(run, rootfs_tarball(tmp_path / "rootfs.tar"), out, "--label", "acf-a-very-long-label-indeed")
    assert result.returncode == 0, result.stderr
    assert dumpe2fs(out)["Filesystem volume name"] == "acf-a-very-long-"


def test_building_over_an_existing_image_replaces_it_and_leaves_nothing_behind(
    run: Runner, tmp_path: Path, clean_env: dict[str, str]
) -> None:
    out = tmp_path / "rootfs.ext4"
    out.write_bytes(b"an older image")
    assert build(run, rootfs_tarball(tmp_path / "rootfs.tar"), out).returncode == 0
    assert out.stat().st_size > 1024 * 1024
    assert sorted(p.name for p in tmp_path.iterdir() if p.name.startswith("rootfs.ext4")) == ["rootfs.ext4"], (
        "no *.tmp.PID left beside the output"
    )
    assert [p for p in Path(clean_env["TMPDIR"]).iterdir() if p.name.startswith("acf-rootfs.")] == [], (
        "the work directory must be removed"
    )


def test_the_requirement_checks_are_optional(run: Runner, tmp_path: Path) -> None:
    out = tmp_path / "rootfs.ext4"
    result = build(
        run, rootfs_tarball(tmp_path / "rootfs.tar", omit=["usr/local/bin/acf-guest-agent"]), out, requirements=False
    )
    assert result.returncode == 0, result.stderr


# ------------------------------------------------------------------------------------------- refusals


@pytest.mark.parametrize(
    ("omit", "workspace_owner", "message"),
    [
        (["usr/local/bin/acf-guest-agent"], (1000, 1000), "/usr/local/bin/acf-guest-agent"),
        (["usr/local/sbin/acf-init"], (1000, 1000), "/usr/local/sbin/acf-init"),
        (["usr/sbin/init"], (1000, 1000), "/sbin/init"),
        (["usr/sbin/resize2fs"], (1000, 1000), "/sbin/resize2fs"),
        (["workspace"], (1000, 1000), "/workspace"),
        ([], (0, 0), "owned by 0:0, expected 1000:1000"),
    ],
)
def test_an_image_that_would_not_boot_is_refused_naming_what_is_wrong_and_no_output_is_written(
    run: Runner,
    tmp_path: Path,
    clean_env: dict[str, str],
    omit: list[str],
    workspace_owner: tuple[int, int],
    message: str,
) -> None:
    out = tmp_path / "rootfs.ext4"
    result = build(run, rootfs_tarball(tmp_path / "rootfs.tar", omit=omit, workspace_owner=workspace_owner), out)
    assert result.returncode == 1
    assert message in result.stderr
    assert "does not meet the guest requirements" in result.stderr
    assert not out.exists()
    assert [p for p in tmp_path.iterdir() if ".tmp." in p.name] == []
    assert [p for p in Path(clean_env["TMPDIR"]).iterdir() if p.name.startswith("acf-rootfs.")] == []


def test_a_tarball_that_tries_to_write_outside_the_root_is_refused(run: Runner, tmp_path: Path) -> None:
    tar = rootfs_tarball(tmp_path / "rootfs.tar", extra_files={"../escape.txt": b"gotcha"})
    result = build(run, tar, tmp_path / "rootfs.ext4")
    assert result.returncode == 1
    assert "cannot extract" in result.stderr
    assert not (tmp_path / "escape.txt").exists()
    assert not (tmp_path / "tmp" / "escape.txt").exists()


def test_something_that_is_not_a_tarball_is_refused(run: Runner, tmp_path: Path) -> None:
    junk = tmp_path / "rootfs.tar"
    junk.write_bytes(b"definitely not a tar archive\n" * 100)
    result = build(run, junk, tmp_path / "rootfs.ext4")
    assert result.returncode == 1
    assert "cannot extract" in result.stderr


@pytest.mark.parametrize(
    ("args", "status", "message"),
    [
        ([], 2, "--tar and --out are required"),
        (["--tar", "x"], 2, "--tar and --out are required"),
        (["--out", "x"], 2, "--tar and --out are required"),
        (["--bogus"], 2, "unknown option"),
    ],
)
def test_usage_errors(run: Runner, args: list[str], status: int, message: str) -> None:
    result = run(["bash", SCRIPT, *args])
    assert result.returncode == status
    assert message in result.stderr


def test_a_slack_that_is_not_a_number_is_a_usage_error(run: Runner, tmp_path: Path) -> None:
    tar = rootfs_tarball(tmp_path / "rootfs.tar")
    result = run(["bash", SCRIPT, "--tar", tar, "--out", tmp_path / "o.ext4", "--slack-mib", "lots"])
    assert result.returncode == 2
    assert "--slack-mib must be a non-negative integer" in result.stderr


def test_a_missing_tarball_is_an_error(run: Runner, tmp_path: Path) -> None:
    result = run(["bash", SCRIPT, "--tar", tmp_path / "absent.tar", "--out", tmp_path / "o.ext4"])
    assert result.returncode == 1
    assert "not a file" in result.stderr


def test_help_goes_to_stdout(run: Runner) -> None:
    result = run(["bash", SCRIPT, "--help"])
    assert result.returncode == 0
    assert "Usage: create-rootfs.sh" in result.stdout
