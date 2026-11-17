"""tools/rootfs_check.py: judge an extracted root filesystem as the guest kernel would see it, not the build host."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import rootfs_check as rc


def mkexec(path: Path, mode: int = 0o755) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n")
    path.chmod(mode)


@pytest.fixture
def debian_like(tmp_path: Path) -> Path:
    """The shape a Debian image really has: merged-usr links and an absolute /usr/sbin/init link."""
    root = tmp_path / "root"
    (root / "usr" / "sbin").mkdir(parents=True)
    (root / "usr" / "bin").mkdir(parents=True)
    (root / "sbin").symlink_to("usr/sbin")  # relative, as dpkg's usrmerge makes them
    (root / "bin").symlink_to("usr/bin")
    mkexec(root / "usr" / "local" / "sbin" / "acf-init")
    (root / "usr" / "sbin" / "init").symlink_to("/usr/local/sbin/acf-init")  # ABSOLUTE
    mkexec(root / "usr" / "local" / "bin" / "acf-guest-agent")
    (root / "workspace").mkdir()
    return root


def test_absolute_symlinks_are_re_rooted_not_followed_into_the_build_host(debian_like: Path) -> None:
    assert rc.resolve_in_root(debian_like, "/sbin/init") == debian_like / "usr" / "local" / "sbin" / "acf-init"
    assert rc.check_executable(debian_like, "/sbin/init") == "/usr/local/sbin/acf-init"


def test_a_link_to_a_path_that_exists_only_on_the_host_is_a_failure(debian_like: Path) -> None:
    # /bin/sh exists on the machine running this test, but not inside the image: the guest would not find it.
    (debian_like / "usr" / "sbin" / "broken").symlink_to("/bin/sh")
    assert Path("/bin/sh").exists()
    with pytest.raises(rc.RootfsCheckError, match="does not exist"):
        rc.check_executable(debian_like, "/sbin/broken")


def test_dotdot_cannot_climb_out_of_the_root(debian_like: Path) -> None:
    (debian_like / "usr" / "evil").symlink_to("../../../../../../../../etc")
    resolved = rc.resolve_in_root(debian_like, "/usr/evil/passwd")
    assert resolved == debian_like / "etc" / "passwd"
    assert debian_like in resolved.parents


def test_relative_links_resolve_from_their_own_directory(debian_like: Path) -> None:
    (debian_like / "usr" / "bin" / "agent").symlink_to("../local/bin/acf-guest-agent")
    assert rc.check_executable(debian_like, "/bin/agent") == "/usr/local/bin/acf-guest-agent"


def test_symlink_loops_are_reported_not_followed_forever(debian_like: Path) -> None:
    (debian_like / "usr" / "a").symlink_to("b")
    (debian_like / "usr" / "b").symlink_to("a")
    with pytest.raises(rc.RootfsCheckError, match="too many levels"):
        rc.resolve_in_root(debian_like, "/usr/a")


def test_a_guest_path_must_be_absolute(debian_like: Path) -> None:
    with pytest.raises(rc.RootfsCheckError, match="not an absolute"):
        rc.resolve_in_root(debian_like, "usr/sbin/init")


def test_executable_checks(debian_like: Path) -> None:
    mkexec(debian_like / "usr" / "bin" / "not-exec", mode=0o644)
    with pytest.raises(rc.RootfsCheckError, match="not executable"):
        rc.check_executable(debian_like, "/usr/bin/not-exec")
    with pytest.raises(rc.RootfsCheckError, match="not a regular file"):
        rc.check_executable(debian_like, "/usr/bin")
    with pytest.raises(rc.RootfsCheckError, match="does not exist"):
        rc.check_executable(debian_like, "/usr/bin/absent")


def test_directory_checks(debian_like: Path) -> None:
    assert rc.check_dir(debian_like, "/workspace") == "/workspace"
    with pytest.raises(rc.RootfsCheckError, match="not a directory"):
        rc.check_dir(debian_like, "/var/lib")
    with pytest.raises(rc.RootfsCheckError, match="not a directory"):
        rc.check_dir(debian_like, "/usr/local/bin/acf-guest-agent")


def test_ownership_checks(debian_like: Path) -> None:
    st = (debian_like / "workspace").stat()
    assert rc.check_owner(debian_like, f"/workspace={st.st_uid}:{st.st_gid}") == f"/workspace {st.st_uid}:{st.st_gid}"
    with pytest.raises(rc.RootfsCheckError, match="owned by"):
        rc.check_owner(debian_like, f"/workspace={st.st_uid + 1}:{st.st_gid}")
    with pytest.raises(rc.RootfsCheckError, match="does not exist"):
        rc.check_owner(debian_like, "/nope=0:0")
    for bad in ("/workspace", "/workspace=1000", "/workspace=a:b", "=1:1"):
        with pytest.raises(rc.RootfsCheckError, match="bad --owner"):
            rc.check_owner(debian_like, bad)


def test_main_lists_every_failure_and_exits_one(debian_like: Path, capsys: pytest.CaptureFixture[str]) -> None:
    st = os.stat(debian_like / "workspace")
    args = [
        "--root", str(debian_like),
        "--exec", "/sbin/init",
        "--exec", "/usr/bin/missing-one",
        "--dir", "/workspace",
        "--dir", "/missing-dir",
        "--owner", f"/workspace={st.st_uid}:{st.st_gid}",
    ]  # fmt: skip
    assert rc.main(args) == 1
    err = capsys.readouterr().err
    assert "ok   /sbin/init -> /usr/local/sbin/acf-init" in err
    assert "FAIL /usr/bin/missing-one: does not exist" in err
    assert "FAIL /missing-dir: is not a directory" in err
    assert err.count("FAIL") == 2


def test_main_quiet_prints_only_failures_and_zero_means_all_hold(
    debian_like: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert rc.main(["--root", str(debian_like), "--quiet", "--exec", "/sbin/init", "--dir", "/workspace"]) == 0
    assert capsys.readouterr().err == ""


def test_main_usage_error_when_root_is_not_a_directory(tmp_path: Path) -> None:
    assert rc.main(["--root", str(tmp_path / "nope"), "--exec", "/sbin/init"]) == 2
