"""scripts/pin-images.sh — resolve the base-image tags in images/images.lock to registry digests.

No registry: crane, skopeo and docker are stubs on PATH. They answer with a digest derived from the reference they
are asked about (so two images get two digests) and can be made to fail or to return garbage. What the real tools
return from a real registry is not exercised here; the arguments the script gives them are.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

Runner = Callable[..., "subprocess.CompletedProcess[str]"]

STUBS = {
    "crane": '#!/bin/sh\necho "crane $*" >>"$ACF_STUB_LOG"\n'
    '[ "$ACF_STUB_MODE" != fail ] || exit 1\n'
    '[ "$ACF_STUB_MODE" != garbage ] || { echo "not-a-digest"; exit 0; }\n'
    '[ "$1" = digest ] || exit 2\n'
    'printf "sha256:%s\\n" "$(printf %s "$2" | sha256sum | cut -d" " -f1)"\n',
    "skopeo": '#!/bin/sh\necho "skopeo $*" >>"$ACF_STUB_LOG"\n'
    '[ "$ACF_STUB_MODE" != fail ] || exit 1\n'
    "for last; do :; done\n"
    'printf "sha256:%s\\n" "$(printf %s "${last#docker://}" | sha256sum | cut -d" " -f1)"\n',
    "docker": '#!/bin/sh\necho "docker $*" >>"$ACF_STUB_LOG"\n'
    '[ "$ACF_STUB_MODE" != fail ] || exit 1\n'
    "for last; do :; done\n"
    'printf "manifest-bytes-of-%s" "$last"\n',
}


def digest_of_ref(ref: str) -> str:
    return "sha256:" + hashlib.sha256(ref.encode()).hexdigest()


def digest_of_manifest_bytes(ref: str) -> str:
    return "sha256:" + hashlib.sha256(f"manifest-bytes-of-{ref}".encode()).hexdigest()


@pytest.fixture
def pin(run: Runner, tree: Path, tmp_path: Path) -> Callable[..., subprocess.CompletedProcess[str]]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in STUBS.items():
        stub = bin_dir / name
        stub.write_text(body)
        stub.chmod(0o755)

    def _pin(
        *args: str | Path, tools: tuple[str, ...] = ("crane", "skopeo", "docker"), mode: str = ""
    ) -> subprocess.CompletedProcess[str]:
        # PATH holds the stubs for the chosen tools only, then the system's (which has none of the real three on CI).
        chosen = tmp_path / "chosen"
        chosen.mkdir(exist_ok=True)
        for name in STUBS:
            link = chosen / name
            if link.is_symlink():
                link.unlink()
            if name in tools:
                link.symlink_to(bin_dir / name)
        env = {
            "PATH": f"{chosen}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            "ACF_STUB_LOG": str(tmp_path / "calls.log"),
            "ACF_STUB_MODE": mode,
        }
        return run(["bash", tree / "scripts/pin-images.sh", *args], env=env)

    return _pin


def refs(tree: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in (tree / "images/images.lock").read_text().splitlines():
        m = re.fullmatch(r"BASE_REF_(\w+)=(\S+)", line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def digests(tree: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in (tree / "images/images.lock").read_text().splitlines():
        m = re.fullmatch(r"BASE_DIGEST_(\w+)=(\S+)", line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def calls(tmp_path: Path) -> list[str]:
    log = tmp_path / "calls.log"
    return log.read_text().splitlines() if log.exists() else []


# ------------------------------------------------------------------------------------------ printing


def test_the_default_mode_prints_one_digest_line_per_image_and_changes_nothing(
    pin: Callable[..., subprocess.CompletedProcess[str]], tree: Path
) -> None:
    before = (tree / "images/images.lock").read_bytes()
    result = pin()
    assert result.returncode == 0, result.stderr
    expected = [f"BASE_DIGEST_{name}={digest_of_ref(ref)}" for name, ref in refs(tree).items()]
    assert result.stdout.splitlines() == expected
    assert len(expected) == 4
    assert (tree / "images/images.lock").read_bytes() == before


def test_the_digest_is_asked_for_by_the_tag_in_the_lock(
    pin: Callable[..., subprocess.CompletedProcess[str]], tree: Path, tmp_path: Path
) -> None:
    pin("--only", "python")
    assert calls(tmp_path) == [f"crane digest {refs(tree)['python']}"]


def test_only_limits_the_work_to_one_image(pin: Callable[..., subprocess.CompletedProcess[str]], tree: Path) -> None:
    result = pin("--only", "node")
    assert result.stdout.splitlines() == [f"BASE_DIGEST_node={digest_of_ref(refs(tree)['node'])}"]


def test_only_with_an_unknown_name_is_an_error(pin: Callable[..., subprocess.CompletedProcess[str]]) -> None:
    result = pin("--only", "nope")
    assert result.returncode == 1
    assert "no BASE_REF_* entries for nope" in result.stderr


# -------------------------------------------------------------------------------------------- writing


def test_write_updates_only_the_digest_lines_and_keeps_comments_order_and_mode(
    pin: Callable[..., subprocess.CompletedProcess[str]], tree: Path
) -> None:
    lock = tree / "images/images.lock"
    lock.chmod(0o640)
    before = lock.read_text().splitlines()
    result = pin("--write")
    assert result.returncode == 0, result.stderr
    after = lock.read_text().splitlines()
    assert len(after) == len(before)
    changed = [(b, a) for b, a in zip(before, after, strict=True) if b != a]
    assert len(changed) == 4
    for old, new in changed:
        assert old.startswith("BASE_DIGEST_")
        assert old.endswith("=UNSET")
        assert new.startswith("BASE_DIGEST_")
        assert new.split("=", 1)[1].startswith("sha256:")
    assert digests(tree) == {name: digest_of_ref(ref) for name, ref in refs(tree).items()}
    assert [line for line in after if line.startswith("#")] == [line for line in before if line.startswith("#")]
    assert [line for line in after if line.startswith("KERNEL_SHA256_")] == [
        line for line in before if line.startswith("KERNEL_SHA256_")
    ]
    assert stat.S_IMODE(lock.stat().st_mode) == 0o640
    assert "updated" in result.stderr
    assert [p.name for p in lock.parent.iterdir() if p.name.startswith("images.lock.")] == [], (
        "no temporary file left behind"
    )


def test_write_with_only_touches_one_line(pin: Callable[..., subprocess.CompletedProcess[str]], tree: Path) -> None:
    pin("--write", "--only", "python")
    got = digests(tree)
    assert got["python"] == digest_of_ref(refs(tree)["python"])
    assert {k: v for k, v in got.items() if k != "python"} == {"base": "UNSET", "node": "UNSET", "browser": "UNSET"}


def test_write_is_idempotent(pin: Callable[..., subprocess.CompletedProcess[str]], tree: Path) -> None:
    pin("--write")
    once = (tree / "images/images.lock").read_bytes()
    assert pin("--write").returncode == 0
    assert (tree / "images/images.lock").read_bytes() == once


def test_a_custom_lock_file_can_be_named(
    pin: Callable[..., subprocess.CompletedProcess[str]], tree: Path, tmp_path: Path
) -> None:
    custom = tmp_path / "other.lock"
    custom.write_text("# mine\nBASE_REF_x=example.com/x:1\nBASE_DIGEST_x=UNSET\n")
    result = pin("--write", "--lock", custom)
    assert result.returncode == 0, result.stderr
    assert (
        custom.read_text() == f"# mine\nBASE_REF_x=example.com/x:1\nBASE_DIGEST_x={digest_of_ref('example.com/x:1')}\n"
    )


def test_write_fails_when_a_digest_line_is_missing_from_the_lock_and_changes_nothing(
    pin: Callable[..., subprocess.CompletedProcess[str]], tree: Path, tmp_path: Path
) -> None:
    custom = tmp_path / "broken.lock"
    custom.write_text("BASE_REF_x=example.com/x:1\n")  # no BASE_DIGEST_x line to rewrite
    result = pin("--write", "--lock", custom)
    assert result.returncode == 1
    assert "key not found: BASE_DIGEST_x" in result.stderr
    assert custom.read_text() == "BASE_REF_x=example.com/x:1\n"
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith("broken.lock.")] == []


# -------------------------------------------------------------------------------------------- verifying


def test_verify_reports_every_unset_pin_as_drift_and_exits_1(
    pin: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    result = pin("--verify")
    assert result.returncode == 1
    assert result.stderr.count("DRIFT") == 4
    assert "pinned=<none>" in result.stderr or "pinned=UNSET" in result.stderr


def test_verify_passes_right_after_write(pin: Callable[..., subprocess.CompletedProcess[str]]) -> None:
    pin("--write")
    result = pin("--verify")
    assert result.returncode == 0, result.stderr
    assert result.stderr.count("ok ") == 4
    assert "DRIFT" not in result.stderr


def test_verify_detects_a_tag_that_moved(pin: Callable[..., subprocess.CompletedProcess[str]], tree: Path) -> None:
    pin("--write")
    lock = tree / "images/images.lock"
    text = lock.read_text().replace(digests(tree)["node"], "sha256:" + "0" * 64)
    lock.write_text(text)
    result = pin("--verify")
    assert result.returncode == 1
    assert result.stderr.count("DRIFT") == 1
    assert "node" in result.stderr.split("DRIFT")[1]
    assert digests(tree)["node"] == "sha256:" + "0" * 64, "verify never edits the lock"


# ---------------------------------------------------------------------------------------- the registry tools


def test_skopeo_is_used_when_crane_is_absent_and_gets_the_docker_transport(
    pin: Callable[..., subprocess.CompletedProcess[str]], tree: Path, tmp_path: Path
) -> None:
    result = pin("--only", "python", tools=("skopeo", "docker"))
    assert result.returncode == 0, result.stderr
    ref = refs(tree)["python"]
    assert calls(tmp_path) == [f"skopeo inspect --no-tags --format {{{{.Digest}}}} docker://{ref}"]
    assert result.stdout.strip() == f"BASE_DIGEST_python={digest_of_ref(ref)}"


def test_docker_hashes_the_exact_manifest_bytes_the_registry_returned(
    pin: Callable[..., subprocess.CompletedProcess[str]], tree: Path, tmp_path: Path
) -> None:
    result = pin("--only", "python", tools=("docker",))
    assert result.returncode == 0, result.stderr
    ref = refs(tree)["python"]
    assert calls(tmp_path) == [f"docker buildx imagetools inspect --raw {ref}"]
    assert result.stdout.strip() == f"BASE_DIGEST_python={digest_of_manifest_bytes(ref)}"


def test_the_tool_can_be_chosen_explicitly(
    pin: Callable[..., subprocess.CompletedProcess[str]], tmp_path: Path
) -> None:
    pin("--only", "python", "--tool", "skopeo")
    assert calls(tmp_path)[0].startswith("skopeo ")


def test_naming_a_tool_that_is_not_installed_is_an_error(pin: Callable[..., subprocess.CompletedProcess[str]]) -> None:
    result = pin("--tool", "crane", tools=("skopeo",))
    assert result.returncode == 1
    assert "required command not found: crane" in result.stderr


def test_no_registry_tool_at_all_is_an_error_that_names_the_choices(run: Runner, tree: Path, tmp_path: Path) -> None:
    sandbox = tmp_path / "only-basics"
    sandbox.mkdir()
    for name in ("dirname", "tr", "wc", "cat", "mktemp", "chmod", "mv", "rm", "sha256sum", "cut"):
        found = subprocess.run(["which", name], capture_output=True, text=True, check=False).stdout.strip()
        if found:
            (sandbox / name).symlink_to(found)
    result = run([shutil.which("bash") or "bash", tree / "scripts/pin-images.sh"], env={"PATH": str(sandbox)})
    assert result.returncode == 1
    assert "need one of crane, skopeo or docker" in result.stderr


@pytest.mark.parametrize("mode", ["fail", "garbage"])
def test_a_tag_that_cannot_be_resolved_or_a_reply_that_is_not_a_digest_is_an_error(
    pin: Callable[..., subprocess.CompletedProcess[str]], tree: Path, mode: str
) -> None:
    result = pin("--write", mode=mode, tools=("crane",))
    assert result.returncode == 1
    if mode == "fail":
        assert "could not resolve" in result.stderr
    else:
        assert "returned something that is not a digest" in result.stderr
    assert set(digests(tree).values()) == {"UNSET"}, "a failure must not leave a half-written lock"


# ------------------------------------------------------------------------------------------------ usage


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--write", "--verify"], "mutually exclusive"),
        (["--bogus"], "unknown option"),
    ],
)
def test_usage_errors_exit_2(
    pin: Callable[..., subprocess.CompletedProcess[str]], args: list[str], message: str
) -> None:
    result = pin(*args)
    assert result.returncode == 2
    assert message in result.stderr


def test_help_goes_to_stdout(pin: Callable[..., subprocess.CompletedProcess[str]]) -> None:
    result = pin("--help")
    assert result.returncode == 0
    assert "Usage: pin-images.sh" in result.stdout
