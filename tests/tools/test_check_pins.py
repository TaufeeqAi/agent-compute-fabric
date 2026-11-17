"""tools/check_pins.py: the three pin files (firecracker.lock, host.example.yaml, images.lock) must agree."""

from __future__ import annotations

from pathlib import Path

import pytest

import check_pins

SHA = "a" * 64
OCI = "sha256:" + "b" * 64


def _write_pinned_locks(tree: Path) -> None:
    """Replace every UNSET in the copied locks with a well-formed digest."""
    for rel in ("scripts/firecracker.lock", "images/images.lock"):
        p = tree / rel
        out = []
        for raw in p.read_text().splitlines():
            key, sep, value = raw.partition("=")
            if sep and value == "UNSET":
                value = OCI if key.startswith("BASE_DIGEST_") else SHA
                out.append(f"{key}={value}")
            else:
                out.append(raw)
        p.write_text("\n".join(out) + "\n")


def test_the_shipped_pins_are_consistent_even_though_digests_are_unset(repo: Path) -> None:
    assert check_pins.check(repo, require_pinned=False) == []


def test_the_release_gate_names_every_unset_input(repo: Path) -> None:
    problems = "\n".join(check_pins.check(repo, require_pinned=True))
    assert "SHA256_x86_64 is UNSET" in problems
    assert "SHA256_aarch64 is UNSET" in problems
    assert "BASE_DIGEST_python is UNSET" in problems
    assert "KERNEL_SHA256_x86_64 is UNSET" in problems


def test_a_fully_pinned_tree_passes_the_release_gate(tree: Path) -> None:
    _write_pinned_locks(tree)
    assert check_pins.check(tree, require_pinned=True) == []


def test_version_drift_between_the_lock_and_the_host_config_is_reported(tree: Path) -> None:
    cfg = tree / "config" / "host.example.yaml"
    cfg.write_text(cfg.read_text().replace("pinned_version: v1.17.0", "pinned_version: v1.16.1"))
    problems = check_pins.check(tree, require_pinned=False)
    assert any("firecracker version drift" in p and "v1.16.1" in p for p in problems), problems


def test_a_version_that_is_not_a_release_tag_is_reported(tree: Path) -> None:
    lock = tree / "scripts" / "firecracker.lock"
    lock.write_text(lock.read_text().replace("VERSION=v1.17.0", "VERSION=latest"))
    assert any("must look like v1.17.0" in p for p in check_pins.check(tree, require_pinned=False))


@pytest.mark.parametrize(
    "bad",
    [
        "BASE_DIGEST_base=sha256:XYZ",  # not hex
        "BASE_DIGEST_base=" + "c" * 64,  # missing the sha256: prefix
        "BASE_DIGEST_base=sha256:" + "c" * 63,  # too short
    ],
)
def test_a_malformed_base_digest_is_reported(tree: Path, bad: str) -> None:
    lock = tree / "images" / "images.lock"
    lock.write_text(lock.read_text().replace("BASE_DIGEST_base=UNSET", bad))
    assert any(
        "BASE_DIGEST_base" in p and "not a valid digest" in p for p in check_pins.check(tree, require_pinned=False)
    )


def test_a_base_ref_that_already_carries_a_digest_is_reported(tree: Path) -> None:
    lock = tree / "images" / "images.lock"
    lock.write_text(lock.read_text().replace("debian:trixie-slim", "debian:trixie-slim@" + OCI))
    assert any("must be a tag" in p for p in check_pins.check(tree, require_pinned=False))


def test_a_recipe_without_a_lock_entry_and_a_lock_entry_without_a_recipe_are_both_reported(tree: Path) -> None:
    (tree / "images" / "extra").mkdir()
    (tree / "images" / "extra" / "Dockerfile").write_text("ARG BASE_REF\nFROM ${BASE_REF}\n")
    (tree / "images" / "node" / "Dockerfile").unlink()
    problems = "\n".join(check_pins.check(tree, require_pinned=False))
    assert "images/extra/Dockerfile has no BASE_REF_extra" in problems
    assert "BASE_REF_node has no images/node/Dockerfile" in problems


def test_a_missing_architecture_is_reported(tree: Path) -> None:
    lock = tree / "images" / "images.lock"
    lock.write_text("\n".join(ln for ln in lock.read_text().splitlines() if "KERNEL_SHA256_aarch64" not in ln) + "\n")
    assert any("missing KERNEL_SHA256_aarch64" in p for p in check_pins.check(tree, require_pinned=False))


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("VERSION v1.17.0\n", "malformed line"),
        ("VERSION=v1.17.0\nVERSION=v1.17.1\n", "duplicate key VERSION"),
        ("VERSION=$(id)\n", "outside"),
        ("VERSION='v1.17.0'\n", "outside"),
        ("1BAD-KEY=x\n", "malformed line"),
    ],
)
def test_the_lock_grammar_is_strict(tmp_path: Path, content: str, message: str) -> None:
    f = tmp_path / "x.lock"
    f.write_text(content)
    with pytest.raises(check_pins.PinError, match=message):
        check_pins.read_lock(f)


def test_comments_and_blank_lines_are_ignored(tmp_path: Path) -> None:
    f = tmp_path / "x.lock"
    f.write_text("# a comment\n\nA=1  # trailing\n   B=2\n")
    assert check_pins.read_lock(f) == {"A": "1", "B": "2"}


def test_exit_codes(repo: Path, tree: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert check_pins.main(["--root", str(repo)]) == 0
    assert check_pins.main(["--root", str(repo), "--require-pinned"]) == 1
    (tree / "scripts" / "firecracker.lock").write_text("garbage\n")
    assert check_pins.main(["--root", str(tree)]) == 2
    assert "malformed line" in capsys.readouterr().err
