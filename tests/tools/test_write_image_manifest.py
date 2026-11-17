"""tools/write_image_manifest.py: the Python writer of the manifest that the Rust host agent reads and verifies."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

import write_image_manifest as wim

GOLDEN = Path(__file__).resolve().parent.parent / "fixtures" / "image-manifest.golden.json"
SCHEMA = Path(__file__).resolve().parent.parent.parent / "schemas" / "image-manifest.schema.json"
KERNEL = b"golden-kernel\n"
ROOTFS = b"golden-rootfs\n"
PROVENANCE = "acf-image-build/1; image=golden; fixture for the Python <-> Rust manifest contract test"


@pytest.fixture
def image(tmp_path: Path) -> Path:
    d = tmp_path / "golden"
    d.mkdir()
    (d / "vmlinux").write_bytes(KERNEL)
    (d / "rootfs.ext4").write_bytes(ROOTFS)
    return d


def golden_manifest(image: Path) -> dict[str, Any]:
    return wim.build_manifest(
        image, name="golden", architecture="x86_64", guest_agent_version="0.1.0", provenance=PROVENANCE
    )


# --------------------------------------------------------------------------- the cross-language contract


def test_the_output_matches_the_committed_golden_file_byte_for_byte(image: Path) -> None:
    produced = wim.render(golden_manifest(image))
    if os.environ.get("ACF_UPDATE_GOLDEN") == "1":
        GOLDEN.write_bytes(produced)
    assert produced == GOLDEN.read_bytes(), (
        "the manifest writer's output changed. If that is intended, the Rust reader (filesystem/images.rs, test "
        "`the_python_writers_golden_manifest_is_accepted`) must still accept it; regenerate with ACF_UPDATE_GOLDEN=1."
    )


def test_the_golden_file_binds_exactly_the_fixture_bytes() -> None:
    m = json.loads(GOLDEN.read_bytes())
    assert m["kernel"] == {"file": "vmlinux", "sha256": hashlib.sha256(KERNEL).hexdigest(), "size": len(KERNEL)}
    assert m["rootfs"] == {"file": "rootfs.ext4", "sha256": hashlib.sha256(ROOTFS).hexdigest(), "size": len(ROOTFS)}


def test_the_output_validates_against_the_schema_the_host_publishes(image: Path) -> None:
    validator = Draft202012Validator(json.loads(SCHEMA.read_text()))
    validator.validate(json.loads(wim.render(golden_manifest(image))))


def test_the_schema_has_teeth(image: Path) -> None:
    validator = Draft202012Validator(json.loads(SCHEMA.read_text()))
    good = json.loads(wim.render(golden_manifest(image)))
    assert not validator.is_valid({**good, "surprise": 1})  # additionalProperties: false, as deny_unknown_fields
    assert not validator.is_valid({k: v for k, v in good.items() if k != "kernel"})


def test_the_output_is_deterministic_and_newline_terminated(image: Path) -> None:
    a, b = wim.render(golden_manifest(image)), wim.render(golden_manifest(image))
    assert a == b
    assert a.endswith(b"}\n")
    assert list(json.loads(a)) == [
        "schema_version", "name", "architecture", "kernel", "rootfs", "boot_args", "guest_agent_version", "provenance",
    ]  # fmt: skip


def test_non_ascii_provenance_is_written_as_utf8(image: Path) -> None:
    m = wim.build_manifest(
        image, name="golden", architecture="aarch64", guest_agent_version="0.1.0", provenance="café ✓"
    )
    assert "café ✓".encode() in wim.render(m)


# --------------------------------------------------------------------------------------- input validation


@pytest.mark.parametrize("name", ["", ".hidden", "a/b", "a b", "x" * 64, "é", "a\n"])
def test_bad_image_names_are_refused(image: Path, name: str) -> None:
    with pytest.raises(wim.ManifestError, match="image name"):
        wim.build_manifest(image, name=name, architecture="x86_64", guest_agent_version="0.1.0")


@pytest.mark.parametrize("name", ["python", "node-24", "a", "x" * 63, "py_3.14", "_x", "-x"])
def test_the_names_the_host_accepts_are_accepted(image: Path, name: str) -> None:
    wim.build_manifest(image, name=name, architecture="x86_64", guest_agent_version="0.1.0")


def test_unknown_architecture_is_refused(image: Path) -> None:
    with pytest.raises(wim.ManifestError, match="architecture"):
        wim.build_manifest(image, name="golden", architecture="riscv64", guest_agent_version="0.1.0")


def test_kernel_and_rootfs_must_be_distinct_files(image: Path) -> None:
    with pytest.raises(wim.ManifestError, match="distinct"):
        wim.build_manifest(
            image, name="golden", architecture="x86_64", guest_agent_version="0.1.0", rootfs_file="vmlinux"
        )


@pytest.mark.parametrize("bad", ["../vmlinux", ".vmlinux", "sub/vmlinux", "", "a b", "x" * 65])
def test_file_names_must_be_plain(image: Path, bad: str) -> None:
    with pytest.raises(wim.ManifestError, match="plain file name"):
        wim.build_manifest(image, name="golden", architecture="x86_64", guest_agent_version="0.1.0", kernel_file=bad)


def test_empty_missing_and_symlinked_files_are_refused(image: Path, tmp_path: Path) -> None:
    (image / "vmlinux").write_bytes(b"")
    with pytest.raises(wim.ManifestError, match="empty"):
        golden_manifest(image)
    (image / "vmlinux").unlink()
    with pytest.raises(wim.ManifestError, match="not a regular file"):
        golden_manifest(image)
    target = tmp_path / "elsewhere"
    target.write_bytes(KERNEL)
    (image / "vmlinux").symlink_to(target)
    with pytest.raises(wim.ManifestError, match="symlinks are refused"):
        golden_manifest(image)


@pytest.mark.parametrize("boot_args", ["x" * 2049, "a\nb", "a\0b"])
def test_boot_args_that_the_host_would_refuse_are_refused_here(image: Path, boot_args: str) -> None:
    with pytest.raises(wim.ManifestError, match="boot_args"):
        wim.build_manifest(
            image, name="golden", architecture="x86_64", guest_agent_version="0.1.0", boot_args=boot_args
        )


def test_a_blank_guest_agent_version_is_refused(image: Path) -> None:
    with pytest.raises(wim.ManifestError, match="guest_agent_version"):
        wim.build_manifest(image, name="golden", architecture="x86_64", guest_agent_version="  ")


def test_a_manifest_larger_than_the_host_accepts_is_refused_at_write_time(image: Path) -> None:
    m = wim.build_manifest(
        image, name="golden", architecture="x86_64", guest_agent_version="0.1.0", provenance="p" * 70_000
    )
    with pytest.raises(wim.ManifestError, match="refuses more than"):
        wim.render(m)


# ------------------------------------------------------------------------------------------------ verify


def written(image: Path) -> bytes:
    data = wim.render(golden_manifest(image))
    wim.write_atomic(image / "manifest.json", data)
    return data


def test_verify_accepts_what_write_produced_and_reports_the_image_id(image: Path) -> None:
    data = written(image)
    m = wim.verify_dir(image)
    assert m["image_id"] == "sha256:" + hashlib.sha256(data).hexdigest()


def test_the_image_id_changes_when_even_whitespace_changes(image: Path) -> None:
    data = written(image)
    first = wim.verify_dir(image)["image_id"]
    (image / "manifest.json").write_bytes(data + b"\n")
    assert wim.verify_dir(image)["image_id"] != first


@pytest.mark.parametrize("victim", ["vmlinux", "rootfs.ext4"])
def test_verify_detects_a_changed_file_of_the_same_size(image: Path, victim: str) -> None:
    written(image)
    p = image / victim
    p.write_bytes(p.read_bytes()[:-2] + b"X\n")
    with pytest.raises(wim.ManifestError, match="hashes to"):
        wim.verify_dir(image)


def test_verify_detects_a_changed_size(image: Path) -> None:
    written(image)
    (image / "vmlinux").write_bytes(KERNEL + b"more")
    with pytest.raises(wim.ManifestError, match="bytes, the manifest says"):
        wim.verify_dir(image)


def test_verify_detects_a_manifest_that_names_a_different_directory(image: Path, tmp_path: Path) -> None:
    written(image)
    moved = tmp_path / "renamed"
    image.rename(moved)
    with pytest.raises(wim.ManifestError, match="does not match its directory"):
        wim.verify_dir(moved)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda m: m.update(surprise=1),
        lambda m: m.pop("kernel"),
        lambda m: m.update(schema_version=2),
        lambda m: m["kernel"].update(extra=1),
        lambda m: m["rootfs"].update(sha256="XYZ"),
    ],
)
def test_verify_refuses_manifests_the_host_would_refuse(image: Path, mutate: Any) -> None:
    written(image)
    m = json.loads((image / "manifest.json").read_text())
    mutate(m)
    (image / "manifest.json").write_text(json.dumps(m))
    with pytest.raises(wim.ManifestError):
        wim.verify_dir(image)


def test_verify_refuses_non_json_and_symlinked_manifests(image: Path, tmp_path: Path) -> None:
    (image / "manifest.json").write_text("{nope")
    with pytest.raises(wim.ManifestError, match="not valid JSON"):
        wim.verify_dir(image)
    (image / "manifest.json").unlink()
    elsewhere = tmp_path / "m.json"
    elsewhere.write_bytes(wim.render(golden_manifest(image)))
    (image / "manifest.json").symlink_to(elsewhere)
    with pytest.raises(wim.ManifestError, match="not a regular file"):
        wim.verify_dir(image)


# ------------------------------------------------------------------------------------------------- the CLI


def test_cli_write_then_verify(image: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert (
        wim.main(
            ["write", "--dir", str(image), "--guest-agent-version", "0.1.0", "--arch", "x86_64", "--provenance", "p"]
        )
        == 0
    )
    out = capsys.readouterr().out.strip()
    assert out.startswith("image_id=sha256:")
    assert wim.main(["verify", "--dir", str(image)]) == 0
    assert out.removeprefix("image_id=") in capsys.readouterr().out
    assert not [p for p in image.iterdir() if p.name.startswith(".manifest")], (
        "the temporary file must not be left behind"
    )


def test_cli_refuses_a_name_that_is_not_the_directory(image: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert wim.main(["write", "--dir", str(image), "--guest-agent-version", "0.1.0", "--name", "other"]) == 1
    assert "must equal the directory name" in capsys.readouterr().err


def test_cli_reports_a_tampered_image_with_status_one(image: Path, capsys: pytest.CaptureFixture[str]) -> None:
    written(image)
    (image / "rootfs.ext4").write_bytes(b"tampered-root\n")  # 14 bytes, like the original: only the hash can tell
    assert wim.main(["verify", "--dir", str(image)]) == 1
    assert "hashes to" in capsys.readouterr().err
