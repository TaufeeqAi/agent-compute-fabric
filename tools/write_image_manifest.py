#!/usr/bin/env python3
"""Write or verify the manifest of an ACF guest image (schema_version 1).

    write_image_manifest.py write  --dir IMAGE_DIR --guest-agent-version 0.1.0 [--provenance TEXT] [--boot-args TEXT]
    write_image_manifest.py verify --dir IMAGE_DIR

An image is a directory ``<state_root>/images/<alias>/`` holding ``manifest.json``, a kernel and a
rootfs. The manifest binds the exact sha256 and size of both files; the host agent copies each file
while hashing the bytes it copies and refuses the sandbox if they differ from the manifest. The
*identity* of an image is the sha256 of the manifest bytes, so any change — even whitespace — is a
different image. This tool therefore writes deterministic bytes.

The rules below mirror ``ImageManifest::validate`` in ``execution/host-agent/src/filesystem/images.rs``
(a cross-language golden test, ``tests/fixtures/image-manifest.golden.json``, pins both sides), and the
output is validated against the committed ``schemas/image-manifest.schema.json`` in the test-suite.

Standard library only: it runs on a bare build host.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 64 * 1024  # the host refuses larger manifests
MAX_BOOT_ARGS = 2048
ARCHITECTURES = ("x86_64", "aarch64")  # == uname -m == Rust's std::env::consts::ARCH
ALIAS_RE = re.compile(
    r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,62}"
)  # 1..=63, [A-Za-z0-9._-], not starting with '.'; fullmatch: `$` would accept a trailing newline
FILE_RE = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}")  # 1..=64, a plain file name
SHA256_RE = re.compile(r"[0-9a-f]{64}")
CHUNK = 1 << 20


class ManifestError(Exception):
    """The image or its manifest is not acceptable (the message says why)."""


def sha256_and_size(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def _entry(directory: Path, file_name: str, what: str) -> dict[str, Any]:
    if not FILE_RE.fullmatch(file_name):
        raise ManifestError(f"{what} file name {file_name!r} is not a plain file name")
    path = directory / file_name
    if path.is_symlink() or not path.is_file():
        raise ManifestError(f"{what} {path} is not a regular file (symlinks are refused)")
    digest, size = sha256_and_size(path)
    if size == 0:
        raise ManifestError(f"{what} {path} is empty")
    return {"file": file_name, "sha256": digest, "size": size}


def build_manifest(
    directory: Path,
    *,
    name: str,
    architecture: str,
    guest_agent_version: str,
    kernel_file: str = "vmlinux",
    rootfs_file: str = "rootfs.ext4",
    boot_args: str | None = None,
    provenance: str | None = None,
) -> dict[str, Any]:
    if not ALIAS_RE.fullmatch(name):
        raise ManifestError(f"image name {name!r} must be 1..63 characters of [A-Za-z0-9._-] and not start with '.'")
    if architecture not in ARCHITECTURES:
        raise ManifestError(f"architecture {architecture!r} must be one of {ARCHITECTURES}")
    if not guest_agent_version.strip():
        raise ManifestError("guest_agent_version must not be empty")
    if kernel_file == rootfs_file:
        raise ManifestError("kernel and rootfs must be distinct files")
    if boot_args is not None and (len(boot_args) > MAX_BOOT_ARGS or "\0" in boot_args or "\n" in boot_args):
        raise ManifestError(f"boot_args is longer than {MAX_BOOT_ARGS} or contains control characters")
    return {
        "schema_version": SCHEMA_VERSION,
        "name": name,
        "architecture": architecture,
        "kernel": _entry(directory, kernel_file, "kernel"),
        "rootfs": _entry(directory, rootfs_file, "rootfs"),
        "boot_args": boot_args,
        "guest_agent_version": guest_agent_version,
        "provenance": provenance,
    }


def render(manifest: dict[str, Any]) -> bytes:
    """Deterministic bytes: key order as written above, two-space indent, trailing newline."""
    data = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode()
    if len(data) > MAX_MANIFEST_BYTES:
        raise ManifestError(f"manifest is {len(data)} bytes; the host refuses more than {MAX_MANIFEST_BYTES}")
    return data


def write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.new.{os.getpid()}")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def verify_dir(directory: Path) -> dict[str, Any]:
    """Re-check an installed image: the manifest parses, names this directory, and binds the files on disk."""
    mpath = directory / "manifest.json"
    if mpath.is_symlink() or not mpath.is_file():
        raise ManifestError(f"{mpath} is not a regular file")
    raw = mpath.read_bytes()
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ManifestError(f"{mpath} is larger than {MAX_MANIFEST_BYTES} bytes")
    try:
        m = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ManifestError(f"{mpath} is not valid JSON: {e}") from e
    expected_keys = {
        "schema_version",
        "name",
        "architecture",
        "kernel",
        "rootfs",
        "boot_args",
        "guest_agent_version",
        "provenance",
    }
    required = expected_keys - {"boot_args", "provenance"}
    if not isinstance(m, dict) or not required <= set(m) or not set(m) <= expected_keys:
        raise ManifestError("manifest has missing or unknown keys")
    if m["schema_version"] != SCHEMA_VERSION:
        raise ManifestError(f"unsupported schema_version {m['schema_version']!r}")
    if m["name"] != directory.name:
        raise ManifestError(f"manifest name {m['name']!r} does not match its directory {directory.name!r}")
    for what in ("kernel", "rootfs"):
        entry = m[what]
        if (
            not isinstance(entry, dict)
            or set(entry) != {"file", "sha256", "size"}
            or not FILE_RE.fullmatch(str(entry["file"]))
            or not SHA256_RE.fullmatch(str(entry["sha256"]))
        ):
            raise ManifestError(f"{what} entry is malformed")
        digest, size = sha256_and_size(directory / entry["file"])
        if size != entry["size"]:
            raise ManifestError(f"{what} {entry['file']} is {size} bytes, the manifest says {entry['size']}")
        if digest != entry["sha256"]:
            raise ManifestError(f"{what} {entry['file']} hashes to {digest}, the manifest says {entry['sha256']}")
    if m["kernel"]["file"] == m["rootfs"]["file"]:
        raise ManifestError("kernel and rootfs must be distinct files")
    m["image_id"] = "sha256:" + hashlib.sha256(raw).hexdigest()
    return m


def require_name_is_directory(name: str, directory: Path) -> None:
    """The host resolves an image by its directory name, so a manifest that names another image can never be found."""
    if name != directory.name:
        raise ManifestError(
            f"--name {name!r} must equal the directory name {directory.name!r}: the host resolves images by directory"
        )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    w = sub.add_parser("write", help="hash the kernel and rootfs in DIR and write DIR/manifest.json")
    w.add_argument("--dir", required=True, type=Path)
    w.add_argument("--name", help="image alias (default: the directory's name; must equal it)")
    w.add_argument("--arch", default=None, help="x86_64 or aarch64 (default: this machine)")
    w.add_argument("--guest-agent-version", required=True)
    w.add_argument("--kernel-file", default="vmlinux")
    w.add_argument("--rootfs-file", default="rootfs.ext4")
    w.add_argument("--boot-args", default=None, help="replaces the host's default kernel command line for THIS image")
    w.add_argument(
        "--provenance",
        default=None,
        help="where this image came from (recorded in the manifest, hence in its identity)",
    )

    v = sub.add_parser("verify", help="re-check DIR/manifest.json against the files on disk")
    v.add_argument("--dir", required=True, type=Path)

    args = ap.parse_args(argv)
    try:
        directory: Path = args.dir.resolve()
        if args.cmd == "write":
            name = args.name or directory.name
            require_name_is_directory(name, directory)
            arch = args.arch or os.uname().machine
            manifest = build_manifest(
                directory,
                name=name,
                architecture=arch,
                guest_agent_version=args.guest_agent_version,
                kernel_file=args.kernel_file,
                rootfs_file=args.rootfs_file,
                boot_args=args.boot_args,
                provenance=args.provenance,
            )
            data = render(manifest)
            write_atomic(directory / "manifest.json", data)
            print(f"image_id=sha256:{hashlib.sha256(data).hexdigest()}")
        else:
            m = verify_dir(directory)
            print(
                f"ok image_id={m['image_id']} kernel={m['kernel']['sha256'][:12]} rootfs={m['rootfs']['sha256'][:12]}"
            )
    except (ManifestError, OSError) as e:
        print(f"write_image_manifest: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
