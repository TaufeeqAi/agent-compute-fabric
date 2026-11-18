#!/usr/bin/env python3
"""Check that ACF's pinned inputs agree with each other (and, for a release, that none is missing).

    check_pins.py                  # consistency only: what is pinned must be well-formed and agree
    check_pins.py --require-pinned # release gate: additionally FAIL while any digest is UNSET

Pins live in three places that must never drift apart:

  scripts/firecracker.lock   VERSION + per-arch tarball sha256 (what install-firecracker.sh installs)
  config/host.example.yaml   firecracker.pinned_version (what `acf-host` demands at startup)
  images/images.lock         base-image and kernel digests (what build-image.sh builds from)

`acf-host` refuses to start when the installed Firecracker differs from ``pinned_version``, and a
snapshot is only valid on the exact version that took it, so a lock that says v1.17.0 next to a config
that says v1.16.1 is a host that cannot start. Better to fail in CI than at 3 a.m.

Standard library only. Exit status: 0 fine, 1 problem(s) found, 2 unreadable input.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION_RE = re.compile(r"v\d+\.\d+\.\d+")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
OCI_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
KEY_RE = re.compile(r"[A-Za-z0-9_]+")
ARCHES = ("x86_64", "aarch64")


class PinError(Exception):
    pass


def read_lock(path: Path) -> dict[str, str]:
    """The same strict KEY=VALUE grammar the shell scripts use (scripts/lib/common.sh: lock_get)."""
    out: dict[str, str] = {}
    try:
        # Bytes, not read_text(): universal-newline translation would turn a lone \r into a line break.
        text = path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise PinError(f"cannot read {path}: {e}") from e
    if "\0" in text:  # the shell parser refuses these too: `read` would silently drop them
        raise PinError(f"{path}: contains a NUL byte")
    # Split on "\n" only and strip ASCII whitespace only, exactly like the shell parser (str.splitlines() and
    # str.strip() would also act on \r, \v, \f and Unicode separators in the middle of a line).
    for n, raw in enumerate(text.split("\n"), 1):
        line = raw.split("#", 1)[0].strip(" \t\n\v\f\r")
        if not line:
            continue
        key, sep, value = line.partition("=")
        if not sep or not KEY_RE.fullmatch(key):
            raise PinError(f"{path}:{n}: malformed line {raw!r} (expected KEY=VALUE)")
        if not re.fullmatch(r"[A-Za-z0-9._:/@+=,-]*", value):
            raise PinError(f"{path}:{n}: value for {key} has characters outside [A-Za-z0-9._:/@+=,-]")
        if key in out:
            raise PinError(f"{path}:{n}: duplicate key {key}")
        out[key] = value
    return out


def config_pinned_version(path: Path) -> str:
    m = re.search(r"^\s*pinned_version:\s*(\S+)\s*$", path.read_text(encoding="utf-8"), re.MULTILINE)
    if not m:
        raise PinError(f"{path}: no firecracker.pinned_version found")
    return m.group(1)


def check(root: Path, *, require_pinned: bool) -> list[str]:
    problems: list[str] = []
    fc = read_lock(root / "scripts" / "firecracker.lock")
    img = read_lock(root / "images" / "images.lock")

    version = fc.get("VERSION", "")
    if not VERSION_RE.fullmatch(version):
        problems.append(f"scripts/firecracker.lock: VERSION {version!r} must look like v1.17.0")
    cfg_version = config_pinned_version(root / "config" / "host.example.yaml")
    if cfg_version != version:
        problems.append(
            "firecracker version drift: "
            f"scripts/firecracker.lock says {version}, config/host.example.yaml says {cfg_version}"
        )

    def digest(path: str, key: str, value: str, pattern: re.Pattern[str]) -> None:
        if value == "UNSET":
            if require_pinned:
                problems.append(f"{path}: {key} is UNSET (a release must pin every input)")
        elif not pattern.fullmatch(value):
            problems.append(f"{path}: {key}={value!r} is not a valid digest")

    for key, value in fc.items():
        if key.startswith("SHA256_"):
            digest("scripts/firecracker.lock", key, value, SHA256_RE)
    problems.extend(f"scripts/firecracker.lock: missing SHA256_{arch}" for arch in ARCHES if f"SHA256_{arch}" not in fc)

    aliases = sorted(k.removeprefix("BASE_REF_") for k in img if k.startswith("BASE_REF_"))
    for alias in aliases:
        if not (root / "images" / alias / "Dockerfile").is_file():
            problems.append(f"images/images.lock: BASE_REF_{alias} has no images/{alias}/Dockerfile")
        if f"BASE_DIGEST_{alias}" not in img:
            problems.append(f"images/images.lock: BASE_REF_{alias} has no BASE_DIGEST_{alias}")
        else:
            digest("images/images.lock", f"BASE_DIGEST_{alias}", img[f"BASE_DIGEST_{alias}"], OCI_DIGEST_RE)
        ref = img[f"BASE_REF_{alias}"]
        if "@" in ref:
            problems.append(
                f"images/images.lock: BASE_REF_{alias} must be a tag; the digest belongs in BASE_DIGEST_{alias}"
            )
    problems.extend(
        f"images/{d}/Dockerfile has no BASE_REF_{d} in images/images.lock"
        for d in sorted(p.name for p in (root / "images").iterdir() if (p / "Dockerfile").is_file())
        if d not in aliases
    )
    for arch in ("x86_64", "aarch64"):
        if f"KERNEL_SHA256_{arch}" not in img:
            problems.append(f"images/images.lock: missing KERNEL_SHA256_{arch}")
        else:
            digest("images/images.lock", f"KERNEL_SHA256_{arch}", img[f"KERNEL_SHA256_{arch}"], SHA256_RE)
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--require-pinned", action="store_true", help="release gate: fail while any digest is UNSET")
    ap.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    try:
        problems = check(args.root, require_pinned=args.require_pinned)
    except (PinError, OSError) as e:
        print(f"check_pins: {e}", file=sys.stderr)
        return 2
    for p in problems:
        print(f"check_pins: {p}", file=sys.stderr)
    if problems:
        return 1
    print("check_pins: ok" + (" (every input is pinned)" if args.require_pinned else ""), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
