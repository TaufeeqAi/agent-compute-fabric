#!/usr/bin/env python3
"""Pack the source tree into a reproducible ZIP (this is what ``make dist`` runs).

    pack_zip.py --root . --out dist/agent-compute-fabric-phase1.zip --prefix agent-compute-fabric-phase1
    pack_zip.py --root . --out dist/x.zip --prefix x --list     # review what would be packed; write nothing

Reproducible means: the same files produce the same bytes, whoever builds them and whenever.

  * members are sorted by their UTF-8 path, under one top-level directory (``--prefix``)
  * every timestamp is 1980-01-01 00:00:00 (the earliest a ZIP can carry); owners and umask play no part
  * a member is 0644, or 0755 when the source file has any executable bit; nothing else is recorded
  * no directory entries, no extra fields, no comments, deflate level 9
  * ``MANIFEST.sha256`` is added: ``<sha256>  <path>`` per member in coreutils format, so that after extraction
    ``sha256sum -c MANIFEST.sha256`` run inside the prefix directory proves the files are the ones that were packed

The compressed bytes also depend on the zlib that deflates them: two machines with different zlib builds produce
different (equally valid) archives with identical contents. Compare the manifests, not the archives, across machines.

What is left out mirrors ``.gitignore`` (a test keeps the two in step): build output (``target/``, ``dist/``),
caches, virtualenvs, bytecode, coverage data, logs, editor files and ``.env`` files (``.env.example`` is kept).

What is refused (exit status 1, nothing written): a symlink, a FIFO/socket/device, a file larger than
``--max-file-bytes`` (this is a *source* archive: a stray binary should fail loudly, not ship), a file name that is not
valid UTF-8 or contains a control character or a backslash, and a ``MANIFEST.sha256`` in the root of the tree that
is not exactly the manifest this tree would get (the name is reserved for the generated one).

A tree unpacked from one of these archives carries that archive's own ``MANIFEST.sha256``. It is accepted and
replaced by the regenerated (identical) one, so unpack-then-repack gives the same archive; once a file has been
edited, added or removed the manifest is stale and the run is refused until it is deleted.

The archive is written to a temporary file next to the destination and renamed into place, so a failed run never
leaves a truncated ZIP behind. Standard library only. Exit status: 0 packed, 1 refused, 2 usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
import tempfile
import unicodedata
import zipfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

MANIFEST_NAME = "MANIFEST.sha256"
ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)
DEFAULT_MAX_FILE_BYTES = 4 * 1024 * 1024
PREFIX_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
FORBIDDEN_NAME_CHARS = re.compile(r"[\x00-\x1f\x7f\\]")
INVISIBLE_CATEGORIES = frozenset(
    {"Cc", "Cf", "Zl", "Zp"}
)  # control, format (bidi overrides), line/paragraph separators

# Directories left out at the repository root only (the `/target/` and `/dist/` lines of .gitignore).
ROOT_ONLY_DIRS = frozenset({"target", "dist"})
# Directories left out wherever they appear.
ANY_DEPTH_DIRS = frozenset(
    {
        ".git",
        ".idea",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        ".vscode",
        "__pycache__",
        "htmlcov",
        "node_modules",
        "venv",
    }
)
EXCLUDED_DIR_SUFFIXES = (".egg-info",)
EXCLUDED_FILE_NAMES = frozenset({".coverage", ".DS_Store", ".env"})
EXCLUDED_FILE_PREFIXES = (".coverage.", ".env.")
EXCLUDED_FILE_SUFFIXES = (".pyc", ".pyo", ".pyd", ".swp", ".log")
KEPT_FILE_NAMES = frozenset({".env.example"})


class PackError(Exception):
    """The tree must not be archived as it is."""


@dataclass(frozen=True)
class Entry:
    rel: str  # POSIX path relative to the root
    path: Path
    size: int
    executable: bool


@dataclass(frozen=True)
class Packed:
    files: int  # members, including the manifest
    uncompressed_bytes: int
    archive_bytes: int
    archive_sha256: str


def is_excluded(rel: str, *, is_dir: bool) -> bool:
    """Whether the repository-relative POSIX path ``rel`` is left out (it, or any directory above it)."""
    parts = rel.split("/")
    directories = parts if is_dir else parts[:-1]
    for depth, name in enumerate(directories):
        if name in ANY_DEPTH_DIRS or name.endswith(EXCLUDED_DIR_SUFFIXES) or (depth == 0 and name in ROOT_ONLY_DIRS):
            return True
    if is_dir:
        return False
    leaf = parts[-1]
    if leaf in KEPT_FILE_NAMES:
        return False
    return (
        leaf in EXCLUDED_FILE_NAMES or leaf.startswith(EXCLUDED_FILE_PREFIXES) or leaf.endswith(EXCLUDED_FILE_SUFFIXES)
    )


def check_name(rel: str) -> None:
    try:
        rel.encode("utf-8")
    except UnicodeEncodeError as e:
        raise PackError(f"{rel!r}: the name is not valid UTF-8") from e
    if FORBIDDEN_NAME_CHARS.search(rel) or any(unicodedata.category(c) in INVISIBLE_CATEGORIES for c in rel):
        raise PackError(
            f"{rel!r}: the name contains a control, invisible or direction-changing character, or a backslash"
        )


def collect(
    root: Path, *, skip: frozenset[Path] = frozenset(), max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
) -> list[Entry]:
    """Every file to archive, sorted by UTF-8 path. Raises PackError for anything that must not be archived."""
    entries: list[Entry] = []
    pending = [(root, "")]
    while pending:
        directory, rel_dir = pending.pop()
        with os.scandir(directory) as it:
            children = sorted(it, key=lambda e: e.name)
        for child in children:
            rel = f"{rel_dir}{child.name}"
            if child.is_symlink():
                if is_excluded(rel, is_dir=child.is_dir()):  # a symlinked virtualenv is not our business
                    continue
                raise PackError(f"{rel}: refusing to archive a symbolic link")
            if child.is_dir(follow_symlinks=False):
                if not is_excluded(rel, is_dir=True):
                    pending.append((Path(child.path), f"{rel}/"))
                continue
            if is_excluded(rel, is_dir=False) or Path(child.path).resolve() in skip:
                continue
            if not child.is_file(follow_symlinks=False):
                raise PackError(f"{rel}: refusing to archive a special file (FIFO, socket or device)")
            check_name(rel)
            info = child.stat(follow_symlinks=False)
            if info.st_size > max_file_bytes:
                raise PackError(
                    f"{rel}: {info.st_size:,} bytes exceeds --max-file-bytes {max_file_bytes:,}"
                    " (a source archive should not carry large binaries)"
                )
            entries.append(Entry(rel, Path(child.path), info.st_size, bool(info.st_mode & 0o111)))
    entries.sort(key=lambda e: e.rel.encode("utf-8"))
    return _without_own_manifest(entries, max_file_bytes)


def _without_own_manifest(entries: list[Entry], max_file_bytes: int) -> list[Entry]:
    """Leave out the root ``MANIFEST.sha256`` of an unpacked archive, after proving it describes exactly this tree.

    The packer writes the manifest itself, so a file of that name must never be archived as if it were source. The one
    harmless case is the manifest of the archive this tree was unpacked from: it equals the manifest about to be
    generated, so it is dropped and regenerated. Anything else (hand-written, or stale because a file has changed since)
    is refused rather than silently replaced.
    """
    present = [e for e in entries if e.rel == MANIFEST_NAME]
    if not present:
        return entries
    others = [e for e in entries if e.rel != MANIFEST_NAME]
    regenerated = manifest_text([(e.rel, hashlib.sha256(read_entry(e, max_file_bytes)).hexdigest()) for e in others])
    if read_entry(present[0], max_file_bytes) != regenerated.encode("utf-8"):
        raise PackError(
            f"{MANIFEST_NAME} is reserved for the generated manifest, and the one in the tree does not describe"
            " this tree (hand-written, or stale because a file has changed since it was written):"
            " delete it and pack again"
        )
    return others


def read_entry(entry: Entry, max_file_bytes: int) -> bytes:
    data = entry.path.read_bytes()
    if len(data) > max_file_bytes:  # it grew between the scan and the read
        raise PackError(f"{entry.rel}: {len(data):,} bytes exceeds --max-file-bytes {max_file_bytes:,}")
    return data


def manifest_text(digests: Sequence[tuple[str, str]]) -> str:
    """coreutils `sha256sum` format, sorted by path (the caller passes (rel, hexdigest) pairs in order)."""
    return "".join(f"{digest}  {rel}\n" for rel, digest in digests)


def _member(name: str, *, executable: bool) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=ZIP_EPOCH)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3  # Unix, whatever the building OS: the permission bits below mean something
    info.external_attr = (stat.S_IFREG | (0o755 if executable else 0o644)) << 16
    return info


def write_archive(entries: Sequence[Entry], prefix: str, destination: Path, max_file_bytes: int) -> Packed:
    """Write the archive atomically to ``destination`` and describe it."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
    tmp = Path(tmp_name)
    try:
        uncompressed = 0
        digests: list[tuple[str, str]] = []
        with os.fdopen(fd, "wb") as raw, zipfile.ZipFile(raw, "w", allowZip64=True) as archive:
            members: list[tuple[str, bytes, bool]] = []
            for entry in entries:
                data = read_entry(entry, max_file_bytes)
                digests.append((entry.rel, hashlib.sha256(data).hexdigest()))
                members.append((entry.rel, data, entry.executable))
            members.append((MANIFEST_NAME, manifest_text(digests).encode("utf-8"), False))
            members.sort(key=lambda m: m[0].encode("utf-8"))
            for rel, data, executable in members:
                archive.writestr(_member(f"{prefix}/{rel}", executable=executable), data, compresslevel=9)
                uncompressed += len(data)
            count = len(members)
        blob = hashlib.sha256()
        with tmp.open("rb") as written:
            while chunk := written.read(1 << 20):
                blob.update(chunk)
        archive_bytes = tmp.stat().st_size
        tmp.chmod(0o644)  # mkstemp creates 0600; a source archive is meant to be read by whoever receives it
        tmp.replace(destination)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return Packed(count, uncompressed, archive_bytes, blob.hexdigest())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pack_zip.py",
        description="Pack the source tree into a reproducible ZIP with an embedded sha256 manifest.",
    )
    parser.add_argument("--root", type=Path, default=Path(), help="directory to pack (default: the current directory)")
    parser.add_argument("--out", type=Path, required=True, help="archive to write (parent directories are created)")
    parser.add_argument("--prefix", required=True, help="the single top-level directory inside the archive")
    parser.add_argument(
        "--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES, help="refuse any file larger than this"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        dest="list_only",
        help="print every member with its size and sha256; write nothing",
    )
    return parser


def run(args: argparse.Namespace) -> int:
    root: Path = args.root
    prefix: str = args.prefix
    if not root.is_dir():
        print(f"pack_zip: --root {root} is not a directory", file=sys.stderr)
        return 2
    if not PREFIX_RE.fullmatch(prefix):
        print(f"pack_zip: --prefix {prefix!r} must match {PREFIX_RE.pattern}", file=sys.stderr)
        return 2
    if args.max_file_bytes < 1:
        print("pack_zip: --max-file-bytes must be positive", file=sys.stderr)
        return 2
    out: Path = args.out
    if out.is_dir():
        print(f"pack_zip: --out {out} is a directory", file=sys.stderr)
        return 2
    try:
        entries = collect(root, skip=frozenset({out.resolve()}), max_file_bytes=args.max_file_bytes)
        if args.list_only:
            for e in entries:
                digest = hashlib.sha256(read_entry(e, args.max_file_bytes)).hexdigest()
                print(f"{'x' if e.executable else '-'} {e.size:>9,}  {digest}  {prefix}/{e.rel}")
            print(f"{len(entries)} files (plus {MANIFEST_NAME}); nothing written")
            return 0
        packed = write_archive(entries, prefix, out, args.max_file_bytes)
    except PackError as e:
        print(f"pack_zip: refusing to pack: {e}", file=sys.stderr)
        return 1
    print(
        f"packed {packed.files} files ({packed.uncompressed_bytes:,} bytes) into {out} "
        f"({packed.archive_bytes:,} bytes, sha256 {packed.archive_sha256})"
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    return run(build_parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
