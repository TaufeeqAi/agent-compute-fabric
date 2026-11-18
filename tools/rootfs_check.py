#!/usr/bin/env python3
"""Check an extracted guest root filesystem *as the guest kernel would see it*.

    rootfs_check.py --root DIR --exec /sbin/init --exec /usr/local/bin/acf-guest-agent \
                    --dir /workspace --owner /workspace=1000:1000

Why this exists: a Debian-based image is "merged-usr" (``/sbin -> usr/sbin``, ``/bin -> usr/bin``) and
uses *absolute* symlinks (``/usr/sbin/init -> /usr/local/sbin/acf-init``). Testing ``DIR/sbin/init`` from
the build host follows those absolute links out of DIR into the HOST's filesystem and answers the wrong
question. Every path here is resolved inside DIR, exactly as a chroot would: absolute link targets are
re-rooted at DIR and ``..`` cannot climb above it.

Nothing in DIR is ever executed. Standard library only (it runs on a bare build host).

Exit status: 0 all requirements hold, 1 at least one does not (all failures are listed), 2 usage.
"""

from __future__ import annotations

import argparse
import os
import stat
import sys
from collections import deque
from pathlib import Path

MAX_SYMLINK_DEPTH = 40  # Linux's own MAXSYMLINKS


class RootfsCheckError(Exception):
    """A requirement does not hold (the message says which and why)."""


def resolve_in_root(root: Path, path: str) -> Path:
    """Return the real path inside ``root`` that ``path`` names from the guest's point of view.

    Symlinks are followed (relative ones from their own directory, absolute ones from ``root``);
    ``..`` never escapes ``root``. The returned path need not exist.
    """
    if not path.startswith("/"):
        raise RootfsCheckError(f"{path!r} is not an absolute guest path")
    pending: deque[str] = deque(c for c in path.split("/") if c and c != ".")
    resolved: list[str] = []
    links = 0
    while pending:
        comp = pending.popleft()
        if comp == "..":
            if resolved:
                resolved.pop()
            continue
        candidate = root.joinpath(*resolved, comp)
        if candidate.is_symlink():
            links += 1
            if links > MAX_SYMLINK_DEPTH:
                raise RootfsCheckError(f"{path}: too many levels of symbolic links")
            target = os.readlink(candidate)
            if target.startswith("/"):
                resolved = []  # absolute: restart at the guest's root, not the host's
            parts = [c for c in target.split("/") if c and c != "."]
            pending.extendleft(reversed(parts))
            continue
        resolved.append(comp)
    return root.joinpath(*resolved)


def check_executable(root: Path, path: str) -> str:
    real = resolve_in_root(root, path)
    if not real.exists():
        raise RootfsCheckError(f"{path}: does not exist (resolved to {real.relative_to(root)})")
    st = real.stat()
    if not stat.S_ISREG(st.st_mode):
        raise RootfsCheckError(f"{path}: is not a regular file")
    if not st.st_mode & 0o111:
        raise RootfsCheckError(f"{path}: is not executable (mode {st.st_mode & 0o7777:o})")
    return f"/{real.relative_to(root)}"


def check_dir(root: Path, path: str) -> str:
    real = resolve_in_root(root, path)
    if not real.is_dir():
        raise RootfsCheckError(f"{path}: is not a directory")
    return f"/{real.relative_to(root)}"


def check_owner(root: Path, spec: str) -> str:
    path, _, ids = spec.partition("=")
    uid_s, _, gid_s = ids.partition(":")
    if not (path and uid_s.isdigit() and gid_s.isdigit()):
        raise RootfsCheckError(f"bad --owner {spec!r} (expected /path=UID:GID)")
    real = resolve_in_root(root, path)
    if not real.exists():
        raise RootfsCheckError(f"{path}: does not exist")
    st = real.stat()
    if (st.st_uid, st.st_gid) != (int(uid_s), int(gid_s)):
        raise RootfsCheckError(f"{path}: owned by {st.st_uid}:{st.st_gid}, expected {uid_s}:{gid_s}")
    return f"{path} {uid_s}:{gid_s}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", required=True, type=Path, help="the extracted root filesystem")
    ap.add_argument(
        "--exec", action="append", default=[], dest="execs", metavar="PATH", help="must be an executable regular file"
    )
    ap.add_argument("--dir", action="append", default=[], dest="dirs", metavar="PATH", help="must be a directory")
    ap.add_argument("--owner", action="append", default=[], metavar="PATH=UID:GID", help="must be owned by UID:GID")
    ap.add_argument("--quiet", action="store_true", help="print only failures")
    args = ap.parse_args(argv)

    root: Path = args.root
    if not root.is_dir():
        print(f"rootfs_check: --root {root} is not a directory", file=sys.stderr)
        return 2

    failures: list[str] = []
    checks = (
        [(check_executable, p) for p in args.execs]
        + [(check_dir, p) for p in args.dirs]
        + [(check_owner, p) for p in args.owner]
    )
    for fn, arg in checks:
        try:
            ok = fn(root, arg)
        except RootfsCheckError as e:
            failures.append(str(e))
        else:
            if not args.quiet:
                print(f"ok   {arg}" + (f" -> {ok}" if ok != arg else ""), file=sys.stderr)
    for f in failures:
        print(f"FAIL {f}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
