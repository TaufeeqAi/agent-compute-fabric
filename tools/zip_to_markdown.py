#!/usr/bin/env python3
"""Turn a source ZIP into markdown: one page per file, the complete directory tree, and an optional single bundle.

    zip_to_markdown.py dist/source.zip --out dist/markdown
    zip_to_markdown.py dist/source.zip --out dist/markdown --bundle dist/markdown/BUNDLE.md

Output (everything is derived from the archive; there are no timestamps, so the same archive gives the same export):

    <out>/INDEX.md            summary, the COMPLETE DIRECTORY TREE, language table, and a linked table of every file
    <out>/files/<path>.md     one page per archived file: metadata (size, lines, sha256) and the content in a code fence
    <bundle>                  (optional) the same, as ONE document: for pasting into a single context window

The fence around each file is longer than any run of backticks inside it, so a markdown file that contains code
fences (most of ``docs/``) cannot break out of its own page. Binary or non-UTF-8 files are described, not inlined.

The archive is treated as UNTRUSTED input (run this script as ``python3 -I``), so before anything is written it is
checked, and one problem anywhere aborts the whole conversion:

  * member names: absolute, ``..``, empty, backslash, drive-letter, control-character names are refused, and so are
    names that collide when case is ignored (they would overwrite each other on macOS and Windows)
  * member types: symbolic links, devices and other non-regular members; encrypted members
  * size limits, enforced twice: from the headers (cheap) and again on the bytes actually read (headers can lie)
  * CRC-32 of every member (the zipfile module checks it as the member is read)
  * ``MANIFEST.sha256``, when the archive carries one (``pack_zip.py`` always adds it): every file must match its
    recorded digest, and no file may be missing from, or extra to, the manifest

Output is written only below ``--out`` (and to ``--bundle``), never through a symbolic link, and never over existing
files unless ``--force`` is given. Standard library only.

Exit status: 0 converted, 1 the archive was refused or failed verification (nothing was written), 2 usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
import unicodedata
import zipfile
import zlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

MANIFEST_NAME = "MANIFEST.sha256"
MIB = 1024 * 1024
DEFAULT_MAX_FILES = 5000
DEFAULT_MAX_FILE_MIB = 8
DEFAULT_MAX_TOTAL_MIB = 256
ZIP_ENCRYPTED_FLAG = 0x1
MAX_PROBLEMS_SHOWN = 20
INVISIBLE_CATEGORIES = frozenset(
    {"Cc", "Cf", "Zl", "Zp"}
)  # control, format (bidi overrides), line/paragraph separators

LANGUAGE_BY_SUFFIX = {
    ".rs": "rust",
    ".py": "python",
    ".pyi": "python",
    ".sh": "bash",
    ".toml": "toml",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".md": "markdown",
    ".service": "ini",
    ".conf": "ini",
    ".cfg": "ini",
    ".ini": "ini",
    ".lock": "ini",
    ".txt": "text",
    ".sha256": "text",
}
LANGUAGE_BY_NAME = {
    "Makefile": "make",
    "Dockerfile": "dockerfile",
    ".gitignore": "gitignore",
    ".shellcheckrc": "ini",
    "Cargo.lock": "toml",
    "uv.lock": "toml",
    "py.typed": "text",
}

_WINDOWS_DRIVE = re.compile(r"[A-Za-z]:")
_FORBIDDEN_CHARS = re.compile(r"[\x00-\x1f\x7f\\]")
_BACKTICK_RUN = re.compile(r"`+")
_MANIFEST_LINE = re.compile(r"([0-9a-f]{64})  (.+)")


class ConversionError(Exception):
    """The archive is unsafe, damaged, or does not match its manifest."""


@dataclass(frozen=True)
class Limits:
    max_files: int = DEFAULT_MAX_FILES
    max_file_bytes: int = DEFAULT_MAX_FILE_MIB * MIB
    max_total_bytes: int = DEFAULT_MAX_TOTAL_MIB * MIB


@dataclass(frozen=True)
class Record:
    rel: str  # POSIX path below the archive's top-level directory
    size: int
    sha256: str
    executable: bool
    language: str
    text: str | None  # None: binary or not UTF-8, so not inlined
    lines: int
    ends_with_newline: bool


@dataclass(frozen=True)
class Archive:
    path: Path
    size: int
    sha256: str
    root_name: str
    records: tuple[Record, ...]
    manifest_entries: int | None  # None: the archive carries no manifest


@dataclass(frozen=True)
class Written:
    pages: int
    bundle_bytes: int | None
    out_dir: Path


@dataclass
class _Node:
    children: dict[str, _Node] = field(default_factory=dict)
    is_file: bool = False


# ----------------------------------------------------------------------------------------------------------------------
# Reading and checking the archive
# ----------------------------------------------------------------------------------------------------------------------


def validate_member_name(name: str) -> str:
    """The name without a trailing slash, or ConversionError for any name that could escape or confuse the output."""
    bare = name[:-1] if name.endswith("/") else name
    if not bare:
        raise ConversionError(f"{name!r}: empty member name")
    if bare.startswith("/") or _WINDOWS_DRIVE.match(bare):
        raise ConversionError(f"{name!r}: absolute path")
    if _FORBIDDEN_CHARS.search(bare) or any(unicodedata.category(c) in INVISIBLE_CATEGORIES for c in bare):
        raise ConversionError(
            f"{name!r}: control, invisible or direction-changing character, or a backslash, in the name"
        )
    if any(part in {"", ".", ".."} for part in bare.split("/")):
        raise ConversionError(f"{name!r}: empty, '.' or '..' path component")
    return bare


def _check_member(info: zipfile.ZipInfo) -> None:
    if info.flag_bits & ZIP_ENCRYPTED_FLAG:
        raise ConversionError(f"{info.filename}: encrypted members are not supported")
    kind = stat.S_IFMT(info.external_attr >> 16)  # 0 when the archive was made without Unix attributes
    if not info.is_dir() and kind not in {0, stat.S_IFREG}:
        raise ConversionError(
            f"{info.filename}: not a regular file (mode {info.external_attr >> 16:o}); links and devices are refused"
        )


def _bounded_read(archive: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> bytes:
    if info.file_size > limit:
        raise ConversionError(f"{info.filename}: {info.file_size:,} bytes exceeds the {limit:,}-byte per-file limit")
    try:
        with archive.open(info) as member:
            data = member.read(limit + 1)
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError, zlib.error, EOFError, OSError) as e:
        raise ConversionError(f"{info.filename}: cannot be read ({type(e).__name__}: {e})") from e
    if len(data) > limit or len(data) != info.file_size:
        raise ConversionError(f"{info.filename}: content is {len(data):,} bytes but its header says {info.file_size:,}")
    return data


def language_for(rel: str, text: str | None) -> str:
    name = rel.rsplit("/", 1)[-1]
    if name in LANGUAGE_BY_NAME:
        return LANGUAGE_BY_NAME[name]
    suffix = Path(name).suffix
    if suffix in LANGUAGE_BY_SUFFIX:
        return LANGUAGE_BY_SUFFIX[suffix]
    if text is not None and text.startswith("#!"):
        first = text.split("\n", 1)[0]
        if "python" in first:
            return "python"
        if re.search(r"(?:/|\s)(?:ba|da|z)?sh\b", first):
            return "bash"
    return "text" if text is not None else "binary"


def describe(rel: str, data: bytes, *, executable: bool) -> Record:
    text: str | None
    try:
        text = None if b"\0" in data else data.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    lines = 0 if text is None else text.count("\n") + (0 if text == "" or text.endswith("\n") else 1)
    return Record(
        rel=rel,
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        executable=executable,
        language=language_for(rel, text),
        text=text,
        lines=lines,
        ends_with_newline=data.endswith(b"\n"),
    )


def verify_manifest(manifest: bytes, records: Sequence[Record]) -> int:
    """Check every record against the manifest's digests. Returns the number of manifest entries."""
    try:
        listing = manifest.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ConversionError(f"{MANIFEST_NAME}: not valid UTF-8") from e
    expected: dict[str, str] = {}
    problems: list[str] = []
    for n, line in enumerate(listing.split("\n"), 1):
        if not line:
            continue
        m = _MANIFEST_LINE.fullmatch(line)
        if m is None:
            problems.append(f"{MANIFEST_NAME}:{n}: malformed line")
        elif m.group(2) in expected:
            problems.append(f"{MANIFEST_NAME}:{n}: {m.group(2)} listed twice")
        else:
            expected[m.group(2)] = m.group(1)
    actual = {r.rel: r.sha256 for r in records}
    problems.extend(
        f"{rel}: listed in the manifest but missing from the archive" for rel in sorted(expected.keys() - actual.keys())
    )
    problems.extend(
        f"{rel}: in the archive but not listed in the manifest" for rel in sorted(actual.keys() - expected.keys())
    )
    problems.extend(
        f"{rel}: sha256 differs from the manifest"
        for rel in sorted(actual.keys() & expected.keys())
        if actual[rel] != expected[rel]
    )
    if problems:
        shown = "\n  ".join(problems[:MAX_PROBLEMS_SHOWN])
        hidden = len(problems) - MAX_PROBLEMS_SHOWN
        more = f"\n  ... and {hidden} more" if hidden > 0 else ""
        raise ConversionError(f"the archive does not match its {MANIFEST_NAME}:\n  {shown}{more}")
    return len(expected)


def read_archive(path: Path, limits: Limits | None = None) -> Archive:
    """Read, check and describe every file in the archive. Nothing is written."""
    limits = limits or Limits()
    try:
        size = path.stat().st_size
    except OSError as e:
        raise ConversionError(f"{path}: {e.strerror or e}") from e
    if size > limits.max_total_bytes:
        raise ConversionError(
            f"{path}: the archive itself is {size:,} bytes, over the {limits.max_total_bytes:,}-byte limit"
        )
    digest = hashlib.sha256()
    with path.open("rb") as raw:
        while chunk := raw.read(MIB):
            digest.update(chunk)
    try:
        archive = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as e:
        raise ConversionError(f"{path}: not a readable ZIP archive ({e})") from e
    with archive:
        infos = archive.infolist()
        if len(infos) > limits.max_files:
            raise ConversionError(f"{len(infos):,} members exceeds the {limits.max_files:,}-member limit")
        names: dict[str, zipfile.ZipInfo] = {}
        declared_total = 0
        for info in infos:
            bare = validate_member_name(info.filename)
            _check_member(info)
            if info.is_dir():
                continue
            if bare in names:
                raise ConversionError(f"{bare}: appears twice in the archive")
            names[bare] = info
            declared_total += info.file_size
        if declared_total > limits.max_total_bytes:
            raise ConversionError(
                f"the files add up to {declared_total:,} bytes, over the {limits.max_total_bytes:,}-byte limit"
            )
        if not names:
            raise ConversionError("the archive contains no files")
        root_name, stripped = _split_root(path, names)
        _check_collisions(stripped)

        records: list[Record] = []
        manifest: bytes | None = None
        total = 0
        for rel in sorted(stripped, key=lambda r: r.encode("utf-8")):
            info = names[stripped[rel]]
            data = _bounded_read(archive, info, limits.max_file_bytes)
            total += len(data)
            if total > limits.max_total_bytes:
                raise ConversionError(f"the files add up to more than the {limits.max_total_bytes:,}-byte limit")
            if rel == MANIFEST_NAME:
                manifest = data
            records.append(describe(rel, data, executable=bool((info.external_attr >> 16) & 0o111)))
    entries = None
    if manifest is not None:
        entries = verify_manifest(manifest, [r for r in records if r.rel != MANIFEST_NAME])
    return Archive(path, size, digest.hexdigest(), root_name, tuple(records), entries)


def _split_root(path: Path, names: dict[str, zipfile.ZipInfo]) -> tuple[str, dict[str, str]]:
    """(display name of the root, {path below the root: original member name}).

    A single shared top-level directory (what ``pack_zip.py`` writes) is stripped and becomes the root's name.
    """
    tops = {n.split("/", 1)[0] for n in names}
    if len(tops) == 1 and all("/" in n for n in names):
        (root,) = tops
        return root, {n.split("/", 1)[1]: n for n in names}
    return path.stem, {n: n for n in names}


def _check_collisions(rels: Iterable[str]) -> None:
    files = set(rels)
    folded: dict[str, str] = {}
    for rel in sorted(files):
        key = rel.casefold()
        if key in folded:
            raise ConversionError(
                f"{folded[key]!r} and {rel!r} differ only by case; they would overwrite each other on some systems"
            )
        folded[key] = rel
        parts = rel.split("/")
        for i in range(1, len(parts)):
            ancestor = "/".join(parts[:i])
            if ancestor in files:
                raise ConversionError(f"{ancestor!r} is both a file and a directory")


# ----------------------------------------------------------------------------------------------------------------------
# Rendering (pure functions: archive in, markdown out)
# ----------------------------------------------------------------------------------------------------------------------


def fence_for(text: str) -> str:
    """A backtick fence longer than any run of backticks in ``text``, so the content cannot close it early."""
    longest = max((len(m.group()) for m in _BACKTICK_RUN.finditer(text)), default=0)
    return "`" * max(3, longest + 1)


def code_block(text: str, language: str) -> str:
    fence = fence_for(text)
    body = text if text == "" or text.endswith("\n") else text + "\n"
    return f"{fence}{language}\n{body}{fence}\n"


def render_tree(root_name: str, rels: Iterable[str]) -> str:
    """The complete directory tree as text: directories first, then files, each sorted by name."""
    root = _Node()
    for rel in rels:
        node = root
        parts = rel.split("/")
        for part in parts[:-1]:
            node = node.children.setdefault(part, _Node())
        node.children[parts[-1]] = _Node(is_file=True)
    lines = [f"{root_name}/"]

    def walk(node: _Node, prefix: str) -> None:
        names = sorted(node.children, key=lambda n: (node.children[n].is_file, n))
        for i, name in enumerate(names):
            child = node.children[name]
            last = i == len(names) - 1
            lines.append(f"{prefix}{'└── ' if last else '├── '}{name}{'' if child.is_file else '/'}")
            if not child.is_file:
                walk(child, prefix + ("    " if last else "│   "))

    walk(root, "")
    return "\n".join(lines) + "\n"


def _kind(record: Record) -> str:
    return "binary" if record.text is None else record.language


def _newline_note(record: Record) -> str:
    if record.text is None:
        return "not applicable (binary)"
    if record.size == 0:
        return "not applicable (empty file)"
    return "yes" if record.ends_with_newline else "no"


def _facts(record: Record) -> list[str]:
    return [
        f"- **Path:** `{record.rel}`",
        f"- **Type:** {_kind(record)}" + ("" if record.text is not None else " (not inlined: not UTF-8 text)"),
        f"- **Size:** {record.size:,} bytes" + (f" · {record.lines:,} lines" if record.text is not None else ""),
        f"- **Executable:** {'yes' if record.executable else 'no'}",
        f"- **Trailing newline:** {_newline_note(record)}",
        f"- **SHA-256:** `{record.sha256}`",
    ]


def _content(record: Record) -> str:
    if record.text is None:
        return f"_Binary content ({record.size:,} bytes) is not inlined; verify it by its SHA-256 above._\n"
    return code_block(record.text, "" if record.language in {"text", "binary"} else record.language)


def render_page(record: Record, *, index_link: str) -> str:
    """One file's page. ``index_link`` is the relative link back to INDEX.md."""
    return "\n".join(
        [f"# `{record.rel}`", "", *_facts(record), f"- **Index:** [INDEX.md]({index_link})", "", _content(record)]
    )


def _language_table(records: Sequence[Record]) -> str:
    totals: dict[str, list[int]] = {}
    for r in records:
        row = totals.setdefault(_kind(r), [0, 0, 0])
        row[0] += 1
        row[1] += r.lines
        row[2] += r.size
    rows = ["| Type | Files | Lines | Bytes |", "|---|---:|---:|---:|"]
    for kind, (files, lines, size) in sorted(totals.items(), key=lambda kv: (-kv[1][1], kv[0])):
        rows.append(f"| {kind} | {files:,} | {lines:,} | {size:,} |")
    return "\n".join(rows) + "\n"


def _summary(archive: Archive) -> list[str]:
    records = archive.records
    texts = [r for r in records if r.text is not None]
    manifest = (
        f"verified ({archive.manifest_entries:,} entries, every digest matches)"
        if archive.manifest_entries is not None
        else "none in the archive (member CRC-32s were still checked)"
    )
    return [
        f"- **Archive:** `{archive.path.name}` · {archive.size:,} bytes · SHA-256 `{archive.sha256}`",
        (
            f"- **Files:** {len(records):,} ({len(texts):,} text, {len(records) - len(texts):,} binary) · "
            f"{sum(r.size for r in records):,} bytes · {sum(r.lines for r in texts):,} lines"
        ),
        f"- **{MANIFEST_NAME}:** {manifest}",
        "- **Generated by:** `tools/zip_to_markdown.py` (no timestamps: the same archive always gives the same export)",
    ]


def _grouped(records: Sequence[Record]) -> list[tuple[str, list[Record]]]:
    groups: dict[str, list[Record]] = {}
    for r in sorted(records, key=lambda r: r.rel.encode("utf-8")):
        directory = r.rel.rsplit("/", 1)[0] if "/" in r.rel else "."
        groups.setdefault(directory, []).append(r)
    return sorted(groups.items(), key=lambda kv: (kv[0] != ".", kv[0].encode("utf-8")))


def page_path(rel: str) -> str:
    """Where a file's page lives, relative to ``--out``."""
    return f"files/{rel}.md"


def render_index(archive: Archive, title: str) -> str:
    parts = [
        f"# {title}",
        "",
        *_summary(archive),
        "",
        "## Directory tree",
        "",
        "```text",
        render_tree(archive.root_name, (r.rel for r in archive.records)).rstrip("\n"),
        "```",
        "",
        "## Contents by type",
        "",
        _language_table(archive.records),
        "## Files",
        "",
        "Each file name links to its page; the page holds the full content.",
        "",
    ]
    for directory, group in _grouped(archive.records):
        parts += [
            f"### `{directory}/` ({len(group)})"
            if directory != "."
            else f"### `{archive.root_name}/` (top level, {len(group)})"
        ]
        parts += ["", "| File | Type | Lines | Bytes | SHA-256 |", "|---|---|---:|---:|---|"]
        for r in group:
            name = r.rel.rsplit("/", 1)[-1]
            parts.append(
                f"| [{name}]({quote(page_path(r.rel))}) | {_kind(r)} | {r.lines:,} | {r.size:,} | `{r.sha256[:12]}…` |"
            )
        parts.append("")
    return "\n".join(parts)


def render_bundle(archive: Archive, title: str) -> str:
    """Everything in one document: summary, tree, then every file in path order."""
    parts = [
        f"# {title} (complete bundle)",
        "",
        *_summary(archive),
        "",
        "## Directory tree",
        "",
        "```text",
        render_tree(archive.root_name, (r.rel for r in archive.records)).rstrip("\n"),
        "```",
        "",
        "## Contents by type",
        "",
        _language_table(archive.records),
        "## Files",
        "",
    ]
    for r in sorted(archive.records, key=lambda r: r.rel.encode("utf-8")):
        parts += [f"### `{r.rel}`", "", *_facts(r)[1:], "", _content(r)]
    return "\n".join(parts)


# ----------------------------------------------------------------------------------------------------------------------
# Writing (only below --out, never through a symlink, never over existing files without --force)
# ----------------------------------------------------------------------------------------------------------------------


def _write(path: Path, content: str, *, overwrite: bool) -> None:
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | (os.O_TRUNC if overwrite else os.O_EXCL)
    try:
        fd = os.open(path, flags, 0o644)
    except FileExistsError as e:
        raise ConversionError(f"{path}: already exists (use --force to overwrite generated files)") from e
    except OSError as e:
        raise ConversionError(
            f"{path}: cannot be written ({e.strerror or e}); symbolic links are never followed"
        ) from e
    with os.fdopen(fd, "wb") as handle:
        handle.write(content.encode("utf-8"))


def _plain_directory(root: Path, directory: Path) -> None:
    """Create ``directory`` below ``root``, refusing to pass through a symbolic link on the way."""
    current = root
    for part in directory.relative_to(root).parts:
        current = current / part
        if current.is_symlink():
            raise ConversionError(f"{current}: is a symbolic link; refusing to write through it")
        try:
            current.mkdir(exist_ok=True)
        except OSError as e:
            raise ConversionError(f"{current}: cannot create the directory ({e.strerror or e})") from e


def prepare_out_dir(out: Path, *, force: bool) -> None:
    if out.is_symlink():
        raise ConversionError(f"{out}: is a symbolic link")
    if out.exists():
        if not out.is_dir():
            raise ConversionError(f"{out}: exists and is not a directory")
        if any(out.iterdir()) and not force:
            raise ConversionError(
                f"{out}: is not empty (use --force to overwrite generated files; nothing else is touched)"
            )
    else:
        out.mkdir(parents=True)


def _plan(archive: Archive, heading: str, out_root: Path, bundle: Path | None) -> list[tuple[Path, str]]:
    """Every file the conversion will write, with its content (rendered in memory before anything touches the disk)."""
    plan = [
        (
            out_root / page_path(r.rel),
            render_page(r, index_link="../" * (r.rel.count("/") + 1) + "INDEX.md"),
        )
        for r in archive.records
    ]
    plan.append((out_root / "INDEX.md", render_index(archive, heading)))
    if bundle is not None:
        plan.append((bundle, render_bundle(archive, heading)))
    return plan


def _preflight(out_root: Path, plan: Sequence[tuple[Path, str]], *, force: bool) -> None:
    """Refuse, before the first byte is written, anything that would clobber a file or pass through a symlink."""
    for dest, _ in plan:
        if dest.is_relative_to(out_root):
            _plain_directory(out_root, dest.parent)
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.is_symlink():
            raise ConversionError(f"{dest}: is a symbolic link; refusing to write through it")
        if dest.exists() and not force:
            raise ConversionError(f"{dest}: already exists (use --force to overwrite generated files)")


def convert(
    archive_path: Path,
    out: Path,
    *,
    bundle: Path | None = None,
    force: bool = False,
    title: str | None = None,
    limits: Limits | None = None,
) -> Written:
    """Verify the archive, then write INDEX.md, ``files/`` and the optional bundle.

    Nothing is written until the whole archive has been read and verified and every destination has been checked.
    """
    archive = read_archive(archive_path, limits)
    heading = title or f"{archive.root_name} \u2014 source export"
    prepare_out_dir(out, force=force)
    out_root = out.resolve()
    plan = _plan(archive, heading, out_root, bundle.resolve() if bundle is not None else None)
    _preflight(out_root, plan, force=force)
    for dest, content in plan:
        _write(dest, content, overwrite=force)
    bundle_bytes = len(plan[-1][1].encode("utf-8")) if bundle is not None else None
    return Written(len(archive.records), bundle_bytes, out)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zip_to_markdown.py",
        description="Turn a source ZIP into markdown: a page per file, the full directory tree, an optional bundle.",
    )
    parser.add_argument("archive", type=Path, help="the ZIP to convert (treated as untrusted)")
    parser.add_argument(
        "--out", type=Path, required=True, help="directory for INDEX.md and files/ (created if missing)"
    )
    parser.add_argument("--bundle", type=Path, help="also write everything as one markdown document at this path")
    parser.add_argument("--title", help="document title (default: derived from the archive's top-level directory)")
    parser.add_argument("--force", action="store_true", help="allow a non-empty --out and overwrite generated files")
    parser.add_argument(
        "--max-files", type=int, default=DEFAULT_MAX_FILES, help="member-count limit (default %(default)s)"
    )
    parser.add_argument(
        "--max-file-mib", type=int, default=DEFAULT_MAX_FILE_MIB, help="per-file limit (default %(default)s)"
    )
    parser.add_argument(
        "--max-total-mib", type=int, default=DEFAULT_MAX_TOTAL_MIB, help="total limit (default %(default)s)"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if min(args.max_files, args.max_file_mib, args.max_total_mib) < 1:
        print("zip_to_markdown: the limits must be positive", file=sys.stderr)
        return 2
    limits = Limits(args.max_files, args.max_file_mib * MIB, args.max_total_mib * MIB)
    try:
        written = convert(args.archive, args.out, bundle=args.bundle, force=args.force, title=args.title, limits=limits)
    except ConversionError as e:
        print(f"zip_to_markdown: refused: {e}", file=sys.stderr)
        return 1
    print(f"wrote {written.pages} pages and INDEX.md to {written.out_dir}")
    if written.bundle_bytes is not None:
        print(f"wrote the bundle {args.bundle} ({written.bundle_bytes:,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
