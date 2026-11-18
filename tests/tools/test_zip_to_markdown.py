"""tools/zip_to_markdown.py: every file becomes a lossless markdown page; a hostile archive is refused unread."""

from __future__ import annotations

import hashlib
import re
import stat
import subprocess
import zipfile
from collections.abc import Callable, Sequence
from pathlib import Path
from urllib.parse import unquote

import pytest

import pack_zip
import zip_to_markdown as z2m

PREFIX = "proj"
EPOCH = (1980, 1, 1, 0, 0, 0)
RLO = chr(0x202E)  # right-to-left override: makes a name read backwards

AWKWARD: dict[str, bytes] = {
    "plain.txt": b"hello\n",
    "no_newline.py": b"print('x')",
    "crlf.sh": b"#!/bin/sh\r\necho hi\r\n",
    "empty.cfg": b"",
    "just_newline.txt": b"\n",
    "fences.md": b"# t\n```python\nx = 1\n```\n\n````\nfour\n````\n`` inline ``\n",
    "uni/ünï-côde.rs": 'fn main() { println!("héllo ☃"); }\n'.encode(),
    "dir with space/file (1).txt": b"spaces and parens\n",
    "lone_cr.txt": b"a\rb",
    "bin/blob.dat": b"\x00\x01\x02\xff\xfe",
    "latin1.txt": b"caf\xe9\n",
    "Makefile": b"all:\n\t@echo hi\n",
}
EXECUTABLE = frozenset({"crlf.sh"})


def is_text(data: bytes) -> bool:
    if b"\0" in data:
        return False
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def write_tree(root: Path, files: dict[str, bytes], *, executable: frozenset[str] = frozenset()) -> Path:
    for rel, data in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o755 if rel in executable else 0o644)
    return root


def pack(root: Path, out: Path) -> Path:
    assert pack_zip.main(["--root", str(root), "--out", str(out), f"--prefix={PREFIX}"]) == 0
    return out


def make_zip(
    path: Path,
    entries: Sequence[tuple[str, bytes]],
    *,
    attrs: dict[str, int] | None = None,
    encrypted: frozenset[str] = frozenset(),
    compress: int = zipfile.ZIP_DEFLATED,
) -> Path:
    """A ZIP built member by member, so that hostile or malformed archives can be written on purpose."""
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries:
            info = zipfile.ZipInfo(name, date_time=EPOCH)
            info.external_attr = (attrs or {}).get(name, 0)
            info.compress_type = compress
            zf.writestr(info, data)
    if encrypted:  # zipfile resets the flag bits when writing, so set bit 0 in the central directory by hand
        blob = bytearray(path.read_bytes())
        at = blob.find(b"PK\x01\x02")
        while at != -1:
            name_length = int.from_bytes(blob[at + 28 : at + 30], "little")
            if blob[at + 46 : at + 46 + name_length].decode() in encrypted:
                blob[at + 8] |= 0x01
            at = blob.find(b"PK\x01\x02", at + 4)
        path.write_bytes(bytes(blob))
    return path


def rewrite(src: Path, dst: Path, mutate: Callable[[dict[str, bytes]], object]) -> Path:
    with zipfile.ZipFile(src) as zf:
        content = {i.filename: zf.read(i) for i in zf.infolist()}
    mutate(content)
    return make_zip(dst, list(content.items()))


def read_page(out: Path, rel: str) -> str:
    return (out / "files" / f"{rel}.md").read_bytes().decode("utf-8")


def parse_page(page: str) -> tuple[dict[str, str], str | None]:
    """The facts and the fenced content of a page: the inverse of render_page (None when nothing was inlined)."""
    lines = page.split("\n")  # not splitlines(): a \r inside the content must survive
    facts: dict[str, str] = {}
    for n, line in enumerate(lines):
        if m := re.fullmatch(r"- \*\*(.+?):\*\* (.*)", line):
            facts[m.group(1)] = m.group(2)
            continue
        if fence := re.fullmatch(r"(`{3,})\S*", line):
            body: list[str] = []
            for inner in lines[n + 1 :]:
                if inner == fence.group(1):
                    break
                body.append(inner)
            else:
                raise AssertionError("unterminated code fence")
            text = "\n".join(body) + ("\n" if body else "")
            if facts["Trailing newline"] == "no":
                text = text.removesuffix("\n")
            return facts, text
    return facts, None


# ------------------------------------------------------------------------------------------------------ round trip


def test_every_file_survives_the_round_trip_byte_for_byte(tmp_path: Path) -> None:
    archive = pack(write_tree(tmp_path / "src", AWKWARD, executable=EXECUTABLE), tmp_path / "x.zip")
    out = tmp_path / "md"
    written = z2m.convert(archive, out)
    assert written.pages == len(AWKWARD) + 1  # plus the manifest

    for rel, data in AWKWARD.items():
        facts, text = parse_page(read_page(out, rel))
        assert facts["Path"] == f"`{rel}`"
        assert facts["SHA-256"] == f"`{hashlib.sha256(data).hexdigest()}`"
        assert facts["Executable"] == ("yes" if rel in EXECUTABLE else "no")
        if is_text(data):
            assert text is not None, rel
            assert text.encode("utf-8") == data, rel
        else:
            assert text is None, rel
            assert "not inlined" in read_page(out, rel)


def test_trailing_newline_and_emptiness_are_reported_honestly(tmp_path: Path) -> None:
    archive = pack(write_tree(tmp_path / "src", AWKWARD), tmp_path / "x.zip")
    out = tmp_path / "md"
    z2m.convert(archive, out)
    newline = {rel: parse_page(read_page(out, rel))[0]["Trailing newline"] for rel in AWKWARD}
    assert newline["plain.txt"] == "yes"
    assert newline["no_newline.py"] == "no"
    assert newline["lone_cr.txt"] == "no"
    assert newline["empty.cfg"] == "not applicable (empty file)"
    assert newline["bin/blob.dat"] == "not applicable (binary)"


def test_a_file_that_contains_code_fences_cannot_break_out_of_its_page(tmp_path: Path) -> None:
    archive = pack(write_tree(tmp_path / "src", {"fences.md": AWKWARD["fences.md"]}), tmp_path / "x.zip")
    out = tmp_path / "md"
    z2m.convert(archive, out)
    page = read_page(out, "fences.md")
    assert "`````markdown\n" in page  # five backticks: longer than the four inside the file
    _, text = parse_page(page)
    assert text is not None
    assert text.encode() == AWKWARD["fences.md"]


@pytest.mark.parametrize(
    ("text", "fence"),
    [("", "```"), ("no ticks", "```"), ("``", "```"), ("```", "````"), ("a ```` b ``` c", "`````")],
)
def test_the_fence_is_longer_than_any_run_of_backticks_in_the_content(text: str, fence: str) -> None:
    assert z2m.fence_for(text) == fence


@pytest.mark.parametrize(
    ("rel", "text", "language"),
    [
        ("src/lib.rs", "", "rust"),
        ("apps/cli/src/main.py", "", "python"),
        ("Makefile", "", "make"),
        ("images/base/Dockerfile", "", "dockerfile"),
        ("Cargo.lock", "", "toml"),
        ("scripts/firecracker.lock", "", "ini"),
        (".gitignore", "", "gitignore"),
        ("deploy/systemd/acf-host.service", "", "ini"),
        ("scripts/run", "#!/usr/bin/env python3\n", "python"),
        ("scripts/run", "#!/bin/sh\n", "bash"),
        ("scripts/run", "#!/usr/bin/env bash\n", "bash"),
        ("scripts/run", "plain words\n", "text"),
        ("blob", None, "binary"),
    ],
)
def test_the_language_comes_from_the_name_then_the_shebang(rel: str, text: str | None, language: str) -> None:
    assert z2m.language_for(rel, text) == language


# ------------------------------------------------------------------------------------------------------ the tree


def test_the_tree_lists_directories_before_files_each_in_order() -> None:
    tree = z2m.render_tree("root", ["b.txt", "a/z.txt", "a/y/q.txt", "a/m.txt", ".hidden/x", "A.txt"])
    assert tree == (
        "root/\n"
        "├── .hidden/\n"
        "│   └── x\n"
        "├── a/\n"
        "│   ├── y/\n"
        "│   │   └── q.txt\n"
        "│   ├── m.txt\n"
        "│   └── z.txt\n"
        "├── A.txt\n"
        "└── b.txt\n"
    )


def test_the_index_holds_the_complete_tree_and_every_link_resolves(tmp_path: Path) -> None:
    archive = pack(write_tree(tmp_path / "src", AWKWARD), tmp_path / "x.zip")
    out = tmp_path / "md"
    z2m.convert(archive, out)
    index = (out / "INDEX.md").read_text(encoding="utf-8")

    tree_block = re.search(r"## Directory tree\n\n```text\n(.*?)\n```", index, re.DOTALL)
    assert tree_block is not None
    tree = tree_block.group(1)
    assert tree.startswith(f"{PREFIX}/\n")
    for rel in (*AWKWARD, "MANIFEST.sha256"):
        assert rel.rsplit("/", 1)[-1] in tree, rel

    targets = [unquote(t) for t in re.findall(r"\]\((files/[^)]+)\)", index)]
    assert len(targets) == len(AWKWARD) + 1
    for target in targets:
        assert (out / target).is_file(), target

    for page in (out / "files").rglob("*.md"):
        link = re.search(r"\[INDEX\.md\]\(([^)]+)\)", page.read_text(encoding="utf-8"))
        assert link is not None
        assert (page.parent / link.group(1)).resolve() == (out / "INDEX.md").resolve()


def test_the_index_reports_what_was_verified(tmp_path: Path) -> None:
    archive = pack(write_tree(tmp_path / "src", AWKWARD), tmp_path / "x.zip")
    z2m.convert(archive, tmp_path / "md")
    index = (tmp_path / "md" / "INDEX.md").read_text(encoding="utf-8")
    assert f"verified ({len(AWKWARD)} entries, every digest matches)" in index
    assert hashlib.sha256(archive.read_bytes()).hexdigest() in index
    assert "2 binary" in index


def test_the_bundle_has_the_tree_and_every_file(tmp_path: Path) -> None:
    archive = pack(write_tree(tmp_path / "src", AWKWARD), tmp_path / "x.zip")
    bundle = tmp_path / "out" / "BUNDLE.md"
    written = z2m.convert(archive, tmp_path / "md", bundle=bundle)
    raw = bundle.read_bytes()  # not read_text(): universal newlines would eat the \r\n of crlf.sh
    text = raw.decode("utf-8")
    assert written.bundle_bytes == len(raw)
    assert "## Directory tree" in text
    for rel in AWKWARD:
        assert f"### `{rel}`" in text, rel
    assert "hello\n```" in text
    assert "not inlined" in text


def test_the_same_archive_gives_the_same_export(tmp_path: Path) -> None:
    archive = pack(write_tree(tmp_path / "src", AWKWARD), tmp_path / "x.zip")
    z2m.convert(archive, tmp_path / "one", bundle=tmp_path / "one-bundle.md")
    z2m.convert(archive, tmp_path / "two", bundle=tmp_path / "two-bundle.md")

    def snapshot(root: Path) -> dict[str, bytes]:
        return {str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}

    assert snapshot(tmp_path / "one") == snapshot(tmp_path / "two")
    assert (tmp_path / "one-bundle.md").read_bytes() == (tmp_path / "two-bundle.md").read_bytes()


def test_without_a_shared_top_level_directory_the_archive_name_is_the_root(tmp_path: Path) -> None:
    path = make_zip(tmp_path / "two.zip", [("a/x.txt", b"1"), ("b/y.txt", b"2")])
    archive = z2m.read_archive(path)
    assert archive.root_name == "two"
    assert [r.rel for r in archive.records] == ["a/x.txt", "b/y.txt"]
    mixed = make_zip(tmp_path / "mixed.zip", [(f"{PREFIX}/x.txt", b"1"), ("top.txt", b"2")])
    assert [r.rel for r in z2m.read_archive(mixed).records] == ["proj/x.txt", "top.txt"]


# ------------------------------------------------------------------------------------------------------ the manifest


@pytest.fixture
def good(tmp_path: Path) -> Path:
    return pack(write_tree(tmp_path / "src", {"a.txt": b"ay\n", "b.txt": b"bee\n"}), tmp_path / "good.zip")


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda c: c.__setitem__(f"{PREFIX}/a.txt", b"tampered\n"), "a.txt: sha256 differs"),
        (lambda c: c.__setitem__(f"{PREFIX}/extra.txt", b"x"), "extra.txt: in the archive but not listed"),
        (lambda c: c.pop(f"{PREFIX}/b.txt"), "b.txt: listed in the manifest but missing"),
        (lambda c: c.__setitem__(f"{PREFIX}/MANIFEST.sha256", b"garbage\n"), "malformed line"),
    ],
    ids=["tampered", "unlisted", "missing", "malformed"],
)
def test_an_archive_that_disagrees_with_its_manifest_is_refused(
    tmp_path: Path, good: Path, mutate: Callable[[dict[str, bytes]], object], message: str
) -> None:
    bad = rewrite(good, tmp_path / "bad.zip", mutate)
    with pytest.raises(z2m.ConversionError, match=re.escape(message)):
        z2m.convert(bad, tmp_path / "md")
    assert not (tmp_path / "md").exists()


def test_an_archive_without_a_manifest_is_accepted_and_says_so(tmp_path: Path, good: Path) -> None:
    plain = rewrite(good, tmp_path / "plain.zip", lambda c: c.pop(f"{PREFIX}/MANIFEST.sha256"))
    archive = z2m.read_archive(plain)
    assert archive.manifest_entries is None
    z2m.convert(plain, tmp_path / "md")
    assert "none in the archive" in (tmp_path / "md" / "INDEX.md").read_text(encoding="utf-8")


# ------------------------------------------------------------------------------------------------------ hostile input


@pytest.mark.parametrize(
    ("name", "message"),
    [
        ("../evil.txt", "'..' path component"),
        (f"{PREFIX}/../../evil.txt", "'..' path component"),
        ("/abs/evil.txt", "absolute path"),
        ("C:evil.txt", "absolute path"),
        (f"{PREFIX}/a\\b.txt", "backslash"),
        (f"{PREFIX}//b.txt", "empty, '.' or '..' path component"),
        (f"./{PREFIX}/a.txt", "empty, '.' or '..' path component"),
        (f"{PREFIX}/a{RLO}b.txt", "direction-changing"),
        (f"{PREFIX}/a\nb.txt", "control"),
    ],
)
def test_a_member_name_that_could_escape_or_deceive_is_refused_before_anything_is_written(
    tmp_path: Path, name: str, message: str
) -> None:
    path = make_zip(tmp_path / "evil.zip", [(f"{PREFIX}/ok.txt", b"ok"), (name, b"evil")])
    out = tmp_path / "md"
    with pytest.raises(z2m.ConversionError, match=re.escape(message)):
        z2m.convert(path, out)
    assert not out.exists()
    assert not (tmp_path / "evil.txt").exists()


@pytest.mark.parametrize("kind", [stat.S_IFLNK, stat.S_IFCHR, stat.S_IFIFO, stat.S_IFSOCK])
def test_links_devices_and_other_special_members_are_refused(tmp_path: Path, kind: int) -> None:
    name = f"{PREFIX}/special"
    path = make_zip(
        tmp_path / "x.zip", [(f"{PREFIX}/ok.txt", b"ok"), (name, b"/etc/passwd")], attrs={name: (kind | 0o777) << 16}
    )
    with pytest.raises(z2m.ConversionError, match="not a regular file"):
        z2m.read_archive(path)


def test_a_duplicate_member_name_is_refused(tmp_path: Path) -> None:
    with pytest.warns(UserWarning, match="Duplicate name"):
        path = make_zip(tmp_path / "x.zip", [(f"{PREFIX}/a.txt", b"1"), (f"{PREFIX}/a.txt", b"2")])
    with pytest.raises(z2m.ConversionError, match="appears twice"):
        z2m.read_archive(path)


def test_names_that_differ_only_by_case_are_refused_because_they_would_overwrite_each_other(tmp_path: Path) -> None:
    path = make_zip(tmp_path / "x.zip", [(f"{PREFIX}/A.txt", b"1"), (f"{PREFIX}/a.txt", b"2")])
    with pytest.raises(z2m.ConversionError, match="differ only by case"):
        z2m.read_archive(path)


def test_a_name_that_is_both_a_file_and_a_directory_is_refused(tmp_path: Path) -> None:
    path = make_zip(tmp_path / "x.zip", [(f"{PREFIX}/a", b"1"), (f"{PREFIX}/a/b", b"2")])
    with pytest.raises(z2m.ConversionError, match="both a file and a directory"):
        z2m.read_archive(path)


def test_an_encrypted_member_is_refused(tmp_path: Path) -> None:
    name = f"{PREFIX}/secret.txt"
    path = make_zip(tmp_path / "x.zip", [(name, b"x"), (f"{PREFIX}/ok.txt", b"ok")], encrypted=frozenset({name}))
    with pytest.raises(z2m.ConversionError, match="encrypted"):
        z2m.read_archive(path)


@pytest.mark.parametrize(
    ("limits", "entries", "message"),
    [
        (z2m.Limits(max_files=2), [("p/a", b"1"), ("p/b", b"2"), ("p/c", b"3")], "member limit"),
        (z2m.Limits(max_file_bytes=5), [("p/a", b"123456"), ("p/b", b"1")], "per-file limit"),
        (z2m.Limits(max_total_bytes=1000), [("p/a", b"\0" * 10_000), ("p/b", b"\0" * 10_000)], "add up to"),
    ],
    ids=["members", "file", "total"],
)
def test_the_size_limits_are_enforced(
    tmp_path: Path, limits: z2m.Limits, entries: Sequence[tuple[str, bytes]], message: str
) -> None:
    path = make_zip(tmp_path / "x.zip", entries)
    with pytest.raises(z2m.ConversionError, match=message):
        z2m.read_archive(path, limits)


def test_an_archive_larger_than_the_total_limit_is_refused_before_it_is_opened(tmp_path: Path) -> None:
    path = tmp_path / "big.zip"
    path.write_bytes(b"\0" * 64)
    with pytest.raises(z2m.ConversionError, match="the archive itself"):
        z2m.read_archive(path, z2m.Limits(max_total_bytes=10))


def test_a_flipped_bit_in_a_member_is_caught_by_its_crc(tmp_path: Path) -> None:
    path = make_zip(tmp_path / "x.zip", [(f"{PREFIX}/a.txt", b"hello world")], compress=zipfile.ZIP_STORED)
    blob = bytearray(path.read_bytes())
    blob[blob.index(b"hello world")] ^= 0x01
    path.write_bytes(bytes(blob))
    with pytest.raises(z2m.ConversionError, match="cannot be read"):
        z2m.read_archive(path)


@pytest.mark.parametrize("content", [b"definitely not a zip", b""], ids=["garbage", "empty"])
def test_a_file_that_is_not_a_zip_is_refused(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "x.zip"
    path.write_bytes(content)
    with pytest.raises(z2m.ConversionError, match="not a readable ZIP"):
        z2m.read_archive(path)


def test_a_missing_archive_and_an_archive_without_files_are_refused(tmp_path: Path) -> None:
    with pytest.raises(z2m.ConversionError):
        z2m.read_archive(tmp_path / "absent.zip")
    only_directories = make_zip(tmp_path / "dirs.zip", [(f"{PREFIX}/", b""), (f"{PREFIX}/sub/", b"")])
    with pytest.raises(z2m.ConversionError, match="no files"):
        z2m.read_archive(only_directories)


# ------------------------------------------------------------------------------------------------------ the output


def test_a_non_empty_output_directory_is_refused_without_force_and_left_untouched(tmp_path: Path, good: Path) -> None:
    out = tmp_path / "md"
    out.mkdir()
    (out / "notes.txt").write_text("mine")
    with pytest.raises(z2m.ConversionError, match="not empty"):
        z2m.convert(good, out)
    assert sorted(p.name for p in out.iterdir()) == ["notes.txt"]


def test_force_overwrites_what_it_generates_and_nothing_else(tmp_path: Path, good: Path) -> None:
    out = tmp_path / "md"
    z2m.convert(good, out)
    (out / "INDEX.md").write_text("stale")
    (out / "notes.txt").write_text("mine")
    z2m.convert(good, out, force=True)
    assert "stale" not in (out / "INDEX.md").read_text(encoding="utf-8")
    assert (out / "notes.txt").read_text() == "mine"


def test_an_existing_bundle_is_not_overwritten_without_force_and_nothing_else_is_written(
    tmp_path: Path, good: Path
) -> None:
    bundle = tmp_path / "BUNDLE.md"
    bundle.write_text("precious")
    with pytest.raises(z2m.ConversionError, match="already exists"):
        z2m.convert(good, tmp_path / "md", bundle=bundle)
    assert bundle.read_text() == "precious"
    assert not (tmp_path / "md" / "INDEX.md").exists()


def test_an_output_directory_that_is_a_symlink_is_refused(tmp_path: Path, good: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(z2m.ConversionError, match="symbolic link"):
        z2m.convert(good, link)
    assert list(real.iterdir()) == []


def test_a_files_directory_that_is_a_symlink_is_never_written_through(tmp_path: Path, good: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    out = tmp_path / "md"
    out.mkdir()
    (out / "files").symlink_to(elsewhere)
    with pytest.raises(z2m.ConversionError, match="symbolic link"):
        z2m.convert(good, out, force=True)
    assert list(elsewhere.iterdir()) == []


def test_an_index_that_is_a_symlink_is_never_written_through(tmp_path: Path, good: Path) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    out = tmp_path / "md"
    out.mkdir()
    (out / "INDEX.md").symlink_to(victim)
    with pytest.raises(z2m.ConversionError, match="symbolic link"):
        z2m.convert(good, out, force=True)
    assert victim.read_text() == "keep me"
    assert not (out / "files").exists() or not list((out / "files").rglob("*.md"))


# ------------------------------------------------------------------------------------------------------ command line


def test_the_command_line_converts_and_reports(tmp_path: Path, good: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "md"
    bundle = tmp_path / "all.md"
    assert z2m.main([str(good), "--out", str(out), "--bundle", str(bundle), "--title", "My export"]) == 0
    shown = capsys.readouterr().out
    assert "wrote 3 pages and INDEX.md" in shown
    assert "wrote the bundle" in shown
    assert (out / "INDEX.md").read_text(encoding="utf-8").startswith("# My export\n")


def test_the_command_line_exit_status_separates_refusal_from_misuse(
    tmp_path: Path, good: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert z2m.main([str(tmp_path / "absent.zip"), "--out", str(tmp_path / "md")]) == 1
    assert "refused" in capsys.readouterr().err
    assert z2m.main([str(good), "--out", str(tmp_path / "md2"), "--max-files", "0"]) == 2


def test_the_script_runs_isolated_as_the_makefile_and_docs_say(
    py: Callable[..., subprocess.CompletedProcess[str]], tmp_path: Path, good: Path, repo: Path
) -> None:
    result = py(repo / "tools" / "zip_to_markdown.py", good, "--out", tmp_path / "md")
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "md" / "INDEX.md").is_file()


# ------------------------------------------------------------------------------------------------------ this repository


def test_the_repository_converts_completely_and_losslessly(repo: Path, tmp_path: Path) -> None:
    archive = tmp_path / "repo.zip"
    assert pack_zip.main(["--root", str(repo), "--out", str(archive), f"--prefix={PREFIX}"]) == 0
    out = tmp_path / "md"
    bundle = tmp_path / "BUNDLE.md"
    written = z2m.convert(archive, out, bundle=bundle)

    with zipfile.ZipFile(archive) as zf:
        names = [n.removeprefix(f"{PREFIX}/") for n in zf.namelist()]
    assert written.pages == len(names)
    assert len(names) > 150  # the whole tree, not a stub

    bundle_text = bundle.read_text(encoding="utf-8")
    for rel in names:
        page = read_page(out, rel)
        facts, text = parse_page(page)
        if rel == pack_zip.MANIFEST_NAME:
            continue
        source = (repo / rel).read_bytes()
        assert facts["SHA-256"] == f"`{hashlib.sha256(source).hexdigest()}`", rel
        if is_text(source):
            assert text is not None
            assert text.encode("utf-8") == source, f"{rel} does not round-trip"
        assert f"### `{rel}`" in bundle_text, rel

    index = (out / "INDEX.md").read_text(encoding="utf-8")
    assert "every digest matches" in index
    for landmark in ("execution/", "apps/", "docs/", "tools/", "tests/", ".github/"):
        assert f"├── {landmark}" in index or f"└── {landmark}" in index, landmark
