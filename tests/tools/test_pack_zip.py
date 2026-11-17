"""tools/pack_zip.py: a reproducible source archive that carries its own sha256 manifest."""

from __future__ import annotations

import hashlib
import os
import re
import shlex
import stat
import zipfile
from pathlib import Path

import pytest

import pack_zip

PREFIX = "proj"


def write_tree(root: Path, files: dict[str, bytes | str], *, executable: frozenset[str] = frozenset()) -> Path:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode())
        path.chmod(0o755 if rel in executable else 0o644)
    return root


def pack(root: Path, out: Path, *extra: str, prefix: str = PREFIX) -> int:
    return pack_zip.main(["--root", str(root), "--out", str(out), f"--prefix={prefix}", *extra])


def members(archive: Path) -> dict[str, zipfile.ZipInfo]:
    with zipfile.ZipFile(archive) as zf:
        return {i.filename.removeprefix(f"{PREFIX}/"): i for i in zf.infolist()}


# ---------------------------------------------------------------------------------------------------- reproducibility


def test_members_are_sorted_under_one_prefix_with_fixed_metadata(tmp_path: Path) -> None:
    root = write_tree(
        tmp_path / "src",
        {"b.txt": "b", "a/z.py": "z", "a/y.sh": "#!/bin/sh\n", "A.txt": "A"},
        executable=frozenset({"a/y.sh"}),
    )
    out = tmp_path / "out" / "x.zip"
    assert pack(root, out) == 0

    with zipfile.ZipFile(out) as zf:
        infos = zf.infolist()
    names = [i.filename for i in infos]
    assert names == [f"{PREFIX}/{n}" for n in ("A.txt", "MANIFEST.sha256", "a/y.sh", "a/z.py", "b.txt")]
    for info in infos:
        assert info.date_time == (1980, 1, 1, 0, 0, 0)
        assert info.create_system == 3
        assert info.compress_type == zipfile.ZIP_DEFLATED
        assert info.extra == b""
        assert info.comment == b""
        assert not info.is_dir()
    modes = {i.filename.removeprefix(f"{PREFIX}/"): stat.S_IMODE(i.external_attr >> 16) for i in infos}
    assert modes == {"A.txt": 0o644, "MANIFEST.sha256": 0o644, "a/y.sh": 0o755, "a/z.py": 0o644, "b.txt": 0o644}


def test_the_same_content_gives_the_same_bytes_whatever_the_timestamps_or_creation_order(tmp_path: Path) -> None:
    files: dict[str, bytes | str] = {"one.txt": "1", "two/three.txt": "3", "two/four.sh": "#!/bin/sh\n"}
    a = write_tree(tmp_path / "a", files, executable=frozenset({"two/four.sh"}))
    b = write_tree(tmp_path / "b", dict(reversed(list(files.items()))), executable=frozenset({"two/four.sh"}))
    for path in b.rglob("*"):
        os.utime(path, (1_000_000_000, 1_000_000_000))
    assert pack(a, tmp_path / "a.zip") == 0
    assert pack(b, tmp_path / "b.zip") == 0
    assert (tmp_path / "a.zip").read_bytes() == (tmp_path / "b.zip").read_bytes()


def test_a_changed_byte_changes_the_archive(tmp_path: Path) -> None:
    root = write_tree(tmp_path / "src", {"a.txt": "one"})
    assert pack(root, tmp_path / "1.zip") == 0
    (root / "a.txt").write_text("two")
    assert pack(root, tmp_path / "2.zip") == 0
    assert (tmp_path / "1.zip").read_bytes() != (tmp_path / "2.zip").read_bytes()


def test_the_embedded_manifest_is_in_sha256sum_format_and_sorted(tmp_path: Path) -> None:
    root = write_tree(tmp_path / "src", {"b.txt": "bee", "a.txt": "ay", "d/c.txt": "sea"})
    out = tmp_path / "x.zip"
    assert pack(root, out) == 0
    with zipfile.ZipFile(out) as zf:
        manifest = zf.read(f"{PREFIX}/MANIFEST.sha256").decode()
    expected = "".join(
        f"{hashlib.sha256(content).hexdigest()}  {name}\n"
        for name, content in (("a.txt", b"ay"), ("b.txt", b"bee"), ("d/c.txt", b"sea"))
    )
    assert manifest == expected
    assert all(re.fullmatch(r"[0-9a-f]{64}  \S+", line) for line in manifest.splitlines())


def test_the_archive_file_is_readable_by_whoever_receives_it(tmp_path: Path) -> None:
    root = write_tree(tmp_path / "src", {"a.txt": "a"})
    out = tmp_path / "x.zip"
    assert pack(root, out) == 0
    assert stat.S_IMODE(out.stat().st_mode) == 0o644  # mkstemp would have left 0600


# ---------------------------------------------------------------------------------------------------- what is left out


@pytest.mark.parametrize(
    "rel",
    [
        "target/debug/acf-host",
        "dist/x.zip",
        ".git/config",
        "a/__pycache__/m.cpython-313.pyc",
        "m.pyc",
        "m.pyo",
        "m.pyd",
        ".venv/bin/python",
        "venv/lib/x.py",
        "node_modules/x/index.js",
        ".mypy_cache/3.12/x.json",
        ".ruff_cache/x",
        "apps/cli/.pytest_cache/v/x",
        ".coverage",
        "apps/cli/.coverage",
        ".coverage.host.123",
        ".DS_Store",
        "docs/.DS_Store",
        "run.log",
        ".env",
        ".env.local",
        "x.swp",
        ".idea/workspace.xml",
        ".vscode/settings.json",
        "pkg.egg-info/PKG-INFO",
        "htmlcov/index.html",
    ],
)
def test_build_output_caches_and_secrets_are_left_out(tmp_path: Path, rel: str) -> None:
    root = write_tree(tmp_path / "src", {"keep.txt": "k", rel: "x"})
    out = tmp_path / "x.zip"
    assert pack(root, out) == 0
    assert set(members(out)) == {"keep.txt", "MANIFEST.sha256"}


@pytest.mark.parametrize(
    "rel",
    [".env.example", ".gitignore", ".github/workflows/ci.yml", "src/target/lib.rs", "docs/dist/notes.md", "Makefile"],
)
def test_ordinary_files_that_look_like_ignored_ones_are_kept(tmp_path: Path, rel: str) -> None:
    root = write_tree(tmp_path / "src", {rel: "x"})
    out = tmp_path / "x.zip"
    assert pack(root, out) == 0
    assert rel in members(out)


def gitignore_samples(pattern: str) -> list[str]:
    """Representative paths that a .gitignore pattern covers (enough for the patterns this repository uses)."""
    is_dir = pattern.endswith("/")
    body = pattern.strip("/")
    variants = [body]
    if (m := re.search(r"\[([^\]]+)\]", body)) is not None:
        variants = [body[: m.start()] + ch + body[m.end() :] for ch in m.group(1)]
    variants = [v.replace("*", "sample") for v in variants]
    return [f"{v}/sample.txt" if is_dir else v for v in variants]


def test_the_exclusions_cover_every_pattern_in_the_repositorys_gitignore(repo: Path) -> None:
    patterns = [
        line.strip()
        for line in (repo / ".gitignore").read_text().splitlines()
        if line.strip() and not line.startswith("#") and not line.startswith("!")
    ]
    assert len(patterns) >= 15  # the parser is reading the real file
    missed = [
        (pattern, sample)
        for pattern in patterns
        for sample in gitignore_samples(pattern)
        if not pack_zip.is_excluded(sample, is_dir=False)
    ]
    assert not missed, f"add these .gitignore patterns to pack_zip.py (or the archive will ship them): {missed}"
    assert not pack_zip.is_excluded(".env.example", is_dir=False)  # the `!.env.example` line


def test_root_only_patterns_do_not_swallow_nested_directories_of_the_same_name() -> None:
    assert pack_zip.is_excluded("target/x", is_dir=False)
    assert not pack_zip.is_excluded("src/target/x", is_dir=False)
    assert pack_zip.is_excluded("dist", is_dir=True)
    assert not pack_zip.is_excluded("docs/dist", is_dir=True)


# ---------------------------------------------------------------------------------------------------- what is refused


def test_a_symbolic_link_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = write_tree(tmp_path / "src", {"real.txt": "r"})
    (root / "link.txt").symlink_to("real.txt")
    out = tmp_path / "x.zip"
    assert pack(root, out) == 1
    assert "link.txt: refusing to archive a symbolic link" in capsys.readouterr().err
    assert not out.exists()


def test_a_symlinked_excluded_directory_is_ignored_not_refused(tmp_path: Path) -> None:
    root = write_tree(tmp_path / "src", {"keep.txt": "k"})
    (root / ".venv").symlink_to(tmp_path)
    out = tmp_path / "x.zip"
    assert pack(root, out) == 0
    assert set(members(out)) == {"keep.txt", "MANIFEST.sha256"}


def test_a_fifo_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = write_tree(tmp_path / "src", {"keep.txt": "k"})
    os.mkfifo(root / "pipe")
    assert pack(root, tmp_path / "x.zip") == 1
    assert "special file" in capsys.readouterr().err


def test_an_oversized_file_is_refused_and_nothing_is_written(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = write_tree(tmp_path / "src", {"big.bin": b"x" * 11, "small.txt": "s"})
    out = tmp_path / "out" / "x.zip"
    assert pack(root, out, "--max-file-bytes", "10") == 1
    assert "big.bin: 11 bytes exceeds --max-file-bytes 10" in capsys.readouterr().err
    assert not out.parent.exists()


@pytest.mark.parametrize(
    "name", ["bad\nname.txt", "bad" + chr(0x202E) + "name.txt", "bad\\name.txt", "bad\x1bname.txt"]
)
def test_names_that_would_confuse_a_reader_or_a_tool_are_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], name: str
) -> None:
    root = write_tree(tmp_path / "src", {"ok.txt": "k", name: "x"})
    assert pack(root, tmp_path / "x.zip") == 1
    assert "name contains" in capsys.readouterr().err


def test_a_hand_written_file_called_like_the_manifest_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = write_tree(tmp_path / "src", {"MANIFEST.sha256": "not ours"})
    assert pack(root, tmp_path / "x.zip") == 1
    assert "reserved" in capsys.readouterr().err


def unpack(archive: Path, destination: Path) -> Path:
    """What `unzip` does, executable bits included (``ZipFile.extractall`` drops them). Returns the prefix directory."""
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            target = destination / info.filename
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(zf.read(info))
            target.chmod(stat.S_IMODE(info.external_attr >> 16))
    return destination / PREFIX


def test_an_unpacked_archive_packs_back_to_the_same_bytes(tmp_path: Path) -> None:
    root = write_tree(
        tmp_path / "src",
        {"a.txt": "a", "d/run.sh": "#!/bin/sh\n", "d/e/f.py": "x = 1\n"},
        executable=frozenset({"d/run.sh"}),
    )
    first = tmp_path / "first.zip"
    assert pack(root, first) == 0
    unpacked = unpack(first, tmp_path / "unpacked")
    assert (unpacked / "MANIFEST.sha256").is_file(), "the premise: an unpacked tree carries its own manifest"
    second = tmp_path / "second.zip"
    assert pack(unpacked, second) == 0
    assert second.read_bytes() == first.read_bytes()


@pytest.mark.parametrize("change", ["edit", "add", "delete"])
def test_an_unpacked_tree_that_no_longer_matches_its_manifest_is_refused_until_the_manifest_is_deleted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], change: str
) -> None:
    root = write_tree(tmp_path / "src", {"a.txt": "a", "b.txt": "b"})
    first = tmp_path / "first.zip"
    assert pack(root, first) == 0
    unpacked = unpack(first, tmp_path / "unpacked")
    if change == "edit":
        (unpacked / "a.txt").write_text("changed")
    elif change == "add":
        (unpacked / "c.txt").write_text("new")
    else:
        (unpacked / "b.txt").unlink()
    capsys.readouterr()
    second = tmp_path / "second.zip"
    assert pack(unpacked, second) == 1
    err = capsys.readouterr().err
    assert "reserved" in err, err
    assert "delete it and pack again" in err, err
    assert not second.exists()

    (unpacked / "MANIFEST.sha256").unlink()
    assert pack(unpacked, second) == 0
    assert "MANIFEST.sha256" in members(second)


def test_a_file_called_like_the_manifest_below_the_root_is_an_ordinary_file(tmp_path: Path) -> None:
    root = write_tree(tmp_path / "src", {"a.txt": "a", "docs/MANIFEST.sha256": "mine"})
    out = tmp_path / "x.zip"
    assert pack(root, out) == 0
    assert set(members(out)) == {"a.txt", "docs/MANIFEST.sha256", "MANIFEST.sha256"}


@pytest.mark.parametrize("prefix", ["", "../x", "a/b", ".hidden", "x y", "-x"])
def test_the_prefix_must_be_one_plain_directory_name(tmp_path: Path, prefix: str) -> None:
    root = write_tree(tmp_path / "src", {"a.txt": "a"})
    assert pack(root, tmp_path / "x.zip", prefix=prefix) == 2
    assert not (tmp_path / "x.zip").exists()


def test_a_missing_root_or_an_output_directory_is_a_usage_error(tmp_path: Path) -> None:
    assert pack(tmp_path / "nope", tmp_path / "x.zip") == 2
    root = write_tree(tmp_path / "src", {"a.txt": "a"})
    (tmp_path / "adir").mkdir()
    assert pack(root, tmp_path / "adir") == 2


# ---------------------------------------------------------------------------------------------------- behaviour


def test_an_archive_written_inside_the_tree_does_not_contain_its_previous_self(tmp_path: Path) -> None:
    root = write_tree(tmp_path / "src", {"a.txt": "a"})
    out = root / "x.zip"
    assert pack(root, out) == 0
    assert pack(root, out) == 0
    assert set(members(out)) == {"a.txt", "MANIFEST.sha256"}


def test_list_mode_describes_every_member_and_writes_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = write_tree(tmp_path / "src", {"a.txt": "ay", "run.sh": "#!/bin/sh\n"}, executable=frozenset({"run.sh"}))
    out = tmp_path / "x.zip"
    assert pack(root, out, "--list") == 0
    shown = capsys.readouterr().out
    assert f"{hashlib.sha256(b'ay').hexdigest()}  {PREFIX}/a.txt" in shown
    assert re.search(rf"^x +\d+  [0-9a-f]{{64}}  {PREFIX}/run\.sh$", shown, re.MULTILINE)
    assert "nothing written" in shown
    assert not out.exists()


def test_a_failure_while_writing_keeps_the_previous_archive_and_leaves_no_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = write_tree(tmp_path / "src", {"a.txt": "a", "b.txt": "b"})
    out = tmp_path / "out" / "x.zip"
    assert pack(root, out) == 0
    before = out.read_bytes()

    calls = 0
    real = pack_zip.read_entry

    def flaky(entry: pack_zip.Entry, max_file_bytes: int) -> bytes:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("disk on fire")
        return real(entry, max_file_bytes)

    monkeypatch.setattr(pack_zip, "read_entry", flaky)
    with pytest.raises(OSError, match="disk on fire"):
        pack(root, out)
    assert out.read_bytes() == before
    assert [p.name for p in out.parent.iterdir()] == ["x.zip"]


def test_the_summary_line_reports_the_archive_checksum(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = write_tree(tmp_path / "src", {"a.txt": "a"})
    out = tmp_path / "x.zip"
    assert pack(root, out) == 0
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    assert f"sha256 {digest}" in capsys.readouterr().out


# ---------------------------------------------------------------------------------------------------- this repository


def test_the_repository_packs_with_executables_intact_and_no_build_output(repo: Path, tmp_path: Path) -> None:
    out = tmp_path / "repo.zip"
    assert pack_zip.main(["--root", str(repo), "--out", str(out), "--prefix", PREFIX]) == 0
    with zipfile.ZipFile(out) as zf:
        by_name = {i.filename.removeprefix(f"{PREFIX}/"): i for i in zf.infolist()}
        for must_have in (
            "Makefile",
            "Cargo.toml",
            "Cargo.lock",
            "MANIFEST.sha256",
            ".gitignore",
            ".github/workflows/ci.yml",
            "docs/ARCHITECTURE.md",
            "tools/pack_zip.py",
            "tools/zip_to_markdown.py",
        ):
            assert must_have in by_name, must_have
        junk = [
            n
            for n in by_name
            if n.startswith(("target/", "dist/", ".git/")) or "__pycache__" in n or n.endswith(".pyc")
        ]
        assert not junk
        for name, info in by_name.items():
            if zf.read(info).startswith(b"#!/"):
                assert stat.S_IMODE(info.external_attr >> 16) == 0o755, (
                    f"{name} starts with a shebang but is not executable"
                )
        assert max(i.file_size for i in by_name.values()) < 1024 * 1024  # a source archive, not a blob store


def test_the_makefile_dist_recipe_uses_only_flags_the_packer_accepts(repo: Path) -> None:
    recipe = re.search(r"tools/pack_zip\.py (.+)", (repo / "Makefile").read_text())
    assert recipe is not None
    args = shlex.split(recipe.group(1).replace("$(DIST_DIR)", "dist").replace("$(DIST_NAME)", "name"))
    parsed = pack_zip.build_parser().parse_args(args)
    assert parsed.prefix == "name"
    assert parsed.out == Path("dist/name.zip")
    assert parsed.root == Path()
