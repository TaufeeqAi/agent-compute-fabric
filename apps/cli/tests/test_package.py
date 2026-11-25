"""The package as a whole: its metadata, its README, and what none of its files may contain.

These are checks a reviewer would otherwise make by hand at every change: that the README's table of
exit statuses is the one the code has, that no instruction fetches a package from a registry, that the
tool declares the dependencies it imports and no other, and that the client it builds is the SDK's own,
configured from nothing but what the person gave.
"""

from __future__ import annotations

import ast
import io
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

import agentcompute
import pytest
import yaml

import agentcompute_cli
from agentcompute_cli import common
from agentcompute_cli import main as entry
from agentcompute_cli.credentials import Settings
from agentcompute_cli.outcome import ExitCode
from support import BASE_URL, CANARY_KEY, PACKAGE, PROJECT, REPOSITORY

README = (PACKAGE / "README.md").read_text(encoding="utf-8")
PYPROJECT: dict[str, Any] = tomllib.loads((PACKAGE / "pyproject.toml").read_text(encoding="utf-8"))
SOURCES = sorted((PACKAGE / "src" / "agentcompute_cli").glob("*.py"))
#: What this package may import besides itself and the standard library.
ALLOWED_IMPORTS = {"agentcompute", "typer", "rich", "httpx2"}


# ---------------------------------------------------------------------------------------------- metadata
def test_the_distribution_is_the_one_that_was_asked_for() -> None:
    project = PYPROJECT["project"]
    assert project["name"] == "agent-compute-cli"
    assert project["requires-python"] == ">=3.12"
    assert project["scripts"] == {"acf": "agentcompute_cli.main:main"}
    assert PYPROJECT["build-system"]["build-backend"] == "hatchling.build"
    assert PYPROJECT["tool"]["hatch"]["version"]["path"] == "src/agentcompute_cli/_version.py"
    assert agentcompute_cli.__version__ == "0.1.0"


def _names(requirements: list[str]) -> dict[str, str]:
    return {re.split(r"[<>=!~ ]", line, maxsplit=1)[0]: line for line in requirements}


def test_the_runtime_dependencies_are_the_four_that_earn_their_place() -> None:
    declared = _names(PYPROJECT["project"]["dependencies"])
    assert set(declared) == {"agent-compute", "typer", "rich", "httpx2"}
    for line in declared.values():
        assert ">=" in line, f"{line}: a floor, the version the tests ran against"
        assert "<" in line, f"{line}: and a cap, the next line that may break"


def test_the_sdk_is_the_one_of_this_repository_during_development_and_a_range_when_published() -> None:
    source = PYPROJECT["tool"]["uv"]["sources"]["agent-compute"]
    assert (PACKAGE / source["path"]).resolve() == REPOSITORY / "sdks" / "python"
    declared = _names(PYPROJECT["project"]["dependencies"])["agent-compute"]
    major, minor, _patch = agentcompute.__version__.split(".")
    assert declared == f"agent-compute>={major}.{minor}.0,<{major}.{int(minor) + 1}"


def test_the_http_library_has_the_range_the_sdk_declares() -> None:
    sdk = tomllib.loads((REPOSITORY / "sdks" / "python" / "pyproject.toml").read_text(encoding="utf-8"))
    theirs = _names(sdk["project"]["dependencies"])["httpx2"]
    assert _names(PYPROJECT["project"]["dependencies"])["httpx2"] == theirs


def test_every_dependency_is_locked_with_the_hash_of_each_file() -> None:
    lock = tomllib.loads((PACKAGE / "uv.lock").read_text(encoding="utf-8"))
    packages = {package["name"]: package for package in lock["package"]}
    assert {"typer", "rich", "httpx2", "agent-compute", "agent-compute-cli"} <= set(packages)
    for name, package in packages.items():
        if "registry" not in package.get("source", {}):
            continue
        files = [*package.get("wheels", []), *([package["sdist"]] if "sdist" in package else [])]
        assert files, name
        assert all(file["hash"].startswith("sha256:") for file in files), name


def _imported(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module is not None:
            names.add(node.module.split(".")[0])
    return names


def test_the_package_imports_what_it_declares_and_nothing_else() -> None:
    third_party: set[str] = set()
    for path in SOURCES:
        third_party |= {
            name for name in _imported(path) if name not in sys.stdlib_module_names and name != "agentcompute_cli"
        }
    assert third_party == ALLOWED_IMPORTS


def test_only_the_public_surface_of_the_sdk_is_used() -> None:
    """``from agentcompute import ...`` and nothing deeper: what is not exported there is not this tool's to use."""
    exported = set(agentcompute.__all__)
    for path in SOURCES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module is not None and node.module.startswith("agentcompute."):
                pytest.fail(f"{path.name} imports from {node.module}")
            if isinstance(node, ast.ImportFrom) and node.module == "agentcompute":
                assert {alias.name for alias in node.names} <= exported, path.name
            if isinstance(node, ast.Attribute) and node.attr.startswith("_") and not node.attr.startswith("__"):
                owner = node.value
                assert isinstance(owner, ast.Name), f"{path.name}:{node.lineno} reaches into {node.attr}"
                assert owner.id in {"self", "cls"}, f"{path.name}:{node.lineno} reaches into {node.attr}"


def test_the_one_command_that_does_not_go_through_the_sdk_is_the_relay() -> None:
    users = {path.name for path in SOURCES if "httpx2" in _imported(path)}
    assert users == {"relay.py", "mcp.py"}


def test_this_tool_opens_no_socket_of_its_own_and_starts_no_program() -> None:
    for path in SOURCES:
        forbidden = {"socket", "subprocess", "urllib3", "requests", "ssl"}
        if path.name == "mcp.py":
            # The relay tells its HTTP client whom to believe: it builds that context and opens nothing with it.
            forbidden -= {"ssl"}
        assert not (_imported(path) & forbidden), path.name


def test_the_relay_uses_the_tls_module_for_one_thing(tmp_path: Path) -> None:
    """A context made from a file of authorities, and nothing else of that module: no socket is wrapped here."""
    source = next(path for path in SOURCES if path.name == "mcp.py").read_text(encoding="utf-8")
    used = set(re.findall(r"\bssl\.([A-Za-z_]+)", source))
    assert used == {"SSLContext", "create_default_context"}


# ------------------------------------------------------------------------------------------- the client
def test_the_client_a_command_builds_is_the_sdks_own_and_shows_no_key() -> None:
    settings = Settings(CANARY_KEY, BASE_URL, PROJECT, {})
    for timeout in (None, 30.0):
        with common.new_fabric(settings, timeout=timeout) as fabric:
            assert isinstance(fabric, agentcompute.Fabric)
            assert BASE_URL in repr(fabric)
            assert CANARY_KEY not in repr(fabric)


# ---------------------------------------------------------------------------------------- the entry point
def test_the_entry_point_makes_both_streams_lenient_before_it_runs_a_command(monkeypatch: pytest.MonkeyPatch) -> None:
    written = io.BytesIO()
    out = io.TextIOWrapper(written, encoding="cp1252", errors="strict")
    err = io.TextIOWrapper(io.BytesIO(), encoding="ascii", errors="strict")
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    monkeypatch.setattr(sys, "argv", ["acf", "--version"])
    with pytest.raises(SystemExit) as stopped:
        entry.main()
    assert stopped.value.code == 0
    assert (out.errors, err.errors) == ("backslashreplace", "backslashreplace")
    out.flush()
    assert written.getvalue() == f"acf {agentcompute_cli.__version__} (SDK {agentcompute.__version__})\n".encode()


# ----------------------------------------------------------------------------------------------- README
def test_the_readme_lists_every_exit_status_and_no_other() -> None:
    rows = re.findall(r"^\| (\d+) \| (.+) \|$", README, flags=re.MULTILINE)
    assert [int(status) for status, _ in rows] == sorted(int(code) for code in ExitCode)
    assert all(meaning.strip() for _, meaning in rows)


def test_the_readme_names_no_package_to_fetch_from_a_registry() -> None:
    assert re.search(r"pipx|uvx|uv tool|npx|npm (install|i)\b", README) is None
    installs = re.findall(r"^.*pip3? install.*$", README, flags=re.MULTILINE)
    assert installs == ["python -m pip install ./sdks/python ./apps/cli"], "only this checkout is ever installed from"
    assert "not registered on any package index yet" in README
    for name in ("agent-compute", "agentcompute"):
        assert name not in README, f"{name}: a name is a thing someone could go and install"


def test_the_readme_says_where_the_credential_is_stored_and_how_an_agent_host_is_set_up() -> None:
    assert "$XDG_CONFIG_HOME/acf/credentials.json" in README
    assert "%APPDATA%\\acf\\credentials.json" in README
    assert "0600" in README
    assert "0700" in README
    snippet = README.partition('"mcpServers"')[2].partition("```")[0]
    command = re.search(r'"command": "([^"]+)"', snippet)
    assert command is not None
    assert command.group(1).startswith("/"), "a path on this machine, not something a launcher would fetch"
    assert '"mcp"' in snippet
    assert "ACF_API_KEY" in snippet


def test_the_readme_lists_every_command_of_the_api_table() -> None:
    surface = yaml.safe_load((REPOSITORY / "protocols" / "api" / "surface.yaml").read_text(encoding="utf-8"))
    synopsis = README.partition("## Commands")[2].partition("```text")[2].partition("```")[0]
    listed = " ".join(synopsis.split())
    for row in surface["operations"]:
        if row["cli"] is None:
            continue
        group, _, action = row["cli"].removeprefix("acf ").rpartition(" ")
        assert f"acf {group}".strip() in listed, row["cli"]
        assert action in listed, row["cli"]


def test_examples_use_addresses_nobody_owns() -> None:
    for host in re.findall(r"https?://([A-Za-z0-9.-]+)", README):
        assert host.endswith(".example"), f"{host}: an example address is one reserved for examples"


# ---------------------------------------------------------------------------------------------- hygiene
#: What a tool leaves in the package's directory and no commit holds: caches, environments, build output.
_NOT_SOURCE = {"__pycache__", "build", "dist", "htmlcov"}


def _files() -> list[Path]:
    """The files of the package itself. A hidden directory or file is a tool's, and so is build output."""
    kept = []
    for path in sorted(PACKAGE.rglob("*")):
        parts = path.relative_to(PACKAGE).parts
        left_by_a_tool = any(
            part.startswith(".") or part in _NOT_SOURCE or part.endswith(".egg-info") for part in parts
        )
        if path.is_file() and not left_by_a_tool:
            kept.append(path)
    return kept


def test_the_files_of_the_package_are_found_whatever_a_tool_left_beside_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A type checker's cache is a database, not text: the checks below read the package and nothing else."""
    package = tmp_path / "package"
    (package / "src").mkdir(parents=True)
    (package / "src" / "module.py").write_text("x = 1\n", encoding="utf-8")
    (package / "README.md").write_text("words\n", encoding="utf-8")
    left_by_tools = (
        ".mypy_cache/3.12/cache.db",
        ".ruff_cache/x",
        ".coverage",
        ".venv/pyvenv.cfg",
        "dist/x.whl",
        "src/__pycache__/m.pyc",
    )
    for left in left_by_tools:
        (package / left).parent.mkdir(parents=True, exist_ok=True)
        (package / left).write_bytes(b"SQLite format 3\x00\xd0\xff")
    monkeypatch.setattr(sys.modules[__name__], "PACKAGE", package)
    assert [path.relative_to(package).as_posix() for path in _files()] == ["README.md", "src/module.py"]


def test_no_file_of_this_package_holds_a_word_it_may_not() -> None:
    """Things are named by what they are, never by the stage of a plan they were built in."""
    stage = re.compile("pha" + "se", re.IGNORECASE)
    unfinished = re.compile(r"\b(TO" + r"DO|FIX" + r"ME|X" + r"XX)\b")
    files = _files()
    assert len(files) > 25
    for path in files:
        text = path.read_text(encoding="utf-8")
        assert stage.search(text) is None, path.relative_to(PACKAGE)
        assert unfinished.search(text) is None, path.relative_to(PACKAGE)
        assert "arti" + "facts/" not in text, path.relative_to(PACKAGE)


def test_every_module_says_what_it_is_for() -> None:
    for path in SOURCES:
        module = ast.parse(path.read_text(encoding="utf-8"))
        assert ast.get_docstring(module), path.name
