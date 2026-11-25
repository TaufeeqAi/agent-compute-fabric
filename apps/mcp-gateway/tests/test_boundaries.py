"""What this process can reach, read from its imports.

An edge process holds nothing: no host credential, no store. It can hold nothing only if it cannot
load the code that does, so the adapter and everything it imports are checked for the core's modules,
both in a fresh interpreter after import and in the source.
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

import acf_mcp

SOURCES = Path(acf_mcp.__file__).resolve().parent
#: The role that verifies, decides and holds the host credential and the store.
CORE = "acf_api.core"
#: Modules a process needs to open a connection of its own. The adapter's only peer is the core, and
#: it reaches the core through the command client.
NETWORK_CLIENTS = frozenset(
    {"httpx2", "httpx", "httpcore2", "requests", "aiohttp", "urllib3", "socket", "ssl", "http", "ftplib", "smtplib"}
)

#: An interpreter that takes nothing from the environment of the test run, and writes no bytecode
#: beside the sources it imports.
FRESH = ("-I", "-B")

IMPORT_EVERYTHING = """
import importlib, json, pkgutil, sys
import acf_mcp
names = ["acf_mcp"] + [m.name for m in pkgutil.walk_packages(acf_mcp.__path__, "acf_mcp.")]
for name in names:
    importlib.import_module(name)
print(json.dumps({"imported": names, "loaded": sorted(sys.modules)}))
"""


def modules() -> list[Path]:
    found = sorted(SOURCES.rglob("*.py"))
    assert len(found) >= 9
    return found


def imported_by(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), filename=str(path))):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None and node.level == 0:
            names.add(node.module)
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
    return names


def test_a_process_that_loads_the_whole_adapter_loads_no_module_of_the_core() -> None:
    """Every module of the package is imported in an interpreter that has imported nothing else."""
    completed = subprocess.run(  # noqa: S603 - the interpreter running this test, and a script written above
        [sys.executable, *FRESH, "-c", IMPORT_EVERYTHING], capture_output=True, text=True, check=True, timeout=120
    )
    report = json.loads(completed.stdout)
    assert {"acf_mcp.cli", "acf_mcp.gateway", "acf_mcp.relay", "acf_mcp.render", "acf_mcp.server"} <= set(
        report["imported"]
    )
    loaded = set(report["loaded"])
    # The check can see what it is looking for: the command interface, which the adapter does use, is there.
    assert "acf_api.command.client" in loaded
    assert "acf_api.edge.config" in loaded
    assert sorted(name for name in loaded if name == CORE or name.startswith(CORE + ".")) == []


def test_no_source_file_imports_or_names_the_core() -> None:
    for path in modules():
        imports = imported_by(path)
        assert not {name for name in imports if name == CORE or name.startswith(CORE + ".")}, path.name
        # Not by a string either, which is how a module is loaded without an import statement.
        assert CORE not in path.read_text(encoding="utf-8"), path.name


def test_the_adapter_imports_nothing_it_could_open_a_connection_with() -> None:
    """It forwards the caller's credential to no service, because it has no client to forward it with."""
    for path in modules():
        roots = {name.split(".")[0] for name in imported_by(path)}
        assert roots & NETWORK_CLIENTS == set(), path.name


def test_what_the_adapter_imports_from_the_platform_is_the_command_interface_and_the_edge_configuration() -> None:
    used: set[str] = set()
    for path in modules():
        used.update(name for name in imported_by(path) if name.startswith("acf_api"))
    packages = {".".join(name.split(".")[:3]) for name in used}
    assert packages <= {
        "acf_api.command.answers",
        "acf_api.command.client",
        "acf_api.command.commands",
        "acf_api.command.errors",
        "acf_api.edge.config",
    }
