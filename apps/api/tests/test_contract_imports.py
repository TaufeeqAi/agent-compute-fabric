"""The edge holds nothing: no module that parses caller bytes can reach the code that decides.

Proves the static half of EC-2 and INV-121 (no process that decodes caller bytes holds the host peer
credential or can open the store): no module of the edge role and no module of the command interface
imports a module of the core, by any way of importing; an interpreter that has loaded the REST adapter
has loaded no module of the core and no database engine; and the command interface, which both roles
and every protocol adapter import, depends on no web framework and on no agent-protocol library.
Catalog entry: T3-EC-01 at the static level. What an edge *process* can open, by its operating-system
identity, is a property of a deployment and is proven there.

The first half of this file tests the detector itself: a lint that cannot find a planted import proves
nothing by finding none.
"""

from __future__ import annotations

import ast
import fnmatch
import functools
import json
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

import pytest

API = Path(__file__).resolve().parents[1]
SRC = API / "src"
PACKAGE = SRC / "acf_api"
#: The packages no module of which may reach the core.
GUARDED = ("edge", "command")
CORE = "acf_api.core"
#: Ways to import by a name computed at run time. A module that holds nothing has no use for one.
#: Called by their bare name, and called as an attribute of whatever holds them (`re.compile` is not one).
DYNAMIC_NAMES = {"__import__", "import_module", "exec", "eval", "compile"}
DYNAMIC_ATTRIBUTES = {
    "__import__",
    "import_module",
    "spec_from_file_location",
    "module_from_spec",
    "run_module",
    "run_path",
}
DYNAMIC_MODULES = {"importlib", "runpy", "pkgutil", "imp", "zipimport"}
WEB_FRAMEWORKS = {
    "starlette",
    "uvicorn",
    "fastapi",
    "flask",
    "aiohttp",
    "django",
    "tornado",
    "sanic",
    "quart",
    "hypercorn",
    "gunicorn",
    "werkzeug",
}
AGENT_PROTOCOL_LIBRARIES = {"mcp", "fastmcp"}


@dataclass(frozen=True)
class Finding:
    line: int
    what: str


def _is_core(module: str) -> bool:
    return module == CORE or module.startswith(CORE + ".")


def _docstrings(tree: ast.AST) -> set[int]:
    """The nodes that are documentation: a string that only describes is not a way to import."""
    found: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef) and node.body:
            first = node.body[0]
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                found.add(id(first.value))
    return found


def _resolve(package: str, level: int, module: str | None) -> str | None:
    """The absolute name a relative import means, or ``None`` when it climbs out of the top package."""
    if level == 0:
        return module or ""
    parts = package.split(".")
    if level - 1 > len(parts) - 1:
        return None
    base = parts[: len(parts) - (level - 1)]
    return ".".join([*base, *(module.split(".") if module else [])])


def _in_import(node: ast.Import) -> list[str]:
    found = [f"import {alias.name}" for alias in node.names if _is_core(alias.name)]
    found += [
        f"dynamic import machinery: {alias.name}" for alias in node.names if alias.name.split(".")[0] in DYNAMIC_MODULES
    ]
    return found


def _in_import_from(node: ast.ImportFrom, package: str) -> list[str]:
    base = _resolve(package, node.level, node.module)
    if base is None:
        return ["a relative import that leaves the package"]
    found = [f"dynamic import machinery: {base}"] if base.split(".")[0] in DYNAMIC_MODULES else []
    for alias in node.names:
        target = f"{base}.{alias.name}" if base else alias.name
        if _is_core(base) or _is_core(target):
            found.append(f"from {'.' * node.level}{node.module or ''} import {alias.name}")
    return found


def _in_call(node: ast.Call) -> list[str]:
    if isinstance(node.func, ast.Name) and node.func.id in DYNAMIC_NAMES:
        return [f"dynamic import machinery: {node.func.id}()"]
    if isinstance(node.func, ast.Attribute) and node.func.attr in DYNAMIC_ATTRIBUTES:
        return [f"dynamic import machinery: .{node.func.attr}()"]
    return []


def findings(source: str, module: str, *, is_package: bool = False) -> list[Finding]:
    """Every way in which ``source``, as the module ``module``, reaches or could reach the core."""
    tree = ast.parse(source)
    package = module if is_package else module.rpartition(".")[0]
    documentation = _docstrings(tree)
    out: set[Finding] = set()
    for node in ast.walk(tree):
        found: list[str] = []
        if isinstance(node, ast.Import):
            found = _in_import(node)
        elif isinstance(node, ast.ImportFrom):
            found = _in_import_from(node, package)
        elif isinstance(node, ast.Call):
            found = _in_call(node)
        elif (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in documentation
            and CORE in node.value
        ):
            found = ["the name of the core in a string that is not documentation"]
        out.update(Finding(getattr(node, "lineno", 0), what) for what in found)
    return sorted(out, key=lambda finding: (finding.line, finding.what))


def guarded_modules() -> list[tuple[str, Path]]:
    found = []
    for name in GUARDED:
        for path in sorted((PACKAGE / name).rglob("*.py")):
            relative = path.relative_to(SRC).with_suffix("")
            parts = relative.parts[:-1] if relative.name == "__init__" else relative.parts
            found.append((".".join(parts), path))
    return found


def third_party_roots(source: str) -> set[str]:
    """The top-level packages a module imports that are neither the standard library nor this package."""
    roots: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return {root for root in roots if root not in sys.stdlib_module_names and root not in {"acf_api", "__future__"}}


# ------------------------------------------------------------------------------- the detector
IN_THE_EDGE = "acf_api.edge.http.app"

FORBIDDEN = [
    "import acf_api.core",
    "import acf_api.core.store.engine as engine",
    "import os, acf_api.core.config",
    "from acf_api.core import config",
    "from acf_api.core.pipeline.service import RuntimeService",
    "from acf_api.core.store import engine as e, ledger",
    "from acf_api import core",
    "from acf_api import command, core",
    "from acf_api import core as c",
    "from ... import core",
    "from ...core import config",
    "from ...core.store import engine",
    "from ...core.pipeline.service import RuntimeService",
    "def late():\n    import acf_api.core.config",
    "def late():\n    from acf_api.core import config\n    return config",
    "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from acf_api.core.config import CoreConfig",
    "try:\n    from acf_api.core import config\nexcept ImportError:\n    config = None",
    "class C:\n    from acf_api.core import config",
    "import importlib",
    "import importlib\nimportlib.import_module('acf_api.core')",
    "import importlib as il\nil.import_module('acf_api.' + 'core')",
    "from importlib import import_module\nimport_module('.core', 'acf_api')",
    "import importlib.util",
    "import runpy",
    "import pkgutil",
    "__import__('acf_api.core')",
    "name = 'core'\n__import__('acf_api.' + name)",
    "import builtins\nbuiltins.__import__('acf_api.core')",
    "exec('import acf_api.core')",
    "eval('__import__(\"acf_api.core\")')",
    "import sys\nmodule = sys.modules.get('acf_api.core')",
    "TARGET = 'acf_api.core.store.engine'",
    "from .... import anything",
]

ALLOWED = [
    "import acf_api.command.codec",
    "from acf_api.command import model as m",
    "from acf_api.command.client import CoreClient",
    "from acf_api import __version__",
    "from acf_api.edge.config import Limits",
    "from . import routes",
    "from .routes import ROUTES",
    "from .. import config",
    "from ..config import Limits",
    "from ...command import codec",
    "from ...command.answers import Answer",
    "import core",
    "from core import config",
    "import acf_api.corelike",
    "from acf_api.core_tools import x",
    '"""This module never imports acf_api.core."""',
    'def f():\n    """Nothing of acf_api.core is reachable from here."""',
    'class C:\n    """Unlike acf_api.core.store."""',
    "# from acf_api.core import config",
    "x = 'the core is another process'",
]


@pytest.mark.proves("T3-EC-01")
@pytest.mark.parametrize("source", FORBIDDEN, ids=[source.replace("\n", "; ")[:60] for source in FORBIDDEN])
def test_the_detector_finds_every_way_of_reaching_the_core(source: str) -> None:
    assert findings(source, IN_THE_EDGE) != []


@pytest.mark.proves("T3-EC-01")
@pytest.mark.parametrize("source", ALLOWED, ids=[source.replace("\n", "; ")[:60] for source in ALLOWED])
def test_the_detector_leaves_what_an_edge_module_may_do(source: str) -> None:
    assert findings(source, IN_THE_EDGE) == []


@pytest.mark.proves("T3-EC-01")
def test_a_relative_import_is_resolved_from_where_the_module_is() -> None:
    assert _resolve("acf_api.edge.http", 1, "routes") == "acf_api.edge.http.routes"
    assert _resolve("acf_api.edge.http", 2, "config") == "acf_api.edge.config"
    assert _resolve("acf_api.edge.http", 3, "core") == "acf_api.core"
    assert _resolve("acf_api.edge.http", 3, None) == "acf_api"
    assert _resolve("acf_api.edge.http", 4, None) is None
    # The same text reaches the core from one place and not from another.
    assert findings("from .. import core", "acf_api.edge.config") != []
    assert findings("from .. import core", "acf_api.edge", is_package=True) != []
    assert findings("from .. import core", "acf_api.edge.http.app") == []
    assert findings("from .. import core", "acf_api.edge.http", is_package=True) == []
    assert findings("from . import core", "acf_api", is_package=True) != []
    assert findings("from ..core import x", "acf_api.command.codec") != []
    # A pattern compiled by `re` is not code compiled to be run.
    assert findings("import re\nPATTERN = re.compile('x')", IN_THE_EDGE) == []
    assert findings("code = compile('import acf_api', 'x', 'exec')", IN_THE_EDGE) != []


# ------------------------------------------------------------------------------- the source
@pytest.mark.proves("T3-EC-01")
def test_the_guarded_packages_are_where_the_test_looks() -> None:
    modules = dict(guarded_modules())
    assert set(modules) == {
        "acf_api.edge",
        "acf_api.edge.config",
        "acf_api.edge.server",
        "acf_api.edge.http",
        "acf_api.edge.http.app",
        "acf_api.edge.http.routes",
        "acf_api.command",
        "acf_api.command.answers",
        "acf_api.command.client",
        "acf_api.command.codec",
        "acf_api.command.commands",
        "acf_api.command.errors",
        "acf_api.command.model",
        "acf_api.command.strictjson",
        "acf_api.command.surface",
    }, "a module was added to or removed from a guarded package: it is covered below, and is named here knowingly"
    assert (PACKAGE / "core").is_dir()


@pytest.mark.proves("T3-EC-01")
@pytest.mark.parametrize(("module", "path"), guarded_modules(), ids=[module for module, _ in guarded_modules()])
def test_no_module_of_the_edge_or_of_the_command_interface_reaches_the_core(module: str, path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    assert findings(source, module, is_package=path.name == "__init__.py") == []
    assert "noqa: TID251" not in source, "the lint that forbids the import is not switched off here"


@pytest.mark.proves("T3-EC-01")
@pytest.mark.parametrize(("module", "path"), guarded_modules(), ids=[module for module, _ in guarded_modules()])
def test_a_guarded_module_imports_only_its_own_role_and_the_command_interface(module: str, path: Path) -> None:
    """Not the core, and not what imports the core in turn: the artifact generator and the entry point do."""
    package = module if path.name == "__init__.py" else module.rpartition(".")[0]
    own = {"acf_api.command"} if module.startswith("acf_api.command") else {"acf_api.command", "acf_api.edge"}
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        targets: list[str] = []
        if isinstance(node, ast.Import):
            targets = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            base = _resolve(package, node.level, node.module)
            assert base is not None
            targets = [base] if base != "acf_api" else [f"acf_api.{alias.name}" for alias in node.names]
        for target in targets:
            if target.split(".")[0] != "acf_api" or target == "acf_api.__version__":
                continue
            assert any(target == allowed or target.startswith(allowed + ".") for allowed in own), (
                f"{module} imports {target}"
            )


@pytest.mark.proves("T3-EC-01")
def test_the_command_interface_depends_on_no_web_framework_and_no_agent_protocol_library() -> None:
    """It is imported by both roles and by every protocol adapter, so it may depend on none of them."""
    imported: dict[str, set[str]] = {}
    for module, path in guarded_modules():
        if module.startswith("acf_api.command"):
            imported[module] = third_party_roots(path.read_text(encoding="utf-8"))
    everything = set().union(*imported.values())
    assert not everything & WEB_FRAMEWORKS
    assert not everything & AGENT_PROTOCOL_LIBRARIES
    # One dependency, for validation. Anything else has to be argued for here before it is imported there.
    assert everything == {"pydantic"}, imported
    edge = set().union(
        *(
            third_party_roots(path.read_text(encoding="utf-8"))
            for module, path in guarded_modules()
            if module.startswith("acf_api.edge")
        )
    )
    assert edge == {"pydantic", "starlette", "uvicorn", "yaml"}


@pytest.mark.proves("T3-EC-01")
def test_the_linter_enforces_the_same_rule_on_the_same_files() -> None:
    settings = tomllib.loads((API / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["ruff"]["lint"]
    assert "TID" in settings["select"]
    assert CORE in settings["flake8-tidy-imports"]["banned-api"]
    lifted = [pattern for pattern, codes in settings["per-file-ignores"].items() if "TID251" in codes or "TID" in codes]
    assert sorted(lifted) == ["src/acf_api/cli.py", "src/acf_api/contract/**", "src/acf_api/core/**", "tests/**"]
    for _module, path in guarded_modules():
        relative = path.relative_to(API).as_posix()
        assert not [pattern for pattern in lifted if fnmatch.fnmatch(relative, pattern)], relative


# ------------------------------------------------------------------------------- a fresh interpreter
_REPORT = """
import importlib, json, sys
for name in sys.argv[1:]:
    importlib.import_module(name)
print(json.dumps(sorted(sys.modules)))
"""


#: What each fresh interpreter is asked to import. One interpreter per row: none shares anything with another.
PROBES: dict[str, tuple[str, ...]] = {
    "the REST adapter": ("acf_api.edge.http.app",),
    "every edge module": tuple(module for module, _ in guarded_modules() if module.startswith("acf_api.edge")),
    "the command interface": tuple(module for module, _ in guarded_modules() if module.startswith("acf_api.command")),
    "the entry point": ("acf_api.cli",),
    "the core": ("acf_api.core.app",),
}


@functools.cache
def _probed() -> dict[str, set[str]]:
    """The modules each interpreter of :data:`PROBES` ended with. They run side by side, to save the wait."""
    started = {
        probe: subprocess.Popen(
            [sys.executable, "-c", _REPORT, *modules], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        for probe, modules in PROBES.items()
    }
    loaded: dict[str, set[str]] = {}
    try:
        for probe, child in started.items():
            out, err = child.communicate(timeout=120)
            assert child.returncode == 0, (probe, err[-2000:])
            loaded[probe] = set(json.loads(out))
    finally:
        for child in started.values():
            if child.poll() is None:
                child.kill()
                child.communicate()
    return loaded


def loaded_after_importing(probe: str) -> set[str]:
    """Every module a fresh interpreter has loaded once it has imported the modules of ``probe``."""
    return _probed()[probe]


def reaches(loaded: set[str], *roots: str) -> list[str]:
    return sorted(name for name in loaded if any(name == root or name.startswith(root + ".") for root in roots))


@pytest.mark.proves("T3-EC-01")
def test_an_interpreter_that_loads_the_rest_adapter_loads_nothing_of_the_core() -> None:
    loaded = loaded_after_importing("the REST adapter")
    assert "acf_api.edge.http.app" in loaded
    assert "acf_api.command.codec" in loaded
    assert reaches(loaded, CORE) == []
    # Neither the engine of the store nor the module that reads it: the edge has no way to open a store.
    assert reaches(loaded, "sqlite3", "_sqlite3") == []
    assert reaches(loaded, "acf_api.contract", "acf_api.cli") == []


@pytest.mark.proves("T3-EC-01")
def test_an_interpreter_that_loads_every_edge_module_loads_nothing_of_the_core() -> None:
    edge = PROBES["every edge module"]
    assert len(edge) >= 5
    loaded = loaded_after_importing("every edge module")
    assert set(edge) <= loaded
    assert reaches(loaded, CORE) == []
    assert reaches(loaded, "sqlite3", "_sqlite3") == []
    # Verifying tokens and reading the host's key are the core's: the libraries for them stay out of the edge.
    assert reaches(loaded, "jwt", "cryptography") == []


@pytest.mark.proves("T3-EC-01")
def test_an_interpreter_that_loads_the_command_interface_loads_no_role_and_no_framework() -> None:
    command = PROBES["the command interface"]
    assert len(command) >= 5
    loaded = loaded_after_importing("the command interface")
    assert set(command) <= loaded
    assert reaches(loaded, CORE, "acf_api.edge", "acf_api.contract", "acf_api.cli") == []
    assert reaches(loaded, *WEB_FRAMEWORKS, *AGENT_PROTOCOL_LIBRARIES) == []
    assert reaches(loaded, "sqlite3", "_sqlite3", "yaml", "jwt", "cryptography") == []
    assert reaches(loaded, "acf_api") == sorted(["acf_api", *command])


@pytest.mark.proves("T3-EC-01")
def test_the_entry_point_loads_a_role_only_when_it_is_asked_to_run_it() -> None:
    """One program starts both roles. Started as an edge, it must not have the core's code in its process."""
    loaded = loaded_after_importing("the entry point")
    assert reaches(loaded, CORE, "acf_api.edge") == []
    assert reaches(loaded, "sqlite3", "_sqlite3") == []
    source = (PACKAGE / "cli.py").read_text(encoding="utf-8")
    top_level = [node for node in ast.parse(source).body if isinstance(node, ast.Import | ast.ImportFrom)]
    for node in top_level:
        names = [alias.name for alias in node.names] if isinstance(node, ast.Import) else [node.module or ""]
        assert not [name for name in names if name.startswith(("acf_api.core", "acf_api.edge", "acf_api.contract"))], (
            ast.unparse(node)
        )
    # The other direction is what makes this a check and not a formality: the core does load a store.
    core = loaded_after_importing("the core")
    assert reaches(core, "sqlite3") != []
    assert reaches(core, "acf_api.core.store.engine") != []
