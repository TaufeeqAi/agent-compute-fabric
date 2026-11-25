"""The test catalog of the contract, mapped to the tests of this package, and the lint of its gate classes.

Proves TV3-8 as far as code can check it: every test that a security row or an invariant row names is
in the gate that blocks acceptance; no test of a surface that is on by default is in the gate for
hardening; and the surfaces that gate does hold are off by default in the code. Catalog entry: T3-RED-49.

It also keeps the account TV3-1 asks for. A mark in a table is not verification, so every entry of the
catalog is either named by a test of this package or carries, below, the reason why this package cannot
prove it: it needs a real host or a real deployment, it needs published packages, it needs a surface
that is off by default, it belongs to another package, or the contract itself did not adopt it. An
entry that is neither proven nor explained fails this file. That is the purpose of the file: it turns
red when a proof is missing, and it is not made green by writing a reason that is not true.

How a test names what it proves, either way:

* ``@pytest.mark.proves("T3-IDM-01", "T3-RED-22")``, on a test function, on a class of tests, or as the
  ``pytestmark`` of a module. ``level="L0"`` to ``"L3"`` says which part, when an entry has several;
* the docstring of the test function, which names the entries it proves, as in ``T3-IDM-02: the answer
  is the operation as of now``. A module docstring names nothing by itself: an entry is proven by tests.

What a test stands for without a ``level``: a test of a ``test_unit_`` or ``test_contract_`` file
stands for the static and the unit level and never for more; the few of them that start the whole core
say so with their level. A test of any other file of this package runs the whole core, against the
model of the host or against the test host binary, and is taken at its author's word up to the level
of the whole process. Nothing here stands for the levels that need a real host or published packages.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

import pytest

from acf_api.core.config import CoreConfig
from acf_api.core.parameters import Parameters

TESTS = Path(__file__).resolve().parent
ENTRY = re.compile(r"T3-[A-Z]+-[0-9]{2}")
LEVELS = ("L0", "L1", "L2", "L3", "L4", "L5")


def _span(prefix: str, first: int, last: int) -> list[str]:
    return [f"T3-{prefix}-{number:02d}" for number in range(first, last + 1)]


#: The catalog: every entry, with the levels at which the contract says it means something.
CATALOG: dict[str, tuple[str, ...]] = {
    "T3-API-01": ("L0",),
    "T3-API-02": ("L2",),
    "T3-API-03": ("L2",),
    "T3-SVC-01": ("L1", "L2"),
    "T3-SVC-02": ("L2",),
    "T3-SVC-03": ("L2",),
    "T3-SEC-01": ("L1", "L2"),
    "T3-SEC-02": ("L2",),
    "T3-SEC-03": ("L2",),
    "T3-SEC-04": ("L2",),
    "T3-SEC-05": ("L2", "L4"),
    "T3-SEC-06": ("L0", "L2"),
    "T3-SEC-07": ("L2",),
    "T3-SEC-08": ("L2",),
    "T3-SEC-09": ("L2",),
    "T3-SEC-10": ("L2",),
    "T3-SEC-11": ("L2",),
    "T3-SEC-12": ("L2",),
    "T3-AUTH-01": ("L1",),
    "T3-AUTH-02": ("L2",),
    "T3-AUTH-03": ("L2",),
    "T3-AUTH-04": ("L2",),
    "T3-AZ-01": ("L1",),
    "T3-AZ-02": ("L1", "L2"),
    "T3-AZ-03": ("L2",),
    "T3-IDM-01": ("L1",),
    **dict.fromkeys(_span("IDM", 2, 6), ("L2",)),
    **dict.fromkeys(_span("REC", 1, 4), ("L2",)),
    "T3-ERR-01": ("L1",),
    "T3-ERR-02": ("L2",),
    "T3-LRO-01": ("L2",),
    "T3-LRO-02": ("L2", "L4"),
    "T3-LRO-03": ("L2", "L4"),
    "T3-LRO-04": ("L2",),
    "T3-LRO-05": ("L2",),
    **dict.fromkeys(_span("MCP", 1, 6), ("L2",)),
    "T3-MCP-07": ("L4",),
    "T3-HB-01": ("L2",),
    "T3-HB-02": ("L2", "L4"),
    "T3-HB-03": ("L2",),
    "T3-IPS-01": ("L2",),
    "T3-IPS-02": ("L2",),
    "T3-IPS-03": ("L0", "L2"),
    **dict.fromkeys(_span("SDK", 1, 3), ("L2",)),
    "T3-SDK-04": ("L1",),
    "T3-SDK-05": ("L2",),
    "T3-SDK-06": ("L2",),
    "T3-CLI-01": ("L2",),
    "T3-CLI-02": ("L2",),
    "T3-CP-01": ("L2",),
    **dict.fromkeys(_span("OBS", 1, 4), ("L2",)),
    "T3-VER-01": ("L0",),
    "T3-VER-02": ("L2",),
    "T3-VER-03": ("L2",),
    "T3-EC-01": ("L0", "L3"),
    "T3-EC-02": ("L2",),
    "T3-EC-03": ("L2",),
    "T3-PRJ-01": ("L2",),
    "T3-CRD-01": ("L1", "L2"),
    "T3-CRD-02": ("L2", "L4"),
    "T3-REL-01": ("L5",),
    "T3-REL-02": ("L5",),
    "T3-CONC-01": ("L2",),
    "T3-PARAM-01": ("L1", "L3"),
    "T3-SCOPE-01": ("L0", "L2"),
    "T3-DX-01": ("L4", "L5"),
    "T3-DX-02": ("L4",),
    "T3-RED-01": ("L2",),
    "T3-RED-02": ("L1",),
    "T3-RED-03": ("L2",),
    "T3-RED-04": ("L2",),
    "T3-RED-05": ("L2",),
    "T3-RED-06": ("L3", "L4"),
    "T3-RED-07": ("L2",),
    "T3-RED-08": ("L2",),
    "T3-RED-09": ("L2",),
    "T3-RED-10": ("L1", "L2"),
    "T3-RED-11": ("L1",),
    # Not adopted by the contract: there is no rule to test, and so no level.
    "T3-RED-12": (),
    "T3-RED-13": ("L1", "L2"),
    "T3-RED-14": ("L0", "L2"),
    **dict.fromkeys(_span("RED", 15, 21), ("L2",)),
    "T3-RED-22": ("L1", "L2"),
    **dict.fromkeys(_span("RED", 23, 26), ("L2",)),
    "T3-RED-27": ("L2", "L4"),
    **dict.fromkeys(_span("RED", 28, 30), ("L2",)),
    "T3-RED-31": ("L2", "L4"),
    **dict.fromkeys(_span("RED", 32, 34), ("L2",)),
    "T3-RED-35": ("L2", "L4"),
    "T3-RED-36": ("L2",),
    "T3-RED-37": ("L2",),
    "T3-RED-38": ("L0", "L2"),
    "T3-RED-39": ("L2",),
    "T3-RED-40": ("L0",),
    "T3-RED-41": ("L4",),
    **dict.fromkeys(_span("RED", 42, 44), ("L2",)),
    "T3-RED-45": ("L0", "L2"),
    "T3-RED-46": ("L2",),
    "T3-RED-47": ("L0",),
    "T3-RED-48": ("L0", "L5"),
    "T3-RED-49": ("L0",),
    "T3-RED-50": ("L2",),
    "T3-RED-51": ("L2",),
}

# ------------------------------------------------------------------------------- the gates of the contract
#: Mandatory blockers: a failed test here blocks acceptance.
P0: frozenset[str] = frozenset(
    [
        *("T3-SEC-01", "T3-SEC-12", "T3-MCP-03", "T3-RED-01", "T3-RED-02", "T3-RED-08"),
        *("T3-EC-01", "T3-EC-03", "T3-RED-03", "T3-RED-06", "T3-RED-09"),
        *("T3-SVC-01", "T3-SVC-02", "T3-SVC-03", "T3-SEC-06", "T3-SCOPE-01", "T3-API-03", "T3-MCP-04"),
        *_span("IDM", 1, 6),
        *_span("REC", 1, 4),
        *("T3-CONC-01", "T3-EC-02"),
        *_span("RED", 15, 26),
        "T3-RED-32",
        *("T3-ERR-01", "T3-ERR-02", "T3-LRO-02", "T3-LRO-03", "T3-LRO-04", "T3-RED-27", "T3-RED-28"),
        *_span("AZ", 1, 3),
        "T3-RED-10",
        *("T3-SEC-02", "T3-SEC-03", "T3-SEC-05", "T3-SEC-09"),
        *_span("AUTH", 1, 4),
        *("T3-RED-04", "T3-RED-33", "T3-CRD-02"),
        *("T3-SEC-04", "T3-SEC-11", "T3-RED-31", "T3-RED-35", "T3-RED-36", "T3-RED-37", "T3-RED-38", "T3-RED-51"),
        *("T3-SEC-07", "T3-SEC-10", "T3-RED-39", "T3-RED-42"),
        *("T3-SDK-01", "T3-CLI-01", "T3-CP-01"),
        *("T3-SEC-08", "T3-SDK-05", "T3-SDK-06"),
        *("T3-API-01", "T3-PARAM-01", "T3-RED-47", "T3-RED-49"),
        *("T3-OBS-01", "T3-OBS-02", "T3-IPS-03", "T3-RED-46"),
        "T3-REL-01",
        # The developer journey, against a real host.
        "T3-DX-01",
    ]
)
#: Required behaviour: a failed test here blocks the release of the interface or component it covers.
P1: frozenset[str] = frozenset(
    [
        *("T3-API-02", "T3-LRO-01", "T3-LRO-05"),
        *("T3-MCP-01", "T3-MCP-02", "T3-MCP-05", "T3-DX-02", "T3-RED-13", "T3-RED-30", "T3-RED-40", "T3-RED-41"),
        "T3-MCP-07",
        *_span("SDK", 2, 4),
        *("T3-RED-07", "T3-RED-29"),
        "T3-CLI-02",
        *("T3-RED-11", "T3-RED-45"),
        "T3-CRD-01",
        *_span("HB", 1, 3),
        "T3-RED-43",
        *("T3-IPS-01", "T3-IPS-02", "T3-PRJ-01", "T3-RED-34", "T3-RED-50"),
        *("T3-OBS-03", "T3-OBS-04"),
        *_span("VER", 1, 3),
        "T3-RED-44",
        # The developer journey once more, from published packages.
        *("T3-REL-02", "T3-RED-48", "T3-DX-01"),
    ]
)
#: Hardening, and surfaces that are off by default: each test, and the switch that turns its surface on.
P2: dict[str, tuple[str, ...]] = {
    "T3-MCP-06": ("mcp_tasks_extension", "mcp_serve_2025_11_25"),
    "T3-RED-05": ("mcp_serve_2025_11_25",),
    "T3-RED-14": ("oauth",),
}
#: In two gates on purpose: against a real host it blocks acceptance, from published packages it blocks the release.
IN_TWO_GATES = {"T3-DX-01"}
NOT_ADOPTED = {"T3-RED-12"}

#: The tests each security row of the contract names.
SECURITY_ROWS: dict[str, tuple[str, ...]] = {
    "SEC-101": ("T3-SEC-01",),
    "SEC-102": ("T3-SEC-02",),
    "SEC-103": ("T3-SEC-03", "T3-RED-04"),
    "SEC-104": ("T3-SEC-04", "T3-RED-51"),
    "SEC-105": ("T3-SEC-05",),
    "SEC-106": ("T3-SEC-06",),
    "SEC-107": ("T3-SEC-07", "T3-RED-39"),
    "SEC-108": ("T3-SEC-08",),
    "SEC-109": ("T3-OBS-01",),
    "SEC-110": ("T3-SVC-02",),
    "SEC-111": ("T3-AZ-02",),
    "SEC-112": ("T3-SEC-09", "T3-EC-01"),
    "SEC-113": ("T3-IPS-03",),
    "SEC-114": ("T3-SDK-05",),
    "SEC-115": ("T3-SDK-06",),
    "SEC-116": ("T3-OBS-02",),
    "SEC-117": ("T3-REL-01",),
    "SEC-118": ("T3-SEC-10", "T3-RED-42"),
    "SEC-119": ("T3-SEC-11", "T3-RED-31", "T3-RED-37"),
    "SEC-120": ("T3-SEC-12",),
    "SEC-121": ("T3-AZ-03", "T3-RED-10"),
    "SEC-122": ("T3-EC-01", "T3-RED-06"),
    "SEC-123": ("T3-RED-46",),
    "SEC-124": ("T3-RED-08",),
    "SEC-125": ("T3-RED-03",),
    "SEC-126": ("T3-RED-33", "T3-RED-01"),
}
#: The tests each invariant row of the contract names.
INVARIANT_ROWS: dict[str, tuple[str, ...]] = {
    "INV-101": ("T3-SCOPE-01",),
    "INV-102": ("T3-SVC-01", "T3-MCP-03"),
    "INV-103": ("T3-SEC-01",),
    "INV-104": (*_span("IDM", 1, 6), *_span("REC", 1, 4), *_span("RED", 15, 26)),
    "INV-105": ("T3-ERR-02", "T3-EC-02"),
    "INV-106": ("T3-LRO-02", "T3-RED-19"),
    "INV-107": ("T3-SVC-03", "T3-RED-19"),
    "INV-108": ("T3-AZ-02", "T3-SVC-02"),
    "INV-109": ("T3-MCP-04", "T3-API-03"),
    "INV-110": ("T3-SEC-06",),
    "INV-111": ("T3-SEC-05", "T3-OBS-02", "T3-SEC-10"),
    "INV-112": ("T3-SEC-07", "T3-RED-39"),
    "INV-113": ("T3-PARAM-01", "T3-RED-38"),
    "INV-114": ("T3-API-01",),
    "INV-115": ("T3-SDK-01", "T3-MCP-03", "T3-CLI-01", "T3-CP-01"),
    "INV-116": ("T3-LRO-03",),
    "INV-117": ("T3-SCOPE-01",),
    "INV-118": ("T3-REL-01",),
    "INV-119": ("T3-SEC-11", "T3-RED-31", "T3-RED-37"),
    "INV-120": ("T3-SEC-12",),
    "INV-121": ("T3-EC-01", "T3-RED-06"),
    "INV-122": ("T3-EC-03", "T3-RED-09"),
    "INV-123": ("T3-RED-17",),
    "INV-124": ("T3-RED-32",),
    "INV-125": ("T3-RED-35", "T3-RED-36"),
    "INV-126": ("T3-RED-33", "T3-RED-01"),
    "INV-127": ("T3-RED-20",),
    "INV-128": ("T3-CRD-02",),
    "INV-129": ("T3-LRO-04",),
}

# ------------------------------------------------------------------------------- what is not proven here, and why
REAL_HOST = "needs a real host or a real deployment"
PUBLISHED = "needs published packages"
OFF_BY_DEFAULT = "needs a surface that is off by default"
OTHER_PACKAGE = "belongs to another package"
REASONS = {REAL_HOST, PUBLISHED, OFF_BY_DEFAULT, OTHER_PACKAGE}

#: The two levels no test of this package can stand for, whatever the entry.
BEYOND_THIS_PACKAGE = {"L4": REAL_HOST, "L5": PUBLISHED}

#: Entries, or one level of an entry, that this package does not prove: the kind of reason, and the reason.
#: Looked at only where no test names the entry at that level. Each is a statement about where the proof
#: has to be made, not a claim that it has been made there.
NOT_PROVEN_HERE: dict[str | tuple[str, str], tuple[str, str]] = {
    **dict.fromkeys(_span("SDK", 1, 6), (OTHER_PACKAGE, "the behaviour of the two SDKs is proven in the SDK packages")),
    "T3-CLI-01": (OTHER_PACKAGE, "the command-line client is a package of its own"),
    "T3-CLI-02": (OTHER_PACKAGE, "exit codes are the command-line client's"),
    "T3-CP-01": (
        OTHER_PACKAGE,
        "the conformance suite is generated here and run by each client; that its answers are answers of the public model is proven here",
    ),
    "T3-MCP-01": (OTHER_PACKAGE, "conformance to the agent protocol is the adapter's, in the agent-protocol gateway"),
    "T3-SEC-08": (OTHER_PACKAGE, "the check of `Origin` and the loopback binding are the agent-protocol adapter's"),
    "T3-RED-07": (
        OTHER_PACKAGE,
        "resolving a name once and refusing a rebound one is done by the SDK and the command-line client",
    ),
    "T3-RED-27": (
        OTHER_PACKAGE,
        "a create that takes a minute is driven to a started sandbox by each client; no client is in this package",
    ),
    "T3-RED-28": (OTHER_PACKAGE, "what a create leaves behind when the start fails is the SDK's policy"),
    "T3-RED-29": (OTHER_PACKAGE, "a handle that must be refreshed is the SDK's"),
    "T3-RED-30": (OTHER_PACKAGE, "closing a stream and cancelling over stdio are the adapter's and the relay's"),
    "T3-RED-44": (OTHER_PACKAGE, "following an operation in a state the client does not know is the SDK's"),
    "T3-RED-47": (OTHER_PACKAGE, "a lint of every name in the documents and the examples, over the whole repository"),
    ("T3-RED-48", "L0"): (OTHER_PACKAGE, "the advisory check of the dependencies runs in the release pipeline"),
    "T3-MCP-06": (
        OFF_BY_DEFAULT,
        "the tasks extension and the previous revision of the agent protocol; a deployment that turns one on runs this test",
    ),
    "T3-RED-05": (OFF_BY_DEFAULT, "sessions exist only in the previous revision of the agent protocol"),
    "T3-RED-14": (OFF_BY_DEFAULT, "the scope challenge exists only with an external authorization server configured"),
    ("T3-RED-06", "L3"): (REAL_HOST, "the running system: the installed units under their own accounts"),
}


# ------------------------------------------------------------------------------- what the tests say they prove
@dataclass(frozen=True)
class Proof:
    entry: str
    test: str
    #: The level the test states, or ``None`` when it states none.
    level: str | None
    #: The levels the test stands for.
    levels: frozenset[str]


def _stands_for(file: str, level: str | None) -> frozenset[str]:
    if level is not None:
        return frozenset({level})
    if file.startswith(("test_unit_", "test_contract_")):
        return frozenset({"L0", "L1"})
    return frozenset({"L0", "L1", "L2"})


def _marks(decorators: list[ast.expr]) -> list[tuple[list[str], str | None]]:
    """The entries and the level of every ``proves`` mark among ``decorators``."""
    found = []
    for node in decorators:
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "proves":
            entries = [arg.value for arg in node.args if isinstance(arg, ast.Constant) and isinstance(arg.value, str)]
            level = next(
                (kw.value.value for kw in node.keywords if kw.arg == "level" and isinstance(kw.value, ast.Constant)),
                None,
            )
            found.append((entries, level if isinstance(level, str) else None))
    return found


def proofs_in(source: str, file: str) -> list[Proof]:
    """Every entry of the catalog a test of ``source`` says it proves, by a mark or in its docstring."""
    tree = ast.parse(source)
    module_marks: list[tuple[list[str], str | None]] = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "pytestmark" for target in node.targets
        ):
            module_marks += _marks(
                list(node.value.elts) if isinstance(node.value, ast.List | ast.Tuple) else [node.value]
            )
    out: list[Proof] = []

    def visit(body: list[ast.stmt], inherited: list[tuple[list[str], str | None]], prefix: str) -> None:
        for node in body:
            if isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
                visit(node.body, inherited + _marks(node.decorator_list), f"{prefix}{node.name}::")
            elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name.startswith("test_"):
                name = f"{file}::{prefix}{node.name}"
                for entries, level in inherited + _marks(node.decorator_list):
                    out.extend(Proof(entry, name, level, _stands_for(file, level)) for entry in entries)
                named = sorted(set(ENTRY.findall(ast.get_docstring(node) or "")))
                out.extend(Proof(entry, name, None, _stands_for(file, None)) for entry in named)

    visit(tree.body, module_marks, "")
    return out


def all_proofs() -> list[Proof]:
    found: list[Proof] = []
    for path in sorted(TESTS.glob("test_*.py")):
        found += proofs_in(path.read_text(encoding="utf-8"), path.name)
    return found


def proven(proofs: list[Proof]) -> dict[tuple[str, str], list[str]]:
    """For every entry and level of the catalog that a test stands for: the tests."""
    by_pair: dict[tuple[str, str], list[str]] = {}
    for proof in proofs:
        for level in CATALOG.get(proof.entry, ()):
            if level in proof.levels:
                by_pair.setdefault((proof.entry, level), []).append(proof.test)
    return by_pair


def explanation(entry: str, level: str) -> tuple[str, str] | None:
    if (entry, level) in NOT_PROVEN_HERE:
        return NOT_PROVEN_HERE[entry, level]
    if level in BEYOND_THIS_PACKAGE:
        return BEYOND_THIS_PACKAGE[level], f"level {level}"
    return NOT_PROVEN_HERE.get(entry)


# ------------------------------------------------------------------------------- the collector, tested
EXAMPLE = '''
"""Module docstring: T3-API-02 is mentioned here and proves nothing by that."""
import pytest

pytestmark = [pytest.mark.proves("T3-SEC-01"), pytest.mark.asyncio]


@pytest.mark.proves("T3-IDM-01", "T3-RED-22")
def test_marked():
    """Says nothing of an entry."""


@pytest.mark.parametrize("x", [1])
@pytest.mark.proves("T3-EC-01", level="L3")
async def test_marked_with_a_level(x):
    pass


def test_named_in_the_docstring():
    """T3-IDM-02, IDM-8: the answer is current. See also T3-RED-20."""


def helper():
    """T3-IDM-03 in a helper proves nothing."""


@pytest.mark.proves("T3-AZ-01")
class TestGroup:
    @pytest.mark.proves("T3-AZ-02", level="L1")
    def test_in_a_class(self):
        """T3-AZ-03."""

    def not_a_test(self):
        """T3-IDM-04."""
'''


@pytest.mark.proves("T3-RED-49")
def test_the_collector_reads_marks_and_docstrings_and_nothing_else() -> None:
    found = {
        (proof.entry, proof.test.split("::", 1)[1], proof.level) for proof in proofs_in(EXAMPLE, "test_example.py")
    }
    assert found == {
        ("T3-SEC-01", "test_marked", None),
        ("T3-IDM-01", "test_marked", None),
        ("T3-RED-22", "test_marked", None),
        ("T3-SEC-01", "test_marked_with_a_level", None),
        ("T3-EC-01", "test_marked_with_a_level", "L3"),
        ("T3-SEC-01", "test_named_in_the_docstring", None),
        ("T3-IDM-02", "test_named_in_the_docstring", None),
        ("T3-RED-20", "test_named_in_the_docstring", None),
        ("T3-SEC-01", "TestGroup::test_in_a_class", None),
        ("T3-AZ-01", "TestGroup::test_in_a_class", None),
        ("T3-AZ-02", "TestGroup::test_in_a_class", "L1"),
        ("T3-AZ-03", "TestGroup::test_in_a_class", None),
    }


@pytest.mark.proves("T3-RED-49")
def test_a_test_stands_for_no_more_than_its_file_can_show() -> None:
    assert _stands_for("test_unit_keys.py", None) == {"L0", "L1"}
    assert _stands_for("test_contract_artifacts.py", None) == {"L0", "L1"}
    assert _stands_for("test_idempotency.py", None) == {"L0", "L1", "L2"}
    assert _stands_for("test_unit_store.py", "L0") == {"L0"}
    assert _stands_for("test_core_startup.py", "L3") == {"L3"}
    # A unit test that names an entry of the whole-process level supports it and does not prove it.
    unit = [Proof("T3-IDM-05", "test_unit_store.py::test_x", None, _stands_for("test_unit_store.py", None))]
    assert proven(unit) == {}
    whole = [Proof("T3-IDM-05", "test_idempotency.py::test_y", None, _stands_for("test_idempotency.py", None))]
    assert proven(whole) == {("T3-IDM-05", "L2"): ["test_idempotency.py::test_y"]}
    assert explanation("T3-LRO-02", "L4") == (REAL_HOST, "level L4")
    assert explanation("T3-REL-01", "L5") == (PUBLISHED, "level L5")
    assert explanation("T3-LRO-02", "L2") is None
    assert explanation("T3-RED-06", "L3") is not None
    assert explanation("T3-EC-01", "L3") is None


# ------------------------------------------------------------------------------- the lint of the gates
@pytest.mark.proves("T3-RED-49")
def test_the_catalog_and_the_gates_name_the_same_tests() -> None:
    assert len(CATALOG) == 135
    assert all(ENTRY.fullmatch(entry) for entry in CATALOG)
    assert all(set(levels) <= set(LEVELS) and list(levels) == sorted(levels) for levels in CATALOG.values())
    assert {entry for entry, levels in CATALOG.items() if not levels} == NOT_ADOPTED
    gated = P0 | P1 | set(P2)
    assert gated == set(CATALOG) - NOT_ADOPTED, (
        "an entry of the catalog is in no gate, or a gate names a test the catalog does not have"
    )
    assert P0 & P1 == IN_TWO_GATES
    assert not set(P2) & (P0 | P1)
    # The developer journey blocks acceptance against a real host and the release from published packages.
    assert CATALOG["T3-DX-01"] == ("L4", "L5")


@pytest.mark.proves("T3-RED-49")
def test_every_test_a_security_row_or_an_invariant_row_names_blocks_acceptance() -> None:
    assert len(SECURITY_ROWS) == 26
    assert len(INVARIANT_ROWS) == 29
    assert sorted(SECURITY_ROWS) == [f"SEC-{number}" for number in range(101, 127)]
    assert sorted(INVARIANT_ROWS) == [f"INV-{number}" for number in range(101, 130)]
    for row, tests in {**SECURITY_ROWS, **INVARIANT_ROWS}.items():
        assert tests, row
        for test in tests:
            assert test in CATALOG, (row, test)
            assert test in P0, f"{test} is named by {row} and is not in the gate that blocks acceptance"


@pytest.mark.proves("T3-RED-49")
def test_the_hardening_gate_holds_only_tests_of_surfaces_that_are_off_by_default() -> None:
    named = {test for tests in (*SECURITY_ROWS.values(), *INVARIANT_ROWS.values()) for test in tests}
    assert not set(P2) & named, "a test a security or invariant row names is never in the hardening gate"
    defaults = Parameters()
    for test, switches in P2.items():
        assert switches, test
        for switch in switches:
            if switch == "oauth":
                # The mode exists only when an operator configures an external authorization server.
                assert CoreConfig.model_fields["oauth"].default is None
                assert not CoreConfig.model_fields["oauth"].is_required()
            else:
                assert getattr(defaults, switch) is False, (
                    f"{switch} is on by default, so {test} tests a surface that is on by default"
                )
    # Every switch of the parameters that turns a surface on is off, and each of the two has its test here.
    surfaces = {
        name
        for name, field in Parameters.model_fields.items()
        if field.annotation is bool and name.startswith("mcp_") and name != "mcp_allow_developer_credentials"
    }
    assert (
        surfaces
        == {"mcp_tasks_extension", "mcp_serve_2025_11_25"}
        == {switch for switches in P2.values() for switch in switches} - {"oauth"}
    )


# ------------------------------------------------------------------------------- the account
@pytest.mark.proves("T3-RED-49")
def test_every_test_names_entries_of_the_catalog_and_a_level_this_package_can_stand_for() -> None:
    """A mistyped entry would prove nothing and be counted nowhere. Nor does any test here stand for a real host."""
    proofs = all_proofs()
    assert len(proofs) > 300
    unknown = sorted({f"{proof.test} names {proof.entry}" for proof in proofs if proof.entry not in CATALOG})
    assert unknown == []
    for proof in proofs:
        assert proof.level is None or proof.level in ("L0", "L1", "L2", "L3"), (
            f"{proof.test}: no test of this package stands for {proof.level}"
        )
    assert not [proof.test for proof in proofs if proof.entry in NOT_ADOPTED]


@pytest.mark.proves("T3-RED-49")
def test_the_reasons_given_are_reasons_and_are_about_entries_of_the_catalog() -> None:
    for key, (kind, text) in NOT_PROVEN_HERE.items():
        entry, level = (key, None) if isinstance(key, str) else key
        assert entry in CATALOG, key
        assert level is None or level in CATALOG[entry], key
        assert kind in REASONS, key
        assert len(text) > 20, key
        assert text[0].islower(), key
        assert not text.endswith("."), key
    # A surface that is off by default is the reason for exactly the tests of the hardening gate.
    assert {key for key, (kind, _text) in NOT_PROVEN_HERE.items() if kind == OFF_BY_DEFAULT} == set(P2)
    assert not {key for key in NOT_PROVEN_HERE if key in NOT_ADOPTED}


@pytest.mark.proves("T3-RED-49")
def test_every_entry_of_the_catalog_is_proven_by_a_test_or_explained() -> None:
    """The table. An entry at a level that no test stands for, and for which no reason is given, fails here."""
    by_pair = proven(all_proofs())
    table: list[tuple[str, str, str]] = []
    missing: list[str] = []
    for entry, levels in CATALOG.items():
        for level in levels:
            tests = by_pair.get((entry, level))
            reason = explanation(entry, level)
            if tests:
                table.append((entry, level, f"proven by {len(tests)} test(s), the first {tests[0]}"))
            elif reason is not None:
                table.append((entry, level, f"not proven here: {reason[0]} ({reason[1]})"))
            else:
                missing.append(f"{entry} at {level}")
    assert len(table) + len(missing) == sum(len(levels) for levels in CATALOG.values())
    # Red on purpose while a pair is unclaimed. The test that proves it has to name it, or has to be
    # written; a reason put into the table in its place would be a mark, and a mark is not verification.
    assert missing == [], (
        f"{len(missing)} entr{'y' if len(missing) == 1 else 'ies'} of the test catalog neither proven by a test of this package "
        "nor explained: " + ", ".join(missing) + ". The test that proves one names it; the top of this file says how"
    )


@pytest.mark.proves("T3-RED-49")
def test_what_this_file_itself_proves_is_in_the_table() -> None:
    by_pair = proven(all_proofs())
    assert any(test.startswith("test_contract_gates.py::") for test in by_pair["T3-RED-49", "L0"])
    # The entries the unit and contract files of this package were written for, each at its own level.
    for entry, level in (
        ("T3-API-01", "L0"),
        ("T3-SEC-06", "L0"),
        ("T3-RED-40", "L0"),
        ("T3-EC-01", "L0"),
        ("T3-RED-38", "L0"),
        ("T3-IPS-03", "L0"),
        ("T3-AUTH-01", "L1"),
        ("T3-AZ-01", "L1"),
        ("T3-AZ-02", "L1"),
        ("T3-IDM-01", "L1"),
        ("T3-ERR-01", "L1"),
        ("T3-PARAM-01", "L1"),
        ("T3-CRD-01", "L1"),
        ("T3-RED-02", "L1"),
        ("T3-RED-10", "L1"),
        ("T3-RED-11", "L1"),
        ("T3-RED-13", "L1"),
        ("T3-RED-22", "L1"),
    ):
        tests = by_pair.get((entry, level), [])
        assert any(test.startswith(("test_unit_", "test_contract_")) for test in tests), (entry, level)
