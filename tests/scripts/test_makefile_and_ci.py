"""The Makefile is the gate: CI, the docs and humans all call the same targets, so they must exist and mean what
they say. These tests keep three things from drifting apart without anyone noticing:

* the targets the workflows and docs invoke exist in the Makefile (a renamed target would otherwise turn a CI job
  into a no-op error nobody sees until the next push);
* ``make release`` can never quietly start building the production binary with the test-only feature;
* the workflows stay least-privilege: read-only token, actions pinned to exact versions, no attacker-controlled
  text interpolated into a shell script.

They read text; they do not run ``cargo`` or ``uv``.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
MAKEFILE = REPO / "Makefile"
WORKFLOWS = sorted((REPO / ".github/workflows").glob("*.yml"))
DOCS = [*sorted((REPO / "docs").glob("*.md")), REPO / "README.md"] if (REPO / "docs").is_dir() else []

TARGET_RULE = re.compile(r"^([a-zA-Z0-9][a-zA-Z0-9_.-]*):(?!=)(?P<rest>.*)$")


def parse_makefile() -> tuple[dict[str, str], set[str], dict[str, list[str]], dict[str, list[str]]]:
    """(help text per documented target, .PHONY names, prerequisites per target, recipe lines per target)."""
    documented: dict[str, str] = {}
    phony: set[str] = set()
    prereqs: dict[str, list[str]] = {}
    recipes: dict[str, list[str]] = {}
    current: list[str] = []
    for line in MAKEFILE.read_text().splitlines():
        if line.startswith("\t"):
            for name in current:
                recipes[name].append(line.strip())
            continue
        if line.startswith(".PHONY:"):
            phony.update(line.removeprefix(".PHONY:").split())
            current = []
            continue
        m = TARGET_RULE.match(line)
        if not m or line.startswith("."):
            current = [] if not line.rstrip().endswith("\\") else current
            continue
        name = m.group(1)
        rest = m.group("rest")
        deps, _, help_text = rest.partition("##")
        prereqs[name] = deps.split()
        recipes.setdefault(name, [])
        current = [name]
        if help_text:
            documented[name] = help_text.strip()
    return documented, phony, prereqs, recipes


DOCUMENTED, PHONY, PREREQS, RECIPES = parse_makefile()
TARGETS = set(PREREQS)


def test_every_documented_target_is_phony_and_every_phony_target_is_documented() -> None:
    assert set(DOCUMENTED) == PHONY - {"help"} | {"help"}, (
        f"documented but not phony: {sorted(set(DOCUMENTED) - PHONY)}; phony but undocumented: "
        f"{sorted(PHONY - set(DOCUMENTED))}"
    )
    assert all(text for text in DOCUMENTED.values())


def test_the_gate_targets_the_docs_and_ci_rely_on_exist() -> None:
    required = {
        "help", "check", "ci", "release", "guest-agent", "fake-host", "schemas", "check-schemas",
        "rust-fmt", "rust-lint", "rust-test", "py-lint", "py-test", "e2e", "tools-lint", "tools-pytest",
        "tools-test", "shellcheck", "check-pins", "check-pins-release", "systemd-verify", "driver-selftest",
        "control-plane", "integration", "dist", "clean",
    }  # fmt: skip
    assert required <= TARGETS, f"missing: {sorted(required - TARGETS)}"


@pytest.mark.skipif(shutil.which("make") is None, reason="make is not installed")
@pytest.mark.parametrize("target", sorted(TARGETS))
def test_make_can_expand_every_target_without_running_it(target: str) -> None:
    result = subprocess.run(
        ["make", "-n", "-C", str(REPO), target], capture_output=True, text=True, check=False, timeout=60
    )
    assert result.returncode == 0, result.stderr


def test_release_never_builds_the_production_binary_with_the_testing_feature() -> None:
    """`testing` compiles an in-memory VM and crash-point injection into the binary. Only the purity *control* may."""
    release = RECIPES["release"]
    assert PREREQS["release"] == ["fake-host"], (
        "the test-only build is a prerequisite only so that it can be the control"
    )
    for line in release:
        assert "--features" not in line, line
        assert "--all-features" not in line, line
        assert "testing" not in line.replace("check-release-purity", ""), line
    assert any("--release" in line and "--bin acf-host" in line for line in release)
    purity = [line for line in release if "check-release-purity.sh" in line]
    assert len(purity) == 1
    assert "--control" in purity[0], "the purity check must be validated against a binary that HAS the feature"
    # and `fake-host` is the one place the feature is enabled
    assert any("--features testing" in line and "acf-host-fake" in line for line in RECIPES["fake-host"])


def test_dist_and_the_gitignore_agree_that_build_output_is_not_source() -> None:
    ignore = (REPO / ".gitignore").read_text().splitlines()
    for needed in ("/target/", "/dist/", "__pycache__/", ".venv/", ".mypy_cache/", ".ruff_cache/", ".pytest_cache/"):
        assert needed in ignore, f".gitignore must list {needed}"


# ------------------------------------------------------------------------------------------------------ workflows
def make_invocations(text: str) -> list[tuple[str, str]]:
    """(target, line) for every `make a b c` in non-comment lines: the words after `make` up to the end of the line."""
    found: list[tuple[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith(("#", "- name:", "name:")):
            continue
        m = re.search(r"(?:^|[\s;&|])make\s+((?:[a-z][a-z0-9-]*\s*)+)$", line)
        if m:
            found.extend((word, raw) for word in m.group(1).split())
    return found


def test_there_are_workflows_to_check() -> None:
    names = {p.name for p in WORKFLOWS}
    assert {"ci.yml", "integration.yml", "audit.yml"} <= names


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_workflows_only_call_make_targets_that_exist(workflow: Path) -> None:
    calls = make_invocations(workflow.read_text())
    unknown = [(t, line.strip()) for t, line in calls if t not in TARGETS]
    assert not unknown, f"{workflow.name} calls undefined make targets: {unknown}"


def test_ci_runs_the_whole_gate_that_make_ci_names() -> None:
    """`make ci` is documented as 'what CI runs'. Every target with a recipe that it pulls in must be called by ci.yml."""
    called = {t for t, _ in make_invocations((REPO / ".github/workflows/ci.yml").read_text())}

    def expand(name: str) -> set[str]:
        """Aggregates (no recipe of their own) stand for their prerequisites; anything with a recipe stands for itself."""
        if RECIPES[name]:
            return {name}
        return set().union(*(expand(dep) for dep in PREREQS[name]))

    wanted = expand("ci")
    assert {
        "rust-test",
        "release",
        "e2e",
        "driver-selftest",
        "control-plane",
        "tools-lint",
        "tools-pytest",
    } <= wanted, sorted(wanted)
    missing = sorted(wanted - called)
    assert not missing, f"`make ci` includes targets that ci.yml never runs: {missing}"


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_workflows_are_least_privilege(workflow: Path) -> None:
    text = workflow.read_text()
    assert re.search(r"^permissions:\n  contents: read\n", text, re.MULTILINE), (
        "top-level permissions must be read-only"
    )
    assert not re.search(r":\s*write\b", text), "no job may ask for write access"
    assert "pull_request_target" not in text, "pull_request_target runs untrusted code with a privileged token"
    assert text.count("persist-credentials: false") == text.count("actions/checkout@"), (
        "every checkout must drop the token from .git/config"
    )


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_every_action_is_pinned_to_an_exact_version_or_commit(workflow: Path) -> None:
    for m in re.finditer(r"^\s*-?\s*uses:\s*(\S+)", workflow.read_text(), re.MULTILINE):
        ref = m.group(1)
        assert "@" in ref, f"{ref}: no ref"
        _, _, version = ref.partition("@")
        assert re.fullmatch(r"v\d+\.\d+\.\d+|[0-9a-f]{40}", version), f"{ref}: pin an exact release tag or a commit SHA"


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_workflow_inputs_reach_the_shell_only_through_the_environment(workflow: Path) -> None:
    """`${{ inputs.x }}` pasted into a `run:` script is command injection; as an env value it is just data."""
    for line in workflow.read_text().splitlines():
        if re.search(r"\$\{\{\s*(inputs|github\.event|github\.head_ref)\b", line):
            assert re.fullmatch(r"\s+[A-Z][A-Z0-9_]*:\s*\$\{\{[^}]+\}\}\s*", line) or "description:" in line, (
                f"{workflow.name}: untrusted expression outside an env mapping: {line.strip()}"
            )


def test_the_integration_workflow_is_manual_only_and_targets_a_self_hosted_kvm_runner() -> None:
    text = (REPO / ".github/workflows/integration.yml").read_text()
    on_block = text.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
    assert "workflow_dispatch:" in on_block
    assert "push:" not in on_block
    assert "pull_request" not in on_block, "a pull request must never run code on a machine that has root and KVM"
    assert "self-hosted" in text
    assert "kvm" in re.search(r"runs-on:.*", text).group(0)  # type: ignore[union-attr]


def test_the_docs_only_name_make_targets_that_exist() -> None:
    bad: list[tuple[str, str]] = []
    for doc in DOCS:
        if not doc.is_file():
            continue
        bad.extend((doc.name, t) for t in re.findall(r"`make ([a-z][a-z0-9-]*)", doc.read_text()) if t not in TARGETS)
    assert not bad, f"docs mention make targets that do not exist: {bad}"
