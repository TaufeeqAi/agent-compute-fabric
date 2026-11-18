"""The Makefile is the gate: CI, the docs and humans all call the same targets, so they must exist and mean what
they say. These tests keep three things from drifting apart without anyone noticing:

* the targets the workflows and docs invoke exist in the Makefile (a renamed target would otherwise turn a CI job
  into a no-op error nobody sees until the next push);
* ``make release`` can never quietly start building the production binary with the test-only feature;
* the generated contracts are checked in BOTH directories, the Rust targets cover the whole workspace, and the
  unit check covers every shipped unit;
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
        "help", "check", "ci", "release", "guest-agent", "fake-host", "schema", "check-schema", "schemas",
        "check-schemas", "rust-fmt", "rust-lint", "rust-test", "net-plumbing-test", "root-test", "py-lint", "py-test", "e2e",
        "tools-lint", "tools-pytest",
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


def variable(name: str) -> str:
    """The value a simple `NAME := value` (or `NAME ?= value`) assignment gives a Makefile variable."""
    found = re.search(rf"^{name}\s*[:?]=\s*(.+)$", MAKEFILE.read_text(), re.MULTILINE)
    assert found is not None, f"the Makefile does not define {name}"
    return found.group(1).strip()


def test_the_generated_contracts_are_written_and_checked_in_both_directories() -> None:
    """`acf-host schema` writes the host API and event schemas to one directory and the file formats to another."""
    assert variable("CONTRACTS_DIR") == "execution/contracts"
    assert variable("SCHEMA_DIR") == "schemas"
    assert (REPO / "execution/contracts/host-api.json").is_file()
    assert (REPO / "schemas/host-config.schema.json").is_file()
    assert "-- schema" in variable("SCHEMA_CMD")
    assert "--locked" in variable("SCHEMA_CMD")

    schema = " ".join(RECIPES["schema"])
    assert "--contracts $(CONTRACTS_DIR)" in schema
    assert "--out $(SCHEMA_DIR)" in schema

    check = " ".join(RECIPES["check-schema"])
    generate = check.split("$(SCHEMA_CMD)", 1)[1].split(";", 1)[0]
    assert "--contracts" in generate
    assert "--out" in generate
    assert "$(CONTRACTS_DIR)" not in generate, "the check generates into a scratch directory"
    assert "$(SCHEMA_DIR)" not in generate, "it must never overwrite the checked-in files"
    for checked_in in ("$(CONTRACTS_DIR)", "$(SCHEMA_DIR)"):
        assert f"diff -ru {checked_in} " in check, f"{checked_in} is generated but its drift is not checked"
    assert "exit 1" in check, "a difference must fail the build"


def test_the_old_schema_target_names_still_work_and_mean_the_same() -> None:
    """Other documents call them `schemas` and `check-schemas`; the host's own test says `make schema`."""
    for alias, target in (("schemas", "schema"), ("check-schemas", "check-schema")):
        assert PREREQS[alias] == [target]
        assert RECIPES[alias] == [], f"{alias} must not grow a recipe of its own"
    assert "run `make schema`" in (REPO / "execution/host-agent/src/api/schema.rs").read_text()


def test_the_rust_targets_cover_the_whole_workspace_with_every_feature() -> None:
    assert any("fmt --all" in line and "--check" in line for line in RECIPES["rust-fmt"])
    for target in ("rust-lint", "rust-test"):
        line = " ".join(RECIPES[target])
        assert "--workspace" in line, target
        assert "--all-features" in line, target
        assert "--locked" in line, target
    assert "-D warnings" in " ".join(RECIPES["rust-lint"])
    members = re.search(r"^members = \[(.+)\]$", (REPO / "Cargo.toml").read_text(), re.MULTILINE)
    assert members is not None
    assert len(members.group(1).split(",")) >= 4, "wire, traffic, host-agent, guest-agent"


def test_the_namespace_tests_have_a_target_that_runs_the_script_and_ci_requires_them() -> None:
    recipe = " ".join(RECIPES["net-plumbing-test"])
    assert "scripts/net-plumbing-test.sh" in recipe
    assert (REPO / "scripts/net-plumbing-test.sh").is_file()
    assert "unshare --user --map-root-user --net --mount" in DOCUMENTED["net-plumbing-test"]
    assert "net-plumbing-test" in PREREQS["check"], "it skips cleanly where it cannot run, so it belongs in `check`"
    ci = (REPO / ".github/workflows/ci.yml").read_text()
    runs = [line.strip() for line in ci.splitlines() if "make net-plumbing-test" in line and "run:" in line]
    assert runs == ["run: ACF_REQUIRE_NETNS=1 make net-plumbing-test"], (
        "`cargo test` ignores these tests, so in CI a skip must be a failure"
    )
    assert "kernel.apparmor_restrict_unprivileged_userns=0" in ci, (
        "an ubuntu-24.04 runner refuses `unshare --user` until this restriction is lifted"
    )


def test_the_root_only_tests_have_a_target_that_builds_unprivileged_and_ci_runs_it() -> None:
    """The Rust tests marked "needs root: run with `make root-test`" are ignored by `cargo test`."""
    recipe = " ".join(RECIPES["root-test"])
    assert "scripts/root-test.sh" in recipe
    assert "sudo" not in recipe, "the target must not run cargo as root; the script elevates only the test binaries"
    assert "root-test" not in PREREQS["check"], "`check` is what runs without root"
    assert "root-test" in PREREQS["ci"]
    ci = (REPO / ".github/workflows/ci.yml").read_text()
    runs = [line.strip() for line in ci.splitlines() if "make root-test" in line and "run:" in line]
    assert runs == ["run: make root-test"], "not `sudo make root-test`: that would leave root's files in target/"


def test_systemd_verify_covers_every_unit_and_stages_every_program_they_start() -> None:
    assert variable("UNITS") == "$(notdir $(wildcard deploy/systemd/*.service))", "every unit, with no list to forget"
    recipe = " ".join(RECIPES["systemd-verify"])
    assert "systemd-analyze verify" in recipe
    assert "$(addprefix /etc/systemd/system/,$(UNITS))" in recipe
    assert "grep -q 'acf-'" in recipe, "a setting systemd warns about and ignores must fail the target too"
    programs: set[str] = set()
    for unit in (REPO / "deploy/systemd").glob("*.service"):
        programs.update(re.findall(r"^Exec\w+=[-@+!]*(/\S+)", unit.read_text(), re.MULTILINE))
    assert programs, "the units start something"
    for program in programs:
        assert f'"$$root{program}"' in recipe, f"{program} is started by a unit but not staged for the check"


def test_the_client_targets_use_only_the_clients_public_surface() -> None:
    """The client is a project of its own. These targets may know where it is, how to run its tools, its `e2e`
    marker and the two variables that marker documents; nothing about its modules or its test files."""
    assert variable("CLI_RUN").endswith("$(UV) --directory apps/cli run --locked")
    for target in ("py-lint", "py-test", "e2e"):
        for line in RECIPES[target]:
            assert line.startswith(("$(CLI_RUN) ", "ACF_REQUIRE_E2E=1 ")), f"{target}: {line}"
            assert "apps/cli" not in line, f"{target} reaches into the client: {line}"
            assert not re.search(r"\bsrc/|tests/|\.py\b|acf_cli", line), f"{target} names a client internal: {line}"
    assert RECIPES["py-test"] == ["$(CLI_RUN) pytest"]
    e2e = " ".join(RECIPES["e2e"])
    assert "pytest -m e2e" in e2e
    assert 'ACF_HOST_FAKE="$(abspath $(HOST_FAKE))"' in e2e
    markers = (REPO / "apps/cli/pyproject.toml").read_text()
    assert '"e2e: ' in markers, "the client no longer declares the marker this target selects"


def test_the_archive_is_named_after_what_it_holds() -> None:
    assert variable("DIST_NAME") == "agent-compute-fabric-execution-plane"
    dist = " ".join(RECIPES["dist"])
    assert "--out $(DIST_DIR)/$(DIST_NAME).zip" in dist
    assert "--prefix $(DIST_NAME)" in dist
    ci = (REPO / ".github/workflows/ci.yml").read_text()
    assert "name: acf-execution-plane-binaries" in ci


def test_the_aggregates_name_the_whole_gate() -> None:
    assert PREREQS["check"] == [
        "rust-fmt", "rust-lint", "rust-test", "net-plumbing-test", "check-schema", "py-lint", "py-test",
        "tools-test", "systemd-verify", "check-pins",
    ]  # fmt: skip
    assert PREREQS["ci"] == ["check", "root-test", "release", "e2e", "driver-selftest", "control-plane"]
    assert RECIPES["check"] == []
    assert RECIPES["ci"] == []


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
        "net-plumbing-test",
        "root-test",
        "check-schema",
        "systemd-verify",
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


def test_the_integration_workflow_starts_the_units_in_their_order_and_leaves_the_enforcer_running() -> None:
    text = (REPO / ".github/workflows/integration.yml").read_text()
    assert "systemctl enable --now acf-cgroup.service acf-lifetime.service acf-host.service" in text
    assert "scripts/host-setup.sh install --acf-host target/release/acf-host" in text
    assert "acf-host doctor --config /etc/acf/host.yaml" in text
    for unit in ("acf-host.service", "acf-lifetime.service", "acf-cgroup.service"):
        assert f"-u {unit}" in text, f"the journal of {unit} is not collected"
    stops = [line.strip() for line in text.splitlines() if "systemctl stop" in line]
    assert stops == ["run: sudo systemctl stop acf-host.service || true"], (
        "the enforcer is what still ends a sandbox a failed test left behind"
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
