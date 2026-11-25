"""The Makefile is the gate: CI, the docs and humans all call the same targets, so they must exist and mean what
they say. These tests keep three things from drifting apart without anyone noticing:

* the targets the workflows and docs invoke exist in the Makefile (a renamed target would otherwise turn a CI job
  into a no-op error nobody sees until the next push);
* ``make release`` can never quietly start building the production binary with the test-only feature;
* the generated contracts are checked in BOTH directories, the Rust targets cover the whole workspace, and the
  unit check covers every shipped unit;
* the workflows stay least-privilege: read-only token, actions pinned to exact versions, no attacker-controlled
  text interpolated into a shell script;
* the developer platform has a gate of its own that its workflow runs completely, and the one workflow that
  publishes packages holds no registry token and asks for nothing but an identity token, in the two jobs that
  upload and nowhere else.

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
DOCS = [*sorted((REPO / "docs").rglob("*.md")), REPO / "README.md"] if (REPO / "docs").is_dir() else []

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
    assert variable("CLI_RUN").endswith("$(UV) --directory apps/host-cli run --locked")
    for target in ("py-lint", "py-test", "e2e"):
        for line in RECIPES[target]:
            assert line.startswith(("$(CLI_RUN) ", "ACF_REQUIRE_E2E=1 ")), f"{target}: {line}"
            assert "apps/host-cli" not in line, f"{target} reaches into the client: {line}"
            assert not re.search(r"\bsrc/|tests/|\.py\b|acf_cli", line), f"{target} names a client internal: {line}"
    assert RECIPES["py-test"] == ["$(CLI_RUN) pytest"]
    e2e = " ".join(RECIPES["e2e"])
    assert "pytest -m e2e" in e2e
    assert 'ACF_HOST_FAKE="$(abspath $(HOST_FAKE))"' in e2e
    markers = (REPO / "apps/host-cli/pyproject.toml").read_text()
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


#: The one permission beyond `contents: read` that any workflow may ask for, and the one workflow that may ask
#: for it. An identity token changes nothing in the repository: it lets a job prove to a package registry which
#: repository, workflow and environment is publishing, so that no registry token has to exist at all.
IDENTITY_TOKEN = "id-token: write"
MAY_ASK_FOR_AN_IDENTITY_TOKEN = {"release.yml"}


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_workflows_are_least_privilege(workflow: Path) -> None:
    text = workflow.read_text()
    assert re.search(r"^permissions:\n  contents: read\n", text, re.MULTILINE), (
        "top-level permissions must be read-only"
    )
    writes = [line.strip() for line in text.splitlines() if re.search(r":\s*write\b", line)]
    allowed = [IDENTITY_TOKEN] if workflow.name in MAY_ASK_FOR_AN_IDENTITY_TOKEN else []
    assert set(writes) <= set(allowed), f"no job may ask for write access: {writes}"
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


# ------------------------------------------------------------------------------- the developer platform
PLATFORM_WORKFLOW = REPO / ".github/workflows/platform.yml"
RELEASE_WORKFLOW = REPO / ".github/workflows/release.yml"
PLATFORM_PYTHON_PROJECTS = ["apps/api", "apps/mcp-gateway", "sdks/python", "apps/cli"]
PLATFORM_NPM_PROJECT = "sdks/typescript"


def jobs_of(workflow: Path) -> dict[str, str]:
    """The text of every job of a workflow, by its id. Jobs are the keys indented by two spaces under `jobs:`."""
    body = workflow.read_text().split("\njobs:\n", 1)[1]
    found: dict[str, str] = {}
    name = ""
    for line in body.splitlines():
        m = re.fullmatch(r"  ([a-z][a-z0-9-]*):", line)
        if m:
            name = m.group(1)
            found[name] = ""
        elif name:
            found[name] += line + "\n"
    return found


def test_the_platform_has_a_gate_of_its_own_and_the_two_gates_do_not_reach_into_each_other() -> None:
    required = {
        "platform-artifacts", "platform-drift", "platform-compat", "platform-lint", "platform-test", "platform-e2e",
        "platform-sdk-ts", "platform-units", "platform-audit", "platform-dist", "platform-check", "platform-ci",
    }  # fmt: skip
    assert required <= TARGETS, f"missing: {sorted(required - TARGETS)}"
    assert PREREQS["platform-check"] == [
        "platform-drift", "platform-compat", "platform-lint", "platform-test", "platform-sdk-ts", "platform-units",
    ]  # fmt: skip
    assert PREREQS["platform-ci"] == ["platform-check", "platform-e2e", "platform-dist"]
    assert RECIPES["platform-check"] == []
    assert RECIPES["platform-ci"] == []
    assert not [t for t in PREREQS["check"] + PREREQS["ci"] if t.startswith("platform-")]
    assert "platform-audit" not in PREREQS["platform-check"], (
        "an advisory published today must not turn an unrelated change red"
    )


def test_the_platform_targets_cover_every_project_and_each_project_has_a_lock() -> None:
    assert variable("PLATFORM_PY").split() == PLATFORM_PYTHON_PROJECTS
    assert variable("SDK_TS") == PLATFORM_NPM_PROJECT
    for project in PLATFORM_PYTHON_PROJECTS:
        assert (REPO / project / "pyproject.toml").is_file(), project
        assert (REPO / project / "uv.lock").is_file(), f"{project} has no lock"
    assert (REPO / PLATFORM_NPM_PROJECT / "package-lock.json").is_file()
    for target in ("platform-lint", "platform-test", "platform-audit", "platform-dist"):
        assert "for project in $(PLATFORM_PY)" in " ".join(RECIPES[target]), f"{target} does not cover every project"
    lint = " ".join(RECIPES["platform-lint"])
    for tool in ("ruff check .", "ruff format --check .", "mypy"):
        assert f"run --locked {tool}" in lint
    for target in ("platform-lint", "platform-test", "platform-e2e", "platform-drift", "platform-artifacts"):
        for line in RECIPES[target]:
            assert "run" not in line or "--locked" in line, f"{target} runs something outside the lock: {line}"


def test_the_platform_targets_use_only_each_projects_public_surface() -> None:
    """They may know where a project is, how to run its tools and its `host` marker; nothing about its modules."""
    for target in ("platform-lint", "platform-test", "platform-e2e", "platform-sdk-ts"):
        for line in RECIPES[target]:
            assert not re.search(r"\bsrc/|tests/|\.py\b|acf_api|acf_mcp|agentcompute", line), (
                f"{target} names an internal: {line}"
            )
    e2e = " ".join(RECIPES["platform-e2e"])
    assert PREREQS["platform-e2e"] == ["fake-host"]
    assert "ACF_REQUIRE_HOST=1" in e2e, "without it a missing host binary is a quiet skip"
    assert 'ACF_HOST_FAKE="$(abspath $(HOST_FAKE))"' in e2e
    assert "pytest -m host" in e2e
    assert '"host: ' in (REPO / "apps/api/pyproject.toml").read_text(), (
        "the API no longer declares the marker this target selects"
    )
    scripts = (REPO / PLATFORM_NPM_PROJECT / "package.json").read_text()
    for script in re.findall(r"\$\(NPM\) run ([a-z:-]+)", " ".join(RECIPES["platform-sdk-ts"])):
        assert f'"{script}":' in scripts, f"the TypeScript SDK has no script named {script}"
    assert "$(NPM) ci" in " ".join(RECIPES["platform-sdk-ts"]), "the install must be the locked one"


def test_the_contract_files_are_generated_into_place_and_checked_without_being_overwritten() -> None:
    assert variable("PROTOCOLS_DIR") == "protocols"
    assert (REPO / "protocols/api/openapi.yaml").is_file()
    write, check = " ".join(RECIPES["platform-artifacts"]), " ".join(RECIPES["platform-drift"])
    assert "--check" not in write
    assert check == write + " --check"


def test_platform_units_covers_every_unit_and_stages_every_program_they_start() -> None:
    assert variable("PLATFORM_UNITS") == "$(notdir $(wildcard deploy/platform/systemd/*.service))"
    recipe = " ".join(RECIPES["platform-units"])
    assert "systemd-analyze verify" in recipe
    assert "$(addprefix /etc/systemd/system/,$(PLATFORM_UNITS))" in recipe
    assert "grep -q 'acf-'" in recipe, "a setting systemd warns about and ignores must fail the target too"
    units = sorted((REPO / "deploy/platform/systemd").glob("*.service"))
    assert [unit.name for unit in units] == [
        "acf-platform-core.service", "acf-platform-mcp.service", "acf-platform-rest.service",
    ]  # fmt: skip
    programs: set[str] = set()
    for unit in units:
        programs.update(re.findall(r"^Exec\w+=[-@+!]*(/\S+)", unit.read_text(), re.MULTILINE))
    assert programs, "the units start something"
    for program in programs:
        assert f'"$$root{program}"' in recipe, f"{program} is started by a unit but not staged for the check"


def test_the_platform_workflow_runs_the_whole_gate_that_make_platform_ci_names() -> None:
    called = {t for t, _ in make_invocations(PLATFORM_WORKFLOW.read_text())}

    def expand(name: str) -> set[str]:
        if RECIPES[name]:
            return {name}
        return set().union(*(expand(dep) for dep in PREREQS[name]))

    wanted = expand("platform-ci")
    assert {
        "platform-drift",
        "platform-compat",
        "platform-lint",
        "platform-test",
        "platform-e2e",
        "platform-sdk-ts",
        "platform-units",
        "platform-dist",
    } == wanted
    missing = sorted(wanted - called)
    assert not missing, f"`make platform-ci` includes targets that platform.yml never runs: {missing}"
    assert called - wanted == {"platform-deploy-test"}, "beyond the gate, CI runs the deployment test and nothing else"


def test_the_contract_files_are_compared_with_the_last_release_and_ci_can_find_that_release() -> None:
    """A comparison that finds no release compares with nothing and passes. In CI that must not happen by accident."""
    recipe = " ".join(RECIPES["platform-compat"])
    assert variable("COMPAT_BASELINE") == "$(shell git describe --tags --match 'acf-api-v*' --abbrev=0 2>/dev/null)"
    assert 'baseline="$(COMPAT_BASELINE)"' in recipe
    assert 'git archive --format=tar "$$baseline" -- "$(PROTOCOLS_DIR)"' in recipe
    assert 'acf-api compat --baseline "$$base/$(PROTOCOLS_DIR)" --accept "$(abspath $(COMPAT_ACCEPTED))"' in recipe
    assert recipe.count("there is no release to compare with") == 2, "a run that compared nothing says so, and why"
    assert 'elif [ -n "$${CI:-}" ]; then' in recipe, "in CI a checkout that git cannot read is a failure, not a pass"
    accepted = REPO / variable("COMPAT_ACCEPTED")
    assert accepted.is_file(), "the reviewed exceptions are a file of the repository, even while there are none"
    findings = [line for line in accepted.read_text().splitlines() if line.strip() and not line.startswith("#")]
    assert all(line.startswith(("REST: ", "tool ", "problems: ")) for line in findings), findings
    release = (REPO / ".github/workflows/release.yml").read_text()
    assert "acf-api-v*" in release, "the tag the comparison looks for is the tag a release of the API is made from"
    job = jobs_of(PLATFORM_WORKFLOW)["contract"]
    assert "run: make platform-compat" in job
    assert "fetch-depth: 0" in job, "a shallow clone has no tags: the comparison would find no release"
    assert "fetch-tags: true" in job
    for name, text in jobs_of(PLATFORM_WORKFLOW).items():
        assert name == "contract" or "fetch-depth: 0" not in text, f"{name} does not need the history"


def test_the_deployment_test_is_in_no_aggregate_and_never_consents_for_its_caller() -> None:
    """It installs the platform on the machine it runs on. Only the caller can say that the machine is disposable."""
    for aggregate in ("check", "ci", "platform-check", "platform-ci"):
        assert "platform-deploy-test" not in PREREQS[aggregate], aggregate
    assert PREREQS["platform-deploy-test"] == ["fake-host"]
    recipe = " ".join(RECIPES["platform-deploy-test"])
    assert 'ACF_DEPLOY_TEST="$${ACF_DEPLOY_TEST:-}"' in recipe, "the consent is passed through, never supplied"
    assert "ACF_DEPLOY_TEST=1" not in recipe
    assert 'ACF_HOST_FAKE="$(abspath $(HOST_FAKE))"' in recipe
    assert "bash scripts/platform-deploy-test.sh" in recipe
    assert "THROW-AWAY MACHINES ONLY" in DOCUMENTED["platform-deploy-test"]
    job = jobs_of(PLATFORM_WORKFLOW)["deployed"]
    assert '          ACF_DEPLOY_TEST: "1"\n        run: make platform-deploy-test\n' in job
    assert "self-hosted" not in job, "it must run on a machine that is thrown away"
    for other, text in jobs_of(PLATFORM_WORKFLOW).items():
        assert other == "deployed" or "ACF_DEPLOY_TEST" not in text


def test_every_lock_of_the_platform_is_audited_and_kept_fresh() -> None:
    audit = (REPO / ".github/workflows/audit.yml").read_text()
    dependabot = (REPO / ".github/dependabot.yml").read_text()
    assert "run: make platform-audit" in audit
    for project in PLATFORM_PYTHON_PROJECTS:
        assert f"      - {project}/uv.lock\n" in audit, f"a change to the lock of {project} does not start the audit"
        assert f"  - package-ecosystem: uv\n    directory: /{project}\n" in dependabot, project
    assert f"      - {PLATFORM_NPM_PROJECT}/package-lock.json\n" in audit
    assert f"  - package-ecosystem: npm\n    directory: /{PLATFORM_NPM_PROJECT}\n" in dependabot
    recipe = " ".join(RECIPES["platform-audit"])
    assert "--locked" in recipe
    assert "--strict" in recipe
    assert "--no-dev" not in recipe, "the tools that build a release are audited too"
    assert re.search(r"pip-audit==\d+\.\d+\.\d+", variable("PIP_AUDIT")), "the auditor itself is pinned"
    assert "$(NPM) audit signatures" in recipe


# ------------------------------------------------------------------------------------------ publishing
def test_packages_are_published_only_from_a_tag_and_only_after_the_audit_and_the_build() -> None:
    text = RELEASE_WORKFLOW.read_text()
    on_block = text.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
    assert "tags:" in on_block
    assert "workflow_dispatch:" in on_block
    for trigger in ("branches:", "pull_request", "schedule:"):
        assert trigger not in on_block, f"a release must not start from {trigger}"
    jobs = jobs_of(RELEASE_WORKFLOW)
    assert set(jobs) == {"plan", "audit", "build", "publish-pypi", "publish-npm"}
    for name in ("publish-pypi", "publish-npm"):
        job = jobs[name]
        assert "    needs: [plan, audit, build]\n" in job, f"{name} can run without the audit or the build"
        assert "github.event_name == 'push'" in job, f"{name} would publish from a dry run"
    assert "run: make platform-audit" in jobs["audit"]
    assert "run: make platform-dist" in jobs["build"]


def test_no_registry_token_exists_and_only_the_two_uploading_jobs_get_an_identity_token() -> None:
    text = RELEASE_WORKFLOW.read_text()
    assert "secrets." not in text, "publishing is by identity, never by a stored token"
    for forbidden in ("NODE_AUTH_TOKEN", "NPM_TOKEN", "PYPI_API_TOKEN", "TWINE_PASSWORD", "password:"):
        assert forbidden not in text, forbidden
    jobs = jobs_of(RELEASE_WORKFLOW)
    for name, job in jobs.items():
        publishes = name.startswith("publish-")
        assert (IDENTITY_TOKEN in job) == publishes, name
        assert ("    environment: " in job) == publishes, f"{name}: a protected environment guards exactly the uploads"
        if publishes:
            assert "    permissions:\n      id-token: write\n" in job, f"{name} asks for more than an identity token"
            assert "actions/checkout@" not in job, (
                f"{name} holds the identity token: it must not run the repository's code"
            )
            assert "make " not in job
            assert "actions/download-artifact@" in job, f"{name} uploads what the build job built"
    assert text.count(IDENTITY_TOKEN) == 2


def test_a_release_without_provenance_is_not_a_release() -> None:
    jobs = jobs_of(RELEASE_WORKFLOW)
    pypi, npm = jobs["publish-pypi"], jobs["publish-npm"]
    assert "pypa/gh-action-pypi-publish@" in pypi
    assert "          attestations: true\n" in pypi
    assert "          skip-existing: false\n" in pypi, "a version is published once and never replaced"
    assert re.search(r"npm publish .* --provenance", npm), "without the flag a missing statement is silent"
    assert "11.5.1" in npm, "trusted publishing needs this npm or newer"


def test_every_tag_the_release_workflow_listens_for_names_a_package_it_can_plan() -> None:
    text = RELEASE_WORKFLOW.read_text()
    on_block = text.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
    tags = re.findall(r'^      - "([a-z-]+)-v\*"$', on_block, re.MULTILINE)
    assert sorted(tags) == ["acf-api", "acf-mcp-gateway", "agent-compute", "agent-compute-cli", "sdk-typescript"]
    plan = jobs_of(RELEASE_WORKFLOW)["plan"]
    cases = re.findall(r"^\s+([a-z-]+)-v\*\)\s+prefix=(\S+);\s+registry=(\w+);\s+directory=(\S+);", plan, re.MULTILINE)
    assert sorted(name for name, *_ in cases) == sorted(tags)
    order = [name for name, *_ in cases]
    assert order.index("agent-compute-cli") < order.index("agent-compute"), "the longer name must be tried first"
    for name, prefix, registry, directory in cases:
        assert prefix == f"{name}-v"
        project = REPO / directory
        if registry == "pypi":
            assert directory in PLATFORM_PYTHON_PROJECTS
            assert re.search(rf'^name = "{name}"$', (project / "pyproject.toml").read_text(), re.MULTILINE), directory
        else:
            assert (registry, directory) == ("npm", PLATFORM_NPM_PROJECT)
            assert (project / "package.json").is_file()
