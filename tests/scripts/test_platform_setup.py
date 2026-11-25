"""scripts/platform-setup.sh and scripts/platform-deploy-test.sh: the decisions they take before they touch anything.

The installer builds environments, creates accounts and installs units, and the deployment test starts services and
inspects processes. Neither belongs in a unit test: the real thing is `make platform-deploy-test`, which CI runs on a
runner it throws away. What is tested here is what must hold on every machine, including a developer's:

* a wrong command line is a usage error, and help never needs root;
* nothing is installed by somebody who is not root;
* the deployment test changes a machine only when its caller said that the machine is disposable, and it checks
  everything it needs before it changes anything;
* the two scripts, the units, the account table and the directory table name the same accounts, paths and units.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

Runner = Callable[..., "subprocess.CompletedProcess[str]"]

REPO = Path(__file__).resolve().parents[2]
SETUP = REPO / "scripts/platform-setup.sh"
DEPLOY_TEST = REPO / "scripts/platform-deploy-test.sh"
DEPLOY = REPO / "deploy/platform"
BASH = shutil.which("bash") or "/bin/bash"
AS_ROOT = os.geteuid() == 0
CONSENT = "ACF_DEPLOY_TEST"


def units() -> list[str]:
    return sorted(unit.name for unit in (DEPLOY / "systemd").glob("*.service"))


def accounts() -> set[str]:
    table = (DEPLOY / "sysusers.d/acf-platform.conf").read_text()
    return set(re.findall(r"^u\s+(\S+)", table, re.MULTILINE))


def directories() -> set[str]:
    table = (DEPLOY / "tmpfiles.d/acf-platform.conf").read_text()
    return set(re.findall(r"^d\s+(\S+)", table, re.MULTILINE))


# --------------------------------------------------------------------------------------------- the command line
@pytest.mark.parametrize("arguments", [["--help"], ["-h"], ["help"], ["install", "--help"], ["check", "--help"]])
def test_help_needs_no_root_and_names_both_commands(run: Runner, arguments: list[str]) -> None:
    result = run([BASH, SETUP, *arguments])
    assert result.returncode == 0, result.stderr
    assert "platform-setup.sh install" in result.stdout
    assert "platform-setup.sh check" in result.stdout
    assert "--host-enrolment FILE" in result.stdout


@pytest.mark.parametrize(
    ("arguments", "said"),
    [
        ([], "Usage:"),
        (["uninstall"], "unknown command: uninstall"),
        (["install", "--force"], "install: unknown option: --force"),
        (["install", "--prefix", "relative/path"], "--prefix must be an absolute path"),
        (["check", "now"], "check: unknown option: now"),
        (["check", "--other-certificate", "x"], "check: unknown option: --other-certificate"),
    ],
)
def test_a_wrong_command_line_is_a_usage_error_before_anything_else(
    run: Runner, arguments: list[str], said: str
) -> None:
    result = run([BASH, SETUP, *arguments])
    assert result.returncode == 2, result.stderr
    assert said in result.stderr
    assert result.stdout == ""


@pytest.mark.skipif(AS_ROOT, reason="as root the installer would install")
@pytest.mark.parametrize("command", ["install", "check"])
def test_nothing_is_installed_or_checked_by_somebody_who_is_not_root(run: Runner, command: str) -> None:
    result = run([BASH, SETUP, command])
    assert result.returncode == 1
    assert "must run as root" in result.stderr


# ------------------------------------------------------------------------------------------ the deployment test
def test_the_deployment_test_refuses_a_machine_nobody_called_disposable(run: Runner) -> None:
    """The first thing it looks at is the consent, as root and as anybody: without it nothing else is even checked."""
    result = run([BASH, DEPLOY_TEST], env={"ACF_HOST_FAKE": "/bin/true"})
    assert result.returncode == 1
    assert "set ACF_DEPLOY_TEST=1 on a machine you throw away" in result.stderr
    assert "ACF_HOST_FAKE" not in result.stderr.replace("ACF_DEPLOY_TEST", "")


@pytest.mark.parametrize("consent", ["0", "yes", "true", ""])
def test_only_the_exact_value_is_consent(run: Runner, consent: str) -> None:
    result = run([BASH, DEPLOY_TEST], env={CONSENT: consent, "ACF_HOST_FAKE": "/bin/true"})
    assert result.returncode == 1
    assert "set ACF_DEPLOY_TEST=1" in result.stderr


@pytest.mark.skipif(AS_ROOT, reason="as root the next check is reached instead")
def test_with_consent_it_still_needs_root(run: Runner) -> None:
    result = run([BASH, DEPLOY_TEST], env={CONSENT: "1", "ACF_HOST_FAKE": "/bin/true"})
    assert result.returncode == 1
    assert "must run as root" in result.stderr


@pytest.mark.needs_root
def test_as_root_with_consent_it_stops_at_the_missing_test_host_before_it_changes_anything(run: Runner) -> None:
    before = sorted(path.name for path in Path("/etc").iterdir())
    result = run([BASH, DEPLOY_TEST], env={CONSENT: "1", "ACF_HOST_FAKE": "/nonexistent/acf-host-fake"})
    assert result.returncode == 1
    assert "ACF_HOST_FAKE must name the test host binary" in result.stderr
    assert sorted(path.name for path in Path("/etc").iterdir()) == before


def test_every_precondition_is_checked_before_the_first_change() -> None:
    """In `main`, the checks come first and `install_and_configure` after them: a refusal leaves the machine alone."""
    text = DEPLOY_TEST.read_text()
    main = text.split("\nmain() {\n", 1)[1]
    first_change = main.index("install_and_configure")
    for precondition in (
        'ACF_DEPLOY_TEST:-}" == 1',
        "require_root",
        "ACF_HOST_FAKE must name",
        "systemd is not the first process",
        "already has a deployment",
        "need_cmd",
    ):
        assert precondition in main, precondition
        assert main.index(precondition) < first_change, f"{precondition} is checked after the machine was changed"


def test_usage_of_the_deployment_test(run: Runner) -> None:
    assert run([BASH, DEPLOY_TEST, "--help"]).returncode == 0
    result = run([BASH, DEPLOY_TEST, "now"], env={CONSENT: "1"})
    assert result.returncode == 2
    assert "unknown argument: now" in result.stderr


# ------------------------------------------------------------------- the scripts and the shipped files agree
def test_the_installer_installs_every_shipped_unit_and_the_test_starts_every_one() -> None:
    setup, test = SETUP.read_text(), DEPLOY_TEST.read_text()
    assert 'for unit in "$UNIT_SOURCE"/acf-platform-*.service; do' in setup, "every unit, with no list to forget"
    assert 'readonly UNIT_SOURCE="$REPO/deploy/platform/systemd"' in setup
    started = re.search(r"^readonly UNITS=\(([^)]*)\)$", test, re.MULTILINE)
    assert started is not None
    assert sorted(started.group(1).split()) == units()
    assert started.group(1).split()[0] == "acf-platform-core.service", "the test indexes the core as the first unit"
    for unit in units():
        assert unit in setup or "acf-platform-*.service" in setup


def test_the_accounts_the_scripts_name_are_the_ones_the_account_table_creates() -> None:
    setup, test = SETUP.read_text(), DEPLOY_TEST.read_text()
    named = re.search(r"^readonly CORE_USER=(\S+) REST_USER=(\S+) MCP_USER=(\S+)$", setup, re.MULTILINE)
    assert named is not None
    assert set(named.groups()) == accounts()
    for account in accounts():
        assert account in test, f"the deployment test never checks {account}"
    assert "acf-testhost" not in accounts(), "the test host's account is the test's own, never a shipped one"


def test_the_paths_the_scripts_use_are_created_by_the_directory_table() -> None:
    setup, test = SETUP.read_text(), DEPLOY_TEST.read_text()
    assert "readonly ETC=/etc/acf-platform" in setup
    assert "/etc/acf-platform" in directories()
    for used in ("$ETC/secrets", "$ETC/rest", "$ETC/mcp", "$ETC/policies"):
        assert used.replace("$ETC", "/etc/acf-platform") in directories(), used
        assert used in setup or used in test, used
    for state in ("/var/lib/acf-platform", "/var/lib/acf-platform-journal", "/run/acf-platform"):
        assert state in directories()
        assert state in test, f"the deployment test never looks at {state}"


def test_the_installer_builds_both_environments_from_their_locks_and_keeps_them_apart() -> None:
    setup = SETUP.read_text()
    assert "sync --quiet --locked --no-dev --no-editable --reinstall" in setup, (
        "from the lock, without tools, without a link back, and never from a cached build of an older tree"
    )
    for project in ("apps/api", "apps/mcp-gateway", "sdks/python"):
        assert (
            'cache-keys = [{ file = "pyproject.toml" }, { file = "src/**" }]'
            in (REPO / project / "pyproject.toml").read_text()
        ), f"{project}: uv watches only pyproject.toml by default, and the version of this package lives under src/"
    assert "UV_PYTHON_DOWNLOADS=never" in setup, "the interpreter is the system's, not one fetched at install time"
    assert 'build_environment apps/api "$PREFIX/api"' in setup
    assert 'build_environment apps/mcp-gateway "$PREFIX/mcp"' in setup
    assert 'find_spec("mcp") is not None' in setup, "the core's environment must not hold the agent-protocol library"
    assert "chmod -R go-w" in setup
    for project in ("apps/api", "apps/mcp-gateway"):
        assert (REPO / project / "uv.lock").is_file()
    programs: set[str] = set()
    for unit in (DEPLOY / "systemd").glob("*.service"):
        programs.update(re.findall(r"^ExecStart=(/\S+)", unit.read_text(), re.MULTILINE))
    assert programs == {"/opt/acf-platform/api/bin/acf-api", "/opt/acf-platform/mcp/bin/acf-mcp"}
    assert "readonly DEFAULT_PREFIX=/opt/acf-platform" in setup


def test_the_installer_makes_the_deployment_id_and_never_overwrites_a_configuration() -> None:
    setup = SETUP.read_text()
    example = (REPO / "config/platform-core.example.yaml").read_text()
    assert "\ndeployment_id: dep_REPLACE_ME\n" in example
    assert "s/^deployment_id: dep_REPLACE_ME$/deployment_id: $id/" in setup
    assert '"$PREFIX/api/bin/acf-api" deployment-id' in setup
    assert 'if [[ ! -e "$ETC/core.yaml" ]]; then' in setup
    assert '"$dst.dist"' in setup, "an operator's changed file is kept and the shipped one offered beside it"
    assert "--force-config" not in setup
    edge = (REPO / "config/platform-edge.example.yaml").read_text()
    assert "\n  port: 8443\n" in edge
    assert "/etc/acf-platform/rest/tls.key" in edge


def test_the_check_lints_the_hosts_enrolment_table_as_the_core_with_copies_of_public_files_only() -> None:
    """The host does not tell a caller its role, so the role is read from the host's table (`acf-api check`).

    The check runs as the core's account. That account opens no edge's directory, so root hands it copies:
    the table and each edge's certificate, never a key, in a directory that is removed afterwards.
    """
    setup = SETUP.read_text()
    check = setup.split("\ncmd_check() {\n", 1)[1].split("\n}\n", 1)[0]
    assert '--host-enrolment) enrolment="${2:?--host-enrolment needs a file}" && shift 2 ;;' in check
    assert "make_workdir platform-check" in check, "the copies live in a directory that is removed on exit"
    assert 'install -m 0644 -- "$enrolment" "$ACF_WORKDIR/enrolment.yaml"' in check
    assert 'install -m 0644 -- "$ETC/$edge/tls.crt" "$ACF_WORKDIR/$edge-edge-tls.crt"' in check
    assert 'lint+=(--other-certificate "$ACF_WORKDIR/$edge-edge-tls.crt")' in check
    assert "for edge in rest mcp; do" in check, "every edge the installer knows is named to the lint"
    assert ".key" not in check, "no private key is copied anywhere"
    assert 'runuser -u "$CORE_USER" -- "$api" check --config "$ETC/core.yaml" "${lint[@]}"' in check
    # The deployment test runs it on the table the test host really writes, and on two tables that are wrong.
    test = DEPLOY_TEST.read_text()
    assert 'check --host-enrolment "$table" | field \'["host_enrolment"]\'' in test
    assert '"one entry, role caller"' in test
    assert 'refused "a table that makes the platform an operator of the host"' in test
    assert 'refused "a table in which the host knows an edge\'s certificate"' in test
    advice = setup.split("cat >&2 <<EOF\n", 1)[1].split("\nEOF\n", 1)[0]
    assert "check --host-enrolment <copy of the host's enrolment table>" in advice


def test_the_installer_creates_no_secret_and_starts_nothing() -> None:
    """Creating the deployment, its secrets and its first key, and starting it, are the operator's steps.

    The installer prints them as advice; it runs none of them.
    """
    code = "\n".join(line for line in SETUP.read_text().splitlines() if not line.lstrip().startswith("#"))
    advice = code.split("cat >&2 <<EOF\n", 1)[1].split("\nEOF\n", 1)[0]
    commands = code.replace(advice, "")
    for forbidden in (
        "openssl",
        "systemctl enable",
        "systemctl start",
        "systemctl restart",
        " init --config",
        "key.issue",
    ):
        assert forbidden not in commands, f"the installer runs `{forbidden}`"
    assert "Nothing is enabled or started" in advice
    assert "systemctl enable --now" in advice, "starting is the operator's step, and the installer says how"
    assert " init --config" in advice
