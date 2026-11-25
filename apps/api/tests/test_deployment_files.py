"""The files an operator installs agree with each other and with the code.

A unit, an account table, a directory table and two example configurations describe one deployment in
five places. Nothing but these tests keeps them saying the same thing: the account a unit runs as is one
the account table creates, a path a configuration names is one the directory table creates and the unit
may write, an exit status a unit does not restart on is the one the program really returns.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from acf_api import cli
from acf_api.core import config as cfg
from acf_api.core.parameters import Parameters
from acf_api.edge import config as edge_cfg
from acf_api.edge import server as edge_server

REPO = Path(__file__).resolve().parents[3]
DEPLOY = REPO / "deploy" / "platform"
UNIT_DIR = DEPLOY / "systemd"
CORE_UNIT = "acf-platform-core.service"
REST_UNIT = "acf-platform-rest.service"
MCP_UNIT = "acf-platform-mcp.service"
UNITS = (CORE_UNIT, REST_UNIT, MCP_UNIT)
EDGE_UNITS = (REST_UNIT, MCP_UNIT)
CORE_EXAMPLE = REPO / "config" / "platform-core.example.yaml"
EDGE_EXAMPLE = REPO / "config" / "platform-edge.example.yaml"
PLACEHOLDER = "deployment_id: dep_REPLACE_ME"


def directives(unit: str) -> dict[str, list[str]]:
    """Every ``Key=value`` of a unit, in order. A key given twice keeps both values."""
    found: dict[str, list[str]] = {}
    for raw in (UNIT_DIR / unit).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "[")):
            continue
        key, _, value = line.partition("=")
        found.setdefault(key, []).append(value)
    return found


def one(unit: str, key: str) -> str:
    values = directives(unit).get(key, [])
    assert len(values) == 1, f"{unit}: expected exactly one {key}=, found {values}"
    return values[0]


def words(unit: str, key: str) -> list[str]:
    return [word for value in directives(unit).get(key, []) for word in value.split()]


def sysusers() -> dict[str, list[list[str]]]:
    """The account table by line type: ``u`` accounts, ``g`` groups, ``m`` memberships."""
    table: dict[str, list[list[str]]] = {"u": [], "g": [], "m": []}
    for raw in (DEPLOY / "sysusers.d" / "acf-platform.conf").read_text(encoding="utf-8").splitlines():
        if raw.strip() and not raw.startswith("#"):
            fields = raw.split()
            table[fields[0]].append(fields[1:])
    return table


def tmpfiles() -> dict[str, tuple[str, str, str, str]]:
    """The directory table: path -> (mode, user, group, age)."""
    table: dict[str, tuple[str, str, str, str]] = {}
    for raw in (DEPLOY / "tmpfiles.d" / "acf-platform.conf").read_text(encoding="utf-8").splitlines():
        if raw.strip() and not raw.startswith("#"):
            kind, path, mode, user, group, age = raw.split()
            assert kind == "d", raw
            table[path] = (mode, user, group, age)
    return table


def core_example() -> cfg.CoreConfig:
    text = CORE_EXAMPLE.read_text(encoding="utf-8")
    assert PLACEHOLDER in text
    return cfg.parse_config(yaml.safe_load(text.replace(PLACEHOLDER, "deployment_id: dep_0123456789abcdefABCD")))


def edge_example() -> edge_cfg.EdgeConfig:
    return edge_cfg.parse_edge_config(yaml.safe_load(EDGE_EXAMPLE.read_text(encoding="utf-8")))


# ------------------------------------------------------------------------------------- the examples
def test_the_core_example_does_not_load_until_its_deployment_id_is_replaced() -> None:
    with pytest.raises(cfg.ConfigError, match="deployment_id"):
        cfg.parse_config(yaml.safe_load(CORE_EXAMPLE.read_text(encoding="utf-8")))


def test_the_core_example_is_otherwise_a_valid_configuration() -> None:
    config = core_example()
    assert config.edge.users == ["acf-rest", "acf-mcp"]
    assert config.edge.uids == []
    assert config.oauth is None
    assert config.audit_sink is None
    assert config.security.allow_shared_identity is False


def test_every_parameter_the_core_example_shows_is_shown_with_its_default() -> None:
    shown = yaml.safe_load(CORE_EXAMPLE.read_text(encoding="utf-8"))["parameters"]
    defaults = Parameters().model_dump()
    assert shown, "the example shows no parameter"
    for name, value in shown.items():
        assert name in defaults, f"{name} is not a parameter"
        assert defaults[name] == value, f"the example shows {name}: {value}, the default is {defaults[name]}"


def test_the_host_allowances_shown_are_the_ones_the_host_example_grants() -> None:
    """The host does not report its allowance for a peer, so the two example files must say the same number."""
    host = yaml.safe_load((REPO / "config" / "host.example.yaml").read_text(encoding="utf-8"))["operations"]
    text = CORE_EXAMPLE.read_text(encoding="utf-8")
    shown = yaml.safe_load(text)["parameters"]
    assert shown["host_ops_allowance"] == host["rate_limit_per_minute"]
    assert shown["host_reads_allowance"] == host["read_rate_limit_per_minute"]
    assert "operations.rate_limit_per_minute" in text
    assert "operations.read_rate_limit_per_minute" in text


def test_a_generated_deployment_id_is_one_the_configuration_accepts(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["deployment-id"]) == 0
    generated = capsys.readouterr().out.strip()
    assert re.fullmatch(cfg.DEPLOYMENT_ID_PATTERN, generated)
    text = CORE_EXAMPLE.read_text(encoding="utf-8").replace(PLACEHOLDER, f"deployment_id: {generated}")
    assert cfg.parse_config(yaml.safe_load(text)).deployment_id == generated


def test_the_edge_example_is_a_valid_configuration_and_agrees_with_the_core_example() -> None:
    edge, core = edge_example(), core_example()
    assert edge.command_socket == core.paths.command_socket
    assert edge.limits.public_wait_max == core.parameters.public_wait_max
    assert edge.limits.max_public_request_bytes == core.parameters.max_public_request_bytes
    assert edge.mcp.serve_2025_11_25 == core.parameters.mcp_serve_2025_11_25
    assert edge.tls is not None, "the example listens on every address, which needs TLS"


def test_the_journal_of_the_example_lies_outside_the_store() -> None:
    paths = core_example().paths
    assert not paths.journal.is_relative_to(paths.store_dir)
    assert not paths.fingerprint_key.is_relative_to(paths.store_dir)


# ------------------------------------------------------------------------- accounts and directories
def test_the_three_roles_run_under_three_accounts_the_account_table_creates() -> None:
    accounts = {fields[0] for fields in sysusers()["u"]}
    users = {unit: one(unit, "User") for unit in UNITS}
    assert set(users.values()) <= accounts
    assert len(set(users.values())) == len(UNITS), "two roles share an account"
    assert "root" not in users.values()
    for unit in UNITS:
        assert one(unit, "Group") == users[unit], f"{unit}: the primary group is the account's own"


def test_every_account_is_given_its_id_by_the_system() -> None:
    for kind in ("u", "g"):
        for fields in sysusers()[kind]:
            assert fields[1] == "-", f"{fields[0]} has a fixed id"


def test_the_edge_accounts_of_the_units_are_the_ones_the_core_is_told_to_admit() -> None:
    assert sorted(one(unit, "User") for unit in EDGE_UNITS) == sorted(core_example().edge.users)


def test_the_command_group_is_one_group_everywhere() -> None:
    group = core_example().edge.socket_group
    assert group is not None
    table = sysusers()
    assert [group] == [fields[0] for fields in table["g"]]
    members = {fields[0] for fields in table["m"] if fields[1] == group}
    assert members == {one(unit, "User") for unit in UNITS}, "the core must belong to the group it hands the socket to"
    for unit in EDGE_UNITS:
        assert words(unit, "SupplementaryGroups") == [group]
    runtime = str(core_example().paths.command_socket.parent)
    mode, user, owner_group, _ = tmpfiles()[runtime]
    assert (user, owner_group) == (one(CORE_UNIT, "User"), group)
    assert mode == "2750", "set-group-id gives a new socket the command group; nobody else may traverse"


def test_every_directory_a_configuration_names_is_created_with_an_owner_that_can_use_it() -> None:
    table = tmpfiles()
    core, core_user = core_example(), one(CORE_UNIT, "User")
    for path in (
        core.paths.store_dir.parent,
        core.paths.journal.parent,
        core.paths.fingerprint_key.parent,
        core.host.private_key.parent,
    ):
        mode, user, group, _ = table[str(path)]
        assert (mode, user, group) == ("0700", core_user, core_user), path
    for path in (core.paths.command_socket.parent, core.paths.admin_socket.parent):
        assert table[str(path)][1] == core_user
    mode, user, _, _ = table[str(core.paths.policies_dir)]
    assert (mode, user) == ("0755", "root"), "the grant templates are written by root only"
    edge = edge_example()
    assert edge.tls is not None
    mode, user, group, _ = table[str(edge.tls.private_key.parent)]
    assert (mode, user, group) == ("0700", one(REST_UNIT, "User"), one(REST_UNIT, "User"))
    assert table["/etc/acf-platform/mcp"] == ("0700", one(MCP_UNIT, "User"), one(MCP_UNIT, "User"), "-")


def test_no_directory_has_an_age_so_nothing_is_ever_cleaned_up() -> None:
    assert {age for _, _, _, age in tmpfiles().values()} == {"-"}


def test_the_configuration_directory_cannot_be_written_by_any_account_of_the_platform() -> None:
    assert tmpfiles()["/etc/acf-platform"] == ("0755", "root", "root", "-")


# ---------------------------------------------------------------------------------------- the units
@pytest.mark.parametrize("unit", UNITS)
def test_every_unit_is_enabled_for_a_normal_boot_and_starts_one_installed_program(unit: str) -> None:
    assert one(unit, "WantedBy") == "multi-user.target"
    program = one(unit, "ExecStart").split()[0]
    assert program.startswith("/opt/acf-platform/")
    assert "/bin/" in program


def test_the_core_and_the_agent_protocol_edge_run_from_separate_environments() -> None:
    programs = {unit: one(unit, "ExecStart").split() for unit in UNITS}
    assert programs[CORE_UNIT][:2] == ["/opt/acf-platform/api/bin/acf-api", "core"]
    assert programs[REST_UNIT][:2] == ["/opt/acf-platform/api/bin/acf-api", "edge"]
    assert programs[MCP_UNIT][0] == "/opt/acf-platform/mcp/bin/acf-mcp"
    for unit in UNITS:
        assert programs[unit][-2] == "--config"
        assert programs[unit][-1].startswith("/etc/acf-platform/")
    assert len({programs[unit][-1] for unit in UNITS}) == len(UNITS), "each role reads a file of its own"


def test_the_core_announces_readiness_and_the_edges_start_after_it_without_requiring_it() -> None:
    assert one(CORE_UNIT, "Type") == "notify"
    assert one(CORE_UNIT, "NotifyAccess") == "main"
    for unit in EDGE_UNITS:
        assert CORE_UNIT in words(unit, "After")
        assert CORE_UNIT in words(unit, "Wants")
        assert "Requires" not in directives(unit)
        assert "BindsTo" not in directives(unit)
        assert "PartOf" not in directives(unit)


def test_a_start_that_a_precondition_refuses_is_not_retried() -> None:
    assert words(CORE_UNIT, "RestartPreventExitStatus") == [str(cli._EXIT_CONFIG)]
    for unit in EDGE_UNITS:
        assert str(edge_server.EXIT_CONFIG) in words(unit, "RestartPreventExitStatus")
    for unit in UNITS:
        assert one(unit, "Restart") == "on-failure"


def test_a_stop_waits_longer_than_the_drain_and_the_longest_wait() -> None:
    core, edge = core_example(), edge_example()
    assert float(one(CORE_UNIT, "TimeoutStopSec")) > core.parameters.drain_timeout
    assert float(one(REST_UNIT, "TimeoutStopSec")) > edge.limits.public_wait_max
    assert float(one(MCP_UNIT, "TimeoutStopSec")) > edge.mcp.tool_wait


@pytest.mark.parametrize("unit", UNITS)
@pytest.mark.parametrize("forbidden", ["PrivateUsers", "DynamicUser", "PrivateNetwork"])
def test_no_unit_sets_what_would_hide_a_peer_identity_or_the_network(unit: str, forbidden: str) -> None:
    assert forbidden not in directives(unit)


@pytest.mark.parametrize("unit", UNITS)
def test_every_role_is_confined_the_same_way(unit: str) -> None:
    expected = {
        "ProtectSystem": "strict",
        "ProtectHome": "yes",
        "PrivateTmp": "yes",
        "PrivateDevices": "yes",
        "NoNewPrivileges": "yes",
        "CapabilityBoundingSet": "",
        "AmbientCapabilities": "",
        "RestrictNamespaces": "yes",
        "RestrictSUIDSGID": "yes",
        "LockPersonality": "yes",
        "MemoryDenyWriteExecute": "yes",
        "SystemCallArchitectures": "native",
        "SystemCallErrorNumber": "EPERM",
        "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
        "LimitCORE": "0",
        "UMask": "0077",
    }
    for key, value in expected.items():
        assert one(unit, key) == value, f"{unit}: {key}"
    filters = directives(unit)["SystemCallFilter"]
    assert filters[:2] == ["@system-service", "~@privileged @resources"]


def test_only_the_core_may_write_and_only_where_the_directory_table_put_its_state() -> None:
    core = core_example()
    writable = {word.lstrip("-") for word in words(CORE_UNIT, "ReadWritePaths")}
    assert writable <= set(tmpfiles())
    for needed in (core.paths.store_dir.parent, core.paths.journal.parent, core.paths.command_socket.parent):
        assert str(needed) in writable
    for unit in EDGE_UNITS:
        assert "ReadWritePaths" not in directives(unit), "an edge keeps no state"
        hidden = {word.lstrip("-") for word in words(unit, "InaccessiblePaths")}
        assert {
            str(core.paths.store_dir.parent),
            str(core.paths.journal.parent),
            str(core.host.private_key.parent),
        } <= hidden


def test_the_core_hands_its_socket_to_a_group_which_the_filter_must_allow() -> None:
    assert directives(CORE_UNIT)["SystemCallFilter"][2:] == ["@chown"]
    for unit in EDGE_UNITS:
        assert len(directives(unit)["SystemCallFilter"]) == 2


def test_the_core_may_listen_on_no_address_and_each_edge_only_on_its_own_port() -> None:
    assert one(CORE_UNIT, "SocketBindDeny") == "any"
    assert "SocketBindAllow" not in directives(CORE_UNIT)
    ports = {unit: one(unit, "SocketBindAllow") for unit in EDGE_UNITS}
    assert ports[REST_UNIT] == f"tcp:{edge_example().listen.port}"
    assert ports[MCP_UNIT] != ports[REST_UNIT]
    assert f"listen.port to {ports[MCP_UNIT].removeprefix('tcp:')}" in EDGE_EXAMPLE.read_text(encoding="utf-8")
    for unit in EDGE_UNITS:
        assert one(unit, "SocketBindDeny") == "any"


def test_the_units_name_no_program_a_search_path_would_have_to_find() -> None:
    for unit in UNITS:
        for key in ("ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop"):
            for value in directives(unit).get(key, []):
                assert value.lstrip("-+!@").startswith("/"), f"{unit}: {key} is not an absolute path"


# ------------------------------------------------------------------------------- systemd's own word
def _tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        pytest.skip(f"{name} is not installed")
    return path


def test_systemd_analyze_has_nothing_to_say_about_the_units(tmp_path: Path) -> None:
    analyze = _tool("systemd-analyze")
    root = tmp_path / "root"
    system = root / "etc/systemd/system"
    system.mkdir(parents=True)
    shipped = Path("/usr/lib/systemd/system")
    if not shipped.is_dir():
        pytest.skip("this machine has no systemd unit directory to resolve targets from")
    shutil.copytree(shipped, root / "usr/lib/systemd/system", symlinks=True)
    for unit in UNITS:
        # Installed as the installer installs it: the mode of a unit is not what a checkout happens to carry.
        shutil.copyfile(UNIT_DIR / unit, system / unit)
        (system / unit).chmod(0o644)
        program = root / one(unit, "ExecStart").split()[0].lstrip("/")
        program.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy("/bin/true", program)
    done = subprocess.run(
        [analyze, "verify", f"--root={root}", *(f"/etc/systemd/system/{unit}" for unit in UNITS)],
        capture_output=True,
        text=True,
        check=False,
    )
    said = done.stdout + done.stderr
    assert done.returncode == 0, said
    assert "acf-platform" not in said, said


def test_systemd_sysusers_applies_the_account_table_to_an_empty_root(tmp_path: Path) -> None:
    sysusers_bin = _tool("systemd-sysusers")
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    done = subprocess.run(
        [sysusers_bin, f"--root={root}", str(DEPLOY / "sysusers.d" / "acf-platform.conf")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    passwd = (root / "etc/passwd").read_text(encoding="utf-8")
    group = (root / "etc/group").read_text(encoding="utf-8")
    for account in ("acf-core", "acf-rest", "acf-mcp"):
        assert re.search(rf"^{account}:", passwd, re.MULTILINE)
    members = re.search(r"^acf-command:[^:]*:[0-9]+:(.*)$", group, re.MULTILINE)
    assert members is not None
    assert set(members.group(1).split(",")) == {"acf-core", "acf-rest", "acf-mcp"}
