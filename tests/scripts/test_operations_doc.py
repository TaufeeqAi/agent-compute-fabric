"""docs/OPERATIONS.md — the operator's manual must speak the host agent's own vocabulary.

A manual is read when something is wrong, which is the worst moment to find that the method, the mode or the
metric it names does not exist. Nothing compiles a document, so these tests tie the names it uses to where they
are defined: the generated host API contract (``execution/contracts/host-api.json``), the example files an operator
installs, the host agent's sources for what the contract does not carry (preflight check names, metric names,
command-line roles), and the files this repository ships (units, scripts).

They check that what the manual names exists. They cannot check that what it says about it is true.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DOC = (REPO / "docs/OPERATIONS.md").read_text(encoding="utf-8")
API = json.loads((REPO / "execution/contracts/host-api.json").read_text(encoding="utf-8"))
HOST_SRC = REPO / "execution/host-agent/src"

METHODS = {m["name"] for m in API["methods"]}
OPERATOR_METHODS = {m["name"] for m in API["methods"] if m["class"] == "operator"}
API_NAMESPACES = {name.split(".")[0] for name in METHODS}
FILE_SUFFIXES = {
    "yaml",
    "yml",
    "json",
    "jsonl",
    "conf",
    "crt",
    "key",
    "wal",
    "lock",
    "reserve",
    "sock",
    "service",
    "sh",
}


def rust_sources() -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in sorted(HOST_SRC.rglob("*.rs")))


def backticked() -> list[str]:
    return re.findall(r"`([^`\n]+)`", DOC)


def test_every_api_method_the_manual_names_is_in_the_contract() -> None:
    named = {
        word
        for span in backticked()
        # `host.info` is a method; `host.yaml` and `config/host.example.yaml` are files.
        for word in re.findall(r"(?<![\w/.-])[a-z]+\.[a-z_]+(?![\w.-])", span)
        if word.split(".")[0] in API_NAMESPACES and word.split(".")[1] not in FILE_SUFFIXES
    }
    assert named <= METHODS, f"not methods of the host API: {sorted(named - METHODS)}"
    assert named >= OPERATOR_METHODS, f"an operator method is never mentioned: {sorted(OPERATOR_METHODS - named)}"
    assert {"host.info", "host.metrics", "sandbox.destroy", "operation.get"} <= named


def test_the_host_modes_are_the_contracts_five_and_each_has_a_way_out() -> None:
    modes = API["host_modes"]
    assert modes == ["STARTING", "SERVING", "DRAINING", "CONTAINMENT", "READ_ONLY"]
    for mode in modes:
        assert f"| `{mode}` |" in DOC, f"{mode} is missing from the tables of section 6"
    gauge = re.search(r"`host_mode` \(([^)]+)\)", DOC)
    assert gauge is not None
    assert gauge.group(1) == ", ".join(f"{n} `{mode}`" for n, mode in enumerate(modes)), (
        "the numbers the manual gives for the host_mode gauge"
    )
    query = (HOST_SRC / "coordinator/query.rs").read_text()
    for n, variant in enumerate(("Starting", "Serving", "Draining", "Containment", "ReadOnly")):
        assert f"HostMode::{variant} => {n}," in query


def test_every_containment_reason_is_explained_and_none_is_invented() -> None:
    reasons = [option["properties"]["reason"]["const"] for option in API["$defs"]["ContainmentReason"]["oneOf"]]
    assert sorted(reasons) == [
        "invalid_profile",
        "lifetime_enforcer_unavailable",
        "mandatory_check",
        "store_regression",
    ]
    table = DOC.split("`CONTAINMENT`, by reason", 1)[1].split("\n\n", 2)[1]
    rows = re.findall(r"^\| `([a-z_]+)` \|", table, re.MULTILINE)
    assert sorted(rows) == sorted(reasons)


def test_the_two_release_modes_and_the_acknowledged_condition_are_the_contracts() -> None:
    release = {option["const"] for option in API["$defs"]["ReleaseMode"]["oneOf"]}
    assert release == {"FORCE_DESTROY", "DECLARE_ABSENT"}
    for mode in release:
        assert f"| `{mode}` |" in DOC
    assert API["$defs"]["RequestedMode"]["enum"] == ["DRAINING", "SERVING"]
    assert [option["const"] for option in API["$defs"]["AckCondition"]["oneOf"]] == ["store_regression"]
    assert "`host.acknowledge` with condition `store_regression`" in DOC


@pytest.mark.parametrize(
    "word",
    ["HOST_NOT_SERVING", "SAFETY_CONTROL_DENIED", "RESOURCE_EXHAUSTED", "QUARANTINED", "SECURITY_CONTROL_FAILURE"],
)
def test_the_failure_classes_the_manual_quotes_exist(word: str) -> None:
    assert word in {c["class"] for c in API["failure_classes"]}
    assert f"`{word}`" in DOC


def test_the_states_the_manual_quotes_exist() -> None:
    assert "UNKNOWN" in API["operation_states"]
    assert {"FAILED", "DESTROYED"} <= set(API["lifecycle_states"])
    for word in ("UNKNOWN", "FAILED", "DESTROYED"):
        assert f"`{word}`" in DOC


def test_the_roles_are_the_three_an_enrolment_entry_may_name() -> None:
    enrolment = (REPO / "config/enrolment.example.yaml").read_text()
    for role in ("observer", "caller", "operator"):
        assert f"#   {role} " in enrolment
        assert f"| `{role}` |" in DOC


def test_the_openssl_commands_are_the_ones_the_enrolment_example_gives() -> None:
    enrolment = (REPO / "config/enrolment.example.yaml").read_text()
    commands = re.findall(r"^#\s+(openssl .+)$", enrolment, re.MULTILINE)
    assert len(commands) == 2, "one for the certificate's fingerprint, one for its public key's"
    for command in commands:
        assert command in DOC, f"the manual must show exactly: {command}"
    for matcher in ("certificate_sha256", "spki_sha256", "local_uid", "local_gid"):
        assert matcher in enrolment
        assert matcher in DOC


def test_every_preflight_check_the_manual_names_is_one_doctor_reports() -> None:
    doctor = (HOST_SRC / "doctor.rs").read_text()
    reported = set(re.findall(r'\bc\("([a-z_0-9]+)"', doctor)) | set(
        re.findall(r'check_uid_range\("([a-z_]+)"', doctor)
    )
    reported |= {m.group(1) for m in re.finditer(r'pub const \w+_CHECK: &str = "([a-z_]+)";', doctor)}
    table = DOC.split("## 2. What the machine must provide", 1)[1].split("\n## ", 1)[0]
    named = {
        name
        for row in table.splitlines()
        if row.startswith("| ") and not row.startswith(("| Requirement", "|---"))
        for name in re.findall(r"`([a-z_0-9]+)`", row.rsplit("|", 2)[1])
    }
    assert named, "the last column of the table names the checks"
    assert named <= reported, f"doctor has no check called: {sorted(named - reported)}"
    assert reported <= named, f"a check doctor reports is not in the manual: {sorted(reported - named)}"


def test_every_metric_the_manual_names_is_one_the_host_keeps() -> None:
    sources = rust_sources()
    section = DOC.split("**Metrics that show standing risk**", 1)[1].split("\n## ", 1)[0]
    named = set(re.findall(r"`([a-z]+(?:_[a-z]+)+)`", section)) - {"host_mode"}
    named -= {word for word in named if word.endswith("_ms") and f"recovery.{word}" in section}  # a host.yaml key
    assert len(named) >= 20, "the standing-risk table and the activity counters"
    missing = sorted(name for name in named if f'"{name}"' not in sources)
    assert not missing, f"the host agent keeps no metric called: {missing}"
    assert '"host_mode"' in sources


def test_the_roles_of_the_binary_and_its_operator_commands_exist() -> None:
    main = (HOST_SRC / "main.rs").read_text()
    subcommands = {"serve", "lifetime", "doctor", "edge", "guest-traffic", "journal verify", "journal compact"}
    # As a command: in a code span, or by its installed path. (`--acf-host FILE` is an option of host-setup.sh.)
    named = set(re.findall(r"(?:`|/opt/acf/bin/)acf-host ((?:journal )?[a-z][a-z-]*)", DOC))
    assert named <= subcommands, f"acf-host has no such command: {sorted(named - subcommands)}"
    for variant in ("Serve", "Edge", "GuestTraffic", "Lifetime", "Doctor", "Journal", "Verify", "Compact"):
        assert re.search(rf"^\s+{variant}\b", main, re.MULTILINE), variant
    assert "--keep-terminal 10000" in DOC
    assert "default_value_t = 10_000" in main


def test_the_files_units_and_script_commands_the_manual_names_are_shipped() -> None:
    for unit in ("acf-cgroup.service", "acf-lifetime.service", "acf-host.service"):
        assert unit in DOC
        assert (REPO / "deploy/systemd" / unit).is_file()
    for path in re.findall(r"`((?:scripts|deploy|config|profiles|images|tests|apps|execution)/[^`\s]+)`", DOC):
        target = path.split()[0].rstrip(".,:;")
        assert (REPO / target).exists(), f"the manual names {target}, which does not exist"
    usage = (REPO / "scripts/host-setup.sh").read_text()
    for command in set(re.findall(r"host-setup\.sh ([a-z]+)", DOC)):
        assert f"host-setup.sh {command}" in usage, command
    for option in ("--destdir", "--edge-ids", "--force-config", "--prefix", "--state-root", "--acf-host"):
        assert option in DOC
        assert option in usage


def test_the_paths_are_the_defaults_of_the_shipped_host_config() -> None:
    example = (REPO / "config/host.example.yaml").read_text()
    for key, value in (
        ("state_root", "/var/lib/acf"),
        ("runtime_dir", "/run/acf"),
        ("socket_path", "/run/acf/host-agent.sock"),
        ("profile_path", "/etc/acf/profile.yaml"),
        ("enrolment_path", "/etc/acf/enrolment.yaml"),
        ("secrets_dir", "/etc/acf/secrets"),
    ):
        assert f"  {key}: {value}\n" in example
        assert value in DOC or Path(value).name in DOC, value
    config = (HOST_SRC / "config.rs").read_text()
    assert 'join("state/journal.wal")' in config
    assert 'join("state/host-agent.lock")' in config
    assert "state/journal.wal" in DOC
    assert "state/host-agent.lock" in DOC or "host-agent.lock" in DOC
    assert 'format!("wal.schema{from}")' in (HOST_SRC / "store/migrate.rs").read_text()
    assert "state/journal.wal.schema<N>" in DOC


def test_the_manual_describes_what_it_is_not_which_stage_of_a_plan_it_belongs_to() -> None:
    assert not re.search(r"phase[ -]?\d", DOC, re.IGNORECASE)
    assert "apps/cli/README.md" in DOC, "the client's commands live with the client"
    assert not re.search(r"\bacf-local\b", DOC), "the manual names API methods, not one client's command line"
