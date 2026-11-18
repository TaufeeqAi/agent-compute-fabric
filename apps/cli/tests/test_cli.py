"""The command line, through Typer, against a scripted transport.

Three families of assertion, in this order of importance:

1. **What was sent.** Every command sends the method it stands for, with the parameters its flags
   describe; a mutation carries an id and a generation, never a name; a bad argument is rejected
   before anything is sent. (Every request is also validated against the published description.)
2. **What the exit code says.** Scripts branch on it: success, refusal, a failed operation, an
   unknown outcome, an outcome that is not established yet, an unreachable host, a usage error.
3. **What goes where.** Data on stdout; refusals, hints and reports for people on stderr; with
   ``--json`` exactly one document on stdout — the host's answer in wire form.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import factories as f
from acf_cli import __version__
from acf_cli.errors import HostUnreachable, ResponseLost
from acf_cli.main import app
from acf_cli.transport import TlsEndpoint, UnixEndpoint
from conftest import Invocation
from support import Contract, FakeClock, answered, op, refused

Invoke = Callable[..., Invocation]
SBX = f.SANDBOX_ID
SNP = f.SNAPSHOT_ID
RUN = f.RUN_ID
OP = f.OPERATION_ID
CURSOR = f"{f.LINEAGE}:41"


def json_out(inv: Invocation) -> Any:
    return json.loads(inv.stdout)


def inspected(**over: Any) -> dict[str, Any]:
    """The answer to the ``sandbox.inspect`` a command makes to turn a name into an id and a generation."""
    return answered("sandbox", f.sandbox_view(**over))


def params(inv: Invocation, index: int = -1) -> dict[str, Any]:
    sent: dict[str, Any] = inv.connection.requests[index]["params"]
    return sent


# ----------------------------------------------------------------------------- the root command
def test_version() -> None:
    result = CliRunner().invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == f"acf-local {__version__}"


def test_no_arguments_prints_usage_and_is_a_usage_error() -> None:
    result = CliRunner().invoke(app, [])
    assert "Usage:" in result.output
    assert result.exit_code == 2


def test_help_lists_every_command_group() -> None:
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    for group in ("sandbox", "snapshot", "operation", "run", "host", "profile", "quarantine"):
        assert group in result.stdout


@pytest.mark.parametrize(
    ("group", "commands"),
    [
        ("sandbox", ["create", "start", "exec", "stop", "destroy", "inspect", "list"]),
        ("snapshot", ["create", "restore", "delete", "list"]),
        ("operation", ["get", "list", "cancel"]),
        ("run", ["once", "inspect", "output"]),
        ("host", ["info", "metrics", "set-mode", "acknowledge"]),
        ("profile", ["reload"]),
        ("quarantine", ["release"]),
    ],
)
def test_every_group_lists_its_commands(group: str, commands: list[str]) -> None:
    result = CliRunner().invoke(app, [group, "--help"])
    assert result.exit_code == 0
    for command in commands:
        assert command in result.stdout


def test_the_default_endpoint_is_the_local_socket_and_the_default_scope(invoke: Invoke) -> None:
    inv = invoke(["host", "metrics"], answered("metrics", {}))
    assert inv.config is not None
    assert inv.config.endpoint == UnixEndpoint(Path("/run/acf/host-agent.sock"))
    assert inv.connection.requests[0]["owner_scope"] == "default"
    assert "on_behalf_of" not in inv.connection.requests[0]


def test_socket_scope_and_on_behalf_of_come_from_options_or_the_environment(invoke: Invoke) -> None:
    flags = invoke(
        ["--socket", "/tmp/x.sock", "--scope", "team-a/prod", "--on-behalf-of", "job:42", "host", "metrics"],
        answered("metrics", {}),
    )
    assert flags.config is not None
    assert flags.config.endpoint == UnixEndpoint(Path("/tmp/x.sock"))
    assert flags.connection.requests[0]["owner_scope"] == "team-a/prod"
    assert flags.connection.requests[0]["on_behalf_of"] == "job:42"
    env = invoke(
        ["host", "metrics"],
        answered("metrics", {}),
        env={"ACF_SOCKET": "/tmp/y.sock", "ACF_SCOPE": "team-b", "ACF_ON_BEHALF_OF": "user:7"},
    )
    assert env.config is not None
    assert env.config.endpoint == UnixEndpoint(Path("/tmp/y.sock"))
    assert env.connection.requests[0]["owner_scope"] == "team-b"
    assert env.connection.requests[0]["on_behalf_of"] == "user:7"


@pytest.mark.parametrize("scope", ["has space", "semi;colon", "x" * 129, ""])
def test_a_scope_outside_the_label_grammar_is_a_usage_error(invoke: Invoke, scope: str) -> None:
    inv = invoke(["--scope", scope, "host", "info"])
    assert inv.exit_code == 2
    assert inv.connection.requests == []


def test_tls_options_select_the_mutual_tls_endpoint(invoke: Invoke) -> None:
    inv = invoke(
        ["--tls", "host-1.example:7443", "--cert", "c.crt", "--key", "c.key", "--ca", "ca.crt",
         "--server-name", "host-1", "host", "metrics"],
        answered("metrics", {}),
    )  # fmt: skip
    assert inv.exit_code == 0
    assert inv.config is not None
    assert inv.config.endpoint == TlsEndpoint(
        host="host-1.example",
        port=7443,
        certificate=Path("c.crt"),
        private_key=Path("c.key"),
        trust_anchors=Path("ca.crt"),
        server_name="host-1",
    )


def test_tls_options_can_come_from_the_environment_and_the_ca_is_optional(invoke: Invoke) -> None:
    env = {"ACF_TLS": "[2001:db8::1]:7443", "ACF_TLS_CERT": "/etc/acf/c.crt", "ACF_TLS_KEY": "/etc/acf/c.key"}
    inv = invoke(["host", "metrics"], answered("metrics", {}), env=env)
    assert inv.config is not None
    endpoint = inv.config.endpoint
    assert isinstance(endpoint, TlsEndpoint)
    assert (endpoint.host, endpoint.port) == ("2001:db8::1", 7443)
    assert endpoint.trust_anchors is None, "no --ca: the system trust store"
    assert endpoint.server_name is None


@pytest.mark.parametrize(
    ("args", "complaint"),
    [
        (["--tls", "host:7443"], "--cert and --key"),  # no client certificate: there is no one-way TLS
        (["--tls", "host:7443", "--cert", "c.crt"], "--cert and --key"),
        (["--tls", "host", "--cert", "c.crt", "--key", "c.key"], "HOST:PORT"),
        (["--tls", "host:0", "--cert", "c.crt", "--key", "c.key"], "HOST:PORT"),
        (["--tls", "host:port", "--cert", "c.crt", "--key", "c.key"], "HOST:PORT"),
        (["--cert", "c.crt"], "only applies together with --tls"),
        (["--ca", "ca.crt"], "only applies together with --tls"),
        (["--server-name", "h"], "only applies together with --tls"),
        (
            ["--socket", "/tmp/x.sock", "--tls", "host:7443", "--cert", "c.crt", "--key", "c.key"],
            "two different endpoints",
        ),
    ],
)
def test_inconsistent_endpoint_options_are_usage_errors(invoke: Invoke, args: list[str], complaint: str) -> None:
    inv = invoke([*args, "host", "info"])
    assert inv.exit_code == 2
    assert complaint in inv.result.output
    assert inv.connection.requests == []


def test_an_environment_socket_does_not_conflict_with_tls_on_the_command_line(invoke: Invoke) -> None:
    inv = invoke(
        ["--tls", "host:7443", "--cert", "c.crt", "--key", "c.key", "host", "metrics"],
        answered("metrics", {}),
        env={"ACF_SOCKET": "/run/acf/host-agent.sock"},
    )
    assert inv.exit_code == 0
    assert inv.config is not None
    assert isinstance(inv.config.endpoint, TlsEndpoint)


TLS_ENVIRONMENT = {
    "ACF_TLS": "host-1.example:7443",
    "ACF_TLS_CERT": "/etc/acf/c.crt",
    "ACF_TLS_KEY": "/etc/acf/c.key",
    "ACF_TLS_CA": "/etc/acf/ca.crt",
    "ACF_TLS_SERVER_NAME": "host-1",
}


def test_a_socket_on_the_command_line_wins_over_a_tls_endpoint_in_the_environment(invoke: Invoke) -> None:
    """What is typed is a statement; the environment is a default, and here it does not apply."""
    inv = invoke(["--socket", "/tmp/x.sock", "host", "metrics"], answered("metrics", {}), env=TLS_ENVIRONMENT)
    assert inv.exit_code == 0
    assert inv.config is not None
    assert inv.config.endpoint == UnixEndpoint(Path("/tmp/x.sock"))


def test_tls_files_in_the_environment_are_ignored_when_no_tls_endpoint_is_named(invoke: Invoke) -> None:
    files_only = {name: value for name, value in TLS_ENVIRONMENT.items() if name != "ACF_TLS"}
    inv = invoke(["host", "metrics"], answered("metrics", {}), env=files_only)
    assert inv.exit_code == 0
    assert inv.config is not None
    assert inv.config.endpoint == UnixEndpoint(Path("/run/acf/host-agent.sock"))


def test_between_two_endpoints_in_the_environment_the_tls_one_is_used(invoke: Invoke) -> None:
    inv = invoke(["host", "metrics"], answered("metrics", {}), env=TLS_ENVIRONMENT | {"ACF_SOCKET": "/tmp/y.sock"})
    assert inv.exit_code == 0
    assert inv.config is not None
    assert inv.config.endpoint == TlsEndpoint(
        host="host-1.example",
        port=7443,
        certificate=Path("/etc/acf/c.crt"),
        private_key=Path("/etc/acf/c.key"),
        trust_anchors=Path("/etc/acf/ca.crt"),
        server_name="host-1",
    )


def test_a_tls_file_typed_next_to_a_typed_socket_is_a_usage_error_whatever_the_environment(invoke: Invoke) -> None:
    inv = invoke(["--socket", "/tmp/x.sock", "--cert", "c.crt", "host", "info"], env=TLS_ENVIRONMENT)
    assert inv.exit_code == 2
    assert "only applies together with --tls" in inv.result.output
    assert inv.connection.requests == []


# ----------------------------------------------------------------------------- failures that are not answers
def test_an_unreachable_host_exits_6_with_a_hint_and_empty_stdout(invoke: Invoke) -> None:
    inv = invoke(
        ["host", "info"], HostUnreachable("no host agent socket at /run/acf/host-agent.sock", hint="is it running?")
    )
    assert inv.exit_code == 6
    assert "error: no host agent socket" in inv.stderr
    assert "hint: is it running?" in inv.stderr
    assert inv.stdout == ""


def test_with_json_a_client_side_failure_is_an_error_document(invoke: Invoke) -> None:
    inv = invoke(["host", "info", "--json"], HostUnreachable("nothing is listening", hint="start it"))
    assert inv.exit_code == 6
    assert json_out(inv) == {
        "error": {
            "kind": "HostUnreachable",
            "message": "nothing is listening",
            "hint": "start it",
            "operation_id": None,
            "exit_code": 6,
        }
    }
    assert "error: nothing is listening" in inv.stderr, "people still get the message"


def test_a_malformed_answer_exits_7(invoke: Invoke) -> None:
    inv = invoke(["host", "info"], b"<html>not the host agent</html>")
    assert inv.exit_code == 7
    assert "not a valid acf.host/2 response" in inv.stderr
    assert "<html>" not in inv.stderr


def test_an_answer_of_another_kind_than_asked_for_exits_7(invoke: Invoke) -> None:
    inv = invoke(["host", "info"], answered("metrics", {}))
    assert inv.exit_code == 7
    assert "expected a `HostInfoBody` result" in inv.stderr


# ----------------------------------------------------------------------------- host info / metrics
def test_host_info_human_and_json(invoke: Invoke, contract: Contract) -> None:
    human = invoke(["host", "info"], answered("host_info", f.host_info()))
    assert human.exit_code == 0
    assert human.connection.methods == ["host.info"]
    assert "params" not in human.connection.requests[0]
    assert "acf.host/2" in human.stdout
    assert "firecracker v1.17.0" in human.stdout
    assert f"as of: {CURSOR}" in human.stderr
    as_json = invoke(["host", "info", "--json"], answered("host_info", f.host_info(live_sandboxes=3)))
    document = json_out(as_json)
    contract.check_response(document)
    assert document["answer"] == "RESULT"
    assert document["result"]["data"]["live_sandboxes"] == 3
    assert document["as_of"] == f.AS_OF
    assert "request_id" not in document


def test_host_metrics(invoke: Invoke) -> None:
    inv = invoke(["host", "metrics"], answered("metrics", f.metrics()))
    assert inv.exit_code == 0
    assert inv.connection.methods == ["host.metrics"]
    assert "gauges.live_sandboxes" in inv.stdout
    as_json = invoke(["host", "metrics", "--json"], answered("metrics", f.metrics()))
    assert json_out(as_json)["result"]["data"]["gauges"]["host_mode"] == 1


def test_a_refused_read_exits_3_and_says_why(invoke: Invoke, contract: Contract) -> None:
    denied = refused("AUTHORIZATION_DENIED", "role `observer` may not call `sandbox.list`")
    human = invoke(["sandbox", "list"], denied)
    assert human.exit_code == 3
    assert "refused: AUTHORIZATION_DENIED - role `observer` may not call `sandbox.list`" in human.stderr
    assert "retry: NEVER" in human.stderr
    assert human.stdout == ""
    as_json = invoke(["sandbox", "list", "--json"], denied)
    assert as_json.exit_code == 3
    document = json_out(as_json)
    contract.check_response(document)
    assert document["refusal"] == {
        "class": "AUTHORIZATION_DENIED",
        "retry": "NEVER",
        "message": denied["refusal"]["message"],
    }


# ----------------------------------------------------------------------------- sandbox create
def test_sandbox_create_sends_what_its_flags_describe(invoke: Invoke) -> None:
    inv = invoke(
        ["sandbox", "create", "--image", "python", "--cpu", "2", "--memory", "4Gi", "--disk", "2048",
         "--name", "job-7", "--lifetime", "2h"],
        op("SUCCEEDED", f.sandbox_body(state="PROVISIONING")),
    )  # fmt: skip
    assert inv.exit_code == 0
    assert inv.connection.methods == ["sandbox.create"]
    assert params(inv) == {
        "name": "job-7",
        "image": "python",
        "resources": {"vcpus": 2, "memory_mib": 4096, "disk_mib": 2048, "network": {"mode": "none"}},
        "lifetime_secs": 7200,
    }
    request = inv.connection.requests[0]
    assert request["operation_id"].startswith("op-")
    assert request["issued_at"].endswith("Z")
    assert request["wait_ms"] == 20_000
    assert "authority" not in request
    assert SBX in inv.stdout
    assert "PROVISIONING" in inv.stdout


def test_sandbox_create_defaults(invoke: Invoke) -> None:
    inv = invoke(["sandbox", "create", "--image", "python"], op("SUCCEEDED", f.sandbox_body()))
    assert params(inv) == {
        "image": "python",
        "resources": {"vcpus": 1, "memory_mib": 512, "disk_mib": 1024, "network": {"mode": "none"}},
    }, "no name and no lifetime are sent when none is asked for: the profile's defaults apply"


def test_sandbox_create_with_an_allowlist(invoke: Invoke) -> None:
    inv = invoke(
        ["sandbox", "create", "--image", "python", "--network", "allowlist",
         "--allow", "pypi.org:443", "--allow", "198.51.100.0/24:5432-5433,8443"],
        op("SUCCEEDED", f.sandbox_body()),
    )  # fmt: skip
    assert params(inv)["resources"]["network"] == {
        "mode": "allowlist",
        "entries": [
            {"destination": {"name": "pypi.org"}, "ports": [{"from": 443, "to": 443}]},
            {
                "destination": {"network": "198.51.100.0/24"},
                "ports": [{"from": 5432, "to": 5433}, {"from": 8443, "to": 8443}],
            },
        ],
    }


@pytest.mark.parametrize(
    "args",
    [
        ["--network", "allowlist"],  # an allowlist with nothing on it is `none`, and must be said as `none`
        ["--allow", "pypi.org:443"],  # connectivity is never implied by an entry alone
        ["--network", "none", "--allow", "pypi.org:443"],
        ["--network", "open"],  # not a network mode
        ["--network", "allowlist", "--allow", "pypi.org"],
        ["--memory", "lots"],
        ["--lifetime", "1500ms"],
        ["--name", ".hidden"],
        ["--cpu", "0"],
        ["--operation-id", "short"],
        ["--timeout", "soon"],
    ],
)
def test_sandbox_create_rejects_bad_arguments_before_sending_anything(invoke: Invoke, args: list[str]) -> None:
    inv = invoke(["sandbox", "create", "--image", "python", *args])
    assert inv.exit_code == 2
    assert inv.connection.requests == []


def test_the_operation_shown_after_a_command_states_effect_and_as_of(invoke: Invoke) -> None:
    inv = invoke(["sandbox", "create", "--image", "python"], op("SUCCEEDED", f.sandbox_body()))
    assert "SUCCEEDED" in inv.stdout
    assert "APPLIED - the operation's effect is in place" in inv.stdout
    assert f"as of      {CURSOR}" in inv.stdout
    assert inv.connection.requests[0]["operation_id"] in inv.stdout, "the operation id is always shown"


def test_json_output_of_an_operation_is_the_operation_answer(invoke: Invoke, contract: Contract) -> None:
    inv = invoke(["sandbox", "create", "--image", "python", "--json"], op("SUCCEEDED", f.sandbox_body()))
    assert inv.exit_code == 0
    document = json_out(inv)
    contract.check_response(document)
    assert document["answer"] == "OPERATION"
    assert document["operation"]["operation_id"] == inv.connection.requests[0]["operation_id"]
    assert document["operation"]["effect"] == "APPLIED"
    assert document["operation"]["result"]["data"]["sandbox_id"] == SBX
    assert inv.stderr == ""


def test_an_explicit_operation_id_is_the_one_that_is_sent(invoke: Invoke) -> None:
    inv = invoke(
        ["sandbox", "create", "--image", "python", "--operation-id", "nightly-2026-11-18"],
        op("SUCCEEDED", f.sandbox_body()),
    )
    assert inv.connection.requests[0]["operation_id"] == "nightly-2026-11-18"


# ----------------------------------------------------------------------------- the outcomes of an operation
def test_a_refused_operation_exits_3_with_class_and_retry_advice(invoke: Invoke, contract: Contract) -> None:
    full = refused("RESOURCE_EXHAUSTED", "no capacity for 4096 MiB", "SAME_REQUEST_LATER")
    human = invoke(["sandbox", "create", "--image", "python"], full)
    assert human.exit_code == 3
    assert "refused: RESOURCE_EXHAUSTED - no capacity for 4096 MiB" in human.stderr
    assert "retry: SAME_REQUEST_LATER" in human.stderr
    assert "nothing was applied" in human.stderr
    assert human.stdout == ""
    as_json = invoke(["sandbox", "create", "--image", "python", "--json"], full)
    assert as_json.exit_code == 3
    document = json_out(as_json)
    contract.check_response(document)
    assert (document["answer"], document["refusal"]["retry"]) == ("REFUSED", "SAME_REQUEST_LATER")


def test_a_failed_operation_exits_4_and_shows_effect_and_cleanup(invoke: Invoke, contract: Contract) -> None:
    failed = op("FAILED", failure=f.failure("TIMEOUT", "deadline passed"), cleanup="PENDING", effect="MAY_BE_APPLIED")
    human = invoke(["sandbox", "start", SBX, "--expected-generation", "1"], failed)
    assert human.exit_code == 4
    assert "FAILED" in human.stderr
    assert "MAY_BE_APPLIED" in human.stderr
    assert "PENDING - something the operation created remains" in human.stderr
    assert "TIMEOUT: deadline passed" in human.stderr
    assert human.stdout == ""
    as_json = invoke(["sandbox", "start", SBX, "--expected-generation", "1", "--json"], failed)
    assert as_json.exit_code == 4
    document = json_out(as_json)
    contract.check_response(document)
    assert (document["operation"]["state"], document["operation"]["cleanup"]) == ("FAILED", "PENDING")


def test_a_cancelled_operation_exits_4(invoke: Invoke) -> None:
    inv = invoke(["sandbox", "start", SBX, "--expected-generation", "1"], op("CANCELLED", cancelled_by="SUPERSEDED"))
    assert inv.exit_code == 4
    assert "SUPERSEDED" in inv.stderr


def test_an_unknown_outcome_exits_5_and_is_called_neither_success_nor_failure(
    invoke: Invoke, contract: Contract
) -> None:
    unknown = op(
        "UNKNOWN", failure=f.failure("UNKNOWN_OUTCOME", "no result could be obtained"), operation_type="exec.run"
    )
    human = invoke(["sandbox", "exec", SBX, "--expected-generation", "1", "--", "true"], unknown)
    assert human.exit_code == 5
    assert "UNKNOWN" in human.stderr
    assert "MAY_BE_APPLIED" in human.stderr
    assert "neither as success nor as failure" in human.stderr
    assert "SUCCEEDED" not in human.stderr
    assert len(human.connection.requests) == 1, "nothing is retried and nothing is polled"
    as_json = invoke(["sandbox", "exec", SBX, "--expected-generation", "1", "--json", "--", "true"], unknown)
    assert as_json.exit_code == 5
    document = json_out(as_json)
    contract.check_response(document)
    assert (document["operation"]["state"], document["operation"]["effect"]) == ("UNKNOWN", "MAY_BE_APPLIED")


def test_a_state_this_client_does_not_know_is_shown_as_unknown_and_is_not_success(invoke: Invoke) -> None:
    inv = invoke(
        ["sandbox", "start", SBX, "--expected-generation", "1"],
        op("ABANDONED", effect="NOT_APPLIED", cleanup="COMPLETE"),
    )
    assert inv.exit_code == 5
    assert "ABANDONED (not recognized by this client)" in inv.stderr


def test_a_non_terminal_operation_is_followed(invoke: Invoke, clock: FakeClock) -> None:
    inv = invoke(
        ["sandbox", "start", SBX, "--expected-generation", "1"],
        op("ACCEPTED", step=None),
        op("IN_PROGRESS"),
        op("SUCCEEDED", f.sandbox_body()),
    )
    assert inv.exit_code == 0
    assert inv.connection.methods == ["sandbox.start", "operation.get", "operation.get"]
    assert clock.sleeps == [0.1, 0.2]


def test_no_wait_returns_what_the_host_recorded_and_exits_8_if_it_has_not_ended(
    invoke: Invoke, contract: Contract
) -> None:
    inv = invoke(["sandbox", "start", SBX, "--expected-generation", "1", "--no-wait"], op("ACCEPTED", step=None))
    assert inv.exit_code == 8
    assert inv.connection.methods == ["sandbox.start"]
    assert inv.connection.requests[0]["wait_ms"] == 0
    assert "has not ended: it is ACCEPTED" in inv.stderr
    assert f"acf-local operation get {inv.connection.requests[0]['operation_id']} --wait" in inv.stderr
    as_json = invoke(["sandbox", "start", SBX, "--expected-generation", "1", "--no-wait", "--json"], op("IN_PROGRESS"))
    assert as_json.exit_code == 8
    document = json_out(as_json)
    contract.check_response(document)
    assert document["operation"]["state"] == "IN_PROGRESS"


def test_no_wait_exits_0_when_the_operation_had_already_ended(invoke: Invoke) -> None:
    inv = invoke(["sandbox", "stop", SBX, "--expected-generation", "1", "--no-wait"], op("SUCCEEDED", f.sandbox_body()))
    assert inv.exit_code == 0


def test_timeout_bounds_how_long_an_operation_is_followed(invoke: Invoke, clock: FakeClock) -> None:
    inv = invoke(
        ["sandbox", "start", SBX, "--expected-generation", "1", "--timeout", "3s"],
        op("IN_PROGRESS"),
        default=op("IN_PROGRESS"),
    )
    assert inv.exit_code == 8
    assert sum(clock.sleeps) == pytest.approx(3.0)
    assert inv.connection.requests[0]["wait_ms"] == 3_000
    assert "has not ended" in inv.stderr


def test_the_timeout_can_come_from_the_environment(invoke: Invoke) -> None:
    inv = invoke(
        ["sandbox", "start", SBX, "--expected-generation", "1"],
        op("SUCCEEDED", f.sandbox_body()),
        env={"ACF_TIMEOUT": "5s"},
    )
    assert inv.connection.requests[0]["wait_ms"] == 5_000


def test_a_lost_response_is_resolved_with_the_same_operation_id(invoke: Invoke) -> None:
    inv = invoke(
        ["sandbox", "start", SBX, "--expected-generation", "1"],
        ResponseLost("the host closed the connection without answering"),
        op("SUCCEEDED", f.sandbox_body()),
    )
    assert inv.exit_code == 0
    first, again = inv.connection.requests
    assert (again["operation_id"], again["issued_at"]) == (first["operation_id"], first["issued_at"])
    assert again["retry"] is True


def test_contact_lost_for_good_exits_8_and_names_the_operation(invoke: Invoke) -> None:
    inv = invoke(
        ["sandbox", "start", SBX, "--expected-generation", "1", "--json"],
        ResponseLost("the host closed the connection without answering"),
        default=HostUnreachable("nothing is listening"),
    )
    assert inv.exit_code == 8
    error = json_out(inv)["error"]
    assert error["kind"] == "OutcomeUnresolved"
    assert error["operation_id"] == inv.connection.requests[0]["operation_id"]
    assert "new id" in error["hint"]
    assert f"operation: {error['operation_id']}" in inv.stderr


# ----------------------------------------------------------------------------- sandbox start / stop / destroy
@pytest.mark.parametrize(("command", "method"), [("start", "sandbox.start"), ("stop", "sandbox.stop")])
def test_a_name_is_resolved_by_a_read_and_the_mutation_carries_id_and_generation(
    invoke: Invoke, command: str, method: str
) -> None:
    inv = invoke(["sandbox", command, "box"], inspected(generation=3), op("SUCCEEDED", f.sandbox_body(generation=3)))
    assert inv.exit_code == 0
    assert inv.connection.methods == ["sandbox.inspect", method]
    assert params(inv, 0) == {"sandbox": "box"}
    assert params(inv) == {"sandbox_id": SBX, "expected_generation": 3}, "never a name"


def test_an_id_with_its_generation_needs_no_read(invoke: Invoke) -> None:
    inv = invoke(
        ["sandbox", "stop", SBX, "--expected-generation", "4", "--if-revision", "17"], op("SUCCEEDED", f.sandbox_body())
    )
    assert inv.connection.methods == ["sandbox.stop"]
    assert params(inv) == {"sandbox_id": SBX, "expected_generation": 4, "if_revision": 17}


def test_an_explicit_generation_overrides_the_one_that_was_read(invoke: Invoke) -> None:
    inv = invoke(
        ["sandbox", "start", "box", "--expected-generation", "2"],
        inspected(generation=5),
        refused("REVISION_CONFLICT", "sandbox is at generation 5, not 2 (stale token)", "AFTER_CHANGE"),
    )
    assert params(inv)["expected_generation"] == 2
    assert inv.exit_code == 3
    assert "REVISION_CONFLICT" in inv.stderr


def test_a_name_that_does_not_resolve_is_the_hosts_refusal(invoke: Invoke) -> None:
    inv = invoke(["sandbox", "start", "ghost"], refused("NOT_FOUND", "no such sandbox"))
    assert inv.exit_code == 3
    assert inv.connection.methods == ["sandbox.inspect"], "nothing was mutated"
    assert "refused: NOT_FOUND - no such sandbox" in inv.stderr


def test_destroy_refuses_without_confirmation_when_nobody_can_be_asked(invoke: Invoke) -> None:
    inv = invoke(["sandbox", "destroy", "box"], inspected())
    assert inv.exit_code == 2
    assert inv.connection.methods == ["sandbox.inspect"], "it looked, and destroyed nothing"
    assert "--yes" in inv.stderr


def test_destroy_with_yes(invoke: Invoke) -> None:
    inv = invoke(
        ["sandbox", "destroy", "box", "--yes"],
        inspected(generation=2),
        op("SUCCEEDED", f.sandbox_body(state="DESTROYED")),
    )
    assert inv.exit_code == 0
    assert inv.connection.methods == ["sandbox.inspect", "sandbox.destroy"]
    assert params(inv) == {"sandbox_id": SBX, "expected_generation": 2}
    assert "DESTROYED" in inv.stdout


def test_destroy_by_id_and_generation_with_yes_makes_no_read(invoke: Invoke) -> None:
    inv = invoke(
        ["sandbox", "destroy", SBX, "--expected-generation", "2", "--yes"],
        op("SUCCEEDED", f.sandbox_body(state="DESTROYED")),
    )
    assert inv.connection.methods == ["sandbox.destroy"]


@pytest.mark.parametrize(("answer", "destroyed"), [("y\n", True), ("n\n", False), ("\n", False)])
def test_destroy_asks_a_human_and_takes_no_for_an_answer(
    invoke: Invoke, monkeypatch: pytest.MonkeyPatch, answer: str, destroyed: bool
) -> None:
    monkeypatch.setattr("acf_cli.common.interactive", lambda: True)
    script = [inspected(), op("SUCCEEDED", f.sandbox_body(state="DESTROYED"))] if destroyed else [inspected()]
    inv = invoke(["sandbox", "destroy", "box"], *script, stdin=answer)
    assert f"destroy sandbox {SBX} (box, generation 1)?" in inv.stderr
    assert ("sandbox.destroy" in inv.connection.methods) is destroyed
    assert inv.exit_code == (0 if destroyed else 1)


# ----------------------------------------------------------------------------- sandbox exec
def test_exec_sends_the_argument_vector_and_relays_the_guests_streams(invoke: Invoke) -> None:
    result = f.run_body(stdout=b"out \xff\x00 bytes\n", stderr=b"warned\n")
    inv = invoke(
        ["sandbox", "exec", "box", "--", "python", "train.py", "--epochs", "3"],
        inspected(state="READY"),
        op("SUCCEEDED", result, operation_type="exec.run", run_id=RUN),
    )
    assert inv.exit_code == 0
    assert inv.connection.methods == ["sandbox.inspect", "exec.run"]
    assert params(inv) == {
        "sandbox_id": SBX,
        "expected_generation": 1,
        "command": {"argv": ["python", "train.py", "--epochs", "3"], "env": {}, "secret_env": {}, "limits": {}},
    }
    assert inv.result.stdout_bytes == b"out \xff\x00 bytes\n", "the guest's stdout, byte for byte, and nothing else"
    assert "warned" in inv.stderr
    assert RUN in inv.stderr, "the report is for people: stderr"
    assert "EXITED (exit 0)" in inv.stderr
    assert "APPLIED" in inv.stderr


def test_exec_with_every_flag(invoke: Invoke) -> None:
    inv = invoke(
        ["sandbox", "exec", SBX, "--expected-generation", "2", "--if-revision", "9",
         "--command", "python -c 'print(1)'", "-e", "LANG=C.UTF-8", "--env", "TZ=UTC",
         "--secret-env", "API_TOKEN=ci-token", "--cwd", "/workspace/job",
         "--time-limit", "90s", "--max-pids", "64", "--max-stdout", "64KiB", "--max-stderr", "4096"],
        op("SUCCEEDED", f.run_body(), operation_type="exec.run"),
    )  # fmt: skip
    assert inv.exit_code == 0
    assert params(inv) == {
        "sandbox_id": SBX,
        "expected_generation": 2,
        "if_revision": 9,
        "command": {
            "argv": ["python", "-c", "print(1)"],
            "env": {"LANG": "C.UTF-8", "TZ": "UTC"},
            "secret_env": {"API_TOKEN": {"ref": "ci-token"}},
            "cwd": "/workspace/job",
            "limits": {"timeout_ms": 90_000, "max_pids": 64, "max_stdout_bytes": 65_536, "max_stderr_bytes": 4_096},
        },
    }


def test_shell_wraps_the_command_in_a_guest_shell(invoke: Invoke) -> None:
    inv = invoke(
        ["sandbox", "exec", SBX, "--expected-generation", "1", "--shell", "-c", "ls | wc -l && echo done"],
        op("SUCCEEDED", f.run_body(), operation_type="exec.run"),
    )
    assert params(inv)["command"]["argv"] == ["/bin/sh", "-c", "ls | wc -l && echo done"]


@pytest.mark.parametrize(
    "args",
    [
        [],  # nothing to run
        ["--command", "a", "--", "b"],  # both forms
        ["--shell", "--", "ls"],  # --shell needs --command
        ["--command", "unbalanced 'quote"],
        ["--command", ""],
        ["-e", "NOEQUALS", "--", "true"],
        ["-e", "A=1", "-e", "A=2", "--", "true"],
        ["-e", "TOKEN=x", "--secret-env", "TOKEN=ci-token", "--", "true"],  # a value and a reference at once
        ["--time-limit", "never", "--", "true"],
        ["--max-stdout", "big", "--", "true"],
    ],
)
def test_exec_rejects_bad_commands_before_sending_anything(invoke: Invoke, args: list[str]) -> None:
    inv = invoke(["sandbox", "exec", SBX, "--expected-generation", "1", *args])
    assert inv.exit_code == 2
    assert inv.connection.requests == []


def test_raw_secret_material_is_never_accepted_as_a_secret_and_never_echoed(invoke: Invoke) -> None:
    material = "s3cr3t/with+punctuation=="
    inv = invoke(
        ["sandbox", "exec", SBX, "--expected-generation", "1", "--secret-env", f"API_TOKEN={material}", "--", "true"]
    )
    assert inv.exit_code == 2
    assert inv.connection.requests == [], "it never left this process"
    assert material not in inv.result.output
    assert "not a secret reference" in inv.stderr
    assert "Never pass the secret itself" in inv.stderr


def test_a_command_that_fails_is_exit_1_because_the_operation_succeeded(invoke: Invoke) -> None:
    inv = invoke(
        ["sandbox", "exec", SBX, "--expected-generation", "1", "--", "false"],
        op("SUCCEEDED", f.run_body(exit_code=3, stdout=b"", stderr=b"boom\n"), operation_type="exec.run"),
    )
    assert inv.exit_code == 1
    assert "boom" in inv.stderr
    assert "EXITED (exit 3)" in inv.stderr
    assert "SUCCEEDED" in inv.stderr, "the host did its job: the operation succeeded"


@pytest.mark.parametrize(
    ("over", "plain", "propagated"),
    [
        ({"exit_code": 0}, 0, 0),
        ({"exit_code": 3}, 1, 3),
        ({"exit_code": 255}, 1, 255),
        ({"status": "SIGNALED", "exit_code": None, "signal": 9}, 1, 137),
        ({"status": "TIMED_OUT", "exit_code": None}, 1, 1),
        ({"status": "OOM_KILLED", "exit_code": 0}, 1, 1),  # a status this client does not know is not a clean exit
    ],
)
def test_the_workloads_exit_status(invoke: Invoke, over: dict[str, Any], plain: int, propagated: int) -> None:
    answer = op("SUCCEEDED", f.run_body(**over), operation_type="exec.run")
    assert invoke(["sandbox", "exec", SBX, "--expected-generation", "1", "--", "x"], answer).exit_code == plain
    with_flag = invoke(
        ["sandbox", "exec", SBX, "--expected-generation", "1", "--propagate-exit-code", "--", "x"], answer
    )
    assert with_flag.exit_code == propagated


def test_a_failed_execution_still_relays_the_output_the_host_captured(invoke: Invoke) -> None:
    backstop = op(
        "FAILED",
        f.run_body(
            status="TIMED_OUT", exit_code=None, stdout=b"partial\n", host_backstop_fired=True, runtime_ended=True
        ),
        operation_type="exec.run",
        failure=f.failure("TIMEOUT", "the host deadline backstop ended the runtime"),
        effect="MAY_BE_APPLIED",
        cleanup="PENDING",
    )
    inv = invoke(["sandbox", "exec", SBX, "--expected-generation", "1", "--", "sleep", "999"], backstop)
    assert inv.exit_code == 4
    assert inv.result.stdout_bytes == b"partial\n"
    assert "host backstop" in inv.stderr
    assert "TIMEOUT" in inv.stderr


def test_exec_json_is_one_document_with_the_output_inside(invoke: Invoke, contract: Contract) -> None:
    inv = invoke(
        ["sandbox", "exec", SBX, "--expected-generation", "1", "--json", "--", "echo", "hi"],
        op("SUCCEEDED", f.run_body(stdout=b"hi\n", exit_code=2), operation_type="exec.run", run_id=RUN),
    )
    assert inv.exit_code == 1, "the exit code still states the workload's result"
    document = json_out(inv)
    contract.check_response(document)
    run = document["operation"]["result"]["data"]
    assert base64.b64decode(run["stdout"]["data_b64"]) == b"hi\n"
    assert run["exit_code"] == 2
    assert inv.stderr == "", "nothing but the document"


def test_ctrl_c_during_exec_cancels_the_execution_and_reports_how_it_ended(invoke: Invoke) -> None:
    cancelled = f.run_body(status="CANCELLED", exit_code=None, stdout=b"so far\n")
    inv = invoke(
        ["sandbox", "exec", SBX, "--expected-generation", "1", "--", "sleep", "999"],
        KeyboardInterrupt(),
        op("SUCCEEDED", f.host_change_body(note="the execution ended Cancelled"), operation_type="operation.cancel"),
        op("CANCELLED", cancelled, operation_type="exec.run", effect="MAY_BE_APPLIED"),
    )
    assert inv.exit_code == 130
    assert inv.connection.methods == ["exec.run", "operation.cancel", "operation.get"]
    exec_id = inv.connection.requests[0]["operation_id"]
    cancel = inv.connection.requests[1]
    assert cancel["params"] == {"operation_id": exec_id}, "the execution is the target"
    assert cancel["operation_id"] != exec_id, "cancelling is an operation of its own"
    assert inv.connection.requests[2]["params"] == {"operation_id": exec_id}
    assert inv.result.stdout_bytes == b"so far\n"
    assert "CANCELLED" in inv.stderr


def test_ctrl_c_when_the_host_cannot_be_asked_says_the_outcome_is_not_known(invoke: Invoke) -> None:
    inv = invoke(
        ["sandbox", "exec", SBX, "--expected-generation", "1", "--", "sleep", "999"],
        KeyboardInterrupt(),
        HostUnreachable("nothing is listening"),
    )
    assert inv.exit_code == 130
    assert "could not be asked how the execution ended" in inv.stderr
    assert f"acf-local operation get {inv.connection.requests[0]['operation_id']}" in inv.stderr


def test_ctrl_c_during_another_mutation_names_the_operation_to_ask_about(invoke: Invoke) -> None:
    inv = invoke(["sandbox", "start", SBX, "--expected-generation", "1"], KeyboardInterrupt())
    assert inv.exit_code == 130
    operation_id = inv.connection.requests[0]["operation_id"]
    assert f"operation {operation_id} was already sent and may still complete" in inv.stderr
    assert f"acf-local operation get {operation_id}" in inv.stderr


# ----------------------------------------------------------------------------- sandbox inspect / list
def test_sandbox_inspect(invoke: Invoke, contract: Contract) -> None:
    human = invoke(["sandbox", "inspect", "box"], inspected(revision=31))
    assert human.exit_code == 0
    assert params(human) == {"sandbox": "box"}
    assert "revision          31" in human.stdout
    as_json = invoke(["sandbox", "inspect", SBX, "--json"], inspected())
    document = json_out(as_json)
    contract.check_response(document)
    assert document["result"]["data"]["sandbox_id"] == SBX


def test_sandbox_list_is_one_page_by_default(invoke: Invoke, contract: Contract) -> None:
    page = f.page(
        [f.sandbox_view(), f.sandbox_view(sandbox_id=f.OTHER_SANDBOX_ID, name="other")], more=True, sequence=30
    )
    human = invoke(["sandbox", "list"], answered("sandboxes", page))
    assert human.exit_code == 0
    assert human.connection.methods == ["sandbox.list"]
    assert "params" not in human.connection.requests[0]
    assert SBX in human.stdout
    assert f.OTHER_SANDBOX_ID in human.stdout
    assert f"2 record(s); listing more follow; cursor {f.LINEAGE}:30" in human.stderr
    assert f"--changed-since {f.LINEAGE}:30" in human.stderr
    as_json = invoke(["sandbox", "list", "--json"], answered("sandboxes", page))
    document = json_out(as_json)
    contract.check_response(document)
    assert document["result"]["data"]["more"] is True
    assert document["result"]["data"]["next"] == {"lineage": f.LINEAGE, "sequence": 30}


def test_list_flags_become_list_params(invoke: Invoke) -> None:
    inv = invoke(
        ["sandbox", "list", "--limit", "50", "--changed-since", f"{f.LINEAGE}:12"], answered("sandboxes", f.page([]))
    )
    assert params(inv) == {"changed_since": {"lineage": f.LINEAGE, "sequence": 12}, "limit": 50}
    assert "no sandboxes" in inv.stdout


@pytest.mark.parametrize(
    "args", [["--limit", "0"], ["--limit", "1001"], ["--changed-since", "41"], ["--changed-since", "x:y"]]
)
def test_bad_list_flags_are_usage_errors(invoke: Invoke, args: list[str]) -> None:
    inv = invoke(["sandbox", "list", *args])
    assert inv.exit_code == 2
    assert inv.connection.requests == []


def test_all_follows_the_cursor_and_a_full_listing_shows_what_exists(invoke: Invoke, contract: Contract) -> None:
    """Pages after the first are *changes*: they replace what an earlier page said, and they carry tombstones."""
    first = f.page(
        [f.sandbox_view(name="a"), f.sandbox_view(sandbox_id=f.OTHER_SANDBOX_ID, name="b")], more=True, sequence=20
    )
    gone = "sbx-" + "0c" * 16
    second = f.page(
        [
            f.sandbox_view(name="a", state="DESTROYED", revision=25),  # destroyed while we were listing
            f.sandbox_view(sandbox_id=gone, name="old", state="DESTROYED", revision=26),  # a tombstone
            f.sandbox_view(sandbox_id="sbx-" + "0d" * 16, name="c", revision=27),
        ],
        sequence=41,
    )
    inv = invoke(
        ["sandbox", "list", "--all", "--limit", "2", "--json"],
        answered("sandboxes", first),
        answered("sandboxes", second),
    )
    assert inv.connection.methods == ["sandbox.list", "sandbox.list"]
    assert params(inv, 0) == {"limit": 2}
    assert params(inv, 1) == {"changed_since": {"lineage": f.LINEAGE, "sequence": 20}, "limit": 2}
    document = json_out(inv)
    contract.check_response(document)
    assert [s["name"] for s in document["result"]["data"]["items"]] == ["b", "c"], "what exists, once"
    assert document["result"]["data"]["more"] is False
    assert document["result"]["data"]["next"]["sequence"] == 41


def test_all_with_a_cursor_keeps_the_tombstones_because_they_are_the_answer(invoke: Invoke) -> None:
    first = f.page([f.sandbox_view(state="DESTROYED", revision=25)], more=True, sequence=25)
    second = f.page([f.sandbox_view(sandbox_id=f.OTHER_SANDBOX_ID, name="new", revision=30)], sequence=41)
    inv = invoke(
        ["sandbox", "list", "--all", "--changed-since", f"{f.LINEAGE}:12"],
        answered("sandboxes", first),
        answered("sandboxes", second),
    )
    assert params(inv, 0) == {"changed_since": {"lineage": f.LINEAGE, "sequence": 12}}
    assert params(inv, 1) == {"changed_since": {"lineage": f.LINEAGE, "sequence": 25}}
    assert "DESTROYED" in inv.stdout
    assert f"2 record(s); listing complete; cursor {CURSOR}" in inv.stderr


def test_a_cursor_the_host_no_longer_keeps_is_its_refusal(invoke: Invoke) -> None:
    expired = refused(
        "CURSOR_EXPIRED",
        "the cursor is older than the change retention window; list again without a cursor",
        "AFTER_CHANGE",
    )
    inv = invoke(["sandbox", "list", "--changed-since", f"{f.LINEAGE}:1"], expired)
    assert inv.exit_code == 3
    assert "CURSOR_EXPIRED" in inv.stderr


# ----------------------------------------------------------------------------- snapshots
def test_snapshot_create(invoke: Invoke) -> None:
    inv = invoke(
        ["snapshot", "create", "box", "--name", "baseline"],
        inspected(generation=2),
        op("SUCCEEDED", f.snapshot_body(), operation_type="snapshot.create"),
    )
    assert inv.exit_code == 0
    assert inv.connection.methods == ["sandbox.inspect", "snapshot.create"]
    assert params(inv) == {"sandbox_id": SBX, "expected_generation": 2, "name": "baseline"}
    assert SNP in inv.stdout
    unnamed = invoke(
        ["snapshot", "create", SBX, "--expected-generation", "1", "--if-revision", "5"],
        op("SUCCEEDED", f.snapshot_body(name=None), operation_type="snapshot.create"),
    )
    assert params(unnamed) == {"sandbox_id": SBX, "expected_generation": 1, "if_revision": 5}


def test_restore_in_place_names_the_snapshot_and_the_sandbox_generation(invoke: Invoke) -> None:
    inv = invoke(
        ["snapshot", "restore", "baseline", "--into", "box"],
        answered("snapshots", f.page([f.snapshot_view()])),
        inspected(generation=3),
        op(
            "SUCCEEDED",
            f.sandbox_body(generation=4, source_snapshot={"snapshot_id": SNP, "snapshot_generation": 1}),
            operation_type="snapshot.restore",
        ),
    )
    assert inv.exit_code == 0
    assert inv.connection.methods == ["snapshot.list", "sandbox.inspect", "snapshot.restore"]
    assert params(inv) == {
        "snapshot": {"snapshot_id": SNP, "snapshot_generation": 1},
        "target": {"kind": "existing", "sandbox_id": SBX, "expected_generation": 3},
    }
    assert "generation        4" in inv.stdout
    assert f"{SNP}@1" in inv.stdout


def test_restore_as_new(invoke: Invoke) -> None:
    inv = invoke(
        ["snapshot", "restore", SNP, "--snapshot-generation", "1", "--new", "--name", "copy", "--lifetime", "10m"],
        op("SUCCEEDED", f.sandbox_body(sandbox_id=f.OTHER_SANDBOX_ID, name="copy"), operation_type="snapshot.restore"),
    )
    assert inv.exit_code == 0
    assert inv.connection.methods == ["snapshot.restore"], "an id with its generation needs no lookup"
    assert params(inv) == {
        "snapshot": {"snapshot_id": SNP, "snapshot_generation": 1},
        "target": {"kind": "new", "name": "copy", "lifetime_secs": 600},
    }
    plain = invoke(
        ["snapshot", "restore", SNP, "--snapshot-generation", "1", "--new"],
        op("SUCCEEDED", f.sandbox_body(), operation_type="snapshot.restore"),
    )
    assert params(plain)["target"] == {"kind": "new"}


def test_restore_in_place_with_an_exact_token_and_precondition(invoke: Invoke) -> None:
    inv = invoke(
        ["snapshot", "restore", SNP, "--snapshot-generation", "1", "--into", SBX,
         "--expected-generation", "2", "--if-revision", "31"],
        op("SUCCEEDED", f.sandbox_body(generation=3), operation_type="snapshot.restore"),
    )  # fmt: skip
    assert inv.connection.methods == ["snapshot.restore"]
    assert params(inv)["target"] == {"kind": "existing", "sandbox_id": SBX, "expected_generation": 2, "if_revision": 31}


@pytest.mark.parametrize(
    "args",
    [
        [],  # neither --into nor --new: the client does not guess
        ["--into", "box", "--new"],
        ["--into", "box", "--name", "copy"],
        ["--into", "box", "--lifetime", "1h"],
        ["--new", "--expected-generation", "2"],
        ["--new", "--if-revision", "2"],
    ],
)
def test_restore_requires_exactly_one_target_and_only_its_own_flags(invoke: Invoke, args: list[str]) -> None:
    inv = invoke(["snapshot", "restore", "baseline", *args])
    assert inv.exit_code == 2
    assert inv.connection.requests == []


def test_a_snapshot_name_is_resolved_through_the_listing(invoke: Invoke) -> None:
    other = f.snapshot_view(name="other", snapshot={"snapshot_id": "snp-" + "0d" * 16, "snapshot_generation": 1})
    listing = answered("snapshots", f.page([other, f.snapshot_view(name="baseline")]))
    inv = invoke(
        ["snapshot", "delete", "baseline", "--yes"],
        listing,
        op("SUCCEEDED", f.snapshot_body(state="DELETED"), operation_type="snapshot.delete"),
    )
    assert inv.exit_code == 0
    assert inv.connection.methods == ["snapshot.list", "snapshot.delete"]
    assert params(inv) == {"snapshot": {"snapshot_id": SNP, "snapshot_generation": 1}}
    assert "DELETED" in inv.stdout


def test_a_snapshot_that_cannot_be_found_or_is_ambiguous_changes_nothing(invoke: Invoke) -> None:
    missing = invoke(["snapshot", "delete", "ghost", "--yes"], answered("snapshots", f.page([f.snapshot_view()])))
    assert missing.exit_code == 3
    assert missing.connection.methods == ["snapshot.list"]
    assert "no snapshot with id or name 'ghost'" in missing.stderr
    assert "snapshots visible: baseline" in missing.stderr
    twin = f.snapshot_view(
        snapshot={"snapshot_id": "snp-" + "0d" * 16, "snapshot_generation": 1}, tags=f.tags(owner_scope="b")
    )
    ambiguous = invoke(
        ["snapshot", "delete", "baseline", "--yes"], answered("snapshots", f.page([f.snapshot_view(), twin]))
    )
    assert ambiguous.exit_code == 3
    assert "names 2 snapshots" in ambiguous.stderr
    assert ambiguous.connection.methods == ["snapshot.list"]


def test_snapshot_delete_needs_confirmation(invoke: Invoke) -> None:
    inv = invoke(["snapshot", "delete", SNP, "--snapshot-generation", "1"])
    assert inv.exit_code == 2
    assert inv.connection.requests == []


def test_a_delete_refused_because_something_depends_on_the_snapshot(invoke: Invoke) -> None:
    inv = invoke(
        ["snapshot", "delete", SNP, "--snapshot-generation", "1", "--yes"],
        refused("STATE_CONFLICT", "the snapshot is referenced by a live generation", "AFTER_CHANGE"),
    )
    assert inv.exit_code == 3
    assert "retry: AFTER_CHANGE" in inv.stderr


def test_snapshot_list(invoke: Invoke, contract: Contract) -> None:
    page = f.page([f.snapshot_view(), f.snapshot_view(state="DELETED", name=None, revision=30)])
    human = invoke(["snapshot", "list", "--changed-since", f"{f.LINEAGE}:9"], answered("snapshots", page))
    assert human.connection.methods == ["snapshot.list"]
    assert params(human) == {"changed_since": {"lineage": f.LINEAGE, "sequence": 9}}
    assert "DELETED" in human.stdout
    as_json = invoke(["snapshot", "list", "--json"], answered("snapshots", page))
    contract.check_response(json_out(as_json))


# ----------------------------------------------------------------------------- operations
@pytest.mark.parametrize(
    ("state", "exit_code"),
    [
        ("SUCCEEDED", 0),
        ("FAILED", 4),
        ("CANCELLED", 4),
        ("UNKNOWN", 5),
        ("ACCEPTED", 8),
        ("IN_PROGRESS", 8),
        ("RECOVERING", 8),
    ],
)
def test_operation_get_exit_status_mirrors_the_operation(invoke: Invoke, state: str, exit_code: int) -> None:
    inv = invoke(["operation", "get", OP], op(state))
    assert inv.exit_code == exit_code
    assert inv.connection.methods == ["operation.get"]
    assert params(inv) == {"operation_id": OP}
    assert state in inv.stdout
    assert "operation_id" not in inv.connection.requests[0], "asking is a read: nothing is submitted"


def test_operation_get_of_an_operation_the_host_does_not_hold(invoke: Invoke, contract: Contract) -> None:
    inv = invoke(["operation", "get", OP, "--json"], refused("NOT_FOUND", f"operation {OP} does not exist"))
    assert inv.exit_code == 3
    document = json_out(inv)
    contract.check_response(document)
    assert document["refusal"]["class"] == "NOT_FOUND"


def test_operation_get_wait_follows_until_the_operation_ends(
    invoke: Invoke, clock: FakeClock, contract: Contract
) -> None:
    inv = invoke(
        ["operation", "get", OP, "--wait", "--json"],
        op("IN_PROGRESS"),
        op("RECOVERING"),
        op("SUCCEEDED", f.sandbox_body()),
    )
    assert inv.exit_code == 0
    assert inv.connection.methods == ["operation.get"] * 3
    document = json_out(inv)
    contract.check_response(document)
    assert (document["answer"], document["operation"]["state"]) == ("OPERATION", "SUCCEEDED")
    timed = invoke(["operation", "get", OP, "--wait", "--timeout", "2s"], op("IN_PROGRESS"), default=op("IN_PROGRESS"))
    assert timed.exit_code == 8


def test_operation_get_rejects_something_that_is_not_an_operation_id(invoke: Invoke) -> None:
    inv = invoke(["operation", "get", "no"])
    assert inv.exit_code == 2
    assert inv.connection.requests == []


def test_one_page_is_shown_exactly_as_the_host_sent_it(invoke: Invoke) -> None:
    """Merging by identity is for pages that follow one another, never for the records of a single page."""
    twice = f.page([f.operation_view("FAILED"), f.operation_view("SUCCEEDED")])
    inv = invoke(["operation", "list", "--json"], answered("operations", twice))
    assert [o["state"] for o in json_out(inv)["result"]["data"]["items"]] == ["FAILED", "SUCCEEDED"]


def test_operation_list(invoke: Invoke, contract: Contract) -> None:
    other = f.operation_view("FAILED", operation_type="exec.run", operation_id="op-" + "1e" * 16)
    page = f.page([f.operation_view(), other], more=True, sequence=14)
    human = invoke(["operation", "list", "--limit", "2"], answered("operations", page))
    assert human.exit_code == 0
    assert params(human) == {"limit": 2}
    assert "sandbox.create" in human.stdout
    assert "exec.run" in human.stdout
    assert "listing more follow" in human.stderr
    as_json = invoke(["operation", "list", "--json"], answered("operations", page))
    contract.check_response(json_out(as_json))


def test_operation_cancel_is_an_operation_about_an_operation(invoke: Invoke) -> None:
    done = op(
        "SUCCEEDED",
        f.host_change_body(note="the execution ended Succeeded"),
        operation_type="operation.cancel",
        target=OP,
    )
    inv = invoke(["operation", "cancel", OP], done)
    assert inv.exit_code == 0
    assert inv.connection.methods == ["operation.cancel"]
    request = inv.connection.requests[0]
    assert request["params"] == {"operation_id": OP}
    assert request["operation_id"] != OP
    assert "issued_at" in request
    assert "the execution ended Succeeded" in inv.stdout


def test_cancelling_something_that_cannot_be_cancelled_is_a_refusal(invoke: Invoke) -> None:
    inv = invoke(
        ["operation", "cancel", OP], refused("STATE_CONFLICT", "`sandbox.create` cannot be cancelled", "AFTER_CHANGE")
    )
    assert inv.exit_code == 3
    assert "cannot be cancelled" in inv.stderr


# ----------------------------------------------------------------------------- run inspect / output
def test_run_inspect_of_a_finished_execution(invoke: Invoke, contract: Contract) -> None:
    human = invoke(["run", "inspect", RUN], answered("run", f.run_result(exit_code=3)))
    assert human.exit_code == 0, "the record was read; what the command did is in the record"
    assert params(human) == {"run_id": RUN}
    assert "EXITED (exit 3)" in human.stdout
    as_json = invoke(["run", "inspect", RUN, "--json"], answered("run", f.run_result()))
    document = json_out(as_json)
    contract.check_response(document)
    assert document["result"]["type"] == "run"


def test_run_inspect_of_an_execution_in_flight_shows_its_operation(invoke: Invoke) -> None:
    inv = invoke(
        ["run", "inspect", RUN],
        answered("operation", f.operation_view("IN_PROGRESS", operation_type="exec.run", run_id=RUN)),
    )
    assert inv.exit_code == 8
    assert "IN_PROGRESS" in inv.stdout
    assert "no result to show" in inv.stderr
    lost = invoke(
        ["run", "inspect", RUN], answered("operation", f.operation_view("UNKNOWN", operation_type="exec.run"))
    )
    assert lost.exit_code == 5


def test_run_inspect_rejects_something_that_is_not_a_run_id(invoke: Invoke) -> None:
    inv = invoke(["run", "inspect", "run-1"])
    assert inv.exit_code == 2
    assert inv.connection.requests == []


def test_run_output_writes_the_stored_bytes_to_stdout(invoke: Invoke) -> None:
    data = b"line one\n\xff\xfe binary\n"
    inv = invoke(["run", "output", RUN], answered("output", f.output_chunk(data)))
    assert inv.exit_code == 0
    assert params(inv) == {"run_id": RUN, "stream": "stdout", "offset": 0}
    assert inv.result.stdout_bytes == data
    assert f"stdout of {RUN}" in inv.stderr


def test_run_output_asks_for_slices_until_the_end(invoke: Invoke, contract: Contract) -> None:
    inv = invoke(
        ["run", "output", RUN, "--stream", "stderr", "--offset", "4", "--json"],
        answered("output", f.output_chunk(b"0123", offset=4, stored=12, eof=False, stream="stderr")),
        answered("output", f.output_chunk(b"4567", offset=8, stored=12, eof=True, stream="stderr")),
    )
    assert [params(inv, i) for i in (0, 1)] == [
        {"run_id": RUN, "stream": "stderr", "offset": 4},
        {"run_id": RUN, "stream": "stderr", "offset": 8},
    ]
    document = json_out(inv)
    contract.check_response(document)
    chunk = document["result"]["data"]
    assert base64.b64decode(chunk["data_b64"]) == b"01234567", "the slices, joined"
    assert (chunk["offset"], chunk["eof"], chunk["stream"]) == (4, True, "stderr")


def test_run_output_stops_at_max_bytes_and_says_where_to_continue(invoke: Invoke) -> None:
    inv = invoke(
        ["run", "output", RUN, "--max-bytes", "6"],
        answered("output", f.output_chunk(b"abcd", offset=0, stored=100, eof=False)),
        answered("output", f.output_chunk(b"ef", offset=4, stored=100, eof=False)),
    )
    assert [params(inv, i)["max_bytes"] for i in (0, 1)] == [6, 2]
    assert inv.result.stdout_bytes == b"abcdef"
    assert "continue with --offset 6" in inv.stderr


def test_run_output_of_an_execution_that_has_not_ended_is_the_hosts_refusal(invoke: Invoke) -> None:
    inv = invoke(["run", "output", RUN], refused("UNSUPPORTED", "the execution has not ended", "AFTER_CHANGE"))
    assert inv.exit_code == 3
    assert "UNSUPPORTED" in inv.stderr


# ----------------------------------------------------------------------------- operator commands
@pytest.mark.parametrize(("word", "mode"), [("draining", "DRAINING"), ("serving", "SERVING"), ("DRAINING", "DRAINING")])
def test_host_set_mode(invoke: Invoke, word: str, mode: str) -> None:
    done = op("SUCCEEDED", f.host_change_body(mode=mode), operation_type="host.set_mode", target="host", sandbox=None)
    inv = invoke(["host", "set-mode", word], done)
    assert inv.exit_code == 0
    assert inv.connection.methods == ["host.set_mode"]
    assert params(inv) == {"mode": mode}
    assert f"host mode {mode}" in inv.stdout


def test_host_set_mode_accepts_only_the_two_modes_an_operator_may_ask_for(invoke: Invoke) -> None:
    for word in ("containment", "read_only", "starting"):
        inv = invoke(["host", "set-mode", word])
        assert inv.exit_code == 2
        assert inv.connection.requests == []


def test_a_non_operator_is_refused(invoke: Invoke) -> None:
    inv = invoke(
        ["host", "set-mode", "draining"], refused("AUTHORIZATION_DENIED", "role `caller` may not call `host.set_mode`")
    )
    assert inv.exit_code == 3


def test_host_acknowledge(invoke: Invoke) -> None:
    done = op(
        "SUCCEEDED",
        f.host_change_body(mode="SERVING", note="store accepted as authoritative"),
        operation_type="host.acknowledge",
        target="host",
        sandbox=None,
    )
    inv = invoke(["host", "acknowledge", "store-regression", "--yes"], done)
    assert inv.exit_code == 0
    assert params(inv) == {"condition": "store_regression"}
    assert "store accepted as authoritative" in inv.stdout
    unconfirmed = invoke(["host", "acknowledge", "store-regression"])
    assert unconfirmed.exit_code == 2
    assert unconfirmed.connection.requests == []


def test_profile_reload(invoke: Invoke, contract: Contract) -> None:
    done = op(
        "SUCCEEDED",
        f.host_change_body(profile=f.profile_id()),
        operation_type="profile.reload",
        target="host",
        sandbox=None,
    )
    inv = invoke(["profile", "reload"], done)
    assert inv.exit_code == 0
    assert inv.connection.methods == ["profile.reload"]
    assert "params" not in inv.connection.requests[0]
    assert "operation_id" in inv.connection.requests[0], "reloading is a recorded operation"
    assert "profile in force default@2.0.0#cdcdcdcdcdcd" in inv.stdout
    as_json = invoke(["profile", "reload", "--json"], done)
    contract.check_response(json_out(as_json))


def test_an_invalid_profile_is_refused_and_the_previous_one_stays(invoke: Invoke) -> None:
    inv = invoke(
        ["profile", "reload"], refused("INTEGRITY_FAILURE", "the safety profile is not a trusted input", "AFTER_CHANGE")
    )
    assert inv.exit_code == 3
    assert "INTEGRITY_FAILURE" in inv.stderr


@pytest.mark.parametrize(("word", "mode"), [("force-destroy", "FORCE_DESTROY"), ("declare-absent", "DECLARE_ABSENT")])
def test_quarantine_release_in_both_modes(invoke: Invoke, word: str, mode: str) -> None:
    done = op(
        "SUCCEEDED",
        f.host_change_body(note=f"assertion {mode}; found before: nothing; found after: nothing"),
        operation_type="quarantine.release",
    )
    inv = invoke(["quarantine", "release", SBX, "--generation", "2", "--mode", word, "--yes"], done)
    assert inv.exit_code == 0
    assert inv.connection.methods == ["quarantine.release"]
    assert params(inv) == {"sandbox_id": SBX, "generation": 2, "mode": mode}
    assert "found after: nothing" in inv.stdout


def test_a_release_the_observation_contradicts_fails_and_stays_quarantined(invoke: Invoke) -> None:
    contradicted = op(
        "FAILED",
        f.host_change_body(note="assertion DeclareAbsent; found after: runtime process"),
        operation_type="quarantine.release",
        failure=f.failure("QUARANTINED", "observation contradicts the assertion"),
        cleanup="QUARANTINED",
        effect="MAY_BE_APPLIED",
    )
    inv = invoke(["quarantine", "release", SBX, "--generation", "2", "--mode", "declare-absent", "--yes"], contradicted)
    assert inv.exit_code == 4
    assert "QUARANTINED - what the operation left is quarantined" in inv.stderr


@pytest.mark.parametrize(
    "args",
    [
        ["box", "--generation", "1", "--mode", "force-destroy", "--yes"],  # a name is never accepted
        [SBX, "--mode", "force-destroy", "--yes"],  # no generation
        [SBX, "--generation", "1", "--yes"],  # no mode: the operator must say what they assert
        [SBX, "--generation", "1", "--mode", "just-delete", "--yes"],
        [SBX, "--generation", "0", "--mode", "force-destroy", "--yes"],
        [SBX, "--generation", "1", "--mode", "force-destroy"],  # no confirmation
    ],
)
def test_quarantine_release_is_explicit_about_everything(invoke: Invoke, args: list[str]) -> None:
    inv = invoke(["quarantine", "release", *args])
    assert inv.exit_code == 2
    assert inv.connection.requests == []


# ----------------------------------------------------------------------------- nothing sensitive is ever sent or shown
def test_no_request_ever_carries_an_authority_field(invoke: Invoke) -> None:
    script = [
        op("SUCCEEDED", f.sandbox_body()),
        answered("host_info", f.host_info()),
        op("SUCCEEDED", f.sandbox_body()),
    ]
    inv = invoke(["sandbox", "create", "--image", "python"], script[0])
    info = invoke(["host", "info"], script[1])
    stop = invoke(["sandbox", "stop", SBX, "--expected-generation", "1"], script[2])
    for sent in (*inv.connection.requests, *info.connection.requests, *stop.connection.requests):
        assert "authority" not in sent


def test_environment_values_are_sent_but_never_printed(invoke: Invoke) -> None:
    inv = invoke(
        ["-v", "sandbox", "exec", SBX, "--expected-generation", "1", "-e", "LANG=very-distinctive-value", "--", "true"],
        op("SUCCEEDED", f.run_body(), operation_type="exec.run"),
    )
    assert params(inv)["command"]["env"] == {"LANG": "very-distinctive-value"}
    assert "very-distinctive-value" not in inv.result.output


# ----------------------------------------------------------------------------- a request that cannot be built
@pytest.mark.parametrize(
    ("args", "complaint"),
    [
        (
            ["sandbox", "stop", SBX, "--expected-generation", "1", "--if-revision", "99999999999999999999999"],
            "if_revision",
        ),
        (["sandbox", "create", "--image", "python", "--cpu", "999"], "vcpus"),
        (["sandbox", "create", "--image", "not an alias"], "--image"),
        (["snapshot", "create", "box", "--name", ".hidden"], "--name"),
        (["snapshot", "restore", SNP, "--snapshot-generation", "1", "--new", "--name", "a/b"], "--name"),
        (["snapshot", "restore", SNP, "--snapshot-generation", "1", "--new", "--lifetime", "1500ms"], "--lifetime"),
        (["sandbox", "inspect", "x" * 65], "sandbox"),
    ],
)
def test_a_request_that_cannot_be_built_is_a_usage_error_and_nothing_is_sent(
    invoke: Invoke, args: list[str], complaint: str
) -> None:
    inv = invoke(args)
    assert inv.exit_code == 2
    assert complaint in inv.stderr
    assert inv.connection.requests == [], "not even the read that would resolve a name"


def test_with_json_a_usage_error_found_by_the_client_is_an_error_document(invoke: Invoke) -> None:
    inv = invoke(["sandbox", "create", "--image", "python", "--cpu", "999", "--json"])
    assert inv.exit_code == 2
    error = json_out(inv)["error"]
    assert (error["kind"], error["exit_code"]) == ("InvalidArgument", 2)
    assert "vcpus" in error["message"]


def test_quarantine_release_says_what_a_sandbox_id_looks_like(invoke: Invoke) -> None:
    inv = invoke(["quarantine", "release", "box", "--generation", "1", "--mode", "force-destroy", "--yes"])
    assert "'box' is not a sandbox id" in inv.stderr
    assert "sbx-" in inv.stderr


# ----------------------------------------------------------------------------- further outcomes of exec
def test_an_execution_that_succeeded_without_a_result_is_a_protocol_violation(invoke: Invoke) -> None:
    inv = invoke(
        ["sandbox", "exec", SBX, "--expected-generation", "1", "--", "true"], op("SUCCEEDED", f.sandbox_body())
    )
    assert inv.exit_code == 7
    assert "succeeded without the result of an execution" in inv.stderr


def test_ctrl_c_before_the_host_recorded_the_execution_says_there_is_no_record(invoke: Invoke) -> None:
    unknown = refused("NOT_FOUND", "operation does not exist")
    inv = invoke(
        ["sandbox", "exec", SBX, "--expected-generation", "1", "--", "true"], KeyboardInterrupt(), unknown, unknown
    )
    assert inv.exit_code == 130
    assert inv.connection.methods == ["exec.run", "operation.cancel", "operation.get"]
    assert "refused: NOT_FOUND" in inv.stderr
    assert "holds no usable record of operation" in inv.stderr


def test_ctrl_c_with_json_prints_how_the_execution_ended(invoke: Invoke, contract: Contract) -> None:
    inv = invoke(
        ["sandbox", "exec", SBX, "--expected-generation", "1", "--json", "--", "sleep", "999"],
        KeyboardInterrupt(),
        op("SUCCEEDED", f.host_change_body(note="the execution ended Cancelled"), operation_type="operation.cancel"),
        op("CANCELLED", f.run_body(status="CANCELLED", exit_code=None), operation_type="exec.run"),
    )
    assert inv.exit_code == 130
    document = json_out(inv)
    contract.check_response(document)
    assert document["operation"]["state"] == "CANCELLED"
    assert inv.result.stdout_bytes.startswith(b"{"), "the guest's output is inside the document, not around it"


def test_verbose_reports_progress_on_stderr(invoke: Invoke) -> None:
    inv = invoke(
        ["-v", "run", "once", "--image", "python", "--", "true"],
        op("SUCCEEDED", f.sandbox_body(state="PROVISIONING")),
        op("SUCCEEDED", f.sandbox_body()),
        op("SUCCEEDED", f.run_body(stdout=b""), operation_type="exec.run"),
        op("SUCCEEDED", f.sandbox_body(state="DESTROYED"), operation_type="sandbox.destroy"),
    )
    assert inv.exit_code == 0
    assert "acf-local: creating the sandbox" in inv.stderr
    assert f"acf-local: destroying {SBX}" in inv.stderr
    assert inv.stdout == ""


def test_run_once_reports_a_refused_step_and_a_step_that_is_not_established(invoke: Invoke) -> None:
    refused_create = invoke(
        ["run", "once", "--image", "python", "--", "true"],
        refused("SAFETY_CONTROL_DENIED", "image not permitted", "AFTER_CHANGE"),
    )
    assert refused_create.exit_code == 3
    assert "REFUSED SAFETY_CONTROL_DENIED" in refused_create.stderr
    assert "cleanup: nothing to clean up" in refused_create.stderr
    lost = invoke(
        ["run", "once", "--image", "python", "--", "true"],
        ResponseLost("the host closed the connection without answering"),
        default=HostUnreachable("nothing is listening"),
    )
    assert lost.exit_code == 8
    assert "not established" in lost.stderr
    assert "If it did, a sandbox exists" in lost.stderr


def test_run_once_interrupted_says_what_the_host_had_recorded(invoke: Invoke) -> None:
    inv = invoke(
        ["run", "once", "--image", "python", "--", "true"],
        op("SUCCEEDED", f.sandbox_body(state="PROVISIONING")),
        KeyboardInterrupt(),
        op("IN_PROGRESS", operation_type="sandbox.start"),
        op("SUCCEEDED", f.sandbox_body(state="DESTROYED"), operation_type="sandbox.destroy"),
    )
    assert inv.exit_code == 130
    assert inv.connection.methods == ["sandbox.create", "sandbox.start", "operation.get", "sandbox.destroy"]
    assert "start: " in inv.stderr
    assert "IN_PROGRESS" in inv.stderr
    assert "interrupted: the steps above are what the host had recorded" in inv.stderr
    assert f"cleanup: destroyed {SBX}" in inv.stderr


def test_run_inspect_json_of_an_execution_in_flight(invoke: Invoke, contract: Contract) -> None:
    inv = invoke(
        ["run", "inspect", RUN, "--json"],
        answered("operation", f.operation_view("IN_PROGRESS", operation_type="exec.run")),
    )
    assert inv.exit_code == 8
    document = json_out(inv)
    contract.check_response(document)
    assert document["result"]["type"] == "operation"


def test_a_snapshot_id_without_its_generation_is_looked_up(invoke: Invoke) -> None:
    second = f.snapshot_view(snapshot={"snapshot_id": SNP, "snapshot_generation": 2}, name="later")
    listing = answered("snapshots", f.page([f.snapshot_view(), second]))
    done = op("SUCCEEDED", f.snapshot_body(state="DELETED"), operation_type="snapshot.delete")
    ambiguous = invoke(["snapshot", "delete", SNP, "--yes"], listing)
    assert ambiguous.exit_code == 3
    assert "names 2 snapshots" in ambiguous.stderr
    exact = invoke(["snapshot", "delete", "later", "--snapshot-generation", "2", "--yes"], listing, done)
    assert params(exact) == {"snapshot": {"snapshot_id": SNP, "snapshot_generation": 2}}
    only = invoke(["snapshot", "delete", SNP, "--yes"], answered("snapshots", f.page([f.snapshot_view()])), done)
    assert params(only) == {"snapshot": {"snapshot_id": SNP, "snapshot_generation": 1}}


# ----------------------------------------------------------------------------- the entry point
def acf_local(*args: str, stdout: int | None = None) -> subprocess.CompletedProcess[bytes]:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
        "PYTHONDONTWRITEBYTECODE": "1",  # a test leaves nothing behind in the source tree
    }
    return subprocess.run(
        [sys.executable, "-m", "acf_cli", *args],
        stdout=stdout if stdout is not None else subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        timeout=60,
        check=False,
    )


def test_the_module_is_runnable_as_a_process() -> None:
    done = acf_local("--version")
    assert done.returncode == 0
    assert done.stdout.decode().strip() == f"acf-local {__version__}"


def test_a_reader_that_went_away_ends_the_process_quietly(tmp_path: Path) -> None:
    """``acf-local ... | head``: stop with the conventional status, without a traceback."""
    reader, writer = os.pipe()
    os.close(reader)
    try:
        done = acf_local("--socket", str(tmp_path / "no-host.sock"), "host", "info", "--json", stdout=writer)
    finally:
        os.close(writer)
    assert done.returncode == 141, "128 + SIGPIPE, not the status of whatever the command was reporting"
    assert b"Traceback" not in done.stderr
    assert b"Exception ignored" not in done.stderr
