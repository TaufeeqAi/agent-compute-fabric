"""The published contract artifacts under ``protocols/``, checked against the contract.

Proves that the artifacts are what the code generates and hold what the contract says: every operation
of the table of operations, routes and tools with its method and path, keyed as that table says
(PUB-1, IDM-1, CRD-9); no name for a surface the contract does not specify (PUB-9, VER-14); no operator
method of the host (SEC-106); tool names that are portable (MCP-16), annotations that are the
contract's and understate no worst case (MCP-10, PUB-5), an input and an output schema per tool in
JSON Schema 2020-12 (MCP-5), and no description that sends an agent to another tool by name (MCP-16);
and a conformance suite whose answers are answers the public model can give.
Catalog entries: T3-API-01, T3-SEC-06 at the static level, and T3-RED-40.

The contract governs the artifacts, not the reverse. So the tables of the contract are written out
below as data, and the artifacts are compared with them rather than with the code they came from.

One reading is fixed here and reported. The mapping table between the public vocabularies and the
host's names the host's operator methods once, in the list of methods the platform never calls. That
list exposes nothing, and without it nothing would say that every host method is accounted for. The
test therefore requires that the operator methods appear there and nowhere else under ``protocols/``.
"""

from __future__ import annotations

import functools
import hashlib
import json
import re
import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator
from openapi_spec_validator import validate as validate_openapi
from pydantic import ValidationError

from acf_api.command import model as m
from acf_api.command.errors import CODES, Code, Kind, Retry
from acf_api.command.surface import HOST_OPERATOR_METHODS, OPERATIONS
from acf_api.contract import generate
from acf_api.edge.http.routes import ROUTES

REPO = Path(__file__).resolve().parents[3]
PROTOCOLS = REPO / "protocols"
P = "/v1/projects/{project}"

#: The table of operations, routes and tools: the public method, its REST route, its tool (or none),
#: its command-line command, and whether a request for it carries an idempotency key.
OPERATION_TABLE: list[tuple[str, str, str, str | None, str, bool]] = [
    ("sandbox.create", "POST", f"{P}/sandboxes", "sandbox_create", "acf sandbox create", True),
    ("sandbox.start", "POST", f"{P}/sandboxes/{{sandbox}}/start", "sandbox_start", "acf sandbox start", True),
    ("execution.create", "POST", f"{P}/sandboxes/{{sandbox}}/executions", "sandbox_exec", "acf exec run", True),
    ("execution.get", "GET", f"{P}/executions/{{execution}}", "exec_status", "acf exec status", False),
    ("execution.output", "GET", f"{P}/executions/{{execution}}/output", "exec_output", "acf exec output", False),
    ("execution.cancel", "POST", f"{P}/executions/{{execution}}/cancel", "exec_cancel", "acf exec cancel", True),
    (
        "snapshot.create",
        "POST",
        f"{P}/sandboxes/{{sandbox}}/snapshots",
        "sandbox_snapshot",
        "acf snapshot create",
        True,
    ),
    (
        "snapshot.restore",
        "POST",
        f"{P}/snapshots/{{snapshot}}/restore",
        "sandbox_restore",
        "acf snapshot restore",
        True,
    ),
    ("sandbox.list", "GET", f"{P}/sandboxes", "sandbox_list", "acf sandbox list", False),
    ("sandbox.get", "GET", f"{P}/sandboxes/{{sandbox}}", "sandbox_inspect", "acf sandbox inspect", False),
    ("snapshot.list", "GET", f"{P}/snapshots", "snapshot_list", "acf snapshot list", False),
    ("sandbox.stop", "POST", f"{P}/sandboxes/{{sandbox}}/stop", "sandbox_stop", "acf sandbox stop", True),
    ("sandbox.destroy", "DELETE", f"{P}/sandboxes/{{sandbox}}", "sandbox_destroy", "acf sandbox destroy", True),
    ("snapshot.delete", "DELETE", f"{P}/snapshots/{{snapshot}}", "snapshot_delete", "acf snapshot delete", True),
    ("operation.get", "GET", f"{P}/operations/{{operation}}", "operation_get", "acf operation get", False),
    ("operation.list", "GET", f"{P}/operations", None, "acf operation list", False),
    # Minting and revoking reach no host and take no key. None of the three is ever a tool.
    ("agent_credential.mint", "POST", f"{P}/agent-credentials", None, "acf auth agent-key create", False),
    ("agent_credential.list", "GET", f"{P}/agent-credentials", None, "acf auth agent-key list", False),
    (
        "agent_credential.revoke",
        "DELETE",
        f"{P}/agent-credentials/{{credential}}",
        None,
        "acf auth agent-key revoke",
        False,
    ),
    ("platform.info", "GET", "/v1/info", "health_check", "acf info", False),
    ("auth.whoami", "GET", "/v1/auth/whoami", None, "acf policy inspect", False),
]
BY_METHOD = {row[0]: row for row in OPERATION_TABLE}

#: The tool catalogue of the contract: readOnlyHint, destructiveHint, idempotentHint, openWorldHint.
ANNOTATIONS: dict[str, tuple[bool, bool, bool, bool]] = {
    "sandbox_create": (False, False, False, False),
    "sandbox_start": (False, False, False, False),
    "sandbox_exec": (False, True, False, True),
    "exec_status": (True, False, True, False),
    "exec_output": (True, False, True, False),
    "exec_cancel": (False, True, True, False),
    "sandbox_snapshot": (False, False, False, False),
    "sandbox_restore": (False, True, False, False),
    "sandbox_list": (True, False, True, False),
    "sandbox_inspect": (True, False, True, False),
    "snapshot_list": (True, False, True, False),
    "operation_get": (True, False, True, False),
    "health_check": (True, False, True, False),
    "sandbox_stop": (False, True, True, False),
    "sandbox_destroy": (False, True, True, False),
    "snapshot_delete": (False, True, True, False),
}

#: The rollback classification of the contract: the worst class each operation can have. An execution
#: is irreversible at worst, in a sandbox with network `allowlist`; a restore retires a generation for good.
WORST_CLASS = {
    "sandbox.create": "COMPENSATABLE",
    "sandbox.start": "COMPENSATABLE",
    "execution.create": "IRREVERSIBLE",
    "snapshot.create": "COMPENSATABLE",
    "snapshot.restore": "IRREVERSIBLE",
    "sandbox.stop": "IRREVERSIBLE",
    "sandbox.destroy": "IRREVERSIBLE",
    "snapshot.delete": "IRREVERSIBLE",
}
#: Operations that end something for good and are idempotent by meaning on the host.
CONTAINMENT = {"sandbox.stop", "sandbox.destroy", "snapshot.delete", "execution.cancel"}
#: Operations that grant: each accepted request is new work, so a tool for one is never idempotent.
GRANTING = {"sandbox.create", "sandbox.start", "execution.create", "snapshot.create", "snapshot.restore"}

#: Words of surfaces the contract does not specify. No route, type, tool or member is named by one.
UNSPECIFIED = ("run", "workspace", "experiment", "evidence", "approval", "tenant", "billing", "file", "stream")
#: Members that hold one of those words and are not a name for such a surface, each for its reason.
NOT_A_SURFACE = {
    "stream": "which of the two output streams of an execution a chunk is read from",
}


@functools.cache
def openapi() -> dict[str, Any]:
    """The published document, read once. No test changes what it returns."""
    loaded = yaml.safe_load((PROTOCOLS / "api" / "openapi.yaml").read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


@functools.cache
def surface() -> dict[str, Any]:
    loaded = yaml.safe_load((PROTOCOLS / "api" / "surface.yaml").read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


@functools.cache
def tools() -> dict[str, dict[str, Any]]:
    return {
        path.stem: json.loads(path.read_text(encoding="utf-8"))
        for path in sorted((PROTOCOLS / "mcp" / "tools").glob("*.json"))
    }


@functools.cache
def scenarios() -> dict[str, Any]:
    loaded = json.loads((PROTOCOLS / "conformance" / "scenarios.json").read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def operations_of(document: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {
        (method.upper(), path): operation
        for path, item in document["paths"].items()
        for method, operation in item.items()
        if method in {"get", "post", "put", "patch", "delete", "head", "options", "trace", "query"}
    }


def parameters_of(document: dict[str, Any], operation: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for listed in operation.get("parameters", []):
        resolved = listed
        while "$ref" in resolved:
            resolved = document["components"]["parameters"][resolved["$ref"].rsplit("/", 1)[1]]
        out.append(resolved)
    return out


def members_of(schema: Any) -> Iterator[str]:
    """The name of every member any object of a schema can have, at any depth."""
    if isinstance(schema, dict):
        for key, value in schema.items():
            if key in {"properties", "patternProperties"} and isinstance(value, dict):
                yield from value
            yield from members_of(value)
    elif isinstance(schema, list):
        for item in schema:
            yield from members_of(item)


def words_of(name: str) -> list[str]:
    """The lower-case words of a name in any of the ways names are written here."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return [word for word in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if word]


def names_a_surface(name: str, word: str) -> bool:
    """Whether a route segment, a type, a tool or a tag is named by ``word``, in the singular or the plural."""
    return any(part in {word, word + "s"} for part in words_of(name))


def is_a_reference_to(member: str, word: str) -> bool:
    """Whether a member is such a thing or points at one: `run`, `runs`, `run_id`, `run_ids`."""
    return member in {word, word + "s", word + "_id", word + "_ids"}


# ------------------------------------------------------------------------------- generated, and current
@pytest.fixture(autouse=True, scope="module")
def one_generation() -> Iterator[None]:
    """One run of the generator serves every test of this file.

    The generator reads nothing but the code, and is held to that here: a second run must give the
    same files. After it, the checks below ask for the files nine times and are given the same ones.
    What each of them still tests is its own subject, the comparison with what is on disk.
    """
    built = generate.build_all()
    assert generate.build_all() == built, "the generator gives other files when it is run again"
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(generate, "build_all", lambda: dict(built))
        yield


@pytest.mark.proves("T3-API-01")
def test_the_checked_in_artifacts_are_what_the_code_generates() -> None:
    assert generate.check(PROTOCOLS) == []
    assert generate.main(["--out", str(PROTOCOLS), "--check"]) == 0


@pytest.mark.proves("T3-API-01")
def test_nothing_is_published_that_the_generator_does_not_write() -> None:
    generated = set(generate.build_all())
    published = {path.relative_to(PROTOCOLS).as_posix() for path in PROTOCOLS.rglob("*") if path.is_file()}
    # The conformance suite is explained to its readers by hand. Everything else comes from the code.
    assert published - generated == {"conformance/README.md"}
    assert generated - published == set()
    assert generated == {
        "api/openapi.yaml",
        "api/surface.yaml",
        "api/problems/registry.yaml",
        "api/mapping/acf.host-2.yaml",
        "mcp/catalogue.json",
        "conformance/scenarios.json",
        *(f"mcp/tools/{name}.json" for name in ANNOTATIONS),
    }


@pytest.mark.proves("T3-API-01")
def test_drift_between_the_artifacts_and_the_code_is_detected(tmp_path: Path) -> None:
    """The check has to be able to fail: a changed file, a missing file and a file for a tool that does not exist."""
    copy = tmp_path / "protocols"
    shutil.copytree(PROTOCOLS, copy)
    assert generate.check(copy) == []

    document = copy / "api" / "openapi.yaml"
    document.write_text(
        document.read_text(encoding="utf-8").replace("sandbox.create", "sandbox.make", 1), encoding="utf-8"
    )
    (copy / "mcp" / "tools" / "exec_status.json").unlink()
    (copy / "mcp" / "tools" / "file_read.json").write_text("{}", encoding="utf-8")
    registry = copy / "api" / "problems" / "registry.yaml"
    registry.write_text(registry.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    stale = generate.check(copy)
    assert sorted(stale) == [
        "api/openapi.yaml",
        "api/problems/registry.yaml",
        "mcp/tools/exec_status.json",
        "mcp/tools/file_read.json (no such tool)",
    ]
    assert generate.main(["--out", str(copy), "--check"]) == 1
    assert generate.main(["--out", str(copy)]) == 0
    assert generate.check(copy) == ["mcp/tools/file_read.json (no such tool)"], (
        "writing restores every artifact and removes nothing it did not write"
    )
    assert generate.check(tmp_path / "absent") != []


# ------------------------------------------------------------------------------- the OpenAPI document
@pytest.mark.proves("T3-API-01")
def test_the_openapi_document_is_a_valid_openapi_document() -> None:
    document = openapi()
    assert document["openapi"].startswith("3.2")
    validate_openapi(document)
    assert document["info"]["version"].split(".")[0] == m.API_VERSION.removeprefix("v")
    assert all(path.startswith("/v1/") for path in document["paths"])


@pytest.mark.proves("T3-API-01")
def test_every_operation_of_the_contract_is_in_the_openapi_document_and_no_other() -> None:
    published = operations_of(openapi())
    expected = {(method, path): public_method for public_method, method, path, _tool, _cli, _keyed in OPERATION_TABLE}
    assert set(published) == set(expected)
    assert len(expected) == len(OPERATION_TABLE) == 21
    for route, public_method in expected.items():
        assert published[route]["operationId"] == public_method, route
    assert len({operation["operationId"] for operation in published.values()}) == 21


@pytest.mark.proves("T3-API-01")
def test_the_output_of_an_execution_is_read_by_stream_and_offset() -> None:
    document = openapi()
    operation = operations_of(document)[("GET", f"{P}/executions/{{execution}}/output")]
    query = {
        parameter["name"]: parameter for parameter in parameters_of(document, operation) if parameter["in"] == "query"
    }
    assert {"stream", "offset"} <= set(query)
    assert query["stream"]["schema"]["enum"] == ["stdout", "stderr"]
    assert query["offset"]["schema"] == {"type": "integer", "minimum": 0}


@pytest.mark.proves("T3-API-01")
@pytest.mark.parametrize("row", OPERATION_TABLE, ids=[row[0] for row in OPERATION_TABLE])
def test_an_operation_is_keyed_exactly_as_the_contract_says(row: tuple[str, str, str, str | None, str, bool]) -> None:
    """Every mutation that creates a host operation carries an idempotency key. Minting and revoking carry none."""
    public_method, method, path, _tool, _cli, keyed = row
    document = openapi()
    operation = operations_of(document)[(method, path)]
    headers = {
        parameter["name"]: parameter for parameter in parameters_of(document, operation) if parameter["in"] == "header"
    }
    assert ("Idempotency-Key" in headers) is keyed
    if keyed:
        assert headers["Idempotency-Key"]["required"] is True
        assert headers["Idempotency-Key"]["schema"] == {"type": "string", "minLength": 1, "maxLength": 255}
        assert operation["x-acf-class"] in {"granting", "containment"}
        # A keyed request answers with an operation: ended, or accepted and to be followed.
        assert {"200", "202"} <= set(operation["responses"])
        assert {"Location", "Retry-After"} <= set(operation["responses"]["202"]["headers"])
        assert "Idempotent-Replayed" in operation["responses"]["200"]["headers"]
    else:
        assert operation["x-acf-class"] in {"read", "platform"}
        assert "202" not in operation["responses"]
    entry = next(entry for entry in surface()["operations"] if entry["method"] == public_method)
    assert entry["idempotency_key"] is keyed
    assert (entry["class"] in {"granting", "containment"}) is keyed
    assert entry["reaches_host"] is (public_method.split(".")[0] not in {"agent_credential", "auth"})


@pytest.mark.proves("T3-API-01")
def test_the_table_of_operations_is_published_as_the_contract_has_it() -> None:
    published = {entry["method"]: entry for entry in surface()["operations"]}
    assert list(published) == [op.method for op in OPERATIONS]
    assert set(published) == set(BY_METHOD)
    for public_method, method, path, tool, cli, _keyed in OPERATION_TABLE:
        entry = published[public_method]
        assert entry["rest"] == f"{method} {path}", public_method
        assert entry["tool"] == tool, public_method
        assert entry["cli"] == cli, public_method
        assert entry["reversibility"] == WORST_CLASS.get(
            public_method, "IRREVERSIBLE" if public_method == "execution.cancel" else None
        ), public_method
    assert {entry["tool"] for entry in published.values()} - {None} == set(ANNOTATIONS)
    assert surface()["api_version"] == "v1"


@pytest.mark.proves("T3-API-01")
def test_every_route_of_the_adapter_is_a_row_of_the_contract() -> None:
    """The routes the REST adapter serves and the document that describes them come from one table."""
    served = {(route.method, route.path): route.operation.method for route in ROUTES}
    assert served == {
        (method, path): public_method for public_method, method, path, _tool, _cli, _keyed in OPERATION_TABLE
    }
    document = operations_of(openapi())
    for route in ROUTES:
        operation = document[(route.method, route.path)]
        assert ("requestBody" in operation) is (route.body is not None)
        assert operation["security"] == ([{}, {"bearer": []}] if route.anonymous else [{"bearer": []}])
    assert [route.operation.method for route in ROUTES if route.anonymous] == ["platform.info"]


@pytest.mark.proves("T3-API-01", "T3-ERR-01")
def test_the_error_answers_of_the_document_are_the_failure_table() -> None:
    document = openapi()
    by_status: dict[int, list[str]] = {}
    for code, info in CODES.items():
        if info.kind is not None and info.http_status is not None:
            by_status.setdefault(info.http_status, []).append(code.value)
    responses = document["components"]["responses"]
    assert set(responses) == {f"Problem{status}" for status in by_status}
    for status, codes in by_status.items():
        response = responses[f"Problem{status}"]
        listed = re.findall(r"[A-Z][A-Z_]+[A-Z]", response["description"].split("Codes:", 1)[1])
        assert sorted(listed) == sorted(codes), status
        assert list(response["content"]) == ["application/problem+json"]
        assert response["content"]["application/problem+json"]["schema"] == {"$ref": "#/components/schemas/Problem"}
        assert ("Retry-After" in response["headers"]) is any(CODES[Code(code)].retry_after for code in codes), status
        assert ("WWW-Authenticate" in response["headers"]) is (status == 401)
    for operation in operations_of(document).values():
        assert {str(status) for status in by_status} <= set(operation["responses"])
    problem = document["components"]["schemas"]["Problem"]
    assert {"type", "title", "status", "detail", "instance", "code", "kind", "retry", "message", "request_id"} <= set(
        problem["required"]
    )
    assert "idempotency_key" in problem["properties"]


# ------------------------------------------------------------------------------- names that must not exist
@functools.cache
def _published_names() -> dict[str, set[str]]:
    """Every name of the published surface, by what it names."""
    document = openapi()
    names: dict[str, set[str]] = {
        "route segment": set(),
        "tag": set(),
        "type": set(),
        "tool": set(),
        "member": set(),
        "parameter": set(),
        "operation": set(),
    }
    for path, item in document["paths"].items():
        names["route segment"].update(segment for segment in path.split("/") if segment and not segment.startswith("{"))
        names["parameter"].update(segment[1:-1] for segment in path.split("/") if segment.startswith("{"))
        for operation in item.values():
            names["operation"].add(operation["operationId"])
            names["tag"].update(operation.get("tags", []))
            names["parameter"].update(parameter["name"] for parameter in parameters_of(document, operation))
    names["tag"].update(tag["name"] for tag in document.get("tags", []))
    names["type"].update(document["components"]["schemas"])
    names["member"].update(members_of(document["components"]["schemas"]))
    for name, tool in tools().items():
        names["tool"].add(name)
        names["member"].update(members_of(tool["inputSchema"]))
        names["member"].update(members_of(tool["outputSchema"]))
        names["type"].update(tool["inputSchema"].get("$defs", {}))
        names["type"].update(tool["outputSchema"].get("$defs", {}))
    for entry in surface()["operations"]:
        names["operation"].add(entry["method"])
    return names


@pytest.mark.proves("T3-API-01")
@pytest.mark.parametrize("word", UNSPECIFIED)
def test_no_route_type_tool_or_member_is_named_for_a_surface_the_contract_does_not_specify(word: str) -> None:
    """`run` is an experiment's run in the master plan; the public resource for one command is an execution."""
    names = _published_names()
    assert sum(len(found) for found in names.values()) > 250, "the lint must have names to look at"
    for kind in ("route segment", "tag", "type", "tool"):
        named = sorted(name for name in names[kind] if names_a_surface(name, word))
        assert named == [], f"a {kind} is named for `{word}`"
    for operation in names["operation"]:
        assert not names_a_surface(operation.split(".")[0], word), operation
        assert word not in operation.split("."), operation
    for kind in ("member", "parameter"):
        named = sorted(name for name in names[kind] if is_a_reference_to(name, word))
        assert named == ([word] if word in NOT_A_SURFACE else []), f"a {kind} is named for `{word}`"


@pytest.mark.proves("T3-API-01")
def test_the_one_member_named_stream_is_the_output_stream_of_an_execution() -> None:
    """Output streaming is not offered. `stream` names which of stdout and stderr a chunk is read from, and nothing else."""
    document = openapi()
    holders = {
        name for name, schema in document["components"]["schemas"].items() if "stream" in schema.get("properties", {})
    }
    assert holders == {"OutputChunk"}
    with_parameter = {
        operation["operationId"]
        for operation in operations_of(document).values()
        if any(p["name"] == "stream" for p in parameters_of(document, operation))
    }
    assert with_parameter == {"execution.output"}
    for name, tool in tools().items():
        mentions = "stream" in set(members_of(tool["inputSchema"])) | set(members_of(tool["outputSchema"]))
        assert mentions is (name == "exec_output"), name
    assert tools()["exec_output"]["inputSchema"]["properties"]["stream"]["enum"] == ["stdout", "stderr"]
    # No media type of a stream, and no route that streams.
    text = (PROTOCOLS / "api" / "openapi.yaml").read_text(encoding="utf-8")
    assert "text/event-stream" not in text
    assert "itemSchema" not in text


@pytest.mark.proves("T3-API-01")
def test_no_backend_field_is_a_member_of_a_published_schema() -> None:
    backend = {
        "process",
        "security_profile_id",
        "kernel_identity",
        "rootfs_identity",
        "profile_id",
        "tags",
        "peer_id",
        "owner_scope",
        "activation_epoch",
        "issuer",
        "run_id",
        "host_id",
        "lineage",
    }
    names = _published_names()
    assert not names["member"] & backend
    assert not names["parameter"] & backend
    assert not {
        name
        for name in names["type"]
        if any(word in name.lower() for word in ("firecracker", "jail", "vmm", "cgroup", "namespace"))
    }


@pytest.mark.proves("T3-SEC-06", level="L0")
@pytest.mark.proves("T3-API-01")
def test_no_operator_method_of_the_host_is_published_as_anything_a_caller_can_reach() -> None:
    assert {"profile.reload", "quarantine.release", "host.set_mode", "host.acknowledge"} == HOST_OPERATOR_METHODS
    spellings = {
        spelling
        for method in HOST_OPERATOR_METHODS
        for spelling in (method, method.replace(".", "_"), method.replace(".", "-"), method.replace(".", "/"))
    }
    mapping_file = PROTOCOLS / "api" / "mapping" / "acf.host-2.yaml"
    for path in sorted(PROTOCOLS.rglob("*")):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        if path == mapping_file:
            # The list of host methods the platform never calls names them, in order to say so. Without that
            # list each of them is gone from the file: no vocabulary and no public method maps to one.
            table = yaml.safe_load(text)
            assert set(table["never_called"]) >= HOST_OPERATOR_METHODS
            head, _, never_called = text.partition("\nnever_called:\n")
            assert never_called.strip(), "the list of methods that are never called is the last part of the table"
            assert not set(table["methods"].values()) & HOST_OPERATOR_METHODS
            assert not set(table["vocabularies"]["operation_type"]) & HOST_OPERATOR_METHODS
            text = head
        found = sorted(spelling for spelling in spellings if spelling in text)
        assert found == [], f"{path.relative_to(PROTOCOLS).as_posix()} names an operator method of the host"
    published = _published_names()
    for kind in ("operation", "tool", "route segment"):
        assert not {
            name
            for name in published[kind]
            if any(word in name for word in ("reload", "quarantine", "set_mode", "acknowledge", "operator", "admin"))
        }, kind


# ------------------------------------------------------------------------------- the tool catalogue
@pytest.mark.proves("T3-RED-40", "T3-API-01")
def test_the_tool_catalogue_is_the_sixteen_tools_of_the_contract() -> None:
    assert set(tools()) == set(ANNOTATIONS)
    assert len(ANNOTATIONS) == 16
    for name, tool in tools().items():
        assert tool["name"] == name
        assert set(tool) == {
            "name",
            "title",
            "description",
            "inputSchema",
            "outputSchema",
            "annotations",
            "x-acf-method",
            "x-acf-class",
            "x-acf-reversibility",
        }
        assert BY_METHOD[tool["x-acf-method"]][3] == name
    # Minting, listing and revoking an agent credential, the list of operations and whoami are never tools.
    assert {row[0] for row in OPERATION_TABLE if row[3] is None} == {
        "operation.list",
        "agent_credential.mint",
        "agent_credential.list",
        "agent_credential.revoke",
        "auth.whoami",
    }


@pytest.mark.proves("T3-RED-40")
@pytest.mark.parametrize("name", sorted(ANNOTATIONS))
def test_a_tool_name_is_valid_in_the_agent_protocol_and_as_a_tool_name_of_the_model_apis(name: str) -> None:
    assert re.fullmatch(r"^[A-Za-z0-9_-]{1,64}$", name)
    assert re.fullmatch(r"^[a-zA-Z0-9_-]{1,128}$", name)
    assert name == name.lower()
    assert not name.startswith(("_", "-"))
    assert not name.endswith(("_", "-"))


@pytest.mark.proves("T3-RED-40")
@pytest.mark.parametrize("name", sorted(ANNOTATIONS))
def test_the_annotations_of_a_tool_are_the_contracts(name: str) -> None:
    read_only, destructive, idempotent, open_world = ANNOTATIONS[name]
    annotations = tools()[name]["annotations"]
    assert annotations == {
        "title": tools()[name]["title"],
        "readOnlyHint": read_only,
        "destructiveHint": destructive,
        "idempotentHint": idempotent,
        "openWorldHint": open_world,
    }
    listed = next(
        entry
        for entry in json.loads((PROTOCOLS / "mcp" / "catalogue.json").read_text(encoding="utf-8"))["tools"]
        if entry["name"] == name
    )
    assert (
        listed["readOnlyHint"],
        listed["destructiveHint"],
        listed["idempotentHint"],
        listed["openWorldHint"],
    ) == ANNOTATIONS[name]


@pytest.mark.proves("T3-RED-40")
@pytest.mark.parametrize("name", sorted(ANNOTATIONS))
def test_no_annotation_understates_the_worst_case_of_its_tool(name: str) -> None:
    """An annotation is a hint and never a control. A hint that says less than the worst case is a wrong hint."""
    tool = tools()[name]
    method = tool["x-acf-method"]
    hints = tool["annotations"]
    worst = WORST_CLASS.get(method)
    if method == "execution.cancel":
        # The classification names no class for a cancel. It ends an execution for good: treated as the worst.
        worst = "IRREVERSIBLE"
    assert tool["x-acf-reversibility"] == worst
    mutates = worst is not None
    assert (tool["x-acf-class"] in {"granting", "containment"}) is mutates
    if mutates:
        assert hints["readOnlyHint"] is False, "a tool that changes something is not read-only"
    if worst == "IRREVERSIBLE":
        assert hints["destructiveHint"] is True, "what cannot be undone is destructive at worst"
    if method in GRANTING:
        assert hints["idempotentHint"] is False, "a second call is new work"
    if method == "execution.create":
        assert hints["openWorldHint"] is True, "a command in a sandbox with a network reaches outside the sandbox"
    # And nothing is overstated either: the table is the table.
    assert hints["readOnlyHint"] is (not mutates)
    assert hints["idempotentHint"] is (not mutates or method in CONTAINMENT)
    assert hints["destructiveHint"] is (worst == "IRREVERSIBLE")
    assert hints["openWorldHint"] is (method == "execution.create")


def _object_schemas(schema: Any) -> Iterator[dict[str, Any]]:
    if isinstance(schema, dict):
        if "properties" in schema:
            yield schema
        for value in schema.values():
            yield from _object_schemas(value)
    elif isinstance(schema, list):
        for item in schema:
            yield from _object_schemas(item)


@pytest.mark.proves("T3-RED-40", "T3-API-01")
@pytest.mark.parametrize("name", sorted(ANNOTATIONS))
def test_a_tool_has_an_input_and_an_output_schema_in_json_schema_2020_12(name: str) -> None:
    tool = tools()[name]
    for which in ("inputSchema", "outputSchema"):
        schema = tool[which]
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["type"] == "object"
        Draft202012Validator.check_schema(schema)
        for nested in _object_schemas(schema):
            # A member the schema does not define is refused: nothing an agent sends is silently ignored.
            assert nested.get("additionalProperties") is False or "patternProperties" in nested, (
                which,
                nested.get("title"),
            )
    validator = Draft202012Validator(tool["inputSchema"])
    assert not validator.is_valid({"anything_unknown": 1})
    assert not validator.is_valid({"project": "prj_0000000000000001"}), (
        "the project is the credential's, never an argument"
    )
    output = Draft202012Validator(tool["outputSchema"])
    assert output.is_valid({"ok": True})
    assert not output.is_valid({"ok": True, "anything_unknown": 1})
    assert "ok" in tool["outputSchema"]["required"]


@pytest.mark.proves("T3-RED-40")
def test_no_description_sends_an_agent_to_another_tool_by_name() -> None:
    """A handle carries identifiers. A description that named a tool would be wrong wherever tools are renamed or hidden."""
    names = set(ANNOTATIONS)
    for name, tool in tools().items():
        texts = [tool["title"], tool["description"]]

        def descriptions(schema: Any) -> Iterator[str]:
            if isinstance(schema, dict):
                if isinstance(schema.get("description"), str):
                    yield schema["description"]
                for value in schema.values():
                    yield from descriptions(value)
            elif isinstance(schema, list):
                for item in schema:
                    yield from descriptions(item)

        texts += list(descriptions(tool["inputSchema"])) + list(descriptions(tool["outputSchema"]))
        for text in texts:
            mentioned = sorted(
                other for other in names if re.search(rf"(?<![A-Za-z0-9_]){re.escape(other)}(?![A-Za-z0-9_])", text)
            )
            assert mentioned == [], f"{name} names {mentioned}"
            assert "tools/call" not in text
            assert "tools/list" not in text


@pytest.mark.proves("T3-RED-40")
def test_the_descriptions_say_what_an_agent_must_know_and_do_not_ask_it_to_manage_keys() -> None:
    for name, tool in tools().items():
        description = tool["description"]
        if tool["x-acf-class"] in {"granting", "containment"}:
            assert "replayed" in description, name
            assert "UNKNOWN" in description, name
            assert "OUTCOME_LOST" in description, name
            assert "inspect" in description, name
            key = tool["inputSchema"]["properties"]["idempotency_key"]
            assert "idempotency_key" not in tool["inputSchema"].get("required", [])
            assert (
                "Leave this out" in key["anyOf"][0]["description"]
                if "anyOf" in key
                else "Leave this out" in key["description"]
            )
        else:
            assert "idempotency_key" not in tool["inputSchema"]["properties"], name
        assert "idempotency key" not in description.lower(), name
    for name in ("sandbox_exec", "exec_status", "exec_output", "sandbox_list", "sandbox_inspect", "snapshot_list"):
        assert "untrusted" in tools()[name]["description"], name


@pytest.mark.proves("T3-RED-40")
def test_a_tool_that_creates_a_named_record_requires_the_name() -> None:
    """The second fence for creates: the host refuses a second record with the same name in a project."""
    assert "name" in tools()["sandbox_create"]["inputSchema"]["required"]
    assert "name" in tools()["sandbox_snapshot"]["inputSchema"]["required"]
    restore = tools()["sandbox_restore"]["inputSchema"]
    as_new = next(
        schema
        for schema in restore["$defs"].values()
        if schema.get("properties", {}).get("kind", {}).get("const") == "new"
    )
    in_place = next(
        schema
        for schema in restore["$defs"].values()
        if schema.get("properties", {}).get("kind", {}).get("const") == "existing"
    )
    assert "name" in as_new["required"]
    assert "name" not in in_place.get("properties", {})


@pytest.mark.proves("T3-API-01")
def test_the_catalogue_file_lists_each_tool_file_by_its_digest() -> None:
    catalogue = json.loads((PROTOCOLS / "mcp" / "catalogue.json").read_text(encoding="utf-8"))
    assert catalogue["schema_version"] == 1
    assert catalogue["protocol_revision"] == "2026-07-28"
    # In the order of the contract's own table of tools.
    assert [entry["name"] for entry in catalogue["tools"]] == list(ANNOTATIONS)
    for entry in catalogue["tools"]:
        content = (PROTOCOLS / "mcp" / "tools" / f"{entry['name']}.json").read_bytes()
        assert entry["sha256"] == hashlib.sha256(content).hexdigest(), entry["name"]
        tool = json.loads(content)
        assert (entry["method"], entry["class"]) == (tool["x-acf-method"], tool["x-acf-class"])
        assert entry["creates_operation"] is (tool["x-acf-class"] in {"granting", "containment"})


# ------------------------------------------------------------------------------- the conformance suite
#: The scenarios that send, on purpose, what a later server may send and this version has never seen.
FROM_A_LATER_SERVER = {"VER-4", "VER-12"}
VOCABULARIES: dict[str, set[str]] = {
    "operation": {state.value for state in m.OperationState} - {"UNRECOGNIZED"},
    "sandbox": {state.value for state in m.SandboxState} - {"UNRECOGNIZED"},
    "snapshot": {state.value for state in m.SnapshotState} - {"UNRECOGNIZED"},
}


def _route_of(method: str, path: str) -> Any:
    for route in ROUTES:
        pattern = re.sub(r"\{[^/}]+\}", "[^/]+", route.path)
        if route.method == method and re.fullmatch(pattern, path):
            return route
    return None


def _unknown_values(view: type[m.ViewModel], body: Any) -> list[str]:
    """Values of the public vocabularies in a view that this version does not have."""
    found: list[str] = []
    if not isinstance(body, dict):
        return found
    if view is m.Operation:
        if body.get("state") not in VOCABULARIES["operation"]:
            found.append(f"operation state {body.get('state')}")
        result = body.get("result") or {}
        if "sandbox" in result:
            found += _unknown_values(m.Sandbox, result["sandbox"])
        if "execution" in result and result["execution"].get("state") not in VOCABULARIES["operation"]:
            found.append(f"execution state {result['execution'].get('state')}")
    elif view is m.Sandbox:
        if body.get("state") not in VOCABULARIES["sandbox"]:
            found.append(f"sandbox state {body.get('state')}")
    elif view is m.SandboxList:
        for item in body.get("items", []):
            found += _unknown_values(m.Sandbox, item)
    elif view is m.Problem:
        if body.get("code") not in Code.__members__:
            found.append(f"code {body.get('code')}")
        if body.get("kind") not in {kind.value for kind in Kind} or body.get("retry") not in {
            retry.value for retry in Retry
        }:
            found.append("kind or retry")
    return found


def _judge(exchange: dict[str, Any]) -> tuple[type[m.ViewModel], Any, list[str]]:
    """The model a response claims to be, its body, and everything about it this version would not send."""
    request, response = exchange["request"], exchange["response"]
    route = _route_of(request["method"], request["path"])
    assert route is not None, (request["method"], request["path"])
    is_problem = response["status"] >= 400
    view: type[m.ViewModel] = m.Problem if is_problem else route.view
    body = response["json"]
    faults: list[str] = []
    try:
        view.model_validate(body)
    except ValidationError as e:
        faults += [f"{'.'.join(map(str, error['loc']))}: {error['type']}" for error in e.errors()]
    faults += _unknown_values(view, body)
    return view, body, faults


@pytest.mark.proves("T3-API-01")
def test_the_conformance_suite_is_described_as_the_contract_describes_it() -> None:
    suite = scenarios()
    assert suite["schema_version"] == 1
    ids = [scenario["id"] for scenario in suite["scenarios"]]
    assert len(ids) == len(set(ids)) == 27
    assert all(re.fullmatch(r"cp-\d{3}-[a-z0-9-]+", scenario_id) for scenario_id in ids)
    for scenario in suite["scenarios"]:
        assert set(scenario) <= {"id", "title", "rules", "call", "config", "exchanges", "expect"}
        assert scenario["rules"]
        assert scenario["exchanges"]
        assert scenario["expect"]["outcome"] in {"success", "error"}
    # No scenario teaches a client a key in the documented form of a real one.
    assert "acf1_dev_conformance" in json.dumps(suite["defaults"])


@pytest.mark.proves("T3-API-01")
def test_every_answer_of_the_conformance_suite_is_an_answer_the_public_model_can_give() -> None:
    """Except where a scenario says, by its rules, that it sends what a later server may send."""
    judged = 0
    deliberate: dict[str, list[str]] = {}
    for scenario in scenarios()["scenarios"]:
        later = bool(FROM_A_LATER_SERVER & set(scenario["rules"]))
        for exchange in scenario["exchanges"]:
            if "fault" in exchange["response"]:
                assert exchange["response"]["fault"] in {"connection_reset", "timeout"}
                continue
            _view, _body, faults = _judge(exchange)
            judged += 1
            if later:
                deliberate.setdefault(scenario["id"], []).extend(faults)
            else:
                assert faults == [], (scenario["id"], faults)
    assert judged >= 40
    # Each of those scenarios does send something this version would not: the exception is used, not just claimed.
    assert sorted(deliberate) == [
        "cp-018-a-state-never-seen-is-not-terminal",
        "cp-021-unknown-members-and-values-are-tolerated",
        "cp-022-an-unknown-code-is-handled-by-kind-and-retry",
        "cp-023-an-unknown-code-that-says-later-is-retried",
    ]
    assert deliberate["cp-018-a-state-never-seen-is-not-terminal"] == ["operation state AWAITING_PLACEMENT"]
    assert sorted(deliberate["cp-021-unknown-members-and-values-are-tolerated"]) == [
        "placement: extra_forbidden",
        "sandbox state HIBERNATED",
    ]
    assert deliberate["cp-022-an-unknown-code-is-handled-by-kind-and-retry"] == ["code FUTURE_REFUSAL"]
    assert deliberate["cp-023-an-unknown-code-that-says-later-is-retried"] == ["code FUTURE_REFUSAL"]


@pytest.mark.proves("T3-API-01")
def test_every_request_of_the_conformance_suite_is_a_request_the_api_accepts() -> None:
    document = openapi()
    published = operations_of(document)
    for scenario in scenarios()["scenarios"]:
        for exchange in scenario["exchanges"]:
            request = exchange["request"]
            route = _route_of(request["method"], request["path"])
            assert route is not None, (scenario["id"], request["method"], request["path"])
            headers = {name.lower(): value for name, value in request.get("headers", {}).items()}
            assert ("idempotency-key" in headers) is route.operation.keyed, scenario["id"]
            if route.body is not None:
                route.body.model_validate_json(json.dumps(request["json"]))
            else:
                assert "json" not in request, scenario["id"]
            allowed = {
                parameter["name"]
                for parameter in parameters_of(document, published[(route.method, route.path)])
                if parameter["in"] == "query"
            }
            assert set(request.get("query", {})) <= allowed, scenario["id"]


@pytest.mark.proves("T3-API-01", "T3-ERR-01")
def test_every_problem_of_the_conformance_suite_has_the_status_and_the_headers_of_its_code() -> None:
    seen = set()
    for scenario in scenarios()["scenarios"]:
        for exchange in scenario["exchanges"]:
            response = exchange["response"]
            if "fault" in response:
                continue
            headers = {name.lower(): value for name, value in response.get("headers", {}).items()}
            assert headers["x-request-id"].startswith("req_")
            if response["status"] >= 400:
                body = response["json"]
                seen.add(body["code"])
                assert headers["content-type"] == "application/problem+json"
                assert body["status"] == response["status"]
                assert body["type"] == "urn:acf:problem:" + body["code"].lower().replace("_", "-")
                if body["code"] in Code.__members__:
                    info = CODES[Code(body["code"])]
                    assert (response["status"], body["kind"], body["retry"]) == (
                        info.http_status,
                        info.kind.value if info.kind else None,
                        info.retry.value,
                    )
                    if info.kind is Kind.UNRESOLVED:
                        assert body["idempotency_key"], "an unresolved answer names the key to ask again with"
                if "retry-after" in headers:
                    assert body["retry"] == "SAME_REQUEST_LATER"
            elif response["status"] == 202:
                assert {"location", "retry-after"} <= set(headers)
                assert response["json"]["terminal"] is False
            else:
                assert response["status"] in {200, 201}
    assert {
        "OUTCOME_UNRESOLVED",
        "OUTCOME_LOST",
        "REQUEST_IN_PROGRESS",
        "STATE_CONFLICT",
        "RATE_LIMITED",
        "PERMISSION_DENIED",
        "IDEMPOTENCY_CONFLICT",
        "CURSOR_EXPIRED",
        "NOT_FOUND",
        "UPSTREAM_UNAVAILABLE",
    } <= seen
