"""From the host's views to the public model, through the mapping table.

Proves PUB-2 (the public vocabularies correspond to the host's through a table, value by value, and
not through an identity assumed in code), PUB-3 (no backend type, mechanism name or host-internal field
crosses the public surface; the image is shown by alias and identity digest), PUB-4 (every field of an
execution result keeps its provenance label), PUB-6 (a host value the table does not hold is shown as
`UNRECOGNIZED` with the raw value beside it, is never mapped onto a known value, and an operation in
such a state is neither terminal nor successful) and PUB-7 (public identifiers, revision validators and
list cursors are derived one-to-one from the host's values and carry no host name and no project).
Catalog entry: the mapping-table part of T3-API-01.

The host's side is read from the host's own contract and from answers recorded from the test host, so
a value the host adds is noticed here before the platform shows it as something it is not.
"""

from __future__ import annotations

import ast
import base64
import copy
import enum
import inspect
import json
import re
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml
from hypothesis import given
from hypothesis import strategies as st

from acf_api.command import commands as c
from acf_api.command import model as m
from acf_api.command.errors import CODES, Code, Retry
from acf_api.command.surface import HOST_OPERATOR_METHODS, HOST_PROTOCOLS, OPERATIONS
from acf_api.core.pipeline import mapping
from acf_api.core.pipeline.mapping import MappingError, MappingTable

REPO = Path(__file__).resolve().parents[3]
HOST_API: dict[str, Any] = json.loads((REPO / "execution" / "contracts" / "host-api.json").read_text(encoding="utf-8"))
RECORDED: dict[str, Any] = json.loads(
    (REPO / "apps" / "host-cli" / "tests" / "data" / "recorded_answers.json").read_text(encoding="utf-8")
)
PACKAGED = REPO / "apps" / "api" / "src" / "acf_api" / "core" / "host" / "data" / "mapping.acf.host-2.yaml"
PUBLISHED = REPO / "protocols" / "api" / "mapping" / "acf.host-2.yaml"

TABLE = mapping.load_table()
PROJECT = "prj_0000000000000001"
LINEAGE = "ba2fe3e6f5862194fe3c2cc68af6ff60"
OTHER_LINEAGE = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
UNRECOGNIZED = "UNRECOGNIZED"
FUTURE = "A_VALUE_FROM_A_LATER_HOST"

#: Members of the host's views that describe the host or its backend. None may appear in a public view.
BACKEND_FIELDS = {
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
}
#: Further names of the host's views that the public model does not use, each for the same reason.
HOST_ONLY_FIELDS = BACKEND_FIELDS | {
    "architecture",
    "manifest_version",
    "provenance_reference",
    "secret_bearing",
    "manifest_digest",
    "secret_refs",
    "step",
    "guest_containment",
    "resource_evidence",
    "artifacts",
    "image_id",
    "run_id",
    "last_run",
    "on_behalf_of",
    "data_b64",
    "kept_bytes",
    "total_bytes",
    "metrics",
    "guest_duration_ms",
    "operation_type",
}


# ------------------------------------------------------------------------------- the table itself
@pytest.mark.proves("T3-API-01")
def test_the_mapping_table_loads_and_names_the_host_protocol_it_is_for() -> None:
    assert TABLE.host_protocol == "acf.host/2" == HOST_API["protocol"]
    assert TABLE.host_protocol in HOST_PROTOCOLS
    assert set(TABLE.vocabularies) == {
        "sandbox_state",
        "operation_state",
        "effect",
        "cleanup",
        "cancelled_by",
        "execution_status",
        "snapshot_state",
        "output_completeness",
        "evidence_status",
        "side_effect",
        "network_mode",
        "issuer",
        "operation_type",
        "failure_class",
    }
    assert mapping.parse_table(yaml.safe_load(PACKAGED.read_text(encoding="utf-8"))) == TABLE


@pytest.mark.proves("T3-API-01")
def test_the_published_copy_of_the_table_is_the_table_the_core_loads() -> None:
    """The table is a contract artifact. What is published is, byte for byte, what decides."""
    assert PUBLISHED.read_bytes() == PACKAGED.read_bytes()


@pytest.mark.proves("T3-API-01")
@pytest.mark.parametrize(
    "damage",
    [
        lambda t: t.update(schema_version=2),
        lambda t: t.pop("schema_version"),
        lambda t: t.pop("vocabularies"),
        lambda t: t.pop("methods"),
        lambda t: t.pop("never_called"),
        lambda t: t.pop("platform_faults"),
        lambda t: t.pop("handled_by_rule"),
        lambda t: t.pop("retry_advice"),
        lambda t: t.update(vocabularies=["sandbox_state"]),
        lambda t: t.update(vocabularies={"sandbox_state": ["READY"]}),
        lambda t: t.update(methods=None),
        lambda t: t.update(platform_faults=None),
    ],
)
def test_a_table_in_another_form_is_not_used(damage: Callable[[dict[str, Any]], Any]) -> None:
    data = yaml.safe_load(PACKAGED.read_text(encoding="utf-8"))
    damage(data)
    with pytest.raises(MappingError):
        mapping.parse_table(data)
    not_tables: tuple[object, ...] = (None, [], "schema_version: 1", 1)
    for not_a_table in not_tables:
        with pytest.raises(MappingError):
            mapping.parse_table(not_a_table)


# ------------------------------------------------------------------------------- every vocabulary of the host
def _values(schema: dict[str, Any]) -> list[str] | None:
    """The values of a definition of the host contract that is an enumeration of strings, else ``None``."""
    if "enum" in schema:
        return list(schema["enum"])
    alternatives = schema.get("oneOf") or schema.get("anyOf")
    if not alternatives:
        return None
    values: list[str] = []
    for alternative in alternatives:
        if "const" in alternative and isinstance(alternative["const"], str):
            values.append(alternative["const"])
        elif "enum" in alternative:
            values.extend(alternative["enum"])
        else:
            return None
    return values


HOST_ENUMERATIONS = {
    name: values for name, schema in HOST_API["$defs"].items() if (values := _values(schema)) is not None
}

#: Every enumeration of the host contract, and the table vocabulary that maps it.
MAPPED = {
    "LifecycleState": "sandbox_state",
    "OperationState": "operation_state",
    "Effect": "effect",
    "Cleanup": "cleanup",
    "CancelledBy": "cancelled_by",
    "RunStatus": "execution_status",
    "SnapshotState": "snapshot_state",
    "OutputStatus": "output_completeness",
    "EvidenceStatus": "evidence_status",
    "SideEffect": "side_effect",
    "NetworkMode": "network_mode",
    "Issuer": "issuer",
}
#: Enumerations the table holds in more than one place, each with a test of its own below.
MAPPED_IN_PARTS = {"OperationType", "FailureClass"}
#: Enumerations that do not cross the public surface at all, and why.
NOT_PUBLIC = {
    "HostMode": "the state of the host as a whole is shown to no caller",
    "ArtifactKind": "artifacts are not part of the public model",
    "RequestedMode": "a parameter of an operator method the platform never calls",
    "ReleaseMode": "a parameter of an operator method the platform never calls",
    "AckCondition": "a parameter of an operator method the platform never calls",
}
#: Enumerations that cross without the table: the public vocabulary has the same words, and a test says so.
SAME_WORDS = {
    "RetryAdvice": {retry.value for retry in Retry},
    "OutputStream": {stream.value for stream in m.OutputStream},
}
#: The public vocabulary each table vocabulary maps into.
PUBLIC: dict[str, type[enum.Enum]] = {
    "sandbox_state": m.SandboxState,
    "operation_state": m.OperationState,
    "effect": m.Effect,
    "cleanup": m.Cleanup,
    "cancelled_by": m.CancelledBy,
    "execution_status": m.ExecutionStatus,
    "snapshot_state": m.SnapshotState,
    "output_completeness": m.OutputCompleteness,
    "evidence_status": m.EvidenceStatus,
    "side_effect": m.SideEffect,
    "network_mode": m.NetworkMode,
    "issuer": m.InitiatedBy,
}
#: The words the platform changes on purpose. Everything else has the host's word.
RENAMED = {
    ("issuer", "PEER"): "CALLER",
    ("operation_type", "exec.run"): "execution.create",
    ("operation_type", "operation.cancel"): "execution.cancel",
}


@pytest.mark.proves("T3-API-01")
def test_every_enumeration_of_the_host_contract_is_accounted_for() -> None:
    """A vocabulary the host adds is mapped, or said to stay inside, before the platform meets a value of it."""
    accounted = set(MAPPED) | MAPPED_IN_PARTS | set(NOT_PUBLIC) | set(SAME_WORDS)
    assert set(HOST_ENUMERATIONS) == accounted
    assert len(HOST_ENUMERATIONS) == 21
    # The lists the host contract states at its top are the same vocabularies, not further ones.
    assert HOST_API["lifecycle_states"] == HOST_ENUMERATIONS["LifecycleState"]
    assert HOST_API["operation_states"] == HOST_ENUMERATIONS["OperationState"]
    assert HOST_API["operation_types"] == HOST_ENUMERATIONS["OperationType"]
    assert HOST_API["host_modes"] == HOST_ENUMERATIONS["HostMode"]
    assert [entry["class"] for entry in HOST_API["failure_classes"]] == HOST_ENUMERATIONS["FailureClass"]


@pytest.mark.proves("T3-API-01")
@pytest.mark.parametrize(("definition", "vocabulary"), sorted(MAPPED.items()))
def test_every_value_of_a_host_vocabulary_is_in_the_table_and_nothing_else_is(definition: str, vocabulary: str) -> None:
    host_values = HOST_ENUMERATIONS[definition]
    table = TABLE.vocabularies[vocabulary]
    assert set(table) == set(host_values), (
        "a host value is not mapped, or the table maps a value the host does not have"
    )
    public = {member.value for member in PUBLIC[vocabulary]} - {UNRECOGNIZED}
    assert set(table.values()) == public, (
        "a public value has no host value, or the table names a value the model does not have"
    )
    for host_value, public_value in table.items():
        # In this version each public value is the host's word, except where the platform chose its own.
        assert public_value == RENAMED.get((vocabulary, host_value), host_value)
        assert TABLE.value(vocabulary, host_value) == (public_value, None)
    assert len(set(table.values())) == len(table), "two host values are shown as one"


@pytest.mark.proves("T3-API-01")
@pytest.mark.parametrize(("definition", "words"), sorted(SAME_WORDS.items()))
def test_a_vocabulary_that_crosses_without_the_table_has_the_same_words_on_both_sides(
    definition: str, words: set[str]
) -> None:
    assert set(HOST_ENUMERATIONS[definition]) == words
    assert set(TABLE.retry_advice.values()) <= {retry.value for retry in Retry}


@pytest.mark.proves("T3-API-01")
def test_every_operation_type_of_the_host_is_shown_under_a_public_method_or_never_met() -> None:
    table = TABLE.vocabularies["operation_type"]
    host_types = set(HOST_ENUMERATIONS["OperationType"])
    operator_types = host_types - set(table)
    assert operator_types == HOST_OPERATOR_METHODS, "an operation type is neither mapped nor an operator method"
    assert operator_types <= TABLE.never_called
    assert set(table) <= host_types
    public_methods = {op.method for op in OPERATIONS}
    for host_type, public_type in table.items():
        assert public_type == RENAMED.get(("operation_type", host_type), host_type)
        # `sandbox.fail` is the host acting by itself: an operation a caller can see and never ask for.
        assert public_type in public_methods or host_type == "sandbox.fail", host_type
        assert public_type not in {"exec.run", "operation.cancel", "run.inspect", "run.output"}
    assert len(set(table.values())) == len(table)


@pytest.mark.proves("T3-API-01", "T3-ERR-01")
def test_every_failure_class_of_the_host_is_in_exactly_one_part_of_the_table() -> None:
    host = {entry["class"]: entry for entry in HOST_API["failure_classes"]}
    kept, faults, by_rule = (
        set(TABLE.vocabularies["failure_class"]),
        set(TABLE.platform_faults),
        set(TABLE.handled_by_rule),
    )
    assert kept | faults | by_rule == set(host)
    assert not kept & faults
    assert not kept & by_rule
    assert not faults & by_rule
    assert faults == {"AUTHENTICATION_FAILED", "AUTHORIZATION_DENIED", "PROTOCOL_ERROR"}
    assert TABLE.handled_by_rule == {
        "EXPIRED_REQUEST": "clock-offset",
        "IDEMPOTENCY_CONFLICT": "conflict-proves-existence",
    }
    for host_class, public_code in TABLE.vocabularies["failure_class"].items():
        # A class the host decides keeps the host's name: the platform maps none onto another.
        assert public_code == host_class
        assert CODES[Code(public_code)].decided_by in {"host", "either"}
        assert TABLE.retry_for(host_class) == host[host_class]["retry"] == CODES[Code(public_code)].retry.value
    assert set(TABLE.retry_advice) == kept
    # Every class that can end an operation and has a public name is shown under it.
    ends_operations = {name for name, entry in host.items() if entry["may_fail_operation"]}
    assert ends_operations - kept == {"PROTOCOL_ERROR"}


@pytest.mark.proves("T3-API-01", "T3-SEC-06")
def test_every_method_of_the_host_is_called_for_a_public_method_or_never_called() -> None:
    host_methods = {entry["name"]: entry for entry in HOST_API["methods"]}
    called = set(TABLE.methods.values())
    assert called | TABLE.never_called == set(host_methods)
    assert not called & TABLE.never_called
    operator_only = {name for name, entry in host_methods.items() if entry["roles"] == ["operator"]}
    assert operator_only == HOST_OPERATOR_METHODS
    assert operator_only <= TABLE.never_called
    assert TABLE.never_called - operator_only == {"host.metrics"}
    public = {op.method: op for op in OPERATIONS}
    assert set(TABLE.methods) <= set(public)
    for method, host_method in TABLE.methods.items():
        assert "operator" not in host_methods[host_method]["class"]
        assert "caller" in host_methods[host_method]["roles"], (
            "the platform is enrolled as a caller and as nothing more"
        )
        if public[method].host_method is not None:
            assert public[method].host_method == host_method
    # A public method that reaches the host is in the table, and one that does not is not.
    assert {method for method, op in public.items() if op.host_method is not None} <= set(TABLE.methods)
    assert not {method for method in TABLE.methods if method.startswith(("agent_credential.", "auth."))}


# ------------------------------------------------------------------------------- a value the table does not hold
vocabularies = st.sampled_from(sorted(TABLE.vocabularies))


@pytest.mark.proves("T3-API-01")
@given(vocabularies, st.text(max_size=100))
def test_a_value_the_table_does_not_hold_is_unrecognized_and_never_a_known_value(
    vocabulary: str, host_value: str
) -> None:
    shown, raw = TABLE.value(vocabulary, host_value)
    if host_value in TABLE.vocabularies[vocabulary]:
        assert (shown, raw) == (TABLE.vocabularies[vocabulary][host_value], None)
    else:
        assert shown == UNRECOGNIZED
        assert raw == host_value[:64]


@pytest.mark.proves("T3-API-01")
@pytest.mark.parametrize("vocabulary", sorted(TABLE.vocabularies))
def test_near_misses_of_a_known_value_are_not_that_value(vocabulary: str) -> None:
    for known in TABLE.vocabularies[vocabulary]:
        for near in (
            known.lower(),
            known.upper(),
            known + " ",
            " " + known,
            known + "\n",
            known + "_",
            known[:-1],
            known.title(),
        ):
            if near in TABLE.vocabularies[vocabulary]:
                continue
            assert TABLE.value(vocabulary, near) == (UNRECOGNIZED, near[:64]), near


@pytest.mark.proves("T3-API-01")
@pytest.mark.parametrize("not_text", [None, 1, 0, True, 1.5, [], ["READY"], {}, {"state": "READY"}])
def test_something_that_is_not_text_where_a_value_belongs_is_unrecognized(not_text: Any) -> None:
    for vocabulary in TABLE.vocabularies:
        shown, raw = TABLE.value(vocabulary, not_text)
        assert shown == UNRECOGNIZED
        assert raw == (None if not_text is None else str(not_text)[:64])


@pytest.mark.proves("T3-API-01")
def test_the_raw_value_beside_an_unrecognized_one_is_bounded() -> None:
    shown, raw = TABLE.value("operation_state", "X" * 10_000)
    assert shown == UNRECOGNIZED
    assert raw == "X" * 64
    assert TABLE.value("operation_state", {"k": "v" * 10_000})[1] == str({"k": "v" * 10_000})[:64]


@pytest.mark.proves("T3-API-01")
def test_only_the_four_states_in_which_an_operation_has_ended_are_terminal() -> None:
    assert {state.value for state in m.TERMINAL_OPERATION_STATES} == {"SUCCEEDED", "FAILED", "CANCELLED", "UNKNOWN"}
    for host_state in HOST_ENUMERATIONS["OperationState"]:
        assert m.is_terminal(TABLE.value("operation_state", host_state)[0]) is (
            host_state in {"SUCCEEDED", "FAILED", "CANCELLED", "UNKNOWN"}
        )
    for unknown in (UNRECOGNIZED, FUTURE, "", "succeeded", "SUCCEEDED ", "DONE", "COMPLETED"):
        assert m.is_terminal(unknown) is False


# ------------------------------------------------------------------------------- recorded answers of the host
def _recorded() -> dict[str, list[dict[str, Any]]]:
    """Every view in the answers recorded from the test host, by kind."""
    found: dict[str, list[dict[str, Any]]] = {"sandbox": [], "snapshot": [], "operation": [], "run": [], "output": []}

    def operation(view: dict[str, Any]) -> None:
        found["operation"].append(view)
        result = view.get("result")
        if isinstance(result, dict) and result.get("type") in {"sandbox", "snapshot", "run"}:
            found[result["type"]].append(result["data"])

    for exchange in RECORDED["exchanges"]:
        response = exchange["response"]
        if response["answer"] == "OPERATION":
            operation(response["operation"])
        elif response["answer"] == "RESULT":
            kind, data = response["result"]["type"], response["result"]["data"]
            if kind in {"sandbox", "run", "output"}:
                found[kind].append(data)
            elif kind == "operation":
                operation(data)
            elif kind in {"sandboxes", "snapshots"}:
                found[{"sandboxes": "sandbox", "snapshots": "snapshot"}[kind]].extend(data["items"])
            elif kind == "operations":
                for item in data["items"]:
                    operation(item)
    return found


RECORDED_VIEWS = _recorded()
SANDBOX: dict[str, Any] = RECORDED_VIEWS["sandbox"][0]
SNAPSHOT: dict[str, Any] = RECORDED_VIEWS["snapshot"][0]
RUN: dict[str, Any] = RECORDED_VIEWS["run"][0]
CHUNK: dict[str, Any] = RECORDED_VIEWS["output"][0]
OPERATION: dict[str, Any] = next(
    view for view in RECORDED_VIEWS["operation"] if view["operation_type"] == "sandbox.create"
)
FAILED_OPERATION: dict[str, Any] = next(view for view in RECORDED_VIEWS["operation"] if view["state"] == "FAILED")
#: No recorded operation was cancelled. This one is the failed one with the two members a cancellation sets.
CANCELLED_OPERATION: dict[str, Any] = {**FAILED_OPERATION, "state": "CANCELLED", "cancelled_by": "CALLER"}

#: What a public view may be made of. Every other member of a host view is poisoned before it is mapped.
SHOWN = {
    "sandbox": {
        "sandbox_id",
        "generation",
        "name",
        "state",
        "resources",
        "image",
        "expires_at",
        "last_run",
        "source_snapshot",
        "failure",
        "quarantined",
        "notes",
        "updated",
        "revision",
    },
    "image": {"image_id", "alias"},
    "snapshot": {
        "snapshot",
        "name",
        "state",
        "size_bytes",
        "source_sandbox",
        "restore_count",
        "incompatible",
        "created",
        "failure",
        "revision",
    },
    "operation": {
        "operation_id",
        "operation_type",
        "state",
        "effect",
        "cleanup",
        "cancelled_by",
        "issuer",
        "on_behalf_of",
        "failure",
        "result",
        "run_id",
        "sandbox",
        "snapshot",
        "created",
        "updated",
    },
    "run": {
        "run_id",
        "operation_id",
        "sandbox_id",
        "generation",
        "status",
        "exit_code",
        "signal",
        "stdout",
        "stderr",
        "guest_duration_ms",
        "host_backstop_fired",
        "runtime_ended",
        "metrics",
        "evidence_status",
        "note",
    },
    "capture": {"status", "total_bytes", "kept_bytes"},
    "metrics": {"wall_ms"},
}
POISON_TEXT, POISON_NUMBER = "POISON", 987_654_321


def _poison(value: Any, label: str) -> Any:
    """A value of the same shape that would be recognized anywhere it surfaced."""
    if isinstance(value, dict):
        return {key: _poison(item, f"{label}.{key}") for key, item in value.items()} or {
            "poison": f"{POISON_TEXT}:{label}"
        }
    if isinstance(value, list):
        return [_poison(item, label) for item in value] or [f"{POISON_TEXT}:{label}"]
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return POISON_NUMBER
    return f"{POISON_TEXT}:{label}"


def _keep(view: dict[str, Any], kind: str) -> dict[str, Any]:
    return {key: (copy.deepcopy(value) if key in SHOWN[kind] else _poison(value, key)) for key, value in view.items()}


def poisoned(view: dict[str, Any], kind: str) -> dict[str, Any]:
    """``view`` with every member the public model has no use for replaced by poison, at every depth."""
    out = _keep(view, kind)
    if kind == "sandbox":
        out["image"] = _keep(view["image"], "image")
        # A process identity is what a host would least want to show. The recorded view may hold none.
        out["process"] = {"boot_id": f"{POISON_TEXT}:boot", "pid": POISON_NUMBER, "start_time_ticks": POISON_NUMBER}
    elif kind == "run":
        out["stdout"], out["stderr"] = _keep(view["stdout"], "capture"), _keep(view["stderr"], "capture")
        out["metrics"] = _keep(view["metrics"], "metrics")
    elif kind == "operation":
        result = view.get("result")
        if isinstance(result, dict):
            inner = result["type"]
            data = (
                poisoned(result["data"], inner)
                if inner in {"sandbox", "snapshot", "run"}
                else _poison(result["data"], "result")
            )
            out["result"] = {"type": inner, "data": data}
    return out


def _members(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _members(item)
    elif isinstance(value, list):
        for item in value:
            yield from _members(item)


def assert_public(view: m.ViewModel) -> dict[str, Any]:
    """A rendered view holds no member of the host's that is internal, and nothing that was poisoned."""
    body = view.model_dump(mode="json", by_alias=True, exclude_none=True)
    text = json.dumps(body)
    assert not set(_members(body)) & HOST_ONLY_FIELDS, sorted(set(_members(body)) & HOST_ONLY_FIELDS)
    assert POISON_TEXT not in text
    assert str(POISON_NUMBER) not in text
    # The host's own prefix of an execution and the host's own names of methods are not public words.
    assert "run-" not in text
    for host_word in ("exec.run", "run.inspect", "run.output", "operation.cancel", "local-operator", "fake-profile"):
        assert host_word not in text, host_word
    # What was rendered is a view of the public model, member for member.
    assert type(view).model_validate(body).model_dump(mode="json", by_alias=True, exclude_none=True) == body
    return body


@pytest.mark.proves("T3-API-01")
def test_the_recorded_answers_hold_enough_of_every_kind_of_view() -> None:
    counts = {kind: len(views) for kind, views in RECORDED_VIEWS.items()}
    for kind, at_least in (("sandbox", 10), ("snapshot", 3), ("operation", 12), ("run", 3), ("output", 1)):
        assert counts[kind] >= at_least, counts
    assert RECORDED["protocol"] == TABLE.host_protocol
    assert any(view.get("process") for view in RECORDED_VIEWS["sandbox"])
    assert any(view["resources"]["network"]["mode"] == "allowlist" for view in RECORDED_VIEWS["sandbox"])
    assert any(view.get("failure") for view in RECORDED_VIEWS["operation"])
    # The poison reaches the members the contract names: each of them is in a recorded view.
    seen = {member for views in RECORDED_VIEWS.values() for view in views for member in _members(view)}
    assert seen >= BACKEND_FIELDS


@pytest.mark.proves("T3-API-01")
@pytest.mark.parametrize("index", range(len(RECORDED_VIEWS["sandbox"])))
def test_a_sandbox_view_shows_no_backend_field(index: int) -> None:
    host = RECORDED_VIEWS["sandbox"][index]
    body = assert_public(mapping.sandbox(TABLE, poisoned(host, "sandbox"), PROJECT, LINEAGE))
    assert body["sandbox_id"] == host["sandbox_id"]
    assert body["project"] == PROJECT
    assert body["state"] == host["state"]
    assert "state_raw" not in body
    assert body["generation"] == host["generation"]
    # The image is shown by alias and identity digest, and by nothing else.
    assert body["image"] == {"alias": host["image"]["alias"], "digest": host["image"]["image_id"]}
    assert body["resources"] == {key: host["resources"][key] for key in ("vcpus", "memory_mib", "disk_mib")}
    assert body["network"]["mode"] == host["resources"]["network"]["mode"]
    assert len(body["network"].get("entries", [])) == len(host["resources"]["network"].get("entries", []))
    assert body["revision"] == mapping.revision(host["revision"], LINEAGE)
    assert body["expires_at"] == host["expires_at"]
    assert body["updated_at"] == host["updated"]
    assert body.get("last_execution") == (None if host["last_run"] is None else "exe-" + host["last_run"][4:])


@pytest.mark.proves("T3-API-01")
@pytest.mark.parametrize("index", range(len(RECORDED_VIEWS["snapshot"])))
def test_a_snapshot_view_shows_no_backend_field(index: int) -> None:
    host = RECORDED_VIEWS["snapshot"][index]
    body = assert_public(mapping.snapshot(TABLE, poisoned(host, "snapshot"), PROJECT, LINEAGE))
    assert (body["snapshot_id"], body["snapshot_generation"]) == (
        host["snapshot"]["snapshot_id"],
        host["snapshot"]["snapshot_generation"],
    )
    assert body["state"] == host["state"]
    assert body["size_bytes"] == host["size_bytes"]
    assert body["created_at"] == host["created"]
    if host.get("source_sandbox"):
        assert body["source_sandbox"] == {
            "sandbox_id": host["source_sandbox"][0],
            "generation": host["source_sandbox"][1],
        }


@pytest.mark.proves("T3-API-01")
@pytest.mark.parametrize("index", range(len(RECORDED_VIEWS["run"])))
def test_an_execution_shows_no_backend_field_and_labels_what_it_shows(index: int) -> None:
    host = RECORDED_VIEWS["run"][index]
    body = assert_public(mapping.execution_from_run(TABLE, poisoned(host, "run"), PROJECT))
    assert body["execution_id"] == "exe-" + host["run_id"][4:]
    assert body["operation_id"] == host["operation_id"]
    assert body["status"] == host["status"]
    assert body.get("exit_code") == host["exit_code"]
    assert body["stdout"] == {
        "stored_bytes": host["stdout"]["kept_bytes"],
        "produced_bytes": host["stdout"]["total_bytes"],
        "completeness": host["stdout"]["status"],
    }
    assert body["durations"] == {"guest_ms": host["guest_duration_ms"], "wall_ms": host["metrics"]["wall_ms"]}
    # The output itself is never part of an execution view: it is read as a chunk, for one response.
    assert host["stdout"]["data_b64"] == "" or host["stdout"]["data_b64"] not in json.dumps(body)
    assert body["provenance"] == mapping.EXECUTION_PROVENANCE


@pytest.mark.proves("T3-API-01")
@pytest.mark.parametrize("index", range(len(RECORDED_VIEWS["operation"])))
def test_an_operation_view_shows_no_backend_field(index: int) -> None:
    host = RECORDED_VIEWS["operation"][index]
    if host["operation_type"] in HOST_OPERATOR_METHODS:
        # An operator's operation, recorded by the host's own client. The platform never asks for one; if it
        # met one, the type would be shown as unrecognized and nothing of the operator's would be.
        body = assert_public(mapping.operation(TABLE, poisoned(host, "operation"), PROJECT, LINEAGE))
        assert (body["type"], body["type_raw"]) == (UNRECOGNIZED, host["operation_type"])
        return
    body = assert_public(
        mapping.operation(TABLE, poisoned(host, "operation"), PROJECT, LINEAGE, replayed=True, key_digest="ab" * 32)
    )
    assert body["operation_id"] == host["operation_id"]
    assert body["type"] == TABLE.vocabularies["operation_type"][host["operation_type"]]
    assert body["state"] == host["state"]
    assert body["terminal"] is (host["state"] in {"SUCCEEDED", "FAILED", "CANCELLED", "UNKNOWN"})
    assert body["initiated_by"] == {"PEER": "CALLER", "HOST": "HOST"}[host["issuer"]]
    assert body.get("effect") == host["effect"]
    assert body.get("cleanup") == host["cleanup"]
    assert body["replayed"] is True
    assert body["recorded"] is False
    assert body["idempotency_key_digest"] == "ab" * 32
    assert (body["created_at"], body["updated_at"]) == (host["created"], host["updated"])
    if host["sandbox"]:
        assert (body["target"]["sandbox_id"], body["target"]["generation"]) == tuple(host["sandbox"])
    if host["run_id"]:
        assert body["target"]["execution_id"] == "exe-" + host["run_id"][4:]
    result = host["result"]
    if result and result["type"] in {"sandbox", "snapshot", "run"}:
        assert set(body["result"]) == {
            {"sandbox": "sandbox", "snapshot": "snapshot", "run": "execution"}[result["type"]]
        }
    else:
        assert "result" not in body


@pytest.mark.proves("T3-API-01")
def test_an_output_chunk_shows_the_bytes_and_where_they_are_in_the_stream() -> None:
    public_id = "exe-" + CHUNK["run_id"][4:]
    body = assert_public(mapping.output_chunk(TABLE, CHUNK, public_id, 4))
    assert body == {
        "execution_id": public_id,
        "stream": "stdout",
        "offset": 0,
        "data_base64": CHUNK["data_b64"],
        "next_offset": 4,
        "eof": False,
        "stored_bytes": 19,
        "produced_bytes": 19,
        "completeness": "COMPLETE",
        "provenance": "GUEST_REPORTED",
    }


@pytest.mark.proves("T3-API-01")
def test_no_view_of_the_public_model_has_a_member_with_a_backend_name() -> None:
    """The same claim without a sample: whatever the host sends, the model has no member to put it in."""

    def subclasses(cls: type[m.ViewModel]) -> set[type[m.ViewModel]]:
        return {cls} | {found for sub in cls.__subclasses__() for found in subclasses(sub)}

    views = subclasses(m.ViewModel) - {m.ViewModel}
    assert len(views) >= 25
    for view in views:
        assert not set(view.model_fields) & HOST_ONLY_FIELDS, view.__name__
        assert not {field.alias for field in view.model_fields.values() if field.alias} & HOST_ONLY_FIELDS, (
            view.__name__
        )
        assert view.model_config.get("extra") == "forbid", view.__name__
    assert not set(m.Image.model_fields) - {"alias", "digest"}


# ------------------------------------------------------------------------------- unknown values in views
def _with(view: dict[str, Any], path: str, value: Any) -> dict[str, Any]:
    out = copy.deepcopy(view)
    node = out
    *parents, last = path.split(".")
    for step in parents:
        node = node[step]
    node[last] = value
    return out


def _at(body: dict[str, Any], path: str) -> Any:
    node: Any = body
    for step in path.split("."):
        node = node.get(step) if isinstance(node, dict) else None
    return node


def _sandbox(view: dict[str, Any]) -> m.ViewModel:
    return mapping.sandbox(TABLE, view, PROJECT, LINEAGE)


def _snapshot(view: dict[str, Any]) -> m.ViewModel:
    return mapping.snapshot(TABLE, view, PROJECT, LINEAGE)


def _operation(view: dict[str, Any]) -> m.ViewModel:
    return mapping.operation(TABLE, view, PROJECT, LINEAGE)


def _execution(view: dict[str, Any]) -> m.ViewModel:
    return mapping.execution_from_run(TABLE, view, PROJECT)


def _chunk(view: dict[str, Any]) -> m.ViewModel:
    return mapping.output_chunk(TABLE, view, "exe-" + "0" * 32, 0)


#: A host view, the member of it that holds a value of a vocabulary, and where the public view shows
#: the value and the raw value.
UNKNOWN_VALUES: list[tuple[str, Callable[[dict[str, Any]], m.ViewModel], dict[str, Any], str, str, str]] = [
    ("sandbox state", _sandbox, SANDBOX, "state", "state", "state_raw"),
    ("network mode", _sandbox, SANDBOX, "resources.network.mode", "network.mode", "network.mode_raw"),
    ("snapshot state", _snapshot, SNAPSHOT, "state", "state", "state_raw"),
    ("operation state", _operation, FAILED_OPERATION, "state", "state", "state_raw"),
    ("operation type", _operation, FAILED_OPERATION, "operation_type", "type", "type_raw"),
    ("effect", _operation, FAILED_OPERATION, "effect", "effect", "effect_raw"),
    ("cleanup", _operation, FAILED_OPERATION, "cleanup", "cleanup", "cleanup_raw"),
    ("cancelled by", _operation, CANCELLED_OPERATION, "cancelled_by", "cancelled_by", "cancelled_by_raw"),
    ("issuer", _operation, FAILED_OPERATION, "issuer", "initiated_by", "initiated_by_raw"),
    ("failure class", _operation, FAILED_OPERATION, "failure.class", "failure.code", "failure.code_raw"),
    (
        "side effect",
        _operation,
        FAILED_OPERATION,
        "failure.side_effect",
        "failure.side_effect",
        "failure.side_effect_raw",
    ),
    ("execution status", _execution, RUN, "status", "status", "status_raw"),
    ("evidence status", _execution, RUN, "evidence_status", "evidence_status", "evidence_status_raw"),
    (
        "output completeness of a summary",
        _execution,
        RUN,
        "stdout.status",
        "stdout.completeness",
        "stdout.completeness_raw",
    ),
    ("output completeness of a chunk", _chunk, CHUNK, "completeness", "completeness", "completeness_raw"),
]


@pytest.mark.proves("T3-API-01")
@pytest.mark.parametrize(
    ("what", "build", "host", "member", "shown_at", "raw_at"), UNKNOWN_VALUES, ids=[row[0] for row in UNKNOWN_VALUES]
)
def test_an_unknown_value_is_shown_as_unrecognized_with_the_raw_value_beside_it(
    what: str,
    build: Callable[[dict[str, Any]], m.ViewModel],
    host: dict[str, Any],
    member: str,
    shown_at: str,
    raw_at: str,
) -> None:
    known = build(host).model_dump(mode="json", by_alias=True)
    assert _at(known, shown_at) not in {None, UNRECOGNIZED}, "the recorded view must hold a known value to begin with"
    assert _at(known, raw_at) is None, "a known value has no raw value beside it"

    unknown = build(_with(host, member, FUTURE)).model_dump(mode="json", by_alias=True)
    assert _at(unknown, shown_at) == UNRECOGNIZED
    assert _at(unknown, raw_at) == FUTURE
    # Nothing else of the view changed: the value was not folded into a neighbour or a default. Two
    # members follow from the value by rule: an unknown state is not terminal, an unknown class is not retried.
    follows = {
        "operation state": ("terminal", True, False),
        "failure class": ("failure.retry", "SAME_REQUEST_LATER", "NEVER"),
    }
    for path in (shown_at, raw_at, *([follows[what][0]] if what in follows else [])):
        if what in follows and path == follows[what][0]:
            assert (_at(known, path), _at(unknown, path)) == follows[what][1:]
        *parents, last = path.split(".")
        for body in (known, unknown):
            node: Any = body
            for step in parents:
                node = node[step]
            node.pop(last, None)
    assert unknown == known


@pytest.mark.proves("T3-API-01")
def test_an_operation_in_an_unrecognized_state_is_neither_terminal_nor_successful() -> None:
    for view in RECORDED_VIEWS["operation"]:
        if view["operation_type"] in HOST_OPERATOR_METHODS:
            continue
        shown = mapping.operation(TABLE, _with(view, "state", FUTURE), PROJECT, LINEAGE)
        assert (shown.state, shown.state_raw, shown.terminal) == (UNRECOGNIZED, FUTURE, False)
        assert shown.state != "SUCCEEDED"
        execution = mapping.execution_from_operation(TABLE, _with(view, "state", FUTURE), PROJECT)
        assert (execution.state, execution.state_raw, execution.terminal) == (UNRECOGNIZED, FUTURE, False)
        if shown.result is not None and shown.result.execution is not None:
            assert shown.result.execution.terminal is False
    assert mapping.execution_from_run(TABLE, RUN, PROJECT, UNRECOGNIZED, FUTURE).terminal is False
    assert mapping.execution_from_run(TABLE, RUN, PROJECT).terminal is True


@pytest.mark.proves("T3-API-01", "T3-ERR-01")
def test_a_failure_keeps_the_hosts_class_and_advice_and_an_unknown_class_is_not_retried() -> None:
    for host_class, public_code in TABLE.vocabularies["failure_class"].items():
        shown = mapping.failure(TABLE, {"class": host_class, "message": "why", "side_effect": "POSSIBLE"})
        assert shown is not None
        assert (shown.code, shown.code_raw, shown.retry, shown.side_effect) == (
            public_code,
            None,
            TABLE.retry_advice[host_class],
            "POSSIBLE",
        )
    unknown = mapping.failure(TABLE, {"class": FUTURE, "message": "why", "side_effect": "NONE"})
    assert unknown is not None
    assert (unknown.code, unknown.code_raw, unknown.retry) == (UNRECOGNIZED, FUTURE, "NEVER")
    # A refusal class of the platform's own that ended an operation has no public name either.
    fault = mapping.failure(TABLE, {"class": "PROTOCOL_ERROR", "message": "why", "side_effect": "NONE"})
    assert fault is not None
    assert (fault.code, fault.code_raw) == (UNRECOGNIZED, "PROTOCOL_ERROR")
    assert mapping.failure(TABLE, None) is None
    assert mapping.failure(TABLE, "FAILED") is None
    long = mapping.failure(TABLE, {"class": "TIMEOUT", "message": "m" * 5000, "side_effect": "NONE"})
    assert long is not None
    assert len(long.message) == 2000
    bare = mapping.failure(TABLE, {})
    assert bare is not None
    assert (bare.code, bare.retry, bare.message, bare.side_effect) == (UNRECOGNIZED, "NEVER", "", None)


@pytest.mark.proves("T3-API-01")
def test_every_field_of_an_execution_result_has_a_provenance_label() -> None:
    """PUB-4: what the guest reported and what the host observed are told apart, field by field."""
    labels = mapping.EXECUTION_PROVENANCE
    assert set(labels.values()) == {m.GUEST_REPORTED, m.HOST_OBSERVED}
    for field in labels:
        head, _, tail = field.partition(".")
        assert head in m.Execution.model_fields, field
        if tail:
            assert tail in m.Durations.model_fields, field
    # Everything an execution reports about its outcome is labelled. What identifies it is not an outcome.
    identifying = {
        "execution_id",
        "operation_id",
        "project",
        "sandbox_id",
        "generation",
        "state",
        "state_raw",
        "terminal",
        "status_raw",
        "evidence_status_raw",
        "provenance",
        "durations",
    }
    assert set(m.Execution.model_fields) - identifying == {field for field in labels if "." not in field}
    assert labels["status"] == labels["exit_code"] == labels["stdout"] == m.GUEST_REPORTED
    assert labels["host_backstop_fired"] == labels["durations.wall_ms"] == m.HOST_OBSERVED
    schema = m.Execution.model_json_schema()["properties"]
    for field, label in labels.items():
        if "." not in field:
            assert schema[field]["x-provenance"] == label, field


@pytest.mark.proves("T3-API-01")
def test_the_actor_of_an_operation_is_read_as_the_host_recorded_it() -> None:
    assert mapping.parse_actor("prn_6N0P4V8B2X7M1C5T") == m.Actor(principal_id="prn_6N0P4V8B2X7M1C5T", agent_label=None)
    assert mapping.parse_actor("prn_6N0P4V8B2X7M1C5T/agent-1") == m.Actor(
        principal_id="prn_6N0P4V8B2X7M1C5T", agent_label="agent-1"
    )
    nobodies: tuple[object, ...] = (None, "", 1, [], {})
    for nobody in nobodies:
        assert mapping.parse_actor(nobody) is None


# ------------------------------------------------------------------------------- opaque identifiers
hex32 = st.text(alphabet="0123456789abcdef", min_size=32, max_size=32)
lineages = st.text(alphabet="0123456789abcdef", min_size=1, max_size=64) | st.text(min_size=0, max_size=20)


@pytest.mark.proves("T3-API-01")
@given(hex32, hex32)
def test_an_execution_identifier_stands_for_exactly_one_identifier_of_the_host(one: str, other: str) -> None:
    public = mapping.execution_id("run-" + one)
    assert public == "exe-" + one
    assert re.fullmatch(m.EXECUTION_ID_PATTERN, public)
    assert mapping.host_run_id(public) == "run-" + one
    assert (mapping.execution_id("run-" + other) == public) is (other == one)
    c.GetExecution(project=PROJECT, execution_id=public)


@pytest.mark.proves("T3-API-01")
@pytest.mark.parametrize(
    "not_a_run_id",
    [
        None,
        "",
        1,
        "run-",
        "run-" + "0" * 31,
        "run-" + "0" * 33,
        "run-" + "G" * 32,
        "run-" + "A" * 32,
        "exe-" + "0" * 32,
        "RUN-" + "0" * 32,
        " run-" + "0" * 32,
        "run_" + "0" * 32,
        ["run-" + "0" * 32],
    ],
)
def test_what_is_not_an_identifier_of_the_host_gets_no_public_identifier(not_a_run_id: Any) -> None:
    assert mapping.execution_id(not_a_run_id) is None


@pytest.mark.proves("T3-API-01")
@given(st.integers(min_value=0, max_value=2**63), lineages, st.integers(min_value=0, max_value=2**63), lineages)
def test_a_revision_validator_stands_for_exactly_one_revision_of_one_lineage(
    revision: int, lineage: str, other: int, other_lineage: str
) -> None:
    validator = mapping.revision(revision, lineage)
    assert re.fullmatch(c.REVISION_PATTERN, validator)
    assert mapping.parse_revision(validator, lineage) == revision
    assert (mapping.revision(other, lineage) == validator) is (other == revision)
    if other_lineage != lineage:
        assert mapping.revision(revision, other_lineage) != validator
        assert mapping.parse_revision(validator, other_lineage) is None


@pytest.mark.proves("T3-API-01")
def test_a_validator_of_another_lineage_does_not_parse() -> None:
    validator = mapping.revision(7, LINEAGE)
    assert mapping.parse_revision(validator, LINEAGE) == 7
    assert mapping.parse_revision(validator, OTHER_LINEAGE) is None
    assert mapping.parse_revision(mapping.revision(7, OTHER_LINEAGE), LINEAGE) is None
    # The lineage is in the validator as a digest. Neither the lineage nor any name of the host is.
    assert LINEAGE not in validator
    assert LINEAGE[:12] not in validator
    assert re.fullmatch(r"r7\.[0-9a-f]{12}", validator)


@pytest.mark.proves("T3-API-01")
@given(st.text(max_size=40), st.sampled_from([LINEAGE, OTHER_LINEAGE, ""]))
def test_a_validator_parses_only_if_it_is_exactly_what_the_platform_derives(text: str, lineage: str) -> None:
    """One-to-one in both directions: no second spelling of a validator stands for the same revision."""
    parsed = mapping.parse_revision(text, lineage)
    assert parsed is None or mapping.revision(parsed, lineage) == text


@pytest.mark.proves("T3-API-01")
@pytest.mark.parametrize(
    "spelling",
    [
        "",
        "r",
        "7",
        "r7",
        "r7.",
        "7.{d}",
        "R7.{d}",
        "r07.{d}",
        "r007.{d}",
        "r+7.{d}",
        "r-7.{d}",
        "r7 .{d}",
        " r7.{d}",
        "r7.{d} ",
        "r7.{d}\n",
        "r7.{D}",
        "r7.{d}0",
        "r7.{d}.x",
        "r7..{d}",
        "r\u0667.{d}",
        "r\u00b2.{d}",
        "r\uff17.{d}",
        "r7e0.{d}",
        "r0x7.{d}",
        "r" + "9" * 5000 + ".{d}",
        "rr7.{d}",
        "r.{d}",
    ],
)
def test_another_spelling_of_a_validator_is_not_a_validator(spelling: str) -> None:
    digest = mapping.revision(7, LINEAGE).partition(".")[2]
    text = spelling.replace("{d}", digest).replace("{D}", digest.upper())
    assert mapping.parse_revision(text, LINEAGE) is None


@pytest.mark.proves("T3-API-01")
@given(lineages, st.integers(min_value=0, max_value=2**63))
def test_a_cursor_stands_for_exactly_one_position_of_the_host(lineage: str, sequence: int) -> None:
    token = mapping.encode_cursor({"lineage": lineage, "sequence": sequence})
    assert re.fullmatch(r"[A-Za-z0-9_-]+", token)
    assert mapping.decode_cursor(token) == {"lineage": lineage, "sequence": sequence}
    assert mapping.encode_cursor({"lineage": lineage, "sequence": sequence + 1}) != token
    assert mapping.encode_cursor({"lineage": lineage + "0", "sequence": sequence}) != token


@pytest.mark.proves("T3-API-01")
def test_a_cursor_of_the_host_fits_the_public_syntax_and_carries_a_position_and_nothing_else() -> None:
    host_cursor = {"lineage": LINEAGE, "sequence": 26}
    token = mapping.encode_cursor(host_cursor)
    assert re.fullmatch(c.CURSOR_PATTERN, token)
    assert mapping.decode_cursor(token) == host_cursor
    c.ListSandboxes(project=PROJECT, cursor=token)
    # A cursor is made from the host's cursor alone: the function is given no project and no host name.
    assert list(inspect.signature(mapping.encode_cursor).parameters) == ["host_cursor"]
    assert list(inspect.signature(mapping.execution_id).parameters) == ["run_id"]
    assert list(inspect.signature(mapping.revision).parameters) == ["host_revision", "lineage"]
    assert mapping.encode_cursor({"lineage": LINEAGE, "sequence": 26, "host_id": "host-1", "project": PROJECT}) == token
    assert mapping.encode_cursor(None) == ""
    assert mapping.encode_cursor("cursor") == ""


@pytest.mark.proves("T3-API-01")
@given(st.text(max_size=80))
def test_a_token_decodes_only_if_it_is_exactly_what_the_platform_issues(token: str) -> None:
    decoded = mapping.decode_cursor(token)
    assert decoded is None or mapping.encode_cursor(decoded) == token


def _token(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii").rstrip("=")


@pytest.mark.proves("T3-API-01")
@pytest.mark.parametrize(
    "token",
    [
        "",
        "!",
        "not base64",
        _token("not json"),
        _token("[]"),
        _token("null"),
        _token("{}"),
        _token('{"l":"x"}'),
        _token('{"s":1}'),
        _token('{"l":1,"s":1}'),
        _token('{"l":"x","s":"1"}'),
        _token('{"l":"x","s":-1}'),
        _token('{"l":"x","s":true}'),
        _token('{"l":"x","s":1.5}'),
        _token('{"l":null,"s":1}'),
        # Other spellings of a token the platform does issue: same position, another text.
        _token('{"l":"x","s":1,"extra":true}'),
        _token('{"s":1,"l":"x"}'),
        _token('{"l": "x", "s": 1}'),
        _token('{"l":"x","s":1} '),
        _token('{"l":"x","s":1}') + "=",
        _token('{"l":"x","s":1}') + "==",
        _token('{"l":"x","s":01}'),
        _token('{"l":"x","s":1,"l":"x"}'),
    ],
)
def test_a_token_the_platform_did_not_issue_is_not_a_cursor(token: str) -> None:
    assert mapping.decode_cursor(token) is None
    assert mapping.decode_cursor(_token('{"l":"x","s":1}')) == {"lineage": "x", "sequence": 1}


@pytest.mark.proves("T3-API-01")
def test_sandbox_snapshot_and_operation_identifiers_are_the_hosts_own_tokens() -> None:
    """The table states the correspondence of each identifier. Three of the four are the same token on both sides."""
    identifiers = yaml.safe_load(PACKAGED.read_text(encoding="utf-8"))["identifiers"]
    assert identifiers == {
        "sandbox": {"public_prefix": "sbx-", "host_prefix": "sbx-"},
        "snapshot": {"public_prefix": "snp-", "host_prefix": "snp-"},
        "execution": {"public_prefix": "exe-", "host_prefix": "run-"},
        "operation": {"public_prefix": "", "host_prefix": ""},
    }
    assert HOST_API["$defs"]["SandboxId"]["pattern"] == m.SANDBOX_ID_PATTERN
    assert HOST_API["$defs"]["SnapshotId"]["pattern"] == m.SNAPSHOT_ID_PATTERN
    assert HOST_API["$defs"]["OperationId"]["pattern"] == m.OPERATION_ID_PATTERN
    assert HOST_API["$defs"]["RunId"]["pattern"] == m.EXECUTION_ID_PATTERN.replace("exe-", "run-")
    for pattern in (m.SANDBOX_ID_PATTERN, m.SNAPSHOT_ID_PATTERN, m.EXECUTION_ID_PATTERN, m.OPERATION_ID_PATTERN):
        assert "prj" not in pattern
        assert "host" not in pattern


@pytest.mark.proves("T3-API-01")
def test_a_network_view_shows_the_entries_the_host_recorded() -> None:
    allowlist = next(view for view in RECORDED_VIEWS["sandbox"] if view["resources"]["network"]["mode"] == "allowlist")
    shown = mapping.network(TABLE, allowlist["resources"]["network"]).model_dump(
        mode="json", by_alias=True, exclude_none=True
    )
    assert shown == {
        "mode": "allowlist",
        "entries": [
            {"name": "pypi.org", "ports": [{"from": 443, "to": 443}]},
            {"network": "198.51.100.0/24", "ports": [{"from": 5432, "to": 5433}]},
        ],
    }
    assert mapping.network(TABLE, {"mode": "none"}).model_dump(exclude_none=True) == {"mode": "none", "entries": []}
    not_networks: tuple[object, ...] = (None, "none", [], 1)
    for not_a_network in not_networks:
        assert mapping.network(TABLE, not_a_network).mode == UNRECOGNIZED
    unknown = mapping.network(
        TABLE, {"mode": "open", "entries": [{"destination": {"name": "x.example"}, "ports": [{"from": 1, "to": 2}]}]}
    )
    assert (unknown.mode, unknown.mode_raw) == (UNRECOGNIZED, "open")


@pytest.mark.proves("T3-API-01")
def test_the_mapping_reads_a_table_and_decoded_json_and_no_type_of_the_host_protocol() -> None:
    """PUB-2: no type of the host protocol appears above the host binding."""
    imported: set[str] = set()
    for node in ast.walk(ast.parse(inspect.getsource(mapping))):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    assert not {module for module in imported if module.startswith("acf_api.core.host")}
    assert isinstance(TABLE, MappingTable)
    for function in (
        mapping.sandbox,
        mapping.snapshot,
        mapping.operation,
        mapping.execution_from_run,
        mapping.output_chunk,
    ):
        hints = inspect.signature(function).parameters
        assert "table" in hints
        assert str(hints["table"].annotation) == "MappingTable"
