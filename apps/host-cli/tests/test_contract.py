"""The client against the host's published API description (``execution/contracts/host-api.json``).

The description is generated from the host's own types, so it is the contract in machine-readable
form. These tests need no host. They prove that the client cannot drift from it:

* the client's method table *is* the published one (names, classes, which ones create operations);
* every closed vocabulary the client knows has exactly the published words;
* every request type has exactly the published fields, and every request the client can build —
  for every method — validates;
* answers recorded from the real host (``tests/data/recorded_answers.json``) and the answers the
  test factories generate validate, and the client's models read them and write them back unchanged.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path
from typing import Any

import pytest
from jsonschema import ValidationError as SchemaError
from pydantic import BaseModel

import factories as f
from acf_cli import requests as rq
from acf_cli import responses as rs
from acf_cli import wire
from acf_cli.responses import ResponseEnvelope, to_wire
from support import Contract, accepted, answered, refused

RECORDED = Path(__file__).resolve().parent / "data" / "recorded_answers.json"


def _words(schema: dict[str, Any]) -> set[str]:
    """The words of an enumeration schema, however the generator spelled it (``enum`` or ``oneOf`` of constants)."""
    words = set(schema.get("enum", []))
    for alternative in schema.get("oneOf", []):
        words |= _words(alternative)
        if "const" in alternative:
            words.add(alternative["const"])
    return words


def _published_type(reference: dict[str, Any] | None) -> str | None:
    return reference["$ref"].rsplit("/", 1)[1] if reference is not None else None


# ----------------------------------------------------------------------------- protocol and methods
def test_the_client_speaks_the_published_protocol(contract: Contract) -> None:
    assert contract.document["protocol"] == wire.PROTOCOL


def test_the_method_table_is_the_published_one(contract: Contract) -> None:
    published = contract.document["methods"]
    assert [m.name for m in rq.METHODS.values()] == [m["name"] for m in published], "same methods, same order"
    assert len(rq.METHODS) == 22
    for entry in published:
        method = rq.METHODS[entry["name"]]
        assert method.operation_class.value == entry["class"], entry["name"]
        assert method.creates_operation == entry["creates_operation"], entry["name"]
        assert method.params_required == entry["params_required"], entry["name"]
        mine = method.params.__name__ if method.params is not None else None
        assert mine == _published_type(entry["params"]), f"{entry['name']}: params type"
        expected_answer = "OPERATION" if method.creates_operation else "RESULT"
        assert entry["answer"] == expected_answer, entry["name"]


def test_roles_are_the_published_ones(contract: Contract) -> None:
    roles = {role for m in contract.document["methods"] for role in m["roles"]}
    assert roles == {r.value for r in wire.Role}


# ----------------------------------------------------------------------------- vocabularies
def test_failure_classes_are_the_published_ones(contract: Contract) -> None:
    published = contract.document["failure_classes"]
    assert [c.value for c in wire.FailureClass] == [c["class"] for c in published], "same classes, same order"
    assert {c["retry"] for c in published} == {a.value for a in wire.RetryAdvice}


@pytest.mark.parametrize(
    ("key", "vocabulary"),
    [
        ("operation_states", wire.OperationState),
        ("operation_types", wire.OperationType),
        ("lifecycle_states", wire.LifecycleState),
        ("host_modes", wire.HostMode),
    ],
)
def test_the_state_vocabularies_are_the_published_ones(contract: Contract, key: str, vocabulary: type[StrEnum]) -> None:
    assert [v.value for v in vocabulary] == contract.document[key]


def test_terminal_states_are_the_contract_table() -> None:
    terminal = {s for s in wire.OperationState if s.is_terminal}
    assert terminal == {
        wire.OperationState.SUCCEEDED,
        wire.OperationState.FAILED,
        wire.OperationState.CANCELLED,
        wire.OperationState.UNKNOWN,
    }


VOCABULARIES: list[type[StrEnum]] = [
    wire.FailureClass,
    wire.RetryAdvice,
    wire.SideEffect,
    wire.OperationState,
    wire.OperationType,
    wire.Effect,
    wire.Cleanup,
    wire.CancelledBy,
    wire.Issuer,
    wire.HostMode,
    wire.LifecycleState,
    wire.SnapshotState,
    wire.RunStatus,
    wire.EvidenceStatus,
    wire.OutputStatus,
    wire.ArtifactKind,
    wire.NetworkMode,
    wire.OutputStream,
    wire.ReleaseMode,
    wire.RequestedMode,
    wire.AckCondition,
]


@pytest.mark.parametrize("vocabulary", VOCABULARIES, ids=lambda v: v.__name__)
def test_every_vocabulary_has_exactly_the_published_words(contract: Contract, vocabulary: type[StrEnum]) -> None:
    assert {v.value for v in vocabulary} == _words(contract.defs[vocabulary.__name__])


def test_no_published_vocabulary_is_unknown_to_the_client(contract: Contract) -> None:
    """A new enumeration in the description must be given a vocabulary here, not silently treated as text."""
    published = {name for name, schema in contract.defs.items() if _words(schema) and "properties" not in schema}
    structural = {
        "NetworkIntent",
        "RestoreTarget",
        "AllowDestination",
        "OperationResult",
        "ReadResult",
        "ResponseEnvelope",
    }
    published -= structural | {"ContainmentReason"}
    assert published == {v.__name__ for v in VOCABULARIES}


def test_identifier_grammars_are_the_published_ones(contract: Contract) -> None:
    assert contract.defs["SandboxId"]["pattern"] == wire.SANDBOX_ID_PATTERN
    assert contract.defs["SnapshotId"]["pattern"] == wire.SNAPSHOT_ID_PATTERN
    assert contract.defs["RunId"]["pattern"] == wire.RUN_ID_PATTERN
    assert contract.defs["OperationId"]["pattern"] == wire.OPERATION_ID_PATTERN
    scope = contract.defs["OwnerScope"]
    assert (scope["pattern"], scope["maxLength"]) == (wire.LABEL_PATTERN, wire.MAX_OWNER_SCOPE_CHARS)


# ----------------------------------------------------------------------------- request types
def _wire_fields(model: type[BaseModel]) -> set[str]:
    return {field.alias or name for name, field in model.model_fields.items()}


REQUEST_TYPES: dict[str, type[BaseModel]] = {
    model.__name__: model
    for model in (
        rq.SandboxCreateParams,
        rq.SandboxResources,
        rq.SandboxTarget,
        rq.SandboxSelector,
        rq.ExecParams,
        rq.CommandSpec,
        rq.RunLimitsRequest,
        rq.SecretRef,
        rq.SnapshotCreateParams,
        rq.SnapshotRestoreParams,
        rq.SnapshotDeleteParams,
        rq.SnapshotRef,
        rq.OperationSelector,
        rq.RunSelector,
        rq.RunOutputParams,
        rq.Cursor,
        rq.ListParams,
        rq.QuarantineReleaseParams,
        rq.SetModeParams,
        rq.AcknowledgeParams,
        rq.AllowEntry,
    )
}


@pytest.mark.parametrize("name", sorted(REQUEST_TYPES))
def test_every_request_type_has_exactly_the_published_fields(contract: Contract, name: str) -> None:
    schema = contract.defs[name]
    model = REQUEST_TYPES[name]
    assert _wire_fields(model) == set(schema["properties"]), name
    required = {field.alias or n for n, field in model.model_fields.items() if field.is_required()}
    assert required == set(schema.get("required", [])), f"{name}: required fields"


def test_the_request_envelope_has_the_published_fields_and_never_authority(contract: Contract) -> None:
    schema = contract.defs["RequestEnvelope"]
    assert _wire_fields(rq.RequestEnvelope) == set(schema["properties"]) - {"authority"}
    required = {n for n, field in rq.RequestEnvelope.model_fields.items() if field.is_required()}
    # `protocol` defaults to the one this client speaks; `request_id` is optional to the host, and
    # this client always sends one, because it checks that an answer belongs to its request.
    assert required == (set(schema["required"]) - {"protocol"}) | {"request_id"}
    assert schema["additionalProperties"] is False


def test_every_parameter_type_of_every_method_is_covered(contract: Contract) -> None:
    referenced = {_published_type(m["params"]) for m in contract.document["methods"]} - {None}
    assert referenced <= set(REQUEST_TYPES)


def test_the_tagged_request_shapes_are_the_published_ones(contract: Contract) -> None:
    """``NetworkIntent``, ``RestoreTarget``, ``AllowDestination`` and ``PortRange``: unions, or renamed on the wire."""
    intents = {
        alt["properties"]["mode"]["const"]: set(alt["properties"]) for alt in contract.defs["NetworkIntent"]["oneOf"]
    }
    assert intents == {"none": _wire_fields(rq.NetworkNone), "allowlist": _wire_fields(rq.NetworkAllowlist)}
    targets = {
        alt["properties"]["kind"]["const"]: set(alt["properties"]) for alt in contract.defs["RestoreTarget"]["oneOf"]
    }
    assert targets == {"existing": _wire_fields(rq.RestoreExisting), "new": _wire_fields(rq.RestoreNew)}
    destinations = [set(alt["properties"]) for alt in contract.defs["AllowDestination"]["oneOf"]]
    assert destinations == [_wire_fields(rq.NameDestination), _wire_fields(rq.NetworkDestination)]
    assert set(rq.PortRange(low=1, high=2).model_dump()) == set(contract.defs["PortRange"]["properties"])


# ----------------------------------------------------------------------------- every request the client can build
TARGET = rq.SandboxTarget(sandbox_id=f.SANDBOX_ID, expected_generation=3, if_revision=17)
SNAPSHOT = rq.SnapshotRef(snapshot_id=f.SNAPSHOT_ID, snapshot_generation=1)
ALLOWLIST = rq.NetworkAllowlist(
    entries=[
        rq.AllowEntry(destination=rq.NameDestination(name="pypi.org"), ports=[rq.PortRange(low=443, high=443)]),
        rq.AllowEntry(
            destination=rq.NetworkDestination(network="198.51.100.0/24"),
            ports=[rq.PortRange(low=5432, high=5433), rq.PortRange(low=8443, high=8443)],
        ),
    ]
)
FULL_COMMAND = rq.CommandSpec(
    argv=["python", "-c", "print('héllo')"],
    env={"LANG": "C.UTF-8", "TZ": "UTC"},
    secret_env={"API_TOKEN": rq.SecretRef(ref="ci-token_v2.prod")},
    cwd="/workspace/job",
    limits=rq.RunLimitsRequest(timeout_ms=90_000, max_pids=64, max_stdout_bytes=65_536, max_stderr_bytes=4_096),
)
CURSOR = rq.Cursor(lineage=f.LINEAGE, sequence=2**53)

#: At least one call per method; several where a method has distinct shapes.
CALLS: list[rq.Call] = [
    rq.sandbox_create(
        rq.SandboxCreateParams(
            image="python",
            resources=rq.SandboxResources(vcpus=1, memory_mib=128, disk_mib=64, network=rq.NetworkNone()),
        )
    ),
    rq.sandbox_create(
        rq.SandboxCreateParams(
            name="job-7_a.b",
            image="python",
            resources=rq.SandboxResources(vcpus=4, memory_mib=4096, disk_mib=8192, network=ALLOWLIST),
            lifetime_secs=7200,
        )
    ),
    rq.sandbox_start(TARGET),
    rq.sandbox_start(rq.SandboxTarget(sandbox_id=f.SANDBOX_ID, expected_generation=1)),
    rq.exec_run(rq.ExecParams(sandbox_id=f.SANDBOX_ID, expected_generation=1, command=rq.CommandSpec(argv=["true"]))),
    rq.exec_run(rq.ExecParams(sandbox_id=f.SANDBOX_ID, expected_generation=2, if_revision=9, command=FULL_COMMAND)),
    rq.snapshot_create(rq.SnapshotCreateParams(sandbox_id=f.SANDBOX_ID, expected_generation=1)),
    rq.snapshot_create(
        rq.SnapshotCreateParams(sandbox_id=f.SANDBOX_ID, expected_generation=1, if_revision=4, name="base")
    ),
    rq.snapshot_restore(
        rq.SnapshotRestoreParams(
            snapshot=SNAPSHOT,
            target=rq.RestoreExisting(sandbox_id=f.SANDBOX_ID, expected_generation=2, if_revision=31),
        )
    ),
    rq.snapshot_restore(rq.SnapshotRestoreParams(snapshot=SNAPSHOT, target=rq.RestoreNew())),
    rq.snapshot_restore(
        rq.SnapshotRestoreParams(snapshot=SNAPSHOT, target=rq.RestoreNew(name="copy", lifetime_secs=600))
    ),
    rq.sandbox_stop(TARGET),
    rq.sandbox_destroy(TARGET),
    rq.snapshot_delete(SNAPSHOT),
    rq.operation_cancel(f.OPERATION_ID),
    rq.sandbox_inspect("box"),
    rq.sandbox_inspect(f.SANDBOX_ID),
    rq.sandbox_list(),
    rq.sandbox_list(rq.ListParams(limit=1)),
    rq.sandbox_list(rq.ListParams(changed_since=CURSOR, limit=1000)),
    rq.snapshot_list(),
    rq.snapshot_list(rq.ListParams(changed_since=CURSOR)),
    rq.operation_get(f.OPERATION_ID),
    rq.operation_list(),
    rq.operation_list(rq.ListParams(changed_since=CURSOR, limit=50)),
    rq.run_inspect(f.RUN_ID),
    rq.run_output(rq.RunOutputParams(run_id=f.RUN_ID, stream=wire.OutputStream.STDOUT)),
    rq.run_output(rq.RunOutputParams(run_id=f.RUN_ID, stream=wire.OutputStream.STDERR, offset=4096, max_bytes=1 << 20)),
    rq.host_info(),
    rq.host_metrics(),
    rq.profile_reload(),
    rq.quarantine_release(
        rq.QuarantineReleaseParams(sandbox_id=f.SANDBOX_ID, generation=2, mode=wire.ReleaseMode.FORCE_DESTROY)
    ),
    rq.quarantine_release(
        rq.QuarantineReleaseParams(sandbox_id=f.SANDBOX_ID, generation=2, mode=wire.ReleaseMode.DECLARE_ABSENT)
    ),
    rq.host_set_mode(wire.RequestedMode.DRAINING),
    rq.host_set_mode(wire.RequestedMode.SERVING),
    rq.host_acknowledge(wire.AckCondition.STORE_REGRESSION),
]


def _envelopes(call: rq.Call) -> list[rq.RequestEnvelope]:
    """Every envelope the client wraps ``call`` in: plain, on behalf of someone, and — for operations — a retry."""
    if not call.method.creates_operation:
        return [
            rq.read_envelope(call, owner_scope="default"),
            rq.read_envelope(call, owner_scope="team-a/project_1:prod@eu=1+x", on_behalf_of="job:42"),
        ]
    op_id, issued = rq.new_operation_id(), rq.utc_timestamp()
    return [
        rq.operation_envelope(call, operation_id=op_id, issued_at=issued, owner_scope="default", wait_ms=20_000),
        rq.operation_envelope(
            call, operation_id=op_id, issued_at=issued, owner_scope="team-a", on_behalf_of="job:42", wait_ms=0
        ),
        rq.operation_envelope(
            call, operation_id=op_id, issued_at=issued, owner_scope="team-a", retry=True, wait_ms=20_000
        ),
    ]


def test_the_sample_calls_cover_every_method() -> None:
    assert {call.method.name for call in CALLS} == set(rq.METHODS)


@pytest.mark.parametrize("call", CALLS, ids=lambda c: c.method.name)
def test_every_request_the_client_builds_is_valid(contract: Contract, call: rq.Call) -> None:
    for envelope in _envelopes(call):
        doc = json.loads(envelope.encode())
        contract.check_request(doc)
        assert doc["protocol"] == contract.document["protocol"]
        assert "authority" not in doc
        assert ("retry" in doc) == envelope.retry, "retry is sent only when it is asserted"


def test_a_retry_differs_from_the_first_submission_only_in_the_flag_and_the_correlation_id() -> None:
    first, _, again = (json.loads(e.encode()) for e in _envelopes(CALLS[0]))
    first.pop("request_id")
    again.pop("request_id")
    assert again.pop("retry") is True
    assert first.pop("owner_scope") == "default"
    assert again.pop("owner_scope") == "team-a"
    assert first == again, "same operation_id, same issued_at, same method, same params"


def test_the_validator_would_catch_a_request_the_host_refuses(contract: Contract) -> None:
    """The contract check is not vacuous: an unknown field, a bad id and a missing token are all rejected."""
    good = json.loads(_envelopes(rq.sandbox_destroy(TARGET))[0].encode())
    contract.check_request(good)
    breakages: list[Callable[[dict[str, Any]], object]] = [
        lambda d: d.update(sneaky=1),
        lambda d: d["params"].update(force=True),
        lambda d: d["params"].update(sandbox_id="sbx-../../etc"),
        lambda d: d["params"].pop("expected_generation"),
        lambda d: d.update(owner_scope="has space"),
    ]
    for mutate in breakages:
        broken = json.loads(json.dumps(good))
        mutate(broken)
        with pytest.raises(SchemaError):
            contract.check_request(broken)
    unidentified = json.loads(json.dumps(good))
    del unidentified["operation_id"]
    with pytest.raises(AssertionError):
        contract.check_request(unidentified)


# ----------------------------------------------------------------------------- response types
RESPONSE_TYPES: dict[str, type[BaseModel]] = {
    "AsOf": rs.AsOf,
    "Refusal": rs.Refusal,
    "FailureInfo": rs.FailureInfo,
    "Tags": rs.Tags,
    "ProfileId": rs.ProfileId,
    "ImageRef": rs.ImageRef,
    "ProcessIdentity": rs.ProcessIdentity,
    "SnapshotRef": rs.SnapshotRefView,
    "Cursor": rs.CursorView,
    "PortRange": rs.PortRangeView,
    "AllowEntry": rs.AllowEntryView,
    "SandboxResources": rs.SandboxResourcesView,
    "SandboxView": rs.SandboxView,
    "SnapshotView": rs.SnapshotView,
    "ArtifactRef": rs.ArtifactRef,
    "OutputCapture": rs.OutputCapture,
    "RunMetrics": rs.RunMetrics,
    "ResourceEvidence": rs.ResourceEvidence,
    "RunResult": rs.RunResult,
    "OutputChunk": rs.OutputChunk,
    "HostChange": rs.HostChange,
    "ProfileLimits": rs.ProfileLimits,
    "CallerParameters": rs.CallerParameters,
    "BackendIdentity": rs.BackendIdentity,
    "CapabilityProfile": rs.CapabilityProfile,
    "HostInfo": rs.HostInfo,
    "OperationView": rs.OperationView,
    "Page": rs.Page,
}


#: Fields the description requires of a host and this client nevertheless reads as optional.
#: They describe the backend and drive nothing here, and they joined the capability profile after
#: the first hosts of this protocol were built: a host that predates them must still be readable.
OPTIONAL_HERE: dict[str, set[str]] = {"CapabilityProfile": {"identifier_slots", "stop_grace_ms"}}


@pytest.mark.parametrize("name", sorted(RESPONSE_TYPES))
def test_every_published_response_field_is_modelled(contract: Contract, name: str) -> None:
    """Unknown fields are tolerated at run time; fields the contract *publishes* are all typed here."""
    schema = contract.defs[name]
    model = RESPONSE_TYPES[name]
    assert _wire_fields(model) == set(schema["properties"]), name
    required = {field.alias or n for n, field in model.model_fields.items() if field.is_required()}
    expected = set(schema.get("required", [])) - OPTIONAL_HERE.get(name, set())
    assert required == expected, f"{name}: a field the host always sends is required here"


def test_the_result_types_are_the_published_ones(contract: Contract) -> None:
    def kinds(name: str) -> set[str]:
        return {alt["properties"]["type"]["const"] for alt in contract.defs[name]["oneOf"]}

    assert kinds("OperationResult") == {"sandbox", "snapshot", "run", "host"}
    assert kinds("ReadResult") == {
        "host_info",
        "metrics",
        "sandbox",
        "sandboxes",
        "snapshots",
        "operation",
        "operations",
        "run",
        "output",
    }
    answers = {alt["properties"]["answer"]["const"] for alt in contract.defs["ResponseEnvelope"]["oneOf"]}
    assert answers == {a.value for a in wire.Answer}


# ----------------------------------------------------------------------------- recorded answers of the real host
def _recorded() -> list[dict[str, Any]]:
    document = json.loads(RECORDED.read_text(encoding="utf-8"))
    exchanges = document["exchanges"]
    assert isinstance(exchanges, list)
    return exchanges


RECORDED_EXCHANGES = _recorded()


def _label(exchange: dict[str, Any]) -> str:
    answer = exchange["response"]
    detail = (
        answer.get("refusal", {}).get("class")
        or (answer.get("operation") or {}).get("state")
        or (answer.get("result") or {}).get("type")
    )
    return f"{exchange['request']['method']}:{answer['answer']}:{detail}"


def test_the_recording_covers_every_method_and_every_answer(contract: Contract) -> None:
    recorded = {e["request"]["method"] for e in RECORDED_EXCHANGES}
    # `host.info` describes the host build itself. Recorded from a host older than the published
    # description, its answer does not validate, and the recorder leaves such an answer out; the
    # shape is then proven by the generated `host_info` answer further down instead.
    assert set(contract.methods) - recorded <= {"host.info"}
    assert "result-host-info" in GENERATED
    assert {e["response"]["answer"] for e in RECORDED_EXCHANGES} == {"REFUSED", "OPERATION", "RESULT"}
    results = {e["response"]["result"]["type"] for e in RECORDED_EXCHANGES if e["response"]["answer"] == "RESULT"}
    assert results >= {"metrics", "sandbox", "sandboxes", "snapshots", "operation", "operations", "run", "output"}
    operation_results = {
        (e["response"]["operation"]["result"] or {}).get("type")
        for e in RECORDED_EXCHANGES
        if e["response"]["answer"] == "OPERATION"
    }
    assert operation_results >= {"sandbox", "snapshot", "run", "host"}


@pytest.mark.parametrize("exchange", RECORDED_EXCHANGES, ids=_label)
def test_recorded_requests_and_answers_are_valid_and_survive_the_models_unchanged(
    contract: Contract, exchange: dict[str, Any]
) -> None:
    contract.check_request(exchange["request"])
    answer = exchange["response"]
    contract.check_response(answer)
    envelope = ResponseEnvelope.model_validate(answer)
    assert to_wire(envelope) == answer, "the models keep every field and add none"
    assert not any(isinstance(v, wire.Unrecognized) for v in _leaves(envelope)), "nothing the host said was unknown"
    assert envelope.request_id == exchange["request"]["request_id"]


def _leaves(model: BaseModel) -> list[object]:
    """Every scalar value reachable from ``model``."""
    found: list[object] = []
    stack: list[object] = [model]
    while stack:
        item = stack.pop()
        if isinstance(item, BaseModel):
            stack.extend(getattr(item, name) for name in type(item).model_fields)
        elif isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list | tuple):
            stack.extend(item)
        else:
            found.append(item)
    return found


# ----------------------------------------------------------------------------- generated answers
GENERATED: dict[str, dict[str, Any]] = {
    "refusal": refused("STATE_CONFLICT", "busy", "AFTER_CHANGE"),
    "refusal-before-any-state": refused("AUTHENTICATION_FAILED", "not enrolled", as_of=None),
    "operation-sandbox": accepted(f.operation_view(result=f.sandbox_body())),
    "operation-allowlist": accepted(
        f.operation_view(
            result=f.sandbox_body(resources={**f.sandbox_view()["resources"], "network": f.network_allowlist()})
        )
    ),
    "operation-snapshot": accepted(f.operation_view(operation_type="snapshot.create", result=f.snapshot_body())),
    "operation-run": accepted(f.operation_view(operation_type="exec.run", result=f.run_body(), run_id=f.RUN_ID)),
    "operation-run-artifacts": accepted(
        f.operation_view(
            operation_type="exec.run",
            result=f.run_body(stdout=b"x" * 6, artifacts=[f.artifact()]),
            run_id=f.RUN_ID,
        )
    ),
    "operation-host": accepted(
        f.operation_view(
            operation_type="host.set_mode", target="host", sandbox=None, result=f.host_change_body(mode="DRAINING")
        )
    ),
    "operation-in-progress": accepted(f.operation_view("IN_PROGRESS")),
    "operation-accepted": accepted(f.operation_view("ACCEPTED", step=None)),
    "operation-recovering": accepted(f.operation_view("RECOVERING")),
    "operation-failed": accepted(f.operation_view("FAILED")),
    "operation-failed-pending": accepted(f.operation_view("FAILED", cleanup="PENDING", effect="MAY_BE_APPLIED")),
    "operation-cancelled": accepted(f.operation_view("CANCELLED", cancelled_by="SUPERSEDED", effect="MAY_BE_APPLIED")),
    "operation-unknown": accepted(f.operation_view("UNKNOWN")),
    "result-host-info": answered("host_info", f.host_info()),
    "result-host-info-containment": answered(
        "host_info",
        f.host_info(mode="CONTAINMENT", containment_reasons=[{"reason": "store_regression", "detail": "marker ahead"}]),
    ),
    "result-metrics": answered("metrics", f.metrics()),
    "result-sandbox": answered("sandbox", f.sandbox_view()),
    "result-sandboxes": answered(
        "sandboxes", f.page([f.sandbox_view(), f.sandbox_view(sandbox_id=f.OTHER_SANDBOX_ID)], more=True)
    ),
    "result-snapshots": answered("snapshots", f.page([f.snapshot_view(incompatible=["another backend"])])),
    "result-operation": answered("operation", f.operation_view()),
    "result-operations": answered("operations", f.page([f.operation_view(), f.operation_view("FAILED")])),
    "result-run": answered("run", f.run_result()),
    "result-output": answered("output", f.output_chunk()),
}


@pytest.mark.parametrize("name", sorted(GENERATED))
def test_generated_answers_are_valid_and_survive_the_models_unchanged(contract: Contract, name: str) -> None:
    answer = {"protocol": wire.PROTOCOL, "request_id": "req-1", **GENERATED[name]}
    contract.check_response(answer)
    assert to_wire(ResponseEnvelope.model_validate(answer)) == answer


def test_the_response_validator_is_not_vacuous(contract: Contract) -> None:
    good = {"protocol": wire.PROTOCOL, "request_id": "req-1", **accepted(f.operation_view())}
    contract.check_response(good)
    breakages: list[Callable[[dict[str, Any]], object]] = [
        lambda d: d["operation"].pop("state"),
        lambda d: d["operation"].update(state="DONE"),
        lambda d: d.update(answer="MAYBE"),
        lambda d: d.pop("operation"),
    ]
    for mutate in breakages:
        broken = json.loads(json.dumps(good))
        mutate(broken)
        with pytest.raises(SchemaError):
            contract.check_response(broken)
