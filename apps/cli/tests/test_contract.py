"""The client's models cannot drift from the host's wire contract.

The Rust host emits JSON Schemas (``acf-host schema``; committed under ``schemas/``). Drift in either
direction is a failure here, in CI, rather than a confusing runtime error:

* every request the client can build validates against ``request.schema.json``;
* the set of methods the client knows equals the set the host serves;
* every field the host can send for a response type is modelled (or consciously excluded);
* values that drive control flow (statuses, failure classes the client branches on) exist in the schema;
* the factories the other tests rely on are valid against the schema themselves.
"""

from __future__ import annotations

import typing
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ValidationError

import factories as f
from acf_cli import models as m
from acf_cli.client import DEFAULT_SOCKET, _rejection_hint
from acf_cli.resolve import LIVE_STATES
from support import error_body, respond


def schema_validator(schema: dict[str, Any]) -> Draft202012Validator:
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def enum_values(defn: dict[str, Any]) -> set[str]:
    """String values of an enum, whether schemars emitted ``enum`` or a ``oneOf`` of ``const``/``enum``."""
    if "enum" in defn:
        return {str(v) for v in defn["enum"]}
    if "const" in defn:
        return {str(defn["const"])}
    out: set[str] = set()
    for key in ("oneOf", "anyOf"):
        for part in defn.get(key, []):
            out |= enum_values(part)
    return out


# ----------------------------------------------------------------------------- requests
TARGET = m.SandboxTarget(sandbox_id=f.SANDBOX_ID, expected_generation=3)
SNAP_REF = m.SnapshotRef(snapshot_id=f.SNAPSHOT_ID, snapshot_generation=1)

SAMPLES: dict[type[m.Body], m.Body] = {
    m.HostInfoRequest: m.HostInfoRequest(),
    m.MetricsRequest: m.MetricsRequest(),
    m.PolicyReloadRequest: m.PolicyReloadRequest(),
    m.SandboxListRequest: m.SandboxListRequest(),
    m.SnapshotListRequest: m.SnapshotListRequest(),
    m.SandboxCreateRequest: m.SandboxCreateRequest(
        params=m.SandboxCreateParams(
            name="work",
            image="python",
            resources=m.SandboxResources(vcpus=2, memory_mib=4096, disk_mib=1024, network="none"),
        )
    ),
    m.SandboxStartRequest: m.SandboxStartRequest(params=TARGET),
    m.SandboxStopRequest: m.SandboxStopRequest(params=TARGET),
    m.SandboxDestroyRequest: m.SandboxDestroyRequest(params=TARGET),
    m.SandboxInspectRequest: m.SandboxInspectRequest(params=m.SandboxSelector(sandbox="work")),
    m.ExecRequest: m.ExecRequest(
        params=m.ExecParams(
            sandbox_id=f.SANDBOX_ID,
            expected_generation=3,
            command=m.CommandSpec(
                argv=["python", "x.py"],
                env={"LANG": "C"},
                cwd="/work",
                limits=m.RunLimitsRequest(timeout_ms=5000, max_pids=64, max_stdout_bytes=1024, max_stderr_bytes=2048),
            ),
        )
    ),
    m.SnapshotCreateRequest: m.SnapshotCreateRequest(
        params=m.SnapshotCreateParams(sandbox_id=f.SANDBOX_ID, expected_generation=3, name="base")
    ),
    m.SnapshotRestoreRequest: m.SnapshotRestoreRequest(
        params=m.SnapshotRestoreParams(
            snapshot=SNAP_REF, target=m.RestoreExisting(sandbox_id=f.SANDBOX_ID, expected_generation=3)
        )
    ),
    m.SnapshotDeleteRequest: m.SnapshotDeleteRequest(params=SNAP_REF),
    m.OperationGetRequest: m.OperationGetRequest(params=m.OperationSelector(operation_id=f.OP_ID)),
    m.OperationCancelRequest: m.OperationCancelRequest(params=m.OperationSelector(operation_id=f.OP_ID)),
    m.RunInspectRequest: m.RunInspectRequest(params=m.RunSelector(run_id=f.RUN_ID)),
}


def envelope_of(body: m.Body, *, operation_id: str | None = None) -> dict[str, Any]:
    env: dict[str, Any] = {"protocol": m.PROTOCOL, "request_id": "req-0123456789ab", "body": body.wire()}
    if operation_id is not None:
        env["operation_id"] = operation_id
    return env


def test_every_request_type_has_a_sample() -> None:
    assert set(SAMPLES) == set(m.ALL_REQUEST_TYPES), "add a sample for the new request type"


@pytest.mark.parametrize("request_type", m.ALL_REQUEST_TYPES, ids=lambda t: t.method)
def test_every_request_the_client_builds_validates_against_the_host_schema(
    request_schema: dict[str, Any], request_type: type[m.Body]
) -> None:
    body = SAMPLES[request_type]
    validator = schema_validator(request_schema)
    validator.validate(envelope_of(body))
    validator.validate(envelope_of(body, operation_id=f.OP_ID))
    assert body.method == request_type.method


def test_the_client_and_the_host_serve_the_same_methods(request_schema: dict[str, Any]) -> None:
    host_methods = {option["properties"]["method"]["const"] for option in request_schema["$defs"]["Request"]["oneOf"]}
    client_methods = {t.method for t in m.ALL_REQUEST_TYPES}
    assert client_methods == host_methods


def test_the_schema_really_is_strict_so_the_checks_above_mean_something(request_schema: dict[str, Any]) -> None:
    validator = schema_validator(request_schema)
    bad_by_name = envelope_of(m.SandboxListRequest())
    bad_by_name["body"] = {"method": "sandbox_destroy", "params": {"sandbox": "work"}}
    assert not validator.is_valid(bad_by_name), "destructive operations must not be expressible by name"
    extra_param = envelope_of(SAMPLES[m.SandboxDestroyRequest])
    extra_param["body"]["params"]["force"] = True
    assert not validator.is_valid(extra_param)
    unknown_method = envelope_of(m.SandboxListRequest())
    unknown_method["body"] = {"method": "rm_rf"}
    assert not validator.is_valid(unknown_method)
    extra_envelope_field = envelope_of(m.SandboxListRequest())
    extra_envelope_field["sneaky"] = 1
    assert not validator.is_valid(extra_envelope_field)


def test_the_client_cannot_even_construct_what_the_host_would_refuse() -> None:
    with pytest.raises(ValidationError):
        m.SandboxTarget(sandbox="by-name")  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        m.SandboxTarget(sandbox_id=f.SANDBOX_ID, expected_generation=1, force=True)  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        m.SandboxTarget(sandbox_id="sbx-nothex", expected_generation=1)
    with pytest.raises(ValidationError):
        m.SandboxTarget(sandbox_id=f.SANDBOX_ID, expected_generation=0)  # generations start at 1
    with pytest.raises(ValidationError):
        m.SandboxResources(vcpus=1, memory_mib=1, disk_mib=1, network="host")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        m.OperationSelector(operation_id="short")


def test_the_phase_1_network_vocabulary_is_none_on_both_sides(
    request_schema: dict[str, Any], response_schema: dict[str, Any]
) -> None:
    # When a later phase adds a network mode this fails on purpose: the CLI must learn it deliberately.
    assert enum_values(request_schema["$defs"]["NetworkMode"]) == {"none"}
    assert enum_values(response_schema["$defs"]["NetworkMode"]) == {"none"}


# ----------------------------------------------------------------------------- responses
#: Response types whose full field set the client models, by schema ``$defs`` name.
MODELLED: dict[str, type[BaseModel]] = {
    "HostInfo": m.HostInfo,
    "SandboxView": m.SandboxView,
    "SnapshotView": m.SnapshotView,
    "RunResult": m.RunResult,
    "OperationView": m.OperationView,
    "OutputCapture": m.OutputCapture,
    "RunMetrics": m.RunMetrics,
    "ResourceEvidence": m.ResourceEvidence,
    "FailureInfo": m.FailureInfo,
    "ArtifactRef": m.ArtifactRef,
    "ImageRef": m.ImageRef,
    "PolicyId": m.PolicyId,
    "ProcessIdentity": m.ProcessIdentity,
    "BackendIdentity": m.BackendIdentity,
    "CapabilityProfile": m.CapabilityProfile,
    "SandboxResources": m.SandboxResources,
    "SnapshotRef": m.SnapshotRef,
    "ErrorBody": m.ErrorBody,
}


def wire_names(model: type[BaseModel]) -> set[str]:
    return {field.alias or name for name, field in model.model_fields.items()}


def required_wire_names(model: type[BaseModel]) -> set[str]:
    return {field.alias or name for name, field in model.model_fields.items() if field.is_required()}


@pytest.mark.parametrize("def_name", sorted(MODELLED))
def test_every_field_the_host_can_send_is_modelled(response_schema: dict[str, Any], def_name: str) -> None:
    defn = response_schema["$defs"][def_name]
    model = MODELLED[def_name]
    assert wire_names(model) == set(defn["properties"]), (
        f"{def_name}: the host and the client disagree about the fields; "
        "model the new field (or remove the old one) in acf_cli/models.py"
    )


@pytest.mark.parametrize("def_name", sorted(MODELLED))
def test_the_client_never_requires_a_field_the_host_may_omit(response_schema: dict[str, Any], def_name: str) -> None:
    defn = response_schema["$defs"][def_name]
    extra = required_wire_names(MODELLED[def_name]) - set(defn.get("required", []))
    assert not extra, f"{def_name}: the client requires {sorted(extra)} but the host may omit them"


def test_the_response_body_variants_match(response_schema: dict[str, Any]) -> None:
    host_types = {o["properties"]["type"]["const"] for o in response_schema["$defs"]["ResponseBody"]["oneOf"]}
    union = typing.get_args(m.ResponseBody)[0]
    client_types = set()
    for cls in typing.get_args(union):
        client_types |= set(typing.get_args(cls.model_fields["type"].annotation))
    assert client_types == host_types


def test_statuses_the_client_branches_on_match_the_schema(response_schema: dict[str, Any]) -> None:
    assert {s.value for s in m.OperationStatus} == enum_values(response_schema["$defs"]["OperationStatus"])


def test_failure_classes_the_client_branches_on_exist(response_schema: dict[str, Any]) -> None:
    known = enum_values(response_schema["$defs"]["FailureClass"])
    used = {"NOT_FOUND", "AUTHORIZATION", "ADMISSION_REJECTED", "STATE_CONFLICT", "VALIDATION"}
    assert used <= known
    assert all(_rejection_hint(c) is not None for c in used)
    assert _rejection_hint("INTERNAL") is None


def test_lifecycle_states_the_client_treats_as_live_exist(response_schema: dict[str, Any]) -> None:
    assert set(LIVE_STATES) <= enum_values(response_schema["$defs"]["LifecycleState"])


def test_string_vocabularies_the_renderer_compares_against_exist(response_schema: dict[str, Any]) -> None:
    defs = response_schema["$defs"]
    assert "COMPLETE" in enum_values(defs["OutputStatus"])
    assert "SUCCEEDED" in enum_values(defs["RunOutcome"])


# ----------------------------------------------------------------------------- factories are valid
FACTORY_BODIES: dict[str, dict[str, Any]] = {
    "host_info": f.body("host_info", f.host_info()),
    "sandbox": f.body("sandbox", f.sandbox_view()),
    "sandboxes": f.body("sandboxes", [f.sandbox_view(), f.sandbox_view(sandbox_id=f.OTHER_SANDBOX_ID, name="x")]),
    "run": f.body("run", f.run_result()),
    "snapshot": f.body("snapshot", f.snapshot_view()),
    "snapshots": f.body("snapshots", [f.snapshot_view()]),
    "operation": f.body("operation", f.operation_view()),
    "metrics": f.body("metrics", {"counters": {"a": 1}, "gauges": {"live_sandboxes": 0}}),
    "ack": f.body("ack"),
}


@pytest.mark.parametrize("kind", sorted(FACTORY_BODIES))
def test_factories_are_valid_against_the_schema_and_parse_into_the_models(
    response_schema: dict[str, Any], kind: str
) -> None:
    wire = respond({"request_id": "r"}, "SUCCEEDED", result=FACTORY_BODIES[kind])
    schema_validator(response_schema).validate(wire)
    parsed = m.ResponseEnvelope.model_validate(wire)
    assert parsed.result is not None
    assert parsed.result.type == kind


def test_the_error_envelope_shape_is_valid_against_the_schema(response_schema: dict[str, Any]) -> None:
    wire = respond(
        {"request_id": "r", "operation_id": f.OP_ID},
        "UNKNOWN",
        error=error_body("TIMEOUT_UNKNOWN", "lost", side_effect="possible", outcome_unknown=True),
    )
    schema_validator(response_schema).validate(wire)
    parsed = m.ResponseEnvelope.model_validate(wire)
    assert parsed.error is not None
    assert (parsed.error.error_class, parsed.error.outcome_unknown) == ("TIMEOUT_UNKNOWN", True)


# ----------------------------------------------------------------------------- tolerance rules
def test_unknown_response_fields_are_ignored_so_an_additive_host_change_does_not_break_us() -> None:
    wire = respond({"request_id": "r"}, "SUCCEEDED", result=f.body("sandbox", f.sandbox_view(brand_new_field=[1, 2])))
    wire["also_new"] = True
    parsed = m.ResponseEnvelope.model_validate(wire)
    assert isinstance(parsed.body(), m.SandboxView)


def test_an_unknown_status_is_not_tolerated_because_it_drives_control_flow() -> None:
    with pytest.raises(ValidationError):
        m.ResponseEnvelope.model_validate(respond({"request_id": "r"}, "MOSTLY_DONE"))


def test_an_unknown_body_type_is_not_tolerated() -> None:
    with pytest.raises(ValidationError):
        m.ResponseEnvelope.model_validate(
            respond({"request_id": "r"}, "SUCCEEDED", result={"type": "mystery", "data": 1})
        )


def test_a_generation_of_zero_from_the_host_is_a_contract_violation() -> None:
    with pytest.raises(ValidationError):
        m.SandboxView.model_validate(f.sandbox_view(generation=0))


def test_is_final_matches_the_host_definition() -> None:
    finals = {s for s in m.OperationStatus if s.is_final}
    assert finals == {
        m.OperationStatus.SUCCEEDED,
        m.OperationStatus.FAILED,
        m.OperationStatus.CANCELLED,
        m.OperationStatus.CONFLICT,
        m.OperationStatus.REJECTED,
    }
    assert not m.OperationStatus.UNKNOWN.is_final, "UNKNOWN is first-class and never final"


def test_the_cli_defaults_to_the_socket_the_host_defaults_to(host_config_schema: dict[str, Any]) -> None:
    """A fresh install must work with no flags: client and server defaults are one fact, kept in two languages."""
    paths = host_config_schema["$defs"]["Paths"]["properties"]
    assert paths["socket_path"]["default"] == DEFAULT_SOCKET
