"""Response models: tolerant of what a newer host may add, strict about what this protocol defines.

The versioning rule under test: a receiver treats an unknown enumeration value **as unknown** —
never as a default, never as a known one, and never by crashing.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

import factories as f
from acf_cli import responses as rs
from acf_cli import wire
from acf_cli.client import exit_code_for
from acf_cli.errors import ExitCode
from acf_cli.responses import ResponseEnvelope, to_wire
from acf_cli.wire import Unrecognized
from support import PROTOCOL, accepted, answered, refused


def envelope(body: dict[str, Any]) -> ResponseEnvelope:
    return ResponseEnvelope.model_validate({"protocol": PROTOCOL, "request_id": "req-1", **body})


# ----------------------------------------------------------------------------- the three answers
def test_a_refusal_carries_class_advice_and_message() -> None:
    env = envelope(refused("STATE_CONFLICT", "sandbox is busy", "AFTER_CHANGE"))
    assert env.answer is wire.Answer.REFUSED
    assert env.refusal is not None
    assert env.refusal.failure_class is wire.FailureClass.STATE_CONFLICT
    assert env.refusal.retry is wire.RetryAdvice.AFTER_CHANGE
    assert env.refusal.message == "sandbox is busy"
    assert (env.operation, env.result) == (None, None)
    assert str(env.as_of) == f"{f.LINEAGE}:41"


def test_a_refusal_that_consulted_no_state_has_no_as_of_and_may_have_no_request_id() -> None:
    env = ResponseEnvelope.model_validate(
        {"protocol": PROTOCOL, "request_id": None, **refused("AUTHENTICATION_FAILED", "not enrolled", as_of=None)}
    )
    assert env.as_of is None
    assert env.request_id is None


def test_an_operation_answer_is_typed_down_to_its_result() -> None:
    env = envelope(accepted(f.operation_view(result=f.sandbox_body(state="PROVISIONING"))))
    assert env.answer is wire.Answer.OPERATION
    view = env.operation
    assert view is not None
    assert view.state is wire.OperationState.SUCCEEDED
    assert view.effect is wire.Effect.APPLIED
    assert view.operation_type is wire.OperationType.SANDBOX_CREATE
    assert isinstance(view.result, rs.SandboxBody)
    assert view.result.data.state is wire.LifecycleState.PROVISIONING
    assert view.sandbox == (f.SANDBOX_ID, 1), "a pair on the wire is a pair here"
    assert view.tags.owner_scope == "default"


@pytest.mark.parametrize(
    ("kind", "data", "model"),
    [
        ("host_info", f.host_info(), rs.HostInfoBody),
        ("metrics", f.metrics(), rs.MetricsBody),
        ("sandbox", f.sandbox_view(), rs.SandboxBody),
        ("sandboxes", f.page([f.sandbox_view()]), rs.SandboxesBody),
        ("snapshots", f.page([f.snapshot_view()]), rs.SnapshotsBody),
        ("operation", f.operation_view(), rs.OperationBody),
        ("operations", f.page([f.operation_view()]), rs.OperationsBody),
        ("run", f.run_result(), rs.RunBody),
        ("output", f.output_chunk(), rs.OutputBody),
    ],
)
def test_every_read_result_has_its_own_type(kind: str, data: Any, model: type[object]) -> None:
    env = envelope(answered(kind, data))
    assert env.answer is wire.Answer.RESULT
    assert isinstance(env.result, model)


@pytest.mark.parametrize(
    ("body", "model"),
    [
        (f.sandbox_body(), rs.SandboxBody),
        (f.snapshot_body(), rs.SnapshotBody),
        (f.run_body(), rs.RunBody),
        (f.host_change_body(mode="DRAINING"), rs.HostChangeBody),
    ],
)
def test_every_operation_result_has_its_own_type(body: dict[str, Any], model: type[object]) -> None:
    view = envelope(accepted(f.operation_view(result=body))).operation
    assert view is not None
    assert isinstance(view.result, model)


def test_an_answer_without_its_body_is_not_an_answer() -> None:
    for broken in (
        {"answer": "REFUSED"},
        {"answer": "OPERATION", "refusal": refused("NOT_FOUND")["refusal"]},
        {"answer": "RESULT", "operation": f.operation_view()},
    ):
        with pytest.raises(ValidationError, match="without its"):
            envelope(broken)


# ----------------------------------------------------------------------------- unknown fields
def test_unknown_fields_are_kept_at_every_level_and_survive_a_round_trip() -> None:
    sandbox = f.sandbox_view(gpu={"model": "x1", "count": 2})
    sandbox["resources"]["hugepages"] = True
    sandbox["image"]["signature"] = "sig-1"
    view = f.operation_view(result={"type": "sandbox", "data": sandbox, "generated_by": "v9"}, priority=7)
    answer = {"protocol": PROTOCOL, "request_id": "req-1", "trace": "abc", **accepted(view)}
    answer["as_of"] = {**f.AS_OF, "epoch": 3}
    env = ResponseEnvelope.model_validate(answer)
    assert to_wire(env) == answer, "nothing a newer host says is dropped from --json output"
    assert env.operation is not None
    assert isinstance(env.operation.result, rs.SandboxBody)
    assert env.operation.result.data.state is wire.LifecycleState.READY, "known fields are still typed"


def test_unknown_fields_in_a_refusal_and_a_page_are_kept() -> None:
    refusal = refused("RESOURCE_EXHAUSTED", "rate limit", "SAME_REQUEST_LATER")
    refusal["refusal"]["retry_after_ms"] = 1500
    assert to_wire(envelope(refusal))["refusal"]["retry_after_ms"] == 1500
    page = f.page([f.sandbox_view()])
    page["total"] = 99
    assert to_wire(envelope(answered("sandboxes", page)))["result"]["data"]["total"] == 99


# ----------------------------------------------------------------------------- unknown words
def test_an_unknown_operation_state_is_kept_as_unknown_and_is_no_known_state() -> None:
    view = envelope(accepted(f.operation_view("SUSPENDED", effect=None, cleanup=None))).operation
    assert view is not None
    assert isinstance(view.state, Unrecognized)
    assert not isinstance(view.state, wire.OperationState)
    assert view.state == "SUSPENDED", "it prints and serialises as what the host sent"
    assert str(view.state) not in [known.value for known in wire.OperationState]
    assert not view.succeeded
    assert not view.is_terminal, "no effect is stated, so it has not ended as far as anyone can tell"
    assert exit_code_for(view) is ExitCode.UNRESOLVED


def test_an_unknown_terminal_state_is_neither_success_nor_failure() -> None:
    """The host states an effect only once an operation is terminal: that is how an unknown state is known final."""
    view = envelope(accepted(f.operation_view("EXPIRED", effect="NOT_APPLIED", cleanup="COMPLETE"))).operation
    assert view is not None
    assert view.is_terminal
    assert not view.succeeded
    assert exit_code_for(view) is ExitCode.UNKNOWN, "never mapped to SUCCEEDED, and never to FAILED either"


@pytest.mark.parametrize(
    ("field", "known"),
    [
        ("effect", wire.Effect),
        ("cleanup", wire.Cleanup),
        ("cancelled_by", wire.CancelledBy),
        ("issuer", wire.Issuer),
        ("operation_type", wire.OperationType),
    ],
)
def test_unknown_words_in_an_operation_are_kept_verbatim(field: str, known: type[object]) -> None:
    sent = f.operation_view("FAILED")
    sent[field] = "SOMETHING_NEW"
    view = envelope(accepted(sent)).operation
    assert view is not None
    value = getattr(view, field)
    assert isinstance(value, Unrecognized)
    assert not isinstance(value, known)
    assert to_wire(view)[field] == "SOMETHING_NEW"


def test_unknown_failure_class_and_retry_advice_are_kept_verbatim() -> None:
    env = envelope(refused("QUOTA_EXCEEDED", "tenant quota", "AFTER_PAYMENT"))
    assert env.refusal is not None
    assert isinstance(env.refusal.failure_class, Unrecognized)
    assert isinstance(env.refusal.retry, Unrecognized)
    assert str(env.refusal.retry) not in [known.value for known in wire.RetryAdvice]
    assert to_wire(env)["refusal"] == {"class": "QUOTA_EXCEEDED", "retry": "AFTER_PAYMENT", "message": "tenant quota"}


def test_unknown_words_deep_inside_views_are_kept_verbatim() -> None:
    sandbox = f.sandbox_view(state="HIBERNATING")
    sandbox["resources"]["network"] = {"mode": "proxy", "upstream": "corp-proxy"}
    run = f.run_result(status="OOM_KILLED", evidence_status="PARTIAL")
    run["stdout"]["status"] = "COMPRESSED"
    run["artifacts"] = [{**f.artifact(), "kind": "core_dump"}]
    parsed_sandbox = rs.SandboxView.model_validate(sandbox)
    parsed_run = rs.RunResult.model_validate(run)
    assert isinstance(parsed_sandbox.state, Unrecognized)
    assert isinstance(parsed_sandbox.resources.network.mode, Unrecognized)
    assert to_wire(parsed_sandbox)["resources"]["network"] == {"mode": "proxy", "upstream": "corp-proxy"}
    assert isinstance(parsed_run.status, Unrecognized)
    assert isinstance(parsed_run.evidence_status, Unrecognized)
    assert isinstance(parsed_run.stdout.status, Unrecognized)
    assert isinstance(parsed_run.artifacts[0].kind, Unrecognized)
    assert not parsed_run.exited_cleanly, (
        "a status this client does not know is not a clean exit, whatever the exit code"
    )


def test_unknown_host_mode_snapshot_state_and_network_mode_are_kept() -> None:
    info = rs.HostInfo.model_validate(
        f.host_info(
            mode="MAINTENANCE", capabilities={**f.host_info()["capabilities"], "network_modes": ["none", "mesh"]}
        )
    )
    assert isinstance(info.mode, Unrecognized)
    assert [type(m).__name__ for m in info.capabilities.network_modes] == ["NetworkMode", "Unrecognized"]
    snapshot = rs.SnapshotView.model_validate(f.snapshot_view(state="ARCHIVED"))
    assert isinstance(snapshot.state, Unrecognized)
    chunk = rs.OutputChunk.model_validate(f.output_chunk(stream="combined", completeness="SAMPLED"))
    assert isinstance(chunk.stream, Unrecognized)
    assert isinstance(chunk.completeness, Unrecognized)


def test_a_result_type_this_client_does_not_know_is_kept_with_its_payload() -> None:
    env = envelope(answered("usage_report", {"cpu_seconds": 12}))
    assert isinstance(env.result, rs.UnrecognizedBody)
    assert env.result.type == "usage_report"
    assert env.result.data == {"cpu_seconds": 12}
    view = envelope(accepted(f.operation_view(result={"type": "volume", "data": {"id": "vol-1"}}))).operation
    assert view is not None
    assert isinstance(view.result, rs.UnrecognizedBody)
    assert to_wire(view)["result"] == {"type": "volume", "data": {"id": "vol-1"}}


def test_an_unknown_answer_kind_parses_and_is_marked_unknown() -> None:
    env = envelope({"answer": "DEFERRED", "ticket": "t-1"})
    assert isinstance(env.answer, Unrecognized)
    assert (env.refusal, env.operation, env.result) == (None, None, None)
    assert to_wire(env)["ticket"] == "t-1"


def test_known_words_stay_enumeration_members() -> None:
    view = rs.OperationView.model_validate(f.operation_view("CANCELLED", cancelled_by="SUPERSEDED"))
    assert view.state is wire.OperationState.CANCELLED
    assert view.cancelled_by is wire.CancelledBy.SUPERSEDED
    assert view.cleanup is wire.Cleanup.COMPLETE
    assert view.is_terminal


# ----------------------------------------------------------------------------- where tolerance stops
@pytest.mark.parametrize(
    "broken",
    [
        {"state": 7},  # a vocabulary value that is not even a string
        {"state": None},
        {"operation_id": None},
        {"revision": "many"},
        {"tags": "local-operator/default"},
        {"sandbox": [f.SANDBOX_ID]},  # a pair with one element
    ],
)
def test_a_known_field_of_the_wrong_type_is_a_violation(broken: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        rs.OperationView.model_validate(f.operation_view(**broken))


def test_a_known_result_type_with_the_wrong_payload_is_a_violation_not_an_unknown_result() -> None:
    with pytest.raises(ValidationError):
        rs.OperationView.model_validate(f.operation_view(result={"type": "sandbox", "data": {"sandbox_id": "x"}}))
    with pytest.raises(ValidationError):
        envelope(answered("operation", {"operation_id": f.OPERATION_ID}))


@pytest.mark.parametrize("missing", ["operation_id", "state", "tags", "target", "revision"])
def test_a_missing_required_field_is_a_violation(missing: str) -> None:
    view = f.operation_view()
    del view[missing]
    with pytest.raises(ValidationError):
        rs.OperationView.model_validate(view)


def test_optional_fields_may_be_absent_altogether() -> None:
    view = f.operation_view("IN_PROGRESS")
    for optional in (
        "effect",
        "cleanup",
        "cancelled_by",
        "failure",
        "result",
        "run_id",
        "snapshot",
        "step",
        "on_behalf_of",
    ):
        del view[optional]
    parsed = rs.OperationView.model_validate(view)
    assert (parsed.effect, parsed.result) == (None, None)
    assert to_wire(parsed) == view, "what the host did not send is not invented on the way out"


def test_a_host_that_predates_the_newer_capability_fields_is_still_read() -> None:
    info = f.host_info()
    del info["capabilities"]["identifier_slots"]
    del info["capabilities"]["stop_grace_ms"]
    parsed = rs.HostInfo.model_validate(info)
    assert parsed.capabilities.identifier_slots is None
    assert to_wire(parsed) == info


# ----------------------------------------------------------------------------- derived facts
@pytest.mark.parametrize(
    ("state", "terminal"),
    [
        ("ACCEPTED", False),
        ("IN_PROGRESS", False),
        ("RECOVERING", False),
        ("SUCCEEDED", True),
        ("FAILED", True),
        ("CANCELLED", True),
        ("UNKNOWN", True),
    ],
)
def test_terminal_states(state: str, terminal: bool) -> None:
    assert rs.OperationView.model_validate(f.operation_view(state)).is_terminal is terminal


@pytest.mark.parametrize(
    ("over", "clean"),
    [
        ({}, True),
        ({"exit_code": 3}, False),
        ({"status": "SIGNALED", "exit_code": None, "signal": 9}, False),
        ({"status": "TIMED_OUT", "exit_code": None}, False),
        ({"status": "CANCELLED", "exit_code": None}, False),
        ({"status": "UNKNOWN", "exit_code": None}, False),
        ({"status": "SPAWN_FAILED", "exit_code": None}, False),
    ],
)
def test_only_an_exit_with_status_zero_is_a_clean_exit(over: dict[str, Any], clean: bool) -> None:
    assert rs.RunResult.model_validate(f.run_result(**over)).exited_cleanly is clean


def test_small_values_print_the_way_people_write_them() -> None:
    assert rs.ProfileId.model_validate(f.profile_id()).short() == "default@2.0.0#cdcdcdcdcdcd"
    assert str(rs.Tags.model_validate(f.tags("tls-caller", "team-a"))) == "tls-caller/team-a"
    assert str(rs.SnapshotRefView(snapshot_id=f.SNAPSHOT_ID, snapshot_generation=2)) == f"{f.SNAPSHOT_ID}@2"
    entries = rs.NetworkIntentView.model_validate(f.network_allowlist()).entries
    assert entries is not None
    assert [str(e) for e in entries] == ["pypi.org:443", "198.51.100.0/24:5432-5433"]


def test_models_are_immutable() -> None:
    view = rs.OperationView.model_validate(f.operation_view())
    with pytest.raises(ValidationError):
        view.state = wire.OperationState.FAILED  # type: ignore[misc]


def test_parsing_from_bytes_gives_the_same_model_as_parsing_from_data() -> None:
    answer = {"protocol": PROTOCOL, "request_id": "req-1", **accepted(f.operation_view(result=f.run_body()))}
    assert ResponseEnvelope.model_validate_json(json.dumps(answer).encode()) == ResponseEnvelope.model_validate(answer)
