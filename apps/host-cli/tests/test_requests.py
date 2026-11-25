"""Request envelopes and parameter types: what this client can send, and what it cannot be made to send."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

import factories as f
from acf_cli import requests as rq
from acf_cli.wire import OPERATION_ID_PATTERN, PROTOCOL, OperationClass, OutputStream

TARGET = rq.SandboxTarget(sandbox_id=f.SANDBOX_ID, expected_generation=2)


# ----------------------------------------------------------------------------- identities and time
def test_generated_operation_ids_are_unique_and_within_the_host_grammar() -> None:
    ids = {rq.new_operation_id() for _ in range(200)}
    assert len(ids) == 200
    assert all(re.fullmatch(OPERATION_ID_PATTERN, i) for i in ids)
    assert all(i.startswith("op-") for i in ids)


def test_request_ids_are_fresh_for_every_request() -> None:
    first = rq.read_envelope(rq.host_info(), owner_scope="default")
    second = rq.read_envelope(rq.host_info(), owner_scope="default")
    assert first.request_id != second.request_id


@pytest.mark.parametrize(
    ("moment", "text"),
    [
        (datetime(2026, 11, 18, 10, 0, 0, tzinfo=UTC), "2026-11-18T10:00:00.000Z"),
        (datetime(2026, 11, 18, 10, 0, 0, 123_999, tzinfo=UTC), "2026-11-18T10:00:00.123Z"),
        # an aware time in another zone is converted, never printed with an offset
        (
            datetime(2026, 11, 18, 15, 30, 0, tzinfo=timezone(timedelta(hours=5, minutes=30))),
            "2026-11-18T10:00:00.000Z",
        ),
        (datetime(2027, 1, 1, 0, 30, tzinfo=timezone(timedelta(hours=1))), "2026-12-31T23:30:00.000Z"),
    ],
)
def test_issued_at_is_utc_with_a_literal_z(moment: datetime, text: str) -> None:
    assert rq.utc_timestamp(moment) == text


def test_issued_at_defaults_to_now_in_the_one_spelling_the_host_accepts() -> None:
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", rq.utc_timestamp())


# ----------------------------------------------------------------------------- the envelope of a read
def test_a_read_carries_no_operation_identity() -> None:
    envelope = rq.read_envelope(rq.sandbox_inspect("box"), owner_scope="team-a", on_behalf_of="job:42")
    assert envelope.wire() == {
        "protocol": PROTOCOL,
        "request_id": envelope.request_id,
        "owner_scope": "team-a",
        "on_behalf_of": "job:42",
        "method": "sandbox.inspect",
        "params": {"sandbox": "box"},
    }


def test_a_method_without_params_sends_none() -> None:
    wire = rq.read_envelope(rq.host_info(), owner_scope="default").wire()
    assert "params" not in wire
    assert "on_behalf_of" not in wire


def test_a_list_without_arguments_sends_no_params_and_with_arguments_only_those() -> None:
    assert "params" not in rq.read_envelope(rq.sandbox_list(), owner_scope="default").wire()
    limited = rq.read_envelope(rq.sandbox_list(rq.ListParams(limit=5)), owner_scope="default").wire()
    assert limited["params"] == {"limit": 5}
    cursor = rq.Cursor(lineage=f.LINEAGE, sequence=9)
    since = rq.read_envelope(rq.operation_list(rq.ListParams(changed_since=cursor)), owner_scope="default").wire()
    assert since["params"] == {"changed_since": {"lineage": f.LINEAGE, "sequence": 9}}


@pytest.mark.parametrize("field", ["operation_id", "issued_at", "retry", "wait_ms"])
def test_a_read_cannot_be_given_operation_fields(field: str) -> None:
    values = {"operation_id": "op-12345678", "issued_at": "2026-11-18T10:00:00Z", "retry": True, "wait_ms": 100}
    envelope = {"request_id": "req-1", "owner_scope": "default", "method": "host.info", field: values[field]}
    with pytest.raises(ValidationError, match="is a read"):
        rq.RequestEnvelope.model_validate(envelope)


# ----------------------------------------------------------------------------- the envelope of an operation
def test_an_operation_carries_its_identity_and_the_wait() -> None:
    envelope = rq.operation_envelope(
        rq.sandbox_destroy(TARGET),
        operation_id="op-12345678",
        issued_at="2026-11-18T10:00:00.000Z",
        owner_scope="team-a",
        wait_ms=20_000,
    )
    assert envelope.wire() == {
        "protocol": PROTOCOL,
        "request_id": envelope.request_id,
        "operation_id": "op-12345678",
        "issued_at": "2026-11-18T10:00:00.000Z",
        "owner_scope": "team-a",
        "wait_ms": 20_000,
        "method": "sandbox.destroy",
        "params": {"sandbox_id": f.SANDBOX_ID, "expected_generation": 2},
    }
    assert json.loads(envelope.encode()) == envelope.wire()


def test_a_wait_of_zero_is_sent_as_zero_not_omitted() -> None:
    """Absent means "as long as the host allows"; zero means "answer as soon as the operation is recorded"."""
    envelope = rq.operation_envelope(
        rq.sandbox_stop(TARGET),
        operation_id="op-12345678",
        issued_at="2026-11-18T10:00:00Z",
        owner_scope="a",
        wait_ms=0,
    )
    assert envelope.wire()["wait_ms"] == 0


def test_a_retry_keeps_the_operation_id_and_issued_at_and_sets_only_the_flag() -> None:
    call = rq.sandbox_start(TARGET)
    operation_id, issued_at = "op-12345678", "2026-11-18T10:00:00.000Z"
    first = rq.operation_envelope(call, operation_id=operation_id, issued_at=issued_at, owner_scope="team-a").wire()
    again = rq.operation_envelope(
        call, operation_id=operation_id, issued_at=issued_at, owner_scope="team-a", retry=True
    ).wire()
    assert "retry" not in first
    assert again.pop("retry") is True
    assert first.pop("request_id") != again.pop("request_id")
    assert first == again


@pytest.mark.parametrize("missing", ["operation_id", "issued_at"])
def test_an_operation_cannot_be_sent_without_its_identity(missing: str) -> None:
    envelope = {
        "request_id": "req-1",
        "owner_scope": "default",
        "method": "sandbox.stop",
        "operation_id": "op-12345678",
        "issued_at": "2026-11-18T10:00:00Z",
    }
    del envelope[missing]
    with pytest.raises(ValidationError, match="creates an operation"):
        rq.RequestEnvelope.model_validate(envelope)


@pytest.mark.parametrize(
    "issued_at", ["2026-11-18T10:00:00+01:00", "2026-11-18 10:00:00Z", "2026-11-18T10:00:00", "yesterday", ""]
)
def test_issued_at_must_be_utc_with_z(issued_at: str) -> None:
    with pytest.raises(ValidationError):
        rq.operation_envelope(rq.sandbox_stop(TARGET), operation_id="op-12345678", issued_at=issued_at, owner_scope="a")


@pytest.mark.parametrize("operation_id", ["short", "has space 12", "a" * 65, "op_12345678", "op-../../etc"])
def test_an_operation_id_outside_the_host_grammar_is_never_sent(operation_id: str) -> None:
    with pytest.raises(ValidationError):
        rq.operation_envelope(
            rq.sandbox_stop(TARGET), operation_id=operation_id, issued_at="2026-11-18T10:00:00Z", owner_scope="a"
        )


@pytest.mark.parametrize("scope", ["", "has space", 'quo"te', "new\nline", "semi;colon", "s" * 129, "ünïcode"])
def test_an_owner_scope_outside_the_label_grammar_is_never_sent(scope: str) -> None:
    with pytest.raises(ValidationError):
        rq.read_envelope(rq.host_info(), owner_scope=scope)


def test_owner_scope_and_on_behalf_of_accept_the_whole_label_alphabet() -> None:
    envelope = rq.read_envelope(rq.host_info(), owner_scope="team-a/project_1:prod@eu=1+x", on_behalf_of="user:42@corp")
    assert envelope.wire()["owner_scope"] == "team-a/project_1:prod@eu=1+x"
    with pytest.raises(ValidationError):
        rq.read_envelope(rq.host_info(), owner_scope="a", on_behalf_of="x" * 257)


def test_an_envelope_has_no_authority_field_and_refuses_one() -> None:
    assert "authority" not in rq.RequestEnvelope.model_fields
    with pytest.raises(ValidationError, match="authority"):
        rq.RequestEnvelope.model_validate(
            {"request_id": "req-1", "owner_scope": "a", "method": "host.info", "authority": {"decision": "x"}}
        )


def test_an_envelope_refuses_an_unknown_method_and_another_protocol() -> None:
    with pytest.raises(ValidationError, match="not a method"):
        rq.RequestEnvelope(request_id="req-1", owner_scope="a", method="sandbox.pause")
    with pytest.raises(ValidationError):
        rq.RequestEnvelope.model_validate(
            {"protocol": "acf.host/1", "request_id": "req-1", "owner_scope": "a", "method": "host.info"}
        )


# ----------------------------------------------------------------------------- calls and the method table
def test_methods_know_their_class_and_whether_they_create_an_operation() -> None:
    reads = {name for name, m in rq.METHODS.items() if not m.creates_operation}
    assert reads == {
        "sandbox.inspect",
        "sandbox.list",
        "snapshot.list",
        "operation.get",
        "operation.list",
        "run.inspect",
        "run.output",
        "host.info",
        "host.metrics",
    }
    assert rq.OPERATION_CANCEL.operation_class is OperationClass.CONTAINMENT, "cancelling is itself an operation"
    assert rq.PROFILE_RELOAD.creates_operation
    assert str(rq.EXEC_RUN) == "exec.run"


def test_a_call_pairs_a_method_only_with_its_own_parameter_type() -> None:
    with pytest.raises(TypeError, match="requires params"):
        rq.Call(rq.SANDBOX_DESTROY)
    with pytest.raises(TypeError, match="takes SandboxTarget"):
        rq.Call(rq.SANDBOX_DESTROY, rq.SandboxSelector(sandbox="box"))
    with pytest.raises(TypeError, match="takes no params"):
        rq.Call(rq.HOST_INFO, rq.ListParams())
    assert rq.Call(rq.SANDBOX_LIST).params_wire() is None


def test_absent_optional_fields_are_omitted_from_params() -> None:
    wire = rq.sandbox_start(TARGET).params_wire()
    assert wire == {"sandbox_id": f.SANDBOX_ID, "expected_generation": 2}, "no if_revision: null"
    with_revision = rq.sandbox_start(rq.SandboxTarget(sandbox_id=f.SANDBOX_ID, expected_generation=2, if_revision=0))
    assert with_revision.params_wire() == {"sandbox_id": f.SANDBOX_ID, "expected_generation": 2, "if_revision": 0}


# ----------------------------------------------------------------------------- parameter types
def test_requests_refuse_unknown_fields() -> None:
    with pytest.raises(ValidationError, match="force"):
        rq.SandboxTarget.model_validate({"sandbox_id": f.SANDBOX_ID, "expected_generation": 1, "force": True})
    with pytest.raises(ValidationError, match="shell"):
        rq.CommandSpec.model_validate({"argv": ["true"], "shell": True})


def test_a_mutation_cannot_be_expressed_with_a_name() -> None:
    with pytest.raises(ValidationError):
        rq.SandboxTarget(sandbox_id="box", expected_generation=1)
    with pytest.raises(ValidationError):
        rq.SandboxTarget(sandbox_id=f.SANDBOX_ID.upper(), expected_generation=1)


@pytest.mark.parametrize("generation", [0, -1, 2**64])
def test_generations_start_at_one_and_fit_the_wire_type(generation: int) -> None:
    with pytest.raises(ValidationError):
        rq.SandboxTarget(sandbox_id=f.SANDBOX_ID, expected_generation=generation)


def test_the_network_intent_has_exactly_two_shapes() -> None:
    assert rq.NetworkNone().model_dump(mode="json") == {"mode": "none"}
    entry = rq.AllowEntry(destination=rq.NameDestination(name="pypi.org"), ports=[rq.PortRange(low=443, high=443)])
    allow = rq.NetworkAllowlist(entries=[entry])
    assert allow.model_dump(mode="json") == {
        "mode": "allowlist",
        "entries": [{"destination": {"name": "pypi.org"}, "ports": [{"from": 443, "to": 443}]}],
    }
    with pytest.raises(ValidationError):
        rq.NetworkAllowlist(entries=[])  # an empty allowlist is `none`, and must be said as `none`
    with pytest.raises(ValidationError):
        rq.NetworkNone.model_validate({"mode": "none", "entries": []})
    with pytest.raises(ValidationError):
        rq.AllowEntry(destination=rq.NameDestination(name="pypi.org"), ports=[])


@pytest.mark.parametrize(("low", "high"), [(0, 10), (1, 65536), (500, 400)])
def test_port_ranges_are_ordered_and_within_the_port_space(low: int, high: int) -> None:
    with pytest.raises(ValidationError):
        rq.PortRange(low=low, high=high)


def test_a_command_is_an_argument_vector_with_a_program() -> None:
    assert rq.CommandSpec(argv=["true"]).model_dump(mode="json", exclude_none=True) == {
        "argv": ["true"],
        "env": {},
        "secret_env": {},
        "limits": {},
    }
    for argv in ([], [""]):
        with pytest.raises(ValidationError):
            rq.CommandSpec(argv=argv)


def test_a_secret_is_expressible_only_as_a_reference() -> None:
    command = rq.CommandSpec(argv=["true"], secret_env={"API_TOKEN": rq.SecretRef(ref="ci-token")})
    assert command.model_dump(mode="json")["secret_env"] == {"API_TOKEN": {"ref": "ci-token"}}
    for raw in (
        {"argv": ["true"], "secret_env": {"API_TOKEN": "hunter2"}},
        {"argv": ["true"], "secret_env": {"API_TOKEN": {"value": "hunter2"}}},
        {"argv": ["true"], "secret_env": {"API_TOKEN": {"ref": "ci-token", "value": "hunter2"}}},
        {"argv": ["true"], "secrets": {"API_TOKEN": "hunter2"}},
    ):
        with pytest.raises(ValidationError):
            rq.CommandSpec.model_validate(raw)
    for bad in ("", "../etc/shadow", "a/b", ".hidden", "has space", "x" * 65):
        with pytest.raises(ValidationError):
            rq.SecretRef(ref=bad)


def test_a_variable_is_a_value_or_a_secret_reference_never_both() -> None:
    with pytest.raises(ValidationError, match="not both"):
        rq.CommandSpec(argv=["true"], env={"TOKEN": "x"}, secret_env={"TOKEN": rq.SecretRef(ref="t")})


@pytest.mark.parametrize("limit", [0, 1001, -3])
def test_a_page_size_is_between_one_and_a_thousand(limit: int) -> None:
    with pytest.raises(ValidationError):
        rq.ListParams(limit=limit)


def test_restore_in_place_and_as_new_are_distinct_shapes() -> None:
    snapshot = rq.SnapshotRef(snapshot_id=f.SNAPSHOT_ID, snapshot_generation=1)
    in_place = rq.SnapshotRestoreParams(
        snapshot=snapshot, target=rq.RestoreExisting(sandbox_id=f.SANDBOX_ID, expected_generation=2, if_revision=9)
    )
    assert rq.snapshot_restore(in_place).params_wire() == {
        "snapshot": {"snapshot_id": f.SNAPSHOT_ID, "snapshot_generation": 1},
        "target": {"kind": "existing", "sandbox_id": f.SANDBOX_ID, "expected_generation": 2, "if_revision": 9},
    }
    as_new = rq.SnapshotRestoreParams(snapshot=snapshot, target=rq.RestoreNew(name="copy", lifetime_secs=600))
    sent = rq.snapshot_restore(as_new).params_wire()
    assert sent is not None
    assert sent["target"] == {"kind": "new", "name": "copy", "lifetime_secs": 600}
    with pytest.raises(ValidationError):
        rq.RestoreNew.model_validate({"kind": "new", "sandbox_id": f.SANDBOX_ID})


def test_names_are_aliases_with_a_bounded_alphabet() -> None:
    resources = rq.SandboxResources(vcpus=1, memory_mib=128, disk_mib=64, network=rq.NetworkNone())
    assert rq.SandboxCreateParams(name="v1.2_final-3", image="python", resources=resources).name == "v1.2_final-3"
    for bad in ("", ".hidden", "a/b", "has space", "x" * 64):
        with pytest.raises(ValidationError):
            rq.SandboxCreateParams(name=bad, image="python", resources=resources)
        with pytest.raises(ValidationError):
            rq.SandboxCreateParams(image=bad, resources=resources)


def test_output_is_read_by_stream_and_offset() -> None:
    call = rq.run_output(rq.RunOutputParams(run_id=f.RUN_ID, stream=OutputStream.STDERR, offset=10, max_bytes=5))
    assert call.params_wire() == {"run_id": f.RUN_ID, "stream": "stderr", "offset": 10, "max_bytes": 5}
    with pytest.raises(ValidationError):
        rq.RunOutputParams(run_id="run-1", stream=OutputStream.STDOUT)
