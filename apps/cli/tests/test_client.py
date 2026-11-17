"""The caller's half of the operation protocol: **observe, never repeat**.

Each test scripts a real Unix-socket host (see ``support.py``) and a fake clock, and then asserts
two things: what the client *returned or raised*, and — just as important — which requests it
*sent*. "Sent the mutation exactly once" is the property that keeps a lost response from turning
into a duplicate sandbox, a duplicate snapshot or a second run.
"""

from __future__ import annotations

import os
import re
import socket
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import factories as f
from acf_cli import models as m
from acf_cli.client import (
    ClientConfig,
    HostClient,
    exit_code_for_status,
    new_operation_id,
    raise_for_status,
)
from acf_cli.errors import (
    ExitCode,
    HostUnreachable,
    InvalidArgument,
    MutationInterrupted,
    OperationFailed,
    OutcomeUnknown,
    ProtocolViolation,
    Rejected,
    TransportError,
)
from support import (
    HEADER,
    ClosedBeforeRead,
    DenyUnread,
    FakeClock,
    Lost,
    Partial,
    RawBytes,
    Reply,
    ScriptedHost,
    Stall,
    bind_unix,
    error_body,
    respond,
)

HostFactory = Callable[..., ScriptedHost]

CREATE = m.SandboxCreateRequest(
    params=m.SandboxCreateParams(
        image="python", resources=m.SandboxResources(vcpus=1, memory_mib=512, disk_mib=1024, network="none")
    )
)
INSPECT = m.SandboxInspectRequest(params=m.SandboxSelector(sandbox="work"))
UNKNOWN_ERROR = error_body("TIMEOUT_UNKNOWN", "the host deadline passed", side_effect="possible", outcome_unknown=True)


# ----------------------------------------------------------------------------- scripted answers
def sandbox_ok(**over: Any) -> Reply:
    return Reply(lambda req: respond(req, "SUCCEEDED", result=f.body("sandbox", f.sandbox_view(**over))))


def answer(status: str, **kw: Any) -> Reply:
    """Answer a *mutation* with ``status``."""
    return Reply(lambda req: respond(req, status, **kw))


def observed(status: str, **kw: Any) -> Reply:
    """Answer an ``operation_get`` for whatever operation it asks about."""
    return Reply(lambda req: respond(req, status, operation_id=req["body"]["params"]["operation_id"], **kw))


def never_heard_of_it() -> Reply:
    return observed("REJECTED", error=error_body("NOT_FOUND", "operation does not exist"))


def sandbox_result() -> dict[str, Any]:
    return f.body("sandbox", f.sandbox_view())


# ----------------------------------------------------------------------------- reads
def test_a_read_is_one_round_trip_with_a_well_formed_envelope(client: HostClient, host_factory: HostFactory) -> None:
    host = host_factory(sandbox_ok())
    env = client.read(INSPECT)
    assert isinstance(env.body(), m.SandboxView)
    (req,) = host.requests
    assert req["protocol"] == "acf.host/1"
    assert re.fullmatch(r"req-[0-9a-f]{12}", req["request_id"])
    assert "operation_id" not in req, "a read does not create an operation"
    assert req["body"] == {"method": "sandbox_inspect", "params": {"sandbox": "work"}}


def test_a_refused_read_raises_with_the_failure_class_and_an_actionable_hint(
    client: HostClient, host_factory: HostFactory
) -> None:
    host_factory(answer("REJECTED", error=error_body("NOT_FOUND", "no sandbox `work`")))
    with pytest.raises(Rejected) as caught:
        client.read(INSPECT)
    assert caught.value.failure_class == "NOT_FOUND"
    assert caught.value.exit_code == ExitCode.REJECTED
    assert caught.value.hint is not None
    assert "list" in caught.value.hint


def test_mutate_refuses_a_non_mutating_request(client: HostClient) -> None:
    with pytest.raises(ValueError, match="not a mutating request"):
        client.mutate(INSPECT)


def test_operation_ids_fit_the_hosts_grammar_and_are_unique() -> None:
    ids = {new_operation_id() for _ in range(500)}
    assert len(ids) == 500
    assert all(re.fullmatch(r"[A-Za-z0-9-]{8,64}", i) for i in ids)
    assert all(m.OperationSelector(operation_id=i) for i in ids)


# ----------------------------------------------------------------------------- the happy mutation
def test_a_mutation_announces_its_operation_id_before_it_is_sent_and_sends_it(
    client: HostClient, host_factory: HostFactory
) -> None:
    host = host_factory(sandbox_ok())
    announced: list[tuple[str, int]] = []
    env = client.mutate(CREATE, on_operation=lambda op: announced.append((op, len(host.requests))))
    assert env.status == m.OperationStatus.SUCCEEDED
    (op_id, requests_seen_at_announcement) = announced[0]
    assert requests_seen_at_announcement == 0, (
        "an interrupt handler must learn the id before anything can have happened"
    )
    assert host.requests[0]["operation_id"] == op_id


class _CtrlC(HostClient):
    """A client whose user presses Ctrl-C while a request is on the wire."""

    def roundtrip(
        self, body: m.Body, *, operation_id: str | None = None, io_timeout_s: float | None = None
    ) -> m.ResponseEnvelope:
        raise KeyboardInterrupt


def test_ctrl_c_during_a_mutation_is_still_a_keyboard_interrupt_but_names_the_operation() -> None:
    announced: list[str] = []
    with pytest.raises(KeyboardInterrupt) as caught:
        _CtrlC(ClientConfig(socket_path=Path("/nonexistent"))).mutate(CREATE, on_operation=announced.append)
    assert isinstance(caught.value, MutationInterrupted), "the handler must learn which operation was in flight"
    assert caught.value.operation_id == announced[0], "the id it reports is the one that was announced (and sent)"


def test_ctrl_c_during_a_read_stays_a_plain_keyboard_interrupt() -> None:
    with pytest.raises(KeyboardInterrupt) as caught:
        _CtrlC(ClientConfig(socket_path=Path("/nonexistent"))).read(m.SandboxListRequest())
    assert not isinstance(caught.value, MutationInterrupted), (
        "a read creates no operation, so there is nothing to observe"
    )


def test_a_caller_supplied_operation_id_is_used_verbatim(client: HostClient, host_factory: HostFactory) -> None:
    host = host_factory(sandbox_ok())
    client.mutate(CREATE, operation_id="op-fixed-0001")
    assert host.requests[0]["operation_id"] == "op-fixed-0001"


@pytest.mark.parametrize("status", ["FAILED", "CANCELLED", "REJECTED", "CONFLICT"])
def test_any_final_status_is_returned_as_is_and_not_retried(
    client: HostClient, host_factory: HostFactory, status: str
) -> None:
    host = host_factory(answer(status, error=error_body("STATE_CONFLICT", "nope")))
    env = client.mutate(CREATE)
    assert env.status.value == status
    assert host.methods == ["sandbox_create"]


# ----------------------------------------------------------------------------- lost responses
def test_a_lost_response_is_resolved_by_asking_not_by_repeating(client: HostClient, host_factory: HostFactory) -> None:
    host = host_factory(Lost(), observed("SUCCEEDED", result=sandbox_result()))
    env = client.mutate(CREATE)
    assert env.status == m.OperationStatus.SUCCEEDED
    assert host.methods == ["sandbox_create", "operation_get"], "the mutation must be sent exactly once"
    assert host.requests[1]["body"]["params"]["operation_id"] == host.requests[0]["operation_id"]


def test_a_lost_response_to_a_running_operation_keeps_observing_until_it_finishes(
    client: HostClient, host_factory: HostFactory, clock: FakeClock
) -> None:
    host = host_factory(
        Lost(), observed("IN_PROGRESS"), observed("IN_PROGRESS"), observed("SUCCEEDED", result=sandbox_result())
    )
    env = client.mutate(CREATE)
    assert env.status == m.OperationStatus.SUCCEEDED
    assert host.methods.count("sandbox_create") == 1
    assert clock.sleeps == sorted(clock.sleeps), "polling backs off, it does not hammer the host"
    assert max(clock.sleeps) <= client.config.poll_max_s


def test_only_when_the_host_has_never_heard_of_it_is_the_request_submitted_again_with_the_same_id(
    client: HostClient, host_factory: HostFactory
) -> None:
    host = host_factory(Lost(), never_heard_of_it(), sandbox_ok())
    env = client.mutate(CREATE)
    assert env.status == m.OperationStatus.SUCCEEDED
    assert host.methods == ["sandbox_create", "operation_get", "sandbox_create"]
    first, _, second = host.requests
    assert first["operation_id"] == second["operation_id"], "same id: the host's atomic begin makes this idempotent"
    assert first["body"] == second["body"]
    assert "retry" not in second, "a resubmission is a fresh begin, not a 'retry' (which the host would reject)"


def test_resubmission_happens_at_most_once(client: HostClient, host_factory: HostFactory) -> None:
    host = host_factory(Lost(), never_heard_of_it(), Lost(), default=never_heard_of_it())
    with pytest.raises(OutcomeUnknown) as caught:
        client.mutate(CREATE)
    assert host.methods.count("sandbox_create") == 2, "one submission plus one resubmission, never a third"
    assert caught.value.operation_id == host.requests[0]["operation_id"]
    assert caught.value.hint is not None
    assert "do NOT re-run" in caught.value.hint
    assert caught.value.exit_code == ExitCode.UNKNOWN


def test_observation_survives_the_host_restarting_mid_way(client: HostClient, host_factory: HostFactory) -> None:
    host = host_factory(Lost(), ClosedBeforeRead(), observed("SUCCEEDED", result=sandbox_result()))
    env = client.mutate(CREATE)
    assert env.status == m.OperationStatus.SUCCEEDED
    assert host.methods.count("sandbox_create") == 1


def test_a_host_that_never_comes_back_ends_in_unknown_with_the_id_to_look_up_later(
    config: ClientConfig, clock: FakeClock, host_factory: HostFactory
) -> None:
    host_factory(Lost(), default=ClosedBeforeRead())
    client = HostClient(config, sleep=clock.sleep, monotonic=clock.monotonic)
    with pytest.raises(OutcomeUnknown) as caught:
        client.mutate(CREATE, resolve_deadline_s=5)
    assert caught.value.operation_id is not None
    assert caught.value.operation_id in (caught.value.hint or "")
    assert clock.now - 1000.0 >= 5


def test_a_host_that_stops_answering_mid_request_is_a_lost_response_not_a_failure(
    socket_path: Path, clock: FakeClock, host_factory: HostFactory
) -> None:
    host = host_factory(Stall(1.0), observed("SUCCEEDED", result=sandbox_result()))
    client = HostClient(
        ClientConfig(socket_path=socket_path, io_timeout_s=0.2), sleep=clock.sleep, monotonic=clock.monotonic
    )
    env = client.mutate(CREATE)
    assert env.status == m.OperationStatus.SUCCEEDED
    assert host.methods.count("sandbox_create") == 1


def test_slow_operations_get_the_generous_timeout(
    socket_path: Path, clock: FakeClock, host_factory: HostFactory
) -> None:
    host = host_factory(Reply(lambda req: respond(req, "SUCCEEDED", result=sandbox_result()), delay=0.5))
    cfg = ClientConfig(socket_path=socket_path, io_timeout_s=0.1, slow_op_timeout_s=5.0)
    env = HostClient(cfg, sleep=clock.sleep, monotonic=clock.monotonic).mutate_slow(CREATE)
    assert env.status == m.OperationStatus.SUCCEEDED
    assert host.methods == ["sandbox_create"], "a 0.5s answer is not 'lost' under a 5s slow-operation timeout"


# ----------------------------------------------------------------------------- UNKNOWN is first-class
def test_unknown_is_observed_for_a_grace_period_then_surfaced_never_retried_never_failed(
    client: HostClient, host_factory: HostFactory
) -> None:
    host = host_factory(answer("UNKNOWN", error=UNKNOWN_ERROR), default=observed("UNKNOWN", error=UNKNOWN_ERROR))
    env = client.mutate(CREATE)
    assert env.status == m.OperationStatus.UNKNOWN
    assert host.methods[0] == "sandbox_create"
    assert set(host.methods[1:]) == {"operation_get"}
    with pytest.raises(OutcomeUnknown) as caught:
        raise_for_status(env)
    assert caught.value.exit_code == ExitCode.UNKNOWN
    assert int(caught.value.exit_code) != int(ExitCode.FAILED), "UNKNOWN must never be reported as FAILED"
    assert "do NOT re-run" in (caught.value.hint or "")
    assert caught.value.operation_id == host.requests[0]["operation_id"]


def test_unknown_that_the_host_later_resolves_is_reported_as_what_it_became(
    client: HostClient, host_factory: HostFactory
) -> None:
    host = host_factory(
        answer("UNKNOWN", error=UNKNOWN_ERROR),
        observed("UNKNOWN", error=UNKNOWN_ERROR),
        observed("SUCCEEDED", result=sandbox_result()),
    )
    env = client.mutate(CREATE)
    assert env.status == m.OperationStatus.SUCCEEDED
    assert host.methods.count("sandbox_create") == 1


def test_an_operation_still_running_elsewhere_is_observed_not_started_twice(
    client: HostClient, host_factory: HostFactory
) -> None:
    host = host_factory(
        answer("IN_PROGRESS"),
        observed("IN_PROGRESS"),
        observed("FAILED", error=error_body("BACKEND_CRASH", "vmm died")),
    )
    env = client.mutate(CREATE)
    assert env.status == m.OperationStatus.FAILED
    assert host.methods.count("sandbox_create") == 1


# ----------------------------------------------------------------------------- transport & connection
def test_a_missing_socket_is_unreachable_and_says_how_to_point_elsewhere(client: HostClient) -> None:
    with pytest.raises(HostUnreachable) as caught:
        client.read(INSPECT)
    assert caught.value.exit_code == ExitCode.UNREACHABLE
    assert "--socket" in (caught.value.hint or "")


def test_a_stale_socket_file_is_reported_as_nothing_listening(config: ClientConfig, client: HostClient) -> None:
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    bind_unix(stale, config.socket_path)  # bound but never listen()ed: connect() gets ECONNREFUSED
    try:
        with pytest.raises(HostUnreachable) as caught:
            client.read(INSPECT)
    finally:
        stale.close()
    assert "nothing is listening" in caught.value.message
    assert "systemctl" in (caught.value.hint or "")


def test_permission_denied_on_the_socket_explains_the_group_requirement(
    client: HostClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def deny(self: socket.socket, address: object) -> None:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(socket.socket, "connect", deny)
    with pytest.raises(HostUnreachable) as caught:
        client.read(INSPECT)
    assert "permission denied" in caught.value.message
    assert "group" in (caught.value.hint or "")


def test_an_unreachable_host_means_nothing_was_sent_so_a_mutation_does_not_enter_observation(
    client: HostClient, clock: FakeClock
) -> None:
    with pytest.raises(HostUnreachable):
        client.mutate(CREATE)
    assert clock.sleeps == [], "nothing was sent, so there is nothing to observe"


def test_a_socket_path_longer_than_sun_path_still_works(tmp_path: Path, clock: FakeClock) -> None:
    deep = tmp_path / "long"
    while len(os.fsencode(deep / "acf.sock")) < 120:
        deep = deep / "a-deliberately-long-directory-name"
    deep.mkdir(parents=True)
    path = deep / "acf.sock"
    assert len(os.fsencode(path)) > 108
    host = ScriptedHost(path, [sandbox_ok()])
    host.start()
    try:
        client = HostClient(ClientConfig(socket_path=path), sleep=clock.sleep, monotonic=clock.monotonic)
        assert isinstance(client.read(INSPECT).body(), m.SandboxView)
    finally:
        host.stop()
    host.assert_clean()


def test_a_request_over_the_limit_is_refused_locally_without_connecting(
    socket_path: Path, host_factory: HostFactory
) -> None:
    host = host_factory()  # an empty script: any connection at all would be recorded as a problem
    client = HostClient(ClientConfig(socket_path=socket_path, max_request_bytes=256))
    big = m.ExecRequest(
        params=m.ExecParams(
            sandbox_id=f.SANDBOX_ID, expected_generation=1, command=m.CommandSpec(argv=["echo", "x" * 1000])
        )
    )
    with pytest.raises(InvalidArgument) as caught:
        client.mutate(big)
    assert "at most 256" in caught.value.message
    assert host.requests == []


def test_a_truncated_response_to_a_read_is_a_transport_error(client: HostClient, host_factory: HostFactory) -> None:
    host_factory(Partial(b'{"protocol":"acf.host/1","status":"SUCCEEDED"}', delivered=10))
    with pytest.raises(TransportError) as caught:
        client.read(INSPECT)
    assert caught.value.request_sent is True


# ----------------------------------------------------------------------------- an untrusted peer
def test_an_oversize_response_is_rejected_before_the_payload_is_read(
    socket_path: Path, host_factory: HostFactory
) -> None:
    host_factory(RawBytes(HEADER.pack(1 << 30)))  # announces 1 GiB, sends nothing
    client = HostClient(ClientConfig(socket_path=socket_path, max_response_bytes=1024))
    with pytest.raises(ProtocolViolation, match="oversize"):
        client.read(INSPECT)


@pytest.mark.parametrize(
    ("payload", "needle"),
    [
        (b"this is not json", "malformed response"),
        (b'{"protocol":"acf.host/1"}', "malformed response"),  # no status
        (b'{"protocol":"acf.host/1","status":"MOSTLY_DONE"}', "malformed response"),
        (b'{"protocol":"acf.host/1","status":"SUCCEEDED","result":{"type":"mystery","data":1}}', "malformed response"),
        (b'{"protocol":"acf.host/2","status":"SUCCEEDED"}', "acf.host/2"),
    ],
)
def test_a_peer_that_does_not_speak_the_protocol_is_a_protocol_violation(
    client: HostClient, host_factory: HostFactory, payload: bytes, needle: str
) -> None:
    host_factory(Reply(payload))
    with pytest.raises(ProtocolViolation, match=needle) as caught:
        client.read(INSPECT)
    assert caught.value.exit_code == ExitCode.PROTOCOL


def test_a_response_to_a_different_request_is_rejected(client: HostClient, host_factory: HostFactory) -> None:
    host_factory(Reply(lambda req: {**respond(req, "SUCCEEDED"), "request_id": "req-someone-else"}))
    with pytest.raises(ProtocolViolation, match="request_id"):
        client.read(INSPECT)


def test_a_protocol_violation_in_the_answer_to_a_mutation_points_at_the_operation_to_look_up(
    client: HostClient, host_factory: HostFactory
) -> None:
    host = host_factory(Reply(b"garbage"))
    with pytest.raises(ProtocolViolation) as caught:
        client.mutate(CREATE)
    assert caught.value.operation_id == host.requests[0]["operation_id"]
    assert "do NOT re-run" in (caught.value.hint or "")
    assert "operation get" in (caught.value.hint or "")


# ----------------------------------------------------------------------------- authorization denial
DENIAL = respond(None, "REJECTED", error=error_body("AUTHORIZATION", "uid 1000 is not permitted to use this host"))


def test_a_denial_sent_before_the_host_reads_the_request_is_still_reported_as_a_denial(
    client: HostClient, host_factory: HostFactory
) -> None:
    host_factory(DenyUnread(DENIAL))
    with pytest.raises(Rejected) as caught:
        client.read(INSPECT)
    assert caught.value.failure_class == "AUTHORIZATION"
    assert "not permitted" in caught.value.message


def test_a_denial_is_reported_even_when_the_request_is_too_big_to_have_been_buffered(
    socket_path: Path, host_factory: HostFactory
) -> None:
    host_factory(DenyUnread(DENIAL))
    client = HostClient(ClientConfig(socket_path=socket_path, max_request_bytes=8 * 1024 * 1024, io_timeout_s=5))
    huge = m.ExecRequest(
        params=m.ExecParams(
            sandbox_id=f.SANDBOX_ID,
            expected_generation=1,
            command=m.CommandSpec(argv=["echo", "x" * (4 * 1024 * 1024)]),
        )
    )
    with pytest.raises((Rejected, HostUnreachable)) as caught:
        raise_for_status(client.mutate(huge))
    # Either the denial was read (preferred) or the failed send is reported as "did not act on it".
    assert caught.value.exit_code in {ExitCode.REJECTED, ExitCode.UNREACHABLE}
    if isinstance(caught.value, Rejected):
        assert caught.value.failure_class == "AUTHORIZATION"
    else:
        assert "did not act on it" in caught.value.message


# ----------------------------------------------------------------------------- cancel / wait_final
def test_cancel_sends_a_plain_request_for_the_named_operation(client: HostClient, host_factory: HostFactory) -> None:
    host = host_factory(observed("IN_PROGRESS"))
    env = client.cancel(f.OP_ID)
    assert env.status == m.OperationStatus.IN_PROGRESS
    assert host.requests[0]["body"] == {"method": "operation_cancel", "params": {"operation_id": f.OP_ID}}
    assert "operation_id" not in host.requests[0], "cancel acts on another operation; it does not create one"


def test_wait_final_polls_until_the_operation_ends(client: HostClient, host_factory: HostFactory) -> None:
    host = host_factory(observed("IN_PROGRESS"), observed("IN_PROGRESS"), observed("CANCELLED"))
    assert client.wait_final(f.OP_ID, timeout_s=30).status == m.OperationStatus.CANCELLED
    assert host.methods == ["operation_get"] * 3


def test_wait_final_gives_back_the_last_answer_when_time_runs_out(
    client: HostClient, host_factory: HostFactory
) -> None:
    host_factory(default=observed("IN_PROGRESS"))
    env = client.wait_final(f.OP_ID, timeout_s=3)
    assert env.status == m.OperationStatus.IN_PROGRESS


def test_wait_final_with_a_dead_host_ends_in_unknown_not_a_hang(client: HostClient, host_factory: HostFactory) -> None:
    host_factory(default=ClosedBeforeRead())
    with pytest.raises(OutcomeUnknown):
        client.wait_final(f.OP_ID, timeout_s=3)


# ----------------------------------------------------------------------------- status -> exit code
def envelope_with(status: str) -> m.ResponseEnvelope:
    error = None if status == "SUCCEEDED" else error_body("INTERNAL", "boom")
    return m.ResponseEnvelope.model_validate(respond({"request_id": "r", "operation_id": f.OP_ID}, status, error=error))


@pytest.mark.parametrize("status", [s.value for s in m.OperationStatus])
def test_exit_codes_for_statuses_agree_with_the_exceptions_raised(status: str) -> None:
    env = envelope_with(status)
    code = exit_code_for_status(env.status)
    if status == "SUCCEEDED":
        assert raise_for_status(env) is env
        assert code == ExitCode.OK
        return
    with pytest.raises((Rejected, OperationFailed, OutcomeUnknown)) as caught:
        raise_for_status(env)
    assert caught.value.exit_code == code


def test_the_exit_code_vocabulary_by_status() -> None:
    assert int(exit_code_for_status(m.OperationStatus.REJECTED)) == 3
    assert int(exit_code_for_status(m.OperationStatus.CONFLICT)) == 3
    assert int(exit_code_for_status(m.OperationStatus.FAILED)) == 4
    assert int(exit_code_for_status(m.OperationStatus.CANCELLED)) == 4
    for undecided in (m.OperationStatus.UNKNOWN, m.OperationStatus.ACCEPTED, m.OperationStatus.IN_PROGRESS):
        assert int(exit_code_for_status(undecided)) == 5


def test_raise_for_status_carries_the_failure_details() -> None:
    env = m.ResponseEnvelope.model_validate(
        respond(
            {"request_id": "r", "operation_id": f.OP_ID},
            "REJECTED",
            error=error_body("ADMISSION_REJECTED", "memory 99999 MiB exceeds the policy ceiling", retryable=True),
        )
    )
    with pytest.raises(Rejected) as caught:
        raise_for_status(env)
    assert caught.value.retryable is True
    assert caught.value.failure_class == "ADMISSION_REJECTED"
    assert caught.value.operation_id == f.OP_ID
    assert "policy ceiling" in caught.value.message
    assert "ceiling" in (caught.value.hint or "")


def test_a_still_running_operation_is_never_reported_as_success_or_failure() -> None:
    env = m.ResponseEnvelope.model_validate(respond({"request_id": "r", "operation_id": f.OP_ID}, "IN_PROGRESS"))
    with pytest.raises(OutcomeUnknown) as caught:
        raise_for_status(env)
    assert "still in progress" in (caught.value.hint or "")
    assert f.OP_ID in (caught.value.hint or "")
