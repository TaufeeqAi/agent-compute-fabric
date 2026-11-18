"""The wire protocol's refusals: what the host does with requests the reference client would never send.

The client is not a security boundary: anything may connect to an endpoint and send any bytes. Everything here goes
over the raw wire, as an enrolled peer, and checks that a request the host cannot or must not serve is refused
with the class the contract names, that nothing is recorded, and that the connection and the host stay usable
for everybody else. All of it is ``control_plane`` (evidence level L2/L3): T-API-02, T-VER-01, T-VER-02, T-AUTH-08,
T-SECR-01 and T-SEC-03.
"""

from __future__ import annotations

import json
import struct
from typing import Any

import pytest

from acf_driver import AcfLocal, envelope, frame, resources, target_of
from acf_integration import HostEnv

pytestmark = [pytest.mark.integration, pytest.mark.control_plane, pytest.mark.usefixtures("clean_host")]

GHOST = {"sandbox_id": "sbx-" + "0" * 32, "expected_generation": 1}


def _create(acf: AcfLocal, **extra: Any) -> dict[str, Any]:
    return {"image": acf.image, "resources": resources(), **extra}


# ============================================================================================ versions and fields
def test_t_ver_01_another_protocol_major_is_refused_before_any_mutation(acf: AcfLocal) -> None:
    """T-VER-01 (L2): a protocol major mismatch, caller <-> host -> refused before any mutation."""
    wire = acf.wire
    with wire.nothing_recorded("a request in another protocol"):
        for spoken in ("acf.host/1", "acf.host/3", "acf.host/20", "ACF.HOST/2", "acf.host", ""):
            answer = wire.call("sandbox.create", _create(acf), protocol=spoken)
            refusal = answer.refused()
            assert (refusal.failure_class, refusal.retry) == ("PROTOCOL_ERROR", "NEVER"), (spoken, refusal)
            assert answer.as_of is None, "a request in another protocol is refused without consulting any state"
    assert wire.sandboxes() == []
    assert "acf.host/2" in wire.info().protocols


def test_t_api_02_an_unknown_field_or_method_is_refused_and_nothing_is_recorded(acf: AcfLocal) -> None:
    """T-API-02 (L2): an unknown field, an unknown method, an unsupported protocol major -> refused; nothing
    recorded."""
    wire = acf.wire
    box = wire.ready(acf.name("strict"))
    with wire.nothing_recorded("a request with something the host does not know"):
        refusals = {
            "an envelope field": wire.call("host.info", None, extra={"priority": "high"}),
            "a parameter": wire.call("sandbox.create", _create(acf, privileged=True)),
            "a nested parameter": wire.call(
                "sandbox.create", {"image": acf.image, "resources": {**resources(), "gpus": 1}}
            ),
            "a command field": wire.call("exec.run", {**target_of(box), "command": {"argv": ["true"], "stdin": "x"}}),
            "a method": wire.call("sandbox.teleport", {}),
            "a method name of an earlier protocol": wire.call("sandbox_create", _create(acf)),
            "a mutation by name": wire.call("sandbox.destroy", {"sandbox": str(box.name)}),
            "a generation of zero": wire.call("sandbox.stop", {**GHOST, "expected_generation": 0}),
            "a page size of zero": wire.call("sandbox.list", {"limit": 0}),
            "a page size above the bound": wire.call("sandbox.list", {"limit": 1001}),
            "retry on a read": wire.call("host.info", None, retry=True),
            "an owner scope with a space": wire.call("host.info", None, scope="team a"),
            "an on_behalf_of with a space": wire.call("sandbox.create", _create(acf), on_behalf_of="user 7"),
            "an operation id that is too short": wire.call("sandbox.create", _create(acf), operation_id="op-1"),
            "an empty argument vector": wire.call("exec.run", {**target_of(box), "command": {"argv": []}}),
        }
    for what, answer in refusals.items():
        refusal = answer.refused()
        assert (refusal.failure_class, refusal.retry) == ("INVALID_REQUEST", "NEVER"), (what, refusal)
    after = wire.refresh(box)
    assert (after.state, after.last_run) == ("READY", None)
    assert [s.sandbox_id for s in wire.sandboxes()] == [box.sandbox_id]


def test_t_auth_08_a_signed_decision_is_refused_by_a_host_that_does_not_advertise_the_feature(acf: AcfLocal) -> None:
    """T-AUTH-08 and T-VER-02 (L2): a request carrying ``authority`` to a host that does not advertise
    ``signed_decision`` -> ``INVALID_REQUEST``; a field of an unadvertised feature is refused."""
    wire = acf.wire
    assert "signed_decision" not in wire.info().features
    decision = {"authority": {"decision": "allow", "signature": "AAAA"}}
    with wire.nothing_recorded("a request that carries a signed decision"):
        on_a_mutation = wire.call("sandbox.create", _create(acf), extra=decision).refused()
        on_a_read = wire.call("host.info", None, extra=decision).refused()
    for refusal in (on_a_mutation, on_a_read):
        assert (refusal.failure_class, refusal.retry) == ("INVALID_REQUEST", "NEVER"), refusal
        assert "signed_decision" in refusal.message
    assert wire.sandboxes() == []


def test_t_secr_01_raw_secret_material_in_a_request_is_refused_and_kept_nowhere(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    """T-SECR-01 (L2): raw secret material in a request -> ``INVALID_REQUEST``. A request names a secret by
    reference; material that arrives anyway must not be kept in the store, in telemetry or in the host's log."""
    host = host_env.test_host()
    wire = acf.wire
    material = "acf-it-raw-secret-7f3a9c1e5b2d"
    box = wire.ready(acf.name("secrets"))
    command = {"argv": ["true"]}
    with wire.nothing_recorded("a request carrying secret material"):
        as_a_string = wire.call(
            "exec.run", {**target_of(box), "command": {**command, "secret_env": {"HOME": material}}}
        )
        beside_a_reference = wire.call(
            "exec.run",
            {**target_of(box), "command": {**command, "secret_env": {"HOME": {"ref": "token", "value": material}}}},
        )
    for answer in (as_a_string, beside_a_reference):
        assert (answer.refused().failure_class, answer.refused().retry) == ("INVALID_REQUEST", "NEVER")
    assert wire.refresh(box).last_run is None

    kept_in = [
        str(path)
        for path in (host.journal, host.state_root / "telemetry" / "events.jsonl", host.log)
        if path.exists() and material.encode() in path.read_bytes()
    ]
    assert kept_in == [], f"the secret material of a refused request was written to {kept_in}"


# ============================================================================================ frames
def test_a_request_that_is_not_a_request_is_refused_and_the_connection_stays_usable(acf: AcfLocal) -> None:
    wire = acf.wire
    with wire.nothing_recorded("bytes that are not a request"), wire.connect() as connection:
        for payload in (b"not json!", b"[1, 2, 3]", b"{}", b"null", b"", b'{"protocol": "acf.host/2"}'):
            connection.send_frame(payload)
            answer = connection.read(timeout=10)
            assert answer is not None, f"the host closed the connection on {payload!r}"
            refusal = answer.refused()
            assert (refusal.failure_class, refusal.retry) == ("INVALID_REQUEST", "NEVER"), (payload, refusal)
            assert answer.as_of is None
        assert connection.request("host.info").answer == "RESULT", "a well-formed request after them must be served"


def test_an_oversized_frame_is_refused_from_its_header_alone_and_the_connection_is_closed(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    """PA-2: a peer consumes bounded memory: the host bounds every frame before it reads it."""
    limit = host_env.config.integer("edge.max_request_bytes")
    wire = acf.wire
    with wire.nothing_recorded("an oversized frame"):
        with wire.connect() as connection:
            connection.send(struct.pack(">I", limit + 1))  # the header alone: not one byte of the body is sent
            answer = connection.read(timeout=10)
            assert answer is not None
            assert answer.refused().failure_class == "INVALID_REQUEST"
            assert str(limit) in answer.refused().message, "the refusal names the bound"
            assert connection.peer_closed(within=10), "after a frame error the stream cannot be trusted any more"
        with wire.connect() as connection:
            padded = json.dumps(envelope("host.info")).encode().ljust(limit, b" ")
            connection.send_frame(padded)
            at_the_limit = connection.read(timeout=30)
            assert at_the_limit is not None
            assert at_the_limit.answer == "RESULT", "a frame of exactly the permitted size is a frame like any other"


def test_a_frame_cut_short_is_refused_and_the_connection_is_closed(acf: AcfLocal) -> None:
    wire = acf.wire
    with wire.nothing_recorded("half a frame"), wire.connect() as connection:
        whole = frame(json.dumps(envelope("sandbox.create", _create(acf))).encode())
        connection.send(whole[: len(whole) // 2])
        connection.finish_sending()
        answer = connection.read(timeout=10)
        assert answer is not None, "the host closed without saying why"
        assert answer.refused().failure_class == "INVALID_REQUEST"
        assert connection.peer_closed(within=10)
    assert wire.sandboxes() == [], "half a request created something"


def test_t_sec_03_silent_and_half_open_peers_do_not_disturb_authenticated_traffic(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    """T-SEC-03 (L2): half-open handshakes, an oversized frame, slow peers -> authenticated traffic is
    unaffected."""
    wire = acf.wire
    per_source = host_env.config.integer("edge.max_connections_per_source")
    idle = [wire.connect() for _ in range(max(1, per_source - 5))]  # with the two below: three places stay free
    slow = wire.connect()
    try:
        slow.send(struct.pack(">I", 4096) + b'{"protocol": "acf.host/2", ')  # a frame that never ends
        oversized = wire.connect()
        idle.append(oversized)
        oversized.send(struct.pack(">I", host_env.config.integer("edge.max_request_bytes") * 4))
        for _ in range(5):
            box = wire.create()
            assert wire.destroy(box).state == "DESTROYED", "a request of a well-behaved peer was not served"
        assert wire.info().mode == "SERVING"
    finally:
        for connection in (*idle, slow):
            connection.close()
