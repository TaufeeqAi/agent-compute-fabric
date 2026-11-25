"""Framing and encoding of the command interface, the one seam between the edge and the core.

Proves, for the boundary of the command interface: a frame is a length and exactly that many bytes of
UTF-8 JSON; the length is checked before a byte of the payload is read or allocated; no configuration
removes the bound; the end of a stream on a frame boundary is told apart from a frame cut short. For
EC-4: a command carries the credential, a request id, the trace context, a deadline, the interface and
its version, bounded client information, the idempotency key if the caller gave one, and one command
of the public model; an unknown command, an unknown member or an unknown version is refused; an answer
is a refusal, an unresolved outcome or a view. For VER-13: the interface has a version, and a frame
that names one outside the served range is refused as that, before anything else of it is judged.
Catalog entry: the codec half of T3-VER-03. That a core refuses an edge outside its range end to end
is proven by the command-socket suite.

A request frame carries the caller's credential, and an answer frame can carry the secret of a freshly
minted one. So a refusal of a frame says nothing of the frame, and holds nothing of it.
"""

from __future__ import annotations

import asyncio
import json
import socket
import struct
import sys
import typing
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import BaseModel

from acf_api.command import answers as a
from acf_api.command import codec, commands, strictjson
from acf_api.command import model as m
from acf_api.command.codec import CodecError, FrameEof, FrameError, FrameTooLarge, FrameTruncated, VersionRefused

PROJECT = "prj_0000000000000001"
SANDBOX = "sbx-" + "0" * 31 + "1"
SNAPSHOT = "snp-" + "0" * 31 + "1"
EXECUTION = "exe-" + "0" * 31 + "1"
OPERATION = "op-" + "a" * 32
CREDENTIAL = "crd_0000000000000001"
VERSION = a.COMMAND_INTERFACE_VERSION
#: A key in the documented form. It never authenticated anything: it only has to be findable.
CANARY = "acf1_dev_" + "C4nAry" * 7 + "X_000000"
CTX: dict[str, Any] = {
    "request_id": "req_0000000000000000000001",
    "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
    "budget_ms": 32_000,
    "interface": "rest",
    "interface_version": "v1",
    "client": {"name": "acf-python", "version": "1.2.3"},
}
GRANT = {
    "schema_version": 1,
    "methods": ["sandbox.create", "sandbox.destroy"],
    "images": ["python"],
    "network": {"modes": ["none"], "destinations": []},
    "ceilings": {
        "vcpus": 1,
        "memory_mib": 512,
        "disk_mib": 1024,
        "execution_timeout_seconds": 60,
        "sandbox_lifetime_seconds": 600,
    },
    "mint_agent_credentials": False,
}

#: One command of every type, with every member it can carry.
COMMANDS: dict[str, dict[str, Any]] = {
    "create_sandbox": {
        "project": PROJECT,
        "spec": {
            "image": "python",
            "resources": {"vcpus": 2, "memory_mib": 512, "disk_mib": 1024},
            "network": {
                "mode": "allowlist",
                "entries": [
                    {"name": "pypi.org", "ports": [{"from": 443, "to": 443}]},
                    {"network": "198.51.100.0/24", "ports": [{"from": 5432, "to": 5433}, {"from": 80, "to": 80}]},
                ],
            },
            "name": "lab",
            "lifetime_seconds": 600,
            "start": True,
        },
        "wait": 5,
    },
    "start_sandbox": {
        "project": PROJECT,
        "sandbox_id": SANDBOX,
        "expected_generation": 3,
        "if_match": "r7.0123456789ab",
        "wait": 0,
    },
    "stop_sandbox": {"project": PROJECT, "sandbox_id": SANDBOX, "expected_generation": "current", "wait": 30},
    "destroy_sandbox": {
        "project": PROJECT,
        "sandbox_id": SANDBOX,
        "expected_generation": "current",
        "if_match": "r12.abcdef012345",
    },
    "exec": {
        "project": PROJECT,
        "sandbox_id": SANDBOX,
        "spec": {
            "expected_generation": 2,
            "argv": ["/bin/sh", "-c", "echo \u00e9 \u4e2d \U0001f600 && printf '%s\\n' \"$HOME\""],
            "cwd": "/work",
            "env": {"LANG": "C.UTF-8", "EMPTY": ""},
            "secret_env": {"API_TOKEN": {"ref": "api-token"}},
            "timeout_seconds": 60,
            "max_pids": 64,
            "max_stdout_bytes": 0,
            "max_stderr_bytes": 4096,
        },
        "if_match": "r7.0123456789ab",
        "wait": 10,
    },
    "cancel_execution": {"project": PROJECT, "execution_id": EXECUTION, "wait": 1},
    "create_snapshot": {
        "project": PROJECT,
        "sandbox_id": SANDBOX,
        "spec": {"expected_generation": "current", "name": "base"},
        "wait": 2,
    },
    "restore_snapshot": {
        "project": PROJECT,
        "snapshot_id": SNAPSHOT,
        "spec": {
            "snapshot_generation": 1,
            "target": {"kind": "existing", "sandbox_id": SANDBOX, "expected_generation": 4},
        },
        "if_match": "r7.0123456789ab",
    },
    "delete_snapshot": {"project": PROJECT, "snapshot_id": SNAPSHOT, "snapshot_generation": 1, "wait": 3},
    "get_operation": {"project": PROJECT, "operation_id": OPERATION, "wait": 30},
    "list_operations": {"project": PROJECT, "limit": 1000, "cursor": "eyJsIjoieCIsInMiOjF9"},
    "get_sandbox": {"project": PROJECT, "sandbox": "lab.1"},
    "list_sandboxes": {"project": PROJECT, "limit": 1},
    "list_snapshots": {"project": PROJECT, "cursor": "c_-1"},
    "get_execution": {"project": PROJECT, "execution_id": EXECUTION},
    "get_execution_output": {
        "project": PROJECT,
        "execution_id": EXECUTION,
        "stream": "stderr",
        "offset": 4096,
        "max_bytes": 65536,
    },
    "mint_agent_credential": {
        "project": PROJECT,
        "spec": {"label": "worker-1", "lifetime_seconds": 3600, "narrowing": GRANT},
    },
    "list_agent_credentials": {"project": PROJECT},
    "revoke_agent_credential": {"project": PROJECT, "credential_id": CREDENTIAL},
    "whoami": {},
    "info": {},
    "list_tools": {},
    "call_tool": {
        "name": "sandbox_exec",
        "arguments": {"sandbox_id": SANDBOX, "argv": ["true"], "nested": {"list": [1, 2.5, None, True, "\u00e9"]}},
    },
    "discover": {},
}
#: The other shape of the one command whose body is a choice.
RESTORE_AS_NEW = {
    "project": PROJECT,
    "snapshot_id": SNAPSHOT,
    "spec": {"snapshot_generation": 2, "target": {"kind": "new", "name": "copy", "lifetime_seconds": 900}},
}


def command(command_type: str, **members: Any) -> dict[str, Any]:
    return {"type": command_type, **COMMANDS[command_type], **members}


def handle(command_type: str = "create_sandbox", **members: Any) -> dict[str, Any]:
    """A request frame as an edge sends it, in the form it has on the wire."""
    frame: dict[str, Any] = {
        "op": "handle",
        "version": VERSION,
        "credential": CANARY,
        "ctx": CTX,
        "idempotency_key": "key-0001",
        "command": command(command_type),
    }
    frame.update(members)
    return frame


def payload(frame: Any) -> bytes:
    return json.dumps(frame).encode("utf-8")


def chain(error: BaseException) -> list[BaseException]:
    """An exception and everything it still holds on to: what a careless log line would print."""
    found: list[BaseException] = []
    pending: list[BaseException | None] = [error]
    while pending:
        current = pending.pop()
        if current is None or current in found:
            continue
        found.append(current)
        pending.extend([current.__cause__, current.__context__])
    return found


def says_nothing_of(error: BaseException, secret: str) -> None:
    for link in chain(error):
        assert secret not in str(link), type(link).__name__
        assert secret not in repr(link), type(link).__name__
        errors = getattr(link, "errors", None)
        if callable(errors):
            # A validation error prints a shortened form of its input. Where the secret falls in it is chance,
            # so the input itself is looked at.
            assert secret not in repr(errors()), "a validation error keeps what it refused"


def reader_of(*chunks: bytes, eof: bool = True) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    for chunk in chunks:
        reader.feed_data(chunk)
    if eof:
        reader.feed_eof()
    return reader


# ------------------------------------------------------------------------------- frames
def test_a_frame_is_a_big_endian_length_and_exactly_that_many_bytes() -> None:
    assert codec.encode_frame(b"", 100) == b"\x00\x00\x00\x00"
    assert codec.encode_frame(b"{}", 100) == b"\x00\x00\x00\x02{}"
    body = b"x" * 0x01_02_03
    frame = codec.encode_frame(body, len(body))
    assert frame[:4] == b"\x00\x01\x02\x03" == struct.pack(">I", len(body))
    assert frame[4:] == body


async def test_a_frame_is_read_whole_and_the_next_one_after_it() -> None:
    first, second = b'{"a":1}', '{"b":"\u00e9"}'.encode()
    reader = reader_of(codec.encode_frame(first, 100) + codec.encode_frame(second, 100) + codec.encode_frame(b"", 100))
    assert await codec.read_frame(reader, 100) == first
    assert await codec.read_frame(reader, 100) == second
    assert await codec.read_frame(reader, 100) == b""
    with pytest.raises(FrameEof):
        await codec.read_frame(reader, 100)


async def test_a_frame_that_arrives_in_pieces_is_one_frame() -> None:
    frame = codec.encode_frame(b'{"k":"' + b"v" * 5000 + b'"}', 10_000)
    reader = asyncio.StreamReader()
    reading = asyncio.ensure_future(codec.read_frame(reader, 10_000))
    for start in range(0, len(frame), 7):
        reader.feed_data(frame[start : start + 7])
        await asyncio.sleep(0)
    assert await asyncio.wait_for(reading, 5) == frame[4:]


@pytest.mark.parametrize(
    "declared", [101, 102, 65_536, codec.MAX_FRAME_HARD_CAP, codec.MAX_FRAME_HARD_CAP + 1, 0x7FFFFFFF, 0xFFFFFFFF]
)
async def test_a_declared_length_above_the_bound_is_refused_before_the_payload_is_read(declared: int) -> None:
    """Only the header has arrived, and the stream is still open: the refusal does not wait for a payload."""
    reader = reader_of(struct.pack(">I", declared), eof=False)
    with pytest.raises(FrameTooLarge) as refused:
        await asyncio.wait_for(codec.read_frame(reader, 100), 2)
    assert (refused.value.length, refused.value.maximum) == (declared, 100)
    assert isinstance(refused.value, FrameError)
    # The same when a payload does follow: none of it is consumed.
    waiting = reader_of(struct.pack(">I", declared) + b"PAYLOAD", eof=False)
    with pytest.raises(FrameTooLarge):
        await asyncio.wait_for(codec.read_frame(waiting, 100), 2)
    assert await waiting.readexactly(7) == b"PAYLOAD"


async def test_a_frame_of_exactly_the_bound_is_read() -> None:
    body = b"y" * 100
    assert await codec.read_frame(reader_of(codec.encode_frame(body, 100)), 100) == body
    with pytest.raises(FrameTooLarge):
        await codec.read_frame(reader_of(codec.encode_frame(body, 100)), 99)


@pytest.mark.parametrize("configured", [codec.MAX_FRAME_HARD_CAP, codec.MAX_FRAME_HARD_CAP + 1, 2**40, sys.maxsize])
async def test_no_configuration_lifts_the_hard_cap(configured: int) -> None:
    """A bound that a setting can remove is not a bound: whatever is configured, 32 MiB is the most."""
    assert codec.MAX_FRAME_HARD_CAP == 32 * 1024 * 1024
    with pytest.raises(FrameTooLarge) as refused:
        await asyncio.wait_for(
            codec.read_frame(reader_of(struct.pack(">I", codec.MAX_FRAME_HARD_CAP + 1), eof=False), configured), 2
        )
    assert refused.value.maximum == codec.MAX_FRAME_HARD_CAP
    with pytest.raises(FrameTooLarge) as too_large:
        codec.encode_frame(bytes(codec.MAX_FRAME_HARD_CAP + 1), configured)
    assert (too_large.value.length, too_large.value.maximum) == (codec.MAX_FRAME_HARD_CAP + 1, codec.MAX_FRAME_HARD_CAP)
    assert codec.DEFAULT_MAX_REQUEST_FRAME <= codec.MAX_FRAME_HARD_CAP
    assert codec.DEFAULT_MAX_ANSWER_FRAME <= codec.MAX_FRAME_HARD_CAP


@pytest.mark.parametrize("configured", [0, -1, -(2**40)])
async def test_a_bound_of_nothing_admits_only_an_empty_frame(configured: int) -> None:
    assert codec.encode_frame(b"", configured) == b"\x00\x00\x00\x00"
    with pytest.raises(FrameTooLarge) as refused:
        codec.encode_frame(b"x", configured)
    assert refused.value.maximum == 0
    assert await codec.read_frame(reader_of(b"\x00\x00\x00\x00"), configured) == b""
    with pytest.raises(FrameTooLarge):
        await codec.read_frame(reader_of(b"\x00\x00\x00\x01x"), configured)


def test_an_oversize_payload_is_refused_and_never_truncated() -> None:
    with pytest.raises(FrameTooLarge) as refused:
        codec.encode_frame(b"x" * 101, 100)
    assert (refused.value.length, refused.value.maximum) == (101, 100)
    assert "101" in str(refused.value)
    assert "100" in str(refused.value)
    assert codec.encode_frame(b"x" * 100, 100)[4:] == b"x" * 100


async def test_the_end_of_a_stream_on_a_frame_boundary_is_not_a_truncated_frame() -> None:
    with pytest.raises(FrameEof):
        await codec.read_frame(reader_of(), 100)
    for partial_header in (b"\x00", b"\x00\x00", b"\x00\x00\x00"):
        with pytest.raises(FrameTruncated, match="inside a frame header"):
            await codec.read_frame(reader_of(partial_header), 100)
    for received in (b"", b"1", b"123456789"):
        with pytest.raises(FrameTruncated, match=f"after {len(received)} of 10 bytes") as cut:
            await codec.read_frame(reader_of(struct.pack(">I", 10) + received), 100)
        assert not isinstance(cut.value, FrameEof)
    assert issubclass(FrameEof, FrameError)
    assert issubclass(FrameTruncated, FrameError)
    assert issubclass(FrameTooLarge, FrameError)
    assert not issubclass(FrameEof, FrameTruncated)
    assert not issubclass(FrameTruncated, FrameEof)
    assert not issubclass(FrameError, CodecError)
    assert not issubclass(CodecError, FrameError)


async def test_a_truncated_frame_says_how_much_arrived_and_nothing_of_what() -> None:
    body = payload(handle())
    with pytest.raises(FrameTruncated) as cut:
        await codec.read_frame(reader_of(struct.pack(">I", len(body)) + body[:-1]), len(body))
    says_nothing_of(cut.value, CANARY)
    says_nothing_of(cut.value, "key-0001")


async def test_frames_cross_a_real_connection_in_both_directions() -> None:
    left, right = socket.socketpair()
    reader_a, writer_a = await asyncio.open_connection(sock=left)
    reader_b, writer_b = await asyncio.open_connection(sock=right)
    try:
        request = codec.encode_request(codec.decode_request(payload(handle())))
        await codec.write_frame(writer_a, request, codec.DEFAULT_MAX_REQUEST_FRAME)
        assert await asyncio.wait_for(codec.read_frame(reader_b, codec.DEFAULT_MAX_REQUEST_FRAME), 5) == request
        answer = codec.encode_answer(a.VerifiedAnswer(), VERSION)
        await codec.write_frame(writer_b, answer, codec.DEFAULT_MAX_ANSWER_FRAME)
        assert (
            codec.decode_answer(await asyncio.wait_for(codec.read_frame(reader_a, codec.DEFAULT_MAX_ANSWER_FRAME), 5))
            == a.VerifiedAnswer()
        )

        # A payload above the bound is refused before a byte of it is written: the peer sees the next frame, whole.
        with pytest.raises(FrameTooLarge):
            await codec.write_frame(writer_a, b"x" * 101, 100)
        await codec.write_frame(writer_a, b"next", 100)
        assert await asyncio.wait_for(codec.read_frame(reader_b, 100), 5) == b"next"

        writer_a.close()
        with pytest.raises(FrameEof):
            await asyncio.wait_for(codec.read_frame(reader_b, 100), 5)
    finally:
        writer_a.close()
        writer_b.close()


# ------------------------------------------------------------------------------- versions
def test_the_interface_serves_a_declared_range_of_versions() -> None:
    assert a.COMMAND_INTERFACE_MIN <= a.COMMAND_INTERFACE_VERSION <= a.COMMAND_INTERFACE_MAX
    assert a.COMMAND_INTERFACE_MIN >= 1
    for version in range(a.COMMAND_INTERFACE_MIN, a.COMMAND_INTERFACE_MAX + 1):
        assert codec.served(version)
    for version in (a.COMMAND_INTERFACE_MIN - 1, a.COMMAND_INTERFACE_MAX + 1, 0, -1, 2**31, 2**63):
        assert not codec.served(version)
    assert a.COMMAND_PROTOCOL == "acf.command"


@pytest.mark.proves("T3-VER-03", level="L1")
@pytest.mark.parametrize("version", [a.COMMAND_INTERFACE_MIN - 1, a.COMMAND_INTERFACE_MAX + 1, 0, -1, 99, 2**40])
def test_a_request_of_a_version_outside_the_range_is_refused_as_that(version: int) -> None:
    with pytest.raises(VersionRefused) as refused:
        codec.decode_request(payload(handle(version=version)))
    assert refused.value.version == version
    assert isinstance(refused.value, CodecError)
    assert str(version) in str(refused.value)
    assert f"{a.COMMAND_INTERFACE_MIN}..{a.COMMAND_INTERFACE_MAX}" in str(refused.value)
    says_nothing_of(refused.value, CANARY)


@pytest.mark.proves("T3-VER-03", level="L1")
def test_the_version_is_judged_before_anything_else_of_a_frame() -> None:
    """A later edge may send what this core has never seen. It is told "version", not "invalid"."""
    from_the_future = {
        "op": "handle_stream",
        "version": a.COMMAND_INTERFACE_MAX + 1,
        "credential": CANARY,
        "context": {"new": True},
        "commands": [1, 2, 3],
    }
    with pytest.raises(VersionRefused) as refused:
        codec.decode_request(payload(from_the_future))
    assert refused.value.version == a.COMMAND_INTERFACE_MAX + 1
    assert codec.peek_version(payload(from_the_future)) == a.COMMAND_INTERFACE_MAX + 1
    # The same frame under a served version is refused for what it is.
    with pytest.raises(CodecError) as invalid:
        codec.decode_request(payload({**from_the_future, "version": VERSION}))
    assert not isinstance(invalid.value, VersionRefused)


@pytest.mark.parametrize("version", ["1", 1.0, 1.5, True, False, None, [1], {"major": 1}])
def test_a_frame_that_names_no_version_is_refused(version: Any) -> None:
    for frame in (handle(version=version), {"op": "verify", "version": version, "credential": None, "ctx": CTX}):
        with pytest.raises(CodecError, match="names no version") as refused:
            codec.decode_request(payload(frame))
        assert not isinstance(refused.value, VersionRefused)
    missing = handle()
    del missing["version"]
    with pytest.raises(CodecError, match="names no version"):
        codec.decode_request(payload(missing))


@pytest.mark.proves("T3-VER-03", level="L1")
def test_an_answer_of_a_version_outside_the_range_is_refused() -> None:
    for version in (a.COMMAND_INTERFACE_MIN - 1, a.COMMAND_INTERFACE_MAX + 1):
        with pytest.raises(VersionRefused) as refused:
            codec.decode_answer(codec.encode_answer(a.AckAnswer(), version))
        assert refused.value.version == version
    assert codec.decode_answer(codec.encode_answer(a.AckAnswer(), VERSION)) == a.AckAnswer()
    frame = json.loads(codec.encode_answer(a.AckAnswer(), VERSION))
    assert frame == {"protocol": "acf.command", "version": VERSION, "answer": {"kind": "ack"}}
    for wrong in (
        {**frame, "protocol": "acf.host/2"},
        {**frame, "protocol": "ACF.COMMAND"},
        {k: v for k, v in frame.items() if k != "protocol"} | {"protocol": None},
    ):
        with pytest.raises(CodecError):
            codec.decode_answer(payload(wrong))


# ------------------------------------------------------------------------------- what a command carries
def test_a_command_carries_what_the_contract_lists_and_nothing_else() -> None:
    assert set(a.HandleRequest.model_fields) == {"op", "version", "credential", "ctx", "idempotency_key", "command"}
    assert set(a.VerifyRequest.model_fields) == {"op", "version", "credential", "ctx"}
    assert set(a.DeliveredRequest.model_fields) == {"op", "version", "credential", "ctx", "delivery_token"}
    assert set(a.RequestContext.model_fields) == {
        "request_id",
        "traceparent",
        "budget_ms",
        "interface",
        "interface_version",
        "client",
    }
    assert set(a.ClientInfo.model_fields) == {"name", "version"}
    # No request of the edge can state who the caller is: the core verifies the credential and trusts nothing else.
    for model in (a.HandleRequest, a.VerifyRequest, a.DeliveredRequest, a.RequestContext):
        assert not set(model.model_fields) & {
            "principal",
            "principal_id",
            "project",
            "project_id",
            "owner_scope",
            "scope",
            "grants",
            "kind",
        }


def test_every_request_and_every_command_refuses_what_it_does_not_define() -> None:
    models: list[type[BaseModel]] = [
        a.HandleRequest,
        a.VerifyRequest,
        a.DeliveredRequest,
        a.RequestContext,
        a.ClientInfo,
        a.Frame,
    ]
    models += list(typing.get_args(typing.get_args(commands.Command)[0]))
    models += list(typing.get_args(typing.get_args(a.Answer)[0]))
    assert len(models) == 6 + 24 + 8
    for model in models:
        assert model.model_config.get("extra") == "forbid", model.__name__
        assert model.model_config.get("strict") is True, model.__name__
        assert model.model_config.get("frozen") is True, model.__name__


def test_the_table_of_commands_below_holds_one_of_every_type() -> None:
    assert tuple(sorted(COMMANDS)) == commands.command_types()
    assert len(COMMANDS) == 24
    union = typing.get_args(typing.get_args(commands.Command)[0])
    assert sorted(str(member.model_fields["type"].default) for member in union) == sorted(COMMANDS)
    # Every member a command can carry is carried by the example, so the round trip below covers it.
    for member in union:
        example = COMMANDS[str(member.model_fields["type"].default)]
        assert set(member.model_fields) - {"type"} - set(example) <= {"if_match", "wait", "limit", "cursor"}, (
            member.__name__
        )


@pytest.mark.proves("T3-VER-03", level="L1")
@pytest.mark.parametrize("command_type", sorted(COMMANDS))
def test_every_command_type_round_trips(command_type: str) -> None:
    sent = payload(handle(command_type))
    request = codec.decode_request(sent)
    assert isinstance(request, a.HandleRequest)
    assert request.command.type == command_type
    assert (request.credential, request.idempotency_key, request.version) == (CANARY, "key-0001", VERSION)
    encoded = codec.encode_request(request)
    assert codec.decode_request(encoded) == request
    # What is encoded is what was sent: nothing was added, dropped or renamed on the way.
    assert json.loads(encoded) == json.loads(sent)
    assert codec.encode_request(codec.decode_request(encoded)) == encoded
    strictjson.loads_object(encoded)
    assert b"\n" not in encoded
    assert b": " not in encoded


def test_the_other_shape_of_a_restore_round_trips_too() -> None:
    frame = handle("restore_snapshot")
    frame["command"] = {"type": "restore_snapshot", **RESTORE_AS_NEW}
    request = codec.decode_request(payload(frame))
    assert isinstance(request, a.HandleRequest)
    assert isinstance(request.command, commands.RestoreSnapshot)
    assert isinstance(request.command.spec.target, m.RestoreAsNew)
    assert json.loads(codec.encode_request(request)) == frame


def test_members_that_are_not_given_are_not_sent_and_come_back_as_their_defaults() -> None:
    bare = {
        "op": "handle",
        "version": VERSION,
        "credential": None,
        "ctx": {k: v for k, v in CTX.items() if k not in {"traceparent", "client"}},
        "command": {"type": "info"},
    }
    request = codec.decode_request(payload(bare))
    assert isinstance(request, a.HandleRequest)
    assert (request.credential, request.idempotency_key, request.ctx.traceparent, request.ctx.client) == (
        None,
        None,
        None,
        a.ClientInfo(),
    )
    encoded = json.loads(codec.encode_request(request))
    assert "idempotency_key" not in encoded
    assert "credential" not in encoded
    assert "traceparent" not in encoded["ctx"]
    assert codec.decode_request(codec.encode_request(request)) == request
    output = codec.decode_request(
        payload(
            handle(
                "get_execution_output",
                command={"type": "get_execution_output", "project": PROJECT, "execution_id": EXECUTION},
            )
        )
    )
    assert isinstance(output, a.HandleRequest)
    assert isinstance(output.command, commands.GetExecutionOutput)
    assert (output.command.stream, output.command.offset, output.command.max_bytes) == (m.OutputStream.STDOUT, 0, None)


def test_the_two_other_requests_round_trip() -> None:
    verify = {"op": "verify", "version": VERSION, "credential": CANARY, "ctx": CTX}
    delivered = {
        "op": "delivered",
        "version": VERSION,
        "credential": CANARY,
        "ctx": {**CTX, "interface": "mcp", "interface_version": "2026-07-28"},
        "delivery_token": "tok_-0123456789",
    }
    for frame, expected in ((verify, a.VerifyRequest), (delivered, a.DeliveredRequest)):
        request = codec.decode_request(payload(frame))
        assert isinstance(request, expected)
        assert json.loads(codec.encode_request(request)) == frame
        assert codec.decode_request(codec.encode_request(request)) == request
    anonymous = codec.decode_request(payload({**verify, "credential": None}))
    assert anonymous.credential is None


argv_texts = st.lists(st.text(max_size=30), min_size=1, max_size=5)
env_names = st.from_regex(r"[A-Za-z_][A-Za-z0-9_]{0,20}", fullmatch=True)
keys = st.text(alphabet=st.characters(min_codepoint=0x21, max_codepoint=0x7E), min_size=1, max_size=255)


@given(
    argv_texts, st.dictionaries(env_names, st.text(max_size=30), max_size=4), keys, st.text(max_size=200) | st.none()
)
def test_whatever_text_a_command_carries_arrives_as_it_was_sent(
    argv: list[str], env: dict[str, str], key: str, credential: str | None
) -> None:
    frame = handle("exec", idempotency_key=key, credential=credential)
    frame["command"]["spec"] = {"expected_generation": 1, "argv": argv, "env": env}
    request = codec.decode_request(payload(frame))
    assert isinstance(request, a.HandleRequest)
    assert isinstance(request.command, commands.Exec)
    assert (request.command.spec.argv, request.command.spec.env, request.idempotency_key, request.credential) == (
        argv,
        env,
        key,
        credential,
    )
    again = codec.decode_request(codec.encode_request(request))
    assert again == request
    framed = codec.encode_frame(codec.encode_request(request), codec.DEFAULT_MAX_REQUEST_FRAME)
    assert codec.decode_request(framed[4:]) == request


# ------------------------------------------------------------------------------- what is refused
def _mutations() -> list[tuple[str, dict[str, Any]]]:
    out: list[tuple[str, dict[str, Any]]] = []

    def at(label: str, *path: str, **members: Any) -> None:
        frame = json.loads(json.dumps(handle()))
        node = frame
        for step in path:
            node = node[step]
        node.update(members)
        out.append((label, frame))

    at("an unknown member of the frame", principal_id="prn_0000000000000001")
    at("an unknown member of the context", "ctx", owner_scope="scp-" + "0" * 32)
    at("an unknown member of the client", "ctx", "client", os="linux")
    at("an unknown member of the command", "command", on_behalf_of="someone")
    at("an unknown member of the body", "command", "spec", privileged=True)
    at("an unknown member of the resources", "command", "spec", "resources", gpus=1)
    at("an unknown member of the network", "command", "spec", "network", fallback="open")
    at("an unknown operation", op="operator")
    at("no operation", op=None)
    for unknown in (
        "profile_reload",
        "quarantine_release",
        "host_set_mode",
        "host_acknowledge",
        "sandbox.create",
        "CREATE_SANDBOX",
        "create_sandbox ",
        "",
        "run",
    ):
        at(f"the command type {unknown!r}", "command", type=unknown)
    at("a command type that is not text", "command", type=1)
    at("a project that is not a project", "command", project="prj_short")
    at("a project of another shape", "command", project="../prj_0000000000000001")
    at("a number sent as text", "ctx", budget_ms="32000")
    at("a deadline of nothing", "ctx", budget_ms=0)
    at("a deadline beyond the hour", "ctx", budget_ms=3_600_001)
    at("an unknown interface", "ctx", interface="grpc")
    at("a request id of another shape", "ctx", request_id="req-1")
    at("a trace parent of another shape", "ctx", traceparent="00-xyz")
    at("a client name beyond its bound", "ctx", "client", name="n" * 65)
    at("a client version beyond its bound", "ctx", "client", version="1" * 33)
    at("a client name with a control character", "ctx", "client", name="acf\npython")
    at("an empty idempotency key", idempotency_key="")
    at("an idempotency key beyond its bound", idempotency_key="k" * 256)
    at("an idempotency key with a space", idempotency_key="key 1")
    at("an idempotency key with a control character", idempotency_key="key\t1")
    at("an idempotency key that is not ASCII", idempotency_key="cl\u00e9")
    at("an idempotency key that is not text", idempotency_key=1)
    at("a credential that is not text", credential=12345)
    at("a wait beyond its bound", "command", wait=3601)
    at("a wait that is not whole", "command", wait=1.5)
    at("a network mode the model does not have", "command", "spec", "network", mode="restricted")
    at("no command", command=None)
    at("a list of commands", command=[command("info")])
    return out


MUTATIONS = _mutations()


@pytest.mark.parametrize(("label", "frame"), MUTATIONS, ids=[label for label, _ in MUTATIONS])
def test_an_unknown_command_or_member_is_refused_and_the_refusal_holds_nothing_of_the_frame(
    label: str, frame: dict[str, Any]
) -> None:
    with pytest.raises(CodecError) as refused:
        codec.decode_request(payload(frame))
    assert not isinstance(refused.value, VersionRefused)
    assert "problem(s)" in str(refused.value)
    says_nothing_of(refused.value, CANARY)
    says_nothing_of(refused.value, "key-0001")
    # The frame it was made from is accepted: it was refused for the change, and for nothing else.
    codec.decode_request(payload(handle()))


@pytest.mark.parametrize("missing", ["op", "ctx", "command"])
def test_a_frame_without_a_required_member_is_refused(missing: str) -> None:
    frame = handle()
    del frame[missing]
    with pytest.raises(CodecError) as refused:
        codec.decode_request(payload(frame))
    says_nothing_of(refused.value, CANARY)
    for inner in ("request_id", "budget_ms", "interface", "interface_version"):
        partial = json.loads(json.dumps(handle()))
        del partial["ctx"][inner]
        with pytest.raises(CodecError):
            codec.decode_request(payload(partial))


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"null",
        b"[]",
        b'"handle"',
        b"1",
        b"{",
        b"\xff\xfe",
        b"\xef\xbb\xbf{}",
        b'{"version":1,"version":2,"op":"verify"}',
        b'{"version":1,"op":"verify","ctx":{"request_id":"a","request_id":"b"}}',
        b'{"version":NaN}',
        b"{" * 100,
    ],
)
def test_a_payload_that_is_not_one_json_object_is_refused(body: bytes) -> None:
    for decode in (codec.decode_request, codec.peek_version):
        with pytest.raises(CodecError) as refused:
            decode(body)
        assert not isinstance(refused.value, VersionRefused)


def test_a_frame_that_repeats_a_member_is_refused_whichever_value_a_parser_would_take() -> None:
    """Two parsers could disagree about which credential, key or command a repeated member means."""
    good = payload(handle())
    for doubled in (
        good[:-1] + b',"credential":"another"}',
        good[:-1] + b',"idempotency_key":"another"}',
        good[:-1] + b',"command":{"type":"info"}}',
        good[:-1] + b',"version":' + str(VERSION).encode() + b"}",
    ):
        with pytest.raises(CodecError) as refused:
            codec.decode_request(doubled)
        says_nothing_of(refused.value, CANARY)


def test_a_refusal_of_a_frame_holds_no_credential_whatever_made_it_invalid() -> None:
    """The validation error of the frame names its input. Only a count leaves the codec."""
    for frame in (
        {k: v for k, v in handle().items() if k != "ctx"},
        handle(command={"type": "nonexistent"}),
        handle(unknown={"credential_copy": CANARY}),
        {**handle(), "ctx": {**CTX, "budget_ms": CANARY}},
        {**handle(), "idempotency_key": CANARY + " with a space"},
    ):
        with pytest.raises(CodecError) as refused:
            codec.decode_request(payload(frame))
        says_nothing_of(refused.value, CANARY)
    truncated = payload(handle())[:-20]
    with pytest.raises(CodecError) as cut:
        codec.decode_request(truncated)
    says_nothing_of(cut.value, CANARY)


# ------------------------------------------------------------------------------- answers
ERROR = m.ErrorBody(
    code="OUTCOME_UNRESOLVED",
    kind="UNRESOLVED",
    retry="SAME_REQUEST_LATER",
    message="ask again",
    request_id="req_0000000000000000000001",
    idempotency_key="key-0001",
)
TOOL = a.ToolDefinition(
    name="sandbox_exec",
    title="Run a command",
    description="Run one command.",
    input_schema={"type": "object", "properties": {"argv": {"type": "array"}}, "additionalProperties": False},
    output_schema={"type": "object"},
    read_only=False,
    destructive=True,
    idempotent=False,
    open_world=True,
)
ANSWERS: dict[str, Any] = {
    "view": a.ViewAnswer(
        view="Operation",
        body={"operation_id": OPERATION, "state": "IN_PROGRESS", "nested": {"list": [1, None, "\u00e9"]}},
        terminal=False,
        replayed=True,
        retry_after_s=1,
        etag="r7.0123456789ab",
        created=True,
    ),
    "error": a.ErrorAnswer(
        error=ERROR,
        retry_after_s=2,
        challenge=a.Challenge(www_authenticate='Bearer realm="acf", error="invalid_token"'),
    ),
    "verified": a.VerifiedAnswer(),
    "tools": a.ToolsAnswer(
        tools=[TOOL, TOOL.model_copy(update={"name": "sandbox_list", "read_only": True, "destructive": False})]
    ),
    "tool": a.ToolAnswer(
        structured={"ok": False, "error": ERROR.model_dump()}, is_error=True, delivery_token="tok_0123456789"
    ),
    "protocol_fault": a.ProtocolFaultAnswer(
        fault="invalid_arguments", message="the arguments do not fit the schema of the tool"
    ),
    "discover": a.DiscoverAnswer(
        server_name="acf",
        server_version="0.3.0",
        instructions="Inspect before acting again.",
        platform_features=["long_poll"],
        host_features=[],
    ),
    "ack": a.AckAnswer(),
}


def test_the_table_of_answers_holds_one_of_every_type() -> None:
    union = typing.get_args(typing.get_args(a.Answer)[0])
    assert sorted(str(member.model_fields["kind"].default) for member in union) == sorted(ANSWERS)
    assert len(ANSWERS) == 8
    for kind, answer in ANSWERS.items():
        assert answer.kind == kind


@pytest.mark.proves("T3-VER-03", level="L1")
@pytest.mark.parametrize("kind", sorted(ANSWERS))
def test_every_answer_type_round_trips(kind: str) -> None:
    answer = ANSWERS[kind]
    encoded = codec.encode_answer(answer, VERSION)
    assert codec.decode_answer(encoded) == answer
    frame = json.loads(encoded)
    assert (frame["protocol"], frame["version"], frame["answer"]["kind"]) == ("acf.command", VERSION, kind)
    assert codec.encode_answer(codec.decode_answer(encoded), VERSION) == encoded
    framed = codec.encode_frame(encoded, codec.DEFAULT_MAX_ANSWER_FRAME)
    assert codec.decode_answer(framed[4:]) == answer


def test_an_answer_with_nothing_optional_round_trips() -> None:
    for answer in (
        a.ViewAnswer(view="Info", body={}),
        a.ErrorAnswer(
            error=m.ErrorBody(
                code="NOT_FOUND", kind="REFUSED", retry="NEVER", message="no such sandbox", request_id="req_1"
            )
        ),
        a.ToolAnswer(structured={}, is_error=False),
        a.ToolsAnswer(tools=[]),
    ):
        assert codec.decode_answer(codec.encode_answer(answer, VERSION)) == answer
    view = json.loads(codec.encode_answer(a.ViewAnswer(view="Info", body={}), VERSION))["answer"]
    assert view == {"kind": "view", "view": "Info", "body": {}, "replayed": False, "created": False}


@pytest.mark.parametrize(
    "answer",
    [
        {"kind": "refused"},
        {"kind": "view", "view": "Operation", "body": {}, "principal": "prn_1"},
        {"kind": "view", "view": "Operation"},
        {"kind": "error", "error": {"code": "NOT_FOUND"}},
        {
            "kind": "error",
            "error": {
                "code": "NOT_FOUND",
                "kind": "REFUSED",
                "retry": "NEVER",
                "message": "m",
                "request_id": "r",
                "host_class": "x",
            },
        },
        {"kind": "tool", "structured": {}, "is_error": "false"},
        {"kind": "protocol_fault", "fault": "timeout", "message": "m"},
        {"kind": "ack", "extra": 1},
        {},
        None,
        [],
    ],
    ids=lambda answer: json.dumps(answer)[:50],
)
def test_an_answer_that_is_not_one_is_refused(answer: Any) -> None:
    with pytest.raises(CodecError) as refused:
        codec.decode_answer(payload({"protocol": "acf.command", "version": VERSION, "answer": answer}))
    assert not isinstance(refused.value, VersionRefused)
    assert "problem(s)" in str(refused.value)


def test_a_refusal_of_an_answer_holds_nothing_of_the_answer() -> None:
    """The answer to minting carries a secret once. A frame of it that cannot be decoded must not keep it."""
    minted = {
        "kind": "view",
        "view": "AgentCredential",
        "body": {"credential_id": CREDENTIAL, "secret": CANARY},
        "unknown_member": CANARY,
    }
    with pytest.raises(CodecError) as refused:
        codec.decode_answer(payload({"protocol": "acf.command", "version": VERSION, "answer": minted}))
    says_nothing_of(refused.value, CANARY)
    for not_a_frame in (
        b"",
        b"[]",
        b"{",
        payload({"protocol": "acf.command", "version": VERSION, "answer": minted})[:-9],
    ):
        with pytest.raises(CodecError) as cut:
            codec.decode_answer(not_a_frame)
        says_nothing_of(cut.value, CANARY)
