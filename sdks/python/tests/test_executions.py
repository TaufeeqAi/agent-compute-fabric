"""Executions: reading one, reading its output as bytes, and cancelling it."""

from __future__ import annotations

import base64
from typing import Any

import pytest

from agentcompute import AsyncFabric, Fabric, OperationFailedError, StateConflictError, UnexpectedResponseError
from support import EXE, EXE2, OP, OP2, REQ, Harness, Json, done, ex, execution, operation, refusal, reply


def _chunk(data: bytes, *, offset: int, eof: bool, stream: str = "stdout", **extra: Any) -> Json:
    body: Json = {
        "execution_id": EXE,
        "stream": stream,
        "offset": offset,
        "data_base64": base64.b64encode(data).decode("ascii"),
        "next_offset": offset + len(data),
        "eof": eof,
        "stored_bytes": 11,
        "produced_bytes": 11,
        "completeness": "COMPLETE",
        "provenance": "GUEST_REPORTED",
    }
    body.update(extra)
    return body


def _handle(harness: Harness, fabric: Fabric | AsyncFabric) -> Any:
    return harness.run(fabric.executions.get(EXE))


def _read_exchange(view: Json | None = None) -> Any:
    return ex("GET", f"/executions/{EXE}", reply(200, view or execution("EXITED", exit_code=0)))


def test_get_reads_one_execution(harness: Harness) -> None:
    view = execution("SIGNALED", exit_code=None, signal=9)
    script = harness.script(_read_exchange(view))
    handle = _handle(harness, harness.client(script))
    assert handle.raw == view
    assert (handle.execution_id, handle.status, handle.exit_code, handle.signal) == (EXE, "SIGNALED", None, 9)
    assert handle.stdout.completeness == "COMPLETE"
    assert handle.provenance["status"] == "GUEST_REPORTED"
    assert handle.request_id == REQ
    assert handle.operation is None


def test_refresh_updates_the_same_handle(harness: Harness) -> None:
    script = harness.script(
        _read_exchange(execution(None, exit_code=None, state="IN_PROGRESS")),
        _read_exchange(execution("EXITED", exit_code=2)),
    )
    handle = _handle(harness, harness.client(script))
    assert (handle.state, handle.status) == ("IN_PROGRESS", None)
    assert harness.run(handle.refresh()) is handle
    assert (handle.state, handle.status, handle.exit_code) == ("SUCCEEDED", "EXITED", 2)


def test_output_reads_one_slice_and_decodes_its_bytes(harness: Harness) -> None:
    script = harness.script(
        _read_exchange(),
        ex(
            "GET",
            f"/executions/{EXE}/output",
            reply(200, _chunk(b"\xff\x00hello", offset=0, eof=False)),
            query={"stream": "stdout", "offset": "0"},
            absent_query=["max_bytes"],
        ),
        ex(
            "GET",
            f"/executions/{EXE}/output",
            reply(200, _chunk(b"err", offset=4, eof=True, stream="stderr", completeness="TRUNCATED")),
            query={"stream": "stderr", "offset": "4", "max_bytes": "3"},
        ),
    )
    handle = _handle(harness, harness.client(script))
    first = harness.run(handle.output())
    assert first.data == b"\xff\x00hello"
    assert isinstance(first.data, bytes)
    assert (first.offset, first.next_offset, first.eof, first.completeness) == (0, 7, False, "COMPLETE")
    assert first.request_id == REQ
    second = harness.run(handle.output("stderr", offset=4, max_bytes=3))
    assert (second.stream, second.data, second.eof, second.completeness) == ("stderr", b"err", True, "TRUNCATED")


def test_read_follows_the_offsets_to_the_end_of_the_stream(harness: Harness) -> None:
    script = harness.script(
        _read_exchange(),
        ex(
            "GET",
            f"/executions/{EXE}/output",
            reply(200, _chunk(b"hello ", offset=0, eof=False)),
            query={"offset": "0"},
        ),
        ex(
            "GET",
            f"/executions/{EXE}/output",
            reply(200, _chunk(b"", offset=6, eof=False, next_offset=7)),
            query={"offset": "6"},
        ),
        ex("GET", f"/executions/{EXE}/output", reply(200, _chunk(b"world", offset=7, eof=True)), query={"offset": "7"}),
    )
    handle = _handle(harness, harness.client(script))
    assert harness.run(handle.read()) == b"hello world"


def test_read_of_an_empty_stream_is_empty(harness: Harness) -> None:
    script = harness.script(
        _read_exchange(),
        ex(
            "GET",
            f"/executions/{EXE}/output",
            reply(200, _chunk(b"", offset=0, eof=True, stream="stderr")),
            query={"stream": "stderr"},
        ),
    )
    assert harness.run(_handle(harness, harness.client(script)).read("stderr")) == b""


@pytest.mark.parametrize(
    ("data", "options", "expected"),
    [
        (b"caf\xc3\xa9\n", {}, "caf" + chr(0xE9) + "\n"),
        (b"caf\xe9", {"encoding": "latin-1"}, "caf" + chr(0xE9)),
        (b"ok\xff", {"errors": "replace"}, "ok" + chr(0xFFFD)),
        (b"ok\xff", {"errors": "ignore"}, "ok"),
    ],
)
def test_text_decodes_with_the_encoding_and_the_error_policy_the_caller_chose(
    harness: Harness, data: bytes, options: dict[str, str], expected: str
) -> None:
    script = harness.script(
        _read_exchange(), ex("GET", f"/executions/{EXE}/output", reply(200, _chunk(data, offset=0, eof=True)))
    )
    assert harness.run(_handle(harness, harness.client(script)).text(**options)) == expected


def test_text_is_strict_by_default_because_output_is_guest_data(harness: Harness) -> None:
    script = harness.script(
        _read_exchange(), ex("GET", f"/executions/{EXE}/output", reply(200, _chunk(b"\xff", offset=0, eof=True)))
    )
    handle = _handle(harness, harness.client(script))
    with pytest.raises(UnicodeDecodeError):
        harness.run(handle.text())


def test_output_that_is_not_base64_is_not_an_answer_of_this_api(harness: Harness) -> None:
    broken = _chunk(b"x", offset=0, eof=True, data_base64="not base64!")
    script = harness.script(_read_exchange(), ex("GET", f"/executions/{EXE}/output", reply(200, broken)))
    handle = _handle(harness, harness.client(script))
    with pytest.raises(UnexpectedResponseError, match="data_base64"):
        harness.run(handle.read())


def test_a_chunk_that_does_not_advance_ends_the_reading_instead_of_looping(harness: Harness) -> None:
    stuck = _chunk(b"", offset=0, eof=False)
    script = harness.script(_read_exchange(), ex("GET", f"/executions/{EXE}/output", reply(200, stuck)))
    handle = _handle(harness, harness.client(script))
    with pytest.raises(UnexpectedResponseError, match="neither ends the stream nor advances"):
        harness.run(handle.read())


def test_output_of_an_execution_that_has_not_ended_is_refused_by_the_server(harness: Harness) -> None:
    script = harness.script(_read_exchange(), ex("GET", f"/executions/{EXE}/output", refusal("STATE_CONFLICT")))
    handle = _handle(harness, harness.client(script))
    with pytest.raises(StateConflictError):
        harness.run(handle.read())


def test_cancel_is_a_keyed_request_without_a_body_and_the_handle_takes_the_answer(harness: Harness) -> None:
    cancelled = done(
        "execution.cancel", "execution", execution("CANCELLED", exit_code=None, state="CANCELLED"), operation_id=OP2
    )
    script = harness.script(
        _read_exchange(execution(None, exit_code=None, state="IN_PROGRESS")),
        ex(
            "POST",
            f"/executions/{EXE}/cancel",
            reply(200, cancelled),
            json=None,
            headers={"idempotency-key": "cancel-1"},
            absent_headers=["content-type"],
        ),
    )
    handle = _handle(harness, harness.client(script))
    assert harness.run(handle.cancel(idempotency_key="cancel-1")) is handle
    assert handle.status == "CANCELLED"
    assert handle.operation.operation_id == OP2


def test_a_handle_made_without_a_request_cancels_at_once_and_then_shows_the_answer(harness: Harness) -> None:
    """A cancel takes a privilege away. Sent through an unread handle, no read stands between a caller and it."""
    cancelled = done("execution.cancel", "execution", execution("CANCELLED", exit_code=None), operation_id=OP2)
    script = harness.script(
        ex(
            "POST",
            f"/executions/{EXE}/cancel",
            reply(200, cancelled),
            json=None,
            headers={"idempotency-key": "stop-it"},
        )
    )
    handle = harness.client(script).executions.handle(EXE)
    assert script.seen == []
    assert (handle.execution_id, handle.raw) == (EXE, {"execution_id": EXE})
    assert (handle.request_id, handle.operation) == (None, None)
    assert repr(handle).endswith(f"(execution_id='{EXE}')")
    with pytest.raises(UnexpectedResponseError, match="member 'state' of this view is missing"):
        _ = handle.state
    assert harness.run(handle.cancel(idempotency_key="stop-it")) is handle
    assert [seen.method for seen in script.seen] == ["POST"], "the cancel was the first and only request"
    assert handle.status == "CANCELLED"
    assert handle.operation is not None
    assert handle.operation.operation_id == OP2


def test_a_handle_made_without_a_request_reads_output_and_can_be_read_itself(harness: Harness) -> None:
    script = harness.script(
        ex("GET", f"/executions/{EXE}/output", reply(200, _chunk(b"hello world", offset=0, eof=True))),
        _read_exchange(execution("EXITED", exit_code=3)),
    )
    handle = harness.client(script).executions.handle(EXE)
    assert harness.run(handle.read()) == b"hello world"
    harness.run(handle.refresh())
    assert (handle.status, handle.exit_code, handle.request_id) == ("EXITED", 3, REQ)


def test_an_answer_about_another_execution_is_not_taken_by_an_unread_handle_either(harness: Harness) -> None:
    other = done("execution.cancel", "execution", execution("CANCELLED", exit_code=None, execution_id=EXE2))
    script = harness.script(ex("POST", f"/executions/{EXE}/cancel", reply(200, other)))
    handle = harness.client(script).executions.handle(EXE)
    with pytest.raises(UnexpectedResponseError, match="another execution"):
        harness.run(handle.cancel())
    assert handle.raw == {"execution_id": EXE}


@pytest.mark.parametrize("wanted", ["", ".", ".."])
def test_an_unread_handle_is_not_made_for_what_cannot_be_an_identifier(harness: Harness, wanted: str) -> None:
    script = harness.script()
    with pytest.raises(ValueError, match="execution_id must name one record"):
        harness.client(script).executions.handle(wanted)
    with pytest.raises(ValueError, match="execution_id must be a string"):
        harness.client(script).executions.handle(7)  # type: ignore[arg-type]
    assert script.seen == []


def test_cancel_generates_a_key_and_follows_its_operation(harness: Harness) -> None:
    cancelling = reply(202, operation("execution.cancel", "IN_PROGRESS", operation_id=OP2), retry_after="1")
    cancelled = done("execution.cancel", "execution", execution("CANCELLED", exit_code=None), operation_id=OP2)
    script = harness.script(
        _read_exchange(),
        ex("POST", f"/executions/{EXE}/cancel", cancelling),
        ex("GET", f"/operations/{OP2}", reply(200, cancelled), query={"wait": "30"}),
    )
    handle = _handle(harness, harness.client(script))
    harness.run(handle.cancel())
    key = script.seen[1].key
    assert key is not None
    assert len(key) == 36


def test_a_cancel_that_did_not_succeed_is_raised_and_the_handle_is_left_as_it_was(harness: Harness) -> None:
    script = harness.script(
        _read_exchange(execution(None, exit_code=None, state="IN_PROGRESS")),
        ex(
            "POST",
            f"/executions/{EXE}/cancel",
            reply(200, operation("execution.cancel", "FAILED", effect="NOT_APPLIED")),
        ),
    )
    handle = _handle(harness, harness.client(script))
    with pytest.raises(OperationFailedError):
        harness.run(handle.cancel())
    assert handle.state == "IN_PROGRESS"


def test_a_cancel_whose_answer_carries_no_execution_leaves_the_handle_as_it_was(harness: Harness) -> None:
    bare = operation("execution.cancel", "SUCCEEDED", operation_id=OP2, target={"execution_id": EXE})
    script = harness.script(
        _read_exchange(execution(None, exit_code=None, state="IN_PROGRESS")),
        ex("POST", f"/executions/{EXE}/cancel", reply(200, bare)),
    )
    handle = _handle(harness, harness.client(script))
    with pytest.raises(UnexpectedResponseError, match="carries no execution"):
        harness.run(handle.cancel())
    assert handle.state == "IN_PROGRESS"


def test_an_answer_about_another_execution_is_not_taken(harness: Harness) -> None:
    other = done("execution.cancel", "execution", execution(execution_id=EXE2), operation_id=OP)
    script = harness.script(_read_exchange(), ex("POST", f"/executions/{EXE}/cancel", reply(200, other)))
    handle = _handle(harness, harness.client(script))
    with pytest.raises(UnexpectedResponseError, match="another execution"):
        harness.run(handle.cancel())
    assert handle.execution_id == EXE


def test_an_operation_is_read_as_it_is_now_or_after_the_server_waited(harness: Harness) -> None:
    running = operation("execution.create", "IN_PROGRESS", operation_id=OP2)
    script = harness.script(
        ex("GET", f"/operations/{OP2}", reply(200, running), absent_query=["wait"]),
        ex("GET", f"/operations/{OP2}", reply(200, running), query={"wait": "0"}),
        ex(
            "GET",
            f"/operations/{OP2}",
            reply(200, operation("execution.create", operation_id=OP2)),
            query={"wait": "25"},
        ),
    )
    fabric = harness.client(script)
    assert harness.run(fabric.operations.get(OP2)).state == "IN_PROGRESS"
    assert harness.run(fabric.operations.get(OP2, wait=0)).request_id == REQ
    ended = harness.run(fabric.operations.get(OP2, wait=25))
    assert (ended.state, ended.terminal, ended.operation_id) == ("SUCCEEDED", True, OP2)
    assert harness.clock.slept == []
