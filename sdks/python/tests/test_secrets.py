"""The credential appears in one header and nowhere else a program or a person could come across it.

Every test here runs calls with a canary key and then searches for it in everything the calls left
behind: every log record of every logger, every ``repr`` and ``str`` of a client, a handle, a view and
an error, every argument, attribute and note of every exception in a chain, every formatted traceback,
and the ``repr`` of every local variable of this package's own frames in those tracebacks, which is what
an error reporter that captures locals would show.
"""

from __future__ import annotations

import logging
import traceback
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import Any

import pytest

from agentcompute import (
    AsyncFabric,
    AuthenticationError,
    ConfigurationError,
    Fabric,
    FabricError,
    OperationFailedError,
    OutcomeUnresolvedError,
)
from support import (
    CANARY_KEY,
    CRD,
    OP2,
    OP3,
    REGISTRY_ROWS,
    SBX,
    SBX2,
    SNP,
    WHOAMI,
    Exchange,
    Harness,
    done,
    ex,
    execution,
    failure,
    fault,
    operation,
    page,
    refusal,
    reply,
    sandbox,
    snapshot,
)

_CREATED = reply(200, done("sandbox.create", "sandbox", sandbox("READY")))
_STARTED = reply(200, done("sandbox.start", "sandbox", sandbox("RUNNING"), operation_id=OP2))
_START_FAILED = reply(
    200, operation("sandbox.start", "FAILED", operation_id=OP2, effect="NOT_APPLIED", failure=failure("TIMEOUT"))
)
_RAN = reply(200, done("execution.create", "execution", execution(), operation_id=OP3))
_SECRET_FREE_CREDENTIAL = {
    "credential_id": CRD,
    "kind": "agent",
    "label": "builder",
    "display_prefix": "acf1_agt_abcd",
    "status": "REVOKED",
    "issued_at": "2026-11-19T10:00:00.000Z",
    "expires_at": "2026-11-19T11:00:00.000Z",
}


def _own_frame(filename: str) -> bool:
    parts = Path(filename).parts
    return "agentcompute" in parts and "tests" not in parts


def _left_by_error(error: BaseException, *, frames: bool = True) -> Iterator[str]:
    """Everything one exception, and every exception it leads to, can show.

    ``frames=False`` leaves out the local variables of this package's frames: an answer that itself
    repeats the credential is held in them, as data, for as long as it is being read.
    """
    pending: list[BaseException] = [error]
    visited: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in visited:
            continue
        visited.add(id(current))
        yield str(current)
        yield repr(current)
        yield repr(current.args)
        yield repr(getattr(current, "__notes__", ()))
        yield repr(vars(current))
        yield "".join(traceback.format_exception(current))
        frame_walker = current.__traceback__ if frames else None
        while frame_walker is not None:
            if _own_frame(frame_walker.tb_frame.f_code.co_filename):
                yield from (repr(value) for value in frame_walker.tb_frame.f_locals.values())
            frame_walker = frame_walker.tb_next
        linked = [current.__cause__, current.__context__, *vars(current).values()]
        pending.extend(link for link in linked if isinstance(link, BaseException))


def _left_by_object(value: object) -> Iterator[str]:
    yield repr(value)
    yield str(value)
    if hasattr(value, "__dict__"):
        yield repr(vars(value))


def _left_by_client(fabric: Fabric | AsyncFabric) -> Iterator[str]:
    driver = fabric._driver
    for part in (fabric, driver, driver.engine, fabric.sandboxes, fabric.auth):
        yield from _left_by_object(part)
    yield repr(vars(driver.engine))


class _Evidence:
    """Collects what was left behind, and fails if the canary is in any of it."""

    def __init__(self, caplog: pytest.LogCaptureFixture) -> None:
        self._caplog = caplog
        self.texts: list[str] = []

    def take(self, texts: Iterable[str]) -> None:
        self.texts.extend(texts)

    def assert_clean(self, canary: str = CANARY_KEY) -> None:
        for record in self._caplog.records:
            self.texts.extend([record.getMessage(), repr(record.args), repr(vars(record))])
        assert self.texts, "nothing was collected: the test proves nothing"
        leaks = [text for text in self.texts if canary in text]
        assert not leaks, f"the credential appears in {len(leaks)} place(s); the first: {leaks[0][:200]!r}"


@pytest.fixture
def evidence(caplog: pytest.LogCaptureFixture) -> _Evidence:
    caplog.set_level(logging.DEBUG)  # every logger, the HTTP library's included
    return _Evidence(caplog)


def test_the_canary_reaches_the_server_in_the_authorization_header(harness: Harness) -> None:
    script = harness.script(ex("GET", f"/sandboxes/{SBX}", reply(200, sandbox())))
    harness.run(harness.client(script).sandboxes.get(SBX))
    assert script.seen[0].headers["authorization"] == f"Bearer {CANARY_KEY}"


def test_successful_calls_leave_the_credential_nowhere(harness: Harness, evidence: _Evidence) -> None:
    script = harness.script(
        ex("POST", "/sandboxes", _CREATED),
        ex("POST", f"/sandboxes/{SBX}/start", _STARTED),
        ex("POST", f"/sandboxes/{SBX}/executions", _RAN),
        ex("POST", f"/sandboxes/{SBX}/snapshots", reply(200, done("snapshot.create", "snapshot", snapshot()))),
        ex("GET", "/sandboxes", reply(200, page([sandbox(), sandbox(sandbox_id=SBX2)]))),
        ex("GET", "/v1/auth/whoami", reply(200, WHOAMI)),
        ex("GET", f"/operations/{OP3}", reply(200, operation("execution.create", operation_id=OP3))),
        ex("DELETE", f"/sandboxes/{SBX}", reply(200, done("sandbox.destroy", "sandbox", sandbox("DESTROYED")))),
    )
    fabric = harness.client(script)
    created = harness.run(fabric.sandboxes.create("python", cpu=1, memory="512MiB", disk="1GiB"))
    ran = harness.run(created.exec(["python", "-V"]))
    taken = harness.run(created.snapshot())
    listed = harness.collect(fabric.sandboxes.list())
    me = harness.run(fabric.whoami())
    looked_up = harness.run(fabric.operations.get(OP3))
    harness.run(created.destroy())

    evidence.take(_left_by_client(fabric))
    for value in (created, ran, taken, *listed, me, looked_up, created.operation, ran.operation, created.image):
        evidence.take(_left_by_object(value))
    evidence.assert_clean()


def _create(fabric: Any) -> Any:
    return fabric.sandboxes.create("python", cpu=1, memory=512, disk=1024, idempotency_key="key-1")


def _create_only(fabric: Any) -> Any:
    return fabric.sandboxes.create("python", cpu=1, memory=512, disk=1024, start=False, idempotency_key="key-1")


def _read(fabric: Any) -> Any:
    return fabric.sandboxes.get(SBX)


def _exec(fabric: Any) -> Any:
    return fabric.sandboxes.handle(SBX).exec(["true"], generation=1, follow_max=1)


_FAILURES: dict[str, tuple[list[Exchange], Callable[[Any], Any]]] = {
    "a read that is never answered": ([ex("GET", f"/sandboxes/{SBX}", fault())] * 3, _read),
    "a read that times out": ([ex("GET", f"/sandboxes/{SBX}", fault("timeout"))] * 3, _read),
    "a server that cannot be reached": ([ex("GET", f"/sandboxes/{SBX}", fault("connect_error"))] * 3, _read),
    "a mutation that is never answered": ([ex("POST", "/sandboxes", fault())] * 3, _create_only),
    "a server that is not this API": ([ex("GET", f"/sandboxes/{SBX}", reply(404))], _read),
    "an answer that is not JSON": ([ex("GET", f"/sandboxes/{SBX}", reply(200))], _read),
    "an operation that failed": (
        [ex("POST", "/sandboxes", reply(200, operation("sandbox.create", "FAILED", effect="NOT_APPLIED")))],
        _create_only,
    ),
    "an operation with an unknown outcome": (
        [ex("POST", "/sandboxes", reply(200, operation("sandbox.create", "UNKNOWN")))],
        _create_only,
    ),
    "an operation that is still running": (
        [
            ex(
                "POST",
                f"/sandboxes/{SBX}/executions",
                reply(202, operation("execution.create", "ACCEPTED"), retry_after="5"),
            )
        ],
        _exec,
    ),
    "a start that failed, sandbox destroyed": (
        [
            ex("POST", "/sandboxes", _CREATED),
            ex("POST", f"/sandboxes/{SBX}/start", _START_FAILED),
            ex("DELETE", f"/sandboxes/{SBX}", reply(200, done("sandbox.destroy", "sandbox", sandbox("DESTROYED")))),
        ],
        _create,
    ),
    "a start that failed, destroy failed too": (
        [
            ex("POST", "/sandboxes", _CREATED),
            ex("POST", f"/sandboxes/{SBX}/start", refusal("UNAUTHENTICATED")),
            ex("DELETE", f"/sandboxes/{SBX}", refusal("UNAUTHENTICATED")),
        ],
        _create,
    ),
    "a start that was never answered": (
        [ex("POST", "/sandboxes", _CREATED), *[ex("POST", f"/sandboxes/{SBX}/start", fault())] * 3],
        _create,
    ),
    "a snapshot that is not listed": (
        [ex("GET", "/snapshots", reply(200, page([])))],
        lambda fabric: fabric.snapshots.get(SNP),
    ),
    "a mint whose answer is lost": (
        [ex("POST", "/agent-credentials", fault())],
        lambda fabric: fabric.auth.mint_agent_credential("builder", lifetime="1h"),
    ),
    "a revocation that cannot contain": (
        [
            ex("DELETE", f"/agent-credentials/{CRD}", reply(200, _SECRET_FREE_CREDENTIAL)),
            ex("GET", "/v1/auth/whoami", refusal("UNAUTHENTICATED")),
        ],
        lambda fabric: fabric.auth.revoke_agent_credential(CRD, contain=True),
    ),
}


@pytest.mark.parametrize("case", sorted(_FAILURES))
def test_a_failure_leaves_the_credential_nowhere(harness: Harness, evidence: _Evidence, case: str) -> None:
    exchanges, call = _FAILURES[case]
    fabric = harness.client(harness.script(*exchanges))
    with pytest.raises(FabricError) as raised:
        harness.run(call(fabric))
    evidence.take(_left_by_error(raised.value))
    evidence.take(_left_by_client(fabric))
    evidence.assert_clean()


@pytest.mark.parametrize("code", sorted(code for code, row in REGISTRY_ROWS.items() if row["error_answer"]))
def test_no_error_answer_leaves_the_credential_anywhere(harness: Harness, evidence: _Evidence, code: str) -> None:
    """Every code of the registry, UNAUTHENTICATED first among them: the one a key is most easily echoed for."""
    answers = [ex("POST", "/sandboxes", refusal(code, idempotency_key="key-1"))] * 3
    script = harness.script(*answers)
    fabric = harness.client(script)
    with pytest.raises(FabricError) as raised:
        harness.run(_create_only(fabric))
    evidence.take(_left_by_error(raised.value))
    evidence.assert_clean()
    script.pending.clear()  # a code that is not retried leaves the other scripted answers unasked


@pytest.mark.parametrize(
    "call",
    [
        lambda fabric: fabric.sandboxes.create("python", cpu=1, memory="4GB", disk=1024),
        lambda fabric: fabric.sandboxes.create("python", cpu=1, memory=512, disk=1024, idempotency_key="a b"),
        lambda fabric: fabric.sandboxes.create("python", cpu=1, memory=512, disk=1024, network="restricted"),
        lambda fabric: fabric.sandboxes.handle(SBX).exec("python -V", generation=1),
        lambda fabric: fabric.sandboxes.handle(SBX).start(),
        lambda fabric: fabric.executions.get(""),
    ],
)
def test_a_refused_argument_leaves_the_credential_nowhere(harness: Harness, evidence: _Evidence, call: Any) -> None:
    fabric = harness.client(harness.script())
    with pytest.raises(ValueError, match=r"\w") as raised:
        harness.run(call(fabric))
    evidence.take(_left_by_error(raised.value))
    evidence.assert_clean()


@pytest.mark.parametrize(
    "options",
    [
        {"base_url": None},
        {"base_url": "ftp://acf.example"},
        {"base_url": "http://acf.example"},
        {"base_url": f"https://developer:{CANARY_KEY}@acf.example"},  # a key pasted into the URL
        {"base_url": f"https://acf.example/?api_key={CANARY_KEY}"},
        {"base_url": f"https://acf.example/#{CANARY_KEY}"},
        {"base_url": "https://acf.example:port"},
        {"base_url": "https://"},
        {"timeout": 0},
        {"max_retries": -1},
        {"follow_max": -1},
        {"api_key": CANARY_KEY + " "},  # a key copied with the space after it
        {"api_key": CANARY_KEY + "\n"},
        {"api_key": CANARY_KEY + chr(0xE9)},
        {"http_client": "not a client"},
    ],
)
def test_a_configuration_error_never_repeats_the_key_or_a_url_that_may_hold_one(
    harness: Harness, options: dict[str, Any]
) -> None:
    client_type = AsyncFabric if harness.is_async else Fabric
    arguments = {"api_key": CANARY_KEY, "base_url": "https://acf.example", **options}
    with pytest.raises(ConfigurationError) as raised:
        client_type(arguments.pop("api_key"), **arguments)
    error = raised.value
    shown = [str(error), repr(error), repr(error.args), "".join(traceback.format_exception(error))]
    assert all(CANARY_KEY not in text for text in shown)
    assert error.__cause__ is None
    assert error.__suppress_context__ or error.__context__ is None


def test_the_engine_holds_the_key_only_inside_an_object_that_does_not_show_it(harness: Harness) -> None:
    fabric = harness.client(harness.script())
    engine = fabric._driver.engine
    plain = [name for name, value in vars(engine).items() if isinstance(value, str) and CANARY_KEY in value]
    assert plain == []
    assert "[secure]" in repr(vars(engine)["_headers"])
    assert CANARY_KEY not in repr(vars(engine))
    assert not any(CANARY_KEY in repr(vars(part)) for part in (fabric, fabric._driver))


# ------------------------------------------------------- when something on the way repeats the credential
def test_a_credential_echoed_in_an_error_answer_is_taken_out_before_it_reaches_the_error(
    harness: Harness, evidence: _Evidence
) -> None:
    """The platform never repeats a credential. A gateway in front of it, quoting the request, might."""
    echo = refusal(
        "UNAUTHENTICATED",
        message=f"the key {CANARY_KEY} is not valid",
        reason=f"bad:{CANARY_KEY}",
        request_id=f"req_{CANARY_KEY}",
        detail=f"Authorization: Bearer {CANARY_KEY}",
    )
    echo["headers"]["x-request-id"] = f"req_{CANARY_KEY}"
    script = harness.script(ex("GET", f"/sandboxes/{SBX}", echo))
    with pytest.raises(AuthenticationError) as raised:
        harness.run(harness.client(script).sandboxes.get(SBX))
    error = raised.value
    assert error.message == "the key [redacted] is not valid"
    assert error.reason == "bad:[redacted]"
    assert error.request_id == "req_[redacted]"
    evidence.take(_left_by_error(error, frames=False))
    evidence.assert_clean()


def test_a_credential_quoted_by_a_transport_failure_is_taken_out_and_the_failure_is_not_kept(
    harness: Harness, evidence: _Evidence
) -> None:
    """A transport that cannot send a header may quote the whole header in its error."""
    quoting = {"fault": "protocol_error", "message": f"Illegal header value b'Bearer {CANARY_KEY}'"}
    script = harness.script(*[ex("POST", "/sandboxes", quoting)] * 3)
    with pytest.raises(OutcomeUnresolvedError) as raised:
        harness.run(_create_only(harness.client(script)))
    assert "Illegal header value b'Bearer [redacted]'" in str(raised.value)
    # The foreign exception shows the credential, so it is not attached as the cause of anything.
    assert raised.value.__cause__ is None
    evidence.take(_left_by_error(raised.value))
    evidence.assert_clean()


def test_a_transport_failure_that_shows_no_credential_is_kept_as_the_cause(harness: Harness) -> None:
    script = harness.script(*[ex("POST", "/sandboxes", fault("connection_reset"))] * 3)
    with pytest.raises(OutcomeUnresolvedError) as raised:
        harness.run(_create_only(harness.client(script)))
    assert type(raised.value.__cause__).__name__ == "ReadError"


def test_a_credential_echoed_in_the_failure_of_an_operation_is_taken_out_of_the_message(
    harness: Harness, evidence: _Evidence
) -> None:
    why = failure("SECURITY_CONTROL_FAILURE", message=f"token {CANARY_KEY} could not be checked")
    ended = operation("sandbox.create", "FAILED", effect="NOT_APPLIED", failure=why)
    script = harness.script(ex("POST", "/sandboxes", reply(200, ended)))
    with pytest.raises(OperationFailedError) as raised:
        harness.run(_create_only(harness.client(script)))
    assert "token [redacted] could not be checked" in str(raised.value)
    evidence.take([str(raised.value), repr(raised.value), repr(raised.value.args), repr(vars(raised.value))])
    evidence.assert_clean()
    # The view is the answer as received: what the server sent is still there for whoever asks for it.
    assert CANARY_KEY in raised.value.operation.raw["failure"]["message"]


def test_an_answer_is_never_shown_whole_where_local_variables_are_dumped(harness: Harness) -> None:
    """A body can hold a secret that was just minted. The objects that carry bodies do not print them."""
    minted = {**_SECRET_FREE_CREDENTIAL, "status": "ACTIVE", "secret": "acf1_agt_only_shown_once_K7dR2"}
    script = harness.script(
        ex("POST", "/agent-credentials", reply(201, minted)),
        ex("POST", "/agent-credentials", reply(404)),
    )
    fabric = harness.client(script)
    credential = harness.run(fabric.auth.mint_agent_credential("builder", lifetime="1h"))
    assert credential.secret == "acf1_agt_only_shown_once_K7dR2"
    assert "only_shown_once" not in f"{credential} {credential!r}"
    with pytest.raises(FabricError) as raised:
        harness.run(fabric.auth.mint_agent_credential("builder", lifetime="1h"))
    assert all("only_shown_once" not in text for text in _left_by_error(raised.value))
