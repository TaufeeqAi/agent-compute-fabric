"""The caller's half of the operation protocol of ``acf.host/2``.

A request to a method that creates an operation has exactly two answers: ``REFUSED`` (nothing was
accepted, nothing was recorded) or ``OPERATION`` (a durable record exists, and the answer is its
state as of the response). :meth:`HostClient.submit` drives one such request to the host's last
word on it, under four rules:

1. **One identity per intent.** The client generates the ``operation_id`` and stamps ``issued_at``
   once. Every later request about the same intent carries the same two values.
2. **A lost answer is resolved, never repeated.** If the request was written and no answer came
   back, the host may have accepted it. The client sends the *same* ``operation_id`` again with
   ``retry: true``; the host then answers with the existing operation, or says it has none
   (``NOT_FOUND``) and does not create one. A new id is never used for the same intent.
3. **A refusal is trusted only as far as it goes.** The host checks its mode, its rate limits and
   its safety profile before it looks for an existing record, so a *retry* can be refused although
   the operation exists. A refused retry is therefore followed by ``operation.get``: only "no such
   operation" there establishes that the request was never accepted. The same question is asked
   after a first submission is refused with ``INTERNAL_ERROR``, the one class with which a host
   says it does not know what went wrong.
4. **An accepted operation is followed, not awaited blindly.** A non-terminal answer is followed
   with ``operation.get`` until the operation is terminal or the caller's patience runs out. What
   is reported then is the state the host last stated — ``UNKNOWN`` as ``UNKNOWN``.

This module owns no policy and no lifecycle truth. It asks, and it reports what it was told.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from acf_cli.errors import (
    ExitCode,
    HostUnreachable,
    MutationInterrupted,
    NotFinished,
    OperationFailed,
    OutcomeUnknown,
    OutcomeUnresolved,
    ProtocolViolation,
    Refused,
    ResponseLost,
)
from acf_cli.requests import (
    Call,
    RequestEnvelope,
    new_operation_id,
    operation_envelope,
    operation_get,
    read_envelope,
    utc_timestamp,
)
from acf_cli.responses import AsOf, OperationBody, OperationView, Refusal, ResponseEnvelope, to_wire
from acf_cli.transport import (
    DEFAULT_MAX_REQUEST_BYTES,
    DEFAULT_MAX_RESPONSE_BYTES,
    DEFAULT_SOCKET,
    Connection,
    Endpoint,
    Exchange,
    UnixEndpoint,
)
from acf_cli.wire import PROTOCOL, Answer, FailureClass, OperationState, RetryAdvice

#: Owner scope used when none is given. An owner scope is an opaque label the host compares for
#: equality: records created under one scope are invisible to a ``caller`` under another.
DEFAULT_SCOPE = "default"
#: First submissions the client will make for one intent before it stops. Each one after the first
#: is made only once the host has stated that it holds no record of the operation.
MAX_SUBMISSIONS_NEVER_RECORDED = 3


def _default_endpoint() -> Endpoint:
    return UnixEndpoint(Path(DEFAULT_SOCKET))


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class ClientConfig:
    endpoint: Endpoint = field(default_factory=_default_endpoint)
    owner_scope: str = DEFAULT_SCOPE
    #: Opaque label the host records with every operation and never compares.
    on_behalf_of: str | None = None
    connect_timeout_s: float = 5.0
    #: How long the host is asked to hold the answer to a request that creates an operation
    #: (``wait_ms``). The host caps it at its own ``wait_max``.
    wait_s: float = 20.0
    #: How much longer than the requested wait the client listens for one response.
    response_margin_s: float = 10.0
    #: How long the client keeps trying to reach the host again once contact is lost in the middle
    #: of an operation, before it reports the outcome as not established.
    outage_patience_s: float = 60.0
    poll_initial_s: float = 0.1
    poll_max_s: float = 2.0
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES


@dataclass(frozen=True, slots=True)
class Outcome:
    """The host's last word on one operation id: a refusal, or the operation as last stated."""

    operation_id: str
    refusal: Refusal | None = None
    operation: OperationView | None = None
    #: The committed state the answer reflects.
    as_of: AsOf | None = None
    #: Requests sent under this operation id; 1 means the first one was answered.
    submissions: int = 1

    def __post_init__(self) -> None:
        if (self.refusal is None) == (self.operation is None):
            msg = "an outcome is either a refusal or an operation"
            raise ValueError(msg)

    def to_wire(self) -> dict[str, Any]:
        """The outcome in the shape of the answer it is: ``REFUSED`` or ``OPERATION``."""
        doc: dict[str, Any] = {"protocol": PROTOCOL}
        if self.operation is not None:
            doc |= {"answer": Answer.OPERATION.value, "operation": to_wire(self.operation)}
        elif self.refusal is not None:
            doc |= {"answer": Answer.REFUSED.value, "refusal": to_wire(self.refusal)}
        doc["as_of"] = to_wire(self.as_of) if self.as_of is not None else None
        return doc

    def envelope(self) -> ResponseEnvelope:
        return ResponseEnvelope.model_validate(self.to_wire())


def answer_document(envelope: ResponseEnvelope) -> dict[str, Any]:
    """An answer as the host sent it, without the per-request correlation id."""
    doc = to_wire(envelope)
    doc.pop("request_id", None)
    return doc


class _Deadline:
    """The caller's patience for one operation. ``None`` means: until the operation ends."""

    def __init__(self, now: Callable[[], float], timeout_s: float | None) -> None:
        self._now = now
        self._at = None if timeout_s is None else now() + max(timeout_s, 0.0)

    def remaining(self) -> float | None:
        return None if self._at is None else max(self._at - self._now(), 0.0)

    def expired(self) -> bool:
        return self._at is not None and self._now() >= self._at

    def clamp(self, seconds: float) -> float:
        left = self.remaining()
        return seconds if left is None else min(seconds, left)


class _Outage:
    """How long the host has been out of reach, without interruption."""

    def __init__(self, now: Callable[[], float], patience_s: float) -> None:
        self._now = now
        self._patience_s = patience_s
        self._since: float | None = None

    def note(self) -> None:
        if self._since is None:
            self._since = self._now()

    def over(self) -> None:
        self._since = None

    def exhausted(self) -> bool:
        return self._since is not None and self._now() - self._since >= self._patience_s


class _Pace:
    """Exponential spacing of polls and retries, capped."""

    def __init__(self, initial_s: float, maximum_s: float) -> None:
        self._next = initial_s
        self._maximum = maximum_s

    def step(self) -> float:
        current = self._next
        self._next = min(self._next * 2, self._maximum)
        return current


@dataclass(slots=True)
class _Drive:
    """The state of driving one operation id to the host's last word on it."""

    operation_id: str
    issued_at: str
    wait: bool
    deadline: _Deadline
    pace: _Pace
    #: Timed from the first answer that did not arrive and never reset: it bounds the whole effort
    #: to learn what became of this operation id.
    outage: _Outage
    #: Requests sent under the operation id.
    submissions: int = 0
    #: Submissions the host is known to have never recorded.
    never_recorded: int = 0
    #: Whether an earlier request may have reached the host. From then on the client asks; it does not submit.
    retry: bool = False


def parse_response(raw: bytes, request_id: str) -> ResponseEnvelope:
    """Decode one response frame and check that it answers the request with this ``request_id``."""
    try:
        envelope = ResponseEnvelope.model_validate_json(raw)
    except ValidationError as e:
        first = e.errors(include_input=False, include_url=False)[0]
        where = ".".join(str(part) for part in first["loc"]) or "the frame"
        raise ProtocolViolation(
            f"the answer is not a valid {PROTOCOL} response "
            f"({e.error_count()} problem(s); first: {where}: {first['msg']})",
            hint="is this client compatible with the host? compare `acf-local --version` with `acf-local host info`",
        ) from e
    if not isinstance(envelope.answer, Answer):
        raise ProtocolViolation(f"the host answered `{envelope.answer}`, which is not an answer of {PROTOCOL}")
    if envelope.request_id is not None and envelope.request_id != request_id:
        raise ProtocolViolation("the answer does not correspond to this request (request_id mismatch)")
    if envelope.answer is Answer.REFUSED:
        # A refusal can be issued before a request is read (an unenrolled peer) or by a host that
        # speaks another protocol version. It is still a refusal, and it says why.
        return envelope
    if envelope.protocol != PROTOCOL:
        raise ProtocolViolation(
            f"the host speaks {envelope.protocol!r}, this client speaks {PROTOCOL!r}",
            hint="use a client and a host of the same protocol major version",
        )
    if envelope.request_id is None:
        raise ProtocolViolation("the answer does not say which request it answers (no request_id)")
    return envelope


def expect[B](body: object, kind: type[B]) -> B:
    """``body`` as the typed result ``kind``, or a :class:`ProtocolViolation` naming what arrived instead."""
    if isinstance(body, kind):
        return body
    got = getattr(body, "type", None) or type(body).__name__
    raise ProtocolViolation(f"expected a `{kind.__name__}` result from the host, got `{got}`")


class HostClient:
    """One connection, kept for the life of the client; no other state between calls."""

    def __init__(
        self,
        config: ClientConfig | None = None,
        *,
        connection: Exchange | None = None,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.config = config or ClientConfig()
        self._connection: Exchange = connection or Connection(
            self.config.endpoint,
            connect_timeout_s=self.config.connect_timeout_s,
            max_request_bytes=self.config.max_request_bytes,
            max_response_bytes=self.config.max_response_bytes,
        )
        self._sleep = sleep
        self._now = monotonic
        self._wall_clock = wall_clock

    def close(self) -> None:
        self._connection.close()

    # ------------------------------------------------------------------ one round trip
    def roundtrip(self, envelope: RequestEnvelope, *, read_timeout_s: float | None = None) -> ResponseEnvelope:
        """Send one request and read its answer.

        Raises:
            HostUnreachable: the request did not reach the host.
            ResponseLost: the request was written and no usable answer came back.
            ProtocolViolation: what came back is not an answer of this protocol to this request.
        """
        timeout = read_timeout_s if read_timeout_s is not None else self.config.response_margin_s
        raw = self._connection.exchange(envelope.encode(), read_timeout_s=timeout)
        return parse_response(raw, envelope.request_id)

    # ------------------------------------------------------------------ reads
    def read(self, call: Call) -> ResponseEnvelope:
        """The answer to a read: ``RESULT`` or ``REFUSED``.

        A read leaves no record, so one whose answer is lost is simply asked again, once.
        """
        if call.method.creates_operation:
            msg = f"`{call.method}` creates an operation; use submit()"
            raise ValueError(msg)
        cfg = self.config
        try:
            answer = self.roundtrip(read_envelope(call, owner_scope=cfg.owner_scope, on_behalf_of=cfg.on_behalf_of))
        except ResponseLost:
            answer = self.roundtrip(read_envelope(call, owner_scope=cfg.owner_scope, on_behalf_of=cfg.on_behalf_of))
        if answer.answer is Answer.OPERATION:
            raise ProtocolViolation(f"the host answered the read `{call.method}` with an operation")
        return answer

    def result(self, call: Call) -> ResponseEnvelope:
        """The ``RESULT`` of a read. A refusal is raised as :class:`Refused`."""
        answer = self.read(call)
        if answer.refusal is not None:
            raise refused(answer.refusal, answer)
        return answer

    # ------------------------------------------------------------------ operations
    def submit(
        self,
        call: Call,
        *,
        operation_id: str | None = None,
        wait: bool = True,
        timeout_s: float | None = None,
        on_operation: Callable[[str], None] | None = None,
    ) -> Outcome:
        """Submit a request that creates an operation and return the host's last word on it.

        ``wait=False`` asks the host to answer as soon as the operation is recorded and does not
        follow it. ``timeout_s`` bounds how long the client follows a non-terminal operation; ``None``
        follows it until it ends, which the host guarantees within the operation's deadline.
        ``on_operation`` is told the operation id before anything is sent, so an interrupt handler
        always knows which operation is in flight.

        Raises:
            HostUnreachable: nothing was sent. The host did not act.
            OutcomeUnresolved: contact was lost after the request may have been sent, and the host
                could not be asked again before the client's patience ran out.
            ProtocolViolation: the host's answer could not be understood.
        """
        if not call.method.creates_operation:
            msg = f"`{call.method}` is a read; use read()"
            raise ValueError(msg)
        cfg = self.config
        state = _Drive(
            operation_id=operation_id or new_operation_id(),
            issued_at=utc_timestamp(self._wall_clock()),
            wait=wait,
            deadline=_Deadline(self._now, timeout_s),
            pace=_Pace(cfg.poll_initial_s, cfg.poll_max_s),
            outage=_Outage(self._now, cfg.outage_patience_s),
        )
        if on_operation is not None:
            on_operation(state.operation_id)
        try:
            return self._drive(call, state)
        except KeyboardInterrupt as e:
            raise MutationInterrupted(state.operation_id) from e

    def observe(self, operation_id: str) -> Outcome:
        """What the host says about ``operation_id`` now (one ``operation.get``)."""
        answer = self.read(operation_get(operation_id))
        if answer.refusal is not None:
            return Outcome(operation_id, refusal=answer.refusal, as_of=answer.as_of, submissions=0)
        view = expect(answer.result, OperationBody).data
        return Outcome(operation_id, operation=view, as_of=answer.as_of, submissions=0)

    def follow(self, operation_id: str, *, timeout_s: float | None = None) -> Outcome:
        """Observe ``operation_id`` until it is terminal, or until ``timeout_s`` has passed."""
        first = self.observe(operation_id)
        if first.operation is None:
            return first
        return self._follow(first.operation, first.as_of, _Deadline(self._now, timeout_s), submissions=0)

    # ------------------------------------------------------------------ the operation protocol
    def _drive(self, call: Call, state: _Drive) -> Outcome:
        op_id = state.operation_id
        while True:
            answer = self._attempt(call, state)
            if answer is None:
                continue
            if answer.operation is not None:
                return self._accepted(answer.operation, answer.as_of, state)
            if answer.refusal is None:
                raise ProtocolViolation(
                    f"the host answered `{call.method}` with a read result",
                    hint=f"ask the host what it recorded: acf-local operation get {op_id}",
                    operation_id=op_id,
                )
            if state.retry:
                outcome = self._after_refused_retry(state, answer.refusal, answer.as_of)
                if outcome is not None:
                    return outcome
            elif answer.refusal.failure_class is FailureClass.INTERNAL_ERROR:
                return self._after_unexplained_refusal(state, answer.refusal, answer.as_of)
            else:
                return Outcome(op_id, refusal=answer.refusal, as_of=answer.as_of, submissions=state.submissions)

    def _attempt(self, call: Call, state: _Drive) -> ResponseEnvelope | None:
        """Send the request once. ``None``: no answer arrived, and the caller is to ask again."""
        cfg = self.config
        op_id = state.operation_id
        wait_s = state.deadline.clamp(cfg.wait_s) if state.wait else 0.0
        envelope = operation_envelope(
            call,
            operation_id=op_id,
            issued_at=state.issued_at,
            owner_scope=cfg.owner_scope,
            on_behalf_of=cfg.on_behalf_of,
            retry=state.retry,
            wait_ms=round(wait_s * 1000),
        )
        state.submissions += 1
        try:
            return self.roundtrip(envelope, read_timeout_s=wait_s + cfg.response_margin_s)
        except HostUnreachable as e:
            if not state.retry:
                raise  # this submission never left; no earlier one can have been accepted
            self._pause(state, e)
        except ResponseLost as e:
            # The frame was written: the host may have accepted it. From here on, ask; do not submit.
            state.retry = True
            self._pause(state, e)
        except ProtocolViolation as e:
            raise ProtocolViolation(
                e.message,
                hint=f"the request may have been accepted. Ask the host: acf-local operation get {op_id}",
                operation_id=op_id,
            ) from e
        return None

    def _after_refused_retry(self, state: _Drive, refusal: Refusal, as_of: AsOf | None) -> Outcome | None:
        """A retry was refused. That is not yet an answer about the operation: ask for the record itself.

        ``None``: nothing is established yet, or the request is to be submitted afresh. Ask again.
        """
        op_id = state.operation_id
        try:
            found = self.read(operation_get(op_id))
        except (HostUnreachable, ResponseLost) as e:
            self._pause(state, e)
            return None
        if found.refusal is None:
            return self._accepted(expect(found.result, OperationBody).data, found.as_of, state)
        if found.refusal.failure_class is not FailureClass.NOT_FOUND:
            if found.refusal.retry is RetryAdvice.SAME_REQUEST_LATER:
                self._pause(state, ResponseLost(found.refusal.message))
                return None
            raise OutcomeUnresolved(
                f"the host would not say whether operation {op_id} exists "
                f"({found.refusal.failure_class}: {found.refusal.message})",
                hint=f"it may have been accepted. Ask again later: acf-local operation get {op_id}",
                operation_id=op_id,
            )
        # The host holds no record under this id: the request was never accepted.
        if refusal.failure_class is not FailureClass.NOT_FOUND:
            # ...and it says why it would not accept it now. That is the answer.
            return Outcome(op_id, refusal=refusal, as_of=as_of, submissions=state.submissions)
        state.never_recorded += 1
        if state.never_recorded >= MAX_SUBMISSIONS_NEVER_RECORDED:
            raise HostUnreachable(
                f"the host never recorded operation {op_id}: each of {state.never_recorded} submissions was lost "
                "before it was accepted. Nothing was applied",
                hint="the connection to the host drops while requests are in flight; check the network path",
                operation_id=op_id,
            )
        state.retry = False  # it is, again, a first submission: under the same id and the same issued_at
        return None

    def _after_unexplained_refusal(self, state: _Drive, refusal: Refusal, as_of: AsOf | None) -> Outcome:
        """The host refused and could not say why (``INTERNAL_ERROR``). Make sure it holds no record.

        A refusal means that nothing was recorded. A host that cannot tell what went wrong may not
        know that either — its edge answers this way when its core does not answer in time — so
        the record is asked for once before the refusal is reported as one.
        """
        op_id = state.operation_id
        try:
            found = self.read(operation_get(op_id))
        except (HostUnreachable, ResponseLost) as e:
            raise OutcomeUnresolved(
                f"the host refused operation {op_id} without a reason ({refusal.failure_class}: {refusal.message}) "
                f"and could not then be asked whether it had recorded it ({e})",
                hint=f"it may have been accepted. Ask the host: acf-local operation get {op_id}",
                operation_id=op_id,
            ) from e
        if found.refusal is None:
            return self._accepted(expect(found.result, OperationBody).data, found.as_of, state)
        if found.refusal.failure_class is FailureClass.NOT_FOUND:
            return Outcome(op_id, refusal=refusal, as_of=as_of, submissions=state.submissions)
        raise OutcomeUnresolved(
            f"the host refused operation {op_id} without a reason ({refusal.failure_class}: {refusal.message}) "
            f"and would not say whether it had recorded it ({found.refusal.failure_class}: {found.refusal.message})",
            hint=f"it may have been accepted. Ask again later: acf-local operation get {op_id}",
            operation_id=op_id,
        )

    def _accepted(self, view: OperationView, as_of: AsOf | None, state: _Drive) -> Outcome:
        if not state.wait:
            return Outcome(view.operation_id, operation=view, as_of=as_of, submissions=state.submissions)
        return self._follow(view, as_of, state.deadline, submissions=state.submissions)

    def _pause(self, state: _Drive, error: Exception) -> None:
        """Wait before asking the host again, or stop asking: its answer is then *not established*."""
        op_id = state.operation_id
        state.outage.note()
        if state.deadline.expired() or state.outage.exhausted():
            raise OutcomeUnresolved(
                f"lost contact with the host while operation {op_id} was in flight ({error})",
                hint="it may have been accepted. Do not submit it again under a new id; "
                f"ask the host: acf-local operation get {op_id}",
                operation_id=op_id,
            ) from error
        self._sleep(state.deadline.clamp(state.pace.step()))

    def _follow(self, view: OperationView, as_of: AsOf | None, deadline: _Deadline, *, submissions: int) -> Outcome:
        """Observe an accepted operation until it is terminal or the caller's patience has run out."""
        cfg = self.config
        op_id = view.operation_id
        pace = _Pace(cfg.poll_initial_s, cfg.poll_max_s)
        outage = _Outage(self._now, cfg.outage_patience_s)
        while not view.is_terminal and not deadline.expired():
            self._sleep(deadline.clamp(pace.step()))
            request = read_envelope(operation_get(op_id), owner_scope=cfg.owner_scope, on_behalf_of=cfg.on_behalf_of)
            try:
                answer = self.roundtrip(request)
            except (HostUnreachable, ResponseLost) as e:
                # The host may be restarting. The operation is durable: keep observing.
                outage.note()
                if outage.exhausted():
                    raise OutcomeUnresolved(
                        f"lost contact with the host while following operation {op_id} ({e})",
                        hint=f"the operation continues on the host. Ask it later: acf-local operation get {op_id}",
                        operation_id=op_id,
                    ) from e
                continue
            outage.over()
            if answer.refusal is not None:
                if answer.refusal.retry is RetryAdvice.SAME_REQUEST_LATER:
                    continue
                raise OutcomeUnresolved(
                    f"the host stopped answering for operation {op_id} "
                    f"({answer.refusal.failure_class}: {answer.refusal.message})",
                    hint=f"ask again later: acf-local operation get {op_id}",
                    operation_id=op_id,
                )
            view = expect(answer.result, OperationBody).data
            as_of = answer.as_of
        return Outcome(op_id, operation=view, as_of=as_of, submissions=submissions)


# ----------------------------------------------------------------------------- reading an outcome
def refused(refusal: Refusal, envelope: ResponseEnvelope, *, operation_id: str | None = None) -> Refused:
    return Refused(f"{refusal.failure_class}: {refusal.message}", envelope, operation_id=operation_id)


def as_refused(outcome: Outcome) -> Refused:
    """The exception that states an outcome which is a refusal."""
    if outcome.refusal is None:
        msg = f"operation {outcome.operation_id} was accepted; its outcome is not a refusal"
        raise ValueError(msg)
    return refused(outcome.refusal, outcome.envelope(), operation_id=outcome.operation_id)


def exit_code_for(view: OperationView) -> ExitCode:
    """The process exit code that states an operation's condition.

    Only ``SUCCEEDED`` is success and only ``FAILED`` and ``CANCELLED`` are failure. ``UNKNOWN`` —
    and any terminal state this client does not know — is neither. An operation that has not ended
    is not established yet.
    """
    if view.succeeded:
        return ExitCode.OK
    if not view.is_terminal:
        return ExitCode.UNRESOLVED
    if view.state in {OperationState.FAILED, OperationState.CANCELLED}:
        return ExitCode.FAILED
    return ExitCode.UNKNOWN


def require_success(outcome: Outcome) -> OperationView:
    """The operation, if it ``SUCCEEDED``; otherwise the exception that states what happened instead."""
    view = outcome.operation
    if view is None:
        raise as_refused(outcome)
    code = exit_code_for(view)
    if code is ExitCode.OK:
        return view
    what = f"operation {view.operation_id} ({view.operation_type})"
    why = f": {view.failure.failure_class}: {view.failure.message}" if view.failure is not None else ""
    if code is ExitCode.UNRESOLVED:
        raise NotFinished(
            f"{what} has not ended: it is {view.state}",
            outcome.envelope(),
            hint=f"it continues on the host. Follow it: acf-local operation get {view.operation_id} --wait",
            operation_id=view.operation_id,
        )
    if code is ExitCode.FAILED:
        raise OperationFailed(f"{what} ended {view.state}{why}", outcome.envelope(), operation_id=view.operation_id)
    raise OutcomeUnknown(
        f"{what} ended {view.state}{why}",
        outcome.envelope(),
        hint="it may have been applied, and the host cannot establish it. Treat it neither as success nor as "
        "failure; a new operation for the same intent is not known to be safe",
        operation_id=view.operation_id,
    )
