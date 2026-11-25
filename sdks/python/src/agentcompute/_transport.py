"""One request, its retries, and the following of an operation: decided once, driven twice.

Everything a call decides is written here as a *flow*: a generator that says what it needs next (send
this request, wait this long) and is told what happened. A flow never touches the network or a clock
that sleeps, so there is exactly one copy of every rule, and the synchronous and the asynchronous client
differ only in the two small drivers at the end of this module, which do what a flow asks and decide
nothing.

The rules, all from the client protocol of the API:

* A request is fixed before its first attempt: method, path, query, body bytes and idempotency key. A
  retry sends the same object again, so the key and the body cannot differ between attempts.
* What happens next is decided from ``kind``, ``code`` and ``retry`` of the problem document. The HTTP
  status alone decides nothing, and message text is never read.
* A request is repeated when the answer says ``SAME_REQUEST_LATER`` (whatever its code), when nothing
  was sent, and when it was sent and nothing came back. ``OUTCOME_LOST`` is never repeated.
* A mutation that got no answer is never reported as refused. Under its key it is either resolved by a
  later attempt or surfaced as unresolved, key attached.
* An operation is followed until it has ended or the follow bound passes. A state this version does not
  know has not ended. Giving up cancels nothing: there is no code path here that sends a cancel.
* The credential is in one header of each request. Text that comes back from outside (a message of the
  server, the words of a transport failure) is cleared of it before it can reach an error or a log.
"""

from __future__ import annotations

import asyncio
import json
import math
import random
import threading
import time
from collections import deque
from collections.abc import Awaitable, Callable, Generator, Mapping
from dataclasses import dataclass, field, replace
from typing import Any, Final, NoReturn
from urllib.parse import quote

import httpx2

from agentcompute import _telemetry
from agentcompute.errors import (
    KIND_UNRESOLVED,
    RETRY_SAME_REQUEST_LATER,
    APIConnectionError,
    APIError,
    APITimeoutError,
    CursorExpiredError,
    IncompatibleServerError,
    OperationFailedError,
    OperationStillRunningError,
    OutcomeUnknownError,
    OutcomeUnresolvedError,
    UnexpectedResponseError,
    error_class,
)
from agentcompute.types import Operation, WhoAmI, has_ended

__all__ = [
    "Answer",
    "AsyncDriver",
    "Engine",
    "Flow",
    "Item",
    "Request",
    "SyncDriver",
    "encode",
    "identifier",
    "page_items",
    "segment",
]

#: Retry delays: the n-th is a random value in [0, min(BACKOFF_MAX, BACKOFF_INITIAL * 2**n)], n from 0.
BACKOFF_INITIAL: Final = 0.5
BACKOFF_MAX: Final = 8.0
#: Polling cadence while following, when an answer gives no ``Retry-After``.
FOLLOW_BACKOFF_INITIAL: Final = 0.5
FOLLOW_BACKOFF_MAX: Final = 5.0
#: The longest wait asked of the server when reading an operation, in whole seconds. It is also the wait
#: the server applies to a mutation that names none.
FOLLOW_WAIT: Final = 30
#: A retry is allowed while the retries of the last BUDGET_WINDOW seconds are fewer than
#: BUDGET_FLOOR + BUDGET_RATIO * the requests of the same window.
BUDGET_WINDOW: Final = 60.0
BUDGET_FLOOR: Final = 10
BUDGET_RATIO: Final = 0.2
#: How often a listing is started again from the beginning after ``CURSOR_EXPIRED``.
LISTING_RESTARTS: Final = 3

_API_ROOT: Final = "/v1"
_PROBLEM_MEDIA_TYPE: Final = "application/problem+json"
_NOT_FOUND: Final = 404
_SERVER_ERRORS: Final = 500
_SUCCESS: Final = range(200, 300)
_CODE_OUTCOME_LOST: Final = "OUTCOME_LOST"
_CODE_OUTCOME_UNRESOLVED: Final = "OUTCOME_UNRESOLVED"
_EFFECT_NOT_APPLIED: Final = "NOT_APPLIED"
_STATE_SUCCEEDED: Final = "SUCCEEDED"
_STATE_UNKNOWN: Final = "UNKNOWN"
_BEARER: Final = "Bearer "
_REDACTED: Final = "[redacted]"
# Past this exponent the ceiling is BACKOFF_MAX anyway, and 2**n must not grow without bound.
_BACKOFF_EXPONENT_MAX: Final = 16
# How far the chain of causes of a foreign exception is examined before it is no longer trusted.
_CHAIN_MAX: Final = 16
_DOT_SEGMENTS: Final = frozenset({"", ".", ".."})

#: Failures of the HTTP library that prove no byte of the request left this process.
_NEVER_SENT: Final = (httpx2.ConnectError, httpx2.ConnectTimeout, httpx2.PoolTimeout, httpx2.UnsupportedProtocol)


@dataclass(frozen=True, slots=True)
class Request:
    """One HTTP request, complete before its first attempt and identical on every attempt."""

    method: str
    #: Path under the base URL. Every variable segment went through :func:`segment`.
    path: str
    query: tuple[tuple[str, str], ...] = ()
    #: The exact bytes of the body. Encoded once, so that a retry cannot send different ones.
    body: bytes | None = None
    #: The idempotency key, on every request that can create an operation.
    key: str | None = None
    #: Whether the request may be sent again after the server may have received it. True for a read,
    #: for anything under a key, and for a request that is idempotent by meaning. False for minting.
    repeatable: bool = True

    @property
    def mutates(self) -> bool:
        return self.method != "GET"


@dataclass(frozen=True, slots=True)
class Reply:
    """What came back for one attempt: nothing is interpreted yet.

    Its `repr` shows the status only: a body can hold a secret that was just minted, or guest output,
    and neither belongs in a dump of local variables.
    """

    status: int
    #: Header names are compared without case.
    headers: Mapping[str, str] = field(repr=False)
    body: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class NoAnswer:
    """One attempt that produced no usable answer."""

    #: False only when it is certain that nothing left this process.
    sent: bool
    timed_out: bool
    #: What happened, in words that are safe to show.
    detail: str
    cause: BaseException | None = None
    #: Set when something did answer, with a 5xx that is not the platform's.
    status: int | None = None
    request_id: str | None = None


@dataclass(frozen=True, slots=True)
class ErrorAnswer:
    """One attempt that was answered with a problem document."""

    error: APIError


@dataclass(frozen=True, slots=True)
class Answer:
    """A successful answer: the JSON object, and what its headers said. Its `repr` leaves the body out."""

    status: int
    body: dict[str, Any] = field(repr=False)
    request_id: str | None
    #: Seconds the server asked to wait before asking again, if it said so.
    retry_after: float | None


class Send:
    """Asks the driver to make one attempt. The driver puts what happened in ``outcome`` and resumes the flow."""

    __slots__ = ("outcome", "request")

    def __init__(self, request: Request) -> None:
        self.request = request
        self.outcome: Reply | NoAnswer


@dataclass(frozen=True, slots=True)
class Sleep:
    """Asks the driver to let this many seconds pass."""

    seconds: float


type Effect = Send | Sleep
type Flow[T] = Generator[Effect, None, T]
type Item = tuple[dict[str, Any], str | None]


# ------------------------------------------------------------------------------------- small pure helpers
def segment(value: str) -> str:
    """One path segment, percent-encoded so that no character of it can end the path or start a query."""
    return quote(value, safe="")


def identifier(value: object, *, what: str) -> str:
    """A caller's identifier or name, fit to become a path segment. Whether it exists is the server's to say.

    ``.`` and ``..`` survive percent-encoding, and a URL library resolves them into the path of another
    route before it sends the request, so they are refused, like the empty string.
    """
    if not isinstance(value, str):
        raise ValueError(f"{what} must be a string, not {type(value).__name__}")
    if value in _DOT_SEGMENTS:
        raise ValueError(f"{what} must name one record, not {value!r}")
    return value


def encode(body: Mapping[str, Any]) -> bytes:
    """The bytes of a JSON body. Called once per logical call, before the first attempt."""
    try:
        return json.dumps(body, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError(f"the request cannot be written as JSON: {error}") from None


def _json_object(body: bytes) -> dict[str, Any] | None:
    try:
        value = json.loads(body)
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _retry_after(headers: Mapping[str, str]) -> float | None:
    """``Retry-After`` in seconds. The API sends whole seconds; any other form is not advice this client reads."""
    text = headers.get("retry-after", "").strip()
    return float(text) if text.isascii() and text.isdecimal() else None


def _media_type(headers: Mapping[str, str]) -> str:
    return headers.get("content-type", "").partition(";")[0].strip().lower()


def _shows(error: BaseException, secret: str) -> bool:
    """Whether a foreign exception, or one it leads to, shows a secret where a printer of errors would look.

    A chain too long to examine counts as showing it.
    """
    pending: list[BaseException | None] = [error]
    examined = 0
    while pending:
        current = pending.pop()
        if current is None:
            continue
        examined += 1
        if examined > _CHAIN_MAX or secret in f"{current} {current!r}":
            return True
        pending += [current.__cause__, current.__context__]
    return False


def _may_repeat(request: Request, failure: ErrorAnswer | NoAnswer) -> bool:
    if isinstance(failure, NoAnswer):
        return request.repeatable or not failure.sent
    return failure.error.retry == RETRY_SAME_REQUEST_LATER and failure.error.code != _CODE_OUTCOME_LOST


def page_items(answer: Answer) -> list[dict[str, Any]]:
    """The ``items`` of a listing answer."""
    entries = answer.body.get("items")
    if not isinstance(entries, list) or not all(isinstance(entry, dict) for entry in entries):
        raise UnexpectedResponseError(
            "the server's answer is not a listing of this API: member 'items' is not a list of objects",
            status=answer.status,
            request_id=answer.request_id,
        )
    return entries


class RetryBudget:
    """Retries as a share of recent requests, per client: what stops a retry storm against a server shedding load."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests: deque[float] = deque()
        self._retries: deque[float] = deque()

    def sent(self, now: float) -> None:
        """Count one request that is about to be sent."""
        with self._lock:
            self._requests.append(now)

    def take(self, now: float) -> bool:
        """Spend one retry if the budget has one, and say whether it had."""
        horizon = now - BUDGET_WINDOW
        with self._lock:
            for window in (self._requests, self._retries):
                while window and window[0] <= horizon:
                    window.popleft()
            if len(self._retries) >= BUDGET_FLOOR + BUDGET_RATIO * len(self._requests):
                return False
            self._retries.append(now)
            return True


# ---------------------------------------------------------------------------------------------- the engine
class Engine:
    """The configuration of one client and every decision its calls make. Holds no state of the server.

    The one thing it remembers is the project, which a credential is bound to for its whole life.
    """

    def __init__(
        self,
        *,
        base_url: str,
        headers: httpx2.Headers,
        project: str | None,
        timeout: float,
        max_retries: int,
        follow_max: float,
        retry_total_max: float,
    ) -> None:
        self.base_url = base_url
        # The credential lives in this object and nowhere else. Its `repr` shows `[secure]` in place of
        # the value, so a dump of local variables or of this object does not show it either.
        self._headers = headers
        self._project = project
        self.timeout = httpx2.Timeout(timeout)
        self.max_retries = max_retries
        self.follow_max = follow_max
        self.retry_total_max = retry_total_max
        #: Seconds on a clock that only moves forward. Replaced by a virtual clock in tests.
        self.clock: Callable[[], float] = time.monotonic
        #: A random value in [0, 1). Jitter spreads retries; it is no secret, so no secure source is needed.
        self.jitter: Callable[[], float] = random.random
        self._budget = RetryBudget()

    @property
    def project(self) -> str | None:
        """The project, once it is known."""
        return self._project

    def url(self, request: Request) -> str:
        """The absolute URL of a request. It is always under the configured base URL: nothing else is ever built."""
        return self.base_url + request.path

    def headers(self, request: Request) -> httpx2.Headers:
        headers = self._headers.copy()
        if request.key is not None:
            headers["Idempotency-Key"] = request.key
        if request.body is not None:
            headers["Content-Type"] = "application/json"
        return headers

    def redact(self, text: str) -> str:
        """Text of foreign origin, with the credential taken out of it.

        The platform never repeats a credential, but what stands in front of it may: a gateway that
        quotes a request in its error page, a transport that quotes a header it could not send.
        """
        return text.replace(self._headers["Authorization"].removeprefix(_BEARER), _REDACTED)

    def unanswered(self, error: httpx2.RequestError) -> NoAnswer:
        """Classify a failure of the HTTP library. Only what proves it is counted as "nothing was sent"."""
        words = str(error)
        detail = f"{type(error).__name__}: {words}" if words else type(error).__name__
        shows = _shows(error, self._headers["Authorization"].removeprefix(_BEARER))
        return NoAnswer(
            sent=not isinstance(error, _NEVER_SENT),
            timed_out=isinstance(error, httpx2.TimeoutException),
            detail=self.redact(detail),
            # A foreign exception that shows the credential is not kept as the cause of anything.
            cause=None if shows else error,
        )

    # ------------------------------------------------------------------------------ one request
    def perform(self, request: Request) -> Flow[Answer]:
        """Send one request until it is answered usefully or may not be sent again, and return the answer."""
        started = self.clock()
        attempt = 1
        while True:
            self._budget.sent(self.clock())
            send = Send(request)
            yield send
            outcome = self._judge(request, send.outcome)
            if isinstance(outcome, Answer):
                return outcome
            delay = self._retry_delay(request, outcome, retries=attempt - 1, started=started)
            if delay is None:
                self._surface(request, outcome)
            reason = outcome.detail if isinstance(outcome, NoAnswer) else outcome.error.code
            _telemetry.retrying(method=request.method, path=request.path, attempt=attempt, delay=delay, reason=reason)
            yield Sleep(delay)
            attempt += 1

    def _judge(self, request: Request, outcome: Reply | NoAnswer) -> Answer | ErrorAnswer | NoAnswer:
        """Read one attempt. A response that is neither a view nor a problem document is raised from here."""
        if isinstance(outcome, NoAnswer):
            return outcome
        status = outcome.status
        header = outcome.headers.get("x-request-id")
        request_id = None if header is None else self.redact(header)
        document = _json_object(outcome.body)
        _telemetry.logger.debug("%s %s -> %d (request %s)", request.method, request.path, status, request_id)
        if status in _SUCCESS and _media_type(outcome.headers) != _PROBLEM_MEDIA_TYPE:
            if document is None:
                raise UnexpectedResponseError(
                    f"{request.method} {request.path} answered {status} with a body that is not a JSON object",
                    status=status,
                    request_id=request_id,
                )
            return Answer(status, document, request_id, _retry_after(outcome.headers))
        if document is not None and isinstance(document.get("code"), str):
            return ErrorAnswer(self._problem(request, outcome, document, request_id))
        if status == _NOT_FOUND:
            raise IncompatibleServerError(
                f"{self.base_url} does not speak version v1 of the Agent Compute Fabric API: "
                f"{request.method} {request.path} answered 404 without a problem document. Check base_url",
                status=status,
                request_id=request_id,
            )
        if status >= _SERVER_ERRORS and request.mutates:
            # Something between here and the platform failed after the request was sent. Whether the
            # platform received it is not known, which is exactly the case of an answer that never came.
            return NoAnswer(
                sent=True,
                timed_out=False,
                detail=f"HTTP {status} without a problem document",
                status=status,
                request_id=request_id,
            )
        raise UnexpectedResponseError(
            f"{request.method} {request.path} answered {status} without a problem document",
            status=status,
            request_id=request_id,
        )

    def _problem(self, request: Request, reply: Reply, document: Mapping[str, Any], request_id: str | None) -> APIError:
        """The error of a problem document. Every string of it is foreign text, and is redacted."""

        def member(name: str) -> str | None:
            value = document.get(name)
            return self.redact(value) if isinstance(value, str) else None

        code = member("code") or ""
        kind = member("kind") or ""
        named = member("idempotency_key")
        return error_class(code, kind)(
            member("message") or member("detail") or member("title") or "",
            code=code,
            kind=kind,
            retry=member("retry") or "",
            status=reply.status,
            request_id=member("request_id") or request_id,
            # An unresolved answer names the key to ask again with. When it does not, the key that was
            # sent is that key. A refusal leaves nothing behind, so there is no key to come back with.
            idempotency_key=named if named is not None or kind != KIND_UNRESOLVED else request.key,
            reason=member("reason"),
            retry_after=_retry_after(reply.headers),
        )

    def _retry_delay(
        self, request: Request, failure: ErrorAnswer | NoAnswer, *, retries: int, started: float
    ) -> float | None:
        """Seconds to wait before the next attempt, or ``None`` when the failure has to be surfaced now."""
        if not _may_repeat(request, failure) or retries >= self.max_retries:
            return None
        ceiling = min(BACKOFF_MAX, BACKOFF_INITIAL * 2 ** min(retries, _BACKOFF_EXPONENT_MAX))
        delay = self.jitter() * ceiling
        advice = failure.error.retry_after if isinstance(failure, ErrorAnswer) else None
        if advice is not None:
            if advice > BACKOFF_MAX:
                # The server asks for more patience than a call may spend: the caller decides, with the advice.
                return None
            delay = max(delay, advice)
        now = self.clock()
        if now - started + delay > self.retry_total_max:
            # A later attempt could arrive after the platform has forgotten the key.
            return None
        return delay if self._budget.take(now) else None

    def _surface(self, request: Request, failure: ErrorAnswer | NoAnswer) -> NoReturn:
        """Raise the error a call ends with when its last attempt failed and no further one is made."""
        if isinstance(failure, ErrorAnswer):
            raise failure.error
        where = f"{request.method} {request.path}"
        if request.key is not None:
            # A mutation under a key that ends without a usable answer is unresolved, whatever the
            # failure looked like from here: the key is what settles it, later.
            raise OutcomeUnresolvedError(
                f"no usable answer to {where} ({failure.detail}): whether the request was accepted is not known. "
                "Make the same call again later, with the same idempotency key and the same arguments",
                code=_CODE_OUTCOME_UNRESOLVED,
                kind=KIND_UNRESOLVED,
                retry=RETRY_SAME_REQUEST_LATER,
                status=failure.status,
                request_id=failure.request_id,
                idempotency_key=request.key,
            ) from failure.cause
        if failure.status is not None:
            raise UnexpectedResponseError(
                f"{where} answered {failure.status} without a problem document: the answer is not the "
                "platform's, and whether the request was received is not known",
                status=failure.status,
                request_id=failure.request_id,
            )
        doubt = "; the server may have received the request" if failure.sent and request.mutates else ""
        unreachable = APITimeoutError if failure.timed_out else APIConnectionError
        raise unreachable(f"{where} at {self.base_url} was not answered ({failure.detail}){doubt}") from failure.cause

    # ------------------------------------------------------------------------------ operations
    def follow_bound(self, follow_max: float | None) -> float:
        """The follow bound of one call: the caller's, checked, or the client's. Called before any request."""
        if follow_max is None:
            return self.follow_max
        acceptable = not isinstance(follow_max, bool) and isinstance(follow_max, int | float)
        if not acceptable or not math.isfinite(follow_max) or follow_max < 0:
            raise ValueError("follow_max must be a finite number of seconds, zero or more")
        return float(follow_max)

    def operate(self, request: Request, *, within: float) -> Flow[Operation]:
        """Issue a mutation and follow its operation until it has ended. The outcome is not judged here.

        The bound is on the following: it counts from the answer that first showed the operation. The
        request that started the operation has the client's timeout, like every request.

        The server holds a mutation open until its operation has ended, for up to its own wait: 30
        seconds unless the request says otherwise. A bound shorter than that is said to the server, in
        whole seconds, so that it is not spent and overrun waiting for the first answer. A bound of zero
        therefore submits and returns at once.
        """
        if within < FOLLOW_WAIT:
            request = replace(request, query=(*request.query, ("wait", str(math.floor(within)))))
        answer = yield from self.perform(request)
        return (yield from self._follow(answer, key=request.key, deadline=self.clock() + within))

    def watch(self, operation_id: str, *, within: float) -> Flow[Operation]:
        """Follow an operation that already exists until it has ended."""
        deadline = self.clock() + within
        path = yield from self._operation_path(operation_id)
        answer = yield from self.perform(Request("GET", path, query=self._wait(deadline)))
        return (yield from self._follow(answer, key=None, deadline=deadline))

    def _wait(self, deadline: float) -> tuple[tuple[str, str], ...]:
        """The ``wait`` of a read while following: the smaller of 30 and the whole seconds left before the bound."""
        left = max(0, math.floor(deadline - self.clock()))
        return (("wait", str(min(FOLLOW_WAIT, left))),)

    def _operation_path(self, operation_id: str) -> Flow[str]:
        return (yield from self.project_path()) + "/operations/" + segment(operation_id)

    def _follow(self, answer: Answer, *, key: str | None, deadline: float) -> Flow[Operation]:
        operation = Operation(answer.body, request_id=answer.request_id)
        backoff = FOLLOW_BACKOFF_INITIAL
        while not has_ended(operation.state):
            delay = answer.retry_after
            if delay is None:
                delay = backoff
                backoff = min(FOLLOW_BACKOFF_MAX, backoff * 2)
            if self.clock() + delay >= deadline:
                again = "" if key is None else f", or make the same call again with idempotency key {key}"
                raise OperationStillRunningError(
                    self.redact(
                        f"operation {operation.operation_id} ({operation.type}) is still {operation.state} at "
                        "the follow bound. Nothing was cancelled and nothing is assumed. Follow it with "
                        f"operations.wait({operation.operation_id!r}){again}"
                    ),
                    operation=operation,
                    idempotency_key=key,
                )
            yield Sleep(delay)
            # The address is built from the operation's identifier. The `Location` of the answer is not
            # used, so that no answer can send the credential anywhere but the configured endpoint.
            path = yield from self._operation_path(operation.operation_id)
            answer = yield from self.perform(Request("GET", path, query=self._wait(deadline)))
            operation = Operation(answer.body, request_id=answer.request_id)
        return operation

    def settle(self, operation: Operation, *, key: str | None) -> None:
        """Return if the ended operation succeeded, and raise what its outcome means otherwise.

        ``UNKNOWN`` is never shown as success or as failure. An operation that ended without success is
        a clean failure only if the host says nothing was applied; with any other effect, one this
        version does not know included, the caller has to inspect the target before deciding.
        """
        state = operation.state
        if state == _STATE_SUCCEEDED:
            return
        failure = operation.failure
        # The host's words are foreign text: they are cleared before they are kept anywhere, a local included.
        because = "no failure is named" if failure is None else self.redact(f"{failure.code}: {failure.message}")
        subject = self.redact(f"operation {operation.operation_id} ({operation.type}) ended {state}")
        if state != _STATE_UNKNOWN and operation.effect == _EFFECT_NOT_APPLIED:
            raise OperationFailedError(
                f"{subject} and nothing was applied ({because}). A new call is allowed",
                operation=operation,
                idempotency_key=key,
            )
        effect = self.redact(operation.effect or "not stated")
        raise OutcomeUnknownError(
            f"{subject} with effect {effect} ({because}): whether it was applied is not known. "
            "Inspect the target before acting again",
            operation=operation,
            idempotency_key=key,
        )

    # ------------------------------------------------------------------------------ project and listings
    def project_path(self) -> Flow[str]:
        """``/v1/projects/{project}``. The project is read from the credential once, when nothing named it.

        Two calls that start at the same moment may both ask; they get the same answer, so no lock is held
        across a request for it.
        """
        project = self._project
        if project is None:
            answer = yield from self.perform(Request("GET", f"{_API_ROOT}/auth/whoami"))
            project = WhoAmI(answer.body).project_id
            self._project = project
        return f"{_API_ROOT}/projects/{segment(project)}"

    def collect(self, collection: str) -> Flow[list[Item]]:
        """Every item of a listing, each once: the pages of one complete pass.

        A pass that ends in ``CURSOR_EXPIRED`` is thrown away and the listing starts again, so that the
        caller never sees an item of an abandoned pass next to the same item of the next one.
        """
        path = (yield from self.project_path()) + collection
        restarts = 0
        while True:
            try:
                items = yield from self._one_pass(path)
            except CursorExpiredError:
                if restarts == LISTING_RESTARTS:
                    raise
                restarts += 1
            else:
                return items

    def _one_pass(self, path: str) -> Flow[list[Item]]:
        items: list[Item] = []
        visited: set[str] = set()
        query: tuple[tuple[str, str], ...] = ()
        while True:
            answer = yield from self.perform(Request("GET", path, query=query))
            items.extend((entry, answer.request_id) for entry in page_items(answer))
            more, cursor = answer.body.get("more"), answer.body.get("next_cursor")
            if more is False:
                return items
            if more is not True or not isinstance(cursor, str) or not cursor or cursor in visited:
                # A page that does not say whether more follow, or that names as the next a page already
                # read, would have this client ask for ever.
                raise UnexpectedResponseError(
                    f"GET {path} answered a page that does not say where the listing continues",
                    status=answer.status,
                    request_id=answer.request_id,
                )
            visited.add(cursor)
            query = (("cursor", cursor),)


# ---------------------------------------------------------------------------------------------- the drivers
class SyncDriver:
    """Does what a flow asks, blocking: one HTTP exchange at a time, and sleeping in between."""

    def __init__(self, engine: Engine, http: httpx2.Client, *, owns_http: bool) -> None:
        self.engine = engine
        self._http = http
        self._owns_http = owns_http
        #: Replaced by a virtual sleep in tests.
        self.sleep: Callable[[float], None] = time.sleep

    def run[T](self, call: str, flow: Flow[T]) -> T:
        """Run one logical call to its end. An interruption stops the waiting and sends nothing."""
        with _telemetry.span(call):
            try:
                while True:
                    effect = next(flow)
                    if isinstance(effect, Sleep):
                        self.sleep(effect.seconds)
                    else:
                        effect.outcome = self._attempt(effect.request)
            except StopIteration as finished:
                result: T = finished.value
                return result
            finally:
                flow.close()

    def _attempt(self, request: Request) -> Reply | NoAnswer:
        engine = self.engine
        try:
            response = self._http.request(
                request.method,
                engine.url(request),
                params=list(request.query) or None,
                content=request.body,
                headers=engine.headers(request),
                # Nothing configured on a caller's HTTP client may add credentials or follow a redirect:
                # the key goes to the configured endpoint, in one header, and nowhere else.
                auth=None,
                follow_redirects=False,
                timeout=engine.timeout,
            )
        except httpx2.RequestError as error:
            return engine.unanswered(error)
        return Reply(response.status_code, response.headers, response.content)

    def close(self) -> None:
        if self._owns_http:
            self._http.close()


class AsyncDriver:
    """Does what a flow asks, awaiting. Cancelling the awaiting task stops the waiting and sends nothing."""

    def __init__(self, engine: Engine, http: httpx2.AsyncClient, *, owns_http: bool) -> None:
        self.engine = engine
        self._http = http
        self._owns_http = owns_http
        #: Replaced by a virtual sleep in tests.
        self.sleep: Callable[[float], Awaitable[None]] = asyncio.sleep

    async def run[T](self, call: str, flow: Flow[T]) -> T:
        with _telemetry.span(call):
            try:
                while True:
                    effect = next(flow)
                    if isinstance(effect, Sleep):
                        await self.sleep(effect.seconds)
                    else:
                        effect.outcome = await self._attempt(effect.request)
            except StopIteration as finished:
                result: T = finished.value
                return result
            finally:
                flow.close()

    async def _attempt(self, request: Request) -> Reply | NoAnswer:
        engine = self.engine
        try:
            response = await self._http.request(
                request.method,
                engine.url(request),
                params=list(request.query) or None,
                content=request.body,
                headers=engine.headers(request),
                auth=None,
                follow_redirects=False,
                timeout=engine.timeout,
            )
        except httpx2.RequestError as error:
            return engine.unanswered(error)
        return Reply(response.status_code, response.headers, response.content)

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()
