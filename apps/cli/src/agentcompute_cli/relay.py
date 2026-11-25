"""The stdio relay of the platform's agent endpoint: what ``acf mcp`` runs.

An agent host speaks the Model Context Protocol to a program it starts, over that program's standard
input and output. The platform speaks the same protocol over HTTP. This module stands between the two
and carries messages, one for one: a line read from the client becomes one HTTP POST to the platform's
MCP endpoint, with the credential added, and what the endpoint answers becomes lines for the client.

What it does:

* **Framing.** One JSON-RPC message per line, in each direction. The body of a POST is the line as the
  client wrote it. An answer is written as one line of printable ASCII, whole, in one call: two answers
  can never be interleaved, and nothing a message holds can break a line.
* **The headers the transport requires** (Streamable HTTP, revision 2026-07-28): the protocol version,
  the method and, for a method that names something, the name. Each is copied from the message and
  never made up. A message that does not state its protocol version is sent without that header, and
  the endpoint says in its own words which revision it serves.
* **The credential.** ``Authorization: Bearer``, to the configured endpoint and nowhere else. No
  redirect is followed.
* **Cancellation.** On stdio a client cancels a request with ``notifications/cancelled``; on HTTP the
  signal is closing the response. The relay translates one into the other, writes nothing more for the
  cancelled request, and does not post the notification: this transport defines none.

It implements no tool and knows nothing about what a tool means, with one exception that the platform
prescribes for this relay. It notes each execution that a call it relayed started and that it has not
seen end. When the client cancels such a call, the relay calls the platform's own tool that cancels an
execution. A call that is still in flight when it is cancelled is waited for, because only its answer
says whether it started one. That is an explicit request made for the client, through the same
endpoint and under the same credential.

What it never does: validate, rewrite, cache or retry a message; make up an answer (a request the
endpoint did not answer gets a JSON-RPC error that says so, never a tool result); cancel anything
because its input closed or because it was interrupted. A closed input is a disconnect: what was read
is carried to its end, and then the relay stops.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import io
import itertools
import json
import re
import threading
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass
from typing import Any, BinaryIO, Final, NoReturn

import httpx2

from agentcompute_cli._version import __version__
from agentcompute_cli.render import IDENTIFIER_MAX, safe_line

__all__ = [
    "ANSWER_MAX",
    "IN_FLIGHT_MAX",
    "LINE_MAX",
    "OVERSIZE",
    "REVISION",
    "Oversize",
    "Relay",
    "stdin_lines",
]

#: The revision of the Model Context Protocol whose HTTP transport this relay speaks.
REVISION: Final = "2026-07-28"

#: The longest line read from the client. A request of the platform is at most a quarter of this.
LINE_MAX: Final = 4 * 1024 * 1024
#: The longest answer, or one event of a streamed answer, read from the endpoint.
ANSWER_MAX: Final = 8 * 1024 * 1024
#: Requests carried at once. A client that sends more waits its turn, in order.
IN_FLIGHT_MAX: Final = 64
#: Calls remembered as having started an execution that was not seen to end. The oldest is forgotten first.
REMEMBERED_MAX: Final = 1024
#: Lines read ahead of the relay. Reading stops when it is full, so a client cannot fill memory.
_QUEUE_MAX: Final = 16
#: Bytes asked of the input at once. A read returns as soon as it has any, so a short line does not wait.
_READ_SIZE: Final = 64 * 1024

_PROTOCOL_VERSION_KEY: Final = "io.modelcontextprotocol/protocolVersion"
_CLIENT_CAPABILITIES_KEY: Final = "io.modelcontextprotocol/clientCapabilities"
_CLIENT_INFO_KEY: Final = "io.modelcontextprotocol/clientInfo"

_CANCELLED: Final = "notifications/cancelled"
_TOOLS_CALL: Final = "tools/call"
#: The tool whose call starts an execution, and the tool the relay calls to cancel one.
_START_TOOL: Final = "sandbox_exec"
_CANCEL_TOOL: Final = "exec_cancel"
_EXECUTION_OPERATION: Final = "execution.create"
#: The states in which an execution is known to have ended. ``UNKNOWN`` is not one of them: what the
#: host could not establish may still be running, and a cancellation the client asked for is then made.
_ENDED: Final = frozenset({"SUCCEEDED", "FAILED", "CANCELLED"})
#: The parameter that the ``Mcp-Name`` header mirrors, for each method that names something.
_NAMED: Final[dict[str, str]] = {_TOOLS_CALL: "name", "prompts/get": "name", "resources/read": "uri"}

_JSON: Final = "application/json"
_EVENT_STREAM: Final = "text/event-stream"
_ACCEPTED: Final = 202
_ERRORS: Final = 400
_SUCCESS: Final = range(200, 300)
# A header value is visible ASCII and spaces. One that starts or ends with a space would not arrive as sent.
_HEADER_SAFE: Final = re.compile(r"[\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?", re.ASCII)
_SENTINEL: Final = re.compile(r"=\?base64\?.*\?=", re.ASCII | re.DOTALL)
_VERSION_MAX: Final = 64
_NAME_MAX: Final = 1024

#: JSON-RPC's own codes for a line that is not JSON, a message that is not one, and a failure of the server.
_PARSE_ERROR: Final = -32700
_INVALID_REQUEST: Final = -32600
_INTERNAL_ERROR: Final = -32603
#: In the ``data`` of an error this relay made itself, so that it cannot be taken for the platform's.
_ORIGIN: Final = {"origin": "acf mcp relay"}

type Json = dict[str, Any]
type _Key = tuple[str, str | int]


class Oversize:
    """Stands for a line that was longer than :data:`LINE_MAX` and was not kept."""


OVERSIZE: Final = Oversize()


class _NoAnswerError(Exception):
    """The endpoint gave no response of the protocol to a message. ``reason`` is this relay's own words."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(slots=True)
class _Exchange:
    """One request of the client, on its way to the endpoint and back."""

    #: The identifier as the client wrote it, whatever JSON value that is.
    rpc_id: object
    #: How a cancellation finds the request. ``None`` when the identifier is not a string or an integer.
    key: _Key | None
    #: Whether the request calls the tool that starts an execution.
    starts_execution: bool
    #: The protocol version the request stated, for a call the relay may have to make on its behalf.
    version: str | None
    cancelled: bool = False
    task: asyncio.Task[None] | None = None


# ------------------------------------------------------------------------------------- reading messages
def _refuse_constant(name: str) -> NoReturn:
    raise ValueError(name)


def _message(data: str | bytes) -> Json | None:
    """A JSON-RPC message, if the text is one JSON object. ``NaN`` and the infinities are not JSON."""
    try:
        value = json.loads(data, parse_constant=_refuse_constant)
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _is_response(message: Json) -> bool:
    return "method" not in message and ("result" in message or "error" in message)


def _key(rpc_id: object) -> _Key | None:
    """A request identifier as something to look a request up by. JSON-RPC compares identifiers exactly."""
    if isinstance(rpc_id, bool) or not isinstance(rpc_id, str | int):
        return None
    return type(rpc_id).__name__, rpc_id


def _params(message: Json) -> Json:
    params = message.get("params")
    return params if isinstance(params, dict) else {}


def _stated_version(message: Json) -> str | None:
    """The protocol version a message states for itself, if it is fit to be a header value."""
    meta = _params(message).get("_meta")
    version = meta.get(_PROTOCOL_VERSION_KEY) if isinstance(meta, dict) else None
    if isinstance(version, str) and len(version) <= _VERSION_MAX and _HEADER_SAFE.fullmatch(version):
        return version
    return None


def _encoded(value: str) -> str:
    """A name as a header value: as it is when that is safe, and base64 between the protocol's marks otherwise."""
    if _HEADER_SAFE.fullmatch(value) and not _SENTINEL.fullmatch(value):
        return value
    return f"=?base64?{base64.b64encode(value.encode('utf-8', 'surrogatepass')).decode('ascii')}?="


def _executions(structured: object) -> Iterator[tuple[str, bool]]:
    """Every execution the structured content of a tool result shows, with whether it has ended.

    A result shows an execution as a view of its own, as the result of an operation, or, while the
    command still runs, only as the target of the operation that runs it.
    """
    if not isinstance(structured, dict):
        return
    operation = structured.get("operation")
    views: list[object] = [structured.get("execution")]
    if isinstance(operation, dict):
        produced = operation.get("result")
        views.append(produced.get("execution") if isinstance(produced, dict) else None)
        target = operation.get("target")
        if operation.get("type") == _EXECUTION_OPERATION and isinstance(target, dict):
            views.append({"execution_id": target.get("execution_id"), "state": operation.get("state")})
    for view in views:
        if isinstance(view, dict):
            execution_id, state = view.get("execution_id"), view.get("state")
            if isinstance(execution_id, str) and isinstance(state, str):
                yield execution_id, state in _ENDED


def _line(message: Json) -> bytes:
    """A message as one line. Printable ASCII: no character of it can end the line or hide in it."""
    return json.dumps(message, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"


def _own_error(rpc_id: object, code: int, message: str) -> Json:
    return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message, "data": _ORIGIN}}


def _shown(value: object) -> str:
    """An identifier in a diagnostic. It was chosen by the client or by the platform, so it is made safe."""
    return safe_line(value if isinstance(value, str) else json.dumps(value), limit=IDENTIFIER_MAX)


def _discard(_message: Json) -> None:
    """What is done with the interim messages of a call the relay made for itself."""


# ---------------------------------------------------------------------------------------------- the relay
class Relay:
    """Carries the messages of one client to one endpoint and back.

    ``write`` receives one whole line per call and must write it in that call. ``log`` receives one
    diagnostic per call; nothing it is given holds a credential or the content of a message.
    """

    def __init__(
        self,
        *,
        endpoint: str,
        api_key: str,
        http: httpx2.AsyncClient,
        write: Callable[[bytes], None],
        log: Callable[[str], None],
    ) -> None:
        self._endpoint = endpoint
        self._authorization = f"Bearer {api_key}"
        self._http = http
        self._write = write
        self._log = log
        self._slots = asyncio.Semaphore(IN_FLIGHT_MAX)
        self._in_flight: dict[_Key, _Exchange] = {}
        #: The call that started each execution not seen to end: its request identifier, the execution,
        #: and the protocol version the call stated.
        self._started: dict[_Key, tuple[str, str | None]] = {}
        self._own_calls = itertools.count(1)

    async def run(self, lines: AsyncIterator[bytes | Oversize]) -> None:
        """Relay every line until the input ends, then carry what was read to its end. Ending cancels nothing."""
        async with asyncio.TaskGroup() as tasks:
            async for line in lines:
                if isinstance(line, Oversize):
                    self._unframed(_INVALID_REQUEST, f"a message is longer than {LINE_MAX} bytes, and was not read")
                    continue
                message = self._framed(line)
                if message is None:
                    continue
                if message.get("method") == _CANCELLED and "id" not in message:
                    self._on_cancelled(message, tasks)
                    continue
                await self._slots.acquire()
                self._dispatch(line.rstrip(b"\r\n"), message, tasks)

    # ------------------------------------------------------------------------------ from the client
    def _framed(self, line: bytes) -> Json | None:
        """The message a line holds. A line that holds none cannot be relayed, and is answered here.

        Nothing else about the message is judged: whether it is a message of the protocol is the
        endpoint's to say. It is read only to find what the headers have to repeat.
        """
        if not line.strip():
            return None
        try:
            value = json.loads(line)
        except (ValueError, RecursionError):
            self._unframed(_PARSE_ERROR, "a line of input is not JSON")
            return None
        if not isinstance(value, dict):
            self._unframed(_INVALID_REQUEST, "a line of input is JSON, and is not a JSON-RPC message")
            return None
        return value

    def _unframed(self, code: int, what: str) -> None:
        # The identifier of what could not be read is not known. JSON-RPC answers that with a null one.
        self._log(f"{what}: answered with an error, and not relayed")
        self._write(_line(_own_error(None, code, f"acf mcp: {what}")))

    def _dispatch(self, body: bytes, message: Json, tasks: asyncio.TaskGroup) -> None:
        if "id" not in message:
            tasks.create_task(self._notify(body, message))
            return
        params = _params(message)
        exchange = _Exchange(
            rpc_id=message["id"],
            key=_key(message["id"]),
            starts_execution=message.get("method") == _TOOLS_CALL and params.get("name") == _START_TOOL,
            version=_stated_version(message),
        )
        if exchange.key is not None:
            # From now on the identifier names this request, not an earlier one that used it.
            self._started.pop(exchange.key, None)
            self._in_flight[exchange.key] = exchange
        exchange.task = tasks.create_task(self._request(body, message, exchange))

    def _on_cancelled(self, message: Json, tasks: asyncio.TaskGroup) -> None:
        """The client's cancellation of one of its requests. A cancellation that names nothing known is ignored."""
        key = _key(_params(message).get("requestId"))
        if key is None:
            return
        exchange = self._in_flight.get(key)
        if exchange is not None:
            exchange.cancelled = True
            if not exchange.starts_execution and exchange.task is not None:
                # Closing the response is how this transport says "cancelled". The endpoint stops waiting,
                # and nothing more. A call that may start an execution is waited for instead: only its
                # answer says whether there is something to cancel.
                exchange.task.cancel()
            return
        started = self._started.pop(key, None)
        if started is not None:
            tasks.create_task(self._cancel_execution(*started))

    # ------------------------------------------------------------------------------ to the endpoint
    def _headers(self, message: Json) -> dict[str, str]:
        headers = {
            "Authorization": self._authorization,
            "Content-Type": _JSON,
            "Accept": f"{_JSON}, {_EVENT_STREAM}",
            "User-Agent": f"agent-compute-cli/{__version__}",
        }
        version = _stated_version(message)
        if version is not None:
            headers["MCP-Protocol-Version"] = version
        method = message.get("method")
        if isinstance(method, str) and len(method) <= _NAME_MAX and _HEADER_SAFE.fullmatch(method):
            headers["Mcp-Method"] = method
            parameter = _NAMED.get(method)
            name = _params(message).get(parameter) if parameter is not None else None
            if isinstance(name, str) and len(name) <= _NAME_MAX:
                headers["Mcp-Name"] = _encoded(name)
        return headers

    async def _converse(self, body: bytes, headers: dict[str, str], forward: Callable[[Json], None]) -> Json:
        """Post one message and return the response the endpoint gives it.

        Messages that come before the response on a stream are handed to ``forward`` as they arrive.
        Raises when the endpoint gives no response of the protocol: nothing is tried a second time.
        """
        try:
            async with self._http.stream(
                "POST", self._endpoint, content=body, headers=headers, follow_redirects=False
            ) as response:
                return await self._response(response, forward)
        # The words of a failure are the library's and may quote what was sent: only its kind is kept.
        except httpx2.TimeoutException as error:
            raise _NoAnswerError(f"it did not answer in time ({type(error).__name__})") from None
        except httpx2.SSEError:
            # The one thing the reader of a stream refuses here, where the media type was checked first.
            raise _NoAnswerError(f"an event of its stream is longer than {ANSWER_MAX} bytes") from None
        except httpx2.TransportError as error:
            raise _NoAnswerError(
                f"it could not be reached, or the connection was lost ({type(error).__name__})"
            ) from None
        except httpx2.HTTPError as error:
            raise _NoAnswerError(f"its answer could not be read ({type(error).__name__})") from None

    @staticmethod
    async def _response(response: httpx2.Response, forward: Callable[[Json], None]) -> Json:
        status = response.status_code
        media = response.headers.get("content-type", "").partition(";")[0].strip().lower()
        if media == _EVENT_STREAM and status in _SUCCESS:
            async for event in httpx2.EventSource(response, max_event_size=ANSWER_MAX):
                message = _message(event.data)
                if message is None:
                    continue
                if _is_response(message):
                    return message
                forward(message)
            raise _NoAnswerError("it closed the stream without a response")
        if media == _JSON:
            data = bytearray()
            async for chunk in response.aiter_bytes():
                data += chunk
                if len(data) > ANSWER_MAX:
                    raise _NoAnswerError(f"its answer is longer than {ANSWER_MAX} bytes")
            message = _message(bytes(data))
            if message is not None and _is_response(message):
                return message
            raise _NoAnswerError(f"it answered HTTP {status} with a body that is not a response of the protocol")
        if status == _ACCEPTED:
            raise _NoAnswerError("it acknowledged the request without answering it (HTTP 202)")
        raise _NoAnswerError(f"it answered HTTP {status} without a message of the protocol")

    async def _notify(self, body: bytes, message: Json) -> None:
        """Carry a notification. Nothing answers one, so nothing is written whatever becomes of it."""
        try:
            async with self._http.stream(
                "POST", self._endpoint, content=body, headers=self._headers(message), follow_redirects=False
            ) as response:
                if response.status_code >= _ERRORS:
                    self._log(f"the endpoint did not accept a notification (HTTP {response.status_code})")
        except httpx2.HTTPError as error:
            self._log(f"a notification did not reach the endpoint ({type(error).__name__})")
        finally:
            self._slots.release()

    async def _request(self, body: bytes, message: Json, exchange: _Exchange) -> None:
        """Carry one request, write what answers it, and note what the answer shows."""
        cancel: tuple[str, str | None] | None = None
        try:
            try:
                final = await self._converse(body, self._headers(message), lambda early: self._deliver(exchange, early))
            except _NoAnswerError as silence:
                self._retire(exchange)
                self._log(f"request {_shown(exchange.rpc_id)}: the endpoint gave no answer: {silence.reason}")
                if exchange.cancelled and exchange.starts_execution:
                    self._log(
                        f"request {_shown(exchange.rpc_id)} was cancelled by the client. Whether it started an "
                        "execution is not known, so nothing was cancelled on the platform"
                    )
                self._deliver(
                    exchange,
                    _own_error(
                        exchange.rpc_id,
                        _INTERNAL_ERROR,
                        f"acf mcp: the platform's MCP endpoint gave no answer to this request: {silence.reason}. "
                        "This error was made by the local relay, not by the platform. Whether the platform "
                        "received the request is not known.",
                    ),
                )
                return
            # Everything from here to the last write happens without a pause: a cancellation that arrives
            # afterwards finds the request ended and its execution, if it started one, on record.
            self._retire(exchange)
            if "error" in final and final.get("id") is None:
                # The endpoint refused before it had read the identifier. On HTTP the response belongs to
                # its request by position; on a shared stream only the identifier says so.
                final = {**final, "id": exchange.rpc_id}
            cancel = self._noted(exchange, final)
            self._deliver(exchange, final)
        finally:
            self._retire(exchange)
            self._slots.release()
        if cancel is not None:
            await self._cancel_execution(*cancel)

    def _retire(self, exchange: _Exchange) -> None:
        # Only this request is removed: the identifier may by now name a later one.
        if exchange.key is not None and self._in_flight.get(exchange.key) is exchange:
            del self._in_flight[exchange.key]

    def _deliver(self, exchange: _Exchange, message: Json) -> None:
        """Write a message that belongs to a request, unless the client cancelled that request."""
        if not exchange.cancelled:
            self._write(_line(message))

    # ------------------------------------------------------------------------------ executions
    def _noted(self, exchange: _Exchange, final: Json) -> tuple[str, str | None] | None:
        """Take note of the executions a result shows. Returns the one to cancel, if the client is owed that."""
        result = final.get("result")
        seen = list(_executions(result.get("structuredContent") if isinstance(result, dict) else None))
        ended = {execution_id for execution_id, has_ended in seen if has_ended}
        if ended:
            self._started = {key: started for key, started in self._started.items() if started[0] not in ended}
        if not exchange.starts_execution:
            return None
        running = next((execution_id for execution_id, _ in seen if execution_id not in ended), None)
        if running is None:
            if exchange.cancelled:
                self._log(
                    f"request {_shown(exchange.rpc_id)} was cancelled by the client, and its answer shows no "
                    "execution that is still running: nothing was cancelled on the platform"
                )
            return None
        if exchange.cancelled:
            return running, exchange.version
        if exchange.key is not None:
            self._started[exchange.key] = (running, exchange.version)
            while len(self._started) > REMEMBERED_MAX:
                del self._started[next(iter(self._started))]
        return None

    async def _cancel_execution(self, execution_id: str, version: str | None) -> None:
        """Ask the platform to cancel an execution, for a client that cancelled the call that started it.

        One call of the platform's own tool, made once. Its answer is for this relay and is not written
        to the client, which asked no such question.
        """
        call: Json = {
            "jsonrpc": "2.0",
            "id": f"acf-relay-{next(self._own_calls)}",
            "method": _TOOLS_CALL,
            "params": {
                "name": _CANCEL_TOOL,
                "arguments": {"execution_id": execution_id},
                "_meta": {
                    _PROTOCOL_VERSION_KEY: version or REVISION,
                    _CLIENT_CAPABILITIES_KEY: {},
                    _CLIENT_INFO_KEY: {"name": "acf", "version": __version__},
                },
            },
        }
        body = json.dumps(call, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        shown = _shown(execution_id)
        unsure = f"it may still be running. Cancel it with: acf exec cancel {shown}"
        try:
            final = await self._converse(body, self._headers(call), _discard)
        except _NoAnswerError as silence:
            self._log(
                f"execution {shown}: its cancellation was asked for and got no answer ({silence.reason}): {unsure}"
            )
            return
        result = final.get("result")
        if not isinstance(result, dict) or result.get("isError") is True:
            self._log(f"execution {shown}: the platform did not cancel it: {unsure}")
            return
        self._log(f"execution {shown} was cancelled, because the client cancelled the call that started it")


# ---------------------------------------------------------------------------------------- standard input
def _unbuffered(stream: BinaryIO) -> Callable[[int], bytes | None]:
    """The reads of the file under a buffered stream, or of the stream itself when it has none under it.

    A buffered stream holds a lock while it waits for input, and an interpreter that is shutting down
    takes that lock: with a thread that will never come back holding it, the interpreter aborts the
    process. The thread that reads here therefore waits where no lock is held.
    """
    reads: Callable[[int], bytes | None] = stream.raw.read if isinstance(stream, io.BufferedReader) else stream.read
    return reads


def _lines(read: Callable[[int], bytes | None]) -> Iterator[bytes | Oversize]:
    """The lines of an input, each with its line end, none longer than :data:`LINE_MAX` before it.

    A longer one is not kept: it is skipped to its end and reported. No more than one line of the bound
    is ever held, however the input is cut into reads.
    """
    held = bytearray()
    # The line being read is already too long: nothing more of it is kept.
    oversize = False
    while chunk := read(_READ_SIZE):
        *ended, rest = chunk.split(b"\n")
        for piece in ended:
            if oversize or len(held) + len(piece) > LINE_MAX:
                yield OVERSIZE
            else:
                yield bytes(held) + piece + b"\n"
            held.clear()
            oversize = False
        if oversize or len(held) + len(rest) > LINE_MAX:
            oversize = True
            held.clear()
        else:
            held += rest
    if oversize:
        yield OVERSIZE
    elif held:
        yield bytes(held)


async def stdin_lines(stream: BinaryIO) -> AsyncIterator[bytes | Oversize]:
    """The lines of a blocking stream, read by a thread of its own.

    A pipe cannot be read without blocking in the same way on every system, and a blocked event loop
    would carry nothing. The thread is a daemon: a relay that is told to stop does not wait for a line
    that may never come. It reads no further ahead than :data:`_QUEUE_MAX` lines that nobody took yet.
    """
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[bytes | Oversize | None] = asyncio.Queue()
    # One permit per line the reader may be ahead. The thread takes one before it hands a line over, and
    # the consumer gives it back when it takes the line: reading stops while nobody takes anything.
    ahead = threading.Semaphore(_QUEUE_MAX)
    read = _unbuffered(stream)

    def pump() -> None:
        # The stream, or the loop, may be closed under this thread at any moment: either ends the
        # reading, and neither is an error.
        with contextlib.suppress(OSError, ValueError, RuntimeError):
            try:
                for line in _lines(read):
                    ahead.acquire()
                    loop.call_soon_threadsafe(queue.put_nowait, line)
            finally:
                loop.call_soon_threadsafe(queue.put_nowait, None)

    threading.Thread(target=pump, name="acf-mcp-input", daemon=True).start()
    while (line := await queue.get()) is not None:
        ahead.release()
        yield line
