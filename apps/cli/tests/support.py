"""Test doubles and helpers.

* :class:`Contract` reads the host's published API description and validates what the client sends
  and what a host may answer. Every request that leaves the client in *any* test goes through it.
* :class:`ScriptedConnection` is an in-process transport: each exchange consumes the next step of a
  script — answer, lose the response, refuse to connect. The client's retry and resolution logic
  runs against it in zero wall time, and a script that is not fully consumed fails the test.
* :class:`ScriptedHost` is a scripted server on a real ``AF_UNIX`` socket, for the transport itself.
* :class:`FakeClock` makes waiting instantaneous and observable.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import struct
import threading
import time
from collections import deque
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Any, Protocol

from jsonschema import Draft202012Validator

import factories as f

HEADER = struct.Struct(">I")
PROTOCOL = "acf.host/2"
SUN_PATH_SAFE = 100

REPO_ROOT = Path(__file__).resolve().parents[3]
API_FILE = REPO_ROOT / "execution" / "contracts" / "host-api.json"


# ----------------------------------------------------------------------------- the published contract
class Contract:
    """The host API description (``execution/contracts/host-api.json``) as a set of validators."""

    def __init__(self, document: dict[str, Any]) -> None:
        self.document = document
        self.defs: dict[str, Any] = document["$defs"]
        self.methods: dict[str, dict[str, Any]] = {m["name"]: m for m in document["methods"]}
        self._request = self._validator({"$ref": "#/$defs/RequestEnvelope"})
        self._response = self._validator({"$ref": "#/$defs/ResponseEnvelope"})

    @classmethod
    def load(cls) -> Contract:
        document = json.loads(API_FILE.read_text(encoding="utf-8"))
        assert isinstance(document, dict)
        return cls(document)

    def _validator(self, schema: dict[str, Any]) -> Draft202012Validator:
        return Draft202012Validator({**schema, "$defs": self.defs})

    def validator_for(self, name: str) -> Draft202012Validator:
        """A validator for one named type of the description."""
        return self._validator({"$ref": f"#/$defs/{name}"})

    def check_request(self, request: dict[str, Any]) -> None:
        """A request is valid when its envelope is, its method exists, and its params have that method's shape."""
        self._request.validate(request)
        method = self.methods.get(request["method"])
        assert method is not None, f"{request['method']!r} is not a published method"
        params = request.get("params")
        if method["params"] is None:
            assert params in (None, {}), f"{method['name']} takes no params, got {params!r}"
        elif params is None:
            assert not method["params_required"], f"{method['name']} requires params"
        else:
            self._validator(method["params"]).validate(params)
        identified = request.get("operation_id") is not None and request.get("issued_at") is not None
        assert identified == method["creates_operation"], (
            f"{method['name']}: operation_id and issued_at accompany exactly the methods that create an operation"
        )
        assert "authority" not in request, "the client never sends `authority`"

    def check_response(self, response: dict[str, Any]) -> None:
        self._response.validate(response)


# ----------------------------------------------------------------------------- answers, in wire form
def refused(
    failure_class: str, message: str = "refused", retry: str = "NEVER", *, as_of: dict[str, Any] | None = f.AS_OF
) -> dict[str, Any]:
    return {
        "answer": "REFUSED",
        "refusal": {"class": failure_class, "retry": retry, "message": message},
        "as_of": as_of,
    }


def accepted(view: dict[str, Any], *, as_of: dict[str, Any] | None = f.AS_OF) -> dict[str, Any]:
    return {"answer": "OPERATION", "operation": view, "as_of": as_of}


def answered(kind: str, data: Any, *, as_of: dict[str, Any] | None = f.AS_OF) -> dict[str, Any]:
    return {"answer": "RESULT", "result": {"type": kind, "data": data}, "as_of": as_of}


Step = Callable[[dict[str, Any]], "dict[str, Any] | bytes | BaseException"] | dict[str, Any] | bytes | BaseException


def op(state: str = "SUCCEEDED", result: dict[str, Any] | None = None, **over: Any) -> Step:
    """Answer about *the request's own* operation.

    For a request that creates an operation: an ``OPERATION`` answer whose view carries the
    request's ``operation_id``, ``issued_at`` and method. For ``operation.get``: a ``RESULT`` with
    the view of the operation that was asked about.
    """

    def build(request: dict[str, Any]) -> dict[str, Any]:
        if request["method"] == "operation.get":
            view = f.operation_view(state=state, result=result, operation_id=request["params"]["operation_id"], **over)
            return answered("operation", view)
        fields = {"operation_id": request["operation_id"], "issued_at": request["issued_at"], **over}
        fields.setdefault("operation_type", request["method"])
        return accepted(f.operation_view(state=state, result=result, **fields))

    return build


# ----------------------------------------------------------------------------- the in-process transport
class ScriptedConnection:
    """An :class:`acf_cli.transport.Exchange` whose every turn is scripted.

    A step is a response (a dict, completed with ``protocol`` and the request's ``request_id``
    unless it sets them), raw bytes, an exception to raise *after the request was taken* (the
    transport's way of saying "not sent" or "sent, no answer"), or a callable from the request to
    any of those.
    """

    def __init__(
        self,
        script: Iterable[Step] = (),
        *,
        check: Callable[[dict[str, Any]], None] | None = None,
        default: Step | None = None,
    ) -> None:
        self.requests: list[dict[str, Any]] = []
        self.read_timeouts: list[float] = []
        self.closed = 0
        self._script: deque[Step] = deque(script)
        self._default = default
        self._check = check

    @property
    def methods(self) -> list[str]:
        return [str(r["method"]) for r in self.requests]

    def exchange(self, payload: bytes, *, read_timeout_s: float) -> bytes:
        request = json.loads(payload)
        assert isinstance(request, dict)
        if self._check is not None:
            self._check(request)
        self.requests.append(request)
        self.read_timeouts.append(read_timeout_s)
        if self._script:
            step = self._script.popleft()
        elif self._default is not None:
            step = self._default
        else:
            raise AssertionError(f"the client sent {request['method']} but the script was exhausted")
        out = step(request) if callable(step) else step
        if isinstance(out, BaseException):
            raise out
        if isinstance(out, bytes):
            return out
        return json.dumps({"protocol": PROTOCOL, "request_id": request.get("request_id"), **out}).encode()

    def close(self) -> None:
        self.closed += 1

    def assert_exhausted(self) -> None:
        assert not self._script, f"{len(self._script)} scripted step(s) were never used"


# ----------------------------------------------------------------------------- framing (independent of acf_cli)
def send_frame(conn: socket.socket, payload: bytes) -> None:
    conn.sendall(HEADER.pack(len(payload)) + payload)


def read_frame(conn: socket.socket) -> bytes | None:
    """One frame's payload, or ``None`` on a clean EOF before any byte."""
    header = _read_exactly(conn, HEADER.size)
    if header is None:
        return None
    (length,) = HEADER.unpack(header)
    if length == 0:
        return b""
    return _read_exactly(conn, length)


def _read_exactly(conn: socket.socket, count: int) -> bytes | None:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = conn.recv(min(remaining, 1 << 16))
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def bind_unix(sock: socket.socket, path: Path) -> None:
    """Bind, working around the 108-byte ``sun_path`` limit for deep temporary directories."""
    if len(os.fsencode(path)) < SUN_PATH_SAFE:
        sock.bind(str(path))
        return
    dir_fd = os.open(path.parent, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        sock.bind(f"/proc/self/fd/{dir_fd}/{path.name}")
    finally:
        os.close(dir_fd)


# ----------------------------------------------------------------------------- a scripted server on a real socket
class Serves(Protocol):
    """What the scripted server does with one connection. It returns the request frames it read."""

    def serve(self, conn: socket.socket) -> list[bytes]: ...


class Echo:
    """Answer each of ``turns`` requests with one frame carrying ``reply(request_payload)``."""

    def __init__(self, reply: Callable[[bytes], bytes], *, turns: int = 1) -> None:
        self._reply = reply
        self._turns = turns

    def serve(self, conn: socket.socket) -> list[bytes]:
        seen: list[bytes] = []
        for _ in range(self._turns):
            frame = read_frame(conn)
            if frame is None:
                break
            seen.append(frame)
            send_frame(conn, self._reply(frame))
        return seen


class Lost:
    """Read the whole request, then close without answering: the response was *lost*."""

    def serve(self, conn: socket.socket) -> list[bytes]:
        frame = read_frame(conn)
        return [frame] if frame is not None else []


class ClosedBeforeRead:
    """Accept, then close without reading anything."""

    def serve(self, conn: socket.socket) -> list[bytes]:
        _ = conn
        return []


class SayThenClose:
    """Write one frame *without reading the request*, then close (an authentication refusal at accept time)."""

    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def serve(self, conn: socket.socket) -> list[bytes]:
        send_frame(conn, self._payload)
        return []


class RawAfterRead:
    """Read the request, then write these exact bytes (no framing added)."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def serve(self, conn: socket.socket) -> list[bytes]:
        frame = read_frame(conn)
        conn.sendall(self._data)
        return [frame] if frame is not None else []


class Stall:
    """Read the request, then say nothing for ``seconds``: the client's timeout fires first."""

    def __init__(self, seconds: float) -> None:
        self._seconds = seconds

    def serve(self, conn: socket.socket) -> list[bytes]:
        frame = read_frame(conn)
        time.sleep(self._seconds)
        return [frame] if frame is not None else []


class ScriptedHost:
    """Connections are assigned behaviours in arrival order and served concurrently."""

    def __init__(self, path: Path, script: Sequence[Serves]) -> None:
        self.socket_path = path
        self.frames: list[bytes] = []
        self.connections = 0
        self.problems: list[str] = []
        self._script: deque[Serves] = deque(script)
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._server: socket.socket | None = None
        self._acceptor: threading.Thread | None = None
        self._workers: list[threading.Thread] = []

    def start(self) -> None:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        bind_unix(server, self.socket_path)
        server.listen(16)
        server.settimeout(0.05)
        self._server = server
        self._acceptor = threading.Thread(target=self._accept_loop, name="scripted-host", daemon=True)
        self._acceptor.start()

    def stop(self) -> None:
        self._stop.set()
        if self._acceptor is not None:
            self._acceptor.join(timeout=5)
        for worker in self._workers:
            worker.join(timeout=5)
        if self._server is not None:
            self._server.close()

    def assert_clean(self) -> None:
        assert not self.problems, f"scripted host saw unexpected behaviour: {self.problems}"
        assert not self._script, f"{len(self._script)} scripted behaviour(s) were never used"

    def _accept_loop(self) -> None:
        assert self._server is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._server.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with self._lock:
                self.connections += 1
                behavior = self._script.popleft() if self._script else None
            worker = threading.Thread(target=self._serve_one, args=(conn, behavior), daemon=True)
            self._workers.append(worker)
            worker.start()

    def _serve_one(self, conn: socket.socket, behavior: Serves | None) -> None:
        with conn, contextlib.suppress(OSError):
            conn.settimeout(5)
            if behavior is None:
                with self._lock:
                    self.problems.append("a connection arrived but the script was exhausted")
                return
            seen = behavior.serve(conn)
            with self._lock:
                self.frames.extend(seen)


# ----------------------------------------------------------------------------- time
class FakeClock:
    """``sleep`` advances ``monotonic`` instantly, so retry and polling logic runs in zero wall time."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.sleeps: list[float] = []

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds

    def monotonic(self) -> float:
        return self.now
