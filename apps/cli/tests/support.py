"""Test doubles for the host agent: a scripted Unix-socket server and a fake clock.

The scripted host speaks the real wire format (u32 big-endian length + JSON) over a real
``AF_UNIX`` socket, so the client's framing, timeout and connection handling are exercised for
real. What is *scripted* is the host's behaviour: answer, answer with a given status, drop the
connection after reading the request (the "lost response" case), close before reading, send
garbage, send half a frame, or stall.

Each accepted connection consumes the next behaviour in the script. A connection with no behaviour
left, or a script that is not fully consumed, fails the test (``assert_clean``): a client that
sends more or fewer requests than the test expects is a behavioural change, not a detail.
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
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, ClassVar, Protocol

HEADER = struct.Struct(">I")
PROTOCOL = "acf.host/1"
SUN_PATH_SAFE = 100


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
    """Bind, working around the 108-byte ``sun_path`` limit exactly like the host does."""
    if len(os.fsencode(path)) < SUN_PATH_SAFE:
        sock.bind(str(path))
        return
    dir_fd = os.open(path.parent, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        sock.bind(f"/proc/self/fd/{dir_fd}/{path.name}")
    finally:
        os.close(dir_fd)


# ----------------------------------------------------------------------------- response builders
def respond(
    request: dict[str, Any] | None,
    status: str,
    *,
    result: dict[str, Any] | None = None,
    error: dict[str, Any] | None = None,
    operation_id: str | None = None,
    protocol: str = PROTOCOL,
) -> dict[str, Any]:
    """A response envelope correlated to ``request`` (same ``request_id``; its ``operation_id`` unless overridden)."""
    request = request or {}
    return {
        "protocol": protocol,
        "request_id": request.get("request_id"),
        "operation_id": operation_id if operation_id is not None else request.get("operation_id"),
        "status": status,
        "result": result,
        "error": error,
    }


def error_body(
    failure_class: str,
    message: str,
    *,
    side_effect: str = "none",
    retryable: bool = False,
    outcome_unknown: bool = False,
) -> dict[str, Any]:
    return {
        "class": failure_class,
        "message": message,
        "side_effect": side_effect,
        "retryable": retryable,
        "outcome_unknown": outcome_unknown,
    }


# ----------------------------------------------------------------------------- behaviours
Build = Callable[[dict[str, Any]], dict[str, Any] | bytes]


class Behavior(Protocol):
    reads_request: ClassVar[bool]

    def run(self, conn: socket.socket, request: dict[str, Any] | None) -> None: ...


class Reply:
    """Read the request, then answer with ``build(request)`` (or a fixed dict/bytes) as one frame."""

    reads_request: ClassVar[bool] = True

    def __init__(self, build: Build | dict[str, Any] | bytes, *, delay: float = 0.0) -> None:
        self._build = build
        self._delay = delay

    def run(self, conn: socket.socket, request: dict[str, Any] | None) -> None:
        assert request is not None
        if self._delay:
            time.sleep(self._delay)
        out = self._build(request) if callable(self._build) else self._build
        payload = out if isinstance(out, bytes) else json.dumps(out).encode()
        send_frame(conn, payload)


class Lost:
    """Read the whole request, then close without answering: the response was *lost*."""

    reads_request: ClassVar[bool] = True

    def run(self, conn: socket.socket, request: dict[str, Any] | None) -> None:
        return


class ClosedBeforeRead:
    """Accept, then close without reading anything (a host that is down or refusing)."""

    reads_request: ClassVar[bool] = False

    def run(self, conn: socket.socket, request: dict[str, Any] | None) -> None:
        return


class DenyUnread:
    """Answer *without reading the request*, then close (an authorization denial at accept time)."""

    reads_request: ClassVar[bool] = False

    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def run(self, conn: socket.socket, request: dict[str, Any] | None) -> None:
        send_frame(conn, json.dumps(self._payload).encode())


class RawBytes:
    """Read the request, then write these exact bytes (no framing added)."""

    reads_request: ClassVar[bool] = True

    def __init__(self, data: bytes) -> None:
        self._data = data

    def run(self, conn: socket.socket, request: dict[str, Any] | None) -> None:
        conn.sendall(self._data)


class Partial:
    """Read the request, announce a frame, deliver only part of it, close."""

    reads_request: ClassVar[bool] = True

    def __init__(self, payload: bytes, delivered: int) -> None:
        self._payload = payload
        self._delivered = delivered

    def run(self, conn: socket.socket, request: dict[str, Any] | None) -> None:
        conn.sendall(HEADER.pack(len(self._payload)) + self._payload[: self._delivered])


class Stall:
    """Read the request, then say nothing for ``seconds`` (bounded) — the client's timeout fires first."""

    reads_request: ClassVar[bool] = True

    def __init__(self, seconds: float) -> None:
        self._seconds = seconds

    def run(self, conn: socket.socket, request: dict[str, Any] | None) -> None:
        time.sleep(self._seconds)


# ----------------------------------------------------------------------------- the server
class ScriptedHost:
    """Connections are *assigned* behaviours in arrival order, then served concurrently.

    Concurrency matters for the stall case: a host that is busy with one connection must still
    accept the client's next one (the client's ``operation_get``), exactly like the real host.
    """

    def __init__(self, path: Path, script: Sequence[Behavior], *, default: Behavior | None = None) -> None:
        self.socket_path = path
        self.requests: list[dict[str, Any]] = []
        self.problems: list[str] = []
        self._script: deque[Behavior] = deque(script)
        self._default = default
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._server: socket.socket | None = None
        self._acceptor: threading.Thread | None = None
        self._workers: list[threading.Thread] = []

    # -- lifecycle
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

    # -- introspection
    @property
    def methods(self) -> list[str]:
        with self._lock:
            return [str(r["body"]["method"]) for r in self.requests]

    # -- server loop
    def _accept_loop(self) -> None:
        assert self._server is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._server.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            behavior = self._next()
            worker = threading.Thread(target=self._serve_one, args=(conn, behavior), daemon=True)
            self._workers.append(worker)
            worker.start()

    def _next(self) -> Behavior | None:
        with self._lock:
            if self._script:
                return self._script.popleft()
        return self._default

    def _serve_one(self, conn: socket.socket, behavior: Behavior | None) -> None:
        with conn, contextlib.suppress(OSError):
            conn.settimeout(5)
            if behavior is None:
                self._problem("a connection arrived but the script was exhausted")
                return
            request: dict[str, Any] | None = None
            if behavior.reads_request:
                frame = read_frame(conn)
                if frame is None:
                    self._problem("the client closed before sending a full request")
                    return
                request = json.loads(frame)
                assert isinstance(request, dict)
                with self._lock:
                    self.requests.append(request)
            behavior.run(conn, request)

    def _problem(self, text: str) -> None:
        with self._lock:
            self.problems.append(text)


# ----------------------------------------------------------------------------- time
class FakeClock:
    """``sleep`` advances ``monotonic`` instantly, so retry/backoff logic runs in zero wall time."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.sleeps: list[float] = []

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds

    def monotonic(self) -> float:
        return self.now
