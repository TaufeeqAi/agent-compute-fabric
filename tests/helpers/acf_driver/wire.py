"""The host's wire protocol, spoken without the reference client: ``u32`` big-endian length, then one JSON document.

Two uses, and they are different:

* :class:`RawConnection` sends whatever a test puts on the wire. Some claims are about the host and not about the
  client ("an unknown field is refused", "another protocol major is refused before anything is recorded", "a request
  that carries ``authority`` is refused, never ignored"), and the client is built never to send such a request.
* :class:`WireHost` is the arranging hand of a test: it drives the host in this process (no subprocess per step) and
  requires each step to succeed, so that the client invocations of a test are the ones the test is about.

What a well-formed request looks like is taken from the published API description
(``execution/contracts/host-api.json``), not from the client: :class:`ApiDescription` reads the method table, the
failure classes with their retry advice, and the state vocabularies.
"""

from __future__ import annotations

import contextlib
import enum
import json
import os
import socket
import ssl
import struct
import subprocess
import time
import uuid
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import cache
from pathlib import Path
from types import TracebackType
from typing import Any, Final, Self

from acf_driver.base import PROTOCOL, DriverError, LostAnswerError, tail
from acf_driver.views import Answer, HostInfo, Operation, Page, Sandbox, Snapshot

REPO: Final = Path(__file__).resolve().parents[3]
API_DESCRIPTION: Final = REPO / "execution" / "contracts" / "host-api.json"

#: The largest answer this client is willing to read: a bound, so that a broken peer cannot make a test allocate.
MAX_ANSWER_BYTES: Final = 64 * 1024 * 1024
#: How long `_done` follows an operation the host was still working on when its wait ended.
FOLLOW_S: Final = 600.0
#: The states of an operation that has not ended.
UNFINISHED: Final = frozenset({"ACCEPTED", "IN_PROGRESS", "RECOVERING"})
#: How many times a full listing is begun again when its continuation cursor expires (API-11).
FULL_LISTING_ATTEMPTS: Final = 3
_HEADER: Final = struct.Struct(">I")


class _Auto(enum.Enum):
    AUTO = enum.auto()


#: "Fill this envelope field the way a well-behaved caller would."
AUTO: Final = _Auto.AUTO


# ---------------------------------------------------------------------------------- the published description
@dataclass(frozen=True)
class MethodInfo:
    name: str
    method_class: str  # granting | containment | read | operator
    roles: tuple[str, ...]
    creates_operation: bool
    params_required: bool


@dataclass(frozen=True)
class ApiDescription:
    """What ``execution/contracts/host-api.json`` says, as far as the suites use it."""

    protocol: str
    methods: tuple[MethodInfo, ...]
    #: failure class -> {"retry", "may_refuse", "may_fail_operation"}
    failure_classes: Mapping[str, Mapping[str, Any]]
    lifecycle_states: tuple[str, ...]
    operation_states: tuple[str, ...]
    host_modes: tuple[str, ...]
    features: tuple[str, ...]

    def method(self, name: str) -> MethodInfo:
        for info in self.methods:
            if info.name == name:
                return info
        raise KeyError(name)

    def creates_operation(self, method: str) -> bool:
        """Whether ``method`` needs ``operation_id`` and ``issued_at``. An unknown method is treated as one that does."""
        try:
            return self.method(method).creates_operation
        except KeyError:
            return True

    def retry_advice(self, failure_class: str) -> str:
        return str(self.failure_classes[failure_class]["retry"])


@cache
def api_description() -> ApiDescription:
    doc = json.loads(API_DESCRIPTION.read_text(encoding="utf-8"))
    methods = tuple(
        MethodInfo(
            name=str(m["name"]),
            method_class=str(m["class"]),
            roles=tuple(str(r) for r in m["roles"]),
            creates_operation=bool(m["creates_operation"]),
            params_required=bool(m["params_required"]),
        )
        for m in doc["methods"]
    )
    return ApiDescription(
        protocol=str(doc["protocol"]),
        methods=methods,
        failure_classes={str(entry["class"]): entry for entry in doc["failure_classes"]},
        lifecycle_states=tuple(str(s) for s in doc["lifecycle_states"]),
        operation_states=tuple(str(s) for s in doc["operation_states"]),
        host_modes=tuple(str(s) for s in doc["host_modes"]),
        features=tuple(str(s) for s in doc["features"]),
    )


# ---------------------------------------------------------------------------------- building requests
def new_operation_id() -> str:
    """A fresh, valid operation id (8 to 64 characters of ``[A-Za-z0-9-]``)."""
    return "op-" + uuid.uuid4().hex


def utc_timestamp(offset_s: float = 0.0) -> str:
    """Now (plus ``offset_s``) in the form ``issued_at`` takes: ``YYYY-MM-DDTHH:MM:SS.fffZ``."""
    moment = datetime.now(UTC) + timedelta(seconds=offset_s)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def envelope(
    method: str,
    params: Mapping[str, Any] | None = None,
    *,
    scope: str = "default",
    operation_id: str | _Auto | None = AUTO,
    issued_at: str | _Auto | None = AUTO,
    request_id: str | _Auto | None = AUTO,
    protocol: str = PROTOCOL,
    retry: bool | None = None,
    wait_ms: int | None = None,
    on_behalf_of: str | None = None,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """One request envelope.

    With the defaults it is what a well-behaved caller sends: a method that creates an operation gets a fresh
    ``operation_id`` and the current time as ``issued_at``; a read gets neither. Every field can be overridden or
    left out (``None``), and ``extra`` adds members the protocol does not know, because sending a request that is
    *not* well formed is the point of this module.
    """
    needs_operation = api_description().creates_operation(method)
    doc: dict[str, Any] = {"protocol": protocol, "owner_scope": scope, "method": method}
    if request_id is AUTO:
        doc["request_id"] = "req-" + uuid.uuid4().hex[:16]
    elif request_id is not None:
        doc["request_id"] = request_id
    if operation_id is AUTO:
        if needs_operation:
            doc["operation_id"] = new_operation_id()
    elif operation_id is not None:
        doc["operation_id"] = operation_id
    if issued_at is AUTO:
        if needs_operation:
            doc["issued_at"] = utc_timestamp()
    elif issued_at is not None:
        doc["issued_at"] = issued_at
    if params is not None:
        doc["params"] = dict(params)
    if retry is not None:
        doc["retry"] = retry
    if wait_ms is not None:
        doc["wait_ms"] = wait_ms
    if on_behalf_of is not None:
        doc["on_behalf_of"] = on_behalf_of
    if extra:
        doc.update(extra)
    return doc


def frame(payload: bytes) -> bytes:
    """``payload`` as one frame: its length as a ``u32`` in network byte order, then the bytes."""
    return _HEADER.pack(len(payload)) + payload


# ---------------------------------------------------------------------------------- one connection
class RawConnection:
    """One connection to an endpoint of the host. Sends what it is told to; reads frames as they come."""

    def __init__(self, sock: socket.socket, where: str) -> None:
        self._sock = sock
        self.where = where

    @classmethod
    def unix(cls, path: str | Path, *, timeout: float = 10.0) -> RawConnection:
        """Connect to the local endpoint. An endpoint that cannot be reached raises the ``OSError`` the kernel gave."""
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect(str(path))
        except OSError:
            sock.close()
            raise
        return cls(sock, f"unix:{path}")

    @classmethod
    def tls(
        cls,
        host: str,
        port: int,
        *,
        certificate: Path,
        private_key: Path,
        ca: Path,
        server_name: str = "localhost",
        timeout: float = 10.0,
    ) -> RawConnection:
        """Connect to the network endpoint with mutual TLS 1.3, presenting ``certificate``."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cafile=str(ca))
        context.load_cert_chain(certfile=str(certificate), keyfile=str(private_key))
        plain = socket.create_connection((host, port), timeout=timeout)
        try:
            sock = context.wrap_socket(plain, server_hostname=server_name)
        except (OSError, ssl.SSLError):
            plain.close()
            raise
        sock.settimeout(timeout)
        return cls(sock, f"tls:{host}:{port}")

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self, kind: type[BaseException] | None, value: BaseException | None, trace: TracebackType | None
    ) -> None:
        self.close()

    def close(self) -> None:
        self._sock.close()

    # ---- sending: three levels, from "these exact bytes" to "this document"
    def send(self, data: bytes) -> None:
        """Put exactly these bytes on the wire (a header that lies, half a frame ...)."""
        self._sock.sendall(data)

    def send_frame(self, payload: bytes) -> None:
        self.send(frame(payload))

    def send_json(self, document: Any) -> None:
        self.send_frame(json.dumps(document, separators=(",", ":")).encode())

    def finish_sending(self) -> None:
        """Half-close: the peer sees the end of the stream and this side can still read."""
        self._sock.shutdown(socket.SHUT_WR)

    # ---- receiving
    def _read_exactly(self, count: int) -> bytes | None:
        """``count`` bytes, or ``None`` if the peer closed before sending any of them."""
        chunks: list[bytes] = []
        got = 0
        while got < count:
            chunk = self._sock.recv(min(count - got, 1 << 16))
            if not chunk:
                if got == 0:
                    return None
                raise DriverError(f"{self.where}: the peer closed in the middle of a frame ({got} of {count} bytes)")
            chunks.append(chunk)
            got += len(chunk)
        return b"".join(chunks)

    def read(self, *, timeout: float | None = None) -> Answer | None:
        """The next answer, or ``None`` when the peer closed the connection on a frame boundary.

        Raises ``TimeoutError`` when nothing arrives in time: silence and a closed connection are different facts.
        """
        if timeout is not None:
            self._sock.settimeout(timeout)
        try:
            header = self._read_exactly(_HEADER.size)
        except ConnectionResetError:
            return None
        if header is None:
            return None
        (length,) = _HEADER.unpack(header)
        if length > MAX_ANSWER_BYTES:
            raise DriverError(f"{self.where}: the peer announced a frame of {length} bytes")
        body = self._read_exactly(length) if length else b""
        if body is None:
            raise DriverError(f"{self.where}: the peer closed after a frame header")
        try:
            document = json.loads(body)
        except json.JSONDecodeError as e:
            raise DriverError(
                f"{self.where}: the answer is not JSON ({e}): {tail(body.decode('utf-8', 'replace'), 300)}"
            ) from e
        return Answer(document)

    def ask(self, document: Any, *, timeout: float | None = None) -> Answer:
        """Send one document and return the one answer to it."""
        self.send_json(document)
        answer = self.read(timeout=timeout)
        if answer is None:
            raise LostAnswerError(f"{self.where}: the peer closed the connection without answering {document!r}")
        return answer

    def request(self, method: str, params: Mapping[str, Any] | None = None, **options: Any) -> Answer:
        """Send a request built by :func:`envelope` (``options`` are its keyword arguments) and return its answer."""
        return self.ask(envelope(method, params, **options))

    def peer_closed(self, *, within: float) -> bool:
        """Whether the peer closes the connection within ``within`` seconds, without sending another frame first."""
        try:
            return self.read(timeout=within) is None
        except TimeoutError:
            return False
        except OSError:
            return True


# ---------------------------------------------------------------------------------- arranging over the wire
def target_of(sandbox: Sandbox) -> dict[str, Any]:
    """The target token of a lifecycle-changing method for the sandbox as ``sandbox`` shows it."""
    return {"sandbox_id": sandbox.sandbox_id, "expected_generation": sandbox.generation}


def snapshot_ref(snapshot: Snapshot) -> dict[str, Any]:
    return {"snapshot_id": snapshot.snapshot_id, "snapshot_generation": snapshot.snapshot_generation}


def resources(
    *, vcpus: int = 1, memory_mib: int = 256, disk_mib: int = 1024, network: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """The ``resources`` of ``sandbox.create``; the network intent defaults to mode ``none``."""
    return {
        "vcpus": vcpus,
        "memory_mib": memory_mib,
        "disk_mib": disk_mib,
        "network": dict(network or {"mode": "none"}),
    }


class WireHost:
    """Arranges and tidies up over the wire, in this process, as one enrolled peer in one owner scope.

    Every helper that names an effect requires the host to have accepted the request and the operation to have
    ended ``SUCCEEDED``; anything else is a :class:`DriverError` that carries the host's answer. The requests a
    test is *about* do not belong here: they go through the reference client, or through :meth:`call`, which
    returns the answer whatever it is.
    """

    def __init__(
        self,
        connect: Callable[[], RawConnection],
        *,
        scope: str = "default",
        image: str = "python",
        page_size: int | None = None,
    ) -> None:
        self._connect = connect
        self.scope = scope
        self.image = image
        #: The ``limit`` of each list request; ``None`` leaves the page size to the host.
        self.page_size = page_size

    def in_scope(self, scope: str) -> WireHost:
        return WireHost(self._connect, scope=scope, image=self.image, page_size=self.page_size)

    def connect(self) -> RawConnection:
        """A connection of this peer, for a test that needs to hold one open or to send several requests on it."""
        return self._connect()

    def call(self, method: str, params: Mapping[str, Any] | None = None, **options: Any) -> Answer:
        """One request, one answer. ``options`` are the keyword arguments of :func:`envelope`."""
        options.setdefault("scope", self.scope)
        with self._connect() as conn:
            return conn.ask(envelope(method, params, **options), timeout=120.0)

    def _done(self, method: str, params: Mapping[str, Any] | None = None) -> Operation:
        """The operation ``method`` creates, followed to its end; it must have ended ``SUCCEEDED``.

        The host answers when the operation ends or when its wait (``operations.wait_max_ms``) is over, whichever is
        first. Work that takes longer on a real host (a snapshot writes the guest's memory to disk) is still in
        progress then, and a caller resolves it by its id, which is what this does, for at most ``FOLLOW_S``.

        An answer can also be lost: the edge closes without one when the core does not answer in time, since it
        cannot know whether the operation was recorded. That is resolved as the protocol says, by the same request
        with ``retry: true``, which the host answers with the operation it holds, or refuses with ``NOT_FOUND`` if it
        never recorded one; then the request is sent again as a first submission, under the same id.
        """
        deadline = time.monotonic() + FOLLOW_S
        answer = self._resolved(envelope(method, params, scope=self.scope), deadline)
        operation = answer.accepted()
        while operation.state in UNFINISHED and time.monotonic() < deadline:
            time.sleep(0.5)
            operation = self.operation(operation.operation_id)
        if operation.state != "SUCCEEDED":
            raise DriverError(
                f"operation {operation.operation_id} ({operation.operation_type}) is {operation.state}, "
                f"expected SUCCEEDED: failure={operation.failure!r}"
            )
        return operation

    def _resolved(self, document: dict[str, Any], deadline: float) -> Answer:
        """The answer to ``document``, a request that creates an operation, with a lost answer resolved by its id."""
        while True:
            try:
                with self._connect() as conn:
                    answer = conn.ask(document, timeout=120.0)
            except LostAnswerError:
                if time.monotonic() >= deadline:
                    raise
                document = {**document, "retry": True}
                time.sleep(1.0)
                continue
            refusal = answer.refusal
            if document.get("retry") and refusal is not None and refusal.failure_class == "NOT_FOUND":
                document = {**document, "retry": False}
                continue
            return answer

    # ---- reads
    def info(self) -> HostInfo:
        return self.call("host.info").host_info()

    def metrics(self) -> Mapping[str, Any]:
        return self.call("host.metrics").metrics()

    def sequence(self) -> int:
        """The commit sequence of the store right now: it moves if and only if something was recorded."""
        return self.call("host.info").sequence

    @contextlib.contextmanager
    def nothing_recorded(self, what: str = "a refused request") -> Iterator[None]:
        """The block must commit nothing: a refusal leaves no operation record and no reservation behind.

        A host that has run for a while also commits on its own: retention forgets what has outlived
        ``operation_retention`` and ``change_retention``, at any moment. So when the commit sequence moved, the
        records are asked: no operation, sandbox or snapshot may have changed since the block began. (Found on the
        first real host, where the one commit inside such a block was retention's ``forget``.)
        """
        start = self.call("host.info").as_of
        if start is None:
            raise DriverError("host.info carried no as_of")
        yield
        after = self.sequence()
        if after == start.sequence:
            return
        changed: list[str] = []
        readers: tuple[tuple[str, Callable[[Answer], Page[Any]]], ...] = (
            ("operation.list", lambda a: a.operations()),
            ("sandbox.list", lambda a: a.sandboxes()),
            ("snapshot.list", lambda a: a.snapshots()),
        )
        for method, page_of in readers:
            answer = self.call(method, {"changed_since": start.to_wire()})
            if answer.refusal is not None:
                raise DriverError(
                    f"{what}: the store moved from commit {start.sequence} to {after}, and what changed could not "
                    f"be read: {answer!r}"
                )
            changed.extend(f"{method}: {_identity(item)}" for item in page_of(answer).items)
        if changed:
            raise DriverError(
                f"{what} must record nothing, but the store moved from commit {start.sequence} to {after} and "
                f"changed {changed}"
            )

    def inspect(self, sandbox: str) -> Sandbox:
        """A sandbox by id or by name."""
        return self.call("sandbox.inspect", {"sandbox": sandbox}).sandbox()

    def refresh(self, sandbox: Sandbox) -> Sandbox:
        return self.inspect(sandbox.sandbox_id)

    def sandboxes(self) -> list[Sandbox]:
        """Every sandbox this peer may see that exists (a full listing has no tombstones)."""
        return [s for s in self._all("sandbox.list", lambda a: a.sandboxes()) if s.state != "DESTROYED"]

    def snapshots(self) -> list[Snapshot]:
        return [s for s in self._all("snapshot.list", lambda a: a.snapshots()) if s.state != "DELETED"]

    def operations(self) -> list[Operation]:
        return self._all("operation.list", lambda a: a.operations())

    def operation(self, operation_id: str) -> Operation:
        found = self.call("operation.get", {"operation_id": operation_id}).result("operation")
        return Operation(found)

    def _all[T: (Sandbox, Snapshot, Operation)](self, method: str, page_of: Callable[[Answer], Page[T]]) -> list[T]:
        """Follow a listing to its end. A later page is a change: it replaces what an earlier page said.

        If retention forgets a tombstone while the listing is followed, the host refuses the next cursor with
        ``CURSOR_EXPIRED``, and "the caller lists again in full" (API-11): it is begun again, a bounded number of
        times, as the reference client does.
        """
        limit = {} if self.page_size is None else {"limit": self.page_size}
        for attempt in range(1, FULL_LISTING_ATTEMPTS + 1):
            page = page_of(self.call(method, limit or None))
            by_identity: dict[str, T] = {}
            while True:
                for item in page.items:
                    by_identity[_identity(item)] = item
                if not page.more:
                    return list(by_identity.values())
                answer = self.call(method, {"changed_since": page.cursor.to_wire(), **limit})
                refusal = answer.refusal
                if (
                    refusal is not None
                    and refusal.failure_class == "CURSOR_EXPIRED"
                    and attempt < FULL_LISTING_ATTEMPTS
                ):
                    break
                page = page_of(answer)
        raise DriverError(f"{method}: the listing could not be followed to its end")

    # ---- sandboxes
    def create(
        self,
        name: str | None = None,
        *,
        vcpus: int = 1,
        memory_mib: int = 256,
        disk_mib: int = 1024,
        network: Mapping[str, Any] | None = None,
        lifetime_secs: int | None = None,
    ) -> Sandbox:
        """``sandbox.create``: a ``PROVISIONING`` sandbox."""
        params: dict[str, Any] = {
            "image": self.image,
            "resources": resources(vcpus=vcpus, memory_mib=memory_mib, disk_mib=disk_mib, network=network),
        }
        if name is not None:
            params["name"] = name
        if lifetime_secs is not None:
            params["lifetime_secs"] = lifetime_secs
        return self._done("sandbox.create", params).sandbox_result()

    def start(self, sandbox: Sandbox) -> Sandbox:
        return self._done("sandbox.start", target_of(sandbox)).sandbox_result()

    def ready(self, name: str | None = None, **create: Any) -> Sandbox:
        """Created and started: a ``READY`` sandbox, the starting point of most checks."""
        started = self.start(self.create(name, **create))
        if started.state != "READY":
            raise DriverError(f"the sandbox is {started.state} after start, expected READY: {started!r}")
        return started

    def run(self, sandbox: Sandbox, argv: list[str], **command: Any) -> Operation:
        """``exec.run`` of ``argv``; the operation must end ``SUCCEEDED`` (whatever the command's own exit status)."""
        return self._done("exec.run", {**target_of(sandbox), "command": {"argv": argv, **command}})

    def completed(self, name: str | None = None, **create: Any) -> Sandbox:
        """A sandbox that has run one command: ``COMPLETED``."""
        box = self.ready(name, **create)
        self.run(box, ["true"])
        return self.refresh(box)

    def stop(self, sandbox: Sandbox) -> Sandbox:
        return self._done("sandbox.stop", target_of(sandbox)).sandbox_result()

    def destroy(self, sandbox: Sandbox) -> Sandbox:
        return self._done("sandbox.destroy", target_of(sandbox)).sandbox_result()

    # ---- snapshots
    def snapshot(self, sandbox: Sandbox, name: str | None = None) -> Snapshot:
        params = target_of(sandbox)
        if name is not None:
            params["name"] = name
        return self._done("snapshot.create", params).snapshot_result()

    def restore_into(self, snapshot: Snapshot, sandbox: Sandbox) -> Sandbox:
        """Restore in place: a new generation of ``sandbox``."""
        restore = {"kind": "existing", **target_of(sandbox)}
        return self._done("snapshot.restore", {"snapshot": snapshot_ref(snapshot), "target": restore}).sandbox_result()

    def restore_new(self, snapshot: Snapshot, name: str | None = None, lifetime_secs: int | None = None) -> Sandbox:
        """Restore as a brand-new sandbox, generation 1."""
        restore: dict[str, Any] = {"kind": "new"}
        if name is not None:
            restore["name"] = name
        if lifetime_secs is not None:
            restore["lifetime_secs"] = lifetime_secs
        return self._done("snapshot.restore", {"snapshot": snapshot_ref(snapshot), "target": restore}).sandbox_result()

    def delete(self, snapshot: Snapshot) -> Snapshot:
        return self._done("snapshot.delete", {"snapshot": snapshot_ref(snapshot)}).snapshot_result()

    # ---- operator methods
    def set_mode(self, mode: str) -> Operation:
        """``host.set_mode`` with ``DRAINING`` or ``SERVING``."""
        return self._done("host.set_mode", {"mode": mode})

    def release(self, sandbox: Sandbox, mode: str) -> Answer:
        """``quarantine.release`` (``FORCE_DESTROY`` or ``DECLARE_ABSENT``); the answer is returned as it is."""
        params = {"sandbox_id": sandbox.sandbox_id, "generation": sandbox.generation, "mode": mode}
        return self.call("quarantine.release", params)

    # ---- tidying up
    def purge(self) -> list[str]:
        """Remove everything this peer can see; return what could not be removed, with the host's reason.

        A draining host is put back to serving first. A quarantined generation is released with ``FORCE_DESTROY``:
        the suites own the host, so "its recorded resources belong to this host" is a statement they can make.
        """
        leftovers: list[str] = []
        if self.info().mode == "DRAINING":
            self.set_mode("SERVING")
        for sandbox in self.sandboxes():
            method = "quarantine.release" if sandbox.quarantined else "sandbox.destroy"
            params: dict[str, Any] = (
                {"sandbox_id": sandbox.sandbox_id, "generation": sandbox.generation, "mode": "FORCE_DESTROY"}
                if sandbox.quarantined
                else target_of(sandbox)
            )
            answer = self.call(method, params)
            operation = answer.operation
            if operation is None or operation.state != "SUCCEEDED":
                leftovers.append(f"sandbox {sandbox.sandbox_id} ({sandbox.state}): {method} answered {answer!r}")
        for snapshot in self.snapshots():
            answer = self.call("snapshot.delete", {"snapshot": snapshot_ref(snapshot)})
            operation = answer.operation
            if operation is None or operation.state != "SUCCEEDED":
                leftovers.append(f"snapshot {snapshot.snapshot_id} ({snapshot.state}): {answer!r}")
        return leftovers


def _identity(item: Sandbox | Snapshot | Operation) -> str:
    if isinstance(item, Sandbox):
        return item.sandbox_id
    if isinstance(item, Snapshot):
        return f"{item.snapshot_id}@{item.snapshot_generation}"
    peer, scope = item.owner
    return f"{peer}/{scope}/{item.operation_id}"


# ---------------------------------------------------------------------------------- as another local user
# The probe is a string so that it can run as ANOTHER user (`python3 -I -c`): it needs no file of this repository,
# which that user may not be able to read. It connects, optionally sends one frame, and reports every frame the host
# sent before it closed. The kernel reports the probe's uid to the host; nothing the probe sends can change it.
_UID_PROBE: Final = r"""
import json, os, socket, struct, sys
path, payload, patience = sys.argv[1], sys.argv[2], float(sys.argv[3])
out = {"uid": os.getuid(), "connect": "ok", "frames": [], "closed": False}
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(patience)
try:
    sock.connect(path)
except OSError as e:
    out["connect"] = type(e).__name__
    print(json.dumps(out))
    sys.exit(0)
if payload:
    raw = payload.encode()
    try:
        sock.sendall(struct.pack(">I", len(raw)) + raw)
    except OSError:
        out["send"] = "failed"
buf = b""
try:
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            out["closed"] = True
            break
        buf += chunk
except OSError:
    out["closed"] = False
while len(buf) >= 4:
    (size,) = struct.unpack(">I", buf[:4])
    if len(buf) < 4 + size:
        break
    out["frames"].append(json.loads(buf[4 : 4 + size]))
    buf = buf[4 + size :]
print(json.dumps(out))
"""


@dataclass(frozen=True)
class UidProbe:
    """What a local process running as ``uid`` got from the host's local endpoint."""

    uid: int
    connect: str  # "ok", or the name of the error: "PermissionError", "FileNotFoundError" ...
    frames: list[Answer]
    closed: bool  # the host closed the connection (as opposed to: the probe stopped waiting)

    @property
    def connected(self) -> bool:
        return self.connect == "ok"


def probe_as_uid(
    socket_path: str | Path, uid: int, request: Mapping[str, Any] | None = None, *, patience: float = 5.0
) -> UidProbe:
    """Connect to the local endpoint as the numeric user ``uid`` (primary group ``uid``, no other groups).

    Needs root. The probe optionally sends ``request`` and reports what came back.
    """
    payload = "" if request is None else json.dumps(request, separators=(",", ":"))
    python = next((p for p in ("/usr/bin/python3", "/usr/local/bin/python3") if Path(p).is_file()), "python3")
    # Becoming another user needs root; asking as oneself needs nothing, and proves the probe itself.
    identity: dict[str, Any] = {} if uid == os.geteuid() else {"user": uid, "group": uid, "extra_groups": []}
    done = subprocess.run(
        [python, "-I", "-c", _UID_PROBE, str(socket_path), payload, str(patience)],
        capture_output=True,
        text=True,
        timeout=patience + 60,
        cwd="/",
        check=False,
        **identity,
    )
    if done.returncode != 0:
        raise DriverError(f"the probe could not run as uid {uid} (exit {done.returncode}): {tail(done.stderr)}")
    doc = json.loads(done.stdout)
    return UidProbe(
        uid=int(doc["uid"]),
        connect=str(doc["connect"]),
        frames=[Answer(f) for f in doc["frames"]],
        closed=bool(doc["closed"]),
    )
