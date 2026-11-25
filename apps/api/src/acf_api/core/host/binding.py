"""The host binding: the platform's only client of the execution plane.

One enrolled peer with role ``caller``, over the host's mutual-TLS endpoint. The binding owns transport,
framing, the pinned identity of the host and the connection classes. It does not choose operation ids,
owner scopes, generations or ``issued_at``; the pipeline does, once, in the ledger. It does not
interpret an answer beyond decoding it, and it retries nothing: the pipeline resolves a lost answer by
reading.

What a failed exchange means is decided here and relied on by everything above:

* :class:`~acf_api.core.host.wire.Unreachable`: nothing was written. The host did not act.
* :class:`~acf_api.core.host.wire.LostAnswer`: the request was written and no usable answer came back.
  The host may have acted. From the moment the first byte of a frame is handed to the connection, every
  failure is this one: a platform that cannot tell must not say "refused".

The host's identity is pinned: only the trust anchors in the configuration are trusted, never the
system store, and the host's certificate must carry the configured ``host_id``.

Connections are divided into classes. Some are used only for containment, some only for resolution
reads and the follower, and the rest serve granting work and other reads, of which no principal may
occupy more than half. No connection is ever held open for a caller's wait.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import struct
from collections import deque
from collections.abc import AsyncIterator
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Final, Protocol

from acf_api.core.host import wire
from acf_api.core.host.wire import (
    HostAnswer,
    HostOperation,
    HostRefusal,
    HostRequest,
    HostResult,
    LostAnswer,
    Unreachable,
)

_HEADER: Final = struct.Struct(">I")
#: The largest response frame a host sends. Checked before the payload is read.
MAX_RESPONSE_BYTES: Final = 64 * 1024 * 1024
DEFAULT_MAX_REQUEST_BYTES: Final = 1024 * 1024


class Lane(StrEnum):
    """Which class of connection a call uses."""

    GENERAL = "general"
    CONTAINMENT = "containment"
    RESOLUTION = "resolution"


class RequestTooLarge(Exception):
    """The encoded request exceeds what the host accepts. It was not sent."""

    def __init__(self, length: int, maximum: int) -> None:
        super().__init__(f"a host request of {length} bytes exceeds the host's bound of {maximum} bytes")
        self.length = length
        self.maximum = maximum


@dataclass(frozen=True, slots=True)
class HostInfo:
    """What ``host.info`` says, as far as the platform uses it. An observation, never an authority."""

    host_id: str
    protocols: tuple[str, ...]
    features: frozenset[str]
    lineage: str
    mode: str
    network_modes: frozenset[str]
    secret_injection: bool
    acceptance_horizon_ms: int
    clock_skew_tolerance_ms: int
    operation_retention_ms: int
    wait_max_ms: int
    max_request_bytes: int
    lifetime_default_secs: int
    lifetime_max_secs: int
    max_vcpus: int
    max_memory_mib: int
    max_disk_mib: int
    max_runtime_ms: int
    max_allowlist_entries: int
    #: The host's pool of identifiers, one for each sandbox. A ceiling of what the host admits at once and
    #: not the number it admits: that is its envelope, which it does not advertise.
    identifier_slots: int | None
    # Values the host does not report today. Each replaces a fallback when it appears.
    peer_id: str | None = None
    role: str | None = None
    time_ms: int | None = None
    ops_per_minute: int | None = None
    reads_per_minute: int | None = None
    forgetting_floor_ms: int | None = None
    #: The host says that it offers create and start as one operation. An observation and nothing more:
    #: this version writes no such request.
    create_with_start: bool = False


def parse_host_info(data: object) -> HostInfo:
    """Read ``host.info``. A field the platform needs and the host does not give is an error."""
    if not isinstance(data, dict):
        msg = "host.info is not an object"
        raise ValueError(msg)  # noqa: TRY004 - one error for every way host.info cannot be read: `info` catches it
    parameters = data.get("parameters") or {}
    ceilings = parameters.get("ceilings") or {}
    capabilities = data.get("capabilities") or {}

    def number(source: dict[str, Any], key: str) -> int:
        value = source.get(key)
        if not isinstance(value, int) or isinstance(value, bool):
            msg = f"host.info lacks the number `{key}`"
            raise ValueError(msg)  # noqa: TRY004 - a number of the wrong type is a missing number, the same error
        return value

    def optional(source: dict[str, Any], key: str) -> int | None:
        value = source.get(key)
        return value if isinstance(value, int) and not isinstance(value, bool) else None

    features = frozenset(str(f) for f in data.get("features") or [])
    return HostInfo(
        host_id=str(data.get("host_id", "")),
        protocols=tuple(str(p) for p in data.get("protocols") or []),
        features=features,
        lineage=str(data.get("lineage", "")),
        mode=str(data.get("mode", "")),
        network_modes=frozenset(str(m) for m in capabilities.get("network_modes") or []),
        secret_injection=bool(capabilities.get("secret_injection", False)),
        acceptance_horizon_ms=number(parameters, "acceptance_horizon_ms"),
        clock_skew_tolerance_ms=number(parameters, "clock_skew_tolerance_ms"),
        operation_retention_ms=number(parameters, "operation_retention_ms"),
        wait_max_ms=number(parameters, "wait_max_ms"),
        max_request_bytes=number(parameters, "max_request_bytes"),
        lifetime_default_secs=number(parameters, "sandbox_lifetime_default_secs"),
        lifetime_max_secs=number(parameters, "sandbox_lifetime_max_secs"),
        max_vcpus=number(ceilings, "max_vcpus"),
        max_memory_mib=number(ceilings, "max_memory_mib"),
        max_disk_mib=number(ceilings, "max_disk_mib"),
        max_runtime_ms=number(ceilings, "max_runtime_ms"),
        max_allowlist_entries=number(ceilings, "max_allowlist_entries"),
        identifier_slots=optional(capabilities, "identifier_slots"),
        peer_id=data.get("peer_id") if isinstance(data.get("peer_id"), str) else None,
        role=data.get("role") if isinstance(data.get("role"), str) else None,
        time_ms=optional(data, "time_ms"),
        ops_per_minute=optional(parameters, "operations_per_minute"),
        reads_per_minute=optional(parameters, "reads_per_minute"),
        forgetting_floor_ms=optional(data, "forgetting_floor_ms"),
        create_with_start="create_with_start" in features,
    )


class HostBinding(Protocol):
    """The port. One per host. Placement across hosts is not behind this port."""

    @property
    def host_id(self) -> str: ...

    async def submit(
        self, request: HostRequest, *, lane: Lane, principal_id: str | None = None
    ) -> HostOperation | HostRefusal:
        """One attempt at a mutation. Raises ``Unreachable`` or ``LostAnswer``."""
        ...

    async def read(
        self, request: HostRequest, *, lane: Lane, principal_id: str | None = None
    ) -> HostResult | HostRefusal:
        """One read. Never a submission."""
        ...

    async def info(self) -> HostInfo:
        """``host.info``, read now."""
        ...

    async def aclose(self) -> None: ...


def tls_context(*, trust_anchors: Path, certificate: Path, private_key: Path) -> ssl.SSLContext:
    """The client side of mutual TLS 1.3, trusting the configured anchors and nothing else."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    # Deliberately no load_default_certs(): a certificate only the system store trusts is not the host's.
    context.load_verify_locations(cafile=str(trust_anchors))
    context.load_cert_chain(str(certificate), str(private_key))
    return context


class _Connection:
    """One connection to the host: one exchange at a time, discarded on its first failure."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer

    def usable(self) -> bool:
        return not self.writer.is_closing() and not self.reader.at_eof()

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.writer.close()

    async def exchange(self, payload: bytes, timeout_s: float) -> bytes:
        frame = _HEADER.pack(len(payload)) + payload
        try:
            self.writer.write(frame)
            await self.writer.drain()
            header = await asyncio.wait_for(self.reader.readexactly(_HEADER.size), timeout_s)
            (length,) = _HEADER.unpack(header)
            if length > MAX_RESPONSE_BYTES:
                raise LostAnswer("the host announced an oversize response")
            return await asyncio.wait_for(self.reader.readexactly(length), timeout_s)
        except LostAnswer:
            self.close()
            raise
        except (OSError, TimeoutError, asyncio.IncompleteReadError, ssl.SSLError) as e:
            self.close()
            raise LostAnswer(f"no answer from the host: {type(e).__name__}") from e
        except BaseException:
            self.close()
            raise


class _Class:
    """One class of connections: a bound, and the idle connections of that class."""

    def __init__(self, size: int) -> None:
        self.size = size
        self.slots = asyncio.Semaphore(size)
        self.idle: deque[_Connection] = deque()
        self.in_use = 0


class MtlsHostBinding:
    """The binding over mutual TLS. Constructed once per core; shared by every request."""

    def __init__(
        self,
        *,
        address: str,
        host_id: str,
        context: ssl.SSLContext,
        max_connections: int,
        reserved_containment: int,
        reserved_resolution: int,
        connect_timeout_s: float,
        read_timeout_s: float,
    ) -> None:
        host, _, port = address.rpartition(":")
        self._host = host.strip("[]")
        self._port = int(port)
        self._host_id = host_id
        self._context = context
        self._connect_timeout_s = connect_timeout_s
        self._read_timeout_s = read_timeout_s
        general = max_connections - reserved_containment - reserved_resolution
        self._classes = {
            Lane.GENERAL: _Class(general),
            Lane.CONTAINMENT: _Class(reserved_containment),
            Lane.RESOLUTION: _Class(reserved_resolution),
        }
        #: No principal may occupy more than half of the general class at one time.
        self._per_principal = max(1, general // 2)
        self._by_principal: dict[str, asyncio.Semaphore] = {}
        self.max_request_bytes = DEFAULT_MAX_REQUEST_BYTES
        self._closed = False

    @property
    def host_id(self) -> str:
        return self._host_id

    def in_use(self) -> dict[str, int]:
        return {lane.value: cls.in_use for lane, cls in self._classes.items()}

    # ------------------------------------------------------------------ connections
    async def _open(self) -> _Connection:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self._host, self._port, ssl=self._context, server_hostname=self._host_id),
                self._connect_timeout_s,
            )
        except ssl.SSLCertVerificationError as e:
            raise wire.HostIdentityError(
                f"the endpoint did not prove it is host {self._host_id}: {e.verify_message}"
            ) from e
        except (OSError, TimeoutError, ssl.SSLError) as e:
            raise Unreachable(f"the host could not be reached: {type(e).__name__}") from e
        return _Connection(reader, writer)

    @contextlib.asynccontextmanager
    async def _lease(self, lane: Lane, principal_id: str | None) -> AsyncIterator[_Connection]:
        cls = self._classes[lane]
        share = None
        if lane is Lane.GENERAL and principal_id is not None:
            share = self._by_principal.setdefault(principal_id, asyncio.Semaphore(self._per_principal))
            await share.acquire()
        try:
            async with cls.slots:
                cls.in_use += 1
                connection: _Connection | None = None
                try:
                    while cls.idle:
                        candidate = cls.idle.pop()
                        if candidate.usable():
                            connection = candidate
                            break
                        candidate.close()
                    if connection is None:
                        connection = await self._open()
                    yield connection
                    if connection.usable() and not self._closed:
                        cls.idle.append(connection)
                    else:
                        connection.close()
                except BaseException:
                    if connection is not None:
                        connection.close()
                    raise
                finally:
                    cls.in_use -= 1
        finally:
            if share is not None:
                share.release()

    async def _exchange(self, request: HostRequest, lane: Lane, principal_id: str | None) -> HostAnswer:
        payload = request.encode()
        if len(payload) > self.max_request_bytes:
            raise RequestTooLarge(len(payload), self.max_request_bytes)
        async with self._lease(lane, principal_id) as connection:
            raw = await connection.exchange(payload, self._read_timeout_s)
        try:
            return wire.decode_answer(raw)
        except (ValueError, RecursionError) as e:
            # The host answered something the platform cannot read: not an envelope, or one nested so deep
            # that the parser gives up. Whether the host acted is not known, and that is all that is said.
            raise LostAnswer("the host's answer could not be decoded") from e

    # ------------------------------------------------------------------ the port
    async def submit(
        self, request: HostRequest, *, lane: Lane, principal_id: str | None = None
    ) -> HostOperation | HostRefusal:
        if request.method not in wire.MUTATING_METHODS:
            msg = f"{request.method} is not a mutation the platform may send"
            raise ValueError(msg)
        answer = await self._exchange(request, lane, principal_id)
        if isinstance(answer, HostResult):
            raise LostAnswer("the host answered a mutation with a read result")
        return answer

    async def read(
        self, request: HostRequest, *, lane: Lane, principal_id: str | None = None
    ) -> HostResult | HostRefusal:
        if request.method not in wire.READ_METHODS:
            msg = f"{request.method} is not a read the platform may send"
            raise ValueError(msg)
        try:
            answer = await self._exchange(request, lane, principal_id)
        except LostAnswer as e:
            # A read changes nothing, so a lost answer to it is only "not answered".
            raise Unreachable(str(e)) from e
        if isinstance(answer, HostOperation):
            raise Unreachable("the host answered a read with an operation")
        return answer

    async def info(self) -> HostInfo:
        answer = await self.read(HostRequest(method="host.info", owner_scope="acf-platform"), lane=Lane.RESOLUTION)
        if isinstance(answer, HostRefusal):
            raise HostRefused(answer)
        try:
            info = parse_host_info(answer.data)
        except ValueError as e:
            raise Unreachable(f"host.info could not be read: {e}") from e
        self.max_request_bytes = info.max_request_bytes
        return info

    async def aclose(self) -> None:
        self._closed = True
        for cls in self._classes.values():
            while cls.idle:
                cls.idle.pop().close()
        await asyncio.sleep(0)


class HostRefused(Exception):
    """The host refused a request of the platform's own (``host.info``)."""

    def __init__(self, refusal: HostRefusal) -> None:
        super().__init__(refusal.failure_class)
        self.refusal = refusal
