"""Transports: the host's local Unix socket and its mutual TLS 1.3 endpoint.

Both carry the same thing: length-delimited JSON frames, one request frame answered by one
response frame, any number of turns per connection. Nothing above this module knows which one is
in use.

What this module decides, and what everything above it relies on, is a single fact about a failed
exchange — **did the request reach the host?**

* :class:`~acf_cli.errors.HostUnreachable`: no. Connecting, authenticating or writing the frame
  failed. The host acts only on complete frames, so it did not act.
* :class:`~acf_cli.errors.ResponseLost`: the frame was written and no usable answer came back. The
  host may have acted.

Bounds: a frame larger than the configured maximum is never sent, and a response that announces
more than the configured maximum is refused before any of its payload is read.

Mutual TLS: protocol version pinned to 1.3 on both ends of the range, the host's certificate
verified against the given trust anchors (the system trust store is used only when none are given)
and against the server name, and a client certificate always presented. Nothing here reads, logs or
prints key material; the key file is handed to the TLS library by path.
"""

from __future__ import annotations

import contextlib
import os
import select
import socket
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from acf_cli.errors import HostUnreachable, InvalidArgument, ProtocolViolation, ResponseLost
from acf_cli.framing import (
    MAX_FRAME_HARD_CAP,
    FrameEof,
    FrameError,
    FrameTooLarge,
    FrameTruncated,
    encode_frame,
    read_frame,
)

DEFAULT_SOCKET = "/run/acf/host-agent.sock"
#: The host's default bound on one request frame. The host remains the authority (``host info``
#: reports its ``max_request_bytes``); this is only the most this client will try to send.
DEFAULT_MAX_REQUEST_BYTES = 1024 * 1024
#: The largest response frame a host ever sends. The announced length is checked before the payload
#: is read, so the bound is on memory this process chooses to commit, not on what a peer claims.
DEFAULT_MAX_RESPONSE_BYTES = MAX_FRAME_HARD_CAP
#: ``sun_path`` is 108 bytes on Linux, one of which is the terminating NUL; stay clear of it.
_SUN_PATH_SAFE = 100
#: How long to look for an answer the host wrote before it stopped reading (an authentication refusal).
_EARLY_ANSWER_TIMEOUT_S = 2.0
#: Fatal alerts a host sends when it does not accept the client's certificate. With TLS 1.3 they
#: arrive after the client's side of the handshake has completed, on the first read.
_CREDENTIAL_ALERTS = ("CERTIFICATE", "UNKNOWN_CA", "ACCESS_DENIED", "DECRYPT_ERROR", "HANDSHAKE_FAILURE")


@dataclass(frozen=True, slots=True)
class UnixEndpoint:
    """The local endpoint. The host identifies the caller by the credentials the kernel reports."""

    path: Path

    def __str__(self) -> str:
        return f"unix:{self.path}"


@dataclass(frozen=True, slots=True)
class TlsEndpoint:
    """The network endpoint. The host identifies the caller by its enrolled client certificate."""

    host: str
    port: int
    certificate: Path
    private_key: Path
    #: PEM file of the authorities trusted to sign the host's certificate. ``None``: the system trust store.
    trust_anchors: Path | None = None
    #: Name the host's certificate must be valid for. ``None``: ``host``.
    server_name: str | None = None

    def __str__(self) -> str:
        return f"tls://{self.host}:{self.port}"


Endpoint = UnixEndpoint | TlsEndpoint


class Exchange(Protocol):
    """All the client needs from a transport."""

    def exchange(self, payload: bytes, *, read_timeout_s: float) -> bytes:
        """Send one request frame and return the payload of the response frame."""
        ...

    def close(self) -> None: ...


# ----------------------------------------------------------------------------- TLS
def _no_passphrase() -> str:
    msg = "the private key is encrypted"
    raise _EncryptedKey(msg)


class _EncryptedKey(Exception):
    """Raised from the passphrase callback: this client never prompts for a passphrase."""


def tls_context(endpoint: TlsEndpoint) -> ssl.SSLContext:
    """The client side of mutual TLS 1.3 for ``endpoint``."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    try:
        if endpoint.trust_anchors is not None:
            context.load_verify_locations(cafile=str(endpoint.trust_anchors))
        else:
            context.load_default_certs()
    except (OSError, ssl.SSLError) as e:
        raise InvalidArgument(
            f"cannot use {endpoint.trust_anchors} as trust anchors: {_reason(e)}",
            hint="--ca must name a PEM file with the certificate of the authority that signed the host's certificate",
        ) from e
    try:
        context.load_cert_chain(str(endpoint.certificate), str(endpoint.private_key), password=_no_passphrase)
    except _EncryptedKey as e:
        raise InvalidArgument(
            f"the private key {endpoint.private_key} is encrypted, and this client does not ask for a passphrase",
            hint="use a key file without a passphrase that only you can read (mode 0600)",
        ) from e
    except (OSError, ssl.SSLError) as e:
        raise InvalidArgument(
            f"cannot use {endpoint.certificate} with key {endpoint.private_key} as a client certificate: {_reason(e)}",
            hint="--cert and --key must name a PEM certificate and its matching PEM private key",
        ) from e
    return context


def _reason(error: OSError) -> str:
    """A short description of an OS or TLS error. Never includes file contents."""
    if isinstance(error, ssl.SSLCertVerificationError):
        return error.verify_message
    if isinstance(error, ssl.SSLError):
        return error.reason or "TLS error"
    return error.strerror or type(error).__name__


def _credential_rejected(error: OSError) -> bool:
    reason = error.reason if isinstance(error, ssl.SSLError) else None
    return reason is not None and "ALERT" in reason and any(word in reason for word in _CREDENTIAL_ALERTS)


def _not_accepted(endpoint: Endpoint, error: ssl.SSLError) -> HostUnreachable:
    return HostUnreachable(
        f"{endpoint} did not accept this client's certificate ({_reason(error)}); the request was not read",
        hint="the certificate must chain to an authority the host trusts for clients, and be enrolled on the host",
    )


def _connect_tls(endpoint: TlsEndpoint, timeout_s: float) -> socket.socket:
    context = tls_context(endpoint)
    try:
        raw = socket.create_connection((endpoint.host, endpoint.port), timeout=timeout_s)
    except OSError as e:
        raise HostUnreachable(
            f"cannot connect to {endpoint}: {_reason(e)}",
            hint="check the address given with --tls and that the host's network endpoint is enabled",
        ) from e
    try:
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return context.wrap_socket(raw, server_hostname=endpoint.server_name or endpoint.host)
    except ssl.SSLCertVerificationError as e:
        raw.close()
        raise HostUnreachable(
            f"the certificate presented by {endpoint} was not accepted: {_reason(e)}",
            hint="--ca must list the authority that signed the host's certificate, and --server-name "
            "(default: the host part of --tls) must be a name the certificate is valid for",
        ) from e
    except ssl.SSLError as e:
        raw.close()
        if _credential_rejected(e):
            raise _not_accepted(endpoint, e) from e
        raise HostUnreachable(
            f"TLS handshake with {endpoint} failed: {_reason(e)}", hint="the host accepts TLS 1.3 only"
        ) from e
    except OSError as e:
        raw.close()
        raise HostUnreachable(f"TLS handshake with {endpoint} failed: {_reason(e)}") from e


# ----------------------------------------------------------------------------- Unix socket
def _connect_unix(endpoint: UnixEndpoint, timeout_s: float) -> socket.socket:
    """Connect to the local socket, working around the 108-byte ``sun_path`` limit for long client paths."""
    path = endpoint.path
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout_s)
    dir_fd: int | None = None
    try:
        target = str(path)
        if len(os.fsencode(path)) >= _SUN_PATH_SAFE:
            # Resolve the final component relative to an open directory descriptor.
            dir_fd = os.open(path.parent, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
            target = f"/proc/self/fd/{dir_fd}/{path.name}"
        sock.connect(target)
    except FileNotFoundError as e:
        sock.close()
        raise HostUnreachable(
            f"no host agent socket at {path}",
            hint="is the host agent running? point the client elsewhere with --socket or $ACF_SOCKET",
        ) from e
    except PermissionError as e:
        sock.close()
        raise HostUnreachable(
            f"permission denied connecting to {path}",
            hint="the socket's mode and group decide who may connect; your user must be allowed by them",
        ) from e
    except ConnectionRefusedError as e:
        sock.close()
        raise HostUnreachable(
            f"nothing is listening on {path}", hint="the host agent is not running (the socket file is stale)"
        ) from e
    except OSError as e:
        sock.close()
        raise HostUnreachable(f"cannot connect to {path}: {_reason(e)}") from e
    finally:
        if dir_fd is not None:
            os.close(dir_fd)
    return sock


def connect(endpoint: Endpoint, timeout_s: float) -> socket.socket:
    """An authenticated stream to ``endpoint``. Raises :class:`HostUnreachable` if there is none to be had."""
    if isinstance(endpoint, TlsEndpoint):
        return _connect_tls(endpoint, timeout_s)
    return _connect_unix(endpoint, timeout_s)


# ----------------------------------------------------------------------------- one connection, many turns
def _has_pending_input(sock: socket.socket) -> bool:
    """Whether anything — data or end of stream — is waiting on a connection that should be idle."""
    if isinstance(sock, ssl.SSLSocket) and sock.pending() > 0:
        return True
    try:
        readable, _, _ = select.select([sock], [], [], 0)
    except (OSError, ValueError):
        return True
    return bool(readable)


class Connection:
    """A connection to the host, opened on first use and kept for the turns that follow.

    It is discarded on the first failure and never reused after one: a response that arrives late
    must not be read as the answer to a later request.
    """

    def __init__(
        self,
        endpoint: Endpoint,
        *,
        connect_timeout_s: float = 5.0,
        max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        self.endpoint = endpoint
        self._connect_timeout_s = connect_timeout_s
        self._max_request_bytes = max_request_bytes
        self._max_response_bytes = max_response_bytes
        self._sock: socket.socket | None = None

    def close(self) -> None:
        sock, self._sock = self._sock, None
        if sock is not None:
            with contextlib.suppress(OSError):
                sock.close()

    def _open(self) -> tuple[socket.socket, bool]:
        """The stream to use and whether it was opened just now."""
        if self._sock is not None:
            if not _has_pending_input(self._sock):
                return self._sock, False
            # The host closed it (idle timeout) or said something nobody asked for: start over.
            self.close()
        self._sock = connect(self.endpoint, self._connect_timeout_s)
        return self._sock, True

    def exchange(self, payload: bytes, *, read_timeout_s: float) -> bytes:
        try:
            frame = encode_frame(payload, self._max_request_bytes)
        except FrameTooLarge as e:
            raise InvalidArgument(
                f"the request is {e.length} bytes; this client sends at most {e.maximum} bytes in one frame",
                hint="shorten the command line or the environment",
            ) from e
        sock, fresh = self._open()
        try:
            sock.settimeout(read_timeout_s)
            sock.sendall(frame)
        except OSError as e:
            if not fresh:
                # A kept connection can have been closed by the host since its last turn. The frame
                # did not get through, so sending it on a new connection is not a repeat.
                self.close()
                return self.exchange(payload, read_timeout_s=read_timeout_s)
            return self._answer_written_before_reading(sock, e)
        return self._read_response(sock, read_timeout_s, fresh=fresh)

    def _answer_written_before_reading(self, sock: socket.socket, send_error: OSError) -> bytes:
        """The send failed, so the host did not act — but it may have said why before it stopped reading."""
        early: bytes | None = None
        try:
            sock.settimeout(_EARLY_ANSWER_TIMEOUT_S)
            early = read_frame(sock, self._max_response_bytes)
        except ssl.SSLError as e:
            if _credential_rejected(e):
                raise _not_accepted(self.endpoint, e) from e
        except (FrameError, OSError):
            early = None
        finally:
            self.close()
        if early is not None:
            return early
        raise HostUnreachable(
            f"could not deliver the request to {self.endpoint} ({_reason(send_error)}); the host did not act on it",
            hint="the host closed the connection before reading the request; check its log",
        ) from send_error

    def _read_response(self, sock: socket.socket, read_timeout_s: float, *, fresh: bool) -> bytes:
        try:
            return read_frame(sock, self._max_response_bytes)
        except FrameTooLarge as e:
            self.close()
            raise ProtocolViolation(f"{self.endpoint} announced an oversize response: {e}") from e
        except FrameEof as e:
            self.close()
            raise ResponseLost(f"{self.endpoint} closed the connection without answering") from e
        except FrameTruncated as e:
            self.close()
            raise ResponseLost(f"{self.endpoint} closed the connection in the middle of its answer") from e
        except TimeoutError as e:
            self.close()
            raise ResponseLost(f"{self.endpoint} did not answer within {read_timeout_s:.0f} s") from e
        except ssl.SSLError as e:
            self.close()
            if fresh and _credential_rejected(e):
                raise _not_accepted(self.endpoint, e) from e
            raise ResponseLost(
                f"the connection to {self.endpoint} failed while waiting for the answer: {_reason(e)}"
            ) from e
        except OSError as e:
            self.close()
            raise ResponseLost(
                f"the connection to {self.endpoint} failed while waiting for the answer: {_reason(e)}"
            ) from e
