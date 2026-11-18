"""The transports: a real Unix socket, and mutual TLS 1.3 against a real TLS peer.

The one fact every layer above relies on is established here: after a failed exchange, *did the
request reach the host?* ``HostUnreachable`` means no; ``ResponseLost`` means it was written and no
usable answer came back.

The TLS tests build a throwaway authority with the ``openssl`` command-line tool and talk to a TLS
server run in this process, so the client's verification and its handling of a refused client
certificate are exercised without the host. They are skipped where ``openssl`` is not installed;
the end-to-end suite covers mutual TLS against the real host either way.
"""

from __future__ import annotations

import contextlib
import errno
import shutil
import socket
import ssl
import struct
import subprocess
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from acf_cli import framing, transport
from acf_cli.errors import ExitCode, HostUnreachable, InvalidArgument, ProtocolViolation, ResponseLost
from acf_cli.transport import Connection, TlsEndpoint, UnixEndpoint, tls_context
from support import (
    ClosedBeforeRead,
    Echo,
    Lost,
    RawAfterRead,
    SayThenClose,
    ScriptedHost,
    Stall,
    read_frame,
    send_frame,
)

HostFactory = Callable[..., ScriptedHost]


def pong(request: bytes) -> bytes:
    return b"pong:" + request


def unix(path: Path, **limits: int) -> Connection:
    return Connection(UnixEndpoint(path), connect_timeout_s=2.0, **limits)


def wait_until(condition: Callable[[], bool], what: str) -> None:
    deadline = time.monotonic() + 5.0
    while not condition():
        assert time.monotonic() < deadline, f"timed out waiting until {what}"
        time.sleep(0.01)


# ----------------------------------------------------------------------------- one exchange
def test_one_exchange_is_one_frame_out_and_one_frame_back(host_factory: HostFactory, socket_path: Path) -> None:
    host = host_factory(Echo(pong))
    connection = unix(socket_path)
    assert connection.exchange(b'{"hello": "world"}', read_timeout_s=2.0) == b'pong:{"hello": "world"}'
    connection.close()
    wait_until(lambda: host.frames == [b'{"hello": "world"}'], "the host saw the request frame")


def test_a_connection_carries_many_turns(host_factory: HostFactory, socket_path: Path) -> None:
    host = host_factory(Echo(pong, turns=3))
    connection = unix(socket_path)
    answers = [connection.exchange(f"turn-{i}".encode(), read_timeout_s=2.0) for i in range(3)]
    connection.close()
    assert answers == [b"pong:turn-0", b"pong:turn-1", b"pong:turn-2"]
    assert host.connections == 1, "one connection, three turns"


def test_binary_and_large_payloads_survive_exactly(host_factory: HostFactory, socket_path: Path) -> None:
    host_factory(Echo(lambda request: request[::-1]))
    payload = bytes(range(256)) * 4096  # 1 MiB
    connection = unix(socket_path)
    assert connection.exchange(payload, read_timeout_s=5.0) == payload[::-1]
    connection.close()


def test_a_long_socket_path_is_reached_through_a_directory_descriptor(tmp_path: Path) -> None:
    deep = tmp_path
    while len(str(deep)) < 130:
        deep /= "a-deliberately-long-directory-name"
    deep.mkdir(parents=True)
    path = deep / "acf.sock"
    assert len(str(path)) > 107, "longer than a sockaddr_un can hold"
    host = ScriptedHost(path, [Echo(pong)])
    host.start()
    try:
        assert unix(path).exchange(b"x", read_timeout_s=2.0) == b"pong:x"
    finally:
        host.stop()
    host.assert_clean()


# ----------------------------------------------------------------------------- a kept connection that went away
def test_a_connection_the_host_closed_while_idle_is_replaced_before_it_is_used(
    host_factory: HostFactory, socket_path: Path
) -> None:
    host = host_factory(Echo(pong), Echo(pong))  # each connection serves one turn, then the host closes it
    connection = unix(socket_path)
    assert connection.exchange(b"one", read_timeout_s=2.0) == b"pong:one"
    kept = connection._sock
    assert kept is not None
    wait_until(lambda: transport._has_pending_input(kept), "the host's close arrived")
    assert connection.exchange(b"two", read_timeout_s=2.0) == b"pong:two"
    connection.close()
    assert host.connections == 2
    wait_until(lambda: host.frames == [b"one", b"two"], "each request reached the host exactly once")


def test_a_send_that_fails_on_a_kept_connection_is_made_again_on_a_new_one(
    host_factory: HostFactory, socket_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The frame did not get through, so sending it on a new connection is not a repeat."""
    host = host_factory(Echo(pong), Echo(pong))
    connection = unix(socket_path)
    assert connection.exchange(b"one", read_timeout_s=2.0) == b"pong:one"
    kept = connection._sock
    assert kept is not None
    wait_until(lambda: transport._has_pending_input(kept), "the host's close arrived")
    monkeypatch.setattr(transport, "_has_pending_input", lambda _sock: False)  # the close went unnoticed
    assert connection.exchange(b"two", read_timeout_s=2.0) == b"pong:two"
    connection.close()
    wait_until(lambda: host.frames == [b"one", b"two"], "the second request reached the host exactly once")


# ----------------------------------------------------------------------------- the request was written; no answer
def test_a_host_that_reads_the_request_and_hangs_up_lost_the_response(
    host_factory: HostFactory, socket_path: Path
) -> None:
    host = host_factory(Lost(), Echo(pong))
    connection = unix(socket_path)
    with pytest.raises(ResponseLost, match="closed the connection without answering") as caught:
        connection.exchange(b"request", read_timeout_s=2.0)
    assert caught.value.exit_code is ExitCode.TRANSPORT
    assert connection._sock is None, "a failed connection is never reused"
    assert connection.exchange(b"again", read_timeout_s=2.0) == b"pong:again"
    connection.close()
    assert host.connections == 2


def test_an_answer_cut_short_is_a_lost_response(host_factory: HostFactory, socket_path: Path) -> None:
    host_factory(RawAfterRead(struct.pack(">I", 100) + b"only-part"))
    with pytest.raises(ResponseLost, match="in the middle of its answer"):
        unix(socket_path).exchange(b"request", read_timeout_s=2.0)


def test_a_host_that_does_not_answer_in_time_lost_the_response(host_factory: HostFactory, socket_path: Path) -> None:
    host_factory(Stall(1.0))
    started = time.monotonic()
    with pytest.raises(ResponseLost, match="did not answer within"):
        unix(socket_path).exchange(b"request", read_timeout_s=0.2)
    assert time.monotonic() - started < 0.9, "the read timeout fired, not the host"


# ----------------------------------------------------------------------------- bounds
def test_an_oversize_response_is_refused_before_its_payload_is_read(
    host_factory: HostFactory, socket_path: Path
) -> None:
    host_factory(RawAfterRead(struct.pack(">I", 10_000) + b"x" * 10_000))
    with pytest.raises(ProtocolViolation, match="oversize response") as caught:
        unix(socket_path, max_response_bytes=1024).exchange(b"request", read_timeout_s=2.0)
    assert caught.value.exit_code is ExitCode.PROTOCOL


def test_a_request_over_the_limit_is_a_usage_error_and_nothing_is_sent(
    host_factory: HostFactory, socket_path: Path
) -> None:
    host = host_factory()
    connection = unix(socket_path, max_request_bytes=16)
    with pytest.raises(InvalidArgument, match="at most 16 bytes"):
        connection.exchange(b"x" * 17, read_timeout_s=2.0)
    assert connection._sock is None
    assert host.connections == 0, "not even a connection was made"


def test_the_response_bound_cannot_be_configured_away(host_factory: HostFactory, socket_path: Path) -> None:
    host_factory(RawAfterRead(struct.pack(">I", 64 * 1024 * 1024 + 1)))
    with pytest.raises(ProtocolViolation):
        unix(socket_path, max_response_bytes=1 << 62).exchange(b"request", read_timeout_s=2.0)


# ----------------------------------------------------------------------------- the request did not reach the host
def test_no_socket_is_unreachable_with_a_hint(socket_path: Path) -> None:
    with pytest.raises(HostUnreachable, match="no host agent socket") as caught:
        unix(socket_path).exchange(b"request", read_timeout_s=1.0)
    assert caught.value.exit_code is ExitCode.TRANSPORT
    assert "--socket" in (caught.value.hint or "")


def test_a_stale_socket_file_is_unreachable(socket_path: Path) -> None:
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.close()  # the file stays; nobody listens
    with pytest.raises(HostUnreachable, match="nothing is listening"):
        unix(socket_path).exchange(b"request", read_timeout_s=1.0)


def test_a_socket_this_user_may_not_open_is_unreachable(host_factory: HostFactory, socket_path: Path) -> None:
    host_factory()
    socket_path.chmod(0o000)
    try:
        with contextlib.closing(socket.socket(socket.AF_UNIX)) as probe:
            try:
                probe.connect(str(socket_path))
            except PermissionError:
                pass
            else:
                pytest.skip("this user can open any socket (running as root)")
        with pytest.raises(HostUnreachable, match="permission denied"):
            unix(socket_path).exchange(b"request", read_timeout_s=1.0)
    finally:
        socket_path.chmod(0o600)


def test_what_the_host_said_before_it_stopped_reading_is_the_answer(
    host_factory: HostFactory, socket_path: Path
) -> None:
    """An unenrolled peer is refused at accept time: the host writes a refusal and closes without reading."""
    host_factory(SayThenClose(b'{"answer":"REFUSED"}'))
    assert unix(socket_path).exchange(b"request", read_timeout_s=2.0) == b'{"answer":"REFUSED"}'


def test_a_host_that_hangs_up_without_reading_did_not_act(host_factory: HostFactory, socket_path: Path) -> None:
    """Whether the hang-up is seen while writing or while reading depends on timing; both say "no answer"."""
    host_factory(ClosedBeforeRead())
    with pytest.raises((HostUnreachable, ResponseLost)):
        unix(socket_path).exchange(b"request", read_timeout_s=2.0)


def test_closing_twice_is_harmless(socket_path: Path) -> None:
    connection = unix(socket_path)
    connection.close()
    connection.close()


def test_endpoints_describe_themselves_without_credentials() -> None:
    assert str(UnixEndpoint(Path("/run/acf/host-agent.sock"))) == "unix:/run/acf/host-agent.sock"
    endpoint = TlsEndpoint("host-1.example", 7443, Path("/secret/client.crt"), Path("/secret/client.key"))
    assert str(endpoint) == "tls://host-1.example:7443"


# ----------------------------------------------------------------------------- mutual TLS
@dataclass(frozen=True)
class Pki:
    """A throwaway authority, a server certificate for localhost, and client certificates."""

    ca: Path
    server_cert: Path
    server_key: Path
    client_cert: Path
    client_key: Path
    encrypted_key: Path
    #: A second authority the server does not trust, and a client certificate it signed.
    other_ca: Path
    other_client_cert: Path
    other_client_key: Path


def _openssl(*args: str, cwd: Path) -> None:
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True, timeout=60)


def _authority(d: Path, name: str) -> None:
    _openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2",
             "-subj", f"/CN={name}", "-keyout", f"{name}.key", "-out", f"{name}.crt", cwd=d)  # fmt: skip


def _leaf(d: Path, name: str, authority: str, extensions: str) -> None:
    (d / f"{name}.ext").write_text(extensions, encoding="utf-8")
    _openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
             "-subj", f"/CN={name}", "-keyout", f"{name}.key", "-out", f"{name}.csr", cwd=d)  # fmt: skip
    _openssl("x509", "-req", "-in", f"{name}.csr", "-CA", f"{authority}.crt", "-CAkey", f"{authority}.key",
             "-CAcreateserial", "-days", "2", "-extfile", f"{name}.ext", "-out", f"{name}.crt", cwd=d)  # fmt: skip


@pytest.fixture(scope="session")
def pki(tmp_path_factory: pytest.TempPathFactory) -> Pki:
    if shutil.which("openssl") is None:
        pytest.skip("the openssl command-line tool is not installed")
    d = tmp_path_factory.mktemp("pki")
    _authority(d, "ca")
    _authority(d, "other-ca")
    _leaf(d, "server", "ca", "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")
    _leaf(d, "client", "ca", "extendedKeyUsage=clientAuth\n")
    _leaf(d, "other-client", "other-ca", "extendedKeyUsage=clientAuth\n")
    _openssl(
        "pkey", "-in", "client.key", "-aes256", "-passout", "pass:not-a-real-passphrase", "-out", "locked.key", cwd=d
    )
    return Pki(
        ca=d / "ca.crt",
        server_cert=d / "server.crt",
        server_key=d / "server.key",
        client_cert=d / "client.crt",
        client_key=d / "client.key",
        encrypted_key=d / "locked.key",
        other_ca=d / "other-ca.crt",
        other_client_cert=d / "other-client.crt",
        other_client_key=d / "other-client.key",
    )


class TlsPeer:
    """A TLS server in this process that requires a client certificate and echoes one frame per connection."""

    def __init__(self, pki: Pki, *, maximum: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.maximum_version = maximum
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=str(pki.ca))
        context.load_cert_chain(str(pki.server_cert), str(pki.server_key))
        self._context = context
        self._listener = socket.create_server(("127.0.0.1", 0))
        self._listener.settimeout(0.05)
        self.port: int = self._listener.getsockname()[1]
        self.versions: list[str | None] = []
        self.frames: list[bytes] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                raw, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with raw, contextlib.suppress(OSError):
                raw.settimeout(5)
                with self._context.wrap_socket(raw, server_side=True) as conn:
                    self.versions.append(conn.version())
                    frame = read_frame(conn)
                    if frame is not None:
                        self.frames.append(frame)
                        send_frame(conn, pong(frame))

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)
        self._listener.close()


@pytest.fixture
def tls_peer(pki: Pki) -> Iterator[TlsPeer]:
    peer = TlsPeer(pki)
    yield peer
    peer.stop()


def mutual(pki: Pki, port: int, **over: object) -> TlsEndpoint:
    fields: dict[str, object] = {
        "host": "127.0.0.1",
        "port": port,
        "certificate": pki.client_cert,
        "private_key": pki.client_key,
        "trust_anchors": pki.ca,
        "server_name": None,
    }
    fields.update(over)
    return TlsEndpoint(**fields)  # type: ignore[arg-type]


def test_the_context_is_tls_1_3_only_and_verifies_the_host(pki: Pki) -> None:
    context = tls_context(mutual(pki, 1))
    assert context.minimum_version is ssl.TLSVersion.TLSv1_3
    assert context.maximum_version is ssl.TLSVersion.TLSv1_3
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_given_trust_anchors_are_the_only_ones_and_the_system_store_is_not_used(pki: Pki) -> None:
    assert tls_context(mutual(pki, 1)).cert_store_stats() == {"x509": 1, "crl": 0, "x509_ca": 1}


def test_without_trust_anchors_the_system_store_is_used(pki: Pki, monkeypatch: pytest.MonkeyPatch) -> None:
    loaded: list[str] = []
    monkeypatch.setattr(ssl.SSLContext, "load_default_certs", lambda _self: loaded.append("system"))
    monkeypatch.setattr(ssl.SSLContext, "load_verify_locations", lambda _self, **_kw: loaded.append("explicit"))
    tls_context(mutual(pki, 1, trust_anchors=None))
    assert loaded == ["system"]
    loaded.clear()
    tls_context(mutual(pki, 1))
    assert loaded == ["explicit"]


def test_mutual_tls_carries_frames_and_negotiates_1_3(pki: Pki, tls_peer: TlsPeer) -> None:
    connection = Connection(mutual(pki, tls_peer.port), connect_timeout_s=5.0)
    assert connection.exchange(b"over tls", read_timeout_s=5.0) == b"pong:over tls"
    connection.close()
    assert tls_peer.versions == ["TLSv1.3"]
    assert tls_peer.frames == [b"over tls"]


def test_the_server_name_can_be_given_separately_from_the_address(pki: Pki, tls_peer: TlsPeer) -> None:
    connection = Connection(mutual(pki, tls_peer.port, server_name="localhost"), connect_timeout_s=5.0)
    assert connection.exchange(b"x", read_timeout_s=5.0) == b"pong:x"
    connection.close()


def test_a_host_certificate_from_another_authority_is_not_accepted(pki: Pki, tls_peer: TlsPeer) -> None:
    connection = Connection(mutual(pki, tls_peer.port, trust_anchors=pki.other_ca), connect_timeout_s=5.0)
    with pytest.raises(HostUnreachable, match="was not accepted") as caught:
        connection.exchange(b"request", read_timeout_s=5.0)
    assert "--ca" in (caught.value.hint or "")
    assert tls_peer.frames == [], "the request was never sent"


def test_a_host_certificate_for_another_name_is_not_accepted(pki: Pki, tls_peer: TlsPeer) -> None:
    connection = Connection(mutual(pki, tls_peer.port, server_name="another-host.example"), connect_timeout_s=5.0)
    with pytest.raises(HostUnreachable, match="was not accepted"):
        connection.exchange(b"request", read_timeout_s=5.0)
    assert tls_peer.frames == []


def test_a_client_certificate_the_host_does_not_trust_means_the_request_was_not_read(
    pki: Pki, tls_peer: TlsPeer
) -> None:
    """With TLS 1.3 the refusal arrives after the client's handshake: it must still read as "nothing was sent"."""
    endpoint = mutual(pki, tls_peer.port, certificate=pki.other_client_cert, private_key=pki.other_client_key)
    connection = Connection(endpoint, connect_timeout_s=5.0)
    with pytest.raises(HostUnreachable, match="did not accept this client's certificate") as caught:
        connection.exchange(b"request", read_timeout_s=5.0)
    assert caught.value.exit_code is ExitCode.TRANSPORT
    assert "enrolled" in (caught.value.hint or "")
    assert tls_peer.frames == []


def test_a_peer_that_cannot_speak_tls_1_3_is_not_talked_to(pki: Pki) -> None:
    peer = TlsPeer(pki, maximum=ssl.TLSVersion.TLSv1_2)
    try:
        with pytest.raises(HostUnreachable, match="TLS handshake"):
            Connection(mutual(pki, peer.port), connect_timeout_s=5.0).exchange(b"request", read_timeout_s=5.0)
        assert peer.frames == []
    finally:
        peer.stop()


def test_nothing_listening_on_the_tls_address_is_unreachable(pki: Pki) -> None:
    with contextlib.closing(socket.create_server(("127.0.0.1", 0))) as placeholder:
        port: int = placeholder.getsockname()[1]
    with pytest.raises(HostUnreachable, match=r"cannot connect to tls://127\.0\.0\.1"):
        Connection(mutual(pki, port), connect_timeout_s=2.0).exchange(b"request", read_timeout_s=2.0)


def test_unusable_credential_files_are_usage_errors_that_show_no_key_material(pki: Pki, tmp_path: Path) -> None:
    garbage = tmp_path / "garbage.pem"
    garbage.write_text("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n", encoding="utf-8")
    cases = [
        (mutual(pki, 1, certificate=tmp_path / "missing.crt"), "client certificate"),
        (
            mutual(pki, 1, private_key=pki.other_client_key),
            "client certificate",
        ),  # a key that is not this certificate's
        (mutual(pki, 1, trust_anchors=garbage), "trust anchors"),
        (mutual(pki, 1, trust_anchors=tmp_path / "missing-ca.crt"), "trust anchors"),
    ]
    for endpoint, what in cases:
        with pytest.raises(InvalidArgument, match=what) as caught:
            tls_context(endpoint)
        assert "PRIVATE KEY" not in f"{caught.value.message}{caught.value.hint}"


def test_an_encrypted_key_is_refused_without_prompting(pki: Pki) -> None:
    with pytest.raises(InvalidArgument, match="is encrypted") as caught:
        tls_context(mutual(pki, 1, private_key=pki.encrypted_key))
    assert "passphrase" in caught.value.message


# ----------------------------------------------------------------------------- a send that fails
class Stream:
    """A stream in the state a test needs, standing in for a socket."""

    def __init__(self, incoming: list[bytes | BaseException], *, send_fails: bool = False) -> None:
        self._incoming = incoming
        self._send_fails = send_fails
        self.sent: list[bytes] = []
        self.closed = False

    def settimeout(self, _seconds: float) -> None:
        return

    def sendall(self, data: bytes) -> None:
        if self._send_fails:
            raise BrokenPipeError(errno.EPIPE, "Broken pipe")
        self.sent.append(data)

    def recv(self, bufsize: int, /) -> bytes:
        if not self._incoming:
            return b""
        head = self._incoming[0]
        if isinstance(head, BaseException):
            self._incoming.pop(0)
            raise head
        chunk, rest = head[:bufsize], head[bufsize:]
        if rest:
            self._incoming[0] = rest
        else:
            self._incoming.pop(0)
        return chunk

    def close(self) -> None:
        self.closed = True


def alert(reason: str) -> ssl.SSLError:
    error = ssl.SSLError(1, f"[SSL: {reason}] alert")
    error.reason = reason
    return error


def connected_to(stream: Stream, monkeypatch: pytest.MonkeyPatch) -> Connection:
    monkeypatch.setattr(transport, "connect", lambda _endpoint, _timeout: stream)
    monkeypatch.setattr(transport, "_has_pending_input", lambda _sock: False)
    return unix(Path("/run/acf/host-agent.sock"))


def test_when_the_send_fails_what_the_host_wrote_before_it_stopped_reading_is_still_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = Stream([framing.encode_frame(b'{"answer":"REFUSED"}', 1024)], send_fails=True)
    assert connected_to(stream, monkeypatch).exchange(b"request", read_timeout_s=1.0) == b'{"answer":"REFUSED"}'
    assert stream.closed, "the connection is not kept after a failed send"


def test_a_send_that_fails_with_nothing_to_read_did_not_reach_the_host(monkeypatch: pytest.MonkeyPatch) -> None:
    for incoming in ([], [b"\x00\x00"], [ConnectionResetError(errno.ECONNRESET, "Connection reset by peer")]):
        stream = Stream(list(incoming), send_fails=True)
        with pytest.raises(HostUnreachable, match="could not deliver the request") as caught:
            connected_to(stream, monkeypatch).exchange(b"request", read_timeout_s=1.0)
        assert "the host did not act on it" in caught.value.message
        assert stream.closed


def test_a_send_that_fails_because_the_host_refused_the_certificate_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    stream = Stream([alert("TLSV13_ALERT_CERTIFICATE_REQUIRED")], send_fails=True)
    with pytest.raises(HostUnreachable, match="did not accept this client's certificate"):
        connected_to(stream, monkeypatch).exchange(b"request", read_timeout_s=1.0)


@pytest.mark.parametrize(
    "reason",
    [
        "TLSV13_ALERT_CERTIFICATE_REQUIRED",
        "TLSV1_ALERT_UNKNOWN_CA",
        "SSLV3_ALERT_BAD_CERTIFICATE",
        "TLSV1_ALERT_ACCESS_DENIED",
    ],
)
def test_a_certificate_alert_on_the_first_read_means_the_request_was_not_read(
    monkeypatch: pytest.MonkeyPatch, reason: str
) -> None:
    stream = Stream([alert(reason)])
    with pytest.raises(HostUnreachable, match="did not accept this client's certificate"):
        connected_to(stream, monkeypatch).exchange(b"request", read_timeout_s=1.0)
    assert stream.closed


def test_any_other_tls_failure_after_the_request_was_written_is_a_lost_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = Stream([alert("SSLV3_ALERT_BAD_RECORD_MAC")])
    with pytest.raises(ResponseLost, match="failed while waiting for the answer"):
        connected_to(stream, monkeypatch).exchange(b"request", read_timeout_s=1.0)


def test_a_certificate_alert_on_a_connection_that_already_answered_is_a_lost_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only on a fresh connection does such an alert prove that nothing was read."""
    stream = Stream([framing.encode_frame(b"first", 1024), alert("TLSV13_ALERT_CERTIFICATE_REQUIRED")])
    connection = connected_to(stream, monkeypatch)
    assert connection.exchange(b"one", read_timeout_s=1.0) == b"first"
    with pytest.raises(ResponseLost):
        connection.exchange(b"two", read_timeout_s=1.0)


def test_a_connection_error_while_waiting_is_a_lost_response(monkeypatch: pytest.MonkeyPatch) -> None:
    stream = Stream([ConnectionResetError(errno.ECONNRESET, "Connection reset by peer")])
    with pytest.raises(ResponseLost, match="Connection reset by peer"):
        connected_to(stream, monkeypatch).exchange(b"request", read_timeout_s=1.0)


def test_a_socket_path_that_cannot_be_one_is_unreachable(tmp_path: Path) -> None:
    not_a_directory = tmp_path / "file"
    not_a_directory.write_text("x", encoding="utf-8")
    with pytest.raises(HostUnreachable, match="cannot connect to"):
        unix(not_a_directory / "acf.sock").exchange(b"request", read_timeout_s=1.0)


def test_a_peer_that_is_not_tls_at_all_is_unreachable(pki: Pki) -> None:
    with contextlib.closing(socket.create_server(("127.0.0.1", 0))) as listener:
        listener.settimeout(5)
        port: int = listener.getsockname()[1]

        def hang_up() -> None:
            with contextlib.suppress(OSError):
                conn, _ = listener.accept()
                conn.close()

        thread = threading.Thread(target=hang_up, daemon=True)
        thread.start()
        with pytest.raises(HostUnreachable, match="TLS handshake"):
            Connection(mutual(pki, port), connect_timeout_s=5.0).exchange(b"request", read_timeout_s=5.0)
        thread.join(timeout=5)
