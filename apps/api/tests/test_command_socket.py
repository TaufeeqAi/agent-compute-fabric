"""The command interface on its socket: the one seam between the role that parses and the role that decides.

A real core (real store, journal and pipeline, over the model host) is started on Unix sockets in a
short private directory, and the edge's real client talks to it. Where the rule under test is the
client's alone (its bounds, its deadline, what it makes of a bad answer), a scripted listener plays
the core, so that the test decides exactly what comes back.

Proves B34, EC-2 to EC-6, VER-13 and the catalog entries T3-EC-03, T3-RED-09 and the first half of
T3-VER-03.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import signal
import socket
import struct
import tempfile
import threading
import time
from collections import deque
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from acf_api import cli
from acf_api.command import codec
from acf_api.command import commands as c
from acf_api.command.answers import (
    COMMAND_INTERFACE_MAX,
    COMMAND_INTERFACE_VERSION,
    AckAnswer,
    Answer,
    ErrorAnswer,
    HandleRequest,
    RequestContext,
    VerifiedAnswer,
    VerifyRequest,
    ViewAnswer,
)
from acf_api.command.client import SocketCoreClient, new_request_id
from acf_api.core import app
from acf_api.core import config as cfg
from acf_api.core.admin import server as admin_server
from acf_api.core.admin.commands import AdminError
from acf_api.core.server import SocketInUse
from acf_api.core.store import engine, journal
from tests.support.deploy import (
    Process,
    core_document,
    platform_command,
    private_dir,
    started,
    wait_until_serving,
    write_platform_identity,
    write_yaml,
)
from tests.support.edge import until
from tests.support.harness import (
    DEPLOYMENT,
    FakeClock,
    Identity,
    Rig,
    build_rig,
    config_dict,
    create_deployment,
    sandbox_spec,
)
from tests.support.model_host import ModelHost

OTHER_DEPLOYMENT = "dep_1A7E3S9G5L2Z8U4K"
_HEADER = struct.Struct(">I")


def context(budget_s: float = 5.0) -> RequestContext:
    return RequestContext(
        request_id=new_request_id(), budget_ms=int(budget_s * 1000), interface="rest", interface_version="v1"
    )


def error_of(answer: Answer) -> tuple[str, str, str]:
    """Code, kind and retry advice of an error answer."""
    assert isinstance(answer, ErrorAnswer), answer
    return answer.error.code, answer.error.kind, answer.error.retry


def frame(payload: bytes) -> bytes:
    return _HEADER.pack(len(payload)) + payload


@pytest.fixture
def short_dir() -> Iterator[Path]:
    """A private directory with a short name: a socket path is limited to 107 bytes."""
    path = Path(tempfile.mkdtemp(prefix="acf-"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@dataclass
class Live:
    """A started core and the edge's client on its command socket."""

    rig: Rig
    client: SocketCoreClient

    @property
    def path(self) -> Path:
        return self.rig.config.paths.command_socket

    def count(self, name: str, **labels: str) -> int:
        return self.rig.core.telemetry.get(name, **labels)


@pytest.fixture
async def live(short_dir: Path) -> AsyncIterator[Live]:
    rig = await build_rig(short_dir)
    await app.start(rig.core)
    client = SocketCoreClient(str(rig.config.paths.command_socket))
    try:
        yield Live(rig, client)
    finally:
        await client.aclose()
        await asyncio.wait_for(rig.close(), 15)


@pytest.fixture
async def dev(live: Live) -> Identity:
    return await live.rig.developer()


def create(dev: Identity, **spec: Any) -> c.CreateSandbox:
    return c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(**spec))


@contextlib.asynccontextmanager
async def connection(path: Path) -> AsyncIterator[tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
    """A raw connection to a command socket, as any process of this user could open one."""
    reader, writer = await asyncio.open_unix_connection(str(path))
    try:
        yield reader, writer
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def closed_without_an_answer(reader: asyncio.StreamReader) -> bool:
    """Whether the peer ended the connection without sending a byte. A reset says the same as an end."""
    try:
        return await asyncio.wait_for(reader.read(1), 5) == b""
    except ConnectionResetError:
        return True


async def raw_answer(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, payload: bytes) -> Answer:
    """Write one frame and decode the answer frame."""
    writer.write(frame(payload))
    await writer.drain()
    return codec.decode_answer(await asyncio.wait_for(codec.read_frame(reader, codec.DEFAULT_MAX_ANSWER_FRAME), 5))


# =============================================================================== the three calls
async def test_verify_handle_and_delivered_cross_the_socket(
    live: Live, dev: Identity, monkeypatch: pytest.MonkeyPatch
) -> None:
    """B34: the credential check, one command of the public model, and the delivery report."""
    assert isinstance(await live.client.verify(dev.key, context()), VerifiedAnswer)

    ctx = context()
    created = await live.client.handle(dev.key, ctx, create(dev, name="over-the-socket"), "k-socket")
    assert isinstance(created, ViewAnswer)
    assert (created.view, created.terminal, created.replayed) == ("Operation", True, False)
    assert created.body["result"]["sandbox"]["name"] == "over-the-socket"
    # The request id of the edge is the one the host was given.
    assert {s.request_id for s in live.rig.host.sent if s.operation_id is not None} == {ctx.request_id}

    replay = await live.client.handle(dev.key, context(), create(dev, name="over-the-socket"), "k-socket")
    assert isinstance(replay, ViewAnswer)
    assert (replay.replayed, replay.body["operation_id"]) == (True, created.body["operation_id"])

    reported: list[tuple[str | None, str, str]] = []
    delivered = live.rig.service.delivered

    async def spy(credential: str | None, ctx: RequestContext, token: str) -> Answer:
        reported.append((credential, ctx.request_id, token))
        acknowledged: Answer = await delivered(credential, ctx, token)
        return acknowledged

    monkeypatch.setattr(live.rig.service, "delivered", spy)
    ctx = context()
    await live.client.delivered(dev.key, ctx, "delivery-token-1")
    assert reported == [(dev.key, ctx.request_id, "delivery-token-1")]
    assert live.client.in_flight == 0


async def test_a_caller_without_a_credential_is_answered_and_not_refused_as_a_bad_frame(live: Live) -> None:
    """EC-3, PUB-8: "no credential" crosses the interface like any other: the core decides what it means."""
    ctx = context()
    missing = await live.client.verify(None, ctx)
    assert error_of(missing) == ("UNAUTHENTICATED", "REFUSED", "NEVER")
    assert isinstance(missing, ErrorAnswer)
    assert missing.error.request_id == ctx.request_id
    assert missing.challenge is not None

    anonymous = await live.client.handle(None, context(), c.Info())
    assert isinstance(anonymous, ViewAnswer)
    assert anonymous.body == {"api_versions": ["v1"], "serving": True}

    unauthenticated = await live.client.handle(None, context(), c.WhoAmI())
    assert error_of(unauthenticated) == ("UNAUTHENTICATED", "REFUSED", "NEVER")
    assert live.count("command_frames_rejected", reason="invalid") == 0


async def test_the_core_verifies_the_credential_itself_on_every_command(live: Live, dev: Identity) -> None:
    """EC-3: the core never trusts an edge for a principal. A command with a bad credential is refused there."""
    stranger = await live.rig.developer("other")
    assert error_of(await live.client.handle("not-a-key", context(), create(dev), "k")) == (
        "UNAUTHENTICATED",
        "REFUSED",
        "NEVER",
    )
    assert error_of(await live.client.handle(stranger.key, context(), create(dev), "k")) == (
        "NOT_FOUND",
        "REFUSED",
        "NEVER",
    )
    assert live.rig.host.mutating() == []


async def test_connections_are_kept_and_reused(live: Live, dev: Identity) -> None:
    for _ in range(5):
        assert isinstance(await live.client.verify(dev.key, context()), VerifiedAnswer)
    assert len(live.client._idle) == 1


# =============================================================================== who may connect
async def test_an_identity_that_is_not_an_edge_identity_is_closed_without_an_answer(short_dir: Path) -> None:
    """EC-2: the command socket admits the configured edge identities and no other."""
    create_deployment(short_dir)
    document = config_dict(short_dir)
    document["edge"] = {"uids": [os.geteuid() + 1]}
    host = ModelHost()
    core = await app.build_core(cfg.parse_config(document), binding=host, clock=FakeClock(), check_files=False)
    try:
        await app.start(core)
        path = core.config.paths.command_socket
        handled = core.telemetry.get("requests", command="create_sandbox", interface="rest", outcome="UNAUTHENTICATED")
        request = VerifyRequest(version=COMMAND_INTERFACE_VERSION, credential="any", ctx=context())
        async with connection(path) as (reader, writer):
            writer.write(frame(codec.encode_request(request)))
            await writer.drain()
            assert await closed_without_an_answer(reader), "the core answered an identity it does not admit"
        assert core.telemetry.get("command_socket_rejected") == 1

        # The edge's client cannot know why no answer came, so it says what it must: a mutation is unresolved.
        client = SocketCoreClient(str(path))
        try:
            assert error_of(await client.verify("any", context())) == (
                "UPSTREAM_UNAVAILABLE",
                "REFUSED",
                "SAME_REQUEST_LATER",
            )
            command = c.CreateSandbox(project="prj_" + "0" * 20, spec=sandbox_spec())
            assert error_of(await client.handle("any", context(), command, "k"))[0] == "OUTCOME_UNRESOLVED"
        finally:
            await client.aclose()
        assert core.telemetry.get("command_socket_rejected") == 3
        assert (
            core.telemetry.get("requests", command="create_sandbox", interface="rest", outcome="UNAUTHENTICATED")
            == handled
        )
        assert host.sent == []
    finally:
        await asyncio.wait_for(core.close(), 15)


async def test_the_command_socket_is_not_open_to_others_by_its_mode(live: Live) -> None:
    """EC-2: owner and group may connect, nobody else; the admin socket is the owner's alone."""
    assert live.path.stat().st_mode & 0o777 == 0o660
    assert live.rig.config.paths.admin_socket.stat().st_mode & 0o777 == 0o600


# =============================================================================== versions and frames
def _handle_payload(dev: Identity, **changes: Any) -> bytes:
    request = HandleRequest(
        version=COMMAND_INTERFACE_VERSION,
        credential=dev.key,
        ctx=context(),
        idempotency_key="k-frame",
        command=create(dev),
    )
    body = json.loads(codec.encode_request(request))
    body.update(changes)
    return json.dumps(body).encode("utf-8")


@pytest.mark.parametrize("version", [0, COMMAND_INTERFACE_MAX + 1, 999, -1])
@pytest.mark.proves("T3-VER-03")
async def test_a_frame_of_a_version_outside_the_served_range_is_refused(
    live: Live, dev: Identity, version: int
) -> None:
    """VER-13, T3-VER-03: an edge and a core interoperate only inside the range the core declares."""
    async with connection(live.path) as (reader, writer):
        refused = await raw_answer(reader, writer, _handle_payload(dev, version=version))
        assert error_of(refused) == ("UNSUPPORTED", "REFUSED", "NEVER")
        # The connection is intact: the same edge, speaking a served version, is answered on it.
        served = await raw_answer(reader, writer, _handle_payload(dev))
        assert isinstance(served, ViewAnswer)
    assert live.count("command_frames_rejected", reason="version") == 1
    assert len(live.rig.host.mutating()) == 1, "a command of a refused version reached the host"


@pytest.mark.parametrize(
    ("label", "changes"),
    [
        ("no-version", {"version": None}),
        ("a-version-that-is-not-a-number", {"version": "1"}),
        ("a-boolean-version", {"version": True}),
        ("an-unknown-call", {"op": "shutdown"}),
        ("an-unknown-command", {"command": {"type": "profile_reload"}}),
        ("an-operator-method", {"command": {"type": "host.set_mode", "mode": "DRAINING"}}),
        ("an-unknown-member", {"principal_id": "prn_asserted_by_the_edge"}),
        (
            "an-unknown-member-of-the-context",
            {
                "ctx": {
                    "request_id": "req_" + "a" * 24,
                    "budget_ms": 1000,
                    "interface": "rest",
                    "interface_version": "v1",
                    "principal": "x",
                }
            },
        ),
        ("a-key-outside-its-form", {"idempotency_key": "two words"}),
    ],
)
async def test_a_frame_that_is_not_a_command_of_the_public_model_is_refused(
    live: Live, dev: Identity, label: str, changes: dict[str, Any]
) -> None:
    """EC-4, B34: an unknown command or member is refused; no operator command and no host method crosses."""
    payload = _handle_payload(dev, **changes)
    if changes.get("version", 0) is None:
        body = json.loads(payload)
        del body["version"]
        payload = json.dumps(body).encode("utf-8")
    async with connection(live.path) as (reader, writer):
        assert error_of(await raw_answer(reader, writer, payload)) == ("INVALID_REQUEST", "REFUSED", "NEVER"), label
    assert live.count("command_frames_rejected", reason="invalid") == 1
    assert live.rig.host.mutating() == []


async def test_a_frame_that_is_not_json_or_repeats_a_member_is_refused(live: Live, dev: Identity) -> None:
    repeated = _handle_payload(dev)[:-1] + b',"credential":"another"}'
    async with connection(live.path) as (reader, writer):
        for payload in (b"not json", b"[]", b"", repeated):
            assert error_of(await raw_answer(reader, writer, payload))[0] == "INVALID_REQUEST"
    assert live.rig.host.mutating() == []


async def test_an_oversize_frame_is_refused_by_its_header_before_it_is_read(short_dir: Path) -> None:
    """A declared length above the bound closes the connection at once: nothing is read and nothing is allocated."""
    rig = await build_rig(short_dir, max_public_request_bytes=1024)
    try:
        await app.start(rig.core)
        path = rig.config.paths.command_socket
        bound = 1024 * 2 + 64 * 1024
        async with connection(path) as (reader, writer):
            # Only the header is sent. A core that waited for the payload would wait for ever.
            writer.write(_HEADER.pack(bound + 1))
            await writer.drain()
            assert await closed_without_an_answer(reader)
        assert rig.core.telemetry.get("command_frames_rejected", reason="framing") == 1

        # At the bound a frame is read: this one is read, found not to be a command, and answered.
        async with connection(path) as (reader, writer):
            assert error_of(await raw_answer(reader, writer, b" " * bound))[0] == "INVALID_REQUEST"
    finally:
        await asyncio.wait_for(rig.close(), 15)


async def test_a_command_too_large_for_a_frame_never_leaves_the_edge(live: Live, dev: Identity) -> None:
    """T3-RED-38: a request too large to carry is refused where it is, and nothing of it reaches the core or the host.

    Only a command that provably never left the edge is answered as a refusal, even when it is a mutation.
    """
    sent = len(live.rig.host.sent)
    small = SocketCoreClient(str(live.path), max_request_frame=256)
    try:
        refused = await small.handle(dev.key, context(), create(dev, name="n" * 60), "k-large")
        assert error_of(refused) == ("UPSTREAM_UNAVAILABLE", "REFUSED", "SAME_REQUEST_LATER")
        assert small._idle == deque(), "a connection was opened for a command that was never sent"
    finally:
        await small.aclose()
    assert live.count("requests", command="create_sandbox", interface="rest", outcome="view") == 0
    assert len(live.rig.host.sent) == sent


async def test_an_answer_too_large_for_the_edge_is_a_lost_answer(live: Live, dev: Identity) -> None:
    """The command was carried out and its answer cannot be read: unresolved, and found again with the key."""
    small = SocketCoreClient(str(live.path), max_answer_frame=64)
    try:
        lost = await small.handle(dev.key, context(), create(dev), "k-big-answer")
        assert error_of(lost) == ("OUTCOME_UNRESOLVED", "UNRESOLVED", "SAME_REQUEST_LATER")
        assert isinstance(lost, ErrorAnswer)
        assert lost.error.idempotency_key == "k-big-answer"
    finally:
        await small.aclose()
    again = await live.client.handle(dev.key, context(), create(dev), "k-big-answer")
    assert isinstance(again, ViewAnswer)
    assert again.replayed is True
    assert len(live.rig.host.sandboxes) == 1


# =============================================================================== a scripted core
@dataclass
class Scripted:
    """A listener that plays the core exactly as a test scripts it. It decides nothing by itself."""

    path: Path
    #: What to write for each frame received: the raw bytes of the answer, or ``None`` to stay silent.
    reply: Callable[[dict[str, Any]], bytes | None] = field(
        default=lambda _: frame(codec.encode_answer(AckAnswer(), 1))
    )
    #: Frames are answered only while this is set.
    gate: asyncio.Event = field(default_factory=asyncio.Event)
    frames: list[dict[str, Any]] = field(default_factory=list)
    connections: int = 0
    close_after_reply: bool = False
    _server: asyncio.Server | None = None
    _writers: list[asyncio.StreamWriter] = field(default_factory=list)

    async def start(self) -> None:
        self.gate.set()
        self._server = await asyncio.start_unix_server(self._serve, path=str(self.path))

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        self._writers.append(writer)
        with contextlib.suppress(codec.FrameError, OSError, asyncio.CancelledError):
            while True:
                body = json.loads(await codec.read_frame(reader, codec.MAX_FRAME_HARD_CAP))
                self.frames.append(body)
                await self.gate.wait()
                answer = self.reply(body)
                if answer is not None:
                    writer.write(answer)
                    await writer.drain()
                if self.close_after_reply:
                    break
        writer.close()

    async def close(self) -> None:
        for writer in self._writers:
            writer.close()
        if self._server is not None:
            self._server.close()


@pytest.fixture
async def scripted(short_dir: Path) -> AsyncIterator[Scripted]:
    core = Scripted(short_dir / "core.sock")
    await core.start()
    try:
        yield core
    finally:
        await core.close()


PROJECT = "prj_" + "0" * 20
SANDBOX = "sbx-" + "0" * 32
GENERAL = c.GetSandbox(project=PROJECT, sandbox=SANDBOX)
MUTATION = c.CreateSandbox(project=PROJECT, spec=sandbox_spec())
CONTAINMENT = c.DestroySandbox(project=PROJECT, sandbox_id=SANDBOX, expected_generation=1)


async def test_the_client_bounds_its_commands_in_flight_and_keeps_a_tenth_for_containment(scripted: Scripted) -> None:
    """B34: at most `edge_max_commands_in_flight` per edge process, a tenth of them for containment commands."""
    client = SocketCoreClient(str(scripted.path), max_in_flight=20)
    scripted.gate.clear()
    try:
        general = [asyncio.create_task(client.handle("key", context(), GENERAL)) for _ in range(18)]
        await until(lambda: len(scripted.frames) == 18)
        # The general share is spent: the next command is refused at once, and nothing of it is sent.
        assert error_of(await client.handle("key", context(), GENERAL)) == (
            "RATE_LIMITED",
            "REFUSED",
            "SAME_REQUEST_LATER",
        )
        assert error_of(await client.handle("key", context(), MUTATION, "k"))[0] == "RATE_LIMITED"
        assert len(scripted.frames) == 18

        # Containment still passes, through the share that is kept for it.
        contained = [asyncio.create_task(client.handle("key", context(), CONTAINMENT, f"k{n}")) for n in range(2)]
        await until(lambda: len(scripted.frames) == 20)
        assert client.in_flight == 20
        # Now the whole bound is spent, for containment and for the credential check alike.
        assert error_of(await client.handle("key", context(), CONTAINMENT, "k-late"))[0] == "RATE_LIMITED"
        assert error_of(await client.verify("key", context()))[0] == "RATE_LIMITED"
        assert len(scripted.frames) == 20

        scripted.gate.set()
        assert all(isinstance(answer, AckAnswer) for answer in await asyncio.gather(*general, *contained))
        assert client.in_flight == 0
        assert isinstance(await client.handle("key", context(), GENERAL), AckAnswer)
    finally:
        scripted.gate.set()
        await client.aclose()


def test_a_client_needs_room_for_one_containment_command_and_one_other() -> None:
    with pytest.raises(ValueError, match="at least 2"):
        SocketCoreClient("/nonexistent", max_in_flight=1)


@pytest.mark.proves("T3-EC-02")
async def test_no_answer_within_the_deadline_is_unresolved_for_a_mutation_and_a_refusal_for_a_read(
    scripted: Scripted,
) -> None:
    """EC-5: an edge that sent a mutating command and has no answer by the deadline answers `OUTCOME_UNRESOLVED`."""
    scripted.reply = lambda _: None
    client = SocketCoreClient(str(scripted.path))
    try:
        started = time.monotonic()
        answers = await asyncio.gather(
            client.handle("key", context(0.2), MUTATION, "k-silent"),
            client.handle("key", context(0.2), CONTAINMENT, "k-contain"),
            client.handle("key", context(0.2), GENERAL),
            client.verify("key", context(0.2)),
        )
        elapsed = time.monotonic() - started
        assert 0.2 <= elapsed < 3.0, elapsed
        mutation, containment, read, verified = answers
        assert error_of(mutation) == ("OUTCOME_UNRESOLVED", "UNRESOLVED", "SAME_REQUEST_LATER")
        assert isinstance(mutation, ErrorAnswer)
        assert mutation.error.idempotency_key == "k-silent"
        assert mutation.retry_after_s is not None
        assert error_of(containment)[0] == "OUTCOME_UNRESOLVED"
        assert error_of(read) == ("UPSTREAM_UNAVAILABLE", "REFUSED", "SAME_REQUEST_LATER")
        assert error_of(verified) == ("UPSTREAM_UNAVAILABLE", "REFUSED", "SAME_REQUEST_LATER")
        assert len(scripted.frames) == 4, "each command had left the edge"
        assert client.in_flight == 0
    finally:
        await client.aclose()


async def test_a_late_answer_is_never_read_as_the_answer_to_a_later_command(scripted: Scripted) -> None:
    """A connection is discarded on its first failure, so what arrives on it afterwards answers nothing."""

    def named(body: dict[str, Any]) -> bytes:
        view = ViewAnswer(view="Echo", body={"request_id": body["ctx"]["request_id"]})
        return frame(codec.encode_answer(view, 1))

    scripted.reply = named
    scripted.gate.clear()
    client = SocketCoreClient(str(scripted.path))
    try:
        first = context(0.1)
        assert error_of(await client.handle("key", first, MUTATION, "k-first"))[0] == "OUTCOME_UNRESOLVED"
        # The core answers the first command now, too late, and then the second.
        scripted.gate.set()
        second = context()
        answer = await client.handle("key", second, GENERAL)
        assert isinstance(answer, ViewAnswer)
        assert answer.body == {"request_id": second.request_id}
        assert scripted.connections == 2
    finally:
        await client.aclose()


@pytest.mark.parametrize(
    "bad",
    [
        frame(b"not json"),
        frame(b'{"protocol":"acf.command","version":1,"answer":{"kind":"unheard-of"}}'),
        frame(codec.encode_answer(AckAnswer(), 1).replace(b'"version":1', b'"version":2')),
        frame(codec.encode_answer(AckAnswer(), 1).replace(b"acf.command", b"acf.elsewhere")),
        _HEADER.pack(1 << 30),
        _HEADER.pack(100) + b"cut short",
        b"",
    ],
    ids=[
        "not-json",
        "unknown-kind",
        "version-outside-the-range",
        "another-protocol",
        "oversize-header",
        "truncated",
        "closed",
    ],
)
@pytest.mark.proves("T3-VER-03", "T3-EC-02")
async def test_an_answer_the_edge_cannot_use_is_a_lost_answer(scripted: Scripted, bad: bytes) -> None:
    """VER-13 on the edge's side, and ERR-1: an unusable answer to a mutation is never turned into a refusal."""
    scripted.reply = lambda _: bad
    scripted.close_after_reply = True
    client = SocketCoreClient(str(scripted.path))
    try:
        started = time.monotonic()
        assert error_of(await client.handle("key", context(), MUTATION, "k"))[0] == "OUTCOME_UNRESOLVED"
        assert error_of(await client.handle("key", context(), GENERAL))[0] == "UPSTREAM_UNAVAILABLE"
        assert time.monotonic() - started < 2.0, "the edge waited for bytes that were never coming"
        assert scripted.connections == 2, "a connection that failed was used again"
    finally:
        await client.aclose()


async def test_a_core_that_cannot_be_reached_is_a_refusal_because_nothing_was_sent(short_dir: Path) -> None:
    """ERR-1: `REFUSED` only when the request never left. With no core listening, it provably did not."""
    client = SocketCoreClient(str(short_dir / "nobody.sock"))
    try:
        for answer in (
            await client.handle("key", context(), MUTATION, "k"),
            await client.handle("key", context(), GENERAL),
            await client.verify("key", context()),
        ):
            assert error_of(answer) == ("UPSTREAM_UNAVAILABLE", "REFUSED", "SAME_REQUEST_LATER")
        # A delivery report is best effort: it is dropped, and the caller of it is told nothing.
        await client.delivered("key", context(), "delivery-token")
    finally:
        await client.aclose()


# =============================================================================== abandoning and dying
CONTAINING = {"operation.cancel", "sandbox.stop", "sandbox.destroy", "snapshot.delete"}


async def test_an_abandoned_exchange_poisons_no_connection_and_cancels_nothing_on_the_host(
    live: Live, dev: Identity
) -> None:
    """LRO-5, INV-116: a cancelled wait in the edge ends the waiting. The operation runs on, and is found by its key."""
    host = live.rig.host
    gate = host.block("sandbox.create")
    pending = asyncio.create_task(live.client.handle(dev.key, context(), create(dev), "k-abandoned"))
    await until(lambda: any(s.method == "sandbox.create" for s in host.sent))
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending
    assert live.client.in_flight == 0

    # The next command on this client is answered for itself, not with what is still to come for the first.
    who = await live.client.handle(dev.key, context(), c.WhoAmI())
    assert isinstance(who, ViewAnswer)
    assert who.view == "WhoAmI"
    await until(lambda: live.count("commands_abandoned") == 1)

    gate.set()
    await until(lambda: len(host.sandboxes) == 1)
    again = await live.client.handle(dev.key, context(), create(dev), "k-abandoned")
    assert isinstance(again, ViewAnswer)
    assert (again.replayed, again.terminal) == (True, True)
    assert len(host.submissions(again.body["operation_id"])) == 1
    assert not CONTAINING & {s.method for s in host.sent}


@pytest.mark.proves("T3-EC-02")
async def test_a_core_that_goes_away_between_request_and_answer_leaves_a_mutation_unresolved(
    live: Live, dev: Identity
) -> None:
    """EC-5: the command was sent and the core is gone. The edge cannot say that nothing happened, and does not."""
    host = live.rig.host
    gate = host.block("sandbox.create")
    pending = asyncio.create_task(live.client.handle(dev.key, context(), create(dev), "k-gone"))
    reading = asyncio.create_task(live.client.handle(dev.key, context(), c.WhoAmI()))
    await until(lambda: any(s.method == "sandbox.create" for s in host.sent))
    assert isinstance(await reading, ViewAnswer)

    assert live.rig.core.command_server is not None
    await asyncio.wait_for(live.rig.core.command_server.close(), 5)
    answer = await asyncio.wait_for(pending, 5)
    assert error_of(answer) == ("OUTCOME_UNRESOLVED", "UNRESOLVED", "SAME_REQUEST_LATER")
    assert isinstance(answer, ErrorAnswer)
    assert answer.error.idempotency_key == "k-gone"
    gate.set()
    # With no core on the socket any more, the next command provably does not leave the edge.
    assert error_of(await live.client.handle(dev.key, context(), create(dev), "k-next"))[0] == "UPSTREAM_UNAVAILABLE"


async def test_a_stop_does_not_wait_for_an_edge_that_keeps_its_connections_open(short_dir: Path) -> None:
    """IPS-15: a planned stop is bounded by `drain_timeout`, not by how long an edge keeps an idle connection."""
    rig = await build_rig(short_dir)
    await app.start(rig.core)
    client = SocketCoreClient(str(rig.config.paths.command_socket))
    try:
        assert error_of(await client.verify(None, context()))[0] == "UNAUTHENTICATED"
        assert len(client._idle) == 1, "the edge holds an idle connection, as it does between two requests"
        # And somebody connected to the admin socket and never sent a command.
        async with connection(rig.config.paths.admin_socket):
            assert await rig.service.drain() is True
            await asyncio.wait_for(rig.close(), 5)
        assert not rig.config.paths.command_socket.exists()
        assert not rig.config.paths.admin_socket.exists()
        assert error_of(await client.verify(None, context()))[0] == "UPSTREAM_UNAVAILABLE"
    finally:
        await client.aclose()


# =============================================================================== one core
async def _build(document: dict[str, Any]) -> app.Core:
    return await app.build_core(cfg.parse_config(document), binding=ModelHost(), clock=FakeClock(), check_files=False)


@pytest.mark.proves("T3-EC-03", "T3-RED-09")
async def test_a_second_core_on_the_same_store_refuses_to_start(live: Live, short_dir: Path) -> None:
    """EC-6, T3-EC-03: exactly one core serves a deployment; it holds the store and the journal for itself."""
    with pytest.raises(app.StartupError, match="held by another core"):
        await _build(config_dict(short_dir))

    # Even with a copy of the journal of its own, the store itself is locked.
    copy = short_dir / "copy" / "security.journal"
    copy.parent.mkdir(mode=0o700)
    shutil.copy(live.rig.config.paths.journal, copy)
    document = config_dict(short_dir)
    document["paths"]["journal"] = str(copy)
    with pytest.raises(app.StartupError, match="held by another core") as refused:
        await _build(document)
    assert isinstance(refused.value.__cause__, engine.StoreLocked)

    # T3-RED-09: nor does a fresh store get it past the journal that the running core holds.
    fresh = config_dict(short_dir)
    fresh["paths"]["store_dir"] = str(short_dir / "fresh-store")
    engine.create_store(short_dir / "fresh-store", DEPLOYMENT)
    with pytest.raises(app.StartupError, match="held by another core"):
        await _build(fresh)

    assert error_of(await live.client.verify(None, context()))[0] == "UNAUTHENTICATED", "the first core was disturbed"


@pytest.mark.proves("T3-EC-03")
async def test_a_second_core_on_the_same_sockets_refuses_to_start_and_leaves_the_first_reachable(
    live: Live, short_dir: Path
) -> None:
    """EC-6: another store does not make a second core. What already answers on the socket is not displaced."""
    elsewhere = short_dir / "second"
    create_deployment(elsewhere)
    for shared in ("admin_socket", "command_socket"):
        document = config_dict(elsewhere)
        document["paths"][shared] = str(getattr(live.rig.config.paths, shared))
        second = await _build(document)
        try:
            with pytest.raises(SocketInUse, match="a second core refuses to start"):
                await app.start(second)
        finally:
            await asyncio.wait_for(second.close(), 15)
        # The refused core is gone, and it took nothing of the first core with it.
        assert live.rig.config.paths.command_socket.is_socket(), shared
        assert live.rig.config.paths.admin_socket.is_socket(), shared
        health = await admin_server.call(live.rig.config.paths.admin_socket, "health", {})
        assert health["deployment_id"] == DEPLOYMENT
        fresh = SocketCoreClient(str(live.path))
        try:
            assert error_of(await fresh.verify(None, context()))[0] == "UNAUTHENTICATED", shared
        finally:
            await fresh.aclose()


async def test_a_socket_path_nobody_answers_on_is_taken_over(short_dir: Path) -> None:
    """A socket file left by a core that died is not another core: the next start replaces it."""
    create_deployment(short_dir)
    run = short_dir / "run"
    run.mkdir(mode=0o700)
    for name in ("command.sock", "admin.sock"):
        stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stale.bind(str(run / name))
        stale.close()
    core = await _build(config_dict(short_dir))
    try:
        await app.start(core)
        assert (await admin_server.call(core.config.paths.admin_socket, "health", {}))["serving"] is True
    finally:
        await asyncio.wait_for(core.close(), 15)

    # Something that is not a socket is never removed.
    (run / "command.sock").write_text("not a socket", encoding="utf-8")
    core = await _build(config_dict(short_dir))
    try:
        with pytest.raises(SocketInUse, match="not a socket"):
            await app.start(core)
    finally:
        await asyncio.wait_for(core.close(), 15)
    assert (run / "command.sock").read_text(encoding="utf-8") == "not a socket"


@pytest.mark.proves("T3-EC-03", "T3-RED-09")
async def test_a_core_serves_only_the_deployment_its_configuration_names(short_dir: Path) -> None:
    """EC-6, IPS-12, T3-EC-03: another deployment id than the store's, or than the journal's, refuses the start."""
    create_deployment(short_dir)
    named_other = config_dict(short_dir)
    named_other["deployment_id"] = OTHER_DEPLOYMENT
    with pytest.raises(app.StartupError, match="another deployment") as by_journal:
        await _build(named_other)
    assert isinstance(by_journal.value.__cause__, journal.JournalError)

    # With a journal of the named deployment, the store's own id still refuses.
    own_journal = short_dir / "other" / "security.journal"
    journal.create_journal(own_journal, OTHER_DEPLOYMENT)
    named_other["paths"]["journal"] = str(own_journal)
    with pytest.raises(app.StartupError, match="another deployment") as by_store:
        await _build(named_other)
    assert isinstance(by_store.value.__cause__, engine.StoreMismatch)

    # T3-RED-09: a fresh store of another deployment beside the existing journal is refused by the journal.
    fresh = config_dict(short_dir)
    fresh["deployment_id"] = OTHER_DEPLOYMENT
    fresh["paths"]["store_dir"] = str(short_dir / "fresh-store")
    engine.create_store(short_dir / "fresh-store", OTHER_DEPLOYMENT)
    with pytest.raises(app.StartupError, match="another deployment"):
        await _build(fresh)

    # None of the refusals left anything locked: the deployment starts under its own name.
    core = await _build(config_dict(short_dir))
    await asyncio.wait_for(core.close(), 15)


# =============================================================================== the admin socket
async def test_the_admin_socket_admits_the_cores_own_identity_and_answers_health(live: Live) -> None:
    path = live.rig.config.paths.admin_socket
    health = await admin_server.call(path, "health", {})
    assert (health["serving"], health["deployment_id"]) == (True, DEPLOYMENT)
    assert health["edge_shares_core_identity"] is True
    assert health["writer_epoch"] == live.rig.service.d.writer_epoch

    with pytest.raises(AdminError, match="unknown admin operation"):
        await admin_server.call(path, "sandbox.create", {})
    async with connection(path) as (reader, writer):
        writer.write(b"this is not a request\n")
        await writer.drain()
        assert json.loads(await asyncio.wait_for(reader.readline(), 5))["ok"] is False
    with pytest.raises(AdminError, match="no core answers"):
        await admin_server.call(path.with_name("absent.sock"), "health", {})


# =============================================================================== the processes, as an operator runs them
def _run(*argv: str) -> int:
    return cli.main(list(argv))


def _exchange_blocking(path: Path, payload: bytes) -> tuple[socket.socket, Answer]:
    """One exchange on a blocking socket that is then left open and idle, as an edge leaves its connections."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect(str(path))
    sock.sendall(frame(payload))
    (length,) = _HEADER.unpack(_read_exactly(sock, _HEADER.size))
    return sock, codec.decode_answer(_read_exactly(sock, length))


def _read_exactly(sock: socket.socket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        assert chunk, "the core closed the connection in the middle of an answer"
        data += chunk
    return data


def _copy_of_a_new_deployment(root: Path) -> None:
    """A new deployment under ``root``: made where the disk is memory, then copied.

    A store holds no path, so it can be moved, and the many small durable writes of creating one do
    not wait for a real disk.
    """
    scratch = Path(tempfile.mkdtemp(prefix="acf-"))
    try:
        create_deployment(scratch)
        shutil.copytree(scratch, root, dirs_exist_ok=True)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


@pytest.mark.proves("T3-EC-03")
def test_the_deployable_as_an_operator_runs_it(capsys: pytest.CaptureFixture[str]) -> None:
    """`init`, `check`, the core as a process, `admin`, a second core that is turned away, and a stop that drains.

    One deployment and one core process serve the whole test: starting a process of the platform is
    the slow part, so it is done as few times as the proof needs.
    """
    with private_dir("c") as root:
        write_platform_identity(root)
        config = write_yaml(root / "core.yaml", core_document(root))
        paths = cfg.load_config(config).paths

        # Before `init` there is no fingerprint key, so the configuration does not check.
        assert _run("check", "--config", str(config)) == 1
        assert "not a trusted input" in capsys.readouterr().err
        assert _run("init", "--config", str(config)) == 0
        assert json.loads(capsys.readouterr().out) == {
            "deployment_id": DEPLOYMENT,
            "store": str(paths.store_dir),
            "journal": str(paths.journal),
        }
        assert paths.fingerprint_key.stat().st_mode & 0o777 == 0o600
        assert _run("init", "--config", str(config)) == 1, "a second `init` must change nothing"
        assert "already exists" in capsys.readouterr().err
        assert _run("check", "--config", str(config)) == 0
        assert json.loads(capsys.readouterr().out)["deployment_id"] == DEPLOYMENT

        # Another deployment, which was given the first one's sockets by mistake.
        other = root / "other"
        _copy_of_a_new_deployment(other)
        write_platform_identity(other)
        document = core_document(other)
        document["paths"]["command_socket"] = str(paths.command_socket)
        document["paths"]["admin_socket"] = str(paths.admin_socket)
        other_config = write_yaml(other / "core.yaml", document)

        with started(platform_command("core", config), root / "core.log") as core:
            wait_until_serving(core, sockets=(paths.command_socket, paths.admin_socket))

            # EC-6, T3-EC-03: a second core on the same store, and one on the same sockets, each refuse to
            # start. The refusal is a message for the operator and an exit status, not a traceback.
            with (
                started(platform_command("core", config), root / "second.log") as second,
                started(platform_command("core", other_config), other / "core.log") as intruder,
            ):
                for refused, reason in ((second, "held by another core"), (intruder, "a second core refuses to start")):
                    status = refused.popen.wait(timeout=30)
                    assert status > 0, refused.output()
                    assert "the core refuses to start" in refused.output()
                    assert reason in refused.output()
                    assert "Traceback" not in refused.output()

            # The first core is where it was, and answers its operator.
            assert _run("admin", "--config", str(config), "health") == 0
            health = json.loads(capsys.readouterr().out)
            assert (health["serving"], health["deployment_id"], health["edge_shares_core_identity"]) == (
                True,
                DEPLOYMENT,
                True,
            )
            assert health["ready"] is False, "no host answers at the configured address"

            assert _run("admin", "--config", str(config), "principal.create", "--label", "alice") == 0
            principal = json.loads(capsys.readouterr().out)
            assert principal["label"] == "alice"
            assert _run("admin", "--config", str(config), "principal.list") == 0
            assert [p["principal_id"] for p in json.loads(capsys.readouterr().out)] == [principal["principal_id"]]

            assert _run("admin", "--config", str(config), "no.such.operation") == 1
            assert "unknown admin operation" in capsys.readouterr().err
            assert _run("admin", "--config", str(config), "principal.create", "label") == 2
            assert "--name value" in capsys.readouterr().err

            # An edge would now connect. Its connection stays open and idle while the core is told to stop.
            request = VerifyRequest(version=COMMAND_INTERFACE_VERSION, credential=None, ctx=context())
            idle, answer = _exchange_blocking(paths.command_socket, codec.encode_request(request))
            try:
                assert error_of(answer)[0] == "UNAUTHENTICATED"
                assert core.stop(signal.SIGTERM, timeout_s=20) == 0, core.output()
                assert idle.recv(1) == b"", "the core ended and left an edge connection open"
            finally:
                idle.close()

            output = core.output()
            assert '"event":"core_started"' in output
            assert '"event":"core_stopping","drained":true' in output
            assert "Traceback" not in output
            assert not paths.command_socket.exists()
            assert not paths.admin_socket.exists()

        # Nothing answers any more, and the operator is told what to look at.
        assert _run("admin", "--config", str(config), "health") == 1
        assert "no core answers" in capsys.readouterr().err


@contextlib.contextmanager
def silent_listener() -> Iterator[tuple[int, Callable[[], int]]]:
    """A TCP listener that accepts connections and never says anything: a host that has stopped answering."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(16)
    server.settimeout(0.1)
    accepted: list[socket.socket] = []
    stop = threading.Event()

    def accept() -> None:
        while not stop.is_set():
            with contextlib.suppress(TimeoutError, OSError):
                accepted.append(server.accept()[0])

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    try:
        yield server.getsockname()[1], lambda: len(accepted)
    finally:
        stop.set()
        thread.join(timeout=5)
        for held in accepted:
            held.close()
        server.close()


async def _prepare(root: Path) -> Identity:
    """A deployment under ``root`` with one developer in it, made over the model host.

    It is made where the disk is memory and then copied: a store holds no path, so it can be moved,
    and the many small durable writes of setting a deployment up do not wait for a real disk.
    """
    scratch = Path(tempfile.mkdtemp(prefix="acf-"))
    try:
        rig = await build_rig(scratch, clock=FakeClock(wall_ms=int(time.time() * 1000)))
        try:
            dev = await rig.developer()
        finally:
            await rig.close()
        shutil.copytree(scratch, root, dirs_exist_ok=True)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return dev


@pytest.mark.proves("T3-EC-02")
def test_killing_the_core_between_request_and_answer_is_outcome_unresolved() -> None:
    """EC-5 with a real process: the core is killed while its host call is in flight; the edge answers unresolved."""
    with private_dir("k") as root, silent_listener() as (port, accepted):
        dev = asyncio.run(_prepare(root))
        write_platform_identity(root)
        document = core_document(root, host_connect_timeout=20.0)
        document["host"]["address"] = f"127.0.0.1:{port}"
        config = write_yaml(root / "core.yaml", document)
        paths = cfg.load_config(config).paths

        async def scenario(core: Process) -> Answer:
            client = SocketCoreClient(str(paths.command_socket))
            try:
                # The first connection to the host is the core's own look at it; wait for it, so that the
                # next one can only be the submission of this command.
                await until(lambda: accepted() >= 1, timeout_s=15)
                before = accepted()
                destroy = c.DestroySandbox(project=dev.project_id, sandbox_id=SANDBOX, expected_generation=1)
                pending = asyncio.create_task(client.handle(dev.key, context(), destroy, "k-killed"))
                await until(lambda: accepted() > before, timeout_s=15)
                assert not pending.done()
                core.popen.kill()
                return await asyncio.wait_for(pending, 10)
            finally:
                await client.aclose()

        with started(platform_command("core", config), root / "core.log") as core:
            wait_until_serving(core, sockets=(paths.command_socket, paths.admin_socket))
            answer = asyncio.run(scenario(core))
            assert core.popen.wait(timeout=10) == -signal.SIGKILL
        assert error_of(answer) == ("OUTCOME_UNRESOLVED", "UNRESOLVED", "SAME_REQUEST_LATER")
        assert isinstance(answer, ErrorAnswer)
        assert answer.error.idempotency_key == "k-killed"
