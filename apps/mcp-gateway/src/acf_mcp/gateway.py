"""The MCP adapter: this process's own layer, in front of the SDK's Streamable HTTP transport.

It runs in an edge process and decides nothing. Before the SDK sees a request, this layer does, in
this order:

    transport bounds -> Host and Origin -> method -> protocol revision
      -> the credential, from the Authorization header only -> the credential check, asked of the core

and only then is a body read. The order matters in the same two places as in the REST adapter. The
credential is checked *before* the body is read, so that a caller who does not authenticate cannot make
this process parse. And the body is bounded *before* it is parsed, so that an oversize body costs a
count and nothing else.

After the SDK has answered, the layer does one more thing: when the answer was the result of a tool
call that the core wants a delivery report for, and its last chunk was handed to the server while the
caller was still there, it tells the core. A caller that closes the stream ends the wait and nothing
else. No report is made, and nothing is sent to the core on the caller's behalf.

Two facts about the servers this runs under shape the delivery rule, and each has a test:

* a server tells an application that its client is gone only through ``receive``, and silently drops
  what is sent afterwards. "Written" is therefore judged by what ``receive`` had said when the last
  chunk was handed over, never by ``send`` returning;
* once a response is complete, ``receive`` reports a disconnect whatever the client did, and the SDK
  then cancels the scope its handler ran in. The report is therefore made after the SDK has returned,
  outside that scope.
"""

from __future__ import annotations

import asyncio
import logging
import math
import re
from dataclasses import dataclass
from typing import Final
from urllib.parse import parse_qsl

from mcp import types
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import ValidationError

from acf_api.command.answers import ErrorAnswer, VerifiedAnswer
from acf_api.command.client import CoreClient, new_request_id
from acf_api.edge.config import EdgeConfig, is_loopback
from acf_mcp import render
from acf_mcp.asgi import Message, Receive, Reply, Scope, Send, header_values, rpc_error, single_header
from acf_mcp.exchange import REVISION, Exchange, enter, leave, request_context
from acf_mcp.metadata import metadata_document, metadata_path
from acf_mcp.relay import Relay

_LOG: Final = logging.getLogger("acf_mcp")

#: Query parameters that would carry a credential. A credential is never accepted in a URL.
_CREDENTIAL_PARAMS: Final = frozenset({"access_token", "api_key", "apikey", "key", "token", "authorization"})
_CREDENTIAL_MAX: Final = 16 * 1024
#: The longest value of a protocol-version header that is repeated back in an error.
_VERSION_ECHO_MAX: Final = 64
#: More digits than any permitted body length has. Longer declarations are refused unread.
_LENGTH_DIGITS_MAX: Final = 12
#: A `Host` value: a name or an address literal, and the port when one is given.
_HOST: Final = re.compile(r"(?P<name>\[[0-9a-f:.]+\]|[a-z0-9._-]+)(?::(?P<port>[0-9]{1,5}))?")
_EVENT_STREAM: Final = b"text/event-stream"


class ConfigurationError(Exception):
    """An edge configuration this adapter cannot serve. The message says what to change."""


class _BodyBoundError(Exception):
    """The body of a request broke a transport bound while it was being read. Nothing was parsed."""

    def __init__(self, reply: Reply) -> None:
        super().__init__(reply.status)
        self.reply = reply


class _ClientGoneError(Exception):
    """The caller closed the connection before its request was whole. There is nobody to answer."""


def _split_host(value: str) -> tuple[str, int | None] | None:
    """A ``Host`` value as its name and its port, or nothing when it is not one."""
    match = _HOST.fullmatch(value.strip().lower())
    if match is None:
        return None
    port = match.group("port")
    return match.group("name"), int(port) if port is not None else None


@dataclass(frozen=True, slots=True)
class Settings:
    """What the adapter needs from an edge configuration, checked, in the form it is used in."""

    path: str
    max_body_bytes: int
    body_read_timeout: float
    #: Milliseconds the core has for one command: the tool wait plus the margin between edge and core.
    budget_ms: int
    #: ``Host`` names answered on any port, and name-and-port pairs answered on that port only.
    hosts: frozenset[str]
    hosts_with_port: frozenset[tuple[str, int]]
    origins: frozenset[str]
    #: Path and bytes of the protected-resource metadata, when a resource is configured.
    metadata: tuple[str, bytes] | None

    @classmethod
    def from_config(cls, config: EdgeConfig) -> Settings:
        mcp, limits = config.mcp, config.limits
        if mcp.serve_2025_11_25:
            raise ConfigurationError(
                "mcp.serve_2025_11_25 is true, and revision 2025-11-25 of the protocol is not implemented in "
                f"this build. Set it to false: the adapter then serves revision {REVISION} only."
            )
        if config.tls is None and not is_loopback(config.listen.host):
            raise ConfigurationError(
                "without `tls` the adapter listens on a loopback address only, and listen.host is "
                f"{config.listen.host}. Configure `tls`, or listen on 127.0.0.1 behind a proxy on the same "
                "machine that terminates TLS."
            )
        budget_ms = math.ceil((mcp.tool_wait + limits.edge_core_deadline_margin) * 1000)
        try:
            request_context(new_request_id(), budget_ms)
        except ValidationError as e:
            raise ConfigurationError(
                "mcp.tool_wait plus limits.edge_core_deadline_margin is longer than one command may wait "
                "for the core. Lower one of them."
            ) from e
        metadata: tuple[str, bytes] | None = None
        if mcp.resource is not None:
            if not mcp.authorization_servers:
                raise ConfigurationError(
                    "mcp.resource is set and mcp.authorization_servers is empty. The metadata of a protected "
                    "resource names at least one authorization server: list it, or remove mcp.resource."
                )
            metadata = (metadata_path(mcp.resource), metadata_document(mcp))
        hosts, hosts_with_port = cls._hosts(config)
        return cls(
            path=mcp.path,
            max_body_bytes=limits.max_public_request_bytes,
            body_read_timeout=limits.body_read_timeout,
            budget_ms=budget_ms,
            hosts=hosts,
            hosts_with_port=hosts_with_port,
            origins=frozenset(origin.strip().rstrip("/").lower() for origin in mcp.allowed_origins),
            metadata=metadata,
        )

    @staticmethod
    def _hosts(config: EdgeConfig) -> tuple[frozenset[str], frozenset[tuple[str, int]]]:
        """The ``Host`` values the endpoint answers to.

        The configured list, when there is one. Otherwise the listen address and ``localhost``, and the
        authority of the configured resource: it is the name the deployment publishes for itself.
        """
        mcp = config.mcp
        entries = list(mcp.allowed_hosts)
        if not entries:
            listen = config.listen.host
            entries = [f"[{listen}]" if ":" in listen and not listen.startswith("[") else listen, "localhost"]
            if mcp.resource is not None:
                authority = mcp.resource.partition("://")[2].partition("/")[0]
                entries.append(authority.rpartition("@")[2])
        any_port: set[str] = set()
        pinned: set[tuple[str, int]] = set()
        for entry in entries:
            parsed = _split_host(entry)
            if parsed is None:
                raise ConfigurationError(
                    f"`{entry}` is not a host or a host:port pair (mcp.allowed_hosts, mcp.resource)"
                )
            name, port = parsed
            if port is None:
                any_port.add(name)
            else:
                pinned.add((name, port))
        return frozenset(any_port), frozenset(pinned)


def _bearer(scope: Scope) -> str | None:
    """The credential of a request: the ``Authorization: Bearer`` header and nothing else."""
    header = single_header(scope, b"authorization")
    if header is None:
        return None
    scheme, _, value = header.partition(" ")
    value = value.strip()
    if scheme.lower() != "bearer" or not value or len(value) > _CREDENTIAL_MAX or not value.isascii():
        return None
    return value


def _is_event_stream(message: Message) -> bool:
    return any(k == b"content-type" and v.startswith(_EVENT_STREAM) for k, v in message.get("headers", ()))


def _too_large(limit: int) -> Reply:
    return rpc_error(413, types.INVALID_REQUEST, f"the request body exceeds {limit} bytes")


class _Watched:
    """The two directions of one authenticated request, between the server and the SDK's transport.

    Inward, the body is held to its bounds as it arrives. Outward, an error of the core that belongs at
    the HTTP level is given there, and it is noted whether the last chunk of a result the core tracks
    was handed over while the caller was still there.
    """

    def __init__(self, exchange: Exchange, receive: Receive, send: Send, settings: Settings) -> None:
        self._exchange = exchange
        self._receive = receive
        self._send = send
        self._max_body_bytes = settings.max_body_bytes
        self._body_deadline = asyncio.get_running_loop().time() + settings.body_read_timeout
        self._received = 0
        self._body_read = False

    async def receive(self) -> Message:
        if self._body_read:
            message = await self._receive()
        else:
            try:
                async with asyncio.timeout_at(self._body_deadline):
                    message = await self._receive()
            except TimeoutError:
                slow = rpc_error(400, types.INVALID_REQUEST, "the request body did not arrive in time")
                raise _BodyBoundError(slow) from None
        if message["type"] == "http.request":
            self._received += len(message.get("body", b""))
            if self._received > self._max_body_bytes:
                raise _BodyBoundError(_too_large(self._max_body_bytes))
            self._body_read = not message.get("more_body", False)
        elif message["type"] == "http.disconnect":
            self._exchange.disconnected = True
            if not self._body_read:
                # Half a request is not handed on to be parsed.
                raise _ClientGoneError
        return message

    async def send(self, message: Message) -> None:
        exchange = self._exchange
        if message["type"] == "http.response.start":
            if exchange.http_error is not None and not _is_event_stream(message):
                # The response has not begun, so the core's error can still be an HTTP answer.
                exchange.replaced = True
                await render.http_refusal(exchange.http_error, exchange.rpc_id).send(self._send, exchange.request_id)
                return
            identified = [*message.get("headers", ()), (b"x-request-id", exchange.request_id.encode("ascii"))]
            await self._send({**message, "headers": identified})
        elif exchange.replaced:
            # The SDK's own body for an answer that was given in its place.
            return
        elif message.get("more_body", False) or exchange.delivery is None:
            await self._send(message)
        else:
            # The last chunk of a result the core wants a delivery report for. One turn of the loop lets
            # a disconnect the server has already seen reach `receive` before it is judged.
            await asyncio.sleep(0)
            still_there = not exchange.disconnected
            await self._send(message)
            exchange.written_in_full = still_there


class Gateway:
    """The ASGI application of the MCP adapter, over one client of the command interface.

    One instance serves one process for its whole life: the SDK's transport cannot be started twice.
    """

    def __init__(self, core: CoreClient, config: EdgeConfig) -> None:
        self.settings: Final = Settings.from_config(config)
        self._core = core
        self._transport = StreamableHTTPSessionManager(
            app=Relay(core, self.settings.budget_ms).server(),
            # An event stream for a call that outlasts the SDK's deferral window, a JSON object otherwise.
            json_response=False,
            stateless=True,
            # Host and Origin are checked by this layer, earlier and once.
            security_settings=TransportSecuritySettings(enable_dns_rebinding_protection=False),
            max_request_body_size=self.settings.max_body_bytes,
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self._lifespan(receive, send)
        elif scope["type"] == "http":
            await self._http(scope, receive, send)

    async def _lifespan(self, receive: Receive, send: Send) -> None:
        await receive()
        try:
            async with self._transport.run():
                await send({"type": "lifespan.startup.complete"})
                await receive()
        finally:
            await self._core.aclose()
        await send({"type": "lifespan.shutdown.complete"})

    # ------------------------------------------------------------------ every request
    async def _http(self, scope: Scope, receive: Receive, send: Send) -> None:
        refusal = self._transport_refusal(scope)
        if refusal is not None:
            await refusal.send(send)
        elif scope["path"] == self.settings.path:
            await self._endpoint(scope, receive, send)
        elif self.settings.metadata is not None and scope["path"] == self.settings.metadata[0]:
            await self._metadata(scope, send, self.settings.metadata[1])
        else:
            # Not the MCP endpoint: no JSON-RPC body, which would say that a modern endpoint is here.
            await Reply(404).send(send)

    def _transport_refusal(self, scope: Scope) -> Reply | None:
        """Bounds, then the two checks against DNS rebinding. Nothing here depends on who is asking."""
        for declared in header_values(scope, b"content-length"):
            if not declared.isascii() or not declared.isdigit():
                return rpc_error(400, types.INVALID_REQUEST, "the Content-Length header is not a number")
            digits = declared.lstrip("0")
            if len(digits) > _LENGTH_DIGITS_MAX or int(digits or "0") > self.settings.max_body_bytes:
                return _too_large(self.settings.max_body_bytes)
        host = single_header(scope, b"host")
        parsed = _split_host(host) if host is not None else None
        if parsed is None or not (parsed[0] in self.settings.hosts or parsed in self.settings.hosts_with_port):
            return rpc_error(
                421,
                types.INVALID_REQUEST,
                "this endpoint does not answer to that Host; "
                "an operator lists the names it answers to in mcp.allowed_hosts",
            )
        origins = header_values(scope, b"origin")
        if origins and (len(origins) > 1 or origins[0].strip().lower() not in self.settings.origins):
            return rpc_error(
                403,
                types.INVALID_REQUEST,
                "this Origin may not call this endpoint; an operator lists the origins that may in mcp.allowed_origins",
            )
        return None

    @staticmethod
    async def _metadata(scope: Scope, send: Send, document: bytes) -> None:
        if scope["method"] != "GET":
            await rpc_error(
                405, types.INVALID_REQUEST, "this document is read with GET", headers=((b"allow", b"GET"),)
            ).send(send)
            return
        await Reply(200, document).send(send)

    # ------------------------------------------------------------------ the MCP endpoint
    @staticmethod
    def _revision_refusal(scope: Scope) -> Reply | None:
        """The protocol's own errors for a revision this endpoint does not serve.

        A request without the header is how a client of an earlier revision arrives, and it has no way
        forward: the message names the revision that is served, which may be all its user gets to see.
        It is also how a current client arrives after it has fallen back from a request that failed for
        another reason, and then this message is shown in place of that reason. It says so.
        """
        versions = header_values(scope, b"mcp-protocol-version")
        if not versions:
            return rpc_error(
                400,
                types.HEADER_MISMATCH,
                f"the MCP-Protocol-Version header is required: this endpoint serves revision {REVISION} of the "
                "Model Context Protocol and no earlier one. A client that shows this after falling back from a "
                "request that failed was refused for another reason first, such as its credential",
            )
        if len(versions) > 1:
            return rpc_error(400, types.HEADER_MISMATCH, "the MCP-Protocol-Version header appears more than once")
        if versions[0] != REVISION:
            return rpc_error(
                400,
                types.UNSUPPORTED_PROTOCOL_VERSION,
                "Unsupported protocol version",
                data={"supported": [REVISION], "requested": versions[0][:_VERSION_ECHO_MAX]},
            )
        return None

    @staticmethod
    def _query_refusal(scope: Scope) -> Reply | None:
        query = scope.get("query_string", b"")
        if not query:
            return None
        names = {name.lower() for name, _ in parse_qsl(query.decode("latin-1"), keep_blank_values=True)}
        if names & _CREDENTIAL_PARAMS:
            message = (
                "a credential is never accepted in a URL: send it in the Authorization header, as `Bearer <credential>`"
            )
        else:
            message = "this endpoint takes no query parameters"
        return rpc_error(400, types.INVALID_REQUEST, message)

    async def _endpoint(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["method"] != "POST":
            await rpc_error(
                405, types.INVALID_REQUEST, "this endpoint answers POST only", headers=((b"allow", b"POST"),)
            ).send(send)
            return
        refusal = self._revision_refusal(scope) or self._query_refusal(scope)
        if refusal is not None:
            await refusal.send(send)
            return
        exchange = Exchange(credential=_bearer(scope), request_id=new_request_id())
        # Authentication precedes decoding: the core is asked before a byte of the body is read.
        verified = await self._core.verify(
            exchange.credential, request_context(exchange.request_id, self.settings.budget_ms)
        )
        if isinstance(verified, ErrorAnswer):
            await render.http_refusal(verified).send(send, exchange.request_id)
            return
        if not isinstance(verified, VerifiedAnswer):
            _LOG.error(
                "unexpected_answer", extra={"fields": {"request_id": exchange.request_id, "kind": verified.kind}}
            )
            await rpc_error(500, types.INTERNAL_ERROR, "the platform could not check the credential").send(
                send, exchange.request_id
            )
            return
        await self._relay(exchange, scope, receive, send)

    async def _relay(self, exchange: Exchange, scope: Scope, receive: Receive, send: Send) -> None:
        """Hand an authenticated request to the SDK's transport, and report its delivery afterwards."""
        watched = _Watched(exchange, receive, send, self.settings)
        token = enter(exchange)
        try:
            await self._transport.handle_request(scope, watched.receive, watched.send)
        except _BodyBoundError as refused:
            # The body is read whole before anything is answered, so this can still be the answer.
            await refused.reply.send(send, exchange.request_id)
            return
        except _ClientGoneError:
            return
        finally:
            leave(token)
        await self._report_delivery(exchange)

    async def _report_delivery(self, exchange: Exchange) -> None:
        """Tell the core that a result was written in full. Written, not read: nothing proves reading."""
        if exchange.delivery is None or not exchange.written_in_full:
            return
        delivery_token, ctx = exchange.delivery
        try:
            await self._core.delivered(exchange.credential, ctx, delivery_token)
        except Exception as e:  # the answer was delivered whatever happens to the report
            # An unreported delivery is the safe direction: the core then treats an identical call that
            # follows as the same request, not as new work.
            _LOG.warning(
                "delivery_not_reported",
                extra={"fields": {"request_id": exchange.request_id, "error": type(e).__name__}},
            )


def create_app(core: CoreClient, config: EdgeConfig) -> Gateway:
    """The ASGI application of the MCP adapter.

    Raises :class:`ConfigurationError` for a configuration the adapter cannot serve.
    """
    return Gateway(core, config)
