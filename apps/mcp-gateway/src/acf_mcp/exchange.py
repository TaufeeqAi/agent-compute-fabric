"""One HTTP request on its way through the adapter, and the context it gives the core.

The adapter's own layer and the handlers that run inside the SDK meet here. The layer authenticates
nothing and decides nothing, but it is the only place that holds the caller's credential, and it is
the one that knows what was written to the transport. The handlers know what the core answered. An
:class:`Exchange` carries those facts between the two for the life of one request, and no longer.

The credential lives in this object and in the commands sent to the core, and nowhere else. It is kept
out of the object's ``repr`` so that no log line and no traceback can carry it.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from typing import Any, Final

from pydantic import ValidationError

from acf_api.command.answers import TRACEPARENT_PATTERN, ClientInfo, ErrorAnswer, RequestContext
from acf_mcp.asgi import RpcId

#: The one revision of the Model Context Protocol this adapter serves.
REVISION: Final = "2026-07-28"

#: Reserved keys of a request's ``_meta`` (basic protocol, "Per-request protocol fields").
CLIENT_INFO_KEY: Final = "io.modelcontextprotocol/clientInfo"
TRACEPARENT_KEY: Final = "traceparent"

_CLIENT_NAME_MAX: Final = 64
_CLIENT_VERSION_MAX: Final = 32
_TRACEPARENT: Final = re.compile(TRACEPARENT_PATTERN)
#: W3C Trace Context forbids these three values although they have the right shape.
_NO_VERSION: Final = "ff"
_NO_TRACE: Final = "0" * 32
_NO_PARENT: Final = "0" * 16


@dataclass(slots=True)
class Exchange:
    """What one request carries between the adapter's layer and the handlers."""

    #: The caller's credential, exactly as presented. Passed to the core with every command; never shown.
    credential: str | None = field(repr=False)
    request_id: str
    #: The JSON-RPC id of the request, once a handler has seen it.
    rpc_id: RpcId | None = None
    #: An error answer of the core that is to be given at the HTTP level, if the response has not begun.
    http_error: ErrorAnswer | None = None
    #: The delivery token of a tool result and the context it was produced under, until it is reported.
    delivery: tuple[str, RequestContext] | None = field(default=None, repr=False)
    #: The server told the application that the client is gone.
    disconnected: bool = False
    #: The answer was given by this adapter's layer in place of the SDK's.
    replaced: bool = False
    #: The last chunk of the answer was handed to the server while the client was still there.
    written_in_full: bool = False


_CURRENT: Final[ContextVar[Exchange]] = ContextVar("acf_mcp_exchange")


def enter(exchange: Exchange) -> Token[Exchange]:
    """Make ``exchange`` the one the handlers of this task, and of the tasks it starts, will see."""
    return _CURRENT.set(exchange)


def leave(token: Token[Exchange]) -> None:
    _CURRENT.reset(token)


def current() -> Exchange:
    """The exchange a handler runs in. Every handler runs under the adapter's layer, which sets it."""
    try:
        return _CURRENT.get()
    except LookupError:
        msg = "a handler ran outside the adapter's own layer"
        raise RuntimeError(msg) from None


def client_info(meta: Mapping[str, Any] | None) -> ClientInfo:
    """What the client says it is. Bounded, checked, and used by the core for audit only.

    A value that does not fit is dropped whole rather than cleaned up: a client's description of itself
    is never worth guessing at.
    """
    info = meta.get(CLIENT_INFO_KEY) if meta is not None else None
    if not isinstance(info, Mapping):
        return ClientInfo()
    name, version = info.get("name"), info.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        return ClientInfo()
    try:
        return ClientInfo(name=name.strip()[:_CLIENT_NAME_MAX], version=version.strip()[:_CLIENT_VERSION_MAX])
    except ValidationError:
        return ClientInfo()


def trace_parent(meta: Mapping[str, Any] | None) -> str | None:
    """A valid W3C trace parent from ``_meta``, or nothing. An invalid one is ignored, never an error."""
    value = meta.get(TRACEPARENT_KEY) if meta is not None else None
    if not isinstance(value, str) or _TRACEPARENT.fullmatch(value) is None:
        return None
    version, trace_id, parent_id, _ = value.split("-")
    if version == _NO_VERSION or trace_id == _NO_TRACE or parent_id == _NO_PARENT:
        return None
    return value


def request_context(request_id: str, budget_ms: int, meta: Mapping[str, Any] | None = None) -> RequestContext:
    """The context of one request, as the command interface carries it."""
    return RequestContext(
        request_id=request_id,
        traceparent=trace_parent(meta),
        budget_ms=budget_ms,
        interface="mcp",
        interface_version=REVISION,
        client=client_info(meta),
    )
