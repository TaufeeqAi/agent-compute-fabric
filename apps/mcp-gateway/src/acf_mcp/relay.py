"""The three methods this adapter serves, each of them one command to the core.

``tools/list`` is ``ListTools``, ``tools/call`` is ``CallTool`` and ``server/discover`` is ``Discover``.
A handler frames: it turns the protocol's request into the command, sends it with the caller's
credential, and renders the answer. It does nothing else, and in particular:

* it validates no argument. The core holds the schemas and answers a protocol fault for a bad call;
* it mints no key, retries nothing and adopts nothing. A call that is repeated is sent again as it is;
* when a call's wait is cancelled, because the caller closed the stream, the wait ends and nothing is
  sent to the core. The operation the call started is the caller's to cancel, with a call of its own.

The SDK's low-level server is used for what it owns: the shapes of the protocol's messages, the
per-request envelope and the Streamable HTTP transport. Two of its defaults are switched off, for the
reasons given in :meth:`Relay.server`.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any, Final

from mcp import MCPError, types
from mcp.server import Server, ServerRequestContext
from pydantic import ValidationError

from acf_api.command.answers import (
    Answer,
    DiscoverAnswer,
    ErrorAnswer,
    ProtocolFaultAnswer,
    RequestContext,
    ToolAnswer,
    ToolsAnswer,
)
from acf_api.command.client import CoreClient
from acf_api.command.commands import CallTool, Discover, ListTools
from acf_mcp import __version__, render
from acf_mcp.exchange import Exchange, current, request_context

_LOG: Final = logging.getLogger("acf_mcp")

#: The software that writes these responses. What the platform calls itself is the core's to say, and
#: `server/discover` says it.
SERVER_NAME: Final = "acf-mcp-gateway"

_Context = ServerRequestContext[Any, Any]


def _no_mirrored_parameters(_name: str) -> None:
    """Tell the SDK that no tool mirrors a parameter into an ``Mcp-Param`` header.

    Without this, the SDK lists the tools through this adapter's own handler before every call with
    arguments, to look for such parameters. That would be a second command to the core for one request
    of a caller. The catalogue declares none, and a test holds it to that.
    """
    return


class Relay:
    """The handlers, over one client of the command interface."""

    def __init__(self, core: CoreClient, budget_ms: int) -> None:
        self._core = core
        #: Milliseconds the core has for one command: the tool wait and the margin between edge and core.
        self._budget_ms = budget_ms

    def server(self) -> Server[Any]:
        """The SDK server these handlers are registered on."""
        server: Server[Any] = Server(
            SERVER_NAME,
            version=__version__,
            on_list_tools=self.list_tools,
            on_call_tool=self.call_tool,
            get_tool_input_schema=_no_mirrored_parameters,
        )
        # The SDK's own handler would answer from this process's state. What is advertised is the core's.
        server.add_request_handler("server/discover", types.RequestParams, self.discover)
        # The SDK starts a telemetry span for every message and names it after `params.name` as the
        # caller sent it, before anything has checked it. This process emits no telemetry of its own:
        # the caller's trace context goes to the core, which owns the platform's.
        server.middleware.clear()
        return server

    def _begin(self, ctx: _Context) -> tuple[Exchange, RequestContext]:
        exchange = current()
        exchange.rpc_id = ctx.request_id
        meta = ctx.params.get("_meta") if ctx.params is not None else None
        return exchange, request_context(
            exchange.request_id, self._budget_ms, meta if isinstance(meta, Mapping) else None
        )

    @staticmethod
    def _unknown(exchange: Exchange, answer: Answer) -> MCPError:
        _LOG.error("unexpected_answer", extra={"fields": {"request_id": exchange.request_id, "kind": answer.kind}})
        return MCPError(types.INTERNAL_ERROR, "the platform gave an answer this endpoint cannot render")

    async def list_tools(self, ctx: _Context, params: types.PaginatedRequestParams | None) -> types.ListToolsResult:
        if params is not None and params.cursor is not None:
            # The catalogue is one page, so no cursor was ever issued. The protocol's answer to that is this error.
            raise MCPError(types.INVALID_PARAMS, "the tool listing is one page: this cursor was not issued by it")
        exchange, rctx = self._begin(ctx)
        answer = await self._core.handle(exchange.credential, rctx, ListTools())
        if isinstance(answer, ToolsAnswer):
            return render.tools_result(answer)
        if isinstance(answer, ErrorAnswer):
            exchange.http_error = answer
            raise render.rpc_failure(answer)
        raise self._unknown(exchange, answer)

    async def discover(self, ctx: _Context, _params: types.RequestParams) -> types.DiscoverResult:
        exchange, rctx = self._begin(ctx)
        answer = await self._core.handle(exchange.credential, rctx, Discover())
        if isinstance(answer, DiscoverAnswer):
            return render.discover_result(answer)
        if isinstance(answer, ErrorAnswer):
            exchange.http_error = answer
            raise render.rpc_failure(answer)
        raise self._unknown(exchange, answer)

    async def call_tool(self, ctx: _Context, params: types.CallToolRequestParams) -> types.CallToolResult:
        exchange, rctx = self._begin(ctx)
        try:
            command = CallTool(name=params.name, arguments=params.arguments or {})
        except ValidationError:
            # Only the name can fail here. The error that pydantic raised quotes its input and is dropped.
            raise render.unknown_tool_name() from None
        answer = await self._core.handle(exchange.credential, rctx, command)
        if isinstance(answer, ToolAnswer):
            if answer.delivery_token is not None:
                # Reported by the adapter's layer, and only once the whole answer has been written.
                exchange.delivery = (answer.delivery_token, rctx)
            return render.tool_result(answer)
        if isinstance(answer, ProtocolFaultAnswer):
            raise render.protocol_fault(answer)
        if isinstance(answer, ErrorAnswer):
            if answer.challenge is not None:
                # One of the two answers of MCP authorization. It is given at the HTTP level when the
                # response has not begun; on a stream that has, the result below is all that can be sent.
                exchange.http_error = answer
            return render.refusal_result(answer)
        raise self._unknown(exchange, answer)
