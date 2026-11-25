"""What the span of one command is called and what it carries.

The core emits one server span for every command, when the operator installed OpenTelemetry, as a child
of the trace the caller named (W3C ``traceparent``: a header for REST, ``params._meta`` for the agent
protocol; the edge extracts it and passes it in the request context).

For the agent protocol the names are the OpenTelemetry conventions for MCP server spans. They are in
Development status, so the version the code follows is pinned in the configuration
(``telemetry.mcp_semconv``) and written out here rather than assumed:

* the span is named after the method, followed by the tool for a call (``tools/call sandbox_exec``);
* ``mcp.method.name`` always; ``mcp.protocol.version``; ``network.transport``;
* for a call of a tool of the catalogue: ``gen_ai.tool.name`` and ``gen_ai.operation.name`` =
  ``execute_tool``;
* ``error.type`` = ``tool_error`` when the result of a call says ``isError``. A request the caller got
  wrong (an unknown tool, arguments that do not fit) is not an error of the server.

A tool name is a label only when it names a tool of the catalogue. What a caller typed never becomes a
span name or an attribute, and neither does an argument, a result or a credential.
"""

from __future__ import annotations

from typing import Final

from acf_api.command import commands as c
from acf_api.command.answers import Answer, ErrorAnswer, RequestContext, ToolAnswer
from acf_api.command.errors import http_status
from acf_api.core.agent import catalog

INTERFACE_MCP: Final = "mcp"
#: The methods of the agent protocol, by the command that carries each.
MCP_METHODS: Final = {"call_tool": "tools/call", "list_tools": "tools/list", "discover": "server/discover"}
TOOL_ERROR: Final = "tool_error"
_SERVER_ERRORS: Final = 500


def span_of(ctx: RequestContext, command: c.Command) -> tuple[str, dict[str, str | int | bool]]:
    """The name and the attributes of the server span of one command."""
    attributes: dict[str, str | int | bool] = {"acf.command": command.type, "acf.interface": ctx.interface}
    method = MCP_METHODS.get(command.type) if ctx.interface == INTERFACE_MCP else None
    if method is None:
        attributes["acf.api_version"] = ctx.interface_version
        return command.type, attributes
    attributes["mcp.method.name"] = method
    attributes["mcp.protocol.version"] = ctx.interface_version
    attributes["network.transport"] = "tcp"
    if isinstance(command, c.CallTool) and command.name in catalog.TOOLS:
        attributes["gen_ai.tool.name"] = command.name
        attributes["gen_ai.operation.name"] = "execute_tool"
        return f"{method} {command.name}", attributes
    return method, attributes


def error_type(answer: Answer) -> str | None:
    """The ``error.type`` of a span, or ``None`` when the server did what it was asked.

    A refusal is an answer: the caller asked for something it may not have, or that cannot be done now.
    On a server span that is not an error, as a 4xx is not. What is one: a tool result that says so, and
    an answer of the class of a 5xx, in which the platform or the host failed the caller.
    """
    if isinstance(answer, ToolAnswer):
        return TOOL_ERROR if answer.is_error else None
    if isinstance(answer, ErrorAnswer) and http_status(answer.error.code, answer.error.retry) >= _SERVER_ERRORS:
        return answer.error.code
    return None
