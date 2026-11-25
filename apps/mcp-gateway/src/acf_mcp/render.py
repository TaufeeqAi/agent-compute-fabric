"""What the core answered, in the shapes of the Model Context Protocol.

Rendering and nothing else: every function here takes one answer of the core and returns its protocol
form. None reads a schema, none looks at a grant, and none changes what was answered.

Two rules of the platform are carried out here, because this is where an answer becomes text.

* **The text of a result is the JSON of its structured content and nothing else.** A string a guest
  produced, or another principal chose, therefore reaches an agent only as a JSON string value. The
  JSON is written in printable ASCII: every other character is escaped. A guest cannot place a line
  break, an invisible character or a direction override in front of an agent, only their escapes.
* **An unsuccessful outcome of a tool call is a result an agent can read**, with ``isError`` set and
  the members every error of the platform carries. A JSON-RPC error is kept for faults of the protocol
  itself, and the HTTP status for the two answers that MCP authorization defines.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Final

from mcp import MCPError, types

from acf_api.command.answers import (
    DiscoverAnswer,
    ErrorAnswer,
    ProtocolFaultAnswer,
    ToolAnswer,
    ToolDefinition,
    ToolsAnswer,
)
from acf_api.command.errors import http_status
from acf_mcp.asgi import Reply, RpcId, rpc_error
from acf_mcp.exchange import REVISION

_LOG: Final = logging.getLogger("acf_mcp")

#: Where `server/discover` advertises what the platform and its host offer: one entry of the
#: capabilities the protocol reserves for what it does not define (`capabilities.experimental`).
EXPERIMENTAL_KEY: Final = "acf"

_UNAUTHORIZED: Final = 401
_FORBIDDEN: Final = 403
_CLIENT_ERRORS: Final = range(400, 500)
_INTERNAL: Final = 500
#: A header value this process is willing to write: printable ASCII, so that no answer can be split.
_HEADER_VALUE: Final = re.compile(r"[\x20-\x7e]+")


def text_of(structured: dict[str, Any]) -> str:
    """The text form of a result: the JSON serialization of its structured content, in printable ASCII.

    Asked for ASCII, ``json`` escapes every character outside U+0020 to U+007E, so what a string holds
    can only appear as itself when it is a printable character, and as an escape otherwise. A value
    JSON does not define (``NaN``, an infinity) is refused rather than written.
    """
    return json.dumps(structured, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _result(structured: dict[str, Any], *, is_error: bool) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=text_of(structured))],
        structured_content=structured,
        is_error=is_error,
    )


def tool_result(answer: ToolAnswer) -> types.CallToolResult:
    """The result of a tool call, exactly as the core produced it."""
    return _result(answer.structured, is_error=answer.is_error)


def error_members(answer: ErrorAnswer) -> dict[str, Any]:
    """The members every error of the platform carries, on every interface."""
    return answer.error.model_dump(mode="json", exclude_none=True)


def refusal_result(answer: ErrorAnswer) -> types.CallToolResult:
    """A refusal or an unresolved outcome of a tool call, as a result an agent can read and act on."""
    return _result({"ok": False, "error": error_members(answer)}, is_error=True)


def protocol_fault(answer: ProtocolFaultAnswer) -> MCPError:
    """A fault of the protocol itself: the error the specification prescribes for an unknown tool or bad arguments."""
    return MCPError(types.INVALID_PARAMS, answer.message, {"fault": answer.fault})


def unknown_tool_name() -> MCPError:
    """A name no tool can have. The command interface cannot carry it, so the core is not asked."""
    return MCPError(
        types.INVALID_PARAMS,
        "no tool has such a name: a tool name is 1 to 64 characters from A-Z, a-z, 0-9, `_` and `-`",
        {"fault": "unknown_tool"},
    )


def _status(answer: ErrorAnswer) -> int:
    """The HTTP status of an error answer: the hint the platform's failure table gives its code.

    An answer that carries a challenge is one of the two answers of MCP authorization: 401 when the
    credential does not authenticate, and 403 otherwise.
    """
    status = http_status(answer.error.code, answer.error.retry)
    if answer.challenge is not None and status != _UNAUTHORIZED:
        return _FORBIDDEN
    return status


def _rpc_code(status: int) -> int:
    """The JSON-RPC code beside an HTTP status. The platform's own ``code`` is in the error's ``data`` and decides."""
    return types.INVALID_REQUEST if status in _CLIENT_ERRORS else types.INTERNAL_ERROR


def rpc_failure(answer: ErrorAnswer) -> MCPError:
    """An error answer to a request that has no result to carry it: listing the tools, or discovery."""
    return MCPError(_rpc_code(_status(answer)), answer.error.message, error_members(answer))


def http_refusal(answer: ErrorAnswer, rpc_id: RpcId | None = None) -> Reply:
    """An error answer given at the HTTP level, with the challenge the core computed, unchanged."""
    status = _status(answer)
    headers: list[tuple[bytes, bytes]] = []
    if answer.challenge is not None:
        challenge = answer.challenge.www_authenticate
        if _HEADER_VALUE.fullmatch(challenge) is None:
            _LOG.error("challenge_not_relayed", extra={"fields": {"request_id": answer.error.request_id}})
            return rpc_error(
                _INTERNAL,
                types.INTERNAL_ERROR,
                "the platform's answer could not be relayed",
                data={"request_id": answer.error.request_id},
                rpc_id=rpc_id,
            )
        headers.append((b"www-authenticate", challenge.encode("ascii")))
    elif status == _UNAUTHORIZED:
        # HTTP requires a challenge with this status. The scheme is the only one this endpoint reads.
        headers.append((b"www-authenticate", b"Bearer"))
    if answer.retry_after_s is not None:
        headers.append((b"retry-after", str(answer.retry_after_s).encode("ascii")))
    return rpc_error(
        status, _rpc_code(status), answer.error.message, data=error_members(answer), rpc_id=rpc_id, headers=headers
    )


def _tool(definition: ToolDefinition) -> types.Tool:
    return types.Tool(
        name=definition.name,
        title=definition.title,
        description=definition.description,
        input_schema=definition.input_schema,
        output_schema=definition.output_schema,
        annotations=types.ToolAnnotations(
            title=definition.title,
            read_only_hint=definition.read_only,
            destructive_hint=definition.destructive,
            idempotent_hint=definition.idempotent,
            open_world_hint=definition.open_world,
        ),
    )


def tools_result(answer: ToolsAnswer) -> types.ListToolsResult:
    """The tool catalogue the core projected for this credential, in one page and in the core's order.

    The listing depends on the credential and on what the host offers now, and nothing told to this
    process says how long it stays true. It is therefore marked private and immediately stale.
    """
    return types.ListToolsResult(tools=[_tool(d) for d in answer.tools], ttl_ms=0, cache_scope="private")


def discover_result(answer: DiscoverAnswer) -> types.DiscoverResult:
    """What the platform says about itself to this credential.

    The features are advertised under ``capabilities.experimental``, the place the protocol keeps for
    capabilities it does not define. No protocol extension is advertised: this adapter implements none.
    """
    identity = types.Implementation(name=answer.server_name, version=answer.server_version)
    return types.DiscoverResult(
        supported_versions=[REVISION],
        capabilities=types.ServerCapabilities(
            tools=types.ToolsCapability(list_changed=False),
            experimental={
                EXPERIMENTAL_KEY: {
                    "platform_features": list(answer.platform_features),
                    "host_features": list(answer.host_features),
                }
            },
        ),
        instructions=answer.instructions or None,
        ttl_ms=0,
        cache_scope="private",
        meta={types.SERVER_INFO_META_KEY: identity.model_dump(by_alias=True, mode="json", exclude_none=True)},
    )
