"""The few ASGI shapes this adapter touches, and how it writes an answer of its own.

An answer of this adapter's own layer is given before the protocol's request id is known: the body has
not been read. Its body is therefore a JSON-RPC error response whose ``id`` is ``null``, the form the
official SDK's own transport uses for a request it refuses at the HTTP level, and the one its client
reads back.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Iterable, MutableMapping
from dataclasses import dataclass
from typing import Any, Final

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
App = Callable[[Scope, Receive, Send], Awaitable[None]]

#: The id of a JSON-RPC request, as a caller chose it.
RpcId = int | str

_JSON: Final = b"application/json"


def header_values(scope: Scope, name: bytes) -> list[str]:
    """Every value of one request header, in the order sent. A server hands header names over in lower case."""
    return [value.decode("latin-1") for key, value in scope["headers"] if key == name]


def single_header(scope: Scope, name: bytes) -> str | None:
    """The value of a header sent exactly once. Sent twice, two readers could disagree, so it counts as not sent."""
    values = header_values(scope, name)
    return values[0] if len(values) == 1 else None


@dataclass(frozen=True, slots=True)
class Reply:
    """A complete HTTP answer of this adapter's own."""

    status: int
    body: bytes = b""
    headers: tuple[tuple[bytes, bytes], ...] = ()

    def start(self, request_id: str | None = None) -> Message:
        headers: list[tuple[bytes, bytes]] = [
            (b"content-length", str(len(self.body)).encode("ascii")),
            (b"cache-control", b"no-store"),
            *self.headers,
        ]
        if self.body:
            headers.insert(0, (b"content-type", _JSON))
        if request_id is not None:
            headers.append((b"x-request-id", request_id.encode("ascii")))
        return {"type": "http.response.start", "status": self.status, "headers": headers}

    def end(self) -> Message:
        return {"type": "http.response.body", "body": self.body, "more_body": False}

    async def send(self, send: Send, request_id: str | None = None) -> None:
        await send(self.start(request_id))
        await send(self.end())


def rpc_error(  # noqa: PLR0913 - the members of one error response
    status: int,
    code: int,
    message: str,
    *,
    data: Any = None,  # noqa: ANN401 - JSON-RPC defines `data` as any JSON value
    rpc_id: RpcId | None = None,
    headers: Iterable[tuple[bytes, bytes]] = (),
) -> Reply:
    """An HTTP answer whose body is one JSON-RPC error response."""
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    # ``id`` is written even when it is null: JSON-RPC 2.0 requires the member in an error response.
    body = json.dumps({"jsonrpc": "2.0", "id": rpc_id, "error": error}, separators=(",", ":"), allow_nan=False)
    return Reply(status, body.encode("ascii"), tuple(headers))
