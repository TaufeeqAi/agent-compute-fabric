"""Answers of the core, and the envelope of one exchange on the command interface.

An answer is a view, an error (``REFUSED`` or ``UNRESOLVED``), a tool result, or the reply to a
credential check. The core never raises across the interface for an expected outcome.

The envelope carries what crosses between the two roles and nothing more: the caller's credential,
unchanged; a request id; the trace context; a time budget; the interface and its version; bounded
client information; the caller's idempotency key if it gave one; and one command.
"""

from __future__ import annotations

from typing import Annotated, Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from acf_api.command.commands import Command
from acf_api.command.model import ErrorBody

#: Version of the command interface. An edge and a core interoperate only inside the range the core declares.
COMMAND_INTERFACE_VERSION: Final = 1
COMMAND_INTERFACE_MIN: Final = 1
COMMAND_INTERFACE_MAX: Final = 1
COMMAND_PROTOCOL: Final = "acf.command"

IDEMPOTENCY_KEY_MIN: Final = 1
#: The hard cap of the wire. The operator's `idempotency_key_max_len` may be lower, never higher.
IDEMPOTENCY_KEY_HARD_MAX: Final = 255
#: A key is 1 to N characters, each in the range 0x21 to 0x7E. Compared byte for byte, never normalized.
IDEMPOTENCY_KEY_PATTERN: Final = r"^[\x21-\x7e]+$"

REQUEST_ID_PATTERN: Final = r"^req_[0-9A-Za-z]{16,40}$"
TRACEPARENT_PATTERN: Final = r"^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$"


class _Wire(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ClientInfo(_Wire):
    """What a client says about itself. Bounded, and used for audit and telemetry only."""

    name: Annotated[str, Field(max_length=64, pattern=r"^[A-Za-z0-9 ._/+-]*$")] = ""
    version: Annotated[str, Field(max_length=32, pattern=r"^[A-Za-z0-9 ._/+-]*$")] = ""


class RequestContext(_Wire):
    """The context of one public request."""

    request_id: Annotated[str, Field(pattern=REQUEST_ID_PATTERN)]
    #: A W3C trace parent. The edge drops a malformed one; it is never an error.
    traceparent: Annotated[str, Field(pattern=TRACEPARENT_PATTERN)] | None = None
    #: Milliseconds the core has to answer, counted from when it reads the command.
    budget_ms: Annotated[int, Field(ge=1, le=3_600_000)]
    interface: Literal["rest", "mcp", "mcp-stdio"]
    #: The public API version, or the agent-protocol revision.
    interface_version: Annotated[str, Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9._-]+$")]
    client: ClientInfo = Field(default_factory=ClientInfo)


class VerifyRequest(_Wire):
    """Asked before a request body is read: does this credential authenticate?"""

    op: Literal["verify"] = "verify"
    version: int
    #: Absent when the caller presented none. A frame leaves out a member that has no value, so the
    #: member must be readable when it is missing: a caller without a credential is still answered.
    credential: str | None = None
    ctx: RequestContext


class HandleRequest(_Wire):
    op: Literal["handle"] = "handle"
    version: int
    credential: str | None = None
    ctx: RequestContext
    idempotency_key: (
        Annotated[
            str,
            Field(min_length=IDEMPOTENCY_KEY_MIN, max_length=IDEMPOTENCY_KEY_HARD_MAX, pattern=IDEMPOTENCY_KEY_PATTERN),
        ]
        | None
    ) = None
    command: Command


class DeliveredRequest(_Wire):
    """Reported by an adapter when the result of a call has been written in full to its transport."""

    op: Literal["delivered"] = "delivered"
    version: int
    credential: str | None = None
    ctx: RequestContext
    delivery_token: Annotated[str, Field(min_length=8, max_length=96, pattern=r"^[A-Za-z0-9_-]+$")]


Request = Annotated[VerifyRequest | HandleRequest | DeliveredRequest, Field(discriminator="op")]
REQUEST_ADAPTER: Final[TypeAdapter[Request]] = TypeAdapter(Request)


class Challenge(_Wire):
    """What an adapter needs to build the challenge of an authentication or scope failure."""

    #: Value of ``WWW-Authenticate``, computed by the core. The adapter relays it and decides nothing.
    www_authenticate: str


class ViewAnswer(_Wire):
    """A resource view or an operation view."""

    kind: Literal["view"] = "view"
    #: Name of the view type in the public model, for example ``Operation``.
    view: str
    body: dict[str, Any]
    #: For an operation view: whether the operation has ended. ``None`` for other views.
    terminal: bool | None = None
    replayed: bool = False
    #: Seconds a caller should wait before it asks again, when the operation has not ended.
    retry_after_s: int | None = None
    etag: str | None = None
    #: Set when a new platform record was created (an agent credential).
    created: bool = False


class ErrorAnswer(_Wire):
    """A refusal or an unresolved outcome."""

    kind: Literal["error"] = "error"
    error: ErrorBody
    retry_after_s: int | None = None
    challenge: Challenge | None = None


class VerifiedAnswer(_Wire):
    """The credential authenticates. Nothing about the principal is told to the edge."""

    kind: Literal["verified"] = "verified"


class ToolDefinition(_Wire):
    """One tool of the agent interface, as the core projects it for a credential."""

    name: str
    title: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    read_only: bool
    destructive: bool
    idempotent: bool
    open_world: bool


class ToolsAnswer(_Wire):
    kind: Literal["tools"] = "tools"
    tools: list[ToolDefinition]


class ToolAnswer(_Wire):
    """The result of a tool call. Every unsuccessful outcome is a result with ``is_error`` set."""

    kind: Literal["tool"] = "tool"
    #: Conforms to the tool's output schema. Its JSON serialization is the only text form.
    structured: dict[str, Any]
    is_error: bool
    #: Present when the call created or adopted a request: the adapter reports delivery with it.
    delivery_token: str | None = None


class ProtocolFaultAnswer(_Wire):
    """A fault of the agent protocol itself: an unknown tool, or arguments that fail the input schema."""

    kind: Literal["protocol_fault"] = "protocol_fault"
    #: ``unknown_tool`` or ``invalid_arguments``.
    fault: Literal["unknown_tool", "invalid_arguments"]
    message: str


class DiscoverAnswer(_Wire):
    kind: Literal["discover"] = "discover"
    server_name: str
    server_version: str
    instructions: str
    platform_features: list[str]
    host_features: list[str]


class AckAnswer(_Wire):
    kind: Literal["ack"] = "ack"


Answer = Annotated[
    ViewAnswer
    | ErrorAnswer
    | VerifiedAnswer
    | ToolsAnswer
    | ToolAnswer
    | ProtocolFaultAnswer
    | DiscoverAnswer
    | AckAnswer,
    Field(discriminator="kind"),
]
ANSWER_ADAPTER: Final[TypeAdapter[Answer]] = TypeAdapter(Answer)


class Frame(_Wire):
    """One answer frame: the protocol, the version the core speaks, and the answer."""

    protocol: Literal["acf.command"] = "acf.command"
    version: int
    answer: Answer


FRAME_ADAPTER: Final[TypeAdapter[Frame]] = TypeAdapter(Frame)
