# acf-mcp-gateway

The MCP adapter of Agent Compute Fabric: the process that lets agents and agent hosts use the platform
through the Model Context Protocol.

It is an **edge process**. It holds no host credential, no store and no secret but its TLS key, and it
imports nothing of the core. It frames MCP messages and relays them to the core over the command
interface. Every decision and every tool semantic is the core's: this process authenticates nobody,
authorizes nothing, mints no idempotency key, retries nothing, validates no tool argument against a
schema, and holds no table of scopes or grants.

| | |
|---|---|
| Protocol | MCP revision `2026-07-28`, over Streamable HTTP, stateless |
| Methods | `server/discover`, `tools/list`, `tools/call` |
| Built on | the official Python SDK, `mcp` 2.3.0 (its low-level `Server` and its Streamable HTTP transport) |
| Command | `acf-mcp --config <edge.yaml>` |
| Import name | `acf_mcp` |

## Running it

```console
$ acf-mcp --config /etc/acf-platform/mcp.yaml
```

In a deployment the process is started by `acf-platform-mcp.service`, under an account of its own and
from an environment of its own; `docs/platform/OPERATIONS.md` is the operator's manual. A start that
the configuration makes impossible exits with status 78, which the unit does not restart on.

The configuration file is the edge configuration that `acf-api edge` reads
(`config/platform-edge.example.yaml`). The adapter uses the
shared sections (`listen`, `tls`, `command_socket`, `limits`, `log_level`) and the `mcp` section:

| Key | Default | What the adapter does with it |
|---|---|---|
| `mcp.path` | `/mcp` | The one path of the MCP endpoint. |
| `mcp.allowed_origins` | none | An `Origin` header that is present and not listed is answered `403`. A request without one is served. |
| `mcp.allowed_hosts` | see below | The `Host` values the endpoint answers to; any other is answered `421`. |
| `mcp.resource` | unset | When set, the canonical URI of the endpoint: its protected-resource metadata is served (see below). |
| `mcp.authorization_servers` | none | Listed in that metadata. Required when `mcp.resource` is set. |
| `mcp.scopes_supported` | none | Listed in that metadata. Used for nothing else. |
| `mcp.tool_wait` | `25` s | With `limits.edge_core_deadline_margin`, how long the adapter waits for the core's answer to one command. Set it to the core's `mcp_tool_wait`. |
| `mcp.serve_2025_11_25` | `false` | Must stay `false`: see "Not in this build". |

Without `mcp.allowed_hosts`, the endpoint answers to the listen address, to `localhost`, and to the
authority of `mcp.resource` when one is configured. An entry without a port matches any port.

The adapter refuses to start, with a message that says what to change, when: `mcp.serve_2025_11_25` is
true; `tls` is absent and `listen.host` is not a loopback address; the tool wait plus the margin is
longer than a command can carry; `mcp.resource` is set without an authorization server; or an entry of
`mcp.allowed_hosts` is not a host. Like every edge process, it also refuses to run as root.

The transport bounds of the server (`edge_max_connections`, `edge_max_header_bytes`,
`keep_alive_timeout`) are set on the HTTP server; `max_public_request_bytes` and `body_read_timeout`
are enforced by the adapter as a body arrives.

## What happens to a request

Before the SDK sees a request, the adapter's own layer does, in this order:

1. **Transport bounds.** A declared body length above `max_public_request_bytes`: `413`.
2. **Host and Origin.** Not an allowed `Host`: `421`. An `Origin` that is present and not allowed: `403`.
3. **Method.** Anything but `POST` on the endpoint: `405` with `Allow: POST`.
4. **Protocol revision.** No `MCP-Protocol-Version` header: `400` with JSON-RPC error `-32020`. A
   revision other than `2026-07-28`: `400` with `-32022` and the list of supported revisions.
5. **Credential.** Read from `Authorization: Bearer` and nowhere else. A request with a query string
   is refused (`400`): a credential is never accepted in a URL.
6. **The credential check, asked of the core.** A credential that does not authenticate: `401`, with
   the `WWW-Authenticate` value the core computed.

Only then is the body read, bounded as it arrives, and handed to the SDK, which checks the envelope
and the `Mcp-Method` and `Mcp-Name` headers against the body and dispatches to one of three handlers.
Each handler sends exactly one command to the core and renders its answer:

| The core answers | The caller receives |
|---|---|
| a tool catalogue | `tools/list`: each tool's `name`, `title`, `description`, `inputSchema`, `outputSchema` and `annotations`, in one page |
| a tool result | `tools/call`: `structuredContent`, one text block that is exactly its JSON, and `isError` as the core set it |
| a protocol fault (unknown tool, arguments that fail the input schema) | JSON-RPC error `-32602` |
| a refusal or an unresolved outcome of a call | a result with `isError: true` and `structuredContent` `{"ok": false, "error": {...}}` |
| an error that carries a challenge | `401` or `403` with the core's `WWW-Authenticate`: the two HTTP answers of MCP authorization |
| an error to `tools/list` or `server/discover` | a JSON-RPC error with the platform's error members in `data`, at the HTTP status of its code |
| what the platform offers | `server/discover`: `supportedVersions`, `instructions`, the server's name and version, and the features under `capabilities.experimental.acf` |

When the core does not answer a call that can create work, the command client answers
`OUTCOME_UNRESOLVED`. It is rendered like any other error and is never turned into a refusal.

A challenge is answered `401` when its code is `UNAUTHENTICATED` and `403` otherwise. The HTTP status
can only be given while the response has not begun: on an event stream that is already open, the
challenge of a call is rendered as the `isError` result every other refusal of a call is.

A refusal that the adapter's own layer gives before the body is read carries a JSON-RPC error body
whose `id` is `null`: the request's id is not known yet. A body that grows past
`max_public_request_bytes` is answered `413` and one that does not arrive within `body_read_timeout`
`400`. A path that is not served is answered `404` with no body. Answers to requests that reached the
core carry `X-Request-Id`, the id under which the core recorded the request.

### Text an agent did not write

The text of a result is the JSON serialization of its `structuredContent` and nothing else, written in
printable ASCII: every other character is escaped. A string that a guest produced, or that another
principal chose, therefore reaches an agent only as a JSON string value, and cannot put a line break,
an invisible character or a direction override in front of it.

### Delivery, and a closed stream

For a call whose result the core tracks, the adapter tells the core once the result has been written
in full to the transport. Closing the stream before that cancels the call's wait in the adapter and
nothing else: no report is made, nothing is cancelled, and no other message goes to the core. The
operation the call started keeps running; ending it is an explicit call of its own.

A call that outlasts the SDK's deferral window (15 seconds) is answered on an event stream that is kept
open with comment lines; a shorter one is answered with a single JSON object.

### Protected-resource metadata

With `mcp.resource` set, the adapter serves OAuth 2.0 Protected Resource Metadata (RFC 9728) at
`/.well-known/oauth-protected-resource` followed by the path of the resource, the address the core
names in its challenges. The document lists the authorization servers and the scopes from the
configuration. It tells a client where to get a token; whether a token is accepted is decided by the
core, which verifies it. The adapter verifies none.

## Not in this build

- **Revision `2025-11-25`.** Not implemented. With `mcp.serve_2025_11_25: true` the adapter refuses to
  start. With the default, a request of that revision, or one without a revision header, is refused
  with the protocol's error, and no code path of the SDK for earlier revisions is reachable.
- **The MCP tasks extension.** Not implemented, and nothing advertises it.
- **A stdio relay.** It belongs to the `acf` command-line tool.
- **Cross-origin browser clients.** `OPTIONS` is answered `405` like every method but `POST`, so a
  preflight fails. `mcp.allowed_origins` governs the `Origin` check only.
- **Telemetry.** The adapter emits none. The caller's trace context (`traceparent` in `_meta`) is
  passed to the core.

## What a developer may run into

The official Python client, in its default mode, falls back to the handshake of earlier revisions when
its first request fails for any reason. A wrong credential is then reported as the adapter's refusal of
that handshake (`-32020`), not as the `401` that caused it. Constructing the client with
`mode="2026-07-28"` shows the real answer.

## Choices the SDK imposed

- The SDK validates `Mcp-Param-*` headers by listing the tools through the server's own handler before
  every call with arguments. That would be a second command to the core for one request, so the
  adapter tells the SDK that no tool mirrors a parameter into a header. The catalogue declares none;
  a test fails if that changes.
- The SDK's default telemetry middleware names a span after `params.name` as the caller sent it,
  before anything has checked it. It is removed.
- The SDK stamps every result with the identity given to its server at construction, before any
  answer of the core exists. That identity is this package's name and version; `server/discover`
  carries the name and version the core reports.
- The window after which a response becomes an event stream, and the interval of its keep-alives, are
  a constant of the SDK (15 seconds) and are not configurable.
- The SDK's own Host and Origin check is switched off: the adapter performs it earlier, before the
  credential check, with the configured lists.

## Development

From this directory, with `uv` installed (the lock fixes every version and every file by its hash):

```console
$ uv run --locked ruff check . && uv run --locked ruff format --check .
$ uv run --locked mypy
$ uv run --locked pytest -q
```

From the repository root, `make platform-lint` and `make platform-test` run the same commands for
every Python project of the platform.

The tests open no socket. The adapter is driven as an ASGI application over a scripted core, by an
HTTP client, by the official SDK's own client, and by a hand-driven exchange that decides when a body
arrives and when the client goes away.

| Module | What it holds |
|---|---|
| `acf_mcp.gateway` | the adapter's own layer in front of the SDK's transport, and the application |
| `acf_mcp.relay` | the three handlers, each one command to the core |
| `acf_mcp.render` | the core's answers in the protocol's shapes |
| `acf_mcp.exchange` | what one request carries between the layer and the handlers; the request context |
| `acf_mcp.metadata` | the protected-resource metadata document and the path it is served at |
| `acf_mcp.asgi` | the ASGI shapes used, and how the adapter writes an answer of its own |
| `acf_mcp.server`, `acf_mcp.cli` | the HTTP server settings and the `acf-mcp` command |
