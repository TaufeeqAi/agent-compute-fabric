# Decision log — the developer platform

Decisions the platform's contract (version 1.1.0) leaves to the implementation, with the reasoning and
the way back. Where the contract itself decides (the pipeline order, the derivation of operation ids,
the ledger's states, the error vocabulary), this log does not repeat it;
[CONTRACT_COMPLIANCE.md](CONTRACT_COMPLIANCE.md) maps clauses to code. The execution plane's log is
[`docs/DECISIONS.md`](../DECISIONS.md); its numbers end at 034, so these begin at 101.

Reversibility: **reversible** (a refactor), **expensive** (touches a wire contract or an on-disk format),
**effectively irreversible** (cannot be undone once data exists). Every entry is *accepted*.

| ID | Decision | Reversibility |
|---|---|---|
| 101 | Python for the interface plane: two packages, three processes | expensive |
| 102 | Edge and core are kept apart twice: by the linter and by the operating system | reversible |
| 103 | The REST edge is Starlette on uvicorn with a route table of our own | reversible |
| 104 | The command interface is length-prefixed JSON on a Unix socket, one exchange per pooled connection | expensive |
| 105 | One model in code; every published contract file is generated from it and checked in | reversible |
| 106 | The store is SQLite: two files, one writer thread, a lock and a writer epoch | expensive |
| 107 | The security journal is an append-only, hash-chained file outside the store | effectively irreversible |
| 108 | A request is claimed before it is sent, and the send cannot be abandoned half-way | reversible |
| 109 | An API key carries its kind and a checksum; the registry keeps a plain digest | expensive |
| 110 | A token authenticates only through an operator's binding; keys are refreshed within bounds | reversible |
| 111 | A grant is a document that only narrows; the decision is a pure function | reversible |
| 112 | The host binding is one pool with three lanes | reversible |
| 113 | Public identifiers are the host's; revisions and cursors are opaque | expensive |
| 114 | One follower per operation, shared by every waiter | reversible |
| 115 | The agent-protocol adapter sits on the official SDK's low-level server, behind a layer of our own | reversible |
| 116 | Agent calls are keyed by the platform: minted, adopted, and reported delivered | expensive |
| 117 | Spans are the core's, follow the conventions, and name nothing a caller typed | reversible |
| 118 | The SDKs are written by hand against generated contracts | reversible |
| 119 | `acf` is a new program on the Python SDK; the host operator's tool moved | expensive |
| 120 | Three accounts, two environments, units confined by default | reversible |
| 121 | Environments are built from locks and from sources, never from a cached build | reversible |
| 122 | Three kinds of test double the evidence: a model host, the real protocol, the deployment | reversible |
| 123 | Publishing is by identity only, one tag per package | reversible |
| 124 | Dependencies are looked up when written and locked | reversible |
| 125 | What the host admits is stated by the operator, and a quota is always a number | reversible |
| 126 | The store remembers how far it applied the journal, and refuses a journal that ends earlier | reversible |
| 127 | Compatibility of the contract files is compared structurally, by direction, with reviewed exceptions | reversible |
| 128 | The platform's role on the host is linted in the host's own table | reversible |
| 129 | A configuration is read exactly: text becomes a path, and nothing else is converted | reversible |
| 130 | One-step create is not offered until the host protocol defines it | reversible |

---

## ADR-101 — Python for the interface plane: two packages, three processes
**Context.** The platform is I/O between callers and one host: it holds no VM, runs no workload, and its
hot path is a few small JSON messages. What it must get right is ordering and durability, not
throughput. The official SDK of the agent protocol that the contract recommends is a Python package.
**Decision.** `acf-api` holds the command interface, the core and the REST edge. `acf-mcp-gateway` holds
the agent-protocol edge and depends on `acf-api` for the command interface and the edge configuration.
A deployment runs three processes from them: one core, and one process for each edge.
**Consequences.** One language for the server, the SDK that most callers use and the CLI. The cost is the
interpreter's speed, which the bounds of the contract make irrelevant here: every request is bounded in
size, rate and concurrency before it is parsed. **Reversibility:** expensive. The seam that would let
the core be rewritten is the command interface (ADR-104), which is versioned for that reason.

## ADR-102 — Edge and core are kept apart twice: by the linter and by the operating system
**Context.** The contract requires that bytes from a caller are decoded in a process that holds neither
the host credential nor the store. One package holding both roles invites an import that quietly joins
them.
**Decision.** No module under `acf_api.edge` or `acf_api.command`, and nothing in `acf_mcp`, imports
`acf_api.core`: a banned-import rule of the linter fails the build, and a test walks the import graph.
At run time the roles are separate accounts, the core checks before it serves that no edge account
could read its secrets or its store, and the command socket admits the edge accounts only.
**Consequences.** A parser flaw in an edge yields a process that holds a TLS key and a socket. The price
is two environments and three units instead of one. **Reversibility:** reversible.

## ADR-103 — The REST edge is Starlette on uvicorn with a route table of our own
**Context.** The edge must refuse a credential in a URL, ask the core to verify the credential *before*
it reads a body, refuse a JSON object with a repeated member, and bound a body as it arrives. A
framework that parses and validates the body on the way in does these in the wrong order or not at all.
The OpenAPI document is a contract artifact, not a by-product of route decorators.
**Decision.** Starlette for routing and ASGI, uvicorn (h11) as the server with its limits set, and a
table of routes (`edge/http/routes.py`) from which both the application and the OpenAPI document are
built. Bodies are decoded by a strict JSON reader of our own and validated by the public model.
**Consequences.** The order of checks is the code's, visible in one function. We give up a framework's
dependency injection and automatic documentation, neither of which the edge needs.
**Reversibility:** reversible: the edge is an adapter over the command interface.

## ADR-104 — The command interface is length-prefixed JSON on a Unix socket, one exchange per pooled connection
**Context.** The edge and the core are on one machine and must authenticate each other without a secret.
**Decision.** A Unix stream socket. A frame is a four-byte big-endian length and a JSON document; every
frame names the version of the interface, and a version the peer does not know is refused as a whole. An edge keeps a pool of connections and uses each for one exchange at a time, so that a lost
connection loses exactly one answer. The core reads the peer's uid from the kernel (`SO_PEERCRED`) and
closes a connection from any account that is not a configured edge. A tenth of an edge's in-flight
bound is kept for containment.
**Consequences.** No HTTP stack, no TLS and no shared secret between the roles; an edge that gets no
answer to a mutation reports `OUTCOME_UNRESOLVED` and never a refusal, because it cannot know.
**Reversibility:** expensive (a wire format), mitigated by the version field.

## ADR-105 — One model in code; every published contract file is generated from it and checked in
**Context.** Five interfaces must expose the same operations with the same outcomes. Five hand-written
descriptions drift.
**Decision.** The public model (`command/model.py`), the error table (`command/errors.py`) and the
operation table (`command/surface.py`) are the source. `acf-api artifacts` writes the OpenAPI document,
the tool definitions and catalogue, the problem registry, the mapping to host methods and the client
conformance suite into `protocols/`; `make platform-drift` fails on any difference, and CI runs it.
**Consequences.** A change of the interface is one change in code and a regenerated directory in the same
commit. While this was being built, the model gained five members after the SDKs were finished; the
Python SDK's schema test caught it, and the TypeScript SDK got the same guard
(`sdks/typescript/tests/contract.test.ts`). **Reversibility:** reversible.

## ADR-106 — The store is SQLite: two files, one writer thread, a lock and a writer epoch
**Context.** The contract asks for exactly one core per deployment, durable claims, and an audit outbox
that can never use the space the registry and the ledger need. It asks for no replication.
**Decision.** `state.db` (registry and ledger) and `audit.db` (outbox, with a page budget of its own),
both in WAL mode with full synchronisation. Every statement runs on one dedicated thread, so the event
loop never waits on a disk and every call has a deadline. An exclusive lock on a file is held for the
life of the process; each start takes a new writer epoch, and a claim carries the epoch that made it.
**Consequences.** No database server to operate, back up or secure; a second core cannot start; a claim
of an earlier process is recognised as not in flight. A deployment is one machine's worth of state.
**Reversibility:** expensive (an on-disk format, behind `core/store`): the registry and the ledger are
narrow interfaces, and a server database would replace the engine underneath them.

## ADR-107 — The security journal is an append-only, hash-chained file outside the store
**Context.** A restore of the store must not revive a revoked key, hand out a scope twice or bring back
a deleted project. Whatever records those facts cannot be part of what is restored.
**Decision.** JSON lines in a file of its own directory, each carrying the SHA-256 of the line before
it, written and synchronised *before* the action it describes takes effect. On every start the core
verifies the chain and replays the journal into the registry. An optional mirror receives a copy.
**Consequences.** The journal is never behind the store, and a restore needs no special procedure. The
chain shows damage and careless edits, not a rewrite of the whole file by someone who owns it; the
file's owner and mode are that defence, and the document says so. **Reversibility:** effectively
irreversible once a deployment exists: its records are what keeps revocations true.

## ADR-108 — A request is claimed before it is sent, and the send cannot be abandoned half-way
**Context.** Between "the ledger says this key is taken" and "the host has the operation" lies the
window in which a crash or a hang-up must not be able to create a second operation or lose the first.
**Decision.** The claim is committed first, with the operation id derived from the key. The claim, the
send and the binding of the answer run as one unit that a closing connection cannot cancel: the caller
stops waiting, the work goes on. Whatever a process leaves as `CLAIMED` is resolved by the next start,
by reading the host, never by sending again unless absence is proven.
**Consequences.** A caller that disconnects cannot leave a claim that nobody owns. Recovery reads only.
**Reversibility:** reversible.

## ADR-109 — An API key carries its kind and a checksum; the registry keeps a plain digest
**Context.** A key that looks like any other string cannot be found by a secret scanner or refused when
it turns up inside a request body. A slow password hash on every request buys nothing for 256 random
bits.
**Decision.** `acf1_dev_…` and `acf1_agt_…`: an issuer and format version, the kind, 43 characters of
base62, and the CRC32 of what precedes it in six more, the shape GitHub introduced for its tokens. The
registry stores the SHA-256 and a display prefix. A request whose body contains a real key anywhere is
refused, exactly: a look-alike without a valid checksum is not one.
**Consequences.** Offline recognition, no false refusals, and a constant-time lookup by digest.
**Reversibility:** expensive: the version in the prefix is the way to change it.

## ADR-110 — A token authenticates only through an operator's binding; keys are refreshed within bounds
**Context.** Accepting any valid token of an issuer would make the issuer's whole user base principals
of the deployment. An unknown key id must not let a caller make the core fetch keys at will.
**Decision.** PyJWT verifies issuer, audience (this deployment's canonical resource), expiry, lifetime
and signature with the configured algorithms only. A verified subject is somebody only if an operator
bound it to a principal and a project. The key set is read at most every `jwks_refresh_interval`, and a
forced read for an unknown key id at most every `jwks_forced_refresh_min_interval`. A token's scopes
narrow the binding and can never widen it; a method they leave out is answered with the challenge that
names the missing scope.
**Consequences.** No authorization server of our own; ten thousand tokens with random key ids cause a
bounded number of reads. **Reversibility:** reversible.

## ADR-111 — A grant is a document that only narrows; the decision is a pure function
**Context.** The contract makes access policy a boundary of its own and requires that the decision sees
the intent of the *target*, not only the words of the request: an execution inherits the network of the
sandbox it runs in.
**Decision.** A grant is a small versioned document (methods, images, network modes and destinations,
ceilings). The effective grant of a credential is the intersection of its role, its narrowing and, for a
token, its scopes. `evaluate()` takes the request, the effective grant, the host's limits and the
target's recorded intent, and returns a decision with an id and the digest of the policy text as its
version. Where the intent of a target cannot be read, the decision is "not now", never "yes".
**Consequences.** The function is tested as a table, and the same decision serves every interface. A
policy engine could replace it behind the same protocol. **Reversibility:** reversible.

## ADR-112 — The host binding is one pool with three lanes
**Context.** If new work can use every connection to the host, then a stop cannot get through when it
matters, and neither can the read that resolves a lost answer.
**Decision.** One pool of mutual-TLS 1.3 connections (the host's own certificate authority only, the
configured host id as the name to verify) with reserved capacity: two connections for containment, one
for resolution, the rest general. The frame format is the host's; the request id of the platform is
sent as the host's request id, which joins the two logs.
**Consequences.** Containment has a path that granting work cannot fill. **Reversibility:** reversible.

## ADR-113 — Public identifiers are the host's; revisions and cursors are opaque
**Context.** A mapping table between public and host identifiers would be state that can be wrong.
**Decision.** Sandbox, snapshot and operation identifiers are passed through. An execution id is the
host's run id with another prefix, a rewrite that needs no table. A revision (`ETag`) is the host's
revision and a digest of its store lineage, so that a revision of a replaced store never matches. A
cursor is the host's, wrapped and base64url-encoded; clients are told it is opaque.
**Consequences.** Nothing to keep in step, and nothing to migrate. **Reversibility:** expensive once
clients hold identifiers.

## ADR-114 — One follower per operation, shared by every waiter
**Context.** Five hundred callers waiting on one operation must not become five hundred reads of the
host each second, and a wait must not hold a host connection.
**Decision.** A wait joins the follower of its operation. The follower polls on the platform's reserved
share of the host's read allowance, with a bounded interval, and wakes every waiter with one answer. A
wait is exempt from the caller's read bucket: it costs the host nothing more.
**Consequences.** The cost of waiting grows with operations, not with waiters. **Reversibility:**
reversible.

## ADR-115 — The agent-protocol adapter sits on the official SDK's low-level server, behind a layer of our own
**Context.** The protocol's revision `2026-07-28` is stateless and young; writing its framing by hand
would mean tracking it by hand. But the SDK does several things in an order the contract does not allow
(reads the body before the credential is known), or that would cost a second command per request, or
that would put caller text into telemetry.
**Decision.** The SDK's low-level `Server` and its Streamable HTTP transport, stateless, behind an ASGI
layer of the adapter's own that runs first: transport bounds, Host and Origin, method, revision,
credential in the header only, the credential check asked of the core, and only then the body. Each of
the three handlers sends exactly one command. The SDK's own Host and Origin check, its hidden tool
listing before a call and its span middleware are switched off, each for a stated reason.
**Consequences.** Revision `2025-11-25` and the tasks extension are not in this build: with the setting
for the older revision on, the adapter refuses to start rather than half-serve it. The official client's
automatic fallback hides a wrong credential behind a version error; the README says how to see the real
answer. **Reversibility:** reversible.

## ADR-116 — Agent calls are keyed by the platform: minted, adopted, and reported delivered
**Context.** An agent host repeats a tool call when it loses an answer, and it cannot be trusted to
bring an idempotency key. Without one, the repeat runs the command twice.
**Decision.** For a tool that can create an operation the core mints the key, records a digest of the
arguments with the claim, and returns the key in the result. An identical call by the same credential
that arrives while the first result is undelivered and inside the adoption window adopts the same key.
The adapter reports to the core when a result has been written to the transport in full; only then does
the next identical call mean new work.
**Consequences.** A lost answer over the agent protocol is as safe as one over REST, at the price of a
delivery report per call. **Reversibility:** expensive: the key in a result is part of the tool schema.

## ADR-117 — Spans are the core's, follow the conventions, and name nothing a caller typed
**Context.** The conventions for spans of the agent protocol are in Development status. The SDK's
default middleware names a span after the tool name exactly as the caller sent it, before anything has
checked it.
**Decision.** The core emits one server span per command when the operator installed OpenTelemetry,
as a child of the caller's trace context, named and attributed as the conventions say today
(`tools/call sandbox_exec`, `mcp.method.name`, `gen_ai.tool.name`, `gen_ai.operation.name`,
`error.type` = `tool_error` for a result that says so). A tool name is a label only when it names a tool
of the catalogue. The version of the conventions is pinned in the configuration. The edges emit none.
**Consequences.** One span per request instead of one per hop; no caller-chosen string in any name or
attribute. HTTP server spans of the edges are not emitted. **Reversibility:** reversible.

## ADR-118 — The SDKs are written by hand against generated contracts
**Context.** A generated client reproduces routes; it does not know that one key must cover a create and
its start, how to follow an operation, or that `UNKNOWN` is neither success nor failure. Those are the
SDK.
**Decision.** Two hand-written SDKs with one surface, held to the generated files instead of generated
from them: every request a test makes is checked against the OpenAPI document, every view against its
schema, and both SDKs and the CLI run the same conformance scenarios. Python depends on `httpx2` alone;
TypeScript on nothing at run time and uses `fetch`. Retries are decided by the `retry` member of the
problem document, never by status alone: the widely copied rule "retry every 409" would repeat a state
conflict. One idempotency key is made per logical call, before the first attempt, and reused on every
retry, as the generated SDKs of the large API vendors do for theirs; here it is mandatory and
caller-visible, so that a call can be resumed from another process.
**Consequences.** More code to own, and parity kept by tests rather than by a generator.
**Reversibility:** reversible.

## ADR-119 — `acf` is a new program on the Python SDK; the host operator's tool moved
**Context.** The name `acf` belongs to the developer's command. The existing client in `apps/cli` speaks
the host's own protocol over its socket and is the host operator's tool.
**Decision.** That client moved to `apps/host-cli` unchanged (program `acf-local`). `apps/cli` is the
new `acf`: a thin layer over the Python SDK, with one command, `acf mcp`, that relays the agent protocol
between stdio and the platform's endpoint and refuses any credential that is not an agent's.
**Consequences.** Two programs for two people, and no command that can reach a host's socket by mistake.
The package name is `agent-compute-cli`, because `acf` is taken on PyPI by somebody else.
**Reversibility:** expensive once people script against it: exit statuses and `--json` are versioned
with the API.

## ADR-120 — Three accounts, two environments, units confined by default
**Context.** The separation of ADR-102 is only as good as its deployment.
**Decision.** Accounts `acf-core`, `acf-rest` and `acf-mcp`; a group that opens the command socket and
nothing else; the runtime directory set-group-id, so that a socket has its group from the moment it
exists. The core and the agent-protocol edge run from separate environments, so that the protocol
library is not on the import path of the process that holds the host key. The units drop every
capability, apply a system-call filter, make the file system read-only and, for the edges, hide the
core's directories altogether. A start refused by a precondition exits 78 and is not retried.
`PrivateUsers=` is deliberately not set: the core recognises an edge by the uid the kernel reports.
**Consequences.** `scripts/platform-deploy-test.sh` installs exactly this on a throw-away machine in CI
and inspects the running processes, so the units are tested as they ship. **Reversibility:** reversible.

## ADR-121 — Environments are built from locks and from sources, never from a cached build
**Context.** The installer builds two environments with `uv sync --locked`. `uv` keeps a cache of built
packages and, by default, considers a package of this checkout unchanged while its `pyproject.toml` is
unchanged. The version of each package lives in a source file. The deployment test showed the result:
an environment that was handed an older build of `acf-api` under the same name.
**Decision.** Each package declares its sources as part of its cache key (`[tool.uv] cache-keys`), and
the installer passes `--reinstall`. A test holds both.
**Consequences.** An install takes a little longer and cannot be stale. **Reversibility:** reversible.

## ADR-122 — Three kinds of test double the evidence: a model host, the real protocol, the deployment
**Context.** The rules that matter most concern what happens when an answer is lost at a particular
moment. The real host offers no way to lose an answer on demand.
**Decision.** (1) A model of the host inside the test process, with a fault at every point of an
exchange, drives the pipeline, the ledger and recovery. (2) The same core runs against the host's own
in-memory build over real mutual TLS, to hold the model to the truth. (3) The deployment test installs
the shipped files and inspects processes. The SDKs and the CLI add the conformance suite, with virtual
time, and never open a socket in a test.
**Consequences.** Fault points are proven against the model only; the documents say which evidence is of
which kind. **Reversibility:** reversible.

## ADR-123 — Publishing is by identity only, one tag per package
**Context.** A registry token is a secret that outlives everyone who created it.
**Decision.** One workflow publishes, by OIDC trusted publishing, with provenance on every file; the
identity token is the only permission beyond read in any workflow and is given to the two uploading
jobs, which run none of the repository's code. A tag names one package and its version. The names are
not registered yet, so the workflow cannot succeed and the TypeScript package is marked private: both
are guards, removed together with the registration. [RELEASING.md](RELEASING.md) has the procedure.
**Consequences.** Nothing to rotate and nothing to leak. **Reversibility:** reversible.

## ADR-124 — Dependencies are looked up when written and locked
**Context.** Versions remembered from somewhere else are wrong by the time they are typed.
**Decision.** Every version was read from the registry's own JSON endpoint on the day it was written,
validated by the tests, and locked with the hash of each file. Published ranges are as narrow as what
was tested. [DEPENDENCY_PROVENANCE.md](DEPENDENCY_PROVENANCE.md) lists each one, including the choices
that follow from it: `httpx2` rather than the unmaintained line it continues, `uv` for locking, the
OpenTelemetry API as an optional extra only.
**Consequences.** A lock is reviewed like code; Dependabot proposes, nobody merges automatically.
**Reversibility:** reversible.

## ADR-125 — What the host admits is stated by the operator, and a quota is always a number
**Context.** A project's quota of live sandboxes and of snapshots defaults to its share of what the host
admits at once. The host does not advertise that: `host.info` carries its pool of identifiers, which is
a ceiling of what it could ever hold (4,096 on a default host) and not what it admits (16). A quota
taken from the pool let one project fill the host, and with no number from either side the quota was
not enforced at all.
**Decision.** Two parameters, `host_max_sandboxes` and `host_max_snapshots`, state the host's envelope,
exactly as `host_ops_allowance` and `host_reads_allowance` state its rate limits: defaults equal to the
host's own, the operator answers for them. A quota is always a number: the operator's, or the share of
these. The quotas may not exceed them, which is checked at start. The identifier pool is used for the
one thing it can show: a configured sandbox count above it cannot be the host's, and granting work is
then refused with the relation named.
**Consequences.** Four values, not two, must be kept equal to the host's configuration by hand until the
host advertises them. The two new parameters are not rows of the contract's register; the tests list
them as additions with the reason. **Reversibility:** reversible: when the host reports its envelope,
the parameters become fallbacks.

## ADR-126 — The store remembers how far it applied the journal, and refuses a journal that ends earlier
**Context.** The journal's hash chain shows a changed, removed or reordered record. It cannot show
records missing at the end: a journal cut at a line boundary is a valid journal. Those records are
revocations, and a core that served from such a journal would let a later restore of the store bring the
credentials back.
**Decision.** The store keeps the sequence of the last journal record it applied. When it is opened
beside a journal that ends before that record, it refuses, before it takes a writer epoch, and the core
does not start. The other direction, a store older than its journal, is a restore, and is brought up to
the journal by the replay that runs on every start.
**Consequences.** Restoring the journal from an old copy stops the start with a message that says which
record is missing. An attacker who can rewrite both files is outside what either check can see; the
journal's copy on the operator's sink is the defence there. **Reversibility:** reversible.

## ADR-127 — Compatibility of the contract files is compared structurally, by direction, with reviewed exceptions
**Context.** Within a major version nothing is removed, retyped or made newly required, and a request
schema never becomes stricter, because a repeated request must stay valid. The files are generated, so
a text diff is noise, and the same schema change is harmless in an answer and breaking in a request, or
the reverse.
**Decision.** `acf-api compat` reads two versions of the REST description, the tool definitions and the
problem registry, follows references, and holds every schema to the rule of the direction it travels:
a request may only be given more freedom, an answer may only say more. A schema that travels both ways
is held to both. Each named schema is reported once. What cannot be proven compatible, such as a
changed pattern, is reported; a reviewed exception is the exact finding in a file, and an exception
that no longer occurs fails. The baseline is the newest `acf-api-v*` tag, found by `make
platform-compat`; a new major passes and lists what it breaks.
**Consequences.** We wrote about 600 lines instead of adopting a general OpenAPI differ: none covers the
tool catalogue or the problem registry, and the direction rule and the references to shared responses
needed our own reading of our own generator's output. The comparison sees shapes, not meanings.
**Reversibility:** reversible.

## ADR-128 — The platform's role on the host is linted in the host's own table
**Context.** On the host the platform must be a `caller`: an `operator` reaches every record and the
host itself. The host does not tell a peer its role, so the platform cannot confirm it over the wire.
**Decision.** `acf-api check --host-enrolment` reads a copy of the host's enrolment table and computes
the two digests by which the table can name the platform's certificate. It passes when exactly one
entry matches, that entry's role is `caller`, and no entry matches a certificate of an edge. The
installer's `check` runs it as the core's account with copies of public files; the deployment test runs
it on the table the test host writes, and on two tables that are wrong.
**Consequences.** The check is as current as the copy it is given, and it decides nothing for the host.
It is replaced by a read of `host.info` when the host reports the role. **Reversibility:** reversible.

## ADR-129 — A configuration is read exactly: text becomes a path, and nothing else is converted
**Context.** A loosely read file turns `"false"` into false and `1` into true. For a switch that changes
what the platform admits, nobody can say afterwards what its author meant.
**Decision.** Both configuration schemas are strict: a value has the type of its setting or the file is
refused, with the setting named and the value never repeated. A path, which YAML can only write as text,
is the single conversion; a whole number is accepted where a fraction is expected.
**Consequences.** A file that an earlier, looser reading accepted may now be refused at start, with the
setting named. **Reversibility:** reversible.

## ADR-130 — One-step create is not offered until the host protocol defines it
**Context.** The contract lets `create` accept `start: true` when the host advertises create and start
as one operation, and forbids building the same effect from two. No version of the host protocol has
such an operation, so the platform does not know how a host would want it written.
**Decision.** The platform never advertises the feature and refuses `start: true` with `UNSUPPORTED`,
whatever a host advertises. The SDKs and the CLI go on driving create and then start.
**Consequences.** A host that gains the operation needs a platform release that implements it; until
then nothing is promised that is not sent. **Reversibility:** reversible.
