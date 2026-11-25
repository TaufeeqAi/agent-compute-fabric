# Architecture — the developer platform

How the code realises the platform's contract (version 1.1.0). The contract says what must hold; this
document says where it holds and why it was built that way. Decisions the contract leaves open are in
[DECISIONS.md](DECISIONS.md) (ADR-101 onwards); clause-by-clause traceability is in
[CONTRACT_COMPLIANCE.md](CONTRACT_COMPLIANCE.md).

Paths are relative to the repository root. `§` refers to the contract.

---

## 1. What the platform is, and what it is not

One ACF host runs sandboxes for *one enrolled peer* over mutual TLS. It knows nothing of developers,
projects, API keys or agents. The platform is that peer. It turns "a developer with a key" into "a
request of the peer, stamped with the project's scope", and it makes that request safe to repeat.

```text
developer ─ SDK / CLI / HTTP ─► REST edge ─┐                       one host
                                           ├─ command socket ─► core ─ mutual TLS ─► acf-host ─► microVMs
agent ───── agent host / acf mcp ─► MCP edge ┘                      │
                                                    registry · ledger · audit outbox · security journal
```

It holds **no state of the workload**: no sandbox, no execution, no snapshot, no output. Those are
facts of the host, read when asked for. What it holds is what only it can know: who may call, which
idempotency key became which host operation, and what was asked. Two consequences run through the code:

* a read always reaches the host, so nothing the platform shows can be stale by more than the read;
* there is one direction of reconciliation. When the platform is unsure, it asks the host and adopts
  the answer. It never asks the host to match the platform.

## 2. Processes and the seam between them

| Process | Package | Account | Holds |
|---|---|---|---|
| core | `apps/api` (`acf_api.core`) | `acf-core` | the host private key, the fingerprint key, the store, the journal |
| REST edge | `apps/api` (`acf_api.edge`) | `acf-rest` | its TLS key |
| agent-protocol edge | `apps/mcp-gateway` (`acf_mcp`) | `acf-mcp` | its TLS key |

**EC-1, EC-2: the edge holds nothing.** The processes that decode bytes from a network cannot open
anything worth taking. This is enforced three times: no edge module imports `acf_api.core` (a linter
rule and `tests/test_contract_imports.py`); the accounts differ and the core refuses to start if an edge
account could read its secrets, its store or its journal (`core/config.py::check_separation`); and the
units hide those directories from the edges' view (`deploy/platform/systemd`).

**The command interface (B34, `acf_api/command`).** A Unix stream socket, a four-byte length and one
JSON document per frame, a version in every frame. Three requests exist:

| Request | Asked when | Answer |
|---|---|---|
| `verify` | before an edge reads a body | the credential authenticates, or an error with the challenge to relay |
| `handle` | once per public request | a view, an error, a tool catalogue, a tool result, a protocol fault, a discovery document |
| `delivered` | after an agent-protocol edge has written a tool result in full | an acknowledgement |

An edge never sees a principal, a project's scope or a grant: it is told the answer and how to render
it. The core authenticates the *caller* on every command and the *edge* by the uid the kernel reports
for the socket's peer. An edge that gets no answer to a mutation answers `OUTCOME_UNRESOLVED`, because
it cannot know whether the core acted (EC-5); to a read, `UPSTREAM_UNAVAILABLE`.

## 3. One model, five interfaces

`acf_api/command/model.py` is the public model: the request bodies, the views, the vocabularies.
`errors.py` is the error table (code, kind, retry advice, HTTP status, SDK exception). `surface.py` is
the table of operations: for each public method its class, the host method behind it, its REST route,
its tool, its SDK call and its CLI command.

Everything a client sees is generated from those three (`acf_api/contract`, written to `protocols/`):

| File | Consumed by |
|---|---|
| `protocols/api/openapi.yaml` | the REST edge's tests; both SDKs' tests, which check every request and view against it |
| `protocols/api/problems/registry.yaml` | the SDKs: code → exception class |
| `protocols/api/surface.yaml` | the CLI's tests: every operation has a command |
| `protocols/mcp/tools/*.json`, `catalogue.json` | the agent-protocol edge's tests; the TypeScript SDK's view guard |
| `protocols/api/mapping/acf.host-2.yaml` | the core: which host method, which parameters, which class |
| `protocols/conformance/scenarios.json` | both SDKs and the CLI: the client protocol under lost answers |

Vocabularies are open on purpose. A state or a code the platform does not know is passed on as
`UNRECOGNIZED` with the host's own value beside it (`…_raw`), and a client treats a value it has never
seen as neither success nor an end (VER-12). A new host can therefore not make an old platform, or an
old client, report success by mistake.

## 4. The pipeline of a request

`acf_api/core/pipeline/service.py` is the single admission path (B23). Every interface arrives here as a
command, and the order below is the order of the code. A request refused at a step has caused nothing
that a later step would have caused: no claim, no host call, and before the bounds not even an audit
record.

The service is one class, `RuntimeService`, assembled from layers. Each layer is a module of
`core/pipeline/`, and a layer can call only what lies beneath it, so the direction of dependency is
visible in the code:

| Layer, lowest first | Module | What it holds |
|---|---|---|
| ground | `ground.py` | the dependencies, the state of one call, the builders of every answer |
| observing the host | `observation.py` | `host.info`, the pinned lineage and peer id, host reads and host refusals, what is offered |
| agent credentials | `credentials.py` | minting, listing and revoking |
| resolution | `resolution.py` | what an entry becomes: reading to resolve a lost answer, the proof of absence, bind, release, lose, and a repeated key |
| reads | `reads.py` | reads, listings, output, following an operation, `whoami`, platform info |
| admission | `admission.py` | capabilities, the values the platform adds, the decision, the quota |
| the exchange | `exchange.py` | the new entry, the claim, the one submission |
| containment | `containment.py` | stop, destroy, cancel and delete, on their own lane |
| the service | `service.py` | the entry points, and the order of the steps below |

```text
 1  authenticate            the credential, by digest; the project is the credential's, never the request's
 2  project                 the path must name the credential's own project, else NOT_FOUND
 3  class of the operation  read · containment · granting · platform        (from the surface table)
 4  key and body checks     a mutation needs a key; a body that contains a platform credential is refused
 ── containment leaves here: its own lane (§6) ─────────────────────────────────────────────────────────
 5  ledger lookup           a key the ledger holds is a RESOLUTION, answered without steps 6–10 (§5)
 6  rate, in-flight         per principal and per project; 429 with Retry-After
 7  readiness               draining · project accepts work · host known and suitable · recovery done · clocks
 8  fix the request         every value the platform adds is chosen once: timeouts, defaults, the target's generation
 9  access policy           the effective grant against the fixed request AND the intent of its target (§8)
10  quota                   under the project's admission lock, counted on the host; held until the host answered
11  claim                   one row in the ledger, with the derived operation id; durable before anything is sent
12  send                    one exchange with the host; every way it can end is handled (§5.2)
13  bind                    the entry records the host's operation; durable before the answer
14  render                  the host's operation in the public model; wait for it through the follower (§7)
```

Why this order: authentication first, so that nothing is done for a stranger; the lookup before the
bounds, so that a retry of something already accepted is never refused for rate; the policy after the
request is fixed, so that it judges what will really be sent; the quota under a lock and counted on the
host, so that no stored counter can disagree with the truth; the claim before the send, so that a
crash after the send finds a record of what was sent.

From the claim to the bind the work is shielded from cancellation: a caller that hangs up stops
waiting, and the exchange runs to its end (ADR-108).

## 5. Idempotency: one key, one operation

### 5.1 The derivation and the ledger

The operation id the host receives is **derived**, not allocated:
`op-` + the first 16 bytes, in hex, of SHA-256 over a version tag, the deployment id, the project, the
principal, the step and the caller's key, each length-framed (`core/pipeline/derivation.py`; golden
vectors in `tests/test_unit_derivation.py`). The same caller repeating the same key reaches the same
operation on the host even if the platform has lost every record of the first attempt, and the host's
own rule (one operation id, one request) does the rest.

The ledger (`core/store/ledger.py`) is one row per (project, principal, key digest):

```text
            claim                    bind (the host answered with the operation)
 (absent) ────────► CLAIMED ─────────────────────────────────────────────► BOUND
                      │  release (the host refused: nothing exists;                │
                      │           or absence was proven)                           │ the host no longer
                      ▼                                                            │ holds the operation
                   (absent)             CLAIMED ──► LOST ◄─────────────────────────┘
                                         absence cannot be proven
```

* `CLAIMED` carries the writer epoch of the process that made it. An entry of an earlier epoch is known
  not to be in flight.
* `BOUND` keeps a small terminal summary once the operation has ended, so that an answer exists after
  the host's own retention has passed (ERR-7).
* `LOST` is permanent: the host no longer holds the operation, and the platform will never run the key
  again. Its key is answered with the recorded terminal summary when the operation was seen to end
  (marked `recorded`), and with `OUTCOME_LOST` when nothing can be said.
* The key itself is never stored: the row holds a keyed digest of it and a keyed fingerprint of the
  request. The same key with a different request is `IDEMPOTENCY_CONFLICT` (422).

### 5.2 Every way an exchange can end

`RuntimeService._send` owns the one moment that matters. The host binding reports that a request was
*not written* with one of three exceptions and nothing else; every other failure leaves a doubt, and a
doubt is never answered "refused".

| What happened | The entry | The caller is told |
|---|---|---|
| the host answered with the operation | `BOUND` | the operation (200, or 202 with `Location` and `Retry-After`) |
| the host refused | released | the host's refusal, in the public vocabulary |
| not written: unreachable, too large, the host's identity not verified | released | `UPSTREAM_UNAVAILABLE` or `REQUEST_TOO_LARGE`: nothing was sent |
| written, no answer; a read finds the operation | `BOUND` | the operation, marked `replayed` |
| written, no answer; a read finds nothing and **absence is proven** | stays `CLAIMED`, the same envelope is sent once more | whatever that exchange gives |
| written, no answer; a read finds nothing and absence cannot be proven | `LOST` | `OUTCOME_LOST` |
| written, no answer; the host cannot be read within the attempts | stays `CLAIMED` | `OUTCOME_UNRESOLVED`, with the key to ask again |

**Absence is proven** only when all three hold (`absence_proven`, REC3-5): the entry was never bound;
the answer comes from the pinned lineage of the host's store at a commit sequence not lower than any
seen before; and the host cannot have forgotten the operation, because the entry's `issued_at` is newer
than the host's forgetting floor or still inside its acceptance horizon. A "not found" from a restored
or replaced host store therefore proves nothing, and the entry becomes `LOST` instead of being run a
second time.

### 5.3 Recovery

`core/pipeline/recovery.py`. Recovery **reads and never submits**: no mutation is ever sent from a
timer or a restart. On a start, every `CLAIMED` entry of an earlier writer epoch is visited once, and
until that pass is done new work is refused with reason `recovery_pass_pending`. Afterwards, a periodic
sweep visits `CLAIMED` entries older than `claim_stale_after` that no live request is working on. A
visit ends in bind, release (absence proven) or `LOST`. The same period runs retention; an entry never
leaves while it is `CLAIMED` or while its operation has not ended.

## 6. Containment has a lane of its own

Stop, destroy, cancel and delete remove privilege. They must work when everything else is refused:
over a rate, during recovery, with a full audit outbox, while the registry cannot be read, on a host
the platform would not send new work to.

* **In the pipeline** they leave after step 4: no rate, no in-flight bound, no readiness gate, no quota.
  The grant is still checked, and so is the project.
* **In the edge's client** a tenth of the in-flight bound is reserved for them.
* **In the host binding** two connections are reserved (`Lane.CONTAINMENT`), and one more for the reads
  that resolve lost answers (`Lane.RESOLUTION`).
* **In authentication** a credential that authenticated within the last `containment_auth_cache_ttl` is
  accepted from memory, for containment only, while the registry cannot be read. That bound is never
  longer than the bound within which a revocation must take effect.
* **For a project being deleted** they stay allowed while new work is refused.

A containment request names a generation, or says `current` explicitly. With a number it acts on that
generation or is refused; a stale validator is refused once and not retried into a loop.

## 7. Waiting without holding the host

A public request may wait for its operation (`wait`, at most `public_wait_max`). The wait does not hold
a host connection: it joins the **follower** of the operation (`core/pipeline/follower.py`), which polls
the host on the platform's reserved share of the read allowance, with a bounded interval, and wakes
every waiter with one answer. Five hundred waiters on one operation cost the host one read per
interval. A wait that ends without an end of the operation answers 202 with the operation as it is.

Two details keep that promise honest. The pace belongs to the operation and outlives its waiters: a
caller who arrives just after the last one left waits for the interval to pass and is not answered by
a poll of its own, so callers arriving one after another on an operation that has ended cannot turn
into one read each. And the caller whose wait *starts* the polling of an operation is charged one read
against its own rate, because that wait is what makes the platform read; a caller that joins a wait
costs the host nothing and is charged nothing. Every waiter is answered from a read that began after
it arrived, never from an older one.

Nothing a client does while waiting ends an operation: not a closed connection, not a timeout, not a
closed stream of the agent protocol (INV-116). Only an explicit cancel, stop or destroy does.

## 8. Who may do what

**Credentials (`core/identity`).** A developer key or an agent key is recognised by its form and
checksum, looked up by its SHA-256, and bound to one principal and one project. An OAuth access token
is verified (issuer, audience, expiry, lifetime, signature) and is somebody only through a subject
binding an operator created. Agent credentials are minted by a developer, always narrower than the
parent, short-lived, and revoked with it.

**Grants (`core/policy/grants.py`).** A grant is a document: methods, images, network modes and
destinations, ceilings. The *effective* grant of a credential is the intersection of its principal's
role in the project, its own narrowing and, for a token, its scopes. Intersection is the only
operation there is, so nothing downstream can widen a grant.

**The decision (`core/policy/authorizer.py::evaluate`).** A pure function of the fixed request, the
effective grant, the host's limits, and the *intent of the target*: an execution inherits the network of
the sandbox it runs in, and a restore inherits what the snapshot recorded. The core reads that intent
from the host before it decides. Where it cannot be read, the decision is "not now"
(`UPSTREAM_UNAVAILABLE`), never "yes". A denial carries a reason code and is audited.

**The host still decides.** A grant can allow more than the host's safety profile; the host then
refuses, and that refusal is what the caller gets. The platform never reduces a request to make it fit.

**Projects are scopes.** A project is given 128 random bits at creation. Every host request of the
project carries that scope, the host stamps it on every record, and a record of another scope does not
exist for the caller (`NOT_FOUND`, never "forbidden"). No field, header or tool argument can name a
scope.

## 9. The agent interface

`apps/mcp-gateway` frames the protocol; `acf_api/core/agent` owns everything that has meaning.

* **The catalogue** (`catalog.py`) is a projection of the surface table: one tool per operation that has
  one, with an input model, an output model and annotations that state its worst case. A tool the
  caller's grant does not allow is not listed.
* **Agent credentials only.** A developer key is offered no tool and its calls are refused with a
  reason that says how to proceed.
* **Keys are the platform's** (`interaction.py`). For a tool that can create an operation the core
  mints the idempotency key, records a keyed digest of the arguments, and returns the key in the
  result. An identical call by the same credential that arrives while the first result is undelivered,
  inside the adoption window, adopts that key: a repeated call after a cut stream finds the first
  operation. The edge reports delivery when a result has been written in full; after that an identical
  call is new work.
* **Results.** Structured content that conforms to the tool's output schema, the same JSON as text in
  printable ASCII, and `isError` for every unsuccessful outcome. Two answers are HTTP answers instead
  of results: no valid credential (401) and a token whose scopes leave the method out (403 with the
  scope to ask for).
* **Guest output is data.** It reaches an agent only as a JSON string value, bounded, labelled as the
  guest's, and never interpreted by the platform.

## 10. The host binding

`core/host/binding.py`, `wire.py`. Mutual TLS 1.3 to the one configured host: the trust anchors are the
configured file and never the system's, the name verified is the configured host id, and the first
store lineage and peer id the platform sees are pinned in the security journal. A different lineage or
peer id later stops new work until an operator acknowledges it (`core/pipeline/standing.py`); entries of
the old lineage then become `LOST`.

`host.info` is an observation, re-read at most every `host_info_ttl`. It decides what the platform
*offers* (features, ceilings). It is never used to skip a check the host makes.

Two things about the host cannot be read from it and are therefore stated or checked elsewhere. What
the host admits at once, and its rate limits for one peer, are parameters of the core that must equal
the host's own configuration (§12). And the role the host gave the platform is linted in the host's own
enrolment table (`core/host/enrolment.py`, `acf-api check --host-enrolment`): exactly one entry for the
platform's certificate, with the role `caller`, and none for an edge's.

The platform sends its own request id as the host's `request_id`, which is what joins the two logs.

## 11. What is durable, and where

| Store | File | Holds | Lost means |
|---|---|---|---|
| registry | `store/state.db` | projects, principals, roles, credential digests, subject bindings | restore, then the journal is replayed |
| ledger | `store/state.db` | one row per accepted key | a repeated key is new work; in-flight requests are resolved by reading the host |
| audit outbox | `store/audit.db` | records not yet delivered or expired, inside its own size budget | those records |
| security journal | a file outside the store | revocations, scope allocations, project deletions, the pinned lineage and peer id, as a hash chain | **must not be lost** |

`core/store/engine.py`: SQLite in WAL mode with full synchronisation; every statement on one dedicated
thread with a deadline; an exclusive lock for the life of the process; a new writer epoch at every
start. A journal record is durable *before* the action it describes takes effect, and the journal is
replayed into the registry on every start, so a restored store can never revive a revoked key
(IPS-14).

The two files check each other. The journal's chain shows a record that was changed, removed or
reordered; it cannot show records missing at its end. The store remembers the last journal record it
applied, and refuses to open beside a journal that ends earlier, before it takes a writer epoch
(ADR-126). A store that is older than its journal is the ordinary restore, and is brought up to it.

## 12. Bounds

Every bound is a parameter with a default (`core/parameters.py`), and the relations among them are
checked at start. Both configuration files are read exactly: a key the schema does not define, or a
value of another type than its setting, stops the start (ADR-129). Four parameters restate what the
host does not advertise: its allowance for one peer (`host_ops_allowance`, `host_reads_allowance`) and
what it admits at once (`host_max_sandboxes`, `host_max_snapshots`). A project's quota is always a
number: the operator's, or the project's share of the last two (ADR-125). Where each bound is enforced:

| Bound | Enforced in |
|---|---|
| request size, header size, connections, body time | the edge, before parsing |
| commands in flight per edge | the edge's client of the command socket |
| requests per principal and per project, in flight per principal and per project | the core (`pipeline/limits.py`), so that the number of edge processes does not matter |
| live sandboxes and snapshots per project | the core, under the project's lock, counted on the host |
| the platform's own use of the host | the binding's lanes; the follower's and the resolution's reserved read share; a retry budget |
| the audit outbox | its own page budget in `audit.db` |

## 13. Telemetry and audit

**Audit** (`core/audit`) is evidence of what was asked: who, where, how, what, the decision, the result,
when. A record holds identifiers, enumerations and keyed digests, and nothing else: the fields it may
carry are a closed set that a test checks. It is written to the outbox and delivered from there.
Nothing reads it to decide anything.

**Telemetry** (`core/telemetry.py`, `pipeline/tracing.py`) is diagnostic. Counters with labels from
closed sets; structured log lines with bounded identifiers; one server span per command when the
operator installed OpenTelemetry, continuing the caller's trace and named by the conventions for the
agent protocol. A caller-supplied string is never a label, a span name or an attribute. Losing
telemetry changes no outcome.

## 14. Trust boundaries

| Boundary | What crosses | What defends it |
|---|---|---|
| caller → edge | bytes | size and time bounds before parsing; a strict JSON reader; no credential in a URL |
| edge → core | commands | the peer's uid from the kernel; every command re-validated; the caller authenticated by the core |
| core → host | requests of one peer | mutual TLS with pinned anchors, name, lineage and peer id; the scope chosen by the core alone |
| guest → agent | output | bounded, labelled, a JSON string value only |
| operator → core | admin commands | a socket of the core's account; each changing command audited |
| repository → registries | packages | identity-only publishing with provenance ([RELEASING.md](RELEASING.md)) |
| a restore → the store | old state | the journal, outside the store, replayed on every start |

## 15. What this build does not have

* A second host, or any placement: a deployment binds one host.
* Replication of the store: one core, one machine.
* The older revision of the agent protocol and its tasks extension: a configuration that turns either
  on is refused, by the core and by the adapter.
* Create and start as one operation: the host protocol has none, so `start: true` is refused and the
  clients drive the two (ADR-130).
* HTTP server spans in the edges; an exporter of any kind.
* An authorization server: tokens of an external one are accepted, none are issued.
* Workspaces, evidence bundles, experiments, billing: later work, named as out of scope by the contract.
