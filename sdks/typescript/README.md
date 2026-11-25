# @agent-compute/sdk

The TypeScript SDK of Agent Compute Fabric: create sandboxes, run commands in them, read their
output, snapshot and restore them, through the platform's public API.

```ts
import { Fabric } from "@agent-compute/sdk";

const fabric = new Fabric(); // ACF_API_KEY and ACF_BASE_URL

const sandbox = await fabric.sandboxes.create("python", { cpu: 2, memory: "4GiB", disk: "10GiB" });
try {
  const execution = await sandbox.exec(["python", "-c", "print('hello')"], { timeout: "10m" });
  console.log(execution.exit_code, await execution.text());
} finally {
  await sandbox.destroy();
}
```

The SDK is a client and decides nothing. Who may ask, what is allowed and what actually happened
are decided by the platform. What the SDK adds is the caller's half of the protocol: one
idempotency key per intent, kept across retries, so that a lost answer never becomes a second
operation; operations followed to their end; and each outcome reported as the distinct thing it is.

Contents: [Install](#install) · [Configuration](#configuration) · [Quickstart](#quickstart) ·
[Errors](#errors) · [Retries and idempotency keys](#retries-and-idempotency-keys) ·
[Resuming a call](#resuming-a-call) · [Units](#units) · [Browsers](#browsers) ·
[What the SDK never does](#what-the-sdk-never-does) · [Development](#development)

## Install

**The npm scope `@agent-compute` is not registered yet.** Do not run
`npm install @agent-compute/sdk`: no such package exists on the public registry today, and a
package that appears there under this name before the scope is registered is not this SDK. Until
the scope is registered, the package is installed from this repository:

```console
cd sdks/typescript
npm ci
npm pack                      # builds, then writes agent-compute-sdk-0.1.0.tgz
cd /path/to/your/project
npm install /path/to/agent-compute-sdk-0.1.0.tgz
```

The manifest is marked `private` so that the package cannot be published by accident before then.

Requirements: Node.js 22.12 or newer (the lines 22, 24 and 26). The package is ESM only, ships its
own type declarations, and has no runtime dependencies: it uses the platform's `fetch`,
`AbortController`, `crypto.randomUUID` and `TextDecoder`. It uses no API that only Node.js has, so
it also runs in other runtimes that provide those; there, pass the configuration as options.

## Configuration

```ts
const fabric = new Fabric({
  apiKey: "…",                       // default: the environment variable ACF_API_KEY
  baseUrl: "https://acf.example",    // default: ACF_BASE_URL
  project: "prj_…",                  // default: ACF_PROJECT, else the project of the credential
});
```

| Option | Environment | Default | Meaning |
|---|---|---|---|
| `apiKey` | `ACF_API_KEY` | none: required | The credential. Sent as `Authorization: Bearer`, to `baseUrl` only. |
| `baseUrl` | `ACF_BASE_URL` | none: required | The endpoint. `https://`, or `http://` to a loopback address. |
| `project` | `ACF_PROJECT` | the credential's | A credential is bound to one project. When none is named, the SDK reads it once from the platform, on first need, and keeps it. |
| `timeout` | | `120` | Seconds one HTTP request may take. It does not bound a followed operation. |
| `maxRetries` | | `2` | How often one call is retried. |
| `followMax` | | `1800` | Seconds a call follows an operation before it reports it as still running. Each call also accepts its own. |
| `retryTotalMax` | | `82800` | Seconds one call may spend retrying: a day, less an hour. |
| `allowInsecureHttp` | | `false` | Allow `http://` to an address that is not loopback. The credential then travels in clear text. |
| `dangerouslyAllowBrowser` | | `false` | See [Browsers](#browsers). |
| `fetch` | | the platform's | The transport. Anything with the shape of `fetch` that the SDK uses. |
| `clock`, `sleep`, `random` | | the platform's | Replace time and jitter, for tests. |

Nothing else is read implicitly. A missing credential or endpoint is a `ConfigurationError` at
construction, before any request. A credential is never accepted inside a URL: a `baseUrl` with
user information, a query string or a fragment is refused, and the refusal does not repeat the
value it was given. So is a `baseUrl` with a space, a line break or a character that does not show:
URL parsing would remove it without a word, and the address used would not be the one written. An
option the SDK does not know is refused too, rather than ignored.

**A platform with a certificate authority of its own.** The SDK has no setting for certificates,
because the platform's `fetch` takes none. In Node.js, name the authority's certificate when the
process starts, `NODE_EXTRA_CA_CERTS=platform-ca.crt node app.js`, which adds it to what Node
believes; or pass a `fetch` of your own that is set up the way you need. The SDK sends the
credential to `baseUrl` only, whatever that `fetch` is set up with, and never follows a redirect.

All times are in seconds, as they are everywhere in the platform's API.

A client holds no state of the server except the project, and may be shared by any number of
concurrent calls.

## Quickstart

### Create

```ts
const sandbox = await fabric.sandboxes.create("python", {
  cpu: 2,
  memory: "4GiB",
  disk: "10GiB",
  network: { mode: "allowlist", entries: [{ name: "packages.example", ports: [443] }] },
  name: "trainer",
  lifetime: "2h",
});
```

The platform creates and starts a sandbox with two operations, and `create` drives both: it
returns when the sandbox has started. With `start: false` it only creates. If the start is refused
or ends without success, the sandbox is destroyed (pass `onStartFailure: "keep"` to keep it) and
the call throws `SandboxStartError`, which names both outcomes.

`network` is `"none"` or an allowlist. There is no other mode: `"restricted"`, like every other
word, is refused before any request. A port is a number or a `[from, to]` pair.

### Run a command

```ts
const execution = await sandbox.exec(["python", "train.py", "--epochs", "3"], {
  cwd: "/work",
  env: { MODE: "test" },
  timeout: "10m",
});
if (execution.exit_code !== 0) {
  console.error(await execution.text("stderr"));
}
```

`exec` takes an argument vector and runs it directly, never through a shell. A string is never
split. To run a command line through a shell, say so: `sandbox.execShell("ls -la | wc -l")` sends
`["/bin/sh", "-c", "ls -la | wc -l"]`.

A command that exits with a status other than 0 is a result, not an error: `exec` returns the
execution, and the caller reads `exit_code`.

### Read output

```ts
const bytes = await execution.read("stdout");                         // Uint8Array, every chunk
const text = await execution.text("stdout");                          // UTF-8, strict
const lenient = await execution.text("stderr", { errors: "replace" });
const chunk = await execution.output("stdout", { offset: 0, maxBytes: 65536 }); // one slice
```

Output is what the guest wrote. Nothing vouches for it: treat it as untrusted data. `text` decodes
with the encoding and the error policy you name; `"strict"`, the default, throws on bytes that are
not valid in the encoding.

### Snapshot, restore, stop, destroy

```ts
const snapshot = await sandbox.snapshot("baseline");
await sandbox.restore(snapshot);                       // the same sandbox, in a new generation
const copy = await snapshot.restoreAsNew({ name: "copy" });
await sandbox.stop();
await sandbox.destroy();
```

### Handles and views

A returned object exposes every member of the platform's view under the name the platform sends
(`sandbox.sandbox_id`, `sandbox.expires_at`), so that it reads like the JSON it came from. A member
of the object that the server left out reads as the default of its schema (`null`, an empty list,
`false`), never `undefined`; a view nested inside it is as the server sent it. What the SDK adds is
camelCase:

- `raw`: the JSON exactly as received, with every member this version of the SDK does not know;
- `requestId`: the request id of the answer. Quote it when asking for help;
- `operation`: the operation whose result the object is (`sandbox.operation?.replayed` tells
  whether the answer reported work that existed before the request).

Every vocabulary of the platform (states, statuses, codes) is a plain string. A value this version
has never seen reaches you unchanged; it is never an error and never mapped onto a known one.

A sandbox handle **states what it saw**: every mutation names the generation the handle last
observed, so a sandbox that was restored behind your back refuses the request
(`RevisionConflictError`) instead of running a command somewhere you never looked. Call
`sandbox.refresh()` and decide. Pass `generation: "current"` to say explicitly that any generation
will do.

`fabric.sandboxes.handle(sandboxId)` makes a handle without a request, for a caller that already
knows the identifier, such as a job that kept it from an earlier run. Such a handle has seen no
generation, so each call through it names one itself (`{ generation: 7 }`, or `"current"`) until
`refresh()` has read the sandbox.

`fabric.executions.handle(executionId)` does the same for an execution. Use it to cancel:
`await fabric.executions.handle(id).cancel()` sends the cancel as its first and only request, so
stopping a command never waits behind a read that a rate limit could refuse.

A name is **resolved once**. `fabric.sandboxes.get("trainer")` reads the sandbox the name belongs
to now, and the handle acts on that sandbox's identifier from then on. If `refresh()` finds that
the name has since been given to another sandbox it throws `NameReboundError`; `refresh({ rebind:
true })` makes the handle that other sandbox.

### Everything else

```ts
for await (const sandbox of fabric.sandboxes.list()) { /* cursors are followed to the end */ }
const snapshot = await fabric.snapshots.get("baseline");     // by identifier or by name
const execution = await fabric.executions.get("exe-…");
await execution.cancel();                                     // the only thing that ends an execution
const operation = await fabric.operations.wait("op-…");       // follows; a failed operation is a result here
const me = await fabric.whoami();
const info = await fabric.info();

const agent = await fabric.auth.mintAgentCredential("worker", { lifetime: "1h" });
agent.secret;                                                 // present once; never printed or serialized
await fabric.auth.revokeAgentCredential(agent.credential_id, { contain: true });
```

Revoking a credential ends what it may ask for, not what it already started. With `contain` the
SDK also cancels every unfinished execution the revoked credential started, and reports which
cancels succeeded (`contained`) and which did not (`containmentErrors`).

Every call accepts `signal`, an `AbortSignal`. Aborting it abandons the call: the pending request
is dropped and the call rejects with the signal's reason. **Nothing is cancelled on the server.**
An operation that was accepted continues.

## Errors

An unsuccessful answer of the platform is one of two kinds, and the classes keep them apart.

| Class | Meaning | What to do |
|---|---|---|
| `RefusedError` and its subclasses | The request was not accepted. Nothing exists. | Follow `retry`: `SAME_REQUEST_LATER` (the SDK already retried), `AFTER_CHANGE` or `NEVER`. |
| `UnresolvedError` and its subclasses | The platform could not establish whether the request was accepted. An operation may exist. | Ask again later with the same key (`error.idempotencyKey`). Never with a new one. |
| `OutcomeLostError` | The platform accepted the key and cannot say what became of the work. | Inspect the target before acting again. Never retried. |
| `OperationFailedError` | The operation ended without success and nothing was applied. | A new request, with a new key, is allowed. |
| `OutcomeUnknownError` | The operation ended and whether it was applied is not known. Neither success nor failure. | Inspect the target before acting again. |
| `OperationStillRunningError` | The follow bound passed. Nothing is assumed and nothing was cancelled. | `fabric.operations.wait(error.operationId)`, or repeat the call with `error.idempotencyKey`. |
| `SandboxStartError` | The sandbox was created and its start did not succeed. | Read `cleanup`: `destroyed`, `kept` or `destroy_failed` (it still exists). |
| `NameReboundError` | The name a handle was obtained by now belongs to another sandbox. | Get the sandbox again, or `refresh({ rebind: true })`. |
| `APIConnectionError`, `APITimeoutError` | No answer arrived. | For a read: try again. For minting a credential: list, and revoke the one nobody saw. |
| `UnexpectedResponseError` | An answer the SDK cannot use: it is not the platform's, or it is a success without the result the call returns. | Read the message. Never retried. |
| `ConfigurationError`, `IncompatibleServerError` | The client cannot work as configured, or the server does not speak API `v1`. | Fix the configuration. |
| `RangeError`, `TypeError` | An argument the SDK cannot use: an ambiguous unit, a string where an argument vector belongs, an unknown option. | Thrown before any request. Fix the call. |

Every error of the SDK extends `FabricError` and has `requestId` when an answer was involved. An
error answer (`APIError`) has `status`, `code`, `kind`, `retry`, `message`, `requestId`,
`idempotencyKey`, `reason` and `retryAfter`. An `OperationError` has `operation`, `operationId`,
`idempotencyKey` and the operation's failure `code`.

Decisions are taken from `code`, `kind` and `retry`. Never branch on `status` alone, and never on
message text.

| `code` | Class |
|---|---|
| `INVALID_REQUEST`, `REQUEST_TOO_LARGE` | `InvalidRequestError` |
| `UNAUTHENTICATED` | `AuthenticationError` |
| `PERMISSION_DENIED` | `PermissionDeniedError` |
| `SAFETY_CONTROL_DENIED` | `SafetyControlDeniedError` |
| `NOT_FOUND` | `NotFoundError` |
| `STATE_CONFLICT`, `QUARANTINED`, `INTEGRITY_FAILURE`, `INCOMPATIBLE_RUNTIME` | `StateConflictError`, `QuarantinedError`, `IntegrityFailureError`, `IncompatibleRuntimeError`, each a `ConflictError` |
| `REVISION_CONFLICT` | `RevisionConflictError` |
| `IDEMPOTENCY_CONFLICT` | `IdempotencyConflictError` |
| `RATE_LIMITED` | `RateLimitError` |
| `RESOURCE_EXHAUSTED` | `CapacityError` |
| `HOST_NOT_SERVING`, `CLOCK_SKEW`, `UPSTREAM_UNAVAILABLE` | `ServiceUnavailableError` |
| `UNSUPPORTED` | `UnsupportedFeatureError` |
| `CURSOR_EXPIRED` | `CursorExpiredError` |
| `INTERNAL_ERROR` | `InternalError` |
| `REQUEST_IN_PROGRESS` | `RequestInProgressError`, an `UnresolvedError` |
| `OUTCOME_UNRESOLVED` | `OutcomeUnresolvedError`, an `UnresolvedError` |
| `OUTCOME_LOST` | `OutcomeLostError`, an `UnresolvedError` |
| a code this version does not know | `UnresolvedError` when `kind` is `UNRESOLVED`, else `RefusedError` |

## Retries and idempotency keys

Every call that creates an operation carries an idempotency key. The SDK generates one (a UUID)
before the first attempt and sends it, with the same body, on every retry of that call.

A call is retried at most `maxRetries` times. What is retried:

- an error answer whose `retry` is `SAME_REQUEST_LATER`, whatever its code;
- no answer at all, for a read and for a mutation that carries a key.

What is not: an error answer that says `AFTER_CHANGE` or `NEVER`; `OUTCOME_LOST`; an answer that is
not the platform's; minting an agent credential that got no answer. No rule looks at the HTTP
status alone.

`fetch` does not say whether a request left before it failed, so the SDK treats every transport
failure as "sent, and no answer came". A mutation without an answer is therefore never reported as
refused. When retries are exhausted it throws `OutcomeUnresolvedError`, which carries the key.

The wait before the n-th retry is random in `[0, min(8, 0.5 × 2ⁿ)]` seconds. A `Retry-After` of the
server replaces it when it is longer. If the server asks for more than 8 seconds the call is not
retried: the error is thrown with the advice in `retryAfter`. Each client also has a retry budget
(a retry is allowed while the retries of the last minute are fewer than 10 plus a fifth of the
requests of the last minute), so that clients do not pile onto a platform that is shedding load.

Listings follow cursors to the end. When a cursor has expired (`CURSOR_EXPIRED`) the listing is
begun again in full, at most three times, and each item is handed out once.

## Resuming a call

Pass your own `idempotencyKey` to make a call resumable, from this process or another. A key is 1
to 255 characters in the range 0x21 to 0x7E; for `sandboxes.create` at most 247, because the SDK
derives `<key>:start` and `<key>:destroy` from it.

```ts
import { Fabric, OperationStillRunningError, OutcomeUnresolvedError } from "@agent-compute/sdk";

const options = { cpu: 2, memory: "4GiB", disk: "10GiB", idempotencyKey: "nightly-2026-11-19" } as const;
try {
  await fabric.sandboxes.create("python", options);
} catch (error) {
  if (error instanceof OutcomeUnresolvedError || error instanceof OperationStillRunningError) {
    // Later, here or elsewhere: the same key and the same arguments. The platform answers with
    // the operation that already exists; it does not create a second one.
    await fabric.sandboxes.create("python", options);
  } else {
    throw error;
  }
}
```

The rules that keep one key equal to one operation:

- Repeat with the **same key and the same arguments**. The same key with other arguments is
  refused (`IdempotencyConflictError`).
- **Never switch to a new key** to get past `OutcomeUnresolvedError`, `RequestInProgressError` or
  `OutcomeLostError`. A new key is a new intent, and may be a second sandbox or a second run.
- After `OutcomeLostError` and `OutcomeUnknownError`, look at the target first.
- The platform remembers a key for about a day. After that the same key starts new work.

## Units

The API speaks integers: vCPUs, MiB, seconds. The SDK converts, and refuses anything ambiguous
with a `RangeError` before any request.

| Value | Accepted | Refused |
|---|---|---|
| `memory`, `disk` | an integer number of MiB; `"512MiB"`, `"4GiB"`, `"1TiB"`, `"1024KiB"`, `"1.5GiB"` (a whole number of MiB) | `"4GB"`, `"4G"`, `"4"`, `"4 GiB"`, `"0.1GiB"` (not whole MiB), `0`, `-1`, `512.5` |
| `lifetime`, `timeout` | an integer number of seconds; `"90s"`, `"10m"`, `"2h"`, `"1d"`, `"1.5h"` (whole seconds) | `"10"`, `"10min"`, `"10M"`, `"1.5s"` (not whole seconds), `0`, `-5`, `1.5` |
| `cpu` | a positive integer | `0`, `1.5`, `"2"` |

Units are case-sensitive and written without a space. `"4GB"` is refused because nobody can say
whether it means 4000 or 4096 MiB.

## Browsers

Constructing a client in a browser page (a `window` with a `document`) throws
`ConfigurationError`. A credential in a page is published to everyone who can open the page: call
the platform from a server instead. If the page is one only you can open, pass
`dangerouslyAllowBrowser: true`. The check is a heuristic about the runtime; it is not a control.

## What the SDK never does

- It sends nothing to any destination but the configured endpoint. No telemetry, no update check.
  It never follows a redirect, and it follows an operation at the configured endpoint, not at an
  address an answer names.
- It never writes to the console, and has no logger.
- It never puts the credential in a URL, an error message or the text form of a client, a handle
  or an error. Text of foreign origin (a server message, a transport failure) has the credential
  struck out before it becomes part of an error.
- It never retries what is not proven safe to repeat, never retries an operation that has ended,
  and never generates a new key to get past an answer.
- It never cancels anything by itself. A timeout, the follow bound and an aborted signal end the
  waiting and nothing else. Cancelling an execution is `execution.cancel()`.
- It never shows `UNKNOWN` or `OUTCOME_LOST` as success, or as a clean failure.
- It never introduces a shell, never splits a string into arguments, and never guesses a unit.
- It never acts on a name. A mutation names an identifier and a generation.
- It never caches the state of the server. A handle holds the view it last saw; `refresh()` reads
  it again.
- It never exports traces. If your application has set up OpenTelemetry and registered a global
  tracer provider, each call is recorded as one span in it, named `acf.` and the call (for example
  `acf.sandboxes.create`), with its retries as events. A span carries no credential, argument,
  environment value or output. The SDK does not import OpenTelemetry and does not depend on it.

## Development

```console
npm ci
npm run typecheck     # tsc --noEmit over src and tests
npm run build         # plain tsc: ESM and declarations into dist/
npm test              # vitest
```

The tests include a runner for the platform's client conformance suite, read from
`protocols/conformance/scenarios.json` of this repository. No test waits in real time, makes a
network connection, or uses a real credential.
