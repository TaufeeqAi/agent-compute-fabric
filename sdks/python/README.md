# agent-compute

The Python SDK of Agent Compute Fabric: create sandboxes, run commands in them, read what the commands
wrote, snapshot and restore, and follow every operation to its end. It has a synchronous client,
`Fabric`, and an asynchronous one, `AsyncFabric`, with the same surface.

The import name is `agentcompute`. This is version 0.1.0, for version `v1` of the public API. It needs
Python 3.12 or later and has one runtime dependency, the HTTP library `httpx2`.

## Install

The distribution name `agent-compute` is **not yet registered on PyPI**. Until it is, do not install a
package of that name from an index: it would not be this one. Install from a checkout of this
repository instead:

```console
python -m pip install ./sdks/python
```

or, in a project managed with `uv`:

```console
uv add ./sdks/python
```

## Configure

A client needs a key and the address of the platform. Each comes from an argument or, if the argument
is not given, from one environment variable:

| What | Argument | Environment | Notes |
|---|---|---|---|
| API key | `api_key` | `ACF_API_KEY` | Sent in the `Authorization` header and nowhere else. |
| Endpoint | `base_url` | `ACF_BASE_URL` | For example `https://acf.example`. |
| Project | `project` | `ACF_PROJECT` | Optional. Without it, the client asks the platform once which project the key belongs to. |
| Certificate authorities | `ca_file` | `ACF_CA_FILE` | Optional. A PEM file. With it, the authorities in that file are the only ones believed about the platform's certificate. |

A platform that you or your organisation run is usually certified by an authority of your own. Name
that authority's certificate with `ca_file`: the client then believes it and no other, not even the
ones your system trusts. A file that is missing or holds no certificate is refused when the client is
built; it is never passed over in favour of the system's authorities.

Nothing else is read from the environment: no proxy settings, and none of the general certificate
variables such as `SSL_CERT_FILE`. If you need those, pass your own `http_client` (an `httpx2.Client`,
or an `httpx2.AsyncClient` for `AsyncFabric`), configured the way you need; `ca_file` and an
`http_client` of your own are one setting too many, and are refused together. Whatever that client is
set up with, the SDK still sends the key to the configured endpoint only, and never follows a redirect.

A client refuses to be built, with a `ConfigurationError`, when:

- the key or the endpoint is missing;
- the endpoint carries user information, a query string or a fragment. A credential is never accepted
  inside a URL, because URLs end up in logs;
- the endpoint is not `https`. Plain `http` is accepted for a loopback address (`localhost`,
  `127.0.0.1`, `[::1]`), and for any address only with `allow_insecure_http=True`.

Other settings, all optional:

| Argument | Default | Meaning |
|---|---|---|
| `timeout` | `120.0` | Seconds for one HTTP request (connecting, sending, and waiting for the answer each get this long). It does not bound a followed operation. |
| `max_retries` | `2` | How often one request is sent again. |
| `follow_max` | `1800.0` | Seconds a call follows one operation before it gives the operation back as still running. Every call that follows takes its own `follow_max` too. |
| `retry_total_max` | `82800.0` | Seconds one request may be retried for, so that the platform still remembers the key when the last attempt arrives. |

## Quickstart

```python
from agentcompute import Fabric

with Fabric() as fabric:  # ACF_API_KEY and ACF_BASE_URL
    sandbox = fabric.sandboxes.create("python", cpu=1, memory="512MiB", disk="2GiB")
    try:
        result = sandbox.exec(["python", "-c", "print(6 * 7)"], timeout="1m")
        print(result.status, result.exit_code)  # EXITED 0
        print(result.text())  # 42
        print(result.read("stderr"))  # b''
    finally:
        sandbox.destroy()
```

The same with the asynchronous client. Every method is awaited, and a listing is an asynchronous
iterator:

```python
import asyncio

from agentcompute import AsyncFabric


async def main() -> None:
    async with AsyncFabric() as fabric:
        sandbox = await fabric.sandboxes.create("python", cpu=1, memory="512MiB", disk="2GiB")
        try:
            result = await sandbox.exec(["python", "-c", "print(6 * 7)"])
            print(await result.text())
            async for other in fabric.sandboxes.list():
                print(other.sandbox_id, other.state)
        finally:
            await sandbox.destroy()


asyncio.run(main())
```

`create` creates the sandbox and then starts it: two operations on the platform, driven by the SDK. It
returns when the sandbox has started. Pass `start=False` to create only.

A command is an **argument vector**. A string is never split, because splitting is what a shell does
and a shell is never introduced without being asked for. To run a command line through the sandbox's
shell, say so: `sandbox.exec_shell("ls -l | wc -l")` sends `["/bin/sh", "-c", "ls -l | wc -l"]`.

A command that exits with a status other than 0 is a **result**, not an error: `exec` returns, and
`status` and `exit_code` say what happened. Output is guest data. `read()` returns bytes, and `text()`
decodes them with the encoding and the error policy you choose (`utf-8` and `strict` by default).

## What a call returns

Every returned object exposes each member of its view as an attribute (`sandbox.state`,
`sandbox.resources.memory_mib`, `execution.exit_code`) and keeps the JSON exactly as the platform sent
it in `.raw`. A member this version does not know is still in `.raw`. Every state, status and code is a
plain string, so a value this version has never seen is shown as it came and is never mistaken for a
known one. `request_id` is on every result and on every error: quote it when you ask for help.

`Sandbox`, `Snapshot` and `Execution` are handles: views with methods. A handle returned by a call that
changed something also has `.operation`, the operation whose answer it came from. `operation.replayed`
is true when that answer reports work that already existed, for example after a lost answer.

```text
fabric.sandboxes    create(image, *, cpu, memory, disk, network=None, name=None, lifetime=None,
                           start=True, on_start_failure="destroy", idempotency_key=None, follow_max=None)
                    get(sandbox)   list()   handle(sandbox_id)
sandbox             start()  exec(argv, ...)  exec_shell(command, ...)  snapshot(name=None)
                    restore(snapshot)  stop()  destroy()  refresh(rebind=False)
fabric.snapshots    list()   get(snapshot)
snapshot            restore_as_new(name=None, lifetime=None)   delete()
fabric.executions   get(execution_id)   handle(execution_id)
execution           output(stream="stdout", offset=0, max_bytes=None)   read(stream)   text(stream)
                    cancel()   refresh()
fabric.operations   get(operation_id, wait=None)   list()   wait(operation_id, follow_max=None)
fabric.auth         whoami()   mint_agent_credential(label, lifetime=..., narrowing=None)
                    agent_credentials()   revoke_agent_credential(credential_id, contain=False)
fabric              whoami()   info()   close()
```

Every call that changes something also takes `idempotency_key=` and `follow_max=`, and every call on a
sandbox that changes it takes `generation=`.

## Units

The API takes integers: vCPUs, MiB, seconds. The SDK accepts what people write and converts it without
guessing.

| Argument | Accepted | Examples |
|---|---|---|
| `cpu` | a positive integer | `2` |
| `memory`, `disk` | an integer in MiB, or a string with a binary unit (`KiB`, `MiB`, `GiB`, `TiB`) that is a whole number of MiB | `512`, `"512MiB"`, `"4GiB"`, `"1.5GiB"` |
| `lifetime`, `timeout` | an integer in seconds, or a string with `s`, `m`, `h` or `d` that is a whole number of seconds | `90`, `"90s"`, `"10m"`, `"2h"`, `"1d"` |
| `network` | `"none"`, or an allowlist | see below |

Anything that could mean two things is refused with a `ValueError` before any request is made:
`"4GB"` and `"4G"` (a decimal unit and a bare letter do not say which size is meant), `"0.1GiB"` (it is
102.4 MiB, and someone would have to round it), `"512"` (a number in a string has no unit), a float, a
negative or zero value. Units are case-sensitive and there is no space between number and unit.

A sandbox has no network unless you ask for one, and there are two modes only. `"restricted"`, like
every other word, is refused. An allowlist names each destination and its ports; a port is a number or
a `[from, to]` pair:

```python
fabric.sandboxes.create(
    "python",
    cpu=2,
    memory="4GiB",
    disk="20GiB",
    network={
        "mode": "allowlist",
        "entries": [
            {"name": "packages.acf.example", "ports": [443]},
            {"network": "10.0.0.0/8", "ports": [[8000, 8100]]},
        ],
    },
)
```

Every argument the SDK refuses is a `ValueError`, whatever is wrong with it: a size without a unit, a
flag that is not `True` or `False`, an idempotency key with a space, a string where an argument vector
is required. One exception to catch, and it always means that nothing was sent.

## Operations and following

Everything that changes something is an operation that may outlive the request that started it. A call
follows its operation until it has ended, and then:

- `SUCCEEDED`: the call returns the resource;
- `FAILED` or `CANCELLED` and nothing was applied: `OperationFailedError`;
- `UNKNOWN`, or ended without success and possibly applied: `OutcomeUnknownError`. This is neither
  success nor failure. Inspect the target before you act again;
- not ended when `follow_max` seconds of following have passed: `OperationStillRunningError`. It carries
  the operation, its identifier and the key. Nothing is assumed and nothing is cancelled.

A state this version of the SDK does not know has not ended, so a newer platform cannot make an older
SDK report success or failure by mistake. `follow_max=0` submits and does not wait: a bound shorter than the 30
seconds for which the platform would hold the request by itself is sent along with it.

`fabric.operations.get(id)` reads any operation, and `fabric.operations.wait(id)` follows one and
returns it however it ended.

## Retries and idempotency keys

The SDK decides from the `kind`, `code` and `retry` of an error answer, never from the HTTP status
alone and never from message text. A request is sent again, at most `max_retries` times, when:

- the answer says `SAME_REQUEST_LATER`, whatever its code;
- nothing was sent (the connection could not be made);
- it was sent and no answer came back.

Nothing else is retried. A refusal that says `AFTER_CHANGE` or `NEVER` is raised at once, and
`OUTCOME_LOST` is never retried.

Between attempts the SDK waits a random time between zero and `0.5 s`, `1 s`, `2 s`, `4 s`, `8 s`
(doubling, capped at 8 s). If the platform sent `Retry-After` and it is longer, that is the wait. If it
is longer than 8 seconds the request is not retried: the error is raised with `retry_after` set, and
you decide. A client also keeps a retry budget, so that a platform shedding load is not hit harder: a
retry is allowed while the retries of the last minute are fewer than 10 plus a fifth of the requests of
the last minute.

Every call that can create an operation carries **one idempotency key**, made before the first attempt
(a random UUID) and reused, with the same body byte for byte, by every retry of that call. One key is
one operation on the platform: repeating a request with its key can never create a second one. The SDK
never makes a new key to get past a conflict, a request in progress, an unresolved outcome or a lost
one. It raises the error, and the error names the key.

`sandboxes.create` is two operations and possibly a third. They run under your key, that key with
`:start`, and that key with `:destroy`, so a key you pass to `create` is at most 247 characters. Any
other key is 1 to 255 visible ASCII characters with no space.

If the start is refused or ends without success, `on_start_failure` decides what becomes of the
sandbox: `"destroy"` (the default) destroys it, `"keep"` leaves it. Either way `SandboxStartError` says
which sandbox, why the start failed, and what happened to it (`cleanup` is `"destroyed"`, `"kept"` or
`"destroy_failed"`). A start whose outcome is merely not established destroys nothing.

## Resuming a call with a key

Pass your own key to make a call resumable from another process or after a crash:

```python
import uuid

key = str(uuid.uuid4())  # store it before the call
sandbox = fabric.sandboxes.create("python", cpu=1, memory="512MiB", disk="2GiB", idempotency_key=key)
```

If the process dies, or the call ends with `OutcomeUnresolvedError`, `RequestInProgressError` or
`OperationStillRunningError`, make **the same call again with the same key and the same arguments**. The
platform answers with the operation that already exists (`sandbox.operation.replayed` is then true) and
the SDK goes on from there, through the start as well. A key reused with different arguments is refused
with `IdempotencyConflictError`. A key that ended in `OutcomeLostError` is finished: inspect the target,
and use a new key for a new intent.

An operation can also be picked up by its identifier, which every `OperationError` carries:
`fabric.operations.wait(error.operation_id)`.

## Errors

Every error of the SDK is a `FabricError`. The classes keep apart the outcomes you must treat
differently.

| Error | What happened | What to do |
|---|---|---|
| `ConfigurationError` | The client cannot be built as configured. | Fix the configuration. |
| `IncompatibleServerError` | The endpoint does not speak API `v1`. | Check `base_url`. |
| `APIConnectionError`, `APITimeoutError` | The platform was not reached, or a request that carries no idempotency key was not answered. | Try again later. After a mint, list the agent credentials first. |
| `UnexpectedResponseError` | The answer is not an answer of this API. | Check what stands at the endpoint; report it with `request_id`. |
| `RefusedError` | The request was not accepted. **Nothing exists** because of it. | Follow `retry`: `SAME_REQUEST_LATER`, `AFTER_CHANGE` or `NEVER`. |
| `UnresolvedError` | The platform could not establish whether the request was accepted. An operation may exist. | Make the same call again with `idempotency_key`. Never use a new key. |
| `OperationFailedError` | The operation ended and nothing was applied. | A new call is allowed. |
| `OutcomeUnknownError` | The operation ended and may have been applied. | Inspect the target before acting again. |
| `OperationStillRunningError` | The follow bound passed. | Follow it later; nothing was cancelled. |
| `SandboxStartError` | `create` created the sandbox and could not start it. | Read `cleanup`, `start_error`, `destroy_error`. |
| `NameReboundError` | The name a handle was obtained by now belongs to another sandbox. | `refresh(rebind=True)`, or get the sandbox again. |

`RefusedError` and `UnresolvedError` are both `APIError`, which carries `status`, `code`, `kind`,
`retry`, `message`, `request_id`, `idempotency_key`, `reason` and `retry_after`. The specific classes
follow the `code`:

| `code` | Exception |
|---|---|
| `INVALID_REQUEST`, `REQUEST_TOO_LARGE` | `InvalidRequestError` |
| `UNAUTHENTICATED` | `AuthenticationError` |
| `PERMISSION_DENIED` | `PermissionDeniedError` |
| `SAFETY_CONTROL_DENIED` | `SafetyControlDeniedError` |
| `NOT_FOUND` | `NotFoundError` |
| `REVISION_CONFLICT` | `RevisionConflictError` |
| `IDEMPOTENCY_CONFLICT` | `IdempotencyConflictError` |
| `RATE_LIMITED` | `RateLimitError` |
| `RESOURCE_EXHAUSTED` | `CapacityError` |
| `HOST_NOT_SERVING`, `CLOCK_SKEW`, `UPSTREAM_UNAVAILABLE` | `ServiceUnavailableError` |
| `UNSUPPORTED` | `UnsupportedFeatureError` |
| `CURSOR_EXPIRED` | `CursorExpiredError` |
| `INTERNAL_ERROR` | `InternalError` |
| `STATE_CONFLICT` | `StateConflictError` (a `ConflictError`) |
| `QUARANTINED` | `QuarantinedError` (a `ConflictError`) |
| `INTEGRITY_FAILURE` | `IntegrityFailureError` (a `ConflictError`) |
| `INCOMPATIBLE_RUNTIME` | `IncompatibleRuntimeError` (a `ConflictError`) |
| `REQUEST_IN_PROGRESS` | `RequestInProgressError` (an `UnresolvedError`) |
| `OUTCOME_UNRESOLVED` | `OutcomeUnresolvedError` (an `UnresolvedError`) |
| `OUTCOME_LOST` | `OutcomeLostError` (an `UnresolvedError`) |

A code this version does not know is raised as `RefusedError`, or as `UnresolvedError` if the answer
says so, and is handled by its `kind` and `retry` like any other.

A mutation under a key that ends without a usable answer is an `OutcomeUnresolvedError`, never a
refusal: the SDK cannot know whether the platform received it, and the key settles that later.

## Generations and names

A sandbox handle **states what it saw**. Every call that changes the sandbox carries the generation of
the view the handle holds. If the sandbox was restored in the meantime, the platform refuses with
`RevisionConflictError`: call `sandbox.refresh()`, look at what changed, and decide. Pass
`generation="current"` only when you mean to act on whatever is there.

A **name is resolved once**. `fabric.sandboxes.get("build")` finds the sandbox the name belongs to now,
and the handle acts on that sandbox's identifier from then on. If the name later belongs to another
sandbox, `refresh()` raises `NameReboundError` and leaves the handle as it was.

`fabric.sandboxes.handle(sandbox_id)` makes a handle without a request, for a caller that already knows
the identifier and the generation. It has seen no generation, so each call through it says
`generation=` itself.

`fabric.executions.handle(execution_id)` does the same for an execution. Use it to cancel:
`fabric.executions.handle(execution_id).cancel()` sends the cancel as its first and only request, so
stopping a command never waits behind a read that a rate limit could refuse.

## Agent credentials

An agent is given a credential of its own, narrower and shorter-lived than yours:

```python
credential = fabric.auth.mint_agent_credential("builder", lifetime="2h")
secret = credential.secret  # in this answer and in no later one: keep it now
```

Minting and revoking carry no idempotency key. If no answer to a mint arrives, the SDK does not ask
again: list `fabric.auth.agent_credentials()` and revoke the one with that label whose secret you never
saw.

Revoking ends what a credential may ask for. It does not end what the credential already started, and
the platform cancels nothing by itself. `revoke_agent_credential(credential_id, contain=True)` revokes
and then cancels every execution the credential started that has not ended. The returned credential
lists the executions that were cancelled (`contained`) and the cancels that did not succeed
(`containment_errors`).

## What the SDK never does

- **It sends no telemetry.** Nothing leaves the process except requests to the endpoint you configured.
  There is no telemetry dependency. Spans are created only if your application installed OpenTelemetry
  itself, through that installation, one span per call; the SDK never configures an exporter.
- **It keeps no copy of the platform's state.** A handle holds the last view an answer gave it and
  nothing is cached behind your back. The one thing a client remembers is the project of its key.
- **It cancels nothing when it stops waiting.** A timeout, a cancelled task, Ctrl-C and the follow bound
  all stop the waiting and nothing more. The operation goes on. Cancelling an execution is the explicit
  call `execution.cancel()`.
- **It never makes a new idempotency key to get past a problem**, and never repeats an operation that
  has ended.
- **It never sends the key anywhere but the endpoint**, never follows a redirect, and never puts the key
  in a URL, a log record, an error message or a `repr`.
- **It never reads configuration you did not give it**: three environment variables, and nothing else.

## Logging

The SDK logs to the `agentcompute` logger and decides nothing about where records go. Each retry is an
`INFO` record with its attempt number, and each answer a `DEBUG` record with its request id.

## Development

```console
cd sdks/python
uv sync --locked
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked mypy
uv run --locked pytest -q
```

The tests talk to a scripted transport and run on a virtual clock: none of them opens a connection or
waits in real time. They include the client conformance suite of the API
(`protocols/conformance/scenarios.json`), run against both clients, and they hold every request the SDK
makes against the OpenAPI document under `protocols/api`.
