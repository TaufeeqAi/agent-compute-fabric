# acf-local — reference client of the Agent Compute Fabric host agent

`acf-local` is the command-line client of the **host agent** (`acf-host`), the privileged
execution plane that runs untrusted code in microVM sandboxes. It speaks the host's wire protocol
`acf.host/2` over the host's local Unix socket or over its mutual TLS endpoint, and it is the
reference implementation of the *caller's half* of that protocol: how to identify an operation,
how to follow it, and what to do when an answer is lost.

```console
$ acf-local run once --image python --cpu 2 --memory 4096 -- python experiment.py
```

This process is only a client. It parses arguments, resolves names to ids, follows operations,
renders answers and chooses exit codes. Who may ask, what is allowed, which transitions are legal
and what actually happened are decided by the host agent; nothing here is trusted to enforce it.

Contents: [Install](#install) · [Connecting](#connecting) · [How a command talks to the host](#how-a-command-talks-to-the-host) ·
[Commands](#commands) · [Output](#output) · [Exit codes](#exit-codes) · [Mutual TLS setup](#mutual-tls-setup) ·
[Development](#development)

## Install

```console
uv tool install ./apps/cli          # puts `acf-local` on your PATH
# or with pip, into an environment of your choice:
pip install ./apps/cli
# or, from a checkout, without installing:
python apps/cli/main.py --help
```

Requires Python 3.12 or newer on Linux. Runtime dependencies are deliberately few (`typer`,
`pydantic`, `rich`): this process talks to a privileged host agent, so every dependency is
supply-chain surface. TLS is the standard library's `ssl`.

## Connecting

Global options come before the command. Where the table names a variable, the option can also be
set in the environment; what is typed on the command line wins.

| Option | Environment | Default | Meaning |
|---|---|---|---|
| `--socket PATH` | `ACF_SOCKET` | `/run/acf/host-agent.sock` | The host's local endpoint. |
| `--tls HOST:PORT` | `ACF_TLS` | — | The host's network endpoint (mutual TLS 1.3) instead of the socket. |
| `--cert FILE` | `ACF_TLS_CERT` | — | With `--tls`: your client certificate (PEM). Required. |
| `--key FILE` | `ACF_TLS_KEY` | — | With `--tls`: its private key (PEM, without a passphrase). Required. |
| `--ca FILE` | `ACF_TLS_CA` | system trust store | With `--tls`: the authority that signed the host's certificate. |
| `--server-name NAME` | `ACF_TLS_SERVER_NAME` | the HOST of `--tls` | With `--tls`: the name the host's certificate must be valid for. |
| `--scope LABEL` | `ACF_SCOPE` | `default` | Owner scope sent with every request. |
| `--on-behalf-of LABEL` | `ACF_ON_BEHALF_OF` | — | Label recorded with every operation; never compared. |
| `--connect-timeout SECONDS` | `ACF_CONNECT_TIMEOUT` | `5` | Time to connect and authenticate. |
| `--verbose`, `-v` | — | off | Progress and extra detail on stderr. |

Operation commands additionally read `ACF_TIMEOUT` (see `--timeout` below).

What you type has to be consistent: `--socket` together with `--tls`, or `--cert`, `--key`, `--ca`
or `--server-name` without `--tls`, is a usage error. The environment only supplies defaults, and
a default that does not apply is ignored: `--socket PATH` on the command line reaches the local
socket although `ACF_TLS` is exported, and the `ACF_TLS_*` file variables mean nothing without a
TLS endpoint. If `ACF_SOCKET` and `ACF_TLS` are both set and neither option is typed, the TLS
endpoint is used.

**Local socket.** The host identifies you by the credentials the kernel reports for the connecting
process — nothing you send — and looks them up in its enrolment table. The kernel limits a Unix
socket path to 107 bytes; when the path you give is longer than that (a deep directory, a bind
mount), the client connects through a descriptor of the socket's directory instead of failing.

**Mutual TLS.** `--tls` selects the network endpoint. The connection is TLS 1.3 only (pinned on
both ends of the version range), the host's certificate is verified against `--ca` and against the
server name, and your client certificate is always presented: there is no one-way TLS mode, so
`--tls` without `--cert` and `--key` is a usage error. When `--ca` is given, the system trust
store is not used. See [Mutual TLS setup](#mutual-tls-setup).

**Who you are, and what you see.** An enrolled peer has one of three roles:

| Role | May call |
|---|---|
| `observer` | `host info`, `host metrics` |
| `caller` | everything except the operator commands, on records of its own owner scope |
| `operator` | everything, on any record; plus `profile reload`, `quarantine release`, `host set-mode`, `host acknowledge` |

The **owner scope** (`--scope`) is an opaque label the host attaches to every sandbox, snapshot
and operation you create. As a `caller` you see and act only on records whose peer and scope equal
your own; anything else is reported as `NOT_FOUND`, so its existence is not revealed. A name is
unique among your own live sandboxes, or among your own snapshots. The client never sends an
`authority` field: that field is reserved by the protocol for a signed decision, and a host that
does not offer the feature refuses any request that carries it.

## How a command talks to the host

A request has one of three answers:

| Answer | Meaning | Afterwards |
|---|---|---|
| `REFUSED` | the request was not accepted | nothing was applied; no operation record exists |
| `OPERATION` | the request was accepted | a durable operation record exists; the answer is its state as of the response |
| `RESULT` | a read, served from committed state | nothing changed |

Reads (`inspect`, `list`, `host info`, …) are one round trip. Every other command creates an
**operation**, and the client drives it as follows.

**One identity per intent.** The client generates an `operation_id` and stamps `issued_at` (UTC)
once, before anything is sent. `--operation-id ID` supplies your own id (8–64 characters of
`[A-Za-z0-9-]`): repeating a command with the same id and the same arguments returns the same
operation, and nothing runs twice, for as long as the host keeps the record (`host info` reports
its operation retention). The same id with *different* arguments is refused with
`IDEMPOTENCY_CONFLICT`.

**Waiting.** By default (`--wait`) the client follows the operation until it reaches a terminal
state: it asks the host to hold the answer for up to 20 seconds, then observes the operation with
`operation.get`, backing off from 0.1 s to 2 s between polls. `--timeout DURATION` (or
`ACF_TIMEOUT`; `90`, `90s`, `5m`) bounds how long the client follows. It does **not** affect the
operation: the host finishes what it accepted whether or not anyone is listening, within the
operation's own deadline. Without `--timeout` the client follows until the operation ends.
`--no-wait` asks the host to answer as soon as the operation is recorded and returns that state.

**A lost response is resolved, never repeated.** If the request was written and no answer came
back (the connection dropped, the read timed out), the host may have accepted it. The client then
sends the **same `operation_id` and the same `issued_at`** again with `retry: true` — never a new
id:

* the host answers with the existing operation → the client follows it;
* the host answers `NOT_FOUND` and `operation.get` confirms it holds no record → the request was
  never accepted, and it is submitted again under the same id and the same `issued_at`. After
  three submissions that the host never recorded the client stops: nothing was applied, exit `6`;
* the host refuses the retry for another reason → that is not yet an answer about the operation.
  A host resolves a request that names an operation it holds before it looks at its mode or at the
  age of the request, but a lookup can still be refused for load, and a host that is starting
  serves nothing. The client asks `operation.get`: if the operation exists it is followed; if it
  does not, the refusal is the answer;
* the host cannot be reached again → the client keeps trying for up to 60 seconds (or until
  `--timeout`), then exits `8` and prints the operation id. The outcome is *not established*: ask
  later with `acf-local operation get ID --wait`. Do not run the command again without
  `--operation-id ID`: a new id would be a second operation.

The same question (`operation.get`) is asked once when a first submission is refused with
`INTERNAL_ERROR`, the one class with which a host says it does not know what went wrong.

If the request never left this machine (no connection, a failed handshake), nothing was sent and
the exit code is `6`.

**An unknown outcome is reported as unknown.** An operation can end `UNKNOWN`: it may have been
applied and the host cannot establish it. The client reports exactly that — exit code `5`, never
success and never failure — and nothing is retried. The same holds for any state or other
vocabulary word this client does not know: it is printed as the host sent it, marked
`(not recognized by this client)`, and never treated as a known one.

**Effect and cleanup.** Every terminal operation states its `effect`, and a failed or cancelled
one states its `cleanup`. Both are always shown.

| `effect` | Meaning |
|---|---|
| `APPLIED` | the operation's effect is in place |
| `NOT_APPLIED` | nothing was applied; a new operation for the same intent is safe |
| `MAY_BE_APPLIED` | it may have been applied; a new operation for the same intent is not known to be safe |

| `cleanup` | Meaning |
|---|---|
| `COMPLETE` | everything the operation created is proven removed |
| `PENDING` | something it created remains and still holds its capacity |
| `QUARANTINED` | what it left is quarantined; an operator must release it |

**Refusals** are reported with their class and the host's retry advice: `SAME_REQUEST_LATER`
(nothing is wrong with the request; the host cannot take it now), `AFTER_CHANGE` (it can be
accepted once the target, the host or the request changes) or `NEVER`.

**Ctrl-C** during an operation prints the operation id and how to ask about it; the host still
finishes what it accepted. During `sandbox exec` it also asks the host to cancel the execution and
reports how the execution really ended. Exit code `130`.

## Commands

Every command accepts `--json`. Commands that create an operation also accept `--operation-id`,
`--wait/--no-wait` and `--timeout`; `run once`, which is four operations, takes `--timeout` only,
and it bounds each of its steps. A sandbox is named by id (`sbx-…`) or by name; a mutation always
carries the id and the generation, never a name (see [Targets](#targets-and-preconditions)).

### Sandboxes

```console
# create: resources reserved, storage provisioned, not yet started
acf-local sandbox create --image python --cpu 2 --memory 4Gi --disk 2048 --name job-7 --lifetime 2h

# with outbound connectivity limited to an allowlist (default: --network none)
acf-local sandbox create --image python --network allowlist \
    --allow pypi.org:443 --allow 198.51.100.0/24:5432-5433,8443

acf-local sandbox start job-7                       # launch the runtime; ends READY
acf-local sandbox exec job-7 -- python train.py --epochs 3
acf-local sandbox exec job-7 --shell -c 'ls | wc -l' -e LANG=C.UTF-8 --cwd /workspace --time-limit 90s
acf-local sandbox exec job-7 --secret-env API_TOKEN=ci-token -- python deploy.py
acf-local sandbox inspect job-7
acf-local sandbox list
acf-local sandbox stop job-7                        # ends the runtime, keeps the storage
acf-local sandbox destroy job-7 --yes               # irreversible; its snapshots are kept
```

| Flag | Meaning |
|---|---|
| `--image ALIAS` | Image alias installed on the host and allowed by its safety profile. |
| `--cpu N` | vCPUs: 1 or an even number. |
| `--memory SIZE`, `--disk SIZE` | `4096` (MiB), `512Mi`, `4Gi`. |
| `--network none\|allowlist` | `none`: no network device exists in the guest. `allowlist`: outbound TCP to the `--allow` entries only. |
| `--allow DEST:PORTS` | Repeatable. `DEST` is an exact DNS name, an IPv4 network in CIDR form, or a single IPv4 address; `PORTS` is a comma-separated list of ports and `LOW-HIGH` ranges. Requires `--network allowlist`. |
| `--lifetime DURATION` | How long the sandbox may live (`3600`, `90m`, `2h`, `1d`). The host destroys it at expiry. Default: the profile's. |
| `--name NAME` | Alias, unique among your own live sandboxes. |

The host refuses a request that exceeds its safety profile (`SAFETY_CONTROL_DENIED`); it never
reduces one to fit. Some destinations are always denied whatever the profile says (loopback,
link-local and metadata addresses, multicast, the host itself); such an entry is refused with
`INVALID_REQUEST`.

`sandbox exec` flags:

| Flag | Meaning |
|---|---|
| `-- ARGV…` or `--command "…"`, `-c` | The command. It is **not** run through a shell: `--command` is split POSIX-style into an argument vector. |
| `--shell` | Run `--command` via `/bin/sh -c` inside the guest (pipes, globs, `&&`). |
| `--env KEY=VALUE`, `-e` | Repeatable. The name must be on the profile's allowlist. |
| `--secret-env VARIABLE=REFERENCE` | Repeatable. The host delivers the secret named `REFERENCE` as `VARIABLE`. See below. |
| `--cwd DIR` | Working directory inside the guest; must be under a prefix the profile permits. |
| `--time-limit DURATION` | Run time limit of the command (`90s`, `1500ms`, `2m`). Default: the profile's. |
| `--max-pids N`, `--max-stdout SIZE`, `--max-stderr SIZE` | Process and captured-output limits (`65536`, `64KiB`, `1MiB`). |
| `--raw` | Relay guest output byte-for-byte even to a terminal. |
| `--propagate-exit-code` | Exit with the command's own status (128+N if killed by signal N) instead of `1`. |

**Secrets are named by reference, only.** `--secret-env API_TOKEN=ci-token` asks the host to
deliver the secret that the operator provisioned on the host under the name `ci-token`. The
protocol has no field that could carry secret material, and neither has this client: a value that
is not a well-formed reference (1–64 characters of `[A-Za-z0-9._-]`, not starting with a dot) is
refused without being sent and without being repeated in the error message. Never pass a secret
itself; `--env` values are ordinary, non-secret data.

**Guest output is untrusted.** When stdout or stderr is a terminal, control and bidi characters
are shown as visible escapes so a workload cannot retitle your terminal or rewrite earlier lines.
When piped or redirected the bytes pass through exactly.

### Snapshots

```console
acf-local snapshot create job-7 --name baseline     # the sandbox must be idle
acf-local snapshot list

# restore in place: a NEW GENERATION of the same sandbox; it keeps its expiry
acf-local snapshot restore baseline --into job-7

# restore as a brand-new sandbox
acf-local snapshot restore baseline --new --name job-7-copy --lifetime 1h

acf-local snapshot delete baseline --yes            # refused while something depends on it
```

`snapshot restore` needs exactly one of `--into SANDBOX` and `--new`; the client does not guess.
A restore in place builds the new generation, verifies it, and only then makes it current: a
failed restore never costs you the sandbox you had. A snapshot is identified by id and generation;
a name, or an id without `--snapshot-generation N`, is looked up through `snapshot list` first.

### Targets and preconditions

A command that changes a sandbox sends `(sandbox_id, expected_generation)`. Given a name — or an id
without a generation — the client reads the sandbox first (`sandbox.inspect`) and uses the
generation it saw. If the sandbox changed in between, the host answers `REVISION_CONFLICT` instead
of acting on something you did not mean.

| Flag | Meaning |
|---|---|
| `--expected-generation N` | Act only if `N` is the sandbox's current generation. Together with an id, the client does not need to read the sandbox first. |
| `--if-revision N` | Stronger: act only if the sandbox's revision (shown by `sandbox inspect`) still equals `N`. |

```console
acf-local sandbox stop sbx-0190f3…  --expected-generation 2 --if-revision 31
```

### Listings and cursors

`sandbox list`, `snapshot list` and `operation list` return one page and print the **cursor** the
listing stands at (`LINEAGE:SEQUENCE`).

| Flag | Meaning |
|---|---|
| `--limit N` | Page size, 1–1000. |
| `--changed-since CURSOR` | Only records that changed after the cursor — **including tombstones**: destroyed sandboxes and deleted snapshots. |
| `--all` | Follow the listing to its end instead of stopping at one page. |

```console
$ acf-local sandbox list
…
2 record(s); listing complete; cursor 5f3c8a1e9b7d42c6a0e1f2d3c4b5a697:41
$ acf-local sandbox list --changed-since 5f3c8a1e9b7d42c6a0e1f2d3c4b5a697:41    # what changed since
```

A full listing shows what exists; a listing from a cursor shows what changed. With `--all`, pages
after the first are changes: a later page replaces what an earlier page said about the same
record. A cursor from another store, or older than the host's change retention, is refused with
`CURSOR_EXPIRED`: list again without one.

### Operations

```console
acf-local operation get op-3f2a…             # what does the host say happened? (never submits anything)
acf-local operation get op-3f2a… --wait      # …and follow it until it has ended
acf-local operation list --limit 50
acf-local operation cancel op-3f2a…          # ask the host to cancel a running execution
```

`operation get` is the tool for a lost response: its exit code states the operation's condition
(`0` succeeded, `4` failed or cancelled, `5` unknown, `8` not ended yet, `3` the host holds no
such operation for you — which, within its operation retention, means the request was never
accepted).

`operation cancel` is itself an operation. It succeeds when the execution has ended — cancelled,
or because it had already finished, in which case nothing changes. Only an execution in progress
can be cancelled; anything else is refused with `STATE_CONFLICT`, because it is bounded by its own
deadline and stopping or destroying the sandbox preempts it.

### Executions

```console
# create a sandbox, start it, run one command, destroy it
acf-local run once --image python --memory 2Gi -- python experiment.py
acf-local run once --image python --keep --name scratch --command "pip list"

acf-local run inspect run-0190f3…            # the record of an execution: status, metrics, limits, artifacts
acf-local run output run-0190f3… --stream stderr
acf-local run output run-0190f3… --offset 4096 --max-bytes 65536
```

`run once` takes the flags of `sandbox create` and of `sandbox exec`, plus `--keep`. It is composed
from four operations (create, start, exec, destroy), each with its own operation id, and it
reports them all. The sandbox is destroyed whatever happened — success, failure, an unknown
outcome, a timeout, Ctrl-C — unless `--keep`: destroying is containment, the host never refuses it
for load, and the record of every operation and the captured output outlive the sandbox. If it is
not established whether the host accepted `create`, there is no sandbox id to act on; the report
says so and names the operation to ask about. A cleanup that fails is reported loudly with the
command that finishes it, and makes the exit code non-zero.

Execution output is readable only through `run inspect` and `run output`. The host returns stored
output in slices; `run output` asks for them in turn, from `--offset` to the end of the stream or
`--max-bytes`, and accepts `--raw` like `sandbox exec`. An execution that has not ended has no
result yet: `run inspect` then shows its operation and exits `8`.

Two different questions are kept apart: *did the operation succeed?* (the host ran the command and
recorded the result) and *did the workload succeed?* (it exited with status 0). A non-zero exit, a
signal or a guest-side timeout is a **result** of a successful operation: exit code `1`.

### Host and operator commands

```console
acf-local host info                          # version, protocols, features, mode, lineage, profile, bounds
acf-local host metrics
acf-local host set-mode draining             # operator: create no new privilege (planned restart)
acf-local host set-mode serving
acf-local host acknowledge store-regression --yes
acf-local profile reload                     # operator: re-read the safety profile file
acf-local quarantine release sbx-0190f3… --generation 2 --mode force-destroy --yes
acf-local quarantine release sbx-0190f3… --generation 2 --mode declare-absent --yes
```

* **`host set-mode`** — while `DRAINING` the host refuses everything that creates privilege
  (create, start, exec, snapshot, restore) with `HOST_NOT_SERVING` and keeps serving stop,
  destroy, cancel and reads. Every other mode is entered by the host itself.
* **`host acknowledge store-regression`** — after its store was found older than the system it
  describes, the host creates no privilege and takes no destructive action until an operator
  states that the store it has is the one to trust.
* **`profile reload`** — the host validates the file before anything changes: an invalid profile
  is refused and the previous one stays in force. Operations already admitted keep the profile
  they were admitted under.
* **`quarantine release`** — a generation the host could not prove to be its own accepts no other
  operation. `force-destroy` asserts that its recorded resources belong to this host: the host
  tears them down and verifies absence. `declare-absent` asserts that nothing remains: the host
  only verifies. If observation contradicts the assertion, the release ends `FAILED` and the
  generation stays quarantined. It takes a sandbox id, never a name.

Destructive commands (`sandbox destroy`, `snapshot delete`, `host acknowledge`,
`quarantine release`) ask for confirmation on a terminal and **refuse** without `--yes` when there
is no terminal to ask on.

## Output

Human-readable output is the default: the result (a sandbox, a snapshot, a table) followed by the
operation that produced it — its id, state, `effect`, `cleanup`, failure and the committed state
the answer reflects (`as of LINEAGE:SEQUENCE`). Refusals, errors, hints and listing footers go to
stderr.

`sandbox exec` and `run once` are different, so that they compose in pipelines: stdout carries the
guest's stdout, byte for byte, and nothing else; the guest's stderr, the execution report and the
operation go to stderr. `run output` likewise writes only the stored bytes to stdout.

With **`--json`**, stdout carries exactly one JSON document and nothing else:

* the host's answer in wire form (`{"protocol", "answer", "refusal" | "operation" | "result",
  "as_of"}`), exactly as the host's published API description
  (`execution/contracts/host-api.json`) defines it, without the per-request correlation id. Fields
  this client does not know are passed through unchanged. For a command that followed an
  operation, the document is the `OPERATION` answer with the operation as last stated; `run output`
  joins the slices it read into one `output` result; `--all` joins pages into one page;
* for `run once`: `{"operations", "steps", "run", "sandbox", "cleanup", "interrupted", "error",
  "exit_code"}`, where `steps` maps each step to its answer;
* when there is no host answer to print (a transport failure, an outcome that is not established,
  a usage error found by the client): `{"error": {"kind", "message", "hint", "operation_id",
  "exit_code"}}`.

The exit code is the same with and without `--json`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success: the operation `SUCCEEDED` (and, for `exec` / `run once`, the command exited with status 0), or the read was answered. |
| `1` | `sandbox exec` / `run once` only: the operation succeeded and the command did **not** exit with status 0 (`--propagate-exit-code` returns its own status instead). |
| `2` | Usage error. Nothing was sent. Includes a destructive command without `--yes` and no terminal. |
| `3` | The host **refused** the request (class and retry advice are printed). Nothing was applied. Also: a name that did not resolve. |
| `4` | The operation ended `FAILED` or `CANCELLED`. Also returned by `run once` when the command ran but the sandbox could not be destroyed. |
| `5` | The operation ended **`UNKNOWN`**: it may have been applied. Neither success nor failure. |
| `6` | Transport error: the host could not be reached, or a read was not answered. Nothing was changed by this command. |
| `7` | Protocol error: the peer did not answer in `acf.host/2`. |
| `8` | Not established **yet**: the operation is still in progress (`--no-wait`, `--timeout`), or contact was lost after the request may have been sent. Ask with `acf-local operation get ID --wait`. |
| `130` | Interrupted (Ctrl-C). |
| `141` | The reader of stdout went away (`acf-local … \| head`). |

`--propagate-exit-code` exists for scripts that want the workload's own status. Those values live
in the same number space as this table: a command that exits `3` is then indistinguishable from
"the host refused" unless you also read `--json`.

## Mutual TLS setup

The host's network endpoint is off unless its configuration has an `edge.tls` section (see
`config/host.example.yaml`):

```yaml
edge:
  tls:
    listen: "0.0.0.0:7443"
    certificate: /etc/acf/tls/host.crt       # the host's certificate chain
    private_key: /etc/acf/tls/host.key
    trust_anchors: /etc/acf/tls/clients-ca.crt   # authorities trusted to sign CLIENT certificates
```

A client certificate that chains to one of those trust anchors is only *authenticated*. It has
authority once the host's enrolment table (`config/enrolment.example.yaml`) names it — by the
fingerprint of the certificate, or of its public key, which survives re-issuing the certificate:

```console
# SHA-256 of the DER certificate
openssl x509 -in client.crt -outform DER | sha256sum
# SHA-256 of the public key
openssl x509 -in client.crt -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum
```

```yaml
peers:
  - peer_id: control-plane-1
    role: caller
    match: { spki_sha256: "<the public-key fingerprint>" }
```

Then, on the client:

```console
export ACF_TLS=host-1.example:7443
export ACF_TLS_CERT=~/.config/acf/client.crt
export ACF_TLS_KEY=~/.config/acf/client.key      # mode 0600; no passphrase
export ACF_TLS_CA=~/.config/acf/host-ca.crt      # the authority that signed the HOST's certificate
acf-local --scope team-a host info
```

What you see when something is wrong:

| Situation | What happens |
|---|---|
| Your certificate is valid but not enrolled | The host refuses with `AUTHENTICATION_FAILED` (exit `3`). |
| Your certificate does not chain to the host's client trust anchors | The connection is not accepted: "did not accept this client's certificate" (exit `6`). The request was not read. |
| The host's certificate is not signed by `--ca`, or is not valid for the server name | "the certificate presented by … was not accepted" (exit `6`). Nothing was sent. Use `--server-name` when you connect by an address the certificate does not list. |
| The peer does not speak TLS 1.3 | "TLS handshake … failed" (exit `6`). |
| The private key is encrypted | Usage error: the client never prompts for a passphrase. |

The client never prints or logs certificates' private keys, and never reads key material itself:
the key file is handed to the TLS library by path.

## Development

```console
cd apps/cli
uv sync
uv run ruff check . && uv run ruff format --check .
uv run mypy
uv run pytest                      # unit and contract tests; the end-to-end tests skip without a host
```

Three layers of tests:

* **Unit tests** — framing, request envelopes, response models (including unknown vocabulary words
  and unknown fields), the lost-response and follow logic against a scripted in-process transport,
  the transports against a real Unix socket and a TLS peer, rendering, every command, exit codes.
* **Contract tests** (`tests/test_contract.py`) — the client against the host's published API
  description `execution/contracts/host-api.json`: the method table, every vocabulary, the fields
  of every request and response type, every request the client can build, and answers recorded
  from the real host (`tests/data/recorded_answers.json`). They need no host. Re-record the
  answers when the host's wire types change:
  `ACF_HOST_FAKE=/path/to/acf-host-fake python tests/record_answers.py`.
* **End-to-end tests** (`-m e2e`) — the real client against the real host agent over its local
  socket and over mutual TLS, on an in-memory backend (**no KVM and no root needed**; they prove the
  seams between client, wire and host, not isolation). Each test starts a host of its own.

```console
cargo build -p acf-host-agent --features testing --bin acf-host-fake     # test-only; never in a release
ACF_REQUIRE_E2E=1 ACF_HOST_FAKE=$PWD/../../target/debug/acf-host-fake uv run pytest -m e2e
```

`ACF_HOST_FAKE` names the binary. Without it the end-to-end tests are skipped; with
`ACF_REQUIRE_E2E=1` (set it in CI) a missing binary is a failure instead. The host refuses trusted
files beneath a world-writable directory, so its state is created in a private directory under
`~/.cache/acf-test` (override with `ACF_E2E_STATE_DIR`; keep it short, because a Unix socket path
is limited to 107 bytes), never under `/tmp`. The TLS unit tests build a throwaway authority with
the `openssl` command-line tool and are skipped where it is not installed.
