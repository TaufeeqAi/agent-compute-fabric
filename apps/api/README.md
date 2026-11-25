# acf-api

The interface plane of Agent Compute Fabric: the service that puts a public API in front of one ACF
host. It authenticates developers and agents, decides what each may do, makes every request safe to
repeat, and translates between the public model and the host's own protocol. It runs nothing itself:
every sandbox, execution and snapshot is the host's, and the host's verdict is final.

One package, two roles, three programs:

| Program | Role | What it is |
|---|---|---|
| `acf-api core --config core.yaml` | core | the one process of a deployment that verifies credentials, decides, keeps the request ledger and speaks to the host. It holds the host private key, the store and the security journal, and listens on no network address |
| `acf-api edge --config rest.yaml` | edge | the REST adapter: terminates TLS, bounds and decodes requests, relays each to the core as one command, encodes the answer. It decides nothing and holds nothing but its TLS key |
| `acf-api init`, `check`, `admin`, `deployment-id`, `artifacts`, `compat` | operator | create a deployment, validate a configuration and lint the host's enrolment table, run an operator command through the running core, generate the contract files, compare them with a released version |

The agent-protocol edge is a package of its own, `apps/mcp-gateway`, built on this one's command
interface. Requires Python 3.12 or later and Linux.

| | |
|---|---|
| Operator's manual | [`docs/platform/OPERATIONS.md`](../../docs/platform/OPERATIONS.md) |
| How it is built, and why | [`docs/platform/ARCHITECTURE.md`](../../docs/platform/ARCHITECTURE.md), [`DECISIONS.md`](../../docs/platform/DECISIONS.md) |
| What was verified | [`docs/platform/VERIFICATION_STATUS.md`](../../docs/platform/VERIFICATION_STATUS.md) |
| The public contract, generated from this package | [`protocols/`](../../protocols/) |

## The shape of a request

```text
caller ──TLS──► edge ──command socket──► core ──mutual TLS──► host
                 │                         │
                 │ bounds, decodes,        │ authenticate → project → class of operation → ledger lookup
                 │ asks the core to        │ → rate and in-flight bounds → readiness → fix the request
                 │ verify the credential   │ → access policy → quota under the project's lock
                 │ BEFORE it reads a body  │ → claim in the ledger → send → bind the answer → render
```

Three rules explain most of the code:

1. **The edge holds nothing.** No module under `acf_api.edge` or `acf_api.command` imports
   `acf_api.core`. A linter rule and a test of the import graph enforce it, and at run time the two roles
   are different accounts joined by one Unix socket that admits the edge accounts only.
2. **One idempotency key is one operation.** The operation id sent to the host is derived from the
   deployment, the project, the principal and the caller's key, so a repeated request finds the
   operation it made. A claim is written to the ledger before anything is sent; whatever a process
   leaves unfinished is resolved by the next one, by reading the host and never by guessing.
3. **The host decides, and unknown is never reported as success.** A refusal is the host's refusal, an
   outcome nobody can learn is `OUTCOME_UNRESOLVED` or `OUTCOME_LOST`, and a grant can only narrow what
   the host's own safety profile allows.

## Layout

| Package | What it holds | Imported by |
|---|---|---|
| `acf_api.command` | the public model, the error table, the table of operations, the commands and answers of the command interface, its framing, a strict JSON reader, the edge's client of the socket | both roles, and every protocol adapter |
| `acf_api.edge` | the edge configuration and the REST adapter: the route table, the application, the HTTP server settings | the edge only |
| `acf_api.core.pipeline` | the admission pipeline: derivation, fingerprint, limits, readiness, the exchange with the host, following, recovery, the mapping to and from the host's model, spans | the core only |
| `acf_api.core.store` | the interface store (SQLite): engine, registry, ledger, audit outbox; and the security journal | the core only |
| `acf_api.core.identity` | API keys, OAuth access tokens, the authenticator | the core only |
| `acf_api.core.policy` | grants, the destination relation, the decision function | the core only |
| `acf_api.core.host` | the host binding: wire format, mutual TLS, connection lanes, the mapping table; the lint of the host's enrolment table | the core only |
| `acf_api.core.agent` | the tool catalogue and the rules of agent calls (minted keys, adoption, delivery, inline output) | the core only |
| `acf_api.core.audit`, `core.admin` | audit records and their sink; the operator's commands and their socket | the core only |
| `acf_api.contract` | the generators of `protocols/`: OpenAPI, tool definitions, problem registry, host mapping, conformance scenarios; and the comparison of two versions of them | the `artifacts` and `compat` commands |

## Configuration

`config/platform-core.example.yaml` and `config/platform-edge.example.yaml` are complete, commented
examples. Both schemas refuse a key they do not define, and read every value exactly: a number written
as text, or a truth value written as a number, is an error and is never interpreted. A path, which a
file can only write as text, is the one conversion. Every bound of the platform is a parameter with a
default that works (`acf_api/core/parameters.py`); the relations among them are checked when the core
starts, and a violated relation stops the start.

Two values describe the host and cannot be read from it, because the host does not advertise them: its
allowance for one peer (`host_ops_allowance`, `host_reads_allowance`) and what it admits at once
(`host_max_sandboxes`, `host_max_snapshots`). Their defaults are the host's own defaults; an operator who
changes one on the host changes it here.

Exit statuses of the programs: `0` done, `1` failed, `2` the command line cannot be used, `78` the
process refuses to start as it is configured (a service manager must not retry that).

## Development

From this directory, with `uv` (the lock fixes every version and every file by its hash):

```console
uv run --locked pytest                  # everything that needs no host
uv run --locked ruff check . && uv run --locked ruff format --check .
uv run --locked mypy
uv run --locked acf-api artifacts --out ../../protocols --check
uv run --locked acf-api compat --baseline <protocols of a release>   # what would break a caller
```

From the repository root, `make platform-check` runs these for every project of the platform, and
`make platform-e2e` builds the host's in-memory test build and runs the tests marked `host` against it,
over the real host protocol and real mutual TLS.

How the tests are organised:

| Tests | Against | What they prove |
|---|---|---|
| `test_unit_*.py` | nothing | one module each: derivation vectors, keys, grants, destinations, the strict JSON reader, framing, the journal, the store, parameters, the mapping, spans, the enrolment lint, the comparison of contract versions |
| `test_contract_*.py` | the generated files | the artifacts are current and complete, the import boundary holds, and every entry of the contract's test catalog is proven by a test or explained |
| `test_idempotency.py`, `test_recovery_faults.py`, `test_pipeline_scope.py`, `test_containment_limits.py`, `test_auth_credentials.py`, `test_agent_interface.py`, `test_standing_audit_projects.py` | a model of the host inside the test, with a fault at every point of an exchange | the pipeline: one key is one operation, every lost answer, recovery, project separation, the order of checks, containment, limits, credentials, the agent interface, readiness, audit |
| `test_edge_*.py`, `test_command_socket.py`, `test_core_startup.py` | the real socket and processes | the REST adapter, the command interface, trusted inputs, one core per store |
| `test_host_binding.py`, `test_e2e_host.py` (marker `host`) | the host's in-memory build, over mutual TLS | the binding and the whole chain as three processes |
| `test_deployment_files.py` | the shipped units, tables and examples | they agree with each other and with the code |

A test that needs the host skips without `ACF_HOST_FAKE`, and fails instead of skipping when
`ACF_REQUIRE_HOST=1` is set, as CI does.

Changing the public interface is one change in `acf_api/command` and a regenerated `protocols/` in the
same commit (`make platform-artifacts`). Both SDKs and the CLI are held to those files by their own
tests, so a member added here and forgotten there fails a build rather than a user.

Within a major version of the interface nothing is removed, retyped or made newly required, and no
request becomes stricter. `make platform-compat` compares the files with those of the newest released
version and fails on a difference that would break a caller. Where the comparison cannot prove a change
compatible it reports the change; a reviewed exception is one exact line in `compat-accepted.txt`.
