# Operations — installing, running and recovering the developer platform

Audience: the person who owns the machine. This is the operator's manual of the developer platform: the
service that puts a REST API and an agent-protocol (MCP) endpoint in front of one ACF host, authenticates
developers and agents, decides what each may do, and makes every request safe to repeat.

Everything here follows the path that `scripts/platform-deploy-test.sh` takes, in the same order. CI runs
that script on a machine it throws away (`.github/workflows/platform.yml`, job `deployed`), so a green run
is a rehearsal of this document: the installer, the three units, the example configurations, the first
project and key, a developer's journey, a restart, and a refused start. What that rehearsal does not
cover is said in [VERIFICATION_STATUS.md](VERIFICATION_STATUS.md).

The host itself is not described here: its manual is [`docs/OPERATIONS.md`](../OPERATIONS.md). The
clients are described in their own READMEs (`sdks/python`, `sdks/typescript`, `apps/cli`).

---

## 1. What runs on the machine

Three processes, three accounts, one socket between them.

| Role | Unit | Runs as | What it is |
|---|---|---|---|
| **core** (`acf-api core`) | `acf-platform-core.service` | `acf-core` | verifies credentials, decides, keeps the request ledger, speaks to the host. The only process that holds the host private key, the fingerprint key, the store and the security journal. Listens on no network address. |
| **REST edge** (`acf-api edge`) | `acf-platform-rest.service` | `acf-rest` | terminates TLS, bounds and decodes REST requests, relays each to the core as one command, encodes the answer. Verifies nothing, decides nothing, holds nothing but its TLS key. |
| **agent-protocol edge** (`acf-mcp`) | `acf-platform-mcp.service` | `acf-mcp` | the same for the Model Context Protocol over Streamable HTTP, without sessions. |

The split is the point. The processes that read bytes from the network cannot open anything worth
taking, and the process that can is reachable only through one Unix socket that admits two accounts.
The core checks this before it serves: if an edge account could read the host key, the fingerprint key,
the store or the journal, by its own id or through any of its groups, the core refuses to start.

Where things live (the defaults of `config/platform-core.example.yaml` and
`config/platform-edge.example.yaml`):

```text
/opt/acf-platform/api/            environment of the core and the REST edge     (root; nobody else writes)
/opt/acf-platform/mcp/            environment of the agent-protocol edge: its protocol library is not
                                  on the core's import path
/etc/acf-platform/                0755 root
    core.yaml                         0640 root:acf-core    which deployment, where its state is, which host
    rest.yaml                         0640 root:acf-rest    where the REST edge listens, its bounds
    mcp.yaml                          0640 root:acf-mcp     the same for the agent-protocol edge
    policies/developer.yaml           0644 root             what a developer's role allows by default
    policies/agent.yaml               0644 root             what an agent credential allows by default
    secrets/                          0700 acf-core
        platform.key                      0600   the platform's private key, as enrolled on the host
        platform.crt                      0644   its certificate
        host-ca.crt                       0644   the authority that signs the host's certificate
        fingerprint.key                   0600   keys the digests in ledger and audit records
    rest/tls.crt, rest/tls.key        0700 acf-rest   the REST endpoint's certificate and key
    mcp/tls.crt, mcp/tls.key          0700 acf-mcp    the agent endpoint's certificate and key
/run/acf-platform/                2750 acf-core:acf-command
    command.sock                      0660   edge → core. The one seam.
    admin.sock                        0600   operator → core (`acf-api admin …`)
/var/lib/acf-platform/store/      0700 acf-core   state.db (registry, ledger), audit.db (outbox), LOCK
/var/lib/acf-platform-journal/    0700 acf-core   security.journal: what a restore must never undo
/var/log/acf-platform/            0750 acf-core   audit.jsonl, when an audit sink is configured
```

The private key, the fingerprint key, the certificate and the host's authority are **trusted inputs**: a
regular file (no symbolic link), owned by `acf-core` or root, not writable by group or others, inside
directories with the same property; the two keys also unreadable by anybody else. The core does not use
an input that fails the rule. It says which one and why, and exits with status 78.

## 2. What the machine and the host must provide

| Need | Why |
|---|---|
| Linux with systemd | the three units, `systemd-sysusers`, `systemd-tmpfiles`. systemd 257 is what the deployment test ran on. |
| A system Python, 3.12 or newer | the environments are built on it. It must be executable by the service accounts, so not one below a home directory. |
| `uv` | installs both environments from their locks, each file checked against its hash |
| One ACF host with its network endpoint open | `edge.tls` in the host's `host.yaml`: mutual TLS 1.3. The platform binds exactly one host. |
| The platform enrolled on that host as **one** peer with role `caller` | never `operator`: no operator method of the host is reachable through the platform, and the role is what makes that true on the host's side |
| The host features `scope_tags` and `operation_list`, protocol `acf.host/2` | the core reads them from `host.info` and refuses new work without them |
| Clocks that agree | the host refuses a request whose `issued_at` is older than its acceptance horizon. Run a time service on both machines. |

The platform and the host may share a machine or not. Nothing in the platform needs KVM.

## 3. Install

```bash
# 0. From a checkout of the tagged release, as your normal user.
make platform-check                      # optional: the gate, on your own machine (section 13)

# 1. The environments, the accounts, the directories, the units, a first configuration.
#    Idempotent. It creates no secret, never overwrites a file of yours, and starts nothing.
sudo env "PATH=$PATH" bash scripts/platform-setup.sh install

# 2. Enrol the platform on the host (section 3.2) and put the three files into /etc/acf-platform/secrets.
# 3. Edit /etc/acf-platform/core.yaml: host.address and host.host_id (section 3.3).
# 4. Give each edge the certificate and key of its endpoint (section 3.4).

# 5. Create the deployment, once, and ask the machine whether everything is in order.
sudo runuser -u acf-core -- /opt/acf-platform/api/bin/acf-api init --config /etc/acf-platform/core.yaml
sudo bash scripts/platform-setup.sh check

# 6. Start.
sudo systemctl enable --now acf-platform-core.service acf-platform-rest.service acf-platform-mcp.service
```

### 3.1 What `platform-setup.sh install` does

* Builds `/opt/acf-platform/api` from `apps/api/uv.lock` and `/opt/acf-platform/mcp` from
  `apps/mcp-gateway/uv.lock`, with `uv sync --locked --no-dev --no-editable`: exactly the locked
  versions, each file checked against its hash, no development tool, no link back into the checkout. It
  then checks that the core's environment does not contain the agent-protocol library.
* Creates the accounts `acf-core`, `acf-rest` and `acf-mcp` and the group `acf-command`
  (`deploy/platform/sysusers.d`), and the directories of section 1 (`deploy/platform/tmpfiles.d`).
* Installs the three units (`deploy/platform/systemd`) and the two grant templates.
* Writes `core.yaml` with a **new deployment id**, and `rest.yaml` and `mcp.yaml` from the edge example
  (the second on port 8444 with its own TLS paths). A file that exists is kept; when it differs from the
  shipped one, the shipped one is written beside it as `*.dist`.

`--prefix DIR` installs the environments elsewhere and writes that path into the units. `--no-mcp` leaves
the agent-protocol edge out. `--python FILE` names the interpreter.

The deployment id is made once and never changed. It is recorded in the store and in the journal, and it
is an input of the derivation that turns a caller's idempotency key into a host operation id. The
example file carries a placeholder that does not load, so that a copied file can never start a second
deployment under the same id. To make an id by hand: `acf-api deployment-id`.

### 3.2 Enrol the platform on the host

On the host, the platform is one peer. Make a key and a certificate for it, signed by an authority the
host lists as a trust anchor (`edge.tls.trust_anchors` in the host's `host.yaml`), and enrol its public
key in the host's `enrolment.yaml` with role `caller`:

```bash
# the value for `spki_sha256`: it survives re-issuing the certificate for the same key
openssl x509 -in platform.crt -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum
```

```yaml
# /etc/acf/enrolment.yaml, on the host
  - peer_id: developer-platform
    role: caller
    match: { spki_sha256: "<the 64 lower-case hex characters printed above>" }
```

Then, on the platform's machine:

```bash
sudo install -o acf-core -g acf-core -m 0600 platform.key /etc/acf-platform/secrets/platform.key
sudo install -o acf-core -g acf-core -m 0644 platform.crt /etc/acf-platform/secrets/platform.crt
sudo install -o acf-core -g acf-core -m 0644 host-ca.crt  /etc/acf-platform/secrets/host-ca.crt
```

`host-ca.crt` is the authority that signed the **host's** certificate. The system trust store is never
consulted, and the host's certificate must carry the configured `host_id` as a subject alternative name.

Whoever holds `platform.key` can act in every project of the deployment. It is the one credential of the
platform that the host knows; a developer's key never leaves the platform.

The role cannot be read back from the host today, so it is checked where it is written: in the host's
enrolment table. Copy the table to the platform's machine and lint it (section 3.5). The lint passes
when the platform's certificate is in the table exactly once, with the role `caller`, and no
certificate of an edge is in it at all. Do this when you deploy and whenever the platform's certificate
or the host's table changes. `acf-api admin health` shows what the host reports about the platform
(`pinned_peer_id`).

### 3.3 `core.yaml`

The file answers four questions: which deployment this is, where its state lives, which host it binds,
and who may connect to it. A key the schema does not define stops the start, and so does a value of
another type than its setting: `"30"` is not a number and `1` is not a truth value. A setting that
changes what the platform admits is read exactly or not at all. The same holds for the edge files.

| Setting | What to decide |
|---|---|
| `deployment_id` | made by the installer; never change it |
| `paths.*` | keep the defaults unless you move state. `paths.journal` must not lie below `paths.store_dir`: `init` refuses it. |
| `paths.journal_mirror` | optional second copy of every journal record, on a volume you collect. Add its directory to the core unit with a `ReadWritePaths=` drop-in. |
| `edge.users`, `edge.socket_group` | the accounts of the edge processes and the group of the command socket. Names are looked up once, at start. |
| `host.address`, `host.host_id` | the host's mutual-TLS endpoint and the identity its certificate must carry |
| `host.trust_anchors`, `host.certificate`, `host.private_key` | the three files of section 3.2 |
| `oauth` | optional: accept access tokens of an external authorization server on the agent endpoint (section 5.4) |
| `audit_sink.file` | optional: deliver audit records to an append-only file (section 9) |
| `parameters` | every bound, each with a default that works (section 7) |

Four values must equal the host's own, because the host does not report them and the platform cannot
read them. If you change one on the host, change it here too.

| In `core.yaml`, under `parameters` | In the host's `host.yaml` | Default of both |
|---|---|---|
| `host_ops_allowance` | `operations.rate_limit_per_minute` | 600 |
| `host_reads_allowance` | `operations.read_rate_limit_per_minute` | 6000 |
| `host_max_sandboxes` | `envelope.max_sandboxes` | 16 |
| `host_max_snapshots` | `envelope.max_snapshots` | 64 |

The last two are what the project quotas are shares of. Set too high, they let one project take every
sandbox the host has; set too low, they refuse work the host would have run. The one check the platform
can make is that `host_max_sandboxes` does not exceed the host's pool of identifiers, which the host
does advertise: beyond it the number cannot be the host's, and new work is refused with
`host_parameter_relation` until it is corrected. `parameters.host_max_connections` (8) must not exceed
the host's `edge.max_connections_per_source`.

### 3.4 The edge files and their TLS keys

`rest.yaml` and `mcp.yaml` have one format (`config/platform-edge.example.yaml`): where the process
listens, where the command socket is, and the transport bounds it applies before it parses anything.
Nothing in them can name a principal, a project or a grant.

```bash
sudo install -o acf-rest -g acf-rest -m 0644 rest.crt /etc/acf-platform/rest/tls.crt
sudo install -o acf-rest -g acf-rest -m 0600 rest.key /etc/acf-platform/rest/tls.key
sudo install -o acf-mcp  -g acf-mcp  -m 0644 mcp.crt  /etc/acf-platform/mcp/tls.crt
sudo install -o acf-mcp  -g acf-mcp  -m 0600 mcp.key  /etc/acf-platform/mcp/tls.key
```

* Without a `tls` section an edge listens on a loopback address only, for a TLS-terminating proxy on the
  same machine. It refuses to start on any other address without TLS.
* Each unit allows its process one listening port and no other (`SocketBindAllow=tcp:8443`, `tcp:8444`).
  **If you change `listen.port`, change that line of the unit too**, in a drop-in.
* `limits.public_wait_max` and `limits.max_public_request_bytes` must equal the core's parameters of the
  same names.
* `mcp.allowed_origins` lists the origins a browser may call from. A request with an `Origin` that is
  not listed is answered 403. An agent host that is not a browser sends none.
* You may run several edge processes. Every limit that concerns a principal or a project is kept in the
  core, so it holds for the deployment whatever their number.

### 3.5 Create the deployment and check it

`acf-api init` creates the store, the security journal and the fingerprint key, and refuses when any of
them exists. `acf-api check` (or `platform-setup.sh check`, which runs it as `acf-core`) validates the
configuration, applies the trusted-input rule to every secret, and reports the separation:

```json
{ "deployment_id": "dep_…", "separation": "holds" }
```

Anything else than `holds` is a list of what an edge account could read. Fix it; the core would refuse
to start for the same reason. `security.allow_shared_identity` is for a development machine with one
account: it admits an edge that runs as the core itself, and nothing else. An edge account of its own
that could read a secret, and an edge that runs as root, stop the start whatever it says.

With a copy of the host's enrolment table, the same command confirms the platform's role on the host
(section 3.2):

```bash
sudo bash scripts/platform-setup.sh check --host-enrolment ./enrolment.yaml
```

```json
{ "deployment_id": "dep_…", "separation": "holds", "host_enrolment": "one entry, role caller" }
```

Anything else under `host_enrolment` is a list of what is wrong, and the command exits with status 1:
no entry matches the platform's certificate, more than one does, the role is not `caller`, or the table
knows the certificate of an edge. The lint reads a copy and changes nothing: an entry it calls wrong is
in force on the host until the host's operator changes it. Run directly, the command is
`acf-api check --config core.yaml --host-enrolment FILE [--other-certificate FILE ...]`.

Back up `fingerprint.key` now, apart from the store (section 8).

## 4. Starting and stopping

```bash
sudo systemctl start acf-platform-core.service acf-platform-rest.service acf-platform-mcp.service
sudo runuser -u acf-core -- /opt/acf-platform/api/bin/acf-api admin --config /etc/acf-platform/core.yaml health
```

**Start order.** The core verifies the journal's chain, opens the store under its exclusive lock, checks
that the store is the configured deployment, takes a new writer epoch, replays the journal into the
registry, and opens its two sockets. Then it tells systemd that it serves (`Type=notify`); the edges are
ordered after it. Its first recovery pass runs from that moment: until the pass has visited every
request an earlier process left unfinished, new work is answered `503 UPSTREAM_UNAVAILABLE` with the
reason `recovery_pass_pending` (the SDKs retry it), while reads and containment (stop, destroy, cancel,
delete) are answered normally.

**The edges do not depend on the core being up.** While the core restarts, an edge answers
`503 UPSTREAM_UNAVAILABLE` with `Retry-After`, and the SDKs retry. Stopping the core does not stop them.

**A stop** (`SIGTERM`): the core refuses new work, lets requests in flight finish or reach the host for
up to `parameters.drain_timeout` (30 s), and exits. A request that was still unresolved is resolved by
the next start from the ledger, by reading the host. Correctness never depends on the drain, and a
`kill -9` loses nothing that was promised.

**A start that is refused** exits with status 78, and systemd does not retry it
(`RestartPreventExitStatus=78`), because nothing changes until you change it:

```bash
journalctl -u acf-platform-core -n 20        # "the core refuses to start: …" names the precondition
```

**Exactly one core.** A second core on the same store finds the lock held and refuses to start. Never
run two cores against copies of one store: both would derive the same operation ids.

## 5. Projects, developers, keys and agents

Everything in this section is an operator command, carried out by the running core through the admin
socket. No public interface can do any of it.

```bash
admin() { sudo runuser -u acf-core -- /opt/acf-platform/api/bin/acf-api admin --config /etc/acf-platform/core.yaml "$@"; }
```

### 5.1 The first project, developer and key

```bash
admin project.create --label "team-a"                       # → project_id, activation: active
admin principal.create --label "alice"                      # → principal_id
admin role.set --principal-id prn_… --project-id prj_…      # the `developer` template, or --grants @file.yaml
admin key.issue --principal-id prn_… --project-id prj_…     # → secret: shown ONCE, stored nowhere
```

* A **project** is the unit of isolation. It is given a scope: 128 random bits that the host stamps on
  every record the project creates and that no request can name. A project is activated only when the
  host holds nothing under its scope; `activation: pending` means the host could not be asked (run
  `admin project.activate --project-id …` again), `refused` means the scope is not empty.
* A **principal** is a person or a service. Its **role** in a project is a grant document: the methods
  it may call, the images, the network modes and destinations, and ceilings for resources, execution
  time and sandbox lifetime. A grant only narrows. Whatever it allows, the host's safety profile still
  decides.
* A **developer key** (`acf1_dev_…`) is bound to one principal and one project. `--lifetime-days`
  defaults to 90 and is capped by `parameters.credential_max_lifetime`. `--grants @file.yaml` narrows
  the key below its role; a narrowing that allows something the role does not is refused.
* The platform keeps a digest of the key and a display prefix. It cannot show a key again.
* **Hand over three things**: the key, the address of the REST edge, and, if the edges' certificates are
  signed by an authority of your own, that authority's certificate. The SDKs and the command-line client
  read no proxy and no general certificate variable from a developer's environment; a developer names
  your authority once (`acf auth login --ca-file`, `ca_file=` or `ACF_CA_FILE` for the Python SDK,
  `NODE_EXTRA_CA_CERTS` for Node.js) and the client then believes it and no other.

The default templates are `policies/defaults/developer.yaml` and `agent.yaml`. Read them before the first
developer arrives: the developer template allows every image and **no network destination**, because
egress is the channel for effects that cannot be undone. List the destinations a project may reach in
its role.

### 5.2 Agents

A developer mints agent credentials for themself, through the API, the SDKs or `acf auth agent-key
create`; an operator is not involved. An agent key (`acf1_agt_…`) always narrows its parent, expires
after at most `parameters.agent_credential_max_lifetime` (one day), has `network: none` unless the
developer granted destinations explicitly, and is revoked together with its parent.

The agent endpoint accepts agent credentials only. A developer key is refused there
(`parameters.mcp_allow_developer_credentials`, off): an agent host is never handed a developer's
authority. Leave it off.

### 5.3 Revoking

```bash
admin key.list [--project-id prj_…]
admin key.revoke --credential-id crd_…          # also revokes every agent credential minted with it
```

A revocation is written to the security journal before it takes effect, so that no restore of the store
can undo it. It is in force for new work at once and for containment within
`parameters.credential_revocation_bound` (60 s). Revoking a credential does not stop what it started:
stop or destroy the sandboxes, or cancel the executions, as a second step. For an agent credential the
SDKs and the CLI do both (`revoke --contain`).

### 5.4 OAuth access tokens (optional)

With an `oauth` section in `core.yaml`, the agent endpoint also accepts access tokens of one external
authorization server. A token authenticates only if it was issued by the configured issuer, for this
deployment's canonical resource URI, is unexpired, and its subject is **bound** to a principal by you:

```bash
admin oauth.bind --issuer https://login.example.org --subject "user-123" \
      --principal-id prn_… --project-id prj_… --kind agent --agent-label "ide"
admin oauth.list
admin oauth.unbind --binding-id bnd_…
```

The core fetches the issuer's keys from `jwks_uri` (or reads `jwks_file`), at most every
`parameters.jwks_refresh_interval`. The agent-protocol edge publishes the protected-resource metadata
that agent hosts read; set `mcp.resource`, `mcp.authorization_servers` and `mcp.scopes_supported` in
`mcp.yaml` to the same values. The edge verifies no token. The core does.

### 5.5 Deleting a project

```bash
admin project.delete --project-id prj_…
```

The project stops accepting new work at once; containment stays allowed, so its owners can still stop and
destroy. The deletion completes when the host holds no sandbox and no snapshot under the project's
scope; until then the command answers `waiting`. Run it again. A deleted project stays deleted across
any restore, and its scope is never issued again.

## 6. The admin commands

`acf-api admin --config <core.yaml> <operation> [--name value …]`. A value that starts with `@` is read
from a YAML or JSON file. The admin socket admits the core's own account and root.

| Operation | Arguments | What it does |
|---|---|---|
| `health` | | everything section 7 describes |
| `metrics` | | counters and timings of this process, connection use, ledger and registry counts |
| `project.create` | `--label` | a new project and scope; activates it on an empty scope |
| `project.activate` | `--project-id` | retry the activation of a `PENDING` project |
| `project.list` | | every project, with what the host holds under its scope and whether a valid developer key exists |
| `project.share` | `--project-id`, `--share` | the project's share of the host allowance and envelope (above 0, below 1; `null` for the default) |
| `project.delete` | `--project-id` | section 5.5 |
| `principal.create` | `--label` | a new principal |
| `principal.list` | | |
| `role.set` | `--principal-id`, `--project-id`, `--template` or `--grants @file` | the principal's grant in the project |
| `key.issue` | `--principal-id`, `--project-id`, `--lifetime-days`, `--grants @file` | a developer key, shown once |
| `key.list` | `--project-id` | credentials: id, kind, display prefix, expiry, revocation |
| `key.revoke` | `--credential-id` | section 5.3 |
| `oauth.bind`, `oauth.list`, `oauth.unbind` | section 5.4 | subject bindings |
| `host.acknowledge-lineage` | `--lineage` | section 10.1 |
| `host.acknowledge-peer` | `--peer-id` | section 10.2 |
| `audit.read` | `--after-seq`, `--limit` | audit records from the outbox |
| `recovery.sweep` | | run one recovery pass now; prints what it resolved |
| `policy.templates` | | the two grant templates as the core loaded them |

## 7. Health, readiness and limits

`admin health` is the one place to look. Two members summarise it:

* `serving`: the platform itself works (its store is usable). Depends on nothing of the host.
* `ready`: new work is accepted. `not_ready_reasons` lists why not; a caller is told the first of them
  as the `reason` of a `503 UPSTREAM_UNAVAILABLE`. Reads and containment are answered whatever this says.

| Reason | Meaning | What to do |
|---|---|---|
| `recovery_pass_pending` | the first pass after a start is still running | wait; it is bounded by the number of unfinished requests |
| `host_not_yet_reached` | no `host.info` yet | check `host.address`, the network, the host |
| `host_identity_unverified` | the endpoint did not prove it is `host.host_id` under the configured authority | `identity_error` says what failed. Never weaken the check. |
| `host_protocol_unsupported`, `host_feature_missing:<name>` | the host does not speak `acf.host/2` or lacks a required feature | upgrade the host |
| `host_refuses_the_platform` | the host refused the platform's own credential | the enrolment was removed or the certificate expired (section 3.2) |
| `host_lineage_changed` | the host's store is not the one first seen | section 10.1 |
| `platform_peer_id_changed` | the host reports another peer id for the platform | section 10.2 |
| `host_parameter_relation` | a parameter violates a relation to a value the host advertises | `host_parameter_violations` names it; fix `core.yaml` |
| `store_unusable` | the store did not answer or is out of space | section 8.3 |

`clock_offset_suspected: true` means the host refused a fresh request as expired. The platform keeps
probing with one request at a time; fix the clocks.

Other members: `ledger` (`claimed`, `bound`, `lost`, `claimed_stale`), `audit` (`records`,
`undelivered`), `store` (sizes, free space, the reserve), `registry` (projects, principals, live
credentials, credentials expiring within 7 days), `journal_records`, `journal_mirror_failures`,
`writer_epoch`, `edge_shares_core_identity` (must be `false`).

**Limits.** Every bound is a parameter with a default (`apps/api/src/acf_api/core/parameters.py` is the
register; the relations among them are checked at start, and a violated relation stops the start).
The ones an operator meets:

| Parameter | Default | Relation |
|---|---|---|
| `public_wait_max` | 30 s | the longest a request waits for its operation. Edges must carry the same value. |
| `host_ops_allowance`, `host_reads_allowance` | 600, 6000 per minute | must equal the host's allowance for one peer (section 3.3) |
| `host_allowance_reserve` | 0.2 | the share kept for containment, for resolving lost answers and for following operations |
| `host_max_sandboxes`, `host_max_snapshots` | 16, 64 | must equal what the host admits at once (section 3.3). The first must not exceed the host's identifier pool. |
| `project_default_share` | 0.5 | a project's share of the allowance that is left, and of the two numbers above. `project.share` sets it per project. |
| `principal_max_in_flight`, `project_max_in_flight` | 16, 32 | the first must not exceed the second |
| `project_max_live_sandboxes`, `project_max_snapshots` | unset | unset: the share of what the host admits, at least 1 (8 and 32 by default). Neither may exceed what the host admits. |
| `host_max_connections` | 8 | of which 2 are kept for containment and 1 for resolution; at least 2 must remain |
| `claim_stale_after` | 120 s | greater than `public_wait_max` plus `server_deadline_margin`; together with `recovery_sweep_interval` shorter than the host's acceptance horizon |
| `idempotency_retention` | unset | unset: the host's operation retention plus `idempotency_safety_margin` (1 h) |
| `credential_revocation_bound` | 60 s | `containment_auth_cache_ttl` must not exceed it |
| `agent_credential_max_lifetime` | 1 day | must not exceed `credential_max_lifetime` |
| `audit_budget_bytes` | 1 GiB | the outbox's own size budget; it can never use the space of the registry and the ledger |
| `audit_required` | off | on: new work is refused while the outbox is full. Containment never is. |
| `drain_timeout` | 30 s | keep the core unit's `TimeoutStopSec` above it |

Rate and in-flight limits are answered `429` with `Retry-After`; a project quota `PERMISSION_DENIED` with the
reason `quota`; a host that is full `RESOURCE_EXHAUSTED`, in the host's own words. Containment
is exempt from all of them: a caller who is over every limit can still stop, cancel, destroy and delete.

## 8. The store, the journal and backup

### 8.1 What is where

| | Holds | If it is lost |
|---|---|---|
| `store/state.db` | projects, principals, roles, credential digests, subject bindings; the request ledger (which idempotency key became which host operation) | restore it from a backup, then start: the journal is replayed |
| `store/audit.db` | audit records not yet delivered or not yet expired | records since the last delivery are lost; nothing else |
| `security.journal` | scope allocations, project deletions, revocations, the deployment id, the pinned host lineage and peer id | **must not be lost**: without it a restored store could revive a revoked key or issue a scope twice. The core does not start without it. |
| `fingerprint.key` | the key of the digests in ledger and audit records | records can no longer be matched to requests; duplicate requests of before the loss are not recognised |

The store holds no sandbox, execution or snapshot state, no output, no guest data, no secret material and
no plaintext credential. The host is the truth for everything that runs.

### 8.2 Backup and restore

* Back up `/var/lib/acf-platform/store` with SQLite's own backup (`sqlite3 state.db ".backup …"`), or a
  file-system snapshot. Copying the files of a running store by hand is not a backup.
* **Do not back up and restore the journal together with the store.** Keep it on a volume that a restore
  of the store never overwrites, and copy it elsewhere continuously (`paths.journal_mirror`, or your log
  shipper: it is an append-only file of JSON lines).
* Back up `fingerprint.key` once, apart from both.

After a restore of the store, just start the core. On **every** start it replays the journal into the
registry: every revocation is applied again, every scope stays used, every deleted project stays
deleted. A request whose ledger entry is missing from the restored store is treated as new; a request
that was in flight is resolved by reading the host.

The journal is a hash chain: each line carries the digest of the line before it. A line that was
changed, removed or reordered breaks the chain, and the core refuses to start on a broken chain. Do not
edit the file. The chain detects damage and careless edits; what keeps an attacker out is the file's
owner and mode.

A chain cannot show that lines are missing at its end: what is left of a journal that was cut at a line
boundary is a valid journal. The store can, because it remembers the last journal record it applied.
A journal that ends before that record is **older than the store**, and the core refuses to start:

```
the core refuses to start: the store has applied record 41 of the security journal, and the journal
ends at record 38: the journal is older than the store. …
```

This is what restoring the journal from an old copy looks like, and it is the one restore that loses
revocations. Put back the journal's newest copy (`paths.journal_mirror`, or what your log shipper
collected) and start again. The other direction, a store older than its journal, is the ordinary restore
described above and needs nothing but a start.

### 8.3 Space

The core keeps `parameters.store_reserve_bytes` (64 MiB) free for the registry and the ledger: with less,
`store_unusable` is reported and new work is refused, while containment is still served. The audit
outbox has a budget of its own. Give `/var/lib/acf-platform` room and watch `store.free_bytes`.

## 9. Audit, logs and metrics

**Audit.** One record for every mutation the core admitted (accepted, refused or unresolved), every
authorization denial, every issuance, minting and revocation of a credential, every read of execution
output, and every operator command that changes something. A record holds identifiers, enumerations and
keyed digests: never a credential, an argument or environment value, or output. With
`audit_sink.file` set, records are appended to that file as JSON lines and then marked delivered;
`audit.undelivered` in health counts what waits. Records leave the outbox after
`parameters.audit_retention` (90 days). The audit record is evidence, not truth: no decision reads it.

**Logs.** Each process writes JSON lines to the journal of its unit (`journalctl -u acf-platform-core`).
A line holds an event name and bounded identifiers. Request ids appear in logs, in every answer
(`X-Request-Id` and the problem document), and in audit records: that is how one request is followed.
No log line holds a credential, a header, a body or output.

**Metrics.** `admin metrics` prints the counters and timings of the running core. The names are stable
within a release; treat them as diagnostics, not as an interface.

**Traces.** If the OpenTelemetry API is installed in an environment (the optional dependency `otel` of
the API package), spans are emitted through it; the platform configures no exporter and sends nothing by
itself.

Losing telemetry or audit changes no outcome, with the one exception you can choose (`audit_required`).

## 10. When the host changes

### 10.1 The host's store was replaced or restored

The platform pins the lineage of the host's store the first time it sees it, in the journal. If the host
later reports another lineage, the operations the ledger points to may not exist any more. The platform
stops accepting new work (`host_lineage_changed`) and waits for you:

```bash
admin health                                              # read `reported_lineage`
admin host.acknowledge-lineage --lineage <that value, exactly>
```

After the acknowledgement, every ledger entry of the old lineage becomes `LOST`: a caller who asks again
with an old key is told `OUTCOME_LOST`, once and for good, instead of having the request run a second
time. Nothing is resubmitted. Tell your developers; they decide what to redo.

### 10.2 The platform's enrolment changed

If a view from the host carries another `peer_id` for the platform than the one first recorded
(`platform_peer_id_changed`), the records the platform created may no longer be its own on the host.
Find out why before you continue. `admin host.acknowledge-peer --peer-id <reported value>` accepts the
new id; entries under the old one become `LOST`.

### 10.3 Rotating the platform's certificate

Issue a new certificate for the **same key**, install it as `platform.crt`, restart the core. An
enrolment by `spki_sha256` keeps matching. A new key is a new enrolment entry on the host; keep the same
`peer_id` there, or you are in section 10.2.

## 11. Upgrading

```bash
git fetch --tags && git checkout <the new tag>
sudo systemctl stop acf-platform-core.service acf-platform-rest.service acf-platform-mcp.service
sudo env "PATH=$PATH" bash scripts/platform-setup.sh install     # rebuilds both environments from the new locks
sudo bash scripts/platform-setup.sh check
sudo systemctl start acf-platform-core.service acf-platform-rest.service acf-platform-mcp.service
```

* Back up the store first (section 8.2). A core never writes a store whose schema is newer than its
  own, so going back to an older release after the schema changed needs that backup.
* Read the release notes for `*.dist` files: the installer wrote them where a shipped configuration or
  template differs from yours.
* The installer rebuilds both environments completely (`uv sync --locked --reinstall`): this checkout's
  own packages are built again from their sources and every package is installed again, so an upgraded
  environment holds no file, and is handed no cached build, of the release it replaces. Do not shorten
  this to a plain `uv sync`: a package's version lives in its sources, and a cache that watches only
  `pyproject.toml` can hand back an older build under the same name.
* Requests in flight during the upgrade are resolved after the restart. Callers that follow the client
  protocol (the SDKs, the CLI) retry with the same key and get the one outcome.

## 12. When something is wrong

| Symptom | Likely cause | Action |
|---|---|---|
| the core unit is `failed`, status 78 | a precondition: configuration, a secret's mode, the separation, the journal's chain, a journal older than the store, another deployment's store | `journalctl -u acf-platform-core -n 20` names it |
| the core unit restarts in a loop | a failure that is not a precondition, for example a full disk | the journal of the unit; `systemctl status` shows `NRestarts` |
| every request is `503 UPSTREAM_UNAVAILABLE` | the core is down, or the edge cannot reach the command socket | `systemctl status acf-platform-core`; `ls -l /run/acf-platform/` (the socket must be `acf-core:acf-command`, 0660) |
| an edge logs `command_socket_rejected` in the core's journal | the edge runs under an account that `edge.users` does not name | fix the unit's `User=` or `core.yaml`; restart the core |
| new work is `UPSTREAM_UNAVAILABLE` with a reason, reads work | the platform is not ready: the reason is the first of `not_ready_reasons` | section 7 |
| new work is `CLOCK_SKEW` | the host refused a fresh request as expired | make the two clocks agree; the platform probes by itself |
| `UNAUTHENTICATED` for a key that was just issued | wrong project in the path, an expired or revoked key, or a key pasted with whitespace | `admin key.list`; the path must name the key's own project |
| `PERMISSION_DENIED` with a reason | the grant does not allow the method, the image, the network intent or a ceiling | read the role (`role.set` prints it); the reason code names the rule |
| `429 RATE_LIMITED` for one developer | the principal's or the project's share is used up | `project.share`, or raise the host's allowance and the two parameters together |
| `PERMISSION_DENIED` with the reason `quota` while the host has room | the project has its share of what the host admits | `project_max_live_sandboxes`, `project_max_snapshots`; if the host admits more than 16 and 64, say so in `host_max_sandboxes` and `host_max_snapshots` |
| new work is refused with `host_parameter_relation` | a parameter cannot be true of this host | `admin health` names it under `host_parameter_violations`; correct `core.yaml` and restart the core |
| `OUTCOME_UNRESOLVED` | the platform could not learn the outcome within its attempts | the caller asks again with the same key; nothing was lost. Persistent: check the host and `ledger.claimed_stale`. |
| `OUTCOME_LOST` | the host no longer knows the operation (section 10.1, or retention passed) | final. The caller decides whether to redo the work under a new key. |
| the agent endpoint answers 403 | an `Origin` that `mcp.allowed_origins` does not list | add the origin, or call without one |
| the agent endpoint refuses a developer key | by design (section 5.2) | mint an agent key |

## 13. Checking a change to this repository

```bash
make platform-check          # contract files and their compatibility, lint, tests, the TypeScript SDK, the units
make platform-e2e            # the platform against the in-memory host, over the real protocol and mutual TLS
make platform-dist           # build every package; install the files into an empty environment
make platform-audit          # advisories against everything the five locks name (needs the network)
make platform-ci             # the first three together: what CI runs on every push
```

`make platform-deploy-test` runs this document for real: it installs the platform on the machine it runs
on, starts the units and inspects the processes. It changes the machine, so it is in no other target and
refuses to run without `ACF_DEPLOY_TEST=1`. Use a machine you throw away.

`scripts/platform-journey/` holds a developer's first minutes as three programs, one for each client
(the Python SDK, the TypeScript SDK, `acf`). Give them the address of a running platform and a developer
key of an empty project, and each says whether every step worked. Run them after an installation or an
upgrade; its README says what a pass proves, which depends on the host behind the platform.

`protocols/` is generated from the code (`make platform-artifacts`) and checked in. Never edit a file
there; `make platform-drift` fails on any difference.

`make platform-compat` compares those files with the ones of the newest released version of the API
(the newest `acf-api-v*` tag that the checkout descends from) and fails on any difference that would
break a caller of that release: something removed, retyped or newly required, or a request that became
stricter. Before the first release there is nothing to compare with, and the target says so.
`make platform-compat COMPAT_BASELINE=<git ref>` compares with another version. `docs/platform/RELEASING.md`
says what to do with a finding.

## 14. Uninstall

```bash
# Destroy the sandboxes and delete the snapshots you want gone first, through the API: the host keeps
# them whether or not the platform exists.
sudo systemctl disable --now acf-platform-mcp.service acf-platform-rest.service acf-platform-core.service
sudo rm -f /etc/systemd/system/acf-platform-*.service /etc/sysusers.d/acf-platform.conf /etc/tmpfiles.d/acf-platform.conf
sudo systemctl daemon-reload
sudo rm -rf /opt/acf-platform /run/acf-platform
# The deployment itself. After this, no idempotency key of the past can be answered and no audit record read:
sudo rm -rf /etc/acf-platform /var/lib/acf-platform /var/lib/acf-platform-journal /var/log/acf-platform
sudo userdel acf-core; sudo userdel acf-rest; sudo userdel acf-mcp; sudo groupdel acf-command
```

Then remove the platform's entry from the host's `enrolment.yaml`. Until you do, the key you just deleted
is still a valid credential there if a copy exists.
