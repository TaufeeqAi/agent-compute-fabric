# Architecture — the ACF host agent (execution plane)

The host agent runs untrusted, agent-generated code in Firecracker microVMs on one Linux host. It is driven by a
control plane (or an operator) over a small versioned API, it survives its own crashes without losing or inventing
state, and it removes privilege reliably even when it can no longer create any.

The normative source is the **execution-plane contract, version 1.2.0** ("the contract"). Identifiers such as
`OP-2`, `RC-4`, `AL-3`, `J-5` or `§16.2` are that document's clause and section numbers; the code cites the same
identifiers in its module comments. This document says how the code realises the contract.
[CONTRACT_COMPLIANCE.md](CONTRACT_COMPLIANCE.md) says where each clause is implemented and tested and where the
implementation had to choose a reading. [VERIFICATION_STATUS.md](VERIFICATION_STATUS.md) says what was run and what
was not. [DECISIONS.md](DECISIONS.md) records the choices the contract leaves open.

Reading order: §1–§3 for the map, §4–§8 for correctness, §9–§13 for the mechanisms, §17 for what is not done.

---

## 1. The system in one page

| Question | Answer |
|---|---|
| What is it? | `acf-host`, one Rust binary that runs in four roles on one host, plus `acf-guest-agent` inside each microVM and `acf-local`, a Python reference client. |
| What does it do? | Creates, starts, executes in, snapshots, restores, stops and destroys sandboxes; records every such request as a durable *operation*; reports what happened with evidence. |
| Who may call it? | Peers listed in the enrolment table, as `observer`, `caller` or `operator`, over a local Unix socket (kernel peer credentials) or mutual TLS 1.3 (client certificate). |
| What limits a request? | The host safety profile: ceilings and capabilities. A request above a ceiling is refused, never reduced. |
| What is authoritative? | The store: one append-only journal file. Memory is a cache of it; telemetry is diagnostic. |
| What happens after a crash? | A new activation observes the host, and a pure decision table says what to do with every unfinished operation and every generation. A granting operation is never continued. Doubt is quarantined, never deleted. |
| What must never happen? | Privilege created without a durable record; a sandbox outliving its expiry; a runtime adopted or deleted without ownership proof; a refusal that leaves a trace; a success reported that a power cut would lose. |

**Mental model.** A clerk in front of a vault. The clerk writes the intent in a ledger before touching anything, the
vault has no door to the street, and after a power cut the clerk reads the ledger, looks at the vault, and only ever
tidies what the ledger proves is theirs. A second, very small clerk does nothing but close each vault at the time
written on its door, whether or not the first clerk is at work.

---

## 2. Processes and privilege domains

One binary, four roles (contract §6.1, INV-024). The roles are separate processes because they face different
parties.

```text
                        peers (control plane, operator, monitoring)
                              │ mutual TLS 1.3            │ Unix socket (kernel peer credentials)
                              ▼                           ▼
   ┌───────────────────────── edge  (PD-1) ─────────────────────────┐   unprivileged user, no capabilities,
   │ accept · limit · authenticate · enrol · bounded decode · schema │   no_new_privs; opens nothing by name
   └──────────────────────────────┬──────────────────────────────────┘
                                  │ socket pair: validated request + (peer_id, role) → answer
                                  ▼
   ┌───────────────────────── core  (PD-2) ─────────────────────────┐   root; the only writer of the store,
   │ admission pipeline → coordinator (BEGIN/STEP/BACKEND/FINISH)    │   the only caller of the backend
   │ store (journal) · recovery · sweep · storage · telemetry        │
   │ backend port → Firecracker backend → jailer → firecracker       │
   └───────┬───────────────────────────┬─────────────────────────────┘
           │ sockets opened inside the │ expiry ticket per runtime
           │ sandbox's namespace       ▼
           ▼                  ┌── lifetime enforcer (PD-4) ──┐   root; reads no peer or guest bytes; needs no
   ┌ guest-traffic (PD-3) ┐   │ ends each runtime at expiry   │   store, no backend and no core
   │ resolver + relay for │   └───────────────────────────────┘
   │ ONE sandbox          │
   └──────────┬───────────┘   unprivileged user of its own, in the host's network namespace
              │ tap device inside the sandbox's own network namespace
              ▼
   microVM: own uid, chroot, PID namespace, network namespace, seccomp, no_new_privs, no capabilities, cgroup v2
      └ acf-init (PID 1) → acf-guest-agent (vsock port 5252, accepts the host only)
            └ each command: unprivileged guest uid, empty environment + request environment, no stdin
```

| Domain | Process | Runs as | Reads bytes from | May mutate the host |
|---|---|---|---|---|
| PD-1 edge | `acf-host edge`, started by the core | `edge.uid`/`edge.gid`, no capabilities, `no_new_privs` | peers | no |
| PD-2 core | `acf-host serve` | root | the edge (validated commands), the guest agent (bounded frames) | yes |
| PD-3 guest-traffic | `acf-host guest-traffic`, one per `allowlist` sandbox | `network.traffic_uid_start + slot`, no capabilities, `no_new_privs`, own control group | one guest's network traffic | no |
| PD-4 lifetime enforcer | `acf-host lifetime` | root | expiry tickets written by the core | ends runtimes only |

How the separation is made real (`privsep.rs`):

* The core starts a role by re-executing its own image (`/proc/self/exe`), with an empty environment and the
  role's identity, and passes configuration and already-open sockets over a socket pair (`SCM_RIGHTS`). A role opens
  nothing by name.
* `no_new_privs` is a per-thread attribute. A role sets it in `main` before the async runtime creates any thread
  (`privsep::enter_role`), so every later thread inherits it, and then verifies its own state from
  `/proc/thread-self/status` before reading a byte. A role started with privilege refuses to run.
* The edge is stateless. If it dies the core starts another with the same listeners; callers see lost responses
  and resolve their operations by id (FS-5). For the same reason the edge never answers `REFUSED` to a request that
  creates an operation when the core did not answer in time: the core may have accepted it, so the edge says
  nothing, closes the connection and counts the lost response. The core validates every request again and checks that the
  `(peer_id, role)` the edge states is enrolled now (PD-2), so a compromised edge has the authority of an enrolled
  peer, bounded by the safety profile, and nothing more.

`tests/process_roles.rs` starts the binary and checks this from `/proc`: the edge is a child of the core running the
same image, every edge thread has `NoNewPrivs: 1` and empty capability sets, no edge descriptor points into the state
directory, connections are accepted by the edge only, and a killed edge is replaced without losing committed state.

---

## 3. Repository and module map

| Path | Contents |
|---|---|
| `execution/wire/` | `acf-wire`: length-delimited framing with a mandatory maximum, and the host ↔ guest protocol types. Shared by host and guest. |
| `execution/traffic/` | `acf-traffic`: the guest-traffic domain. Allowlist model and pure verdicts, a strict DNS codec, a TLS ClientHello parser, the resolver and the relay. No host-mutation code. |
| `execution/host-agent/` | `acf-host`: library and binary (all four roles and the operator tools). `acf-host-fake` (feature `testing`) is the same edge, core and store over an in-memory backend. |
| `execution/guest-agent/` | `acf-guest-agent`: the in-VM executor. Runs inside the untrusted guest. |
| `execution/contracts/` | `host-api.json`, `event-schema.json`: generated from the Rust types, checked in, drift fails the build. |
| `schemas/` | Generated JSON Schemas of the files a host reads or writes: configuration, safety profile, enrolment, image and snapshot manifests. |
| `apps/cli/` | `acf-local`: the Python reference client. It asks; it never decides. |
| `config/`, `profiles/` | Shipped examples: `host.example.yaml`, `enrolment.example.yaml`, `profiles/default.yaml`. |
| `deploy/`, `scripts/`, `tools/`, `images/` | systemd units, install and build scripts with pins, repository tooling, guest image recipes. |
| `tests/` | Repository-level Python suites: tooling, scripts, and the KVM integration and isolation suites. |

Modules of `acf-host`, by the contract's boundary map (§7.1):

| Boundary | Module | Responsibility |
|---|---|---|
| B01 API / admission, B04 identity | `edge/`, `api/` | Endpoints, pre-authentication limits, credentials → `(peer_id, role)`, strict decode. `api/` is the wire model: envelope, typed commands, responses, generated schemas. |
| B02 domain | `domain/`, `ids.rs` | Closed vocabularies and pure rules: methods and classes, roles, tags, lifecycle relation, operation states, host modes, failure classes, fingerprint, network intent, evidence. Imports no edge, store-engine or backend type. |
| B03 authorization | `authority/` | Enrolment table, safety profile, the trusted-input rule. |
| B05 operations, B06 orchestration | `coordinator/` | The one writer: admission pipeline, BEGIN/STEP/FINISH, every flow, operator methods, reads, the sweep, applying recovery. |
| B07 observation / recovery | `recovery/` | The decision table as pure functions. Decides, never writes. |
| B08 hypervisor, B09 isolation | `backend/` | The backend port (`backend/mod.rs`) and its Firecracker implementation (`backend/firecracker/`), with process identity, limits and namespaces. One replacement unit. |
| B10 guest execution | `guest/` | Host-side guest client: bounded frames, re-enforced output caps, the host's own deadline. |
| B11 resources | `resources/` | Admission arithmetic (pure), sandbox lifetime and the lifetime enforcer. |
| B12 network | `network/` | Admission-time intent validation, the guest segment, launching the guest-traffic role, network evidence. |
| B13 storage / images / snapshots | `storage/` | Layout, generation directories with ownership markers, image store, hash-while-copy, snapshot store and manifest, output artifacts. |
| B14 persistence | `store/`, `durability.rs` | The journal, records, schema migration, the instance lock. |
| B15 configuration / secrets | `config.rs`, `secrets/` | The parameter register and its mandatory checks; the secret provider port and the file provider. |
| B16 observability | `telemetry/` | Events and counters. Owns emission and no decision. |
| — | `app.rs`, `main.rs`, `privsep.rs`, `doctor.rs`, `clock.rs` | Startup sequence shared by production and tests; role entry; preflight; time sources. |
| — | `testing/` (`cfg(test)` or feature `testing`) | In-memory backend, fake Firecracker API, fault points, test PKI, the rig, the invariant checker, the catalog suites. |

Dependency direction: `domain` ← `authority`, `store`, `storage`, `resources`, `network` ← `coordinator` → `backend`
(port only). Nothing above `backend/mod.rs` names Firecracker; a test fails if it does (T-BACK-01).

---

## 4. Authority

Authority has three independent parts, checked in this order.

**Enrolment (§9.1, `authority/enrolment.rs`).** A credential has authority only if the enrolment table lists it. An
entry is `{peer_id, role, match}`, and `match` names exactly one credential: `certificate_sha256`, `spki_sha256`,
`local_uid` or `local_gid`. There are no patterns. The core loads the table through the trusted-input rule and hands
the parsed table to the edge. It re-reads the file at least twice per `edge.enrolment_refresh_ms`; a changed table is
pushed to the edge, which closes connections whose entry is gone (AU-5). A table that cannot be used leaves the
previous one in force and is counted.

**Role (§9.2, `domain/method.rs`).** The role table is a pure function, tested for every method × every role.

| Role | May call |
|---|---|
| `observer` | `host.info`, `host.metrics` |
| `caller` | every granting, containment and read method, on records carrying its own tags |
| `operator` | everything, on any record, plus the operator methods |

**Tags (§9.3, `domain/authority.rs`).** Every sandbox, snapshot and operation carries `(peer_id, owner_scope)` of the
request that created it. `owner_scope` is an opaque label the host stores and compares for equality only. A `caller`
sees a record only if its tags are equal; anything else is `NOT_FOUND`, for reads and mutations alike, so a record's
existence is never revealed across scopes (AU-9). A peer is not a tenant: the host holds no tenant, user, billing or
approval concept (INV-015, T-SCOPE-01).

**The safety profile (§9.4, `authority/profile.rs`).** Ceilings (vCPUs, memory, disk, runtime, process count, output
budgets, argv, environment entries, lifetime, allowlist entries), defaults, capabilities (network modes, image
aliases, exec, snapshot create/restore/delete, sandbox destroy, secret injection, private destinations) and the
execution identity inside the guest. Its identity is the SHA-256 of the verified bytes. An operation captures the
profile at admission and is governed by it until it ends (SP-2); `profile.reload` affects later operations only and
refuses a file that does not validate. Above a ceiling, an ungranted capability, or a field the profile has no rule
for: `SAFETY_CONTROL_DENIED`. Nothing is clamped (SP-3, N4). The switches `sandbox_destroy` and `snapshot_delete`
govern role `caller` only: an operator and the host itself are never refused containment.

`on_behalf_of` and signed decisions: `on_behalf_of` is recorded and never compared. The feature `signed_decision` is
not advertised, and a request carrying `authority` is refused with `INVALID_REQUEST` (T-AUTH-08).

---

## 5. The host API

Protocol `acf.host/2`. One request frame, one response frame: a `u32` big-endian length followed by JSON, at most
`edge.max_request_bytes` for a request. The transport is replaceable; the types in `api/` do not know which one
carries them. `execution/contracts/host-api.json` is generated from those types and lists every method with its
class, roles, parameter schema and answer kind, every failure class with where it may appear and its retry advice,
and the closed state vocabularies.

**Envelope (§10.2).** `protocol`, `method`, `owner_scope`, optional `request_id`, `params`, `on_behalf_of`, `wait_ms`;
for every non-read method also `operation_id` (chosen by the caller), `issued_at` and optionally `retry`. The field
`authority` is reserved for signed decisions and is refused while that feature is not advertised. Every type
denies unknown fields. Shape checks that need only the request (resource shape, aliases, generation ≥ 1, a non-zero
lifetime, a non-empty argv) run at decode, in the edge and again in the core. A refusal for a request that did not
decode says what kind of value was found, what was expected and where; it never repeats the value, the unknown
field or the unknown variant (`api::decode_error`), so material that a request carried where it did not belong is
not echoed by the answer that refuses it.

**Methods (§10.3).** Twenty-two, in four classes. The class, not the method, decides how the host treats capacity,
exclusivity, deadlines and inheritance.

| Class | Methods | Treatment |
|---|---|---|
| granting | `sandbox.create`, `sandbox.start`, `exec.run`, `snapshot.create`, `snapshot.restore` | Creates privilege. One per sandbox. Bounded by a deadline. Never continued by a later activation. |
| containment | `sandbox.stop`, `sandbox.destroy`, `snapshot.delete`, `operation.cancel` | Removes privilege. Never refused for capacity, rate or load. Supersedes weaker operations. Re-driven until proven. |
| read | `sandbox.inspect`, `sandbox.list`, `snapshot.list`, `operation.get`, `operation.list`, `run.inspect`, `run.output`, `host.info`, `host.metrics` | Served from committed state. Leaves no record. |
| operator | `profile.reload`, `quarantine.release`, `host.set_mode`, `host.acknowledge` | Role `operator` only. Recorded operations. |

**Answers (§10.4).** A non-read request receives exactly one of `REFUSED` (nothing was accepted, no record exists) or
`OPERATION` (a durable record exists; `view` is its state as of the response). A read receives `RESULT` or `REFUSED`.
Every answer that reflects committed state carries `as_of {lineage, sequence}`.

**Failure classes (§10.5, `error.rs`).** Twenty-three, closed. Two predicates encode the table's columns: a class may
appear in a refusal, as the failure of an operation, or both. A refusal carries retry advice: `SAME_REQUEST_LATER`,
`AFTER_CHANGE` or `NEVER`. Every internal error also carries a side-effect marker, `NONE` or `POSSIBLE` (FS-2); the
default for a backend error is `POSSIBLE`.

**Reads (§10.6, `coordinator/query.rs`).** Served from committed state under roles and tags. A list accepts
`changed_since {lineage, sequence}` and then returns exactly the records that changed, including tombstones of
destroyed sandboxes and deleted snapshots, for `change_retention`. A cursor from another lineage, older than the
change floor or ahead of the store is `CURSOR_EXPIRED`. Names are aliases accepted by reads only (ID-5). A name is
unique within its tags and is looked up there first; an operator may also name a sandbox of other tags when the
name is unambiguous among the records it may read, and is told to use the id when it is not. `host.info` lists a
feature only while the host offers it: `allowlist_network` needs the backend's support and the profile's listing.

**Waiting (API-6, API-7).** An accepted operation runs in its own task. The response is held until the operation ends
or `wait_ms` (capped by `wait_max`) elapses, and is never sent before BEGIN is durable. A disconnect, a slow caller
or the end of the wait changes nothing about the operation (OP-16).

---

## 6. The operation protocol

Every non-read method follows one protocol (§11.1, `coordinator/ops.rs`).

```text
refuse?   protocol · schema · enrolment · role · (known operation? answer it) · host mode · rate · acceptance horizon
          tags · safety profile · state · token · exclusivity · capacity          no record, no effect
  └─ BEGIN    one commit: idempotency + exclusivity + admission + the reserved state + ACCEPTED
       └─ STEP     the name of a privileged step, durable before the step runs    IN_PROGRESS
            └─ BACKEND  the step: success, or a classified failure with a side-effect marker
                 └─ FINISH   one commit: terminal state + lifecycle + lease changes
```

Three properties hold by construction.

* **Exclusivity is derived from committed state.** "Is this sandbox busy?" is answered by the non-terminal
  operations in the store, inside the BEGIN commit closure. There is no in-memory lock that a restart would forget
  (J-3). The states an operation reserves are committed in BEGIN, so the joint-state invariants hold after every
  commit: an execution moves the generation to `RUNNING`, a snapshot moves it to `PAUSED`, a destroy of a live
  generation moves it to `STOPPING`.
* **Every write of an operation is fenced.** STEP, FINISH and every intermediate commit go through `commit_for`,
  which checks inside the commit that the operation is still non-terminal (CC-2). A containment operation ends the
  operations it supersedes in its own BEGIN commit (CC-3); from then on the superseded task can write nothing, and it
  is told to stop.
* **Failure handling is observation-based.** After an error whose marker is `POSSIBLE`, the flow tries to undo and
  the terminal record states what was observed afterwards (FS-3). An error marked `NONE` on a step may be retried up
  to `step_max_attempts`, within the host-wide `retry_budget`, for the three retryable classes only (RY-5, RY-6).

**States (§11.3).** `ACCEPTED`, `IN_PROGRESS`, `RECOVERING`, and the terminal `SUCCEEDED`, `FAILED`,
`CANCELLED (by CALLER | SUPERSEDED)`, `UNKNOWN`. `UNKNOWN` is never collapsed into another state (OP-9). `effect`
and `cleanup` are derived at read time from the record and from the committed state of what the operation left
behind (`derived_cleanup`), so a `PENDING` cleanup becomes `COMPLETE` when the residue is proven gone without
rewriting the operation.

**Idempotency (§11.4).** The key is `(peer_id, owner_scope, operation_id)`. Same key and same fingerprint: the
existing operation, nothing runs again. Same key, different fingerprint: `IDEMPOTENCY_CONFLICT`. `retry: true` for an
unknown key: `NOT_FOUND`, never a new operation. A request that names an operation the host already holds is
resolved before the host mode, the rate limit for new work and the age of `issued_at` are looked at
(`pipeline.rs::known_operation`): it creates nothing, so it is served wherever a read is served. A caller whose
response was lost while the host began to drain can still learn what happened. The same three answers are given
again inside the BEGIN commit, which is what decides between two requests that arrive at once. The fingerprint is SHA-256 over the method and the canonical form
of `params` (`domain/fingerprint.rs`); `request_id`, `retry`, `issued_at`, `on_behalf_of` and `wait_ms` are excluded,
and secret material never reaches it because params carry references only.

**Time (§11.5).** `issued_at` must lie within `acceptance_horizon` (and at most `clock_skew_tolerance` ahead);
`operation_retention ≥ acceptance_horizon` is a mandatory check, which is what makes a replayed request either a
known operation or an expired one. Every operation has an absolute monotonic deadline recorded at BEGIN; one recorded
in an earlier boot counts as expired. A granting operation past its deadline is undone and ends `FAILED/TIMEOUT`; the
success path re-checks the deadline immediately before FINISH (OP-15).

**Cancellation (§11.7).** `operation.cancel` is itself a containment operation. It ends an execution in flight and
is confirmed by the guest; for other types and states it answers what the contract's table says (already terminal,
not cancellable, inherited).

**Host-issued operations (§11.8).** What the host does on its own initiative (ending an expired sandbox, failing a
generation whose runtime is gone, stopping a degraded one, quarantining) is a recorded operation with issuer `HOST`
under the tags of the sandbox it acts on, so the owner can see what the host did and why. `sandbox.fail` is the
host's own operation type and is not callable.

---

## 7. State

**Generation lifecycle (§12.1, `domain/lifecycle.rs`).**

```text
REQUESTED → PROVISIONING → READY → RUNNING → COMPLETED
                              │        │  ↘ FAILED
                              └────────┴→ PAUSED → (the state it was paused from)
     any live state ───────────────────→ STOPPING → STOPPED → DESTROYED
```

The transition relation is a `const fn` tested for every state pair. Nothing leaves `DESTROYED`; a `FAILED`
generation never returns to a live state; a `STOPPED` generation is never started again. A sandbox continues after a
stop only through a new generation created by restore. A sandbox id names a lineage of generations; a generation
number is never reused (ID-1). `QUARANTINED` is a durable condition with a reason, not a state.

**Snapshots (§12.3).** `REQUESTED → SNAPSHOTTING → VERIFYING → READY → DELETED`, with `INVALID` reachable from any
state before `DELETED`. Only `READY` is restorable. A `READY` snapshot becomes `INVALID` when a restore finds
that its manifest, or one of its artifacts, no longer matches what the store holds.

**Leases (§12.4, `resources/admission.rs`).** A generation's lease is reserved in the BEGIN that allocates it and is
released only in the commit that records it `DESTROYED`. A `FAILED` or quarantined generation keeps its lease and its
identifiers, so a leaked runtime cannot hide behind a free slot (LS-1). Snapshot quota is reserved at BEGIN, set to
the real size at `READY`, released at `DELETED`.

**Host modes (§12.6, `domain/mode.rs`).**

| Mode | Granting | Containment | Reads | Operator | Entered when |
|---|:---:|:---:|:---:|:---:|---|
| `STARTING` | – | – | – | – | from process start until startup recovery ends; no endpoint is open |
| `SERVING` | ✓ | ✓ | ✓ | ✓ | recovery complete and every mandatory check passed |
| `DRAINING` | – | ✓ | ✓ | ✓ | `host.set_mode`, or a shutdown signal |
| `CONTAINMENT` | – | ✓ | ✓ | ✓ | a failed mandatory check, an unusable profile, a store older than the system, or no lifetime enforcer |
| `READ_ONLY` | – | – | ✓ | – | the store cannot be written or interpreted |

A failed mandatory check never makes the core exit (HM-2): a host that will not start cannot destroy what it already
runs. Reasons accumulate; the mode holds while any remains. The mode is computed, not stored: `READ_ONLY` if the
journal is write-blocked, else `STARTING`, else `CONTAINMENT` if any reason exists, else `DRAINING`, else `SERVING`.

**Joint-state invariants (§12.7).** J-1 to J-8 relate operations, generations, snapshots and leases.
`testing/invariants.rs` checks all of them over a `JournalState`. The rig installs it as a commit observer, so every
suite asserts them after every commit, and T-STATE-03 does so under random operations and crashes.

---

## 8. Concurrency

* One granting operation per sandbox. A second is refused with `STATE_CONFLICT` and leaves no record. Nothing is
  queued (CC-1).
* A mutation names the generation it expects (`expected_generation`) and may add `if_revision`. A stale token is
  `REVISION_CONFLICT` with no effect (CC-2).
* Containment strength: `sandbox.destroy` and `quarantine.release` > `sandbox.stop` > `sandbox.fail`. A containment
  request is refused only when containment of equal or greater strength is already in flight; everything weaker is
  superseded (CC-3, CC-4). The BEGIN that supersedes also commits what keeps the invariants true: a snapshot that
  was still being written becomes `INVALID`, and the generation a restore in place was building becomes `FAILED`
  (`supersede_entries`). The containment flow then waits up to `preempt_grace` for the superseded task to let go.
* Capacity is checked and consumed in one commit, so concurrent creates for the last slot admit exactly one (CC-6).
* Rate limits are a token bucket per peer, separately for operations and reads. Containment is exempt.

---

## 9. The store

`store/journal.rs` is a narrow write-ahead journal, not an event log: one line per atomic batch,

```text
<crc32 hex, 8 chars> <space> <json {"seq":N,"epoch":E,"entries":[...]}> \n
```

where entries are full-record upserts and the latest record for a key wins.

| Property | Mechanism |
|---|---|
| Atomicity (PS-3) | A batch is visible entirely or not at all. |
| Single critical section (PS-4, PS-7) | `commit_with(check)` holds one mutex across *check → append → fsync → apply*. Memory is updated only after the fsync succeeds, so it never runs ahead of disk. |
| Identity (PS-5, PS-6) | **Lineage**: a random id written when the store is created; qualifies every sequence, revision and cursor. **Commit sequence**: strictly increasing; stamped on each record as its `revision`. **Activation epoch**: one more than the highest in the file, taken at each open for writing and recorded in every batch. |
| One writer | An advisory `flock` on `host-agent.lock`, taken before the store is read. Before every append the file must still have the length this writer left; if not, another writer exists and this activation fences itself. |
| Failed or uncertain commit (FS-9) | A failed append is rolled back by truncation. If the rollback cannot be confirmed, the store demands a fail-stop: the activation ends and must be restarted. |
| Corruption (PS-8) | A torn tail is a crash artefact: truncated and reported. Any other corruption opens the store write-blocked and the host serves in `READ_ONLY`. |
| Schema (PS-11, PS-12) | A store with a higher schema is neither written nor interpreted. Migration 1 → 2 is atomic (new file written and synced, then two renames), keeps the previous file as `<store>.schema1`, and carries non-terminal operations over uninterpreted. |
| Reserve (PS-9) | A ballast file of `store.reserve_bytes`. If an append fails for lack of space the ballast is released and the append retried, so a destroy can still be recorded. While it is released the host refuses new privilege. |
| Bounded growth (PS-10) | The sweep forgets terminal operations after `operation_retention`, output after `output_retention`, tombstones after `change_retention`. The file is append-only, so what was forgotten or replaced leaves it only when it is rewritten as current state: at open, and while serving once it has grown past `store.compact_at_bytes` and at least half of it is history (`Journal::compact_if_grown`). The rewrite changes no revision and continues the sequence. The maintenance tools (`acf-host journal verify`, `journal compact`) open a store of any size. |

Records (`store/records.rs`) are deliberately small: store meta, activation, profile-in-force, operation, sandbox,
generation, snapshot, recovery, quarantine, and the forget record that retention writes. Snapshot manifests and
captured output live in subsystem files and are only located from the store. No path, no secret material and no output byte is ever stored in a record.

All synchronisation goes through `durability.rs`, which has a test-only switch to skip `fsync`. It is compiled only
under `cfg(test)` or the `testing` feature; a release build always syncs.

---

## 10. Recovery and the sweep

**Startup (`coordinator/recover.rs`, RC-5).** Before any endpoint opens, within `recovery.startup_deadline_ms`, the
core resolves every operation an earlier activation left unfinished and observes every generation. Each record's
attempt count is incremented durably before the attempt, so a record whose recovery crashes the core is quarantined
after `recovery.max_attempts`, across restarts (RC-4). When the deadline passes, generations still unobserved are
quarantined and the host leaves `STARTING`.

**Observation (§16.1).** The backend assembles `Observation` from host-side facts only: the runtime is `ABSENT`,
`PRESENT` (process id, start time and boot id all match the record, and the jail id is in its argv), `FOREIGN`
(something else holds the recorded pid; it is never signalled) or `UNKNOWN`; on-disk resources are `ABSENT`, `OWNED`
(the ownership marker names this generation, this lineage and the recorded nonce) or `NOT_OWNED`; enforcement is
`INTACT`, `DEGRADED` or `UNKNOWN`. Observation writes nothing.

**The decision table (§16.2, `recovery/decision.rs`).** Two pure functions; every row is a unit test, and any
combination the table does not list is quarantine.

* `decide_inherited` (Part A): an operation left by an earlier activation. Ownership doubt wins over every other
  row. `sandbox.create`, and `snapshot.restore` before its switch, are undone to proven absence. `sandbox.start`
  with a runtime present is stopped, never adopted. `exec.run` ends `UNKNOWN` and its runtime is stopped: a command
  handed to a guest may have run, and is never sent twice. `snapshot.create` is discarded and the guest resumed.
  A restore after its switch finishes retiring the old generation. Containment is re-driven.
* `decide_idle` (Part B): a generation no operation holds. A healthy idle generation is adopted. A missing runtime
  makes the generation `FAILED` (lease kept). A degraded control stops the runtime with `SECURITY_CONTROL_FAILURE`;
  nothing is repaired in place. A runtime under a record that says none should exist is stopped. An expired sandbox
  is destroyed. An observation that cannot be completed is retried at the next sweep and quarantined after the bound.

Recovery never creates privilege, resolves no secret and checks no authority (RC-9, SEC-021).

**The sweep (`coordinator/sweep.rs`, RC-6).** Every `sweep_interval` the same Part B pass runs over generations that
no operation holds, each decision applied as a host-issued containment operation that commits only if the generation
is still the one, and in the state, that was observed (RC-7). The pass also re-drives inherited containment, applies
retention and refreshes the host's own health: the lifetime enforcer's heartbeat and the store's reserve.

**Posture after launch (IS-3).** No mandatory control of a live generation goes unverified for longer than
`posture_recheck_interval`, whether the sandbox is idle or an operation holds it. The sweep does not decide a sandbox
that an operation holds (RC-6), so the operations that hold a verified runtime watch it themselves
(`Host::while_intact`): an execution, a snapshot capture and a restore in place observe the runtime every quarter of
the interval. If a control is lost the step is abandoned with `SECURITY_CONTROL_FAILURE` and the runtime is ended;
a paused guest is not resumed. The arithmetic is in one place (`RecoveryConfig::posture_due_after`): observations are
never more than half the interval apart (the relation `sweep_interval ≤ posture_recheck_interval / 4` is a mandatory
check), and a control that is costly to verify, such as listing a sandbox's packet filter, is verified at the first
observation after half the interval has passed.

**Quarantine (§16.4, `coordinator/operator.rs`).** A quarantined generation is touched only by
`quarantine.release`, an operator method with two modes. `FORCE_DESTROY` removes the recorded resources by their
host-derived names on the operator's assertion. `DECLARE_ABSENT` asserts they are already gone. Either way the host
observes afterwards and releases the lease only if observation agrees; the result records what was found before and
after.

**A store older than the system (§16.5).** Each ownership marker carries the commit sequence at which its generation
was created. A marker newer than the store's last sequence at open means the store was replaced by an older copy.
The host enters `CONTAINMENT`, takes no destructive action, and stays there until an operator calls
`host.acknowledge`, after which the suspended recovery runs under the acknowledged store.

---

## 11. The backend

**The port (`backend/mod.rs`, §26).** `SandboxBackend` is a semantic boundary: provision, start, observe, pause,
resume, snapshot, restore, discover, stop, teardown, exec, probe, stats, busy slots, residue, force teardown. A
backend reports and never decides lifecycle state; it never retries; it sets the side-effect marker whenever it
cannot rule a change out; `stop` and `teardown` are idempotent; `observe`, `discover`, `residue` and `busy_slots`
change nothing. `CapabilityProfile` declares what exists (network modes, snapshot and restore, secret injection,
incremental output, per-runtime overhead, identifier slots, stop grace); a request needing an undeclared capability
is refused with `UNSUPPORTED` before BEGIN. `LaunchSink` is called the instant a runtime process exists, before it is
configured: the coordinator records the process identity durably and arms lifetime enforcement, and if that fails the
backend ends the runtime.

**The Firecracker backend (`backend/firecracker/`).** Each step fails closed; if any step fails after the VMM exists,
the VMM is killed before the error is returned.

```text
provision  verified copies of kernel and rootfs into the generation directory; the sandbox's own network namespace
network    (allowlist only) tap device, packet filter, sockets, guest-traffic role          netplumb.rs
launch     jailer: chroot, PID namespace, cgroup v2, unique uid/gid, network namespace → identity recorded, ticket armed
prove      jail id in argv → seccomp filter, no_new_privs, empty capabilities, chroot, uid → inside its namespace
configure  link payload into the jail → machine-config, boot-source, drive, vsock, (network interface)
assert     GET /vm/config shows zero network interfaces (mode none) or exactly one (allowlist)
boot       InstanceStart → Running → guest agent Hello → agent version check → network verdict
```

* The binaries are trusted inputs with a pinned identity and a pinned version (TI-2, `verify.rs`). The identity
  is the SHA-256 of each installed file, held in the host configuration (`firecracker.firecracker_sha256`,
  `firecracker.jailer_sha256`). Both files are hashed at startup, before either is run even to ask its version,
  and again before every start and restore, so a file replaced while the host runs is refused instead of
  executed. An unset or different digest, or another version than `firecracker.pinned_version`, is a failed
  mandatory check. The jailer is never bypassed and `--no-seccomp` is never passed.
* Every other tool the core runs as root (`unshare` for the namespace of every sandbox; `ip`, `nft` and `nsenter`
  for mode `allowlist`) is named by an absolute configured path, verified as a trusted executable, and started with
  an empty environment. Nothing is looked up through `PATH`.
* Identifier pool (RS-3): slot *i* runs its VMM as uid `uid_range_start + i`. A slot is assigned only if records show
  it free and observation (`busy_slots`) shows no live resource carrying it.
* Limits (RS-2): a per-sandbox cgroup v2 created by the jailer (`cpu.max`, `memory.max` including the declared VMM
  overhead, `pids.max`), in addition to the VM boundary. Evidence is read back from the same cgroup; drift from the
  configured values is a degraded control.
* Signalling (`backend/process/supervisor.rs`): open a pidfd, verify the stronger-than-pid identity, signal through
  the pidfd. A recycled pid cannot receive the signal.
* API models (`models.rs`) are transcribed from the pinned version's API description and each has a golden-JSON test.
* The backend declares `secret_injection: false` and `restore_reseeds_entropy: false`, so secret delivery is refused
  on this backend and entropy reseeding is reported as not proven.

---

## 12. Network

Two modes (§20). Any other word is `UNSUPPORTED`, decided before the request is decoded any further, so that a
caller written for a later contract learns that the mode is not offered here. A generation's intent is recorded
and immutable (NW-3).

**`none`.** No network device exists in the guest. Three independent layers: no interface in the VMM configuration
(asserted from `GET /vm/config`), an empty network namespace, and a guest-side corroboration that can only add a
violation.

**`allowlist`.** Outbound TCP to listed destinations, nothing inbound, IPv4 only. Offered only where the profile lists
it and the backend finds `ip`, `nft` and `nsenter` as trusted executables.

```text
guest ── eth0 ══ tap0 (gateway address) ── [ sandbox network namespace: no route out, forwards nothing ]
                    ├─ UDP gateway:53      resolver socket ─┐ bound inside the namespace by the core,
                    └─ TCP gateway:15001   relay socket ────┘ served by the guest-traffic role in the HOST namespace
                       ▲ every guest TCP connection is redirected here by the packet filter
```

* Every sandbox uses the same private /30 (`network.guest_segment`, default `10.201.0.0/30`). It is never routed, so
  it cannot collide, and a restored guest finds the addresses it was captured with.
* The packet filter (`nft`, table `inet acf`) redirects all guest TCP to the relay port and drops by default on
  input, forward and output. Nothing is forwarded; ICMP, IPv6 and other UDP have no rule.
* The guest-traffic role (`acf-traffic`) is the only way out. The resolver answers only for allowlisted names,
  refuses every other name without an upstream query, returns `A` records only and records the addresses it returned
  (AL-3). The relay reads the destination the guest dialled (`SO_ORIGINAL_DST`), reads the TLS server name when a
  name entry could allow it, and asks one pure function for the verdict: a name entry allows a TLS connection whose
  server name equals the entry, to an address the resolver returned for that name to this sandbox within
  `dns_binding_ttl`, on a listed port (AL-4, which is what defeats DNS rebinding); a network entry allows TCP to its
  addresses and ports (AL-5). Loopback, link-local and metadata addresses, multicast, the host's own addresses and
  other sandboxes are denied whatever the allowlist says; private ranges need the profile's `private_destinations`
  (AL-6).
* Deny by construction (NW-1): the namespace has no route, so if the role stops or the filter is flushed the guest
  has no connectivity. The sweep re-checks that the role's control group has processes and that the filter listing
  still hashes to the digest recorded at setup.
* Everything is created before the VMM is launched; a setup failure means the generation never runs (NW-2).

Admission (`network/intent.rs`) uses the same parser and address classification as the enforcement point, so an entry
admission accepts is one the role can load.

---

## 13. Execution, storage, resources, secrets

**Execution (§18, `coordinator/exec.rs`, `guest/`).** An execution is an argument vector, never interpreted by a
shell. One at a time per sandbox, no stdin. The request may set only environment names the profile lists; the
working directory must lie under a permitted prefix. The guest is given a deadline; the host keeps its own, later by
`backstop_margin`, and ends the runtime if it passes (EX-5). The outcome table of §18.2 is implemented row by row:
a workload's own failure is a result, not an operation failure; a command handed to a guest never reports
`NOT_APPLIED` and is never sent twice; when no result can be obtained the runtime is ended and the operation is
`UNKNOWN`. Output has a byte budget per stream; excess is counted, not stored, and never blocks the workload. Output
is readable only through `run.inspect` and `run.output`, under tags, and never appears in telemetry.

The guest is untrusted (`guest/client.rs`): every frame is bounded before allocation, unknown fields are rejected,
output caps are re-enforced on what comes back, and every result field is labelled `HOST_OBSERVED` or
`GUEST_REPORTED` in the schema. Only host-observed facts drive host decisions. The host initiates every connection
(Firecracker's vsock socket, `CONNECT 5252`); the host never listens for a guest. A guest agent whose version differs
from the image manifest fails the start or the restore (GP-4).

**Storage (§21, `storage/`).** Paths are derived from validated typed ids, never read from a record. A generation
directory holds an `OWNER.json` marker with the generation, the store lineage, the creation sequence and a nonce the
store also holds; cleanup that cannot prove ownership quarantines instead of deleting. An image's identity is the
SHA-256 of its manifest, which binds the kernel and root filesystem digests; files are hashed while they are copied
from an open descriptor, so the digest describes the bytes that are booted.

**Snapshots and restore (§21, `coordinator/snapshots.rs`).** Create: probe → pause → capture and verified copy →
write manifest → re-hash → `READY`; the guest returns to the state it was paused from whether or not the capture
succeeds. The manifest's digest is held in the store; a manifest or artifact on disk is believed only if it matches.
Restore: store-held digest → manifest → compatibility gate (backend identity and security-profile digest, VMM
version, architecture, CPU model and feature digest, guest agent and protocol version, secret references still
resolvable) → admission for the new generation → verified copy → load → agent version → the baseline probe must
reproduce the snapshot's baseline → switch in one commit → retire the old generation. The old generation stays
current until the new one is verified, so a failed restore never costs the caller their sandbox (RE-6).

**Resources and lifetime (§19, `resources/`).** Admission is a pure function over committed state, run inside the
BEGIN commit: vCPUs, memory including per-runtime overhead, disk at full size, sandbox count, free-space headroom,
snapshot count and bytes. Never overcommitted, never reduced to fit. Every sandbox has an expiry, from the request or
the profile's default, never beyond the profile's ceiling. Two independent mechanisms end it: the coordinator issues
`sandbox.destroy` at expiry, and the lifetime enforcer ends the runtime named by an *expiry ticket* written the
instant the runtime exists. A ticket holds the process identity, the control group's kill switch and the monotonic
expiry of this boot. The enforcer writes only to a `cgroup.kill` under the configured root, signals only the recorded
process instance, and writes a heartbeat; when the core cannot see a fresh heartbeat it stops creating privilege.
Across a reboot the remaining time is recomputed from the wall clock and never exceeds what remained before (LT-2).

**Secrets (§22, `secrets/`).** Requests carry references only; raw material in a request is `INVALID_REQUEST`.
`SecretMaterial` is neither `Clone` nor `Serialize` nor printable and is overwritten when dropped, so it cannot be
written to a record, a fingerprint or an event. A reference is resolved inside the operation that delivers it, at the
moment of delivery, and a later activation never resolves it again because an inherited operation is never
continued. A generation is marked secret-bearing for what was delivered to it: the mark is written at BEGIN so that
a crash after a delivery cannot lose it, and an operation that establishes that nothing reached the guest takes
back exactly the references it added. The shipped provider reads one trusted file per reference from `paths.secrets_dir`. Delivery requires the
backend capability `secret_injection`, which the Firecracker backend does not declare.

---

## 14. Observability

Three classes of information with three reliabilities (§24.1). Committed state is authoritative and is read through
the API. Security evidence (confinement posture, network verdict, restore oracle) is obtained at the call site or the
operation fails closed. Diagnostic telemetry is best effort: a full disk or a dead log file increments a counter and
changes no outcome (OB-6).

* **Events** (`telemetry/events.rs`, `execution/contracts/event-schema.json`): JSON lines under
  `<state_root>/telemetry`, each with `host_id`, lineage, activation epoch, a per-activation sequence number and,
  when it describes a committed change, that change's commit sequence. A consumer detects loss from a gap and
  resynchronises by listing. Failures are described by class and side-effect marker, never by message. Types:
  `operation.accepted`, `operation.step`, `operation.finished`, `recovery.operation`, `recovery.finished`,
  `generation.quarantined`, `sandbox.destroyed`, `snapshot.invalidated`, `security.control_failure`,
  `host.containment`, `host.mode`, `host.acknowledged`, `profile.reloaded`.
* **Metrics** (`telemetry/metrics.rs`, `host.metrics`): counters of activity, and gauges that show standing risk:
  `quarantined_generations`, `oldest_quarantine_age_ms`, `failed_generations_holding_leases`, `unmanaged_resources`,
  `operations_open`, `oldest_open_operation_age_ms`, `ms_since_last_complete_sweep`, `store_reserve_released`,
  `host_mode`. Labels are closed vocabularies; a value outside a small character set is recorded as `invalid`, and
  the number of series is bounded (OB-8).
* **Logs**: `tracing` to standard error; `ACF_LOG_FORMAT=json` for JSON lines.

No secret material, credential, execution output or privileged host path is placed in any of them (OB-7).

---

## 15. Trust boundaries and control surfaces

| Party | Trusted for | Not trusted for |
|---|---|---|
| Operator (root) | configuration, profile, enrolment, binaries, images, secrets | — |
| Enrolled peer | its role and tags, within the safety profile | anything about another scope; anything above the profile |
| Edge process | the enrolled `(peer_id, role)` of a request | request validity (the core validates again) |
| Guest | nothing | every statement is bounded, labelled and never an input to a host decision |
| Upstream resolver | availability | safe addresses (answers are filtered) |
| Telemetry sink | nothing | — |

**The trusted-input rule (TI-1, `authority/trusted_file.rs`).** Configuration, profile, enrolment table, secrets, TLS
material and every executable the core runs are used only if they are regular files (no symlink), owned by a trusted
owner, not writable by group or other, reached through directories with the same property, and within a size bound.
Every check is made on the already-open descriptor, and the bytes that are hashed and parsed are read from that
descriptor. A linked directory on the way is judged by the directory it points to and by every directory that one is
reached through. An executable may be a link placed by a trusted owner (distributions ship `/usr/sbin/ip` that way);
the file it resolves to, and the way there, are held to the same rule.

**Control surfaces (§17.3).** The local socket and, if configured, one TLS listener, both served by the edge; the
edge ↔ core socket pair; the Firecracker API socket inside each jail; the vsock socket of each VM (host-initiated
only); the expiry ticket directory; per-sandbox resolver and relay sockets, reachable only from that sandbox's
namespace. No surface is reachable from a guest. Test code, fault points, the in-memory backend and the test PKI are
compiled only under the `testing` feature; a release build contains none of them, and the build verifies that from
the artifact (TI-3).

---

## 16. Configuration and state on disk

Three trusted files, three questions:

| File | Question | Code |
|---|---|---|
| `/etc/acf/host.yaml` | Where do things live, how big is the machine, and what is every bound? | `config.rs` |
| `/etc/acf/profile.yaml` | How much may one request consume, and which capabilities exist here? | `authority/profile.rs` |
| `/etc/acf/enrolment.yaml` | Who may call, in which role? | `authority/enrolment.rs` |

Every bound is a named, finite parameter with a default (§30, INV-034); zero never means unlimited. Validation has
two tiers. `HostConfig::parse` rejects a file that does not parse or that would point the host at unsafe paths or
identities. `HostConfig::mandatory_checks` evaluates the relations between parameters (for example
`operation_retention ≥ acceptance_horizon`, output budgets fitting the memory set aside for the agent, profile
ceilings within the envelope). A violated relation is a failed mandatory check: `CONTAINMENT`, not exit. `acf-host
doctor` runs the machine checks: `/dev/kvm`, the kernel release, cgroup v2 delegation, swap, SMT, kernel same-page
merging, both identifier
ranges against the account database, the edge identity, the state directory and its free space, the network tools,
`unshare`, the lifetime enforcer's heartbeat, the Firecracker and jailer binaries against their pinned digests and
the pinned version, and
that the profile and the enrolment table load. Each is `PASS`, `WARN` or `FAIL`. `serve` runs the same checks and
records every `FAIL` as a reason for `CONTAINMENT`.

```text
<state_root>/                      default /var/lib/acf, mode 0700
  state/            journal.wal, journal.reserve, host-agent.lock
  images/<alias>/   manifest.json, kernel, rootfs                      installed by the operator, read-only to the host
  sandboxes/<sbx>/<gen>/   OWNER.json, jail/…, net.digest
  snapshots/<snp>/<gen>/   manifest.json, vmstate, mem, disk
  artifacts/<art>/         content, meta.json                          captured output
  telemetry/               events.jsonl

<runtime_dir>/                     default /run/acf
  host-agent.sock          the local endpoint
  netns/                   one persistent network namespace per generation
  expiry/                  expiry tickets and the enforcer's heartbeat
```

---

## 17. Test architecture and what is not verified

Evidence levels follow the contract (§31.1): L0 static, L1 unit and property, L2 whole process against a test
backend, L3 shipped configuration and profile, L4 real VMM, L5 real supply chain.

* **Pure decisions at L1**: the lifecycle relation, the role and mode tables, admission arithmetic, the recovery
  table, the fingerprint, network verdicts, parsers (property-tested), the journal including corruption and failed
  appends, the migration.
* **The catalog suites at L2** (`testing/suites/`, one module per catalog section, each test named after its
  entry): the real coordinator, store, recovery and admission pipeline over the in-memory backend. The rig models a
  restart by opening the store again over the same disk and the same world of still-running fake runtimes. The
  fault-point matrix crashes every operation type at every fault point and compares the outcome with an oracle
  transcribed from the contract.
* **The backend conformance suite** (`testing/conformance.rs`, T-BACK-02): fifteen rules of the port, written
  against `dyn SandboxBackend` only: a launch that cannot be recorded leaves no runtime, observation changes
  nothing, another process instance is never signalled, teardown needs the proof of ownership, changed bytes are
  never launched, a restore reproduces the baseline. One body of assertions, run against the in-memory backend in
  every `cargo test` and against the Firecracker adapter under `make root-test`. The catalog suites judge the
  coordinator through the test backend; this judges the test backend by the rules the real one is held to.
* **The Firecracker backend without KVM** (`testing/fc_backend_tests.rs`): a fake jailer that parses the real
  flags, a fake API server that enforces the VMM's state-machine rules, real file staging and the real guest agent.
* **Process and kernel**: `tests/process_roles.rs` (roles as processes), and the network plumbing in a real network
  namespace, run as root or inside `unshare --user --map-root-user --net --mount` (`make net-plumbing-test`).
* **Tests that need root** are marked `#[ignore]` with the reason, so a plain `cargo test` reports them as ignored
  instead of passing them unseen; asked for explicitly without root they fail. `make root-test` runs them.
* **Shipped files at L3**: the example configuration, profile and enrolment table are parsed by the real loaders
  and checked against each other.

**Not verified.** No microVM has been booted from this code: the environment it was written in has no `/dev/kvm`.
Everything the contract marks L4 or L5 is unrun, including the isolation claims as observed on a real VMM, kernel
enforcement of limits, the lifetime enforcer against a real runtime, the allowlist end to end through a real guest,
and the restore oracle on a real snapshot. [VERIFICATION_STATUS.md](VERIFICATION_STATUS.md) lists each entry.

---

## 18. Seams

| If this changes | Cut here | What stays |
|---|---|---|
| Transport or encoding | `edge/`, `acf-wire` framing | `api/` types, the admission pipeline |
| Credential mechanism | `edge/local.rs`, `edge/tls.rs`, the `match` forms of enrolment | `(peer_id, role)` and everything behind it |
| Decision provider | `authority/` (a signed decision would be verified here) | roles, tags, the profile as the local floor |
| Store engine | `store/journal.rs` behind `commit_with` / `read` | records, the coordinator, recovery |
| VMM | `backend/firecracker/` as one unit, with its network plumbing and storage placement | the port, the coordinator, the conformance suite and the catalog suites (run both against the new backend) |
| Secret provider | `secrets::SecretProvider` | references in requests and records |
| Telemetry backend | `telemetry/` | events' schema and the counters' names |
| Guest agent or runner | `guest/`, `acf-wire::guest` (versioned) | the execution outcome table |

What the contract defers and the code reserves a place for: signed decisions (`authority` in the envelope is refused
today), incremental output (`incremental_output` is declared false), snapshot portability and export, image
distribution, file transfer to and from a guest, shares between scopes, network byte budgets.
