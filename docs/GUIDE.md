# Codebase guide — how to read, reason about and change the host agent

Written for the engineer or architect who will own this code. [ARCHITECTURE.md](ARCHITECTURE.md) says what the code
is. This guide says how to read it, which promises it makes, where a small change has a large effect, and how to
change it without breaking a promise. It refers to the execution-plane contract (version 1.2.0) by its clause ids.

## How to use this guide

Four passes. Each answers one question. Do them in order: detail without the map is how an invariant gets "fixed"
into a bug.

| Pass | Question | You are done when you can | Time |
|---|---|---|---|
| 1 | What does the code do? | trace one request from a socket to a microVM and back, naming each function | 2 h |
| 2 | How is it structured? | say which module owns each promise and which test pins it | 1 day |
| 3 | Where are the leverage, the risks and the seams? | change an operation, a parameter or the backend safely and say what to review | 2 days |
| 4 | What does it optimise, and how should it evolve? | argue what must not change, and what would make you reverse a decision | ongoing |

---

## 0. The whole system on one page

```text
 peer ──TLS 1.3 / Unix socket──► edge (unprivileged) ──socket pair──► core (root)
                                  authenticate, bound, decode           admit ─► BEGIN ─► STEP ─► backend ─► FINISH
                                                                          │                         │
                                                              journal.wal (the only truth)    jailer ─► firecracker ─► guest
                                                                          │                         │         vsock :5252
                                  lifetime enforcer (root) ◄── expiry ticket per runtime            └─ guest-traffic (unprivileged)
```

Five sentences that carry most of the design:

1. **The store is the only truth.** Memory is a cache of it; telemetry is a rumour about it.
2. **Nothing privileged happens before a durable record says it may.** BEGIN before any effect, STEP before each
   privileged step, FINISH before any answer.
3. **A refusal leaves nothing.** No record, no reservation, no effect.
4. **Creating privilege is optional; removing it is not.** Granting operations are refused under any doubt.
   Containment is never refused for load, never waits for a guest, and is re-driven until proven.
5. **Doubt is quarantined.** Nothing is adopted, signalled or deleted without proof that it is ours.

---

## 1. First pass — what the code does

### 1.1 Life of a request

Follow `sandbox.create` and then `exec.run`. Open each file as you go.

| Step | Where | What happens |
|---|---|---|
| 1 | `edge/serve.rs` | A connection is accepted under `max_connections` and the per-source cap. The peer is authenticated (`edge/local.rs`: kernel peer credentials; `edge/tls.rs`: client certificate) and looked up in the enrolment table. Not enrolled: one refusal, closed, before any request is read. |
| 2 | `edge/serve.rs`, `api/envelope.rs`, `api/command.rs` | One frame of at most `max_request_bytes` is read, decoded strictly and validated. The edge relays it to the core with the peer's `(peer_id, role)` over `edge/channel.rs`. |
| 3 | `coordinator/link.rs` | The core's end of the channel. Each request runs in its own task. |
| 4 | `coordinator/pipeline.rs::admit` | Protocol version, validation again, enrolment again, role, host mode, rate, acceptance horizon. A read is answered here from committed state. |
| 5 | `coordinator/pipeline.rs::operate` | The operation is spawned as a task. The response waits for it, up to `wait_ms`, and never returns before BEGIN is durable. |
| 6 | `coordinator/sandbox.rs::sandbox_create` | Profile check, then `begin` with a closure that runs inside the commit: tags, capacity, identifier slot. The lease and the generation record are written with the operation record. |
| 7 | `coordinator/ops.rs::step`, then `SandboxBackend::provision` | The step's name is durable first. The backend makes verified copies of the image and creates the namespace. |
| 8 | `coordinator/ops.rs::finish` | One commit: `SUCCEEDED`, generation `PROVISIONING`. |
| 9 | `sandbox_start` | Same shape. `LaunchSink` records the runtime's process identity and arms the expiry ticket the instant the VMM exists, before it is configured. Posture and network evidence are verified; the generation becomes `READY`. |
| 10 | `coordinator/exec.rs::exec` | BEGIN moves the generation to `RUNNING`. `exec_body` declares the step, calls `SandboxBackend::exec` under `while_intact`, builds the result, stores output through `storage/artifacts.rs`, and finishes with the generation `COMPLETED`. |
| 11 | `guest/client.rs` → vsock → `execution/guest-agent` | The host connects to the guest. The agent runs the argument vector as the unprivileged guest user with capped output and a deadline. The host keeps a later deadline of its own. |

Then read one failure: in `exec_failed`, see that an error after the command may have reached the guest never
becomes `FAILED/NOT_APPLIED`: the runtime is ended and the operation is `UNKNOWN`.

### 1.2 A reading order

| # | File | Why |
|---|---|---|
| 1 | `lib.rs`, `main.rs`, `app.rs` | the roles and the startup sequence, in about 700 lines |
| 2 | `domain/method.rs`, `domain/mode.rs`, `domain/lifecycle.rs`, `error.rs` | the closed vocabularies; each is a table with a test that transcribes the contract |
| 3 | `coordinator/mod.rs`, `coordinator/pipeline.rs`, `coordinator/ops.rs` | the protocol every operation follows |
| 4 | `coordinator/sandbox.rs`, `coordinator/exec.rs` | two flows end to end |
| 5 | `store/journal.rs` (the header and `commit_with`), `store/records.rs` | what is durable and what atomic means here |
| 6 | `recovery/decision.rs`, then `coordinator/recover.rs` and `coordinator/sweep.rs` | the decision, then how it is applied |
| 7 | `backend/mod.rs`, then `backend/firecracker/backend.rs` | the port, then one implementation of it |
| 8 | `testing/rig.rs`, `testing/suites/rec.rs`, `testing/conformance.rs` | how a restart is modelled, how every fault point is tested, and what any backend must honour |

### 1.3 What to remember after the first pass

* The edge decides nothing and holds nothing. The core decides everything and reads no peer bytes.
* An operation is a record with a state machine. A flow is a function that moves it.
* The backend reports. The coordinator commits.

---

## 2. Second pass — how it is structured

### 2.1 Who owns which promise

| Promise | Owner | Pinned by |
|---|---|---|
| Peer bytes are parsed without privilege | `privsep.rs`, `edge/` | `tests/process_roles.rs` |
| One pipeline for every endpoint | `coordinator/pipeline.rs::admit` | `t_auth_02_…`, `suites/edge.rs` |
| A caller sees only its own tags | `domain/authority.rs`, `Ctx::require_access` | `t_auth_03_…` |
| A limit is refused, never clamped | `authority/profile.rs` | `t_auth_06_…` |
| The command set, roles, modes, classes are exactly the contract's | `domain/` | the table tests beside each |
| A refusal leaves nothing | every precheck runs before or inside BEGIN | `t_api_03_…` |
| No effect without a prior durable declaration | `coordinator/ops.rs` | `t_pers_02_…`, `t_op_05_t_rec_02_…` |
| No answer before the state is durable | `pipeline.rs::operate` | `t_op_08_…` |
| The joint-state invariants hold after every commit | reserved states in BEGIN, `supersede_entries` | `testing/invariants.rs`, `t_state_03_…` |
| One writer; a stale writer cannot write | `store/journal.rs`, `store/lock.rs` | `t_pers_04_…` |
| Memory never runs ahead of the store | `Journal::commit_with` | `t_pers_03_…`, `store::journal` tests |
| An inherited granting operation is never continued | `recovery/decision.rs`, `coordinator/recover.rs` | `t_rec_03_…`, the decision rows |
| Nothing is touched without ownership proof | `storage/generation.rs`, `backend/process/` | `t_rec_04_…`, `t_rec_05_…` |
| A failed generation keeps its lease | `resources/admission.rs` | `t_res_03_…` |
| A sandbox ends at its expiry with or without the core | `resources/lifetime.rs` | `resources::lifetime` tests; L4 not run |
| A lost control ends the runtime, idle or held | `coordinator/sweep.rs`, `Host::while_intact` | `t_sec_05_…` |
| Loss of network enforcement yields no connectivity | `backend/firecracker/netplumb.rs`, `execution/traffic/` | `netplumb` and `acf-traffic` tests; L4 not run |
| A restore is accepted only by the oracle | `coordinator/snapshots.rs` | `t_snap_01_…` to `t_snap_03_…` |
| Secret material cannot be written anywhere | the type `SecretMaterial` | `t_secr_*`, `secrets` tests |
| Telemetry changes no outcome | `telemetry/` | `t_obs_01_t_obs_02_…` |
| Every bound is finite and validated | `config.rs` | `config` tests, `shipped_files_tests` |
| The release contains no test code | feature `testing` | the release purity check |

### 2.2 The house style

Patterns that recur. Follow them and the code stays reviewable; break one and say why in the change.

* **Decide in a pure function, apply in one place.** The lifecycle relation, role and mode tables, admission
  arithmetic, recovery plans, fingerprint, network verdicts and expiry arithmetic take values and return values.
  Each has an exhaustive test. The code that applies a decision contains no judgement.
* **Check inside the commit.** Anything that must be true at the moment a record is written is checked in the
  closure passed to `Journal::commit_with` (through `begin` or `commit_for`), not before it.
* **Errors carry a class and a side-effect marker.** `AcfError::with_possible_side_effect()` is the difference
  between "nothing happened" and "look before you decide". The default for I/O errors is `POSSIBLE`.
* **Identifiers are typed and validated on construction and on deserialisation.** A path is derived from an id;
  it is never read from a record.
* **A vocabulary is closed and tested against the contract.** Adding a method, state or failure class without a
  contract change fails a test.
* **Capabilities over paths.** `cap-std` directories for storage; open descriptors for trusted files; a pidfd for
  signals.
* **What cannot be verified here is said, not simulated.** A test that needs root is ignored with its reason. A
  backend capability that is not proven is declared false.
* **Comments say why and cite the clause.** A comment that restates the code is deleted.

### 2.3 Three flows that explain almost everything

**Containment supersedes (CC-3).** `sandbox_destroy` → `begin_containment` → inside the commit `admit_containment`
returns what is in flight and weaker; `supersede_entries` writes their terminal records and what keeps the
invariants true. After the commit, `preempt` cancels the superseded tasks and waits up to `preempt_grace`. A
superseded task finds out at its next write: `commit_for` returns `AcfError::superseded()`, and the task stops
without writing.

**A crash anywhere (TV-4).** The `fault!` macro marks the five points: before BEGIN, after BEGIN, before the
backend step, after the backend acted, after FINISH and before the response. `suites/rec.rs` arms each point for
each operation type, drops the host, builds a new activation over the same store and the same world, and compares
the result with an oracle transcribed from the contract. In a release build the macro expands to nothing.

**The sweep (RC-6, RC-7).** `run_sweeper` → `sweep_once` → `sweep_generations` → `observe_generation` →
`decide_idle` → `apply_idle`. Whatever the plan, it is applied as a host-issued operation whose BEGIN re-checks that
the generation is still in the state that was observed. The sweep skips a sandbox that an operation holds; that
operation watches the runtime itself through `while_intact`.

### 2.4 What to remember after the second pass

* If a fact must survive a restart, it is in a record. If it is not in a record, a restart must be able to
  rediscover it by observation.
* Every promise has an owner and a test. If you cannot name both, you have found a gap.

---

## 3. Third pass — leverage, risks and seams

### 3.1 Where a small change has a large effect

| Place | Why it is sensitive |
|---|---|
| `Journal::commit_with` | The one critical section. Idempotent BEGIN, atomic admission and fencing all rest on check, append, fsync and apply happening under one lock, in that order. |
| `coordinator/ops.rs::{begin, commit_for, finish}` | Every operation passes through them. A write that bypasses `commit_for` is a write a superseded task can make. |
| `recovery/decision.rs` | The whole of what happens after a crash. A changed row changes the meaning of every interrupted operation. |
| `authority/trusted_file.rs` | Everything the root process believes or executes passes through it. |
| `domain/` tables | They are the wire vocabulary. Changing one changes the generated contract and every client. |
| `store/records.rs` | On-disk format. A changed field needs a schema version and a migration. |
| `privsep.rs::enter_role` | Must run before the runtime has a second thread. Moving it after runtime construction silently leaves threads without `no_new_privs`. |
| `config.rs::mandatory_checks` | The relations make bounds mean what the documents say. Removing one can turn an upper bound into a hope. |

### 3.2 Risk register

| Risk | Why it matters | Mitigation in place | What is still open |
|---|---|---|---|
| Nothing has run on a real VMM | Every isolation claim is, so far, a claim about code | Fail-closed verification at launch; the adapter's orchestration tested against a fake API with the real guest agent | The L4 suites must be run on a KVM host before any use with untrusted code |
| The Firecracker adapter's tests need root | They were not run where this was written | They are ignored visibly, not passed | `make root-test` on a host with root |
| API models are transcribed from one release | A field rename upstream is a `400` at runtime | Golden-JSON tests per body; the version is pinned and verified at startup | Re-transcribe when the pin moves |
| The whole store is held in memory | Size grows with operations retained: at most rate limit × retention per peer, which is large with the defaults | Retention; the file is rewritten while serving; rate limits before BEGIN | No ceiling on record count other than that product: size the two parameters for the machine |
| A TLS server name is the guest's claim | Two sites behind one allowlisted address are both reachable | Stated in the contract and in the traffic crate | Accepted |
| Snapshots contain guest memory | A secret present at capture is in the file | Private to the core; no export; secret-bearing snapshots are tracked | Encryption at rest is not implemented |
| Guest entropy after restore | Two restores of one snapshot can share random state | The backend does not claim reseeding; the result says so | Needs a guest kernel and VMM feature verified at L4 |
| Timing in tests | A loaded machine makes real-time tests flaky | Manual clocks where a decision depends on time | A few tests still wait on real time with generous bounds |

### 3.3 Change recipes

**Add a parameter.** Add the field with a default in `config.rs`; add it to the non-zero list or state its
relation in `mandatory_checks`; add a line to `config/host.example.yaml` (a test compares the example with the
built-in defaults); regenerate schemas; add a case to the relation test.

**Add a method.** The contract changes first. Then: `domain/method.rs` (variant, class, table test),
`api/command.rs` (typed params, strict), `pipeline.rs::run` or `read`, the flow, `OperationType` if it is an
operation, a recovery row for it in `decide_inherited` (the test that enumerates all types fails until you do),
`rig.rs::valid_params`, a suite test, regenerate the contracts, update the client.

**Add a step to a flow.** Call `step(op, "name")` before the privileged call. Decide what the failure path does
if the process dies right after: the fault-point matrix will ask. If the step creates a resource, its identity
must be derivable from records that are already durable.

**Change a record.** Bump `STORE_SCHEMA_VERSION`, write the migration in `store/migrate.rs` (it works on the
latest record per key and never interprets an operation's intent), keep the old file, add a migration test with a
non-terminal operation in the old store.

**Replace the backend.** Implement `SandboxBackend` and `CapabilityProfile` in a new directory under `backend/`.
Bring the isolation controls, network plumbing and storage placement with it: they are one unit. First make it pass
`testing/conformance.rs` (build a `Subject` for it, as `fc_backend_tests.rs` does for Firecracker): those are the
rules the coordinator relies on, and they fail with the rule's name. Then run every suite in `testing/suites/`
against it, then the L4 suites. Nothing above `backend/mod.rs` should need to change; if it does, the port was
leaking.

**Move the Firecracker pin.** Update `scripts/firecracker.lock` (version and both digests from two sources),
`firecracker.pinned_version` in the example configuration (each host also takes the two binary digests the
installer prints), re-transcribe `models.rs` against the new API
description, run the root tests and the KVM suites. Existing snapshots become incompatible; `snapshot.list` says so.

### 3.4 Twelve questions for a review

1. Does every new privileged call have a STEP before it and a failure path that observes?
2. Is every new write of an operation made through `commit_for`?
3. Could this refusal leave a record or a reservation?
4. Is the check made inside the commit that depends on it?
5. Does a new error path set the side-effect marker correctly, and is `NONE` actually provable?
6. Does anything now trust a statement from a guest, or from a peer beyond its role and tags?
7. Is a new string from a request bounded, validated and kept out of metric labels and paths?
8. Does a new bound have a parameter, a default, a non-zero check and, if it relates to another, a relation?
9. Does recovery know what to do if the process dies in the middle of the new code?
10. Is new behaviour that needs root or a VMM marked so that its absence is visible in the test summary?
11. Did the generated contracts change, and is the change intended?
12. Does the change add anything to a release build that belongs behind the `testing` feature?

### 3.5 Debugging playbook

| Symptom | Look at | Likely cause |
|---|---|---|
| Host is in `CONTAINMENT` | `host.info` → `containment_reasons`; `acf-host doctor` | a failed mandatory check, an unusable profile or enrolment table, no lifetime enforcer, or a store older than the system |
| Host is in `READ_ONLY` | `host.info` → `read_only_reason`; `acf-host journal verify` | store corruption other than a torn tail, an unsupported schema, or a fail-stop |
| An operation is `UNKNOWN` | its `failure` and the generation's `failure` | no result could be obtained for an execution; the runtime was ended on purpose |
| A generation is quarantined | `quarantined` on `sandbox.inspect`; the recovery record | ownership could not be proven, or observation failed `recovery_max_attempts` times |
| `RESOURCE_EXHAUSTED` with apparently free capacity | `host.metrics`: `failed_generations_holding_leases`, `quarantined_generations` | failed or quarantined generations keep their leases until destroyed or released |
| `allowlist` is `UNSUPPORTED` | `acf-host doctor` → `network_tools` | `ip`, `nft` or `nsenter` is not a trusted executable at the configured path |
| A start fails with `SECURITY_CONTROL_FAILURE` | the message names the control | the jailer did not establish it; never worked around by configuration |
| Events have a gap | `events_dropped` | the telemetry sink failed; list to resynchronise |

Useful commands: `acf-host doctor --json`, `acf-host journal verify`, `RUST_LOG=debug`, `ACF_LOG_FORMAT=json`.

---

## 4. Fourth pass — what it optimises and how it should evolve

### 4.1 The optimisation target

In order: **containment under failure**, then **truthfulness of every answer**, then **simplicity of the
privileged code**, then throughput. Consequences you will meet in review:

* An interrupted create is thrown away rather than completed. Lost work is cheaper than authority that outlives
  its request.
* A sandbox whose state is in doubt stops accepting work and keeps its lease. Capacity is cheaper than a runtime
  nobody accounts for.
* Every commit is synchronous and serialised. One host's operation rate does not justify a second critical
  section.
* There is one binary and one store per host. Coordination between hosts belongs to the control plane.

### 4.2 The view from an agent platform

The callers are agents and the systems that run them. What that implies for this layer:

* **Untrusted code is the normal case.** The guest is hostile by assumption: its frames are bounded, its
  statements labelled, its deadline backed by the host's own.
* **Retries are constant.** Agents and orchestrators retry. Caller-chosen operation ids, the fingerprint and the
  `retry` flag make a retry a lookup, never a second attempt.
* **Outcomes must be honest enough to plan on.** `effect` tells a planner whether a new operation is safe;
  `UNKNOWN` tells it that it is not.
* **Egress is the main exfiltration path.** Mode `none` is the default worth keeping; `allowlist` binds names to
  resolver answers so that a name entry cannot be turned into access to an arbitrary address.
* **Snapshots are how agents branch.** A restore is a new generation, and a restored guest can share random state
  with its sibling; the result says so.

### 4.3 Evolution

| Direction | What is reserved today | What it will cost |
|---|---|---|
| Decisions signed by a policy authority | the `authority` field, refused today | verification in `authority/`, a key in trusted configuration, binding to operation id and fingerprint |
| Output while a command runs | `incremental_output`, declared false | a streaming path in the guest protocol and bounded buffering in the core |
| Secret delivery | the provider port and the bookkeeping | a delivery mechanism in the backend that never writes material to disk |
| File transfer | nothing on the host | a guest-protocol extension; the host must still never parse a guest filesystem |
| A second backend | the port, the capability profile and the conformance suite | the backend, its controls and plumbing, and a full run of the suites |
| Several hosts | `host_id`, lineage, cursors | nothing here: placement and quotas are the control plane's |

### 4.4 What would change the design

* **Evidence that the single critical section limits a real workload** would justify per-sandbox commit streams,
  at the price of re-proving admission atomicity.
* **A requirement to continue interrupted creates** would require durable authority for the continuation, which
  is what a signed decision would provide.
* **A VMM with a stable machine-readable API contract** would retire the transcribed models.
* **A measured need for memory deduplication between sandboxes** conflicts with the isolation profile and would be
  a contract change, not a tuning change.

### 4.5 What to remember

The design gives up throughput, convenience and some availability of *granting* to make *containment* and
*truthfulness* unconditional. When a change trades in the other direction, it needs a reason of the same weight.

---

## 5. Exercises

1. Kill the core between the launch of a VMM and the commit that records `READY`. Predict the generation's state
   after the next start, then find the row in `decide_inherited` and the case in `suites/rec.rs`.
2. Two callers send `sandbox.create` for the last slot. Show, from `begin` and `reserve_sandbox`, why exactly one
   is admitted.
3. A caller's response is lost after `exec.run` succeeded. Write the request it should send next and say what the
   host answers, and what it answers if the operation record has been removed by retention.
4. Remove the `commit_for` check from `step` in a scratch branch and find which tests fail and why.
5. A guest sends a 2 GiB frame. Find the three places that stop it.
6. An operator restores yesterday's backup of the store. Trace what the host does at startup and what the operator
   must do.
7. Add a host parameter `operations.max_open_per_peer`. List every file you touch before writing any code.

## 6. Glossary

| Term | Meaning |
|---|---|
| activation | one start of the core on a store; has an epoch |
| containment | removing privilege: stop, destroy, delete, cancel, fail |
| effect | whether an ended operation's intent is in place: applied, not applied, may be applied |
| generation | one runtime incarnation of a sandbox; the fencing token |
| granting | creating privilege: create, start, exec, snapshot, restore |
| inherited operation | a non-terminal operation whose epoch is lower than the current one |
| lease | the capacity and identifiers a generation holds until it is destroyed |
| lineage | the identity of a store; qualifies sequences, revisions and cursors |
| owner scope | an opaque label a peer attaches to what it creates |
| posture | the isolation controls of a running VMM, as observed |
| quarantine | a durable condition: the host will not touch the generation until an operator releases it |
| residue | what a failed or cancelled operation may have left behind |
| revision | the commit sequence of a record's last change |
| tags | `(peer_id, owner_scope)` on every caller-visible record |
