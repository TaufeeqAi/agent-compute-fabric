# Study guide — thinking about the Phase 1 codebase

*Written as a senior staff engineer and principal AI architect would brief the next person who has to change this code
without breaking its promises. [ARCHITECTURE.md](ARCHITECTURE.md) says what the code **is**; this guide says how to **read**
it, **reason** about it and **change** it. Every layer answers the same seven questions: what is it, why does it exist,
how does it work, what depends on it, what can fail, what should I remember, how do I compress it.*

## How to use this guide

Four passes. Each answers one question and ends where the next begins. Do not skip ahead: detail without the map is
how people "fix" an invariant into a bug.

| Pass | Question | You are done when you can… | Time |
|---|---|---|---|
| **Junior** | What does the code do? | trace `acf-local run` from the keyboard into the guest and back | 1 h |
| **Senior** | How is the system structured? | name the boundaries, say who owns each invariant and which test pins it | half a day |
| **Staff** | Where are the leverage, the risks and the seams? | change an operation, a backend or a pin safely, and say what to review | 1–2 days |
| **Principal** | What is it optimising, and how should it evolve? | argue what Phase 2 must *not* change, and what would make you reverse a decision | ongoing |

---

## 0. The whole system on one page

```text
 acf-local (Python)  ──►  /run/acf/host-agent.sock  ──►  acf-host (Rust, root)  ──►  jailer ─► firecracker ─► microVM
   asks, prints            SO_PEERCRED identity            decides, records,                                    │
   never enforces          u32-BE + JSON "acf.host/1"      verifies, recovers                  vsock :5252 ◄────┘
                                                                  │                       acf-guest-agent (uid 1000 workloads)
                                                       journal.wal (intent first)
```

Everything is machinery for five promises. They are *design* promises; the second column says how far each is proven today.

| # | Promise | Proven without KVM | Proven only on a KVM host (**not yet run**) |
|---|---|---|---|
| 1 | **Nothing escapes.** A guest cannot reach the host, the network or another sandbox. | admission, trusted-file, network-verdict and posture parsers; guest agent protocol | `tests/isolation/{network,process,filesystem,host_control}` |
| 2 | **Nothing is lost.** Every mutation is recorded *before* it happens. | journal tests (torn tail, corruption, atomic commit); five crash points | `tests/integration/recovery` |
| 3 | **Nothing is guessed.** After a crash the host acts only on what it can prove it owns; ambiguity is `UNKNOWN`. | the pure `classify` table, one test per row | real `kill -9` of a real host agent |
| 4 | **Nothing is unbounded.** CPU, memory, pids, disk, output and time all have enforced ceilings. | capacity arithmetic, limits, `enforce_bounds`, guest exec tests | `tests/integration/execution` (cgroup values, OOM) |
| 5 | **Nothing is unexplained.** Every run returns evidence: what ran, under which policy, in which generation, with what result. | contract tests, CLI contract tests, generated schemas | evidence on a real guest |

**Mental model:** a *court clerk in front of a vault*. The clerk writes the intent in a ledger **before** touching
anything; the vault has no door to the street; after a power cut the clerk reads the ledger and tidies only what the ledger
proves is theirs. If the ledger is ambiguous, the clerk says "unknown" instead of guessing.

---

## 1. Junior pass — what the code does

### 1.1 The seven questions, for the whole system

| Question | Answer |
|---|---|
| **What is it?** | Three programs: `acf-local` (Python CLI), `acf-host` (privileged Rust daemon), `acf-guest-agent` (static Rust binary inside each VM). Together: create, run a command in, snapshot, restore and destroy a Firecracker microVM, and return evidence. |
| **Why does it exist?** | Code written by an AI agent is untrusted *and* often simply wrong. It must run somewhere that cannot hurt the host or other runs, and the operator must be able to prove afterwards exactly what happened, even across a crash. |
| **How does it work?** | A request becomes a durable *operation*: validate, record, declare the next step, do it, record the result. Crashes are resolved at start by a pure decision table. |
| **What depends on it?** | Phase 2 (agent runtime, tool gateway) consumes `Operation`, `SandboxBackend`, `ResourcePolicy`, `SnapshotRef` and the evidence types, never Firecracker details. |
| **What can fail?** | The host agent (restart → recovery), the VMM (reconcile), the guest (hostile or lying → bounded), the journal (corruption → read-only quarantine), the disk, the operator (mis-owned policy → refused at load). |
| **What should I remember?** | Python never enforces policy. The kernel enforces; the host *verifies by observation* that enforcement took hold, and fails closed if not. |
| **Compression** | Ledger first, act second, verify third, repair by table. |

### 1.2 Life of `acf-local run`

`run` is four operations composed by the client (`apps/cli/src/acf_cli/runner.py`): **create → start → exec → destroy**
(destroy is skipped with `--keep`). Follow one of them (`exec`) end to end:

| # | Step | Where |
|---|---|---|
| 1 | The CLI splits `--command` into argv (a shell only with `--shell`), builds the request, and frames it: `u32` big-endian length + JSON envelope `{protocol:"acf.host/1", request_id, operation_id, retry, body:{method, params}}`. | `apps/cli/src/acf_cli/{run,client,framing}.py` |
| 2 | The host accepts the connection and reads the caller's uid/gid from the kernel (`SO_PEERCRED`). A caller that is not allowed gets one `AUTHORIZATION` frame and is closed. | `server/ipc.rs`, `admission/auth.rs` |
| 3 | The strict `Request` enum decodes the body (unknown fields are errors). Read-only methods answer directly; everything else (`Request::is_mutating`) becomes an operation. | `protocol/request.rs`, `server/dispatch.rs::dispatch` |
| 4 | Policy is checked (ceilings, capabilities, allowed values). A refusal here leaves **no record and no reservation**. | `admission/policy.rs` |
| 5 | `begin` appends one durable record (op id, request fingerprint, caller, policy digest). For `create` and `restore` the capacity check and the reservation commit in that same atomic append, so a capacity refusal also leaves nothing behind. `step` then declares the next privileged step *before* it runs. | `lifecycle/ops.rs::{begin, step}`, `lifecycle/capacity.rs` |
| 6 | The backend acts. For `exec`: the host talks vsock to the guest agent, which runs the command as uid 1000 in its own cgroup with an empty environment, caps on output and a deadline. | `firecracker/backend.rs`, `guest/client.rs`, `guest-agent/src/exec.rs` |
| 7 | The host re-imposes the caps on what the guest claims (`guest/client.rs::enforce_bounds`), because the guest is the adversary. | `guest/client.rs` |
| 8 | `finish` writes the terminal record: status, result, evidence, failure class, side-effect flag. Then the response is sent. | `lifecycle/ops.rs::finish` |
| 9 | The CLI prints evidence and maps the outcome to an exit code (0 ok, 1 workload failed, 3 refused, 4 failed, **5 unknown**, …). | `apps/cli/src/acf_cli/{render,errors}.py` |

`create` ends in `PROVISIONING` (no VMM yet); `start` is what boots the VM and brings it to `READY`; only an idle sandbox
(`READY` or `COMPLETED`) accepts `exec` or a snapshot.

### 1.3 A ninety-minute reading order

1. [ARCHITECTURE.md §1–§2](ARCHITECTURE.md) (15 min) — the map.
2. `execution/host-agent/src/domain/{lifecycle,operation}.rs` — the vocabulary; the lifecycle table is one `matches!`.
3. `protocol/request.rs` and `server/dispatch.rs` — the whole API surface in two files.
4. `lifecycle/ops.rs` — `begin`/`step`/`finish`, the shape every mutation shares.
5. `operation/journal.rs` — `commit_with`, then the tests at the bottom of the file.
6. `recovery/classify.rs` — one pure function; read the table in [ARCHITECTURE §10](ARCHITECTURE.md) beside it.
7. `backend.rs` — the `SandboxBackend` trait; then `testing/fake_backend.rs` (a complete second implementation).
8. `guest-agent/src/{main,server,exec}.rs` — the only code that runs inside the untrusted VM.
9. `testing/contract_tests.rs`, one test at a time. The test *names* are the specification.

### 1.4 What a Junior should remember

* A name is never an authority: destructive requests carry ids and `expected_generation`.
* `UNKNOWN` is a real answer. Exit code 5 means *observe, do not re-run*.
* If a test is skipped, read why: the skip reason is the honest list of what has not been proven.

---

## 2. Senior pass — how the system is structured

### 2.1 Boundaries and who owns what

The spec numbers eleven boundaries (BND-01…11); the table in [ARCHITECTURE §3](ARCHITECTURE.md) maps each to files. The
shape that matters is the dependency direction:

```text
CLI ─► protocol ─► dispatch ─► lifecycle ─► { capacity · filesystem · network · snapshot } ─► SandboxBackend ─► Firecracker/Linux
                                   ▲                                                                │
                        recovery (classify ─► actuate) ◄──────── journal ◄──── LaunchSink ◄─────────┘
```

`domain/` depends on nothing but ids and errors. A backend never calls up into the lifecycle: it is handed a
`LaunchSink` so the host can journal "a VMM now exists, and here is its identity" the instant it exists, before the
backend does anything else. That one inversion is what lets recovery find every process the system ever started.

### 2.2 The house style: patterns that recur

If you learn these eleven, you can predict how any new code here should look.

| Pattern | Where | Why | Pinned by |
|---|---|---|---|
| **Intent before action** (write-ahead) | `lifecycle/ops.rs` | a crash can never erase the fact that something was about to happen | `recovery_tests.rs` (five crash points) |
| **Atomic check-and-append** | `Journal::commit_with` | the capacity check and the reservation it justifies commit together, so admission cannot race | `journal.rs` tests, `capacity.rs` tests |
| **Pure core, imperative shell** | `classify`, lifecycle table, `reserve_*`, `fingerprint`, network verdict, `SecurityPosture::violations` | every row of every decision is a unit test, no VM needed | the `#[cfg(test)]` modules beside each |
| **Capability-confined paths** | `filesystem/*` over `cap-std`; validated id newtypes in `ids.rs` | a path is derived from a validated id inside a directory handle; persisted paths are never trusted | `layout`/`generation` tests |
| **Strict wire types, generated schemas** | `protocol/*`, `schema.rs`, `schemas/*.json` | the Rust types are the single source of truth; drift fails CI | `make check-schemas` |
| **Verify, don't assume** | posture read-back from `/proc`, image hashed while copied, snapshot re-hashed at restore, restore oracle | configuration says what was *asked*; observation says what *is* | `identity.rs`, `hashcopy.rs`, snapshot tests |
| **Distrust the guest** | `enforce_bounds`; the guest may only *add* evidence of a violation | the workload controls the guest agent's process tree | `enforce_bounds_distrusts_a_lying_guest` |
| **Fail closed on security evidence, degrade on telemetry** | `network/verify.rs`, `telemetry/*` | missing proof of isolation is a refusal; a dead log file is an inconvenience | `a_dead_log_file_degrades_telemetry_without_failing_the_caller` |
| **Backend behind a trait + capability profile** | `backend.rs` | Phase 2 can add a backend without touching lifecycle, journal or recovery; unsupported is a stable `UNSUPPORTED` | `fake_backend.rs`, `fc_backend_tests.rs` |
| **Fault injection at the seams** | `fault!` in `lifecycle/mod.rs`, `testing/fault.rs` | crash tests that do not depend on timing | `recovery_tests.rs` |
| **The gate is the Makefile** | `Makefile`, `tests/scripts/test_makefile_and_ci.py` | CI, docs and a laptop run the same commands; a doc naming a missing target fails a test | ADR-021 |

Where the ideas come from (lineage, not copied code): write-ahead logging from database engines; *crash-only software*
(a process that can only stop by crashing has only one recovery path to get right) for `acf-init` and the host;
capability-based file access from `cap-std`; Firecracker's own jailer model (chroot, per-VM uid, PID and network
namespaces, seccomp, cgroups) for confinement; `SO_PEERCRED` as used by local daemons such as the Docker and systemd
sockets for identity.

### 2.3 Two flows that explain almost everything

**The write-ahead flow (happy path).**

```text
decode ─► authenticate ─► authorise + admit ─► BEGIN ─► STEP(name) ─► BACKEND ─► FINISH ─► respond
refusals stop here, leaving nothing ─────────▲        ▲ durable      ▲ mutation  ▲ durable
```

**The crash flow.** After a crash, recovery reads the journal. A non-terminal operation plus its last declared step tells
`classify` what *could* have happened; observation (does a directory exist? is there a VMM, and is it provably ours?)
tells it what *did*. The five injectable crash points show what survives each:

| Crash point (`FaultPoint`) | What the disk says | Outcome |
|---|---|---|
| `BeforeJournalWrite` | nothing | no trace; the same `operation_id` is still usable |
| `AfterJournalBeforeMutation` | op recorded, nothing done | abandoned untouched or retried idempotently |
| `BeforeBackendStep` | step declared, backend not yet called | classified by observation |
| `AfterBackendMutationBeforeCommit` | **a mutation may have happened, unrecorded** | the hard case: observation decides; `exec` becomes `UNKNOWN`, never re-run |
| `AfterTerminalCommitBeforeResponse` | result persisted, response lost | `retry: true` returns the stored result; nothing re-executes |

### 2.4 The invariants

Ten statements that must stay true. A change that weakens one needs a decision record ([DECISIONS.md](DECISIONS.md)), not
just a passing build.

| # | Invariant | Enforced by | Pinned by |
|---|---|---|---|
| 1 | A refused request leaves no record and reserves nothing. | `dispatch` prechecks | `policy_denials_happen_before_any_record_or_side_effect` |
| 2 | Same operation id + same fingerprint ⇒ the original result; different fingerprint ⇒ `CONFLICT`; `retry` of an unseen id ⇒ `NOT_FOUND`. | `operation/fingerprint.rs`, `begin` | contract tests |
| 3 | Admission and reservation commit atomically; a failed generation keeps its reservation. | `commit_with`, `capacity.rs` | `journal.rs`, `capacity.rs` tests |
| 4 | A stale generation reference never acts on the current incarnation. | `expected_generation` | `stale_generation_references_never_act_on_the_current_incarnation` |
| 5 | Only a process whose identity (pid + start ticks + boot id) matches is ever signalled. | `process/identity.rs`, recovery `Foreign` | `identity.rs` tests |
| 6 | If ownership of a directory cannot be proven, nothing is deleted: quarantine. | first rule of `classify` | `classify` tests |
| 7 | `network=none` holds in three independent layers; the guest can only add violations. | Firecracker config, empty netns, guest probes | `network/verify.rs` tests; `isolation/network` (K) |
| 8 | The digest describes the bytes that will boot. | `filesystem/hashcopy.rs` | `hashcopy` tests |
| 9 | A restore is accepted only if the oracle reproduces the baseline (and a reboot is detected). | `snapshot/*`, `lifecycle/snapshots.rs` | `a_tampered_snapshot_is_refused_before_any_vmm_is_launched` |
| 10 | Telemetry is never authority; security evidence fails closed. | `telemetry/*`, `network/verify.rs` | `a_dead_log_file_degrades_telemetry_without_failing_the_caller` |

### 2.5 What a Senior should remember

* The seams are real: `SandboxBackend`, `protocol/` (transport-neutral), `Journal` (records are the contract, storage is not).
* The fake backend is a full second implementation. When the real one and the fake disagree, the fake is wrong until proven otherwise.
* "Where is this enforced, and which test fails if I remove it?" is the question to ask of every line of policy code.

---

## 3. Staff pass — leverage, risks and seams

### 3.1 Where a small change has a large effect

| Leverage point | Why it is leveraged | The trap |
|---|---|---|
| `recovery/classify.rs` | one pure function; one row is one crash story; `match` has no catch-all arm, so a new `OperationType` does not compile until it is classified | "simplifying" two rows into one `RetryIdempotent` — `exec` must never retry |
| `Journal::commit_with` | the single place correctness under concurrency is decided | doing the check outside the closure "for readability" reintroduces the race |
| `SandboxBackend` + `testing/fake_backend.rs` | everything above the trait is testable without KVM; Phase 2 backends plug in here | letting Firecracker types leak up through the trait |
| The Makefile gate and its tests-about-tests | docs, CI and local runs cannot drift silently | adding a CI step that is not a make target |
| The black-box driver (`tests/helpers/acf_driver.py`) | the same assertions run against the in-memory host today and a real host tomorrow | giving it white-box shortcuts that only work in-memory |

### 3.2 Seams: where to cut when requirements change

| Seam | Behind it | To extend | Must not change |
|---|---|---|---|
| `SandboxBackend` | Firecracker, jailer, vsock | implement the trait and a `CapabilityProfile`; unsupported ops return `UNSUPPORTED` | lifecycle, journal, recovery semantics |
| `server/` | Unix socket only | add a transport (remote control plane) *with* mTLS and tenancy | `protocol/` types; the idempotency rules |
| `Journal` | one WAL file | swap storage if records stay the contract | CRC/atomic-batch semantics; quarantine behaviour |
| Network modes | `network=none` only | policy entry + `NetworkEvidence` verdict function + its own adversarial suite **before** it is listed in `capabilities.network_modes` | the guest-can-only-add-violations rule |
| Policy | one YAML, immutable per operation | add capabilities and ceilings | the per-operation policy digest |

### 3.3 Risk register

Likelihood/impact are judgement, not measurement. *Detect* says what would tell you.

| ID | Risk | L | I | Detect | Mitigation today | Class |
|---|---|---|---|---|---|---|
| R1 | KVM-only behaviour (seccomp, vsock, cgroup values, `ip`, kmsg) is wrong in some way never exercised | **high** | high | first `make integration` run | the suites exist and are type-checked; fake + real guest agent cover the logic | **existential** until run |
| R2 | First real image built from unverified inputs (digests `UNSET`) | med | high | `make check-pins-release` fails by design | installer and builder refuse unpinned inputs | cheap to mitigate |
| R3 | Root daemon: a bug in the jailer setup, per-VM uid or trusted-file loader is the whole blast radius | low | **very high** | `doctor`, posture read-back, isolation suites | defence in depth; `unsafe` forbidden in the host; moderate systemd hardening | high-leverage |
| R4 | Corrupt journal: read-only quarantine with no repair tool | low | med | `host info` reports it | documented move-aside procedure | accepted (never guess) |
| R5 | Quarantined sandbox keeps its reservation and has no release command | med | low–med | capacity shrinks; `RECOVERY_QUARANTINED` | manual procedure in OPERATIONS §7.1 | accepted; Phase 2 work |
| R6 | Guest agent version recorded, not enforced against the manifest | med | med | none automatic | documented known gap | cheap to mitigate |
| R7 | Snapshots hold guest memory (secrets) | med | high | none automatic | 0700 root state, `doctor` checks the mode | accepted; document in policy |
| R8 | Dependency drift (a major bump of `serde-saphyr` landed during development) | med | low–med | re-resolution log in DEPENDENCY_PROVENANCE | locks + `--locked` + full gate | cheap to mitigate |
| R9 | Fake backend and real backend diverge | med | med | KVM suites vs control-plane suites disagree | shared contract tests; real guest agent in the fake path | high-leverage |
| R10 | Supply-chain scans never run (advisory databases unreachable) | med | med | `audit.yml` | scheduled workflow | cheap to mitigate |
| R11 | Product friction: no stdin, no TTY, no file transfer, single-flight exec | high | low (Phase 1) | first real agent integration | deliberate; evidence quality first | accepted |

### 3.4 Change recipes

**Add an operation type.** Let the compiler lead: (1) `OperationType` in `domain/operation.rs`; (2) a `Request` variant in
`protocol/request.rs` and the arm in `server/dispatch.rs`; (3) the lifecycle implementation using `begin/step/finish`;
(4) a row in `classify` — it will not compile without one; (5) the CLI command; (6) regenerate schemas with
`make schemas` (CI runs `make check-schemas`); (7) a contract test *and* a recovery test per crash point that applies;
(8) update [CONTRACT_COMPLIANCE.md](CONTRACT_COMPLIANCE.md) and the tables in [ARCHITECTURE.md](ARCHITECTURE.md).

**Add a failure class.** `FailureClass` in `error.rs`, its `side_effect` default, its CLI exit-code mapping, the table in
ARCHITECTURE §11, and a test that a refusal of this class creates no operation record.

**Add a network mode.** Write the adversarial suite first (it must be able to fail), then the verdict function, then the
policy entry, then — last — the capability listing. The three-layer rule applies: a configuration layer, a topology layer and
a guest-side corroboration, with the guest unable to clear a violation.

**Bump Firecracker.** Change `scripts/firecracker.lock`, `config/host.example.yaml` and the guest images **together**
(`make check-pins` fails if they disagree). Existing snapshots become incompatible by design. Re-run the KVM suites.

**Bump a dependency.** Update the manifest floor and the lock, run the full gate (`make ci`), and record it in
[DEPENDENCY_PROVENANCE.md](DEPENDENCY_PROVENANCE.md). A *major* bump of a parser that reads config or policy deserves a
test that feeds it the shipped files (`shipped_files_tests.rs` already does).

**Change the on-disk journal.** The framing and the records are the contract. Keep a reader for the old form, and add a test
whose fixture is the old bytes.

### 3.5 Twelve questions for a code review here

1. What is recorded *before* this mutation, and what does recovery do if we crash right after it?
2. Could this be retried? If it could have partly happened, does the code say `UNKNOWN`?
3. Where does this value come from — the kernel, the journal, or the caller? Is it trusted accordingly?
4. Does a refusal path leave a record or a reservation behind?
5. Is any path built from something other than a validated id inside a directory handle?
6. Does the host signal or delete anything it has not proven is its own?
7. If the guest lies here, what is the worst thing the host believes?
8. Which test fails if this line is deleted? Is that test in the no-KVM gate or only on KVM?
9. Is a security fact being *asked for* (config) where it should be *observed* (`/proc`, the kernel)?
10. Does this widen policy (a ceiling, a capability, a network mode)? Where is the decision record?
11. Does the generated schema change? Was it regenerated, not edited?
12. What does the operator see when this fails, and can they act without reading the source?

Question 8 earned its place the hard way. `read_trusted` refuses a policy file whose ancestor directories are group- or
world-writable, and its unit tests asserted only that the refusal had the security class. Those tests built their files
under the temp directory, and `/tmp` is itself world-writable, so every one of them passed because `/tmp` was refused,
whatever the line under test did. The flaw showed only when a gate ran with a different `$TMPDIR` (2026-10-19, `make ci`).
The repair has three parts, and the pattern generalises: the walk takes a private `start` directory so a test judges
directories it built; each test asserts *which* check spoke (a message fragment, not just an error class); and a mutation
run (switch a check off, expect red) proved the tests bite. A refusal test that does not name its reason is a test of the
environment.

### 3.6 Debugging playbook

| Symptom | Likely meaning | Look at |
|---|---|---|
| `acf-host serve` refuses to start | `doctor` found a FAIL (kernel, kvm, cgroup, uid range, state root, unshare, firecracker, policy) | `acf-host doctor` |
| Start fails with a `SECURITY` error | the VMM posture or the `network=none` verdict showed a violation | `acf-local operation get <id>`, then the network evidence |
| CLI exit 5 | outcome unknown (lost response, timeout, crash mid-exec) | `operation get`, `sandbox inspect`; never re-run blindly |
| Sandbox sits in `PROVISIONING` | normal after `create`; `start` boots it | `sandbox start` |
| `ADMISSION_REJECTED` | above a policy ceiling or the capacity envelope | `host info`, `host metrics`, `/etc/acf/policy.yaml` |
| `RECOVERY_QUARANTINED` | ownership of a generation could not be proven | [OPERATIONS §7.1](OPERATIONS.md) |
| Host is read-only | journal corruption mid-file | [OPERATIONS §7.2](OPERATIONS.md) |
| A test is *skipped* | a missing capability (KVM, root, the fake host binary) | the skip reason; `ACF_INTEGRATION=1` turns skips into failures |

---

## 4. Principal pass — what the system optimises, and how it should evolve

### 4.1 The optimisation target

**Evidence integrity under failure**, bought with generality and speed. The system is willing to refuse, to be slow
to start, to forbid stdin and file transfer and a second network mode, in exchange for being able to say, for every run,
*what happened* and *what is certain*. The decisions that encode this, with the way back (the full table is in
[DECISIONS.md](DECISIONS.md)):

| Chosen | Over | Cost | Way back |
|---|---|---|---|
| Our own narrow WAL | an embedded database | we own corruption handling | reversible behind `Journal`; the records are the contract |
| `UNKNOWN` as a first-class status | rounding to success/failure | callers must handle a third answer | expensive: recovery semantics depend on it |
| Verify by observation | trust the jailer's configuration | extra reads at every start | reversible |
| Doubt means quarantine | best-effort cleanup | no release command in Phase 1 | reversible |
| Policy immutable per operation | live policy edits | reload affects only future operations | expensive: evidence cites the digest |
| One privileged process | a multi-process split | a larger root blast radius | reversible; trait seams already exist |
| Python client that never enforces | a smart client | two codebases, a schema step | expensive: the wire format |

### 4.2 The AI-architecture view

*Facts* are what the code does; *hypotheses* are what it should enable and have not yet been measured.

**Where it sits.** In an agent system this is the **actuator** for the code-execution tool: the one component that must
stay deterministic and auditable when everything upstream is probabilistic.

**Principles it encodes (facts):**

1. **Authority never flows from model output.** Policy and enforcement live outside the model and outside the client; the
   caller's identity comes from the kernel. A prompt-injected agent can ask for anything; it can be *granted* only what policy allows.
2. **Assume the code is wrong before assuming it is malicious.** Most agent-written code is buggy, not hostile. Ceilings,
   process-tree kills, output caps and deadlines make the common failure (a runaway loop) cheap, and the same mechanisms
   contain the rare hostile one.
3. **Agents retry; the protocol makes retries safe.** Operation ids, request fingerprints, `retry`, and `UNKNOWN`
   exist so that a timeout never becomes a duplicated side effect.
4. **Evidence is the interface between probabilistic and deterministic parts.** A structured run record (policy digest,
   generation, limits, truncation flags, containment mode) is what audits, evals and an agent's own reflection should consume.
5. **Environment reset is a checked operation.** Snapshot/restore with the baseline oracle turns "reset the world" into
   something the system can *prove* happened.

**Hypotheses, not yet evidence** (*Evidence insufficient — decision requires validation*):

* Restore is fast enough to serve as the reset primitive for evaluation loops. **Falsifier:** a first KVM measurement of
  restore latency that dominates the run time. **Fallback:** pooled warm VMs.
* Reservation-based capacity (reserve the full request, not observed use) is the right admission model for bursty agent
  workloads. **Falsifier:** utilisation far below reservation in the first real workload.
* The three-layer `network=none` check will not disagree with itself on real hardware. **Falsifier:** any run where one
  layer says "isolated" and another does not; the response is to find which layer is wrong, not to loosen the check.

**What Phase 2 must not change:** the operation protocol and its idempotency rules; "Python never enforces"; policy
immutability per operation; `UNKNOWN`; the guest-can-only-add-violations rule; telemetry-is-not-authority.

### 4.3 Evolution

| Phase 2 capability | Rides on | Precondition | Start when |
|---|---|---|---|
| Egress modes (proxy, allowlist) | policy + `NetworkEvidence` verdict | a new adversarial suite that can fail | Phase 1 isolation suites are green on real hardware |
| Remote control plane | `protocol/` + a new transport | mTLS, tenancy, per-tenant policy | local semantics proven on KVM |
| Second backend (e.g. another VMM) | `SandboxBackend` + `CapabilityProfile` | contract tests run against it unchanged | a concrete need, not before (Gate H) |
| Sessions (stdin/TTY, long-lived shells) | exec model | an evidence story for interleaved I/O | a product need that single-flight exec cannot meet |
| File transfer | filesystem capability model | digest-verified, size-capped, policy-gated | same |
| Multi-host scheduling | envelope + operation identity | a placement owner and a shared state story | one host is demonstrably the limit |

### 4.4 What would change my mind

| If… | …then reconsider |
|---|---|
| operators meet quarantine more than rarely | build the supervised release command before anything else |
| restore latency makes snapshots useless as a reset | pooled warm VMs, or a different reset primitive |
| the fake and the real backend disagree more than once | spend on contract-test parity before any new feature |
| a dependency in the config/policy path keeps shipping majors | vendor the parsing behind a thin trait |
| the first KVM run fails mostly in probes, not in isolation | treat the probes as the product risk and harden them first |

### 4.5 What a Principal should remember

* This phase's deliverable is **trust in the failure path**, not features. Every shortcut that makes the happy path
  simpler by blurring a crash outcome spends that trust.
* Reversibility is the budget. Wire format, recovery semantics, policy digests and image identity are expensive to
  reverse; spend deliberately. Everything else here is meant to be refactorable.

---

## 5. Reading plan and exercises

### 5.1 Three paths

| Path | Do this |
|---|---|
| **90 minutes** | §1.3 reading order; run `make e2e`, then read two tests in `apps/cli/tests/test_e2e.py` against the CLI code they drive. |
| **One day** | The above, plus [ARCHITECTURE.md](ARCHITECTURE.md) end to end, `recovery_tests.rs`, `fc_backend_tests.rs`, and the spec's §27 beside [CONTRACT_COMPLIANCE.md](CONTRACT_COMPLIANCE.md). |
| **One week** | Everything, then do exercises 3, 5 and 8. Finish by writing the decision memo in exercise 10. |

### 5.2 Exercises

| # | Exercise | What it teaches | Start at |
|---|---|---|---|
| 1 | List every use of `Request::is_mutating`. Why is `operation_cancel` mutating? | what counts as a mutation, and why cancel needs a record | `protocol/request.rs` |
| 2 | Arm `AfterBackendMutationBeforeCommit` during `snapshot_create`, then write the recovery test. | the crash-test idiom: arm, crash, recover, assert | `testing/recovery_tests.rs` |
| 3 | In a scratch copy, change `classify` so `exec` retries. Which tests fail? Are there enough? | mutation testing by hand; the value of the table | `recovery/classify.rs` |
| 4 | Move the capacity check outside `commit_with`. Write the test that would have caught it. | why atomicity is a property you must be able to test | `lifecycle/capacity.rs` |
| 5 | Add a lying-guest case to `enforce_bounds` (a result that under-reports its own truncation). | distrust as a design rule | `guest/client.rs` |
| 6 | Add a check to `acf-host doctor` and make `serve` fail on it. | ADR-018: `serve` enforces what `doctor` reports | `doctor.rs` |
| 7 | Write an isolation test, then run it under `ACF_CONTROL_PLANE=1` and under `ACF_INTEGRATION=1`. | the three modes of one suite | `tests/helpers/acf_integration.py` |
| 8 | Read `network/verify.rs`; construct an input where the guest *claims* isolation but the topology disagrees. | why the guest can only add violations | `network/verify.rs` |
| 9 | Add a new field to a response type; regenerate schemas; watch `make check-schemas` fail until you do. | schemas as a generated contract | `schema.rs` |
| 10 | Write a decision memo (context, options, trade-offs, reversibility, what would change the decision) for a *supervised quarantine release* command. | the Phase 2 backlog item with the most safety content | [DECISIONS.md](DECISIONS.md), OPERATIONS §7.1 |

### 5.3 Glossary

| Term | Meaning |
|---|---|
| **Operation** | the durable record of one mutating request, from `BEGIN` to a terminal status |
| **Fingerprint** | canonical-JSON sha256 of a request; what makes a retry recognisable |
| **Generation** | one incarnation of a sandbox; ids name a lineage, generations are never reused |
| **Reservation** | capacity set aside at admission and held until the generation is destroyed |
| **Evidence** | the structured record of a run: result, limits, policy digest, containment, truncation |
| **Oracle** | the baseline probe (`boot_id` + canary digest + agent version) a restore must reproduce |
| **Quarantine** | the state of a generation or journal the host refuses to touch because it cannot prove ownership |
| **Posture** | the VMM's observed confinement (uid, seccomp, `NoNewPrivs`, capabilities, chroot) read from `/proc` |
| **K / R / C / P / T** | legend in [CONTRACT_COMPLIANCE.md](CONTRACT_COMPLIANCE.md): which kind of evidence proves a clause |

---

### Compressed summary

Phase 1 is a ledger in front of a vault. The host writes intent first, lets the kernel confine, *checks* that it did, and
after a crash a pure table decides what is safe to adopt, clean, quarantine or admit is unknown. Everything else — the
trait seams, the fake backend, the schemas, the make gate — exists to keep that failure path testable.

### Three insights

1. **The failure path is the product.** Most of the code and almost all of the tests exist for the moments after something
   went wrong; the happy path is thin on purpose.
2. **Verification beats configuration.** Reading `/proc` back, re-hashing images and snapshots, and re-imposing caps on guest
   output turn "we asked for it" into "we saw it".
3. **Pure cores buy confidence without hardware.** The decision table, admission arithmetic, fingerprint, network verdict
   and posture parser carry the risky logic and run anywhere; the VM is the thin, last-proven layer.

### Three risks

1. **KVM-only behaviour is unproven.** Seccomp, vsock, cgroup values and the guest's `ip`/kmsg use have never run on real
   hardware; the first run will find something.
2. **Unverified inputs on first build.** Digests are `UNSET`; an operator who forces past that builds from unchecked bytes.
3. **A root daemon's blast radius.** The controls that matter are the jailer setup, the per-VM uid and the trusted-file
   loader; a bug in any of them is the whole attack surface.

### Next best question

*On a real KVM host, which test fails first — and is it a wrong assumption in a probe, or a real isolation gap?* Run
`make integration` per [OPERATIONS.md](OPERATIONS.md), read the first failure before the rest, and write down which
promise in §0 it touches.
