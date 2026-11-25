# Decision log

Decisions the execution-plane contract (version 1.2.0) leaves to the implementation, with the reasoning and the way
back. Where the contract itself decides, this log does not repeat it; [CONTRACT_COMPLIANCE.md](CONTRACT_COMPLIANCE.md)
maps clauses to code and lists the places where a clause had to be read one way or another.

Reversibility: **reversible** (a refactor), **expensive** (touches a wire contract or an on-disk format),
**effectively irreversible** (cannot be undone once data exists). Every entry is *accepted*.

| ID | Decision | Reversibility |
|---|---|---|
| 001 | Rust privileged plane, Python reference client; the client never enforces | expensive |
| 002 | One binary, four roles, each its own process | reversible |
| 003 | The edge is stateless and the core validates everything again | reversible |
| 004 | Authority is enrolment, role, tags and the safety profile; no tenant concept on the host | expensive |
| 005 | One operation protocol; the reserved state is committed in BEGIN | expensive |
| 006 | Exclusivity is read from committed state; every write of an operation is fenced | expensive |
| 007 | A narrow journal of our own, with lineage, sequence, epoch and a reserve | reversible |
| 008 | One trusted-input rule for files and for executables | reversible |
| 009 | A failed mandatory check means `CONTAINMENT`, never exit | reversible |
| 010 | Admission is one commit with the reservation; a failed generation keeps its lease | expensive |
| 011 | Recovery is a pure table; a granting operation is never continued; doubt is quarantined | reversible |
| 012 | Lifetime is enforced by a separate process that needs only a directory of tickets | reversible |
| 013 | Posture is verified by observation, and re-verified by whoever holds the sandbox | reversible |
| 014 | Mode `none` is proven in three independent layers | reversible |
| 015 | Mode `allowlist`: a namespace with no route, one constant segment, an unprivileged relay | reversible |
| 016 | The backend port is semantic and declares its capabilities | reversible |
| 017 | Image identity is the hash of the manifest; files are hashed while they are copied | expensive |
| 018 | Full snapshots bound to the store; a restore is accepted only by an oracle | expensive |
| 019 | Execution: one at a time, an argument vector, no stdin, a host backstop | reversible |
| 020 | Secrets travel by reference; material cannot be serialised | reversible |
| 021 | Schemas are generated from the types; the contract's tables are transcribed and tested | reversible |
| 022 | Telemetry decides nothing | reversible |
| 023 | Tests are named after the catalog; a test that cannot run is ignored, never passed | reversible |
| 024 | The Firecracker pin moves only with a run on real KVM | reversible |
| 025 | Dependencies are verified at write time and locked | reversible |
| 026 | Rust 2024; `unsafe` forbidden except one audited block in the guest | reversible |
| 027 | Guest init is a POSIX-sh PID 1, crash-only | reversible |
| 028 | MMIO transport; Firecracker's default boot arguments plus an explicit `pci=off` | reversible |
| 029 | The cgroup parent is created by a oneshot unit, not by the core | reversible |
| 030 | Pins fail closed | reversible |
| 031 | The Makefile is the gate; KVM suites fail, never skip, when enabled | reversible |
| 032 | The source archive is reproducible, self-describing and read as untrusted | reversible |
| 033 | The VMM and the jailer are pinned by digest in the host configuration and hashed before every launch | reversible |

---

## ADR-001 — Rust privileged plane, Python reference client; the client never enforces
**Context.** A client that also checks limits creates two authorities that drift, and the client runs where the
caller runs, which is the wrong place for a decision.
**Decision.** `acf-local` builds requests, resolves names to ids through reads, renders answers and chooses exit
codes. Every allow, deny and legality check happens in `acf-host`. The wire contract is generated from the Rust types
and the client is tested against it.
**Consequences.** A client bug cannot widen authority, and a second client inherits all enforcement. Cost: two
toolchains and a schema step. **Reversibility:** expensive (the wire format), mitigated by the versioned protocol.

## ADR-002 — One binary, four roles, each its own process
**Context.** The contract requires that bytes from a peer and bytes from a guest's network traffic are parsed
without host-mutation capability, and that lifetime enforcement survives the core. It also requires one artifact.
**Decision.** `acf-host` runs as `serve` (core), `edge`, `guest-traffic` and `lifetime`. The core starts the edge
and each guest-traffic process by re-executing `/proc/self/exe` with an empty environment and an unprivileged
identity, and passes configuration and open sockets over a socket pair. A role sets `no_new_privs` before its
runtime has a second thread, then verifies from `/proc/thread-self/status` that it holds no privilege, and refuses to
run otherwise. The lifetime enforcer is a separate service so that restarting the core never stops it.
**Consequences.** A parser bug in the edge or the relay yields an unprivileged process with two sockets. An upgrade
of the file on disk cannot make two roles of one activation run different code. Cost: role startup is part of the
start path and has its own tests (`tests/process_roles.rs`). **Reversibility:** reversible.

## ADR-003 — The edge is stateless and the core validates everything again
**Context.** If the edge held state, its death would lose it; if the core trusted the edge's validation, a
compromised edge could send anything.
**Decision.** The edge authenticates, enrols, bounds, decodes and validates, then relays the request with the
peer's enrolled `(peer_id, role)`. The core runs the same decode and shape checks, checks the enrolment in force
now, and only then admits. If the edge dies the core starts another with the same listeners.
**Consequences.** A compromised edge has the authority of an enrolled peer, bounded by the safety profile. Callers
resolve lost responses by operation id. Cost: each request is validated twice. **Reversibility:** reversible.

## ADR-004 — Authority is enrolment, role, tags and the safety profile; no tenant concept on the host
**Context.** The host cannot know who a control plane's users are, and must not pretend to.
**Decision.** An enrolment entry names one credential exactly and gives it one role. Records carry
`(peer_id, owner_scope)`; `owner_scope` is opaque and compared for equality only. A record with other tags is
`NOT_FOUND`. The profile is the host's own floor: ceilings and capabilities, nothing about users or prices. The
switches `sandbox_destroy` and `snapshot_delete` bind role `caller` only, because containment by an operator or by
the host must never be refusable.
**Consequences.** Rotating a certificate is an enrolment change that touches no record. A peer that serves several
tenants separates them with scopes it chooses. **Reversibility:** expensive (tags are in every record).

## ADR-005 — One operation protocol; the reserved state is committed in BEGIN
**Context.** The dangerous bug is reporting "failed" for something that happened, or "succeeded" for something
that did not. The joint-state invariants must hold after every commit, not only at the end of an operation.
**Decision.** Refusal leaves nothing. BEGIN commits the record, the reservation and the state the operation
reserves in one batch: an execution makes the generation `RUNNING`, a snapshot makes it `PAUSED`, a destroy of a
live generation makes it `STOPPING`. STEP names a privileged step durably before it runs. FINISH commits the
terminal state with every lifecycle and lease change. `effect` and `cleanup` are derived when an operation is read,
from the committed state of what it left behind.
**Consequences.** A crash at any point leaves a record that says what may have happened. A pending cleanup
becomes complete without rewriting history. Cost: at least three commits per operation. **Reversibility:**
expensive.

## ADR-006 — Exclusivity is read from committed state; every write of an operation is fenced
**Context.** An in-memory lock is forgotten by a restart and cannot be seen by recovery.
**Decision.** "Is this sandbox busy?" is answered inside the BEGIN commit from the non-terminal operations in the
store. Every later write of an operation goes through `commit_for`, which refuses if the operation is no longer
non-terminal. A containment operation ends the operations it supersedes in its own BEGIN commit, and in the same
commit marks an unfinished snapshot `INVALID` and the generation a restore was building `FAILED`.
**Consequences.** A superseded task cannot write anything, whatever it is doing. The invariants hold at the commit
that supersedes. **Reversibility:** expensive (recovery depends on it).

## ADR-007 — A narrow journal of our own, with lineage, sequence, epoch and a reserve
**Context.** Admission needs an atomic check-and-append with one writer, small state and crash behaviour that can
be tested exhaustively. An embedded database would be a large dependency inside a root process.
**Decision.** An append-only file of CRC-framed batches of full-record upserts. One writer lock spans check,
append, fsync and apply; readers use a separate lock on the committed state (ADR-034). A lineage id qualifies every sequence and cursor; the commit sequence is each record's revision;
an activation epoch fences stale writers. A torn tail is repaired; any other corruption makes the host
`READ_ONLY`; an uncertain commit is a fail-stop. A ballast file keeps room to record containment on a full disk.
**Consequences.** The store's failure behaviour is unit-tested, including failed appends and lost rollbacks. The
previous schema's file is kept at migration. Cost: the whole state is in memory, which is fine for one host's
sandboxes. **Reversibility:** reversible behind `commit_with` and `read`; the records are the contract.

## ADR-008 — One trusted-input rule for files and for executables
**Context.** A file or a tool that an unprivileged user can replace is a root-execution primitive.
**Decision.** Configuration, profile, enrolment, secrets and TLS material are read through one loader that checks
the open descriptor: regular file, trusted owner, not writable by group or other, bounded size, no link at the leaf,
and every directory on the way with the same property, including the directories a linked directory is reached
through. Executables obey the same rule. Because distributions ship some tools as links, an executable's leaf may
be a link placed by a trusted owner; the file it resolves to and the way there are then checked as well. Every tool
is named by an absolute configured path and started with an empty environment.
**Consequences.** Misconfiguration is loud, and nothing is found through `PATH`. Cost: `/etc/acf` and the tool
directories must be root-owned and closed, which the installer arranges. **Reversibility:** reversible.

## ADR-009 — A failed mandatory check means `CONTAINMENT`, never exit
**Context.** A host that refuses to start cannot destroy the sandboxes it already runs.
**Decision.** Structural defects that make the configuration unusable stop the process. Everything else (a
violated relation between parameters, a failed preflight check, an unusable profile, enrolment table or TLS
material, a missing lifetime enforcer, a store older than the system) is recorded as a reason for `CONTAINMENT`:
no new privilege, containment and reads served. An unusable profile is replaced by one that denies everything and
still permits containment; an unusable enrolment table by one that admits local root as operator.
**Consequences.** The host stays administrable in every failure it can describe. **Reversibility:** reversible.

## ADR-010 — Admission is one commit with the reservation; a failed generation keeps its lease
**Context.** Check-then-act admission lets two creators take the last slot, and releasing a lease on failure lets
a leaked runtime hide behind a free slot.
**Decision.** Capacity is a pure function over committed state evaluated inside the BEGIN commit. A lease is
released only in the commit that records the generation `DESTROYED`. An identifier slot is assigned only if records
show it free and the backend sees no live resource carrying it.
**Consequences.** No overcommit and no hidden leak; a stuck generation visibly consumes capacity and is counted.
**Reversibility:** expensive.

## ADR-011 — Recovery is a pure table; a granting operation is never continued; doubt is quarantined
**Context.** Continuing an interrupted operation would need the authority, the secrets and the deadline of a
request made to an earlier activation.
**Decision.** Two pure functions decide: one for an operation an earlier activation left, one for a generation no
operation holds. Granting operations are undone to proven absence; an interrupted execution ends `UNKNOWN` and its
runtime is stopped; containment is re-driven. Ownership doubt wins over every other rule. Attempts are counted
durably before they are made. Quarantine is left only through `quarantine.release`, where an operator asserts and
the host observes afterwards.
**Consequences.** Recovery creates no privilege and needs no secret. Cost: an interrupted create is lost work.
**Reversibility:** reversible.

## ADR-012 — Lifetime is enforced by a separate process that needs only a directory of tickets
**Context.** A sandbox must not outlive its expiry because the core crashed, hung or was being upgraded.
**Decision.** The instant a runtime process exists, before it is configured, the core writes a ticket: process
identity, the control group's kill switch, the monotonic expiry of this boot. `acf-host lifetime` reads the
directory, ends what has expired, and writes a heartbeat. It signals only the recorded process instance and writes
only to a `cgroup.kill` under the configured root. The core stops creating privilege when the heartbeat is stale.
Tickets live on the runtime filesystem, so they do not survive a reboot, and neither does any runtime.
**Consequences.** The enforcer has no store, no backend and no peer input, and can be restarted at any time.
**Reversibility:** reversible; the contract leaves the mechanism open.

## ADR-013 — Posture is verified by observation, and re-verified by whoever holds the sandbox
**Context.** The jailer should chroot, change identity, drop capabilities and install seccomp. A wrong flag or a
kernel difference silently does not. And the sweep does not observe a sandbox that an operation holds.
**Decision.** After launch and before any configuration, the host reads the VMM's state from `/proc` and ends it on
any miss. Afterwards, the sweep observes idle generations, and an execution, a snapshot capture and a restore in
place observe the runtime they hold every quarter of `posture_recheck_interval`. A lost control ends the runtime
with `SECURITY_CONTROL_FAILURE`; a paused guest is not resumed; nothing is repaired in place. A start in flight is
not watched, because a runtime still being launched has not installed every control yet.
**Consequences.** The interval is an upper bound for every control, which the relation
`sweep_interval ≤ posture_recheck_interval / 4` makes checkable at startup. **Reversibility:** reversible.

## ADR-014 — Mode `none` is proven in three independent layers
**Decision.** The VMM configuration has no network interface, which Firecracker itself reports; the VMM runs in
an empty network namespace, which is checked by inode; the guest agent lists its interfaces and tries egress, and
can only add a violation. The host-side layers are judged before the first vCPU instruction.
**Consequences.** A compromised guest cannot talk the host into "verified". **Reversibility:** reversible.

## ADR-015 — Mode `allowlist`: a namespace with no route, one constant segment, an unprivileged relay
**Context.** The contract requires that loss of enforcement yields no connectivity, that traffic parsing runs
without host privilege, and that a name entry cannot be turned into access to another address.
**Decision.** Each sandbox has its own network namespace with a tap device, a packet filter and no route. The same
private /30 is used in every namespace. All guest TCP is redirected to a relay socket and DNS goes to a resolver
socket, both bound inside the namespace by the core and served by a `guest-traffic` process that runs in the host's
namespace under its own uid and control group. A name entry allows a TLS connection whose server name equals the
entry, to an address the resolver returned for that name to this sandbox within the binding lifetime.
**Consequences.** If the relay dies or the filter is flushed there is nothing that carries a packet. Restored
guests find the addresses they were captured with. Accepted limit: a TLS server name is the guest's claim, so two
sites sharing one allowlisted address can both be reached. **Reversibility:** reversible; this is the backend's.

## ADR-016 — The backend port is semantic and declares its capabilities
**Decision.** The coordinator is written against `SandboxBackend` and `CapabilityProfile`. It reads the identifier
pool size, per-runtime overhead and stop grace from the declared capabilities, never from Firecracker's
configuration. A request needing an undeclared capability is refused before BEGIN. The VMM, the isolation
controls, the network plumbing and storage placement are replaced together or not at all.
**Consequences.** Every flow and all of recovery are tested against an in-memory backend. That backend is itself
held to the port's rules by the conformance suite (`testing/conformance.rs`), the same assertions the Firecracker
adapter must pass, so the double cannot drift from the port without a test failing. A second real backend is
deliberately not written. **Reversibility:** reversible.

## ADR-017 — Image identity is the hash of the manifest; files are hashed while they are copied
**Decision.** An image is a kernel, a root filesystem and a manifest; its identity is the SHA-256 of the manifest
bytes, which binds both file digests and records the guest agent and protocol versions. The host copies each file
from an open descriptor while hashing it and compares, so the digest describes the bytes that are booted.
**Consequences.** No window between check and use. Images are not bit-reproducible; identity is that of what was
built. **Reversibility:** expensive (identities are recorded).

## ADR-018 — Full snapshots bound to the store; a restore is accepted only by an oracle
**Decision.** A snapshot is CPU and device state, guest memory and the disk, each copied with its digest. The
manifest's digest is held in the store. A restore checks integrity, then compatibility, loads into a new
generation, and requires the guest to reproduce the probe taken before the capture. The switch to the new
generation is one commit, and the old generation is retired afterwards.
**Consequences.** "Verified restore" has a definition, and a failed restore never costs the caller their sandbox.
Cost: snapshots are large and contain guest memory. The Firecracker backend does not claim that a restore reseeds
guest entropy. **Reversibility:** expensive.

## ADR-019 — Execution: one at a time, an argument vector, no stdin, a host backstop
**Decision.** One execution per sandbox. The command is an argument vector that no shell interprets. The
environment is empty plus the names the profile allows. The guest gets a deadline and the host keeps a later one;
when it passes the host ends the runtime. Output is capped per stream and fully counted. When no result can be
obtained the operation is `UNKNOWN` and the runtime is ended.
**Consequences.** Evidence is attributable to exactly one command. No interactive sessions. **Reversibility:**
reversible.

## ADR-020 — Secrets travel by reference; material cannot be serialised
**Decision.** A request names a secret; raw material in a request is refused. `SecretMaterial` implements neither
`Clone` nor `Serialize` nor `Debug` output of its content, and is overwritten when dropped. Resolution happens
inside the delivering operation. The shipped provider reads one trusted file per reference. The Firecracker backend
declares `secret_injection: false`, so delivery is refused there before BEGIN.
**Consequences.** The rule is structural rather than procedural. Delivery to a real guest is future work behind a
declared capability. **Reversibility:** reversible.

## ADR-021 — Schemas are generated from the types; the contract's tables are transcribed and tested
**Decision.** The method table, role table, mode table, lifecycle relation and failure classes are written as
code and each is compared with a transcription of the contract's table in a unit test. `host-api.json` and the
file-format schemas are generated from the types, checked in, and a difference fails the build.
**Consequences.** A method added in code without a contract change fails a test. A client cannot drift silently.
**Reversibility:** reversible.

## ADR-022 — Telemetry decides nothing
**Decision.** `emit` returns nothing and cannot fail. Events carry a per-activation sequence and, for committed
changes, the commit sequence. Metric labels are closed vocabularies and the number of series is bounded. Security
evidence never passes through telemetry: it is obtained at the call site or the operation fails.
**Consequences.** A full disk changes no outcome and is visible as a counter. **Reversibility:** reversible.

## ADR-023 — Tests are named after the catalog; a test that cannot run is ignored, never passed
**Decision.** One suite module per catalog section; each test carries its entry's id in its name. The rig
restarts a host by opening the store again over the same disk and the same world of running fake runtimes, and it
checks the joint-state invariants after every commit. Tests that need root are `#[ignore]`d with the reason and
fail when asked for without it. `fsync` is skipped in test builds only, through one module that a release build
compiles without the switch.
**Consequences.** Cargo's own summary shows what did not run. **Reversibility:** reversible.

## ADR-024 — The Firecracker pin moves only with a run on real KVM
**Context.** A snapshot is valid only on the Firecracker version that took it, and the API models are transcribed
from one version's description. A newer release existed when this was written.
**Decision.** The pin stays at `v1.17.0`, whose release digests are recorded. Moving it requires the integration
suites to pass on a KVM host with the new binaries.
**Consequences.** The host may trail upstream by a release. **Reversibility:** reversible.

## ADR-025 — Dependencies are verified at write time and locked
**Decision.** Versions were resolved against the registries when the code was written, not from memory
([DEPENDENCY_PROVENANCE.md](DEPENDENCY_PROVENANCE.md)). Manifests carry floors, lock files are committed and builds
use them. The TLS stack is built without TLS 1.2. GitHub Actions are pinned by commit.
**Consequences.** Reproducible builds; advisory scanning must run where the advisory databases are reachable.
**Reversibility:** reversible.

## ADR-026 — Rust 2024; `unsafe` forbidden except one audited block in the guest
**Decision.** Workspace lints forbid `unsafe` and deny `unwrap`, `panic`, `todo` and `dbg`. The guest agent allows
one `unsafe` block (`pre_exec`, to join the per-execution control group and set resource limits between `fork` and
`exec`) and documents why it is async-signal-safe. System interfaces go through `rustix` and `cap-std`. Release
profile: `panic = "abort"`, thin LTO, overflow checks on.
**Consequences.** A memory-safety bug has to come from a dependency or the kernel. **Reversibility:** reversible.

## ADR-027 — Guest init is a POSIX-sh PID 1, crash-only
**Decision.** `acf-init` refuses to run unless it is PID 1 of a guest, mounts, hardens, raises loopback, runs the
agent as a child, and ends when the agent ends. Exiting PID 1 panics the kernel; with `panic=1 reboot=k` the VMM
exits, so the host sees a dead runtime rather than a half-alive one.
**Consequences.** Small enough to read and test. No supervision tree. **Reversibility:** reversible.

## ADR-028 — MMIO transport; Firecracker's default boot arguments plus an explicit `pci=off`
**Decision.** The host does not pass `--enable-pci`. The built-in boot arguments are Firecracker's documented
default with `pci=off` spelled out; the serial device is disabled. A value in configuration or in an image manifest
replaces the default, so an override must carry every flag it keeps.
**Consequences.** A smaller device surface; a guest has no console unless `diagnostic_log` is turned on, which is
off by default because it is guest-influenced disk growth. **Reversibility:** reversible.

## ADR-029 — The cgroup parent is created by a oneshot unit, not by the core
**Decision.** A unit creates the parent group and delegates `cpu`, `memory` and `pids` before the core starts;
`doctor` verifies the delegation.
**Consequences.** The core never writes to the root of the cgroup tree. **Reversibility:** reversible.

## ADR-030 — Pins fail closed
**Decision.** The Firecracker installer and the image builder refuse to proceed while a digest they need is
`UNSET`. The lock files use a strict `KEY=VALUE` grammar parsed identically by shell and Python.
**Consequences.** A root-executed binary is never installed on trust. The four base images and the `x86_64` kernel
are pinned, each from a measurement (the lock files say how); the `aarch64` kernel is still `UNSET`, so a release
cannot be cut until someone measures one. **Reversibility:** reversible.

## ADR-031 — The Makefile is the gate; KVM suites fail, never skip, when enabled
**Decision.** CI calls make targets, and guard tests fail if a workflow or a document names a target that does
not exist or if the release build could include the test-only feature. With the integration switch set, a missing
KVM environment is an error that lists what is missing.
**Consequences.** "Passed locally" and "passed in CI" mean the same thing, and a suite cannot report success on a
host where it verified nothing. **Reversibility:** reversible.

## ADR-032 — The source archive is reproducible, self-describing and read as untrusted
**Decision.** `tools/pack_zip.py` builds the delivery archive with sorted members, fixed timestamps, normalised
modes and an embedded SHA-256 manifest. `tools/zip_to_markdown.py` turns an archive into markdown pages, the
complete directory tree and an optional single-document bundle, and refuses an archive whose names, sizes, checksums
or manifest do not hold before it writes anything.
**Consequences.** Anyone with `sha256sum` can check the deliverable. **Reversibility:** reversible.

## ADR-033 — The VMM and the jailer are pinned by digest in the host configuration and hashed before every launch
**Decision.** `firecracker.firecracker_sha256` and `firecracker.jailer_sha256` hold the SHA-256 of the two
installed files; the installer prints them. The host hashes both at startup, before it runs either even for
`--version`, and again before every start and restore. A digest that is unset or different is a failed
mandatory check at startup and an `INTEGRITY_FAILURE` at launch. The example configuration leaves both unset.
**Why not the version alone.** A version is what a binary says about itself. A wrong build with the right
version line, or a file replaced under a running host, would be run as root.
**Why not a private verified copy.** Copying the binaries into the state root and running the copies would make
the executed bytes exactly the hashed ones, as is done for kernels and root filesystems. It adds a second place
a root-executed binary lives and a dependency on where that place is mounted. Hashing costs a few milliseconds
per launch for a file of a few megabytes, and the window that remains is covered by the trusted-input rule.
**Consequences.** A new host needs two more lines in its configuration before it creates a sandbox. Upgrading
the binaries without the configuration stops new launches and nothing else. **Reversibility:** reversible.

## ADR-034 — No answer waits for a disk: reads bypass the writer, and bulk disk work leaves the async worker
**Context.** On the first real host, one create's answer was lost: the edge gave up after its 60 s deadline,
although the core answers a create after at most 30 s. The trigger was a slow disk. That create spent 165 s
copying, hashing and flushing a 225 MB root filesystem. Two things turned that into a lost answer. The store
took one mutex for reads and commits alike and held it across each commit's `fdatasync`. On ext4 in ordered mode,
that flush waits for the filesystem-journal transaction carrying the root filesystem's data blocks. Separately,
the copy ran inline on an async worker. Measured on that host: a read answered in 2 ms when idle and in about
5 s, the whole create, when a create was running.
**Decision.** The store keeps two locks. Writers take a writer lock for *check → append → fsync → apply*. The
committed state has its own lock, which a writer takes only to apply a batch that is already durable. Readers
see the last durable state at once. Every flush and every bulk copy goes through `durability::blocking`, which
first hands the worker's other tasks to another worker (`block_in_place`).
**Why not `spawn_blocking`.** A detached task outlives the operation that started it. A create that timed out
could still be writing its copy while its compensation removes the directory.
**Why not an async store.** Every commit site is synchronous and short on a healthy disk. The defect was readers
queuing behind flushes, not commits being synchronous.
**Consequences.** Measured on the same host afterwards: reads during creates have a median of 2 ms, and one read
in three creates took 0.47 s. Commits still queue behind each other, as they must. A commit's flush still waits
for what the filesystem has to write first. The store and the sandbox payloads share `state_root`, and so one
filesystem, so on a slow disk a create's staging still delays the commits made meanwhile, though no longer the
reads ([OPERATIONS.md](OPERATIONS.md) §9). **Reversibility:** reversible inside `store/journal.rs` and
`durability.rs`.
