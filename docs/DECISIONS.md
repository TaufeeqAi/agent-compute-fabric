# Decision log — 

Architecture decisions that are *not* spelled out by the contract, with the reasoning and the way back.
Reversibility uses the project's vocabulary: **reversible** (a refactor), **expensive** (touches a wire contract or on-disk
format), **effectively irreversible** (cannot be undone once data exists). Status of all entries: *accepted*.

| ID | Decision | Reversibility |
|---|---|---|
| 001 | Python client, Rust privileged plane; the client never enforces | expensive |
| 002 | One privileged process; Firecracker behind a `SandboxBackend` trait | reversible |
| 003 | Operation protocol: validate → begin → step → backend → finish; `UNKNOWN` is first-class | expensive |
| 004 | A narrow, CRC-framed write-ahead journal of our own | reversible |
| 005 | Identity from `SO_PEERCRED`; two-layer socket access control | expensive |
| 006 | One trusted-file loader for config, policy and executed binaries | reversible |
| 007 | Policy is immutable per operation; reload affects the future only | expensive |
| 008 | Admission is atomic with reservation; failed generations keep their reservation | expensive |
| 009 | `network=none` is proven in three independent layers | reversible |
| 010 | Verify the VMM's confinement by reading `/proc` back, before configuring it | reversible |
| 011 | Image identity = sha256(manifest bytes); hash while copying | expensive |
| 012 | Full snapshots, bound to the journal; restore is accepted only by a probe oracle | expensive |
| 013 | Recovery is a pure decision table; doubt means quarantine | reversible |
| 014 | Exec is single-flight, no stdin, empty environment, per-exec cgroup | reversible |
| 015 | Guest init is a POSIX-sh PID 1, crash-only | reversible |
| 016 | MMIO transport; Firecracker's default boot args plus an explicit `pci=off` | reversible |
| 017 | The cgroup parent is created by a oneshot unit, not by the agent | reversible |
| 018 | `serve` enforces the same checks as `doctor` | reversible |
| 019 | Pins fail closed: UNSET refuses, `--allow-unpinned` is recorded | reversible |
| 020 | Image hygiene: pinned ext4 features, no setuid/setgid, explicit default `PATH` | reversible |
| 021 | The Makefile is the gate; guard tests keep CI, docs and Makefile honest | reversible |
| 022 | KVM suites fail, never skip, when enabled; a control-plane subset runs everywhere | reversible |
| 023 | Dependencies: verified-latest at write time, floors + committed locks, Actions by commit SHA | reversible |
| 024 | Rust 2024, `unsafe` forbidden in the host, one audited exception in the guest | reversible |
| 025 | The source archive is reproducible, carries its own sha256 manifest, and is read as untrusted | reversible |

---

## ADR-001 — Python client, Rust privileged plane; the client never enforces
**Context.** The Master Plan fixes a Python CLI and a Rust host agent. A client that also "checks policy" would create two
authorities that drift, and the client runs as an unprivileged user — the wrong place for a decision.
**Decision.** `acf-local` parses, resolves names to ids, renders evidence and picks exit codes; *every* allow/deny and
every legality check happens in `acf-host`. The wire contract is generated from the Rust types (`make schemas`; `make check-schemas`
fails if `schemas/` is stale) and the Python models are tested against it.
**Consequences.** Client bugs cannot widen authority; a second client (SDK) inherits all enforcement. Cost: two
toolchains, and a schema step. **Reversibility:** expensive (the wire format), mitigated by the versioned protocol `acf.host/1`.

## ADR-002 — One privileged process; Firecracker behind `SandboxBackend`
**Context.** Spec §26 projects eleven boundaries onto *one* process; §25 asks for backend replaceability without a speculative second backend.
**Decision.** `acf-host` is the only privileged process; the jailer and `firecracker` are tools it launches. Everything
Firecracker-specific lives behind the `SandboxBackend` trait with a `CapabilityProfile`; unsupported operations return the stable `UNSUPPORTED`.
**Consequences.** Lifecycle, journal and recovery are backend-agnostic and are tested with an in-memory backend and with a
fake Firecracker + the real guest agent. A real second backend is deliberately not written (Gate H). **Reversibility:** reversible.

## ADR-003 — Operation protocol; `UNKNOWN` is first-class
**Context.** The dangerous bug in a runtime like this is reporting "failed" for something that happened (then re-running it) or
"succeeded" for something that did not.
**Decision.** Every mutating request is a durable operation: *begin* (fingerprint, caller, policy, reservation in one atomic
append) → *step* (the next privileged action is declared **before** it runs) → backend → *finish* (one atomic terminal
record). A failure whose side effect "may have happened" and that cannot be proven clean is `UNKNOWN`. Refusals happen before
*begin* and leave nothing behind. Duplicates are resolved by canonical request fingerprint.
**Consequences.** Retrying is safe by construction; `exec` after a crash is *always* `UNKNOWN` and never re-run. Cost: every
operation writes at least three journal records. **Reversibility:** expensive (recovery semantics depend on it).

## ADR-004 — A narrow, CRC-framed write-ahead journal of our own
**Context.** Admission needs an atomic *check-and-append* (room? then reserve) with a single writer, small state, and crash
semantics we can test exhaustively. An embedded database would be a large dependency inside a root process.
**Decision.** `operation/journal.rs`: an append-only file, one line per *atomic batch* —
`<crc32 hex> <json {"seq":N,"entries":[…]}>\n` — with `commit_with(check)` atomic under one lock, a single-instance lock file,
torn-tail repair, **read-only quarantine** on mid-file corruption, and compaction to live state plus the newest terminal operations. It holds only what recovery needs (spec §10.2); logs and metrics are not authority.
**Consequences.** Fully unit-tested including corruption and failed appends; no migration tooling yet (spec §21.5 keeps that a storage
concern). **Reversibility:** reversible behind `Journal`; the *records* are the contract.

## ADR-005 — Identity from `SO_PEERCRED`; two-layer socket access control
**Context.** Local callers must be authenticated without secrets that could leak into an agent's environment.
**Decision.** The kernel reports the caller's real uid/gid. Layer 1 is the socket's mode/group; layer 2 is the host's allow-list
(`allowed_uids`/`allowed_gids`). Both must admit. An unauthorised peer that reaches the socket gets one `AUTHORIZATION`
frame and is closed *before any request is read* (status `REJECTED`, no operation). Admin actions need `trusted_owner_uids`.
**Consequences.** No tokens to rotate or leak; callers are Unix users. remote protocol must add real authentication — this is
deliberately not forward-compatible with tenants. **Reversibility:** expensive.

## ADR-006 — One trusted-file loader
**Context.** Config, policy and the binaries a root daemon executes are all "files an unprivileged user might replace".
**Decision.** A single function loads them: root-owned, regular, `O_NOFOLLOW`, not group/world-writable, every ancestor checked,
≤ 1 MiB; failure is `SECURITY_CONTROL_FAILURE` and the file is not used. The policy's identity is the sha256 of the verified bytes.
**Consequences.** Misconfiguration is loud. Cost: operators must keep `/etc/acf` root-owned (the installer does). **Reversibility:** reversible.

## ADR-007 — Policy is immutable per operation
**Context.** A policy edited mid-run must not retroactively change what a running sandbox was allowed.
**Decision.** Each operation records the policy digest it was admitted under and keeps that policy; `policy_reload` swaps the
policy atomically for *future* operations only and is itself a durable, admin-only operation. A bad file is refused and the old policy stays.
**Consequences.** Evidence can always say "run R was permitted by policy P". **Reversibility:** expensive.

## ADR-008 — Admission is atomic with reservation
**Context.** Check-then-act admission lets two creators take the last slot.
**Decision.** Capacity is a pure function over journal state evaluated *inside* `Journal::commit_with`, so the check and the
reservation it justifies are one append. A failed generation keeps its reservation until it is destroyed; an over-ceiling request is refused, never clamped.
**Consequences.** No overcommit and no hidden leaks; a stuck generation visibly consumes capacity. **Reversibility:** expensive.

## ADR-009 — `network=none` in three independent layers
**Context.** "No network" claimed by one mechanism is one bug from false.
**Decision.** (1) the Firecracker configuration has no NIC — authoritative; (2) the VMM runs in a dedicated *empty* network
namespace; (3) the guest agent corroborates by listing interfaces and attempting egress to three addresses. The guest can only *add* a
violation. Any violation ⇒ the start fails closed and the VMM is killed. Egress/proxy code does not exist in.
**Consequences.** A compromised guest cannot talk the host into "verified". Adding a mode requires a new verdict function and an adversarial suite. **Reversibility:** reversible.

## ADR-010 — Verify confinement by observation, before configuring the VMM
**Context.** The jailer *should* chroot, setuid, drop capabilities and install seccomp; a wrong flag or a kernel difference silently doesn't.
**Decision.** After launch the host reads `/proc/<pid>/status` and `/root`: expected uid ≠ 0, `Seccomp: 2`, `NoNewPrivs`, empty
`CapEff`, root = jail. Any miss ⇒ kill the VMM *before* sending it any configuration. The profile is hashed into `security_profile_id`.
**Consequences.** Misconfiguration becomes a refused start, not a silent hole. Unproven on real hardware until the KVM run. **Reversibility:** reversible.

## ADR-011 — Image identity is the hash of the manifest; hash while copying
**Context.** Validate-then-use is a TOCTOU window; a swapped rootfs between hash and boot defeats provenance.
**Decision.** An image is `kernel` + `rootfs.ext4` + `manifest.json`; its id is sha256(manifest bytes), which binds both file digests. The host copies the
rootfs into the generation directory *while hashing it* (holes preserved) and compares, so the digest describes the booted bytes.
**Consequences.** Cheap, strong, auditable. Images are not bit-reproducible; identity is that of what was actually built. **Reversibility:** expensive (ids are recorded).

## ADR-012 — Full snapshots, journal-bound; restore accepted only by an oracle
**Context.** A restore that "worked" but resumed the wrong state or a rebooted guest is worse than a failure.
**Decision.** Full Firecracker snapshots plus a disk copy; the manifest names every artifact (sha256, size), the host CPU
fingerprint, Firecracker version, security-profile id and image identity, and its digest is bound into the journal. At restore
the artifacts are re-hashed, then the guest is probed (`boot_id` + canary sha + agent version) and must reproduce the baseline
digest; a changed `boot_id` reveals a reboot. Same host/version/CPU only; quotas on count and bytes.
**Consequences.** "Verified restore" has a definition. Cost: snapshots are large and hold memory (secrets). **Reversibility:** expensive.

## ADR-013 — Recovery is a pure decision table; doubt means quarantine
**Decision.** `classify(op, state, has_handle, observed, switched) → Plan` is a pure function (every row a unit test). Ownership
doubt beats every other rule: nothing is deleted or signalled that the journal cannot prove is ours (OWNER marker with nonce;
process identity = pid + start-time ticks + boot id). A record touched `max_attempts` times is quarantined, not retried forever.
**Consequences.** Recovery is boring and auditable. Cost: no release command for a quarantine (known gap). **Reversibility:** reversible.

## ADR-014 — Exec: single-flight, no stdin, empty environment, per-exec cgroup
**Decision.** One exec per sandbox at a time (the loser gets `STATE_CONFLICT` without a record). stdin is `/dev/null`;
the environment is empty plus allow-listed request variables plus an explicit default `PATH`; commands run as uid/gid 1000; each gets a
cgroup-v2 child with `pids.max` and `cgroup.kill` (falling back to `RLIMIT_NPROC`, and *reporting* the weaker `containment`);
cancel arrives on a second connection; output is capped but fully counted.
**Consequences.** Evidence is attributable to exactly one command; no interactive sessions in. **Reversibility:** reversible.

## ADR-015 — Guest init is a POSIX-sh PID 1, crash-only
**Context.** Init is part of the guest's trusted computing base and must be small enough to read.
**Decision.** A shell script (`acf-init`) that refuses to run unless it is PID 1 of a guest, mounts, hardens, grows the root filesystem, raises
loopback, floors the clock, runs the agent as a child, and ends when the agent ends. Exiting PID 1 panics the kernel; with
`panic=1 reboot=k` the VMM exits, so the host sees a dead VM rather than a half-alive one. Logic that can be pure (clock floor, block-name parsing) is tested as functions.
**Consequences.** Readable and testable (`tests/scripts/test_acf_init.py`, real namespaces under root); no supervision tree. **Reversibility:** reversible.

## ADR-016 — MMIO transport; Firecracker's default boot args plus an explicit `pci=off`
**Decision.** The host does not pass `--enable-pci`, so virtio devices are MMIO. The built-in boot-args default is Firecracker v1.17.0's documented
default plus `pci=off`; a value in config or an image manifest *replaces* the default, so overrides must carry every flag they keep. The serial device is disabled (`8250.nr_uarts=0`).
**Consequences.** Smaller device surface; debugging a guest has no console by default (`diagnostic_log` is opt-in because it is guest-influenced disk growth). **Reversibility:** reversible.

## ADR-017 — The cgroup parent is created by a oneshot unit
**Context.** The agent must not need write access to the root of the cgroup tree at runtime, and delegation must be re-created at every boot.
**Decision.** `acf-cgroup.service` runs `acf-setup-cgroup` (POSIX sh) before the agent; `doctor` verifies that `cpu`, `memory` and `pids` are delegated.
**Consequences.** A clear failure message when the host cannot provide the profile. **Reversibility:** reversible.

## ADR-018 — `serve` enforces the same checks as `doctor`
**Decision.** `doctor` prints one line per check; `serve` runs the identical checks and refuses to start on any FAIL (WARN is tolerated: swap, SMT, low headroom).
**Consequences.** An isolation profile the machine cannot honour is a start-up error, not a runtime surprise. **Reversibility:** reversible.

## ADR-019 — Pins fail closed
**Decision.** Image builds and the Firecracker installer refuse (exit 3) while a digest is `UNSET`. `--allow-unpinned` exists for development and is
written into the manifest as `unpinned`. The lock files use a strict `KEY=VALUE` grammar parsed identically by bash and Python (a parity test feeds both the same inputs).
**Consequences.** The repository ships *unpinned by honesty*: the first operator pins (see OPERATIONS §3). **Reversibility:** reversible.

## ADR-020 — Image hygiene
**Decision.** ext4 features are pinned in `scripts/mke2fs.conf` (the host's mke2fs defaults must not decide what the guest kernel needs);
every setuid/setgid bit is stripped in each image's Dockerfile (`find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -exec chmod a-s {} +`) and
*asserted absent* in a running guest by a K test; the agent injects an explicit default `PATH` because the environment is empty;
the guest agent is verified static by reading its ELF header, never by executing it.
**Consequences.** No privilege-escalation binaries in the guest; reproducible filesystem features. **Reversibility:** reversible.

## ADR-021 — The Makefile is the gate
**Decision.** CI calls make targets; guard tests fail if a workflow or a doc names a missing target, if `make release` could build with
the test-only feature, or if `make ci` includes something CI never runs. Docs may only mention `` `make X` `` for targets that exist.
**Consequences.** "Passed locally" and "passed in CI" mean the same thing. **Reversibility:** reversible.

## ADR-022 — KVM suites fail, never skip, when enabled
**Decision.** `ACF_INTEGRATION=1` makes a missing environment an *error with a list of what is missing*; a suite that skips on a broken host would
report success exactly where the isolation claims matter. Tests that depend only on admission/policy/state/exit-code semantics are marked `control_plane` and
also run against the in-memory host loaded with the **shipped** config and policy. The driver is black-box (CLI + a raw wire client + `/proc`) and is itself tested.
**Consequences.** Real coverage on every push for what needs no VM; honest skips otherwise. **Reversibility:** reversible.

## ADR-023 — Dependency policy
**Decision.** Versions were resolved against crates.io / PyPI / GitHub at write time, not from memory (see [DEPENDENCY_PROVENANCE.md](DEPENDENCY_PROVENANCE.md));
manifests carry floors, locks (`Cargo.lock`, `uv.lock` ×2) are committed and used with `--locked`; the CLI's runtime surface is three libraries; GitHub Actions are pinned by full
commit SHA (with the release tag in a trailing comment, resolved by `git ls-remote`) and Dependabot proposes bumps.
**Consequences.** Reproducible builds; advisory scanning (`audit.yml`) must run where the advisory databases are reachable. **Reversibility:** reversible.

## ADR-024 — Rust 2024; `unsafe` forbidden in the host
**Decision.** Workspace lints: `unsafe_code = forbid`, `unwrap_used`/`panic`/`todo`/`dbg_macro` denied; the guest agent allows exactly one `unsafe` block (`pre_exec`, needed to join the per-exec cgroup and set `RLIMIT_NPROC`/`RLIMIT_CORE` between `fork` and `exec`) and documents why it is async-signal-safe.
System interfaces go through `rustix` and `cap-std`. Release profile: `panic = "abort"`, LTO, overflow checks **on**.
**Consequences.** A memory-safety bug has to come from a dependency or the kernel. **Reversibility:** reversible.

## ADR-025 — The source archive is reproducible, self-describing and read as untrusted
**Decision.** `make dist` builds the delivery ZIP with `tools/pack_zip.py`: members sorted by UTF-8 path under one top-level directory, every
timestamp fixed at 1980-01-01, modes normalised to 0644/0755 (the executable bit is kept), no directory entries, deflate level 9, and an embedded
`MANIFEST.sha256` in coreutils format. The exclusions mirror `.gitignore` (a test keeps the two in step); a symlink, a special file, an oversized file
or a name with a control or direction-changing character is refused rather than skipped, and so is a root `MANIFEST.sha256` that is not exactly the
manifest the tree would get (an unpacked archive's own manifest is accepted and regenerated, so unpack-then-repack gives the same archive; a stale one
is refused until deleted). `tools/zip_to_markdown.py` turns an archive into one markdown
page per file, the complete directory tree and an optional single-document bundle. It treats the archive as **untrusted**: member names, types, sizes
(checked from the headers and again on the bytes read) and CRCs are verified, the manifest must match every file, nothing is written through a
symbolic link or over an existing file without `--force`, and the first problem refuses the whole archive before anything is written.
**Consequences.** Anyone with `sha256sum` can check the deliverable, and the same source always yields the same manifest. Byte-identical *archives* also
need the same zlib build, so cross-machine comparison should use the manifest. The markdown export is lossless (a test parses every page of this
repository back into the exact bytes of its source file) and therefore about as large as the source. **Reversibility:** reversible.
