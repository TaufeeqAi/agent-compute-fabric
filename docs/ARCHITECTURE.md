# Architecture — Agent Compute Fabric, Phase 1

Phase 1 is a **local, secure execution runtime**: one Linux host, local callers only, one network mode (`none`),
Firecracker microVMs behind a backend trait. Normative source: *Phase 1 Contract Specification v1.1.0*
(referred to as "the spec", `§` = its section numbers). This document says **how the code realises it**;
[CONTRACT_COMPLIANCE.md](CONTRACT_COMPLIANCE.md) says where each clause is proven and
[VERIFICATION_STATUS.md](VERIFICATION_STATUS.md) says what has and has not been run.

Reading order: §1 for the map, §3–§4 for the security story, §5–§9 for correctness, §14 for what is *not* done.

---

## 1. The system in seven questions

| # | Question | Answer |
|---|---|---|
| 1 | **What is it?** | `acf-host` (privileged Rust daemon) + `acf-guest-agent` (in-VM) + `acf-local` (Python CLI). It creates, runs commands in, snapshots, restores and destroys Firecracker microVMs, and returns *evidence* about every run. |
| 2 | **Why does it exist?** | Agent-generated code must be run somewhere an attacker-controlled workload cannot reach the host, the network or another run — and the operator must be able to *prove* what happened even after a crash. |
| 3 | **How does it work?** | Every mutating request becomes a durable **operation** (validate → record → declare step → act → record result). A crash at any point is resolved by a pure, table-driven **recovery** pass. `UNKNOWN` is a first-class outcome, never rounded to success or failure. |
| 4 | **What depends on it?** | Phase 2 (agent runtime, tool gateway, remote control plane) consumes the semantic interfaces (`Operation`, `SandboxBackend`, `ResourcePolicy`, `SnapshotRef`, `HostEvent`), never Firecracker details. |
| 5 | **What can fail?** | The host agent (restart → recovery), the VMM (crash → reconcile), the guest (lying/hostile → bounded by host-side checks), the journal (corruption → read-only quarantine), the disk (quota/headroom), the operator (mis-owned policy → refused at load). See §11. |
| 6 | **What should I remember?** | Python never enforces policy. The kernel (SO_PEERCRED, cgroups, namespaces, seccomp) enforces; the host *verifies by observation* that enforcement took hold, and fails closed if not. |
| 7 | **Mental model** | *A court clerk in front of a vault*: the clerk (host agent) writes the intent in a ledger **before** touching anything, the vault (jailed VMM) has no door to the street, and after a power cut the clerk reads the ledger and only ever tidies what the ledger proves is theirs. |

---

## 2. Process topology and data flow

```text
 operator / agent runtime
        │  acf-local (Python, Typer)          never enforces policy, never touches Firecracker
        ▼
 /run/acf/host-agent.sock        AF_UNIX, mode 0660, SO_PEERCRED identity
        │  u32 big-endian length + JSON       protocol "acf.host/1"
        ▼
 ┌──────────────────────────── acf-host (Rust, root) ─────────────────────────────┐
 │ server/ipc ─► dispatch ─► admission (auth, policy) ─► lifecycle coordinator     │
 │                                  │                         │                    │
 │     operation journal (CRC WAL) ◄┴── recovery (classify→actuate) ◄── at start   │
 │                                                            ▼                    │
 │     SandboxBackend (trait) ─► FirecrackerBackend ─► jailer ─► firecracker        │
 │     filesystem (images/generations/artifacts) · snapshot store · telemetry      │
 └───────────────────────────────────┬─────────────────────────────────────────────┘
                                     │ vsock (Firecracker UDS, "CONNECT 5252\n" → "OK")
                                     ▼
   microVM — own uid, chroot, PID ns, EMPTY net ns, seccomp, NoNewPrivs, caps 0, cgroup v2
      └─ acf-init (POSIX sh, PID 1) ─► acf-guest-agent (static musl, vsock :5252, peer CID 2 only)
             └─ every command: uid 1000, empty env + request env, no stdin, pipes, per-exec cgroup
```

One privileged process, one local client, one VMM per sandbox. No daemon besides `acf-host`; no listening TCP/UDP
port anywhere (asserted by `isolation/host_control`).

### Repository map

| Path | What lives there |
|---|---|
| `execution/wire/` | `acf-wire`: the u32-BE framing and the guest protocol types shared by host and guest (one definition, two users). |
| `execution/host-agent/` | `acf-host` library + binary: everything privileged. `acf-host-fake` (feature `testing`) is the same server over an in-memory backend. |
| `execution/guest-agent/` | `acf-guest-agent`: in-VM executor (library + binary). Runs inside the untrusted guest. |
| `apps/cli/` | `acf-local`: Typer/Pydantic client. Own `pyproject.toml`, own `uv.lock`, own tests. |
| `images/` | Image recipes (Dockerfile per alias), `images.lock` pins, the `acf-init` overlay. |
| `scripts/`, `tools/` | Operator scripts (install/build/pin) and the Python tools they use; all have tests under `tests/`. `tools/pack_zip.py` and `tools/zip_to_markdown.py` build the delivery archive and its markdown export (ADR-025). |
| `deploy/` | systemd units and tmpfiles. `config/`, `policies/`: the shipped configuration and policy. `schemas/`: generated JSON Schemas. |
| `tests/` | `integration/`, `isolation/` (KVM-gated), `helpers/` (black-box driver), `scripts/`, `tools/`, `fixtures/`. |

---

## 3. Components (the spec's BND-01…11 as code)

| BND | Boundary | Code | Owns |
|---|---|---|---|
| 01 | Local client / CLI | `apps/cli/src/acf_cli/` | Parsing, rendering evidence, exit codes. **No policy.** |
| 02 | Caller authentication and admission | `admission/{auth,policy,trusted_file}.rs`, `server/ipc.rs` | Who may call; what a caller may do; integrity of config/policy files. |
| 03 | Operation coordinator | `operation/{fingerprint,journal,lock,records}.rs`, `lifecycle/{mod,ops}.rs` | Operation identity, idempotency, the WAL, per-resource serialisation. |
| 04 | Lifecycle domain | `domain/*`, `lifecycle/{sandbox,snapshots,exec,query}.rs` | State machines, generations, failure taxonomy, results. |
| 05 | Resource admission and supervisor | `lifecycle/capacity.rs`, `process/{identity,limits,supervisor}.rs` | Atomic reservation, VMM identity, cgroup limits, signalling only what is provably ours. |
| 06 | Filesystem / image manager | `filesystem/{layout,generation,hashcopy,images,artifacts}.rs` | Capability-confined paths, immutable image identity, ownership-proven cleanup. |
| 07 | Network isolation | `network/{netns,verify}.rs`, guest `netprobe.rs` | Empty namespace, the three-layer `network=none` verdict. |
| 08 | Firecracker backend adapter | `backend.rs` (trait), `firecracker/*`, `guest/{client,connector}.rs` | Everything Firecracker-specific, behind `SandboxBackend`. |
| 09 | Snapshot / restore | `snapshot/{manifest,store}.rs`, `lifecycle/snapshots.rs` | Exact-object binding, compatibility gate, restore oracle. |
| 10 | RecoveryCoordinator | `recovery/{classify,actuate}.rs` | Deterministic classification and bounded convergence. |
| 11 | Telemetry / evidence | `telemetry/{events,metrics}.rs`, `domain/evidence.rs` | Diagnostic events and counters (never authority); run evidence. |

Also: `protocol/` (wire types, strict `deny_unknown_fields`), `server/` (accept loop, dispatch), `config.rs`, `doctor.rs`
(preflight), `schema.rs` (JSON Schema generation), `ids.rs` (validated id newtypes), `clock.rs` (monotonic + wall),
`error.rs` (taxonomy), `app.rs` (wiring).

**Dependency direction (spec §26.1):** CLI → protocol → dispatch → lifecycle → {capacity, filesystem, network,
snapshot} → `SandboxBackend` → Firecracker/Linux. `domain/` depends on nothing but ids and errors. A backend never calls
up into the lifecycle: it is handed a `LaunchSink` so the host can journal *"a VMM now exists, here is its identity"*
the instant it exists, before the backend does anything else.

---

## 4. Trust boundaries and the control-surface inventory (spec §17.1–17.2)

Trust levels, innermost distrust first: **guest workload** (hostile) → **guest agent** (trusted only to *add* evidence of
a violation, never to clear one) → **VMM** (untrusted-but-confined; verified after launch) → **host agent** (trusted) →
**kernel**.

| Surface | Owner / privilege | Reachable from guest? | Permissions | Created / torn down | Test |
|---|---|---|---|---|---|
| Host control socket `/run/acf/host-agent.sock` | root | no | `socket_mode` (0660) + `socket_gid`; created 0600 then adjusted; never replaces a live socket or a regular file | `server/ipc.rs` / clean shutdown | `isolation/host_control`, `server::ipc::tests` |
| Firecracker API socket | VM uid, inside the jail chroot | no (guest has no path to it) | jail-private | by the VMM at launch / with the generation | `test_the_vmms_sockets_are_unreachable_to_other_local_users` |
| Guest vsock UDS (host side of the vsock device) | VM uid, inside the jail | host-initiated only | jail-private | VMM / generation | `test_the_guest_agent_obeys_only_the_host`, `guest-agent/tests/protocol.rs` |
| Jail directory, `OWNER.json`, pid file | root | no | root-only tree | `filesystem/generation.rs` | `generation::tests`, `recovery_tests` |
| Network-namespace handle `/run/acf/netns/acf-<jail_id>` | root | no | 0700 dir, 0600 file | `network/netns.rs` (`unshare --net=`) | `netns::tests`, `isolation/network` |
| cgroup `<cgroup_root>/acf/<jail_id>` | root | no | kernel-enforced limits | `process/limits.rs` + jailer | `isolation/host_control`, `limits::tests` |
| Listening TCP/UDP/raw ports | — | — | **none by design** | — | `test_no_acf_process_listens_on_a_network_port` |
| Inherited file descriptors | VMM | — | the VMM holds none of the host's state | jailer closes | `test_the_vmm_holds_no_descriptor_for_the_hosts_own_state` |
| Shared filesystem paths | — | — | **none**: the guest sees one virtio block device | — | `test_the_guest_has_one_block_device_and_no_shared_filesystem` |
| Privileged devices (`/dev/kvm`) | VMM only (jailer creates the node inside the jail) | no | — | jailer | `test_the_guest_has_no_device_that_is_a_control_channel` |
| Helper interfaces | `firecracker` and `jailer` binaries; `unshare` (util-linux) | — | the two binaries: root-owned, version-pinned, verified by `doctor` and at start; `unshare`: presence checked by `doctor` | `scripts/install-firecracker.sh` | `firecracker::verify::tests`, `doctor::tests` |

### The trusted-file rule

Config, policy and the binaries the host executes are loaded through one function (`admission/trusted_file.rs`):
root-owned (`trusted_owner_uids`), regular file, opened with `O_NOFOLLOW`, not group/world-writable (`mode & 0o022`),
every ancestor directory checked the same way, ≤ 1 MiB. Any failure is `SECURITY_CONTROL_FAILURE` and the file is
**not loaded** — there is no "warn and continue". The policy's identity is the sha256 of the exact bytes verified.

### Control-surface summary for the three isolation claims

* **Network:** the Firecracker configuration has no NIC (authoritative), the VMM sits in a dedicated empty network
  namespace, and the guest agent corroborates (interface list + three egress attempts: `1.1.1.1:53`,
  `[2606:4700:4700::1111]:53`, `169.254.169.254:80`). A guest can only *add* a violation. Violation ⇒ start fails closed
  with a `SECURITY` error and the VMM is killed. Policy offers only `network_modes: [none]`; adding a mode is a
  contract change (spec §18.7), so egress/proxy code is deliberately absent.
* **Filesystem:** the image is hashed *while it is copied* (`filesystem/hashcopy.rs`), so the digest describes the bytes
  the VM will boot, not bytes that may have changed since validation (spec §19.4). All state paths derive from validated
  ids (`ids.rs`) inside capability directories (`cap-std`); persisted paths are never trusted.
* **Process:** the VMM runs as a per-VM uid from a reserved range, in a chroot, a new PID namespace, under seccomp with
  `NoNewPrivs` and no capabilities — read back from `/proc/<pid>/status` after launch (`process/identity.rs::
  SecurityPosture::violations`) and killed if any of it is missing, *before* the VMM is configured.

---

## 5. The operation protocol (spec §8, §12)

```text
request ─► decode (strict) ─► authenticate (SO_PEERCRED) ─► authorise + admit (policy, capacity)
        ─► BEGIN   one durable record: op id, request fingerprint, caller, policy id, reservation
        ─► STEP    write-ahead: the next privileged step is declared BEFORE it runs
        ─► BACKEND the privileged mutation (Firecracker/jailer/guest)
        ─► FINISH  terminal record: status, result, evidence, failure class, side-effect flag
```

* **Refusals leave no trace.** `VALIDATION`, `AUTHORIZATION`, `ADMISSION_REJECTED`, `SCHEMA_MISMATCH`, `NOT_FOUND` are
  answered before BEGIN; no operation record exists, nothing was reserved (`policy_denials_happen_before_any_record_or_side_effect`).
  An unauthorised caller is accepted, sent one `AUTHORIZATION` frame, and closed (status `REJECTED`, `request_id` null).
* **Idempotency.** A mutating request may carry an `operation_id`. Same id + same canonical fingerprint ⇒ the original
  result, nothing re-executed. Same id + different fingerprint ⇒ `CONFLICT`. `retry: true` for an id the host never saw ⇒
  `NOT_FOUND`: a retry is *never* reinterpreted as a fresh request (spec §12.4). The fingerprint is a canonical-JSON
  sha256: key order and whitespace do not matter, `null` equals absent, floats are refused rather than normalised.
* **Statuses.** `ACCEPTED`, `IN_PROGRESS`, `SUCCEEDED`, `FAILED`, `CANCELLED`, `UNKNOWN`, `CONFLICT`, `REJECTED`.
  `UNKNOWN` means *the mutation may have happened*; it is resolved by observation or quarantined — never retried blindly,
  never reported as success.
* **Mutating vs read-only.** Everything except `host_info`, `metrics`, `sandbox_inspect`, `sandbox_list`,
  `snapshot_list`, `operation_get`, `run_inspect` creates an operation (including `operation_cancel` and `policy_reload`).
* **Destructive requests take ids, not names.** `sandbox_destroy` carries `sandbox_id` + `expected_generation`
  (spec §12.5); a name can never retarget a destroy (`names_never_retarget_a_destructive_operation`).
* **Serialisation.** One exec at a time per sandbox (the loser gets `STATE_CONFLICT` *without* a record);
  snapshot and exec exclude each other and need an idle sandbox.

### The narrow journal (spec §10.2, §21)

`operation/journal.rs` is an append-only file of CRC-framed JSON records (`state/journal.wal`, mode 0600) holding only
what recovery needs: operations, sandbox/snapshot generation records, reservations. `Journal::commit_with` is an atomic
*check-and-append*: the capacity check and the reservation it justifies commit together, which is what makes admission
race-free. Failure modes: a torn final line is repaired (earlier state intact); mid-file corruption puts the host in
**read-only quarantine** (no mutation, recovery included); a failed append changes neither memory nor disk; compaction
keeps live state plus the newest terminal operations. A single-instance lock (`state/host-agent.lock`) prevents two
agents sharing a journal.

---

## 6. Lifecycle (spec §11)

```text
REQUESTED → PROVISIONING → READY → RUNNING → COMPLETED
                               │       │  └─► FAILED
                               └───────┴─► PAUSED ─► (back)        any live state → STOPPING → STOPPED → DESTROYED
```

`READY` and `COMPLETED` are the *idle* states (agent up, no run in flight): only they admit `exec` and `snapshot_create`.
The transition relation is one `matches!` in `domain/lifecycle.rs`; everything not listed is forbidden
(`DESTROYED → *`, `FAILED → RUNNING`, `STOPPED → RUNNING`). An illegal transition is `STATE_CONFLICT`.

**Generations.** A sandbox id names a *lineage*; each (re)incarnation is a **generation** (`sbx-…`, gen 1, 2, …).
Operations carry `expected_generation`; a stale reference never acts on the current incarnation
(`stale_generation_references_never_act_on_the_current_incarnation`). Generation directories are never reused.

**Snapshots** (`REQUESTED → SNAPSHOTTING → VERIFYING → READY`, any → `INVALID`, `READY|INVALID → DELETED`): only `READY`
is restorable. Restore is either *in place* (new generation of the same sandbox, old one retired after the switch) or
*as new* (an independent sandbox; the source may be destroyed). A restore never costs the caller their existing sandbox
if it fails (`a_failed_restore_never_costs_the_caller_their_existing_sandbox`).

### Admission and capacity (spec §13.2, §18)

Admission is **atomic with reservation** (`lifecycle/capacity.rs`, inside `commit_with`). For each create/restore it
checks, against the host *envelope* in config and everything already reserved:

| Dimension | Rule |
|---|---|
| vCPUs | `reserved + request ≤ envelope.vcpus`; Firecracker accepts 1 or an even number (also checked) |
| Memory | `reserved + request + vmm_overhead_mib (64) ≤ envelope.memory_mib` |
| Disk | `reserved + request ≤ envelope.disk_mib` (sparse files, budgeted at full size) |
| Sandboxes / uid slots | `≤ max_sandboxes`; the lowest free slot in `uid_range` becomes the VM uid |
| Headroom | free space on the state filesystem after the reservation ≥ `min_free_headroom_mib` |
| Snapshots | count ≤ `max_snapshots`, bytes ≤ `snapshot_quota_bytes`, free-space check |

A request above a **policy ceiling** is refused (`ADMISSION_REJECTED`), never clamped. A failed generation *keeps* its
reservation until destroyed, so a leaked VM can never be hidden by a "free" slot. Per-VM kernel limits (cgroup v2):
`cpu.max = vcpus*100000+25000 / 100000`, `memory.max = (mem+overhead) MiB`, `memory.swap.max = 0`,
`memory.oom.group = 1`, `pids.max = vcpus+32`.

---

## 7. Guest side

**`acf-init`** (`images/overlay/usr/local/sbin/acf-init`, POSIX sh) is PID 1. It is *crash-only*: when init ends for any
reason the kernel panics and, with `panic=1 reboot=k` in the boot args, the VMM exits — the host sees a dead VM, never a
half-alive one. It refuses to run unless it really is PID 1 of a guest, mounts the pseudo-filesystems, hardens
(`kernel.dmesg_restrict=1`, `kernel.kptr_restrict=2`), grows the root filesystem with `resize2fs` to the requested disk
size, raises loopback with `ip`, floors the clock at the image's build time (a Firecracker x86_64 guest has no RTC), then
runs the agent as its child (a shell as PID 1 reaps every orphan for free, including processes a command daemonised).

**`acf-guest-agent`** (static musl) listens on vsock port 5252 and **accepts only peer CID 2** (the host); any other
peer is dropped. Messages (same u32-BE + JSON framing as the host socket): `Hello`, `Ping{nonce}`, `Exec`, `Cancel`
(on a *second* connection, so a cancel is never queued behind the exec it cancels), `Probe`, `NetProbe`, `Shutdown`.

Per command the agent: creates a cgroup-v2 child with `pids.max` (and kills the whole tree with `cgroup.kill`; if
cgroup v2 is unavailable it falls back to `RLIMIT_NPROC` and **says so** in the result's `containment` field); runs as
uid/gid 1000 with an empty environment plus the request's env plus an explicit default `PATH`; stdin is `/dev/null`;
stdout/stderr are pipes with caps; the deadline kills the process group; a descendant that escapes and holds a pipe open
yields an *incomplete* result instead of a hang. Output over the cap is truncated **but fully counted** and the child is
not blocked.

**The host distrusts the agent** (`guest/client.rs::enforce_bounds`): frame size is bounded by the output budget
(never above the hard cap), a lying guest cannot inflate results past policy, a guest that ignores its own deadline is
killed by the host backstop (the run is reported `TIMED_OUT`, the sandbox `FAILED`).

---

## 8. Images (spec §19)

An **image alias** (`base`, `python`, `node`, `browser`) resolves to `images/<alias>/` containing a kernel, a root
filesystem and `manifest.json`. **Identity = sha256(manifest bytes)**; the manifest records kernel/rootfs digests,
sizes, guest-agent version, provenance (pinned vs `unpinned`) and boot args. The host re-verifies on use, copying the
rootfs *while hashing it* into the generation directory (holes preserved), so a swapped source yields a different digest,
not a silent success. Build path: `scripts/build-image.sh` → `create-rootfs.sh` (a container-filesystem tarball → one ext4
file with the features pinned in `scripts/mke2fs.conf`, setuid/setgid stripped, `acf-init` and the static agent installed) →
`tools/write_image_manifest.py` → `--install`. Pins live in `images/images.lock`; `scripts/pin-images.sh` resolves tags
to digests; `build-image.sh` **refuses** UNSET pins unless `--allow-unpinned` (recorded in the manifest).

## 9. Snapshot and restore oracle (spec §20)

A snapshot is a *full* Firecracker snapshot (memory + state) plus a disk copy, bound to the journal by digest: the
manifest names every artifact with sha256 and size, the host's own CPU fingerprint (flag order and duplicates ignored,
content not), Firecracker version, security-profile id and image identity. `artifacts_are_reverified_from_disk` — at
restore, the bytes on disk are re-hashed; a changed artifact, a changed manifest, or a deleted directory invalidates
the snapshot and it is never loaded (`a_tampered_snapshot_is_refused_before_any_vmm_is_launched`). Compatibility
differences are named individually.

**The restore oracle (spec §20.5):** at snapshot time the host probes the guest for a *baseline* (`boot_id` + a canary
file's sha256 + `agent_version`). After restore the same probe must reproduce the same digest, and a **reboot is
detected** because `boot_id` changes. A restore that does not reproduce the baseline is rejected. Snapshots contain
guest memory: treat them as secrets (0700 root; `doctor` fails on a state root open to group/other).

## 10. Recovery (spec §22)

At start, **recovery runs before the socket is bound**; the socket appearing is the readiness signal.
`recovery/classify.rs` is a pure function `classify(op, generation_state, has_handle, observed, switched) -> Plan`, so
every row of the table is a unit test:

| Operation was… | Observed | Plan |
|---|---|---|
| any, directory ownership **unprovable** | anything | `Quarantine` — wins over every other rule; nothing is deleted |
| `sandbox_create` | nothing exists | `AbandonUntouched` |
| `sandbox_create` | partial resources, provably ours | `CleanupThenFail` |
| `sandbox_start` | no VMM | `AbandonUntouched` (stays startable) |
| `sandbox_start` | VMM exists | `StopAndMarkFailed` (a VMM never recorded READY is stopped, not trusted) |
| `exec` | anything | `FailSafeUnknown` — stop the VMM, generation `FAILED`, operation `UNKNOWN`; **never retried** |
| `sandbox_stop`/`destroy`, `snapshot_delete` | any | `RetryIdempotent` |
| `snapshot_create` | any | `DiscardSnapshot` (bring the guest back, drop partial artifacts, release quota) |
| `snapshot_restore` | before the switch | `AbandonUntouched` / `CleanupThenFail` (old generation kept) |
| `snapshot_restore` | after the switch | `RetireSuperseded` (finish retiring the old generation) |
| `policy_reload` | any | `AbandonUntouched` |

Idle `READY`/`COMPLETED` sandboxes whose recorded `ProcessIdentity` (pid + start-time ticks + boot id) still matches
are **adopted**; a process that merely *holds the recorded pid* is classed `Foreign` and is never signalled. A record
recovery has touched `max_attempts` (3) times is quarantined, not retried forever. Orphan directories are flagged once
and never deleted. A host reboot voids monotonic deadlines safely (`remaining` is `None` across a reboot).

---

## 11. Failure taxonomy and the CLI contract

`FailureClass`: `VALIDATION`, `AUTHORIZATION`, `STATE_CONFLICT`, `ADMISSION_REJECTED`, `RESOURCE_EXHAUSTION`,
`TIMEOUT_UNKNOWN`, `BACKEND_UNAVAILABLE`, `BACKEND_CRASH`, `CORRUPT_INPUT`, `SCHEMA_MISMATCH`, `COMPATIBILITY_FAILURE`,
`PARTIAL_COMPLETION`, `LOST_RESPONSE`, `SECURITY_CONTROL_FAILURE`, `EVIDENCE_INCOMPLETE`, `OUTPUT_LIMIT`,
`RECOVERY_QUARANTINED`, `UNSUPPORTED`, `NOT_FOUND`, `INTERNAL`. Each failure carries a `side_effect` (`none` | `possible`)
and the wire `ErrorBody` carries `retryable` / `outcome_unknown` — mutually exclusive and conservative.

| Exit | Meaning | What the caller should do |
|---|---|---|
| 0 | ok | — |
| 1 | the *workload* failed (non-zero exit, timeout) | read the evidence; the platform worked |
| 2 | usage error | fix the command line |
| 3 | **refused** — nothing changed | change the request, retry freely |
| 4 | definitive failure | nothing is half-done; inspect the evidence |
| 5 | **unknown** | *observe* (`operation get`, `sandbox inspect`); never blindly re-run |
| 6 | host unreachable | start/repair the agent; nothing changed |
| 7 | protocol violation | version skew or a bug; stop |
| 130 | interrupted | the command was cancelled with its whole tree |

## 12. Configuration vs policy vs identity

| Question | Answered by | File |
|---|---|---|
| *Where do things live, how big is this machine?* | **config** | `/etc/acf/host.yaml` (`config/host.example.yaml`): paths, `envelope`, `firecracker`, `recovery`, `security` |
| *What may a caller do, and how much may it use?* | **policy** | `/etc/acf/policy.yaml` (`policies/default.yaml`): ceilings, defaults, capabilities, execution identity |
| *Who is the caller?* | **the kernel** | `SO_PEERCRED` on the socket |

Policy is **immutable per operation**: each run records the digest of the policy it was admitted under, and reloading
(`policy_reload`, admin only) changes only future operations. Shipped envelope: 4 vCPU, 8 GiB, 64 GiB disk, 16 sandboxes,
32 GiB / 64 snapshots. Shipped ceilings: 4 vCPU, 4096 MiB, 8192 MiB disk, 1 h, 1024 pids, 8 MiB stdout/stderr — chosen so
the milestone command fits. The shipped pair is checked for consistency by `shipped_files_tests`.

## 13. State on disk

```text
<state_root>/                 0700 root          (default /var/lib/acf)
  state/        journal.wal, host-agent.lock     0600 files
  images/<alias>/                                 kernel, rootfs, manifest.json (root-owned, verified on use)
  sandboxes/<sbx>/<gen>/      OWNER.json, jail/…  one directory per generation; marker proves ownership
  snapshots/<snp>/<gen>/      memory, state, disk, manifest
  artifacts/<art>/            spilled large outputs, digest-verified on every read (tampering is detected)
<runtime_dir>/  (/run/acf)    host-agent.sock, netns/acf-<jail_id>
<cgroup_root>/<cgroup_parent>/<jail_id>/          per-VM limits (cgroup v2)
```

Telemetry (`telemetry/events.rs`, `metrics.rs`): a bounded in-memory event ring with strictly increasing sequence numbers
mirrored to JSON lines, and process-local counters/gauges served by `host metrics`. **Telemetry is never authority**: a
dead log file degrades diagnostics and nothing else (spec §23.1; `a_dead_log_file_degrades_telemetry_without_failing_the_caller`).
Security evidence (VMM posture, network verdict) is different: failing to obtain it **fails closed**.

---

## 14. Test architecture

* **Make is the gate.** CI calls make targets; `tests/scripts/test_makefile_and_ci.py` fails if a workflow or a doc names
  a target that does not exist, if `make release` could build with the test-only feature, or if `make ci` pulls in
  something CI never runs.
* **Pyramid.** Pure functions first (lifecycle table, admission arithmetic, fingerprint, recovery classification,
  network verdict, posture parser) → contract tests over the real coordinator with an in-memory backend
  (`testing/contract_tests.rs`, `recovery_tests.rs`, `server_tests.rs`) → the **real Firecracker backend logic** against a
  fake Firecracker and the **real guest agent** (`fc_backend_tests.rs`) → the CLI against the real server over a real
  socket (`apps/cli/tests/test_e2e.py`) → KVM-only integration and isolation suites against real microVMs.
* **Dual mode.** KVM suites are *skipped* unless `ACF_INTEGRATION=1`; when enabled, a missing environment **fails**.
  Tests marked `control_plane` also run under `ACF_CONTROL_PLANE=1` against `acf-host-fake` loaded with the **shipped**
  config and policy (`make control-plane`), so authorisation, admission and policy semantics are exercised on every push
  without KVM. `ACF_REQUIRE_ROOT=1` turns root-needing skips into failures (CI's root step).
* **Black-box driver** (`tests/helpers/acf_driver.py`): drives only `acf-local` and a raw wire client; reads `/proc` for
  white-box isolation facts (`acf_proc.py`, with its parsers unit-tested against fabricated tables *and* this kernel).
  The driver is itself tested against an in-memory host (`make driver-selftest`).
* **Crash points.** `testing/fault.rs` injects failure at each journal/backend step; every recovery row of §10 has a test.

---

## 15. Known gaps (read before relying on Phase 1)

Honest list; none is hidden in code comments. See [VERIFICATION_STATUS.md](VERIFICATION_STATUS.md) for the execution evidence.

1. **Nothing here has booted a real microVM.** The authoring environment has no `/dev/kvm`. The Firecracker adapter is
   verified against a faithful fake and the *real* guest agent; the kernel, jailer, seccomp, vsock and cgroup behaviour are
   proven only by the KVM suites, which have **not been run**. Expect first-run corrections.
2. **Pins are UNSET.** Base-image digests, kernel digests and Firecracker tarball digests are `UNSET` because the registries
   and release assets were unreachable; the installer and image builder refuse to proceed until they are pinned
   (`make check-pins-release` fails by design). Base-image *tags* were not re-resolved.
3. **Guest agent version is recorded, not enforced.** The host does not compare `manifest.guest_agent_version` with the
   agent's `Hello.agent_version`.
4. **Guest wall clock is only floored** at the image build time; the host does not push real time in Phase 1.
5. **Online resize and lazy inode-table cost are unmeasured** (`resize2fs` at boot; needs a real guest to time).
6. **Image bytes are not bit-reproducible**; identity is the digest of the bytes actually built, recorded in the manifest.
7. **`network=none` only**, one host, local callers only. No egress proxy, no allowlists, no remote protocol, no
   multi-tenant authorisation, no scheduler (spec §4.4, Gate H).
8. **No file-transfer API.** Code and data reach a sandbox through the image or the command itself.
9. **Single-flight exec per sandbox; no stdin/TTY.** Deliberate for evidence quality; Phase 2 may add sessions.
10. **Snapshots are same-host, same-Firecracker-version, same-CPU-fingerprint artifacts**, and contain guest memory.
11. **Telemetry is process-local**: counters and an event ring, no exporter, no cross-restart history beyond the JSON log.
12. **Systemd hardening is moderate** by design (the daemon is root; tightening needs a KVM host to prove nothing breaks).
13. **Supply-chain checks not run here:** `cargo audit`, `pip-audit` (advisory databases unreachable); GitHub Actions are
    pinned by commit SHA, but the SHAs were resolved from the git remote, not from each project's signed release notes.
14. **Fake backend cannot test cancellation/interrupt**; those paths are covered by the real-guest-agent tests and the
    KVM suites only.
15. **Quarantine has no release command.** A generation whose ownership could not be proven stays flagged (and keeps its
    reservation); `sandbox destroy` refuses it with `RECOVERY_QUARANTINED`. The operator clears it by hand
    ([OPERATIONS.md §7.1](OPERATIONS.md)). A corrupt journal likewise has no repair tool, only the documented
    move-aside-and-inspect procedure (§7.2). Both are deliberate "never guess" choices; a supervised release is Phase 2 work.

## 16. How it should evolve (seams Phase 2 may rely on)

* **Backends:** implement `SandboxBackend` (+ `CapabilityProfile`); unsupported operations return `UNSUPPORTED`, a stable
  result (DELTA-018). The lifecycle, journal and recovery do not change.
* **Network modes:** a new mode needs a policy entry, a `NetworkEvidence` verdict function and its own adversarial test
  suite *before* it appears in `capabilities.network_modes`.
* **Transport:** `server/` is the only place that knows about Unix sockets; `protocol/` is transport-neutral and
  schema-generated (`schemas/*.json`), which is the seam for a remote control plane (which must add mTLS and tenancy —
  explicitly *not* Phase 1).
* **Journal:** the narrow-journal rule keeps migration to an embedded database a storage change, not a semantic one.
* **Multi-host:** the envelope, generation and operation-identity model already assume nothing about "one machine"
  except the uid pool and the state root.

---

### Compressed summary
Phase 1 is a crash-honest ledger in front of a jailed VM: record intent first, act, verify the kernel really enforced
the confinement, and after any crash let a pure table decide — adopt, clean, quarantine, or admit *unknown*.

### Three insights
1. **Verification beats configuration.** The host reads `/proc` back after launch; it never assumes the jailer worked.
2. **`UNKNOWN` is a feature.** Refusing to round an ambiguous `exec` to success/failure is what makes retries safe.
3. **Pure cores make the hard parts testable without KVM** (recovery table, admission, network verdict, fingerprint).

### Three risks
1. The KVM-only behaviour (seccomp, vsock, cgroup values, `ip`, `/dev/kmsg`) is unproven until the first real run.
2. UNSET pins mean the first real image is built from unverified inputs unless the operator pins them first.
3. A root daemon with moderate systemd hardening: the controls that matter live in the jailer, per-VM uid and trusted-file
   loader — a bug in those is the whole blast radius.

### Next best question
*"On a real KVM host, which of the 64 skipped-in-control-plane tests fails first, and is it a bad assumption in a probe
or a real isolation gap?"* — run `make integration` per [OPERATIONS.md](OPERATIONS.md) and read the first failure.
