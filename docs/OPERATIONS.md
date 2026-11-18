# Operations — installing, running and recovering the host agent

Audience: the person who owns the machine. This is the operator's manual of the execution plane: one host
binary, `acf-host`, that boots Firecracker microVMs as sandboxes and answers a small API about them.

Everything here follows the path the `integration` workflow (`.github/workflows/integration.yml`) takes, in the
same order, so a green run of that workflow is a rehearsal of this document. Until such a run exists on your
hardware, treat the procedures as unrehearsed on a KVM host (see [VERIFICATION_STATUS.md](VERIFICATION_STATUS.md)):
expect to correct something on first contact, and send the correction back.

The client is not described here. The reference client lives in `apps/cli` and speaks the host API over the
local socket or over mutual TLS; its commands are in [`apps/cli/README.md`](../apps/cli/README.md). This manual
names API *methods* (`host.info`, `host.set_mode`, …): call them with that client or with your own.

---

## 1. What runs on the machine

One binary, several roles. The roles are processes, not services of their own: they share one version.

| Role | Started by | Runs as | What it is |
|---|---|---|---|
| **core** (`acf-host serve`) | `acf-host.service` | root | coordinator, durable store, Firecracker/jailer backend, recovery. The only writer. |
| **edge** (`acf-host edge`, internal) | the core, by re-executing its own image | `edge.uid` / `edge.gid`, no capability | the only process that reads bytes from a caller: authenticates, limits, decodes, hands validated commands to the core |
| **guest-traffic** (`acf-host guest-traffic`, internal) | the core, one per sandbox in network mode `allowlist` | that sandbox's own uid, no capability | answers DNS for listed names and relays TCP to listed destinations; if it stops, the sandbox has no connectivity |
| **lifetime enforcer** (`acf-host lifetime`) | `acf-lifetime.service` | root, one capability | ends every runtime at its expiry, whether or not the core runs |

Three systemd units ship in `deploy/systemd/`:

| Unit | Purpose |
|---|---|
| `acf-cgroup.service` | once per boot: creates the cgroup v2 parent (`<cgroup_root>/acf`) with `cpu`, `memory`, `pids` delegated |
| `acf-lifetime.service` | the lifetime enforcer; always restarted, never stopped with the core |
| `acf-host.service` | the core (which starts the edge and the guest-traffic processes itself) |

Where things live (the defaults of `config/host.example.yaml`):

```text
/opt/acf/bin/{acf-host,firecracker,jailer}       /opt/acf/libexec/{acf-setup-cgroup,acf-wait-ready}
/etc/acf/host.yaml        where things live, how big this machine is, every bound
/etc/acf/profile.yaml     the safety profile: what one request may consume, which capabilities exist
/etc/acf/enrolment.yaml   who may call this host, and in which role
/etc/acf/secrets/         0700; one file per secret reference
/etc/acf/tls/             optional: host.crt, host.key, clients-ca.crt for the mutual-TLS endpoint
/var/lib/acf/             0700 root; durable state
    state/journal.wal         the store        state/host-agent.lock    the single-instance lock
    state/journal.reserve     capacity kept back so that a full disk never prevents recording a destroy
    images/ sandboxes/ snapshots/ artifacts/   telemetry/events.jsonl
/run/acf/                 0755; volatile
    host-agent.sock           the local endpoint (mode and group from host.yaml)
    netns/                    0700; one handle per sandbox network namespace
    expiry/                   0700; expiry tickets and the enforcer's heartbeat
```

All files under `/etc/acf` and every program the core runs are **trusted inputs**: a regular file (no symlink),
owned by root, not writable by group or other, inside directories with the same property, at most 1 MiB for the
three YAML files. The host does not use an input that fails this rule; it says which one and why.

## 2. What the machine must provide

`acf-host doctor` checks each line; the name in the last column is the check's name in its report.

| Requirement | Why | Check |
|---|---|---|
| Linux ≥ 5.10 on x86_64 or aarch64 | pidfd, openat2, cgroup v2 | `kernel` |
| `/dev/kvm` usable by root | Firecracker | `kvm` |
| cgroup v2 (unified) with `cpu`, `memory`, `pids`; the parent `<cgroup_root>/acf` delegating them | per-VM limits, and one sibling group per `allowlist` sandbox for its guest-traffic process | `cgroup_v2`, `cgroup_parent` |
| root-owned `firecracker` and `jailer`, each with the bytes pinned in `host.yaml` (`firecracker.firecracker_sha256`, `firecracker.jailer_sha256`) and at the pinned version (`firecracker.pinned_version`) | executed as root, so what runs must be what was pinned; a snapshot is valid only on the version that took it | `firecracker` |
| util-linux `unshare` at `network.unshare_bin` | creates every sandbox's network namespace, in both network modes. **Without it no sandbox can be created.** | `unshare` |
| iproute2 `ip`, nftables `nft`, util-linux `nsenter` at `network.ip_bin`, `nft_bin`, `nsenter_bin` | build the namespace of an `allowlist` sandbox. Without them that mode is not offered; mode `none` works. | `network_tools` (a warning) |
| an unprivileged user for the edge, outside both per-sandbox uid ranges | the edge holds no privilege | `edge_identity` |
| no local account inside `firecracker.uid_range_start … +uid_range_size` (100000, 4096) or `network.traffic_uid_start … +uid_range_size` (200000) | one uid per VMM and one per guest-traffic process; a sandbox must never run as a real user | `uid_range`, `traffic_uid_range` |
| `/var/lib/acf` private (0700) with at least `envelope.min_free_headroom_mib` free | the store, images, snapshots (guest memory!) | `state_root` |
| the lifetime enforcer running | a runtime launched without it could outlive its expiry | `lifetime` (a warning before the first start) |
| a safety profile that loads and fits the envelope; an enrolment table that loads | what a request may consume; who may call | `profile`, `enrolment` |
| no swap; SMT off; kernel same-page merging off (`echo 0 > /sys/kernel/mm/ksm/run`; a kernel without it passes) | guest memory must not be paged to disk; sibling hyperthreads share a core; merged pages are shared between sandboxes, a timing side channel | `swap`, `smt`, `ksm` (warnings) |

To build: a Rust toolchain (`rust-toolchain.toml` pins it; plus the musl target for the guest agent), `uv`,
and for images Docker with BuildKit. `scripts/host-setup.sh prerequisites` reports on `ip`, `nft`, `nsenter` and
`unshare` alone, with the package to install for each.

## 3. Install

```bash
# 0. Build, as your normal user. `make release` builds acf-host without any test-only code and proves it.
make release
make guest-agent                      # the static guest agent for the images

# 1. Firecracker and the jailer, pinned and digest-verified (scripts/firecracker.lock). The installer
#    prints two lines on stdout: the digest of each installed binary. Keep them for step 4.
sudo scripts/install-firecracker.sh | tee firecracker-digests.txt

# 2. The host agent: the edge user, the directories, the three trusted files, the three units.
#    Idempotent. It starts nothing and never overwrites a file of yours in /etc/acf.
sudo scripts/host-setup.sh install --acf-host target/release/acf-host

# 3. A guest image. Needs root, Docker, a LARGE disk-backed TMPDIR and a guest kernel (images/README.md).
sudo --preserve-env=TMPDIR scripts/build-image.sh --image python --kernel /path/to/vmlinux --install

# 4. Review /etc/acf (sections 3.2 to 3.5): put the two lines of step 1 into the `firecracker`
#    section of /etc/acf/host.yaml. Then ask the machine.
sudo /opt/acf/bin/acf-host doctor --config /etc/acf/host.yaml

# 5. Start: control groups, the lifetime enforcer, then the core (section 5).
sudo systemctl enable --now acf-cgroup.service acf-lifetime.service acf-host.service
```

### 3.1 Pins

| Input | Where | State in the repository |
|---|---|---|
| Firecracker tarball, per architecture | `scripts/firecracker.lock` (`VERSION`, `SHA256_<arch>`) | pinned. `install-firecracker.sh` measures what it downloads and refuses on any difference; `--print-digest` prints the measurement without installing. |
| The installed `firecracker` and `jailer` binaries | `host.yaml`: `firecracker.firecracker_sha256`, `firecracker.jailer_sha256` | unset in the example on purpose: the installer prints both for the files it installed from the verified tarball. The host hashes each file at startup and before every launch. |
| Base images (registry digests) | `images/images.lock` `BASE_DIGEST_<name>` | `UNSET`: `scripts/pin-images.sh --write` resolves them (`crane`, `skopeo` or `docker buildx`) |
| Guest kernel, per architecture | `images/images.lock` `KERNEL_SHA256_<arch>` | `UNSET`: `sha256sum` your uncompressed `vmlinux` into the lock (`images/README.md` says where kernels come from) |

`make check-pins` keeps the pin files consistent with each other and with `config/host.example.yaml`;
`make check-pins-release` fails while anything is `UNSET` and is the release gate. `build-image.sh` exits 3 on an
unset pin; `--allow-unpinned` is for development and stamps the image's manifest, so an unpinned image can never
pass for a pinned one. `firecracker.pinned_version` in `host.yaml` must equal `VERSION` in the lock.

The two binary digests are the host's own pin, separate from the tarball's: the tarball digest says what was
downloaded, and the binary digests say what the host will run as root. While either is unset, or the installed
file no longer hashes to it, `doctor` reports `firecracker` as failed and the host creates no sandbox. A
binary that changes while the host runs is refused at the next start or restore, with `INTEGRITY_FAILURE`.

### 3.2 What `host-setup.sh install` does

* Refuses an `acf-host` that contains test-only code (`scripts/check-release-purity.sh`), before touching anything.
* Creates user `acf-edge` (with its group) and group `acf` from `deploy/sysusers.d/acf.conf`, with
  `systemd-sysusers` where it exists and with `useradd`/`groupadd` otherwise. Existing accounts are left as they are.
* Creates `/opt/acf/{bin,libexec}`, `/etc/acf`, `/etc/acf/secrets` (0700) and `/var/lib/acf` (0700); installs the
  binary and the two helpers; installs the units, `tmpfiles.d/acf.conf` and `sysusers.d/acf.conf`; creates
  `/run/acf`, `/run/acf/netns` and `/run/acf/expiry` through `systemd-tmpfiles`.
* Installs `config/host.example.yaml`, `profiles/default.yaml` and `config/enrolment.example.yaml` as
  `/etc/acf/host.yaml`, `profile.yaml` and `enrolment.yaml` **if they are absent**. A file of yours is kept; the
  shipped version is written beside it as `*.dist` when the two differ (`--force-config` replaces yours).
* Writes the edge user's ids into a `host.yaml` it installs (`edge.uid`, `edge.gid`). It never edits a `host.yaml`
  of yours: it prints the ids, and so does `scripts/host-setup.sh user` at any later time.
* Says which of `ip`, `nft`, `nsenter`, `unshare` is missing or would not be trusted, and what the host cannot do
  without it. It installs no package.

`--destdir DIR` stages every file under `DIR` and changes nothing else on the machine (packaging);
`--edge-ids UID:GID` then writes the ids the target machine will use. `--prefix` and `--state-root` are written
into the units, the tmpfiles entry and the installed `host.yaml`.

### 3.3 `host.yaml`: this machine

Read the comments in `config/host.example.yaml`; they are the reference. What an operator must decide:

* `host_id`: the name of this deployment. It labels every event and is the name clients address.
* `edge.uid`, `edge.gid`: **required** when the core runs as root. The core refuses to start without `edge.uid`.
* `envelope`: what this machine may promise. Admission reserves against it and refuses what does not fit; it
  never overcommits and never shrinks a request. Size it below what the host has. Per sandbox the host budgets
  `memory + firecracker.vmm_overhead_mib` and the disk at full size; a failed sandbox keeps its reservation
  until it is destroyed.
* Every bound is finite; zero never means "unlimited". Some bounds must hold a relation to another (the file
  says which: for example `operations.wait_max_ms` below the shortest operation deadline, and
  `envelope.max_sandboxes × (max_stdout_bytes + max_stderr_bytes)` of the profile within
  `envelope.agent_memory_mib`). A broken relation does not stop the host: it starts in `CONTAINMENT`.

If you change `paths.runtime_dir`, `paths.socket_path`, `paths.state_root` or `firecracker.cgroup_parent`, change
the same path in the units and in `deploy/tmpfiles.d/acf.conf`: the units name the defaults.

### 3.4 `profile.yaml`: what one request may consume

The safety profile is the host's own floor: ceilings per sandbox and per command, defaults for what a request
leaves out, and the capabilities that exist here (network modes, image aliases, exec, snapshots, secret injection,
private destinations). It holds no rule about tenants, users or prices. A request above a ceiling, or for a
capability that is not granted, is refused with `SAFETY_CONTROL_DENIED`; nothing is clamped. Keep each ceiling
at or below the envelope. Changing it is section 7.

### 3.5 `enrolment.yaml`: who may call

A credential that is not listed has no authority, however valid it is. One entry names one peer:

```yaml
schema_version: 1
peers:
  - peer_id: local-root          # the name records and events carry; allocated here, never taken from a request
    role: operator               # observer | caller | operator
    match: { local_uid: 0 }      # exactly one of: local_uid, local_gid, certificate_sha256, spki_sha256
```

| Role | May call |
|---|---|
| `observer` | `host.info` and `host.metrics` only |
| `caller` | every granting, containment and read method, on records that carry its own tags |
| `operator` | everything a caller may call, on any record, plus `profile.reload`, `quarantine.release`, `host.set_mode`, `host.acknowledge` |

**Local callers.** The socket is created 0600, then opened to `edge.socket_mode` and `edge.socket_gid`. Reaching
the socket is not authority: the edge matches the uid the kernel reports (a `local_uid` entry), or else the
caller's primary gid (a `local_gid` entry). To let a group of people use the host: set `edge.socket_gid` to the
gid of group `acf` (`getent group acf`), restart the core, and enrol them by uid or by primary gid.

**The network endpoint (optional).** Mutual TLS 1.3; there is no TLS 1.2 and no anonymous mode.

```bash
sudo install -d -m 0700 -o root -g root /etc/acf/tls
sudo install -m 0644 -o root -g root host.crt clients-ca.crt /etc/acf/tls/
sudo install -m 0600 -o root -g root host.key /etc/acf/tls/
```

```yaml
# /etc/acf/host.yaml
edge:
  tls:
    listen: "0.0.0.0:7443"
    certificate: /etc/acf/tls/host.crt       # must carry host_id as a subject alternative name
    private_key: /etc/acf/tls/host.key
    trust_anchors: /etc/acf/tls/clients-ca.crt
```

The trust anchors are the ones you list; the system trust store is never used. A client certificate that chains
to an anchor is only *authenticated*. It has authority when an enrolment entry names it, in one of two ways:

```bash
# by certificate: changes whenever the certificate is re-issued
openssl x509 -in client.crt -outform DER | sha256sum

# by public key: survives re-issuing the certificate for the same key
openssl x509 -in client.crt -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum
```

```yaml
  - peer_id: control-plane-1
    role: caller
    match: { spki_sha256: "<the 64 lower-case hex characters printed above>" }
```

The core reads the three TLS files once, at start: changing them needs a restart. A certificate, key or anchor
it cannot use, a certificate that does not name `host_id`, or an address it cannot listen on leaves the network
endpoint closed and the host in `CONTAINMENT` (reason `mandatory_check`); the local endpoint still works.

**Changing the table.** Edit the file; no restart. The core re-reads it while it runs, and a removed entry stops
working, on open connections too, within `edge.enrolment_refresh_ms`. A file it cannot use is not used: the
previous table stays in force and `enrolment_reload_failures` counts. One credential names one peer, and one
peer has one role; a table that says otherwise is refused as a whole.

### 3.6 Secrets

`/etc/acf/secrets/` holds one file per secret reference, for the built-in provider. A request never carries
secret material, only a reference; the file is read, through the trusted-input rule, at the moment of delivery.
Whether delivery exists at all is a capability: `capabilities.secret_injection` in the profile, and the backend
must offer it. `host.info` reports what the backend offers (`capabilities`); the Firecracker backend declares
that it does not, so a request that needs a secret is refused as unsupported.

## 4. `acf-host doctor`

```bash
sudo /opt/acf/bin/acf-host doctor --config /etc/acf/host.yaml            # one line per check
sudo /opt/acf/bin/acf-host doctor --config /etc/acf/host.yaml --json     # the same, for a program
```

Each check is `PASS`, `WARN` (works, with less margin than the profile assumes) or `FAIL`. The exit status is 1
when any check fails. `acf-host.service` prints the report into the journal before every start.

A `FAIL` does **not** keep the core from starting. A host that will not start cannot destroy what it already
runs, so a failed mandatory check makes the core start in `CONTAINMENT`: it stops and destroys, answers reads,
and creates nothing. What does keep the core from starting is the first row of section 13.

## 5. Starting and stopping

**Order.** `acf-cgroup.service` → `acf-lifetime.service` → `acf-host.service`. The units encode it; enabling all
three is all an operator does. Why this order:

* The enforcer must be reporting before the core creates anything. The core reads the enforcer's heartbeat
  (`<runtime_dir>/expiry/enforcer.alive`) and, while it is older than `lifetime.heartbeat_max_age_ms`, is in
  `CONTAINMENT` with reason `lifetime_enforcer_unavailable`.
* The core recovers before it opens an endpoint: it resolves what an earlier activation left in flight and
  observes every sandbox once, within `recovery.startup_deadline_ms`. Only then does it listen. The unit is
  "started" when a process listens on the local socket, so anything ordered after it can connect.

**Stopping the core** (`systemctl stop acf-host`, or a restart) sends it SIGTERM. It stops creating sandboxes,
lets operations in flight finish for up to `operations.drain_timeout_ms`, ends its edge and exits. What a stop
does **not** end: VMs, guest-traffic processes and the lifetime enforcer. They are not members of the unit, so
systemd does not signal them, and the next activation adopts what it finds. To end sandboxes, destroy them
(`sandbox.destroy`) before stopping; otherwise each still ends at its expiry.

**Never stop the enforcer on a host that runs sandboxes.** While it is down nothing bounds a runtime's lifetime
if the core is down too, and the core is in `CONTAINMENT`. `systemctl restart acf-lifetime` is safe: it keeps
nothing in memory that it cannot rebuild from its tickets.

After a **reboot** no runtime exists. The tickets and namespace handles were on `/run`; the core marks what was
running as failed, and every sandbox's expiry is carried over, never lengthened.

**Hardening of the units** is explained in the unit files. One rule for anyone adding a drop-in to
`acf-host.service`: no option that gives the unit a mount namespace of its own (`ProtectSystem=`, `ProtectHome=`,
`PrivateTmp=`, `ReadWritePaths=` and the like), no device restriction, no `ProtectControlGroups=`. A sandbox's
network namespace is kept alive by a bind mount under `/run/acf/netns`; made inside a private mount namespace it
is invisible to the next activation, which then cannot prove that an adopted VM is inside its namespace and
stops it.

## 6. Host modes

`host.info` reports `mode`, and with it `containment_reasons` or `read_only_reason`. A refusal that is caused by
the mode has class `HOST_NOT_SERVING`.

| Mode | Granting (create, start, exec, snapshot, restore) | Containment (stop, destroy, delete, cancel) | Reads | Operator methods |
|---|---|---|---|---|
| `STARTING` | no endpoint is open | | | |
| `SERVING` | served | served | served | served |
| `DRAINING` | refused | served | served | served |
| `CONTAINMENT` | refused | served | served | served |
| `READ_ONLY` | refused | refused | served | refused |

| Mode | How the host gets there | How to leave it |
|---|---|---|
| `STARTING` | every start, until startup recovery ends | wait. It is bounded by `recovery.startup_deadline_ms`; a sandbox not yet observed by then is quarantined and the host goes on. |
| `SERVING` | recovery is complete and nothing below applies | |
| `DRAINING` | an operator called `host.set_mode` with `DRAINING`, or the core received SIGTERM | `host.set_mode` with `SERVING`. A restart also leaves it: draining is not remembered across activations. |
| `CONTAINMENT` | one or more reasons hold (next table); the mode lasts while any remains | remove every reason |
| `READ_ONLY` | the store cannot be written or interpreted | section 9 |

`CONTAINMENT`, by reason (`containment_reasons[].reason`, with the detail beside it):

| Reason | Meaning | How it clears |
|---|---|---|
| `mandatory_check` | a preflight check failed (the detail starts with the check's name), a relation between two bounds of `host.yaml` is broken, the enrolment table could not be used at start, or the network endpoint could not be opened | fix the cause and **restart the core** |
| `invalid_profile` | the safety profile could not be loaded or validated at start; the host runs a profile that denies everything | fix `/etc/acf/profile.yaml`, then `profile.reload` |
| `lifetime_enforcer_unavailable` | the enforcer's heartbeat is missing or stale | start `acf-lifetime.service`; the reason clears by itself at the core's next sweep |
| `store_regression` | an ownership marker on disk is newer than the store: the store is older than the system it describes | section 8 |

`host.set_mode` cannot ask for `SERVING` while the host is in `CONTAINMENT`: the cause has to go first.
In `READ_ONLY` the host takes no action it cannot record. Runtimes still end at their expiry: that is the
enforcer's job, and it needs neither the core nor the store.

## 7. Routine procedures

Operator methods are recorded operations and run one at a time for the host.

**Planned restart, with a drain.**

1. `host.set_mode` with `DRAINING`. Nothing new is created; stop, destroy, reads and operator methods still work.
2. Watch `operations_in_flight` in `host.info` reach 0, or decide that you have waited long enough.
3. `systemctl restart acf-host`. Correctness never depends on the drain: an operation still in flight when the
   core stops is resolved by the next activation, never continued. A granting operation is undone; an execution
   that was running ends `UNKNOWN`, its sandbox `FAILED`, and it is never run again.
4. The new activation is `SERVING` again once recovery ends. VMs were not touched and are adopted.

**Reloading the safety profile.** Edit `/etc/acf/profile.yaml` (keep it a trusted input), then `profile.reload`.
The new profile governs later operations only; an operation in flight keeps the profile it was admitted under.
A file that does not validate, or does not fit the envelope, is refused and the previous profile stays in force.

**Changing who may call.** Edit `/etc/acf/enrolment.yaml`; see 3.5. No method, no restart.

**Changing `host.yaml`.** Restart the core; run `doctor` first. If the change touches `lifetime.*`,
`paths.runtime_dir` or `firecracker.cgroup_root`, restart `acf-lifetime.service` as well: the enforcer reads the
same file.

**A sandbox that expired.** Nothing to do. At its expiry the core destroys it; if the core is down or slow, the
enforcer ends its runtime within `lifetime.expiry_tolerance_ms` and the core cleans up when it next looks.

## 8. Quarantine, unmanaged resources and an older store

### 8.1 A quarantined sandbox

The host quarantines a sandbox generation when it cannot prove that the generation's resources are its own to
remove, or cannot contain it after `recovery.max_attempts` attempts, or could not observe it before the startup
recovery deadline. **It deletes and signals nothing it cannot prove it owns.** A quarantined generation keeps its
reservation (it counts against capacity), accepts no operation except `quarantine.release`, and answers
`sandbox.destroy` with `QUARANTINED`. `host.info` counts them (`quarantined`); `sandbox.inspect` gives the reason.

`quarantine.release` takes the sandbox id, the generation and one of two assertions. The assertion is yours; the
observation is the host's, and both are recorded in the operation.

| Mode | You assert | The host does |
|---|---|---|
| `FORCE_DESTROY` | "the resources recorded for this generation belong to this host" | stops the recorded runtime (never a process that merely holds its pid), removes the generation's control groups, network namespace and directory, then looks |
| `DECLARE_ABSENT` | "nothing remains" | only looks |

In both modes the host then checks for what the generation recorded: its runtime process, any process running as
its uid, its control group and guest-traffic control group, its network namespace, its directory. Only when it
finds nothing does the generation become `DESTROYED` and its reservation return. If anything is found, the
release ends `FAILED` with what was found, and the generation stays quarantined: remove what the result names,
or use `FORCE_DESTROY`, and release again.

### 8.2 Unmanaged resources

A directory under `sandboxes/` that no record owns, that carries the marker of another store, or that has no
valid marker is `UNMANAGED`. It is reported (`unmanaged_resources` in `host.metrics`, and once in the store) and
**never modified**. Inspect it and remove it by hand when you are sure; the host will not.

### 8.3 A store older than the system (`host.acknowledge`)

Every sandbox directory carries a marker with the store's lineage and the commit sequence at which it was
created. If, at start, a marker of this store's lineage is newer than the store's last commit, the store is older
than the system it describes: a backup of the store was restored without the directories that belong to it, or
the store lost its tail. The host enters `CONTAINMENT` (reason `store_regression`), recovers nothing and takes
no destructive action.

Choose one:

* **Supply the right store.** Stop the core, put back the store that belongs to these directories, start.
* **Accept this store.** `host.acknowledge` with condition `store_regression`. The store becomes authoritative
  again: its commit sequence is moved past every marker on disk, the suspended recovery runs, and whatever the
  store does not describe is `UNMANAGED` from then on (8.2). Their runtimes still end at their expiry.

## 9. The store

The store is one append-only file, `<state_root>/state/journal.wal`, owned by the core. Nothing else writes it.

**What the host does on its own.** A torn final record, the signature of a crash during an append, is dropped
and reported at the next start. The file only grows by appending, so the host rewrites it as current state
(*compaction*): when it opens a store larger than `store.compact_at_bytes` (64 MiB), and while it serves, as soon
as the file has grown past that size and at least half of it is history. `store_compactions` counts the rewrites.
A commit whose outcome is uncertain, or a second writer, makes the core end itself; `acf-host.service` restarts it
and the new activation re-establishes its state from the store.

**`READ_ONLY`.** `read_only_reason` in `host.info` says which case:

| Reason | Meaning | What to do |
|---|---|---|
| the store is corrupt | corruption that cannot be a crash artefact (valid data follows the bad record) | there is no repair tool: a corrupt record is never believed. Stop the core, `journal verify` to see where. Then either restore the store **together with** the directories it describes (section 10), or move `state/journal.wal` aside and start with an empty store: everything the old one described is then `UNMANAGED` (8.2), and running sandboxes end at their expiry. Keep the old file. |
| the store was written with a schema this version does not support | a newer version wrote it | run the version that wrote it. The file is neither written nor interpreted meanwhile. |
| the outcome of a commit is uncertain; this activation was fenced | see above: the core ends itself and is restarted | if it keeps happening, look at the disk, and for a second `acf-host serve` on the same state root |

**A full disk.** `state/journal.reserve` (`store.reserve_bytes`) is capacity that workload data cannot take. When
an append fails for lack of space the reserve is released and the append retried, so a stop or a destroy can
still be recorded. While the host runs on its reserve it refuses granting operations (`RESOURCE_EXHAUSTED`) and
`store_reserve_released` is 1; free some space and the host takes the reserve back by itself.

**Tools.** Both take the single-instance lock, so they refuse to run while the core does: stop it first.

```bash
sudo systemctl stop acf-host
sudo /opt/acf/bin/acf-host journal verify  --config /etc/acf/host.yaml
sudo /opt/acf/bin/acf-host journal compact --config /etc/acf/host.yaml --keep-terminal 10000
sudo systemctl start acf-host
```

`verify` prints `lineage`, `batches`, `bytes`, `last_seq`, `next_epoch` and `integrity`, and exits 2 unless the
integrity is `Clean` or `TornTailRepaired` (opening the store repairs a torn tail). It does not migrate: a store
of an older schema is reported as unsupported here and migrated by the core at its next start. `compact`
rewrites the file as current state only and keeps the newest `--keep-terminal` finished operations (10000 by
default); revisions and the commit sequence are preserved. Both tools open a store of any size, and opening it
does not rewrite it: `verify` only looks.

**Size.** Finished operations are forgotten after `operations.operation_retention_ms`, and the records of
destroyed sandboxes and deleted snapshots after `operations.change_retention_ms`. They leave the file when it is
compacted, which the host does by itself (above). Watch `store_bytes`: it should stay within a small multiple of
what the current records need. What the host keeps is bounded by `operations.rate_limit_per_minute` times
`operations.operation_retention_ms` for each peer, and all of it is held in memory, so size those two for the
machine. The core does not open a store above 256 MiB. If a store ever gets there, stop the core and run
`journal compact`: the tool opens it whatever its size, and the core opens the result.

## 10. Backup

* **The store and the sandbox directories are one unit.** Back up `/var/lib/acf` as a whole, with the core
  stopped, or not at all. Restoring `state/` without the `sandboxes/` that belong to it, or the other way round,
  is the situation of 8.3: the host starts in `CONTAINMENT` and waits for you.
* **Snapshots contain guest memory.** Treat `snapshots/` as secrets; the state root is 0700 root and a copy of it
  must not land anywhere with weaker access control. The same holds for `/etc/acf/secrets` and
  `/etc/acf/tls/host.key`.
* `/run/acf` is not backed up: after a reboot no runtime exists and its content means nothing.
* What is cheap to keep and worth it: `/etc/acf` (the three trusted files are what makes a rebuilt host behave
  like the old one), and the pin files you built your images from.
* A restored host is a *new activation of the same store*. Sandboxes that were running when the backup was taken
  are not running now; recovery marks them failed, and their expiry is never lengthened by the time they spent
  in a backup.

## 11. Upgrading

**The host agent.**

1. Build and check: `make release`. Read the release notes for a change of `host.yaml` or of the profile.
2. Drain and stop the core (section 7). VMs keep running.
3. `sudo scripts/host-setup.sh install --acf-host target/release/acf-host`: the binary is replaced atomically;
   your files in `/etc/acf` are kept, and a shipped file that differs from yours appears beside it as `*.dist`.
   Compare them: a key this version requires is in the `.dist`.
4. `sudo systemctl daemon-reload`, then `sudo systemctl restart acf-lifetime.service`: the enforcer is a
   long-running process of the *old* binary until it is restarted. The restart is brief and loses nothing:
   the tickets are on disk.
5. `sudo /opt/acf/bin/acf-host doctor --config /etc/acf/host.yaml`, then `sudo systemctl start acf-host`.

The core starts its edge and the guest-traffic processes from its own running image, so the roles of one
activation never mix versions.

**The store's schema.** When a new version brings a new store schema, the core migrates the store the first time
it opens it, before recovery. The migration is atomic: the new file is written beside the old one and only then
switched in, and an interrupted migration leaves the previous schema intact. **The previous store file is kept
beside the new one**, as `state/journal.wal.schema<N>`, and the host never deletes it. The journal says
`the store was migrated from an earlier schema`. Operations that were in flight are carried over as they are and
resolved like any inherited operation. A store that cannot be migrated is not interpreted either: the host is
`READ_ONLY` and the original file is untouched. Records written before scope tags existed are given to peer
`local-root`, scope `default`.

**Firecracker.** A snapshot is valid only on the Firecracker version that took it. Move
`scripts/firecracker.lock`, the installed binaries, `firecracker.pinned_version` and the two binary digests
(`firecracker.firecracker_sha256`, `firecracker.jailer_sha256`: the installer prints the new ones) together, with
no sandbox running, and take new snapshots afterwards. A mismatch between the installed binaries and the version
or the digests is a failed mandatory check. Replacing a binary under a running host does not change what the
host accepts: every later start and restore is refused until the configuration pins the new bytes and the core
is restarted.

**Guest images** are installed directories (`<state_root>/images/<name>`); installing a new build replaces the
alias. A sandbox copies and verifies its image when it is created and does not depend on the image store
afterwards.

## 12. Logs, events and metrics

Three kinds of information, three reliabilities. **State** is read through the API (`host.info`, the list and
inspect methods): it is durable and authoritative. Events and logs may be lost and are never an authority.

| What | Where | Notes |
|---|---|---|
| Logs of the three units | `journalctl -u acf-host -u acf-lifetime -u acf-cgroup` | `RUST_LOG=debug` and `ACF_LOG_FORMAT=json` in `/etc/default/acf-host` (read by both long-running units) |
| Events | `<state_root>/telemetry/events.jsonl`, one JSON object per line (`execution/contracts/event-schema.json`) | each carries `host_id`, the store lineage, the activation epoch and a sequence number that only grows within an activation: a gap means events were lost. Never contains output, secrets or host paths. |
| Metrics | `host.metrics`: counters and gauges as JSON | an `observer` may read them |

The host does not rotate `events.jsonl`; rotate it yourself. A failure to write an event changes no operation: it
is counted (`events_dropped`).

**Metrics that show standing risk**, as opposed to activity. These are the ones to alert on:

| Metric | Why it matters |
|---|---|
| `host_mode` (0 `STARTING`, 1 `SERVING`, 2 `DRAINING`, 3 `CONTAINMENT`, 4 `READ_ONLY`) | anything but 1 outside a planned restart |
| `quarantined_generations`, `oldest_quarantine_age_ms` | each one holds capacity until an operator releases it |
| `failed_generations_holding_leases` | failed sandboxes that nobody destroyed: capacity that is gone until someone does |
| `unmanaged_resources` | directories no record owns; the host will never clean them up |
| `oldest_open_operation_age_ms`, `operations_open` | an operation that does not end |
| `ms_since_last_complete_sweep` | the host has not observed every sandbox for this long (-1: not yet in this activation). Compare with `recovery.sweep_interval_ms`. |
| `store_bytes` against `store_reserve_bytes`; `store_reserve_released`; `store_compactions` | the store's growth, whether it is living on its reserve, and how often its file was rewritten as current state |
| `posture_failures_after_launch`, `security_control_failures` | an isolation control that was in force at launch and is not any more; the runtime was stopped |
| `runtime_losses_detected` | VMMs that disappeared under a sandbox |
| `refusals_before_authentication`, `handshake_failures` | someone is knocking |
| `edge_restarts` | the edge died and was started again; callers saw lost responses |
| `enrolment_reload_failures` | the enrolment file on disk is not the one in force |
| `events_dropped` | the event log cannot be written |

Activity counters (`operations_accepted`, `operations_finished`, `operation_failures`, `refusals`, `runs`,
`recovery_outcomes`, `sandboxes_expired`, `quarantines`, `quarantine_releases`, …) are in the same reply. A
metric label is always a word from a closed vocabulary, never an id or a caller's string.

## 13. When something is wrong

| Symptom | Meaning | What to do |
|---|---|---|
| `acf-host.service` fails at once; `acf-wait-ready: the core (pid …) exited before it listened` | the core could not start at all. Its own line is just above: an unreadable or structurally invalid `host.yaml`, `edge.uid is not set`, `another host-agent instance holds …/host-agent.lock`, a socket path that is not a socket, a store above 256 MiB (section 9: `journal compact`) | fix what it names. Nothing was changed. |
| the unit starts, `host.info` says `CONTAINMENT` | section 6: the reasons are in the same reply and in the journal (`host is in CONTAINMENT`) | by reason |
| `mandatory_check: kvm: cannot open /dev/kvm …` | KVM is off, or a drop-in restricts devices | enable KVM; remove the drop-in; restart |
| `mandatory_check: cgroup_parent: … does not exist` | `acf-cgroup.service` did not run | `systemctl start acf-cgroup`, restart the core |
| `mandatory_check: firecracker: … is … but the profile is pinned to …` | binaries and `pinned_version` disagree | section 11 |
| `mandatory_check: firecracker: … has no pinned identity: firecracker.…_sha256 is not set` | the host configuration does not pin the installed binary | put the two lines the installer printed into `host.yaml` (section 3, step 4); restart |
| `mandatory_check: firecracker: … hashes to … but firecracker.…_sha256 pins …`; a start or restore fails with `INTEGRITY_FAILURE` naming a binary | the installed file is not the one that was pinned: it was replaced, upgraded or damaged | find out why before anything else. If the change was yours, section 11 |
| `mandatory_check: unshare: …` | `network.unshare_bin` is missing or not a trusted executable | install util-linux or correct the path; restart |
| `lifetime_enforcer_unavailable` | the enforcer is not running, or cannot write `<runtime_dir>/expiry` | `systemctl status acf-lifetime`; a status of `226/NAMESPACE` means `/run/acf` does not exist: `systemd-tmpfiles --create /etc/tmpfiles.d/acf.conf` |
| `host.info` says `READ_ONLY` | section 9 | by `read_only_reason` |
| a request is refused with `HOST_NOT_SERVING` | the mode does not serve that class of method | section 6 |
| network mode `allowlist` is refused as unsupported | `ip`, `nft` or `nsenter` is missing or not trusted (`doctor`: `network_tools`) | install iproute2 / nftables / util-linux, or correct the paths; restart |
| a request that should fit is refused with `RESOURCE_EXHAUSTED` | a failed or quarantined generation still holds its reservation; free space is below `envelope.min_free_headroom_mib`; or the store is on its reserve | destroy failed sandboxes, release quarantined ones, free space |
| `sandbox.destroy` answers `QUARANTINED` | 8.1 | `quarantine.release` |
| a sandbox became `FAILED` with `SECURITY_CONTROL_FAILURE` | a control that confines it was no longer in force (its control-group limits, its namespace, its packet filter, its guest-traffic process); the host stopped it and repaired nothing | this is the system working. Find out what changed the machine underneath it; destroy the sandbox. |
| every sandbox is stopped as `SECURITY_CONTROL_FAILURE` after a restart of the core | the core cannot see the namespace handles of the previous activation | a drop-in gave `acf-host.service` a mount namespace: section 5 |
| a local caller cannot connect | the socket's mode or group does not admit it | `edge.socket_mode`, `edge.socket_gid`; restart the core |
| a caller connects and is dropped before any answer | authenticated, not enrolled | 3.5 |
| the network endpoint is closed | reason `mandatory_check: the network endpoint cannot be opened: …` or `cannot listen on …` | 3.5; restart |
| a caller lost a response | the edge or the core restarted under it | nothing was lost: the operation is recorded. Ask for it by id (`operation.get`); do not send the request again under a new id. |

## 14. Checking a change to this repository

`make help` lists every target. The ones that matter to an operator who changes a script, a unit or a profile:

| Goal | Command | Needs |
|---|---|---|
| Everything that runs anywhere | `make check` | Rust, `uv`, systemd's tools |
| What CI runs on every push | `make ci` | as above, and `sudo` for `make root-test` |
| The units are well-formed (all three) | `make systemd-verify` | `systemd-analyze` |
| The network plumbing against a real kernel | `make net-plumbing-test` | an unprivileged user namespace, or root; `ip`, `nft` |
| The Rust tests that need root | `make root-test` | `sudo` |
| The shipped configuration and profile against the in-memory host | `make control-plane` | Rust, `uv` |
| The real thing | `make integration` | a KVM host, root, an installed image, the three units running |

The integration suite **owns the host**: it refuses to start while sandboxes or snapshots exist and destroys what
is live after each test. Run it on a dedicated runner (`[self-hosted, linux, x64, kvm]` in the workflow), never
on a machine whose sandboxes you care about. Its environment variables are documented at the top of
`tests/helpers/acf_integration.py`.

It does more than call the API. As root, on the host it is pointed at, it:

* kills and restarts the core through its unit, and kills VMMs and guest-traffic processes;
* replaces the configured jailer with a script of its own for the length of one test, twice pinned in
  `host.yaml` in place of the real jailer's digest (with a restart of the core before and after) and once left
  unpinned; the real jailer and the original `host.yaml` are put back whatever happens. A run that is
  interrupted there leaves `<jailer>.acf-it-real` beside the jailer: move it back and restore the digest;
* writes `memory.max` and `pids.max` of a sandbox's control group, and flushes the packet filter of a
  sandbox's network namespace;
* adds a marked block to `/etc/hosts`, and creates the network namespace `acf-it-far` and the devices
  `acf-it-h` and `acf-it-f` with addresses of 198.51.100.0/24, for the allowlist tests, and removes them;
* writes `/proc/sys/kernel/ns_last_pid` to force a process id to be reused.

With `ACF_ENTRY_RECORD` set to a path, the entry-conditions test writes what it found there (the workflow
keeps it as an artifact).

## 15. Uninstall

```bash
# Destroy the sandboxes you want gone first (sandbox.destroy); delete the snapshots you do not want to keep.
sudo systemctl disable --now acf-host.service
sudo systemctl disable --now acf-lifetime.service acf-cgroup.service     # the enforcer last
sudo rm -f /etc/systemd/system/acf-{host,lifetime,cgroup}.service /etc/tmpfiles.d/acf.conf /etc/sysusers.d/acf.conf
sudo systemctl daemon-reload
sudo rm -rf /opt/acf /etc/acf /run/acf    # and /var/lib/acf only when you are sure no snapshot is wanted
sudo userdel acf-edge && sudo groupdel acf
```
