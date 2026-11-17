# Operations — installing, running and recovering Phase 1

Audience: the person who owns the machine. Everything here is the path the `integration` workflow
(`.github/workflows/integration.yml`) takes, in the same order, so a green run of that workflow is a rehearsal of this
document. **None of it has been executed on a real KVM host by the author** — see
[VERIFICATION_STATUS.md](VERIFICATION_STATUS.md). Expect to correct something on first contact and send the correction back.

---

## 1. What the machine must provide

| Requirement | Why | How it is checked |
|---|---|---|
| Linux ≥ 5.10 on x86_64 or aarch64 | `pidfd`, `openat2`, cgroup v2 | `acf-host doctor` → `kernel` |
| `/dev/kvm` usable by root | Firecracker | `doctor` → `kvm` |
| cgroup v2 (unified) with `cpu`, `memory`, `pids` delegated to `<cgroup_root>/acf` | per-VM limits | `doctor` → `cgroup_parent`; `scripts/acf-setup-cgroup` (re)creates it at every boot via `acf-cgroup.service` |
| No swap (warning) / SMT off (warning) | memory limits and side-channel posture | `doctor` → `swap`, `smt` |
| uid range `100000…104095` unused by any local account | one unprivileged uid per VM | `doctor` → `uid_range` |
| `/var/lib/acf` private (0700 root) with free space | journal, images, snapshots (guest memory!) | `doctor` → `state_root` |
| util-linux `unshare` | empty network namespaces | `doctor` → `unshare` |
| root-owned `firecracker` + `jailer` at the pinned version | executed as root | `doctor` → `firecracker` |
| a valid policy | what callers may do | `doctor` → `policy` |

`acf-host serve` runs the same checks and **refuses to start** on any FAIL (warnings are tolerated). Build-time extras:
Docker with BuildKit (images), a Rust toolchain (`rust-toolchain.toml`, plus the musl target for the guest agent), and `uv`.

## 2. Install

```bash
# 0. Build (as your normal user). `make release` builds the production acf-host and proves it contains no test code.
make release
make guest-agent                      # static musl guest agent, verified to be static

# 1. Firecracker + jailer, pinned. Refuses (exit 3) while the digest in scripts/firecracker.lock is UNSET:
#    pass a digest you verified out of band for this run, or pin it first (section 3).
sudo scripts/install-firecracker.sh --sha256 <sha256-of-the-release-tarball>

# 2. The agent, config, policy, systemd units. Idempotent; never overwrites your host.yaml / policy.yaml
#    (a differing shipped copy is written beside it as *.dist).
sudo scripts/host-setup.sh install --acf-host target/release/acf-host

# 3. A guest image. Needs root, Docker, a LARGE disk-backed TMPDIR, and a guest kernel (see section 3).
sudo --preserve-env=TMPDIR scripts/build-image.sh --image python --kernel /path/to/vmlinux --install

# 4. Start and inspect.
sudo systemctl daemon-reload
sudo systemctl enable --now acf-host.service
sudo /opt/acf/bin/acf-host doctor

# 5. The client (any user who may use the socket).
uv tool install ./apps/cli
acf-local host info
```

Layout created (all `root:root`; the host refuses to trust anything an unprivileged user could replace):

```text
/opt/acf/bin/{acf-host,firecracker,jailer}    /opt/acf/libexec/acf-setup-cgroup
/etc/acf/{host.yaml,policy.yaml}              /var/lib/acf/            0700   (state, images, sandboxes, snapshots)
/run/acf/host-agent.sock                      /etc/systemd/system/{acf-host,acf-cgroup}.service
```

### The milestone

```bash
acf-local run --image python --cpu 2 --memory 4096 --network none --command "python experiment.py"

acf-local run --image python --cpu 2 --memory 4096 --network none --keep --name lab --command "python experiment.py"
acf-local snapshot create baseline --sandbox lab
acf-local snapshot restore baseline            # rolls `lab` back; prints the verified-restore evidence
```

`experiment.py` must exist in the image or be created by the command itself (`--shell`, or `-- sh -c '…'`): there is no file-transfer API in Phase 1.

## 3. Pinning the inputs (do this once, review it like a dependency bump)

Three inputs are **UNSET** in the repository, on purpose: their digests could not be verified from the authoring
environment, and inventing them would be worse than refusing.

| Input | Where | How to pin |
|---|---|---|
| Firecracker tarball (per arch) | `scripts/firecracker.lock` `SHA256_<arch>` | `scripts/install-firecracker.sh --print-digest` downloads and prints what it measured; cross-check against the release page's `*.tgz.sha256.txt` and `gh api repos/firecracker-microvm/firecracker/releases/tags/v1.17.0 --jq '.assets[].digest'`, then commit. |
| Base images (registry digests) | `images/images.lock` `BASE_DIGEST_<alias>` | `scripts/pin-images.sh --write` (needs `crane`, `skopeo` or `docker buildx`). **The tags in the file were not re-resolved**: if one does not exist the script fails loudly — fix the tag, rerun. `--verify` detects drift later. |
| Guest kernel (per arch) | `images/images.lock` `KERNEL_SHA256_<arch>` | Build or obtain an *uncompressed* `vmlinux`; `python3 tools/check_kernel_config.py vmlinux` (or `--config .config`) checks that everything the guest needs is built in (`=y`; no modules, no initramfs); `sha256sum` it into the lock. Firecracker publishes recipes and configs under its `resources/guest_configs/`. |

`make check-pins` (offline) keeps the pin files consistent with each other and `config/host.example.yaml`;
`make check-pins-release` **fails while anything is UNSET** — use it as the release gate. `build-image.sh --allow-unpinned`
exists for development and stamps the manifest `unpinned`, so such an image can never pass for a pinned one.

## 4. Giving people access

The socket's first access-control layer is its mode; the second is the host's own identity check (`SO_PEERCRED`) against
`allowed_uids` / `allowed_gids` — **both must admit the caller**. Default: root only. To let an operator group use the CLI:

```yaml
# /etc/acf/host.yaml
security:
  allowed_gids: [990]        # gid of the "acf" group
  socket_gid: 990
  socket_mode: "0660"
```

then `sudo systemctl restart acf-host` (recovery adopts running sandboxes). A caller who cannot open the socket gets exit 6
with this hint; one who can but is not allow-listed gets exit 3 (`AUTHORIZATION`) and the host has recorded nothing.
`policy_reload` (administrators only: uids in `security.trusted_owner_uids`) applies a changed `/etc/acf/policy.yaml`
to *future* operations only: `acf-local host reload-policy`.

## 5. Sizing

`envelope` in `host.yaml` is what the machine may promise: it reserves against it atomically and refuses what does not
fit (it never overcommits). Leave room for the host agent, the kernel and page cache. Policy ceilings must not exceed the
envelope (`shipped_files_tests` enforces that for the shipped pair). Per sandbox the host budgets `memory + vmm_overhead_mib`
(64) and `disk` at full size. A *failed* sandbox keeps its reservation until destroyed.

## 6. Running day to day

| Task | Command |
|---|---|
| Is it healthy? Which policy is in force? | `acf-local host info` (`mode` is `normal` or `read_only_quarantine`) |
| Counters / gauges | `acf-local host metrics` |
| Preflight again | `sudo /opt/acf/bin/acf-host doctor [--json]` |
| Agent log | `journalctl -u acf-host.service` (`ACF_LOG_FORMAT=json`, `RUST_LOG=debug` via `/etc/default/acf-host`) |
| Event log (JSON lines) | `/var/lib/acf/telemetry/`; diagnostic only — never authority |
| What happened to this run? | `acf-local evidence get RUN_ID` |
| What happened to this request? | `acf-local operation get OP_ID` — the CLI prints the id whenever a reply was lost, and the host can always resolve it |
| Stop everything | `sudo systemctl stop acf-host` — VMMs are **not** killed (they survive for adoption); `acf-local sandbox destroy` first if you want them gone |
| Compact the journal (agent stopped) | `sudo /opt/acf/bin/acf-host journal compact --config /etc/acf/host.yaml [--keep-terminal 10000]` |
| Journal integrity (agent stopped) | `sudo /opt/acf/bin/acf-host journal verify --config /etc/acf/host.yaml` |

**Upgrades.** A Firecracker snapshot is valid only on the exact version, CPU fingerprint and security profile that took
it. Changing `firecracker.pinned_version` (the lock, the binaries and the config together), the kernel, the guest agent or
the host CPU makes existing snapshots incompatible: restore refuses them with `COMPATIBILITY_FAILURE` naming the difference.
Take new baselines after an upgrade.

**Backups.** Snapshots contain guest memory. They are secrets; the state root is 0700 root and should never be copied
to a place with weaker access control. The journal is not a backup target — it is meaningful only with the directories it describes.

## 7. When something is wrong

| Symptom | Meaning | What to do |
|---|---|---|
| `acf-host` will not start; journal says `refusing to start: <check> …` | a `doctor` FAIL (names every failing check) | fix exactly what it names; `acf-host doctor` reprints the report |
| exit **3** | the request was refused; **nothing changed** | read the `class` (`VALIDATION`, `AUTHORIZATION`, `ADMISSION_REJECTED`, `STATE_CONFLICT`…) and change the request |
| exit **5** (`UNKNOWN`) | the host cannot say whether the mutation happened (e.g. its VM died mid-command) | **observe, don't re-run**: `acf-local operation get OP_ID`, `acf-local sandbox inspect ID`. Recovery stops the VMM and marks the sandbox `FAILED` on its own; the run's `outcome` stays `UNKNOWN`. Re-run the workload in a *new* sandbox only if it is idempotent. |
| exit **6** | socket missing / not permitted / agent down | `systemctl status acf-host`; check group/mode (section 4). Nothing was changed. |
| exit **7** | protocol violation (version skew) | client and host from different releases; upgrade together |
| `sandbox` shows `quarantined: …` and `destroy` answers `RECOVERY_QUARANTINED` | ownership of its resources could not be proven (forged/missing `OWNER.json`, symlinked directory, corrupt record); **the host deliberately deleted nothing** | see 7.1 |
| `host info` says `read_only_quarantine` | the journal has mid-file corruption; the host serves reads and refuses every mutation | see 7.2 |
| a directory under `sandboxes/` that no record owns | an orphan; flagged once, **never deleted** | inspect it; remove by hand once you are sure |
| `start` fails with a `SECURITY` error naming `network=none` or a posture check | the VMM or guest contradicted the isolation profile; it was killed before use | this is the system working; do not bypass it — find out why (kernel/image/Firecracker version) |
| `ADMISSION_REJECTED` for a request that "should fit" | a failed or quarantined generation still holds its reservation, or headroom is short | `acf-local sandbox list`; destroy failed generations; check free space against `min_free_headroom_mib` |

### 7.1 A quarantined sandbox (Phase 1 has no "release" command — known gap)

1. `acf-local sandbox inspect ID` — read `quarantined` (the reason) and `process` (pid, start-time ticks, boot id).
2. Decide whether you really own it: compare `<state_root>/sandboxes/<sbx>/<gen>/OWNER.json` with the journal's
   sandbox/generation id and look for a VMM in `<cgroup_root>/acf/<jail_id>`.
3. If you do: stop `acf-host`, end any leftover VMM (`echo 1 > <cgroup>/cgroup.kill`, then `rmdir` it), unmount and remove
   `/run/acf/netns/acf-<jail_id>`, remove the generation directory, start `acf-host`.
4. The journal still lists the generation as quarantined and **it keeps its reservation**. Phase 1 offers no supported way to
   forget it; either live with one reserved slot, or — when nothing you care about is running — reset the state root
   (stop the agent, move `/var/lib/acf/state` aside, start; directories that no record owns are then flagged as orphans, not deleted).

### 7.2 A corrupt journal

1. `systemctl stop acf-host`, then `acf-host journal verify` to see where the corruption is. A torn *tail* is repaired
   automatically at start and is not this case.
2. There is no repair tool: the journal is the only authority over what exists. Move `/var/lib/acf/state` aside, restart,
   and treat every directory under `sandboxes/` and `snapshots/` as an orphan to inspect and remove by hand. Keep the old
   `state/` for forensics.

## 8. Running the tests

| Goal | Command | Needs |
|---|---|---|
| Everything that runs anywhere | `make check` | Rust, `uv`; root helps (a third of `tools-pytest` needs uid 0) |
| What CI runs on every push | `make ci` | as above |
| Control-plane half of the KVM suites against the in-memory host and the **shipped** config/policy | `make control-plane` | nothing |
| Prove the test driver itself | `make driver-selftest` | nothing |
| The real thing | `make integration` | KVM host, root, installed image, `acf-host` running |

Environment (all optional except the switch):

| Variable | Meaning | Default |
|---|---|---|
| `ACF_INTEGRATION` | `1`: the real suites; a missing environment **fails**, it does not skip | unset: skip |
| `ACF_CONTROL_PLANE` | `1`: the `control_plane` subset on the in-memory host (`ACF_HOST_FAKE` must point at `acf-host-fake`) | unset: skip |
| `ACF_REQUIRE_ROOT` | `1`: tests needing root fail instead of skipping | unset |
| `ACF_LOCAL` | CLI command line | `acf-local` |
| `ACF_SOCKET` | host control socket (also read by the CLI) | `/run/acf/host-agent.sock` |
| `ACF_IO_TIMEOUT` | CLI: how long a *prompt* reply may take | CLI default |
| `ACF_TEST_IMAGE` | image alias the tests boot | `python` |
| `ACF_STATE_ROOT` / `ACF_HOST_CONFIG` / `ACF_POLICY_PATH` / `ACF_HOST_UNIT` | white-box checks and recovery tests | `/var/lib/acf`, `/etc/acf/host.yaml`, `/etc/acf/policy.yaml`, `acf-host.service` |
| `ACF_TEST_ENVELOPE_VCPUS` / `_MEMORY_MIB` / `ACF_TEST_VMM_OVERHEAD_MIB` / `ACF_TEST_MAX_SANDBOXES` | your `host.yaml` numbers if you changed them | the shipped values (4, 8192, 64, 16) |
| `ACF_TEST_SNAPSHOT_LIMIT` | `envelope.max_snapshots` if you lowered it for the quota test | unset: that test skips |
| `ACF_LOG_FORMAT`, `RUST_LOG` | host log format and level | text, `info` |
| `ACF_MIN_FREE_MIB` | `build-image.sh` free-space floor | 4096 |

The integration suite **owns the host**: it refuses to start while sandboxes or snapshots exist and destroys whatever is
live after each test. Run it on a dedicated runner (`[self-hosted, linux, x64, kvm]` in the workflow), never on a machine
whose sandboxes you care about. A Unix socket path is limited to 107 bytes: keep `TMPDIR` short (`/tmp`) for
`make e2e`, `make driver-selftest` and `make control-plane`.

## 9. Uninstall

```bash
sudo systemctl disable --now acf-host.service acf-cgroup.service
acf-local sandbox list            # destroy anything you want gone first
sudo rm -f /etc/systemd/system/acf-{host,cgroup}.service /etc/tmpfiles.d/acf.conf
sudo rm -rf /opt/acf /etc/acf     # and /var/lib/acf only when you are sure no snapshot is wanted
```
