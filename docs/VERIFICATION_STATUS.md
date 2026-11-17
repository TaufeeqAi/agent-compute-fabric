# Verification status — what was run, what passed, what was not

Read this before trusting anything else in the repository. It lists the evidence that exists, with counts, and — more
importantly — the evidence that does **not** exist yet. Anything not listed as passing here is unverified.

Gate run: `make ci`, through the real Makefile, 2026-10-18 23:42–23:50 UTC (7 min 49 s), exit status 0.

## 1. The short version

Everything that can run **without KVM, without a network and without a container engine** ran and passed: 249 Rust
tests, 365 CLI tests, 757 repository tool and script tests, 17 driver self-tests and 44 control-plane tests, plus
`cargo fmt`, `clippy -D warnings`, schema-drift, production-binary purity, pin consistency and `systemd-analyze verify`.

**No real microVM has ever been booted from this code.** The machine it was written on has no `/dev/kvm`. The 64 tests
that assert on a real guest were *skipped*, not passed. They are where the isolation claims will be proven or
disproven, and the first run on a KVM host should be expected to find something (see §5).

Three classes of input (base-image digests, kernel digests, Firecracker tarball digests; eight pins in all) are
deliberately unpinned (`UNSET`), so the installer and the image builder refuse to proceed until a person pins them from
a machine that can reach the registries (§4).

## 2. How much each kind of evidence is worth

| Level | What a pass shows | Status |
|---|---|---|
| L0 — static | it compiles, is formatted, lint-clean and type-checked; generated schemas have not drifted; shipped config and policy parse | ran, passed |
| L1 — unit and property | each module's rules: journal framing and replay, the recovery decision table, admission, the operation protocol, fault injection at the five crash points | ran, passed |
| L2 — whole process, fake VM | the real Python CLI against the real host server over a real Unix socket; the Firecracker adapter against a fake Firecracker API and fake jailer, driving the **real guest agent** | ran, passed |
| L3 — control plane | the policy and admission suites against the **shipped** config and policy, through the black-box driver | ran, passed (44) |
| L4 — real VMM | boot, jailer, seccomp, cgroups, network namespace, vsock, snapshots, limits, crash recovery on KVM | **not run** (64 tests skip) |
| L5 — real supply chain | registries, kernel image, release assets, advisory databases | **not run** |

L0–L3 prove that the *logic* is coherent and that the pieces fit together. They cannot prove that a kernel enforces
what the host asks for; that is exactly what L4 is for.

## 3. What ran

### 3.1 The gate (`make ci`)

| Stage | Target | Result |
|---|---|---|
| Rust formatting | `rust-fmt` | clean |
| Rust lint | `rust-lint` | clean (`clippy --workspace --all-targets --all-features -D warnings`) |
| Rust tests | `rust-test` | **249 passed** — guest-agent lib 15, guest protocol 6, host-agent lib 220, wire 8; doc-tests 0 |
| Schema drift | `check-schemas` | `schemas/` equals what the binary generates |
| CLI lint and types | `py-lint` | ruff check and format clean; mypy clean (30 source files) |
| CLI tests | `py-test` | **365 passed**. On a fresh tree the 23 end-to-end tests skip in this stage (no host binary has been built yet) and run, as a hard requirement, in the `e2e` stage below, so a first run shows 342 passed, 23 skipped here |
| Tooling lint and types | `tools-lint` | ruff check and format clean; mypy clean (42 source files) |
| Tool and script tests | `tools-test` | **757 passed** — 449 in `tests/scripts`, 308 in `tests/tools` (incl. 46 Makefile/CI/doc guard tests). On a fresh tree 2 of them (the release-purity self-tests) skip until `make release` has built the binaries, so a first run shows 755 passed, 2 skipped; `make release` runs the purity check itself either way |
| systemd units | `systemd-verify` | `units verify` (`systemd-analyze verify` only; the units were never started) |
| Pin consistency | `check-pins` | ok |
| Production build | `release` | built; the production `acf-host` contains no test-only code (`scripts/check-release-purity.sh`, method validated against the test build) |
| End to end | `e2e` | **23 passed** (the CLI's end-to-end tests against the real host server and the real CLI; a missing host binary counts as a failure, never a skip) |
| Driver self-test | `driver-selftest` | **17 passed** |
| Control plane | `control-plane` | **44 passed, 64 skipped** |

The 64 skips, by file (every reason is "needs a real guest: it asserts on what runs inside a microVM"):
`integration/execution/test_execution_limits.py` 11 · `integration/recovery/test_host_recovery.py` 7 ·
`integration/snapshots/test_snapshot_restore.py` 12 · `integration/vm_lifecycle/test_vm_lifecycle.py` 5 ·
`isolation/filesystem/test_guest_filesystem.py` 5 · `isolation/host_control/test_host_control_surface.py` 11 ·
`isolation/network/test_guest_network.py` 6 · `isolation/process/test_guest_processes.py` 7.
On a KVM host `ACF_INTEGRATION=1` turns every skip into a failure, so a skip can never pass for a result there.

### 3.2 Also run, outside the gate

* `actionlint` 1.7.12 over the three workflows: no findings. **The workflows themselves have never executed** (§4, item 9).
* `python3 -I tools/check_pins.py --require-pinned` — fails, by design, and lists the eight unset pins (§4).
* A mutation check of the trusted-file loader's tests (§6): three checks switched off, five tests turned red, the loader
  restored byte for byte.
* The packaging checks (reproducible archive, manifest, lossless markdown export, the clean-room run) were run on the
  final archive. Their results are reported with the archive and not recorded here: this file is inside the archive, and
  an archive cannot contain its own hash.

## 4. What was not run, and what that leaves unproven

| # | Not run | Why | What stays unproven |
|---|---|---|---|
| 1 | The KVM integration and isolation suites (64 tests) | no `/dev/kvm` | everything about a real guest: boot, jailer and seccomp confinement, cgroup limits (memory, pids, CPU, wall clock), `network=none` as the host *observes* it in a real `/proc`, vsock, snapshot create and restore on real memory and disk images, recovery after a real `SIGKILL` of the host or the VMM |
| 2 | A real image build (`scripts/build-image.sh` against a registry and a real kernel) | registries unreachable; no usable Docker daemon | the real rootfs, kernel and manifest pipeline. The container path ran only against a stub `docker`, and the rest through `--rootfs-tar` |
| 3 | The Firecracker installer on a real release tarball | release assets unreachable | digest verification on real bytes; the behaviour of the real `jailer` binary |
| 4 | The static musl guest-agent build (`make guest-agent`) | the musl target is not installed | that the agent links statically and runs as a child of the in-image init. Tests ran against the native build |
| 5 | `cargo audit` and `pip-audit` | advisory databases unreachable | the known-vulnerability status of the locked dependency set (`.github/workflows/audit.yml` runs both) |
| 6 | Starting the units under systemd | only `systemd-analyze verify` ran | runtime semantics: ordering, cgroup delegation, `ExecStartPre` behaviour |
| 7 | Any performance measurement | no KVM | boot latency, exec overhead, snapshot size and time, `resize2fs` cost at boot, journal `fsync` cost under load |
| 8 | Several distinct caller uids | everything ran as root, one uid | `SO_PEERCRED` with real unprivileged callers. The allow-by-uid-or-gid logic is unit-tested with synthetic credentials |
| 9 | The GitHub Actions workflows | no GitHub access from the authoring environment | how the jobs behave on a non-root runner with its own `$TMPDIR` and toolchain; the first push may differ |
| 10 | Three provenance details | see [DEPENDENCY_PROVENANCE.md](DEPENDENCY_PROVENANCE.md) | `serde-saphyr` 2.0.0's changelog (judged by building and testing it); base-image *tags* were not re-resolved; action SHAs came from `git ls-remote`, not signed release notes |

### The pins that are deliberately `UNSET`

| File | Keys |
|---|---|
| `scripts/firecracker.lock` | `SHA256_x86_64`, `SHA256_aarch64` |
| `images/images.lock` | `BASE_DIGEST_base`, `BASE_DIGEST_browser`, `BASE_DIGEST_node`, `BASE_DIGEST_python`, `KERNEL_SHA256_x86_64`, `KERNEL_SHA256_aarch64` |

`make check-pins-release` fails while any is unset, the installer refuses with exit status 3, and the image builder
refuses to build. They were not invented: a digest that nobody measured would be worse than none. How to fill them is
in `scripts/firecracker.lock` and [OPERATIONS.md](OPERATIONS.md).

## 5. What to expect on the first KVM run

Budget for first-contact corrections. The probes in `tests/isolation/` encode assumptions about what a real guest and a
real kernel will show; when one fails, the question to ask first is *a wrong assumption in the probe, or a real
isolation gap?* — and the answer must come from reading the guest, not from loosening the assertion. Run order and the
operator's checklist are in [OPERATIONS.md](OPERATIONS.md); the suites are started with `make integration`.

## 6. Two defects the gate found late

Both were found by running a check from a different starting point than the one it was written in, which is the
reason to do that.

1. **Vacuous refusal tests.** `admission/trusted_file.rs` refuses a policy file whose ancestor directories are group- or
   world-writable. Its tests asserted only that a refusal carried the security class, and they built their files under
   the temp directory, which is under `/tmp`, itself world-writable. Every refusal test therefore passed because `/tmp`
   was refused, whatever the line under test did. It surfaced when a gate run used a different `$TMPDIR`. The loader now
   has a private `start` parameter (production always starts at `/`), so tests judge directories they built; each test
   asserts which check spoke; and disabling the ancestor-mode, file-mode and file-owner checks turned five tests red.
   The general lesson is in [GUIDE.md §3.5](GUIDE.md).
2. **An unpacked archive could not be re-packed.** `make ci` run from the *unpacked ZIP* failed two repository
   tests: the tree now contained the archive's own `MANIFEST.sha256`, which the packer refused as a reserved name. The
   packer now accepts a root manifest that is exactly what it would generate (and regenerates it, so unpack-then-repack
   gives the same bytes) and still refuses a hand-written or stale one ([ADR-025](DECISIONS.md)).

## 7. Environment

| | |
|---|---|
| OS, kernel | Ubuntu 24.04.5 LTS, Linux 6.18.44 x86_64, 2 vCPU, 8 GiB, running as root |
| `/dev/kvm` | absent |
| Rust | `rustc 1.97.0 (2d8144b78 2026-07-07)`, `cargo 1.97.0` — the version `rust-toolchain.toml` pins |
| Python, uv | CPython 3.13.16; uv 0.11.32 here (CI pins 0.13.1); ruff 0.17.1, mypy 2.4.0, pytest 9.1.1 |
| Accommodation | the pinned toolchain's download is blocked, so Rust ran with `RUSTUP_TOOLCHAIN=stable`, which resolves to the same 1.97.0 |
| Network | HTTPS through a proxy allowlist (package registries only); no container registry, no GitHub release assets |

Only one Python interpreter (3.13) and one OS were tried; the manifests allow Python 3.12 and newer.

## 8. How to reproduce

```bash
make ci                    # everything in §3.1; needs Rust, uv, Python 3.12+, systemd-analyze
make check-pins-release    # must FAIL until the eight pins are filled in
make integration           # on a KVM host only, with ACF_INTEGRATION=1: the 64 skipped tests
```

## Compressed summary

The logic is exercised thoroughly and agrees with itself; the kernel has not been asked yet. Treat every isolation
claim as a hypothesis with a test written for it, until the KVM suites have run.
