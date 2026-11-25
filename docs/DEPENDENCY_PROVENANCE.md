# Dependency provenance

Where every version in this repository came from, how it was checked, when, and what could not be checked. It
also records the upstream guidance and the prior art that shaped the design, with the place each was taken from.

The rule: *resolve versions from the registries at write time, not from memory.* A model's or an author's memory of
"the latest" is stale by construction, so the repository records its evidence.

Three kinds of statement are kept apart:

| Label | Meaning |
|---|---|
| **Verified** | Read from the authoritative registry or git remote on the stated date, by the method described. |
| **Exercised** | Compiled and tested in this repository on the stated date ([VERIFICATION_STATUS.md](VERIFICATION_STATUS.md)). |
| **Unverified** | Could not be reached or checked from the environment this was written in. Listed in §8. |

## 1. Method

| Ecosystem | Authority used | How the newest release was chosen |
|---|---|---|
| Rust crates | crates.io registry API (`https://crates.io/api/v1/crates/<name>`) | `max_stable_version`: newest version that is neither yanked nor a pre-release |
| Rust toolchain | `https://static.rust-lang.org/dist/channel-rust-stable.toml` | the stable channel's `pkg.rust` version and manifest date |
| Python packages | PyPI JSON API (`https://pypi.org/pypi/<name>/json`), and `pip index versions` | `info.version` |
| GitHub Actions | `git ls-remote` on the action's repository | newest `vX.Y.Z` tag; an annotated tag is peeled (`refs/tags/<tag>^{}`) to its commit |
| Firecracker | GitHub releases API of `firecracker-microvm/firecracker` | newest release; asset `digest` compared with the published `<tarball>.sha256.txt` |

Every request used a generic client name and public URLs only.

Manifests carry floors, the committed lock files (`Cargo.lock`, `uv.lock`, `apps/host-cli/uv.lock`) carry the exact
resolution, and builds use `--locked`, which fails instead of silently resolving again. A floor is the oldest
version the code was tested against; the lock is what was built.

## 2. Resolution log

| Date | What was resolved or re-checked |
|---|---|
| 2026-10-09 – 2026-10-18 | First resolutions and one full re-check for the previous delivery: crates, Python packages, action tags and commits |
| 2026-11-18 | **Everything re-checked for this delivery**: the Rust toolchain, every direct crate, every Python floor, the action tags and commits, the CI tool versions, and the Firecracker releases with their digests. Lock files regenerated. |

## 3. Drift found by the 2026-11-18 re-check

A month had moved more than twenty pins. This is why the re-check exists.

| Pin | Before | After | Note |
|---|---|---|---|
| Rust toolchain | 1.97.0 | **1.100.0** | stable channel manifest dated 2026-11-12; `rust-version` follows |
| `clap` | 4.6.7 | 4.6.8 | |
| `crc32fast` | 1.5.2 | 1.5.5 | journal checksums |
| `rustix` | 1.1.5 | 1.1.6 | feature `net` added: socket options, descriptor passing |
| `serde-saphyr` | 2.0.0 | 2.1.1 | YAML for configuration, profile and enrolment |
| `tokio` | 1.53.3 | 1.54.1 | |
| `uuid` | 1.28.0 | 1.29.3 | |
| `vsock` | 0.5.4 | 0.5.5 | guest agent transport |
| `typer` | 0.27.3 | 0.29.1 | client; the cap moved to `<0.30` |
| `pydantic` | 2.14.1 | 2.14.3 | client models |
| `pytest` | 9.1.1 | 9.2.0 | |
| `mypy` | 2.4.0 | 2.4.1 | |
| `ruff` | 0.17.1 | 0.17.5 | |
| `hatchling` | 1.32.4 | 1.33.0 | client build backend |
| `astral-sh/setup-uv` | v10.3.0 | v10.3.3 | |
| `Swatinem/rust-cache` | v2.9.1 | v2.9.3 | |
| `uv` (CI input) | 0.13.1 | 0.13.9 | |
| `cargo-audit` | 0.22.2 | 0.23.0 | |
| Firecracker | tag only, digests `UNSET` | `v1.17.0` with both release digests | see §7; `v1.18.0` exists and is deliberately not adopted |

New direct dependencies in this delivery, all resolved on 2026-11-18: `rustls` 0.23.46, `tokio-rustls` 0.26.6,
`rcgen` 0.14.10 (tests only).

## 4. Rust

Toolchain: `rust-toolchain.toml` pins **1.100.0** with `rustfmt` and `clippy`; `rust-version = "1.100"`; edition
2024. The pinned toolchain is the one that compiled and tested this code.

`Cargo.lock` holds 229 packages. The direct dependencies (workspace floor = locked version; **verified** and
**exercised** on 2026-11-18):

| Crate | Locked | Features | Used for |
|---|---|---|---|
| `async-trait` | 0.1.92 | | the backend, secret-provider and launch-sink ports |
| `base64` | 0.23.1 | | binary output inside JSON |
| `cap-std` | 4.0.3 | | capability-based file access for state, images and snapshots |
| `clap` | 4.6.8 | `derive` | command lines of `acf-host` and the test host |
| `crc32fast` | 1.5.5 | | journal batch checksums |
| `hex` | 0.4.3 | | digests |
| `http-body-util` | 0.1.5 | | Firecracker API client |
| `hyper` | 1.12.0 | `client`, `http1` | Firecracker API client over a Unix socket |
| `hyper-util` | 0.1.21 | `tokio` | the same |
| `proptest` | 1.12.0 | | property tests (dev) |
| `rcgen` | 0.14.10 | `aws_lc_rs`, `pem`; no defaults | certificates for the mutual-TLS tests; behind the `testing` feature only |
| `rustix` | 1.1.6 | `fs process thread mount system time pipe event net` | system calls without `unsafe`: peer credentials, descriptor passing, namespaces, `SO_ORIGINAL_DST` |
| `rustls` | 0.23.46 | `std`, `aws_lc_rs`; no defaults | TLS 1.3 for the network endpoint. The `tls12` feature is off, so no TLS 1.2 code is compiled in |
| `schemars` | 1.2.3 | | JSON Schema generation for the API and the file formats |
| `serde` | 1.0.229 | `derive` | |
| `serde-saphyr` | 2.1.1 | | YAML: host configuration, safety profile, enrolment table |
| `serde_json` | 1.0.154 | | wire envelope, journal records |
| `sha2` | 0.11.1 | | image identity, profile digest, fingerprints |
| `tempfile` | 3.27.0 | | tests; optional in the host behind `testing` |
| `thiserror` | 2.0.21 | | error types |
| `tokio` | 1.54.1 | `rt-multi-thread macros net io-util time fs process signal sync` | async runtime |
| `tokio-rustls` | 0.26.6 | `aws_lc_rs`; no defaults | TLS acceptor |
| `tokio-util` | 0.7.20 | `rt` | cancellation tokens, task tracker |
| `tracing` | 0.1.44 | | structured logs |
| `tracing-subscriber` | 0.3.23 | `env-filter`, `json` | log output |
| `uuid` | 1.29.3 | `v7`, `serde` | identifiers |
| `vsock` | 0.5.5 | | guest agent transport |

The cryptographic provider is `aws-lc-rs` (locked 1.19.0, with `aws-lc-sys` 0.47.0); it builds here with a C
compiler only. `rustls-webpki` is locked at 0.103.17. The guest-traffic crate uses `rustix`, `serde`, `serde_json`,
`thiserror`, `tokio` and `tracing` only: it has no TLS library, because it reads a server name and decrypts nothing.

## 5. Python

Both projects require Python `>=3.12`. They were exercised on Python 3.12.3; 3.13 is listed in the client's
classifiers and was not run.

Both lock files were regenerated with `uv` 0.13.1 and are accepted unchanged (`uv lock --check`) by 0.13.9, the
release the workflows pin.

`apps/host-cli` (the `acf-local` client; **verified** and **exercised** on 2026-11-18):

| Package | Floor | Locked | Cap and reason |
|---|---|---|---|
| `typer` | 0.29.1 | 0.29.1 | `<0.30`: before 1.0 a minor release can break |
| `pydantic` | 2.14.3 | 2.14.3 | `<3`: the next major |
| `rich` | 15.0.0 | 15.0.0 | `<16`: the next major |

The runtime surface is three libraries on purpose: the client talks to a privileged host agent, so each dependency
is supply-chain surface. TLS is the standard library's `ssl`. Development only: `pytest` 9.2.0, `pytest-timeout`
2.4.0, `pytest-cov` 7.1.0, `jsonschema` 4.26.0, `types-jsonschema` 4.26.0.20261006, `mypy` 2.4.1, `ruff` 0.17.5;
build backend `hatchling` 1.33.0.

Repository tooling (root `pyproject.toml`; no runtime dependencies): `pytest` 9.2.0, `pytest-timeout` 2.4.0,
`jsonschema` 4.26.0, `types-jsonschema` 4.26.0.20261006, `mypy` 2.4.1, `ruff` 0.17.5, `shellcheck-py` 0.11.0.1.

## 6. CI, release and supply-chain tooling

GitHub Actions are pinned to full commit SHAs with the tag in a trailing comment. Resolved by `git ls-remote` on
2026-11-18:

| Action | Tag | Commit |
|---|---|---|
| `actions/checkout` | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `astral-sh/setup-uv` | v10.3.3 | `68559e99cc807c1eb7e9238fd43a15bba460eec2` |
| `actions/upload-artifact` | v7.0.2 | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` |
| `Swatinem/rust-cache` | v2.9.3 | `d1527c8f67ef9af357290475d4af4b0fab8f12e0` (peeled; the tag is annotated) |

A commit cannot be re-pointed the way a tag can. What it does not prove is that the commit is the one the
maintainers intended; that needs the project's release notes or signatures. Dependabot proposes updates for the
actions, the Rust lock and both Python locks. A guard test fails if any `uses:` is not an exact tag or a 40-hex
commit.

| Tool | Pinned | Where | Verified |
|---|---|---|---|
| `uv` | 0.13.9 | `setup-uv` input in the workflows | 2026-11-18 |
| `cargo-audit` | 0.23.0 | `audit.yml` | 2026-11-18 |
| `pip-audit` | 2.10.1 | `audit.yml` | 2026-11-18 (still the newest) |

## 7. Firecracker, guest kernel, base images

| Input | State | Evidence |
|---|---|---|
| Firecracker | **`v1.17.0`** in `scripts/firecracker.lock` and in the example configuration | Release published 2026-09-10. Its changelog lists the `sync_snapshot_files` snapshot parameter this host uses, and a fix for an ownership race in the jailer. |
| Firecracker tarball digests | **pinned** for `x86_64` and `aarch64` | Each value was read from two published sources that agree: the release's asset metadata and the `.sha256.txt` file beside the tarball. The `x86_64` tarball was then downloaded and installed by `scripts/install-firecracker.sh` on the test host, and the digest the installer measured equals the pin. The `aarch64` tarball was not downloaded. The installer measures what it downloads and refuses on any difference, so a wrong value fails closed. |
| The installed `firecracker` and `jailer` binaries | **pinned per host**, not in the repository | `firecracker.firecracker_sha256` and `firecracker.jailer_sha256` in the host configuration. The installer prints the digest of each file it installed from the verified tarball; the host hashes both at startup and before every launch. The example configuration leaves them unset: a digest that nobody measured would be worse than none. |
| Firecracker `v1.18.0` | **not adopted** | Published 2026-11-09. It adds a new device type and changes none of the API calls or jailer flags this host uses. The pin moves only together with a run of the integration suites on a KVM host. That run exists for `v1.17.0`, not for `v1.18.0`. |
| Guest kernel digest, `x86_64` | **pinned** | `vmlinux-6.1.188` of Firecracker's CI artifact set `20261105-6ea6634994fa-0`, 45,188,080 bytes. The download matched the bucket's multipart ETag. Its embedded configuration and its published `.config` both pass `tools/check_kernel_config.py`. It booted every guest of the integration run (see [VERIFICATION_STATUS.md](VERIFICATION_STATUS.md)). |
| Guest kernel digest, `aarch64` | **`UNSET`** | No `aarch64` kernel was downloaded and no `aarch64` machine was available. `make check-pins-release` therefore still fails, as it must. |
| Base image digests | **pinned**, all four | Resolved by `scripts/pin-images.sh` (Docker's view of the registry) and again by the registry's own API without Docker; both gave the same digest of each tag's multi-architecture index. The `python` image was built from its pin and booted. `base`, `node` and `browser` were pinned and not built. |

Security notices read while choosing the pin: CVE-2026-1386, published in January 2026, by which the jailer could
be made to overwrite a host file through a symbolic link
([AWS security bulletin 2026-003](https://aws.amazon.com/security/security-bulletins/2026-003-AWS/)); the security
fix in v1.15.1 (CVE-2026-5747); and the fixes for races in the jailer listed for v1.16.2 and v1.17.0. All of them
are in the pinned release. The host's own trusted-input rule (no link at the leaf of a file, every directory on the
way closed to other users) is the defence in depth against the same class of problem.

`make check-pins` validates the pin files and their consistency; `make check-pins-release` fails while anything is
`UNSET`, so a release cannot be cut with unpinned inputs by accident.

## 8. What could not be verified

* **Bare metal and `aarch64`.** The microVMs of the integration run were booted under nested virtualisation, on
  `x86_64`, inside WSL 2. See [VERIFICATION_STATUS.md](VERIFICATION_STATUS.md).
* **The `base`, `node` and `browser` images.** Their bases are pinned; the images were not built.
* **Advisory databases, over time.** `cargo audit --deny warnings` (cargo-audit 0.23.0) over the 229 locked crates
  and `pip-audit` (2.10.1) over both Python lock files reported nothing on 2026-11-18. An advisory published later
  is found only by running them again; `audit.yml` does that on a schedule.
* **Upstream changelogs of every bumped crate.** The bumps in §3 were judged by building and by the full test
  suites, not by reading each changelog.
* **Python 3.13.**

## 9. Upstream guidance and prior art

What the design takes from others, and where it was read (all on 2026-11-18).

**Firecracker's own guidance.**

| Source | What it says | Where the host follows it |
|---|---|---|
| [Production host setup](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md) | run through the jailer with a uid and gid per instance; keep the default seccomp filters; disable the serial console or bound its output; bound logs; disable swap; disable SMT; disable kernel same-page merging; block guest access to the metadata address; have the host end an unresponsive VMM; keep the parents of the jailer's inputs unwritable | `backend/firecracker/jailer.rs` (never `--no-seccomp`), the identifier pool, `8250.nr_uarts=0` in the default boot arguments, `diagnostic_log` off by default, the `swap`, `smt` and `ksm` checks of `acf-host doctor`, the always-denied address classes of mode `allowlist`, the execution backstop and the lifetime enforcer, the trusted-input rule |
| [Jailer](https://github.com/firecracker-microvm/firecracker/blob/main/docs/jailer.md) | the jailer's inputs are trusted; it creates the device nodes and the cgroup | every jailer input is derived from validated ids and checked as a trusted input; cgroup v2 only |
| [Snapshot support](https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/snapshot-support.md) | snapshot files are trusted and must be protected; a snapshot is loaded by the version that took it; resuming one snapshot more than once makes guests share random state unless the guest reseeds | digests held in the store and verified on the bytes loaded; the version in the compatibility gate; the restore result notes a repeated restore; the backend does not claim entropy reseeding |
| [Network for clones](https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/network-for-clones.md) | give each clone its own network namespace with the same device name | one namespace per sandbox, device `tap0`, one constant guest segment |
| [Changelog](https://github.com/firecracker-microvm/firecracker/blob/main/CHANGELOG.md), [releases](https://github.com/firecracker-microvm/firecracker/releases) | versions, dates, API changes | the pin and the transcribed API models |

**Projects that solve a neighbouring problem.** None of their code is used; these are the patterns recognised in
them and applied here.

| Project | Pattern | Here |
|---|---|---|
| [E2B infrastructure](https://github.com/e2b-dev/infra) | a per-node orchestrator behind an API; a daemon inside each sandbox; a network namespace and an egress filter per sandbox; templates restored from snapshots | the host agent as the per-node authority; the guest agent; per-sandbox namespace and filter; restore as a new generation |
| [OpenSandbox egress component](https://www.mintlify.com/alibaba/OpenSandbox/components/egress) | a DNS proxy that feeds packet-filter sets with a lifetime | the resolver records the addresses it returned, and a name entry is honoured only for those addresses within the binding lifetime |
| [Evervault: egress networking with packet-filter redirection](https://evervault.com/blog/built-enclaves-egress-networking-iptables), [trans_proxy](https://madeye.github.io/trans_proxy/) | redirect all outbound TCP to a local proxy, recover the destination with `SO_ORIGINAL_DST`, read the TLS server name | the relay of the guest-traffic role |
| flintlock, firecracker-containerd, Kata Containers | a VMM behind a narrow provider interface; a guest agent over vsock | the backend port and its capability profile; the guest protocol |
| [AWS Lambda MicroVMs announcement](https://aws.amazon.com/about-aws/whats-new/2026/06/aws-lambda-microvms) | microVM isolation offered as a product primitive for untrusted code | context for the threat model, not a design input |

## 10. How to re-verify

```sh
# Rust: anything newer than the lock allows? (prints what would change, writes nothing)
cargo update --dry-run

# Python: does each lock match its manifest, and is anything newer?
uv lock --check && uv --directory apps/host-cli lock --check
uv lock --upgrade --dry-run

# Actions: the commit a tag points at (an annotated tag shows a second, peeled line)
git ls-remote https://github.com/actions/checkout.git 'refs/tags/v7.0.1' 'refs/tags/v7.0.1^{}'

# Firecracker: the published digests of the pinned release
gh api repos/firecracker-microvm/firecracker/releases/tags/v1.17.0 \
  --jq '.assets[] | select(.name | endswith(".tgz")) | "\(.name) \(.digest)"'
```

Then run the gates in [VERIFICATION_STATUS.md](VERIFICATION_STATUS.md). A dependency change is accepted only when
the whole gate passes on the new lock.
