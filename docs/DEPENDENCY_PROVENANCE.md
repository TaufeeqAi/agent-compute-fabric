# Dependency provenance

Where every version in this repository came from, how it was checked, when, and what could **not** be checked.

The rule for this phase was: *resolve versions from the registries at write time; do not default to whatever the author
remembers.* A model's memory of "the latest" is stale by construction, so the repository records its evidence instead of
asking you to trust it.

Three kinds of statement are kept apart below:

| Label | Meaning |
|---|---|
| **Verified** | Read from the authoritative registry or git remote on the stated date, by a command that is described here. |
| **Exercised** | Compiled and tested in this repository on the stated date (see [VERIFICATION_STATUS.md](VERIFICATION_STATUS.md)). |
| **Unverified** | Could not be reached or checked from the environment this was written in. Listed in full in §7. |

## 1. Method

| Ecosystem | Authority used | How the newest release was chosen |
|---|---|---|
| Rust crates | crates.io sparse index (`https://index.crates.io/<prefix>/<name>`) | Newest version that is neither yanked nor a pre-release. |
| Python packages | PyPI JSON API (`https://pypi.org/pypi/<name>/json`) | Newest version that is neither yanked nor a pre-release, and whose files are not all yanked. |
| GitHub Actions, Firecracker | `git ls-remote --tags` on the project's repository | Newest stable semver tag; an annotated tag is **peeled** (`refs/tags/<tag>^{}`) to the commit it points at. |
| Rust toolchain | `rustc --version` of the installed stable channel | Equal to `rust-toolchain.toml`. |

Manifests carry **floors** (`>=` for Python, caret requirements for crates), the committed locks (`Cargo.lock`,
`uv.lock`, `apps/cli/uv.lock`) carry the **exact** resolution, and every `cargo` and `uv run` invocation in the Makefile
and the workflows passes `--locked`, which fails instead of silently re-resolving. A floor is the oldest version the code was tested against; the lock is what was
actually built.

## 2. Resolution log

| Date | What was resolved or re-checked |
|---|---|
| 2026-10-09 | Rust crates (first resolution); Firecracker tag and changelog. |
| 2026-10-13 | Python packages. |
| 2026-10-14 | GitHub Action release tags; `cargo-audit`; `pip-audit`. |
| 2026-10-17 | **Everything re-checked** (drift found, see §3); lock files regenerated; all gates re-run. |
| 2026-10-18 | Action tags re-resolved to commit SHAs with `git ls-remote`; workflows now pin the SHAs. |

## 3. Drift found by the re-check (2026-10-09 → 2026-10-17)

Eleven pins had moved in eight days. This is the reason the re-check exists: a version that was "latest" when first
resolved is not latest when the phase ships.

| Pin | Before | After | Note |
|---|---|---|---|
| `proptest` | 1.11.0 | 1.12.0 | dev only |
| `schemars` | 1.2.2 | 1.2.3 | JSON-schema generation |
| `serde_json` | 1.0.151 | 1.0.154 | |
| `serde-saphyr` | 1.3.0 | **2.0.0** | **Major bump.** YAML loader for config and policy. The upstream changelog could not be fetched, so the upgrade was judged empirically: the workspace compiles, and every Rust test (including the shipped config/policy parsing and the trusted-file loader) passes. |
| `sha2` | 0.11.0 | 0.11.1 | image and policy digests |
| `tokio` | 1.53.2 | 1.53.3 | |
| `tokio-util` | 0.7.19 | 0.7.20 | |
| `uuid` | 1.27.0 | 1.28.0 | UUID v7 operation/run identifiers |
| `ruff` | 0.17.0 | 0.17.1 | dev tool |
| `pydantic` | 2.14.0 | 2.14.1 | CLI response models |
| `uv` (CI `setup-uv` input) | 0.13.0 | 0.13.1 | |

## 4. Rust

Toolchain: `rust-toolchain.toml` pins **1.97.0** (components `rustfmt`, `clippy`); `rust-version = "1.97"`, edition 2024.
The highest `rust-version` declared by any locked dependency is **1.89** (`uuid` 1.28.0, `serde-saphyr` 2.0.0), so the
workspace's own 1.97 is a choice (the verified toolchain), not a requirement of a dependency.

The 1.97.0 toolchain download was blocked in the authoring environment; the tests were run on the installed **stable**
channel, which was also `rustc 1.97.0`. The pinned toolchain itself was therefore not downloaded there.

`Cargo.lock` holds 182 packages. The direct dependencies (workspace manifest floor = locked version, 24 crates, all **verified** on
2026-10-17 and **exercised** on the same day):

| Crate | Locked | Features | Used for |
|---|---|---|---|
| `async-trait` | 0.1.92 | | `SandboxBackend` and other async traits |
| `base64` | 0.23.1 | | binary stdout/stderr data inside JSON (`wire::guest`, host exec) |
| `cap-std` | 4.0.3 | | capability-based file access for state and artifacts |
| `clap` | 4.6.7 | `derive` | host-agent and fake-host command lines |
| `crc32fast` | 1.5.2 | | write-ahead journal checksums |
| `hex` | 0.4.3 | | digests |
| `http-body-util` | 0.1.5 | | Firecracker API client |
| `hyper` | 1.12.0 | `client`, `http1` | Firecracker API client over a Unix socket (also re-exports `Bytes`) |
| `hyper-util` | 0.1.21 | `tokio` | same |
| `proptest` | 1.12.0 | | property tests (`dev-dependencies`) |
| `rustix` | 1.1.5 | `fs process thread mount system time pipe event` | safe syscall wrappers (peer credentials, file-system and process calls); the host forbids `unsafe` |
| `schemars` | 1.2.3 | | JSON Schema generation for the host's protocol and record types (`make schemas`) |
| `serde` | 1.0.229 | `derive` | |
| `serde-saphyr` | 2.0.0 | | YAML config and policy |
| `serde_json` | 1.0.154 | | wire envelope, journal records |
| `sha2` | 0.11.1 | | image identity, policy digest |
| `tempfile` | 3.27.0 | | tests only (`dev-dependencies` in both agents) |
| `thiserror` | 2.0.21 | | error types |
| `tokio` | 1.53.3 | `rt-multi-thread macros net io-util time fs process signal sync` | async runtime |
| `tokio-util` | 0.7.20 | | `CancellationToken` for shutdown and operation cancel |
| `tracing` | 0.1.44 | | structured logs |
| `tracing-subscriber` | 0.3.23 | `env-filter`, `json` | JSON logs |
| `uuid` | 1.28.0 | `v7`, `serde` | identifiers |
| `vsock` | 0.5.4 | | guest agent transport |

## 5. Python

Both packages require Python `>=3.12`.

`apps/cli` (the `acf-local` CLI; **verified** 2026-10-13, re-verified 2026-10-17):

| Package | Floor | Locked | Cap and reason |
|---|---|---|---|
| `typer` | 0.27.3 | 0.27.3 | `<0.28`: pre-1.0, minor releases can break |
| `pydantic` | 2.14.1 | 2.14.1 | `<3`: the next major |
| `rich` | 15.0.0 | 15.0.0 | `<16`: the next major |

The runtime surface is deliberately three libraries: the CLI talks to a privileged socket, so each dependency is
supply-chain surface. Dev-only: `pytest` 9.1.1, `pytest-timeout` 2.4.0, `pytest-cov` 7.1.0, `jsonschema` 4.26.0,
`types-jsonschema`, `mypy` 2.4.0, `ruff` 0.17.1 (`uv.lock` has 33 packages).

Repository tooling (`pyproject.toml` at the root; no runtime dependencies; `uv.lock` has 22 packages): `pytest` 9.1.1,
`pytest-timeout` 2.4.0, `jsonschema` 4.26.0, `types-jsonschema`, `mypy` 2.4.0, `ruff` 0.17.1, `shellcheck-py` 0.11.0.1.

## 6. CI, release and supply-chain tooling

GitHub Actions, pinned to full commit SHAs (the tag is in a trailing comment). Tags were checked on 2026-10-14; the SHAs
were resolved on 2026-10-18 by `git ls-remote` and re-checked against the tag in the same command that rewrote the
workflows.

| Action | Tag | Commit SHA |
|---|---|---|
| `actions/checkout` | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `astral-sh/setup-uv` | v10.3.0 | `1c37ad07a6a961277cf70c0d37d6f313000f5884` |
| `actions/upload-artifact` | v7.0.2 | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` |
| `Swatinem/rust-cache` | v2.9.1 | `c19371144df3bb44fab255c43d04cbc2ab54d1c4` (peeled; the tag is annotated) |

A commit SHA cannot be re-pointed the way a tag can. What it does not prove is that the commit is the one the maintainers
signed off on; that needs the project's release notes or signatures, which could not be consulted. Dependabot
(`.github/dependabot.yml`: `github-actions`, `cargo`, `uv` twice, weekly) proposes updates and rewrites the SHA and the
tag comment together. A guard test (`tests/scripts/test_makefile_and_ci.py`) fails if any `uses:` is not an exact tag or a
40-hex SHA.

| Tool | Pinned version | Where | Verified |
|---|---|---|---|
| `uv` | 0.13.1 | `setup-uv` input in all three workflows | 2026-10-17 |
| `cargo-audit` | 0.22.2 | `audit.yml`, installed with `cargo install --locked` | 2026-10-14 |
| `pip-audit` | 2.10.1 | `audit.yml`, via `uvx --from pip-audit==2.10.1` | 2026-10-14 |
| `actionlint` | 1.7.12 | used while authoring; **not** a repository dependency (see `.github/actionlint.yaml` for its one custom-label setting) | 2026-10-17 |

## 7. Firecracker, guest kernel, base images

| Input | State | Evidence |
|---|---|---|
| Firecracker | **`v1.17.0`** in `scripts/firecracker.lock` and `config/host.example.yaml` (kept equal by `make check-pins`) | The tag exists; its changelog lists `[1.17.0]` including the `sync_snapshot_files` snapshot parameter this host uses; no `v1.17.1` or `v1.18.0` existed on 2026-10-09/12. |
| Firecracker tarball digests | **`UNSET`** (`SHA256_x86_64`, `SHA256_aarch64`) | The release assets were unreachable from the authoring environment. `scripts/install-firecracker.sh` **refuses** (exit 3) while a digest is `UNSET`. |
| Guest kernel digests | **`UNSET`** (`KERNEL_SHA256_*`) | No kernel was built or downloaded. |
| Base image digests | **`UNSET`** (`BASE_DIGEST_base`, `_python`, `_node`, `_browser`) | The registries were unreachable. The tags in `images/images.lock` (`debian:trixie-slim`, `python:3.14-slim-trixie`, `node:24-trixie-slim`) were chosen by the author and **not re-resolved**; `scripts/pin-images.sh` resolves them to digests and fails loudly on a tag that does not exist. |

`make check-pins` validates the pin files' shape and cross-file consistency; `make check-pins-release` additionally
**fails** while anything is `UNSET`, so a release cannot be cut with unpinned inputs by accident.

## 8. What could not be verified from the authoring environment

Blocked or unavailable, reported rather than routed around:

- **Container registries** (`public.ecr.aws`, Docker Hub): base-image tags unresolved, so every `BASE_DIGEST_*` is `UNSET`.
- **GitHub release assets and the GitHub REST API**: Firecracker tarball digests unset; Action SHAs were resolved with
  `git ls-remote` instead of the releases API.
- **Advisory databases** (RustSec, PyPI advisories): `cargo audit` and `pip-audit` have **never been run** on this lock
  set. `audit.yml` exists to run them where the databases are reachable.
- **Upstream changelog for `serde-saphyr` 2.0.0**: not fetchable; the major bump was evaluated by building and testing.
- **The pinned 1.97.0 toolchain download**: not fetchable; the installed stable `rustc 1.97.0` was used.
- **A KVM host, a container daemon, `CAP_SYS_RESOURCE`**: not available, so nothing here has booted a real microVM. See
  [VERIFICATION_STATUS.md](VERIFICATION_STATUS.md).

## 9. How to re-verify

Nothing below needs this repository's tooling beyond a shell, `git` and `curl`/`cargo`:

```sh
# Actions and Firecracker: the commit a tag points at (annotated tags show a second, peeled line)
git ls-remote https://github.com/actions/checkout.git 'refs/tags/v7.0.1' 'refs/tags/v7.0.1^{}'

# Rust: anything newer than the lock allows? (needs the network; prints what would change, writes nothing)
cargo update --dry-run

# Python: anything newer than the lock allows?
uv lock --check            # lock matches the manifest
uv lock --upgrade --dry-run
```

Then run the gates in [VERIFICATION_STATUS.md](VERIFICATION_STATUS.md). A dependency change is accepted only when the
whole gate passes on the new lock.
