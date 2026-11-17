# Agent Compute Fabric — 

A **local, secure execution runtime**: run untrusted, agent-generated code inside a Firecracker microVM on one Linux
host, with no network, hard resource limits, durable crash recovery, snapshots that restore to a *verified* state, and
**evidence** (run id, exit code, stdout/stderr, metrics, artifact references) for every run.

```bash
acf-local run --image python --cpu 2 --memory 4096 --network none --command "python experiment.py"

acf-local run --image python --cpu 2 --memory 4096 --network none --keep --name lab --command "python experiment.py"
acf-local snapshot create baseline --sandbox lab
acf-local snapshot restore baseline        # rolls `lab` back and prints the verified-restore evidence
```


> **Status — read this before you rely on it.**
> The code is complete for the contract and every check that can run **without KVM, root or network** passes
> (Rust, the Python CLI, the repository tooling, the in-memory end-to-end and control-plane suites).
> **No real microVM has ever been booted from this code**: the environment it was written in has no `/dev/kvm`. The KVM
> integration and isolation suites exist, are type-checked, and have **not been run**. The base-image, kernel and
> Firecracker digests are deliberately `UNSET`, so the installer and the image builder refuse to proceed until you pin
> them. [docs/VERIFICATION_STATUS.md](docs/VERIFICATION_STATUS.md) lists exactly what was run, with counts, and what was not.

## How it works in one paragraph

`acf-local` (Python) turns a command line into one request and prints the answer; it never enforces policy.
`acf-host` (Rust, one root process) authenticates the caller with `SO_PEERCRED`, checks the request against policy and
capacity, **writes the intent to a CRC-framed journal before touching anything**, launches a jailed Firecracker VM with
no network device inside an empty network namespace, *reads `/proc` back to confirm the confinement took hold*, runs the
command through a tiny in-guest agent, and records the result. After any crash, a pure decision table classifies every
half-finished operation: adopt it, clean it, quarantine it, or report it as `UNKNOWN`, which is never retried blindly.

## Quick start (no KVM needed)

You need a Rust toolchain (`rust-toolchain.toml` pins 1.97.0), [`uv`](https://docs.astral.sh/uv/) and Python 3.12 or
newer. Everything goes through `make`; `make help` lists every target.

```bash
make check          # everything that runs without KVM, root or network
make ci             # what CI runs on every push (adds the production build, e2e, driver self-test, control-plane)
```

The pieces, if you want them one at a time: `make rust-test`, `make py-test`, `make tools-test`, `make e2e` (the real CLI
against the real host server over a real socket, with in-memory VMs), `make control-plane` (the policy and admission
suites against the shipped config and policy) and `make release` (the production `acf-host`, proven to contain no test code).

## On a KVM host

[docs/OPERATIONS.md](docs/OPERATIONS.md) is the path: what the machine must provide, install, pin the inputs, grant access,
size it, run it, recover it, and run the KVM suites with `make integration`. Budget for first-contact corrections: that
document has never been executed on real hardware by its author.

## Package and export

```bash
make dist           # dist/agent-compute-fabric-phase1.zip: reproducible, sorted, fixed timestamps, with MANIFEST.sha256

python3 -I tools/zip_to_markdown.py dist/agent-compute-fabric-phase1.zip \
    --out dist/markdown --bundle dist/markdown/BUNDLE.md
```

The converter writes one markdown page per file under `dist/markdown/files/`, an `INDEX.md` holding the **complete
directory tree**, and (with `--bundle`) the whole phase as a single document. It treats the ZIP as untrusted input:
unsafe names, links, size bombs and manifest mismatches are refused before anything is written.

## Layout

```text
execution/
  wire/            acf-wire: framing and guest-protocol types shared by host and guest
  host-agent/      acf-host: the privileged plane (admission, journal, lifecycle, recovery, Firecracker backend)
  guest-agent/     acf-guest-agent: the in-VM executor (static musl, vsock)
apps/cli/          acf-local: the Python client (Typer + Pydantic), its own lock file and tests
images/            image recipes, images.lock pins, the acf-init overlay
scripts/ tools/    install / build / pin scripts and the Python tools behind them
deploy/ config/ policies/ schemas/    systemd units, shipped config and policy, generated JSON Schemas
tests/             integration + isolation (KVM), helpers (black-box driver), scripts, tools, fixtures
docs/              the documents below
.github/           ci, audit and (manual, self-hosted KVM) integration workflows
```

## Documents

| Read this | When you want to know |
|---|---|
| [docs/GUIDE.md](docs/GUIDE.md) | how to *think* about the codebase: four levels (what the code does → how it is structured → where the risks and seams are → what it optimises), reading order, how to change it safely |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | how the code realises the contract: components, trust boundaries, operation protocol, recovery, known gaps |
| [docs/CONTRACT_COMPLIANCE.md](docs/CONTRACT_COMPLIANCE.md) | where each clause of the spec (gates A–H, §27 tests, SEC-001…015, Δ ledger) is proven, and where the implementation chose a stricter reading |
| [docs/DECISIONS.md](docs/DECISIONS.md) | 25 decisions the spec leaves open, with reasoning and the way back |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | installing, pinning, running and recovering it |
| [docs/DEPENDENCY_PROVENANCE.md](docs/DEPENDENCY_PROVENANCE.md) | where every version came from, how it was verified, and what could not be |
| [docs/VERIFICATION_STATUS.md](docs/VERIFICATION_STATUS.md) | what has and has not been run, with counts |
| [apps/cli/README.md](apps/cli/README.md) · [images/README.md](images/README.md) | the CLI's commands and exit codes · building and pinning guest images |

## Compressed summary

A ledger-first, kernel-enforced, evidence-producing sandbox runtime: Python asks, Rust decides and verifies, a pure table
repairs after crashes, and nothing is ever reported as success when it might not be.
