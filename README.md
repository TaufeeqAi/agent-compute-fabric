# Agent Compute Fabric — execution plane

A **host agent that runs untrusted, agent-generated code in Firecracker microVMs** on one Linux host, for a control
plane (or an operator) that drives it over a small versioned API. It records every request as a durable operation,
survives its own crashes without losing or inventing state, and keeps removing privilege even when it can no longer
create any.

```console
# as an enrolled peer, over the host's local socket or its mutual-TLS endpoint
acf-local run once --image python --cpu 2 --memory 4Gi -- python experiment.py

acf-local sandbox create --image python --name lab --lifetime 2h \
    --network allowlist --allow pypi.org:443
acf-local sandbox start lab
acf-local sandbox exec lab -- python train.py
acf-local snapshot create lab --name baseline
acf-local snapshot restore baseline --into lab      # a new, verified generation of the same sandbox
```

> **Status — read this before you rely on it.**
> The code implements the execution-plane contract, version 1.2.0, and everything that can run **without KVM and
> without root** was run and passes: the Rust workspace, the Python client including its end-to-end suite against
> the real edge, core and store, and the repository tooling.
> **No microVM has been booted from this code.** The environment it was written in has no usable `/dev/kvm` and no
> root. Every isolation claim is therefore implemented and tested against doubles, not demonstrated on a real VMM.
> The guest kernel and base-image pins are still `UNSET`, so the image builder refuses to proceed until you pin
> them, and a host creates no sandbox until its configuration pins the digests of the two Firecracker binaries
> its installer printed. [docs/VERIFICATION_STATUS.md](docs/VERIFICATION_STATUS.md) lists what was run, with counts, and what was not.

## How it works

`acf-host` is one binary that runs in four roles. An unprivileged **edge** terminates the local socket and the
mutual-TLS endpoint, authenticates the peer against the enrolment table, and relays validated requests. A
privileged **core** is the only writer of the store and the only caller of the backend: it checks role, scope and
the host safety profile, **writes the intent to an append-only journal before touching anything**, launches a
jailed Firecracker VM, *reads the kernel's view back to confirm the confinement took hold*, runs commands through a
small in-guest agent, and records what happened. An unprivileged **guest-traffic** process per sandbox is the only
way out of a sandbox with network mode `allowlist`. A separate **lifetime enforcer** ends every runtime at its
expiry whether or not the core is running. After any crash, a pure decision table decides what to do with each
unfinished operation: undo it, finish removing what it removed, quarantine what cannot be proven ours, or report
`UNKNOWN`, which is never retried blindly.

## Quick start (no KVM, no root)

You need the Rust toolchain that `rust-toolchain.toml` pins, [`uv`](https://docs.astral.sh/uv/) and Python 3.12
or newer. Everything goes through `make`; `make help` lists every target.

```bash
make check          # everything that runs without KVM, root or network
make e2e            # the real client against the real edge and core, with in-memory VMs
make control-plane  # the black-box suites against the in-memory host with the shipped configuration and profile
```

One piece at a time: `make rust-test`, `make net-plumbing-test` (the namespace tests, inside an unprivileged user
namespace), `make py-test`, `make tools-test`, `make check-schema` (the generated contracts match the code) and
`make release` (the production `acf-host`, proven to contain no test-only code). `make root-test` runs the Rust
tests that need root.

## On a KVM host

[docs/OPERATIONS.md](docs/OPERATIONS.md) is the path: prerequisites, install, the three trusted files, enrolment,
`acf-host doctor`, the start order (control groups, lifetime enforcer, core), host modes, quarantine, backup,
upgrade, and `make integration` for the suites that boot real microVMs. Expect first-contact corrections: that
path has not been executed on real hardware by its authors.

## Layout

```text
execution/
  wire/            acf-wire: framing and the host-guest protocol, shared by host and guest
  traffic/         acf-traffic: the guest-traffic domain (allowlist verdicts, resolver, relay); no host-mutation code
  host-agent/      acf-host: edge, core, store, recovery, lifetime enforcer, Firecracker backend
  guest-agent/     acf-guest-agent: the in-VM executor (static, vsock)
  contracts/       host-api.json, event-schema.json: generated from the Rust types, checked in
apps/cli/          acf-local: the Python reference client, with its own lock file and tests
config/ profiles/  the shipped example configuration, enrolment table and safety profile
schemas/           generated JSON Schemas of the files a host reads or writes
deploy/            systemd units, sysusers and tmpfiles snippets
scripts/ tools/    install, build and pin scripts, and the Python tools behind them
images/            guest image recipes, pins, the init overlay
tests/             scripts and tools tests; integration and isolation suites (KVM), with a control-plane subset
docs/              the documents below
.github/           workflows that run the same make targets
```

## Documents

| Read this | When you want to know |
|---|---|
| [docs/GUIDE.md](docs/GUIDE.md) | how to read, reason about and change the codebase: four passes, reading order, who owns which promise, change recipes, review questions |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | how the code realises the contract: roles, the operation protocol, the store, recovery, the backend, network, trust boundaries |
| [docs/CONTRACT_COMPLIANCE.md](docs/CONTRACT_COMPLIANCE.md) | where each clause is implemented and tested, and where a clause had to be read one way |
| [docs/DECISIONS.md](docs/DECISIONS.md) | the decisions the contract leaves open, with reasoning and the way back |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | installing, enrolling, running, recovering and upgrading a host |
| [docs/VERIFICATION_STATUS.md](docs/VERIFICATION_STATUS.md) | what was run, with counts, and what was not |
| [docs/DEPENDENCY_PROVENANCE.md](docs/DEPENDENCY_PROVENANCE.md) | where every version came from, how it was verified, and the upstream guidance and prior art behind the design |
| [apps/cli/README.md](apps/cli/README.md) · [images/README.md](images/README.md) | the client's commands and exit codes · building and pinning guest images |

## Package and export

```bash
make dist           # dist/agent-compute-fabric-execution-plane.zip: sorted, fixed timestamps, with MANIFEST.sha256

python3 -I tools/zip_to_markdown.py dist/agent-compute-fabric-execution-plane.zip \
    --out dist/markdown --bundle dist/markdown/BUNDLE.md
```

The converter writes one markdown page per file, an index with the complete directory tree, and, with `--bundle`,
the whole tree as one document. It treats the archive as untrusted input: unsafe names, links, size bombs and
manifest mismatches are refused before anything is written.

## In one sentence

Record first, verify by observation, contain under every failure, and never report as success what might not be.
