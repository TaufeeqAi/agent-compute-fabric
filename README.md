# Agent Compute Fabric

Two parts, in one repository:

* the **execution plane**: a host agent that runs untrusted, agent-generated code in Firecracker microVMs on one
  Linux host, and answers a small versioned API about them. Most of this page describes it;
* the **developer platform**: the service in front of a host that developers and agents actually use. A REST API
  and an agent-protocol (MCP) endpoint, a Python and a TypeScript SDK, and the `acf` command-line tool. It has
  [a section of its own](#the-developer-platform) below and its documents in [`docs/platform/`](docs/platform/).

## The execution plane

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
> The code implements the execution-plane contract, version 1.2.0. Everything that runs without KVM and without
> root passes: the Rust workspace, the Python client including its end-to-end suite against the real edge, core and
> store, and the repository tooling. With root and KVM, on one machine (WSL 2 on Windows 11, KVM nested inside
> Hyper-V, `x86_64`), the host was installed under systemd and **real Firecracker microVMs were booted from this
> code**. The suites that need a real guest ran there, and twelve defects that only a real host could show were
> found and fixed. That machine is a development laptop, not a production host. Its monotonic clock runs about 5.6 %
> slow, its disk is virtual, and its virtualisation is nested. Nothing has run on bare metal or on `aarch64`, and
> the `aarch64` kernel pin is still `UNSET`, so `make check-pins-release` fails on purpose. A host creates no sandbox
> until its configuration pins the digests of the two Firecracker binaries its installer printed.
> [docs/VERIFICATION_STATUS.md](docs/VERIFICATION_STATUS.md) lists what was run, with counts, what failed and why,
> and what was not run.

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
upgrade, and `make integration` for the suites that boot real microVMs. That path was followed on the machine
described in [docs/VERIFICATION_STATUS.md](docs/VERIFICATION_STATUS.md), nested virtualisation inside WSL 2; on bare
metal, expect corrections that a nested host could not show.

## The developer platform

The host's API is for a control plane: one enrolled peer, mutual TLS, no notion of a developer or a project. The
developer platform is that control plane's public side. It gives each developer and each agent a credential of
their own, decides what each may do, makes every request safe to repeat, and translates between a public model
and the host's protocol. It runs nothing itself: every sandbox is the host's, and the host's verdict is final.

```python
from agentcompute import Fabric

with Fabric() as fabric:                      # ACF_BASE_URL and ACF_API_KEY
    sandbox = fabric.sandboxes.create("python", cpu=1, memory="512MiB", disk="2GiB")
    result = sandbox.exec(["python", "-c", "print(6 * 7)"])
    print(result.exit_code, result.text())
    sandbox.destroy()
```

Three processes under three accounts: a **core** that verifies credentials, decides, keeps the ledger of requests
and holds the one credential the host knows; and two **edges**, one for REST and one for the agent protocol, that
read the bytes callers send and hold nothing but their TLS keys. An agent gets a short-lived credential that can
do less than the developer who minted it, and has no network unless destinations were granted.

> **Status.** The platform implements its contract, version 1.1.0; two surfaces the contract keeps off by default
> (an older revision of the agent protocol and its tasks extension) are not built, and
> [docs/platform/CONTRACT_COMPLIANCE.md](docs/platform/CONTRACT_COMPLIANCE.md) lists every other place where the
> implementation reads the contract narrowly. Its gate passes, including the whole chain
> against the host's in-memory build over the real protocol and mutual TLS, and a deployment test that installs
> the shipped units on a machine with systemd, starts them, drives a developer's and an agent's journey through
> the TLS endpoints, and inspects what the running processes can reach. It has **not** run against a host that
> boots real microVMs, the GitHub workflows have not run on GitHub, and **no package is published**: the package
> names are not registered, so every README installs from a checkout.
> [docs/platform/VERIFICATION_STATUS.md](docs/platform/VERIFICATION_STATUS.md) lists what was run and what was not.

```bash
make platform-check    # contract files and their compatibility, lint, tests of the four Python projects, the TypeScript SDK, the units
make platform-e2e      # the platform against the in-memory host, over the real protocol and mutual TLS
make platform-dist     # build every package and prove that the files install and import
```

| Read this | When you want to know |
|---|---|
| [docs/platform/QUICKSTART.md](docs/platform/QUICKSTART.md) | how to go from a key to a running command: Python, TypeScript, the command line, plain HTTP, an agent |
| [docs/platform/ARCHITECTURE.md](docs/platform/ARCHITECTURE.md) | how the platform is built: roles, the pipeline of a request, the ledger, recovery, credentials and grants, the agent interface |
| [docs/platform/OPERATIONS.md](docs/platform/OPERATIONS.md) | installing, configuring, running, backing up and upgrading a deployment |
| [docs/platform/CONTRACT_COMPLIANCE.md](docs/platform/CONTRACT_COMPLIANCE.md) · [DECISIONS.md](docs/platform/DECISIONS.md) | where each clause is implemented and tested · what the contract left open, and why it was decided as it was |
| [docs/platform/VERIFICATION_STATUS.md](docs/platform/VERIFICATION_STATUS.md) · [DEPENDENCY_PROVENANCE.md](docs/platform/DEPENDENCY_PROVENANCE.md) | what was run, with counts · where every version came from |
| [docs/platform/RELEASING.md](docs/platform/RELEASING.md) | how a package reaches a registry, by identity and with provenance |
| [protocols/](protocols/) | the public contract as files: OpenAPI, tool definitions, the problem registry, the client conformance suite |

## Layout

```text
execution/
  wire/            acf-wire: framing and the host-guest protocol, shared by host and guest
  traffic/         acf-traffic: the guest-traffic domain (allowlist verdicts, resolver, relay); no host-mutation code
  host-agent/      acf-host: edge, core, store, recovery, lifetime enforcer, Firecracker backend
  guest-agent/     acf-guest-agent: the in-VM executor (static, vsock)
  contracts/       host-api.json, event-schema.json: generated from the Rust types, checked in
apps/host-cli/     acf-local: the host operator's Python client, with its own lock file and tests
apps/api/          acf-api: the platform's core and REST edge
apps/mcp-gateway/  acf-mcp: the platform's agent-protocol edge
apps/cli/          acf: the developer's command-line tool, on the Python SDK
sdks/              python/ (agentcompute) and typescript/ (@agent-compute/sdk)
protocols/         the platform's public contract, generated from apps/api and checked in
policies/          the default grant templates of the platform
config/ profiles/  the shipped example configuration, enrolment table and safety profile
schemas/           generated JSON Schemas of the files a host reads or writes
deploy/            systemd units, sysusers and tmpfiles snippets (the platform's under deploy/platform/)
scripts/ tools/    install, build and pin scripts, and the Python tools behind them
images/            guest image recipes, pins, the init overlay
tests/             scripts and tools tests; integration and isolation suites (KVM), with a control-plane subset
docs/              the documents below; the platform's under docs/platform/
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
| [apps/host-cli/README.md](apps/host-cli/README.md) · [images/README.md](images/README.md) | the client's commands and exit codes · building and pinning guest images |


## In one sentence

Record first, verify by observation, contain under every failure, and never report as success what might not be.
