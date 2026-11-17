# acf-local — Agent Compute Fabric, Phase 1 CLI

`acf-local` is the command-line client for the Phase 1 **host agent** (`acf-host`). It runs
untrusted code in a local, network-less Firecracker microVM and gives you back *evidence* of what
happened: a run id, the exit status, stdout and stderr, resource metrics, and artifact references.

```console
$ acf-local run --image python --cpu 2 --memory 4096 --network none --command "python experiment.py"
```

This process is only a client. It parses arguments, resolves names to ids, renders results and
chooses exit codes. Every decision about what is *allowed*, which transitions are *legal* and what
*actually happened* is made by the privileged Rust host agent; nothing here is trusted to enforce
it (boundary BND-01 of the Phase 1 contract).

## Install

```console
uv tool install ./apps/cli          # puts `acf-local` on your PATH
# or, from a checkout, without installing:
python apps/cli/main.py --help
```

Requires Python 3.12+. Runtime dependencies are deliberately few (`typer`, `pydantic`, `rich`):
this process talks to a privileged socket, so every dependency is supply-chain surface.

## Connecting

The CLI talks to the host agent over a Unix socket (default `/run/acf/host-agent.sock`, the same
default the host binds). Override with `--socket PATH` or `ACF_SOCKET`; `--io-timeout` /
`ACF_IO_TIMEOUT` bounds how long a *prompt* reply (anything but `run`/`exec`) may take. The host
identifies you by the kernel's `SO_PEERCRED`, not by anything you send, and applies the policy bound
to your uid/gid.

A Unix socket path may be at most 107 bytes long (kernel limit). The host refuses to start with a
longer `paths.socket_path`; the CLI copes with long *client* paths by connecting through a directory
file descriptor.

## Commands

| Command | What it does |
|---|---|
| `run` | create → start → exec → destroy, in one go (the Phase 1 milestone) |
| `exec NAME -- CMD...` | run a command in an existing sandbox |
| `sandbox create/start/stop/destroy/list/inspect` | explicit lifecycle |
| `snapshot create/restore/list/inspect/delete` | snapshots, and rollback *with proof* |
| `evidence get RUN_ID` | the evidence record of a run (finished or not) |
| `operation get/cancel OP_ID` | observe or cancel an operation — the recovery tool |
| `host info/metrics/reload-policy` | what the host is, and what it is enforcing |

Every command accepts `--json` (machine-readable on stdout; human text goes to stderr).
Destructive commands (`sandbox destroy`, `snapshot delete`) ask for confirmation on a terminal and
**refuse** without `--yes` when there is no terminal to ask on.

### Which stream carries what

`stdout` is for **data**, `stderr` is for **people**:

* `run` / `exec` (and `evidence get --output`): `stdout` is the guest's stdout, byte for byte, and
  nothing else; the guest's stderr goes to `stderr`, followed by the structured run report.
* with `--json`: `stdout` is exactly one JSON document and the guest's output is *inside* it
  (base64). Nothing else is written to `stdout`.
* every other command: the result is on `stdout`, errors and hints on `stderr`.

### How `run` treats your command

The command is **not run through a shell**. `--command "python a.py --x 1"` is split POSIX-style
into `argv`. Use `--shell` (or `-- sh -c '...'`) when you want pipes, globs or `&&`.

Guest output is *untrusted*. When stdout/stderr is a terminal, control and bidi characters are
shown as visible escapes so a workload cannot retitle your terminal or rewrite earlier lines.
When piped or redirected the bytes pass through exactly. `--raw` disables sanitizing.

### Two different questions: "did the operation work?" and "did the workload succeed?"

An `exec` **operation** is `SUCCEEDED` whenever the host ran the command and recorded the result —
even if the command exited 3 or was cancelled. *How the workload ended* is in the run's
`outcome` (`SUCCEEDED`, `FAILED`, `CANCELLED`, `TIMED_OUT`, `UNKNOWN`). The CLI keeps the two
apart: operation problems are exit codes `3`–`7`; the workload's own end is `0` or `1` (or its real
status with `--propagate-exit-code`).

### Exit codes

| Code | Meaning |
|---|---|
| `0` | success |
| `1` | the workload ran to a definite end but did not succeed (`--propagate-exit-code` returns its own status instead) |
| `2` | usage error (including: destructive command without `--yes` and no terminal) |
| `3` | the host refused the request; **nothing changed** |
| `4` | the operation was accepted and definitively failed — **also** returned by `run` when the command ran but destroying the sandbox failed (the exact command to finish the job is printed) |
| `5` | **outcome unknown / not final** — observe it (`operation get`), never re-run it |
| `6` | host agent unreachable |
| `7` | protocol violation (wrong peer or version) |
| `130` | interrupted (Ctrl-C); `141` if stdout was closed by the reader |

`--propagate-exit-code` exists for scripts that want the workload's own status (`128+N` when it was
killed by signal `N`). Those values live in the same number space as the table above: a workload
that exits `3` is indistinguishable from "the host refused" unless you also read `--json`. Use it
when you control the workload; otherwise prefer the default codes plus `--json`.

### Ctrl-C

* during `run`/`exec` the command is **cancelled** (a request: the CLI then observes how it ended and
  prints the evidence, including whatever the workload had already printed), the sandbox is cleaned
  up if every outcome is known, and the exit status is `130`;
* if the host cannot confirm how it ended, you are told so and given `acf-local operation get <id>`;
* during any other mutation you are told which operation was already sent and may still complete.
  It is journaled by the host: **observe it, do not repeat it.**

### The one rule

> A mutation whose outcome is unknown is **resolved by observation, never by re-running it.**

The CLI mints an operation id for every mutation. If a response is lost it asks the host what
happened; only when the host says it has never heard of the operation is the request submitted
again (same id; the host's atomic begin makes that exactly a first submission). `run` leaves its
sandbox in place if any step is unknown, because destroying it would erase the evidence.

## Development

```console
cd apps/cli
uv sync
uv run ruff check . && uv run ruff format --check .
uv run mypy
uv run pytest                      # unit + contract tests (+ e2e if the fake host is built)
```

End-to-end tests drive the real CLI against the real host server over a real Unix socket, on an
in-memory VM backend (**no KVM needed**; they prove the CLI ⇄ wire ⇄ host seams, not isolation):

```console
cargo build -p acf-host-agent --features testing --bin acf-host-fake   # test-only; never in a release
ACF_REQUIRE_E2E=1 uv run pytest -m e2e                                  # missing binary => FAIL, not skip
```

Set `ACF_HOST_FAKE=/path/to/acf-host-fake` to use another build. If your `$TMPDIR` is deep, point it
somewhere short (`TMPDIR=/tmp`): socket paths are limited to 107 bytes.

The repository's top-level `schemas/` holds the JSON Schemas emitted by `acf-host schema`;
`tests/test_contract.py` fails if the client's models drift from them. Refresh with `make schemas`.
