# Verification status — what was run, what passed, what was not

Read this before trusting anything else in the repository. It lists the evidence that exists, with counts, and the
evidence that does not exist yet. Anything not listed as passing here is unverified.

Gates run on 2026-11-18, on the tree this file ships with, on the machine described in §9. The machine has no usable
KVM and no root, and that sets the limit of everything below.

## 1. The short version

Everything that can run **without KVM and without root** ran and passed:

| | Result |
|---|---|
| Rust workspace: format, lint (warnings are errors) in the test configuration and in the shipping configuration | clean |
| Rust workspace: every test, every feature | **509 passed, 0 failed, 18 ignored** |
| The namespace tests, inside an unprivileged user namespace | **10 passed** (4 of the 18 ignored tests are among them) |
| Generated contracts and schemas against the Rust types | no drift |
| The production `acf-host` | contains no test-only code; the check is validated against a binary that does |
| Reference client: lint, format, strict types | clean |
| Reference client: tests | **828 passed**; end to end against the real edge, core and store: **34 passed** |
| Repository tooling: lint, format, strict types | clean |
| Repository tooling and scripts: tests | **873 passed, 93 skipped** (they need root) |
| Black-box driver against the in-memory host | **43 passed** |
| Black-box suites against the in-memory host, with the shipped configuration and profile | **104 passed, 66 skipped** (65 need a real guest, 1 needs root) |

**No microVM has been booted from this code.** `/dev/kvm` exists on the machine and the build user may not open it;
there is no root and no container engine. Therefore:

* **Nothing at level L4 or L5 has run.** The tests that need a real guest exist and were skipped, not passed. On a
  KVM host `ACF_INTEGRATION=1` turns every one of those skips into a failure, so a skip can never stand for a result
  there.
* **13 Rust tests need root and were compiled, not run:** the twelve tests of the Firecracker adapter against an
  emulated VMM, and the guest agent's process-budget test.
* **Six pins are deliberately `UNSET`** (§7), and a host needs two digests of its own in its configuration before it
  creates a sandbox.

Every isolation claim in this repository is *implemented and tested against doubles*. None is *demonstrated*.

## 2. How much each kind of evidence is worth

The levels are the contract's (§31.1, TV-2). A test that needs L4 is never satisfied at L2.

| Level | What a pass shows | Status |
|---|---|---|
| L0 static | it compiles, is formatted, lint-clean and type-checked; generated contracts and schemas have not drifted; the release artifact holds no test code; shipped units and workflows parse | ran, passed. ShellCheck and actionlint are not installed here: not run |
| L1 unit and property | each pure decision and each module's rules: the lifecycle relation, the role and mode tables, admission arithmetic, the recovery table, the fingerprint, network verdicts, the journal's framing and replay, the parsers | ran, passed |
| L2 whole process, test backend | the real coordinator, store, recovery and admission pipeline over the in-memory backend; the roles as real processes; the real client against the real edge and core; the network plumbing in a real network namespace | ran, passed |
| L3 shipped configuration and profile | the shipped files load and agree with each other; the black-box suites against the in-memory host started with them | ran, passed |
| L4 real VMM | boot, jailer and seccomp confinement, kernel-enforced limits, both network modes as a guest experiences them, vsock, snapshots of real memory, recovery after a real kill | **not run** |
| L5 real supply chain | registries, the kernel image, release archives, advisory databases | **not run** |

L0 to L3 show that the logic is coherent and that the pieces fit. They cannot show that a kernel enforces what the
host asks for. That is what L4 is for.

## 3. What ran

### 3.1 Rust

`cargo test --workspace --all-features --locked`, Rust 1.100.0:

| Test binary | Passed | Ignored |
|---|---:|---:|
| `acf-host-agent`, unit tests and the catalog suites | 397 | 15 |
| `acf-host-agent`, `tests/process_roles.rs` (the roles as real processes) | 2 | 0 |
| `acf-guest-agent`, unit tests | 16 | 0 |
| `acf-guest-agent`, `tests/protocol.rs` | 5 | 1 |
| `acf-traffic`, unit tests | 55 | 0 |
| `acf-traffic`, `tests/relay.rs` | 17 | 0 |
| `acf-traffic`, `tests/resolver.rs` | 9 | 1 |
| `acf-traffic`, `tests/redirect.rs` | 0 | 1 |
| `acf-wire`, unit tests | 8 | 0 |
| **Total** | **509** | **18** |

Of the host agent's 412 tests, 84 are the catalog suites in `testing/suites/` (one module per section of the
contract's test catalog), 2 are the backend conformance suite on the in-memory backend, 12 are the Firecracker
adapter's (all ignored: root), and the rest are unit tests beside the code they test.

Also clean: `cargo fmt --all --check`; `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`;
the same lint without the test feature, which is the configuration that ships; and the comparison of
`execution/contracts/` and `schemas/` with what the types generate.

### 3.2 The 18 ignored tests

A test that cannot run where `cargo test` runs is marked ignored with its reason, so the summary shows it. Asked for
explicitly without what it needs, it fails; it never passes unseen.

| Tests | Need | Here |
|---|---|---|
| host agent: the plumbing of mode `allowlist` (1), the network namespace (2); traffic crate: the relay behind a real packet-filter redirect (1) | a network namespace of their own | **run and passed**: `make net-plumbing-test` runs them inside `unshare --user --map-root-user --net --mount`, with the tests of the same modules: 9 passed in the host agent, 1 in the traffic crate |
| traffic crate: the resolver against the machine's own upstream (1) | a working system resolver | **run explicitly and passed** |
| host agent: the Firecracker adapter against an emulated VMM with the real guest agent (12), including the adapter's half of the conformance suite | root: they give files to per-sandbox users and create namespaces | **not run** (`make root-test`) |
| guest agent: a fork bomb is contained by the process budget (1) | root: it creates a control group | **not run** (`make root-test`) |

### 3.3 The release artifact

`cargo build --release --locked -p acf-host-agent --bin acf-host`, then `scripts/check-release-purity.sh` with the
test-only binary as its control: the production binary contains none of the nine sentinels of test-only code, and
every one of them is present in the control, so the check can find what it looks for. Run the other way, on the
test-only binary itself, the check fails, as it must. The guest agent and the traffic crate also build in the
release profile.

Not built: the static guest agent for the images (`make guest-agent`); the musl target is not installed here.

### 3.4 The reference client (`apps/cli`)

| Stage | Result |
|---|---|
| `ruff check`, `ruff format --check` | clean (41 files) |
| `mypy`, strict | clean (40 source files) |
| unit tests | 828 passed; the 34 end-to-end tests are skipped in this stage because no host is named |
| end-to-end tests, required to run | **34 passed**: the real `acf-local` against `acf-host-fake` built from this tree, which is the real edge process, the real core and the real store over the in-memory backend, over the local socket and over mutual TLS |
| answers recorded from that host | 34 of 34 exchanges recorded, and every one validates against `execution/contracts/host-api.json` |
| lock files | `uv lock --check` passes for both lock files with the uv release the workflows pin |

### 3.5 Repository tooling and scripts

| Stage | Result |
|---|---|
| `ruff check`, `ruff format --check` | clean (68 files) |
| `mypy`, strict | clean (59 source files, including the suites that need KVM, which are type-checked here) |
| `pytest tests/scripts tests/tools` | **873 passed, 93 skipped**. Every skip is a test that needs uid 0: the installer, the host setup, the image scripts |
| `systemd-analyze verify` of the shipped units | part of the tests above; the units were never started |

### 3.6 The black-box suites without a VMM

`tests/integration` and `tests/isolation` drive a host only through its API, with the reference client. Two of their
modes need no VMM:

| Mode | What it is | Result |
|---|---|---|
| driver self-test (`make driver-selftest`) | the driver itself, proven against the in-memory host | **43 passed** |
| control plane (`make control-plane`) | every check that needs no guest, against the in-memory host started with the **shipped** configuration and safety profile | **104 passed, 66 skipped** (65 need a real guest, 1 needs root) |

Of the 66 tests skipped in control-plane mode, 65 need a real guest (execution 8, recovery 12, snapshots 2,
entry conditions 1, lifecycle 6, filesystem 5, host control 7, lifetime 1, network 10, process 13) and 1 needs
root. With no switch set, all 213 tests of the two directories are skipped, each with its reason. With
`ACF_INTEGRATION=1` on this machine all 170 fail with the same list of what the machine lacks, and none is
skipped: a suite that needs a real VMM fails, and never skips, when a real VMM is required (TV-5).

Lint, format and strict types are clean for `tests/` (52 source files).

## 4. The contract's test catalog, entry by entry

"Level" is the lowest level at which the contract says the entry means something. "Here":

* **passed**: run at that level, or at the level the entry names, and passed;
* **below L4**: the entry needs a real VMM; what is listed ran below that level and passed; the L4 test exists and
  was not run;
* **not run**: nothing below the level the entry needs would mean anything, or only a root-only test exists.

Rust tests named `t_…` are in `execution/host-agent/src/testing/suites/`; other Rust tests are named by module.
Black-box tests are in `tests/integration` and `tests/isolation`, named by directory.

### Authority and API

| Entry | Level | Tests | Here |
|---|:---:|---|---|
| T-AUTH-01 | L2 | `t_auth_01_…` (two: at the edge, at the core); black-box `host_control` | passed |
| T-AUTH-02 | L2 | `t_auth_02_…` (every method × every role); black-box `host_control` | passed |
| T-AUTH-03 | L2 | `t_auth_03_…`; black-box `host_control` | passed |
| T-AUTH-04 | L2 | `t_auth_04_…`, `edge::tls` tests | passed |
| T-AUTH-05 | L2 | `t_auth_05_…`; black-box `host_control` | passed |
| T-AUTH-06 | L2 | `t_auth_06_…`, `authority::profile` tests (12); black-box `execution`, `network` | passed |
| T-AUTH-07 | L2 | `t_auth_07_…`; black-box `host_control` | passed |
| T-AUTH-08 | L2 | `t_auth_08_…`; black-box `test_protocol_refusals.py` | passed |
| T-API-01 | L0 | `api::schema::tests::the_checked_in_contracts_match_the_types`; the table tests of `domain::method`, `domain::mode`, `error`; `make check-schema` | passed |
| T-API-02 | L2 | `t_api_02_…`; black-box `test_protocol_refusals.py` | passed |
| T-API-03 | L2 | `t_api_03_…`; black-box `vm_lifecycle` | passed |
| T-API-04 | L2 | `t_api_04_…`; black-box `vm_lifecycle` | passed |
| T-API-05 | L1 | `t_api_05_…` | passed |
| T-API-06 | L1 | four `t_api_06_…`: property-based tests of the request decoder and of the guest-protocol decoder (arbitrary bytes, mutated valid requests) | passed. Property-based, not coverage-guided fuzzing |

### Operations, state, concurrency

| Entry | Level | Tests | Here |
|---|:---:|---|---|
| T-OP-01 | L2 | `t_op_01_…` (two); the client's end-to-end lost-response test; black-box `vm_lifecycle` | passed |
| T-OP-02 | L2 | `t_op_02_the_idempotency_table`; black-box `vm_lifecycle` | passed |
| T-OP-03 | L2 | `t_op_03_…`; the relation tests in `config`; black-box `vm_lifecycle` | passed |
| T-OP-04 | L1 | `domain::fingerprint` tests (6) | passed |
| T-OP-05 | L2 | `t_op_05_t_rec_02_…`: every fault point of every operation type against an oracle transcribed from the contract | passed |
| T-OP-06 | L2 | `t_op_06_…` | passed |
| T-OP-07 | L2 | `t_op_07_cancellation` | passed |
| T-OP-08 | L2 | `t_op_08_…` | passed |
| T-STATE-01 | L1 | `domain::lifecycle::tests::every_pair_of_states_is_judged_exactly_as_the_contract_table_says` (100 pairs) | passed |
| T-STATE-02 | L2 | `t_state_02_…` (two); black-box `vm_lifecycle`, `recovery` | passed |
| T-STATE-03 | L2 | `t_state_03_…`; and J-1 to J-8 are asserted after every commit of every suite (`testing/invariants.rs`) | passed |
| T-STATE-04 | L2 | `t_state_04_…`, `domain::mode` tests; black-box `recovery` | passed |
| T-CONC-01 | L2 | `t_conc_01_…` | passed |
| T-CONC-02 | L2 | `t_conc_02_…`; black-box `vm_lifecycle` | passed |
| T-CONC-03 | L4 | L2: `t_conc_03_…` (two). L4: `recovery/test_host_recovery.py` | below L4 |
| T-CONC-04 | L2 | `t_conc_04_…`; black-box `execution` | passed |
| T-CONC-05 | L2 | `t_conc_05_…`; black-box `execution` | passed |
| T-CONC-06 | L2 | `t_conc_06_…`; black-box `vm_lifecycle` | passed |

### Recovery and persistence

| Entry | Level | Tests | Here |
|---|:---:|---|---|
| T-REC-01 | L1 | `recovery::decision` tests (25): every row of the table, and unlisted combinations | passed |
| T-REC-02 | L2 | `t_op_05_t_rec_02_…` | passed |
| T-REC-03 | L2 | `t_rec_03_…` | passed |
| T-REC-04 | L4 | L2: `t_rec_04_…`, `resources::lifetime` (a reused process id is never signalled), conformance rule 6. L4: `recovery/test_host_recovery.py` | below L4 |
| T-REC-05 | L2 | `t_rec_05_…` | passed |
| T-REC-06 | L2 | `t_rec_06_…`; black-box `recovery` | passed |
| T-REC-07 | L2 | `t_rec_07_…` | passed |
| T-REC-08 | L4 | L2: `t_rec_08_…`. L4: `recovery/test_host_recovery.py` | below L4 |
| T-REC-09 | L2 | `t_rec_09_…` | passed |
| T-REC-10 | L2 | `t_rec_10_…`; black-box `recovery` | passed |
| T-REC-11 | L4 | L2: `t_rec_11_…`. L4: `recovery/test_host_recovery.py` | below L4 |
| T-REC-12 | L2 | `t_rec_12_…` | passed |
| T-PERS-01 | L1 | `store::journal` tests (20), `store::lock` | passed |
| T-PERS-02 | L2 | `t_pers_02_…`, `t_op_08_…` | passed |
| T-PERS-03 | L2 | `t_pers_03_…` | passed |
| T-PERS-04 | L2 | `t_pers_04_one_writer_per_store` | passed |
| T-PERS-05 | L1 | `store::journal` tests (a torn tail is repaired; other corruption is refused) | passed |
| T-PERS-06 | L2 | `t_pers_06_…`, `ps_10_…`, the rate-limiter test in `coordinator` | passed |
| T-PERS-07 | L2 | `t_pers_07_schema_changes`, `store::migrate` tests (5) | passed |

### Security

| Entry | Level | Tests | Here |
|---|:---:|---|---|
| T-SEC-01 | L2 | `tests/process_roles.rs::t_sec_01_…` (the edge is a separate process of the same image, `NoNewPrivs`, empty capability sets, no descriptor into the state directory), `suites/edge.rs::t_sec_01_…`, `privsep` tests | passed. The change of user id from root to the edge's user happens only when the core is root: not run here |
| T-SEC-02 | L4 | `host_control/test_host_control_surface.py`; the inventory is `docs/ARCHITECTURE.md` §15 | not run |
| T-SEC-03 | L2 | `t_sec_03_…`; black-box `test_protocol_refusals.py` | passed |
| T-SEC-04 | L4 | below: the network gate before the first vCPU (`backend::firecracker::backend::tests`), the posture rules (`backend::process`). Root: `fc_backend_tests::a_vmm_that_fails_the_confinement_check_is_killed_before_it_is_configured`. L4: `process/test_guest_processes.py` | below L4, at unit level only |
| T-SEC-05 | L4 | L2: `t_sec_05_…` (idle and held). L4: `process/test_guest_processes.py` | below L4 |
| T-SEC-06 | L0 | `scripts/check-release-purity.sh` on the release artifact, with a control; its own tests in `tests/scripts` | passed |
| T-SEC-07 | L2 | binaries: `backend::firecracker::verify::tests`, `…::backend::tests::a_binary_replaced_while_the_host_runs_is_never_launched`. Image: `…::a_file_swapped_after_its_digest_was_recorded_is_never_staged`, `storage::hashcopy`. Snapshot: `t_snap_01_…`, conformance rule 14. Profile, configuration, enrolment: `authority::trusted_file` (13). Root: `fc_backend_tests::provisioning_rejects_a_corrupt_image_and_an_undersized_disk`. On a real host: `process/test_guest_processes.py` (a jailer replaced under a running host) | passed, through the staging and verification functions. Through a whole launch on the Firecracker adapter, and on a real host: not run |
| T-SEC-08 | L1 | `ids` tests (6), `storage::layout` (5), `storage::generation` (6), `resources::lifetime` (ticket names) | passed |

### Execution, resources, host

| Entry | Level | Tests | Here |
|---|:---:|---|---|
| T-EXEC-01 | L2 | `t_exec_01_every_execution_outcome` | passed |
| T-EXEC-02 | L4 | L2: `guest::client::tests::host_backstop_kills_the_vm_when_the_guest_ignores_its_deadline` against the real guest agent. L4: `execution/test_execution_limits.py` | below L4 |
| T-EXEC-03 | L2 | `t_exec_03_…`; the OU-3 relation in `config` | passed |
| T-EXEC-04 | L4 | below: the guest agent's `an_argument_with_shell_metacharacters_reaches_the_program_as_it_was_given` and `environment_is_not_inherited`; `authority::profile::tests::exec_env_cwd_and_argv_rules`. L4: `execution/test_execution_limits.py` | below L4 |
| T-EXEC-05 | L2 | `guest::client` tests (8) against the real guest agent, `acf-wire` tests, `t_api_06_the_guest_protocol_decoder_…` | passed |
| T-EXEC-06 | L2 | `t_exec_06_…` | passed |
| T-EXEC-07 | L2 | `t_exec_07_t_secr_02_…` | passed |
| T-RES-01 | L1 | `resources::admission` tests (7) | passed |
| T-RES-02 | L4 | below: `backend::process::limits` tests (what is written and how drift is read). L4: `execution/test_execution_limits.py` | below L4, at unit level only |
| T-RES-03 | L2 | `t_res_03_…`; black-box `recovery` | passed |
| T-RES-04 | L2 | `t_res_04_…` | passed |
| T-RES-05 | L4 | `snapshots/test_snapshot_restore.py` | not run |
| T-HOST-01 | L4 | L2: `resources::lifetime::tests::with_no_core_running_a_runtime_ends_at_its_expiry_and_not_before` (a real child process), `t_host_01_…` (two). L4: `lifetime/test_sandbox_lifetime.py` | below L4 |
| T-HOST-02 | L2 | `t_host_02_draining`; black-box `recovery` | passed |
| T-HOST-03 | L2 | `t_host_03_…`; black-box `recovery` | passed |

### Network

All eight entries need a real guest. What ran below that level:

| Entry | Level | Ran below L4 | L4 test | Here |
|---|:---:|---|---|---|
| T-NET-01 | L4 | `network::verify` (the three layers as a pure verdict), the namespace tests in a real namespace | `network/test_guest_network.py` | below L4 |
| T-NET-02 | L4 | `acf-traffic` policy and relay tests | same file | below L4 |
| T-NET-03 | L4 | `acf-traffic` resolver tests: a name outside the list gets no upstream query | same file | below L4 |
| T-NET-04 | L4 | `acf-traffic`: a name is honoured only for the addresses the resolver itself returned | same file | below L4 |
| T-NET-05 | L4 | `acf-traffic`: the TLS server name is checked against the entry | same file | below L4 |
| T-NET-06 | L4 | `acf-traffic` policy: the always-denied classes; `network::intent` | same file | below L4 |
| T-NET-07 | L4 | the plumbing test in a real namespace: no way out but the two sockets | same file | below L4 |
| T-NET-08 | L4 | the network gate before the first vCPU | same file | below L4 |

### Snapshots, secrets, observability, versioning, backend, scope

| Entry | Level | Tests | Here |
|---|:---:|---|---|
| T-SNAP-01 | L2 | `t_snap_01_…`; black-box `snapshots` | passed |
| T-SNAP-02 | L2 | `t_snap_02_…`, `storage::snapshots` manifest tests | passed |
| T-SNAP-03 | L4 | L2: `t_snap_03_the_restore_oracle`, conformance rule 15. Root: `fc_backend_tests::snapshot_then_restore_…`. L4: `snapshots/test_snapshot_restore.py` | below L4 |
| T-SNAP-04 | L2 | `t_snap_04_…` | passed |
| T-SNAP-05 | L2 | `t_auth_03_…` (snapshots across scopes); black-box `snapshots` | passed |
| T-SNAP-06 | L2 | `t_snap_06_…`; black-box `snapshots` | passed |
| T-SNAP-07 | L0 | `t_snap_07_…` | passed |
| T-SECR-01 | L2 | `t_secr_01_…`; black-box `test_protocol_refusals.py` | passed |
| T-SECR-02 | L2 | `t_exec_07_t_secr_02_…` | passed |
| T-SECR-03 | L2 | `t_secr_03_…` | passed |
| T-SECR-04 | L2 | `t_secr_04_…` | passed |
| T-OBS-01, T-OBS-02 | L2 | `t_obs_01_t_obs_02_…` | passed |
| T-OBS-03 | L2 | `t_obs_03_…` | passed |
| T-OBS-04 | L1 | `telemetry::metrics` tests (3) | passed |
| T-VER-01, T-VER-02 | L2 | `t_ver_01_t_ver_02_…`, `t_ver_02_a_feature_is_advertised_only_while_the_host_offers_it`; the guest half in `guest::client`; black-box `test_protocol_refusals.py` | passed |
| T-VER-03 | L1 | `apps/cli/tests/test_responses.py` | passed |
| T-BACK-01 | L0 | `t_back_01_…` | passed |
| T-BACK-02 | L2, L4 | L2: `testing::conformance::t_back_02_…` (two) on the in-memory backend. Root: the same suite on the Firecracker adapter. L4: `vm_lifecycle/test_vm_lifecycle.py` | passed at L2; the adapter and L4 not run |
| T-BACK-03 | L2 | `t_back_03_…` | passed |
| T-RETRY-01 | L2 | `t_retry_01_…` | passed |
| T-SCOPE-01 | L0 | `t_scope_01_…` | passed |
| T-DOC-01 | L0 | a lint of the contract document; it has no counterpart in a code repository | not applicable |
| T-ENTRY-01 | L4, L5 | `vm_lifecycle/test_entry_conditions.py` | not run; the entry conditions are not met (§7) |

Counted: of the catalog's 107 entries, 83 passed at the level the contract names (two of them, T-SEC-01 and
T-SEC-07, with a part that needs root and was not run, as their rows say); 19 need a real VMM and have only
evidence below that level; 3 were not run at all (T-SEC-02, T-RES-05, T-ENTRY-01); T-BACK-02 passed at one of its
two levels; and T-DOC-01 does not apply.

## 5. What was not run, and what that leaves unproven

| # | Not run | Why | What stays unproven |
|---|---|---|---|
| 1 | The L4 suites (`make integration`) | no usable `/dev/kvm` | everything about a real guest: boot, jailer and seccomp confinement, kernel-enforced limits, mode `none` as the host observes it in a real `/proc`, mode `allowlist` end to end, vsock, snapshot and restore of real memory and disk, recovery after a real kill of the host or the VMM |
| 2 | The 13 root-only Rust tests (`make root-test`) | no root | the Firecracker adapter's orchestration against the emulated VMM, including the launch order, the fail-closed paths and the adapter's half of the conformance suite; the guest agent's process budget |
| 3 | The 93 root-only tooling tests | no root | the installer, the host setup and the image scripts as root: ownership, modes, atomic replacement, the two digest lines the installer prints |
| 4 | A real image build | no container engine, no pinned kernel | the root filesystem, kernel and manifest pipeline on real inputs |
| 5 | The Firecracker installer on a real release archive | not downloaded | digest verification on the real bytes; the behaviour of the real jailer |
| 6 | The static guest agent (`make guest-agent`) | the musl target is not installed | that the agent links statically and runs under the in-image init |
| 7 | `cargo audit`, `pip-audit`, ShellCheck, actionlint | not installed here | advisories for the locked dependency set; script and workflow lint. `.github/workflows` runs all four |
| 8 | The units under a running service manager | only `systemd-analyze verify` | ordering, delegation, restart behaviour, `ExecStartPre` |
| 9 | The GitHub workflows | never executed | how the jobs behave on a hosted runner; the first push may differ |
| 10 | Any performance measurement | no VMM | boot latency, snapshot size and time, commit cost under load, the cost of hashing the two binaries before a launch |
| 11 | Several real caller identities | one unprivileged user | peer credentials with distinct real users and groups; the enrolment logic is tested with synthetic credentials |

## 6. What to expect on the first KVM run

Budget for first-contact corrections. The probes in `tests/isolation` encode assumptions about what a real guest
and a real kernel will show. When one fails, ask first whether the probe assumed wrongly or the isolation has a
gap, and answer by reading the guest, never by loosening the assertion. Run `make root-test` before `make
integration`: the adapter's tests against the emulated VMM are cheaper to debug than a guest. The order of
operations and the operator's checklist are in [OPERATIONS.md](OPERATIONS.md).

## 7. Pins

| Where | Keys | State |
|---|---|---|
| `scripts/firecracker.lock` | `VERSION`, `SHA256_x86_64`, `SHA256_aarch64` | pinned to v1.17.0; both digests read from two published sources that agree; not measured from a downloaded archive here |
| `images/images.lock` | `BASE_DIGEST_base`, `BASE_DIGEST_python`, `BASE_DIGEST_node`, `BASE_DIGEST_browser` | `UNSET` |
| `images/images.lock` | `KERNEL_SHA256_x86_64`, `KERNEL_SHA256_aarch64` | `UNSET` |
| the host configuration | `firecracker.firecracker_sha256`, `firecracker.jailer_sha256` | unset in the shipped example: each host pins the two files its installer installed |

`make check-pins-release` fails while any of the six is `UNSET`, and the image builder refuses to build. They were
not invented: a digest that nobody measured would be worse than none. This is also why T-ENTRY-01 is not met.

## 8. What the gates found

Recorded because each was found by running something from a different starting point than the one it was written
in.

1. **Three deviations from the contract, found by the reference client's end-to-end tests.** A retry of an
   operation that had succeeded was refused with `HOST_NOT_SERVING` once the host began to drain; a failed secret
   resolution left the sandbox marked as secret-bearing; and the edge answered `REFUSED` to a request the core might
   already have accepted. All three are fixed and have a test each ([CONTRACT_COMPLIANCE.md](CONTRACT_COMPLIANCE.md)
   §4, readings 19, 20 and 22).
2. **Tests that passed without running.** The tests that need root returned early when they had none, and were
   counted as passed. They are now ignored with their reason, and fail if asked for without root.
3. **A store that its own host would refuse.** The journal is opened only below a size limit, and nothing rewrote
   it while the host served, so a long-running host could grow a store that its next start would not open. The
   host now rewrites the file while it serves.
4. **Two catalog entries without a test that did what the entry says.** Writing §4 of this file showed that
   T-BACK-02 had no conformance suite and T-STATE-01 no exhaustive pair test. Both exist now.
5. **A refusal test that passed for the wrong reason, and the gap behind it.** The test of the binary check
   asserted only "refused", and its files lived under a world-writable directory, so the trusted-input rule
   refused them before the check under test was reached. Rewriting it to name which rule spoke showed that the VMM
   and the jailer were identified by path and version only. They are now pinned by digest and hashed before every
   launch.
6. **Five more deviations, found by the black-box suites against the in-memory host.** An unknown network mode
   word was refused as malformed instead of `UNSUPPORTED`; `host.info` advertised mode `allowlist` although the
   profile did not list it; a refusal repeated the text a request carried where a secret reference belonged; a
   snapshot whose artifact had been changed stayed `READY` after the restore that detected it; and an operator
   could not find another scope's sandbox by name. All five are fixed and have a test each
   ([CONTRACT_COMPLIANCE.md](CONTRACT_COMPLIANCE.md) §4, readings 25 to 29).
7. **A status read in the wrong place.** A one-line shell check printed success for a formatting check that had
   failed; the scripted gate, which reads each status where the command ran, caught the difference. Every result
   in this file comes from a script that does that.

Under heavy machine load a few tests that wait on real time ran slowly enough to fail (TLS handshakes of the
client's end-to-end tests, and tests that start several real processes). None reproduced on a quiet machine.
Tests whose verdict depends on time use a manual clock.

## 9. Environment

| | |
|---|---|
| Machine | 16 logical CPUs, 7.8 GiB of memory; Windows 11 with WSL 2 |
| OS, kernel | Ubuntu 24.04.2 LTS; Linux 6.6.87.1-microsoft-standard-WSL2, x86_64 |
| User | an ordinary user (uid 1000) with no root and no membership of the `kvm` group |
| `/dev/kvm` | present, `root:kvm 0660`: not usable by the build user |
| Container engine | none reachable |
| Rust | `rustc 1.100.0 (0ef1bc386 2026-11-09)`, `cargo 1.100.0`: the release `rust-toolchain.toml` pins |
| Python | CPython 3.12.3 |
| Python tools | ruff 0.17.5, mypy 2.4.1, pytest 9.2.0, pytest-timeout 2.4.0; uv 0.13.9 for the lock checks |
| Other | systemd 255 (`systemd-analyze`); util-linux 2.39.3 (`unshare`); `ip` and `nft` present |
| Not installed | ShellCheck, actionlint, cargo-audit, pip-audit, the musl Rust target |
| Filesystems | the sources on a Windows filesystem mounted into WSL; build output and virtual environments on ext4 |

Only one Python interpreter and one OS were tried. The manifests allow Python 3.12 and newer.

## 10. How to reproduce

```bash
make check            # format, lint, Rust tests, namespace tests, schema drift, client, tooling, units, pins
make release          # the production binary and the purity check
make e2e              # the client against the real edge, core and store
make driver-selftest control-plane
make check-pins-release   # must FAIL until the six pins are filled in

sudo make root-test   # on a machine with root: the 13 tests that need it
make integration      # on a KVM host, with ACF_INTEGRATION=1: the suites that boot real microVMs
```

## In one sentence

The logic is exercised thoroughly and agrees with itself; the kernel has not been asked yet. Treat every isolation
claim as a hypothesis with a test written for it, until the KVM suites have run.
