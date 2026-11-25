# Verification status — what was run, what passed, what was not

Read this before trusting anything else in the repository. It lists the evidence that exists, with counts, and the
evidence that does not exist yet. Anything not listed as passing here is unverified.

Everything below was run on 2026-11-18, on the tree this file ships with, on one machine (§9). That machine was used
two ways. As an ordinary user, with no KVM and no root, it ran every gate that needs neither. As root, with KVM
nested inside WSL 2, it ran the root-only tests, the supply-chain steps, and the suites that boot real Firecracker
microVMs against the installed host. §6 says what that second use can and cannot show.

## 1. The short version

Without KVM and without root:

| | Result |
|---|---|
| Rust workspace: format, lint (warnings are errors) in the test configuration and in the shipping configuration | clean |
| Rust workspace: every test, every feature | **522 passed, 0 failed, 19 ignored** (each ignored test needs root or a namespace of its own, and ran that way: §3.2) |
| The namespace tests, inside an unprivileged user namespace | **10 passed** |
| Generated contracts and schemas against the Rust types | no drift |
| The production `acf-host` | contains no test-only code; the check is validated against a binary that does |
| Reference client: lint, format, strict types | clean |
| Reference client: tests | **831 passed**; end to end against the real edge, core and store: **34 passed** |
| Repository tooling: lint, format, strict types | clean |
| Repository tooling and scripts: tests | **873 passed, 94 skipped** (they need root) |
| Black-box driver against the in-memory host | **43 passed** |
| Black-box suites against the in-memory host, with the shipped configuration and profile | **104 passed, 66 skipped** (65 need a real guest, 1 needs root) |

As root, and on a real VMM:

| | Result |
|---|---|
| The Rust tests that need root: the Firecracker adapter against an emulated VMM (with its half of the conformance suite), the change of user id for a role, the guest agent's process budget | **14 passed, 0 failed** |
| Repository tooling and scripts, as root | **961 passed, 6 skipped** (§3.5) |
| Supply chain (`x86_64`) | the Firecracker v1.17.0 release archive measured equal to its pin; four base images and the guest kernel pinned from measurements; the `python` image built from them and booted |
| Advisories and linters | `cargo audit --deny warnings`: nothing, 229 crates. `pip-audit`: nothing, both locks. actionlint: clean. ShellCheck: clean |
| **Black-box suites against the installed host, booting real microVMs** | **144 passed, 2 failed, 24 skipped** (the skips are checks that need the test host's own files: they passed in the control-plane run) |

The two failures, which are expected and explained:

* **T-ENTRY-01**: the entry conditions require every input pinned for a release. The `aarch64` guest kernel was
  never measured and is `UNSET`, so the check refuses, as it must.
* **T-HOST-01**: a runtime ended 1.06 s after its expiry plus the tolerance, measured by the wall clock. On this
  machine the monotonic clock, which the enforcer's timers use, runs 5.6 % slow against the wall clock (§6). The
  result says nothing either way about the enforcer.

Getting there took four full real-VM runs and found twelve defects in the host agent, the shipped unit and the
reference client that no double could show (§8). They are fixed, each with a test.

**What this does not show.** Nothing has run on bare metal, on another kernel than WSL 2's, or on `aarch64`. The
machine is a development laptop whose disk is virtual and whose virtualisation is nested. Treat the L4 results as
"the code does what it claims on one faithful but unusual Linux host", not as a production qualification.

## 2. How much each kind of evidence is worth

The levels are the contract's (§31.1, TV-2). A test that needs L4 is never satisfied at L2.

| Level | What a pass shows | Status |
|---|---|---|
| L0 static | it compiles, is formatted, lint-clean and type-checked; generated contracts and schemas have not drifted; the release artifact holds no test code; shipped units and workflows parse and lint | ran, passed |
| L1 unit and property | each pure decision and each module's rules: the lifecycle relation, the role and mode tables, admission arithmetic, the recovery table, the fingerprint, network verdicts, the journal's framing and replay, the parsers | ran, passed |
| L2 whole process, test backend | the real coordinator, store, recovery and admission pipeline over the in-memory backend; the roles as real processes; the real client against the real edge and core; the network plumbing in a real network namespace | ran, passed |
| L3 shipped configuration and profile | the shipped files load and agree with each other; the black-box suites against the in-memory host started with them | ran, passed |
| L4 real VMM | boot, jailer and seccomp confinement, kernel-enforced limits, both network modes as a guest experiences them, vsock, snapshots of real memory, recovery after a real kill | **ran on one nested-virtualisation machine**: 144 passed, 2 failed (§1) |
| L5 real supply chain | registries, the kernel image, release archives, advisory databases | **ran for `x86_64`**; `aarch64` not |

## 3. What ran

### 3.1 Rust

`cargo test --workspace --all-features --locked`, Rust 1.100.0:

| Test binary | Passed | Ignored |
|---|---:|---:|
| `acf-host-agent`, unit tests and the catalog suites | 409 | 16 |
| `acf-host-agent`, the binary's own tests (`main.rs`) | 1 | 0 |
| `acf-host-agent`, `tests/process_roles.rs` (the roles as real processes) | 2 | 0 |
| `acf-guest-agent`, unit tests | 16 | 0 |
| `acf-guest-agent`, `tests/protocol.rs` | 5 | 1 |
| `acf-traffic`, unit tests | 55 | 0 |
| `acf-traffic`, `tests/relay.rs` | 17 | 0 |
| `acf-traffic`, `tests/resolver.rs` | 9 | 1 |
| `acf-traffic`, `tests/redirect.rs` | 0 | 1 |
| `acf-wire`, unit tests | 8 | 0 |
| **Total** | **522** | **19** |

Of the host agent's 425 tests, 85 are the catalog suites in `testing/suites/` (one module per section of the
contract's test catalog), 2 are the backend conformance suite on the in-memory backend, 12 are the Firecracker
adapter's (ignored: root), 21 are the store's, and the rest are unit tests beside the code they test.

Also clean: `cargo fmt --all --check`; `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`;
the same lint without the test feature, which is the configuration that ships; and the comparison of
`execution/contracts/` and `schemas/` with what the types generate.

One run of the full gate had one failure, `t_sec_03_unauthenticated_and_misbehaving_peers_do_not_disturb_authenticated_traffic`.
The test gives its authenticated connection an idle timeout of 800 ms. Under the load of the whole workspace running
in parallel, opening ten connections took longer than that, and the edge closed the connection as idle. The test
passed six times in a row on its own, and the next full run (the counts above) passed it. It is a timing margin in
a test, not a fault of the edge, and it is recorded here because it happened.

### 3.2 The 19 ignored tests

A test that cannot run where `cargo test` runs is marked ignored with its reason, so the summary shows it. Asked for
explicitly without what it needs, it fails; it never passes unseen. All nineteen ran, each where it can:

| Tests | Need | Ran |
|---|---|---|
| host agent: the plumbing of mode `allowlist` (1), the network namespace (2); traffic crate: the relay behind a real packet-filter redirect (1) | a network namespace of their own | inside `unshare --user --map-root-user --net --mount` (`make net-plumbing-test`), with the other tests of the same modules: **10 passed** (9 in the host agent, 1 in the traffic crate) |
| traffic crate: the resolver against the machine's own upstream (1) | a working system resolver | explicitly: **passed** |
| host agent: the Firecracker adapter against an emulated VMM with the real guest agent (12), including the adapter's half of the conformance suite | root | `make root-test`'s binaries, as root: **12 passed** |
| host agent: a root core starts a role under another user id (1) | root | as root: **passed** |
| guest agent: a fork bomb is contained by the process budget (1) | root: it creates a control group | as root: **passed** |

### 3.3 The release artifact

`cargo build --release --locked -p acf-host-agent --bin acf-host`, then `scripts/check-release-purity.sh` with the
test-only binary as its control: the production binary contains none of the sentinels of test-only code, and every
one of them is present in the control, so the check can find what it looks for. Run the other way, on the test-only
binary itself, the check fails, as it must. The guest agent and the traffic crate also build in the release
profile. The static guest agent for the image was built for `x86_64-unknown-linux-musl` and runs under the in-image
init in every guest of the real-VM run. This release binary is the one installed on the test host for that run.

### 3.4 The reference client (`apps/host-cli`)

| Stage | Result |
|---|---|
| `ruff check`, `ruff format --check` | clean (41 files) |
| `mypy`, strict | clean (40 source files) |
| unit tests | 831 passed; the 34 end-to-end tests are skipped in this stage because no host is named |
| end-to-end tests, required to run | **34 passed**: the real `acf-local` against `acf-host-fake` built from this tree, which is the real edge process, the real core and the real store over the in-memory backend, over the local socket and over mutual TLS |
| answers recorded from that host | 34 of 34 exchanges recorded, and every one validates against `execution/contracts/host-api.json` |
| lock files | `uv lock --check` passes for both lock files with the uv release the workflows pin |

The real-VM suites drive the host through this client too, so it also ran against the installed host.

### 3.5 Repository tooling and scripts

| Stage | Result |
|---|---|
| `ruff check`, `ruff format --check` | clean |
| `mypy`, strict | clean (including the suites, which are type-checked here: 52 source files under `tests/`) |
| `pytest tests/scripts tests/tools` as the ordinary user | **873 passed, 94 skipped**. Every skip is a test that needs uid 0 |
| the same as root | **961 passed, 6 skipped**. The six: two need the release and control binaries built in their own tree, one needs to run a script as an unprivileged user from a directory that only root may enter, one would run the real installed host's `check`, one writes files whose ownership root makes moot, and one checks the `sudo` path, which root does not take |
| `systemd-analyze verify` of the shipped units | part of the tests above; the units then ran under systemd on the test host |
| ShellCheck 0.11.0 | the repository's guard over every shell script, at the strictest severity: 13 passed |
| actionlint 1.7.12 | clean over every workflow |

### 3.6 The black-box suites without a VMM

`tests/integration` and `tests/isolation` drive a host only through its API, with the reference client. Two of their
modes need no VMM:

| Mode | What it is | Result |
|---|---|---|
| driver self-test (`make driver-selftest`) | the driver itself, proven against the in-memory host | **43 passed** |
| control plane (`make control-plane`) | every check that needs no guest, against the in-memory host started with the **shipped** configuration and safety profile | **104 passed, 66 skipped** (65 need a real guest, 1 needs root) |

With no switch set, all 213 tests of the two directories are skipped, each with its reason. With
`ACF_INTEGRATION=1` and an unprivileged user, all 170 fail with the list of what is missing, and none is skipped: a
suite that needs a real VMM fails, and never skips, when a real VMM is required (TV-5).

### 3.7 The suites against the installed host, on a real VMM

`make integration` as root: `ACF_INTEGRATION=1`, the host installed by `scripts/host-setup.sh` and running under
systemd (`acf-cgroup`, `acf-lifetime`, `acf-host`), the release binary of §3.3, Firecracker v1.17.0 installed by
`scripts/install-firecracker.sh` and pinned by digest in `/etc/acf/host.yaml`, the `python` image built by
`scripts/build-image.sh` from its pinned base and the pinned kernel. The run took 53 minutes.

| Module | Passed | Failed | Skipped |
|---|---:|---:|---:|
| `integration/execution/test_client_contract.py` | 7 | 0 | 1 |
| `integration/execution/test_execution_limits.py` | 23 | 0 | 3 |
| `integration/recovery/test_host_recovery.py` | 15 | 0 | 7 |
| `integration/snapshots/test_snapshot_restore.py` | 14 | 0 | 2 |
| `integration/test_protocol_refusals.py` | 7 | 0 | 1 |
| `integration/vm_lifecycle/test_entry_conditions.py` | 0 | 1 | 0 |
| `integration/vm_lifecycle/test_operation_protocol.py` | 9 | 0 | 0 |
| `integration/vm_lifecycle/test_vm_lifecycle.py` | 20 | 0 | 0 |
| `isolation/filesystem/test_guest_filesystem.py` | 5 | 0 | 0 |
| `isolation/host_control/test_host_control_surface.py` | 9 | 0 | 8 |
| `isolation/lifetime/test_sandbox_lifetime.py` | 2 | 1 | 0 |
| `isolation/network/test_guest_network.py` | 20 | 0 | 2 |
| `isolation/process/test_guest_processes.py` | 13 | 0 | 0 |
| **Total** | **144** | **2** | **24** |

Every skip has the same reason: the check uses the test host's own files or identities, so it runs under `make
control-plane`, where it passed, and not against a production host.

### 3.8 The supply chain

| Input | What was done | Result |
|---|---|---|
| Firecracker v1.17.0, `x86_64` | downloaded and installed by `scripts/install-firecracker.sh` | the archive's digest equals the pin in `scripts/firecracker.lock`; the installer printed the two binary digests, which were put in `/etc/acf/host.yaml` |
| Base images | resolved by `scripts/pin-images.sh` and again by the registry's own API without Docker | all four digests agree between the two; written to `images/images.lock` |
| Guest kernel, `x86_64` | `vmlinux-6.1.188` of Firecracker's CI artifacts | matched the bucket's multipart ETag; its configuration passes `tools/check_kernel_config.py`; pinned |
| The `python` image | `scripts/build-image.sh --install` with Docker Desktop's engine | built and installed; booted by every guest of §3.7. `base`, `node` and `browser` were not built |
| Advisory databases | `cargo audit --deny warnings`, `pip-audit` over both Python locks | nothing reported |

## 4. The contract's test catalog, entry by entry

"Level" is the lowest level at which the contract says the entry means something. "Here":

* **passed**: run at that level, or at the level the entry names, and passed. For an L4 entry that means on the
  machine of §6;
* **failed**: run at that level and failed; the row says why;
* **not applicable**: the entry has no counterpart in a code repository.

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
| T-API-04 | L2 | `t_api_04_…` (two, one of them a full listing followed to its end after retention); `coordinator::query` paging tests; black-box `vm_lifecycle` | passed |
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
| T-OP-08 | L2 | `t_op_08_…`; `store::journal::tests::a_read_is_answered_while_a_commit_waits_for_its_disk_flush` | passed |
| T-STATE-01 | L1 | `domain::lifecycle::tests::every_pair_of_states_is_judged_exactly_as_the_contract_table_says` (100 pairs) | passed |
| T-STATE-02 | L2 | `t_state_02_…` (two); black-box `vm_lifecycle` (every state a healthy host can show, on real guests), `recovery` | passed |
| T-STATE-03 | L2 | `t_state_03_…`; and J-1 to J-8 are asserted after every commit of every suite (`testing/invariants.rs`) | passed |
| T-STATE-04 | L2 | `t_state_04_…`, `domain::mode` tests; black-box `recovery` | passed |
| T-CONC-01 | L2 | `t_conc_01_…` | passed |
| T-CONC-02 | L2 | `t_conc_02_…`; black-box `vm_lifecycle` | passed |
| T-CONC-03 | L4 | L2: `t_conc_03_…` (two). L4: `recovery/test_host_recovery.py` (two) | passed |
| T-CONC-04 | L2 | `t_conc_04_…`; black-box `execution` | passed |
| T-CONC-05 | L2 | `t_conc_05_…`; black-box `execution` | passed |
| T-CONC-06 | L2 | `t_conc_06_…`; black-box `vm_lifecycle` | passed |

### Recovery and persistence

| Entry | Level | Tests | Here |
|---|:---:|---|---|
| T-REC-01 | L1 | `recovery::decision` tests (25): every row of the table, and unlisted combinations | passed |
| T-REC-02 | L2 | `t_op_05_t_rec_02_…` | passed |
| T-REC-03 | L2 | `t_rec_03_…` | passed |
| T-REC-04 | L4 | L2: `t_rec_04_…`, `resources::lifetime` (a reused process id is never signalled), conformance rule 6. Root: `fc_backend_tests::a_pid_file_naming_a_process_that_is_not_ours_is_never_adopted_or_signalled`. L4: `recovery/test_host_recovery.py` (four) | passed |
| T-REC-05 | L2 | `t_rec_05_…` | passed |
| T-REC-06 | L2 | `t_rec_06_…`; black-box `recovery` | passed |
| T-REC-07 | L2 | `t_rec_07_…` | passed |
| T-REC-08 | L4 | L2: `t_rec_08_…`. L4: `recovery/test_host_recovery.py` | passed |
| T-REC-09 | L2 | `t_rec_09_…` | passed |
| T-REC-10 | L2 | `t_rec_10_…`; black-box `recovery` | passed |
| T-REC-11 | L4 | L2: `t_rec_11_…`. L4: `recovery/test_host_recovery.py` | passed |
| T-REC-12 | L2 | `t_rec_12_…` | passed |
| T-PERS-01 | L1 | `store::journal` tests (21), `store::lock` | passed |
| T-PERS-02 | L2 | `t_pers_02_…`, `t_op_08_…` | passed |
| T-PERS-03 | L2 | `t_pers_03_…` | passed |
| T-PERS-04 | L2 | `t_pers_04_one_writer_per_store` | passed |
| T-PERS-05 | L1 | `store::journal` tests (a torn tail is repaired; other corruption is refused) | passed |
| T-PERS-06 | L2 | `t_pers_06_…`, `ps_10_…`, the rate-limiter test in `coordinator` | passed |
| T-PERS-07 | L2 | `t_pers_07_schema_changes`, `store::migrate` tests (5) | passed |

### Security

| Entry | Level | Tests | Here |
|---|:---:|---|---|
| T-SEC-01 | L2 | `tests/process_roles.rs::t_sec_01_…` (the edge is a separate process of the same image, `NoNewPrivs`, empty capability sets, no descriptor into the state directory), `suites/edge.rs::t_sec_01_…`, `privsep` tests. Root: `privsep::tests::a_root_core_starts_a_role_under_another_user_id`. On a real host: `host_control/test_host_control_surface.py` | passed |
| T-SEC-02 | L4 | `host_control/test_host_control_surface.py`; the inventory is `docs/ARCHITECTURE.md` §15 | passed |
| T-SEC-03 | L2 | `t_sec_03_…`; black-box `test_protocol_refusals.py` | passed (§3.1 records one timing failure under load) |
| T-SEC-04 | L4 | the network gate before the first vCPU (`backend::firecracker::backend::tests`), the posture rules, including the VMM's own seccomp filter (`backend::process::identity`). Root: `fc_backend_tests::a_vmm_that_fails_the_confinement_check_is_killed_before_it_is_configured`. L4: `process/test_guest_processes.py` (two) | passed |
| T-SEC-05 | L4 | L2: `t_sec_05_…` (idle and held). L4: `process/test_guest_processes.py` (three) | passed |
| T-SEC-06 | L0 | `scripts/check-release-purity.sh` on the release artifact, with a control; its own tests in `tests/scripts` | passed |
| T-SEC-07 | L2 | binaries: `backend::firecracker::verify::tests`, `…::backend::tests::a_binary_replaced_while_the_host_runs_is_never_launched`. Image: `…::a_file_swapped_after_its_digest_was_recorded_is_never_staged`, `storage::hashcopy`. Snapshot: `t_snap_01_…`, conformance rule 14. Profile, configuration, enrolment: `authority::trusted_file` (13). Root: `fc_backend_tests::provisioning_rejects_a_corrupt_image_and_an_undersized_disk`. On a real host: `process/test_guest_processes.py::test_t_sec_07_a_jailer_replaced_under_a_running_host_is_refused_and_never_run` | passed |
| T-SEC-08 | L1 | `ids` tests (6), `storage::layout` (5), `storage::generation` (6), `resources::lifetime` (ticket names) | passed |

### Execution, resources, host

| Entry | Level | Tests | Here |
|---|:---:|---|---|
| T-EXEC-01 | L2 | `t_exec_01_every_execution_outcome` | passed |
| T-EXEC-02 | L4 | L2: `guest::client::tests::host_backstop_kills_the_vm_when_the_guest_ignores_its_deadline` against the real guest agent. L4: `execution/test_execution_limits.py` | passed |
| T-EXEC-03 | L2 | `t_exec_03_…`; the OU-3 relation in `config` | passed |
| T-EXEC-04 | L4 | below: the guest agent's `an_argument_with_shell_metacharacters_reaches_the_program_as_it_was_given` and `environment_is_not_inherited`; `authority::profile::tests::exec_env_cwd_and_argv_rules`. L4: `execution/test_execution_limits.py` | passed |
| T-EXEC-05 | L2 | `guest::client` tests (8) against the real guest agent, `acf-wire` tests, `t_api_06_the_guest_protocol_decoder_…` | passed |
| T-EXEC-06 | L2 | `t_exec_06_…` | passed |
| T-EXEC-07 | L2 | `t_exec_07_t_secr_02_…` | passed |
| T-RES-01 | L1 | `resources::admission` tests (7) | passed |
| T-RES-02 | L4 | below: `backend::process::limits` tests (what is written and how drift is read). Root: the guest agent's process budget. L4: `execution/test_execution_limits.py` | passed |
| T-RES-03 | L2 | `t_res_03_…`; black-box `recovery` | passed |
| T-RES-04 | L2 | `t_res_04_…` | passed |
| T-RES-05 | L4 | `snapshots/test_snapshot_restore.py` | passed |
| T-HOST-01 | L4 | L2: `resources::lifetime::tests::with_no_core_running_a_runtime_ends_at_its_expiry_and_not_before` (a real child process), `t_host_01_…` (two). L4: `lifetime/test_sandbox_lifetime.py` | **failed** on this machine: ended 1.06 s past the tolerance by the wall clock, which the monotonic clock trails by 5.6 % (§6). Not demonstrated |
| T-HOST-02 | L2 | `t_host_02_draining`; black-box `recovery` | passed |
| T-HOST-03 | L2 | `t_host_03_…`; black-box `recovery` | passed |

### Network

All eight entries need a real guest.

| Entry | Level | Ran below L4 | L4 test | Here |
|---|:---:|---|---|---|
| T-NET-01 | L4 | `network::verify` (the three layers as a pure verdict), the namespace tests in a real namespace | `network/test_guest_network.py` | passed |
| T-NET-02 | L4 | `acf-traffic` policy and relay tests | same file | passed |
| T-NET-03 | L4 | `acf-traffic` resolver tests: a name outside the list gets no upstream query | same file | passed |
| T-NET-04 | L4 | `acf-traffic`: a name is honoured only for the addresses the resolver itself returned | same file | passed |
| T-NET-05 | L4 | `acf-traffic`: the TLS server name is checked against the entry | same file | passed |
| T-NET-06 | L4 | `acf-traffic` policy: the always-denied classes; `network::intent` | same file | passed |
| T-NET-07 | L4 | the plumbing test in a real namespace: no way out but the two sockets | same file (two) | passed |
| T-NET-08 | L4 | the network gate before the first vCPU | same file | passed |

### Snapshots, secrets, observability, versioning, backend, scope

| Entry | Level | Tests | Here |
|---|:---:|---|---|
| T-SNAP-01 | L2 | `t_snap_01_…`; black-box `snapshots` | passed |
| T-SNAP-02 | L2 | `t_snap_02_…`, `storage::snapshots` manifest tests | passed |
| T-SNAP-03 | L4 | L2: `t_snap_03_the_restore_oracle`, conformance rule 15. Root: `fc_backend_tests::snapshot_then_restore_…`. L4: `snapshots/test_snapshot_restore.py` | passed |
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
| T-VER-03 | L1 | `apps/host-cli/tests/test_responses.py` | passed |
| T-BACK-01 | L0 | `t_back_01_…` | passed |
| T-BACK-02 | L2, L4 | L2: `testing::conformance::t_back_02_…` (two) on the in-memory backend. Root: the same suite on the Firecracker adapter. L4: `vm_lifecycle/test_vm_lifecycle.py` | passed at both levels |
| T-BACK-03 | L2 | `t_back_03_…` | passed |
| T-RETRY-01 | L2 | `t_retry_01_…` | passed |
| T-SCOPE-01 | L0 | `t_scope_01_…` | passed |
| T-DOC-01 | L0 | a lint of the contract document; it has no counterpart in a code repository | not applicable |
| T-ENTRY-01 | L4, L5 | `vm_lifecycle/test_entry_conditions.py` | **failed**: every `x86_64` input is pinned and was used; the `aarch64` kernel pin is `UNSET` (§7) |

Counted: of the catalog's 107 entries, 104 passed at the level the contract names, 2 failed (T-HOST-01, T-ENTRY-01),
and T-DOC-01 does not apply. Of the 21 entries whose decisive test needs a real VMM, 20 passed, on the machine of §6
and nowhere else, and T-HOST-01 failed there; T-BACK-02 passed at its L4 level too.

## 5. What was not run, and what that leaves unproven

| # | Not run | Why | What stays unproven |
|---|---|---|---|
| 1 | Anything on bare metal | the only KVM available was nested inside WSL 2 | timing, interrupt and device behaviour without an outer hypervisor; anything specific to a production kernel |
| 2 | Anything on `aarch64` | no machine, no measured kernel | the `aarch64` build, kernel configuration, jailer and seccomp behaviour |
| 3 | The `base`, `node` and `browser` images | only `python` was built | their recipes on real inputs (their bases are pinned) |
| 4 | The GitHub workflows | not pushed | how the jobs behave on a hosted runner, which has KVM only in some configurations |
| 5 | The lifetime enforcer's deadline, judged against a correct clock | the test machine's monotonic clock is slow (§6) | T-HOST-01, INV-030 |
| 6 | Any performance measurement | timings from a virtual disk under nested virtualisation are not performance figures | boot latency, snapshot size and time, commit cost under load on real hardware |
| 7 | Several real caller identities, and a peer on another machine | one user and the local endpoint, plus mutual TLS on the loopback address | peer credentials of distinct real users and groups; TLS across a real network |
| 8 | A long-lived host under a real workload | the test host ran for a day of suites | retention, compaction and memory over weeks; the change floor of §8 item 11 was found only because the host had run for longer than `change_retention` |

## 6. What the test host is, and what it cannot show

The real-VM evidence comes from one machine: a laptop running Windows 11 with WSL 2, KVM nested inside Hyper-V,
Ubuntu 24.04 on Microsoft's WSL kernel. It is a faithful Linux host in most respects and an unusual one in four.
Each of the four was measured, and each affects what a result there means.

| Property | Measured | Consequence |
|---|---|---|
| The monotonic clock runs slow | `CLOCK_MONOTONIC` advances about 5.6 % slower than the wall clock: 60 s of monotonic time is 63.4 s of wall time, and the wall clock is stepped forward by about 1.7 s every 30 s | anything timed on the monotonic clock ends late by wall time. T-HOST-01 measures the enforcer's kill against the wall clock and fails by that margin. It could not pass on this machine, and its failure is not evidence against the enforcer |
| The disk is a virtual disk on the laptop's SSD | a create (copy, hash and flush of a 225 MB root filesystem) took 7 s at the median and 20 s at the 90th percentile; right after snapshot writes, a few took 86 to 169 s | the slow tail exposed §8 item 9. In one run it also made two snapshot tests exceed their 300 s budget. Timings from this machine are not performance figures |
| Virtualisation is nested | `kvm_intel` reports nested support; every microVM ran inside the WSL 2 virtual machine | boot and snapshot times include the outer hypervisor. Nothing here shows behaviour on bare metal |
| The distribution stops when no session is open | services end and process ids start again from 1; the boot id does not change | a run must keep a session open. A host agent that compared only boot ids would mistake the restarted distribution for the same boot; this one also checks process start times |

After the last run, when the distribution was next started, its root filesystem reported a corrupt extent header in
one file of the systemd journal (`EXT4-fs error … bad header/extent`). The kernel aborted the filesystem journal and
remounted it read-only, and the distribution must be repaired with `e2fsck` before it runs again. The results above
were all read before that. The host agent never writes that file. Whether the day's write load on WSL's virtual disk
contributed is not known.

## 7. Pins

| Where | Keys | State |
|---|---|---|
| `scripts/firecracker.lock` | `VERSION`, `SHA256_x86_64`, `SHA256_aarch64` | v1.17.0; both digests read from two published sources that agree; the `x86_64` archive was then downloaded and measured equal |
| `images/images.lock` | `BASE_DIGEST_base`, `BASE_DIGEST_python`, `BASE_DIGEST_node`, `BASE_DIGEST_browser` | pinned: resolved by two independent methods that agree |
| `images/images.lock` | `KERNEL_SHA256_x86_64` | pinned: `vmlinux-6.1.188` of Firecracker's CI artifacts; the lock records where it came from |
| `images/images.lock` | `KERNEL_SHA256_aarch64` | `UNSET`: no `aarch64` kernel was measured |
| the host configuration | `firecracker.firecracker_sha256`, `firecracker.jailer_sha256` | unset in the shipped example: each host pins the two files its installer installed. The test host did |

`make check-pins-release` fails while anything is `UNSET`, and today it names exactly one input, the `aarch64`
kernel. That is also why T-ENTRY-01 is not met. A digest that nobody measured would be worse than none.

## 8. What the gates found

Recorded because each was found by running something from a different starting point than the one it was written in.

### 8.1 Without KVM and without root

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

### 8.2 On the first real host

Run on the machine of §6, as root, against the installed host under systemd. The first full real-VM run passed 115
tests and failed 31; the last passed 144 and failed the two of §1. Each item below was found by a real-VM suite, a
root test, or a gate run on that machine. Each was fixed in the host agent, the shipped unit or the reference client,
and each has a test that fails without the fix.

1. **Every real VMM was refused by the confinement check.** The jailer pivots into the jail in a mount namespace
   of its own, so to an observer outside it the VMM's `/proc/<pid>/root` reads `/`. The check compared paths as
   text. It now compares the root directory by device and inode (`backend::process::identity::same_directory`).
2. **A VMM that installed no seccomp filter passed the confinement check.** A process started from a unit with
   `SystemCallFilter=` inherits the unit's filters, and "seccomp mode 2" is true of it whether or not it installed
   one of its own. Started with `--no-seccomp`, Firecracker passed. The check now counts filters beyond those of the
   host process that started the VMM: at launch for every thread but the first, and once the guest is up for every
   thread ([CONTRACT_COMPLIANCE.md](CONTRACT_COMPLIANCE.md) §4, reading 31).
3. **The confinement read failed when a VMM thread ended while it was being read** (`ESRCH` from the thread's
   status file). A thread that is gone is skipped.
4. **The edge could not start under systemd.** The unit said `User=root`. With `NoNewPrivileges=yes`, systemd then
   drops `CAP_SETUID` from the effective set, and the core could not change the edge to its own user. The unit
   names no user now (`tests/scripts/test_deploy.py` checks that it does not).
5. **The guest-traffic role refused the argument the core starts it with**: the jail id. Test: the command lines
   the core starts its roles with are parsed by the role's own parser (`main.rs`).
6. **A second stop of a VMM whose recorded session leader had exited failed** (`EINVAL` from `pidfd_open`). If the
   recorded identity no longer matches a live process, the process is already gone.
7. **The events directory was readable by every user** (`0755`). It is `0700`.
8. **A guest with no resolver configured kept the image build machine's resolvers** in `/etc/resolv.conf`. The
   init removes the file when it has no resolver to write (`tests/scripts/test_acf_init.py`).
9. **An answer could be lost to a slow disk.** Every read waited for any concurrent commit's flush, and a create's
   staging could make that flush take minutes. Once, a create's own answer did not come before the edge's deadline.
   Reads now never wait for a flush, and bulk disk work leaves the async worker ([DECISIONS.md](DECISIONS.md)
   ADR-034; [CONTRACT_COMPLIANCE.md](CONTRACT_COMPLIANCE.md) §4, reading 30). Measured on the same machine: a read
   during a create took about 5 s before, and 2 ms at the median after; one read in three creates still took 0.47 s.
10. **A command could not reach its process budget in a small guest.** The kernel's default `RLIMIT_NPROC` is half
    of `threads-max`, which scales with memory; in a 256 MiB guest it is below the budget the host grants. The
    guest agent raises the hard limit to the budget before it starts a command, so the control group is what stops
    a fork bomb, as designed.
11. **A full listing could no longer be completed once the host had run for longer than `change_retention`.**
    Every listing longer than one page ended with a cursor that the host itself refused (`CURSOR_EXPIRED`), the
    reference client's `operation list --all` included. The change floor now bounds only the lists that have
    tombstones, and a page never ends below it ([CONTRACT_COMPLIANCE.md](CONTRACT_COMPLIANCE.md) §4, reading 32).
    The client and the suites' driver now list again in full when a continuation is refused that way, as API-11
    says.
12. **The reference client refused every command on a machine where the host's socket existed but the user could
    not read it.** It gave a usage error before the transport could say "permission denied connecting to ..." with
    its hint. The `--socket` option no longer checks readability, which is not what connecting needs. The client's
    own unit tests found this: they began to fail on the test machine once a real host was installed there.

Also changed while finding item 4: the core now starts its roles from the image it is running (`/proc/self/exe`),
after checking that it is the same file, by device and inode, as the installed binary.

The suites and the tooling tests were wrong in about twenty places, each an assumption about a real host that the
in-memory host or an empty machine could not contradict. They were corrected by reading what the guest, the kernel
and the host showed, never by loosening an assertion. Examples:
* a path inside a jailed process must be read through `/proc/<pid>/root`;
* an operation that takes longer than the host's wait is followed by its id instead of being expected to have ended;
* a lost answer is resolved by resubmitting with `retry: true`, as the reference client does;
* a check that "nothing was recorded" asks which records changed, because a long-lived host's retention commits on
  its own;
* the tests of the fail-closed pin paths start from an unpinned copy of the lock, not from whatever the repository's
  lock holds.

One remaining fragility is in the suites, not the host. The pid-reuse test of T-REC-04 gives a decoy process the
recorded pid through `ns_last_pid`. On a busy machine another process can take the freed pid first. That happened in
one run, and the test then fails to set itself up.

## 9. Environment

| | |
|---|---|
| Machine | Intel Core i7-11800H, 16 logical CPUs, 7.8 GiB of memory; Windows 11 with WSL 2 |
| OS, kernel | Ubuntu 24.04.2 LTS; Linux 6.6.87.1-microsoft-standard-WSL2, x86_64 |
| Users | an ordinary user (uid 1000) with no membership of the `kvm` group; root, through `wsl -u root`, for the root-only tests and the real-host runs |
| `/dev/kvm` | `root:kvm 0660`; nested virtualisation enabled |
| Service manager, control groups | systemd 255; cgroup v2 with the cpu, memory and pids controllers delegated |
| Filesystems | the sources on a Windows filesystem mounted into WSL; build output, virtual environments and the host's state on ext4 (`data=ordered`) on WSL's virtual disk |
| Container engine | Docker Desktop's engine, reached from WSL through its proxy socket, for the image build only |
| Firecracker | v1.17.0 and its jailer, installed by `scripts/install-firecracker.sh` into `/opt/acf/bin` |
| Guest | kernel `vmlinux-6.1.188` (Firecracker CI), the `python` image built by `scripts/build-image.sh` |
| Rust | `rustc 1.100.0 (0ef1bc386 2026-11-09)`, `cargo 1.100.0`: the release `rust-toolchain.toml` pins; the `x86_64-unknown-linux-musl` target for the guest agent |
| Python | CPython 3.12.3 |
| Python tools | ruff 0.17.5, mypy 2.4.1, pytest 9.2.0, pytest-timeout 2.4.0; uv 0.13.9 for the lock checks |
| Audit and lint | cargo-audit 0.23.0, pip-audit 2.10.1, ShellCheck 0.11.0, actionlint 1.7.12 |

Only one Python interpreter and one OS were tried. The manifests allow Python 3.12 and newer.

## 10. How to reproduce

```bash
make check            # format, lint, Rust tests, namespace tests, schema drift, client, tooling, units, pins
make release          # the production binary and the purity check
make e2e              # the client against the real edge, core and store
make driver-selftest control-plane
make check-pins-release   # fails until the aarch64 kernel is pinned too

sudo make root-test   # on a machine with root: the tests that need it
make integration      # on a KVM host, as root, with ACF_INTEGRATION=1: the suites that boot real microVMs
```

On WSL 2, keep a session open for the length of a run: the distribution stops, and its services with it, when the
last one ends.

## In one sentence

The logic is exercised thoroughly and agrees with itself, and on one nested-virtualisation laptop the kernel was
asked and agreed, except where that laptop's own clock could not answer; bare metal and `aarch64` have not been asked.
