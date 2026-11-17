# Contract compliance 

How *Phase 1 Contract Specification v1.1.0* and the *Master Plan*  section are met, **with the test that can fail
for each clause**. Nothing here is a claim that a test has been run unless the legend says so; the execution record is
in [VERIFICATION_STATUS.md](VERIFICATION_STATUS.md).

| Mark | Suite | Command | Needs |
|---|---|---|---|
| **R** | Rust unit/contract/recovery/server/fake-Firecracker tests (name = `module::test`) | `make rust-test` | nothing |
| **C** | Python integration/isolation tests that also run against the in-memory host with the **shipped** config + policy | `make control-plane` | nothing (no KVM) |
| **K** | Python integration/isolation tests that need a real microVM | `make integration` | KVM host, root, installed image, `ACF_INTEGRATION=1` |
| **P** | CLI unit, contract and end-to-end tests | `make py-test`, `make e2e` | nothing |
| **T** | Script/tool tests (installers, image tooling, pins, guard tests) | `make tools-test` | root for ~⅓ of them |

**K tests are written, type-checked and lint-clean, but have not been executed** (no `/dev/kvm` where this was built).
Where a clause is proven by K alone it says so; treat those as *specified and instrumented*, not *demonstrated*.

---

## 1. Master Plan → actual structure

The Master Plan's tree is a *sketch*; the spec (§26) says the projection "is not a requirement to create eleven packages".
Differences are deliberate and listed here so nothing looks accidentally missing.

| Master Plan sketch | Actual | Why |
|---|---|---|
| `apps/cli/main.py` | `apps/cli/main.py` + `src/acf_cli/*` | The entry point stays; the package is testable and typed. |
| `host-agent/rust-toolchain.toml` | workspace-root `rust-toolchain.toml` | Three crates share one toolchain pin. |
| `src/lifecycle/{create,start,stop,destroy}.rs` | `lifecycle/{sandbox,ops,exec,snapshots,capacity,query}.rs` | create/start/stop/destroy share one state machine and one begin/step/finish protocol; splitting by verb duplicated it. `exec` and snapshots are first-class. |
| `firecracker/{client,machine,drives,network,snapshot}.rs` | `firecracker/{backend,client,jailer,models,verify}.rs` | Machine/drive/snapshot request bodies live together in `models.rs` (one serde-tested file); `network.rs` is absent because the VMM has **no** network device (`network=none`); `jailer.rs` and `verify.rs` carry the confinement. |
| `process/{supervisor,limits}.rs` | `process/{supervisor,limits,identity}.rs` | `identity.rs` adds pid + start-time + boot-id identity (DELTA-013). |
| `filesystem/{mounts,cleanup}.rs` | `filesystem/{layout,generation,hashcopy,images,artifacts}.rs` | No mounts happen on the host (the guest sees one block device); cleanup is *ownership-proven generation removal*. |
| `network/{namespace,egress,proxy}.rs` | `network/{netns,verify}.rs` | **`egress.rs` and `proxy.rs` are deliberately absent**: supports `none` only (spec §18.7, Gate H). |
| `telemetry/{metrics,events}.rs` | same | ✓ |
| *(not in sketch)* | `admission/`, `operation/`, `recovery/`, `snapshot/`, `protocol/`, `server/`, `guest/`, `domain/`, `backend.rs`, `app.rs`, `doctor.rs`, `schema.rs` | The spec's BND-02/03/09/10 and the wire contract (§7, §24). |
| *(not in sketch)* | `execution/wire`, `execution/guest-agent` | Exec needs an in-VM agent and a shared protocol crate. |
| `tests/integration/{vm_lifecycle,execution,snapshots}` | same **+ `recovery/`** | Spec §27.6. |
| `tests/isolation/{filesystem,process,network}` | same **+ `host_control/`** | Spec §27.5/§27.9, SEC-001/-002/-009/-010. |
| `scripts/{install-firecracker,build-image,create-rootfs}.sh` | same **+ `host-setup.sh`, `pin-images.sh`, `acf-setup-cgroup`, `check-release-purity.sh`** | Operator path and release gate. |
| `images/{base,python,node,browser}/` | same + `overlay/` (`acf-init`) + `images.lock` | Pinned inputs. |
| `policies/default.yaml` | same | ✓ |

## 2. Master Plan phase gate → evidence

| Gate item | Evidence | Run here? |
|---|---|---|
| **VM lifecycle deterministic** | R `domain::lifecycle::tests::*` (transition table incl. forbidden cases); R `contract_tests::{full_lifecycle_releases_every_resource, destroy_and_stop_are_idempotent, stale_generation_references_never_act_on_the_current_incarnation}`; C `vm_lifecycle::{test_the_explicit_lifecycle_walks_the_documented_states, test_start_is_legal_exactly_once_from_provisioning, test_stop_and_destroy_by_id_are_idempotent_but_a_destroyed_name_is_gone}`; K `test_the_vmm_process_lives_exactly_as_long_as_the_sandbox_runs` | R, C yes; K no |
| **Execution isolation tested** | K `isolation/{filesystem,process,host_control}/*`; R guest-agent `exec::tests::*`, `fork_bomb_is_contained_by_the_process_budget` | R yes; K no |
| **Network modes tested** | R `network::verify::tests::*`; R `fc_backend_tests::a_guest_that_reports_a_nic_fails_the_boot_closed_and_the_vmm_is_killed`; C `isolation/network::{test_none_is_the_only_network_mode_in_every_place_a_mode_can_be_named, test_a_client_that_bypasses_the_cli_still_cannot_ask_for_another_network_mode[×8]}`; K `isolation/network::*` (no NIC, no egress to 3 targets, no listeners, no raw sockets) | R, C yes; K no |
| **Resource limits enforced** | R `capacity::tests::*`, `limits::tests::*`, `contract_tests::admission_is_atomic_against_the_host_envelope`; C `integration/execution::{ceilings, envelope, vcpu budget, concurrent creates}`; K `integration/execution::{fork bomb, memory hog, disk full, deadline, output cap, …}` | R, C yes; K no |
| **Snapshot/restore verified** | R `contract_tests::{snapshot_break_restore_returns_the_workspace_to_a_verified_baseline, a_restore_that_does_not_reproduce_the_baseline_is_rejected}`; R `fc_backend_tests::snapshot_then_restore_reproduces_guest_state_and_a_reboot_is_detected` (real guest agent); K `integration/snapshots::*` | R yes; K no |
| **Crash recovery works** | R `recovery_tests::*` (20 tests, all five injection points); K `integration/recovery::*` | R yes; K no |
| **Host agent cannot be controlled from guest** | K `host_control::{test_the_guest_cannot_reach_the_host_agent_the_vmm_api_or_the_hosts_vsock_services, test_the_guest_agent_obeys_only_the_host, test_the_guest_has_no_device_that_is_a_control_channel}`; R guest-agent `tests/protocol.rs` (strict protocol, `Hello` first). The decisive checks are K. | R partly; K no |

**First technical milestone** (`run_id`, `exit_code`, stdout, stderr, metrics, artifact references; then snapshot and
restore returning the workspace to a verified state):

```bash
acf-local run --image python --cpu 2 --memory 4096 --network none --keep --name lab --command "python experiment.py"
acf-local snapshot create baseline --sandbox lab
acf-local snapshot restore baseline
```

`--keep` leaves the sandbox idle so it can be snapshotted; without it `run` destroys the sandbox afterwards (the
Master Plan's one-shot form). C `test_the_milestone_run_succeeds_and_leaves_nothing_behind` runs the one-shot form
against the in-memory host; K runs it for real and asserts the guest executed the command
(`test_the_guest_really_executed_the_command`).

---

## 3. Acceptance gates (spec §28)

### Gate A — Local caller and admission
| Requirement | Evidence |
|---|---|
| unauthorised local caller rejected | R `server_tests::a_peer_that_is_not_allowlisted_is_denied_before_any_request_is_read`, `admission::auth::tests::*`; C `host_control::{test_a_local_process_without_access_to_the_socket_cannot_even_connect, test_a_local_process_that_reaches_the_socket_is_still_refused_by_the_hosts_own_identity_check}` |
| policy integrity verified | R `trusted_file::tests::*`, `policy::tests::unknown_keys_and_wrong_schema_are_rejected`; K `test_a_policy_file_that_fails_its_integrity_check_is_never_loaded` |
| invalid requests produce no privileged mutation | R `contract_tests::policy_denials_happen_before_any_record_or_side_effect`, `protocol::request::tests::*`, `server_tests::malformed_requests_are_answered_precisely_and_do_not_kill_the_connection`; C `host_control::{test_a_command_the_policy_does_not_grant_…[×5], test_a_create_the_policy_does_not_grant_…}` |
| operation identity and request fingerprint persisted | R `operation::fingerprint::tests::*`, `journal::tests::committed_state_survives_reopen`, `contract_tests::same_operation_id_*`; C `test_an_operation_id_is_idempotent_for_one_request_and_a_conflict_for_any_other` |

### Gate B — Lifecycle
| Requirement | Evidence |
|---|---|
| create/start/run/stop/destroy deterministic | see §2 row 1; R `contract_tests::full_lifecycle_releases_every_resource`; R `server_tests::a_whole_lifecycle_works_through_the_wire_protocol_alone`; P `apps/cli/tests/test_e2e.py` |
| stale generation rejected | R `contract_tests::stale_generation_references_never_act_on_the_current_incarnation`, `names_never_retarget_a_destructive_operation` |
| duplicate operation semantics proven | R `same_operation_id_same_request_returns_the_original_result_without_mutating`, `same_operation_id_different_request_is_a_conflict_and_a_missing_retry_is_rejected`; C as Gate A |

### Gate C — Isolation
| Requirement | Evidence |
|---|---|
| guest cannot reach host control surfaces | K `host_control::{…_the_guest_cannot_reach_the_host_agent_the_vmm_api_or_the_hosts_vsock_services, …_the_guest_agent_obeys_only_the_host, …_the_vmms_sockets_are_unreachable_to_other_local_users, …_the_vmm_holds_no_descriptor_for_the_hosts_own_state}` |
| guest cannot obtain host KVM authority | K `host_control::test_the_guest_has_no_device_that_is_a_control_channel`; K `filesystem::test_the_guest_has_one_block_device_and_no_shared_filesystem` |
| filesystem / network / process isolation verified | K `isolation/filesystem/*` (5), `isolation/process/*` (7), `isolation/network/*` (8, of which 2 also C) |

### Gate D — Resources
| Requirement | Evidence |
|---|---|
| CPU / memory / runtime / PID / disk / output / network semantics tested | below-at-above-limit: R `capacity::tests::each_dimension_can_be_the_one_that_rejects`, guest `exec::tests::{deadline_kills_the_process_group, output_over_cap_is_truncated_but_fully_counted_and_child_not_blocked}`, R `guest::client::tests::output_is_truncated_at_the_cap_and_flagged`; C `execution::*` ceiling tests; K `execution::{test_the_guest_sees_the_cpus_and_memory_it_was_promised, …disk…, …fork_bomb…, …memory_hog…, …deadline…, …output…}` |
| host-wide reservation prevents admission races | R `contract_tests::{admission_is_atomic_against_the_host_envelope, concurrent_creates_can_never_both_take_the_last_slot}`; C `test_concurrent_creates_never_overcommit_the_envelope` |
| quota / exhaustion evidence recorded | R `limits::tests::stats_are_parsed_from_kernel_files_and_become_evidence`; R `capacity::tests::snapshot_quota_count_and_free_space`; K `test_a_run_reports_what_the_vmm_really_consumed`, `test_the_snapshot_count_limit_is_enforced` |

### Gate E — Snapshot
| Requirement | Evidence |
|---|---|
| snapshot quota enforced | R `capacity::tests::snapshot_quota_count_and_free_space`; K `snapshots::test_the_snapshot_count_limit_is_enforced` |
| exact artifact identity bound | R `snapshot::store::tests::{manifest_is_bound_to_the_journal_digest, artifacts_are_reverified_from_disk}`; K `snapshots::{…artifact_changed_on_the_host…, …manifest_changed_on_the_host…, …directory_deleted_on_the_host…, …missing_snapshot_artifact…}` |
| compatibility gate enforced | R `snapshot::manifest::tests::{compatible_when_everything_matches_and_each_difference_is_named, cpuinfo_fingerprint_…}` |
| verified restore predicate proven | R `contract_tests::{a_restore_that_does_not_reproduce_the_baseline_is_rejected, snapshot_break_restore_returns_the_workspace_to_a_verified_baseline}`; R `fc_backend_tests::snapshot_then_restore_reproduces_guest_state_and_a_reboot_is_detected`; guest `probe::tests::*` |
| corruption / tamper rejected safely | R `contract_tests::a_tampered_manifest_or_artifact_is_refused_and_never_loaded`, `fc_backend_tests::a_tampered_snapshot_is_refused_before_any_vmm_is_launched`, `contract_tests::a_failed_restore_never_costs_the_caller_their_existing_sandbox` |

### Gate F — Recovery
| Requirement | Evidence |
|---|---|
| host-agent restart reconciles | R `recovery_tests::{a_healthy_survivor_is_adopted_and_remains_usable_after_a_restart, interrupted_stop_and_destroy_are_completed_by_recovery, an_interrupted_snapshot_*, a_restore_that_died_*}`; K `recovery::{test_an_idle_sandbox_is_adopted_by_the_next_agent_process, test_repeated_crashes_converge_on_the_same_sandbox}` |
| Firecracker crash reconciles | R `recovery_tests::a_vmm_that_vanished_while_the_host_was_down_is_reported_not_assumed_alive`, `fc_backend_tests::a_pid_file_naming_a_process_that_is_not_ours_is_never_adopted_or_signalled`; K `recovery::test_a_vmm_killed_from_outside_is_noticed_and_the_sandbox_can_be_cleaned_up` |
| ambiguous mutation becomes known or quarantined | R `recovery_tests::{an_interrupted_run_is_unknown_and_its_sandbox_is_stopped_never_retried, a_forged_ownership_marker_is_quarantined_and_nothing_is_deleted, a_corrupt_journal_puts_the_host_in_read_only_quarantine_and_recovery_mutates_nothing}`, `classify::tests::*`; K `recovery::test_a_crash_during_a_command_never_reports_success_and_retires_the_sandbox` |
| recovery convergence bounded | R `recovery_tests::recovery_is_bounded_and_quarantines_instead_of_looping`; every `recover_checked` also asserts the second pass is a no-op |
| cleanup cannot delete unowned paths/resources | R `generation::tests::*`, `recovery_tests::{a_symlinked_generation_directory_is_never_followed_by_recovery, orphan_directories_are_flagged_once_and_never_deleted}`, `fc_backend_tests::teardown_refuses_while_running_and_requires_ownership_proof` |

### Gate G — Evidence and observability
| Requirement | Evidence |
|---|---|
| terminal result contains evidence completeness | R `contract_tests::{a_lost_exec_result_is_unknown_and_never_reported_as_failed, truncated_output_is_flagged_and_large_output_is_spilled_and_rehydrated, a_host_backstop_kill_marks_the_sandbox_failed_but_the_run_timed_out}`; P `apps/cli/tests/test_contract.py` (CLI models validate against the generated JSON Schemas) |
| diagnostic telemetry failure does not redefine lifecycle truth | R `telemetry::events::tests::a_dead_log_file_degrades_telemetry_without_failing_the_caller` |
| required execution/security evidence explicit | *Execution evidence:* every `RunResult` carries `evidence_status`, `resource_evidence` (configured · effective · observed peak · violation · the mechanism that actually enforced it), both output captures with truncation flags and artifact references, `policy_id` and `image_id`. *Security evidence:* the VMM posture and the network verdict are computed at every launch (`StartOutcome`) and **fail the start closed** when missing or violated (R `network::verify::tests::*`, `fc_backend_tests::a_vmm_that_fails_the_confinement_check_…`); the `security_profile_id` is recorded on every generation |

### Gate H — Phase boundary
| Requirement | Evidence |
|---|---|
| no cloud control plane | the only listener is the Unix socket; `hyper` is built with `client`+`http1` only (no `server`), used solely to speak to Firecracker's API socket; R `server::ipc::tests::*`; K `host_control::test_no_acf_process_listens_on_a_network_port` |
| no remote mTLS host protocol | no TLS dependency in the workspace (`Cargo.toml`) |
| no multi-tenant authorisation | one allow-list (`allowed_uids`/`allowed_gids`) + one admin set (`trusted_owner_uids`); no tenant concept in `domain/` |
| no generalised workflow/controller subsystem | none exists; operations are the nine in `OperationType` |
| no speculative alternative backend | one `SandboxBackend` implementation besides the test fake; `CapabilityProfile` advertises `network_modes: [none]` |

---

## 4. Test contract (spec §27)

| § | Required coverage | Where |
|---|---|---|
| 27.2 Unit | lifecycle legality · generation/revision · fingerprint · failure & retry classification · admission arithmetic · output accounting · manifest validation · path confinement · policy integrity · schema validation | `domain::lifecycle::tests`; `contract_tests::stale_*`; `operation::fingerprint::tests`; `protocol::response::tests`, `recovery::classify::tests`; `capacity::tests`; guest `exec::tests`, `guest::client::tests`; `snapshot::manifest::tests`; `filesystem::layout::io_tests`, `ids::tests`; `admission::{policy,trusted_file}::tests`; `schema::tests`, `apps/cli/tests/test_contract.py` |
| 27.3 Contract | duplicate · lost response · stale generation · unknown outcome · reservation atomicity · cleanup ownership · snapshot binding · restore predicate | `testing/contract_tests.rs` (23), `server_tests::a_client_that_disconnects_mid_request_can_still_resolve_its_operation_by_id`, `recovery_tests::a_lost_response_is_resolved_by_operation_id_even_across_a_restart` |
| 27.4 Integration | CLI→host · host→Firecracker · Firecracker→microVM · microVM→workload · snapshot→restore | CLI→host: P `test_e2e.py`, R `server_tests::a_whole_lifecycle_works_through_the_wire_protocol_alone`; host→Firecracker: R `fc_backend_tests::*` (fake Firecracker + **real guest agent**); the rest: K `tests/integration/*` |
| 27.5 Isolation (from inside the guest) | host fs traversal · `/dev/kvm` · Firecracker socket · host-agent socket · inherited descriptors · network · resource exhaustion · process-tree abuse | K: `filesystem::test_a_file_on_the_host_is_nowhere_in_the_guest`; `host_control::test_the_guest_has_no_device_that_is_a_control_channel`; `host_control::…cannot_reach_the_host_agent_the_vmm_api…`; `process::test_the_workload_inherits_nothing_from_the_guest_agent_but_its_standard_streams`; `isolation/network/*`; `execution::{fork bomb, memory hog, disk full}`; `process::*` |
| 27.6 Recovery (inject at …) | before journal write · after journal/before mutation · during backend mutation · after backend mutation/before response · after terminal backend state/before result persistence · after result persistence/before response · host-agent crash · Firecracker crash · power loss | `testing/fault.rs` defines **five** injection points, all hooked in production code and armed by tests: `BeforeJournalWrite` (`a_crash_before_the_journal_write_…`), `AfterJournalBeforeMutation`, `BeforeBackendStep` (*during* a mutation: the step is declared, the effect may not have happened), `AfterBackendMutationBeforeCommit` (covers both "after backend mutation" and "after terminal backend state / before persistence": one point, because nothing between the backend returning and the commit is observable), `AfterTerminalCommitBeforeResponse` (`a_crash_after_the_result_was_persisted_…`). Host-agent crash = every one of these (the coordinator is dropped and rebuilt over the surviving journal). Firecracker crash: R `a_vmm_that_vanished_…`, K `recovery::test_a_vmm_killed_from_outside_…`. Power loss: R torn-tail journal tests (`journal::tests::a_torn_final_line_is_repaired_…`, `a_bad_final_record_with_newline_is_also_a_torn_tail`) + `recovery_is_unaffected_by_a_host_reboot_voiding_monotonic_deadlines`; a real power cut is not tested. Every row asserts the specific classification. |
| 27.7 Snapshot adversarial | manifest tamper · artifact replacement after validation · missing backing resource · incompatible CPU/arch · schema mismatch · corrupt data · concurrent snapshot/delete · quota · restore readiness failure | R `store::tests::*`, `manifest::tests::*`, `contract_tests::{a_tampered_manifest_or_artifact_is_refused_and_never_loaded, a_restore_that_does_not_reproduce_the_baseline_is_rejected, snapshot_and_exec_exclude_each_other_and_need_an_idle_sandbox}`; K `integration/snapshots::*`. *Concurrent snapshot/delete* is serialised by the per-snapshot lock (R); a true race against a real VMM is K only. |
| 27.8 Resource | below / at / above limit · concurrent admission · host-wide exhaustion · recovery after violation | R `capacity::tests::each_dimension_can_be_the_one_that_rejects`, `concurrent_creates_can_never_both_take_the_last_slot`; C ceilings and envelope; K enforcement under real load |
| 27.9 Policy / security | unauthorised caller · policy ownership change · mutation during active run · deny-before-mutation · guest reaching control surface · setup failure fail-closed | R `server_tests::*`, `trusted_file::tests::*`, `fc_backend_tests::a_vmm_that_fails_the_confinement_check_is_killed_before_it_is_configured`; K `host_control::{test_a_policy_file_that_fails_its_integrity_check_is_never_loaded, test_a_policy_edit_never_changes_a_run_that_was_already_admitted}` |
| 27.10 Property-style | idempotent destroy · stale generation · op-id never aliases fingerprints · recovery converges or quarantines · cleanup never leaves its roots · unknown never becomes success | R `proptest` in `fingerprint::tests::permuting_object_keys_never_changes_the_digest`, `frame::tests::arbitrary_payloads_roundtrip`, `garbage_never_panics_or_overallocates`; idempotent destroy: `destroy_and_stop_are_idempotent` (repeated 3×); convergence: `recover_checked` (second pass is a no-op); confinement: `layout::io_tests`, `ids::tests::*` |

---

## 5. Security invariants (spec §17.3)

| ID | Invariant | Proof (spec: …) | Here |
|---|---|---|---|
| SEC-001 | Guest cannot invoke host-agent lifecycle authority | adversarial guest control-surface test | K `host_control::…guest_cannot_reach_the_host_agent_the_vmm_api_or_the_hosts_vsock_services`, `…guest_agent_obeys_only_the_host` (the guest agent's accept-only-CID-2 rule lives in its `main.rs` accept loop and is covered by K alone); R guest-agent `tests/protocol.rs` (first message must be `Hello`, strict protocol) |
| SEC-002 | Guest cannot read/write Firecracker control sockets | socket permission/reachability test | K `…vmms_sockets_are_unreachable_to_other_local_users`; the socket lives inside the jail chroot under the VM's uid |
| SEC-003 | Guest cannot access `/dev/kvm` | device enumeration test | K `…guest_has_no_device_that_is_a_control_channel` |
| SEC-004 | Host execution constrained by Jailer/process/security configuration | manifest + process inspection | R `jailer::tests::argv_is_exact_and_never_disables_security_controls`, `identity::tests::posture_parsing_and_policy`; K `…vmm_runs_unprivileged_in_its_own_jail_and_without_a_network`, `…vmm_is_confined_by_its_own_cgroup` |
| SEC-005 | Paths confined to approved roots | traversal/symlink/race tests | R `layout::io_tests::capability_dir_cannot_be_escaped_with_dotdot_or_absolute_paths`, `ids::tests::{no_string_with_a_separator_or_dot_is_ever_accepted, path_traversal_and_wrong_prefix_are_unrepresentable}`, `generation::tests::cleanup_refuses_a_symlinked_generation_and_never_follows_it`, `hashcopy::tests::a_swapped_source_yields_a_different_digest_not_a_silent_success` |
| SEC-006 | Network isolation matches declared mode | guest connectivity probes | R `network::verify::tests::*`; C/K `isolation/network/*` |
| SEC-007 | Resource enforcement trusted and bounded | stress/limit tests | R `limits::tests::*`, guest `exec::tests::*`; K `integration/execution/*` |
| SEC-008 | Snapshot artifacts are protected trusted-host data | permission/tamper tests | R `store::tests::*`, `doctor::tests::state_root_must_be_private`; K `…state_directory_is_closed_to_other_users`, `snapshots::…changed_on_the_host…` |
| SEC-009 | Caller authorisation fails closed | unauthorised local process test | R `auth::tests::*`, `server_tests::a_peer_that_is_not_allowlisted_…`; C `host_control::test_a_local_process_*` |
| SEC-010 | Policy integrity cannot be weakened by untrusted edits | ownership/permission mutation test | R `trusted_file::tests::{group_writable_file_is_rejected, wrong_owner_is_rejected, symlink_leaf_is_rejected_without_following, world_writable_ancestor_is_rejected}`; K `…policy_file_that_fails_its_integrity_check_…` |
| SEC-011 | Security-control setup failure prevents guest execution | injected setup failure test | R `fc_backend_tests::{a_vmm_that_fails_the_confinement_check_is_killed_before_it_is_configured, a_guest_that_reports_a_nic_fails_the_boot_closed_and_the_vmm_is_killed, an_api_failure_after_launch_leaves_no_live_vmm_behind}`, `jailer::tests::launch_surfaces_a_failing_jailer_…`, `doctor::tests::enforce_refuses_on_any_failure_…`, guest `exec::tests::cgroup_create_fails_closed_…` |
| SEC-012 | Telemetry does not become lifecycle authority | telemetry failure tests | R `events::tests::a_dead_log_file_degrades_telemetry_without_failing_the_caller` |
| SEC-013 | Cleanup cannot delete outside its validated ownership root | corrupted-metadata cleanup tests | R `generation::tests::*`, `recovery_tests::{a_forged_ownership_marker_is_quarantined_…, orphan_directories_are_flagged_once_and_never_deleted}`, `fc_backend_tests::{teardown_refuses_while_running_and_requires_ownership_proof, a_pid_file_naming_a_process_that_is_not_ours_…}` |
| SEC-014 | No hidden shared resource crosses the control boundary | control-surface enumeration | K `…vmm_holds_no_descriptor_for_the_hosts_own_state`, `process::…inherits_nothing_from_the_guest_agent…`, `filesystem::…one_block_device_and_no_shared_filesystem`, `…no_acf_process_listens_on_a_network_port`; inventory in [ARCHITECTURE.md §4](ARCHITECTURE.md) |
| SEC-015 | Security-relevant runtime configuration recorded as a manifest | runtime manifest assertion | `FirecrackerBackend::new` builds the profile (VMM + version, jailer settings, seccomp posture, cgroup controls, network mode, machine config, boot-args digest) and records its digest as `security_profile_id` on every generation, every sandbox view and every snapshot manifest (R `snapshot::manifest::tests::*` rejects a profile mismatch); K `…vmm_runs_unprivileged_…` reads the posture back from `/proc` |

---

## 6. Contract delta ledger (spec §30) → code

| Δ | Title | Implemented in |
|---|---|---|
| 001 | Local caller authentication | `admission/auth.rs`, `server/ipc.rs` (SO_PEERCRED; identity is never self-asserted) |
| 002 | Closed control surface | [ARCHITECTURE.md §4](ARCHITECTURE.md); `isolation/host_control` |
| 003 | Request fingerprint | `operation/fingerprint.rs` (canonical JSON, sha256, floats refused) |
| 004 | Resource generation / CAS | `ids::Generation`, `expected_generation` on every mutating request, `filesystem/generation.rs` |
| 005 | Atomic resource admission | `lifecycle/capacity.rs` inside `Journal::commit_with` |
| 006 | Output budget and completeness | `domain/evidence.rs` (`OutputCapture`), guest `exec.rs`, `guest/client.rs::enforce_bounds`, artifact spill |
| 007 | Snapshot exact-object binding | `snapshot/{manifest,store}.rs` |
| 008 | Image TOCTOU | `filesystem/hashcopy.rs`, `images.rs` (identity = sha256 of manifest bytes; rootfs hashed while copied) |
| 009 | Security runtime manifest | `firecracker/backend.rs` profile → `security_profile_id` |
| 010 | Policy authority and immutability | `admission/{policy,trusted_file}.rs`; `PolicyId` recorded per operation |
| 011 | Deterministic recovery classification | `recovery/classify.rs` (pure function) |
| 012 | Cleanup ownership proof | `OWNER.json` marker with nonce; `SandboxBackend::teardown(owner_nonce)` |
| 013 | Resource identity beyond PID | `process/identity.rs` (pid + start-time ticks + boot id) |
| 014 | Snapshot restore verification | probe digest oracle (`lifecycle/snapshots.rs`, guest `probe.rs`) |
| 015 | Network vocabulary repair | `domain/resources.rs::NetworkMode` has one variant, `none`; unknown modes are rejected at the wire |
| 016 | Narrow journal | `operation/{journal,records}.rs` |
| 017 | RecoveryCoordinator boundary | `recovery/` |
| 018 | Backend capability profile | `backend.rs::CapabilityProfile`; `UNSUPPORTED` failure class |
| 019 | Evidence classification | `telemetry/mod.rs` (REQUIRED_EXECUTION_EVIDENCE · SECURITY_EVIDENCE · DIAGNOSTIC_TELEMETRY) |
| 020 | Semantic protocol versioning | `protocol::PROTOCOL = "acf.host/1"`; `deny_unknown_fields` everywhere; R `wrong_protocol_version_is_rejected_not_negotiated_silently` |

## 7. Where the implementation chose a stricter or different reading

* **Create ends in `PROVISIONING`, not `READY`.** A sandbox is provisioned (disk copied, identity journaled) by `create`
  and launched by `start`; `READY` means "VMM up and agent answering Hello". This keeps `create` free of a running VMM
  (cheap to recover) and makes "start exactly once" a testable rule.
* **Restore verification is a probe digest, not a screenshot of state.** The oracle is `boot_id` + a canary sha +
  agent version (spec §20.5 leaves the predicate to the implementation). A workload's own memory is not diffed.
* **Telemetry export is out of scope**; metrics are process-local counters (spec §23.5 requires only that telemetry
  failure not change truth).
* **`policy_reload` is an operation** (durable, admin-only) rather than a side-channel, so a reload is as auditable as a run.
