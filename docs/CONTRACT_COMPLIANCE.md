# Contract compliance

How the execution-plane contract, version 1.2.0, is met: for each family of clauses, where it is implemented and
which tests can fail for it. Identifiers (`OP-2`, `T-REC-04`, `INV-026`, `§16.2`) are the contract's own.

This document maps; it does not report results. Whether a test was run, and at which evidence level, is in
[VERIFICATION_STATUS.md](VERIFICATION_STATUS.md). The short form: everything at L0 to L3 runs without KVM and was
run; **nothing at L4 or L5 has been run**, so every clause whose only decisive test is L4 is *implemented and
instrumented*, not *demonstrated*.

Paths are relative to `execution/host-agent/src/` unless they start with another crate's directory. A test named
`t_xxx_nn_…` lives in `testing/suites/`; other tests are named by the module they sit in.

---

## 1. Module projection (§29)

| Contract projection | Code | Notes |
|---|---|---|
| `edge/` | `edge/` | `serve.rs` (limits, authentication, decode, relay), `local.rs`, `tls.rs`, `channel.rs` |
| `authority/` | `authority/` | `enrolment.rs`, `profile.rs`, `trusted_file.rs` |
| `domain/` | `domain/`, `ids.rs`, `error.rs` | imports no edge, store-engine or backend type |
| `coordinator/` | `coordinator/` | `pipeline.rs`, `ops.rs`, `sandbox.rs`, `exec.rs`, `snapshots.rs`, `operator.rs`, `query.rs`, `sweep.rs`, `recover.rs`, `link.rs` |
| `recovery/` | `recovery/decision.rs` | pure functions only; applying a decision is the coordinator's |
| `backend/` | `backend/mod.rs` (port), `backend/firecracker/`, `backend/process/`, `backend/netns.rs` | one replacement unit |
| `guest/` | `guest/`, `execution/wire/`, `execution/guest-agent/` | |
| `resources/` | `resources/admission.rs`, `resources/lifetime.rs` | |
| `network/` | `network/`, `execution/traffic/` | the guest-traffic role's code is its own crate so that it cannot link host-mutation code |
| `storage/` | `storage/` | images, snapshots, generation directories, output artifacts |
| `secrets/` | `secrets/` | |
| `store/` | `store/`, `durability.rs` | |
| `telemetry/` | `telemetry/` | |
| `contracts/` | `execution/contracts/` | plus `schemas/` for file formats |
| — | `api/`, `app.rs`, `main.rs`, `privsep.rs`, `doctor.rs`, `config.rs`, `clock.rs` | the wire model, startup, roles, preflight, parameters, time |

---

## 2. Clauses → code → tests

### 2.1 Privilege domains and security model (§6.1, §17)

| Clauses | Implementation | Tests |
|---|---|---|
| PD-1, INV-025, SEC-016 | `privsep.rs` (`enter_role`, `verify_unprivileged`, `spawn_role`), `edge/serve.rs::role_main`, `main.rs` | `privsep` tests; `tests/process_roles.rs::t_sec_01_the_edge_is_a_separate_unprivileged_process_and_the_core_reads_no_peer_bytes`; `t_sec_01_only_validated_commands_reach_the_core` |
| PD-2 | `coordinator/pipeline.rs::admit` (re-validation, enrolment re-check) | `t_auth_01_a_peer_that_is_not_enrolled_has_no_authority_at_the_core` |
| PD-3, NW-5 | `execution/traffic/` (no process, file, namespace or filter operations), `network/traffic.rs::role_main` | `acf-traffic` tests; `network::traffic` tests |
| PD-4, LT-4, INV-030 | `resources/lifetime.rs` (`TicketDir`, `enforce_once`, `run_enforcer`), `main.rs::lifetime_role` | `resources::lifetime` tests (a real child process is ended at its expiry and not before); `t_host_01_without_a_lifetime_enforcer_the_host_creates_no_privilege`. T-HOST-01 itself is L4 |
| PA-1, PA-2 | `edge/serve.rs` (admission order, `max_connections`, per-source cap, `handshake_deadline`, `max_request_bytes`, `idle_timeout`) | `t_sec_03_unauthenticated_and_misbehaving_peers_do_not_disturb_authenticated_traffic`; `t_auth_01_a_credential_that_is_not_enrolled_is_refused_before_any_request_is_read` |
| PA-3 | evidence is obtained at the call site: `backend/firecracker/backend.rs` (`start`, `restore`), `coordinator/sandbox.rs` | `fc_backend_tests` (root); `t_op_05_t_rec_02_…` |
| TI-1 | `authority/trusted_file.rs` (`read_trusted`, `check_ancestors`, `trusted_executable`) | `authority::trusted_file` tests (13) |
| TI-2 | kernel, root filesystem and snapshot artifacts: hashed while they are copied (`storage/hashcopy.rs`, `stage_file`). VMM and jailer: pinned by digest in the host configuration, hashed at startup before either is run and again before every launch (`backend/firecracker/verify.rs`). Release archive: `scripts/firecracker.lock` | `storage::hashcopy`, `storage::images`, `backend::firecracker::verify::tests::a_binary_is_run_only_from_a_trusted_path_with_the_pinned_bytes_and_the_pinned_version`; `backend::firecracker::backend::tests::a_binary_replaced_while_the_host_runs_is_never_launched` and `…::a_file_swapped_after_its_digest_was_recorded_is_never_staged` (T-SEC-07); `t_snap_01_…`; `fc_backend_tests::provisioning_rejects_a_corrupt_image_and_an_undersized_disk` (root) |
| TI-3 | feature `testing`; `coordinator/mod.rs::fault!` expands to nothing without it | `scripts/check-release-purity.sh` and its test (T-SEC-06) |
| TI-4 | `Cargo.lock`, `uv.lock`, `scripts/*.lock`, `tools/check_pins.py` | `tests/tools/test_check_pins.py` |
| IS-1, IS-2 | `backend/firecracker/backend.rs` (prove step), `backend/process/identity.rs::SecurityPosture`, `BackendIdentity::security_profile_id` | `backend::process::identity` tests; `fc_backend_tests::a_vmm_that_fails_the_confinement_check_is_killed_before_it_is_configured` (root). T-SEC-04 is L4 |
| IS-3 | `coordinator/sweep.rs` (idle), `coordinator/sandbox.rs::while_intact` (held), `config.rs::RecoveryConfig::posture_due_after` | `t_sec_05_a_control_lost_after_launch_ends_the_runtime_whether_the_sandbox_is_idle_or_held`; `recovery::decision` rows. T-SEC-05 itself is L4 |
| IS-4, NW-2 | `backend/firecracker/backend.rs::network_gate` before `InstanceStart` and before resume | `backend::firecracker::backend::tests::no_vcpu_is_started_unless_the_host_side_network_evidence_holds` |
| CS-1, CS-2, SEC-018 | inventory in [ARCHITECTURE.md](ARCHITECTURE.md) §15; the host never listens for a guest (`guest/connector.rs`) | T-SEC-02 is L4: not run |

### 2.2 Identity and authority (§8, §9)

| Clauses | Implementation | Tests |
|---|---|---|
| ID-1, ID-2, INV-018 | `store/records.rs::SandboxRecord` (`last_generation`, `current`), `ids.rs` | `t_conc_06_a_destroyed_sandbox_accepts_nothing_and_a_generation_is_never_reused` |
| ID-3, ID-4 | `store/journal.rs` (revision stamping, lineage), `coordinator/query.rs::changed_since` | `t_api_04_reads_carry_as_of_and_changed_since_returns_exactly_the_changes`; `store::journal` tests |
| ID-5 | `ids.rs` (validated ids), `storage/layout.rs`, `SandboxRef::jail_id` | `ids` tests; `storage::generation` tests |
| AU-1, SEC-012 | `edge/` (two endpoints), `coordinator/pipeline.rs` (one pipeline) | `suites/edge.rs`; `t_auth_02_…` |
| AU-2, AU-6 | `authority/enrolment.rs` | `authority::enrolment` tests; `t_auth_01_…` (both) |
| AU-3 | `edge/tls.rs::server_config` (TLS 1.3 only, explicit anchors, mandatory client certificate) | `t_auth_04_the_network_endpoint_needs_explicit_anchors_and_tls_1_3`; `edge::tls` tests |
| AU-4 | `edge/tls.rs::bound_to_host`, called by `app.rs::load_tls` | `edge::tls::tests::the_hosts_certificate_must_name_the_host`; `t_auth_04_…` |
| AU-5 | `app.rs::refresh_enrolment`, `edge/serve.rs` (connections re-checked on change) | `t_auth_05_a_removed_enrolment_entry_ends_open_connections_within_the_bound` |
| AU-7 – AU-10, INV-015, INV-032 | `domain/authority.rs` (`Tags`, `AuthorityContext::may_access`), `coordinator/mod.rs::Ctx::require_access` | `t_auth_03_another_scope_or_peer_gets_not_found_and_an_operator_succeeds`; `t_scope_01_…` |
| AU-11 – AU-13 | `api/envelope.rs` (`authority` refused while `signed_decision` is not advertised) | `t_auth_08_a_request_carrying_authority_is_refused_not_ignored`; `api` tests |
| SP-1 – SP-5, INV-004 | `authority/profile.rs` | `authority::profile` tests (12); `t_auth_06_the_safety_profile_refuses_and_never_clamps`; `t_auth_07_profile_reload_is_recorded_affects_only_later_operations_and_refuses_an_invalid_profile` |
| §9.2 role table | `domain/method.rs::allowed_for` | `domain::method` tests; `t_auth_02_every_method_for_every_role_is_allowed_exactly_as_the_role_table_says` |

### 2.3 Host API (§10)

| Clauses | Implementation | Tests |
|---|---|---|
| API-1, API-2, INV-036, OB-9 | `api/schema.rs` → `execution/contracts/*.json`, `schemas/*.json` | `api::schema` tests, including `the_checked_in_contracts_match_the_types` (T-API-01); `domain::method`, `domain::mode`, `error` table tests |
| API-3, API-4, VR-2 | `api/envelope.rs`, `api/command.rs` (`deny_unknown_fields`, `validate_shape`), `api/mod.rs::decode_error` (a refusal says what was expected, never what the request held) | `t_api_02_…`, `t_api_05_…`, `t_api_06_…` (four fuzz and property tests); `api::tests::a_refusal_for_an_undecodable_request_never_repeats_what_the_request_said` |
| API-5, FS-1 | `api/response.rs`, `error.rs::retry_advice` | `t_api_03_every_refusal_class_leaves_no_operation_record_and_no_reservation`; `error` tests |
| API-6, API-7, INV-028 | `coordinator/pipeline.rs::operate` (answer only after BEGIN is durable) | `t_op_08_a_response_never_reports_a_state_that_a_power_cut_would_lose`; `t_pers_02_…` |
| API-8, API-9, RY-7 | `coordinator/pipeline.rs::known_operation` (a known operation is resolved before mode, rate and horizon), `coordinator/ops.rs::begin` (the same answers inside the commit), `domain/operation.rs::terminal_effect` | `t_op_01_a_retried_request_is_the_same_operation_and_nothing_runs_again`; `t_op_01_a_retry_is_resolved_whatever_the_host_mode_and_however_old_the_request`; `t_op_02_the_idempotency_table` |
| API-10 – API-12 | `coordinator/query.rs` | `t_api_04_…`; `coordinator::query` tests; `t_exec_03_output_is_bounded_counted_and_readable_in_slices` |
| §10.3 command set, §10.5 failure classes | `domain/method.rs`, `error.rs` | `the_command_set_is_exactly_the_contract_table`; `error` tests |

### 2.4 Operations, failure, retry, concurrency (§11, §13 – §15)

| Clauses | Implementation | Tests |
|---|---|---|
| OP-1 – OP-6, FS-1 – FS-3 | `coordinator/ops.rs` (`begin`, `step`, `finish`, `commit_for`), every flow | `t_op_05_t_rec_02_every_fault_point_of_every_operation_type_ends_as_the_contract_says`; `t_pers_02_every_privileged_step_is_declared_durably_before_it_runs`; `coordinator::ops` tests |
| OP-7 – OP-9, FS-4, FS-8, INV-008, INV-017 | `coordinator/ops.rs::derived_cleanup`, `Outcome`, `coordinator/exec.rs::exec_failed` | `t_op_05_…`; `t_exec_01_every_execution_outcome`; `domain::operation` tests |
| OP-10 – OP-13, INV-005 | `store/records.rs::OpKey`, `domain/fingerprint.rs`, `config.rs::mandatory_checks`, `coordinator/sweep.rs::retention` | `domain::fingerprint` tests (T-OP-04); `t_op_02_…`; `t_op_03_the_acceptance_horizon_and_the_retention_relation` |
| OP-14 – OP-17 | `clock.rs` (`MonotonicRef`), `coordinator/sandbox.rs::bounded`, `coordinator/ops.rs::ensure_within_deadline` | `t_op_06_a_granting_operation_past_its_deadline_is_undone_and_never_succeeds`; `clock` tests |
| OP-18 – OP-20, INV-026, SEC-021 | `recovery/decision.rs::decide_inherited`, `coordinator/recover.rs` | `recovery::decision` rows; `t_rec_03_observation_causes_no_write_and_no_backend_mutation`; `t_secr_03_a_later_activation_never_resolves_a_secret_again` |
| OP-21 – OP-23 | `coordinator/exec.rs::operation_cancel` | `t_op_07_cancellation` |
| OP-24, OP-25 | `coordinator/sweep.rs`, `coordinator/sandbox.rs::sandbox_fail`, `Issuer::Host` | `t_rec_11_a_runtime_lost_while_serving_fails_the_generation_and_keeps_the_lease`; `t_host_01_every_sandbox_has_an_expiry_and_the_host_destroys_it_then` |
| FS-5 – FS-7 | task per operation (`pipeline.rs::operate`), recovery; `edge/serve.rs::session` gives no answer, rather than `REFUSED`, when the core did not answer a request that creates an operation | `t_op_01_…`; `edge::serve::tests::an_unanswered_operation_request_gets_no_answer_and_an_unanswered_read_is_refused`; `tests/process_roles.rs` (an edge killed in mid-service loses nothing committed) |
| FS-9, PS-7 | `store/journal.rs` (rollback, write block), `coordinator/mod.rs::check_store`, `Host::fatal` | `t_pers_03_a_failed_commit_changes_nothing_and_an_uncertain_one_is_a_fail_stop`; `store::journal` tests |
| RY-1 – RY-6, INV-009 | `coordinator/sandbox.rs::retry_step`, `error.rs::never_retried`, `Host::retry_budget` | `t_retry_01_a_dependency_outage_is_retried_within_bounds_and_never_becomes_a_storm` |
| CC-1, CC-2, INV-007 | `coordinator/ops.rs` (`admit_granting`, `target_in`, `commit_for`) | `t_conc_01_…`, `t_conc_02_…`, `t_state_02_a_stale_token_is_a_revision_conflict_for_every_lifecycle_method` |
| CC-3, CC-4, INV-031 | `coordinator/ops.rs` (`admit_containment`, `supersede_entries`), `coordinator/sandbox.rs::begin_containment` | `t_conc_03_containment_preempts_an_execution_that_never_returns`; `t_conc_03_destroy_preempts_every_kind_of_granting_operation`; `t_conc_04_…` |
| CC-5 | operation deadlines (`bounded`), `observe_timeout`, per-call deadlines in `backend/firecracker/` and `guest/client.rs` | `guest::client` tests; `t_op_06_…` |
| CC-6 | `resources/admission.rs` inside the BEGIN commit | `t_conc_05_concurrent_creates_for_the_last_slot_admit_exactly_one`; `resources::admission` tests (T-RES-01) |
| CC-7 | nothing is queued | `t_conc_01_one_granting_operation_per_sandbox_and_nothing_is_queued` |
| CC-8, CC-9 | `coordinator/snapshots.rs` (restore admission, references) | `t_conc_06_…`; `t_snap_04_a_referenced_snapshot_cannot_be_deleted` |

### 2.5 State (§12)

| Clauses | Implementation | Tests |
|---|---|---|
| §12.1 lifecycle relation | `domain/lifecycle.rs::can_transition_to` | `domain::lifecycle::tests::every_pair_of_states_is_judged_exactly_as_the_contract_table_says` (T-STATE-01: all 100 pairs against the table as transcribed) |
| §12.2 admission per state | the precheck of each flow | `t_state_02_every_method_in_every_state_is_admitted_exactly_as_the_admission_table_says` |
| §12.3 snapshot states | `domain/lifecycle.rs::SnapshotState` | `domain::lifecycle::tests::every_pair_of_snapshot_states_is_judged_as_the_contract_says`; `t_snap_*` |
| LS-1 – LS-3, INV-027 | `resources/admission.rs`, `store/records.rs::holds_reservation` | `t_res_03_a_failed_or_quarantined_generation_keeps_its_lease_until_destroyed`; `t_snap_06_…` |
| HM-1 – HM-4, INV-022 | `domain/mode.rs`, `coordinator/mod.rs::mode`, `app.rs::load_trusted_inputs`, `coordinator/operator.rs` (`host_set_mode`, `drain`) | `domain::mode` tests; `t_state_04_…`; `t_host_02_draining`; `t_host_03_a_failed_mandatory_check_with_generations_present` |
| J-1 – J-8, OP-6, INV-006 | reserved states in BEGIN; `supersede_entries`; `coordinator/sandbox.rs::quarantine` | `testing/invariants.rs`, asserted after every commit of every suite; `t_state_03_the_joint_state_invariants_hold_after_every_commit_under_random_operations_and_faults` |

### 2.6 Observation and recovery (§16)

| Clauses | Implementation | Tests |
|---|---|---|
| OB-1 – OB-3, INV-011, INV-033, SEC-019 | `backend/mod.rs::Observation`, `coordinator/recover.rs::observe_generation`, `backend/process/supervisor.rs` | `t_rec_03_…`; `backend::process::supervisor` tests; `resources::lifetime::…a_reused_pid_is_never_signalled…` |
| §16.2 Part A and B | `recovery/decision.rs` | `recovery::decision` tests (25): every row, and unlisted combinations (T-REC-01) |
| RC-1 – RC-3, INV-010, SEC-011 | `storage/generation.rs` (owner marker, nonce), `backend/process/identity.rs`, `LaunchSink` | `t_rec_04_nothing_is_signalled_or_deleted_without_proof_of_ownership`; `t_rec_05_a_resource_no_record_owns_is_reported_and_never_modified`; `storage::generation` tests |
| RC-4 | durable attempt counts (`RecoveryRecord.attempts`, `GenerationRecord.observe_attempts`) | `t_rec_07_a_record_whose_recovery_crashes_the_core_is_quarantined_after_the_bound` |
| RC-5 | `coordinator/recover.rs::recover`, `app.rs::serve_host` (recover before any endpoint) | `t_rec_12_when_the_startup_recovery_deadline_passes_the_rest_is_quarantined` |
| RC-6, RC-7 | `coordinator/sweep.rs` (`run_sweeper`, `host_operation`) | `t_rec_11_…`; `t_sec_05_…` |
| RC-8 | `clock.rs` (boot id in every monotonic reference), ticket boot id | `clock` tests; `resources::lifetime` tests |
| RC-9 | recovery calls no secret provider and no authority check | `t_rec_03_…`; `t_secr_03_…` |
| QR-1 – QR-5 | `coordinator/operator.rs::quarantine_release`, `SandboxBackend::{residue, force_teardown}`, `ops.rs::target_in` | `t_rec_06_quarantine_release_acts_on_the_assertion_and_then_observes`; `t_obs_03_…` |
| LN-1 – LN-4 | `storage/generation.rs::OwnerMarker` (lineage, `created_seq`), `coordinator/recover.rs`, `operator.rs::host_acknowledge` | `t_rec_10_a_store_older_than_the_system_it_describes` |

### 2.7 Execution and the guest (§18)

| Clauses | Implementation | Tests |
|---|---|---|
| EX-1 – EX-4 | `authority/profile.rs::authorize_exec`, `execution/guest-agent/src/exec.rs` | `authority::profile` tests (`exec_env_cwd_and_argv_rules`); the guest agent's unit tests (16), among them `an_argument_with_shell_metacharacters_reaches_the_program_as_it_was_given`, and `tests/protocol.rs`. T-EXEC-04 is L4 |
| §18.2 outcome table | `coordinator/exec.rs` | `t_exec_01_every_execution_outcome` |
| EX-5, EX-6 | `guest/client.rs` (host deadline, cancel, backstop) | `guest::client` tests against the real guest agent. T-EXEC-02 is L4 |
| OU-1 – OU-4, INV-016 | guest-agent capture; `guest/client.rs::enforce_bounds`; `coordinator/exec.rs::capture`; `storage/artifacts.rs`; `config.rs` (OU-3 relation) | `t_exec_03_…`; `t_exec_07_t_secr_02_…`; `config` tests |
| OU-5 | not offered: `incremental_output` is declared false and not advertised | `api::tests::deferred_features_are_not_advertised` |
| GP-1 – GP-3 | `execution/wire/` (framing with a mandatory maximum, strict types), `guest/connector.rs` | `acf-wire` tests (8); `t_api_06_the_guest_protocol_decoder_survives_arbitrary_bytes` |
| GP-4, GP-5, VR-5 | `storage/images.rs` (manifest records versions), `coordinator/sandbox.rs::check_agent_version` | `t_exec_06_a_guest_agent_of_another_version_is_refused_at_start_and_at_restore`; `guest::client` tests |
| GP-6, GP-7 | `domain/evidence.rs` (`HOST_OBSERVED`, `GUEST_REPORTED` labels in the schema) | `domain::evidence` tests |
| GP-8 | no host code mounts or resolves paths inside a guest filesystem | `t_scope_01_…` (static) |

### 2.8 Resources and lifetime (§19)

| Clauses | Implementation | Tests |
|---|---|---|
| RS-1 | `resources/admission.rs::reserve_sandbox` | `resources::admission` tests (7) |
| RS-2 | `backend/process/limits.rs` (`CgroupSpec`, `drift`, evidence) | `backend::process::limits` tests. T-RES-02 is L4 |
| RS-3 | `resources/admission.rs::Pool`, `SandboxBackend::busy_slots` | `t_res_04_an_identifier_carried_by_a_live_resource_is_never_assigned` |
| RS-4 | fresh generation directory and verified copies per generation | `storage::generation` tests. T-RES-05 is L4 |
| LT-1 – LT-3 | `resources/lifetime.rs` (`new_expiry`, `remaining_ms`, `reanchor`), `authority/profile.rs::authorize_lifetime`, the sweep | `resources::lifetime` tests; `t_host_01_every_sandbox_has_an_expiry_and_the_host_destroys_it_then` |

### 2.9 Network (§20)

| Clauses | Implementation | Tests |
|---|---|---|
| NW-1, INV-013, SEC-020 | a namespace with no route; `execution/traffic/` closes on every failure path | `backend::firecracker::netplumb` tests, including the real-namespace test; `acf-traffic` tests. T-NET-07 is L4 |
| NW-2 | plumbing before launch; `network_gate` before the first vCPU | `backend::firecracker::backend` tests; `netplumb` tests. T-NET-08 is L4 |
| NW-3 | `GenerationRecord.resources.network`; no code path changes it | `domain::network` tests |
| §20.1 vocabulary | `domain/network.rs::NetworkMode` (two words), `api/command.rs::unknown_network_mode` (any other word is `UNSUPPORTED`), `coordinator/query.rs::host_info` (a mode is advertised only if profile and backend both offer it) | `t_api_02_…`; `t_ver_02_a_feature_is_advertised_only_while_the_host_offers_it`; `t_back_03_…` |
| NW-4, AL-6 | `execution/traffic/src/policy.rs` (always-denied classes, host addresses, other sandboxes) | `acf-traffic` policy tests; `network::intent` tests |
| NW-6 | `backend/firecracker/backend.rs` (`teardown`, `force_teardown`, `residue`) | `fc_backend_tests::teardown_refuses_while_running_and_requires_ownership_proof` (root) |
| AL-1, AL-2 | `domain/network.rs`, `network/intent.rs`, `execution/traffic/src/policy.rs` | `network::intent` tests; `t_api_05_…` |
| AL-3 | `execution/traffic/src/resolver.rs`, `dns.rs` | `acf-traffic` resolver tests |
| AL-4, AL-5 | `execution/traffic/src/relay.rs`, `sni.rs`, `policy.rs::connect_verdict` | `acf-traffic` relay and policy tests |
| §20.2 mode `none`, three layers | `network/verify.rs::evaluate_none`, `backend/netns.rs`, guest-agent `netprobe.rs` | `network::verify` tests; `fc_backend_tests::a_guest_that_reports_a_nic_fails_the_boot_closed_and_the_vmm_is_killed` (root). T-NET-01 is L4 |

### 2.10 Storage, images, snapshots, secrets (§21, §22)

| Clauses | Implementation | Tests |
|---|---|---|
| ST-1, ST-2, SEC-009 | `storage/layout.rs` (capability-based directories), `storage/generation.rs` | `storage::layout`, `storage::generation` tests (T-SEC-08) |
| IM-1 – IM-4 | `storage/images.rs`, `storage/hashcopy.rs` | `storage::images`, `storage::hashcopy` tests |
| SNP-1 – SNP-4, INV-035 | `storage/snapshots/` (manifest, store), `SnapshotRecord.manifest_digest` | `storage::snapshots` tests; `t_snap_01_a_tampered_snapshot_is_refused_before_any_runtime_is_launched` |
| SNP-5 | `coordinator/snapshots.rs` (`snapshot_create`, `snapshot_failed`) | `t_rec_08_…`; `t_op_05_…` |
| SNP-6 | tags on `SnapshotRecord` | `t_auth_03_…` (T-SNAP-05) |
| SNP-7 | snapshot directories are private to the core; the API has no export method | `t_snap_07_snapshot_storage_is_private_and_there_is_no_export_method` |
| RF-1 – RF-3 | `coordinator/snapshots.rs::snapshot_delete`, `CapabilityProfile::runtime_depends_on_snapshot` | `t_snap_04_…` |
| RE-1 – RE-7, INV-019, SEC-008 | `coordinator/snapshots.rs` (`snapshot_restore`, `restore_body`), `storage/snapshots/manifest.rs::check_compat` | `t_snap_01_…`, `t_snap_02_…`, `t_snap_03_the_restore_oracle`, `t_rec_09_a_restore_interrupted_before_or_after_its_switch`; `fc_backend_tests::snapshot_then_restore_reproduces_guest_state_and_a_reboot_is_detected` (root). T-SNAP-03 itself is L4 |
| SC-1 – SC-7, INV-020, SEC-010 | `secrets/mod.rs`, `api/command.rs` (references only), `coordinator/exec.rs` (`unmarked`), `coordinator/snapshots.rs` | `secrets` tests; `t_secr_01_…`, `t_exec_07_t_secr_02_…`, `t_secr_03_…`, `t_secr_04_…`; `sc_3_sc_5_a_reference_that_does_not_resolve_delivers_nothing_and_marks_nothing` |

### 2.11 Persistence, observability, versioning, backend, parameters (§23 – §26, §30)

| Clauses | Implementation | Tests |
|---|---|---|
| PS-1 – PS-8, INV-029 | `store/journal.rs`, `store/lock.rs` | `store::journal` tests (20: T-PERS-01, T-PERS-05); `t_pers_04_one_writer_per_store` |
| PS-9, PS-10 | reserve ballast; rate limit before BEGIN; retention; `Journal::compact_if_grown` called by the sweep | `t_pers_06_a_full_disk_does_not_prevent_recording_containment`; `ps_10_the_store_file_is_rewritten_while_the_host_serves_and_nothing_is_lost`; `store::journal` tests (`a_store_that_grew_is_compacted_while_it_is_open_and_loses_nothing`, `a_large_store_is_rewritten_only_when_it_has_doubled`, `the_maintenance_tools_open_a_store_the_core_refuses_for_its_size`); `coordinator` rate-limiter test |
| PS-11, PS-12, VR-8 | `store/migrate.rs` | `store::migrate` tests (5); `t_pers_07_schema_changes` |
| PS-13 | `store/records.rs`, `ActivationRecord.manifest` | `store::journal` tests |
| OB-4 – OB-8, INV-023, SEC-015 | `telemetry/` | `telemetry` tests (T-OBS-04); `t_obs_01_t_obs_02_…`; `t_obs_03_every_standing_risk_measurement_moves_under_its_condition`; `t_exec_07_…` |
| VR-1, VR-3, VR-4, INV-021 | `api/mod.rs` (`PROTOCOL`, `FEATURES`), `pipeline.rs` | `t_ver_01_t_ver_02_…`; `t_api_02_…`. VR-4 for the client: `apps/cli` tests (T-VER-03) |
| VR-6, VR-7 | `check_compat`; `snapshot.list` reports `incompatible` per snapshot | `storage::snapshots::manifest` tests; `t_snap_02_…` |
| BK-1 – BK-5, INV-002, SEC-002 | `backend/mod.rs` | `t_back_01_nothing_above_the_backend_port_names_a_backend`; `t_back_03_an_undeclared_capability_is_refused_with_no_effect` |
| §26.5 replacement verification | `testing/conformance.rs`: fifteen rules of the port, against `dyn SandboxBackend` only | `t_back_02_the_test_backend_passes_the_backend_conformance_suite`, `t_back_02_a_backend_that_declares_less_still_conforms` (L2); `fc_backend_tests::t_back_02_the_firecracker_adapter_passes_the_backend_conformance_suite` (root). The L4 half of T-BACK-02 is in `tests/integration` |
| BK-6 | `FirecrackerBackend::new` declares snapshot, restore, guest execution, `none`, and `allowlist` where its tools are trusted | `shipped_files_tests`; `doctor` tests |
| PR-1 – PR-3, INV-034 | `config.rs` (`validate`, `mandatory_checks`), `HostInfo.parameters` | `config` tests; `shipped_files_tests` (L3); `t_op_03_…` |

---

## 3. Invariants (§27)

Every invariant maps to the tests the contract names for it; the table above places each of those tests. The
invariants whose named tests are all L4, and therefore not demonstrated here, are **INV-001** (T-SEC-02) and
**INV-030** (T-HOST-01). **INV-012** and **INV-013** name L4 tests too; their L1 and L2 analogues listed above were
run. **INV-034** names T-DOC-01, which is a lint of the contract document and is not part of this repository.

---

## 4. Where a clause had to be read one way

Each reading is the stricter one unless stated. They are recorded so that a reviewer can disagree with a
specific sentence rather than hunt for it in code.

1. **Reserved states are committed in BEGIN (OP-2, J-1, J-2).** An execution's BEGIN makes the generation
   `RUNNING`; a snapshot's makes it `PAUSED`, although the probe that becomes the restore oracle still runs while
   the vCPUs run; a destroy of a live generation makes it `STOPPING`. Otherwise the joint-state invariants would
   hold only at the end of an operation.
2. **What a containment BEGIN commits for what it supersedes (CC-3, J-4, J-7).** Besides the superseded
   operation's terminal record, an unfinished snapshot becomes `INVALID` and the generation a restore in place was
   building becomes `FAILED`, in the same commit.
3. **Quarantining a `RUNNING` or `PAUSED` generation records it `FAILED` (§12.1 against J-1, J-2, J-6).** The
   contract says a quarantined generation keeps its state, and also that `RUNNING` and `PAUSED` exist only under an
   operation in flight. With no operation left, the invariants win.
4. **An inherited `quarantine.release` on a generation that is `NOT_OWNED` ends `FAILED` (§16.2, first row).** It
   is re-driven only when the ownership marker is intact.
5. **A runtime under a `FAILED` generation is stopped like one under a `STOPPED` generation (§16.2 Part B).** The
   table lists `STOPPED` only. A containment that keeps failing is quarantined after `recovery_max_attempts`.
6. **The startup deadline does not quarantine a generation whose inherited operation this activation already
   resolved (RC-5).** It has been observed.
7. **`sandbox_destroy` and `snapshot_delete` in the profile bind role `caller` only (SP-3 against CC-4).** A
   profile that denies everything still permits containment.
8. **Shape checks run at decode (API-3).** Resource shape, aliases, generation ≥ 1, a non-zero lifetime and a
   non-empty argument vector are refused in the edge and again in the core, before role or state is looked at.
9. **The per-source connection cap counts per source (PA-2).** A source is an address on the network endpoint and
   a uid on the local one; two peers behind one source compete.
10. **IS-3 covers a sandbox that an operation holds (IS-3 with RC-6).** The operation watches the runtime it
    holds. The contract fixes only that the interval is finite; this implementation adds the relation
    `sweep_interval ≤ posture_recheck_interval / 4` as a mandatory check so that the interval is an upper bound.
    A start in flight is not watched: its launch verification and its deadline cover it.
11. **A control lost during an execution ends the operation `UNKNOWN` (§18.2, "no result could be obtained").** The
    generation records `SECURITY_CONTROL_FAILURE` as the reason its runtime was ended.
12. **A control lost during a snapshot ends the runtime; the guest is not resumed (SNP-5 against IS-3).** SNP-5 says
    the guest returns to its previous state whether the capture succeeds or fails. Resuming a runtime whose
    control is known to be lost would repair nothing and run it unprotected.
13. **TI-1 for executables allows a link at the leaf.** Distributions ship tools as links. The link must be in a
    trusted directory, and the file it resolves to and every directory on the way must satisfy the rule.
14. **AU-4 is enforced by the host on its own certificate.** The leaf must carry `host_id` as a subject
    alternative name, or the network endpoint is not opened.
15. **NW-2 is judged before the first vCPU instruction.** The host-side evidence (interface count, namespace,
    guest-traffic role) must hold before `InstanceStart` and before a restored guest is resumed. The guest's own
    report is collected afterwards and can only add a violation.
16. **Mode `allowlist` uses one constant guest segment (§20.2).** The contract leaves addressing open. A constant,
    unrouted /30 per namespace cannot collide and survives snapshot and restore.
17. **BK-6 against missing tools.** The backend declares `allowlist` only where `ip`, `nft` and `nsenter` are
    trusted executables. On a host without them a request for the mode is `UNSUPPORTED` and `doctor` warns; such a
    host does not meet BK-6.
18. **SC-6 resolves each recorded reference at restore admission and discards the material.** That is the only
    way to know that a reference "resolves for the restoring request".
19. **A request that names a known operation is resolved before the host mode, the rate limit for new work and the
    acceptance horizon are applied (§11.4, RY-7, API-8).** The idempotency table does not order its rows against
    §12.6. Read the other way, a caller whose response was lost while the host began to drain would be told
    `HOST_NOT_SERVING` about an operation that succeeded. A lookup is still bounded by the read rate limit, except
    for containment.
20. **The secret-bearing mark is written at BEGIN and taken back if nothing was delivered (SC-5 with SC-3).** Written
    only after a delivery, a crash in between would lose it. Kept after a failed resolution, one mistyped reference
    would make every later snapshot of the sandbox unrestorable.
21. **An execution that fails before it reaches the guest leaves the generation `COMPLETED` (§12.1).** BEGIN
    reserved `RUNNING`, and `RUNNING → READY` is not a transition. Both are idle states with the same admission.
22. **When the core does not answer, the edge gives no answer to a request that creates an operation (§10.4, FS-5).**
    `REFUSED` states that no operation record exists, which the edge cannot know. The caller sees a lost response
    and resolves the operation by its id. A read that got no answer is refused, because it created nothing.
23. **"Bounded growth" covers the store's file, not only its records (PS-10).** Retention removes records from the
    state; an append-only file keeps their bytes until it is rewritten. The host rewrites the file while it serves,
    so that a long-running host cannot grow a store its next start would refuse to open.
24. **The pinned identity of the VMM and of the jailer is a digest in the host configuration, verified by hashing
    the file (TI-2).** This reading is the weaker one in one respect, stated here. The contract asks that identity
    be verified on the bytes executed. The host hashes each binary from an open descriptor at startup, before it
    runs either even to ask its version, and again before every launch; it then executes the *path*. Between
    that hash and the `execve` the file is protected by TI-1 alone: the path is writable by the trusted owner
    only. Executing the hashed descriptor would close that window; it was not done because the jailer takes the
    VMM by path and copies it into the jail itself.
25. **A network mode word the host does not know is `UNSUPPORTED`, decided before the request is decoded any
    further (§20.1 against API-3).** §20.1 says any other value is refused with `UNSUPPORTED`; the schema lists two
    words, and a value outside a schema is otherwise `INVALID_REQUEST`. §20.1 is the specific rule: a caller
    written for a later contract learns that the mode is not offered here. A `mode` that is not a string is
    malformed.
26. **A feature is advertised only while the host offers it (VR-3 with §20.1).** `host.info` lists
    `allowlist_network` only if the backend supports the mode and the profile in force lists it, so the list
    follows a profile reload. `capabilities` stays the backend's own declaration (§26.3).
27. **A refusal never repeats what the request said (SC-1, and API-3).** A decode error names the kind of value
    found and what was expected, and where; never the value, the unknown field or the unknown variant. Raw
    secret material in a request is therefore not repeated by the answer that refuses it.
28. **An artifact that fails its digest during a restore makes the snapshot `INVALID` (SNP-3, §12.3).** The
    restore fails with `INTEGRITY_FAILURE` either way. The snapshot is invalidated only when its own files no
    longer match its manifest, which the host establishes by hashing them again; an integrity failure of
    anything else, or a guest that did not reproduce the baseline, leaves an intact snapshot `READY`.
29. **An operator may name a sandbox of other tags, if the name is unambiguous (§9.2 with ID-5).** A name is
    unique only within its tags. It is looked up in the requester's own tags first; an operator, who may read
    any record, then finds a sandbox of that name wherever it is the only one, and is told to use the id
    where several scopes use the name. Operation ids already followed this rule.

---

## 5. Not implemented, by the contract's own deferral or by declared capability

| Item | State |
|---|---|
| Signed decisions (AU-11 – AU-13) | the field is reserved and refused; the feature is not advertised |
| Incremental output (OU-5) | not advertised; output is available when the execution ends |
| Secret delivery to a guest (SC-2) | the port, the provider and the bookkeeping exist; the Firecracker backend declares `secret_injection: false`, so a request that needs delivery is `UNSUPPORTED` |
| Guest entropy reseeding (RE-7) | reported as not proven (`restore_reseeds_entropy: false`); the restore result carries a note when a snapshot is restored more than once |
| Snapshot export, portability, image distribution, file transfer, shares between scopes, network byte budgets | out of scope by §39; no code |

---

## 6. Known nonconformance and unverified areas

* **Everything at L4 and L5.** No microVM has been booted from this code. The isolation claims, kernel enforcement
  of limits, the lifetime enforcer against a real runtime, the allowlist through a real guest, and the restore
  oracle on a real snapshot are implemented and tested against doubles only.
* **The Firecracker backend's orchestration tests need root** (they create namespaces and give files to other
  users). They are marked ignored and were not run in the environment this was written in.
* **T-ENTRY-01** (the entry conditions of §4.1 on a real host and a real supply chain) is not met: the guest
  kernel and base-image pins are still `UNSET`.
* **T-DOC-01** is a lint of the contract document itself and has no counterpart here.
* **The number of retained records has no ceiling of its own.** The contract bounds it by
  `operation_rate_limit` × `operation_retention` per peer (PS-10), and so does the host. With the default
  parameters that product is large, and the whole state is held in memory: an enrolled peer that uses its full
  rate for a full retention period makes the core hold every one of those records. Size the two parameters for
  the machine.
