# Verification status — the developer platform

What was run, on what, and with which result; and what was not run. Written on 2026-11-20, from the output
of the commands named below. A mark in a table is not verification: every row here names the command
that produced it, and section 6 names what no command in this repository can produce.

The execution plane has a page of its own, [`docs/VERIFICATION_STATUS.md`](../VERIFICATION_STATUS.md).

## 1. Summary

| What | Command | Result |
|---|---|---|
| The contract files are what the code generates | `make platform-drift` | up to date |
| The contract files against the last release | `make platform-compat` | no release exists yet: the target says so and compares nothing. The comparison itself is tested (166 tests) |
| Lint, format and types, four Python projects | `make platform-lint` | no finding (`ruff` 0.17.6, `ruff format`, strict `mypy` 2.4.1) |
| `apps/api` | `uv run --locked pytest` | 2,806 tests, all passing: 2,762 without a host and 44 against the host's in-memory build |
| `apps/api` against the host's in-memory build | `make platform-e2e` | 44 passed |
| `apps/mcp-gateway` | `uv run --locked pytest` | 342 passed |
| `sdks/python` | `uv run --locked pytest` | 1,753 passed on each of Python 3.12, 3.13 and 3.14 |
| `apps/cli` | `uv run --locked pytest` | 816 passed on each of Python 3.12, 3.13 and 3.14 |
| `sdks/typescript` | `npm ci && npm run typecheck && npm test && npm run build` | 781 passed on each of Node.js 22, 24 and 26, each from a clean copy with a locked install |
| Repository tests of the Makefile, the workflows and the scripts | `uv run --locked pytest tests/scripts tests/tools` | 937 passed; 96 skipped, which need root or a machine set up for the execution plane |
| The units | `make platform-units` (`systemd-analyze verify`, systemd 257) | accepted without a remark |
| The platform's three shell scripts | ShellCheck at `--severity=style` | no finding |
| The packages | `make platform-dist` | nine files built (a wheel and a source archive for each of the four Python packages, a tarball for the TypeScript SDK), installed into an empty environment and imported |
| The deployment | `make platform-deploy-test` | 75 checks, all passing, on a fresh machine |
| The developer journey, live | the three programs of `scripts/platform-journey/` against that deployment (section 4.8) | Python SDK 28 of 28 checks; TypeScript SDK 25 of 25 on each of three Node.js lines; `acf` 44 of 44 |
| The whole gate | `make platform-ci` | passed (exit status 0) on a clean copy of the tree, as an unprivileged user, in one container with `make`, `uv`, Node.js 24 and systemd 257 |

## 2. Where it ran

Everything ran in Linux containers on one x86-64 machine. Nothing ran on a hosted runner.

| Used for | Environment |
|---|---|
| The Python projects, the repository tests, `make` | Debian with Python 3.12.16 and `uv` 0.13.9; the lock of each project fixes everything else |
| The other Python versions | interpreters 3.13.18 and 3.14.10, installed by `uv`, same locks |
| The TypeScript SDK | the official Node.js images: 22.23.5, 24.22.3 and 26.13.1; and Node.js 24 on Windows |
| The deployment test, the units, the live journeys | Debian 13 with systemd 257 as the init process and Python 3.13.5, three service accounts, the shipped units |
| The host | the in-memory test build of the execution plane's host agent (`acf-host-fake`), built from this repository. It speaks `acf.host/2` over mutual TLS, keeps its journal, enforces its admission and lifecycle rules, and boots no microVM |

## 3. Kinds of evidence

The contract grades evidence in levels. What stands behind each here:

| Level | Meaning | Here |
|---|---|---|
| L0 | static: the files themselves | lints, the generated files, the import boundary, the catalogue's account |
| L1 | one unit | `test_unit_*.py`, the unit suites of the SDKs and the CLI |
| L2 | the whole process, with the host replaced | the core with a real store and journal on disk, against a model of the host inside the test (faults at every point) or against the host's in-memory build over mutual TLS |
| L3 | the deployed system | the deployment test: installed units, three accounts, the running processes inspected |
| L4 | a real host | **not run** |
| L5 | published packages | **not run** |

The model of the host is held to the truth in two ways: its lifecycle and admission rules were taken
from the host's source, and the same core is run against the host's own in-memory build, where every
answer is decoded and mapped by the real binding.

## 4. The suites

### 4.1 `apps/api`

2,806 tests, all passing.

| Kind | Files | Tests | Run against |
|---|---|---:|---|
| Units | `test_unit_*.py` (16 files) | 1,889 | nothing: pure functions, formats, the store and the journal on disk |
| The contract files and the account of the catalogue | `test_contract_*.py` | 215 | the generated files; the import graph |
| The pipeline, the ledger, recovery, credentials, the agent interface | `test_idempotency.py`, `test_recovery_faults.py`, `test_pipeline_scope.py`, `test_pipeline_guarantees.py`, `test_containment_limits.py`, `test_auth_credentials.py`, `test_agent_interface.py`, `test_standing_audit_projects.py`, `test_smoke.py` | 225 | the whole core with a real store and journal, and a model of the host with a fault at every point |
| The REST adapter, the command socket, the start of the core | `test_edge_http.py`, `test_edge_lost_answer.py`, `test_command_socket.py`, `test_core_startup.py` | 394 | real sockets and real processes |
| The binding and the whole chain | `test_host_binding.py`, `test_e2e_host.py` (marker `host`) | 44 | the host's in-memory build, over mutual TLS |
| The shipped units, tables and examples | `test_deployment_files.py` | 39 | the files themselves; `systemd-analyze` and `systemd-sysusers` where installed |

Two tests of the last row need `systemd-analyze` and `systemd-sysusers`. Where those are not installed
the two are skipped; in the environment of `make platform-ci` they ran and passed. The 44 tests of the
host are skipped by `make platform-test`, which builds no host, and run by `make platform-e2e`, which
sets `ACF_REQUIRE_HOST=1`: a test that needs the host then fails instead of skipping.

### 4.2 `apps/mcp-gateway`

342 passed. The adapter against a scripted core: headers and revisions, `Origin` and `Host`, the
two HTTP answers, rendering of every kind of result, the relay of delivery, the metadata of the
protected resource.

### 4.3 `sdks/python`

| Python | Result |
|---|---|
| 3.12.16 | 1,753 passed |
| 3.13.18 | 1,753 passed |
| 3.14.10 | 1,753 passed |

A scripted transport and virtual time; no test opens a socket. The 27 conformance scenarios run through
the synchronous and the asynchronous client.

### 4.4 `sdks/typescript`

| Node.js | npm | Type-check | Tests | Build |
|---|---|---|---|---|
| 22.23.5 | 10.9.9 | no finding | 781 passed | 36 files |
| 24.22.3 | 11.19.1 | no finding | 781 passed | 36 files |
| 26.13.1 | 11.20.0 | no finding | 781 passed | 36 files |

Each from a clean copy: locked install, type-check, tests, build. A guard compares the SDK's views with
the generated tool definitions, so a member added to the public model and forgotten here fails a build.

### 4.5 `apps/cli`

816 passed on each of Python 3.12, 3.13 and 3.14. Every command is driven from the generated table of operations; the conformance
scenarios run through the commands in both output modes; `acf mcp` is also run as a real process, for
its behaviour under signals and a reader that goes away.

### 4.6 Repository tests

937 passed; 96 skipped, which need root or a machine set up for the execution plane. They hold the Makefile, the workflows, the installer and the deployment test to each
other: every job runs a `make` target, the platform's gate and the execution plane's do not reach into
each other, only the two publishing jobs may ask for an identity token, the deployment test never
consents for its caller.

### 4.7 The deployment test

`scripts/platform-deploy-test.sh`, 75 checks, all passing, on a fresh machine, on a machine it may change:

* the installer builds both environments from their locks, and the core's environment holds no
  agent-protocol library;
* the shipped example does not load until its deployment id is replaced; `init`; the separation holds;
* the host's own enrolment table is linted: the platform is in it once, as a caller; a table that makes
  it an operator, and one that knows an edge's certificate, are refused;
* the three units start and report ready; the developer journey over REST (create, replay, conflict,
  start, execute, output, a stale generation, another project, stop, destroy);
* the agent interface (catalogue, a tool call, a minted key, a developer key refused, 401, 403, the
  protocol's own error for another revision, POST only);
* the running processes: no capability, a system-call filter, three accounts, no network listener in
  the core; no edge account reads a secret, the store, the journal, the other edge's key or the admin
  socket; a stranger and the core's own account are not admitted to the command socket;
* restarts: the answer while the core is down, a key from before the restart, a new writer epoch, a
  refused start is not retried.

### 4.8 The developer journey, live over TLS

The three programs of `scripts/platform-journey/`, each against the deployment of 4.7, each with a key
that an operator command issued for an empty project, over TLS with the deployment's own certificates
named as the only authorities:

| Program | Result |
|---|---|
| `python_sdk.py`, Python 3.12.16, authority named with `ACF_CA_FILE` | 28 of 28 checks |
| `typescript_sdk.mjs`, Node.js 22.23.5, authority named with `NODE_EXTRA_CA_CERTS` | 25 of 25 checks |
| `typescript_sdk.mjs`, Node.js 24.22.3 | 25 of 25 checks |
| `typescript_sdk.mjs`, Node.js 26.13.1 | 25 of 25 checks |
| `cli.sh`: `acf` installed from the checkout, authority named with `acf auth login --ca-file`, the relay with `ACF_MCP_URL` | 44 of 44 checks |

`acf` was installed from the checkout into an empty environment and run as a real process. Its journey
also proves the negative: without the authority's certificate nothing is believed, and a general
certificate variable of the environment changes nothing.

### 4.9 Other Python versions

The same locks on the other interpreters the packages declare, each run in an environment of its own:

| Project | Python 3.12.16 | Python 3.13.18 | Python 3.14.10 |
|---|---|---|---|
| `apps/api` | 2,804 passed, 2 skipped | 2,804 passed, 2 skipped | 2,804 passed, 2 skipped |
| `apps/mcp-gateway` | 342 passed | 342 passed | 342 passed |
| `sdks/python` | 1,753 passed | 1,753 passed | 1,753 passed |
| `apps/cli` | 816 passed | 816 passed | 816 passed |

The two skipped tests need `systemd-analyze` and `systemd-sysusers`, which those environments do not
have; they pass in the environment of `make platform-ci`, which has them.

## 5. The contract's test catalogue

The contract lists 135 test entries, each with the levels at which it means something.
`apps/api/tests/test_contract_gates.py` holds the list and fails when an entry is neither named by a
test of that package nor carries a reason. The table below is printed from that file:
135 entries, which stand for 161 pairs of an entry and a level. 121 pairs are proven by named tests of
`apps/api` (511 of its tests name an entry). 19 belong to another package, 14 need a real host or a real
deployment, 4 need published packages, 2 need a surface that is off by default, and one entry was not
adopted by the contract. None is missing.

| Entry | Gate | Level | Where it is proven |
|---|---|---|---|
| T3-API-01 | P0 | L0 | 62 tests in `test_contract_artifacts.py`, `test_unit_errors.py`, `test_unit_mapping.py` |
| T3-API-02 | P1 | L2 | 24 tests in `test_edge_http.py` |
| T3-API-03 | P0 | L2 | 5 tests in `test_e2e_host.py`, `test_edge_http.py`, `test_standing_audit_projects.py` |
| T3-SVC-01 | P0 | L1 | 2 tests in `test_pipeline_scope.py` |
| T3-SVC-01 | P0 | L2 | 2 tests in `test_pipeline_scope.py` |
| T3-SVC-02 | P0 | L2 | 1 test in `test_pipeline_scope.py` |
| T3-SVC-03 | P0 | L2 | 2 tests in `test_e2e_host.py`, `test_pipeline_scope.py` |
| T3-SEC-01 | P0 | L1 | 1 test in `test_pipeline_scope.py` |
| T3-SEC-01 | P0 | L2 | 1 test in `test_pipeline_scope.py` |
| T3-SEC-02 | P0 | L2 | 2 tests in `test_host_binding.py` |
| T3-SEC-03 | P0 | L2 | 1 test in `test_auth_credentials.py` |
| T3-SEC-04 | P0 | L2 | 8 tests in `test_edge_http.py` |
| T3-SEC-05 | P0 | L2 | 3 tests in `test_edge_http.py` |
| T3-SEC-05 | P0 | L4 | not here: needs a real host or a real deployment. level L4 |
| T3-SEC-06 | P0 | L0 | 3 tests in `test_contract_artifacts.py`, `test_host_binding.py`, `test_unit_mapping.py` |
| T3-SEC-06 | P0 | L2 | 1 test in `test_host_binding.py` |
| T3-SEC-07 | P0 | L2 | 1 test in `test_agent_interface.py` |
| T3-SEC-08 | P0 | L2 | not here: belongs to another package. the check of `Origin` and the loopback binding are the agent-protocol adapter's |
| T3-SEC-09 | P0 | L2 | 6 tests in `test_core_startup.py` |
| T3-SEC-10 | P0 | L2 | 1 test in `test_auth_credentials.py` |
| T3-SEC-11 | P0 | L2 | 2 tests in `test_containment_limits.py` |
| T3-SEC-12 | P0 | L2 | 3 tests in `test_e2e_host.py`, `test_pipeline_scope.py` |
| T3-AUTH-01 | P0 | L1 | 21 tests in `test_unit_keys.py`, `test_unit_store.py` |
| T3-AUTH-02 | P0 | L2 | 1 test in `test_auth_credentials.py` |
| T3-AUTH-03 | P0 | L2 | 1 test in `test_auth_credentials.py` |
| T3-AUTH-04 | P0 | L2 | 1 test in `test_auth_credentials.py` |
| T3-AZ-01 | P0 | L1 | 22 tests in `test_unit_grants.py` |
| T3-AZ-02 | P0 | L1 | 12 tests in `test_pipeline_scope.py`, `test_unit_grants.py` |
| T3-AZ-02 | P0 | L2 | 1 test in `test_pipeline_scope.py` |
| T3-AZ-03 | P0 | L2 | 2 tests in `test_auth_credentials.py` |
| T3-IDM-01 | P0 | L1 | 14 tests in `test_unit_derivation.py` |
| T3-IDM-02 | P0 | L2 | 2 tests in `test_edge_http.py`, `test_idempotency.py` |
| T3-IDM-03 | P0 | L2 | 1 test in `test_idempotency.py` |
| T3-IDM-04 | P0 | L2 | 1 test in `test_idempotency.py` |
| T3-IDM-05 | P0 | L2 | 1 test in `test_idempotency.py` |
| T3-IDM-06 | P0 | L2 | 3 tests in `test_agent_interface.py`, `test_edge_http.py`, `test_idempotency.py` |
| T3-REC-01 | P0 | L2 | 1 test in `test_recovery_faults.py` |
| T3-REC-02 | P0 | L2 | 2 tests in `test_recovery_faults.py` |
| T3-REC-03 | P0 | L2 | 1 test in `test_recovery_faults.py` |
| T3-REC-04 | P0 | L2 | 1 test in `test_recovery_faults.py` |
| T3-ERR-01 | P0 | L1 | 26 tests in `test_contract_artifacts.py`, `test_unit_errors.py`, `test_unit_mapping.py` |
| T3-ERR-02 | P0 | L2 | 1 test in `test_recovery_faults.py` |
| T3-LRO-01 | P1 | L2 | 9 tests in `test_containment_limits.py`, `test_edge_http.py` |
| T3-LRO-02 | P0 | L2 | 1 test in `test_pipeline_guarantees.py` |
| T3-LRO-02 | P0 | L4 | not here: needs a real host or a real deployment. level L4 |
| T3-LRO-03 | P0 | L2 | 1 test in `test_containment_limits.py` |
| T3-LRO-03 | P0 | L4 | not here: needs a real host or a real deployment. level L4 |
| T3-LRO-04 | P0 | L2 | 1 test in `test_pipeline_guarantees.py` |
| T3-LRO-05 | P1 | L2 | 2 tests in `test_containment_limits.py` |
| T3-MCP-01 | P1 | L2 | not here: belongs to another package. conformance to the agent protocol is the adapter's, in the agent-protocol gateway |
| T3-MCP-02 | P1 | L2 | 2 tests in `test_agent_interface.py` |
| T3-MCP-03 | P0 | L2 | 1 test in `test_pipeline_guarantees.py` |
| T3-MCP-04 | P0 | L2 | 1 test in `test_agent_interface.py` |
| T3-MCP-05 | P1 | L2 | 2 tests in `test_agent_interface.py` |
| T3-MCP-06 | P2 | L2 | not here: needs a surface that is off by default. the tasks extension and the previous revision of the agent protocol; a deployment that turns one on runs this test |
| T3-MCP-07 | P1 | L4 | not here: needs a real host or a real deployment. level L4 |
| T3-HB-01 | P1 | L2 | 5 tests in `test_host_binding.py`, `test_recovery_faults.py` |
| T3-HB-02 | P1 | L2 | 5 tests in `test_host_binding.py`, `test_standing_audit_projects.py` |
| T3-HB-02 | P1 | L4 | not here: needs a real host or a real deployment. level L4 |
| T3-HB-03 | P1 | L2 | 1 test in `test_standing_audit_projects.py` |
| T3-IPS-01 | P1 | L2 | 2 tests in `test_pipeline_guarantees.py`, `test_recovery_faults.py` |
| T3-IPS-02 | P1 | L2 | 1 test in `test_unit_store.py` |
| T3-IPS-03 | P0 | L0 | 2 tests in `test_standing_audit_projects.py`, `test_unit_store.py` |
| T3-IPS-03 | P0 | L2 | 1 test in `test_standing_audit_projects.py` |
| T3-SDK-01 | P0 | L2 | not here: belongs to another package. the behaviour of the two SDKs is proven in the SDK packages |
| T3-SDK-02 | P1 | L2 | not here: belongs to another package. the behaviour of the two SDKs is proven in the SDK packages |
| T3-SDK-03 | P1 | L2 | not here: belongs to another package. the behaviour of the two SDKs is proven in the SDK packages |
| T3-SDK-04 | P1 | L1 | not here: belongs to another package. the behaviour of the two SDKs is proven in the SDK packages |
| T3-SDK-05 | P0 | L2 | not here: belongs to another package. the behaviour of the two SDKs is proven in the SDK packages |
| T3-SDK-06 | P0 | L2 | not here: belongs to another package. the behaviour of the two SDKs is proven in the SDK packages |
| T3-CLI-01 | P0 | L2 | not here: belongs to another package. the command-line client is a package of its own |
| T3-CLI-02 | P1 | L2 | not here: belongs to another package. exit codes are the command-line client's |
| T3-CP-01 | P0 | L2 | not here: belongs to another package. the conformance suite is generated here and run by each client; that its answers are answers of the public model is proven here |
| T3-OBS-01 | P0 | L2 | 1 test in `test_standing_audit_projects.py` |
| T3-OBS-02 | P0 | L2 | 1 test in `test_standing_audit_projects.py` |
| T3-OBS-03 | P1 | L2 | 3 tests in `test_host_binding.py`, `test_standing_audit_projects.py` |
| T3-OBS-04 | P1 | L2 | 1 test in `test_standing_audit_projects.py` |
| T3-VER-01 | P1 | L0 | 21 tests in `test_unit_compat.py` |
| T3-VER-02 | P1 | L2 | 5 tests in `test_edge_http.py` |
| T3-VER-03 | P1 | L2 | 4 tests in `test_command_socket.py`, `test_pipeline_guarantees.py` |
| T3-EC-01 | P0 | L0 | 14 tests in `test_contract_imports.py`, `test_core_startup.py` |
| T3-EC-01 | P0 | L3 | 4 tests in `test_core_startup.py` |
| T3-EC-02 | P0 | L2 | 10 tests in `test_command_socket.py`, `test_edge_lost_answer.py` |
| T3-EC-03 | P0 | L2 | 6 tests in `test_command_socket.py` |
| T3-PRJ-01 | P1 | L2 | 1 test in `test_standing_audit_projects.py` |
| T3-CRD-01 | P1 | L1 | 17 tests in `test_auth_credentials.py`, `test_unit_grants.py`, `test_unit_store.py` |
| T3-CRD-01 | P1 | L2 | 5 tests in `test_auth_credentials.py` |
| T3-CRD-02 | P0 | L2 | 1 test in `test_auth_credentials.py` |
| T3-CRD-02 | P0 | L4 | not here: needs a real host or a real deployment. level L4 |
| T3-REL-01 | P0 | L5 | not here: needs published packages. level L5 |
| T3-REL-02 | P1 | L5 | not here: needs published packages. level L5 |
| T3-CONC-01 | P0 | L2 | 1 test in `test_pipeline_guarantees.py` |
| T3-PARAM-01 | P0 | L1 | 33 tests in `test_unit_parameters.py` |
| T3-PARAM-01 | P0 | L3 | 1 test in `test_unit_parameters.py` |
| T3-SCOPE-01 | P0 | L0 | 1 test in `test_e2e_host.py` |
| T3-SCOPE-01 | P0 | L2 | 2 tests in `test_e2e_host.py` |
| T3-DX-01 | P0+P1 | L4 | not here: needs a real host or a real deployment. level L4 |
| T3-DX-01 | P0+P1 | L5 | not here: needs published packages. level L5 |
| T3-DX-02 | P1 | L4 | not here: needs a real host or a real deployment. level L4 |
| T3-RED-01 | P0 | L2 | 2 tests in `test_standing_audit_projects.py` |
| T3-RED-02 | P0 | L1 | 4 tests in `test_unit_keys.py` |
| T3-RED-03 | P0 | L2 | 9 tests in `test_host_binding.py`, `test_standing_audit_projects.py` |
| T3-RED-04 | P0 | L2 | 3 tests in `test_auth_credentials.py` |
| T3-RED-05 | P2 | L2 | not here: needs a surface that is off by default. sessions exist only in the previous revision of the agent protocol |
| T3-RED-06 | P0 | L3 | not here: needs a real host or a real deployment. the running system: the installed units under their own accounts |
| T3-RED-06 | P0 | L4 | not here: needs a real host or a real deployment. level L4 |
| T3-RED-07 | P1 | L2 | not here: belongs to another package. resolving a name once and refusing a rebound one is done by the SDK and the command-line client |
| T3-RED-08 | P0 | L2 | 3 tests in `test_edge_http.py`, `test_pipeline_scope.py` |
| T3-RED-09 | P0 | L2 | 2 tests in `test_command_socket.py` |
| T3-RED-10 | P0 | L1 | 19 tests in `test_auth_credentials.py`, `test_unit_authorizer_intent.py` |
| T3-RED-10 | P0 | L2 | 3 tests in `test_auth_credentials.py` |
| T3-RED-11 | P1 | L1 | 33 tests in `test_unit_destinations.py` |
| T3-RED-12 | - | - | not adopted by the contract: there is no rule to test |
| T3-RED-13 | P1 | L1 | 10 tests in `test_agent_interface.py`, `test_unit_grants.py` |
| T3-RED-13 | P1 | L2 | 1 test in `test_agent_interface.py` |
| T3-RED-14 | P2 | L0 | 2 tests in `test_auth_credentials.py` |
| T3-RED-14 | P2 | L2 | 2 tests in `test_auth_credentials.py` |
| T3-RED-15 | P0 | L2 | 3 tests in `test_agent_interface.py` |
| T3-RED-16 | P0 | L2 | 1 test in `test_agent_interface.py` |
| T3-RED-17 | P0 | L2 | 1 test in `test_idempotency.py` |
| T3-RED-18 | P0 | L2 | 1 test in `test_idempotency.py` |
| T3-RED-19 | P0 | L2 | 1 test in `test_recovery_faults.py` |
| T3-RED-20 | P0 | L2 | 1 test in `test_idempotency.py` |
| T3-RED-21 | P0 | L2 | 1 test in `test_idempotency.py` |
| T3-RED-22 | P0 | L1 | 5 tests in `test_pipeline_guarantees.py`, `test_unit_derivation.py` |
| T3-RED-22 | P0 | L2 | 1 test in `test_pipeline_guarantees.py` |
| T3-RED-23 | P0 | L2 | 1 test in `test_pipeline_guarantees.py` |
| T3-RED-24 | P0 | L2 | 2 tests in `test_standing_audit_projects.py` |
| T3-RED-25 | P0 | L2 | 1 test in `test_standing_audit_projects.py` |
| T3-RED-26 | P0 | L2 | 1 test in `test_recovery_faults.py` |
| T3-RED-27 | P0 | L2 | not here: belongs to another package. a create that takes a minute is driven to a started sandbox by each client; no client is in this package |
| T3-RED-27 | P0 | L4 | not here: needs a real host or a real deployment. level L4 |
| T3-RED-28 | P0 | L2 | not here: belongs to another package. what a create leaves behind when the start fails is the SDK's policy |
| T3-RED-29 | P1 | L2 | not here: belongs to another package. a handle that must be refreshed is the SDK's |
| T3-RED-30 | P1 | L2 | not here: belongs to another package. closing a stream and cancelling over stdio are the adapter's and the relay's |
| T3-RED-31 | P0 | L2 | 2 tests in `test_containment_limits.py` |
| T3-RED-31 | P0 | L4 | not here: needs a real host or a real deployment. level L4 |
| T3-RED-32 | P0 | L2 | 1 test in `test_recovery_faults.py` |
| T3-RED-33 | P0 | L2 | 1 test in `test_recovery_faults.py` |
| T3-RED-34 | P1 | L2 | 1 test in `test_pipeline_guarantees.py` |
| T3-RED-35 | P0 | L2 | 1 test in `test_host_binding.py` |
| T3-RED-35 | P0 | L4 | not here: needs a real host or a real deployment. level L4 |
| T3-RED-36 | P0 | L2 | 3 tests in `test_containment_limits.py` |
| T3-RED-37 | P0 | L2 | 3 tests in `test_containment_limits.py` |
| T3-RED-38 | P0 | L0 | 4 tests in `test_command_socket.py`, `test_unit_parameters.py` |
| T3-RED-38 | P0 | L2 | 1 test in `test_command_socket.py` |
| T3-RED-39 | P0 | L2 | 1 test in `test_agent_interface.py` |
| T3-RED-40 | P1 | L0 | 8 tests in `test_contract_artifacts.py` |
| T3-RED-41 | P1 | L4 | not here: needs a real host or a real deployment. level L4 |
| T3-RED-42 | P0 | L2 | 1 test in `test_auth_credentials.py` |
| T3-RED-43 | P1 | L2 | 3 tests in `test_host_binding.py`, `test_standing_audit_projects.py` |
| T3-RED-44 | P1 | L2 | not here: belongs to another package. following an operation in a state the client does not know is the SDK's |
| T3-RED-45 | P1 | L0 | 19 tests in `test_pipeline_guarantees.py`, `test_unit_enrolment.py` |
| T3-RED-45 | P1 | L2 | 1 test in `test_pipeline_guarantees.py` |
| T3-RED-46 | P0 | L2 | 1 test in `test_standing_audit_projects.py` |
| T3-RED-47 | P0 | L0 | not here: belongs to another package. a lint of every name in the documents and the examples, over the whole repository |
| T3-RED-48 | P1 | L0 | not here: belongs to another package. the advisory check of the dependencies runs in the release pipeline |
| T3-RED-48 | P1 | L5 | not here: needs published packages. level L5 |
| T3-RED-49 | P0 | L0 | 9 tests in `test_contract_gates.py` |
| T3-RED-50 | P1 | L2 | 1 test in `test_standing_audit_projects.py` |
| T3-RED-51 | P0 | L2 | 2 tests in `test_standing_audit_projects.py` |

Gate classes are the contract's: P0 blocks acceptance, P1 blocks the release of the component it
covers, P2 is hardening or a surface that is off by default. "Not here" is a statement about where the
proof has to be made, not a claim that it was made there; sections 4.3 to 4.5 say what the client
packages prove, and section 6 says what nothing proves yet.

## 6. Not run, and why

| What | Why | What it would take |
|---|---|---|
| Anything against a real host with KVM (level L4) | no such host was available to this work | a KVM machine with the execution plane installed and the platform deployed against it as [OPERATIONS.md](OPERATIONS.md) describes; the journeys of 4.8 are then the test. No `make` target does this: `platform-e2e` and the deployment test always start the in-memory build |
| The workflows on a hosted runner | nothing was pushed | a push; the jobs run the `make` targets of section 1 |
| The release workflow, a published package, provenance checks, the journey from published packages (level L5) | the five names and the npm scope are not registered, and only an owner can configure a trusted publisher | [RELEASING.md](RELEASING.md), section 3 |
| `make platform-audit` as part of this record | it reads advisory databases over the network and its answer changes by the day | run it before a release; the release workflow does |
| An external authorization server | none was set up | a test deployment with one; the verification itself is tested against keys made in the tests |
| macOS and Windows for the Python SDK and the CLI | the tests ran on Linux | the suites cover both branches of every platform-specific path by telling the code which system it is on |
| Load | not attempted | a load test against a real host; every bound is a parameter |

## 7. What verification found

Defects that the tests, the deployment test or a live run found during this work, and that were fixed.
They are listed because each one says something about where this code can be wrong.

| Found by | Defect | Fix |
|---|---|---|
| the deployment test | an environment was handed an older build of a package of this checkout, because the build cache watched only `pyproject.toml` | sources are part of the cache key, and the installer reinstalls (ADR-121) |
| a test that failed one run in many | the follower of an operation forgot its pace when its last waiter left, so a stream of waiters could read the host without bound, and joiners were not charged | the pace outlives the waiters; a wait that starts polling is charged as a read |
| writing the adapter | the challenge of an unauthenticated tool call was dropped by the core | a refusal that carries a challenge is answered as the HTTP answer it is |
| mapping the test catalogue | the access decision had no deadline | bounded by the request's own; a slow or failing decision refuses new work and never containment |
| comparing with the host's source | the model of the host started sandboxes on create | the model follows the host's lifecycle |
| reading the host's source | a quota was a share of the host's identifier pool (4,096) and not of what it admits (16); with no number it was not enforced | the envelope is a parameter; a quota is always a number (ADR-125) |
| a review of the unit tests | a journal cut at a line boundary was accepted | the store refuses a journal that ends before what it applied (ADR-126) |
| the same review | a configuration value of the wrong type was converted | both schemas read exactly (ADR-129) |
| a review of the edge | the development switch for a shared account waived every separation finding | it waives the shared account only |
| the same review | a host that advertised one-step create would have been promised it and sent a create alone | never offered (ADR-130) |
| a real process under signals | the stdio relay aborted when stopped while its input was open, and gave the wrong status when its reader went away | exits 143, 130 or 141 |
| the live run of the CLI | no client could reach a platform certified by a private authority | `ca_file`, `ACF_CA_FILE`, `acf auth login --ca-file` |
| a review of the CLI | cancelling an execution read it first, so a read limit could delay a cancel; an address with a line break passed the SDK's check | a handle without a read; such an address is refused |
| the type checker, once the tests were held to it | the answer to the agent protocol's discovery raised in the core: a method had lost a parameter and one caller still passed it. No test reached that call | fixed; a test of the core reaches it, and the deployment test asks for discovery over TLS |
| the linter, asked why it skipped four files | the package that generates the contract files was in a directory named like the repository's ignored planning material, so git would never have committed it and the bundler would have left it out | the package is `acf_api.contract`; no file of the platform is ignored |
| reading the code during the clean-up | the core's retry budget remembered every request for as long as the host stayed reachable | what is older than the window is forgotten on every request |
| the same reading | a revocation that had taken effect could be answered as an internal error if the registry failed to be read again | the answer is the revoked credential, whatever fails after the revocation |
| running the whole gate in one tree, as an owner would | two tests depended on what else was in the checkout: one verified the units with whatever file modes the checkout carried, and one read every file in the CLI's directory, including the cache the type checker had just written there | the units are staged with the installer's mode; the test reads the package's own files, and a test holds that |
| the same reading | the test of two derivation versions passed without deriving anything under a second version, and the rule it was named for was not implemented | an earlier version's id is read on the host before a first submission; the test forgets the ledger entry and proves that nothing is sent again |

## 8. Running it again

```bash
make platform-check                                   # no host needed
make fake-host && make platform-e2e                   # needs a Rust toolchain
make platform-dist
sudo ACF_DEPLOY_TEST=1 make platform-deploy-test      # a machine you throw away: root, systemd, uv, a Python 3.12+
```

`platform-deploy-test` leaves a running deployment behind, which is what the journeys of 4.8 use:
`scripts/platform-journey/README.md` says how to run them against it, or against any other platform.
The catalogue table of section 5 is the output of `apps/api/tests/test_contract_gates.py`'s own
functions; the file's docstring says how a test names what it proves.
