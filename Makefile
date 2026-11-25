# Agent Compute Fabric: one entry point for every check, build and package step.
#
#   make help            what each target does
#   make check           the execution plane: everything that runs anywhere (no KVM, no network, no root needed)
#   make release         the production `acf-host`, proven free of test-only code
#   make integration     KVM hosts only: boots real microVMs (see docs/OPERATIONS.md)
#   make platform-check  the developer platform: API, agent-protocol adapter, SDKs, CLI, contract files
#
# CI runs these same targets (.github/workflows/ci.yml), so "it passed on my machine" and "it passed in CI"
# mean the same thing. Anything that is not a target here is not part of the gate.

SHELL          := bash
.SHELLFLAGS    := -euo pipefail -c
.DEFAULT_GOAL  := help
.DELETE_ON_ERROR:

CARGO          ?= cargo
UV             ?= uv
PYTHON         ?= python3

# Where cargo puts its output (honours CARGO_TARGET_DIR so `make` and `cargo` always agree).
TARGET_DIR     := $(if $(CARGO_TARGET_DIR),$(CARGO_TARGET_DIR),target)
HOST_RELEASE   := $(TARGET_DIR)/release/acf-host
HOST_FAKE      := $(TARGET_DIR)/debug/acf-host-fake

# The guest agent is built static (musl) so it runs in an image that has no matching libc.
# The default follows the machine you build on: x86_64 or aarch64.
GUEST_ARCH     ?= $(shell uname -m)
MUSL_TARGET    ?= $(GUEST_ARCH)-unknown-linux-musl
GUEST_AGENT    := $(TARGET_DIR)/$(MUSL_TARGET)/release/acf-guest-agent

# `uv run` for the repository tooling (root project) and for the client project (apps/host-cli).
# Both are locked: a dependency that is not in uv.lock cannot sneak into a check.
UV_RUN         ?= $(UV) run --locked
CLI_RUN        ?= $(UV) --directory apps/host-cli run --locked

# A Unix socket path is limited to 107 bytes; a deep $TMPDIR breaks tests that put a socket there.
SHORT_TMPDIR   ?= /tmp

# Everything `acf-host schema` writes, and where: both directories are checked in.
CONTRACTS_DIR  := execution/contracts
SCHEMA_DIR     := schemas
SCHEMA_CMD     := $(CARGO) run -q --locked -p acf-host-agent --bin acf-host -- schema

UNITS          := $(notdir $(wildcard deploy/systemd/*.service))

DIST_DIR       := dist
DIST_NAME      := agent-compute-fabric-execution-plane

# ------------------------------------------------------------------------------------------------
.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "; printf "Usage: make <target>\n\n"} \
	     /^[a-zA-Z0-9_.-]+:.*## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ---- Rust: the whole workspace (wire, traffic, host-agent, guest-agent) -------------------------
.PHONY: rust-fmt rust-lint rust-test net-plumbing-test root-test
rust-fmt: ## rustfmt over the workspace, check only
	$(CARGO) fmt --all -- --check

rust-lint: ## clippy over every crate, target and feature; warnings are errors
	$(CARGO) clippy --workspace --all-targets --all-features --locked -- -D warnings

rust-test: ## every Rust test of the workspace that needs neither root nor a namespace: unit tests, the contract's test catalog, the process roles
	$(CARGO) test --workspace --all-features --locked

net-plumbing-test: ## the Rust tests that need a network namespace of their own, inside `unshare --user --map-root-user --net --mount` (a clean skip where that is not allowed; ACF_REQUIRE_NETNS=1 makes the skip a failure)
	CARGO="$(CARGO)" bash scripts/net-plumbing-test.sh

root-test: ## the Rust tests that need root (`cargo test` ignores them): built as you, run as root through sudo
	CARGO="$(CARGO)" bash scripts/root-test.sh

# ---- the generated contracts: execution/contracts/ and schemas/ ----------------------------------
.PHONY: schema check-schema schemas check-schemas
schema: ## regenerate execution/contracts/ and schemas/ from the Rust types (the single source of truth)
	$(SCHEMA_CMD) --contracts $(CONTRACTS_DIR) --out $(SCHEMA_DIR) >/dev/null

check-schema: ## fail if execution/contracts/ or schemas/ differs from what the Rust types generate
	tmp="$$(mktemp -d)"; trap 'rm -rf "$$tmp"' EXIT; \
	$(SCHEMA_CMD) --contracts "$$tmp/contracts" --out "$$tmp/schemas" >/dev/null; \
	stale=0; \
	diff -ru $(CONTRACTS_DIR) "$$tmp/contracts" || stale=1; \
	diff -ru $(SCHEMA_DIR) "$$tmp/schemas" || stale=1; \
	if [ "$$stale" -ne 0 ]; then \
	    echo "the checked-in files differ from what the types generate: run 'make schema' and commit the result" >&2; \
	    exit 1; \
	fi; \
	echo "$(CONTRACTS_DIR)/ and $(SCHEMA_DIR)/ are up to date"

schemas: schema ## the same as `schema`

check-schemas: check-schema ## the same as `check-schema`

# ---- binaries ----------------------------------------------------------------------------------
.PHONY: fake-host release guest-agent
fake-host: ## build the TEST-ONLY in-memory host `acf-host-fake`: the client's end-to-end tests and the purity control (never ship it)
	$(CARGO) build --locked -p acf-host-agent --features testing --bin acf-host-fake

release: fake-host ## build the production acf-host (no `testing` feature) and prove it contains no test-only code
	$(CARGO) build --release --locked -p acf-host-agent --bin acf-host
	bash scripts/check-release-purity.sh "$(HOST_RELEASE)" --control "$(HOST_FAKE)"

guest-agent: ## build the static guest agent for the images (adds the musl rustup target) and verify it is static
	rustup target add $(MUSL_TARGET)
	$(CARGO) build --release --locked -p acf-guest-agent --target $(MUSL_TARGET)
	$(PYTHON) -I tools/elf_info.py --arch $(GUEST_ARCH) --static "$(GUEST_AGENT)"

# ---- Python: the client (apps/host-cli) -------------------------------------------------------------
# What these targets rely on is the client's public surface only: it is a uv project with ruff, mypy
# and pytest configured, a pytest marker `e2e`, and the two variables that marker documents.
.PHONY: py-lint py-test e2e
py-lint: ## ruff, ruff format --check and strict mypy for the client
	$(CLI_RUN) ruff check .
	$(CLI_RUN) ruff format --check .
	$(CLI_RUN) mypy

py-test: ## the client's tests (its end-to-end tests skip unless the test-only host is built)
	$(CLI_RUN) pytest

e2e: fake-host ## drive the real client against the real edge and core (in-memory VMs, no KVM); a missing binary FAILS
	ACF_REQUIRE_E2E=1 ACF_HOST_FAKE="$(abspath $(HOST_FAKE))" TMPDIR="$(SHORT_TMPDIR)" \
	    $(CLI_RUN) pytest -m e2e

# ---- Python: repository tooling (scripts/, tools/, deploy/, images/, tests/) -------------------
.PHONY: tools-lint tools-pytest tools-test shellcheck check-pins check-pins-release systemd-verify driver-selftest control-plane
tools-lint: ## ruff + strict mypy over tools/ and tests/ (including the KVM-only tests, which are type-checked here)
	$(UV_RUN) ruff check .
	$(UV_RUN) ruff format --check .
	$(UV_RUN) mypy

tools-pytest: ## the script, tool and unit-file tests (run it as root: about a third of it needs uid 0 and skips otherwise)
	$(UV_RUN) pytest

tools-test: tools-lint tools-pytest ## both of the above

shellcheck: ## ShellCheck at its strictest severity over every shell script
	$(UV_RUN) pytest tests/scripts/test_shellcheck.py -q

check-pins: ## image/Firecracker pins agree with each other (offline, fast)
	$(PYTHON) -I tools/check_pins.py

check-pins-release: ## release gate: FAILS while any digest is still UNSET
	$(PYTHON) -I tools/check_pins.py --require-pinned

systemd-verify: ## systemd-analyze verify every shipped unit against a throw-away root (needs systemd)
	@command -v systemd-analyze >/dev/null || { echo "systemd-analyze not found: install systemd" >&2; exit 1; }
	@test -n "$(UNITS)" || { echo "no units found in deploy/systemd" >&2; exit 1; }
	@root="$$(mktemp -d)"; trap 'rm -rf "$$root"' EXIT; \
	install -d "$$root/etc/systemd/system" "$$root/opt/acf/bin" "$$root/opt/acf/libexec" "$$root/usr/lib/systemd"; \
	cp -a /usr/lib/systemd/system "$$root/usr/lib/systemd/system"; \
	install -m 0755 /bin/true "$$root/opt/acf/bin/acf-host"; \
	install -m 0755 /bin/true "$$root/opt/acf/libexec/acf-setup-cgroup"; \
	install -m 0755 /bin/true "$$root/opt/acf/libexec/acf-wait-ready"; \
	install -m 0644 $(addprefix deploy/systemd/,$(UNITS)) "$$root/etc/systemd/system/"; \
	status=0; \
	said="$$(systemd-analyze verify --root="$$root" $(addprefix /etc/systemd/system/,$(UNITS)) 2>&1)" || status=$$?; \
	if [ "$$status" -ne 0 ] || grep -q 'acf-' <<<"$$said"; then \
	    printf '%s\n' "$$said" >&2; \
	    echo "systemd-analyze has something to say about the shipped units (a setting it ignores is a setting that is not in force)" >&2; \
	    exit 1; \
	fi; \
	echo "units verify: $(UNITS)"

driver-selftest: fake-host ## prove the integration-test driver against the in-memory host (no KVM, no root)
	ACF_DRIVER_SELFTEST=1 ACF_HOST_FAKE="$(abspath $(HOST_FAKE))" ACF_LOCAL="$(CLI_RUN) acf-local" \
	    TMPDIR="$(SHORT_TMPDIR)" $(UV_RUN) pytest tests/integration/test_driver_selftest.py -p no:cacheprovider

# ---- real VMs ----------------------------------------------------------------------------------
control-plane: fake-host ## the integration/isolation checks that need no guest, against the in-memory host with the SHIPPED config and safety profile (no KVM)
	ACF_CONTROL_PLANE=1 ACF_HOST_FAKE="$(abspath $(HOST_FAKE))" ACF_LOCAL="$(CLI_RUN) acf-local" \
	    TMPDIR="$(SHORT_TMPDIR)" $(UV_RUN) pytest tests/integration tests/isolation \
	    --ignore=tests/integration/test_driver_selftest.py -p no:cacheprovider

.PHONY: integration
integration: ## KVM host only: integration + isolation tests against a RUNNING acf-host (see docs/OPERATIONS.md)
	ACF_INTEGRATION=1 ACF_LOCAL="$(CLI_RUN) acf-local" $(UV_RUN) pytest tests/integration tests/isolation \
	    --ignore=tests/integration/test_driver_selftest.py

# ---- the developer platform: apps/api, apps/mcp-gateway, apps/cli, sdks/, protocols/ ------------
# Five projects, each with a lock of its own: four uv projects and one npm package. These targets rely
# on each project's public surface only: its linters and its tests are configured in the project, and
# the marker `host` selects the tests that need the in-memory host. They are a gate of their own
# (`platform-check`, `platform-ci`): nothing here changes what `check` and `ci` mean.
NPM            ?= npm
PLATFORM_PY    := apps/api apps/mcp-gateway sdks/python apps/cli
SDK_TS         := sdks/typescript
API_RUN        ?= $(UV) --directory apps/api run --locked
PROTOCOLS_DIR  := protocols
PLATFORM_UNITS := $(notdir $(wildcard deploy/platform/systemd/*.service))
# What `platform-compat` compares the contract files with: by default the newest release of the API that
# this commit descends from. Before the first release there is none, and nothing can be taken from anyone.
COMPAT_BASELINE ?= $(shell git describe --tags --match 'acf-api-v*' --abbrev=0 2>/dev/null)
COMPAT_ACCEPTED := apps/api/compat-accepted.txt
PLATFORM_DIST  := $(DIST_DIR)/platform
# pip-audit is pinned: the version found on PyPI on 2026-11-19.
PIP_AUDIT      ?= $(UV) tool run --from pip-audit==2.10.1 pip-audit

.PHONY: platform-artifacts platform-drift platform-compat platform-lint platform-test platform-e2e platform-sdk-ts platform-units platform-audit platform-dist
platform-artifacts: ## regenerate protocols/ from the code: the OpenAPI document, the tool definitions, the problem registry, the host mapping, the conformance scenarios
	$(API_RUN) acf-api artifacts --out "$(abspath $(PROTOCOLS_DIR))"

platform-drift: ## fail if protocols/ differs from what the code generates
	$(API_RUN) acf-api artifacts --out "$(abspath $(PROTOCOLS_DIR))" --check

platform-compat: ## fail if the contract files take anything from a caller of the last release (COMPAT_BASELINE=<git ref>; default: the newest acf-api-v* tag)
	@baseline="$(COMPAT_BASELINE)"; \
	if [ -z "$$baseline" ]; then \
	    if git rev-parse --git-dir >/dev/null 2>&1; then \
	        echo "platform-compat: no acf-api-v* tag is an ancestor of this commit: there is no release to compare with"; \
	    elif [ -n "$${CI:-}" ]; then \
	        echo "platform-compat: git cannot read this checkout, so the last release cannot be found" >&2; exit 2; \
	    else \
	        echo "platform-compat: this is not a git checkout: there is no release to compare with"; \
	    fi; \
	    exit 0; \
	fi; \
	base="$$(mktemp -d)"; trap 'rm -rf "$$base"' EXIT; \
	git archive --format=tar "$$baseline" -- "$(PROTOCOLS_DIR)" | tar -x -C "$$base"; \
	$(API_RUN) acf-api compat --baseline "$$base/$(PROTOCOLS_DIR)" --accept "$(abspath $(COMPAT_ACCEPTED))"

platform-lint: ## ruff, ruff format --check and strict mypy for the platform's four Python projects, each under its own configuration
	for project in $(PLATFORM_PY); do \
	    echo "== $$project"; \
	    $(UV) --directory "$$project" run --locked ruff check .; \
	    $(UV) --directory "$$project" run --locked ruff format --check .; \
	    $(UV) --directory "$$project" run --locked mypy; \
	done

platform-test: ## the tests of the platform's four Python projects (the ones that need the in-memory host skip unless it is built)
	for project in $(PLATFORM_PY); do \
	    echo "== $$project"; \
	    TMPDIR="$(SHORT_TMPDIR)" $(UV) --directory "$$project" run --locked pytest; \
	done

platform-e2e: fake-host ## the platform against the real host protocol over mutual TLS (in-memory VMs, no KVM); a missing binary FAILS
	ACF_REQUIRE_HOST=1 ACF_HOST_FAKE="$(abspath $(HOST_FAKE))" TMPDIR="$(SHORT_TMPDIR)" $(API_RUN) pytest -m host

platform-sdk-ts: ## the TypeScript SDK: install from its lock, type-check, test, build
	cd $(SDK_TS) && $(NPM) ci && $(NPM) run typecheck && $(NPM) test && $(NPM) run build

platform-units: ## systemd-analyze verify the platform's units against a throw-away root (needs systemd)
	@command -v systemd-analyze >/dev/null || { echo "systemd-analyze not found: install systemd" >&2; exit 1; }
	@test -n "$(PLATFORM_UNITS)" || { echo "no units found in deploy/platform/systemd" >&2; exit 1; }
	@root="$$(mktemp -d)"; trap 'rm -rf "$$root"' EXIT; \
	install -d "$$root/etc/systemd/system" "$$root/opt/acf-platform/api/bin" "$$root/opt/acf-platform/mcp/bin" "$$root/usr/lib/systemd"; \
	cp -a /usr/lib/systemd/system "$$root/usr/lib/systemd/system"; \
	install -m 0755 /bin/true "$$root/opt/acf-platform/api/bin/acf-api"; \
	install -m 0755 /bin/true "$$root/opt/acf-platform/mcp/bin/acf-mcp"; \
	install -m 0644 $(addprefix deploy/platform/systemd/,$(PLATFORM_UNITS)) "$$root/etc/systemd/system/"; \
	status=0; \
	said="$$(systemd-analyze verify --root="$$root" $(addprefix /etc/systemd/system/,$(PLATFORM_UNITS)) 2>&1)" || status=$$?; \
	if [ "$$status" -ne 0 ] || grep -q 'acf-' <<<"$$said"; then \
	    printf '%s\n' "$$said" >&2; \
	    echo "systemd-analyze has something to say about the platform's units (a setting it ignores is a setting that is not in force)" >&2; \
	    exit 1; \
	fi; \
	echo "units verify: $(PLATFORM_UNITS)"

platform-audit: ## known advisories against everything the platform's five locks name, development tools included (needs the network)
	tmp="$$(mktemp -d)"; trap 'rm -rf "$$tmp"' EXIT; \
	for project in $(PLATFORM_PY); do \
	    echo "== $$project"; \
	    $(UV) --directory "$$project" export -q --locked --no-emit-project --no-emit-local --format requirements-txt -o "$$tmp/requirements.txt"; \
	    $(PIP_AUDIT) --requirement "$$tmp/requirements.txt" --no-deps --disable-pip --strict; \
	done
	cd $(SDK_TS) && $(NPM) ci --ignore-scripts && $(NPM) audit && $(NPM) audit signatures

platform-dist: ## build every package of the platform into dist/platform/ and prove that the files install and import in an empty environment
	rm -rf "$(PLATFORM_DIST)"
	mkdir -p "$(PLATFORM_DIST)"
	for project in $(PLATFORM_PY); do \
	    $(UV) build -q --no-sources --directory "$$project" --out-dir "$(abspath $(PLATFORM_DIST))"; \
	done
	cd $(SDK_TS) && $(NPM) ci && $(NPM) pack --pack-destination "$(abspath $(PLATFORM_DIST))"
	venv="$$(mktemp -d)"; trap 'rm -rf "$$venv"' EXIT; \
	$(UV) venv -q "$$venv"; \
	$(UV) pip install -q --python "$$venv/bin/python" --find-links "$(PLATFORM_DIST)" "$(PLATFORM_DIST)"/*.whl; \
	"$$venv/bin/python" -c "import acf_api, acf_mcp, agentcompute, agentcompute_cli"; \
	"$$venv/bin/acf-api" --version; "$$venv/bin/acf-mcp" --version; "$$venv/bin/acf" --version
	ls -1 "$(PLATFORM_DIST)"

# Not part of any aggregate, on purpose: it installs the platform on the machine it runs on.
.PHONY: platform-deploy-test
platform-deploy-test: fake-host ## THROW-AWAY MACHINES ONLY (root, systemd, ACF_DEPLOY_TEST=1): install the platform as an operator would, start its units, use it, and check what the running processes cannot reach
	as_root=(); [ "$$(id -u)" -eq 0 ] || as_root=(sudo); \
	"$${as_root[@]}" env ACF_DEPLOY_TEST="$${ACF_DEPLOY_TEST:-}" ACF_HOST_FAKE="$(abspath $(HOST_FAKE))" UV="$$(command -v $(UV))" \
	    bash scripts/platform-deploy-test.sh

.PHONY: platform-check platform-ci
platform-check: platform-drift platform-compat platform-lint platform-test platform-sdk-ts platform-units ## everything of the platform that needs neither the in-memory host nor a package build

platform-ci: platform-check platform-e2e platform-dist ## what CI runs for the platform (see .github/workflows/platform.yml)

# ---- aggregate ---------------------------------------------------------------------------------
.PHONY: check ci
check: rust-fmt rust-lint rust-test net-plumbing-test check-schema py-lint py-test tools-test systemd-verify check-pins ## everything that runs without KVM, root or network

ci: check root-test release e2e driver-selftest control-plane ## what CI runs on every push (see .github/workflows/ci.yml); needs sudo for root-test

# ---- packaging ---------------------------------------------------------------------------------
.PHONY: dist clean
dist: ## reproducible source ZIP in dist/ (no build output, no caches, fixed timestamps)
	$(PYTHON) -I tools/pack_zip.py --root . --out $(DIST_DIR)/$(DIST_NAME).zip --prefix $(DIST_NAME)

clean: ## remove build output and caches (never touches sources)
	$(CARGO) clean
	rm -rf $(DIST_DIR) .ruff_cache .mypy_cache .pytest_cache apps/host-cli/.ruff_cache apps/host-cli/.mypy_cache \
	       apps/host-cli/.pytest_cache apps/host-cli/.coverage
	for project in $(PLATFORM_PY); do \
	    rm -rf "$$project/.ruff_cache" "$$project/.mypy_cache" "$$project/.pytest_cache" "$$project/.coverage" "$$project/dist"; \
	done
	rm -rf $(SDK_TS)/dist $(SDK_TS)/coverage
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
