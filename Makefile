# Agent Compute Fabric — Phase 1: one entry point for every check, build and package step.
#
#   make help            what each target does
#   make check           everything that runs anywhere (no KVM, no network, no root needed)
#   make release         the production `acf-host`, proven free of test-only code
#   make integration     KVM hosts only: boots real microVMs (see docs/OPERATIONS.md)
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

# `uv run` for the repository tooling (root project) and for the CLI project (apps/cli).
# Both are locked: a dependency that is not in uv.lock cannot sneak into a check.
UV_RUN         ?= $(UV) run --locked
CLI_RUN        ?= $(UV) --directory apps/cli run --locked

# A Unix socket path is limited to 107 bytes; a deep $TMPDIR breaks the end-to-end tests.
SHORT_TMPDIR   ?= /tmp

SCHEMA_DIR     := schemas
DIST_DIR       := dist
DIST_NAME      := agent-compute-fabric-phase1

# ------------------------------------------------------------------------------------------------
.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "; printf "Usage: make <target>\n\n"} \
	     /^[a-zA-Z0-9_.-]+:.*## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ---- Rust --------------------------------------------------------------------------------------
.PHONY: rust-fmt rust-lint rust-test
rust-fmt: ## rustfmt, check only
	$(CARGO) fmt --all -- --check

rust-lint: ## clippy over every target and feature; warnings are errors
	$(CARGO) clippy --workspace --all-targets --all-features --locked -- -D warnings

rust-test: ## every Rust test: unit, contract, recovery, server, guest protocol
	$(CARGO) test --workspace --all-features --locked

# ---- wire contract -----------------------------------------------------------------------------
.PHONY: schemas check-schemas
schemas: ## regenerate schemas/ from the Rust types (the single source of truth)
	$(CARGO) run -q --locked -p acf-host-agent --bin acf-host -- schema --out $(SCHEMA_DIR) >/dev/null

check-schemas: ## fail if schemas/ differs from what the Rust types generate
	tmp="$$(mktemp -d)"; trap 'rm -rf "$$tmp"' EXIT; \
	$(CARGO) run -q --locked -p acf-host-agent --bin acf-host -- schema --out "$$tmp" >/dev/null; \
	diff -ru $(SCHEMA_DIR) "$$tmp" && echo "schemas/ is up to date"

# ---- binaries ----------------------------------------------------------------------------------
.PHONY: fake-host release guest-agent
fake-host: ## build the TEST-ONLY in-memory host used by the CLI end-to-end tests (never ship it)
	$(CARGO) build --locked -p acf-host-agent --features testing --bin acf-host-fake

release: fake-host ## build the production acf-host (no `testing` feature) and prove it contains no test code
	$(CARGO) build --release --locked -p acf-host-agent --bin acf-host
	bash scripts/check-release-purity.sh $(HOST_RELEASE) --control $(HOST_FAKE)

guest-agent: ## build the static guest agent for the images (adds the musl rustup target) and verify it is static
	rustup target add $(MUSL_TARGET)
	$(CARGO) build --release --locked -p acf-guest-agent --target $(MUSL_TARGET)
	$(PYTHON) -I tools/elf_info.py --arch $(GUEST_ARCH) --static $(GUEST_AGENT)

# ---- Python: the CLI (apps/cli) ----------------------------------------------------------------
.PHONY: py-lint py-test e2e
py-lint: ## ruff, ruff format --check and strict mypy for the CLI
	$(CLI_RUN) ruff check .
	$(CLI_RUN) ruff format --check .
	$(CLI_RUN) mypy

py-test: ## the CLI's unit and contract tests (the end-to-end tests skip unless the fake host is built)
	$(CLI_RUN) pytest

e2e: fake-host ## drive the real CLI against the real host server (in-memory VMs, no KVM); a missing binary FAILS
	ACF_REQUIRE_E2E=1 ACF_HOST_FAKE="$(abspath $(HOST_FAKE))" TMPDIR="$(SHORT_TMPDIR)" \
	    $(CLI_RUN) pytest -m e2e

# ---- Python: repository tooling (scripts/, tools/, images/, tests/) ----------------------------
.PHONY: tools-lint tools-pytest tools-test shellcheck check-pins check-pins-release systemd-verify driver-selftest control-plane
tools-lint: ## ruff + strict mypy over tools/ and tests/ (including the KVM-only tests, which are type-checked here)
	$(UV_RUN) ruff check .
	$(UV_RUN) ruff format --check .
	$(UV_RUN) mypy

tools-pytest: ## the script/tool test-suite (run it as root: about a third of it needs uid 0 and skips otherwise)
	$(UV_RUN) pytest

tools-test: tools-lint tools-pytest ## both of the above

shellcheck: ## ShellCheck at its strictest severity over every shell script
	$(UV_RUN) pytest tests/scripts/test_shellcheck.py -q

check-pins: ## image/Firecracker pins agree with each other (offline, fast)
	$(PYTHON) -I tools/check_pins.py

check-pins-release: ## release gate: FAILS while any digest is still UNSET
	$(PYTHON) -I tools/check_pins.py --require-pinned

systemd-verify: ## systemd-analyze verify the shipped units against a throw-away root (needs systemd)
	@command -v systemd-analyze >/dev/null || { echo "systemd-analyze not found: install systemd" >&2; exit 1; }
	@root="$$(mktemp -d)"; trap 'rm -rf "$$root"' EXIT; \
	install -d "$$root/etc/systemd/system" "$$root/opt/acf/bin" "$$root/opt/acf/libexec" "$$root/usr/bin" "$$root/bin" \
	  "$$root/usr/lib/systemd"; \
	cp -a /usr/lib/systemd/system "$$root/usr/lib/systemd/system"; \
	for f in /bin/sh /usr/bin/timeout; do install -m 0755 "$$f" "$$root$$f"; done; \
	install -m 0755 /bin/true "$$root/opt/acf/bin/acf-host"; \
	install -m 0755 /bin/true "$$root/opt/acf/libexec/acf-setup-cgroup"; \
	install -m 0644 deploy/systemd/*.service "$$root/etc/systemd/system/"; \
	systemd-analyze verify --root="$$root" /etc/systemd/system/acf-cgroup.service /etc/systemd/system/acf-host.service \
	  && echo "units verify"

driver-selftest: fake-host ## prove the integration-test driver against the in-memory host (no KVM, no root)
	ACF_DRIVER_SELFTEST=1 ACF_HOST_FAKE="$(abspath $(HOST_FAKE))" ACF_LOCAL="$(CLI_RUN) acf-local" \
	    TMPDIR="$(SHORT_TMPDIR)" $(UV_RUN) pytest tests/integration/test_driver_selftest.py -p no:cacheprovider

# ---- real VMs ----------------------------------------------------------------------------------
control-plane: fake-host ## the integration/isolation checks that need no guest, against the in-memory host with the SHIPPED config and policy (no KVM)
	ACF_CONTROL_PLANE=1 ACF_HOST_FAKE="$(abspath $(HOST_FAKE))" ACF_LOCAL="$(CLI_RUN) acf-local" \
	    TMPDIR="$(SHORT_TMPDIR)" $(UV_RUN) pytest tests/integration tests/isolation \
	    --ignore=tests/integration/test_driver_selftest.py -p no:cacheprovider

.PHONY: integration
integration: ## KVM host only: integration + isolation tests against a RUNNING acf-host (see docs/OPERATIONS.md)
	ACF_INTEGRATION=1 ACF_LOCAL="$(CLI_RUN) acf-local" $(UV_RUN) pytest tests/integration tests/isolation \
	    --ignore=tests/integration/test_driver_selftest.py

# ---- aggregate ---------------------------------------------------------------------------------
.PHONY: check ci
check: rust-fmt rust-lint rust-test check-schemas py-lint py-test tools-test systemd-verify check-pins ## everything that runs without KVM, root or network

ci: check release e2e driver-selftest control-plane ## what CI runs on every push (see .github/workflows/ci.yml)

# ---- packaging ---------------------------------------------------------------------------------
.PHONY: dist clean
dist: ## reproducible source ZIP in dist/ (no build output, no caches, fixed timestamps)
	$(PYTHON) -I tools/pack_zip.py --root . --out $(DIST_DIR)/$(DIST_NAME).zip --prefix $(DIST_NAME)

clean: ## remove build output and caches (never touches sources)
	$(CARGO) clean
	rm -rf $(DIST_DIR) .ruff_cache .mypy_cache .pytest_cache apps/cli/.ruff_cache apps/cli/.mypy_cache \
	       apps/cli/.pytest_cache apps/cli/.coverage
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
