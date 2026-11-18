#!/usr/bin/env bash
# check-release-purity.sh BINARY [--control BINARY]
#
# Prove that a release `acf-host` contains NO test-only code.
#
# The `testing` feature of the host agent compiles in an in-memory backend, crash-point and store
# fault injection, a lifetime guard that enforces nothing, a throwaway certificate authority (the
# `rcgen` crate), a switch that stops the store waiting for the disk, and the `acf-host-fake` binary.
# None of it may be reachable from a production binary: there must be no request, flag or
# environment variable by which an operator (or an attacker) could trigger a fault point, mint a
# credential or swap in a fake VM. `Cargo.toml` and the `cfg` gates make that true by construction;
# this script is the independent, mechanical second check on the *artifact*, because "by
# construction" is exactly what a stray `features = ["testing"]` in a dependency edge silently breaks.
#
# Method: literal strings that exist only in test-only code must be absent from BINARY. A check that
# finds nothing proves nothing unless it CAN find something, so `--control` names a binary built WITH
# the feature (`acf-host-fake`: `make fake-host`), in which every sentinel must be present. Without
# a control the script still checks BINARY but says that the method was not self-validated.
#
# Why strings and not symbols: the release profile strips symbols, so only what the code itself
# carries survives in the artifact. The sentinels below were chosen from real builds: each one is
# present in `acf-host-fake` in both the dev and the release profile and absent from a release
# `acf-host`. The first group is the one that matters most: those strings sit in the core's own code
# paths, so they are what a release `acf-host` built with the feature by mistake actually contains
# (the test doubles of the other groups are not linked into it, because nothing in it names them).
#
# The switch that skips fsync (durability.rs) is the one item with no string of its own: it is a
# flag and a branch. It is compiled under the same single feature as the crash points, so a binary
# that has it has the first group too, and that is how it is caught.
#
# Exit: 0 pure, 1 test-only code found (or the control is blind), 2 usage.

# shellcheck disable=SC2034  # read by lib/common.sh
ACF_SCRIPT_NAME=check-release-purity.sh
# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

# Where each literal comes from, under execution/host-agent/src.
SENTINELS=(
    # Fault injection, compiled into the coordinator and the store themselves:
    "simulated crash at"                   # error.rs: the error a crash point returns
    "AfterBackendMutationBeforeCommit"     # testing/fault.rs: a crash point's name
    "AfterTerminalCommitBeforeResponse"    # testing/fault.rs: a crash point's name
    "injected store append failure"        # store/journal.rs: the store's injected write error
    # Test doubles:
    "FakeBackend"                          # testing/fake_backend.rs: the in-memory backend
    "the lifetime enforcer is down (test)" # resources/lifetime.rs: the guard that enforces nothing
    # The throwaway certificate authority, and the crate that only it uses:
    "acf test authority"                   # testing/pki.rs
    "rcgen"
    # The test binary itself:
    "acf-host-fake"                        # bin/acf_host_fake.rs
)

usage() {
    cat <<'EOF'
Usage: check-release-purity.sh BINARY [--control TESTING_BINARY]
EOF
}

contains() { grep -a -q -F -- "$2" "$1"; }

# join_quoted ITEM...: `a`, `b c`, `d` (a sentinel may contain spaces, so a plain list would be ambiguous).
join_quoted() {
    local out="" s
    for s in "$@"; do
        out+="${out:+, }\`$s\`"
    done
    printf '%s' "$out"
}

main() {
    local bin="" control=""
    while (($#)); do
        case "$1" in
            --control) control="${2:?--control needs a file}"; shift 2 ;;
            -h | --help) usage; exit 0 ;;
            -*) die_usage "unknown option: $1" ;;
            *) [[ -z "$bin" ]] || die_usage "only one BINARY may be given"; bin="$1"; shift ;;
        esac
    done
    [[ -n "$bin" ]] || die_usage "missing BINARY"
    [[ -f "$bin" ]] || die "not a file: $bin"
    need_cmd grep

    local s found=()
    for s in "${SENTINELS[@]}"; do
        if contains "$bin" "$s"; then found+=("$s"); fi
    done
    if ((${#found[@]})); then
        die "$bin contains test-only code (found: $(join_quoted "${found[@]}")). It must be built without --features testing."
    fi

    if [[ -n "$control" ]]; then
        [[ -f "$control" ]] || die "control is not a file: $control"
        local blind=()
        for s in "${SENTINELS[@]}"; do
            contains "$control" "$s" || blind+=("$s")
        done
        if ((${#blind[@]})); then
            die "the control $control does not contain: $(join_quoted "${blind[@]}"); this check cannot see test-only code (update SENTINELS)"
        fi
        log "ok: $bin is free of test-only code (method validated against $control)"
    else
        log "ok: $bin is free of test-only code (no --control given: the method itself was not validated)"
    fi
}

main "$@"
