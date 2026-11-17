#!/usr/bin/env bash
# check-release-purity.sh BINARY [--control BINARY]
#
# Prove that a release `acf-host` contains NO test-only code.
#
# The crate's `testing` feature compiles in an in-memory fake backend and crash-point injection. It
# must never be reachable from a production binary: there must be no request, flag or environment
# variable by which an operator (or an attacker) could trigger a fault point or swap in a fake VM.
# `Cargo.toml` and the `cfg` gates make that true by construction; this script is the independent,
# mechanical second check on the *artifact*, because "by construction" is exactly what a stray
# `features = ["testing"]` in a dependency edge silently breaks.
#
# Method: literal strings that exist only in test-only modules must be absent from BINARY. A check
# that finds nothing proves nothing unless it CAN find something, so `--control` names a binary built
# WITH the feature (for example target/debug/acf-host-fake), in which every sentinel must be present.
# Without a control the script still checks BINARY but says that the method was not self-validated.
#
# Exit: 0 pure, 1 test-only code found (or the control is blind), 2 usage.

# shellcheck disable=SC2034  # read by lib/common.sh
ACF_SCRIPT_NAME=check-release-purity.sh
# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

# Literals that appear only in testing/fake_backend.rs and testing/fault.rs.
SENTINELS=(
    "fake-profile"
    "fake-0"
    "AfterBackendMutationBeforeCommit"
    "AfterTerminalCommitBeforeResponse"
)

usage() {
    cat <<'EOF'
Usage: check-release-purity.sh BINARY [--control TESTING_BINARY]
EOF
}

contains() { grep -a -q -F -- "$2" "$1"; }

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
        die "$bin contains test-only code (found: ${found[*]}). It must be built without --features testing."
    fi

    if [[ -n "$control" ]]; then
        [[ -f "$control" ]] || die "control is not a file: $control"
        local blind=()
        for s in "${SENTINELS[@]}"; do
            contains "$control" "$s" || blind+=("$s")
        done
        if ((${#blind[@]})); then
            die "the control $control does not contain: ${blind[*]}; this check cannot see test-only code (update SENTINELS)"
        fi
        log "ok: $bin is free of test-only code (method validated against $control)"
    else
        log "ok: $bin is free of test-only code (no --control given: the method itself was not validated)"
    fi
}

main "$@"
