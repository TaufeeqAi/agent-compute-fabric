#!/usr/bin/env bash
# root-test.sh — run the Rust tests that need root.
#
#   root-test.sh            (this is what `make root-test` runs)
#
# Some tests in the workspace need what only root has: they give files to per-sandbox users, create
# network namespaces on the machine, or make a process switch to an unprivileged uid. They are marked
#
#     #[ignore = "needs root: run with `make root-test`"]
#
# so that `cargo test` reports them as ignored instead of passing them unseen; asked for without
# root they fail. This script is how they are asked for:
#
#   1. acf-host-agent, the ignored library tests in `fc_backend_tests` and `privsep`: the Firecracker
#      backend against a scripted VMM, and a role started under another user id.
#   2. acf-guest-agent, the ignored tests of tests/protocol.rs: the agent switching to an
#      unprivileged uid.
#
# The test binaries are built first, as the invoking user, so nothing in the target directory or in
# cargo's caches ends up owned by root. Only the two binaries run as root, each through `sudo`; run
# by root, the script needs no sudo. A run in which no test ran is a failure, not a pass.
#
# Unlike the namespace tests (net-plumbing-test.sh) these have no unprivileged way to run, so there
# is nothing to skip to: without root and without sudo the script fails and says so.
#
# Environment: CARGO (default: cargo).
# Exit: 0 the tests ran and passed | 1 a test or the build failed, or root is not to be had | 2 usage.

# shellcheck disable=SC2034  # read by lib/common.sh
ACF_SCRIPT_NAME=root-test.sh
# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

REPO="$(repo_root)"
export CARGO="${CARGO:-cargo}"
AS_ROOT=()

usage() {
    cat <<'EOF'
Usage: root-test.sh

Builds the test binaries of acf-host-agent and acf-guest-agent as you, then runs the tests that are
ignored because they need root, as root (through sudo, unless you are root already).

Environment:
  CARGO   the cargo to build with   (default: cargo)
EOF
}

main() {
    case "${1:-}" in
        -h | --help) usage; exit 0 ;;
        '') ;;
        *) die_usage "unknown argument: $1" ;;
    esac
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        command -v sudo >/dev/null 2>&1 ||
            die "these tests need root and there is no \`sudo\` to become root with; run this script as root"
        AS_ROOT=(sudo --)
    fi
    need_cmd "$CARGO"
    need_cmd python3
    need_cmd tee
    make_workdir acf-root-test

    local backend guest
    backend="$(cargo_test_binary acf-host-agent --all-features --lib)"
    guest="$(cargo_test_binary acf-guest-agent --test protocol)"

    run_test_binary "acf-host-agent: fc_backend_tests and privsep, as root" "$REPO/execution/host-agent" \
        "${AS_ROOT[@]}" "$backend" fc_backend_tests privsep:: --ignored ||
        die "the Firecracker backend tests failed"

    run_test_binary "acf-guest-agent: protocol, as root" "$REPO/execution/guest-agent" \
        "${AS_ROOT[@]}" "$guest" --ignored ||
        die "the guest agent tests failed"

    log "ok: the tests that need root ran and passed"
}

main "$@"
