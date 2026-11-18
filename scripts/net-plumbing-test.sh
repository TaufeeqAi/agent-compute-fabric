#!/usr/bin/env bash
# net-plumbing-test.sh — run the Rust tests that need a network namespace of their own.
#
#   net-plumbing-test.sh            (this is what `make net-plumbing-test` runs)
#
# Two groups of tests in the workspace build real kernel state: a network namespace, a device, a
# packet filter. They are `#[ignore]`d, so `cargo test` never runs them, and when they are asked for
# they demand a place where they may create a namespace: root, or, for an ordinary user, the inside of
#
#     unshare --user --map-root-user --net --mount -- <test binary> <filters>
#
# This script gives them that place:
#
#   1. acf-host-agent, the library tests whose names contain `netplumb` or `netns`: a sandbox's
#      network namespace, its device, its packet filter, and the two sockets bound inside it.
#   2. acf-traffic, tests/redirect.rs: the relay behind a real packet-filter redirect. That test
#      needs its namespace prepared, and its own header says how; the same commands are run here,
#      in the namespace, before the test binary.
#
# The test binaries are built first, outside any namespace, as the invoking user, so nothing in the
# target directory ends up owned by a mapped root. Each binary then runs in a namespace of its own,
# with the ignored tests included. A run in which no test ran is a failure, not a pass: a filter
# that matches nothing must not turn the gate green.
#
# Where this machine does not let the invoking user create such a namespace (unprivileged user
# namespaces are disabled or restricted), or lacks `ip` and `nft`, the script says so and exits 0: a
# skip, not a pass. ACF_REQUIRE_NETNS=1 makes that skip a failure; CI sets it.
#
# Environment: CARGO (default: cargo), ACF_REQUIRE_NETNS.
# Exit: 0 the tests ran and passed, or were skipped | 1 a test or the build failed, or a required
#       run was skipped | 2 usage.

# shellcheck disable=SC2034  # read by lib/common.sh
ACF_SCRIPT_NAME=net-plumbing-test.sh
# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

REPO="$(repo_root)"
export CARGO="${CARGO:-cargo}"
REQUIRE="${ACF_REQUIRE_NETNS:-0}"
NS=()

# What tests/redirect.rs asks for: a loopback device, 198.51.100.10 standing for a public
# destination, and a rule that redirects what "the guest" (127.0.0.2) sends to three ports to the
# relay on port 15001. `$0` is the test binary. The marker file tells a namespace that could not be
# prepared from a test that failed.
# shellcheck disable=SC2016  # expanded by the `sh -c` inside the namespace, not here
readonly PREPARE_REDIRECT='
ip link set lo up &&
ip addr add 198.51.100.10/32 dev lo &&
nft add table ip acf &&
nft "add chain ip acf out { type nat hook output priority -100 ; }" &&
nft "add rule ip acf out ip saddr 127.0.0.2 tcp dport { 443, 8443, 9443 } redirect to :15001" &&
: >"$ACF_NETNS_PREPARED" &&
exec "$0" "$@"'

usage() {
    cat <<'EOF'
Usage: net-plumbing-test.sh

Builds the test binaries of acf-host-agent and acf-traffic and runs the tests that need a network
namespace inside one (unshare --user --map-root-user --net --mount; as root: unshare --net --mount).

Environment:
  CARGO               the cargo to build with                     (default: cargo)
  ACF_REQUIRE_NETNS   1: a skip, for whatever reason, is a failure (default: a skip exits 0)
EOF
}

# skip MESSAGE: these tests cannot run here. A clean exit, unless the run is required.
skip() {
    if [[ "$REQUIRE" == 1 ]]; then
        die "$* (ACF_REQUIRE_NETNS=1: a skip is a failure)"
    fi
    log "skipped: $*"
    exit 0
}

# pick_namespace: how this user gets a namespace of its own. Sets NS, or skips.
pick_namespace() {
    command -v unshare >/dev/null 2>&1 || skip "\`unshare\` (util-linux) is not installed"
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        NS=(unshare --net --mount --)
        "${NS[@]}" true 2>/dev/null ||
            skip "root cannot create a network namespace here (\`${NS[*]} true\` failed; an unprivileged container?)"
    else
        NS=(unshare --user --map-root-user --net --mount --)
        "${NS[@]}" true 2>/dev/null ||
            skip "this user cannot create a user namespace with its own network namespace (\`${NS[*]} true\` failed). Unprivileged user namespaces are disabled or restricted on this machine (kernel.unprivileged_userns_clone, kernel.apparmor_restrict_unprivileged_userns); run this as root instead"
    fi
}

main() {
    case "${1:-}" in
        -h | --help) usage; exit 0 ;;
        '') ;;
        *) die_usage "unknown argument: $1" ;;
    esac
    [[ "$REQUIRE" == 0 || "$REQUIRE" == 1 ]] || die_usage "ACF_REQUIRE_NETNS must be 0 or 1"

    # The preparation needs both; an unprivileged user's PATH often leaves the sbin directories out.
    PATH="$PATH:/usr/sbin:/sbin"
    pick_namespace
    command -v ip >/dev/null 2>&1 || skip "\`ip\` (iproute2) is not installed"
    command -v nft >/dev/null 2>&1 || skip "\`nft\` (nftables) is not installed"
    need_cmd "$CARGO"
    need_cmd python3
    need_cmd tee
    make_workdir acf-netns-test

    local plumbing redirect
    plumbing="$(cargo_test_binary acf-host-agent --all-features --lib)"
    redirect="$(cargo_test_binary acf-traffic --test redirect)"

    run_test_binary "acf-host-agent: netplumb, netns" "$REPO/execution/host-agent" \
        "${NS[@]}" "$plumbing" netplumb netns --include-ignored ||
        die "the network plumbing tests failed"

    export ACF_NETNS_PREPARED="$ACF_WORKDIR/prepared"
    if ! run_test_binary "acf-traffic: redirect" "$REPO/execution/traffic" \
        "${NS[@]}" sh -c "$PREPARE_REDIRECT" "$redirect" --include-ignored; then
        [[ -e "$ACF_NETNS_PREPARED" ]] ||
            skip "the namespace for tests/redirect.rs could not be prepared (the output above names the command that failed; a kernel without nftables NAT?)"
        die "the redirect test failed"
    fi

    log "ok: the namespace tests ran and passed (${NS[*]})"
}

main "$@"
