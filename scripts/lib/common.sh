# shellcheck shell=bash
# Shared helpers for the ACF operator scripts. Source this file; do not execute it.
#
# Conventions (every script in scripts/ follows them):
#   * strict mode: `set -Eeuo pipefail`; unset variables and failed pipes are errors
#   * stdout is for data a caller may capture; every message goes to stderr
#   * exit codes:  0 ok | 1 error | 2 usage | 3 NOT PINNED (a digest the script requires is UNSET)
#   * lock files (scripts/firecracker.lock, images/images.lock) are read by a strict KEY=VALUE
#     parser and are NEVER sourced: a lock file cannot execute code
#   * nothing is downloaded and trusted by name alone: every artifact is checked against a digest

if [[ -n "${ACF_COMMON_SH_LOADED:-}" ]]; then
    return 0
fi
ACF_COMMON_SH_LOADED=1

set -Eeuo pipefail

ACF_SCRIPT_NAME="${ACF_SCRIPT_NAME:-${0##*/}}"
readonly EX_ERROR=1 EX_USAGE=2 EX_UNPINNED=3

log() { printf '%s: %s\n' "$ACF_SCRIPT_NAME" "$*" >&2; }
warn() { printf '%s: WARNING: %s\n' "$ACF_SCRIPT_NAME" "$*" >&2; }
die() {
    printf '%s: ERROR: %s\n' "$ACF_SCRIPT_NAME" "$*" >&2
    exit "$EX_ERROR"
}
die_usage() {
    printf '%s: %s\n' "$ACF_SCRIPT_NAME" "$*" >&2
    printf "Try '%s --help'.\n" "$ACF_SCRIPT_NAME" >&2
    exit "$EX_USAGE"
}
die_unpinned() {
    printf '%s: NOT PINNED: %s\n' "$ACF_SCRIPT_NAME" "$*" >&2
    exit "$EX_UNPINNED"
}

# need_cmd CMD [HINT]: fail early, with a hint, when a required tool is missing.
need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1${2:+ ($2)}"
}

require_root() {
    [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "must run as root (try: sudo $0 ...)"
}

# repo_root: absolute path of the repository containing scripts/.
repo_root() {
    local here
    here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    printf '%s\n' "$here"
}

# host_arch: the architecture name used everywhere in ACF (uname -m == Rust's ARCH constant).
host_arch() {
    local m
    m="$(uname -m)"
    case "$m" in
        x86_64 | aarch64) printf '%s\n' "$m" ;;
        *) die "unsupported architecture: $m (Firecracker supports x86_64 and aarch64)" ;;
    esac
}

is_sha256() { [[ "${1:-}" =~ ^[0-9a-f]{64}$ ]]; }

sha256_file() {
    local out
    out="$(sha256sum -- "$1")" || die "cannot hash $1"
    printf '%s\n' "${out%% *}"
}

# _lock_entries FILE: validate the WHOLE file, then print its entries as KEY=VALUE lines, in file order.
# Format: one KEY=VALUE per line; '#' starts a comment; blank lines are ignored. Keys are [A-Za-z0-9_]+ and
# unique; values are restricted to a conservative character set (no quotes, no whitespace, no shell
# metacharacters), so a value can never be interpreted as anything but data. Any other line is an error —
# including one AFTER the key a caller asked for, and a repeated key: a lock file is either entirely
# well-formed or not trusted at all. tools/check_pins.py implements the same grammar for the Python side;
# tests/scripts/test_lock_grammar.py runs both on the same inputs and demands the same verdicts.
_lock_entries() {
    local file=$1 line k v n=0
    local -A seen=()
    [[ -r "$file" ]] || die "lock file not readable: $file"
    # `read` silently drops NUL bytes, which would let a file say one thing to this parser and another to Python's.
    [[ "$(tr -d '\0' <"$file" | wc -c)" -eq "$(wc -c <"$file")" ]] || die "$file contains a NUL byte"
    while IFS= read -r line || [[ -n "$line" ]]; do
        n=$((n + 1))
        line="${line%%#*}"
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -z "$line" ]] && continue
        [[ "$line" == *=* ]] || die "$file:$n: malformed line (expected KEY=VALUE): $line"
        k="${line%%=*}"
        v="${line#*=}"
        [[ "$k" =~ ^[A-Za-z0-9_]+$ ]] || die "$file:$n: invalid key: $k"
        [[ "$v" =~ ^[A-Za-z0-9._:/@+=,-]*$ ]] || die "$file:$n: value for $k contains characters outside [A-Za-z0-9._:/@+=,-]"
        [[ -z "${seen[$k]+set}" ]] || die "$file:$n: duplicate key: $k"
        seen[$k]=1
        printf '%s=%s\n' "$k" "$v"
    done <"$file"
}

# lock_get FILE KEY: print the value of KEY; fail if the key is absent (or the file is not well-formed).
lock_get() {
    local file=$1 key=$2 entries line
    entries="$(_lock_entries "$file")" || exit "$EX_ERROR"
    while IFS= read -r line; do
        if [[ "${line%%=*}" == "$key" ]]; then
            printf '%s\n' "${line#*=}"
            return 0
        fi
    done <<<"$entries"
    die "$file: key not found: $key"
}

# lock_keys FILE [PREFIX]: print, in file order, every key that starts with PREFIX.
lock_keys() {
    local file=$1 prefix=${2:-} entries line k
    entries="$(_lock_entries "$file")" || exit "$EX_ERROR"
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        k="${line%%=*}"
        if [[ "$k" == "$prefix"* ]]; then
            printf '%s\n' "$k"
        fi
    done <<<"$entries"
}

# lock_get_pinned FILE KEY WHAT: like lock_get, but an UNSET/empty value is the fail-closed
# exit code 3 with an actionable message, not a silent default.
lock_get_pinned() {
    local file=$1 key=$2 what=$3 v
    v="$(lock_get "$file" "$key")"
    if [[ -z "$v" || "$v" == "UNSET" ]]; then
        die_unpinned "$key is UNSET in $file. Pin $what there (verify it out-of-band first); refusing to continue without it."
    fi
    printf '%s\n' "$v"
}

# make_workdir PREFIX: create a private temp dir, removed on exit (also on error and signals).
make_workdir() {
    local d
    d="$(mktemp -d "${TMPDIR:-/tmp}/${1:-acf}.XXXXXXXX")" || die "cannot create a temporary directory"
    ACF_WORKDIR="$d"
    trap 'rm -rf -- "${ACF_WORKDIR:-}"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
}

# require_free_mib DIR MIB WHAT: fail early, and clearly, when DIR has less than MIB mebibytes free.
# /tmp is often a RAM-backed tmpfs; unpacking an image into it ends in an unhelpful "No space left on
# device" (or the OOM killer) halfway through a long build.
require_free_mib() {
    local dir=$1 need=$2 what=$3 avail
    avail="$(df --output=avail -B1M -- "$dir" 2>/dev/null | tail -n 1 | tr -d '[:space:]')" || true
    [[ "$avail" =~ ^[0-9]+$ ]] || die "cannot determine the free space in $dir"
    ((avail >= need)) ||
        die "$what needs about ${need} MiB free in $dir, but only ${avail} MiB is available; point TMPDIR at a larger, disk-backed directory"
}

# human_mib BYTES: integer MiB, rounded up.
human_mib() { printf '%d' $((($1 + 1048575) / 1048576)); }

# cargo_test_binary PACKAGE CARGO_ARGS...: build the ONE test target the arguments select (for example
# `--lib`, or `--test NAME`), without running it, and print the path of its executable. The build
# runs as the invoking user from the repository root with ${CARGO:-cargo}; cargo's own diagnostics
# go to stderr. Needs make_workdir. This is how a script runs a test binary somewhere `cargo test`
# cannot follow it: inside a namespace, or as root.
cargo_test_binary() {
    local package=$1 messages exe
    shift
    messages="$ACF_WORKDIR/$package.build.json"
    log "building the tests of $package"
    (cd "$(repo_root)" && "${CARGO:-cargo}" test --no-run --locked --message-format=json-render-diagnostics -p "$package" "$@") >"$messages" ||
        die "cargo could not build the tests of $package"
    exe="$(python3 -I -c '
import json
import sys

found = []
for line in sys.stdin:
    if not line.startswith("{"):
        continue
    try:
        message = json.loads(line)
    except ValueError:
        continue
    if (
        message.get("reason") == "compiler-artifact"
        and message.get("executable")
        and message.get("profile", {}).get("test")
    ):
        found.append(message["executable"])
if len(found) != 1:
    sys.exit(f"expected exactly one test executable, cargo reported {len(found)}")
print(found[0])
' <"$messages")" || die "cannot tell which test executable cargo built for $package"
    [[ -x "$exe" ]] || die "cargo reported a test executable that does not exist: $exe"
    printf '%s\n' "$exe"
}

# run_test_binary LABEL DIR COMMAND...: run a test binary (COMMAND, with whatever it is wrapped in)
# from DIR, as cargo runs a test from its package directory, and show what it prints. Fails when
# the command fails, and when no test ran: a filter that matches nothing must not look like a pass.
# Needs make_workdir.
run_test_binary() {
    local label=$1 dir=$2 logfile status=0
    shift 2
    logfile="$(mktemp "$ACF_WORKDIR/run.XXXXXXXX")"
    log "$label"
    (cd "$dir" && "$@") 2>&1 | tee "$logfile" || status=$?
    ((status == 0)) || return "$status"
    grep -q -E '^test .+ \.\.\. ok$' "$logfile" ||
        die "$label: no test ran (the filters match nothing, or the test harness changed its output); a run that tests nothing is not a pass"
}
