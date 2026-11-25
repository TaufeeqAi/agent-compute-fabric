#!/usr/bin/env bash
# The developer journey with `acf`, the command-line client, against a platform that is running.
#
#   python -m pip install ./sdks/python ./apps/cli
#   ACF_BASE_URL=https://acf.example:8443 ACF_API_KEY=acf1_dev_... \
#     [ACF_MCP_URL=https://acf.example:8444/mcp] [ACF_CA_FILE=authority.pem] [ACF=/path/to/acf] \
#     bash scripts/platform-journey/cli.sh
#
# A developer key of a project that holds nothing is all it needs. The program is run as a real process,
# with a home directory of its own, so the credentials you have stored are neither read nor changed. It
# logs in, creates a sandbox, runs a command, takes a snapshot, repeats a request under its key, mints an
# agent key, relays one message of the agent protocol when ACF_MCP_URL is given, and removes what it made.
# Every step is a check; the exit status is the number of checks that failed.
#
# What a pass means depends on what is behind the platform: python_sdk.py, beside this file, says it.
set -uo pipefail

ACF="${ACF:-acf}"
: "${ACF_BASE_URL:?set ACF_BASE_URL to the address of the public API}"
: "${ACF_API_KEY:?set ACF_API_KEY to a developer key}"
command -v "$ACF" >/dev/null 2>&1 || { echo "cli.sh: $ACF is not installed (python -m pip install ./sdks/python ./apps/cli)" >&2; exit 2; }

KEY="$ACF_API_KEY"
ADDRESS="$ACF_BASE_URL"
ENDPOINT="${ACF_MCP_URL:-}"
AUTHORITY="${ACF_CA_FILE:-}"
[[ -z "$AUTHORITY" ]] || AUTHORITY="$(readlink -f -- "$AUTHORITY")"
unset ACF_API_KEY ACF_BASE_URL ACF_MCP_URL ACF_CA_FILE ACF_PROJECT ACF_PROFILE

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
export HOME="$work/home" XDG_CONFIG_HOME="$work/home/.config"
mkdir -p "$HOME"
stored="$XDG_CONFIG_HOME/acf/credentials.json"
run="$(($(date +%s) % 1000000))"
failures=0
passed=0

ok() {
    printf 'ok   %s\n' "$1"
    passed=$((passed + 1))
}
bad() {
    printf 'FAIL %s\n' "$1"
    failures=$((failures + 1))
}
# expect WHAT WANTED ACTUAL: an exit status.
expect() { if [[ "$2" == "$3" ]]; then ok "$1 (status $3)"; else bad "$1: expected status $2, got $3"; fi; }
# has WHAT NEEDLE TEXT, lacks WHAT NEEDLE TEXT.
has() { if grep -qF -- "$2" <<<"$3"; then ok "$1"; else bad "$1: '$2' is not in the output"; fi; }
lacks() { if grep -qF -- "$2" <<<"$3"; then bad "$1: it is in the output"; else ok "$1"; fi; }
field() { python3 -I -c 'import json, sys; print(eval("json.load(sys.stdin)" + sys.argv[1]))' "$1"; }

has "the program says what it is" "acf" "$("$ACF" --version)"

login=(auth login --base-url "$ADDRESS" --key-stdin)
if [[ -n "$AUTHORITY" ]]; then
    out="$(printf '%s' "$KEY" | "$ACF" "${login[@]}" 2>&1)"
    status=$?
    if ((status != 0)); then ok "without the platform's authority nobody is believed (status $status)"; else bad "login succeeded without --ca-file"; fi
    lacks "a refusal does not show the key" "$KEY" "$out"
    printf '%s' "$KEY" | SSL_CERT_FILE="$AUTHORITY" "$ACF" "${login[@]}" >/dev/null 2>&1
    status=$?
    if ((status != 0)); then ok "a general certificate variable changes nothing (status $status)"; else bad "SSL_CERT_FILE was believed"; fi
    if [[ -e "$stored" ]]; then bad "a login that failed stored something"; else ok "a login that failed stored nothing"; fi
    login+=(--ca-file "$AUTHORITY")
fi
[[ -z "$ENDPOINT" ]] || login+=(--mcp-url "$ENDPOINT")

out="$(printf '%s' "$KEY" | "$ACF" "${login[@]}" 2>&1)"
expect "auth login" 0 $?
lacks "login never shows the key" "$KEY" "$out"
has "the stored file is its owner's alone" "600" "$(stat -c '%a' "$stored" 2>/dev/null)"
[[ -z "$AUTHORITY" ]] || has "the authority is stored as an absolute path" "\"ca_file\": \"$AUTHORITY\"" "$(cat "$stored")"

out="$("$ACF" info --json)"
expect "info" 0 $?
has "info names the API version" '"v1"' "$out"
out="$("$ACF" policy inspect 2>&1)"
expect "policy inspect" 0 $?
has "policy inspect shows what the key may do" "sandbox.create" "$out"

name="journey-cli-$run"
# Small enough for the snapshot quota of a default host, of which a snapshot takes memory and disk.
out="$("$ACF" sandbox create --image python --cpu 1 --memory 128MiB --disk 256MiB --name "$name" --json 2>"$work/err")"
status=$?
expect "sandbox create (creates, then starts)" 0 "$status"
((status == 0)) || cat "$work/err"
sandbox="$(field '["sandbox_id"]' <<<"$out")"
has "the sandbox is up after create" '"READY"' "$out"
has "the listing shows it by name" "$name" "$("$ACF" sandbox list 2>&1)"

out="$("$ACF" exec run "$name" --json -- python -c 'print(6 * 7)' 2>"$work/err")"
status=$?
expect "exec run" 0 "$status"
((status == 0)) || cat "$work/err"
execution="$(field '["execution_id"]' <<<"$out")"
has "the command exited" '"EXITED"' "$out"
"$ACF" exec status "$execution" >/dev/null 2>&1
expect "exec status" 0 $?
out="$("$ACF" exec output "$execution" --json 2>&1)"
expect "exec output, asked for by the identifier alone" 0 $?
has "output is labelled as the guest's" "GUEST_REPORTED" "$out"
"$ACF" exec cancel "$execution" >/dev/null 2>&1
status=$?
if ((status == 0 || status == 3 || status == 7)); then ok "cancelling what has ended is answered by the platform (status $status)"; else bad "exec cancel: status $status"; fi

out="$("$ACF" snapshot create "$name" --name "$name-base" --json 2>"$work/err")"
status=$?
expect "snapshot create" 0 "$status"
((status == 0)) || cat "$work/err"
snapshot="$(field '["snapshot_id"]' <<<"$out" 2>/dev/null)"
has "the snapshot is listed by name" "$name-base" "$("$ACF" snapshot list 2>&1)"

out="$("$ACF" operation list --json)"
expect "operation list" 0 $?
operation="$(python3 -I -c 'import json, sys; print(json.load(sys.stdin)[0]["operation_id"])' <<<"$out")"
"$ACF" operation get "$operation" >/dev/null 2>&1
expect "operation get" 0 $?

first="$("$ACF" sandbox stop "$name" --idempotency-key "$name-stop" --json 2>"$work/err")"
expect "sandbox stop" 0 $?
again="$("$ACF" sandbox stop "$name" --idempotency-key "$name-stop" --json 2>"$work/err")"
expect "the same command under the same key again" 0 $?
if [[ "$first" == "$again" ]]; then ok "and it is the same answer: nothing ran twice"; else bad "the repeated command answered differently"; fi
out="$("$ACF" sandbox stop "$sandbox" --generation current --idempotency-key "$name-stop" 2>&1)"
expect "the same key with another request is a refusal" 3 $?
has "and the refusal names the conflict" "IDEMPOTENCY_CONFLICT" "$out"
"$ACF" sandbox inspect "no-such-sandbox-$run" >/dev/null 2>&1
expect "a sandbox that does not exist is a refusal" 3 $?

out="$("$ACF" auth agent-key create --label "$name-agent" --lifetime 1h --json 2>"$work/err")"
expect "agent-key create" 0 $?
agent="$(field '["secret"]' <<<"$out")"
credential="$(field '["credential_id"]' <<<"$out")"
if [[ -n "$ENDPOINT" ]]; then
    message='{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"platform-journey","version":"1"}}}}'
    out="$(printf '%s\n' "$message" | ACF_API_KEY="$agent" ACF_BASE_URL="$ADDRESS" ACF_MCP_URL="$ENDPOINT" ACF_CA_FILE="$AUTHORITY" "$ACF" mcp 2>"$work/relay.err")"
    status=$?
    expect "acf mcp relays a message and ends when its input ends" 0 "$status"
    ((status == 0)) || cat "$work/relay.err"
    has "the answer is the platform's tool catalogue" '"sandbox_create"' "$out"
    lacks "neither stream of the relay shows the key" "$agent" "$out$(cat "$work/relay.err")"
    out="$(printf '%s\n' "$message" | "$ACF" mcp 2>&1)"
    expect "acf mcp does not start with the developer's key" 2 $?
    has "and says that an agent acts through an agent key" "agent key" "$out"
fi
"$ACF" auth agent-key revoke "$credential" >/dev/null 2>&1
expect "agent-key revoke" 0 $?

if [[ -n "${snapshot:-}" ]]; then
    "$ACF" snapshot delete "$snapshot" >/dev/null 2>&1
    expect "snapshot delete" 0 $?
fi
"$ACF" sandbox destroy "$sandbox" --generation current >/dev/null 2>&1
expect "sandbox destroy" 0 $?
"$ACF" auth logout >/dev/null 2>&1
expect "auth logout" 0 $?
if [[ -e "$stored" ]]; then bad "the credentials file outlived its last profile"; else ok "the file went with its last profile"; fi
"$ACF" sandbox list >/dev/null 2>&1
expect "after logout there is no key to use" 2 $?

printf '\n'
echo "$passed of $((passed + failures)) checks passed"
exit "$failures"
