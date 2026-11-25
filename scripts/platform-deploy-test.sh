#!/usr/bin/env bash
# platform-deploy-test.sh — install the developer platform on THIS machine as an operator would, start
# its units under systemd, use it, and check what the running processes hold and cannot reach.
#
#   ACF_DEPLOY_TEST=1 ACF_HOST_FAKE=target/debug/acf-host-fake platform-deploy-test.sh
#   (this is what `make platform-deploy-test` runs, through sudo)
#
# It CHANGES THE MACHINE: it creates accounts, directories under /etc, /opt, /run and /var, and systemd
# units, and it starts and stops services. Run it on a machine you throw away: a CI runner, a container
# that has systemd as its first process, a virtual machine. It refuses to run unless ACF_DEPLOY_TEST=1
# says that this is such a machine, and it refuses a machine that already has a deployment.
#
# What it proves, on a real systemd and through the shipped files only (scripts/platform-setup.sh, the
# units, the account and directory tables, the example configurations):
#   1. the two environments build from their locks, and the core's has no agent-protocol library;
#   2. the core starts confined, announces readiness, and binds the host over mutual TLS;
#   3. a developer's journey works through the TLS endpoint of the REST edge: create, replay under the
#      same key, conflict on a changed body, start, execute, read output, stale generation, stop, destroy;
#   4. the agent-protocol edge answers a tool listing and a tool call with an agent key, and refuses a
#      developer key;
#   5. the processes that read caller bytes hold no capability, cannot gain one, run under a system-call
#      filter, and cannot open the host private key, the fingerprint key, the store or the journal, by
#      their accounts or from inside their own mount namespaces;
#   6. the command socket admits the edge accounts and nobody else;
#   7. while the core is stopped the edge answers "unavailable, retry"; after the restart the ledger still
#      answers an old key with its operation;
#   8. a core whose secret others can read refuses to start, and systemd does not retry it.
#
# The host it binds is the test-only in-memory host (`make fake-host`), started here under an account of
# its own. No KVM is needed.
#
# Environment: ACF_DEPLOY_TEST=1 (required), ACF_HOST_FAKE (the test host binary; required), UV.
# Exit: 0 every check passed | 1 a check failed, or the machine is not usable | 2 usage.

# shellcheck disable=SC2034  # read by lib/common.sh
ACF_SCRIPT_NAME=platform-deploy-test.sh
# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

REPO="$(repo_root)"
readonly PREFIX=/opt/acf-platform ETC=/etc/acf-platform
readonly API="$PREFIX/api/bin/acf-api"
readonly CORE_YAML="$ETC/core.yaml"
readonly HOST_USER=acf-testhost HOST_UNIT=acf-test-host HOST_PORT=7443
readonly REST_URL=https://localhost:8443 MCP_URL=https://localhost:8444/mcp
readonly UNITS=(acf-platform-core.service acf-platform-rest.service acf-platform-mcp.service)
readonly SANDBOX_SPEC='{"image":"python","resources":{"vcpus":1,"memory_mib":512,"disk_mib":1024}}'
FAILURES=0
KEY=""
PROJECT=""
# Makes the idempotency keys of this run its own, so that a second run on the same machine starts new work.
RUN_ID="$(date +%s)"

usage() {
    cat <<'EOF'
Usage: ACF_DEPLOY_TEST=1 ACF_HOST_FAKE=<acf-host-fake> platform-deploy-test.sh

Installs the platform on this machine, starts it under systemd and tests it. It changes the machine:
run it only on one you throw away.
EOF
}

step() { printf '\n== %s\n' "$*" >&2; }

# check WHAT EXPECTED ACTUAL: one comparison; a mismatch is counted and the run goes on, so that one
# report shows everything that is wrong.
check() {
    if [[ "$2" == "$3" ]]; then
        log "ok: $1"
    else
        FAILURES=$((FAILURES + 1))
        warn "FAILED: $1: expected '$2', got '$3'"
    fi
}

# refused WHAT COMMAND...: the command must fail.
refused() {
    local what=$1 said
    shift
    if said="$("$@" 2>&1)"; then
        FAILURES=$((FAILURES + 1))
        warn "FAILED: $what: it succeeded, and must not"
    else
        log "ok: refused: $what [$(tail -n 1 <<<"$said" | cut -c1-90)]"
    fi
}

# field EXPRESSION: read one JSON document from stdin and print `document<EXPRESSION>`; nothing if absent.
field() {
    python3 -I -c '
import json, sys
try:
    value = eval("json.load(sys.stdin)" + sys.argv[1])
except (KeyError, IndexError, TypeError, ValueError):
    value = ""
print(value if not isinstance(value, bool) else str(value).lower())' "$1"
}

admin() { runuser -u acf-core -- "$API" admin --config "$CORE_YAML" "$@"; }

# rest METHOD PATH [curl arguments...]: one request to the REST edge with the developer key. The body
# goes to stdout; the status line and headers to $ACF_WORKDIR/headers.
rest() {
    local method=$1 path=$2
    shift 2
    curl -sS --max-time 90 --cacert "$ETC/rest/tls.crt" -D "$ACF_WORKDIR/headers" \
        -H "Authorization: Bearer $KEY" -X "$method" "$REST_URL$path" "$@"
}

status_of_last() { awk 'NR == 1 { print $2 }' "$ACF_WORKDIR/headers"; }

# mcp CREDENTIAL METHOD TOOL PARAMS [curl arguments...]: one request of the agent protocol, revision
# 2026-07-28, to the agent-protocol edge. TOOL is empty for a method that names none; PARAMS is the
# members of `params` as JSON without braces, or empty. The body goes to stdout; the status line and
# headers to $ACF_WORKDIR/mcp-headers.
mcp() {
    local credential=$1 method=$2 tool=$3 params=$4
    shift 4
    local envelope='"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"deploy-test","version":"1"}}'
    local -a headers=(-H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream'
        -H 'MCP-Protocol-Version: 2026-07-28' -H "Mcp-Method: $method")
    if [[ -n "$tool" ]]; then
        headers+=(-H "Mcp-Name: $tool")
    fi
    if [[ -n "$credential" ]]; then
        headers+=(-H "Authorization: Bearer $credential")
    fi
    curl -sS --max-time 90 --cacert "$ETC/mcp/tls.crt" -D "$ACF_WORKDIR/mcp-headers" "${headers[@]}" "$@" \
        -X POST "$MCP_URL" -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":{${params:+$params,}$envelope}}"
}

mcp_status() { awk 'NR == 1 { print $2 }' "$ACF_WORKDIR/mcp-headers"; }

# mutate KEY PATH BODY: a POST under an idempotency key, waiting for its operation.
mutate() {
    rest POST "$2?wait=30" -H 'Content-Type: application/json' -H "Idempotency-Key: $1" -d "$3"
}

wait_for_port() {
    local port=$1 _
    for _ in $(seq 150); do
        if ss -ltnH | grep -q ":$port "; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

self_signed() { # directory, owner
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -keyout "$1/tls.key" -out "$1/tls.crt" 2>/dev/null
    chown "$2:$2" "$1/tls.key" "$1/tls.crt"
    chmod 0600 "$1/tls.key"
    chmod 0644 "$1/tls.crt"
}

show_journals() {
    local unit
    for unit in "${UNITS[@]}" "$HOST_UNIT.service"; do
        printf '\n---- journal of %s\n' "$unit" >&2
        journalctl -u "$unit" --no-pager -n 40 >&2 || true
    done
}

# ------------------------------------------------------------------------------------------------
install_and_configure() {
    step "install: scripts/platform-setup.sh"
    bash "$REPO/scripts/platform-setup.sh" install
    check "the core's environment has no agent-protocol library" 0 \
        "$("$PREFIX/api/bin/python" -I -c 'import importlib.util; print(int(importlib.util.find_spec("mcp") is not None))')"

    step "a host to bind: the in-memory test host, under an account of its own"
    id "$HOST_USER" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$HOST_USER"
    install -D -m 0755 -- "$ACF_HOST_FAKE" /usr/local/libexec/acf-host-fake
    systemd-run --quiet --unit="$HOST_UNIT" --collect -p User="$HOST_USER" -p StateDirectory="$HOST_UNIT" -p RuntimeDirectory="$HOST_UNIT" \
        /usr/local/libexec/acf-host-fake --state "/var/lib/$HOST_UNIT/state" --socket "/run/$HOST_UNIT/h.sock" \
        --tls-listen "127.0.0.1:$HOST_PORT" --tls-dir "/var/lib/$HOST_UNIT/tls"
    wait_for_port "$HOST_PORT" || die "the test host does not listen on $HOST_PORT"

    step "what an operator provides: the host's authority, the platform's certificate and key, the endpoints"
    local tls="/var/lib/$HOST_UNIT/tls"
    install -o acf-core -g acf-core -m 0644 "$tls/ca.crt" "$ETC/secrets/host-ca.crt"
    install -o acf-core -g acf-core -m 0644 "$tls/caller.crt" "$ETC/secrets/platform.crt"
    install -o acf-core -g acf-core -m 0600 "$tls/caller.key" "$ETC/secrets/platform.key"
    sed -i -e "s|^  address: .*$|  address: 127.0.0.1:$HOST_PORT|" -e 's|^  host_id: .*$|  host_id: test-host|' "$CORE_YAML"
    self_signed "$ETC/rest" acf-rest
    self_signed "$ETC/mcp" acf-mcp

    step "the shipped example does not load until its deployment id is replaced"
    refused "acf-api check on config/platform-core.example.yaml" "$API" check --config "$REPO/config/platform-core.example.yaml"

    step "create the deployment, check it"
    runuser -u acf-core -- "$API" init --config "$CORE_YAML" >&2
    check "the separation of the edge accounts holds" holds "$(bash "$REPO/scripts/platform-setup.sh" check | field '["separation"]')"

    step "the host's own enrolment table: the platform is in it once, as a caller, and no edge is in it"
    # The host does not tell a caller its role, so the role is read where the host's operator wrote it.
    local table="/var/lib/$HOST_UNIT/state/enrolment.yaml" edge_digest
    check "the platform's certificate is enrolled once, with the role caller" "one entry, role caller" \
        "$(bash "$REPO/scripts/platform-setup.sh" check --host-enrolment "$table" | field '["host_enrolment"]')"
    sed 's/role: caller/role: operator/' "$table" >"$ACF_WORKDIR/as-operator.yaml"
    refused "a table that makes the platform an operator of the host" \
        bash "$REPO/scripts/platform-setup.sh" check --host-enrolment "$ACF_WORKDIR/as-operator.yaml"
    edge_digest="$(openssl x509 -in "$ETC/rest/tls.crt" -outform DER | sha256sum | cut -d' ' -f1)"
    {
        cat "$table"
        printf '  - { peer_id: rest-edge, role: observer, match: { certificate_sha256: "%s" } }\n' "$edge_digest"
    } >"$ACF_WORKDIR/with-an-edge.yaml"
    refused "a table in which the host knows an edge's certificate" \
        bash "$REPO/scripts/platform-setup.sh" check --host-enrolment "$ACF_WORKDIR/with-an-edge.yaml"
}

start_everything() {
    step "start the three units"
    systemctl start "${UNITS[@]}" || die "a unit did not start"
    local unit
    for unit in "${UNITS[@]}"; do
        check "$unit is active" active "$(systemctl is-active "$unit")"
    done
    wait_for_port 8443 || die "the REST edge does not listen"
    wait_for_port 8444 || die "the agent-protocol edge does not listen"
    check "the core is ready" true "$(admin health | field '["ready"]')"
    check "the core serves the pinned host" test-host "$(admin health | field '["host_id"]')"
    check "the core does not share its account with an edge" false "$(admin health | field '["edge_shares_core_identity"]')"
}

developer_journey() {
    step "a project, a developer and a key"
    local principal sandbox generation execution first again
    admin project.create --label deploy-test >"$ACF_WORKDIR/project.json"
    PROJECT="$(field '["project_id"]' <"$ACF_WORKDIR/project.json")"
    check "the project is active on an empty scope" active "$(field '["activation"]' <"$ACF_WORKDIR/project.json")"
    principal="$(admin principal.create --label developer-one | field '["principal_id"]')"
    admin role.set --principal-id "$principal" --project-id "$PROJECT" >/dev/null
    KEY="$(admin key.issue --principal-id "$principal" --project-id "$PROJECT" | field '["secret"]')"
    [[ "$KEY" == acf1_dev_* ]] || die "no developer key was issued"

    step "the developer journey through the REST edge"
    local run=$RUN_ID base="/v1/projects/$PROJECT" spec=$SANDBOX_SPEC
    check "whoami names the project of the key" "$PROJECT" "$(rest GET /v1/auth/whoami | field '["project_id"]')"
    check "no credential is 401 with a challenge" "401 Bearer" \
        "$(curl -sS --cacert "$ETC/rest/tls.crt" -o /dev/null -D - "$REST_URL/v1/auth/whoami" | awk 'NR == 1 { printf "%s ", $2 } tolower($1) == "www-authenticate:" { printf "%s", $2 }' | tr -d '\r')"

    mutate "create-$run" "$base/sandboxes" "$spec" >"$ACF_WORKDIR/create.json"
    check "create: the operation succeeded" "SUCCEEDED APPLIED" "$(field '["state"]' <"$ACF_WORKDIR/create.json") $(field '["effect"]' <"$ACF_WORKDIR/create.json")"
    first="$(field '["operation_id"]' <"$ACF_WORKDIR/create.json")"
    sandbox="$(field '["target"]["sandbox_id"]' <"$ACF_WORKDIR/create.json")"
    generation="$(field '["target"]["generation"]' <"$ACF_WORKDIR/create.json")"
    again="$(mutate "create-$run" "$base/sandboxes" "$spec")"
    check "the same key again is the same operation, marked as a replay" "$first true" "$(field '["operation_id"]' <<<"$again") $(field '["replayed"]' <<<"$again")"
    check "the same key with another body is a conflict" IDEMPOTENCY_CONFLICT \
        "$(mutate "create-$run" "$base/sandboxes" '{"image":"python","resources":{"vcpus":2,"memory_mib":512,"disk_mib":1024}}' | field '["code"]')"

    check "start" "SUCCEEDED READY" "$(mutate "start-$run" "$base/sandboxes/$sandbox/start" "{\"expected_generation\": $generation}" |
        python3 -I -c 'import json, sys; d = json.load(sys.stdin); print(d.get("state"), d.get("result", {}).get("sandbox", {}).get("state"))')"
    mutate "exec-$run" "$base/sandboxes/$sandbox/executions" "{\"expected_generation\": $generation, \"argv\": [\"/bin/echo\", \"deployed\"]}" >"$ACF_WORKDIR/exec.json"
    execution="$(field '["target"]["execution_id"]' <"$ACF_WORKDIR/exec.json")"
    check "execute: exited 0" "SUCCEEDED 0" "$(field '["result"]["execution"]["state"]' <"$ACF_WORKDIR/exec.json") $(field '["result"]["execution"]["exit_code"]' <"$ACF_WORKDIR/exec.json")"
    check "output is labelled as the guest's" GUEST_REPORTED "$(rest GET "$base/executions/$execution/output?stream=stdout" | field '["provenance"]')"
    check "a stale generation is refused before anything changes" REVISION_CONFLICT \
        "$(mutate "stale-$run" "$base/sandboxes/$sandbox/stop" '{"expected_generation": 99}' | field '["code"]')"
    check "another project's records do not exist for this key" NOT_FOUND "$(rest GET /v1/projects/prj_AAAAAAAAAAAAAAAAAAAA/sandboxes | field '["code"]')"
    check "stop" SUCCEEDED "$(mutate "stop-$run" "$base/sandboxes/$sandbox/stop" '{"expected_generation": "current"}' | field '["state"]')"
    check "destroy" SUCCEEDED "$(rest DELETE "$base/sandboxes/$sandbox?wait=30&expected_generation=current" -H "Idempotency-Key: destroy-$run" | field '["state"]')"
}

agent_interface() {
    step "an agent, through the agent-protocol edge"
    local agent health='"name":"health_check","arguments":{}'
    agent="$(rest POST "/v1/projects/$PROJECT/agent-credentials" -H 'Content-Type: application/json' -d '{"label":"deploy-test","lifetime_seconds":600}' | field '["secret"]')"
    [[ "$agent" == acf1_agt_* ]] || die "no agent key was minted"

    check "discovery says what this platform offers, and never one-step create" "true false" \
        "$(mcp "$agent" server/discover "" "" | python3 -I -c '
import json, sys
offered = json.load(sys.stdin)["result"]["capabilities"]["experimental"]["acf"]["platform_features"]
print(str("agent_credentials" in offered).lower(), str("create_with_start" in offered).lower())')"
    check "an agent key is offered the catalogue" yes \
        "$(mcp "$agent" tools/list "" "" | python3 -I -c 'import json, sys; print("yes" if "sandbox_create" in {t["name"] for t in json.load(sys.stdin)["result"]["tools"]} else "no")')"
    check "a tool call answers with structured content, and its text is the same JSON" "false true" \
        "$(mcp "$agent" tools/call health_check "$health" | python3 -I -c '
import json, sys
result = json.load(sys.stdin)["result"]
same = json.loads(result["content"][0]["text"]) == result["structuredContent"]
print(str(result.get("isError", False)).lower(), str(same).lower())')"
    check "an agent creates a sandbox, under a key the platform minted for the call" "SUCCEEDED mk_" \
        "$(mcp "$agent" tools/call sandbox_create '"name":"sandbox_create","arguments":{"name":"from-an-agent","image":"python","resources":{"vcpus":1,"memory_mib":512,"disk_mib":1024}}' |
            python3 -I -c 'import json, sys; s = json.load(sys.stdin)["result"]["structuredContent"]; print(s["operation"]["state"], s["idempotency_key"][:3])')"

    check "a developer key is offered no tool" 0 "$(mcp "$KEY" tools/list "" "" | python3 -I -c 'import json, sys; print(len(json.load(sys.stdin)["result"]["tools"]))')"
    check "a call with a developer key is refused, as a result the caller can read" "true PERMISSION_DENIED agent_credential_required" \
        "$(mcp "$KEY" tools/call health_check "$health" | python3 -I -c '
import json, sys
result = json.load(sys.stdin)["result"]
error = result["structuredContent"]["error"]
print(str(result.get("isError", False)).lower(), error["code"], error.get("reason"))')"

    mcp "" tools/list "" "" >/dev/null
    check "no credential is 401 with a challenge" "401 yes" "$(mcp_status) $(grep -qi '^www-authenticate: Bearer' "$ACF_WORKDIR/mcp-headers" && echo yes || echo no)"
    mcp "$agent" tools/list "" "" -H 'Origin: https://not-listed.invalid' >/dev/null
    check "an Origin that is not listed is refused" 403 "$(mcp_status)"
    check "a revision the platform does not serve is refused with the protocol's own error" "400 -32022" \
        "$(curl -sS --cacert "$ETC/mcp/tls.crt" -o "$ACF_WORKDIR/revision.json" -w '%{http_code}' -X POST "$MCP_URL" \
            -H 'Content-Type: application/json' -H 'MCP-Protocol-Version: 2025-11-25' -H 'Mcp-Method: tools/list' -H "Authorization: Bearer $agent" \
            -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}') $(field '["error"]["code"]' <"$ACF_WORKDIR/revision.json")"
    check "the endpoint is POST only" 405 "$(curl -sS --cacert "$ETC/mcp/tls.crt" -o /dev/null -w '%{http_code}' "$MCP_URL")"
}

running_processes() {
    step "what the running processes hold"
    local unit pid status
    for unit in "${UNITS[@]}"; do
        pid="$(systemctl show -p MainPID --value "$unit")"
        status="$(awk '/^(CapPrm|CapEff|CapBnd|NoNewPrivs|Seccomp):/ { printf "%s ", $2 }' "/proc/$pid/status")"
        check "$unit: no capability, none to gain, a system-call filter" "0000000000000000 0000000000000000 0000000000000000 1 2 " "$status"
    done
    check "the three roles run under three accounts" 3 \
        "$(for unit in "${UNITS[@]}"; do awk '/^Uid:/ { print $2 }' "/proc/$(systemctl show -p MainPID --value "$unit")/status"; done | sort -u | wc -l)"
    check "the core listens on no network address" "" "$(ss -ltnpH | grep "pid=$(systemctl show -p MainPID --value "${UNITS[0]}")," || true)"

    step "what the edge accounts cannot reach"
    local account edge_pid uid gid
    for account in acf-rest acf-mcp; do
        refused "$account reads the host private key" runuser -u "$account" -- cat "$ETC/secrets/platform.key"
        refused "$account reads the fingerprint key" runuser -u "$account" -- cat "$ETC/secrets/fingerprint.key"
        refused "$account lists the store" runuser -u "$account" -- ls /var/lib/acf-platform
        refused "$account reads the journal" runuser -u "$account" -- cat /var/lib/acf-platform-journal/security.journal
        refused "$account connects to the admin socket" runuser -u "$account" -- python3 -I -c \
            'import socket; socket.socket(socket.AF_UNIX).connect("/run/acf-platform/admin.sock")'
    done
    refused "acf-rest reads the other edge's TLS key" runuser -u acf-rest -- cat "$ETC/mcp/tls.key"
    refused "acf-mcp reads the other edge's TLS key" runuser -u acf-mcp -- cat "$ETC/rest/tls.key"

    step "the same, from inside each edge's own mount namespace"
    for unit in "${UNITS[1]}" "${UNITS[2]}"; do
        edge_pid="$(systemctl show -p MainPID --value "$unit")"
        uid="$(awk '/^Uid:/ { print $2 }' "/proc/$edge_pid/status")"
        gid="$(awk '/^Gid:/ { print $2 }' "/proc/$edge_pid/status")"
        refused "$unit sees the host private key" nsenter --target "$edge_pid" --mount --setuid "$uid" --setgid "$gid" -- cat "$ETC/secrets/platform.key"
        refused "$unit sees the store" nsenter --target "$edge_pid" --mount --setuid "$uid" --setgid "$gid" -- ls /var/lib/acf-platform
        refused "$unit sees the journal" nsenter --target "$edge_pid" --mount --setuid "$uid" --setgid "$gid" -- ls /var/lib/acf-platform-journal
        refused "$unit writes below /etc" nsenter --target "$edge_pid" --mount --setuid "$uid" --setgid "$gid" -- touch "$ETC/written-by-an-edge"
        refused "$unit writes below /usr" nsenter --target "$edge_pid" --mount --setuid "$uid" --setgid "$gid" -- touch /usr/written-by-an-edge
    done

    step "the command socket admits the edge accounts and nobody else"
    local probe='
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.settimeout(3)
s.connect("/run/acf-platform/command.sock")
s.sendall(b"\x00\x00\x00\x02{}")
sys.exit(0 if s.recv(64) else 1)'
    check "the socket is the core's, opened to the command group only" "660 acf-core acf-command" "$(stat -c '%a %U %G' /run/acf-platform/command.sock)"
    check "the admin socket is the core's alone" "600 acf-core" "$(stat -c '%a %U' /run/acf-platform/admin.sock)"
    refused "an account outside the command group connects" runuser -u "$HOST_USER" -- python3 -I -c "$probe"
    refused "the core's own account is not an edge: connected, then closed without an answer" runuser -u acf-core -- python3 -I -c "$probe"
}

restarts() {
    step "the core is stopped: the edge stays up and says when to try again"
    systemctl stop "${UNITS[0]}"
    check "the answer while the core is down" "503 UPSTREAM_UNAVAILABLE SAME_REQUEST_LATER" \
        "$(rest GET /v1/info >"$ACF_WORKDIR/down.json" && printf '%s %s %s' "$(status_of_last)" "$(field '["code"]' <"$ACF_WORKDIR/down.json")" "$(field '["retry"]' <"$ACF_WORKDIR/down.json")")"
    check "the answer says when to try again" yes "$(grep -qi '^retry-after:' "$ACF_WORKDIR/headers" && echo yes || echo no)"
    check "the REST edge is still active" active "$(systemctl is-active "${UNITS[1]}")"

    step "the core is started again: the ledger still answers"
    local before again
    before="$(field '["operation_id"]' <"$ACF_WORKDIR/create.json")"
    systemctl start "${UNITS[0]}" || die "the core did not start again"
    again="$(mutate "create-$RUN_ID" "/v1/projects/$PROJECT/sandboxes" "$SANDBOX_SPEC")"
    check "the key of before the restart still answers with its operation, and creates nothing" "$before true" \
        "$(field '["operation_id"]' <<<"$again") $(field '["replayed"]' <<<"$again")"
    check "the core took a new writer epoch" yes "$([[ "$(admin health | field '["writer_epoch"]')" -ge 2 ]] && echo yes || echo no)"

    step "a core whose secret others can read refuses to start, and is not retried"
    systemctl stop "${UNITS[0]}"
    chmod 0640 "$ETC/secrets/platform.key"
    refused "systemctl start with a group-readable host key" systemctl start "${UNITS[0]}"
    check "exit status of the refused start" 78 "$(systemctl show -p ExecMainStatus --value "${UNITS[0]}")"
    check "systemd did not retry it" 0 "$(systemctl show -p NRestarts --value "${UNITS[0]}")"
    chmod 0600 "$ETC/secrets/platform.key"
    systemctl reset-failed "${UNITS[0]}"
    systemctl start "${UNITS[0]}" || die "the core did not start after the mode was put right"
    check "the core is active again" active "$(systemctl is-active "${UNITS[0]}")"
}

main() {
    if (($#)); then
        case "$1" in
            -h | --help) usage && exit 0 ;;
            *) die_usage "unknown argument: $1" ;;
        esac
    fi
    [[ "${ACF_DEPLOY_TEST:-}" == 1 ]] || die "this script changes the machine it runs on; set ACF_DEPLOY_TEST=1 on a machine you throw away"
    require_root
    [[ -n "${ACF_HOST_FAKE:-}" && -x "$ACF_HOST_FAKE" ]] || die "ACF_HOST_FAKE must name the test host binary (make fake-host)"
    [[ -d /run/systemd/system ]] || die "systemd is not the first process of this machine"
    [[ ! -e "$CORE_YAML" ]] || die "$CORE_YAML exists: this machine already has a deployment, and this test is not for it"
    local tool
    for tool in curl openssl python3 runuser nsenter ss systemd-run; do
        need_cmd "$tool"
    done
    make_workdir acf-deploy-test
    trap 'status=$?; if ((status != 0 || FAILURES != 0)); then show_journals; fi; rm -rf -- "${ACF_WORKDIR:-}"; exit "$status"' EXIT

    install_and_configure
    start_everything
    developer_journey
    agent_interface
    running_processes
    restarts

    step "result"
    ((FAILURES == 0)) || die "$FAILURES check(s) failed"
    log "every check passed"
}

main "$@"
