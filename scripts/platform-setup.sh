#!/usr/bin/env bash
# platform-setup.sh — prepare a machine to run the ACF developer platform (core, REST edge, agent-protocol edge).
#
#   platform-setup.sh install [options]   build the two environments from their locks; create the accounts
#                                         and directories; install the units, the grant templates and a
#                                         first configuration
#   platform-setup.sh check [--prefix D]  run `acf-api check` as the core's account: is the configuration
#                                         valid, are the secrets trusted inputs, is the edge kept apart?
#
# `install` is idempotent and conservative:
#   * every package is installed from a lock that fixes each file by its hash (`uv sync --locked`); nothing
#     is resolved, and nothing is fetched by name alone
#   * the core's environment and the agent-protocol edge's environment are separate directories, so the
#     protocol library that edge needs is not on the import path of the process that holds the host key
#   * it never overwrites a configuration or a grant template an operator has changed (the shipped version
#     is written next to it as *.dist when they differ)
#   * it creates no secret and no deployment state, and it does not enable or start anything: those are
#     operator decisions, printed as next steps
#
# What it creates:
#   /opt/acf-platform/api/                 the environment of the core and of the REST edge   (root, not writable by others)
#   /opt/acf-platform/mcp/                 the environment of the agent-protocol edge
#   accounts acf-core, acf-rest, acf-mcp   one per role; group acf-command opens the command socket
#   /etc/acf-platform/                     core.yaml, rest.yaml, mcp.yaml, policies/, secrets/ (the core's),
#                                          rest/ and mcp/ (each edge's own TLS key)
#   /run/acf-platform/                     the command socket and the admin socket
#   /var/lib/acf-platform/                 the interface store
#   /var/lib/acf-platform-journal/         the security journal, apart from the store on purpose
#   acf-platform-core, -rest, -mcp         the three systemd units, plus sysusers.d and tmpfiles.d entries
#
# The interpreter must be one the service accounts can execute: a system Python (3.12 or newer), not one
# under somebody's home directory. `--python` names it; by default the newest of python3.14 … python3.12
# and python3 found in PATH is used.
#
# Environment: UV (default: uv).
# Exit: 0 ok | 1 error | 2 usage.

# shellcheck disable=SC2034  # read by lib/common.sh
ACF_SCRIPT_NAME=platform-setup.sh
# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

REPO="$(repo_root)"
readonly DEFAULT_PREFIX=/opt/acf-platform
readonly ETC=/etc/acf-platform
readonly CORE_USER=acf-core REST_USER=acf-rest MCP_USER=acf-mcp
readonly UNIT_SOURCE="$REPO/deploy/platform/systemd"
UV="${UV:-uv}"
PREFIX=$DEFAULT_PREFIX
PYTHON=""
WITH_MCP=1

usage() {
    cat <<'EOF'
Usage:
  platform-setup.sh install [--prefix DIR] [--python FILE] [--no-mcp]
  platform-setup.sh check   [--prefix DIR] [--host-enrolment FILE]

install options:
  --prefix DIR     where the two environments go                          (default /opt/acf-platform)
  --python FILE    the interpreter to build them on, 3.12 or newer        (default: found in PATH)
  --no-mcp         do not install the agent-protocol edge

check options:
  --host-enrolment FILE   a copy of the host's enrolment table: the platform's certificate must be in it
                          once, with the role `caller`, and no edge's certificate at all
EOF
}

# find_python: the interpreter to build on. It must run for an unprivileged account, so one that lives
# below a home directory is refused rather than found unusable when the units start.
find_python() {
    local candidate path
    if [[ -n "$PYTHON" ]]; then
        [[ -x "$PYTHON" ]] || die "--python $PYTHON is not an executable file"
        path="$(readlink -f -- "$PYTHON")"
    else
        path=""
        for candidate in python3.14 python3.13 python3.12 python3; do
            if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -I -c 'import sys; raise SystemExit(sys.version_info < (3, 12))'; then
                path="$(readlink -f -- "$(command -v "$candidate")")"
                break
            fi
        done
        [[ -n "$path" ]] || die "no Python 3.12 or newer in PATH; install one or name it with --python"
    fi
    "$path" -I -c 'import sys; raise SystemExit(sys.version_info < (3, 12))' || die "$path is older than Python 3.12"
    case "$path" in
        /home/* | /root/*) die "$path lives below a home directory, which the service accounts cannot read; use a system interpreter" ;;
    esac
    printf '%s\n' "$path"
}

# build_environment PROJECT DIR: DIR becomes exactly what the lock of PROJECT names, without its
# development tools and without a link back into this checkout. `--reinstall` rebuilds this
# checkout's own packages from their sources and installs every package again, so that an upgrade
# cannot keep a file, or be handed a cached build, of the release it replaces.
build_environment() {
    local project=$1 dir=$2
    log "building $dir from $project/uv.lock"
    UV_PROJECT_ENVIRONMENT="$dir" UV_PYTHON_DOWNLOADS=never UV_LINK_MODE=copy \
        "$UV" sync --quiet --locked --no-dev --no-editable --reinstall --project "$REPO/$project" --python "$PYTHON" ||
        die "uv could not build $dir from the lock of $project"
    chown -R root:root -- "$dir"
    chmod -R go-w -- "$dir"
}

# install_file SRC DST MODE OWNER GROUP: atomic replace (write beside, then rename).
install_file() {
    local src=$1 dst=$2 mode=$3 owner=$4 group=$5 tmp
    tmp="$(dirname "$dst")/.$(basename "$dst").new.$$"
    install -m "$mode" -o "$owner" -g "$group" -- "$src" "$tmp"
    mv -f -- "$tmp" "$dst"
}

# install_config SRC DST MODE GROUP: keep the operator's file; offer the shipped one as DST.dist.
install_config() {
    local src=$1 dst=$2 mode=$3 group=$4
    if [[ ! -e "$dst" ]]; then
        install_file "$src" "$dst" "$mode" root "$group"
        log "installed $dst"
    elif cmp -s -- "$src" "$dst"; then
        log "$dst is already the shipped version"
    else
        install_file "$src" "$dst.dist" "$mode" root "$group"
        warn "$dst differs from the shipped version; kept yours, wrote $dst.dist"
    fi
}

# render_unit SRC DST: the shipped unit, with this installation's prefix written in.
render_unit() {
    if [[ "$PREFIX" == "$DEFAULT_PREFIX" ]]; then
        cp -- "$1" "$2"
    else
        sed -e "s|$DEFAULT_PREFIX|$PREFIX|g" -- "$1" >"$2"
    fi
}

install_identities_and_directories() {
    install -D -m 0644 -o root -g root -- "$REPO/deploy/platform/sysusers.d/acf-platform.conf" /etc/sysusers.d/acf-platform.conf
    systemd-sysusers acf-platform.conf
    install -D -m 0644 -o root -g root -- "$REPO/deploy/platform/tmpfiles.d/acf-platform.conf" /etc/tmpfiles.d/acf-platform.conf
    systemd-tmpfiles --create acf-platform.conf
}

install_units() {
    local unit rendered
    for unit in "$UNIT_SOURCE"/acf-platform-*.service; do
        if [[ "$WITH_MCP" -eq 0 && "${unit##*/}" == acf-platform-mcp.service ]]; then
            continue
        fi
        rendered="$ACF_WORKDIR/${unit##*/}"
        render_unit "$unit" "$rendered"
        install_file "$rendered" "/etc/systemd/system/${unit##*/}" 0644 root root
        log "installed /etc/systemd/system/${unit##*/}"
    done
    systemctl daemon-reload
}

# install_first_configuration: a configuration that needs only the operator's own facts. The deployment
# id is made here, once: the example carries a placeholder that does not load, so that no two
# deployments can ever be started under one copied id.
install_first_configuration() {
    local id core="$ACF_WORKDIR/core.yaml" mcp="$ACF_WORKDIR/mcp.yaml"
    install_config "$REPO/policies/defaults/developer.yaml" "$ETC/policies/developer.yaml" 0644 root
    install_config "$REPO/policies/defaults/agent.yaml" "$ETC/policies/agent.yaml" 0644 root
    if [[ ! -e "$ETC/core.yaml" ]]; then
        id="$("$PREFIX/api/bin/acf-api" deployment-id)" || die "could not make a deployment id"
        grep -q '^deployment_id: dep_REPLACE_ME$' "$REPO/config/platform-core.example.yaml" ||
            die "config/platform-core.example.yaml no longer carries the deployment id placeholder"
        sed -e "s/^deployment_id: dep_REPLACE_ME$/deployment_id: $id/" -- "$REPO/config/platform-core.example.yaml" >"$core"
        install_file "$core" "$ETC/core.yaml" 0640 root "$CORE_USER"
        log "installed $ETC/core.yaml with a new deployment id ($id)"
    else
        log "$ETC/core.yaml exists; left as it is"
    fi
    install_config "$REPO/config/platform-edge.example.yaml" "$ETC/rest.yaml" 0640 "$REST_USER"
    if [[ "$WITH_MCP" -eq 1 ]]; then
        # The same file format, on the agent-protocol edge's own port and with its own TLS key.
        sed -e 's|^  port: 8443$|  port: 8444|' -e "s|$ETC/rest/tls\\.|$ETC/mcp/tls.|" -- "$REPO/config/platform-edge.example.yaml" >"$mcp"
        if ! grep -q '^  port: 8444$' "$mcp" || ! grep -q "$ETC/mcp/tls.key" "$mcp"; then
            die "config/platform-edge.example.yaml no longer has the port and the TLS paths this script rewrites"
        fi
        install_config "$mcp" "$ETC/mcp.yaml" 0640 "$MCP_USER"
    fi
}

cmd_install() {
    while (($#)); do
        case "$1" in
            --prefix) PREFIX="${2:?--prefix needs a directory}" && shift 2 ;;
            --python) PYTHON="${2:?--python needs a file}" && shift 2 ;;
            --no-mcp) WITH_MCP=0 && shift ;;
            -h | --help) usage && exit 0 ;;
            *) die_usage "install: unknown option: $1" ;;
        esac
    done
    [[ "$PREFIX" == /* ]] || die_usage "--prefix must be an absolute path"
    require_root
    need_cmd "$UV" "https://docs.astral.sh/uv/"
    need_cmd systemd-sysusers "this script installs systemd units"
    need_cmd systemd-tmpfiles
    need_cmd systemctl
    PYTHON="$(find_python)"
    make_workdir acf-platform-setup
    log "interpreter: $PYTHON ($("$PYTHON" -I -c 'import platform; print(platform.python_version())'))"

    install -d -m 0755 -o root -g root -- "$PREFIX"
    build_environment apps/api "$PREFIX/api"
    "$PREFIX/api/bin/acf-api" --version >&2
    if [[ "$WITH_MCP" -eq 1 ]]; then
        build_environment apps/mcp-gateway "$PREFIX/mcp"
        "$PREFIX/mcp/bin/acf-mcp" --version >&2
        "$PREFIX/api/bin/python" -I -c 'import importlib.util, sys; sys.exit(importlib.util.find_spec("mcp") is not None)' ||
            die "the core's environment contains the agent-protocol library; the two environments must stay apart"
    fi

    install_identities_and_directories
    install_units
    install_first_configuration

    cat >&2 <<EOF

$ACF_SCRIPT_NAME: installed. Nothing is enabled or started. Next:
  1. Enrol the platform on the host as ONE peer with role \`caller\`, and put what that gave you where
     $ETC/core.yaml names it, each file owned by $CORE_USER:
       $ETC/secrets/host-ca.crt    the authority that signs the host's certificate   (0644)
       $ETC/secrets/platform.crt   the platform's certificate                        (0644)
       $ETC/secrets/platform.key   the platform's private key                        (0600)
  2. Set host.address and host.host_id in $ETC/core.yaml.
  3. Give each edge the TLS certificate and key of its endpoint, owned by the edge's own account:
       $ETC/rest/tls.crt, $ETC/rest/tls.key (0600)   and   $ETC/mcp/tls.crt, $ETC/mcp/tls.key (0600)
  4. Create the deployment, once, and check it. With a copy of the host's enrolment table the check
     also confirms what the host cannot tell the platform: that it is enrolled once, as a caller.
       runuser -u $CORE_USER -- $PREFIX/api/bin/acf-api init --config $ETC/core.yaml
       $0 check --host-enrolment <copy of the host's enrolment table>
  5. systemctl enable --now acf-platform-core.service acf-platform-rest.service$([[ "$WITH_MCP" -eq 1 ]] && printf ' acf-platform-mcp.service')
  6. Create a project, a developer and a key: docs/platform/OPERATIONS.md
EOF
}

cmd_check() {
    local enrolment=""
    while (($#)); do
        case "$1" in
            --prefix) PREFIX="${2:?--prefix needs a directory}" && shift 2 ;;
            --host-enrolment) enrolment="${2:?--host-enrolment needs a file}" && shift 2 ;;
            -h | --help) usage && exit 0 ;;
            *) die_usage "check: unknown option: $1" ;;
        esac
    done
    require_root
    local api="$PREFIX/api/bin/acf-api"
    [[ -x "$api" ]] || die "$api is not installed; run '$0 install' first"
    local -a lint=()
    if [[ -n "$enrolment" ]]; then
        [[ -f "$enrolment" ]] || die "$enrolment is not a file"
        # The check runs as the core's account, which can open neither an edge's directory nor, perhaps,
        # the operator's copy of the table. Root hands it copies of what is public: the table, and the
        # certificate of each edge, which the host must not know.
        make_workdir platform-check
        install -m 0644 -- "$enrolment" "$ACF_WORKDIR/enrolment.yaml"
        lint=(--host-enrolment "$ACF_WORKDIR/enrolment.yaml")
        local edge
        for edge in rest mcp; do
            if [[ -f "$ETC/$edge/tls.crt" ]]; then
                install -m 0644 -- "$ETC/$edge/tls.crt" "$ACF_WORKDIR/$edge-edge-tls.crt"
                lint+=(--other-certificate "$ACF_WORKDIR/$edge-edge-tls.crt")
            fi
        done
        chmod 0755 "$ACF_WORKDIR"
    fi
    runuser -u "$CORE_USER" -- "$api" check --config "$ETC/core.yaml" "${lint[@]}"
}

main() {
    (($#)) || { usage >&2 && exit "$EX_USAGE"; }
    local command=$1
    shift
    case "$command" in
        install) cmd_install "$@" ;;
        check) cmd_check "$@" ;;
        -h | --help | help) usage ;;
        *) die_usage "unknown command: $command" ;;
    esac
}

main "$@"
