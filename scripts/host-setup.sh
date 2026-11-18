#!/usr/bin/env bash
# host-setup.sh — prepare a machine to run the ACF host agent (the execution plane).
#
#   host-setup.sh install [options]            create the identities and directories; install the
#                                              agent, its units and the three trusted files
#   host-setup.sh user                         create the edge user and the socket group; print their ids
#   host-setup.sh prerequisites [--config F]   are ip, nft, nsenter and unshare where host.yaml says?
#   host-setup.sh cgroup  [PARENT]             (re)create the cgroup v2 parent for sandboxes
#   host-setup.sh check   [--json]             run `acf-host doctor` (does this machine honour the profile?)
#
# `install` is idempotent and conservative:
#   * it never overwrites an operator's /etc/acf/host.yaml, profile.yaml or enrolment.yaml (the
#     shipped version is written next to it as *.dist when they differ; --force-config replaces them)
#   * it refuses to install an `acf-host` that contains test-only code (scripts/check-release-purity.sh)
#   * it does not enable or start anything: that is an operator decision, printed as a next step
#
# What it creates (all root:root; nothing group/world-writable, because `acf-host` refuses to trust
# files, programs or ancestor directories that an unprivileged user could replace):
#   /opt/acf/bin/acf-host               the one host binary: core, edge, guest-traffic, lifetime enforcer
#                                       (firecracker + jailer: scripts/install-firecracker.sh)
#   /opt/acf/libexec/acf-setup-cgroup   used by acf-cgroup.service
#   /opt/acf/libexec/acf-wait-ready     used by acf-host.service (readiness)
#   /etc/acf/host.yaml                  where things live, how big the machine is, every bound
#   /etc/acf/profile.yaml               the safety profile: what one request may consume
#   /etc/acf/enrolment.yaml             who may call this host, and in which role
#   /etc/acf/secrets/                   0700; one file per secret reference
#   /var/lib/acf/                       0700; durable state
#   /run/acf/, netns/, expiry/          runtime: socket, namespace handles, expiry tickets (tmpfiles.d)
#   user acf-edge, group acf            the unprivileged identity of the edge; a group for local callers
#   acf-cgroup, acf-lifetime, acf-host  the three systemd units, plus tmpfiles.d and sysusers.d entries
#
# The edge user's uid and gid are written into a host.yaml that this script installs (edge.uid,
# edge.gid): a core that runs as root refuses to start without edge.uid. An operator's own host.yaml
# is never edited; the ids are printed instead.
#
# --destdir DIR prefixes every absolute path (like `make DESTDIR`) and changes nothing else on the
# machine: no account, no runtime directory, no systemctl. For packaging, and for testing this
# script. The accounts of the target machine are not known then, so edge.uid and edge.gid stay unset
# in the staged host.yaml unless --edge-ids names them.

# shellcheck disable=SC2034  # read by lib/common.sh
ACF_SCRIPT_NAME=host-setup.sh
# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

REPO="$(repo_root)"
readonly DEFAULT_PREFIX=/opt/acf DEFAULT_STATE_ROOT=/var/lib/acf
readonly ETC=/etc/acf RUNTIME_DIR=/run/acf
readonly EDGE_USER=acf-edge SOCKET_GROUP=acf
PREFIX=$DEFAULT_PREFIX
STATE_ROOT=$DEFAULT_STATE_ROOT
DESTDIR=""
ACF_HOST_BIN=""
NO_SYSTEMD=0
FORCE_CONFIG=0
EDGE_IDS=""
EDGE_UID=""
EDGE_GID=""
SOCKET_GID=""
# The host.yaml whose network.*_bin paths `prerequisites` looks at.
HOST_YAML=$ETC/host.yaml

usage() {
    cat <<'EOF'
Usage:
  host-setup.sh install [--prefix DIR] [--acf-host FILE] [--state-root DIR] [--no-systemd] [--force-config]
                        [--destdir DIR [--edge-ids UID:GID]]
  host-setup.sh user
  host-setup.sh prerequisites [--config FILE]
  host-setup.sh cgroup  [PARENT]
  host-setup.sh check   [--json]

install options:
  --prefix DIR        installation prefix                     (default /opt/acf)
  --acf-host FILE     release acf-host binary to install      (default target/release/acf-host)
  --state-root DIR    durable state directory                 (default /var/lib/acf)
  --no-systemd        do not install the systemd units or the tmpfiles.d and sysusers.d entries
  --force-config      overwrite /etc/acf/host.yaml, profile.yaml and enrolment.yaml with the shipped files
  --destdir DIR       stage every file under DIR and change nothing else on this machine
                      (no account, no runtime directory, no systemctl): packaging, tests
  --edge-ids UID:GID  with --destdir: the ids the edge user will have on the target machine, written
                      into the staged host.yaml as edge.uid and edge.gid

prerequisites options:
  --config FILE       the host.yaml to read the four paths from   (default /etc/acf/host.yaml)
EOF
}

# dpath PATH: PATH under --destdir.
dpath() { printf '%s%s\n' "$DESTDIR" "$1"; }

# install_file SRC DST MODE: atomic replace (write beside, then rename), root-owned.
install_file() {
    local src=$1 dst=$2 mode=$3 tmp
    tmp="$(dirname "$dst")/.$(basename "$dst").new.$$"
    install -m "$mode" -o root -g root -- "$src" "$tmp"
    mv -f -- "$tmp" "$dst"
}

# install_config SRC DST: keep the operator's file; offer the shipped one as DST.dist.
install_config() {
    local src=$1 dst=$2
    if [[ ! -e "$dst" || "$FORCE_CONFIG" -eq 1 ]]; then
        install_file "$src" "$dst" 0644
        log "installed $dst"
    elif cmp -s -- "$src" "$dst"; then
        log "$dst is already the shipped version"
    else
        install_file "$src" "$dst.dist" 0644
        warn "$dst differs from the shipped version; kept yours, wrote $dst.dist"
    fi
}

# make_root_dir DIR MODE: create (or correct) a root-owned directory.
make_root_dir() {
    install -d -m "$2" -o root -g root -- "$1"
    chown root:root -- "$1"
    chmod "$2" -- "$1"
}

# render SRC DST: SRC with this installation's --prefix and --state-root written in. The shipped files
# name the defaults, so with the defaults this is a copy.
render() {
    local src=$1 dst=$2
    local -a edits=()
    [[ "$PREFIX" == "$DEFAULT_PREFIX" ]] || edits+=(-e "s|$DEFAULT_PREFIX|$PREFIX|g")
    [[ "$STATE_ROOT" == "$DEFAULT_STATE_ROOT" ]] || edits+=(-e "s|$DEFAULT_STATE_ROOT|$STATE_ROOT|g")
    if ((${#edits[@]})); then
        sed "${edits[@]}" -- "$src" >"$dst"
    else
        cp -- "$src" "$dst"
    fi
}

# render_host_config DST: the shipped host.yaml for this installation, with the edge's identity
# written in when it is known. The shipped file carries the two keys commented out; if they are not
# there to fill in, that is an error here and not a host that will not start later.
render_host_config() {
    local dst=$1 base="$ACF_WORKDIR/host.base.yaml"
    render "$REPO/config/host.example.yaml" "$base"
    if [[ -z "$EDGE_UID" ]]; then
        cp -- "$base" "$dst"
        return 0
    fi
    sed -E -e "s/^  # uid: [0-9]+\$/  uid: $EDGE_UID/" -e "s/^  # gid: [0-9]+\$/  gid: $EDGE_GID/" -- "$base" >"$dst"
    if [[ "$(grep -c -x -- "  uid: $EDGE_UID" "$dst")" -ne 1 || "$(grep -c -x -- "  gid: $EDGE_GID" "$dst")" -ne 1 ]]; then
        die "config/host.example.yaml has no commented-out \`# uid:\` and \`# gid:\` under \`edge:\` to fill in; nothing was installed. Set edge.uid: $EDGE_UID and edge.gid: $EDGE_GID in $ETC/host.yaml by hand"
    fi
}

# passwd_ids NAME: "UID GID" of an account, or nothing when there is none.
passwd_ids() {
    local entry uid gid
    entry="$(getent passwd "$1")" || return 0
    IFS=: read -r _ _ uid gid _ <<<"$entry"
    printf '%s %s\n' "$uid" "$gid"
}

# group_id NAME: the gid of a group, or nothing when there is none.
group_id() {
    local entry gid
    entry="$(getent group "$1")" || return 0
    IFS=: read -r _ _ gid _ <<<"$entry"
    printf '%s\n' "$gid"
}

# ensure_identities: the edge user with its group, and the socket group. Existing ones are left as
# they are. Sets EDGE_UID, EDGE_GID and SOCKET_GID.
ensure_identities() {
    need_cmd getent
    local sysusers="$REPO/deploy/sysusers.d/acf.conf" ids
    if [[ -z "$(passwd_ids "$EDGE_USER")" || -z "$(group_id "$SOCKET_GROUP")" ]]; then
        if command -v systemd-sysusers >/dev/null 2>&1; then
            log "creating user $EDGE_USER and group $SOCKET_GROUP with systemd-sysusers"
            systemd-sysusers "$sysusers" >&2 || die "systemd-sysusers could not apply $sysusers"
        else
            need_cmd groupadd "this machine has no systemd-sysusers; the shadow tools are the other way to create $EDGE_USER"
            need_cmd useradd "this machine has no systemd-sysusers; the shadow tools are the other way to create $EDGE_USER"
            log "creating user $EDGE_USER and group $SOCKET_GROUP with useradd and groupadd"
            [[ -n "$(group_id "$EDGE_USER")" ]] || groupadd --system -- "$EDGE_USER"
            [[ -n "$(passwd_ids "$EDGE_USER")" ]] ||
                useradd --system --gid "$EDGE_USER" --home-dir / --no-create-home --shell /usr/sbin/nologin \
                    --comment "ACF host agent edge (unprivileged)" -- "$EDGE_USER"
            [[ -n "$(group_id "$SOCKET_GROUP")" ]] || groupadd --system -- "$SOCKET_GROUP"
        fi
    fi
    ids="$(passwd_ids "$EDGE_USER")"
    [[ -n "$ids" ]] || die "user $EDGE_USER does not exist although it was just created (is the account database read-only?)"
    EDGE_UID="${ids% *}"
    EDGE_GID="${ids#* }"
    SOCKET_GID="$(group_id "$SOCKET_GROUP")"
    [[ -n "$SOCKET_GID" ]] || die "group $SOCKET_GROUP does not exist although it was just created"
    [[ "$EDGE_UID" =~ ^[0-9]+$ && "$EDGE_GID" =~ ^[0-9]+$ && "$SOCKET_GID" =~ ^[0-9]+$ ]] ||
        die "the account database returned ids that are not numbers for $EDGE_USER / $SOCKET_GROUP"
    # The edge reads bytes from callers: it must hold no privilege, and root's identity is privilege.
    [[ "$EDGE_UID" -ne 0 && "$EDGE_GID" -ne 0 ]] || die "$EDGE_USER has uid or gid 0; the edge must be an unprivileged user of its own"
}

# configured_tool KEY DEFAULT: the path $HOST_YAML gives network.KEY, or the built-in default.
configured_tool() {
    local key=$1 default=$2 value=""
    if [[ -r "$HOST_YAML" ]]; then
        value="$(sed -n -E "/^[[:space:]]+$key:/{s/^[[:space:]]+$key:[[:space:]]*[\"']?([^\"'[:space:]#]+).*\$/\\1/p;q}" "$HOST_YAML")"
    fi
    printf '%s\n' "${value:-$default}"
}

# report_prerequisites: the four programs the core runs as root besides Firecracker and the jailer,
# at the paths host.yaml names. Nothing is installed here; `acf-host doctor` is the authority (checks
# network_tools and unshare). It is said early so that it is not found out at the first sandbox.
# Returns 1 when one of them is missing or would not be trusted.
report_prerequisites() {
    local key default package path owner mode problem without missing=0
    while read -r key default package; do
        if [[ "$key" == unshare_bin ]]; then
            without="Every sandbox gets a network namespace of its own and unshare creates it: until then no sandbox can be created, and the core starts in CONTAINMENT."
        else
            without="Until then network mode \`allowlist\` is not offered; mode \`none\` works."
        fi
        path="$(configured_tool "$key" "$default")"
        problem=""
        if [[ ! -f "$path" || ! -x "$path" ]]; then
            problem="no executable at $path. Install the $package package, or correct the path in $HOST_YAML."
        else
            read -r owner mode < <(stat -L -c '%u %a' -- "$path")
            if [[ "$owner" -ne 0 || $((8#$mode & 8#22)) -ne 0 ]]; then
                problem="$path is not owned by root, or is writable by group or other (owner $owner, mode $mode): acf-host will not run it."
            fi
        fi
        if [[ -n "$problem" ]]; then
            warn "network.$key: $problem $without"
            missing=1
        fi
    done <<'EOF'
ip_bin /usr/sbin/ip iproute2
nft_bin /usr/sbin/nft nftables
nsenter_bin /usr/bin/nsenter util-linux
unshare_bin /usr/bin/unshare util-linux
EOF
    if ((missing)); then
        return 1
    fi
    log "prerequisites: ip, nft, nsenter and unshare are present at the paths $HOST_YAML names"
}

cmd_install() {
    local c unit fc_prefix="" identity
    while (($#)); do
        case "$1" in
            --prefix) PREFIX="${2:?--prefix needs a value}"; shift 2 ;;
            --acf-host) ACF_HOST_BIN="${2:?--acf-host needs a value}"; shift 2 ;;
            --state-root) STATE_ROOT="${2:?--state-root needs a value}"; shift 2 ;;
            --destdir) DESTDIR="${2:?--destdir needs a value}"; shift 2 ;;
            --edge-ids) EDGE_IDS="${2:?--edge-ids needs UID:GID}"; shift 2 ;;
            --no-systemd) NO_SYSTEMD=1; shift ;;
            --force-config) FORCE_CONFIG=1; shift ;;
            -h | --help) usage; exit 0 ;;
            *) die_usage "unknown option: $1" ;;
        esac
    done
    [[ "$PREFIX" == /* && "$STATE_ROOT" == /* ]] || die_usage "--prefix and --state-root must be absolute paths"
    # They are written into unit files and host.yaml: keep them to characters that mean nothing there.
    [[ "$PREFIX" =~ ^[A-Za-z0-9._/-]+$ && "$STATE_ROOT" =~ ^[A-Za-z0-9._/-]+$ ]] ||
        die_usage "--prefix and --state-root may contain only letters, digits, '.', '_', '-' and '/'"
    [[ -z "$DESTDIR" || "$DESTDIR" == /* ]] || die_usage "--destdir must be an absolute path"
    if [[ -n "$EDGE_IDS" ]]; then
        [[ -n "$DESTDIR" ]] || die_usage "--edge-ids is for --destdir; a live install reads the ids from the account database"
        [[ "$EDGE_IDS" =~ ^([1-9][0-9]*):([1-9][0-9]*)$ ]] || die_usage "--edge-ids must be UID:GID, two numbers greater than 0"
        EDGE_UID="${BASH_REMATCH[1]}"
        EDGE_GID="${BASH_REMATCH[2]}"
    fi
    require_root
    for c in install cmp sed grep stat; do need_cmd "$c"; done

    ACF_HOST_BIN="${ACF_HOST_BIN:-$REPO/target/release/acf-host}"
    [[ -f "$ACF_HOST_BIN" && -x "$ACF_HOST_BIN" ]] ||
        die "no acf-host binary at $ACF_HOST_BIN (build it: make release, or pass --acf-host FILE)"
    log "checking that $ACF_HOST_BIN contains no test-only code"
    bash "$REPO/scripts/check-release-purity.sh" "$ACF_HOST_BIN"

    # Identities first: host.yaml needs the edge's ids. A staged install touches no account database.
    if [[ -z "$DESTDIR" ]]; then
        ensure_identities
    fi
    # Everything that can still be refused is decided before the first file is installed.
    make_workdir acf-host-setup
    render_host_config "$ACF_WORKDIR/host.yaml"

    # Directories. Every component below the root must stay root-owned and not group/world-writable.
    make_root_dir "$(dpath "$PREFIX")" 0755
    make_root_dir "$(dpath "$PREFIX/bin")" 0755
    make_root_dir "$(dpath "$PREFIX/libexec")" 0755
    make_root_dir "$(dpath "$ETC")" 0755
    make_root_dir "$(dpath "$ETC/secrets")" 0700
    make_root_dir "$(dpath "$STATE_ROOT")" 0700
    make_root_dir "$(dpath "$STATE_ROOT/images")" 0755

    install_file "$ACF_HOST_BIN" "$(dpath "$PREFIX/bin/acf-host")" 0755
    install_file "$REPO/scripts/acf-setup-cgroup" "$(dpath "$PREFIX/libexec/acf-setup-cgroup")" 0755
    install_file "$REPO/scripts/acf-wait-ready" "$(dpath "$PREFIX/libexec/acf-wait-ready")" 0755

    # The three trusted files.
    install_config "$ACF_WORKDIR/host.yaml" "$(dpath "$ETC/host.yaml")"
    install_config "$REPO/profiles/default.yaml" "$(dpath "$ETC/profile.yaml")"
    install_config "$REPO/config/enrolment.example.yaml" "$(dpath "$ETC/enrolment.yaml")"
    if [[ -e "$(dpath "$ETC/policy.yaml")" ]]; then
        warn "$(dpath "$ETC/policy.yaml") is no longer read: the safety profile is $ETC/profile.yaml. Carry your limits over and remove the old file."
    fi

    if [[ "$NO_SYSTEMD" -eq 0 ]]; then
        make_root_dir "$(dpath /etc/systemd/system)" 0755
        make_root_dir "$(dpath /etc/tmpfiles.d)" 0755
        make_root_dir "$(dpath /etc/sysusers.d)" 0755
        for unit in acf-cgroup.service acf-lifetime.service acf-host.service; do
            render "$REPO/deploy/systemd/$unit" "$ACF_WORKDIR/$unit"
            install_file "$ACF_WORKDIR/$unit" "$(dpath "/etc/systemd/system/$unit")" 0644
        done
        render "$REPO/deploy/tmpfiles.d/acf.conf" "$ACF_WORKDIR/tmpfiles.conf"
        install_file "$ACF_WORKDIR/tmpfiles.conf" "$(dpath /etc/tmpfiles.d/acf.conf)" 0644
        install_file "$REPO/deploy/sysusers.d/acf.conf" "$(dpath /etc/sysusers.d/acf.conf)" 0644
    fi

    if [[ -z "$DESTDIR" ]]; then
        # The runtime directory must exist, with these modes, before any role starts.
        if [[ "$NO_SYSTEMD" -eq 0 ]] && command -v systemd-tmpfiles >/dev/null 2>&1; then
            systemd-tmpfiles --create /etc/tmpfiles.d/acf.conf || die "systemd-tmpfiles could not apply /etc/tmpfiles.d/acf.conf"
        else
            make_root_dir "$RUNTIME_DIR" 0755
            make_root_dir "$RUNTIME_DIR/netns" 0700
            make_root_dir "$RUNTIME_DIR/expiry" 0700
            warn "$RUNTIME_DIR was created directly. It does not survive a reboot: create it (0755), $RUNTIME_DIR/netns (0700) and $RUNTIME_DIR/expiry (0700) at every boot, before any acf-host role starts."
        fi
        # /run/systemd/system exists exactly when systemd is the running service manager.
        if [[ "$NO_SYSTEMD" -eq 0 && -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1; then
            systemctl daemon-reload || die "systemctl daemon-reload failed"
        fi
        # Said, not enforced: the machine can be completed after the install.
        report_prerequisites || true
    fi

    [[ "$PREFIX" == "$DEFAULT_PREFIX" ]] || fc_prefix=" --prefix $PREFIX"
    if [[ -n "$SOCKET_GID" ]]; then
        identity="user $EDGE_USER is uid $EDGE_UID, gid $EDGE_GID: host.yaml must say edge.uid: $EDGE_UID and edge.gid: $EDGE_GID
                      group $SOCKET_GROUP is gid $SOCKET_GID: set edge.socket_gid: $SOCKET_GID to let its members reach the socket"
    elif [[ -n "$EDGE_UID" ]]; then
        identity="staged with edge.uid: $EDGE_UID and edge.gid: $EDGE_GID: the target machine's $EDGE_USER must have these ids"
    else
        identity="edge.uid and edge.gid are NOT set in a staged host.yaml: on the target machine run
                      \`host-setup.sh user\` and write the ids it prints into $ETC/host.yaml"
    fi
    cat >&2 <<EOF

Installed. Next steps (nothing has been started):
  1. scripts/install-firecracker.sh$fc_prefix
                      the pinned Firecracker and jailer (digest-verified)
  2. scripts/build-image.sh --image python --kernel VMLINUX --install
                      build and install a guest image (see images/README.md)
  3. Review the three trusted files in $ETC. They decide everything this host will do:
       host.yaml      where things live, how big this machine is, every bound
                      $identity
       profile.yaml   the safety profile: what one request may consume, which capabilities exist
       enrolment.yaml who may call this host and in which role (as shipped: root, locally, as operator)
  4. $PREFIX/bin/acf-host doctor --config $ETC/host.yaml
EOF
    if [[ "$NO_SYSTEMD" -eq 0 ]]; then
        cat >&2 <<EOF
  5. systemctl enable --now acf-cgroup.service acf-lifetime.service acf-host.service
                      in that order: control groups, the lifetime enforcer, then the core
EOF
    else
        cat >&2 <<EOF
  5. Start, in this order and under your own supervisor:
       $PREFIX/libexec/acf-setup-cgroup acf                      once per boot
       $PREFIX/bin/acf-host lifetime --config $ETC/host.yaml     always running, never stopped with the core
       $PREFIX/bin/acf-host serve --config $ETC/host.yaml        the core
EOF
    fi
}

cmd_user() {
    (($# == 0)) || die_usage "user takes no arguments"
    require_root
    ensure_identities
    printf 'edge_user=%s\nedge_uid=%s\nedge_gid=%s\nsocket_group=%s\nsocket_gid=%s\n' \
        "$EDGE_USER" "$EDGE_UID" "$EDGE_GID" "$SOCKET_GROUP" "$SOCKET_GID"
    log "in $ETC/host.yaml: edge.uid: $EDGE_UID and edge.gid: $EDGE_GID (required); edge.socket_gid: $SOCKET_GID lets members of $SOCKET_GROUP reach the socket"
}

cmd_prerequisites() {
    while (($#)); do
        case "$1" in
            --config) HOST_YAML="${2:?--config needs a file}"; shift 2 ;;
            -h | --help) usage; exit 0 ;;
            *) die_usage "unknown option: $1" ;;
        esac
    done
    [[ -r "$HOST_YAML" ]] || die "cannot read $HOST_YAML (pass --config FILE, or run: host-setup.sh install)"
    need_cmd sed
    need_cmd stat
    report_prerequisites
}

cmd_cgroup() {
    require_root
    exec sh "$REPO/scripts/acf-setup-cgroup" "$@"
}

cmd_check() {
    local arg
    for arg in "$@"; do
        [[ "$arg" == --json ]] || die_usage "check accepts only --json"
    done
    local bin="$PREFIX/bin/acf-host"
    [[ -x "$bin" ]] || bin="$REPO/target/release/acf-host"
    [[ -x "$bin" ]] || die "acf-host is not installed; run: host-setup.sh install"
    exec "$bin" doctor --config "$ETC/host.yaml" "$@"
}

main() {
    local sub="${1:-}"
    [[ $# -gt 0 ]] && shift
    case "$sub" in
        install) cmd_install "$@" ;;
        user) cmd_user "$@" ;;
        prerequisites) cmd_prerequisites "$@" ;;
        cgroup) cmd_cgroup "$@" ;;
        check) cmd_check "$@" ;;
        -h | --help | help) usage ;;
        '') usage >&2; exit "$EX_USAGE" ;;
        *) die_usage "unknown command: $sub" ;;
    esac
}

main "$@"
