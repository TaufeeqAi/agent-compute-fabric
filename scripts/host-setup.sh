#!/usr/bin/env bash
# host-setup.sh — prepare a machine to run the ACF Phase 1 host agent.
#
#   host-setup.sh install [options]   create directories, install the agent, units and defaults
#   host-setup.sh cgroup  [PARENT]    (re)create the cgroup v2 parent for sandbox VMs
#   host-setup.sh check               run `acf-host doctor` (does this machine honour the profile?)
#
# `install` is idempotent and conservative:
#   * it never overwrites an operator's /etc/acf/host.yaml or /etc/acf/policy.yaml (the shipped
#     version is written next to it as *.dist when they differ; --force-config replaces them)
#   * it refuses to install an `acf-host` that contains test-only code (scripts/check-release-purity.sh)
#   * it does not enable or start the service: that is an operator decision, printed as a next step
#
# Layout it creates (all root:root; nothing group/world-writable, because `acf-host` refuses to trust
# files, binaries or ancestor directories that an unprivileged user could replace):
#   /opt/acf/bin/acf-host            the agent            (firecracker + jailer: install-firecracker.sh)
#   /opt/acf/libexec/acf-setup-cgroup
#   /etc/acf/host.yaml, policy.yaml  configuration and policy
#   /var/lib/acf/                    durable state, 0700
#   /run/acf/                        runtime (socket), via systemd-tmpfiles
#
# --destdir DIR prefixes every absolute path (like `make DESTDIR`) and skips systemctl/tmpfiles:
# for packaging and for testing this script without touching the machine.

# shellcheck disable=SC2034  # read by lib/common.sh
ACF_SCRIPT_NAME=host-setup.sh
# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

REPO="$(repo_root)"
PREFIX=/opt/acf
ETC=/etc/acf
STATE_ROOT=/var/lib/acf
DESTDIR=""
ACF_HOST_BIN=""
NO_SYSTEMD=0
FORCE_CONFIG=0

usage() {
    cat <<'EOF'
Usage:
  host-setup.sh install [--prefix DIR] [--acf-host FILE] [--state-root DIR] [--destdir DIR]
                        [--no-systemd] [--force-config]
  host-setup.sh cgroup  [PARENT]
  host-setup.sh check

install options:
  --prefix DIR       installation prefix                     (default /opt/acf)
  --acf-host FILE    release acf-host binary to install      (default target/release/acf-host)
  --state-root DIR   durable state directory                 (default /var/lib/acf)
  --destdir DIR      stage everything under DIR; skips systemctl and tmpfiles (packaging, tests)
  --no-systemd       do not install the systemd units or tmpfiles.d entry
  --force-config     overwrite /etc/acf/host.yaml and policy.yaml with the shipped examples
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

cmd_install() {
    while (($#)); do
        case "$1" in
            --prefix) PREFIX="${2:?--prefix needs a value}"; shift 2 ;;
            --acf-host) ACF_HOST_BIN="${2:?--acf-host needs a value}"; shift 2 ;;
            --state-root) STATE_ROOT="${2:?--state-root needs a value}"; shift 2 ;;
            --destdir) DESTDIR="${2:?--destdir needs a value}"; shift 2 ;;
            --no-systemd) NO_SYSTEMD=1; shift ;;
            --force-config) FORCE_CONFIG=1; shift ;;
            -h | --help) usage; exit 0 ;;
            *) die_usage "unknown option: $1" ;;
        esac
    done
    [[ "$PREFIX" == /* && "$STATE_ROOT" == /* ]] || die_usage "--prefix and --state-root must be absolute paths"
    [[ -z "$DESTDIR" || "$DESTDIR" == /* ]] || die_usage "--destdir must be an absolute path"
    require_root
    need_cmd install
    need_cmd cmp

    ACF_HOST_BIN="${ACF_HOST_BIN:-$REPO/target/release/acf-host}"
    [[ -f "$ACF_HOST_BIN" && -x "$ACF_HOST_BIN" ]] ||
        die "no acf-host binary at $ACF_HOST_BIN (build it: make release, or pass --acf-host FILE)"
    log "checking that $ACF_HOST_BIN contains no test-only code"
    "$REPO/scripts/check-release-purity.sh" "$ACF_HOST_BIN"

    # Directories. Every component below the root must stay root-owned and not group/world-writable.
    make_root_dir "$(dpath "$PREFIX")" 0755
    make_root_dir "$(dpath "$PREFIX/bin")" 0755
    make_root_dir "$(dpath "$PREFIX/libexec")" 0755
    make_root_dir "$(dpath "$ETC")" 0755
    make_root_dir "$(dpath "$STATE_ROOT")" 0700
    make_root_dir "$(dpath "$STATE_ROOT/images")" 0755

    install_file "$ACF_HOST_BIN" "$(dpath "$PREFIX/bin/acf-host")" 0755
    install_file "$REPO/scripts/acf-setup-cgroup" "$(dpath "$PREFIX/libexec/acf-setup-cgroup")" 0755
    install_config "$REPO/config/host.example.yaml" "$(dpath "$ETC/host.yaml")"
    install_config "$REPO/policies/default.yaml" "$(dpath "$ETC/policy.yaml")"

    if [[ "$NO_SYSTEMD" -eq 0 ]]; then
        make_root_dir "$(dpath /etc/systemd/system)" 0755
        make_root_dir "$(dpath /etc/tmpfiles.d)" 0755
        install_file "$REPO/deploy/systemd/acf-cgroup.service" "$(dpath /etc/systemd/system/acf-cgroup.service)" 0644
        install_file "$REPO/deploy/systemd/acf-host.service" "$(dpath /etc/systemd/system/acf-host.service)" 0644
        install_file "$REPO/deploy/tmpfiles.d/acf.conf" "$(dpath /etc/tmpfiles.d/acf.conf)" 0644
        if [[ -z "$DESTDIR" ]]; then
            command -v systemd-tmpfiles >/dev/null 2>&1 && systemd-tmpfiles --create /etc/tmpfiles.d/acf.conf
            command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload
        fi
    fi

    cat >&2 <<EOF

Installed. Next steps (nothing has been started):
  1. scripts/install-firecracker.sh                 pinned Firecracker + jailer (digest-verified)
  2. scripts/build-image.sh --image python --kernel VMLINUX --install
                                                     build and install a guest image (see images/README.md)
  3. $PREFIX/bin/acf-host doctor --config $ETC/host.yaml
  4. systemctl enable --now acf-host.service
Review $ETC/policy.yaml and $ETC/host.yaml first: they define who may connect and what they may do.
EOF
}

cmd_cgroup() {
    require_root
    exec "$REPO/scripts/acf-setup-cgroup" "$@"
}

cmd_check() {
    local bin="$PREFIX/bin/acf-host"
    [[ -x "$bin" ]] || bin="$REPO/target/release/acf-host"
    [[ -x "$bin" ]] || die "acf-host is not installed; run: host-setup.sh install"
    exec "$bin" doctor --config "$ETC/host.yaml"
}

main() {
    local sub="${1:-}"
    [[ $# -gt 0 ]] && shift
    case "$sub" in
        install) cmd_install "$@" ;;
        cgroup) cmd_cgroup "$@" ;;
        check) cmd_check ;;
        -h | --help | help) usage ;;
        '') usage >&2; exit "$EX_USAGE" ;;
        *) die_usage "unknown command: $sub" ;;
    esac
}

main "$@"
