#!/usr/bin/env bash
# create-rootfs.sh — turn a root filesystem tarball into a minimal, bootable ext4 image.
#
#   create-rootfs.sh --tar ROOTFS.tar --out ROOTFS.ext4 [options]
#
# Input is the tarball of a container's filesystem (`docker buildx build --output type=tar`,
# `docker export`, `podman export`, ...). Output is one ext4 file, sized to its contents plus a little
# slack, ready for Firecracker as the root drive.
#
# How (the pattern Firecracker's own getting-started guide uses: `mkfs.ext4 -d <dir>`):
#   1. extract the tarball as root with numeric ownership and modes preserved;
#   2. check the guest requirements against the *extracted tree* (tools/rootfs_check.py resolves
#      symlinks inside the tree, so merged-usr images are judged as the guest will see them);
#   3. size the image from the tree, then `mkfs.ext4 -d` it — no loop mounts, no chroot, no copying
#      through a mounted filesystem, and no guest binary is ever executed on the build host;
#   4. `e2fsck -fn` the result and move it into place atomically.
#
# The image is deliberately SMALL. The host agent refuses a sandbox whose disk is smaller than the
# image, grows the file to the requested disk size (sparse), and the guest grows the filesystem into
# it at boot (resize2fs) — see images/overlay/usr/local/sbin/acf-init. A big image here would make
# every sandbox pay for space it never uses.
#
# The tarball is extracted as root: only feed it output of a build you trust.
#
# Options:
#   --slack-mib N     free space to leave in the image                  (default 64)
#   --label NAME      filesystem label, at most 16 bytes                (default acf-rootfs)
#   --exec PATH       guest path that must be an executable file        (repeatable)
#   --dir PATH        guest path that must be a directory               (repeatable)
#   --owner P=U:G     guest path that must be owned by UID:GID          (repeatable)

# shellcheck disable=SC2034  # read by lib/common.sh
ACF_SCRIPT_NAME=create-rootfs.sh
# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

REPO="$(repo_root)"
TAR=""
OUT=""
SLACK_MIB=64
LABEL="acf-rootfs"
REQ_ARGS=()

usage() {
    cat <<'EOF'
Usage: create-rootfs.sh --tar ROOTFS.tar --out ROOTFS.ext4 [--slack-mib N] [--label NAME]
                        [--exec PATH]... [--dir PATH]... [--owner PATH=UID:GID]...
EOF
}

# build_image STAGE OUT_TMP SIZE_MIB LABEL: one mkfs attempt; returns non-zero if it does not fit.
build_image() {
    local stage=$1 out=$2 size_mib=$3 label=$4
    rm -f -- "$out"
    truncate -s "${size_mib}M" -- "$out"
    MKE2FS_CONFIG="$REPO/scripts/mke2fs.conf" \
        mkfs.ext4 -q -F -t ext4 -m 0 -L "$label" -E root_owner=0:0 -d "$stage" -- "$out"
}

main() {
    while (($#)); do
        case "$1" in
            --tar) TAR="${2:?--tar needs a file}"; shift 2 ;;
            --out) OUT="${2:?--out needs a file}"; shift 2 ;;
            --slack-mib) SLACK_MIB="${2:?--slack-mib needs a number}"; shift 2 ;;
            --label) LABEL="${2:?--label needs a value}"; shift 2 ;;
            --exec | --dir | --owner) REQ_ARGS+=("$1" "${2:?$1 needs a value}"); shift 2 ;;
            -h | --help) usage; exit 0 ;;
            *) die_usage "unknown option: $1" ;;
        esac
    done
    [[ -n "$TAR" && -n "$OUT" ]] || die_usage "--tar and --out are required"
    [[ -f "$TAR" ]] || die "not a file: $TAR"
    [[ "$SLACK_MIB" =~ ^[0-9]+$ ]] || die_usage "--slack-mib must be a non-negative integer"
    require_root
    for c in tar mkfs.ext4 e2fsck truncate du python3; do need_cmd "$c"; done

    make_workdir acf-rootfs
    # stage (~ the tarball) + the image (~ the tarball) + slack; a compressed tarball needs more.
    require_free_mib "$ACF_WORKDIR" $(($(human_mib "$(stat -c %s -- "$TAR")") * 3 + 256)) "building an image from $TAR"
    local stage="$ACF_WORKDIR/stage"
    mkdir -p -- "$stage"

    log "extracting $TAR"
    tar --extract --file "$TAR" --directory "$stage" --numeric-owner --same-owner --preserve-permissions ||
        die "cannot extract $TAR"
    # Mount points the guest init needs, whatever the source image did or did not ship.
    mkdir -p -- "$stage/dev" "$stage/proc" "$stage/sys" "$stage/run" "$stage/tmp"
    chmod 1777 -- "$stage/tmp"
    rm -f -- "$stage/.dockerenv"

    if ((${#REQ_ARGS[@]})); then
        log "checking guest requirements"
        python3 -I "$REPO/tools/rootfs_check.py" --root "$stage" --quiet "${REQ_ARGS[@]}" ||
            die "the root filesystem does not meet the guest requirements listed above"
    fi

    # Allocated blocks (not apparent size): thousands of small files each waste part of a 4 KiB block.
    local used_mib size_mib attempt tmp="$OUT.tmp.$$"
    used_mib="$(du -sm -- "$stage" | awk '{print $1}')"
    trap 'rm -f -- "$tmp"; rm -rf -- "${ACF_WORKDIR:-}"' EXIT
    for attempt in 1 2 3 4 5; do
        # 8% inode tables/bitmaps/descriptors + 16 MiB journal, +25% per retry, + the caller's slack.
        size_mib=$((used_mib * (108 + 25 * (attempt - 1)) / 100 + 16 + SLACK_MIB))
        log "attempt $attempt: ${used_mib} MiB of content -> ${size_mib} MiB image"
        if build_image "$stage" "$tmp" "$size_mib" "${LABEL:0:16}" 2>"$ACF_WORKDIR/mkfs.err"; then
            break
        fi
        if ((attempt == 5)); then
            cat "$ACF_WORKDIR/mkfs.err" >&2
            die "mkfs.ext4 could not populate the image even at ${size_mib} MiB"
        fi
    done

    e2fsck -fn -- "$tmp" >"$ACF_WORKDIR/fsck.out" 2>&1 || {
        cat "$ACF_WORKDIR/fsck.out" >&2
        die "the new image failed e2fsck"
    }
    mv -f -- "$tmp" "$OUT"
    trap 'rm -rf -- "${ACF_WORKDIR:-}"' EXIT
    log "wrote $OUT ($(stat -c %s -- "$OUT") bytes, ${size_mib} MiB, e2fsck clean)"
}

main "$@"
