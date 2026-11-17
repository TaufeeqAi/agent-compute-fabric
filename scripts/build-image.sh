#!/usr/bin/env bash
# build-image.sh — build a bootable ACF guest image directory: kernel + rootfs + manifest.
#
#   build-image.sh --image python --kernel /path/to/vmlinux [options]
#
# An image is a directory `<state_root>/images/<name>/` holding
#     manifest.json   binds the sha256 and size of the two files below; its own sha256 IS the image id
#     vmlinux         an UNCOMPRESSED guest kernel
#     rootfs.ext4     a compact ext4 root filesystem (the guest grows it to the sandbox's disk at boot)
# This script produces that directory. Every input is pinned and checked, and nothing is trusted by name:
#
#   1. pins           images/images.lock must pin the base image (registry digest) and the kernel
#                     (sha256). An UNSET pin is a hard stop (exit 3); `--allow-unpinned` is the
#                     development escape hatch and is recorded in the manifest, so an unpinned image
#                     can never pass for a pinned one.
#   2. kernel         the file's sha256 must equal its pin; its configuration is checked for the options
#                     a guest needs (tools/check_kernel_config.py); "no embedded config" is a warning.
#   3. guest agent    a prebuilt, STATIC acf-guest-agent for the image's architecture
#                     (`make guest-agent`); verified by reading its ELF header, never by running it.
#   4. container      `docker buildx build` of images/<name>/Dockerfile from the digest-pinned base,
#                     exported as a filesystem tarball. Only the filesystem survives; see the Dockerfile.
#   5. rootfs         scripts/create-rootfs.sh: extract, check the guest requirements, mkfs.ext4 -d, fsck.
#   6. manifest       tools/write_image_manifest.py: hashes both files, records provenance.
#   7. install        (--install) copy into <state-root>/images/<name> and re-verify it there.
#
# Requires root (the rootfs is built with real ownership) and, unless --rootfs-tar is given, Docker
# with BuildKit. Building for the other architecture needs QEMU user-mode emulation (binfmt_misc).
#
# Exit codes: 0 ok | 1 error | 2 usage | 3 an input the build requires is not pinned.

# shellcheck disable=SC2034  # read by lib/common.sh
ACF_SCRIPT_NAME=build-image.sh
# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

REPO="$(repo_root)"
LOCK="$REPO/images/images.lock"
IMAGE=""
ARCH=""
KERNEL=""
AGENT=""
OUT_ROOT="$REPO/dist/images"
INSTALL=0
STATE_ROOT=/var/lib/acf
REQUIREMENTS=""
ROOTFS_TAR=""
SLACK_MIB=64
EPOCH="${SOURCE_DATE_EPOCH:-}"
EPOCH_SOURCE="the SOURCE_DATE_EPOCH environment variable"
ALLOW_UNPINNED=0
DOCKER=docker
MIN_FREE_MIB="${ACF_MIN_FREE_MIB:-4096}"
UNPINNED=()
STAGE_PARENT=""
INSTALL_STAGE=""

usage() {
    cat <<'EOF'
Usage: build-image.sh --image NAME --kernel FILE [options]

  --image NAME            which image to build: base, python, node or browser (a directory under images/)
  --kernel FILE           the guest kernel: an uncompressed vmlinux, pinned in images/images.lock
  --arch ARCH             x86_64 or aarch64                                     (default: this machine)
  --guest-agent FILE      static acf-guest-agent for ARCH   (default: target/ARCH-unknown-linux-musl/release/acf-guest-agent)
  --out-root DIR          the image is written to DIR/NAME                      (default: dist/images)
  --install               then install it into STATE_ROOT/images/NAME and re-verify it there
  --state-root DIR        where `acf-host` keeps its state                      (default: /var/lib/acf)
  --requirements FILE     hash-pinned pip requirements to bake in (python and browser images only)
  --rootfs-tar FILE       skip the container build and use this filesystem tarball (it must already contain the guest layer)
  --slack-mib N           free space left inside the image                      (default: 64)
  --source-date-epoch N   build time baked in as the guest's clock floor        (default: $SOURCE_DATE_EPOCH, else the git commit time, else now)
  --allow-unpinned        DEVELOPMENT ONLY: build although a pin in images/images.lock is UNSET; recorded in the manifest
  --docker CMD            container CLI to use                                  (default: docker)

Environment: TMPDIR (use a large, disk-backed directory; /tmp is often RAM), ACF_MIN_FREE_MIB (default 4096).
Prints `image_id=sha256:...` on stdout.
EOF
}

is_unset() { [[ -z "$1" || "$1" == UNSET ]]; }

# available_images: the names of the recipes under images/ (a recipe is a directory with a Dockerfile).
available_images() {
    local d
    for d in "$REPO"/images/*/Dockerfile; do
        d="${d%/Dockerfile}"
        printf '%s ' "${d##*/}"
    done
}

# unpinned_or_die KEY WHAT: an UNSET pin stops the build unless --allow-unpinned was given.
unpinned_or_die() {
    ((ALLOW_UNPINNED)) ||
        die_unpinned "$1 is UNSET in images/images.lock. Pin $2 there (scripts/pin-images.sh resolves base-image digests; \`sha256sum\` the kernel), or pass --allow-unpinned for a development build that the manifest will mark as unpinned."
    UNPINNED+=("$1")
}

resolve_epoch() {
    if [[ -z "$EPOCH" ]]; then
        if git -C "$REPO" rev-parse --git-dir >/dev/null 2>&1 && EPOCH="$(git -C "$REPO" log -1 --format=%ct 2>/dev/null)" && [[ -n "$EPOCH" ]]; then
            EPOCH_SOURCE="the git commit time"
        else
            EPOCH="$(date +%s)"
            EPOCH_SOURCE="the current time (set SOURCE_DATE_EPOCH for a reproducible clock floor)"
        fi
    fi
    [[ "$EPOCH" =~ ^[0-9]{9,11}$ ]] || die_usage "the build time must be seconds since the epoch, got: $EPOCH"
}

guest_agent_version() {
    python3 -I -c 'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["workspace"]["package"]["version"])' "$REPO/Cargo.toml" ||
        die "cannot read the workspace version from Cargo.toml"
}

check_kernel() {
    local rc=0
    python3 -I "$REPO/tools/check_kernel_config.py" --arch "$ARCH" "$KERNEL" || rc=$?
    case $rc in
        0) ;;
        3) warn "the kernel carries no embedded configuration, so its options could not be checked here; tests/integration boots it for real" ;;
        *) die "the guest kernel does not meet ACF's requirements (see above)" ;;
    esac
}

# assemble_context DIR: what the Dockerfile COPYs from.
assemble_context() {
    local ctx=$1
    mkdir -p -- "$ctx"
    cp -- "$REPO/images/$IMAGE/Dockerfile" "$ctx/Dockerfile"
    cp -a -- "$REPO/images/overlay" "$ctx/overlay"
    install -m 0755 -- "$AGENT" "$ctx/acf-guest-agent"
    if [[ -n "$REQUIREMENTS" ]]; then
        cp -- "$REQUIREMENTS" "$ctx/requirements.txt"
    else
        : >"$ctx/requirements.txt"
    fi
}

# build_tar CONTEXT TAR REF: build the image and export its filesystem.
build_tar() {
    local ctx=$1 tar=$2 ref=$3 platform
    need_cmd "$DOCKER" "install Docker with BuildKit, or pass --rootfs-tar"
    "$DOCKER" buildx version >/dev/null 2>&1 || die "'$DOCKER buildx' is required: BuildKit exports the filesystem as a tarball"
    case "$ARCH" in
        x86_64) platform=linux/amd64 ;;
        aarch64) platform=linux/arm64 ;;
        *) die "unsupported architecture: $ARCH" ;;
    esac
    log "building $IMAGE for $platform from $ref"
    "$DOCKER" buildx build --pull --platform "$platform" \
        --build-arg "BASE_REF=$ref" --build-arg "SOURCE_DATE_EPOCH=$EPOCH" \
        --output "type=tar,dest=$tar" "$ctx" >&2 || die "the container build failed"
}

# swap_into_place NEW FINAL: replace FINAL by NEW (same filesystem). Between the two renames FINAL is
# absent for an instant; a sandbox created in that instant fails cleanly with "image not found".
swap_into_place() {
    local new=$1 final=$2 old="$2.old.$$"
    if [[ -e "$final" ]]; then
        mv -T -- "$final" "$old"
    fi
    mv -T -- "$new" "$final"
    rm -rf -- "$old"
}

main() {
    while (($#)); do
        case "$1" in
            --image) IMAGE="${2:?--image needs a name}"; shift 2 ;;
            --kernel) KERNEL="${2:?--kernel needs a file}"; shift 2 ;;
            --arch) ARCH="${2:?--arch needs a value}"; shift 2 ;;
            --guest-agent) AGENT="${2:?--guest-agent needs a file}"; shift 2 ;;
            --out-root) OUT_ROOT="${2:?--out-root needs a directory}"; shift 2 ;;
            --install) INSTALL=1; shift ;;
            --state-root) STATE_ROOT="${2:?--state-root needs a directory}"; shift 2 ;;
            --requirements) REQUIREMENTS="${2:?--requirements needs a file}"; shift 2 ;;
            --rootfs-tar) ROOTFS_TAR="${2:?--rootfs-tar needs a file}"; shift 2 ;;
            --slack-mib) SLACK_MIB="${2:?--slack-mib needs a number}"; shift 2 ;;
            --source-date-epoch) EPOCH="${2:?--source-date-epoch needs a number}"; EPOCH_SOURCE="--source-date-epoch"; shift 2 ;;
            --allow-unpinned) ALLOW_UNPINNED=1; shift ;;
            --docker) DOCKER="${2:?--docker needs a command}"; shift 2 ;;
            -h | --help) usage; exit 0 ;;
            *) die_usage "unknown option: $1" ;;
        esac
    done
    [[ -n "$IMAGE" && -n "$KERNEL" ]] || die_usage "--image and --kernel are required"
    [[ "$IMAGE" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || die_usage "--image must be a short lower-case name (letters, digits, '-')"
    [[ -f "$REPO/images/$IMAGE/Dockerfile" ]] || die_usage "no such image: images/$IMAGE/Dockerfile (available: $(available_images))"
    [[ "$SLACK_MIB" =~ ^[0-9]+$ ]] || die_usage "--slack-mib must be a non-negative integer"
    [[ "$MIN_FREE_MIB" =~ ^[0-9]+$ ]] || die_usage "ACF_MIN_FREE_MIB must be a non-negative integer"
    if [[ -n "$REQUIREMENTS" ]]; then
        [[ "$IMAGE" == python || "$IMAGE" == browser ]] || die_usage "--requirements applies to the python and browser images only"
        [[ -f "$REQUIREMENTS" ]] || die "not a file: $REQUIREMENTS"
        grep -qE '^[^#]*--hash=sha256:' "$REQUIREMENTS" || die "$REQUIREMENTS has no --hash=sha256:... entries; the build installs with --require-hashes"
    fi
    ARCH="${ARCH:-$(host_arch)}"
    [[ "$ARCH" == x86_64 || "$ARCH" == aarch64 ]] || die_usage "--arch must be x86_64 or aarch64"
    [[ -n "$AGENT" ]] || AGENT="$REPO/target/$ARCH-unknown-linux-musl/release/acf-guest-agent"
    for c in python3 sha256sum install cp mv df; do need_cmd "$c"; done

    # --- 1. pins ---------------------------------------------------------------------------------
    local base_ref base_digest kernel_pin
    base_ref="$(lock_get "$LOCK" "BASE_REF_$IMAGE")"
    base_digest="$(lock_get "$LOCK" "BASE_DIGEST_$IMAGE")"
    kernel_pin="$(lock_get "$LOCK" "KERNEL_SHA256_$ARCH")"
    if [[ -z "$ROOTFS_TAR" ]]; then
        if is_unset "$base_digest"; then
            unpinned_or_die "BASE_DIGEST_$IMAGE" "the base image's digest"
            base_digest=""
        fi
    fi
    if is_unset "$kernel_pin"; then
        unpinned_or_die "KERNEL_SHA256_$ARCH" "the guest kernel's sha256"
        kernel_pin=""
    fi

    # --- 2. kernel -------------------------------------------------------------------------------
    [[ -f "$KERNEL" && ! -L "$KERNEL" ]] || die "the kernel must be a regular file (not a symlink): $KERNEL"
    local kernel_sha
    kernel_sha="$(sha256_file "$KERNEL")"
    if [[ -n "$kernel_pin" && "$kernel_sha" != "$kernel_pin" ]]; then
        die "the kernel hashes to $kernel_sha but images/images.lock pins KERNEL_SHA256_$ARCH=$kernel_pin"
    fi
    check_kernel

    # --- 3. guest agent --------------------------------------------------------------------------
    local agent_sha=""
    if [[ -z "$ROOTFS_TAR" ]]; then
        [[ -f "$AGENT" && ! -L "$AGENT" ]] || die "no guest agent at $AGENT (build it with \`make guest-agent\`, or pass --guest-agent)"
        python3 -I "$REPO/tools/elf_info.py" --arch "$ARCH" --static "$AGENT" >/dev/null || die "the guest agent is not a static $ARCH executable (see above)"
        agent_sha="$(sha256_file "$AGENT")"
    fi

    resolve_epoch
    log "guest clock floor: $EPOCH (from $EPOCH_SOURCE)"
    local version
    version="$(guest_agent_version)"

    # --- 4. container build ----------------------------------------------------------------------
    # Everything above only reads; from here the build needs root (the rootfs keeps real ownership).
    require_root
    make_workdir acf-image
    mkdir -p -- "$OUT_ROOT"
    STAGE_PARENT="$(mktemp -d "$OUT_ROOT/.stage.XXXXXXXX")" || die "cannot create a staging directory in $OUT_ROOT"
    trap 'rm -rf -- "${ACF_WORKDIR:-}" "${STAGE_PARENT:-}" "${INSTALL_STAGE:-}"' EXIT
    require_free_mib "$ACF_WORKDIR" "$MIN_FREE_MIB" "building the $IMAGE image"

    local tar ref pinned
    if [[ -n "$ROOTFS_TAR" ]]; then
        [[ -f "$ROOTFS_TAR" ]] || die "not a file: $ROOTFS_TAR"
        tar="$ROOTFS_TAR"
        ref="external-rootfs-tarball sha256:$(sha256_file "$ROOTFS_TAR")"
        pinned="external-rootfs"
    else
        tar="$ACF_WORKDIR/rootfs.tar"
        ref="$base_ref"
        [[ -z "$base_digest" ]] || ref="$base_ref@$base_digest"
        assemble_context "$ACF_WORKDIR/context"
        build_tar "$ACF_WORKDIR/context" "$tar" "$ref"
        pinned=yes
    fi
    ((${#UNPINNED[@]} == 0)) || pinned=no

    # --- 5. rootfs -------------------------------------------------------------------------------
    local dir="$STAGE_PARENT/$IMAGE"
    mkdir -p -- "$dir"
    "$REPO/scripts/create-rootfs.sh" --tar "$tar" --out "$dir/rootfs.ext4" --slack-mib "$SLACK_MIB" --label "acf-$IMAGE" \
        --exec /sbin/init --exec /usr/local/sbin/acf-init --exec /usr/local/bin/acf-guest-agent \
        --exec /sbin/resize2fs --exec /bin/mount \
        --dir /workspace --dir /var/lib --owner /workspace=1000:1000
    install -m 0644 -- "$KERNEL" "$dir/vmlinux"

    # --- 6. manifest -----------------------------------------------------------------------------
    local git_rev="none"
    git -C "$REPO" rev-parse HEAD >/dev/null 2>&1 && git_rev="$(git -C "$REPO" rev-parse --short=12 HEAD)"
    local provenance="acf-image-build/1; image=$IMAGE; arch=$ARCH; base=$ref; kernel_sha256=$kernel_sha; agent_sha256=${agent_sha:-external}; source_date_epoch=$EPOCH; git=$git_rev; pinned=$pinned"
    ((${#UNPINNED[@]} == 0)) || provenance+="; unpinned=$(IFS=,; printf '%s' "${UNPINNED[*]}")"
    local out id
    out="$(python3 -I "$REPO/tools/write_image_manifest.py" write --dir "$dir" --arch "$ARCH" --guest-agent-version "$version" --provenance "$provenance")" ||
        die "cannot write the manifest"
    id="${out#image_id=}"
    python3 -I "$REPO/tools/write_image_manifest.py" verify --dir "$dir" >/dev/null || die "the image we just built does not verify"

    mkdir -p -- "$OUT_ROOT"
    swap_into_place "$dir" "$OUT_ROOT/$IMAGE"
    local rootfs_bytes
    rootfs_bytes="$(stat -c %s -- "$OUT_ROOT/$IMAGE/rootfs.ext4")"

    # --- 7. install ------------------------------------------------------------------------------
    if ((INSTALL)); then
        local images_dir="$STATE_ROOT/images" staged
        install -d -m 0755 -o root -g root -- "$images_dir"
        staged="$(mktemp -d "$images_dir/.stage.XXXXXXXX")"
        INSTALL_STAGE="$staged"
        mkdir -p -- "$staged/$IMAGE"
        cp -- "$OUT_ROOT/$IMAGE/"{manifest.json,vmlinux,rootfs.ext4} "$staged/$IMAGE/"
        chown -R root:root -- "$staged"
        chmod 0755 -- "$staged" "$staged/$IMAGE"
        chmod 0644 -- "$staged/$IMAGE/"{manifest.json,vmlinux,rootfs.ext4}
        python3 -I "$REPO/tools/write_image_manifest.py" verify --dir "$staged/$IMAGE" >/dev/null || die "the installed copy does not verify"
        swap_into_place "$staged/$IMAGE" "$images_dir/$IMAGE"
        log "installed into $images_dir/$IMAGE"
    fi

    log "built $IMAGE ($ARCH): image id $id"
    log "  rootfs $(human_mib "$rootfs_bytes") MiB: a sandbox needs --disk at least that large (the host refuses less)"
    log "  provenance: $provenance"
    if [[ "$pinned" == external-rootfs ]]; then
        warn "the root filesystem came from an external tarball: only its sha256 is recorded, so the image is only as trustworthy as that tarball"
    fi
    if ((${#UNPINNED[@]})); then
        warn "this image is NOT fully pinned (unpinned: ${UNPINNED[*]}); do not ship it"
    fi
    printf 'image_id=%s\n' "$id"
}

main "$@"
