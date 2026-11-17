#!/usr/bin/env bash
# install-firecracker.sh — install the pinned Firecracker and jailer binaries.
#
#   install-firecracker.sh [--prefix DIR] [--from-tarball FILE] [--sha256 HEX] [--destdir DIR]
#   install-firecracker.sh --print-digest [--from-tarball FILE]
#
# Why a script and not "download the latest":
#   * a Firecracker snapshot is only valid on the exact version that took it;
#   * `acf-host` executes these binaries as root, and refuses them unless they are root-owned,
#     not group/world-writable, in root-owned non-writable directories, and exactly the pinned version.
#
# So the release version and the tarball's sha256 are pinned in scripts/firecracker.lock, the digest is
# verified BEFORE anything is extracted, only the two binaries we need are extracted (by exact name),
# each is version-checked before it is installed, and installation is an atomic rename.
#
# A digest that is UNSET in the lock is a hard stop (exit 3), never a silent skip. `--sha256 HEX`
# supplies a digest you verified out-of-band for this one run (it does not edit the lock).

# shellcheck disable=SC2034  # read by lib/common.sh
ACF_SCRIPT_NAME=install-firecracker.sh
# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

REPO="$(repo_root)"
LOCK="$REPO/scripts/firecracker.lock"
PREFIX=/opt/acf
DESTDIR=""
TARBALL=""
OVERRIDE_SHA=""
PRINT_DIGEST=0
MAX_DOWNLOAD_BYTES=$((256 * 1024 * 1024))

usage() {
    cat <<'EOF'
Usage:
  install-firecracker.sh [--prefix DIR] [--from-tarball FILE] [--sha256 HEX] [--destdir DIR]
  install-firecracker.sh --print-digest [--from-tarball FILE]

  --prefix DIR         install to DIR/bin/{firecracker,jailer}        (default /opt/acf)
  --from-tarball FILE  use a tarball you already have (air-gapped hosts) instead of downloading
  --sha256 HEX         expected digest, verified by you out-of-band; overrides the lock for this run
  --destdir DIR        stage under DIR (packaging, tests)
  --print-digest       download (or read) the tarball and print its sha256; installs nothing, needs no root

The pinned version and digests live in scripts/firecracker.lock.
EOF
}

# member_exists LISTING NAME: exact-line match in a `tar -t` listing.
member_exists() { grep -Fxq -- "$2" <<<"$1"; }

# check_version BIN WHAT: the binary must report exactly the pinned version.
check_version() {
    local bin=$1 what=$2 out
    out="$("$bin" --version 2>&1 | head -n 1)" || die "$what: cannot run --version"
    if [[ "$out" != *"$VERSION"* ]]; then
        die "$what reports '$out' but the pin is $VERSION"
    fi
}

fetch() {
    local url=$1 dest=$2
    need_cmd curl
    log "downloading $url"
    # HTTPS only, TLS >= 1.2, bounded size, retried; the digest check below is the real gate.
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
        --retry 3 --max-filesize "$MAX_DOWNLOAD_BYTES" --output "$dest" -- "$url" ||
        die "download failed: $url (is github.com reachable from this host? use --from-tarball)"
}

main() {
    while (($#)); do
        case "$1" in
            --prefix) PREFIX="${2:?--prefix needs a value}"; shift 2 ;;
            --from-tarball) TARBALL="${2:?--from-tarball needs a file}"; shift 2 ;;
            --sha256) OVERRIDE_SHA="${2:?--sha256 needs a value}"; shift 2 ;;
            --destdir) DESTDIR="${2:?--destdir needs a value}"; shift 2 ;;
            --print-digest) PRINT_DIGEST=1; shift ;;
            -h | --help) usage; exit 0 ;;
            *) die_usage "unknown option: $1" ;;
        esac
    done
    [[ "$PREFIX" == /* ]] || die_usage "--prefix must be an absolute path"
    [[ -z "$DESTDIR" || "$DESTDIR" == /* ]] || die_usage "--destdir must be an absolute path"
    [[ -z "$OVERRIDE_SHA" ]] || is_sha256 "$OVERRIDE_SHA" || die_usage "--sha256 must be 64 lowercase hex characters"
    need_cmd tar
    need_cmd sha256sum
    need_cmd grep

    VERSION="$(lock_get "$LOCK" VERSION)"
    [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "$LOCK: VERSION must look like v1.17.0, got '$VERSION'"
    local arch name url
    arch="$(host_arch)"
    name="firecracker-${VERSION}-${arch}.tgz"
    url="https://github.com/firecracker-microvm/firecracker/releases/download/${VERSION}/${name}"

    make_workdir acf-fc
    local tgz="$ACF_WORKDIR/$name"
    if [[ -n "$TARBALL" ]]; then
        [[ -f "$TARBALL" ]] || die "not a file: $TARBALL"
        cp -- "$TARBALL" "$tgz"
    else
        fetch "$url" "$tgz"
    fi
    local actual
    actual="$(sha256_file "$tgz")"

    if [[ "$PRINT_DIGEST" -eq 1 ]]; then
        printf '%s  %s\n' "$actual" "$name"
        log "compare this with the release page's ${name}.sha256.txt and the GitHub API digest before pinning"
        return 0
    fi

    require_root
    need_cmd install
    local expected="$OVERRIDE_SHA"
    if [[ -z "$expected" ]]; then
        expected="$(lock_get "$LOCK" "SHA256_${arch}")"
        if [[ -z "$expected" || "$expected" == "UNSET" ]]; then
            die_unpinned "SHA256_${arch} is UNSET in $LOCK. The tarball I measured is $actual — compare it with the release page's ${name}.sha256.txt, pin it in the lock (or pass --sha256 once), then re-run. Refusing to install an unverified root-executed binary."
        fi
    fi
    is_sha256 "$expected" || die "expected digest is not 64 lowercase hex characters: $expected"
    [[ "$actual" == "$expected" ]] || die "sha256 mismatch for $name: expected $expected, got $actual. Nothing was extracted or installed."
    log "digest verified: $actual"

    # Extract exactly the two members we need, by exact name, never the rest of the archive.
    local dir="release-${VERSION}-${arch}"
    local fc_member="$dir/firecracker-${VERSION}-${arch}" jl_member="$dir/jailer-${VERSION}-${arch}"
    local listing
    listing="$(tar -tzf "$tgz")" || die "$name is not a readable gzip tarball"
    member_exists "$listing" "$fc_member" || die "$name has no member $fc_member (upstream layout changed? first entries: $(head -n 5 <<<"$listing" | tr '\n' ' '))"
    member_exists "$listing" "$jl_member" || die "$name has no member $jl_member"
    local stage="$ACF_WORKDIR/x"
    mkdir -p -- "$stage"
    tar -xzf "$tgz" -C "$stage" --no-same-owner --no-same-permissions -- "$fc_member" "$jl_member"
    chmod 0755 -- "$stage/$fc_member" "$stage/$jl_member"

    # Prove each binary is the pinned version BEFORE it is installed (it is digest-verified, so
    # running it as root to ask for its version is as safe as installing it).
    check_version "$stage/$fc_member" firecracker
    check_version "$stage/$jl_member" jailer

    local bindir="${DESTDIR}${PREFIX}/bin"
    install -d -m 0755 -o root -g root -- "${DESTDIR}${PREFIX}" "$bindir"
    chown root:root -- "${DESTDIR}${PREFIX}" "$bindir"
    chmod 0755 -- "${DESTDIR}${PREFIX}" "$bindir"
    install -m 0755 -o root -g root -- "$stage/$fc_member" "$bindir/.firecracker.new.$$"
    install -m 0755 -o root -g root -- "$stage/$jl_member" "$bindir/.jailer.new.$$"
    mv -f -- "$bindir/.firecracker.new.$$" "$bindir/firecracker"
    mv -f -- "$bindir/.jailer.new.$$" "$bindir/jailer"

    log "installed $bindir/firecracker and $bindir/jailer ($VERSION, $arch)"
    log "make sure firecracker.pinned_version is $VERSION in /etc/acf/host.yaml, then run: acf-host doctor"
}

main "$@"
