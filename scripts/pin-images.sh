#!/usr/bin/env bash
# pin-images.sh — resolve the base-image tags in images/images.lock to registry digests.
#
#   pin-images.sh                 print BASE_DIGEST_<name>=sha256:... for every BASE_REF_<name>
#   pin-images.sh --write         ... and write them into images/images.lock (comments are preserved)
#   pin-images.sh --verify        resolve again and FAIL if a pinned digest is not what its tag points to now
#
# A tag is a moving target ("3.14-slim-trixie" is re-pointed at every rebuild); a digest is the content.
# build-image.sh builds only from a digest, so bumping a base image is a deliberate, reviewable edit:
#
#   1. change BASE_REF_<name> (or do nothing, to pick up the latest rebuild of the same tag)
#   2. scripts/pin-images.sh --write
#   3. commit images/images.lock and review the diff like any dependency bump
#
# --verify is the drift detector: run it on a schedule to learn that a tag moved (a security rebuild you
# want to pick up) or vanished (a tag removed from the registry, which you want to know BEFORE a build).
#
# The digest pinned is that of the tag's top-level manifest — the multi-architecture index — so the same
# pin serves x86_64 and aarch64 builds.
#
# Resolution needs one of: crane (go-containerregistry), skopeo, or docker with buildx. A tag that does
# not exist makes this fail loudly; nothing is guessed.

# shellcheck disable=SC2034  # read by lib/common.sh
ACF_SCRIPT_NAME=pin-images.sh
# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

REPO="$(repo_root)"
LOCK="$REPO/images/images.lock"
WRITE=0
VERIFY=0
TOOL=""
ONLY=""

usage() {
    cat <<'EOF'
Usage: pin-images.sh [--write | --verify] [--only NAME] [--tool crane|skopeo|docker] [--lock FILE]

  --write       update BASE_DIGEST_<name> in the lock file
  --verify      exit 1 if any pinned digest differs from what its tag resolves to now (UNSET counts as differing)
  --only NAME   just this image (base, python, node, browser)
  --tool T      how to talk to the registry          (default: the first of crane, skopeo, docker found)
  --lock FILE   the lock file                        (default: images/images.lock)
EOF
}

pick_tool() {
    if [[ -n "$TOOL" ]]; then
        need_cmd "$TOOL"
        return
    fi
    local t
    for t in crane skopeo docker; do
        if command -v "$t" >/dev/null 2>&1; then
            TOOL=$t
            return
        fi
    done
    die "need one of crane, skopeo or docker (with buildx) to talk to the registry"
}

# resolve_digest REF: print the sha256:... digest REF's tag points to.
resolve_digest() {
    local ref=$1 out
    case "$TOOL" in
        crane) out="$(crane digest "$ref")" ;;
        skopeo) out="$(skopeo inspect --no-tags --format '{{.Digest}}' "docker://$ref")" ;;
        # The digest of a manifest is the sha256 of its exact bytes, so hash what the registry returned.
        docker) out="sha256:$(docker buildx imagetools inspect --raw "$ref" | sha256sum | cut -d' ' -f1)" ;;
        *) die "unknown --tool: $TOOL" ;;
    esac || die "$TOOL could not resolve $ref (does the tag exist? is the registry reachable?)"
    [[ "$out" =~ ^sha256:[0-9a-f]{64}$ ]] || die "$TOOL returned something that is not a digest for $ref: $out"
    printf '%s\n' "$out"
}

# rewrite_lock FILE KEY=VALUE...: replace those keys' values in place, keeping every other line, comments included.
rewrite_lock() {
    local file=$1 tmp line key kv
    shift
    local -A want=()
    for kv in "$@"; do
        want["${kv%%=*}"]="${kv#*=}"
    done
    tmp="$(mktemp "$file.XXXXXXXX")"
    while IFS= read -r line || [[ -n "$line" ]]; do
        key="${line%%=*}"
        if [[ "$line" =~ ^[A-Za-z0-9_]+= && -n "${want[$key]+set}" ]]; then
            printf '%s=%s\n' "$key" "${want[$key]}"
            unset "want[$key]"
        else
            printf '%s\n' "$line"
        fi
    done <"$file" >"$tmp"
    if ((${#want[@]})); then
        rm -f -- "$tmp"
        die "not found in $file: ${!want[*]}"
    fi
    chmod --reference="$file" -- "$tmp"
    mv -f -- "$tmp" "$file"
}

main() {
    while (($#)); do
        case "$1" in
            --write) WRITE=1; shift ;;
            --verify) VERIFY=1; shift ;;
            --only) ONLY="${2:?--only needs a name}"; shift 2 ;;
            --tool) TOOL="${2:?--tool needs a name}"; shift 2 ;;
            --lock) LOCK="${2:?--lock needs a file}"; shift 2 ;;
            -h | --help) usage; exit 0 ;;
            *) die_usage "unknown option: $1" ;;
        esac
    done
    ((WRITE + VERIFY <= 1)) || die_usage "--write and --verify are mutually exclusive"
    pick_tool

    local names=() key name ref have want drift=0
    while IFS= read -r key; do
        name="${key#BASE_REF_}"
        if [[ -z "$ONLY" || "$ONLY" == "$name" ]]; then
            names+=("$name")
        fi
    done < <(lock_keys "$LOCK" BASE_REF_)
    ((${#names[@]})) || die "no BASE_REF_* entries${ONLY:+ for $ONLY} in $LOCK"

    local updates=()
    for name in "${names[@]}"; do
        ref="$(lock_get "$LOCK" "BASE_REF_$name")"
        have="$(lock_get "$LOCK" "BASE_DIGEST_$name")"
        want="$(resolve_digest "$ref")"
        if ((VERIFY)); then
            if [[ "$have" == "$want" ]]; then
                log "ok      $name  $ref  $want"
            else
                log "DRIFT   $name  $ref  pinned=${have:-<none>} registry=$want"
                drift=1
            fi
        else
            printf 'BASE_DIGEST_%s=%s\n' "$name" "$want"
            updates+=("BASE_DIGEST_$name=$want")
        fi
    done
    if ((VERIFY)); then
        exit "$drift"
    fi
    if ((WRITE)); then
        rewrite_lock "$LOCK" "${updates[@]}"
        log "updated $LOCK"
    fi
}

main "$@"
