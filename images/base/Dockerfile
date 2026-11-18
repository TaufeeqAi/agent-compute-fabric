# images/base/Dockerfile — Debian (slim) + the ACF guest layer. No language runtimes.
#
# Built by scripts/build-image.sh, never by hand: the script pins BASE_REF to a digest, assembles the
# build context (this file, overlay/, the guest agent, requirements.txt) and exports the resulting
# filesystem as a tarball for scripts/create-rootfs.sh. ONLY the filesystem is exported — ENV, USER,
# WORKDIR, ENTRYPOINT and CMD instructions have no effect on the guest, so none are used. Environment
# for a command comes from the request (see profiles/default.yaml) and the guest agent's default PATH.
#
# BASE_REF has no default on purpose: a build without one fails ("base name should not be blank")
# instead of silently building from whatever `latest` means today.
ARG BASE_REF
FROM ${BASE_REF}

# >>> ACF GUEST LAYER — byte-identical in every image; tests/tools/test_images.py fails if the copies drift.
# What it does, in order: install the init and the agent (copied from the build context that
# scripts/build-image.sh assembles); make sure the tools init needs exist; create the unprivileged
# user (uid/gid 1000 must equal execution.guest_uid/guest_gid in the host policy) and /workspace;
# bake the image's build time in as the guest's clock floor; make init the kernel's /sbin/init; strip
# every setuid/setgid bit (workloads run as uid 1000 and have no use for `su` or `mount`); drop caches.
ARG SOURCE_DATE_EPOCH
ARG DEBIAN_FRONTEND=noninteractive
COPY --chmod=0755 overlay/usr/local/sbin/acf-init /usr/local/sbin/acf-init
COPY --chmod=0755 acf-guest-agent /usr/local/bin/acf-guest-agent
RUN set -eux; \
    test -n "${SOURCE_DATE_EPOCH}"; \
    apt-get update; \
    apt-get install -y --no-install-recommends e2fsprogs iproute2 procps; \
    for tool in mount resize2fs ip date readlink; do command -v "${tool}" >/dev/null; done; \
    getent group 1000 >/dev/null || groupadd --gid 1000 sandbox; \
    getent passwd 1000 >/dev/null || useradd --uid 1000 --gid 1000 --create-home --shell /bin/bash sandbox; \
    install -d -m 0755 -o 1000 -g 1000 /workspace; \
    install -d -m 0755 /usr/local/share/acf; \
    printf '%s\n' "${SOURCE_DATE_EPOCH}" > /usr/local/share/acf/clock-epoch; \
    ln -sf /usr/local/sbin/acf-init /usr/sbin/init; \
    find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -exec chmod a-s {} +; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* /var/log/apt /var/log/dpkg.log /var/log/alternatives.log
# <<< ACF GUEST LAYER
