# images/browser/Dockerfile — Python + headless Chromium + the ACF guest layer (experimental).
#
# Built by scripts/build-image.sh, never by hand: the script pins BASE_REF to a digest, assembles the
# build context (this file, overlay/, the guest agent, requirements.txt) and exports the resulting
# filesystem as a tarball for scripts/create-rootfs.sh. ONLY the filesystem is exported — ENV, USER,
# WORKDIR, ENTRYPOINT and CMD instructions have no effect on the guest, so none are used. Environment
# for a command comes from the request (see policies/default.yaml) and the guest agent's default PATH.
#
# BASE_REF has no default on purpose: a build without one fails ("base name should not be blank")
# instead of silently building from whatever `latest` means today.
ARG BASE_REF
FROM ${BASE_REF}

# Headless Chromium from the Debian archive, on top of the Python image's base (so Python drivers such as
# Playwright's or Selenium's can talk to it). EXPERIMENTAL: not exercised by the Phase 1 test-suite.
#
# The guest layer below strips every setuid bit, including Chromium's `chrome-sandbox`, so run it with
# `--no-sandbox --headless --disable-gpu --disable-dev-shm-usage`. That is the normal way to run Chromium
# in a container, and here the microVM, not Chromium's own sandbox, is the isolation boundary.
COPY requirements.txt /tmp/acf-requirements.txt
RUN set -eux; \
    export DEBIAN_FRONTEND=noninteractive; \
    apt-get update; \
    apt-get install -y --no-install-recommends chromium fonts-liberation; \
    command -v chromium >/dev/null; \
    if [ -s /tmp/acf-requirements.txt ]; then \
        pip install --no-cache-dir --disable-pip-version-check --require-hashes --only-binary=:all: -r /tmp/acf-requirements.txt; \
    fi; \
    rm -f /tmp/acf-requirements.txt

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
