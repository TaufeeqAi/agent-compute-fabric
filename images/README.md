# Guest images

An **image** is what a sandbox boots: a kernel, a root filesystem, and a manifest that binds them.

```text
<state_root>/images/<name>/
├── manifest.json     schema_version, name, architecture, kernel{file,sha256,size}, rootfs{...},
│                     boot_args?, guest_agent_version, provenance
├── vmlinux           an UNCOMPRESSED guest kernel
└── rootfs.ext4       a compact ext4 root filesystem
```

The image's **identity** is the sha256 of `manifest.json`'s bytes (`image_id=sha256:…`). The host copies
`vmlinux` and `rootfs.ext4` into the sandbox while hashing what it copies and refuses to boot if either
differs from the manifest, so a sandbox can only ever run the exact bytes the manifest names.

This directory holds the recipes; `scripts/build-image.sh` turns a recipe into an image directory.

```text
images/
├── images.lock            every input pinned by content: base-image digests, kernel sha256
├── overlay/               files copied into every image (the guest init)
│   └── usr/local/sbin/acf-init
├── base/Dockerfile        Debian (slim) + the ACF guest layer
├── python/Dockerfile      official Python (slim) + the guest layer; optional hash-pinned requirements
├── node/Dockerfile        official Node.js (slim) + the guest layer
└── browser/Dockerfile     Python + headless Chromium + the guest layer (experimental)
```

## What the host assumes about every guest — "the guest contract"

| The host relies on | Provided by |
|---|---|
| `/sbin/init` exists and ends the VM if it fails | the guest layer links `/usr/sbin/init → /usr/local/sbin/acf-init` |
| an agent answers `Hello` on vsock port 5252 within `guest_ready_timeout_ms` | `acf-init` starts `/usr/local/bin/acf-guest-agent --allow-shutdown` |
| the root disk grows to the size the sandbox asked for | `acf-init` runs `resize2fs` on the root device at every boot (online) |
| commands run as `execution.guest_uid`/`guest_gid` (1000 in `policies/default.yaml`) | the guest layer creates uid/gid 1000 if absent and makes `/workspace` theirs |
| `/workspace` exists, writable by that uid, is the default working directory | the guest layer |
| there is a working `127.0.0.1` even though there is no network device | `acf-init` brings `lo` up and writes `/etc/hosts` |
| a command's process tree is bounded and killable as a unit | `acf-init` mounts cgroup v2; the agent creates one cgroup per command |
| `network=none` means no interface but `lo` | the host attaches no network device; the agent reports what it sees |

`acf-init`'s failure policy is *crash-only*: anything the contract cannot do without is fatal (init exits →
kernel panic → `panic=1` reboots → `reboot=k` ends the VMM), so the host learns about a bad guest in a
second instead of after the 30 s ready timeout. The agent exiting is fatal too. Details and the one-page
reasoning are in the header of [`acf-init`](overlay/usr/local/sbin/acf-init).

**If you change the guest user.** `execution.guest_uid` in the host policy and the user the Dockerfile
creates are two halves of one contract: if they disagree, commands run as a uid that cannot write
`/workspace`. `build-image.sh` checks the image side (`--owner /workspace=1000:1000`); nothing can check
the policy side from here, so change them together.

## Building an image

You need: root, Docker with BuildKit (`docker buildx`), a **static** guest agent, a guest **kernel**, and a
pinned `images/images.lock`.

```console
$ make guest-agent                              # static acf-guest-agent (x86_64-unknown-linux-musl)
$ scripts/pin-images.sh --write                 # resolve base-image tags to digests (needs crane, skopeo or docker)
$ sha256sum /path/to/vmlinux                    # put it in images.lock as KERNEL_SHA256_x86_64
$ export TMPDIR=/var/tmp                        # a big, disk-backed directory (see "Sizes")
$ sudo -E scripts/build-image.sh --image python --kernel /path/to/vmlinux --install
image_id=sha256:…
```

`--install` puts the image into `/var/lib/acf/images/python` and re-verifies it there. Without it the
image is left in `dist/images/python`. Other options: `--requirements FILE` (hash-pinned pip requirements
baked into the python/browser image — a sandbox with no network cannot `pip install`), `--arch aarch64`
(needs QEMU user-mode emulation for the container steps), `--rootfs-tar FILE` (use a filesystem tarball
you exported yourself, e.g. with `podman export`; it must already contain the guest layer).

### Pins and the fail-closed rule

`build-image.sh` exits **3** ("NOT PINNED") when a digest it needs is `UNSET` in `images/images.lock`. The
`--allow-unpinned` flag exists for development, and its effect is recorded in the manifest's provenance
(`pinned=no; unpinned=…`), which is part of the image identity: an unpinned image cannot pass for a
pinned one. `make check-pins-release` fails while anything is `UNSET`; run it before you ship.

The tags in `images.lock` were chosen from knowledge of the Debian 13 ("trixie") generation and were
**not resolved against a registry** when this repository was written (no registry was reachable).
`scripts/pin-images.sh` resolves each tag and fails loudly on one that does not exist. Bump a base by
changing its tag, re-running `pin-images.sh --write`, and reviewing the diff like any dependency bump;
`pin-images.sh --verify` tells you when a tag has moved underneath a pin.

## The kernel

ACF does not build kernels. It needs an **uncompressed `vmlinux`** with the options in
[`tools/check_kernel_config.py`](../tools/check_kernel_config.py) built in (`=y`; the guest runs with
`nomodule` and no initramfs). `build-image.sh` runs that check; a kernel built **without**
`CONFIG_IKCONFIG` cannot be inspected, which is reported as a warning ("unverifiable"), never a pass.

Where to get one — all from Firecracker's own documentation (`docs/kernel-policy.md` at v1.17.0):

* supported guest kernels are 5.10, 6.1 and 6.18 (6.18 is supported through at least mid-2028; 6.1's
  published minimum end-of-support date is 2026-09-02, so prefer 6.18 for new images);
* the guest configurations Firecracker validates with are in `resources/guest_configs/` in its repository;
* Amazon Linux's microVM kernel sources are tagged `microvm-kernel-*` at `github.com/amazonlinux/linux`.

Build from one of those configurations with `CONFIG_IKCONFIG=y` added, then `sha256sum` the `vmlinux` and
pin it. Not done here: building or booting a kernel (the environment this repository was written in has no
`/dev/kvm`); `tests/integration` does it on a KVM host.

The host's default kernel command line is `reboot=k panic=1 pci=off nomodule 8250.nr_uarts=0 i8042.noaux
i8042.nomux i8042.dumbkbd swiotlb=noforce` — Firecracker's own default plus an explicit `pci=off`, because
ACF uses the MMIO virtio transport, not PCI (so no `--enable-pci`). Firecracker appends `root=/dev/vda rw`
itself. A manifest `boot_args` **replaces** the default and so must carry all of it; leave it `null`.

## Sizes and disks

The root filesystem is built **compact** (content + ~8 % + a 16 MiB journal + `--slack-mib`, default 64)
and grows at boot. The host copies it into a sparse file of `--disk` MiB and refuses a disk smaller than
the image: the build prints `rootfs N MiB`, so use `--disk` ≥ N plus the room a workload needs. (The CLI's
default `--disk` is 1024.)

* The build host needs roughly **3× the tarball** in free space for `TMPDIR` (tarball + extracted tree +
  image). `/tmp` is often a RAM-backed tmpfs: set `TMPDIR` to a disk. The scripts check and say so.
* ext4 features are pinned in [`scripts/mke2fs.conf`](../scripts/mke2fs.conf) — `has_journal extent huge_file
  flex_bg metadata_csum 64bit dir_nlink extra_isize` + `resize_inode` — not whatever the build host's
  `mke2fs` defaults to. A newer `mke2fs` can enable features (`orphan_file`, for one) that a 5.10 guest
  kernel does not understand; the kernel then mounts the root filesystem read-only, which surfaces much
  later as a baffling "read-only file system". `resize_inode` reserves what online growth needs (up to
  ~1000× the original size).
* Measured here (e2fsprogs 1.47.0, offline `resize2fs`): a 236 MiB image grows to 1, 4 and 8 GiB in
  under 0.1 s without allocating any host disk (metadata only), and inode density stays ≈ 1 inode per
  8.7 KiB. **Not measured here:** the guest's *online* growth (this environment cannot grant the
  capability it needs) and ext4's background zeroing of new inode tables, which — from how ext4's lazy
  initialisation works — will eventually write roughly 3 % of the added space as zeroes into the sandbox's
  sparse disk file.
* `/tmp` is on the root filesystem, not tmpfs: it counts against the sandbox's disk, survives snapshots,
  and cannot silently consume the sandbox's memory.

## Adding a package, or a new image

* **Python packages:** `--requirements FILE`, pinned **with hashes** (`pip-compile --generate-hashes`, or
  `uv pip compile --generate-hashes`). `pip install --require-hashes --only-binary=:all:` refuses anything
  else. Nothing can be installed at run time (there is no network).
* **A new image:** add `images/<name>/Dockerfile` (copy a short one — the block between
  `# >>> ACF GUEST LAYER` and `# <<< ACF GUEST LAYER` must stay byte-identical; `tests/tools/test_images.py`
  fails otherwise), add `BASE_REF_<name>` / `BASE_DIGEST_<name>` to `images.lock`, add the name to
  `capabilities.images` in your policy. `make check-pins` verifies the three agree.
* ENV, USER, WORKDIR, ENTRYPOINT and CMD in a Dockerfile do nothing: only the filesystem is exported.
  A command's environment comes from the request (`policies/default.yaml: execution.env_allowlist`) plus
  the guest agent's default `PATH`.

## What the guest layer does for security

None of it replaces the VM boundary; it narrows what runs *inside* it.

* **No setuid/setgid files.** Every setuid/setgid bit is removed at build time. Workloads run as uid 1000
  and have no use for `su`, `mount` or `passwd`, and each is local-privilege-escalation surface.
* **No network device at all** for `network=none` (host-side); the guest only has `lo`.
* **No modules, no initramfs:** `nomodule` on the command line; everything the guest needs is built into
  the kernel the manifest pins.
* **Hardening sysctls:** `kernel.dmesg_restrict=1`, `kernel.kptr_restrict=2`; core dumps off.
* **Crash-only:** a guest that cannot set itself up powers off instead of limping.

## Known limitations

* **Wall clock.** A Firecracker x86_64 guest has no RTC, so its clock starts at 1970. `acf-init` raises it
  to the image's build time (`/usr/local/share/acf/clock-epoch`, from `SOURCE_DATE_EPOCH`) — a floor, not
  the real time. Phase 1 does not push the host's time into the guest, and a restored snapshot continues
  from the time it was taken.
* **Not bit-reproducible.** The *identity* of an image is exact (its manifest hash), but rebuilding the same
  recipe yields different bytes: apt packages move, and ext4 and layer timestamps differ. Pinning the
  Debian archive to a snapshot date is a future hardening step.
* **Browser image:** experimental and not covered by the Phase 1 test-suite. Run Chromium with
  `--no-sandbox` (its setuid helper is gone by design) — the microVM is the boundary.
* **The kernel is an input, not an output.** ACF checks it and pins it; it does not build it.
