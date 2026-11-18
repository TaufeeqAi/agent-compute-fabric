#!/usr/bin/env python3
"""Check a guest kernel's configuration against what an ACF guest needs.

    check_kernel_config.py KERNEL        # an uncompressed vmlinux built with CONFIG_IKCONFIG, or
    check_kernel_config.py --config .config

A guest that boots but lacks vsock never answers the host; one without ext4 never mounts its root; one
without the pids cgroup controller loses the atomic process-tree bound. These are cheap to detect at
image-build time and miserable to debug through a VMM that has no console (the default boot args
disable the serial device on purpose).

The kernel runs with no modules and no initramfs (``nomodule`` is on its command line), so every
required feature must be built in (``=y``); ``=m`` does not count.

The list follows Firecracker's own "Guest kernel configuration items" and "Minimal boot requirements"
(docs/kernel-policy.md, v1.17.0) for the boot path, plus what ACF's guest agent and init add. What only
network mode ``allowlist`` needs (a network device, and the kernel's own address configuration) is
reported as a note: a kernel without it still serves network mode ``none``.

If the kernel was built without ``CONFIG_IKCONFIG`` there is no embedded configuration to read. That is
reported as *unverifiable* (exit 3), never as a pass: pass ``--config`` with the ``.config`` it was
built from, or rely on the boot tests in tests/integration.

Exit status: 0 every required option is present, 1 something required is missing, 2 usage or an
unreadable input, 3 the configuration cannot be read out of the kernel image.
Standard library only.
"""

from __future__ import annotations

import argparse
import re
import sys
import zlib
from pathlib import Path

# option -> why the guest needs it. All must be `=y`, on every architecture.
REQUIRED: dict[str, str] = {
    "CONFIG_BLK_DEV": "block layer",
    "CONFIG_VIRTIO": "virtio core",
    "CONFIG_VIRTIO_BLK": "the root disk is a virtio-blk device",
    "CONFIG_VIRTIO_MMIO": "Firecracker's default virtio transport (the host does not pass --enable-pci)",
    "CONFIG_EXT4_FS": "the root filesystem is ext4",
    "CONFIG_VSOCKETS": "the host reaches the guest agent over vsock",
    "CONFIG_VIRTIO_VSOCKETS": "virtio transport for vsock",
    "CONFIG_NET": "networking core (vsock and loopback need it even with network=none)",
    "CONFIG_INET": "AF_INET on the loopback interface",
    "CONFIG_UNIX": "AF_UNIX: the guest agent and most runtimes use it",
    "CONFIG_DEVTMPFS": "/dev is a devtmpfs mounted by acf-init",
    "CONFIG_PROC_FS": "/proc",
    "CONFIG_SYSFS": "/sys",
    "CONFIG_TMPFS": "/run and /dev/shm",
    "CONFIG_BINFMT_ELF": "run ELF programs",
    "CONFIG_BINFMT_SCRIPT": "run #! scripts (acf-init is one)",
    "CONFIG_CGROUPS": "per-command containment (cgroup v2 is mounted by acf-init)",
    "CONFIG_CGROUP_PIDS": "pids.max bounds a command's process tree and cgroup.kill ends it atomically",
}

# x86_64 only (Firecracker "Minimal boot requirements").
REQUIRED_X86_64: dict[str, str] = {
    "CONFIG_KVM_GUEST": "paravirtual clock: without it the guest has no usable time source under KVM",
}

# x86_64 needs ONE of these ways to discover virtio-mmio devices (ACPI is the current one; the
# command-line mechanism is the deprecated legacy one, which Firecracker still supports).
DISCOVERY_X86_64: tuple[tuple[str, ...], ...] = (
    ("CONFIG_ACPI", "CONFIG_PCI"),
    ("CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES",),
)

# Worth knowing, never fatal.
ADVICE: dict[str, str] = {
    "CONFIG_RANDOM_TRUST_CPU": (
        "seeds the kernel RNG from CPU instructions at boot (Firecracker: available for >= 5.10)"
    ),
    "CONFIG_PTP_1588_CLOCK_KVM": "high-precision timekeeping (Firecracker lists it for x86_64)",
    "CONFIG_MEMCG": "memory accounting inside the guest",
    "CONFIG_IKCONFIG": "lets this tool (and operators) read the configuration back out of the image",
}

# Needed only by network mode `allowlist`, in which the guest has one network device and takes its address,
# gateway and resolver from the kernel command line. A kernel without them still runs every sandbox in mode
# `none`, so their absence is reported and never fatal.
ALLOWLIST: dict[str, str] = {
    "CONFIG_VIRTIO_NET": "the guest's network device (eth0)",
    "CONFIG_IP_PNP": "the guest's address, gateway and resolver are set from the kernel command line (`ip=`)",
}

_LINE = re.compile(r"^(?P<key>CONFIG_[A-Z0-9_]+)=(?P<val>.*)$")
_NOT_SET = re.compile(r"^# (?P<key>CONFIG_[A-Z0-9_]+) is not set$")
_MAGIC_START = b"IKCFG_ST"


class KernelConfigError(Exception):
    """The configuration could not be read."""


def parse_config(text: str) -> dict[str, str]:
    """``CONFIG_X=y`` -> {"CONFIG_X": "y"}; ``# CONFIG_X is not set`` -> {"CONFIG_X": "n"}."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if m := _LINE.match(line):
            out[m["key"]] = m["val"].strip('"')
        elif m := _NOT_SET.match(line):
            out[m["key"]] = "n"
    return out


def extract_embedded_config(image: bytes) -> str:
    """Pull the gzip'd ``.config`` out of a kernel built with CONFIG_IKCONFIG (like scripts/extract-ikconfig)."""
    start = image.find(_MAGIC_START)
    if start < 0:
        raise KernelConfigError("no embedded configuration (built without CONFIG_IKCONFIG)")
    blob = image[start + len(_MAGIC_START) :]
    try:
        return zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(blob).decode("utf-8", "replace")  # gzip framing
    except zlib.error as e:
        raise KernelConfigError(f"the embedded configuration is not a readable gzip stream: {e}") from e


def architecture_of(cfg: dict[str, str]) -> str | None:
    if cfg.get("CONFIG_X86_64") == "y":
        return "x86_64"
    if cfg.get("CONFIG_ARM64") == "y":
        return "aarch64"
    return None


class Report:
    def __init__(self, arch: str, missing: list[str], advice: list[str], no_allowlist: list[str]) -> None:
        self.arch, self.missing, self.advice, self.no_allowlist = arch, missing, advice, no_allowlist

    @property
    def ok(self) -> bool:
        return not self.missing


def evaluate(cfg: dict[str, str]) -> Report:
    arch = architecture_of(cfg)
    if arch is None:
        raise KernelConfigError("the configuration is for neither x86_64 (CONFIG_X86_64) nor arm64 (CONFIG_ARM64)")
    missing = [f"{k}: {why}" for k, why in REQUIRED.items() if cfg.get(k) != "y"]
    if arch == "x86_64":
        missing += [f"{k}: {why}" for k, why in REQUIRED_X86_64.items() if cfg.get(k) != "y"]
        if not any(all(cfg.get(k) == "y" for k in group) for group in DISCOVERY_X86_64):
            options = " or ".join("+".join(g) for g in DISCOVERY_X86_64)
            missing.append(f"one of [{options}]: the guest must be able to discover Firecracker's virtio-mmio devices")
    advice = [f"{k}: {why}" for k, why in ADVICE.items() if cfg.get(k) != "y"]
    no_allowlist = [f"{k}: {why}" for k, why in ALLOWLIST.items() if cfg.get(k) != "y"]
    return Report(arch, missing, advice, no_allowlist)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("kernel", nargs="?", type=Path, help="uncompressed kernel image (vmlinux)")
    ap.add_argument(
        "--config", type=Path, help="a kernel .config file to check instead of reading one out of the image"
    )
    ap.add_argument(
        "--arch", choices=("x86_64", "aarch64"), help="fail if the configuration is for a different architecture"
    )
    args = ap.parse_args(argv)
    if (args.kernel is None) == (args.config is None):
        ap.error("give exactly one of KERNEL or --config")

    try:
        if args.config is not None:
            text = args.config.read_text(encoding="utf-8", errors="replace")
            source = str(args.config)
        else:
            text = extract_embedded_config(args.kernel.read_bytes())
            source = f"{args.kernel} (embedded configuration)"
    except OSError as e:
        print(f"check_kernel_config: {e}", file=sys.stderr)
        return 2
    except KernelConfigError as e:
        print(
            f"check_kernel_config: {e}; {args.kernel} cannot be verified from here. "
            "Pass --config with the .config it was built from, or rely on tests/integration.",
            file=sys.stderr,
        )
        return 3

    cfg = parse_config(text)
    if not cfg:
        print(f"check_kernel_config: {source} contains no CONFIG_ lines", file=sys.stderr)
        return 2
    try:
        report = evaluate(cfg)
    except KernelConfigError as e:
        print(f"check_kernel_config: {source}: {e}", file=sys.stderr)
        return 2
    for line in report.advice:
        print(f"note    {line}", file=sys.stderr)
    for line in report.no_allowlist:
        print(f"note    network mode `allowlist` needs {line}", file=sys.stderr)
    for line in report.missing:
        print(f"MISSING {line}", file=sys.stderr)
    if args.arch is not None and report.arch != args.arch:
        print(f"MISMATCH {source} is configured for {report.arch}, but the image is for {args.arch}", file=sys.stderr)
        return 1
    if not report.ok:
        return 1
    print(f"ok: {source} ({report.arch}) has every required option built in", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
