"""Builders for the synthetic inputs the script and tool tests feed to the code under test.

Only construction lives here — no assertions, no test logic — so that a test reads as "given this input, expect
that outcome". Everything is created from scratch in a temporary directory: no network, no KVM, no real kernel.
"""

from __future__ import annotations

import gzip
import io
import os
import platform
import struct
import tarfile
from collections.abc import Iterable, Mapping
from pathlib import Path

import check_kernel_config as kc

# ----------------------------------------------------------------------------------------------- ELF files

EM_X86_64, EM_AARCH64, EM_ARM = 62, 183, 40
PT_LOAD, PT_INTERP = 1, 3


def make_elf(
    *,
    machine: int = EM_X86_64,
    interpreter: str | None = None,
    e_type: int = 2,
    bits: int = 2,
    endian: int = 1,
    extra_phdrs: int = 1,
) -> bytes:
    """A syntactically valid 64-bit little-endian ELF header + program header table (no code)."""
    phdrs: list[tuple[int, bytes]] = [(PT_LOAD, b"")] * extra_phdrs
    if interpreter is not None:
        phdrs.append((PT_INTERP, interpreter.encode() + b"\0"))
    phoff, phentsize = 64, 56
    data_off = phoff + phentsize * len(phdrs)
    ident = b"\x7fELF" + bytes([bits, endian, 1, 0]) + b"\0" * 8
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH", e_type, machine, 1, 0, phoff, 0, 0, 64, phentsize, len(phdrs), 0, 0, 0
    )
    assert len(header) == 64
    table = b""
    blobs = b""
    for p_type, blob in phdrs:
        table += struct.pack("<IIQQQQQQ", p_type, 5, data_off + len(blobs), 0, 0, len(blob), len(blob), 1)
        blobs += blob
    return header + table + blobs


def host_machine() -> str:
    """The architecture name ACF uses for this machine (`uname -m`), or "" when ACF does not support it."""
    machine = platform.machine()
    return machine if machine in ("x86_64", "aarch64") else ""


def elf_machine(arch: str) -> int:
    return {"x86_64": EM_X86_64, "aarch64": EM_AARCH64}[arch]


def static_agent(path: Path, arch: str) -> Path:
    """A file that passes `elf_info.py --static --arch ARCH`: it is only ever read, never run."""
    path.write_bytes(make_elf(machine=elf_machine(arch)))
    path.chmod(0o755)
    return path


# -------------------------------------------------------------------------------------------- guest kernels

X86_REQUIRED = [*kc.REQUIRED, *kc.REQUIRED_X86_64, "CONFIG_X86_64", "CONFIG_ACPI", "CONFIG_PCI"]
ARM_REQUIRED = [*kc.REQUIRED, "CONFIG_ARM64"]


def config_text(options: list[str], *, drop: tuple[str, ...] = (), extra: tuple[str, ...] = ()) -> str:
    lines = [f"{o}=y" for o in options if o not in drop] + list(extra)
    return "# Automatically generated file\n" + "\n".join(lines) + "\n"


def kernel_image(text: str, *, trailer: bytes = b"IKCFG_ED") -> bytes:
    """Bytes that look, to check_kernel_config, like a kernel with an embedded (gzip'd) .config."""
    return b"\x7fELF-not-really" + b"\0" * 64 + b"IKCFG_ST" + gzip.compress(text.encode()) + trailer + b"\0" * 64


def good_kernel(path: Path, arch: str = "x86_64", *, salt: bytes = b"") -> Path:
    """A "kernel" whose embedded config satisfies every requirement; `salt` makes distinct files for distinct ids."""
    options = X86_REQUIRED if arch == "x86_64" else ARM_REQUIRED
    path.write_bytes(kernel_image(config_text(options)) + salt)
    return path


def kernel_without_config(path: Path) -> Path:
    path.write_bytes(b"\x7fELF-not-really" + b"\0" * 256)
    return path


# ------------------------------------------------------------------------------------------ root filesystems

EXECUTABLE_BODY = b"#!/bin/sh\nexit 0\n"


def _add_dir(tf: tarfile.TarFile, name: str, *, mode: int = 0o755, uid: int = 0, gid: int = 0) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    info.mode, info.uid, info.gid = mode, uid, gid
    tf.addfile(info)


def _add_file(
    tf: tarfile.TarFile, name: str, data: bytes = EXECUTABLE_BODY, *, mode: int = 0o755, uid: int = 0, gid: int = 0
) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode, info.uid, info.gid = mode, uid, gid
    tf.addfile(info, io.BytesIO(data))


def _add_symlink(tf: tarfile.TarFile, name: str, target: str) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.SYMTYPE
    info.linkname = target
    info.mode = 0o777
    tf.addfile(info)


def rootfs_tarball(
    path: Path,
    *,
    omit: Iterable[str] = (),
    workspace_owner: tuple[int, int] = (1000, 1000),
    extra_files: Mapping[str, bytes] | None = None,
    owned_files: Mapping[str, tuple[bytes, int, int, int]] | None = None,
    padding_bytes: int = 0,
    dockerenv: bool = False,
) -> Path:
    """A filesystem tarball shaped like a merged-/usr Debian guest image, with everything the build requires.

    /sbin and /bin are symlinks into /usr (so the build's check must resolve links the way the guest will),
    /usr/sbin/init is an ABSOLUTE symlink to the init, and /workspace belongs to the sandbox user. ``omit``
    removes entries by path to make an image that must be refused; ``owned_files`` maps a path to
    ``(data, uid, gid, mode)`` for entries whose numeric ownership and mode must survive the build.
    """
    skip = set(omit)
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as tf:
        for d in (
            "usr",
            "usr/bin",
            "usr/sbin",
            "usr/local",
            "usr/local/bin",
            "usr/local/sbin",
            "usr/local/share",
            "usr/local/share/acf",
            "etc",
            "var",
        ):
            _add_dir(tf, d)
        _add_symlink(tf, "bin", "usr/bin")
        _add_symlink(tf, "sbin", "usr/sbin")
        if "var/lib" not in skip:
            _add_dir(tf, "var/lib")
        if "workspace" not in skip:
            _add_dir(tf, "workspace", uid=workspace_owner[0], gid=workspace_owner[1])
        for exe in ("usr/local/sbin/acf-init", "usr/local/bin/acf-guest-agent", "usr/sbin/resize2fs", "usr/bin/mount"):
            if exe not in skip:
                _add_file(tf, exe)
        if "usr/sbin/init" not in skip:
            _add_symlink(tf, "usr/sbin/init", "/usr/local/sbin/acf-init")
        _add_file(tf, "usr/local/share/acf/clock-epoch", b"1700000000\n", mode=0o644)
        _add_file(tf, "etc/os-release", b'PRETTY_NAME="Test Linux"\n', mode=0o644)
        if dockerenv:
            _add_file(tf, ".dockerenv", b"", mode=0o755)
        for name, data in (extra_files or {}).items():
            _add_file(tf, name, data, mode=0o644)
        for name, (data, uid, gid, file_mode) in (owned_files or {}).items():
            _add_file(tf, name, data, mode=file_mode, uid=uid, gid=gid)
        if padding_bytes:
            _add_file(
                tf,
                "usr/share-padding",
                os.urandom(min(padding_bytes, 1 << 20)) * max(1, padding_bytes >> 20),
                mode=0o644,
            )
    return path


# ----------------------------------------------------------------------------------- Firecracker release tarball


def firecracker_tarball(
    path: Path,
    *,
    version: str = "v1.17.0",
    arch: str,
    firecracker_reports: str | None = None,
    jailer_reports: str | None = None,
    omit_jailer: bool = False,
    extra_members: Mapping[str, bytes] | None = None,
    gzip_it: bool = True,
) -> Path:
    """A release archive laid out like upstream's: ``release-<v>-<arch>/{firecracker,jailer}-<v>-<arch>``.

    The two "binaries" are shell scripts that answer ``--version`` the way the real ones do, so the installer's
    version check can be exercised without a real Firecracker.
    """
    top = f"release-{version}-{arch}"
    fc_name = f"firecracker-{version}-{arch}"
    jl_name = f"jailer-{version}-{arch}"
    fc_says = firecracker_reports or f"Firecracker {version}"
    jl_says = jailer_reports or f"Jailer {version}"
    with tarfile.open(path, "w:gz") if gzip_it else tarfile.open(path, "w") as tf:
        _add_dir(tf, top)
        _add_file(tf, f"{top}/{fc_name}", f'#!/bin/sh\necho "{fc_says}"\n'.encode())
        if not omit_jailer:
            _add_file(tf, f"{top}/{jl_name}", f'#!/bin/sh\necho "{jl_says}"\n'.encode())
        _add_file(tf, f"{top}/{fc_name}.debug", b"debug symbols", mode=0o644)
        for name, data in (extra_members or {}).items():
            _add_file(tf, name, data, mode=0o644)
    return path
