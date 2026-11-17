#!/usr/bin/env python3
"""Describe — and optionally check — an ELF executable WITHOUT running it.

    elf_info.py FILE                          # prints: arch=x86_64 static=yes
    elf_info.py --arch aarch64 --static FILE  # exit 1 unless FILE is a static aarch64 executable

Why: scripts/build-image.sh puts a prebuilt ``acf-guest-agent`` into a guest image. Two mistakes cost
a boot to discover, and boot failures in a VMM with no console are miserable to debug:

  * an agent built for the wrong architecture (an x86_64 agent in an aarch64 image);
  * an agent linked dynamically against the BUILD host's libc, which the image may not have, or may
    have in a different version — the guest then dies at its first instruction with "No such file or
    directory", which names the missing dynamic loader and not the actual problem.

The guest agent is therefore built static (``make guest-agent``: the ``*-unknown-linux-musl`` target)
and this tool verifies that at image-build time. "Static" means: no ``PT_INTERP`` program header, i.e.
no dynamic loader is requested. (static-pie has a ``PT_DYNAMIC`` but no ``PT_INTERP``: it is static.)

Only 64-bit little-endian ELF is understood — that is both architectures Firecracker supports
(x86_64, aarch64). Anything else is reported as "not a supported ELF", never guessed at.

The file is only read, never executed (``ldd`` would execute it). Standard library only.

Exit status: 0 ok, 1 a requested check failed, 2 unreadable or not a supported ELF.
"""

from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

EI_CLASS_64 = 2
EI_DATA_LE = 1
MACHINES = {62: "x86_64", 183: "aarch64"}  # EM_X86_64, EM_AARCH64
PT_INTERP = 3
MAX_PHDRS = 4096  # a sanity bound on a header table we are about to walk
ELF64_EHDR_SIZE = 64  # sizeof(Elf64_Ehdr)
ELF64_PHDR_SIZE = 56  # sizeof(Elf64_Phdr)


class NotElfError(Exception):
    """The file is not a 64-bit little-endian ELF executable of a supported architecture."""


@dataclass(frozen=True)
class ElfInfo:
    arch: str
    static: bool
    interpreter: str | None


def inspect(data: bytes) -> ElfInfo:
    if len(data) < ELF64_EHDR_SIZE or data[:4] != b"\x7fELF":
        raise NotElfError("not an ELF file")
    if data[4] != EI_CLASS_64 or data[5] != EI_DATA_LE:
        raise NotElfError("not a 64-bit little-endian ELF")
    e_type, e_machine = struct.unpack_from("<HH", data, 16)
    if e_type not in (2, 3):  # ET_EXEC, ET_DYN (position-independent executables are ET_DYN)
        raise NotElfError(f"ELF type {e_type} is not an executable")
    arch = MACHINES.get(e_machine)
    if arch is None:
        raise NotElfError(f"unsupported ELF machine {e_machine} (supported: {', '.join(MACHINES.values())})")
    (e_phoff,) = struct.unpack_from("<Q", data, 32)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
    if e_phnum > MAX_PHDRS or (e_phnum and e_phentsize < ELF64_PHDR_SIZE):
        raise NotElfError("implausible program header table")
    interpreter: str | None = None
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + 56 > len(data):
            raise NotElfError("program header table runs past the end of the file")
        p_type, _flags, p_offset, _vaddr, _paddr, p_filesz = struct.unpack_from("<IIQQQQ", data, off)
        if p_type == PT_INTERP:
            raw = data[p_offset : p_offset + p_filesz]
            interpreter = raw.split(b"\0", 1)[0].decode("utf-8", "replace")
            break
    return ElfInfo(arch=arch, static=interpreter is None, interpreter=interpreter)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("file", type=Path)
    ap.add_argument(
        "--arch", choices=sorted(MACHINES.values()), help="fail unless the file is built for this architecture"
    )
    ap.add_argument(
        "--static", action="store_true", help="fail unless the file is statically linked (requests no dynamic loader)"
    )
    args = ap.parse_args(argv)

    try:
        info = inspect(args.file.read_bytes())
    except OSError as e:
        print(f"elf_info: {e}", file=sys.stderr)
        return 2
    except NotElfError as e:
        print(f"elf_info: {args.file}: {e}", file=sys.stderr)
        return 2

    print(
        f"arch={info.arch} static={'yes' if info.static else 'no'}"
        + (f" interpreter={info.interpreter}" if info.interpreter else "")
    )
    failed = False
    if args.arch and info.arch != args.arch:
        print(f"elf_info: {args.file} is built for {info.arch}, expected {args.arch}", file=sys.stderr)
        failed = True
    if args.static and not info.static:
        print(
            f"elf_info: {args.file} is dynamically linked (loader {info.interpreter}); "
            "the guest image's libc is not the build host's. "
            "Build the agent with `make guest-agent` (a static musl binary).",
            file=sys.stderr,
        )
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
