"""tools/elf_info.py: read an ELF header (never execute the file) and say what architecture and linkage it has."""

from __future__ import annotations

import shutil
import struct
from pathlib import Path

import pytest

import elf_info
from acf_testkit import EM_AARCH64, EM_ARM, make_elf


def test_a_static_x86_64_executable() -> None:
    info = elf_info.inspect(make_elf())
    assert (info.arch, info.static, info.interpreter) == ("x86_64", True, None)


def test_a_dynamic_aarch64_executable_names_its_loader() -> None:
    info = elf_info.inspect(make_elf(machine=EM_AARCH64, interpreter="/lib/ld-linux-aarch64.so.1"))
    assert (info.arch, info.static, info.interpreter) == ("aarch64", False, "/lib/ld-linux-aarch64.so.1")


def test_a_position_independent_static_executable_is_static() -> None:
    # static-pie is ET_DYN with no PT_INTERP.
    assert elf_info.inspect(make_elf(e_type=3)).static is True


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"", "not an ELF"),
        (b"#!/bin/sh\n" + b"x" * 100, "not an ELF"),
        (make_elf(bits=1), "64-bit little-endian"),
        (make_elf(endian=2), "64-bit little-endian"),
        (make_elf(machine=EM_ARM), "unsupported ELF machine 40"),
        (make_elf(e_type=1), "not an executable"),  # a relocatable object
        (make_elf()[:70], "runs past the end"),  # truncated inside the program header table
    ],
)
def test_anything_that_is_not_a_supported_executable_is_refused(data: bytes, message: str) -> None:
    with pytest.raises(elf_info.NotElfError, match=message):
        elf_info.inspect(data)


def test_an_implausible_header_table_is_refused() -> None:
    data = bytearray(make_elf())
    struct.pack_into("<H", data, 56, 60000)  # e_phnum
    with pytest.raises(elf_info.NotElfError, match="implausible"):
        elf_info.inspect(bytes(data))


def test_exit_codes_and_messages(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    static_x86 = tmp_path / "static-x86"
    static_x86.write_bytes(make_elf())
    dynamic_arm = tmp_path / "dynamic-arm"
    dynamic_arm.write_bytes(make_elf(machine=EM_AARCH64, interpreter="/lib/ld-musl-aarch64.so.1"))
    text = tmp_path / "script"
    text.write_text("#!/bin/sh\n")

    assert elf_info.main([str(static_x86)]) == 0
    assert capsys.readouterr().out.strip() == "arch=x86_64 static=yes"
    assert elf_info.main(["--arch", "x86_64", "--static", str(static_x86)]) == 0

    assert elf_info.main(["--arch", "aarch64", str(static_x86)]) == 1
    assert "built for x86_64, expected aarch64" in capsys.readouterr().err

    assert elf_info.main(["--static", str(dynamic_arm)]) == 1
    err = capsys.readouterr().err
    assert "dynamically linked" in err
    assert "make guest-agent" in err

    assert elf_info.main([str(text)]) == 2
    assert elf_info.main([str(tmp_path / "missing")]) == 2


def test_a_real_statically_linked_binary_if_this_machine_has_one(capsys: pytest.CaptureFixture[str]) -> None:
    # Debian ships ldconfig.real statically linked; it is a positive control against a real linker's output.
    candidates = [p for p in (shutil.which("ldconfig.real"), "/sbin/ldconfig.real", "/usr/sbin/ldconfig.real") if p]
    real = next((Path(p) for p in candidates if Path(p).is_file()), None)
    if real is None:
        pytest.skip("no known static ELF on this machine")
    assert elf_info.main(["--static", str(real)]) == 0
    assert "static=yes" in capsys.readouterr().out


def test_a_real_dynamically_linked_binary_if_this_machine_has_one(capsys: pytest.CaptureFixture[str]) -> None:
    sh = shutil.which("dash") or shutil.which("bash")
    if sh is None:
        pytest.skip("no shell found")
    assert elf_info.main(["--static", sh]) == 1
    captured = capsys.readouterr()
    assert "static=no" in captured.out
    assert "interpreter=" in captured.out
