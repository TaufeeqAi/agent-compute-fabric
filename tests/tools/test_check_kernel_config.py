"""tools/check_kernel_config.py: does a guest kernel have what an ACF guest needs, built in?"""

from __future__ import annotations

from pathlib import Path

import pytest

import check_kernel_config as kc
from acf_testkit import ARM_REQUIRED, X86_REQUIRED, config_text, kernel_image


def test_parse_config_understands_y_m_quoted_and_not_set() -> None:
    cfg = kc.parse_config(
        'CONFIG_A=y\nCONFIG_B=m\nCONFIG_C="text"\n# CONFIG_D is not set\n# an ordinary comment\nGARBAGE\n'
    )
    assert cfg == {"CONFIG_A": "y", "CONFIG_B": "m", "CONFIG_C": "text", "CONFIG_D": "n"}


def test_a_complete_x86_64_config_passes() -> None:
    report = kc.evaluate(kc.parse_config(config_text(X86_REQUIRED)))
    assert report.ok
    assert report.arch == "x86_64"


def test_a_complete_arm64_config_passes_without_the_x86_only_options() -> None:
    report = kc.evaluate(kc.parse_config(config_text(ARM_REQUIRED)))
    assert report.ok
    assert report.arch == "aarch64"


@pytest.mark.parametrize("option", sorted(kc.REQUIRED))
def test_every_required_option_is_enforced(option: str) -> None:
    report = kc.evaluate(kc.parse_config(config_text(X86_REQUIRED, drop=(option,))))
    assert not report.ok
    assert any(m.startswith(option + ":") for m in report.missing)


def test_a_module_does_not_count_because_the_guest_has_no_initramfs() -> None:
    text = config_text(X86_REQUIRED, drop=("CONFIG_VIRTIO_BLK",), extra=("CONFIG_VIRTIO_BLK=m",))
    report = kc.evaluate(kc.parse_config(text))
    assert [m for m in report.missing if m.startswith("CONFIG_VIRTIO_BLK")]


def test_x86_64_needs_the_paravirtual_clock() -> None:
    report = kc.evaluate(kc.parse_config(config_text(X86_REQUIRED, drop=("CONFIG_KVM_GUEST",))))
    assert [m for m in report.missing if m.startswith("CONFIG_KVM_GUEST")]


@pytest.mark.parametrize(
    ("drop", "extra", "ok"),
    [
        (
            ("CONFIG_ACPI", "CONFIG_PCI"),
            ("CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y",),
            True,
        ),  # the legacy discovery mechanism
        (("CONFIG_ACPI",), (), False),  # ACPI alone, without PCI, is not enough
        (("CONFIG_PCI",), (), False),
        (("CONFIG_ACPI", "CONFIG_PCI"), (), False),  # no way to find the devices at all
    ],
)
def test_x86_64_needs_one_way_to_discover_virtio_mmio_devices(
    drop: tuple[str, ...], extra: tuple[str, ...], ok: bool
) -> None:
    report = kc.evaluate(kc.parse_config(config_text(X86_REQUIRED, drop=drop, extra=extra)))
    assert report.ok is ok
    if not ok:
        assert any("virtio-mmio" in m for m in report.missing)


def test_virtio_net_is_noted_as_unneeded_but_never_fatal() -> None:
    report = kc.evaluate(kc.parse_config(config_text(X86_REQUIRED, extra=("CONFIG_VIRTIO_NET=y",))))
    assert report.ok
    assert [u for u in report.unneeded if u.startswith("CONFIG_VIRTIO_NET")]


def test_a_config_for_neither_architecture_is_refused() -> None:
    with pytest.raises(kc.KernelConfigError, match="neither x86_64"):
        kc.evaluate(kc.parse_config("CONFIG_FOO=y\n"))


def test_the_embedded_configuration_is_extracted_from_an_image() -> None:
    text = config_text(X86_REQUIRED)
    assert kc.extract_embedded_config(kernel_image(text)) == text


def test_an_image_without_ikconfig_is_reported_not_guessed_at() -> None:
    with pytest.raises(kc.KernelConfigError, match="no embedded configuration"):
        kc.extract_embedded_config(b"\x7fELF" + b"\0" * 1000)


def test_a_corrupt_embedded_blob_is_reported() -> None:
    with pytest.raises(kc.KernelConfigError, match="not a readable gzip"):
        kc.extract_embedded_config(b"junk IKCFG_ST" + b"definitely not gzip" * 4)


def test_exit_status_zero_for_a_good_kernel_image(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    k = tmp_path / "vmlinux"
    k.write_bytes(kernel_image(config_text(X86_REQUIRED)))
    assert kc.main([str(k)]) == 0
    assert "has every required option built in" in capsys.readouterr().err


def test_exit_status_one_lists_everything_missing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    c = tmp_path / ".config"
    c.write_text(config_text(X86_REQUIRED, drop=("CONFIG_VSOCKETS", "CONFIG_EXT4_FS")))
    assert kc.main(["--config", str(c)]) == 1
    err = capsys.readouterr().err
    assert "MISSING CONFIG_VSOCKETS" in err
    assert "MISSING CONFIG_EXT4_FS" in err


def test_exit_status_three_means_unverifiable_never_a_pass(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    k = tmp_path / "vmlinux"
    k.write_bytes(b"\x7fELF" + b"\0" * 4096)
    assert kc.main([str(k)]) == 3
    assert "cannot be verified" in capsys.readouterr().err


def test_exit_status_two_for_unreadable_or_empty_input(tmp_path: Path) -> None:
    assert kc.main([str(tmp_path / "nope")]) == 2
    empty = tmp_path / "empty.config"
    empty.write_text("# nothing here\n")
    assert kc.main(["--config", str(empty)]) == 2


def test_exactly_one_input_is_required(tmp_path: Path) -> None:
    c = tmp_path / ".config"
    c.write_text(config_text(X86_REQUIRED))
    with pytest.raises(SystemExit) as e:
        kc.main([])
    assert e.value.code == 2
    with pytest.raises(SystemExit) as e2:
        kc.main([str(c), "--config", str(c)])
    assert e2.value.code == 2


@pytest.mark.parametrize(
    ("options", "built_for", "image_arch", "status"),
    [
        (X86_REQUIRED, "x86_64", "x86_64", 0),
        (ARM_REQUIRED, "aarch64", "aarch64", 0),
        (X86_REQUIRED, "x86_64", "aarch64", 1),
        (ARM_REQUIRED, "aarch64", "x86_64", 1),
    ],
)
def test_arch_fails_a_kernel_configured_for_the_other_architecture(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], options: list[str], built_for: str, image_arch: str, status: int
) -> None:
    c = tmp_path / ".config"
    c.write_text(config_text(options))
    assert kc.main(["--config", str(c), "--arch", image_arch]) == status
    err = capsys.readouterr().err
    if status:
        assert f"configured for {built_for}, but the image is for {image_arch}" in err
    else:
        assert "has every required option built in" in err


def test_arch_does_not_turn_an_unverifiable_kernel_into_a_pass_or_a_failure(tmp_path: Path) -> None:
    k = tmp_path / "vmlinux"
    k.write_bytes(b"\x7fELF" + b"\0" * 4096)
    assert kc.main([str(k), "--arch", "x86_64"]) == 3


def test_arch_rejects_a_name_that_is_not_an_architecture_acf_supports(tmp_path: Path) -> None:
    c = tmp_path / ".config"
    c.write_text(config_text(X86_REQUIRED))
    with pytest.raises(SystemExit) as e:
        kc.main(["--config", str(c), "--arch", "riscv64"])
    assert e.value.code == 2
