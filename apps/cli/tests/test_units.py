"""Quantity parsing: strict and total. A mis-parsed ``--memory`` is an admission bug, not a typo."""

from __future__ import annotations

import pytest

from acf_cli.errors import InvalidArgument
from acf_cli.units import (
    format_bytes,
    format_ms,
    parse_bytes,
    parse_duration_ms,
    parse_env,
    parse_memory_mib,
)


@pytest.mark.parametrize(
    ("text", "mib"),
    [("4096", 4096), ("512Mi", 512), ("512mib", 512), ("512M", 512), ("4Gi", 4096), ("4g", 4096), (" 2 GiB ", 2048)],
)
def test_memory_accepts_binary_units(text: str, mib: int) -> None:
    assert parse_memory_mib(text) == mib


@pytest.mark.parametrize("text", ["", "0", "0Gi", "-1", "1.5Gi", "4T", "Gi", "1e3", "4 096", "٣٠٠", "4Gi!", "0x10"])
def test_memory_rejects_everything_else(text: str) -> None:
    with pytest.raises(InvalidArgument):
        parse_memory_mib(text)


def test_arabic_indic_digits_cannot_smuggle_a_value_past_the_parser() -> None:
    # int("٣٠٠") == 300 in Python; the regex is ASCII-only so this never reaches int().
    assert int("٣٠٠") == 300
    with pytest.raises(InvalidArgument):
        parse_memory_mib("٣٠٠")


@pytest.mark.parametrize(
    ("text", "ms"),
    [
        ("90", 90_000),
        ("90s", 90_000),
        ("1500ms", 1500),
        ("2m", 120_000),
        ("1h", 3_600_000),
        ("0.5s", 500),
        ("1.5m", 90_000),
    ],
)
def test_duration_units(text: str, ms: int) -> None:
    assert parse_duration_ms(text) == ms


@pytest.mark.parametrize("text", ["", "0", "0s", "-5", "abc", "5d", "1:30", "1e3s"])
def test_duration_rejects_garbage_and_non_positive(text: str) -> None:
    with pytest.raises(InvalidArgument):
        parse_duration_ms(text)


@pytest.mark.parametrize(
    ("text", "count"),
    [
        ("65536", 65536),
        ("64KiB", 65536),
        ("64k", 65536),
        ("1MiB", 1 << 20),
        ("1M", 1 << 20),
        ("2G", 2 << 30),
        ("10b", 10),
    ],
)
def test_byte_sizes(text: str, count: int) -> None:
    assert parse_bytes(text) == count


@pytest.mark.parametrize("text", ["", "0", "-1", "1.5M", "1T", "KiB"])
def test_byte_sizes_reject_garbage(text: str) -> None:
    with pytest.raises(InvalidArgument):
        parse_bytes(text)


def test_env_parsing() -> None:
    assert parse_env(["A=1", "B=two=three", "C="]) == {"A": "1", "B": "two=three", "C": ""}
    assert parse_env([]) == {}


@pytest.mark.parametrize("items", [["A"], ["=x"], ["A=1", "A=2"]])
def test_env_rejects_malformed_and_duplicates(items: list[str]) -> None:
    with pytest.raises(InvalidArgument):
        parse_env(items)


@pytest.mark.parametrize(
    ("count", "text"),
    [
        (0, "0 B"),
        (1023, "1023 B"),
        (1024, "1.0 KiB"),
        (1536, "1.5 KiB"),
        (12 * 1024 * 1024, "12.0 MiB"),
        (5 * 1024**3, "5.0 GiB"),
    ],
)
def test_format_bytes(count: int, text: str) -> None:
    assert format_bytes(count) == text


@pytest.mark.parametrize(
    ("ms", "text"), [(0, "0 ms"), (742, "742 ms"), (12_300, "12.3 s"), (247_000, "4m07s"), (3_600_000, "60m00s")]
)
def test_format_ms(ms: int, text: str) -> None:
    assert format_ms(ms) == text
