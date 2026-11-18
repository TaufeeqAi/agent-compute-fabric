"""Command-line value parsing: strict and total. A mis-parsed ``--memory`` is an admission mistake, not a typo."""

from __future__ import annotations

import pytest

from acf_cli.errors import InvalidArgument
from acf_cli.requests import NameDestination, NetworkDestination
from acf_cli.units import (
    format_bytes,
    format_ms,
    parse_allow,
    parse_bytes,
    parse_cursor,
    parse_duration_ms,
    parse_duration_s,
    parse_env,
    parse_memory_mib,
    parse_secret_env,
    parse_whole_seconds,
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
        ("1d", 86_400_000),
        ("0.5s", 500),
        ("1.5m", 90_000),
    ],
)
def test_duration_units(text: str, ms: int) -> None:
    assert parse_duration_ms(text) == ms


@pytest.mark.parametrize("text", ["", "0", "0s", "-5", "abc", "5w", "1:30", "1e3s"])
def test_duration_rejects_garbage_and_non_positive(text: str) -> None:
    with pytest.raises(InvalidArgument):
        parse_duration_ms(text)


def test_a_client_side_wait_is_in_seconds() -> None:
    assert parse_duration_s("1500ms") == 1.5
    assert parse_duration_s("2m") == 120.0


@pytest.mark.parametrize(("text", "seconds"), [("3600", 3600), ("90m", 5400), ("2h", 7200), ("1d", 86400)])
def test_a_lifetime_is_a_whole_number_of_seconds(text: str, seconds: int) -> None:
    assert parse_whole_seconds(text, what="--lifetime") == seconds


@pytest.mark.parametrize("text", ["1500ms", "0.5s", "0", "soon"])
def test_a_lifetime_that_is_not_whole_seconds_is_refused(text: str) -> None:
    with pytest.raises(InvalidArgument):
        parse_whole_seconds(text, what="--lifetime")


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


# ----------------------------------------------------------------------------- environment
def test_env_parsing() -> None:
    assert parse_env(["A=1", "B=two=three", "C="]) == {"A": "1", "B": "two=three", "C": ""}
    assert parse_env([]) == {}


@pytest.mark.parametrize("items", [["A"], ["=x"], ["A=1", "A=2"]])
def test_env_rejects_malformed_and_duplicates(items: list[str]) -> None:
    with pytest.raises(InvalidArgument):
        parse_env(items)


def test_a_secret_variable_names_a_reference() -> None:
    parsed = parse_secret_env(["API_TOKEN=ci-token_v2.prod", "DB=db-password"])
    assert {name: ref.ref for name, ref in parsed.items()} == {"API_TOKEN": "ci-token_v2.prod", "DB": "db-password"}
    assert parse_secret_env([]) == {}


@pytest.mark.parametrize(
    "value",
    [
        "p@ssw0rd!",  # punctuation outside the reference grammar
        "hunter2 with spaces",
        "-----BEGIN PRIVATE KEY-----",
        "ghp_" + "a" * 80,  # longer than any reference
        ".hidden",
        "",
        "../../etc/shadow",
    ],
)
def test_something_that_is_not_a_reference_is_refused_and_never_echoed(value: str) -> None:
    """Raw secret material must not be accepted as a secret, and must not end up in an error message either."""
    with pytest.raises(InvalidArgument) as caught:
        parse_secret_env([f"API_TOKEN={value}"])
    rendered = f"{caught.value.message} {caught.value.hint}"
    assert "API_TOKEN" in rendered
    if value:
        assert value not in rendered
    assert "never" in rendered.lower()


@pytest.mark.parametrize("items", [["API_TOKEN"], ["=ci-token"], ["A=one", "A=two"]])
def test_secret_variables_reject_malformed_and_duplicates(items: list[str]) -> None:
    with pytest.raises(InvalidArgument) as caught:
        parse_secret_env(items)
    assert "one" not in caught.value.message
    assert "ci-token" not in caught.value.message


# ----------------------------------------------------------------------------- allowlist entries
def test_an_allow_entry_is_a_name_or_a_network_plus_ports() -> None:
    name, network, single = parse_allow(["pypi.org:443", "198.51.100.0/24:5432-5433,8443", "203.0.113.7:22"])
    assert name.destination == NameDestination(name="pypi.org")
    assert [(p.low, p.high) for p in name.ports] == [(443, 443)]
    assert network.destination == NetworkDestination(network="198.51.100.0/24")
    assert [(p.low, p.high) for p in network.ports] == [(5432, 5433), (8443, 8443)]
    assert single.destination == NetworkDestination(network="203.0.113.7/32"), "a bare address is that one address"


def test_allow_entries_serialise_to_the_wire_shape() -> None:
    (entry,) = parse_allow(["files.example.org:80,443"])
    assert entry.model_dump(mode="json") == {
        "destination": {"name": "files.example.org"},
        "ports": [{"from": 80, "to": 80}, {"from": 443, "to": 443}],
    }


@pytest.mark.parametrize(
    "entry",
    [
        "pypi.org",  # no ports
        ":443",  # no destination
        "pypi.org:",  # empty ports
        "pypi.org:0",  # port out of range
        "pypi.org:70000",
        "pypi.org:443-80",  # empty range
        "pypi.org:https",
        "pypi.org:80,,443",
        "198.51.100.0/24/and/more:443",  # too long to be a network
    ],
)
def test_malformed_allow_entries_are_usage_errors(entry: str) -> None:
    with pytest.raises(InvalidArgument) as caught:
        parse_allow([entry])
    assert caught.value.hint is not None


def test_whether_a_destination_is_permitted_is_not_decided_here() -> None:
    """Loopback and metadata addresses are well formed; refusing them is the host's decision, with its own class."""
    loopback, metadata = parse_allow(["127.0.0.1:80", "169.254.169.254/32:80"])
    assert loopback.destination == NetworkDestination(network="127.0.0.1/32")
    assert metadata.destination == NetworkDestination(network="169.254.169.254/32")


# ----------------------------------------------------------------------------- cursors
def test_a_cursor_is_lineage_and_sequence() -> None:
    cursor = parse_cursor("5f3c8a1e9b7d42c6a0e1f2d3c4b5a697:41")
    assert (cursor.lineage, cursor.sequence) == ("5f3c8a1e9b7d42c6a0e1f2d3c4b5a697", 41)
    assert parse_cursor(" lin:eage:7 ").lineage == "lin:eage", "the sequence is what follows the last colon"


@pytest.mark.parametrize("text", ["", "41", "lineage:", ":41", "lineage:x", "lineage:-1", "lineage:4.1"])
def test_malformed_cursors_are_usage_errors(text: str) -> None:
    with pytest.raises(InvalidArgument):
        parse_cursor(text)


# ----------------------------------------------------------------------------- formatting
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
    ("ms", "text"),
    [
        (0, "0 ms"),
        (742, "742 ms"),
        (12_300, "12.3 s"),
        (247_000, "4m07s"),
        (3_600_000, "1h00m"),
        (7_500_000, "2h05m"),
        (86_400_000, "1d00h"),
        (273_600_000, "3d04h"),
    ],
)
def test_format_ms(ms: int, text: str) -> None:
    assert format_ms(ms) == text
