"""API keys and identifiers: their format, how they are recognized exactly, and what may be shown of them.

Proves CRD-3 (the format: issuer and version, kind marker, 256 random bits in base62, a CRC32 of the
rest), CRD-4 (what the registry may hold of a key: a digest and a display prefix), SEC-118 as far as a
pure function can (a key inside any text is found exactly, and nothing that is not a key is), PRJ-1
(a scope string is 128 bits from the random source and nothing else) and the syntax AZ-10 relies on
(the kind marker). Catalog entries: T3-AUTH-01, T3-RED-02, and the detector half of T3-RED-42. That a
request carrying a key is refused in each of the four places is proven by the pipeline suite.

The tests look at the encoding, never at the quality of the random source: the source is the
operating system's, and a test cannot measure it.
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import itertools
import json
import re
import subprocess
import sys
import zlib
from collections import Counter
from pathlib import Path
from typing import Any
from unittest import mock

import jsonschema
import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from acf_api.command import model as m
from acf_api.core import config as cfg
from acf_api.core.identity import keys

REPO = Path(__file__).resolve().parents[3]

BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
KEY_SHAPE = re.compile(r"^acf1_(dev|agt)_[0-9A-Za-z]{43}_[0-9A-Za-z]{6}$")
KEY_LENGTH = 4 + 1 + 3 + 1 + 43 + 1 + 6
KINDS = {"developer": "dev", "agent": "agt"}
#: The one source of randomness of the module, by the name under which the module reaches it.
RANDOM_SOURCE = "acf_api.core.identity.keys.secrets.token_bytes"

base62_text = st.text(alphabet=BASE62, max_size=80)
#: Text that looks like what surrounds a key in a request: base64 in both alphabets, and JSON punctuation.
plain_text = st.text(alphabet=BASE62 + "+/=-_ .,:\"'{}[]\n", max_size=120)
random_parts = st.text(alphabet=BASE62, min_size=43, max_size=43)
checksums = st.text(alphabet=BASE62, min_size=6, max_size=6)


def to_base62(number: int, length: int) -> str:
    """Base62, most significant digit first, padded with the zero digit. Written apart from the implementation."""
    digits = ""
    while number:
        number, rem = divmod(number, 62)
        digits = BASE62[rem] + digits
    return digits.rjust(length, "0")


def from_base62(text: str) -> int:
    number = 0
    for ch in text:
        number = number * 62 + BASE62.index(ch)
    return number


def checksum_of(body: str) -> str:
    return to_base62(zlib.crc32(body.encode("ascii")), 6)


def forged(prefix: str, marker: str, random_part: str) -> str:
    """A key-shaped string with a correct checksum, for any prefix, marker and random part."""
    body = f"{prefix}_{marker}_{random_part}"
    return f"{body}_{checksum_of(body)}"


def some_keys() -> list[str]:
    return [keys.generate_key(kind) for kind in KINDS for _ in range(3)]


# ------------------------------------------------------------------------------- format
@pytest.mark.proves("T3-AUTH-01")
@pytest.mark.parametrize(("kind", "marker"), sorted(KINDS.items()))
def test_a_generated_key_has_the_format_of_the_contract(kind: str, marker: str) -> None:
    for _ in range(200):
        key = keys.generate_key(kind)
        assert KEY_SHAPE.fullmatch(key)
        assert len(key) == KEY_LENGTH == 59
        prefix, shown_marker, random_part, checksum = key.split("_")
        assert (prefix, shown_marker) == ("acf1", marker)
        assert len(random_part) == 43
        assert checksum == checksum_of(f"{prefix}_{shown_marker}_{random_part}")


@pytest.mark.proves("T3-AUTH-01")
def test_there_are_exactly_two_kinds() -> None:
    assert keys.KIND_MARKERS == KINDS
    assert keys.KEY_FORMAT_VERSION == 1
    assert keys.KEY_PREFIX == "acf1"
    with pytest.raises(KeyError):
        keys.generate_key("operator")


@pytest.mark.proves("T3-AUTH-01")
@given(st.binary(min_size=32, max_size=32), st.sampled_from(sorted(KINDS)))
def test_the_random_part_is_exactly_the_256_bits_of_the_source(source: bytes, kind: str) -> None:
    """One call for 32 bytes, encoded one-to-one: no bit is dropped, folded or added."""
    with mock.patch(RANDOM_SOURCE, return_value=source) as token_bytes:
        key = keys.generate_key(kind)
    token_bytes.assert_called_once_with(32)
    random_part = key.split("_")[2]
    assert from_base62(random_part).to_bytes(32, "big") == source


@pytest.mark.proves("T3-AUTH-01")
@pytest.mark.parametrize(
    "source", [bytes(32), b"\xff" * 32, bytes(range(1, 33)), b"\x80" + bytes(31), bytes(31) + b"\x01"]
)
def test_the_extremes_of_the_random_part_keep_the_fixed_length(source: bytes) -> None:
    """The largest 256-bit number still fits 43 base62 digits, and the smallest is padded to them."""
    with mock.patch(RANDOM_SOURCE, return_value=source):
        key = keys.generate_key("agent")
    assert len(key) == KEY_LENGTH
    assert KEY_SHAPE.fullmatch(key)
    assert from_base62(key.split("_")[2]) == int.from_bytes(source, "big")
    assert keys.parse_key(key) == keys.ParsedKey(1, "agent")
    assert 62**43 > 2**256 > 62**42, "43 digits are the fewest that hold 256 bits"


@pytest.mark.proves("T3-AUTH-01")
def test_the_checksum_is_the_crc32_of_everything_before_it() -> None:
    body = "acf1_dev_" + "0" * 43
    assert zlib.crc32(body.encode("ascii")) == from_base62(checksum_of(body))
    assert keys.parse_key(f"{body}_{checksum_of(body)}") == keys.ParsedKey(1, "developer")
    assert 62**6 > 2**32, "six digits hold every CRC32"


# ------------------------------------------------------------------------------- recognizing a key
@pytest.mark.proves("T3-AUTH-01")
@pytest.mark.parametrize("kind", sorted(KINDS))
def test_a_generated_key_is_recognized_with_its_kind(kind: str) -> None:
    for _ in range(200):
        key = keys.generate_key(kind)
        assert keys.parse_key(key) == keys.ParsedKey(version=1, kind=kind)
        assert keys.kind_of(key) == kind


@pytest.mark.proves("T3-AUTH-01")
def test_every_single_character_corruption_is_rejected() -> None:
    """Every position, every other character: offline, a damaged key is never taken for a key."""
    replacements = BASE62 + "_-+/= "
    for key in some_keys():
        for position, original in enumerate(key):
            for replacement in replacements:
                if replacement == original:
                    continue
                damaged = key[:position] + replacement + key[position + 1 :]
                assert keys.parse_key(damaged) is None, (position, replacement)


@pytest.mark.proves("T3-AUTH-01")
def test_swapped_neighbours_and_lost_or_added_characters_are_rejected() -> None:
    for key in some_keys():
        for position in range(len(key) - 1):
            if key[position] != key[position + 1]:
                swapped = key[:position] + key[position + 1] + key[position] + key[position + 2 :]
                assert keys.parse_key(swapped) is None, position
        for position in range(len(key)):
            assert keys.parse_key(key[:position] + key[position + 1 :]) is None, position
        for position in range(len(key) + 1):
            for extra in "0aZ_":
                assert keys.parse_key(key[:position] + extra + key[position:]) is None, (position, extra)


@pytest.mark.proves("T3-AUTH-01")
@given(random_parts, st.sampled_from(["usr", "DEV", "AGT", "dev1", "de", "adm", "opr", "key", ""]))
def test_a_wrong_kind_marker_is_rejected_even_with_a_correct_checksum(random_part: str, marker: str) -> None:
    assert keys.parse_key(forged("acf1", marker, random_part)) is None


@pytest.mark.proves("T3-AUTH-01")
@given(
    random_parts,
    st.sampled_from(["acf0", "acf2", "acf9", "acf10", "acf", "ACF1", "acg1", "xcf1", "acf\u0661"]),
    st.sampled_from(["dev", "agt"]),
)
def test_another_version_or_issuer_is_rejected_even_with_a_correct_checksum(
    random_part: str, prefix: str, marker: str
) -> None:
    body = f"{prefix}_{marker}_{random_part}"
    checksum = to_base62(zlib.crc32(body.encode("utf-8")), 6)
    assert keys.parse_key(f"{body}_{checksum}") is None


@pytest.mark.proves("T3-AUTH-01")
@given(st.text(alphabet=BASE62, max_size=90).filter(lambda part: len(part) != 43), st.sampled_from(["dev", "agt"]))
def test_a_random_part_of_another_length_is_rejected_even_with_a_correct_checksum(
    random_part: str, marker: str
) -> None:
    assert keys.parse_key(forged("acf1", marker, random_part)) is None


@pytest.mark.proves("T3-AUTH-01")
@given(random_parts, checksums, st.sampled_from(["dev", "agt"]))
def test_a_look_alike_with_another_checksum_is_rejected(random_part: str, checksum: str, marker: str) -> None:
    body = f"acf1_{marker}_{random_part}"
    assume(checksum != checksum_of(body))
    assert keys.parse_key(f"{body}_{checksum}") is None


@pytest.mark.proves("T3-AUTH-01")
def test_text_around_a_key_makes_it_not_a_key() -> None:
    """`parse_key` answers for the whole text. A key with anything before or after it is not a key."""
    key = keys.generate_key("developer")
    for wrapped in (
        f" {key}",
        f"{key} ",
        f"{key}\n",
        f"\n{key}",
        f"Bearer {key}",
        f"{key}{key}",
        f'"{key}"',
        key.lower(),
        key.upper(),
    ):
        assert keys.parse_key(wrapped) is None, wrapped[:12]
    assert keys.parse_key("") is None


@pytest.mark.proves("T3-AUTH-01")
def test_digits_and_letters_of_other_scripts_are_not_base62() -> None:
    key = keys.generate_key("agent")
    body, _, _checksum = key.rpartition("_")
    for position in range(9, 52):
        for foreign in (
            "\u0661",
            "\uff10",
            "\u0430",
            "\uff21",
        ):  # Arabic-Indic one, fullwidth zero, Cyrillic a, fullwidth A
            altered = body[:position] + foreign + body[position + 1 :]
            checksum = to_base62(zlib.crc32(altered.encode("utf-8")), 6)
            assert keys.parse_key(f"{altered}_{checksum}") is None


@pytest.mark.proves("T3-AUTH-01")
@given(st.text(max_size=120))
def test_any_text_is_answered_without_an_error(text: str) -> None:
    """Malformed keys are rejected offline: no lookup, no exception, whatever the caller sent."""
    parsed = keys.parse_key(text)
    assert parsed is None or KEY_SHAPE.fullmatch(text)
    assert keys.kind_of(text) == (None if parsed is None else parsed.kind)
    assert isinstance(keys.contains_key(text), bool)


# ------------------------------------------------------------------------------- a key inside other text
@pytest.mark.proves("T3-AUTH-01", "T3-RED-42")
@given(plain_text, plain_text, st.sampled_from(sorted(KINDS)))
def test_a_key_is_found_at_the_start_at_the_end_and_in_the_middle(before: str, after: str, kind: str) -> None:
    key = keys.generate_key(kind)
    assert keys.contains_key(key)
    assert keys.contains_key(key + after)
    assert keys.contains_key(before + key)
    assert keys.contains_key(before + key + after)


@pytest.mark.proves("T3-RED-42")
def test_a_key_is_found_where_requests_carry_text() -> None:
    key = keys.generate_key("agent")
    for text in (
        f"Authorization: Bearer {key}",
        json.dumps({"env": {"ACF_API_KEY": key}}),
        f"https://example.test/?api_key={key}&x=1",
        f"export ACF_API_KEY={key}\n",
        f"x{key}y",
        f"{key}{key}",
        f"acf1_dev_{key}",
        "A" * 5000 + key + "B" * 5000,
    ):
        assert keys.contains_key(text), text[:24]


@pytest.mark.proves("T3-RED-42")
@pytest.mark.parametrize("shared", [1, 2, 3, 4])
@pytest.mark.parametrize("kind", sorted(KINDS))
def test_a_look_alike_that_runs_into_a_key_does_not_hide_it(shared: int, kind: str) -> None:
    """A decoy whose last characters are the first characters of a real key. The key is still there, verbatim.

    A scan that takes candidates one after the other, never overlapping, reads the decoy, finds its
    checksum wrong, and resumes behind it: in the middle of the key. The test is exact only if every
    position is a possible start.
    """
    key = keys.generate_key(kind)
    decoy = "acf1_dev_" + "A" * 43 + "_" + "B" * (6 - shared)
    text = decoy + key
    assert keys.KEY_PATTERN.fullmatch(text[:KEY_LENGTH]), "the decoy must be key-shaped up to and into the key"
    assert keys.parse_key(text[:KEY_LENGTH]) is None
    assert keys.contains_key(text)
    assert keys.contains_key("noise " + text + " noise")


@pytest.mark.proves("T3-RED-42")
@given(
    st.lists(st.sampled_from(["acf1_dev_", "acf1_agt_", "acf1", "_", "A" * 43, "B" * 6, "a", "0"]), max_size=12),
    st.sampled_from(sorted(KINDS)),
)
def test_no_arrangement_of_key_fragments_before_a_key_hides_it(fragments: list[str], kind: str) -> None:
    key = keys.generate_key(kind)
    assert keys.contains_key("".join(fragments) + key)
    assert keys.contains_key("".join(fragments) + key + "".join(fragments))


@pytest.mark.proves("T3-RED-42")
@given(plain_text, random_parts, checksums, st.sampled_from(["dev", "agt"]), plain_text)
def test_a_look_alike_with_a_wrong_checksum_is_not_flagged(
    before: str, random_part: str, checksum: str, marker: str, after: str
) -> None:
    body = f"acf1_{marker}_{random_part}"
    assume(checksum != checksum_of(body))
    assert not keys.contains_key(f"{before}{body}_{checksum}{after}")


@pytest.mark.proves("T3-RED-42")
@given(
    st.text(alphabet=BASE62 + "+/=", max_size=400),
    st.text(alphabet=BASE62 + "-_", max_size=400),
    st.binary(max_size=300),
)
def test_random_base62_and_base64_text_is_not_flagged(standard: str, urlsafe: str, raw: bytes) -> None:
    """Exact means no false alarm either: an argument that is ordinary encoded data is not refused."""
    assert not keys.contains_key(standard)
    assert not keys.contains_key(urlsafe)
    assert not keys.contains_key(base64.b64encode(raw).decode("ascii"))
    assert not keys.contains_key(base64.urlsafe_b64encode(raw).decode("ascii"))
    assert not keys.contains_key(raw.hex())


@pytest.mark.proves("T3-RED-42")
def test_things_that_resemble_a_key_are_not_flagged() -> None:
    key = keys.generate_key("developer")
    body, _, checksum = key.rpartition("_")
    wrong = "000000" if checksum != "000000" else "000001"
    for text in (
        "",
        "acf1_dev_",
        key[:-1],
        key[1:],
        f"{body}_{wrong}",
        keys.display_prefix(key),
        key.replace("_", "-"),
        key.replace("_", " "),
        key[:30] + "\n" + key[30:],
        key[:30] + " " + key[30:],
        keys.key_digest(key),
        forged("acf1", "usr", "A" * 43),
        "mk_" + "A" * 32,
    ):
        assert not keys.contains_key(text), text[:16]


# ------------------------------------------------------------------------------- what may be shown and stored
@pytest.mark.proves("T3-AUTH-01")
@pytest.mark.parametrize("kind", sorted(KINDS))
def test_the_display_prefix_shows_four_characters_of_the_random_part_and_no_more(kind: str) -> None:
    for _ in range(100):
        key = keys.generate_key(kind)
        prefix = keys.display_prefix(key)
        random_part = key.split("_")[2]
        assert prefix == f"acf1_{KINDS[kind]}_{random_part[:4]}"
        assert len(prefix) == keys.DISPLAY_PREFIX_LEN == 13
        assert random_part[4:] not in prefix
        assert keys.parse_key(prefix) is None
        assert not keys.contains_key(prefix)


@pytest.mark.proves("T3-AUTH-01")
def test_the_stored_digest_is_the_sha256_of_the_whole_key_and_reveals_none_of_it() -> None:
    key = keys.generate_key("developer")
    digest = keys.key_digest(key)
    assert digest == hashlib.sha256(key.encode("utf-8")).hexdigest()
    assert re.fullmatch(r"[0-9a-f]{64}", digest)
    assert key.split("_")[2] not in digest
    other = keys.generate_key("developer")
    assert keys.key_digest(other) != digest
    assert keys.key_digest(key[:-1] + ("0" if key[-1] != "0" else "1")) != digest


@pytest.mark.proves("T3-AUTH-01")
def test_what_parsing_returns_never_carries_the_key() -> None:
    """A parsed key is safe to log: it says a version and a kind, and nothing of the secret."""
    key = keys.generate_key("agent")
    parsed = keys.parse_key(key)
    assert parsed is not None
    random_part = key.split("_")[2]
    for rendering in (repr(parsed), str(parsed)):
        assert random_part not in rendering
        assert random_part[:8] not in rendering


# ------------------------------------------------------------------------------- identifiers and scope strings
@pytest.mark.proves("T3-AUTH-01")
def test_identifiers_have_the_documented_shapes() -> None:
    for prefix, pattern in (
        ("prj", m.PROJECT_ID_PATTERN),
        ("crd", m.CREDENTIAL_ID_PATTERN),
        ("dep", cfg.DEPLOYMENT_ID_PATTERN),
        ("prn", r"^prn_[0-9A-Za-z]{20}$"),
        ("bnd", r"^bnd_[0-9A-Za-z]{20}$"),
    ):
        made = {keys.new_id(prefix) for _ in range(500)}
        assert len(made) == 500
        for identifier in made:
            assert re.fullmatch(pattern, identifier), identifier
            assert re.fullmatch(rf"{prefix}_[0-9A-Za-z]{{20}}", identifier)
    minted = {keys.new_minted_key() for _ in range(500)}
    assert len(minted) == 500
    for key in minted:
        assert re.fullmatch(r"mk_[0-9A-Za-z]{32}", key)
        # A minted idempotency key is a key of the wire: 1 to 255 characters in the range 0x21 to 0x7E.
        assert re.fullmatch(r"[\x21-\x7e]{1,255}", key)
        assert not keys.contains_key(key)


@pytest.mark.proves("T3-RED-02")
def test_a_scope_string_is_128_bits_from_the_random_source_and_nothing_else() -> None:
    """PRJ-1: no label, no name and no counter can enter, because the function takes nothing and reads one source."""
    assert not inspect.signature(keys.new_scope).parameters
    for source in (bytes(16), b"\xff" * 16, bytes(range(16)), b"\x00" * 15 + b"\x01"):
        with mock.patch(RANDOM_SOURCE, return_value=source) as token_bytes:
            scope = keys.new_scope()
        token_bytes.assert_called_once_with(16)
        assert scope == "scp-" + source.hex()
        assert keys.SCOPE_PATTERN.fullmatch(scope)


@pytest.mark.proves("T3-RED-02")
def test_a_scope_string_is_an_owner_scope_the_host_accepts() -> None:
    host_api: dict[str, Any] = json.loads(
        (REPO / "execution" / "contracts" / "host-api.json").read_text(encoding="utf-8")
    )
    schema = {"$schema": host_api["$schema"], "$defs": host_api["$defs"], "$ref": "#/$defs/OwnerScope"}
    validator = jsonschema.Draft202012Validator(schema)
    for _ in range(200):
        scope = keys.new_scope()
        assert keys.SCOPE_PATTERN.fullmatch(scope)
        assert len(scope) == 36
        validator.validate(scope)


#: A fresh interpreter per batch: what a core is after a restart, whatever its store was restored to.
_BATCH = """
import sys
from acf_api.core.identity.keys import new_scope
count = int(sys.argv[1])
scopes = [new_scope() for _ in range(count)]
assert all(len(s) == 36 and s.startswith("scp-") for s in scopes)
sys.stdout.write("".join(s[4:] for s in scopes))
"""


@pytest.mark.proves("T3-RED-02")
@pytest.mark.timeout(120)
def test_a_million_scope_strings_across_restarts_hold_no_repeat_and_no_counter() -> None:
    """A million scope strings from four processes that share nothing: no repeat, and no position that counts.

    A generator that kept its place in the store, in a file or in a seeded sequence would start again
    from the same place in each fresh process and repeat itself. One that counted would hold most of
    its bytes still.
    """
    batches, per_batch = 4, 250_000
    children = [
        subprocess.Popen([sys.executable, "-c", _BATCH, str(per_batch)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for _ in range(batches)
    ]
    outputs = []
    for child in children:
        out, err = child.communicate(timeout=100)
        assert child.returncode == 0, err.decode("utf-8", "replace")[-400:]
        outputs.append(out)
    raw = b"".join(bytes.fromhex(out.decode("ascii")) for out in outputs)
    total = batches * per_batch
    assert len(raw) == 16 * total == 16_000_000

    assert len({raw[i : i + 16] for i in range(0, len(raw), 16)}) == total == 1_000_000

    # Every byte of a scope takes every value, about equally often. Of 100 000 scopes each value is
    # expected 391 times in a position, with a deviation of 20: the bounds are ten deviations wide.
    sample = raw[: 16 * 100_000]
    for position in range(16):
        seen = Counter(sample[position::16])
        assert len(seen) == 256, position
        assert min(seen.values()) > 190, position
        assert max(seen.values()) < 590, position

    # No scope follows from the one before it by a step.
    numbers = [int.from_bytes(raw[i : i + 16], "big") for i in range(0, 16 * 50_000, 16)]
    steps = {b - a for a, b in itertools.pairwise(numbers)}
    assert len(steps) == len(numbers) - 1
    assert min(abs(step) for step in steps) > 2**64


@pytest.mark.proves("T3-RED-02")
@settings(max_examples=25)
@given(st.integers(min_value=0, max_value=2**128 - 1))
def test_scope_strings_of_any_two_draws_differ_exactly_when_the_draws_differ(number: int) -> None:
    """The encoding loses nothing: two scopes are equal only if all 128 bits were."""
    with mock.patch(RANDOM_SOURCE, return_value=number.to_bytes(16, "big")):
        one = keys.new_scope()
    with mock.patch(RANDOM_SOURCE, return_value=((number + 1) % 2**128).to_bytes(16, "big")):
        other = keys.new_scope()
    assert one != other
    assert int(one[4:], 16) == number
