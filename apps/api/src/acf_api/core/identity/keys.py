"""API keys and identifiers: their format, how they are made, and how they are recognized exactly.

A key is ``acf<version>_<kind>_<random>_<checksum>``:

* ``acf1``: who issued it and the format version;
* ``dev`` or ``agt``: a developer key or an agent key;
* 43 characters of base62: 256 bits from the operating system's random source;
* 6 characters of base62: the CRC32 of everything before the last underscore.

The checksum is not a secret and adds no security to a key. It lets a secret scanner, and the platform,
tell a real key from a look-alike without a lookup: a malformed key is rejected offline, and a request
body that contains a real key can be refused exactly.

The registry stores the SHA-256 of a key and a display prefix. For a key of 256 random bits a plain
digest is adequate: there is nothing to brute-force, so a slow password hash would buy nothing.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import zlib
from dataclasses import dataclass
from typing import Final

_ALPHABET: Final = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_INDEX: Final = {ch: i for i, ch in enumerate(_ALPHABET)}

#: The issuer's name: the fixed start of a key of any format version.
_ISSUER: Final = "acf"
KEY_FORMAT_VERSION: Final = 1
KEY_PREFIX: Final = f"{_ISSUER}{KEY_FORMAT_VERSION}"
KIND_MARKERS: Final = {"developer": "dev", "agent": "agt"}
_KIND_OF_MARKER: Final = {marker: kind for kind, marker in KIND_MARKERS.items()}
RANDOM_LEN: Final = 43
CHECKSUM_LEN: Final = 6
#: What a key looks like, for scanning text. The checksum decides whether a match is a key.
KEY_PATTERN: Final = re.compile(
    rf"{_ISSUER}[0-9]_(?:dev|agt)_[0-9A-Za-z]{{{RANDOM_LEN}}}_[0-9A-Za-z]{{{CHECKSUM_LEN}}}"
)
DISPLAY_PREFIX_LEN: Final = len(KEY_PREFIX) + 1 + 3 + 1 + 4

_ID_LEN: Final = 20
SCOPE_PATTERN: Final = re.compile(r"^scp-[0-9a-f]{32}$")


def _base62(number: int, length: int) -> str:
    digits: list[str] = []
    while number:
        number, rem = divmod(number, 62)
        digits.append(_ALPHABET[rem])
    return "".join(reversed(digits)).rjust(length, "0")


def _checksum(body: str) -> str:
    return _base62(zlib.crc32(body.encode("ascii")), CHECKSUM_LEN)


@dataclass(frozen=True, slots=True)
class ParsedKey:
    version: int
    kind: str


def generate_key(kind: str) -> str:
    """A new key of ``kind``. The caller shows it once and stores only its digest and display prefix."""
    marker = KIND_MARKERS[kind]
    random_part = _base62(int.from_bytes(secrets.token_bytes(32), "big"), RANDOM_LEN)
    body = f"{KEY_PREFIX}_{marker}_{random_part}"
    return f"{body}_{_checksum(body)}"


def parse_key(text: str) -> ParsedKey | None:
    """What ``text`` is, if it is a well-formed key of a version this build knows. No lookup, no I/O."""
    if KEY_PATTERN.fullmatch(text) is None:
        return None
    body, _, checksum = text.rpartition("_")
    if not hmac.compare_digest(_checksum(body), checksum):
        return None
    prefix, marker, _random = body.split("_")
    version = int(prefix[3:])
    if version != KEY_FORMAT_VERSION:
        return None
    return ParsedKey(version, _KIND_OF_MARKER[marker])


def key_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def display_prefix(text: str) -> str:
    """The part of a key that may be shown and stored: enough to tell two keys apart, useless to an attacker."""
    return text[:DISPLAY_PREFIX_LEN]


def contains_key(text: str) -> bool:
    """Whether ``text`` contains a real key anywhere. Exact: a look-alike without a valid checksum is not one.

    Every place where the issuer's name stands is tried as the start of a key. A scan that took one
    candidate after the other would read a look-alike, find its checksum wrong and resume behind it,
    and so step over a real key that begins inside the look-alike.
    """
    start = text.find(_ISSUER)
    while start != -1:
        match = KEY_PATTERN.match(text, start)
        if match is not None and parse_key(match.group(0)) is not None:
            return True
        start = text.find(_ISSUER, start + 1)
    return False


def kind_of(text: str) -> str | None:
    """The kind a key claims by its marker, without verifying anything else. For messages to a developer."""
    parsed = parse_key(text)
    return None if parsed is None else parsed.kind


def new_id(prefix: str) -> str:
    """A random identifier: ``<prefix>_`` and 20 characters of base62 (about 119 bits)."""
    return f"{prefix}_" + "".join(secrets.choice(_ALPHABET) for _ in range(_ID_LEN))


def new_scope() -> str:
    """A project's scope string: 128 bits from the random source, never derived from a label or a counter."""
    return "scp-" + secrets.token_hex(16)


def new_minted_key() -> str:
    """An idempotency key the platform mints for a tool call that carried none."""
    return "mk_" + "".join(secrets.choice(_ALPHABET) for _ in range(32))
