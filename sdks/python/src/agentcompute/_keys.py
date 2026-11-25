"""Idempotency keys: one per logical call, made before the first attempt and never changed after.

A key is what makes "ask again" safe: the platform maps one key to one operation, so a request that is
repeated with the same key and the same body can never create a second one. Three rules keep that true
on this side, and all three live here or are enforced by the callers of this module:

* the key exists before the first attempt, so that even a request that never got an answer can be resolved;
* a retry reuses it, with the same body, byte for byte;
* no situation is ever escaped by making a new key. A conflict, a request in progress, an unresolved or a
  lost outcome are surfaced to the caller with the key they concern.

``sandboxes.create()`` is two operations, and possibly a third: create, start, and a destroy when the
start fails. The second and third use keys derived from the caller's, so the whole sequence resumes from
one key.
"""

from __future__ import annotations

import uuid
from typing import Final

__all__ = ["CREATE_KEY_MAX_LENGTH", "KEY_MAX_LENGTH", "checked", "destroy_key", "for_call", "new_key", "start_key"]

#: The longest key the API accepts.
KEY_MAX_LENGTH: Final = 255

_START_SUFFIX: Final = ":start"
_DESTROY_SUFFIX: Final = ":destroy"

#: The longest key ``sandboxes.create()`` accepts: it must leave room for the longer derived suffix.
CREATE_KEY_MAX_LENGTH: Final = KEY_MAX_LENGTH - len(_DESTROY_SUFFIX)

_FIRST_CHARACTER: Final = "\x21"
_LAST_CHARACTER: Final = "\x7e"


def new_key() -> str:
    """A key nobody else has: a random UUID (version 4)."""
    return str(uuid.uuid4())


def checked(key: object, *, limit: int = KEY_MAX_LENGTH) -> str:
    """The caller's key, if the API can take it: 1 to ``limit`` characters, each from 0x21 to 0x7E.

    The platform compares keys byte for byte and never normalizes them, so neither does this function:
    a key with a space or a non-ASCII character is refused, not repaired.
    """
    if not isinstance(key, str):
        raise ValueError("idempotency_key must be a string")
    if not key or len(key) > limit:
        raise ValueError(f"idempotency_key must be 1 to {limit} characters long; this one has {len(key)}")
    if not all(_FIRST_CHARACTER <= character <= _LAST_CHARACTER for character in key):
        raise ValueError("idempotency_key may only hold visible ASCII characters (0x21 to 0x7E, so no space)")
    return key


def for_call(key: str | None, *, limit: int = KEY_MAX_LENGTH) -> str:
    """The key of one logical call: the caller's, checked, or a new one."""
    return new_key() if key is None else checked(key, limit=limit)


def start_key(key: str) -> str:
    """The key of the start that ``sandboxes.create()`` issues after its create."""
    return key + _START_SUFFIX


def destroy_key(key: str) -> str:
    """The key of the destroy that ``sandboxes.create()`` issues when the start fails."""
    return key + _DESTROY_SUFFIX
