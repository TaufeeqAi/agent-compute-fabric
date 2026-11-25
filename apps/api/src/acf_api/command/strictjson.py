"""Strict JSON: the one profile in which a request body is read.

A body is UTF-8 JSON. It is refused when it repeats a member name, nests deeper than the bound, carries
a number that JSON does not define (``NaN``, ``Infinity``, or a literal too large for a double, which
would decode to infinity), holds a string that is not text (an escaped half of a surrogate pair), or
is not valid UTF-8. A repeated member name is the case that matters most: two parsers that disagree
about which value wins would give one request two meanings, and the fingerprint of a request must have
exactly one. For the same reason whatever is decoded here can be put in canonical form.

``canonical`` is the form a decoded value is hashed in: sorted member names, no insignificant
whitespace, UTF-8, no escaping of non-ASCII. The same intent therefore has the same bytes whichever
interface it arrived through.
"""

from __future__ import annotations

import json
import math
from typing import Any, Final, NoReturn

#: Deepest nesting a request body may have. Far above anything the public model defines.
MAX_DEPTH: Final = 32


class StrictJsonError(ValueError):
    """The body is not acceptable JSON in the strict profile. The message never repeats the body."""


def _reject_constant(name: str) -> NoReturn:
    msg = f"the number {name} is not JSON"
    raise StrictJsonError(msg)


def _unique_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            msg = "a JSON object repeats a member name"
            raise StrictJsonError(msg)
        out[key] = value
    return out


def _finite(literal: str) -> float:
    """A real number of the body. One too large for a double would decode to infinity, which has no JSON form."""
    value = float(literal)
    if math.isinf(value):
        msg = "a number of the body is too large"
        raise StrictJsonError(msg)
    return value


def _require_text(value: str) -> None:
    """Refuse a string that is not text: an escape that names half of a surrogate pair has no UTF-8 form."""
    if value.isascii():
        return
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        msg = "a string of the body holds half of a surrogate pair"
        raise StrictJsonError(msg) from None


def _depth(value: object, limit: int) -> None:
    """Refuse a value nested deeper than ``limit``, or one that holds a string that is not text.

    Iterative, so depth cannot exhaust the stack. One pass serves both checks: what this function lets
    through, :func:`canonical` can encode.
    """
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, level = stack.pop()
        if isinstance(item, str):
            _require_text(item)
            continue
        if isinstance(item, dict):
            for name in item:
                _require_text(name)
            children: list[Any] = list(item.values())
        elif isinstance(item, list):
            children = item
        else:
            continue
        if level > limit:
            msg = f"the JSON value nests deeper than {limit} levels"
            raise StrictJsonError(msg)
        stack.extend((child, level + 1) for child in children)


def loads(data: bytes | bytearray | memoryview) -> Any:  # noqa: ANN401 - any JSON value: the caller narrows it
    """Decode ``data`` in the strict profile."""
    try:
        text = bytes(data).decode("utf-8", errors="strict")
    except UnicodeDecodeError as e:
        msg = "the body is not valid UTF-8"
        raise StrictJsonError(msg) from e
    if text.startswith("\ufeff"):
        msg = "the body starts with a byte order mark"
        raise StrictJsonError(msg)
    try:
        value = json.loads(
            text, object_pairs_hook=_unique_members, parse_constant=_reject_constant, parse_float=_finite
        )
    except StrictJsonError:
        raise
    except RecursionError as e:
        msg = f"the JSON value nests deeper than {MAX_DEPTH} levels"
        raise StrictJsonError(msg) from e
    except ValueError as e:
        # json.JSONDecodeError, and the bare ValueError of an oversized integer literal.
        msg = "the body is not valid JSON"
        raise StrictJsonError(msg) from e
    _depth(value, MAX_DEPTH)
    return value


def loads_object(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Decode ``data`` and require a JSON object at the top."""
    value = loads(data)
    if not isinstance(value, dict):
        msg = "the body must be a JSON object"
        raise StrictJsonError(msg)
    return value


def canonical(value: object) -> bytes:
    """The canonical bytes of a decoded JSON value: what a fingerprint or a digest is computed over."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def dumps(value: object) -> bytes:
    """Compact JSON for a response body or a frame."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
