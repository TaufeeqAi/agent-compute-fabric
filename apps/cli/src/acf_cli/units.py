"""Parsing of human-friendly quantities.

All parsers are strict and total: they either return a positive integer or raise
:class:`~acf_cli.errors.InvalidArgument` with a message that says what was expected. They never
guess (no silent unit defaults beyond the documented one) because a mis-parsed ``--memory`` is
a resource-admission bug, not a typo.
"""

from __future__ import annotations

import re

from acf_cli.errors import InvalidArgument

_MEMORY = re.compile(r"^(?P<n>[0-9]+)\s*(?P<unit>|m|mi|mib|g|gi|gib)$", re.IGNORECASE)
_DURATION = re.compile(r"^(?P<n>[0-9]+(?:\.[0-9]+)?)\s*(?P<unit>ms|s|m|h)?$", re.IGNORECASE)
_BYTES = re.compile(r"^(?P<n>[0-9]+)\s*(?P<unit>|b|k|kb|kib|m|mb|mib|g|gb|gib)$", re.IGNORECASE)

_KIB = 1024
_MS_PER_SECOND = 1_000
_MS_PER_MINUTE = 60_000

_DURATION_MS = {"ms": 1.0, "s": 1_000.0, "m": 60_000.0, "h": 3_600_000.0}
_BYTES_FACTOR = {
    "": 1,
    "b": 1,
    "k": 1 << 10,
    "kb": 1 << 10,
    "kib": 1 << 10,
    "m": 1 << 20,
    "mb": 1 << 20,
    "mib": 1 << 20,
    "g": 1 << 30,
    "gb": 1 << 30,
    "gib": 1 << 30,
}


def parse_memory_mib(text: str) -> int:
    """``4096`` / ``4096Mi`` / ``4Gi`` -> MiB. A bare number is MiB; ``G`` means GiB (binary units)."""
    m = _MEMORY.match(text.strip())
    if not m:
        raise InvalidArgument(
            f"invalid memory size {text!r}", hint="use e.g. 4096, 512Mi or 4Gi (binary units; bare numbers are MiB)"
        )
    value = int(m["n"])
    unit = m["unit"].lower()
    mib = value * 1024 if unit in {"g", "gi", "gib"} else value
    if mib <= 0:
        raise InvalidArgument("memory must be greater than zero")
    return mib


def parse_duration_ms(text: str) -> int:
    """``90`` / ``90s`` / ``1500ms`` / ``2m`` / ``1h`` -> milliseconds. A bare number is seconds."""
    m = _DURATION.match(text.strip())
    if not m:
        raise InvalidArgument(
            f"invalid duration {text!r}", hint="use e.g. 90, 90s, 1500ms, 2m or 1h (bare numbers are seconds)"
        )
    ms = round(float(m["n"]) * _DURATION_MS[(m["unit"] or "s").lower()])
    if ms <= 0:
        raise InvalidArgument("duration must be greater than zero")
    return ms


def parse_bytes(text: str) -> int:
    """``1048576`` / ``64KiB`` / ``1M`` -> bytes (binary units; a bare number is bytes)."""
    m = _BYTES.match(text.strip())
    if not m:
        raise InvalidArgument(
            f"invalid size {text!r}", hint="use e.g. 65536, 64KiB or 1MiB (binary units; bare numbers are bytes)"
        )
    value = int(m["n"]) * _BYTES_FACTOR[m["unit"].lower()]
    if value <= 0:
        raise InvalidArgument("size must be greater than zero")
    return value


def parse_env(items: list[str]) -> dict[str, str]:
    """``["A=1", "B=two"]`` -> ``{"A": "1", "B": "two"}``. Duplicate or malformed entries are errors."""
    out: dict[str, str] = {}
    for item in items:
        key, sep, value = item.partition("=")
        if not sep or not key:
            raise InvalidArgument(f"invalid --env entry {item!r}", hint="use KEY=VALUE")
        if key in out:
            raise InvalidArgument(f"environment variable {key!r} given more than once")
        out[key] = value
    return out


def format_bytes(count: int) -> str:
    """Compact binary size for humans: ``8 B``, ``1.5 KiB``, ``12.0 MiB``."""
    size = float(count)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < _KIB or unit == "GiB":
            return f"{int(size)} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= _KIB
    return f"{count} B"  # pragma: no cover - loop always returns


def format_ms(ms: int) -> str:
    """``742 ms`` / ``12.3 s`` / ``4m07s``."""
    if ms < _MS_PER_SECOND:
        return f"{ms} ms"
    if ms < _MS_PER_MINUTE:
        return f"{ms / _MS_PER_SECOND:.1f} s"
    minutes, rest = divmod(ms // _MS_PER_SECOND, 60)
    return f"{minutes}m{rest:02d}s"
