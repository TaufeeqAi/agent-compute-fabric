"""Parsing of command-line values, and formatting of quantities for people.

All parsers are strict and total: they either return a well-formed value or raise
:class:`~acf_cli.errors.InvalidArgument` with a message that says what was expected. They never
guess (no silent unit defaults beyond the documented one): a mis-parsed ``--memory`` is a
resource-admission mistake, not a typo.
"""

from __future__ import annotations

import ipaddress
import re

from pydantic import ValidationError

from acf_cli.errors import InvalidArgument
from acf_cli.requests import AllowEntry, Cursor, NameDestination, NetworkDestination, PortRange, SecretRef

_MEMORY = re.compile(r"^(?P<n>[0-9]+)\s*(?P<unit>|m|mi|mib|g|gi|gib)$", re.IGNORECASE)
_DURATION = re.compile(r"^(?P<n>[0-9]+(?:\.[0-9]+)?)\s*(?P<unit>ms|s|m|h|d)?$", re.IGNORECASE)
_BYTES = re.compile(r"^(?P<n>[0-9]+)\s*(?P<unit>|b|k|kb|kib|m|mb|mib|g|gb|gib)$", re.IGNORECASE)
_PORTS = re.compile(r"^(?P<low>[0-9]{1,5})(?:-(?P<high>[0-9]{1,5}))?$")

_KIB = 1024
_MS_PER_SECOND = 1_000
_MS_PER_MINUTE = 60_000
_S_PER_HOUR = 3_600
_S_PER_DAY = 86_400

_DURATION_MS = {"ms": 1.0, "s": 1_000.0, "m": 60_000.0, "h": 3_600_000.0, "d": 86_400_000.0}
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

_ALLOW_HINT = "use NAME:PORTS or CIDR:PORTS, for example pypi.org:443 or 198.51.100.0/24:5432-5433,8443"


def parse_memory_mib(text: str) -> int:
    """``4096`` / ``4096Mi`` / ``4Gi`` -> MiB. A bare number is MiB; ``G`` means GiB (binary units)."""
    m = _MEMORY.match(text.strip())
    if not m:
        raise InvalidArgument(
            f"invalid size {text!r}", hint="use e.g. 4096, 512Mi or 4Gi (binary units; bare numbers are MiB)"
        )
    value = int(m["n"])
    unit = m["unit"].lower()
    mib = value * 1024 if unit in {"g", "gi", "gib"} else value
    if mib <= 0:
        raise InvalidArgument("a size must be greater than zero")
    return mib


def parse_duration_ms(text: str) -> int:
    """``90`` / ``90s`` / ``1500ms`` / ``2m`` / ``1h`` / ``1d`` -> milliseconds. A bare number is seconds."""
    m = _DURATION.match(text.strip())
    if not m:
        raise InvalidArgument(
            f"invalid duration {text!r}", hint="use e.g. 90, 90s, 1500ms, 2m, 1h or 1d (bare numbers are seconds)"
        )
    ms = round(float(m["n"]) * _DURATION_MS[(m["unit"] or "s").lower()])
    if ms <= 0:
        raise InvalidArgument("a duration must be greater than zero")
    return ms


def parse_duration_s(text: str) -> float:
    """A duration in seconds, for client-side waiting."""
    return parse_duration_ms(text) / _MS_PER_SECOND


def parse_whole_seconds(text: str, *, what: str) -> int:
    """A duration the host counts in whole seconds (a sandbox lifetime)."""
    ms = parse_duration_ms(text)
    if ms % _MS_PER_SECOND:
        raise InvalidArgument(f"{what} must be a whole number of seconds, not {text!r}")
    return ms // _MS_PER_SECOND


def parse_bytes(text: str) -> int:
    """``1048576`` / ``64KiB`` / ``1M`` -> bytes (binary units; a bare number is bytes)."""
    m = _BYTES.match(text.strip())
    if not m:
        raise InvalidArgument(
            f"invalid size {text!r}", hint="use e.g. 65536, 64KiB or 1MiB (binary units; bare numbers are bytes)"
        )
    value = int(m["n"]) * _BYTES_FACTOR[m["unit"].lower()]
    if value <= 0:
        raise InvalidArgument("a size must be greater than zero")
    return value


def parse_env(items: list[str]) -> dict[str, str]:
    """``["A=1", "B=two"]`` -> ``{"A": "1", "B": "two"}``. Duplicate or malformed entries are errors."""
    out: dict[str, str] = {}
    for item in items:
        key, sep, value = item.partition("=")
        if not sep:
            raise InvalidArgument(f"invalid --env entry {item!r}", hint="use KEY=VALUE")
        if not key:
            raise InvalidArgument("an --env entry has no variable name", hint="use KEY=VALUE")
        if key in out:
            raise InvalidArgument(f"environment variable {key!r} given more than once")
        out[key] = value
    return out


def parse_secret_env(items: list[str]) -> dict[str, SecretRef]:
    """``["API_TOKEN=ci-token"]`` -> variable name to secret **reference**.

    A reference is the name of a secret the operator provisioned on the host. The value given here
    is never echoed, in case someone passes the secret itself by mistake: a value that is not a
    well-formed reference is refused without being repeated, and is never sent.
    """
    out: dict[str, SecretRef] = {}
    for item in items:
        key, sep, reference = item.partition("=")
        if not sep or not key:
            raise InvalidArgument("a --secret-env entry is not of the form VARIABLE=REFERENCE")
        if key in out:
            raise InvalidArgument(f"secret variable {key!r} given more than once")
        try:
            out[key] = SecretRef(ref=reference)
        except ValidationError:
            raise InvalidArgument(
                f"the value given for secret variable {key!r} is not a secret reference",
                hint="a reference is the NAME of a secret provisioned on the host: 1-64 characters of "
                "[A-Za-z0-9._-], not starting with a dot. Never pass the secret itself",
            ) from None
    return out


def _port_ranges(text: str, entry: str) -> list[PortRange]:
    ranges: list[PortRange] = []
    for part in text.split(","):
        m = _PORTS.match(part.strip())
        if not m:
            raise InvalidArgument(f"invalid ports {part!r} in --allow {entry!r}", hint=_ALLOW_HINT)
        low = int(m["low"])
        high = int(m["high"]) if m["high"] is not None else low
        try:
            ranges.append(PortRange(low=low, high=high))
        except ValidationError:
            raise InvalidArgument(
                f"invalid ports {part!r} in --allow {entry!r}", hint="ports are 1-65535, and a range is LOW-HIGH"
            ) from None
    return ranges


def parse_allow(items: list[str]) -> list[AllowEntry]:
    """``["pypi.org:443", "198.51.100.0/24:5432-5433,8443"]`` -> allowlist entries.

    A destination with a ``/`` is an IPv4 network; a bare IPv4 address is that single address
    (``/32``); anything else is an exact DNS name. Whether an entry is *permitted* is the host's
    decision (some destinations are always denied), never this client's.
    """
    entries: list[AllowEntry] = []
    for item in items:
        destination, sep, ports = item.strip().rpartition(":")
        if not sep or not destination or not ports:
            raise InvalidArgument(f"invalid --allow entry {item!r}", hint=_ALLOW_HINT)
        target: NameDestination | NetworkDestination
        try:
            if "/" in destination:
                target = NetworkDestination(network=destination)
            elif _is_ipv4(destination):
                target = NetworkDestination(network=f"{destination}/32")
            else:
                target = NameDestination(name=destination)
        except ValidationError:
            raise InvalidArgument(f"invalid destination in --allow {item!r}", hint=_ALLOW_HINT) from None
        entries.append(AllowEntry(destination=target, ports=_port_ranges(ports, item)))
    return entries


def _is_ipv4(text: str) -> bool:
    try:
        ipaddress.IPv4Address(text)
    except ValueError:
        return False
    return True


def parse_cursor(text: str) -> Cursor:
    """``LINEAGE:SEQUENCE``, as printed after every listing, -> a cursor for ``--changed-since``."""
    lineage, sep, sequence = text.strip().rpartition(":")
    if not sep or not lineage or not sequence.isdecimal():
        raise InvalidArgument(
            f"invalid cursor {text!r}", hint="use the cursor a listing printed: LINEAGE:SEQUENCE (see --json: next)"
        )
    return Cursor(lineage=lineage, sequence=int(sequence))


def format_bytes(count: int) -> str:
    """Compact binary size for humans: ``8 B``, ``1.5 KiB``, ``12.0 MiB``."""
    size = float(count)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < _KIB or unit == "GiB":
            return f"{int(size)} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= _KIB
    return f"{count} B"  # pragma: no cover - loop always returns


def format_ms(ms: int) -> str:
    """``742 ms`` / ``12.3 s`` / ``4m07s`` / ``2h05m`` / ``3d04h``."""
    if ms < _MS_PER_SECOND:
        return f"{ms} ms"
    if ms < _MS_PER_MINUTE:
        return f"{ms / _MS_PER_SECOND:.1f} s"
    seconds = ms // _MS_PER_SECOND
    if seconds < _S_PER_HOUR:
        minutes, rest = divmod(seconds, 60)
        return f"{minutes}m{rest:02d}s"
    if seconds < _S_PER_DAY:
        hours, rest = divmod(seconds, _S_PER_HOUR)
        return f"{hours}h{rest // 60:02d}m"
    days, rest = divmod(seconds, _S_PER_DAY)
    return f"{days}d{rest // _S_PER_HOUR:02d}h"
