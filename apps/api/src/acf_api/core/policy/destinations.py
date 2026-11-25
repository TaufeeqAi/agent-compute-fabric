"""The destination relation: when a requested allowlist entry is inside what a grant allows.

A grant's destinations use the host's entry form, an exact DNS name or an IPv4 network with a set of
ports, and may also hold a suffix rule ``*.<suffix>``. A requested entry is inside the grant if and
only if one of these holds, and anything else is denied:

* name: the requested name equals a granted name, compared as ASCII lower case after conversion to
  A-labels and removal of one trailing dot; or it ends with ``.<suffix>`` of a granted suffix rule, at a
  label boundary;
* network: the requested network is contained in a granted network;

and in either case the requested ports are a subset of the ports granted for that destination.

A requested name is never matched against a granted network, nor a network against a name. A name that
cannot be converted is inside nothing.

Everything here is a pure function. The same functions decide whether one *grant* is inside another,
which is what minting an agent credential checks.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Final

MAX_NAME_LEN: Final = 253
MAX_LABEL_LEN: Final = 63
#: The host's entry form of a network: `a.b.c.d/len`, the length without a leading zero.
_CIDR: Final = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}/(?:0|[1-9][0-9]?)")

PortSet = tuple[tuple[int, int], ...]


@dataclass(frozen=True, slots=True)
class Destination:
    """One destination of a grant or of a request, normalized."""

    #: ``name``, ``suffix`` or ``network``.
    kind: str
    #: The A-label name, the A-label suffix without its ``*.``, or the network in canonical CIDR form.
    value: str
    ports: PortSet


def normalize_name(name: str) -> str | None:  # noqa: PLR0911 - one exit per way a name is not a DNS name
    """``name`` as lower-case A-labels without a trailing dot, or ``None`` if it is not a DNS name."""
    if not name or len(name) > MAX_NAME_LEN + 1:
        return None
    if name.endswith("."):
        name = name[:-1]
    if not name or len(name) > MAX_NAME_LEN:
        return None
    labels: list[str] = []
    for label in name.split("."):
        if not label:
            return None
        try:
            ascii_label = label.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return None
        if not ascii_label or len(ascii_label) > MAX_LABEL_LEN:
            return None
        if not all(c.isascii() and (c.isalnum() or c == "-") for c in ascii_label):
            return None
        if ascii_label.startswith("-") or ascii_label.endswith("-"):
            return None
        labels.append(ascii_label)
    normalized = ".".join(labels)
    # The bound is on the name a resolver sees. An A-label is longer than the text it encodes.
    return normalized if len(normalized) <= MAX_NAME_LEN else None


def normalize_network(network: str) -> str | None:
    """``network`` in canonical CIDR form, or ``None`` if it is not an IPv4 network with no host bits set.

    The form is the host's: a dotted quad, a slash and a prefix length. A bare address, a dotted
    netmask and a zero-padded prefix are other notations, which the host refuses.
    """
    if _CIDR.fullmatch(network) is None:
        return None
    try:
        parsed = ipaddress.IPv4Network(network, strict=True)
    except ValueError:
        return None
    return parsed.with_prefixlen


def _is_port(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65535  # noqa: PLR2004 - the ports of TCP


def normalize_ports(ranges: list[tuple[int, int]]) -> PortSet | None:
    """Sorted, merged, inclusive ranges, or ``None`` if a range is not ``1 <= from <= to <= 65535``.

    A bound that is not an integer makes the set unreadable like any other malformed bound: a view of
    the host is read with this function too, and what it shows is not typed.
    """
    cleaned: list[tuple[int, int]] = []
    for first, last in ranges:
        if not (_is_port(first) and _is_port(last) and first <= last):
            return None
        cleaned.append((first, last))
    if not cleaned:
        return None
    cleaned.sort()
    merged = [cleaned[0]]
    for first, last in cleaned[1:]:
        if first <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], last))
        else:
            merged.append((first, last))
    return tuple(merged)


def ports_inside(requested: PortSet, granted: PortSet) -> bool:
    """Whether every requested port is a granted port."""
    return all(any(g_first <= first and last <= g_last for g_first, g_last in granted) for first, last in requested)


def _name_under_suffix(name: str, suffix: str) -> bool:
    """Whether ``name`` ends with ``.suffix`` at a label boundary. The suffix itself is not under itself."""
    return name.endswith("." + suffix)


def _network_inside(requested: str, granted: str) -> bool:
    return ipaddress.IPv4Network(requested).subnet_of(ipaddress.IPv4Network(granted))


def inside(requested: Destination, granted: tuple[Destination, ...]) -> bool:
    """Whether ``requested`` is inside what ``granted`` allows.

    ``requested`` may itself be a suffix rule: that is how a narrowing is checked against its parent. A
    suffix rule is inside a granted suffix rule when it is equal to it or lies under it.
    """
    for g in granted:
        if not ports_inside(requested.ports, g.ports):
            continue
        if requested.kind == "name":
            if (g.kind == "name" and g.value == requested.value) or (
                g.kind == "suffix" and _name_under_suffix(requested.value, g.value)
            ):
                return True
        elif requested.kind == "suffix":
            if g.kind == "suffix" and (g.value == requested.value or _name_under_suffix(requested.value, g.value)):
                return True
        elif requested.kind == "network" and g.kind == "network" and _network_inside(requested.value, g.value):
            return True
    return False


def destination(
    *, name: str | None, suffix: str | None, network: str | None, ports: list[tuple[int, int]]
) -> Destination | None:
    """Normalize one destination. ``None``: it is malformed, and therefore inside nothing."""
    port_set = normalize_ports(ports)
    if port_set is None:
        return None
    if name is not None:
        value = normalize_name(name)
        return None if value is None else Destination("name", value, port_set)
    if suffix is not None:
        if not suffix.startswith("*."):
            return None
        value = normalize_name(suffix[2:])
        return None if value is None else Destination("suffix", value, port_set)
    if network is not None:
        value = normalize_network(network)
        return None if value is None else Destination("network", value, port_set)
    return None
