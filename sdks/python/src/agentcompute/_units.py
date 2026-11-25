"""What a caller may write for a size, a duration, a network or a command, and nothing else.

The API takes integers: vCPUs, MiB, seconds. People write ``"4GiB"`` and ``"10m"``. This module is the
only place where one becomes the other, and it is strict on purpose: a mis-read ``memory`` is a
resource-admission mistake, not a typo. Every function here either returns a well-formed value or raises
:class:`ValueError` with a message that says what was expected, before any request is made. Nothing is
guessed: no decimal unit is read as a binary one, no bare number in a string is given a unit, and
nothing is rounded. ``"1.5GiB"`` is exactly 1536 MiB and is accepted; ``"0.1GiB"`` is 102.4 MiB, which
someone would have to round, and is refused.

Only what this client has to understand to send the right thing is checked here. The ranges of the
values, and whether a name or a destination is acceptable, are the server's to say.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, Final

__all__ = [
    "argument_vector",
    "count",
    "environment",
    "flag",
    "mebibytes",
    "network_spec",
    "seconds",
    "shell_vector",
    "text",
    "whole",
]

# Digits, an optional decimal fraction, a unit: no sign, no exponent, no space. ASCII digits only:
# `int()` accepts digits of other scripts, and a quantity is no place for them.
_SIZE: Final = re.compile(r"(?P<whole>[0-9]+)(?:\.(?P<fraction>[0-9]+))?(?P<unit>KiB|MiB|GiB|TiB)", re.ASCII)
_DURATION: Final = re.compile(r"(?P<whole>[0-9]+)(?:\.(?P<fraction>[0-9]+))?(?P<unit>[smhd])", re.ASCII)

#: Binary units, in KiB: the smallest, so that every factor is an integer and the arithmetic is exact.
_KIB_PER: Final[dict[str, int]] = {"KiB": 1, "MiB": 1024, "GiB": 1024**2, "TiB": 1024**3}
_KIB_PER_MIB: Final = 1024
#: Units of time, in seconds. Lower case only: ``M`` and ``D`` are not units here.
_SECONDS_PER: Final[dict[str, int]] = {"s": 1, "m": 60, "h": 3_600, "d": 86_400}

_SIZE_FORMS: Final = (
    "a positive integer number of MiB, or a string with a binary unit that is a whole number of MiB, "
    'such as "512MiB" or "4GiB"'
)
_DURATION_FORMS: Final = (
    "a positive integer number of seconds, or a string that is a whole number of seconds, "
    'such as "90s", "10m", "2h" or "1d"'
)

_SHELL: Final = ("/bin/sh", "-c")
_PORT_PAIR: Final = 2
_NETWORK_FORMS: Final = 'network must be "none" or an allowlist, {"mode": "allowlist", "entries": [...]}'


def whole(value: object) -> int | None:
    """The value, if it is an integer. ``True`` is an ``int`` in Python and is never a quantity."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def text(value: object, *, what: str) -> str:
    """A string the caller passed, as it is. Whether the server accepts it is the server's to say."""
    if not isinstance(value, str):
        raise ValueError(f"{what} must be a string, not {type(value).__name__}")
    return value


def flag(value: object, *, what: str) -> bool:
    """A flag. A string such as ``"false"`` is refused: it is truthy, and would turn the flag on."""
    if not isinstance(value, bool):
        raise ValueError(f"{what} must be True or False, not {value!r}")
    return value


def count(value: object, *, what: str) -> int:
    """A positive whole number with no unit (``cpu``)."""
    number = whole(value)
    if number is None or number <= 0:
        raise ValueError(f"{what} must be a positive integer, not {value!r}")
    return number


def _exact(match: re.Match[str], per_unit: Mapping[str, int], divisor: int) -> int | None:
    """The quantity a string states, in units of ``divisor`` smallest units, if that is a whole number."""
    fraction = match["fraction"] or ""
    scaled = int(match["whole"] + fraction) * per_unit[match["unit"]]
    denominator = 10 ** len(fraction) * divisor
    return scaled // denominator if scaled % denominator == 0 else None


def mebibytes(value: object, *, what: str) -> int:
    """``512`` or ``"512MiB"`` or ``"4GiB"`` -> MiB.

    ``"4GB"`` and ``"4G"`` are refused: a decimal unit and a bare letter do not say which size is meant.
    So are a string with no unit, a float, and a quantity that is not a whole number of MiB.
    """
    number = whole(value)
    if number is None and isinstance(value, str):
        match = _SIZE.fullmatch(value)
        number = _exact(match, _KIB_PER, _KIB_PER_MIB) if match is not None else None
    if number is None or number <= 0:
        raise ValueError(f"{what} must be {_SIZE_FORMS}, not {value!r}")
    return number


def seconds(value: object, *, what: str) -> int:
    """``90`` or ``"90s"`` or ``"10m"`` or ``"2h"`` or ``"1d"`` -> whole seconds."""
    number = whole(value)
    if number is None and isinstance(value, str):
        match = _DURATION.fullmatch(value)
        number = _exact(match, _SECONDS_PER, 1) if match is not None else None
    if number is None or number <= 0:
        raise ValueError(f"{what} must be {_DURATION_FORMS}, not {value!r}")
    return number


def _is_text(value: object) -> bool:
    return isinstance(value, str | bytes | bytearray)


def argument_vector(argv: object) -> list[str]:
    """The command as the list of its arguments.

    A string is refused, although Python would let it pass for a sequence of one-character strings:
    splitting a command line is what a shell does, and a shell is never introduced implicitly.
    """
    if _is_text(argv):
        raise ValueError(
            'argv must be a list of strings such as ["python", "-V"], not a single string: a string is never '
            "split. Use exec_shell(...) to run a command line through /bin/sh"
        )
    if not isinstance(argv, Sequence) or not all(isinstance(item, str) for item in argv):
        raise ValueError('argv must be a list of strings such as ["python", "-V"]')
    if not argv:
        raise ValueError("argv must name a program: it is empty")
    return list(argv)


def shell_vector(command: object) -> list[str]:
    """The one way a command line is accepted: ``["/bin/sh", "-c", command]``, asked for by name."""
    return [*_SHELL, text(command, what="the command of exec_shell")]


def environment(env: object) -> dict[str, str]:
    """Environment variables as a plain mapping of strings."""
    if not isinstance(env, Mapping) or not all(isinstance(k, str) and isinstance(v, str) for k, v in env.items()):
        raise ValueError("env must map variable names to string values")
    return dict(env)


def _port_range(port: object, where: str) -> dict[str, int]:
    single = whole(port)
    if single is not None:
        return {"from": single, "to": single}
    if isinstance(port, Sequence) and not _is_text(port) and len(port) == _PORT_PAIR:
        low, high = whole(port[0]), whole(port[1])
        if low is not None and high is not None:
            return {"from": low, "to": high}
    raise ValueError(f"a port of {where} must be a port number or a [from, to] pair of port numbers, not {port!r}")


def _entry(entry: object, index: int) -> dict[str, Any]:
    where = f"network entry {index}"
    if not isinstance(entry, Mapping):
        raise ValueError(f"{where} must be a mapping with ports and one of name and network")
    members = sorted(str(key) for key in entry)
    if members not in (["name", "ports"], ["network", "ports"]):
        # A member that is not known would be dropped without a word; it is refused instead.
        raise ValueError(f"{where} must have exactly ports and one of name and network; it has: {', '.join(members)}")
    kind = members[0]
    ports = entry["ports"]
    if not isinstance(ports, Sequence) or _is_text(ports):
        raise ValueError(f"the ports of {where} must be a list, for example [443] or [[8000, 8100]]")
    return {
        kind: text(entry[kind], what=f"the {kind} of {where}"),
        "ports": [_port_range(port, where) for port in ports],
    }


def network_spec(network: object) -> dict[str, Any]:
    """The ``network`` member of a create request, in the API's form.

    There are two modes and no third. ``"restricted"``, like every other word, is refused, so that a
    caller never believes in a mode the host does not enforce. An allowlist is sent with every port as
    a ``{"from": n, "to": m}`` range.
    """
    if isinstance(network, str):
        if network == "none":
            return {"mode": "none"}
        raise ValueError(f"{_NETWORK_FORMS}; no other mode exists, and this is {network!r}")
    if not isinstance(network, Mapping) or network.get("mode") != "allowlist":
        raise ValueError(_NETWORK_FORMS)
    members = sorted(str(key) for key in network)
    if members != ["entries", "mode"]:
        raise ValueError(f"an allowlist has exactly mode and entries; this one has: {', '.join(members)}")
    entries = network["entries"]
    if not isinstance(entries, Sequence) or _is_text(entries):
        raise ValueError("the entries of an allowlist must be a list")
    return {"mode": "allowlist", "entries": [_entry(entry, index) for index, entry in enumerate(entries)]}
