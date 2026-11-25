"""What a command line says, turned into what the SDK takes. Nothing here is sent anywhere.

The SDK is the one place where a size or a lifetime becomes the API's integer, and it is strict about
it. This module does not repeat that work: it hands the SDK what was typed and lets it accept or refuse.
The one thing it adds is what a command line cannot express: on a command line everything is text, so a
bare number is passed on as the number it is, and the SDK reads a number as MiB or as seconds.

What the SDK does not parse is parsed here: how long this tool follows an operation, a generation, a
``NAME=VALUE`` pair, and a file of JSON.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final, Literal

from agentcompute_cli.outcome import UsageError

__all__ = ["duration", "environment", "generation", "json_file", "network", "quantity"]

#: A generation as the SDK takes it: a number, or the explicit word for "whatever is current".
type Generation = int | Literal["current"]

_CURRENT: Final = "current"
_NONE: Final = "none"
# ASCII digits only: `int()` and `str.isdigit()` accept digits of other scripts.
_WHOLE: Final = re.compile(r"[0-9]+", re.ASCII)
_DURATION: Final = re.compile(r"(?P<number>[0-9]+(?:\.[0-9]+)?)(?P<unit>[smhd]?)", re.ASCII)
_SECONDS_PER: Final[dict[str, int]] = {"": 1, "s": 1, "m": 60, "h": 3_600, "d": 86_400}
#: The largest file read for a network or a narrowing: more than any request the platform accepts.
_FILE_MAX: Final = 1024 * 1024


def quantity(text: str) -> int | str:
    """A size or a lifetime as typed: ``512`` is the number 512, ``4GiB`` and ``2h`` are left to the SDK."""
    return int(text) if _WHOLE.fullmatch(text) else text


def duration(text: str, *, option: str) -> float:
    """Seconds, from ``90``, ``90s``, ``2m``, ``1.5h`` or ``1d``. For the waits of this tool itself."""
    match = _DURATION.fullmatch(text)
    if match is None:
        raise UsageError(f"{option} takes a duration such as 90, 90s, 10m, 2h or 1d, not {text!r}")
    return float(match["number"]) * _SECONDS_PER[match["unit"]]


def generation(text: str | None) -> Generation | None:
    """``--generation``: a number, or ``current`` to act on whatever generation is there."""
    if text is None:
        return None
    if text == _CURRENT:
        return _CURRENT
    if _WHOLE.fullmatch(text) and int(text) > 0:
        return int(text)
    raise UsageError(
        f"--generation takes a generation number, or the word current to act on whatever is there, not {text!r}"
    )


def environment(pairs: Sequence[str] | None) -> dict[str, str] | None:
    """``--env NAME=VALUE``, any number of times. ``None`` when there was none: nothing is then sent."""
    if not pairs:
        return None
    variables: dict[str, str] = {}
    for pair in pairs:
        name, separator, value = pair.partition("=")
        if not separator or not name:
            raise UsageError(
                "--env takes NAME=VALUE",
                next_step="To pass on a variable of your own environment, write NAME=$NAME.",
            )
        if name in variables:
            raise UsageError(f"--env names {name} more than once")
        variables[name] = value
    return variables


def json_file(path: Path, *, option: str) -> dict[str, Any]:
    """A JSON object read from a file the command line names."""
    try:
        with path.open("rb") as file:
            data = file.read(_FILE_MAX + 1)
    except OSError as error:
        # The operating system's words name the file and nothing else.
        raise UsageError(f"{option}: {path} cannot be read ({error.strerror or type(error).__name__})") from None
    if len(data) > _FILE_MAX:
        raise UsageError(f"{option}: {path} is larger than {_FILE_MAX} bytes, which is more than a request may hold")
    try:
        document = json.loads(data)
    except (ValueError, RecursionError):
        # The parser's message quotes the text it could not read, and the file may hold anything.
        raise UsageError(f"{option}: {path} does not hold JSON") from None
    if not isinstance(document, dict):
        raise UsageError(f"{option}: {path} holds JSON that is not an object")
    return document


def network(text: str | None) -> Literal["none"] | dict[str, Any] | None:
    """``--network none`` or ``--network FILE``, where the file holds an allowlist.

    ``None`` when the option was not given: nothing is then sent and the platform's default applies. A
    file called ``none`` is named ``./none``.
    """
    if text is None:
        return None
    if text == _NONE:
        return _NONE
    return json_file(Path(text), option="--network")
