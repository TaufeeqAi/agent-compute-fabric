"""What this program writes, and how it is made safe to write.

Three rules, in this order of importance:

1. **Text from outside is data.** Every string the platform sent and every byte a sandbox wrote is
   controlled by someone else as far as a terminal is concerned: an escape sequence can retitle the
   window, a carriage return can rewrite the line above, a direction override can make one name read as
   another. Such text reaches a terminal only with every control and format character shown as a visible
   escape, and reaches a table only up to a bounded length. It never reaches ``rich`` as markup.
2. **The credential is never written.** Everything that is written passes one function that takes the
   key of this invocation out of it, should anything have echoed the key.
3. **``--json`` is the API's representation.** One JSON document: the view as the platform sent it, in
   printable ASCII, so that it is safe on a terminal as well.

Guest output is the one thing that is ever written as it is: to a pipe or a file, where exact bytes are
what the reader wants and no terminal interprets them.
"""

from __future__ import annotations

import io
import json
import os
import sys
import unicodedata
from collections.abc import Iterable, Sequence
from typing import Final, TextIO

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

__all__ = [
    "CELL_MAX",
    "IDENTIFIER_MAX",
    "VALUE_MAX",
    "is_plain",
    "json_line",
    "lenient",
    "line",
    "pairs",
    "protect",
    "safe_block",
    "safe_line",
    "safe_text",
    "scrub",
    "scrub_bytes",
    "table",
    "unprotect",
    "write_guest_bytes",
    "write_json",
]

#: The longest text of one table cell: a name, a state, a short message.
CELL_MAX: Final = 64
#: The longest identifier shown. Identifiers are never shortened in practice: the platform's are shorter.
IDENTIFIER_MAX: Final = 128
#: The longest value of a key-value view or of a message: long enough for any honest one.
VALUE_MAX: Final = 2000

#: A credential shorter than this is not one the platform issues. Replacing it wherever it occurs would
#: shred every message, including the one that says the key is wrong.
_SECRET_MIN: Final = 8
_REDACTED: Final = "[redacted]"
_ELLIPSIS: Final = "…"
#: Wide enough that nothing is folded: a pipe or a file gets every cell whole.
_UNBOUNDED_WIDTH: Final = 100_000
_BYTE_LIMIT: Final = 0x100
_BMP_LIMIT: Final = 0x10000
#: Unicode categories that draw nothing and change what is drawn: controls, format characters (direction
#: overrides, zero-width characters), lone surrogates, and the line and paragraph separators.
_HIDDEN: Final = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})
_DELETE: Final = "\x7f"


class _Secrets:
    """The credentials of this invocation, in every spelling they could be written in."""

    def __init__(self) -> None:
        self._texts: list[str] = []
        self._bytes: list[bytes] = []

    def add(self, secret: str) -> None:
        if len(secret) < _SECRET_MIN:
            return
        # Inside a JSON string a quote and a backslash are written with an escape.
        spellings = {secret, json.dumps(secret)[1:-1]}
        self._texts.extend(sorted(spellings - set(self._texts), key=len, reverse=True))
        self._bytes = [text.encode("utf-8", "surrogatepass") for text in self._texts]

    def clear(self) -> None:
        self._texts = []
        self._bytes = []

    def scrub(self, text: str) -> str:
        for secret in self._texts:
            text = text.replace(secret, _REDACTED)
        return text

    def scrub_bytes(self, data: bytes) -> bytes:
        for secret in self._bytes:
            data = data.replace(secret, _REDACTED.encode("ascii"))
        return data


_SECRETS: Final = _Secrets()


def protect(secret: str) -> None:
    """Make sure this credential is never written by this process, whoever hands it back."""
    _SECRETS.add(secret)


def unprotect() -> None:
    """Forget every credential. One invocation ends here; the next protects its own."""
    _SECRETS.clear()


def scrub(text: str) -> str:
    """The text without any credential of this invocation."""
    return _SECRETS.scrub(text)


def scrub_bytes(data: bytes) -> bytes:
    """The bytes without any credential of this invocation."""
    return _SECRETS.scrub_bytes(data)


# --------------------------------------------------------------------------------------- untrusted text
def _escape(character: str) -> str:
    code = ord(character)
    if code < _BYTE_LIMIT:
        return f"\\x{code:02x}"
    if code < _BMP_LIMIT:
        return f"\\u{code:04x}"
    return f"\\U{code:08x}"


def _visible(text: str, *, keep: str = "") -> str:
    """The text with every character that draws nothing shown as an escape, except those in ``keep``."""
    if text.isprintable():
        # Nothing Python calls printable is a control, a format character, a surrogate or a separator.
        return text
    return "".join(
        character
        if character in keep or character.isprintable() or unicodedata.category(character) not in _HIDDEN
        else _escape(character)
        for character in text
    )


def safe_line(value: object, *, limit: int = VALUE_MAX) -> str:
    """One line of text that came from outside this program, fit to be shown anywhere.

    No credential, no control or format character (a line break and a tab are shown as escapes too: a
    value that could start a new line could draw a row that was never sent), and at most ``limit``
    characters, with a mark when it was cut.
    """
    text = scrub(value if isinstance(value, str) else str(value))
    shown = _visible(text[: limit + 1])
    if len(text) > limit or len(shown) > limit:
        return shown[: limit - 1] + _ELLIPSIS
    return shown


def safe_text(text: str) -> str:
    """Text of several lines that this program did not write, fit for a terminal.

    Line breaks and tabs survive, and nothing else that is hidden does. A carriage return is kept only
    as part of the line ending it belongs to: on its own it would let one line overwrite another.
    """
    return "\n".join(_visible(each, keep="\t") for each in scrub(text).replace("\r\n", "\n").split("\n"))


def safe_block(data: bytes) -> str:
    """Bytes a sandbox wrote, as text fit for a terminal. A byte sequence that is not UTF-8 is shown, not dropped."""
    return safe_text(data.decode("utf-8", errors="backslashreplace"))


# ----------------------------------------------------------------------------------------- the streams
def is_plain(stream: TextIO) -> bool:
    """Whether a stream gets no colour and no table border: it is not a terminal, or ``NO_COLOR`` is set."""
    return not stream.isatty() or os.environ.get("NO_COLOR", "") != ""


def lenient(stream: TextIO) -> None:
    """Make a stream write a character its encoding lacks as a visible escape, instead of failing on it.

    A name can hold any character, and the encoding of a pipe or a file is the system's: on some systems
    that is not UTF-8. A write that failed there would end a command after the platform had done what
    was asked, with the result unsaid.
    """
    if isinstance(stream, io.TextIOWrapper):
        stream.reconfigure(errors="backslashreplace")


def line(text: str, *, err: bool = False) -> None:
    """One line of this program's own words. Whatever it quotes must have been made safe by the caller."""
    stream = sys.stderr if err else sys.stdout
    stream.write(scrub(text) + "\n")


def json_line(document: object) -> str:
    """A JSON document as one line of printable ASCII, without any credential."""
    return _ascii_json(document, indent=None)


def _ascii_json(document: object, *, indent: int | None) -> str:
    separators = (",", ":") if indent is None else None
    text = json.dumps(document, indent=indent, separators=separators, ensure_ascii=True)
    # `json` escapes everything below U+0020 and above U+007E. DELETE is neither, and is a control.
    return scrub(text.replace(_DELETE, "\\u007f"))


def write_json(document: object) -> None:
    """Exactly one JSON document on standard output."""
    sys.stdout.write(_ascii_json(document, indent=2) + "\n")


def write_guest_bytes(data: bytes, *, err: bool = False, raw: bool = False) -> None:
    """What a sandbox wrote, to standard output or standard error.

    To a terminal it is written as safe text, unless ``raw`` says the caller insisted. To anything else
    it is written byte for byte.
    """
    stream = sys.stderr if err else sys.stdout
    if not data:
        return
    if stream.isatty() and not raw:
        text = safe_block(data)
        stream.write(text if text.endswith("\n") else text + "\n")
        return
    stream.flush()
    stream.buffer.write(scrub_bytes(data))
    stream.buffer.flush()


# ------------------------------------------------------------------------------------------ rich views
class _Console(Console):
    """A console that leaves a reader that went away to the one place that handles it.

    The library would end the process there and then, with a status of its own. The status of this tool
    is decided in one place, for every way of writing.
    """

    def on_broken_pipe(self) -> None:
        raise BrokenPipeError


def _console(stream: TextIO) -> Console:
    """A console bound to the stream as it is now, so that a test runner's replacement is honoured."""
    plain = is_plain(stream)
    return _Console(
        file=stream,
        width=None if stream.isatty() else _UNBOUNDED_WIDTH,
        color_system=None if plain else "auto",
        highlight=False,
        emoji=False,
        markup=False,
        soft_wrap=False,
    )


def table(columns: Sequence[str], rows: Iterable[Sequence[str]], *, empty: str) -> None:
    """A table on standard output. Every cell must already be safe text; ``empty`` is said when there is no row."""
    plain = is_plain(sys.stdout)
    grid = Table(box=None if plain else box.SIMPLE_HEAD, show_edge=False, pad_edge=False, header_style="bold")
    for column in columns:
        grid.add_column(column, overflow="fold")
    count = 0
    for row in rows:
        count += 1
        grid.add_row(*(Text(cell) for cell in row))
    if count == 0:
        line(empty)
        return
    _console(sys.stdout).print(grid)


def pairs(rows: Iterable[tuple[str, str]], *, err: bool = False) -> None:
    """A key-value view. Every value must already be safe text."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold", no_wrap=True)
    grid.add_column(overflow="fold")
    for key, value in rows:
        grid.add_row(Text(key), Text(value))
    _console(sys.stderr if err else sys.stdout).print(grid)
