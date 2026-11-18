"""Reading the numbers the suites assert on from the files the host itself loads.

``config/host.example.yaml`` (or ``/etc/acf/host.yaml``) and ``profiles/default.yaml`` (or ``/etc/acf/profile.yaml``)
are the source of every bound: the envelope, the ceilings, the defaults, the intervals. A suite that carried its own
copy of those numbers would keep passing after the shipped files changed, so the suites read the files.

The repository's tooling has no YAML library, and these two files use a small, regular subset of YAML: nested
mappings by indentation, scalars, quoted strings, and one-line lists (``[none, allowlist]``). :func:`read_settings`
reads exactly that subset and REFUSES anything else: a construct it does not know is an error, never a guess.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

type Value = int | bool | str | list[str]

_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_INTEGER = re.compile(r"-?[0-9]+")


def _without_comment(line: str) -> str:
    """``line`` up to a ``#`` that starts a comment (at the start, or after white space), outside quotes."""
    quote: str | None = None
    for index, char in enumerate(line):
        if quote is not None:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == "#" and (index == 0 or line[index - 1] in " \t"):
            return line[:index]
    return line


def _scalar(text: str, where: str) -> int | bool | str:
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    if text in {"true", "false"}:
        return text == "true"
    if _INTEGER.fullmatch(text):
        return int(text)
    if any(char in text for char in "{}[]&*!|>%@`"):
        raise ValueError(f"{where}: this reader does not know the YAML construct in {text!r}")
    return text


def _value(text: str, where: str) -> Value:
    if text.startswith("["):
        if not text.endswith("]"):
            raise ValueError(f"{where}: a list must be closed on the line it starts: {text!r}")
        inner = text[1:-1].strip()
        return [str(_scalar(item.strip(), where)) for item in inner.split(",")] if inner else []
    return _scalar(text, where)


def read_settings(text: str) -> dict[str, Value]:
    """Every scalar and one-line list of ``text``, keyed by its dotted path (``envelope.vcpus``)."""
    values: dict[str, Value] = {}
    open_mappings: list[tuple[int, str]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        body = _without_comment(line).rstrip()
        if not body.strip():
            continue
        where = f"line {number}"
        indent = len(body) - len(body.lstrip(" "))
        if body[indent : indent + 1] == "\t":
            raise ValueError(f"{where}: indentation with a tab")
        key, colon, rest = body.strip().partition(":")
        if not colon or not _KEY.fullmatch(key) or (rest and not rest.startswith(" ")):
            raise ValueError(f"{where}: expected `key: value`, found {line.strip()!r}")
        while open_mappings and open_mappings[-1][0] >= indent:
            open_mappings.pop()
        path = ".".join([*(name for _, name in open_mappings), key])
        rest = rest.strip()
        if rest:
            if path in values:
                raise ValueError(f"{where}: `{path}` is set twice")
            values[path] = _value(rest, where)
        else:
            open_mappings.append((indent, key))
    return values


@dataclass(frozen=True)
class Settings:
    """One of the host's files, read. ``defaults`` answers for a key the file leaves out."""

    path: Path
    values: Mapping[str, Value]
    defaults: Settings | None = None

    @classmethod
    def load(cls, path: Path, *, defaults: Settings | None = None) -> Settings:
        try:
            values = read_settings(path.read_text(encoding="utf-8"))
        except ValueError as e:
            raise ValueError(f"{path}: {e}") from e
        return cls(path=path, values=values, defaults=defaults)

    def sha256(self) -> str:
        """The digest of the file's bytes: for the safety profile this is its identity."""
        return hashlib.sha256(self.path.read_bytes()).hexdigest()

    def has(self, key: str) -> bool:
        return key in self.values

    def _get(self, key: str) -> Value:
        if key in self.values:
            return self.values[key]
        if self.defaults is not None:
            return self.defaults._get(key)
        raise KeyError(f"{self.path} does not set `{key}`")

    def integer(self, key: str) -> int:
        value = self._get(key)
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{self.path}: `{key}` is not an integer: {value!r}")
        return value

    def text(self, key: str) -> str:
        value = self._get(key)
        if isinstance(value, list):
            raise TypeError(f"{self.path}: `{key}` is a list: {value!r}")
        return str(value)

    def flag(self, key: str) -> bool:
        value = self._get(key)
        if not isinstance(value, bool):
            raise TypeError(f"{self.path}: `{key}` is not true or false: {value!r}")
        return value

    def words(self, key: str) -> list[str]:
        value = self._get(key)
        if not isinstance(value, list):
            raise TypeError(f"{self.path}: `{key}` is not a list: {value!r}")
        return list(value)
