"""Length-delimited framing, byte-compatible with the host's wire crate.

Wire format: a ``u32`` big-endian length followed by exactly that many payload bytes. The same
frames travel over the local Unix socket and over mutual TLS.

Security properties (each one has a test, and each mirrors the host's side):

* a declared length above the caller's ``max_len`` is rejected **before any payload is read or
  allocated**, so a hostile or confused peer cannot make this process buffer more than it chose to;
* ``max_len`` is clamped to :data:`MAX_FRAME_HARD_CAP`, so a misconfiguration cannot remove the bound;
* a clean EOF on a frame boundary is distinguishable from a frame cut short.
"""

from __future__ import annotations

import struct
from typing import Protocol

#: Absolute upper bound on any frame, whatever the caller asks for (64 MiB, same as the host's).
MAX_FRAME_HARD_CAP = 64 * 1024 * 1024

_HEADER = struct.Struct(">I")
_CHUNK = 1 << 16


class FrameError(Exception):
    """Base class for framing failures."""


class FrameEof(FrameError):
    """The peer closed the connection cleanly, on a frame boundary."""


class FrameTruncated(FrameError):
    """The peer closed the connection in the middle of a frame."""


class FrameTooLarge(FrameError):
    """A frame (declared or about to be sent) exceeds the permitted maximum."""

    def __init__(self, length: int, maximum: int) -> None:
        super().__init__(f"frame of {length} bytes exceeds the permitted maximum of {maximum} bytes")
        self.length = length
        self.maximum = maximum


class Readable(Protocol):
    """The slice of ``socket.socket`` this module needs (kept narrow so tests can fake it)."""

    def recv(self, bufsize: int, /) -> bytes: ...


def _clamp(max_len: int) -> int:
    return min(max_len, MAX_FRAME_HARD_CAP)


def encode_frame(payload: bytes, max_len: int) -> bytes:
    """Return ``header + payload``; refuse payloads above ``max_len`` (clamped to the hard cap)."""
    limit = _clamp(max_len)
    if len(payload) > limit:
        raise FrameTooLarge(len(payload), limit)
    return _HEADER.pack(len(payload)) + payload


def _read_exactly(src: Readable, count: int, *, eof_ok_if_empty: bool) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining > 0:
        chunk = src.recv(min(remaining, _CHUNK))
        if not chunk:
            if eof_ok_if_empty and remaining == count:
                raise FrameEof("peer closed the connection on a frame boundary")
            raise FrameTruncated(f"peer closed the connection after {count - remaining} of {count} bytes")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_frame(src: Readable, max_len: int) -> bytes:
    """Blocking read of one frame's payload."""
    limit = _clamp(max_len)
    header = _read_exactly(src, _HEADER.size, eof_ok_if_empty=True)
    (length,) = _HEADER.unpack(header)
    if length > limit:
        raise FrameTooLarge(length, limit)
    if length == 0:
        return b""
    return _read_exactly(src, length, eof_ok_if_empty=False)
