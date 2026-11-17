"""Framing: byte-compatible with ``acf-wire`` and bounded before anything is allocated."""

from __future__ import annotations

import random
import struct

import pytest

from acf_cli.framing import (
    MAX_FRAME_HARD_CAP,
    FrameEof,
    FrameTooLarge,
    FrameTruncated,
    encode_frame,
    read_frame,
)


class Feed:
    """A ``recv``-only source over fixed bytes, delivering at most ``step`` bytes per call."""

    def __init__(self, data: bytes, step: int = 1 << 20) -> None:
        self._data = data
        self._pos = 0
        self._step = step
        self.requested: list[int] = []

    def recv(self, bufsize: int, /) -> bytes:
        self.requested.append(bufsize)
        take = min(bufsize, self._step)
        chunk = self._data[self._pos : self._pos + take]
        self._pos += len(chunk)
        return chunk

    @property
    def consumed(self) -> int:
        return self._pos


def test_wire_format_is_u32_big_endian_length_then_payload() -> None:
    assert encode_frame(b"hello", 1024) == b"\x00\x00\x00\x05hello"
    assert encode_frame(b"", 1024) == b"\x00\x00\x00\x00"


def test_roundtrip_with_arbitrary_payloads_and_arbitrary_read_sizes() -> None:
    rng = random.Random(0xACF)
    for _ in range(200):
        payload = rng.randbytes(rng.randrange(0, 5000))
        step = rng.choice([1, 3, 7, 64, 4096, 1 << 20])
        assert read_frame(Feed(encode_frame(payload, 1 << 20), step), 1 << 20) == payload


def test_a_declared_length_over_the_limit_is_rejected_before_any_payload_is_read() -> None:
    # Header claims 1 MiB; the caller allows 1 KiB. Only the 4 header bytes may be consumed.
    feed = Feed(struct.pack(">I", 1 << 20) + b"x" * 100)
    with pytest.raises(FrameTooLarge) as caught:
        read_frame(feed, 1024)
    assert feed.consumed == 4, "the payload must not be read (or buffered) once the length is known to be too big"
    assert caught.value.length == 1 << 20
    assert caught.value.maximum == 1024


def test_the_hard_cap_holds_even_if_the_caller_asks_for_more() -> None:
    feed = Feed(struct.pack(">I", MAX_FRAME_HARD_CAP + 1))
    with pytest.raises(FrameTooLarge):
        read_frame(feed, 1 << 62)
    with pytest.raises(FrameTooLarge):
        encode_frame(b"x" * 10, 5)
    assert MAX_FRAME_HARD_CAP == 64 * 1024 * 1024


def test_a_frame_exactly_at_the_limit_is_accepted() -> None:
    payload = b"y" * 1024
    assert read_frame(Feed(encode_frame(payload, 1024)), 1024) == payload


def test_clean_eof_on_a_frame_boundary_is_distinguishable_from_truncation() -> None:
    with pytest.raises(FrameEof):
        read_frame(Feed(b""), 1024)
    with pytest.raises(FrameTruncated):
        read_frame(Feed(b"\x00\x00"), 1024)  # cut inside the header
    with pytest.raises(FrameTruncated):
        read_frame(Feed(struct.pack(">I", 10) + b"abc"), 1024)  # cut inside the payload


def test_zero_length_frame_is_valid() -> None:
    assert read_frame(Feed(b"\x00\x00\x00\x00"), 1024) == b""


def test_two_frames_back_to_back_are_read_independently() -> None:
    feed = Feed(encode_frame(b"one", 1024) + encode_frame(b"two", 1024))
    assert read_frame(feed, 1024) == b"one"
    assert read_frame(feed, 1024) == b"two"
    with pytest.raises(FrameEof):
        read_frame(feed, 1024)
