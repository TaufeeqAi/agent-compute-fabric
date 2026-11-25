"""Framing and encoding of the command interface.

Wire format: a ``u32`` big-endian length followed by exactly that many bytes of UTF-8 JSON. One request
frame is answered by one answer frame; a connection carries one exchange at a time.

Bounds, each with a test:

* a declared length above the reader's maximum is rejected before any payload is read or allocated;
* the maximum is clamped to :data:`MAX_FRAME_HARD_CAP`, so a misconfiguration cannot remove the bound;
* a clean end of stream on a frame boundary is distinguishable from a frame cut short.

Neither side logs a frame: the request frame carries the caller's credential.
"""

from __future__ import annotations

import asyncio
import struct
from typing import Final

from pydantic import ValidationError

from acf_api.command import strictjson
from acf_api.command.answers import (
    COMMAND_INTERFACE_MAX,
    COMMAND_INTERFACE_MIN,
    FRAME_ADAPTER,
    REQUEST_ADAPTER,
    Answer,
    Frame,
    Request,
)

#: Absolute upper bound of any frame of the command interface.
MAX_FRAME_HARD_CAP: Final = 32 * 1024 * 1024
#: Default bound of a request frame: a public request of 1 MiB, its context and the credential.
DEFAULT_MAX_REQUEST_FRAME: Final = 2 * 1024 * 1024
#: Default bound of an answer frame: a page of views or one output chunk in base64.
DEFAULT_MAX_ANSWER_FRAME: Final = 16 * 1024 * 1024

_HEADER: Final = struct.Struct(">I")


class FrameError(Exception):
    """Base class of framing failures."""


class FrameEof(FrameError):
    """The peer closed the connection on a frame boundary."""


class FrameTruncated(FrameError):
    """The peer closed the connection in the middle of a frame."""


class FrameTooLarge(FrameError):
    """A frame, declared or about to be sent, exceeds the permitted maximum."""

    def __init__(self, length: int, maximum: int) -> None:
        super().__init__(f"frame of {length} bytes exceeds the permitted maximum of {maximum} bytes")
        self.length = length
        self.maximum = maximum


class CodecError(Exception):
    """A frame was read in full and is not a message of the command interface."""


class VersionRefused(CodecError):
    """The frame names a version of the command interface outside the range this side serves."""

    def __init__(self, version: int) -> None:
        super().__init__(
            f"command interface version {version} is outside the served range "
            f"{COMMAND_INTERFACE_MIN}..{COMMAND_INTERFACE_MAX}"
        )
        self.version = version


def _clamp(max_len: int) -> int:
    return max(0, min(max_len, MAX_FRAME_HARD_CAP))


def encode_frame(payload: bytes, max_len: int) -> bytes:
    """``header + payload``. A payload above ``max_len`` is refused, never truncated."""
    limit = _clamp(max_len)
    if len(payload) > limit:
        raise FrameTooLarge(len(payload), limit)
    return _HEADER.pack(len(payload)) + payload


async def read_frame(reader: asyncio.StreamReader, max_len: int) -> bytes:
    """Read one frame's payload."""
    limit = _clamp(max_len)
    try:
        header = await reader.readexactly(_HEADER.size)
    except asyncio.IncompleteReadError as e:
        if not e.partial:
            raise FrameEof("peer closed the connection on a frame boundary") from e
        raise FrameTruncated("peer closed the connection inside a frame header") from e
    (length,) = _HEADER.unpack(header)
    if length > limit:
        raise FrameTooLarge(length, limit)
    if length == 0:
        return b""
    try:
        return await reader.readexactly(length)
    except asyncio.IncompleteReadError as e:
        raise FrameTruncated(f"peer closed the connection after {len(e.partial)} of {length} bytes") from e


async def write_frame(writer: asyncio.StreamWriter, payload: bytes, max_len: int) -> None:
    writer.write(encode_frame(payload, max_len))
    await writer.drain()


def served(version: int) -> bool:
    """Whether this side serves ``version`` of the command interface."""
    return COMMAND_INTERFACE_MIN <= version <= COMMAND_INTERFACE_MAX


def encode_request(request: Request) -> bytes:
    return strictjson.dumps(request.model_dump(mode="json", by_alias=True, exclude_none=True))


def peek_version(payload: bytes) -> int:
    """The version a request frame names, read before the frame is validated against that version."""
    try:
        value = strictjson.loads_object(payload)
    except strictjson.StrictJsonError as e:
        raise CodecError("the frame is not a JSON object") from e
    version = value.get("version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise CodecError("the frame names no version")
    return version


def decode_request(payload: bytes) -> Request:
    """Decode and validate a request frame. An unknown command, member or version is refused."""
    version = peek_version(payload)
    if not served(version):
        raise VersionRefused(version)
    try:
        return REQUEST_ADAPTER.validate_json(payload)
    except ValidationError as e:
        problems = e.error_count()
    # The validation error quotes its input, and the input is a frame with a credential in it. Only the
    # count leaves this function: the refusal is raised here, outside the handler, so that it carries the
    # validation error neither as its cause nor as its context.
    raise CodecError(f"the frame is not a valid command ({problems} problem(s))")


def encode_answer(answer: Answer, version: int) -> bytes:
    frame = Frame(version=version, answer=answer)
    return strictjson.dumps(frame.model_dump(mode="json", by_alias=True, exclude_none=True))


def decode_answer(payload: bytes) -> Answer:
    frame: Frame | None = None
    problems = 0
    try:
        frame = FRAME_ADAPTER.validate_json(payload)
    except ValidationError as e:
        problems = e.error_count()
    if frame is None:
        # As for a request: an answer can carry the secret of a credential that was just minted.
        raise CodecError(f"the frame is not a valid answer ({problems} problem(s))")
    if not served(frame.version):
        raise VersionRefused(frame.version)
    return frame.answer
