"""The derivation of a host operation id from the scope of a request and its idempotency key.

Exactly this function, and versioned::

    operation_id = "op-" || lowercase_hex( SHA-256(M)[0 .. 16] )
    M            = "acf.p3.operation-id" || 0x00 || F(version) || F(deployment_id) || F(project_id)
                   || F(principal_id) || F(step) || F(key)
    F(x)         = the length of UTF-8(x) as a 4-byte big-endian unsigned integer, followed by UTF-8(x)
    version      = "1"
    step         = the host method the public operation maps to, for example "sandbox.create"

The result is 35 characters of ``[a-z0-9-]``, inside the host's syntax for caller-supplied operation ids.

Because the derivation is deterministic, a ledger that has been restored to an earlier state cannot
make one key produce two host operations: the host's own duplicate detection still sees the same id.
For the same reason nothing here may change without a new version, and a new version is introduced
with a period in which the previous version's id is read on the host before any first submission
under the new one.

The domain-separation label below is part of the function. It is a constant of the wire, not a name
of anything.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Final

DERIVATION_VERSION: Final = "1"
#: Versions whose ids are still looked up on the host before a first submission under the current one.
PREVIOUS_VERSIONS: Final[tuple[str, ...]] = ()
_LABEL: Final = b"acf.p3.operation-id\x00"
_LENGTH: Final = struct.Struct(">I")


def _field(value: str) -> bytes:
    data = value.encode("utf-8")
    return _LENGTH.pack(len(data)) + data


def derive_operation_id(
    *, deployment_id: str, project_id: str, principal_id: str, step: str, key: str, version: str = DERIVATION_VERSION
) -> str:
    """The host operation id of the request ``key`` names, in this scope, for this step."""
    message = (
        _LABEL
        + _field(version)
        + _field(deployment_id)
        + _field(project_id)
        + _field(principal_id)
        + _field(step)
        + _field(key)
    )
    return "op-" + hashlib.sha256(message).digest()[:16].hex()
