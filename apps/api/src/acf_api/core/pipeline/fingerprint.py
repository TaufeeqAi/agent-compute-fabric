"""Keyed digests: the fingerprint of a request, and the digests of keys and of arguments.

Every digest here is an HMAC-SHA-256 under the fingerprint key, which never leaves the core and is
never in the store. With the key an operator can confirm what a record refers to; without it the
digests reveal nothing, which matters because argument and environment values are sensitive caller
data and an idempotency key is a handle on a request.

The fingerprint is computed from the decoded command, not from wire bytes, so the same intent has the
same fingerprint through REST, the agent interface and the command-line client. It covers the public
method, the project, the target identifiers and the caller's parameters, in canonical form. It does
not cover ``wait``, the request id, trace headers, or any value the platform adds.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any, Final

from acf_api.command import strictjson
from acf_api.command.commands import Command

_KEY_BYTES: Final = 32
_FINGERPRINT: Final = b"acf.fingerprint.v1\x00"
_KEY_DIGEST: Final = b"acf.key-digest.v1\x00"
_ARGS_DIGEST: Final = b"acf.args-digest.v1\x00"
_AUDIT_DIGEST: Final = b"acf.audit-digest.v1\x00"

#: Members of a command that are transport values and never part of what the caller asked for.
_EXCLUDED: Final = frozenset({"wait"})


class FingerprintKey:
    """The fingerprint key. Its ``repr`` shows nothing."""

    __slots__ = ("_key",)

    def __init__(self, key: bytes) -> None:
        if len(key) < _KEY_BYTES:
            msg = "the fingerprint key must be at least 32 bytes"
            raise ValueError(msg)
        self._key = key

    def __repr__(self) -> str:
        return "FingerprintKey(<hidden>)"

    @staticmethod
    def parse(text: str) -> FingerprintKey:
        """Read a key file: 64 or more hexadecimal characters."""
        try:
            return FingerprintKey(bytes.fromhex(text.strip()))
        except ValueError as e:
            msg = "the fingerprint key file must hold at least 64 hexadecimal characters"
            raise ValueError(msg) from e

    def _mac(self, label: bytes, data: bytes) -> str:
        return hmac.new(self._key, label + data, hashlib.sha256).hexdigest()

    def key_digest(self, idempotency_key: str) -> str:
        """The digest under which an idempotency key is stored and reported. Byte for byte, never normalized."""
        return self._mac(_KEY_DIGEST, idempotency_key.encode("utf-8"))

    def fingerprint(self, method: str, command: Command) -> str:
        """The fingerprint of one request: what the caller asked for, in canonical form."""
        body = command.model_dump(mode="json", by_alias=True, exclude_none=False)
        body.pop("type", None)
        for name in _EXCLUDED:
            body.pop(name, None)
        return self._mac(_FINGERPRINT, strictjson.canonical({"method": method, "request": body}))

    def args_digest(self, tool: str, arguments: dict[str, Any]) -> str:
        """The digest of the canonical arguments of a tool call, by which an identical re-issue is recognized."""
        cleaned = {k: v for k, v in arguments.items() if k != "idempotency_key"}
        return self._mac(_ARGS_DIGEST, strictjson.canonical({"tool": tool, "arguments": cleaned}))

    def audit_digest(self, value: object) -> str:
        """The keyed digest of an argument vector or an environment, for the audit record of an execution."""
        return self._mac(_AUDIT_DIGEST, strictjson.canonical(value))
