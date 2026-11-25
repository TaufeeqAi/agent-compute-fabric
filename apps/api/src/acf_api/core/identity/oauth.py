"""Verification of OAuth access tokens for the agent interface.

When an operator has configured an external authorization server, the deployment is an OAuth resource
server. A token is accepted only if all of these hold:

* its signature verifies against the configured issuer's key set, with an algorithm the operator allowed;
* its issuer is the configured issuer;
* it was issued for this deployment: its audience names the configured resource URI. Libraries leave
  this check off by default; here it cannot be turned off;
* it has not expired, and what is left of its life does not exceed ``oauth_token_max_lifetime``;
* its subject is one an operator has bound to a principal. A token of an unbound subject is refused
  however valid it is.

The key set is refreshed on a schedule. A key id that is not in the set forces a refresh, at most once
per ``jwks_forced_refresh_min_interval``: a flood of tokens with random key ids causes a bounded number
of fetches. The token itself never leaves this module and is never logged.
"""

from __future__ import annotations

import asyncio
import json
import urllib.request
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import jwt
from jwt import PyJWK, PyJWKSet

from acf_api.core.clock import Clock

#: Scope values name public methods: ``acf:<method>``. ``acf:*`` narrows nothing.
SCOPE_PREFIX: Final = "acf:"
SCOPE_ALL: Final = "acf:*"
_MAX_JWKS_BYTES: Final = 256 * 1024
_MAX_TOKEN_BYTES: Final = 16 * 1024


class TokenRejected(Exception):
    """The token does not authenticate. ``reason`` is for internal counters, never for the caller."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class KeySetUnavailable(Exception):
    """The issuer's key set could not be read. The token is neither accepted nor called invalid."""


@dataclass(frozen=True, slots=True)
class VerifiedToken:
    issuer: str
    subject: str
    expires_at_ms: int
    #: Public methods the token's scopes name, or ``None`` when its scopes narrow nothing.
    methods: frozenset[str] | None
    scopes: frozenset[str]


Fetcher = Callable[[], Awaitable[dict[str, Any]]]


def file_fetcher(path: Path) -> Fetcher:
    async def fetch() -> dict[str, Any]:
        def read() -> dict[str, Any]:
            data = json.loads(path.read_bytes()[:_MAX_JWKS_BYTES])
            if not isinstance(data, dict):
                raise KeySetUnavailable("the key set file is not a JSON object")
            return data

        try:
            return await asyncio.to_thread(read)
        except (OSError, ValueError) as e:
            raise KeySetUnavailable("the key set file cannot be read") from e

    return fetch


def https_fetcher(url: str, timeout_s: float) -> Fetcher:
    """Read the key set over HTTPS. The only outbound connection the core makes besides the host."""
    if not url.startswith("https://"):
        msg = "the key set URL must be https"
        raise ValueError(msg)

    async def fetch() -> dict[str, Any]:
        def read() -> dict[str, Any]:
            request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "acf-api"})  # noqa: S310 - https only, checked above
            with urllib.request.urlopen(request, timeout=timeout_s) as response:  # noqa: S310
                data = json.loads(response.read(_MAX_JWKS_BYTES + 1)[:_MAX_JWKS_BYTES])
            if not isinstance(data, dict):
                raise KeySetUnavailable("the key set is not a JSON object")
            return data

        try:
            return await asyncio.wait_for(asyncio.to_thread(read), timeout_s)
        except (OSError, ValueError, TimeoutError) as e:
            raise KeySetUnavailable("the key set could not be fetched") from e

    return fetch


class KeySet:
    """The issuer's keys, with bounded refreshes."""

    def __init__(
        self, fetch: Fetcher, clock: Clock, *, refresh_interval_s: float, forced_min_interval_s: float
    ) -> None:
        self._fetch = fetch
        self._clock = clock
        self._refresh_interval = refresh_interval_s
        self._forced_min_interval = forced_min_interval_s
        self._keys: dict[str, PyJWK] = {}
        self._fetched_at: float | None = None
        self._forced_at: float | None = None
        self._lock = asyncio.Lock()
        self.fetches = 0

    async def _refresh(self) -> None:
        data = await self._fetch()
        self.fetches += 1
        try:
            key_set = PyJWKSet.from_dict(data)
        except jwt.PyJWTError as e:
            raise KeySetUnavailable("the key set holds no usable key") from e
        self._keys = {key.key_id: key for key in key_set.keys if key.key_id}
        self._fetched_at = self._clock.monotonic()

    async def key(self, key_id: str) -> PyJWK | None:
        """The key with this id, refreshing the set when it is due or when the id is not in it."""
        async with self._lock:
            now = self._clock.monotonic()
            if self._fetched_at is None or now - self._fetched_at >= self._refresh_interval:
                await self._refresh()
            found = self._keys.get(key_id)
            if found is not None:
                return found
            if self._forced_at is not None and now - self._forced_at < self._forced_min_interval:
                return None
            self._forced_at = now
            await self._refresh()
            return self._keys.get(key_id)


class TokenVerifier:
    def __init__(
        self,
        *,
        issuer: str,
        resource: str,
        algorithms: list[str],
        key_set: KeySet,
        clock: Clock,
        max_lifetime_s: float,
    ) -> None:
        self._issuer = issuer
        self._resource = resource
        self._algorithms = list(algorithms)
        self._keys = key_set
        self._clock = clock
        self._max_lifetime_s = max_lifetime_s

    async def verify(self, token: str) -> VerifiedToken:
        if len(token) > _MAX_TOKEN_BYTES:
            raise TokenRejected("too_large")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as e:
            raise TokenRejected("malformed") from e
        algorithm = header.get("alg")
        key_id = header.get("kid")
        if algorithm not in self._algorithms:
            raise TokenRejected("algorithm")
        if not isinstance(key_id, str) or not key_id:
            raise TokenRejected("no_key_id")
        key = await self._keys.key(key_id)
        if key is None:
            raise TokenRejected("unknown_key")
        try:
            claims = jwt.decode(
                token,
                key.key,
                algorithms=self._algorithms,
                audience=self._resource,
                issuer=self._issuer,
                leeway=0,
                options={
                    "require": ["exp", "iss", "aud", "sub"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
        except jwt.ExpiredSignatureError as e:
            raise TokenRejected("expired") from e
        except jwt.InvalidAudienceError as e:
            raise TokenRejected("audience") from e
        except jwt.InvalidIssuerError as e:
            raise TokenRejected("issuer") from e
        except jwt.PyJWTError as e:
            raise TokenRejected("invalid") from e
        expires_at_ms = int(claims["exp"]) * 1000
        if expires_at_ms - self._clock.wall_ms() > self._max_lifetime_s * 1000:
            raise TokenRejected("lifetime")
        subject = claims["sub"]
        if not isinstance(subject, str) or not subject:
            raise TokenRejected("subject")
        return VerifiedToken(self._issuer, subject, expires_at_ms, *_scopes(claims.get("scope")))


def _scopes(claim: object) -> tuple[frozenset[str] | None, frozenset[str]]:
    """The methods a ``scope`` claim names. No claim, or ``acf:*``, narrows nothing."""
    if not isinstance(claim, str) or not claim.strip():
        return None, frozenset()
    scopes = frozenset(claim.split())
    if SCOPE_ALL in scopes:
        return None, scopes
    return frozenset(s[len(SCOPE_PREFIX) :] for s in scopes if s.startswith(SCOPE_PREFIX)), scopes


def scope_for(method: str) -> str:
    """The scope that names a public method, for the challenge of an insufficient-scope answer."""
    return SCOPE_PREFIX + method
