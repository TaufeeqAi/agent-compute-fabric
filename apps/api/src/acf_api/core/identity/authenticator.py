"""Who is calling: from a bearer credential to a principal, its project and its effective grant.

The core verifies the credential itself, on every command. An edge never asserts a principal, and the
core never trusts one from an edge.

Every failure is one opaque ``UNAUTHENTICATED``. The reason (malformed, unknown, expired, revoked, ...)
is counted for the operator and is never told to the caller, so that an attacker cannot use the
platform to learn which keys exist.

A credential authenticates one principal and is bound to exactly one project. Grants live on the role,
the pair of principal and project; a credential only refers to them and may narrow them. An agent
credential is narrowed twice: by what its parent may do today, and by its own narrowing.

While the registry cannot be read, nothing authenticates, with one exception that exists so that
containment never waits for the platform's own machinery: a credential that authenticated within the
last ``containment_auth_cache_ttl`` is remembered and accepted *for containment only*.
"""

from __future__ import annotations

import asyncio
import hmac
from dataclasses import dataclass
from typing import Final, Protocol

from acf_api.core.clock import Clock
from acf_api.core.identity import keys
from acf_api.core.identity.oauth import KeySetUnavailable, TokenRejected, TokenVerifier
from acf_api.core.policy import grants as g
from acf_api.core.store.engine import StoreError
from acf_api.core.store.registry import ACTIVE, DELETING, Credential, Registry

VIA_KEY: Final = "api_key"
VIA_TOKEN: Final = "oauth"  # noqa: S105 - the way a principal authenticated, not a secret
_CACHE_MAX: Final = 4096


class AuthFailure(Exception):
    """The credential does not authenticate. ``reason`` never reaches the caller."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class RegistryUnavailable(Exception):
    """The registry could not be read, so nothing can be said about the credential."""


@dataclass(frozen=True, slots=True)
class Principal:
    principal_id: str
    project_id: str
    #: The project's scope string: the owner scope of every host request made for this principal.
    scope: str
    project_state: str
    credential_id: str
    kind: str
    agent_label: str | None
    grant: g.EffectiveGrant
    policy_version: str
    expires_at_ms: int
    parent_credential_id: str | None
    via: str
    #: For a token: the scopes it carried, and the methods its binding allows that its scopes left out.
    token_scopes: frozenset[str] = frozenset()
    scoped_out: frozenset[str] = frozenset()

    @property
    def on_behalf_of(self) -> str:
        """The label sent to the host: the principal, and for an agent credential its fixed label.

        No text supplied with a request ever enters it.
        """
        return self.principal_id if self.agent_label is None else f"{self.principal_id}/{self.agent_label}"

    @property
    def accepts_granting(self) -> bool:
        return self.project_state == ACTIVE


class Counter(Protocol):
    def count(self, name: str, value: int = 1, **labels: str) -> None: ...


class Authenticator:
    def __init__(
        self,
        registry: Registry,
        clock: Clock,
        *,
        token_verifier: TokenVerifier | None,
        containment_cache_ttl_s: float,
        telemetry: Counter,
        deadline_s: float = 2.0,
    ) -> None:
        self._registry = registry
        self._clock = clock
        self._tokens = token_verifier
        self._ttl = containment_cache_ttl_s
        #: ``auth_deadline``: no request waits longer than this to learn who its caller is.
        self._deadline = deadline_s
        self._telemetry = telemetry
        #: digest of the credential -> (principal, when it authenticated, monotonic). Memory only.
        self._recent: dict[str, tuple[Principal, float]] = {}

    async def authenticate(self, credential: str | None, *, containment: bool = False) -> Principal:
        """The principal behind ``credential``.

        Raises :class:`AuthFailure` when it does not authenticate, and :class:`RegistryUnavailable` when
        nothing can be said. ``containment``: a recent authentication is accepted from memory while the
        registry is unavailable.
        """
        if not credential:
            raise self._failed("missing")
        digest = keys.key_digest(credential)
        try:
            principal = await asyncio.wait_for(self._verify(credential, digest), self._deadline)
        except (StoreError, TimeoutError) as e:
            # Nothing can be said about the credential. It is not called invalid.
            if containment:
                cached = self._recall(digest)
                if cached is not None:
                    self._telemetry.count("auth_from_containment_cache")
                    return cached
            raise RegistryUnavailable from e
        self._remember(digest, principal)
        return principal

    def forget(self, credential_ids: list[str]) -> None:
        """Drop remembered authentications of revoked credentials, so the cache stops honouring them at once."""
        gone = set(credential_ids)
        for digest in [
            d for d, (p, _) in self._recent.items() if p.credential_id in gone or p.parent_credential_id in gone
        ]:
            del self._recent[digest]

    # ------------------------------------------------------------------ internals
    def _failed(self, reason: str) -> AuthFailure:
        self._telemetry.count("auth_failures", reason=reason)
        return AuthFailure(reason)

    def _remember(self, digest: str, principal: Principal) -> None:
        if len(self._recent) >= _CACHE_MAX:
            oldest = min(self._recent, key=lambda d: self._recent[d][1])
            del self._recent[oldest]
        self._recent[digest] = (principal, self._clock.monotonic())

    def _recall(self, digest: str) -> Principal | None:
        hit = self._recent.get(digest)
        if hit is None:
            return None
        principal, at = hit
        if self._clock.monotonic() - at > self._ttl or self._clock.wall_ms() >= principal.expires_at_ms:
            del self._recent[digest]
            return None
        return principal

    async def _verify(self, credential: str, digest: str) -> Principal:
        if credential.startswith("acf"):
            return await self._verify_key(credential, digest)
        if self._tokens is None:
            raise self._failed("malformed")
        return await self._verify_token(credential)

    async def _verify_key(self, credential: str, digest: str) -> Principal:
        parsed = keys.parse_key(credential)
        if parsed is None:
            raise self._failed("malformed")
        record = await self._registry.credential_by_digest(digest)
        # The comparison of the digests runs in constant time, whether or not a record was found.
        stored = record.key_digest if record is not None else "0" * len(digest)
        if not hmac.compare_digest(stored, digest) or record is None:
            raise self._failed("unknown")
        if record.kind != parsed.kind:
            raise self._failed("kind_mismatch")
        now = self._clock.wall_ms()
        if record.revoked_at_ms is not None:
            raise self._failed("revoked")
        if now >= record.expires_at_ms:
            raise self._failed("expired")
        principal = await self._principal_for(record, now)
        if record.first_used_at_ms is None:
            await self._registry.mark_first_use(record.credential_id, now)
        return principal

    async def _principal_for(self, record: Credential, now: int) -> Principal:
        parent_narrowing: g.EffectiveGrant | None = None
        if record.parent_credential_id is not None:
            parent = await self._registry.credential(record.parent_credential_id)
            if parent is None or not parent.live(now):
                raise self._failed("parent_not_live")
            parent_narrowing = self._parse(parent.narrowing_json)
        return await self._resolve(
            principal_id=record.principal_id,
            project_id=record.project_id,
            credential_id=record.credential_id,
            kind=record.kind,
            agent_label=record.agent_label,
            narrowings=[parent_narrowing, self._parse(record.narrowing_json)],
            expires_at_ms=record.expires_at_ms,
            parent=record.parent_credential_id,
            via=VIA_KEY,
        )

    def _parse(self, text: str | None) -> g.EffectiveGrant | None:
        if text is None:
            return None
        try:
            return g.parse(text)
        except g.GrantError as e:
            # An unreadable grant makes the credential unusable. It is never read as a broader one.
            raise self._failed("grant_unreadable") from e

    async def _resolve(
        self,
        *,
        principal_id: str,
        project_id: str,
        credential_id: str,
        kind: str,
        agent_label: str | None,
        narrowings: list[g.EffectiveGrant | None],
        expires_at_ms: int,
        parent: str | None,
        via: str,
        token_methods: frozenset[str] | None = None,
        token_scopes: frozenset[str] = frozenset(),
    ) -> Principal:
        project = await self._registry.project(project_id)
        if project is None or project.state not in {ACTIVE, DELETING}:
            raise self._failed("project_inactive")
        role = await self._registry.role(principal_id, project_id)
        if role is None:
            raise self._failed("no_role")
        grant = self._parse(role.grants_json)
        if grant is None:  # pragma: no cover - a role always has grants
            raise self._failed("no_role")
        for narrowing in narrowings:
            grant = g.narrow(grant, narrowing)
        scoped_out: frozenset[str] = frozenset()
        if token_methods is not None:
            scoped_out = grant.methods - token_methods
            grant = g.EffectiveGrant(
                grant.methods & token_methods,
                grant.images,
                grant.modes,
                grant.destinations,
                grant.ceilings,
                grant.mint_agent_credentials,
            )
        return Principal(
            principal_id=principal_id,
            project_id=project_id,
            scope=project.scope,
            project_state=project.state,
            credential_id=credential_id,
            kind=kind,
            agent_label=agent_label,
            grant=grant,
            policy_version=role.policy_version,
            expires_at_ms=expires_at_ms,
            parent_credential_id=parent,
            via=via,
            token_scopes=token_scopes,
            scoped_out=scoped_out,
        )

    async def _verify_token(self, token: str) -> Principal:
        if self._tokens is None:  # pragma: no cover - checked by the caller
            raise self._failed("malformed")
        try:
            verified = await self._tokens.verify(token)
        except TokenRejected as e:
            raise self._failed("token_" + e.reason) from e
        except KeySetUnavailable as e:
            # Nothing can be said about the token. It is not called invalid; the caller may ask again.
            raise RegistryUnavailable from e
        binding = await self._registry.binding(verified.issuer, verified.subject)
        if binding is None:
            raise self._failed("token_unbound")
        if binding.revoked_at_ms is not None:
            raise self._failed("token_binding_revoked")
        return await self._resolve(
            principal_id=binding.principal_id,
            project_id=binding.project_id,
            credential_id=binding.binding_id,
            kind=binding.kind,
            agent_label=binding.agent_label,
            narrowings=[self._parse(binding.narrowing_json)],
            expires_at_ms=verified.expires_at_ms,
            parent=None,
            via=VIA_TOKEN,
            token_methods=verified.methods,
            token_scopes=verified.scopes,
        )
