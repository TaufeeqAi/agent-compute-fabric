"""The access policy: may this principal ask for this method, with these values, on this target?

The policy only narrows. It can never make the host allow more than its safety profile, and the host
checks that profile independently. One engine computes every verdict, for REST, for the tool catalogue
and for tool calls alike; no adapter holds a table of scopes or grants.

A decision for new granting work is taken once, after every value of the request is fixed and before
the claim, and is recorded with the ledger entry. It looks at the request *and* at the target: an
operation that uses an existing sandbox or snapshot is checked against the image, resources and
network intent the host recorded for that target, not only against what the request says. If the host's
views do not show a property the grant restricts, the intent is unreadable and is treated as the
widest the host allows, so the request is refused unless the grant allows all of that.

Containment is decided by a local rule that needs no read and cannot fail for lack of a dependency:
the credential's grant allows the method. :func:`allows_containment` is that rule.

``Authorizer`` is the port a later policy engine fills. It already takes the target, may perform I/O,
may fail, and is called after the request is fixed.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Final, Protocol

from acf_api.command.errors import Code, Retry
from acf_api.core.policy.destinations import Destination, inside
from acf_api.core.policy.grants import EffectiveGrant, widens

# Reasons, from a bounded set. A reason is a label; it never carries a value of the request.
R_METHOD: Final = "method"
R_IMAGE: Final = "image"
R_RESOURCES: Final = "resources"
R_NETWORK_MODE: Final = "network_mode"
R_DESTINATION: Final = "destination"
R_LIFETIME: Final = "lifetime"
R_TIMEOUT: Final = "timeout"
R_TARGET_IMAGE: Final = "target_image"
R_TARGET_RESOURCES: Final = "target_resources"
R_TARGET_NETWORK: Final = "target_network"
R_TARGET_UNREADABLE: Final = "target_intent_unreadable"
R_MINT: Final = "mint"
R_NARROWING: Final = "narrowing_widens"
R_AGENT_REQUIRED: Final = "agent_credential_required"
R_QUOTA: Final = "quota"
R_UNAVAILABLE: Final = "policy_unavailable"
R_TARGET_MISSING: Final = "target_not_found"


@dataclass(frozen=True, slots=True)
class Intent:
    """The recorded intent of a sandbox or a snapshot, as far as the host's views show it.

    ``None`` in a field means the views do not show that property: it is unreadable.
    """

    image_alias: str | None
    image_readable: bool
    vcpus: int | None
    memory_mib: int | None
    disk_mib: int | None
    network_mode: str | None
    #: The allowlist entries, when the mode is ``allowlist`` and the view shows them.
    entries: tuple[Destination, ...] | None


UNREADABLE: Final = Intent(
    image_alias=None, image_readable=False, vcpus=None, memory_mib=None, disk_mib=None, network_mode=None, entries=None
)


@dataclass(frozen=True, slots=True)
class HostLimits:
    """What the host allows at most, as it advertises it. Used only to bound an unreadable intent."""

    network_modes: frozenset[str]
    max_vcpus: int
    max_memory_mib: int
    max_disk_mib: int
    max_runtime_seconds: int
    lifetime_default_seconds: int
    lifetime_max_seconds: int


@dataclass(frozen=True, slots=True)
class PolicyRequest:
    """One fixed request, in the terms the policy evaluates. Built by the pipeline; holds no caller text."""

    method: str
    image: str | None = None
    vcpus: int | None = None
    memory_mib: int | None = None
    disk_mib: int | None = None
    network_mode: str | None = None
    #: Requested allowlist entries. ``None`` in the tuple: an entry that could not be normalized.
    entries: tuple[Destination | None, ...] = ()
    #: The lifetime the request will have: the caller's, or the host's default when the caller gave none.
    lifetime_seconds: int | None = None
    #: The runtime the request will have: the caller's, or the host's maximum when the caller gave none.
    timeout_seconds: int | None = None
    #: The recorded intent of each sandbox or snapshot the operation uses.
    targets: tuple[Intent, ...] = ()
    #: For minting: the narrowing asked for.
    narrowing: EffectiveGrant | None = None


@dataclass(frozen=True, slots=True)
class Decision:
    allowed: bool
    decision_id: str
    policy_version: str
    reason: str | None = None
    #: The public code of a denial. PERMISSION_DENIED unless the policy could not be asked.
    code: Code = Code.PERMISSION_DENIED
    retry: Retry = Retry.NEVER


@dataclass(frozen=True, slots=True)
class Subject:
    """Who is asking: the effective grant of the credential, and what kind of credential it is."""

    principal_id: str
    project_id: str
    credential_kind: str
    grant: EffectiveGrant
    policy_version: str
    extra: dict[str, str] = field(default_factory=dict)


class Authorizer(Protocol):
    async def decide(self, subject: Subject, request: PolicyRequest, limits: HostLimits | None) -> Decision: ...


def new_decision_id() -> str:
    return "dec_" + secrets.token_hex(10)


def allows_containment(grant: EffectiveGrant, method: str) -> bool:
    """The local rule for containment: the grant allows the method. No read, no dependency."""
    return method in grant.methods


def allows_method(grant: EffectiveGrant, method: str) -> bool:
    return method in grant.methods


def _deny(
    subject: Subject, reason: str, *, retry: Retry = Retry.NEVER, code: Code = Code.PERMISSION_DENIED
) -> Decision:
    return Decision(
        allowed=False,
        decision_id=new_decision_id(),
        policy_version=subject.policy_version,
        reason=reason,
        code=code,
        retry=retry,
    )


def _check_values(grant: EffectiveGrant, r: PolicyRequest) -> str | None:  # noqa: PLR0911 - one exit per rule
    """The request's own values against the grant. ``None``: all inside."""
    if r.image is not None and not grant.allows_image(r.image):
        return R_IMAGE
    c = grant.ceilings
    if (
        (r.vcpus is not None and r.vcpus > c.vcpus)
        or (r.memory_mib is not None and r.memory_mib > c.memory_mib)
        or (r.disk_mib is not None and r.disk_mib > c.disk_mib)
    ):
        return R_RESOURCES
    if r.network_mode is not None and r.network_mode not in grant.modes:
        return R_NETWORK_MODE
    for entry in r.entries:
        if entry is None or not inside(entry, grant.destinations):
            return R_DESTINATION
    if r.lifetime_seconds is not None and r.lifetime_seconds > c.sandbox_lifetime_seconds:
        return R_LIFETIME
    if r.timeout_seconds is not None and r.timeout_seconds > c.execution_timeout_seconds:
        return R_TIMEOUT
    return None


def _check_intent(grant: EffectiveGrant, intent: Intent, limits: HostLimits | None) -> str | None:  # noqa: PLR0911, PLR0912
    """A target's recorded intent against the grant. An unreadable property counts as the widest allowed."""
    # Image.
    if intent.image_readable:
        if not grant.allows_image(intent.image_alias):
            return R_TARGET_IMAGE
    elif not grant.allows_image(None):
        # Unreadable: any image the host allows. Only a grant that allows every image covers that.
        return R_TARGET_UNREADABLE
    # Resources.
    c = grant.ceilings
    widest = (limits.max_vcpus, limits.max_memory_mib, limits.max_disk_mib) if limits is not None else None
    for index, (value, ceiling) in enumerate(
        ((intent.vcpus, c.vcpus), (intent.memory_mib, c.memory_mib), (intent.disk_mib, c.disk_mib))
    ):
        if value is not None:
            if value > ceiling:
                return R_TARGET_RESOURCES
        elif widest is None or widest[index] > ceiling:
            return R_TARGET_UNREADABLE
    # Network.
    if intent.network_mode is None:
        offered = limits.network_modes if limits is not None else None
        if offered is None or not offered <= grant.modes or "allowlist" in offered:
            # No grant can say "every destination", so an unreadable allowlist is never inside one.
            return R_TARGET_UNREADABLE
        return None
    if intent.network_mode not in grant.modes:
        return R_TARGET_NETWORK
    if intent.network_mode == "allowlist":
        if intent.entries is None:
            return R_TARGET_UNREADABLE
        if any(not inside(entry, grant.destinations) for entry in intent.entries):
            return R_TARGET_NETWORK
    return None


def evaluate(subject: Subject, request: PolicyRequest, limits: HostLimits | None) -> Decision:  # noqa: PLR0911 - one exit per verdict
    """The verdict, as a pure function of the grant, the fixed request and the targets' recorded intent."""
    grant = subject.grant
    if request.method not in grant.methods:
        return _deny(subject, R_METHOD)
    if request.method == "agent_credential.mint":
        if subject.credential_kind != "developer" or not grant.mint_agent_credentials:
            return _deny(subject, R_MINT)
        if request.narrowing is not None and widens(request.narrowing, grant):
            return _deny(subject, R_NARROWING)
        return Decision(allowed=True, decision_id=new_decision_id(), policy_version=subject.policy_version)
    reason = _check_values(grant, request)
    if reason is not None:
        return _deny(subject, reason)
    for intent in request.targets:
        reason = _check_intent(grant, intent, limits)
        if reason is not None:
            retry = Retry.AFTER_CHANGE if reason == R_TARGET_UNREADABLE else Retry.NEVER
            return _deny(subject, reason, retry=retry)
    return Decision(allowed=True, decision_id=new_decision_id(), policy_version=subject.policy_version)


class GrantAuthorizer:
    """The authorizer of this version: grants from the registry, evaluated locally."""

    async def decide(self, subject: Subject, request: PolicyRequest, limits: HostLimits | None) -> Decision:
        return evaluate(subject, request, limits)


def unavailable(subject: Subject) -> Decision:
    """No decision could be reached. Granting work is then refused; containment never comes here."""
    return _deny(subject, R_UNAVAILABLE, retry=Retry.SAME_REQUEST_LATER, code=Code.UPSTREAM_UNAVAILABLE)
