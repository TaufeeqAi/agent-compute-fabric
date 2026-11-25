"""Grants: what a role allows, how a credential narrows it, and when one grant is inside another.

A grant lists the public methods allowed, the images allowed, the network modes allowed and, for
``allowlist``, the destinations allowed, ceilings for resources, runtime and lifetime, and whether the
credential may mint agent credentials. Nothing in a grant depends on who created a record.

Rules:

* deny by default: a method, image, network mode or destination the grant does not mention is denied;
* a grant with a field this version does not know makes its credential unusable, never broader;
* effective permission is the role's grant, narrowed by the credential, inside the host safety profile.
  The platform computes the first two. The host checks the profile independently, so a ceiling above
  the host's is legal and simply never reached;
* narrowing never widens: the effective grant of a credential is inside the grant it narrows.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Final

from pydantic import ValidationError

from acf_api.command import model as m
from acf_api.command.surface import BY_METHOD
from acf_api.core.policy.destinations import Destination, destination, inside

ANY_IMAGE: Final = "*"
GRANT_SCHEMA_VERSION: Final = 1
KNOWN_METHODS: Final = frozenset(BY_METHOD)


class GrantError(Exception):
    """A grant cannot be interpreted. Its credential is unusable; it is never read as a broader grant."""


@dataclass(frozen=True, slots=True)
class Ceilings:
    vcpus: int
    memory_mib: int
    disk_mib: int
    execution_timeout_seconds: int
    sandbox_lifetime_seconds: int

    def min(self, other: Ceilings) -> Ceilings:
        return Ceilings(
            min(self.vcpus, other.vcpus),
            min(self.memory_mib, other.memory_mib),
            min(self.disk_mib, other.disk_mib),
            min(self.execution_timeout_seconds, other.execution_timeout_seconds),
            min(self.sandbox_lifetime_seconds, other.sandbox_lifetime_seconds),
        )

    def within(self, other: Ceilings) -> bool:
        return (
            self.vcpus <= other.vcpus
            and self.memory_mib <= other.memory_mib
            and self.disk_mib <= other.disk_mib
            and self.execution_timeout_seconds <= other.execution_timeout_seconds
            and self.sandbox_lifetime_seconds <= other.sandbox_lifetime_seconds
        )


@dataclass(frozen=True, slots=True)
class EffectiveGrant:
    """A grant in normalized form: what the access policy evaluates."""

    methods: frozenset[str]
    images: frozenset[str]
    modes: frozenset[str]
    destinations: tuple[Destination, ...]
    ceilings: Ceilings
    mint_agent_credentials: bool

    def allows_image(self, alias: str | None) -> bool:
        if ANY_IMAGE in self.images:
            return True
        return alias is not None and alias in self.images

    def to_view(self) -> dict[str, Any]:
        """The grant as a caller sees it through ``whoami``."""
        return {
            "schema_version": GRANT_SCHEMA_VERSION,
            "methods": sorted(self.methods),
            "images": sorted(self.images),
            "network": {
                "modes": sorted(self.modes),
                "destinations": [_destination_view(d) for d in self.destinations],
            },
            "ceilings": {
                "vcpus": self.ceilings.vcpus,
                "memory_mib": self.ceilings.memory_mib,
                "disk_mib": self.ceilings.disk_mib,
                "execution_timeout_seconds": self.ceilings.execution_timeout_seconds,
                "sandbox_lifetime_seconds": self.ceilings.sandbox_lifetime_seconds,
            },
            "mint_agent_credentials": self.mint_agent_credentials,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_view(), sort_keys=True, separators=(",", ":"))


def _destination_view(d: Destination) -> dict[str, Any]:
    ports = [{"from": first, "to": last} for first, last in d.ports]
    if d.kind == "suffix":
        return {"suffix": "*." + d.value, "ports": ports}
    return {d.kind: d.value, "ports": ports}


def normalize(grant: m.Grant) -> EffectiveGrant:
    """A validated grant in normalized form. A method or a destination that cannot be read is an error."""
    unknown = sorted(set(grant.methods) - KNOWN_METHODS)
    if unknown:
        raise GrantError(f"the grant names {len(unknown)} method(s) this version does not know")
    destinations: list[Destination] = []
    for entry in grant.network.destinations:
        d = destination(
            name=entry.name,
            suffix=entry.suffix,
            network=entry.network,
            ports=[(p.first, p.last) for p in entry.ports],
        )
        if d is None:
            raise GrantError("the grant holds a destination that is not a name, a suffix rule or an IPv4 network")
        destinations.append(d)
    return EffectiveGrant(
        methods=frozenset(grant.methods),
        images=frozenset(grant.images),
        modes=frozenset(mode.value for mode in grant.network.modes),
        destinations=tuple(destinations),
        ceilings=Ceilings(
            grant.ceilings.vcpus,
            grant.ceilings.memory_mib,
            grant.ceilings.disk_mib,
            grant.ceilings.execution_timeout_seconds,
            grant.ceilings.sandbox_lifetime_seconds,
        ),
        mint_agent_credentials=grant.mint_agent_credentials,
    )


def parse(data: object) -> EffectiveGrant:
    """Parse a grant from its stored or submitted form. Unknown fields make it unusable."""
    try:
        text = data if isinstance(data, str | bytes) else json.dumps(data)
        grant = m.Grant.model_validate_json(text)
    except (ValidationError, ValueError, TypeError) as e:
        raise GrantError("the grant is not valid for this version of the grant schema") from e
    return normalize(grant)


def narrow(parent: EffectiveGrant, narrowing: EffectiveGrant | None) -> EffectiveGrant:
    """``parent`` narrowed by ``narrowing``. The result is inside ``parent`` whatever ``narrowing`` says."""
    if narrowing is None:
        return parent
    if ANY_IMAGE in parent.images:
        images = narrowing.images
    elif ANY_IMAGE in narrowing.images:
        images = parent.images
    else:
        images = parent.images & narrowing.images
    return EffectiveGrant(
        methods=parent.methods & narrowing.methods,
        images=images,
        modes=parent.modes & narrowing.modes,
        destinations=tuple(d for d in narrowing.destinations if inside(d, parent.destinations)),
        ceilings=parent.ceilings.min(narrowing.ceilings),
        mint_agent_credentials=parent.mint_agent_credentials and narrowing.mint_agent_credentials,
    )


def widens(child: EffectiveGrant, parent: EffectiveGrant) -> list[str]:
    """Where ``child`` allows something ``parent`` does not. Empty: ``child`` is inside ``parent``."""
    out: list[str] = []
    if not child.methods <= parent.methods:
        out.append("methods")
    if ANY_IMAGE not in parent.images and (ANY_IMAGE in child.images or not child.images <= parent.images):
        out.append("images")
    if not child.modes <= parent.modes:
        out.append("network_modes")
    if any(not inside(d, parent.destinations) for d in child.destinations):
        out.append("destinations")
    if not child.ceilings.within(parent.ceilings):
        out.append("ceilings")
    if child.mint_agent_credentials and not parent.mint_agent_credentials:
        out.append("mint_agent_credentials")
    return out


def policy_version(grants_json: str) -> str:
    """A short, stable name for one text of a grant, recorded with every decision taken under it."""
    return "pv_" + hashlib.sha256(grants_json.encode("utf-8")).hexdigest()[:16]
