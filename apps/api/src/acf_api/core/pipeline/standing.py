"""The platform's standing: whether it may accept granting work right now, and why not.

Granting work (create, start, exec, snapshot, restore) is refused, with nothing sent, while any of
these holds. Containment and reads are never gated by any of them.

* the first recovery pass after a start has not visited every entry of an earlier epoch;
* the host speaks none of the protocols this build was built for, or lacks a required feature;
* the host reports a store lineage other than the pinned one, and no operator has acknowledged it;
* a view carries another peer id for the platform than the one first recorded;
* the endpoint did not prove it is the configured host;
* the host refused the platform itself (its enrolment was removed, its certificate expired);
* the two clocks differ: the host refused a fresh ``issued_at`` as expired.

The lineage and the peer id are *pinned*: the first value seen is written to the security journal, and
any other value is a change an operator must acknowledge. After the acknowledgement, the ledger's
entries under the old value become LOST and are never resubmitted.

``host.info`` is an observation, re-read at most every ``host_info_ttl``. It decides what the platform
offers. It is never used to skip a check the host makes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from acf_api.command.surface import HOST_PROTOCOLS, REQUIRED_HOST_FEATURES
from acf_api.core.host.binding import HostInfo

NOT_RECOVERED: Final = "recovery_pass_pending"
HOST_UNKNOWN: Final = "host_not_yet_reached"
PROTOCOL: Final = "host_protocol_unsupported"
FEATURE: Final = "host_feature_missing"
LINEAGE: Final = "host_lineage_changed"
PEER: Final = "platform_peer_id_changed"
IDENTITY: Final = "host_identity_unverified"
REFUSED_BY_HOST: Final = "host_refuses_the_platform"
CLOCK: Final = "clock_offset"
STORE: Final = "store_unusable"
HOST_PARAMETER: Final = "host_parameter_relation"


@dataclass(slots=True)
class Standing:
    """Mutable state of one core. Read by the pipeline before granting work; written by what observes the host."""

    info: HostInfo | None = None
    info_at: float | None = None
    pinned_lineage: str | None = None
    pinned_peer_id: str | None = None
    #: A lineage the host reported that is not the pinned one. Set until an operator acknowledges it.
    reported_lineage: str | None = None
    reported_peer_id: str | None = None
    recovered: bool = False
    store_usable: bool = True
    identity_error: str | None = None
    refused_by_host: str | None = None
    clock_offset: bool = False
    #: When the next granting request may pass as a probe while the clock offset stands (monotonic).
    probe_at: float = 0.0
    #: The highest commit sequence seen from the host under the pinned lineage.
    sequence_high_water: int = 0
    host_parameter_violations: list[str] = field(default_factory=list)
    #: Development only: the edge shares the core's operating-system identity.
    shared_identity: bool = False
    journal_mirror_failures: int = 0

    # ------------------------------------------------------------------ what the host offers
    def missing_features(self) -> list[str]:
        if self.info is None:
            return []
        return [f for f in REQUIRED_HOST_FEATURES if f not in self.info.features]

    def protocol_supported(self) -> bool:
        return self.info is not None and any(p in self.info.protocols for p in HOST_PROTOCOLS)

    def offers(self, feature: str) -> bool:
        return self.info is not None and feature in self.info.features

    # ------------------------------------------------------------------ readiness
    def not_ready_reasons(self) -> list[str]:
        """Why granting work is refused. Empty: it is accepted."""
        reasons: list[str] = []
        if not self.store_usable:
            reasons.append(STORE)
        if not self.recovered:
            reasons.append(NOT_RECOVERED)
        if self.identity_error is not None:
            reasons.append(IDENTITY)
        if self.info is None:
            if self.identity_error is None:
                reasons.append(HOST_UNKNOWN)
        else:
            if not self.protocol_supported():
                reasons.append(PROTOCOL)
            reasons.extend(f"{FEATURE}:{name}" for name in self.missing_features())
        if self.reported_lineage is not None:
            reasons.append(LINEAGE)
        if self.reported_peer_id is not None:
            reasons.append(PEER)
        if self.refused_by_host is not None:
            reasons.append(REFUSED_BY_HOST)
        if self.host_parameter_violations:
            reasons.append(HOST_PARAMETER)
        return reasons

    def ready(self) -> bool:
        return not self.not_ready_reasons()

    def serving(self) -> bool:
        """Whether the platform itself serves. Depends on nothing of the host, so anyone may be told."""
        return self.store_usable

    # ------------------------------------------------------------------ observations
    def observe_lineage(self, lineage: str, sequence: int | None) -> bool:
        """Note the lineage of an answer. Returns ``False`` when it is not the pinned one."""
        if self.pinned_lineage is None:
            return True
        if lineage != self.pinned_lineage:
            self.reported_lineage = lineage
            return False
        if sequence is not None and sequence > self.sequence_high_water:
            self.sequence_high_water = sequence
        return True

    def observe_peer(self, peer_id: str) -> bool:
        """Note the peer id on a view. Returns ``False`` when it is not the recorded one."""
        if self.pinned_peer_id is None:
            return True
        if peer_id != self.pinned_peer_id:
            self.reported_peer_id = peer_id
            return False
        return True

    def health(self) -> dict[str, object]:
        """Everything an operator is told. Never shown through a public interface."""
        return {
            "serving": self.serving(),
            "ready": self.ready(),
            "not_ready_reasons": self.not_ready_reasons(),
            "host_id": self.info.host_id if self.info else None,
            "host_mode": self.info.mode if self.info else None,
            "host_features": sorted(self.info.features) if self.info else None,
            "host_protocols": list(self.info.protocols) if self.info else None,
            "pinned_lineage": self.pinned_lineage,
            "reported_lineage": self.reported_lineage,
            "pinned_peer_id": self.pinned_peer_id,
            "reported_peer_id": self.reported_peer_id,
            "host_role": self.info.role if self.info else None,
            "identity_error": self.identity_error,
            "refused_by_host": self.refused_by_host,
            "clock_offset_suspected": self.clock_offset,
            "host_parameter_violations": list(self.host_parameter_violations),
            "missing_features": self.missing_features(),
            "edge_shares_core_identity": self.shared_identity,
            "journal_mirror_failures": self.journal_mirror_failures,
        }
