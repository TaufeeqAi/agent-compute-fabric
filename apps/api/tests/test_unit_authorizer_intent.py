"""The access check against the recorded intent of the target, with the target's intent stubbed.

Proves AZ-7: for an operation that uses an existing sandbox or snapshot (start, exec, snapshot,
restore), the grant is checked against the image, the resources and the network intent the host
recorded for the target, and not only against what the request says; a property the host's views do
not show is unreadable, and an unreadable intent counts as the widest the host's safety profile
allows, so the request is refused unless the grant allows all of that. It also proves the part of
SEC-121 that follows: a credential without network egress cannot reach it through a target that has it.

Catalog entry: the unit half of T3-RED-10. How the intent of a sandbox and of a snapshot is read from
the host's views, and that the four operations are refused end to end, is proven by the pipeline suite.

The policy is a pure function, so the target is whatever the test says it is. Nothing here talks to a host.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import pytest
import yaml
from hypothesis import given
from hypothesis import strategies as st

from acf_api.command.errors import Code, Retry
from acf_api.core.policy import authorizer as az
from acf_api.core.policy import grants as g
from acf_api.core.policy.destinations import Destination, destination

REPO = Path(__file__).resolve().parents[3]

#: The operations that use an existing sandbox or snapshot: start, exec, snapshot, restore.
ON_A_TARGET = ["sandbox.start", "execution.create", "snapshot.create", "snapshot.restore"]
CEILINGS = {
    "vcpus": 2,
    "memory_mib": 1024,
    "disk_mib": 2048,
    "execution_timeout_seconds": 600,
    "sandbox_lifetime_seconds": 3600,
}
#: A host that offers no network: the only case in which an unreadable network intent can be covered at all.
HOST_WITHOUT_NETWORK = az.HostLimits(frozenset({"none"}), 4, 4096, 8192, 3600, 3600, 86400)
HOST = dataclasses.replace(HOST_WITHOUT_NETWORK, network_modes=frozenset({"none", "allowlist"}))
EVERY_PORT = [{"from": 1, "to": 65535}]


def grant(**members: Any) -> g.EffectiveGrant:
    body: dict[str, Any] = {
        "methods": ON_A_TARGET,
        "images": ["python"],
        "network": {"modes": ["none"]},
        "ceilings": dict(CEILINGS),
    }
    body.update(members)
    return g.parse(body)


def entry(name: str | None = None, network: str | None = None, port: int = 443) -> Destination:
    made = destination(name=name, suffix=None, network=network, ports=[(port, port)])
    assert made is not None
    return made


def intent(**changes: Any) -> az.Intent:
    """A target every property of which is readable and inside the grant of :func:`grant`."""
    return dataclasses.replace(az.Intent("python", True, 2, 1024, 2048, "none", None), **changes)


def decide(
    the_grant: g.EffectiveGrant,
    method: str,
    *targets: az.Intent,
    limits: az.HostLimits | None = HOST,
    kind: str = "agent",
    **values: Any,
) -> az.Decision:
    subject = az.Subject("prn_test", "prj_test", kind, the_grant, "pv_test")
    return az.evaluate(subject, az.PolicyRequest(method=method, targets=targets, **values), limits)


def denied(decision: az.Decision, reason: str) -> None:
    assert decision.allowed is False
    assert decision.reason == reason
    assert decision.code is Code.PERMISSION_DENIED
    assert decision.retry is (Retry.AFTER_CHANGE if reason == az.R_TARGET_UNREADABLE else Retry.NEVER)


NO_NETWORK = grant()
ALLOWLIST_TARGETS = [
    intent(network_mode="allowlist", entries=(entry("pypi.org"),)),
    intent(network_mode="allowlist", entries=(entry(network="203.0.113.0/24"),)),
    intent(network_mode="allowlist", entries=()),
    intent(network_mode="allowlist", entries=None),
]


# ------------------------------------------------------------------------------- a readable intent
@pytest.mark.proves("T3-RED-10")
@pytest.mark.parametrize("method", ON_A_TARGET)
def test_a_target_whose_intent_is_readable_and_inside_the_grant_is_allowed(method: str) -> None:
    for limits in (HOST, HOST_WITHOUT_NETWORK, None):
        decision = decide(NO_NETWORK, method, intent(), limits=limits)
        assert decision.allowed
        assert decision.reason is None
    assert decide(NO_NETWORK, method, intent(vcpus=1, memory_mib=1, disk_mib=1)).allowed
    assert decide(NO_NETWORK, method).allowed, "an operation without a target has no intent to check"


@pytest.mark.proves("T3-RED-10")
@pytest.mark.parametrize("method", ON_A_TARGET)
@pytest.mark.parametrize(
    "target", ALLOWLIST_TARGETS, ids=["one-name", "one-network", "no-entries", "entries-not-shown"]
)
def test_a_credential_without_network_cannot_use_a_target_that_has_one(method: str, target: az.Intent) -> None:
    """The request says nothing about a network. The sandbox it would run in has one: denied."""
    denied(decide(NO_NETWORK, method, target), az.R_TARGET_NETWORK)
    denied(decide(NO_NETWORK, method, target, limits=HOST_WITHOUT_NETWORK), az.R_TARGET_NETWORK)
    denied(decide(NO_NETWORK, method, target, limits=None), az.R_TARGET_NETWORK)
    denied(decide(NO_NETWORK, method, target, kind="developer"), az.R_TARGET_NETWORK)


@pytest.mark.proves("T3-RED-10")
@pytest.mark.parametrize("method", ON_A_TARGET)
def test_a_target_with_a_network_mode_the_grant_does_not_mention_is_denied(method: str) -> None:
    for mode in ("allowlist", "restricted", "open", "NONE", ""):
        denied(decide(NO_NETWORK, method, intent(network_mode=mode, entries=())), az.R_TARGET_NETWORK)
    denied(decide(grant(network={"modes": []}), method, intent()), az.R_TARGET_NETWORK)
    only_allowlist = grant(
        network={"modes": ["allowlist"], "destinations": [{"name": "pypi.org", "ports": EVERY_PORT}]}
    )
    denied(decide(only_allowlist, method, intent()), az.R_TARGET_NETWORK)


@pytest.mark.proves("T3-RED-10")
@pytest.mark.parametrize("method", ON_A_TARGET)
def test_an_allowlist_target_is_allowed_only_if_every_entry_of_it_is_inside_the_grant(method: str) -> None:
    egress = grant(
        network={
            "modes": ["none", "allowlist"],
            "destinations": [
                {"name": "pypi.org", "ports": [{"from": 443, "to": 443}]},
                {"suffix": "*.example.com", "ports": [{"from": 443, "to": 443}]},
                {"network": "10.0.0.0/8", "ports": [{"from": 5432, "to": 5432}]},
            ],
        }
    )

    def with_entries(*entries: Destination) -> az.Intent:
        return intent(network_mode="allowlist", entries=entries)

    assert decide(egress, method, with_entries()).allowed
    assert decide(egress, method, with_entries(entry("pypi.org"))).allowed
    assert decide(
        egress,
        method,
        with_entries(entry("PyPI.org."), entry("a.example.com"), entry(network="10.1.0.0/16", port=5432)),
    ).allowed
    for outside in (
        entry("example.org"),
        entry("example.com"),
        entry("evilexample.com"),
        entry("pypi.org", port=80),
        entry(network="10.1.0.0/16"),
        entry(network="192.168.0.0/16", port=5432),
        entry(network="0.0.0.0/0", port=5432),
    ):
        denied(decide(egress, method, with_entries(outside)), az.R_TARGET_NETWORK)
        denied(decide(egress, method, with_entries(entry("pypi.org"), outside)), az.R_TARGET_NETWORK)
    # The entries are not shown: the target may reach anything, and no grant says "anything".
    denied(decide(egress, method, intent(network_mode="allowlist", entries=None)), az.R_TARGET_UNREADABLE)


@pytest.mark.proves("T3-RED-10")
@pytest.mark.parametrize("method", ON_A_TARGET)
def test_a_target_of_an_image_the_grant_does_not_mention_is_denied(method: str) -> None:
    for alias in ("node", "browser", "Python", "python2", "", "*"):
        denied(decide(NO_NETWORK, method, intent(image_alias=alias)), az.R_TARGET_IMAGE)
    # The image is shown and has no alias: it is none of the images the grant lists.
    denied(decide(NO_NETWORK, method, intent(image_alias=None)), az.R_TARGET_IMAGE)
    denied(decide(grant(images=[]), method, intent()), az.R_TARGET_IMAGE)
    every_image = grant(images=["*"])
    for shown in ("node", "browser", None):
        assert decide(every_image, method, intent(image_alias=shown)).allowed


@pytest.mark.proves("T3-RED-10")
@pytest.mark.parametrize("method", ON_A_TARGET)
@pytest.mark.parametrize("resource", ["vcpus", "memory_mib", "disk_mib"])
def test_a_target_above_a_ceiling_of_the_grant_is_denied(method: str, resource: str) -> None:
    ceiling = CEILINGS[resource]
    assert decide(NO_NETWORK, method, intent(**{resource: ceiling})).allowed
    assert decide(NO_NETWORK, method, intent(**{resource: ceiling - 1})).allowed
    for above in (ceiling + 1, ceiling * 2, 10**9):
        denied(decide(NO_NETWORK, method, intent(**{resource: above})), az.R_TARGET_RESOURCES)
        # What the host would allow does not matter for a property that is shown.
        denied(decide(NO_NETWORK, method, intent(**{resource: above}), limits=None), az.R_TARGET_RESOURCES)
        denied(
            decide(NO_NETWORK, method, intent(**{resource: above}), limits=HOST_WITHOUT_NETWORK), az.R_TARGET_RESOURCES
        )


@pytest.mark.proves("T3-RED-10")
def test_the_target_is_checked_as_well_as_the_request_and_not_in_place_of_it() -> None:
    """Inside on one side and outside on the other is outside."""
    exec_ = "execution.create"
    assert decide(NO_NETWORK, exec_, intent(), timeout_seconds=600).allowed
    denied(decide(NO_NETWORK, exec_, intent(), timeout_seconds=601), az.R_TIMEOUT)
    denied(decide(NO_NETWORK, exec_, intent(vcpus=3), timeout_seconds=600), az.R_TARGET_RESOURCES)
    restore = "snapshot.restore"
    assert decide(NO_NETWORK, restore, intent(), lifetime_seconds=3600).allowed
    denied(decide(NO_NETWORK, restore, intent(), lifetime_seconds=3601), az.R_LIFETIME)
    denied(decide(NO_NETWORK, restore, intent(image_alias="node"), lifetime_seconds=3600), az.R_TARGET_IMAGE)
    # A method the grant does not list is denied before any target is looked at.
    denied(decide(grant(methods=["sandbox.start"]), exec_, intent()), az.R_METHOD)


@pytest.mark.proves("T3-RED-10")
@pytest.mark.parametrize("method", ON_A_TARGET)
def test_every_target_of_an_operation_must_be_inside(method: str) -> None:
    good, bad = intent(), intent(network_mode="allowlist", entries=())
    assert decide(NO_NETWORK, method, good, good).allowed
    denied(decide(NO_NETWORK, method, good, bad), az.R_TARGET_NETWORK)
    denied(decide(NO_NETWORK, method, bad, good), az.R_TARGET_NETWORK)
    denied(decide(NO_NETWORK, method, good, az.UNREADABLE), az.R_TARGET_UNREADABLE)
    denied(decide(NO_NETWORK, method, good, good, intent(disk_mib=4096)), az.R_TARGET_RESOURCES)


# ------------------------------------------------------------------------------- an unreadable intent
#: A grant that covers everything a host without a network allows at most.
COVERS_THE_HOST = grant(
    images=["*"],
    ceilings={**CEILINGS, "vcpus": 4, "memory_mib": 4096, "disk_mib": 8192},
)


@pytest.mark.proves("T3-RED-10")
def test_the_unreadable_intent_shows_nothing() -> None:
    assert az.Intent(None, False, None, None, None, None, None) == az.UNREADABLE


@pytest.mark.proves("T3-RED-10")
@pytest.mark.parametrize("method", ON_A_TARGET)
def test_an_unreadable_intent_is_allowed_only_if_the_grant_covers_the_widest_the_host_allows(method: str) -> None:
    assert decide(COVERS_THE_HOST, method, az.UNREADABLE, limits=HOST_WITHOUT_NETWORK).allowed
    roomier = grant(images=["*", "python"], ceilings={**CEILINGS, "vcpus": 64, "memory_mib": 65536, "disk_mib": 65536})
    assert decide(roomier, method, az.UNREADABLE, limits=HOST_WITHOUT_NETWORK).allowed
    for narrower in (
        grant(images=["python"], ceilings=COVERS_THE_HOST.to_view()["ceilings"]),
        grant(images=["python", "node", "base", "browser"], ceilings=COVERS_THE_HOST.to_view()["ceilings"]),
        grant(images=["*"], ceilings={**COVERS_THE_HOST.to_view()["ceilings"], "vcpus": 3}),
        grant(images=["*"], ceilings={**COVERS_THE_HOST.to_view()["ceilings"], "memory_mib": 4095}),
        grant(images=["*"], ceilings={**COVERS_THE_HOST.to_view()["ceilings"], "disk_mib": 8191}),
        grant(images=["*"], ceilings=COVERS_THE_HOST.to_view()["ceilings"], network={"modes": []}),
        NO_NETWORK,
    ):
        denied(decide(narrower, method, az.UNREADABLE, limits=HOST_WITHOUT_NETWORK), az.R_TARGET_UNREADABLE)


@pytest.mark.proves("T3-RED-10")
@pytest.mark.parametrize("method", ON_A_TARGET)
def test_an_unreadable_intent_is_denied_when_the_host_limits_are_not_known(method: str) -> None:
    """Without the host's limits there is no widest to compare with. The grant cannot be shown to cover it."""
    widest = grant(
        images=["*"],
        network={"modes": ["none", "allowlist"]},
        ceilings={**CEILINGS, "vcpus": 255, "memory_mib": 4_194_304, "disk_mib": 268_435_456},
    )
    denied(decide(widest, method, az.UNREADABLE, limits=None), az.R_TARGET_UNREADABLE)
    for one in ({"vcpus": None}, {"memory_mib": None}, {"disk_mib": None}, {"network_mode": None}):
        denied(decide(widest, method, intent(**one), limits=None), az.R_TARGET_UNREADABLE)
    # The image is the one property a grant can cover without knowing the host: `*` is every image.
    assert decide(widest, method, intent(image_alias=None, image_readable=False), limits=None).allowed


@pytest.mark.proves("T3-RED-10")
@pytest.mark.parametrize("method", ON_A_TARGET)
@pytest.mark.parametrize(
    ("unreadable", "covering", "not_covering"),
    [
        ({"image_alias": None, "image_readable": False}, {"images": ["*"]}, {"images": ["python", "node"]}),
        ({"image_alias": "python", "image_readable": False}, {"images": ["*"]}, {"images": ["python"]}),
        ({"vcpus": None}, {"ceilings": {**CEILINGS, "vcpus": 4}}, {"ceilings": {**CEILINGS, "vcpus": 3}}),
        (
            {"memory_mib": None},
            {"ceilings": {**CEILINGS, "memory_mib": 4096}},
            {"ceilings": {**CEILINGS, "memory_mib": 4095}},
        ),
        (
            {"disk_mib": None},
            {"ceilings": {**CEILINGS, "disk_mib": 8192}},
            {"ceilings": {**CEILINGS, "disk_mib": 8191}},
        ),
        ({"network_mode": None}, {"network": {"modes": ["none"]}}, {"network": {"modes": []}}),
    ],
    ids=["image", "image-with-a-stale-alias", "vcpus", "memory", "disk", "network"],
)
def test_one_unreadable_property_is_enough_to_need_the_widest_of_that_property(
    method: str, unreadable: dict[str, Any], covering: dict[str, Any], not_covering: dict[str, Any]
) -> None:
    target = intent(**unreadable)
    assert decide(grant(**covering), method, target, limits=HOST_WITHOUT_NETWORK).allowed
    denied(decide(grant(**not_covering), method, target, limits=HOST_WITHOUT_NETWORK), az.R_TARGET_UNREADABLE)
    # The readable properties are still checked as they are.
    denied(
        decide(grant(**covering), method, dataclasses.replace(target, network_mode="allowlist", entries=())),
        az.R_TARGET_NETWORK,
    )


@pytest.mark.proves("T3-RED-10")
@pytest.mark.parametrize("method", ON_A_TARGET)
def test_an_unreadable_network_is_denied_for_every_grant_when_the_host_offers_allowlist(method: str) -> None:
    """No grant can say "every destination", so no grant covers a network intent it cannot see."""
    everything_a_grant_can_say = grant(
        images=["*"],
        network={
            "modes": ["none", "allowlist"],
            "destinations": [
                {"network": "0.0.0.0/0", "ports": EVERY_PORT},
                {"suffix": "*.com", "ports": EVERY_PORT},
                {"suffix": "*.org", "ports": EVERY_PORT},
                {"suffix": "*.net", "ports": EVERY_PORT},
            ],
        },
        ceilings={**CEILINGS, "vcpus": 255, "memory_mib": 4_194_304, "disk_mib": 268_435_456},
        mint_agent_credentials=True,
    )
    for limits in (HOST, dataclasses.replace(HOST, network_modes=frozenset({"allowlist"}))):
        for target in (az.UNREADABLE, intent(network_mode=None), intent(network_mode="allowlist", entries=None)):
            denied(decide(everything_a_grant_can_say, method, target, limits=limits), az.R_TARGET_UNREADABLE)
            denied(
                decide(everything_a_grant_can_say, method, target, limits=limits, kind="developer"),
                az.R_TARGET_UNREADABLE,
            )
    # The same grant, the same target, a host with no network to offer: now the grant covers the widest.
    assert decide(everything_a_grant_can_say, method, az.UNREADABLE, limits=HOST_WITHOUT_NETWORK).allowed


modes = st.lists(st.sampled_from(["none", "allowlist"]), unique=True)
wide_destinations = st.lists(
    st.sampled_from(
        [
            {"network": "0.0.0.0/0", "ports": EVERY_PORT},
            {"suffix": "*.com", "ports": EVERY_PORT},
            {"name": "pypi.org", "ports": EVERY_PORT},
            {"network": "10.0.0.0/8", "ports": [{"from": 443, "to": 443}]},
        ]
    ),
    max_size=4,
)
any_grant = st.builds(
    lambda the_modes, the_destinations, images, vcpus, memory, disk: grant(
        images=images,
        network={"modes": the_modes, "destinations": the_destinations},
        ceilings={**CEILINGS, "vcpus": vcpus, "memory_mib": memory, "disk_mib": disk},
    ),
    modes,
    wide_destinations,
    st.sampled_from([["*"], ["python"], [], ["*", "python"]]),
    st.sampled_from([1, 4, 255]),
    st.sampled_from([1024, 4096, 4_194_304]),
    st.sampled_from([2048, 8192, 268_435_456]),
)
readable_or_not = st.builds(
    az.Intent,
    image_alias=st.sampled_from([None, "python", "node"]),
    image_readable=st.booleans(),
    vcpus=st.sampled_from([None, 1, 4, 8]),
    memory_mib=st.sampled_from([None, 512, 4096]),
    disk_mib=st.sampled_from([None, 1024, 8192]),
    network_mode=st.just(None),
    entries=st.none(),
)


@pytest.mark.proves("T3-RED-10")
@given(
    any_grant,
    readable_or_not,
    st.sampled_from(ON_A_TARGET),
    st.sampled_from([frozenset({"allowlist"}), frozenset({"none", "allowlist"})]),
)
def test_no_grant_at_all_covers_a_network_intent_it_cannot_see(
    the_grant: g.EffectiveGrant, target: az.Intent, method: str, offered: frozenset[str]
) -> None:
    decision = decide(the_grant, method, target, limits=dataclasses.replace(HOST, network_modes=offered))
    assert not decision.allowed
    assert decision.code is Code.PERMISSION_DENIED


@pytest.mark.proves("T3-RED-10")
@given(any_grant, readable_or_not, st.sampled_from(ON_A_TARGET))
def test_an_unreadable_property_never_makes_a_request_easier_to_allow(
    the_grant: g.EffectiveGrant, target: az.Intent, method: str
) -> None:
    """Hiding a property cannot help: if the target is allowed with a property hidden, it is allowed with it shown at the host's widest."""
    limits = HOST_WITHOUT_NETWORK
    if not decide(the_grant, method, target, limits=limits).allowed:
        return
    shown = dataclasses.replace(
        target,
        image_readable=True,
        vcpus=target.vcpus if target.vcpus is not None else limits.max_vcpus,
        memory_mib=target.memory_mib if target.memory_mib is not None else limits.max_memory_mib,
        disk_mib=target.disk_mib if target.disk_mib is not None else limits.max_disk_mib,
        network_mode="none",
    )
    assert decide(the_grant, method, shown, limits=limits).allowed


# ------------------------------------------------------------------------------- the shipped agent template
@pytest.mark.proves("T3-RED-10")
@pytest.mark.parametrize("method", ON_A_TARGET)
def test_an_agent_credential_of_the_shipped_template_meets_all_of_the_above(method: str) -> None:
    """The matrix of the catalog entry, for the grant an agent gets when its developer names no narrowing."""
    agent = g.parse(yaml.safe_load((REPO / "policies" / "defaults" / "agent.yaml").read_text(encoding="utf-8")))
    assert agent.modes == {"none"}
    c = agent.ceilings
    inside = az.Intent("python", True, c.vcpus, c.memory_mib, c.disk_mib, "none", None)
    assert decide(agent, method, inside).allowed
    for target in ALLOWLIST_TARGETS:
        denied(
            decide(
                agent, method, dataclasses.replace(inside, network_mode=target.network_mode, entries=target.entries)
            ),
            az.R_TARGET_NETWORK,
        )
    denied(decide(agent, method, dataclasses.replace(inside, vcpus=c.vcpus + 1)), az.R_TARGET_RESOURCES)
    denied(decide(agent, method, dataclasses.replace(inside, memory_mib=c.memory_mib + 1)), az.R_TARGET_RESOURCES)
    denied(decide(agent, method, dataclasses.replace(inside, disk_mib=c.disk_mib + 1)), az.R_TARGET_RESOURCES)
    # A snapshot whose source is gone shows nothing of its intent. The host offers allowlist: refused.
    denied(decide(agent, method, az.UNREADABLE), az.R_TARGET_UNREADABLE)
    denied(decide(agent, method, az.UNREADABLE, limits=None), az.R_TARGET_UNREADABLE)
