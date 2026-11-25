"""Grants: what a role allows, how a credential narrows it, and when one grant is inside another.

Proves AZ-1 (what a grant holds, and nothing about who created a record), AZ-2 (deny by default:
whatever a grant does not mention is denied), AZ-3 (a field this version does not know makes the grant
unusable, never broader), AZ-4 (the effective permission is the role's grant narrowed by the
credential; narrowing never widens), AZ-5 (the two shipped templates), the grant half of CRD-9 (a
narrowing is a subset of the minting credential's grant; an agent credential cannot mint) and SEC-111
(a grant only narrows). Catalog entries: T3-AZ-01, the unit halves of T3-AZ-02, T3-RED-13 and
T3-CRD-01. That a grant above the host's ceiling is refused by the host and not by the platform, and
that the `acf mcp` relay refuses a developer key, are proven elsewhere.

"Never widens" is tested three ways, because it is the property everything else rests on: with the
function that reports widening, dimension by dimension without that function, and by its meaning, that
no request allowed under a narrowed grant is refused under the grant it narrows.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from hypothesis import given, settings
from hypothesis import strategies as st

from acf_api.command import model as m
from acf_api.command.errors import Code, Retry
from acf_api.command.surface import OPERATIONS, OperationClass
from acf_api.core import app
from acf_api.core.policy import authorizer as az
from acf_api.core.policy import grants as g
from acf_api.core.policy.destinations import Destination, destination, inside

REPO = Path(__file__).resolve().parents[3]
POLICIES = REPO / "policies" / "defaults"

ALL_METHODS = sorted(op.method for op in OPERATIONS)
MINT = "agent_credential.mint"
CEILING_NAMES = ("vcpus", "memory_mib", "disk_mib", "execution_timeout_seconds", "sandbox_lifetime_seconds")
CEILINGS = {
    "vcpus": 4,
    "memory_mib": 4096,
    "disk_mib": 8192,
    "execution_timeout_seconds": 600,
    "sandbox_lifetime_seconds": 3600,
}
LIMITS = az.HostLimits(frozenset({"none", "allowlist"}), 8, 16384, 65536, 3600, 3600, 86400)
HTTPS = [{"from": 443, "to": 443}]


def grant_dict(**members: Any) -> dict[str, Any]:
    """A grant in its stored form. Whatever a test does not name is absent, and so denied."""
    body: dict[str, Any] = {"schema_version": 1, "ceilings": dict(CEILINGS)}
    body.update(members)
    return body


def parsed(**members: Any) -> g.EffectiveGrant:
    return g.parse(grant_dict(**members))


def full(**members: Any) -> g.EffectiveGrant:
    body = {
        "methods": ALL_METHODS,
        "images": ["*"],
        "network": {"modes": ["none", "allowlist"], "destinations": [{"suffix": "*.example.com", "ports": HTTPS}]},
        "mint_agent_credentials": True,
    }
    body.update(members)
    return parsed(**body)


def subject(grant: g.EffectiveGrant, kind: str = "developer") -> az.Subject:
    return az.Subject("prn_test", "prj_test", kind, grant, "pv_test")


def decide(
    grant: g.EffectiveGrant,
    request: az.PolicyRequest,
    *,
    kind: str = "developer",
    limits: az.HostLimits | None = LIMITS,
) -> az.Decision:
    return az.evaluate(subject(grant, kind), request, limits)


def name(text: str, ports: tuple[tuple[int, int], ...] = ((443, 443),)) -> Destination:
    made = destination(name=text, suffix=None, network=None, ports=list(ports))
    assert made is not None
    return made


# ------------------------------------------------------------------------------- methods: the whole table
@pytest.mark.proves("T3-AZ-01")
def test_every_method_against_every_grant_of_one_method() -> None:
    """Exhaustive: each public method, under each grant that lists exactly one method, and under none."""
    assert len(ALL_METHODS) == len(set(ALL_METHODS)) == len(OPERATIONS) >= 20
    checked = 0
    for granted in [None, *ALL_METHODS]:
        grant = parsed(methods=[] if granted is None else [granted], mint_agent_credentials=True)
        for requested in ALL_METHODS:
            decision = decide(grant, az.PolicyRequest(method=requested))
            assert decision.allowed is (requested == granted), (granted, requested)
            assert az.allows_method(grant, requested) is (requested == granted)
            assert az.allows_containment(grant, requested) is (requested == granted)
            if not decision.allowed:
                assert (decision.reason, decision.code, decision.retry) == (
                    az.R_METHOD,
                    Code.PERMISSION_DENIED,
                    Retry.NEVER,
                )
            checked += 1
    assert checked == (len(ALL_METHODS) + 1) * len(ALL_METHODS)


@pytest.mark.proves("T3-AZ-01")
@pytest.mark.parametrize("missing", ALL_METHODS)
def test_a_grant_that_lists_every_method_but_one_denies_exactly_that_one(missing: str) -> None:
    grant = full(methods=[method for method in ALL_METHODS if method != missing])
    for requested in ALL_METHODS:
        assert decide(grant, az.PolicyRequest(method=requested)).allowed is (requested != missing), requested


@pytest.mark.proves("T3-AZ-01")
def test_a_grant_that_mentions_nothing_allows_nothing() -> None:
    """Deny by default starts with the grant itself: only its ceilings are required, and they allow nothing alone."""
    empty = g.parse({"ceilings": CEILINGS})
    assert empty.methods == frozenset()
    assert empty.images == frozenset()
    assert empty.modes == frozenset()
    assert empty.destinations == ()
    assert empty.mint_agent_credentials is False
    for requested in ALL_METHODS:
        assert not decide(empty, az.PolicyRequest(method=requested)).allowed
        assert not az.allows_containment(empty, requested)


@pytest.mark.proves("T3-AZ-01")
@pytest.mark.parametrize(
    "unknown",
    [
        "",
        "sandbox",
        "sandbox.create ",
        "SANDBOX.CREATE",
        "sandbox.*",
        "*",
        "profile.reload",
        "quarantine.release",
        "host.set_mode",
        "host.acknowledge",
        "exec.run",
        "sandbox.inspect",
    ],
)
def test_a_method_that_is_not_a_public_method_is_denied_and_cannot_be_granted(unknown: str) -> None:
    """Host methods and operator methods are not public methods: no grant can name one, and no request passes as one."""
    assert not decide(full(), az.PolicyRequest(method=unknown)).allowed
    with pytest.raises(g.GrantError):
        parsed(methods=["sandbox.create", unknown])


@pytest.mark.proves("T3-AZ-01")
def test_every_decision_is_identified_and_names_the_policy_it_was_taken_under() -> None:
    grant = full()
    decisions = [decide(grant, az.PolicyRequest(method=method)) for method in ALL_METHODS] + [
        decide(parsed(), az.PolicyRequest(method=method)) for method in ALL_METHODS
    ]
    ids = [decision.decision_id for decision in decisions]
    assert len(set(ids)) == len(ids)
    assert all(re.fullmatch(r"dec_[0-9a-f]{20}", decision_id) for decision_id in ids)
    assert {decision.policy_version for decision in decisions} == {"pv_test"}


# ------------------------------------------------------------------------------- deny by default: values
@pytest.mark.proves("T3-AZ-01")
def test_an_image_the_grant_does_not_mention_is_denied() -> None:
    create = "sandbox.create"
    none_listed = parsed(methods=[create])
    one_listed = parsed(methods=[create], images=["python"])
    every = parsed(methods=[create], images=["*"])
    for image in ("python", "node", "*", ""):
        assert decide(none_listed, az.PolicyRequest(method=create, image=image)).reason == az.R_IMAGE
        assert decide(every, az.PolicyRequest(method=create, image=image)).allowed
    assert decide(one_listed, az.PolicyRequest(method=create, image="python")).allowed
    for image in ("node", "Python", "python ", "pythonx", "*", ""):
        assert decide(one_listed, az.PolicyRequest(method=create, image=image)).reason == az.R_IMAGE, image


@pytest.mark.proves("T3-AZ-01")
def test_a_network_mode_the_grant_does_not_mention_is_denied() -> None:
    create = "sandbox.create"
    for modes in ([], ["none"], ["allowlist"], ["none", "allowlist"]):
        grant = parsed(methods=[create], images=["*"], network={"modes": modes})
        for mode in ("none", "allowlist", "restricted", "open", "host", "NONE", ""):
            decision = decide(grant, az.PolicyRequest(method=create, image="python", network_mode=mode))
            assert decision.allowed is (mode in modes), (modes, mode)
            if not decision.allowed:
                assert decision.reason == az.R_NETWORK_MODE


@pytest.mark.proves("T3-AZ-01")
def test_a_destination_the_grant_does_not_mention_is_denied() -> None:
    create = "sandbox.create"
    listed = {"modes": ["allowlist"], "destinations": [{"name": "pypi.org", "ports": HTTPS}]}
    grant = parsed(methods=[create], images=["*"], network=listed)
    nothing_listed = parsed(methods=[create], images=["*"], network={"modes": ["allowlist"]})

    def asked(*entries: Destination | None) -> az.PolicyRequest:
        return az.PolicyRequest(method=create, image="python", network_mode="allowlist", entries=entries)

    assert decide(grant, asked(name("pypi.org"))).allowed
    assert decide(grant, asked(name("PyPI.org."))).allowed
    assert decide(grant, asked()).allowed
    for entries in (
        (name("example.com"),),
        (name("pypi.org"), name("example.com")),
        (name("pypi.org", ((80, 80),)),),
        (name("files.pypi.org"),),
        (None,),
        (name("pypi.org"), None),
    ):
        assert decide(grant, asked(*entries)).reason == az.R_DESTINATION
    assert decide(nothing_listed, asked(name("pypi.org"))).reason == az.R_DESTINATION
    # An entry that cannot be read is inside nothing, however much the grant allows.
    wide = full(
        network={
            "modes": ["allowlist"],
            "destinations": [
                {"network": "0.0.0.0/0", "ports": [{"from": 1, "to": 65535}]},
                {"suffix": "*.com", "ports": [{"from": 1, "to": 65535}]},
            ],
        }
    )
    assert decide(wide, asked(None)).reason == az.R_DESTINATION


@pytest.mark.proves("T3-AZ-01")
@pytest.mark.parametrize(
    ("field", "ceiling", "reason"),
    [
        ("vcpus", "vcpus", az.R_RESOURCES),
        ("memory_mib", "memory_mib", az.R_RESOURCES),
        ("disk_mib", "disk_mib", az.R_RESOURCES),
        ("lifetime_seconds", "sandbox_lifetime_seconds", az.R_LIFETIME),
        ("timeout_seconds", "execution_timeout_seconds", az.R_TIMEOUT),
    ],
)
def test_a_value_is_allowed_up_to_its_ceiling_and_denied_above_it(field: str, ceiling: str, reason: str) -> None:
    grant = full()
    at = CEILINGS[ceiling]

    def asking_for(value: int) -> az.PolicyRequest:
        members: dict[str, Any] = {field: value}
        return az.PolicyRequest(method="sandbox.create", **members)

    assert decide(grant, asking_for(at)).allowed
    assert decide(grant, asking_for(1)).allowed
    above = decide(grant, asking_for(at + 1))
    assert (above.allowed, above.reason, above.code, above.retry) == (
        False,
        reason,
        Code.PERMISSION_DENIED,
        Retry.NEVER,
    )


# ------------------------------------------------------------------------------- unknown fields
def _dict_paths(value: Any, path: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    """The path to every object inside a JSON value, the value itself included."""
    paths: list[tuple[Any, ...]] = []
    if isinstance(value, dict):
        paths.append(path)
        for key, child in value.items():
            paths.extend(_dict_paths(child, (*path, key)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            paths.extend(_dict_paths(child, (*path, index)))
    return paths


def _with_member(value: Any, path: tuple[Any, ...], member: str, content: Any) -> Any:
    out = copy.deepcopy(value)
    node = out
    for step in path:
        node = node[step]
    node[member] = content
    return out


RICH_GRANT: dict[str, Any] = {
    "schema_version": 1,
    "methods": ["sandbox.create", "sandbox.destroy"],
    "images": ["python"],
    "network": {
        "modes": ["none", "allowlist"],
        "destinations": [
            {"name": "pypi.org", "ports": [{"from": 443, "to": 443}]},
            {"suffix": "*.example.com", "ports": [{"from": 80, "to": 80}, {"from": 443, "to": 443}]},
            {"network": "10.0.0.0/8", "ports": [{"from": 5432, "to": 5432}]},
        ],
    },
    "ceilings": dict(CEILINGS),
    "mint_agent_credentials": False,
}


@pytest.mark.proves("T3-AZ-01")
def test_the_grant_the_next_tests_damage_is_itself_valid() -> None:
    grant = g.parse(RICH_GRANT)
    assert grant.methods == {"sandbox.create", "sandbox.destroy"}
    assert [(dest.kind, dest.value) for dest in grant.destinations] == [
        ("name", "pypi.org"),
        ("suffix", "example.com"),
        ("network", "10.0.0.0/8"),
    ]
    # The grant itself, its network, three destinations, their four port ranges, and the ceilings.
    assert len(_dict_paths(RICH_GRANT)) == 10


@pytest.mark.proves("T3-AZ-01")
@pytest.mark.parametrize("path", _dict_paths(RICH_GRANT), ids=lambda path: "/".join(map(str, path)) or "top")
@pytest.mark.parametrize(
    ("member", "content"),
    [
        ("allow_all", True),
        ("owner", "prn_x"),
        ("created_by", "me"),
        ("x", None),
        ("images_extra", ["*"]),
        ("conditions", {"creator": "self"}),
    ],
)
def test_an_unknown_field_anywhere_makes_the_grant_unusable(path: tuple[Any, ...], member: str, content: Any) -> None:
    """Never a broader grant, and never a grant with the field ignored: the credential is unusable."""
    damaged = _with_member(RICH_GRANT, path, member, content)
    for form in (damaged, json.dumps(damaged), json.dumps(damaged).encode()):
        with pytest.raises(g.GrantError):
            g.parse(form)


@pytest.mark.proves("T3-AZ-01")
@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": 2},
        {"schema_version": 0},
        {"schema_version": "1"},
        {"schema_version": None},
        {"methods": "sandbox.create"},
        {"methods": [1]},
        {"methods": None},
        {"images": "*"},
        {"images": [None]},
        {"network": None},
        {"network": []},
        {"network": {"modes": ["restricted"]}},
        {"network": {"modes": ["none", "open"]}},
        {"network": {"modes": "none"}},
        {"network": {"modes": ["NONE"]}},
        {"network": {"modes": ["allowlist"], "destinations": [{"ports": HTTPS}]}},
        {
            "network": {
                "modes": ["allowlist"],
                "destinations": [{"name": "a.example", "network": "10.0.0.0/8", "ports": HTTPS}],
            }
        },
        {
            "network": {
                "modes": ["allowlist"],
                "destinations": [{"name": "a.example", "suffix": "*.example", "ports": HTTPS}],
            }
        },
        {"network": {"modes": ["allowlist"], "destinations": [{"name": "a.example"}]}},
        {"network": {"modes": ["allowlist"], "destinations": [{"name": "a.example", "ports": []}]}},
        {"network": {"modes": ["allowlist"], "destinations": [{"name": "a.example", "ports": [{"from": 0, "to": 1}]}]}},
        {
            "network": {
                "modes": ["allowlist"],
                "destinations": [{"name": "a.example", "ports": [{"from": 90, "to": 80}]}],
            }
        },
        {"network": {"modes": ["allowlist"], "destinations": [{"name": "a.example", "ports": [{"from": 443}]}]}},
        {
            "network": {
                "modes": ["allowlist"],
                "destinations": [{"name": "a.example", "ports": [{"first": 443, "last": 443, "port": 1}]}],
            }
        },
        {"network": {"modes": ["allowlist"], "destinations": [{"name": "exa mple.com", "ports": HTTPS}]}},
        {"network": {"modes": ["allowlist"], "destinations": [{"name": "*.example.com", "ports": HTTPS}]}},
        {"network": {"modes": ["allowlist"], "destinations": [{"suffix": "example.com", "ports": HTTPS}]}},
        {"network": {"modes": ["allowlist"], "destinations": [{"suffix": "*", "ports": HTTPS}]}},
        {"network": {"modes": ["allowlist"], "destinations": [{"network": "10.0.0.1/8", "ports": HTTPS}]}},
        {"network": {"modes": ["allowlist"], "destinations": [{"network": "10.0.0.0/255.0.0.0", "ports": HTTPS}]}},
        {"network": {"modes": ["allowlist"], "destinations": [{"network": "*", "ports": HTTPS}]}},
        {"network": {"modes": ["allowlist"], "destinations": ["*"]}},
        {"network": {"modes": ["allowlist"], "destinations": "*"}},
        {"ceilings": None},
        {"ceilings": {}},
        {"ceilings": {**CEILINGS, "vcpus": "4"}},
        {"ceilings": {**CEILINGS, "vcpus": True}},
        {"ceilings": {**CEILINGS, "vcpus": 4.0}},
        {"ceilings": {**CEILINGS, "vcpus": 0}},
        {"ceilings": {**CEILINGS, "vcpus": -1}},
        {"ceilings": {**CEILINGS, "memory_mib": None}},
        {"ceilings": {k: v for k, v in CEILINGS.items() if k != "disk_mib"}},
        {"ceilings": {**CEILINGS, "sandbox_lifetime_seconds": 10**12}},
        {"mint_agent_credentials": "true"},
        {"mint_agent_credentials": 1},
        {"mint_agent_credentials": None},
    ],
    ids=lambda change: json.dumps(change)[:70],
)
def test_a_grant_that_cannot_be_read_as_written_is_unusable(change: dict[str, Any]) -> None:
    with pytest.raises(g.GrantError):
        g.parse({**RICH_GRANT, **change})


@pytest.mark.proves("T3-AZ-01")
@pytest.mark.parametrize(
    "stored",
    [
        None,
        "",
        "{}",
        "null",
        "[]",
        "*",
        '"*"',
        "true",
        1,
        [],
        [RICH_GRANT],
        "{",
        b"\xff",
        json.dumps(RICH_GRANT) + "x",
        "{'methods': ['*']}",
    ],
)
def test_what_is_not_a_grant_at_all_is_unusable(stored: Any) -> None:
    with pytest.raises(g.GrantError):
        g.parse(stored)


@pytest.mark.proves("T3-AZ-01")
def test_the_refusal_of_a_grant_does_not_repeat_the_grant() -> None:
    canary = "CANARY-7d1f"
    for damaged in (
        {**RICH_GRANT, canary: canary},
        {**RICH_GRANT, "methods": [canary]},
        {**RICH_GRANT, "images": [canary], "x": 1},
    ):
        with pytest.raises(g.GrantError) as refused:
            g.parse(damaged)
        assert canary not in str(refused.value)


# ------------------------------------------------------------------------------- random grants and requests
IMAGES = ["*", "python", "node", "debian"]
NAMES = ["example.com", "a.example.com", "b.a.example.com", "example.org", "evilexample.com", "pypi.org"]
SUFFIXES = ["*.example.com", "*.a.example.com", "*.org", "*.com"]
NETWORKS = ["0.0.0.0/0", "10.0.0.0/8", "10.0.0.0/24", "10.0.1.0/24", "10.0.0.1/32", "192.168.0.0/16"]
PORT_SETS = [[(443, 443)], [(80, 80)], [(80, 80), (443, 443)], [(80, 443)], [(1, 65535)], [(8000, 8100)]]
VALUES = {
    "vcpus": [1, 2, 4],
    "memory_mib": [256, 512, 1024],
    "disk_mib": [1024, 2048],
    "execution_timeout_seconds": [60, 600],
    "sandbox_lifetime_seconds": [600, 3600],
}

port_lists = st.sampled_from(PORT_SETS).map(lambda ranges: [{"from": first, "to": last} for first, last in ranges])
destination_dicts = st.one_of(
    st.fixed_dictionaries({"name": st.sampled_from(NAMES), "ports": port_lists}),
    st.fixed_dictionaries({"suffix": st.sampled_from(SUFFIXES), "ports": port_lists}),
    st.fixed_dictionaries({"network": st.sampled_from(NETWORKS), "ports": port_lists}),
)
grant_dicts = st.fixed_dictionaries(
    {
        "schema_version": st.just(1),
        "methods": st.lists(st.sampled_from(ALL_METHODS), unique=True),
        "images": st.lists(st.sampled_from(IMAGES), unique=True, max_size=3),
        "network": st.fixed_dictionaries(
            {
                "modes": st.lists(st.sampled_from(["none", "allowlist"]), unique=True),
                "destinations": st.lists(destination_dicts, max_size=3),
            }
        ),
        "ceilings": st.fixed_dictionaries({field: st.sampled_from(values) for field, values in VALUES.items()}),
        "mint_agent_credentials": st.booleans(),
    }
)
random_grants = grant_dicts.map(g.parse)
destinations = st.one_of(
    st.builds(
        lambda text, ports: destination(name=text, suffix=None, network=None, ports=ports),
        st.sampled_from([*NAMES, "x.b.a.example.com", "exa mple.com"]),
        st.sampled_from(PORT_SETS),
    ),
    st.builds(
        lambda text, ports: destination(name=None, suffix=None, network=text, ports=ports),
        st.sampled_from([*NETWORKS, "10.0.0.128/25", "10.0.0.1"]),
        st.sampled_from(PORT_SETS),
    ),
)


def around(values: list[int]) -> st.SearchStrategy[int | None]:
    return st.none() | st.sampled_from(sorted({v + d for v in values for d in (-1, 0, 1) if v + d > 0}))


intents = st.builds(
    az.Intent,
    image_alias=st.none() | st.sampled_from(IMAGES[1:]),
    image_readable=st.booleans(),
    vcpus=around(VALUES["vcpus"]),
    memory_mib=around(VALUES["memory_mib"]),
    disk_mib=around(VALUES["disk_mib"]),
    network_mode=st.none() | st.sampled_from(["none", "allowlist", "other"]),
    entries=st.none() | st.lists(destinations.filter(lambda entry: entry is not None), max_size=2).map(tuple),
)
host_limits = st.none() | st.builds(
    az.HostLimits,
    network_modes=st.sampled_from([frozenset({"none"}), frozenset({"none", "allowlist"}), frozenset()]),
    max_vcpus=st.sampled_from([1, 2, 4, 8]),
    max_memory_mib=st.sampled_from([256, 1024, 4096]),
    max_disk_mib=st.sampled_from([1024, 2048, 8192]),
    max_runtime_seconds=st.just(3600),
    lifetime_default_seconds=st.just(3600),
    lifetime_max_seconds=st.just(86400),
)
policy_requests = st.builds(
    az.PolicyRequest,
    method=st.sampled_from([*ALL_METHODS, "profile.reload"]),
    image=st.none() | st.sampled_from([*IMAGES, "ruby"]),
    vcpus=around(VALUES["vcpus"]),
    memory_mib=around(VALUES["memory_mib"]),
    disk_mib=around(VALUES["disk_mib"]),
    network_mode=st.none() | st.sampled_from(["none", "allowlist", "restricted"]),
    entries=st.lists(destinations, max_size=2).map(tuple),
    lifetime_seconds=around(VALUES["sandbox_lifetime_seconds"]),
    timeout_seconds=around(VALUES["execution_timeout_seconds"]),
    targets=st.lists(intents, max_size=2).map(tuple),
    narrowing=st.none() | random_grants,
)

#: What covers an entry of the pools above: the way a wider grant is built from a narrower one.
COVERED_BY = {
    "example.com": {"suffix": "*.com"},
    "a.example.com": {"suffix": "*.example.com"},
    "b.a.example.com": {"suffix": "*.a.example.com"},
    "example.org": {"suffix": "*.org"},
    "evilexample.com": {"suffix": "*.com"},
    "pypi.org": {"suffix": "*.org"},
    "*.example.com": {"suffix": "*.com"},
    "*.a.example.com": {"suffix": "*.example.com"},
    "10.0.0.0/24": {"network": "10.0.0.0/8"},
    "10.0.1.0/24": {"network": "10.0.0.0/8"},
    "10.0.0.1/32": {"network": "10.0.0.0/24"},
    "10.0.0.0/8": {"network": "0.0.0.0/0"},
    "192.168.0.0/16": {"network": "0.0.0.0/0"},
}


@st.composite
def grant_and_wider(draw: st.DrawFn) -> tuple[g.EffectiveGrant, g.EffectiveGrant]:
    """A grant, and one built from it by only ever adding: methods, images, modes, destinations, room."""
    inner: dict[str, Any] = draw(grant_dicts)
    outer: dict[str, Any] = copy.deepcopy(inner)
    outer["methods"] = sorted(set(inner["methods"]) | set(draw(st.lists(st.sampled_from(ALL_METHODS), unique=True))))
    outer["images"] = (
        ["*"]
        if draw(st.booleans())
        else sorted(set(inner["images"]) | set(draw(st.lists(st.sampled_from(IMAGES), max_size=2))))
    )
    outer["network"]["modes"] = sorted(
        set(inner["network"]["modes"]) | set(draw(st.lists(st.sampled_from(["none", "allowlist"]), unique=True)))
    )
    widened = []
    for entry in inner["network"]["destinations"]:
        key = entry.get("name") or entry.get("suffix") or entry.get("network")
        how = draw(st.sampled_from(["same", "cover", "ports"]))
        if how == "cover" and key in COVERED_BY:
            widened.append({**COVERED_BY[key], "ports": entry["ports"]})
        elif how == "ports":
            widened.append({**entry, "ports": [{"from": 1, "to": 65535}]})
        else:
            widened.append(entry)
    extra = draw(st.lists(destination_dicts, max_size=6 - len(widened) if len(widened) < 6 else 0))
    outer["network"]["destinations"] = draw(st.permutations(widened + extra))
    outer["ceilings"] = {
        field: value + draw(st.sampled_from([0, 0, 1, 50])) for field, value in inner["ceilings"].items()
    }
    outer["mint_agent_credentials"] = inner["mint_agent_credentials"] or draw(st.booleans())
    return g.parse(inner), g.parse(outer)


# ------------------------------------------------------------------------------- narrowing
@pytest.mark.proves("T3-AZ-02", "T3-RED-13", "T3-CRD-01")
@settings(max_examples=200)  # twice the cases of the profile: this is the property the file is for
@given(random_grants, random_grants)
def test_narrowing_never_widens(parent: g.EffectiveGrant, narrowing: g.EffectiveGrant) -> None:
    effective = g.narrow(parent, narrowing)
    assert g.widens(effective, parent) == []
    # The effective grant is inside what the credential asked for as well: it is the narrowing, cut to the parent.
    assert g.widens(effective, narrowing) == []


@pytest.mark.proves("T3-AZ-02", "T3-RED-13", "T3-CRD-01")
@given(random_grants, random_grants)
def test_a_narrowed_grant_does_not_exceed_its_parent_on_any_dimension(
    parent: g.EffectiveGrant, narrowing: g.EffectiveGrant
) -> None:
    """The same claim without the function that reports widening: each dimension, looked at directly."""
    effective = g.narrow(parent, narrowing)
    assert effective.methods <= parent.methods
    assert effective.modes <= parent.modes
    if g.ANY_IMAGE not in parent.images:
        assert g.ANY_IMAGE not in effective.images
        assert effective.images <= parent.images
    for entry in effective.destinations:
        assert inside(entry, parent.destinations), entry
        assert entry in narrowing.destinations
    for field in CEILING_NAMES:
        assert getattr(effective.ceilings, field) <= getattr(parent.ceilings, field), field
        assert getattr(effective.ceilings, field) <= getattr(narrowing.ceilings, field), field
    assert parent.mint_agent_credentials or not effective.mint_agent_credentials
    assert narrowing.mint_agent_credentials or not effective.mint_agent_credentials


@pytest.mark.proves("T3-AZ-02", "T3-RED-13", "T3-CRD-01")
@given(random_grants, random_grants, policy_requests, host_limits, st.sampled_from(["developer", "agent"]))
def test_nothing_is_allowed_under_a_narrowed_grant_that_its_parent_refuses(
    parent: g.EffectiveGrant,
    narrowing: g.EffectiveGrant,
    request: az.PolicyRequest,
    limits: az.HostLimits | None,
    kind: str,
) -> None:
    effective = g.narrow(parent, narrowing)
    if az.evaluate(subject(effective, kind), request, limits).allowed:
        assert az.evaluate(subject(parent, kind), request, limits).allowed
        assert az.evaluate(subject(narrowing, kind), request, limits).allowed


@pytest.mark.proves("T3-AZ-02")
@given(random_grants)
def test_narrowing_by_nothing_or_by_itself_changes_nothing(grant: g.EffectiveGrant) -> None:
    assert g.narrow(grant, None) is grant
    itself = g.narrow(grant, grant)
    assert g.widens(itself, grant) == []
    assert g.widens(grant, itself) == []
    assert g.widens(grant, grant) == []


@pytest.mark.proves("T3-AZ-02", "T3-RED-13")
@given(random_grants, random_grants, random_grants)
def test_narrowing_twice_stays_inside_the_first_grant(
    role: g.EffectiveGrant, credential: g.EffectiveGrant, agent: g.EffectiveGrant
) -> None:
    """Role, credential, agent credential: the chain only ever gets narrower."""
    developer = g.narrow(role, credential)
    minted = g.narrow(developer, agent)
    assert g.widens(minted, developer) == []
    assert g.widens(minted, role) == []


# ------------------------------------------------------------------------------- monotonicity
@pytest.mark.proves("T3-AZ-02")
@given(grant_and_wider())
def test_a_grant_built_by_adding_is_never_reported_as_narrower(pair: tuple[g.EffectiveGrant, g.EffectiveGrant]) -> None:
    inner, outer = pair
    assert g.widens(inner, outer) == []


@pytest.mark.proves("T3-AZ-02")
@settings(max_examples=200)  # twice the cases of the profile: this is the property the file is for
@given(grant_and_wider(), policy_requests, host_limits, st.sampled_from(["developer", "agent"]))
def test_a_smaller_grant_never_allows_more(
    pair: tuple[g.EffectiveGrant, g.EffectiveGrant], request: az.PolicyRequest, limits: az.HostLimits | None, kind: str
) -> None:
    """Monotonicity: whatever is allowed under a grant is allowed under every grant it is inside."""
    inner, outer = pair
    assert g.widens(inner, outer) == []
    if az.evaluate(subject(inner, kind), request, limits).allowed:
        assert az.evaluate(subject(outer, kind), request, limits).allowed


@st.composite
def request_inside(draw: st.DrawFn, grant: g.EffectiveGrant) -> az.PolicyRequest:
    """A request that stays inside ``grant`` on every dimension. The grant lists a method other than minting."""
    c = grant.ceilings

    def up_to(ceiling: int) -> st.SearchStrategy[int | None]:
        return st.none() | st.integers(1, ceiling)

    image = None
    if grant.images:
        image = draw(st.none() | st.sampled_from(sorted(IMAGES[1:] if g.ANY_IMAGE in grant.images else grant.images)))
    mode = draw(st.none() | st.sampled_from(sorted(grant.modes))) if grant.modes else None
    entries: list[Destination] = []
    if mode == "allowlist" and grant.destinations:
        for granted in draw(st.lists(st.sampled_from(grant.destinations), max_size=2)):
            first, last = draw(st.sampled_from(granted.ports))
            ports = ((draw(st.integers(first, last)),) * 2,)
            if granted.kind == "suffix":
                entries.append(Destination("name", "x." + granted.value, ports))
            else:
                entries.append(Destination(granted.kind, granted.value, ports))
    target = az.Intent(
        image_alias=image,
        image_readable=image is not None,
        vcpus=draw(st.integers(1, c.vcpus)),
        memory_mib=draw(st.integers(1, c.memory_mib)),
        disk_mib=draw(st.integers(1, c.disk_mib)),
        network_mode=mode,
        entries=tuple(entries) if mode == "allowlist" else None,
    )
    readable_target = image is not None and mode is not None
    return az.PolicyRequest(
        method=draw(st.sampled_from(sorted(grant.methods - {MINT}))),
        image=image,
        vcpus=draw(up_to(c.vcpus)),
        memory_mib=draw(up_to(c.memory_mib)),
        disk_mib=draw(up_to(c.disk_mib)),
        network_mode=mode,
        entries=tuple(entries),
        lifetime_seconds=draw(up_to(c.sandbox_lifetime_seconds)),
        timeout_seconds=draw(up_to(c.execution_timeout_seconds)),
        targets=(target,) if readable_target and draw(st.booleans()) else (),
    )


def _lists_a_method(body: dict[str, Any]) -> bool:
    return bool(set(body["methods"]) - {MINT})


@st.composite
def grant_and_request_inside_it(draw: st.DrawFn) -> tuple[g.EffectiveGrant, az.PolicyRequest, az.HostLimits | None]:
    grant = g.parse(draw(grant_dicts.filter(_lists_a_method)))
    return grant, draw(request_inside(grant)), draw(host_limits)


@st.composite
def wider_grant_and_request_inside_the_smaller(
    draw: st.DrawFn,
) -> tuple[g.EffectiveGrant, g.EffectiveGrant, az.PolicyRequest]:
    inner, outer = draw(grant_and_wider().filter(lambda pair: bool(pair[0].methods - {MINT})))
    return inner, outer, draw(request_inside(inner))


@pytest.mark.proves("T3-AZ-02")
@given(wider_grant_and_request_inside_the_smaller(), host_limits, st.sampled_from(["developer", "agent"]))
def test_what_a_grant_allows_every_grant_around_it_allows(
    case: tuple[g.EffectiveGrant, g.EffectiveGrant, az.PolicyRequest], limits: az.HostLimits | None, kind: str
) -> None:
    """The same monotonicity, fed only requests the smaller grant allows, so that every example tests it."""
    inner, outer, request = case
    assert az.evaluate(subject(inner, kind), request, limits).allowed
    assert az.evaluate(subject(outer, kind), request, limits).allowed


@pytest.mark.proves("T3-AZ-01", "T3-AZ-02")
@given(grant_and_request_inside_it(), st.sampled_from(["developer", "agent"]))
def test_a_request_inside_a_grant_on_every_dimension_is_allowed(
    case: tuple[g.EffectiveGrant, az.PolicyRequest, az.HostLimits | None], kind: str
) -> None:
    """The other half of deny by default: what the grant does mention is allowed, so the properties above are not vacuous."""
    grant, request, limits = case
    decision = az.evaluate(subject(grant, kind), request, limits)
    assert decision.allowed, decision.reason
    assert decision.reason is None


# ------------------------------------------------------------------------------- what widening is
BASE = {
    "methods": ["sandbox.create", "sandbox.get"],
    "images": ["python"],
    "network": {"modes": ["none"], "destinations": [{"name": "pypi.org", "ports": HTTPS}]},
    "mint_agent_credentials": False,
}


@pytest.mark.proves("T3-AZ-02", "T3-RED-13")
@pytest.mark.parametrize(
    ("change", "reported"),
    [
        ({}, []),
        ({"methods": ["sandbox.create", "sandbox.get", "sandbox.destroy"]}, ["methods"]),
        ({"methods": ["sandbox.destroy"]}, ["methods"]),
        ({"methods": ["sandbox.create"]}, []),
        ({"methods": []}, []),
        ({"images": ["python", "node"]}, ["images"]),
        ({"images": ["node"]}, ["images"]),
        ({"images": ["*"]}, ["images"]),
        ({"images": []}, []),
        (
            {"network": {"modes": ["none", "allowlist"], "destinations": [{"name": "pypi.org", "ports": HTTPS}]}},
            ["network_modes"],
        ),
        ({"network": {"modes": ["allowlist"], "destinations": []}}, ["network_modes"]),
        ({"network": {"modes": [], "destinations": []}}, []),
        ({"network": {"modes": ["none"], "destinations": [{"name": "example.com", "ports": HTTPS}]}}, ["destinations"]),
        (
            {"network": {"modes": ["none"], "destinations": [{"suffix": "*.pypi.org", "ports": HTTPS}]}},
            ["destinations"],
        ),
        (
            {
                "network": {
                    "modes": ["none"],
                    "destinations": [{"name": "pypi.org", "ports": [{"from": 80, "to": 443}]}],
                }
            },
            ["destinations"],
        ),
        (
            {"network": {"modes": ["none"], "destinations": [{"network": "0.0.0.0/0", "ports": HTTPS}]}},
            ["destinations"],
        ),
        ({"network": {"modes": ["none"], "destinations": [{"name": "PyPI.org.", "ports": HTTPS}]}}, []),
        ({"ceilings": {**CEILINGS, "vcpus": 5}}, ["ceilings"]),
        ({"ceilings": {**CEILINGS, "memory_mib": 4097}}, ["ceilings"]),
        ({"ceilings": {**CEILINGS, "disk_mib": 8193}}, ["ceilings"]),
        ({"ceilings": {**CEILINGS, "execution_timeout_seconds": 601}}, ["ceilings"]),
        ({"ceilings": {**CEILINGS, "sandbox_lifetime_seconds": 3601}}, ["ceilings"]),
        ({"ceilings": dict.fromkeys(CEILINGS, 1)}, []),
        ({"mint_agent_credentials": True}, ["mint_agent_credentials"]),
        (
            {
                "methods": ["operation.list"],
                "images": ["*"],
                "network": {"modes": ["allowlist"], "destinations": [{"suffix": "*.org", "ports": HTTPS}]},
                "ceilings": {name: value + 1 for name, value in CEILINGS.items()},
                "mint_agent_credentials": True,
            },
            ["methods", "images", "network_modes", "destinations", "ceilings", "mint_agent_credentials"],
        ),
    ],
    ids=lambda value: json.dumps(value)[:60] if isinstance(value, dict) else None,
)
def test_widening_is_reported_dimension_by_dimension(change: dict[str, Any], reported: list[str]) -> None:
    parent = parsed(**BASE)
    child = parsed(**{**BASE, **change})
    assert g.widens(child, parent) == reported


@pytest.mark.proves("T3-AZ-02")
def test_a_parent_that_allows_every_image_is_widened_by_no_list_of_images() -> None:
    parent = parsed(**{**BASE, "images": ["*"]})
    for images in ([], ["python"], ["python", "node"], ["*"], ["*", "python"]):
        assert g.widens(parsed(**{**BASE, "images": images}), parent) == []
    assert g.narrow(parent, parsed(**{**BASE, "images": ["node"]})).images == {"node"}
    assert g.narrow(parsed(**BASE), parsed(**{**BASE, "images": ["*"]})).images == {"python"}
    assert g.narrow(parsed(**BASE), parsed(**{**BASE, "images": ["node"]})).images == frozenset()


# ------------------------------------------------------------------------------- minting
@pytest.mark.proves("T3-CRD-01", "T3-RED-13")
def test_only_a_developer_credential_whose_grant_allows_minting_may_mint() -> None:
    request = az.PolicyRequest(method=MINT)
    allowed = parsed(methods=[MINT], mint_agent_credentials=True)
    assert decide(allowed, request).allowed
    assert decide(allowed, request, limits=None).allowed
    for grant, kind, reason in (
        (parsed(methods=[MINT], mint_agent_credentials=False), "developer", az.R_MINT),
        (parsed(methods=[], mint_agent_credentials=True), "developer", az.R_METHOD),
        (allowed, "agent", az.R_MINT),
        (allowed, "", az.R_MINT),
        (allowed, "operator", az.R_MINT),
    ):
        refused = decide(grant, request, kind=kind)
        assert (refused.allowed, refused.reason, refused.code) == (False, reason, Code.PERMISSION_DENIED)


@pytest.mark.proves("T3-CRD-01", "T3-RED-13")
@given(grant_and_wider())
def test_a_narrowing_inside_the_minting_grant_is_accepted(pair: tuple[g.EffectiveGrant, g.EffectiveGrant]) -> None:
    narrowing, minting = pair
    if MINT in minting.methods and minting.mint_agent_credentials:
        assert decide(minting, az.PolicyRequest(method=MINT, narrowing=narrowing)).allowed


@pytest.mark.proves("T3-CRD-01", "T3-RED-13")
@given(random_grants, random_grants)
def test_a_narrowing_that_widens_on_any_dimension_is_refused(
    minting: g.EffectiveGrant, narrowing: g.EffectiveGrant
) -> None:
    """Minting never widens: the request is refused, it is not cut down to what the parent has."""
    minting = g.narrow(full(), minting) if MINT in minting.methods else minting
    decision = decide(minting, az.PolicyRequest(method=MINT, narrowing=narrowing))
    may_mint = MINT in minting.methods and minting.mint_agent_credentials
    assert decision.allowed is (may_mint and g.widens(narrowing, minting) == [])
    if may_mint and not decision.allowed:
        assert decision.reason == az.R_NARROWING


@pytest.mark.proves("T3-CRD-01")
@pytest.mark.parametrize(
    "dimension", ["methods", "images", "network_modes", "destinations", "ceilings", "mint_agent_credentials"]
)
def test_each_dimension_alone_is_enough_to_refuse_a_mint(dimension: str) -> None:
    minting = parsed(**{**BASE, "methods": [MINT, "sandbox.create"], "mint_agent_credentials": False})
    minting = g.EffectiveGrant(
        minting.methods,
        minting.images,
        minting.modes,
        minting.destinations,
        minting.ceilings,
        mint_agent_credentials=True,
    )
    wider_in: dict[str, dict[str, Any]] = {
        "methods": {"methods": ["sandbox.create", "sandbox.destroy"]},
        "images": {"images": ["*"]},
        "network_modes": {"network": {"modes": ["none", "allowlist"], "destinations": []}},
        "destinations": {"network": {"modes": ["none"], "destinations": [{"suffix": "*.org", "ports": HTTPS}]}},
        "ceilings": {"ceilings": {**CEILINGS, "sandbox_lifetime_seconds": CEILINGS["sandbox_lifetime_seconds"] + 1}},
        "mint_agent_credentials": {"mint_agent_credentials": True},
    }
    wider = wider_in[dimension]
    inside_it = parsed(**{**BASE, "methods": ["sandbox.create"]})
    assert decide(minting, az.PolicyRequest(method=MINT, narrowing=inside_it)).allowed
    refused = decide(
        minting, az.PolicyRequest(method=MINT, narrowing=parsed(**{**BASE, "methods": ["sandbox.create"], **wider}))
    )
    if dimension == "mint_agent_credentials":
        # The parent may mint, so a narrowing that asks for it does not widen. What an agent credential
        # can do with it is settled by its kind: an agent credential never mints.
        assert refused.allowed
        assert not decide(
            g.narrow(minting, parsed(**{**BASE, "methods": [MINT], **wider})),
            az.PolicyRequest(method=MINT),
            kind="agent",
        ).allowed
    else:
        assert (refused.allowed, refused.reason) == (False, az.R_NARROWING)


# ------------------------------------------------------------------------------- the stored form
@pytest.mark.proves("T3-AZ-01")
@given(random_grants)
def test_the_stored_form_of_a_grant_reads_back_as_the_same_grant(grant: g.EffectiveGrant) -> None:
    """A role's grant is stored as text and read on every request. What is read is what was stored."""
    stored = grant.to_json()
    assert g.parse(stored) == grant
    assert g.parse(json.loads(stored)) == grant
    assert g.parse(stored).to_json() == stored
    assert set(grant.to_view()) == {
        "schema_version",
        "methods",
        "images",
        "network",
        "ceilings",
        "mint_agent_credentials",
    }
    m.Grant.model_validate_json(stored)


@pytest.mark.proves("T3-AZ-01")
def test_the_policy_version_names_one_text_of_a_grant() -> None:
    one, other = full().to_json(), parsed().to_json()
    assert g.policy_version(one) == g.policy_version(one)
    assert g.policy_version(one) != g.policy_version(other)
    assert re.fullmatch(r"pv_[0-9a-f]{16}", g.policy_version(one))


@pytest.mark.proves("T3-AZ-01")
def test_a_grant_holds_what_the_contract_lists_and_nothing_about_who_created_a_record() -> None:
    """AZ-1: methods, images, network modes and destinations, five ceilings, and whether minting is allowed."""
    assert set(m.Grant.model_fields) == {
        "schema_version",
        "methods",
        "images",
        "network",
        "ceilings",
        "mint_agent_credentials",
    }
    assert set(m.GrantNetwork.model_fields) == {"modes", "destinations"}
    assert set(m.GrantDestination.model_fields) == {"name", "suffix", "network", "ports"}
    assert set(m.GrantCeilings.model_fields) == set(CEILING_NAMES)
    assert g.GRANT_SCHEMA_VERSION == 1
    assert frozenset(ALL_METHODS) == g.KNOWN_METHODS


# ------------------------------------------------------------------------------- the shipped templates
def template(name: str) -> g.EffectiveGrant:
    return g.parse(yaml.safe_load((POLICIES / f"{name}.yaml").read_text(encoding="utf-8")))


@pytest.mark.proves("T3-AZ-01", "T3-CRD-01")
def test_the_shipped_templates_parse_and_agent_is_inside_developer() -> None:
    developer, agent = template("developer"), template("agent")
    assert g.widens(agent, developer) == []
    assert g.widens(developer, agent) != [], "the two templates must not be the same grant"
    loaded = app.load_templates(POLICIES)
    assert loaded == {"developer": developer, "agent": agent}
    assert sorted(path.name for path in POLICIES.glob("*.yaml")) == ["agent.yaml", "developer.yaml"]
    for grant in (developer, agent):
        assert grant.methods <= g.KNOWN_METHODS
        assert g.parse(grant.to_json()) == grant


@pytest.mark.proves("T3-AZ-01", "T3-CRD-01", "T3-RED-13")
def test_the_agent_template_has_no_network_no_minting_and_keeps_containment() -> None:
    agent = template("agent")
    assert agent.modes == {"none"}
    assert agent.destinations == ()
    assert agent.mint_agent_credentials is False
    assert not {method for method in agent.methods if method.startswith("agent_credential.")}
    containment = {op.method for op in OPERATIONS if op.operation_class is OperationClass.CONTAINMENT}
    assert containment == {"sandbox.stop", "sandbox.destroy", "execution.cancel", "snapshot.delete"}
    assert containment <= agent.methods
    for method in containment:
        assert az.allows_containment(agent, method)
    # An agent credential cannot mint, whatever narrowing it was given and whatever its parent may do.
    for parent in (template("developer"), full()):
        effective = g.narrow(parent, agent)
        assert not effective.mint_agent_credentials
        assert MINT not in effective.methods
        assert not decide(effective, az.PolicyRequest(method=MINT), kind="agent").allowed
        assert not decide(
            effective, az.PolicyRequest(method="sandbox.create", image="python", network_mode="allowlist"), kind="agent"
        ).allowed
        assert decide(
            effective, az.PolicyRequest(method="sandbox.create", image="python", network_mode="none"), kind="agent"
        ).allowed


@pytest.mark.proves("T3-AZ-01")
def test_the_developer_template_may_mint_and_reaches_no_destination_by_default() -> None:
    developer = template("developer")
    assert developer.mint_agent_credentials is True
    assert {MINT, "agent_credential.list", "agent_credential.revoke"} <= developer.methods
    assert developer.modes == {"none", "allowlist"}
    # Egress is a capability that is granted explicitly: the mode is there, and no destination is.
    assert developer.destinations == ()
    asked = az.PolicyRequest(
        method="sandbox.create", image="python", network_mode="allowlist", entries=(name("pypi.org"),)
    )
    assert decide(developer, asked).reason == az.R_DESTINATION


@pytest.mark.proves("T3-AZ-01")
def test_no_ceiling_of_the_agent_template_is_above_the_shipped_host_profile() -> None:
    """AZ-5: the `agent` template takes its ceilings from the host profile's defaults, not from above its maximums.

    Read either way, as the profile's `defaults` or as the ceilings of the default profile, no ceiling
    of the template may exceed the ceiling the shipped profile sets for the same thing. A ceiling
    above the host's is legal for a grant in general (AZ-4); for this template the contract asks for less.
    """
    profile = yaml.safe_load((REPO / "profiles" / "default.yaml").read_text(encoding="utf-8"))["limits"]
    agent, developer = template("agent").ceilings, template("developer").ceilings
    assert agent.vcpus <= profile["max_vcpus"]
    assert agent.memory_mib <= profile["max_memory_mib"]
    assert agent.disk_mib <= profile["max_disk_mib"]
    assert agent.execution_timeout_seconds * 1000 <= profile["max_runtime_ms"]
    assert agent.sandbox_lifetime_seconds <= profile["max_lifetime_secs"]
    for field in CEILING_NAMES:
        assert getattr(agent, field) < getattr(developer, field), field
