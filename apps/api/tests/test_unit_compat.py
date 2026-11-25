"""The comparison of two versions of the contract artifacts: what breaks a caller, and what does not.

Proves T3-VER-01 and the rule it guards, VER-1: within a major version nothing is removed, renamed,
retyped or made newly required, and no request schema becomes stricter. The cases below change copies of
the documents this package really generates, one change at a time, so the comparison is tried against the
shapes it has to read; the keywords those documents do not use are tried on small documents written here.
"""

from __future__ import annotations

import copy
import json
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from acf_api import cli
from acf_api.contract import compat, generate
from acf_api.core.agent import catalog

pytestmark = pytest.mark.proves("T3-VER-01", level="L0")

REPO = Path(__file__).resolve().parents[3]
PROTOCOLS = REPO / "protocols"
SANDBOXES = "/v1/projects/{project}/sandboxes"
EXECUTIONS = "/v1/projects/{project}/sandboxes/{sandbox}/executions"
POST_SANDBOXES = f"REST: POST {SANDBOXES}"

_REST = generate.build_openapi()
_TOOLS = {name: generate.build_tool(spec) for name, spec in catalog.TOOLS.items()}
_PROBLEMS = generate.build_problems()

#: What a change returns is never used, so it may return whatever its last step returns.
Change = Callable[[dict[str, Any]], object]


def rest(change: Change) -> list[str]:
    """What breaks when the REST description is changed in one way."""
    changed = copy.deepcopy(_REST)
    change(changed)
    return compat.breaking_changes(_REST, changed)


def tools(change: Change) -> list[str]:
    changed = copy.deepcopy(_TOOLS)
    change(changed)
    return compat.breaking_tool_changes(_TOOLS, changed)


def schema(document: dict[str, Any], name: str) -> dict[str, Any]:
    found: dict[str, Any] = document["components"]["schemas"][name]
    return found


def member(document: dict[str, Any], name: str, of: str) -> dict[str, Any]:
    found: dict[str, Any] = schema(document, name)["properties"][of]
    return found


def create(document: dict[str, Any]) -> dict[str, Any]:
    found: dict[str, Any] = document["paths"][SANDBOXES]["post"]
    return found


def parameter(document: dict[str, Any], name: str) -> dict[str, Any]:
    return next(p for p in create(document)["parameters"] if p.get("name") == name)


# ------------------------------------------------------------------------------------- nothing changed
def test_a_version_is_compatible_with_itself() -> None:
    assert compat.breaking_changes(_REST, copy.deepcopy(_REST)) == []
    assert compat.breaking_tool_changes(_TOOLS, copy.deepcopy(_TOOLS)) == []
    assert compat.breaking_problem_changes(_PROBLEMS, copy.deepcopy(_PROBLEMS)) == []


def test_the_documents_under_test_are_the_real_ones() -> None:
    """A comparison that had nothing to read would find nothing wrong. These are the sizes it reads."""
    assert len(_REST["paths"]) >= 18
    assert len(_REST["components"]["schemas"]) >= 40
    assert len(_TOOLS) == 16
    assert len(_PROBLEMS["codes"]) >= 20


# ---------------------------------------------------------------------------------- REST: what breaks
def _remove_parameter(d: dict[str, Any]) -> None:
    create(d)["parameters"] = [p for p in create(d)["parameters"] if p.get("name") != "wait"]


def _add_required_parameter(d: dict[str, Any]) -> None:
    create(d)["parameters"].append({"name": "X-Region", "in": "header", "required": True, "schema": {"type": "string"}})


def _add_required_member(d: dict[str, Any]) -> None:
    schema(d, "SandboxSpec")["properties"]["region"] = {"type": "string"}
    schema(d, "SandboxSpec")["required"].append("region")


def _never_null(d: dict[str, Any]) -> None:
    schema(d, "SandboxSpec")["properties"]["lifetime_seconds"] = {
        "type": "integer",
        "minimum": 1,
        "maximum": 31536000,
        "default": None,
    }


def _one_network_only(d: dict[str, Any]) -> None:
    network = member(d, "SandboxSpec", "network")
    network["oneOf"] = [alternative for alternative in network["oneOf"] if alternative["$ref"].endswith("/NetworkNone")]


def _integer_generation_only(d: dict[str, Any]) -> None:
    generation = member(d, "ExecSpec", "expected_generation")
    generation["anyOf"] = [alternative for alternative in generation["anyOf"] if alternative.get("type") == "integer"]


def _may_be_null(d: dict[str, Any]) -> None:
    schema(d, "Sandbox")["properties"]["state"] = {"anyOf": [{"type": "string"}, {"type": "null"}], "title": "State"}


REST_BREAKS: list[tuple[str, Change, str]] = [
    ("a route", lambda d: d["paths"][SANDBOXES].pop("post"), f"{POST_SANDBOXES}: the route was removed"),
    ("a path", lambda d: d["paths"].pop("/v1/info"), "REST: GET /v1/info: the route was removed"),
    ("a parameter", _remove_parameter, f"{POST_SANDBOXES}: the query parameter `wait` was removed"),
    (
        "a parameter made required",
        lambda d: parameter(d, "wait").update(required=True),
        f"{POST_SANDBOXES}: the query parameter `wait` is newly required",
    ),
    (
        "a parameter with less room",
        lambda d: parameter(d, "wait")["schema"].update(maximum=60),
        f"{POST_SANDBOXES}: query parameter `wait`: `maximum` was lowered from 3600 to 60",
    ),
    (
        "a new required parameter",
        _add_required_parameter,
        f"{POST_SANDBOXES}: the new header parameter `X-Region` is required",
    ),
    (
        "a shared header with less room",
        lambda d: d["components"]["parameters"]["IdempotencyKey"]["schema"].update(maxLength=16),
        f"{POST_SANDBOXES}: header parameter `Idempotency-Key`: `maxLength` was lowered from 255 to 16",
    ),
    (
        "a request body",
        lambda d: create(d).pop("requestBody"),
        f"{POST_SANDBOXES}: a request body of `application/json` is no longer accepted",
    ),
    (
        "a request member",
        lambda d: schema(d, "SandboxSpec")["properties"].pop("start"),
        "REST: request schema SandboxSpec: member `start` was removed",
    ),
    (
        "a request member made required",
        lambda d: schema(d, "SandboxSpec")["required"].append("name"),
        "REST: request schema SandboxSpec: member `name` is newly required",
    ),
    (
        "a new required request member",
        _add_required_member,
        "REST: request schema SandboxSpec: member `region` is newly required",
    ),
    (
        "a shorter string",
        lambda d: member(d, "SandboxSpec", "image").update(maxLength=64),
        "REST: request schema SandboxSpec.image: `maxLength` was lowered from 128 to 64",
    ),
    (
        "a higher minimum",
        lambda d: member(d, "SandboxSpec", "lifetime_seconds")["anyOf"][0].update(minimum=60),
        "REST: request schema SandboxSpec.lifetime_seconds: `minimum` was raised from 1 to 60",
    ),
    (
        "a bound where there was none",
        lambda d: member(d, "ExecSpec", "argv")["items"].update(maxLength=1024),
        "REST: request schema ExecSpec.argv[]: `maxLength` 1024 was added",
    ),
    (
        "a bound in a schema that others refer to",
        lambda d: member(d, "Resources", "vcpus").update(maximum=64),
        "REST: request schema Resources.vcpus: `maximum` was lowered from 255 to 64",
    ),
    (
        "a request that no longer takes null",
        _never_null,
        "REST: request schema SandboxSpec.lifetime_seconds: null is no longer accepted",
    ),
    (
        "a pattern that changed",
        lambda d: member(d, "SandboxSpec", "name")["anyOf"][0].update(pattern="^[a-z]{1,8}$"),
        "REST: request schema SandboxSpec.name: the pattern changed",
    ),
    (
        "a pattern where there was none",
        lambda d: member(d, "SandboxSpec", "image").update(pattern="^[a-z]+$"),
        "REST: request schema SandboxSpec.image: a pattern was added",
    ),
    (
        "a default with another meaning",
        lambda d: member(d, "SandboxSpec", "start").update(default=True),
        "REST: request schema SandboxSpec.start: the default changed from false to true",
    ),
    (
        "an alternative of a request",
        _one_network_only,
        "REST: request schema SandboxSpec.network: NetworkAllowlist is no longer accepted",
    ),
    (
        "a literal alternative of a request",
        _integer_generation_only,
        'REST: request schema ExecSpec.expected_generation: the constant "current" is no longer accepted',
    ),
    (
        "a request member of another type",
        lambda d: member(d, "SandboxSpec", "start").update(type="string", default=False),
        "REST: request schema SandboxSpec.start: the type changed from boolean to string",
    ),
    (
        "names of members that are no longer taken",
        lambda d: member(d, "ExecSpec", "env").update(patternProperties={"^[A-Z]+$": {"type": "string"}}),
        "REST: request schema ExecSpec.env: members named like `^[A-Za-z_][A-Za-z0-9_]{0,254}$` are no longer accepted",
    ),
    (
        "an answer member",
        lambda d: schema(d, "Sandbox")["properties"].pop("name"),
        "REST: answer schema Sandbox: member `name` was removed",
    ),
    (
        "an answer member that may be absent",
        lambda d: schema(d, "Sandbox")["required"].remove("state"),
        "REST: answer schema Sandbox: member `state` may now be absent",
    ),
    (
        "an answer member of another type",
        lambda d: member(d, "Sandbox", "generation").update(type="string"),
        "REST: answer schema Sandbox.generation: the type changed from integer to string",
    ),
    (
        "an integer that may now be any number",
        lambda d: member(d, "Sandbox", "generation").update(type="number"),
        "REST: answer schema Sandbox.generation: the type changed from integer to number",
    ),
    ("an answer member that may be null", _may_be_null, "REST: answer schema Sandbox.state: may now be null"),
    (
        "a success status",
        lambda d: create(d)["responses"].pop("202"),
        f"{POST_SANDBOXES}: the answer `202` was removed",
    ),
    (
        "a header of an answer",
        lambda d: create(d)["responses"]["202"]["headers"].pop("Location"),
        f"{POST_SANDBOXES}: answer 202: the header `Location` was removed",
    ),
    (
        "a header of a shared answer",
        lambda d: d["components"]["responses"]["Problem401"]["headers"].pop("WWW-Authenticate"),
        "REST: answer Problem401: the header `WWW-Authenticate` was removed",
    ),
    (
        "the media type of an answer",
        lambda d: d["components"]["responses"]["Problem400"].update(content={"application/json": {"schema": {}}}),
        "REST: answer Problem400: is no longer given as `application/problem+json`",
    ),
    (
        "a route that needs a credential now",
        lambda d: d["paths"]["/v1/info"]["get"].update(security=[{"bearer": []}]),
        "REST: GET /v1/info: can no longer be called without a credential",
    ),
    (
        "a credential scheme",
        lambda d: create(d).update(security=[{"oauth": []}]),
        f"{POST_SANDBOXES}: can no longer be called with `bearer`",
    ),
]


@pytest.mark.parametrize(
    ("change", "finding"), [(c, f) for _, c, f in REST_BREAKS], ids=[name for name, _, _ in REST_BREAKS]
)
def test_what_takes_something_from_a_caller_of_the_rest_surface_is_found(change: Change, finding: str) -> None:
    assert finding in rest(change)


@pytest.mark.parametrize(
    ("change", "finding"),
    [(c, f) for name, c, f in REST_BREAKS if "shared" not in name and "others refer" not in name],
    ids=[name for name, _, _ in REST_BREAKS if "shared" not in name and "others refer" not in name],
)
def test_one_change_is_one_finding(change: Change, finding: str) -> None:
    """A change is reported where it is, once: not once for every route that leads to it."""
    assert rest(change) == [finding]


def test_a_schema_many_routes_use_is_reported_once_and_a_shared_parameter_for_each_route() -> None:
    assert rest(lambda d: member(d, "Resources", "vcpus").update(maximum=64)) == [
        "REST: request schema Resources.vcpus: `maximum` was lowered from 255 to 64"
    ]
    per_route = rest(lambda d: d["components"]["parameters"]["IdempotencyKey"]["schema"].update(maxLength=16))
    carrying = [
        f"{method.upper()} {path}"
        for path, item in _REST["paths"].items()
        for method, operation in item.items()
        if {"$ref": "#/components/parameters/IdempotencyKey"} in operation["parameters"]
    ]
    assert len(carrying) > 5
    assert per_route == [
        f"REST: {route}: header parameter `Idempotency-Key`: `maxLength` was lowered from 255 to 16"
        for route in carrying
    ]


# ------------------------------------------------------------------------- REST: what does not break
def _new_route(d: dict[str, Any]) -> None:
    d["paths"]["/v1/projects/{project}/volumes"] = {"get": copy.deepcopy(d["paths"][SANDBOXES]["get"])}


def _new_optional_parameter(d: dict[str, Any]) -> None:
    create(d)["parameters"].append({"name": "dry_run", "in": "query", "required": False, "schema": {"type": "boolean"}})


def _new_alternative(d: dict[str, Any]) -> None:
    d["components"]["schemas"]["NetworkOpen"] = {
        "type": "object",
        "properties": {"mode": {"const": "open", "type": "string"}},
    }
    member(d, "SandboxSpec", "network")["oneOf"].append({"$ref": "#/components/schemas/NetworkOpen"})


def _new_answer_member(d: dict[str, Any]) -> None:
    schema(d, "Sandbox")["properties"]["region"] = {"type": "string"}
    schema(d, "Sandbox")["required"].append("region")


def _renamed_schema(d: dict[str, Any]) -> None:
    """The name of a schema is not on the wire. Its shape is."""
    text = json.dumps(d).replace('#/components/schemas/Resources"', '#/components/schemas/Capacity"')
    renamed = json.loads(text)
    renamed["components"]["schemas"]["Capacity"] = renamed["components"]["schemas"].pop("Resources")
    d.clear()
    d.update(renamed)


def _never_null_answer(d: dict[str, Any]) -> None:
    schema(d, "Sandbox")["properties"]["name"] = {"type": "string", "title": "Name"}


def _null_accepted(d: dict[str, Any]) -> None:
    schema(d, "SandboxSpec")["properties"]["image"] = {"anyOf": [member(d, "SandboxSpec", "image"), {"type": "null"}]}


REST_KEEPS: list[tuple[str, Change]] = [
    ("a new route", _new_route),
    ("a new optional parameter", _new_optional_parameter),
    (
        "a new optional request member",
        lambda d: schema(d, "SandboxSpec")["properties"].update(region={"type": "string"}),
    ),
    ("a longer string", lambda d: member(d, "SandboxSpec", "image").update(maxLength=256)),
    ("a lower minimum and a higher maximum", lambda d: parameter(d, "wait")["schema"].update(maximum=7200)),
    ("a bound that is gone", lambda d: member(d, "SandboxSpec", "image").pop("maxLength")),
    ("a pattern that is gone", lambda d: member(d, "SandboxSpec", "name")["anyOf"][0].pop("pattern")),
    ("a request that takes any number", lambda d: member(d, "Resources", "vcpus").update(type="number")),
    ("a request that takes null as well", _null_accepted),
    ("a new alternative of a request", _new_alternative),
    ("a request member that is no longer required", lambda d: schema(d, "SandboxSpec")["required"].remove("image")),
    ("a new answer member", _new_answer_member),
    ("an answer member that is never null any more", _never_null_answer),
    ("an error status that is no longer listed", lambda d: create(d)["responses"].pop("410")),
    (
        "a new header of an answer",
        lambda d: create(d)["responses"]["200"]["headers"].update({"X-New": {"schema": {"type": "string"}}}),
    ),
    ("other words", lambda d: member(d, "SandboxSpec", "image").update(description="Other words.", title="Other")),
    ("a schema nobody refers to", lambda d: d["components"]["schemas"].update(Unused={"type": "object"})),
    ("another name for a schema", _renamed_schema),
    ("a route that no longer needs a credential", lambda d: create(d).update(security=[{}, {"bearer": []}])),
    ("another minor version", lambda d: d["info"].update(version="1.4.0")),
]


@pytest.mark.parametrize("change", [c for _, c in REST_KEEPS], ids=[name for name, _ in REST_KEEPS])
def test_what_only_adds_or_loosens_is_compatible(change: Change) -> None:
    assert rest(change) == []


# ------------------------------------------------------------------------------- the two directions
def _both_ways(grant: dict[str, Any]) -> dict[str, Any]:
    """A description in which one schema is sent and received."""
    reference = {"$ref": "#/components/schemas/Grant"}
    return {
        "openapi": "3.2.0",
        "info": {"title": "t", "version": "1.0.0"},
        "paths": {
            "/grants": {
                "put": {
                    "requestBody": {"required": True, "content": {"application/json": {"schema": reference}}},
                    "responses": {
                        "200": {"description": "the grant", "content": {"application/json": {"schema": reference}}}
                    },
                }
            }
        },
        "components": {"schemas": {"Grant": grant}},
    }


GRANT: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "methods": {"type": "array", "items": {"type": "string"}},
        "level": {"type": "integer", "enum": [1, 2]},
    },
    "required": ["methods"],
}


def test_a_schema_that_travels_both_ways_is_held_to_both_rules() -> None:
    def changed(change: Change) -> list[str]:
        grant = copy.deepcopy(GRANT)
        change(grant)
        return compat.breaking_changes(_both_ways(GRANT), _both_ways(grant))

    assert changed(lambda g: g["properties"].pop("level")) == [
        "REST: request schema Grant: member `level` was removed",
        "REST: answer schema Grant: member `level` was removed",
    ]
    # Newly required: a caller who left it out is refused. Nothing changes for one who reads it.
    assert changed(lambda g: g["required"].append("level")) == [
        "REST: request schema Grant: member `level` is newly required"
    ]
    # No longer required: nothing changes for a caller who sends it. One who reads it can no longer count on it.
    assert changed(lambda g: g["required"].remove("methods")) == [
        "REST: answer schema Grant: member `methods` may now be absent"
    ]
    # One value less: a request with it is refused. One value more: a reader treats what it does not know as unknown.
    assert changed(lambda g: g["properties"]["level"].update(enum=[1])) == [
        "REST: request schema Grant.level: 2 is no longer accepted"
    ]
    assert changed(lambda g: g["properties"]["level"].update(enum=[1, 2, 3])) == []


# ------------------------------------------------------------------------------ the other keywords
def _one(old: dict[str, Any], new: dict[str, Any], direction: compat.Direction) -> list[str]:
    walk = compat._Comparison({}, {}, subject="s", request="sent", answer="received")
    walk.schema(old, new, direction, "x")
    return walk.findings


REQUEST, ANSWER = compat.Direction.REQUEST, compat.Direction.ANSWER
OBJECT: dict[str, Any] = {"type": "object", "properties": {"a": {"type": "string"}}}


@pytest.mark.parametrize(
    ("old", "new", "direction", "finding"),
    [
        (
            OBJECT,
            {**OBJECT, "additionalProperties": False},
            REQUEST,
            "members the schema does not name are no longer accepted as they were",
        ),
        (
            {**OBJECT, "additionalProperties": {"type": "string"}},
            {**OBJECT, "additionalProperties": False},
            REQUEST,
            "members the schema does not name are no longer accepted as they were",
        ),
        ({"type": "string"}, {"type": "string", "enum": ["a", "b"]}, REQUEST, 'only "a", "b" are accepted now'),
        (
            {"type": "string", "enum": ["a", "b", "c"]},
            {"type": "string", "enum": ["a"]},
            REQUEST,
            '"b", "c" are no longer accepted',
        ),
        ({"const": "a"}, {"enum": ["b", "c"]}, REQUEST, '"a" is no longer accepted'),
        ({"type": "string"}, {"type": "string", "const": "a"}, REQUEST, 'only "a" is accepted now'),
        ({"const": "a"}, {"const": "b"}, REQUEST, 'the constant changed from "a" to "b"'),
        ({"const": "a"}, {"const": "b"}, ANSWER, 'the constant changed from "a" to "b"'),
        ({"type": "string", "const": "a"}, {"type": "string"}, ANSWER, 'is no longer always "a"'),
        (
            {"type": "string", "format": "date-time"},
            {"type": "string", "format": "date"},
            ANSWER,
            "the format changed from `date-time` to `date`",
        ),
        ({"type": ["string", "null"]}, {"type": "string"}, REQUEST, "null is no longer accepted"),
        ({"type": "string"}, {"type": ["string", "null"]}, ANSWER, "may now be null"),
        ({"type": "null"}, {"type": ["string", "null"]}, ANSWER, "may now be string"),
        ({}, {"type": "string"}, REQUEST, "the type changed from any type to string"),
        ({"type": "string"}, {}, ANSWER, "the type changed from string to any type"),
        ({"type": "number"}, {"type": "integer"}, REQUEST, "the type changed from number to integer"),
        (
            {"type": "array", "items": {"type": "string"}},
            {"type": "array"},
            ANSWER,
            "its items are no longer described",
        ),
        ({"type": "array"}, {"type": "array", "uniqueItems": True}, REQUEST, "its items must now be unique"),
        ({"type": "integer"}, {"type": "integer", "multipleOf": 4}, REQUEST, "`multipleOf` was added"),
        ({"type": "integer", "multipleOf": 2}, {"type": "integer", "multipleOf": 4}, REQUEST, "`multipleOf` changed"),
        ({"type": "integer", "default": 1}, {"type": "integer"}, REQUEST, "the default changed from 1 to none"),
        (
            {"anyOf": [{"type": "string"}, {"type": "integer"}]},
            {"type": "string"},
            REQUEST,
            "integer is no longer accepted",
        ),
        ({"type": "string"}, {"anyOf": [{"type": "string"}, {"type": "integer"}]}, ANSWER, "may now be integer"),
    ],
)
def test_each_keyword_is_held_to_the_rule_of_its_direction(
    old: dict[str, Any], new: dict[str, Any], direction: compat.Direction, finding: str
) -> None:
    assert _one(old, new, direction) == [f"s: x: {finding}"]


@pytest.mark.parametrize(
    ("old", "new", "direction"),
    [
        ({**OBJECT, "additionalProperties": False}, OBJECT, REQUEST),
        ({**OBJECT, "additionalProperties": {"type": "string"}}, OBJECT, REQUEST),
        ({"type": "string", "enum": ["a"]}, {"type": "string", "enum": ["a", "b"]}, REQUEST),
        ({"type": "string", "enum": ["a"]}, {"type": "string"}, REQUEST),
        ({"type": "string", "enum": ["a", "b"]}, {"type": "string", "enum": ["a"]}, ANSWER),
        ({"type": "string", "enum": ["a"]}, {"type": "string", "enum": ["a", "b"]}, ANSWER),
        ({"type": "string", "const": "a"}, {"type": "string"}, REQUEST),
        ({"type": "string"}, {"type": ["string", "null"]}, REQUEST),
        ({"type": ["string", "null"]}, {"type": "string"}, ANSWER),
        ({"type": "integer"}, {"type": "number"}, REQUEST),
        ({"type": "number"}, {"type": "integer"}, ANSWER),
        ({"type": "string"}, {}, REQUEST),
        ({}, {"type": "string"}, ANSWER),
        ({"type": "integer", "minimum": 1, "maximum": 5}, {"type": "integer", "minimum": 5, "maximum": 5}, ANSWER),
        ({"type": "array", "uniqueItems": True}, {"type": "array"}, REQUEST),
        ({"anyOf": [{"type": "string"}, {"type": "integer"}]}, {"type": "string"}, ANSWER),
        ({"type": "string"}, {"anyOf": [{"type": "string"}, {"type": "integer"}]}, REQUEST),
        ({"type": "integer"}, {"type": "integer", "default": 1}, REQUEST),
    ],
)
def test_the_same_change_in_the_other_direction_is_compatible(
    old: dict[str, Any], new: dict[str, Any], direction: compat.Direction
) -> None:
    assert _one(old, new, direction) == []


def test_members_a_schema_admits_without_naming_them_are_compared_as_members() -> None:
    def named_freely(of: str) -> dict[str, Any]:
        return {**OBJECT, "additionalProperties": {"type": of}}

    def named_by_pattern(of: str) -> dict[str, Any]:
        return {"type": "object", "patternProperties": {"^[a-z]+$": {"type": of}}, "additionalProperties": False}

    for shape in (named_freely, named_by_pattern):
        assert _one(shape("string"), shape("integer"), REQUEST) == ["s: x.*: the type changed from string to integer"]
        assert _one(shape("number"), shape("integer"), ANSWER) == []
    # In an answer, names that are no longer used take nothing from a reader.
    assert _one(named_by_pattern("string"), {"type": "object", "additionalProperties": False}, ANSWER) == []


def test_a_schema_that_refers_to_itself_is_compared_once_and_the_comparison_ends() -> None:
    def tree(extra: dict[str, Any]) -> dict[str, Any]:
        node = {
            "type": "object",
            "properties": {"children": {"type": "array", "items": {"$ref": "#/$defs/Node"}}, **extra},
        }
        return {"$defs": {"Node": node}, "$ref": "#/$defs/Node"}

    old, new = tree({"label": {"type": "string"}}), tree({})
    walk = compat._Comparison(old, new, subject="s", request="sent", answer="received")
    walk.schema(old, new, ANSWER, "x")
    assert walk.findings == ["s: received Node: member `label` was removed"]


@pytest.mark.parametrize(
    ("reference", "why"),
    [("#/$defs/Missing", "points at nothing"), ("other.json#/a", "leaves the document"), ("#/$defs/Loop", "never end")],
)
def test_a_reference_that_cannot_be_followed_is_an_error_and_not_a_clean_result(reference: str, why: str) -> None:
    document = {"$defs": {"Loop": {"$ref": "#/$defs/Loop"}}}
    walk = compat._Comparison(document, document, subject="s", request="sent", answer="received")
    with pytest.raises(compat.NotComparable, match=why):
        walk.schema({"$ref": reference}, {"$ref": reference}, REQUEST, "x")


# -------------------------------------------------------------------------------------------- tools
def _defs(d: dict[str, Any], tool: str, part: str, name: str) -> dict[str, Any]:
    found: dict[str, Any] = d[tool][part]["$defs"][name]
    return found


TOOL_BREAKS: list[tuple[str, Change, str]] = [
    ("a tool", lambda t: t.pop("sandbox_create"), "tool sandbox_create: the tool was removed"),
    (
        "an input made required",
        lambda t: t["sandbox_create"]["inputSchema"]["required"].append("lifetime_seconds"),
        "tool sandbox_create: input: member `lifetime_seconds` is newly required",
    ),
    (
        "an input",
        lambda t: t["sandbox_create"]["inputSchema"]["properties"].pop("network"),
        "tool sandbox_create: input: member `network` was removed",
    ),
    (
        "an input with less room",
        lambda t: _defs(t, "sandbox_create", "inputSchema", "Resources")["properties"]["vcpus"].update(maximum=8),
        "tool sandbox_create: input schema Resources.vcpus: `maximum` was lowered from 255 to 8",
    ),
    (
        "an input with another pattern",
        lambda t: t["sandbox_create"]["inputSchema"]["properties"]["name"].update(pattern="^[a-z]+$"),
        "tool sandbox_create: input.name: the pattern changed",
    ),
    (
        "an output",
        lambda t: t["sandbox_create"]["outputSchema"]["properties"].pop("sandbox"),
        "tool sandbox_create: output: member `sandbox` was removed",
    ),
    (
        "a member of an output",
        lambda t: _defs(t, "sandbox_create", "outputSchema", "Sandbox")["properties"].pop("state"),
        "tool sandbox_create: output schema Sandbox: member `state` was removed",
    ),
    (
        "an output that is always there no more",
        lambda t: t["sandbox_create"]["outputSchema"]["required"].remove("ok"),
        "tool sandbox_create: output: member `ok` may now be absent",
    ),
    (
        "the description of an output",
        lambda t: t["sandbox_create"].pop("outputSchema"),
        "tool sandbox_create: its output is no longer described",
    ),
    (
        "a tool that reads no more",
        lambda t: t["sandbox_list"]["annotations"].update(readOnlyHint=False),
        "tool sandbox_list: no longer promises to change nothing",
    ),
    (
        "a tool that may destroy now",
        lambda t: t["sandbox_create"]["annotations"].update(destructiveHint=True),
        "tool sandbox_create: no longer promises to destroy nothing",
    ),
    (
        "a tool that may not be repeated now",
        lambda t: t["sandbox_destroy"]["annotations"].pop("idempotentHint"),
        "tool sandbox_destroy: no longer promises that a repeated call changes nothing more",
    ),
    (
        "a tool that may reach outside now",
        lambda t: t["sandbox_list"]["annotations"].update(openWorldHint=True),
        "tool sandbox_list: no longer promises to stay inside the platform",
    ),
]


@pytest.mark.parametrize(
    ("change", "finding"), [(c, f) for _, c, f in TOOL_BREAKS], ids=[name for name, _, _ in TOOL_BREAKS]
)
def test_what_takes_something_from_an_agent_host_is_found(change: Change, finding: str) -> None:
    assert tools(change) == [finding]


def _new_tool(t: dict[str, Any]) -> None:
    t["volume_list"] = copy.deepcopy(t["sandbox_list"])


TOOL_KEEPS: list[tuple[str, Change]] = [
    ("a new tool", _new_tool),
    (
        "a new optional input",
        lambda t: t["sandbox_create"]["inputSchema"]["properties"].update(region={"type": "string"}),
    ),
    ("a new output", lambda t: t["sandbox_create"]["outputSchema"]["properties"].update(region={"type": "string"})),
    ("an input that is no longer required", lambda t: t["sandbox_create"]["inputSchema"]["required"].remove("name")),
    ("a stronger promise", lambda t: t["sandbox_create"]["annotations"].update(idempotentHint=True)),
    ("other words", lambda t: t["sandbox_create"].update(description="Other words.", title="Other")),
]


@pytest.mark.parametrize("change", [c for _, c in TOOL_KEEPS], ids=[name for name, _ in TOOL_KEEPS])
def test_what_only_adds_to_a_tool_is_compatible(change: Change) -> None:
    assert tools(change) == []


# ----------------------------------------------------------------------------------------- problems
def test_a_code_is_never_removed_and_keeps_its_problem_type_and_its_kind() -> None:
    def changed(change: Change) -> list[str]:
        registry = copy.deepcopy(_PROBLEMS)
        change(registry)
        return compat.breaking_problem_changes(_PROBLEMS, registry)

    first = _PROBLEMS["codes"][0]
    code, kind = first["code"], first["kind"]
    other = "UNRESOLVED" if kind == "REFUSED" else "REFUSED"
    assert changed(lambda r: r["codes"].pop(0)) == [f"problems: the code `{code}` was removed"]
    assert changed(lambda r: r["codes"][0].update(type="urn:other")) == [
        f"problems: the problem type of `{code}` changed from `{first['type']}` to `urn:other`"
    ]
    assert changed(lambda r: r["codes"][0].update(kind=other)) == [
        f"problems: the kind of `{code}` changed from `{kind}` to `{other}`"
    ]
    # A new code, and other words for an old one, take nothing from a client: it decides by kind and retry.
    assert (
        changed(lambda r: r["codes"].append({"code": "NEW_CODE", "type": "urn:acf:problem:new", "kind": "REFUSED"}))
        == []
    )
    assert changed(lambda r: r["codes"][0].update(title="Other words")) == []


# -------------------------------------------------------------------------------- versions and files
def _tree(tmp_path: Path, name: str = "baseline") -> Path:
    """A copy of the checked-in artifacts that a test may change."""
    return Path(shutil.copytree(PROTOCOLS, tmp_path / name))


def _rewrite(path: Path, change: Change) -> None:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    change(document)
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")


def test_the_checked_in_artifacts_are_compatible_with_what_the_code_generates(
    capsys: pytest.CaptureFixture[str],
) -> None:
    files = generate.build_all()
    report = compat.compare(compat.read_tree(PROTOCOLS), files)
    assert report.findings == ()
    assert (report.baseline_version, report.candidate_version, report.new_major) == ("1.0.0", "1.0.0", False)
    assert cli.main(["compat", "--baseline", str(PROTOCOLS)]) == 0
    assert capsys.readouterr().out == "1.0.0 against 1.0.0: compatible\n"


def test_a_candidate_that_lost_something_fails_and_every_part_of_the_contract_is_read(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The baseline has a route, a tool and a code that the code does not generate: three findings, status 1."""
    baseline = _tree(tmp_path)
    _rewrite(baseline / compat.OPENAPI, _new_route)
    shutil.copy(baseline / "mcp/tools/sandbox_list.json", baseline / "mcp/tools/volume_list.json")
    _rewrite(
        baseline / compat.PROBLEMS,
        lambda r: r["codes"].append({"code": "GONE", "type": "urn:acf:problem:gone", "kind": "REFUSED"}),
    )

    assert compat.run(baseline) == 1
    said = capsys.readouterr()
    assert said.out == ""
    assert said.err.splitlines() == [
        "1.0.0 against 1.0.0: 3 changes would break a caller of 1.0.0:",
        "  REST: GET /v1/projects/{project}/volumes: the route was removed",
        "  tool volume_list: the tool was removed",
        "  problems: the code `GONE` was removed",
        "within a major version nothing is removed, retyped or made newly required, and no request becomes stricter",
    ]


def test_a_new_major_version_may_break_and_says_what_it_breaks(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    baseline, candidate = _tree(tmp_path), _tree(tmp_path, "candidate")
    _rewrite(candidate / compat.OPENAPI, lambda d: (d["info"].update(version="2.0.0"), d["paths"].pop("/v1/info")))
    assert compat.run(baseline, candidate) == 0
    assert capsys.readouterr().out.splitlines() == [
        "2.0.0 against 1.0.0: a new major version, which may break. 1 breaking change:",
        "  REST: GET /v1/info: the route was removed",
    ]
    # The same loss inside the major is refused.
    _rewrite(candidate / compat.OPENAPI, lambda d: d["info"].update(version="1.9.0"))
    assert compat.run(baseline, candidate) == 1


def test_a_reviewed_finding_is_accepted_by_its_exact_text_and_must_still_occur(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    baseline, candidate = _tree(tmp_path), _tree(tmp_path, "candidate")
    _rewrite(
        candidate / compat.OPENAPI,
        lambda d: member(d, "SandboxSpec", "name")["anyOf"][0].update(pattern="^[A-Za-z0-9._-]{1,63}$"),
    )
    finding = "REST: request schema SandboxSpec.name: the pattern changed"
    accepted = tmp_path / "accepted.txt"

    accepted.write_text(f"# The new pattern accepts every name the old one did.\n\n{finding}\n", encoding="utf-8")
    assert (
        cli.main(["compat", "--baseline", str(baseline), "--candidate", str(candidate), "--accept", str(accepted)]) == 0
    )
    assert capsys.readouterr().out == "1.0.0 against 1.0.0: compatible (1 reviewed exception)\n"

    # Words that are nearly the finding accept nothing.
    accepted.write_text(finding.replace("changed", "CHANGED") + "\n", encoding="utf-8")
    assert compat.run(baseline, candidate, accepted) == 1
    said = capsys.readouterr().err
    assert f"  {finding}\n" in said
    assert "1 accepted finding did not occur; remove what is stale:" in said

    # And an exception whose reason is gone has to go.
    accepted.write_text(f"{finding}\n", encoding="utf-8")
    assert compat.run(baseline, baseline, accepted) == 1
    assert "1 accepted finding did not occur; remove what is stale:" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("damage", "why"),
    [
        (lambda root: (root / compat.OPENAPI).unlink(), "the baseline has no api/openapi.yaml"),
        (lambda root: (root / compat.OPENAPI).write_text("a: [", encoding="utf-8"), "cannot be parsed"),
        (lambda root: (root / compat.OPENAPI).write_text("- a\n", encoding="utf-8"), "is not a mapping"),
        (lambda root: (root / compat.OPENAPI).write_text("paths: {}\n", encoding="utf-8"), "states no `info.version`"),
        (lambda root: (root / "mcp/tools/sandbox_list.json").write_text("{", encoding="utf-8"), "cannot be parsed"),
        (shutil.rmtree, "the baseline has no api/openapi.yaml"),
    ],
    ids=["no description", "not YAML", "not a mapping", "no version", "a tool that is not JSON", "no directory"],
)
def test_a_baseline_that_cannot_be_read_is_an_error_of_its_own(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], damage: Callable[[Path], object], why: str
) -> None:
    """Status 2, never 0: a comparison that read nothing has not found the versions compatible."""
    baseline = _tree(tmp_path)
    damage(baseline)
    assert compat.run(baseline) == 2
    assert why in capsys.readouterr().err


def test_an_accept_file_that_cannot_be_read_is_an_error_too(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert compat.run(PROTOCOLS, None, tmp_path / "missing.txt") == 2
    assert "cannot be read" in capsys.readouterr().err
