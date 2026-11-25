"""The derivation of a host operation id from the scope of a request and its idempotency key.

Proves IDM-3 (the function, its golden vectors and the syntax of its result), IDM-11 (the project and
the principal are inputs, so one key under two of either names two requests), IPS-12 (the deployment
id is an input) and the unit half of VER-13 (the derivation is versioned, and a version changes every
id). Catalog entries: T3-IDM-01, and T3-RED-22 as far as one implementation can prove it. That one key
never yields two host operations while two derivation versions share a store is proven by the
pipeline suite.

The golden vectors below are the contract's. They are data of the wire: an implementation in another
language, or a later version of this one, reproduces them or is wrong.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import re
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from acf_api.command.surface import OPERATIONS
from acf_api.core.pipeline import derivation, mapping
from acf_api.core.pipeline.derivation import DERIVATION_VERSION, PREVIOUS_VERSIONS, derive_operation_id

REPO = Path(__file__).resolve().parents[3]

DEPLOYMENT = "dep_7Q2M9K4T1V8X3B6N"
PROJECT = "prj_4H8C2W6Y0R5J9D3F"
OTHER_PROJECT = "prj_1A7E3S9G5L2Z8U4K"
PRINCIPAL = "prn_6N0P4V8B2X7M1C5T"
KEY = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"

#: deployment_id, project_id, principal_id, step, key, operation_id: the table of IDM-3, row by row.
GOLDEN = [
    (DEPLOYMENT, PROJECT, PRINCIPAL, "sandbox.create", KEY, "op-bdb50123f5baed8b1d005319bc45625b"),
    (DEPLOYMENT, PROJECT, PRINCIPAL, "exec.run", KEY, "op-b435e5f1918542e19073a57a47ac2334"),
    (DEPLOYMENT, OTHER_PROJECT, PRINCIPAL, "sandbox.create", KEY, "op-bc172b6b317e5b3c705306ce7aaa955f"),
    (DEPLOYMENT, PROJECT, PRINCIPAL, "sandbox.create", "k", "op-382d6abfb90af55750b97c41515edc8d"),
]

#: The inputs, in the order in which the clause concatenates them.
FIELDS = ("version", "deployment_id", "project_id", "principal_id", "step", "key")
RESULT = re.compile(r"^op-[0-9a-f]{32}$")
#: The host's syntax for an operation id a caller supplies, as the contract states it.
HOST_SYNTAX = re.compile(r"^[A-Za-z0-9-]{8,64}$")

texts = st.text(max_size=40)
inputs = st.fixed_dictionaries(dict.fromkeys(FIELDS, texts))


def spelled_out(*, deployment_id: str, project_id: str, principal_id: str, step: str, key: str, version: str) -> str:
    """The function of IDM-3, written from the clause and not from the implementation."""

    def f(x: str) -> bytes:
        data = x.encode("utf-8")
        return len(data).to_bytes(4, "big") + data

    label, separator = b"acf.p3.operation-id", b"\x00"
    message = label + separator + f(version) + f(deployment_id) + f(project_id) + f(principal_id) + f(step) + f(key)
    return "op-" + hashlib.sha256(message).digest()[0:16].hex()


@pytest.mark.proves("T3-IDM-01", "T3-RED-22")
@pytest.mark.parametrize(("deployment_id", "project_id", "principal_id", "step", "key", "expected"), GOLDEN)
def test_the_golden_vectors_of_the_contract(
    deployment_id: str, project_id: str, principal_id: str, step: str, key: str, expected: str
) -> None:
    derived = derive_operation_id(
        deployment_id=deployment_id, project_id=project_id, principal_id=principal_id, step=step, key=key
    )
    assert derived == expected


@pytest.mark.proves("T3-IDM-01", "T3-RED-22")
def test_the_golden_vectors_are_of_version_one_which_is_the_current_version() -> None:
    """A vector says nothing about its version: the current one must be the one the contract fixes."""
    assert DERIVATION_VERSION == "1"
    assert DERIVATION_VERSION not in PREVIOUS_VERSIONS
    for deployment_id, project_id, principal_id, step, key, expected in GOLDEN:
        explicit = derive_operation_id(
            deployment_id=deployment_id,
            project_id=project_id,
            principal_id=principal_id,
            step=step,
            key=key,
            version="1",
        )
        assert explicit == expected


@pytest.mark.proves("T3-IDM-01")
@settings(max_examples=200)  # twice the cases of the profile: this is the property the file is for
@given(inputs)
def test_the_implementation_is_exactly_the_function_of_the_clause(values: dict[str, str]) -> None:
    assert derive_operation_id(**values) == spelled_out(**values)


@pytest.mark.proves("T3-IDM-01")
@given(inputs)
def test_the_result_is_inside_the_host_syntax_whatever_the_inputs_are(values: dict[str, str]) -> None:
    derived = derive_operation_id(**values)
    assert RESULT.fullmatch(derived)
    assert HOST_SYNTAX.fullmatch(derived)
    assert len(derived) == 35


@pytest.mark.proves("T3-IDM-01")
def test_the_result_fits_the_operation_id_of_the_host_contract() -> None:
    """The host publishes its own syntax. A derived id must be one the host accepts from a caller."""
    host_api: dict[str, Any] = json.loads(
        (REPO / "execution" / "contracts" / "host-api.json").read_text(encoding="utf-8")
    )
    schema = {"$schema": host_api["$schema"], "$defs": host_api["$defs"], "$ref": "#/$defs/OperationId"}
    validator = jsonschema.Draft202012Validator(schema)
    for _deployment, _project, _principal, _step, _key, operation_id in GOLDEN:
        validator.validate(operation_id)
    constraints = host_api["$defs"]["OperationId"]
    assert constraints.get("type") == "string"
    assert {"pattern", "minLength", "maxLength"} & set(constraints), (
        "the host contract no longer states a syntax to check against"
    )


@pytest.mark.proves("T3-IDM-01")
@given(inputs, st.sampled_from(FIELDS), texts)
def test_changing_any_one_input_changes_the_result(values: dict[str, str], field: str, replacement: str) -> None:
    if replacement == values[field]:
        replacement += "x"
    assert derive_operation_id(**{**values, field: replacement}) != derive_operation_id(**values)


@pytest.mark.proves("T3-IDM-01")
@pytest.mark.parametrize("field", FIELDS)
def test_each_input_alone_decides_the_result(field: str) -> None:
    """One named change per input, beside the property above: the same request with one thing different."""
    base = {
        "deployment_id": DEPLOYMENT,
        "project_id": PROJECT,
        "principal_id": PRINCIPAL,
        "step": "sandbox.create",
        "key": KEY,
        "version": "1",
    }
    changed = {**base, field: base[field] + "x"}
    assert derive_operation_id(**changed) != derive_operation_id(**base)


@pytest.mark.proves("T3-IDM-01")
def test_a_boundary_between_two_inputs_cannot_be_moved() -> None:
    """Length prefixes: `ab` + `c` and `a` + `bc` are two requests, not one."""
    common = {"deployment_id": DEPLOYMENT, "step": "sandbox.create", "key": KEY}
    one = derive_operation_id(project_id="ab", principal_id="c", **common)
    other = derive_operation_id(project_id="a", principal_id="bc", **common)
    assert one != other


@pytest.mark.proves("T3-IDM-01")
@given(
    st.text(min_size=1, max_size=24),
    st.data(),
    st.sampled_from(list(itertools.pairwise(FIELDS))),
    inputs,
)
def test_no_two_splits_of_one_text_over_adjacent_inputs_collide(
    text: str, data: st.DataObject, pair: tuple[str, str], values: dict[str, str]
) -> None:
    left, right = pair
    first = data.draw(st.integers(0, len(text)))
    second = data.draw(st.integers(0, len(text)).filter(lambda cut: cut != first))
    one = derive_operation_id(**{**values, left: text[:first], right: text[first:]})
    other = derive_operation_id(**{**values, left: text[:second], right: text[second:]})
    assert one != other


@pytest.mark.proves("T3-IDM-01")
def test_the_length_of_an_input_is_counted_in_bytes_of_utf8() -> None:
    """`é` is one character and two bytes. A prefix counted in characters would make the encoding ambiguous."""
    common = {"deployment_id": DEPLOYMENT, "project_id": PROJECT, "principal_id": PRINCIPAL, "step": "sandbox.create"}
    derived = derive_operation_id(key="é", **common)
    assert derived == spelled_out(key="é", version="1", **common)
    message = b"acf.p3.operation-id\x00" + b"".join(
        len(part).to_bytes(4, "big") + part
        for part in (b"1", DEPLOYMENT.encode(), PROJECT.encode(), PRINCIPAL.encode(), b"sandbox.create", b"\xc3\xa9")
    )
    assert derived == "op-" + hashlib.sha256(message).hexdigest()[:32]


@pytest.mark.proves("T3-IDM-01")
def test_inputs_that_contain_the_separator_or_the_label_stay_apart() -> None:
    common = {"deployment_id": DEPLOYMENT, "project_id": PROJECT, "principal_id": PRINCIPAL}
    seen = {
        derive_operation_id(step=step, key=key, **common)
        for step, key in [
            ("sandbox.create", "k"),
            ("sandbox.create\x00", "k"),
            ("sandbox.create", "\x00k"),
            ("sandbox.create", "k\x00"),
            ("sandbox.create", "acf.p3.operation-id\x00k"),
            ("", "sandbox.createk"),
            ("sandbox.createk", ""),
        ]
    }
    assert len(seen) == 7


@pytest.mark.proves("T3-RED-22")
@given(inputs, texts)
def test_another_version_gives_another_id(values: dict[str, str], version: str) -> None:
    """VER-13: a version is an input, so the ids of two versions never meet, and each can be read on the host."""
    if version == values["version"]:
        version += "2"
    assert derive_operation_id(**{**values, "version": version}) != derive_operation_id(**values)


@pytest.mark.proves("T3-RED-22")
def test_the_version_defaults_to_the_current_one() -> None:
    values = {
        "deployment_id": DEPLOYMENT,
        "project_id": PROJECT,
        "principal_id": PRINCIPAL,
        "step": "exec.run",
        "key": KEY,
    }
    assert derive_operation_id(**values) == derive_operation_id(**values, version=DERIVATION_VERSION)
    assert derive_operation_id(**values) != derive_operation_id(**values, version="2")


@pytest.mark.proves("T3-IDM-01")
def test_the_inputs_can_only_be_given_by_name() -> None:
    """Five strings in a row are easy to swap. A project in the place of a principal would still derive an id."""
    with pytest.raises(TypeError):
        derive_operation_id(DEPLOYMENT, PROJECT, PRINCIPAL, "sandbox.create", KEY)  # type: ignore[call-arg]


@pytest.mark.proves("T3-IDM-01")
def test_the_step_of_every_keyed_operation_is_its_host_method() -> None:
    """`step` is the host method the public operation maps to. The table of operations and the mapping table agree on it."""
    table = mapping.load_table()
    keyed = [op for op in OPERATIONS if op.keyed]
    assert keyed
    for op in keyed:
        assert op.host_method is not None, op.method
        assert table.host_method(op.method) == op.host_method, op.method
    steps = [op.host_method for op in keyed]
    assert len(set(steps)) == len(steps), "two public operations share a step, so one key would name one id for both"
    common = {"deployment_id": DEPLOYMENT, "project_id": PROJECT, "principal_id": PRINCIPAL, "key": KEY}
    assert len({derive_operation_id(step=str(step), **common) for step in steps}) == len(steps)


@pytest.mark.proves("T3-IDM-01")
def test_the_derivation_reads_nothing_but_its_arguments() -> None:
    """Deterministic: no clock, no counter and no random source. The same inputs give the same id every time."""
    values = {
        "deployment_id": DEPLOYMENT,
        "project_id": PROJECT,
        "principal_id": PRINCIPAL,
        "step": "sandbox.create",
        "key": KEY,
    }
    assert {derive_operation_id(**values) for _ in range(1000)} == {GOLDEN[0][5]}
    assert derivation.DERIVATION_VERSION == "1"
