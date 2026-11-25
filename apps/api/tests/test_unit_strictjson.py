"""Strict JSON: the one profile in which a request body is read, and the form a decoded value is hashed in.

Proves DATA-7 as far as decoding goes (a body is UTF-8 JSON; a repeated member name is refused, at
every depth) and the property IDM-4 needs from it (a decoded value has exactly one normalized form,
whatever the order of its members, its whitespace or the spelling of its characters and numbers were).
The schema half of DATA-7, a member the schema does not define and a number outside its range, is
proven where the schemas are: by the model and the REST adapter.

No catalog entry names this module alone. T3-RED-23 (a body with a repeated member name is refused)
rests on it and is proven through the REST adapter.

The rule that ties the two halves together is tested as a property: whatever ``loads`` accepts,
``canonical`` can encode, and decoding that encoding gives the same value back. A value that could be
decoded and not normalized would be a request without a fingerprint.
"""

from __future__ import annotations

import json
import math
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from acf_api.command.strictjson import MAX_DEPTH, StrictJsonError, canonical, dumps, loads, loads_object

CANARY = "CANARY_3f9a61c2"


def refused(data: bytes) -> str:
    """The message of the refusal of ``data``. A message never repeats the body."""
    with pytest.raises(StrictJsonError) as caught:
        loads(data)
    message = str(caught.value)
    assert CANARY not in message
    assert CANARY not in str(caught.value.__cause__ or "")
    return message


# ------------------------------------------------------------------------------- repeated member names
@pytest.mark.parametrize(
    "body",
    [
        b'{"a":1,"a":2}',
        b'{"a":1,"a":1}',
        b'{"a":1,"b":2,"a":3}',
        b'{"x":{"a":1,"a":2}}',
        b'[{"a":1,"a":2}]',
        b'{"x":[1,{"y":[{"a":null,"a":null}]}]}',
        b'{"a":{"b":1},"a":{"b":1}}',
        b'{"":1,"":2}',
        b'{"a":1,"\\u0061":2}',
        b'{"\\u00e9":1,"\xc3\xa9":2}',
        b'{"a":1, "a" :2}',
    ],
)
def test_a_repeated_member_name_is_refused(body: bytes) -> None:
    assert refused(body) == "a JSON object repeats a member name"


@given(
    st.lists(st.sampled_from(["object", "array", "wide"]), max_size=MAX_DEPTH - 1),
    st.text(max_size=8),
    st.sampled_from(["1", "null", '"x"', "[]", "{}"]),
)
def test_a_repeated_member_name_is_refused_at_every_depth(wrappers: list[str], name: str, value: str) -> None:
    key = json.dumps(name)
    text = "{" + key + ":" + value + "," + key + ":" + value + "}"
    for wrapper in wrappers:
        if wrapper == "object":
            text = '{"w":' + text + "}"
        elif wrapper == "array":
            text = "[" + text + "]"
        else:
            text = '{"a":0,"w":' + text + ',"z":[1,2]}'
    assert refused(text.encode("utf-8")) == "a JSON object repeats a member name"


def test_the_same_name_in_two_objects_is_not_a_repeat() -> None:
    assert loads(b'[{"a":1},{"a":2}]') == [{"a": 1}, {"a": 2}]
    assert loads(b'{"a":{"a":{"a":1}}}') == {"a": {"a": {"a": 1}}}
    # Two names that only look alike are two names: member names are compared by code point, never normalized.
    composed, decomposed = "\u00e9", "e\u0301"
    assert loads(json.dumps({composed: 1, decomposed: 2}).encode()) == {composed: 1, decomposed: 2}
    assert loads(json.dumps({composed: 1, decomposed: 2}, ensure_ascii=False).encode()) == {composed: 1, decomposed: 2}
    assert loads(b'{"a":1,"A":2}') == {"a": 1, "A": 2}


def test_the_refusal_of_a_repeat_does_not_say_which_name() -> None:
    assert CANARY not in refused(f'{{"{CANARY}":1,"{CANARY}":2}}'.encode())
    assert CANARY not in refused(f'{{"a":"{CANARY}",}}'.encode())
    assert CANARY not in refused(f'{{"a":"{CANARY}","b":NaN}}'.encode())


# ------------------------------------------------------------------------------- numbers JSON does not define
@pytest.mark.parametrize(
    "body",
    [b"NaN", b"Infinity", b"-Infinity", b'{"a":NaN}', b"[1,Infinity]", b'{"a":[{"b":-Infinity}]}', b"[NaN,NaN]"],
)
def test_nan_and_infinity_are_refused(body: bytes) -> None:
    assert "is not JSON" in refused(body)


@pytest.mark.parametrize(
    "body",
    [b"1e400", b"-1e400", b'{"a":1e309}', b"[1E999]", b'{"a":[{"b":-2.5e+308}]}', b"[123456789e400]", b"1.8e308"],
)
def test_a_number_too_large_for_a_double_is_refused(body: bytes) -> None:
    """A literal that overflows would decode to infinity: a value with no JSON form, and so with no fingerprint."""
    refused(body)


def test_the_largest_double_and_numbers_that_underflow_are_numbers() -> None:
    assert loads(b"1.7976931348623157e308") == 1.7976931348623157e308
    assert loads(b"-1.7976931348623157e308") == -1.7976931348623157e308
    assert loads(b"1e-400") == 0.0
    assert loads(b"[0, -0, 0.0, -0.0, 1.5, 1e2]") == [0, 0, 0.0, -0.0, 1.5, 100.0]


def test_an_integer_keeps_every_digit_and_an_absurd_one_is_refused() -> None:
    assert loads(b"123456789012345678901234567890") == 123456789012345678901234567890
    assert loads(b"-9007199254740993") == -9007199254740993
    assert refused(b"[" + b"9" * 5000 + b"]") == "the body is not valid JSON"


@pytest.mark.parametrize(
    "body",
    [b"01", b"+1", b".5", b"1.", b"0x10", b"1e", b"--1", b"1_000", b"\xef\xbc\x91", b"1,5"],
)
def test_numbers_in_other_notations_are_refused(body: bytes) -> None:
    refused(body)


# ------------------------------------------------------------------------------- UTF-8, and nothing else
@pytest.mark.parametrize(
    "body",
    [
        b'{"a":"\xff"}',
        b'{"a":"\xc3"}',
        b'{"a":"\xc3\x28"}',
        b'{"a":"\xe2\x82"}',
        b'{"a":"\xc0\x80"}',
        b'{"a":"\xe0\x80\xaf"}',
        b'{"a":"\xed\xa0\x80"}',
        b'{"a":"\xf4\x90\x80\x80"}',
        b'{"\xfe":1}',
        b"\x80",
        '{"a":"é"}'.encode("latin-1"),
        '{"a":1}'.encode("utf-16"),
        '{"a":1}'.encode("utf-16-le"),
        '{"a":1}'.encode("utf-16-be"),
        '{"a":1}'.encode("utf-32"),
    ],
)
def test_a_body_that_is_not_utf8_is_refused(body: bytes) -> None:
    assert refused(body) in {"the body is not valid UTF-8", "the body is not valid JSON"}
    if b"\x00" not in body:
        assert refused(body) == "the body is not valid UTF-8"


@pytest.mark.parametrize(
    "escape", ["\\ud800", "\\udbff", "\\udc00", "\\udfff", "\\ud800x", "x\\udfff", "\\ud83d\\ud83d", "\\ude00\\ud83d"]
)
def test_half_of_a_surrogate_pair_is_refused_wherever_it_stands(escape: str) -> None:
    """An escaped half pair decodes to a string that is not text: it has no UTF-8 form, and so no normalized form."""
    refused(f'"{escape}"'.encode("ascii"))
    refused(f'{{"a":"{escape}"}}'.encode("ascii"))
    refused(f'{{"{escape}":1}}'.encode("ascii"))
    refused(f'[[{{"a":["{escape}"]}}]]'.encode("ascii"))


def test_a_whole_surrogate_pair_is_one_character() -> None:
    assert loads(b'"\\ud83d\\ude00"') == "\U0001f600"
    assert loads('"\U0001f600"'.encode()) == "\U0001f600"
    assert canonical(loads(b'{"k":"\\ud83d\\ude00"}')) == '{"k":"\U0001f600"}'.encode()


def test_a_byte_order_mark_is_refused_at_the_start_and_is_a_character_elsewhere() -> None:
    assert refused(b'\xef\xbb\xbf{"a":1}') == "the body starts with a byte order mark"
    assert refused(b"\xef\xbb\xbf") == "the body starts with a byte order mark"
    assert refused(b'\xef\xbb\xbf\xef\xbb\xbf{"a":1}') == "the body starts with a byte order mark"
    assert loads(b'{"a":"\xef\xbb\xbf"}') == {"a": "\ufeff"}
    assert loads(b'{"a":"\\ufeff"}') == {"a": "\ufeff"}
    refused(b'{"a":1}\xef\xbb\xbf')


# ------------------------------------------------------------------------------- nesting
@pytest.mark.parametrize(
    ("opening", "closing"),
    [(b"[", b"]"), (b'{"a":', b"}"), (b'[{"a":', b"}]")],
    ids=["arrays", "objects", "mixed"],
)
def test_nesting_is_accepted_up_to_the_bound_and_refused_beyond_it(opening: bytes, closing: bytes) -> None:
    levels_per_unit = opening.count(b"[") + opening.count(b"{")
    at_bound = MAX_DEPTH // levels_per_unit
    innermost = b"1" if opening.endswith(b":") else b""
    loads(opening * at_bound + innermost + closing * at_bound)
    message = refused(opening * (at_bound + 1) + innermost + closing * (at_bound + 1))
    assert message == f"the JSON value nests deeper than {MAX_DEPTH} levels"
    assert MAX_DEPTH == 32


def test_a_scalar_at_the_deepest_level_is_not_a_level() -> None:
    assert loads(b"[" * 32 + b'"x"' + b"]" * 32) is not None
    assert loads(b"[" * 31 + b'{"a":1}' + b"]" * 31) is not None
    refused(b"[" * 32 + b"{}" + b"]" * 32)
    refused(b"[" * 32 + b"[]" + b"]" * 32)


@pytest.mark.parametrize(
    "body",
    [
        b"[" * 100_000 + b"]" * 100_000,
        b'{"a":' * 100_000 + b"1" + b"}" * 100_000,
        b"[" * 2_000_000,
        b'{"a":' * 1_000_000,
        b'[{"a":' * 200_000 + b"1" + b"}]" * 200_000,
        b"[" * 900 + b"]" * 900,
        b"[" * 1100 + b"]" * 1100,
    ],
    ids=[
        "arrays-100k",
        "objects-100k",
        "unclosed-arrays-2M",
        "unclosed-objects-1M",
        "mixed-200k",
        "below-the-recursion-limit",
        "at-the-recursion-limit",
    ],
)
def test_very_deep_input_is_refused_as_too_deep_and_never_as_a_crash(body: bytes) -> None:
    """Depth costs the caller bytes and must cost the platform no stack: the refusal is the ordinary one."""
    assert refused(body) == f"the JSON value nests deeper than {MAX_DEPTH} levels"


def test_a_wide_and_shallow_body_is_not_deep() -> None:
    wide = {f"k{i}": [i, str(i), {"v": i}] for i in range(20_000)}
    assert loads(json.dumps(wide).encode()) == wide


# ------------------------------------------------------------------------------- what is JSON at all
@pytest.mark.parametrize(
    "body",
    [
        b"",
        b" ",
        b"\n\t ",
        b"{",
        b"}",
        b'{"a":1,}',
        b"[1,]",
        b"{'a':1}",
        b"{a:1}",
        b'{"a":1} {"b":2}',
        b'{"a":1}x',
        b'// c\n{"a":1}',
        b'{"a":1 /* c */}',
        b'{"a":"line\nbreak"}',
        b'{"a":"tab\there"}',
        b'{"a":"\x00"}',
        b'{"a":"\\x41"}',
        b'{"a":"\\u12"}',
        b'{"a":undefined}',
        b"True",
        b"None",
        b'{"a":1}\x00',
        b"\x00",
    ],
)
def test_what_is_not_json_is_refused(body: bytes) -> None:
    assert refused(body) == "the body is not valid JSON"


def test_whitespace_around_a_value_is_insignificant() -> None:
    assert loads(b' \n\t{"a" : [ 1 , 2 ] }\r\n ') == {"a": [1, 2]}


@pytest.mark.parametrize("body", [b"[]", b"[{}]", b'"x"', b"1", b"1.5", b"null", b"true", b"false"])
def test_a_request_body_must_be_an_object(body: bytes) -> None:
    loads(body)
    with pytest.raises(StrictJsonError) as caught:
        loads_object(body)
    assert str(caught.value) == "the body must be a JSON object"


def test_an_object_body_is_decoded_from_any_bytes_like_input() -> None:
    body = b'{"a":{"b":[1,2,{"c":null}]}}'
    expected = {"a": {"b": [1, 2, {"c": None}]}}
    assert loads_object(body) == expected
    assert loads_object(bytearray(body)) == expected
    assert loads_object(memoryview(body)) == expected
    assert loads_object(b"{}") == {}
    for wrong in (b"", b'{"a":1,"a":2}', b"\xef\xbb\xbf{}", b'{"a":NaN}', b"{" * 40):
        with pytest.raises(StrictJsonError):
            loads_object(wrong)


def test_a_refusal_is_a_value_error_and_nothing_else_escapes() -> None:
    """Callers catch one exception. No decoder error of the standard library reaches them under another name."""
    assert issubclass(StrictJsonError, ValueError)
    for body in (
        b"\xff",
        b"{",
        b"[" * 5000,
        b"NaN",
        b"9" * 6000,
        b'{"a":1,"a":1}',
        b"\xef\xbb\xbf1",
        b'"\\ud800"',
        b"1e999",
    ):
        with pytest.raises(StrictJsonError):
            loads(body)


# ------------------------------------------------------------------------------- the normalized form
def _json_values() -> st.SearchStrategy[Any]:
    scalars = (
        st.none()
        | st.booleans()
        | st.integers(min_value=-(10**30), max_value=10**30)
        | st.floats(allow_nan=False, allow_infinity=False)
        | st.text(max_size=12)
    )
    return st.recursive(
        scalars,
        lambda children: st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=6), children, max_size=4),
        max_leaves=20,
    )


def _reordered(value: Any) -> Any:
    """The same value with the members of every object in the opposite order."""
    if isinstance(value, dict):
        return {key: _reordered(value[key]) for key in reversed(list(value))}
    if isinstance(value, list):
        return [_reordered(item) for item in value]
    return value


def _same(left: Any, right: Any) -> bool:
    """Equality that tells 0.0 from -0.0 and 1 from 1.0, as the normalized form does."""
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(_same(left[k], right[k]) for k in left)
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(_same(a, b) for a, b in zip(left, right, strict=True))
    if isinstance(left, float) and isinstance(right, float):
        return left == right and math.copysign(1.0, left) == math.copysign(1.0, right)
    return type(left) is type(right) and bool(left == right)


@given(_json_values())
def test_the_normalized_form_does_not_depend_on_member_order_or_whitespace(value: Any) -> None:
    spaced = json.dumps(_reordered(value), indent=3, ensure_ascii=True).encode("utf-8")
    compact = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sorted_first = json.dumps(value, sort_keys=True).encode("utf-8")
    forms = {canonical(loads(spaced)), canonical(loads(compact)), canonical(loads(sorted_first)), canonical(value)}
    assert len(forms) == 1


@given(_json_values())
def test_the_normalized_form_decodes_to_the_same_value_and_normalizing_twice_changes_nothing(value: Any) -> None:
    form = canonical(value)
    assert _same(loads(form), value)
    assert canonical(loads(form)) == form
    assert _same(loads(dumps(value)), value)
    assert canonical(loads(dumps(value))) == form


def _json_texts() -> st.SearchStrategy[str]:
    """JSON as a caller may spell it: escapes, exponents, half pairs, numbers at the edge of a double."""
    hex4 = st.integers(0, 0xFFFF).map(lambda n: f"\\u{n:04x}")
    piece = (
        st.text(alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x2FFF, exclude_characters='"\\'), max_size=4)
        | hex4
        | st.sampled_from(
            [
                '\\"',
                "\\\\",
                "\\/",
                "\\b",
                "\\f",
                "\\n",
                "\\r",
                "\\t",
                "\\ud83d\\ude00",
                "\\ud800",
                "\\udc00",
                "\U0001f600",
            ]
        )
    )
    strings = st.lists(piece, max_size=4).map(lambda parts: '"' + "".join(parts) + '"')
    numbers = st.sampled_from(
        [
            "0",
            "-0",
            "1",
            "-1",
            "1.0",
            "1.00",
            "1e0",
            "1E2",
            "1e308",
            "1e309",
            "-1e400",
            "1e-400",
            "0.1",
            "9" * 25,
            "2.5e-3",
        ]
    )
    scalars = strings | numbers | st.sampled_from(["null", "true", "false"])
    return st.recursive(
        scalars,
        lambda children: (
            st.lists(children, max_size=3).map(lambda items: "[" + ",".join(items) + "]")
            | st.lists(st.tuples(strings, children), max_size=3).map(
                lambda members: "{" + ",".join(f"{name}:{value}" for name, value in members) + "}"
            )
        ),
        max_leaves=12,
    )


@given(_json_texts())
def test_whatever_is_accepted_has_a_normalized_form(text: str) -> None:
    """The rule that makes a fingerprint possible: decoded means normalizable, and the two agree."""
    try:
        value = loads(text.encode("utf-8"))
    except StrictJsonError:
        return
    form = canonical(value)
    assert _same(loads(form), value)
    assert canonical(loads(form)) == form
    assert loads(dumps(value)) == value


def test_non_ascii_text_is_normalized_as_utf8_and_never_as_escapes() -> None:
    assert canonical({"k": "é"}) == b'{"k":"\xc3\xa9"}'
    assert canonical(loads(b'{"k":"\\u00e9"}')) == canonical(loads(b'{"k":"\xc3\xa9"}')) == b'{"k":"\xc3\xa9"}'
    assert canonical(loads(b'{"\\u4e2d\\u6587":"\\u4f8b"}')) == '{"中文":"例"}'.encode()
    assert canonical("\u2028\u2029") == '"\u2028\u2029"'.encode()
    assert canonical("a/b") == b'"a/b"'
    assert canonical('q"\\\n') == b'"q\\"\\\\\\n"'
    assert dumps({"k": "é", "a": 1}) == b'{"k":"\xc3\xa9","a":1}'


def test_text_is_never_normalized_by_meaning() -> None:
    """Composed and decomposed spellings are different strings. The platform compares, it does not interpret."""
    assert canonical("\u00e9") != canonical("e\u0301")
    assert canonical({"\u00e9": 1}) != canonical({"e\u0301": 1})
    assert canonical("A") != canonical("a")
    assert canonical(" a") != canonical("a")


def test_members_are_ordered_by_name_whatever_order_they_arrived_in() -> None:
    names = ["b", "a", "B", "", "é", "aa", "\uffff", "\U0001f600", "10", "9", "a b"]
    forward = dict.fromkeys(names, 0)
    backward = dict.fromkeys(reversed(names), 0)
    assert canonical(forward) == canonical(backward)
    assert list(loads(canonical(forward))) == sorted(names)
    assert canonical({"z": {"b": 1, "a": 2}, "y": [{"d": 1, "c": 2}]}) == b'{"y":[{"c":2,"d":1}],"z":{"a":2,"b":1}}'


def test_one_number_has_one_form_however_it_was_spelled() -> None:
    assert {canonical(loads(text)) for text in (b"1.0", b"1.00", b"1e0", b"10e-1", b"0.1E1")} == {b"1.0"}
    assert {canonical(loads(text)) for text in (b"100", b" 100 ")} == {b"100"}
    assert canonical(loads(b"1E20")) == b"1e+20"
    # An integer and a real are two values. A schema that asks for an integer refuses the real.
    assert canonical(loads(b"1")) != canonical(loads(b"1.0"))


def test_a_value_that_is_not_json_has_no_normalized_form() -> None:
    for value in (float("nan"), float("inf"), float("-inf"), {"a": float("nan")}, [1, float("inf")]):
        with pytest.raises(ValueError, match="not JSON compliant"):
            canonical(value)
        with pytest.raises(ValueError, match="not JSON compliant"):
            dumps(value)
