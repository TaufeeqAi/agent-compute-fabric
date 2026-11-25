"""Units, argument vectors, networks and keys: what a caller may write, and every refusal.

The API takes integers and exact shapes. Whatever this package accepts on top of that, it converts
without guessing, and whatever it does not accept it refuses with a ``ValueError`` before any request.
The first half of this module checks the conversions as tables. The second half checks, on both
clients, that a refusal really happens before anything is sent.
"""

from __future__ import annotations

from typing import Any

import pytest

from agentcompute import _keys
from agentcompute._resources import expected_generation
from agentcompute._units import (
    argument_vector,
    count,
    environment,
    flag,
    mebibytes,
    network_spec,
    seconds,
    shell_vector,
    text,
)
from support import CRD, EXE, OP, OP3, SBX, SNP, Harness, done, ex, execution, reply, sandbox

#: A digit of another script. `int()` reads it as 4; a quantity must be written in ASCII digits.
_ARABIC_INDIC_FOUR = chr(0x0664)
#: Characters outside 0x21 to 0x7E, written by code point so that this file stays ASCII.
_E_ACUTE = "caf" + chr(0xE9)
_ZERO_WIDTH = "k" + chr(0x200B)


# ------------------------------------------------------------------------------------------------ sizes
@pytest.mark.parametrize(
    ("value", "mib"),
    [
        (1, 1),
        (512, 512),
        (4096, 4096),
        ("512MiB", 512),
        ("1GiB", 1024),
        ("4GiB", 4096),
        ("0512MiB", 512),
        ("1TiB", 1_048_576),
        ("2048KiB", 2),
        # A fraction that is exactly a whole number of MiB says one thing only.
        ("1.5GiB", 1536),
        ("0.5GiB", 512),
        ("1.0GiB", 1024),
        ("0.25TiB", 262_144),
        ("1024.0KiB", 1),
        ("0.0009765625GiB", 1),
    ],
)
def test_a_size_is_an_integer_in_mib_or_a_string_with_a_binary_unit(value: int | str, mib: int) -> None:
    assert mebibytes(value, what="memory") == mib


@pytest.mark.parametrize(
    "value",
    [
        "4GB",  # a decimal unit: 4 000 000 000 bytes or 4 GiB?
        "4G",  # a bare letter says even less
        "4MB",
        "4M",
        "0.1GiB",  # 102.4 MiB: someone would have to round it
        "1.5MiB",
        "1.0001GiB",
        "512KiB",  # half a MiB
        "1KiB",
        "512",  # a number in a string has no unit
        "4gib",
        "4Gib",
        "4GIB",
        "4 GiB",
        " 4GiB",
        "4GiB ",
        "4PiB",
        "4B",
        "1e3MiB",
        "+4GiB",
        "-4GiB",
        "1.GiB",
        ".5GiB",
        "1,5GiB",
        "1.5.0GiB",
        "MiB",
        "",
        "0MiB",
        "0GiB",
        "0.0GiB",
        0,
        -1,
        1.5,  # a bare float
        512.0,
        True,
        None,
        b"4GiB",
        [4],
    ],
)
def test_a_size_that_could_mean_two_things_is_refused(value: object) -> None:
    with pytest.raises(ValueError, match="memory must be"):
        mebibytes(value, what="memory")


def test_digits_of_another_script_cannot_smuggle_a_size_past_the_parser() -> None:
    # int() reads these as 4; the parser must not.
    assert int(_ARABIC_INDIC_FOUR) == 4
    with pytest.raises(ValueError, match="disk must be"):
        mebibytes(_ARABIC_INDIC_FOUR + "GiB", what="disk")
    with pytest.raises(ValueError, match="disk must be"):
        mebibytes("1." + _ARABIC_INDIC_FOUR + "GiB", what="disk")


def test_the_arithmetic_is_exact_however_long_the_fraction() -> None:
    """Integers only: no binary fraction decides by rounding which sizes pass."""
    assert mebibytes("0.5" + "0" * 400 + "GiB", what="memory") == 512
    with pytest.raises(ValueError, match="memory must be"):
        mebibytes("0.5" + "0" * 400 + "1GiB", what="memory")
    assert mebibytes(str(2**70) + "GiB", what="disk") == 2**80


# -------------------------------------------------------------------------------------------- durations
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1, 1),
        (90, 90),
        ("90s", 90),
        ("10m", 600),
        ("2h", 7200),
        ("1d", 86_400),
        ("36h", 129_600),
        ("1.5m", 90),
        ("0.5h", 1800),
        ("0.25m", 15),
        ("1.0s", 1),
        ("0.5d", 43_200),
    ],
)
def test_a_duration_is_an_integer_in_seconds_or_a_string_with_a_unit(value: int | str, expected: int) -> None:
    assert seconds(value, what="timeout") == expected


@pytest.mark.parametrize(
    "value",
    [
        "90",  # which unit?
        "10 m",
        "1.5s",  # not a whole number of seconds
        "0.5s",
        "0.001h",
        "0.01m",
        "500ms",
        "10M",
        "2H",
        "1D",
        "1w",
        "1h30m",
        "1.m",
        ".5m",
        "h",
        "",
        "0s",
        "0d",
        "0.0h",
        "-5s",
        _ARABIC_INDIC_FOUR + "m",
        0,
        -5,
        1.5,
        90.0,
        True,
        None,
    ],
)
def test_a_duration_that_could_mean_two_things_is_refused(value: object) -> None:
    with pytest.raises(ValueError, match="timeout must be"):
        seconds(value, what="timeout")


@pytest.mark.parametrize("value", [1, 2, 64])
def test_a_cpu_count_is_a_positive_integer(value: int) -> None:
    assert count(value, what="cpu") == value


@pytest.mark.parametrize("value", [0, -1, 1.5, 2.0, "2", True, None])
def test_any_other_cpu_count_is_refused(value: object) -> None:
    with pytest.raises(ValueError, match="cpu must be a positive integer"):
        count(value, what="cpu")


# ---------------------------------------------------------------------------------------- text and flags
@pytest.mark.parametrize("value", ["python", "", " ", "a/b", _E_ACUTE])
def test_a_text_argument_is_passed_as_it_is(value: str) -> None:
    """Whether a name or an image is acceptable is the server's to say. Only its type is this client's."""
    assert text(value, what="name") == value


@pytest.mark.parametrize("value", [5, None, b"python", ["python"], True])
def test_a_text_argument_is_a_string(value: object) -> None:
    with pytest.raises(ValueError, match="name must be a string"):
        text(value, what="name")


def test_a_flag_is_true_or_false_and_nothing_that_merely_looks_like_one() -> None:
    assert flag(True, what="start") is True
    assert flag(False, what="start") is False
    lookalikes: list[object] = ["false", "true", 0, 1, None, []]
    for value in lookalikes:
        # "false" is truthy: read as a flag it would turn the flag on.
        with pytest.raises(ValueError, match="start must be True or False"):
            flag(value, what="start")


# ------------------------------------------------------------------------------------- argument vectors
@pytest.mark.parametrize("argv", [["python", "-V"], ("python", "-V"), ["true"], ["sh", "-c", "a b"], [""]])
def test_an_argument_vector_is_sent_as_it_is(argv: Any) -> None:
    assert argument_vector(argv) == list(argv)


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        ("python -V", "a string is never split"),  # splitting is what a shell does
        ("python", "a string is never split"),
        (b"python", "a string is never split"),
        ([], "it is empty"),
        ((), "it is empty"),
        (["python", 3], "list of strings"),
        ([b"python"], "list of strings"),
        (None, "list of strings"),
        (5, "list of strings"),
        ({"python": "-V"}, "list of strings"),
    ],
)
def test_anything_that_is_not_an_argument_vector_is_refused(argv: object, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        argument_vector(argv)


def test_a_command_line_is_accepted_only_through_the_shell_form() -> None:
    assert shell_vector("echo $HOME | wc -c") == ["/bin/sh", "-c", "echo $HOME | wc -c"]
    assert shell_vector("") == ["/bin/sh", "-c", ""]


@pytest.mark.parametrize("command", [["echo", "hi"], None, 5, b"echo hi"])
def test_the_shell_form_takes_one_string(command: object) -> None:
    with pytest.raises(ValueError, match="must be a string"):
        shell_vector(command)


@pytest.mark.parametrize("env", [{}, {"A": "1"}, {"PATH": "/bin", "EMPTY": ""}])
def test_an_environment_maps_names_to_strings(env: dict[str, str]) -> None:
    assert environment(env) == env


@pytest.mark.parametrize("env", [{"A": 1}, {1: "a"}, [("A", "1")], "A=1", None, {"A": None}])
def test_any_other_environment_is_refused(env: object) -> None:
    with pytest.raises(ValueError, match="env must map"):
        environment(env)


# ---------------------------------------------------------------------------------------------- network
def test_no_network_is_sent_as_its_mode_when_the_caller_says_it() -> None:
    assert network_spec("none") == {"mode": "none"}


def test_an_allowlist_is_sent_with_every_port_as_a_range() -> None:
    spec = network_spec(
        {
            "mode": "allowlist",
            "entries": [
                {"name": "pypi.org", "ports": [443]},
                {"network": "10.0.0.0/8", "ports": [[8000, 8100], 22, (5432, 5433)]},
            ],
        }
    )
    assert spec == {
        "mode": "allowlist",
        "entries": [
            {"name": "pypi.org", "ports": [{"from": 443, "to": 443}]},
            {
                "network": "10.0.0.0/8",
                "ports": [{"from": 8000, "to": 8100}, {"from": 22, "to": 22}, {"from": 5432, "to": 5433}],
            },
        ],
    }


def test_what_an_allowlist_may_hold_is_the_servers_to_say() -> None:
    """The shape is this client's business. Whether a name, a port or an empty list is allowed is not."""
    assert network_spec({"mode": "allowlist", "entries": []}) == {"mode": "allowlist", "entries": []}
    odd = {"mode": "allowlist", "entries": [{"name": "", "ports": []}, {"network": "anything", "ports": [0, [9, 1]]}]}
    assert network_spec(odd) == {
        "mode": "allowlist",
        "entries": [
            {"name": "", "ports": []},
            {"network": "anything", "ports": [{"from": 0, "to": 0}, {"from": 9, "to": 1}]},
        ],
    }


_ENTRY = {"name": "pypi.org", "ports": [443]}


@pytest.mark.parametrize(
    "network",
    [
        "restricted",  # not a mode of the platform, and must not be mistaken for the narrower one
        "allowlist",  # the word alone has no entries
        "open",
        "host",
        "NONE",
        "None",
        "",
        True,
        0,
        {"mode": "none"},
        {"mode": "restricted", "entries": []},
        {"mode": "allowlist"},
        {"mode": "allowlist", "entries": "pypi.org:443"},
        {"mode": "allowlist", "entries": None},
        {"mode": "allowlist", "entries": [_ENTRY], "fallback": "open"},
        {"entries": [_ENTRY]},
        ["pypi.org"],
    ],
)
def test_every_other_word_or_shape_of_network_is_refused(network: object) -> None:
    with pytest.raises(ValueError, match=r"(network must be|an allowlist has exactly|entries of an allowlist)"):
        network_spec(network)


@pytest.mark.parametrize(
    "entry",
    [
        "pypi.org:443",
        {"ports": [443]},  # no destination
        {"name": "pypi.org", "network": "10.0.0.0/8", "ports": [443]},  # two destinations
        {"name": 5, "ports": [443]},
        {"name": "pypi.org"},  # no ports
        {"name": "pypi.org", "ports": 443},
        {"name": "pypi.org", "ports": "443"},
        {"name": "pypi.org", "ports": ["443"]},
        {"name": "pypi.org", "ports": [443.0]},
        {"name": "pypi.org", "ports": [True]},
        {"name": "pypi.org", "ports": [[8000]]},
        {"name": "pypi.org", "ports": [[8000, 8100, 8200]]},
        {"name": "pypi.org", "ports": [[8000, "8100"]]},
        {"name": "pypi.org", "ports": [{"from": 443, "to": 443}]},
        {"name": "pypi.org", "ports": [443], "protocol": "udp"},  # a member that would be dropped silently
        {"suffix": "*.pypi.org", "ports": [443]},
    ],
)
def test_a_malformed_allowlist_entry_is_refused(entry: object) -> None:
    with pytest.raises(ValueError, match="network entry 0"):
        network_spec({"mode": "allowlist", "entries": [entry]})


# ------------------------------------------------------------------------------------------------- keys
@pytest.mark.parametrize("key", ["k", "key-0001", "a" * 255, "!~", "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b", "a:b/c?d=e"])
def test_a_key_is_1_to_255_visible_ascii_characters(key: str) -> None:
    assert _keys.checked(key) == key
    assert _keys.for_call(key) == key


@pytest.mark.parametrize(
    "key",
    ["", "a" * 256, "a b", " key", "key ", "tab\tkey", "line\nbreak", _E_ACUTE, "\x7f", "\x00", _ZERO_WIDTH],
)
def test_any_other_key_is_refused_and_never_repaired(key: str) -> None:
    with pytest.raises(ValueError, match="idempotency_key"):
        _keys.checked(key)


@pytest.mark.parametrize("key", [123, b"key", ["key"], 1.5, True])
def test_a_key_is_a_string(key: object) -> None:
    with pytest.raises(ValueError, match="idempotency_key must be a string"):
        _keys.checked(key)


def test_a_generated_key_is_a_random_uuid_of_version_4_and_never_the_same_twice() -> None:
    keys = {_keys.for_call(None) for _ in range(200)}
    assert len(keys) == 200
    for key in keys:
        assert len(key) == 36
        assert key[14] == "4"
        assert _keys.checked(key) == key


def test_create_leaves_room_for_the_keys_it_derives() -> None:
    longest = "k" * _keys.CREATE_KEY_MAX_LENGTH
    assert _keys.CREATE_KEY_MAX_LENGTH == 247
    assert _keys.checked(longest, limit=_keys.CREATE_KEY_MAX_LENGTH) == longest
    assert len(_keys.start_key(longest)) <= _keys.KEY_MAX_LENGTH
    assert len(_keys.destroy_key(longest)) == _keys.KEY_MAX_LENGTH
    assert _keys.start_key("key-1") == "key-1:start"
    assert _keys.destroy_key("key-1") == "key-1:destroy"
    with pytest.raises(ValueError, match="1 to 247 characters"):
        _keys.checked("k" * 248, limit=_keys.CREATE_KEY_MAX_LENGTH)


# ------------------------------------------------------------------------------------------ generations
def test_a_handle_states_the_generation_it_saw_unless_the_caller_says_otherwise() -> None:
    assert expected_generation(None, 3) == 3
    assert expected_generation(7, 3) == 7
    assert expected_generation("current", 3) == "current"


@pytest.mark.parametrize("stated", [0, -1, True, 1.5, "latest", "CURRENT", "2", ""])
def test_any_other_generation_is_refused(stated: Any) -> None:
    with pytest.raises(ValueError, match="generation must be"):
        expected_generation(stated, 3)


@pytest.mark.parametrize("observed", [None, "1", True, 1.0])
def test_a_handle_that_saw_no_generation_does_not_invent_one(observed: object) -> None:
    with pytest.raises(ValueError, match="has not seen a generation"):
        expected_generation(None, observed)


# --------------------------------------------------------------------- refused before any request is made
_CREATE: dict[str, Any] = {"cpu": 1, "memory": 512, "disk": 1024}


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"memory": "4GB"}, "memory must be"),
        ({"memory": "4G"}, "memory must be"),
        ({"memory": "0.1GiB"}, "memory must be"),
        ({"memory": 0}, "memory must be"),
        ({"memory": -512}, "memory must be"),
        ({"memory": 512.0}, "memory must be"),
        ({"disk": "10GB"}, "disk must be"),
        ({"disk": 1.5}, "disk must be"),
        ({"cpu": 0}, "cpu must be a positive integer"),
        ({"cpu": 1.5}, "cpu must be a positive integer"),
        ({"cpu": "2"}, "cpu must be a positive integer"),
        ({"lifetime": "90"}, "lifetime must be"),
        ({"lifetime": 0}, "lifetime must be"),
        ({"lifetime": 1.5}, "lifetime must be"),
        ({"lifetime": "1.5s"}, "lifetime must be"),
        ({"network": "restricted"}, "network must be"),
        ({"network": "allowlist"}, "network must be"),
        ({"network": {"mode": "allowlist", "entries": [{"name": "pypi.org", "ports": ["443"]}]}}, "a port of"),
        ({"name": 5}, "name must be a string"),
        ({"start": "false"}, "start must be True or False"),
        ({"start": 0}, "start must be True or False"),
        ({"on_start_failure": "ignore"}, "on_start_failure must be"),
        ({"idempotency_key": "has a space"}, "idempotency_key"),
        ({"idempotency_key": "k" * 248}, "1 to 247 characters"),
        ({"idempotency_key": ""}, "idempotency_key"),
        ({"follow_max": -1}, "follow_max must be"),
        ({"follow_max": float("nan")}, "follow_max must be"),
        ({"follow_max": float("inf")}, "follow_max must be"),
        ({"follow_max": "30"}, "follow_max must be"),
        ({"follow_max": True}, "follow_max must be"),
    ],
)
def test_create_refuses_a_bad_argument_before_any_request(
    harness: Harness, changes: dict[str, Any], message: str
) -> None:
    script = harness.script()
    fabric = harness.client(script)
    with pytest.raises(ValueError, match=message):
        harness.run(fabric.sandboxes.create("python", **{**_CREATE, **changes}))
    assert script.seen == []


def test_create_refuses_an_image_that_is_not_a_string_before_any_request(harness: Harness) -> None:
    script = harness.script()
    fabric = harness.client(script)
    image: Any = 3.12
    with pytest.raises(ValueError, match="image must be a string"):
        harness.run(fabric.sandboxes.create(image, **_CREATE))
    assert script.seen == []


def test_create_converts_units_and_sends_only_what_the_caller_set(harness: Harness) -> None:
    created = done("sandbox.create", "sandbox", sandbox("READY", name="builder"))
    script = harness.script(
        ex(
            "POST",
            "/sandboxes",
            reply(200, created),
            json={
                "image": "python",
                "resources": {"vcpus": 2, "memory_mib": 4096, "disk_mib": 2048},
                "network": {
                    "mode": "allowlist",
                    "entries": [
                        {"name": "pypi.org", "ports": [{"from": 443, "to": 443}]},
                        {"network": "10.0.0.0/8", "ports": [{"from": 8000, "to": 8100}]},
                    ],
                },
                "name": "builder",
                "lifetime_seconds": 7200,
            },
        )
    )
    fabric = harness.client(script)
    result = harness.run(
        fabric.sandboxes.create(
            "python",
            cpu=2,
            memory="4GiB",
            disk=2048,
            network={
                "mode": "allowlist",
                "entries": [
                    {"name": "pypi.org", "ports": [443]},
                    {"network": "10.0.0.0/8", "ports": [[8000, 8100]]},
                ],
            },
            name="builder",
            lifetime="2h",
            start=False,
        )
    )
    assert result.name == "builder"


def test_a_member_the_caller_did_not_set_is_not_sent_and_start_never_is(harness: Harness) -> None:
    bare = {"image": "python", "resources": {"vcpus": 1, "memory_mib": 512, "disk_mib": 1024}}
    created = reply(200, done("sandbox.create", "sandbox", sandbox("READY")))
    script = harness.script(
        ex("POST", "/sandboxes", created, json=bare),
        ex("POST", "/sandboxes", created, json=bare),
        # The caller said "none": that is a member the caller set, and the same request to the platform.
        ex("POST", "/sandboxes", created, json={**bare, "network": {"mode": "none"}}),
    )
    fabric = harness.client(script)
    harness.run(fabric.sandboxes.create("python", start=False, **_CREATE))
    harness.run(fabric.sandboxes.create("python", start=False, network=None, name=None, lifetime=None, **_CREATE))
    harness.run(fabric.sandboxes.create("python", start=False, network="none", **_CREATE))
    assert all("start" not in seen.json for seen in script.seen)


@pytest.mark.parametrize(
    ("argv", "message"),
    [("python -V", "a string is never split"), ([], "it is empty"), (["python", 3], "list of strings")],
)
def test_exec_refuses_what_is_not_an_argument_vector_before_any_request(
    harness: Harness, argv: Any, message: str
) -> None:
    script = harness.script()
    handle = harness.client(script).sandboxes.handle(SBX)
    with pytest.raises(ValueError, match=message):
        harness.run(handle.exec(argv, generation=1))
    assert script.seen == []


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"timeout": "10"}, "timeout must be"),
        ({"timeout": 0}, "timeout must be"),
        ({"timeout": 2.5}, "timeout must be"),
        ({"env": {"A": 1}}, "env must map"),
        ({"cwd": 5}, "cwd must be a string"),
        ({"generation": 0}, "generation must be"),
        ({"generation": "latest"}, "generation must be"),
        ({"generation": None}, "has not seen a generation"),
        ({"idempotency_key": "a b"}, "idempotency_key"),
        ({"idempotency_key": "k" * 256}, "1 to 255 characters"),
        ({"follow_max": -0.5}, "follow_max must be"),
    ],
)
def test_exec_refuses_a_bad_option_before_any_request(harness: Harness, options: dict[str, Any], message: str) -> None:
    script = harness.script()
    handle = harness.client(script).sandboxes.handle(SBX)
    with pytest.raises(ValueError, match=message):
        harness.run(handle.exec(["true"], **{"generation": 1, **options}))
    assert script.seen == []


def test_exec_sends_the_vector_and_the_options_the_caller_set(harness: Harness) -> None:
    ran = done("execution.create", "execution", execution(), operation_id=OP3)
    script = harness.script(
        ex(
            "POST",
            f"/sandboxes/{SBX}/executions",
            reply(200, ran),
            json={
                "expected_generation": 4,
                "argv": ["python", "train.py", "--epochs", "3"],
                "cwd": "/work",
                "env": {"SEED": "7"},
                "timeout_seconds": 600,
            },
        )
    )
    handle = harness.client(script).sandboxes.handle(SBX)
    result = harness.run(
        handle.exec(
            ["python", "train.py", "--epochs", "3"], cwd="/work", env={"SEED": "7"}, timeout="10m", generation=4
        )
    )
    assert result.execution_id == EXE


def test_the_shell_form_sends_the_shell_explicitly(harness: Harness) -> None:
    ran = done("execution.create", "execution", execution(), operation_id=OP3)
    script = harness.script(
        ex(
            "POST",
            f"/sandboxes/{SBX}/executions",
            reply(200, ran),
            json={"expected_generation": 1, "argv": ["/bin/sh", "-c", "ls -l | wc -l"]},
        )
    )
    handle = harness.client(script).sandboxes.handle(SBX)
    harness.run(handle.exec_shell("ls -l | wc -l", generation=1))


def test_the_shell_form_refuses_a_vector_before_any_request(harness: Harness) -> None:
    script = harness.script()
    handle = harness.client(script).sandboxes.handle(SBX)
    command: Any = ["ls", "-l"]
    with pytest.raises(ValueError, match="must be a string"):
        harness.run(handle.exec_shell(command, generation=1))
    assert script.seen == []


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"stream": "stdin"}, "stream must be"),
        ({"stream": "STDOUT"}, "stream must be"),
        ({"offset": -1}, "offset must be"),
        ({"offset": 1.5}, "offset must be"),
        ({"max_bytes": 0}, "max_bytes must be"),
        ({"max_bytes": "64"}, "max_bytes must be"),
    ],
)
def test_output_refuses_a_bad_position_before_any_request(
    harness: Harness, options: dict[str, Any], message: str
) -> None:
    script = harness.script(ex("GET", f"/executions/{EXE}", reply(200, execution())))
    fabric = harness.client(script)
    handle = harness.run(fabric.executions.get(EXE))
    position = {"stream": "stdout", **options}
    with pytest.raises(ValueError, match=message):
        harness.run(handle.output(position.pop("stream"), **position))
    assert len(script.seen) == 1


@pytest.mark.parametrize(
    "call",
    [
        lambda fabric: fabric.sandboxes.get(""),
        lambda fabric: fabric.sandboxes.get("."),
        lambda fabric: fabric.sandboxes.get(".."),  # a URL library would resolve it into another route
        lambda fabric: fabric.sandboxes.get(5),
        lambda fabric: fabric.sandboxes.handle(""),
        lambda fabric: fabric.sandboxes.handle(".."),
        lambda fabric: fabric.snapshots.get(""),
        lambda fabric: fabric.executions.get(""),
        lambda fabric: fabric.executions.get(".."),
        lambda fabric: fabric.operations.get(""),
        lambda fabric: fabric.operations.get(".."),
        lambda fabric: fabric.operations.get(OP, wait=-1),
        lambda fabric: fabric.operations.get(OP, wait=1.5),
        lambda fabric: fabric.operations.get(OP, wait="30"),
        lambda fabric: fabric.operations.wait(OP, follow_max=-1),
        lambda fabric: fabric.operations.wait("..", follow_max=1),
        lambda fabric: fabric.auth.mint_agent_credential(5, lifetime="1h"),
        lambda fabric: fabric.auth.mint_agent_credential("agent", lifetime="60"),
        lambda fabric: fabric.auth.mint_agent_credential("agent", lifetime=0),
        lambda fabric: fabric.auth.mint_agent_credential("agent", lifetime="1h", narrowing=["sandbox.create"]),
        lambda fabric: fabric.auth.mint_agent_credential("agent", lifetime="1h", narrowing={"methods": {"a set"}}),
        lambda fabric: fabric.auth.revoke_agent_credential(""),
        lambda fabric: fabric.auth.revoke_agent_credential(".."),
        lambda fabric: fabric.auth.revoke_agent_credential(CRD, contain="yes"),
        lambda fabric: fabric.auth.revoke_agent_credential(CRD, contain=1),
        lambda fabric: fabric.sandboxes.handle(SBX).restore(123, generation=1),
        lambda fabric: fabric.sandboxes.handle(SBX).restore(SNP, generation=1),
        lambda fabric: fabric.sandboxes.handle(SBX).restore("baseline", generation=1),
        lambda fabric: fabric.sandboxes.handle(SBX).snapshot(5, generation=1),
        lambda fabric: fabric.sandboxes.handle(SBX).start(),
        lambda fabric: fabric.sandboxes.handle(SBX).stop(generation=-2),
        lambda fabric: fabric.sandboxes.handle(SBX).destroy(idempotency_key="a b", generation=1),
        lambda fabric: fabric.sandboxes.handle(SBX).refresh(rebind="yes"),
    ],
)
def test_every_other_call_refuses_a_bad_argument_before_any_request(harness: Harness, call: Any) -> None:
    script = harness.script()
    fabric = harness.client(script)
    with pytest.raises(ValueError, match=r"\w"):
        harness.run(call(fabric))
    assert script.seen == []


def test_restore_takes_a_snapshot_handle_because_only_a_handle_knows_the_generation(harness: Harness) -> None:
    script = harness.script()
    handle = harness.client(script).sandboxes.handle(SBX)
    wrong: Any = {"snapshot_id": SNP, "snapshot_generation": 1}
    with pytest.raises(ValueError, match="restore takes a snapshot handle"):
        harness.run(handle.restore(wrong, generation=2, idempotency_key="key-1", follow_max=10))
    assert script.seen == []
