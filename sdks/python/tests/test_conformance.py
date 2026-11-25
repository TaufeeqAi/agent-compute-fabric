"""The client conformance suite, run against both clients.

Each scenario of ``protocols/conformance/scenarios.json`` scripts what a server answers and states what a
correct client does. The runner makes the one call of the scenario and checks three things: that the
client sent exactly the scripted requests, in order, with nothing extra and nothing missing; that the
call ended the way the scenario says; and that it waited at least as long as the scenario requires, on a
virtual clock.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

import agentcompute
from agentcompute import AsyncFabric, Fabric
from support import SCENARIOS, Exchange, Harness, Script

_DOCUMENT: dict[str, Any] = json.loads(SCENARIOS.read_text(encoding="utf-8"))
_DEFAULTS: dict[str, str] = _DOCUMENT["defaults"]
_SCENARIOS: list[dict[str, Any]] = _DOCUMENT["scenarios"]

#: The exit classes of the command-line client. The SDK has no exit codes; the runner only checks that a
#: scenario names one of them, so that a new class cannot appear unnoticed.
_EXIT_CLASSES = {
    "success",
    "command_failed",
    "usage",
    "refused",
    "operation_failed",
    "outcome_unknown",
    "unreachable",
    "unresolved",
    "outcome_lost",
    "still_running",
}


def _call(harness: Harness, fabric: Fabric | AsyncFabric, name: str, args: dict[str, Any]) -> Any:
    """Make the one logical call of a scenario. The neutral call names are mapped onto this SDK's surface."""
    key = args.get("idempotency_key")
    if name == "sandbox.create":
        return harness.run(
            fabric.sandboxes.create(
                args["image"],
                cpu=args["vcpus"],
                memory=args["memory_mib"],
                disk=args["disk_mib"],
                start=args.get("start", True),
                idempotency_key=key,
            )
        )
    if name == "sandbox.get":
        return harness.run(fabric.sandboxes.get(args["sandbox"]))
    if name == "sandbox.list":
        return harness.collect(fabric.sandboxes.list())
    if name == "sandbox.exec":
        # The scenario states the sandbox and the generation, and scripts no read: the handle is made
        # without a request and the call states the generation itself.
        sandbox = fabric.sandboxes.handle(args["sandbox_id"])
        return harness.run(sandbox.exec(args["argv"], generation=args["expected_generation"], idempotency_key=key))
    pytest.fail(f"the runner does not know the call {name!r}: teach it before adding such a scenario")


def _check_result(expected: dict[str, Any], result: Any) -> None:
    if isinstance(result, list):
        assert len(result) == expected["count"]
        assert [item.sandbox_id for item in result] == expected["ids"]
        return
    for member, value in expected.items():
        assert result.raw[member] == value, member
        assert getattr(result, member) == value, member


def _check_error(expected: dict[str, Any], error: BaseException) -> None:
    assert type(error).__name__ == expected["class"]
    assert isinstance(error, getattr(agentcompute, expected["class"]))
    for member in ("code", "kind", "retry"):
        if member in expected:
            assert getattr(error, member) == expected[member], member


def test_the_suite_is_the_one_this_runner_was_written_for() -> None:
    assert _DOCUMENT["schema_version"] == 1
    assert len(_SCENARIOS) == 27
    assert len({scenario["id"] for scenario in _SCENARIOS}) == 27
    assert _DOCUMENT["following"] == {
        "wait_s": 30,
        "backoff_initial_s": 0.5,
        "backoff_max_s": 5,
        "rule": _DOCUMENT["following"]["rule"],
    }


@pytest.mark.parametrize("scenario", _SCENARIOS, ids=[scenario["id"] for scenario in _SCENARIOS])
def test_scenario(harness: Harness, scenario: dict[str, Any]) -> None:
    call, expect = scenario["call"], scenario["expect"]
    script: Script = harness.script(
        *(Exchange(exchange["request"], exchange["response"]) for exchange in scenario["exchanges"]),
        base_url=_DEFAULTS["base_url"],
        api_key=_DEFAULTS["api_key"],
        key=call["args"].get("idempotency_key"),
    )
    config = scenario.get("config", {})
    options: dict[str, Any] = {}
    if "max_retries" in config:
        options["max_retries"] = config["max_retries"]
    if "follow_max_s" in config:
        options["follow_max"] = config["follow_max_s"]
    assert set(config) <= {"max_retries", "follow_max_s"}, "a setting this runner does not know"
    fabric = harness.client(
        script, base_url=_DEFAULTS["base_url"], api_key=_DEFAULTS["api_key"], project=_DEFAULTS["project"], **options
    )

    assert expect["exit_code"] in _EXIT_CLASSES
    if expect["outcome"] == "error":
        with pytest.raises(agentcompute.FabricError) as raised:
            _call(harness, fabric, call["name"], call["args"])
        _check_error(expect["error"], raised.value)
    else:
        assert expect["outcome"] == "success"
        result = _call(harness, fabric, call["name"], call["args"])
        _check_result(expect.get("result", {}), result)
        if "replayed" in expect:
            assert result.operation.replayed is expect["replayed"]

    assert harness.clock.waited >= expect.get("min_wait_s", 0)
    # "No request unexpected, none left over."
    script.finish()
