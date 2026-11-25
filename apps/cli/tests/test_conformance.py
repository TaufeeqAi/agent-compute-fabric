"""The client conformance suite of the API, run through the commands.

Each scenario of ``protocols/conformance/scenarios.json`` scripts what a server answers and states what
a correct client does. The runner turns the one call of a scenario into the command line a person would
type, and checks three things: that exactly the scripted requests were sent, in order, with nothing
extra and nothing missing; that the command ended in the exit class the scenario names; and that it
waited at least as long as the scenario requires, on a clock that does not wait.

Every scenario is run twice, once with ``--json`` and once for a person, because the two share nothing
but the call: the first proves what a script reads, the second what a person is told.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from agentcompute_cli.outcome import ExitCode
from support import SCENARIOS, Cli, Exchange, Run

_DOCUMENT: dict[str, Any] = json.loads(SCENARIOS.read_text(encoding="utf-8"))
_DEFAULTS: dict[str, str] = _DOCUMENT["defaults"]
_SCENARIOS: list[dict[str, Any]] = _DOCUMENT["scenarios"]

#: The exit status of each exit class the suite names.
EXIT_CLASSES: dict[str, ExitCode] = {
    "success": ExitCode.OK,
    "command_failed": ExitCode.COMMAND_FAILED,
    "usage": ExitCode.USAGE,
    "refused": ExitCode.REFUSED,
    "operation_failed": ExitCode.OPERATION_FAILED,
    "outcome_unknown": ExitCode.OUTCOME_UNKNOWN,
    "unreachable": ExitCode.UNREACHABLE,
    "unresolved": ExitCode.UNRESOLVED,
    "outcome_lost": ExitCode.OUTCOME_LOST,
    "still_running": ExitCode.STILL_RUNNING,
}
#: What the SDK does without being told, and what this tool therefore does: it has no option for it.
SDK_MAX_RETRIES = 2
#: The errors whose answer is an operation, not a problem document.
OPERATION_ERRORS = {"OperationFailedError", "OutcomeUnknownError", "OperationStillRunningError", "SandboxStartError"}


def _command(call: dict[str, Any], options: list[str]) -> list[str]:
    """The command line of a scenario's call. The neutral call names are mapped onto this tool's commands."""
    name, args = call["name"], call["args"]
    if "idempotency_key" in args:
        options = [*options, "--idempotency-key", args["idempotency_key"]]
    if name == "sandbox.create":
        command = ["sandbox", "create", "--image", args["image"], "--cpu", str(args["vcpus"])]
        command += ["--memory", str(args["memory_mib"]), "--disk", str(args["disk_mib"])]
        return [*command, *([] if args.get("start", True) else ["--no-start"]), *options]
    if name == "sandbox.get":
        return ["sandbox", "inspect", args["sandbox"], *options]
    if name == "sandbox.list":
        return ["sandbox", "list", *options]
    if name == "sandbox.exec":
        # The scenario states the sandbox and the generation, and scripts no read: neither does the command.
        stated = ["--generation", str(args["expected_generation"])]
        return ["exec", "run", args["sandbox_id"], *stated, *options, "--", *args["argv"]]
    pytest.fail(f"the runner does not know the call {name!r}: teach it before adding such a scenario")


def _run(cli: Cli, scenario: dict[str, Any], options: list[str]) -> Run:
    call, config = scenario["call"], scenario.get("config", {})
    assert set(config) <= {"max_retries", "follow_max_s"}, "a setting this runner does not know"
    assert config.get("max_retries", SDK_MAX_RETRIES) == SDK_MAX_RETRIES, "the command line cannot set this"
    if "follow_max_s" in config:
        options = [*options, "--follow-max", str(config["follow_max_s"])]
    return cli.run(
        _command(call, options),
        *(Exchange(exchange["request"], exchange["response"]) for exchange in scenario["exchanges"]),
        env={
            "ACF_API_KEY": _DEFAULTS["api_key"],
            "ACF_BASE_URL": _DEFAULTS["base_url"],
            "ACF_PROJECT": _DEFAULTS["project"],
        },
        api_key=_DEFAULTS["api_key"],
        base_url=_DEFAULTS["base_url"],
        key=call["args"].get("idempotency_key"),
    )


def _check_result(expected: dict[str, Any], printed: Any) -> None:
    if isinstance(printed, list):
        assert len(printed) == expected["count"]
        assert [item["sandbox_id"] for item in printed] == expected["ids"]
        return
    for member, value in expected.items():
        assert printed[member] == value, member


def _check_error(expected: dict[str, Any], run: Run) -> None:
    """The document a failed ``--json`` command prints is the API's own answer, and says what the scenario says."""
    document = run.error_document
    if expected["class"] in OPERATION_ERRORS:
        assert document["operation_id"].startswith("op-"), "an operation that did not succeed is shown as it is"
        if "code" in expected:
            assert document["failure"]["code"] == expected["code"]
        return
    for member in ("code", "kind", "retry"):
        if member in expected:
            assert document[member] == expected[member], member


def test_the_suite_is_the_one_this_runner_was_written_for() -> None:
    assert _DOCUMENT["schema_version"] == 1
    assert len(_SCENARIOS) == 27
    assert len({scenario["id"] for scenario in _SCENARIOS}) == 27
    assert {scenario["expect"]["exit_code"] for scenario in _SCENARIOS} <= set(EXIT_CLASSES)
    assert {scenario["call"]["name"] for scenario in _SCENARIOS} <= {
        "sandbox.create",
        "sandbox.get",
        "sandbox.list",
        "sandbox.exec",
    }


def test_no_exit_class_but_success_exits_zero_and_no_two_share_a_status() -> None:
    assert [name for name, code in EXIT_CLASSES.items() if code == 0] == ["success"]
    assert len(set(EXIT_CLASSES.values())) == len(EXIT_CLASSES)


@pytest.mark.parametrize("scenario", _SCENARIOS, ids=[scenario["id"] for scenario in _SCENARIOS])
def test_scenario_as_a_script_reads_it(cli: Cli, scenario: dict[str, Any]) -> None:
    expect = scenario["expect"]
    run = _run(cli, scenario, ["--json"])

    assert run.exit_code == EXIT_CLASSES[expect["exit_code"]], run.stderr
    if expect["outcome"] == "error":
        assert run.stdout == "", "a command that failed prints no result"
        _check_error(expect["error"], run)
        assert run.stderr.splitlines()[-1].startswith("  next: "), "every failure ends with what to do next"
    else:
        _check_result(expect.get("result", {}), run.json)
        assert run.stderr == "", "a result is the one document, even when the command it ran exited with another status"
    assert cli.clock.waited >= expect.get("min_wait_s", 0)


@pytest.mark.parametrize("scenario", _SCENARIOS, ids=[scenario["id"] for scenario in _SCENARIOS])
def test_scenario_as_a_person_sees_it(cli: Cli, scenario: dict[str, Any]) -> None:
    expect = scenario["expect"]
    run = _run(cli, scenario, [])

    assert run.exit_code == EXIT_CLASSES[expect["exit_code"]], run.stderr
    if expect["outcome"] == "error":
        assert run.stdout == ""
        assert run.stderr.startswith("error: ")
        assert run.stderr.splitlines()[-1].startswith("  next: ")
        if "code" in expect["error"]:
            assert expect["error"]["code"] in run.stderr, "the code the platform gave is shown"
    if "replayed" in expect:
        assert ("replayed" in run.stderr) is expect["replayed"], "a result of earlier work is said to be one"
    assert cli.clock.waited >= expect.get("min_wait_s", 0)


def test_the_unresolved_scenario_names_the_key_to_ask_again_with(cli: Cli) -> None:
    scenario = next(s for s in _SCENARIOS if s["id"] == "cp-016-retries-exhausted-stays-unresolved")
    run = _run(cli, scenario, [])
    assert "--idempotency-key key-0001" in run.stderr
    assert "Never with another key" in run.stderr


def test_the_still_running_scenario_names_the_operation_and_the_command_that_follows_it(cli: Cli) -> None:
    scenario = next(s for s in _SCENARIOS if s["id"] == "cp-025-follow-bound-reached")
    run = _run(cli, scenario, [])
    assert "acf operation get op-cccccccccccccccccccccccccccccccc --wait 30" in run.stderr
    assert "--idempotency-key key-0100" in run.stderr
    assert "Nothing was cancelled" in run.stderr


def test_the_start_failure_scenario_says_what_became_of_the_sandbox(cli: Cli) -> None:
    scenario = next(s for s in _SCENARIOS if s["id"] == "cp-024-start-fails-and-the-sandbox-is-destroyed")
    run = _run(cli, scenario, [])
    assert "sandbox sbx-00000000000000000000000000000001 was created and could not be started" in run.stderr
    assert "The sandbox was destroyed" in run.stderr
    assert "RESOURCE_EXHAUSTED" in run.stderr
