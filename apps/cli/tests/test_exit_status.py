"""Every exit status, each from the outcome that produces it.

Scripts and CI branch on the exit status, so each one is produced here by the answer of the platform
that it stands for, and by nothing else. Three rules are held on top of the table:

* an unknown outcome and a lost outcome never exit 0;
* every failure ends with what the person can do next, and names the idempotency key when asking again
  with it is that next step;
* a command that failed prints no result on standard output.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from agentcompute import (
    APIConnectionError,
    APITimeoutError,
    AuthenticationError,
    ConfigurationError,
    FabricError,
    IncompatibleServerError,
    NameReboundError,
    NotFoundError,
    Operation,
    OperationFailedError,
    OperationStillRunningError,
    OutcomeLostError,
    OutcomeUnknownError,
    OutcomeUnresolvedError,
    RateLimitError,
    RefusedError,
    RequestInProgressError,
    SandboxStartError,
    UnexpectedResponseError,
    UnresolvedError,
)

from agentcompute_cli import render, views
from agentcompute_cli.outcome import (
    ArgumentError,
    CliError,
    ExitCode,
    UsageError,
    condition_of,
    describe,
    exit_code_for,
)
from support import (
    CRD,
    EXE,
    OP,
    OP2,
    OP3,
    REGISTRY_ROWS,
    SBX,
    Cli,
    Exchange,
    FakeStream,
    Json,
    credential,
    done,
    ex,
    execution,
    failure,
    fault,
    interrupt,
    operation,
    page,
    problem,
    refusal,
    reply,
    sandbox,
    whoami,
)

INSPECT = ["sandbox", "inspect", SBX]
START = ["sandbox", "start", SBX, "--generation", "1", "--idempotency-key", "key-9"]
START_PATH = f"/sandboxes/{SBX}/start"
RUN = ["exec", "run", SBX, "--generation", "1", "--idempotency-key", "key-9", "--", "true"]
RUN_PATH = f"/sandboxes/{SBX}/executions"
CREATE = ["sandbox", "create", "--image", "python", "--cpu", "1", "--memory", "512", "--disk", "1024"]
CREATE += ["--idempotency-key", "key-9"]


def read(response: Json) -> Exchange:
    return ex("GET", f"/sandboxes/{SBX}", response)


def start(response: Json) -> Exchange:
    return ex("POST", START_PATH, response, headers={"idempotency-key": "key-9"})


def ended(kind: str, state: str, effect: str | None, code: str = "TIMEOUT", **extra: Any) -> Json:
    return operation(kind, state, effect=effect, failure=failure(code), operation_id=OP2, **extra)


def ends_with_a_next_step(stderr: str) -> bool:
    return stderr.splitlines()[-1].startswith("  next: ")


# ------------------------------------------------------------------------------------------- the table
def test_the_statuses_are_the_published_ones() -> None:
    assert {code.name: int(code) for code in ExitCode} == {
        "OK": 0,
        "COMMAND_FAILED": 1,
        "USAGE": 2,
        "REFUSED": 3,
        "OPERATION_FAILED": 4,
        "OUTCOME_UNKNOWN": 5,
        "UNREACHABLE": 6,
        "INCOMPATIBLE": 7,
        "UNRESOLVED": 8,
        "OUTCOME_LOST": 9,
        "STILL_RUNNING": 10,
        "INTERRUPTED": 130,
        "READER_GONE": 141,
    }


def _api_error(kind: type[RefusedError | UnresolvedError], code: str) -> FabricError:
    return kind("m", code=code, kind="REFUSED", retry="NEVER")


def _operation_error(
    kind: type[OperationFailedError | OutcomeUnknownError | OperationStillRunningError],
) -> FabricError:
    return kind("m", operation=Operation(operation()), idempotency_key="k")


@pytest.mark.parametrize(
    ("error", "status"),
    [
        (UsageError("m"), 2),
        (ArgumentError("memory must be ..."), 2),
        (CliError("m", exit_code=ExitCode.INCOMPATIBLE, next_step="n"), 7),
        (ConfigurationError("m"), 2),
        (IncompatibleServerError("m", status=404), 7),
        (UnexpectedResponseError("m"), 7),
        (APIConnectionError("m"), 6),
        (APITimeoutError("m"), 6),
        (_api_error(RefusedError, "FUTURE"), 3),
        (_api_error(NotFoundError, "NOT_FOUND"), 3),
        (_api_error(AuthenticationError, "UNAUTHENTICATED"), 3),
        (_api_error(RateLimitError, "RATE_LIMITED"), 3),
        (_api_error(UnresolvedError, "FUTURE"), 8),
        (_api_error(RequestInProgressError, "REQUEST_IN_PROGRESS"), 8),
        (_api_error(OutcomeUnresolvedError, "OUTCOME_UNRESOLVED"), 8),
        (_api_error(OutcomeLostError, "OUTCOME_LOST"), 9),
        (_operation_error(OperationFailedError), 4),
        (_operation_error(OutcomeUnknownError), 5),
        (_operation_error(OperationStillRunningError), 10),
        (KeyboardInterrupt(), 130),
        (BrokenPipeError(), 141),
    ],
    ids=lambda value: type(value).__name__ if isinstance(value, BaseException) else str(value),
)
def test_one_function_decides_the_status_of_every_error(error: BaseException, status: int) -> None:
    assert exit_code_for(error) == status


@pytest.mark.parametrize(
    ("start_error", "status"),
    [
        (_api_error(RefusedError, "RESOURCE_EXHAUSTED"), 3),
        (_operation_error(OperationFailedError), 4),
        (_operation_error(OutcomeUnknownError), 5),
    ],
)
def test_a_start_failure_exits_with_the_status_of_the_start(start_error: Any, status: int) -> None:
    for cleanup in ("destroyed", "kept", "destroy_failed"):
        error = SandboxStartError("m", sandbox_id=SBX, start_error=start_error, cleanup=cleanup)
        assert exit_code_for(error) == status


def test_an_error_of_the_sdk_this_version_has_no_rule_for_is_an_unknown_outcome_and_never_zero() -> None:
    class LaterError(FabricError):
        """An error a later SDK might raise."""

    for error in (LaterError("m"), NameReboundError("m", name="n", sandbox_id=SBX, rebound_to=SBX)):
        assert exit_code_for(error) is ExitCode.OUTCOME_UNKNOWN
        report = describe(error, key=None)
        assert report.exit_code is ExitCode.OUTCOME_UNKNOWN
        assert "Inspect the target" in report.next_step


@pytest.mark.parametrize("defect", [RuntimeError("a defect"), ValueError("a defect"), ExceptionGroup("g", [OSError()])])
def test_a_defect_is_an_unknown_outcome_and_neither_0_nor_the_1_of_a_command_that_ran(defect: Exception) -> None:
    """A ``ValueError`` too: only around a call of the SDK does it mean that an argument was refused."""
    assert exit_code_for(defect) is ExitCode.OUTCOME_UNKNOWN
    report = describe(defect, key="key-9")
    assert report.exit_code is ExitCode.OUTCOME_UNKNOWN
    assert type(defect).__name__ in report.headline
    assert "a defect of the tool, not an answer of the platform" in report.headline
    assert "a request may have been sent" in report.details[0]
    assert "Inspect the target" in report.next_step
    assert "--idempotency-key key-9" in report.next_step
    assert report.document is None


# -------------------------------------------------------------------------------------------- 0 and 1
def test_0_done(cli: Cli) -> None:
    run = cli.run(INSPECT, read(reply(200, sandbox())))
    assert run.exit_code == 0
    assert run.stderr == ""


@pytest.mark.parametrize(
    "view",
    [
        execution("EXITED", exit_code=1),
        execution("EXITED", exit_code=255),
        execution("SIGNALED", exit_code=None, signal=9),
        execution("TIMED_OUT", exit_code=None),
        execution("A_STATUS_NEVER_SEEN", exit_code=0),
        execution(None, exit_code=None),
    ],
    ids=["exit-1", "exit-255", "signal", "timed-out", "unknown-status", "nothing-reported"],
)
def test_1_the_command_ran_and_did_not_exit_with_status_0(cli: Cli, view: Json) -> None:
    run = cli.run(RUN, ex("POST", RUN_PATH, reply(200, done("execution.create", "execution", view))))
    assert run.exit_code == 1
    assert "did not exit with status 0" in run.stderr
    assert EXE in run.stderr


def test_the_command_that_exited_0_is_0(cli: Cli) -> None:
    run = cli.run(RUN, ex("POST", RUN_PATH, reply(200, done("execution.create", "execution", execution()))))
    assert (run.exit_code, run.stdout, run.stderr) == (0, "", "")


# ----------------------------------------------------------------------------------------------- 2
@pytest.mark.parametrize(
    ("args", "complaint"),
    [
        (["sandbox", "inspect"], "Missing argument"),
        (["sandbox", "inspect", SBX, "--no-such-option"], "No such option"),
        (["sandbox", "create", "--image", "python"], "Missing option"),
        (["sandbox", "start", SBX, "--generation", "latest"], "--generation takes a generation number"),
        (["sandbox", "start", SBX, "--generation", "0"], "--generation takes a generation number"),
        (["sandbox", "start", SBX, "--follow-max", "soon"], "--follow-max takes a duration"),
        (["sandbox", "start", SBX, "--follow-max", "5m", "--no-wait"], "two different things about waiting"),
        (["sandbox", "inspect", SBX, "--timeout", "-1"], "--timeout takes a duration"),
        ([*CREATE, "--no-wait"], "--no-wait issues one operation"),
        ([*CREATE, "--no-start", "--keep-on-start-failure"], "--no-start asks for none"),
        (["exec", "run", SBX], "there is nothing to run"),
        (["exec", "run", SBX, "python", "x.py"], "goes after `--`"),
        (["exec", "run", SBX, "--shell", "ls", "--", "ls"], "not both"),
        (["exec", "run", SBX, "--env", "NOVALUE", "--", "ls"], "--env takes NAME=VALUE"),
        (["exec", "run", SBX, "--env", "A=1", "--env", "A=2", "--", "ls"], "more than once"),
        (["exec", "output", EXE, "--force"], "--force only applies together with --raw"),
        (["exec", "output", EXE, "--raw", "--json"], "give one of them"),
        (["snapshot", "restore", "snp", "--into", SBX, "--name", "n"], "--into restores into one that exists"),
        (["snapshot", "restore", "snp", "--generation", "1"], "there is none"),
        (["sandbox", "list", "--profile", "has space"], "a profile name is"),
    ],
    ids=lambda value: " ".join(value[:3]) if isinstance(value, list) else None,
)
def test_2_a_command_line_that_cannot_be_used_sends_nothing(cli: Cli, args: list[str], complaint: str) -> None:
    run = cli.run(args)
    assert run.exit_code == 2
    assert complaint in run.stderr
    assert run.stdout == ""
    assert run.requests == []


@pytest.mark.parametrize(
    ("args", "complaint"),
    [
        ([*CREATE[:6], "--memory", "4GB", "--disk", "1024"], "memory must be"),
        ([*CREATE[:6], "--memory", "512", "--disk", "1.5"], "disk must be"),
        ([*CREATE, "--lifetime", "soon"], "lifetime must be"),
        ([*CREATE, "--idempotency-key", "has space"], "idempotency_key may only hold"),
        ([*CREATE, "--idempotency-key", "k" * 248], "idempotency_key must be 1 to 247"),
        (["exec", "run", SBX, "--generation", "1", "--timeout", "0", "--", "ls"], "timeout must be"),
        (["operation", "get", ".."], "must name one record"),
    ],
    ids=["decimal-unit", "bare-fraction", "lifetime", "key-with-space", "key-too-long", "zero-timeout", "dot-dot"],
)
def test_2_what_the_sdk_refuses_before_any_request_is_a_usage_error(cli: Cli, args: list[str], complaint: str) -> None:
    run = cli.run(args)
    assert run.exit_code == 2
    assert complaint in run.stderr
    assert "The request was not sent" in run.stderr
    assert ends_with_a_next_step(run.stderr)
    assert run.requests == []


def test_2_what_the_sdk_refuses_after_a_read_is_said_in_words_that_are_true(cli: Cli) -> None:
    """The sandbox was looked up by its name before the key was refused, so "nothing was sent" would be false."""
    run = cli.run(
        ["sandbox", "start", "build", "--idempotency-key", "has space"],
        ex("GET", "/sandboxes/build", reply(200, sandbox("STOPPED", name="build"))),
    )
    assert run.exit_code == 2
    assert "idempotency_key may only hold" in run.stderr
    assert "The request was not sent" in run.stderr
    assert "Nothing was sent" not in run.stderr
    assert [seen.method for seen in run.requests] == ["GET"]


# ------------------------------------------------------------------------------------------- a defect
def _broken(*_: object, **__: object) -> None:
    raise ValueError("a value this tool could not show \x1b[31m")


@pytest.mark.parametrize(
    ("args", "exchanges", "broken"),
    [
        (START, [start(reply(200, done("sandbox.start", "sandbox", sandbox("RUNNING"))))], "show_sandbox"),
        (
            ["exec", "run", SBX, "--generation", "1", "--idempotency-key", "key-9", "--json", "--", "true"],
            [ex("POST", RUN_PATH, reply(200, done("execution.create", "execution", execution())))],
            "show_execution",
        ),
        (INSPECT, [read(reply(200, sandbox()))], "show_sandbox"),
    ],
    ids=["after-a-change", "exec-run", "after-a-read"],
)
def test_a_defect_is_shown_as_one_and_exits_5_whatever_the_command(
    cli: Cli, monkeypatch: pytest.MonkeyPatch, args: list[str], exchanges: list[Exchange], broken: str
) -> None:
    """Not 2, though it is a ``ValueError``: the request was sent. Not 1, which says that a command ran."""
    monkeypatch.setattr(views, broken, _broken)
    monkeypatch.setattr(render, "write_json", _broken)
    run = cli.run(args, *exchanges, tty=True)
    assert run.exit_code == 5
    assert run.stdout == ""
    assert "Traceback (most recent call last)" in run.stderr
    assert "ValueError: a value this tool could not show \\x1b[31m" in run.stderr
    assert "\x1b" not in run.stderr
    assert "error: acf failed in a way it has no rule for (ValueError)" in run.stderr
    assert "not sent" not in run.stderr
    assert ends_with_a_next_step(run.stderr)
    assert ("--idempotency-key key-9" in run.stderr.splitlines()[-1]) is ("key-9" in args)


@pytest.mark.parametrize(
    ("env", "complaint"),
    [
        ({"ACF_API_KEY": None}, "there is no API key to use"),
        ({"ACF_BASE_URL": None}, "the address of the platform is not known"),
        ({"ACF_BASE_URL": "http://acf.example"}, "base_url must be https"),
        ({"ACF_BASE_URL": "https://user:secret@acf.example"}, "must not carry user information"),
        ({"ACF_BASE_URL": "https://acf.example/?key=1"}, "must not carry a query string"),
        ({"ACF_BASE_URL": "https://acf.example\n"}, "the address of the platform holds a space, a line break"),
        ({"ACF_BASE_URL": " https://acf.example"}, "the address of the platform holds a space, a line break"),
        ({"ACF_BASE_URL": "https://acf.example\t.secret.example"}, "or another character no URL has"),
        ({"ACF_BASE_URL": "https://acf.example/\N{ZERO WIDTH SPACE}"}, "or another character no URL has"),
        ({"ACF_PROJECT": ".."}, "project"),
    ],
    ids=[
        "no-key",
        "no-address",
        "plain-http",
        "userinfo",
        "query",
        "address-line-break",
        "address-leading-space",
        "address-tab",
        "address-hidden-character",
        "bad-project",
    ],
)
def test_2_a_configuration_that_cannot_work_sends_nothing(cli: Cli, env: dict[str, str | None], complaint: str) -> None:
    run = cli.run(INSPECT, env=env)
    assert run.exit_code == 2
    assert complaint in run.stderr
    assert ends_with_a_next_step(run.stderr)
    assert "secret" not in run.stderr, "an address that was refused is not repeated"
    assert run.requests == []


# ----------------------------------------------------------------------------------------------- 3
REFUSALS = sorted(code for code, row in REGISTRY_ROWS.items() if row["error_answer"] and row["kind"] == "REFUSED")


@pytest.mark.parametrize("code", REFUSALS)
def test_3_every_refusal_of_the_registry(cli: Cli, code: str) -> None:
    # An answer that says "later" is waited for, except when it asks for more patience than a call may spend.
    status = REGISTRY_ROWS[code]["http_status"] or 409
    run = cli.run([*INSPECT, "--json"], read(refusal(code, status=status, retry_after=600)))
    assert run.exit_code == 3
    assert run.stdout == ""
    document = run.error_document
    assert (document["code"], document["kind"]) == (code, "REFUSED")
    assert document["retry"] == REGISTRY_ROWS[code]["retry"]
    assert document["request_id"]
    assert ends_with_a_next_step(run.stderr)


def test_3_a_refusal_says_that_nothing_exists_and_what_to_do(cli: Cli) -> None:
    run = cli.run(START, start(refusal("PERMISSION_DENIED", reason="network_mode")))
    assert run.exit_code == 3
    assert run.stderr.startswith("error: refused: PERMISSION_DENIED: Permission denied\n")
    assert "nothing was created or changed" in run.stderr
    assert "Reason: network_mode." in run.stderr
    assert "acf policy inspect" in run.stderr.splitlines()[-1]


@pytest.mark.parametrize(
    ("code", "members", "advice"),
    [
        ("FUTURE_REFUSAL", {"retry": "NEVER"}, "will not be accepted as it is"),
        ("FUTURE_REFUSAL", {"retry": "AFTER_CHANGE"}, "once something changes"),
        ("FUTURE_REFUSAL", {"retry": "A_WORD_NEVER_SEEN"}, "retry advice this version does not know"),
        ("FUTURE_REFUSAL", {"kind": "A_KIND_NEVER_SEEN"}, "will not be accepted as it is"),
        ("REVISION_CONFLICT", {}, "acf sandbox inspect SANDBOX"),
        ("IDEMPOTENCY_CONFLICT", {}, "belongs to a different request"),
        ("UNAUTHENTICATED", {}, "acf auth login"),
        ("NOT_FOUND", {}, "acf sandbox list"),
    ],
)
def test_3_the_advice_follows_the_code_and_the_retry_advice_never_the_status(
    cli: Cli, code: str, members: dict[str, Any], advice: str
) -> None:
    run = cli.run(START, start(refusal(code, status=409, **members)))
    assert run.exit_code == 3
    assert advice in run.stderr.splitlines()[-1]


def test_3_a_refusal_that_says_later_names_how_long(cli: Cli) -> None:
    run = cli.run(START, start(refusal("RATE_LIMITED", retry_after=600)))
    assert run.exit_code == 3
    assert "Run the same command again, not before 600 s from now." in run.stderr


# ------------------------------------------------------------------------------------------- 4 and 5
@pytest.mark.parametrize(("state", "code"), [("FAILED", "DEPENDENCY_UNAVAILABLE"), ("CANCELLED", "TIMEOUT")])
def test_4_the_operation_ended_and_nothing_was_applied(cli: Cli, state: str, code: str) -> None:
    run = cli.run(START, start(reply(200, ended("sandbox.start", state, "NOT_APPLIED", code))))
    assert run.exit_code == 4
    assert run.stdout == ""
    assert run.stderr.startswith(f"error: failed: operation {OP2} (sandbox.start) ended {state}: {code}: it failed\n")
    assert "Nothing was applied." in run.stderr
    assert "leave --idempotency-key out" in run.stderr.splitlines()[-1]


@pytest.mark.parametrize(
    ("state", "effect"),
    [("UNKNOWN", "MAY_BE_APPLIED"), ("UNKNOWN", "NOT_APPLIED"), ("FAILED", "MAY_BE_APPLIED"),
     ("CANCELLED", "AN_EFFECT_NEVER_SEEN"), ("FAILED", None)],
)  # fmt: skip
def test_5_the_outcome_is_unknown_or_may_have_been_applied_and_is_never_0(
    cli: Cli, state: str, effect: str | None
) -> None:
    run = cli.run(START, start(reply(200, ended("sandbox.start", state, effect))))
    assert run.exit_code == 5
    assert run.stdout == ""
    assert "outcome unknown" in run.stderr
    assert "neither success nor failure" in run.stderr
    assert "Inspect the target before acting again" in run.stderr.splitlines()[-1]
    assert f"acf operation get {OP2}" in run.stderr


def test_a_failed_operation_with_json_prints_the_operation_as_the_platform_sent_it(cli: Cli) -> None:
    sent = ended("sandbox.start", "FAILED", "NOT_APPLIED", "DEPENDENCY_UNAVAILABLE")
    run = cli.run([*START, "--json"], start(reply(200, sent)))
    assert run.exit_code == 4
    assert run.stdout == ""
    assert run.error_document == sent


# ------------------------------------------------------------------------------------------- 6 and 7
@pytest.mark.parametrize("kind", ["connect_error", "connection_reset", "timeout"])
def test_6_a_read_that_got_no_answer(cli: Cli, kind: str) -> None:
    run = cli.run(INSPECT, read(fault(kind)), read(fault(kind)), read(fault(kind)))
    assert run.exit_code == 6
    assert run.stdout == ""
    assert run.stderr.startswith("error: unreachable: ")
    assert "run the command again" in run.stderr.splitlines()[-1]


def test_7_what_answers_is_not_this_api(cli: Cli) -> None:
    run = cli.run(INSPECT, read({"status": 404, "content": b"<html>not found</html>"}))
    assert run.exit_code == 7
    assert "does not speak version v1" in run.stderr
    assert "Check the address" in run.stderr.splitlines()[-1]


@pytest.mark.parametrize(
    "response",
    [
        {"status": 200, "content": b"<html>hello</html>"},
        {"status": 200, "json": [1, 2]},
        {"status": 418, "content": b""},
    ],
    ids=["not-json", "not-an-object", "no-problem-document"],
)
def test_7_an_answer_that_is_not_an_answer_of_this_api(cli: Cli, response: Json) -> None:
    run = cli.run(INSPECT, read(response))
    assert run.exit_code == 7
    assert run.stderr.startswith("error: unexpected answer: ")
    assert ends_with_a_next_step(run.stderr)


def test_7_a_view_that_lacks_what_the_api_always_sends(cli: Cli) -> None:
    broken = sandbox()
    del broken["resources"]
    run = cli.run(INSPECT, read(reply(200, broken)))
    assert run.exit_code == 7
    assert "member 'resources'" in run.stderr


# ----------------------------------------------------------------------------------------------- 8
@pytest.mark.parametrize("code", ["OUTCOME_UNRESOLVED", "REQUEST_IN_PROGRESS"])
def test_8_the_platform_cannot_say_yet_and_the_message_names_the_key(cli: Cli, code: str) -> None:
    answer = refusal(code, retry_after=1, idempotency_key="key-9")
    run = cli.run(START, start(answer), start(answer), start(answer))
    assert run.exit_code == 8
    assert run.stdout == ""
    assert f"error: unresolved: {code}" in run.stderr
    assert "an operation may exist because of it" in run.stderr
    assert "with the same arguments and --idempotency-key key-9" in run.stderr.splitlines()[-1]
    assert {seen.key for seen in run.requests} == {"key-9"}, "every attempt carried the one key"
    assert len({seen.body for seen in run.requests}) == 1, "and the same body"


@pytest.mark.parametrize("kind", ["connection_reset", "timeout"])
def test_8_a_request_that_changes_something_got_no_answer(cli: Cli, kind: str) -> None:
    run = cli.run(START, start(fault(kind)), start(fault(kind)), start(fault(kind)))
    assert run.exit_code == 8
    assert "error: unresolved: OUTCOME_UNRESOLVED" in run.stderr
    assert "--idempotency-key key-9" in run.stderr.splitlines()[-1]


def test_8_the_key_this_tool_made_is_named_when_the_caller_gave_none(cli: Cli) -> None:
    answer = refusal("OUTCOME_UNRESOLVED", retry_after=1)
    exchange = ex("POST", START_PATH, answer)
    run = cli.run(["sandbox", "start", SBX, "--generation", "1"], exchange, exchange, exchange)
    sent = run.requests[0].key
    assert sent is not None
    assert len(sent) == 36, "a key is made before anything is sent"
    assert f"--idempotency-key {sent}" in run.stderr


def test_8_a_code_never_seen_whose_kind_is_unresolved(cli: Cli) -> None:
    later = refusal("FUTURE_UNRESOLVED", status=503, kind="UNRESOLVED", retry="SAME_REQUEST_LATER", retry_after=600)
    run = cli.run(START, start(later))
    assert run.exit_code == 8
    assert "--idempotency-key key-9" in run.stderr.splitlines()[-1]
    never = refusal("FUTURE_UNRESOLVED", status=410, kind="UNRESOLVED", retry="NEVER")
    run = cli.run(START, start(never))
    assert run.exit_code == 8
    assert "Inspect the target before acting again" in run.stderr.splitlines()[-1], (
        "it says never, so nothing is repeated"
    )


def test_8_the_start_of_a_create_is_resumed_with_the_key_of_the_create(cli: Cli) -> None:
    """The start runs under ``<key>:start``. Asking again with that derived key would be a different request."""
    created = done("sandbox.create", "sandbox", sandbox("READY"))
    lost = ex("POST", START_PATH, fault(), headers={"idempotency-key": "key-9:start"})
    run = cli.run(CREATE, ex("POST", "/sandboxes", reply(200, created)), lost, lost, lost)
    assert run.exit_code == 8
    assert "--idempotency-key key-9." in run.stderr.splitlines()[-1]
    assert "key-9:start" not in run.stderr.splitlines()[-1]
    assert f"Sandbox {SBX} was created" in run.stderr, "what the SDK knows about the sequence is passed on"


# ------------------------------------------------------------------------------------------ 9 and 10
def test_9_the_outcome_is_lost_for_good_and_is_never_0(cli: Cli) -> None:
    run = cli.run(START, start(refusal("OUTCOME_LOST", idempotency_key="key-9")))
    assert run.exit_code == 9
    assert run.stdout == ""
    assert len(run.requests) == 1, "it is never asked again"
    assert "error: outcome lost: OUTCOME_LOST" in run.stderr
    assert "neither success nor failure" in run.stderr
    last = run.stderr.splitlines()[-1]
    assert "Inspect the target before acting again" in last
    assert "This idempotency key is finished" in last


def test_10_still_running_names_the_operation_and_the_command_that_follows_it(cli: Cli) -> None:
    running = operation("sandbox.start", "IN_PROGRESS", operation_id=OP2)
    run = cli.run([*START, "--follow-max", "0"], start(reply(202, running, retry_after="1")))
    assert run.exit_code == 10
    assert run.stdout == ""
    assert f"error: still running: operation {OP2} (sandbox.start) is IN_PROGRESS" in run.stderr
    assert "Nothing was cancelled and nothing is assumed" in run.stderr
    last = run.stderr.splitlines()[-1]
    assert f"acf operation get {OP2} --wait 30" in last
    assert "--idempotency-key key-9" in last


def test_10_an_execution_that_is_still_running_says_where_its_output_will_be(cli: Cli) -> None:
    running = operation(
        "execution.create", "IN_PROGRESS", operation_id=OP3, target={"sandbox_id": SBX, "execution_id": EXE}
    )
    run = cli.run([*RUN[:-2], "--follow-max", "0", "--", "true"], ex("POST", RUN_PATH, reply(202, running)))
    assert run.exit_code == 10
    assert f"acf exec output {EXE}" in run.stderr.splitlines()[-1]


def test_10_a_state_never_seen_has_not_ended(cli: Cli) -> None:
    odd = operation("sandbox.start", "AWAITING_PLACEMENT", operation_id=OP2)
    run = cli.run([*START, "--follow-max", "0"], start(reply(200, odd)))
    assert run.exit_code == 10
    assert "AWAITING_PLACEMENT" in run.stderr


# ----------------------------------------------------------------------------------------- 130 and 141
def test_130_interrupted_says_that_nothing_was_cancelled_and_how_to_cancel(cli: Cli) -> None:
    run = cli.run(RUN, ex("POST", RUN_PATH, interrupt()))
    assert run.exit_code == 130
    assert run.stdout == ""
    assert run.stderr.startswith("error: interrupted\n")
    assert "Nothing was cancelled" in run.stderr
    last = run.stderr.splitlines()[-1]
    assert "--idempotency-key key-9" in last
    assert "acf exec cancel EXECUTION" in last
    assert len(run.requests) == 1, "an interruption sends nothing: no cancel is made for the person"


def test_130_an_interrupted_read_changed_nothing(cli: Cli) -> None:
    run = cli.run(INSPECT, read(interrupt()))
    assert run.exit_code == 130
    assert "it changed nothing" in run.stderr.splitlines()[-1]


class _Closed(FakeStream):
    """Standard output whose reader has gone away."""

    def write(self, text: str) -> int:
        raise BrokenPipeError(32, "Broken pipe")


def test_141_the_reader_of_standard_output_went_away(cli: Cli) -> None:
    run = cli.run(INSPECT, read(reply(200, sandbox())), stdout=_Closed())
    assert run.exit_code == 141
    assert run.stderr == "", "it stops quietly, as other tools do"


# ---------------------------------------------------------------------------------- create, then start
def created() -> Exchange:
    return ex("POST", "/sandboxes", reply(200, done("sandbox.create", "sandbox", sandbox("READY"))))


def destroyed(response: Json | None = None) -> Exchange:
    answer = response or reply(200, done("sandbox.destroy", "sandbox", sandbox("DESTROYED")))
    return ex("DELETE", f"/sandboxes/{SBX}", answer, headers={"idempotency-key": "key-9:destroy"})


def test_a_start_that_is_refused_destroys_the_sandbox_and_exits_3(cli: Cli) -> None:
    refused = ex("POST", START_PATH, refusal("STATE_CONFLICT"))
    run = cli.run(CREATE, created(), refused, destroyed())
    assert run.exit_code == 3
    assert run.stdout == ""
    assert f"error: sandbox {SBX} was created and could not be started" in run.stderr
    assert "Its start: refused: STATE_CONFLICT: State conflict." in run.stderr
    assert "The sandbox was destroyed: nothing is left of it." in run.stderr


def test_a_start_that_fails_with_the_sandbox_kept_says_how_to_go_on(cli: Cli) -> None:
    failed = ex("POST", START_PATH, reply(200, ended("sandbox.start", "FAILED", "NOT_APPLIED", "RESOURCE_EXHAUSTED")))
    run = cli.run([*CREATE, "--keep-on-start-failure"], created(), failed)
    assert run.exit_code == 4
    assert "The sandbox was kept, as asked." in run.stderr
    last = run.stderr.splitlines()[-1]
    assert f"acf sandbox start {SBX}" in last
    assert f"acf sandbox destroy {SBX}" in last


def test_a_start_whose_outcome_is_unknown_exits_5_and_a_failed_destroy_is_said(cli: Cli) -> None:
    unknown = ex("POST", START_PATH, reply(200, ended("sandbox.start", "UNKNOWN", "MAY_BE_APPLIED")))
    run = cli.run(CREATE, created(), unknown, destroyed(refusal("STATE_CONFLICT")))
    assert run.exit_code == 5
    assert "Destroying it did not succeed either (refused: STATE_CONFLICT: State conflict)" in run.stderr
    assert f"acf sandbox inspect {SBX}" in run.stderr.splitlines()[-1]


def test_a_start_failure_with_json_prints_the_answer_about_the_start(cli: Cli) -> None:
    sent = ended("sandbox.start", "FAILED", "NOT_APPLIED", "RESOURCE_EXHAUSTED")
    run = cli.run([*CREATE, "--json"], created(), ex("POST", START_PATH, reply(200, sent)), destroyed())
    assert run.exit_code == 4
    assert run.error_document == sent
    assert "The sandbox was destroyed" in run.stderr


# ------------------------------------------------------------------------------- reads that state a condition
@pytest.mark.parametrize(
    ("view", "status"),
    [
        (operation(), 0),
        (operation("sandbox.start", "IN_PROGRESS"), 10),
        (operation("sandbox.start", "A_STATE_NEVER_SEEN"), 10),
        (operation("sandbox.start", "FAILED", effect="NOT_APPLIED", failure=failure("TIMEOUT")), 4),
        (operation("sandbox.start", "CANCELLED", effect="NOT_APPLIED"), 4),
        (operation("sandbox.start", "FAILED", effect="MAY_BE_APPLIED"), 5),
        (operation("sandbox.start", "FAILED"), 5),
        (operation("sandbox.start", "UNKNOWN", effect="MAY_BE_APPLIED"), 5),
    ],
    ids=["succeeded", "running", "state-never-seen", "failed", "cancelled", "may-be-applied", "no-effect", "unknown"],
)
def test_operation_get_prints_the_operation_and_exits_with_its_condition(cli: Cli, view: Json, status: int) -> None:
    run = cli.run(["operation", "get", OP, "--json"], ex("GET", f"/operations/{OP}", reply(200, view)))
    assert run.exit_code == status
    assert run.json == view, "the operation is what was asked for, however it stands"
    assert (run.stderr == "") is (status == 0)


def test_operation_get_says_how_to_follow_an_operation_that_has_not_ended(cli: Cli) -> None:
    view = operation("sandbox.start", "IN_PROGRESS")
    run = cli.run(["operation", "get", OP, "--wait", "30"],
                  ex("GET", f"/operations/{OP}", reply(200, view), query={"wait": "30"}))  # fmt: skip
    assert run.exit_code == 10
    assert f"acf operation get {OP} --wait 30" in run.stderr


@pytest.mark.parametrize(("state", "effect", "status"), [
    ("SUCCEEDED", "APPLIED", 0), ("SUCCEEDED", None, 0), ("ACCEPTED", None, 10), ("FAILED", "NOT_APPLIED", 4),
    ("UNKNOWN", "NOT_APPLIED", 5), ("FAILED", "APPLIED", 5), ("CANCELLED", None, 5),
])  # fmt: skip
def test_the_condition_of_an_operation(state: str, effect: str | None, status: int) -> None:
    assert condition_of(state, effect) == status


def test_exec_status_is_a_read_and_an_unknown_outcome_still_never_exits_0(cli: Cli) -> None:
    for view, status in [
        (execution(), 0),
        (execution("EXITED", exit_code=3), 0),
        (execution(None, exit_code=None, state="IN_PROGRESS"), 0),
        (execution(None, exit_code=None, state="FAILED"), 0),
        (execution("UNKNOWN", exit_code=None, state="UNKNOWN"), 5),
    ]:
        run = cli.run(["exec", "status", EXE, "--json"], ex("GET", f"/executions/{EXE}", reply(200, view)))
        assert run.exit_code == status
        assert run.json == view
    assert "neither success nor failure" in run.stderr


# ------------------------------------------------------------------------------------------- --no-wait
def test_no_wait_prints_the_operation_that_has_not_ended_and_exits_0(cli: Cli) -> None:
    running = operation("sandbox.start", "ACCEPTED", operation_id=OP2)
    run = cli.run([*START, "--no-wait", "--json"], start(reply(202, running, retry_after="1")))
    assert run.exit_code == 0
    assert run.json == running
    assert len(run.requests) == 1, "nothing is followed"
    assert run.requests[0].query == {"wait": "0"}, "and the platform is asked not to hold the request open"


def test_a_command_that_follows_leaves_the_wait_of_the_first_answer_to_the_platform(cli: Cli) -> None:
    finished = done("sandbox.start", "sandbox", sandbox("RUNNING"), operation_id=OP2)
    run = cli.run(START, start(reply(200, finished)))
    assert run.exit_code == 0
    assert run.requests[0].query == {}


def test_no_wait_prints_the_operation_also_when_it_ended_in_the_first_answer(cli: Cli) -> None:
    finished = done("sandbox.start", "sandbox", sandbox("RUNNING"), operation_id=OP2)
    run = cli.run([*START, "--no-wait", "--json"], start(reply(200, finished)))
    assert run.exit_code == 0
    assert run.json == finished, "one shape for a script: the operation, never the resource"
    human = cli.run([*START, "--no-wait"], start(reply(200, finished)))
    assert OP2 in human.stdout


def test_no_wait_does_not_turn_an_operation_that_ended_without_success_into_a_success(cli: Cli) -> None:
    run = cli.run([*START, "--no-wait"], start(reply(200, ended("sandbox.start", "UNKNOWN", "MAY_BE_APPLIED"))))
    assert run.exit_code == 5
    run = cli.run([*START, "--no-wait"], start(reply(200, ended("sandbox.start", "FAILED", "NOT_APPLIED"))))
    assert run.exit_code == 4


def test_no_wait_on_exec_run_issues_the_command_and_relays_no_output(cli: Cli) -> None:
    ran = done("execution.create", "execution", execution("EXITED", exit_code=1, stdout_bytes=5), operation_id=OP3)
    run = cli.run([*RUN[:-2], "--no-wait", "--json", "--", "true"], ex("POST", RUN_PATH, reply(200, ran)))
    assert run.exit_code == 0, "with --no-wait the status says that the operation was issued"
    assert run.json == ran
    assert run.requests[0].query == {"wait": "0"}


# ----------------------------------------------------------------------------------- revoke and contain
def _contain(*cancels: Exchange) -> list[Exchange]:
    theirs = operation(
        "execution.create",
        "IN_PROGRESS",
        operation_id=OP3,
        target={"sandbox_id": SBX, "execution_id": EXE},
        actor={"principal_id": "prn_0000000000000001", "agent_label": "builder"},
    )
    return [
        ex("DELETE", f"/agent-credentials/{CRD}", reply(200, credential("REVOKED"))),
        ex("GET", "/v1/auth/whoami", reply(200, whoami())),
        ex("GET", "/operations", reply(200, page([theirs, operation()]))),
        *cancels,
    ]


def test_revoke_with_contain_cancels_what_the_key_started(cli: Cli) -> None:
    stopped = done("execution.cancel", "execution", execution("CANCELLED", exit_code=None, state="CANCELLED"))
    run = cli.run(["auth", "agent-key", "revoke", CRD, "--contain"],
                  *_contain(ex("POST", f"/executions/{EXE}/cancel", reply(200, stopped))))  # fmt: skip
    assert run.exit_code == 0
    assert "REVOKED" in run.stdout
    assert f"cancelled execution {EXE}" in run.stderr


def test_revoke_with_contain_exits_with_the_status_of_a_cancel_that_did_not_succeed(cli: Cli) -> None:
    run = cli.run(["auth", "agent-key", "revoke", CRD, "--contain", "--json"],
                  *_contain(ex("POST", f"/executions/{EXE}/cancel", refusal("STATE_CONFLICT"))))  # fmt: skip
    assert run.exit_code == 3, "the key is revoked, and what it started may still be running: that is not a success"
    assert run.json == credential("REVOKED")
    assert f"could not cancel execution {EXE}: refused: STATE_CONFLICT" in run.stderr
    assert "acf exec cancel EXECUTION" in run.stderr.splitlines()[-1]


def test_revoke_with_contain_says_so_when_there_was_nothing_to_cancel(cli: Cli) -> None:
    run = cli.run(
        ["auth", "agent-key", "revoke", CRD, "--contain"],
        ex("DELETE", f"/agent-credentials/{CRD}", reply(200, credential("REVOKED"))),
        ex("GET", "/v1/auth/whoami", reply(200, whoami())),
        ex("GET", "/operations", reply(200, page([]))),
    )
    assert run.exit_code == 0
    assert "the key had no execution in progress" in run.stderr


# ------------------------------------------------------------------------------------- --json and errors
def test_the_document_of_a_refusal_holds_the_members_the_platform_sent(cli: Cli) -> None:
    sent = problem("PERMISSION_DENIED", reason="quota")
    run = cli.run([*INSPECT, "--json"], read(refusal("PERMISSION_DENIED", reason="quota")))
    document = run.error_document
    assert document == {
        name: sent[name] for name in ("code", "kind", "retry", "message", "request_id", "reason", "status")
    }
    assert run.stderr.splitlines()[0] == json.dumps(document, separators=(",", ":")), "one line, and the first"


def test_an_unresolved_answer_names_its_key_in_the_document(cli: Cli) -> None:
    run = cli.run([*START, "--json"], start(refusal("OUTCOME_LOST", idempotency_key="key-9")))
    assert run.error_document["idempotency_key"] == "key-9"


def test_a_failure_the_platform_did_not_describe_has_no_document(cli: Cli) -> None:
    run = cli.run([*INSPECT, "--json"], read(fault()), read(fault()), read(fault()))
    assert run.exit_code == 6
    assert run.stderr.startswith("error: unreachable: "), "there is no answer of the API to print"
