"""The key never appears in anything this tool writes, logs or raises.

Every test here runs against a platform that does what an honest one never does: it repeats the
caller's key wherever free text can stand. In a name, in a note, in a message, in a request id, in the
output of a command, in the words of a transport failure. The key the tests hold is a canary, and it is
searched for in every byte written to standard output and standard error, in every log record, and in
every message and ``repr`` of what was raised.

The commands are those of the generated table of the API, so a command that is added is covered here
without anyone remembering to.
"""

from __future__ import annotations

import base64
import logging
from typing import Any

import pytest

from agentcompute_cli import render
from agentcompute_cli.outcome import ArgumentError, describe
from cases import CASES
from support import (
    CANARY_KEY,
    EXE,
    OP2,
    SBX,
    Cli,
    Exchange,
    Json,
    Run,
    done,
    ex,
    execution,
    failure,
    fault,
    interrupt,
    operation,
    refusal,
    reply,
    sandbox,
    surface,
)

CANARY = CANARY_KEY.encode()
#: Members that hold free text: chosen by someone, or written by the platform or the host for people.
TEXTS = frozenset(
    {
        "name", "label", "message", "note", "quarantined", "revision", "expires_at", "updated_at", "created_at",
        "issued_at", "display_prefix", "policy_version", "alias", "digest", "agent_label", "reason", "detail",
        "title", "request_id", "completeness",
    }
)  # fmt: skip
LISTS = frozenset({"notes", "incompatible", "methods", "images", "platform_features", "host_features"})
MODES: list[list[str]] = [[], ["--json"], ["--verbose"], ["--json", "--verbose"]]
WORDS = {row["method"]: row["cli"].split()[1:] for row in surface() if row["cli"]}


def poisoned(value: Any) -> Any:
    """An answer in which the platform repeats the caller's key wherever free text can stand."""
    if isinstance(value, list):
        return [poisoned(item) for item in value]
    if not isinstance(value, dict):
        return value
    echoed: Json = {}
    for name, member in value.items():
        if name in TEXTS and isinstance(member, str):
            echoed[name] = f"{member} {CANARY_KEY}"
        elif name in LISTS and isinstance(member, list):
            echoed[name] = [*member, CANARY_KEY]
        elif name == "data_base64" and isinstance(member, str):
            echoed[name] = base64.b64encode(base64.b64decode(member) + b"\n" + CANARY + b"\n").decode()
        else:
            echoed[name] = poisoned(member)
    return echoed


def echoing(exchange: Exchange) -> Exchange:
    response = dict(exchange.response)
    if "json" in response:
        response["json"] = poisoned(response["json"])
    response["headers"] = {**response.get("headers", {}), "x-request-id": f"req {CANARY_KEY}"}
    return Exchange(exchange.request, response)


def clean(run: Run) -> bool:
    return CANARY not in run.stdout_bytes and CANARY not in run.stderr_bytes


@pytest.fixture(autouse=True)
def records(caplog: pytest.LogCaptureFixture) -> pytest.LogCaptureFixture:
    caplog.set_level(logging.DEBUG)
    return caplog


def logged(caplog: pytest.LogCaptureFixture) -> str:
    return "\n".join(f"{record.getMessage()} {record.args!r}" for record in caplog.records)


# ---------------------------------------------------------------------------------------- every command
@pytest.mark.parametrize("flags", MODES, ids=lambda flags: " ".join(flags) or "plain")
@pytest.mark.parametrize("method", sorted(CASES))
def test_no_command_writes_the_key_whatever_the_platform_sends_back(
    cli: Cli, caplog: pytest.LogCaptureFixture, method: str, flags: list[str]
) -> None:
    case, words = CASES[method], WORDS[method]
    for tty in (False, True):
        run = cli.run([*words, *flags, *case.args[len(words) :]], *map(echoing, case.exchanges), tty=tty)
        assert run.exit_code == 0, run.stderr
        assert clean(run)
        assert b"[redacted]" in run.stdout_bytes + run.stderr_bytes or method == "execution.create", (
            "the place where the key stood is marked, so the test knows it looked in the right place"
        )
    assert CANARY_KEY not in logged(caplog)


# ------------------------------------------------------------------------------------- every error path
INSPECT = ["sandbox", "inspect", SBX]
START = ["sandbox", "start", SBX, "--generation", "1", "--idempotency-key", "key-9"]
CREATE = ["sandbox", "create", "--image", "python", "--cpu", "1", "--memory", "512", "--disk", "1024"]
RUN = ["exec", "run", SBX, "--generation", "1", "--", "printenv"]
ECHO = f"you sent Authorization: Bearer {CANARY_KEY}"


def read(response: Json) -> Exchange:
    return ex("GET", f"/sandboxes/{SBX}", response)


def start(response: Json) -> Exchange:
    return ex("POST", f"/sandboxes/{SBX}/start", response)


def ended(state: str, effect: str) -> Json:
    return operation(
        "sandbox.start", state, effect=effect, failure=failure(f"TIMEOUT {CANARY_KEY}", message=ECHO), operation_id=OP2
    )


def error_paths() -> dict[str, tuple[list[str], list[Exchange], int]]:
    refused = refusal("PERMISSION_DENIED", message=ECHO, reason=CANARY_KEY, idempotency_key=CANARY_KEY)
    unresolved = refusal("OUTCOME_UNRESOLVED", message=ECHO, retry_after=600)
    lost = refusal("OUTCOME_LOST", message=ECHO, idempotency_key=CANARY_KEY)
    silent = fault("connection_reset", f"could not send header Authorization: Bearer {CANARY_KEY}")
    running = operation(f"sandbox.start {CANARY_KEY}", f"IN_PROGRESS {CANARY_KEY}", operation_id=OP2)
    created = ex("POST", "/sandboxes", reply(200, done("sandbox.create", "sandbox", sandbox("READY"))))
    destroy = ex("DELETE", f"/sandboxes/{SBX}", refused)
    html = {"status": 200, "content": f"<html>{ECHO}</html>".encode()}
    return {
        "refused": (INSPECT, [read(refused)], 3),
        "refused-change": (START, [start(refused)], 3),
        "unresolved": (START, [start(unresolved)], 8),
        "lost": (START, [start(lost)], 9),
        "failed": (START, [start(reply(200, ended("FAILED", "NOT_APPLIED")))], 4),
        "unknown": (START, [start(reply(200, ended("UNKNOWN", "MAY_BE_APPLIED")))], 5),
        "still-running": ([*START, "--follow-max", "0"], [start(reply(202, running))], 10),
        "unreachable": (INSPECT, [read(silent), read(silent), read(silent)], 6),
        "no-answer-to-a-change": (START, [start(silent), start(silent), start(silent)], 8),
        "not-this-api": (INSPECT, [read({"status": 404, "content": f"<html>{ECHO}</html>".encode()})], 7),
        "not-json": (INSPECT, [read(html)], 7),
        "start-refused-destroy-refused": (CREATE, [created, start(refused), destroy], 3),
        "interrupted": (START, [start(interrupt())], 130),
        "operation-get-unknown": (
            ["operation", "get", OP2],
            [ex("GET", f"/operations/{OP2}", reply(200, ended("UNKNOWN", "MAY_BE_APPLIED")))],
            5,
        ),
    }


ERROR_PATHS = error_paths()


@pytest.mark.parametrize("flags", MODES, ids=lambda flags: " ".join(flags) or "plain")
@pytest.mark.parametrize("path", sorted(ERROR_PATHS))
def test_no_error_path_writes_the_key(cli: Cli, caplog: pytest.LogCaptureFixture, path: str, flags: list[str]) -> None:
    args, exchanges, status = ERROR_PATHS[path]
    run = cli.run([*args, *flags], *map(echoing, exchanges))
    assert run.exit_code == status, run.stderr
    assert clean(run)
    assert CANARY_KEY not in logged(caplog)


def test_the_error_paths_cover_every_status_an_answer_can_produce() -> None:
    assert {status for _, _, status in ERROR_PATHS.values()} == {3, 4, 5, 6, 7, 8, 9, 10, 130}


@pytest.mark.parametrize("tty", [False, True], ids=["pipe", "terminal"])
def test_output_of_a_command_that_printed_the_key_is_not_passed_on_with_it(cli: Cli, tty: bool) -> None:
    """A sandbox that was handed the key can print it. This tool still does not write it."""
    printed = b"ACF_API_KEY=" + CANARY + b"\n"
    view = execution(stdout_bytes=len(printed), stderr_bytes=len(printed))
    chunks = [
        ex(
            "GET",
            f"/executions/{EXE}/output",
            reply(200, {"execution_id": EXE, "stream": stream, "offset": 0, "next_offset": len(printed), "eof": True,
                        "data_base64": base64.b64encode(printed).decode(), "stored_bytes": len(printed),
                        "produced_bytes": len(printed), "completeness": "COMPLETE"}),
        )
        for stream in ("stdout", "stderr")
    ]  # fmt: skip
    executed = ex("POST", f"/sandboxes/{SBX}/executions", reply(200, done("execution.create", "execution", view)))
    run = cli.run(RUN, executed, *chunks, tty=tty)
    assert run.exit_code == 0, run.stderr
    assert clean(run)
    assert run.stdout_bytes == b"ACF_API_KEY=[redacted]\n"
    assert run.stderr_bytes == b"ACF_API_KEY=[redacted]\n"


@pytest.mark.parametrize(
    "address",
    [f"https://user:{CANARY_KEY}@acf.test", f"https://acf.test/?key={CANARY_KEY}", f"http://{CANARY_KEY}.example"],
    ids=["as-user-information", "in-a-query", "in-a-host"],
)
def test_an_address_that_holds_the_key_is_refused_without_repeating_it(cli: Cli, address: str) -> None:
    run = cli.run([*INSPECT, "--verbose"], env={"ACF_BASE_URL": address})
    assert run.exit_code == 2
    assert clean(run)
    assert run.requests == []


def test_verbose_says_where_the_configuration_came_from_and_not_what_it_is(cli: Cli) -> None:
    run = cli.run([*INSPECT, "--verbose"], read(reply(200, sandbox())))
    assert "acf: key: from the environment (ACF_API_KEY)" in run.stderr
    assert "acf: address: from the environment (ACF_BASE_URL)" in run.stderr
    assert clean(run)


# ------------------------------------------------------------------------------------------ what is raised
def test_no_report_of_an_error_holds_the_key_once_it_is_protected() -> None:
    """The words of every report pass the one function that writes them. This holds it to that."""
    render.protect(CANARY_KEY)
    try:
        report = describe(ArgumentError(f"memory must be a size, not {CANARY_KEY!r}"), key=None)
        written = [render.safe_line(text) for text in (report.headline, *report.details, report.next_step)]
    finally:
        render.unprotect()
    assert all(CANARY_KEY not in line for line in written)


@pytest.mark.parametrize(
    ("flags", "broken"),
    [
        ([], "agentcompute_cli.views.show_sandbox"),
        (["--verbose"], "agentcompute_cli.views.show_sandbox"),
        (["--json"], "agentcompute_cli.render.write_json"),
    ],
    ids=["plain", "verbose", "json"],
)
def test_the_traceback_of_a_defect_is_shown_without_the_key(
    cli: Cli, monkeypatch: pytest.MonkeyPatch, flags: list[str], broken: str
) -> None:
    """A traceback quotes the words of whatever failed, and those can quote anything."""

    def fail(*_: object, **__: object) -> None:
        raise RuntimeError(f"could not show what came with Authorization: Bearer {CANARY_KEY}")

    monkeypatch.setattr(broken, fail)
    started = done("sandbox.start", "sandbox", sandbox("RUNNING"))
    for tty in (False, True):
        run = cli.run([*START, *flags], start(reply(200, started)), tty=tty)
        assert run.exit_code == 5
        assert "Traceback (most recent call last)" in run.stderr
        assert "Authorization: Bearer [redacted]" in run.stderr
        assert clean(run)


def test_the_key_is_forgotten_between_two_commands(cli: Cli) -> None:
    cli.run(INSPECT, read(reply(200, sandbox())))
    assert render.scrub(CANARY_KEY) == CANARY_KEY, "nothing of one invocation protects, or leaks into, the next"
