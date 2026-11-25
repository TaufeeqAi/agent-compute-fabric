"""The command for every public operation, driven from the generated table of the API.

``protocols/api/surface.yaml`` lists each public operation with its REST route, its SDK call and its
command. For every row that names a command, this file proves four things: the command exists under
that exact name; it makes the SDK call the row names; that call reaches the route the row names; and
with ``--json`` standard output is exactly the JSON the platform sent, with nothing else on it.

A row without a case below fails a test, so a new operation cannot appear without its command.
"""

from __future__ import annotations

import functools
import re
from collections.abc import Callable
from typing import Any

import pytest
from agentcompute import Execution, Fabric, Sandbox, Snapshot

from cases import CASES
from support import (
    BASE_URL,
    CANARY_KEY,
    SBX,
    Cli,
    Json,
    ex,
    page,
    reply,
    sandbox,
    surface,
)

COMMON_OPTIONS = ("--json", "--profile", "--base-url", "--project", "--verbose", "--timeout")
MUTATION_OPTIONS = ("--idempotency-key", "--follow-max", "--no-wait")


ROWS = {row["method"]: row for row in surface() if row["cli"]}


# ----------------------------------------------------------------------------------- the table itself
def test_every_operation_with_a_command_has_a_case_here() -> None:
    assert set(CASES) == set(ROWS), "protocols/api/surface.yaml and the cases of this file name different operations"


def test_the_table_is_the_one_this_file_was_written_for() -> None:
    assert len(ROWS) == 21
    assert {row["cli"] for row in ROWS.values()} == {
        "acf sandbox create", "acf sandbox start", "acf exec run", "acf exec status", "acf exec output",
        "acf exec cancel", "acf snapshot create", "acf snapshot restore", "acf sandbox list",
        "acf sandbox inspect", "acf snapshot list", "acf sandbox stop", "acf sandbox destroy",
        "acf snapshot delete", "acf operation get", "acf operation list", "acf auth agent-key create",
        "acf auth agent-key list", "acf auth agent-key revoke", "acf info", "acf policy inspect",
    }  # fmt: skip


# ------------------------------------------------------------------------------------ the SDK's calls
def _owners() -> dict[str, type]:
    """The class each word of the table's ``sdk`` column stands for. Taken from a client, not from a private module."""
    with Fabric(CANARY_KEY, base_url=BASE_URL) as fabric:
        return {
            "fabric": Fabric,
            "sandbox": Sandbox,
            "snapshot": Snapshot,
            "execution": Execution,
            "sandboxes": type(fabric.sandboxes),
            "snapshots": type(fabric.snapshots),
            "executions": type(fabric.executions),
            "operations": type(fabric.operations),
            "auth": type(fabric.auth),
        }


OWNERS = _owners()


def _spy(monkeypatch: pytest.MonkeyPatch, call: str) -> list[str]:
    """Record every call of the SDK method that ``sandboxes.create()`` or ``sandbox.start()`` names."""
    owner_word, _, method = call.removesuffix("()").partition(".")
    owner = OWNERS[owner_word]
    original: Callable[..., Any] = getattr(owner, method)
    calls: list[str] = []

    @functools.wraps(original)
    def recorded(*args: Any, **kwargs: Any) -> Any:
        calls.append(call)
        return original(*args, **kwargs)

    monkeypatch.setattr(owner, method, recorded)
    return calls


def _route(rest: str) -> tuple[str, re.Pattern[str]]:
    method, template = rest.split(" ")
    return method, re.compile(re.sub(r"\\\{[a-z]+\\\}", "[^/]+", re.escape(template)))


@pytest.mark.parametrize("method", sorted(CASES))
def test_the_command_makes_the_call_of_the_table_and_prints_its_answer_as_it_came(
    cli: Cli, monkeypatch: pytest.MonkeyPatch, method: str
) -> None:
    row, case = ROWS[method], CASES[method]
    words = row["cli"].split()[1:]
    assert case.args[: len(words)] == words, "the command is not the one the table names"
    calls = _spy(monkeypatch, row["sdk"])

    # Straight after the command: what follows a `--` belongs to the command that is run in the sandbox.
    run = cli.run([*words, "--json", *case.args[len(words) :]], *case.exchanges)

    assert run.exit_code == 0, run.stderr
    assert run.json == case.printed, "--json is the platform's JSON, exactly"
    assert run.stdout.endswith("\n")
    assert run.stdout.count("\n") == len(run.stdout.splitlines())
    assert run.stderr == "", "nothing but the document is written when a command succeeds with --json"
    assert calls, f"the command did not call {row['sdk']}"
    verb, path = _route(row["rest"])
    assert any(seen.method == verb and path.fullmatch(seen.path) for seen in run.requests), row["rest"]
    if row["idempotency_key"]:
        assert all(seen.key for seen in run.requests if seen.method != "GET"), "a request that changes carries a key"
    else:
        assert all(seen.key is None for seen in run.requests), "a read, a mint and a revocation carry no key"


@pytest.mark.parametrize("method", sorted(CASES))
def test_the_command_shows_the_same_answer_to_a_person(cli: Cli, method: str) -> None:
    case = CASES[method]
    run = cli.run(case.args, *case.exchanges)
    assert run.exit_code == 0, run.stderr
    assert case.shown in run.stdout
    assert CANARY_KEY not in run.stdout + run.stderr


@pytest.mark.parametrize("method", sorted(ROWS))
def test_the_command_exists_and_takes_the_options_every_command_takes(cli: Cli, method: str) -> None:
    row = ROWS[method]
    run = cli.run([*row["cli"].split()[1:], "--help"])
    assert run.exit_code == 0
    for option in COMMON_OPTIONS:
        assert option in run.stdout, f"{row['cli']} does not take {option}"
    for option in MUTATION_OPTIONS:
        assert (option in run.stdout) is row["idempotency_key"], f"{row['cli']} and {option}"


def test_a_generation_is_an_option_exactly_where_the_sdk_call_takes_one(cli: Cli) -> None:
    takes = {"sandbox.start", "sandbox.stop", "sandbox.destroy", "execution.create", "snapshot.create",
             "snapshot.restore"}  # fmt: skip
    for method, row in ROWS.items():
        run = cli.run([*row["cli"].split()[1:], "--help"])
        assert ("--generation" in run.stdout) is (method in takes), row["cli"]


def test_a_list_prints_one_array_and_an_empty_listing_an_empty_one(cli: Cli) -> None:
    run = cli.run(["sandbox", "list", "--json"], ex("GET", "/sandboxes", reply(200, page([]))))
    assert run.json == []
    human = cli.run(["sandbox", "list"], ex("GET", "/sandboxes", reply(200, page([]))))
    assert human.stdout == "no sandboxes\n"


def test_a_member_this_version_has_never_seen_is_printed_as_it_came(cli: Cli) -> None:
    odd: Json = sandbox("HIBERNATED", shape={"new": [1, 2]}, quota_class="gold")
    run = cli.run(["sandbox", "inspect", SBX, "--json"], ex("GET", f"/sandboxes/{SBX}", reply(200, odd)))
    assert run.json == odd
    human = cli.run(["sandbox", "inspect", SBX], ex("GET", f"/sandboxes/{SBX}", reply(200, odd)))
    assert "HIBERNATED" in human.stdout, "a state this version does not know is shown as it is"
