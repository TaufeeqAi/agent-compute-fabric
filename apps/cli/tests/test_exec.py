"""Running a command, and acting on a sandbox by name or by identifier.

The rules held here: the command is an argument vector that is passed on as it is, and only ``--shell``
introduces a shell; a name is resolved once and the request states the generation that was seen; a
request body carries what was asked for and nothing else; and what a command wrote goes to the stream
of the same name.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from support import EXE, OP3, SBX, SNP, Cli, Exchange, Json, chunk, done, ex, execution, page, reply, sandbox, snapshot

RUN_PATH = f"/sandboxes/{SBX}/executions"


def ran(view: Json | None = None, **request: Any) -> Exchange:
    answer = done("execution.create", "execution", view or execution(), operation_id=OP3)
    return ex("POST", RUN_PATH, reply(200, answer), **request)


def read(name: str = SBX, generation: int = 3) -> Exchange:
    return ex("GET", f"/sandboxes/{name}", reply(200, sandbox(generation=generation, name="build")))


def out(stream: str, data: bytes, **members: Any) -> Exchange:
    body = chunk(base64.b64encode(data).decode(), size=len(data), stream=stream, **members)
    return ex("GET", f"/executions/{EXE}/output", reply(200, body), query={"stream": stream, "offset": "0"})


def sent(cli: Cli, args: list[str]) -> Json:
    """The body of the one request ``acf exec run`` makes for these arguments."""
    run = cli.run(["exec", "run", SBX, "--generation", "1", *args], ran())
    assert run.exit_code == 0, run.stderr
    body: Json = run.requests[0].json
    return body


# ------------------------------------------------------------------------------------------ the command
@pytest.mark.parametrize(
    "argv",
    [
        ["python", "-V"],
        ["echo", "two words", "", "  spaced  "],
        ["sh", "-c", "ls | wc -l && echo $HOME"],
        ["--json", "--verbose", "--", "-h"],
        ["printf", "%s\n", "é✓", "a;b|c>d"],
    ],
)
def test_the_argument_vector_is_passed_on_as_it_is(cli: Cli, argv: list[str]) -> None:
    assert sent(cli, ["--", *argv]) == {"expected_generation": 1, "argv": argv}


def test_what_follows_the_separator_is_never_an_option_of_this_tool(cli: Cli) -> None:
    run = cli.run(["exec", "run", SBX, "--generation", "1", "--", "tool", "--json", "--no-wait"], ran())
    assert run.requests[0].json["argv"] == ["tool", "--json", "--no-wait"]
    assert run.stdout == "", "--json was the command's, so nothing was printed as JSON"


def test_shell_is_the_one_way_to_pass_a_command_line_and_says_what_it_sends(cli: Cli) -> None:
    assert sent(cli, ["--shell", "ls -l | wc -l"]) == {
        "expected_generation": 1,
        "argv": ["/bin/sh", "-c", "ls -l | wc -l"],
    }


def test_a_string_is_never_split(cli: Cli) -> None:
    assert sent(cli, ["--", "python -V"])["argv"] == ["python -V"]


def test_the_options_of_the_command_become_members_of_the_request(cli: Cli) -> None:
    body = sent(cli, ["--cwd", "/work", "--env", "A=1", "--env", "B=x=y", "--env", "EMPTY=", "--timeout", "10m",
                      "--", "make"])  # fmt: skip
    assert body == {
        "expected_generation": 1,
        "argv": ["make"],
        "cwd": "/work",
        "env": {"A": "1", "B": "x=y", "EMPTY": ""},
        "timeout_seconds": 600,
    }


def test_a_member_nobody_asked_for_is_not_sent(cli: Cli) -> None:
    assert set(sent(cli, ["--", "true"])) == {"expected_generation", "argv"}


def test_timeout_bounds_the_command_and_request_timeout_the_request(cli: Cli) -> None:
    run = cli.run(
        ["exec", "run", SBX, "--generation", "1", "--timeout", "90", "--request-timeout", "30s", "--", "true"], ran()
    )
    assert run.requests[0].json["timeout_seconds"] == 90
    assert cli.clients[0][1] == 30.0


# ------------------------------------------------------------------------------- names and generations
def test_a_name_is_resolved_once_and_the_request_states_the_generation_that_was_seen(cli: Cli) -> None:
    run = cli.run(
        ["exec", "run", "build", "--", "true"],
        read("build"),
        ran(json={"expected_generation": 3, "argv": ["true"]}),
    )
    assert run.exit_code == 0, run.stderr
    assert [seen.path.rsplit("/", 2)[-2:] for seen in run.requests] == [["sandboxes", "build"], [SBX, "executions"]]


def test_an_identifier_without_a_generation_is_read_first(cli: Cli) -> None:
    run = cli.run(["exec", "run", SBX, "--", "true"], read(), ran(json={"expected_generation": 3, "argv": ["true"]}))
    assert run.exit_code == 0, run.stderr


def test_an_identifier_with_a_generation_needs_no_read(cli: Cli) -> None:
    run = cli.run(
        ["exec", "run", SBX, "--generation", "7", "--", "true"], ran(json={"expected_generation": 7, "argv": ["true"]})
    )
    assert len(run.requests) == 1


def test_a_name_with_a_generation_is_still_resolved_and_the_stated_generation_is_sent(cli: Cli) -> None:
    run = cli.run(
        ["exec", "run", "build", "--generation", "7", "--", "true"],
        read("build"),
        ran(json={"expected_generation": 7, "argv": ["true"]}),
    )
    assert run.exit_code == 0, run.stderr


def test_current_is_sent_only_when_the_word_is_given(cli: Cli) -> None:
    run = cli.run(
        ["exec", "run", SBX, "--generation", "current", "--", "true"],
        ran(json={"expected_generation": "current", "argv": ["true"]}),
    )
    assert run.exit_code == 0, run.stderr


@pytest.mark.parametrize("action", ["start", "stop"])
def test_start_and_stop_state_the_generation_they_saw(cli: Cli, action: str) -> None:
    answer = reply(200, done(f"sandbox.{action}", "sandbox", sandbox(generation=3)))
    run = cli.run(
        ["sandbox", action, "build"],
        read("build"),
        ex("POST", f"/sandboxes/{SBX}/{action}", answer, json={"expected_generation": 3}),
    )
    assert run.exit_code == 0, run.stderr


def test_destroy_states_the_generation_it_saw(cli: Cli) -> None:
    answer = reply(200, done("sandbox.destroy", "sandbox", sandbox("DESTROYED", generation=3)))
    run = cli.run(
        ["sandbox", "destroy", "build"],
        read("build"),
        ex("DELETE", f"/sandboxes/{SBX}", answer, query={"expected_generation": "3"}),
    )
    assert run.exit_code == 0, run.stderr


# ----------------------------------------------------------------------------------------------- create
CREATE = ["sandbox", "create", "--image", "python", "--cpu", "2"]
RESOURCES = {"vcpus": 2, "memory_mib": 4096, "disk_mib": 20480}


def created(**request: Any) -> Exchange:
    return ex("POST", "/sandboxes", reply(200, done("sandbox.create", "sandbox", sandbox("READY"))), **request)


@pytest.mark.parametrize(("memory", "disk"), [("4096", "20480"), ("4GiB", "20GiB"), ("4096MiB", "20480MiB")])
def test_a_bare_number_is_mebibytes_and_a_unit_is_a_binary_unit(cli: Cli, memory: str, disk: str) -> None:
    run = cli.run(
        [*CREATE, "--memory", memory, "--disk", disk, "--no-start"],
        created(json={"image": "python", "resources": RESOURCES}),
    )
    assert run.exit_code == 0, run.stderr


def test_create_sends_what_was_asked_for_and_never_a_default(cli: Cli) -> None:
    run = cli.run(
        [*CREATE, "--memory", "4GiB", "--disk", "20GiB", "--no-start", "--name", "build", "--lifetime", "2h",
         "--network", "none"],
        created(json={"image": "python", "resources": RESOURCES, "name": "build", "lifetime_seconds": 7200,
                      "network": {"mode": "none"}}),
    )  # fmt: skip
    assert run.exit_code == 0, run.stderr


def test_an_allowlist_is_read_from_a_file(cli: Cli, tmp_path: Path) -> None:
    allowlist = tmp_path / "network.json"
    allowlist.write_text(
        json.dumps(
            {
                "mode": "allowlist",
                "entries": [
                    {"name": "packages.acf.example", "ports": [443]},
                    {"network": "10.0.0.0/8", "ports": [[8000, 8100]]},
                ],
            }
        ),
        encoding="utf-8",
    )
    wanted = {
        "mode": "allowlist",
        "entries": [
            {"name": "packages.acf.example", "ports": [{"from": 443, "to": 443}]},
            {"network": "10.0.0.0/8", "ports": [{"from": 8000, "to": 8100}]},
        ],
    }
    run = cli.run(
        [*CREATE, "--memory", "4GiB", "--disk", "20GiB", "--no-start", "--network", str(allowlist)],
        created(json={"image": "python", "resources": RESOURCES, "network": wanted}),
    )
    assert run.exit_code == 0, run.stderr


@pytest.mark.parametrize(
    ("content", "complaint"),
    [
        (None, "cannot be read"),
        (b"not json", "does not hold JSON"),
        (b"[1, 2]", "holds JSON that is not an object"),
        (b'{"mode": "restricted"}', "network must be"),
        (b'{"mode": "allowlist", "entries": [{"name": "x", "ports": [443], "extra": 1}]}', "exactly ports and one of"),
        (b" " * (1024 * 1024 + 1), "is larger than"),
    ],
    ids=["missing", "not-json", "not-an-object", "no-such-mode", "unknown-member", "too-large"],
)
def test_a_network_file_that_cannot_be_used_sends_nothing(
    cli: Cli, tmp_path: Path, content: bytes | None, complaint: str
) -> None:
    file = tmp_path / "network.json"
    if content is not None:
        file.write_bytes(content)
    run = cli.run([*CREATE, "--memory", "4GiB", "--disk", "20GiB", "--network", str(file)])
    assert run.exit_code == 2
    assert complaint in run.stderr
    assert run.requests == []


def test_restricted_like_every_other_word_is_not_a_network(cli: Cli) -> None:
    run = cli.run([*CREATE, "--memory", "4GiB", "--disk", "20GiB", "--network", "restricted"])
    assert run.exit_code == 2
    assert run.requests == []


def test_create_starts_what_it_created_under_the_key_with_its_suffix(cli: Cli) -> None:
    started = reply(200, done("sandbox.start", "sandbox", sandbox("RUNNING")))
    run = cli.run(
        [*CREATE, "--memory", "4GiB", "--disk", "20GiB", "--idempotency-key", "key-1", "--json"],
        created(headers={"idempotency-key": "key-1"}),
        ex("POST", f"/sandboxes/{SBX}/start", started, headers={"idempotency-key": "key-1:start"},
           json={"expected_generation": 1}),
    )  # fmt: skip
    assert run.exit_code == 0, run.stderr
    assert run.json == sandbox("RUNNING")


def test_a_narrowing_is_read_from_a_file_and_sent_as_it_is(cli: Cli, tmp_path: Path) -> None:
    grant = {"methods": ["sandbox.create"], "ceilings": {"vcpus": 1}}
    file = tmp_path / "grant.json"
    file.write_text(json.dumps(grant), encoding="utf-8")
    minted = {"credential_id": "crd_0000000000000002", "kind": "agent", "display_prefix": "acf1_agt_x",
              "status": "ACTIVE", "issued_at": "t", "expires_at": "t", "secret": "acf1_agt_minted_secret"}  # fmt: skip
    run = cli.run(
        ["auth", "agent-key", "create", "--label", "builder", "--lifetime", "3600", "--narrowing", str(file)],
        ex("POST", "/agent-credentials", reply(201, minted),
           json={"label": "builder", "lifetime_seconds": 3600, "narrowing": grant}),
    )  # fmt: skip
    assert run.exit_code == 0, run.stderr
    assert run.stdout == "acf1_agt_minted_secret\n", "the secret, once, and nothing else on standard output"
    assert "this is the only time the secret is shown" in run.stderr
    assert "acf1_agt_minted_secret" not in run.stderr


def test_a_mint_that_carries_no_secret_is_not_a_success(cli: Cli) -> None:
    minted = {"credential_id": "crd_0000000000000002", "kind": "agent", "display_prefix": "acf1_agt_x",
              "status": "ACTIVE", "issued_at": "t", "expires_at": "t"}  # fmt: skip
    run = cli.run(
        ["auth", "agent-key", "create", "--label", "builder", "--lifetime", "1h"],
        ex("POST", "/agent-credentials", reply(201, minted)),
    )
    assert run.exit_code == 7
    assert "acf auth agent-key revoke" in run.stderr.splitlines()[-1]


# ----------------------------------------------------------------------------------------------- output
def test_what_the_command_wrote_goes_to_the_stream_of_the_same_name(cli: Cli) -> None:
    view = execution(stdout_bytes=4, stderr_bytes=5)
    run = cli.run(
        ["exec", "run", SBX, "--generation", "1", "--", "true"],
        ran(view),
        out("stdout", b"out\n"),
        out("stderr", b"err!\n"),
    )
    assert run.exit_code == 0
    assert (run.stdout_bytes, run.stderr_bytes) == (b"out\n", b"err!\n")


def test_a_stream_that_holds_nothing_is_not_asked_for(cli: Cli) -> None:
    run = cli.run(
        ["exec", "run", SBX, "--generation", "1", "--", "true"], ran(execution(stdout_bytes=3)), out("stdout", b"hi\n")
    )
    assert run.stdout_bytes == b"hi\n"
    assert len(run.requests) == 2


def test_output_is_read_to_its_end(cli: Cli) -> None:
    first = chunk(base64.b64encode(b"one ").decode(), size=4, eof=False, stored_bytes=7)
    second = chunk(base64.b64encode(b"two").decode(), offset=4, size=3)
    run = cli.run(
        ["exec", "run", SBX, "--generation", "1", "--", "true"],
        ran(execution(stdout_bytes=7)),
        ex("GET", f"/executions/{EXE}/output", reply(200, first), query={"stream": "stdout", "offset": "0"}),
        ex("GET", f"/executions/{EXE}/output", reply(200, second), query={"stream": "stdout", "offset": "4"}),
    )
    assert run.stdout_bytes == b"one two"


def test_output_that_was_not_all_stored_is_said_to_be_so(cli: Cli) -> None:
    view = execution(stdout_bytes=4)
    view["stdout"] = {"stored_bytes": 4, "produced_bytes": 9000, "completeness": "TRUNCATED"}
    run = cli.run(["exec", "run", SBX, "--generation", "1", "--", "true"], ran(view), out("stdout", b"part"))
    assert run.exit_code == 0
    assert "acf: stdout is TRUNCATED: 4 of 9000 bytes were stored" in run.stderr


def test_with_json_the_result_is_the_one_document_and_no_output_is_read(cli: Cli) -> None:
    view = execution("EXITED", exit_code=3, stdout_bytes=100)
    run = cli.run(["exec", "run", SBX, "--generation", "1", "--json", "--", "false"], ran(view))
    assert run.exit_code == 1
    assert run.json == view
    assert len(run.requests) == 1


def test_exec_output_asks_for_the_slice_that_was_named(cli: Cli) -> None:
    body = chunk(base64.b64encode(b"err").decode(), offset=10, size=3, stream="stderr", eof=False, stored_bytes=50)
    run = cli.run(
        ["exec", "output", EXE, "--stream", "stderr", "--offset", "10", "--max-bytes", "3"],
        ex("GET", f"/executions/{EXE}/output", reply(200, body),
           query={"stream": "stderr", "offset": "10", "max_bytes": "3"}),
    )  # fmt: skip
    assert run.exit_code == 0, run.stderr
    assert run.stdout_bytes == b"err"
    assert "acf: stderr bytes 10 to 13 of 50 stored" in run.stderr
    assert "more follows: --offset 13" in run.stderr


def test_exec_output_says_when_the_stream_has_ended(cli: Cli) -> None:
    run = cli.run(
        ["exec", "output", EXE],
        ex("GET", f"/executions/{EXE}/output", reply(200, chunk(base64.b64encode(b"all").decode(), size=3))),
    )
    assert "end of the stream" in run.stderr
    assert len(run.requests) == 1, "the slice is the only request"


def test_exec_cancel_sends_the_cancel_and_nothing_before_it(cli: Cli) -> None:
    """Stopping a command takes a privilege away: no read, which a limit could refuse, stands in front of it."""
    cancelled = execution("CANCELLED", exit_code=None)
    run = cli.run(
        ["exec", "cancel", EXE, "--idempotency-key", "stop-it"],
        ex(
            "POST",
            f"/executions/{EXE}/cancel",
            reply(200, done("execution.cancel", "execution", cancelled)),
            headers={"idempotency-key": "stop-it"},
        ),
    )
    assert run.exit_code == 0, run.stderr
    assert [request.method for request in run.requests] == ["POST"]
    assert "CANCELLED" in run.stdout


def test_exec_cancel_of_what_cannot_be_an_identifier_is_a_usage_error_and_sends_nothing(cli: Cli) -> None:
    run = cli.run(["exec", "cancel", ".."])
    assert run.exit_code == 2
    assert run.requests == []


@pytest.mark.parametrize("args", [["--stream", "stdin"], ["--offset", "-1"], ["--max-bytes", "0"]])
def test_exec_output_refuses_a_slice_that_cannot_be(cli: Cli, args: list[str]) -> None:
    run = cli.run(["exec", "output", EXE, *args])
    assert run.exit_code == 2
    assert run.requests == []


# --------------------------------------------------------------------------------------------- snapshots
def test_a_snapshot_is_found_by_its_name_in_the_listing(cli: Cli) -> None:
    listed = ex("GET", "/snapshots", reply(200, page([snapshot(name="base")])))
    deleted = reply(200, done("snapshot.delete", "snapshot", snapshot("DELETED", name="base")))
    run = cli.run(
        ["snapshot", "delete", "base"],
        listed,
        ex("DELETE", f"/snapshots/{SNP}", deleted, query={"snapshot_generation": "1"}),
    )
    assert run.exit_code == 0, run.stderr


def test_a_snapshot_that_is_not_listed_is_not_found(cli: Cli) -> None:
    run = cli.run(["snapshot", "delete", "nowhere"], ex("GET", "/snapshots", reply(200, page([]))))
    assert run.exit_code == 3
    assert "NOT_FOUND" in run.stderr


def test_restore_as_a_new_sandbox_is_another_request_than_restore_into_one(cli: Cli) -> None:
    listed = ex("GET", "/snapshots", reply(200, page([snapshot()])))
    restored = reply(200, done("snapshot.restore", "sandbox", sandbox("READY", sandbox_id="sbx-" + "0" * 31 + "2")))
    run = cli.run(
        ["snapshot", "restore", SNP, "--name", "copy", "--lifetime", "1h"],
        listed,
        ex("POST", f"/snapshots/{SNP}/restore", restored,
           json={"snapshot_generation": 1, "target": {"kind": "new", "name": "copy", "lifetime_seconds": 3600}}),
    )  # fmt: skip
    assert run.exit_code == 0, run.stderr


def test_restore_into_a_sandbox_named_by_name_reads_it_and_states_its_generation(cli: Cli) -> None:
    listed = ex("GET", "/snapshots", reply(200, page([snapshot()])))
    restored = reply(200, done("snapshot.restore", "sandbox", sandbox("READY", generation=4)))
    run = cli.run(
        ["snapshot", "restore", SNP, "--into", "build"],
        listed,
        read("build"),
        ex("POST", f"/snapshots/{SNP}/restore", restored,
           json={"snapshot_generation": 1,
                 "target": {"kind": "existing", "sandbox_id": SBX, "expected_generation": 3}}),
    )  # fmt: skip
    assert run.exit_code == 0, run.stderr


# --------------------------------------------------------------------------------------------- --verbose
def test_verbose_writes_the_request_id_of_the_result_and_never_a_header(cli: Cli) -> None:
    run = cli.run(
        ["sandbox", "inspect", SBX, "--verbose", "--json"],
        ex("GET", f"/sandboxes/{SBX}", reply(200, sandbox(), x_request_id="req_result_1")),
    )
    assert run.exit_code == 0
    assert "acf: request req_result_1" in run.stderr
    assert run.json == sandbox(), "standard output is still the one document"
    assert "Authorization" not in run.stderr
    assert "Bearer" not in run.stderr


def test_verbose_writes_the_request_id_of_an_error(cli: Cli) -> None:
    refused = reply(404, {"code": "NOT_FOUND", "kind": "REFUSED", "retry": "NEVER", "message": "Not found",
                          "request_id": "req_error_1"}, content_type="application/problem+json")  # fmt: skip
    run = cli.run(["sandbox", "inspect", SBX, "--verbose"], ex("GET", f"/sandboxes/{SBX}", refused))
    assert run.exit_code == 3
    assert "acf: request req_error_1" in run.stderr


def test_verbose_names_the_key_before_anything_is_sent_and_shows_each_retry(cli: Cli) -> None:
    later = reply(429, {"code": "RATE_LIMITED", "kind": "REFUSED", "retry": "SAME_REQUEST_LATER", "message": "m",
                        "request_id": "req_1"}, content_type="application/problem+json", retry_after="2")  # fmt: skip
    started = reply(200, done("sandbox.start", "sandbox", sandbox()), x_request_id="req_2")
    path = f"/sandboxes/{SBX}/start"
    run = cli.run(
        ["sandbox", "start", SBX, "--generation", "1", "--idempotency-key", "key-7", "--verbose"],
        ex("POST", path, later),
        ex("POST", path, started),
    )
    assert run.exit_code == 0, run.stderr
    lines = run.stderr.splitlines()
    assert "acf: idempotency key key-7" in lines
    assert any("attempt 1 did not succeed (RATE_LIMITED)" in line for line in lines), "a retry is never silent"
    assert "acf: request req_2" in lines
    assert cli.clock.waited >= 2


def test_without_verbose_none_of_that_is_written(cli: Cli) -> None:
    run = cli.run(["sandbox", "inspect", SBX, "--json"], ex("GET", f"/sandboxes/{SBX}", reply(200, sandbox())))
    assert run.stderr == ""
