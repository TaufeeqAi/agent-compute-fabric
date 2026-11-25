"""Text that came from the platform or from a sandbox never drives a terminal.

A name is chosen by whoever created the record, a message by the host, output by the command that ran:
none of it is this program's text. These tests hold three rules. No escape sequence and no control
character reaches a terminal, in any view; nothing is ever interpreted as markup; and a table cell is
bounded. ``--json`` is held to the same rule by being printable ASCII.
"""

from __future__ import annotations

import base64
import io
import json
import sys

import pytest

from agentcompute_cli import render
from support import (
    EXE,
    SBX,
    Cli,
    Exchange,
    FakeStream,
    Json,
    chunk,
    done,
    ex,
    execution,
    failure,
    operation,
    page,
    reply,
    sandbox,
)

ESC = "\x1b"
#: Retitles the window, clears the screen, turns the text red, rewrites the line, makes a name read backwards.
HOSTILE = f"{ESC}]0;owned\x07{ESC}[2J{ESC}[31m\rall good\N{RIGHT-TO-LEFT OVERRIDE}exe.gnp"
HOSTILE_BYTES = HOSTILE.encode()
#: The only escape sequences this program writes of its own accord, and only to a terminal: bold, and its end.
OWN_STYLE = (f"{ESC}[1m", f"{ESC}[0m")


def no_control_characters(text: str) -> bool:
    """Nothing but printable text and line ends, once this program's own bold headers are set aside."""
    for style in OWN_STYLE:
        text = text.replace(style, "")
    return all(character in "\n" or character.isprintable() for character in text)


# ----------------------------------------------------------------------------------------- safe text
@pytest.mark.parametrize(
    ("given", "shown"),
    [
        ("plain text", "plain text"),
        (f"{ESC}]0;owned\x07", "\\x1b]0;owned\\x07"),
        (f"{ESC}[2J{ESC}[H", "\\x1b[2J\\x1b[H"),
        ("loading\rall good", "loading\\x0dall good"),
        ("two\nlines", "two\\x0alines"),
        ("a\tb", "a\\x09b"),
        ("a\x00b", "a\\x00b"),
        ("\x7f", "\\x7f"),
        ("\x9b31m", "\\x9b31m"),
        ("evil\N{RIGHT-TO-LEFT OVERRIDE}gnp.exe", "evil\\u202egnp.exe"),
        ("zero\N{ZERO WIDTH SPACE}width", "zero\\u200bwidth"),
        ("line\N{LINE SEPARATOR}separator", "line\\u2028separator"),
        ("lone\ud800surrogate", "lone\\ud800surrogate"),
        ("tag\U000e0041", "tag\\U000e0041"),
        ("héllo wörld ✓ 日本語", "héllo wörld ✓ 日本語"),
        (12, "12"),
        (None, "None"),
    ],
)
def test_one_line_of_text_from_outside(given: object, shown: str) -> None:
    assert render.safe_line(given) == shown


def test_a_line_from_outside_is_bounded_and_says_when_it_was_cut() -> None:
    assert render.safe_line("x" * 64, limit=64) == "x" * 64
    cut = render.safe_line("x" * 10_000, limit=64)
    assert len(cut) == 64
    assert cut.endswith("…")
    grown = render.safe_line(ESC * 100, limit=64)
    assert len(grown) == 64, "a value that grows when it is made safe is bounded as it is shown"
    assert ESC not in grown


@pytest.mark.parametrize(
    ("given", "shown"),
    [
        (b"plain\n", "plain\n"),
        (b"tab\there\n", "tab\there\n"),
        (b"windows\r\nline\r\n", "windows\nline\n"),
        (b"loading...\rall good\n", "loading...\\x0dall good\n"),
        (f"{ESC}[31mred{ESC}[0m\n".encode(), "\\x1b[31mred\\x1b[0m\n"),
        (b"\xff\xfe", "\\xff\\xfe"),
        (b"a\x00b", "a\\x00b"),
        ("héllo ✓\n".encode(), "héllo ✓\n"),
    ],
)
def test_what_a_sandbox_wrote_as_text_for_a_terminal(given: bytes, shown: str) -> None:
    assert render.safe_block(given) == shown


def test_no_byte_a_sandbox_can_write_becomes_a_control_character_on_a_terminal() -> None:
    shown = render.safe_block(bytes(range(256)) * 2)
    assert all(character in "\n\t" or character.isprintable() for character in shown)


def test_text_of_several_lines_from_outside_keeps_its_lines_and_nothing_hidden() -> None:
    given = f"one\r\ntwo\tand a tab\n{ESC}[31mthree\rfour\N{RIGHT-TO-LEFT OVERRIDE}\n"
    assert render.safe_text(given) == "one\ntwo\tand a tab\n\\x1b[31mthree\\x0dfour\\u202e\n"


# ------------------------------------------------------------------------------------------ the streams
def test_a_stream_made_lenient_writes_a_character_its_encoding_lacks_as_an_escape() -> None:
    """Where the encoding of a pipe is not UTF-8, a name must not be able to end a command that did its work."""
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="cp1252", errors="strict")
    name = "\N{CJK UNIFIED IDEOGRAPH-65E5} caf\N{LATIN SMALL LETTER E WITH ACUTE} \N{HORIZONTAL ELLIPSIS}"
    with pytest.raises(UnicodeEncodeError):
        stream.write(name)
    render.lenient(stream)
    stream.write(name)
    stream.flush()
    assert raw.getvalue() == b"\\u65e5 caf\xe9 \x85", "what the encoding has is written as it is"


def test_a_stream_that_is_not_the_interpreters_own_is_left_as_it_is() -> None:
    replaced = io.StringIO()
    render.lenient(replaced)
    replaced.write("\N{CJK UNIFIED IDEOGRAPH-65E5}")
    assert replaced.getvalue() == "\N{CJK UNIFIED IDEOGRAPH-65E5}"


# ------------------------------------------------------------------------------------- the credential
def test_a_protected_credential_is_taken_out_of_everything_that_is_written() -> None:
    secret = 'acf1_dev_"quoted\\key'
    render.protect(secret)
    try:
        assert render.scrub(f"Bearer {secret}!") == "Bearer [redacted]!"
        assert render.scrub_bytes(b"x" + secret.encode() + b"y") == b"x[redacted]y"
        assert secret not in render.safe_line(f"name {secret}")
        line = render.json_line({"message": f"you sent {secret}"})
        assert json.loads(line) == {"message": "you sent [redacted]"}, "also where JSON writes it with escapes"
    finally:
        render.unprotect()
    assert render.scrub(secret) == secret, "one invocation's credential is forgotten when it ends"


def test_a_credential_too_short_to_be_one_does_not_shred_every_message() -> None:
    render.protect("e")
    try:
        assert render.scrub("error: refused") == "error: refused"
    finally:
        render.unprotect()


# --------------------------------------------------------------------------------------------- JSON
def test_json_is_printable_ascii_whatever_the_platform_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    out = FakeStream(tty=True)
    monkeypatch.setattr(sys, "stdout", out)
    sent = {"name": HOSTILE, "note": "délai \x7f \N{LINE SEPARATOR} ✓", "n": 1.5, "nothing": None}
    render.write_json(sent)
    written = out.written
    assert all(byte == 0x0A or 0x20 <= byte < 0x7F for byte in written)
    assert json.loads(written) == sent, "and it is still the same document"


def test_one_line_of_json_is_one_line() -> None:
    line = render.json_line({"a": "x\ny", "b": [1, {"c": "\N{LINE SEPARATOR}"}]})
    assert "\n" not in line
    assert line == '{"a":"x\\ny","b":[1,{"c":"\\u2028"}]}'


# -------------------------------------------------------------------------------------------- tables
ROW = [SBX, "[bold red]boom[/bold red] [link=https://evil.example]click[/link]", ":warning:", "1"]


def table(monkeypatch: pytest.MonkeyPatch, *, tty: bool, no_color: bool = False) -> str:
    out = FakeStream(tty=tty)
    monkeypatch.setattr(sys, "stdout", out)
    if no_color:
        monkeypatch.setenv("NO_COLOR", "1")
    render.table(["SANDBOX", "NAME", "STATE", "GEN"], [ROW], empty="nothing")
    return out.written.decode()


def test_a_value_is_never_markup(monkeypatch: pytest.MonkeyPatch) -> None:
    shown = table(monkeypatch, tty=False)
    assert "[bold red]boom[/bold red]" in shown
    assert "[link=https://evil.example]click[/link]" in shown
    assert ":warning:" in shown, "nor the name of an emoji"


def test_no_colour_and_no_border_when_standard_output_is_not_a_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    shown = table(monkeypatch, tty=False)
    assert ESC not in shown
    assert shown.isascii(), "no line-drawing character"
    assert [line.split()[0] for line in shown.splitlines()] == ["SANDBOX", SBX], "and nothing between the rows"


def test_no_colour_and_no_border_when_no_color_is_set(monkeypatch: pytest.MonkeyPatch) -> None:
    shown = table(monkeypatch, tty=True, no_color=True)
    assert ESC not in shown
    assert shown.isascii()


def test_a_terminal_gets_a_header_rule(monkeypatch: pytest.MonkeyPatch) -> None:
    shown = table(monkeypatch, tty=True)
    assert "─" in shown


def test_an_empty_variable_named_no_color_does_not_count(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "")
    assert render.is_plain(FakeStream(tty=True)) is False
    monkeypatch.setenv("NO_COLOR", "0")
    assert render.is_plain(FakeStream(tty=True)) is True, "any value that is set and not empty counts"
    assert render.is_plain(FakeStream(tty=False)) is True


def test_a_pipe_gets_every_cell_whole(monkeypatch: pytest.MonkeyPatch) -> None:
    out = FakeStream(tty=False)
    monkeypatch.setattr(sys, "stdout", out)
    wide = ["x" * 60, "y" * 60, "z" * 60, "w" * 60]
    render.table(["A", "B", "C", "D"], [wide], empty="nothing")
    assert out.written.decode().splitlines()[1].split() == wide, "an identifier that was folded would be a wrong one"


def test_an_empty_table_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    out = FakeStream()
    monkeypatch.setattr(sys, "stdout", out)
    render.table(["A"], [], empty="no sandboxes")
    assert out.written == b"no sandboxes\n"


# ------------------------------------------------------------------------------------- guest output
def test_a_pipe_gets_the_exact_bytes_even_if_they_are_not_text(monkeypatch: pytest.MonkeyPatch) -> None:
    out = FakeStream(tty=False)
    monkeypatch.setattr(sys, "stdout", out)
    payload = b"\x1b[31mred\x1b[0m\xff\x00\r\n"
    render.write_guest_bytes(payload)
    assert out.written == payload


def test_a_terminal_gets_safe_text_that_ends_its_line(monkeypatch: pytest.MonkeyPatch) -> None:
    out = FakeStream(tty=True)
    monkeypatch.setattr(sys, "stdout", out)
    render.write_guest_bytes(b"\x1b]0;owned\x07done")
    assert out.written == b"\\x1b]0;owned\\x07done\n"


def test_raw_is_the_caller_insisting(monkeypatch: pytest.MonkeyPatch) -> None:
    out = FakeStream(tty=True)
    monkeypatch.setattr(sys, "stdout", out)
    render.write_guest_bytes(b"\x1b[1mbold", raw=True)
    assert out.written == b"\x1b[1mbold"


def test_the_other_stream_and_nothing_at_all(monkeypatch: pytest.MonkeyPatch) -> None:
    out, err = FakeStream(), FakeStream()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    render.write_guest_bytes(b"to-err", err=True)
    render.write_guest_bytes(b"")
    assert (out.written, err.written) == (b"", b"to-err")


# ------------------------------------------------------------------------------------- the commands
def hostile_sandbox() -> Json:
    return sandbox(
        HOSTILE,
        name=HOSTILE,
        notes=[HOSTILE],
        quarantined=HOSTILE,
        failure=failure(HOSTILE, message=HOSTILE),
        image={"alias": HOSTILE, "digest": HOSTILE},
        network={"mode": HOSTILE, "entries": [{"name": HOSTILE, "ports": [{"from": 1, "to": 2}]}]},
    )


@pytest.mark.parametrize("tty", [True, False], ids=["terminal", "pipe"])
@pytest.mark.parametrize("as_json", [True, False], ids=["json", "human"])
def test_no_view_of_a_sandbox_lets_a_control_character_through(cli: Cli, tty: bool, as_json: bool) -> None:
    flags = ["--json"] if as_json else []
    listed = cli.run(
        ["sandbox", "list", *flags], ex("GET", "/sandboxes", reply(200, page([hostile_sandbox()]))), tty=tty
    )
    shown = cli.run(
        ["sandbox", "inspect", SBX, *flags], ex("GET", f"/sandboxes/{SBX}", reply(200, hostile_sandbox())), tty=tty
    )
    for run in (listed, shown):
        assert run.exit_code == 0, run.stderr
        assert no_control_characters(run.stdout + run.stderr)
        assert "\\x1b" in run.stdout or "\\u001b" in run.stdout, "what was hidden is shown, not dropped"


def test_a_name_cannot_draw_a_second_row(cli: Cli) -> None:
    forged = sandbox(name=f"real\n{SBX}  forged  RUNNING")
    run = cli.run(["sandbox", "list"], ex("GET", "/sandboxes", reply(200, page([forged]))))
    assert len(run.stdout.splitlines()) == 2, "one header and one row"


def test_a_long_name_is_cut_in_a_table_and_an_identifier_is_not(cli: Cli) -> None:
    long = sandbox(name="n" * 5000)
    run = cli.run(["sandbox", "list"], ex("GET", "/sandboxes", reply(200, page([long]))))
    row = run.stdout.splitlines()[1].split()
    assert row[0] == SBX
    assert len(row[1]) == render.CELL_MAX
    assert row[1].endswith("…")


def test_a_message_of_the_platform_is_made_safe_in_an_error(cli: Cli) -> None:
    document = {"code": "PERMISSION_DENIED", "kind": "REFUSED", "retry": "NEVER"}
    document |= {"message": HOSTILE, "request_id": HOSTILE, "reason": HOSTILE}
    refused = reply(403, document, content_type="application/problem+json")
    for flags in ([], ["--json"], ["--verbose"]):
        run = cli.run(["sandbox", "inspect", SBX, *flags], ex("GET", f"/sandboxes/{SBX}", refused), tty=True)
        assert run.exit_code == 3
        assert no_control_characters(run.stderr)


def test_the_failure_of_an_operation_is_made_safe(cli: Cli) -> None:
    ended = operation("sandbox.start", "FAILED", effect="NOT_APPLIED", failure=failure(HOSTILE, message=HOSTILE))
    run = cli.run(
        ["sandbox", "start", SBX, "--generation", "1"],
        ex("POST", f"/sandboxes/{SBX}/start", reply(200, ended)),
        tty=True,
    )
    assert run.exit_code == 4
    assert no_control_characters(run.stderr)


def ran(stdout: bytes, stderr: bytes = b"") -> list[Exchange]:
    view = execution(stdout_bytes=len(stdout), stderr_bytes=len(stderr), note=HOSTILE)
    exchanges: list[Exchange] = [
        ex("POST", f"/sandboxes/{SBX}/executions", reply(200, done("execution.create", "execution", view)))
    ]
    for stream, data in (("stdout", stdout), ("stderr", stderr)):
        if data:
            body = chunk(base64.b64encode(data).decode(), size=len(data), stream=stream)
            exchanges.append(
                ex("GET", f"/executions/{EXE}/output", reply(200, body), query={"stream": stream, "offset": "0"})
            )
    return exchanges


RUN = ["exec", "run", SBX, "--generation", "1", "--", "cat", "file"]


def test_exec_run_shows_guest_output_as_safe_text_on_a_terminal(cli: Cli) -> None:
    run = cli.run(RUN, *ran(HOSTILE_BYTES, HOSTILE_BYTES), tty=True)
    assert run.exit_code == 0, run.stderr
    assert no_control_characters(run.stdout + run.stderr)
    assert "\\x1b]0;owned\\x07" in run.stdout
    assert "\\x1b]0;owned\\x07" in run.stderr, "standard error of the command goes to standard error, as safe"


def test_exec_run_writes_guest_output_to_a_pipe_byte_for_byte(cli: Cli) -> None:
    binary = bytes(range(256))
    run = cli.run(RUN, *ran(binary, HOSTILE_BYTES))
    assert run.exit_code == 0, run.stderr
    assert run.stdout_bytes == binary
    assert run.stderr_bytes == HOSTILE_BYTES


OUTPUT = ["exec", "output", EXE]


def output(data: bytes) -> list[Exchange]:
    body = chunk(base64.b64encode(data).decode(), size=len(data))
    return [ex("GET", f"/executions/{EXE}/output", reply(200, body))]


def test_exec_output_shows_safe_text_on_a_terminal_and_exact_bytes_in_a_pipe(cli: Cli) -> None:
    on_terminal = cli.run(OUTPUT, *output(HOSTILE_BYTES), tty=True)
    assert on_terminal.exit_code == 0, on_terminal.stderr
    assert no_control_characters(on_terminal.stdout)
    in_pipe = cli.run(OUTPUT, *output(HOSTILE_BYTES))
    assert in_pipe.stdout_bytes == HOSTILE_BYTES


def test_raw_output_to_a_terminal_is_refused_before_anything_is_asked(cli: Cli) -> None:
    run = cli.run([*OUTPUT, "--raw"], tty=True)
    assert run.exit_code == 2
    assert "escape sequences included" in run.stderr
    assert "--force" in run.stderr.splitlines()[-1]
    assert run.requests == []


def test_raw_output_to_a_terminal_takes_force(cli: Cli) -> None:
    run = cli.run([*OUTPUT, "--raw", "--force"], *output(HOSTILE_BYTES), tty=True)
    assert run.exit_code == 0, run.stderr
    assert run.stdout_bytes == HOSTILE_BYTES


def test_raw_output_to_a_pipe_needs_no_force(cli: Cli) -> None:
    run = cli.run([*OUTPUT, "--raw"], *output(HOSTILE_BYTES))
    assert run.exit_code == 0, run.stderr
    assert run.stdout_bytes == HOSTILE_BYTES
