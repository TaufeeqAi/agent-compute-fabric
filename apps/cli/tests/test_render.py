"""Rendering. Guest output is attacker-controlled; names and messages are data, never markup."""

from __future__ import annotations

import io
import json
from typing import Any

import pytest

from acf_cli import render
from acf_cli.errors import Rejected
from acf_cli.models import HostInfo, RunResult, SandboxView, SnapshotView
from factories import SANDBOX_ID, host_info, run_result, sandbox_view, snapshot_view


# ----------------------------------------------------------------------------- sanitizing
@pytest.mark.parametrize(
    ("raw", "shown"),
    [
        (b"plain text\n", "plain text\n"),
        (b"tab\there\n", "tab\there\n"),
        (b"\x1b]0;pwned\x07", "\\x1b]0;pwned\\x07"),  # OSC: would retitle the terminal
        (b"\x1b[2J\x1b[H", "\\x1b[2J\\x1b[H"),  # clear screen
        (b"loading...\rall good\n", "loading...\\x0dall good\n"),  # \r rewrites the line
        (b"a\x00b", "a\\x00b"),
        (b"\x08\x08\x08", "\\x08\\x08\\x08"),
        ("evil\N{RIGHT-TO-LEFT OVERRIDE}gnp.exe".encode(), "evil\\u202egnp.exe"),  # bidi override (Cf)
        ("zero\u200bwidth".encode(), "zero\\u200bwidth"),
        (b"\xff\xfe", "\\xff\\xfe"),  # not UTF-8: shown, not dropped
        (b"\x7f", "\\x7f"),  # DEL
        ("héllo wörld ✓".encode(), "héllo wörld ✓"),  # ordinary non-ASCII survives
    ],
)
def test_sanitize_for_terminal(raw: bytes, shown: str) -> None:
    assert render.sanitize_for_terminal(raw) == shown


def test_sanitized_output_contains_no_control_characters_at_all() -> None:
    every_byte = bytes(range(256))
    shown = render.sanitize_for_terminal(every_byte)
    assert all(ch in "\n\t" or ch.isprintable() for ch in shown)


class FakeStream(io.TextIOWrapper):
    """A text stream with a binary ``buffer`` whose ``isatty`` we control."""

    def __init__(self, *, tty: bool) -> None:
        self._raw = io.BytesIO()
        super().__init__(self._raw, encoding="utf-8", write_through=True)
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty

    @property
    def written(self) -> bytes:
        self.flush()
        return self._raw.getvalue()


def test_a_pipe_gets_the_exact_bytes_even_if_they_are_not_utf8(monkeypatch: pytest.MonkeyPatch) -> None:
    out = FakeStream(tty=False)
    monkeypatch.setattr("sys.stdout", out)
    payload = b"\x1b[31mred\x1b[0m\xff\x00\r\n"
    render.write_stream(payload, to_stderr=False, raw=False)
    assert out.written == payload


def test_a_terminal_gets_sanitized_text_with_a_final_newline(monkeypatch: pytest.MonkeyPatch) -> None:
    out = FakeStream(tty=True)
    monkeypatch.setattr("sys.stdout", out)
    render.write_stream(b"\x1b]0;pwned\x07done", to_stderr=False, raw=False)
    assert out.written == b"\\x1b]0;pwned\\x07done\n"


def test_raw_overrides_sanitizing_on_a_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    out = FakeStream(tty=True)
    monkeypatch.setattr("sys.stdout", out)
    render.write_stream(b"\x1b[1mbold", to_stderr=False, raw=True)
    assert out.written == b"\x1b[1mbold"


def test_stderr_stream_goes_to_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    out, err = FakeStream(tty=False), FakeStream(tty=False)
    monkeypatch.setattr("sys.stdout", out)
    monkeypatch.setattr("sys.stderr", err)
    render.write_stream(b"to-err", to_stderr=True, raw=False)
    assert (out.written, err.written) == (b"", b"to-err")


def test_empty_output_writes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    out = FakeStream(tty=True)
    monkeypatch.setattr("sys.stdout", out)
    render.write_stream(b"", to_stderr=False, raw=False)
    assert out.written == b""


def test_malformed_base64_decodes_to_nothing_rather_than_raising() -> None:
    run = RunResult.model_validate(run_result())
    broken = run.stdout.model_copy(update={"data_b64": "***not base64***"})
    assert render.decode_capture(broken) == b""
    assert render.decode_capture(run.stdout) == b"hello\n"


# ----------------------------------------------------------------------------- no markup injection
def test_names_are_data_not_rich_markup(capsys: pytest.CaptureFixture[str]) -> None:
    nasty = "[red]boom[/red] [link=https://evil.example]click[/link] [bold"
    view = SandboxView.model_validate(sandbox_view(name=nasty))
    render.render_sandboxes([view])
    render.render_sandbox(view)
    out = capsys.readouterr().out
    assert "[red]boom[/red]" in out
    assert "[link=https://evil.example]click[/link]" in out
    assert "\x1b" not in out, "no styling may be applied from data"


def test_error_messages_are_data_not_markup(capsys: pytest.CaptureFixture[str]) -> None:
    render.render_error(Rejected("bad [bold]thing[/bold]", hint="try [red]x[/red]", operation_id="op-12345678"))
    err = capsys.readouterr().err
    assert "bad [bold]thing[/bold]" in err
    assert "try [red]x[/red]" in err
    assert "op-12345678" in err


# ----------------------------------------------------------------------------- JSON mirrors the wire
def test_json_output_uses_wire_field_names(capsys: pytest.CaptureFixture[str]) -> None:
    view = SandboxView.model_validate(
        sandbox_view(failure={"class": "BACKEND_CRASH", "message": "vmm died", "side_effect": "possible"})
    )
    render.print_json(view)
    data: dict[str, Any] = json.loads(capsys.readouterr().out)
    assert data["failure"] == {"class": "BACKEND_CRASH", "message": "vmm died", "side_effect": "possible"}
    assert data["sandbox_id"] == SANDBOX_ID


def test_print_json_handles_dicts_and_lists_of_models(capsys: pytest.CaptureFixture[str]) -> None:
    snap = SnapshotView.model_validate(snapshot_view())
    render.print_json({"snapshots": [snap], "n": 1})
    data = json.loads(capsys.readouterr().out)
    assert data["n"] == 1
    assert data["snapshots"][0]["snapshot"]["snapshot_id"] == snap.snapshot.snapshot_id


# ----------------------------------------------------------------------------- run report
def test_run_report_lists_the_fields_the_milestone_requires(capsys: pytest.CaptureFixture[str]) -> None:
    run = RunResult.model_validate(run_result())
    render.render_run_report(run, verbose=False)
    err = capsys.readouterr().err
    for needle in (
        "run_id",
        run.run_id,
        "SUCCEEDED (exit 0)",
        "742 ms",
        "51.0 ms",
        "12.0 MiB",
        "stdout",
        "stderr",
        "evidence",
    ):
        assert needle in err, needle


def test_truncated_output_is_flagged_never_silently_cut(capsys: pytest.CaptureFixture[str]) -> None:
    truncated = run_result(
        stdout={
            "status": "TRUNCATED",
            "total_bytes": 5_000_000,
            "kept_bytes": 1_048_576,
            "data_b64": "",
            "artifact": None,
        }
    )
    render.render_run_report(RunResult.model_validate(truncated), verbose=False)
    err = capsys.readouterr().err
    assert "TRUNCATED" in err
    assert "kept 1.0 MiB of 4.8 MiB" in err


def test_resource_violations_are_always_shown_other_evidence_only_when_verbose(
    capsys: pytest.CaptureFixture[str],
) -> None:
    evidence = [
        {
            "resource": "memory",
            "configured": 4096,
            "effective": 4096,
            "observed_peak": 4096,
            "violation": "OOM_KILLED",
            "action_taken": "workload killed",
            "mechanism": "cgroup2 memory.max",
        },
        {
            "resource": "pids",
            "configured": 64,
            "effective": 64,
            "observed_peak": 3,
            "violation": None,
            "action_taken": "none",
            "mechanism": "guest rlimit",
        },
    ]
    run = RunResult.model_validate(run_result(outcome="FAILED", exit_code=None, signal=9, resource_evidence=evidence))
    render.render_run_report(run, verbose=False)
    quiet = capsys.readouterr().err
    assert "OOM_KILLED" in quiet
    assert "killed by signal 9" in quiet
    assert "pids" not in quiet
    render.render_run_report(run, verbose=True)
    assert "pids" in capsys.readouterr().err


def test_outcome_summary_variants() -> None:
    assert render.outcome_summary(RunResult.model_validate(run_result())) == "SUCCEEDED (exit 0)"
    assert (
        render.outcome_summary(RunResult.model_validate(run_result(outcome="FAILED", exit_code=2))) == "FAILED (exit 2)"
    )
    killed = RunResult.model_validate(run_result(outcome="FAILED", exit_code=None, signal=11))
    assert render.outcome_summary(killed) == "FAILED (killed by signal 11)"
    timed_out = RunResult.model_validate(run_result(outcome="TIMED_OUT", exit_code=None, signal=None))
    assert render.outcome_summary(timed_out) == "TIMED_OUT"


def test_cleanup_and_operation_lines(capsys: pytest.CaptureFixture[str]) -> None:
    render.render_cleanup("FAILED: boom. finish with: acf-local sandbox destroy sbx-x")
    render.render_operation_lines({"create": "op-aaaaaaaa", "exec": "op-bbbbbbbb"})
    render.render_operation_lines({})
    err = capsys.readouterr().err
    assert "cleanup: FAILED: boom" in err
    assert "operations: create=op-aaaaaaaa, exec=op-bbbbbbbb" in err


# ----------------------------------------------------------------------------- tables and host info
def test_empty_listings_say_so(capsys: pytest.CaptureFixture[str]) -> None:
    render.render_sandboxes([])
    render.render_snapshots([])
    out = capsys.readouterr().out
    assert "no sandboxes" in out
    assert "no snapshots" in out


def test_host_info_warns_in_quarantine_mode(capsys: pytest.CaptureFixture[str]) -> None:
    render.render_host_info(
        HostInfo.model_validate(host_info(mode="read_only_quarantine", journal_integrity="CORRUPT"))
    )
    out = capsys.readouterr().out
    assert "read_only_quarantine" in out
    assert "mutations are refused" in out


def test_flatten_metrics() -> None:
    flat = render.flatten_metrics({"gauges": {"live_sandboxes": 2}, "counters": {'ops{status="FAILED"}': 4, "a": 1}})
    assert flat == [("counters.a", 1), ('counters.ops{status="FAILED"}', 4), ("gauges.live_sandboxes", 2)]
