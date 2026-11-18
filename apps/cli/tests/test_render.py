"""Rendering. Guest output is attacker-controlled; names and messages are data, never markup; an unknown
word of a closed vocabulary is shown as unknown, never as a known one."""

from __future__ import annotations

import io
import json
from typing import Any

import pytest

import factories as f
from acf_cli import render
from acf_cli.errors import HostUnreachable
from acf_cli.responses import (
    AsOf,
    CursorView,
    HostChange,
    HostInfo,
    OperationView,
    Refusal,
    RunResult,
    SandboxView,
    SnapshotView,
)
from acf_cli.wire import Unrecognized

AS_OF = AsOf.model_validate(f.AS_OF)


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
    assert render.decode_base64("***not base64***") == b""
    assert render.decode_base64("aGVsbG8K") == b"hello\n"
    assert render.decode_base64("") == b""


# ----------------------------------------------------------------------------- no markup injection
def test_names_are_data_not_rich_markup(capsys: pytest.CaptureFixture[str]) -> None:
    nasty = "[red]boom[/red] [link=https://evil.example]click[/link] [bold"
    view = SandboxView.model_validate(f.sandbox_view(name=nasty))
    render.render_sandboxes([view])
    render.render_sandbox(view)
    out = capsys.readouterr().out
    assert "[red]boom[/red]" in out
    assert "[link=https://evil.example]click[/link]" in out
    assert "\x1b" not in out, "no styling may be applied from data"


def test_error_messages_are_data_not_markup(capsys: pytest.CaptureFixture[str]) -> None:
    render.render_error(HostUnreachable("bad [bold]thing[/bold]", hint="try [red]x[/red]", operation_id="op-12345678"))
    err = capsys.readouterr().err
    assert "error: bad [bold]thing[/bold]" in err
    assert "hint: try [red]x[/red]" in err
    assert "operation: op-12345678" in err


def test_a_long_hint_is_one_line_so_a_command_in_it_can_be_copied(capsys: pytest.CaptureFixture[str]) -> None:
    hint = "ask the host: acf-local operation get op-0123456789abcdef0123456789abcdef --wait " + "x" * 200
    render.render_error(HostUnreachable("lost", hint=hint))
    lines = capsys.readouterr().err.splitlines()
    assert any(hint in line for line in lines), "prose is never re-wrapped"


# ----------------------------------------------------------------------------- refusals
def refusal(
    failure_class: str = "STATE_CONFLICT", retry: str = "AFTER_CHANGE", message: str = "sandbox is busy"
) -> Refusal:
    return Refusal.model_validate({"class": failure_class, "retry": retry, "message": message})


def test_a_refusal_shows_its_class_its_retry_advice_and_that_nothing_happened(
    capsys: pytest.CaptureFixture[str],
) -> None:
    render.render_refusal(refusal(), AS_OF)
    captured = capsys.readouterr()
    assert captured.out == "", "a refusal is not data"
    assert "refused: STATE_CONFLICT - sandbox is busy" in captured.err
    assert "retry: AFTER_CHANGE - it can be accepted once the target, the host or the request changes" in captured.err
    assert "nothing was applied, and no operation was recorded" in captured.err
    assert f"as of: {f.LINEAGE}:41" in captured.err


@pytest.mark.parametrize(
    ("advice", "meaning"),
    [
        ("SAME_REQUEST_LATER", "the host cannot take it now"),
        ("AFTER_CHANGE", "once the target, the host or the request changes"),
        ("NEVER", "will never be accepted"),
    ],
)
def test_every_retry_advice_is_explained(advice: str, meaning: str, capsys: pytest.CaptureFixture[str]) -> None:
    render.render_refusal(refusal(retry=advice), None)
    assert meaning in capsys.readouterr().err


def test_an_unknown_class_and_unknown_advice_are_shown_as_unknown(capsys: pytest.CaptureFixture[str]) -> None:
    render.render_refusal(refusal("QUOTA_EXCEEDED", "AFTER_PAYMENT"), None)
    err = capsys.readouterr().err
    assert "QUOTA_EXCEEDED (not recognized by this client)" in err
    assert "AFTER_PAYMENT (not recognized by this client)" in err
    assert "as of" not in err


# ----------------------------------------------------------------------------- operations
def operation(state: str = "SUCCEEDED", result: dict[str, Any] | None = None, **over: Any) -> OperationView:
    return OperationView.model_validate(f.operation_view(state, result, **over))


def test_an_operation_shows_state_effect_and_cleanup(capsys: pytest.CaptureFixture[str]) -> None:
    render.render_operation(operation("FAILED", cleanup="PENDING", effect="MAY_BE_APPLIED"), AS_OF)
    out = capsys.readouterr().out
    assert f"{f.OPERATION_ID} (sandbox.create)" in out
    assert "FAILED" in out
    assert "MAY_BE_APPLIED - it may have been applied" in out
    assert "PENDING - something the operation created remains and still holds its lease" in out
    assert "DEPENDENCY_UNAVAILABLE: backend down (side effect: POSSIBLE)" in out
    assert f"{f.LINEAGE}:41" in out


@pytest.mark.parametrize(
    ("effect", "meaning"),
    [
        ("APPLIED", "the operation's effect is in place"),
        ("NOT_APPLIED", "nothing was applied; a new operation for the same intent is safe"),
        ("MAY_BE_APPLIED", "a new operation for the same intent is not known to be safe"),
    ],
)
def test_every_effect_is_explained(effect: str, meaning: str, capsys: pytest.CaptureFixture[str]) -> None:
    render.render_operation(operation("FAILED", effect=effect), None)
    assert meaning in capsys.readouterr().out


def test_an_operation_that_has_not_ended_states_no_effect(capsys: pytest.CaptureFixture[str]) -> None:
    render.render_operation(operation("IN_PROGRESS"), None)
    out = capsys.readouterr().out
    assert "IN_PROGRESS" in out
    assert "not stated before it ends" in out
    assert "cleanup" not in out, "cleanup is shown when the host states one"


def test_unknown_is_shown_as_unknown_with_what_it_means(capsys: pytest.CaptureFixture[str]) -> None:
    render.render_operation(operation("UNKNOWN", failure=f.failure("UNKNOWN_OUTCOME", "no result")), None)
    out = capsys.readouterr().out
    assert "UNKNOWN" in out
    assert "MAY_BE_APPLIED" in out
    assert "SUCCEEDED" not in out
    assert "FAILED" not in out.replace("UNKNOWN_OUTCOME", "")


def test_words_this_client_does_not_know_are_marked_everywhere_in_an_operation(
    capsys: pytest.CaptureFixture[str],
) -> None:
    view = operation(
        "SUSPENDED", effect="DEFERRED", cleanup="ESCROWED", cancelled_by="SCHEDULER", operation_type="volume.attach"
    )
    render.render_operation(view, None)
    out = capsys.readouterr().out
    for word in ("SUSPENDED", "DEFERRED", "ESCROWED", "SCHEDULER", "volume.attach"):
        assert f"{word} (not recognized by this client)" in out
    render.render_operations([view])
    table = capsys.readouterr().out
    assert "SUSPENDED (not recognized by this client)" in table


def test_shown_marks_only_what_is_unrecognized() -> None:
    assert render.shown(Unrecognized("NEW_WORD")) == "NEW_WORD (not recognized by this client)"
    assert render.shown(operation().state) == "SUCCEEDED"
    assert render.shown("plain text") == "plain text"


@pytest.mark.parametrize(
    ("result", "summary"),
    [
        (f.sandbox_body(state="PROVISIONING"), f"sandbox {f.SANDBOX_ID} generation 1 (PROVISIONING)"),
        (f.snapshot_body(), f"snapshot {f.SNAPSHOT_ID}@1 (READY)"),
        (f.run_body(exit_code=3), f"run {f.RUN_ID}: EXITED (exit 3)"),
        (f.host_change_body(mode="DRAINING"), "host mode DRAINING"),
        (f.host_change_body(note="the execution ended Succeeded"), "the execution ended Succeeded"),
        (None, "-"),
        ({"type": "volume", "data": {"id": "vol-1"}}, "volume (a result type not recognized by this client)"),
    ],
)
def test_result_summary(result: dict[str, Any] | None, summary: str) -> None:
    assert render.result_summary(operation(result=result)) == summary


def test_the_operation_table(capsys: pytest.CaptureFixture[str]) -> None:
    render.render_operations([operation(), operation("CANCELLED", operation_type="exec.run")])
    out = capsys.readouterr().out
    assert "OPERATION" in out
    assert "sandbox.create" in out
    assert "exec.run" in out
    assert "CANCELLED" in out
    render.render_operations([])
    assert "no operations" in capsys.readouterr().out


# ----------------------------------------------------------------------------- sandboxes and snapshots
def test_a_sandbox_shows_its_network_owner_expiry_and_revision(capsys: pytest.CaptureFixture[str]) -> None:
    view = f.sandbox_view(quarantined="ownership not provable", secret_bearing=True, notes=["restored twice"])
    view["resources"]["network"] = f.network_allowlist()
    render.render_sandbox(SandboxView.model_validate(view))
    out = capsys.readouterr().out
    assert "allowlist: pypi.org:443, 198.51.100.0/24:5432-5433" in out
    assert "local-operator/default" in out
    assert f.LATER in out
    assert "ownership not provable" in out
    assert "secret-bearing    yes" in out
    assert "note: restored twice" in out
    assert "revision          11" in out


def test_the_sandbox_table_flags_quarantine_and_unknown_states(capsys: pytest.CaptureFixture[str]) -> None:
    views = [
        SandboxView.model_validate(f.sandbox_view(quarantined="residue")),
        SandboxView.model_validate(f.sandbox_view(sandbox_id=f.OTHER_SANDBOX_ID, state="HIBERNATING", name=None)),
    ]
    render.render_sandboxes(views)
    out = capsys.readouterr().out
    assert "READY [quarantined]" in out
    assert "HIBERNATING (not recognized by this client)" in out
    render.render_sandboxes([])
    assert "no sandboxes" in capsys.readouterr().out


def test_a_snapshot_says_why_it_cannot_be_restored_here(capsys: pytest.CaptureFixture[str]) -> None:
    view = SnapshotView.model_validate(
        f.snapshot_view(incompatible=["another backend version"], secret_refs=["ci-token"])
    )
    render.render_snapshot(view)
    out = capsys.readouterr().out
    assert f"{f.SNAPSHOT_ID} (generation 1)" in out
    assert "3.0 MiB" in out
    assert "cannot be restored on this host: another backend version" in out
    assert "ci-token" in out
    render.render_snapshots([view])
    assert "READY [incompatible]" in capsys.readouterr().out
    render.render_snapshots([])
    assert "no snapshots" in capsys.readouterr().out


def test_a_listing_footer_gives_the_cursor_and_says_whether_more_follows(capsys: pytest.CaptureFixture[str]) -> None:
    cursor = CursorView(lineage=f.LINEAGE, sequence=17)
    render.render_listing_footer(2, cursor, more=True, as_of=AS_OF)
    more = capsys.readouterr()
    assert more.out == "", "the footer is for people: it never mixes into data on stdout"
    assert f"2 record(s); listing more follow; cursor {f.LINEAGE}:17" in more.err
    assert f"--changed-since {f.LINEAGE}:17" in more.err
    render.render_listing_footer(0, cursor, more=False, as_of=None)
    done = capsys.readouterr().err
    assert "listing complete" in done
    assert "continue with" not in done


# ----------------------------------------------------------------------------- the host
def test_host_info_shows_what_a_caller_depends_on(capsys: pytest.CaptureFixture[str]) -> None:
    render.render_host_info(HostInfo.model_validate(f.host_info()))
    out = capsys.readouterr().out
    assert "acf.host/2" in out
    assert "firecracker v1.17.0" in out
    assert "default@2.0.0#cdcdcdcdcdcd" in out
    assert "none, allowlist" in out
    assert "30.0 s" in out  # wait max
    assert "5m00s" in out  # acceptance horizon
    assert "1d00h" in out  # operation retention
    assert "warning" not in out


def test_host_info_warns_when_the_host_is_not_serving_and_says_why(capsys: pytest.CaptureFixture[str]) -> None:
    info = f.host_info(
        mode="CONTAINMENT",
        containment_reasons=[{"reason": "store_regression", "detail": "a marker is ahead of the store"}],
    )
    render.render_host_info(HostInfo.model_validate(info))
    out = capsys.readouterr().out
    assert "warning: the host is CONTAINMENT" in out
    assert "store_regression: a marker is ahead of the store" in out
    render.render_host_info(HostInfo.model_validate(f.host_info(mode="READ_ONLY", read_only_reason="store corrupt")))
    assert "read-only: store corrupt" in capsys.readouterr().out
    render.render_host_info(HostInfo.model_validate(f.host_info(mode="MAINTENANCE")))
    assert "the host is MAINTENANCE (not recognized by this client)" in capsys.readouterr().out


def test_a_host_change_is_one_line(capsys: pytest.CaptureFixture[str]) -> None:
    change = HostChange.model_validate({"mode": "DRAINING", "profile": f.profile_id(), "note": "noted"})
    assert (
        render.host_change_summary(change) == "host mode DRAINING; profile in force default@2.0.0#cdcdcdcdcdcd; noted"
    )
    assert render.host_change_summary(HostChange.model_validate({})) == "-"
    render.render_host_change(change)
    assert "host mode DRAINING" in capsys.readouterr().out


def test_metrics_are_flattened_to_dotted_names(capsys: pytest.CaptureFixture[str]) -> None:
    data = {"gauges": {"live_sandboxes": 1}, "counters": {"runs": {"status=Exited": 4}}}
    assert render.flatten_metrics(data) == [("counters.runs.status=Exited", 4), ("gauges.live_sandboxes", 1)]
    render.render_metrics(data)
    assert "counters.runs.status=Exited" in capsys.readouterr().out
    render.render_metrics({})
    assert "no metrics yet" in capsys.readouterr().out
    render.render_metrics(None)
    assert "no metrics yet" in capsys.readouterr().out


# ----------------------------------------------------------------------------- executions
def run(**over: Any) -> RunResult:
    return RunResult.model_validate(f.run_result(**over))


def test_a_run_report_goes_to_stderr_and_labels_what_the_guest_said(capsys: pytest.CaptureFixture[str]) -> None:
    render.render_run_report(run(artifacts=[f.artifact()]), verbose=False)
    captured = capsys.readouterr()
    assert captured.out == "", "stdout belongs to the guest's own output"
    assert f.RUN_ID in captured.err
    assert "EXITED (exit 0)  [reported by the guest]" in captured.err
    assert "default@2.0.0#cdcdcdcdcdcd" in captured.err
    assert f"artifact {f.ARTIFACT_ID}" in captured.err


def test_a_run_report_can_be_the_data_itself(capsys: pytest.CaptureFixture[str]) -> None:
    render.render_run_report(run(), verbose=False, to_stderr=False)
    captured = capsys.readouterr()
    assert f.RUN_ID in captured.out
    assert captured.err == ""


@pytest.mark.parametrize(
    ("over", "summary"),
    [
        ({}, "EXITED (exit 0)"),
        ({"exit_code": 137}, "EXITED (exit 137)"),
        ({"status": "SIGNALED", "exit_code": None, "signal": 9}, "SIGNALED (signal 9)"),
        ({"status": "TIMED_OUT", "exit_code": None}, "TIMED_OUT"),
        ({"status": "OOM_KILLED", "exit_code": None}, "OOM_KILLED (not recognized by this client)"),
    ],
)
def test_run_summary(over: dict[str, Any], summary: str) -> None:
    assert render.run_summary(run(**over)) == summary


def test_limits_that_were_reached_are_always_shown_and_the_rest_only_when_asked(
    capsys: pytest.CaptureFixture[str],
) -> None:
    evidence = [
        {**f.run_result()["resource_evidence"][0], "resource": "runtime_ms", "violated": False},
        {
            "resource": "stdout_bytes",
            "configured": 10,
            "effective": 10,
            "observed_peak": 5000,
            "violated": True,
            "action_taken": "truncated; remainder drained and counted",
            "mechanism": "guest capture cap, re-enforced by host",
        },
    ]
    result = f.run_result(resource_evidence=evidence)
    result["stdout"] = f.output_capture(b"0123456789", status="TRUNCATED", total_bytes=5000)
    truncated = RunResult.model_validate(result)
    render.render_run_report(truncated, verbose=False)
    quiet = capsys.readouterr().err
    assert "stdout_bytes: configured 10, observed peak 5000 - LIMIT REACHED" in quiet
    assert "runtime_ms" not in quiet
    assert "[TRUNCATED: kept 10 B of 4.9 KiB]" in quiet
    render.render_run_report(truncated, verbose=True)
    assert "runtime_ms: configured 60000, observed peak 12 - ok" in capsys.readouterr().err


def test_the_host_backstop_and_notes_are_shown(capsys: pytest.CaptureFixture[str]) -> None:
    report = run(
        status="TIMED_OUT", exit_code=None, host_backstop_fired=True, runtime_ended=True, note="ended by the host"
    )
    render.render_run_report(report, verbose=False)
    err = capsys.readouterr().err
    assert "host backstop" in err
    assert "ended by the host" in err


# ----------------------------------------------------------------------------- JSON
def test_json_output_is_one_document_with_non_ascii_preserved(capsys: pytest.CaptureFixture[str]) -> None:
    render.print_json({"name": "höst", "items": [1, 2], "nested": {"ok": True}})
    out = capsys.readouterr().out
    assert json.loads(out) == {"name": "höst", "items": [1, 2], "nested": {"ok": True}}
    assert "höst" in out
    assert out.endswith("}\n")


def test_a_note_is_one_labelled_line_on_stderr(capsys: pytest.CaptureFixture[str]) -> None:
    render.render_note("cleanup", "destroyed sbx-1")
    captured = capsys.readouterr()
    assert (captured.out, captured.err) == ("", "cleanup: destroyed sbx-1\n")


def test_a_runtime_the_host_ended_without_the_backstop_is_shown(capsys: pytest.CaptureFixture[str]) -> None:
    render.render_run_report(run(runtime_ended=True), verbose=False)
    assert "ended by the host as part of this execution" in capsys.readouterr().err
