"""Human-readable rendering and machine-readable (JSON) output.

Two rules matter more than prettiness:

1. **Guest output is attacker-controlled.** A workload can print ANSI/OSC escape sequences that
   retitle a terminal, rewrite earlier lines (``\\r``), or hide text with bidi overrides. When a
   stream is going to a *terminal* it is sanitized (control/format characters shown as visible
   escapes); when it goes to a pipe or file the bytes are passed through untouched, byte-exact.
2. **No markup interpretation of data.** Every dynamic value goes through ``rich.text.Text``, so a
   sandbox *name* like ``[red]x`` can never change how the table renders.

``--json`` output mirrors the wire contract (field names, ``class`` rather than ``error_class``) so
scripts see the same shapes the schemas describe.
"""

from __future__ import annotations

import base64
import binascii
import json
import sys
import unicodedata
from collections.abc import Iterable, Sequence
from typing import Any

from pydantic import BaseModel
from rich.console import Console
from rich.table import Table
from rich.text import Text

from acf_cli.errors import AcfCliError
from acf_cli.models import (
    HostInfo,
    OperationStatus,
    OperationView,
    OutputCapture,
    ResponseEnvelope,
    RunResult,
    SandboxView,
    SnapshotView,
)
from acf_cli.units import format_bytes, format_ms

_KEEP = {"\n", "\t"}
_LATIN1_LIMIT = 0x100


def make_console(*, stderr: bool = False) -> Console:
    """A console bound to the *current* ``sys.stdout``/``sys.stderr`` (so test runners can capture it)."""
    stream = sys.stderr if stderr else sys.stdout
    width = None if stream.isatty() else 140  # do not wrap tables when piped
    return Console(file=stream, width=width, highlight=False, emoji=False, markup=False, soft_wrap=False)


def prose(console: Console, text: Text) -> None:
    """Print one logical line of prose **without inserting line breaks**.

    Messages and hints routinely contain a command the operator will copy
    (``acf-local sandbox destroy sbx-…``). Letting rich re-wrap such a line at the console width
    would split the command in half, so prose is soft-wrapped: the terminal may fold it visually,
    but the bytes on the stream stay one line. Tables keep rich's folding, which is what you want
    for columns.
    """
    console.print(text, soft_wrap=True)


# ----------------------------------------------------------------------------- JSON
def to_jsonable(obj: Any) -> Any:  # noqa: ANN401 - recursive structural conversion
    if isinstance(obj, BaseModel):
        return obj.model_dump(mode="json", by_alias=True)
    if isinstance(obj, dict):
        return {k: to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list | tuple):
        return [to_jsonable(v) for v in obj]
    return obj


def print_json(obj: Any) -> None:  # noqa: ANN401
    sys.stdout.write(json.dumps(to_jsonable(obj), indent=2, sort_keys=False, ensure_ascii=False) + "\n")
    sys.stdout.flush()


# ----------------------------------------------------------------------------- untrusted bytes
def decode_capture(cap: OutputCapture) -> bytes:
    """The bytes the host kept for a stream. A malformed base64 body is a host bug and decodes to nothing."""
    try:
        return base64.b64decode(cap.data_b64, validate=True)
    except (binascii.Error, ValueError):
        return b""


def sanitize_for_terminal(data: bytes) -> str:
    """Make arbitrary bytes safe to show on a terminal.

    Newlines and tabs survive. Every other control (``Cc``) or format (``Cf``, e.g. bidi overrides)
    character, and every undecodable byte, is replaced with a visible escape.
    """
    out: list[str] = []
    for ch in data.decode("utf-8", errors="backslashreplace"):
        if ch in _KEEP:
            out.append(ch)
        elif unicodedata.category(ch) in {"Cc", "Cf"}:
            cp = ord(ch)
            out.append(f"\\x{cp:02x}" if cp < _LATIN1_LIMIT else f"\\u{cp:04x}")
        else:
            out.append(ch)
    return "".join(out)


def write_stream(data: bytes, *, to_stderr: bool, raw: bool) -> None:
    """Relay guest output. Terminal + not ``raw`` => sanitized text; otherwise exact bytes."""
    stream = sys.stderr if to_stderr else sys.stdout
    if not data:
        return
    if stream.isatty() and not raw:
        text = sanitize_for_terminal(data)
        stream.write(text if text.endswith("\n") else text + "\n")
    else:
        buf = getattr(stream, "buffer", None)
        if buf is not None:
            buf.write(data)
        else:  # pragma: no cover - exotic stream without a buffer
            stream.write(data.decode("utf-8", errors="replace"))
    stream.flush()


# ----------------------------------------------------------------------------- errors
def render_error(err: AcfCliError) -> None:
    console = make_console(stderr=True)
    prose(console, Text.assemble(("error: ", "bold red"), Text(err.message)))
    if err.operation_id:
        prose(console, Text.assemble(("  operation: ", "dim"), Text(err.operation_id)))
    if err.hint:
        prose(console, Text.assemble(("  hint: ", "dim"), Text(err.hint)))


# ----------------------------------------------------------------------------- tables
def _t(value: object) -> Text:
    return Text("" if value is None else str(value))


def _table(title: str | None, columns: Sequence[str]) -> Table:
    table = Table(title=title, title_justify="left", header_style="bold", show_edge=False, pad_edge=False)
    for col in columns:
        table.add_column(col, no_wrap=True, overflow="fold")
    return table


def render_sandboxes(items: Iterable[SandboxView]) -> None:
    table = _table(None, ["ID", "NAME", "GEN", "STATE", "VCPU", "MEM", "DISK", "IMAGE", "UPDATED"])
    rows = 0
    for s in items:
        rows += 1
        table.add_row(
            _t(s.sandbox_id),
            _t(s.name or "-"),
            _t(s.generation),
            _t(s.state),
            _t(s.resources.vcpus),
            _t(f"{s.resources.memory_mib} MiB"),
            _t(f"{s.resources.disk_mib} MiB"),
            _t(s.image.alias or s.image.image_id[:19]),
            _t(s.updated),
        )
    console = make_console()
    console.print(table if rows else Text("no sandboxes"))


def _resources_line(s: SandboxView) -> str:
    r = s.resources
    return f"{r.vcpus} vCPU, {r.memory_mib} MiB RAM, {r.disk_mib} MiB disk, network={r.network}"


def render_sandbox(s: SandboxView) -> None:
    console = make_console()
    console.print(
        _kv_table(
            [
                ("sandbox", s.sandbox_id),
                ("name", s.name or "-"),
                ("generation", s.generation),
                ("state", s.state),
                ("resources", _resources_line(s)),
                ("image", f"{s.image.alias or '-'}  {s.image.image_id}"),
                ("process", f"pid {s.process.pid} (start {s.process.start_time_ticks})" if s.process else "-"),
                ("security profile", s.security_profile_id),
                ("last run", s.last_run or "-"),
                (
                    "restored from",
                    f"{s.source_snapshot.snapshot_id} (gen {s.source_snapshot.snapshot_generation})"
                    if s.source_snapshot
                    else "-",
                ),
                ("failure", f"{s.failure.error_class}: {s.failure.message}" if s.failure else "-"),
                ("quarantined", s.quarantined or "-"),
                ("updated", s.updated),
            ]
        )
    )
    for note in s.notes:
        prose(console, Text.assemble(("note: ", "dim"), Text(note)))


def render_snapshots(items: Iterable[SnapshotView]) -> None:
    table = _table(None, ["ID", "NAME", "STATE", "SIZE", "SOURCE", "RESTORES", "CREATED"])
    rows = 0
    for s in items:
        rows += 1
        src = f"{s.source_sandbox[0]}@{s.source_sandbox[1]}" if s.source_sandbox else "-"
        table.add_row(
            _t(s.snapshot.snapshot_id),
            _t(s.name or "-"),
            _t(s.state),
            _t(format_bytes(s.size_bytes)),
            _t(src),
            _t(s.restore_count),
            _t(s.created),
        )
    console = make_console()
    console.print(table if rows else Text("no snapshots"))


def render_snapshot(s: SnapshotView) -> None:
    console = make_console()
    console.print(
        _kv_table(
            [
                ("snapshot", f"{s.snapshot.snapshot_id} (generation {s.snapshot.snapshot_generation})"),
                ("name", s.name or "-"),
                ("state", s.state),
                ("size", format_bytes(s.size_bytes)),
                (
                    "source sandbox",
                    f"{s.source_sandbox[0]} (generation {s.source_sandbox[1]})" if s.source_sandbox else "-",
                ),
                ("manifest digest", s.manifest_digest or "-"),
                ("restores", s.restore_count),
                ("created", s.created),
                ("failure", f"{s.failure.error_class}: {s.failure.message}" if s.failure else "-"),
            ]
        )
    )


def render_host_info(h: HostInfo) -> None:
    console = make_console()
    console.print(
        _kv_table(
            [
                ("host agent", f"{h.version} ({h.protocol})"),
                ("instance", h.instance_id),
                ("mode", h.mode),
                ("backend", f"{h.backend.name} {h.backend.version}"),
                ("security profile", h.backend.security_profile_id),
                ("policy", h.policy.short()),
                ("journal", h.journal_integrity),
                ("sandboxes", h.live_sandboxes),
                ("snapshots", h.snapshots),
                ("network modes", ", ".join(h.capabilities.network_modes)),
                ("max vCPUs", h.capabilities.max_vcpus),
            ]
        )
    )
    if h.mode != "normal":
        prose(
            console,
            Text.assemble(
                ("warning: ", "bold yellow"),
                Text(f"host is in {h.mode} mode: mutations are refused until the journal is repaired"),
            ),
        )


def _kv_table(rows: Sequence[tuple[str, object]]) -> Table:
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold", no_wrap=True)
    table.add_column(overflow="fold")
    for key, value in rows:
        table.add_row(_t(key), _t(value))
    return table


# ----------------------------------------------------------------------------- run report
def _stream_line(name: str, cap: OutputCapture) -> str:
    flags = (
        ""
        if cap.status == "COMPLETE"
        else f" [{cap.status}: kept {format_bytes(cap.kept_bytes)} of {format_bytes(cap.total_bytes)}]"
    )
    art = f"  artifact {cap.artifact.artifact_id} {cap.artifact.content_digest or ''}".rstrip() if cap.artifact else ""
    return f"{name:<8}{format_bytes(cap.total_bytes)}{flags}{art}"


def outcome_summary(run: RunResult) -> str:
    if run.exit_code is not None:
        return f"{run.outcome} (exit {run.exit_code})"
    if run.signal is not None:
        return f"{run.outcome} (killed by signal {run.signal})"
    return run.outcome


def render_run_report(run: RunResult, *, verbose: bool) -> None:
    """The structured result of one run — everything the Phase 1 milestone asks for, on stderr."""
    console = make_console(stderr=True)
    m = run.metrics
    lines: list[tuple[str, object]] = [
        ("run_id", run.run_id),
        ("sandbox", f"{run.sandbox_id} (generation {run.generation})"),
        ("outcome", outcome_summary(run)),
        ("wall time", format_ms(m.wall_ms)),
        ("cpu time", f"{m.cpu_usage_usec / 1000:.1f} ms" if m.cpu_usage_usec is not None else "n/a"),
        ("peak memory", format_bytes(m.memory_peak_bytes) if m.memory_peak_bytes is not None else "n/a"),
        ("stdout", _stream_line("", run.stdout).strip()),
        ("stderr", _stream_line("", run.stderr).strip()),
        ("evidence", run.evidence_status),
        ("policy", run.policy_id.short()),
        ("image", run.image_id),
    ]
    if run.note:
        lines.append(("note", run.note))
    console.print(_kv_table(lines))
    violations = [e for e in run.resource_evidence if e.violation]
    shown = run.resource_evidence if verbose else violations
    for e in shown:
        status = f"VIOLATION {e.violation}: {e.action_taken}" if e.violation else "ok"
        prose(
            console,
            Text(
                f"  {e.resource}: configured {e.configured}, observed peak {e.observed_peak} — {status} [{e.mechanism}]"
            ),
        )
    for art in run.artifacts:
        size = format_bytes(art.byte_size or 0)
        prose(console, Text(f"  artifact {art.artifact_id}  {art.kind:<7} {art.content_digest or '-'}  {size}"))


def render_cleanup(text: str) -> None:
    console = make_console(stderr=True)
    tag = ("cleanup: ", "bold red") if text.startswith(("FAILED", "skipped")) else ("cleanup: ", "dim")
    prose(console, Text.assemble(tag, Text(text)))


def render_operation_lines(ops: dict[str, str]) -> None:
    if not ops:
        return
    console = make_console(stderr=True)
    prose(console, Text("operations: " + ", ".join(f"{step}={op}" for step, op in ops.items()), style="dim"))


# ----------------------------------------------------------------------------- operations
_STATUS_GUIDANCE = {
    OperationStatus.UNKNOWN: "The host cannot yet say if this was applied. Do NOT re-run it; observe again shortly.",
    OperationStatus.ACCEPTED: "Accepted and not yet started. Observe it again shortly.",
    OperationStatus.IN_PROGRESS: "Still running. Observe it again shortly (or add --wait).",
    OperationStatus.REJECTED: "Refused before anything changed.",
    OperationStatus.CONFLICT: "Refused: the resource changed since it was read. Nothing was changed.",
}


def result_summary(env: ResponseEnvelope) -> str:
    """One line saying what an operation produced, without dumping the payload."""
    data = env.body()
    if isinstance(data, RunResult):
        return f"run {data.run_id}: {outcome_summary(data)}"
    if isinstance(data, SandboxView):
        return f"sandbox {data.sandbox_id} generation {data.generation} ({data.state})"
    if isinstance(data, SnapshotView):
        return f"snapshot {data.snapshot.snapshot_id} ({data.state})"
    if isinstance(data, OperationView):
        return f"operation {data.operation_id} ({data.status})"
    return env.result.type if env.result is not None else "-"


def render_operation(env: ResponseEnvelope) -> None:
    """What the host knows about one operation (the answer to ``operation get``)."""
    console = make_console()
    rows: list[tuple[str, object]] = [
        ("operation", env.operation_id or "-"),
        ("status", env.status.value),
        ("result", result_summary(env)),
    ]
    if env.error is not None:
        rows += [
            ("error", f"{env.error.error_class}: {env.error.message}"),
            ("side effect", env.error.side_effect),
            ("outcome unknown", "yes" if env.error.outcome_unknown else "no"),
            ("retryable", "yes (same operation id)" if env.error.retryable else "no"),
        ]
    console.print(_kv_table(rows))
    guidance = _STATUS_GUIDANCE.get(env.status)
    if guidance is not None:
        prose(console, Text.assemble(("note: ", "dim"), Text(guidance)))


def render_pending_run(op: OperationView) -> None:
    """A run that has not finished: there is no result yet, only the operation that is producing it.

    Goes to **stderr**, like the finished run report: with ``evidence get --output`` stdout belongs
    to the guest's bytes, so a status table must never leak into a redirected output file.
    """
    console = make_console(stderr=True)
    console.print(
        _kv_table(
            [
                ("run", op.run_id or "-"),
                ("operation", op.operation_id),
                ("status", op.status.value),
                ("phase", ", ".join(f"{k}={v}" for k, v in op.phase.items()) or "-"),
                ("updated", op.updated),
            ]
        )
    )
    prose(console, Text.assemble(("note: ", "dim"), Text("the run has not finished; there is no evidence record yet")))


# ----------------------------------------------------------------------------- metrics
def flatten_metrics(data: object, prefix: str = "") -> list[tuple[str, object]]:
    """``{"counters": {"a": 1}}`` -> ``[("counters.a", 1)]`` (labelled series keep their label text)."""
    if isinstance(data, dict):
        out: list[tuple[str, object]] = []
        for key in sorted(data):
            out.extend(flatten_metrics(data[key], f"{prefix}.{key}" if prefix else str(key)))
        return out
    return [(prefix, data)]


def render_metrics(data: dict[str, Any]) -> None:
    rows = flatten_metrics(data)
    console = make_console()
    console.print(_kv_table(rows) if rows else Text("no metrics yet"))
