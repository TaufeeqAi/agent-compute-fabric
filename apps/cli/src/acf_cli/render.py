"""Human-readable rendering and machine-readable (JSON) output.

Three rules matter more than prettiness:

1. **Guest output is attacker-controlled.** A workload can print ANSI/OSC escape sequences that
   retitle a terminal, rewrite earlier lines (``\\r``), or hide text with bidi overrides. When a
   stream is going to a *terminal* it is sanitized (control/format characters shown as visible
   escapes); when it goes to a pipe or file the bytes are passed through untouched, byte-exact.
2. **No markup interpretation of data.** Every dynamic value goes through ``rich.text.Text``, so a
   sandbox *name* like ``[red]x`` can never change how a table renders.
3. **An unknown word stays unknown.** A value of a closed vocabulary that this client does not know
   is printed as the host sent it and marked as not recognized. It is never shown as a known one.

``--json`` output is the host's answer in wire form (field names, ``class`` and all), so scripts
see the shapes the published API description declares.
"""

from __future__ import annotations

import base64
import binascii
import json
import sys
import unicodedata
from collections.abc import Iterable, Sequence

from rich.console import Console
from rich.table import Table
from rich.text import Text

from acf_cli.errors import AcfCliError
from acf_cli.responses import (
    AsOf,
    CursorView,
    FailureInfo,
    HostChange,
    HostChangeBody,
    HostInfo,
    NetworkIntentView,
    OperationView,
    OutputCapture,
    ProfileLimits,
    Refusal,
    RunBody,
    RunResult,
    SandboxBody,
    SandboxView,
    SnapshotBody,
    SnapshotView,
)
from acf_cli.units import format_bytes, format_ms
from acf_cli.wire import Cleanup, Effect, HostMode, OutputStatus, RetryAdvice, Unrecognized

_KEEP = {"\n", "\t"}
_UNBOUNDED_WIDTH = 100_000
_LATIN1_LIMIT = 0x100

_RETRY_ADVICE: dict[str, str] = {
    RetryAdvice.SAME_REQUEST_LATER: "nothing is wrong with the request; the host cannot take it now. Send it later",
    RetryAdvice.AFTER_CHANGE: "it can be accepted once the target, the host or the request changes",
    RetryAdvice.NEVER: "this exact request will never be accepted",
}
_EFFECT: dict[str, str] = {
    Effect.APPLIED: "the operation's effect is in place",
    Effect.NOT_APPLIED: "nothing was applied; a new operation for the same intent is safe",
    Effect.MAY_BE_APPLIED: "it may have been applied; a new operation for the same intent is not known to be safe",
}
_CLEANUP: dict[str, str] = {
    Cleanup.COMPLETE: "everything the operation created is proven removed",
    Cleanup.PENDING: "something the operation created remains and still holds its lease",
    Cleanup.QUARANTINED: "what the operation left is quarantined; an operator must release it",
}


def make_console(*, stderr: bool = False) -> Console:
    """A console bound to the *current* ``sys.stdout``/``sys.stderr`` (so test runners can capture it)."""
    stream = sys.stderr if stderr else sys.stdout
    # A terminal folds long cells to its width. A pipe or a file gets every cell whole: an id that
    # was cut to fit a column would be a wrong id.
    width = None if stream.isatty() else _UNBOUNDED_WIDTH
    return Console(file=stream, width=width, highlight=False, emoji=False, markup=False, soft_wrap=False)


def prose(console: Console, text: Text) -> None:
    """Print one logical line of prose **without inserting line breaks**.

    Messages and hints routinely contain a command the operator will copy. Letting rich re-wrap such
    a line at the console width would split the command in half, so prose is soft-wrapped: the
    terminal may fold it visually, but the bytes on the stream stay one line.
    """
    console.print(text, soft_wrap=True)


def shown(value: object) -> str:
    """A vocabulary value for people: what the host sent, marked when this client does not know the word."""
    if isinstance(value, Unrecognized):
        return f"{value} (not recognized by this client)"
    return str(value)


def _explained(value: str, meanings: dict[str, str]) -> str:
    meaning = meanings.get(value)
    return f"{shown(value)} - {meaning}" if meaning is not None else shown(value)


# ----------------------------------------------------------------------------- JSON
def print_json(document: object) -> None:
    """Exactly one JSON document on stdout."""
    sys.stdout.write(json.dumps(document, indent=2, sort_keys=False, ensure_ascii=False) + "\n")
    sys.stdout.flush()


# ----------------------------------------------------------------------------- untrusted bytes
def decode_base64(data_b64: str) -> bytes:
    """The bytes of a base64 field. A malformed body is a host defect and decodes to nothing."""
    try:
        return base64.b64decode(data_b64, validate=True)
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


# ----------------------------------------------------------------------------- building blocks
def _t(value: object) -> Text:
    return Text("" if value is None else str(value))


def _table(columns: Sequence[str]) -> Table:
    table = Table(title_justify="left", header_style="bold", show_edge=False, pad_edge=False)
    for col in columns:
        table.add_column(col, overflow="fold")
    return table


def _kv_table(rows: Sequence[tuple[str, object]]) -> Table:
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold", no_wrap=True)
    table.add_column(overflow="fold")
    for key, value in rows:
        table.add_row(_t(key), _t(value))
    return table


def _failure(failure: FailureInfo | None) -> str:
    if failure is None:
        return "-"
    return f"{shown(failure.failure_class)}: {failure.message} (side effect: {shown(failure.side_effect)})"


def _network(network: NetworkIntentView) -> str:
    if not network.entries:
        return shown(network.mode)
    return f"{shown(network.mode)}: {', '.join(str(e) for e in network.entries)}"


# ----------------------------------------------------------------------------- errors and refusals
def render_error(err: AcfCliError) -> None:
    console = make_console(stderr=True)
    prose(console, Text.assemble(("error: ", "bold red"), Text(err.message)))
    if err.operation_id:
        prose(console, Text.assemble(("  operation: ", "dim"), Text(err.operation_id)))
    if err.hint:
        prose(console, Text.assemble(("  hint: ", "dim"), Text(err.hint)))


def render_refusal(refusal: Refusal, as_of: AsOf | None) -> None:
    """A refusal, on stderr: its class, what to do about it, and the fact that nothing happened."""
    console = make_console(stderr=True)
    head = Text.assemble(
        ("refused: ", "bold red"), Text(shown(refusal.failure_class)), Text(" - "), Text(refusal.message)
    )
    prose(console, head)
    prose(console, Text.assemble(("  retry: ", "dim"), Text(_explained(refusal.retry, _RETRY_ADVICE))))
    prose(console, Text("  nothing was applied, and no operation was recorded", style="dim"))
    if as_of is not None:
        prose(console, Text.assemble(("  as of: ", "dim"), Text(str(as_of))))


# ----------------------------------------------------------------------------- operations
def result_summary(view: OperationView) -> str:
    """One line saying what an operation produced, without dumping the payload."""
    result = view.result
    if isinstance(result, RunBody):
        return f"run {result.data.run_id}: {run_summary(result.data)}"
    if isinstance(result, SandboxBody):
        s = result.data
        return f"sandbox {s.sandbox_id} generation {s.generation} ({shown(s.state)})"
    if isinstance(result, SnapshotBody):
        return f"snapshot {result.data.snapshot} ({shown(result.data.state)})"
    if isinstance(result, HostChangeBody):
        return host_change_summary(result.data)
    if result is None:
        return "-"
    return f"{result.type} (a result type not recognized by this client)"


def operation_rows(view: OperationView, as_of: AsOf | None) -> list[tuple[str, object]]:
    rows: list[tuple[str, object]] = [
        ("operation", f"{view.operation_id} ({shown(view.operation_type)})"),
        ("state", shown(view.state)),
        (
            "effect",
            _explained(view.effect, _EFFECT) if view.effect is not None else "- (not stated before it ends)",
        ),
    ]
    if view.cleanup is not None:
        rows.append(("cleanup", _explained(view.cleanup, _CLEANUP)))
    if view.cancelled_by is not None:
        rows.append(("cancelled by", shown(view.cancelled_by)))
    rows += [("target", view.target), ("step", view.step or "-")]
    if view.failure is not None:
        rows.append(("failure", _failure(view.failure)))
    rows.append(("result", result_summary(view)))
    rows += [("issued by", f"{shown(view.issuer)} {view.tags}"), ("updated", view.updated)]
    if as_of is not None:
        rows.append(("as of", str(as_of)))
    return rows


def render_operation(view: OperationView, as_of: AsOf | None, *, to_stderr: bool = False) -> None:
    """What the host states about one operation: its state, its effect and what it left behind."""
    make_console(stderr=to_stderr).print(_kv_table(operation_rows(view, as_of)))


def render_operations(items: Iterable[OperationView]) -> None:
    table = _table(["OPERATION", "TYPE", "STATE", "EFFECT", "CLEANUP", "TARGET", "UPDATED", "REV"])
    rows = 0
    for op in items:
        rows += 1
        table.add_row(
            _t(op.operation_id),
            _t(shown(op.operation_type)),
            _t(shown(op.state)),
            _t(shown(op.effect) if op.effect is not None else "-"),
            _t(shown(op.cleanup) if op.cleanup is not None else "-"),
            _t(op.target),
            _t(op.updated),
            _t(op.revision),
        )
    make_console().print(table if rows else Text("no operations"))


# ----------------------------------------------------------------------------- sandboxes
def render_sandboxes(items: Iterable[SandboxView]) -> None:
    table = _table(["SANDBOX", "NAME", "GEN", "STATE", "VCPU", "MEM", "DISK", "NETWORK", "SCOPE", "EXPIRES", "REV"])
    rows = 0
    for s in items:
        rows += 1
        table.add_row(
            _t(s.sandbox_id),
            _t(s.name or "-"),
            _t(s.generation),
            _t(shown(s.state) + (" [quarantined]" if s.quarantined else "")),
            _t(s.resources.vcpus),
            _t(f"{s.resources.memory_mib} MiB"),
            _t(f"{s.resources.disk_mib} MiB"),
            _t(shown(s.resources.network.mode)),
            _t(s.tags),
            _t(s.expires_at),
            _t(s.revision),
        )
    make_console().print(table if rows else Text("no sandboxes"))


def sandbox_rows(s: SandboxView) -> list[tuple[str, object]]:
    r = s.resources
    return [
        ("sandbox", s.sandbox_id),
        ("name", s.name or "-"),
        ("generation", s.generation),
        ("state", shown(s.state)),
        ("resources", f"{r.vcpus} vCPU, {r.memory_mib} MiB RAM, {r.disk_mib} MiB disk"),
        ("network", _network(r.network)),
        ("image", f"{s.image.alias or '-'}  {s.image.image_id}"),
        ("owner", str(s.tags)),
        ("expires", s.expires_at),
        ("process", f"pid {s.process.pid} (start {s.process.start_time_ticks})" if s.process else "-"),
        ("security profile", s.security_profile_id),
        ("last run", s.last_run or "-"),
        ("restored from", str(s.source_snapshot) if s.source_snapshot else "-"),
        ("failure", _failure(s.failure)),
        ("quarantined", s.quarantined or "-"),
        ("secret-bearing", "yes" if s.secret_bearing else "no"),
        ("revision", s.revision),
        ("updated", s.updated),
    ]


def render_sandbox(s: SandboxView) -> None:
    console = make_console()
    console.print(_kv_table(sandbox_rows(s)))
    for note in s.notes:
        prose(console, Text.assemble(("note: ", "dim"), Text(note)))


# ----------------------------------------------------------------------------- snapshots
def render_snapshots(items: Iterable[SnapshotView]) -> None:
    table = _table(["SNAPSHOT", "GEN", "NAME", "STATE", "SIZE", "SOURCE", "RESTORES", "SCOPE", "CREATED", "REV"])
    rows = 0
    for s in items:
        rows += 1
        src = f"{s.source_sandbox[0]}@{s.source_sandbox[1]}" if s.source_sandbox else "-"
        table.add_row(
            _t(s.snapshot.snapshot_id),
            _t(s.snapshot.snapshot_generation),
            _t(s.name or "-"),
            _t(shown(s.state) + (" [incompatible]" if s.incompatible else "")),
            _t(format_bytes(s.size_bytes)),
            _t(src),
            _t(s.restore_count),
            _t(s.tags),
            _t(s.created),
            _t(s.revision),
        )
    make_console().print(table if rows else Text("no snapshots"))


def render_snapshot(s: SnapshotView) -> None:
    console = make_console()
    source = f"{s.source_sandbox[0]} (generation {s.source_sandbox[1]})" if s.source_sandbox else "-"
    console.print(
        _kv_table(
            [
                ("snapshot", f"{s.snapshot.snapshot_id} (generation {s.snapshot.snapshot_generation})"),
                ("name", s.name or "-"),
                ("state", shown(s.state)),
                ("size", format_bytes(s.size_bytes)),
                ("source sandbox", source),
                ("owner", str(s.tags)),
                ("manifest digest", s.manifest_digest or "-"),
                ("restores", s.restore_count),
                ("secret references", ", ".join(s.secret_refs) or "-"),
                ("failure", _failure(s.failure)),
                ("revision", s.revision),
                ("created", s.created),
            ]
        )
    )
    for reason in s.incompatible:
        prose(console, Text.assemble(("cannot be restored on this host: ", "bold yellow"), Text(reason)))


def render_listing_footer(count: int, cursor: CursorView, *, more: bool, as_of: AsOf | None) -> None:
    """Where a listing stands, on stderr: the cursor to continue or to ask for changes from."""
    console = make_console(stderr=True)
    state = "more follow" if more else "complete"
    prose(console, Text(f"{count} record(s); listing {state}; cursor {cursor}", style="dim"))
    if more:
        prose(console, Text(f"continue with: --changed-since {cursor}   (or pass --all)", style="dim"))
    if as_of is not None:
        prose(console, Text(f"as of {as_of}", style="dim"))


# ----------------------------------------------------------------------------- the host
def host_change_summary(change: HostChange) -> str:
    parts: list[str] = []
    if change.mode is not None:
        parts.append(f"host mode {shown(change.mode)}")
    if change.profile is not None:
        parts.append(f"profile in force {change.profile.short()}")
    if change.note:
        parts.append(change.note)
    return "; ".join(parts) or "-"


def _or_dash(value: object) -> str:
    return "-" if value is None else str(value)


def _ceilings(c: ProfileLimits) -> str:
    return (
        f"{c.max_vcpus} vCPU, {c.max_memory_mib} MiB RAM, {c.max_disk_mib} MiB disk, "
        f"runtime {format_ms(c.max_runtime_ms)}, {c.max_pids} pids, "
        f"lifetime {c.max_lifetime_secs} s, {c.max_allowlist_entries} allowlist entries"
    )


def render_host_info(h: HostInfo) -> None:
    console = make_console()
    p = h.parameters
    c = p.ceilings
    console.print(
        _kv_table(
            [
                ("host agent", h.version),
                ("host id", h.host_id),
                ("protocols", ", ".join(h.protocols)),
                ("features", ", ".join(h.features) or "-"),
                ("mode", shown(h.mode)),
                ("store lineage", h.lineage),
                ("activation", f"epoch {h.activation_epoch} ({h.instance_id})"),
                ("backend", f"{h.backend.name} {h.backend.version}"),
                ("security profile", h.backend.security_profile_id),
                ("network modes", ", ".join(shown(m) for m in h.capabilities.network_modes) or "-"),
                ("identifier slots", _or_dash(h.capabilities.identifier_slots)),
                ("safety profile", h.profile.short()),
                ("store", h.store_integrity),
                ("sandboxes", f"{h.live_sandboxes} live, {h.quarantined} quarantined"),
                ("snapshots", h.snapshots),
                ("operations in flight", h.operations_in_flight),
                ("wait max", format_ms(p.wait_max_ms)),
                ("acceptance horizon", format_ms(p.acceptance_horizon_ms)),
                ("operation retention", format_ms(p.operation_retention_ms)),
                ("change retention", format_ms(p.change_retention_ms)),
                ("max request", format_bytes(p.max_request_bytes)),
                ("ceilings", _ceilings(c)),
                ("default lifetime", f"{p.sandbox_lifetime_default_secs} s"),
            ]
        )
    )
    if h.mode is not HostMode.SERVING:
        prose(console, Text.assemble(("warning: ", "bold yellow"), Text(f"the host is {shown(h.mode)}")))
    for reason in h.containment_reasons:
        prose(console, Text.assemble(("  containment: ", "dim"), Text(f"{reason.reason}: {reason.detail}")))
    if h.read_only_reason:
        prose(console, Text.assemble(("  read-only: ", "dim"), Text(h.read_only_reason)))


def render_host_change(change: HostChange) -> None:
    prose(make_console(), Text(host_change_summary(change)))


def flatten_metrics(data: object, prefix: str = "") -> list[tuple[str, object]]:
    """``{"counters": {"a": 1}}`` -> ``[("counters.a", 1)]`` (labelled series keep their label text)."""
    if isinstance(data, dict):
        out: list[tuple[str, object]] = []
        for key in sorted(data):
            out.extend(flatten_metrics(data[key], f"{prefix}.{key}" if prefix else str(key)))
        return out
    return [(prefix, data)]


def render_metrics(data: object) -> None:
    rows = flatten_metrics(data) if isinstance(data, dict) else []
    make_console().print(_kv_table(rows) if rows else Text("no metrics yet"))


# ----------------------------------------------------------------------------- executions
def _stream_line(cap: OutputCapture) -> str:
    flags = (
        ""
        if cap.status is OutputStatus.COMPLETE
        else f" [{shown(cap.status)}: kept {format_bytes(cap.kept_bytes)} of {format_bytes(cap.total_bytes)}]"
    )
    art = f"  artifact {cap.artifact.artifact_id} {cap.artifact.content_digest or ''}".rstrip() if cap.artifact else ""
    return f"{format_bytes(cap.total_bytes)}{flags}{art}"


def run_summary(run: RunResult) -> str:
    if run.exit_code is not None:
        return f"{shown(run.status)} (exit {run.exit_code})"
    if run.signal is not None:
        return f"{shown(run.status)} (signal {run.signal})"
    return shown(run.status)


def render_run_report(run: RunResult, *, verbose: bool, to_stderr: bool = True) -> None:
    """The record of one execution. What the guest reported is labelled as such."""
    console = make_console(stderr=to_stderr)
    m = run.metrics
    lines: list[tuple[str, object]] = [
        ("run", run.run_id),
        ("sandbox", f"{run.sandbox_id} (generation {run.generation})"),
        ("status", f"{run_summary(run)}  [reported by the guest]"),
        ("guest duration", format_ms(run.guest_duration_ms)),
        ("wall time", format_ms(m.wall_ms)),
        ("cpu time", f"{m.cpu_usage_usec / 1000:.1f} ms" if m.cpu_usage_usec is not None else "n/a"),
        ("peak memory", format_bytes(m.memory_peak_bytes) if m.memory_peak_bytes is not None else "n/a"),
        ("stdout", _stream_line(run.stdout)),
        ("stderr", _stream_line(run.stderr)),
        ("evidence", shown(run.evidence_status)),
        ("safety profile", run.profile_id.short()),
        ("image", run.image_id),
    ]
    if run.host_backstop_fired:
        lines.append(("host backstop", "fired: the host ended the runtime at its own deadline"))
    elif run.runtime_ended:
        lines.append(("runtime", "ended by the host as part of this execution"))
    if run.note:
        lines.append(("note", run.note))
    console.print(_kv_table(lines))
    for e in run.resource_evidence if verbose else [e for e in run.resource_evidence if e.violated]:
        status = f"LIMIT REACHED: {e.action_taken}" if e.violated else "ok"
        text = f"  {e.resource}: configured {e.configured}, observed peak {e.observed_peak} - {status} [{e.mechanism}]"
        prose(console, Text(text))
    for art in run.artifacts:
        size = format_bytes(art.byte_size or 0)
        prose(console, Text(f"  artifact {art.artifact_id}  {shown(art.kind):<7} {art.content_digest or '-'}  {size}"))


def render_note(label: str, text: str, *, alarming: bool = False) -> None:
    """One labelled line on stderr."""
    console = make_console(stderr=True)
    prose(console, Text.assemble((f"{label}: ", "bold red" if alarming else "dim"), Text(text)))
