"""How each view of the API is shown to a person.

A view is shown as the platform sent it: every state, status and code is printed as the string it is,
so that a value this version has never seen is shown and never taken for a known one. Every string is
made safe before it is placed in a table (:func:`agentcompute_cli.render.safe_line`): a name is chosen
by whoever created the record, a note or a message by the host, and neither is this program's text.

What a guest reported about an execution is labelled as such, with the label the platform gives it.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from typing import Any, Final

from agentcompute import (
    AgentCredential,
    ExecutionView,
    Failure,
    Info,
    NetworkView,
    Operation,
    OutputChunk,
    OutputSummary,
    SandboxView,
    SnapshotView,
    WhoAmI,
)

from agentcompute_cli import render
from agentcompute_cli.render import CELL_MAX, IDENTIFIER_MAX, safe_line

__all__ = [
    "operation_line",
    "show_chunk_status",
    "show_credential",
    "show_credentials",
    "show_execution",
    "show_info",
    "show_operation",
    "show_operations",
    "show_sandbox",
    "show_sandboxes",
    "show_snapshot",
    "show_snapshots",
    "show_whoami",
]

_DASH: Final = "-"

type Rows = list[tuple[str, str]]


def _identifier(value: object) -> str:
    return _DASH if value is None else safe_line(value, limit=IDENTIFIER_MAX)


def _cell(value: object) -> str:
    return _DASH if value is None or value == "" else safe_line(value, limit=CELL_MAX)


def _value(value: object) -> str:
    return _DASH if value is None or value == "" else safe_line(value)


def _failure(failure: Failure | None) -> str:
    if failure is None:
        return _DASH
    raw = "" if failure.code_raw is None else f" (the host said {failure.code_raw})"
    return _value(f"{failure.code}{raw}: {failure.message} (retry {failure.retry})")


def _network(network: NetworkView) -> str:
    entries = []
    for entry in network.entries:
        ports = ",".join(
            str(port.first) if port.first == port.last else f"{port.first}-{port.last}" for port in entry.ports
        )
        entries.append(f"{entry.name or entry.network or '?'}:{ports}")
    return _value(network.mode if not entries else f"{network.mode}: {', '.join(entries)}")


def _flatten(data: Mapping[str, Any], prefix: str = "") -> Iterator[tuple[str, str]]:
    """A JSON object as rows, whatever its members: ``{"a": {"b": 1}}`` is the row ``a.b`` with value ``1``."""
    for key in sorted(data):
        value = data[key]
        name = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            yield from _flatten(value, name)
        elif isinstance(value, list) and not any(isinstance(item, dict | list) for item in value):
            yield _value(name), _value(", ".join(str(item) for item in value) or _DASH)
        else:
            yield _value(name), _value(render.json_line(value) if isinstance(value, dict | list) else value)


# ------------------------------------------------------------------------------------------ sandboxes
def show_sandboxes(sandboxes: Sequence[SandboxView]) -> None:
    render.table(
        ["SANDBOX", "NAME", "STATE", "GEN", "IMAGE", "VCPU", "MEMORY", "DISK", "NETWORK", "EXPIRES"],
        (
            [
                _identifier(sandbox.sandbox_id),
                _cell(sandbox.name),
                _cell(sandbox.state if sandbox.quarantined is None else f"{sandbox.state} [quarantined]"),
                str(sandbox.generation),
                _cell(sandbox.image.alias or sandbox.image.digest),
                str(sandbox.resources.vcpus),
                f"{sandbox.resources.memory_mib} MiB",
                f"{sandbox.resources.disk_mib} MiB",
                _cell(sandbox.network.mode),
                _cell(sandbox.expires_at),
            ]
            for sandbox in sandboxes
        ),
        empty="no sandboxes",
    )


def show_sandbox(sandbox: SandboxView) -> None:
    resources = sandbox.resources
    rows: Rows = [
        ("sandbox", _identifier(sandbox.sandbox_id)),
        ("name", _value(sandbox.name)),
        ("state", _value(sandbox.state)),
        ("generation", str(sandbox.generation)),
        ("image", _value(f"{sandbox.image.alias or _DASH}  {sandbox.image.digest}")),
        ("resources", f"{resources.vcpus} vCPU, {resources.memory_mib} MiB memory, {resources.disk_mib} MiB disk"),
        ("network", _network(sandbox.network)),
        ("expires", _value(sandbox.expires_at)),
        ("last execution", _identifier(sandbox.last_execution)),
    ]
    source = sandbox.source_snapshot
    if source is not None:
        rows.append(("restored from", f"{_identifier(source.snapshot_id)} generation {source.snapshot_generation}"))
    if sandbox.failure is not None:
        rows.append(("failure", _failure(sandbox.failure)))
    if sandbox.quarantined is not None:
        rows.append(("quarantined", _value(sandbox.quarantined)))
    rows += [("revision", _value(sandbox.revision)), ("updated", _value(sandbox.updated_at))]
    rows += [("note", _value(note)) for note in sandbox.notes]
    render.pairs(rows)


# ----------------------------------------------------------------------------------------- executions
def _labelled(value: object, provenance: Mapping[str, Any], member: str) -> str:
    """A member of an execution's result, with the platform's label of who reported it."""
    label = provenance.get(member)
    return _value(value) if not isinstance(label, str) else f"{_value(value)}  [{_cell(label)}]"


def _stream(summary: OutputSummary | None) -> str:
    if summary is None:
        return _DASH
    return _value(f"{summary.stored_bytes} bytes stored, {summary.produced_bytes} produced, {summary.completeness}")


def show_execution(execution: ExecutionView, *, err: bool = False) -> None:
    provenance = execution.provenance
    rows: Rows = [
        ("execution", _identifier(execution.execution_id)),
        ("operation", _identifier(execution.operation_id)),
        ("sandbox", f"{_identifier(execution.sandbox_id)} generation {_value(execution.generation)}"),
        ("state", _value(execution.state)),
        ("status", _labelled(execution.status, provenance, "status")),
        ("exit code", _labelled(execution.exit_code, provenance, "exit_code")),
    ]
    if execution.signal is not None:
        rows.append(("signal", _labelled(execution.signal, provenance, "signal")))
    durations = execution.durations
    if durations is not None:
        rows.append(("duration", f"guest {_value(durations.guest_ms)} ms, wall {_value(durations.wall_ms)} ms"))
    rows += [
        ("stdout", _labelled(_stream(execution.stdout), provenance, "stdout")),
        ("stderr", _labelled(_stream(execution.stderr), provenance, "stderr")),
    ]
    if execution.host_backstop_fired:
        rows.append(("host backstop", "fired: the host ended the command at its own deadline"))
    if execution.evidence_status is not None:
        rows.append(("evidence", _value(execution.evidence_status)))
    if execution.note is not None:
        rows.append(("note", _value(execution.note)))
    render.pairs(rows, err=err)


def show_chunk_status(chunk: OutputChunk) -> None:
    """Where a slice of output stands in its stream, on standard error: the data itself goes to standard output."""
    end = chunk.next_offset
    position = f"bytes {chunk.offset} to {end} of {chunk.stored_bytes} stored ({chunk.produced_bytes} produced)"
    more = "end of the stream" if chunk.eof else f"more follows: --offset {end}"
    render.line(f"acf: {_cell(chunk.stream)} {position}, {_cell(chunk.completeness)}; {more}", err=True)


# ------------------------------------------------------------------------------------------ snapshots
def show_snapshots(snapshots: Sequence[SnapshotView]) -> None:
    render.table(
        ["SNAPSHOT", "GEN", "NAME", "STATE", "SIZE", "SOURCE", "RESTORES", "CREATED"],
        (
            [
                _identifier(snapshot.snapshot_id),
                str(snapshot.snapshot_generation),
                _cell(snapshot.name),
                _cell(snapshot.state if not snapshot.incompatible else f"{snapshot.state} [incompatible]"),
                f"{snapshot.size_bytes} bytes",
                _DASH if snapshot.source_sandbox is None else _identifier(snapshot.source_sandbox.sandbox_id),
                str(snapshot.restore_count),
                _cell(snapshot.created_at),
            ]
            for snapshot in snapshots
        ),
        empty="no snapshots",
    )


def show_snapshot(snapshot: SnapshotView) -> None:
    source = snapshot.source_sandbox
    rows: Rows = [
        ("snapshot", f"{_identifier(snapshot.snapshot_id)} generation {snapshot.snapshot_generation}"),
        ("name", _value(snapshot.name)),
        ("state", _value(snapshot.state)),
        ("size", f"{snapshot.size_bytes} bytes"),
        (
            "source sandbox",
            _DASH if source is None else f"{_identifier(source.sandbox_id)} generation {source.generation}",
        ),
        ("restores", str(snapshot.restore_count)),
    ]
    if snapshot.failure is not None:
        rows.append(("failure", _failure(snapshot.failure)))
    rows += [("revision", _value(snapshot.revision)), ("created", _value(snapshot.created_at))]
    rows += [("cannot be restored here", _value(reason)) for reason in snapshot.incompatible]
    render.pairs(rows)


# ----------------------------------------------------------------------------------------- operations
def _text(raw: Mapping[str, Any], member: str) -> str:
    """A member of a view for a status line. Read from the JSON, so that an odd view still gets its line."""
    value = raw.get(member)
    return _cell(value if isinstance(value, str) else None)


def operation_line(operation: Operation) -> str:
    """One line about the operation behind a result: its identifier, and whether the result is of earlier work."""
    raw = operation.raw
    said = f"operation {_identifier(raw.get('operation_id'))} ({_text(raw, 'type')}) {_text(raw, 'state')}"
    if raw.get("replayed") is True:
        return f"{said}; replayed: this answer reports work that already existed, and started nothing new"
    return said


def _target(operation: Operation) -> str:
    target = operation.target
    parts = []
    if target.sandbox_id is not None:
        generation = "" if target.generation is None else f" generation {target.generation}"
        parts.append(f"sandbox {_identifier(target.sandbox_id)}{generation}")
    if target.snapshot_id is not None:
        generation = "" if target.snapshot_generation is None else f" generation {target.snapshot_generation}"
        parts.append(f"snapshot {_identifier(target.snapshot_id)}{generation}")
    if target.execution_id is not None:
        parts.append(f"execution {_identifier(target.execution_id)}")
    return ", ".join(parts) or _DASH


def _actor(operation: Operation) -> str:
    actor = operation.actor
    if actor is None:
        return _DASH
    label = "" if actor.agent_label is None else f" as agent {_cell(actor.agent_label)}"
    return f"{_identifier(actor.principal_id)}{label}"


def show_operations(operations: Sequence[Operation]) -> None:
    render.table(
        ["OPERATION", "TYPE", "STATE", "EFFECT", "TARGET", "ACTOR", "UPDATED"],
        (
            [
                _identifier(operation.operation_id),
                _cell(operation.type),
                _cell(operation.state),
                _cell(operation.effect),
                _target(operation),
                _actor(operation),
                _cell(operation.updated_at),
            ]
            for operation in operations
        ),
        empty="no operations",
    )


def show_operation(operation: Operation) -> None:
    rows: Rows = [
        ("operation", f"{_identifier(operation.operation_id)} ({_cell(operation.type)})"),
        ("state", _value(operation.state)),
        ("effect", _value(operation.effect) if operation.effect is not None else "- (not stated before it ends)"),
    ]
    if operation.failure is not None:
        rows.append(("failure", _failure(operation.failure)))
    if operation.cleanup is not None:
        rows.append(("cleanup", _value(operation.cleanup)))
    if operation.cancelled_by is not None:
        rows.append(("cancelled by", _value(operation.cancelled_by)))
    rows += [
        ("target", _target(operation)),
        ("asked by", _actor(operation)),
        ("created", _value(operation.created_at)),
        ("updated", _value(operation.updated_at)),
    ]
    if operation.replayed:
        rows.append(("replayed", "yes: this answer reports work that already existed"))
    if operation.recorded:
        rows.append(("recorded", "yes: the host no longer holds the operation; this is the outcome that was recorded"))
    render.pairs(rows)


# ---------------------------------------------------------------------------------------- credentials
def show_credentials(credentials: Sequence[AgentCredential]) -> None:
    render.table(
        ["CREDENTIAL", "LABEL", "STATUS", "KIND", "PREFIX", "ISSUED", "EXPIRES"],
        (
            [
                _identifier(credential.credential_id),
                _cell(credential.label),
                _cell(credential.status),
                _cell(credential.kind),
                _cell(credential.display_prefix),
                _cell(credential.issued_at),
                _cell(credential.expires_at),
            ]
            for credential in credentials
        ),
        empty="no agent credentials",
    )


def show_credential(credential: AgentCredential, *, err: bool = False) -> None:
    """An agent credential, without its secret: the secret is printed by the one command that mints it."""
    rows: Rows = [
        ("credential", _identifier(credential.credential_id)),
        ("label", _value(credential.label)),
        ("kind", _value(credential.kind)),
        ("status", _value(credential.status)),
        ("prefix", _value(credential.display_prefix)),
        ("issued", _value(credential.issued_at)),
        ("expires", _value(credential.expires_at)),
    ]
    narrowing = credential.narrowing
    if narrowing is not None:
        rows += [(f"narrowing {name}", value) for name, value in _flatten(narrowing)]
    render.pairs(rows, err=err)


def show_whoami(whoami: WhoAmI, *, err: bool = False) -> None:
    credential = whoami.credential
    rows: Rows = [
        ("principal", _identifier(whoami.principal_id)),
        ("project", _identifier(whoami.project_id)),
        ("credential", f"{_identifier(credential.credential_id)} ({_cell(credential.kind)})"),
    ]
    if credential.agent_label is not None:
        rows.append(("agent label", _value(credential.agent_label)))
    rows += [("expires", _value(credential.expires_at)), ("policy version", _value(whoami.policy_version))]
    rows += [(f"grant {name}", value) for name, value in _flatten(whoami.grants)]
    render.pairs(rows, err=err)


# ----------------------------------------------------------------------------------------------- info
def show_info(info: Info) -> None:
    rows: Rows = [
        ("API versions", _value(", ".join(info.api_versions))),
        ("serving", "yes" if info.serving else "no"),
    ]
    if info.ready is not None:
        rows.append(("ready for new work", "yes" if info.ready else "no"))
    rows += [("not ready because", _value(reason)) for reason in info.not_ready_reasons or ()]
    if info.platform_features is not None:
        rows.append(("platform features", _value(", ".join(info.platform_features))))
    if info.host_features is not None:
        rows.append(("host features", _value(", ".join(info.host_features))))
    ceilings = info.ceilings
    if ceilings is not None:
        rows += [(f"ceiling {name}", value) for name, value in _flatten(ceilings.raw)]
    parameters = info.parameters
    if parameters is not None:
        rows += [(f"parameter {name}", value) for name, value in _flatten(parameters)]
    render.pairs(rows)
