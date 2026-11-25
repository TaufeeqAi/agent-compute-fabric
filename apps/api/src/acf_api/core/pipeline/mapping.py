"""From the host's views to the public model, through the mapping table.

This is the only module that knows both vocabularies. The correspondence between them is the table
loaded here (``acf_api/core/host/data/mapping.acf.host-2.yaml``), not an identity assumed in code:

* a host value the table does not hold is shown as ``UNRECOGNIZED``, with the raw value beside it, and
  is never mapped onto a known value. An operation in an unrecognized state is neither successful nor
  terminal;
* no backend type, mechanism name or host-internal field crosses: no process identity, no profile id,
  no kernel or root filesystem identity, no host name. The image is shown by alias and identity digest;
* public identifiers, revision validators and list cursors are opaque tokens derived one-to-one from
  the host's values. None carries a host name or a project;
* every field of an execution result keeps the host's provenance label.

Everything here is a pure function of its arguments.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from importlib import resources
from typing import Any, Final

import yaml

from acf_api.command import model as m
from acf_api.command.errors import Retry

UNRECOGNIZED: Final = m.UNRECOGNIZED
_HEX32: Final = frozenset("0123456789abcdef")
#: The most digits a host revision has: those of an unsigned 64-bit number.
_REVISION_DIGITS: Final = 20


class MappingError(Exception):
    """The mapping table cannot be used."""


@dataclass(frozen=True, slots=True)
class MappingTable:
    host_protocol: str
    vocabularies: dict[str, dict[str, str]]
    platform_faults: frozenset[str]
    handled_by_rule: dict[str, str]
    retry_advice: dict[str, str]
    methods: dict[str, str]
    never_called: frozenset[str]

    def value(self, vocabulary: str, host_value: object) -> tuple[str, str | None]:
        """The public value of a host value, and the raw value when the table does not hold it."""
        if not isinstance(host_value, str):
            return UNRECOGNIZED, None if host_value is None else str(host_value)[:64]
        known = self.vocabularies[vocabulary].get(host_value)
        return (known, None) if known is not None else (UNRECOGNIZED, host_value[:64])

    def retry_for(self, failure_class: str) -> str:
        return self.retry_advice.get(failure_class, Retry.NEVER.value)

    def host_method(self, public_method: str) -> str:
        return self.methods[public_method]


def load_table() -> MappingTable:
    text = (resources.files("acf_api.core.host") / "data" / "mapping.acf.host-2.yaml").read_text(encoding="utf-8")
    return parse_table(yaml.safe_load(text))


def parse_table(data: Any) -> MappingTable:  # noqa: ANN401 - any YAML value: what is not the table is refused below
    try:
        if data["schema_version"] != 1:
            raise MappingError("the mapping table has a schema version this build does not know")
        return MappingTable(
            host_protocol=str(data["host_protocol"]),
            vocabularies={str(k): {str(a): str(b) for a, b in v.items()} for k, v in data["vocabularies"].items()},
            platform_faults=frozenset(str(x) for x in data["platform_faults"]),
            handled_by_rule={str(k): str(v) for k, v in data["handled_by_rule"].items()},
            retry_advice={str(k): str(v) for k, v in data["retry_advice"].items()},
            methods={str(k): str(v) for k, v in data["methods"].items()},
            never_called=frozenset(str(x) for x in data["never_called"]),
        )
    except (KeyError, TypeError, AttributeError) as e:
        raise MappingError("the mapping table is not in the expected form") from e


# ------------------------------------------------------------------------------- identifiers
def execution_id(run_id: object) -> str | None:
    """The public identifier of an execution, from the host's identifier of it."""
    if isinstance(run_id, str) and run_id.startswith("run-") and len(run_id) == 36 and set(run_id[4:]) <= _HEX32:  # noqa: PLR2004
        return "exe-" + run_id[4:]
    return None


def host_run_id(public_execution_id: str) -> str:
    return "run-" + public_execution_id[4:]


def revision(host_revision: object, lineage: str) -> str:
    """The opaque validator of a resource: the host's revision, bound to the lineage it belongs to."""
    number = host_revision if isinstance(host_revision, int) and not isinstance(host_revision, bool) else 0
    return f"r{number}.{hashlib.sha256(lineage.encode('utf-8')).hexdigest()[:12]}"


def parse_revision(validator: str, lineage: str) -> int | None:
    """The host revision a validator stands for, or ``None`` when it is not a validator of this lineage.

    One revision has one validator. Another spelling of the number, or the digest of another lineage, is
    not one: callers compare validators for equality, so two of them must never mean the same revision.
    """
    head = validator.partition(".")[0]
    digits = head[1:]
    if not head.startswith("r") or not (digits.isascii() and digits.isdigit()) or len(digits) > _REVISION_DIGITS:
        return None
    number = int(digits)
    return number if revision(number, lineage) == validator else None


def encode_cursor(host_cursor: object) -> str:
    """An opaque page token for the host's cursor."""
    if not isinstance(host_cursor, dict):
        return ""
    raw = json.dumps(
        {"l": str(host_cursor.get("lineage", "")), "s": int(host_cursor.get("sequence", 0))}, separators=(",", ":")
    )
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")


def decode_cursor(token: str) -> dict[str, Any] | None:
    """The host cursor behind a page token, or ``None`` when the token is not one the platform issued."""
    try:
        raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
        body = json.loads(raw)
        lineage, sequence = body["l"], body["s"]
    except (ValueError, KeyError, TypeError):
        return None
    if not isinstance(lineage, str) or not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
        return None
    cursor = {"lineage": lineage, "sequence": sequence}
    # One position has one token. Another spelling of it is not a token the platform issued.
    return cursor if encode_cursor(cursor) == token else None


def parse_actor(on_behalf_of: object) -> m.Actor | None:
    """The actor of an operation, as the host recorded it: a principal and, for an agent, its label."""
    if not isinstance(on_behalf_of, str) or not on_behalf_of:
        return None
    principal, _, label = on_behalf_of.partition("/")
    return m.Actor(principal_id=principal, agent_label=label or None)


# ------------------------------------------------------------------------------- views
def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _obj(value: object) -> dict[str, Any]:
    """A decoded JSON object, or an empty one when the host sent something else."""
    return value if isinstance(value, dict) else {}


def failure(table: MappingTable, host_failure: object) -> m.Failure | None:
    if not isinstance(host_failure, dict):
        return None
    raw_class = host_failure.get("class")
    code, raw = table.value("failure_class", raw_class)
    side_effect, side_effect_raw = (
        table.value("side_effect", host_failure.get("side_effect")) if "side_effect" in host_failure else (None, None)
    )
    return m.Failure(
        code=code,
        code_raw=raw,
        retry=table.retry_for(raw_class) if isinstance(raw_class, str) else Retry.NEVER.value,
        message=str(host_failure.get("message", ""))[:2000],
        side_effect=side_effect,
        side_effect_raw=side_effect_raw,
    )


def network(table: MappingTable, host_network: object) -> m.NetworkView:
    if not isinstance(host_network, dict):
        return m.NetworkView(mode=UNRECOGNIZED)
    mode, raw = table.value("network_mode", host_network.get("mode"))
    entries: list[m.AllowEntryView] = []
    for entry in host_network.get("entries") or []:
        if not isinstance(entry, dict):
            continue
        dest = _obj(entry.get("destination"))
        ports = [
            m.PortRangeView.model_validate({"from": p.get("from"), "to": p.get("to")})
            for p in entry.get("ports") or []
            if isinstance(p, dict) and _int(p.get("from")) is not None and _int(p.get("to")) is not None
        ]
        entries.append(m.AllowEntryView(name=_str(dest.get("name")), network=_str(dest.get("network")), ports=ports))
    return m.NetworkView(mode=mode, mode_raw=raw, entries=entries)


def snapshot_ref(host_ref: object) -> m.SnapshotRef | None:
    if not isinstance(host_ref, dict):
        return None
    sid, generation = _str(host_ref.get("snapshot_id")), _int(host_ref.get("snapshot_generation"))
    return m.SnapshotRef(snapshot_id=sid, snapshot_generation=generation) if sid and generation is not None else None


def sandbox(table: MappingTable, view: dict[str, Any], project: str, lineage: str) -> m.Sandbox:
    state, state_raw = table.value("sandbox_state", view.get("state"))
    resources_view = _obj(view.get("resources"))
    image = _obj(view.get("image"))
    return m.Sandbox(
        sandbox_id=str(view.get("sandbox_id", "")),
        project=project,
        name=_str(view.get("name")),
        state=state,
        state_raw=state_raw,
        generation=_int(view.get("generation")) or 0,
        revision=revision(view.get("revision"), lineage),
        image=m.Image(alias=_str(image.get("alias")), digest=str(image.get("image_id", ""))),
        resources=m.ResourcesView(
            vcpus=_int(resources_view.get("vcpus")) or 0,
            memory_mib=_int(resources_view.get("memory_mib")) or 0,
            disk_mib=_int(resources_view.get("disk_mib")) or 0,
        ),
        network=network(table, resources_view.get("network")),
        expires_at=str(view.get("expires_at", "")),
        last_execution=execution_id(view.get("last_run")),
        quarantined=_str(view.get("quarantined")),
        failure=failure(table, view.get("failure")),
        source_snapshot=snapshot_ref(view.get("source_snapshot")),
        notes=[str(n)[:500] for n in view.get("notes") or [] if isinstance(n, str)][:32],
        updated_at=str(view.get("updated", "")),
    )


def snapshot(table: MappingTable, view: dict[str, Any], project: str, lineage: str) -> m.Snapshot:
    state, state_raw = table.value("snapshot_state", view.get("state"))
    ref = _obj(view.get("snapshot"))
    source = view.get("source_sandbox")
    source_ref = None
    if isinstance(source, list) and len(source) == 2 and isinstance(source[0], str) and _int(source[1]) is not None:  # noqa: PLR2004
        source_ref = m.SandboxRef(sandbox_id=source[0], generation=source[1])
    return m.Snapshot(
        snapshot_id=str(ref.get("snapshot_id", "")),
        snapshot_generation=_int(ref.get("snapshot_generation")) or 0,
        project=project,
        name=_str(view.get("name")),
        state=state,
        state_raw=state_raw,
        revision=revision(view.get("revision"), lineage),
        source_sandbox=source_ref,
        size_bytes=_int(view.get("size_bytes")) or 0,
        restore_count=_int(view.get("restore_count")) or 0,
        incompatible=[str(n)[:500] for n in view.get("incompatible") or [] if isinstance(n, str)][:32],
        failure=failure(table, view.get("failure")),
        created_at=str(view.get("created", "")),
    )


def _output_summary(table: MappingTable, capture: object) -> m.OutputSummary | None:
    if not isinstance(capture, dict):
        return None
    completeness, raw = table.value("output_completeness", capture.get("status"))
    return m.OutputSummary(
        stored_bytes=_int(capture.get("kept_bytes")) or 0,
        produced_bytes=_int(capture.get("total_bytes")) or 0,
        completeness=completeness,
        completeness_raw=raw,
    )


#: The provenance of each field of an execution result, as the host labels it.
EXECUTION_PROVENANCE: Final = {
    "status": m.GUEST_REPORTED,
    "exit_code": m.GUEST_REPORTED,
    "signal": m.GUEST_REPORTED,
    "durations.guest_ms": m.GUEST_REPORTED,
    "durations.wall_ms": m.HOST_OBSERVED,
    "stdout": m.GUEST_REPORTED,
    "stderr": m.GUEST_REPORTED,
    "host_backstop_fired": m.HOST_OBSERVED,
    "runtime_ended": m.HOST_OBSERVED,
    "evidence_status": m.HOST_OBSERVED,
    "note": m.HOST_OBSERVED,
}


def execution_from_run(
    table: MappingTable,
    run: dict[str, Any],
    project: str,
    operation_state: str = "SUCCEEDED",
    state_raw: str | None = None,
) -> m.Execution:
    """An execution that has ended, from the host's result of it."""
    status, status_raw = table.value("execution_status", run.get("status"))
    evidence, evidence_raw = table.value("evidence_status", run.get("evidence_status"))
    metrics = _obj(run.get("metrics"))
    return m.Execution(
        execution_id=execution_id(run.get("run_id")) or "",
        operation_id=str(run.get("operation_id", "")),
        project=project,
        sandbox_id=_str(run.get("sandbox_id")),
        generation=_int(run.get("generation")),
        state=operation_state,
        state_raw=state_raw,
        terminal=m.is_terminal(operation_state),
        status=status,
        status_raw=status_raw,
        exit_code=_int(run.get("exit_code")),
        signal=_int(run.get("signal")),
        durations=m.Durations(guest_ms=_int(run.get("guest_duration_ms")), wall_ms=_int(metrics.get("wall_ms"))),
        stdout=_output_summary(table, run.get("stdout")),
        stderr=_output_summary(table, run.get("stderr")),
        host_backstop_fired=bool(run.get("host_backstop_fired")),
        runtime_ended=bool(run.get("runtime_ended")),
        evidence_status=evidence,
        evidence_status_raw=evidence_raw,
        note=_str(run.get("note")),
        provenance=dict(EXECUTION_PROVENANCE),
    )


def execution_from_operation(table: MappingTable, view: dict[str, Any], project: str) -> m.Execution:
    """An execution in flight, or one that ended without a result, from the operation that runs it."""
    state, state_raw = table.value("operation_state", view.get("state"))
    result = view.get("result")
    if isinstance(result, dict) and result.get("type") == "run" and isinstance(result.get("data"), dict):
        return execution_from_run(table, result["data"], project, state, state_raw)
    target = view.get("sandbox")
    sandbox_id = target[0] if isinstance(target, list) and target and isinstance(target[0], str) else None
    generation = target[1] if isinstance(target, list) and len(target) == 2 and _int(target[1]) is not None else None  # noqa: PLR2004
    return m.Execution(
        execution_id=execution_id(view.get("run_id")) or "",
        operation_id=str(view.get("operation_id", "")),
        project=project,
        sandbox_id=sandbox_id,
        generation=generation,
        state=state,
        state_raw=state_raw,
        terminal=m.is_terminal(state),
    )


def operation(
    table: MappingTable,
    view: dict[str, Any],
    project: str,
    lineage: str,
    *,
    replayed: bool = False,
    key_digest: str | None = None,
) -> m.Operation:
    """A public operation view, from the host's operation view as of this answer."""
    state, state_raw = table.value("operation_state", view.get("state"))
    op_type, type_raw = table.value("operation_type", view.get("operation_type"))
    effect, effect_raw = table.value("effect", view.get("effect")) if view.get("effect") is not None else (None, None)
    cleanup, cleanup_raw = (
        table.value("cleanup", view.get("cleanup")) if view.get("cleanup") is not None else (None, None)
    )
    cancelled, cancelled_raw = (
        table.value("cancelled_by", view.get("cancelled_by")) if view.get("cancelled_by") is not None else (None, None)
    )
    initiated, initiated_raw = table.value("issuer", view.get("issuer"))
    target = view.get("sandbox")
    snap = _obj(view.get("snapshot"))
    result_view: m.OperationResult | None = None
    result = view.get("result")
    if isinstance(result, dict) and isinstance(result.get("data"), dict):
        kind, data = result.get("type"), result["data"]
        if kind == "sandbox":
            result_view = m.OperationResult(sandbox=sandbox(table, data, project, lineage))
        elif kind == "snapshot":
            result_view = m.OperationResult(snapshot=snapshot(table, data, project, lineage))
        elif kind == "run":
            result_view = m.OperationResult(execution=execution_from_run(table, data, project, state, state_raw))
    return m.Operation(
        operation_id=str(view.get("operation_id", "")),
        project=project,
        type=op_type,
        type_raw=type_raw,
        state=state,
        state_raw=state_raw,
        terminal=m.is_terminal(state),
        effect=effect,
        effect_raw=effect_raw,
        failure=failure(table, view.get("failure")),
        cleanup=cleanup,
        cleanup_raw=cleanup_raw,
        cancelled_by=cancelled,
        cancelled_by_raw=cancelled_raw,
        target=m.OperationTarget(
            sandbox_id=target[0] if isinstance(target, list) and target and isinstance(target[0], str) else None,
            generation=target[1]
            if isinstance(target, list) and len(target) == 2 and _int(target[1]) is not None  # noqa: PLR2004 - a sandbox and its generation are a pair
            else None,
            snapshot_id=_str(snap.get("snapshot_id")),
            snapshot_generation=_int(snap.get("snapshot_generation")),
            execution_id=execution_id(view.get("run_id")),
        ),
        result=result_view,
        initiated_by=initiated,
        initiated_by_raw=initiated_raw,
        actor=parse_actor(view.get("on_behalf_of")),
        created_at=_str(view.get("created")),
        updated_at=_str(view.get("updated")),
        replayed=replayed,
        idempotency_key_digest=key_digest,
    )


def output_chunk(table: MappingTable, chunk: dict[str, Any], public_execution_id: str, raw_len: int) -> m.OutputChunk:
    completeness, raw = table.value("output_completeness", chunk.get("completeness"))
    offset = _int(chunk.get("offset")) or 0
    return m.OutputChunk(
        execution_id=public_execution_id,
        stream=str(chunk.get("stream", "")),
        offset=offset,
        data_base64=str(chunk.get("data_b64", "")),
        next_offset=offset + raw_len,
        eof=bool(chunk.get("eof")),
        stored_bytes=_int(chunk.get("stored_bytes")) or 0,
        produced_bytes=_int(chunk.get("produced_bytes")) or 0,
        completeness=completeness,
        completeness_raw=raw,
    )
