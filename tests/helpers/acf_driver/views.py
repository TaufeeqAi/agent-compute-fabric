"""Typed, read-only views over the documents the host answers with.

The field names are the ones of the published API description (``execution/contracts/host-api.json``): a view is a
thin wrapper over one JSON object that gives the fields the suites assert on as attributes, and the whole object
as a mapping. Nothing here interprets a value: an unknown state or class is returned as the host sent it.

These classes deliberately do not come from the client's Python package. A black-box suite that shared the
client's models would pass whenever the client and its own models agree, which is exactly the failure it exists
to catch.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from acf_driver.base import TERMINAL_STATES, DriverError


class View(Mapping[str, Any]):
    """A read-only wrapper over one JSON object."""

    def __init__(self, raw: Mapping[str, Any]) -> None:
        if not isinstance(raw, Mapping):
            raise DriverError(f"expected a JSON object for {type(self).__name__}, got {type(raw).__name__}: {raw!r}")
        self.raw: Mapping[str, Any] = raw

    def __getitem__(self, key: str) -> Any:
        return self.raw[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.raw)

    def __len__(self) -> int:
        return len(self.raw)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({json.dumps(self.raw, sort_keys=True)[:800]})"

    # ---- typed access to members; a missing or mistyped member is a driver error that names it
    def _text(self, key: str) -> str:
        value = self.raw.get(key)
        if not isinstance(value, str):
            raise DriverError(f"{type(self).__name__}.{key} is not a string: {value!r} in {self!r}")
        return value

    def _opt_text(self, key: str) -> str | None:
        value = self.raw.get(key)
        if value is not None and not isinstance(value, str):
            raise DriverError(f"{type(self).__name__}.{key} is neither a string nor null: {value!r}")
        return value

    def _int(self, key: str) -> int:
        value = self.raw.get(key)
        if isinstance(value, bool) or not isinstance(value, int):
            raise DriverError(f"{type(self).__name__}.{key} is not an integer: {value!r} in {self!r}")
        return value

    def _opt_int(self, key: str) -> int | None:
        value = self.raw.get(key)
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int):
            raise DriverError(f"{type(self).__name__}.{key} is neither an integer nor null: {value!r}")
        return value

    def _flag(self, key: str) -> bool:
        value = self.raw.get(key)
        if not isinstance(value, bool):
            raise DriverError(f"{type(self).__name__}.{key} is not a boolean: {value!r} in {self!r}")
        return value

    def _object(self, key: str) -> Mapping[str, Any]:
        value = self.raw.get(key)
        if not isinstance(value, Mapping):
            raise DriverError(f"{type(self).__name__}.{key} is not an object: {value!r} in {self!r}")
        return value

    def _opt_object(self, key: str) -> Mapping[str, Any] | None:
        value = self.raw.get(key)
        if value is not None and not isinstance(value, Mapping):
            raise DriverError(f"{type(self).__name__}.{key} is neither an object nor null: {value!r}")
        return value

    def _array(self, key: str) -> list[Any]:
        value = self.raw.get(key, [])
        if not isinstance(value, list):
            raise DriverError(f"{type(self).__name__}.{key} is not an array: {value!r} in {self!r}")
        return value


def _pair(value: Any, what: str) -> tuple[str, int]:
    """``[id, generation]`` as the host encodes a (sandbox, generation) reference."""
    if not isinstance(value, list) or len(value) != 2 or not isinstance(value[0], str) or not isinstance(value[1], int):
        raise DriverError(f"{what} is not an [id, generation] pair: {value!r}")
    return value[0], value[1]


@dataclass(frozen=True)
class Cursor:
    """A position in one store's history: meaningful only with its lineage."""

    lineage: str
    sequence: int

    def __str__(self) -> str:
        return f"{self.lineage}:{self.sequence}"

    def to_wire(self) -> dict[str, Any]:
        return {"lineage": self.lineage, "sequence": self.sequence}

    @classmethod
    def of(cls, raw: Any, what: str) -> Cursor:
        if (
            not isinstance(raw, Mapping)
            or not isinstance(raw.get("lineage"), str)
            or not isinstance(raw.get("sequence"), int)
        ):
            raise DriverError(f"{what} is not a {{lineage, sequence}} object: {raw!r}")
        return cls(str(raw["lineage"]), int(raw["sequence"]))


class Refusal(View):
    """``REFUSED {class, retry, message}``: nothing was applied and nothing was recorded."""

    @property
    def failure_class(self) -> str:
        return self._text("class")

    @property
    def retry(self) -> str:
        return self._text("retry")

    @property
    def message(self) -> str:
        return self._text("message")


class Failure(View):
    """The failure of an operation, or of a generation: ``{class, message, side_effect}``."""

    @property
    def failure_class(self) -> str:
        return self._text("class")

    @property
    def message(self) -> str:
        return self._text("message")

    @property
    def side_effect(self) -> str:
        return self._text("side_effect")


class Sandbox(View):
    @property
    def sandbox_id(self) -> str:
        return self._text("sandbox_id")

    @property
    def generation(self) -> int:
        return self._int("generation")

    @property
    def state(self) -> str:
        return self._text("state")

    @property
    def name(self) -> str | None:
        return self._opt_text("name")

    @property
    def revision(self) -> int:
        return self._int("revision")

    @property
    def jail_id(self) -> str:
        """The host-derived name of this generation's mechanisms: control group, namespace handle, expiry ticket."""
        return f"{self.sandbox_id}-g{self.generation}"

    @property
    def vmm_identity(self) -> tuple[int, int] | None:
        """``(pid, start_time_ticks)`` of the runtime process the host recorded, or ``None`` when it records none."""
        process = self._opt_object("process")
        if process is None:
            return None
        return int(process["pid"]), int(process["start_time_ticks"])

    @property
    def quarantined(self) -> str | None:
        """The reason, when the generation carries the condition ``QUARANTINED``."""
        return self._opt_text("quarantined")

    @property
    def failure(self) -> Failure | None:
        found = self._opt_object("failure")
        return None if found is None else Failure(found)

    @property
    def resources(self) -> Mapping[str, Any]:
        return self._object("resources")

    @property
    def network(self) -> Mapping[str, Any]:
        network = self.resources.get("network")
        if not isinstance(network, Mapping):
            raise DriverError(f"the sandbox has no network intent: {self!r}")
        return network

    @property
    def expires_at(self) -> str:
        return self._text("expires_at")

    @property
    def last_run(self) -> str | None:
        return self._opt_text("last_run")

    @property
    def source_snapshot(self) -> tuple[str, int] | None:
        ref = self._opt_object("source_snapshot")
        return None if ref is None else (str(ref["snapshot_id"]), int(ref["snapshot_generation"]))

    @property
    def notes(self) -> list[str]:
        return [str(note) for note in self._array("notes")]

    @property
    def owner(self) -> tuple[str, str]:
        """``(peer_id, owner_scope)`` of the request that created the sandbox."""
        tags = self._object("tags")
        return str(tags["peer_id"]), str(tags["owner_scope"])


class Snapshot(View):
    @property
    def snapshot_id(self) -> str:
        return str(self._object("snapshot")["snapshot_id"])

    @property
    def snapshot_generation(self) -> int:
        return int(self._object("snapshot")["snapshot_generation"])

    @property
    def ref(self) -> tuple[str, int]:
        return self.snapshot_id, self.snapshot_generation

    @property
    def state(self) -> str:
        return self._text("state")

    @property
    def name(self) -> str | None:
        return self._opt_text("name")

    @property
    def restore_count(self) -> int:
        return self._int("restore_count")

    @property
    def size_bytes(self) -> int:
        return self._int("size_bytes")

    @property
    def manifest_digest(self) -> str | None:
        return self._opt_text("manifest_digest")

    @property
    def source_sandbox(self) -> tuple[str, int] | None:
        raw = self.raw.get("source_sandbox")
        return None if raw is None else _pair(raw, "source_sandbox")

    @property
    def incompatible(self) -> list[str]:
        return [str(reason) for reason in self._array("incompatible")]

    @property
    def owner(self) -> tuple[str, str]:
        tags = self._object("tags")
        return str(tags["peer_id"]), str(tags["owner_scope"])


class Stream(View):
    """One captured output stream of an execution."""

    @property
    def status(self) -> str:
        return self._text("status")

    @property
    def total_bytes(self) -> int:
        return self._int("total_bytes")

    @property
    def kept_bytes(self) -> int:
        return self._int("kept_bytes")

    @property
    def is_inline(self) -> bool:
        """Whether the kept bytes travel in this very document (large output is stored and read with ``run output``)."""
        return len(base64.b64decode(self._text("data_b64"))) == self.kept_bytes

    def inline(self) -> bytes:
        data = base64.b64decode(self._text("data_b64"))
        if len(data) != self.kept_bytes:
            raise DriverError(
                f"the host kept {self.kept_bytes} bytes of this stream and sent {len(data)} of them inline: "
                "read the stored output with `run output` (AcfLocal.run_output)"
            )
        return data


class Run(View):
    """The record of one execution (``RunResult``)."""

    @property
    def run_id(self) -> str:
        return self._text("run_id")

    @property
    def operation_id(self) -> str:
        return self._text("operation_id")

    @property
    def sandbox_id(self) -> str:
        return self._text("sandbox_id")

    @property
    def generation(self) -> int:
        return self._int("generation")

    @property
    def status(self) -> str:
        """EXITED | SIGNALED | TIMED_OUT | SPAWN_FAILED | CANCELLED | UNKNOWN."""
        return self._text("status")

    @property
    def exit_code(self) -> int | None:
        return self._opt_int("exit_code")

    @property
    def signal(self) -> int | None:
        return self._opt_int("signal")

    @property
    def stdout(self) -> Stream:
        return Stream(self._object("stdout"))

    @property
    def stderr(self) -> Stream:
        return Stream(self._object("stderr"))

    @property
    def stdout_text(self) -> str:
        return self.stdout.inline().decode("utf-8", errors="replace")

    @property
    def stderr_text(self) -> str:
        return self.stderr.inline().decode("utf-8", errors="replace")

    def stdout_json(self) -> Any:
        """The captured stdout parsed as JSON (the guest-side probes print one document)."""
        text = self.stdout_text
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            raise DriverError(
                f"run {self.run_id}: stdout is not JSON ({e}); status {self.status}, exit {self.exit_code}, "
                f"stdout={text[:300]!r}, stderr={self.stderr_text[:600]!r}"
            ) from e

    @property
    def evidence_status(self) -> str:
        return self._text("evidence_status")

    @property
    def host_backstop_fired(self) -> bool:
        return self._flag("host_backstop_fired")

    @property
    def runtime_ended(self) -> bool:
        return self._flag("runtime_ended")

    @property
    def guest_containment(self) -> str:
        return self._text("guest_containment")

    @property
    def guest_duration_ms(self) -> int:
        return self._int("guest_duration_ms")

    @property
    def profile_digest(self) -> str:
        return str(self._object("profile_id")["digest"])

    def evidence(self, resource: str) -> Mapping[str, Any]:
        """The resource-evidence entry for ``resource`` (``guest_pids``, ``runtime_ms``, ``stdout_bytes``, ``memory`` ...)."""
        entries = [entry for entry in self._array("resource_evidence") if isinstance(entry, Mapping)]
        for entry in entries:
            if entry.get("resource") == resource:
                return entry
        names = [entry.get("resource") for entry in entries]
        raise DriverError(f"run {self.run_id} has no resource evidence for {resource!r} (it has: {names})")

    def succeeded(self) -> bool:
        """The command ended by itself with exit status 0."""
        return self.status == "EXITED" and self.exit_code == 0


class HostChange(View):
    """What an operator method changed (the result of ``host.set_mode``, ``profile.reload`` ...)."""

    @property
    def mode(self) -> str | None:
        return self._opt_text("mode")

    @property
    def profile_digest(self) -> str | None:
        profile = self._opt_object("profile")
        return None if profile is None else str(profile["digest"])

    @property
    def note(self) -> str | None:
        return self._opt_text("note")


class Operation(View):
    """An operation as of the answer that carried it."""

    @property
    def operation_id(self) -> str:
        return self._text("operation_id")

    @property
    def operation_type(self) -> str:
        return self._text("operation_type")

    @property
    def state(self) -> str:
        return self._text("state")

    @property
    def terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    @property
    def effect(self) -> str | None:
        return self._opt_text("effect")

    @property
    def cleanup(self) -> str | None:
        return self._opt_text("cleanup")

    @property
    def cancelled_by(self) -> str | None:
        return self._opt_text("cancelled_by")

    @property
    def failure(self) -> Failure | None:
        found = self._opt_object("failure")
        return None if found is None else Failure(found)

    @property
    def failure_class(self) -> str | None:
        failure = self.failure
        return None if failure is None else failure.failure_class

    @property
    def issuer(self) -> str:
        return self._text("issuer")

    @property
    def owner(self) -> tuple[str, str]:
        tags = self._object("tags")
        return str(tags["peer_id"]), str(tags["owner_scope"])

    @property
    def on_behalf_of(self) -> str | None:
        return self._opt_text("on_behalf_of")

    @property
    def target(self) -> str:
        return self._text("target")

    @property
    def step(self) -> str | None:
        return self._opt_text("step")

    @property
    def run_id(self) -> str | None:
        return self._opt_text("run_id")

    @property
    def sandbox(self) -> tuple[str, int] | None:
        raw = self.raw.get("sandbox")
        return None if raw is None else _pair(raw, "operation.sandbox")

    @property
    def profile_digest(self) -> str:
        return str(self._object("profile_id")["digest"])

    @property
    def activation_epoch(self) -> int:
        return self._int("activation_epoch")

    @property
    def revision(self) -> int:
        return self._int("revision")

    @property
    def created(self) -> str:
        return self._text("created")

    @property
    def result_type(self) -> str | None:
        result = self._opt_object("result")
        return None if result is None else str(result.get("type"))

    def _result(self, kind: str) -> Mapping[str, Any]:
        result = self._opt_object("result")
        if result is None or result.get("type") != kind or not isinstance(result.get("data"), Mapping):
            raise DriverError(f"operation {self.operation_id} ({self.state}) carries no `{kind}` result: {self!r}")
        data: Mapping[str, Any] = result["data"]
        return data

    def sandbox_result(self) -> Sandbox:
        return Sandbox(self._result("sandbox"))

    def snapshot_result(self) -> Snapshot:
        return Snapshot(self._result("snapshot"))

    def run_result(self) -> Run:
        return Run(self._result("run"))

    def host_change(self) -> HostChange:
        return HostChange(self._result("host"))


class HostInfo(View):
    @property
    def version(self) -> str:
        return self._text("version")

    @property
    def host_id(self) -> str:
        return self._text("host_id")

    @property
    def protocols(self) -> list[str]:
        return [str(p) for p in self._array("protocols")]

    @property
    def features(self) -> list[str]:
        return [str(f) for f in self._array("features")]

    @property
    def mode(self) -> str:
        return self._text("mode")

    @property
    def containment_reasons(self) -> list[Mapping[str, Any]]:
        return [reason for reason in self._array("containment_reasons") if isinstance(reason, Mapping)]

    @property
    def read_only_reason(self) -> str | None:
        return self._opt_text("read_only_reason")

    @property
    def lineage(self) -> str:
        return self._text("lineage")

    @property
    def activation_epoch(self) -> int:
        return self._int("activation_epoch")

    @property
    def instance_id(self) -> str:
        return self._text("instance_id")

    @property
    def backend_name(self) -> str:
        return str(self._object("backend")["name"])

    @property
    def backend_version(self) -> str:
        return str(self._object("backend")["version"])

    @property
    def capabilities(self) -> Mapping[str, Any]:
        return self._object("capabilities")

    @property
    def network_modes(self) -> list[str]:
        return [str(mode) for mode in self.capabilities.get("network_modes", [])]

    @property
    def profile_digest(self) -> str:
        return str(self._object("profile")["digest"])

    @property
    def parameters(self) -> Mapping[str, Any]:
        return self._object("parameters")

    @property
    def ceilings(self) -> Mapping[str, Any]:
        ceilings = self.parameters.get("ceilings")
        if not isinstance(ceilings, Mapping):
            raise DriverError(f"host.info reports no profile ceilings: {self!r}")
        return ceilings

    @property
    def store_integrity(self) -> str:
        return self._text("store_integrity")

    @property
    def live_sandboxes(self) -> int:
        return self._int("live_sandboxes")

    @property
    def snapshots(self) -> int:
        return self._int("snapshots")

    @property
    def quarantined(self) -> int:
        return self._int("quarantined")

    @property
    def operations_in_flight(self) -> int:
        return self._int("operations_in_flight")


class OutputChunk(View):
    """A slice of one stream of an execution's stored output."""

    @property
    def data(self) -> bytes:
        return base64.b64decode(self._text("data_b64"))

    @property
    def offset(self) -> int:
        return self._int("offset")

    @property
    def stored_bytes(self) -> int:
        return self._int("stored_bytes")

    @property
    def produced_bytes(self) -> int:
        return self._int("produced_bytes")

    @property
    def completeness(self) -> str:
        return self._text("completeness")

    @property
    def eof(self) -> bool:
        return self._flag("eof")


@dataclass(frozen=True)
class Page[T]:
    """One page of a listing: ``items`` in ascending revision order, and where the listing stands."""

    items: list[T]
    more: bool
    cursor: Cursor


class Answer(View):
    """One answer in wire form: ``{"protocol", "answer", "refusal" | "operation" | "result", "as_of"}``.

    This is what the host sends for one request, and what ``acf-local --json`` prints for one command.
    """

    @property
    def protocol(self) -> str:
        return self._text("protocol")

    @property
    def answer(self) -> str:
        """REFUSED | OPERATION | RESULT."""
        return self._text("answer")

    @property
    def request_id(self) -> str | None:
        return self._opt_text("request_id")

    @property
    def as_of(self) -> Cursor | None:
        """The committed state the answer reflects; absent on a refusal that consulted no state."""
        raw = self.raw.get("as_of")
        return None if raw is None else Cursor.of(raw, "as_of")

    @property
    def sequence(self) -> int:
        """The commit sequence of ``as_of`` (the answer must carry one)."""
        as_of = self.as_of
        if as_of is None:
            raise DriverError(f"the answer does not say which committed state it reflects: {self!r}")
        return as_of.sequence

    @property
    def refusal(self) -> Refusal | None:
        found = self._opt_object("refusal")
        return None if found is None else Refusal(found)

    @property
    def operation(self) -> Operation | None:
        found = self._opt_object("operation")
        return None if found is None else Operation(found)

    def refused(self) -> Refusal:
        """The refusal this answer is; a driver error says what it was instead."""
        refusal = self.refusal
        if self.answer != "REFUSED" or refusal is None:
            raise DriverError(f"expected a refusal, the host answered {self.answer}: {self!r}")
        return refusal

    def accepted(self) -> Operation:
        """The operation this answer carries; a driver error says what it was instead."""
        operation = self.operation
        if self.answer != "OPERATION" or operation is None:
            raise DriverError(f"expected an accepted operation, the host answered {self.answer}: {self!r}")
        return operation

    def succeeded(self) -> Operation:
        """The operation, which must have ended ``SUCCEEDED``."""
        operation = self.accepted()
        if operation.state != "SUCCEEDED":
            raise DriverError(
                f"operation {operation.operation_id} ({operation.operation_type}) is {operation.state}, "
                f"expected SUCCEEDED: failure={operation.failure!r}"
            )
        return operation

    def result(self, kind: str) -> Any:
        """The data of a read answered with a ``RESULT`` of type ``kind``."""
        result = self._opt_object("result")
        if self.answer != "RESULT" or result is None or result.get("type") != kind:
            raise DriverError(f"expected a `{kind}` result, the host answered: {self!r}")
        return result.get("data")

    def host_info(self) -> HostInfo:
        return HostInfo(self.result("host_info"))

    def sandbox(self) -> Sandbox:
        return Sandbox(self.result("sandbox"))

    def run(self) -> Run:
        return Run(self.result("run"))

    def output(self) -> OutputChunk:
        return OutputChunk(self.result("output"))

    def metrics(self) -> Mapping[str, Any]:
        data = self.result("metrics")
        if not isinstance(data, Mapping):
            raise DriverError(f"host.metrics did not return an object: {data!r}")
        return data

    def _page(self, kind: str) -> tuple[list[Mapping[str, Any]], bool, Cursor]:
        data = self.result(kind)
        if (
            not isinstance(data, Mapping)
            or not isinstance(data.get("items"), list)
            or not isinstance(data.get("more"), bool)
        ):
            raise DriverError(f"the `{kind}` result is not a page: {data!r}")
        return list(data["items"]), bool(data["more"]), Cursor.of(data.get("next"), f"{kind}.next")

    def sandboxes(self) -> Page[Sandbox]:
        items, more, cursor = self._page("sandboxes")
        return Page([Sandbox(item) for item in items], more, cursor)

    def snapshots(self) -> Page[Snapshot]:
        items, more, cursor = self._page("snapshots")
        return Page([Snapshot(item) for item in items], more, cursor)

    def operations(self) -> Page[Operation]:
        items, more, cursor = self._page("operations")
        return Page([Operation(item) for item in items], more, cursor)
