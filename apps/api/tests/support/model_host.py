"""A model of the host agent, for tests of the platform's own logic.

It implements the ``HostBinding`` port in memory and follows the rules of the host that the platform
relies on: operations keyed by a caller-supplied id inside a ``(peer, scope)`` namespace; a duplicate
of a known operation is answered with that operation before anything else is checked; ``REFUSED``
means nothing was recorded; tags separate scopes; a generation's resources never change; a name is
unique within a scope; lists return every record that is not destroyed or deleted.

It is a model and not the host. A test that passes here proves the platform's logic against these
rules; the tests marked ``host`` run the same platform against the real test host binary.

On top of the rules it offers the controls the fault-point tests need: lose an answer before or after
acceptance, become unreachable, forget finished operations, replace or regress the store lineage,
change the platform's peer id, shift the clock, refuse the platform itself, omit a feature, hold an
operation open, fail every start, and emit a state or a refusal class nobody knows.
"""

from __future__ import annotations

import asyncio
import base64
import copy
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from acf_api.core.clock import parse_rfc3339, rfc3339
from acf_api.core.host.binding import HostInfo, Lane, parse_host_info
from acf_api.core.host.wire import (
    AsOf,
    HostIdentityError,
    HostOperation,
    HostRefusal,
    HostRequest,
    HostResult,
    LostAnswer,
    Unreachable,
)

TERMINAL = {"SUCCEEDED", "FAILED", "CANCELLED", "UNKNOWN"}


class Crash(BaseException):
    """The core process dies at this point: nothing after it runs, and nothing was written to the host."""


FEATURES = ["allowlist_network", "change_cursor", "host_modes", "operation_list", "quarantine_release", "scope_tags"]


@dataclass
class Fault:
    """What happens to the next matching exchange."""

    #: ``unreachable`` (nothing written), ``lost_before`` (written, not applied, no answer),
    #: ``lost_after`` (applied, no answer), ``crash`` (the core dies before it writes).
    kind: str
    method: str | None = None
    remaining: int = 1


@dataclass
class Sent:
    """One request the platform sent, as the host saw it."""

    method: str
    owner_scope: str
    operation_id: str | None
    issued_at: str | None
    on_behalf_of: str | None
    request_id: str | None
    params: Any
    lane: Lane
    raw: bytes


@dataclass
class ModelHost:
    host_id: str = "host-model"
    peer_id: str = "platform-peer"
    lineage: str = "lineage-1"
    now_ms: Callable[[], int] = lambda: 0
    features: list[str] = field(default_factory=lambda: list(FEATURES))
    protocols: list[str] = field(default_factory=lambda: ["acf.host/2"])
    acceptance_horizon_ms: int = 300_000
    clock_skew_tolerance_ms: int = 30_000
    operation_retention_ms: int = 86_400_000
    #: The envelope: how many sandboxes the host admits at once. It is not advertised, as on the real host.
    max_sandboxes: int = 8
    #: The pool of identifiers, which is advertised, and which is far larger than the envelope.
    identifier_slots: int = 4096
    network_modes: list[str] = field(default_factory=lambda: ["none", "allowlist"])
    max_vcpus: int = 8
    max_memory_mib: int = 16384
    max_disk_mib: int = 65536
    max_runtime_ms: int = 3_600_000
    lifetime_default_secs: int = 3600
    lifetime_max_secs: int = 86_400
    #: Milliseconds the host's clock is ahead of the platform's.
    clock_offset_ms: int = 0
    #: Extra members merged into ``host.info`` (for values the host does not report today).
    info_extra: dict[str, Any] = field(default_factory=dict)
    #: What ``host.info`` reports as the host's id, when it is not the id the binding was configured with.
    info_host_id: str | None = None
    #: Image aliases and environment variable names the safety profile permits. ``None``: every one.
    #: The real host refuses the others in words that quote the alias or the name it was sent.
    allowed_images: list[str] | None = None
    allowed_env: list[str] | None = None

    def __post_init__(self) -> None:
        self.sequence = 0
        self.sandboxes: dict[str, dict[str, Any]] = {}
        self.snapshots: dict[str, dict[str, Any]] = {}
        #: (peer id, owner scope, operation id) -> operation view.
        self.operations: dict[tuple[str, str, str], dict[str, Any]] = {}
        self._fingerprints: dict[tuple[str, str, str], str] = {}
        self.outputs: dict[str, dict[str, bytes]] = {}
        self.sent: list[Sent] = []
        self.faults: list[Fault] = []
        self.refuse_platform: str | None = None
        self.identity_error: str | None = None
        #: Methods whose operations stay IN_PROGRESS until ``finish`` is called.
        self.hold: set[str] = set()
        self.fail_starts = False
        self.unknown_state: str | None = None
        self.refuse_next: tuple[str, str, str] | None = None
        #: method -> an event a submission of that method waits for before the host looks at it.
        self.blocked: dict[str, asyncio.Event] = {}
        self._counter = 0
        self.closed = False

    # ------------------------------------------------------------------ controls
    def fault(self, kind: str, method: str | None = None, times: int = 1) -> None:
        self.faults.append(Fault(kind, method, times))

    def _take_fault(self, method: str, kinds: set[str]) -> str | None:
        for f in self.faults:
            if f.kind in kinds and f.method in {None, method}:
                f.remaining -= 1
                if f.remaining <= 0:
                    self.faults.remove(f)
                return f.kind
        return None

    def block(self, method: str) -> asyncio.Event:
        """Make submissions of ``method`` wait until the returned event is set."""
        event = asyncio.Event()
        self.blocked[method] = event
        return event

    def forget_operations(self, keep: int = 0) -> int:
        """Remove finished operations, oldest first, down to ``keep``. What a journal compaction does."""
        finished = [k for k, v in self.operations.items() if v["state"] in TERMINAL]
        drop = finished[: max(0, len(finished) - keep)]
        for key in drop:
            del self.operations[key]
        return len(drop)

    def replace_lineage(self, lineage: str = "lineage-2") -> None:
        """A replaced host store: another lineage, and nothing of the old one."""
        self.lineage, self.sequence = lineage, 0
        self.sandboxes.clear()
        self.snapshots.clear()
        self.operations.clear()
        self._fingerprints.clear()

    def regress(self, sequence: int) -> None:
        """The same lineage at a lower commit sequence: a store older than the system it describes."""
        self.sequence = sequence

    def finish(self, operation_id: str, state: str = "SUCCEEDED", **changes: Any) -> None:
        """End a held operation."""
        for (_, _, oid), view in self.operations.items():
            if oid == operation_id:
                view["state"] = state
                view["effect"] = changes.pop("effect", "APPLIED" if state == "SUCCEEDED" else "NOT_APPLIED")
                view.update(changes)
                self._touch(view)
                sandbox = self.sandboxes.get(view.get("sandbox", [None])[0])
                if view["operation_type"] == "exec.run" and sandbox is not None and sandbox["state"] == "RUNNING":
                    sandbox["state"] = "COMPLETED"
                    self._touch(sandbox)

    def submissions(self, operation_id: str) -> list[Sent]:
        return [s for s in self.sent if s.operation_id == operation_id and s.method != "operation.get"]

    def mutating(self) -> list[Sent]:
        return [s for s in self.sent if s.operation_id is not None]

    # ------------------------------------------------------------------ internals
    def _host_now(self) -> int:
        return self.now_ms() + self.clock_offset_ms

    def _stamp(self) -> str:
        return rfc3339(self._host_now())

    def _next_id(self, prefix: str) -> str:
        self._counter += 1
        return f"{prefix}-{self._counter:032x}"

    def _commit(self) -> int:
        self.sequence += 1
        return self.sequence

    def _as_of(self) -> AsOf:
        return AsOf(self.lineage, self.sequence)

    def _touch(self, record: dict[str, Any]) -> None:
        record["revision"] = self._commit()
        record["updated"] = self._stamp()

    def _tags(self, scope: str) -> dict[str, str]:
        return {"peer_id": self.peer_id, "owner_scope": scope}

    def _refuse(self, failure_class: str, retry: str, message: str) -> HostRefusal:
        return HostRefusal(failure_class, retry, message, self._as_of())

    def _visible(self, record: dict[str, Any], scope: str) -> bool:
        tags = record["tags"]
        return bool(tags["peer_id"] == self.peer_id and tags["owner_scope"] == scope)

    def _sandbox(self, scope: str, selector: str) -> dict[str, Any] | None:
        for sandbox in self.sandboxes.values():
            if self._visible(sandbox, scope) and selector in {sandbox["sandbox_id"], sandbox.get("name")}:
                return sandbox
        return None

    def _record(self, request: HostRequest, lane: Lane) -> None:
        self.sent.append(
            Sent(
                request.method,
                request.owner_scope,
                request.operation_id,
                request.issued_at,
                request.on_behalf_of,
                request.request_id,
                copy.deepcopy(request.params),
                lane,
                request.encode(),
            )
        )

    def _gate(self, request: HostRequest, lane: Lane) -> None:
        if self.closed:
            raise Unreachable("closed")
        if self.identity_error is not None:
            raise HostIdentityError(self.identity_error)
        if self._take_fault(request.method, {"unreachable"}) is not None:
            raise Unreachable("injected")
        if self._take_fault(request.method, {"crash"}) is not None:
            raise Crash
        self._record(request, lane)
        if self._take_fault(request.method, {"lost_before"}) is not None:
            raise LostAnswer("injected before acceptance")

    # ------------------------------------------------------------------ the port
    async def aclose(self) -> None:
        self.closed = True

    async def info(self) -> HostInfo:
        if self.identity_error is not None:
            raise HostIdentityError(self.identity_error)
        if self._take_fault("host.info", {"unreachable"}) is not None:
            raise Unreachable("injected")
        return parse_host_info(self.info_document())

    def info_document(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            "version": "model",
            "host_id": self.info_host_id or self.host_id,
            "protocols": list(self.protocols),
            "features": list(self.features),
            "mode": "SERVING",
            "containment_reasons": [],
            "lineage": self.lineage,
            "activation_epoch": 1,
            "instance_id": "model",
            "capabilities": {
                "backend": "model",
                "network_modes": list(self.network_modes),
                "secret_injection": False,
                "incremental_output": False,
                "identifier_slots": self.identifier_slots,
            },
            "parameters": {
                "acceptance_horizon_ms": self.acceptance_horizon_ms,
                "clock_skew_tolerance_ms": self.clock_skew_tolerance_ms,
                "operation_retention_ms": self.operation_retention_ms,
                "change_retention_ms": 3_600_000,
                "output_retention_ms": 3_600_000,
                "wait_max_ms": 30_000,
                "max_request_bytes": 1_048_576,
                "sandbox_lifetime_default_secs": self.lifetime_default_secs,
                "sandbox_lifetime_max_secs": self.lifetime_max_secs,
                "allowlist_max_entries": 32,
                "ceilings": {
                    "max_vcpus": self.max_vcpus,
                    "max_memory_mib": self.max_memory_mib,
                    "max_disk_mib": self.max_disk_mib,
                    "max_runtime_ms": self.max_runtime_ms,
                    "max_pids": 1024,
                    "max_stdout_bytes": 1_048_576,
                    "max_stderr_bytes": 1_048_576,
                    "max_argv_items": 256,
                    "max_argv_bytes": 65536,
                    "max_env_entries": 128,
                    "max_lifetime_secs": self.lifetime_max_secs,
                    "max_allowlist_entries": 32,
                },
            },
            "store_integrity": "ok",
            "live_sandboxes": 0,
            "snapshots": 0,
            "quarantined": 0,
            "operations_in_flight": 0,
        }
        document.update(self.info_extra)
        return document

    async def read(  # noqa: PLR0911 - one answer per read method of the host
        self, request: HostRequest, *, lane: Lane, principal_id: str | None = None
    ) -> HostResult | HostRefusal:
        self._gate(request, lane)
        if self.refuse_platform is not None:
            return self._refuse(self.refuse_platform, "NEVER", "the peer is not accepted")
        scope, params = request.owner_scope, request.params or {}
        method = request.method
        if method == "host.info":
            return HostResult("host_info", self.info_document(), self._as_of())
        if method == "sandbox.inspect":
            sandbox = self._sandbox(scope, str(params.get("sandbox")))
            if sandbox is None:
                return self._refuse("NOT_FOUND", "NEVER", "no such sandbox")
            return HostResult("sandbox", copy.deepcopy(sandbox), self._as_of())
        if method in {"sandbox.list", "snapshot.list", "operation.list"}:
            return self._list(method, scope, params)
        if method == "operation.get":
            view = self.operations.get((self.peer_id, scope, str(params.get("operation_id"))))
            if view is None:
                # The host names the identifier it was asked for, as the real one does.
                return self._refuse("NOT_FOUND", "NEVER", f"operation {params.get('operation_id')} does not exist")
            return HostResult("operation", self._operation_view(view), self._as_of())
        if method in {"run.inspect", "run.output"}:
            return self._run_read(method, scope, params)
        return self._refuse("INVALID_REQUEST", "NEVER", "unknown method")

    def _list(self, method: str, scope: str, params: dict[str, Any]) -> HostResult | HostRefusal:
        since = params.get("changed_since")
        after = 0
        if isinstance(since, dict):
            if since.get("lineage") != self.lineage:
                return self._refuse("CURSOR_EXPIRED", "AFTER_CHANGE", "the cursor belongs to another lineage")
            after = int(since.get("sequence", 0))
        limit = int(params.get("limit") or 100)
        if method == "sandbox.list":
            records = [s for s in self.sandboxes.values() if isinstance(since, dict) or s["state"] != "DESTROYED"]
            kind = "sandboxes"
        elif method == "snapshot.list":
            records = [s for s in self.snapshots.values() if isinstance(since, dict) or s["state"] != "DELETED"]
            kind = "snapshots"
        else:
            records = [self._operation_view(o) for o in self.operations.values()]
            kind = "operations"
        visible = sorted(
            (r for r in records if self._visible(r, scope) and r["revision"] > after), key=lambda r: r["revision"]
        )
        page = visible[:limit]
        more = len(visible) > limit
        next_seq = page[-1]["revision"] if page and more else self.sequence
        data = {"items": copy.deepcopy(page), "more": more, "next": {"lineage": self.lineage, "sequence": next_seq}}
        return HostResult(kind, data, self._as_of())

    def _run_read(self, method: str, scope: str, params: dict[str, Any]) -> HostResult | HostRefusal:
        run_id = str(params.get("run_id"))
        op = next(
            (o for o in self.operations.values() if o.get("run_id") == run_id and self._visible(o, scope)),
            None,
        )
        if op is None:
            return self._refuse("NOT_FOUND", "NEVER", f"run {run_id} does not exist")
        if method == "run.inspect":
            if op["state"] in TERMINAL and op.get("result"):
                return HostResult("run", copy.deepcopy(op["result"]["data"]), self._as_of())
            return HostResult("operation", self._operation_view(op), self._as_of())
        if op["state"] not in TERMINAL:
            return self._refuse("UNSUPPORTED", "AFTER_CHANGE", "the execution has not ended")
        stream = str(params.get("stream"))
        data = self.outputs.get(run_id, {}).get(stream, b"")
        offset = int(params.get("offset") or 0)
        if offset > len(data):
            return self._refuse("INVALID_REQUEST", "NEVER", "offset beyond the stored output")
        end = min(len(data), offset + int(params.get("max_bytes") or 65536))
        chunk = {
            "run_id": run_id,
            "stream": stream,
            "offset": offset,
            "data_b64": base64.b64encode(data[offset:end]).decode("ascii"),
            "stored_bytes": len(data),
            "produced_bytes": len(data),
            "completeness": "COMPLETE",
            "eof": end == len(data),
        }
        return HostResult("output", chunk, self._as_of())

    def _operation_view(self, view: dict[str, Any]) -> dict[str, Any]:
        out = copy.deepcopy(view)
        result = out.get("result")
        if isinstance(result, dict) and result.get("type") == "sandbox":
            # The result is the sandbox as of the answer, not as of the operation's end.
            current = self.sandboxes.get(result["data"]["sandbox_id"])
            if current is not None:
                result["data"] = copy.deepcopy(current)
        return out

    async def submit(
        self, request: HostRequest, *, lane: Lane, principal_id: str | None = None
    ) -> HostOperation | HostRefusal:
        self._gate(request, lane)
        gate = self.blocked.get(request.method)
        if gate is not None:
            await gate.wait()
        answer = self._apply(request)
        if self._take_fault(request.method, {"lost_after"}) is not None:
            raise LostAnswer("injected after acceptance")
        return answer

    def _apply(self, request: HostRequest) -> HostOperation | HostRefusal:  # noqa: PLR0911, PLR0912 - one branch per mutation of the host
        if self.refuse_platform is not None:
            return self._refuse(self.refuse_platform, "NEVER", "the peer is not accepted")
        scope, params, method = request.owner_scope, request.params or {}, request.method
        if request.operation_id is None or request.issued_at is None:
            return self._refuse("INVALID_REQUEST", "NEVER", "an operation id and issued_at are required")
        key = (self.peer_id, scope, request.operation_id)
        fingerprint = json.dumps({"m": method, "p": params}, sort_keys=True)
        existing = self.operations.get(key)
        if existing is not None:
            # A known operation is answered before the mode, the rate and the horizon are applied.
            if self._fingerprints[key] != fingerprint:
                return self._refuse("IDEMPOTENCY_CONFLICT", "NEVER", "the operation id names a different request")
            return HostOperation(self._operation_view(existing), self._as_of())
        issued = parse_rfc3339(request.issued_at)
        if issued is None:
            return self._refuse("INVALID_REQUEST", "NEVER", "issued_at is not a timestamp")
        age = self._host_now() - issued
        if age > self.acceptance_horizon_ms or age < -self.clock_skew_tolerance_ms:
            return self._refuse("EXPIRED_REQUEST", "NEVER", "issued_at is outside the acceptance horizon")
        if self.refuse_next is not None:
            failure_class, retry, message = self.refuse_next
            self.refuse_next = None
            return self._refuse(failure_class, retry, message)

        op: dict[str, Any] = {
            "operation_id": request.operation_id,
            "operation_type": method,
            "state": "SUCCEEDED",
            "issuer": "PEER",
            "tags": self._tags(scope),
            "target": "host",
            "profile_id": "model-profile",
            "activation_epoch": 1,
            "issued_at": request.issued_at,
            "on_behalf_of": request.on_behalf_of,
            "created": self._stamp(),
            "updated": self._stamp(),
            "effect": "APPLIED",
            "revision": 0,
        }

        def target(sandbox_id: str, *, containment: bool = False) -> dict[str, Any] | HostRefusal:
            sandbox = self._sandbox(scope, sandbox_id)
            if sandbox is None or sandbox["sandbox_id"] != sandbox_id:
                return self._refuse("NOT_FOUND", "NEVER", "no such sandbox")
            if params_generation is not None and sandbox["generation"] != params_generation:
                return self._refuse(
                    "REVISION_CONFLICT",
                    "AFTER_CHANGE",
                    f"sandbox {sandbox_id} is at generation {sandbox['generation']}, not {params_generation} (stale token)",
                )
            if_revision = (params.get("target") or params).get("if_revision")
            if if_revision is not None and sandbox["revision"] != if_revision:
                return self._refuse("REVISION_CONFLICT", "AFTER_CHANGE", "the sandbox is at another revision")
            if sandbox["state"] == "DESTROYED" and not containment:
                return self._refuse("STATE_CONFLICT", "AFTER_CHANGE", "the sandbox is destroyed")
            return sandbox

        params_generation = (params.get("target") or params).get("expected_generation")

        if method == "sandbox.create":
            resources = params["resources"]
            if self.allowed_images is not None and params["image"] not in self.allowed_images:
                # In the host's own words, which quote the alias it was asked for.
                return self._refuse(
                    "SAFETY_CONTROL_DENIED",
                    "AFTER_CHANGE",
                    f"image alias `{params['image']}` is not permitted by the safety profile",
                )
            if resources["vcpus"] > self.max_vcpus or resources["memory_mib"] > self.max_memory_mib:
                return self._refuse("SAFETY_CONTROL_DENIED", "AFTER_CHANGE", "above a ceiling of the safety profile")
            if resources["network"]["mode"] not in self.network_modes:
                return self._refuse("UNSUPPORTED", "AFTER_CHANGE", "the network mode is not offered")
            lifetime = params.get("lifetime_secs")
            if lifetime is not None and lifetime > self.lifetime_max_secs:
                return self._refuse(
                    "SAFETY_CONTROL_DENIED", "AFTER_CHANGE", "the lifetime is above the profile's ceiling"
                )
            name = params.get("name")
            if name is not None and self._sandbox(scope, name) is not None:
                return self._refuse(
                    "STATE_CONFLICT", "AFTER_CHANGE", "a sandbox with that name already exists in this scope"
                )
            live = [s for s in self.sandboxes.values() if s["state"] != "DESTROYED"]
            if len(live) >= self.max_sandboxes:
                return self._refuse("RESOURCE_EXHAUSTED", "SAME_REQUEST_LATER", "no capacity")
            sandbox = self._new_sandbox(scope, name, params["image"], resources, lifetime)
            op["sandbox"] = [sandbox["sandbox_id"], 1]
            op["target"] = sandbox["sandbox_id"]
            op["result"] = {"type": "sandbox", "data": sandbox}
        elif method in {"sandbox.start", "sandbox.stop", "sandbox.destroy"}:
            found = target(params["sandbox_id"], containment=method != "sandbox.start")
            if isinstance(found, HostRefusal):
                return found
            op["sandbox"] = [found["sandbox_id"], found["generation"]]
            op["target"] = found["sandbox_id"]
            if method == "sandbox.start":
                # A generation is started once. A stopped one is never started again: a sandbox continues
                # after a stop only through a new generation, which a restore creates.
                if found["state"] != "PROVISIONING":
                    return self._refuse(
                        "STATE_CONFLICT", "AFTER_CHANGE", "the sandbox cannot be started from its state"
                    )
                if self.fail_starts:
                    op["state"], op["effect"], op["cleanup"] = "FAILED", "NOT_APPLIED", "COMPLETE"
                    op["failure"] = {
                        "class": "DEPENDENCY_UNAVAILABLE",
                        "message": "the runtime did not start",
                        "side_effect": "NONE",
                    }
                else:
                    found["state"] = "READY"
            elif method == "sandbox.stop":
                found["state"] = "STOPPED"
                self._supersede(found["sandbox_id"])
            else:
                found["state"] = "DESTROYED"
                self._supersede(found["sandbox_id"])
            self._touch(found)
            op["result"] = {"type": "sandbox", "data": found}
        elif method == "exec.run":
            found = target(params["sandbox_id"])
            if isinstance(found, HostRefusal):
                return found
            # The two idle states: the guest agent is up and no run is in flight.
            if found["state"] not in {"READY", "COMPLETED"} and not self._run_in_flight(found["sandbox_id"]):
                return self._refuse("STATE_CONFLICT", "AFTER_CHANGE", "an execution needs a started, idle sandbox")
            if self.allowed_env is not None:
                for variable in [*(params["command"].get("env") or {}), *(params["command"].get("secret_env") or {})]:
                    if variable not in self.allowed_env:
                        return self._refuse(
                            "SAFETY_CONTROL_DENIED",
                            "AFTER_CHANGE",
                            f"environment variable `{variable}` is not on the safety-profile allowlist",
                        )
            if any(
                o["operation_type"] == "exec.run"
                and o["state"] not in TERMINAL
                and o.get("sandbox", [None])[0] == found["sandbox_id"]
                for o in self.operations.values()
            ):
                return self._refuse("STATE_CONFLICT", "AFTER_CHANGE", "an execution is already running in this sandbox")
            run_id = self._next_id("run")
            op["run_id"] = run_id
            op["sandbox"] = [found["sandbox_id"], found["generation"]]
            op["target"] = found["sandbox_id"]
            argv = params["command"]["argv"]
            stdout = (" ".join(argv) + "\n").encode("utf-8")
            self.outputs[run_id] = {"stdout": stdout, "stderr": b""}
            op["result"] = {"type": "run", "data": self._run_result(run_id, request.operation_id, found, stdout, argv)}
            found["last_run"] = run_id
            # RUNNING while the run is in flight, COMPLETED once it has ended with a known result.
            found["state"] = "RUNNING" if method in self.hold else "COMPLETED"
            self._touch(found)
        elif method == "snapshot.create":
            found = target(params["sandbox_id"])
            if isinstance(found, HostRefusal):
                return found
            name = params.get("name")
            if name is not None and any(
                s.get("name") == name and self._visible(s, scope) and s["state"] != "DELETED"
                for s in self.snapshots.values()
            ):
                return self._refuse("STATE_CONFLICT", "AFTER_CHANGE", "a snapshot with this name exists")
            snapshot: dict[str, Any] | None
            snapshot = {
                "snapshot": {"snapshot_id": self._next_id("snp"), "snapshot_generation": 1},
                "state": "READY",
                "tags": self._tags(scope),
                "name": name,
                "size_bytes": 4096,
                "restore_count": 0,
                "created": self._stamp(),
                "source_sandbox": [found["sandbox_id"], found["generation"]],
                "revision": 0,
                # What the host records and does not show: the resources and image of the source generation.
                "_recorded": {"resources": copy.deepcopy(found["resources"]), "image": copy.deepcopy(found["image"])},
            }
            self._touch(snapshot)
            self.snapshots[snapshot["snapshot"]["snapshot_id"]] = snapshot
            op["sandbox"] = [found["sandbox_id"], found["generation"]]
            op["snapshot"] = snapshot["snapshot"]
            op["target"] = snapshot["snapshot"]["snapshot_id"]
            op["result"] = {"type": "snapshot", "data": {k: v for k, v in snapshot.items() if not k.startswith("_")}}
        elif method == "snapshot.restore":
            ref = params["snapshot"]
            snapshot = self.snapshots.get(ref["snapshot_id"])
            if snapshot is None or not self._visible(snapshot, scope) or snapshot["state"] != "READY":
                return self._refuse("NOT_FOUND", "NEVER", "no such snapshot")
            recorded = snapshot["_recorded"]
            host_target = params["target"]
            if host_target["kind"] == "existing":
                found = target(host_target["sandbox_id"])
                if isinstance(found, HostRefusal):
                    return found
                found["generation"] += 1
                found["resources"] = copy.deepcopy(recorded["resources"])
                found["image"] = copy.deepcopy(recorded["image"])
                found["source_snapshot"] = dict(ref)
                found["state"] = "READY"
                self._touch(found)
            else:
                name = host_target.get("name")
                if name is not None and self._sandbox(scope, name) is not None:
                    return self._refuse(
                        "STATE_CONFLICT", "AFTER_CHANGE", "a sandbox with that name already exists in this scope"
                    )
                found = self._new_sandbox(
                    scope,
                    name,
                    recorded["image"]["alias"],
                    recorded["resources"],
                    host_target.get("lifetime_secs"),
                    state="READY",
                )
                found["source_snapshot"] = dict(ref)
            snapshot["restore_count"] += 1
            op["sandbox"] = [found["sandbox_id"], found["generation"]]
            op["snapshot"] = dict(ref)
            op["target"] = found["sandbox_id"]
            op["result"] = {"type": "sandbox", "data": found}
        elif method == "snapshot.delete":
            ref = params["snapshot"]
            snapshot = self.snapshots.get(ref["snapshot_id"])
            if snapshot is None or not self._visible(snapshot, scope):
                return self._refuse("NOT_FOUND", "NEVER", "no such snapshot")
            snapshot["state"] = "DELETED"
            self._touch(snapshot)
            op["snapshot"] = dict(ref)
            op["target"] = ref["snapshot_id"]
        elif method == "operation.cancel":
            victim = self.operations.get((self.peer_id, scope, str(params.get("operation_id"))))
            if victim is None:
                return self._refuse("NOT_FOUND", "NEVER", "no such operation")
            if victim["state"] not in TERMINAL:
                victim["state"], victim["effect"], victim["cancelled_by"], victim["cleanup"] = (
                    "CANCELLED",
                    "MAY_BE_APPLIED",
                    "CALLER",
                    "COMPLETE",
                )
                self._touch(victim)
            op["target"] = victim.get("target", "host")
            op["run_id"] = victim.get("run_id")
        else:
            return self._refuse("INVALID_REQUEST", "NEVER", "unknown method")

        if method in self.hold and op["state"] == "SUCCEEDED":
            op["state"] = self.unknown_state or "IN_PROGRESS"
            op.pop("effect", None)
        op["revision"] = self._commit()
        self.operations[key] = op
        self._fingerprints[key] = fingerprint
        return HostOperation(self._operation_view(op), self._as_of())

    def _run_in_flight(self, sandbox_id: str) -> bool:
        return any(
            o["operation_type"] == "exec.run"
            and o["state"] not in TERMINAL
            and o.get("sandbox", [None])[0] == sandbox_id
            for o in self.operations.values()
        )

    def _supersede(self, sandbox_id: str) -> None:
        for o in self.operations.values():
            if (
                o["operation_type"] == "exec.run"
                and o["state"] not in TERMINAL
                and o.get("sandbox", [None])[0] == sandbox_id
            ):
                o["state"], o["effect"], o["cancelled_by"], o["cleanup"] = (
                    "CANCELLED",
                    "MAY_BE_APPLIED",
                    "SUPERSEDED",
                    "COMPLETE",
                )
                self._touch(o)

    def _new_sandbox(
        self,
        scope: str,
        name: Any,
        image: Any,
        resources: dict[str, Any],
        lifetime: Any,
        *,
        state: str = "PROVISIONING",
    ) -> dict[str, Any]:
        """A first generation. Created, it waits to be started; restored from a snapshot, it is up already."""
        seconds = int(lifetime) if lifetime is not None else self.lifetime_default_secs
        sandbox: dict[str, Any] = {
            "sandbox_id": self._next_id("sbx"),
            "generation": 1,
            "state": state,
            "resources": copy.deepcopy(resources),
            "image": {
                "alias": image,
                "image_id": "sha256:" + "ab" * 32,
                "architecture": "x86_64",
                "kernel_identity": "sha256:" + "cd" * 32,
                "rootfs_identity": "sha256:" + "ef" * 32,
                "manifest_version": 1,
            },
            "tags": self._tags(scope),
            "name": name,
            "expires_at": rfc3339(self._host_now() + seconds * 1000),
            "lifetime_secs": seconds,
            "security_profile_id": "model-profile",
            "secret_bearing": False,
            "process": {"pid": 4242, "start_time_ticks": 1, "boot_id": "boot"},
            "revision": 0,
            "updated": self._stamp(),
        }
        self._touch(sandbox)
        self.sandboxes[sandbox["sandbox_id"]] = sandbox
        return sandbox

    def _run_result(
        self, run_id: str, operation_id: str, sandbox: dict[str, Any], stdout: bytes, argv: list[str]
    ) -> dict[str, Any]:
        exit_code = 1 if argv and argv[0] == "false" else 0
        return {
            "run_id": run_id,
            "operation_id": operation_id,
            "sandbox_id": sandbox["sandbox_id"],
            "generation": sandbox["generation"],
            "status": "EXITED",
            "exit_code": exit_code,
            "stdout": {"status": "COMPLETE", "total_bytes": len(stdout), "kept_bytes": len(stdout), "data_b64": ""},
            "stderr": {"status": "COMPLETE", "total_bytes": 0, "kept_bytes": 0, "data_b64": ""},
            "guest_duration_ms": 7,
            "guest_containment": "none",
            "host_backstop_fired": False,
            "runtime_ended": False,
            "metrics": {"wall_ms": 9},
            "evidence_status": "COMPLETE",
            "resource_evidence": [],
            "artifacts": [],
            "profile_id": "model-profile",
            "image_id": sandbox["image"]["image_id"],
        }
