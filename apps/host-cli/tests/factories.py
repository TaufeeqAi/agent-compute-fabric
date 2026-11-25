"""Builders of wire-shaped answers of protocol ``acf.host/2``.

Every builder returns plain JSON-compatible data in exactly the shape the host sends, with every
field the host's types have. ``tests/test_contract.py`` validates each of them against the
published API description, so a builder cannot drift from the contract without a test failing.
"""

from __future__ import annotations

import base64
from typing import Any

SANDBOX_ID = "sbx-" + "0a" * 16
OTHER_SANDBOX_ID = "sbx-" + "0b" * 16
SNAPSHOT_ID = "snp-" + "0c" * 16
RUN_ID = "run-" + "0d" * 16
OPERATION_ID = "op-" + "0e" * 16
ARTIFACT_ID = "art-" + "0f" * 16
LINEAGE = "5f3c8a1e9b7d42c6a0e1f2d3c4b5a697"
AS_OF: dict[str, Any] = {"lineage": LINEAGE, "sequence": 41}
DIGEST = "sha256:" + "ab" * 32
NOW = "2026-11-18T10:00:00.000Z"
LATER = "2026-11-18T11:00:00.000Z"


def tags(peer_id: str = "local-operator", owner_scope: str = "default") -> dict[str, Any]:
    return {"peer_id": peer_id, "owner_scope": owner_scope}


def profile_id() -> dict[str, Any]:
    return {"name": "default", "version": "2.0.0", "digest": "cd" * 32}


def failure(
    failure_class: str = "DEPENDENCY_UNAVAILABLE", message: str = "backend down", side_effect: str = "POSSIBLE"
) -> dict[str, Any]:
    return {"class": failure_class, "message": message, "side_effect": side_effect}


def network_none() -> dict[str, Any]:
    return {"mode": "none"}


def network_allowlist() -> dict[str, Any]:
    return {
        "mode": "allowlist",
        "entries": [
            {"destination": {"name": "pypi.org"}, "ports": [{"from": 443, "to": 443}]},
            {"destination": {"network": "198.51.100.0/24"}, "ports": [{"from": 5432, "to": 5433}]},
        ],
    }


def sandbox_view(**over: Any) -> dict[str, Any]:
    view: dict[str, Any] = {
        "sandbox_id": SANDBOX_ID,
        "generation": 1,
        "name": "box",
        "state": "READY",
        "resources": {"vcpus": 1, "memory_mib": 512, "disk_mib": 1024, "network": network_none()},
        "image": {
            "image_id": DIGEST,
            "alias": "python",
            "architecture": "x86_64",
            "kernel_identity": DIGEST,
            "rootfs_identity": DIGEST,
            "manifest_version": 1,
            "provenance_reference": None,
        },
        "tags": tags(),
        "expires_at": LATER,
        "process": {"pid": 4242, "start_time_ticks": 99, "boot_id": "5b8f5c1e-5d0a-4a44-8a51-0b6f1c2d3e4f"},
        "security_profile_id": "sec-1",
        "last_run": None,
        "source_snapshot": None,
        "failure": None,
        "quarantined": None,
        "secret_bearing": False,
        "notes": [],
        "updated": NOW,
        "revision": 11,
    }
    view.update(over)
    return view


def snapshot_view(**over: Any) -> dict[str, Any]:
    view: dict[str, Any] = {
        "snapshot": {"snapshot_id": SNAPSHOT_ID, "snapshot_generation": 1},
        "name": "baseline",
        "state": "READY",
        "tags": tags(),
        "size_bytes": 3 * 1024 * 1024,
        "source_sandbox": [SANDBOX_ID, 1],
        "manifest_digest": DIGEST,
        "restore_count": 0,
        "secret_refs": [],
        "incompatible": [],
        "created": NOW,
        "failure": None,
        "revision": 23,
    }
    view.update(over)
    return view


def output_capture(data: bytes = b"", **over: Any) -> dict[str, Any]:
    cap: dict[str, Any] = {
        "status": "COMPLETE",
        "total_bytes": len(data),
        "kept_bytes": len(data),
        "data_b64": base64.b64encode(data).decode(),
        "artifact": None,
    }
    cap.update(over)
    return cap


def artifact(kind: str = "stdout", size: int = 6) -> dict[str, Any]:
    return {
        "artifact_id": ARTIFACT_ID,
        "kind": kind,
        "logical_name": kind,
        "schema_version": 1,
        "content_digest": DIGEST,
        "byte_size": size,
        "source_operation_id": OPERATION_ID,
        "sandbox_id": SANDBOX_ID,
        "run_id": RUN_ID,
    }


def run_result(stdout: bytes = b"hello\n", stderr: bytes = b"", **over: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "run_id": RUN_ID,
        "operation_id": OPERATION_ID,
        "sandbox_id": SANDBOX_ID,
        "generation": 1,
        "status": "EXITED",
        "exit_code": 0,
        "signal": None,
        "stdout": output_capture(stdout),
        "stderr": output_capture(stderr),
        "guest_duration_ms": 12,
        "guest_containment": "guest cgroup v2 pids.max + cgroup.kill",
        "host_backstop_fired": False,
        "runtime_ended": False,
        "metrics": {"wall_ms": 12, "cpu_usage_usec": 3400, "memory_peak_bytes": 20 * 1024 * 1024},
        "evidence_status": "COMPLETE",
        "resource_evidence": [
            {
                "resource": "runtime_ms",
                "configured": 60000,
                "effective": 60000,
                "observed_peak": 12,
                "violated": False,
                "action_taken": "none",
                "mechanism": "guest deadline + host backstop (monotonic)",
            }
        ],
        "artifacts": [],
        "profile_id": profile_id(),
        "image_id": DIGEST,
        "note": None,
    }
    result.update(over)
    return result


def sandbox_body(**over: Any) -> dict[str, Any]:
    return {"type": "sandbox", "data": sandbox_view(**over)}


def snapshot_body(**over: Any) -> dict[str, Any]:
    return {"type": "snapshot", "data": snapshot_view(**over)}


def run_body(**over: Any) -> dict[str, Any]:
    return {"type": "run", "data": run_result(**over)}


def host_change_body(
    mode: str | None = None, profile: dict[str, Any] | None = None, note: str | None = None
) -> dict[str, Any]:
    return {"type": "host", "data": {"mode": mode, "profile": profile, "note": note}}


_EFFECT_OF = {"SUCCEEDED": "APPLIED", "UNKNOWN": "MAY_BE_APPLIED", "FAILED": "NOT_APPLIED", "CANCELLED": "NOT_APPLIED"}
_CLEANUP_OF = {"FAILED": "COMPLETE", "CANCELLED": "COMPLETE"}


def operation_view(state: str = "SUCCEEDED", result: dict[str, Any] | None = None, **over: Any) -> dict[str, Any]:
    """An operation. ``effect`` and ``cleanup`` default to what the contract's tables give for ``state``."""
    view: dict[str, Any] = {
        "operation_id": OPERATION_ID,
        "operation_type": "sandbox.create",
        "state": state,
        "effect": _EFFECT_OF.get(state),
        "cleanup": _CLEANUP_OF.get(state),
        "cancelled_by": "CALLER" if state == "CANCELLED" else None,
        "issuer": "PEER",
        "tags": tags(),
        "on_behalf_of": None,
        "target": SANDBOX_ID,
        "step": "provision",
        "failure": failure() if state in {"FAILED", "UNKNOWN"} else None,
        "result": result,
        "run_id": None,
        "sandbox": [SANDBOX_ID, 1],
        "snapshot": None,
        "profile_id": profile_id(),
        "activation_epoch": 1,
        "issued_at": NOW,
        "created": NOW,
        "updated": NOW,
        "revision": 14,
    }
    view.update(over)
    return view


def host_info(**over: Any) -> dict[str, Any]:
    info: dict[str, Any] = {
        "version": "0.2.0",
        "host_id": "host-1",
        "protocols": ["acf.host/2"],
        "features": [
            "allowlist_network",
            "change_cursor",
            "host_modes",
            "operation_list",
            "quarantine_release",
            "scope_tags",
        ],
        "mode": "SERVING",
        "containment_reasons": [],
        "read_only_reason": None,
        "lineage": LINEAGE,
        "activation_epoch": 3,
        "instance_id": "inst-" + "11" * 16,
        "backend": {
            "name": "firecracker",
            "version": "v1.17.0",
            "security_profile_id": "sec-1",
            "profile": {"seccomp": True},
        },
        "capabilities": {
            "backend": "firecracker",
            "pause_resume": True,
            "snapshot": True,
            "restore": True,
            "guest_exec": True,
            "network_modes": ["none", "allowlist"],
            "max_vcpus": 32,
            "secret_injection": False,
            "incremental_output": False,
            "restore_reseeds_entropy": True,
            "runtime_depends_on_snapshot": True,
            "runtime_depends_on_image": False,
            "per_runtime_overhead_mib": 64,
            "identifier_slots": 4096,
            "stop_grace_ms": 2000,
        },
        "profile": profile_id(),
        "parameters": {
            "acceptance_horizon_ms": 300000,
            "clock_skew_tolerance_ms": 30000,
            "operation_retention_ms": 86400000,
            "change_retention_ms": 3600000,
            "output_retention_ms": 86400000,
            "wait_max_ms": 30000,
            "max_request_bytes": 1048576,
            "ceilings": {
                "max_vcpus": 4,
                "max_memory_mib": 4096,
                "max_disk_mib": 8192,
                "max_runtime_ms": 3600000,
                "max_pids": 1024,
                "max_stdout_bytes": 8388608,
                "max_stderr_bytes": 8388608,
                "max_argv_items": 256,
                "max_argv_bytes": 131072,
                "max_env_entries": 32,
                "max_lifetime_secs": 86400,
                "max_allowlist_entries": 32,
            },
            "sandbox_lifetime_default_secs": 3600,
            "sandbox_lifetime_max_secs": 86400,
            "allowlist_max_entries": 32,
        },
        "store_integrity": "Clean",
        "live_sandboxes": 2,
        "snapshots": 1,
        "quarantined": 0,
        "operations_in_flight": 0,
    }
    info.update(over)
    return info


def page(items: list[dict[str, Any]], *, more: bool = False, sequence: int = 41) -> dict[str, Any]:
    return {"items": items, "more": more, "next": {"lineage": LINEAGE, "sequence": sequence}}


def output_chunk(
    data: bytes = b"hello\n", *, offset: int = 0, stored: int | None = None, eof: bool = True, **over: Any
) -> dict[str, Any]:
    chunk: dict[str, Any] = {
        "run_id": RUN_ID,
        "stream": "stdout",
        "offset": offset,
        "data_b64": base64.b64encode(data).decode(),
        "stored_bytes": stored if stored is not None else offset + len(data),
        "produced_bytes": stored if stored is not None else offset + len(data),
        "completeness": "COMPLETE",
        "eof": eof,
    }
    chunk.update(over)
    return chunk


def metrics() -> dict[str, Any]:
    return {
        "counters": {"operations_accepted{type=sandbox.create}": 4},
        "gauges": {"live_sandboxes": 1, "host_mode": 1},
    }
