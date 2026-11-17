"""Canonical sample payloads, shaped exactly like the host's responses.

``tests/test_contract.py`` validates every factory against ``schemas/response.schema.json``, so these
cannot silently drift from the real contract — which would turn every scripted-host test into a
test of an imaginary protocol.
"""

from __future__ import annotations

import base64
from typing import Any

SANDBOX_ID = "sbx-" + "0a" * 16
OTHER_SANDBOX_ID = "sbx-" + "0b" * 16
RUN_ID = "run-" + "1f" * 16
SNAPSHOT_ID = "snp-" + "2c" * 16
OP_ID = "op-" + "3d" * 16
SHA = "sha256:" + "ab" * 32
UPDATED = "2026-10-10T12:00:00Z"


def merged(base: dict[str, Any], over: dict[str, Any]) -> dict[str, Any]:
    return {**base, **over}


def body(kind: str, data: Any = None) -> dict[str, Any]:
    """A ``ResponseBody`` (``ack`` carries no ``data``)."""
    return {"type": kind} if kind == "ack" else {"type": kind, "data": data}


def image_ref(**over: Any) -> dict[str, Any]:
    return merged(
        {
            "image_id": SHA,
            "alias": "python",
            "architecture": "x86_64",
            "kernel_identity": SHA,
            "rootfs_identity": SHA,
            "manifest_version": 1,
            "provenance_reference": None,
        },
        over,
    )


def resources(**over: Any) -> dict[str, Any]:
    return merged({"vcpus": 2, "memory_mib": 4096, "disk_mib": 1024, "network": "none"}, over)


def sandbox_view(**over: Any) -> dict[str, Any]:
    return merged(
        {
            "sandbox_id": SANDBOX_ID,
            "generation": 1,
            "name": None,
            "state": "READY",
            "resources": resources(),
            "image": image_ref(),
            "process": {"pid": 4242, "start_time_ticks": 123456, "boot_id": "boot-1"},
            "security_profile_id": "fc-jailer-v1",
            "last_run": None,
            "source_snapshot": None,
            "failure": None,
            "quarantined": None,
            "notes": [],
            "updated": UPDATED,
        },
        over,
    )


def capture(data: bytes = b"", *, total: int | None = None, status: str = "COMPLETE") -> dict[str, Any]:
    return {
        "status": status,
        "total_bytes": len(data) if total is None else total,
        "kept_bytes": len(data),
        "data_b64": base64.b64encode(data).decode(),
        "artifact": None,
    }


def run_result(**over: Any) -> dict[str, Any]:
    return merged(
        {
            "run_id": RUN_ID,
            "operation_id": OP_ID,
            "sandbox_id": SANDBOX_ID,
            "generation": 1,
            "outcome": "SUCCEEDED",
            "exit_code": 0,
            "signal": None,
            "stdout": capture(b"hello\n"),
            "stderr": capture(b""),
            "metrics": {"wall_ms": 742, "cpu_usage_usec": 51_000, "memory_peak_bytes": 12_582_912},
            "evidence_status": "COMPLETE",
            "resource_evidence": [],
            "artifacts": [],
            "policy_id": {"name": "default", "version": "1.0.0", "digest": "ab" * 32},
            "image_id": SHA,
            "note": None,
        },
        over,
    )


def snapshot_view(**over: Any) -> dict[str, Any]:
    return merged(
        {
            "snapshot": {"snapshot_id": SNAPSHOT_ID, "snapshot_generation": 1},
            "name": "baseline",
            "state": "READY",
            "size_bytes": 8 * 1024 * 1024,
            "source_sandbox": [SANDBOX_ID, 1],
            "manifest_digest": SHA,
            "restore_count": 0,
            "created": UPDATED,
            "failure": None,
        },
        over,
    )


def host_info(**over: Any) -> dict[str, Any]:
    return merged(
        {
            "version": "0.1.0",
            "protocol": "acf.host/1",
            "instance_id": "inst-1",
            "mode": "normal",
            "backend": {
                "name": "firecracker",
                "version": "1.17.0",
                "security_profile_id": "fc-jailer-v1",
                "profile": {},
            },
            "capabilities": {
                "backend": "firecracker",
                "pause_resume": True,
                "snapshot": True,
                "restore": True,
                "guest_exec": True,
                "network_modes": ["none"],
                "max_vcpus": 32,
            },
            "policy": {"name": "default", "version": "1.0.0", "digest": "ab" * 32},
            "journal_integrity": "ok",
            "live_sandboxes": 0,
            "snapshots": 0,
        },
        over,
    )


def operation_view(**over: Any) -> dict[str, Any]:
    return merged(
        {
            "operation_id": OP_ID,
            "operation_type": "exec",
            "status": "IN_PROGRESS",
            "phase": {"phase": "in_progress", "step": "guest_exec"},
            "resource_id": SANDBOX_ID,
            "failure": None,
            "result": None,
            "run_id": RUN_ID,
            "updated": UPDATED,
        },
        over,
    )
