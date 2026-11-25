"""From a fixed public command to the host request it stands for, and to the terms the policy evaluates.

Pure functions. A host request is built from the command the caller sent and the values recorded in
the ledger entry, and from nothing else, so that every submission of one entry is the same request.
Nothing here reads a clock, a store or the host.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from acf_api.command import commands as c
from acf_api.command import model as m
from acf_api.core.pipeline import mapping
from acf_api.core.policy.authorizer import UNREADABLE, Intent
from acf_api.core.policy.destinations import Destination, destination
from acf_api.core.store.ledger import Chosen

MutatingCommand = (
    c.CreateSandbox
    | c.StartSandbox
    | c.StopSandbox
    | c.DestroySandbox
    | c.Exec
    | c.CancelExecution
    | c.CreateSnapshot
    | c.RestoreSnapshot
    | c.DeleteSnapshot
)


@dataclass(frozen=True, slots=True)
class Fixed:
    """What the platform resolved for a request before it is sent, beyond what the ledger records."""

    #: The host revision behind ``If-Match``, when the caller sent one.
    if_revision: int | None = None
    #: For a cancel: the host operation that runs the execution.
    cancel_operation_id: str | None = None


def _network(network: m.NetworkNone | m.NetworkAllowlist) -> dict[str, Any]:
    if isinstance(network, m.NetworkNone):
        return {"mode": "none"}
    entries: list[dict[str, Any]] = []
    for entry in network.entries:
        dest = {"name": entry.name} if isinstance(entry, m.AllowName) else {"network": entry.network}
        entries.append({"destination": dest, "ports": [{"from": p.first, "to": p.last} for p in entry.ports]})
    return {"mode": "allowlist", "entries": entries}


def _target(sandbox_id: str, generation: int, fixed: Fixed) -> dict[str, Any]:
    target: dict[str, Any] = {"sandbox_id": sandbox_id, "expected_generation": generation}
    if fixed.if_revision is not None:
        target["if_revision"] = fixed.if_revision
    return target


def _generation(stated: int | str, chosen: Chosen) -> int:
    """The generation a request acts on: the caller's number, or the one read and recorded for ``current``."""
    if isinstance(stated, int):
        return stated
    if chosen.generation is None:
        msg = "a request that states `current` has no recorded generation"
        raise ValueError(msg)
    return chosen.generation


def stated_generation(command: MutatingCommand) -> int | str | None:
    """The target generation as the caller stated it, or ``None`` for a command that names no sandbox."""
    if isinstance(command, c.StartSandbox | c.StopSandbox | c.DestroySandbox):
        return command.expected_generation
    if isinstance(command, c.Exec | c.CreateSnapshot):
        return command.spec.expected_generation
    if isinstance(command, c.RestoreSnapshot) and isinstance(command.spec.target, m.RestoreInPlace):
        return command.spec.target.expected_generation
    return None


def target_sandbox(command: MutatingCommand) -> str | None:
    """The sandbox whose generation the command acts on, if it names one."""
    if isinstance(command, c.StartSandbox | c.StopSandbox | c.DestroySandbox | c.Exec | c.CreateSnapshot):
        return command.sandbox_id
    if isinstance(command, c.RestoreSnapshot) and isinstance(command.spec.target, m.RestoreInPlace):
        return command.spec.target.sandbox_id
    return None


def host_params(command: MutatingCommand, chosen: Chosen, fixed: Fixed) -> dict[str, Any]:  # noqa: PLR0911, PLR0912
    """The ``params`` of the host request. Members the host treats as optional are left out when unset."""
    if isinstance(command, c.CreateSandbox):
        spec = command.spec
        params: dict[str, Any] = {
            "image": spec.image,
            "resources": {
                "vcpus": spec.resources.vcpus,
                "memory_mib": spec.resources.memory_mib,
                "disk_mib": spec.resources.disk_mib,
                "network": _network(spec.network),
            },
        }
        if spec.name is not None:
            params["name"] = spec.name
        lifetime = chosen.lifetime_seconds if chosen.lifetime_seconds is not None else spec.lifetime_seconds
        if lifetime is not None:
            params["lifetime_secs"] = lifetime
        return params
    if isinstance(command, c.StartSandbox | c.StopSandbox | c.DestroySandbox):
        return _target(command.sandbox_id, _generation(command.expected_generation, chosen), fixed)
    if isinstance(command, c.Exec):
        spec_e = command.spec
        limits: dict[str, Any] = {}
        timeout = chosen.timeout_seconds if chosen.timeout_seconds is not None else spec_e.timeout_seconds
        if timeout is not None:
            limits["timeout_ms"] = timeout * 1000
        for public, host in (
            ("max_pids", "max_pids"),
            ("max_stdout_bytes", "max_stdout_bytes"),
            ("max_stderr_bytes", "max_stderr_bytes"),
        ):
            value = getattr(spec_e, public)
            if value is not None:
                limits[host] = value
        command_spec: dict[str, Any] = {"argv": list(spec_e.argv), "env": dict(spec_e.env)}
        if spec_e.cwd is not None:
            command_spec["cwd"] = spec_e.cwd
        if limits:
            command_spec["limits"] = limits
        if spec_e.secret_env:
            command_spec["secret_env"] = {name: {"ref": ref.ref} for name, ref in spec_e.secret_env.items()}
        out = _target(command.sandbox_id, _generation(spec_e.expected_generation, chosen), fixed)
        out["command"] = command_spec
        return out
    if isinstance(command, c.CreateSnapshot):
        out = _target(command.sandbox_id, _generation(command.spec.expected_generation, chosen), fixed)
        if command.spec.name is not None:
            out["name"] = command.spec.name
        return out
    if isinstance(command, c.RestoreSnapshot):
        ref = {"snapshot_id": command.snapshot_id, "snapshot_generation": command.spec.snapshot_generation}
        target = command.spec.target
        if isinstance(target, m.RestoreInPlace):
            host_target = _target(target.sandbox_id, _generation(target.expected_generation, chosen), fixed)
            host_target["kind"] = "existing"
        else:
            host_target = {"kind": "new"}
            if target.name is not None:
                host_target["name"] = target.name
            lifetime = chosen.lifetime_seconds if chosen.lifetime_seconds is not None else target.lifetime_seconds
            if lifetime is not None:
                host_target["lifetime_secs"] = lifetime
        return {"snapshot": ref, "target": host_target}
    if isinstance(command, c.DeleteSnapshot):
        return {"snapshot": {"snapshot_id": command.snapshot_id, "snapshot_generation": command.snapshot_generation}}
    if fixed.cancel_operation_id is None:
        msg = "a cancel has no resolved operation"
        raise ValueError(msg)
    return {"operation_id": fixed.cancel_operation_id}


def requested_entries(network: m.NetworkNone | m.NetworkAllowlist) -> tuple[Destination | None, ...]:
    """The requested allowlist entries, normalized. ``None`` in the tuple: an entry that cannot be read."""
    if isinstance(network, m.NetworkNone):
        return ()
    out: list[Destination | None] = []
    for entry in network.entries:
        ports = [(p.first, p.last) for p in entry.ports]
        if isinstance(entry, m.AllowName):
            out.append(destination(name=entry.name, suffix=None, network=None, ports=ports))
        else:
            out.append(destination(name=None, suffix=None, network=entry.network, ports=ports))
    return tuple(out)


def intent_of(sandbox_view: dict[str, Any]) -> Intent:
    """The recorded intent of a sandbox, from the host's view of it. What the view does not show is unreadable."""
    image = sandbox_view.get("image")
    resources = sandbox_view.get("resources")
    if not isinstance(resources, dict):
        return (
            UNREADABLE
            if not isinstance(image, dict)
            else Intent(
                image_alias=_alias(image),
                image_readable=True,
                vcpus=None,
                memory_mib=None,
                disk_mib=None,
                network_mode=None,
                entries=None,
            )
        )
    network = resources.get("network")
    mode: str | None = None
    entries: tuple[Destination, ...] | None = None
    if isinstance(network, dict) and isinstance(network.get("mode"), str):
        mode = network["mode"]
        if mode == "allowlist":
            collected: list[Destination] = []
            readable = isinstance(network.get("entries"), list)
            for entry in network.get("entries") or []:
                dest = entry.get("destination") if isinstance(entry, dict) else None
                ports = entry.get("ports") if isinstance(entry, dict) else None
                normalized = None
                if isinstance(dest, dict) and isinstance(ports, list):
                    normalized = destination(
                        name=dest.get("name") if isinstance(dest.get("name"), str) else None,
                        suffix=None,
                        network=dest.get("network") if isinstance(dest.get("network"), str) else None,
                        ports=[(p.get("from"), p.get("to")) for p in ports if isinstance(p, dict)],  # type: ignore[misc]
                    )
                if normalized is None:
                    readable = False
                    break
                collected.append(normalized)
            entries = tuple(collected) if readable else None
    return Intent(
        image_alias=_alias(image) if isinstance(image, dict) else None,
        image_readable=isinstance(image, dict) and isinstance(image.get("alias"), str),
        vcpus=_number(resources.get("vcpus")),
        memory_mib=_number(resources.get("memory_mib")),
        disk_mib=_number(resources.get("disk_mib")),
        network_mode=mode,
        entries=entries,
    )


def _alias(image: dict[str, Any]) -> str | None:
    alias = image.get("alias")
    return alias if isinstance(alias, str) else None


def _number(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def produced(view: dict[str, Any]) -> dict[str, Any]:
    """The identifiers of what an operation acted on and produced, for its recorded terminal summary."""
    out: dict[str, Any] = {}
    target = view.get("sandbox")
    if isinstance(target, list) and len(target) == 2 and isinstance(target[0], str):  # noqa: PLR2004
        out["sandbox_id"] = target[0]
        if _number(target[1]) is not None:
            out["generation"] = target[1]
    snap = view.get("snapshot")
    if isinstance(snap, dict):
        if isinstance(snap.get("snapshot_id"), str):
            out["snapshot_id"] = snap["snapshot_id"]
        if _number(snap.get("snapshot_generation")) is not None:
            out["snapshot_generation"] = snap["snapshot_generation"]
    execution = mapping.execution_id(view.get("run_id"))
    if execution is not None:
        out["execution_id"] = execution
    result = view.get("result")
    if isinstance(result, dict) and isinstance(result.get("data"), dict):
        data = result["data"]
        if result.get("type") == "sandbox" and isinstance(data.get("sandbox_id"), str):
            out.setdefault("sandbox_id", data["sandbox_id"])
            if _number(data.get("generation")) is not None:
                out["generation"] = data["generation"]
        if result.get("type") == "snapshot" and isinstance(data.get("snapshot"), dict):
            ref = data["snapshot"]
            if isinstance(ref.get("snapshot_id"), str):
                out.setdefault("snapshot_id", ref["snapshot_id"])
            if _number(ref.get("snapshot_generation")) is not None:
                out.setdefault("snapshot_generation", ref["snapshot_generation"])
    return out
