"""Typed extraction of response payloads, and name/id resolution.

Names are a *human convenience* and exist only on the read path (spec §12.5): the CLI resolves a
name to ``(sandbox_id, generation)`` with a read, and every mutation then carries the id and the
generation it just saw. If the sandbox changed in between, the host answers ``CONFLICT`` (stale
reference) instead of acting on something the operator did not mean.
"""

from __future__ import annotations

from acf_cli.client import HostClient
from acf_cli.errors import LookupFailure, ProtocolViolation
from acf_cli.models import (
    ResponseEnvelope,
    SandboxInspectRequest,
    SandboxListRequest,
    SandboxSelector,
    SandboxView,
    SnapshotListRequest,
    SnapshotView,
)

#: States in which a sandbox's guest agent is up (so a snapshot/exec is plausible).
LIVE_STATES = frozenset({"READY", "RUNNING", "COMPLETED", "PAUSED"})


def expect[T](env: ResponseEnvelope, kind: type[T]) -> T:
    """The envelope's ``data`` as ``kind``, or a :class:`ProtocolViolation` naming what arrived instead."""
    data = env.body()
    if not isinstance(data, kind):
        got = type(data).__name__ if data is not None else "no result"
        raise ProtocolViolation(f"expected a {kind.__name__} from the host, got {got}")
    return data


def expect_list[T](env: ResponseEnvelope, kind: type[T]) -> list[T]:
    data = env.body()
    if not isinstance(data, list) or not all(isinstance(x, kind) for x in data):
        raise ProtocolViolation(f"expected a list of {kind.__name__} from the host")
    return list(data)


def list_sandboxes(client: HostClient) -> list[SandboxView]:
    return expect_list(client.read(SandboxListRequest()), SandboxView)


def list_snapshots(client: HostClient) -> list[SnapshotView]:
    return expect_list(client.read(SnapshotListRequest()), SnapshotView)


def resolve_sandbox(client: HostClient, ref: str) -> SandboxView:
    """A sandbox by id **or** name (the host does the matching; names only ever match live sandboxes)."""
    return expect(client.read(SandboxInspectRequest(params=SandboxSelector(sandbox=ref))), SandboxView)


def resolve_snapshot(client: HostClient, ref: str) -> SnapshotView:
    """A snapshot by id or name. An exact id always wins; a name must match exactly one snapshot."""
    snaps = list_snapshots(client)
    by_id = [s for s in snaps if s.snapshot.snapshot_id == ref]
    if by_id:
        return by_id[0]
    by_name = [s for s in snaps if s.name == ref]
    if len(by_name) == 1:
        return by_name[0]
    if not by_name:
        known = ", ".join(sorted(s.name or s.snapshot.snapshot_id for s in snaps)) or "none"
        raise LookupFailure(f"no snapshot with id or name {ref!r}", hint=f"existing snapshots: {known}")
    ids = ", ".join(s.snapshot.snapshot_id for s in by_name)
    raise LookupFailure(f"snapshot name {ref!r} is ambiguous ({len(by_name)} matches)", hint=f"use an id: {ids}")


def only_live_sandbox(client: HostClient) -> SandboxView:
    """The single sandbox that is up, for commands where the operator did not name one."""
    live = [s for s in list_sandboxes(client) if s.state in LIVE_STATES]
    if len(live) == 1:
        return live[0]
    if not live:
        raise LookupFailure(
            "there is no running sandbox to act on",
            hint="create one: acf-local run --keep ... or acf-local sandbox create ...",
        )
    names = ", ".join(s.name or s.sandbox_id for s in live)
    raise LookupFailure(f"{len(live)} sandboxes are up ({names}); say which one", hint="pass --sandbox <name-or-id>")
