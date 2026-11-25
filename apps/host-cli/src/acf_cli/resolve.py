"""Name and id resolution, and listings that span pages.

Names are a *human convenience* and exist only on the read path: the host accepts an alias for a
read-only lookup and never for a mutation. The client therefore resolves a name to
``(sandbox_id, generation)`` with a read, and every mutation then carries the id and the generation
it just saw. If the sandbox changed in between, the host answers ``REVISION_CONFLICT`` instead of
acting on something the operator did not mean. A caller who wants no window at all passes the id
and ``--expected-generation`` and no read is made.

A listing is one page per request. :func:`listing` follows the host's cursor; a full listing that
spans pages is merged the way the protocol defines it: later pages are *changes* (they carry
tombstones), so they replace what an earlier page said about the same record.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Hashable
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from acf_cli.client import HostClient, expect
from acf_cli.errors import LookupFailure, ProtocolViolation, Refused
from acf_cli.requests import (
    Call,
    Cursor,
    ListParams,
    SandboxTarget,
    SnapshotRef,
    operation_list,
    sandbox_inspect,
    sandbox_list,
    snapshot_list,
)
from acf_cli.responses import (
    AsOf,
    CursorView,
    OperationsBody,
    OperationView,
    Page,
    ResponseEnvelope,
    SandboxBody,
    SandboxesBody,
    SandboxView,
    SnapshotsBody,
    SnapshotView,
    to_wire,
)
from acf_cli.wire import SANDBOX_ID_PATTERN, SNAPSHOT_ID_PATTERN, FailureClass, LifecycleState, SnapshotState

#: API-11: a listing begun in full whose continuation cursor the host no longer accepts is begun
#: again ("the caller lists again in full"), up to this many times in all.
FULL_LISTING_ATTEMPTS = 3

_SANDBOX_ID = re.compile(SANDBOX_ID_PATTERN)
_SNAPSHOT_ID = re.compile(SNAPSHOT_ID_PATTERN)


def is_sandbox_id(text: str) -> bool:
    return _SANDBOX_ID.fullmatch(text) is not None


def is_snapshot_id(text: str) -> bool:
    return _SNAPSHOT_ID.fullmatch(text) is not None


# ----------------------------------------------------------------------------- sandboxes
def inspect_sandbox(client: HostClient, ref: str) -> SandboxView:
    """A sandbox by id **or** name. The host does the matching; a name resolves only within the caller's own tags."""
    return expect(client.result(sandbox_inspect(ref)).result, SandboxBody).data


def sandbox_target(
    client: HostClient, ref: str, *, expected_generation: int | None, if_revision: int | None
) -> SandboxTarget:
    """The target token of a mutation: an id, the generation to act on, and an optional revision precondition."""
    if is_sandbox_id(ref) and expected_generation is not None:
        return SandboxTarget(sandbox_id=ref, expected_generation=expected_generation, if_revision=if_revision)
    view = inspect_sandbox(client, ref)
    return target_of(view, expected_generation=expected_generation, if_revision=if_revision)


def target_of(
    view: SandboxView, *, expected_generation: int | None = None, if_revision: int | None = None
) -> SandboxTarget:
    try:
        return SandboxTarget(
            sandbox_id=view.sandbox_id,
            expected_generation=expected_generation if expected_generation is not None else view.generation,
            if_revision=if_revision,
        )
    except ValueError as e:
        raise ProtocolViolation(f"the host named a sandbox this client cannot address ({view.sandbox_id!r})") from e


# ----------------------------------------------------------------------------- listings
@dataclass(frozen=True, slots=True)
class Listing[T: BaseModel]:
    """A listing as far as it was followed."""

    kind: str
    items: list[T]
    #: The position the listing stands at: pass it as ``--changed-since`` to continue, or later to ask for changes.
    cursor: CursorView
    more: bool
    as_of: AsOf | None
    protocol: str

    def to_wire(self) -> dict[str, Any]:
        """The listing in the shape of the ``RESULT`` it is — one page, however many requests it took."""
        page = {"items": [to_wire(i) for i in self.items], "more": self.more, "next": to_wire(self.cursor)}
        return {
            "protocol": self.protocol,
            "answer": "RESULT",
            "result": {"type": self.kind, "data": page},
            "as_of": to_wire(self.as_of) if self.as_of is not None else None,
        }


def _listing[T: BaseModel](
    client: HostClient,
    make_call: Callable[[ListParams | None], Call],
    page_of: Callable[[ResponseEnvelope], Page[T]],
    kind: str,
    *,
    changed_since: Cursor | None,
    limit: int | None,
    follow: bool,
    identity: Callable[[T], Hashable],
    is_tombstone: Callable[[T], bool],
) -> Listing[T]:
    first_page = changed_since is None and limit is None
    params = None if first_page else ListParams(changed_since=changed_since, limit=limit)
    for attempt in range(1, FULL_LISTING_ATTEMPTS + 1):
        answer = client.result(make_call(params))
        page = page_of(answer)
        items = list(page.items)  # one page is shown exactly as the host sent it
        try:
            while follow and page.more:
                position = Cursor(lineage=page.next.lineage, sequence=page.next.sequence)
                answer = client.result(make_call(ListParams(changed_since=position, limit=limit)))
                page = page_of(answer)
                # A later page is a change: what it says about a record replaces what an earlier page said.
                changed = {identity(item) for item in page.items}
                items = [item for item in items if identity(item) not in changed] + list(page.items)
        except Refused as e:
            # The host forgot a tombstone after the position this listing had reached. A listing
            # begun in full is begun again; one begun at the caller's own cursor reports the refusal,
            # because "list again in full" is then the caller's decision.
            refusal = e.envelope.refusal
            expired = refusal is not None and refusal.failure_class is FailureClass.CURSOR_EXPIRED
            if changed_since is None and expired and attempt < FULL_LISTING_ATTEMPTS:
                continue
            raise
        break
    if follow and changed_since is None:
        # A full listing shows what exists. Pages after the first are deltas and carry tombstones.
        items = [item for item in items if not is_tombstone(item)]
    return Listing(kind, items, page.next, page.more, answer.as_of, answer.protocol)


def list_sandboxes(
    client: HostClient, *, changed_since: Cursor | None = None, limit: int | None = None, follow: bool = False
) -> Listing[SandboxView]:
    return _listing(
        client,
        sandbox_list,
        lambda answer: expect(answer.result, SandboxesBody).data,
        "sandboxes",
        changed_since=changed_since,
        limit=limit,
        follow=follow,
        identity=lambda s: s.sandbox_id,
        is_tombstone=lambda s: s.state is LifecycleState.DESTROYED,
    )


def list_snapshots(
    client: HostClient, *, changed_since: Cursor | None = None, limit: int | None = None, follow: bool = False
) -> Listing[SnapshotView]:
    return _listing(
        client,
        snapshot_list,
        lambda answer: expect(answer.result, SnapshotsBody).data,
        "snapshots",
        changed_since=changed_since,
        limit=limit,
        follow=follow,
        identity=lambda s: (s.snapshot.snapshot_id, s.snapshot.snapshot_generation),
        is_tombstone=lambda s: s.state is SnapshotState.DELETED,
    )


def list_operations(
    client: HostClient, *, changed_since: Cursor | None = None, limit: int | None = None, follow: bool = False
) -> Listing[OperationView]:
    return _listing(
        client,
        operation_list,
        lambda answer: expect(answer.result, OperationsBody).data,
        "operations",
        changed_since=changed_since,
        limit=limit,
        follow=follow,
        identity=lambda o: (o.tags.peer_id, o.tags.owner_scope, o.operation_id),
        is_tombstone=lambda _o: False,
    )


# ----------------------------------------------------------------------------- snapshots
def resolve_snapshot(client: HostClient, ref: str, *, generation: int | None = None) -> SnapshotRef:
    """A snapshot by id or name. An id together with its generation needs no read at all."""
    if is_snapshot_id(ref) and generation is not None:
        return SnapshotRef(snapshot_id=ref, snapshot_generation=generation)
    snapshots = list_snapshots(client, follow=True).items
    if is_snapshot_id(ref):
        matches = [s for s in snapshots if s.snapshot.snapshot_id == ref]
    else:
        matches = [s for s in snapshots if s.name == ref]
    if generation is not None:
        matches = [s for s in matches if s.snapshot.snapshot_generation == generation]
    if len(matches) == 1:
        found = matches[0].snapshot
        try:
            return SnapshotRef(snapshot_id=found.snapshot_id, snapshot_generation=found.snapshot_generation)
        except ValueError as e:
            raise ProtocolViolation(f"the host named a snapshot this client cannot address ({found})") from e
    if not matches:
        known = ", ".join(sorted(s.name or s.snapshot.snapshot_id for s in snapshots)) or "none"
        raise LookupFailure(
            f"no snapshot with id or name {ref!r} is visible to this caller and owner scope",
            hint=f"snapshots visible: {known}",
        )
    ids = ", ".join(str(s.snapshot) for s in matches)
    raise LookupFailure(f"{ref!r} names {len(matches)} snapshots", hint=f"use an id and --snapshot-generation: {ids}")
