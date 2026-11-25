"""Recovery: the ledger is reconciled against the host in one direction, towards the host, and by reading.

The platform has one thing to reconcile: a ledger entry that was claimed and whose outcome it does not
know, because the core crashed or an answer was lost. Recovery reads the host with the entry's
operation id and adopts the host's answer:

* the host holds the operation: the entry is bound;
* the host holds none, and that proves the operation never existed: the entry is released, and a later
  request with the key is a fresh attempt;
* otherwise the entry becomes LOST, and the answer for its key is ``OUTCOME_LOST``. That is the cost of
  not guessing.

**Recovery never submits.** No mutating request is sent to the host from here, from a timer, or from
any path that is not a caller's own request. A platform restart does not invent work.

At a start, every CLAIMED entry of an earlier writer epoch is visited, whatever its age: the epoch
proves that nobody holds it in flight. Until that pass is done the platform refuses granting work. An
entry the pass could not resolve because the host did not answer does not hold readiness back; it
stays CLAIMED and is visited again. Afterwards, on a period, every CLAIMED entry older than
``claim_stale_after`` that no live request is working on is visited the same way.

The same period runs retention: ledger entries, audit records and old credential records leave when
their time has passed. A ledger entry never leaves while it is CLAIMED or while its operation is not
known to have ended.
"""

from __future__ import annotations

import asyncio
from typing import Final

from acf_api.core.host import wire
from acf_api.core.host.binding import Lane
from acf_api.core.host.wire import HostOperation, HostRefusal, HostRequest, HostResult, Unreachable
from acf_api.core.pipeline.service import RuntimeService
from acf_api.core.store import ledger as lg
from acf_api.core.store.engine import StoreError
from acf_api.core.store.outbox import AuditOutbox

BOUND: Final = "bound"
RELEASED: Final = "released"
LOST: Final = "lost"
UNREACHED: Final = "unreached"
_BATCH: Final = 500


class Recovery:
    def __init__(self, service: RuntimeService, outbox: AuditOutbox) -> None:
        self._service = service
        self._d = service.d
        self._outbox = outbox
        self._scopes: dict[str, str | None] = {}

    async def _scope(self, project_id: str) -> str | None:
        if project_id not in self._scopes:
            project = await self._d.registry.project(project_id)
            self._scopes[project_id] = project.scope if project is not None else None
        return self._scopes[project_id]

    async def visit(self, entry: lg.Entry) -> str:
        """Bring one CLAIMED entry to BOUND, released or LOST by reading the host. Never by submitting."""
        scope = await self._scope(entry.project_id)
        if scope is None:
            # The project is gone from the registry: nothing can be read under it, and nothing is guessed.
            await self._d.ledger.lose(entry.entry_id, self._d.clock.wall_ms())
            return LOST
        request = HostRequest(method="operation.get", owner_scope=scope, params={"operation_id": entry.operation_id})
        try:
            answer = await self._d.binding.read(request, lane=Lane.RESOLUTION)
        except Unreachable:
            return UNREACHED
        await self._service.observe(answer)
        if isinstance(answer, HostResult) and answer.type == "operation" and isinstance(answer.data, dict):
            host_op = HostOperation(answer.data, answer.as_of)
            await self._d.ledger.bind(
                entry.entry_id,
                lineage=host_op.as_of.lineage if host_op.as_of else None,
                seq=host_op.as_of.sequence if host_op.as_of else None,
                peer_id=host_op.peer_id,
                at_ms=self._d.clock.wall_ms(),
            )
            if host_op.terminal:
                bound = await self._d.ledger.find(entry.project_id, entry.principal_id, entry.key_digest)
                if bound is not None:
                    await self._service.record_summary(bound, host_op)
            return BOUND
        if isinstance(answer, HostRefusal) and answer.failure_class == wire.NOT_FOUND:
            info = await self._service.host_info()
            if self._service.absence_proven(entry, info, answer.as_of):
                await self._d.ledger.release(entry.entry_id)
                return RELEASED
            await self._d.ledger.lose(entry.entry_id, self._d.clock.wall_ms())
            return LOST
        return UNREACHED

    async def _pass(self, entries: list[lg.Entry]) -> dict[str, int]:
        counts = {BOUND: 0, RELEASED: 0, LOST: 0, UNREACHED: 0}
        for entry in entries:
            if self._service.entry_in_flight(entry.entry_id):
                continue
            try:
                outcome = await self.visit(entry)
            except StoreError:
                outcome = UNREACHED
            counts[outcome] += 1
            self._d.telemetry.count("recovery_visits", outcome=outcome)
        return counts

    async def startup_pass(self) -> dict[str, int]:
        """Visit every CLAIMED entry of an earlier epoch. When it returns, granting work may be accepted."""
        totals = {BOUND: 0, RELEASED: 0, LOST: 0, UNREACHED: 0}
        try:
            await self._service.host_info(force=True)
            seen: set[int] = set()
            while True:
                entries = [
                    e
                    for e in await self._d.ledger.claimed(before_epoch=self._d.writer_epoch, limit=_BATCH)
                    if e.entry_id not in seen
                ]
                if not entries:
                    break
                seen.update(e.entry_id for e in entries)
                for name, n in (await self._pass(entries)).items():
                    totals[name] += n
        finally:
            # Every entry of an earlier epoch has been visited. One the host did not answer for stays CLAIMED.
            self._d.standing.recovered = True
        return totals

    async def sweep(self) -> dict[str, int]:
        """Visit every CLAIMED entry that is older than the stale bound and that no live request holds."""
        stale_before = self._d.clock.wall_ms() - int(self._d.params.claim_stale_after * 1000)
        return await self._pass(await self._d.ledger.claimed(older_than_ms=stale_before, limit=_BATCH))

    async def retention(self) -> dict[str, int]:
        """Let records leave whose time has passed. Deletes records of the platform; touches nothing on the host."""
        p, now = self._d.params, self._d.clock.wall_ms()
        info = self._d.standing.info
        retention_s = p.retention(info.operation_retention_ms / 1000 if info is not None else None)
        removed_entries = await self._d.ledger.expire(now - int(retention_s * 1000))
        removed_audit = await self._outbox.expire(now - int(p.audit_retention * 1000))
        removed_credentials = await self._d.registry.purge_credentials(now - int(p.audit_retention * 1000))
        for name, n in (("ledger", removed_entries), ("audit", removed_audit), ("credentials", removed_credentials)):
            if n:
                self._d.telemetry.count("retention_removed", n, part=name)
        return {"ledger": removed_entries, "audit": removed_audit, "credentials": removed_credentials}

    async def run(self) -> None:
        """The periodic task of the core: sweep, retention and a fresh look at the host."""
        interval = self._d.params.recovery_sweep_interval
        while True:
            await asyncio.sleep(interval)
            try:
                await self._service.host_info()
                await self.sweep()
                await self.retention()
            except StoreError:
                self._d.telemetry.count("recovery_store_unavailable")
            except Exception:  # a background task must not die; the failure is counted
                self._d.telemetry.count("recovery_errors")
