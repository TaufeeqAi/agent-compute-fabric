"""Reads: the commands that change nothing.

The fifth layer of the Runtime Service. It extends the resolution layer and calls it, the platform
operations (for the list of agent credentials), the layer that observes the host and the shared
ground.

What is here: the dispatch of a read command, the lists, the output of an execution, one operation
with an optional wait, and the two views the platform answers about itself and the caller.

The rules it carries:

* a read is checked against the grant before anything else, and a denial is audited;
* a read that can reach the host is charged to the read rate and counted against the in-flight
  bounds. A caller that joins a wait on an operation shares the follower's one poll and costs the
  host no read of its own, so it is charged nothing; the wait that makes the platform poll is charged,
  and so is a read the platform makes for one caller alone;
* every waiter of one operation is answered from one read, made after the waiter arrived;
* an operation the platform accepted and the host no longer holds is answered from the outcome the
  ledger recorded for it, or as ``OUTCOME_LOST``;
* output is held for the duration of the answer and stored nowhere, and who read which bytes is
  audited;
* platform info for an authenticated caller says nothing about the host as a whole, and nothing of
  another project.
"""

from __future__ import annotations

from typing import Any

from acf_api.command import commands as c
from acf_api.command import model as m
from acf_api.command.answers import Answer, RequestContext
from acf_api.command.errors import Code
from acf_api.command.surface import PublicOperation
from acf_api.core.clock import rfc3339
from acf_api.core.host import wire
from acf_api.core.host.binding import Lane
from acf_api.core.host.wire import HostOperation, HostRefusal, HostRequest, Unreachable
from acf_api.core.identity.authenticator import Principal
from acf_api.core.pipeline import mapping
from acf_api.core.pipeline.ground import _RETRY_AFTER_S, _dict
from acf_api.core.pipeline.observation import _lineage
from acf_api.core.pipeline.resolution import Resolution
from acf_api.core.policy import authorizer as az
from acf_api.core.store import ledger as lg
from acf_api.core.store.engine import StoreError


class Reads(Resolution):
    """The read commands of the public model, one branch each."""

    async def _read(  # noqa: PLR0911 - one branch per read of the public model
        self, principal: Principal, ctx: RequestContext, op: PublicOperation, command: c.Command, wait_s: float | None
    ) -> Answer:
        if not az.allows_method(principal.grant, op.method):
            await self._audit_denial(principal, ctx, op, Code.PERMISSION_DENIED, az.R_METHOD)
            raise self._permission_denied(principal, ctx, op.method, az.R_METHOD)
        if isinstance(command, c.WhoAmI):
            return self._view("WhoAmI", self._whoami(principal))
        if isinstance(command, c.ListAgentCredentials):
            return await self._list_agent_credentials(principal, ctx)
        waits = (
            isinstance(command, c.GetOperation)
            and self._wait(command.wait if wait_s is None else wait_s, ctx, default=0.0) > 0
        )
        if not waits:
            # A caller that waits on an operation shares the follower's one poll and costs the host no read of
            # its own, so it is not charged to the read rate. It still counts against the in-flight bounds.
            self._bounds_for_read(principal, ctx)
        refused = self._in_flight.enter(principal.project_id, principal.principal_id)
        if refused is not None:
            raise self._error(ctx, Code.RATE_LIMITED, "too many requests in flight", reason=refused.bound)
        try:
            table, project = self.d.table, principal.project_id
            lineage = self.d.standing.pinned_lineage or ""
            if isinstance(command, c.Info):
                return self._view("Info", await self._info(principal))
            if isinstance(command, c.GetSandbox):
                result = await self._host_read(principal, ctx, "sandbox.inspect", {"sandbox": command.sandbox})
                view = mapping.sandbox(table, _dict(result.data), project, _lineage(result, lineage))
                return self._view("Sandbox", view, etag=view.revision)
            if isinstance(command, c.ListSandboxes | c.ListSnapshots | c.ListOperations):
                return await self._list(principal, ctx, command)
            if isinstance(command, c.GetExecution):
                result = await self._host_read(
                    principal, ctx, "run.inspect", {"run_id": mapping.host_run_id(command.execution_id)}
                )
                data = _dict(result.data)
                execution = (
                    mapping.execution_from_run(table, data, project)
                    if result.type == "run"
                    else mapping.execution_from_operation(table, data, project)
                )
                return self._view("Execution", execution)
            if isinstance(command, c.GetExecutionOutput):
                return await self._output(principal, ctx, op, command)
            if isinstance(command, c.GetOperation):
                return await self._get_operation(principal, ctx, command, wait_s)
            raise self._error(ctx, Code.UNSUPPORTED, "this version does not serve the command")
        finally:
            self._in_flight.leave(principal.project_id, principal.principal_id)

    async def _list(
        self, principal: Principal, ctx: RequestContext, command: c.ListSandboxes | c.ListSnapshots | c.ListOperations
    ) -> Answer:
        params: dict[str, Any] = {}
        if command.limit is not None:
            params["limit"] = command.limit
        if command.cursor is not None:
            cursor = mapping.decode_cursor(command.cursor)
            if cursor is None:
                raise self._error(
                    ctx, Code.INVALID_REQUEST, "the cursor is not one this platform issued", reason="cursor"
                )
            params["changed_since"] = cursor
        table, project = self.d.table, principal.project_id
        method = {
            "list_sandboxes": "sandbox.list",
            "list_snapshots": "snapshot.list",
            "list_operations": "operation.list",
        }[command.type]
        result = await self._host_read(principal, ctx, method, params or None)
        page = _dict(result.data)
        lineage = _lineage(result, self.d.standing.pinned_lineage or "")
        items = [i for i in page.get("items") or [] if isinstance(i, dict)]
        next_cursor, more = mapping.encode_cursor(page.get("next")), bool(page.get("more"))
        if isinstance(command, c.ListSandboxes):
            return self._view(
                "SandboxList",
                m.SandboxList(
                    items=[mapping.sandbox(table, i, project, lineage) for i in items],
                    next_cursor=next_cursor,
                    more=more,
                ),
            )
        if isinstance(command, c.ListSnapshots):
            return self._view(
                "SnapshotList",
                m.SnapshotList(
                    items=[mapping.snapshot(table, i, project, lineage) for i in items],
                    next_cursor=next_cursor,
                    more=more,
                ),
            )
        return self._view(
            "OperationList",
            m.OperationList(
                items=[mapping.operation(table, i, project, lineage) for i in items], next_cursor=next_cursor, more=more
            ),
        )

    async def _output(
        self, principal: Principal, ctx: RequestContext, op: PublicOperation, command: c.GetExecutionOutput
    ) -> Answer:
        chunk, raw_len = await self.read_output(
            principal, ctx, command.execution_id, command.stream.value, command.offset, command.max_bytes
        )
        await self._audit_output(
            principal, ctx, op, command.execution_id, command.stream.value, command.offset, raw_len
        )
        return self._view("OutputChunk", mapping.output_chunk(self.d.table, chunk, command.execution_id, raw_len))

    async def read_output(
        self,
        principal: Principal,
        ctx: RequestContext,
        execution_id: str,
        stream: str,
        offset: int,
        max_bytes: int | None,
    ) -> tuple[dict[str, Any], int]:
        """One slice of one stream, from the host. Held for the duration of the answer and stored nowhere."""
        limit = min(max_bytes or self.d.params.output_chunk_max, self.d.params.output_chunk_max)
        result = await self._host_read(
            principal,
            ctx,
            "run.output",
            {"run_id": mapping.host_run_id(execution_id), "stream": stream, "offset": offset, "max_bytes": limit},
        )
        chunk = _dict(result.data)
        data_b64 = chunk.get("data_b64")
        raw_len = (len(data_b64) // 4) * 3 - data_b64.count("=", -2) if isinstance(data_b64, str) and data_b64 else 0
        return chunk, raw_len

    async def _get_operation(
        self, principal: Principal, ctx: RequestContext, command: c.GetOperation, wait_s: float | None
    ) -> Answer:
        wait = self._wait(command.wait if wait_s is None else wait_s, ctx, default=0.0)
        answer: HostOperation | HostRefusal | None = None
        charged = wait <= 0  # a read that does not wait was charged with every other read, before it got here
        if wait > 0:
            if not self.d.follower.following(principal.scope, command.operation_id):
                # Nobody waits on this operation yet, so this wait is what makes the platform poll it: it is
                # this caller's read, and it is bounded like one. A caller that joins a wait costs the host
                # nothing and is charged nothing. No await lies between this check and the wait below.
                self._bounds_for_read(principal, ctx)
                charged = True
            # Every waiter of one operation is answered from one read, made after the waiter arrived.
            answer = await self.d.follower.wait(principal.scope, command.operation_id, wait, ctx.request_id)
            if answer is not None:
                await self.observe(answer)
        if answer is None:
            if not charged:
                self._bounds_for_read(principal, ctx)
            request = HostRequest(
                method="operation.get",
                owner_scope=principal.scope,
                params={"operation_id": command.operation_id},
                request_id=ctx.request_id,
            )
            try:
                read = await self.d.binding.read(request, lane=Lane.GENERAL, principal_id=principal.principal_id)
            except Unreachable as e:
                raise self._error(
                    ctx, Code.UPSTREAM_UNAVAILABLE, "the host could not be reached; the read can be repeated"
                ) from e
            await self.observe(read)
            answer = read if isinstance(read, HostRefusal) else HostOperation(_dict(read.data), read.as_of)
        entry = await self._entry_by_operation(principal.project_id, command.operation_id)
        if isinstance(answer, HostRefusal):
            if answer.failure_class == wire.NOT_FOUND and entry is not None and entry.state != lg.CLAIMED:
                # The platform accepted a request for this operation and the host no longer holds it.
                return await self._answer_forgotten(principal, ctx, entry, key=None)
            raise self._host_refusal(ctx, answer, said=(command.operation_id,))
        host_op = answer
        if entry is not None:
            await self.record_summary(entry, host_op)
        view = mapping.operation(
            self.d.table,
            host_op.view,
            principal.project_id,
            _lineage(host_op, self.d.standing.pinned_lineage or ""),
            key_digest=entry.key_digest if entry is not None else None,
        )
        return self._view(
            "Operation", view, terminal=view.terminal, retry_after_s=None if view.terminal else _RETRY_AFTER_S
        )

    async def _entry_by_operation(self, project_id: str, operation_id: str) -> lg.Entry | None:
        try:
            return await self.d.ledger.by_operation(project_id, operation_id)
        except StoreError:
            return None

    def _whoami(self, principal: Principal) -> m.WhoAmI:
        return m.WhoAmI(
            principal_id=principal.principal_id,
            project_id=principal.project_id,
            credential=m.CredentialView(
                credential_id=principal.credential_id,
                kind=principal.kind,
                agent_label=principal.agent_label,
                expires_at=rfc3339(principal.expires_at_ms),
            ),
            grants=principal.grant.to_view(),
            policy_version=principal.policy_version,
        )

    async def _info(self, principal: Principal) -> m.Info:
        """Platform info for an authenticated caller: nothing about the host as a whole, and nothing of
        another project.
        """
        info = await self.host_info()
        s = self.d.standing
        grant = principal.grant.ceilings
        ceilings = None
        host_features: list[str] = []
        if info is not None:
            ceilings = m.Ceilings(
                vcpus=min(grant.vcpus, info.max_vcpus),
                memory_mib=min(grant.memory_mib, info.max_memory_mib),
                disk_mib=min(grant.disk_mib, info.max_disk_mib),
                execution_timeout_seconds=min(grant.execution_timeout_seconds, info.max_runtime_ms // 1000),
                sandbox_lifetime_seconds=min(grant.sandbox_lifetime_seconds, info.lifetime_max_secs),
                allowlist_entries=info.max_allowlist_entries,
            )
            host_features = sorted(self.offered_host_features(info))
        return m.Info(
            api_versions=[m.API_VERSION],
            serving=s.serving(),
            ready=s.ready(),
            not_ready_reasons=s.not_ready_reasons(),
            platform_features=sorted(self.platform_features()),
            host_features=host_features,
            parameters=self.d.params.public(),
            ceilings=ceilings,
        )
