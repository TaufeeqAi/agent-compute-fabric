"""Where audit records go: into the outbox, and from there to the operator's sink.

Writing a record never blocks a request beyond the store's deadline and never fails one, with a single
exception the operator chooses: with ``audit_required`` on, granting work is refused while the outbox
is full. Containment is never refused for audit.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Protocol

from acf_api.core.audit.records import AuditEvent
from acf_api.core.store.engine import StoreError
from acf_api.core.store.outbox import AuditOutbox
from acf_api.core.telemetry import Telemetry


class AuditSink(Protocol):
    async def record(self, event: AuditEvent) -> bool:
        """Write one record. ``False``: it could not be written, and the loss was counted."""
        ...

    @property
    def writable(self) -> bool:
        """Whether the last attempt to write succeeded."""
        ...


class OutboxSink:
    def __init__(self, outbox: AuditOutbox, telemetry: Telemetry) -> None:
        self._outbox = outbox
        self._telemetry = telemetry
        self._writable = True

    @property
    def writable(self) -> bool:
        return self._writable

    async def record(self, event: AuditEvent) -> bool:
        try:
            await self._outbox.append(event.to_record())
        except StoreError:
            self._writable = False
            self._telemetry.count("audit_records_dropped")
            return False
        self._writable = True
        self._telemetry.count("audit_records_written")
        return True


async def drain(outbox: AuditOutbox, sink_file: Path, telemetry: Telemetry, *, batch: int = 200) -> int:
    """Deliver undelivered records to the operator's file, oldest first. Returns how many were delivered.

    A record is marked delivered only after the file has been flushed to disk, so a crash can deliver a
    record twice and never zero times. Duplicates are harmless: a record carries its request id.
    """
    pending = await outbox.undelivered(batch)
    if not pending:
        return 0

    def append() -> None:
        fd = os.open(sink_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC, 0o640)
        try:
            os.write(fd, b"".join(text.encode("utf-8") + b"\n" for _, text in pending))
            os.fsync(fd)
        finally:
            os.close(fd)

    try:
        await asyncio.to_thread(append)
    except OSError:
        telemetry.count("audit_delivery_failures")
        return 0
    await outbox.mark_delivered(pending[-1][0])
    telemetry.count("audit_records_delivered", len(pending))
    return len(pending)
