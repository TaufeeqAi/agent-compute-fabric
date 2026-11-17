"""Unix-socket client for the host agent, implementing the *caller's half* of the operation protocol.

The rule everything here serves (spec §12.4, §14.2, §15.2):

    **A mutation whose outcome is unknown is resolved by observation, never by re-running it.**

Concretely, :meth:`HostClient.mutate`

1. mints a client-side ``operation_id`` and submits the request with it;
2. if the *response is lost* (connection reset/EOF/timeout after the frame was written) it does
   **not** resend blindly — it asks the host what happened (``operation_get``) and keeps asking
   until the operation is final;
3. only if the host answers "I have never heard of that operation" is the request submitted
   again — with the same id, which the host's atomic begin makes idempotent;
4. an ``UNKNOWN`` status is surfaced as such (exit code 5), never retried and never mapped to FAILED.

This module is transport + protocol only. It owns no policy and no lifecycle truth (BND-01).
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from acf_cli.errors import (
    ExitCode,
    HostUnreachable,
    InvalidArgument,
    MutationInterrupted,
    OperationFailed,
    OutcomeUnknown,
    ProtocolViolation,
    Rejected,
    TransportError,
)
from acf_cli.framing import FrameEof, FrameTooLarge, FrameTruncated, encode_frame, read_frame
from acf_cli.models import (
    PROTOCOL,
    Body,
    OperationCancelRequest,
    OperationGetRequest,
    OperationSelector,
    OperationStatus,
    ResponseEnvelope,
)

DEFAULT_SOCKET = "/run/acf/host-agent.sock"
#: Mirrors the host's default ``security.max_request_bytes``; the host remains the authority.
DEFAULT_MAX_REQUEST_BYTES = 1024 * 1024
#: Equal to the host's hard response cap (64 MiB): a result the host is allowed to send is a result this
#: client can receive. The length is checked before the payload is read, so the bound is on memory we
#: choose to commit, not on what a peer announces.
DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024 * 1024
#: ``sun_path`` is 108 bytes on Linux (including the NUL); stay clear of it.
_SUN_PATH_SAFE = 100


@dataclass(frozen=True, slots=True)
class ClientConfig:
    socket_path: Path = Path(DEFAULT_SOCKET)
    connect_timeout_s: float = 5.0
    #: Per-request I/O timeout for requests that answer promptly (everything except ``exec``).
    io_timeout_s: float = 30.0
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    #: How long to keep *observing* an operation whose response was lost or which is still running.
    resolve_deadline_s: float = 60.0
    #: How long to wait for an ``UNKNOWN`` operation to be resolved by the host's own recovery.
    unknown_grace_s: float = 5.0
    poll_initial_s: float = 0.1
    poll_max_s: float = 2.0
    #: Patience for operations that legitimately take a while: boot, snapshot create/restore, destroy.
    slow_op_timeout_s: float = 600.0


def new_operation_id() -> str:
    """``op-`` + 32 lowercase hex: unguessable, within the host's ``[A-Za-z0-9-]{8,64}`` grammar."""
    return f"op-{uuid.uuid4().hex}"


def _new_request_id() -> str:
    return f"req-{uuid.uuid4().hex[:12]}"


def _connect(cfg: ClientConfig) -> socket.socket:
    """Connect to the control socket, working around the 108-byte ``sun_path`` limit."""
    path = cfg.socket_path
    raw = os.fsencode(path)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(cfg.connect_timeout_s)
    dir_fd: int | None = None
    try:
        target = str(path)
        if len(raw) >= _SUN_PATH_SAFE:
            # Same trick the host uses: resolve the final component relative to an open directory fd.
            dir_fd = os.open(path.parent, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
            target = f"/proc/self/fd/{dir_fd}/{path.name}"
        sock.connect(target)
    except FileNotFoundError as e:
        sock.close()
        raise HostUnreachable(
            f"no host agent socket at {path}",
            hint="is `acf-host serve` running? point the CLI elsewhere with --socket or $ACF_SOCKET",
        ) from e
    except PermissionError as e:
        sock.close()
        raise HostUnreachable(
            f"permission denied connecting to {path}",
            hint="the socket is group-restricted: your user must be in its group (see docs/OPERATIONS.md)",
        ) from e
    except ConnectionRefusedError as e:
        sock.close()
        raise HostUnreachable(
            f"nothing is listening on {path}",
            hint="the host agent is not running (stale socket file); start it with `systemctl start acf-host`",
        ) from e
    except OSError as e:
        sock.close()
        raise HostUnreachable(f"cannot connect to {path}: {e.strerror or e}") from e
    finally:
        if dir_fd is not None:
            os.close(dir_fd)
    return sock


class HostClient:
    """One connection per request; no hidden state between calls."""

    def __init__(
        self,
        config: ClientConfig | None = None,
        *,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.config = config or ClientConfig()
        self._sleep = sleep
        self._now = monotonic

    # ------------------------------------------------------------------ one round trip
    def roundtrip(
        self,
        body: Body,
        *,
        operation_id: str | None = None,
        io_timeout_s: float | None = None,
    ) -> ResponseEnvelope:
        """Send one request and read one response. Raises on transport/protocol failure only.

        Raises:
            HostUnreachable: nothing was sent (connect failed, or the host closed before reading).
            TransportError: the request frame was written but no valid response arrived.
            ProtocolViolation: the peer did not speak ``acf.host/1``.
        """
        request_id = _new_request_id()
        envelope: dict[str, object] = {"protocol": PROTOCOL, "request_id": request_id, "body": body.wire()}
        if operation_id is not None:
            envelope["operation_id"] = operation_id
        payload = json.dumps(envelope, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        try:
            frame = encode_frame(payload, self.config.max_request_bytes)
        except FrameTooLarge as e:
            raise InvalidArgument(
                f"request is {e.length} bytes; the host accepts at most {e.maximum}",
                hint="shorten the command line or environment",
            ) from e

        sock = _connect(self.config)
        try:
            sock.settimeout(io_timeout_s if io_timeout_s is not None else self.config.io_timeout_s)
            try:
                sock.sendall(frame)
            except OSError as e:
                # The host acts only on complete frames, so a failed send means it did not act. It
                # may still have written an explanation first (e.g. an authorization denial).
                early = self._read_response(sock, request_id, sent=False)
                if early is not None:
                    return early
                raise HostUnreachable(
                    f"could not deliver the request to the host ({e.strerror or e}); it did not act on it",
                    hint="check the host agent log; a policy or peer-credential check may have refused this caller",
                ) from e
            result = self._read_response(sock, request_id, sent=True)
            if result is None:  # pragma: no cover - sent=True never returns None
                raise TransportError("no response", request_sent=True)
            return result
        finally:
            sock.close()

    def _read_response(self, sock: socket.socket, request_id: str, *, sent: bool) -> ResponseEnvelope | None:
        try:
            raw = read_frame(sock, self.config.max_response_bytes)
        except FrameEof as e:
            if not sent:
                return None
            raise TransportError("the host closed the connection without answering", request_sent=True) from e
        except FrameTruncated as e:
            if not sent:
                return None
            raise TransportError("the host closed the connection mid-response", request_sent=True) from e
        except FrameTooLarge as e:
            raise ProtocolViolation(f"the host sent an oversize response: {e}") from e
        except TimeoutError as e:
            if not sent:
                return None
            raise TransportError("timed out waiting for the host to answer", request_sent=True) from e
        except OSError as e:
            if not sent:
                return None
            raise TransportError(
                f"connection failed while waiting for the answer: {e.strerror or e}", request_sent=True
            ) from e
        return self._parse(raw, request_id)

    @staticmethod
    def _parse(raw: bytes, request_id: str) -> ResponseEnvelope:
        try:
            env = ResponseEnvelope.model_validate_json(raw)
        except ValidationError as e:
            first = e.errors()[0]["msg"]
            raise ProtocolViolation(
                f"malformed response from the host: {e.error_count()} validation error(s); first: {first}",
                hint="is this CLI the same version as the host agent? see `acf-local host info`",
            ) from e
        if env.protocol != PROTOCOL:
            raise ProtocolViolation(
                f"the host speaks {env.protocol!r}, this CLI speaks {PROTOCOL!r}",
                hint="upgrade the CLI or the host so both speak the same protocol major version",
            )
        if env.request_id not in (None, request_id):
            raise ProtocolViolation("the response does not correspond to this request (request_id mismatch)")
        return env

    # ------------------------------------------------------------------ reads
    def read(self, body: Body, *, io_timeout_s: float | None = None) -> ResponseEnvelope:
        """A pure read: one round trip, final answer or an exception. Never creates an operation."""
        env = self.roundtrip(body, io_timeout_s=io_timeout_s)
        return raise_for_status(env)

    # ------------------------------------------------------------------ mutations
    def mutate(
        self,
        body: Body,
        *,
        operation_id: str | None = None,
        io_timeout_s: float | None = None,
        resolve_deadline_s: float | None = None,
        on_operation: Callable[[str], None] | None = None,
    ) -> ResponseEnvelope:
        """Submit a mutating request and drive it to a final answer.

        Returns the final envelope (any final status, or ``UNKNOWN``/in-progress when the deadline
        for observation passed — use :func:`raise_for_status` to turn those into exceptions).
        ``on_operation`` is called with the operation id *before* anything is sent, so an interrupt
        handler always knows which operation to cancel/resolve.
        """
        if not body.mutating:
            msg = f"{body.method} is not a mutating request; use read()"
            raise ValueError(msg)
        op_id = operation_id or new_operation_id()
        if on_operation is not None:
            on_operation(op_id)
        try:
            return self._submit_and_observe(
                body, op_id, io_timeout_s=io_timeout_s, resolve_deadline_s=resolve_deadline_s
            )
        except KeyboardInterrupt as e:
            # Still a KeyboardInterrupt to every handler, but now it says which operation was in flight.
            raise MutationInterrupted(op_id) from e

    def _submit_and_observe(
        self, body: Body, op_id: str, *, io_timeout_s: float | None, resolve_deadline_s: float | None
    ) -> ResponseEnvelope:
        try:
            env = self.roundtrip(body, operation_id=op_id, io_timeout_s=io_timeout_s)
        except TransportError:
            # The frame was written; the host may have acted. Observe, don't repeat.
            return self._observe(body, op_id, resubmit_allowed=True, deadline_s=resolve_deadline_s)
        except ProtocolViolation as e:
            # The request was delivered and the answer is unusable: the host may well have acted.
            raise ProtocolViolation(
                e.message,
                hint=f"it may have been applied; do NOT re-run it. Observe it: acf-local operation get {op_id}",
                operation_id=op_id,
            ) from e
        if env.status.is_final:
            return env
        # ACCEPTED / IN_PROGRESS (a duplicate of a running op) or UNKNOWN: ask, don't act.
        return self._observe(body, op_id, resubmit_allowed=False, first=env, deadline_s=resolve_deadline_s)

    def mutate_slow(
        self,
        body: Body,
        *,
        operation_id: str | None = None,
        on_operation: Callable[[str], None] | None = None,
    ) -> ResponseEnvelope:
        """:meth:`mutate` with the generous timeouts that boot/snapshot/destroy need."""
        slow = self.config.slow_op_timeout_s
        return self.mutate(
            body, operation_id=operation_id, io_timeout_s=slow, resolve_deadline_s=slow, on_operation=on_operation
        )

    def _observe(
        self,
        body: Body,
        op_id: str,
        *,
        resubmit_allowed: bool,
        first: ResponseEnvelope | None = None,
        deadline_s: float | None = None,
    ) -> ResponseEnvelope:
        cfg = self.config
        start = self._now()
        deadline = start + (deadline_s if deadline_s is not None else cfg.resolve_deadline_s)
        unknown_deadline = start + cfg.unknown_grace_s
        backoff = cfg.poll_initial_s
        last = first
        resubmitted = False
        while True:
            if last is not None and last.status == OperationStatus.UNKNOWN and self._now() >= unknown_deadline:
                return last
            if self._now() >= deadline:
                if last is not None:
                    return last
                raise OutcomeUnknown(
                    f"lost contact with the host while operation {op_id} was in flight, and it did not come back in "
                    f"{deadline - start:.0f}s",
                    hint=f"do NOT re-run it. When the host is back: acf-local operation get {op_id}",
                    operation_id=op_id,
                )
            self._sleep(backoff)
            backoff = min(backoff * 2, cfg.poll_max_s)
            try:
                got = self.roundtrip(OperationGetRequest(params=OperationSelector(operation_id=op_id)))
            except (HostUnreachable, TransportError):
                continue  # the host may be restarting: keep observing until the deadline
            if (
                got.status == OperationStatus.REJECTED
                and got.error is not None
                and got.error.error_class == "NOT_FOUND"
            ):
                # The host has no record: the request never reached its journal, so nothing happened.
                # Submitting it again with the same id is exactly a first submission (atomic begin).
                if resubmit_allowed and not resubmitted:
                    resubmitted = True
                    try:
                        again = self.roundtrip(body, operation_id=op_id)
                    except (HostUnreachable, TransportError):
                        continue
                    if again.status.is_final:
                        return again
                    last = again
                continue
            if got.status.is_final:
                return got
            last = got

    def cancel(self, operation_id: str) -> ResponseEnvelope:
        """Ask the host to cancel an in-flight ``exec``. Cancellation is a *request*: observe the result."""
        return self.roundtrip(OperationCancelRequest(params=OperationSelector(operation_id=operation_id)))

    def wait_final(self, operation_id: str, *, timeout_s: float | None = None) -> ResponseEnvelope:
        """Poll ``operation_get`` until the operation is final (or the deadline passes)."""
        cfg = self.config
        deadline = self._now() + (timeout_s if timeout_s is not None else cfg.resolve_deadline_s)
        backoff = cfg.poll_initial_s
        last: ResponseEnvelope | None = None
        while True:
            with contextlib.suppress(HostUnreachable, TransportError):
                last = self.roundtrip(OperationGetRequest(params=OperationSelector(operation_id=operation_id)))
                if last.status.is_final:
                    return last
            if self._now() >= deadline:
                if last is not None:
                    return last
                raise OutcomeUnknown(
                    f"could not observe operation {operation_id}",
                    hint=f"retry later: acf-local operation get {operation_id}",
                    operation_id=operation_id,
                )
            self._sleep(backoff)
            backoff = min(backoff * 2, cfg.poll_max_s)


def raise_for_status(env: ResponseEnvelope) -> ResponseEnvelope:
    """Return ``env`` iff it is ``SUCCEEDED``; otherwise raise the exception that matches the status."""
    status = env.status
    if status == OperationStatus.SUCCEEDED:
        return env
    err = env.error
    message = err.message if err is not None else f"operation ended with status {status}"
    failure_class = err.error_class if err is not None else None
    op = env.operation_id
    if status in {OperationStatus.REJECTED, OperationStatus.CONFLICT}:
        raise Rejected(
            message,
            failure_class=failure_class,
            retryable=bool(err and err.retryable),
            hint=_rejection_hint(failure_class),
            operation_id=op,
        )
    if status in {OperationStatus.FAILED, OperationStatus.CANCELLED}:
        raise OperationFailed(message, failure_class=failure_class, status=str(status), operation_id=op)
    # UNKNOWN, or still ACCEPTED/IN_PROGRESS when we stopped watching.
    where = f"acf-local operation get {op}" if op else "acf-local operation get <operation-id>"
    reason = (
        "the host cannot yet say whether it was applied"
        if status == OperationStatus.UNKNOWN
        else "it is still in progress"
    )
    raise OutcomeUnknown(
        f"{message}" if err is not None else f"operation {op or ''} outcome is not known: {reason}",
        hint=f"do NOT re-run it ({reason}). Observe it with: {where}",
        operation_id=op,
    )


def exit_code_for_status(status: OperationStatus) -> ExitCode:
    """The process exit code an operation status maps to (what :func:`raise_for_status` would exit with).

    Anything that is not final, and ``UNKNOWN``, is "outcome not known": the caller must observe,
    not retry. A test pins this to the exceptions :func:`raise_for_status` raises.
    """
    if status == OperationStatus.SUCCEEDED:
        return ExitCode.OK
    if status in {OperationStatus.REJECTED, OperationStatus.CONFLICT}:
        return ExitCode.REJECTED
    if status in {OperationStatus.FAILED, OperationStatus.CANCELLED}:
        return ExitCode.FAILED
    return ExitCode.UNKNOWN


def _rejection_hint(failure_class: str | None) -> str | None:
    return {
        "AUTHORIZATION": "the policy in force does not grant this; see `acf-local host info` and the policy file",
        "ADMISSION_REJECTED": "the request exceeds a policy ceiling or the host's remaining capacity",
        "STATE_CONFLICT": "the resource changed since it was read, or that transition is illegal; inspect, then retry",
        "NOT_FOUND": "check the id or name with the matching `list` command",
        "VALIDATION": "the request was malformed; see the message",
    }.get(failure_class or "")
