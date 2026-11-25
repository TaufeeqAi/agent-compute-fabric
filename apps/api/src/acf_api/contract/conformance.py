"""Build the client conformance suite: scripted server answers and the behaviour a correct client shows.

Every answer in a scenario is built from the public model, so an answer in the suite is one the
platform can give. Two scenarios add, on purpose, what a later version of the server may send and this
version of a client has never seen: an unknown member, an unknown state, an unknown code.

The format is described in ``protocols/conformance/README.md``.
"""

from __future__ import annotations

from typing import Any, Final

from acf_api.command import model as m
from acf_api.command.errors import CODES, Code, problem_type

PROJECT: Final = "prj_0000000000000001"
BASE: Final = f"/v1/projects/{PROJECT}"
SBX: Final = "sbx-" + "0" * 31 + "1"
SBX2: Final = "sbx-" + "0" * 31 + "2"
SNP: Final = "snp-" + "0" * 31 + "1"
EXE: Final = "exe-" + "0" * 31 + "1"
OP_CREATE: Final = "op-" + "a" * 32
OP_START: Final = "op-" + "b" * 32
OP_EXEC: Final = "op-" + "c" * 32
OP_DESTROY: Final = "op-" + "d" * 32
T0: Final = "2026-11-19T10:00:00.000Z"
T1: Final = "2026-11-19T10:00:02.000Z"
REQ: Final = "req_000000000000000000000001"
IMAGE_DIGEST: Final = "sha256:" + "1" * 64

_CREATE_ARGS: Final[dict[str, Any]] = {"image": "python", "vcpus": 1, "memory_mib": 512, "disk_mib": 1024}
_CREATE_BODY: Final[dict[str, Any]] = {
    "image": "python",
    "resources": {"vcpus": 1, "memory_mib": 512, "disk_mib": 1024},
}


def _dump(view: m.ViewModel) -> dict[str, Any]:
    return view.model_dump(mode="json", by_alias=True, exclude_none=True)


def sandbox(state: str, *, sandbox_id: str = SBX, generation: int = 1, name: str | None = None) -> m.Sandbox:
    return m.Sandbox(
        sandbox_id=sandbox_id,
        project=PROJECT,
        name=name,
        state=state,
        generation=generation,
        revision=f"r{generation + 10}.0123456789ab",
        image=m.Image(alias="python", digest=IMAGE_DIGEST),
        resources=m.ResourcesView(vcpus=1, memory_mib=512, disk_mib=1024),
        network=m.NetworkView(mode="none"),
        expires_at="2026-11-19T12:00:00.000Z",
        updated_at=T1,
    )


def execution(status: str | None, *, exit_code: int | None = None, state: str = "SUCCEEDED") -> m.Execution:
    ended = m.is_terminal(state)
    return m.Execution(
        execution_id=EXE,
        operation_id=OP_EXEC,
        project=PROJECT,
        sandbox_id=SBX,
        generation=2,
        state=state,
        terminal=ended,
        status=status,
        exit_code=exit_code,
        durations=m.Durations(guest_ms=12, wall_ms=20) if ended else None,
        stdout=m.OutputSummary(stored_bytes=0, produced_bytes=0, completeness="COMPLETE") if ended else None,
        stderr=m.OutputSummary(stored_bytes=0, produced_bytes=0, completeness="COMPLETE") if ended else None,
        host_backstop_fired=False if ended else None,
        runtime_ended=False if ended else None,
        evidence_status="COMPLETE" if ended else None,
        provenance={
            "status": m.GUEST_REPORTED,
            "exit_code": m.GUEST_REPORTED,
            "signal": m.GUEST_REPORTED,
            "durations.guest_ms": m.GUEST_REPORTED,
            "durations.wall_ms": m.HOST_OBSERVED,
            "stdout": m.GUEST_REPORTED,
            "stderr": m.GUEST_REPORTED,
            "host_backstop_fired": m.HOST_OBSERVED,
            "runtime_ended": m.HOST_OBSERVED,
            "evidence_status": m.HOST_OBSERVED,
        }
        if ended
        else {},
    )


def operation(
    operation_id: str,
    op_type: str,
    state: str,
    *,
    result: m.OperationResult | None = None,
    effect: str | None = None,
    failure: m.Failure | None = None,
    cleanup: str | None = None,
    replayed: bool = False,
    target: m.OperationTarget | None = None,
) -> m.Operation:
    return m.Operation(
        operation_id=operation_id,
        project=PROJECT,
        type=op_type,
        state=state,
        terminal=m.is_terminal(state),
        effect=effect,
        failure=failure,
        cleanup=cleanup,
        target=target or m.OperationTarget(sandbox_id=SBX, generation=1),
        result=result,
        initiated_by="CALLER",
        actor=m.Actor(principal_id="prn_0000000000000001"),
        created_at=T0,
        updated_at=T1,
        replayed=replayed,
        idempotency_key_digest="5f2c" * 16,
    )


def ok(
    view: m.ViewModel | dict[str, Any], *, status: int = 200, headers: dict[str, str] | None = None
) -> dict[str, Any]:
    body = view if isinstance(view, dict) else _dump(view)
    return {"status": status, "headers": {"x-request-id": REQ, **(headers or {})}, "json": body}


def accepted(view: m.ViewModel) -> dict[str, Any]:
    op_id = view.operation_id if isinstance(view, m.Operation) else OP_CREATE
    return ok(view, status=202, headers={"location": f"{BASE}/operations/{op_id}", "retry-after": "1"})


def problem(
    code: str,
    *,
    kind: str | None = None,
    retry: str | None = None,
    status: int | None = None,
    key: str | None = None,
    retry_after: int | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    info = CODES.get(Code(code)) if code in Code.__members__ else None
    the_kind = kind or (info.kind.value if info and info.kind else "REFUSED")
    the_retry = retry or (info.retry.value if info else "NEVER")
    the_status = status or (info.http_status if info and info.http_status else 400)
    title = info.title if info else "A code this client has never seen"
    body = m.Problem(
        type=problem_type(code),
        title=title,
        status=the_status,
        detail=title,
        instance=f"urn:acf:request:{REQ}",
        code=code,
        kind=the_kind,
        retry=the_retry,
        message=title,
        request_id=REQ,
        idempotency_key=key,
        reason=reason,
    )
    headers = {"x-request-id": REQ, "content-type": "application/problem+json"}
    if retry_after is not None:
        headers["retry-after"] = str(retry_after)
    return {"status": the_status, "headers": headers, "json": _dump(body)}


def post(
    path: str, body: dict[str, Any] | None, key: str = "$KEY", query: dict[str, str] | None = None
) -> dict[str, Any]:
    request: dict[str, Any] = {"method": "POST", "path": BASE + path, "headers": {"idempotency-key": key}}
    if body is not None:
        request["json"] = body
    if query:
        request["query"] = query
    return request


def get(path: str, query: dict[str, str] | None = None) -> dict[str, Any]:
    request: dict[str, Any] = {"method": "GET", "path": path}
    if query:
        request["query"] = query
    return request


def scenario(
    sid: str,
    title: str,
    rules: list[str],
    call: tuple[str, dict[str, Any]],
    exchanges: list[tuple[dict[str, Any], dict[str, Any]]],
    expect: dict[str, Any],
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": sid,
        "title": title,
        "rules": rules,
        "call": {"name": call[0], "args": call[1]},
        "exchanges": [{"request": q, "response": a} for q, a in exchanges],
        "expect": expect,
    }
    if config:
        out["config"] = config
    return out


def build() -> dict[str, Any]:
    created = operation(
        OP_CREATE,
        "sandbox.create",
        "SUCCEEDED",
        effect="APPLIED",
        result=m.OperationResult(sandbox=sandbox("PROVISIONING")),
    )
    started = operation(
        OP_START, "sandbox.start", "SUCCEEDED", effect="APPLIED", result=m.OperationResult(sandbox=sandbox("READY"))
    )
    create_only = {**_CREATE_ARGS, "start": False, "idempotency_key": "key-0001"}
    exec_args = {"sandbox_id": SBX, "expected_generation": 2, "argv": ["python", "-V"], "idempotency_key": "key-0100"}
    exec_body = {"expected_generation": 2, "argv": ["python", "-V"]}
    exec_target = m.OperationTarget(sandbox_id=SBX, generation=2, execution_id=EXE)

    scenarios = [
        scenario(
            "cp-001-create-answers-terminal",
            "A create that ends inside the wait is answered with the ended operation.",
            ["CP-1", "IDM-1", "LRO-1"],
            ("sandbox.create", create_only),
            [(post("/sandboxes", _CREATE_BODY), ok(created))],
            {
                "outcome": "success",
                "result": {"sandbox_id": SBX, "state": "PROVISIONING"},
                "replayed": False,
                "exit_code": "success",
            },
        ),
        scenario(
            "cp-002-create-then-start",
            "The client drives create and then start, with the key and that key suffixed `:start`.",
            ["SDK-9", "LRO-10", "CP-1"],
            ("sandbox.create", {**_CREATE_ARGS, "idempotency_key": "key-0002"}),
            [
                (post("/sandboxes", _CREATE_BODY), ok(created)),
                (post(f"/sandboxes/{SBX}/start", {"expected_generation": 1}, key="$KEY:start"), ok(started)),
            ],
            {"outcome": "success", "result": {"sandbox_id": SBX, "state": "READY"}, "exit_code": "success"},
        ),
        scenario(
            "cp-003-follow-to-the-end",
            "A 202 is followed at the operation until it has ended.",
            ["CP-4", "LRO-2", "LRO-4"],
            ("sandbox.create", create_only),
            [
                (post("/sandboxes", _CREATE_BODY), accepted(operation(OP_CREATE, "sandbox.create", "ACCEPTED"))),
                (
                    get(f"{BASE}/operations/{OP_CREATE}", {"wait": "30"}),
                    ok(operation(OP_CREATE, "sandbox.create", "IN_PROGRESS"), headers={"retry-after": "1"}),
                ),
                (get(f"{BASE}/operations/{OP_CREATE}", {"wait": "30"}), ok(created)),
            ],
            {
                "outcome": "success",
                "result": {"sandbox_id": SBX, "state": "PROVISIONING"},
                "min_wait_s": 2,
                "exit_code": "success",
            },
        ),
        scenario(
            "cp-004-lost-answer-same-key",
            "No answer arrives: the client repeats the same request with the same key and the same body.",
            ["CP-2", "RT-1", "IDM-17"],
            ("sandbox.create", create_only),
            [
                (post("/sandboxes", _CREATE_BODY), {"fault": "connection_reset"}),
                (
                    post("/sandboxes", _CREATE_BODY),
                    ok(
                        operation(
                            OP_CREATE,
                            "sandbox.create",
                            "SUCCEEDED",
                            effect="APPLIED",
                            result=m.OperationResult(sandbox=sandbox("PROVISIONING")),
                            replayed=True,
                        ),
                        headers={"idempotent-replayed": "true"},
                    ),
                ),
            ],
            {"outcome": "success", "result": {"sandbox_id": SBX}, "replayed": True, "exit_code": "success"},
        ),
        scenario(
            "cp-005-unresolved-then-resolved",
            "OUTCOME_UNRESOLVED is resolved by asking again with the same key.",
            ["CP-2", "SDK-5"],
            ("sandbox.create", create_only),
            [
                (post("/sandboxes", _CREATE_BODY), problem("OUTCOME_UNRESOLVED", key="key-0001", retry_after=1)),
                (post("/sandboxes", _CREATE_BODY), ok(created)),
            ],
            {"outcome": "success", "result": {"sandbox_id": SBX}, "min_wait_s": 1, "exit_code": "success"},
        ),
        scenario(
            "cp-006-request-in-progress-is-retried",
            "A 409 that is REQUEST_IN_PROGRESS is retried with the same key.",
            ["CP-3", "SDK-4", "SDK-5"],
            ("sandbox.create", create_only),
            [
                (post("/sandboxes", _CREATE_BODY), problem("REQUEST_IN_PROGRESS", key="key-0001", retry_after=1)),
                (post("/sandboxes", _CREATE_BODY), ok(created)),
            ],
            {"outcome": "success", "result": {"sandbox_id": SBX}, "exit_code": "success"},
        ),
        scenario(
            "cp-007-state-conflict-is-not-retried",
            "A 409 that is STATE_CONFLICT is not retried: the status alone decides nothing.",
            ["CP-3", "SDK-4", "CC3-2"],
            ("sandbox.exec", exec_args),
            [(post(f"/sandboxes/{SBX}/executions", exec_body), problem("STATE_CONFLICT"))],
            {
                "outcome": "error",
                "error": {"class": "StateConflictError", "code": "STATE_CONFLICT", "kind": "REFUSED"},
                "exit_code": "refused",
            },
        ),
        scenario(
            "cp-008-rate-limited-honours-retry-after",
            "A server Retry-After replaces the computed delay when it is longer.",
            ["RT-1"],
            ("sandbox.create", create_only),
            [
                (post("/sandboxes", _CREATE_BODY), problem("RATE_LIMITED", retry_after=3)),
                (post("/sandboxes", _CREATE_BODY), ok(created)),
            ],
            {"outcome": "success", "result": {"sandbox_id": SBX}, "min_wait_s": 3, "exit_code": "success"},
        ),
        scenario(
            "cp-009-retry-after-beyond-the-cap",
            "A Retry-After longer than the client's backoff cap is not waited for: the failure is surfaced.",
            ["RT-1"],
            ("sandbox.create", create_only),
            [(post("/sandboxes", _CREATE_BODY), problem("RATE_LIMITED", retry_after=600))],
            {
                "outcome": "error",
                "error": {"class": "RateLimitError", "code": "RATE_LIMITED", "retry": "SAME_REQUEST_LATER"},
                "exit_code": "refused",
            },
        ),
        scenario(
            "cp-010-permission-denied",
            "A refusal with retry NEVER is surfaced at once.",
            ["CP-3", "RT-6"],
            ("sandbox.create", create_only),
            [(post("/sandboxes", _CREATE_BODY), problem("PERMISSION_DENIED", reason="network_mode"))],
            {
                "outcome": "error",
                "error": {"class": "PermissionDeniedError", "code": "PERMISSION_DENIED", "kind": "REFUSED"},
                "exit_code": "refused",
            },
        ),
        scenario(
            "cp-011-nonzero-exit-is-a-result",
            "A command that exits with a status other than 0 is a result of a successful operation.",
            ["ERR-2"],
            ("sandbox.exec", {**exec_args, "argv": ["false"]}),
            [
                (
                    post(f"/sandboxes/{SBX}/executions", {"expected_generation": 2, "argv": ["false"]}),
                    ok(
                        operation(
                            OP_EXEC,
                            "execution.create",
                            "SUCCEEDED",
                            effect="APPLIED",
                            result=m.OperationResult(execution=execution("EXITED", exit_code=1)),
                            target=exec_target,
                        )
                    ),
                )
            ],
            {
                "outcome": "success",
                "result": {"execution_id": EXE, "status": "EXITED", "exit_code": 1},
                "exit_code": "command_failed",
            },
        ),
        scenario(
            "cp-012-operation-failed-not-applied",
            "An operation that ends FAILED with effect NOT_APPLIED is a failure, and nothing was applied.",
            ["ERR-2", "LRO-6"],
            ("sandbox.exec", exec_args),
            [
                (
                    post(f"/sandboxes/{SBX}/executions", exec_body),
                    ok(
                        operation(
                            OP_EXEC,
                            "execution.create",
                            "FAILED",
                            effect="NOT_APPLIED",
                            cleanup="COMPLETE",
                            failure=m.Failure(
                                code="DEPENDENCY_UNAVAILABLE",
                                retry="SAME_REQUEST_LATER",
                                message="A dependency of the host was unavailable",
                                side_effect="NONE",
                            ),
                            target=exec_target,
                        )
                    ),
                )
            ],
            {
                "outcome": "error",
                "error": {"class": "OperationFailedError", "code": "DEPENDENCY_UNAVAILABLE"},
                "exit_code": "operation_failed",
            },
        ),
        scenario(
            "cp-013-unknown-is-never-success-or-failure",
            "An operation that ends UNKNOWN is reported as unknown, distinctly.",
            ["CP-5", "ERR-3"],
            ("sandbox.exec", exec_args),
            [
                (
                    post(f"/sandboxes/{SBX}/executions", exec_body),
                    ok(
                        operation(
                            OP_EXEC,
                            "execution.create",
                            "UNKNOWN",
                            effect="MAY_BE_APPLIED",
                            failure=m.Failure(
                                code="UNKNOWN_OUTCOME",
                                retry="AFTER_CHANGE",
                                message="The outcome of the operation is unknown",
                                side_effect="POSSIBLE",
                            ),
                            result=m.OperationResult(execution=execution("UNKNOWN", state="UNKNOWN")),
                            target=exec_target,
                        )
                    ),
                )
            ],
            {
                "outcome": "error",
                "error": {"class": "OutcomeUnknownError", "code": "UNKNOWN_OUTCOME"},
                "exit_code": "outcome_unknown",
            },
        ),
        scenario(
            "cp-014-failed-may-be-applied-is-unknown",
            "FAILED with effect MAY_BE_APPLIED is not a clean failure: the caller must inspect before deciding.",
            ["CP-5", "RT-6"],
            ("sandbox.exec", exec_args),
            [
                (
                    post(f"/sandboxes/{SBX}/executions", exec_body),
                    ok(
                        operation(
                            OP_EXEC,
                            "execution.create",
                            "FAILED",
                            effect="MAY_BE_APPLIED",
                            cleanup="PENDING",
                            failure=m.Failure(
                                code="TIMEOUT", retry="SAME_REQUEST_LATER", message="Timed out", side_effect="POSSIBLE"
                            ),
                            target=exec_target,
                        )
                    ),
                )
            ],
            {
                "outcome": "error",
                "error": {"class": "OutcomeUnknownError", "code": "TIMEOUT"},
                "exit_code": "outcome_unknown",
            },
        ),
        scenario(
            "cp-015-outcome-lost-is-never-retried",
            "OUTCOME_LOST is surfaced once and never retried, with this key or with another.",
            ["CP-5", "ERR-7", "SDK-5"],
            ("sandbox.create", create_only),
            [(post("/sandboxes", _CREATE_BODY), problem("OUTCOME_LOST", key="key-0001"))],
            {
                "outcome": "error",
                "error": {"class": "OutcomeLostError", "code": "OUTCOME_LOST", "kind": "UNRESOLVED", "retry": "NEVER"},
                "exit_code": "outcome_lost",
            },
        ),
        scenario(
            "cp-016-retries-exhausted-stays-unresolved",
            "When the outcome stays unresolved, the client says so and exposes the key. It never tries a new one.",
            ["CP-2", "RT-1", "RT-6", "SDK-5"],
            ("sandbox.create", create_only),
            [
                (post("/sandboxes", _CREATE_BODY), problem("OUTCOME_UNRESOLVED", key="key-0001", retry_after=1)),
                (post("/sandboxes", _CREATE_BODY), problem("OUTCOME_UNRESOLVED", key="key-0001", retry_after=1)),
                (post("/sandboxes", _CREATE_BODY), problem("OUTCOME_UNRESOLVED", key="key-0001", retry_after=1)),
            ],
            {
                "outcome": "error",
                "error": {"class": "OutcomeUnresolvedError", "code": "OUTCOME_UNRESOLVED", "kind": "UNRESOLVED"},
                "exit_code": "unresolved",
            },
            config={"max_retries": 2},
        ),
        scenario(
            "cp-017-idempotency-conflict",
            "A key reused for a different request is refused, and no other key is tried.",
            ["RT-6", "IDM-6"],
            ("sandbox.create", create_only),
            [(post("/sandboxes", _CREATE_BODY), problem("IDEMPOTENCY_CONFLICT"))],
            {
                "outcome": "error",
                "error": {"class": "IdempotencyConflictError", "code": "IDEMPOTENCY_CONFLICT"},
                "exit_code": "refused",
            },
        ),
        scenario(
            "cp-018-a-state-never-seen-is-not-terminal",
            "A state the client does not know is neither terminal nor success: following continues.",
            ["CP-4", "VER-12"],
            ("sandbox.create", create_only),
            [
                (
                    post("/sandboxes", _CREATE_BODY),
                    ok(
                        {**_dump(operation(OP_CREATE, "sandbox.create", "ACCEPTED")), "state": "AWAITING_PLACEMENT"},
                        status=202,
                        headers={"location": f"{BASE}/operations/{OP_CREATE}", "retry-after": "1"},
                    ),
                ),
                (get(f"{BASE}/operations/{OP_CREATE}", {"wait": "30"}), ok(created)),
            ],
            {"outcome": "success", "result": {"sandbox_id": SBX, "state": "PROVISIONING"}, "exit_code": "success"},
        ),
        scenario(
            "cp-019-list-follows-cursors",
            "A listing follows cursors to the end.",
            ["SDK-7"],
            ("sandbox.list", {}),
            [
                (
                    get(f"{BASE}/sandboxes"),
                    ok(m.SandboxList(items=[sandbox("PROVISIONING")], next_cursor="c1", more=True)),
                ),
                (
                    get(f"{BASE}/sandboxes", {"cursor": "c1"}),
                    ok(m.SandboxList(items=[sandbox("READY", sandbox_id=SBX2)], next_cursor="c2", more=False)),
                ),
            ],
            {"outcome": "success", "result": {"count": 2, "ids": [SBX, SBX2]}, "exit_code": "success"},
        ),
        scenario(
            "cp-020-cursor-expired-lists-again",
            "CURSOR_EXPIRED makes the client list again in full.",
            ["SDK-7"],
            ("sandbox.list", {}),
            [
                (
                    get(f"{BASE}/sandboxes"),
                    ok(m.SandboxList(items=[sandbox("PROVISIONING")], next_cursor="c1", more=True)),
                ),
                (get(f"{BASE}/sandboxes", {"cursor": "c1"}), problem("CURSOR_EXPIRED")),
                (
                    get(f"{BASE}/sandboxes"),
                    ok(
                        m.SandboxList(
                            items=[sandbox("PROVISIONING"), sandbox("READY", sandbox_id=SBX2)],
                            next_cursor="c9",
                            more=False,
                        )
                    ),
                ),
            ],
            {"outcome": "success", "result": {"count": 2, "ids": [SBX, SBX2]}, "exit_code": "success"},
        ),
        scenario(
            "cp-021-unknown-members-and-values-are-tolerated",
            "A member and an enumeration value the client has never seen do not break it.",
            ["VER-4"],
            ("sandbox.get", {"sandbox": SBX}),
            [
                (
                    get(f"{BASE}/sandboxes/{SBX}"),
                    ok(
                        {**_dump(sandbox("PROVISIONING")), "state": "HIBERNATED", "placement": {"zone": "a"}},
                        headers={"etag": '"r11.0123456789ab"'},
                    ),
                )
            ],
            {"outcome": "success", "result": {"sandbox_id": SBX, "state": "HIBERNATED"}, "exit_code": "success"},
        ),
        scenario(
            "cp-022-an-unknown-code-is-handled-by-kind-and-retry",
            "A refusal code the client has never seen is handled by its kind and its retry advice: NEVER is not retried.",
            ["VER-12", "CP-3"],
            ("sandbox.create", create_only),
            [(post("/sandboxes", _CREATE_BODY), problem("FUTURE_REFUSAL", kind="REFUSED", retry="NEVER", status=409))],
            {
                "outcome": "error",
                "error": {"class": "RefusedError", "code": "FUTURE_REFUSAL", "kind": "REFUSED", "retry": "NEVER"},
                "exit_code": "refused",
            },
        ),
        scenario(
            "cp-023-an-unknown-code-that-says-later-is-retried",
            "The same unknown code with retry SAME_REQUEST_LATER is retried, with the same key.",
            ["VER-12", "CP-3"],
            ("sandbox.create", create_only),
            [
                (
                    post("/sandboxes", _CREATE_BODY),
                    problem("FUTURE_REFUSAL", kind="REFUSED", retry="SAME_REQUEST_LATER", status=503, retry_after=1),
                ),
                (post("/sandboxes", _CREATE_BODY), ok(created)),
            ],
            {"outcome": "success", "result": {"sandbox_id": SBX}, "exit_code": "success"},
        ),
        scenario(
            "cp-024-start-fails-and-the-sandbox-is-destroyed",
            "When the start fails, the default policy destroys the sandbox and the error names both outcomes.",
            ["SDK-9"],
            ("sandbox.create", {**_CREATE_ARGS, "idempotency_key": "key-0024"}),
            [
                (post("/sandboxes", _CREATE_BODY), ok(created)),
                (
                    post(f"/sandboxes/{SBX}/start", {"expected_generation": 1}, key="$KEY:start"),
                    ok(
                        operation(
                            OP_START,
                            "sandbox.start",
                            "FAILED",
                            effect="NOT_APPLIED",
                            cleanup="COMPLETE",
                            failure=m.Failure(
                                code="RESOURCE_EXHAUSTED",
                                retry="SAME_REQUEST_LATER",
                                message="The host has no capacity for this request",
                                side_effect="NONE",
                            ),
                        )
                    ),
                ),
                (
                    {
                        "method": "DELETE",
                        "path": f"{BASE}/sandboxes/{SBX}",
                        "query": {"expected_generation": "1"},
                        "headers": {"idempotency-key": "$KEY:destroy"},
                    },
                    ok(
                        operation(
                            OP_DESTROY,
                            "sandbox.destroy",
                            "SUCCEEDED",
                            effect="APPLIED",
                            result=m.OperationResult(sandbox=sandbox("DESTROYED")),
                        )
                    ),
                ),
            ],
            {
                "outcome": "error",
                "error": {"class": "SandboxStartError", "code": "RESOURCE_EXHAUSTED"},
                "exit_code": "operation_failed",
            },
        ),
        scenario(
            "cp-025-follow-bound-reached",
            "At the follow bound the client reports that the operation is still running. It assumes nothing. "
            "A bound shorter than the server's own wait is said to the server with the mutation.",
            ["CP-4", "LRO-2", "LRO-4"],
            ("sandbox.exec", exec_args),
            [
                (
                    post(f"/sandboxes/{SBX}/executions", exec_body, query={"wait": "5"}),
                    accepted(operation(OP_EXEC, "execution.create", "IN_PROGRESS", target=exec_target)),
                ),
                *[
                    (
                        get(f"{BASE}/operations/{OP_EXEC}", {"wait": str(wait)}),
                        ok(
                            operation(OP_EXEC, "execution.create", "IN_PROGRESS", target=exec_target),
                            headers={"retry-after": "1"},
                        ),
                    )
                    for wait in (4, 3, 2, 1)
                ],
            ],
            {"outcome": "error", "error": {"class": "OperationStillRunningError"}, "exit_code": "still_running"},
            config={"follow_max_s": 5},
        ),
        scenario(
            "cp-026-not-found",
            "A record of another project, or one that does not exist, is NOT_FOUND.",
            ["SEC-120"],
            ("sandbox.get", {"sandbox": SBX}),
            [(get(f"{BASE}/sandboxes/{SBX}"), problem("NOT_FOUND"))],
            {"outcome": "error", "error": {"class": "NotFoundError", "code": "NOT_FOUND"}, "exit_code": "refused"},
        ),
        scenario(
            "cp-027-upstream-unavailable-is-retried",
            "UPSTREAM_UNAVAILABLE says nothing was sent: the same request is repeated later.",
            ["RT-1"],
            ("sandbox.get", {"sandbox": SBX}),
            [
                (get(f"{BASE}/sandboxes/{SBX}"), problem("UPSTREAM_UNAVAILABLE", retry_after=1)),
                (get(f"{BASE}/sandboxes/{SBX}"), ok(sandbox("READY"), headers={"etag": '"r11.0123456789ab"'})),
            ],
            {"outcome": "success", "result": {"sandbox_id": SBX, "state": "READY"}, "exit_code": "success"},
        ),
    ]
    return {
        "schema_version": 1,
        "defaults": {"project": PROJECT, "base_url": "https://acf.test", "api_key": "acf1_dev_conformance"},
        "following": {
            "wait_s": 30,
            "backoff_initial_s": 0.5,
            "backoff_max_s": 5,
            "rule": (
                "After an answer in which the operation has not ended, the client waits Retry-After seconds if the "
                "answer carried it, else its backoff. If that wait would reach the follow bound, it reports the "
                "operation as still running. Otherwise it reads the operation with wait = min(wait_s, whole seconds "
                "left before the bound)."
            ),
        },
        "scenarios": scenarios,
    }
