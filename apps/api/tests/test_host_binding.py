"""The host binding against the real test host: the platform's only client of the execution plane.

The test host is the host agent's real edge, admission pipeline, coordinator and store over an
in-memory backend. The binding speaks to it over mutual TLS 1.3 as the enrolled ``caller``, exactly as
a deployment does. Whatever the platform assumes about the host's wire contract is checked here against
the host itself and not against the model of it: field names, the duplicate rule, the form of
``issued_at``, the tags on every view, and what a refusal says.

Three kinds of counterpart appear:

* the real host, for everything that is the host's behaviour;
* an interposer between the binding and the real host, to lose an answer at a chosen point or to
  change what ``host.info`` says, which the host binary cannot be told to do;
* a scripted TLS listener, for answers no well-behaved host gives.

Proves B26, HB-4, HB-7 to HB-10, SEC-102, SEC-125 and OBS-1, and the catalog entries T3-HB-01,
T3-HB-02, T3-RED-03 (the identity of the host), T3-RED-43, T3-SEC-02 and T3-OBS-03.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import secrets
import ssl
import struct
import time
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from acf_api.command import commands as c
from acf_api.command import model as m
from acf_api.command.answers import Answer, ErrorAnswer, RequestContext, ViewAnswer
from acf_api.command.client import new_request_id
from acf_api.core import app
from acf_api.core import config as cfg
from acf_api.core.clock import rfc3339
from acf_api.core.host import wire
from acf_api.core.host.binding import HostRefused, Lane, MtlsHostBinding, RequestTooLarge, tls_context
from acf_api.core.host.wire import (
    HostIdentityError,
    HostOperation,
    HostRefusal,
    HostRequest,
    HostResult,
    LostAnswer,
    Unreachable,
)
from acf_api.core.pipeline import mapping
from tests.support.deploy import (
    TEST_HOST_CALLER_PEER,
    TEST_HOST_ID,
    Authority,
    RawHostClient,
    RealHost,
    interposed,
    running_host,
)
from tests.support.harness import Identity, config_dict, create_deployment, sandbox_spec

pytestmark = pytest.mark.host

_HEADER = struct.Struct(">I")
TABLE = mapping.load_table()
#: §41 of the contract: what the platform requires of a host before it serves granting work.
REQUIRED_PROTOCOL = "acf.host/2"
REQUIRED_FEATURES = {"scope_tags", "operation_list"}
RESOURCES = {"vcpus": 1, "memory_mib": 256, "disk_mib": 128, "network": {"mode": "none"}}


@pytest.fixture(scope="module")
def host() -> Iterator[RealHost]:
    with running_host() as running:
        yield running


def binding_for(
    host: RealHost,
    identity: str = "caller",
    *,
    address: str | None = None,
    host_id: str = TEST_HOST_ID,
    anchors: Path | None = None,
    **settings: Any,
) -> MtlsHostBinding:
    context = tls_context(
        trust_anchors=anchors or host.anchors,
        certificate=host.certificate(identity),
        private_key=host.private_key(identity),
    )
    values: dict[str, Any] = {
        "max_connections": 8,
        "reserved_containment": 2,
        "reserved_resolution": 1,
        "connect_timeout_s": 5.0,
        "read_timeout_s": 15.0,
    }
    values.update(settings)
    return MtlsHostBinding(address=address or host.address, host_id=host_id, context=context, **values)


def stamp(offset_s: float = 0.0) -> str:
    return rfc3339(int((time.time() + offset_s) * 1000))


def operation_id() -> str:
    return "op-" + secrets.token_hex(16)


def mutation(method: str, scope: str, params: dict[str, Any], **envelope: Any) -> HostRequest:
    """A mutating envelope as the pipeline builds one: an operation id, `issued_at`, a label and a request id."""
    values: dict[str, Any] = {
        "operation_id": operation_id(),
        "issued_at": stamp(),
        "on_behalf_of": "prn_binding_test",
        "request_id": new_request_id(),
        "wait_ms": 5000,
    }
    values.update(envelope)
    return HostRequest(method=method, owner_scope=scope, params=params, **values)


def reading(method: str, scope: str, params: dict[str, Any] | None = None) -> HostRequest:
    return HostRequest(method=method, owner_scope=scope, params=params, request_id=new_request_id())


def create_request(scope: str, **envelope: Any) -> HostRequest:
    return mutation("sandbox.create", scope, {"image": "python", "resources": RESOURCES}, **envelope)


async def accepted(binding: MtlsHostBinding, request: HostRequest, lane: Lane = Lane.GENERAL) -> HostOperation:
    answer = await binding.submit(request, lane=lane)
    assert isinstance(answer, HostOperation), answer
    return answer


async def result(binding: MtlsHostBinding, request: HostRequest, lane: Lane = Lane.GENERAL) -> HostResult:
    answer = await binding.read(request, lane=lane)
    assert isinstance(answer, HostResult), answer
    return answer


async def refusal(binding: MtlsHostBinding, request: HostRequest, lane: Lane = Lane.GENERAL) -> HostRefusal:
    send = binding.submit if request.method in wire.MUTATING_METHODS else binding.read
    answer = await send(request, lane=lane)
    assert isinstance(answer, HostRefusal), answer
    return answer


async def empty(binding: MtlsHostBinding, scope: str) -> None:
    """Remove what a test left under a scope: the host's envelope is small, and the next test needs it."""
    listed = await result(binding, reading("sandbox.list", scope), Lane.CONTAINMENT)
    for sandbox in listed.data["items"]:
        target = {"sandbox_id": sandbox["sandbox_id"], "expected_generation": sandbox["generation"]}
        await binding.submit(mutation("sandbox.destroy", scope, target), lane=Lane.CONTAINMENT)
    snapshots = await result(binding, reading("snapshot.list", scope), Lane.CONTAINMENT)
    for snapshot in snapshots.data["items"]:
        await binding.submit(
            mutation("snapshot.delete", scope, {"snapshot": snapshot["snapshot"]}), lane=Lane.CONTAINMENT
        )


@pytest.fixture
async def caller(host: RealHost) -> AsyncIterator[MtlsHostBinding]:
    binding = binding_for(host)
    try:
        yield binding
    finally:
        await binding.aclose()


@pytest.fixture
async def scope(host: RealHost) -> AsyncIterator[str]:
    """An owner scope of this test alone. What the test leaves under it is removed afterwards."""
    name = "scp-" + secrets.token_hex(16)
    try:
        yield name
    finally:
        cleaner = binding_for(host)
        try:
            await empty(cleaner, name)
        finally:
            await cleaner.aclose()


# =============================================================================== host.info
@pytest.mark.proves("T3-HB-02")
async def test_host_info_is_parsed_and_says_what_the_platform_requires(caller: MtlsHostBinding) -> None:
    """HB-4, T3-HB-02: the host speaks a protocol major the platform was built for and advertises what it requires."""
    info = await caller.info()
    assert info.host_id == TEST_HOST_ID
    assert REQUIRED_PROTOCOL in info.protocols
    assert info.features >= REQUIRED_FEATURES
    assert "allowlist_network" in info.features
    assert info.network_modes >= {"none"}
    assert info.mode == "SERVING"
    assert info.lineage
    assert info.acceptance_horizon_ms > info.clock_skew_tolerance_ms > 0
    assert info.operation_retention_ms >= info.acceptance_horizon_ms
    assert min(info.max_vcpus, info.max_memory_mib, info.max_disk_mib, info.max_runtime_ms, info.lifetime_max_secs) > 0
    assert info.lifetime_default_secs <= info.lifetime_max_secs
    # The pool of identifiers is all the host says about how much it holds. Its envelope is not in `host.info`.
    assert info.identifier_slots is not None
    assert info.identifier_slots >= 16
    # What the binding learned replaces its default: the host's bound for one request.
    assert caller.max_request_bytes == info.max_request_bytes > 0


async def test_host_info_does_not_yet_report_what_the_platform_has_fallbacks_for(caller: MtlsHostBinding) -> None:
    """§41 of the contract, current state: no peer id, role, time, rate limit, forgetting floor or one-step create.

    When the host begins to report one of these, this test fails, and the fallback beside it is then to
    be replaced, not kept.
    """
    info = await caller.info()
    assert (info.peer_id, info.role, info.time_ms) == (None, None, None)
    assert (info.ops_per_minute, info.reads_per_minute, info.forgetting_floor_ms) == (None, None, None)
    assert info.create_with_start is False


# =============================================================================== a whole life, decoded and mapped
async def test_a_sandbox_lives_its_whole_life_through_the_binding_and_every_answer_decodes_and_maps(
    caller: MtlsHostBinding, scope: str
) -> None:
    """B26: create, start, execute, read output, snapshot, restore, stop, destroy; each answer through the mapping table."""
    lineage = (await caller.info()).lineage
    project = "prj_" + "0" * 20
    sequences: list[int] = []

    def seen(answer: HostOperation | HostResult) -> None:
        assert answer.as_of is not None
        assert answer.as_of.lineage == lineage
        sequences.append(answer.as_of.sequence)

    def public(answer: HostOperation) -> Any:
        seen(answer)
        assert answer.peer_id == TEST_HOST_CALLER_PEER
        assert answer.view["tags"] == {"peer_id": TEST_HOST_CALLER_PEER, "owner_scope": scope}
        view = mapping.operation(TABLE, answer.view, project, lineage)
        assert (view.state, view.terminal, view.effect) == ("SUCCEEDED", True, "APPLIED"), answer.view
        assert view.type != "UNRECOGNIZED"
        assert (view.initiated_by, view.actor is not None and view.actor.principal_id) == ("CALLER", "prn_binding_test")
        return view

    created = public(
        await accepted(
            caller, mutation("sandbox.create", scope, {"image": "python", "resources": RESOURCES, "name": "lab"})
        )
    )
    sandbox = created.result.sandbox
    assert (sandbox.state, sandbox.generation, sandbox.name) == ("PROVISIONING", 1, "lab")
    assert (sandbox.resources.vcpus, sandbox.resources.memory_mib, sandbox.resources.disk_mib) == (1, 256, 128)
    assert (sandbox.network.mode, sandbox.image.alias) == ("none", "python")
    assert sandbox.image.digest.startswith("sha256:")
    assert sandbox.expires_at.endswith("Z")
    assert sandbox.updated_at.endswith("Z")
    sandbox_id = sandbox.sandbox_id
    target = {"sandbox_id": sandbox_id, "expected_generation": 1}

    started = public(await accepted(caller, mutation("sandbox.start", scope, target)))
    assert started.result.sandbox.state == "READY"
    assert started.result.sandbox.revision != sandbox.revision

    ran = public(
        await accepted(
            caller, mutation("exec.run", scope, {**target, "command": {"argv": ["echo", "hello"], "env": {}}})
        )
    )
    execution = ran.result.execution
    assert (execution.status, execution.exit_code, execution.terminal) == ("EXITED", 0, True)
    assert execution.execution_id.startswith("exe-")
    assert execution.execution_id == ran.target.execution_id
    assert (execution.stdout.stored_bytes, execution.stdout.completeness) == (
        execution.stdout.produced_bytes,
        "COMPLETE",
    )
    assert execution.evidence_status != "UNRECOGNIZED"
    run_id = mapping.host_run_id(execution.execution_id)

    inspected = await result(caller, reading("run.inspect", scope, {"run_id": run_id}))
    seen(inspected)
    assert inspected.type == "run"
    assert mapping.execution_from_run(TABLE, inspected.data, project).execution_id == execution.execution_id

    output = await result(
        caller, reading("run.output", scope, {"run_id": run_id, "stream": "stdout", "offset": 0, "max_bytes": 1024})
    )
    seen(output)
    produced = base64.b64decode(output.data["data_b64"])
    chunk = mapping.output_chunk(TABLE, output.data, execution.execution_id, len(produced))
    assert (chunk.eof, chunk.completeness, chunk.next_offset) == (True, "COMPLETE", execution.stdout.stored_bytes)
    assert b"hello" in produced

    after_run = await result(caller, reading("sandbox.inspect", scope, {"sandbox": "lab"}))
    seen(after_run)
    by_name = mapping.sandbox(TABLE, after_run.data, project, lineage)
    assert (by_name.sandbox_id, by_name.state, by_name.last_execution) == (
        sandbox_id,
        "COMPLETED",
        execution.execution_id,
    )

    snapped = public(await accepted(caller, mutation("snapshot.create", scope, {**target, "name": "base"})))
    snapshot = snapped.result.snapshot
    assert (snapshot.state, snapshot.name, snapshot.snapshot_generation) == ("READY", "base", 1)
    assert snapshot.snapshot_id.startswith("snp-")
    assert snapshot.source_sandbox is not None
    assert (snapshot.source_sandbox.sandbox_id, snapshot.source_sandbox.generation) == (sandbox_id, 1)
    assert snapshot.size_bytes > 0
    reference = {"snapshot_id": snapshot.snapshot_id, "snapshot_generation": 1}

    listed = await result(caller, reading("snapshot.list", scope, {"limit": 10}))
    seen(listed)
    assert [mapping.snapshot(TABLE, item, project, lineage).snapshot_id for item in listed.data["items"]] == [
        snapshot.snapshot_id
    ]
    assert wire.peer_id_of(listed) == TEST_HOST_CALLER_PEER

    restored = public(
        await accepted(
            caller,
            mutation("snapshot.restore", scope, {"snapshot": reference, "target": {**target, "kind": "existing"}}),
        )
    )
    assert (restored.result.sandbox.generation, restored.result.sandbox.state) == (2, "READY")
    assert restored.result.sandbox.source_snapshot.snapshot_id == snapshot.snapshot_id
    target = {"sandbox_id": sandbox_id, "expected_generation": 2}

    stopped = public(await accepted(caller, mutation("sandbox.stop", scope, target), Lane.CONTAINMENT))
    assert stopped.result.sandbox.state == "STOPPED"
    destroyed = public(await accepted(caller, mutation("sandbox.destroy", scope, target), Lane.CONTAINMENT))
    assert destroyed.result.sandbox.state == "DESTROYED"
    deleted = public(
        await accepted(caller, mutation("snapshot.delete", scope, {"snapshot": reference}), Lane.CONTAINMENT)
    )
    assert deleted.target.snapshot_id == snapshot.snapshot_id

    operations = await result(caller, reading("operation.list", scope, {"limit": 100}))
    seen(operations)
    types = [mapping.operation(TABLE, item, project, lineage).type for item in operations.data["items"]]
    assert sorted(types) == sorted(
        # The public names of the host's operation types, through the mapping table.
        [
            "sandbox.create",
            "sandbox.start",
            "execution.create",
            "snapshot.create",
            "snapshot.restore",
            "sandbox.stop",
            "sandbox.destroy",
            "snapshot.delete",
        ]
    )
    remaining = await result(caller, reading("sandbox.list", scope))
    assert remaining.data["items"] == []
    assert mapping.decode_cursor(mapping.encode_cursor(remaining.data["next"])) == remaining.data["next"]
    assert sequences == sorted(sequences), "the host's commit sequence went backwards"


async def test_a_stopped_sandbox_cannot_be_started_again(caller: MtlsHostBinding, scope: str) -> None:
    """The host's lifecycle, carried faithfully: `STOPPED` leads to `DESTROYED` and nowhere else."""
    created = await accepted(caller, create_request(scope))
    target = {"sandbox_id": created.view["sandbox"][0], "expected_generation": 1}
    await accepted(caller, mutation("sandbox.start", scope, target))
    await accepted(caller, mutation("sandbox.stop", scope, target), Lane.CONTAINMENT)
    refused = await refusal(caller, mutation("sandbox.start", scope, target))
    assert (refused.failure_class, refused.retry) == ("STATE_CONFLICT", "AFTER_CHANGE")
    assert TABLE.value("failure_class", refused.failure_class) == ("STATE_CONFLICT", None)


# =============================================================================== what the platform relies on
async def test_a_duplicate_submission_of_the_same_envelope_is_the_same_operation(
    caller: MtlsHostBinding, scope: str
) -> None:
    """IDM-3, RT-2: the host deduplicates by operation id, so a resubmission creates nothing."""
    request = create_request(scope, issued_at=rfc3339(int(time.time()) * 1000))
    assert request.issued_at is not None
    assert request.issued_at.endswith(".000Z")
    first = await accepted(caller, request)
    second = await accepted(caller, request)
    assert second.operation_id == first.operation_id == request.operation_id
    assert second.view["sandbox"] == first.view["sandbox"]
    # IDM-16 compares these two strings: the host returns `issued_at` exactly as it was sent.
    assert first.issued_at == second.issued_at == request.issued_at
    listed = await result(caller, reading("sandbox.list", scope))
    assert [item["sandbox_id"] for item in listed.data["items"]] == [first.view["sandbox"][0]]


async def test_an_operation_id_names_one_request_and_keeps_the_issued_at_it_was_created_with(
    caller: MtlsHostBinding, scope: str
) -> None:
    """IDM-15, IDM-16: a different request under a known id is a conflict; the same one under a new time is the old operation."""
    request = create_request(scope)
    first = await accepted(caller, request)

    different = HostRequest(
        method=request.method,
        owner_scope=scope,
        params={"image": "python", "resources": {**RESOURCES, "vcpus": 2}},
        operation_id=request.operation_id,
        issued_at=request.issued_at,
    )
    conflict = await refusal(caller, different)
    assert (conflict.failure_class, conflict.retry) == (wire.IDEMPOTENCY_CONFLICT, "NEVER")

    later = HostRequest(
        method=request.method,
        owner_scope=scope,
        params=request.params,
        operation_id=request.operation_id,
        issued_at=stamp(1.0),
    )
    again = await accepted(caller, later)
    assert again.issued_at == first.issued_at == request.issued_at
    assert again.issued_at != later.issued_at


async def test_a_known_operation_is_answered_whatever_its_age_and_an_unknown_old_one_is_refused(
    caller: MtlsHostBinding, scope: str
) -> None:
    """IDM-7: the acceptance horizon refuses an operation the host has forgotten, and never one it still holds."""
    info = await caller.info()
    old = stamp(-(info.acceptance_horizon_ms / 1000 + 60))
    known = create_request(scope)
    first = await accepted(caller, known)
    aged = HostRequest(
        method=known.method, owner_scope=scope, params=known.params, operation_id=known.operation_id, issued_at=old
    )
    assert (await accepted(caller, aged)).operation_id == first.operation_id

    expired = await refusal(caller, create_request(scope, issued_at=old))
    assert (expired.failure_class, expired.retry) == (wire.EXPIRED_REQUEST, "NEVER")
    ahead = await refusal(caller, create_request(scope, issued_at=stamp(info.clock_skew_tolerance_ms / 1000 + 60)))
    assert ahead.failure_class == wire.EXPIRED_REQUEST

    absent = await refusal(caller, reading("operation.get", scope, {"operation_id": operation_id()}), Lane.RESOLUTION)
    assert (absent.failure_class, absent.retry) == (wire.NOT_FOUND, "NEVER")
    assert absent.as_of is not None, "REC3-5 judges an absence by the committed state the answer reflects"


async def test_a_name_is_unique_within_a_scope_and_lists_show_what_is_not_destroyed(
    caller: MtlsHostBinding, scope: str
) -> None:
    """DATA-5, IDM-10 (f), CC3-7: the host refuses a second record with a name; a list counts what still exists."""
    named = {"image": "python", "resources": RESOURCES, "name": "one-of-a-kind"}
    first = await accepted(caller, mutation("sandbox.create", scope, named))
    second = await refusal(caller, mutation("sandbox.create", scope, named))
    assert second.failure_class == "STATE_CONFLICT"
    other_scope = "scp-" + secrets.token_hex(16)
    try:
        elsewhere = await accepted(caller, mutation("sandbox.create", other_scope, named))
        assert elsewhere.view["sandbox"][0] != first.view["sandbox"][0]
    finally:
        await empty(caller, other_scope)

    listed = await result(caller, reading("sandbox.list", scope, {"limit": 1000}))
    assert [(item["sandbox_id"], item["state"] != "DESTROYED") for item in listed.data["items"]] == [
        (first.view["sandbox"][0], True)
    ]
    await accepted(
        caller,
        mutation("sandbox.destroy", scope, {"sandbox_id": first.view["sandbox"][0], "expected_generation": 1}),
        Lane.CONTAINMENT,
    )
    assert (await result(caller, reading("sandbox.list", scope))).data["items"] == []


CANARY = "kanarienvogel7Q2M9K4T"


async def test_what_a_refusal_of_the_host_repeats_of_the_request_and_what_it_never_does(
    caller: MtlsHostBinding, scope: str
) -> None:
    """The host's refusals as they are today: some quote a name the caller chose; none quotes a value or an argument.

    The platform does not rely on the first half: it withholds an explanation that quotes the request
    (the next tests). It does rely on the second: argument and environment *values* never come back.
    """
    created = await accepted(caller, create_request(scope))
    target = {"sandbox_id": created.view["sandbox"][0], "expected_generation": 1}
    await accepted(caller, mutation("sandbox.start", scope, target))

    def run(**command: Any) -> HostRequest:
        return mutation("exec.run", scope, {**target, "command": {"argv": ["true"], "env": {}, **command}})

    # A request that cannot be decoded is refused without a word of it.
    unknown_member = await refusal(
        caller, mutation("sandbox.create", scope, {"image": "python", "resources": RESOURCES, CANARY: 1})
    )
    wrong_type = await refusal(
        caller, mutation("sandbox.create", scope, {"image": "python", "resources": {**RESOURCES, "vcpus": CANARY}})
    )
    bad_name = await refusal(
        caller, mutation("sandbox.create", scope, {"image": "python", "resources": RESOURCES, "name": f"{CANARY} x"})
    )
    for refused in (unknown_member, wrong_type, bad_name):
        assert (refused.failure_class, CANARY in refused.message) == ("INVALID_REQUEST", False), refused

    # Values and arguments are never quoted, whatever the refusal is about.
    value = await refusal(caller, run(env={"SOME_NAME": CANARY}))
    arguments = await refusal(caller, run(argv=[CANARY] * 40))
    directory = await refusal(caller, run(cwd=f"relative/{CANARY}"))
    for refused in (value, arguments, directory):
        assert (refused.failure_class, CANARY in refused.message) == ("SAFETY_CONTROL_DENIED", False), refused

    # A name the safety profile does not permit, and an identifier the host does not hold, are quoted.
    image = await refusal(caller, mutation("sandbox.create", scope, {"image": CANARY, "resources": RESOURCES}))
    variable = await refusal(caller, run(env={CANARY: "value"}))
    absent = await refusal(caller, reading("operation.get", scope, {"operation_id": f"op-{CANARY}"}), Lane.RESOLUTION)
    assert (image.failure_class, variable.failure_class, absent.failure_class) == (
        "SAFETY_CONTROL_DENIED",
        "SAFETY_CONTROL_DENIED",
        "NOT_FOUND",
    )
    for refused, quoted in ((image, [CANARY]), (variable, [CANARY]), (absent, [f"op-{CANARY}"])):
        assert CANARY in refused.message, (
            "the host no longer quotes this: the platform's withholding has nothing left to do here"
        )
        assert wire.repeats(refused.message, quoted)


async def test_the_explanation_of_a_host_refusal_is_passed_on_unless_it_quotes_the_request(
    host: RealHost, tmp_path: Path
) -> None:
    """ERR-6 on the public surface, whatever the host says: the class and the advice are the host's, the caller's words stay out."""
    binding = binding_for(host)
    core = await core_over(binding, tmp_path)
    try:
        dev = await developer(core)
        service = core.service
        created = view(
            await service.handle(
                dev.key, context(), c.CreateSandbox(project=dev.project_id, spec=sandbox_spec()), "k-create"
            )
        )
        sandbox_id = created["result"]["sandbox"]["sandbox_id"]
        view(
            await service.handle(
                dev.key,
                context(),
                c.StartSandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation=1),
                "k-start",
            )
        )

        image = error(
            await service.handle(
                dev.key, context(), c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(image=CANARY)), "k-image"
            )
        )
        variable = error(
            await service.handle(
                dev.key,
                context(),
                c.Exec(project=dev.project_id, sandbox_id=sandbox_id, spec=sandbox_exec(env={CANARY: "v"})),
                "k-env",
            )
        )
        absent = error(
            await service.handle(
                dev.key, context(), c.GetOperation(project=dev.project_id, operation_id=f"op-{CANARY}"), None
            )
        )
        assert [(e.code, e.kind, e.retry) for e in (image, variable, absent)] == [
            ("SAFETY_CONTROL_DENIED", "REFUSED", "AFTER_CHANGE"),
            ("SAFETY_CONTROL_DENIED", "REFUSED", "AFTER_CHANGE"),
            ("NOT_FOUND", "REFUSED", "NEVER"),
        ]
        for refused in (image, variable, absent):
            assert CANARY not in refused.model_dump_json()
            assert refused.message
        assert core.telemetry.get("host_messages_withheld", host_class="SAFETY_CONTROL_DENIED") == 2

        # An explanation in the host's own words is the caller's to read, unchanged.
        named = c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(name="taken"))
        view(await service.handle(dev.key, context(), named, "k-named"))
        taken = error(await service.handle(dev.key, context(), named, "k-named-again"))
        assert (taken.code, taken.retry) == ("STATE_CONFLICT", "AFTER_CHANGE")
        assert taken.message == "a sandbox with that name already exists in this scope"
    finally:
        await empty(binding, dev.scope)
        await core.close()


# =============================================================================== scopes
async def test_records_of_one_owner_scope_are_not_found_under_another(caller: MtlsHostBinding, scope: str) -> None:
    """HB-10, SEC-120: tags separate scopes on the host, for every method, once the platform has named one."""
    created = await accepted(
        caller, mutation("sandbox.create", scope, {"image": "python", "resources": RESOURCES, "name": "mine"})
    )
    sandbox_id = created.view["sandbox"][0]
    target = {"sandbox_id": sandbox_id, "expected_generation": 1}
    await accepted(caller, mutation("sandbox.start", scope, target))
    ran = await accepted(caller, mutation("exec.run", scope, {**target, "command": {"argv": ["true"], "env": {}}}))
    snapped = await accepted(caller, mutation("snapshot.create", scope, target))
    reference = snapped.view["snapshot"]

    other = "scp-" + secrets.token_hex(16)
    attempts = [
        reading("sandbox.inspect", other, {"sandbox": sandbox_id}),
        reading("sandbox.inspect", other, {"sandbox": "mine"}),
        reading("operation.get", other, {"operation_id": created.operation_id}),
        reading("run.inspect", other, {"run_id": ran.view["run_id"]}),
        reading("run.output", other, {"run_id": ran.view["run_id"], "stream": "stdout"}),
        mutation("sandbox.start", other, target),
        mutation("exec.run", other, {**target, "command": {"argv": ["true"], "env": {}}}),
        mutation("snapshot.create", other, target),
        mutation("snapshot.restore", other, {"snapshot": reference, "target": {"kind": "new"}}),
        mutation("snapshot.delete", other, {"snapshot": reference}),
        mutation("operation.cancel", other, {"operation_id": ran.operation_id}),
        mutation("sandbox.stop", other, target),
        mutation("sandbox.destroy", other, target),
    ]
    for attempt in attempts:
        lane = (
            Lane.CONTAINMENT
            if attempt.method in {"sandbox.stop", "sandbox.destroy", "snapshot.delete", "operation.cancel"}
            else Lane.GENERAL
        )
        refused = await refusal(caller, attempt, lane)
        assert (refused.failure_class, refused.retry) == (wire.NOT_FOUND, "NEVER"), attempt.method
    for method in ("sandbox.list", "snapshot.list", "operation.list"):
        assert (await result(caller, reading(method, other))).data["items"] == [], method

    still = await result(caller, reading("sandbox.inspect", scope, {"sandbox": sandbox_id}))
    assert still.data["tags"] == {"peer_id": TEST_HOST_CALLER_PEER, "owner_scope": scope}


async def test_an_operator_method_is_not_a_request_the_binding_will_send(caller: MtlsHostBinding, scope: str) -> None:
    """T3-SEC-06, SEC-106: no operator capability of the host is reachable; the binding refuses to carry one at all."""
    for method in sorted(wire.FORBIDDEN_METHODS):
        request = mutation(method, scope, {"mode": "DRAINING"})
        with pytest.raises(ValueError, match="not a mutation the platform may send"):
            await caller.submit(request, lane=Lane.GENERAL)
        with pytest.raises(ValueError, match="not a read the platform may send"):
            await caller.read(request, lane=Lane.GENERAL)
    assert caller.in_use() == {"general": 0, "containment": 0, "resolution": 0}


# =============================================================================== the host's identity
@pytest.mark.proves("T3-RED-03")
async def test_a_host_whose_certificate_does_not_carry_the_configured_host_id_is_refused_and_sent_nothing(
    host: RealHost, caller: MtlsHostBinding, scope: str
) -> None:
    """HB-9, SEC-125, T3-RED-03: the binding requires the configured `host_id`; nothing is sent to anything else."""
    impostor = binding_for(host, host_id="another-host")
    request = create_request(scope)
    try:
        with pytest.raises(HostIdentityError, match="another-host"):
            await impostor.submit(request, lane=Lane.GENERAL)
        with pytest.raises(HostIdentityError):
            await impostor.read(reading("sandbox.list", scope), lane=Lane.GENERAL)
        with pytest.raises(HostIdentityError):
            await impostor.info()
        assert impostor.in_use() == {"general": 0, "containment": 0, "resolution": 0}
    finally:
        await impostor.aclose()
    assert isinstance(HostIdentityError("x"), Unreachable), "the pipeline reads it as: nothing was written"
    absent = await refusal(
        caller, reading("operation.get", scope, {"operation_id": request.operation_id}), Lane.RESOLUTION
    )
    assert absent.failure_class == wire.NOT_FOUND
    assert (await result(caller, reading("sandbox.list", scope))).data["items"] == []


@pytest.mark.proves("T3-RED-03")
async def test_a_host_whose_chain_the_configured_anchors_do_not_sign_is_refused(
    host: RealHost, caller: MtlsHostBinding, scope: str, tmp_path: Path
) -> None:
    """HB-9: only the trust anchors of the configuration are trusted. Another authority's word counts for nothing."""
    elsewhere = Authority("an authority the host was not signed by").write_anchor(tmp_path / "other-ca.crt")
    distrusting = binding_for(host, anchors=elsewhere)
    request = create_request(scope)
    try:
        with pytest.raises(HostIdentityError):
            await distrusting.submit(request, lane=Lane.GENERAL)
        with pytest.raises(HostIdentityError):
            await distrusting.info()
    finally:
        await distrusting.aclose()
    absent = await refusal(
        caller, reading("operation.get", scope, {"operation_id": request.operation_id}), Lane.RESOLUTION
    )
    assert absent.failure_class == wire.NOT_FOUND


@pytest.mark.proves("T3-RED-03")
def test_the_system_trust_store_is_never_consulted_and_only_tls_1_3_is_spoken(host: RealHost) -> None:
    """HB-9, T3-RED-03: a certificate only the system store trusts is not the host's. B26: mutual TLS 1.3."""
    context = tls_context(
        trust_anchors=host.anchors, certificate=host.certificate("caller"), private_key=host.private_key("caller")
    )
    assert context.cert_store_stats() == {"x509": 1, "crl": 0, "x509_ca": 1}
    assert (context.minimum_version, context.maximum_version) == (ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3)
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname is True


async def test_the_host_itself_speaks_nothing_below_tls_1_3(host: RealHost) -> None:
    older = host.context("caller")
    older.minimum_version = ssl.TLSVersion.TLSv1_2
    older.maximum_version = ssl.TLSVersion.TLSv1_2
    with pytest.raises((ssl.SSLError, ConnectionError)):
        await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", host.port, ssl=older, server_hostname=TEST_HOST_ID), 10
        )


async def test_an_identity_the_host_has_not_enrolled_is_refused_by_the_host_and_nothing_is_recorded(
    host: RealHost, caller: MtlsHostBinding, scope: str
) -> None:
    """ERR-5: `AUTHENTICATION_FAILED` is the host's refusal of the platform itself, carried as a refusal.

    The `stranger` identity is signed by the host's authority and is in no enrolment entry. The host
    completes the handshake, says so in one refusal frame and closes. The binding reads that frame as
    the answer to what it sent: a refusal, for a read and for a mutation alike, and never a lost answer.
    """
    request = create_request(scope)
    for _ in range(3):
        stranger = binding_for(host, "stranger")
        try:
            with pytest.raises(HostRefused) as refused:
                await stranger.info()
            assert (refused.value.refusal.failure_class, refused.value.refusal.retry) == (
                "AUTHENTICATION_FAILED",
                "NEVER",
            )
            submitted = await stranger.submit(request, lane=Lane.GENERAL)
            assert isinstance(submitted, HostRefusal)
            assert submitted.failure_class == "AUTHENTICATION_FAILED"
            assert submitted.failure_class in TABLE.platform_faults
        finally:
            await stranger.aclose()
    absent = await refusal(
        caller, reading("operation.get", scope, {"operation_id": request.operation_id}), Lane.RESOLUTION
    )
    assert absent.failure_class == wire.NOT_FOUND


# =============================================================================== connection classes
async def test_containment_and_resolution_have_connections_that_granting_work_cannot_take(
    caller: MtlsHostBinding, scope: str
) -> None:
    """T3-RED-35, HB-8: with the general class exhausted, a containment call and a resolution read still complete.

    Whoever holds every connection that granting work may use, by however many keys and sandboxes, cannot
    delay a destroy: it travels in a class of its own and completes within the bound stated below.
    """
    created = await accepted(caller, create_request(scope))
    target = {"sandbox_id": created.view["sandbox"][0], "expected_generation": 1}
    async with contextlib.AsyncExitStack() as held:
        for _ in range(5):
            await held.enter_async_context(caller._lease(Lane.GENERAL, None))
        assert caller.in_use() == {"general": 5, "containment": 0, "resolution": 0}

        waiting = asyncio.create_task(caller.read(reading("sandbox.list", scope), lane=Lane.GENERAL))
        await asyncio.sleep(0.3)
        assert not waiting.done(), "a sixth general call found a connection that the class does not have"

        destroyed = await asyncio.wait_for(
            accepted(caller, mutation("sandbox.destroy", scope, target), Lane.CONTAINMENT), 5
        )
        assert destroyed.view["result"]["data"]["state"] == "DESTROYED"
        resolved = await asyncio.wait_for(
            result(caller, reading("operation.get", scope, {"operation_id": created.operation_id}), Lane.RESOLUTION), 5
        )
        assert resolved.data["operation_id"] == created.operation_id
        assert not waiting.done()
    assert isinstance(await asyncio.wait_for(waiting, 5), HostResult)
    assert caller.in_use() == {"general": 0, "containment": 0, "resolution": 0}


async def test_no_principal_holds_more_than_half_of_the_general_class(caller: MtlsHostBinding, scope: str) -> None:
    """HB-8: one principal's calls cannot occupy the class; another principal's still find a connection."""
    async with contextlib.AsyncExitStack() as held:
        for _ in range(2):
            await held.enter_async_context(caller._lease(Lane.GENERAL, "prn_greedy"))
        third = asyncio.create_task(
            caller.read(reading("sandbox.list", scope), lane=Lane.GENERAL, principal_id="prn_greedy")
        )
        await asyncio.sleep(0.3)
        assert not third.done(), "one principal took a third of five general connections"
        assert caller.in_use()["general"] == 2

        other = await asyncio.wait_for(
            caller.read(reading("sandbox.list", scope), lane=Lane.GENERAL, principal_id="prn_modest"), 5
        )
        assert isinstance(other, HostResult)
        # Containment is not counted against a principal's share of the general class.
        contained = await asyncio.wait_for(
            caller.read(reading("sandbox.list", scope), lane=Lane.CONTAINMENT, principal_id="prn_greedy"), 5
        )
        assert isinstance(contained, HostResult)
    assert isinstance(await asyncio.wait_for(third, 5), HostResult)


async def test_the_binding_never_opens_more_connections_than_it_was_given(host: RealHost, scope: str) -> None:
    """B26: at most `host_max_connections` connections, however many calls are made at once."""
    with interposed(host, host.base) as relay:
        counted = binding_for(host, address=relay.address, anchors=relay.anchors)
        try:
            calls = [
                counted.read(reading("sandbox.list", scope), lane=lane)
                for lane in (Lane.GENERAL, Lane.CONTAINMENT, Lane.RESOLUTION)
                for _ in range(20)
            ]
            assert all(isinstance(answer, HostResult) for answer in await asyncio.gather(*calls))
            assert len(relay.requests) == 60
            assert 1 <= relay.connections <= 8, relay.connections
        finally:
            await counted.aclose()


async def test_a_request_larger_than_the_host_accepts_is_refused_before_anything_is_sent(
    host: RealHost, scope: str
) -> None:
    """The host's bound for one request is the binding's too: an oversize request is never put on the wire."""
    with interposed(host, host.base) as relay:
        bounded = binding_for(host, address=relay.address, anchors=relay.anchors)
        try:
            info = await bounded.info()
            sent = len(relay.requests)
            oversize = mutation(
                "exec.run",
                scope,
                {
                    "sandbox_id": "sbx-" + "0" * 32,
                    "expected_generation": 1,
                    "command": {"argv": ["x" * info.max_request_bytes]},
                },
            )
            with pytest.raises(RequestTooLarge) as refused:
                await bounded.submit(oversize, lane=Lane.GENERAL)
            assert (refused.value.maximum, refused.value.length > refused.value.maximum) == (
                info.max_request_bytes,
                True,
            )
            with pytest.raises(RequestTooLarge):
                await bounded.read(
                    reading("sandbox.inspect", scope, {"sandbox": "x" * info.max_request_bytes}), lane=Lane.GENERAL
                )
            assert len(relay.requests) == sent
            assert bounded.in_use() == {"general": 0, "containment": 0, "resolution": 0}
        finally:
            await bounded.aclose()


# =============================================================================== lost answers, at the binding
@pytest.mark.proves("T3-HB-01")
async def test_what_a_failed_exchange_means_is_decided_by_whether_the_request_was_written(
    host: RealHost, caller: MtlsHostBinding, scope: str
) -> None:
    """B26: before the request is written, `Unreachable`; after, `LostAnswer` for a mutation. A read changed nothing."""
    with interposed(host, host.base) as relay:
        lossy = binding_for(host, address=relay.address, anchors=relay.anchors)
        try:
            # The host acts and its answer is lost.
            relay.rewrite = lambda request, answer: None if request["method"] == "sandbox.create" else answer
            acted = create_request(scope)
            with pytest.raises(LostAnswer):
                await lossy.submit(acted, lane=Lane.GENERAL)
            # RT-2: the operation is found by reading it with its id, and the same envelope is the same operation.
            relay.rewrite = None
            found = await result(
                lossy, reading("operation.get", scope, {"operation_id": acted.operation_id}), Lane.RESOLUTION
            )
            assert (found.data["operation_id"], found.data["issued_at"]) == (acted.operation_id, acted.issued_at)
            assert (await accepted(lossy, acted)).view["sandbox"] == found.data["sandbox"]

            # The request is lost on the way: the binding cannot tell the difference, and does not pretend to.
            relay.refuse = lambda request: request["method"] == "sandbox.create"
            never_arrived = create_request(scope)
            with pytest.raises(LostAnswer):
                await lossy.submit(never_arrived, lane=Lane.GENERAL)
            relay.refuse = None
            absent = await refusal(
                lossy, reading("operation.get", scope, {"operation_id": never_arrived.operation_id}), Lane.RESOLUTION
            )
            assert absent.failure_class == wire.NOT_FOUND

            # A read whose answer is lost is only "not answered".
            relay.rewrite = lambda request, answer: None
            with pytest.raises(Unreachable) as unanswered:
                await lossy.read(reading("sandbox.list", scope), lane=Lane.GENERAL)
            assert not isinstance(unanswered.value, HostIdentityError)
            relay.rewrite = None
            assert len((await result(lossy, reading("sandbox.list", scope))).data["items"]) == 1
            assert lossy.in_use() == {"general": 0, "containment": 0, "resolution": 0}
        finally:
            await lossy.aclose()

    # With nothing listening, the request provably never left.
    nowhere = binding_for(host, address="127.0.0.1:1", connect_timeout_s=2.0)
    try:
        with pytest.raises(Unreachable) as unreachable:
            await nowhere.submit(create_request(scope), lane=Lane.GENERAL)
        assert not isinstance(unreachable.value, HostIdentityError)
    finally:
        await nowhere.aclose()


@contextlib.asynccontextmanager
async def scripted_host(
    directory: Path, reply: Callable[[dict[str, Any]], bytes | None], *, tls_1_2: bool = False
) -> AsyncIterator[tuple[MtlsHostBinding, list[dict[str, Any]]]]:
    """A TLS listener that answers each request with the bytes ``reply`` gives, and a binding that trusts it."""
    authority = Authority("acf scripted host")
    anchors = authority.write_anchor(directory / "scripted-ca.crt")
    certificate, key = authority.issue(directory, "scripted", names=(TEST_HOST_ID, "127.0.0.1"), server=True)
    client_certificate, client_key = authority.issue(directory, "platform")
    served = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    served.load_cert_chain(str(certificate), str(key))
    if tls_1_2:
        served.maximum_version = ssl.TLSVersion.TLSv1_2
    requests: list[dict[str, Any]] = []

    async def serve(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        with contextlib.suppress(asyncio.IncompleteReadError, OSError):
            (length,) = _HEADER.unpack(await reader.readexactly(_HEADER.size))
            request = json.loads(await reader.readexactly(length))
            requests.append(request)
            answer = reply(request)
            if answer is not None:
                writer.write(answer)
                await writer.drain()
        writer.close()

    server = await asyncio.start_server(serve, "127.0.0.1", 0, ssl=served)
    port = server.sockets[0].getsockname()[1]
    binding = MtlsHostBinding(
        address=f"127.0.0.1:{port}",
        host_id=TEST_HOST_ID,
        context=tls_context(trust_anchors=anchors, certificate=client_certificate, private_key=client_key),
        max_connections=8,
        reserved_containment=2,
        reserved_resolution=1,
        connect_timeout_s=5.0,
        read_timeout_s=3.0,
    )
    try:
        yield binding, requests
    finally:
        await binding.aclose()
        server.close()


def _framed(text: bytes) -> bytes:
    return _HEADER.pack(len(text)) + text


UNREADABLE_ANSWERS = {
    "not-json": _framed(b"this is not an envelope"),
    "not-an-object": _framed(b"[]"),
    "another-protocol": _framed(
        b'{"protocol":"some.other/1","answer":"REFUSED","refusal":{"class":"NOT_FOUND","retry":"NEVER","message":"x"}}'
    ),
    "an-answer-kind-nobody-knows": _framed(b'{"protocol":"acf.host/2","answer":"MAYBE"}'),
    "an-operation-without-its-view": _framed(b'{"protocol":"acf.host/2","answer":"OPERATION"}'),
    "a-refusal-without-its-body": _framed(b'{"protocol":"acf.host/2","answer":"REFUSED"}'),
    "invalid-utf8": _framed(b'{"protocol":"acf.host/2","answer":"\xff\xfe"}'),
    "nested-beyond-any-parser": _framed(b"[" * 200_000 + b"]" * 200_000),
    "an-oversize-length": _HEADER.pack(1 << 31),
    "cut-short": _HEADER.pack(4096) + b'{"protocol":"acf.host/2"',
    "closed-without-an-answer": b"",
    "a-result-for-a-mutation": _framed(
        b'{"protocol":"acf.host/2","answer":"RESULT","result":{"type":"sandboxes","data":{"items":[]}}}'
    ),
}


@pytest.mark.parametrize("name", sorted(UNREADABLE_ANSWERS))
@pytest.mark.proves("T3-HB-01")
async def test_an_answer_the_platform_cannot_use_is_a_lost_answer_whatever_makes_it_unusable(
    tmp_path: Path, name: str
) -> None:
    """ERR-1 at this hop: once the request is written, every failure means "the host may have acted"."""
    async with scripted_host(tmp_path, lambda _: UNREADABLE_ANSWERS[name]) as (binding, requests):
        with pytest.raises(LostAnswer):
            await binding.submit(create_request("scp-" + "0" * 32), lane=Lane.GENERAL)
        assert [request["method"] for request in requests] == ["sandbox.create"], "the request had been written"
        assert binding.in_use() == {"general": 0, "containment": 0, "resolution": 0}
        if name != "a-result-for-a-mutation":
            with pytest.raises(Unreachable):
                await binding.read(reading("sandbox.list", "scp-" + "0" * 32), lane=Lane.GENERAL)


async def test_a_listener_that_offers_less_than_tls_1_3_is_not_spoken_to(tmp_path: Path) -> None:
    """B26: mutual TLS 1.3 and nothing below it. Nothing is written to an endpoint that offers less."""
    async with scripted_host(tmp_path, lambda _: None, tls_1_2=True) as (binding, requests):
        with pytest.raises(Unreachable):
            await binding.submit(create_request("scp-" + "0" * 32), lane=Lane.GENERAL)
        assert requests == []


# =============================================================================== the pipeline over the real binding
def context() -> RequestContext:
    return RequestContext(request_id=new_request_id(), budget_ms=8000, interface="rest", interface_version="v1")


async def core_over(binding: MtlsHostBinding, root: Path, **parameters: Any) -> app.Core:
    """A real core (store, journal, pipeline, system clock) whose host binding is the one given."""
    create_deployment(root, **parameters)
    document = config_dict(root, **parameters)
    document["host"]["host_id"] = TEST_HOST_ID
    core = await app.build_core(cfg.parse_config(document), binding=binding, check_files=False)
    await core.recovery.startup_pass()
    return core


async def developer(core: app.Core, label: str = "dev") -> Identity:
    project = await core.admin.run("project.create", {"label": f"{label}-project"})
    assert project["state"] == "ACTIVE", project
    principal = await core.admin.run("principal.create", {"label": label})
    await core.admin.run("role.set", {"principal_id": principal["principal_id"], "project_id": project["project_id"]})
    key = await core.admin.run(
        "key.issue", {"principal_id": principal["principal_id"], "project_id": project["project_id"]}
    )
    stored = await core.service.d.registry.project(project["project_id"])
    assert stored is not None
    return Identity(project["project_id"], principal["principal_id"], key["credential_id"], key["secret"], stored.scope)


def view(answer: Answer) -> dict[str, Any]:
    assert isinstance(answer, ViewAnswer), answer
    return answer.body


@pytest.mark.proves("T3-SEC-02", "T3-OBS-03")
async def test_no_credential_of_a_caller_ever_reaches_the_host_and_every_request_carries_the_callers_request_id(
    host: RealHost, tmp_path: Path
) -> None:
    """SEC-102, T3-SEC-02, OBS-1, T3-OBS-03, SEC-101: the traffic to the host, captured as it was sent."""
    with interposed(host, host.base) as relay:
        binding = binding_for(host, address=relay.address, anchors=relay.anchors)
        core = await core_over(binding, tmp_path)
        try:
            dev = await developer(core)
            service = core.service
            caused: dict[str, tuple[int, int]] = {}

            async def call(command: c.Command, key: str | None = None) -> dict[str, Any]:
                ctx, before = context(), len(relay.requests)
                body = view(await service.handle(dev.key, ctx, command, key))
                caused[ctx.request_id] = (before, len(relay.requests))
                return body

            created = await call(c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(name="traced")), "k-create")
            sandbox_id = created["result"]["sandbox"]["sandbox_id"]
            await call(
                c.StartSandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation="current"), "k-start"
            )
            ran = await call(c.Exec(project=dev.project_id, sandbox_id=sandbox_id, spec=sandbox_exec()), "k-exec")
            await call(c.GetExecutionOutput(project=dev.project_id, execution_id=ran["target"]["execution_id"]))
            await call(c.GetSandbox(project=dev.project_id, sandbox="traced"))
            await call(c.ListSandboxes(project=dev.project_id))
            await call(c.GetOperation(project=dev.project_id, operation_id=created["operation_id"]))
            await call(c.WhoAmI())
            await call(
                c.DestroySandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation="current"),
                "k-destroy",
            )

            assert len(relay.frames) > 12
            everything = b"\n".join(relay.frames)
            assert dev.key.encode("ascii") not in everything, "a caller's credential was sent to the host"
            assert b"acf1_dev_" not in everything
            assert b"Bearer" not in everything
            # What does travel: the principal as a label, the project's scope, and the platform's request id.
            first_call = min(first for first, _ in caused.values())
            assert {r["owner_scope"] for r in relay.requests[first_call:] if r["method"] != "host.info"} == {dev.scope}
            for request_id, (first, last) in caused.items():
                sent = relay.requests[first:last]
                assert {request.get("request_id") for request in sent} <= {request_id}, [r["method"] for r in sent]
            assert sum(last - first for first, last in caused.values()) >= 12
            mutating = [
                request
                for request in relay.requests
                if request.get("operation_id") and request["method"] != "operation.get"
            ]
            assert [request["method"] for request in mutating] == [
                "sandbox.create",
                "sandbox.start",
                "exec.run",
                "sandbox.destroy",
            ]
            assert {request["on_behalf_of"] for request in mutating} == {dev.principal_id}
            assert all(set(request) <= ENVELOPE_MEMBERS for request in relay.requests)
        finally:
            await core.close()


#: The members of the host's request envelope. The platform adds none: no trace context, no credential.
ENVELOPE_MEMBERS = {
    "protocol",
    "owner_scope",
    "method",
    "params",
    "operation_id",
    "issued_at",
    "on_behalf_of",
    "request_id",
    "wait_ms",
}


def sandbox_exec(**spec: Any) -> m.ExecSpec:
    return m.ExecSpec.model_validate({"expected_generation": 1, "argv": ["echo", "traced"], **spec})


def error(answer: Answer) -> Any:
    assert isinstance(answer, ErrorAnswer), answer
    return answer.error


@pytest.mark.proves("T3-HB-01")
async def test_a_lost_host_answer_is_resolved_by_reading_the_operation_and_never_by_submitting_again(
    host: RealHost, tmp_path: Path
) -> None:
    """T3-HB-01, RT-2: the entry's operation id is read, at most `host_resolve_attempts` times; one operation exists."""
    with interposed(host, host.base) as relay:
        binding = binding_for(host, address=relay.address, anchors=relay.anchors)
        core = await core_over(binding, tmp_path)
        try:
            dev = await developer(core)
            attempts = core.config.parameters.host_resolve_attempts
            create = c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(name="resolved"))

            def about(operation: str) -> list[str]:
                return [
                    request["method"]
                    for request in relay.requests
                    if request.get("operation_id") == operation
                    or (request.get("params") or {}).get("operation_id") == operation
                ]

            # The host accepts and its answer is lost; the read that follows is answered.
            relay.rewrite = lambda request, answer: None if request["method"] == "sandbox.create" else answer
            resolved = view(await core.service.handle(dev.key, context(), create, "k-lost-once"))
            assert (resolved["state"], resolved["replayed"]) == ("SUCCEEDED", False)
            assert about(resolved["operation_id"]) == ["sandbox.create", "operation.get"]

            # Every answer is lost, the reads included: the platform cannot tell, says so, and stops reading.
            relay.rewrite = lambda request, answer: (
                None if request["method"] in {"sandbox.create", "operation.get"} else answer
            )
            other = c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(name="unresolved"))
            unresolved = error(await core.service.handle(dev.key, context(), other, "k-lost-always"))
            assert (unresolved.code, unresolved.kind, unresolved.idempotency_key) == (
                "OUTCOME_UNRESOLVED",
                "UNRESOLVED",
                "k-lost-always",
            )
            lost = [r for r in relay.requests if r["method"] == "sandbox.create"][-1]["operation_id"]
            assert about(lost) == ["sandbox.create"] + ["operation.get"] * attempts

            # The caller asks again with the same key: the operation that was created all along, marked as earlier work.
            relay.rewrite = None
            again = view(await core.service.handle(dev.key, context(), other, "k-lost-always"))
            assert (again["operation_id"], again["replayed"], again["state"]) == (lost, True, "SUCCEEDED")
            assert about(lost).count("sandbox.create") == 1

            with RawHostClient(host, "operator") as operator:
                # An operator sees the records of every scope; these are the ones of this project.
                everything = operator.read("sandbox.list", dev.scope, {"limit": 1000})["items"]
                names = sorted(item["name"] for item in everything if item["tags"]["owner_scope"] == dev.scope)
            assert names == ["resolved", "unresolved"]
        finally:
            await empty(binding, dev.scope)
            await core.close()


@pytest.mark.proves("T3-HB-02", "T3-RED-43")
async def test_what_host_info_says_decides_what_the_platform_offers(host: RealHost, tmp_path: Path) -> None:
    """HB-4, T3-HB-02, T3-RED-43: a required feature or the protocol gone, granting work is refused and says what is missing."""
    with interposed(host, host.base) as relay:
        binding = binding_for(host, address=relay.address, anchors=relay.anchors)
        core = await core_over(binding, tmp_path, host_info_ttl=0.05)
        try:
            dev = await developer(core)
            says: dict[str, Any] = {}

            def changed(request: dict[str, Any], answer: dict[str, Any]) -> dict[str, Any]:
                if request["method"] == "host.info" and answer.get("answer") == "RESULT":
                    answer["result"]["data"].update(says)
                return answer

            relay.rewrite = changed
            real = (await binding.info()).features
            number = 0

            async def create() -> Answer:
                nonlocal number
                number += 1
                await asyncio.sleep(0.06)  # longer than `host_info_ttl`: the next request reads the host again
                command = c.CreateSandbox(project=dev.project_id, spec=sandbox_spec())
                return await core.service.handle(dev.key, context(), command, f"k-{number}")

            for feature in sorted(REQUIRED_FEATURES):
                says["features"] = sorted(real - {feature})
                refused = error(await create())
                assert (refused.code, refused.kind, refused.retry) == (
                    "UPSTREAM_UNAVAILABLE",
                    "REFUSED",
                    "SAME_REQUEST_LATER",
                )
                assert refused.reason == f"host_feature_missing:{feature}"

            says["features"] = sorted(real)
            says["protocols"] = ["acf.host/9"]
            assert error(await create()).reason == "host_protocol_unsupported"
            assert not [r for r in relay.requests if r["method"] == "sandbox.create"], (
                "granting work reached a host that lacks what it needs"
            )

            # Reads and containment are not gated; and an optional feature gone only withdraws what needs it.
            assert (
                view(await core.service.handle(dev.key, context(), c.ListSandboxes(project=dev.project_id), None))[
                    "items"
                ]
                == []
            )
            says.pop("protocols")
            says["features"] = sorted(real - {"allowlist_network"})
            await asyncio.sleep(0.06)
            info = view(await core.service.handle(dev.key, context(), c.Info(), None))
            assert (info["ready"], "allowlist_network" in info["host_features"]) == (True, False)
            says.clear()
            await asyncio.sleep(0.06)
            assert (
                "allowlist_network"
                in view(await core.service.handle(dev.key, context(), c.Info(), None))["host_features"]
            )
            assert view(await create())["state"] == "SUCCEEDED"
        finally:
            await empty(binding, dev.scope)
            await core.close()


@pytest.mark.proves("T3-RED-03")
async def test_a_host_that_is_not_the_configured_one_makes_the_platform_not_ready_and_names_the_reason(
    host: RealHost, tmp_path: Path
) -> None:
    """SEC-125, T3-RED-03: granting work is refused, with a named reason, against a host whose identity does not verify."""
    binding = binding_for(host, host_id="another-host")
    core = await core_over(binding, tmp_path)
    try:
        health = await core.admin.run("health", {})
        assert health["ready"] is False
        assert "host_identity_unverified" in health["not_ready_reasons"]
        assert "another-host" in health["identity_error"]
        # A project cannot even be activated: its scope cannot be shown to be empty on a host nobody verified.
        project = await core.admin.run("project.create", {"label": "unverified"})
        assert project["state"] == "PENDING"
    finally:
        await core.close()
