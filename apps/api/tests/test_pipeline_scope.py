"""Project separation, pipeline order, and the host's verdict.

Proves SVC-1 to SVC-7, SEC-101, SEC-110, SEC-120, SEC-124, INV-102, INV-103, INV-107 and the catalog
entries T3-SEC-01, T3-SEC-12, T3-SVC-01, T3-SVC-02, T3-SVC-03 and T3-RED-08, against the model host.

The host cannot check the owner scope its peer names. Everything in this file exists because the
platform is the only place where one project is kept apart from another.
"""

from __future__ import annotations

import json
import random
from typing import Any

import pytest

from acf_api.command import commands as c
from acf_api.command import model as m
from acf_api.command.answers import ErrorAnswer, ProtocolFaultAnswer, ViewAnswer
from acf_api.core.agent import catalog
from tests.support.harness import Identity, Rig, sandbox_spec


async def _populate(rig: Rig, who: Identity, key: str) -> dict[str, str]:
    """A started sandbox with an execution and a snapshot, and the identifiers of all of it."""
    created = await rig.view(who, c.CreateSandbox(project=who.project_id, spec=sandbox_spec()), key)
    sandbox_id = created["result"]["sandbox"]["sandbox_id"]
    started = await rig.view(
        who, c.StartSandbox(project=who.project_id, sandbox_id=sandbox_id, expected_generation=1), key + ":start"
    )
    spec = m.ExecSpec(expected_generation=1, argv=["true"])
    ran = await rig.view(who, c.Exec(project=who.project_id, sandbox_id=sandbox_id, spec=spec), key + ":exec")
    snap = await rig.view(
        who,
        c.CreateSnapshot(project=who.project_id, sandbox_id=sandbox_id, spec=m.SnapshotSpec(expected_generation=1)),
        key + ":snap",
    )
    return {
        "sandbox_id": sandbox_id,
        "execution_id": ran["target"]["execution_id"],
        "snapshot_id": snap["result"]["snapshot"]["snapshot_id"],
        "operation_id": started["operation_id"],
    }


def _every_command(project: str, ids: dict[str, str]) -> list[tuple[c.Command, str | None]]:
    """One command of every kind that names a record, addressed to ``project`` with the given identifiers."""
    target = m.RestoreInPlace(kind="existing", sandbox_id=ids["sandbox_id"], expected_generation="current")
    restore = m.RestoreSpec(snapshot_generation=1, target=target)
    return [
        (c.GetSandbox(project=project, sandbox=ids["sandbox_id"]), None),
        (c.StartSandbox(project=project, sandbox_id=ids["sandbox_id"], expected_generation="current"), "x-start"),
        (c.StopSandbox(project=project, sandbox_id=ids["sandbox_id"], expected_generation="current"), "x-stop"),
        (c.DestroySandbox(project=project, sandbox_id=ids["sandbox_id"], expected_generation="current"), "x-destroy"),
        (
            c.Exec(
                project=project,
                sandbox_id=ids["sandbox_id"],
                spec=m.ExecSpec(expected_generation="current", argv=["id"]),
            ),
            "x-exec",
        ),
        (
            c.CreateSnapshot(
                project=project, sandbox_id=ids["sandbox_id"], spec=m.SnapshotSpec(expected_generation="current")
            ),
            "x-snap",
        ),
        (c.RestoreSnapshot(project=project, snapshot_id=ids["snapshot_id"], spec=restore), "x-restore"),
        (c.DeleteSnapshot(project=project, snapshot_id=ids["snapshot_id"], snapshot_generation=1), "x-delete"),
        (c.GetExecution(project=project, execution_id=ids["execution_id"]), None),
        (c.GetExecutionOutput(project=project, execution_id=ids["execution_id"]), None),
        (c.CancelExecution(project=project, execution_id=ids["execution_id"]), "x-cancel"),
        (c.GetOperation(project=project, operation_id=ids["operation_id"]), None),
    ]


async def test_a_resource_name_with_another_project_is_not_found(rig: Rig) -> None:
    """SVC-3, SEC-101: the project is taken from the resource name only when the credential is bound to it."""
    mine = await rig.developer("mine")
    theirs = await rig.developer("theirs")
    ids = await _populate(rig, theirs, "t")
    sent_before = len(rig.host.sent)
    for command, key in _every_command(theirs.project_id, ids):
        error = await rig.error(mine, command, key)
        assert (error.code, error.kind) == ("NOT_FOUND", "REFUSED"), command.type
    assert len(rig.host.sent) == sent_before, "a request for another project never reaches the host"


async def test_identifiers_of_another_project_grant_nothing(rig: Rig) -> None:
    """T3-SEC-12, SEC-120: possession of an identifier is not access. Under my own project the record does not exist."""
    mine = await rig.developer("mine")
    theirs = await rig.developer("theirs")
    ids = await _populate(rig, theirs, "t")
    for command, key in _every_command(mine.project_id, ids):
        error = await rig.error(mine, command, key)
        assert (error.code, error.kind) == ("NOT_FOUND", "REFUSED"), command.type
    # Nothing of theirs changed.
    still = await rig.view(theirs, c.GetSandbox(project=theirs.project_id, sandbox=ids["sandbox_id"]))
    assert still["state"] == "COMPLETED"
    listed = await rig.view(mine, c.ListSandboxes(project=mine.project_id))
    assert listed["items"] == []
    assert (await rig.view(mine, c.ListSnapshots(project=mine.project_id)))["items"] == []
    assert (await rig.view(mine, c.ListOperations(project=mine.project_id)))["items"] == []


async def test_identifiers_of_another_project_grant_nothing_through_tools(rig: Rig) -> None:
    """T3-SEC-12 for the agent interface: every tool that names a record."""
    mine = await rig.developer("mine")
    theirs = await rig.developer("theirs")
    ids = await _populate(rig, theirs, "t")
    agent = (await rig.mint_agent(mine))["secret"]
    calls: dict[str, dict[str, Any]] = {
        "sandbox_inspect": {"sandbox": ids["sandbox_id"]},
        "sandbox_start": {"sandbox_id": ids["sandbox_id"]},
        "sandbox_stop": {"sandbox_id": ids["sandbox_id"]},
        "sandbox_destroy": {"sandbox_id": ids["sandbox_id"]},
        "sandbox_exec": {"sandbox_id": ids["sandbox_id"], "argv": ["id"]},
        "sandbox_snapshot": {"sandbox_id": ids["sandbox_id"], "name": "s"},
        "sandbox_restore": {
            "snapshot_id": ids["snapshot_id"],
            "snapshot_generation": 1,
            "target": {"kind": "new", "name": "n"},
        },
        "snapshot_delete": {"snapshot_id": ids["snapshot_id"], "snapshot_generation": 1},
        "exec_status": {"execution_id": ids["execution_id"]},
        "exec_output": {"execution_id": ids["execution_id"]},
        "exec_cancel": {"execution_id": ids["execution_id"]},
        "operation_get": {"operation_id": ids["operation_id"]},
    }
    for name, arguments in calls.items():
        result = await rig.tool(agent, name, arguments)
        assert result.is_error is True, name
        assert result.structured["error"]["code"] == "NOT_FOUND", (name, result.structured)


@pytest.mark.parametrize(
    "member", ["project", "project_id", "owner_scope", "scope", "tenant", "on_behalf_of", "principal_id"]
)
async def test_no_tool_argument_can_name_a_project(rig: Rig, dev: Identity, member: str) -> None:
    """SVC-3: a tool call acts in its credential's project and takes no project argument."""
    other = await rig.developer("other")
    agent = (await rig.mint_agent(dev))["secret"]
    # Setting the other project up made the platform list the host under its scope. Nothing after this may.
    sent = len(rig.host.sent)
    for name, spec in catalog.TOOLS.items():
        answer = await rig.call(agent, c.CallTool(name=name, arguments={member: other.project_id}), interface="mcp")
        assert isinstance(answer, ProtocolFaultAnswer), (name, answer)
        assert answer.fault == "invalid_arguments"
        assert member not in spec.input_model.model_json_schema().get("properties", {})
    assert all(s.owner_scope != other.scope for s in rig.host.sent[sent:])


async def test_no_command_carries_a_scope_or_a_principal() -> None:
    """EC-3, EC-4: the wire types of the command interface have no member an edge could assert an identity with."""
    schema = json.dumps(c.COMMAND_ADAPTER.json_schema())
    for word in ("owner_scope", "principal_id", "on_behalf_of", 'operation_id": {"default', "issued_at", "peer_id"):
        assert word not in schema or word.startswith("operation_id"), word
    for name in ("owner_scope", "principal_id", "on_behalf_of", "issued_at", "peer_id", "scope"):
        assert f'"{name}"' not in schema, name


async def test_every_host_request_carries_the_scope_of_its_credential(rig: Rig) -> None:  # noqa: PLR0912 - one branch per kind of request in the workload
    """T3-SEC-01: a random workload of two projects; each request the host saw is under the right scope and label."""
    one = await rig.developer("one")
    two = await rig.developer("two")
    scope_of = {one.principal_id: one.scope, two.principal_id: two.scope}
    rng = random.Random(20261119)  # a reproducible workload, not a secret
    sandboxes: dict[str, list[str]] = {one.principal_id: [], two.principal_id: []}
    for step in range(120):
        who = rng.choice([one, two])
        other = two if who is one else one
        # A quarter of the requests name the other project, or the other project's sandbox.
        project = other.project_id if rng.random() < 0.15 else who.project_id
        pool = sandboxes[other.principal_id] if rng.random() < 0.15 else sandboxes[who.principal_id]
        action = rng.choice(["create", "list", "get", "start", "exec", "stop", "destroy", "snapshot"])
        key = f"w-{step}"
        if action == "create":
            answer = await rig.call(who, c.CreateSandbox(project=project, spec=sandbox_spec()), key)
            if isinstance(answer, ViewAnswer):
                sandboxes[who.principal_id].append(answer.body["result"]["sandbox"]["sandbox_id"])
            continue
        if action == "list":
            await rig.call(who, c.ListSandboxes(project=project))
            continue
        if not pool:
            continue
        sandbox_id = rng.choice(pool)
        command: c.Command
        if action == "get":
            command = c.GetSandbox(project=project, sandbox=sandbox_id)
        elif action == "start":
            command = c.StartSandbox(project=project, sandbox_id=sandbox_id, expected_generation="current")
        elif action == "exec":
            command = c.Exec(
                project=project, sandbox_id=sandbox_id, spec=m.ExecSpec(expected_generation="current", argv=["id"])
            )
        elif action == "stop":
            command = c.StopSandbox(project=project, sandbox_id=sandbox_id, expected_generation="current")
        elif action == "destroy":
            command = c.DestroySandbox(project=project, sandbox_id=sandbox_id, expected_generation="current")
        else:
            command = c.CreateSnapshot(
                project=project, sandbox_id=sandbox_id, spec=m.SnapshotSpec(expected_generation="current")
            )
        answer = await rig.call(who, command, key)
        if isinstance(answer, ViewAnswer) and isinstance(command, c.GetSandbox):
            assert answer.body["sandbox_id"] in sandboxes[who.principal_id], "a view of another project's sandbox"
    mutating = rig.host.mutating()
    assert len(mutating) > 20, "the workload reached the host"
    for sent in mutating:
        assert sent.on_behalf_of in scope_of
        assert sent.owner_scope == scope_of[sent.on_behalf_of]
    # No record carries the other project's scope: every sandbox of the host belongs to exactly its creator's scope.
    for sandbox in rig.host.sandboxes.values():
        owner = one if sandbox["sandbox_id"] in sandboxes[one.principal_id] else two
        assert sandbox["tags"]["owner_scope"] == owner.scope


async def test_activity_in_one_project_changes_no_answer_to_another(rig: Rig) -> None:
    """T3-RED-08, SEC-124: lists, info and whoami of project Y are the same bytes before and after work in project X."""
    quiet = await rig.developer("quiet")
    busy = await rig.developer("busy")

    async def answers() -> list[dict[str, Any]]:
        return [
            await rig.view(quiet, c.ListSandboxes(project=quiet.project_id)),
            await rig.view(quiet, c.ListSnapshots(project=quiet.project_id)),
            await rig.view(quiet, c.Info()),
            await rig.view(quiet, c.WhoAmI()),
            await rig.view(None, c.Info()),
        ]

    before = await answers()
    await _populate(rig, busy, "b")
    after = await answers()
    for a, b in zip(before, after, strict=True):
        a.pop("next_cursor", None)
        b.pop("next_cursor", None)
        assert a == b
    anonymous = after[-1]
    assert anonymous == {"api_versions": ["v1"], "serving": True}


async def test_nothing_reaches_the_host_without_an_authenticated_credential(rig: Rig, dev: Identity) -> None:
    """T3-SVC-01: missing, malformed, unknown, expired and revoked credentials stop at the first step."""
    sent = len(rig.host.sent)
    expired = await rig.admin("key.issue", principal_id=dev.principal_id, project_id=dev.project_id, lifetime_days=1)
    revoked = await rig.admin("key.issue", principal_id=dev.principal_id, project_id=dev.project_id)
    await rig.admin("key.revoke", credential_id=revoked["credential_id"])
    unknown = dev.key[:-8] + ("A" if dev.key[-8] != "A" else "B") + dev.key[-7:]
    rig.clock.advance(2 * 86400)
    command = c.CreateSandbox(project=dev.project_id, spec=sandbox_spec())
    answers = []
    for credential in (None, "", "not-a-key", unknown, expired["secret"], revoked["secret"], "Bearer " + dev.key):
        answer = await rig.call(credential, command, "k")
        assert isinstance(answer, ErrorAnswer)
        answers.append(
            (answer.error.code, answer.error.kind, answer.error.retry, answer.error.message, answer.error.reason)
        )
    # One opaque answer: nothing tells the caller which check failed.
    assert len(set(answers)) == 1
    assert answers[0][0] == "UNAUTHENTICATED"
    assert len(rig.host.sent) == sent


async def test_a_request_that_fails_a_step_never_reaches_the_next(rig: Rig, dev: Identity) -> None:
    """T3-SVC-01: the order of the checks, pair by pair."""
    other = await rig.developer("other")
    command = c.CreateSandbox(project=dev.project_id, spec=sandbox_spec())
    service = rig.core.service
    # Entitlement precedes the key check: another project is NOT_FOUND even without a key.
    assert (
        await rig.error(dev, c.CreateSandbox(project=other.project_id, spec=sandbox_spec()), None)
    ).code == "NOT_FOUND"
    # Bounds precede readiness: an exhausted rate is RATE_LIMITED although the platform is also not ready.
    service.d.standing.recovered = False
    service._ops.set_project_rate(dev.project_id, 0.0)  # the limiter of this test's project
    while service._ops.admit(dev.project_id, dev.principal_id) is None:  # spend the burst
        pass
    limited = await rig.error(dev, command, "k-1")
    assert (limited.code, limited.kind) == ("RATE_LIMITED", "REFUSED")
    # Readiness precedes the access policy: a request the grant would deny is told "not ready", not "denied".
    service._ops.set_project_rate(dev.project_id, 6000.0)
    denied_later = c.CreateSandbox(
        project=dev.project_id, spec=sandbox_spec(resources={"vcpus": 200, "memory_mib": 512, "disk_mib": 1})
    )
    assert (await rig.error(dev, denied_later, "k-2")).code == "UPSTREAM_UNAVAILABLE"
    service.d.standing.recovered = True
    # The access policy precedes the quota and the claim: a denial leaves no entry and reaches no host.
    sent = len(rig.host.mutating())
    assert (await rig.error(dev, denied_later, "k-2")).code == "PERMISSION_DENIED"
    assert len(rig.host.mutating()) == sent
    assert (await service.d.ledger.counts(0))["claimed"] == 0


async def test_the_host_verdict_is_returned_unchanged(rig: Rig, dev: Identity) -> None:
    """T3-SVC-02, T3-AZ-02, SEC-110: the platform does not refuse on a ceiling it copied, and does not reduce a request."""
    # The grant allows more than the host: the request goes to the host as it was asked, and the host refuses it.
    big = c.CreateSandbox(
        project=dev.project_id, spec=sandbox_spec(resources={"vcpus": 32, "memory_mib": 512, "disk_mib": 1024})
    )
    error = await rig.error(dev, big, "k-big")
    assert (error.code, error.kind, error.retry) == ("SAFETY_CONTROL_DENIED", "REFUSED", "AFTER_CHANGE")
    sent = rig.host.mutating()[-1]
    assert sent.params["resources"]["vcpus"] == 32, "the request was not reduced to fit"
    # An unknown class is carried as unknown, with the host's advice, and is never mapped onto a known one.
    rig.host.refuse_next = ("QUOTA_OF_THE_FUTURE", "SAME_REQUEST_LATER", "later")
    unknown = await rig.error(dev, c.CreateSandbox(project=dev.project_id, spec=sandbox_spec()), "k-unknown")
    assert (unknown.code, unknown.kind, unknown.retry, unknown.code_raw) == (
        "UNRECOGNIZED",
        "REFUSED",
        "SAME_REQUEST_LATER",
        "QUOTA_OF_THE_FUTURE",
    )


async def test_reads_always_reach_the_host(rig: Rig, dev: Identity) -> None:
    """T3-SVC-03, INV-107: a state changed directly on the host is visible on the next public read."""
    created = await rig.view(dev, c.CreateSandbox(project=dev.project_id, spec=sandbox_spec()), "k")
    sandbox_id = created["result"]["sandbox"]["sandbox_id"]
    assert (await rig.view(dev, c.GetSandbox(project=dev.project_id, sandbox=sandbox_id)))["state"] == "PROVISIONING"
    rig.host.sandboxes[sandbox_id]["state"] = "FAILED"
    assert (await rig.view(dev, c.GetSandbox(project=dev.project_id, sandbox=sandbox_id)))["state"] == "FAILED"
    listed = await rig.view(dev, c.ListSandboxes(project=dev.project_id))
    assert [s["state"] for s in listed["items"]] == ["FAILED"]
    # A value nobody knows is shown as unknown, with the raw value beside it.
    rig.host.sandboxes[sandbox_id]["state"] = "HIBERNATING"
    odd = await rig.view(dev, c.GetSandbox(project=dev.project_id, sandbox=sandbox_id))
    assert (odd["state"], odd["state_raw"]) == ("UNRECOGNIZED", "HIBERNATING")


async def test_no_view_shows_a_field_of_the_host_or_of_its_backend(rig: Rig, dev: Identity) -> None:
    """PUB-3: no process identity, profile id, kernel or root filesystem identity, tags or peer id crosses."""
    ids = await _populate(rig, dev, "p")
    views = [
        await rig.view(dev, c.GetSandbox(project=dev.project_id, sandbox=ids["sandbox_id"])),
        await rig.view(dev, c.ListSnapshots(project=dev.project_id)),
        await rig.view(dev, c.ListOperations(project=dev.project_id)),
        await rig.view(dev, c.GetExecution(project=dev.project_id, execution_id=ids["execution_id"])),
        await rig.view(dev, c.Info()),
    ]
    text = json.dumps(views)
    for word in (
        "process",
        "boot_id",
        "security_profile_id",
        "kernel_identity",
        "rootfs_identity",
        "profile_id",
        "peer_id",
        "owner_scope",
        "tags",
        "platform-peer",
        dev.scope,
        "host-model",
        "lineage-1",
    ):
        assert word not in text, word
