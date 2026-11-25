"""Guarantees that hold across interfaces, across interleavings and across a bad day of a dependency.

Each test here is the whole core over the model host. Together they prove the catalog entries
T3-LRO-02, T3-LRO-04, T3-MCP-03, T3-CONC-01, T3-IPS-01, T3-RED-22, T3-RED-23, T3-RED-34 and T3-RED-45 at the level of the
running pipeline: what a caller is told and what the host was asked, never how the code got there.
"""

from __future__ import annotations

import asyncio
import random
from pathlib import Path
from typing import Any

import pytest

from acf_api.command import commands as c
from acf_api.command.answers import Answer, ErrorAnswer, ToolAnswer, ViewAnswer
from acf_api.core.pipeline import derivation
from acf_api.core.policy import authorizer as az
from tests.support.harness import DEPLOYMENT, Identity, Rig, build_rig, sandbox_spec
from tests.support.model_host import Crash, ModelHost

RESOURCES = {"vcpus": 1, "memory_mib": 512, "disk_mib": 1024}


def create(dev: Identity, **spec: Any) -> c.CreateSandbox:
    return c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(**spec))


async def started(rig: Rig, dev: Identity, key: str = "k-setup") -> str:
    created = await rig.view(dev, create(dev), key)
    sandbox_id = str(created["result"]["sandbox"]["sandbox_id"])
    await rig.view(
        dev, c.StartSandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation=1), key + ":start"
    )
    return sandbox_id


def creates(rig: Rig) -> list[Any]:
    return [sent for sent in rig.host.mutating() if sent.method == "sandbox.create"]


# ------------------------------------------------------------------------------------ unknown stays unknown
async def test_an_execution_that_ended_unknown_is_unknown_on_rest_and_on_the_agent_interface(
    rig: Rig, dev: Identity
) -> None:
    """T3-LRO-02, ERR-3, INV-106: UNKNOWN is reported as UNKNOWN. It is never success and never a clean failure."""
    sandbox_id = await started(rig, dev)
    agent = (await rig.mint_agent(dev))["secret"]
    rig.host.hold.add("exec.run")
    call = {"sandbox_id": sandbox_id, "argv": ["sleep", "600"]}
    running = await rig.tool(agent, "sandbox_exec", call)
    operation_id = running.structured["operation"]["operation_id"]
    assert running.structured["operation"]["terminal"] is False
    # The host restarted under the run and cannot say what became of it.
    rig.host.finish(operation_id, "UNKNOWN", effect="MAY_BE_APPLIED")

    over_rest = await rig.view(dev, c.GetOperation(project=dev.project_id, operation_id=operation_id))
    assert (over_rest["state"], over_rest["terminal"], over_rest["effect"]) == ("UNKNOWN", True, "MAY_BE_APPLIED")
    assert over_rest.get("failure") is None, "nothing is invented to make an unknown outcome look like a failure"

    read_by_agent = await rig.tool(agent, "operation_get", {"operation_id": operation_id})
    assert read_by_agent.is_error is False, "the read succeeded; what it shows is an unknown outcome"
    assert read_by_agent.structured["operation"]["state"] == "UNKNOWN"

    # The first result never reached the agent, so the same call again is the same call: it is answered
    # with the one operation, and an operation that ended UNKNOWN is not a success.
    again = await rig.tool(agent, "sandbox_exec", call)
    assert again.structured["operation"]["operation_id"] == operation_id
    assert again.structured["operation"]["state"] == "UNKNOWN"
    assert (again.is_error, again.structured["ok"]) == (True, False)
    assert len([sent for sent in rig.host.mutating() if sent.method == "exec.run"]) == 1


# ---------------------------------------------------------------------------- one request, one operation
async def test_one_public_request_is_one_host_operation_and_a_create_starts_nothing(rig: Rig, dev: Identity) -> None:
    """T3-LRO-04, LRO-10: create and start are two operations, and no request ever becomes two on the host."""
    before = len(rig.host.mutating())
    created = await rig.view(dev, create(dev, name="two-steps"), "k")
    sandbox_id = created["result"]["sandbox"]["sandbox_id"]
    assert [sent.method for sent in rig.host.mutating()[before:]] == ["sandbox.create"]
    assert created["result"]["sandbox"]["state"] == "PROVISIONING", "created, and not started by the platform"

    # Both at once is something only a host can offer. This one does not, so it is refused and nothing is sent:
    # the platform does not make two host operations out of one request.
    both = await rig.error(dev, create(dev, name="both", start=True), "k-both")
    assert (both.code, both.kind) == ("UNSUPPORTED", "REFUSED")
    assert len(rig.host.mutating()) == before + 1

    start = c.StartSandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation=1)
    assert (await rig.view(dev, start, "k:start"))["result"]["sandbox"]["state"] == "READY"
    assert [sent.method for sent in rig.host.mutating()[before:]] == ["sandbox.create", "sandbox.start"]


# ------------------------------------------------------------------------------- the same on both interfaces
NARROW = {
    "schema_version": 1,
    "methods": ["sandbox.create", "sandbox.get", "sandbox.list", "operation.get", "platform.info", "auth.whoami"],
    "images": ["python"],
    "network": {"modes": ["none"], "destinations": []},
    "ceilings": {
        "vcpus": 1,
        "memory_mib": 512,
        "disk_mib": 1024,
        "execution_timeout_seconds": 60,
        "sandbox_lifetime_seconds": 600,
    },
}
ALLOWLIST = {"mode": "allowlist", "entries": [{"name": "packages.example", "ports": [{"from": 443, "to": 443}]}]}
NOBODYS = "sbx-" + "0" * 32


def _scenarios() -> list[tuple[str, dict[str, Any]]]:
    """What is asked, once. Each interface gets a name of its own, so that the two runs do not meet."""
    inside = {"image": "python", "resources": RESOURCES, "lifetime_seconds": 300}
    return [
        ("a request inside the grant", inside),
        ("an image the grant does not list", {**inside, "image": "node"}),
        ("more processors than the grant's ceiling", {**inside, "resources": {**RESOURCES, "vcpus": 2}}),
        ("more memory than the grant's ceiling", {**inside, "resources": {**RESOURCES, "memory_mib": 1024}}),
        ("a network the grant does not allow", {**inside, "network": ALLOWLIST}),
        ("a lifetime above the grant's ceiling", {**inside, "lifetime_seconds": 3600}),
        # The grant's ceiling is below the host's default, and the platform does not shorten a request to fit.
        ("no lifetime named, so the host's default applies", {"image": "python", "resources": RESOURCES}),
    ]


def _outcome(answer: Answer) -> tuple[str, ...]:
    """What a caller was told, in the words both interfaces share."""
    if isinstance(answer, ViewAnswer):
        return ("allowed",)
    if isinstance(answer, ErrorAnswer):
        return (answer.error.code, answer.error.kind, answer.error.reason or "")
    assert isinstance(answer, ToolAnswer), answer
    if not answer.is_error:
        return ("allowed",)
    error = answer.structured["error"]
    return (error["code"], error["kind"], error.get("reason") or "")


async def test_what_rest_allows_or_refuses_the_agent_interface_allows_or_refuses_for_the_same_reason(
    rig: Rig, dev: Identity
) -> None:
    """T3-MCP-03, INV-115: one access policy, asked the same question whichever interface carried it."""
    agent = (await rig.mint_agent(dev, narrowing=NARROW))["secret"]
    seen: set[tuple[str, ...]] = set()
    for number, (what, spec) in enumerate(_scenarios()):
        over_rest = await rig.call(agent, create(dev, name=f"rest-{number}", **spec), f"rest-{number}")
        as_a_tool = await rig.call(
            agent, c.CallTool(name="sandbox_create", arguments={"name": f"tool-{number}", **spec}), interface="mcp"
        )
        assert _outcome(over_rest) == _outcome(as_a_tool), what
        seen.add(_outcome(over_rest))
    assert ("allowed",) in seen
    assert len(seen) >= 4, f"the scenarios were meant to meet several different rules, and met {sorted(seen)}"

    # A method the grant leaves out, and a record that is nobody's.
    rest = await rig.call(agent, c.ListSnapshots(project=dev.project_id))
    tool = await rig.call(agent, c.CallTool(name="snapshot_list"), interface="mcp")
    assert _outcome(rest) == _outcome(tool) == ("PERMISSION_DENIED", "REFUSED", az.R_METHOD)
    rest = await rig.call(agent, c.GetSandbox(project=dev.project_id, sandbox=NOBODYS))
    tool = await rig.call(agent, c.CallTool(name="sandbox_inspect", arguments={"sandbox": NOBODYS}), interface="mcp")
    assert _outcome(rest)[:2] == _outcome(tool)[:2] == ("NOT_FOUND", "REFUSED")


# ---------------------------------------------------------------------------------- any order, one outcome
@pytest.mark.parametrize("seed", range(6))
async def test_random_interleavings_make_one_host_operation_for_each_key(tmp_path: Path, seed: int) -> None:
    """T3-CONC-01, CC3-6: whatever the order of arrival, one key is one operation and every answer agrees."""
    # Room enough that the only bound this schedule can meet is the one under test: the key.
    rig = await build_rig(
        tmp_path,
        host=ModelHost(max_sandboxes=64),
        principal_max_in_flight=200,
        project_max_in_flight=200,
        project_max_live_sandboxes=50,
        host_ops_allowance=600_000,
    )
    try:
        dev = await rig.developer()
        order = random.Random(seed)  # a reproducible schedule, not a secret
        keys = [f"key-{seed}-{number}" for number in range(6)]
        # Most requests of a key are the same request; a few carry another body under the same key.
        requests = [(key, "same") for key in keys for _ in range(5)] + [(key, "other") for key in keys[:3]]
        order.shuffle(requests)
        gate = rig.host.block("sandbox.create")

        async def ask(key: str, body: str, pause: float) -> tuple[str, str, Answer]:
            await asyncio.sleep(pause)
            name = f"box-{key}" if body == "same" else f"other-{key}"
            return key, body, await rig.call(dev, create(dev, name=name), key)

        tasks = [asyncio.create_task(ask(key, body, order.uniform(0, 0.03))) for key, body in requests]
        await asyncio.sleep(order.uniform(0.005, 0.04))
        gate.set()
        answers = await asyncio.gather(*tasks)

        operations: dict[str, set[str]] = {key: set() for key in keys}
        bodies: dict[str, set[str]] = {key: set() for key in keys}
        for key, body, answer in answers:
            if isinstance(answer, ViewAnswer):
                operations[key].add(answer.body["operation_id"])
                bodies[key].add(body)
            else:
                assert isinstance(answer, ErrorAnswer)
                # Two answers are possible for a request that did not get the operation: it is still being
                # decided, or the key belongs to a different request. Neither is a refusal by inference.
                assert answer.error.code in {"REQUEST_IN_PROGRESS", "IDEMPOTENCY_CONFLICT"}, answer.error
        for key in keys:
            assert len(operations[key]) == 1, f"{key} was answered with {len(operations[key])} operations"
            assert len(bodies[key]) == 1, f"two different requests were accepted under {key}"
        sent = [call.operation_id for call in creates(rig)]
        assert sorted(sent) == sorted(next(iter(found)) for found in operations.values()), (
            "one submission for each key, and no other"
        )
        # Asked again in peace, every key answers with its operation, as a replay.
        for key in keys:
            name = f"box-{key}" if bodies[key] == {"same"} else f"other-{key}"
            later = await rig.view(dev, create(dev, name=name), key)
            assert {later["operation_id"]} == operations[key]
            assert later["replayed"] is True
        assert len(creates(rig)) == len(keys)
    finally:
        await rig.close()


# --------------------------------------------------------------------- a key outlives the way ids are derived
def _derived(dev: Identity, key: str, version: str) -> str:
    return derivation.derive_operation_id(
        deployment_id=DEPLOYMENT,
        project_id=dev.project_id,
        principal_id=dev.principal_id,
        step="sandbox.create",
        key=key,
        version=version,
    )


async def test_a_key_accepted_before_a_change_of_derivation_never_becomes_a_second_operation(
    rig: Rig, dev: Identity, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T3-RED-22, T3-VER-03, VER-13: an earlier version's id is read on the host before a first submission.

    Three ways a key can meet a release that derives operation ids differently: the ledger still holds
    its entry; the ledger has forgotten it and the host has not; nobody has ever seen it. In none of them
    does one key become two host operations, and where the host cannot be asked nothing is sent at all.
    """
    key = "key-across-versions"
    first = await rig.view(dev, create(dev, name="kept"), key)
    assert first["replayed"] is False
    assert first["operation_id"] == _derived(dev, key, "1") != _derived(dev, key, "2")

    # A later release derives ids in another way, and names this one as an earlier version.
    monkeypatch.setattr(derivation, "DERIVATION_VERSION", "2")
    monkeypatch.setattr(derivation, "PREVIOUS_VERSIONS", ("1",))
    rig = await rig.restart()
    try:
        ledger = rig.core.service.d.ledger
        # The ledger holds the entry: a resolution. It keeps the id it was claimed with, and nothing is derived.
        again = await rig.view(dev, create(dev, name="kept"), key)
        assert (again["operation_id"], again["replayed"]) == (first["operation_id"], True)
        assert len(creates(rig)) == 1

        # The ledger has forgotten the entry, as a store does that was restored to an earlier state.
        await ledger._store.state(lambda conn: conn.execute("DELETE FROM entries").rowcount, write=True)
        mark = len(rig.host.sent)
        found = await rig.view(dev, create(dev, name="kept"), key)
        assert (found["operation_id"], found["replayed"]) == (first["operation_id"], True)
        assert len(creates(rig)) == 1, "the host held the operation under the earlier id: nothing was sent again"
        asked = [sent.params["operation_id"] for sent in rig.host.sent[mark:] if sent.method == "operation.get"]
        assert asked[0] == _derived(dev, key, "1")
        recorded = await ledger._store.state(
            lambda conn: [
                tuple(row) for row in conn.execute("SELECT operation_id, derivation_version, state FROM entries")
            ]
        )
        assert recorded == [(first["operation_id"], "1", "BOUND")], "the entry says how its id was derived"

        # A key nobody has seen: its earlier id is asked for first, and it is submitted under the id of today.
        mark = len(rig.host.sent)
        fresh = await rig.view(dev, create(dev, name="new"), "key-of-the-later-version")
        methods = [sent.method for sent in rig.host.sent[mark:]]
        assert methods.index("operation.get") < methods.index("sandbox.create")
        assert fresh["operation_id"] == _derived(dev, "key-of-the-later-version", "2")
        assert fresh["replayed"] is False
        assert len(creates(rig)) == 2

        # A host that cannot be asked about the earlier id: the request is refused, unclaimed and unsent.
        rig.host.fault("unreachable", "operation.get", times=50)
        refused = await rig.error(dev, create(dev, name="later"), "key-while-the-host-is-away")
        assert (refused.code, refused.kind, refused.retry) == ("UPSTREAM_UNAVAILABLE", "REFUSED", "SAME_REQUEST_LATER")
        assert len(creates(rig)) == 2
        assert await ledger.claimed() == []
        rig.host.faults.clear()
        assert (await rig.view(dev, create(dev, name="later"), "key-while-the-host-is-away"))["replayed"] is False
        assert len(creates(rig)) == 3
    finally:
        await rig.close()


async def test_with_no_earlier_derivation_nothing_is_read_before_a_submission(rig: Rig, dev: Identity) -> None:
    """VER-13 costs nothing while there is one version: the list of earlier ones is empty."""
    assert derivation.PREVIOUS_VERSIONS == ()
    await rig.view(dev, create(dev, name="only"), "key-of-the-only-version")
    assert [sent.method for sent in rig.host.sent if sent.method == "operation.get"] == []


# ----------------------------------------------------------------- one request, whoever carries it
async def test_a_request_repeated_by_another_client_is_the_same_operation_and_no_digest_crosses_deployments(
    rig: Rig, dev: Identity, tmp_path: Path
) -> None:
    """T3-RED-23, IDM-4: the key and the request decide, not the program that sent them; digests are keyed per deployment."""
    command = create(dev, name="shared")
    from_the_sdk = await rig.view(dev, command, "key-shared")
    # The same developer repeats the request from another program: the same key, the same request.
    ctx = rig.ctx()
    ctx = ctx.model_copy(
        update={"client": ctx.client.model_copy(update={"name": "acf", "version": "9.9"})} if ctx.client else {}
    )
    from_the_cli = await rig.core.service.handle(dev.key, ctx, command, "key-shared")
    assert isinstance(from_the_cli, ViewAnswer)
    assert from_the_cli.body["operation_id"] == from_the_sdk["operation_id"]
    assert from_the_cli.body["replayed"] is True
    assert len(creates(rig)) == 1

    # Another deployment has another fingerprint key: the same key and the same request leave other digests,
    # so a digest read in one deployment says nothing about a request in another.
    other = await build_rig(tmp_path / "another-deployment")
    try:
        here, there = rig.core.service.d.fingerprint, other.core.service.d.fingerprint
        assert here.key_digest("key-shared") != there.key_digest("key-shared")
        assert here.fingerprint("sandbox.create", command) != there.fingerprint("sandbox.create", command)
        assert here.fingerprint("sandbox.create", command) == here.fingerprint(
            "sandbox.create", create(dev, name="shared")
        )
    finally:
        await other.close()


# --------------------------------------------------------------------------- a bad day of the access policy
class Moody:
    """An access policy that can be told to fail or to take its time. Until then it is the shipped one."""

    def __init__(self) -> None:
        self.mood = "fine"
        self.asked = 0
        self._shipped = az.GrantAuthorizer()

    async def decide(self, subject: az.Subject, request: az.PolicyRequest, limits: az.HostLimits | None) -> az.Decision:
        self.asked += 1
        if self.mood == "failing":
            msg = "the policy backend is down"
            raise RuntimeError(msg)
        if self.mood == "slow":
            await asyncio.sleep(30)
        return await self._shipped.decide(subject, request, limits)


@pytest.mark.parametrize("mood", ["failing", "slow"])
async def test_with_a_failing_or_a_slow_access_policy_new_work_is_refused_and_containment_passes(
    tmp_path: Path, mood: str
) -> None:
    """T3-RED-45, EVO-2, AZ-9: no decision is a refusal with nothing sent, and stopping never needs a decision."""
    policy = Moody()
    rig = await build_rig(tmp_path, authorizer=policy)
    try:
        dev = await rig.developer()
        sandbox_id = await started(rig, dev)
        sent_before = len(rig.host.mutating())
        asked_before = policy.asked
        policy.mood = mood

        # The caller's budget leaves the decision a fifth of a second: the default margin of the edge is two.
        answer = await asyncio.wait_for(rig.call(dev, create(dev, name="not-today"), "k-new", budget_s=2.2), 5)
        assert isinstance(answer, ErrorAnswer)
        assert (answer.error.code, answer.error.kind, answer.error.retry) == (
            "UPSTREAM_UNAVAILABLE",
            "REFUSED",
            "SAME_REQUEST_LATER",
        )
        assert policy.asked == asked_before + 1
        assert len(rig.host.mutating()) == sent_before, "nothing was sent, and nothing was claimed"

        # Containment asks nobody: the grant allows the method, or it does not.
        stop = c.StopSandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation=1)
        assert (await asyncio.wait_for(rig.view(dev, stop, "k-stop", budget_s=2.2), 5))["state"] == "SUCCEEDED"
        destroy = c.DestroySandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation="current")
        assert (await asyncio.wait_for(rig.view(dev, destroy, "k-destroy", budget_s=2.2), 5))["state"] == "SUCCEEDED"
        assert policy.asked == asked_before + 1, "containment never came to the policy"

        # When the policy is itself again, the same key is a fresh attempt: the refusal left nothing behind.
        policy.mood = "fine"
        assert (await rig.view(dev, create(dev, name="not-today"), "k-new"))["replayed"] is False
    finally:
        await rig.close()


# ------------------------------------------------------------------------------- dying at the last step
async def test_a_core_that_dies_between_a_refusal_and_the_release_leaves_a_key_that_still_works(
    rig: Rig, dev: Identity, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T3-IPS-01, REC3-5: a crash during the release. The claim stays, and the next start proves it empty."""
    rig.host.allowed_images = ["python"]
    refused_by_the_host = create(dev, name="not-here", image="node")

    async def dies(_entry_id: int) -> None:
        raise Crash

    with monkeypatch.context() as patched:
        patched.setattr(rig.core.service.d.ledger, "release", dies)
        with pytest.raises(Crash):
            await rig.call(dev, refused_by_the_host, "k-refused")
    assert len(await rig.core.service.d.ledger.claimed()) == 1, "the host refused, and the claim was never released"
    assert creates(rig)[-1].operation_id is not None

    rig = await rig.restart()
    try:
        # The first pass of the new process read the host, found nothing, and could prove that nothing was ever there.
        assert await rig.core.service.d.ledger.claimed() == []
        # So the key is free. With the same request it is refused by the host again, as a request of its own,
        refused = await rig.error(dev, refused_by_the_host, "k-refused")
        assert (refused.code, refused.kind) == ("SAFETY_CONTROL_DENIED", "REFUSED")
        # and once the host allows the image, the same key and the same request are new work that succeeds.
        rig.host.allowed_images = None
        accepted = await rig.view(dev, refused_by_the_host, "k-refused")
        assert (accepted["state"], accepted["replayed"]) == ("SUCCEEDED", False)
        assert len([s for s in rig.host.sandboxes.values() if s.get("name") == "not-here"]) == 1
    finally:
        await rig.close()


# ------------------------------------------------------------------------------------- stopping under load
async def test_a_stop_under_load_refuses_what_arrives_and_leaves_no_claim_behind(tmp_path: Path) -> None:
    """T3-RED-34, IPS-15: what is in flight when the stop arrives finishes or reaches the host; nothing stays CLAIMED.

    The other half of the entry, that a store is never migrated while requests are served, is a property
    of the store alone and is proven with it (test_unit_store.py).
    """
    rig = await build_rig(
        tmp_path,
        host=ModelHost(max_sandboxes=64),
        principal_max_in_flight=100,
        project_max_in_flight=100,
        project_max_live_sandboxes=50,
        host_ops_allowance=600_000,
        drain_timeout=10.0,
    )
    try:
        dev = await rig.developer()
        gate = rig.host.block("sandbox.create")
        load = [asyncio.create_task(rig.call(dev, create(dev, name=f"load-{n}"), f"load-{n}")) for n in range(12)]
        await asyncio.sleep(0.1)
        draining = asyncio.create_task(rig.core.service.drain())
        await asyncio.sleep(0.02)
        assert not draining.done(), "the stop waits for the requests in flight"
        late = await rig.error(dev, create(dev, name="too-late"), "too-late")
        assert (late.code, late.kind, late.retry) == ("UPSTREAM_UNAVAILABLE", "REFUSED", "SAME_REQUEST_LATER")
        gate.set()
        assert await asyncio.wait_for(draining, 10) is True, "everything in flight ended inside the drain timeout"
        answers = await asyncio.gather(*load)
        assert all(isinstance(answer, ViewAnswer) and answer.body["state"] == "SUCCEEDED" for answer in answers)
        assert len(creates(rig)) == len(load), "the request that arrived during the stop was never sent"
    finally:
        rig = await rig.restart()
    try:
        assert await rig.core.service.d.ledger.claimed() == []
        dev = rig.identities[0]
        # The key that was refused during the stop is new work for the next process.
        assert (await rig.view(dev, create(dev, name="too-late"), "too-late"))["replayed"] is False
    finally:
        await rig.close()
