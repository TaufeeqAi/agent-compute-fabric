"""The containment lane, the bounds on granting work, quotas, and the follower.

Proves SVC-8 to SVC-10, CC3-2 to CC3-5, CC3-7, CC3-8, LRO-1 to LRO-5, LRO-9, HB-7, IDM-12, INV-116,
INV-119, INV-125 and the catalog entries T3-SEC-11, T3-RED-31, T3-RED-36, T3-RED-37, T3-LRO-01,
T3-LRO-03 and T3-LRO-05, against the model host.

Containment (stop, destroy, cancel, delete) removes privilege. It is never refused for load, never
waits for the platform's readiness, and does not need the ledger.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest

from acf_api.command import commands as c
from acf_api.command import model as m
from acf_api.command.answers import ErrorAnswer, ViewAnswer
from acf_api.core.host.binding import Lane
from acf_api.core.store.engine import StoreUnavailable
from tests.support.harness import Identity, Rig, build_rig, sandbox_spec
from tests.support.model_host import ModelHost


async def _running(rig: Rig, dev: Identity, key: str = "setup") -> str:
    created = await rig.view(dev, c.CreateSandbox(project=dev.project_id, spec=sandbox_spec()), key)
    sandbox_id = str(created["result"]["sandbox"]["sandbox_id"])
    await rig.view(
        dev, c.StartSandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation=1), key + ":start"
    )
    return sandbox_id


def _exhaust_bounds(rig: Rig, dev: Identity) -> None:
    """Spend the rate of the project and fill the in-flight bounds of the principal."""
    service = rig.core.service
    service._ops.set_project_rate(dev.project_id, 0.0)
    while service._ops.admit(dev.project_id, dev.principal_id) is None:
        pass
    while service._in_flight.enter(dev.project_id, dev.principal_id) is None:
        pass


async def test_containment_passes_with_every_limit_saturated_and_the_platform_not_ready(
    rig: Rig, dev: Identity
) -> None:
    """T3-RED-36, T3-SEC-11: rate, in-flight and readiness refuse granting work and let containment through."""
    one, two = await _running(rig, dev, "a"), await _running(rig, dev, "b")
    rig.host.hold.add("exec.run")
    spec = m.ExecSpec(expected_generation=1, argv=["sleep", "600"])
    running = await rig.view(dev, c.Exec(project=dev.project_id, sandbox_id=one, spec=spec, wait=0), "exec")
    _exhaust_bounds(rig, dev)
    rig.core.service.d.standing.recovered = False

    refused = await rig.error(dev, c.CreateSandbox(project=dev.project_id, spec=sandbox_spec()), "new")
    assert refused.code == "RATE_LIMITED"

    cancelled = await rig.view(
        dev, c.CancelExecution(project=dev.project_id, execution_id=running["target"]["execution_id"]), "cancel"
    )
    assert cancelled["type"] == "execution.cancel"
    stopped = await rig.view(
        dev, c.StopSandbox(project=dev.project_id, sandbox_id=one, expected_generation="current"), "stop"
    )
    assert stopped["result"]["sandbox"]["state"] == "STOPPED"
    destroyed = await rig.view(
        dev, c.DestroySandbox(project=dev.project_id, sandbox_id=two, expected_generation=1), "destroy"
    )
    assert destroyed["result"]["sandbox"]["state"] == "DESTROYED"
    # Containment used the connections kept for it, for its reads as well as for its submissions.
    lanes = {s.lane for s in rig.host.sent if s.method in {"sandbox.stop", "sandbox.destroy", "operation.cancel"}}
    assert lanes == {Lane.CONTAINMENT}


async def test_containment_proceeds_while_the_store_is_offline(rig: Rig, dev: Identity) -> None:
    """T3-RED-36, IDM-12, INV-125: no registry, no ledger, no audit: the request is sent anyway."""
    sandbox_id = await _running(rig, dev)
    # The credential authenticated moments ago. Now the store stops answering.
    rig.core.store.usable = False
    with pytest.raises(StoreUnavailable):
        await rig.core.service.d.ledger.counts(0)

    granting = await rig.error(dev, c.CreateSandbox(project=dev.project_id, spec=sandbox_spec()), "new")
    assert (granting.code, granting.kind) == ("UPSTREAM_UNAVAILABLE", "REFUSED")
    reading = await rig.error(dev, c.ListSandboxes(project=dev.project_id))
    assert reading.code == "UPSTREAM_UNAVAILABLE"

    destroyed = await rig.view(
        dev, c.DestroySandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation="current"), "destroy"
    )
    assert destroyed["result"]["sandbox"]["state"] == "DESTROYED"
    assert rig.core.telemetry.get("auth_from_containment_cache") >= 1
    # The host operation id is still the derived one, so a repeat of the request is deduplicated by the host.
    again = await rig.view(
        dev, c.DestroySandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation="current"), "destroy"
    )
    assert again["operation_id"] == destroyed["operation_id"]
    assert len({s.operation_id for s in rig.host.mutating() if s.method == "sandbox.destroy"}) == 1


async def test_the_containment_cache_honours_only_a_recent_authentication(rig: Rig, dev: Identity) -> None:
    """SVC-10: a credential the core has not seen recently is not admitted from memory."""
    sandbox_id = await _running(rig, dev)
    stranger = await rig.admin("key.issue", principal_id=dev.principal_id, project_id=dev.project_id)
    rig.core.store.usable = False
    destroy = c.DestroySandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation="current")
    # Never authenticated before: nothing to remember.
    assert (await rig.error(stranger["secret"], destroy, "d-1")).code == "UPSTREAM_UNAVAILABLE"
    # Authenticated before, and the memory of it has aged out.
    rig.clock.advance(rig.config.parameters.containment_auth_cache_ttl + 1)
    assert (await rig.error(dev, destroy, "d-2")).code == "UPSTREAM_UNAVAILABLE"
    assert all(s.method != "sandbox.destroy" for s in rig.host.mutating())


async def test_a_revoked_credential_is_forgotten_by_the_containment_cache_at_once(rig: Rig, dev: Identity) -> None:
    """CRD-6: the cache stops honouring a revoked credential."""
    sandbox_id = await _running(rig, dev)
    await rig.admin("key.revoke", credential_id=dev.credential_id)
    rig.core.store.usable = False
    destroy = c.DestroySandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation="current")
    assert (await rig.error(dev, destroy, "d")).code == "UPSTREAM_UNAVAILABLE"


async def test_containment_is_decided_by_a_local_rule(rig: Rig) -> None:
    """AZ-9: the grant allows the method, or it does not. No read of the host is needed to say so."""
    grants = {
        "schema_version": 1,
        "methods": ["sandbox.create", "sandbox.start", "sandbox.get"],
        "images": ["*"],
        "network": {"modes": ["none"], "destinations": []},
        "ceilings": {
            "vcpus": 2,
            "memory_mib": 1024,
            "disk_mib": 2048,
            "execution_timeout_seconds": 60,
            "sandbox_lifetime_seconds": 3600,
        },
    }
    dev = await rig.developer("narrow", grants=grants)
    sandbox_id = await _running(rig, dev)
    sent = len(rig.host.sent)
    error = await rig.error(
        dev, c.DestroySandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation="current"), "d"
    )
    assert (error.code, error.reason) == ("PERMISSION_DENIED", "method")
    assert len(rig.host.sent) == sent


async def test_a_destroy_that_states_current_wins_a_race_with_a_restore(rig: Rig, dev: Identity) -> None:
    """T3-RED-36, SVC-10, CC3-3: the conflict proved nothing existed, so the core reads again and sends again."""
    sandbox_id = await _running(rig, dev)
    rig.host.refuse_next = ("REVISION_CONFLICT", "AFTER_CHANGE", "the sandbox is at another generation")
    answer = await rig.call(
        dev, c.DestroySandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation="current"), "d"
    )
    assert isinstance(answer, ViewAnswer), getattr(answer, "error", None)
    assert answer.body["result"]["sandbox"]["state"] == "DESTROYED"
    assert rig.core.telemetry.get("containment_generation_retries") == 1


async def test_a_destroy_that_states_a_generation_gets_the_conflict(rig: Rig, dev: Identity) -> None:
    """CC3-3: with an integer the request acts on that generation or is refused."""
    sandbox_id = await _running(rig, dev)
    error = await rig.error(
        dev, c.DestroySandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation=7), "d"
    )
    assert (error.code, error.kind, error.retry) == ("REVISION_CONFLICT", "REFUSED", "AFTER_CHANGE")
    assert rig.host.sandboxes[sandbox_id]["state"] == "READY"


async def test_granting_work_that_states_current_gets_the_conflict(rig: Rig, dev: Identity) -> None:
    """CC3-3: for granting work a restore that lands in between yields the conflict, never an action on the wrong generation."""
    sandbox_id = await _running(rig, dev)
    rig.host.refuse_next = ("REVISION_CONFLICT", "AFTER_CHANGE", "the sandbox is at another generation")
    spec = m.ExecSpec(expected_generation="current", argv=["id"])
    error = await rig.error(dev, c.Exec(project=dev.project_id, sandbox_id=sandbox_id, spec=spec), "e")
    assert error.code == "REVISION_CONFLICT"


async def test_a_second_execution_in_one_sandbox_is_refused_by_the_host(rig: Rig, dev: Identity) -> None:
    """CC3-2: the platform does not queue executions."""
    sandbox_id = await _running(rig, dev)
    rig.host.hold.add("exec.run")
    spec = m.ExecSpec(expected_generation=1, argv=["sleep", "600"])
    await rig.view(dev, c.Exec(project=dev.project_id, sandbox_id=sandbox_id, spec=spec, wait=0), "first")
    error = await rig.error(dev, c.Exec(project=dev.project_id, sandbox_id=sandbox_id, spec=spec, wait=0), "second")
    assert (error.code, error.kind) == ("STATE_CONFLICT", "REFUSED")


async def test_containment_preempts_a_running_execution(rig: Rig, dev: Identity) -> None:
    """CC3-4: the preempted execution is reported as cancelled, superseded."""
    sandbox_id = await _running(rig, dev)
    rig.host.hold.add("exec.run")
    spec = m.ExecSpec(expected_generation=1, argv=["sleep", "600"])
    running = await rig.view(dev, c.Exec(project=dev.project_id, sandbox_id=sandbox_id, spec=spec, wait=0), "e")
    await rig.view(
        dev, c.DestroySandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation="current"), "d"
    )
    ended = await rig.view(dev, c.GetOperation(project=dev.project_id, operation_id=running["operation_id"]))
    assert (ended["state"], ended["cancelled_by"]) == ("CANCELLED", "SUPERSEDED")
    assert ended["effect"] == "MAY_BE_APPLIED"


# ------------------------------------------------------------------------------- bounds on granting work
async def test_requests_in_flight_are_bounded_per_principal(tmp_path: Any) -> None:
    """T3-SEC-11, CC3-5: the bound holds before anything is sent to the host."""
    rig = await build_rig(tmp_path, principal_max_in_flight=3, project_max_in_flight=8, project_max_live_sandboxes=8)
    try:
        dev = await rig.developer()
        sandboxes = []
        for i in range(6):
            created = await rig.view(dev, c.CreateSandbox(project=dev.project_id, spec=sandbox_spec()), f"c-{i}")
            sandboxes.append(created["result"]["sandbox"]["sandbox_id"])
        gate = rig.host.block("sandbox.start")
        calls = [
            asyncio.create_task(
                rig.call(
                    dev, c.StartSandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation=1), f"k-{i}"
                )
            )
            for i, sandbox_id in enumerate(sandboxes)
        ]
        await asyncio.sleep(0.05)
        waiting = len([s for s in rig.host.sent if s.method == "sandbox.start"])
        assert waiting == 3
        gate.set()
        answers = await asyncio.gather(*calls)
        refused = [a for a in answers if isinstance(a, ErrorAnswer)]
        assert len(refused) == 3
        assert {(a.error.code, a.error.reason) for a in refused} == {("RATE_LIMITED", "principal_max_in_flight")}
        assert all(a.retry_after_s is not None for a in refused)
    finally:
        await rig.close()


async def test_a_project_that_reaches_its_share_does_not_affect_another(tmp_path: Any) -> None:
    """CC3-8, T3-RED-37 second half: a share is a ceiling for one project, never a reservation taken from others."""
    rig = await build_rig(tmp_path, project_rate=20, principal_rate=20)
    try:
        noisy, quiet = await rig.developer("noisy"), await rig.developer("quiet")
        outcomes = []
        for i in range(12):
            answer = await rig.call(noisy, c.CreateSandbox(project=noisy.project_id, spec=sandbox_spec()), f"n-{i}")
            outcomes.append(answer.error.code if isinstance(answer, ErrorAnswer) else "ok")
        assert "RATE_LIMITED" in outcomes
        assert outcomes.count("ok") <= 4, "a rate of 20 a minute admits a burst of two and no more"
        ok = await rig.view(quiet, c.CreateSandbox(project=quiet.project_id, spec=sandbox_spec()), "q-0")
        assert ok["state"] == "SUCCEEDED"
    finally:
        await rig.close()


async def test_thirty_two_concurrent_creates_against_a_quota_of_four(tmp_path: Any) -> None:
    """T3-RED-31, CC3-7: the count is read from the host inside the project's admission lock."""
    # A host allowance large enough that the rate admits all thirty-two: what is tested here is the quota.
    rig = await build_rig(
        tmp_path,
        project_max_live_sandboxes=4,
        principal_max_in_flight=64,
        project_max_in_flight=64,
        host_ops_allowance=60000,
    )
    try:
        dev = await rig.developer()
        rig.host.max_sandboxes = 64
        answers = await asyncio.gather(
            *[rig.call(dev, c.CreateSandbox(project=dev.project_id, spec=sandbox_spec()), f"q-{i}") for i in range(32)]
        )
        created = [a for a in answers if isinstance(a, ViewAnswer)]
        refused = [a for a in answers if isinstance(a, ErrorAnswer)]
        assert len(created) == 4
        assert {(a.error.code, a.error.reason, a.error.retry) for a in refused} == {
            ("PERMISSION_DENIED", "quota", "AFTER_CHANGE")
        }
        assert len([s for s in rig.host.sandboxes.values() if s["state"] != "DESTROYED"]) == 4
        # No counter is stored: after one is destroyed, one more may be created.
        victim = created[0].body["result"]["sandbox"]["sandbox_id"]
        await rig.view(
            dev, c.DestroySandbox(project=dev.project_id, sandbox_id=victim, expected_generation="current"), "free"
        )
        assert (await rig.view(dev, c.CreateSandbox(project=dev.project_id, spec=sandbox_spec()), "q-next"))[
            "state"
        ] == "SUCCEEDED"
    finally:
        await rig.close()


async def test_with_no_quota_configured_one_project_cannot_fill_the_host(tmp_path: Any) -> None:
    """T3-RED-31, CC3-7, CC3-8, INV-113: the default quota is a project's share of what the host admits.

    The host admits eight sandboxes and advertises a pool of 4,096 identifiers. The quota follows the first
    number, which the operator states because the host does not, and never the second: with the pool as the
    quota's base, one project could take every sandbox the host has.
    """
    rig = await build_rig(tmp_path, principal_max_in_flight=64, project_max_in_flight=64, host_ops_allowance=60000)
    try:
        assert (rig.host.max_sandboxes, rig.host.identifier_slots) == (8, 4096)
        assert rig.core.service.d.params.project_max_live_sandboxes is None
        greedy, other = await rig.developer("greedy"), await rig.developer("other")
        answers = await asyncio.gather(
            *[
                rig.call(greedy, c.CreateSandbox(project=greedy.project_id, spec=sandbox_spec()), f"g-{i}")
                for i in range(12)
            ]
        )
        refused = [a for a in answers if isinstance(a, ErrorAnswer)]
        assert len([a for a in answers if isinstance(a, ViewAnswer)]) == 4, "a half of what the host admits"
        assert {(a.error.code, a.error.reason) for a in refused} == {("PERMISSION_DENIED", "quota")}
        # The host itself refused nothing: the project met its own bound, and the rest of the host is free.
        created = [request for request in rig.host.mutating() if request.method == "sandbox.create"]
        assert len(created) == 4
        for n in range(4):
            command = c.CreateSandbox(project=other.project_id, spec=sandbox_spec())
            assert (await rig.view(other, command, f"o-{n}"))["state"] == "SUCCEEDED"
    finally:
        await rig.close()


async def test_a_host_that_has_fewer_identifiers_than_the_configured_envelope_is_not_served(tmp_path: Any) -> None:
    """HB-4: a relation to a value of the host is checked as soon as the host advertises the value.

    The host gives every sandbox an identifier of its own, so a configured sandbox count above its pool
    cannot be the host's. Granting work is refused until an operator corrects the number; containment is not.
    """
    rig = await build_rig(tmp_path, host=ModelHost(identifier_slots=4), host_max_sandboxes=8)
    try:
        dev = await rig.developer()
        refused = await rig.error(dev, c.CreateSandbox(project=dev.project_id, spec=sandbox_spec()), "k")
        assert (refused.code, refused.kind, refused.reason) == (
            "UPSTREAM_UNAVAILABLE",
            "REFUSED",
            "host_parameter_relation",
        )
        assert rig.core.service.d.standing.host_parameter_violations == [
            "host_max_sandboxes must not exceed the host's identifier pool: it is not the host's sandbox count"
        ]
        assert rig.host.mutating() == []
    finally:
        await rig.close()


async def test_an_unresolved_create_that_reached_the_host_is_counted_by_the_next(tmp_path: Any) -> None:
    """CC3-7: a record counts from the moment the host accepts the operation that creates it."""
    rig = await build_rig(tmp_path, project_max_live_sandboxes=1)
    try:
        dev = await rig.developer()
        rig.host.fault("lost_after", "sandbox.create")
        rig.host.fault("unreachable", "operation.get", times=50)
        lost = await rig.error(dev, c.CreateSandbox(project=dev.project_id, spec=sandbox_spec()), "first")
        assert lost.code == "OUTCOME_UNRESOLVED"
        rig.host.faults.clear()
        second = await rig.error(dev, c.CreateSandbox(project=dev.project_id, spec=sandbox_spec()), "second")
        assert (second.code, second.reason) == ("PERMISSION_DENIED", "quota")
    finally:
        await rig.close()


async def test_snapshots_have_a_quota_of_their_own(tmp_path: Any) -> None:
    """CC3-7."""
    rig = await build_rig(tmp_path, project_max_snapshots=2)
    try:
        dev = await rig.developer()
        sandbox_id = await _running(rig, dev)
        results = []
        for i in range(4):
            command = c.CreateSnapshot(
                project=dev.project_id, sandbox_id=sandbox_id, spec=m.SnapshotSpec(expected_generation=1)
            )
            answer = await rig.call(dev, command, f"s-{i}")
            assert isinstance(answer, ViewAnswer | ErrorAnswer)
            results.append("ok" if isinstance(answer, ViewAnswer) else answer.error.reason)
        assert results == ["ok", "ok", "quota", "quota"]
    finally:
        await rig.close()


# ------------------------------------------------------------------------------- following
async def test_a_wait_of_zero_answers_at_once_and_a_wait_follows_to_the_end(rig: Rig, dev: Identity) -> None:
    """T3-LRO-01, LRO-1 to LRO-3."""
    rig.host.hold.add("sandbox.create")
    answer = await rig.call(dev, c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(), wait=0), "k")
    assert isinstance(answer, ViewAnswer)
    assert (answer.terminal, answer.body["state"], answer.retry_after_s) == (False, "IN_PROGRESS", 1)
    operation_id = answer.body["operation_id"]

    async def finish_soon() -> None:
        await asyncio.sleep(0.05)
        rig.host.finish(operation_id)

    finisher = asyncio.create_task(finish_soon())
    followed = await rig.call(dev, c.GetOperation(project=dev.project_id, operation_id=operation_id, wait=2))
    await finisher
    assert isinstance(followed, ViewAnswer)
    assert (followed.terminal, followed.body["state"]) == (True, "SUCCEEDED")
    # At the bound, a wait ends with a correct answer: the operation has not ended.
    rig.host.hold.add("sandbox.start")
    sandbox_id = followed.body["result"]["sandbox"]["sandbox_id"]
    start = c.StartSandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation=1, wait=1)
    still = await rig.call(dev, start, "k-start", budget_s=1.0)
    assert isinstance(still, ViewAnswer)
    assert still.terminal is False


async def test_many_waiters_on_one_operation_cost_one_poll_per_interval(tmp_path: Any) -> None:
    """T3-LRO-05, T3-RED-37, LRO-9, HB-7: a wait costs the host reads per operation, not per caller."""
    rig = await build_rig(
        tmp_path,
        follow_poll_interval_min=0.05,
        follow_poll_interval_max=0.1,
        principal_max_in_flight=1000,
        project_max_in_flight=1000,
    )
    try:
        dev = await rig.developer()
        rig.host.hold.add("sandbox.create")
        first = await rig.view(dev, c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(), wait=0), "k")
        operation_id = first["operation_id"]
        polls_before = len([s for s in rig.host.sent if s.method == "operation.get" and s.lane is Lane.RESOLUTION])
        started = time.monotonic()
        waiters = [
            asyncio.create_task(
                rig.call(dev, c.GetOperation(project=dev.project_id, operation_id=operation_id, wait=1), budget_s=3.0)
            )
            for _ in range(500)
        ]
        await asyncio.sleep(0.4)
        rig.host.finish(operation_id)
        answers = await asyncio.gather(*waiters)
        assert all(isinstance(a, ViewAnswer) and a.body["state"] == "SUCCEEDED" for a in answers)
        polls = (
            len([s for s in rig.host.sent if s.method == "operation.get" and s.lane is Lane.RESOLUTION]) - polls_before
        )
        elapsed = time.monotonic() - started
        # At most one poll per shortest interval for as long as the following lasted, whatever the 500 waiters:
        # five hundred reads would be the cost of following per caller. The bound is on the rate and not on a
        # count, so that a slow machine, on which everything takes longer, proves the same thing.
        assert 1 <= polls <= elapsed / 0.05 + 2, (polls, elapsed)
        assert polls < len(waiters) / 4, (polls, elapsed)
        assert rig.core.service.d.follower.followed() == 0
    finally:
        await rig.close()


async def test_callers_who_arrive_after_an_operation_ended_do_not_each_cause_a_read(tmp_path: Any) -> None:
    """T3-LRO-05, LRO-9: the pace is the operation's. It does not start again with every caller."""
    interval = 0.05
    rig = await build_rig(tmp_path, follow_poll_interval_min=interval, follow_poll_interval_max=0.1)
    try:
        dev = await rig.developer()
        created = await rig.view(dev, c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(), wait=0), "k")
        assert created["terminal"] is True
        polls_before = len([s for s in rig.host.sent if s.method == "operation.get" and s.lane is Lane.RESOLUTION])
        started = time.monotonic()
        answered = 0
        # One after the other: each caller has left before the next arrives, so nobody is ever joined.
        while time.monotonic() - started < 6 * interval:
            answer = await rig.call(
                dev, c.GetOperation(project=dev.project_id, operation_id=created["operation_id"], wait=1)
            )
            assert isinstance(answer, ViewAnswer)
            assert answer.body["state"] == "SUCCEEDED"
            answered += 1
        elapsed = time.monotonic() - started
        polls = (
            len([s for s in rig.host.sent if s.method == "operation.get" and s.lane is Lane.RESOLUTION]) - polls_before
        )
        assert answered >= 3
        assert polls == answered, "every caller is answered from a read of its own time, made after it arrived"
        assert polls <= elapsed / interval + 1, (polls, elapsed)
    finally:
        await rig.close()


async def test_a_wait_that_starts_the_polling_is_its_callers_read_and_one_that_joins_is_free(tmp_path: Any) -> None:
    """T3-RED-37, CC3-8, LRO-9: reads the platform causes stay inside the project's share, waits included.

    The project's share leaves it one read at a time. A wait on an operation nobody follows takes it;
    callers who join that wait take nothing; a wait on another operation is refused like any read. The
    follower's own reads come out of the platform's reserve, which the share of a project does not touch.
    """
    rig = await build_rig(
        tmp_path,
        follow_poll_interval_min=0.05,
        follow_poll_interval_max=0.1,
        # Room for the waiters themselves, so that the bound this test meets is the rate and not the number in flight.
        principal_max_in_flight=100,
        project_max_in_flight=100,
    )
    try:
        dev = await rig.developer()
        rig.host.hold.add("sandbox.create")
        one = await rig.view(dev, c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(name="one"), wait=0), "k1")
        two = await rig.view(dev, c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(name="two"), wait=0), "k2")
        # From here on: a five-hundredth of the usable allowance, which is less than ten reads a minute.
        await rig.admin("project.share", project_id=dev.project_id, share=0.002)

        def waiting(operation: dict[str, Any]) -> c.GetOperation:
            return c.GetOperation(project=dev.project_id, operation_id=operation["operation_id"], wait=1)

        first = asyncio.create_task(rig.call(dev, waiting(one), budget_s=3.0))
        await asyncio.sleep(0.02)
        joined = [asyncio.create_task(rig.call(dev, waiting(one), budget_s=3.0)) for _ in range(20)]
        await asyncio.sleep(0.02)
        refused = await rig.error(dev, waiting(two))
        assert (refused.code, refused.kind) == ("RATE_LIMITED", "REFUSED")
        assert refused.reason in {"principal_rate", "project_rate"}
        rig.host.finish(one["operation_id"])
        answers = await asyncio.gather(first, *joined)
        assert all(isinstance(a, ViewAnswer) and a.body["state"] == "SUCCEEDED" for a in answers)
    finally:
        await rig.close()


async def test_a_waiter_is_never_answered_from_a_read_made_before_it_arrived(rig: Rig, dev: Identity) -> None:
    """LRO-9: every waiter is answered from a read that was made after the waiter arrived."""
    rig.host.hold.add("sandbox.create")
    first = await rig.view(dev, c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(), wait=0), "k")
    follower = rig.core.service.d.follower
    waiter = asyncio.create_task(follower.wait(dev.scope, first["operation_id"], 1.0, "req_" + "0" * 24))
    await asyncio.sleep(0.03)
    sent_at_arrival = len(rig.host.sent)
    rig.host.finish(first["operation_id"])
    result = await waiter
    assert result is not None
    assert len(rig.host.sent) > sent_at_arrival, "the answer came from a read made after the operation ended"


async def test_abandoning_a_wait_cancels_nothing(rig: Rig, dev: Identity) -> None:
    """T3-LRO-03, LRO-5, INV-116: a cancelled waiter leaves the host operation running."""
    sandbox_id = await _running(rig, dev)
    rig.host.hold.add("exec.run")
    spec = m.ExecSpec(expected_generation=1, argv=["sleep", "600"])
    call = asyncio.create_task(
        rig.call(dev, c.Exec(project=dev.project_id, sandbox_id=sandbox_id, spec=spec, wait=2), "e")
    )
    await asyncio.sleep(0.1)
    call.cancel()
    with pytest.raises(asyncio.CancelledError):
        await call
    operations = [o for o in rig.host.operations.values() if o["operation_type"] == "exec.run"]
    assert [o["state"] for o in operations] == ["IN_PROGRESS"]
    assert all(s.method != "operation.cancel" for s in rig.host.mutating())
    # The claim was bound although the caller went away: the same key finds the operation.
    again = await rig.view(dev, c.Exec(project=dev.project_id, sandbox_id=sandbox_id, spec=spec, wait=0), "e")
    assert again["replayed"] is True
    assert (await rig.core.service.d.ledger.counts(0))["claimed"] == 0
