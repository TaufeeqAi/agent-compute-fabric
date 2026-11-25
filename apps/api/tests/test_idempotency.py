"""One idempotency key yields at most one host operation, whatever is repeated.

Proves IDM-1, IDM-5, IDM-6, IDM-8, IDM-11, IDM-13 to IDM-17 and the catalog entries T3-IDM-02 to
T3-IDM-06, T3-RED-17, T3-RED-18, T3-RED-20 and T3-RED-21, against the model host.
"""

from __future__ import annotations

import asyncio

from acf_api.command import commands as c
from acf_api.command import model as m
from acf_api.command.answers import ErrorAnswer, ViewAnswer
from tests.support.harness import Identity, Rig, sandbox_spec


def create(dev: Identity, **spec: object) -> c.CreateSandbox:
    return c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(**spec))


async def running_sandbox(rig: Rig, dev: Identity, key: str = "k-setup") -> str:
    created = await rig.view(dev, create(dev), key)
    sandbox_id = str(created["result"]["sandbox"]["sandbox_id"])
    await rig.view(
        dev, c.StartSandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation=1), key + ":start"
    )
    return sandbox_id


async def test_same_key_same_request_is_the_same_operation_marked_as_a_replay(rig: Rig, dev: Identity) -> None:
    """T3-IDM-02: the answer is the operation as of now, read from the host, and says it reports earlier work."""
    first = await rig.call(dev, create(dev, name="one"), "key-a")
    second = await rig.call(dev, create(dev, name="one"), "key-a")
    assert isinstance(first, ViewAnswer)
    assert isinstance(second, ViewAnswer)
    assert first.replayed is False
    assert first.body["replayed"] is False
    assert second.replayed is True
    assert second.body["replayed"] is True
    assert second.body["operation_id"] == first.body["operation_id"]
    assert len(rig.host.submissions(first.body["operation_id"])) == 1
    # The second answer was read from the host, not from a stored copy: the host was asked for the operation.
    assert [s.method for s in rig.host.sent if s.operation_id is None][-1] == "operation.get"


async def test_a_replay_shows_the_current_state_not_the_first_answer(rig: Rig, dev: Identity) -> None:
    """IDM-8: a replay returns the operation's current state."""
    rig.host.hold.add("sandbox.create")
    first = await rig.view(dev, c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(), wait=0), "key-hold")
    assert first["state"] == "IN_PROGRESS"
    assert first["terminal"] is False
    rig.host.finish(first["operation_id"])
    second = await rig.view(dev, c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(), wait=0), "key-hold")
    assert second["state"] == "SUCCEEDED"
    assert second["replayed"] is True


async def test_same_key_different_request_is_a_conflict_and_changes_nothing(rig: Rig, dev: Identity) -> None:
    """T3-IDM-03."""
    first = await rig.view(dev, create(dev, name="one"), "key-b")
    error = await rig.error(dev, create(dev, name="two"), "key-b")
    assert (error.code, error.kind, error.retry) == ("IDEMPOTENCY_CONFLICT", "REFUSED", "NEVER")
    again = await rig.view(dev, create(dev, name="one"), "key-b")
    assert again["operation_id"] == first["operation_id"]
    assert len(rig.host.mutating()) == 1


async def test_wait_is_not_part_of_the_request(rig: Rig, dev: Identity) -> None:
    """IDM-4: `wait` is a transport value. The same intent with another wait is the same request."""
    first = await rig.view(dev, c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(), wait=0), "key-w")
    second = await rig.view(dev, c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(), wait=1), "key-w")
    assert second["operation_id"] == first["operation_id"]


async def test_a_spelled_out_default_is_the_same_request(rig: Rig, dev: Identity) -> None:
    """IDM-4: the fingerprint is computed from the decoded command, so defaults do not matter."""
    first = await rig.view(dev, create(dev), "key-d")
    second = await rig.view(dev, create(dev, network={"mode": "none"}, start=False), "key-d")
    assert second["operation_id"] == first["operation_id"]


async def test_concurrent_duplicates_make_one_host_operation(rig: Rig, dev: Identity) -> None:
    """T3-IDM-04: one claims; the others are told the request is in progress, or get the same operation."""
    gate = rig.host.block("sandbox.create")
    calls = [asyncio.create_task(rig.call(dev, create(dev, name="race"), "key-race")) for _ in range(8)]
    await asyncio.sleep(0.05)
    gate.set()
    answers = await asyncio.gather(*calls)
    operations = {a.body["operation_id"] for a in answers if isinstance(a, ViewAnswer)}
    codes = {a.error.code for a in answers if isinstance(a, ErrorAnswer)}
    assert len(operations) == 1
    assert codes <= {"REQUEST_IN_PROGRESS"}
    for answer in answers:
        if isinstance(answer, ErrorAnswer):
            assert answer.error.kind == "UNRESOLVED"
            assert answer.error.retry == "SAME_REQUEST_LATER"
            assert answer.error.idempotency_key == "key-race"
    assert len(rig.host.submissions(next(iter(operations)))) == 1


async def test_a_key_after_a_definitive_refusal_is_a_fresh_attempt(rig: Rig, dev: Identity) -> None:
    """T3-IDM-05, ERR-8: the refusal proved nothing exists, so the entry was released."""
    rig.host.refuse_next = ("RESOURCE_EXHAUSTED", "SAME_REQUEST_LATER", "no capacity")
    error = await rig.error(dev, create(dev), "key-r")
    assert (error.code, error.kind, error.retry) == ("RESOURCE_EXHAUSTED", "REFUSED", "SAME_REQUEST_LATER")
    assert await rig.core.service.d.ledger.counts(0) == {"claimed": 0, "bound": 0, "lost": 0, "claimed_stale": 0}
    retried = await rig.view(dev, create(dev), "key-r")
    assert retried["state"] == "SUCCEEDED"
    assert retried["replayed"] is False


async def test_a_mutation_without_a_key_is_refused(rig: Rig, dev: Identity) -> None:
    """T3-IDM-06, IDM-1."""
    error = await rig.error(dev, create(dev), None)
    assert (error.code, error.reason) == ("INVALID_REQUEST", "idempotency_key")
    assert rig.host.mutating() == []


async def test_a_key_is_scoped_by_project_and_principal(rig: Rig) -> None:
    """T3-RED-21, IDM-11: the same key and body under two projects are two independent requests."""
    one = await rig.developer("one")
    two = await rig.developer("two")
    first = await rig.view(one, create(one, name="same"), "shared-key")
    second = await rig.view(two, create(two, name="same"), "shared-key")
    assert first["operation_id"] != second["operation_id"]
    assert second["replayed"] is False
    assert {s.owner_scope for s in rig.host.mutating()} == {one.scope, two.scope}


async def test_a_resolution_skips_every_check_for_new_work(rig: Rig, dev: Identity) -> None:
    """T3-RED-18, IDM-14: narrowed grant, exhausted bounds, platform not ready: the operation is returned."""
    first = await rig.view(dev, create(dev, name="kept"), "key-keep")
    # The grant no longer allows the method.
    await rig.admin(
        "role.set",
        principal_id=dev.principal_id,
        project_id=dev.project_id,
        grants={
            "schema_version": 1,
            "methods": ["auth.whoami"],
            "images": [],
            "network": {"modes": [], "destinations": []},
            "ceilings": {
                "vcpus": 1,
                "memory_mib": 1,
                "disk_mib": 1,
                "execution_timeout_seconds": 1,
                "sandbox_lifetime_seconds": 1,
            },
        },
    )
    assert (await rig.error(dev, create(dev, name="new"), "key-new")).code == "PERMISSION_DENIED"
    narrowed = await rig.view(dev, create(dev, name="kept"), "key-keep")
    assert narrowed["operation_id"] == first["operation_id"]
    # The platform is not ready for granting work.
    rig.core.service.d.standing.recovered = False
    not_ready = await rig.view(dev, create(dev, name="kept"), "key-keep")
    assert not_ready["operation_id"] == first["operation_id"]
    assert not_ready["replayed"] is True
    assert len(rig.host.mutating()) == 1


async def test_a_retry_after_a_restore_returns_the_original_operation(rig: Rig, dev: Identity) -> None:
    """T3-RED-17, IDM-13, IDM-15: the generation read for `current` was recorded, so the retry is the same request."""
    sandbox_id = await running_sandbox(rig, dev)
    snapshot = await rig.view(
        dev,
        c.CreateSnapshot(
            project=dev.project_id, sandbox_id=sandbox_id, spec=m.SnapshotSpec(expected_generation=1, name="base")
        ),
        "k-snap",
    )
    ref = snapshot["result"]["snapshot"]
    stop = c.StopSandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation="current")
    # The answer to the stop is lost, and every read that could resolve it fails as well.
    rig.host.fault("lost_after", "sandbox.stop")
    rig.host.fault("unreachable", "operation.get", times=10)
    lost = await rig.error(dev, stop, "k-stop")
    assert (lost.code, lost.kind) == ("OUTCOME_UNRESOLVED", "UNRESOLVED")
    rig.host.faults.clear()
    # Meanwhile the sandbox is restored in place: its generation moves on.
    await rig.view(
        dev,
        c.RestoreSnapshot(
            project=dev.project_id,
            snapshot_id=ref["snapshot_id"],
            spec=m.RestoreSpec(
                snapshot_generation=ref["snapshot_generation"],
                target=m.RestoreInPlace(kind="existing", sandbox_id=sandbox_id, expected_generation="current"),
            ),
        ),
        "k-restore",
    )
    retried = await rig.restart()
    try:
        answer = await retried.call(dev, stop, "k-stop")
        assert isinstance(answer, ViewAnswer), getattr(answer, "error", None)
        assert answer.body["type"] == "sandbox.stop"
        assert answer.replayed is True
        # Exactly one stop was ever submitted, and it named the generation that was current when it was claimed.
        stops = [s for s in retried.host.mutating() if s.method == "sandbox.stop"]
        assert len(stops) == 1
        assert stops[0].params["expected_generation"] == 1
    finally:
        await retried.close()


async def test_a_key_reused_while_the_host_holds_its_operation_is_a_marked_replay(rig: Rig, dev: Identity) -> None:
    """T3-RED-20, IDM-16, INV-127: an operation that existed before a request is never shown as its new work."""
    first = await rig.view(dev, create(dev, name="old"), "key-old")
    ledger = rig.core.service.d.ledger
    # The platform forgets the key (its retention passed) while the host still remembers the operation.
    rig.clock.advance(10)
    assert await ledger.expire(rig.clock.wall_ms()) == 1
    again = await rig.call(dev, create(dev, name="old"), "key-old")
    assert isinstance(again, ViewAnswer), getattr(again, "error", None)
    assert again.body["operation_id"] == first["operation_id"]
    assert again.replayed is True
    assert again.body["replayed"] is True


async def test_a_host_conflict_on_a_derived_id_proves_existence(rig: Rig, dev: Identity) -> None:
    """IDM-15: the conflict never reaches the caller; the operation it proves is read and returned as a replay."""
    first = await rig.view(dev, create(dev, name="conflict"), "key-c")
    ledger = rig.core.service.d.ledger
    rig.clock.advance(10)
    await ledger.expire(rig.clock.wall_ms())
    # The host now holds an operation under this id whose request differs from what is sent next.
    for key in list(rig.host._fingerprints):  # the model's own record of what each id was used for
        rig.host._fingerprints[key] = "something else"
    answer = await rig.call(dev, create(dev, name="conflict"), "key-c")
    assert isinstance(answer, ViewAnswer), getattr(answer, "error", None)
    assert answer.body["operation_id"] == first["operation_id"]
    assert answer.replayed is True
    assert rig.core.telemetry.get("operator_diagnostics", kind="host_conflict_on_derived_id") == 1


async def test_the_key_digest_is_shown_and_the_key_is_not_stored(rig: Rig, dev: Identity) -> None:
    """IPS-1, SEC-113: the ledger holds a keyed digest of the key."""
    view = await rig.view(dev, create(dev), "a-very-recognizable-key-0123456789")
    digest = view["idempotency_key_digest"]
    assert len(digest) == 64
    assert "recognizable" not in digest
    for name in ("state.db", "state.db-wal"):
        path = rig.config.paths.store_dir / name
        if path.exists():
            assert b"a-very-recognizable-key" not in path.read_bytes()
