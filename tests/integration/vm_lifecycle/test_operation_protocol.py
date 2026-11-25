"""Operations as the caller sees them: one identity per intent, a position on every answer, and no lost updates.

Everything here is ``control_plane``: none of it depends on a guest. The checks are named after the entries of the
contract's test catalog they implement at evidence level L2/L3 (whole process, shipped configuration and profile).
What the reference client can express goes through the client; the rest (``retry``, ``issued_at``, a request with
no operation id) goes over the raw wire.
"""

from __future__ import annotations

import pytest

from acf_driver import AcfLocal, Answer, WireHost, new_operation_id, resources, target_of, utc_timestamp
from acf_integration import HostEnv

pytestmark = [pytest.mark.integration, pytest.mark.control_plane, pytest.mark.usefixtures("clean_host")]


def _create_params(acf: AcfLocal, name: str, *, memory_mib: int = 256) -> dict[str, object]:
    return {"name": name, "image": acf.image, "resources": resources(memory_mib=memory_mib)}


# ============================================================================================ idempotency
def test_t_op_01_a_repeated_operation_id_is_the_same_operation_and_runs_nothing_again(acf: AcfLocal) -> None:
    """T-OP-01 (L2): an accepted operation, sent again with the same id -> the same operation; nothing executed
    again."""
    wire = acf.wire
    name, create_id = acf.name("once"), new_operation_id()
    args = ("sandbox", "create", "--image", acf.image, "--name", name, "--operation-id", create_id)
    first = acf.ok(*args).succeeded()
    with wire.nothing_recorded("a repeated request"):
        second = acf.ok(*args).succeeded()
    box = first.sandbox_result()
    assert first.operation_id == second.operation_id == create_id
    assert second.sandbox_result().sandbox_id == box.sandbox_id
    assert [s.sandbox_id for s in wire.sandboxes()] == [box.sandbox_id], "the repeated create made a second sandbox"

    # The same over the wire, with the retry flag a client sets when it did not see the first answer.
    raw_id, raw_params = new_operation_id(), _create_params(acf, acf.name("resent"))
    sent = wire.call("sandbox.create", raw_params, operation_id=raw_id).succeeded()
    with wire.nothing_recorded("a retry of an accepted request"):
        resent = wire.call("sandbox.create", raw_params, operation_id=raw_id, retry=True).succeeded()
    assert (resent.operation_id, resent.sandbox_result().sandbox_id) == (raw_id, sent.sandbox_result().sandbox_id)
    assert len(wire.sandboxes()) == 2

    ready = wire.start(box)
    exec_id = new_operation_id()
    command = ("sandbox", "exec", ready.sandbox_id, "--operation-id", exec_id, "--", "true")
    ran = acf.ok(*command).succeeded()
    with wire.nothing_recorded("a repeated execution"):
        again = acf.ok(*command).succeeded()
    assert again.run_result().run_id == ran.run_result().run_id, "the command was executed a second time"
    assert wire.operation(exec_id).run_id == ran.run_result().run_id


def test_t_op_02_one_id_names_one_request(acf: AcfLocal) -> None:
    """T-OP-02 (L2): the same id with a different body -> ``IDEMPOTENCY_CONFLICT``; ``retry`` for an unknown id ->
    ``NOT_FOUND``; no id -> ``INVALID_REQUEST``."""
    wire = acf.wire
    name, operation_id = acf.name("fixed"), new_operation_id()
    create = ("sandbox", "create", "--image", acf.image, "--name", name, "--operation-id", operation_id)
    made = acf.ok(*create, "--memory", "256").succeeded().sandbox_result()

    with wire.nothing_recorded("a request that reuses an operation id"):
        other_body = acf.refused(*create, "--memory", "1024")
        unknown_retry = wire.call("sandbox.create", _create_params(acf, acf.name("never")), retry=True).refused()
        no_id = wire.call("sandbox.create", _create_params(acf, acf.name("anon")), operation_id=None).refused()
    assert (other_body.failure_class, other_body.retry) == ("IDEMPOTENCY_CONFLICT", "NEVER")
    assert (unknown_retry.failure_class, unknown_retry.retry) == ("NOT_FOUND", "NEVER"), (
        "a retry of an operation the host does not know is never treated as a new request"
    )
    assert (no_id.failure_class, no_id.retry) == ("INVALID_REQUEST", "NEVER")
    assert [s.sandbox_id for s in wire.sandboxes()] == [made.sandbox_id]
    assert wire.inspect(name).resources["memory_mib"] == 256, "the conflicting body changed the sandbox"


def test_an_operation_id_belongs_to_one_peer_in_one_owner_scope(acf: AcfLocal, host_env: HostEnv) -> None:
    wire, elsewhere = acf.wire, acf.wire.in_scope("it-other-scope")
    operation_id = new_operation_id()
    mine = wire.call("sandbox.create", _create_params(acf, acf.name("a")), operation_id=operation_id).succeeded()
    theirs = elsewhere.call("sandbox.create", _create_params(acf, acf.name("b")), operation_id=operation_id).succeeded()
    assert mine.sandbox_result().sandbox_id != theirs.sandbox_result().sandbox_id, (
        "the same id in another owner scope is another operation"
    )
    assert (mine.owner, theirs.owner) == ((host_env.peer_id, "default"), (host_env.peer_id, "it-other-scope"))


def test_t_op_03_a_request_outside_the_acceptance_horizon_is_refused(acf: AcfLocal, host_env: HostEnv) -> None:
    """T-OP-03 (L2), first half: ``issued_at`` outside the horizon -> ``EXPIRED_REQUEST``."""
    wire = acf.wire
    horizon = host_env.config.integer("operations.acceptance_horizon_ms") / 1000
    skew = host_env.config.integer("operations.clock_skew_tolerance_ms") / 1000

    def create(offset_s: float) -> Answer:
        return wire.call("sandbox.create", _create_params(acf, acf.name("t")), issued_at=utc_timestamp(offset_s))

    with wire.nothing_recorded("a request outside the acceptance horizon"):
        too_old = wire.call(
            "sandbox.create", _create_params(acf, acf.name("old")), issued_at=utc_timestamp(-(horizon + 5))
        ).refused()
        too_new = wire.call(
            "sandbox.create", _create_params(acf, acf.name("new")), issued_at=utc_timestamp(skew + 5)
        ).refused()
        undated = wire.call("sandbox.create", _create_params(acf, acf.name("undated")), issued_at=None).refused()
    assert (too_old.failure_class, too_old.retry) == ("EXPIRED_REQUEST", "NEVER")
    assert (too_new.failure_class, too_new.retry) == ("EXPIRED_REQUEST", "NEVER")
    assert undated.failure_class == "INVALID_REQUEST", "an operation without `issued_at` cannot be placed in time"

    inside = [create(-(horizon - 10)), create(skew - 10)]
    assert [answer.succeeded().state for answer in inside] == ["SUCCEEDED", "SUCCEEDED"], (
        "a request just inside the horizon, and one just inside the tolerated clock skew, are accepted"
    )


# ============================================================================================ positions and reads
def test_t_api_03_every_answer_states_its_position_and_only_an_accepted_request_moves_it(acf: AcfLocal) -> None:
    """T-API-03 (L2): a refusal leaves no operation record and no reservation."""
    wire = acf.wire
    start = wire.call("host.info")
    assert start.as_of is not None

    accepted = acf.ok("sandbox", "create", "--image", acf.image, "--name", acf.name("pos"))
    assert accepted.as_of is not None
    assert accepted.as_of.lineage == start.as_of.lineage
    assert accepted.as_of.sequence > start.as_of.sequence, "an accepted operation is recorded"
    assert accepted.succeeded().revision <= accepted.as_of.sequence

    operations_before = {op.operation_id for op in wire.operations()}
    refused = acf.json("sandbox", "create", "--image", acf.image, "--memory", "65536").answer()
    assert refused.refused().failure_class == "SAFETY_CONTROL_DENIED"
    assert refused.as_of is not None, "a refusal that consulted the host's state says as of when"
    assert refused.as_of.sequence == wire.sequence(), "the refusal was recorded"
    assert {op.operation_id for op in wire.operations()} == operations_before
    assert wire.info().live_sandboxes == 1, "the refused request holds a reservation"


def test_t_api_04_a_cursor_returns_exactly_what_changed_including_tombstones(acf: AcfLocal) -> None:
    """T-API-04 (L2): reads carry ``as_of``; ``changed_since`` returns exactly the changed records and tombstones;
    an old or foreign cursor -> ``CURSOR_EXPIRED``."""
    wire = acf.wire
    untouched = wire.ready(acf.name("untouched"))
    start = wire.call("sandbox.list").sandboxes().cursor
    doomed = wire.ready(acf.name("doomed"))
    kept = wire.create(acf.name("kept"))
    wire.destroy(doomed)

    listed = acf.ok("sandbox", "list", "--changed-since", str(start)).sandboxes()
    changed = {s.sandbox_id: s.state for s in listed.items}
    assert changed == {kept.sandbox_id: "PROVISIONING", doomed.sandbox_id: "DESTROYED"}, (
        "exactly the records that changed, the destroyed one as a tombstone, and not the untouched one"
    )
    assert untouched.sandbox_id not in changed
    assert {s.sandbox_id for s in wire.sandboxes()} == {untouched.sandbox_id, kept.sandbox_id}, (
        "a listing without a cursor has no tombstones"
    )
    nothing_new = wire.call("sandbox.list", {"changed_since": listed.cursor.to_wire()}).sandboxes()
    assert (nothing_new.items, nothing_new.more) == ([], False)

    foreign = wire.call("sandbox.list", {"changed_since": {"lineage": "0" * 32, "sequence": 1}}).refused()
    ahead = wire.call(
        "sandbox.list", {"changed_since": {"lineage": start.lineage, "sequence": start.sequence + 10**6}}
    ).refused()
    assert [(r.failure_class, r.retry) for r in (foreign, ahead)] == [("CURSOR_EXPIRED", "AFTER_CHANGE")] * 2


def test_a_listing_can_be_followed_page_by_page_to_the_same_end(acf: AcfLocal) -> None:
    wire = acf.wire
    made = {wire.create(acf.name(f"p{i}")).sandbox_id for i in range(4)}
    first_page = acf.ok("sandbox", "list", "--limit", "1").sandboxes()
    assert (len(first_page.items), first_page.more) == (1, True)
    paged = WireHost(acf.target.connect, image=acf.image, page_size=1)
    assert {s.sandbox_id for s in paged.sandboxes()} == made, "following the cursor must reach every record"


def test_an_operation_can_be_read_back_by_id_and_is_in_the_list(acf: AcfLocal, host_env: HostEnv) -> None:
    wire = acf.wire
    box = wire.ready(acf.name("read"))
    ran = wire.run(box, ["true"])
    by_id = acf.ok("operation", "get", ran.operation_id).accepted()
    assert (by_id.operation_id, by_id.operation_type, by_id.state) == (ran.operation_id, "exec.run", "SUCCEEDED")
    assert (by_id.run_id, by_id.target, by_id.owner) == (ran.run_id, box.sandbox_id, (host_env.peer_id, "default"))
    assert by_id.issuer == "PEER"
    listed = {op.operation_id: op for op in wire.operations()}
    assert listed[ran.operation_id].operation_type == "exec.run"
    mine = sorted(op.operation_type for op in listed.values() if op.target == box.sandbox_id)
    assert mine == ["exec.run", "sandbox.create", "sandbox.start"], "every operation on the sandbox is listed, once"
    page = acf.ok("operation", "list", "--limit", "1").operations()
    assert (len(page.items), page.more) == (1, True)


def test_cancelling_an_operation_that_has_ended_changes_nothing_about_it(acf: AcfLocal) -> None:
    wire = acf.wire
    box = wire.ready(acf.name("late-cancel"))
    ran = wire.run(box, ["true"])
    before = wire.refresh(box)
    cancel = acf.ok("operation", "cancel", ran.operation_id).accepted()
    assert cancel.operation_type == "operation.cancel"
    after = wire.operation(ran.operation_id)
    assert (after.state, after.effect, after.cancelled_by, after.run_id) == ("SUCCEEDED", "APPLIED", None, ran.run_id)
    assert wire.refresh(box).state == before.state == "COMPLETED"
    assert wire.call("exec.run", {**target_of(before), "command": {"argv": ["true"]}}).succeeded().state == "SUCCEEDED"
