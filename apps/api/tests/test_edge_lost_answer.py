"""An answer that is lost between the edge and the core, at every point and for every mutation.

The edge cannot tell whether the core accepted a command it sent and got no answer to. So it never
says "refused" for a command that may have created something: it answers ``OUTCOME_UNRESOLVED`` and
names the idempotency key, and the caller's repeat of the same request reaches the true outcome
through the ledger, without a second host operation.

The answer is dropped by the test at two points of the hop: before the core saw the command, and
after the core handled it and before the edge had its answer. A third point belongs to the edge
alone: the core answered, and the edge failed before it wrote the response.

Proves EC-5, ERR-1 and INV-105 at this hop, the two fault points of TV3-4 that lie between the roles,
and the catalog entry T3-EC-02.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from acf_api.command.answers import AckAnswer
from acf_api.command.surface import OperationClass
from acf_api.edge.http.routes import ROUTES, RouteSpec
from tests.support.edge import (
    SANDBOX_BODY,
    Edge,
    Point,
    assert_problem,
    build_world,
    call_route,
    method_of,
    project_path,
    serving,
    view_of,
)
from tests.support.harness import Identity, Rig

#: Routes whose command can create a host operation: a lost answer leaves a doubt about one.
MUTATING = [s for s in ROUTES if s.operation.operation_class in {OperationClass.GRANTING, OperationClass.CONTAINMENT}]
READS = [s for s in ROUTES if s.operation.operation_class is OperationClass.READ]
POINTS: list[Point] = ["before", "after"]


@pytest.fixture
async def edge(rig: Rig) -> AsyncIterator[Edge]:
    async with serving(rig) as built:
        yield built


def test_every_route_is_a_mutation_a_read_or_a_platform_operation() -> None:
    """The three groups below are the whole table: no route is left without a rule for its lost answer."""
    platform = [s for s in ROUTES if s.operation.operation_class is OperationClass.PLATFORM]
    assert len(MUTATING) + len(READS) + len(platform) == len(ROUTES)
    assert sorted(method_of(s) for s in platform) == ["agent_credential.mint", "agent_credential.revoke"]
    assert all(s.operation.keyed for s in MUTATING)


@pytest.mark.parametrize("point", POINTS)
@pytest.mark.parametrize("spec", MUTATING, ids=method_of)
@pytest.mark.proves("T3-EC-02")
async def test_a_lost_answer_to_a_mutation_is_unresolved_and_the_same_request_reaches_the_true_outcome(
    edge: Edge, dev: Identity, spec: RouteSpec, point: Point
) -> None:
    """T3-EC-02, EC-5: `OUTCOME_UNRESOLVED` with the key, never a refusal; then the operation, exactly once on the host."""
    world = await build_world(edge, dev)
    host = edge.rig.host
    submitted = len(host.mutating())

    edge.core.lose_next(point)
    lost = await call_route(edge, world, spec, dev, key="k-lost")
    problem = assert_problem(lost, "OUTCOME_UNRESOLVED", retry="SAME_REQUEST_LATER")
    assert (problem["kind"], problem["idempotency_key"]) == ("UNRESOLVED", "k-lost")
    assert lost.status_code == 503
    # What the caller was not told is what happened: the core either never saw the command, or carried it out.
    assert edge.core.seen[-1].reached is (point == "after")
    assert len(host.mutating()) - submitted == (1 if point == "after" else 0)

    again = await call_route(edge, world, spec, dev, key="k-lost")
    operation = view_of(again)
    assert operation["terminal"] is True
    assert operation["replayed"] is (point == "after")
    assert ("idempotent-replayed" in again.headers) is (point == "after")
    assert [s.method for s in host.submissions(operation["operation_id"])] == [spec.operation.host_method]
    assert len(host.mutating()) - submitted == 1, "one key, one host operation, whatever was lost"

    # And every later repeat is the same operation, marked as earlier work.
    third = await call_route(edge, world, spec, dev, key="k-lost")
    assert (view_of(third)["operation_id"], third.headers["idempotent-replayed"]) == (operation["operation_id"], "true")
    assert len(host.submissions(operation["operation_id"])) == 1


@pytest.mark.parametrize("point", POINTS)
@pytest.mark.parametrize("spec", READS, ids=method_of)
@pytest.mark.proves("T3-EC-02")
async def test_a_lost_answer_to_a_read_is_a_refusal_that_can_be_repeated(
    edge: Edge, dev: Identity, spec: RouteSpec, point: Point
) -> None:
    """§15.3: `UPSTREAM_UNAVAILABLE` for a read. A read created nothing whatever happened to it."""
    world = await build_world(edge, dev)
    edge.core.lose_next(point)
    lost = await call_route(edge, world, spec, dev)
    problem = assert_problem(lost, "UPSTREAM_UNAVAILABLE", retry="SAME_REQUEST_LATER")
    assert problem["kind"] == "REFUSED"
    assert "idempotency_key" not in problem
    view_of(await call_route(edge, world, spec, dev))


@pytest.mark.parametrize("point", POINTS)
async def test_a_lost_answer_to_the_credential_check_is_a_refusal_and_the_body_is_not_passed_on(
    edge: Edge, dev: Identity, point: Point
) -> None:
    """The check changes nothing, so its lost answer is a plain refusal, and nothing after it runs."""
    edge.core.lose_next(point, op="verify")
    lost = await edge.post(project_path(dev, "/sandboxes"), dev, key="k", json=SANDBOX_BODY)
    assert assert_problem(lost, "UPSTREAM_UNAVAILABLE", retry="SAME_REQUEST_LATER")["kind"] == "REFUSED"
    assert [seen.op for seen in edge.core.seen] == ["verify"]
    assert edge.rig.host.mutating() == []
    view_of(await edge.post(project_path(dev, "/sandboxes"), dev, key="k", json=SANDBOX_BODY))


@pytest.mark.parametrize("failure", ["the-client-fails", "the-answer-cannot-be-rendered"])
@pytest.mark.parametrize("spec", MUTATING, ids=method_of)
@pytest.mark.proves("T3-EC-02")
async def test_an_edge_that_fails_after_the_core_answered_does_not_say_refused(
    edge: Edge, dev: Identity, spec: RouteSpec, failure: str
) -> None:
    """TV3-4, last fault point; ERR-1: the command was carried out, so the edge's own failure cannot be a refusal."""
    world = await build_world(edge, dev)
    host = edge.rig.host
    submitted = len(host.mutating())
    if failure == "the-client-fails":
        edge.core.break_next(RuntimeError("the edge failed after the command was handled"))
    else:
        # An answer of a kind the REST adapter has no rendering for.
        edge.core.answer_next(AckAnswer())

    failed = await call_route(edge, world, spec, dev, key="k-edge")
    problem = assert_problem(failed, "OUTCOME_UNRESOLVED", retry="SAME_REQUEST_LATER")
    assert (problem["kind"], problem["idempotency_key"]) == ("UNRESOLVED", "k-edge")
    assert len(host.mutating()) - submitted == 1

    again = await call_route(edge, world, spec, dev, key="k-edge")
    operation = view_of(again)
    assert operation["replayed"] is True
    assert len(host.submissions(operation["operation_id"])) == 1


async def test_an_edge_that_fails_on_a_read_refuses_without_claiming_that_nothing_was_passed_on(
    edge: Edge, dev: Identity
) -> None:
    """A read changed nothing, so a refusal is the truth. Saying that the request never left the edge would not be."""
    edge.core.break_next(RuntimeError("the edge failed after the command was handled"))
    failed = await edge.get("/v1/auth/whoami", dev)
    problem = assert_problem(failed, "INTERNAL_ERROR")
    assert problem["kind"] == "REFUSED"
    assert edge.core.seen[-1].reached is True
    assert "before the request was passed on" not in problem["message"]
    assert "nothing was sent" not in problem["message"]


# =============================================================================== platform operations
@pytest.mark.parametrize("point", POINTS)
@pytest.mark.proves("T3-EC-02")
async def test_a_lost_answer_to_a_mint_is_unresolved_and_the_credential_is_found_by_listing(
    edge: Edge, dev: Identity, point: Point
) -> None:
    """Minting carries no key (CRD-9), so nothing can be named to ask again with; the list tells what exists."""
    path = project_path(dev, "/agent-credentials")
    body = {"label": "agent-lost", "lifetime_seconds": 600}
    edge.core.lose_next(point)
    lost = await edge.post(path, dev, json=body)
    problem = assert_problem(lost, "OUTCOME_UNRESOLVED", retry="SAME_REQUEST_LATER")
    assert problem["kind"] == "UNRESOLVED"
    assert "idempotency_key" not in problem

    listed = view_of(await edge.get(path, dev))["items"]
    if point == "before":
        assert listed == []
        minted = view_of(await edge.post(path, dev, json=body), 201)
        assert minted["label"] == "agent-lost"
        return
    # The credential was minted and its secret was in the answer that was lost. It is listed, and it can be revoked.
    (found,) = listed
    assert (found["label"], found["status"]) == ("agent-lost", "ISSUED")
    assert "secret" not in found
    # The label is taken: the repeat is refused for that, and no second credential appears.
    repeat = await edge.post(path, dev, json=body)
    assert assert_problem(repeat, "INVALID_REQUEST")["reason"] == "label_in_use"
    revoked = view_of(await edge.delete(f"{path}/{found['credential_id']}", dev))
    assert revoked["status"] == "REVOKED"


@pytest.mark.parametrize("point", POINTS)
@pytest.mark.proves("T3-EC-02")
async def test_a_lost_answer_to_a_revocation_is_unresolved_and_revoking_again_is_the_same_as_once(
    edge: Edge, dev: Identity, point: Point
) -> None:
    path = project_path(dev, "/agent-credentials")
    minted = view_of(await edge.post(path, dev, json={"label": "agent-1", "lifetime_seconds": 600}), 201)
    edge.core.lose_next(point)
    lost = await edge.delete(f"{path}/{minted['credential_id']}", dev)
    assert assert_problem(lost, "OUTCOME_UNRESOLVED")["kind"] == "UNRESOLVED"
    again = view_of(await edge.delete(f"{path}/{minted['credential_id']}", dev))
    assert again["status"] == "REVOKED"
    # Whichever attempt revoked it, the key no longer authenticates.
    assert_problem(await edge.get("/v1/auth/whoami", minted["secret"]), "UNAUTHENTICATED")
