"""The REST adapter: the public resource model over HTTP, on the real pipeline and the model host.

The adapter decides nothing, so what is proven here is what it must do by itself: bound and decode
strictly before anything is passed on, ask for the credential check before a body is read, and render
the core's answers exactly: a view, an operation with ``200`` or ``202``, or a problem document.

Proves B21, LRO-1 to LRO-3, IDM-1, IDM-2, IDM-17, ERR-6, DATA-7, VER-3, CC3-3 (the validator), SEC-104
and SEC-105 at the adapter, and the catalog entries T3-API-02, T3-API-03 (against the model host),
T3-LRO-01, T3-VER-02 (the server's half), T3-SEC-04, T3-SEC-05 (what the edge writes) and the
anonymous part of T3-RED-08.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from acf_api.command.answers import AckAnswer
from acf_api.core.identity import keys
from acf_api.edge.http.routes import ROUTES, RouteSpec
from tests.support.edge import (
    CONTRACT_TABLE,
    PROBLEM_MEMBERS,
    REQUEST_ID,
    SANDBOX_BODY,
    Edge,
    World,
    assert_problem,
    build_world,
    call_route,
    create_sandbox,
    method_of,
    problem_of,
    project_path,
    route_calls,
    serving,
    standing_edge,
    start_sandbox,
    started_sandbox,
    until,
    view_of,
)
from tests.support.harness import POLICIES, Identity, Rig

#: What a planted string looks like. No message, header or log line of the platform may ever contain it.
CANARY = "kanarienvogel7Q2M9K4T"


@pytest.fixture
async def edge(rig: Rig) -> AsyncIterator[Edge]:
    async with serving(rig) as built:
        yield built


OPERATION_ROUTES = [spec for spec in ROUTES if spec.answers_operation]
KEYED_ROUTES = [spec for spec in ROUTES if spec.operation.keyed]
PROJECT_ROUTES = [spec for spec in ROUTES if "project" in spec.path_params]
BODY_ROUTES = [spec for spec in ROUTES if spec.body is not None]
BODILESS_ROUTES = [spec for spec in ROUTES if spec.body is None]


def test_the_table_of_calls_names_every_route_and_no_other() -> None:
    """A route added to the adapter without a request here is a route nobody proved to answer."""
    placeholder = World(Identity("prj_x", "prn_x", "crd_x", "key", "scope"), "s", "i", "n", "e", "o", "c")
    assert sorted(route_calls(placeholder)) == sorted(method_of(spec) for spec in ROUTES)
    assert len({(spec.method, spec.path) for spec in ROUTES}) == len(ROUTES)


# =============================================================================== every route answers
@pytest.mark.parametrize("spec", ROUTES, ids=method_of)
@pytest.mark.proves("T3-API-02")
async def test_every_route_answers_with_its_view(edge: Edge, dev: Identity, spec: RouteSpec) -> None:
    """T3-API-02: each route of the table answers a valid request with the view the table names."""
    world = await build_world(edge, dev)
    response = await call_route(edge, world, spec, dev)
    body = view_of(response, spec.success_status)
    # The view is exactly the public model's: no member the model does not define.
    spec.view.model_validate(body)
    assert REQUEST_ID.fullmatch(response.headers["x-request-id"])
    assert response.headers["cache-control"] == "no-store"
    assert "location" not in response.headers
    if spec.answers_operation:
        assert body["terminal"] is True
        assert body["project"] == dev.project_id
        assert "idempotent-replayed" not in response.headers


async def test_every_request_reaches_the_core_with_the_callers_credential_unchanged_and_a_bounded_budget(
    edge: Edge, dev: Identity
) -> None:
    """EC-3: the edge asserts no principal; it passes the credential on. B21: the command carries the wait plus the margin."""
    view_of(await edge.get("/v1/auth/whoami", dev))
    verify, handle = edge.core.seen
    assert (verify.op, handle.op, handle.command) == ("verify", "handle", "whoami")
    assert verify.credential == handle.credential == dev.key
    expected_ms = int((edge.limits.public_wait_max + edge.limits.edge_core_deadline_margin) * 1000)
    assert verify.budget_ms == handle.budget_ms == expected_ms
    assert verify.request_id == handle.request_id == edge.responses[-1].headers["x-request-id"]


async def test_the_request_id_of_a_response_is_the_one_the_host_was_given(edge: Edge, dev: Identity) -> None:
    """OBS-1 at the adapter: one id joins the caller's answer, the command and every host request it caused."""
    before = len(edge.rig.host.sent)
    response = await edge.post(project_path(dev, "/sandboxes"), dev, key="k-trace", json=SANDBOX_BODY)
    view_of(response)
    caused = edge.rig.host.sent[before:]
    assert [s.method for s in caused if s.operation_id is not None] == ["sandbox.create"]
    assert {s.request_id for s in caused} == {response.headers["x-request-id"]}


# =============================================================================== 200, 202 and waiting
@pytest.mark.parametrize("spec", OPERATION_ROUTES, ids=method_of)
@pytest.mark.proves("T3-API-02", "T3-LRO-01")
async def test_an_operation_that_has_not_ended_is_202_with_location_and_retry_after(
    edge: Edge, dev: Identity, spec: RouteSpec
) -> None:
    """LRO-1, LRO-2, T3-API-02, T3-LRO-01: 202 names the operation; reading it there is 200 whatever its state."""
    world = await build_world(edge, dev)
    assert spec.operation.host_method is not None
    edge.rig.host.hold.add(spec.operation.host_method)
    call = route_calls(world)[method_of(spec)]
    response = await call_route(edge, world, spec, dev, params={**(call.params or {}), "wait": 0})
    body = view_of(response, 202)
    assert body["terminal"] is False
    assert body["state"] == "IN_PROGRESS"
    assert response.headers["location"] == project_path(dev, f"/operations/{body['operation_id']}")
    assert int(response.headers["retry-after"]) >= 1

    followed = await edge.get(response.headers["location"], dev)
    current = view_of(followed)
    assert (current["operation_id"], current["terminal"]) == (body["operation_id"], False)
    assert int(followed.headers["retry-after"]) >= 1
    assert "location" not in followed.headers

    edge.rig.host.finish(body["operation_id"])
    ended = await edge.get(response.headers["location"], dev)
    assert view_of(ended)["terminal"] is True
    assert "retry-after" not in ended.headers


@pytest.mark.proves("T3-API-02")
async def test_an_operation_that_failed_is_still_200_with_the_operation(edge: Edge, dev: Identity) -> None:
    """ERR-2: an accepted request never produces an error answer; its outcome is the operation's."""
    sandbox = await create_sandbox(edge, dev)
    edge.rig.host.fail_starts = True
    response = await edge.post(
        project_path(dev, f"/sandboxes/{sandbox['sandbox_id']}/start"),
        dev,
        key="k-start",
        json={"expected_generation": 1},
    )
    operation = view_of(response)
    assert (operation["state"], operation["terminal"], operation["effect"]) == ("FAILED", True, "NOT_APPLIED")
    assert operation["failure"]["code"] == "DEPENDENCY_UNAVAILABLE"


@pytest.mark.proves("T3-LRO-01")
async def test_a_wait_is_capped_at_public_wait_max_and_defaults_to_it(tmp_path: Path) -> None:
    """LRO-2, T3-LRO-01: a caller may ask for an hour; the request is held for the platform's bound and no longer."""
    async with standing_edge(tmp_path, public_wait_max=0.3, mcp_tool_wait=0.2) as edge:
        dev = await edge.rig.developer()
        edge.rig.host.hold.add("sandbox.create")
        for key, params in (("k-hour", {"wait": 3600}), ("k-default", None)):
            started = time.monotonic()
            response = await edge.post(project_path(dev, "/sandboxes"), dev, key=key, json=SANDBOX_BODY, params=params)
            elapsed = time.monotonic() - started
            assert view_of(response, 202)["terminal"] is False
            assert 0.25 <= elapsed < 2.0, (key, elapsed)
        started = time.monotonic()
        at_once = await edge.post(
            project_path(dev, "/sandboxes"), dev, key="k-zero", json=SANDBOX_BODY, params={"wait": 0}
        )
        assert at_once.status_code == 202
        assert time.monotonic() - started < 0.25


@pytest.mark.proves("T3-LRO-01")
async def test_a_mutation_returns_200_as_soon_as_its_operation_ends_within_the_wait(edge: Edge, dev: Identity) -> None:
    """LRO-1: terminal only if the operation ended within the request's wait, and then without delay."""
    host = edge.rig.host
    host.hold.add("sandbox.create")
    pending = asyncio.create_task(
        edge.post(project_path(dev, "/sandboxes"), dev, key="k-wait", json=SANDBOX_BODY, params={"wait": 2})
    )
    await until(lambda: bool(host.operations))
    assert not pending.done()
    (operation,) = host.operations.values()
    host.finish(operation["operation_id"])
    response = await asyncio.wait_for(pending, 1.5)
    assert view_of(response)["state"] == "SUCCEEDED"
    assert "location" not in response.headers


@pytest.mark.proves("T3-LRO-01")
async def test_reading_an_operation_answers_at_once_or_long_polls_until_it_ends(edge: Edge, dev: Identity) -> None:
    """LRO-3, T3-LRO-01."""
    host = edge.rig.host
    host.hold.add("sandbox.create")
    accepted = await edge.post(
        project_path(dev, "/sandboxes"), dev, key="k-poll", json=SANDBOX_BODY, params={"wait": 0}
    )
    location = accepted.headers["location"]

    started = time.monotonic()
    assert view_of(await edge.get(location, dev))["terminal"] is False
    assert time.monotonic() - started < 0.5, "without `wait` the current state is returned at once"

    poll = asyncio.create_task(edge.get(location, dev, params={"wait": 2}))
    await asyncio.sleep(0.15)
    assert not poll.done(), "with `wait` the request is held while the operation has not ended"
    host.finish(accepted.json()["operation_id"])
    ended = await asyncio.wait_for(poll, 1.0)
    assert view_of(ended)["terminal"] is True


@pytest.mark.parametrize("wait", [None, 0, 2])
@pytest.mark.proves("T3-LRO-01")
async def test_waiting_for_an_operation_the_host_does_not_hold_is_not_found_and_does_not_wait(
    edge: Edge, dev: Identity, wait: int | None
) -> None:
    """LRO-3: there is nothing to wait for, and the answer says so at once, with or without a wait."""
    started = time.monotonic()
    params = {"wait": wait} if wait is not None else None
    response = await edge.get(project_path(dev, f"/operations/op-{CANARY}"), dev, params=params)
    assert_problem(response, "NOT_FOUND", retry="NEVER")
    assert CANARY not in response.text
    assert time.monotonic() - started < 1.0


# =============================================================================== idempotency at the adapter
async def test_a_replay_is_marked_in_the_header_and_in_the_body(edge: Edge, dev: Identity) -> None:
    """IDM-17, T3-IDM-02 at the adapter: `Idempotent-Replayed: true` on a replay and on nothing else."""
    first = await edge.post(project_path(dev, "/sandboxes"), dev, key="k-same", json=SANDBOX_BODY)
    second = await edge.post(project_path(dev, "/sandboxes"), dev, key="k-same", json=SANDBOX_BODY)
    assert "idempotent-replayed" not in first.headers
    assert view_of(first)["replayed"] is False
    assert second.headers["idempotent-replayed"] == "true"
    assert view_of(second)["replayed"] is True
    assert second.json()["operation_id"] == first.json()["operation_id"]
    assert len(edge.rig.host.submissions(first.json()["operation_id"])) == 1


async def test_a_replay_of_an_operation_that_has_not_ended_is_a_marked_202(edge: Edge, dev: Identity) -> None:
    edge.rig.host.hold.add("sandbox.create")
    first = await edge.post(project_path(dev, "/sandboxes"), dev, key="k-held", json=SANDBOX_BODY, params={"wait": 0})
    second = await edge.post(project_path(dev, "/sandboxes"), dev, key="k-held", json=SANDBOX_BODY, params={"wait": 0})
    assert (first.status_code, second.status_code) == (202, 202)
    assert "idempotent-replayed" not in first.headers
    assert second.headers["idempotent-replayed"] == "true"
    assert second.headers["location"] == first.headers["location"]


@pytest.mark.parametrize("spec", KEYED_ROUTES, ids=method_of)
async def test_a_mutation_without_an_idempotency_key_is_refused_before_it_is_passed_on(
    edge: Edge, dev: Identity, spec: RouteSpec
) -> None:
    """IDM-1, T3-IDM-06: every request that can create an operation carries a key."""
    world = await build_world(edge, dev)
    handled, sent = edge.core.count("handle"), len(edge.rig.host.sent)
    response = await call_route(edge, world, spec, dev, key=None)
    assert assert_problem(response, "INVALID_REQUEST", retry="NEVER")["reason"] == "idempotency_key"
    assert edge.core.count("handle") == handled
    assert len(edge.rig.host.sent) == sent


@pytest.mark.parametrize(
    "key",
    ["two words", "tab\tinside", "del\x7f", "", "k" * 256, "clé".encode(), b"\xff\xfe"],
    ids=["space", "tab", "delete", "empty", "256-characters", "non-ascii", "invalid-utf8"],
)
async def test_an_idempotency_key_outside_the_form_is_refused(edge: Edge, dev: Identity, key: str | bytes) -> None:
    """IDM-2: 1 to 255 characters, each in the range 0x21 to 0x7E."""
    response = await edge.post(project_path(dev, "/sandboxes"), dev, key=key, json=SANDBOX_BODY)
    assert assert_problem(response, "INVALID_REQUEST")["reason"] == "idempotency_key"
    assert edge.core.count("handle") == 0
    assert edge.rig.host.mutating() == []


async def test_every_character_of_the_key_alphabet_is_accepted_and_keys_are_compared_byte_for_byte(
    edge: Edge, dev: Identity
) -> None:
    """IDM-2: the longest key, every allowed character, and no normalization of case."""
    alphabet = "".join(chr(code) for code in range(0x21, 0x7F))
    longest = await edge.post(project_path(dev, "/sandboxes"), dev, key="k" * 255, json=SANDBOX_BODY)
    every = await edge.post(project_path(dev, "/sandboxes"), dev, key=alphabet, json=SANDBOX_BODY)
    upper = await edge.post(project_path(dev, "/sandboxes"), dev, key="Key-A", json=SANDBOX_BODY)
    lower = await edge.post(project_path(dev, "/sandboxes"), dev, key="key-a", json=SANDBOX_BODY)
    operations = {view_of(r)["operation_id"] for r in (longest, every, upper, lower)}
    assert len(operations) == 4
    assert all(r.json()["replayed"] is False for r in (longest, every, upper, lower))
    replay = await edge.post(project_path(dev, "/sandboxes"), dev, key=alphabet, json=SANDBOX_BODY)
    assert view_of(replay)["operation_id"] == every.json()["operation_id"]
    assert replay.headers["idempotent-replayed"] == "true"


async def test_the_operators_shorter_key_bound_is_enforced_by_the_core(tmp_path: Path) -> None:
    """`idempotency_key_max_len` may be lower than the wire's 255, never higher."""
    async with standing_edge(tmp_path, idempotency_key_max_len=16) as edge:
        dev = await edge.rig.developer()
        refused = await edge.post(project_path(dev, "/sandboxes"), dev, key="k" * 17, json=SANDBOX_BODY)
        assert assert_problem(refused, "INVALID_REQUEST")["reason"] == "idempotency_key"
        assert edge.rig.host.mutating() == []
        view_of(await edge.post(project_path(dev, "/sandboxes"), dev, key="k" * 16, json=SANDBOX_BODY))


# =============================================================================== the validator
def _host_revision(validator: str) -> int:
    return int(validator.removeprefix("r").split(".")[0])


async def test_a_sandbox_carries_its_validator_as_an_etag_and_if_match_carries_it_back(
    edge: Edge, dev: Identity
) -> None:
    """CC3-3: the public revision is exposed as `ETag`; `If-Match` becomes the host's `if_revision`."""
    sandbox = await create_sandbox(edge, dev)
    path = project_path(dev, f"/sandboxes/{sandbox['sandbox_id']}")
    read = await edge.get(path, dev)
    validator = view_of(read)["revision"]
    assert read.headers["etag"] == f'"{validator}"'
    assert validator == sandbox["revision"]

    started = await edge.post(
        f"{path}/start", dev, key="k-start", json={"expected_generation": 1}, headers={"If-Match": read.headers["etag"]}
    )
    assert view_of(started)["result"]["sandbox"]["state"] == "READY"
    assert edge.rig.host.mutating()[-1].params == {
        "sandbox_id": sandbox["sandbox_id"],
        "expected_generation": 1,
        "if_revision": _host_revision(validator),
    }
    # The sandbox changed, so its validator did.
    assert (await edge.get(path, dev)).headers["etag"] != read.headers["etag"]


async def test_a_stale_validator_is_refused_by_the_host_and_changes_nothing(edge: Edge, dev: Identity) -> None:
    """A validator of an earlier state, or of another sandbox, is not the sandbox's: `REVISION_CONFLICT`, 412."""
    sandbox_id = (await create_sandbox(edge, dev))["sandbox_id"]
    other = await create_sandbox(edge, dev, "k-other")
    path = project_path(dev, f"/sandboxes/{sandbox_id}")
    stale = (await edge.get(path, dev)).headers["etag"]
    await start_sandbox(edge, dev, sandbox_id)

    for label, validator in (("stale", stale), ("of-another-sandbox", f'"{other["revision"]}"')):
        refused = await edge.post(
            f"{path}/stop", dev, key=f"k-stop-{label}", json={"expected_generation": 1}, headers={"If-Match": validator}
        )
        assert_problem(refused, "REVISION_CONFLICT", retry="AFTER_CHANGE")
    assert view_of(await edge.get(path, dev))["state"] == "READY"

    fresh = (await edge.get(path, dev)).headers["etag"]
    stopped = await edge.post(
        f"{path}/stop", dev, key="k-stop-fresh", json={"expected_generation": 1}, headers={"If-Match": fresh}
    )
    assert view_of(stopped)["result"]["sandbox"]["state"] == "STOPPED"


async def test_a_stale_validator_with_the_current_generation_is_refused_once_and_not_retried(
    edge: Edge, dev: Identity
) -> None:
    """CC3-3: containment that states `current` tries again after a restore; a validator the caller pinned cannot become valid."""
    sandbox_id = (await create_sandbox(edge, dev))["sandbox_id"]
    path = project_path(dev, f"/sandboxes/{sandbox_id}")
    stale = (await edge.get(path, dev)).headers["etag"]
    await start_sandbox(edge, dev, sandbox_id)
    before = len(edge.rig.host.mutating())

    started = time.monotonic()
    refused = await edge.delete(
        path, dev, key="k-destroy", params={"expected_generation": "current"}, headers={"If-Match": stale}
    )
    assert_problem(refused, "REVISION_CONFLICT", retry="AFTER_CHANGE")
    assert time.monotonic() - started < 1.0
    assert len(edge.rig.host.mutating()) - before == 1, (
        "the host was asked again for a precondition that cannot come true"
    )
    assert view_of(await edge.get(path, dev))["state"] == "READY"


async def test_a_validator_of_another_lineage_is_refused_by_the_platform_and_nothing_is_sent(
    edge: Edge, dev: Identity
) -> None:
    """A validator is bound to the store lineage it was issued under (PUB-7); one from elsewhere names nothing here."""
    sandbox = await create_sandbox(edge, dev)
    path = project_path(dev, f"/sandboxes/{sandbox['sandbox_id']}")
    foreign = f'"r{_host_revision(sandbox["revision"])}.000000000000"'
    before = len(edge.rig.host.mutating())
    refused = await edge.post(
        f"{path}/start", dev, key="k-foreign", json={"expected_generation": 1}, headers={"If-Match": foreign}
    )
    assert assert_problem(refused, "INVALID_REQUEST", retry="AFTER_CHANGE")["reason"] == "if_match"
    assert len(edge.rig.host.mutating()) == before


@pytest.mark.parametrize("value", ["not-a-validator", '"r1"', 'W/"r1.000000000000"', "*", f'"{CANARY}"'])
async def test_an_if_match_that_is_not_one_entity_tag_of_this_api_is_refused(
    edge: Edge, dev: Identity, value: str
) -> None:
    sandbox = await create_sandbox(edge, dev)
    path = project_path(dev, f"/sandboxes/{sandbox['sandbox_id']}/start")
    handled = edge.core.count("handle")
    refused = await edge.post(path, dev, key="k-bad", json={"expected_generation": 1}, headers={"If-Match": value})
    assert assert_problem(refused, "INVALID_REQUEST")["reason"] == "if_match"
    assert CANARY not in refused.text
    assert edge.core.count("handle") == handled


async def test_if_match_on_a_route_that_takes_none_is_refused(edge: Edge, dev: Identity) -> None:
    sandbox = await create_sandbox(edge, dev)
    validator = {"If-Match": f'"{sandbox["revision"]}"'}
    read = await edge.get(project_path(dev, f"/sandboxes/{sandbox['sandbox_id']}"), dev, headers=validator)
    created = await edge.post(project_path(dev, "/sandboxes"), dev, key="k-new", json=SANDBOX_BODY, headers=validator)
    for refused in (read, created):
        assert assert_problem(refused, "INVALID_REQUEST")["reason"] == "if_match"


# =============================================================================== every code the platform decides
_PROVEN: set[str] = set()


def decides[Test: Callable[..., Awaitable[None]]](code: str) -> Callable[[Test], Test]:
    """Mark a test as the proof of the problem document of one code the platform can decide."""

    def mark(test: Test) -> Test:
        _PROVEN.add(code)
        return test

    return mark


def test_every_code_the_platform_can_decide_has_a_proof_below() -> None:
    """T3-API-02: "for each code". A code decided by the platform without a test here was not proven."""
    assert {code for code, row in CONTRACT_TABLE.items() if row.decided_by in {"platform", "either"}} == _PROVEN


def _restricted(*without: str) -> dict[str, Any]:
    """The `developer` grant template without some methods."""
    grant = yaml.safe_load((POLICIES / "developer.yaml").read_text(encoding="utf-8"))
    assert isinstance(grant, dict)
    grant["methods"] = [method for method in grant["methods"] if method not in without]
    return grant


@decides("INVALID_REQUEST")
@pytest.mark.proves("T3-API-02")
async def test_problem_invalid_request(tmp_path: Path) -> None:
    async with standing_edge(tmp_path) as edge:
        dev = await edge.rig.developer()
        response = await edge.post(project_path(dev, "/sandboxes"), dev, key="k", json={"image": "python"})
        assert_problem(response, "INVALID_REQUEST", retry="NEVER")


@decides("UNAUTHENTICATED")
@pytest.mark.proves("T3-API-02")
async def test_problem_unauthenticated_is_one_answer_for_every_credential_that_does_not_authenticate(
    tmp_path: Path,
) -> None:
    """§15.3: missing, invalid, expired or revoked are answered alike, without saying which."""
    async with standing_edge(tmp_path) as edge:
        dev = await edge.rig.developer()
        unknown = keys.generate_key("developer")
        revoked = await edge.rig.developer("gone")
        await edge.rig.admin("key.revoke", credential_id=revoked.credential_id)
        answers = [
            await edge.get(project_path(dev, "/sandboxes"), who) for who in (None, unknown, "not-a-key", revoked.key)
        ]
        bodies = [assert_problem(response, "UNAUTHENTICATED", retry="NEVER") for response in answers]
        assert len({(b["message"], b["title"], b.get("reason")) for b in bodies}) == 1
        assert {response.headers["www-authenticate"] for response in answers} == {"Bearer"}
        assert edge.rig.host.sent[-1].method != "sandbox.list"


@decides("PERMISSION_DENIED")
@pytest.mark.proves("T3-API-02")
async def test_problem_permission_denied(tmp_path: Path) -> None:
    async with standing_edge(tmp_path) as edge:
        reader = await edge.rig.developer("reader", grants=_restricted("sandbox.create"))
        response = await edge.post(project_path(reader, "/sandboxes"), reader, key="k", json=SANDBOX_BODY)
        assert_problem(response, "PERMISSION_DENIED", retry="NEVER")
        assert edge.rig.host.mutating() == []


@decides("NOT_FOUND")
@pytest.mark.proves("T3-API-02")
async def test_problem_not_found(tmp_path: Path) -> None:
    async with standing_edge(tmp_path) as edge:
        dev = await edge.rig.developer()
        response = await edge.get(project_path(dev, "/sandboxes/sbx-" + "0" * 32), dev)
        assert_problem(response, "NOT_FOUND", retry="NEVER")


@decides("IDEMPOTENCY_CONFLICT")
@pytest.mark.proves("T3-API-02")
async def test_problem_idempotency_conflict(tmp_path: Path) -> None:
    async with standing_edge(tmp_path) as edge:
        dev = await edge.rig.developer()
        view_of(await edge.post(project_path(dev, "/sandboxes"), dev, key="k", json=SANDBOX_BODY))
        response = await edge.post(
            project_path(dev, "/sandboxes"), dev, key="k", json={**SANDBOX_BODY, "name": "other"}
        )
        assert_problem(response, "IDEMPOTENCY_CONFLICT", retry="NEVER")
        assert len(edge.rig.host.mutating()) == 1


@decides("REQUEST_IN_PROGRESS")
@pytest.mark.proves("T3-API-02")
async def test_problem_request_in_progress(tmp_path: Path) -> None:
    async with standing_edge(tmp_path) as edge:
        dev = await edge.rig.developer()
        gate = edge.rig.host.block("sandbox.create")
        first = asyncio.create_task(edge.post(project_path(dev, "/sandboxes"), dev, key="k", json=SANDBOX_BODY))
        await until(lambda: any(s.method == "sandbox.create" for s in edge.rig.host.sent))
        second = await edge.post(project_path(dev, "/sandboxes"), dev, key="k", json=SANDBOX_BODY)
        body = assert_problem(second, "REQUEST_IN_PROGRESS", retry="SAME_REQUEST_LATER")
        assert body["idempotency_key"] == "k"
        gate.set()
        assert view_of(await first)["replayed"] is False
        assert len(edge.rig.host.mutating()) == 1


@decides("RATE_LIMITED")
@pytest.mark.proves("T3-API-02")
async def test_problem_rate_limited(tmp_path: Path) -> None:
    async with standing_edge(tmp_path, principal_rate=1) as edge:
        dev = await edge.rig.developer()
        view_of(await edge.post(project_path(dev, "/sandboxes"), dev, key="k1", json=SANDBOX_BODY))
        response = await edge.post(project_path(dev, "/sandboxes"), dev, key="k2", json=SANDBOX_BODY)
        assert_problem(response, "RATE_LIMITED", retry="SAME_REQUEST_LATER")
        assert len(edge.rig.host.mutating()) == 1


@decides("UNSUPPORTED")
@pytest.mark.proves("T3-API-02")
async def test_problem_unsupported(tmp_path: Path) -> None:
    async with standing_edge(tmp_path) as edge:
        dev = await edge.rig.developer()
        response = await edge.post(project_path(dev, "/sandboxes"), dev, key="k", json={**SANDBOX_BODY, "start": True})
        assert_problem(response, "UNSUPPORTED", retry="AFTER_CHANGE")


@decides("REQUEST_TOO_LARGE")
@pytest.mark.proves("T3-API-02")
async def test_problem_request_too_large(tmp_path: Path) -> None:
    async with standing_edge(tmp_path, limits={"max_public_request_bytes": 1024}) as edge:
        dev = await edge.rig.developer()
        response = await edge.post(
            project_path(dev, "/sandboxes"), dev, key="k", json={**SANDBOX_BODY, "name": "n" * 2000}
        )
        assert_problem(response, "REQUEST_TOO_LARGE", retry="NEVER")


@decides("CLOCK_SKEW")
@pytest.mark.proves("T3-API-02")
async def test_problem_clock_skew(tmp_path: Path) -> None:
    async with standing_edge(tmp_path) as edge:
        dev = await edge.rig.developer()
        edge.rig.host.clock_offset_ms = -31_000
        response = await edge.post(project_path(dev, "/sandboxes"), dev, key="k", json=SANDBOX_BODY)
        assert_problem(response, "CLOCK_SKEW", retry="SAME_REQUEST_LATER")
        assert edge.rig.host.sandboxes == {}


@decides("UPSTREAM_UNAVAILABLE")
@pytest.mark.proves("T3-API-02")
async def test_problem_upstream_unavailable_when_the_host_refuses_the_platform_itself(tmp_path: Path) -> None:
    """ERR-5: a fault of the platform's own enrolment is never the caller's authentication failure."""
    async with standing_edge(tmp_path) as edge:
        dev = await edge.rig.developer()
        edge.rig.host.refuse_platform = "AUTHENTICATION_FAILED"
        response = await edge.post(project_path(dev, "/sandboxes"), dev, key="k", json=SANDBOX_BODY)
        assert_problem(response, "UPSTREAM_UNAVAILABLE", retry="SAME_REQUEST_LATER")


@decides("OUTCOME_UNRESOLVED")
@pytest.mark.proves("T3-API-02")
async def test_problem_outcome_unresolved_names_the_key_to_ask_again_with(tmp_path: Path) -> None:
    """The host accepted, the answer was lost, and the host cannot be read: the platform cannot tell, and says so."""
    async with standing_edge(tmp_path) as edge:
        dev = await edge.rig.developer()
        edge.rig.host.fault("lost_after", "sandbox.create")
        edge.rig.host.fault("unreachable", "operation.get", times=edge.rig.config.parameters.host_resolve_attempts)
        response = await edge.post(project_path(dev, "/sandboxes"), dev, key="k-lost", json=SANDBOX_BODY)
        body = assert_problem(response, "OUTCOME_UNRESOLVED", retry="SAME_REQUEST_LATER")
        assert body["idempotency_key"] == "k-lost"
        again = await edge.post(project_path(dev, "/sandboxes"), dev, key="k-lost", json=SANDBOX_BODY)
        assert view_of(again)["replayed"] is True
        assert len(edge.rig.host.sandboxes) == 1


@decides("OUTCOME_LOST")
@pytest.mark.proves("T3-API-02")
async def test_problem_outcome_lost(tmp_path: Path) -> None:
    """ERR-7: the platform accepted the key, and the host, on another lineage now, holds no operation for it."""
    async with standing_edge(tmp_path) as edge:
        dev = await edge.rig.developer()
        edge.rig.host.hold.add("sandbox.create")
        assert (
            await edge.post(project_path(dev, "/sandboxes"), dev, key="k-gone", json=SANDBOX_BODY, params={"wait": 0})
        ).status_code == 202
        edge.rig.host.replace_lineage()
        response = await edge.post(
            project_path(dev, "/sandboxes"), dev, key="k-gone", json=SANDBOX_BODY, params={"wait": 0}
        )
        body = assert_problem(response, "OUTCOME_LOST", retry="NEVER")
        assert body["idempotency_key"] == "k-gone"
        assert edge.rig.host.mutating()[-1].method == "sandbox.create"
        assert len(edge.rig.host.mutating()) == 1, "a lost outcome is never resubmitted"


@decides("INTERNAL_ERROR")
@pytest.mark.proves("T3-API-02")
async def test_problem_internal_error_is_a_refusal_only_while_nothing_was_sent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """§15.2: `INTERNAL_ERROR` is REFUSED if nothing was sent; otherwise the answer is `OUTCOME_UNRESOLVED` (ERR-1)."""
    async with standing_edge(tmp_path) as edge:
        dev = await edge.rig.developer()
        host = edge.rig.host

        async def broken_read(*_: Any, **__: Any) -> Any:
            raise RuntimeError("the platform fails while it reads")

        with monkeypatch.context() as patch:
            patch.setattr(host, "read", broken_read)
            read = await edge.get(project_path(dev, "/sandboxes"), dev)
        assert_problem(read, "INTERNAL_ERROR", retry="AFTER_CHANGE")

        submit = host.submit

        async def accepted_then_broken(*args: Any, **kwargs: Any) -> Any:
            await submit(*args, **kwargs)
            raise RuntimeError("the platform fails after the host accepted")

        with monkeypatch.context() as patch:
            patch.setattr(host, "submit", accepted_then_broken)
            sent = await edge.post(project_path(dev, "/sandboxes"), dev, key="k-sent", json=SANDBOX_BODY)
        body = assert_problem(sent, "OUTCOME_UNRESOLVED", retry="SAME_REQUEST_LATER")
        assert body["idempotency_key"] == "k-sent"
        again = await edge.post(project_path(dev, "/sandboxes"), dev, key="k-sent", json=SANDBOX_BODY)
        assert view_of(again)["replayed"] is True
        assert len(host.sandboxes) == 1


HOST_CLASSES = {
    "INVALID_REQUEST": "NEVER",
    "SAFETY_CONTROL_DENIED": "AFTER_CHANGE",
    "NOT_FOUND": "NEVER",
    "STATE_CONFLICT": "AFTER_CHANGE",
    "QUARANTINED": "AFTER_CHANGE",
    "REVISION_CONFLICT": "AFTER_CHANGE",
    "RESOURCE_EXHAUSTED": "SAME_REQUEST_LATER",
    "HOST_NOT_SERVING": "SAME_REQUEST_LATER",
    "UNSUPPORTED": "AFTER_CHANGE",
    "INTEGRITY_FAILURE": "AFTER_CHANGE",
    "INCOMPATIBLE_RUNTIME": "AFTER_CHANGE",
    "INTERNAL_ERROR": "AFTER_CHANGE",
}


def test_the_host_classes_below_are_the_ones_the_table_lets_the_host_decide() -> None:
    by_host = {code for code, row in CONTRACT_TABLE.items() if row.decided_by in {"host", "either"}}
    # `CURSOR_EXPIRED` refuses a list and has a test of its own.
    assert set(HOST_CLASSES) | {"CURSOR_EXPIRED"} == by_host


@pytest.mark.parametrize("host_class", sorted(HOST_CLASSES))
@pytest.mark.proves("T3-API-02")
async def test_a_refusal_of_the_host_keeps_its_class_and_advice_and_gets_the_status_of_the_table(
    edge: Edge, dev: Identity, host_class: str
) -> None:
    """ERR-4, T3-API-02: the host's class is the public code, unchanged; the platform maps none onto another."""
    edge.rig.host.refuse_next = (host_class, HOST_CLASSES[host_class], "the host refuses this request")
    response = await edge.post(project_path(dev, "/sandboxes"), dev, key="k", json=SANDBOX_BODY)
    body = assert_problem(response, host_class, retry=HOST_CLASSES[host_class])
    assert body["message"] == "the host refuses this request"
    assert edge.rig.host.sandboxes == {}
    # The refusal proved that nothing exists: the same key is a fresh attempt (ERR-8).
    again = await edge.post(project_path(dev, "/sandboxes"), dev, key="k", json=SANDBOX_BODY)
    assert view_of(again)["replayed"] is False


async def test_the_hosts_explanation_of_a_refusal_is_passed_on_unless_it_quotes_the_request(
    edge: Edge, dev: Identity
) -> None:
    """ERR-6: the host explains some refusals in the caller's own words; the code and the advice cross, those words do not."""
    sandbox_id = await started_sandbox(edge, dev)
    edge.rig.host.allowed_images = ["python"]
    edge.rig.host.allowed_env = []
    image = await edge.post(project_path(dev, "/sandboxes"), dev, key="k-image", json={**SANDBOX_BODY, "image": CANARY})
    variable = await edge.post(
        project_path(dev, f"/sandboxes/{sandbox_id}/executions"),
        dev,
        key="k-env",
        json={"expected_generation": 1, "argv": ["true"], "env": {CANARY: "value"}},
    )
    absent = await edge.get(project_path(dev, f"/operations/op-{CANARY}"), dev)
    for response, code, retry in (
        (image, "SAFETY_CONTROL_DENIED", "AFTER_CHANGE"),
        (variable, "SAFETY_CONTROL_DENIED", "AFTER_CHANGE"),
        (absent, "NOT_FOUND", "NEVER"),
    ):
        assert_problem(response, code, retry=retry)
        assert CANARY not in response.text
    # The model host said what the real host says: its own words did quote the request each time.
    assert edge.rig.core.telemetry.get("host_messages_withheld", host_class="SAFETY_CONTROL_DENIED") == 2
    assert edge.rig.core.telemetry.get("host_messages_withheld", host_class="NOT_FOUND") == 1

    # An explanation that quotes nothing is the caller's to read, as the host gave it.
    view_of(await edge.post(project_path(dev, "/sandboxes"), dev, key="k-one", json={**SANDBOX_BODY, "name": "taken"}))
    taken = await edge.post(project_path(dev, "/sandboxes"), dev, key="k-two", json={**SANDBOX_BODY, "name": "taken"})
    assert assert_problem(taken, "STATE_CONFLICT")["message"] == "a sandbox with that name already exists in this scope"


@pytest.mark.proves("T3-API-02")
async def test_a_cursor_the_host_no_longer_serves_is_cursor_expired(edge: Edge, dev: Identity) -> None:
    await create_sandbox(edge, dev)
    page = view_of(await edge.get(project_path(dev, "/sandboxes"), dev))
    edge.rig.host.lineage = "lineage-after"
    response = await edge.get(project_path(dev, "/sandboxes"), dev, params={"cursor": page["next_cursor"]})
    assert_problem(response, "CURSOR_EXPIRED", retry="AFTER_CHANGE")


@pytest.mark.parametrize(("retry", "status"), [("NEVER", 400), ("AFTER_CHANGE", 409), ("SAME_REQUEST_LATER", 503)])
@pytest.mark.proves("T3-API-02")
async def test_a_class_this_version_does_not_know_is_shown_as_unrecognized_and_handled_by_its_advice(
    edge: Edge, dev: Identity, retry: str, status: int
) -> None:
    """ERR-4, PUB-6: never mapped onto a known class; the raw value travels beside it."""
    edge.rig.host.refuse_next = ("BRAND_NEW_CLASS", retry, "a refusal of a later host")
    response = await edge.post(project_path(dev, "/sandboxes"), dev, key="k", json=SANDBOX_BODY)
    body = problem_of(response)
    assert response.status_code == status
    assert (body["code"], body["code_raw"], body["kind"], body["retry"]) == (
        "UNRECOGNIZED",
        "BRAND_NEW_CLASS",
        "REFUSED",
        retry,
    )
    assert body.keys() >= PROBLEM_MEMBERS
    assert body["type"] == "urn:acf:problem:unrecognized"


# =============================================================================== the request id
async def test_every_response_carries_a_request_id_of_its_own(edge: Edge, dev: Identity) -> None:
    """B21: `request_id` on every response: a view, a problem, an unknown path, a wrong method, liveness."""
    sandbox = await create_sandbox(edge, dev)
    await edge.get(project_path(dev, f"/sandboxes/{sandbox['sandbox_id']}"), dev)
    await edge.get("/v1/info")
    await edge.get("/v1/auth/whoami")
    await edge.get("/v1/auth/whoami", dev, params={"nope": "1"})
    await edge.post(project_path(dev, "/sandboxes"), dev, json=SANDBOX_BODY)
    await edge.get("/v1/nothing-here", dev)
    await edge.request("PUT", "/v1/info", dev)
    await edge.get("/healthz")
    assert len(edge.responses) == 9
    ids = [response.headers.get("x-request-id", "") for response in edge.responses]
    assert all(REQUEST_ID.fullmatch(value) for value in ids), ids
    assert len(set(ids)) == len(ids)


# =============================================================================== strict bodies
def _raw(text: str) -> bytes:
    return text.encode("utf-8")


#: Bodies of a create that the strict profile or the schema refuses. Each plants the canary where a careless
#: message would repeat it: in a member name, in a value, in a key of a mapping.
REFUSED_BODIES: dict[str, bytes] = {
    "repeated-member": _raw(
        '{"image":"python","image":"' + CANARY + '","resources":{"vcpus":1,"memory_mib":512,"disk_mib":1024}}'
    ),
    "repeated-member-nested": _raw(
        '{"image":"python","resources":{"vcpus":1,"vcpus":2,"memory_mib":512,"disk_mib":1024,"' + CANARY + '":1}}'
    ),
    "unknown-member": _raw(
        '{"image":"python","resources":{"vcpus":1,"memory_mib":512,"disk_mib":1024},"' + CANARY + '":true}'
    ),
    "unknown-member-nested": _raw(
        '{"image":"python","resources":{"vcpus":1,"memory_mib":512,"disk_mib":1024,"' + CANARY + '":1}}'
    ),
    "wrong-type-string-for-number": _raw(
        '{"image":"python","resources":{"vcpus":"' + CANARY + '","memory_mib":512,"disk_mib":1024}}'
    ),
    "wrong-type-number-for-string": _raw(
        '{"image":7,"resources":{"vcpus":1,"memory_mib":512,"disk_mib":1024},"name":"' + CANARY + '"}'
    ),
    "wrong-type-boolean-for-number": _raw(
        '{"image":"python","resources":{"vcpus":true,"memory_mib":512,"disk_mib":1024}}'
    ),
    "wrong-type-fraction-for-integer": _raw(
        '{"image":"python","resources":{"vcpus":1.5,"memory_mib":512,"disk_mib":1024}}'
    ),
    "wrong-type-array-for-object": _raw('{"image":"python","resources":["' + CANARY + '"]}'),
    "number-below-range": _raw('{"image":"python","resources":{"vcpus":0,"memory_mib":512,"disk_mib":1024}}'),
    "number-above-range": _raw('{"image":"python","resources":{"vcpus":256,"memory_mib":512,"disk_mib":1024}}'),
    "number-beyond-any-integer": _raw(
        '{"image":"python","resources":{"vcpus":1e400,"memory_mib":512,"disk_mib":1024}}'
    ),
    "number-with-five-thousand-digits": _raw(
        '{"image":"python","resources":{"vcpus":' + "9" * 5000 + ',"memory_mib":512,"disk_mib":1024}}'
    ),
    "value-outside-its-pattern": _raw(
        '{"image":"python","resources":{"vcpus":1,"memory_mib":512,"disk_mib":1024},"name":"'
        + CANARY
        + ' with spaces"}'
    ),
    "value-outside-its-vocabulary": _raw(
        '{"image":"python","resources":{"vcpus":1,"memory_mib":512,"disk_mib":1024},"network":{"mode":"'
        + CANARY
        + '"}}'
    ),
    "missing-member": _raw('{"image":"python"}'),
    "not-json": _raw(CANARY + " is not JSON"),
    "truncated": _raw('{"image":"' + CANARY),
    "not-an-object": _raw('["' + CANARY + '"]'),
    "a-string": _raw('"' + CANARY + '"'),
    "null": b"null",
    "empty": b"",
    "nan": _raw('{"image":"python","resources":{"vcpus":NaN,"memory_mib":512,"disk_mib":1024}}'),
    "infinity": _raw('{"image":"python","resources":{"vcpus":Infinity,"memory_mib":512,"disk_mib":1024}}'),
    "invalid-utf8": b'{"image":"\xff\xfe'
    + CANARY.encode()
    + b'","resources":{"vcpus":1,"memory_mib":512,"disk_mib":1024}}',
    "byte-order-mark": b"\xef\xbb\xbf"
    + _raw('{"image":"python","resources":{"vcpus":1,"memory_mib":512,"disk_mib":1024}}'),
    "nested-too-deep": _raw('{"image":"python","resources":' + "[" * 40 + '"' + CANARY + '"' + "]" * 40 + "}"),
    "trailing-content": _raw(
        '{"image":"python","resources":{"vcpus":1,"memory_mib":512,"disk_mib":1024}} "' + CANARY + '"'
    ),
}


@pytest.mark.parametrize("name", sorted(REFUSED_BODIES))
@pytest.mark.proves("T3-VER-02")
async def test_a_body_outside_the_strict_profile_or_the_schema_is_refused_without_repeating_it(
    edge: Edge, dev: Identity, name: str
) -> None:
    """DATA-7, VER-3, ERR-6, T3-VER-02: refused with `INVALID_REQUEST`, by the edge, in words that are its own."""
    response = await edge.post(
        project_path(dev, "/sandboxes"),
        dev,
        key="k-body",
        content=REFUSED_BODIES[name],
        headers={"Content-Type": "application/json"},
    )
    assert_problem(response, "INVALID_REQUEST", retry="NEVER")
    assert CANARY not in response.text
    assert CANARY not in str(response.headers)
    assert edge.core.count("handle") == 0, "a body the edge cannot decode is never passed on"
    assert edge.rig.host.mutating() == []


async def test_the_same_body_without_its_fault_is_accepted(edge: Edge, dev: Identity) -> None:
    """The control of the test above: what is refused there is refused for its fault and for nothing else."""
    for number, content_type in enumerate(("application/json", "application/json; charset=utf-8", "Application/JSON")):
        body = _raw(
            '{"image":"python","resources":{"vcpus":1,"memory_mib":512,"disk_mib":1024},"name":"fine-'
            + str(number)
            + '"}'
        )
        response = await edge.post(
            project_path(dev, "/sandboxes"),
            dev,
            key=f"k-{number}",
            content=body,
            headers={"Content-Type": content_type},
        )
        assert view_of(response)["result"]["sandbox"]["name"] == f"fine-{number}"
    assert len(edge.rig.host.sandboxes) == 3


@pytest.mark.parametrize(
    ("label", "body"),
    [
        ("an-unknown-member-of-an-execution", {"expected_generation": 1, "argv": ["true"], CANARY: 1}),
        (
            "a-mapping-key-outside-its-pattern",
            {"expected_generation": 1, "argv": ["true"], "env": {f"{CANARY} =": "v"}},
        ),
        ("a-mapping-value-of-the-wrong-type", {"expected_generation": 1, "argv": ["true"], "env": {"NAME": [CANARY]}}),
        ("an-item-of-the-wrong-type", {"expected_generation": 1, "argv": ["true", {CANARY: 1}]}),
        (
            "an-unknown-member-of-a-secret-reference",
            {"expected_generation": 1, "argv": ["true"], "secret_env": {"S": {"ref": "r", CANARY: 1}}},
        ),
    ],
)
@pytest.mark.proves("T3-VER-02")
async def test_what_the_caller_named_is_never_repeated_either(
    edge: Edge, dev: Identity, label: str, body: dict[str, Any]
) -> None:
    """ERR-6: a refusal says where the schema was not met in the schema's own names, never in the caller's."""
    sandbox_id = await started_sandbox(edge, dev)
    response = await edge.post(project_path(dev, f"/sandboxes/{sandbox_id}/executions"), dev, key="k-exec", json=body)
    assert_problem(response, "INVALID_REQUEST")
    assert CANARY not in response.text, label


@pytest.mark.parametrize(
    "content_type", ["text/plain", "application/x-www-form-urlencoded", "application/problem+json", None]
)
async def test_a_body_that_is_not_declared_as_json_is_refused(
    edge: Edge, dev: Identity, content_type: str | None
) -> None:
    headers = {"Content-Type": content_type} if content_type is not None else {}
    body = _raw('{"image":"python","resources":{"vcpus":1,"memory_mib":512,"disk_mib":1024}}')
    response = await edge.post(project_path(dev, "/sandboxes"), dev, key="k", content=body, headers=headers)
    assert assert_problem(response, "INVALID_REQUEST")["reason"] == "content_type"
    assert edge.rig.host.mutating() == []


@pytest.mark.parametrize("spec", BODILESS_ROUTES, ids=method_of)
@pytest.mark.proves("T3-VER-02")
async def test_a_body_on_a_route_that_takes_none_is_refused(edge: Edge, dev: Identity, spec: RouteSpec) -> None:
    """VER-3 for routes without a body: what a caller sends and nobody reads would be silently ignored."""
    world = await build_world(edge, dev)
    handled, sent = edge.core.count("handle"), len(edge.rig.host.sent)
    response = await call_route(edge, world, spec, dev, json={CANARY: True})
    assert assert_problem(response, "INVALID_REQUEST")["reason"] == "body"
    assert CANARY not in response.text
    assert edge.core.count("handle") == handled
    assert len(edge.rig.host.sent) == sent


async def test_a_platform_credential_inside_a_body_is_refused_and_not_repeated(edge: Edge, dev: Identity) -> None:
    """SEC-118, SEC-105: the refusal of a request that carries a key does not carry the key."""
    planted = keys.generate_key("developer")
    response = await edge.post(
        project_path(dev, "/sandboxes"), dev, key="k", json={**SANDBOX_BODY, "image": f"python-{planted}"}
    )
    assert assert_problem(response, "INVALID_REQUEST")["reason"] == "credential_in_request"
    assert planted not in response.text
    assert edge.rig.host.mutating() == []


# =============================================================================== the query string
@pytest.mark.parametrize(
    ("label", "params"),
    [
        ("unknown", [(CANARY, "1")]),
        ("unknown-beside-a-known-one", [("limit", "5"), ("offset", CANARY)]),
        ("repeated", [("limit", "5"), ("limit", "6")]),
        ("not-a-number", [("limit", CANARY)]),
        ("negative", [("limit", "-1")]),
        ("below-its-range", [("limit", "0")]),
        ("above-its-range", [("limit", "1001")]),
        ("a-fraction", [("limit", "1.5")]),
        ("digits-of-another-script", [("limit", "٣")]),
        ("an-empty-cursor", [("cursor", "")]),
    ],
)
@pytest.mark.proves("T3-VER-02")
async def test_a_query_parameter_the_route_does_not_define_or_cannot_read_is_refused(
    edge: Edge, dev: Identity, label: str, params: list[tuple[str, str]]
) -> None:
    response = await edge.get(project_path(dev, "/sandboxes"), dev, params=params)
    assert assert_problem(response, "INVALID_REQUEST")["reason"] == "query", label
    assert CANARY not in response.text
    assert edge.core.count("handle") == 0


async def test_a_cursor_this_platform_did_not_issue_is_refused(edge: Edge, dev: Identity) -> None:
    response = await edge.get(project_path(dev, "/sandboxes"), dev, params={"cursor": CANARY})
    assert assert_problem(response, "INVALID_REQUEST")["reason"] == "cursor"
    assert CANARY not in response.text


async def test_a_required_query_parameter_and_a_wait_outside_its_range_are_refused(edge: Edge, dev: Identity) -> None:
    sandbox = await create_sandbox(edge, dev)
    path = project_path(dev, f"/sandboxes/{sandbox['sandbox_id']}")
    missing = await edge.delete(path, dev, key="k-destroy")
    bad_generation = await edge.delete(path, dev, key="k-destroy", params={"expected_generation": "latest"})
    long_wait = await edge.delete(path, dev, key="k-destroy", params={"expected_generation": 1, "wait": 3601})
    for response in (missing, bad_generation, long_wait):
        assert assert_problem(response, "INVALID_REQUEST")["reason"] == "query"
    assert view_of(await edge.get(path, dev))["state"] == "PROVISIONING"


@pytest.mark.parametrize(
    "name", ["access_token", "api_key", "apikey", "key", "token", "authorization", "Access_Token", "TOKEN"]
)
@pytest.mark.proves("T3-SEC-05")
async def test_a_credential_in_a_query_parameter_is_refused_before_the_core_is_asked(
    edge: Edge, dev: Identity, name: str
) -> None:
    """SEC-105: a credential is never accepted from a URL, even a valid one, even beside a valid header."""
    for who in (None, dev):
        response = await edge.get(project_path(dev, "/sandboxes"), who, params={name: dev.key})
        assert assert_problem(response, "INVALID_REQUEST")["reason"] == "credential_in_url"
        assert dev.key not in response.text
        assert dev.key not in str(response.headers)
    assert edge.core.seen == []
    anonymous = await edge.get("/v1/info", params={name: dev.key})
    assert assert_problem(anonymous, "INVALID_REQUEST")["reason"] == "credential_in_url"


# =============================================================================== bounded before parsed
class Upload:
    """A request body that arrives in pieces and counts how many of them the server took."""

    def __init__(self, pieces: list[bytes], *, pause_s: float = 0.0) -> None:
        self._pieces = pieces
        self._pause_s = pause_s
        self.taken = 0

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for piece in self._pieces:
            if self._pause_s and self.taken:
                await asyncio.sleep(self._pause_s)
            self.taken += 1
            yield piece


@pytest.mark.proves("T3-SEC-04")
async def test_an_oversize_body_is_refused_by_its_declared_length_before_a_byte_is_read(tmp_path: Path) -> None:
    """SEC-104, T3-SEC-04: `Content-Length` above the bound costs a count and nothing else."""
    async with standing_edge(tmp_path, limits={"max_public_request_bytes": 1024}) as edge:
        dev = await edge.rig.developer()
        upload = Upload([b"x" * 512] * 4)
        response = await edge.post(
            project_path(dev, "/sandboxes"),
            dev,
            key="k",
            content=upload,
            headers={"Content-Type": "application/json", "Content-Length": "2048"},
        )
        assert_problem(response, "REQUEST_TOO_LARGE", retry="NEVER")
        assert upload.taken == 0
        assert edge.core.count("handle") == 0


@pytest.mark.proves("T3-SEC-04")
async def test_an_oversize_body_without_a_declared_length_is_refused_as_soon_as_it_passes_the_bound(
    tmp_path: Path,
) -> None:
    """SEC-104: the bound applies to a body that arrives in pieces, and the rest of it is never taken or parsed."""
    async with standing_edge(tmp_path, limits={"max_public_request_bytes": 1024}) as edge:
        dev = await edge.rig.developer()
        upload = Upload([b"{" * 100] * 1000)
        response = await edge.post(
            project_path(dev, "/sandboxes"), dev, key="k", content=upload, headers={"Content-Type": "application/json"}
        )
        # Not `INVALID_REQUEST`: the bytes were never parsed, so nobody found out that they are not JSON.
        assert_problem(response, "REQUEST_TOO_LARGE")
        assert upload.taken <= 12, upload.taken
        assert edge.core.count("handle") == 0


@pytest.mark.proves("T3-SEC-04")
async def test_a_body_at_the_bound_is_read_and_one_byte_more_is_not(tmp_path: Path) -> None:
    async with standing_edge(tmp_path, limits={"max_public_request_bytes": 1024}) as edge:
        dev = await edge.rig.developer()
        stem = _raw('{"image":"python","resources":{"vcpus":1,"memory_mib":512,"disk_mib":1024}}')
        at_bound = stem + b" " * (1024 - len(stem))
        accepted = await edge.post(
            project_path(dev, "/sandboxes"),
            dev,
            key="k1",
            content=at_bound,
            headers={"Content-Type": "application/json"},
        )
        view_of(accepted)
        refused = await edge.post(
            project_path(dev, "/sandboxes"),
            dev,
            key="k2",
            content=at_bound + b" ",
            headers={"Content-Type": "application/json"},
        )
        assert_problem(refused, "REQUEST_TOO_LARGE")


@pytest.mark.proves("T3-SEC-04")
async def test_a_body_that_arrives_too_slowly_is_refused_and_other_callers_are_not_held_up(tmp_path: Path) -> None:
    """SEC-104, T3-SEC-04: a slow upload holds one request for a bounded time; authenticated traffic is unaffected."""
    async with standing_edge(tmp_path, limits={"body_read_timeout": 0.3}) as edge:
        dev = await edge.rig.developer()
        upload = Upload([b'{"image":', b'"python"}'], pause_s=30.0)
        started = time.monotonic()
        slow = asyncio.create_task(
            edge.post(
                project_path(dev, "/sandboxes"),
                dev,
                key="k-slow",
                content=upload,
                headers={"Content-Type": "application/json"},
            )
        )
        await until(lambda: upload.taken == 1)
        meanwhile = await edge.get("/v1/auth/whoami", dev)
        assert view_of(meanwhile)["project_id"] == dev.project_id
        assert not slow.done()
        response = await asyncio.wait_for(slow, 3.0)
        assert 0.25 <= time.monotonic() - started < 3.0
        assert assert_problem(response, "INVALID_REQUEST")["reason"] == "slow_body"
        assert edge.core.count("handle") == 1, "only the other caller's request was passed on"
        assert edge.rig.host.mutating() == []


@pytest.mark.proves("T3-SEC-04")
async def test_the_credential_is_checked_before_a_body_is_read(edge: Edge, dev: Identity) -> None:
    """EC-3, SVC-1: authentication precedes decoding. An unauthenticated caller cannot make the edge read or parse."""
    for who in (None, keys.generate_key("developer"), "not-a-key"):
        upload = Upload([_raw(CANARY + " is not JSON")] * 3)
        response = await edge.post(
            project_path(dev, "/sandboxes"), who, key="k", content=upload, headers={"Content-Type": "application/json"}
        )
        # The body would be refused as `INVALID_REQUEST`. The answer shows that nobody looked at it.
        assert_problem(response, "UNAUTHENTICATED")
        assert upload.taken == 0
    assert [seen.op for seen in edge.core.seen] == ["verify"] * 3

    # The control: with a credential that authenticates, the same body is read and refused for what it is.
    upload = Upload([_raw(CANARY + " is not JSON")] * 3)
    response = await edge.post(
        project_path(dev, "/sandboxes"), dev, key="k", content=upload, headers={"Content-Type": "application/json"}
    )
    assert_problem(response, "INVALID_REQUEST")
    assert upload.taken == 3


@pytest.mark.proves("T3-SEC-04")
async def test_requests_that_are_refused_before_anything_is_decided_leave_nothing_durable(
    edge: Edge, dev: Identity
) -> None:
    """SEC-104, IPS-13: an unauthenticated or malformed request leaves a counter and nothing in the store."""
    view_of(await edge.get("/v1/auth/whoami", dev))
    before = await edge.rig.admin("health")
    for attempt in range(50):
        assert (await edge.get(project_path(dev, "/sandboxes"), f"not-a-key-{attempt}")).status_code == 401
        assert (
            await edge.post(
                project_path(dev, "/sandboxes"),
                dev,
                key=f"k{attempt}",
                content=b"{",
                headers={"Content-Type": "application/json"},
            )
        ).status_code == 400
        assert (await edge.get(project_path(dev, "/sandboxes"), dev, params={"nope": attempt})).status_code == 400
    after = await edge.rig.admin("health")
    for part in ("ledger", "audit", "registry", "journal_records"):
        assert after[part] == before[part], part
    assert after["store"]["state_bytes"] == before["store"]["state_bytes"]
    assert after["store"]["audit_bytes"] == before["store"]["audit_bytes"]


# =============================================================================== paths and methods
@pytest.mark.parametrize(
    "path", ["/", "/v1", "/v2/info", "/v1/projects", "/v1/info/extra", "/v1/sandboxes", f"/{CANARY}"]
)
async def test_an_unknown_path_is_a_problem_document(edge: Edge, dev: Identity, path: str) -> None:
    response = await edge.get(path, dev)
    assert_problem(response, "NOT_FOUND", retry="NEVER")
    assert CANARY not in response.text
    assert edge.core.seen == []


@pytest.mark.parametrize("path", ["/v1/info/", "/v1/auth/whoami/"])
async def test_a_path_with_a_trailing_slash_is_an_unknown_path_and_not_a_redirect(
    edge: Edge, dev: Identity, path: str
) -> None:
    """A redirect would be an answer that is no problem document, and it would repeat the query string in `Location`."""
    response = await edge.get(path, dev, params={"access_token": dev.key})
    assert_problem(response, "NOT_FOUND")
    assert "location" not in response.headers
    assert dev.key not in str(response.headers)


@pytest.mark.parametrize(
    ("method", "path"),
    [("POST", "/v1/info"), ("PUT", "/v1/auth/whoami"), ("PATCH", "/v1/info"), ("DELETE", "/healthz")],
)
async def test_a_method_a_route_does_not_answer_is_a_problem_document(
    edge: Edge, dev: Identity, method: str, path: str
) -> None:
    response = await edge.request(method, path, dev)
    assert assert_problem(response, "INVALID_REQUEST")["reason"] == "method"
    assert "GET" in response.headers["allow"]
    assert edge.core.seen == []


@pytest.mark.parametrize(
    "path",
    [
        "/v1/projects/not-a-project/sandboxes",
        "/v1/projects/{project}/sandboxes/not-a-sandbox/start",
        "/v1/projects/{project}/snapshots/" + CANARY + "/restore",
    ],
)
async def test_an_identifier_outside_its_form_is_refused_by_the_edge(edge: Edge, dev: Identity, path: str) -> None:
    body = {"expected_generation": 1} if path.endswith("/start") else SANDBOX_BODY
    if path.endswith("/restore"):
        body = {"snapshot_generation": 1, "target": {"kind": "new"}}
    response = await edge.post(path.replace("{project}", dev.project_id), dev, key="k", json=body)
    assert_problem(response, "INVALID_REQUEST")
    assert CANARY not in response.text
    assert edge.core.count("handle") == 0


@pytest.mark.parametrize("spec", PROJECT_ROUTES, ids=method_of)
async def test_a_resource_name_with_another_project_is_not_found(edge: Edge, dev: Identity, spec: RouteSpec) -> None:
    """SEC-101, SVC-3: the project in the name is accepted only on the credential's binding; nothing of the other is shown."""
    world = await build_world(edge, dev)
    stranger = await edge.rig.developer("stranger")
    sent = len(edge.rig.host.sent)
    response = await call_route(edge, world, spec, stranger)
    body = assert_problem(response, "NOT_FOUND", retry="NEVER")
    assert dev.project_id not in body["message"]
    assert len(edge.rig.host.sent) == sent, "nothing was asked of the host for a project the credential is not bound to"


# =============================================================================== info and liveness
async def test_info_without_a_credential_shows_only_the_api_versions_and_whether_the_platform_serves(
    edge: Edge,
) -> None:
    """PUB-8, B21: the public API versions and the platform's own health, and nothing else."""
    response = await edge.get("/v1/info")
    assert view_of(response) == {"api_versions": ["v1"], "serving": True}
    assert [seen.op for seen in edge.core.seen] == ["handle"]
    assert edge.core.seen[0].credential is None


@pytest.mark.proves("T3-RED-08")
async def test_info_without_a_credential_is_the_same_bytes_whatever_the_host_and_other_projects_do(
    edge: Edge, dev: Identity
) -> None:
    """SEC-124, T3-RED-08 for an anonymous client: no answer to an unauthenticated caller depends on host state."""
    host = edge.rig.host
    first = await edge.get("/v1/info")
    sent = len(host.sent)

    # Another project works; then the host changes in every way it can.
    await started_sandbox(edge, dev)
    host.features.remove("scope_tags")
    host.protocols[:] = ["acf.host/9"]
    host.max_vcpus = 1
    edge.rig.clock.advance(edge.rig.config.parameters.host_info_ttl + 1)
    assert view_of(await edge.get("/v1/info", dev))["ready"] is False
    host.replace_lineage()
    host.refuse_platform = "AUTHENTICATION_FAILED"
    host.fault("unreachable", None, times=1000)
    sent_by_others = len(host.sent) - sent

    second = await edge.get("/v1/info")
    assert second.content == first.content
    assert second.status_code == first.status_code == 200
    assert len(host.sent) - sent == sent_by_others, "an anonymous request caused a request to the host"


async def test_info_with_a_credential_shows_what_the_platform_offers_and_nothing_of_the_host_as_a_whole(
    edge: Edge, dev: Identity
) -> None:
    """PUB-8, HB-2: features, parameters and the ceilings of the caller's project; no count, mode or state of the host."""
    await started_sandbox(edge, dev)
    info = view_of(await edge.get("/v1/info", dev))
    assert set(info) == {
        "api_versions",
        "serving",
        "ready",
        "not_ready_reasons",
        "platform_features",
        "host_features",
        "parameters",
        "ceilings",
    }
    assert (info["ready"], info["not_ready_reasons"]) == (True, [])
    assert info["host_features"] == ["allowlist_network"]
    assert info["ceilings"]["vcpus"] == edge.rig.host.max_vcpus
    assert info["parameters"]["public_wait_max"] == edge.limits.public_wait_max
    text = str(info)
    for hidden in ("live_sandboxes", "mode", "lineage", "host_id", edge.rig.host.host_id, edge.rig.host.lineage):
        assert hidden not in text


async def test_an_invalid_credential_on_info_is_refused_and_not_treated_as_anonymous(edge: Edge) -> None:
    response = await edge.get("/v1/info", keys.generate_key("developer"))
    assert_problem(response, "UNAUTHENTICATED")


async def test_liveness_answers_without_the_core(edge: Edge) -> None:
    """Liveness is the edge process's alone: it asks the core nothing, so it answers when the core cannot."""
    edge.core.lose_next("before", op="verify")
    edge.core.lose_next("before", op="handle")
    response = await edge.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["cache-control"] == "no-store"
    assert edge.core.seen == []


# =============================================================================== capabilities
@pytest.mark.proves("T3-API-03")
async def test_a_capability_the_host_does_not_advertise_is_refused_as_unsupported_and_nothing_is_recorded(
    edge: Edge, dev: Identity
) -> None:
    """CG-1, T3-API-03: create with start, secret references and the allowlist mode, each refused before the host."""
    sandbox_id = await started_sandbox(edge, dev)
    sent = len(edge.rig.host.mutating())

    with_start = await edge.post(
        project_path(dev, "/sandboxes"), dev, key="k-start", json={**SANDBOX_BODY, "start": True}
    )
    assert assert_problem(with_start, "UNSUPPORTED", retry="AFTER_CHANGE")["reason"] == "create_with_start"

    secret = await edge.post(
        project_path(dev, f"/sandboxes/{sandbox_id}/executions"),
        dev,
        key="k-secret",
        json={"expected_generation": 1, "argv": ["env"], "secret_env": {"TOKEN": {"ref": "deploy-token"}}},
    )
    assert assert_problem(secret, "UNSUPPORTED", retry="AFTER_CHANGE")["reason"] == "secret_injection"

    edge.rig.host.features.remove("allowlist_network")
    edge.rig.clock.advance(edge.rig.config.parameters.host_info_ttl + 1)
    allowlist = {"mode": "allowlist", "entries": [{"name": "example.org", "ports": [{"from": 443, "to": 443}]}]}
    network = await edge.post(
        project_path(dev, "/sandboxes"), dev, key="k-net", json={**SANDBOX_BODY, "network": allowlist}
    )
    assert assert_problem(network, "UNSUPPORTED", retry="AFTER_CHANGE")["reason"] == "allowlist_network"

    assert len(edge.rig.host.mutating()) == sent
    # Nothing was claimed for a refused request: the key of each is free for a request the host can serve.
    plain = await edge.post(project_path(dev, "/sandboxes"), dev, key="k-start", json=SANDBOX_BODY)
    assert view_of(plain)["replayed"] is False


@pytest.mark.proves("T3-API-03")
async def test_secret_references_are_passed_on_once_the_host_advertises_secret_injection(
    edge: Edge, dev: Identity
) -> None:
    """CG-2: when a capability becomes advertised, its surface appears; the reference travels, never a secret."""
    sandbox_id = await started_sandbox(edge, dev)
    edge.rig.host.info_extra["capabilities"] = {
        **edge.rig.host.info_document()["capabilities"],
        "secret_injection": True,
    }
    edge.rig.clock.advance(edge.rig.config.parameters.host_info_ttl + 1)
    assert "secret_injection" in view_of(await edge.get("/v1/info", dev))["host_features"]
    ran = await edge.post(
        project_path(dev, f"/sandboxes/{sandbox_id}/executions"),
        dev,
        key="k-secret",
        json={"expected_generation": 1, "argv": ["env"], "secret_env": {"TOKEN": {"ref": "deploy-token"}}},
    )
    view_of(ran)
    assert edge.rig.host.mutating()[-1].params["command"]["secret_env"] == {"TOKEN": {"ref": "deploy-token"}}


# =============================================================================== what the edge writes
@pytest.mark.proves("T3-SEC-05")
async def test_no_credential_is_ever_written_into_an_answer_or_a_log_line(
    edge: Edge, dev: Identity, caplog: pytest.LogCaptureFixture
) -> None:
    """SEC-105, T3-SEC-05 for the edge: a credential that was presented appears in no response and no log record."""
    caplog.set_level(logging.DEBUG)
    planted = keys.generate_key("developer")
    world = await build_world(edge, dev)
    for who in (dev, planted):
        secret = who if isinstance(who, str) else who.key
        for spec in ROUTES:
            await call_route(edge, world, spec, who, key=f"k-{method_of(spec)}" if spec.operation.keyed else None)
        await edge.get("/v1/nothing-here", who)
        await edge.get(project_path(dev, "/sandboxes"), who, params={"token": secret})
        await edge.post(
            project_path(dev, "/sandboxes"), who, key="k", content=b"{", headers={"Content-Type": "application/json"}
        )
        # The edge itself fails, before and after the command was passed on.
        edge.core.break_next(RuntimeError("the client of the command interface failed"))
        await edge.get("/v1/auth/whoami", who)
        edge.core.answer_next(AckAnswer())
        await edge.get("/v1/auth/whoami", who)

    written = [response.text + str(response.headers) for response in edge.responses]
    # The HTTP client of this test logs the URLs it was told to call. What the platform logs is everything else.
    logged = [
        f"{record.getMessage()} {record.__dict__.get('fields', '')} {record.exc_text or ''}"
        for record in caplog.records
        if not record.name.startswith("httpx")
    ]
    assert logged, "the platform logged nothing, so nothing was searched"
    for secret in (dev.key, planted):
        assert not any(secret in text for text in written)
        assert not any(secret in line for line in logged)
