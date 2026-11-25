"""Sandbox and snapshot handles: they act on an identifier, state what they saw, and are updated by answers."""

from __future__ import annotations

from typing import Any

import pytest

from agentcompute import (
    AsyncFabric,
    Fabric,
    NameReboundError,
    NotFoundError,
    RevisionConflictError,
    UnexpectedResponseError,
)
from support import (
    EXE,
    OP,
    OP2,
    REQ,
    SBX,
    SBX2,
    SNP,
    SNP2,
    Harness,
    Json,
    done,
    ex,
    execution,
    operation,
    page,
    refusal,
    reply,
    sandbox,
    snapshot,
)


def _get(harness: Harness, fabric: Fabric | AsyncFabric, wanted: str = SBX) -> Any:
    return harness.run(fabric.sandboxes.get(wanted))


def _ran() -> Json:
    return reply(200, done("execution.create", "execution", execution()))


# --------------------------------------------------------------------------------------- reading a sandbox
def test_get_reads_one_sandbox_and_returns_a_handle_with_its_view(harness: Harness) -> None:
    view = sandbox("RUNNING", name="web", generation=4)
    script = harness.script(ex("GET", f"/sandboxes/{SBX}", reply(200, view, etag='"r14.0123456789ab"')))
    handle = _get(harness, harness.client(script))
    assert handle.raw == view
    assert (handle.sandbox_id, handle.name, handle.state, handle.generation) == (SBX, "web", "RUNNING", 4)
    assert handle.resources.memory_mib == 512
    assert handle.network.mode == "none"
    assert handle.request_id == REQ
    assert handle.operation is None
    assert repr(handle) in {
        f"Sandbox(sandbox_id='{SBX}', name='web', state='RUNNING', generation=4)",
        f"AsyncSandbox(sandbox_id='{SBX}', name='web', state='RUNNING', generation=4)",
    }


def test_refresh_reads_the_sandbox_again_and_updates_the_same_handle(harness: Harness) -> None:
    script = harness.script(
        ex("GET", f"/sandboxes/{SBX}", reply(200, sandbox("READY", generation=1))),
        ex("GET", f"/sandboxes/{SBX}", reply(200, sandbox("RUNNING", generation=2))),
    )
    handle = _get(harness, harness.client(script))
    assert harness.run(handle.refresh()) is handle
    assert (handle.state, handle.generation) == ("RUNNING", 2)


@pytest.mark.parametrize(
    ("wanted", "sent"),
    [
        ("my sandbox", "my%20sandbox"),
        ("a/b", "a%2Fb"),  # stays one segment
        ("../x", "..%2Fx"),
        ("...", "..."),
        ("a?b#c", "a%3Fb%23c"),
        ("caf" + chr(0xE9), "caf%C3%A9"),
    ],
)
def test_an_identifier_is_one_path_segment_whatever_it_holds(harness: Harness, wanted: str, sent: str) -> None:
    script = harness.script(ex("GET", f"/sandboxes/{wanted}", refusal("NOT_FOUND")))
    with pytest.raises(NotFoundError):
        _get(harness, harness.client(script), wanted)
    assert script.seen[0].raw_path == f"/v1/projects/prj_0000000000000001/sandboxes/{sent}"


# ------------------------------------------------------------------------------ handles state what they saw
def test_a_mutation_states_the_generation_the_handle_last_saw(harness: Harness) -> None:
    script = harness.script(
        ex("GET", f"/sandboxes/{SBX}", reply(200, sandbox(generation=7))),
        ex("POST", f"/sandboxes/{SBX}/executions", _ran(), json={"expected_generation": 7, "argv": ["true"]}),
    )
    handle = _get(harness, harness.client(script))
    harness.run(handle.exec(["true"]))


def test_current_is_sent_only_when_the_caller_says_so(harness: Harness) -> None:
    script = harness.script(
        ex("GET", f"/sandboxes/{SBX}", reply(200, sandbox(generation=7))),
        ex("POST", f"/sandboxes/{SBX}/executions", _ran(), json={"expected_generation": "current", "argv": ["true"]}),
        ex("POST", f"/sandboxes/{SBX}/executions", _ran(), json={"expected_generation": 9, "argv": ["true"]}),
        ex("POST", f"/sandboxes/{SBX}/executions", _ran(), json={"expected_generation": 7, "argv": ["true"]}),
    )
    handle = _get(harness, harness.client(script))
    harness.run(handle.exec(["true"], generation="current"))
    harness.run(handle.exec(["true"], generation=9))
    # Neither of the two changed what the handle saw.
    harness.run(handle.exec(["true"]))


def test_after_a_mutation_that_returns_the_sandbox_the_handle_holds_the_answer(harness: Harness) -> None:
    restored = done("snapshot.restore", "sandbox", sandbox("READY", generation=8), operation_id=OP2)
    script = harness.script(
        ex("GET", f"/sandboxes/{SBX}", reply(200, sandbox("RUNNING", generation=7))),
        ex("GET", "/snapshots", reply(200, page([snapshot(name="baseline", generation=2)]))),
        ex(
            "POST",
            f"/snapshots/{SNP}/restore",
            reply(200, restored),
            json={
                "snapshot_generation": 2,
                "target": {"kind": "existing", "sandbox_id": SBX, "expected_generation": 7},
            },
        ),
        ex("POST", f"/sandboxes/{SBX}/executions", _ran(), json={"expected_generation": 8, "argv": ["true"]}),
    )
    fabric = harness.client(script)
    handle = _get(harness, fabric)
    baseline = harness.run(fabric.snapshots.get("baseline"))
    assert harness.run(handle.restore(baseline)) is handle
    assert (handle.state, handle.generation) == ("READY", 8)
    assert handle.operation.operation_id == OP2
    harness.run(handle.exec(["true"]))


def test_a_handle_whose_sandbox_was_restored_elsewhere_is_refused_until_it_is_refreshed(harness: Harness) -> None:
    script = harness.script(
        ex("GET", f"/sandboxes/{SBX}", reply(200, sandbox(generation=1))),
        ex(
            "POST",
            f"/sandboxes/{SBX}/executions",
            refusal("REVISION_CONFLICT"),
            json={"expected_generation": 1, "argv": ["true"]},
        ),
        ex(
            "POST",
            f"/sandboxes/{SBX}/executions",
            refusal("REVISION_CONFLICT"),
            json={"expected_generation": 1, "argv": ["true"]},
        ),
        ex("GET", f"/sandboxes/{SBX}", reply(200, sandbox(generation=2))),
        ex("POST", f"/sandboxes/{SBX}/executions", _ran(), json={"expected_generation": 2, "argv": ["true"]}),
    )
    handle = _get(harness, harness.client(script))
    for _ in range(2):
        with pytest.raises(RevisionConflictError) as raised:
            harness.run(handle.exec(["true"]))
        assert raised.value.retry == "AFTER_CHANGE"
        assert handle.generation == 1  # the handle does not guess what changed
    harness.run(handle.refresh())
    assert harness.run(handle.exec(["true"])).execution_id == EXE


# ---------------------------------------------------------------------------------------- lifecycle calls
@pytest.mark.parametrize(("action", "state"), [("start", "RUNNING"), ("stop", "STOPPED")])
def test_start_and_stop_send_the_generation_and_take_the_answer(harness: Harness, action: str, state: str) -> None:
    ended = done(f"sandbox.{action}", "sandbox", sandbox(state, generation=3))
    script = harness.script(
        ex("GET", f"/sandboxes/{SBX}", reply(200, sandbox("READY", generation=3))),
        ex(
            "POST",
            f"/sandboxes/{SBX}/{action}",
            reply(200, ended),
            json={"expected_generation": 3},
            headers={"idempotency-key": "key-9"},
        ),
    )
    handle = _get(harness, harness.client(script))
    assert harness.run(getattr(handle, action)(idempotency_key="key-9")) is handle
    assert handle.state == state
    assert handle.operation.type == f"sandbox.{action}"


def test_destroy_states_the_generation_in_the_query_and_sends_no_body(harness: Harness) -> None:
    script = harness.script(
        ex("GET", f"/sandboxes/{SBX}", reply(200, sandbox("RUNNING", generation=5))),
        ex(
            "DELETE",
            f"/sandboxes/{SBX}",
            reply(200, done("sandbox.destroy", "sandbox", sandbox("DESTROYED", generation=5))),
            query={"expected_generation": "5"},
            json=None,
        ),
        ex(
            "DELETE",
            f"/sandboxes/{SBX}",
            reply(200, done("sandbox.destroy", "sandbox", sandbox("DESTROYED", generation=5))),
            query={"expected_generation": "current"},
        ),
    )
    handle = _get(harness, harness.client(script))
    harness.run(handle.destroy())
    assert handle.state == "DESTROYED"
    harness.run(handle.destroy(generation="current"))
    assert script.seen[1].key != script.seen[2].key


def test_snapshot_returns_a_handle_on_the_snapshot_and_leaves_the_sandbox_as_it_was(harness: Harness) -> None:
    taken = done("snapshot.create", "snapshot", snapshot("READY", name="baseline"), operation_id=OP2)
    script = harness.script(
        ex("GET", f"/sandboxes/{SBX}", reply(200, sandbox(generation=2))),
        ex(
            "POST",
            f"/sandboxes/{SBX}/snapshots",
            reply(200, taken),
            json={"expected_generation": 2, "name": "baseline"},
        ),
        ex("POST", f"/sandboxes/{SBX}/snapshots", reply(200, taken), json={"expected_generation": 2}),
    )
    handle = _get(harness, harness.client(script))
    taken_handle = harness.run(handle.snapshot("baseline"))
    assert (taken_handle.snapshot_id, taken_handle.name, taken_handle.snapshot_generation) == (SNP, "baseline", 1)
    assert taken_handle.operation.operation_id == OP2
    assert handle.operation is None
    harness.run(handle.snapshot())


def test_an_answer_about_another_sandbox_is_not_taken(harness: Harness) -> None:
    other = done("sandbox.start", "sandbox", sandbox("RUNNING", sandbox_id=SBX2))
    script = harness.script(
        ex("GET", f"/sandboxes/{SBX}", reply(200, sandbox("READY"))),
        ex("POST", f"/sandboxes/{SBX}/start", reply(200, other)),
    )
    handle = _get(harness, harness.client(script))
    with pytest.raises(UnexpectedResponseError, match="another sandbox"):
        harness.run(handle.start())
    assert (handle.sandbox_id, handle.state) == (SBX, "READY")


# ------------------------------------------------------------------------------- a name is resolved once
def test_a_name_is_resolved_once_and_the_handle_acts_on_the_identifier(harness: Harness) -> None:
    script = harness.script(
        ex("GET", "/sandboxes/web", reply(200, sandbox(name="web", generation=2))),
        ex("POST", f"/sandboxes/{SBX}/executions", _ran(), json={"expected_generation": 2, "argv": ["true"]}),
        ex(
            "POST",
            f"/sandboxes/{SBX}/stop",
            reply(200, done("sandbox.stop", "sandbox", sandbox("STOPPED", generation=2))),
        ),
        ex(
            "DELETE",
            f"/sandboxes/{SBX}",
            reply(200, done("sandbox.destroy", "sandbox", sandbox("DESTROYED", generation=2))),
        ),
    )
    handle = _get(harness, harness.client(script), "web")
    harness.run(handle.exec(["true"]))
    harness.run(handle.stop())
    harness.run(handle.destroy())
    assert all("/sandboxes/web" not in seen.path for seen in script.seen[1:])


def test_refresh_of_a_handle_obtained_by_name_looks_the_name_up_again(harness: Harness) -> None:
    script = harness.script(
        ex("GET", "/sandboxes/web", reply(200, sandbox("READY", name="web"))),
        ex("GET", "/sandboxes/web", reply(200, sandbox("RUNNING", name="web", generation=2))),
    )
    handle = _get(harness, harness.client(script), "web")
    harness.run(handle.refresh())
    assert (handle.sandbox_id, handle.state, handle.generation) == (SBX, "RUNNING", 2)


def test_a_name_that_now_belongs_to_another_sandbox_fails_the_refresh(harness: Harness) -> None:
    script = harness.script(
        ex("GET", "/sandboxes/web", reply(200, sandbox("RUNNING", name="web", generation=2))),
        ex("GET", "/sandboxes/web", reply(200, sandbox("READY", name="web", sandbox_id=SBX2))),
        ex("POST", f"/sandboxes/{SBX}/executions", _ran(), json={"expected_generation": 2, "argv": ["true"]}),
    )
    handle = _get(harness, harness.client(script), "web")
    with pytest.raises(NameReboundError) as raised:
        harness.run(handle.refresh())
    error = raised.value
    assert (error.name, error.sandbox_id, error.rebound_to) == ("web", SBX, SBX2)
    assert "rebind=True" in str(error)
    # The handle is untouched and still acts on the sandbox it resolved, never on the name.
    assert (handle.sandbox_id, handle.generation) == (SBX, 2)
    harness.run(handle.exec(["true"]))


def test_rebind_moves_the_handle_to_the_sandbox_that_holds_the_name_now(harness: Harness) -> None:
    script = harness.script(
        ex("GET", "/sandboxes/web", reply(200, sandbox("RUNNING", name="web", generation=2))),
        ex("GET", "/sandboxes/web", reply(200, sandbox("READY", name="web", sandbox_id=SBX2, generation=1))),
        ex(
            "POST",
            f"/sandboxes/{SBX2}/start",
            reply(200, done("sandbox.start", "sandbox", sandbox(sandbox_id=SBX2))),
            json={"expected_generation": 1},
        ),
    )
    handle = _get(harness, harness.client(script), "web")
    harness.run(handle.refresh(rebind=True))
    assert (handle.sandbox_id, handle.generation) == (SBX2, 1)
    harness.run(handle.start())


def test_a_handle_obtained_by_identifier_is_refreshed_by_identifier(harness: Harness) -> None:
    script = harness.script(
        ex("GET", f"/sandboxes/{SBX}", reply(200, sandbox(name="web"))),
        ex("GET", f"/sandboxes/{SBX}", reply(200, sandbox(name="web", generation=2))),
    )
    handle = _get(harness, harness.client(script))
    harness.run(handle.refresh())
    assert handle.generation == 2


# ---------------------------------------------------------------------------------- a handle that read nothing
def test_a_handle_made_without_a_request_holds_the_identifier_and_nothing_else(harness: Harness) -> None:
    script = harness.script(ex("GET", f"/sandboxes/{SBX}", reply(200, sandbox("RUNNING", generation=6))))
    fabric = harness.client(script)
    handle = fabric.sandboxes.handle(SBX)
    assert script.seen == []
    assert handle.sandbox_id == SBX
    assert handle.raw == {"sandbox_id": SBX}
    assert handle.request_id is None
    assert repr(handle).endswith(f"(sandbox_id='{SBX}')")
    with pytest.raises(UnexpectedResponseError, match="member 'state' of this view is missing"):
        _ = handle.state
    harness.run(handle.refresh())
    assert (handle.state, handle.generation) == ("RUNNING", 6)


# -------------------------------------------------------------------------------------------------- snapshots
def test_a_snapshot_is_found_by_identifier_or_by_name_in_the_listing(harness: Harness) -> None:
    listing = [snapshot(name="nightly"), snapshot(snapshot_id=SNP2, name="baseline", generation=3)]
    script = harness.script(
        ex("GET", "/snapshots", reply(200, page(listing))),
        ex("GET", "/snapshots", reply(200, page(listing[:1], more=True, cursor="s1"))),
        ex("GET", "/snapshots", reply(200, page(listing[1:])), query={"cursor": "s1"}),
    )
    fabric = harness.client(script)
    by_id = harness.run(fabric.snapshots.get(SNP2))
    by_name = harness.run(fabric.snapshots.get("baseline"))
    assert by_id.raw == by_name.raw == listing[1]
    assert (by_name.snapshot_id, by_name.snapshot_generation, by_name.request_id) == (SNP2, 3, REQ)


def test_an_identifier_wins_over_a_name_that_looks_like_it(harness: Harness) -> None:
    listing = [snapshot(snapshot_id=SNP2, name=SNP), snapshot(snapshot_id=SNP, name="real")]
    script = harness.script(ex("GET", "/snapshots", reply(200, page(listing))))
    assert harness.run(harness.client(script).snapshots.get(SNP)).name == "real"


def test_a_snapshot_the_project_does_not_list_is_not_found(harness: Harness) -> None:
    script = harness.script(ex("GET", "/snapshots", reply(200, page([snapshot(name="nightly")]))))
    with pytest.raises(NotFoundError, match="no snapshot") as raised:
        harness.run(harness.client(script).snapshots.get("baseline"))
    assert (raised.value.code, raised.value.kind, raised.value.retry) == ("NOT_FOUND", "REFUSED", "NEVER")
    assert raised.value.status is None


@pytest.mark.parametrize("wanted", ["", ".", ".."])
def test_a_dot_segment_is_never_an_identifier(harness: Harness, wanted: str) -> None:
    """A URL library resolves a dot segment into the path of another route before it sends anything."""
    script = harness.script()
    fabric = harness.client(script)
    with pytest.raises(ValueError, match="sandbox must name one record"):
        _get(harness, fabric, wanted)
    assert script.seen == []


def test_restore_takes_the_handle_of_a_snapshot_found_by_name(harness: Harness) -> None:
    restored = done("snapshot.restore", "sandbox", sandbox("READY", generation=2))
    script = harness.script(
        ex("GET", "/snapshots", reply(200, page([snapshot(snapshot_id=SNP2, name="baseline", generation=4)]))),
        ex(
            "POST",
            f"/snapshots/{SNP2}/restore",
            reply(200, restored),
            json={
                "snapshot_generation": 4,
                "target": {"kind": "existing", "sandbox_id": SBX, "expected_generation": 1},
            },
        ),
    )
    fabric = harness.client(script)
    handle = fabric.sandboxes.handle(SBX)
    baseline = harness.run(fabric.snapshots.get("baseline"))
    harness.run(handle.restore(baseline, generation=1))
    assert handle.generation == 2


def test_restore_does_not_resolve_a_name_by_itself(harness: Harness) -> None:
    script = harness.script()
    handle = harness.client(script).sandboxes.handle(SBX)
    name: Any = "baseline"
    with pytest.raises(ValueError, match="restore takes a snapshot handle"):
        harness.run(handle.restore(name, generation=1))
    assert script.seen == []


def test_a_snapshot_restores_as_a_new_sandbox(harness: Harness) -> None:
    created = done("snapshot.restore", "sandbox", sandbox("READY", sandbox_id=SBX2, name="copy"), operation_id=OP2)
    script = harness.script(
        ex("GET", "/snapshots", reply(200, page([snapshot(generation=2)]))),
        ex(
            "POST",
            f"/snapshots/{SNP}/restore",
            reply(200, created),
            json={"snapshot_generation": 2, "target": {"kind": "new", "name": "copy", "lifetime_seconds": 600}},
            headers={"idempotency-key": "key-new"},
        ),
        ex(
            "POST",
            f"/snapshots/{SNP}/restore",
            reply(200, created),
            json={"snapshot_generation": 2, "target": {"kind": "new"}},
        ),
    )
    fabric = harness.client(script)
    source = harness.run(fabric.snapshots.get(SNP))
    copy = harness.run(source.restore_as_new(name="copy", lifetime="10m", idempotency_key="key-new"))
    assert (copy.sandbox_id, copy.name, copy.generation) == (SBX2, "copy", 1)
    assert copy.operation is not None
    assert copy.operation.operation_id == OP2
    assert type(copy).__name__ in {"Sandbox", "AsyncSandbox"}
    harness.run(source.restore_as_new())


def test_deleting_a_snapshot_names_its_generation_and_takes_the_answer(harness: Harness) -> None:
    deleted = done("snapshot.delete", "snapshot", snapshot("DELETED", generation=2), operation_id=OP)
    script = harness.script(
        ex("GET", "/snapshots", reply(200, page([snapshot(generation=2)]))),
        ex("DELETE", f"/snapshots/{SNP}", reply(200, deleted), query={"snapshot_generation": "2"}, json=None),
    )
    fabric = harness.client(script)
    handle = harness.run(fabric.snapshots.get(SNP))
    assert harness.run(handle.delete()) is handle
    assert handle.state == "DELETED"
    assert handle.operation is not None
    assert handle.operation.type == "snapshot.delete"
    assert script.seen[1].key is not None


def test_a_snapshot_delete_that_did_not_succeed_leaves_the_handle_as_it_was(harness: Harness) -> None:
    script = harness.script(
        ex("GET", "/snapshots", reply(200, page([snapshot()]))),
        ex("DELETE", f"/snapshots/{SNP}", reply(200, operation("snapshot.delete", "FAILED", effect="NOT_APPLIED"))),
    )
    fabric = harness.client(script)
    handle = harness.run(fabric.snapshots.get(SNP))
    with pytest.raises(Exception, match="nothing was applied"):
        harness.run(handle.delete())
    assert handle.state == "READY"


def test_an_answer_about_another_snapshot_is_not_taken(harness: Harness) -> None:
    other = done("snapshot.delete", "snapshot", snapshot("DELETED", snapshot_id=SNP2))
    script = harness.script(
        ex("GET", "/snapshots", reply(200, page([snapshot()]))),
        ex("DELETE", f"/snapshots/{SNP}", reply(200, other)),
    )
    fabric = harness.client(script)
    handle = harness.run(fabric.snapshots.get(SNP))
    with pytest.raises(UnexpectedResponseError, match="another snapshot"):
        harness.run(handle.delete())
    assert (handle.snapshot_id, handle.state) == (SNP, "READY")
