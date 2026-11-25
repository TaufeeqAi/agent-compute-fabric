"""Views: every member of every schema, the JSON as received, and tolerance for what a later server sends.

The first tests are driven by the OpenAPI document itself: for every schema of a view, an instance is
generated from the schema, and the view class must expose every member it defines. A member added to
the API without a matching attribute here fails them.
"""

from __future__ import annotations

from typing import Any

import pytest

import agentcompute
from agentcompute import (
    Actor,
    AgentCredential,
    AllowEntryView,
    Ceilings,
    CredentialView,
    Durations,
    ExecutionView,
    Failure,
    Image,
    Info,
    NetworkView,
    Operation,
    OperationResult,
    OperationTarget,
    OutputChunk,
    OutputSummary,
    PortRangeView,
    ResourcesView,
    SandboxRef,
    SandboxView,
    SnapshotRef,
    SnapshotView,
    UnexpectedResponseError,
    View,
    WhoAmI,
)
from agentcompute.types import Member
from contract import CONTRACT
from support import OP, REQ, SBX, Harness, done, ex, execution, operation, problem, reply, sandbox, snapshot

#: Every view class and the schema of the OpenAPI document it is a view of.
_VIEWS: dict[type[View], str] = {
    Actor: "Actor",
    AgentCredential: "AgentCredential",
    AllowEntryView: "AllowEntryView",
    Ceilings: "Ceilings",
    CredentialView: "CredentialView",
    Durations: "Durations",
    ExecutionView: "Execution",
    Failure: "Failure",
    Image: "Image",
    Info: "Info",
    NetworkView: "NetworkView",
    Operation: "Operation",
    OperationResult: "OperationResult",
    OperationTarget: "OperationTarget",
    OutputChunk: "OutputChunk",
    OutputSummary: "OutputSummary",
    PortRangeView: "PortRangeView",
    ResourcesView: "ResourcesView",
    SandboxRef: "SandboxRef",
    SandboxView: "Sandbox",
    SnapshotRef: "SnapshotRef",
    SnapshotView: "Snapshot",
    WhoAmI: "WhoAmI",
}
#: Members whose name Python cannot use as an attribute, and the attribute that reads them.
_RENAMED = {"from": "first", "to": "last"}
_CASES = sorted(_VIEWS.items(), key=lambda item: item[1])
_IDS = [schema for _, schema in _CASES]


def _schema(name: str) -> dict[str, Any]:
    return CONTRACT.schemas[name]


def _example(schema: dict[str, Any], *, full: bool) -> Any:
    """A value the schema accepts: every member when ``full``, only the required ones otherwise."""
    if "$ref" in schema:
        return _example(_schema(schema["$ref"].rsplit("/", 1)[1]), full=full)
    if "const" in schema:
        return schema["const"]
    if "anyOf" in schema:
        options = [option for option in schema["anyOf"] if option.get("type") != "null"]
        return _example(options[0], full=full)
    kind = schema.get("type")
    if kind == "object":
        required = set(schema.get("required", ()))
        members = schema.get("properties", {})
        return {name: _example(member, full=full) for name, member in members.items() if full or name in required}
    if kind == "array":
        return [_example(schema["items"], full=full)] if full else []
    return {"string": "text", "integer": 7, "boolean": True, "number": 1.5}[str(kind)]


def _members(view: type[View]) -> dict[str, str]:
    """The members a view class reads: JSON key -> attribute name."""
    found: dict[str, str] = {}
    for klass in view.__mro__:
        for attribute, value in vars(klass).items():
            if isinstance(value, Member):
                found.setdefault(value._key or attribute, attribute)
    return found


def test_every_schema_that_is_a_view_has_a_class() -> None:
    answered = {"Sandbox", "Snapshot", "Execution", "Operation", "OutputChunk", "WhoAmI", "Info", "AgentCredential"}
    reachable = set(answered)
    frontier = list(answered)
    while frontier:
        text = str(_schema(frontier.pop()))
        for name in CONTRACT.schemas:
            if f"#/components/schemas/{name}'" in text and name not in reachable:
                reachable.add(name)
                frontier.append(name)
    assert reachable == set(_VIEWS.values())


@pytest.mark.parametrize(("view", "schema"), _CASES, ids=_IDS)
def test_a_view_exposes_every_member_of_its_schema_and_nothing_else(view: type[View], schema: str) -> None:
    defined = set(_schema(schema)["properties"])
    assert set(_members(view)) == defined
    for key, attribute in _members(view).items():
        assert attribute == _RENAMED.get(key, key)


@pytest.mark.parametrize("full", [True, False], ids=["every member", "required members only"])
@pytest.mark.parametrize(("view", "schema"), _CASES, ids=_IDS)
def test_every_member_of_a_view_can_be_read(view: type[View], schema: str, full: bool) -> None:
    raw = _example(_schema(schema), full=full)
    instance = view(raw, request_id=REQ)
    assert instance.raw is raw
    assert instance.request_id == REQ
    required = set(_schema(schema).get("required", ()))
    for key, attribute in _members(view).items():
        value = getattr(instance, attribute)
        if key not in raw:
            assert key not in required
            assert value in (None, (), {}, False), f"an absent {key} read as {value!r}"
        elif isinstance(raw[key], str | int | bool) or (isinstance(raw[key], dict) and not isinstance(value, View)):
            assert value == raw[key]
        elif isinstance(raw[key], list):
            assert len(value) == len(raw[key])
        else:
            assert isinstance(value, View)
            assert value.raw == raw[key]
    assert type(instance).__name__ in repr(instance)


@pytest.mark.parametrize(("view", "schema"), _CASES, ids=_IDS)
def test_a_missing_required_member_is_reported_when_it_is_read_and_only_then(view: type[View], schema: str) -> None:
    required = _schema(schema).get("required", [])
    full = _example(_schema(schema), full=True)
    for key in required:
        raw = {name: value for name, value in full.items() if name != key}
        instance = view(raw)  # building the view reads nothing
        with pytest.raises(UnexpectedResponseError, match=f"member '{key}' of this view is missing"):
            getattr(instance, _RENAMED.get(key, key))


@pytest.mark.parametrize(("view", "schema"), _CASES, ids=_IDS)
def test_a_member_of_the_wrong_json_type_is_not_read_as_something_else(view: type[View], schema: str) -> None:
    for key, attribute in _members(view).items():
        raw = _example(_schema(schema), full=True)
        raw[key] = 1.5 if not isinstance(raw[key], float) else "text"
        with pytest.raises(UnexpectedResponseError, match=f"member '{key}'"):
            getattr(view(raw), attribute)


def test_a_boolean_is_not_an_integer_and_an_integer_is_not_a_boolean() -> None:
    with pytest.raises(UnexpectedResponseError, match="'generation'"):
        _ = SandboxView(sandbox(generation=True)).generation
    with pytest.raises(UnexpectedResponseError, match="'terminal'"):
        _ = Operation({**operation(), "terminal": 1}).terminal


@pytest.mark.parametrize("identifier", ["", ".", "..", None, 5])
def test_an_identifier_is_never_empty_and_never_a_dot_segment(identifier: object) -> None:
    with pytest.raises(UnexpectedResponseError, match="'sandbox_id'"):
        _ = SandboxView({**sandbox(), "sandbox_id": identifier}).sandbox_id


# --------------------------------------------------------------------------- what a later server may send
def test_a_member_this_version_does_not_know_is_ignored_and_kept_in_raw() -> None:
    raw = sandbox(placement={"zone": "a"}, labels=["x"])
    raw["image"]["signature"] = "sig"
    raw["resources"]["gpus"] = 2
    view = SandboxView(raw)
    assert view.raw["placement"] == {"zone": "a"}
    assert view.image.raw["signature"] == "sig"
    assert view.resources.raw == {"vcpus": 1, "memory_mib": 512, "disk_mib": 1024, "gpus": 2}
    assert not hasattr(view, "placement")
    assert view.state == "RUNNING"


@pytest.mark.parametrize("state", ["HIBERNATED", "UNRECOGNIZED", "running", ""])
def test_a_vocabulary_value_never_seen_is_shown_as_it_came(state: str) -> None:
    assert SandboxView(sandbox(state)).state == state
    assert SnapshotView(snapshot(state)).state == state
    assert Operation(operation(state=state)).state == state
    assert ExecutionView(execution(state)).status == state
    assert Operation(operation(effect=state)).effect == state
    assert NetworkView({"mode": state}).mode == state
    assert Failure({"code": state, "retry": state, "message": "m"}).retry == state


def test_the_raw_value_of_an_unrecognized_host_value_is_kept_beside_it() -> None:
    view = SandboxView(sandbox("UNRECOGNIZED", state_raw="DEFROSTING"))
    assert (view.state, view.state_raw) == ("UNRECOGNIZED", "DEFROSTING")
    failed = Failure({"code": "UNRECOGNIZED", "code_raw": "GREMLINS", "retry": "NEVER", "message": "m"})
    assert (failed.code, failed.code_raw) == ("UNRECOGNIZED", "GREMLINS")


def test_unknown_members_and_values_arrive_through_a_client_untouched(harness: Harness) -> None:
    view = sandbox("HIBERNATED", placement={"zone": "a"})
    view["network"] = {"mode": "mesh", "mode_raw": "MESH", "entries": [], "policy": "strict"}
    ended = done("sandbox.thaw", "sandbox", view, effect="PARTLY_APPLIED", stage="warm", initiated_by="SCHEDULER")
    script = harness.script(
        ex("GET", f"/sandboxes/{SBX}", reply(200, view)),
        ex("POST", f"/sandboxes/{SBX}/start", reply(200, ended)),
    )
    handle = harness.run(harness.client(script).sandboxes.get(SBX))
    assert handle.raw == view
    assert (handle.state, handle.network.mode, handle.network.mode_raw) == ("HIBERNATED", "mesh", "MESH")
    harness.run(handle.start())
    started = handle.operation
    assert started is not None
    assert (started.type, started.effect, started.initiated_by) == ("sandbox.thaw", "PARTLY_APPLIED", "SCHEDULER")
    assert started.raw["stage"] == "warm"


def test_an_error_keeps_what_the_problem_document_said_even_if_it_is_new() -> None:
    document = problem("FUTURE_CODE", kind="DEFERRED", retry="WHEN_READY", reason="backlog", hint="later")
    error = agentcompute.errors.error_class(document["code"], document["kind"])(
        document["message"], code=document["code"], kind=document["kind"], retry=document["retry"]
    )
    assert type(error) is agentcompute.RefusedError
    assert (error.code, error.kind, error.retry) == ("FUTURE_CODE", "DEFERRED", "WHEN_READY")


# ----------------------------------------------------------------------------------------- thin and honest
def test_a_port_range_reads_from_and_to_under_names_python_allows() -> None:
    entry = AllowEntryView({"name": "pypi.org", "ports": [{"from": 443, "to": 443}, {"from": 8000, "to": 8100}]})
    assert [(port.first, port.last) for port in entry.ports] == [(443, 443), (8000, 8100)]
    assert entry.ports[1].raw == {"from": 8000, "to": 8100}
    assert (entry.name, entry.network) == ("pypi.org", None)


def test_lists_are_read_as_tuples_and_absent_lists_as_empty() -> None:
    view = SandboxView(sandbox(notes=["a", "b"]))
    assert view.notes == ("a", "b")
    bare = sandbox()
    del bare["notes"]
    assert SandboxView(bare).notes == ()
    assert NetworkView({"mode": "none"}).entries == ()
    assert Info({"api_versions": ["v1"], "serving": True}).host_features is None


def test_replayed_and_recorded_are_false_unless_the_answer_says_true() -> None:
    bare = operation()
    del bare["replayed"], bare["recorded"]
    assert (Operation(bare).replayed, Operation(bare).recorded) == (False, False)
    assert Operation(operation(replayed=True)).replayed is True
    assert Operation(operation(recorded=True)).recorded is True


def test_the_result_of_an_operation_is_read_as_views() -> None:
    ended = Operation(done("execution.create", "execution", execution("EXITED", exit_code=3), operation_id=OP))
    result = ended.result
    assert result is not None
    assert (result.sandbox, result.snapshot) == (None, None)
    assert result.execution is not None
    assert result.execution.exit_code == 3
    assert ended.target.sandbox_id == SBX
    assert Operation(operation(state="IN_PROGRESS")).result is None


def test_views_are_equal_when_their_json_is_and_are_not_hashable() -> None:
    assert SandboxView(sandbox()) == SandboxView(sandbox())
    assert SandboxView(sandbox()) != SandboxView(sandbox("READY"))
    assert SandboxView({"sandbox_id": SBX}) != SandboxRef({"sandbox_id": SBX})
    assert SandboxView(sandbox()) != sandbox()
    with pytest.raises(TypeError, match="unhashable"):
        hash(SandboxView(sandbox()))


def test_a_repr_shows_what_identifies_the_view_and_never_a_secret() -> None:
    assert (
        repr(SandboxView(sandbox(name="web")))
        == f"SandboxView(sandbox_id='{SBX}', name='web', state='RUNNING', generation=1)"
    )
    assert (
        repr(Operation(operation()))
        == f"Operation(operation_id='{OP}', type='sandbox.create', state='SUCCEEDED', effect='APPLIED')"
    )
    assert repr(PortRangeView({"from": 1, "to": 2})) == "PortRangeView(from=1, to=2)"
    minted = AgentCredential(
        {"credential_id": "crd_1", "label": "builder", "status": "ACTIVE", "secret": "acf1_agt_s3cr3t"}
    )
    assert repr(minted) == "AgentCredential(credential_id='crd_1', label='builder', status='ACTIVE')"
    assert "s3cr3t" not in f"{minted} {minted!r}"


def test_the_public_names_are_the_ones_the_package_exports() -> None:
    exported = set(agentcompute.__all__)
    assert exported == {name for name in vars(agentcompute) if not name.startswith("_")} - _MODULES | {"__version__"}
    for view in _VIEWS:
        assert view.__name__ in exported
    assert agentcompute.__version__ == "0.1.0"


_MODULES = {"auth", "client", "errors", "execution", "operation", "sandbox", "snapshot", "types"}


def test_a_member_read_on_the_class_is_the_member_itself() -> None:
    assert isinstance(SandboxView.state, Member)
    assert isinstance(agentcompute.Sandbox.generation, Member)
    assert isinstance(agentcompute.AsyncSandbox.generation, Member)
