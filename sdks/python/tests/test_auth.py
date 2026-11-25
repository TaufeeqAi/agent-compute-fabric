"""The credential in use, the project it is bound to, and the agent credentials it minted."""

from __future__ import annotations

from typing import Any

import pytest

from agentcompute import (
    APIConnectionError,
    AsyncFabric,
    AuthenticationError,
    Fabric,
    ServiceUnavailableError,
    StateConflictError,
    UnexpectedResponseError,
)
from support import (
    CRD,
    EXE,
    EXE2,
    OP,
    OP2,
    OP3,
    PRINCIPAL,
    PROJECT,
    REQ,
    SBX,
    WHOAMI,
    Exchange,
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
)

_SECRET = "acf1_agt_minted_secret_J4hT8sQ1"
_EXE3 = "exe-" + "0" * 31 + "3"


def _credential(status: str = "ACTIVE", **extra: Any) -> Json:
    view: Json = {
        "credential_id": CRD,
        "kind": "agent",
        "label": "builder",
        "display_prefix": "acf1_agt_abcd",
        "status": status,
        "issued_at": "2026-11-19T10:00:00.000Z",
        "expires_at": "2026-11-19T11:00:00.000Z",
    }
    view.update(extra)
    return view


def _whoami_exchange() -> Exchange:
    return ex("GET", "/v1/auth/whoami", reply(200, WHOAMI))


# ---------------------------------------------------------------------------------------------- who am I
def test_whoami_shows_the_principal_the_project_and_the_grants(harness: Harness) -> None:
    script = harness.script(_whoami_exchange(), _whoami_exchange())
    fabric = harness.client(script)
    for me in (harness.run(fabric.whoami()), harness.run(fabric.auth.whoami())):
        assert (me.principal_id, me.project_id, me.policy_version) == (PRINCIPAL, PROJECT, "1")
        assert (me.credential.credential_id, me.credential.kind, me.credential.agent_label) == (CRD, "developer", None)
        assert me.grants == {"methods": ["sandbox.create"]}
        assert me.raw == WHOAMI
        assert me.request_id == REQ


def test_info_reads_the_platform_info(harness: Harness) -> None:
    body = {
        "api_versions": ["v1"],
        "serving": True,
        "ready": True,
        "platform_features": ["agent_credentials", "long_poll"],
        "host_features": ["scope_tags"],
        "parameters": {"public_wait_max": 30, "retry_budget_ratio": 0.2},
        "ceilings": {
            "vcpus": 8,
            "memory_mib": 16384,
            "disk_mib": 65536,
            "execution_timeout_seconds": 3600,
            "sandbox_lifetime_seconds": 86400,
            "allowlist_entries": 64,
        },
    }
    script = harness.script(ex("GET", "/v1/info", reply(200, body)))
    info = harness.run(harness.client(script).info())
    assert (info.api_versions, info.serving, info.ready) == (("v1",), True, True)
    assert info.platform_features == ("agent_credentials", "long_poll")
    assert info.not_ready_reasons is None
    assert info.parameters == {"public_wait_max": 30, "retry_budget_ratio": 0.2}
    assert info.ceilings is not None
    assert info.ceilings.memory_mib == 16384
    assert info.raw == body


# ------------------------------------------------------------------------------------------- the project
def _sandbox_read(project: str = PROJECT) -> Exchange:
    return ex("GET", f"/v1/projects/{project}/sandboxes/{SBX}", reply(200, sandbox()))


def test_without_a_project_the_credential_is_asked_once_and_the_answer_is_kept(harness: Harness) -> None:
    script = harness.script(_whoami_exchange(), _sandbox_read(), _sandbox_read(), _sandbox_read())
    fabric = harness.client(script, project=None)
    assert "project=None" in repr(fabric)
    for _ in range(3):
        harness.run(fabric.sandboxes.get(SBX))
    assert [seen.path for seen in script.seen].count("/v1/auth/whoami") == 1
    assert f"project='{PROJECT}'" in repr(fabric)


def test_a_project_from_the_environment_is_used_without_asking(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ACF_PROJECT", "prj_fromenvironment0001")
    script = harness.script(_sandbox_read("prj_fromenvironment0001"))
    harness.run(harness.client(script, project=None).sandboxes.get(SBX))


def test_a_project_given_as_an_argument_wins_over_the_environment(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ACF_PROJECT", "prj_fromenvironment0001")
    script = harness.script(_sandbox_read("prj_fromargument000001"))
    harness.run(harness.client(script, project="prj_fromargument000001").sandboxes.get(SBX))


def test_a_refused_whoami_surfaces_and_nothing_is_kept(harness: Harness) -> None:
    script = harness.script(
        ex("GET", "/v1/auth/whoami", refusal("UNAUTHENTICATED")), _whoami_exchange(), _sandbox_read()
    )
    fabric = harness.client(script, project=None)
    with pytest.raises(AuthenticationError, match="UNAUTHENTICATED"):
        harness.run(fabric.sandboxes.get(SBX))
    assert harness.run(fabric.sandboxes.get(SBX)).sandbox_id == SBX


# ----------------------------------------------------------------------------------------------- minting
def test_minting_sends_the_label_the_lifetime_and_the_narrowing_and_shows_the_secret_once(harness: Harness) -> None:
    narrowing = {
        "methods": ["execution.create"],
        "ceilings": {
            "vcpus": 1,
            "memory_mib": 512,
            "disk_mib": 1024,
            "execution_timeout_seconds": 60,
            "sandbox_lifetime_seconds": 600,
        },
    }
    script = harness.script(
        ex(
            "POST",
            "/agent-credentials",
            reply(201, _credential(secret=_SECRET, narrowing=narrowing)),
            json={"label": "builder", "lifetime_seconds": 7200, "narrowing": narrowing},
            absent_headers=["idempotency-key"],
        )
    )
    minted = harness.run(
        harness.client(script).auth.mint_agent_credential("builder", lifetime="2h", narrowing=narrowing)
    )
    assert minted.secret == _SECRET
    assert (minted.credential_id, minted.kind, minted.label, minted.status) == (CRD, "agent", "builder", "ACTIVE")
    assert minted.narrowing == narrowing
    assert minted.raw["secret"] == _SECRET
    assert _SECRET not in repr(minted)
    assert _SECRET not in str(minted)
    assert (minted.contained, minted.containment_errors) == ((), ())


def test_minting_without_a_narrowing_sends_none(harness: Harness) -> None:
    script = harness.script(
        ex("POST", "/agent-credentials", reply(201, _credential()), json={"label": "builder", "lifetime_seconds": 60})
    )
    minted = harness.run(harness.client(script).auth.mint_agent_credential("builder", lifetime=60))
    assert minted.secret is None


def test_the_agent_credentials_are_listed_without_secrets(harness: Harness) -> None:
    listing = {"items": [_credential(), _credential("REVOKED", credential_id="crd_0000000000000002", label="old")]}
    script = harness.script(ex("GET", "/agent-credentials", reply(200, listing)))
    credentials = harness.run(harness.client(script).auth.agent_credentials())
    assert isinstance(credentials, list)
    assert [(c.label, c.status, c.secret) for c in credentials] == [
        ("builder", "ACTIVE", None),
        ("old", "REVOKED", None),
    ]
    assert all(c.request_id == REQ for c in credentials)


# ---------------------------------------------------------------------------------------------- revoking
def test_revoking_sends_one_request_and_cancels_nothing_by_itself(harness: Harness) -> None:
    script = harness.script(
        ex(
            "DELETE",
            f"/agent-credentials/{CRD}",
            reply(200, _credential("REVOKED")),
            json=None,
            absent_headers=["idempotency-key"],
        )
    )
    revoked = harness.run(harness.client(script).auth.revoke_agent_credential(CRD))
    assert revoked.status == "REVOKED"
    assert (revoked.contained, revoked.containment_errors) == ((), ())
    assert len(script.seen) == 1


def _running(execution_id: str, operation_id: str, *, state: str = "IN_PROGRESS", **actor: Any) -> Json:
    who = {"principal_id": PRINCIPAL, "agent_label": "builder", **actor}
    return operation(
        "execution.create",
        state,
        operation_id=operation_id,
        actor=who,
        target={"sandbox_id": SBX, "generation": 1, "execution_id": execution_id},
    )


def _cancel(execution_id: str, response: Json | None = None) -> Exchange:
    cancelled = done("execution.cancel", "execution", execution("CANCELLED", exit_code=None, execution_id=execution_id))
    return ex("POST", f"/executions/{execution_id}/cancel", response or reply(200, cancelled), json=None)


def test_with_contain_the_executions_the_credential_started_are_cancelled(harness: Harness) -> None:
    operations = [
        _running(EXE, OP),  # the revoked credential's, still running: cancelled
        _running("exe-" + "9" * 32, "op-" + "1" * 32, agent_label="other-agent"),  # another agent of the same developer
        _running("exe-" + "8" * 32, "op-" + "2" * 32, principal_id="prn_someoneelse00001"),  # the same label, elsewhere
        _running("exe-" + "7" * 32, "op-" + "3" * 32, agent_label=None),  # the developer's own
        _running("exe-" + "6" * 32, "op-" + "4" * 32, state="SUCCEEDED"),  # has ended
        _running("exe-" + "5" * 32, "op-" + "5" * 32, state="CANCELLED"),
        operation("sandbox.start", "IN_PROGRESS", actor={"principal_id": PRINCIPAL, "agent_label": "builder"}),
        operation("execution.create", "IN_PROGRESS", operation_id="op-" + "6" * 32, actor=None),
    ]
    later = [_running(EXE2, OP2, state="ACCEPTED"), _running(_EXE3, OP3, state="AWAITING_PLACEMENT")]
    script = harness.script(
        ex("DELETE", f"/agent-credentials/{CRD}", reply(200, _credential("REVOKED"))),
        _whoami_exchange(),
        ex("GET", "/operations", reply(200, page(operations, more=True, cursor="o1"))),
        ex("GET", "/operations", reply(200, page(later)), query={"cursor": "o1"}),
        _cancel(EXE),
        _cancel(EXE2),
        _cancel(_EXE3),  # a state this version does not know has not ended
    )
    revoked = harness.run(harness.client(script).auth.revoke_agent_credential(CRD, contain=True))

    assert revoked.status == "REVOKED"
    assert revoked.contained == (EXE, EXE2, _EXE3)
    assert revoked.containment_errors == ()
    # The revocation comes first: it is what ends what the credential may ask for.
    assert script.seen[0].method == "DELETE"
    keys = [seen.key for seen in script.seen[4:]]
    assert all(key is not None and len(key) == 36 for key in keys)
    assert len(set(keys)) == 3


def test_a_cancel_that_fails_is_reported_and_the_others_still_happen(harness: Harness) -> None:
    script = harness.script(
        ex("DELETE", f"/agent-credentials/{CRD}", reply(200, _credential("REVOKED"))),
        _whoami_exchange(),
        ex("GET", "/operations", reply(200, page([_running(EXE, OP), _running(EXE2, OP2), _running(_EXE3, OP3)]))),
        _cancel(EXE, refusal("STATE_CONFLICT")),
        _cancel(EXE2),
        _cancel(_EXE3, reply(200, operation("execution.cancel", "UNKNOWN", operation_id="op-" + "7" * 32))),
    )
    revoked = harness.run(harness.client(script).auth.revoke_agent_credential(CRD, contain=True))

    assert revoked.contained == (EXE2,)
    first, second = revoked.containment_errors
    assert (first.execution_id, first.operation_id) == (EXE, OP)
    assert isinstance(first.error, StateConflictError)
    assert (second.execution_id, second.operation_id) == (_EXE3, OP3)
    assert type(second.error).__name__ == "OutcomeUnknownError"


def test_an_operation_that_names_no_execution_is_reported_not_skipped(harness: Harness) -> None:
    nameless = operation(
        "execution.create", "IN_PROGRESS", actor={"principal_id": PRINCIPAL, "agent_label": "builder"}, target={}
    )
    script = harness.script(
        ex("DELETE", f"/agent-credentials/{CRD}", reply(200, _credential("REVOKED"))),
        _whoami_exchange(),
        ex("GET", "/operations", reply(200, page([nameless]))),
    )
    revoked = harness.run(harness.client(script).auth.revoke_agent_credential(CRD, contain=True))
    assert revoked.contained == ()
    (unnamed,) = revoked.containment_errors
    assert (unnamed.execution_id, unnamed.operation_id) == (None, OP)


def test_a_credential_without_a_label_identifies_nothing_so_nothing_is_cancelled(harness: Harness) -> None:
    """Matching "no label" would cancel the caller's own executions."""
    unlabelled = _credential("REVOKED")
    del unlabelled["label"]
    script = harness.script(ex("DELETE", f"/agent-credentials/{CRD}", reply(200, unlabelled)))
    with pytest.raises(UnexpectedResponseError, match="names no label") as raised:
        harness.run(harness.client(script).auth.revoke_agent_credential(CRD, contain=True))
    assert "none was cancelled" in str(raised.value)
    assert any(f"Credential {CRD} was revoked" in note for note in raised.value.__notes__)
    assert len(script.seen) == 1


@pytest.mark.parametrize("failing", ["whoami", "listing"])
def test_if_containing_cannot_complete_the_error_says_the_credential_was_revoked(
    harness: Harness, failing: str
) -> None:
    unavailable = refusal("UPSTREAM_UNAVAILABLE", retry_after=1)
    steps = [ex("DELETE", f"/agent-credentials/{CRD}", reply(200, _credential("REVOKED")))]
    if failing == "whoami":
        steps += [ex("GET", "/v1/auth/whoami", unavailable)] * 3
    else:
        steps += [_whoami_exchange(), *[ex("GET", "/operations", unavailable)] * 3]
    script = harness.script(*steps)
    with pytest.raises(ServiceUnavailableError) as raised:
        harness.run(harness.client(script).auth.revoke_agent_credential(CRD, contain=True))
    note = " ".join(raised.value.__notes__)
    assert f"Credential {CRD} was revoked" in note
    assert "contain=True" in note


def test_if_the_revocation_itself_fails_nothing_is_cancelled(harness: Harness) -> None:
    script = harness.script(*[ex("DELETE", f"/agent-credentials/{CRD}", {"fault": "connect_error"})] * 3)
    with pytest.raises(APIConnectionError):
        harness.run(harness.client(script).auth.revoke_agent_credential(CRD, contain=True))
    assert all(seen.method == "DELETE" for seen in script.seen)


def test_a_client_built_for_one_flavor_returns_handles_of_that_flavor(harness: Harness) -> None:
    script = harness.script(_sandbox_read())
    fabric: Fabric | AsyncFabric = harness.client(script)
    handle = harness.run(fabric.sandboxes.get(SBX))
    expected = "AsyncSandbox" if harness.is_async else "Sandbox"
    assert type(handle).__name__ == expected
