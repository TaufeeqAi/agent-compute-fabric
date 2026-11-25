"""Credentials: who authenticates, what an agent credential may do, and what the access policy sees of a target.

Proves CRD-1 to CRD-13, AZ-4 to AZ-10, SEC-103, SEC-105, SEC-118, SEC-121, INV-128 and the catalog
entries T3-AUTH-02 to T3-AUTH-04, T3-AZ-03, T3-CRD-01, T3-CRD-02 (the part the platform decides),
T3-RED-04, T3-RED-10, T3-RED-13 (the minting half), T3-RED-42, T3-SEC-03 and T3-SEC-10, against the
model host.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from acf_api.command import commands as c
from acf_api.command import model as m
from acf_api.command.answers import ErrorAnswer, ViewAnswer
from acf_api.core.identity import keys
from acf_api.core.store.engine import StoreUnavailable
from tests.support.harness import Identity, Rig, build_rig, sandbox_spec

ALLOWLIST_GRANT: dict[str, Any] = {
    "schema_version": 1,
    "methods": [
        "sandbox.create",
        "sandbox.start",
        "sandbox.stop",
        "sandbox.destroy",
        "sandbox.get",
        "sandbox.list",
        "execution.create",
        "execution.get",
        "execution.output",
        "execution.cancel",
        "snapshot.create",
        "snapshot.restore",
        "snapshot.delete",
        "snapshot.list",
        "operation.get",
        "operation.list",
        "agent_credential.mint",
        "agent_credential.list",
        "agent_credential.revoke",
        "platform.info",
        "auth.whoami",
    ],
    "images": ["*"],
    "network": {
        "modes": ["none", "allowlist"],
        "destinations": [
            {"name": "pypi.org", "ports": [{"from": 443, "to": 443}]},
            {"suffix": "*.pythonhosted.org", "ports": [{"from": 443, "to": 443}]},
            {"network": "10.20.0.0/16", "ports": [{"from": 8000, "to": 8100}]},
        ],
    },
    "ceilings": {
        "vcpus": 8,
        "memory_mib": 16384,
        "disk_mib": 65536,
        "execution_timeout_seconds": 86400,
        "sandbox_lifetime_seconds": 86400,
    },
    "mint_agent_credentials": True,
}
ALLOWLIST = {"mode": "allowlist", "entries": [{"name": "pypi.org", "ports": [{"from": 443, "to": 443}]}]}


def _spec(**body: Any) -> m.SandboxSpec:
    return sandbox_spec(**body)


async def _whoami(rig: Rig, credential: str | Identity) -> dict[str, Any]:
    return await rig.view(credential, c.WhoAmI())


# ------------------------------------------------------------------------------- authentication
async def test_every_authentication_failure_is_the_same_opaque_answer(rig: Rig, dev: Identity) -> None:
    """T3-AUTH-02, CRD-5: the caller learns nothing about which check failed; the operator's counters do."""
    revoked = await rig.admin("key.issue", principal_id=dev.principal_id, project_id=dev.project_id)
    await rig.admin("key.revoke", credential_id=revoked["credential_id"])
    short = await rig.admin("key.issue", principal_id=dev.principal_id, project_id=dev.project_id, lifetime_days=1)
    rig.clock.advance(2 * 86400)
    well_formed_unknown = keys.generate_key("developer")
    wrong_kind = dev.key.replace("_dev_", "_agt_")
    bodies = []
    for credential in (None, "x", well_formed_unknown, wrong_kind, revoked["secret"], short["secret"], dev.key + "x"):
        answer = await rig.call(credential, c.WhoAmI())
        assert isinstance(answer, ErrorAnswer)
        assert answer.challenge is not None
        assert answer.challenge.www_authenticate == "Bearer"
        body = answer.error.model_dump()
        body.pop("request_id")
        bodies.append(json.dumps(body, sort_keys=True))
    assert len(set(bodies)) == 1
    counted = {k for k in rig.core.telemetry.snapshot()["counters"] if k.startswith("auth_failures")}
    assert {
        "auth_failures{reason=missing}",
        "auth_failures{reason=malformed}",
        "auth_failures{reason=unknown}",
        "auth_failures{reason=revoked}",
        "auth_failures{reason=expired}",
    } <= counted


async def test_a_revocation_takes_effect_for_the_next_request(rig: Rig, dev: Identity) -> None:
    """T3-AUTH-03, CRD-6: journal, then registry, then done. From that moment the key authenticates nothing."""
    assert (await _whoami(rig, dev))["principal_id"] == dev.principal_id
    await rig.admin("key.revoke", credential_id=dev.credential_id)
    assert (await rig.error(dev, c.WhoAmI())).code == "UNAUTHENTICATED"
    records = [r for r in rig.core.journal.records if r.type == "credential_revoked"]
    assert [r.data["credential_id"] for r in records] == [dev.credential_id]
    # Revoking again changes nothing and fails nothing.
    assert (await rig.admin("key.revoke", credential_id=dev.credential_id))["revoked"] == []


async def test_no_public_command_issues_or_revokes_a_developer_key(rig: Rig, dev: Identity) -> None:
    """T3-AUTH-04, CRD-8: the command interface has no such command, and the revoke that exists does not reach one."""
    types = set(c.command_types())
    assert not {t for t in types if "developer" in t or t in {"issue_key", "create_project", "set_role"}}
    error = await rig.error(dev, c.RevokeAgentCredential(project=dev.project_id, credential_id=dev.credential_id))
    assert error.code == "NOT_FOUND"
    assert (await _whoami(rig, dev))["credential"]["kind"] == "developer"


async def test_the_registry_holds_a_digest_and_a_prefix_never_the_key(rig: Rig, dev: Identity) -> None:
    """SEC-105, CRD-4."""
    record = await rig.core.service.d.registry.credential(dev.credential_id)
    assert record is not None
    assert record.key_digest == keys.key_digest(dev.key)
    assert dev.key.startswith(record.display_prefix)
    assert len(record.display_prefix) < 16
    for name in ("state.db", "state.db-wal", "audit.db", "audit.db-wal"):
        path = rig.config.paths.store_dir / name
        if path.exists():
            assert dev.key.encode() not in path.read_bytes()
    assert dev.key.encode() not in rig.config.paths.journal.read_bytes()


async def test_whoami_shows_the_callers_own_grants(rig: Rig, dev: Identity) -> None:
    """AZ-6."""
    who = await _whoami(rig, dev)
    assert who["project_id"] == dev.project_id
    assert who["credential"]["credential_id"] == dev.credential_id
    assert who["grants"]["mint_agent_credentials"] is True
    assert "sandbox.create" in who["grants"]["methods"]


async def test_a_grant_with_an_unknown_field_makes_the_credential_unusable(rig: Rig, dev: Identity) -> None:
    """AZ-3: unusable, never broader."""
    registry = rig.core.service.d.registry
    await registry.set_role(
        dev.principal_id, dev.project_id, json.dumps({**ALLOWLIST_GRANT, "approve_everything": True}), "pv_x"
    )
    assert (await rig.error(dev, c.WhoAmI())).code == "UNAUTHENTICATED"
    assert rig.core.telemetry.get("auth_failures", reason="grant_unreadable") == 1


# ------------------------------------------------------------------------------- agent credentials
async def test_an_agent_credential_is_narrower_and_cannot_mint(rig: Rig, dev: Identity) -> None:
    """T3-CRD-01, CRD-9, AZ-5, SEC-121: the default narrowing is the agent template, cut to what the parent may do."""
    minted = await rig.mint_agent(dev, "worker")
    assert minted["kind"] == "agent"
    assert minted["label"] == "worker"
    assert keys.parse_key(minted["secret"]) == keys.ParsedKey(1, "agent")
    who = await _whoami(rig, minted["secret"])
    assert who["credential"]["agent_label"] == "worker"
    assert who["grants"]["network"]["modes"] == ["none"]
    assert who["grants"]["mint_agent_credentials"] is False
    assert "agent_credential.mint" not in who["grants"]["methods"]
    assert {"sandbox.stop", "sandbox.destroy", "execution.cancel", "snapshot.delete"} <= set(who["grants"]["methods"])
    spec = m.MintAgentCredentialSpec(label="child", lifetime_seconds=60)
    error = await rig.error(minted["secret"], c.MintAgentCredential(project=dev.project_id, spec=spec))
    assert (error.code, error.reason) == ("PERMISSION_DENIED", "method")
    # The secret is shown once: listing never shows it again.
    listed = await rig.view(dev, c.ListAgentCredentials(project=dev.project_id))
    assert [item["credential_id"] for item in listed["items"]] == [minted["credential_id"]]
    assert "secret" not in listed["items"][0]


async def test_minting_never_widens(rig: Rig) -> None:
    """T3-CRD-01, CRD-9: every method, image, mode, destination and ceiling of the narrowing is one the parent allows."""
    dev = await rig.developer("d", grants=ALLOWLIST_GRANT)
    base = {**ALLOWLIST_GRANT, "mint_agent_credentials": False, "methods": ["sandbox.create", "sandbox.get"]}
    wider: list[dict[str, Any]] = [
        {
            **base,
            "methods": [
                "sandbox.create",
                "operation.list",
                "auth.whoami",
                "sandbox.get",
                "sandbox.list",
                "snapshot.list",
                "execution.get",
                "execution.output",
                "platform.info",
                "operation.get",
                "sandbox.start",
                "sandbox.stop",
                "sandbox.destroy",
                "execution.create",
                "execution.cancel",
                "snapshot.create",
                "snapshot.restore",
                "snapshot.delete",
                "agent_credential.list",
                "agent_credential.revoke",
                "agent_credential.mint",
            ],
            "mint_agent_credentials": True,
        },
        {**base, "ceilings": {**ALLOWLIST_GRANT["ceilings"], "vcpus": 9}},
        {
            **base,
            "network": {
                "modes": ["allowlist"],
                "destinations": [{"name": "example.org", "ports": [{"from": 443, "to": 443}]}],
            },
        },
        {
            **base,
            "network": {
                "modes": ["allowlist"],
                "destinations": [{"name": "pypi.org", "ports": [{"from": 80, "to": 443}]}],
            },
        },
        {
            **base,
            "network": {
                "modes": ["allowlist"],
                "destinations": [{"network": "10.0.0.0/8", "ports": [{"from": 8000, "to": 8100}]}],
            },
        },
    ]
    for index, narrowing in enumerate(wider):
        spec = m.MintAgentCredentialSpec.model_validate_json(
            json.dumps({"label": f"a{index}", "lifetime_seconds": 60, "narrowing": narrowing})
        )
        answer = await rig.call(dev, c.MintAgentCredential(project=dev.project_id, spec=spec))
        if index == 0:
            # Asking for minting itself is inside the parent; an agent credential still cannot mint (kind).
            assert isinstance(answer, ViewAnswer)
            child = answer.body["secret"]
            again = m.MintAgentCredentialSpec(label="grandchild", lifetime_seconds=60)
            denied = await rig.error(child, c.MintAgentCredential(project=dev.project_id, spec=again))
            assert (denied.code, denied.reason) == ("PERMISSION_DENIED", "mint")
            continue
        assert isinstance(answer, ErrorAnswer), index
        assert (answer.error.code, answer.error.reason) == ("PERMISSION_DENIED", "narrowing_widens"), index
    inside = {
        **base,
        "network": {
            "modes": ["allowlist"],
            "destinations": [{"name": "files.pythonhosted.org", "ports": [{"from": 443, "to": 443}]}],
        },
    }
    spec = m.MintAgentCredentialSpec.model_validate_json(
        json.dumps({"label": "ok", "lifetime_seconds": 60, "narrowing": inside})
    )
    assert (await rig.view(dev, c.MintAgentCredential(project=dev.project_id, spec=spec)))["label"] == "ok"


async def test_a_label_is_unique_among_live_agent_credentials(rig: Rig, dev: Identity) -> None:
    """T3-CRD-01, CRD-9."""
    first = await rig.mint_agent(dev, "same")
    spec = m.MintAgentCredentialSpec(label="same", lifetime_seconds=60)
    error = await rig.error(dev, c.MintAgentCredential(project=dev.project_id, spec=spec))
    assert (error.code, error.reason) == ("INVALID_REQUEST", "label_in_use")
    await rig.view(dev, c.RevokeAgentCredential(project=dev.project_id, credential_id=first["credential_id"]))
    assert (await rig.mint_agent(dev, "same"))["label"] == "same"


async def test_an_agent_credential_never_outlives_its_parent(rig: Rig, dev: Identity) -> None:
    """CRD-7: no later than the bound for agent keys, and no later than the key that minted it."""
    too_long = m.MintAgentCredentialSpec(
        label="long", lifetime_seconds=int(rig.config.parameters.agent_credential_max_lifetime) + 60
    )
    error = await rig.error(dev, c.MintAgentCredential(project=dev.project_id, spec=too_long))
    assert (error.code, error.reason) == ("INVALID_REQUEST", "lifetime")
    short_parent = await rig.admin(
        "key.issue", principal_id=dev.principal_id, project_id=dev.project_id, lifetime_days=0.01
    )
    beyond = m.MintAgentCredentialSpec(label="beyond", lifetime_seconds=3600)
    error = await rig.error(short_parent["secret"], c.MintAgentCredential(project=dev.project_id, spec=beyond))
    assert error.reason == "lifetime"


async def test_revoking_the_parent_revokes_its_agent_credentials(rig: Rig, dev: Identity) -> None:
    """T3-CRD-01, CRD-9."""
    agent = await rig.mint_agent(dev, "child")
    assert (await _whoami(rig, agent["secret"]))["credential"]["kind"] == "agent"
    revoked = await rig.admin("key.revoke", credential_id=dev.credential_id)
    assert set(revoked["revoked"]) == {dev.credential_id, agent["credential_id"]}
    assert (await rig.error(agent["secret"], c.WhoAmI())).code == "UNAUTHENTICATED"


async def test_a_mint_whose_answer_was_lost_is_found_by_listing_and_revoked(rig: Rig, dev: Identity) -> None:
    """T3-CRD-01, CRD-9: nobody saw the secret; the parent lists, and revokes. Revoking is idempotent."""
    await rig.mint_agent(dev, "orphan")
    listed = await rig.view(dev, c.ListAgentCredentials(project=dev.project_id))
    orphan = listed["items"][0]["credential_id"]
    command = c.RevokeAgentCredential(project=dev.project_id, credential_id=orphan)
    assert (await rig.view(dev, command))["status"] == "REVOKED"
    assert (await rig.view(dev, command))["status"] == "REVOKED"
    # Another developer of the same project cannot revoke it: it is not among those it minted.
    other_key = await rig.admin("key.issue", principal_id=dev.principal_id, project_id=dev.project_id)
    assert (await rig.error(other_key["secret"], command)).code == "NOT_FOUND"


async def test_a_revocation_that_took_effect_is_answered_as_done_whatever_fails_after_it(
    rig: Rig, dev: Identity, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ERR-1, CRD-6: once the journal and the registry hold the revocation, no failure may answer that nothing happened."""
    agent = await rig.mint_agent(dev)
    registry = rig.core.service.d.registry
    real, reads = registry.credential, 0

    async def fails_the_second_time(credential_id: str) -> Any:
        nonlocal reads
        reads += 1
        if reads == 2:
            raise StoreUnavailable("the store did not answer")
        return await real(credential_id)

    monkeypatch.setattr(registry, "credential", fails_the_second_time)
    answer = await rig.view(dev, c.RevokeAgentCredential(project=dev.project_id, credential_id=agent["credential_id"]))
    assert reads == 2, "the record was read before the revocation and again after it"
    assert (answer["credential_id"], answer["status"]) == (agent["credential_id"], "REVOKED")
    monkeypatch.undo()
    assert (await rig.error(agent["secret"], c.WhoAmI())).code == "UNAUTHENTICATED"


async def test_a_listing_of_agent_credentials_that_cannot_be_read_is_unavailable_and_not_an_internal_error(
    rig: Rig, dev: Identity, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def unreadable(**_: Any) -> Any:
        raise StoreUnavailable("the store did not answer")

    monkeypatch.setattr(rig.core.service.d.registry, "credentials", unreadable)
    refused = await rig.error(dev, c.ListAgentCredentials(project=dev.project_id))
    assert (refused.code, refused.kind, refused.retry) == ("UPSTREAM_UNAVAILABLE", "REFUSED", "SAME_REQUEST_LATER")


async def test_minting_and_revoking_take_no_key_and_leave_no_ledger_entry(rig: Rig, dev: Identity) -> None:
    """CRD-9: platform operations reach no host."""
    sent = len(rig.host.sent)
    agent = await rig.mint_agent(dev, "plain")
    await rig.view(dev, c.RevokeAgentCredential(project=dev.project_id, credential_id=agent["credential_id"]))
    assert len(rig.host.sent) == sent
    assert await rig.core.service.d.ledger.counts(0) == {"claimed": 0, "bound": 0, "lost": 0, "claimed_stale": 0}


async def test_what_an_agent_creates_expires_with_its_credential(rig: Rig, dev: Identity) -> None:
    """T3-CRD-02, CRD-10, INV-128: the lifetime sent to the host is bounded by the credential's remaining life plus the grace."""
    agent = await rig.mint_agent(dev, "short", lifetime=600)
    grace = int(rig.config.parameters.agent_expiry_grace)
    created = await rig.view(agent["secret"], c.CreateSandbox(project=dev.project_id, spec=_spec(name="a")), "k-a")
    sent = rig.host.mutating()[-1]
    assert sent.params["lifetime_secs"] == 600 + grace
    assert sent.on_behalf_of == f"{dev.principal_id}/short"
    assert created["actor"] == {"principal_id": dev.principal_id, "agent_label": "short"}
    # A shorter lifetime that the agent asked for is kept; a longer one is bounded.
    await rig.view(
        agent["secret"], c.CreateSandbox(project=dev.project_id, spec=_spec(name="b", lifetime_seconds=120)), "k-b"
    )
    assert rig.host.mutating()[-1].params["lifetime_secs"] == 120
    await rig.view(
        agent["secret"], c.CreateSandbox(project=dev.project_id, spec=_spec(name="c", lifetime_seconds=7200)), "k-c"
    )
    assert rig.host.mutating()[-1].params["lifetime_secs"] == 600 + grace
    # The value was chosen once and recorded: a retry of the same key sends nothing new and returns the same operation.
    rig.clock.advance(300)
    again = await rig.view(agent["secret"], c.CreateSandbox(project=dev.project_id, spec=_spec(name="a")), "k-a")
    assert again["operation_id"] == created["operation_id"]
    # A developer credential is not bounded this way.
    await rig.view(dev, c.CreateSandbox(project=dev.project_id, spec=_spec(name="d")), "k-d")
    assert "lifetime_secs" not in rig.host.mutating()[-1].params


# ------------------------------------------------------------------------------- the target's recorded intent
async def _allowlist_world(rig: Rig) -> tuple[Identity, str, dict[str, Any]]:
    """A developer who may use an allowlist, a running allowlist sandbox, and an agent with network `none`."""
    dev = await rig.developer("net", grants=ALLOWLIST_GRANT)
    created = await rig.view(dev, c.CreateSandbox(project=dev.project_id, spec=_spec(network=ALLOWLIST)), "net-create")
    sandbox_id = created["result"]["sandbox"]["sandbox_id"]
    agent = await rig.mint_agent(dev, "confined")
    return dev, sandbox_id, agent


async def test_an_agent_without_network_cannot_use_a_sandbox_that_has_one(rig: Rig) -> None:
    """T3-RED-10, T3-AZ-03, AZ-7, SEC-121: the policy checks the target, not only the request."""
    dev, sandbox_id, agent = await _allowlist_world(rig)
    key = agent["secret"]
    # Start of a created allowlist sandbox.
    start = await rig.error(
        key, c.StartSandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation=1), "a-start"
    )
    assert (start.code, start.reason) == ("PERMISSION_DENIED", "target_network")
    await rig.view(dev, c.StartSandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation=1), "d-start")
    # Exec in it.
    spec = m.ExecSpec(expected_generation=1, argv=["curl", "https://pypi.org"])
    exec_error = await rig.error(key, c.Exec(project=dev.project_id, sandbox_id=sandbox_id, spec=spec), "a-exec")
    assert (exec_error.code, exec_error.reason) == ("PERMISSION_DENIED", "target_network")
    # A snapshot of it, and a restore of a snapshot taken from it, in place and as new.
    snap_error = await rig.error(
        key,
        c.CreateSnapshot(project=dev.project_id, sandbox_id=sandbox_id, spec=m.SnapshotSpec(expected_generation=1)),
        "a-snap",
    )
    assert snap_error.reason == "target_network"
    snapshot = await rig.view(
        dev,
        c.CreateSnapshot(project=dev.project_id, sandbox_id=sandbox_id, spec=m.SnapshotSpec(expected_generation=1)),
        "d-snap",
    )
    ref = snapshot["result"]["snapshot"]
    plain = await rig.view(dev, c.CreateSandbox(project=dev.project_id, spec=_spec()), "d-plain")
    plain_id = plain["result"]["sandbox"]["sandbox_id"]
    in_place = m.RestoreSpec(
        snapshot_generation=1, target=m.RestoreInPlace(kind="existing", sandbox_id=plain_id, expected_generation=1)
    )
    as_new = m.RestoreSpec(snapshot_generation=1, target=m.RestoreAsNew(kind="new", name="copy"))
    for label, spec_r in (("in-place", in_place), ("as-new", as_new)):
        error = await rig.error(
            key, c.RestoreSnapshot(project=dev.project_id, snapshot_id=ref["snapshot_id"], spec=spec_r), f"a-{label}"
        )
        assert (error.code, error.reason) == ("PERMISSION_DENIED", "target_network"), label
    # Nothing the agent asked for reached the host as a mutation.
    assert all("/" not in (s.on_behalf_of or "") for s in rig.host.mutating())
    # Asking for an allowlist in a request is denied by the request's own values.
    denied = await rig.error(key, c.CreateSandbox(project=dev.project_id, spec=_spec(network=ALLOWLIST)), "a-create")
    assert (denied.code, denied.reason) == ("PERMISSION_DENIED", "network_mode")


async def test_a_snapshot_whose_intent_is_unreadable_is_refused_and_a_readable_one_is_allowed(rig: Rig) -> None:
    """T3-RED-10, AZ-7: until the snapshot view shows its intent, it is read through a sandbox that still carries it."""
    dev = await rig.developer("snap", grants=ALLOWLIST_GRANT)
    agent = (await rig.mint_agent(dev, "restorer"))["secret"]
    created = await rig.view(dev, c.CreateSandbox(project=dev.project_id, spec=_spec()), "c")
    sandbox_id = created["result"]["sandbox"]["sandbox_id"]
    snapshot = await rig.view(
        dev,
        c.CreateSnapshot(project=dev.project_id, sandbox_id=sandbox_id, spec=m.SnapshotSpec(expected_generation=1)),
        "s",
    )
    ref = snapshot["result"]["snapshot"]
    as_new = m.RestoreSpec(snapshot_generation=1, target=m.RestoreAsNew(kind="new", name="copy"))
    restore = c.RestoreSnapshot(project=dev.project_id, snapshot_id=ref["snapshot_id"], spec=as_new)
    # Readable: the generation the snapshot was taken from is still the current one of its source sandbox.
    allowed = await rig.view(agent, restore, "a-readable")
    assert allowed["state"] == "SUCCEEDED"
    copy_id = allowed["result"]["sandbox"]["sandbox_id"]
    # The source moves on to another generation by a restore of another snapshot.
    other = await rig.view(
        dev,
        c.CreateSnapshot(project=dev.project_id, sandbox_id=copy_id, spec=m.SnapshotSpec(expected_generation=1)),
        "s2",
    )
    other_ref = other["result"]["snapshot"]
    move = m.RestoreSpec(
        snapshot_generation=1, target=m.RestoreInPlace(kind="existing", sandbox_id=sandbox_id, expected_generation=1)
    )
    await rig.view(
        dev, c.RestoreSnapshot(project=dev.project_id, snapshot_id=other_ref["snapshot_id"], spec=move), "move"
    )
    # Now no sandbox the restore may look at carries the first snapshot's generation: unreadable.
    newer = m.RestoreSpec(snapshot_generation=1, target=m.RestoreAsNew(kind="new", name="copy2"))
    unreadable = await rig.error(
        agent, c.RestoreSnapshot(project=dev.project_id, snapshot_id=ref["snapshot_id"], spec=newer), "a-unreadable"
    )
    assert (unreadable.code, unreadable.reason, unreadable.retry) == (
        "PERMISSION_DENIED",
        "target_intent_unreadable",
        "AFTER_CHANGE",
    )
    # The developer's grant does not cover "every destination" either: while the host offers an allowlist, nobody's does.
    for_dev = await rig.error(
        dev, c.RestoreSnapshot(project=dev.project_id, snapshot_id=ref["snapshot_id"], spec=newer), "d-unreadable"
    )
    assert for_dev.reason == "target_intent_unreadable"
    # A snapshot that a sandbox shows as the one its generation was restored from is readable again.
    carried = m.RestoreSpec(
        snapshot_generation=1, target=m.RestoreInPlace(kind="existing", sandbox_id=sandbox_id, expected_generation=2)
    )
    ok = await rig.view(
        agent,
        c.RestoreSnapshot(project=dev.project_id, snapshot_id=other_ref["snapshot_id"], spec=carried),
        "a-carried",
    )
    assert ok["state"] == "SUCCEEDED"


async def test_ceilings_and_images_of_the_target_are_checked_too(rig: Rig) -> None:
    """T3-RED-10: the same matrix for resources and for images."""
    dev = await rig.developer("big", grants=ALLOWLIST_GRANT)
    big = await rig.view(
        dev,
        c.CreateSandbox(
            project=dev.project_id, spec=_spec(resources={"vcpus": 4, "memory_mib": 8192, "disk_mib": 1024})
        ),
        "big",
    )
    sandbox_id = big["result"]["sandbox"]["sandbox_id"]
    agent = (await rig.mint_agent(dev, "small"))["secret"]
    start = await rig.error(
        agent, c.StartSandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation=1), "a"
    )
    assert (start.code, start.reason) == ("PERMISSION_DENIED", "target_resources")
    narrowing = {
        **ALLOWLIST_GRANT,
        "images": ["node"],
        "mint_agent_credentials": False,
        "network": {"modes": ["none"], "destinations": []},
    }
    picky = (await rig.mint_agent(dev, "picky", narrowing=narrowing))["secret"]
    image = await rig.error(
        picky, c.StartSandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation=1), "p"
    )
    assert (image.code, image.reason) == ("PERMISSION_DENIED", "target_image")
    create = await rig.error(picky, c.CreateSandbox(project=dev.project_id, spec=_spec()), "p-create")
    assert create.reason == "image"


async def test_requested_destinations_are_checked_by_the_destination_relation(rig: Rig) -> None:
    """T3-AZ-03, NET3-2, AZ-8: inside the grant goes to the host; outside is denied before it."""
    dev = await rig.developer("dest", grants=ALLOWLIST_GRANT)

    def network(**entry: Any) -> dict[str, Any]:
        return {"mode": "allowlist", "entries": [entry]}

    allowed = [
        network(name="pypi.org", ports=[{"from": 443, "to": 443}]),
        network(name="PyPI.org.", ports=[{"from": 443, "to": 443}]),
        network(name="files.pythonhosted.org", ports=[{"from": 443, "to": 443}]),
        network(network="10.20.30.0/24", ports=[{"from": 8000, "to": 8010}]),
    ]
    denied = [
        network(name="example.org", ports=[{"from": 443, "to": 443}]),
        network(name="pypi.org", ports=[{"from": 80, "to": 80}]),
        network(name="pythonhosted.org", ports=[{"from": 443, "to": 443}]),
        network(name="evilpythonhosted.org", ports=[{"from": 443, "to": 443}]),
        network(network="10.21.0.0/24", ports=[{"from": 8000, "to": 8010}]),
        network(network="10.20.0.0/15", ports=[{"from": 8000, "to": 8010}]),
        network(network="10.20.30.0/24", ports=[{"from": 22, "to": 22}]),
    ]
    for index, net in enumerate(allowed):
        view = await rig.view(dev, c.CreateSandbox(project=dev.project_id, spec=_spec(network=net)), f"ok-{index}")
        assert view["state"] == "SUCCEEDED"
        await rig.view(
            dev,
            c.DestroySandbox(
                project=dev.project_id, sandbox_id=view["result"]["sandbox"]["sandbox_id"], expected_generation=1
            ),
            f"rm-{index}",
        )
    sent = len(rig.host.mutating())
    for index, net in enumerate(denied):
        error = await rig.error(dev, c.CreateSandbox(project=dev.project_id, spec=_spec(network=net)), f"no-{index}")
        assert (error.code, error.reason) == ("PERMISSION_DENIED", "destination"), net
    assert len(rig.host.mutating()) == sent


async def test_a_network_mode_the_host_does_not_define_is_refused(rig: Rig, dev: Identity) -> None:
    """NET3-1, CON-302: `restricted` and every other word are not part of the vocabulary."""
    with pytest.raises(ValueError, match=r"restricted|mode"):
        _spec(network={"mode": "restricted"})


# ------------------------------------------------------------------------------- secrets in requests
async def test_a_platform_credential_anywhere_in_a_request_is_refused(rig: Rig, dev: Identity) -> None:
    """T3-RED-42, T3-SEC-10, SEC-118: exact, because the format and its checksum decide. Random text is accepted."""
    created = await rig.view(dev, c.CreateSandbox(project=dev.project_id, spec=_spec()), "c")
    sandbox_id = created["result"]["sandbox"]["sandbox_id"]
    await rig.view(dev, c.StartSandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation=1), "s")
    canary = keys.generate_key("developer")
    sent = len(rig.host.mutating())
    in_argument = m.ExecSpec(expected_generation=1, argv=["deploy", "--token", canary])
    in_environment = m.ExecSpec(expected_generation=1, argv=["env"], env={"API_KEY": f"prefix {canary} suffix"})
    commands: list[c.Command] = [
        c.Exec(project=dev.project_id, sandbox_id=sandbox_id, spec=in_argument),
        c.Exec(project=dev.project_id, sandbox_id=sandbox_id, spec=in_environment),
    ]
    for index, command in enumerate(commands):
        error = await rig.error(dev, command, f"leak-{index}")
        assert (error.code, error.reason) == ("INVALID_REQUEST", "credential_in_request")
        assert canary not in error.message
    assert len(rig.host.mutating()) == sent
    # Text that only looks like a key, and random base64, pass.
    look_alike = canary[:-1] + ("A" if canary[-1] != "A" else "B")
    harmless = m.ExecSpec(expected_generation=1, argv=["echo", look_alike, "c2VjcmV0LWxvb2tpbmctYmFzZTY0LXRleHQ="])
    assert (await rig.view(dev, c.Exec(project=dev.project_id, sandbox_id=sandbox_id, spec=harmless), "fine"))[
        "state"
    ] == "SUCCEEDED"
    # A secret is named by reference, and only when the host advertises the capability.
    by_reference = m.ExecSpec.model_validate_json(
        json.dumps({"expected_generation": 1, "argv": ["env"], "secret_env": {"TOKEN": {"ref": "deploy-token"}}})
    )
    unsupported = await rig.error(dev, c.Exec(project=dev.project_id, sandbox_id=sandbox_id, spec=by_reference), "ref")
    assert (unsupported.code, unsupported.reason) == ("UNSUPPORTED", "secret_injection")


# ------------------------------------------------------------------------------- OAuth access tokens
ISSUER = "https://issuer.acf.example"
RESOURCE = "https://acf.example/mcp"


class _TokenFactory:
    """An authorization server for tests: one signing key and its key set."""

    def __init__(self, directory: Path) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.kid = "key-1"
        self.jwks = directory / "jwks.json"
        self.fetches = 0
        self.write()

    def write(self, *, kid: str | None = None) -> None:
        public = jwt.algorithms.ECAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        self.jwks.write_text(json.dumps({"keys": [{**public, "kid": kid or self.kid, "alg": "ES256", "use": "sig"}]}))

    def token(self, now_s: int, **claims: Any) -> str:
        body = {"iss": ISSUER, "aud": RESOURCE, "sub": "agent-7", "iat": now_s, "exp": now_s + 600, **claims}
        headers = {"kid": claims.pop("kid", self.kid)} if "kid" in claims else {"kid": self.kid}
        body.pop("kid", None)
        pem = self.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        return jwt.encode(body, pem, algorithm="ES256", headers=headers)


@pytest.fixture
async def oauth(tmp_path: Path) -> Any:
    factory = _TokenFactory(tmp_path)
    extra = {
        "oauth": {
            "issuer": ISSUER,
            "resource": RESOURCE,
            "jwks_file": str(factory.jwks),
            "scopes_supported": ["acf:sandbox.list"],
        }
    }
    rig = await build_rig(tmp_path / "deployment", config_extra=extra)
    # PyJWT reads the real clock for `exp`; the rig's clock follows it for these tests.
    rig.clock._wall = int(time.time() * 1000)
    try:
        dev = await rig.developer()
        yield rig, dev, factory
    finally:
        await rig.close()


async def test_a_token_is_accepted_only_through_a_binding_and_for_this_deployment(oauth: Any) -> None:
    """T3-SEC-03, T3-RED-04, SEC-103, CRD-13, MCP-4."""
    rig, dev, factory = oauth
    now = int(time.time())
    good = factory.token(now)
    # An unbound subject is refused however valid the token is.
    assert (await rig.error(good, c.WhoAmI(), interface="mcp")).code == "UNAUTHENTICATED"
    binding = await rig.admin(
        "oauth.bind",
        issuer=ISSUER,
        subject="agent-7",
        principal_id=dev.principal_id,
        project_id=dev.project_id,
        agent_label="oauth-agent",
    )
    who = await rig.view(good, c.WhoAmI(), interface="mcp")
    assert who["credential"]["kind"] == "agent"
    assert who["credential"]["agent_label"] == "oauth-agent"
    assert who["grants"]["network"]["modes"] == ["none"]
    refused = {
        "wrong audience": factory.token(now, aud="https://other.example/mcp"),
        "wrong issuer": factory.token(now, iss="https://evil.example"),
        "expired": factory.token(now - 7200, exp=now - 3600),
        "lives too long": factory.token(now, exp=now + 86400),
        "another subject": factory.token(now, sub="agent-8"),
        "no expiry": jwt.encode(
            {"iss": ISSUER, "aud": RESOURCE, "sub": "agent-7"},
            factory.key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            ),
            algorithm="ES256",
            headers={"kid": factory.kid},
        ),
        "unsigned": jwt.encode(
            {"iss": ISSUER, "aud": RESOURCE, "sub": "agent-7", "exp": now + 60},
            None,  # type: ignore[arg-type]  # an unsigned token is made with no key
            algorithm="none",
            headers={"kid": factory.kid},
        ),
        "tampered": good[:-4] + ("AAAA" if not good.endswith("AAAA") else "BBBB"),
    }
    for label, token in refused.items():
        answer = await rig.call(token, c.WhoAmI(), interface="mcp")
        assert isinstance(answer, ErrorAnswer), label
        assert answer.error.code == "UNAUTHENTICATED", label
        # The challenge points an agent host at the protected-resource metadata.
        assert answer.challenge is not None
        assert "resource_metadata=" in answer.challenge.www_authenticate
    # A revoked binding stops authenticating at once.
    await rig.admin("oauth.unbind", binding_id=binding["binding_id"])
    assert (await rig.error(good, c.WhoAmI(), interface="mcp")).code == "UNAUTHENTICATED"


async def test_scopes_narrow_a_binding_and_never_widen_it(oauth: Any) -> None:
    """T3-RED-04, T3-RED-14, CRD-13, AZ-9: the step-up challenge is computed by the access policy, in the core."""
    rig, dev, factory = oauth
    await rig.admin(
        "oauth.bind",
        issuer=ISSUER,
        subject="agent-7",
        principal_id=dev.principal_id,
        project_id=dev.project_id,
        agent_label="scoped",
    )
    now = int(time.time())
    narrow = factory.token(now, scope="acf:sandbox.list acf:auth.whoami")
    who = await rig.view(narrow, c.WhoAmI(), interface="mcp")
    assert sorted(who["grants"]["methods"]) == ["auth.whoami", "sandbox.list"]
    assert (await rig.view(narrow, c.ListSandboxes(project=dev.project_id), interface="mcp"))["items"] == []
    denied = await rig.call(narrow, c.GetSandbox(project=dev.project_id, sandbox="sbx-" + "0" * 32), interface="mcp")
    assert isinstance(denied, ErrorAnswer)
    assert (denied.error.code, denied.error.reason) == ("PERMISSION_DENIED", "method")
    assert denied.challenge is not None
    assert 'error="insufficient_scope"' in denied.challenge.www_authenticate
    assert 'scope="acf:sandbox.get"' in denied.challenge.www_authenticate
    # A scope for something the binding does not allow adds nothing.
    greedy = factory.token(now, scope="acf:* acf:agent_credential.mint")
    grants = (await rig.view(greedy, c.WhoAmI(), interface="mcp"))["grants"]
    assert grants["mint_agent_credentials"] is False
    assert "agent_credential.mint" not in grants["methods"]
    # A method outside the binding is denied without a step-up challenge: no scope would help.
    plain = await rig.call(greedy, c.ListOperations(project=dev.project_id), interface="mcp")
    assert isinstance(plain, ErrorAnswer)
    assert plain.challenge is None


async def test_a_tool_call_outside_a_tokens_scopes_is_answered_with_the_challenge_and_not_with_a_tool_result(
    oauth: Any,
) -> None:
    """MCP-7, T3-RED-14: the step-up is one of the two HTTP answers of the protocol's authorization.

    The adapter can give a status and a challenge only if the core hands it the refusal itself. As a
    tool result the refusal would reach the model, which cannot ask for another token.
    """
    rig, dev, factory = oauth
    await rig.admin(
        "oauth.bind",
        issuer=ISSUER,
        subject="agent-7",
        principal_id=dev.principal_id,
        project_id=dev.project_id,
        agent_label="scoped",
    )
    narrow = factory.token(int(time.time()), scope="acf:sandbox.list acf:auth.whoami")
    # A read tool, refused before any command exists.
    read = await rig.call(
        narrow, c.CallTool(name="sandbox_inspect", arguments={"sandbox": "sbx-" + "0" * 32}), interface="mcp"
    )
    assert isinstance(read, ErrorAnswer)
    assert (read.error.code, read.error.reason) == ("PERMISSION_DENIED", "method")
    assert read.challenge is not None
    assert 'error="insufficient_scope"' in read.challenge.www_authenticate
    assert 'scope="acf:sandbox.get"' in read.challenge.www_authenticate
    # A tool that would create an operation: the same answer, and nothing was claimed or sent.
    sent_before = len(rig.host.mutating())
    create = await rig.call(
        narrow,
        c.CallTool(
            name="sandbox_create",
            arguments={
                "name": "probe",
                "image": "python",
                "resources": {"vcpus": 1, "memory_mib": 512, "disk_mib": 1024},
            },
        ),
        interface="mcp",
    )
    assert isinstance(create, ErrorAnswer)
    assert create.challenge is not None
    assert 'scope="acf:sandbox.create"' in create.challenge.www_authenticate
    assert rig.host.mutating()[sent_before:] == []
    # A tool inside the scopes still answers as a tool.
    assert (await rig.tool(narrow, "sandbox_list")).is_error is False


async def test_a_tool_call_outside_an_agent_keys_grant_stays_a_tool_result(rig: Rig, dev: Identity) -> None:
    """MCP-7: without a token there is nothing to step up to, so the refusal is a result the agent can read."""
    narrowing = {
        "schema_version": 1,
        "methods": ["sandbox.list", "auth.whoami", "platform.info"],
        "images": ["*"],
        "network": {"modes": ["none"], "destinations": []},
        "ceilings": {
            "vcpus": 1,
            "memory_mib": 512,
            "disk_mib": 1024,
            "execution_timeout_seconds": 60,
            "sandbox_lifetime_seconds": 600,
        },
    }
    minted = await rig.mint_agent(dev, narrowing=narrowing)
    refused = await rig.tool(minted["secret"], "sandbox_inspect", {"sandbox": "sbx-" + "0" * 32})
    assert refused.is_error is True
    assert refused.structured["error"]["code"] == "PERMISSION_DENIED"
    assert refused.structured["error"]["reason"] == "method"


async def test_unknown_key_ids_cause_a_bounded_number_of_key_set_reads(oauth: Any) -> None:
    """T3-RED-04, CRD-13: ten thousand tokens with random key ids."""
    rig, dev, factory = oauth
    await rig.admin(
        "oauth.bind",
        issuer=ISSUER,
        subject="agent-7",
        principal_id=dev.principal_id,
        project_id=dev.project_id,
        agent_label="flood",
    )
    now = int(time.time())
    assert (await rig.view(factory.token(now), c.WhoAmI(), interface="mcp"))["principal_id"] == dev.principal_id
    verifier = rig.core.service.d.authenticator._tokens  # the key set under test
    key_set = verifier._keys
    before = key_set.fetches
    pem = factory.key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    body = {"iss": ISSUER, "aud": RESOURCE, "sub": "agent-7", "exp": now + 600}
    rejected = 0
    for index in range(10_000):
        token = jwt.encode(body, pem, algorithm="ES256", headers={"kid": f"random-{index}"})
        with pytest.raises(Exception) as refused:  # noqa: PT011 - the kind is checked by its name, below
            await verifier.verify(token)
        assert type(refused.value).__name__ == "TokenRejected"
        rejected += 1
    assert rejected == 10_000, "every one of them is rejected"
    assert key_set.fetches - before <= 1
