"""The platform's standing toward the host, the audit trail, and the life of a project.

Proves HB-4, HB-9, HB-10, ERR-5, REC3-7, TIME-1, CG-1, VER-5, OBS-1, OBS-3, OBS-4, OBS-6, OBS-9 to
OBS-11, IPS-13, SEC-109, SEC-113, SEC-116, SEC-123, SEC-125, PRJ-1 to PRJ-5 and the catalog entries
T3-API-03, T3-HB-02, T3-HB-03, T3-IPS-03, T3-OBS-01, T3-OBS-02, T3-OBS-03, T3-OBS-04, T3-PRJ-01,
T3-RED-01, T3-RED-03, T3-RED-24, T3-RED-25, T3-RED-43, T3-RED-46, T3-RED-50 and T3-RED-51, against the
model host.
"""

from __future__ import annotations

import json
import logging
import shutil
from typing import Any

import pytest

from acf_api.command import commands as c
from acf_api.command import model as m
from acf_api.core.audit import records as audit_records
from acf_api.core.pipeline.fingerprint import FingerprintKey
from acf_api.core.store.engine import OutboxFull
from tests.support.harness import Identity, Rig, build_rig, sandbox_spec
from tests.support.model_host import ModelHost


def _create(dev: Identity, **spec: Any) -> c.CreateSandbox:
    return c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(**spec))


async def _running(rig: Rig, dev: Identity) -> str:
    created = await rig.view(dev, _create(dev), "setup")
    sandbox_id = str(created["result"]["sandbox"]["sandbox_id"])
    await rig.view(
        dev, c.StartSandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation=1), "setup:start"
    )
    return sandbox_id


async def _audit(rig: Rig) -> list[dict[str, Any]]:
    return [r["record"] for r in await rig.core.outbox.read(limit=1000)]


# ------------------------------------------------------------------------------- what the host offers
@pytest.mark.parametrize("feature", ["scope_tags", "operation_list"])
async def test_granting_work_is_refused_while_a_required_feature_is_missing(tmp_path: Any, feature: str) -> None:
    """T3-RED-43, HB-4: the refusal names what is missing. Containment and reads still pass."""
    host = ModelHost()
    host.features.remove(feature)
    rig = await build_rig(tmp_path, host=host)
    try:
        dev = await rig.developer()
        refused = await rig.error(dev, _create(dev), "k")
        assert (refused.code, refused.kind, refused.reason) == (
            "UPSTREAM_UNAVAILABLE",
            "REFUSED",
            f"host_feature_missing:{feature}",
        )
        assert rig.host.mutating() == []
        assert (await rig.view(dev, c.ListSandboxes(project=dev.project_id)))["items"] == []
        info = await rig.view(dev, c.Info())
        assert info["ready"] is False
        assert f"host_feature_missing:{feature}" in info["not_ready_reasons"]
    finally:
        await rig.close()


async def test_a_host_that_speaks_another_protocol_gets_no_granting_work(tmp_path: Any) -> None:
    """HB-4, VER-10."""
    host = ModelHost()
    host.protocols = ["acf.host/3"]
    rig = await build_rig(tmp_path, host=host)
    try:
        dev = await rig.developer()
        assert (await rig.error(dev, _create(dev), "k")).reason == "host_protocol_unsupported"
    finally:
        await rig.close()


async def test_what_the_host_advertises_decides_what_is_offered(rig: Rig, dev: Identity) -> None:
    """T3-HB-02, T3-API-03, CG-1, VER-5, INV-109: a capability is offered only when its implementer advertises it."""
    info = await rig.view(dev, c.Info())
    assert info["host_features"] == ["allowlist_network"]
    assert "create_with_start" not in info["platform_features"]
    # One-step create is not advertised: asking for it is UNSUPPORTED, and nothing is emulated from two operations.
    unsupported = await rig.error(dev, _create(dev, start=True), "k-start")
    assert (unsupported.code, unsupported.kind, unsupported.reason) == ("UNSUPPORTED", "REFUSED", "create_with_start")
    assert rig.host.mutating() == []
    # The host stops offering the allowlist: after the next look at host.info the platform stops offering it too.
    rig.host.features.remove("allowlist_network")
    await rig.core.service.host_info(force=True)
    assert (await rig.view(dev, c.Info()))["host_features"] == []
    network = {"mode": "allowlist", "entries": [{"name": "pypi.org", "ports": [{"from": 443, "to": 443}]}]}
    gone = await rig.error(dev, _create(dev, network=network), "k-net")
    assert (gone.code, gone.reason) == ("UNSUPPORTED", "allowlist_network")
    # A host that begins to advertise one-step create changes nothing in this version. The platform does not
    # know how that host wants the one operation written, so it neither offers the feature nor accepts
    # `start`: to offer it and then send a create alone would report a started sandbox that was not started.
    rig.host.features.append("create_with_start")
    await rig.core.service.host_info(force=True)
    assert rig.core.service.d.standing.info is not None
    assert rig.core.service.d.standing.info.create_with_start is True, "the host's word is seen"
    assert "create_with_start" not in (await rig.view(dev, c.Info()))["platform_features"]
    still = await rig.error(dev, _create(dev, start=True), "k-start-again")
    assert (still.code, still.kind, still.reason) == ("UNSUPPORTED", "REFUSED", "create_with_start")
    assert rig.host.mutating() == []


async def test_info_shows_ceilings_of_the_callers_project_and_nothing_of_the_host_as_a_whole(
    rig: Rig, dev: Identity
) -> None:
    """PUB-8, HB-2, SEC-124."""
    await _running(rig, dev)
    info = await rig.view(dev, c.Info())
    assert info["ceilings"]["vcpus"] == rig.host.max_vcpus, "the lower of the grant's and the host's ceiling"
    assert info["parameters"]["public_wait_max"] == rig.config.parameters.public_wait_max
    text = json.dumps(info)
    for word in ("live_sandboxes", "operations_in_flight", "quarantined", "mode", "lineage", "host_id", 'snapshots":'):
        assert word not in text, word


# ------------------------------------------------------------------------------- the host's identity and the platform's own
async def test_another_peer_id_for_the_platform_stops_granting_work(rig: Rig, dev: Identity) -> None:
    """T3-RED-03, HB-10, HB-6, SEC-125: the first peer id seen is journaled; any other is a change an operator confirms."""
    first = await rig.view(dev, _create(dev, name="before"), "k-before")
    assert rig.core.service.d.standing.pinned_peer_id == "platform-peer"
    assert [r.data["peer_id"] for r in rig.core.journal.records if r.type == "peer_recorded"] == ["platform-peer"]
    # The enrolment changed: views now carry another peer id, and records made under the old one are out of reach.
    rig.host.peer_id = "platform-peer-2"
    discovered = await rig.view(dev, _create(dev, name="discovering"), "k-discover")
    assert discovered["state"] == "SUCCEEDED"
    refused = await rig.error(dev, _create(dev, name="after"), "k-after")
    assert (refused.code, refused.reason) == ("UPSTREAM_UNAVAILABLE", "platform_peer_id_changed")
    health = await rig.admin("health")
    assert health["reported_peer_id"] == "platform-peer-2"
    with pytest.raises(Exception, match="not the peer id"):
        await rig.admin("host.acknowledge-peer", peer_id="someone-else")
    acknowledged = await rig.admin("host.acknowledge-peer", peer_id="platform-peer-2")
    assert acknowledged["previous"] == "platform-peer"
    assert acknowledged["entries_lost"] == 1
    # The old key is answered from its recorded outcome; the entry made under the new id is untouched.
    old = await rig.view(dev, _create(dev, name="before"), "k-before")
    assert (old["operation_id"], old["recorded"]) == (first["operation_id"], True)
    assert (await rig.view(dev, _create(dev, name="discovering"), "k-discover"))["recorded"] is False
    assert (await rig.view(dev, _create(dev, name="after"), "k-after"))["state"] == "SUCCEEDED"


async def test_nothing_is_sent_to_an_endpoint_that_is_not_the_configured_host(tmp_path: Any) -> None:
    """T3-RED-03, HB-9: a wrong `host_id`, or a certificate the configured anchors do not sign."""
    host = ModelHost()
    host.info_host_id = "another-host"
    rig = await build_rig(tmp_path, host=host)
    try:
        dev = await rig.developer()
        refused = await rig.error(dev, _create(dev), "k")
        assert (refused.code, refused.reason) == ("UPSTREAM_UNAVAILABLE", "host_identity_unverified")
        assert rig.host.mutating() == []
        # The transport could not verify the endpoint at all.
        host.info_host_id = None
        host.identity_error = "the endpoint did not prove it is host host-model"
        await rig.core.service.host_info(force=True)
        assert (await rig.error(dev, _create(dev), "k-2")).reason == "host_identity_unverified"
        assert rig.host.mutating() == []
        host.identity_error = None
        await rig.core.service.host_info(force=True)
        assert (await rig.view(dev, _create(dev), "k-3"))["state"] == "SUCCEEDED"
    finally:
        await rig.close()


@pytest.mark.parametrize("host_class", ["AUTHENTICATION_FAILED", "AUTHORIZATION_DENIED", "PROTOCOL_ERROR"])
async def test_a_host_that_refuses_the_platform_itself_is_never_the_callers_failure(
    rig: Rig, dev: Identity, host_class: str
) -> None:
    """T3-HB-03, T3-RED-25, ERR-5, REC3-7: the claim is released, readiness is false, containment is still attempted."""
    sandbox_id = await _running(rig, dev)
    rig.host.refuse_platform = host_class
    refused = await rig.error(dev, _create(dev), "k")
    assert (refused.code, refused.kind, refused.retry) == ("UPSTREAM_UNAVAILABLE", "REFUSED", "SAME_REQUEST_LATER")
    assert refused.code_raw is None
    assert host_class not in refused.message
    assert (await rig.core.service.d.ledger.counts(0))["claimed"] == 0
    health = await rig.admin("health")
    assert health["ready"] is False
    assert health["refused_by_host"] == host_class
    assert rig.core.telemetry.get("operator_diagnostics", kind="host_refuses_the_platform") >= 1
    # A later granting request is refused before anything is sent.
    sent = len(rig.host.mutating())
    assert (await rig.error(dev, _create(dev), "k-2")).reason == "host_refuses_the_platform"
    assert len(rig.host.mutating()) == sent
    # A containment request is still sent, and gets the truthful answer.
    stop = await rig.error(
        dev, c.StopSandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation=1), "k-stop"
    )
    assert stop.code == "UPSTREAM_UNAVAILABLE"
    assert rig.host.mutating()[-1].method == "sandbox.stop"
    # When the host accepts the platform again, so does the platform accept granting work.
    rig.host.refuse_platform = None
    await rig.core.service.host_info(force=True)
    assert (await rig.view(dev, _create(dev), "k"))["state"] == "SUCCEEDED"


async def test_a_clock_offset_is_reported_as_what_it_is(rig: Rig, dev: Identity) -> None:
    """T3-RED-24, TIME-1: the host refused a fresh `issued_at`, so the cause is the two clocks."""
    rig.host.clock_offset_ms = -31_000  # the platform's clock is 31 s ahead of the host's
    skew = await rig.error(dev, _create(dev), "k")
    assert (skew.code, skew.kind, skew.retry) == ("CLOCK_SKEW", "REFUSED", "SAME_REQUEST_LATER")
    assert (await rig.core.service.d.ledger.counts(0))["claimed"] == 0
    assert (await rig.admin("health"))["clock_offset_suspected"] is True
    # New granting work is refused without being sent, until one request per period is let through as a probe.
    sent = len(rig.host.mutating())
    assert (await rig.error(dev, _create(dev), "k-2")).code == "CLOCK_SKEW"
    assert len(rig.host.mutating()) == sent
    rig.host.clock_offset_ms = 0
    rig.clock.advance(rig.config.parameters.host_info_ttl + 1)
    assert (await rig.view(dev, _create(dev), "k-3"))["state"] == "SUCCEEDED"
    assert (await rig.admin("health"))["clock_offset_suspected"] is False


async def test_a_start_long_after_its_create_is_a_request_of_its_own(rig: Rig, dev: Identity) -> None:
    """T3-RED-24, LRO-10, IDM-7: each public operation has its own `issued_at`."""
    created = await rig.view(dev, _create(dev), "k")
    rig.clock.advance(360)
    started = await rig.view(
        dev,
        c.StartSandbox(
            project=dev.project_id, sandbox_id=created["result"]["sandbox"]["sandbox_id"], expected_generation=1
        ),
        "k:start",
    )
    assert started["state"] == "SUCCEEDED"
    create, start = rig.host.mutating()
    assert create.issued_at != start.issued_at


async def test_the_platform_request_id_is_the_hosts_request_id(rig: Rig, dev: Identity) -> None:
    """T3-OBS-03, OBS-1: the envelope admits no trace field, so the request id joins the two traces."""
    ctx = rig.ctx()
    await rig.core.service.handle(dev.key, ctx, _create(dev), "k")
    mine = [s for s in rig.host.sent if s.request_id == ctx.request_id]
    assert [s.method for s in mine] == ["sandbox.list", "sandbox.create"]
    body = json.loads(mine[-1].raw)
    assert set(body) <= {
        "protocol",
        "owner_scope",
        "method",
        "params",
        "operation_id",
        "issued_at",
        "on_behalf_of",
        "request_id",
        "wait_ms",
    }
    assert dev.key not in mine[-1].raw.decode(), "a caller's credential is never forwarded to the host"


# ------------------------------------------------------------------------------- audit
CANARY_ARG = "CANARY-ARGUMENT-7f3a9c"
CANARY_ENV = "CANARY-ENVIRONMENT-51be02"


async def test_one_record_per_admitted_mutation_denial_and_output_read(rig: Rig, dev: Identity) -> None:
    """OBS-3, OBS-4, OBS-10: who, where, how, what, the decision, the result and when."""
    sandbox_id = await _running(rig, dev)
    spec = m.ExecSpec(expected_generation=1, argv=["echo", CANARY_ARG], env={"TOKEN": CANARY_ENV})
    ran = await rig.view(dev, c.Exec(project=dev.project_id, sandbox_id=sandbox_id, spec=spec), "k-exec")
    execution_id = ran["target"]["execution_id"]
    await rig.view(dev, c.GetExecutionOutput(project=dev.project_id, execution_id=execution_id, offset=2, max_bytes=3))
    await rig.error(dev, _create(dev, resources={"vcpus": 200, "memory_mib": 1, "disk_mib": 1}), "k-denied")
    rig.host.refuse_next = ("STATE_CONFLICT", "AFTER_CHANGE", "busy")
    await rig.error(dev, c.Exec(project=dev.project_id, sandbox_id=sandbox_id, spec=spec), "k-refused")
    await rig.view(dev, c.ListSandboxes(project=dev.project_id))
    records = await _audit(rig)
    by_event: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        by_event.setdefault(record["event"], []).append(record)
        assert set(record) <= audit_records.FIELDS, set(record) - audit_records.FIELDS
        assert set(record.get("details", {})) <= audit_records.DETAIL_FIELDS
    executed = next(r for r in by_event["mutation"] if r.get("execution_id") == execution_id)
    assert executed["principal_id"] == dev.principal_id
    assert executed["credential_id"] == dev.credential_id
    assert executed["project_id"] == dev.project_id
    assert executed["method"] == "execution.create"
    assert executed["outcome"] == "accepted"
    assert executed["interface"] == "rest"
    assert executed["decision_id"].startswith("dec_")
    assert executed["policy_version"].startswith("pv_")
    assert executed["operation_id"] == ran["operation_id"]
    assert executed["idempotency_key_digest"] == ran["idempotency_key_digest"]
    assert executed["details"]["network_mode"] == "none"
    assert executed["details"]["argv_items"] == 2
    read = by_event["execution.output.read"][0]
    assert read["details"] == {"stream": "stdout", "offset": 2, "bytes": 3}
    denied = next(r for r in by_event["mutation"] if r.get("code") == "PERMISSION_DENIED")
    assert (denied["outcome"], denied["reason"]) == ("REFUSED", "resources")
    refused = next(r for r in by_event["mutation"] if r.get("code") == "STATE_CONFLICT")
    assert refused["outcome"] == "REFUSED"
    assert "sandbox.list" not in {r.get("method") for r in records}, "a plain read leaves no audit record"
    assert {r["event"] for r in records} >= {"operator.action", "mutation", "execution.output.read"}


async def test_no_argument_value_credential_or_output_is_in_audit_logs_or_the_store(
    rig: Rig, dev: Identity, caplog: pytest.LogCaptureFixture
) -> None:
    """T3-OBS-02, T3-RED-46, T3-IPS-03, SEC-113, SEC-116, SEC-123: canaries searched for everywhere."""
    caplog.set_level(logging.DEBUG)
    sandbox_id = await _running(rig, dev)
    spec = m.ExecSpec(
        expected_generation=1, argv=["deploy", CANARY_ARG], env={"TOKEN": CANARY_ENV}, cwd="/srv/" + CANARY_ARG
    )
    ran = await rig.view(
        dev, c.Exec(project=dev.project_id, sandbox_id=sandbox_id, spec=spec), "CANARY-IDEMPOTENCY-KEY"
    )
    execution_id = ran["target"]["execution_id"]
    rig.host.outputs["run-" + execution_id[4:]]["stdout"] = b"CANARY-OUTPUT-bytes"
    await rig.view(dev, c.GetExecutionOutput(project=dev.project_id, execution_id=execution_id))
    agent = await rig.mint_agent(dev, "leak-check")
    await rig.error("acf1_dev_" + "x" * 43 + "_AAAAAA", c.WhoAmI())
    canaries = [CANARY_ARG, CANARY_ENV, "CANARY-OUTPUT", "CANARY-IDEMPOTENCY-KEY", dev.key, agent["secret"]]
    haystacks = {
        "audit": json.dumps(await _audit(rig)),
        "telemetry": json.dumps(rig.core.telemetry.snapshot()),
        "logs": "\n".join(f"{r.getMessage()} {getattr(r, 'fields', '')}" for r in caplog.records),
        "journal": rig.config.paths.journal.read_text(),
    }
    for name in ("state.db", "state.db-wal", "audit.db", "audit.db-wal"):
        path = rig.config.paths.store_dir / name
        if path.exists():
            haystacks[name] = path.read_bytes().decode("latin-1")
    for where, text in haystacks.items():
        for canary in canaries:
            assert canary not in text, f"{canary[:12]}… found in {where}"


async def test_with_the_fingerprint_key_an_operator_confirms_what_ran(rig: Rig, dev: Identity) -> None:
    """T3-OBS-04, OBS-9: the record holds keyed digests. Without the key they reveal nothing."""
    sandbox_id = await _running(rig, dev)
    argv, env = ["python", "train.py", "--epochs", "3"], {"SEED": "42"}
    spec = m.ExecSpec(expected_generation=1, argv=argv, env=env)
    await rig.view(dev, c.Exec(project=dev.project_id, sandbox_id=sandbox_id, spec=spec), "k")
    record = next(r for r in await _audit(rig) if r.get("method") == "execution.create")
    key = FingerprintKey.parse(rig.config.paths.fingerprint_key.read_text())
    assert record["details"]["argv_digest"] == key.audit_digest(argv)
    assert record["details"]["env_digest"] == key.audit_digest(env)
    assert record["details"]["argv_digest"] != key.audit_digest(["python", "train.py", "--epochs", "4"])
    other = FingerprintKey(b"k" * 32)
    assert other.audit_digest(argv) != record["details"]["argv_digest"], "the digest is keyed"
    assert FingerprintKey.parse("ab" * 32).audit_digest(argv) != record["details"]["argv_digest"]
    assert repr(key) == "FingerprintKey(<hidden>)"


async def test_a_failing_audit_sink_changes_no_outcome(rig: Rig, dev: Identity) -> None:
    """T3-OBS-01, OBS-6, SEC-109, AR-305: the loss is counted."""

    async def full(_: dict[str, Any]) -> int:
        raise OutboxFull("the audit outbox has used its budget")

    rig.core.outbox.append = full  # type: ignore[method-assign, assignment]
    created = await rig.view(dev, _create(dev), "k")
    assert created["state"] == "SUCCEEDED"
    destroyed = await rig.view(
        dev,
        c.DestroySandbox(
            project=dev.project_id, sandbox_id=created["result"]["sandbox"]["sandbox_id"], expected_generation=1
        ),
        "d",
    )
    assert destroyed["state"] == "SUCCEEDED"
    assert rig.core.telemetry.get("audit_records_dropped") >= 2
    assert (await rig.admin("health"))["audit_writable"] is False


async def test_with_audit_required_a_full_outbox_refuses_granting_work_and_never_containment(tmp_path: Any) -> None:
    """OBS-11, T3-RED-51: the operator's choice. Containment is never refused for audit."""
    rig = await build_rig(tmp_path, audit_required=True)
    try:
        dev = await rig.developer()
        created = await rig.view(dev, _create(dev), "k")

        async def full(_: dict[str, Any]) -> int:
            raise OutboxFull("the audit outbox has used its budget")

        rig.core.outbox.append = full  # type: ignore[method-assign, assignment]
        await rig.error(dev, _create(dev, resources={"vcpus": 200, "memory_mib": 1, "disk_mib": 1}), "k-trigger")
        refused = await rig.error(dev, _create(dev), "k-2")
        assert (refused.code, refused.kind, refused.reason) == ("UPSTREAM_UNAVAILABLE", "REFUSED", "audit_required")
        destroy = c.DestroySandbox(
            project=dev.project_id, sandbox_id=created["result"]["sandbox"]["sandbox_id"], expected_generation=1
        )
        assert (await rig.view(dev, destroy, "d"))["state"] == "SUCCEEDED"
    finally:
        await rig.close()


async def test_requests_that_fail_before_authentication_write_nothing_durable(rig: Rig, dev: Identity) -> None:
    """T3-RED-51, IPS-13, SEC-104: a flood of invalid keys grows the store by nothing. They are counted."""
    before_audit = len(await _audit(rig))
    sizes_before = await rig.core.store.sizes()
    for index in range(2000):
        await rig.error(f"acf1_dev_{index:043d}_AAAAAA", _create(dev), f"k-{index}")
    assert len(await _audit(rig)) == before_audit
    sizes_after = await rig.core.store.sizes()
    assert sizes_after["state_bytes"] == sizes_before["state_bytes"]
    assert sizes_after["audit_bytes"] == sizes_before["audit_bytes"]
    assert rig.core.telemetry.get("auth_failures", reason="malformed") >= 2000
    # A rate-limited request leaves a counter and no audit record either.
    service = rig.core.service
    service._ops.set_project_rate(dev.project_id, 0.0)
    while service._ops.admit(dev.project_id, dev.principal_id) is None:
        pass
    assert (await rig.error(dev, _create(dev), "k-limited")).code == "RATE_LIMITED"
    assert len(await _audit(rig)) == before_audit


async def test_audit_records_are_delivered_to_the_operators_sink(tmp_path: Any) -> None:
    """OBS-11: at least once, oldest first, marked delivered only after the sink has them on disk."""
    from acf_api.core.audit.sink import drain

    sink = tmp_path / "audit.jsonl"
    rig = await build_rig(tmp_path / "deployment", config_extra={"audit_sink": {"file": str(sink)}})
    try:
        dev = await rig.developer()
        await rig.view(dev, _create(dev), "k")
        delivered = await drain(rig.core.outbox, sink, rig.core.telemetry)
        lines = [json.loads(line) for line in sink.read_text().splitlines()]
        assert delivered == len(lines) > 0
        assert lines[-1]["event"] == "mutation"
        assert (await rig.core.outbox.counts())["undelivered"] == 0
        assert await drain(rig.core.outbox, sink, rig.core.telemetry) == 0
    finally:
        await rig.close()


# ------------------------------------------------------------------------------- projects
async def test_a_project_is_activated_only_on_an_empty_scope(rig: Rig, dev: Identity) -> None:
    """T3-PRJ-01, T3-RED-01, PRJ-1 to PRJ-3: the scope is random, journaled before use, and must hold nothing."""
    project = await rig.admin("project.create", label="clean")
    assert project["state"] == "ACTIVE"
    assert "scope" not in project, "a scope string is not shown, even to the operator's listing of a project"
    stored = await rig.core.service.d.registry.project(project["project_id"])
    assert stored is not None
    assert stored.scope.startswith("scp-")
    assert len(stored.scope) == 36
    allocated = [r.data for r in rig.core.journal.records if r.type == "scope_allocated"]
    assert {"project_id": project["project_id"], "scope": stored.scope} in allocated
    # A scope under which the host already holds something is never activated.
    original = rig.core.admin._holdings

    async def occupied(scope: str) -> dict[str, int | None]:
        return {"sandboxes": 1, "snapshots": 0, "operations": 3}

    rig.core.admin._holdings = occupied  # type: ignore[method-assign]
    dirty = await rig.admin("project.create", label="dirty")
    assert dirty["state"] == "PENDING"
    assert dirty["activation"].startswith("refused")
    assert rig.core.telemetry.get("operator_diagnostics", kind="project_scope_not_empty") == 1
    with pytest.raises(Exception, match="not ACTIVE"):  # noqa: PT012 - kept as written: any step of the sequence may be the one refused
        principal = await rig.admin("principal.create", label="p")
        await rig.admin("role.set", principal_id=principal["principal_id"], project_id=dirty["project_id"])
        await rig.admin("key.issue", principal_id=principal["principal_id"], project_id=dirty["project_id"])
    rig.core.admin._holdings = original  # type: ignore[method-assign]


async def test_after_a_restore_no_project_is_given_a_scope_that_was_issued_before(rig: Rig, dev: Identity) -> None:
    """T3-RED-01, PRJ-2, PRJ-3, IPS-10: a scope the journal allocated and the restored registry forgot is reported and retired."""
    backup = rig.root / "backup"
    await rig.core.close()
    shutil.copytree(rig.config.paths.store_dir, backup)
    rig.host.closed = False
    live = await rig.restart()
    later = await live.developer("later")
    created = await live.view(later, _create(later), "k")
    await live.core.close()
    shutil.rmtree(live.config.paths.store_dir)
    shutil.copytree(backup, live.config.paths.store_dir)
    live.host.closed = False
    restored = await live.restart()
    try:
        # The project made after the backup is gone from the registry, and its key with it.
        assert (await restored.error(later, c.WhoAmI())).code == "UNAUTHENTICATED"
        assert restored.core.telemetry.get("operator_diagnostics", kind="scopes_unknown_to_the_registry") == 1
        # No project, old or new, can reach the record the lost project made.
        fresh = await restored.developer("fresh")
        assert fresh.scope != later.scope
        sandbox_id = created["result"]["sandbox"]["sandbox_id"]
        for who in (dev, fresh):
            assert (
                await restored.error(who, c.GetSandbox(project=who.project_id, sandbox=sandbox_id))
            ).code == "NOT_FOUND"
            assert (await restored.view(who, c.ListSandboxes(project=who.project_id)))["items"] == []
        # The forgotten scope is retired: it can never be allocated again.
        with pytest.raises(Exception, match="issued before"):
            await restored.core.service.d.registry.create_project("prj_" + "Z" * 20, "reuse", later.scope)
    finally:
        await restored.close()


async def test_deleting_a_project_waits_for_an_empty_scope(rig: Rig, dev: Identity) -> None:
    """T3-RED-50, PRJ-4: DELETING refuses granting work and allows containment; DELETED only when nothing is left."""
    sandbox_id = await _running(rig, dev)
    snapshot = await rig.view(
        dev,
        c.CreateSnapshot(project=dev.project_id, sandbox_id=sandbox_id, spec=m.SnapshotSpec(expected_generation=1)),
        "snap",
    )
    ref = snapshot["result"]["snapshot"]
    deleting = await rig.admin("project.delete", project_id=dev.project_id)
    assert deleting["state"] == "DELETING"
    assert deleting["deletion"].startswith("waiting")
    refused = await rig.error(dev, _create(dev), "k-new")
    assert (refused.code, refused.reason) == ("PERMISSION_DENIED", "project_deleting")
    await rig.view(
        dev, c.DestroySandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation=1), "k-destroy"
    )
    still = await rig.admin("project.delete", project_id=dev.project_id)
    assert still["state"] == "DELETING", "a snapshot is still held under the scope"
    await rig.view(
        dev,
        c.DeleteSnapshot(
            project=dev.project_id, snapshot_id=ref["snapshot_id"], snapshot_generation=ref["snapshot_generation"]
        ),
        "k-rm",
    )
    done = await rig.admin("project.delete", project_id=dev.project_id)
    assert done["state"] == "DELETED"
    assert (await rig.error(dev, c.WhoAmI())).code == "UNAUTHENTICATED"
    types = [r.type for r in rig.core.journal.records]
    assert types.count("project_deleted") == 1
    assert types.count("scope_retired") == 1
    with pytest.raises(Exception, match="issued before"):
        await rig.core.service.d.registry.create_project("prj_" + "Y" * 20, "reuse", dev.scope)


async def test_a_project_outlives_its_credentials(rig: Rig, dev: Identity) -> None:
    """PRJ-5: revoking the last key deletes nothing; the listing shows the project and what the host holds for it."""
    await _running(rig, dev)
    await rig.admin("key.revoke", credential_id=dev.credential_id)
    listing = {p["project_id"]: p for p in await rig.admin("project.list")}
    mine = listing[dev.project_id]
    assert mine["state"] == "ACTIVE"
    assert mine["has_valid_developer_credential"] is False
    assert mine["host_records"]["sandboxes"] == 1
    assert rig.host.sandboxes, "nothing was removed"
