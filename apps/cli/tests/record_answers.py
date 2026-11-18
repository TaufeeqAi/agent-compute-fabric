"""Record real answers of the host for the contract tests.

    ACF_HOST_FAKE=/path/to/acf-host-fake python tests/record_answers.py

Starts the test host, walks one scenario that touches every method and every kind of answer, and
writes each exchange (the request as sent, the answer as received) to
``tests/data/recorded_answers.json``. ``tests/test_contract.py`` then checks, without any host,
that every recorded request and answer is valid against the published API description and that the
client's models read the answers and write them back unchanged.

An exchange that the published description rejects is left out and reported. That happens when the
host binary and the description are not of the same build.

Run it again whenever the host's wire types change.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import ValidationError as SchemaError

sys.path.insert(0, str(Path(__file__).resolve().parent))

from acf_cli import requests as rq
from acf_cli.client import ClientConfig, HostClient, expect, require_success
from acf_cli.responses import OperationView, RunBody, SandboxBody, SnapshotBody
from acf_cli.transport import Connection, Exchange
from acf_cli.wire import AckCondition, OutputStream, ReleaseMode, RequestedMode
from hostproc import HostUnavailable, running_host
from support import Contract

OUTPUT = Path(__file__).resolve().parent / "data" / "recorded_answers.json"


class Recording:
    """A transport that remembers every exchange it carried."""

    def __init__(self, inner: Exchange) -> None:
        self._inner = inner
        self.exchanges: list[dict[str, Any]] = []

    def exchange(self, payload: bytes, *, read_timeout_s: float) -> bytes:
        raw = self._inner.exchange(payload, read_timeout_s=read_timeout_s)
        self.exchanges.append({"request": json.loads(payload), "response": json.loads(raw)})
        return raw

    def close(self) -> None:
        self._inner.close()


def _done(client: HostClient, call: rq.Call) -> OperationView:
    return require_success(client.submit(call))


def scenario(client: HostClient) -> None:
    """One pass over every method. Refusals and a failed operation are part of it on purpose."""
    client.read(rq.host_info())
    client.read(rq.host_metrics())

    allow = rq.NetworkAllowlist(
        entries=[
            rq.AllowEntry(destination=rq.NameDestination(name="pypi.org"), ports=[rq.PortRange(low=443, high=443)]),
            rq.AllowEntry(
                destination=rq.NetworkDestination(network="198.51.100.0/24"), ports=[rq.PortRange(low=5432, high=5433)]
            ),
        ]
    )
    resources = rq.SandboxResources(vcpus=1, memory_mib=128, disk_mib=64, network=allow)
    created = _done(client, rq.sandbox_create(rq.SandboxCreateParams(name="box", image="python", resources=resources)))
    box = expect(created.result, SandboxBody).data
    target = rq.SandboxTarget(sandbox_id=box.sandbox_id, expected_generation=box.generation)
    client.read(rq.sandbox_inspect("box"))
    _done(client, rq.sandbox_start(target))

    def execute(command: rq.CommandSpec) -> rq.Call:
        return rq.exec_run(
            rq.ExecParams(sandbox_id=target.sandbox_id, expected_generation=target.expected_generation, command=command)
        )

    ran = _done(client, execute(rq.CommandSpec(argv=["python", "-c", "print(1)"], env={"LANG": "C.UTF-8"})))
    run = expect(ran.result, RunBody).data
    client.read(rq.run_inspect(run.run_id))
    client.read(rq.run_output(rq.RunOutputParams(run_id=run.run_id, stream=OutputStream.STDOUT, max_bytes=4)))

    snapped = _done(
        client,
        rq.snapshot_create(
            rq.SnapshotCreateParams(
                sandbox_id=target.sandbox_id, expected_generation=target.expected_generation, name="base"
            )
        ),
    )
    snapshot = expect(snapped.result, SnapshotBody).data.snapshot
    ref = rq.SnapshotRef(snapshot_id=snapshot.snapshot_id, snapshot_generation=snapshot.snapshot_generation)
    client.read(rq.snapshot_list())
    in_place = rq.RestoreExisting(sandbox_id=target.sandbox_id, expected_generation=target.expected_generation)
    restored = _done(client, rq.snapshot_restore(rq.SnapshotRestoreParams(snapshot=ref, target=in_place)))
    current = expect(restored.result, SandboxBody).data
    as_new = _done(
        client, rq.snapshot_restore(rq.SnapshotRestoreParams(snapshot=ref, target=rq.RestoreNew(name="copy")))
    )
    copy = expect(as_new.result, SandboxBody).data
    # A secret reference that does not resolve on the host: an operation that ends FAILED.
    unresolvable = rq.CommandSpec(argv=["true"], secret_env={"PATH": rq.SecretRef(ref="not-provisioned")})
    client.submit(
        rq.exec_run(
            rq.ExecParams(sandbox_id=copy.sandbox_id, expected_generation=copy.generation, command=unresolvable)
        )
    )

    client.read(rq.operation_get(ran.operation_id))
    first = client.read(rq.sandbox_list(rq.ListParams(limit=1)))
    client.read(rq.operation_list(rq.ListParams(limit=2)))
    client.submit(rq.operation_cancel(ran.operation_id))

    # Refusals: an unknown name, an illegal transition, a profile denial, operator methods with nothing to do.
    client.read(rq.sandbox_inspect("no-such-sandbox"))
    client.submit(
        rq.sandbox_start(rq.SandboxTarget(sandbox_id=current.sandbox_id, expected_generation=current.generation))
    )
    client.submit(rq.sandbox_start(target))  # a stale generation
    denied = rq.SandboxResources(vcpus=1, memory_mib=128, disk_mib=64, network=rq.NetworkNone())
    client.submit(rq.sandbox_create(rq.SandboxCreateParams(image="not-installed", resources=denied)))
    client.submit(rq.host_acknowledge(AckCondition.STORE_REGRESSION))
    client.submit(
        rq.quarantine_release(
            rq.QuarantineReleaseParams(
                sandbox_id=current.sandbox_id, generation=current.generation, mode=ReleaseMode.DECLARE_ABSENT
            )
        )
    )
    # "I already submitted this" for an id the host has never seen: never treated as new.
    client.roundtrip(
        rq.operation_envelope(
            rq.sandbox_stop(target),
            operation_id=rq.new_operation_id(),
            issued_at=rq.utc_timestamp(),
            owner_scope=client.config.owner_scope,
            retry=True,
        )
    )

    _done(client, rq.host_set_mode(RequestedMode.DRAINING))
    client.submit(rq.sandbox_create(rq.SandboxCreateParams(image="python", resources=denied)))
    _done(client, rq.host_set_mode(RequestedMode.SERVING))
    _done(client, rq.profile_reload())

    _done(client, rq.sandbox_stop(rq.SandboxTarget(sandbox_id=copy.sandbox_id, expected_generation=copy.generation)))
    _done(client, rq.sandbox_destroy(rq.SandboxTarget(sandbox_id=copy.sandbox_id, expected_generation=copy.generation)))
    _done(
        client,
        rq.sandbox_destroy(rq.SandboxTarget(sandbox_id=current.sandbox_id, expected_generation=current.generation)),
    )
    _done(client, rq.snapshot_delete(ref))
    cursor = first.as_of
    assert cursor is not None
    since = rq.ListParams(changed_since=rq.Cursor(lineage=cursor.lineage, sequence=cursor.sequence))
    client.read(rq.sandbox_list(since))  # tombstones of the destroyed sandboxes
    client.read(rq.snapshot_list(since))  # and of the deleted snapshot


def main() -> int:
    try:
        with running_host() as host:
            config = ClientConfig(endpoint=host.unix())
            recording = Recording(Connection(config.endpoint))
            client = HostClient(config, connection=recording)
            try:
                scenario(client)
            finally:
                client.close()
    except HostUnavailable as e:
        sys.stderr.write(f"{e}\n")
        return 1
    contract = Contract.load()
    valid: list[dict[str, Any]] = []
    for exchange in recording.exchanges:
        try:
            contract.check_request(exchange["request"])
            contract.check_response(exchange["response"])
        except (AssertionError, SchemaError):
            method = exchange["request"]["method"]
            sys.stderr.write(f"left out: the published description rejects this host's `{method}` exchange\n")
        else:
            valid.append(exchange)
    OUTPUT.parent.mkdir(exist_ok=True)
    document = {"protocol": "acf.host/2", "source": "acf-host-fake", "exchanges": valid}
    OUTPUT.write_text(json.dumps(document, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    sys.stderr.write(f"recorded {len(valid)} of {len(recording.exchanges)} exchanges to {OUTPUT}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
