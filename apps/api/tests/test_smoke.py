"""The developer journey through the pipeline, against the model host: create, start, execute, read, destroy."""

from __future__ import annotations

import base64

from acf_api.command import commands as c
from acf_api.command import model as m
from tests.support.harness import Identity, Rig, sandbox_spec


async def test_create_start_exec_output_destroy(rig: Rig, dev: Identity) -> None:
    created = await rig.view(dev, c.CreateSandbox(project=dev.project_id, spec=sandbox_spec(name="lab")), "k-create")
    assert created["state"] == "SUCCEEDED"
    assert created["terminal"] is True
    assert created["replayed"] is False
    sandbox = created["result"]["sandbox"]
    assert sandbox["state"] == "PROVISIONING"
    assert sandbox["project"] == dev.project_id
    sandbox_id = sandbox["sandbox_id"]

    started = await rig.view(
        dev, c.StartSandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation=1), "k-create:start"
    )
    assert started["result"]["sandbox"]["state"] == "READY"

    spec = m.ExecSpec(expected_generation=1, argv=["echo", "hello"])
    ran = await rig.view(dev, c.Exec(project=dev.project_id, sandbox_id=sandbox_id, spec=spec), "k-exec")
    execution = ran["result"]["execution"]
    assert execution["status"] == "EXITED"
    assert execution["exit_code"] == 0
    assert execution["provenance"]["status"] == "GUEST_REPORTED"
    assert execution["execution_id"].startswith("exe-")

    chunk = await rig.view(dev, c.GetExecutionOutput(project=dev.project_id, execution_id=execution["execution_id"]))
    assert base64.b64decode(chunk["data_base64"]) == b"echo hello\n"
    assert chunk["eof"] is True
    assert chunk["provenance"] == "GUEST_REPORTED"

    destroyed = await rig.view(
        dev, c.DestroySandbox(project=dev.project_id, sandbox_id=sandbox_id, expected_generation="current"), "k-destroy"
    )
    assert destroyed["result"]["sandbox"]["state"] == "DESTROYED"

    # One host operation per key, each under the project's scope and the principal's label.
    mutating = rig.host.mutating()
    assert [s.method for s in mutating] == ["sandbox.create", "sandbox.start", "exec.run", "sandbox.destroy"]
    assert {s.owner_scope for s in rig.host.sent if s.method != "host.info"} == {dev.scope}
    assert {s.on_behalf_of for s in mutating} == {dev.principal_id}
