"""One command line for every public operation, with the conversation it must have with the platform.

Shared by the tests that prove what each command does and by the tests that prove what none of them
ever writes. The keys are the method names of the generated table of the API.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from support import (
    CRD,
    EXE,
    OP,
    OP2,
    SBX,
    SBX2,
    SNP,
    Exchange,
    chunk,
    credential,
    done,
    ex,
    execution,
    info,
    operation,
    page,
    reply,
    sandbox,
    snapshot,
    whoami,
)

MINTED = "acf1_agt_minted_Kd93LmQ0pXz7"


@dataclass(frozen=True)
class Case:
    """One operation of the table, as a command line and the conversation it must have with the platform."""

    args: list[str]
    exchanges: list[Exchange]
    #: What ``--json`` must print: the view as the platform sent it, or the list of them.
    printed: Any
    #: Something the human rendering must show.
    shown: str


def _cases() -> dict[str, Case]:
    ready, running = sandbox("READY"), sandbox("RUNNING")
    restored = sandbox("READY", generation=2)
    ran = execution()
    cancelled = execution("CANCELLED", exit_code=None, state="CANCELLED")
    taken = snapshot(name="base")
    deleted = snapshot("DELETED")
    minted = credential(secret=MINTED)
    revoked = credential("REVOKED")
    out = chunk("aGVsbG8K", size=6)
    created, started = operation(), operation("sandbox.start", operation_id=OP2)
    return {
        "sandbox.create": Case(
            ["sandbox", "create", "--image", "python", "--cpu", "1", "--memory", "512MiB", "--disk", "1GiB",
             "--no-start", "--idempotency-key", "key-1"],
            [
                ex("POST", "/sandboxes", reply(200, done("sandbox.create", "sandbox", ready)),
                   headers={"idempotency-key": "key-1"},
                   json={"image": "python", "resources": {"vcpus": 1, "memory_mib": 512, "disk_mib": 1024}}),
            ],
            ready,
            SBX,
        ),
        "sandbox.start": Case(
            ["sandbox", "start", SBX, "--generation", "1"],
            [ex("POST", f"/sandboxes/{SBX}/start", reply(200, done("sandbox.start", "sandbox", running)),
                json={"expected_generation": 1})],
            running,
            "RUNNING",
        ),
        "execution.create": Case(
            ["exec", "run", SBX, "--generation", "1", "--", "python", "-V"],
            [ex("POST", f"/sandboxes/{SBX}/executions", reply(200, done("execution.create", "execution", ran)),
                json={"expected_generation": 1, "argv": ["python", "-V"]})],
            ran,
            "",
        ),
        "execution.get": Case(
            ["exec", "status", EXE], [ex("GET", f"/executions/{EXE}", reply(200, ran))], ran, "EXITED"
        ),
        "execution.output": Case(
            ["exec", "output", EXE],
            [ex("GET", f"/executions/{EXE}/output", reply(200, out), query={"stream": "stdout", "offset": "0"})],
            out,
            "hello",
        ),
        "execution.cancel": Case(
            ["exec", "cancel", EXE],
            [ex("POST", f"/executions/{EXE}/cancel", reply(200, done("execution.cancel", "execution", cancelled)))],
            cancelled,
            "CANCELLED",
        ),
        "snapshot.create": Case(
            ["snapshot", "create", SBX, "--generation", "1", "--name", "base"],
            [ex("POST", f"/sandboxes/{SBX}/snapshots", reply(200, done("snapshot.create", "snapshot", taken)),
                json={"expected_generation": 1, "name": "base"})],
            taken,
            SNP,
        ),
        "snapshot.restore": Case(
            ["snapshot", "restore", SNP, "--into", SBX, "--generation", "1"],
            [
                ex("GET", "/snapshots", reply(200, page([snapshot()]))),
                ex("POST", f"/snapshots/{SNP}/restore", reply(200, done("snapshot.restore", "sandbox", restored)),
                   json={"snapshot_generation": 1,
                         "target": {"kind": "existing", "sandbox_id": SBX, "expected_generation": 1}}),
            ],
            restored,
            SBX,
        ),
        "sandbox.list": Case(
            ["sandbox", "list"],
            [ex("GET", "/sandboxes", reply(200, page([running, sandbox(sandbox_id=SBX2, name="second")])))],
            [running, sandbox(sandbox_id=SBX2, name="second")],
            "second",
        ),
        "sandbox.get": Case(["sandbox", "inspect", SBX], [ex("GET", f"/sandboxes/{SBX}", reply(200, running))],
                            running, SBX),
        "snapshot.list": Case(
            ["snapshot", "list"], [ex("GET", "/snapshots", reply(200, page([taken])))], [taken], "base"
        ),
        "sandbox.stop": Case(
            ["sandbox", "stop", SBX, "--generation", "1"],
            [ex("POST", f"/sandboxes/{SBX}/stop", reply(200, done("sandbox.stop", "sandbox", sandbox("STOPPED"))),
                json={"expected_generation": 1})],
            sandbox("STOPPED"),
            "STOPPED",
        ),
        "sandbox.destroy": Case(
            ["sandbox", "destroy", SBX, "--generation", "1"],
            [ex("DELETE", f"/sandboxes/{SBX}",
                reply(200, done("sandbox.destroy", "sandbox", sandbox("DESTROYED"))),
                query={"expected_generation": "1"})],
            sandbox("DESTROYED"),
            "DESTROYED",
        ),
        "snapshot.delete": Case(
            ["snapshot", "delete", SNP],
            [
                ex("GET", "/snapshots", reply(200, page([snapshot()]))),
                ex("DELETE", f"/snapshots/{SNP}", reply(200, done("snapshot.delete", "snapshot", deleted)),
                   query={"snapshot_generation": "1"}),
            ],
            deleted,
            "DELETED",
        ),
        "operation.get": Case(["operation", "get", OP], [ex("GET", f"/operations/{OP}", reply(200, created))],
                              created, OP),
        "operation.list": Case(
            ["operation", "list"],
            [ex("GET", "/operations", reply(200, page([created, started])))],
            [created, started],
            OP2,
        ),
        "agent_credential.mint": Case(
            ["auth", "agent-key", "create", "--label", "builder", "--lifetime", "2h"],
            [ex("POST", "/agent-credentials", reply(201, minted), json={"label": "builder", "lifetime_seconds": 7200},
                absent_headers=["idempotency-key"])],
            minted,
            MINTED,
        ),
        "agent_credential.list": Case(
            ["auth", "agent-key", "list"],
            [ex("GET", "/agent-credentials", reply(200, {"items": [credential()]}))],
            [credential()],
            "builder",
        ),
        "agent_credential.revoke": Case(
            ["auth", "agent-key", "revoke", CRD],
            [ex("DELETE", f"/agent-credentials/{CRD}", reply(200, revoked), absent_headers=["idempotency-key"])],
            revoked,
            "REVOKED",
        ),
        "platform.info": Case(["info"], [ex("GET", "/v1/info", reply(200, info()))], info(), "v1"),
        "auth.whoami": Case(
            ["policy", "inspect"], [ex("GET", "/v1/auth/whoami", reply(200, whoami()))], whoami(), "sandbox.create"
        ),
    }  # fmt: skip


CASES = _cases()
