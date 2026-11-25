#!/usr/bin/env python3
"""The developer journey with the Python SDK, against a platform that is running.

    python -m pip install ./sdks/python
    ACF_BASE_URL=https://acf.example:8443 ACF_API_KEY=acf1_dev_... [ACF_CA_FILE=authority.pem] \\
        python scripts/platform-journey/python_sdk.py

A developer key of a project that holds nothing is all it needs. It creates a sandbox, runs commands,
takes a snapshot, restores it as a second sandbox, mints and revokes an agent key, and removes everything
it made. Every step is a check; the exit status is 0 when every check passed.

What a pass means depends on what is behind the platform. Against the host's in-memory test build it
proves the SDK, the platform and its deployment, and nothing about microVMs. Against a real host it is the
journey the contract names as the acceptance test of the developer experience.
"""

from __future__ import annotations

import os
import sys
import time

import agentcompute
from agentcompute import Fabric

#: Small enough for the snapshot quota of a default host, of which a snapshot takes memory and disk.
MEMORY, DISK = "128MiB", "256MiB"
RUN = f"{int(time.time()) % 1_000_000:06d}"
checks: list[bool] = []


def check(what: str, passed: object, detail: object = "") -> None:
    checks.append(bool(passed))
    shown = f"  [{str(detail)[:160]}]" if detail != "" else ""
    print(("ok   " if passed else "FAIL ") + what + shown)


def main() -> int:
    started = time.monotonic()
    authority = os.environ.get("ACF_CA_FILE") or None
    with Fabric() as fabric:  # ACF_API_KEY, ACF_BASE_URL and, for an authority of your own, ACF_CA_FILE
        info = fabric.info()
        check("info: the platform serves and is ready", info.raw.get("serving") is True and info.raw.get("ready") is True)
        who = fabric.whoami()
        check("whoami: a developer key, bound to one project", who.credential.kind == "developer", who.project_id)

        name, key = f"journey-{RUN}", f"journey-create-{RUN}"
        sandbox = fabric.sandboxes.create("python", cpu=1, memory=MEMORY, disk=DISK, name=name, idempotency_key=key)
        check("create (create, then start): the sandbox is up", sandbox.state == "READY", sandbox.sandbox_id)
        again = fabric.sandboxes.create("python", cpu=1, memory=MEMORY, disk=DISK, name=name, idempotency_key=key)
        check("the same call under the same key is the same sandbox", again.sandbox_id == sandbox.sandbox_id)
        listed = [s.sandbox_id for s in fabric.sandboxes.list() if s.state != "DESTROYED"]
        check("and not a second one", listed.count(sandbox.sandbox_id) == 1, len(listed))

        result = sandbox.exec(["python", "-c", "print(6 * 7)"], timeout="1m")
        check("exec: a result with a status and an exit code", result.status == "EXITED" and result.exit_code == 0)
        check("exec: output is bytes, and text when asked", isinstance(result.read(), bytes) and isinstance(result.text(), str))
        check("exec: what the guest reported is labelled as the guest's", result.provenance.get("exit_code") == "GUEST_REPORTED")
        shell = sandbox.exec_shell("echo one; echo two")
        check("exec_shell asks for a shell explicitly", shell.exit_code == 0)
        check("an execution is found again by its identifier", fabric.executions.get(result.execution_id).status == "EXITED")
        unread = fabric.executions.handle(result.execution_id)
        check("a handle made without a read reads output", isinstance(unread.read(), bytes))

        check("a name resolves to the identifier", fabric.sandboxes.get(name).sandbox_id == sandbox.sandbox_id)
        try:
            fabric.sandboxes.get("sbx-" + "0" * 32)
            check("a sandbox that does not exist is NotFoundError", False)
        except agentcompute.NotFoundError as error:
            check("a sandbox that does not exist is NotFoundError", error.code == "NOT_FOUND", error.request_id)
        try:
            sandbox.stop(generation=99)
            check("a stale generation is RevisionConflictError", False)
        except agentcompute.RevisionConflictError as error:
            check("a stale generation is RevisionConflictError", error.retry == "AFTER_CHANGE")

        snapshot = sandbox.snapshot(f"journey-base-{RUN}")
        check("snapshot", snapshot.state == "READY", snapshot.snapshot_id)
        copy = snapshot.restore_as_new(name=f"journey-copy-{RUN}")
        check("restore as a new sandbox: up without a start", copy.sandbox_id != sandbox.sandbox_id and copy.state == "READY")
        source = copy.source_snapshot
        check("the copy says where it came from", source is not None and source.snapshot_id == snapshot.snapshot_id)

        minted = fabric.auth.mint_agent_credential(f"journey-agent-{RUN}", lifetime="10m")
        secret = minted.secret or ""
        check("an agent key is minted, and printing it does not show the secret", secret.startswith("acf1_agt_") and secret not in repr(minted))
        check("it is listed, without its secret", all("secret" not in c.raw for c in fabric.auth.agent_credentials()))
        with Fabric(api_key=secret, ca_file=authority) as agent:
            seen = [s.sandbox_id for s in agent.sandboxes.list()]
            check("the agent key works within its grant", sandbox.sandbox_id in seen, len(seen))
            try:
                agent.auth.mint_agent_credential("nested", lifetime="1m")
                check("an agent cannot mint keys", False)
            except agentcompute.PermissionDeniedError as error:
                check("an agent cannot mint keys", True, error.reason)
            fabric.auth.revoke_agent_credential(minted.credential_id, contain=True)
            try:
                agent.whoami()
                check("a revoked agent key no longer authenticates", False)
            except agentcompute.AuthenticationError as error:
                check("a revoked agent key no longer authenticates", error.code == "UNAUTHENTICATED")

        try:
            sandbox.exec(["sleep", "0"], follow_max=0)
            check("follow_max=0 answers at once", True)
        except agentcompute.OperationStillRunningError as error:
            check("follow_max=0 answers at once, and names the operation", bool(error.operation_id))
        check("operations are listed", len(list(fabric.operations.list())) >= 6)

        check("snapshot deleted", snapshot.delete().state == "DELETED")
        for box in (copy, sandbox):
            box.stop(generation="current")
            check(f"stop and destroy {box.sandbox_id[-6:]}", box.destroy(generation="current").state == "DESTROYED")
        left = [s.sandbox_id for s in fabric.sandboxes.list() if s.state != "DESTROYED" and s.sandbox_id in {sandbox.sandbox_id, copy.sandbox_id}]
        check("nothing this journey made is left", left == [], left)

    passed = sum(checks)
    seconds = time.monotonic() - started
    print(f"\n{passed} of {len(checks)} checks passed in {seconds:.1f} s on Python {sys.version.split()[0]}")
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
