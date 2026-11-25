"""The whole chain, as a deployment runs it: a caller over HTTP, an edge process, a core process, the real test host.

Three processes are started for this module: the test host (the host agent's real edge, admission,
coordinator and store over an in-memory backend), the core (``acf-api core``), bound to it over mutual
TLS as the enrolled ``caller``, and an edge (``acf-api edge``) on a loopback port. The deployment is
made with ``acf-api init``; the project, the principal, the role and the developer key with
``acf-api admin``. Everything after that is plain HTTP.

One thing differs from a deployment: the edge and the core run as the same user, because a test has
one. The configuration says so (``allow_shared_identity``), and the checks that need two accounts are
said to be missing where they are.

Proves the developer journey at the level of whole processes, and the catalog entries T3-SVC-03,
T3-API-03, T3-SCOPE-01 (what the running processes have open) and the runtime half of T3-EC-01.
"""

from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import re
import shutil
import signal
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx2
import pytest

from acf_api import cli
from acf_api.core import config as cfg
from acf_api.edge.http.routes import ROUTES
from tests.support.deploy import (
    TEST_HOST_CALLER_PEER,
    TEST_HOST_ID,
    Process,
    RawHostClient,
    RealHost,
    core_document,
    edge_document,
    free_port,
    platform_command,
    private_dir,
    running_host,
    started,
    wait_until_serving,
    write_yaml,
)
from tests.support.edge import SANDBOX_BODY, World, method_of, route_calls
from tests.support.harness import DEPLOYMENT

pytestmark = [pytest.mark.host, pytest.mark.timeout(170)]

SCOPE = re.compile(r"^scp-[0-9a-f]{32}$")
REQUEST_ID = re.compile(r"^req_[0-9A-Za-z]{16,40}$")
#: The ceilings of the safety profile the test host is built with.
HOST_CEILINGS = {
    "vcpus": 4,
    "memory_mib": 2048,
    "disk_mib": 4096,
    "execution_timeout_seconds": 60,
    "sandbox_lifetime_seconds": 7200,
}
SMALL = {"image": "python", "resources": {"vcpus": 1, "memory_mib": 256, "disk_mib": 128}}


def acf_api(*argv: str) -> tuple[int, str, str]:
    """Run the operator's tool in this process and return its exit status and what it wrote."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        status = cli.main(list(argv))
    return status, out.getvalue(), err.getvalue()


@dataclass(frozen=True)
class Developer:
    project_id: str
    principal_id: str
    key: str

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.key}"}

    def path(self, tail: str = "") -> str:
        return f"/v1/projects/{self.project_id}{tail}"


@dataclass
class Platform:
    """The running deployment: the real host, one core process and one edge process."""

    host: RealHost
    root: Path
    core_config: Path
    paths: cfg.Paths
    core: Process
    edge: Process
    port: int

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def admin(self, operation: str, **arguments: Any) -> Any:
        """One operator command through `acf-api admin`, as an operator types it."""
        argv = ["admin", "--config", str(self.core_config), operation]
        for name, value in arguments.items():
            argv += [f"--{name.replace('_', '-')}", value if isinstance(value, str) else json.dumps(value)]
        status, out, err = acf_api(*argv)
        assert status == 0, err
        return json.loads(out)

    def developer(self, label: str) -> Developer:
        project = self.admin("project.create", label=f"{label}-project")
        assert (project["state"], project["activation"]) == ("ACTIVE", "active"), project
        principal = self.admin("principal.create", label=label)
        role = self.admin(
            "role.set", principal_id=principal["principal_id"], project_id=project["project_id"], template="developer"
        )
        assert "sandbox.create" in role["grants"]["methods"]
        key = self.admin("key.issue", principal_id=principal["principal_id"], project_id=project["project_id"])
        assert key["kind"] == "developer"
        return Developer(project["project_id"], principal["principal_id"], key["secret"])

    def client(self, who: Developer | None = None) -> httpx2.Client:
        return httpx2.Client(base_url=self.url, headers=who.headers if who else {}, timeout=30.0)


@pytest.fixture(scope="module")
def platform() -> Iterator[Platform]:
    with running_host() as host, private_dir("e") as root:
        # The platform's host credential: the `caller` identity the host enrolled, installed as a deployment does.
        secrets_dir = root / "secrets"
        secrets_dir.mkdir(mode=0o700)
        shutil.copy(host.anchors, secrets_dir / "ca.crt")
        shutil.copy(host.certificate("caller"), secrets_dir / "platform.crt")
        shutil.copy(host.private_key("caller"), secrets_dir / "platform.key")
        (secrets_dir / "platform.key").chmod(0o600)

        document = core_document(
            root,
            public_wait_max=5.0,
            server_deadline_margin=3.0,
            edge_core_deadline_margin=1.0,
            mcp_tool_wait=2.0,
            sdk_request_timeout=30.0,
            claim_stale_after=10.0,
            follow_poll_interval_min=0.05,
            follow_poll_interval_max=0.5,
            drain_timeout=10.0,
        )
        document["host"]["address"] = host.address
        document["host"]["host_id"] = TEST_HOST_ID
        core_config = write_yaml(root / "core.yaml", document)
        paths = cfg.load_config(core_config).paths
        status, out, err = acf_api("init", "--config", str(core_config))
        assert (status, json.loads(out)["deployment_id"]) == (0, DEPLOYMENT), err
        status, out, err = acf_api("check", "--config", str(core_config))
        assert status == 0, err

        port = free_port()
        edge_config = write_yaml(
            root / "edge.yaml",
            edge_document(paths.command_socket, port, public_wait_max=5.0, edge_core_deadline_margin=1.0),
        )
        with (
            started(platform_command("core", core_config), root / "core.log") as core,
            started(platform_command("edge", edge_config), root / "edge.log") as edge,
        ):
            wait_until_serving(core, sockets=(paths.command_socket, paths.admin_socket))
            wait_until_serving(edge, ports=(port,))
            yield Platform(host, root, core_config, paths, core, edge, port)


def settle(client: httpx2.Client, response: httpx2.Response) -> dict[str, Any]:
    """The operation of an accepted mutation, followed to its end at the place the answer named."""
    assert response.status_code in {200, 202}, response.text
    operation: dict[str, Any] = response.json()
    deadline = time.monotonic() + 30
    while not operation["terminal"]:
        assert response.status_code == 202
        assert int(response.headers["retry-after"]) >= 1
        assert time.monotonic() < deadline, operation
        response = client.get(response.headers["location"], params={"wait": 5})
        assert response.status_code == 200, response.text
        operation = response.json()
    assert REQUEST_ID.fullmatch(response.headers["x-request-id"])
    return operation


def problem(response: httpx2.Response, code: str, status: int) -> dict[str, Any]:
    assert response.headers["content-type"] == "application/problem+json", response.text
    body: dict[str, Any] = response.json()
    assert (body["code"], response.status_code, body["status"]) == (code, status, status), body
    assert response.headers["x-request-id"] == body["request_id"]
    return body


def mutate(client: httpx2.Client, method: str, path: str, key: str, **request: Any) -> dict[str, Any]:
    """One mutation under an idempotency key, followed to the end of its operation."""
    operation = settle(client, client.request(method, path, headers={"Idempotency-Key": key}, **request))
    assert (operation["state"], operation["effect"]) == ("SUCCEEDED", "APPLIED"), operation
    return operation


# =============================================================================== the journey
@pytest.mark.proves("T3-SVC-03", "T3-API-03")
def test_the_developer_journey_over_http_against_the_real_host(platform: Platform) -> None:
    """Info, whoami, create, start, exec, status, output, snapshot, restore, stop, destroy, list, and an operation read."""
    alice = platform.developer("alice")
    with (
        platform.client() as anonymous,
        platform.client(alice) as http,
        RawHostClient(platform.host, "operator") as operator,
    ):
        # ---- who is asking, and what the platform offers
        assert anonymous.get("/healthz").json() == {"status": "ok"}
        assert anonymous.get("/v1/info").json() == {"api_versions": ["v1"], "serving": True}
        problem(anonymous.get("/v1/auth/whoami"), "UNAUTHENTICATED", 401)

        info = http.get("/v1/info").json()
        assert (info["ready"], info["not_ready_reasons"]) == (True, []), info
        assert "allowlist_network" in info["host_features"]
        assert "create_with_start" not in info["platform_features"]
        assert {name: info["ceilings"][name] for name in HOST_CEILINGS} == HOST_CEILINGS, (
            "the lower of the grant and the host"
        )
        who = http.get("/v1/auth/whoami").json()
        assert (who["principal_id"], who["project_id"], who["credential"]["kind"]) == (
            alice.principal_id,
            alice.project_id,
            "developer",
        )

        # ---- create, then start: two operations (LRO-10)
        created = mutate(http, "POST", alice.path("/sandboxes"), "journey-create", json={**SMALL, "name": "lab"})
        sandbox = created["result"]["sandbox"]
        sandbox_id = sandbox["sandbox_id"]
        assert (sandbox["project"], sandbox["name"], sandbox["generation"], sandbox["state"]) == (
            alice.project_id,
            "lab",
            1,
            "PROVISIONING",
        )
        assert (created["type"], created["replayed"], created["actor"]["principal_id"]) == (
            "sandbox.create",
            False,
            alice.principal_id,
        )
        started_op = mutate(
            http,
            "POST",
            alice.path(f"/sandboxes/{sandbox_id}/start"),
            "journey-create:start",
            json={"expected_generation": 1},
        )
        assert started_op["result"]["sandbox"]["state"] == "READY"

        # The same key and request again: the same operation, marked as earlier work, and nothing new on the host.
        again = http.post(
            alice.path("/sandboxes"), headers={"Idempotency-Key": "journey-create"}, json={**SMALL, "name": "lab"}
        )
        assert (again.status_code, again.headers["idempotent-replayed"], again.json()["operation_id"]) == (
            200,
            "true",
            created["operation_id"],
        )

        # ---- on the host, the record carries the platform's peer id and the project's scope, and nothing else of the caller
        on_host = operator.read("sandbox.inspect", "operator-view", {"sandbox": sandbox_id})
        assert on_host["tags"]["peer_id"] == TEST_HOST_CALLER_PEER
        assert SCOPE.fullmatch(on_host["tags"]["owner_scope"])
        assert alice.key not in json.dumps(on_host)

        # ---- execute, read status and output
        ran = mutate(
            http,
            "POST",
            alice.path(f"/sandboxes/{sandbox_id}/executions"),
            "journey-exec",
            json={"expected_generation": 1, "argv": ["echo", "hello"]},
        )
        execution = ran["result"]["execution"]
        assert (execution["status"], execution["exit_code"], execution["provenance"]["exit_code"]) == (
            "EXITED",
            0,
            "GUEST_REPORTED",
        )
        execution_id = execution["execution_id"]
        status = http.get(alice.path(f"/executions/{execution_id}")).json()
        assert (status["execution_id"], status["terminal"], status["sandbox_id"]) == (execution_id, True, sandbox_id)
        chunk = http.get(
            alice.path(f"/executions/{execution_id}/output"), params={"stream": "stdout", "offset": 0}
        ).json()
        assert b"hello" in base64.b64decode(chunk["data_base64"])
        assert (chunk["eof"], chunk["provenance"], chunk["next_offset"]) == (
            True,
            "GUEST_REPORTED",
            chunk["stored_bytes"],
        )

        # ---- snapshot, and restore in place: a new generation of the same sandbox
        snapped = mutate(
            http,
            "POST",
            alice.path(f"/sandboxes/{sandbox_id}/snapshots"),
            "journey-snap",
            json={"expected_generation": 1, "name": "base"},
        )
        snapshot = snapped["result"]["snapshot"]
        assert (snapshot["state"], snapshot["name"], snapshot["source_sandbox"]["sandbox_id"]) == (
            "READY",
            "base",
            sandbox_id,
        )
        restored = mutate(
            http,
            "POST",
            alice.path(f"/snapshots/{snapshot['snapshot_id']}/restore"),
            "journey-restore",
            json={
                "snapshot_generation": 1,
                "target": {"kind": "existing", "sandbox_id": sandbox_id, "expected_generation": 1},
            },
        )
        assert (restored["result"]["sandbox"]["generation"], restored["result"]["sandbox"]["state"]) == (2, "READY")
        read = http.get(alice.path(f"/sandboxes/{sandbox_id}"))
        assert read.headers["etag"] == f'"{read.json()["revision"]}"'
        assert read.json()["source_snapshot"]["snapshot_id"] == snapshot["snapshot_id"]
        # A handle that still states generation 1 is refused by the host, and the refusal is the host's.
        stale = http.post(
            alice.path(f"/sandboxes/{sandbox_id}/executions"),
            headers={"Idempotency-Key": "journey-stale"},
            json={"expected_generation": 1, "argv": ["true"]},
        )
        assert problem(stale, "REVISION_CONFLICT", 412)["retry"] == "AFTER_CHANGE"

        # ---- T3-SVC-03: a state changed directly on the host is what the next public read shows
        second = mutate(http, "POST", alice.path("/sandboxes"), "journey-second", json={**SMALL, "name": "beside"})[
            "result"
        ]["sandbox"]
        assert sorted(item["name"] for item in http.get(alice.path("/sandboxes")).json()["items"]) == ["beside", "lab"]
        gone = operator.mutate(
            "sandbox.destroy", "operator-acts", {"sandbox_id": second["sandbox_id"], "expected_generation": 1}
        )
        assert (gone["state"], gone["tags"]["peer_id"]) == ("SUCCEEDED", "tls-operator")
        assert http.get(alice.path(f"/sandboxes/{second['sandbox_id']}")).json()["state"] == "DESTROYED"
        assert [item["name"] for item in http.get(alice.path("/sandboxes")).json()["items"]] == ["lab"]
        assert (
            http.get(alice.path(f"/operations/{created['operation_id']}")).json()["result"]["sandbox"]["generation"]
            == 2
        )

        # ---- an operation is read by its id, and waited for
        waited = http.get(alice.path(f"/operations/{ran['operation_id']}"), params={"wait": 2})
        assert (waited.status_code, waited.json()["terminal"], waited.json()["target"]["execution_id"]) == (
            200,
            True,
            execution_id,
        )
        listed = http.get(alice.path("/operations"), params={"limit": 100}).json()["items"]
        assert sorted(item["type"] for item in listed) == sorted(
            [
                "sandbox.create",
                "sandbox.create",
                "sandbox.start",
                "execution.create",
                "snapshot.create",
                "snapshot.restore",
            ]
        ), "the operator's own operation belongs to no project and is in no project's list"

        # ---- T3-API-03: a capability that is not advertised is refused; one that is, is the host's to judge
        with_start = http.post(
            alice.path("/sandboxes"), headers={"Idempotency-Key": "journey-one-step"}, json={**SMALL, "start": True}
        )
        assert problem(with_start, "UNSUPPORTED", 422)["reason"] == "create_with_start"
        secret = http.post(
            alice.path(f"/sandboxes/{sandbox_id}/executions"),
            headers={"Idempotency-Key": "journey-secret"},
            json={"expected_generation": 2, "argv": ["env"], "secret_env": {"TOKEN": {"ref": "deploy-token"}}},
        )
        if "secret_injection" in info["host_features"]:
            # This host's backend declares secret injection, so the reference is passed on and the host
            # decides: its safety profile allows no such variable. The verdict is the host's, unchanged.
            refused = problem(secret, "SAFETY_CONTROL_DENIED", 403)
            assert "TOKEN" not in refused["message"]
        else:
            assert problem(secret, "UNSUPPORTED", 422)["reason"] == "secret_injection"
        assert [item["name"] for item in http.get(alice.path("/sandboxes")).json()["items"]] == ["lab"], (
            "a refused request left something behind"
        )

        # ---- agent credentials are the platform's own records and reach no host
        minted = http.post(alice.path("/agent-credentials"), json={"label": "agent-1", "lifetime_seconds": 600})
        assert minted.status_code == 201
        agent = minted.json()
        with platform.client(Developer(alice.project_id, alice.principal_id, agent["secret"])) as as_agent:
            assert as_agent.get("/v1/auth/whoami").json()["credential"]["kind"] == "agent"
            assert as_agent.get(alice.path(f"/sandboxes/{sandbox_id}")).json()["sandbox_id"] == sandbox_id
            assert http.delete(alice.path(f"/agent-credentials/{agent['credential_id']}")).json()["status"] == "REVOKED"
            problem(as_agent.get("/v1/auth/whoami"), "UNAUTHENTICATED", 401)

        # ---- stop, destroy, delete: containment
        stopped = mutate(
            http,
            "POST",
            alice.path(f"/sandboxes/{sandbox_id}/stop"),
            "journey-stop",
            json={"expected_generation": "current"},
        )
        assert stopped["result"]["sandbox"]["state"] == "STOPPED"
        destroyed = mutate(
            http, "DELETE", alice.path(f"/sandboxes/{sandbox_id}"), "journey-destroy", params={"expected_generation": 2}
        )
        assert destroyed["result"]["sandbox"]["state"] == "DESTROYED"
        mutate(
            http,
            "DELETE",
            alice.path(f"/snapshots/{snapshot['snapshot_id']}"),
            "journey-delete",
            params={"snapshot_generation": 1},
        )
        assert http.get(alice.path("/sandboxes")).json()["items"] == []
        assert http.get(alice.path("/snapshots")).json()["items"] == []
        assert operator.read("sandbox.inspect", "operator-view", {"sandbox": sandbox_id})["state"] == "DESTROYED"


# =============================================================================== two projects
def test_two_projects_never_see_each_others_records_through_any_route(platform: Platform) -> None:
    """SEC-101, SEC-120, T3-SEC-12 over HTTP: another project's records are `NOT_FOUND`, by name of project or by identifier."""
    bob, carol = platform.developer("bob"), platform.developer("carol")
    with (
        platform.client(bob) as as_bob,
        platform.client(carol) as as_carol,
        RawHostClient(platform.host, "operator") as operator,
    ):
        sandbox_id = mutate(as_bob, "POST", bob.path("/sandboxes"), "two-create", json={**SMALL, "name": "bobs"})[
            "result"
        ]["sandbox"]["sandbox_id"]
        idle_id = mutate(as_bob, "POST", bob.path("/sandboxes"), "two-idle", json=SMALL)["result"]["sandbox"][
            "sandbox_id"
        ]
        mutate(as_bob, "POST", bob.path(f"/sandboxes/{sandbox_id}/start"), "two-start", json={"expected_generation": 1})
        ran = mutate(
            as_bob,
            "POST",
            bob.path(f"/sandboxes/{sandbox_id}/executions"),
            "two-exec",
            json={"expected_generation": 1, "argv": ["echo", "private"]},
        )
        snapshot = mutate(
            as_bob, "POST", bob.path(f"/sandboxes/{sandbox_id}/snapshots"), "two-snap", json={"expected_generation": 1}
        )["result"]["snapshot"]
        minted = as_bob.post(bob.path("/agent-credentials"), json={"label": "agent-1", "lifetime_seconds": 600}).json()
        ids = {
            "sandbox_id": sandbox_id,
            "idle_id": idle_id,
            "snapshot_id": snapshot["snapshot_id"],
            "execution_id": ran["target"]["execution_id"],
            "operation_id": ran["operation_id"],
            "credential_id": minted["credential_id"],
        }
        # Two projects are two owner scopes on the host, under the one peer the platform is.
        bobs_scope = operator.read("sandbox.inspect", "operator-view", {"sandbox": sandbox_id})["tags"]["owner_scope"]
        before = json.dumps(operator.read("sandbox.list", "operator-view", {"limit": 1000}), sort_keys=True)

        def as_carol_would(world: World, spec_method: str, http_method: str) -> httpx2.Response:
            call = route_calls(world)[spec_method]
            headers = {"Idempotency-Key": f"carol-{spec_method}"} if http_method != "GET" else {}
            return as_carol.request(http_method, call.path, params=call.params, json=call.json, headers=headers)

        in_bobs_project = World(dev=bob, **ids)  # type: ignore[arg-type]
        in_her_own = World(dev=carol, **ids)  # type: ignore[arg-type]
        project_routes = [spec for spec in ROUTES if "project" in spec.path_params]
        assert len(project_routes) == 19
        for spec in project_routes:
            # Naming the other project: nothing of it exists for this credential, whatever the route.
            named = as_carol_would(in_bobs_project, method_of(spec), spec.method)
            assert problem(named, "NOT_FOUND", 404)["retry"] == "NEVER", method_of(spec)

            # Naming her own project and the other's identifiers: possession of an identifier grants nothing.
            guessed = as_carol_would(in_her_own, method_of(spec), spec.method)
            if method_of(spec) in {"sandbox.list", "snapshot.list", "operation.list", "agent_credential.list"}:
                # A list of her own project: whatever she made herself, and nothing that is his.
                assert guessed.status_code == 200, method_of(spec)
                assert not [value for value in (*ids.values(), "bobs", bob.project_id) if value in guessed.text], (
                    method_of(spec)
                )
            elif method_of(spec) in {"sandbox.create", "agent_credential.mint"}:
                assert guessed.status_code in {200, 201, 202}, "her own project is hers to use"
            else:
                problem(guessed, "NOT_FOUND", 404)

        # Nothing of the other project changed, and what she made is under a scope of her own.
        carols = as_carol.get(carol.path("/sandboxes")).json()["items"]
        assert len(carols) == 1
        carols_scope = operator.read("sandbox.inspect", "operator-view", {"sandbox": carols[0]["sandbox_id"]})["tags"][
            "owner_scope"
        ]
        assert SCOPE.fullmatch(carols_scope)
        assert carols_scope != bobs_scope
        after = operator.read("sandbox.list", "operator-view", {"limit": 1000})
        bobs = [item for item in after["items"] if item["tags"]["owner_scope"] == bobs_scope]
        assert sorted(item["sandbox_id"] for item in bobs) == sorted([sandbox_id, idle_id])
        assert [item for item in json.loads(before)["items"] if item["tags"]["owner_scope"] == bobs_scope] == bobs
        assert as_bob.get(bob.path(f"/executions/{ids['execution_id']}")).json()["status"] == "EXITED"
        assert as_bob.get(bob.path("/agent-credentials")).json()["items"][0]["status"] == "ISSUED"

        for who, client in ((bob, as_bob), (carol, as_carol)):
            for item in client.get(who.path("/sandboxes")).json()["items"]:
                mutate(
                    client,
                    "DELETE",
                    who.path(f"/sandboxes/{item['sandbox_id']}"),
                    f"clean-{item['sandbox_id']}",
                    params={"expected_generation": "current"},
                )
        mutate(
            as_bob,
            "DELETE",
            bob.path(f"/snapshots/{snapshot['snapshot_id']}"),
            "clean-snapshot",
            params={"snapshot_generation": 1},
        )


# =============================================================================== what the processes have open
def _sockets_of(pid: int) -> set[str]:
    """The inode of every socket the process has open."""
    inodes: set[str] = set()
    for fd in os.listdir(f"/proc/{pid}/fd"):
        with contextlib.suppress(OSError):
            target = os.readlink(f"/proc/{pid}/fd/{fd}")
            if target.startswith("socket:["):
                inodes.add(target[len("socket:[") : -1])
    return inodes


def _files_of(pid: int) -> set[str]:
    """Every path the process has open that is a file, a directory or a device."""
    paths: set[str] = set()
    for fd in os.listdir(f"/proc/{pid}/fd"):
        with contextlib.suppress(OSError):
            target = os.readlink(f"/proc/{pid}/fd/{fd}")
            if target.startswith("/"):
                paths.add(target)
    return paths


@dataclass(frozen=True)
class Tcp:
    local_port: int
    remote_port: int
    listening: bool


def _tcp_of(pid: int) -> list[Tcp]:
    """The TCP sockets of the process, from the kernel's table of its network namespace."""
    mine, found = _sockets_of(pid), []
    for table in ("tcp", "tcp6"):
        with contextlib.suppress(OSError):
            for line in Path(f"/proc/{pid}/net/{table}").read_text(encoding="ascii").splitlines()[1:]:
                fields = line.split()
                if fields[9] in mine:
                    local, remote = fields[1].rsplit(":", 1)[1], fields[2].rsplit(":", 1)[1]
                    found.append(Tcp(int(local, 16), int(remote, 16), listening=fields[3] == "0A"))
    return found


def _unix_of(pid: int) -> list[tuple[str, bool]]:
    """The named Unix sockets of the process: path, and whether it listens."""
    mine, found = _sockets_of(pid), []
    for line in Path(f"/proc/{pid}/net/unix").read_text(encoding="utf-8").splitlines()[1:]:
        fields = line.split()
        if fields[6] in mine and len(fields) > 7:
            # Flags: 00010000 marks a socket that accepts connections.
            found.append((fields[7], int(fields[3], 16) & 0x10000 != 0))
    return found


@pytest.mark.proves("T3-SCOPE-01", level="L2")
def test_the_core_listens_on_its_two_sockets_and_talks_to_nothing_but_the_host(platform: Platform) -> None:
    """T3-SCOPE-01 at run time: the platform opens nothing outside its inventory.

    Observed from ``/proc``: every socket of the core process, matched by inode against the kernel's
    tables of TCP and Unix sockets, and every file it has open.
    """
    dave = platform.developer("dave")
    with platform.client(dave) as http:
        # Something of every kind was done, so every connection class to the host has been opened.
        sandbox_id = mutate(http, "POST", dave.path("/sandboxes"), "open-create", json=SMALL)["result"]["sandbox"][
            "sandbox_id"
        ]
        http.get(dave.path(f"/operations/{sandbox_id.replace('sbx-', 'op-')}"))
        mutate(http, "DELETE", dave.path(f"/sandboxes/{sandbox_id}"), "open-destroy", params={"expected_generation": 1})

        core, edge = platform.core.pid, platform.edge.pid
        tcp = _tcp_of(core)
        assert tcp, "the core has no connection to the host although it just used it"
        assert [connection for connection in tcp if connection.listening] == [], "the core listens on a network port"
        assert {connection.remote_port for connection in tcp} == {platform.host.port}, (
            "the core talks to something that is not the host"
        )
        assert len(tcp) <= 8, "more connections to the host than `host_max_connections`"

        unix = _unix_of(core)
        sockets = {str(platform.paths.command_socket), str(platform.paths.admin_socket)}
        assert {path for path, listening in unix if listening} == sockets
        assert {path for path, _ in unix} == sockets, "the core has a named local socket that is not one of its two"

        inventory = (
            str(platform.paths.store_dir),
            str(platform.paths.journal),
            str(platform.root / "core.log"),
            "/dev/null",
        )
        strays = sorted(path for path in _files_of(core) if not path.startswith(inventory))
        assert strays == [], f"the core has open: {strays}"

        # ---- the edge: one listener, its connections to the command socket, and nothing of the core's
        edge_tcp = _tcp_of(edge)
        assert {connection.local_port for connection in edge_tcp if connection.listening} == {platform.port}
        assert all(connection.local_port == platform.port for connection in edge_tcp), (
            "the edge opened a network connection of its own"
        )
        assert {path for path, _ in _unix_of(edge)} <= {str(platform.paths.command_socket)}
        held = _files_of(edge)
        for guarded in (platform.paths.store_dir, platform.paths.journal.parent, platform.root / "secrets"):
            assert not [path for path in held if path.startswith(str(guarded))], (
                f"the edge has something of {guarded} open"
            )
        assert (
            sorted(path for path in held if not path.startswith((str(platform.root / "edge.log"), "/dev/null"))) == []
        )


def test_an_edge_holds_nothing_it_could_give_away(platform: Platform) -> None:
    """EC-2, SEC-122: the edge's configuration names a socket and its bounds, and no secret, store or host."""
    text = (platform.root / "edge.yaml").read_text(encoding="utf-8")
    for word in ("secrets", "store", "journal", "fingerprint", "private_key", str(platform.host.port)):
        assert word not in text
    environment = Path(f"/proc/{platform.edge.pid}/environ").read_bytes().decode("utf-8", errors="replace")
    assert "acf1_" not in environment
    assert str(platform.paths.store_dir) not in Path(f"/proc/{platform.edge.pid}/cmdline").read_bytes().decode(
        "utf-8", errors="replace"
    )


# =============================================================================== stopping
def test_a_stop_signal_drains_the_core_and_the_edge_then_refuses_only_what_never_left_it(platform: Platform) -> None:
    """IPS-15: SIGTERM ends the core cleanly while an edge holds connections to it. Runs last: it stops the deployment."""
    erin = platform.developer("erin")
    with platform.client(erin) as http:
        assert http.get("/v1/auth/whoami").status_code == 200, "the edge now holds a connection to the core"
        assert platform.core.stop(signal.SIGTERM, timeout_s=20) == 0, platform.core.output()
        output = platform.core.output()
        assert '"event":"core_stopping","drained":true' in output
        assert "Traceback" not in output
        assert not platform.paths.command_socket.exists()
        assert not platform.paths.admin_socket.exists()

        # The edge is alive and says exactly what it knows: the core cannot be reached, and nothing was sent.
        assert http.get("/healthz").status_code == 200
        for response in (
            http.get("/v1/auth/whoami"),
            http.get("/v1/info"),
            http.post(erin.path("/sandboxes"), headers={"Idempotency-Key": "after-stop"}, json=SANDBOX_BODY),
        ):
            refused = problem(response, "UPSTREAM_UNAVAILABLE", 503)
            assert (refused["kind"], refused["retry"]) == ("REFUSED", "SAME_REQUEST_LATER")
            assert int(response.headers["retry-after"]) >= 1
    # The edge ends on the signal as well. Its server hands the signal back to the process once it has
    # shut down, so the status is the signal's own, which a service manager counts as a clean stop.
    assert platform.edge.stop(signal.SIGTERM, timeout_s=20) in {0, -signal.SIGTERM}, platform.edge.output()
    assert "Traceback" not in platform.edge.output()
