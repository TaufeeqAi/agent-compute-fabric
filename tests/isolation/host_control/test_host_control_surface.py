"""Isolation, the host's control surface: who may give the host orders, and what a guest can reach of it.

INWARD (``control_plane``; evidence level L2/L3): a peer has authority only through an enrolment entry, acts only
within its role and its owner scope, and loses a connection when its entry is removed. These are the catalog
entries T-AUTH-01, T-AUTH-02, T-AUTH-03, T-AUTH-05 and T-AUTH-07, through the reference client and the raw wire,
over the local endpoint and over mutual TLS.

OUTWARD (a production host, as root; evidence level L4): T-SEC-02. What the processes of the host listen on or
hold open is compared with the contract's closed inventory of control surfaces, by reading the kernel's tables,
and a guest then tries every surface from the inside, in both network modes. The checks of the VMM's own
confinement that this inventory rests on are here too.
"""

from __future__ import annotations

import json
import os
import socket
import stat
import time
from pathlib import Path
from typing import Any

import pytest

from acf_driver import (
    SHIPPED_ENROLMENT,
    AcfLocal,
    api_description,
    probe_as_uid,
    resources,
)
from acf_driver.netlab import GUEST_TCP_PROBE
from acf_integration import HostEnv, HostUnit, SystemdUnit, edited_copy, private_host, require_root, vmm_of
from acf_proc import (
    cgroup_pids,
    children_of,
    command_line,
    confinement,
    file_identities,
    host_path,
    inet_sockets,
    inet_sockets_in_namespace_of,
    interfaces_in_namespace_of,
    unix_socket_paths,
)

pytestmark = [pytest.mark.isolation, pytest.mark.usefixtures("clean_host")]

UNPRIVILEGED = 65534  # "nobody": a local account that is neither root nor enrolled
GHOST_SANDBOX = "sbx-" + "0" * 32
GHOST_SNAPSHOT = {"snapshot_id": "snp-" + "0" * 32, "snapshot_generation": 1}
GHOST_OPERATION = "op-" + "0" * 32
GHOST_RUN = "run-" + "0" * 32
ROLES = ("observer", "caller", "operator")
TCP_LISTEN = "0A"
RELAY_PORT = 15001
RESOLVER_PORT = 53
#: The port the guest agent listens on inside the guest, and the host's address in that address family.
GUEST_AGENT_PORT = 5252

# What the guest may legitimately open read-write under /dev. Anything else is a way out or a way to attack the guest.
# `vsock` is the guest agent's own channel; the workload's use of it is attacked in the tests below.
HARMLESS_DEVICES = {"null", "zero", "full", "random", "urandom", "tty", "ptmx", "vsock"}

GUEST_REACH_THE_HOST = """
import errno, json, os, socket, stat, sys
host_socket = sys.argv[1]
def name(e):
    return errno.errorcode.get(e.errno or 0, type(e).__name__)
def connect(family, address):
    try:
        s = socket.socket(family, socket.SOCK_STREAM)
    except OSError as e:
        return 'socket:' + name(e)
    s.settimeout(3)
    try:
        s.connect(address)
        return 'CONNECTED'
    except OSError as e:
        return name(e)
    finally:
        s.close()
vsock = {}
if hasattr(socket, 'AF_VSOCK'):
    for port in (1, 22, 80, 443, 1024, 2049, 4000, 5000, 5252, 5253, 6000, 8080, 9999, 65535):
        vsock[str(port)] = connect(socket.AF_VSOCK, (2, port))  # CID 2 is the host
unix = {p: connect(socket.AF_UNIX, p) for p in (host_socket, '/run/acf/host-agent.sock', '/run/firecracker.socket')}
sockets = []
for top in ('/run', '/var', '/tmp', '/srv', '/opt', '/mnt', '/home', '/root', '/workspace', '/etc'):
    for root, _dirs, files in os.walk(top):
        for entry in _dirs + files:
            path = os.path.join(root, entry)
            try:
                if stat.S_ISSOCK(os.lstat(path).st_mode):
                    sockets.append(path)
            except OSError:
                pass
print(json.dumps({'vsock': vsock, 'unix': unix, 'sockets': sorted(sockets)}))
"""

GUEST_SELF_AGENT = """
import errno, fcntl, json, socket, struct, sys
port = int(sys.argv[1])
def local_cid():
    try:
        with open('/dev/vsock', 'rb') as device:
            buf = bytearray(4)
            fcntl.ioctl(device.fileno(), 0x7B9, buf, True)  # IOCTL_VM_SOCKETS_GET_LOCAL_CID
            return struct.unpack('I', buf)[0]
    except OSError:
        return None
result = {}
for label, cid in (('loopback_cid', getattr(socket, 'VMADDR_CID_LOCAL', 1)), ('own_cid', local_cid())):
    if cid is None:
        result[label] = 'no-cid'
        continue
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect((cid, port))
    except OSError as e:
        result[label] = 'blocked:' + errno.errorcode.get(e.errno or 0, type(e).__name__)
        continue
    request = json.dumps({'type': 'ping', 'nonce': 'intruder'}).encode()
    try:
        s.sendall(struct.pack('>I', len(request)) + request)
        reply = s.recv(4)
    except OSError as e:
        result[label] = 'dropped:' + errno.errorcode.get(e.errno or 0, type(e).__name__)
        continue
    finally:
        s.close()
    result[label] = 'SERVED' if reply else 'dropped:eof'
print(json.dumps(result))
"""

GUEST_DEVICES = """
import json, os, stat
DANGEROUS = ['kvm', 'mem', 'kmem', 'port', 'vhost-net', 'vhost-vsock', 'fuse', 'net/tun', 'vda', 'vdb', 'sda',
             'loop-control', 'uinput']
accessible = []
for name in sorted(os.listdir('/dev')):
    path = '/dev/' + name
    try:
        mode = os.lstat(path).st_mode
    except OSError:
        continue
    if (stat.S_ISCHR(mode) or stat.S_ISBLK(mode)) and os.access(path, os.R_OK | os.W_OK):
        accessible.append(name)
dangerous = [d for d in DANGEROUS if os.path.exists('/dev/' + d) and os.access('/dev/' + d, os.R_OK | os.W_OK)]
print(json.dumps({'accessible': accessible, 'dangerous': dangerous}))
"""


def _valid_params(acf: AcfLocal) -> dict[str, dict[str, Any] | None]:
    """For every method, parameters that pass the schema: the role check comes after it."""
    ghost = {"sandbox_id": GHOST_SANDBOX, "expected_generation": 1}
    return {
        "sandbox.create": {"image": acf.image, "resources": resources()},
        "sandbox.start": ghost,
        "exec.run": {**ghost, "command": {"argv": ["true"]}},
        "snapshot.create": ghost,
        "snapshot.restore": {"snapshot": GHOST_SNAPSHOT, "target": {"kind": "new"}},
        "sandbox.stop": ghost,
        "sandbox.destroy": ghost,
        "snapshot.delete": {"snapshot": GHOST_SNAPSHOT},
        "operation.cancel": {"operation_id": GHOST_OPERATION},
        "sandbox.inspect": {"sandbox": GHOST_SANDBOX},
        "sandbox.list": None,
        "snapshot.list": None,
        "operation.get": {"operation_id": GHOST_OPERATION},
        "operation.list": None,
        "run.inspect": {"run_id": GHOST_RUN},
        "run.output": {"run_id": GHOST_RUN, "stream": "stdout"},
        "host.info": None,
        "host.metrics": None,
        "profile.reload": None,
        "quarantine.release": {"sandbox_id": GHOST_SANDBOX, "generation": 1, "mode": "DECLARE_ABSENT"},
        "host.set_mode": {"mode": "SERVING"},
        "host.acknowledge": {"condition": "store_regression"},
    }


# ====================================================================================== INWARD: who may give orders
@pytest.mark.control_plane
def test_t_auth_01_a_chain_valid_but_unenrolled_peer_is_refused_before_any_request_is_read(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    """T-AUTH-01 (L2): a chain-valid but unenrolled peer -> ``AUTHENTICATION_FAILED``, closed before any request
    is read."""
    stranger = host_env.test_host().identity("stranger")
    wire = acf.wire
    with wire.nothing_recorded("a connection of an unenrolled peer"):
        with stranger.connect() as connection:
            unasked = connection.read(timeout=10)
            assert unasked is not None, "the host closed without saying why"
            refusal = unasked.refused()
            assert (refusal.failure_class, refusal.retry) == ("AUTHENTICATION_FAILED", "NEVER")
            assert unasked.as_of is None, "a peer without authority learns nothing about the host's state"
            assert unasked.request_id is None, "the refusal answers no request: none was read"
            assert connection.peer_closed(within=10), "the connection of an unenrolled peer must be closed"
        through_client = host_env.peer(acf, "stranger").json("host", "info").answer()
    assert through_client.refused().failure_class == "AUTHENTICATION_FAILED"


@pytest.mark.control_plane
def test_t_auth_01_an_unknown_local_caller_is_refused_before_any_request_is_read(
    acf: AcfLocal, host_env: HostEnv, tmp_path: Path
) -> None:
    """T-AUTH-01 (L2): an unknown local caller -> ``AUTHENTICATION_FAILED``, closed before any request is read.

    The host is started with the shipped enrolment example, edited only so that the one local user it enrols is not
    the user running this test: reaching the socket is not authority.
    """
    table = edited_copy(
        SHIPPED_ENROLMENT, tmp_path / "enrolment.yaml", {"local_uid: 0": f"local_uid: {os.geteuid() + 1}"}
    )
    with private_host(host_env, acf, enrolment=table) as private:
        with private.host.connect() as connection:
            unasked = connection.read(timeout=10)
            assert unasked is not None, "the host closed without saying why"
            assert unasked.refused().failure_class == "AUTHENTICATION_FAILED"
            assert (unasked.as_of, unasked.request_id) == (None, None)
            assert connection.peer_closed(within=10)
        done = private.acf.json("sandbox", "create", "--image", acf.image)
        assert done.refusal().failure_class == "AUTHENTICATION_FAILED"
        assert not any(private.host.state_root.glob("sandboxes/*")), "an unenrolled local caller created something"


@pytest.mark.control_plane
def test_the_local_endpoint_is_closed_to_other_local_users(acf: AcfLocal, host_env: HostEnv) -> None:
    require_root(host_env, "connecting to the local endpoint as another user")
    mine = probe_as_uid(host_env.socket, os.geteuid(), {"probe": "not a request"})
    assert mine.connected, "control: the probe itself cannot connect, so a refusal below would prove nothing"
    other = probe_as_uid(host_env.socket, UNPRIVILEGED, {"probe": "not a request"})
    assert not other.connected, f"uid {UNPRIVILEGED} connected to the host's local endpoint"
    assert other.connect == "PermissionError", other
    assert stat.S_IMODE(host_env.socket.stat().st_mode) & 0o007 == 0, "the local endpoint is open to everyone"


@pytest.mark.control_plane
def test_the_published_roles_are_the_roles_of_the_contract() -> None:
    """§9.2: an observer may call ``host.info`` and ``host.metrics``; a caller every granting, containment and
    read method; an operator all of that and the operator methods."""
    for method in api_description().methods:
        if method.name in {"host.info", "host.metrics"}:
            expected: tuple[str, ...] = ROLES
        elif method.method_class == "operator":
            expected = ("operator",)
        else:
            expected = ("caller", "operator")
        assert tuple(method.roles) == expected, method.name


@pytest.mark.control_plane
@pytest.mark.parametrize("role", ROLES)
def test_t_auth_02_every_method_is_allowed_for_a_role_exactly_as_the_contract_says(
    acf: AcfLocal, host_env: HostEnv, role: str
) -> None:
    """T-AUTH-02 (L2): every method x every role -> allowed exactly as §9.2. A method outside the peer's role is
    refused with ``AUTHORIZATION_DENIED`` and records nothing."""
    peer = host_env.peer(acf, role).wire
    params = _valid_params(acf)
    methods = api_description().methods
    assert {method.name for method in methods} == set(params), "this test must cover every published method"
    for method in methods:
        allowed = role in method.roles
        if allowed:
            answer = peer.call(method.name, params[method.name])
            classes = (answer.refusal.failure_class,) if answer.refusal is not None else ()
            assert not set(classes) & {"AUTHORIZATION_DENIED", "AUTHENTICATION_FAILED"}, (role, method.name, answer)
            continue
        with acf.wire.nothing_recorded(f"`{method.name}` called by a {role}"):
            refusal = peer.call(method.name, params[method.name]).refused()
        assert (refusal.failure_class, refusal.retry) == ("AUTHORIZATION_DENIED", "NEVER"), (role, method.name)


@pytest.mark.control_plane
def test_t_auth_03_another_owner_scope_sees_not_found_and_an_operator_succeeds(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    """T-AUTH-03 (L2): a different owner scope -> ``NOT_FOUND`` on reads and mutations, so that the existence of a
    record is not revealed; an operator succeeds."""
    owner = host_env.peer(acf, "caller", scope="it-scope-a")
    outsider = host_env.peer(acf, "caller", scope="it-scope-b")
    box = owner.wire.ready(acf.name("owned"))
    ran = owner.wire.run(box, ["true"])
    assert ran.run_id is not None
    assert box.owner == ("tls-caller", "it-scope-a")
    target = {"sandbox_id": box.sandbox_id, "expected_generation": box.generation}

    with acf.wire.nothing_recorded("a request across owner scopes"):
        refusals = [
            outsider.refused("sandbox", "inspect", box.sandbox_id),
            outsider.refused("sandbox", "inspect", str(box.name)),
            outsider.refused("operation", "get", ran.operation_id),
            outsider.refused("run", "inspect", ran.run_id),
            outsider.wire.call("run.output", {"run_id": ran.run_id, "stream": "stdout"}).refused(),
            outsider.wire.call("exec.run", {**target, "command": {"argv": ["true"]}}).refused(),
            outsider.wire.call("sandbox.stop", target).refused(),
            outsider.wire.call("sandbox.destroy", target).refused(),
            outsider.wire.call("operation.cancel", {"operation_id": ran.operation_id}).refused(),
        ]
    assert [(r.failure_class, r.retry) for r in refusals] == [("NOT_FOUND", "NEVER")] * len(refusals), refusals
    assert outsider.ok("sandbox", "list").sandboxes().items == []
    assert ran.operation_id not in {op.operation_id for op in outsider.wire.operations()}
    assert owner.wire.refresh(box).state == "COMPLETED", "a request from another scope reached the sandbox"

    operator = host_env.peer(acf, "operator", scope="it-scope-of-the-operator")
    assert operator.inspect(box.sandbox_id).owner == ("tls-caller", "it-scope-a"), "an operator reads any record"
    assert operator.ok("operation", "get", ran.operation_id).accepted().run_id == ran.run_id
    destroyed = operator.ok("sandbox", "destroy", box.sandbox_id, "--yes").succeeded().sandbox_result()
    assert destroyed.state == "DESTROYED", "an operator acts on any record"


@pytest.mark.control_plane
def test_t_auth_05_a_removed_enrolment_entry_makes_the_open_connection_unusable_within_the_bound(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    """T-AUTH-05 (L2): an enrolment entry is removed -> the open connection is unusable within the bound
    (``edge.enrolment_refresh_ms``)."""
    bound = host_env.config.integer("edge.enrolment_refresh_ms") / 1000
    with private_host(host_env, acf, tls=True) as private:
        caller, operator = private.host.identity("caller"), private.host.identity("operator")
        table = private.host.enrolment_path
        with caller.connect() as connection:
            assert connection.request("sandbox.list").answer == "RESULT", "control: the caller is enrolled"
            kept = [line for line in table.read_text(encoding="utf-8").splitlines() if "tls-caller" not in line]
            table.write_text("\n".join(kept) + "\n", encoding="utf-8")
            removed = time.monotonic()

            unasked = connection.read(timeout=bound + 5)
            took = time.monotonic() - removed
            assert unasked is not None, "the connection was closed without a reason"
            assert unasked.refused().failure_class == "AUTHENTICATION_FAILED"
            assert took <= bound + 1, f"the removed peer kept its connection for {took:.1f}s; the bound is {bound:.0f}s"
            assert connection.peer_closed(within=10)

        with caller.connect() as again:
            refused = again.read(timeout=10)
            assert refused is not None
            assert refused.refused().failure_class == "AUTHENTICATION_FAILED", "a new connection of the removed peer"
        with operator.connect() as other:
            assert other.request("host.info").answer == "RESULT", "the other entries are untouched"


@pytest.mark.control_plane
def test_t_auth_07_a_profile_reload_is_a_recorded_operator_operation_that_changes_no_earlier_run(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    """T-AUTH-07 (L2): a profile reload does not change an operation that was admitted before it; reload is a
    recorded operator operation; an invalid profile is refused."""
    ceiling = host_env.profile.integer("limits.max_pids")
    with private_host(host_env, acf) as private:
        client, wire, profile = private.acf, private.acf.wire, private.host.profile_path
        original = profile.read_text(encoding="utf-8")
        assert original.count(f"max_pids: {ceiling}") == 1
        box = wire.ready(acf.name("before"))
        earlier = wire.run(box, ["true"], limits={"max_pids": ceiling}).run_result()
        old_digest = wire.info().profile_digest
        assert earlier.profile_digest == old_digest, "a run records the profile it was admitted under"

        profile.write_text(original.replace(f"max_pids: {ceiling}", f"max_pids: {ceiling // 2}"), encoding="utf-8")
        assert wire.info().profile_digest == old_digest, "an edited file is not in force until it is reloaded"
        reloaded = client.ok("profile", "reload").succeeded()
        assert (reloaded.operation_type, reloaded.owner[0]) == ("profile.reload", "local-operator")
        new_digest = wire.info().profile_digest
        assert new_digest not in {old_digest, ""}
        assert reloaded.host_change().profile_digest == new_digest
        assert wire.info().ceilings["max_pids"] == ceiling // 2

        assert client.ok("run", "inspect", earlier.run_id).run().profile_digest == old_digest, "the earlier run changed"
        over = client.refused("sandbox", "exec", box.sandbox_id, "--max-pids", str(ceiling), "--", "true")
        assert over.failure_class == "SAFETY_CONTROL_DENIED", "the new ceiling binds the next request"
        later = client.execute(box.sandbox_id, ["true"]).run
        assert later.profile_digest == new_digest

        for broken, why in (
            (original.replace(f"max_pids: {ceiling}", "max_pids: 0"), "a ceiling of zero"),
            (original + "\nunknown_section: {}\n", "a field the host does not know"),
        ):
            profile.write_text(broken, encoding="utf-8")
            with wire.nothing_recorded("a reload of an invalid profile"):
                refusal = client.refused("profile", "reload")
            assert refusal.failure_class == "INTEGRITY_FAILURE", why
            assert wire.info().profile_digest == new_digest, f"{why} replaced the profile in force"

        profile.write_text(original, encoding="utf-8")
        profile.chmod(0o666)
        writable = client.refused("profile", "reload")
        assert writable.failure_class == "INTEGRITY_FAILURE", "a profile others can write is not a trusted input"
        profile.chmod(0o644)
        assert client.ok("profile", "reload").succeeded().host_change().profile_digest == old_digest


# ====================================================================== OUTWARD: what the host opens (L4, as root)
def _kernel_form(address: str, port: int) -> str:
    """An IPv4 address and port as ``/proc/net/{tcp,udp}`` print them."""
    return f"{socket.inet_aton(address)[::-1].hex().upper()}:{port:04X}"


def _gateway(host_env: HostEnv) -> str:
    """The host's address on a sandbox's segment: the first address of ``network.guest_segment``."""
    network = host_env.config.text("network.guest_segment").split("/")[0]
    return socket.inet_ntoa((int.from_bytes(socket.inet_aton(network), "big") + 1).to_bytes(4, "big"))


def _edge_of(core: int) -> int:
    edges = [pid for pid in children_of(core) if "edge" in command_line(pid)]
    assert len(edges) == 1, f"expected exactly one edge process under the core (pid {core}), found {edges}"
    return edges[0]


def test_t_sec_02_what_the_host_opens_is_the_inventory_and_a_guest_reaches_none_of_it(
    acf: AcfLocal, host_env: HostEnv, host_unit: HostUnit
) -> None:
    """T-SEC-02: "what the release artifact listens on or opens equals the inventory; a guest probe reaches none of
    it, in every network mode".

    On the real host, as root, with one sandbox in each network mode running: the sockets of every process of the
    host (the core, its edge, the lifetime enforcer, both VMMs, the guest-traffic process) are read from the
    kernel's tables and compared with the contract's closed inventory: the local endpoint and (only if configured)
    the network endpoint in the edge; the VMM's control socket and the guest channel inside the jail; the resolver
    and the relay of the allowlist sandbox, inside its namespace; nothing else, and no listener for connections a
    guest initiates. Then each guest tries the surfaces from the inside. Pass: the tables hold exactly the
    inventory, and no guest connects to, or gets an answer from, any of it.
    """
    require_root(host_env, "reading the socket tables and descriptors of every process of the host")
    closed = acf.boot("no-network")
    open_ = acf.boot("allowlist", allow=["198.51.100.10:8443"])
    core = host_unit.main_pid()
    edge = _edge_of(core)
    enforcer = SystemdUnit(host_env.lifetime_unit).main_pid()
    vmms = {box.sandbox_id: vmm_of(box)[0] for box in (closed, open_)}
    traffic = cgroup_pids(host_env.traffic_cgroup_dir(open_))
    assert len(traffic) == 1, f"expected one guest-traffic process for the allowlist sandbox, found {traffic}"
    assert cgroup_pids(host_env.traffic_cgroup_dir(closed)) == [], "a sandbox with no network has a traffic process"

    # --- the edge: the two ingress endpoints, and nothing else
    assert str(host_env.socket) in unix_socket_paths(edge), "control: the edge does not hold the local endpoint"
    listening = sorted(str(s) for s in inet_sockets(edge) if s.table.startswith("tcp") and s.state == TCP_LISTEN)
    if host_env.config.has("edge.tls.listen"):
        address, _, port = host_env.config.text("edge.tls.listen").rpartition(":")
        assert listening == [f"tcp {_kernel_form(address, int(port))} state {TCP_LISTEN}"], listening
    else:
        assert listening == [], f"no network endpoint is configured, yet the edge listens on {listening}"
    assert [s for s in inet_sockets(edge) if not s.table.startswith("tcp")] == [], "the edge holds a UDP or raw socket"

    # --- the core and the lifetime enforcer: no network socket at all, and no endpoint of their own
    for name, pid in (("core", core), ("lifetime enforcer", enforcer)):
        assert [str(s) for s in inet_sockets(pid)] == [], f"the {name} holds a network socket"
    own = sorted({path for path in unix_socket_paths(core) if path.startswith(("/", "@"))} - {str(host_env.socket)})
    assert own == [], f"the core holds an endpoint that is not in the inventory: {own}"
    assert [path for path in unix_socket_paths(enforcer) if path.startswith(("/", "@"))] == []

    # --- each VMM: its control socket and the guest channel, inside its jail; no network socket
    for box in (closed, open_):
        pid = vmms[box.sandbox_id]
        jail = host_env.jail_root(box)
        assert [str(s) for s in inet_sockets(pid)] == [], "a VMM holds a network socket"
        bound = sorted(str(host_path(pid, path)) for path in unix_socket_paths(pid) if path.startswith("/"))
        assert bound == sorted(str(jail / name) for name in ("api.sock", "v.sock")), bound
        initiated_by_guest = sorted(path.name for path in jail.glob("v.sock_*"))
        assert initiated_by_guest == [], f"a listener for guest-initiated connections exists: {initiated_by_guest}"
    assert interfaces_in_namespace_of(vmms[closed.sandbox_id]) == ["lo"], "mode `none`: the namespace must be empty"

    # --- the guest-traffic process: the resolver and the relay, in the sandbox's namespace, and nothing else
    gateway = _gateway(host_env)
    inside = sorted(str(s) for s in inet_sockets_in_namespace_of(traffic[0], vmms[open_.sandbox_id]))
    assert inside == sorted(
        [
            f"tcp {_kernel_form(gateway, RELAY_PORT)} state {TCP_LISTEN}",
            f"udp {_kernel_form(gateway, RESOLVER_PORT)} state 07",
        ]
    ), inside
    outside = [str(s) for s in inet_sockets(traffic[0]) if s.state == TCP_LISTEN]
    assert outside == [], f"the guest-traffic process listens in the host's own namespace: {outside}"

    # --- from the inside, in both network modes
    for box in (closed, open_):
        seen = acf.python(
            box.sandbox_id, GUEST_REACH_THE_HOST, str(host_env.socket), options=["--time-limit", "180s"]
        ).stdout_json()
        assert "CONNECTED" not in seen["vsock"].values(), (
            f"the guest connected to a service on the host: {seen['vsock']}"
        )
        assert set(seen["unix"].values()) == {"ENOENT"}, (
            f"a host socket exists in the guest's filesystem: {seen['unix']}"
        )
        named_like_ours = [path for path in seen["sockets"] if "host-agent" in path or "firecracker" in path]
        assert named_like_ours == [], f"a control socket appears in the guest's filesystem: {named_like_ours}"
    targets = [{"address": gateway, "port": port} for port in (RELAY_PORT, 22, 80, 443, 8443)]
    answers = acf.python(open_.sandbox_id, GUEST_TCP_PROBE, json.dumps(targets), options=["--time-limit", "120s"])
    received = {
        f"{t['address']}:{t['port']}": r["received"] for t, r in zip(targets, answers.stdout_json(), strict=True)
    }
    assert set(received.values()) == {""}, f"something on the host's side of the segment answered the guest: {received}"


def test_the_vmm_runs_unprivileged_in_its_own_jail_and_shares_no_identity(acf: AcfLocal, host_env: HostEnv) -> None:
    require_root(host_env, "reading the status of the VMM processes")
    uid_range = (
        host_env.config.integer("firecracker.uid_range_start"),
        host_env.config.integer("firecracker.uid_range_size"),
    )
    boxes = [acf.boot("jail-a"), acf.boot("jail-b")]
    uids: list[int] = []
    for box in boxes:
        pid = vmm_of(box)[0]
        facts = confinement(pid, compared_with=os.getpid())
        assert facts.violations(uid_range=uid_range) == [], f"the VMM of {box.sandbox_id} is not confined: {facts}"
        assert facts.root == host_env.jail_root(box), "the VMM's root directory is not its generation's jail"
        assert pid in cgroup_pids(host_env.cgroup_dir(box)), "the VMM is not in its generation's control group"
        uids.append(facts.uids[0])
    assert uids[0] != uids[1], "two VMs must never share a user id"


def test_the_state_directory_is_closed_to_other_users(acf: AcfLocal, host_env: HostEnv) -> None:
    require_root(host_env, "walking the host's state directory")
    box = acf.boot("modes")
    acf.wire.snapshot(box, acf.name("modes"))  # so that a snapshot directory exists too
    root = host_env.state_root
    assert (root.stat().st_uid, stat.S_IMODE(root.stat().st_mode)) == (0, 0o700), f"{root} must be 0700 root-owned"

    loose: list[str] = []
    for directory, dirs, _files in os.walk(root):
        here = Path(directory)
        if here.name == "images":  # operator-installed inputs; the host only reads them
            dirs[:] = []
            continue
        if here.name == "jail":  # the VMM's own root: its modes are the jailer's, and the test above checks it
            dirs[:] = []
        mode = stat.S_IMODE(here.stat().st_mode)
        if mode & 0o077:
            loose.append(f"{here} {mode:04o}")
    assert loose == [], "directories the host keeps must be closed to group and others:\n  " + "\n  ".join(loose)
    snapshots = sorted((root / "snapshots").glob("*/*/*"))
    assert snapshots, "control: no snapshot file was found to check"
    readable = [str(path) for path in snapshots if stat.S_IMODE(path.stat().st_mode) & 0o077]
    assert readable == [], f"snapshot data holds guest memory and must be readable by the core only: {readable}"


def test_the_vmms_sockets_are_unreachable_to_other_local_users(acf: AcfLocal, host_env: HostEnv) -> None:
    require_root(host_env, "connecting to a VMM's sockets as another user")
    box = acf.boot("sockets")
    pid = vmm_of(box)[0]
    inside = [path for path in unix_socket_paths(pid) if path.startswith("/")]
    assert inside, f"control: the VMM binds no socket that could be tried; saw {unix_socket_paths(pid)}"
    verdict = {str(host_path(pid, path)): probe_as_uid(host_path(pid, path), UNPRIVILEGED).connect for path in inside}
    assert set(verdict.values()) == {"PermissionError"}, f"another local user could reach a VMM socket: {verdict}"


def test_the_vmm_holds_no_file_of_the_hosts_own_state(acf: AcfLocal, host_env: HostEnv) -> None:
    require_root(host_env, "reading the descriptors of the VMM")
    box = acf.boot("inherit")
    pid = vmm_of(box)[0]
    state = host_env.state_root
    private = [
        state,
        state / "state",
        state / "state" / "journal.wal",
        state / "state" / "host-agent.lock",
        state / "images",
        state / "snapshots",
        host_env.profile.path,
        host_env.config.path,
        Path(host_env.config.text("paths.enrolment_path")),
    ]
    forbidden = {(p.stat().st_dev, p.stat().st_ino): str(p) for p in private if p.exists()}
    assert len(forbidden) >= 5, f"control: the probe found too few of the host's files to look for: {forbidden}"
    held = file_identities(pid)
    leaked = sorted(f"{held[identity]} -> {path}" for identity, path in forbidden.items() if identity in held)
    assert leaked == [], f"the VMM holds files of the host's own state: {leaked}"


# ====================================================================== OUTWARD, guest side (L4)
def test_the_guest_agent_obeys_only_the_host(acf: AcfLocal) -> None:
    """The host initiates every connection of the guest protocol, and the guest agent accepts connections only
    from the host: the workload, inside the guest, is not the host."""
    box = acf.boot("agent-peer")
    seen = acf.python(
        box.sandbox_id, GUEST_SELF_AGENT, str(GUEST_AGENT_PORT), options=["--time-limit", "120s"]
    ).stdout_json()
    assert "SERVED" not in seen.values(), f"the guest agent served a request from inside the guest: {seen}"
    assert acf.sh(box.sandbox_id, "echo alive").stdout_text == "alive\n"


def test_the_guest_has_no_device_that_is_a_control_channel(acf: AcfLocal) -> None:
    box = acf.boot("devices")
    seen = acf.python(box.sandbox_id, GUEST_DEVICES).stdout_json()
    assert seen["dangerous"] == [], (
        f"the workload can open a device that reaches the host or the disk: {seen['dangerous']}"
    )
    unexpected = sorted(set(seen["accessible"]) - HARMLESS_DEVICES)
    assert unexpected == [], (
        f"device nodes the workload can read and write beyond {sorted(HARMLESS_DEVICES)}: {unexpected}. If one is "
        "harmless, add it to HARMLESS_DEVICES with the reason; if not, the image must not ship it."
    )
