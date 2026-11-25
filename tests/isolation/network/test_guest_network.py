"""Isolation, network: what a sandbox may reach, and what happens when the host's enforcement is lost.

The contract has two network modes. ``none`` means there is no network device in the guest. ``allowlist`` means
outbound TCP to the destinations of the sandbox's recorded entries, through the host's own resolver and relay, and
nothing else, for every protocol and address family.

ADMISSION (``control_plane``; evidence level L2/L3, shipped profile)
    Which intents the host records and which it refuses: an unknown mode word, a destination class the contract
    always denies, a private range the profile does not enable, a malformed entry, too many entries. A recorded
    intent is immutable: a restore carries it over unchanged.

BEING in the guest (a production host, as root; evidence level L4)
    One test per catalog entry, T-NET-01 to T-NET-08. The allowlist tests use the lab of
    ``acf_driver.netlab``: a second network namespace on the host with listeners that answer every contact with a
    token and log it. "Allowed" means the guest shows the listener's token; "denied" means the listener's log has
    no line. Connecting alone proves nothing: the relay accepts every redirected connection and then closes the
    ones it denies. The tests change the host's network configuration (a namespace, a device pair, a marked block in
    ``/etc/hosts``) and put it back.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager, suppress
from typing import Any

import pytest

from acf_driver import (
    EXIT_FAILED,
    EXIT_REFUSED,
    EXIT_UNKNOWN,
    EXIT_USAGE,
    AcfLocal,
    Sandbox,
    resources,
    snapshot_ref,
)
from acf_driver.netlab import (
    FAR_ADDRESS_V6,
    GUEST_DATAGRAM_PROBE,
    GUEST_DNS_PROBE,
    GUEST_NETWORK_FACTS,
    GUEST_TCP_PROBE,
    HOST_ADDRESS,
    LISTED_ADDRESS,
    UNLISTED_ADDRESS,
    FarSide,
    Listener,
    far_side,
)
from acf_integration import HostEnv, await_sandbox, edited_copy, in_namespace, private_host, require_root, vmm_of
from acf_proc import cgroup_pids, interfaces_in_namespace_of, namespace, pids_with_argument

pytestmark = [pytest.mark.isolation, pytest.mark.usefixtures("clean_host")]

# What "there is no way out" looks like to a program: the kernel knows no route (or no such address family).
NO_ROUTE = {"ENETUNREACH", "EHOSTUNREACH", "EAFNOSUPPORT", "EADDRNOTAVAIL"}
DNS_NOERROR, DNS_REFUSED = 0, 5
QTYPE_A, QTYPE_AAAA = 1, 28
PORT, OTHER_PORT, TLS_PORT = 8080, 8081, 8443
LISTED_NAME = "listed.acf-it.test"
UNLISTED_NAME = "unlisted.acf-it.test"
REBOUND_NAME = "rebound.acf-it.test"

#: Destination classes the contract denies whatever the entries say (AL-6).
ALWAYS_DENIED = {
    "loopback": "127.0.0.0/8",
    "one loopback address": "127.0.0.1/32",
    "link-local": "169.254.0.0/16",
    "the metadata address": "169.254.169.254/32",
    "multicast": "224.0.0.0/4",
    "broadcast": "255.255.255.255/32",
    "everything": "0.0.0.0/0",
}
PRIVATE_RANGES = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"]

GUEST_EGRESS = """
import errno, json, socket
def name(e):
    return errno.errorcode.get(e.errno or 0, type(e).__name__)
def attempt(family, kind, host, port):
    try:
        s = socket.socket(family, kind)
    except OSError as e:
        return 'socket:' + name(e)
    s.settimeout(3)
    try:
        if kind == socket.SOCK_STREAM:
            s.connect((host, port))
        else:
            s.sendto(b'x', (host, port))
        return 'SENT'
    except OSError as e:
        return name(e)
    finally:
        s.close()
targets = {
    'tcp public': (socket.AF_INET, socket.SOCK_STREAM, '198.51.100.10', 80),
    'udp dns': (socket.AF_INET, socket.SOCK_DGRAM, '198.51.100.10', 53),
    'tcp metadata': (socket.AF_INET, socket.SOCK_STREAM, '169.254.169.254', 80),
    'tcp private': (socket.AF_INET, socket.SOCK_STREAM, '10.0.0.1', 22),
    'tcp ipv6': (socket.AF_INET6, socket.SOCK_STREAM, '2001:db8::1', 80),
    'udp ipv6': (socket.AF_INET6, socket.SOCK_DGRAM, '2001:db8::1', 53),
}
result = {label: attempt(*spec) for label, spec in targets.items()}
try:
    socket.getaddrinfo('example.org', 80)
    result['resolve'] = 'RESOLVED'
except OSError as e:
    result['resolve'] = type(e).__name__
print(json.dumps(result))
"""

GUEST_HOST_SERVICE = """
import errno, json, socket, sys
port = int(sys.argv[1])
result = {}
for address in ['127.0.0.1', *sys.argv[2:]]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect((address, port))
        result[address] = 'CONNECTED'
    except OSError as e:
        result[address] = errno.errorcode.get(e.errno or 0, type(e).__name__)
    finally:
        s.close()
print(json.dumps(result))
"""

GUEST_LOOPBACK = """
import json, socket, threading
server = socket.socket()
server.bind(('127.0.0.1', 0))
server.listen(1)
port = server.getsockname()[1]
def serve():
    conn, _ = server.accept()
    conn.sendall(conn.recv(16).upper())
    conn.close()
threading.Thread(target=serve, daemon=True).start()
client = socket.create_connection(('127.0.0.1', port), timeout=5)
client.sendall(b'loopback')
print(json.dumps({'echo': client.recv(16).decode()}))
"""

GUEST_LISTENERS = """
import json
listening = []
for table in ('/proc/net/tcp', '/proc/net/tcp6'):
    try:
        rows = open(table).read().splitlines()[1:]
    except OSError:
        continue
    listening += [table + ' ' + r.split()[1] for r in rows if r.split()[3] == '0A']
print(json.dumps(listening))
"""

GUEST_PRIVILEGED = """
import errno, json, os, socket, subprocess
def tried(make):
    try:
        make().close()
        return 'allowed'
    except OSError as e:
        return errno.errorcode.get(e.errno or 0, type(e).__name__)
def ip(*args):
    try:
        return subprocess.run(['ip', *args], capture_output=True, timeout=20).returncode
    except (OSError, subprocess.SubprocessError):
        return 'missing'
def write(path):
    try:
        open(path, 'w').write('1')
        return 'allowed'
    except OSError as e:
        return errno.errorcode.get(e.errno or 0, type(e).__name__)
print(json.dumps({
    'packet_socket': tried(lambda: socket.socket(socket.AF_PACKET, socket.SOCK_RAW)),
    'raw_icmp': tried(lambda: socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)),
    'raw_tcp': tried(lambda: socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)),
    'link_add': ip('link', 'add', 'acf0', 'type', 'dummy'),
    'addr_add': ip('addr', 'add', '10.9.9.9/24', 'dev', 'lo'),
    'loopback_down': ip('link', 'set', 'lo', 'down'),
    'ip_forward': write('/proc/sys/net/ipv4/ip_forward'),
    'interfaces_after': sorted(os.listdir('/sys/class/net')),
}))
"""

# A listener INSIDE a guest, for the "other sandboxes" probe: argv = port token. It answers every contact.
GUEST_LISTEN = """
import socket, sys
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('0.0.0.0', int(sys.argv[1])))
server.listen(8)
while True:
    conn, _ = server.accept()
    conn.sendall(sys.argv[2].encode())
    conn.close()
"""


def _entry(destination: dict[str, str], *ports: tuple[int, int]) -> dict[str, Any]:
    return {"destination": destination, "ports": [{"from": low, "to": high} for low, high in ports or ((443, 443),)]}


def _allowlist(*entries: dict[str, Any]) -> dict[str, Any]:
    return {"mode": "allowlist", "entries": list(entries)}


def _create(acf: AcfLocal, network: dict[str, Any]) -> dict[str, Any]:
    return {"image": acf.image, "resources": resources(network=network)}


# ============================================================================================ admission
@pytest.mark.control_plane
def test_the_two_modes_of_the_contract_are_offered_and_no_other_word_names_a_mode(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    """§20.1: there are two network modes, ``none`` and ``allowlist``; any other value is refused; there is no
    fallback to a broader mode (NW-3). The contract names the class ``UNSUPPORTED``; the published request schema
    knows only the two words, so the host refuses any other one earlier, as ``INVALID_REQUEST``."""
    wire = acf.wire
    offered = set(wire.info().network_modes)
    assert offered <= {"none", "allowlist"}, f"the host offers a mode the contract does not define: {offered}"
    assert "none" in offered
    if host_env.control_plane:
        assert offered == set(host_env.profile.words("capabilities.network_modes"))

    usage = acf.call("sandbox", "create", "--image", acf.image, "--network", "host")
    assert usage.returncode == EXIT_USAGE, "the client must not send a mode word it does not know"
    with wire.nothing_recorded("a request naming a mode that does not exist"):
        for word in ("host", "nat", "bridge", "restricted", "NONE", "Allowlist", " none", ""):
            refusal = wire.call("sandbox.create", _create(acf, {"mode": word})).refused()
            assert refusal.failure_class in {"UNSUPPORTED", "INVALID_REQUEST"}, (word, refusal)
        shapes = [
            {"image": acf.image, "resources": {**resources(), "network": "none"}},
            _create(acf, {"mode": "none", "entries": []}),
            _create(acf, {"mode": "allowlist"}),
            _create(acf, _allowlist()),
            {"image": acf.image, "resources": {k: v for k, v in resources().items() if k != "network"}},
        ]
        for params in shapes:
            assert wire.call("sandbox.create", params).refused().failure_class == "INVALID_REQUEST", params
    assert wire.sandboxes() == []


@pytest.mark.control_plane
def test_a_mode_the_profile_does_not_list_is_refused_whatever_the_backend_supports(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    """§20.1: a mode is offered only if the profile lists it and the backend supports it. The backend here
    supports ``allowlist``; a profile that lists only ``none`` must be enough to keep it from being used."""
    host = host_env.test_host()
    assert host.profile is not None
    narrow = edited_copy(
        host.profile,
        host.base / "profile-without-allowlist.yaml",
        {"network_modes: [none, allowlist]": "network_modes: [none]"},
    )
    try:
        with private_host(host_env, acf, profile=narrow) as private:
            wire = private.acf.wire
            with wire.nothing_recorded("a mode the profile does not list"):
                refusal = private.acf.refused(
                    "sandbox", "create", "--image", acf.image, "--network", "allowlist", "--allow", "example.org:443"
                )
            assert (refusal.failure_class, refusal.retry) == ("SAFETY_CONTROL_DENIED", "AFTER_CHANGE")
            assert wire.create(acf.name("still-none")).network["mode"] == "none"
    finally:
        narrow.unlink(missing_ok=True)


@pytest.mark.control_plane
def test_an_allowlist_is_recorded_as_asked_and_a_restore_cannot_change_it(acf: AcfLocal) -> None:
    """NW-3: a generation's network intent is recorded and immutable."""
    wire = acf.wire
    name = acf.name("intent")
    created = acf.ok(
        "sandbox", "create", "--image", acf.image, "--name", name, "--memory", "128", "--disk", "256",
        "--network", "allowlist", "--allow", "pypi.org:443", "--allow", "198.51.100.0/24:5432-5433,8443",
    )  # fmt: skip
    box = created.succeeded().sandbox_result()
    expected = _allowlist(
        _entry({"name": "pypi.org"}, (443, 443)),
        _entry({"network": "198.51.100.0/24"}, (5432, 5433), (8443, 8443)),
    )
    assert box.network == expected, "the recorded intent is not what was asked for"

    ready = wire.start(box)
    snapshot = wire.snapshot(ready, acf.name("with-intent"))
    assert wire.restore_into(snapshot, ready).network == expected, "restore in place changed the network intent"
    assert wire.restore_new(snapshot, acf.name("clone")).network == expected, "a restored sandbox must carry the intent"
    with wire.nothing_recorded("a restore that names a network"):
        widened = wire.call(
            "snapshot.restore",
            {"snapshot": snapshot_ref(snapshot), "target": {"kind": "new", "network": {"mode": "none"}}},
        ).refused()
    assert widened.failure_class == "INVALID_REQUEST", "a restore has no way to name another network intent"
    plain = wire.create(acf.name("plain"), memory_mib=128, disk_mib=256)
    assert plain.network == {"mode": "none"}, "the default is no network"


@pytest.mark.control_plane
@pytest.mark.parametrize("what", sorted(ALWAYS_DENIED))
def test_t_auth_06_an_entry_naming_a_class_that_is_always_denied_is_refused(acf: AcfLocal, what: str) -> None:
    """AL-6 at admission: loopback, link-local (including metadata addresses), multicast and broadcast are denied
    whatever the entries say, so an entry that names one is refused and nothing is recorded."""
    wire = acf.wire
    with wire.nothing_recorded(f"an allowlist entry for {what}"):
        refusal = wire.call(
            "sandbox.create", _create(acf, _allowlist(_entry({"network": ALWAYS_DENIED[what]})))
        ).refused()
    assert (refusal.failure_class, refusal.retry) == ("INVALID_REQUEST", "NEVER"), refusal
    assert "always denied" in refusal.message
    assert wire.sandboxes() == []


@pytest.mark.control_plane
def test_t_auth_06_private_ranges_need_a_capability_the_shipped_profile_does_not_grant(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    """T-AUTH-06 (L2): a capability not granted -> ``SAFETY_CONTROL_DENIED``; no record. AL-6: private address
    ranges are denied unless the profile enables ``private_destinations`` and an entry names them."""
    wire = acf.wire
    assert host_env.profile.flag("capabilities.private_destinations") is False
    with wire.nothing_recorded("an allowlist entry for a private range"):
        through_client = acf.refused(
            "sandbox", "create", "--image", acf.image, "--network", "allowlist", "--allow", "10.1.2.3:443"
        )
        refusals = [
            wire.call("sandbox.create", _create(acf, _allowlist(_entry({"network": network})))).refused()
            for network in PRIVATE_RANGES
        ]
    for refusal in (through_client, *refusals):
        assert (refusal.failure_class, refusal.retry) == ("SAFETY_CONTROL_DENIED", "AFTER_CHANGE"), refusal
        assert "private_destinations" in refusal.message

    host = host_env.test_host()
    assert host.profile is not None
    granting = edited_copy(
        host.profile,
        host.base / "profile-with-private.yaml",
        {"private_destinations: false": "private_destinations: true"},
    )
    try:
        with private_host(host_env, acf, profile=granting) as private:
            admitted = private.acf.wire.call(
                "sandbox.create", _create(acf, _allowlist(_entry({"network": "10.0.0.0/8"})))
            ).succeeded()
            assert admitted.sandbox_result().network["entries"][0]["destination"] == {"network": "10.0.0.0/8"}
            still = private.acf.wire.call(
                "sandbox.create", _create(acf, _allowlist(_entry({"network": "127.0.0.0/8"})))
            ).refused()
            assert still.failure_class == "INVALID_REQUEST", "no profile can permit a class that is always denied"
    finally:
        granting.unlink(missing_ok=True)


@pytest.mark.control_plane
def test_a_malformed_entry_or_one_entry_too_many_is_refused_and_nothing_is_recorded(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    """AL-1: an entry is an exact DNS name or an IPv4 network and a non-empty set of ports; the number of entries
    is bounded by the profile."""
    wire = acf.wire
    malformed: list[dict[str, Any]] = [
        _entry({"network": "2001:db8::/32"}),  # IPv6 is not provided
        _entry({"network": "198.51.100.7/24"}),  # host bits set
        _entry({"network": "198.51.100.0/33"}),
        _entry({"network": "198.51.100.7"}),  # not in CIDR form
        _entry({"name": "*.example.org"}),  # an EXACT name: no wildcards
        _entry({"name": "localhost"}),
        _entry({"name": "example.org."}),
        _entry({"name": "under_score.example.org"}),
        _entry({"name": "203.0.113.5"}),  # an address is not a name
        _entry({"name": "a.example.org", "network": "198.51.100.0/24"}),
        {"destination": {"name": "a.example.org"}, "ports": []},
        {"destination": {"name": "a.example.org"}, "ports": [{"from": 0, "to": 1}]},
        {"destination": {"name": "a.example.org"}, "ports": [{"from": 9, "to": 1}]},
        {"destination": {"name": "a.example.org"}, "ports": [{"from": 1, "to": 65536}]},
        {"destination": {"name": "a.example.org"}, "ports": [{"from": 443, "to": 443}], "protocol": "udp"},
    ]
    with wire.nothing_recorded("a malformed allowlist entry"):
        for entry in malformed:
            refusal = wire.call("sandbox.create", _create(acf, _allowlist(entry))).refused()
            assert (refusal.failure_class, refusal.retry) == ("INVALID_REQUEST", "NEVER"), (entry, refusal)

    limit = host_env.profile.integer("limits.max_allowlist_entries")
    many = [_entry({"name": f"h{i}.example.org"}) for i in range(limit + 1)]
    with wire.nothing_recorded("an allowlist above the profile's bound"):
        too_many = wire.call("sandbox.create", _create(acf, _allowlist(*many))).refused()
    assert (too_many.failure_class, too_many.retry) == ("SAFETY_CONTROL_DENIED", "AFTER_CHANGE")
    at_limit = wire.call("sandbox.create", _create(acf, _allowlist(*many[:limit]))).succeeded().sandbox_result()
    assert len(at_limit.network["entries"]) == limit


# ============================================================================================ mode none (L4)
def _host_addresses() -> list[str]:
    """The IPv4 addresses this machine answers on, apart from loopback."""
    found: set[str] = set()
    with suppress(OSError):
        found.update(str(info[4][0]) for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET))
    with suppress(OSError), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect(("198.51.100.200", 9))  # no packet is sent: this only asks the kernel which address it would use
        found.add(probe.getsockname()[0])
    return sorted(address for address in found if not address.startswith("127."))


@contextmanager
def _listening_on_the_host() -> Iterator[tuple[int, list[socket.socket]]]:
    """A TCP listener on every address of the host, loopback included; yields the port and the sockets."""
    first = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    first.bind(("0.0.0.0", 0))  # noqa: S104 - the point is a service the guest would reach if it could reach the host
    first.listen(16)
    first.setblocking(False)
    try:
        yield first.getsockname()[1], [first]
    finally:
        first.close()


def test_t_net_01_mode_none_has_no_device_and_all_three_verification_layers_hold(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    """T-NET-01: "``none``: no device; all three verification layers".

    On the real host, as root. Layer one: the VMM is given no network device, so the guest's kernel has no
    interface but loopback and no route. Layer two: the VMM runs in a network namespace of its own that holds
    loopback and nothing else. Layer three: the guest corroborates, and can only add a violation: every attempt to
    leave (TCP, UDP, both address families, the metadata address, a private range, a name lookup) fails because
    there is no route, a service listening on every address of the host is unreachable, and the workload cannot
    create an interface or open a raw socket. Pass: all of it.
    """
    require_root(host_env, "looking into the network namespace of the VMM")
    box = acf.boot("none")
    assert box.network == {"mode": "none"}
    pid = vmm_of(box)[0]
    assert namespace(pid, "net") != namespace(os.getpid(), "net"), "the VMM shares the host's network namespace"
    assert interfaces_in_namespace_of(pid) == ["lo"], "the VMM's namespace must hold loopback and nothing else"
    assert cgroup_pids(host_env.traffic_cgroup_dir(box)) == [], "a sandbox with no network has a guest-traffic process"

    facts = acf.python(box.sandbox_id, GUEST_NETWORK_FACTS).stdout_json()
    assert facts["interfaces"] == ["lo"], f"the guest has a network device: {facts['interfaces']}"
    assert facts["routes"] == [], f"the guest has a route: {facts['routes']}"
    assert "nameserver" not in facts["resolv_conf"], "a sandbox without a network must have no resolver"

    egress = acf.python(box.sandbox_id, GUEST_EGRESS, options=["--time-limit", "120s"]).stdout_json()
    leaks = {label: outcome for label, outcome in egress.items() if outcome in {"SENT", "RESOLVED"}}
    assert leaks == {}, f"something left a guest that has no network: {leaks}"
    timeouts = {label: outcome for label, outcome in egress.items() if outcome in {"timeout", "TimeoutError"}}
    assert timeouts == {}, f"an attempt hung instead of failing at once; is there a route? {timeouts}"

    with _listening_on_the_host() as (port, listeners):
        addresses = _host_addresses()
        seen = acf.python(box.sandbox_id, GUEST_HOST_SERVICE, str(port), *addresses).stdout_json()
        assert "CONNECTED" not in seen.values(), f"the guest reached a service on the host: {seen}"
        assert seen["127.0.0.1"] == "ECONNREFUSED", "127.0.0.1 in the guest must be the guest's own loopback"
        for listener in listeners:
            with pytest.raises(BlockingIOError):
                listener.accept()

    privileged = acf.python(box.sandbox_id, GUEST_PRIVILEGED).stdout_json()
    for attempt in ("packet_socket", "raw_icmp", "raw_tcp", "ip_forward"):
        assert privileged[attempt] in {"EPERM", "EACCES", "EROFS"}, f"the workload could `{attempt}`: {privileged}"
    for attempt in ("link_add", "addr_add", "loopback_down"):
        assert privileged[attempt] != 0, f"the workload could `ip {attempt}`: {privileged}"
    assert privileged["interfaces_after"] == ["lo"]


def test_loopback_works_inside_a_guest_and_nothing_in_it_listens_on_a_port(acf: AcfLocal) -> None:
    box = acf.boot("loopback")
    assert acf.python(box.sandbox_id, GUEST_LOOPBACK).stdout_json() == {"echo": "LOOPBACK"}, (
        "loopback inside the guest must work: local-only workloads are not to be broken"
    )
    assert acf.python(box.sandbox_id, GUEST_LISTENERS).stdout_json() == [], (
        "something in the guest listens on a TCP port"
    )


# ============================================================================================ allowlist (L4)
def _probe_tcp(acf: AcfLocal, box: Sandbox, targets: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    run = acf.python(box.sandbox_id, GUEST_TCP_PROBE, json.dumps(list(targets)), options=["--time-limit", "180s"])
    assert run.succeeded(), run
    outcomes: list[dict[str, Any]] = run.stdout_json()
    return outcomes


def _resolve(acf: AcfLocal, box: Sandbox, *questions: tuple[str, int]) -> list[dict[str, Any]]:
    run = acf.python(
        box.sandbox_id, GUEST_DNS_PROBE, json.dumps([list(q) for q in questions]), options=["--time-limit", "120s"]
    )
    assert run.succeeded(), run
    answers: list[dict[str, Any]] = run.stdout_json()
    return answers


def _to(listener: Listener, server_name: str | None = None) -> dict[str, Any]:
    target: dict[str, Any] = {"address": listener.address, "port": listener.port}
    if server_name is not None:
        target["server_name"] = server_name
    return target


def _lab_sandbox(acf: AcfLocal, lab: FarSide, label: str) -> Sandbox:
    """An allowlist sandbox for the lab: one address on one port, and two names on the TLS port."""
    lab.publish({LISTED_NAME: LISTED_ADDRESS, REBOUND_NAME: LISTED_ADDRESS, UNLISTED_NAME: LISTED_ADDRESS})
    return acf.boot(
        label, allow=[f"{LISTED_ADDRESS}/32:{PORT}", f"{LISTED_NAME}:{TLS_PORT}", f"{REBOUND_NAME}:{TLS_PORT}"]
    )


def test_t_net_02_the_allowlist_matrix_of_listed_and_unlisted_destinations_and_ports(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    """T-NET-02: "allowlist matrix: listed and unlisted destinations and ports".

    On the real host, as root, with the lab open: the sandbox's entries are one address on one port and one name
    on one port. The guest contacts the listed address on its listed port, the listed address on another port,
    another address on the listed port, and the listed name (after resolving it, with that server name) on its
    port. Pass: the guest shows the token of exactly the listed combinations, and only those listeners logged a
    contact. A sandbox with no network at all, given the same targets, reaches none.
    """
    require_root(host_env, "building the network lab")
    with far_side() as lab:
        listed, other_port = lab.tcp(LISTED_ADDRESS, PORT), lab.tcp(LISTED_ADDRESS, OTHER_PORT)
        other_address = lab.tcp(UNLISTED_ADDRESS, PORT)
        by_name = lab.tcp(LISTED_ADDRESS, TLS_PORT)
        box = _lab_sandbox(acf, lab, "matrix")
        facts = acf.python(box.sandbox_id, GUEST_NETWORK_FACTS).stdout_json()
        assert facts["interfaces"] == ["eth0", "lo"], "an allowlist sandbox has exactly one device"

        resolved = _resolve(acf, box, (LISTED_NAME, QTYPE_A))[0]
        assert (resolved["rcode"], resolved["addresses"]) == (DNS_NOERROR, [LISTED_ADDRESS]), resolved
        targets = [_to(listed), _to(other_port), _to(other_address), _to(by_name, LISTED_NAME)]
        got = [outcome["received"] for outcome in _probe_tcp(acf, box, targets)]
        assert got == [listed.token, "", "", by_name.token], f"the matrix is not the allowlist: {got}"
        assert (len(listed.contacts()), len(by_name.contacts())) == (1, 1)
        assert (other_port.contacts(), other_address.contacts()) == ([], []), "a denied connection reached the far side"

        closed = acf.boot("matrix-none")
        refused = acf.python(closed.sandbox_id, GUEST_TCP_PROBE, json.dumps([_to(listed)])).stdout_json()
        assert refused[0]["connected"] is False, "a sandbox with no network connected somewhere"
        assert len(listed.contacts()) == 1


def test_t_net_03_a_name_outside_the_allowlist_is_refused_by_the_resolver(acf: AcfLocal, host_env: HostEnv) -> None:
    """T-NET-03: "a name outside the allowlist is refused with no upstream query".

    On the real host, as root, with the lab open: the host's own resolver knows the unlisted name (it is published
    next to the listed one), so an answer for it could only come from asking upstream. Pass: the guest's query for
    the unlisted name is answered ``REFUSED`` with no record; the listed name resolves to its address; a query for
    any other record type of the listed name returns no record (address records only); no datagram reaches a
    resolver other than the host's.
    """
    require_root(host_env, "building the network lab")
    with far_side() as lab:
        elsewhere = lab.udp(LISTED_ADDRESS, 53)
        box = _lab_sandbox(acf, lab, "names")
        listed, unlisted, never_published, other_type = _resolve(
            acf,
            box,
            (LISTED_NAME, QTYPE_A),
            (UNLISTED_NAME, QTYPE_A),
            ("nowhere.acf-it.test", QTYPE_A),
            (LISTED_NAME, QTYPE_AAAA),
        )
        assert (listed["rcode"], listed["addresses"]) == (DNS_NOERROR, [LISTED_ADDRESS]), listed
        assert (unlisted["rcode"], unlisted["answers"]) == (DNS_REFUSED, 0), (
            f"the resolver answered for a name the allowlist does not hold: {unlisted}"
        )
        assert (never_published["rcode"], never_published["answers"]) == (DNS_REFUSED, 0), never_published
        assert (other_type["rcode"], other_type["answers"]) == (DNS_NOERROR, 0), "address records only"

        direct = acf.python(
            box.sandbox_id, GUEST_DATAGRAM_PROBE, json.dumps({"udp": [[LISTED_ADDRESS, 53]]})
        ).stdout_json()
        assert direct["udp"][0]["reply"] == "", "the guest got an answer from a resolver that is not the host's"
        assert elsewhere.contacts() == [], "a name lookup left the sandbox for another resolver"


def test_t_net_04_an_address_that_changes_between_resolution_and_connection_is_denied(
    acf: AcfLocal, host_env: HostEnv
) -> None:
    """T-NET-04: "an address that changes between resolution and connection -> denied" (the allowlist rejects DNS
    rebinding).

    On the real host, as root, with the lab open: a listed name first resolves to a far-side address, and the
    guest's connection to it with that server name is relayed (the control). Then the name is re-published as one
    of the host's own addresses, where a listener waits. Pass: the resolver never hands the guest the denied
    address; a connection with the listed server name to that address, or to a far-side address the resolver never
    returned for the name, yields no token, and neither listener logs a contact.
    """
    require_root(host_env, "building the network lab")
    with far_side() as lab:
        first = lab.tcp(LISTED_ADDRESS, TLS_PORT)
        never_resolved = lab.tcp(UNLISTED_ADDRESS, TLS_PORT)
        on_the_host = lab.tcp_on_host(HOST_ADDRESS, TLS_PORT)
        box = _lab_sandbox(acf, lab, "rebind")

        assert _resolve(acf, box, (REBOUND_NAME, QTYPE_A))[0]["addresses"] == [LISTED_ADDRESS]
        control = _probe_tcp(acf, box, [_to(first, REBOUND_NAME)])[0]
        assert control["received"] == first.token, f"control: the listed name is not reachable at all: {control}"

        lab.publish({LISTED_NAME: LISTED_ADDRESS, REBOUND_NAME: HOST_ADDRESS})
        rebound = _resolve(acf, box, (REBOUND_NAME, QTYPE_A))[0]
        assert HOST_ADDRESS not in rebound["addresses"], "the resolver handed the guest one of the host's own addresses"
        after = _probe_tcp(acf, box, [_to(on_the_host, REBOUND_NAME), _to(never_resolved, REBOUND_NAME)])
        assert [outcome["received"] for outcome in after] == ["", ""], f"a rebound address was reached: {after}"
        assert (on_the_host.contacts(), never_resolved.contacts()) == ([], [])


def test_t_net_05_another_server_name_on_an_allowed_address_is_denied(acf: AcfLocal, host_env: HostEnv) -> None:
    """T-NET-05: "a different server name on an allowed address -> denied".

    On the real host, as root, with the lab open: after resolving the listed name, the guest opens three
    connections to the address it was given, on the entry's port: with another server name, with no server name
    at all (plain bytes), and with the listed one. Pass: only the last shows the listener's token, and the
    listener logs exactly that one contact.
    """
    require_root(host_env, "building the network lab")
    with far_side() as lab:
        listener = lab.tcp(LISTED_ADDRESS, TLS_PORT)
        box = _lab_sandbox(acf, lab, "server-name")
        assert _resolve(acf, box, (LISTED_NAME, QTYPE_A))[0]["addresses"] == [LISTED_ADDRESS]
        got = _probe_tcp(acf, box, [_to(listener, UNLISTED_NAME), _to(listener), _to(listener, LISTED_NAME)])
        assert [outcome["received"] for outcome in got] == ["", "", listener.token], got
        assert len(listener.contacts()) == 1, (
            f"a connection without the listed server name was relayed: {listener.contacts()}"
        )


def test_t_net_06_everything_the_contract_always_denies_is_denied(acf: AcfLocal, host_env: HostEnv) -> None:
    """T-NET-06: "loopback, link-local, metadata, host addresses, other sandboxes, IPv6, ICMP, UDP -> denied".

    On the real host, as root, with the lab open: listeners wait on the host's loopback, on the host's own lab
    address, on the far side over IPv6 and over UDP, and inside a second sandbox. The guest of the first sandbox
    tries each, and the metadata address, and sends an echo request to an address its allowlist names. Pass: no
    token comes back from any of them, no listener logs a contact, and no echo reply arrives; the allowed
    destination still works (the control), so "nothing arrived" is not just a broken sandbox.
    """
    require_root(host_env, "building the network lab")
    gateway = host_env.config.text("network.guest_segment").split("/")[0].rsplit(".", 1)
    gateway_address, guest_address = f"{gateway[0]}.{int(gateway[1]) + 1}", f"{gateway[0]}.{int(gateway[1]) + 2}"
    with far_side() as lab:
        allowed = lab.tcp(LISTED_ADDRESS, PORT)
        loopback, host_own = lab.tcp_on_host("127.0.0.1", PORT), lab.tcp_on_host(HOST_ADDRESS, PORT)
        over_v6, over_udp = lab.tcp(FAR_ADDRESS_V6, PORT), lab.udp(LISTED_ADDRESS, PORT)
        box = _lab_sandbox(acf, lab, "denied")
        neighbour = _lab_sandbox(acf, lab, "neighbour")
        neighbour_token = "acf-it-neighbour-token"
        serving = acf.spawn(
            "sandbox", "exec", neighbour.sandbox_id, "--time-limit", "300s", "--", "python", "-c", GUEST_LISTEN,
            str(PORT), neighbour_token,
        )  # fmt: skip
        try:
            await_sandbox(
                acf, neighbour, lambda seen: seen.state == "RUNNING", within=60, what="the neighbour listening"
            )
            targets = [
                _to(allowed),
                {"address": "127.0.0.1", "port": PORT},
                {"address": HOST_ADDRESS, "port": PORT},
                {"address": "169.254.169.254", "port": 80},
                {"address": gateway_address, "port": PORT},
                {"address": guest_address, "port": PORT},
                {"address": FAR_ADDRESS_V6, "port": PORT, "family": 6},
            ]
            got = [outcome["received"] for outcome in _probe_tcp(acf, box, targets)]
            datagrams = acf.python(
                box.sandbox_id,
                GUEST_DATAGRAM_PROBE,
                json.dumps({"udp": [[LISTED_ADDRESS, PORT]], "icmp": [LISTED_ADDRESS, HOST_ADDRESS]}),
                options=["--time-limit", "120s"],
            ).stdout_json()
        finally:
            serving.kill()
        assert got[0] == allowed.token, f"control: the allowed destination does not work: {got}"
        assert got[1:] == [""] * (len(targets) - 1), f"a destination that is always denied answered: {got}"
        assert neighbour_token not in "".join(got), "one sandbox reached another"
        for name, listener in (
            ("loopback", loopback),
            ("host address", host_own),
            ("IPv6", over_v6),
            ("UDP", over_udp),
        ):
            assert listener.contacts() == [], f"{name}: a denied contact arrived: {listener.contacts()}"
        assert datagrams["udp"][0]["reply"] == "", "UDP left the sandbox and was answered"
        assert [echo["reply"] for echo in datagrams["icmp"]] == [False, False], "an echo request was answered"
        assert len(allowed.contacts()) == 1


@pytest.mark.parametrize("loss", ["filter_flushed", "traffic_process_killed"])
def test_t_net_07_losing_the_enforcement_yields_no_connectivity(acf: AcfLocal, host_env: HostEnv, loss: str) -> None:
    """T-NET-07: "filtering state flushed, or the guest-traffic process killed -> no connectivity" (deny by
    construction: the absence, loss or corruption of the host's filtering state yields no connectivity, never
    more).

    On the real host, as root, with the lab open: the allowed destination is reached once (the control). Then the
    packet filter of the sandbox's namespace is flushed, or the guest-traffic process of the sandbox is sent
    SIGKILL. Pass: from then on no listener of the lab logs a contact from the sandbox, whether the guest's probe
    still runs or the host has already stopped the generation.
    """
    require_root(host_env, "building the network lab, entering a namespace and ending a process of another user")
    with far_side() as lab:
        allowed, never = lab.tcp(LISTED_ADDRESS, PORT), lab.tcp(UNLISTED_ADDRESS, PORT)
        box = _lab_sandbox(acf, lab, "lost")
        assert _probe_tcp(acf, box, [_to(allowed)])[0]["received"] == allowed.token, (
            "control: nothing works to begin with"
        )

        if loss == "filter_flushed":
            flushed = in_namespace(host_env, box, "nft", "flush", "ruleset")
            assert flushed.returncode == 0, flushed.stderr
        else:
            traffic = cgroup_pids(host_env.traffic_cgroup_dir(box))
            assert traffic, "control: the allowlist sandbox has no guest-traffic process to end"
            for pid in traffic:
                os.kill(pid, signal.SIGKILL)

        attempt = acf.execute(
            box.sandbox_id,
            ["python", "-c", GUEST_TCP_PROBE, json.dumps([_to(allowed), _to(never)])],
            options=["--time-limit", "120s"],
        )
        if attempt.completed.returncode not in {
            EXIT_REFUSED,
            EXIT_FAILED,
            EXIT_UNKNOWN,
        }:  # else: the generation is gone
            outcomes = attempt.run.stdout_json()
            assert [outcome["received"] for outcome in outcomes] == ["", ""], (
                f"connectivity without enforcement: {outcomes}"
            )
        time.sleep(2)  # a late packet would have arrived by now
        assert len(allowed.contacts()) == 1, (
            f"the sandbox reached the far side without enforcement: {allowed.contacts()}"
        )
        assert never.contacts() == [], "losing the enforcement opened a destination that was never allowed"


def test_t_net_08_a_generation_whose_network_setup_fails_never_runs(acf: AcfLocal, host_env: HostEnv) -> None:
    """T-NET-08: "network setup fails -> the generation never runs".

    On the real host, as root. The generation's network namespace exists from its creation (the host makes it
    when it provisions the generation); what the start adds inside it, for network mode ``allowlist``, is the
    guest's device. That name is taken in the namespace before the start is asked for, so the host's setup of
    the device fails (it never reuses something that already exists). Pass: the start ends ``FAILED``; the
    sandbox never becomes ``READY``; no VMM process of the generation exists.
    """
    require_root(host_env, "entering the generation's network namespace and seeing the VMM of another user")
    box = acf.wire.create(
        acf.name("no-setup"), network=_allowlist(_entry({"network": f"{LISTED_ADDRESS}/32"}, (PORT, PORT)))
    )
    handle = host_env.netns_handle(box)
    assert handle.exists(), "control: the generation's network namespace is made when it is created"
    taken = in_namespace(host_env, box, "ip", "link", "add", "tap0", "type", "dummy")
    assert taken.returncode == 0, f"control: the device name could not be taken: {taken.stderr}"
    done = acf.json("sandbox", "start", box.sandbox_id)
    after = acf.wire.refresh(box)
    running = pids_with_argument(box.jail_id)
    assert done.returncode == EXIT_FAILED, f"a generation without its network was started:\n{done.describe()}"
    assert done.operation().state == "FAILED"
    assert after.state != "READY", "a generation whose network could not be set up must never be ready"
    assert after.vmm_identity is None or not running, "a runtime was left behind"
    assert running == [], f"a VMM of the generation is running without a network: pids {running}"
