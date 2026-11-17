"""Isolation, network: ``network=none`` is not a setting the guest can undo (contract §18.6, §18.7, §27.5, SEC-006).

The host enforces it in three independent layers (``execution/host-agent/src/network``): the VMM is configured with
no network interface at all, it runs inside an empty network namespace, and the guest agent corroborates. These
tests attack from the outside in.

NAMING the mode (``control_plane``: these also run against the in-memory host, in CI, with the shipped files)
    ``none`` is the only mode that exists, everywhere a mode can be named: the CLI, the host's capability list, and
    the wire protocol, including a client that skips the CLI and sends the host whatever it likes. The CLI is not
    a security boundary, so the last one is the claim that matters.

BEING in the guest (a real microVM)
    The guest has no interface but loopback and no route; every attempt to leave (TCP, UDP, IPv4, IPv6, DNS, the
    metadata address, private ranges) fails *because there is no route*, not because it timed out; a service that
    listens on the host is not reachable from the guest, not even at ``127.0.0.1`` (that is the guest's own
    loopback); loopback itself works, so local-only workloads are not broken; the unprivileged workload cannot
    open raw or packet sockets or reconfigure interfaces.

The probes are small Python programs run inside the guest (``python -c``); each prints one JSON document.
"""

from __future__ import annotations

import errno
import socket
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress

import pytest

from acf_driver import EXIT_USAGE, AcfLocal, new_operation_id, raw_call

pytestmark = [pytest.mark.isolation, pytest.mark.usefixtures("clean_host")]

# What "there is no way out" looks like to a program: the kernel knows no route (or no such address family).
NO_ROUTE = {"ENETUNREACH", "EHOSTUNREACH", "EAFNOSUPPORT", "EADDRNOTAVAIL"}

RESOURCES = {"vcpus": 1, "memory_mib": 256, "disk_mib": 1024, "network": "none"}

GUEST_INTERFACES = """
import json, os
def rows(path, skip):
    try:
        return [r for r in open(path).read().splitlines()[skip:] if r.strip()]
    except OSError:
        return []
resolv = rows('/etc/resolv.conf', 0)
print(json.dumps({
    'interfaces': sorted(os.listdir('/sys/class/net')),
    'proc_dev': sorted(r.split(':')[0].strip() for r in rows('/proc/net/dev', 2)),
    'ipv4_route_devices': sorted({r.split()[0] for r in rows('/proc/net/route', 1)}),
    'ipv6_route_devices': sorted({r.split()[-1] for r in rows('/proc/net/ipv6_route', 0)}),
    'nameservers': [r for r in resolv if r.split()[:1] == ['nameserver']],
}))
"""

GUEST_EGRESS = """
import errno, json, socket
def name(e):
    return errno.errorcode.get(e.errno or 0, type(e).__name__)
def attempt(family, kind, host, port):
    try:
        s = socket.socket(family, kind)
    except OSError as e:
        return name(e)
    s.settimeout(3)
    try:
        s.connect((host, port))  # for UDP this only chooses a route: it fails at once when there is none
        return 'CONNECTED'
    except OSError as e:
        return name(e)
    finally:
        s.close()
targets = [
    (socket.AF_INET, '1.1.1.1', 53), (socket.AF_INET, '8.8.8.8', 443), (socket.AF_INET, '169.254.169.254', 80),
    (socket.AF_INET, '10.0.0.1', 80), (socket.AF_INET, '172.16.0.1', 80), (socket.AF_INET, '192.168.1.1', 80),
    (socket.AF_INET6, '2606:4700:4700::1111', 53), (socket.AF_INET6, 'fd00::1', 80),
]
result = {}
for kind_name, kind in (('tcp', socket.SOCK_STREAM), ('udp', socket.SOCK_DGRAM)):
    for family, host, port in targets:
        result[f'{kind_name} {host}:{port}'] = attempt(family, kind, host, port)
try:
    socket.getaddrinfo('example.com', 80)
    result['dns example.com'] = 'RESOLVED'
except OSError as e:
    result['dns example.com'] = type(e).__name__
try:
    result['localhost'] = sorted({a[4][0] for a in socket.getaddrinfo('localhost', 80, socket.AF_INET)})
except OSError as e:
    result['localhost'] = type(e).__name__
print(json.dumps(result))
"""

# argv: the port a service on the HOST listens on, then the host's own addresses.
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


# ------------------------------------------------------------------------------------------ naming the mode
@pytest.mark.control_plane
def test_none_is_the_only_network_mode_in_every_place_a_mode_can_be_named(acf: AcfLocal) -> None:
    for args in (
        ("run", "--image", acf.image, "--network", "restricted", "--command", "true"),
        ("sandbox", "create", "--image", acf.image, "--network", "host"),
    ):
        refused = acf.call(*args, "--json")
        assert refused.returncode == EXIT_USAGE, refused.describe()
        assert "--network" in refused.stderr, "the refusal must name the option that was wrong"
    assert acf.sandbox_list() == [], "a refused request must create nothing"

    modes = acf.host_info()["capabilities"]["network_modes"]
    assert modes == ["none"], f"the host must advertise exactly the one mode Phase 1 has: {modes}"
    box = acf.sandbox_create(acf.name("mode"))
    assert box["resources"]["network"] == "none"


@pytest.mark.control_plane
@pytest.mark.parametrize("mode", ["restricted", "host", "nat", "allowlist", "None", "NONE", " none", ""])
def test_a_client_that_bypasses_the_cli_still_cannot_ask_for_another_network_mode(acf: AcfLocal, mode: str) -> None:
    """The CLI is not a security boundary: the HOST must refuse, whoever sends the request and however it is spelt."""
    assert acf.socket is not None
    params = {"image": acf.image, "resources": {**RESOURCES, "network": mode}}
    answer = raw_call(acf.socket, "sandbox_create", params, operation_id=new_operation_id())
    assert answer.connected
    assert answer.status == "REJECTED", answer.frames
    assert answer.error is not None
    assert answer.error["class"] == "VALIDATION"
    assert answer.error["side_effect"] == "none", "a refusal must not have touched anything"
    assert "expected `none`" in answer.error["message"], answer.error["message"]
    assert acf.sandbox_list() == []

    # the same request with the one valid mode is accepted: it was the mode that was refused, not the request's shape
    ok = raw_call(acf.socket, "sandbox_create", {**params, "resources": RESOURCES}, operation_id=new_operation_id())
    assert ok.status == "SUCCEEDED", ok.frames
    assert len(acf.sandbox_list()) == 1


# ------------------------------------------------------------------------------------------ being in the guest
def test_the_guest_has_no_network_interface_but_loopback(acf: AcfLocal) -> None:
    box = acf.boot("ifaces")
    assert box.name is not None
    seen = acf.python(box.name, GUEST_INTERFACES).stdout_json()
    assert seen["interfaces"] == ["lo"], f"the guest must see loopback and nothing else: {seen['interfaces']}"
    assert seen["proc_dev"] == ["lo"]
    assert set(seen["ipv4_route_devices"]) <= {"lo"}, f"an IPv4 route leaves the machine: {seen['ipv4_route_devices']}"
    assert set(seen["ipv6_route_devices"]) <= {"lo"}, f"an IPv6 route leaves the machine: {seen['ipv6_route_devices']}"
    assert seen["nameservers"] == [], (
        f"a resolver is configured in a guest that cannot reach one: {seen['nameservers']}"
    )


def test_no_attempt_to_leave_the_machine_gets_anywhere(acf: AcfLocal) -> None:
    box = acf.boot("egress")
    assert box.name is not None
    seen = acf.python(box.name, GUEST_EGRESS, timeout="120s").stdout_json()
    local = seen.pop("localhost")
    dns = seen.pop("dns example.com")
    connected = {target: how for target, how in seen.items() if how == "CONNECTED"}
    assert connected == {}, f"the guest reached the outside: {connected}"
    timed_out = {target: how for target, how in seen.items() if how not in NO_ROUTE}
    assert timed_out == {}, (
        f"every attempt must fail with 'no route' ({sorted(NO_ROUTE)}). Anything else (a timeout, a refusal) means "
        f"packets went somewhere: {timed_out}"
    )
    assert dns == "gaierror", f"a name must not resolve in a guest with no resolver: {dns}"
    assert local == ["127.0.0.1"], f"`localhost` must resolve to the guest's own loopback and nothing else: {local}"


def test_a_service_on_the_host_is_not_a_neighbour_of_the_guest(acf: AcfLocal) -> None:
    with _listening_on_the_host() as (port, addresses, accepted):
        box = acf.boot("neighbour")
        assert box.name is not None
        seen = acf.python(box.name, GUEST_HOST_SERVICE, str(port), *addresses, timeout="120s").stdout_json()
        assert "CONNECTED" not in seen.values(), f"the guest connected to a service on the host: {seen}"
        assert seen["127.0.0.1"] == errno.errorcode[errno.ECONNREFUSED], (
            "127.0.0.1 inside the guest is the GUEST's loopback: nothing listens there, so it must be refused"
        )
        assert {a: seen[a] for a in addresses if a in seen} == dict.fromkeys(addresses, "ENETUNREACH"), (
            f"the host's own addresses must be unreachable, not merely unanswered: {seen}"
        )
    assert accepted() == 0, "the host's listener saw a connection from the guest"


def test_loopback_works_inside_the_guest(acf: AcfLocal) -> None:
    """The isolation must not break what a network-less workload legitimately does: talk to itself."""
    box = acf.boot("loopback")
    assert box.name is not None
    assert acf.python(box.name, GUEST_LOOPBACK).stdout_json() == {"echo": "LOOPBACK"}


def test_nothing_in_the_guest_listens_on_a_network_port(acf: AcfLocal) -> None:
    box = acf.boot("listeners")
    assert box.name is not None
    assert acf.python(box.name, GUEST_LISTENERS).stdout_json() == [], (
        "the guest agent speaks vsock only; a TCP listener means something was added to the image"
    )


def test_the_workload_cannot_open_raw_sockets_or_reconfigure_the_network(acf: AcfLocal) -> None:
    box = acf.boot("netadmin")
    assert box.name is not None
    seen = acf.python(box.name, GUEST_PRIVILEGED, timeout="120s").stdout_json()
    denied = {"EPERM", "EACCES"}
    for probe in ("packet_socket", "raw_icmp", "raw_tcp", "ip_forward"):
        assert seen[probe] in denied, f"the workload could do `{probe}`: {seen[probe]}"
    for command in ("link_add", "addr_add", "loopback_down"):
        assert seen[command] not in {0, "missing"}, (
            f"`ip {command}` must FAIL for the workload (exit {seen[command]!r}); 'missing' means the guest layer "
            "lost iproute2 and this test proved nothing"
        )
    assert seen["interfaces_after"] == ["lo"]


# ------------------------------------------------------------------------------------------ helpers
@contextmanager
def _listening_on_the_host() -> Iterator[tuple[int, list[str], Callable[[], int]]]:
    """A TCP service on every host address; yields (port, the host's non-loopback IPv4 addresses, accepted-count)."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 0))  # noqa: S104 - the point is a service reachable on every host address
    server.listen(8)
    server.setblocking(False)
    port = server.getsockname()[1]
    addresses = sorted({a for a in _host_addresses() if not a.startswith("127.")})

    def accepted() -> int:
        count = 0
        while True:
            try:
                conn, _ = server.accept()
            except BlockingIOError:
                return count
            conn.close()
            count += 1

    try:
        yield port, addresses, accepted
    finally:
        server.close()


def _host_addresses() -> list[str]:
    found: list[str] = []
    with suppress(OSError):
        found += [str(info[4][0]) for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)]
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(
            ("192.0.2.1", 9)
        )  # TEST-NET-1: connecting a UDP socket sends nothing, it picks the source address
        found.append(str(probe.getsockname()[0]))
    except OSError:
        pass
    finally:
        probe.close()
    return found
