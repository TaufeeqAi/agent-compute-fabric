"""An "outside world" for the network suites on a production host: somewhere for a guest to try to reach.

The allowlist checks need destinations that exist, answer, and can say whether anything arrived. Using the real
internet would make the suites depend on it and would send probes to machines that never asked for them. Instead
the lab builds a second network namespace on the host under test (the *far side*), joins it to the host with a
device pair, and gives it addresses from TEST-NET-2 (198.51.100.0/24, reserved for documentation, routed
nowhere)::

    guest ── tap0 ──[ sandbox namespace: filter + relay + resolver ]      host namespace          far side
                                                 relay connects from here ── acf-it-h ══════ acf-it-f
                                                                            198.51.100.1     198.51.100.10, .11

* A **listener** answers every contact with its own random token and writes one line per contact to a log. A guest
  that shows the token really exchanged bytes with that listener; a log without a line proves nothing arrived. A
  probe that only checks ``connect()`` proves nothing here: the host's relay accepts every redirected connection
  and then closes the ones it denies.
* **Names** are published in a marked block of ``/etc/hosts``, which the host's resolver consults for the names on
  a sandbox's allowlist. The block is removed when the lab closes.
* The host's end of the device pair is one of *the host's own addresses*: a destination the contract denies whatever
  the allowlist says. The lab must therefore be open **before** the sandbox under test is created.

Everything here needs root and changes the host's network configuration, so it is used only by the suites that
run against a production host (``ACF_INTEGRATION=1``). The guest-side probes are plain Python sources that the
suites run inside a sandbox; they print one JSON document.
"""

from __future__ import annotations

import contextlib
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType

from acf_driver.base import DriverError, wait_for

FAR_NAMESPACE = "acf-it-far"
HOST_DEVICE = "acf-it-h"
FAR_DEVICE = "acf-it-f"
#: The host's end of the pair: one of the host's own addresses.
HOST_ADDRESS = "198.51.100.1"
#: Two far-side addresses: tests list the first in an allowlist and leave the second out.
LISTED_ADDRESS = "198.51.100.10"
UNLISTED_ADDRESS = "198.51.100.11"
PREFIX = 24
#: An IPv6 pair on the same devices (2001:db8::/32 is the documentation prefix).
HOST_ADDRESS_V6 = "2001:db8:51::1"
FAR_ADDRESS_V6 = "2001:db8:51::10"
PREFIX_V6 = 64

HOSTS_FILE = Path("/etc/hosts")
HOSTS_BEGIN = "# >>> acf integration suites: published names (this block is removed when the test ends)"
HOSTS_END = "# <<< acf integration suites"

READY_LINE = "listening"

# One listener: argv = protocol family address port token log. It answers every contact with the token and logs
# "<peer address> <bytes received> <first bytes, hex>".
_LISTENER = r"""
import socket, sys
protocol, family, address, port, token, log = sys.argv[1:7]
kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
sock = socket.socket(socket.AF_INET6 if family == "6" else socket.AF_INET, kind)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((address, int(port)))
if protocol == "tcp":
    sock.listen(16)
out = open(log, "a", buffering=1)
out.write("listening\n")
while True:
    if protocol == "tcp":
        conn, peer = sock.accept()
        conn.settimeout(2.0)
        try:
            data = conn.recv(4096)
        except OSError:
            data = b""
        out.write("%s %d %s\n" % (peer[0], len(data), data[:16].hex()))
        try:
            conn.sendall(token.encode())
        except OSError:
            pass
        conn.close()
    else:
        data, peer = sock.recvfrom(4096)
        out.write("%s %d %s\n" % (peer[0], len(data), data[:16].hex()))
        sock.sendto(token.encode(), peer)
"""


def _run(*argv: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    done = subprocess.run(list(argv), capture_output=True, text=True, check=False, timeout=60)
    if check and done.returncode != 0:
        raise DriverError(
            f"`{' '.join(argv)}` failed ({done.returncode}): {done.stderr.strip() or done.stdout.strip()}"
        )
    return done


@dataclass
class Listener:
    """One listening socket of the lab, and what reached it."""

    where: str  # "far" or "host"
    protocol: str  # "tcp" or "udp"
    address: str
    port: int
    #: What it answers every contact with; nothing else on the machine knows this string.
    token: str
    log: Path
    process: subprocess.Popen[bytes]

    def contacts(self) -> list[str]:
        """One line per connection or datagram that reached this listener: ``peer bytes first-bytes-in-hex``."""
        lines = self.log.read_text(encoding="utf-8").splitlines()
        return [line for line in lines if line != READY_LINE]

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=10)


@dataclass
class FarSide:
    """The lab. Use it as a context manager; everything it created is removed on the way out."""

    directory: Path = field(default_factory=lambda: Path(tempfile.mkdtemp(prefix="acf-it-lab-")))
    listeners: list[Listener] = field(default_factory=list)

    # ---- life
    def __enter__(self) -> FarSide:
        if os.geteuid() != 0:
            raise DriverError("the network lab creates a namespace and a device pair: it needs root")
        if shutil.which("ip") is None:
            raise DriverError("the network lab needs `ip` (iproute2) on PATH")
        self._remove_network()  # what an interrupted earlier run may have left
        self._remove_names()
        try:
            self._build_network()
        except BaseException:
            self.close()
            raise
        return self

    def __exit__(
        self, kind: type[BaseException] | None, value: BaseException | None, trace: TracebackType | None
    ) -> None:
        self.close()

    def close(self) -> None:
        for listener in self.listeners:
            listener.stop()
        self.listeners.clear()
        self._remove_names()
        self._remove_network()
        shutil.rmtree(self.directory, ignore_errors=True)

    def _build_network(self) -> None:
        _run("ip", "netns", "add", FAR_NAMESPACE)
        _run("ip", "link", "add", HOST_DEVICE, "type", "veth", "peer", "name", FAR_DEVICE)
        _run("ip", "link", "set", FAR_DEVICE, "netns", FAR_NAMESPACE)
        _run("ip", "addr", "add", f"{HOST_ADDRESS}/{PREFIX}", "dev", HOST_DEVICE)
        _run("ip", "-6", "addr", "add", f"{HOST_ADDRESS_V6}/{PREFIX_V6}", "dev", HOST_DEVICE, "nodad")
        _run("ip", "link", "set", HOST_DEVICE, "up")
        far = ("ip", "-n", FAR_NAMESPACE)
        _run(*far, "link", "set", "lo", "up")
        for address in (LISTED_ADDRESS, UNLISTED_ADDRESS):
            _run(*far, "addr", "add", f"{address}/{PREFIX}", "dev", FAR_DEVICE)
        _run(*far, "-6", "addr", "add", f"{FAR_ADDRESS_V6}/{PREFIX_V6}", "dev", FAR_DEVICE, "nodad")
        _run(*far, "link", "set", FAR_DEVICE, "up")

    @staticmethod
    def _remove_network() -> None:
        _run("ip", "link", "del", HOST_DEVICE, check=False)
        _run("ip", "netns", "del", FAR_NAMESPACE, check=False)

    # ---- listeners
    def _listen(self, where: str, protocol: str, address: str, port: int) -> Listener:
        token = f"acf-it-{secrets.token_hex(12)}"
        log = self.directory / f"{where}-{protocol}-{address.replace(':', '_')}-{port}.log"
        family = "6" if ":" in address else "4"
        argv = [sys.executable, "-I", "-c", _LISTENER, protocol, family, address, str(port), token, str(log)]
        if where == "far":
            argv = ["ip", "netns", "exec", FAR_NAMESPACE, *argv]
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        listener = Listener(where, protocol, address, port, token, log, process)
        self.listeners.append(listener)

        def listening() -> bool | None:
            if process.poll() is not None:
                error = process.stderr.read().decode(errors="replace") if process.stderr else ""
                raise DriverError(f"the {where}-side {protocol} listener on {address}:{port} ended at once: {error}")
            return True if log.exists() and READY_LINE in log.read_text(encoding="utf-8") else None

        wait_for(f"the {where}-side {protocol} listener on {address}:{port}", listening, timeout=20.0, interval=0.05)
        return listener

    def tcp(self, address: str, port: int) -> Listener:
        """A TCP listener on the far side."""
        return self._listen("far", "tcp", address, port)

    def udp(self, address: str, port: int) -> Listener:
        """A UDP listener on the far side."""
        return self._listen("far", "udp", address, port)

    def tcp_on_host(self, address: str, port: int) -> Listener:
        """A TCP listener in the HOST's own namespace: something a guest must never reach."""
        return self._listen("host", "tcp", address, port)

    # ---- names
    def publish(self, names: Mapping[str, str]) -> None:
        """Make the host's own resolver answer ``name -> address`` (replaces what the lab published before)."""
        self._remove_names()
        block = [HOSTS_BEGIN, *(f"{address} {name}" for name, address in names.items()), HOSTS_END]
        original = HOSTS_FILE.read_text(encoding="utf-8")
        separator = "" if original.endswith("\n") or not original else "\n"
        HOSTS_FILE.write_text(original + separator + "\n".join(block) + "\n", encoding="utf-8")

    @staticmethod
    def _remove_names() -> None:
        try:
            lines = HOSTS_FILE.read_text(encoding="utf-8").splitlines()
        except OSError:
            return
        if HOSTS_BEGIN not in lines:
            return
        kept: list[str] = []
        inside = False
        for line in lines:
            if line == HOSTS_BEGIN:
                inside = True
            elif line == HOSTS_END:
                inside = False
            elif not inside:
                kept.append(line)
        HOSTS_FILE.write_text("\n".join(kept) + "\n", encoding="utf-8")


@contextlib.contextmanager
def far_side() -> Iterator[FarSide]:
    """The lab, open for the duration of a ``with`` block."""
    with FarSide() as lab:
        yield lab


# ================================================================================================ guest probes
# Each probe is run inside a sandbox as ``python -c SOURCE ARGUMENT`` and prints one JSON document.

#: argv[1]: JSON list of {"address", "port", "server_name"?, "family"?}. For each target the guest connects, sends
#: a TLS ClientHello carrying ``server_name`` (or one plain line), and reports what came back:
#: [{"connected": bool, "received": str, "error": str | None}, ...]
GUEST_TCP_PROBE = r"""
import json, socket, ssl, sys

def client_hello(name):
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    tls = context.wrap_bio(incoming, outgoing, server_hostname=name)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()

results = []
for target in json.loads(sys.argv[1]):
    outcome = {"connected": False, "received": "", "error": None}
    family = socket.AF_INET6 if target.get("family") == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(6.0)
    try:
        # Built before the connection exists: a listener waits only briefly for the first bytes, and building a
        # ClientHello can take longer than that in a small guest or on a busy machine.
        name = target.get("server_name")
        opening = client_hello(name) if name else b"acf-it probe\n"
        sock.connect((target["address"], target["port"]))
        outcome["connected"] = True
        sock.sendall(opening)
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        outcome["received"] = b"".join(chunks).decode("latin-1")
    except OSError as e:
        outcome["error"] = "%s: %s" % (type(e).__name__, e)
    finally:
        sock.close()
    results.append(outcome)
print(json.dumps(results))
"""

#: argv[1]: JSON list of [name, qtype] (1 = A, 28 = AAAA). The guest asks the resolver the host gave it
#: (/etc/resolv.conf) over UDP and reports, per question:
#: {"resolver": str, "rcode": int | None, "addresses": [str], "answers": int, "error": str | None}
#: argv[2], optional: "ADDRESS:PORT" of a resolver to ask instead (the driver's self-test uses it).
GUEST_DNS_PROBE = r"""
import json, os, socket, struct, sys

def resolver():
    for line in open("/etc/resolv.conf"):
        fields = line.split()
        if len(fields) >= 2 and fields[0] == "nameserver":
            return fields[1]
    raise OSError("/etc/resolv.conf names no resolver")

def skip_name(packet, at):
    while True:
        length = packet[at]
        if length == 0:
            return at + 1
        if length & 0xC0 == 0xC0:
            return at + 2
        at += 1 + length

def ask(server, port, name, qtype):
    ident = struct.unpack(">H", os.urandom(2))[0]
    question = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"
    query = struct.pack(">HHHHHH", ident, 0x0100, 1, 0, 0, 0) + question + struct.pack(">HH", qtype, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(8.0)
    try:
        sock.sendto(query, (server, port))
        while True:
            packet, _ = sock.recvfrom(2048)
            if len(packet) >= 12 and struct.unpack(">H", packet[:2])[0] == ident:
                break
    finally:
        sock.close()
    flags, questions, answers = struct.unpack(">HHH", packet[2:8])
    at = 12
    for _ in range(questions):
        at = skip_name(packet, at) + 4
    addresses = []
    for _ in range(answers):
        at = skip_name(packet, at)
        rtype, _klass, _ttl, size = struct.unpack(">HHIH", packet[at:at + 10])
        at += 10
        if rtype == 1 and size == 4:
            addresses.append(socket.inet_ntoa(packet[at:at + 4]))
        at += size
    return {"rcode": flags & 0x000F, "addresses": addresses, "answers": answers}

results = []
for name, qtype in json.loads(sys.argv[1]):
    outcome = {"resolver": None, "rcode": None, "addresses": [], "answers": 0, "error": None}
    try:
        server, port = sys.argv[2].rsplit(":", 1) if len(sys.argv) > 2 else (resolver(), "53")
        outcome["resolver"] = server
        outcome.update(ask(server, int(port), name, qtype))
    except (OSError, ValueError, IndexError, struct.error) as e:
        outcome["error"] = "%s: %s" % (type(e).__name__, e)
    results.append(outcome)
print(json.dumps(results))
"""

#: argv[1]: JSON {"udp": [[address, port], ...], "icmp": [address, ...]}. The guest sends one datagram to each UDP
#: target and one echo request to each ICMP target, and reports whether ANY reply came back:
#: {"udp": [{"sent": bool, "reply": str, "error": str | None}], "icmp": [{"sent": bool, "reply": bool, "error": ...}]}
GUEST_DATAGRAM_PROBE = r"""
import json, socket, struct, sys

plan = json.loads(sys.argv[1])
report = {"udp": [], "icmp": []}
for address, port in plan.get("udp", []):
    outcome = {"sent": False, "reply": "", "error": None}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(4.0)
    try:
        sock.sendto(b"acf-it datagram", (address, port))
        outcome["sent"] = True
        outcome["reply"] = sock.recvfrom(2048)[0].decode("latin-1")
    except OSError as e:
        outcome["error"] = "%s: %s" % (type(e).__name__, e)
    finally:
        sock.close()
    report["udp"].append(outcome)
for address in plan.get("icmp", []):
    outcome = {"sent": False, "reply": False, "error": None}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    except OSError as e:
        outcome["error"] = "%s: %s" % (type(e).__name__, e)
        report["icmp"].append(outcome)
        continue
    sock.settimeout(4.0)
    try:
        # An echo request; for this kind of socket the kernel fills in the identifier and the checksum.
        sock.sendto(struct.pack(">BBHHH", 8, 0, 0, 0, 1) + b"acf-it echo", (address, 0))
        outcome["sent"] = True
        sock.recvfrom(2048)
        outcome["reply"] = True
    except OSError as e:
        outcome["error"] = "%s: %s" % (type(e).__name__, e)
    finally:
        sock.close()
    report["icmp"].append(outcome)
print(json.dumps(report))
"""

#: No argument. What the guest's own kernel says about its network: interfaces, IPv4 and IPv6 addresses, routes.
GUEST_NETWORK_FACTS = r"""
import json, os, socket, struct

def read(path):
    try:
        return open(path).read()
    except OSError:
        return ""

interfaces = sorted(os.listdir("/sys/class/net"))
routes = []
for line in read("/proc/net/route").splitlines()[1:]:
    fields = line.split()
    if len(fields) >= 8:
        routes.append({
            "device": fields[0],
            "destination": socket.inet_ntoa(struct.pack("<L", int(fields[1], 16))),
            "gateway": socket.inet_ntoa(struct.pack("<L", int(fields[2], 16))),
            "mask": socket.inet_ntoa(struct.pack("<L", int(fields[7], 16))),
        })
inet6 = [line.split() for line in read("/proc/net/if_inet6").splitlines()]
print(json.dumps({
    "interfaces": interfaces,
    "routes": routes,
    "ipv6": [{"address": f[0], "scope": f[3], "device": f[5]} for f in inet6 if len(f) >= 6],
    "resolv_conf": read("/etc/resolv.conf"),
}))
"""
