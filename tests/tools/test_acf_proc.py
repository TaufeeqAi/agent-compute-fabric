"""The ``/proc`` readers of the isolation suites: formats against text, and against this machine's own kernel.

A reader that misparses a kernel table would make an isolation test pass vacuously (an empty list of listeners
looks exactly like a host with no listeners), so they are checked first against the documented formats and then
against sockets this very process creates.
"""

from __future__ import annotations

import os
import socket
from pathlib import Path

import pytest

from acf_proc import (
    CGROUP_ROOT,
    PROC,
    cgroup_dir,
    host_path,
    ids,
    inet_sockets,
    interfaces_in_namespace_of,
    namespace,
    parse_cgroup_v2,
    parse_inet_table,
    parse_net_dev,
    parse_socket_inodes,
    parse_status,
    parse_unix_table,
    proc_status,
    same_file,
    socket_inodes,
    thread_statuses,
    unix_socket_paths,
)

STATUS = """Name:\tfirecracker
Umask:\t0022
State:\tS (sleeping)
NSpid:\t4242\t1
Uid:\t100007\t100007\t100007\t100007
Gid:\t100007\t100007\t100007\t100007
CapEff:\t0000000000000000
NoNewPrivs:\t1
Seccomp:\t2
"""

TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0016 0100007F:D431 01 00000000:00000000 00:00000000 00000000     0        0 777 1 0000000000000000 20 4 30 10 -1
"""

UNIX = """Num       RefCount Protocol Flags    Type St Inode Path
0000000000000000: 00000002 00000000 00010000 0001 01 23456 /run/acf/host-agent.sock
0000000000000000: 00000003 00000000 00000000 0001 03 23457
0000000000000000: 00000002 00000000 00010000 0001 01 23458 @abstract
"""

NET_DEV = """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
  eth0:     100       1    0    0    0     0          0         0       50       1    0    0    0     0       0          0
"""


# ------------------------------------------------------------------------------------------------ formats
def test_status_lines_become_a_mapping() -> None:
    status = parse_status(STATUS)
    assert status["Name"] == "firecracker"
    assert status["Seccomp"] == "2"
    assert status["NSpid"].split() == ["4242", "1"]
    assert ids(status, "Uid") == (100007, 100007, 100007, 100007)


def test_only_socket_links_yield_inodes() -> None:
    links = ["socket:[10]", "pipe:[11]", "/dev/null", "anon_inode:[eventfd]", "socket:[12]", "socket:[x]"]
    assert parse_socket_inodes(links) == {10, 12}


def test_an_inet_table_is_filtered_by_inode_and_the_header_is_skipped() -> None:
    rows = parse_inet_table("tcp", TCP, {12345})
    assert [(r.table, r.local, r.state) for r in rows] == [("tcp", "0100007F:1F90", "0A")]
    assert parse_inet_table("tcp", TCP, {1}) == []
    assert parse_inet_table("tcp", TCP, set()) == []
    assert [r.state for r in parse_inet_table("tcp", TCP, {12345, 777})] == ["0A", "01"]


def test_unix_sockets_without_a_path_are_ignored_and_abstract_names_are_kept() -> None:
    assert parse_unix_table(UNIX, {23456, 23457, 23458}) == ["/run/acf/host-agent.sock", "@abstract"]
    assert parse_unix_table(UNIX, {23457}) == []


def test_interface_names_are_read_after_the_two_header_lines() -> None:
    assert parse_net_dev(NET_DEV) == ["lo", "eth0"]
    assert parse_net_dev(NET_DEV.splitlines()[0] + "\n" + NET_DEV.splitlines()[1] + "\n") == []


def test_the_unified_cgroup_line_is_the_one_that_counts() -> None:
    assert parse_cgroup_v2("0::/acf/firecracker/abc\n") == "/acf/firecracker/abc"
    assert parse_cgroup_v2("12:memory:/legacy\n0::/unified\n") == "/unified"
    with pytest.raises(ValueError, match="cgroup v2"):
        parse_cgroup_v2("12:memory:/legacy\n")


# ------------------------------------------------------------------------------------------------ this kernel
needs_proc_net = pytest.mark.skipif(not (PROC / "net" / "tcp").exists(), reason="this kernel has no /proc/net/tcp")


def test_our_own_status_is_readable_and_consistent() -> None:
    status = proc_status(os.getpid())
    assert ids(status, "Uid")[0] == os.getuid()
    assert ids(status, "Gid")[0] == os.getgid()
    assert len(ids(status, "Uid")) == 4
    threads = thread_statuses(os.getpid())
    assert threads
    assert all("Name" in t for t in threads.values())


def test_a_namespace_has_an_identity_and_our_root_is_the_real_root() -> None:
    assert namespace(os.getpid(), "net").startswith("net:[")
    assert same_file(host_path(os.getpid(), "/etc/hostname"), Path("/etc/hostname"))
    assert not same_file(host_path(os.getpid(), "/etc/hostname"), Path("/etc/passwd"))


@needs_proc_net
def test_a_listening_tcp_socket_of_ours_is_found_with_its_port() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        assert listener.fileno() >= 0
        assert socket_inodes(os.getpid())
        mine = [s for s in inet_sockets(os.getpid()) if s.table == "tcp" and s.local.endswith(f":{port:04X}")]
        assert [s.state for s in mine] == ["0A"], f"expected one LISTEN socket on port {port}: {mine}"
    after = [s for s in inet_sockets(os.getpid()) if s.local.endswith(f":{port:04X}")]
    assert after == [], "a closed socket must disappear from the view"


@needs_proc_net
def test_a_bound_udp_socket_is_found() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind(("127.0.0.1", 0))
        port = udp.getsockname()[1]
        assert [s.table for s in inet_sockets(os.getpid()) if s.local.endswith(f":{port:04X}")] == ["udp"]


def test_a_bound_unix_socket_is_found_by_its_path(tmp_path: Path) -> None:
    path = tmp_path / "s"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(path))
        server.listen(1)
        if not (PROC / "net" / "unix").exists():
            pytest.skip("this kernel has no /proc/net/unix")
        assert str(path) in unix_socket_paths(os.getpid())


def test_our_network_namespace_lists_at_least_loopback() -> None:
    if not (PROC / "net" / "dev").exists():
        pytest.skip("this kernel has no /proc/net/dev")
    assert "lo" in interfaces_in_namespace_of(os.getpid())


def test_our_cgroup_directory_exists_on_a_unified_hierarchy() -> None:
    try:
        directory = cgroup_dir(os.getpid())
    except (ValueError, OSError):
        pytest.skip("this machine has no cgroup v2 hierarchy for this process")
    assert directory == CGROUP_ROOT or CGROUP_ROOT in directory.parents
