"""Looking at host processes through ``/proc``: what the white-box isolation tests know about the VMM and the agent.

The isolation claims about the HOST side are claims about processes: the VMM runs as an unprivileged uid inside a
chroot, a PID namespace and an empty network namespace, under seccomp, in its own cgroup, and nothing of ACF listens
on a network port. The kernel is the only witness that cannot be talked into agreeing, so the tests read ``/proc``
directly rather than trusting what the host agent says about itself.

Every reader is a thin wrapper over a pure ``parse_*`` function, so the formats are unit-tested against text
(``tests/tools/test_acf_proc.py``) and against this machine's own ``/proc``: a parser that is wrong is found on a
laptop, not on the first KVM run.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

PROC = Path("/proc")
CGROUP_ROOT = Path("/sys/fs/cgroup")
_SOCKET_LINK = re.compile(r"^socket:\[(\d+)\]$")

# /proc/net tables that hold network sockets, and the column of the socket inode in each.
INET_TABLES = ("tcp", "tcp6", "udp", "udp6", "raw", "raw6")
_INODE_COLUMN = 9


def parse_status(text: str) -> dict[str, str]:
    """``/proc/PID/status`` as ``{"Uid": "1000\\t1000\\t1000\\t1000", "Name": "sh", ...}`` (values stripped)."""
    found: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            found[key.strip()] = value.strip()
    return found


def proc_status(pid: int, *, tid: int | None = None) -> dict[str, str]:
    """The status of a process, or of one of its threads (``tid``)."""
    where = PROC / str(pid) / "task" / str(tid) if tid is not None else PROC / str(pid)
    return parse_status((where / "status").read_text())


def thread_statuses(pid: int) -> dict[int, dict[str, str]]:
    """``{tid: status}`` for every thread of ``pid`` (a thread that exits while we look is skipped)."""
    found: dict[int, dict[str, str]] = {}
    for entry in sorted((PROC / str(pid) / "task").iterdir(), key=lambda p: int(p.name)):
        try:
            found[int(entry.name)] = parse_status((entry / "status").read_text())
        except OSError:
            continue
    return found


def ids(status: Mapping[str, str], field: str) -> tuple[int, ...]:
    """The numbers of a ``Uid``/``Gid`` line: (real, effective, saved, filesystem)."""
    return tuple(int(n) for n in status[field].split())


def parse_socket_inodes(links: Iterable[str]) -> set[int]:
    """Inode numbers out of ``readlink`` results of ``/proc/PID/fd/*`` (``socket:[1234]`` -> 1234)."""
    found: set[int] = set()
    for link in links:
        match = _SOCKET_LINK.match(link)
        if match:
            found.add(int(match.group(1)))
    return found


def socket_inodes(pid: int) -> set[int]:
    """The inodes of every socket ``pid`` holds open."""
    links: list[str] = []
    for fd in (PROC / str(pid) / "fd").iterdir():
        try:
            links.append(str(fd.readlink()))
        except OSError:
            continue  # closed while we looked
    return parse_socket_inodes(links)


@dataclass(frozen=True)
class InetSocket:
    table: str  # tcp, tcp6, udp, udp6, raw, raw6
    local: str  # hex "ADDR:PORT" exactly as the kernel prints it
    state: str  # hex state ("0A" is TCP LISTEN)

    def __str__(self) -> str:
        return f"{self.table} {self.local} state {self.state}"


def parse_inet_table(table: str, text: str, inodes: set[int]) -> list[InetSocket]:
    """The rows of a ``/proc/net/{tcp,udp,...}`` table whose inode is in ``inodes`` (the header row is skipped)."""
    found: list[InetSocket] = []
    for row in text.splitlines()[1:]:
        fields = row.split()
        if len(fields) > _INODE_COLUMN and fields[_INODE_COLUMN].isdigit() and int(fields[_INODE_COLUMN]) in inodes:
            found.append(InetSocket(table, fields[1], fields[3]))
    return found


def inet_sockets(pid: int) -> list[InetSocket]:
    """Every network (IPv4/IPv6 TCP/UDP/raw) socket ``pid`` holds, looked up in the tables of ITS network namespace."""
    inodes = socket_inodes(pid)
    found: list[InetSocket] = []
    if not inodes:
        return found
    for table in INET_TABLES:
        try:
            text = (PROC / str(pid) / "net" / table).read_text()
        except OSError:
            continue  # the family is not compiled in
        found += parse_inet_table(table, text, inodes)
    return found


def parse_unix_table(text: str, inodes: set[int]) -> list[str]:
    """Bound paths (as the owner sees them) of the unix sockets in ``inodes``; abstract names keep their ``@``."""
    found: list[str] = []
    for row in text.splitlines()[1:]:
        fields = row.split(None, 7)
        if len(fields) == 8 and fields[6].isdigit() and int(fields[6]) in inodes:
            found.append(fields[7])
    return found


def unix_socket_paths(pid: int) -> list[str]:
    """Where ``pid``'s bound unix sockets live, relative to ITS root directory (a chrooted process sees a short path)."""
    return parse_unix_table((PROC / str(pid) / "net" / "unix").read_text(), socket_inodes(pid))


def host_path(pid: int, path_in_its_root: str) -> Path:
    """The path, on THIS machine, of a file ``pid`` sees at ``path_in_its_root`` (resolves its chroot)."""
    return Path((PROC / str(pid) / "root").readlink()) / path_in_its_root.lstrip("/")


def parse_net_dev(text: str) -> list[str]:
    """Interface names in ``/proc/PID/net/dev`` (two header lines first)."""
    return [line.partition(":")[0].strip() for line in text.splitlines()[2:] if ":" in line]


def interfaces_in_namespace_of(pid: int) -> list[str]:
    return parse_net_dev((PROC / str(pid) / "net" / "dev").read_text())


def namespace(pid: int, kind: str) -> str:
    """``net:[4026531840]``-style identity of one of ``pid``'s namespaces (``net``, ``pid``, ``mnt`` ...)."""
    return str((PROC / str(pid) / "ns" / kind).readlink())


def parse_cgroup_v2(text: str) -> str:
    """The path of a process in the unified (v2) hierarchy, from ``/proc/PID/cgroup``; raises if there is none."""
    for line in text.splitlines():
        hierarchy, _, rest = line.partition(":")
        if hierarchy == "0":
            return rest.partition(":")[2]
    raise ValueError("this process is not in a cgroup v2 hierarchy")


def cgroup_dir(pid: int) -> Path:
    """The cgroup v2 directory that confines ``pid``."""
    relative = parse_cgroup_v2((PROC / str(pid) / "cgroup").read_text())
    return CGROUP_ROOT / relative.lstrip("/")


def cgroup_value(directory: Path, name: str) -> str:
    return (directory / name).read_text().strip()
