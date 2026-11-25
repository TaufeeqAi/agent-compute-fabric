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
    """A path on THIS machine that reaches the file ``pid`` sees at ``path_in_its_root``.

    Through ``/proc/PID/root``, which the kernel resolves in the process's own root. Reading the link instead
    would not do: a jailer gives the VMM a mount namespace of its own and moves its root there with
    ``pivot_root``, and seen from here the link then reads ``/``. Compare what this path reaches with
    :func:`same_file`, not its text.
    """
    return PROC / str(pid) / "root" / path_in_its_root.lstrip("/")


def same_file(a: Path, b: Path) -> bool:
    """Whether ``a`` and ``b`` are the same file or directory: the same device and inode, through links."""
    try:
        x, y = a.stat(), b.stat()
    except OSError:
        return False
    return (x.st_dev, x.st_ino) == (y.st_dev, y.st_ino)


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


def cgroup_pids(directory: Path) -> list[int]:
    """The processes a control group holds right now (empty when the group does not exist)."""
    try:
        text = (directory / "cgroup.procs").read_text()
    except OSError:
        return []
    return [int(line) for line in text.split() if line.isdigit()]


# ------------------------------------------------------------------------------------------- which process is it
def parse_stat(text: str) -> list[str]:
    """The fields of ``/proc/PID/stat`` from the third one (the state) on.

    The second field, the command name, may itself contain spaces and parentheses, so the rest starts after the
    LAST ``)``. Index 0 is the state, index 1 the parent pid, index 19 the start time in clock ticks.
    """
    return text.rpartition(")")[2].split()


def start_time_ticks(pid: int) -> int | None:
    """When ``pid`` started, in clock ticks since boot; ``None`` when there is no such process (a zombie has exited)."""
    try:
        fields = parse_stat((PROC / str(pid) / "stat").read_text())
    except OSError:
        return None
    if len(fields) < 20 or fields[0] in {"Z", "X"}:
        return None
    return int(fields[19])


def process_alive(pid: int, started_at_ticks: int) -> bool:
    """Is the process with exactly this identity still running on THIS machine?

    The host identifies a process by ``(pid, start time)`` because a pid alone can be recycled: a different process
    that reuses the number is not the one that was asked about.
    """
    return start_time_ticks(pid) == started_at_ticks


def parent_of(pid: int) -> int | None:
    try:
        fields = parse_stat((PROC / str(pid) / "stat").read_text())
    except OSError:
        return None
    return int(fields[1]) if len(fields) > 1 else None


def all_pids() -> list[int]:
    return sorted(int(entry.name) for entry in PROC.iterdir() if entry.name.isdigit())


def children_of(pid: int) -> list[int]:
    """The processes whose parent is ``pid``."""
    return [child for child in all_pids() if child != pid and parent_of(child) == pid]


def executable(pid: int) -> Path | None:
    """The file ``pid`` executes, as the kernel names it; ``None`` when it cannot be read (gone, or not ours)."""
    try:
        return (PROC / str(pid) / "exe").readlink()
    except OSError:
        return None


def command_line(pid: int) -> list[str]:
    """The argument vector of ``pid`` (empty when it cannot be read)."""
    try:
        raw = (PROC / str(pid) / "cmdline").read_bytes()
    except OSError:
        return []
    return [part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part]


def pids_with_argument(argument: str) -> list[int]:
    """Every live process that has ``argument`` in its argument vector (a generation's host-derived id names its VMM)."""
    return [pid for pid in all_pids() if argument in command_line(pid) and start_time_ticks(pid) is not None]


def pids_running_as(uid: int) -> list[int]:
    """Every live process whose real, effective, saved or filesystem uid is ``uid``."""
    found: list[int] = []
    for pid in all_pids():
        try:
            status = proc_status(pid)
        except OSError:
            continue  # it exited while we looked
        if "Uid" in status and uid in ids(status, "Uid") and start_time_ticks(pid) is not None:
            found.append(pid)
    return found


def file_identities(pid: int) -> dict[tuple[int, int], str]:
    """``(device, inode) -> where`` for every file ``pid`` holds open or has mapped.

    Two names of one file (a hard link, a path seen through another root directory) have the same identity, so this
    answers "does this process still use that file?" whatever name it was opened by.
    """
    found: dict[tuple[int, int], str] = {}
    for kind in ("fd", "map_files"):
        try:
            entries = list((PROC / str(pid) / kind).iterdir())
        except OSError:
            continue
        for entry in entries:
            try:
                info = entry.stat()
            except OSError:
                continue  # closed or unmapped while we looked
            found.setdefault((info.st_dev, info.st_ino), f"{kind}/{entry.name}")
    return found


def inet_sockets_in_namespace_of(holder: int, namespace_of: int) -> list[InetSocket]:
    """The network sockets ``holder`` holds that live in the network namespace of ``namespace_of``.

    A process can hold a socket that was created in another namespace (the guest-traffic process holds the two
    sockets of its sandbox's namespace); such a socket appears in that namespace's tables, not in the holder's own.
    """
    inodes = socket_inodes(holder)
    found: list[InetSocket] = []
    for table in INET_TABLES:
        try:
            text = (PROC / str(namespace_of) / "net" / table).read_text()
        except OSError:
            continue
        found += parse_inet_table(table, text, inodes)
    return found


# ------------------------------------------------------------------------------------------- where bytes live
_SCAN_CHUNK = 8 << 20


def file_contains(path: Path, needle: bytes) -> bool:
    """Whether the file holds ``needle`` anywhere (read in chunks, so a disk image of any size can be searched)."""
    overlap = b""
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(_SCAN_CHUNK)
            if not chunk:
                return False
            if needle in overlap + chunk:
                return True
            overlap = chunk[-(len(needle) - 1) :] if len(needle) > 1 else b""


def parse_maps(text: str) -> list[tuple[int, int, str]]:
    """``(start, end, permissions)`` of every mapping in ``/proc/PID/maps``."""
    found: list[tuple[int, int, str]] = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 2 or "-" not in fields[0]:
            continue
        start, _, end = fields[0].partition("-")
        found.append((int(start, 16), int(end, 16), fields[1]))
    return found


def memory_contains(pid: int, needle: bytes) -> bool:
    """Whether any readable mapping of ``pid`` holds ``needle`` right now (needs the right to read its memory).

    For a VMM this covers the guest's memory, which is mapped into the VMM process. A mapping that cannot be read
    (a device region, a guard page) is skipped: it cannot hold bytes a guest wrote.
    """
    mappings = parse_maps((PROC / str(pid) / "maps").read_text())
    with (PROC / str(pid) / "mem").open("rb", buffering=0) as memory:
        for start, end, permissions in mappings:
            if not permissions.startswith("r"):
                continue
            overlap = b""
            position = start
            while position < end:
                try:
                    memory.seek(position)
                    chunk = memory.read(min(_SCAN_CHUNK, end - position))
                except (OSError, ValueError, OverflowError):
                    break
                if not chunk:
                    break
                if needle in overlap + chunk:
                    return True
                overlap = chunk[-(len(needle) - 1) :] if len(needle) > 1 else b""
                position += len(chunk)
    return False


# ------------------------------------------------------------------------------------------- confinement
NO_CAPABILITIES = "0000000000000000"


@dataclass(frozen=True)
class Confinement:
    """What the kernel says about how one process is confined (the facts a jailer is supposed to establish)."""

    uids: tuple[int, ...]  # real, effective, saved, filesystem
    gids: tuple[int, ...]
    effective_capabilities: str
    permitted_capabilities: str
    no_new_privs: bool
    #: Seccomp mode per thread name (2 is "filter").
    seccomp_by_thread: dict[str, str]
    #: How many seccomp filters each thread carries, and how many it could have inherited from the process
    #: that started it: mode 2 proves nothing under a service manager, because filters are inherited.
    seccomp_filters_by_thread: dict[str, int]
    inherited_filters: int
    #: How many PID namespaces deep the process is (1: the namespace of this machine's init).
    pid_namespace_depth: int
    #: The device and inode of its root directory, and whether that is this machine's root.
    root_identity: tuple[int, int]
    machine_root: bool
    #: Kinds of namespace it SHARES with the process that is looking.
    shared_namespaces: tuple[str, ...]

    def violations(self, *, uid_range: tuple[int, int]) -> list[str]:
        """Everything that is not as a jailed VMM must be; empty when the confinement holds."""
        low, size = uid_range
        found: list[str] = []
        if len(set(self.uids)) != 1 or not low <= self.uids[0] < low + size:
            found.append(f"uid {self.uids} is not one unprivileged id in [{low}, {low + size})")
        if len(set(self.gids)) != 1 or self.gids[0] == 0:
            found.append(f"gid {self.gids} is not one unprivileged id")
        if (self.effective_capabilities, self.permitted_capabilities) != (NO_CAPABILITIES, NO_CAPABILITIES):
            found.append(f"capabilities are held: {self.effective_capabilities} / {self.permitted_capabilities}")
        if not self.no_new_privs:
            found.append("no_new_privs is not set")
        unfiltered = sorted(name for name, mode in self.seccomp_by_thread.items() if mode != "2")
        if unfiltered or not self.seccomp_by_thread:
            found.append(f"threads without a system-call filter: {unfiltered or 'no thread could be read'}")
        inherited_only = sorted(
            name for name, count in self.seccomp_filters_by_thread.items() if count <= self.inherited_filters
        )
        if inherited_only:
            found.append(f"threads with no system-call filter of their own, only inherited ones: {inherited_only}")
        if self.pid_namespace_depth < 2:
            found.append("it is not in a PID namespace of its own")
        if self.machine_root:
            found.append("its root directory is the machine's root")
        if self.shared_namespaces:
            found.append(f"it shares these namespaces with an ordinary process: {', '.join(self.shared_namespaces)}")
        return found

    def has_root(self, directory: Path) -> bool:
        """Whether its root directory is ``directory`` (by identity, not by name)."""
        found = directory.stat()
        return self.root_identity == (found.st_dev, found.st_ino)


def seccomp_filters(pid: int) -> int:
    """How many seccomp filters ``pid``'s first thread carries (0 when the kernel does not say)."""
    return int(proc_status(pid).get("Seccomp_filters", "0") or 0)


def confinement(pid: int, *, compared_with: int, inherited_from: int | None = None) -> Confinement:
    """The confinement of ``pid`` as the kernel reports it.

    Namespaces are compared with those of ``compared_with``. ``inherited_from`` is the process that started it
    (for a VMM: the host's core): a filter counts as the process's own only beyond the ones that one carries.
    """
    status = proc_status(pid)
    threads = {tid: thread for tid, thread in thread_statuses(pid).items() if "Seccomp" in thread}
    root = (PROC / str(pid) / "root").stat()
    machine = Path("/").stat()
    return Confinement(
        uids=ids(status, "Uid"),
        gids=ids(status, "Gid"),
        effective_capabilities=status["CapEff"],
        permitted_capabilities=status["CapPrm"],
        no_new_privs=status.get("NoNewPrivs") == "1",
        seccomp_by_thread={f"{thread.get('Name', '?')}/{tid}": thread["Seccomp"] for tid, thread in threads.items()},
        seccomp_filters_by_thread={
            f"{thread.get('Name', '?')}/{tid}": int(thread.get("Seccomp_filters", "0") or 0)
            for tid, thread in threads.items()
        },
        inherited_filters=seccomp_filters(inherited_from) if inherited_from is not None else 0,
        pid_namespace_depth=len(status.get("NSpid", "").split()),
        root_identity=(root.st_dev, root.st_ino),
        machine_root=(root.st_dev, root.st_ino) == (machine.st_dev, machine.st_ino),
        shared_namespaces=tuple(
            kind for kind in ("net", "pid", "mnt") if namespace(pid, kind) == namespace(compared_with, kind)
        ),
    )
