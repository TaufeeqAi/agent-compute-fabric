"""deploy/: the three systemd units, and the sysusers.d and tmpfiles.d entries.

A unit file is configuration that nothing compiles, so a wrong line is found on a host, at the worst moment. These
tests read the units as text and pin the properties the host agent depends on:

* the start order (control groups, the lifetime enforcer, the core) and what a stop of the core may and may not end;
* that the lifetime enforcer's life is not tied to the core's;
* that no hardening option is present which would break KVM, the jailer, a sandbox's network namespace or
  control-group management, each with the reason it would;
* that every path a unit names agrees with the shipped host.yaml and with what scripts/host-setup.sh installs.

`make systemd-verify` asks systemd itself whether the units are well-formed; the two tests at the end ask
systemd-sysusers and systemd-tmpfiles to apply their files to an empty root, where those tools exist.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

Runner = Callable[..., "subprocess.CompletedProcess[str]"]

REPO = Path(__file__).resolve().parents[2]
SYSTEMD = REPO / "deploy/systemd"
CGROUP, LIFETIME, HOST = "acf-cgroup.service", "acf-lifetime.service", "acf-host.service"
EXAMPLE = (REPO / "config/host.example.yaml").read_text()
HOST_SETUP = (REPO / "scripts/host-setup.sh").read_text()

Unit = dict[str, dict[str, list[str]]]


def parse_unit(name: str) -> Unit:
    """{section: {directive: [values, in order]}}. A directive may repeat (After=, SystemCallFilter=)."""
    sections: Unit = {}
    current: dict[str, list[str]] | None = None
    for raw in (SYSTEMD / name).read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        header = re.fullmatch(r"\[(\w+)\]", line)
        if header:
            current = sections.setdefault(header.group(1), {})
            continue
        assert current is not None, f"{name}: a directive before the first section: {line}"
        assert not raw.endswith("\\"), f"{name}: continuation lines are not expected here: {raw}"
        key, sep, value = line.partition("=")
        assert sep, f"{name}: not a directive: {line}"
        current.setdefault(key, []).append(value)
    return sections


UNITS = {name: parse_unit(name) for name in (CGROUP, LIFETIME, HOST)}


def words(unit: str, section: str, directive: str) -> list[str]:
    """Every whitespace-separated word of every occurrence of a directive."""
    return [w for value in UNITS[unit][section].get(directive, []) for w in value.split()]


def one(unit: str, section: str, directive: str) -> str:
    values = UNITS[unit][section].get(directive, [])
    assert len(values) == 1, f"{unit}: expected exactly one {directive}= in [{section}], found {values}"
    return values[0]


def configured(key: str) -> str:
    """The value the shipped host.yaml gives a key (they are the built-in defaults)."""
    found = re.search(rf"^\s+{key}:\s*(\S+)", EXAMPLE, re.MULTILINE)
    assert found is not None, f"config/host.example.yaml has no {key}"
    return found.group(1)


def all_directives(unit: str) -> set[str]:
    return {directive for section in UNITS[unit].values() for directive in section}


# ----------------------------------------------------------------------------------------------- the unit set


def test_the_shipped_units_are_exactly_the_three_and_host_setup_installs_all_of_them() -> None:
    assert sorted(p.name for p in SYSTEMD.iterdir()) == sorted(UNITS)
    installed = re.search(r"for unit in ([^;]+); do", HOST_SETUP)
    assert installed is not None
    assert installed.group(1).split() == [CGROUP, LIFETIME, HOST]


@pytest.mark.parametrize("unit", sorted(UNITS))
def test_every_unit_is_enabled_for_a_normal_boot_and_documents_itself(unit: str) -> None:
    assert one(unit, "Install", "WantedBy") == "multi-user.target"
    assert one(unit, "Unit", "Description")
    assert one(unit, "Unit", "Documentation").endswith("docs/OPERATIONS.md")
    assert set(UNITS[unit]) == {"Unit", "Service", "Install"}


@pytest.mark.parametrize("unit", sorted(UNITS))
def test_every_program_a_unit_starts_is_one_that_host_setup_installs(unit: str) -> None:
    started = [
        command.lstrip("-@+!").split()[0]
        for directive, values in UNITS[unit]["Service"].items()
        if directive.startswith("Exec")
        for command in values
    ]
    assert started, unit
    for program in started:
        assert program.startswith("/opt/acf/"), f"{unit} starts {program}: a shell or a system tool is not needed"
        relative = program.removeprefix("/opt/acf/")
        assert f'"$(dpath "$PREFIX/{relative}")"' in HOST_SETUP, f"host-setup.sh does not install {program}"


@pytest.mark.parametrize("unit", [LIFETIME, HOST])
def test_the_roles_run_as_root_from_the_one_binary_with_the_one_configuration(unit: str) -> None:
    role = {LIFETIME: "lifetime", HOST: "serve"}[unit]
    assert one(unit, "Service", "ExecStart") == f"/opt/acf/bin/acf-host {role} --config /etc/acf/host.yaml"
    if unit == HOST:
        # Root by default. `User=` together with `NoNewPrivileges=yes` makes systemd start the process without
        # CAP_SETUID, and the core must switch to the edge's and the guest-traffic roles' users.
        service = UNITS[unit]["Service"]
        why = "acf-host.service must not set User= or Group=: with NoNewPrivileges=yes systemd then drops CAP_SETUID"
        assert "User" not in service, why
        assert "Group" not in service, why
    else:
        assert one(unit, "Service", "User") == "root"
        assert one(unit, "Service", "Group") == "root"
    assert one(unit, "Service", "EnvironmentFile") == "-/etc/default/acf-host", "optional overrides, never required"
    assert one(unit, "Service", "NoNewPrivileges") == "yes"
    assert one(unit, "Service", "LimitCORE") == "0"


# ------------------------------------------------------------------------------------------------- acf-cgroup


def test_the_cgroup_unit_creates_the_configured_parent_once_per_boot_before_the_other_two() -> None:
    assert one(CGROUP, "Service", "Type") == "oneshot"
    assert one(CGROUP, "Service", "RemainAfterExit") == "yes"
    assert one(CGROUP, "Service", "ExecStart") == f"/opt/acf/libexec/acf-setup-cgroup {configured('cgroup_parent')}"
    assert set(words(CGROUP, "Unit", "Before")) == {LIFETIME, HOST}


# ----------------------------------------------------------------------------------------------- acf-lifetime


def test_the_enforcer_starts_after_the_cgroup_unit_and_before_the_core() -> None:
    assert CGROUP in words(LIFETIME, "Unit", "After")
    assert words(LIFETIME, "Unit", "Before") == [HOST]


def test_nothing_ties_the_enforcers_life_to_the_cores() -> None:
    """Stopping or restarting the core must leave the enforcer running: it is what still bounds a lifetime."""
    for directive in (
        "PartOf",
        "BindsTo",
        "Requires",
        "Requisite",
        "Conflicts",
        "StopPropagatedFrom",
        "ReloadPropagatedFrom",
    ):
        assert HOST not in words(LIFETIME, "Unit", directive), f"{LIFETIME}: {directive}={HOST}"
    # ... and from the other side: Requires= or BindsTo= in the core's unit would stop the core with the enforcer,
    # PartOf= would restart it. Wants= pulls the enforcer in at start and does nothing else.
    assert words(HOST, "Unit", "Wants") == [LIFETIME]
    for directive in ("Requires", "BindsTo", "PartOf", "Requisite", "Upholds", "PropagatesStopTo"):
        assert LIFETIME not in words(HOST, "Unit", directive), f"{HOST}: {directive}={LIFETIME}"


def test_the_enforcer_is_always_restarted_and_systemd_never_gives_up_on_it() -> None:
    assert one(LIFETIME, "Service", "Restart") == "always"
    assert one(LIFETIME, "Unit", "StartLimitIntervalSec") == "0", "a start limit would end the restarts"
    restart_ms = float(one(LIFETIME, "Service", "RestartSec").removesuffix("s")) * 1000
    assert restart_ms < int(configured("heartbeat_max_age_ms")), (
        "a restart should fit inside the heartbeat's maximum age, or every restart puts the core in CONTAINMENT"
    )


def test_the_enforcer_holds_one_capability_and_a_read_only_file_system() -> None:
    assert words(LIFETIME, "Service", "CapabilityBoundingSet") == ["CAP_KILL"], (
        "signalling a VMM that runs as another uid; nothing else needs a capability"
    )
    assert one(LIFETIME, "Service", "AmbientCapabilities") == ""
    assert one(LIFETIME, "Service", "ProtectSystem") == "strict"
    assert words(LIFETIME, "Service", "ReadWritePaths") == [configured("runtime_dir")], (
        "the expiry tickets and the heartbeat live in <runtime_dir>/expiry"
    )
    assert one(LIFETIME, "Service", "PrivateNetwork") == "yes", "it reads no byte from a peer or a guest"
    assert one(LIFETIME, "Service", "RestrictNamespaces") == "yes"
    assert one(LIFETIME, "Service", "MemoryDenyWriteExecute") == "yes"


@pytest.mark.parametrize(
    ("directive", "why"),
    [
        ("ProtectControlGroups", "makes control groups read-only: no runtime's cgroup.kill could be written"),
        ("ProtectKernelTunables", "remounts /sys read-only; the kill switch is a file under /sys/fs/cgroup"),
        ("ProtectProc", "hides other users' processes: a VMM's /proc/<pid>/stat is how its identity is proven"),
        ("ProcSubset", "the same: the enforcer must see every process"),
        ("PrivateUsers", "root would no longer be root: the tickets must be root's, and CAP_KILL must be real"),
        ("PrivatePIDs", "a pid in a ticket would name nothing"),
        ("DynamicUser", "the enforcer is root by design"),
    ],
)
def test_the_enforcer_keeps_what_ending_a_runtime_needs(directive: str, why: str) -> None:
    assert directive not in all_directives(LIFETIME), f"{directive}= {why}"


def test_the_enforcers_system_call_filter_keeps_the_calls_that_end_a_runtime() -> None:
    filters = UNITS[LIFETIME]["Service"]["SystemCallFilter"]
    assert filters[0] == "@system-service", "the allow-list comes first: it sets the default to deny"
    # pidfd_open, pidfd_send_signal and kill are in @process, which @system-service includes; @process must
    # therefore never be taken away again.
    removed = [group for value in filters[1:] for group in value.removeprefix("~").split()]
    assert all(value.startswith("~") for value in filters[1:])
    assert set(removed) == {"@privileged", "@resources"}
    assert one(LIFETIME, "Service", "SystemCallErrorNumber") == "EPERM"


# -------------------------------------------------------------------------------------------------- acf-host


def test_the_core_requires_the_cgroup_unit_wants_the_enforcer_and_starts_after_both() -> None:
    assert words(HOST, "Unit", "Requires") == [CGROUP]
    assert {CGROUP, LIFETIME} <= set(words(HOST, "Unit", "After"))


def test_readiness_is_a_listener_on_the_configured_socket_and_the_timeouts_fit_the_recovery_deadline() -> None:
    helper, socket_path, seconds = one(HOST, "Service", "ExecStartPost").split()
    assert helper == "/opt/acf/libexec/acf-wait-ready"
    assert socket_path == configured("socket_path"), "the helper looks for exactly the path the core binds"
    recovery_s = int(configured("startup_deadline_ms")) / 1000
    assert int(seconds) > 2 * recovery_s, "the core listens only after recovery, which may take its whole deadline"
    assert int(one(HOST, "Service", "TimeoutStartSec")) > int(seconds), (
        "systemd must not give up before the helper does"
    )
    assert one(HOST, "Service", "Type") == "exec"


def test_the_preflight_report_is_printed_but_never_stops_the_core_from_starting() -> None:
    pre = one(HOST, "Service", "ExecStartPre")
    assert pre == "-/opt/acf/bin/acf-host doctor --config /etc/acf/host.yaml", (
        "the dash: a failed check must not stop the unit; the core itself starts in CONTAINMENT and still destroys"
    )


def test_a_stop_signals_only_the_core_and_waits_longer_than_the_drain() -> None:
    assert one(HOST, "Service", "KillMode") == "mixed", (
        "SIGTERM to the core alone, so that it drains while its edge still answers; SIGKILL afterwards to what is "
        "left in the unit's control group. VMs, guest-traffic processes and the enforcer are not in that group."
    )
    assert one(HOST, "Service", "KillSignal") == "SIGTERM"
    drain_s = int(configured("drain_timeout_ms")) / 1000
    assert int(one(HOST, "Service", "TimeoutStopSec")) > drain_s
    assert one(HOST, "Service", "Restart") == "on-failure"


MOUNT_NAMESPACE = [
    "ProtectSystem", "ProtectHome", "PrivateTmp", "PrivateDevices", "PrivateMounts", "ProtectKernelTunables",
    "ProtectKernelModules", "ProtectKernelLogs", "ProtectControlGroups", "ProtectProc", "ProcSubset",
    "ProtectHostname", "ReadWritePaths", "ReadOnlyPaths", "InaccessiblePaths", "ExecPaths", "NoExecPaths",
    "BindPaths", "BindReadOnlyPaths", "TemporaryFileSystem", "MountFlags", "MountAPIVFS", "RootDirectory",
    "RootImage", "PrivateIPC", "PrivateUsers", "PrivatePIDs", "DynamicUser", "StateDirectory", "RuntimeDirectory",
]  # fmt: skip


@pytest.mark.parametrize("directive", MOUNT_NAMESPACE)
def test_the_core_has_no_mount_namespace_of_its_own(directive: str) -> None:
    """A sandbox's network namespace is kept alive by a bind mount at <runtime_dir>/netns/acf-<jail-id>.

    Made inside a unit's private mount namespace, that mount does not reach the host and is gone for the next
    activation of the core. The next core then finds a plain file where the namespace should be: it cannot prove
    that an adopted VM is inside its namespace, and stops it. Every one of these options gives the unit such a
    namespace (StateDirectory= and RuntimeDirectory= do not, but they would hand the directories' modes to systemd).
    """
    assert directive not in all_directives(HOST)


@pytest.mark.parametrize(
    ("directive", "why"),
    [
        ("PrivateDevices", "no /dev/kvm"),
        ("DevicePolicy", "a device allow-list has to name /dev/kvm and /dev/net/tun and still be right tomorrow"),
        ("DeviceAllow", "any entry turns the unit's device access into an allow-list"),
        ("ProtectClock", "implies DeviceAllow=char-rtc, that is an allow-list without /dev/kvm"),
        ("PrivateNetwork", "the core must reach every sandbox's namespace and bind the network endpoint"),
        ("IPAddressDeny", "the guest-traffic processes it starts relay to the outside"),
        ("MemoryDenyWriteExecute", "inherited by every VMM; unproven without a KVM host"),
        ("Delegate", "the sandboxes' control groups are deliberately outside this unit"),
        ("Slice", "the same"),
    ],
)
def test_the_core_keeps_kvm_the_network_and_its_place_in_the_control_group_tree(directive: str, why: str) -> None:
    assert directive not in all_directives(HOST), f"{directive}= {why}"


def test_the_namespaces_left_to_the_core_are_the_three_the_host_uses_and_never_user() -> None:
    allowed = set(one(HOST, "Service", "RestrictNamespaces").split())
    assert allowed == {"net", "mnt", "pid"}, (
        "net: one namespace per sandbox (unshare --net, nsenter --net, the jailer's --netns); "
        "mnt and pid: the jailer's chroot and --new-pid-ns"
    )


def test_the_address_families_cover_both_endpoints_the_relay_and_the_plumbing() -> None:
    families = set(one(HOST, "Service", "RestrictAddressFamilies").split())
    assert not any(f.startswith("~") for f in families), "an allow-list"
    assert families == {"AF_UNIX", "AF_INET", "AF_INET6", "AF_NETLINK"}


def test_the_capability_set_is_a_deny_list_that_takes_nothing_the_host_or_the_jailer_uses() -> None:
    value = one(HOST, "Service", "CapabilityBoundingSet")
    assert value.startswith("~"), "an allow-list that misses one capability stops every sandbox from starting"
    denied = set(value.removeprefix("~").split())
    needed = {
        "CAP_SYS_ADMIN",  # namespaces, mounts, pivot_root, setns
        "CAP_NET_ADMIN",  # ip, nft inside a sandbox's namespace
        "CAP_NET_BIND_SERVICE",  # the resolver socket on port 53 inside the namespace
        "CAP_SYS_CHROOT", "CAP_MKNOD", "CAP_CHOWN", "CAP_FOWNER",  # the jailer's chroot and device nodes
        "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH",  # files and sockets that belong to a sandbox's uid
        "CAP_SETUID", "CAP_SETGID",  # the edge, the guest-traffic processes, the jailer's drop to the VM uid
        "CAP_KILL", "CAP_SYS_PTRACE",  # ending and inspecting processes of other uids (/proc/<pid>/root, ns/net)
        "CAP_SYS_RESOURCE",  # the jailer's resource limits
    }  # fmt: skip
    assert not denied & needed, sorted(denied & needed)
    assert {"CAP_SYS_MODULE", "CAP_SYS_BOOT", "CAP_SYS_TIME", "CAP_SYS_RAWIO"} <= denied


def test_the_system_call_filter_is_a_deny_list_of_groups_no_part_of_the_host_calls() -> None:
    filters = UNITS[HOST]["Service"]["SystemCallFilter"]
    assert all(value.startswith("~") for value in filters), "an allow-list here would have to know the jailer"
    denied = {group for value in filters for group in value.removeprefix("~").split()}
    assert denied == {"@clock", "@module", "@reboot", "@swap", "@raw-io"}
    # The groups the jailer, `unshare`, `nsenter`, `ip` and `nft` live in must never appear here.
    assert not denied & {"@mount", "@privileged", "@process", "@setuid", "@chown", "@network-io", "@file-system"}
    assert one(HOST, "Service", "SystemCallErrorNumber") == "EPERM", "a refused call is an error, not a dead VMM"
    assert one(HOST, "Service", "SystemCallArchitectures") == "native"


# --------------------------------------------------------------------------------------------------- sysusers.d

SYSUSERS = REPO / "deploy/sysusers.d/acf.conf"


def sysusers_lines() -> list[list[str]]:
    return [
        re.findall(r'"[^"]*"|\S+', line)
        for line in SYSUSERS.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]


def test_sysusers_creates_the_edge_user_and_the_socket_group_with_ids_chosen_by_the_system() -> None:
    lines = sysusers_lines()
    assert [line[:3] for line in lines] == [["u", "acf-edge", "-"], ["g", "acf", "-"]]
    user = lines[0]
    assert user[4:] == ["-", "-"], "no home directory and no login shell: the defaults are / and nologin"
    # The names are the ones host-setup.sh looks up afterwards.
    assert "readonly EDGE_USER=acf-edge SOCKET_GROUP=acf" in HOST_SETUP


def test_a_system_account_cannot_fall_inside_a_per_sandbox_uid_range() -> None:
    """The two ranges must not contain any account; `acf-host doctor` fails the host if one does."""
    assert int(configured("uid_range_start")) >= 100000
    assert int(configured("traffic_uid_start")) >= 100000
    assert "-" in [line[2] for line in sysusers_lines()], "ids are allocated from the system range"


@pytest.mark.skipif(shutil.which("systemd-sysusers") is None, reason="systemd-sysusers is not installed")
def test_systemd_sysusers_applies_the_file_to_an_empty_root(run: Runner, tmp_path: Path) -> None:
    root = tmp_path / "root"
    (root / "etc/sysusers.d").mkdir(parents=True)
    shutil.copy(SYSUSERS, root / "etc/sysusers.d/acf.conf")
    result = run(["systemd-sysusers", f"--root={root}", "acf.conf"])
    assert result.returncode == 0, result.stderr
    passwd = dict(line.split(":", 1) for line in (root / "etc/passwd").read_text().splitlines())
    groups = {line.split(":")[0]: int(line.split(":")[2]) for line in (root / "etc/group").read_text().splitlines()}
    _, uid, gid, _, home, shell = passwd["acf-edge"].split(":")
    assert 0 < int(uid) < 1000, "a system account"
    assert int(gid) == groups["acf-edge"], "its own group, not a shared one"
    assert home == "/"
    assert shell.endswith("/nologin")
    assert 0 < groups["acf"] < 1000
    assert groups["acf"] != groups["acf-edge"]


# --------------------------------------------------------------------------------------------------- tmpfiles.d

TMPFILES = REPO / "deploy/tmpfiles.d/acf.conf"


def tmpfiles_entries() -> dict[str, tuple[str, ...]]:
    entries: dict[str, tuple[str, ...]] = {}
    for line in TMPFILES.read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            kind, path, *rest = line.split()
            assert path not in entries, f"{path} is listed twice"
            entries[path] = (kind, *rest)
    return entries


def test_tmpfiles_creates_the_runtime_and_state_directories_with_the_modes_the_host_expects() -> None:
    runtime, state = configured("runtime_dir"), configured("state_root")
    assert tmpfiles_entries() == {
        runtime: ("d", "0755", "root", "root", "-"),  # traversable: the socket inside has its own mode and group
        f"{runtime}/netns": ("d", "0700", "root", "root", "-"),
        f"{runtime}/expiry": ("d", "0700", "root", "root", "-"),
        state: ("d", "0700", "root", "root", "-"),
    }
    assert Path(configured("socket_path")).parent == Path(runtime)


def test_no_entry_has_an_age_so_nothing_is_ever_cleaned_up() -> None:
    """An expiry ticket removed by systemd-tmpfiles-clean would be a sandbox whose lifetime nobody enforces."""
    for path, (kind, *_, age) in tmpfiles_entries().items():
        assert kind == "d", f"{path}: only `d` creates a directory without ever emptying it"
        assert age == "-", path


def test_the_runtime_subdirectories_are_the_ones_the_host_agent_derives() -> None:
    source = REPO / "execution/host-agent/src"
    assert 'self.paths.runtime_dir.join("expiry")' in (source / "config.rs").read_text()
    assert 'self.cfg.paths.runtime_dir.join("netns")' in (source / "backend/firecracker/backend.rs").read_text()


@pytest.mark.needs_root
@pytest.mark.skipif(shutil.which("systemd-tmpfiles") is None, reason="systemd-tmpfiles is not installed")
def test_systemd_tmpfiles_applies_the_file_to_an_empty_root(run: Runner, tmp_path: Path) -> None:
    root = tmp_path / "root"
    (root / "etc/tmpfiles.d").mkdir(parents=True)
    (root / "run").mkdir()
    (root / "var/lib").mkdir(parents=True)
    shutil.copy(TMPFILES, root / "etc/tmpfiles.d/acf.conf")
    result = run(["systemd-tmpfiles", f"--root={root}", "--create", "acf.conf"])
    assert result.returncode == 0, result.stderr
    for path, (_, mode, *_) in tmpfiles_entries().items():
        made = root / path.lstrip("/")
        assert made.is_dir(), path
        assert f"{made.stat().st_mode & 0o7777:04o}" == mode, path
        assert (made.stat().st_uid, made.stat().st_gid) == (0, 0), path
