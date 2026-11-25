"""images/overlay/usr/local/sbin/acf-init — the guest's PID 1 — tested without a guest.

The init is a shell script that is also a library: with ``ACF_INIT_SOURCE_ONLY=1`` it defines its functions and
returns without touching the machine. These tests source it and call the functions directly, under both shells
it may plausibly run as (dash is ``/bin/sh`` in the Debian-based images; bash covers everything else), aimed at
scratch directories and stub programs.

What is deliberately NOT done here:

* ``main`` is never run and nothing is mounted: that reconfigures the machine, and it is exercised by
  ``tests/integration`` on a real microVM. (The init itself refuses to run unless it is PID 1; one test pins that.)
* ``mount_core`` is not called: it touches /dev, /proc and /sys, which are real on the machine running the tests.

The one test that needs a real kernel feature — a supervisor that reaps orphans — runs the real ``supervise`` as
PID 1 of a throw-away PID namespace, next to a positive control (a PID 1 that does not reap) so that "no zombies"
means something.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
INIT = REPO / "images/overlay/usr/local/sbin/acf-init"
GUEST_AGENT_MAIN = REPO / "execution/guest-agent/src/main.rs"

SYSTEM_PATH = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin")

SHELLS = [
    pytest.param(name, id=name, marks=pytest.mark.skipif(shutil.which(name) is None, reason=f"{name} is not installed"))
    for name in ("dash", "bash")
]

# Prepended to every test body. The init resets PATH and defines klog() to write to the kernel log, so after
# sourcing it we (a) point klog at stderr — the tests read what the init says, and never write to a real kernel log —
# and (b) apply the PATH the test asked for (stub programs first).
PRELUDE = r"""
. "$ACF_INIT"
klog() { printf 'acf-init: %s\n' "$*" >&2; }
if [ -n "${ACF_TEST_PATH+set}" ]; then PATH=$ACF_TEST_PATH; fi
"""

# `main` in COMMAND position (start of a line, or after ; & | ( {) — the one call no test may ever make.
# (The word as an argument, e.g. in a list of function names to look up, is fine.)
COMMAND_MAIN = r"(?:^|[;&|({\n])\s*main(?:\s|;|$)"


@dataclass
class Lab:
    """A scratch area for one test: a directory of stub programs, a log they write to, and room for fakes."""

    root: Path
    bin: Path
    empty: Path
    log: Path

    def stub(self, name: str, body: str = "") -> Path:
        """An executable `name` that records "name ARGS" in the call log and then runs `body` (builtins only)."""
        path = self.bin / name
        path.write_text(f'#!/bin/sh\necho "{name} $*" >>"$ACF_STUB_LOG"\n{body}\n')
        path.chmod(0o755)
        return path

    def calls(self) -> list[str]:
        return self.log.read_text().splitlines() if self.log.exists() else []


@pytest.fixture
def lab(tmp_path: Path) -> Lab:
    root = tmp_path / "lab"
    root.mkdir()
    (root / "bin").mkdir()
    (root / "empty").mkdir()
    return Lab(root=root, bin=root / "bin", empty=root / "empty", log=root / "calls.log")


@pytest.fixture(scope="session")
def init_lib(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The shipped init with its last line — the bare call to `main` — replaced by `echo reached-main`.

    Every test that sources or executes the init uses THIS copy, never the shipped file. Everything above the last
    line, the PID-1 guard and the SOURCE_ONLY switch included, is byte-for-byte what ships; but nothing a test does
    can run the real boot sequence (mounts, sysctls, hostname, /etc/hosts, resize2fs) on the machine running it —
    not even if a future edit breaks those two guards. (Only parsing and reading the shipped file is done directly.)
    """
    text = INIT.read_text()
    assert text.endswith("\nmain\n"), (
        "acf-init must end with a bare call to main (tests/scripts/test_acf_init.py relies on it)"
    )
    path = tmp_path_factory.mktemp("init-lib") / "acf-init"
    path.write_text(text.removesuffix("main\n") + "echo reached-main\n")
    path.chmod(0o755)
    return path


ShellRunner = Callable[..., "subprocess.CompletedProcess[str]"]


@pytest.fixture
def sh(lab: Lab, init_lib: Path) -> ShellRunner:
    """sh(shell, body, *args, path=None, isolated=False, env=None): run `body` after sourcing the init as a library.

    ``path`` lists directories searched BEFORE the system PATH (stub programs); with ``isolated=True`` they are the
    ONLY directories searched, which is how "neither ip nor ifconfig exists" is tested.
    """

    def _sh(
        shell: str,
        body: str,
        *args: str,
        path: Sequence[Path] | None = None,
        isolated: bool = False,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        binary = shutil.which(shell)
        assert binary, f"{shell} is not installed"
        merged = {
            "PATH": os.pathsep.join(SYSTEM_PATH),
            "LC_ALL": "C",
            "HOME": str(lab.root),
            "ACF_INIT": str(init_lib),
            "ACF_INIT_SOURCE_ONLY": "1",
            "ACF_STUB_LOG": str(lab.log),
            **(env or {}),
        }
        if path is not None:
            dirs = [str(p) for p in path] + ([] if isolated else list(SYSTEM_PATH))
            merged["ACF_TEST_PATH"] = os.pathsep.join(dirs)
        assert not re.search(COMMAND_MAIN, body), "tests must never run main()"
        return subprocess.run(
            [binary, "-c", PRELUDE + body, "acf-test", *args],
            capture_output=True,
            text=True,
            env=merged,
            cwd=lab.root,
            timeout=60,
            check=False,
        )

    return _sh


def warnings_of(result: subprocess.CompletedProcess[str]) -> list[str]:
    return [line for line in result.stderr.splitlines() if line]


# ---------------------------------------------------------------------------------------------- the file


@pytest.mark.parametrize("shell", ["dash", "bash"])
def test_the_init_parses_under_every_shell_it_may_run_as(
    shell: str, run: Callable[..., subprocess.CompletedProcess[str]]
) -> None:
    if shutil.which(shell) is None:
        pytest.skip(f"{shell} is not installed")
    result = run([shell, "-n", INIT])
    assert result.returncode == 0, result.stderr


def test_the_init_is_executable_and_starts_with_a_posix_sh_shebang() -> None:
    assert os.access(INIT, os.X_OK)
    assert INIT.read_text().splitlines()[0] == "#!/bin/sh"


def test_the_init_uses_no_bashisms_in_its_code(repo: Path) -> None:
    """`#!/bin/sh` is dash on the guests; `[[`, arrays and `local` would work on a developer's bash and break there."""
    code = [line for line in INIT.read_text().splitlines() if not line.lstrip().startswith("#")]
    text = "\n".join(code)
    for needle in ("[[", "]]", "local ", "declare ", "function ", "source ", "<(", "${!", "+=(", "=("):
        assert needle not in text, f"bash-only construct {needle!r} in acf-init"


def test_executing_the_init_as_a_program_refuses_unless_it_is_pid_1(
    init_lib: Path, run: Callable[..., subprocess.CompletedProcess[str]]
) -> None:
    """Run by hand (as root, on a laptop) the real `main` would rename the machine and rewrite /etc/hosts."""
    result = run(["/bin/sh", init_lib])
    assert result.returncode == 2
    assert "refusing to run" in result.stderr
    assert result.stdout == "", "the guard must stop the init BEFORE the call to main"


@pytest.mark.parametrize("shell", SHELLS)
def test_source_only_mode_defines_the_functions_and_does_nothing_else(shell: str, sh: ShellRunner) -> None:
    names = "root_majmin block_name_from_link clock_floor_target render_hosts mount_fs mount_core set_limits harden"
    names += " set_identity grow_root prepare_state loopback_up apply_clock_floor supervise main klog warn fatal"
    result = sh(shell, f'for f in {names}; do command -v "$f" >/dev/null || echo "missing: $f"; done')
    assert result.returncode == 0, result.stderr
    assert result.stdout == "", result.stdout
    assert result.stderr == ""


def test_executing_the_init_in_source_only_mode_exits_quietly(
    init_lib: Path, run: Callable[..., subprocess.CompletedProcess[str]]
) -> None:
    result = run(["/bin/sh", init_lib], env={"ACF_INIT_SOURCE_ONLY": "1"})
    assert (result.returncode, result.stdout, result.stderr) == (0, "", "")


def test_the_flags_the_init_passes_to_the_agent_are_flags_the_agent_parses() -> None:
    init = INIT.read_text()
    agent = GUEST_AGENT_MAIN.read_text()
    passed = [tok for tok in init.split() if tok.startswith("--") and tok.isascii()]
    agent_flags = {tok.strip('",') for tok in agent.split() if tok.startswith('"--')}
    wanted = {tok for tok in passed if tok in {"--allow-shutdown", "--listen", "--canary", "--boot-id"}}
    assert "--allow-shutdown" in wanted, "the host's Shutdown request does nothing unless the agent was started with it"
    assert wanted <= agent_flags, f"{sorted(wanted - agent_flags)} are not parsed by acf-guest-agent"


# ------------------------------------------------------------------------------------- pure functions

MOUNTINFO_TYPICAL = (
    "21 1 254:0 / / rw,relatime shared:1 - ext4 /dev/root rw\n"
    "22 21 0:5 / /dev rw,nosuid - devtmpfs devtmpfs rw,mode=755\n"
    "23 21 0:21 / /sys rw,nosuid,nodev,noexec - sysfs sysfs rw\n"
)


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize(
    ("mountinfo", "expected"),
    [
        pytest.param(MOUNTINFO_TYPICAL, "254:0", id="typical"),
        pytest.param(
            "1 0 0:2 / / rw - rootfs rootfs rw\n" + MOUNTINFO_TYPICAL, "254:0", id="the-last-entry-for-slash-wins"
        ),
        pytest.param("5 4 8:1 / / rw - ext4 /dev/sda1 rw\n", "8:1", id="no-optional-fields"),
        pytest.param(
            "5 4 259:2 / / rw,relatime shared:1 master:2 propagate_from:3 - ext4 /dev/nvme0n1p2 rw\n",
            "259:2",
            id="many-optional-fields",
        ),
    ],
)
def test_root_majmin_finds_the_device_holding_slash(
    shell: str, mountinfo: str, expected: str, sh: ShellRunner, lab: Lab
) -> None:
    (lab.root / "mountinfo").write_text(mountinfo)
    result = sh(shell, 'root_majmin "$1"', str(lab.root / "mountinfo"))
    assert (result.returncode, result.stdout) == (0, expected + "\n"), result.stderr


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize(
    "mountinfo",
    [
        pytest.param("", id="empty"),
        pytest.param(
            "22 21 0:5 / /dev rw - devtmpfs devtmpfs rw\n23 21 0:21 / /sys rw - sysfs sysfs rw\n", id="no-root-entry"
        ),
        pytest.param("22 21 0:5 / /not/ rw - tmpfs tmpfs rw\n", id="a-path-ending-in-a-slash-is-not-the-root"),
        pytest.param("22 21 0:5 /sub /subdir rw - tmpfs tmpfs rw\n", id="a-bind-mounted-subdirectory-is-not-the-root"),
    ],
)
def test_root_majmin_says_nothing_when_there_is_no_root_entry(
    shell: str, mountinfo: str, sh: ShellRunner, lab: Lab
) -> None:
    (lab.root / "mountinfo").write_text(mountinfo)
    result = sh(shell, 'root_majmin "$1"', str(lab.root / "mountinfo"))
    assert result.returncode == 1
    assert result.stdout == ""


@pytest.mark.parametrize("shell", SHELLS)
def test_root_majmin_on_a_missing_file_is_no_answer_not_a_crash(shell: str, sh: ShellRunner, lab: Lab) -> None:
    result = sh(shell, 'root_majmin "$1"; echo "rc=$?"', str(lab.root / "nope"))
    assert result.stdout == "rc=1\n"


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize(
    ("target", "name"),
    [
        ("../../devices/platform/virtio-mmio.0/virtio0/block/vda", "vda"),
        ("../../devices/pci0000:00/0000:00:04.0/virtio1/block/vda", "vda"),
        ("../../devices/pci0000:00/0000:00:05.0/nvme/nvme0/nvme0n1", "nvme0n1"),
        ("../../devices/platform/soc/mmc_host/mmc0/mmc0:0001/block/mmcblk0p1", "mmcblk0p1"),
        ("vda", "vda"),
        ("loop0", "loop0"),
    ],
)
def test_block_name_from_link_takes_the_last_component(shell: str, target: str, name: str, sh: ShellRunner) -> None:
    result = sh(shell, 'block_name_from_link "$1"', target)
    assert (result.returncode, result.stdout) == (0, name + "\n"), result.stderr


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize(
    "target",
    [
        pytest.param("", id="empty"),
        pytest.param("../../devices/block/", id="trailing-slash"),
        pytest.param(".", id="dot"),
        pytest.param("..", id="dot-dot"),
        pytest.param("../..", id="dot-dot-link-target"),
        pytest.param("../../devices/block/v da", id="space"),
        pytest.param("../../devices/block/$(reboot)", id="command-substitution"),
        pytest.param("../../devices/block/vda;reboot", id="semicolon"),
        pytest.param("../../devices/block/v*", id="glob"),
        pytest.param("../../devices/block/v\na", id="newline"),
    ],
)
def test_block_name_from_link_refuses_anything_that_could_not_be_a_device_name(
    shell: str, target: str, sh: ShellRunner
) -> None:
    result = sh(shell, 'block_name_from_link "$1"', target)
    assert result.returncode == 1
    assert result.stdout == ""


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize(
    ("now", "content", "expected"),
    [
        pytest.param("100", "1700000000\n", "1700000000\n", id="clock-before-the-image-was-built"),
        pytest.param("0", "1700000000\n", "1700000000\n", id="clock-at-the-epoch"),
        pytest.param("1700000000", "1700000000\n", "", id="exactly-the-build-time"),
        pytest.param("1800000000", "1700000000\n", "", id="clock-already-later"),
        pytest.param("100", "1700000000", "1700000000\n", id="no-trailing-newline"),
        pytest.param("100", "  1700000000  \n", "1700000000\n", id="surrounding-blanks"),
        pytest.param("100", "1700000000\nignored second line\n", "1700000000\n", id="only-the-first-line-counts"),
        pytest.param("100", "", "", id="empty-file"),
        pytest.param("100", "\n", "", id="blank-line"),
        pytest.param("100", "not-a-number\n", "", id="garbage"),
        pytest.param("100", "-5\n", "", id="negative"),
        pytest.param("100", "17e8\n", "", id="exponent"),
        pytest.param("100", "1700000000 1\n", "", id="two-numbers"),
    ],
)
def test_clock_floor_target_only_ever_moves_the_clock_forward_to_the_images_build_time(
    shell: str, now: str, content: str, expected: str, sh: ShellRunner, lab: Lab
) -> None:
    epoch = lab.root / "clock-epoch"
    epoch.write_text(content)
    result = sh(shell, 'clock_floor_target "$1" "$2"', now, str(epoch))
    assert result.returncode == 0, result.stderr
    assert result.stdout == expected


@pytest.mark.parametrize("shell", SHELLS)
def test_clock_floor_target_without_an_epoch_file_does_nothing(shell: str, sh: ShellRunner, lab: Lab) -> None:
    result = sh(shell, 'clock_floor_target 100 "$1"', str(lab.root / "absent"))
    assert (result.returncode, result.stdout) == (0, "")


@pytest.mark.parametrize("shell", SHELLS)
def test_clock_floor_target_survives_a_number_too_big_for_the_shell(shell: str, sh: ShellRunner, lab: Lab) -> None:
    (lab.root / "epoch").write_text("99999999999999999999999999\n")
    result = sh(shell, 'clock_floor_target 100 "$1"', str(lab.root / "epoch"))
    assert result.returncode == 0  # whatever it prints, the init must go on booting


@pytest.mark.parametrize("shell", SHELLS)
def test_render_hosts_makes_localhost_and_the_machine_name_resolve(shell: str, sh: ShellRunner) -> None:
    result = sh(shell, "render_hosts acf-sandbox")
    assert result.stdout == "127.0.0.1\tlocalhost\n127.0.1.1\tacf-sandbox\n::1\tlocalhost ip6-localhost ip6-loopback\n"


@pytest.mark.parametrize("shell", SHELLS)
def test_render_resolv_takes_over_the_resolver_the_host_chose(shell: str, sh: ShellRunner, lab: Lab) -> None:
    """In network mode `allowlist` the kernel records the resolver from the `ip=` argument in /proc/net/pnp."""
    pnp = lab.root / "pnp"
    pnp.write_text("#PROTO: MANUAL\nnameserver 10.201.0.1\n")
    result = sh(shell, 'render_resolv "$1"', str(pnp))
    assert (result.returncode, result.stdout, result.stderr) == (0, "nameserver 10.201.0.1\n", "")


@pytest.mark.parametrize("shell", SHELLS)
def test_render_resolv_takes_only_well_formed_ipv4_nameservers(shell: str, sh: ShellRunner, lab: Lab) -> None:
    """Nothing but digits and dots reaches /etc/resolv.conf, whatever the file says; the last line needs no newline."""
    pnp = lab.root / "pnp"
    pnp.write_text(
        "#MANUAL\n"
        "nameserver 0.0.0.0\n"
        "nameserver evil;reboot\n"
        "nameserver $(reboot)\n"
        "nameserver fe80::1\n"
        "nameserver\n"
        "domain example.test\n"
        "bootserver 10.0.0.9\n"
        "nameserver 10.201.0.1 trailing words\n"
        "nameserver 192.0.2.7"
    )
    result = sh(shell, 'render_resolv "$1"', str(pnp))
    assert (result.returncode, result.stderr) == (0, "")
    assert result.stdout == "nameserver 10.201.0.1\nnameserver 192.0.2.7\n"


@pytest.mark.parametrize("shell", SHELLS)
def test_render_resolv_says_nothing_for_a_sandbox_without_a_network(shell: str, sh: ShellRunner, lab: Lab) -> None:
    empty = lab.root / "pnp-empty"
    empty.write_text("")
    for pnp in (empty, lab.root / "no-such-file"):
        result = sh(shell, 'render_resolv "$1"', str(pnp))
        assert (result.returncode, result.stdout, result.stderr) == (0, "", ""), pnp


@pytest.mark.parametrize("shell", SHELLS)
def test_set_resolver_writes_resolv_conf_only_when_the_host_gave_the_sandbox_a_network(
    shell: str, sh: ShellRunner, lab: Lab
) -> None:
    pnp = lab.root / "pnp"
    pnp.write_text("#PROTO: MANUAL\nnameserver 10.201.0.1\n")
    with_network = lab.root / "etc-allowlist"
    with_network.mkdir()
    result = sh(shell, 'set_resolver "$1" "$2"', str(pnp), str(with_network))
    assert (result.returncode, result.stderr) == (0, "")
    assert (with_network / "resolv.conf").read_text() == "nameserver 10.201.0.1\n"

    # Mode `none`: no resolver exists, so no file is written. A stale one would only produce timeouts.
    no_network = lab.root / "etc-none"
    no_network.mkdir()
    (lab.root / "pnp-empty").write_text("")
    result = sh(shell, 'set_resolver "$1" "$2"', str(lab.root / "pnp-empty"), str(no_network))
    assert (result.returncode, result.stderr) == (0, "")
    assert list(no_network.iterdir()) == []

    # ... and one the image carried is removed: a container build leaves the build machine's resolvers in it.
    (no_network / "resolv.conf").write_text("nameserver 1.1.1.1\nnameserver 1.0.0.1\n")
    result = sh(shell, 'set_resolver "$1" "$2"', str(lab.root / "pnp-empty"), str(no_network))
    assert (result.returncode, result.stderr) == (0, "")
    assert list(no_network.iterdir()) == [], "a sandbox without a network has no resolver"


@pytest.mark.parametrize("shell", SHELLS)
def test_set_resolver_replaces_a_resolv_conf_that_is_a_dangling_link(shell: str, sh: ShellRunner, lab: Lab) -> None:
    """A base image may ship /etc/resolv.conf as a link into a directory that does not exist in the guest."""
    pnp = lab.root / "pnp"
    pnp.write_text("nameserver 10.201.0.1\n")
    etc = lab.root / "etc"
    etc.mkdir()
    (etc / "resolv.conf").symlink_to(lab.root / "run" / "resolver" / "stub-resolv.conf")
    result = sh(shell, 'set_resolver "$1" "$2"', str(pnp), str(etc))
    assert (result.returncode, result.stderr) == (0, "")
    assert not (etc / "resolv.conf").is_symlink()
    assert (etc / "resolv.conf").read_text() == "nameserver 10.201.0.1\n"
    assert not (lab.root / "run").exists(), "nothing is written through the link"


@pytest.mark.parametrize("shell", SHELLS)
def test_set_resolver_reports_failure_quietly_so_that_init_can_warn(shell: str, sh: ShellRunner, lab: Lab) -> None:
    """`main` turns the failure into its own warning; the shell's "cannot create" must not reach the log."""
    pnp = lab.root / "pnp"
    pnp.write_text("nameserver 10.201.0.1\n")
    result = sh(shell, 'set_resolver "$1" "$2" || echo could-not-write', str(pnp), str(lab.root / "no-etc"))
    assert (result.returncode, result.stdout, result.stderr) == (0, "could-not-write\n", "")


def test_main_sets_the_resolver_after_loopback_and_only_warns_when_it_cannot() -> None:
    """The resolver is comfort, not contract: an address entry of the allowlist works without it."""
    body = INIT.read_text().split("\nmain() {\n", 1)[1].split("\n}\n", 1)[0]
    steps = [line.strip().split(" ", 1)[0] for line in body.splitlines() if line.strip()]
    assert steps.index("loopback_up") < steps.index("set_resolver") < steps.index("supervise")
    assert 'set_resolver || warn "cannot write /etc/resolv.conf' in body


@pytest.mark.parametrize("shell", SHELLS)
def test_fatal_logs_and_exits_with_status_1_and_warn_only_logs(shell: str, sh: ShellRunner) -> None:
    result = sh(shell, 'warn "just a heads-up"; echo still-running; fatal "cannot go on"; echo not-reached')
    assert result.returncode == 1
    assert result.stdout == "still-running\n"
    assert warnings_of(result) == ["acf-init: warning: just a heads-up", "acf-init: FATAL: cannot go on"]


# ------------------------------------------------------------------------------------- the steps


@pytest.mark.parametrize("shell", SHELLS)
def test_mount_fs_creates_the_target_and_names_type_options_and_source(shell: str, sh: ShellRunner, lab: Lab) -> None:
    lab.stub("mount")
    target = lab.root / "deeper" / "proc"
    result = sh(shell, 'mount_fs proc "$1" nosuid,nodev,noexec', str(target), path=[lab.bin])
    assert result.returncode == 0, result.stderr
    assert target.is_dir()
    assert lab.calls() == [f"mount -t proc -o nosuid,nodev,noexec proc {target}"]


@pytest.mark.parametrize("shell", SHELLS)
def test_mount_fs_without_options_passes_none(shell: str, sh: ShellRunner, lab: Lab) -> None:
    lab.stub("mount")
    target = lab.root / "sys"
    target.mkdir()
    result = sh(shell, 'mount_fs sysfs "$1"', str(target), path=[lab.bin])
    assert result.returncode == 0, result.stderr
    assert lab.calls() == [f"mount -t sysfs sysfs {target}"]


@pytest.mark.parametrize("shell", SHELLS)
def test_mount_fs_returns_the_status_of_mount_so_callers_can_decide_what_is_fatal(
    shell: str, sh: ShellRunner, lab: Lab
) -> None:
    lab.stub("mount", "exit 32")
    target = lab.root / "t"
    target.mkdir()
    result = sh(shell, 'mount_fs tmpfs "$1" size=1m; echo "rc=$?"', str(target), path=[lab.bin])
    assert result.stdout == "rc=32\n"


@pytest.mark.parametrize("shell", SHELLS)
def test_mount_fs_does_not_try_to_mount_where_it_cannot_make_the_directory(
    shell: str, sh: ShellRunner, lab: Lab
) -> None:
    lab.stub("mount")
    (lab.root / "a-file").write_text("")
    result = sh(shell, 'mount_fs tmpfs "$1/child"; echo "rc=$?"', str(lab.root / "a-file"), path=[lab.bin])
    assert result.stdout == "rc=1\n"
    assert lab.calls() == []


@pytest.mark.parametrize("shell", SHELLS)
def test_set_limits_turns_core_dumps_off_and_never_fails_the_boot(shell: str, sh: ShellRunner) -> None:
    result = sh(shell, 'set_limits; echo "rc=$? core=$(ulimit -c)"')
    assert result.stdout == "rc=0 core=0\n", result.stderr


@pytest.mark.parametrize("shell", SHELLS)
def test_harden_sets_the_two_kernel_sysctls(shell: str, sh: ShellRunner, lab: Lab) -> None:
    sysctl = lab.root / "sys"
    (sysctl / "kernel").mkdir(parents=True)
    (sysctl / "kernel/dmesg_restrict").write_text("0\n")
    (sysctl / "kernel/kptr_restrict").write_text("0\n")
    result = sh(shell, 'harden "$1"', str(sysctl))
    assert (result.returncode, result.stderr) == (0, "")
    assert (sysctl / "kernel/dmesg_restrict").read_text() == "1"
    assert (sysctl / "kernel/kptr_restrict").read_text() == "2"


@pytest.mark.parametrize("shell", SHELLS)
def test_harden_leaves_a_sysctl_the_kernel_does_not_have_alone(shell: str, sh: ShellRunner, lab: Lab) -> None:
    sysctl = lab.root / "sys"
    (sysctl / "kernel").mkdir(parents=True)
    (sysctl / "kernel/dmesg_restrict").write_text("0\n")
    result = sh(shell, 'harden "$1"', str(sysctl))
    assert (result.returncode, result.stderr) == (0, "")
    assert (sysctl / "kernel/dmesg_restrict").read_text() == "1"
    assert not (sysctl / "kernel/kptr_restrict").exists(), "must not create a file where the kernel has no sysctl"


@pytest.mark.parametrize("shell", SHELLS)
def test_harden_warns_cleanly_when_a_write_fails(shell: str, sh: ShellRunner, lab: Lab) -> None:
    sysctl = lab.root / "sys"
    (sysctl / "kernel/dmesg_restrict").mkdir(parents=True)  # a directory: writable, but not writable-to
    result = sh(shell, 'harden "$1"', str(sysctl))
    assert result.returncode == 0
    assert warnings_of(result) == [f"acf-init: warning: cannot set {sysctl}/kernel/dmesg_restrict"], result.stderr


@pytest.mark.parametrize("shell", SHELLS)
def test_set_identity_names_the_machine_and_makes_localhost_resolve(shell: str, sh: ShellRunner, lab: Lab) -> None:
    etc = lab.root / "etc"
    etc.mkdir()
    hostname = lab.root / "hostname"
    result = sh(shell, 'set_identity "$1" "$2"', str(etc), str(hostname))
    assert (result.returncode, result.stderr) == (0, "")
    assert hostname.read_text() == "acf-sandbox"
    assert (etc / "hostname").read_text() == "acf-sandbox\n"
    assert (etc / "hosts").read_text() == (
        "127.0.0.1\tlocalhost\n127.0.1.1\tacf-sandbox\n::1\tlocalhost ip6-localhost ip6-loopback\n"
    )


@pytest.mark.parametrize("shell", SHELLS)
def test_set_identity_is_idempotent(shell: str, sh: ShellRunner, lab: Lab) -> None:
    etc = lab.root / "etc"
    etc.mkdir()
    args = (str(etc), str(lab.root / "hostname"))
    first = sh(shell, 'set_identity "$1" "$2"', *args)
    snapshot = {p.name: p.read_bytes() for p in (etc / "hosts", etc / "hostname")}
    second = sh(shell, 'set_identity "$1" "$2"', *args)
    assert (first.returncode, second.returncode) == (0, 0)
    assert {p.name: p.read_bytes() for p in (etc / "hosts", etc / "hostname")} == snapshot


@pytest.mark.parametrize("shell", SHELLS)
def test_set_identity_failures_are_warnings_and_nothing_else_reaches_stderr(
    shell: str, sh: ShellRunner, lab: Lab
) -> None:
    """The shell would print "cannot create ..." itself for a failed redirection; the init must not let that through."""
    missing_etc = lab.root / "no-etc"
    result = sh(shell, 'set_identity "$1" "$2"', str(missing_etc), str(lab.root / "no-dir" / "hostname"))
    assert result.returncode == 0
    assert warnings_of(result) == [
        "acf-init: warning: cannot set the hostname",
        f'acf-init: warning: cannot write {missing_etc}/hosts; "localhost" will not resolve',
    ]


def fake_machine(
    lab: Lab, *, majmin: str = "254:0", link: str | None = "../../devices/platform/virtio-mmio.0/virtio0/block/vda"
) -> dict[str, Path]:
    """A pretend /proc/self/mountinfo, /sys/dev/block and /dev, for grow_root."""
    mountinfo = lab.root / "mountinfo"
    mountinfo.write_text(f"21 1 {majmin} / / rw,relatime - ext4 /dev/root rw\n23 21 0:21 / /sys rw - sysfs sysfs rw\n")
    sysblk = lab.root / "sys-dev-block"
    sysblk.mkdir()
    if link is not None:
        (sysblk / majmin).symlink_to(link)
    dev = lab.root / "dev"
    dev.mkdir()
    return {"mountinfo": mountinfo, "sysblk": sysblk, "dev": dev}


def grow(
    shell: str, sh: ShellRunner, machine: dict[str, Path], lab: Lab, **kwargs: object
) -> subprocess.CompletedProcess[str]:
    return sh(
        shell,
        'grow_root "$1" "$2" "$3"',
        str(machine["mountinfo"]),
        str(machine["sysblk"]),
        str(machine["dev"]),
        path=[lab.bin],
        **kwargs,
    )


@pytest.mark.parametrize("shell", SHELLS)
def test_grow_root_is_fatal_when_it_cannot_tell_which_device_holds_slash(shell: str, sh: ShellRunner, lab: Lab) -> None:
    machine = fake_machine(lab)
    machine["mountinfo"].write_text("23 21 0:21 / /sys rw - sysfs sysfs rw\n")
    lab.stub("resize2fs")
    result = grow(shell, sh, machine, lab)
    assert result.returncode == 1
    assert warnings_of(result) == ["acf-init: FATAL: cannot tell which device holds /"]
    assert lab.calls() == []


@pytest.mark.parametrize("shell", SHELLS)
def test_grow_root_is_fatal_when_sysfs_has_no_such_block_device(shell: str, sh: ShellRunner, lab: Lab) -> None:
    machine = fake_machine(lab, link=None)
    lab.stub("resize2fs")
    result = grow(shell, sh, machine, lab)
    assert result.returncode == 1
    assert "FATAL: no block device for 254:0" in result.stderr
    assert lab.calls() == []


@pytest.mark.parametrize("shell", SHELLS)
def test_grow_root_is_fatal_on_a_device_link_it_does_not_understand(shell: str, sh: ShellRunner, lab: Lab) -> None:
    machine = fake_machine(lab, link="../..")
    lab.stub("resize2fs")
    result = grow(shell, sh, machine, lab)
    assert result.returncode == 1
    assert "FATAL: unexpected device link for 254:0" in result.stderr
    assert lab.calls() == []


@pytest.mark.parametrize("shell", SHELLS)
def test_grow_root_will_not_hand_resize2fs_anything_that_is_not_a_block_device(
    shell: str, sh: ShellRunner, lab: Lab
) -> None:
    machine = fake_machine(lab)
    (machine["dev"] / "vda").write_text("a regular file is not a disk")
    lab.stub("resize2fs")
    result = grow(shell, sh, machine, lab)
    assert result.returncode == 1
    assert f"FATAL: {machine['dev']}/vda is not a block device" in result.stderr
    assert lab.calls() == []


def make_block_node(path: Path) -> None:
    try:
        os.mknod(path, stat.S_IFBLK | 0o600, os.makedev(7, 0))
    except PermissionError:
        pytest.skip("cannot create a block device node here (needs CAP_MKNOD)")
    except OSError as exc:  # e.g. a sandbox that forbids mknod entirely
        pytest.skip(f"cannot create a block device node here: {exc}")


@pytest.mark.needs_root
@pytest.mark.parametrize("shell", SHELLS)
def test_grow_root_resizes_the_device_that_holds_slash(shell: str, sh: ShellRunner, lab: Lab) -> None:
    machine = fake_machine(lab)
    make_block_node(machine["dev"] / "vda")
    lab.stub("resize2fs")
    result = grow(shell, sh, machine, lab)
    assert (result.returncode, result.stderr) == (0, "")
    assert lab.calls() == [f"resize2fs {machine['dev']}/vda"]


@pytest.mark.needs_root
@pytest.mark.parametrize("shell", SHELLS)
def test_grow_root_failing_is_fatal_because_the_sandbox_would_have_less_disk_than_promised(
    shell: str, sh: ShellRunner, lab: Lab
) -> None:
    machine = fake_machine(lab)
    make_block_node(machine["dev"] / "vda")
    lab.stub("resize2fs", "exit 1")
    result = grow(shell, sh, machine, lab)
    assert result.returncode == 1
    assert "FATAL: resize2fs" in result.stderr
    assert "less disk than requested" in result.stderr


@pytest.mark.parametrize("shell", SHELLS)
def test_prepare_state_creates_the_agents_directory_private_to_root(shell: str, sh: ShellRunner, lab: Lab) -> None:
    state = lab.root / "var" / "lib" / "acf"
    workspace = lab.root / "workspace"
    workspace.mkdir()
    result = sh(shell, 'prepare_state "$1" "$2"', str(state), str(workspace))
    assert (result.returncode, result.stderr) == (0, "")
    assert stat.S_IMODE(state.stat().st_mode) == 0o700


@pytest.mark.parametrize("shell", SHELLS)
def test_prepare_state_tightens_a_directory_that_already_exists(shell: str, sh: ShellRunner, lab: Lab) -> None:
    state = lab.root / "acf"
    state.mkdir()
    state.chmod(0o777)
    workspace = lab.root / "workspace"
    workspace.mkdir()
    result = sh(shell, 'prepare_state "$1" "$2"', str(state), str(workspace))
    assert result.returncode == 0
    assert stat.S_IMODE(state.stat().st_mode) == 0o700


@pytest.mark.parametrize("shell", SHELLS)
def test_prepare_state_warns_about_a_missing_workspace_but_boots(shell: str, sh: ShellRunner, lab: Lab) -> None:
    workspace = lab.root / "workspace"
    result = sh(shell, 'prepare_state "$1" "$2"', str(lab.root / "acf"), str(workspace))
    assert result.returncode == 0
    assert warnings_of(result) == [f"acf-init: warning: {workspace} does not exist in this image"]


@pytest.mark.parametrize("shell", SHELLS)
def test_prepare_state_is_fatal_when_the_state_directory_cannot_be_made(shell: str, sh: ShellRunner, lab: Lab) -> None:
    (lab.root / "a-file").write_text("")
    result = sh(shell, 'prepare_state "$1/acf" "$2"', str(lab.root / "a-file"), str(lab.root))
    assert result.returncode == 1
    assert "FATAL: cannot create" in result.stderr


@pytest.mark.parametrize("shell", SHELLS)
def test_loopback_up_uses_ip_when_there_is_one(shell: str, sh: ShellRunner, lab: Lab) -> None:
    lab.stub("ip")
    lab.stub("ifconfig")
    result = sh(shell, "loopback_up", path=[lab.bin], isolated=True)
    assert (result.returncode, result.stderr) == (0, "")
    assert lab.calls() == ["ip link set lo up"]


@pytest.mark.parametrize("shell", SHELLS)
def test_loopback_up_falls_back_to_ifconfig(shell: str, sh: ShellRunner, lab: Lab) -> None:
    lab.stub("ifconfig")
    result = sh(shell, "loopback_up", path=[lab.bin], isolated=True)
    assert result.returncode == 0
    assert lab.calls() == ["ifconfig lo up"]


@pytest.mark.parametrize("shell", SHELLS)
def test_loopback_up_reports_failure_when_there_is_no_tool_and_when_the_tool_fails(
    shell: str, sh: ShellRunner, lab: Lab
) -> None:
    assert sh(shell, "loopback_up", path=[lab.empty], isolated=True).returncode == 1
    lab.stub("ip", "exit 2")
    failing = sh(shell, "loopback_up", path=[lab.bin], isolated=True)
    assert failing.returncode == 2


DATE_STUB = r"""
case "$1" in
    +%s) printf '%s\n' "$ACF_FAKE_NOW" ;;
    -u) exit "${ACF_FAKE_SET_RC:-0}" ;;
    *) exit 99 ;;
esac
"""


@pytest.mark.parametrize("shell", SHELLS)
def test_apply_clock_floor_moves_a_clock_that_starts_in_1970_to_the_build_time(
    shell: str, sh: ShellRunner, lab: Lab
) -> None:
    lab.stub("date", DATE_STUB)
    (lab.root / "epoch").write_text("1700000000\n")
    result = sh(
        shell,
        "CLOCK_EPOCH_FILE=$1; apply_clock_floor",
        str(lab.root / "epoch"),
        path=[lab.bin],
        env={"ACF_FAKE_NOW": "42"},
    )
    assert (result.returncode, result.stderr) == (0, "")
    assert lab.calls() == ["date +%s", "date -u -s @1700000000"]


@pytest.mark.parametrize("shell", SHELLS)
def test_apply_clock_floor_leaves_a_sane_clock_alone(shell: str, sh: ShellRunner, lab: Lab) -> None:
    lab.stub("date", DATE_STUB)
    (lab.root / "epoch").write_text("1700000000\n")
    result = sh(
        shell,
        "CLOCK_EPOCH_FILE=$1; apply_clock_floor",
        str(lab.root / "epoch"),
        path=[lab.bin],
        env={"ACF_FAKE_NOW": "1900000000"},
    )
    assert result.returncode == 0
    assert lab.calls() == ["date +%s"]


@pytest.mark.parametrize("shell", SHELLS)
def test_apply_clock_floor_without_an_epoch_file_does_not_touch_the_clock(
    shell: str, sh: ShellRunner, lab: Lab
) -> None:
    lab.stub("date", DATE_STUB)
    result = sh(
        shell,
        "CLOCK_EPOCH_FILE=$1; apply_clock_floor",
        str(lab.root / "absent"),
        path=[lab.bin],
        env={"ACF_FAKE_NOW": "42"},
    )
    assert result.returncode == 0
    assert lab.calls() == ["date +%s"]


@pytest.mark.parametrize("shell", SHELLS)
def test_apply_clock_floor_reports_a_clock_that_cannot_be_set(shell: str, sh: ShellRunner, lab: Lab) -> None:
    lab.stub("date", DATE_STUB)
    (lab.root / "epoch").write_text("1700000000\n")
    result = sh(
        shell,
        'CLOCK_EPOCH_FILE=$1; apply_clock_floor; echo "rc=$?"',
        str(lab.root / "epoch"),
        path=[lab.bin],
        env={"ACF_FAKE_NOW": "42", "ACF_FAKE_SET_RC": "1"},
    )
    assert result.stdout == "rc=1\n"


@pytest.mark.parametrize("shell", SHELLS)
def test_supervise_ends_the_guest_with_the_agents_exit_status_in_the_message(shell: str, sh: ShellRunner) -> None:
    result = sh(shell, 'supervise sh -c "echo working; exit 7"; echo not-reached')
    assert result.returncode == 1  # init's own status: the kernel panics on it, the host sees the VMM end
    assert result.stdout == "working\n"
    assert warnings_of(result) == ["acf-init: FATAL: sh exited with status 7; ending the guest so the host can see it"]


@pytest.mark.parametrize("shell", SHELLS)
def test_supervise_treats_a_clean_exit_and_a_kill_as_equally_fatal(shell: str, sh: ShellRunner) -> None:
    clean = sh(shell, "supervise true")
    killed = sh(shell, 'supervise sh -c "kill -KILL \\$\\$"')
    assert clean.returncode == 1
    assert "exited with status 0" in clean.stderr
    assert killed.returncode == 1
    assert "exited with status 137" in killed.stderr


@pytest.mark.parametrize("shell", SHELLS)
def test_supervise_passes_arguments_through_untouched(shell: str, sh: ShellRunner) -> None:
    result = sh(shell, 'supervise printf "<%s>" "a b" "" "*" \'$HOME\'')
    assert result.stdout == "<a b><><*><$HOME>"


# ------------------------------------------------------------------- reaping: a real PID 1, in a PID namespace

# What the "agent" does: start a grandchild and let its parent exit, so the grandchild is re-parented to PID 1;
# give it time to exit; then count the zombies in the namespace. (/proc/PID/stat is `pid (comm) STATE ppid ...`.)
ORPHANING_AGENT = r"""
( sleep 0.1 & )
sleep 0.6
zombies=0
for stat in /proc/[0-9]*/stat; do
    read -r line <"$stat" 2>/dev/null || continue
    rest=${line##*) }
    case $rest in Z*) zombies=$((zombies + 1)) ;; esac
done
echo "zombies=$zombies"
"""


def in_pid_namespace(args: Sequence[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["unshare", "--pid", "--fork", "--kill-child", "--mount-proc", *args],
        capture_output=True,
        text=True,
        env={"PATH": os.pathsep.join(SYSTEM_PATH), "LC_ALL": "C", **env},
        timeout=60,
        check=False,
    )


@pytest.fixture(scope="module")
def pid_namespace() -> None:
    """Skip the test unless this machine lets us create a PID namespace (root, and a container policy that allows it)."""
    if shutil.which("unshare") is None:
        pytest.skip("unshare is not installed")
    probe = in_pid_namespace(["sh", "-c", 'test "$$" = 1 && test -r /proc/1/stat'], {})
    if probe.returncode != 0:
        pytest.skip(f"cannot create a PID namespace here: {probe.stderr.strip() or probe.returncode}")


@pytest.mark.needs_root
@pytest.mark.usefixtures("pid_namespace")
def test_the_control_a_pid_1_that_waits_only_for_its_child_leaves_the_orphan_a_zombie() -> None:
    """If this did not show a zombie, "zero zombies" below would prove nothing about the init."""
    control = "import subprocess, sys; sys.exit(subprocess.run(['sh', '-c', sys.argv[1]], check=False).returncode)"
    result = in_pid_namespace([sys.executable, "-I", "-c", control, ORPHANING_AGENT], {})
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "zombies=1"


@pytest.mark.needs_root
@pytest.mark.usefixtures("pid_namespace")
@pytest.mark.parametrize("shell", SHELLS)
def test_supervise_as_pid_1_reaps_the_orphans_of_the_commands_the_agent_runs(shell: str, init_lib: Path) -> None:
    script = '. "$ACF_INIT"; klog() { printf "%s\\n" "$*" >&2; }; supervise sh -c "$ACF_AGENT_SCRIPT"'
    binary = shutil.which(shell)
    assert binary
    result = in_pid_namespace(
        [binary, "-c", script],
        {"ACF_INIT": str(init_lib), "ACF_INIT_SOURCE_ONLY": "1", "ACF_AGENT_SCRIPT": ORPHANING_AGENT},
    )
    assert result.stdout.strip() == "zombies=0", result.stderr
    assert result.returncode == 1  # the agent exited, so init ends the guest
    assert "FATAL: sh exited with status 0" in result.stderr


@pytest.mark.needs_root
@pytest.mark.usefixtures("pid_namespace")
def test_the_pid_1_guard_lets_the_first_process_of_a_pid_namespace_through_to_main(init_lib: Path) -> None:
    """The other half of the guard: as PID 1 the init proceeds (here to the replaced `main`: an echo), as PID 2+ it refuses."""
    result = in_pid_namespace(["/bin/sh", str(init_lib)], {})
    assert (result.returncode, result.stdout, result.stderr) == (0, "reached-main\n", "")


@pytest.mark.needs_root
@pytest.mark.usefixtures("pid_namespace")
def test_the_pid_1_guard_refuses_the_second_process_of_a_pid_namespace(init_lib: Path) -> None:
    result = in_pid_namespace(["/bin/sh", "-c", f'/bin/sh {init_lib}; echo "rc=$?"'], {})
    assert "rc=2" in result.stdout
    assert "reached-main" not in result.stdout
    assert "refusing to run" in result.stderr
