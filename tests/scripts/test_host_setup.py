"""scripts/host-setup.sh — install the host agent, its trusted files, its identities and its units on a machine.

Nothing here touches the machine running the tests:

* ``install`` always runs with ``--destdir`` into a temporary directory, which also skips the account database,
  the runtime directory, ``systemd-tmpfiles`` and ``systemctl``;
* ``user`` runs against a fake account database: the programs it would call (``getent``, ``systemd-sysusers``,
  ``useradd``, ``groupadd``) are stubs, on a ``PATH`` that holds nothing else it could reach by accident;
* ``prerequisites`` only reads, and is pointed at a ``host.yaml`` written by the test.

The script finds the repository relative to itself, so a test that edits what the script reads works on a private
copy of the repository's non-Rust parts (the ``tree`` fixture). What stays untested here is what only a live
install does (creating the runtime directory, ``systemctl daemon-reload``): the ``integration`` workflow runs that.
"""

from __future__ import annotations

import difflib
import os
import re
import shutil
import stat
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

Runner = Callable[..., "subprocess.CompletedProcess[str]"]

REPO = Path(__file__).resolve().parents[2]
needs_root = pytest.mark.needs_root  # `install -o root -g root` and the script's own require_root
BASH = shutil.which("bash") or "/bin/bash"

UNITS = ("acf-cgroup.service", "acf-lifetime.service", "acf-host.service")
TRUSTED_FILES = {
    "host.yaml": "config/host.example.yaml",
    "profile.yaml": "profiles/default.yaml",
    "enrolment.yaml": "config/enrolment.example.yaml",
}


def acf_host(tmp_path: Path, *, extra: bytes = b"") -> Path:
    path = tmp_path / "acf-host"
    path.write_bytes(b"#!/bin/sh\necho acf-host stand-in\n" + extra)
    path.chmod(0o755)
    return path


def install(run: Runner, tree: Path, dest: Path, binary: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return run(["bash", tree / "scripts/host-setup.sh", "install", "--acf-host", binary, "--destdir", dest, *extra])


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def stub(bin_dir: Path, name: str, body: str) -> None:
    path = bin_dir / name
    path.write_text(f"#!{BASH}\n{body}")
    path.chmod(0o755)


# ------------------------------------------------------------------------------------------------------ install


@needs_root
def test_install_creates_the_documented_layout_with_root_owned_unwritable_files(
    run: Runner, tree: Path, tmp_path: Path
) -> None:
    dest = tmp_path / "dest"
    result = install(run, tree, dest, acf_host(tmp_path))
    assert result.returncode == 0, result.stderr

    expected_dirs = {
        "opt/acf": 0o755,
        "opt/acf/bin": 0o755,
        "opt/acf/libexec": 0o755,
        "etc/acf": 0o755,
        "etc/acf/secrets": 0o700,
        "var/lib/acf": 0o700,
        "var/lib/acf/images": 0o755,
        "etc/systemd/system": 0o755,
        "etc/tmpfiles.d": 0o755,
        "etc/sysusers.d": 0o755,
    }
    for rel, want in expected_dirs.items():
        path = dest / rel
        assert path.is_dir(), rel
        assert mode(path) == want, f"{rel}: {mode(path):o}"
        assert (path.stat().st_uid, path.stat().st_gid) == (0, 0), rel

    expected_files = {
        "opt/acf/bin/acf-host": (tmp_path / "acf-host", 0o755),
        "opt/acf/libexec/acf-setup-cgroup": (tree / "scripts/acf-setup-cgroup", 0o755),
        "opt/acf/libexec/acf-wait-ready": (tree / "scripts/acf-wait-ready", 0o755),
        **{f"etc/acf/{name}": (tree / source, 0o644) for name, source in TRUSTED_FILES.items()},
        **{f"etc/systemd/system/{unit}": (tree / "deploy/systemd" / unit, 0o644) for unit in UNITS},
        "etc/tmpfiles.d/acf.conf": (tree / "deploy/tmpfiles.d/acf.conf", 0o644),
        "etc/sysusers.d/acf.conf": (tree / "deploy/sysusers.d/acf.conf", 0o644),
    }
    for rel, (source, want) in expected_files.items():
        path = dest / rel
        assert path.is_file(), rel
        assert path.read_bytes() == source.read_bytes(), rel
        assert mode(path) == want, f"{rel}: {mode(path):o}"
        assert (path.stat().st_uid, path.stat().st_gid) == (0, 0), rel

    installed = {p.relative_to(dest).as_posix() for p in dest.rglob("*") if p.is_file()}
    assert installed == set(expected_files), "nothing else is installed, and no atomic-replace temporary survives"
    assert not (dest / "run").exists(), "the runtime directory belongs to the target machine, not to a staged tree"
    assert "Installed. Next steps (nothing has been started)" in result.stderr
    assert "systemctl enable --now acf-cgroup.service acf-lifetime.service acf-host.service" in result.stderr
    assert "edge.uid and edge.gid are NOT set in a staged host.yaml" in result.stderr


@needs_root
def test_a_staged_install_starts_nothing_and_touches_no_account_database(
    run: Runner, tree: Path, tmp_path: Path
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "calls.log"
    for name in ("systemctl", "systemd-tmpfiles", "systemd-sysusers", "useradd", "groupadd", "getent"):
        stub(bin_dir, name, f'echo "{name} $*" >>"{log}"\n')
    env = {"PATH": f"{bin_dir}:{os.environ.get('PATH', '/usr/bin:/bin')}"}
    result = run(
        [
            "bash",
            tree / "scripts/host-setup.sh",
            "install",
            "--acf-host",
            acf_host(tmp_path),
            "--destdir",
            tmp_path / "dest",
        ],
        env=env,
    )
    assert result.returncode == 0, result.stderr
    assert not log.exists(), f"--destdir must change nothing but the staged tree; it ran: {log.read_text()}"


@needs_root
def test_a_second_install_succeeds_and_keeps_everything(run: Runner, tree: Path, tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    binary = acf_host(tmp_path)
    assert install(run, tree, dest, binary).returncode == 0
    before = {p.relative_to(dest): p.read_bytes() for p in dest.rglob("*") if p.is_file()}
    again = install(run, tree, dest, binary)
    assert again.returncode == 0, again.stderr
    after = {p.relative_to(dest): p.read_bytes() for p in dest.rglob("*") if p.is_file()}
    assert after == before
    assert again.stderr.count("is already the shipped version") == len(TRUSTED_FILES)
    assert "WARNING" not in again.stderr


@needs_root
def test_an_operators_edited_trusted_file_is_never_overwritten_the_shipped_one_is_offered_beside_it(
    run: Runner, tree: Path, tmp_path: Path
) -> None:
    dest = tmp_path / "dest"
    binary = acf_host(tmp_path)
    assert install(run, tree, dest, binary).returncode == 0
    for name in TRUSTED_FILES:
        (dest / "etc/acf" / name).write_text(f"# edited by the operator: {name}\n")
    again = install(run, tree, dest, binary)
    assert again.returncode == 0, again.stderr
    for name, source in TRUSTED_FILES.items():
        assert (dest / "etc/acf" / name).read_text() == f"# edited by the operator: {name}\n"
        assert (dest / "etc/acf" / f"{name}.dist").read_bytes() == (tree / source).read_bytes()
    assert again.stderr.count("kept yours, wrote") == len(TRUSTED_FILES)


@needs_root
def test_force_config_replaces_the_operators_files_with_the_shipped_ones(
    run: Runner, tree: Path, tmp_path: Path
) -> None:
    dest = tmp_path / "dest"
    binary = acf_host(tmp_path)
    assert install(run, tree, dest, binary).returncode == 0
    for name in TRUSTED_FILES:
        (dest / "etc/acf" / name).write_text("# edited\n")
    assert install(run, tree, dest, binary, "--force-config").returncode == 0
    for name, source in TRUSTED_FILES.items():
        assert (dest / "etc/acf" / name).read_bytes() == (tree / source).read_bytes()


@needs_root
def test_an_upgrade_replaces_the_binary_atomically_and_leaves_state_and_secrets_alone(
    run: Runner, tree: Path, tmp_path: Path
) -> None:
    dest = tmp_path / "dest"
    assert install(run, tree, dest, acf_host(tmp_path)).returncode == 0
    (dest / "var/lib/acf/images").joinpath("keep-me").write_text("an installed image would be here")
    (dest / "var/lib/acf/state").mkdir()
    (dest / "var/lib/acf/state/journal.wal").write_text("the store")
    (dest / "etc/acf/secrets/api-token").write_text("provisioned by the operator")
    newer = acf_host(tmp_path, extra=b"# a newer build\n")
    assert install(run, tree, dest, newer).returncode == 0
    assert (dest / "opt/acf/bin/acf-host").read_bytes() == newer.read_bytes()
    assert (dest / "var/lib/acf/images/keep-me").read_text() == "an installed image would be here"
    assert (dest / "var/lib/acf/state/journal.wal").read_text() == "the store"
    assert (dest / "etc/acf/secrets/api-token").read_text() == "provisioned by the operator"
    assert mode(dest / "etc/acf/secrets") == 0o700


@needs_root
@pytest.mark.parametrize("sentinel", ["simulated crash at", "FakeBackend", "acf-host-fake"])
def test_a_binary_with_test_only_code_is_refused_before_anything_is_installed(
    run: Runner, tree: Path, tmp_path: Path, sentinel: str
) -> None:
    dest = tmp_path / "dest"
    result = install(run, tree, dest, acf_host(tmp_path, extra=sentinel.encode()))
    assert result.returncode == 1
    assert "contains test-only code" in result.stderr
    assert not dest.exists() or list(dest.rglob("*")) == [], "a refused binary must leave the machine untouched"


@needs_root
def test_a_missing_or_non_executable_binary_is_refused_with_the_way_to_build_it(
    run: Runner, tree: Path, tmp_path: Path
) -> None:
    missing = install(run, tree, tmp_path / "dest", tmp_path / "absent")
    assert missing.returncode == 1
    assert "no acf-host binary at" in missing.stderr
    assert "make release" in missing.stderr
    plain = tmp_path / "plain"
    plain.write_text("not executable")
    assert install(run, tree, tmp_path / "dest", plain).returncode == 1


@needs_root
def test_no_systemd_skips_the_units_but_installs_the_rest_and_says_how_to_start_the_roles(
    run: Runner, tree: Path, tmp_path: Path
) -> None:
    dest = tmp_path / "dest"
    result = install(run, tree, dest, acf_host(tmp_path), "--no-systemd")
    assert result.returncode == 0, result.stderr
    assert (dest / "opt/acf/bin/acf-host").is_file()
    assert (dest / "etc/acf/enrolment.yaml").is_file()
    for absent in ("etc/systemd", "etc/tmpfiles.d", "etc/sysusers.d"):
        assert not (dest / absent).exists(), absent
    assert "systemctl" not in result.stderr
    lifetime = result.stderr.index("acf-host lifetime --config /etc/acf/host.yaml")
    serve = result.stderr.index("acf-host serve --config /etc/acf/host.yaml")
    assert lifetime < serve, "the lifetime enforcer is started before the core"


@needs_root
def test_prefix_and_state_root_are_written_into_everything_that_names_them(
    run: Runner, tree: Path, tmp_path: Path
) -> None:
    dest = tmp_path / "dest"
    result = install(
        run, tree, dest, acf_host(tmp_path), "--prefix", "/usr/local/acf", "--state-root", "/srv/acf-state"
    )
    assert result.returncode == 0, result.stderr
    assert (dest / "usr/local/acf/bin/acf-host").is_file()
    assert (dest / "usr/local/acf/libexec/acf-setup-cgroup").is_file()
    assert (dest / "usr/local/acf/libexec/acf-wait-ready").is_file()
    assert mode(dest / "srv/acf-state") == 0o700
    assert mode(dest / "srv/acf-state/images") == 0o755
    assert not (dest / "opt").exists()
    assert not (dest / "var").exists()

    # A unit that still started /opt/acf/bin/acf-host would start nothing.
    for unit in UNITS:
        text = (dest / "etc/systemd/system" / unit).read_text()
        assert "/opt/acf" not in text, unit
        assert "/usr/local/acf/" in text, unit
    assert "ExecStart=/usr/local/acf/bin/acf-host serve" in (dest / "etc/systemd/system/acf-host.service").read_text()
    tmpfiles = (dest / "etc/tmpfiles.d/acf.conf").read_text()
    assert re.search(r"^d\s+/srv/acf-state\s+0700\s+root\s+root\s", tmpfiles, re.MULTILINE)
    assert "/var/lib/acf" not in tmpfiles
    config = (dest / "etc/acf/host.yaml").read_text()
    assert "state_root: /srv/acf-state" in config
    assert "firecracker_bin: /usr/local/acf/bin/firecracker" in config
    assert "jailer_bin: /usr/local/acf/bin/jailer" in config

    assert "/usr/local/acf/bin/acf-host doctor" in result.stderr
    assert "scripts/install-firecracker.sh --prefix /usr/local/acf" in result.stderr
    again = install(run, tree, dest, acf_host(tmp_path), "--prefix", "/usr/local/acf", "--state-root", "/srv/acf-state")
    assert again.returncode == 0, again.stderr
    assert "WARNING" not in again.stderr, "the rendered file is the shipped version of this installation"


@needs_root
def test_edge_ids_are_written_into_the_staged_host_config_and_nothing_else_changes(
    run: Runner, tree: Path, tmp_path: Path
) -> None:
    dest = tmp_path / "dest"
    result = install(run, tree, dest, acf_host(tmp_path), "--edge-ids", "990:991")
    assert result.returncode == 0, result.stderr
    shipped = (tree / "config/host.example.yaml").read_text().splitlines()
    staged = (dest / "etc/acf/host.yaml").read_text().splitlines()
    changed = [
        line
        for line in difflib.unified_diff(shipped, staged, lineterm="", n=0)
        if line[:1] in "+-" and line[:3] not in ("+++", "---")
    ]
    assert changed == ["-  # uid: 990", "-  # gid: 990", "+  uid: 990", "+  gid: 991"]
    # Both keys sit in the `edge:` block: the first key after it that is not a comment.
    edge = staged.index("edge:")
    first_keys = [line for line in staged[edge + 1 :] if line.strip() and not line.lstrip().startswith("#")][:2]
    assert first_keys == ["  uid: 990", "  gid: 991"]
    assert "staged with edge.uid: 990 and edge.gid: 991" in result.stderr

    again = install(run, tree, dest, acf_host(tmp_path), "--edge-ids", "990:991")
    assert again.returncode == 0, again.stderr
    assert "WARNING" not in again.stderr
    assert not (dest / "etc/acf/host.yaml.dist").exists()


@needs_root
def test_a_shipped_config_without_the_keys_to_fill_in_is_an_error_before_anything_is_installed(
    run: Runner, tree: Path, tmp_path: Path
) -> None:
    example = tree / "config/host.example.yaml"
    example.write_text(example.read_text().replace("  # uid: 990\n", ""))
    dest = tmp_path / "dest"
    result = install(run, tree, dest, acf_host(tmp_path), "--edge-ids", "990:991")
    assert result.returncode == 1
    assert "no commented-out `# uid:` and `# gid:`" in result.stderr
    assert "nothing was installed" in result.stderr
    assert not dest.exists() or list(dest.rglob("*")) == []


@needs_root
def test_a_policy_file_left_by_an_earlier_layout_is_pointed_out_and_left_alone(
    run: Runner, tree: Path, tmp_path: Path
) -> None:
    dest = tmp_path / "dest"
    (dest / "etc/acf").mkdir(parents=True)
    (dest / "etc/acf/policy.yaml").write_text("# the previous layout\n")
    result = install(run, tree, dest, acf_host(tmp_path))
    assert result.returncode == 0, result.stderr
    assert "policy.yaml is no longer read: the safety profile is /etc/acf/profile.yaml" in result.stderr
    assert (dest / "etc/acf/policy.yaml").read_text() == "# the previous layout\n"
    assert (dest / "etc/acf/profile.yaml").read_bytes() == (tree / "profiles/default.yaml").read_bytes()


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (["--prefix", "relative/dir"], "must be absolute paths"),
        (["--state-root", "relative"], "must be absolute paths"),
        (["--destdir", "relative"], "--destdir must be an absolute path"),
        (["--prefix", "/opt/a b"], "may contain only"),
        (["--state-root", "/srv/acf|x"], "may contain only"),
        (["--edge-ids", "990:991"], "--edge-ids is for --destdir"),
        (["--destdir", "/nonexistent/stage", "--edge-ids", "0:991"], "two numbers greater than 0"),
        (["--destdir", "/nonexistent/stage", "--edge-ids", "990"], "two numbers greater than 0"),
        (["--destdir", "/nonexistent/stage", "--edge-ids", "acf-edge:acf-edge"], "two numbers greater than 0"),
        (["--bogus"], "unknown option: --bogus"),
    ],
)
def test_bad_arguments_are_usage_errors_and_touch_nothing(
    run: Runner, tree: Path, tmp_path: Path, extra: list[str], message: str
) -> None:
    result = run(["bash", tree / "scripts/host-setup.sh", "install", "--acf-host", acf_host(tmp_path), *extra])
    assert result.returncode == 2, result.stderr
    assert message in result.stderr
    assert not (tmp_path / "relative").exists()
    assert not Path("/nonexistent/stage").exists()


def test_the_subcommands_and_their_exit_codes(run: Runner, tree: Path) -> None:
    script = tree / "scripts/host-setup.sh"
    assert run(["bash", script]).returncode == 2
    assert "Usage:" in run(["bash", script]).stderr
    unknown = run(["bash", script, "frobnicate"])
    assert unknown.returncode == 2
    assert "unknown command: frobnicate" in unknown.stderr
    for flag in ("--help", "-h", "help"):
        helped = run(["bash", script, flag])
        assert helped.returncode == 0
        for subcommand in ("install", "user", "prerequisites", "cgroup", "check"):
            assert f"host-setup.sh {subcommand}" in helped.stdout, subcommand
    assert run(["bash", script, "check", "--verbose"]).returncode == 2
    assert run(["bash", script, "user", "extra"]).returncode == 2


@needs_root
def test_cgroup_hands_its_arguments_to_acf_setup_cgroup(run: Runner, tree: Path, tmp_path: Path) -> None:
    fake = tmp_path / "cgroup"
    fake.mkdir()
    (fake / "cgroup.controllers").write_text("cpuset cpu io memory pids\n")
    result = run(["bash", tree / "scripts/host-setup.sh", "cgroup", "mygroup"], env={"ACF_CGROUP_ROOT": str(fake)})
    assert result.returncode == 0, result.stderr
    assert (fake / "mygroup").is_dir()


@pytest.mark.skipif(
    Path("/opt/acf/bin/acf-host").exists(), reason="this machine has a real acf-host installed; `check` would run it"
)
def test_check_without_an_installed_agent_says_how_to_install_one(run: Runner, tree: Path) -> None:
    result = run(["bash", tree / "scripts/host-setup.sh", "check"])
    assert result.returncode == 1
    assert "acf-host is not installed" in result.stderr
    assert "host-setup.sh install" in result.stderr


# --------------------------------------------------------------------------------------------------------- user

GETENT = """\
while IFS= read -r line; do
    if [[ "$line" == "$2:"* ]]; then printf '%s\\n' "$line"; exit 0; fi
done <"$FAKE_DB/$1"
exit 2
"""
SYSUSERS = """\
printf 'systemd-sysusers %s\\n' "$*" >>"$CALLS"
printf 'acf-edge:x:990:991:ACF host agent edge (unprivileged):/:/usr/sbin/nologin\\n' >>"$FAKE_DB/passwd"
printf 'acf-edge:x:991:\\nacf:x:992:\\n' >>"$FAKE_DB/group"
"""
GROUPADD = """\
printf 'groupadd %s\\n' "$*" >>"$CALLS"
name="${*: -1}"
case "$name" in acf-edge) gid=881 ;; *) gid=882 ;; esac
printf '%s:x:%s:\\n' "$name" "$gid" >>"$FAKE_DB/group"
"""
USERADD = """\
printf 'useradd %s\\n' "$*" >>"$CALLS"
printf '%s:x:880:881:edge:/:/usr/sbin/nologin\\n' "${*: -1}" >>"$FAKE_DB/passwd"
"""


class FakeAccounts:
    """An account database in two files, and a ``PATH`` on which only the stubs given here can change it."""

    def __init__(self, tmp_path: Path, **stubs: str) -> None:
        self.db = tmp_path / "accounts"
        self.db.mkdir()
        (self.db / "passwd").write_text("root:x:0:0:root:/root:/bin/sh\n")
        (self.db / "group").write_text("root:x:0:\n")
        self.calls = tmp_path / "account-calls.log"
        self.bin = tmp_path / "account-bin"
        self.bin.mkdir()
        for tool in ("bash", "dirname", "cat"):  # all the script itself needs on this path
            real = shutil.which(tool)
            assert real is not None, tool
            (self.bin / tool).symlink_to(real)
        stub(self.bin, "getent", GETENT)
        for name, body in stubs.items():
            stub(self.bin, name.replace("_", "-"), body)

    @property
    def env(self) -> dict[str, str]:
        return {"PATH": str(self.bin), "FAKE_DB": str(self.db), "CALLS": str(self.calls)}

    def called(self) -> list[str]:
        return self.calls.read_text().splitlines() if self.calls.exists() else []


def user(run: Runner, tree: Path, accounts: FakeAccounts) -> subprocess.CompletedProcess[str]:
    return run(["bash", tree / "scripts/host-setup.sh", "user"], env=accounts.env)


def printed(result: subprocess.CompletedProcess[str]) -> dict[str, str]:
    return dict(line.split("=", 1) for line in result.stdout.splitlines())


@needs_root
def test_user_creates_the_identities_from_the_shipped_sysusers_file_and_prints_their_ids(
    run: Runner, tree: Path, tmp_path: Path
) -> None:
    accounts = FakeAccounts(tmp_path, systemd_sysusers=SYSUSERS, useradd=USERADD, groupadd=GROUPADD)
    result = user(run, tree, accounts)
    assert result.returncode == 0, result.stderr
    assert accounts.called() == [f"systemd-sysusers {tree}/deploy/sysusers.d/acf.conf"], (
        "systemd-sysusers is preferred, and it is given the file a package would install"
    )
    assert printed(result) == {
        "edge_user": "acf-edge",
        "edge_uid": "990",
        "edge_gid": "991",
        "socket_group": "acf",
        "socket_gid": "992",
    }
    assert "edge.uid: 990 and edge.gid: 991 (required)" in result.stderr


@needs_root
def test_user_falls_back_to_useradd_and_groupadd_where_there_is_no_systemd_sysusers(
    run: Runner, tree: Path, tmp_path: Path
) -> None:
    accounts = FakeAccounts(tmp_path, useradd=USERADD, groupadd=GROUPADD)
    result = user(run, tree, accounts)
    assert result.returncode == 0, result.stderr
    assert accounts.called() == [
        "groupadd --system -- acf-edge",
        (
            "useradd --system --gid acf-edge --home-dir / --no-create-home --shell /usr/sbin/nologin"
            " --comment ACF host agent edge (unprivileged) -- acf-edge"
        ),
        "groupadd --system -- acf",
    ]
    assert printed(result)["edge_uid"] == "880"
    assert printed(result)["edge_gid"] == "881"
    assert printed(result)["socket_gid"] == "882"


@needs_root
def test_user_leaves_existing_identities_exactly_as_they_are(run: Runner, tree: Path, tmp_path: Path) -> None:
    accounts = FakeAccounts(tmp_path, systemd_sysusers=SYSUSERS, useradd=USERADD, groupadd=GROUPADD)
    with (accounts.db / "passwd").open("a") as f:
        f.write("acf-edge:x:455:456:created by the site's own tooling:/:/sbin/nologin\n")
    with (accounts.db / "group").open("a") as f:
        f.write("acf-edge:x:456:\nacf:x:457:alice,bob\n")
    result = user(run, tree, accounts)
    assert result.returncode == 0, result.stderr
    assert accounts.called() == [], "nothing is created, changed or re-applied"
    assert (printed(result)["edge_uid"], printed(result)["edge_gid"], printed(result)["socket_gid"]) == (
        "455",
        "456",
        "457",
    )


@needs_root
def test_user_creates_only_what_is_missing(run: Runner, tree: Path, tmp_path: Path) -> None:
    accounts = FakeAccounts(tmp_path, useradd=USERADD, groupadd=GROUPADD)
    with (accounts.db / "passwd").open("a") as f:
        f.write("acf-edge:x:455:456:edge:/:/sbin/nologin\n")
    with (accounts.db / "group").open("a") as f:
        f.write("acf-edge:x:456:\n")
    result = user(run, tree, accounts)
    assert result.returncode == 0, result.stderr
    assert accounts.called() == ["groupadd --system -- acf"]
    assert printed(result)["edge_uid"] == "455"


@needs_root
def test_an_edge_user_that_is_root_is_refused(run: Runner, tree: Path, tmp_path: Path) -> None:
    accounts = FakeAccounts(tmp_path)
    with (accounts.db / "passwd").open("a") as f:
        f.write("acf-edge:x:0:0:a dangerous shortcut:/:/bin/sh\n")
    with (accounts.db / "group").open("a") as f:
        f.write("acf:x:457:\n")
    result = user(run, tree, accounts)
    assert result.returncode == 1
    assert "acf-edge has uid or gid 0" in result.stderr
    assert result.stdout == "", "no ids are printed for an identity the host must not use"


@needs_root
def test_user_says_which_tools_are_missing_when_it_cannot_create_an_account(
    run: Runner, tree: Path, tmp_path: Path
) -> None:
    result = user(run, tree, FakeAccounts(tmp_path))
    assert result.returncode == 1
    assert "required command not found: groupadd" in result.stderr
    assert "no systemd-sysusers" in result.stderr


@needs_root
def test_a_tool_that_creates_nothing_is_an_error_not_an_empty_answer(run: Runner, tree: Path, tmp_path: Path) -> None:
    accounts = FakeAccounts(tmp_path, systemd_sysusers='printf "systemd-sysusers %s\\n" "$*" >>"$CALLS"\n')
    result = user(run, tree, accounts)
    assert result.returncode == 1
    assert "user acf-edge does not exist although it was just created" in result.stderr
    assert result.stdout == ""


# ------------------------------------------------------------------------------------------------ prerequisites

TOOLS = ("ip", "nft", "nsenter", "unshare")
AS_ROOT = os.geteuid() == 0


def host_yaml(tmp_path: Path, tools_dir: Path, *, lines: dict[str, str] | None = None) -> Path:
    """A host.yaml whose network section names the four tools in ``tools_dir`` (``lines`` replaces an entry)."""
    entries = {tool: f"  {tool}_bin: {tools_dir / tool}" for tool in TOOLS}
    entries.update(lines or {})
    path = tmp_path / "host.yaml"
    path.write_text("schema_version: 2\nhost_id: host-1\nnetwork:\n" + "\n".join(entries.values()) + "\n")
    return path


def tools(tmp_path: Path, *, without: tuple[str, ...] = ()) -> Path:
    directory = tmp_path / "tools"
    directory.mkdir()
    for tool in TOOLS:
        if tool not in without:
            (directory / tool).write_text("#!/bin/sh\n")
            (directory / tool).chmod(0o755)
    return directory


def prerequisites(run: Runner, config: Path) -> subprocess.CompletedProcess[str]:
    return run(["bash", REPO / "scripts/host-setup.sh", "prerequisites", "--config", config])


@pytest.mark.skipif(not AS_ROOT, reason="as an ordinary user the test's own files are not root-owned")
def test_four_root_owned_unwritable_tools_are_reported_present(run: Runner, tmp_path: Path) -> None:
    config = host_yaml(tmp_path, tools(tmp_path))
    result = prerequisites(run, config)
    assert result.returncode == 0, result.stderr
    assert f"prerequisites: ip, nft, nsenter and unshare are present at the paths {config} names" in result.stderr
    assert "WARNING" not in result.stderr


@pytest.mark.skipif(AS_ROOT, reason="root owns the files this test writes")
def test_a_tool_that_root_does_not_own_is_not_one_the_host_will_run(run: Runner, tmp_path: Path) -> None:
    result = prerequisites(run, host_yaml(tmp_path, tools(tmp_path)))
    assert result.returncode == 1
    for tool in TOOLS:
        assert f"network.{tool}_bin: " in result.stderr
    assert result.stderr.count("is not owned by root, or is writable by group or other") == len(TOOLS)
    assert "acf-host will not run it" in result.stderr


@pytest.mark.parametrize(
    ("tool", "package", "consequence"),
    [
        ("ip", "iproute2", "network mode `allowlist` is not offered; mode `none` works"),
        ("nft", "nftables", "network mode `allowlist` is not offered; mode `none` works"),
        ("nsenter", "util-linux", "network mode `allowlist` is not offered; mode `none` works"),
        ("unshare", "util-linux", "no sandbox can be created, and the core starts in CONTAINMENT"),
    ],
)
def test_a_missing_tool_is_named_with_its_package_and_what_the_host_cannot_do_without_it(
    run: Runner, tmp_path: Path, tool: str, package: str, consequence: str
) -> None:
    directory = tools(tmp_path, without=(tool,))
    result = prerequisites(run, host_yaml(tmp_path, directory))
    assert result.returncode == 1
    missing = [line for line in result.stderr.splitlines() if f"no executable at {directory / tool}." in line]
    assert len(missing) == 1, result.stderr
    assert f"network.{tool}_bin: " in missing[0]
    assert f"Install the {package} package" in missing[0]
    assert consequence in missing[0]
    assert "are present at the paths" not in result.stderr


def test_a_tool_that_group_or_other_can_write_is_refused_whoever_owns_it(run: Runner, tmp_path: Path) -> None:
    directory = tools(tmp_path)
    (directory / "nft").chmod(0o775)
    result = prerequisites(run, host_yaml(tmp_path, directory))
    assert result.returncode == 1
    refused = [line for line in result.stderr.splitlines() if "network.nft_bin: " in line]
    assert len(refused) == 1
    assert "mode 775" in refused[0]


def test_quoted_paths_and_trailing_comments_in_host_yaml_are_read_as_yaml_means_them(
    run: Runner, tmp_path: Path
) -> None:
    directory = tools(tmp_path, without=("ip", "nft"))
    config = host_yaml(
        tmp_path,
        directory,
        lines={
            "ip": f'  ip_bin: "{directory / "ip"}"   # quoted',
            "nft": f"  nft_bin: '{directory / 'nft'}'",
        },
    )
    result = prerequisites(run, config)
    assert f"no executable at {directory / 'ip'}." in result.stderr
    assert f"no executable at {directory / 'nft'}." in result.stderr


def test_a_path_host_yaml_does_not_name_is_the_built_in_default(run: Runner, tmp_path: Path) -> None:
    config = tmp_path / "host.yaml"
    config.write_text("schema_version: 2\nhost_id: host-1\n# network:\n#   ip_bin: /elsewhere/ip\n")
    result = prerequisites(run, config)
    for default in ("/usr/sbin/ip", "/usr/sbin/nft", "/usr/bin/nsenter", "/usr/bin/unshare"):
        present = Path(default).is_file()
        assert (f"no executable at {default}." in result.stderr) == (not present), default
    assert "/elsewhere/ip" not in result.stderr, "a commented-out key is not a setting"


def test_the_built_in_defaults_are_the_ones_the_shipped_host_config_names() -> None:
    script = (REPO / "scripts/host-setup.sh").read_text()
    example = (REPO / "config/host.example.yaml").read_text()
    for tool, package in (
        ("ip", "iproute2"),
        ("nft", "nftables"),
        ("nsenter", "util-linux"),
        ("unshare", "util-linux"),
    ):
        shipped = re.search(rf"^  {tool}_bin: (\S+)$", example, re.MULTILINE)
        assert shipped is not None, f"config/host.example.yaml no longer names network.{tool}_bin"
        assert f"\n{tool}_bin {shipped.group(1)} {package}\n" in script, tool


def test_prerequisites_needs_a_host_yaml_it_can_read(run: Runner, tmp_path: Path) -> None:
    result = prerequisites(run, tmp_path / "absent.yaml")
    assert result.returncode == 1
    assert "cannot read" in result.stderr
    assert run(["bash", REPO / "scripts/host-setup.sh", "prerequisites", "--bogus"]).returncode == 2
