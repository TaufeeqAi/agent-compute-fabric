"""The stored credential: where it lives, who may read it, and which configuration a command runs with.

Four things are proved here. The file is created for its owner alone and replaced whole; a file that
others can read is refused, not repaired; each value comes from a flag, then the environment, then the
stored profile; and ``acf auth login`` stores a key without ever showing it.

File modes are a POSIX matter. Both branches are run on whatever system runs the tests, by telling the
module which kind of system it is on.
"""

from __future__ import annotations

import getpass
import json
import os
import stat
from pathlib import Path

import pytest

import authorities
from agentcompute_cli import common, credentials
from agentcompute_cli.credentials import CredentialStore, Profile, RelaySettings, Settings
from agentcompute_cli.outcome import UsageError
from support import (
    AGENT_KEY,
    BASE_URL,
    CANARY_KEY,
    MCP_URL,
    PRINCIPAL,
    PROJECT,
    SBX,
    Cli,
    ex,
    refusal,
    reply,
    sandbox,
    whoami,
)

STORED_KEY = "acf1_dev_stored_Wm4TzC8nB1q6"
OTHER_URL = "https://other.acf.test"
NO_ENVIRONMENT = {"ACF_API_KEY": None, "ACF_BASE_URL": None, "ACF_PROJECT": None}
WHOAMI = ex("GET", "/v1/auth/whoami", reply(200, whoami()))

needs_posix = pytest.mark.skipif(os.name != "posix", reason="file modes are a POSIX matter")


def mode_of(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.fixture
def store(tmp_path: Path) -> CredentialStore:
    return CredentialStore(tmp_path / "config" / "acf" / "credentials.json")


# ------------------------------------------------------------------------------------- where the file is
def test_the_file_is_under_the_configuration_directory_of_the_user(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(credentials, "is_windows", lambda: False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    assert credentials.credentials_path() == tmp_path / "xdg" / "acf" / "credentials.json"
    monkeypatch.delenv("XDG_CONFIG_HOME")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    assert credentials.credentials_path() == tmp_path / "home" / ".config" / "acf" / "credentials.json"


def test_a_relative_configuration_directory_is_ignored_as_its_specification_says(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(credentials, "is_windows", lambda: False)
    monkeypatch.setenv("XDG_CONFIG_HOME", "relative/place")
    monkeypatch.setenv("HOME", str(tmp_path))
    assert credentials.credentials_path() == tmp_path / ".config" / "acf" / "credentials.json"


def test_on_windows_the_file_is_under_the_application_data_of_the_user(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(credentials, "is_windows", lambda: True)
    monkeypatch.setenv("APPDATA", str(tmp_path / "Roaming"))
    assert credentials.credentials_path() == tmp_path / "Roaming" / "acf" / "credentials.json"
    monkeypatch.delenv("APPDATA")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    assert credentials.credentials_path() == tmp_path / "AppData" / "Roaming" / "acf" / "credentials.json"


def test_no_home_directory_is_said_plainly(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_home() -> Path:
        raise RuntimeError("Could not determine home directory.")

    monkeypatch.setattr(credentials, "is_windows", lambda: False)
    monkeypatch.delenv("XDG_CONFIG_HOME")
    monkeypatch.setattr(Path, "home", no_home)
    with pytest.raises(UsageError, match="home directory"):
        credentials.credentials_path()


# ------------------------------------------------------------------------------------------- the file
@needs_posix
def test_the_file_is_created_for_its_owner_alone_in_a_directory_only_the_owner_can_enter(
    store: CredentialStore,
) -> None:
    store.put("default", Profile(STORED_KEY, BASE_URL, PROJECT))
    assert mode_of(store.path) == 0o600
    assert mode_of(store.path.parent) == 0o700


@needs_posix
def test_a_directory_that_was_there_with_a_wider_mode_is_closed(store: CredentialStore) -> None:
    store.path.parent.mkdir(parents=True)
    store.path.parent.chmod(0o755)
    store.put("default", Profile(STORED_KEY, BASE_URL))
    assert mode_of(store.path.parent) == 0o700
    assert mode_of(store.path.parent.parent) != 0o700, "the directory above is not this tool's to change"


@needs_posix
def test_a_file_that_was_there_is_replaced_and_stays_closed_whatever_the_mask(store: CredentialStore) -> None:
    before = os.umask(0)
    try:
        store.put("default", Profile(STORED_KEY, BASE_URL))
        store.put("other", Profile(STORED_KEY, OTHER_URL))
    finally:
        os.umask(before)
    assert mode_of(store.path) == 0o600


def test_the_file_is_replaced_whole_and_nothing_else_is_left_behind(store: CredentialStore) -> None:
    store.put("default", Profile(STORED_KEY, BASE_URL, PROJECT, MCP_URL))
    first = store.path.stat().st_ino
    store.put("agent", Profile(AGENT_KEY, OTHER_URL))
    assert store.path.stat().st_ino != first, "a new file took the place of the old one: it was not written in place"
    assert [entry.name for entry in store.path.parent.iterdir()] == ["credentials.json"]
    assert json.loads(store.path.read_text(encoding="utf-8")) == {
        "version": 1,
        "profiles": {
            "agent": {"api_key": AGENT_KEY, "base_url": OTHER_URL},
            "default": {"api_key": STORED_KEY, "base_url": BASE_URL, "project": PROJECT, "mcp_url": MCP_URL},
        },
    }
    assert store.read() == {
        "default": Profile(STORED_KEY, BASE_URL, PROJECT, MCP_URL),
        "agent": Profile(AGENT_KEY, OTHER_URL),
    }


def test_a_write_that_fails_leaves_the_old_file_and_no_other(
    store: CredentialStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    store.put("default", Profile(STORED_KEY, BASE_URL))
    before = store.path.read_bytes()

    def refuse(*_: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "fsync", refuse)
    with pytest.raises(UsageError, match="cannot be written") as raised:
        store.put("other", Profile(AGENT_KEY, OTHER_URL))
    assert AGENT_KEY not in str(raised.value)
    assert store.path.read_bytes() == before
    assert [entry.name for entry in store.path.parent.iterdir()] == ["credentials.json"]


def test_no_file_is_no_profile(store: CredentialStore) -> None:
    assert store.read() == {}
    assert store.get("default") is None
    assert store.remove("default") is False


def test_removing_the_last_profile_removes_the_file(store: CredentialStore) -> None:
    store.put("default", Profile(STORED_KEY, BASE_URL))
    store.put("other", Profile(STORED_KEY, OTHER_URL))
    assert store.remove("other") is True
    assert set(store.read()) == {"default"}
    assert store.remove("default") is True
    assert not store.path.exists()


@needs_posix
@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o660, 0o606, 0o601, 0o610])
def test_a_file_that_others_can_read_or_change_is_refused_and_not_repaired(store: CredentialStore, mode: int) -> None:
    store.put("default", Profile(STORED_KEY, BASE_URL))
    store.path.chmod(mode)
    with pytest.raises(UsageError) as raised:
        store.read()
    message = f"{raised.value.message} {raised.value.next_step}"
    assert f"mode {mode:04o}" in message
    assert "chmod 600" in message
    assert "revoked" in message, "a key that others could read has to be considered seen"
    assert STORED_KEY not in message
    assert mode_of(store.path) == mode, "the file is left as it was found"


@needs_posix
def test_where_modes_mean_nothing_they_are_neither_set_nor_judged(
    store: CredentialStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(credentials, "is_posix", lambda: False)
    store.path.parent.mkdir(parents=True)
    store.path.parent.chmod(0o755)
    store.put("default", Profile(STORED_KEY, BASE_URL))
    assert mode_of(store.path.parent) == 0o755, "no mode is forced on a system that has none"
    store.path.chmod(0o644)
    assert store.get("default") == Profile(STORED_KEY, BASE_URL)


@pytest.mark.parametrize(
    "content",
    [
        b"not json " + STORED_KEY.encode(),
        b"[]",
        b'{"version": 1}',
        b'{"version": 1, "profiles": []}',
        b'{"version": 1, "profiles": {"default": "' + STORED_KEY.encode() + b'"}}',
        b'{"version": 1, "profiles": {"default": {"api_key": "' + STORED_KEY.encode() + b'"}}}',
        b'{"version": 1, "profiles": {"default": {"api_key": "", "base_url": "https://acf.test"}}}',
        b'{"version": 1, "profiles": {"default": {"api_key": "k", "base_url": "u", "project": 7}}}',
        b'{"version": 1, "profiles": {"a": {"api_key": "k", "base_url": "u"}}}' + b" " * (1024 * 1024),
    ],
    ids=["not-json", "not-an-object", "no-profiles", "profiles-not-an-object", "profile-not-an-object", "no-address",
         "empty-key", "project-not-text", "too-large"],
)  # fmt: skip
def test_a_file_this_tool_did_not_write_is_refused_without_a_word_of_its_content(
    store: CredentialStore, content: bytes
) -> None:
    store.path.parent.mkdir(parents=True)
    store.path.write_bytes(content)
    store.path.chmod(0o600)
    with pytest.raises(UsageError, match="is not a credentials file of this tool") as raised:
        store.read()
    assert STORED_KEY not in f"{raised.value.message} {raised.value.next_step}"


def test_a_file_of_a_later_format_is_refused(store: CredentialStore) -> None:
    store.path.parent.mkdir(parents=True)
    store.path.write_text('{"version": 2, "profiles": {}}', encoding="utf-8")
    store.path.chmod(0o600)
    with pytest.raises(UsageError, match="a format this version of the tool does not know"):
        store.read()


def test_something_that_is_not_a_file_is_refused(store: CredentialStore) -> None:
    store.path.mkdir(parents=True)
    with pytest.raises(UsageError):
        store.read()


# ----------------------------------------------------------------------------------------- precedence
def test_a_flag_wins_over_the_environment_which_wins_over_the_profile(
    store: CredentialStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    store.put("default", Profile(STORED_KEY, "https://stored.acf.test", "prj_stored0000000000"))

    stored = credentials.resolve(base_url=None, project=None, profile=None, store=store)
    assert (stored.api_key, stored.base_url, stored.project) == (
        STORED_KEY,
        "https://stored.acf.test",
        "prj_stored0000000000",
    )
    assert stored.sources == {"key": "profile default", "address": "profile default", "project": "profile default"}

    monkeypatch.setenv("ACF_API_KEY", CANARY_KEY)
    monkeypatch.setenv("ACF_BASE_URL", "https://env.acf.test")
    monkeypatch.setenv("ACF_PROJECT", "prj_env0000000000000")
    env = credentials.resolve(base_url=None, project=None, profile=None, store=store)
    assert (env.api_key, env.base_url, env.project) == (CANARY_KEY, "https://env.acf.test", "prj_env0000000000000")
    assert env.sources["key"] == "the environment (ACF_API_KEY)"

    flags = credentials.resolve(
        base_url="https://flag.acf.test", project="prj_flag000000000000", profile=None, store=store
    )
    assert (flags.api_key, flags.base_url, flags.project) == (
        CANARY_KEY,
        "https://flag.acf.test",
        "prj_flag000000000000",
    )
    assert flags.sources == {
        "key": "the environment (ACF_API_KEY)",
        "address": "--base-url",
        "project": "--project",
    }


def test_each_value_is_resolved_on_its_own(store: CredentialStore, monkeypatch: pytest.MonkeyPatch) -> None:
    store.put("default", Profile(STORED_KEY, "https://stored.acf.test", "prj_stored0000000000"))
    monkeypatch.setenv("ACF_API_KEY", CANARY_KEY)
    settings = credentials.resolve(base_url=None, project=None, profile=None, store=store)
    assert settings.api_key == CANARY_KEY
    assert settings.base_url == "https://stored.acf.test"


def test_the_project_of_a_profile_goes_with_the_key_of_that_profile_only(
    store: CredentialStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A project belongs to a key. A key from the environment is asked for its own, not given the profile's."""
    store.put("default", Profile(STORED_KEY, "https://stored.acf.test", "prj_stored0000000000"))
    monkeypatch.setenv("ACF_API_KEY", CANARY_KEY)
    settings = credentials.resolve(base_url=None, project=None, profile=None, store=store)
    assert settings.project is None
    assert settings.sources["project"] == "the key itself, asked once"


def test_a_variable_set_to_nothing_is_not_set(store: CredentialStore, monkeypatch: pytest.MonkeyPatch) -> None:
    store.put("default", Profile(STORED_KEY, "https://stored.acf.test"))
    monkeypatch.setenv("ACF_API_KEY", "")
    monkeypatch.setenv("ACF_BASE_URL", "")
    settings = credentials.resolve(base_url=None, project=None, profile=None, store=store)
    assert (settings.api_key, settings.base_url) == (STORED_KEY, "https://stored.acf.test")


def test_the_profile_is_the_flag_then_the_environment_then_default(
    store: CredentialStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    store.put("default", Profile(STORED_KEY, "https://default.acf.test"))
    store.put("work", Profile(STORED_KEY, "https://work.acf.test"))
    store.put("lab", Profile(STORED_KEY, "https://lab.acf.test"))
    assert credentials.resolve(base_url=None, project=None, profile=None, store=store).base_url.startswith(
        "https://default"
    )
    monkeypatch.setenv("ACF_PROFILE", "work")
    assert credentials.resolve(base_url=None, project=None, profile=None, store=store).base_url.startswith(
        "https://work"
    )
    assert credentials.resolve(base_url=None, project=None, profile="lab", store=store).base_url.startswith(
        "https://lab"
    )


def test_a_profile_that_was_named_and_does_not_exist_is_an_error_and_the_default_one_is_not(
    store: CredentialStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(UsageError, match="there is no API key to use"):
        credentials.resolve(base_url=None, project=None, profile=None, store=store)
    with pytest.raises(UsageError, match="there is no profile work") as raised:
        credentials.resolve(base_url=None, project=None, profile="work", store=store)
    assert "acf auth login --profile work" in raised.value.next_step
    monkeypatch.setenv("ACF_API_KEY", CANARY_KEY)
    monkeypatch.setenv("ACF_BASE_URL", BASE_URL)
    monkeypatch.setenv("ACF_PROJECT", PROJECT)
    assert credentials.resolve(base_url=None, project=None, profile=None, store=store).api_key == CANARY_KEY


def test_the_file_is_not_touched_when_the_environment_says_everything(
    store: CredentialStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    store.path.parent.mkdir(parents=True)
    store.path.write_bytes(b"not a credentials file")
    monkeypatch.setenv("ACF_API_KEY", CANARY_KEY)
    monkeypatch.setenv("ACF_BASE_URL", BASE_URL)
    monkeypatch.setenv("ACF_PROJECT", PROJECT)
    assert credentials.resolve(base_url=None, project=None, profile=None, store=store).base_url == BASE_URL


def test_the_relay_takes_its_key_from_the_environment_or_the_profile_and_its_endpoint_from_three_places(
    store: CredentialStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    store.put("default", Profile(AGENT_KEY, BASE_URL, PROJECT, MCP_URL))
    stored = credentials.resolve_relay(endpoint=None, profile=None, store=store)
    assert stored == RelaySettings(AGENT_KEY, MCP_URL, BASE_URL)
    monkeypatch.setenv("ACF_MCP_URL", "https://env.acf.test/mcp")
    monkeypatch.setenv("ACF_API_KEY", CANARY_KEY)
    env = credentials.resolve_relay(endpoint=None, profile=None, store=store)
    assert (env.api_key, env.endpoint) == (CANARY_KEY, "https://env.acf.test/mcp")
    flag = credentials.resolve_relay(endpoint="https://flag.acf.test/mcp", profile=None, store=store)
    assert flag.endpoint == "https://flag.acf.test/mcp"


def test_the_relay_says_what_is_missing(store: CredentialStore, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(UsageError, match="there is no agent key to relay with") as raised:
        credentials.resolve_relay(endpoint=MCP_URL, profile=None, store=store)
    assert "acf auth agent-key create" in raised.value.next_step
    monkeypatch.setenv("ACF_API_KEY", AGENT_KEY)
    with pytest.raises(UsageError, match="the address of the platform's MCP endpoint is not known"):
        credentials.resolve_relay(endpoint=None, profile=None, store=store)
    assert credentials.resolve_relay(endpoint=MCP_URL, profile=None, store=store).base_url is None


def test_nothing_that_holds_a_key_shows_it(store: CredentialStore) -> None:
    for holder in (
        Profile(STORED_KEY, BASE_URL),
        Settings(STORED_KEY, BASE_URL, None, {}),
        RelaySettings(STORED_KEY, MCP_URL, None),
    ):
        assert STORED_KEY not in repr(holder)
        assert STORED_KEY not in str(holder)


@pytest.mark.parametrize("name", ["", "has space", "../escape", ".hidden", "x" * 65, "naïve"])
def test_a_profile_name_the_file_cannot_hold_is_refused(name: str) -> None:
    with pytest.raises(UsageError, match="a profile name is"):
        credentials.profile_name(name)


@pytest.mark.parametrize("name", ["default", "work-2", "a.b_c", "X" * 64])
def test_a_profile_name(name: str) -> None:
    assert credentials.profile_name(name) == name


@pytest.mark.parametrize(
    ("url", "complaint"),
    [
        ("http://acf.example/mcp", "must be https"),
        ("https://user:secret@acf.example/mcp", "must not carry user information"),
        ("https://acf.example/mcp?token=secret", "must not carry a query string"),
        ("https://acf.example/mcp#secret", "must not carry a query string or a fragment"),
        ("ftp://acf.example/mcp", "must be an https URL"),
        ("acf.example/mcp", "must be an https URL"),
        ("https:///mcp", "must be an https URL"),
        ("https://acf.example:port/mcp", "is not a URL this tool can read"),
    ],
)
def test_an_endpoint_a_key_may_not_be_sent_to_is_refused_without_repeating_it(url: str, complaint: str) -> None:
    with pytest.raises(UsageError, match=complaint) as raised:
        credentials.endpoint_address(url)
    assert "secret" not in f"{raised.value.message} {raised.value.next_step}"


@pytest.mark.parametrize(
    "url",
    ["https://acf.example/mcp", "http://localhost:8080/mcp", "http://127.0.0.1:8080/mcp", "http://[::1]:8080/mcp"],
)
def test_an_endpoint_a_key_may_be_sent_to(url: str) -> None:
    assert credentials.endpoint_address(url) == url


# ----------------------------------------------------------------------------------------- the commands
def test_a_command_runs_with_the_stored_profile_when_the_environment_says_nothing(cli: Cli) -> None:
    CredentialStore(cli.credentials_file).put("default", Profile(STORED_KEY, BASE_URL, PROJECT))
    run = cli.run(
        ["sandbox", "inspect", SBX, "--verbose"],
        ex("GET", f"/sandboxes/{SBX}", reply(200, sandbox())),
        env=NO_ENVIRONMENT,
        api_key=STORED_KEY,
    )
    assert run.exit_code == 0, run.stderr
    assert "acf: key: from profile default" in run.stderr
    assert STORED_KEY not in run.stdout + run.stderr


def test_flags_reach_the_client(cli: Cli) -> None:
    run = cli.run(
        ["sandbox", "inspect", SBX, "--base-url", OTHER_URL, "--project", "prj_0000000000000002", "--timeout", "2m"],
        ex("GET", f"/v1/projects/prj_0000000000000002/sandboxes/{SBX}", reply(200, sandbox())),
        base_url=OTHER_URL,
    )
    assert run.exit_code == 0, run.stderr
    settings, timeout = cli.clients[0]
    assert (settings.base_url, settings.project, timeout) == (OTHER_URL, "prj_0000000000000002", 120.0)


def test_without_a_project_the_key_is_asked_for_its_own_once(cli: Cli) -> None:
    run = cli.run(
        ["sandbox", "inspect", SBX],
        WHOAMI,
        ex("GET", f"/sandboxes/{SBX}", reply(200, sandbox())),
        env={"ACF_PROJECT": None},
    )
    assert run.exit_code == 0, run.stderr


@needs_posix
def test_a_command_refuses_a_credentials_file_that_others_can_read(cli: Cli) -> None:
    CredentialStore(cli.credentials_file).put("default", Profile(STORED_KEY, BASE_URL, PROJECT))
    cli.credentials_file.chmod(0o644)
    run = cli.run(["sandbox", "inspect", SBX], env=NO_ENVIRONMENT)
    assert run.exit_code == 2
    assert "can be read or changed by other users (mode 0644)" in run.stderr
    assert "chmod 600" in run.stderr.splitlines()[-1]
    assert STORED_KEY not in run.stderr
    assert run.requests == []


def test_there_is_no_option_that_takes_a_key(cli: Cli) -> None:
    for command in (["sandbox", "list"], ["auth", "login"], ["mcp"]):
        run = cli.run([*command, "--api-key", "x"])
        assert run.exit_code == 2
        assert "No such option" in run.stderr


# ----------------------------------------------------------------------------------------------- login
def typed(monkeypatch: pytest.MonkeyPatch, key: str) -> list[str]:
    """Stand in for the person at the keyboard. Returns the prompts they were shown."""
    prompts: list[str] = []

    def ask(prompt: str = "") -> str:
        prompts.append(prompt)
        return key

    monkeypatch.setattr(getpass, "getpass", ask)
    return prompts


def test_login_checks_the_key_stores_it_and_never_shows_it(cli: Cli, monkeypatch: pytest.MonkeyPatch) -> None:
    prompts = typed(monkeypatch, STORED_KEY)
    run = cli.run(
        ["auth", "login", "--base-url", BASE_URL], WHOAMI, env=NO_ENVIRONMENT, stdin_tty=True, api_key=STORED_KEY
    )
    assert run.exit_code == 0, run.stderr
    assert len(prompts) == 1
    assert STORED_KEY not in run.stdout + run.stderr
    assert PRINCIPAL in run.stdout
    assert PROJECT in run.stdout
    assert f"stored in {cli.credentials_file}, profile default" in run.stderr
    assert CredentialStore(cli.credentials_file).read() == {"default": Profile(STORED_KEY, BASE_URL, PROJECT)}


@needs_posix
def test_login_leaves_a_file_only_its_owner_can_read(cli: Cli, monkeypatch: pytest.MonkeyPatch) -> None:
    typed(monkeypatch, STORED_KEY)
    cli.run(["auth", "login", "--base-url", BASE_URL], WHOAMI, env=NO_ENVIRONMENT, stdin_tty=True, api_key=STORED_KEY)
    assert mode_of(cli.credentials_file) == 0o600
    assert mode_of(cli.credentials_file.parent) == 0o700


def test_login_reads_the_key_from_standard_input_when_asked(cli: Cli) -> None:
    run = cli.run(
        ["auth", "login", "--key-stdin", "--profile", "ci", "--json"],
        WHOAMI,
        env={"ACF_API_KEY": None},
        stdin=STORED_KEY.encode() + b"\n",
        api_key=STORED_KEY,
    )
    assert run.exit_code == 0, run.stderr
    assert run.json == whoami()
    assert STORED_KEY not in run.stdout + run.stderr
    assert CredentialStore(cli.credentials_file).get("ci") == Profile(STORED_KEY, BASE_URL, PROJECT)


def test_login_does_not_guess_where_the_key_comes_from(cli: Cli) -> None:
    run = cli.run(["auth", "login"], env={"ACF_API_KEY": None}, stdin=STORED_KEY.encode())
    assert run.exit_code == 2
    assert "there is no terminal to ask for the key" in run.stderr
    assert "--key-stdin" in run.stderr
    assert not cli.credentials_file.exists()


def test_login_does_not_take_the_key_of_the_environment_for_the_one_to_store(
    cli: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    typed(monkeypatch, STORED_KEY)
    run = cli.run(["auth", "login"], WHOAMI, stdin_tty=True, api_key=STORED_KEY)
    assert run.exit_code == 0, run.stderr
    assert CredentialStore(cli.credentials_file).get("default") == Profile(STORED_KEY, BASE_URL, PROJECT)


def test_login_stores_nothing_when_the_platform_does_not_know_the_key(
    cli: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    typed(monkeypatch, STORED_KEY)
    run = cli.run(
        ["auth", "login"], ex("GET", "/v1/auth/whoami", refusal("UNAUTHENTICATED")), stdin_tty=True, api_key=STORED_KEY
    )
    assert run.exit_code == 3
    assert STORED_KEY not in run.stdout + run.stderr
    assert not cli.credentials_file.exists()


def test_login_stores_nothing_for_a_key_of_another_project_than_the_one_named(
    cli: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    typed(monkeypatch, STORED_KEY)
    run = cli.run(["auth", "login", "--project", "prj_0000000000000002"], WHOAMI, stdin_tty=True, api_key=STORED_KEY)
    assert run.exit_code == 2
    assert f"this key belongs to project {PROJECT}" in run.stderr
    assert "Nothing was stored" in run.stderr
    assert "Nothing was sent" not in run.stderr, "the platform was asked who the key is"
    assert not cli.credentials_file.exists()


@pytest.mark.parametrize("given", [b"", b"   \n"])
def test_login_with_no_key_is_a_usage_error(cli: Cli, given: bytes) -> None:
    run = cli.run(["auth", "login", "--key-stdin"], stdin=given)
    assert run.exit_code == 2
    assert "no key was given" in run.stderr


def test_login_whose_prompt_is_closed_without_an_answer_is_a_usage_error(
    cli: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    def closed(prompt: str = "") -> str:
        raise EOFError

    monkeypatch.setattr(getpass, "getpass", closed)
    run = cli.run(["auth", "login"], stdin_tty=True)
    assert run.exit_code == 2
    assert "no key was given" in run.stderr
    assert "Traceback" not in run.stderr
    assert run.requests == []


@pytest.mark.parametrize(
    "key",
    [STORED_KEY + " and more", "cl\N{LATIN SMALL LETTER E WITH ACUTE}-" + "k" * 20],
    ids=["space", "not-ascii"],
)
def test_login_refuses_a_key_with_a_character_no_key_has_and_stores_nothing(cli: Cli, key: str) -> None:
    run = cli.run(["auth", "login", "--key-stdin"], stdin=key.encode(), api_key=key)
    assert run.exit_code == 2
    assert "holds a character no key has" in run.stderr
    assert run.requests == []
    assert not cli.credentials_file.exists()
    assert key not in run.stdout + run.stderr


# --------------------------------------------------------------------------------- whom to believe
@pytest.fixture
def authority(tmp_path: Path) -> Path:
    path = tmp_path / "authority.pem"
    path.write_text(authorities.ONE, encoding="ascii")
    return path


def test_the_authorities_come_from_the_environment_or_with_the_stored_address(
    store: CredentialStore, monkeypatch: pytest.MonkeyPatch, authority: Path, tmp_path: Path
) -> None:
    other = tmp_path / "other.pem"
    other.write_text(authorities.TWO, encoding="ascii")
    store.put("default", Profile(STORED_KEY, BASE_URL, PROJECT, None, str(authority)))

    stored = credentials.resolve(base_url=None, project=None, profile=None, store=store)
    assert stored.ca_file == str(authority)
    assert stored.sources["certificate authorities"] == "profile default"

    monkeypatch.setenv("ACF_CA_FILE", str(other))
    named = credentials.resolve(base_url=None, project=None, profile=None, store=store)
    assert named.ca_file == str(other)
    assert named.sources["certificate authorities"] == "the environment (ACF_CA_FILE)"


def test_stored_authorities_say_nothing_about_another_address(
    store: CredentialStore, monkeypatch: pytest.MonkeyPatch, authority: Path
) -> None:
    """They were named for the stored platform. For an address from a flag or the environment, the default applies."""
    store.put("default", Profile(STORED_KEY, BASE_URL, PROJECT, None, str(authority)))
    by_flag = credentials.resolve(base_url=OTHER_URL, project=None, profile=None, store=store)
    assert (by_flag.base_url, by_flag.ca_file) == (OTHER_URL, None)
    assert "certificate authorities" not in by_flag.sources
    monkeypatch.setenv("ACF_BASE_URL", OTHER_URL)
    by_environment = credentials.resolve(base_url=None, project=None, profile=None, store=store)
    assert (by_environment.base_url, by_environment.ca_file) == (OTHER_URL, None)


def test_without_any_authorities_named_nothing_is_said_about_them(store: CredentialStore) -> None:
    store.put("default", Profile(STORED_KEY, BASE_URL, PROJECT))
    settings = credentials.resolve(base_url=None, project=None, profile=None, store=store)
    assert settings.ca_file is None
    assert sorted(settings.sources) == ["address", "key", "project"]


@pytest.mark.parametrize("wrong", ["missing.pem", "a-directory", "line\nbreak.pem"])
def test_a_file_of_authorities_that_is_no_file_is_a_usage_error_and_never_passed_over(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, wrong: str
) -> None:
    if wrong == "a-directory":
        (tmp_path / wrong).mkdir()
    monkeypatch.setenv("ACF_API_KEY", CANARY_KEY)
    monkeypatch.setenv("ACF_BASE_URL", BASE_URL)
    monkeypatch.setenv("ACF_CA_FILE", str(tmp_path / wrong))
    with pytest.raises(UsageError, match="is not a file this user can read") as refused:
        credentials.resolve(base_url=None, project=None, profile=None)
    assert "ACF_CA_FILE" in (refused.value.next_step or "")


def test_a_relative_path_is_kept_absolute(monkeypatch: pytest.MonkeyPatch, authority: Path) -> None:
    """A stored relative path would name another file from another directory."""
    monkeypatch.chdir(authority.parent)
    assert credentials.ca_file_path(authority.name) == str(authority.resolve())


def test_the_client_a_command_builds_is_told_the_authorities_and_nothing_else_it_was_not_given(
    monkeypatch: pytest.MonkeyPatch, authority: Path
) -> None:
    built: list[dict[str, object]] = []

    class Recorded:
        def __init__(self, api_key: str, **options: object) -> None:
            built.append(options)

    monkeypatch.setattr(common, "Fabric", Recorded)
    common.new_fabric(Settings(CANARY_KEY, BASE_URL, None, {}), timeout=None)
    common.new_fabric(Settings(CANARY_KEY, BASE_URL, PROJECT, {}, str(authority)), timeout=30.0)
    assert built == [
        {"base_url": BASE_URL, "project": None},
        {"base_url": BASE_URL, "project": PROJECT, "timeout": 30.0, "ca_file": str(authority)},
    ]


def test_a_command_with_a_file_that_holds_no_certificate_is_refused_by_the_sdk_as_a_usage_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    words = tmp_path / "words.pem"
    words.write_text("no certificate here\n", encoding="ascii")
    with pytest.raises(Exception, match="ca_file is not a file of certificates") as refused:
        common.new_fabric(Settings(CANARY_KEY, BASE_URL, None, {}, str(words)), timeout=None)
    assert type(refused.value).__name__ == "ConfigurationError"


def test_login_stores_the_authorities_as_an_absolute_path_and_checks_the_key_with_them(
    cli: Cli, monkeypatch: pytest.MonkeyPatch, authority: Path
) -> None:
    monkeypatch.chdir(authority.parent)
    run = cli.run(
        ["auth", "login", "--key-stdin", "--ca-file", authority.name],
        WHOAMI,
        stdin=STORED_KEY.encode(),
        api_key=STORED_KEY,
    )
    assert run.exit_code == 0, run.stderr
    assert cli.clients[-1][0].ca_file == str(authority.resolve()), "the key was checked believing those authorities"
    stored = CredentialStore(cli.credentials_file).get("default")
    assert stored == Profile(STORED_KEY, BASE_URL, PROJECT, None, str(authority.resolve()))
    assert json.loads(cli.credentials_file.read_text())["profiles"]["default"]["ca_file"] == str(authority.resolve())


def test_login_keeps_the_authorities_for_the_same_platform_and_drops_them_for_another(
    cli: Cli, authority: Path
) -> None:
    login = ["auth", "login", "--key-stdin"]
    first = cli.run([*login, "--ca-file", str(authority)], WHOAMI, stdin=STORED_KEY.encode(), api_key=STORED_KEY)
    assert first.exit_code == 0, first.stderr
    store = CredentialStore(cli.credentials_file)

    again = cli.run(login, WHOAMI, stdin=STORED_KEY.encode(), api_key=STORED_KEY)
    assert again.exit_code == 0, again.stderr
    assert store.get("default") == Profile(STORED_KEY, BASE_URL, PROJECT, None, str(authority))

    moved = cli.run([*login, "--base-url", OTHER_URL], WHOAMI, stdin=STORED_KEY.encode(), api_key=STORED_KEY,
                    base_url=OTHER_URL)  # fmt: skip
    assert moved.exit_code == 0, moved.stderr
    assert store.get("default") == Profile(STORED_KEY, OTHER_URL, PROJECT), "another platform has other authorities"


def test_login_with_a_file_of_authorities_that_is_no_file_stores_nothing(cli: Cli, tmp_path: Path) -> None:
    run = cli.run(
        ["auth", "login", "--key-stdin", "--ca-file", str(tmp_path / "missing.pem")], stdin=STORED_KEY.encode()
    )
    assert run.exit_code == 2
    assert "is not a file this user can read" in run.stderr
    assert run.requests == []
    assert not cli.credentials_file.exists()


def test_a_command_uses_the_stored_authorities_of_the_profile_it_runs_with(cli: Cli, authority: Path) -> None:
    CredentialStore(cli.credentials_file).put("default", Profile(STORED_KEY, BASE_URL, PROJECT, None, str(authority)))
    run = cli.run(
        ["sandbox", "inspect", SBX, "--verbose"],
        ex("GET", f"/sandboxes/{SBX}", reply(200, sandbox())),
        env=NO_ENVIRONMENT,
        api_key=STORED_KEY,
    )
    assert run.exit_code == 0, run.stderr
    assert cli.clients[-1][0].ca_file == str(authority)
    assert "acf: certificate authorities: from profile default" in run.stderr
    assert str(authority) not in run.stdout


def test_login_needs_to_know_which_platform(cli: Cli) -> None:
    run = cli.run(["auth", "login", "--key-stdin"], env=NO_ENVIRONMENT, stdin=STORED_KEY.encode())
    assert run.exit_code == 2
    assert "the address of the platform is not known" in run.stderr


def test_login_stores_the_address_of_the_mcp_endpoint_and_keeps_it_for_the_same_platform(cli: Cli) -> None:
    login = ["auth", "login", "--key-stdin", "--profile", "agent"]
    first = cli.run([*login, "--mcp-url", MCP_URL], ex("GET", "/v1/auth/whoami", reply(200, whoami("agent"))),
                    stdin=AGENT_KEY.encode(), api_key=AGENT_KEY)  # fmt: skip
    assert first.exit_code == 0, first.stderr
    store = CredentialStore(cli.credentials_file)
    assert store.get("agent") == Profile(AGENT_KEY, BASE_URL, PROJECT, MCP_URL)

    again = cli.run(login, WHOAMI, stdin=STORED_KEY.encode(), api_key=STORED_KEY)
    assert again.exit_code == 0, again.stderr
    assert store.get("agent") == Profile(STORED_KEY, BASE_URL, PROJECT, MCP_URL), "a new key for the same platform"

    moved = cli.run([*login, "--base-url", OTHER_URL], WHOAMI, stdin=STORED_KEY.encode(), api_key=STORED_KEY,
                    base_url=OTHER_URL)  # fmt: skip
    assert moved.exit_code == 0, moved.stderr
    assert store.get("agent") == Profile(STORED_KEY, OTHER_URL, PROJECT), "another platform has another endpoint"


def test_login_refuses_an_mcp_address_a_key_may_not_be_sent_to(cli: Cli) -> None:
    run = cli.run(["auth", "login", "--key-stdin", "--mcp-url", "http://acf.example/mcp"], stdin=STORED_KEY.encode())
    assert run.exit_code == 2
    assert "must be https" in run.stderr
    assert not cli.credentials_file.exists()


@pytest.mark.parametrize("option", ["--mcp-url", "--base-url"])
def test_login_does_not_store_an_address_with_a_character_no_url_has(cli: Cli, option: str) -> None:
    address = (MCP_URL if option == "--mcp-url" else BASE_URL) + "\n"
    run = cli.run(["auth", "login", "--key-stdin", option, address], stdin=STORED_KEY.encode())
    assert run.exit_code == 2
    assert "holds a space, a line break or another character no URL has" in run.stderr
    assert run.requests == []
    assert not cli.credentials_file.exists()


def test_logout_removes_the_profile_and_says_that_the_key_is_still_valid(cli: Cli) -> None:
    store = CredentialStore(cli.credentials_file)
    store.put("default", Profile(STORED_KEY, BASE_URL))
    run = cli.run(["auth", "logout"])
    assert run.exit_code == 0
    assert "removed profile default" in run.stderr
    assert "still valid" in run.stderr
    assert store.read() == {}
    again = cli.run(["auth", "logout", "--profile", "work"])
    assert again.exit_code == 0
    assert "there is no profile work" in again.stderr
    assert STORED_KEY not in run.stdout + run.stderr
