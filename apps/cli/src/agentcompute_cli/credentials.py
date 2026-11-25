"""Where a credential is kept on this machine, and which configuration a command runs with.

**The file.** ``$XDG_CONFIG_HOME/acf/credentials.json`` (``~/.config/acf/`` when the variable is not
set), and ``%APPDATA%\\acf\\credentials.json`` on Windows. It holds profiles, each a key and the address
it belongs to. On a POSIX system the file is created readable and writable by its owner only, in a
directory only the owner can enter, and it is replaced as a whole, never written in place: a reader sees
the old file or the new one. A file that other users can read or change is refused, not repaired: its
key has to be considered seen, and saying so is the only useful thing left to do.

**Precedence.** For each value: a flag, then the environment (``ACF_API_KEY``, ``ACF_BASE_URL``,
``ACF_PROJECT``), then the stored profile (``--profile``, else ``ACF_PROFILE``, else ``default``). There
is no flag for the key: a key on a command line ends up in shell history and in process listings. The
project of a profile is used only together with the key of that profile, because a project belongs to
a key; a key from the environment is asked for its own.

**Whom to believe.** A platform that somebody runs for themselves is usually certified by an authority
of their own. ``ACF_CA_FILE``, or the file ``acf auth login --ca-file`` stored with a profile, names a
PEM file of certificate authorities; with one, those are the only ones believed about the platform's
certificate. The stored file goes with the stored address, as the stored project goes with the stored
key: authorities that were named for one platform say nothing about another.

Nothing in this module prints, logs or raises a key.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import os
import re
import stat
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final
from urllib.parse import urlsplit

from agentcompute_cli.outcome import UsageError

__all__ = [
    "DEFAULT_PROFILE",
    "ENV_API_KEY",
    "ENV_BASE_URL",
    "ENV_CA_FILE",
    "ENV_MCP_URL",
    "ENV_PROFILE",
    "ENV_PROJECT",
    "CredentialStore",
    "Profile",
    "RelaySettings",
    "Settings",
    "api_address",
    "ca_file_path",
    "credentials_path",
    "endpoint_address",
    "environment",
    "is_posix",
    "is_windows",
    "profile_name",
    "resolve",
    "resolve_relay",
]

ENV_API_KEY: Final = "ACF_API_KEY"
ENV_BASE_URL: Final = "ACF_BASE_URL"
ENV_PROJECT: Final = "ACF_PROJECT"
ENV_PROFILE: Final = "ACF_PROFILE"
ENV_MCP_URL: Final = "ACF_MCP_URL"
ENV_CA_FILE: Final = "ACF_CA_FILE"
DEFAULT_PROFILE: Final = "default"

_DIRECTORY: Final = "acf"
_FILE: Final = "credentials.json"
_DIRECTORY_MODE: Final = 0o700
#: Every permission of the group and of everyone else.
_OTHERS: Final = 0o077
_FORMAT: Final = 1
#: Far more than any number of profiles needs. A larger file is not one this tool wrote.
_FILE_MAX: Final = 1024 * 1024
_PROFILE_NAME: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", re.ASCII)
_LOGIN: Final = "Store a key with `acf auth login`."


def is_posix() -> bool:
    """Whether file modes mean what they mean on a POSIX system."""
    return os.name == "posix"


def is_windows() -> bool:
    """Whether per-user application data lives under ``%APPDATA%``."""
    return os.name == "nt"


def credentials_path() -> Path:
    """The file the credentials of this user are kept in."""
    try:
        if is_windows():
            roaming = os.environ.get("APPDATA", "")
            base = Path(roaming) if roaming else Path.home() / "AppData" / "Roaming"
        else:
            # The base-directory specification says a relative path here is to be ignored.
            configured = Path(os.environ.get("XDG_CONFIG_HOME", ""))
            base = configured if configured.is_absolute() else Path.home() / ".config"
    except RuntimeError:
        raise UsageError(
            "the home directory of this user cannot be determined, so there is no place for stored credentials",
            next_step=f"Set {ENV_API_KEY} and {ENV_BASE_URL} instead.",
        ) from None
    return base / _DIRECTORY / _FILE


def profile_name(name: str) -> str:
    """A profile name the file can hold, or a usage error."""
    if _PROFILE_NAME.fullmatch(name) is None:
        raise UsageError("a profile name is 1 to 64 letters, digits, dots, hyphens or underscores, and starts with one")
    return name


def _is_this_machine(host: str) -> bool:
    """Whether a host is this machine, by its literal form. No name is resolved to find out."""
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _spelled(url: str, what: str) -> str:
    """The address, unless it holds a character no URL has: a space, a line break, anything that draws nothing.

    A parser that checks an address drops such a character without a word, and what sends the request
    does not: the address that was checked has to be the address that is used. It is refused and not
    tidied, because an address that was typed wrong is one nobody looked at.
    """
    if not url.isprintable() or " " in url:
        raise UsageError(f"{what} holds a space, a line break or another character no URL has")
    return url


def ca_file_path(named: str) -> str:
    """The file of certificate authorities somebody named, as an absolute path. A usage error if it is no file.

    Whether it holds a certificate is for whatever builds the connection to say. The path is kept
    absolute, because a relative one names another file from another directory.
    """
    refusal = UsageError(
        "the file of certificate authorities that was named is not a file this user can read",
        next_step=f"Check --ca-file, {ENV_CA_FILE} or the stored profile: each names a PEM file.",
    )
    if not named.isprintable():
        raise refusal
    try:
        path = Path(named).expanduser().resolve()
        with path.open("rb"):
            pass
    except (OSError, RuntimeError, ValueError):
        raise refusal from None
    if not path.is_file():
        raise refusal
    return str(path)


def api_address(url: str) -> str:
    """The address of the public API as it may be handed to the SDK, which checks everything else about it."""
    return _spelled(url, "the address of the platform")


def endpoint_address(url: str) -> str:
    """The address of the platform's MCP endpoint, if a key may be sent to it. The rules the SDK has for its own.

    No message from here repeats the address: an address that is refused may be one that holds a secret.
    """
    what = "the address of the MCP endpoint"
    _spelled(url, what)
    try:
        parts = urlsplit(url)
        host, _port = parts.hostname, parts.port
    except ValueError:
        raise UsageError(f"{what} is not a URL this tool can read") from None
    if parts.username is not None or parts.password is not None:
        raise UsageError(
            f"{what} must not carry user information: a credential is never accepted in a URL",
            next_step=f"Give the key through {ENV_API_KEY} or `acf auth login`.",
        )
    if "?" in url or "#" in url:
        raise UsageError(f"{what} must not carry a query string or a fragment: the endpoint takes neither")
    scheme = parts.scheme.lower()
    if not host or scheme not in {"http", "https"}:
        raise UsageError(f"{what} must be an https URL, for example https://acf.example/mcp")
    if scheme == "http" and not _is_this_machine(host):
        raise UsageError(
            f"{what} must be https: over plain http the key can be read by the network. "
            "Plain http is accepted for this machine only"
        )
    return url


@dataclass(frozen=True, slots=True)
class Profile:
    """One stored credential and the platform it belongs to. Its ``repr`` leaves the key out."""

    api_key: str = field(repr=False)
    base_url: str
    project: str | None = None
    #: The address of the platform's agent endpoint, for ``acf mcp``.
    mcp_url: str | None = None
    #: A PEM file of the only certificate authorities to believe about this platform. An absolute path.
    ca_file: str | None = None

    def to_json(self) -> dict[str, str]:
        members = {
            "api_key": self.api_key,
            "base_url": self.base_url,
            "project": self.project,
            "mcp_url": self.mcp_url,
            "ca_file": self.ca_file,
        }
        return {name: value for name, value in members.items() if value is not None}


def _profile(entry: object) -> Profile | None:
    if not isinstance(entry, dict):
        return None
    key, base_url = entry.get("api_key"), entry.get("base_url")
    project, mcp_url, ca_file = entry.get("project"), entry.get("mcp_url"), entry.get("ca_file")
    optional_are_text = all(value is None or isinstance(value, str) for value in (project, mcp_url, ca_file))
    if not isinstance(key, str) or not isinstance(base_url, str) or not key or not base_url or not optional_are_text:
        return None
    return Profile(key, base_url, project or None, mcp_url or None, ca_file or None)


class CredentialStore:
    """The credentials file of this user: read whole, replaced whole."""

    def __init__(self, path: Path | None = None) -> None:
        self.path: Final = path if path is not None else credentials_path()

    def _refused(self, why: str, *, next_step: str) -> UsageError:
        return UsageError(f"the credentials file {self.path} {why}", next_step=next_step)

    def _malformed(self) -> UsageError:
        return self._refused(
            "is not a credentials file of this tool",
            next_step="Remove it and run `acf auth login` again.",
        )

    def read(self) -> dict[str, Profile]:
        """Every stored profile. Empty when there is no file."""
        try:
            descriptor = os.open(self.path, os.O_RDONLY)
        except FileNotFoundError:
            return {}
        except OSError as error:
            raise self._refused(
                f"cannot be opened ({error.strerror or type(error).__name__})",
                next_step=f"Make it readable by you, or set {ENV_API_KEY} and {ENV_BASE_URL} instead.",
            ) from None
        try:
            # The file that was opened is the one that is judged: a file swapped in later cannot pass for it.
            status = os.fstat(descriptor)
            if not stat.S_ISREG(status.st_mode):
                raise self._malformed()
            mode = stat.S_IMODE(status.st_mode)
            if is_posix() and mode & _OTHERS:
                raise self._refused(
                    f"can be read or changed by other users (mode {mode:04o}). It holds a key, "
                    "which now has to be considered seen",
                    next_step=f"Have the key revoked, then run `chmod 600 {self.path}`, or remove the file, "
                    "and run `acf auth login` with a new key.",
                )
            data = b""
            while len(data) <= _FILE_MAX and (more := os.read(descriptor, _FILE_MAX + 1 - len(data))):
                data += more
        finally:
            os.close(descriptor)
        try:
            document = json.loads(data) if len(data) <= _FILE_MAX else None
        except (ValueError, RecursionError):
            # Never quoted: what could not be parsed may still hold a key.
            document = None
        if not isinstance(document, dict) or not isinstance(document.get("profiles"), dict):
            raise self._malformed()
        if document.get("version") != _FORMAT:
            raise self._refused(
                "has a format this version of the tool does not know",
                next_step="Use the version of the tool that wrote it, or remove it and run `acf auth login` again.",
            )
        profiles: dict[str, Profile] = {}
        for name, entry in document["profiles"].items():
            profile = _profile(entry)
            if profile is None:
                raise self._malformed()
            profiles[name] = profile
        return profiles

    def get(self, name: str) -> Profile | None:
        return self.read().get(name)

    def put(self, name: str, profile: Profile) -> None:
        """Store a profile, replacing the one of that name."""
        profiles = self.read()
        profiles[name] = profile
        self._replace(profiles)

    def remove(self, name: str) -> bool:
        """Remove a profile, and the file with the last one. Says whether there was such a profile."""
        profiles = self.read()
        if name not in profiles:
            return False
        del profiles[name]
        if profiles:
            self._replace(profiles)
        else:
            self.path.unlink()
        return True

    def _replace(self, profiles: Mapping[str, Profile]) -> None:
        document = {"version": _FORMAT, "profiles": {name: profile.to_json() for name, profile in profiles.items()}}
        data = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
        directory = self.path.parent
        try:
            directory.mkdir(mode=_DIRECTORY_MODE, parents=True, exist_ok=True)
            if is_posix():
                # Also when the directory was there already, with a wider mode than this file's home may have.
                directory.chmod(_DIRECTORY_MODE)
            # Created for the owner alone, under a name nothing else has. It becomes the file in one step.
            descriptor, temporary = tempfile.mkstemp(dir=directory, prefix=f".{_FILE}.", suffix=".tmp")
            try:
                with os.fdopen(descriptor, "wb") as file:
                    file.write(data)
                    file.flush()
                    os.fsync(file.fileno())
                os.replace(temporary, self.path)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(temporary)
                raise
        except OSError as error:
            raise self._refused(
                f"cannot be written ({error.strerror or type(error).__name__})",
                next_step=f"Make {directory} writable by you, or set {ENV_API_KEY} and {ENV_BASE_URL} instead.",
            ) from None


# --------------------------------------------------------------------------------------- configuration
@dataclass(frozen=True, slots=True)
class Settings:
    """What one command talks to the platform with. Its ``repr`` leaves the key out."""

    api_key: str = field(repr=False)
    base_url: str
    project: str | None
    #: Where each value came from, in words fit to be shown: never a value.
    sources: Mapping[str, str]
    #: A PEM file of the only certificate authorities to believe about the platform. ``None``: the default.
    ca_file: str | None = None


@dataclass(frozen=True, slots=True)
class RelaySettings:
    """What ``acf mcp`` runs with. Its ``repr`` leaves the key out."""

    api_key: str = field(repr=False)
    endpoint: str
    #: The address of the public API, when one is known: the key is checked there before the relay starts.
    base_url: str | None
    #: A PEM file of the only certificate authorities to believe about the platform. ``None``: the default.
    ca_file: str | None = None


def environment(name: str) -> str | None:
    """A variable of the environment. Set to nothing is the same as not set."""
    return os.environ.get(name) or None


class _Stored:
    """The stored profile of one command, read when a value is first asked of it and at most once."""

    def __init__(self, named: str | None, store: CredentialStore | None) -> None:
        self._named = named if named is not None else environment(ENV_PROFILE)
        if self._named is not None:
            # A name someone gave is checked whether or not the profile turns out to be needed.
            profile_name(self._named)
        self._store = store
        self._profile: Profile | None = None
        self._read = False

    @property
    def name(self) -> str:
        return self._named if self._named is not None else DEFAULT_PROFILE

    def profile(self) -> Profile | None:
        if not self._read:
            store = self._store if self._store is not None else CredentialStore()
            self._profile = store.get(self.name)
            self._read = True
            if self._profile is None and self._named is not None:
                raise UsageError(
                    f"there is no profile {self.name} in {store.path}",
                    next_step=f"Store one with `acf auth login --profile {self.name}`.",
                )
        return self._profile

    def source(self) -> str:
        return f"profile {self.name}"


def resolve(
    *,
    base_url: str | None,
    project: str | None,
    profile: str | None,
    store: CredentialStore | None = None,
) -> Settings:
    """The configuration of one command: a flag, then the environment, then the stored profile."""
    stored = _Stored(profile, store)
    sources: dict[str, str] = {}

    key = environment(ENV_API_KEY)
    key_is_stored = key is None
    if key is None:
        held = stored.profile()
        if held is None:
            raise UsageError("there is no API key to use", next_step=f"Set {ENV_API_KEY}, or: {_LOGIN}")
        key = held.api_key
        sources["key"] = stored.source()
    else:
        sources["key"] = f"the environment ({ENV_API_KEY})"

    address = base_url
    sources["address"] = "--base-url"
    if address is None:
        address = environment(ENV_BASE_URL)
        sources["address"] = f"the environment ({ENV_BASE_URL})"
    if address is None:
        held = stored.profile()
        if held is None:
            raise UsageError(
                "the address of the platform is not known",
                next_step=f"Pass --base-url, set {ENV_BASE_URL}, or: {_LOGIN}",
            )
        address = held.base_url
        sources["address"] = stored.source()
    api_address(address)

    authorities = environment(ENV_CA_FILE)
    if authorities is not None:
        sources["certificate authorities"] = f"the environment ({ENV_CA_FILE})"
    elif sources["address"] == stored.source():
        # The stored authorities were named for the stored address, and say nothing about another one.
        held = stored.profile()
        authorities = held.ca_file if held is not None else None
        if authorities is not None:
            sources["certificate authorities"] = stored.source()

    chosen = project
    sources["project"] = "--project"
    if chosen is None:
        chosen = environment(ENV_PROJECT)
        sources["project"] = f"the environment ({ENV_PROJECT})"
    if chosen is None and key_is_stored:
        held = stored.profile()
        chosen = held.project if held is not None else None
        sources["project"] = stored.source()
    if chosen is None:
        sources["project"] = "the key itself, asked once"
    return Settings(key, address, chosen, sources, None if authorities is None else ca_file_path(authorities))


def resolve_relay(*, endpoint: str | None, profile: str | None, store: CredentialStore | None = None) -> RelaySettings:
    """The configuration of ``acf mcp``: the key from the environment or the profile, never from a flag."""
    stored = _Stored(profile, store)
    mint = "Mint an agent key with `acf auth agent-key create --label NAME --lifetime 1h`"

    key = environment(ENV_API_KEY)
    if key is None:
        held = stored.profile()
        if held is None:
            raise UsageError(
                "there is no agent key to relay with",
                next_step=f"{mint}, and set {ENV_API_KEY} to it in the configuration of the agent host.",
            )
        key = held.api_key

    address = endpoint if endpoint is not None else environment(ENV_MCP_URL)
    endpoint_is_stored = False
    if address is None:
        held = stored.profile()
        address = held.mcp_url if held is not None else None
        endpoint_is_stored = address is not None
    if address is None:
        raise UsageError(
            "the address of the platform's MCP endpoint is not known",
            next_step=f"Pass --endpoint, set {ENV_MCP_URL}, or store it with `acf auth login --mcp-url URL`.",
        )

    base_url = environment(ENV_BASE_URL)
    if base_url is None:
        held = stored.profile()
        base_url = held.base_url if held is not None else None

    authorities = environment(ENV_CA_FILE)
    if authorities is None and endpoint_is_stored:
        held = stored.profile()
        authorities = held.ca_file if held is not None else None
    return RelaySettings(
        key,
        address,
        None if base_url is None else api_address(base_url),
        None if authorities is None else ca_file_path(authorities),
    )
