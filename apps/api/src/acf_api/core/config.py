"""Configuration of the core, and the trusted-input rule for the files it depends on.

The configuration is one YAML file. A key the schema does not define is a startup failure, never a
warning: a setting that narrows what the platform does must not be silently ignored by a version that
does not know it.

Three files are secrets or decide whom the core believes: the host peer credential (a private key), the
fingerprint key and the trust anchors of the host. Each is a *trusted input*: a regular file, owned by
the core's own identity or by root, in directories nobody else can write, and for the two secrets
readable by nobody else. The core refuses to start otherwise. It also refuses to start when an edge
identity could read a secret or open the store, because the role that decodes caller bytes must hold
neither.
"""

from __future__ import annotations

import grp
import os
import pwd
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Final, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from acf_api.core.parameters import Parameters, violations

CONFIG_SCHEMA_VERSION: Final = 1
DEPLOYMENT_ID_PATTERN: Final = r"^dep_[0-9A-Za-z]{16,32}$"


class ConfigError(Exception):
    """The configuration cannot be used. The message names the setting, never a secret value."""


#: A path is written as text in the file, and that is the one conversion a configuration is given. Every
#: other value has to have the type of its setting: a number written as text, or a truth value written as
#: a number, is a mistake to report and never one to interpret.
FilePath = Annotated[Path, Field(strict=False)]


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class Paths(_Section):
    #: Directory of the interface store. Only the core's identity can open it.
    store_dir: FilePath
    #: The security journal: append-only, kept where a restore of the store never overwrites it.
    journal: FilePath
    #: Optional second copy of the journal, on the sink the operator chose.
    journal_mirror: FilePath | None = None
    #: Keys the digests of commands and arguments. Never in the store.
    fingerprint_key: FilePath
    command_socket: FilePath
    admin_socket: FilePath
    #: Directory with the grant templates `developer.yaml` and `agent.yaml`.
    policies_dir: FilePath


_ACCOUNT_NAME: Final = r"^[a-z_][a-z0-9_-]{0,30}\$?$"


class EdgeAccess(_Section):
    """Who may connect to the command socket: the operating-system identities of the edge processes.

    An identity is named (``users``) or numbered (``uids``). A name is looked up in the account database
    once, when the core starts; a name the database does not know stops the start.
    """

    users: list[Annotated[str, Field(pattern=_ACCOUNT_NAME)]] = Field(default_factory=list, max_length=16)
    uids: list[Annotated[int, Field(ge=0)]] = Field(default_factory=list, max_length=16)
    #: Group that owns the command socket, by name or by number. Neither: the core's own group.
    socket_group: Annotated[str, Field(pattern=_ACCOUNT_NAME)] | None = None
    socket_gid: Annotated[int, Field(ge=0)] | None = None


class HostEndpoint(_Section):
    """The one host this deployment binds, and how the platform proves itself to it."""

    #: `host:port` of the host's mutual-TLS endpoint.
    address: Annotated[str, Field(pattern=r"^[A-Za-z0-9.\-\[\]:]+:[0-9]{1,5}$")]
    #: The identity the host's certificate must carry. Also the value recorded with every ledger entry.
    host_id: Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")]
    #: The only authorities trusted to sign the host's certificate. The system store is never consulted.
    trust_anchors: FilePath
    certificate: FilePath
    private_key: FilePath


class OAuthConfig(_Section):
    """An external authorization server whose access tokens the agent interface accepts."""

    issuer: Annotated[str, Field(min_length=1, max_length=512, pattern=r"^https://")]
    #: The canonical URI of this deployment's agent endpoint: the audience every token must name.
    resource: Annotated[str, Field(min_length=1, max_length=512, pattern=r"^https://")]
    #: Where the issuer's key set is read: an `https://` URL or a local file.
    jwks_uri: Annotated[str, Field(pattern=r"^https://")] | None = None
    jwks_file: FilePath | None = None
    algorithms: list[Literal["ES256", "ES384", "RS256", "PS256", "EdDSA"]] = Field(
        default=["ES256", "RS256"], min_length=1
    )
    #: Scopes the deployment advertises in its protected-resource metadata.
    scopes_supported: list[Annotated[str, Field(pattern=r"^[\x21\x23-\x5b\x5d-\x7e]+$", max_length=64)]] = Field(
        default_factory=list, max_length=64
    )


class AuditSink(_Section):
    """Where audit records are delivered from the outbox: an append-only file the operator collects."""

    file: FilePath


class Security(_Section):
    #: Development only. Lets an edge run as the core's own operating-system identity. The core then says
    #: so through health on every start; the separation the deployment relies on does not hold. It admits
    #: that one thing: an edge account of its own that could read a secret, and an edge that runs as root,
    #: stop the start whatever this says.
    allow_shared_identity: bool = False


class Telemetry(_Section):
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    #: Version of the OpenTelemetry conventions for the agent protocol the spans follow. They are still
    #: in development status, so the version is pinned here rather than assumed.
    mcp_semconv: str = "development-2026-11"


class CoreConfig(_Section):
    schema_version: Literal[1]
    #: The deployment this core serves. The store must carry the same id, or the core refuses to serve.
    deployment_id: Annotated[str, Field(pattern=DEPLOYMENT_ID_PATTERN)]
    paths: Paths
    edge: EdgeAccess
    host: HostEndpoint
    oauth: OAuthConfig | None = None
    audit_sink: AuditSink | None = None
    security: Security = Field(default_factory=Security)
    telemetry: Telemetry = Field(default_factory=Telemetry)
    parameters: Parameters = Field(default_factory=Parameters)


def _load_yaml(path: Path) -> object:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise ConfigError(f"cannot read {path}: {e.strerror or type(e).__name__}") from e
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ConfigError(f"{path} is not valid YAML") from e


def _problems(e: ValidationError) -> str:
    """Where a configuration is wrong: locations and reasons, never the offending value."""
    return "; ".join(f"{'.'.join(str(p) for p in err['loc']) or '<root>'}: {err['msg']}" for err in e.errors())


def parse_config(data: object, *, source: str = "configuration") -> CoreConfig:
    if not isinstance(data, dict):
        raise ConfigError(f"{source} must be a mapping")
    try:
        config = CoreConfig.model_validate(data)
    except ValidationError as e:
        raise ConfigError(f"{source} is not valid: {_problems(e)}") from e
    broken = violations(config.parameters)
    if broken:
        raise ConfigError(f"{source} violates a relation among its parameters: " + "; ".join(broken))
    if config.oauth is not None and (config.oauth.jwks_uri is None) == (config.oauth.jwks_file is None):
        raise ConfigError(f"{source}: oauth needs exactly one of jwks_uri and jwks_file")
    if not config.edge.users and not config.edge.uids:
        raise ConfigError(f"{source}: edge names no identity; give edge.users or edge.uids")
    if config.edge.socket_group is not None and config.edge.socket_gid is not None:
        raise ConfigError(f"{source}: edge.socket_group and edge.socket_gid name the same thing; give one")
    return config


def load_config(path: Path) -> CoreConfig:
    return parse_config(_load_yaml(path), source=str(path))


# ------------------------------------------------------------------------------- trusted inputs
class UntrustedInput(Exception):
    """A file the core depends on is not a trusted input. The message says which rule failed."""


def _trusted_owner(uid: int) -> bool:
    return uid in {0, os.geteuid()}


def _check_ancestors(path: Path) -> None:
    for parent in path.resolve().parents:
        try:
            st = parent.stat()
        except OSError as e:
            raise UntrustedInput(f"{parent}: cannot be examined ({e.strerror})") from e
        if not _trusted_owner(st.st_uid):
            raise UntrustedInput(f"{parent}: owned by uid {st.st_uid}, which is neither this process nor root")
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise UntrustedInput(f"{parent}: writable by its group or by others")


def check_trusted_input(path: Path, *, secret: bool) -> None:
    """Raise :class:`UntrustedInput` unless ``path`` is a trusted input.

    ``secret``: the file must also be unreadable by its group and by others.
    """
    try:
        st = path.lstat()
    except OSError as e:
        raise UntrustedInput(f"{path}: cannot be examined ({e.strerror})") from e
    if stat.S_ISLNK(st.st_mode):
        raise UntrustedInput(f"{path}: is a symbolic link")
    if not stat.S_ISREG(st.st_mode):
        raise UntrustedInput(f"{path}: is not a regular file")
    if not _trusted_owner(st.st_uid):
        raise UntrustedInput(f"{path}: owned by uid {st.st_uid}, which is neither this process nor root")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise UntrustedInput(f"{path}: writable by its group or by others")
    if secret and st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise UntrustedInput(f"{path}: readable by its group or by others; a secret must be mode 0600 or 0400")
    _check_ancestors(path)


@dataclass(frozen=True, slots=True)
class EdgeIdentities:
    """The edge identities of a configuration, as the kernel will report them."""

    uids: frozenset[int]
    socket_gid: int | None


def resolve_edge(edge: EdgeAccess) -> EdgeIdentities:
    """Look the configured account names up. Raises :class:`ConfigError` for a name that does not exist."""
    uids = set(edge.uids)
    for name in edge.users:
        try:
            uids.add(pwd.getpwnam(name).pw_uid)
        except KeyError:
            raise ConfigError(f"edge.users names {name!r}, which is not an account of this machine") from None
    gid = edge.socket_gid
    if edge.socket_group is not None:
        try:
            gid = grp.getgrnam(edge.socket_group).gr_gid
        except KeyError:
            raise ConfigError(
                f"edge.socket_group names {edge.socket_group!r}, which is not a group of this machine"
            ) from None
    return EdgeIdentities(frozenset(uids), gid)


def groups_of(uid: int) -> frozenset[int]:
    """Every group the account database gives ``uid``. Empty for an id without an account."""
    try:
        account = pwd.getpwuid(uid)
    except KeyError:
        return frozenset()
    try:
        return frozenset(os.getgrouplist(account.pw_name, account.pw_gid))
    except OSError:
        return frozenset({account.pw_gid})


def could_read(path: Path, uid: int, gids: frozenset[int]) -> bool:
    """Whether an identity could open ``path`` for reading, by ownership and mode bits alone."""
    try:
        st = path.stat()
    except OSError:
        return False
    if uid == 0:
        return True
    if st.st_uid == uid:
        return bool(st.st_mode & stat.S_IRUSR)
    if st.st_gid in gids:
        return bool(st.st_mode & stat.S_IRGRP)
    return bool(st.st_mode & stat.S_IROTH)


def check_separation(config: CoreConfig, *, shared_identity_allowed: bool = False) -> list[str]:
    """Why the edge is not separated from what only the core may hold. Empty: the separation holds.

    Checked for every configured edge identity: it must not be the core's identity, and it must not be
    able to read the host private key, the fingerprint key, the store or the journal, by its own id or
    through any group the account database gives it.

    ``shared_identity_allowed``: leave out the one reason that ``security.allow_shared_identity`` admits,
    an edge that is the core itself. What is left then stops the start in any configuration.
    """
    reasons: list[str] = []
    me = os.geteuid()
    guarded = {
        "the host private key": config.host.private_key,
        "the fingerprint key": config.paths.fingerprint_key,
        "the store": config.paths.store_dir,
        "the security journal": config.paths.journal,
    }
    for uid in sorted(resolve_edge(config.edge).uids):
        if uid == me:
            if not shared_identity_allowed:
                reasons.append(f"edge uid {uid} is the core's own identity")
            continue
        if uid == 0:
            reasons.append("an edge process must not run as root")
            continue
        gids = groups_of(uid)
        for what, path in guarded.items():
            if could_read(path, uid, gids):
                reasons.append(f"edge uid {uid} could read {what} ({path})")
    return reasons


def check_startup_files(config: CoreConfig) -> None:
    """The trusted-input rule for every file that is a secret or decides whom the core believes."""
    check_trusted_input(config.host.private_key, secret=True)
    check_trusted_input(config.paths.fingerprint_key, secret=True)
    check_trusted_input(config.host.certificate, secret=False)
    check_trusted_input(config.host.trust_anchors, secret=False)
    if config.oauth is not None and config.oauth.jwks_file is not None:
        check_trusted_input(config.oauth.jwks_file, secret=False)
