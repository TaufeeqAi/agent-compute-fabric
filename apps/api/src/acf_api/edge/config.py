"""Configuration of an edge process.

An edge process holds nothing the system needs: no host credential, no store, no secret but its TLS
key. Its configuration says where it listens, where the core's command socket is, and the transport
bounds it enforces before it parses anything. Nothing here can name a principal, a project or a grant.

An unknown key is a startup failure.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Annotated, Final, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

#: Exit status of an edge process that cannot start as it is configured (``EX_CONFIG`` of sysexits.h).
#: Both edge programs use it, and the units do not restart on it: nothing changes until an operator
#: changes it.
EXIT_CONFIG: Final = 78


class EdgeConfigError(Exception):
    """The edge configuration cannot be used."""


#: A path is written as text in the file, and that is the one conversion a configuration is given. Every
#: other value has to have the type of its setting.
FilePath = Annotated[Path, Field(strict=False)]


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class Listen(_Section):
    host: str = "127.0.0.1"
    port: Annotated[int, Field(ge=1, le=65535)] = 8443


class Tls(_Section):
    certificate: FilePath
    private_key: FilePath


class Limits(_Section):
    """Transport bounds, per edge process. Bytes from a caller are bounded before they are parsed."""

    max_public_request_bytes: Annotated[int, Field(ge=1024, le=32 * 1024 * 1024)] = 1024 * 1024
    edge_max_connections: Annotated[int, Field(ge=1, le=1_000_000)] = 1024
    edge_max_header_bytes: Annotated[int, Field(ge=1024, le=1024 * 1024)] = 16 * 1024
    edge_max_commands_in_flight: Annotated[int, Field(ge=2, le=100_000)] = 256
    #: How long a public request waits for its operation. Must equal the core's value.
    public_wait_max: Annotated[float, Field(ge=0, le=3600)] = 30.0
    edge_core_deadline_margin: Annotated[float, Field(gt=0, le=600)] = 2.0
    #: Longest time one request body may take to arrive.
    body_read_timeout: Annotated[float, Field(gt=0, le=600)] = 20.0
    keep_alive_timeout: Annotated[float, Field(gt=0, le=600)] = 15.0


class Mcp(_Section):
    """Settings of the agent-protocol adapter. Read only by that adapter."""

    path: Annotated[str, Field(pattern=r"^/[A-Za-z0-9/_-]*$")] = "/mcp"
    #: Origins a browser may call from. An `Origin` that is present and not listed is refused with 403.
    allowed_origins: list[str] = Field(default_factory=list)
    #: `Host` values the endpoint answers to. Empty: the listen address and `localhost`.
    allowed_hosts: list[str] = Field(default_factory=list)
    #: The canonical URI of this endpoint, when an external authorization server is configured in the core.
    resource: Annotated[str, Field(pattern=r"^https://")] | None = None
    authorization_servers: list[Annotated[str, Field(pattern=r"^https://")]] = Field(default_factory=list)
    scopes_supported: list[str] = Field(default_factory=list)
    #: Must equal the core's value. The core decides; this only selects which transport shapes are parsed.
    serve_2025_11_25: bool = False
    tool_wait: Annotated[float, Field(ge=0, le=3600)] = 25.0


class EdgeConfig(_Section):
    schema_version: Literal[1]
    listen: Listen = Field(default_factory=Listen)
    #: Without TLS the edge listens on loopback only, for a TLS-terminating proxy on the same machine.
    tls: Tls | None = None
    command_socket: FilePath
    limits: Limits = Field(default_factory=Limits)
    mcp: Mcp = Field(default_factory=Mcp)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def parse_edge_config(data: object, *, source: str = "edge configuration") -> EdgeConfig:
    if not isinstance(data, dict):
        raise EdgeConfigError(f"{source} must be a mapping")
    try:
        config = EdgeConfig.model_validate(data)
    except ValidationError as e:
        where = "; ".join(f"{'.'.join(str(p) for p in err['loc']) or '<root>'}: {err['msg']}" for err in e.errors())
        raise EdgeConfigError(f"{source} is not valid: {where}") from e
    if config.tls is None and not is_loopback(config.listen.host):
        raise EdgeConfigError(f"{source}: without `tls` the edge listens on a loopback address only")
    return config


def load_edge_config(path: Path) -> EdgeConfig:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as e:
        raise EdgeConfigError(f"cannot read {path}: {e.strerror or type(e).__name__}") from e
    except yaml.YAMLError as e:
        raise EdgeConfigError(f"{path} is not valid YAML") from e
    return parse_edge_config(data, source=str(path))
