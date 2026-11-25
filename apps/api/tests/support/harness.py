"""A real core over a temporary store and journal, with the model host and a clock tests can move.

Nothing here is a mock of the platform: the store is SQLite on disk, the journal is a file, the
pipeline is the pipeline. Only the host (the model) and time are replaced.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from acf_api.command import commands as c
from acf_api.command import model as m
from acf_api.command.answers import Answer, ClientInfo, ErrorAnswer, RequestContext, ToolAnswer, ViewAnswer
from acf_api.command.client import new_request_id
from acf_api.core import app
from acf_api.core import config as cfg
from acf_api.core.policy.authorizer import Authorizer
from acf_api.core.store import engine, journal
from tests.support.model_host import ModelHost

REPO = Path(__file__).resolve().parents[4]
POLICIES = REPO / "policies" / "defaults"
DEPLOYMENT = "dep_7Q2M9K4T1V8X3B6N"


class FakeClock:
    """A wall clock and a monotonic clock that move only when a test moves them."""

    def __init__(self, wall_ms: int = 1_800_000_000_000) -> None:
        self._wall = wall_ms
        self._mono = 1000.0

    def wall_ms(self) -> int:
        return self._wall

    def monotonic(self) -> float:
        return self._mono

    def advance(self, seconds: float) -> None:
        self._wall += int(seconds * 1000)
        self._mono += seconds

    def shift_wall(self, seconds: float) -> None:
        """Move the wall clock alone: what a clock that is wrong looks like."""
        self._wall += int(seconds * 1000)


def config_dict(root: Path, *, config_extra: dict[str, Any] | None = None, **parameters: Any) -> dict[str, Any]:
    secrets_dir = root / "secrets"
    return {
        **(config_extra or {}),
        "schema_version": 1,
        "deployment_id": DEPLOYMENT,
        "paths": {
            "store_dir": str(root / "store"),
            "journal": str(root / "journal" / "security.journal"),
            "fingerprint_key": str(secrets_dir / "fingerprint.key"),
            "command_socket": str(root / "run" / "command.sock"),
            "admin_socket": str(root / "run" / "admin.sock"),
            "policies_dir": str(POLICIES),
        },
        "edge": {"uids": [os.geteuid()]},
        "host": {
            "address": "127.0.0.1:1",
            "host_id": "host-model",
            "trust_anchors": str(secrets_dir / "ca.crt"),
            "certificate": str(secrets_dir / "platform.crt"),
            "private_key": str(secrets_dir / "platform.key"),
        },
        # The tests run the edge and the core as one user. A deployment never does.
        "security": {"allow_shared_identity": True},
        "parameters": {
            "follow_poll_interval_min": 0.01,
            "follow_poll_interval_max": 0.05,
            "public_wait_max": 2.0,
            "mcp_tool_wait": 1.0,
            "server_deadline_margin": 1.0,
            "edge_core_deadline_margin": 0.5,
            "sdk_request_timeout": 10.0,
            "claim_stale_after": 5.0,
            "host_resolve_attempts": 2,
            **parameters,
        },
    }


def create_deployment(root: Path, *, config_extra: dict[str, Any] | None = None, **parameters: Any) -> cfg.CoreConfig:
    """What ``acf-api init`` does: the fingerprint key, the journal and an empty store."""
    config = cfg.parse_config(config_dict(root, config_extra=config_extra, **parameters))
    key = config.paths.fingerprint_key
    key.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not key.exists():
        key.write_text(secrets.token_hex(32) + "\n", encoding="ascii")
        key.chmod(0o600)
    if not config.paths.journal.exists():
        journal.create_journal(config.paths.journal, config.deployment_id)
    if not (config.paths.store_dir / engine.STATE_FILE).exists():
        engine.create_store(config.paths.store_dir, config.deployment_id)
    return config


@dataclass
class Identity:
    """One developer of one project, as an operator would set it up."""

    project_id: str
    principal_id: str
    credential_id: str
    key: str
    scope: str


@dataclass
class Rig:
    """A running core with its model host and clock, and shortcuts for what tests do all the time."""

    root: Path
    config: cfg.CoreConfig
    core: app.Core
    host: ModelHost
    clock: FakeClock
    identities: list[Identity] = field(default_factory=list)
    config_extra: dict[str, Any] | None = None

    @property
    def service(self) -> Any:
        return self.core.service

    def ctx(self, *, interface: str = "rest", budget_s: float = 5.0) -> RequestContext:
        return RequestContext(
            request_id=new_request_id(),
            budget_ms=int(budget_s * 1000),
            interface=interface,  # type: ignore[arg-type]
            interface_version="v1" if interface == "rest" else "2026-07-28",
            client=ClientInfo(name="tests", version="0"),
        )

    async def admin(self, op: str, **args: Any) -> Any:
        return await self.core.admin.run(op, args)

    async def developer(self, label: str = "dev", *, template: str = "developer", grants: Any = None) -> Identity:
        project = await self.admin("project.create", label=f"{label}-project")
        assert project["state"] == "ACTIVE", project
        principal = await self.admin("principal.create", label=label)
        role: dict[str, Any] = {"principal_id": principal["principal_id"], "project_id": project["project_id"]}
        if grants is not None:
            role["grants"] = grants
        else:
            role["template"] = template
        await self.admin("role.set", **role)
        key = await self.admin("key.issue", principal_id=principal["principal_id"], project_id=project["project_id"])
        stored = await self.core.service.d.registry.project(project["project_id"])
        assert stored is not None
        identity = Identity(
            project["project_id"], principal["principal_id"], key["credential_id"], key["secret"], stored.scope
        )
        self.identities.append(identity)
        return identity

    async def call(
        self,
        who: Identity | str | None,
        command: c.Command,
        key: str | None = None,
        *,
        interface: str = "rest",
        budget_s: float = 5.0,
    ) -> Answer:
        credential = who.key if isinstance(who, Identity) else who
        return await self.core.service.handle(
            credential, self.ctx(interface=interface, budget_s=budget_s), command, key
        )

    async def view(
        self, who: Identity | str | None, command: c.Command, key: str | None = None, **kw: Any
    ) -> dict[str, Any]:
        answer = await self.call(who, command, key, **kw)
        assert isinstance(answer, ViewAnswer), getattr(answer, "error", answer)
        return answer.body

    async def error(
        self, who: Identity | str | None, command: c.Command, key: str | None = None, **kw: Any
    ) -> m.ErrorBody:
        answer = await self.call(who, command, key, **kw)
        assert isinstance(answer, ErrorAnswer), answer
        return answer.error

    async def tool(self, who: Identity | str, name: str, arguments: dict[str, Any] | None = None) -> ToolAnswer:
        answer = await self.call(who, c.CallTool(name=name, arguments=arguments or {}), interface="mcp")
        assert isinstance(answer, ToolAnswer), answer
        return answer

    async def mint_agent(
        self, who: Identity, label: str = "agent-1", *, lifetime: int = 3600, narrowing: Any = None
    ) -> dict[str, Any]:
        spec = m.MintAgentCredentialSpec.model_validate_json(
            __import__("json").dumps(
                {"label": label, "lifetime_seconds": lifetime, **({"narrowing": narrowing} if narrowing else {})}
            )
        )
        return await self.view(who, c.MintAgentCredential(project=who.project_id, spec=spec))

    async def close(self) -> None:
        await self.core.close()

    async def restart(self, *, recover: bool = True, **parameters: Any) -> Rig:
        """Stop the core and start another over the same store, journal, host and clock: a new writer epoch."""
        await self.core.close()
        self.host.closed = False
        fresh = await build_rig(
            self.root, host=self.host, clock=self.clock, recover=recover, config_extra=self.config_extra, **parameters
        )
        fresh.config_extra = self.config_extra
        fresh.identities = self.identities
        return fresh


def sandbox_spec(**overrides: Any) -> m.SandboxSpec:
    body: dict[str, Any] = {"image": "python", "resources": {"vcpus": 1, "memory_mib": 512, "disk_mib": 1024}}
    body.update(overrides)
    return m.SandboxSpec.model_validate_json(__import__("json").dumps(body))


async def build_rig(
    root: Path,
    *,
    host: ModelHost | None = None,
    clock: FakeClock | None = None,
    authorizer: Authorizer | None = None,
    recover: bool = True,
    config_extra: dict[str, Any] | None = None,
    **parameters: Any,
) -> Rig:
    clock = clock or FakeClock()
    host = host or ModelHost()
    host.now_ms = clock.wall_ms
    # The host does not advertise what it admits: an operator states it, and here the operator is the test.
    parameters.setdefault("host_max_sandboxes", host.max_sandboxes)
    config = create_deployment(root, config_extra=config_extra, **parameters)
    core = await app.build_core(config, binding=host, clock=clock, authorizer=authorizer, check_files=False)
    if recover:
        await core.recovery.startup_pass()
    return Rig(root, config, core, host, clock, config_extra=config_extra)
