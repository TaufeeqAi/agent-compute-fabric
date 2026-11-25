"""Assembly and life of the core process.

Start order, each step a precondition of the next. The core serves nothing before the last one:

1. read the configuration; a key the schema does not define, or a violated relation among the
   parameters, stops the start;
2. check that every secret and every file that decides whom the core believes is a trusted input, and
   that no edge identity could read a secret or open the store. Otherwise the core refuses to start;
3. open the security journal and verify its chain; open the store under its exclusive lock, check that
   it is the configured deployment and that the journal holds every record the store has applied, and
   take a new writer epoch;
4. replay the journal into the registry: every revocation is applied again, every scope stays used,
   every deleted project stays deleted. This runs on every start, so a restored store is never served
   before it has been brought up to the journal;
5. open the sockets; then run the first recovery pass, during which granting work is refused.

On a stop signal the core refuses new granting work, lets the requests in flight finish or bind within
``drain_timeout``, and exits. An entry that is still CLAIMED afterwards is resolved at the next start.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import yaml

from acf_api import supervisor
from acf_api.core import config as cfg
from acf_api.core.admin.commands import Admin
from acf_api.core.admin.server import AdminServer
from acf_api.core.agent.interaction import AgentInteraction
from acf_api.core.audit.sink import OutboxSink, drain
from acf_api.core.clock import Clock, SystemClock
from acf_api.core.host.binding import HostBinding, MtlsHostBinding, tls_context
from acf_api.core.identity.authenticator import Authenticator
from acf_api.core.identity.oauth import KeySet, TokenVerifier, file_fetcher, https_fetcher
from acf_api.core.pipeline import mapping
from acf_api.core.pipeline.fingerprint import FingerprintKey
from acf_api.core.pipeline.follower import Follower
from acf_api.core.pipeline.recovery import Recovery
from acf_api.core.pipeline.service import Deps, RuntimeService
from acf_api.core.pipeline.standing import Standing
from acf_api.core.policy import grants as g
from acf_api.core.policy.authorizer import Authorizer, GrantAuthorizer
from acf_api.core.server import CommandServer, SocketInUse
from acf_api.core.store import journal as j
from acf_api.core.store.engine import Store
from acf_api.core.store.ledger import Ledger
from acf_api.core.store.outbox import AuditOutbox
from acf_api.core.store.registry import Registry
from acf_api.core.telemetry import Telemetry, configure_logging

TEMPLATE_NAMES: Final = ("developer", "agent")
_AUDIT_DRAIN_INTERVAL_S: Final = 5.0


class StartupError(Exception):
    """The core cannot start. The message says which precondition failed."""


def load_templates(directory: Path) -> dict[str, g.EffectiveGrant]:
    """The grant templates the platform ships: ``developer`` and ``agent``."""
    templates: dict[str, g.EffectiveGrant] = {}
    for name in TEMPLATE_NAMES:
        path = directory / f"{name}.yaml"
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as e:
            raise StartupError(f"the grant template {path} cannot be read") from e
        try:
            templates[name] = g.parse(data)
        except g.GrantError as e:
            raise StartupError(f"the grant template {path} is not a valid grant: {e}") from e
    if g.widens(templates["agent"], templates["developer"]):
        raise StartupError("the `agent` template allows something the `developer` template does not")
    return templates


@dataclass(slots=True)
class Core:
    """A running core: everything a test or the process entry point needs a handle on."""

    config: cfg.CoreConfig
    store: Store
    journal: j.SecurityJournal
    service: RuntimeService
    agent: AgentInteraction
    recovery: Recovery
    admin: Admin
    outbox: AuditOutbox
    telemetry: Telemetry
    command_server: CommandServer | None = None
    admin_server: AdminServer | None = None
    tasks: list[asyncio.Task[None]] | None = None

    async def close(self) -> None:
        for task in self.tasks or []:
            task.cancel()
        for task in self.tasks or []:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        if self.command_server is not None:
            await self.command_server.close()
        if self.admin_server is not None:
            await self.admin_server.close()
        await self.service.d.follower.aclose()
        await self.service.d.binding.aclose()
        self.store.close()
        self.journal.close()


def _token_verifier(config: cfg.CoreConfig, clock: Clock) -> TokenVerifier | None:
    oauth, p = config.oauth, config.parameters
    if oauth is None:
        return None
    fetch = (
        file_fetcher(oauth.jwks_file)
        if oauth.jwks_file is not None
        else https_fetcher(str(oauth.jwks_uri), p.auth_deadline)
    )
    key_set = KeySet(
        fetch,
        clock,
        refresh_interval_s=p.jwks_refresh_interval,
        forced_min_interval_s=p.jwks_forced_refresh_min_interval,
    )
    return TokenVerifier(
        issuer=oauth.issuer,
        resource=oauth.resource,
        algorithms=list(oauth.algorithms),
        key_set=key_set,
        clock=clock,
        max_lifetime_s=p.oauth_token_max_lifetime,
    )


def resource_metadata_url(resource: str) -> str:
    """Where the protected-resource metadata of an endpoint is published (RFC 9728)."""
    scheme, _, rest = resource.partition("://")
    authority, _, path = rest.partition("/")
    return f"{scheme}://{authority}/.well-known/oauth-protected-resource" + (f"/{path}" if path else "")


async def build_core(  # noqa: PLR0912, PLR0915 - one core assembled in the order its parts need each other
    config: cfg.CoreConfig,
    *,
    binding: HostBinding | None = None,
    clock: Clock | None = None,
    authorizer: Authorizer | None = None,
    check_files: bool = True,
) -> Core:
    """Assemble a core over its store and journal, and replay the journal. Opens no socket.

    ``binding``, ``clock`` and ``authorizer`` are the seams tests use; a deployment passes none of them.
    """
    p = config.parameters
    clock = clock or SystemClock()
    telemetry = Telemetry()
    standing = Standing()

    if check_files:
        try:
            cfg.check_startup_files(config)
        except cfg.UntrustedInput as e:
            raise StartupError(f"not a trusted input: {e}") from e
    allowed = config.security.allow_shared_identity
    try:
        separation = cfg.check_separation(config)
        refusing = cfg.check_separation(config, shared_identity_allowed=allowed) if allowed else separation
    except cfg.ConfigError as e:
        raise StartupError(str(e)) from e
    if refusing:
        raise StartupError("the edge is not separated from what only the core may hold: " + "; ".join(refusing))
    if separation:
        # Only the shared identity is left, and the configuration admits it. It is said on every start.
        standing.shared_identity = True
        telemetry.diagnostic("edge_shares_core_identity")

    try:
        fingerprint = FingerprintKey.parse(config.paths.fingerprint_key.read_text(encoding="ascii"))
    except (OSError, ValueError) as e:
        raise StartupError(f"the fingerprint key cannot be used: {e}") from e
    templates = load_templates(config.paths.policies_dir)
    table = mapping.load_table()

    # The journal first: a store without its journal is never served.
    journal = j.SecurityJournal(config.paths.journal, config.paths.journal_mirror)
    try:
        records = journal.open(config.deployment_id)
    except j.JournalError as e:
        raise StartupError(str(e)) from e
    store = Store(
        config.paths.store_dir,
        deadline_s=p.store_deadline,
        audit_budget_bytes=p.audit_budget_bytes,
        reserve_bytes=p.store_reserve_bytes,
    )
    try:
        identity = store.open(config.deployment_id, journal_seq=journal.last_seq)
    except Exception as e:
        journal.close()
        raise StartupError(str(e)) from e

    registry = Registry(store, journal)
    ledger = Ledger(store)
    outbox = AuditOutbox(store)
    state = j.fold(records)
    # Whatever the store was restored to, it is brought up to the journal before anything is served.
    report = await registry.replay(state)
    if any(report[k] for k in ("revocations_reapplied", "bindings_reapplied", "deletions_reapplied")):
        telemetry.diagnostic(
            "journal_replayed_over_an_older_store", **{k: v for k, v in report.items() if k != "unknown_scopes"}
        )
    if report["unknown_scopes"]:
        # The host may still hold records under a scope the restored registry no longer knows.
        telemetry.diagnostic("scopes_unknown_to_the_registry", count=len(report["unknown_scopes"]))
    standing.pinned_lineage = state.lineage
    standing.pinned_peer_id = state.peer_id
    if state.lineage is not None:
        standing.sequence_high_water = await ledger.high_water(state.lineage)

    if binding is None:
        try:
            context = tls_context(
                trust_anchors=config.host.trust_anchors,
                certificate=config.host.certificate,
                private_key=config.host.private_key,
            )
        except (OSError, ValueError) as e:
            store.close()
            journal.close()
            raise StartupError(f"the host credential cannot be used: {type(e).__name__}") from e
        binding = MtlsHostBinding(
            address=config.host.address,
            host_id=config.host.host_id,
            context=context,
            max_connections=p.host_max_connections,
            reserved_containment=p.host_conn_reserved_containment,
            reserved_resolution=p.host_conn_reserved_resolution,
            connect_timeout_s=p.host_connect_timeout,
            read_timeout_s=p.host_call_wait + p.host_deadline_margin,
        )

    authenticator = Authenticator(
        registry,
        clock,
        token_verifier=_token_verifier(config, clock),
        containment_cache_ttl_s=p.containment_auth_cache_ttl,
        telemetry=telemetry,
        deadline_s=p.auth_deadline,
    )
    follower = Follower(
        binding,
        telemetry,
        interval_min_s=p.follow_poll_interval_min,
        interval_max_s=p.follow_poll_interval_max,
        reads_per_minute=p.reserved_reads_per_minute(),
    )
    deps = Deps(
        deployment_id=config.deployment_id,
        params=p,
        clock=clock,
        registry=registry,
        ledger=ledger,
        journal=journal,
        authenticator=authenticator,
        authorizer=authorizer or GrantAuthorizer(),
        binding=binding,
        table=table,
        fingerprint=fingerprint,
        audit=OutboxSink(outbox, telemetry),
        telemetry=telemetry,
        standing=standing,
        follower=follower,
        writer_epoch=identity.writer_epoch,
        templates=templates,
        resource_metadata_url=resource_metadata_url(config.oauth.resource) if config.oauth is not None else None,
        oauth_resource=config.oauth.resource if config.oauth is not None else None,
    )
    service = RuntimeService(deps)
    agent = AgentInteraction(service)
    service.agent = agent
    recovery = Recovery(service, outbox)
    admin = Admin(service, store, outbox, recovery)
    for project in await registry.projects():
        if project.share is not None:
            service.set_project_share(project.project_id, project.share)
    return Core(config, store, journal, service, agent, recovery, admin, outbox, telemetry)


async def _drain_audit(core: Core) -> None:
    sink = core.config.audit_sink
    if sink is None:
        return
    while True:
        await asyncio.sleep(_AUDIT_DRAIN_INTERVAL_S)
        with contextlib.suppress(Exception):
            while await drain(core.outbox, sink.file, core.telemetry):
                pass


async def start(core: Core) -> None:
    """Open the sockets and begin the first recovery pass. Granting work is refused until the pass is done."""
    config = core.config
    core.admin_server = AdminServer(core.admin, config.paths.admin_socket, core.telemetry)
    await core.admin_server.start()
    edge = cfg.resolve_edge(config.edge)
    core.command_server = CommandServer(
        core.service,
        config.paths.command_socket,
        allowed_uids=edge.uids,
        socket_gid=edge.socket_gid,
        telemetry=core.telemetry,
        max_request_frame=config.parameters.max_public_request_bytes * 2 + 64 * 1024,
    )
    await core.command_server.start()

    async def recover_then_maintain() -> None:
        totals = await core.recovery.startup_pass()
        core.telemetry.log(logging.INFO, "recovery_pass_done", **totals)
        await core.recovery.run()

    core.tasks = [
        asyncio.create_task(recover_then_maintain(), name="acf-recovery"),
        asyncio.create_task(_drain_audit(core), name="acf-audit-drain"),
    ]


async def run(config_path: Path) -> int:
    """The core process: start, serve until a stop signal, drain, stop."""
    try:
        config = cfg.load_config(config_path)
    except cfg.ConfigError as e:
        raise StartupError(str(e)) from e
    configure_logging(config.telemetry.log_level)
    core = await build_core(config)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    try:
        try:
            await start(core)
        except SocketInUse as e:
            # Another core answers on one of the sockets. That is a refusal for an operator to read and a
            # service manager not to retry, like every other precondition of a start.
            raise StartupError(str(e)) from e
        except OSError as e:
            raise StartupError(f"a socket of the core cannot be opened: {e}") from e
        core.telemetry.log(
            logging.INFO, "core_started", deployment_id=config.deployment_id, writer_epoch=core.service.d.writer_epoch
        )
        # Both sockets are served from here on. Granting work is still refused until the first recovery
        # pass is done; containment and reads are not, which is why readiness is announced now.
        supervisor.ready(f"deployment {config.deployment_id}, writer epoch {core.service.d.writer_epoch}")
        await stop.wait()
        supervisor.stopping()
        drained = await core.service.drain()
        core.telemetry.log(logging.INFO, "core_stopping", drained=drained)
    finally:
        await core.close()
    return 0
