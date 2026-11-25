"""The edge process: an HTTP server over the REST adapter.

Transport bounds are set here, on the server, so that they hold before any of the adapter's code runs:
the number of connections, the size of a request's headers, and how long an idle connection is kept.
The body bound is the adapter's, because it must apply to a body that arrives in pieces.

An edge process must not be the core's identity and must not run as root. It is the process that reads
untrusted bytes; it is meant to hold nothing worth taking.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import uvicorn
from starlette.applications import Starlette

from acf_api.command.client import SocketCoreClient
from acf_api.edge.config import EXIT_CONFIG, EdgeConfig, EdgeConfigError, load_edge_config
from acf_api.edge.http.app import create_app

__all__ = ["EXIT_CONFIG", "build_app", "run", "server_config"]


def build_app(config: EdgeConfig) -> Starlette:
    core = SocketCoreClient(
        str(config.command_socket),
        max_in_flight=config.limits.edge_max_commands_in_flight,
        max_request_frame=config.limits.max_public_request_bytes * 2 + 64 * 1024,
    )
    return create_app(core, config.limits)


def server_config(app: Starlette, config: EdgeConfig) -> uvicorn.Config:
    """The server settings that carry the transport bounds of an edge process."""
    limits = config.limits
    return uvicorn.Config(
        app,
        host=config.listen.host,
        port=config.listen.port,
        ssl_certfile=str(config.tls.certificate) if config.tls is not None else None,
        ssl_keyfile=str(config.tls.private_key) if config.tls is not None else None,
        http="h11",
        h11_max_incomplete_event_size=limits.edge_max_header_bytes,
        limit_concurrency=limits.edge_max_connections,
        timeout_keep_alive=int(limits.keep_alive_timeout),
        # Nothing about the software is told to a caller, and no request line is logged by the server:
        # the adapter logs what may be logged.
        server_header=False,
        access_log=False,
        log_level=config.log_level.lower(),
        proxy_headers=False,
        lifespan="on",
    )


def run(config_path: Path) -> int:
    try:
        config = load_edge_config(config_path)
    except EdgeConfigError as e:
        logging.getLogger("acf_api.edge").error("%s", e)  # noqa: TRY400 - the message says what is wrong with the configuration; a traceback adds nothing
        return EXIT_CONFIG
    if os.geteuid() == 0:
        logging.getLogger("acf_api.edge").error("an edge process must not run as root")
        return EXIT_CONFIG
    uvicorn.Server(server_config(build_app(config), config)).run()
    return 0
