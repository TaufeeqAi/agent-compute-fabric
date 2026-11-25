"""``acf-mcp``: the MCP adapter, as an edge process.

    acf-mcp --config <edge.yaml>

The configuration is the edge configuration that ``acf-api edge`` reads: where this process listens,
where the core's command socket is, the transport bounds, and the ``mcp`` section.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from acf_mcp import __version__


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="acf-mcp",
        description="The MCP adapter of Agent Compute Fabric: an edge process that relays MCP requests to the core.",
    )
    parser.add_argument("--version", action="version", version=f"acf-mcp {__version__}")
    parser.add_argument("--config", type=Path, required=True, help="the edge configuration file")
    args = parser.parse_args(argv)

    from acf_mcp import server  # noqa: PLC0415 - `--version` and `--help` answer without loading the HTTP stack

    return server.run(args.config)


if __name__ == "__main__":
    raise SystemExit(main())
