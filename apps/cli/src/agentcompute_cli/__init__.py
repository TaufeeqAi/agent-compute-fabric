"""``acf``: the developer's command-line client of Agent Compute Fabric.

Every command but one is a call of the Python SDK (package ``agentcompute``): this package parses a
command line, makes the call, prints what the platform answered and picks an exit status. The one
exception is ``acf mcp``, which relays the agent protocol between standard input and output and the
platform's agent endpoint.

Nothing here decides what is allowed, what happened or whether to ask again: the platform decides the
first two, and the SDK the third.
"""

from agentcompute_cli._version import __version__

__all__ = ["__version__"]
