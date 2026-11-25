"""acf-mcp-gateway: the MCP adapter of Agent Compute Fabric.

An edge process. It frames messages of the Model Context Protocol and relays them to the core over the
command interface. It holds no host credential, no store and no secret but its TLS key, and every
decision and every tool semantic is the core's.
"""

__version__ = "0.3.0"
