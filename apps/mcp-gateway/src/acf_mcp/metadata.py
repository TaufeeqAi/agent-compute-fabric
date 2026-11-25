"""OAuth 2.0 Protected Resource Metadata (RFC 9728) for the MCP endpoint.

When an operator has configured an external authorization server, an MCP client learns where it is
from this document, which the core names in the ``resource_metadata`` parameter of its challenges. The
document is configuration and nothing more: it tells a client where to get a token. Whether a token is
accepted is decided by the core, which verifies its issuer, its audience and its subject binding. This
process verifies no token.
"""

from __future__ import annotations

import json
from typing import Final

from acf_api.edge.config import Mcp

WELL_KNOWN: Final = "/.well-known/oauth-protected-resource"


def metadata_path(resource: str) -> str:
    """The path at which the metadata of ``resource`` is published (RFC 9728, section 3.1).

    The well-known segment goes between the authority and the path of the resource identifier. This is
    the rule the core applies when it writes the document's address into a challenge; the two must give
    the same address, or a client is sent to a document that is not there.
    """
    _, _, rest = resource.partition("://")
    _, _, path = rest.partition("/")
    # A request path carries neither a query nor a fragment.
    path = path.split("?", 1)[0].split("#", 1)[0]
    return WELL_KNOWN + (f"/{path}" if path else "")


def metadata_document(mcp: Mcp) -> bytes:
    """The metadata document of the configured resource, as the bytes that are served."""
    document: dict[str, object] = {
        "resource": mcp.resource,
        "authorization_servers": list(mcp.authorization_servers),
        # A credential is read from the Authorization header and nowhere else.
        "bearer_methods_supported": ["header"],
    }
    if mcp.scopes_supported:
        document["scopes_supported"] = list(mcp.scopes_supported)
    return json.dumps(document, separators=(",", ":")).encode("ascii")
