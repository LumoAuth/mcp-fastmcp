"""LumoAuth for FastMCP.

Protect a FastMCP server with LumoAuth in three lines::

    from fastmcp import FastMCP
    from lumoauth_fastmcp import LumoAuthProvider

    mcp = FastMCP("Invoices", auth=LumoAuthProvider())

Configuration comes from ``LUMOAUTH_ORG_ID`` and ``LUMOAUTH_MCP_SERVER_ID``;
the provider reads everything else from the server's registration.

Add LumoAuth's per-tool policy with ``middleware=[auth.tool_policy()]``,
scope and caller checks with ``require_scopes`` / ``require_agent`` /
``require_user``, and read the verified caller with ``current_caller()``.
"""

from lumoauth_fastmcp._registration import Registration
from lumoauth_fastmcp._resource import normalize_resource, same_resource
from lumoauth_fastmcp.caller import LumoAccessToken, current_caller, lumo_claims
from lumoauth_fastmcp.checks import (
    capability_covered,
    missing_scopes,
    require_agent,
    require_scopes,
    require_user,
    scope_covered,
)
from lumoauth_fastmcp.policy import ClientCredentialsToken, LumoToolPolicy
from lumoauth_fastmcp.provider import DEFAULT_LUMOAUTH_URL, LumoAuthProvider

__version__ = "1.0.0"

__all__ = [
    "DEFAULT_LUMOAUTH_URL",
    "ClientCredentialsToken",
    "LumoAccessToken",
    "LumoAuthProvider",
    "LumoToolPolicy",
    "Registration",
    "capability_covered",
    "current_caller",
    "lumo_claims",
    "missing_scopes",
    "normalize_resource",
    "require_agent",
    "require_scopes",
    "require_user",
    "same_resource",
    "scope_covered",
]
