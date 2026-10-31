"""Authorization checks for FastMCP components, with LumoAuth semantics.

They plug into FastMCP's ``auth=`` argument of ``@mcp.tool`` /
``@mcp.resource`` / ``@mcp.prompt`` and into ``AuthMiddleware``::

    from fastmcp.server.middleware import AuthMiddleware
    from lumoauth_fastmcp import require_scopes, require_agent

    @mcp.tool(auth=require_scopes("invoices:refund"))
    def refund(invoice_id: str) -> str: ...

    mcp = FastMCP(..., middleware=[AuthMiddleware(auth=require_scopes("mcp:read"))])

Differences from FastMCP's own ``require_scopes``:

- LumoAuth's one wildcard rule applies: a granted scope that ends in
  ``:*`` covers the scopes under that prefix (``invoices:*`` covers
  ``invoices:refund`` and ``invoices:refund:partial``). Every other scope
  compares exactly, so ``invoices.*`` is an ordinary scope. Prefer narrow
  scopes: the MCP security best practices list wildcard scopes as a
  common mistake.
- A shortfall raises :class:`fastmcp.exceptions.InsufficientScopeError`
  naming the missing scopes. Through ``AuthMiddleware`` that becomes an
  ``insufficient_scope`` step-up; as a component-level ``auth=`` check,
  FastMCP hides the component instead.
"""

from __future__ import annotations

from typing import Iterable, List

from fastmcp.exceptions import InsufficientScopeError
from fastmcp.utilities.authorization import AuthCheck, AuthContext

from lumoauth_fastmcp.caller import lumo_claims

__all__ = [
    "scope_covered",
    "missing_scopes",
    "capability_covered",
    "require_scopes",
    "require_agent",
    "require_user",
]

def scope_covered(required: str, granted: Iterable[str]) -> bool:
    """``True`` when *required* is granted exactly or by a ``prefix:*`` scope.

    The same rule as LumoAuth's ``McpAuthorizationController::scopeCovered``.
    """
    for scope in granted:
        if scope == required:
            return True
        if scope.endswith(":*"):
            prefix = scope[:-1]  # keeps the trailing ':'
            if prefix != ":" and required.startswith(prefix) and len(required) > len(prefix):
                return True
    return False


def missing_scopes(required: Iterable[str], granted: Iterable[str]) -> List[str]:
    """The entries of *required* that *granted* does not cover, in order."""
    granted_list = list(granted)
    return [scope for scope in required if not scope_covered(scope, granted_list)]


def _normalize_capability(capability: str) -> str:
    normalized = capability.strip().lower().replace(":", ".").replace("-", ".")
    while ".." in normalized:
        normalized = normalized.replace("..", ".")
    return normalized.strip(".")


def capability_covered(required: str, granted: Iterable[str]) -> bool:
    """LumoAuth's agent capability match (``AgentCapability::covers``).

    Capabilities compare in canonical form (lower case, ``:`` and ``-`` read
    as ``.``); ``*`` covers everything and ``users.*`` covers ``users.delete``
    but not ``users`` itself.
    """
    wanted = _normalize_capability(required)
    if not wanted:
        return False
    for capability in granted:
        have = _normalize_capability(capability)
        if not have:
            continue
        if have == "*" or have == wanted:
            return True
        if have.endswith(".*") and wanted.startswith(have[:-1]):
            return True
    return False


def require_scopes(*scopes: str) -> AuthCheck:
    """Require every listed scope; wildcards in the token count."""
    if not scopes:
        raise ValueError("require_scopes() needs at least one scope")
    required = tuple(scopes)

    def check(ctx: AuthContext) -> bool:
        if ctx.token is None:
            return False
        missing = missing_scopes(required, ctx.token.scopes)
        if missing:
            raise InsufficientScopeError(missing)
        return True

    check.__name__ = f"require_scopes({', '.join(required)})"
    return check


def require_agent(*capabilities: str) -> AuthCheck:
    """Admit only AI agents (``is_agent`` tokens) holding every listed capability."""
    required = tuple(capabilities)

    def check(ctx: AuthContext) -> bool:
        claims = lumo_claims(ctx.token)
        if claims is None or not claims.is_agent:
            return False
        return all(capability_covered(c, claims.capabilities) for c in required)

    check.__name__ = f"require_agent({', '.join(required)})"
    return check


def require_user(*, allow_delegation: bool = False) -> AuthCheck:
    """Admit only human users.

    Args:
        allow_delegation: Also admit an agent that acts for a user (the
            token's ``sub`` is the user and ``act`` names the agent).
    """

    def check(ctx: AuthContext) -> bool:
        claims = lumo_claims(ctx.token)
        if claims is None or claims.is_agent:
            return False
        return allow_delegation or not claims.is_delegated

    check.__name__ = "require_user()"
    return check
