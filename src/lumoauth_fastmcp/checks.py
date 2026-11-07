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

import base64
import json
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Union

from fastmcp.exceptions import AuthorizationError, InsufficientScopeError
from fastmcp.utilities.authorization import AuthCheck, AuthContext
from lumoauth.capabilities import any_capability_covers

from lumoauth_fastmcp._asgi import current_request_auth
from lumoauth_fastmcp.caller import current_caller, lumo_claims

__all__ = [
    "InsufficientAuthorizationDetailsError",
    "authorization_detail_covered",
    "build_authorization_detail",
    "capability_covered",
    "ensure_jit",
    "missing_authorization_details",
    "missing_scopes",
    "require_agent",
    "require_jit",
    "require_scopes",
    "require_user",
    "scope_covered",
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


def capability_covered(required: str, granted: Iterable[str]) -> bool:
    """LumoAuth's agent capability match (``AgentCapability::covers``).

    Capabilities compare in the form that the server stores: trimmed, ASCII
    letters in lower case, ``:`` and ``-`` read as ``.``. ``*`` covers
    everything, and ``users.*`` covers ``users.delete`` but not ``users``
    itself. The rules come from :func:`lumoauth.any_capability_covers`, so
    they match the server's contract cases. Entries of *granted* that are
    not strings are ignored.
    """
    return any_capability_covers(granted, required)


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


# ── JIT / RFC 9396 Rich Authorization Requests (RAR) ─────────────────


class InsufficientAuthorizationDetailsError(AuthorizationError):
    """Raised when a tool or route requires RFC 9396 ``authorization_details`` (JIT step-up).

    Matches LumoAuth's ``JitAuthorizationErrorSubscriber`` error format so
    self-escalating agents (via ``JITContext`` or ``agent.request_jit_permission``)
    can read ``required_details`` / ``header_value`` and request human approval.
    """

    error: str = "insufficient_authorization_details"

    def __init__(
        self,
        required_details: Sequence[Mapping[str, Any]],
        *,
        message: Optional[str] = None,
    ) -> None:
        self.required_details: List[Dict[str, Any]] = [dict(item) for item in required_details]
        hint_json = json.dumps(self.required_details, separators=(",", ":"))
        self.header_value: str = base64.b64encode(hint_json.encode("utf-8")).decode("ascii")
        if message is None:
            types = ", ".join(str(d.get("type") or "unknown") for d in self.required_details)
            message = (
                f"Authorization failed: insufficient_authorization_details "
                f"(required: {types}; authorization_details_hint={hint_json})"
            )
        super().__init__(message)

    def to_dict(self) -> Dict[str, Any]:
        """Structured RFC 9396 challenge body."""
        return {
            "error": self.error,
            "error_description": str(self),
            "authorization_details_hint": self.required_details,
            "Insufficient-Authorization-Details": self.header_value,
        }


def build_authorization_detail(
    type: str,
    *,
    actions: Optional[Iterable[str]] = None,
    locations: Optional[Iterable[str]] = None,
    identifier: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a normalized RFC 9396 ``authorization_details`` requirement entry."""
    if not isinstance(type, str) or not type.strip():
        raise ValueError("authorization_details 'type' must be a non-empty string")
    detail: Dict[str, Any] = {"type": type.strip()}
    if actions is not None:
        act_list = [str(a).strip() for a in actions if str(a).strip()]
        if act_list:
            detail["actions"] = act_list
    if locations is not None:
        loc_list = [str(loc).strip() for loc in locations if str(loc).strip()]
        if loc_list:
            detail["locations"] = loc_list
    if identifier is not None and str(identifier).strip():
        detail["identifier"] = str(identifier).strip()
    return detail


def _normalize_required_details(
    type_or_details: Union[str, Mapping[str, Any], Iterable[Mapping[str, Any]]],
    *,
    actions: Optional[Iterable[str]] = None,
    locations: Optional[Iterable[str]] = None,
    identifier: Optional[str] = None,
) -> List[Dict[str, Any]]:
    if isinstance(type_or_details, str):
        return [
            build_authorization_detail(
                type_or_details, actions=actions, locations=locations, identifier=identifier
            )
        ]
    if isinstance(type_or_details, Mapping):
        return [
            build_authorization_detail(
                str(type_or_details.get("type") or ""),
                actions=type_or_details.get("actions"),
                locations=type_or_details.get("locations"),
                identifier=type_or_details.get("identifier"),
            )
        ]
    result = [
        build_authorization_detail(
            str(item.get("type") or ""),
            actions=item.get("actions"),
            locations=item.get("locations"),
            identifier=item.get("identifier"),
        )
        for item in type_or_details
        if isinstance(item, Mapping)
    ]
    if not result:
        raise ValueError("require_jit() needs at least one authorization_details entry")
    return result


def _entry_covers(required: Mapping[str, Any], granted: Mapping[str, Any]) -> bool:
    req_type = required.get("type")
    grant_type = granted.get("type")
    if not isinstance(req_type, str) or grant_type not in (req_type, "*"):
        return False

    req_actions = required.get("actions")
    if isinstance(req_actions, list) and req_actions:
        grant_actions = granted.get("actions")
        if not isinstance(grant_actions, list):
            return False
        grant_set = {str(a) for a in grant_actions}
        if "*" not in grant_set and not all(str(a) in grant_set for a in req_actions):
            return False

    req_locations = required.get("locations")
    if isinstance(req_locations, list) and req_locations:
        grant_locations = granted.get("locations")
        if not isinstance(grant_locations, list):
            return False
        grant_loc_set = {str(loc) for loc in grant_locations}
        if "*" not in grant_loc_set and not all(str(loc) in grant_loc_set for loc in req_locations):
            return False

    req_id = required.get("identifier")
    if isinstance(req_id, str) and req_id:
        grant_id = granted.get("identifier")
        if grant_id not in (req_id, "*"):
            return False

    return True


def authorization_detail_covered(
    required: Mapping[str, Any], granted: Iterable[Mapping[str, Any]]
) -> bool:
    """``True`` when at least one entry in *granted* covers *required*."""
    return any(_entry_covers(required, entry) for entry in granted if isinstance(entry, Mapping))


def missing_authorization_details(
    required: Iterable[Mapping[str, Any]], granted: Iterable[Mapping[str, Any]]
) -> List[Dict[str, Any]]:
    """Return the entries of *required* that *granted* does not cover."""
    granted_list = [entry for entry in granted if isinstance(entry, Mapping)]
    return [dict(req) for req in required if not authorization_detail_covered(req, granted_list)]


def require_jit(
    type_or_details: Union[str, Mapping[str, Any], Iterable[Mapping[str, Any]]],
    *,
    actions: Optional[Iterable[str]] = None,
    locations: Optional[Iterable[str]] = None,
    identifier: Optional[str] = None,
) -> AuthCheck:
    """Require a task-bound JIT grant (RFC 9396 ``authorization_details``).

    When the caller's token (or ``X-LumoAuth-Jit-Token`` header) lacks a
    matching ``authorization_details`` entry, raises
    :class:`InsufficientAuthorizationDetailsError` with ``authorization_details_hint``.
    """
    required = _normalize_required_details(
        type_or_details, actions=actions, locations=locations, identifier=identifier
    )

    def check(ctx: AuthContext) -> bool:
        claims = lumo_claims(ctx.token)
        if claims is None:
            return False
        missing = missing_authorization_details(required, claims.authorization_details)
        if missing:
            err = InsufficientAuthorizationDetailsError(missing)
            state = current_request_auth.get()
            if state is not None:
                state.jit_failure = err
            raise err
        return True

    check.__name__ = f"require_jit({', '.join(d['type'] for d in required)})"
    setattr(check, "_lumo_jit_required", required)
    return check


def ensure_jit(
    type_or_details: Union[str, Mapping[str, Any], Iterable[Mapping[str, Any]]],
    *,
    actions: Optional[Iterable[str]] = None,
    locations: Optional[Iterable[str]] = None,
    identifier: Optional[str] = None,
    caller: Optional[Any] = None,
) -> None:
    """Verify inside a tool body that the current caller holds a JIT grant.

    Useful when ``identifier`` or ``locations`` depend on runtime tool arguments
    (for example ``ensure_jit("payment", actions=["refund"], identifier=invoice_id)``).
    """
    required = _normalize_required_details(
        type_or_details, actions=actions, locations=locations, identifier=identifier
    )
    claims = caller if caller is not None else current_caller()
    if claims is None:
        raise InsufficientAuthorizationDetailsError(required)
    missing = missing_authorization_details(required, claims.authorization_details)
    if missing:
        err = InsufficientAuthorizationDetailsError(missing)
        state = current_request_auth.get()
        if state is not None:
            state.jit_failure = err
        raise err
