"""Who is calling: the verified LumoAuth claims of the current request.

Inside a tool, resource or prompt::

    from lumoauth_fastmcp import current_caller

    @mcp.tool
    def list_invoices() -> list[dict]:
        caller = current_caller()
        if caller.is_agent:
            ...  # caller.agent_id is "agt_…"
        if caller.is_delegated:
            ...  # an agent acts for the user caller.sub; caller.actor names it

``current_caller()`` returns :class:`lumoauth.verify.AccessTokenClaims`, the
same object the LumoAuth Python SDK returns from ``verify_access_token``.
"""

from __future__ import annotations

from typing import Any, List, Mapping, Optional

from fastmcp.server.auth import AccessToken
from fastmcp.server.dependencies import get_access_token
from lumoauth.verify import AccessTokenClaims
from pydantic import PrivateAttr

__all__ = ["LumoAccessToken", "current_caller", "lumo_claims", "claims_from_payload"]


class LumoAccessToken(AccessToken):
    """A FastMCP access token that also carries the verified LumoAuth claims."""

    _lumo: Optional[AccessTokenClaims] = PrivateAttr(default=None)

    @classmethod
    def from_claims(
        cls,
        token: str,
        claims: AccessTokenClaims,
        *,
        resource: str,
        scopes: Optional[List[str]] = None,
    ) -> "LumoAccessToken":
        access_token = cls(
            token=token,
            # RFC 9068 client_id; agent tokens carry the agent id there.
            client_id=claims.client_id or claims.sub,
            scopes=list(claims.scopes) if scopes is None else scopes,
            expires_at=claims.exp,
            resource=resource,
            subject=claims.sub,
            claims=dict(claims.claims),
        )
        access_token._lumo = claims
        return access_token

    @property
    def lumo(self) -> AccessTokenClaims:
        """The verified LumoAuth claims."""
        if self._lumo is None:
            self._lumo = claims_from_payload(self.claims)
        return self._lumo


def _strings(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return tuple(part for part in value.split() if part)
    if isinstance(value, list):
        return tuple(item for item in value if isinstance(item, str) and item)
    return ()


def _int(value: Any) -> Optional[int]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value)


def claims_from_payload(payload: Mapping[str, Any]) -> AccessTokenClaims:
    """Rebuild :class:`AccessTokenClaims` from a payload that was already verified.

    FastMCP keeps the raw JWT claims on its ``AccessToken`` (for example
    across background-task serialization); this restores the LumoAuth view
    of them. It does not verify anything.
    """
    aud = payload.get("aud")
    act = payload.get("act")
    cnf = payload.get("cnf")
    jti = payload.get("jti")
    client_id = payload.get("client_id")
    token_use = payload.get("token_use")
    capabilities = payload.get("capabilities")
    return AccessTokenClaims(
        sub=str(payload.get("sub") or ""),
        iss=str(payload.get("iss") or ""),
        aud=(aud,) if isinstance(aud, str) else _strings(aud) if isinstance(aud, list) else (),
        exp=_int(payload.get("exp")) or 0,
        scopes=_strings(payload.get("scope")),
        is_agent=payload.get("is_agent") is True,
        capabilities=_strings(capabilities) if isinstance(capabilities, list) else (),
        jti=jti if isinstance(jti, str) else None,
        nbf=_int(payload.get("nbf")),
        iat=_int(payload.get("iat")),
        client_id=client_id if isinstance(client_id, str) else None,
        act=act if isinstance(act, dict) else None,
        cnf=cnf if isinstance(cnf, dict) else None,
        token_use=token_use if isinstance(token_use, str) else None,
        claims=dict(payload),
    )


def lumo_claims(token: Optional[AccessToken]) -> Optional[AccessTokenClaims]:
    """The LumoAuth claims of a FastMCP access token, or ``None`` without one."""
    if token is None:
        return None
    if isinstance(token, LumoAccessToken):
        return token.lumo
    return claims_from_payload(token.claims or {})


def current_caller() -> Optional[AccessTokenClaims]:
    """The verified caller of the current request, or ``None``.

    ``None`` means that the request carried no LumoAuth token, which only
    happens on transports without OAuth (stdio, in-memory clients).
    """
    return lumo_claims(get_access_token())
