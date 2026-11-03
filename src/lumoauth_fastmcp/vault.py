"""Token Vault helper for FastMCP tools.

Most MCP tools call an upstream SaaS API (Slack, GitHub, Google Workspace,
Jira, Salesforce). LumoAuth's Token Vault holds encrypted refresh tokens in
custody and mints short-lived outbound access tokens via
``POST /orgs/{org}/api/v1/agents/me/connections/{connection_id}/token``.

Inside a FastMCP tool::

    @mcp.tool
    def create_issue(repo: str, title: str) -> dict:
        gh = auth.vault_token("conn_github_prod")
        # gh.access_token is a short-lived GitHub token; when the MCP caller is
        # a user or a user-delegated agent, user_id=caller.sub is passed automatically!
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests
from lumoauth import LumoAuth
from lumoauth.errors import (
    LumoAuthApiError,
    LumoAuthAuthenticationError,
    LumoAuthConfigError,
    LumoAuthNetworkError,
    LumoAuthNotFoundError,
    LumoAuthPermissionDeniedError,
    LumoAuthValidationError,
)
from lumoauth.verify import AccessTokenClaims

from lumoauth_fastmcp._asgi import current_traceparent
from lumoauth_fastmcp.caller import current_caller
from lumoauth_fastmcp.policy import ClientCredentialsToken

__all__ = ["VaultToken", "LumoVaultClient", "resolve_vault_user_id"]


@dataclass(frozen=True)
class VaultToken:
    """Short-lived outbound OAuth access token minted by LumoAuth's Token Vault."""

    access_token: str
    token_type: str = "Bearer"
    expires_at: Optional[str] = None
    scopes: Tuple[str, ...] = ()
    connection_id: Optional[str] = None
    user_id: Optional[str] = None

    def __str__(self) -> str:
        return self.access_token

    def headers(self) -> Dict[str, str]:
        """Authorization header dictionary for outbound requests."""
        return {"Authorization": f"{self.token_type} {self.access_token}"}


def resolve_vault_user_id(
    caller: Optional[AccessTokenClaims],
    explicit_user_id: Optional[str] = None,
) -> Optional[str]:
    """Determine the ``user_id`` to request from the Token Vault.

    - If *explicit_user_id* is provided, returns it.
    - If *caller* is a human user (``not caller.is_agent``) or a user-delegated
      agent (``caller.is_delegated`` where ``caller.sub`` is the user and
      ``caller.actor`` is the agent), returns ``caller.sub``.
    - If *caller* is an autonomous agent, returns ``None``.
    """
    if explicit_user_id is not None:
        cleaned = explicit_user_id.strip()
        return cleaned or None
    if caller is None:
        return None
    if not caller.is_agent or caller.is_delegated:
        return caller.sub or None
    return None


def _parse_expiry_epoch(expires_at: Optional[str], default_ttl: float) -> float:
    if isinstance(expires_at, str) and expires_at.strip():
        text = expires_at.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            remaining = dt.timestamp() - time.time()
            # Keep a 30-second safety margin before actual token expiry.
            return time.monotonic() + max(0.0, remaining - 30.0)
        except ValueError:
            pass
    return time.monotonic() + max(0.0, default_ttl)


class LumoVaultClient:
    """Client for retrieving outbound SaaS tokens from LumoAuth's Token Vault."""

    def __init__(
        self,
        *,
        issuer: str,
        agent_token: Optional[str] = None,
        token_provider: Optional[Callable[[], str]] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        org_id: Optional[str] = None,
        lumoauth_url: Optional[str] = None,
        cache_ttl: float = 60.0,
        verify_tls: bool = True,
        request_fn: Optional[Callable[[str, str, Dict[str, str], Optional[Dict[str, Any]]], Any]] = None,
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.cache_ttl = cache_ttl
        self._verify_tls = verify_tls
        self._request_fn = request_fn
        self._tokens_helper: Optional[ClientCredentialsToken] = None

        if token_provider is not None:
            self._token_provider = token_provider
        elif agent_token:
            self._token_provider = lambda: agent_token
        elif client_id and client_secret and org_id:
            self._tokens_helper = ClientCredentialsToken(
                LumoAuth(base_url=lumoauth_url, org_id=org_id),
                client_id,
                client_secret,
                scopes=("vault:token", "mcp:authorize"),
            )
            self._token_provider = self._tokens_helper
        else:
            raise LumoAuthConfigError(
                "Token Vault access requires an agent token (agent_token= or LUMOAUTH_AGENT_TOKEN) "
                "or MCP client credentials (LUMOAUTH_MCP_CLIENT_ID and LUMOAUTH_MCP_CLIENT_SECRET)."
            )

        self._cache: Dict[Tuple[str, str], Tuple[float, VaultToken]] = {}
        self._lock = threading.Lock()

    def get_token(
        self,
        connection_id: str,
        *,
        user_id: Optional[str] = None,
        caller: Optional[AccessTokenClaims] = None,
        traceparent: Optional[str] = None,
    ) -> VaultToken:
        """Fetch a short-lived outbound token for *connection_id* from the Token Vault."""
        if not isinstance(connection_id, str) or not connection_id.strip():
            raise LumoAuthValidationError("connection_id is required")
        conn = connection_id.strip()

        active_caller = caller if caller is not None else current_caller()
        resolved_user = resolve_vault_user_id(active_caller, user_id)
        cache_key = (conn, resolved_user or "")

        if self.cache_ttl > 0:
            with self._lock:
                cached = self._cache.get(cache_key)
                if cached is not None:
                    expires_mono, token_obj = cached
                    if time.monotonic() < expires_mono:
                        return token_obj
                    del self._cache[cache_key]

        tp = (
            traceparent
            or (active_caller.traceparent if active_caller is not None else None)
            or current_traceparent()
        )
        url = f"{self.issuer}/agents/me/connections/{conn}/token"
        payload: Dict[str, Any] = {"user_id": resolved_user} if resolved_user else {}

        body = self._send("POST", url, payload, traceparent=tp)
        if not isinstance(body, dict) or not isinstance(body.get("access_token"), str):
            raise LumoAuthValidationError("unexpected Token Vault response from LumoAuth")

        raw_scopes = body.get("scopes")
        scopes: Tuple[str, ...] = ()
        if isinstance(raw_scopes, list):
            scopes = tuple(str(s) for s in raw_scopes if isinstance(s, str) and s)
        elif isinstance(raw_scopes, str):
            scopes = tuple(s for s in raw_scopes.split() if s)

        expires_at = body.get("expires_at") if isinstance(body.get("expires_at"), str) else None
        vault_token = VaultToken(
            access_token=body["access_token"],
            token_type=str(body.get("token_type") or "Bearer"),
            expires_at=expires_at,
            scopes=scopes,
            connection_id=conn,
            user_id=resolved_user,
        )

        if self.cache_ttl > 0:
            expiry_mono = _parse_expiry_epoch(expires_at, self.cache_ttl)
            if expiry_mono > time.monotonic():
                with self._lock:
                    self._cache[cache_key] = (expiry_mono, vault_token)

        return vault_token

    def list_connections(self, *, traceparent: Optional[str] = None) -> List[Dict[str, Any]]:
        """List active Token Vault connections available to this agent/server."""
        tp = traceparent or current_traceparent()
        url = f"{self.issuer}/agents/me/connections"
        body = self._send("GET", url, None, traceparent=tp)
        if isinstance(body, dict) and isinstance(body.get("connections"), list):
            return [c for c in body["connections"] if isinstance(c, dict)]
        if isinstance(body, list):
            return [c for c in body if isinstance(c, dict)]
        return []

    def clear_cache(self) -> None:
        with self._lock:
            self._cache.clear()

    def _send(
        self,
        method: str,
        url: str,
        payload: Optional[Dict[str, Any]],
        *,
        traceparent: Optional[str] = None,
    ) -> Any:
        for attempt in (0, 1):
            bearer = self._token_provider()
            headers: Dict[str, str] = {
                "Authorization": f"Bearer {bearer}",
                "Accept": "application/json",
            }
            if payload is not None:
                headers["Content-Type"] = "application/json"
            if traceparent:
                headers["traceparent"] = traceparent

            if self._request_fn is not None:
                status, data = self._request_fn(method, url, headers, payload)
            else:
                try:
                    resp = requests.request(
                        method,
                        url,
                        json=payload if payload is not None else None,
                        headers=headers,
                        timeout=15,
                        verify=self._verify_tls,
                    )
                except requests.RequestException as exc:
                    raise LumoAuthNetworkError(f"Token Vault request to {url} failed: {exc}", exc) from exc
                status = resp.status_code
                try:
                    data = resp.json() if resp.text else {}
                except ValueError:
                    data = {"message": resp.text}

            if status == 401 and attempt == 0 and self._tokens_helper is not None:
                self._tokens_helper.invalidate()
                continue

            if 200 <= status < 300:
                return data

            msg = (
                (data.get("error_description") or data.get("message") or data.get("error"))
                if isinstance(data, dict)
                else f"HTTP {status}"
            ) or f"HTTP {status}"
            code = (data.get("code") or data.get("error")) if isinstance(data, dict) else None
            if status == 401:
                raise LumoAuthAuthenticationError(str(msg), code=str(code or "UNAUTHORIZED"), status_code=401, body=data)
            if status == 403:
                raise LumoAuthPermissionDeniedError(str(msg), code=str(code or "FORBIDDEN"), status_code=403, body=data)
            if status == 404:
                raise LumoAuthNotFoundError(str(msg), code=str(code or "NOT_FOUND"), status_code=404, body=data)
            raise LumoAuthApiError(str(msg), code=str(code or "API_ERROR"), status_code=status, body=data)
        return {}
