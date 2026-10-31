"""Per-tool authorization decided by LumoAuth.

A valid token proves the caller may reach the MCP server. Whether that user
or agent may run a particular tool is a policy question that LumoAuth
answers (``POST /orgs/{org}/api/v1/mcp/servers/{id}/tools/authorize``):
roles, relationships, ABAC rules and agent capabilities all apply.

The MCP server asks as itself, with its own client-credentials token
(scope ``mcp:authorize``). It never forwards the caller's token, which the
MCP specification forbids. Set up once in the LumoAuth portal:

1. Create an OAuth client for the MCP server with the ``client_credentials``
   grant and the ``mcp:authorize`` scope.
2. Add it under *Per-tool authorization* on the MCP server's page.

Then::

    auth = LumoAuthProvider()          # + LUMOAUTH_MCP_CLIENT_ID / _SECRET
    mcp = FastMCP("Invoices", auth=auth, middleware=[auth.tool_policy()])

``tools/list`` then shows each caller only the tools it may run, and
``tools/call`` refuses the others.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import OrderedDict
from functools import partial
from typing import Any, List, Optional, Sequence, Tuple

import anyio
import mcp_types as mt
from fastmcp.exceptions import AuthorizationError
from fastmcp.server.dependencies import get_http_request
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.base import Tool, ToolResult
from lumoauth import LumoAuth
from lumoauth.errors import (
    LumoAuthAuthenticationError,
    LumoAuthConfigError,
    LumoAuthError,
    LumoAuthValidationError,
)
from lumoauth.verify import AccessTokenClaims

from lumoauth_fastmcp.caller import current_caller

__all__ = ["LumoToolPolicy", "ClientCredentialsToken", "DecisionCache"]

logger = logging.getLogger("lumoauth.fastmcp")

MCP_AUTHORIZE_SCOPE = "mcp:authorize"


class ClientCredentialsToken:
    """A cached client-credentials access token, usable as a ``token_provider``."""

    def __init__(
        self,
        client: LumoAuth,
        client_id: str,
        client_secret: str,
        *,
        scopes: Sequence[str] = (MCP_AUTHORIZE_SCOPE,),
        leeway: float = 60.0,
    ) -> None:
        self._client = client
        self._client_id = client_id
        self._client_secret = client_secret
        self._scopes = list(scopes)
        self._leeway = leeway
        self._token: Optional[str] = None
        self._expires_at = 0.0
        self._lock = threading.Lock()

    def __call__(self) -> str:
        with self._lock:
            now = time.monotonic()
            if self._token is not None and now < self._expires_at:
                return self._token
            response = self._client.auth.client_credentials(
                self._client_id, self._client_secret, scopes=self._scopes
            )
            token = response.get("access_token") if isinstance(response, dict) else None
            if not isinstance(token, str) or not token:
                raise LumoAuthConfigError("LumoAuth returned no access token for the MCP server's client")
            expires_in = response.get("expires_in")
            lifetime = float(expires_in) if isinstance(expires_in, (int, float)) else 300.0
            self._token = token
            self._expires_at = now + max(0.0, lifetime - self._leeway)
            return token

    def invalidate(self) -> None:
        with self._lock:
            self._token = None
            self._expires_at = 0.0


class DecisionCache:
    """A small time-bounded LRU of ``(subject type, subject, tool) -> allowed``."""

    def __init__(self, ttl: float, max_entries: int = 10_000) -> None:
        self.ttl = ttl
        self._max_entries = max_entries
        self._entries: "OrderedDict[Tuple[str, str, str], Tuple[float, bool]]" = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: Tuple[str, str, str]) -> Optional[bool]:
        if self.ttl <= 0:
            return None
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if entry[0] <= time.monotonic():
                del self._entries[key]
                return None
            self._entries.move_to_end(key)
            return entry[1]

    def put(self, key: Tuple[str, str, str], allowed: bool) -> None:
        if self.ttl <= 0:
            return
        with self._lock:
            self._entries[key] = (time.monotonic() + self.ttl, allowed)
            self._entries.move_to_end(key)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


def _has_http_request() -> bool:
    try:
        get_http_request()
    except RuntimeError:
        return False
    return True


class LumoToolPolicy(Middleware):
    """FastMCP middleware: LumoAuth decides which tools each caller may run.

    Args:
        provider: A :class:`~lumoauth_fastmcp.LumoAuthProvider`; supplies the
            organization, server id and client credentials.
        server_id, org_id, lumoauth_url, client_id, client_secret: Override
            the provider's values (or the ``LUMOAUTH_*`` environment).
        cache_ttl: Seconds to remember a decision (default 30; 0 disables).
            A policy change in LumoAuth takes effect within this time.
        filter_list: Hide the tools a caller may not run from ``tools/list``.
        max_concurrency: Parallel decisions while filtering a list.
        client: A ready :class:`lumoauth.LumoAuth` client whose token
            provider yields the server's ``mcp:authorize`` token (tests).

    Decisions fail closed: when LumoAuth cannot be asked, the tool is refused.
    Requests without OAuth (stdio, in-memory) are not checked, as FastMCP's
    own ``AuthMiddleware`` does.
    """

    def __init__(
        self,
        *,
        provider: Any = None,
        server_id: Optional[str] = None,
        org_id: Optional[str] = None,
        lumoauth_url: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        cache_ttl: float = 30.0,
        filter_list: bool = True,
        max_concurrency: int = 8,
        client: Optional[LumoAuth] = None,
    ) -> None:
        env = os.environ
        self.server_id = (
            server_id
            or getattr(provider, "server_id", None)
            or env.get("LUMOAUTH_MCP_SERVER_ID")
            or None
        )
        if not self.server_id:
            raise LumoAuthConfigError(
                "the tool policy needs the registered MCP server id (LUMOAUTH_MCP_SERVER_ID)"
            )
        self.filter_list = filter_list
        self.max_concurrency = max(1, max_concurrency)
        self.cache = DecisionCache(cache_ttl)
        self._tokens: Optional[ClientCredentialsToken] = None

        if client is None:
            org = org_id or getattr(provider, "org_id", None) or env.get("LUMOAUTH_ORG_ID") or None
            base = (
                lumoauth_url
                or getattr(provider, "lumoauth_url", None)
                or env.get("LUMOAUTH_URL")
                or None
            )
            cid = client_id or getattr(provider, "client_id", None) or env.get("LUMOAUTH_MCP_CLIENT_ID")
            secret = (
                client_secret
                or getattr(provider, "client_secret", None)
                or env.get("LUMOAUTH_MCP_CLIENT_SECRET")
            )
            if not org:
                raise LumoAuthConfigError("the tool policy needs the organization (LUMOAUTH_ORG_ID)")
            if not cid or not secret:
                raise LumoAuthConfigError(
                    "the tool policy asks LumoAuth as the MCP server itself. Set "
                    "LUMOAUTH_MCP_CLIENT_ID and LUMOAUTH_MCP_CLIENT_SECRET to an OAuth client "
                    "with the client_credentials grant and the mcp:authorize scope, and add "
                    "that client under Per-tool authorization on the MCP server's page."
                )
            self._tokens = ClientCredentialsToken(LumoAuth(base_url=base, org_id=org), cid, secret)
            client = LumoAuth(base_url=base, org_id=org, token_provider=self._tokens)
        self._client = client

    # ── Decisions ─────────────────────────────────────────────────────

    async def is_allowed(self, caller: AccessTokenClaims, tool: str) -> bool:
        """Whether LumoAuth lets *caller* run *tool* (cached, fails closed)."""
        subject_type = "agent" if caller.is_agent else "user"
        key = (subject_type, caller.sub, tool)
        cached = self.cache.get(key)
        if cached is not None:
            return cached
        try:
            allowed = await anyio.to_thread.run_sync(partial(self._decide, subject_type, caller.sub, tool))
        except LumoAuthValidationError as exc:
            # A name LumoAuth cannot hold a policy for (too long, '/', ':' …).
            logger.warning("LumoAuth cannot authorize tool %r: %s", tool, exc)
            allowed = False
        except LumoAuthError as exc:
            logger.warning("LumoAuth tool authorization failed for %r, refusing: %s", tool, exc)
            return False
        self.cache.put(key, allowed)
        return allowed

    def _decide(self, subject_type: str, subject_id: str, tool: str) -> bool:
        try:
            decision = self._client.mcp.authorize_tool(self.server_id, subject_type, subject_id, tool)
        except LumoAuthAuthenticationError:
            # The cached server token was revoked or rotated: fetch a new one once.
            if self._tokens is None:
                raise
            self._tokens.invalidate()
            decision = self._client.mcp.authorize_tool(self.server_id, subject_type, subject_id, tool)
        return decision.allowed

    # ── FastMCP middleware hooks ──────────────────────────────────────

    async def on_list_tools(
        self,
        context: MiddlewareContext[mt.ListToolsRequest],
        call_next: CallNext[mt.ListToolsRequest, Sequence[Tool]],
    ) -> Sequence[Tool]:
        tools = await call_next(context)
        if not self.filter_list:
            return tools
        caller = current_caller()
        if caller is None:
            return tools if not _has_http_request() else []

        allowed: List[bool] = [False] * len(tools)
        limiter = anyio.Semaphore(self.max_concurrency)

        async def decide(index: int, tool: Tool) -> None:
            async with limiter:
                allowed[index] = await self.is_allowed(caller, tool.name)

        async with anyio.create_task_group() as group:
            for index, tool in enumerate(tools):
                group.start_soon(decide, index, tool)
        return [tool for tool, ok in zip(tools, allowed) if ok]

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        caller = current_caller()
        name = context.message.name
        if caller is None:
            if not _has_http_request():
                return await call_next(context)
            raise AuthorizationError(f"Authorization failed for tool '{name}': no verified caller")
        if not await self.is_allowed(caller, name):
            raise AuthorizationError(
                f"Authorization failed for tool '{name}': LumoAuth policy does not allow this caller"
            )
        return await call_next(context)
