"""FastMCP auth provider for MCP servers registered in LumoAuth.

LumoAuth is the authorization server: it registers MCP clients (Client ID
Metadata Documents or dynamic registration), shows consent, and issues
access tokens whose ``aud`` is the MCP server's Resource URI. The FastMCP
server is a pure resource server. This provider gives it the four things
the MCP authorization specification asks of one:

- RFC 9728 protected resource metadata at the server's own origin, naming
  the LumoAuth organization as the authorization server;
- a ``401`` challenge that points clients at that document;
- local verification of LumoAuth ``at+jwt`` tokens: signature against the
  organization JWKS, issuer, audience, expiry, refusal of portal test
  tokens, and the RFC 9449 DPoP binding when the token is sender-constrained;
- the verified caller (user or agent, delegation chain, scopes) for tools.

Three lines::

    from fastmcp import FastMCP
    from lumoauth_fastmcp import LumoAuthProvider

    mcp = FastMCP("Invoices", auth=LumoAuthProvider())

with ``LUMOAUTH_ORG_ID`` and ``LUMOAUTH_MCP_SERVER_ID`` in the environment.
The provider reads the rest (Resource URI, advertised scopes, whether DPoP
is required) from the server's registration in LumoAuth at start-up.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import threading
import time
from functools import partial
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple, Union
from urllib.parse import urlsplit

import anyio
from fastmcp.server.auth import AccessToken, AuthProvider
from lumoauth.errors import (
    LumoAuthConfigError,
    LumoAuthError,
    LumoAuthNetworkError,
    LumoAuthTokenError,
)
from lumoauth.verify import (
    AccessTokenClaims,
    AccessTokenVerifier,
    DpopRequest,
    InMemoryReplayCache,
    JwksCache,
    ReplayCache,
)
from mcp.server.auth.routes import build_resource_metadata_url, cors_middleware
from pydantic import AnyHttpUrl
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import Scope

from lumoauth_fastmcp._asgi import LumoAuthHttpMiddleware, current_request_auth
from lumoauth_fastmcp._registration import DEFAULT_DPOP_ALGS, Registration, fetch_registration
from lumoauth_fastmcp._resource import matching_audiences, origin_of, same_resource
from lumoauth_fastmcp.caller import LumoAccessToken
from lumoauth_fastmcp.checks import scope_covered

__all__ = ["LumoAuthProvider", "DEFAULT_LUMOAUTH_URL"]

DEFAULT_LUMOAUTH_URL = "https://app.lumoauth.dev"
_METADATA_TTL = 3600.0
_MAX_CACHED_VERIFIERS = 8

logger = logging.getLogger("lumoauth.fastmcp")


def _unverified_payload(token: str) -> Dict[str, Any]:
    """The JWT payload without any check, to pick the verifier. Never trusted."""
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    try:
        segment = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(segment))
    except ValueError:
        return {}
    return payload if isinstance(payload, dict) else {}


class LumoAuthProvider(AuthProvider):
    """Protects a FastMCP server with LumoAuth.

    Every argument is optional and falls back to an environment variable:

    ==========================  ==============================
    Argument                    Environment variable
    ==========================  ==============================
    ``org_id``                  ``LUMOAUTH_ORG_ID``
    ``server_id``               ``LUMOAUTH_MCP_SERVER_ID``
    ``resource``                ``LUMOAUTH_MCP_RESOURCE``
    ``lumoauth_url``            ``LUMOAUTH_URL``
    ``issuer``                  ``LUMOAUTH_ISSUER``
    ``client_id``               ``LUMOAUTH_MCP_CLIENT_ID``
    ``client_secret``           ``LUMOAUTH_MCP_CLIENT_SECRET``
    ==========================  ==============================

    Args:
        org_id: The organization slug, for example ``"acme"``.
        server_id: The registered MCP server id (``mcp_…``). With it the
            provider fetches the registration once at start-up and takes
            the Resource URI, the advertised scopes and the DPoP
            requirement from it.
        resource: The registered Resource URI, the ``aud`` of tokens for
            this server. Needed only without ``server_id``.
        base_url: This server's public base URL. Defaults to the origin of
            the Resource URI. Without ``server_id`` or ``resource``, the
            Resource URI is ``base_url`` plus the MCP path (FastMCP style).
        lumoauth_url: The LumoAuth instance, ``https://app.lumoauth.dev``
            by default (``https://eu.app.lumoauth.dev`` for the EU region).
        issuer: The organization issuer. Defaults to
            ``{lumoauth_url}/orgs/{org_id}/api/v1``; set it for a custom domain.
        required_scopes: Scopes every request must carry. A wildcard in the
            token (``mcp:*``) satisfies them.
        scopes_supported: Scopes to advertise in the metadata and the
            ``401`` challenge. Defaults to the registration's basic scopes.
        require_dpop: Refuse tokens that are not DPoP-bound. Defaults to
            the registration's *Require DPoP* switch.
        client_id, client_secret: The MCP server's own OAuth client, used
            only by :meth:`tool_policy` to ask LumoAuth about tools.
        resource_name, resource_documentation: Extra metadata fields.
        registration: The registration document (or a
            :class:`Registration`) to use instead of fetching it.
        fetch: ``fetch(url) -> dict`` for the registration, discovery and
            JWKS requests (tests, custom transports).
        replay_cache: Where DPoP proof ids are remembered. The default is
            per process; give a shared store (Redis) to several workers.
        clock_skew: Seconds of leeway on ``exp``/``nbf`` and proof times.
        request_url: ``request_url(scope) -> str`` builds the public URL of
            a request for the DPoP ``htu`` check. The default is the public
            origin plus the request path, which suits a TLS-terminating proxy
            that keeps paths.
        authorization_server_metadata: Also serve LumoAuth's authorization
            server metadata at ``/.well-known/oauth-authorization-server`` of
            this server, for clients written before protected resource
            metadata existed (MCP 2025-03-26).
        verify_tls: Verify LumoAuth's TLS certificate (local dev only off).
    """

    def __init__(
        self,
        *,
        org_id: Optional[str] = None,
        server_id: Optional[str] = None,
        resource: Optional[str] = None,
        base_url: Optional[Union[AnyHttpUrl, str]] = None,
        lumoauth_url: Optional[str] = None,
        issuer: Optional[str] = None,
        required_scopes: Optional[List[str]] = None,
        scopes_supported: Optional[List[str]] = None,
        require_dpop: Optional[bool] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        resource_name: Optional[str] = None,
        resource_documentation: Optional[str] = None,
        registration: Optional[Union[Registration, Mapping[str, Any]]] = None,
        fetch: Optional[Callable[[str], Any]] = None,
        replay_cache: Optional[ReplayCache] = None,
        clock_skew: float = 60,
        request_url: Optional[Callable[[Scope], str]] = None,
        authorization_server_metadata: bool = True,
        verify_tls: bool = True,
    ) -> None:
        env = os.environ
        self.lumoauth_url = (lumoauth_url or env.get("LUMOAUTH_URL") or DEFAULT_LUMOAUTH_URL).rstrip("/")
        self.org_id: Optional[str] = org_id or env.get("LUMOAUTH_ORG_ID") or None
        self.server_id: Optional[str] = server_id or env.get("LUMOAUTH_MCP_SERVER_ID") or None

        issuer_value = issuer or env.get("LUMOAUTH_ISSUER") or None
        if issuer_value is None:
            if not self.org_id:
                raise LumoAuthConfigError(
                    "LumoAuthProvider needs the organization: pass org_id= or set "
                    "LUMOAUTH_ORG_ID (or pass the issuer=)."
                )
            issuer_value = f"{self.lumoauth_url}/orgs/{self.org_id}/api/v1"
        self.issuer: str = issuer_value.rstrip("/")

        if isinstance(registration, Registration):
            reg: Optional[Registration] = registration
        elif registration is not None:
            reg = Registration.from_metadata(registration)
        elif self.server_id:
            reg = fetch_registration(self.issuer, self.server_id, fetch=fetch, verify_tls=verify_tls)
        else:
            reg = None
        self.registration = reg

        explicit_resource = resource or env.get("LUMOAUTH_MCP_RESOURCE") or None
        if explicit_resource and reg is not None and not same_resource(explicit_resource, reg.resource):
            raise LumoAuthConfigError(
                f"resource {explicit_resource!r} is not the Resource URI {reg.resource!r} "
                f"registered for {self.server_id or 'this MCP server'}."
            )
        self.resource: Optional[str] = explicit_resource or (reg.resource if reg else None)
        if self.resource is None and base_url is None:
            raise LumoAuthConfigError(
                "LumoAuthProvider needs this server's Resource URI: set "
                "LUMOAUTH_MCP_SERVER_ID to the registered server id, or pass resource= "
                "or base_url=."
            )
        if base_url is None:
            base_url = origin_of(self.resource or "")

        super().__init__(base_url=base_url, required_scopes=required_scopes)

        self.require_dpop: bool = (
            require_dpop if require_dpop is not None else (reg.require_dpop if reg else False)
        )
        self.dpop_algs: Tuple[str, ...] = reg.dpop_algs if reg else DEFAULT_DPOP_ALGS
        self._scopes_supported: Optional[List[str]] = (
            list(scopes_supported)
            if scopes_supported is not None
            else (list(reg.scopes_supported) if reg else None)
        )
        self.resource_name = resource_name or (reg.resource_name if reg else None)
        self.resource_documentation = resource_documentation or (
            reg.resource_documentation if reg else None
        )
        self.client_id: Optional[str] = client_id or env.get("LUMOAUTH_MCP_CLIENT_ID") or None
        self.client_secret: Optional[str] = (
            client_secret or env.get("LUMOAUTH_MCP_CLIENT_SECRET") or None
        )

        self._fetch = fetch
        self._verify_tls = verify_tls
        self._clock_skew = float(clock_skew)
        self._replay_cache: ReplayCache = replay_cache or InMemoryReplayCache()
        self._request_url = request_url
        self._serve_as_metadata = authorization_server_metadata
        self._verifiers: Dict[Tuple[str, str], AccessTokenVerifier] = {}
        self._jwks: Optional[JwksCache] = None
        self._lock = threading.Lock()
        self._as_metadata: Optional[Tuple[float, Dict[str, Any]]] = None

    # ── FastMCP hooks ──────────────────────────────────────────────────

    @property
    def scopes_supported(self) -> List[str]:
        if self._scopes_supported is not None:
            return list(self._scopes_supported)
        return list(self.required_scopes)

    def get_challenge_scopes(self, required_scopes: Optional[List[str]] = None) -> List[str]:
        if required_scopes is not None:
            return required_scopes
        return list(self.required_scopes) or self.scopes_supported

    def _get_resource_url(self, path: Optional[str] = None) -> Optional[AnyHttpUrl]:
        if self.resource:
            return AnyHttpUrl(self.resource)
        return super()._get_resource_url(path)

    def set_mcp_path(self, mcp_path: Optional[str]) -> None:
        super().set_mcp_path(mcp_path)
        if self.resource is None and self._resource_url is not None:
            self.resource = str(self._resource_url)

    def get_routes(self, mcp_path: Optional[str] = None) -> List[Route]:
        self.set_mcp_path(mcp_path)
        resource_url = self._get_resource_url(mcp_path)
        if resource_url is None:
            return []
        metadata_path = urlsplit(str(build_resource_metadata_url(resource_url))).path
        routes = [
            Route(
                metadata_path,
                endpoint=cors_middleware(self._protected_resource_endpoint, ["GET", "OPTIONS"]),
                methods=["GET", "OPTIONS"],
            )
        ]
        if self._serve_as_metadata:
            routes.append(
                Route(
                    "/.well-known/oauth-authorization-server",
                    endpoint=cors_middleware(self._authorization_server_endpoint, ["GET", "OPTIONS"]),
                    methods=["GET", "OPTIONS"],
                )
            )
        return routes

    def get_middleware(self) -> list:
        return [Middleware(LumoAuthHttpMiddleware, provider=self), *super().get_middleware()]

    async def verify_token(self, token: str) -> Optional[AccessToken]:
        state = current_request_auth.get()
        dpop = None
        if state is not None:
            dpop = DpopRequest(
                method=state.method,
                url=state.url,
                proof=state.proof,
                scheme=state.scheme or "Bearer",
            )
        try:
            claims = await anyio.to_thread.run_sync(partial(self.verify_claims, token, dpop=dpop))
        except LumoAuthTokenError as exc:
            if state is not None:
                state.failure = exc
            if exc.code == "TOKEN_KEYS_UNAVAILABLE":
                logger.warning("LumoAuth signing keys unavailable: %s", exc.message)
            elif exc.code == "TOKEN_MALFORMED" and token.count(".") != 2:
                logger.info(
                    "Refused a token that is not a JWT. LumoAuth issues opaque tokens only "
                    "to clients set to the opaque token format; switch the client to JWT."
                )
            else:
                logger.info("LumoAuth token refused (%s): %s", exc.code, exc.message)
            return None
        except LumoAuthError as exc:
            logger.error("LumoAuth token verification failed: %s", exc)
            return None

        scopes = list(claims.scopes)
        # Server-wide required scopes are checked by exact match downstream;
        # list the ones a granted wildcard covers so that check passes too.
        scopes += [
            scope
            for scope in self.required_scopes
            if scope not in scopes and scope_covered(scope, claims.scopes)
        ]
        return LumoAccessToken.from_claims(token, claims, resource=self.resource or "", scopes=scopes)

    # ── Verification (also usable from custom routes) ──────────────────

    def verify_claims(self, token: str, *, dpop: Optional[DpopRequest] = None) -> AccessTokenClaims:
        """Verify a LumoAuth access token for this server, synchronously.

        Raises:
            LumoAuthTokenError: The token or its DPoP proof is not acceptable;
                ``code`` says why.
        """
        if not self.resource:
            raise LumoAuthConfigError(
                "the Resource URI is not known yet: FastMCP has not built this provider's routes"
            )
        audiences = matching_audiences(_unverified_payload(token).get("aud"), self.resource)
        # Verify against the spelling of the resource found in the token, if
        # it is one LumoAuth would match; the verifier checks it again.
        verifier = self._verifier_for(audiences[0] if audiences else self.resource)
        return verifier.verify(token, dpop=dpop)

    def _verifier_for(self, resource: str) -> AccessTokenVerifier:
        with self._lock:
            verifier = self._verifiers.get((self.issuer, resource))
            if verifier is not None:
                return verifier
            verifier = AccessTokenVerifier(
                self.issuer,
                resource,
                fetch=self._fetch,
                clock_skew=self._clock_skew,
                require_dpop=self.require_dpop,
                replay_cache=self._replay_cache,
                verify_tls=self._verify_tls,
            )
            # One JWKS cache for every spelling of the resource.
            if self._jwks is None:
                self._jwks = verifier.jwks
            else:
                verifier.jwks = self._jwks
            if len(self._verifiers) < _MAX_CACHED_VERIFIERS:
                self._verifiers[(self.issuer, resource)] = verifier
            return verifier

    # ── Requests ───────────────────────────────────────────────────────

    def request_url(self, scope: Scope) -> str:
        """The public URL of an ASGI request, for the DPoP ``htu`` check."""
        if self._request_url is not None:
            return self._request_url(scope)
        raw = scope.get("raw_path")
        if isinstance(raw, (bytes, bytearray)) and raw:
            path = bytes(raw).decode("latin-1")
        else:
            path = f"{scope.get('root_path', '')}{scope.get('path', '')}"
        if not path.startswith("/"):
            path = "/" + path
        return origin_of(str(self.base_url)) + path

    # ── Discovery documents ────────────────────────────────────────────

    @property
    def resource_metadata_url(self) -> Optional[str]:
        """Where this server serves its protected resource metadata."""
        resource_url = self._get_resource_url(self._mcp_path)
        return str(build_resource_metadata_url(resource_url)) if resource_url else None

    def protected_resource_metadata(self) -> Dict[str, Any]:
        """The RFC 9728 document this server publishes."""
        document: Dict[str, Any] = {
            "resource": self.resource,
            # RFC 9728: issuer identifiers. MCP clients find LumoAuth's
            # metadata from it ({issuer}/.well-known/openid-configuration).
            "authorization_servers": [self.issuer],
            "bearer_methods_supported": ["header"],
        }
        scopes = self.scopes_supported
        if scopes:
            document["scopes_supported"] = scopes
        if self.resource_name:
            document["resource_name"] = self.resource_name
        if self.resource_documentation:
            document["resource_documentation"] = str(self.resource_documentation)
        if self.require_dpop:
            document["dpop_bound_access_tokens_required"] = True
            document["dpop_signing_alg_values_supported"] = list(self.dpop_algs)
        return document

    async def _protected_resource_endpoint(self, request: Request) -> JSONResponse:
        return JSONResponse(
            self.protected_resource_metadata(),
            headers={"Cache-Control": f"public, max-age={int(_METADATA_TTL)}"},
        )

    async def _authorization_server_endpoint(self, request: Request) -> JSONResponse:
        try:
            metadata = await anyio.to_thread.run_sync(self._authorization_server_metadata)
        except LumoAuthError as exc:
            return JSONResponse(
                {"error": "server_error", "error_description": f"cannot fetch LumoAuth metadata: {exc}"},
                status_code=502,
            )
        return JSONResponse(
            metadata, headers={"Cache-Control": f"public, max-age={int(_METADATA_TTL)}"}
        )

    def _authorization_server_metadata(self) -> Dict[str, Any]:
        cached = self._as_metadata
        now = time.monotonic()
        if cached is not None and now - cached[0] < _METADATA_TTL:
            return cached[1]
        document = self._get_json(f"{self.issuer}/.well-known/oauth-authorization-server")
        if not isinstance(document, dict):
            raise LumoAuthConfigError("LumoAuth's authorization server metadata is not an object")
        self._as_metadata = (now, document)
        return document

    def _get_json(self, url: str) -> Any:
        if self._fetch is not None:
            return self._fetch(url)
        import requests

        try:
            response = requests.get(
                url, headers={"Accept": "application/json"}, timeout=10, verify=self._verify_tls
            )
        except requests.RequestException as exc:
            raise LumoAuthNetworkError(f"cannot reach LumoAuth at {url}: {exc}", exc) from exc
        if response.status_code != 200:
            raise LumoAuthConfigError(f"LumoAuth answered HTTP {response.status_code} for {url}")
        try:
            return response.json()
        except ValueError as exc:
            raise LumoAuthConfigError(f"LumoAuth sent invalid JSON for {url}") from exc

    # ── Per-tool authorization ─────────────────────────────────────────

    def tool_policy(self, **options: Any) -> Any:
        """FastMCP middleware that asks LumoAuth about each tool.

        See :class:`lumoauth_fastmcp.policy.LumoToolPolicy` for ``options``.
        """
        from lumoauth_fastmcp.policy import LumoToolPolicy

        return LumoToolPolicy(provider=self, **options)
