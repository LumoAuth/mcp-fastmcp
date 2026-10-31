"""Reads an MCP server's registration from LumoAuth.

LumoAuth publishes each registered MCP server's protected resource metadata
(RFC 9728) at ``{issuer}/.well-known/oauth-protected-resource/mcp/{server_id}``.
That public document carries everything a resource server needs from the
registration: the Resource URI (the token audience), the advertised scopes
and whether only DPoP-bound tokens are accepted.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional, Tuple
from urllib.parse import quote

from lumoauth.errors import LumoAuthConfigError, LumoAuthNetworkError

__all__ = ["DEFAULT_DPOP_ALGS", "Registration", "registration_url", "fetch_registration"]

# The proof algorithms LumoAuth accepts (McpServer::DPOP_PROOF_ALGS).
DEFAULT_DPOP_ALGS: Tuple[str, ...] = (
    "ES256", "ES384", "ES512",
    "RS256", "RS384", "RS512",
    "PS256", "PS384", "PS512",
    "EdDSA",
)

Fetch = Callable[[str], Any]


@dataclass(frozen=True)
class Registration:
    """The parts of an MCP server registration that a resource server uses."""

    resource: str
    scopes_supported: Tuple[str, ...] = ()
    require_dpop: bool = False
    dpop_algs: Tuple[str, ...] = DEFAULT_DPOP_ALGS
    resource_name: Optional[str] = None
    resource_documentation: Optional[str] = None

    @classmethod
    def from_metadata(cls, document: Mapping[str, Any]) -> "Registration":
        """Build from a protected resource metadata document."""
        if not isinstance(document, Mapping):
            raise LumoAuthConfigError("the MCP server metadata is not a JSON object")
        resource = document.get("resource")
        if not isinstance(resource, str) or not resource:
            raise LumoAuthConfigError("the MCP server metadata has no 'resource'")
        scopes = document.get("scopes_supported")
        algs = document.get("dpop_signing_alg_values_supported")
        name = document.get("resource_name")
        docs = document.get("resource_documentation")
        return cls(
            resource=resource,
            scopes_supported=tuple(s for s in scopes if isinstance(s, str) and s)
            if isinstance(scopes, list)
            else (),
            require_dpop=document.get("dpop_bound_access_tokens_required") is True,
            dpop_algs=tuple(a for a in algs if isinstance(a, str) and a)
            if isinstance(algs, list) and algs
            else DEFAULT_DPOP_ALGS,
            resource_name=name if isinstance(name, str) and name else None,
            resource_documentation=docs if isinstance(docs, str) and docs else None,
        )


def registration_url(issuer: str, server_id: str) -> str:
    """URL of LumoAuth's hosted metadata document for one MCP server."""
    return (
        f"{issuer.rstrip('/')}/.well-known/oauth-protected-resource/mcp/"
        f"{quote(server_id, safe='')}"
    )


def fetch_registration(
    issuer: str,
    server_id: str,
    *,
    fetch: Optional[Fetch] = None,
    timeout: float = 10.0,
    verify_tls: bool = True,
) -> Registration:
    """Fetch and parse the registration of *server_id*.

    Raises:
        LumoAuthConfigError: LumoAuth does not know the server, the server is
            registered as Public, or the answer is not a metadata document.
        LumoAuthNetworkError: LumoAuth could not be reached.
    """
    url = registration_url(issuer, server_id)
    if fetch is not None:
        return Registration.from_metadata(fetch(url))

    import requests

    try:
        response = requests.get(
            url, headers={"Accept": "application/json"}, timeout=timeout, verify=verify_tls
        )
    except requests.RequestException as exc:
        raise LumoAuthNetworkError(f"cannot reach LumoAuth at {url}: {exc}", exc) from exc

    if response.status_code == 404:
        raise LumoAuthConfigError(
            f"LumoAuth has no active MCP server {server_id!r} at {issuer}. Check "
            "LUMOAUTH_MCP_SERVER_ID and LUMOAUTH_ORG_ID: the server id is shown on the "
            "server's page under AI Agents > MCP servers."
        )
    if response.status_code == 400:
        raise LumoAuthConfigError(
            f"MCP server {server_id!r} is registered as Public, so LumoAuth issues no "
            "tokens for it. Switch its authorization mode to 'OAuth 2.1 protected'."
        )
    if response.status_code != 200:
        raise LumoAuthConfigError(f"LumoAuth answered HTTP {response.status_code} for {url}")
    try:
        document = response.json()
    except (ValueError, json.JSONDecodeError) as exc:
        raise LumoAuthConfigError(f"LumoAuth sent invalid JSON for {url}") from exc
    return Registration.from_metadata(document)
