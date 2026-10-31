"""Shared fixtures: a fake LumoAuth organization and a FastMCP app behind LumoAuthProvider."""

from __future__ import annotations

import json
import time
from typing import Any, Dict, Iterator, List, Optional

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastmcp import FastMCP
from lumoauth._jose import b64url_encode, public_jwk, sign
from starlette.testclient import TestClient

from lumoauth_fastmcp import LumoAuthProvider, current_caller

ISSUER = "https://app.lumoauth.dev/orgs/acme/api/v1"
ORIGIN = "https://mcp.example.com"
RESOURCE = f"{ORIGIN}/mcp"
SERVER_ID = "mcp_0123456789abcdef01234567"

SIGNING_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWKS = {"keys": [dict(public_jwk(SIGNING_KEY.public_key()), kid="k1", alg="RS256", use="sig")]}

ACCEPT = "application/json, text/event-stream"
INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": {"name": "pytest", "version": "1.0"},
    },
}


def make_token(claims: Optional[Dict[str, Any]] = None, *, header: Optional[Dict[str, Any]] = None) -> str:
    now = int(time.time())
    hdr = {"typ": "at+jwt", "alg": "RS256", "kid": "k1"}
    hdr.update(header or {})
    body: Dict[str, Any] = {
        "iss": ISSUER,
        "sub": "user-123",
        "aud": RESOURCE,
        "client_id": "https://client.example.com/metadata.json",
        "exp": now + 600,
        "iat": now - 5,
        "jti": f"jti-{now}-{id(claims)}",
        "scope": "mcp:read",
    }
    body.update(claims or {})
    h = b64url_encode(json.dumps(hdr, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(body, separators=(",", ":")).encode())
    return f"{h}.{p}.{b64url_encode(sign(SIGNING_KEY, 'RS256', f'{h}.{p}'.encode()))}"


def fake_fetch(url: str) -> Any:
    documents = {
        f"{ISSUER}/.well-known/openid-configuration": {
            "issuer": ISSUER,
            "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
        },
        f"{ISSUER}/.well-known/jwks.json": JWKS,
        f"{ISSUER}/.well-known/oauth-authorization-server": {
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/oauth/authorize",
            "token_endpoint": f"{ISSUER}/oauth/token",
            "code_challenge_methods_supported": ["S256"],
        },
        f"{ISSUER}/.well-known/oauth-protected-resource/mcp/{SERVER_ID}": registration_document(),
    }
    if url not in documents:
        raise AssertionError(f"unexpected fetch of {url}")
    return documents[url]


def registration_document(*, require_dpop: bool = False, scopes: List[str] | None = None) -> Dict[str, Any]:
    document: Dict[str, Any] = {
        "resource": RESOURCE,
        # The provider publishes its configured issuer and never copies this
        # value; older LumoAuth releases put the metadata URL here.
        "authorization_servers": [ISSUER],
        "bearer_methods_supported": ["header"],
        "scopes_supported": scopes if scopes is not None else ["mcp:read"],
    }
    if require_dpop:
        document["dpop_bound_access_tokens_required"] = True
        document["dpop_signing_alg_values_supported"] = ["ES256", "RS256"]
    return document


def build_server(provider: LumoAuthProvider, **fastmcp_kwargs: Any) -> FastMCP:
    mcp = FastMCP("test", auth=provider, **fastmcp_kwargs)

    @mcp.tool
    def whoami() -> dict:
        caller = current_caller()
        assert caller is not None
        return {
            "sub": caller.sub,
            "is_agent": caller.is_agent,
            "agent_id": caller.agent_id,
            "actor": caller.actor,
            "scopes": list(caller.scopes),
        }

    @mcp.tool
    def refund(invoice_id: str) -> str:
        return f"refunded {invoice_id}"

    return mcp


def make_provider(**overrides: Any) -> LumoAuthProvider:
    options: Dict[str, Any] = {
        "issuer": ISSUER,
        "server_id": SERVER_ID,
        "registration": registration_document(),
        "fetch": fake_fetch,
    }
    options.update(overrides)
    return LumoAuthProvider(**options)


@pytest.fixture
def client_for():
    """``client_for(provider, **fastmcp_kwargs)`` -> a running TestClient."""
    clients: List[TestClient] = []

    def factory(provider: LumoAuthProvider, **fastmcp_kwargs: Any) -> TestClient:
        app = build_server(provider, **fastmcp_kwargs).http_app(
            path="/mcp", json_response=True, stateless_http=True
        )
        client = TestClient(app, base_url=ORIGIN)
        client.__enter__()
        clients.append(client)
        return client

    yield factory
    for client in clients:
        client.__exit__(None, None, None)


def rpc(client: TestClient, payload: Dict[str, Any], headers: Dict[str, str]) -> Any:
    response = client.post(
        "/mcp",
        json=payload,
        headers={"Accept": ACCEPT, "MCP-Protocol-Version": "2025-11-25", **headers},
    )
    return response


def call_tool(client: TestClient, name: str, arguments: Dict[str, Any], headers: Dict[str, str]) -> Any:
    return rpc(
        client,
        {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": name, "arguments": arguments}},
        headers,
    )


@pytest.fixture
def no_lumoauth_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in (
        "LUMOAUTH_URL",
        "LUMOAUTH_ORG_ID",
        "LUMOAUTH_ISSUER",
        "LUMOAUTH_MCP_SERVER_ID",
        "LUMOAUTH_MCP_RESOURCE",
        "LUMOAUTH_MCP_CLIENT_ID",
        "LUMOAUTH_MCP_CLIENT_SECRET",
    ):
        monkeypatch.delenv(name, raising=False)
    yield
