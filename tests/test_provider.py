"""LumoAuthProvider end to end through FastMCP's real HTTP app."""

from __future__ import annotations

import json
import time

import pytest
from lumoauth.dpop import DpopKey, DpopProofSigner
from lumoauth.errors import LumoAuthConfigError

from conftest import (
    INITIALIZE,
    ISSUER,
    ORIGIN,
    RESOURCE,
    SERVER_ID,
    call_tool,
    fake_fetch,
    make_provider,
    make_token,
    registration_document,
    rpc,
)
from lumoauth_fastmcp import LumoAuthProvider

METADATA_URL = f"{ORIGIN}/.well-known/oauth-protected-resource/mcp"


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def tool_payload(response) -> dict:
    body = response.json()
    assert "result" in body, body
    return json.loads(body["result"]["content"][0]["text"])


# ── Discovery ────────────────────────────────────────────────────────


def test_metadata_names_the_issuer_and_the_registration(client_for):
    client = client_for(make_provider())
    response = client.get(
        "/.well-known/oauth-protected-resource/mcp", headers={"Origin": "https://claude.ai"}
    )
    assert response.status_code == 200
    assert response.json() == {
        "resource": RESOURCE,
        "authorization_servers": [ISSUER],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["mcp:read"],
    }
    assert response.headers["access-control-allow-origin"] == "*"


def test_metadata_announces_dpop_when_the_registration_requires_it(client_for):
    provider = make_provider(registration=registration_document(require_dpop=True))
    document = client_for(provider).get("/.well-known/oauth-protected-resource/mcp").json()
    assert document["dpop_bound_access_tokens_required"] is True
    assert document["dpop_signing_alg_values_supported"] == ["ES256", "RS256"]


def test_authorization_server_metadata_is_mirrored_for_legacy_clients(client_for):
    response = client_for(make_provider()).get("/.well-known/oauth-authorization-server")
    assert response.status_code == 200
    assert response.json()["issuer"] == ISSUER


def test_registration_is_fetched_from_lumoauth(no_lumoauth_env):
    provider = LumoAuthProvider(issuer=ISSUER, server_id=SERVER_ID, fetch=fake_fetch)
    assert provider.resource == RESOURCE
    assert provider.scopes_supported == ["mcp:read"]
    assert provider.require_dpop is False


def test_environment_configuration(monkeypatch, no_lumoauth_env):
    monkeypatch.setenv("LUMOAUTH_ORG_ID", "acme")
    monkeypatch.setenv("LUMOAUTH_MCP_SERVER_ID", SERVER_ID)
    provider = LumoAuthProvider(fetch=fake_fetch)
    assert provider.issuer == ISSUER
    assert provider.resource == RESOURCE


def test_configuration_errors_are_actionable(no_lumoauth_env):
    with pytest.raises(LumoAuthConfigError, match="LUMOAUTH_ORG_ID"):
        LumoAuthProvider(resource=RESOURCE)
    with pytest.raises(LumoAuthConfigError, match="Resource URI"):
        LumoAuthProvider(issuer=ISSUER)
    with pytest.raises(LumoAuthConfigError, match="registered"):
        make_provider(resource="https://elsewhere.example.com/mcp")


# ── Challenges ───────────────────────────────────────────────────────


def test_missing_token_gets_a_challenge_without_error(client_for):
    response = rpc(client_for(make_provider()), INITIALIZE, {})
    assert response.status_code == 401
    challenge = response.headers["www-authenticate"]
    assert challenge.startswith("Bearer ")
    assert f'resource_metadata="{METADATA_URL}"' in challenge
    assert 'scope="mcp:read"' in challenge
    assert "error=" not in challenge


def test_dpop_server_challenges_with_the_dpop_scheme(client_for):
    provider = make_provider(registration=registration_document(require_dpop=True))
    response = rpc(client_for(provider), INITIALIZE, {})
    assert response.status_code == 401
    challenge = response.headers["www-authenticate"]
    assert challenge.startswith("DPoP ")
    assert 'algs="ES256 RS256"' in challenge
    assert f'resource_metadata="{METADATA_URL}"' in challenge


# ── Bearer tokens ────────────────────────────────────────────────────


def test_valid_token_reaches_the_server(client_for):
    response = rpc(client_for(make_provider()), INITIALIZE, bearer(make_token()))
    assert response.status_code == 200
    assert response.json()["result"]["serverInfo"]["name"] == "test"


def test_tools_see_the_verified_caller(client_for):
    token = make_token(
        {
            "sub": "user-123",
            "act": {"sub": "agent_agt_42", "sub_profile": "ai_agent"},
            "scope": "mcp:read invoices:read",
        }
    )
    response = call_tool(client_for(make_provider()), "whoami", {}, bearer(token))
    assert response.status_code == 200
    assert tool_payload(response) == {
        "sub": "user-123",
        "is_agent": False,
        "agent_id": None,
        "actor": "agent_agt_42",
        "scopes": ["mcp:read", "invoices:read"],
    }


def test_agent_token(client_for):
    token = make_token({"sub": "agent_agt_42", "is_agent": True, "client_id": "agt_42"})
    payload = tool_payload(call_tool(client_for(make_provider()), "whoami", {}, bearer(token)))
    assert payload["is_agent"] is True
    assert payload["agent_id"] == "agt_42"


@pytest.mark.parametrize(
    "claims, reason",
    [
        ({"aud": "https://other.example.com/mcp"}, "audience"),
        ({"iss": "https://app.lumoauth.dev/orgs/other/api/v1"}, "issuer"),
        ({"exp": int(time.time()) - 3600}, "expired"),
        ({"token_use": "test"}, "test tokens"),
    ],
)
def test_refused_tokens_get_the_real_reason(client_for, claims, reason):
    response = rpc(client_for(make_provider()), INITIALIZE, bearer(make_token(claims)))
    assert response.status_code == 401
    challenge = response.headers["www-authenticate"]
    assert challenge.startswith("Bearer ")
    assert 'error="invalid_token"' in challenge
    assert reason in challenge
    assert f'resource_metadata="{METADATA_URL}"' in challenge


def test_wrong_token_type_is_refused(client_for):
    response = rpc(client_for(make_provider()), INITIALIZE, bearer(make_token(header={"typ": "JWT"})))
    assert response.status_code == 401


def test_audience_is_compared_like_lumoauth_compares_resources(client_for):
    token = make_token({"aud": "HTTPS://MCP.example.com:443/mcp/"})
    assert rpc(client_for(make_provider()), INITIALIZE, bearer(token)).status_code == 200


def test_required_scopes_accept_a_wildcard_grant(client_for):
    client = client_for(make_provider(required_scopes=["mcp:tools:call"]))
    assert rpc(client, INITIALIZE, bearer(make_token({"scope": "mcp:tools:*"}))).status_code == 200
    response = rpc(client, INITIALIZE, bearer(make_token({"scope": "mcp:read"})))
    assert response.status_code == 403
    assert 'error="insufficient_scope"' in response.headers["www-authenticate"]


# ── DPoP ─────────────────────────────────────────────────────────────


@pytest.fixture
def dpop_client(client_for):
    return client_for(make_provider(registration=registration_document(require_dpop=True)))


def test_dpop_bound_token_with_a_valid_proof(dpop_client):
    signer = DpopProofSigner(DpopKey.generate())
    token = make_token({"cnf": {"jkt": signer.thumbprint}})
    response = rpc(dpop_client, INITIALIZE, signer.headers("POST", RESOURCE, token))
    assert response.status_code == 200


def test_replayed_dpop_proof_is_refused(dpop_client):
    signer = DpopProofSigner(DpopKey.generate())
    token = make_token({"cnf": {"jkt": signer.thumbprint}})
    headers = signer.headers("POST", RESOURCE, token)
    assert rpc(dpop_client, INITIALIZE, headers).status_code == 200
    replay = rpc(dpop_client, INITIALIZE, headers)
    assert replay.status_code == 401
    challenge = replay.headers["www-authenticate"]
    assert challenge.startswith("DPoP ")
    assert 'error="invalid_dpop_proof"' in challenge


def test_proof_for_another_url_is_refused(dpop_client):
    signer = DpopProofSigner(DpopKey.generate())
    token = make_token({"cnf": {"jkt": signer.thumbprint}})
    headers = signer.headers("POST", f"{ORIGIN}/other", token)
    assert rpc(dpop_client, INITIALIZE, headers).status_code == 401


def test_bound_token_presented_as_bearer_is_refused(dpop_client):
    signer = DpopProofSigner(DpopKey.generate())
    token = make_token({"cnf": {"jkt": signer.thumbprint}})
    headers = {"Authorization": f"Bearer {token}", "DPoP": signer.create_proof("POST", RESOURCE, access_token=token)}
    response = rpc(dpop_client, INITIALIZE, headers)
    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("DPoP ")


def test_unbound_token_is_refused_where_dpop_is_required(dpop_client):
    response = rpc(dpop_client, INITIALIZE, bearer(make_token()))
    assert response.status_code == 401
    challenge = response.headers["www-authenticate"]
    assert challenge.startswith("DPoP ")
    assert "DPoP-bound" in challenge


def test_bound_token_also_works_where_dpop_is_optional(client_for):
    signer = DpopProofSigner(DpopKey.generate())
    token = make_token({"cnf": {"jkt": signer.thumbprint}})
    response = rpc(client_for(make_provider()), INITIALIZE, signer.headers("POST", RESOURCE, token))
    assert response.status_code == 200
