"""Scope/caller checks and the LumoAuth per-tool policy."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import List, Set, Tuple

import pytest
from fastmcp.exceptions import InsufficientScopeError
from fastmcp.utilities.authorization import AuthContext
from lumoauth.errors import LumoAuthNetworkError

from conftest import call_tool, make_provider, make_token, rpc
from lumoauth_fastmcp import (
    LumoToolPolicy,
    capability_covered,
    normalize_resource,
    require_agent,
    require_scopes,
    require_user,
    scope_covered,
)
from lumoauth_fastmcp.caller import LumoAccessToken, claims_from_payload


# ── Pure helpers ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "required, granted, expected",
    [
        ("files:read", ["files:read"], True),
        ("files:read", ["files:*"], True),
        ("files:read:own", ["files:*"], True),
        ("files", ["files:*"], False),
        ("filesystem:read", ["files:*"], False),
        # Only ':*' is a wildcard, as in LumoAuth; everything else is exact.
        ("invoices.refund", ["invoices.*"], False),
        ("invoices.*", ["invoices.*"], True),
        ("files:read", [":*"], False),
        ("files:read", ["files:write"], False),
    ],
)
def test_scope_covered(required, granted, expected):
    assert scope_covered(required, granted) is expected


@pytest.mark.parametrize(
    "required, granted, expected",
    [
        ("users.delete", ["users.*"], True),
        ("users:delete", ["Users-*"], True),
        ("users", ["users.*"], False),
        ("anything", ["*"], True),
        ("tool:search_web", ["tool.search_web"], True),
        ("tool:search_web", ["tool.search"], False),
    ],
)
def test_capability_covered(required, granted, expected):
    assert capability_covered(required, granted) is expected


@pytest.mark.parametrize(
    "uri, normalized",
    [
        ("HTTPS://MCP.Example.com:443/mcp/", "https://mcp.example.com/mcp"),
        ("http://localhost:80/", "http://localhost"),
        ("https://mcp.example.com/Path?x=1#frag", "https://mcp.example.com/Path?x=1"),
        ("http://[::1]:8000/mcp", "http://[::1]:8000/mcp"),
    ],
)
def test_normalize_resource(uri, normalized):
    assert normalize_resource(uri) == normalized


def context(claims: dict) -> AuthContext:
    full = {"iss": "i", "sub": "user-1", "aud": "a", "exp": 1, "scope": "", **claims}
    token = LumoAccessToken.from_claims("t", claims_from_payload(full), resource="a")
    return AuthContext(token=token, component=SimpleNamespace(tags=set()))


def test_require_scopes_names_the_shortfall():
    check = require_scopes("invoices:read", "invoices:refund")
    assert check(context({"scope": "invoices:*"})) is True
    with pytest.raises(InsufficientScopeError) as caught:
        check(context({"scope": "invoices:read"}))
    assert caught.value.required_scopes == ["invoices:refund"]
    assert check(AuthContext(token=None, component=SimpleNamespace(tags=set()))) is False


def test_require_agent_and_require_user():
    agent = context({"sub": "agent_agt_1", "is_agent": True, "capabilities": ["billing.*"]})
    user = context({"sub": "user-1"})
    delegated = context({"sub": "user-1", "act": {"sub": "agent_agt_1"}})
    assert require_agent()(agent) is True
    assert require_agent("billing:refund")(agent) is True
    assert require_agent("users.delete")(agent) is False
    assert require_agent()(user) is False
    assert require_user()(user) is True
    assert require_user()(agent) is False
    assert require_user()(delegated) is False
    assert require_user(allow_delegation=True)(delegated) is True


# ── LumoToolPolicy ───────────────────────────────────────────────────


class FakeMcp:
    def __init__(self, allowed: Set[str], error: Exception | None = None) -> None:
        self.allowed = allowed
        self.error = error
        self.calls: List[Tuple[str, str, str, str]] = []

    def authorize_tool(self, server_id: str, subject_type: str, subject_id: str, tool: str):
        self.calls.append((server_id, subject_type, subject_id, tool))
        if self.error is not None:
            raise self.error
        return SimpleNamespace(allowed=tool in self.allowed)


def policy_client(client_for, fake: FakeMcp, **options):
    provider = make_provider()
    policy = LumoToolPolicy(provider=provider, client=SimpleNamespace(mcp=fake), **options)
    return client_for(provider, middleware=[policy])


def list_tools(client, token: str) -> List[str]:
    response = rpc(client, {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}, {"Authorization": f"Bearer {token}"})
    assert response.status_code == 200, response.text
    return sorted(tool["name"] for tool in response.json()["result"]["tools"])


def refused(response) -> bool:
    """A JSON-RPC error or an error result, either way naming the reason."""
    body = response.json()
    if "error" in body:
        return "Authorization failed" in json.dumps(body["error"])
    result = body["result"]
    return bool(result.get("isError")) and "Authorization failed" in json.dumps(result)


def test_policy_filters_tools_list(client_for):
    fake = FakeMcp({"whoami"})
    client = policy_client(client_for, fake)
    assert list_tools(client, make_token()) == ["whoami"]
    assert {call[3] for call in fake.calls} == {"whoami", "refund"}
    assert all(call[:3] == ("mcp_0123456789abcdef01234567", "user", "user-123") for call in fake.calls)


def test_policy_refuses_a_denied_tool_and_allows_the_rest(client_for):
    client = policy_client(client_for, FakeMcp({"whoami"}))
    token = make_token()
    assert refused(call_tool(client, "refund", {"invoice_id": "inv_1"}, {"Authorization": f"Bearer {token}"}))
    allowed = call_tool(client, "whoami", {}, {"Authorization": f"Bearer {token}"})
    assert "error" not in allowed.json() and not allowed.json()["result"].get("isError")


def test_policy_asks_about_agents_as_agents(client_for):
    fake = FakeMcp({"whoami", "refund"})
    client = policy_client(client_for, fake)
    token = make_token({"sub": "agent_agt_9", "is_agent": True})
    list_tools(client, token)
    assert {call[1:3] for call in fake.calls} == {("agent", "agent_agt_9")}


def test_policy_decisions_are_cached(client_for):
    fake = FakeMcp({"whoami"})
    client = policy_client(client_for, fake)
    token = make_token()
    list_tools(client, token)
    list_tools(client, token)
    assert len(fake.calls) == 2


def test_policy_fails_closed(client_for):
    client = policy_client(client_for, FakeMcp(set(), error=LumoAuthNetworkError("down")))
    token = make_token()
    assert list_tools(client, token) == []
    assert refused(call_tool(client, "whoami", {}, {"Authorization": f"Bearer {token}"}))


def test_policy_needs_server_credentials(no_lumoauth_env):
    provider = make_provider()
    with pytest.raises(Exception, match="LUMOAUTH_MCP_CLIENT_ID"):
        LumoToolPolicy(provider=provider, org_id="acme")
