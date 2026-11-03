"""Tests for JIT/RAR step-up guards, Token Vault helper, and W3C traceparent propagation."""

from __future__ import annotations

import base64
import json
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

import pytest
from fastmcp import FastMCP
from fastmcp.server.middleware import AuthMiddleware
from starlette.testclient import TestClient

from conftest import (
    ISSUER,
    ORIGIN,
    RESOURCE,
    SERVER_ID,
    call_tool,
    make_provider,
    make_token,
    rpc,
)
from lumoauth_fastmcp import (
    InsufficientAuthorizationDetailsError,
    LumoToolPolicy,
    LumoVaultClient,
    authorization_detail_covered,
    build_authorization_detail,
    current_caller,
    current_trace_id,
    current_traceparent,
    ensure_jit,
    missing_authorization_details,
    parse_traceparent,
    require_jit,
    resolve_vault_user_id,
)
from lumoauth_fastmcp.caller import claims_from_payload


# ── W3C traceparent ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    "raw, expected_trace_id",
    [
        (
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "4bf92f3577b34da6a3ce929d0e0e4736",
        ),
        (
            "  00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-00  ",
            "4bf92f3577b34da6a3ce929d0e0e4736",
        ),
        ("01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", None),
        ("00-00000000000000000000000000000000-00f067aa0ba902b7-01", None),
        ("00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01", None),
        ("not-a-traceparent", None),
        (None, None),
    ],
)
def test_parse_traceparent(raw, expected_trace_id):
    parsed = parse_traceparent(raw)
    if expected_trace_id is None:
        assert parsed is None
    else:
        assert parsed is not None
        assert parsed[1] == expected_trace_id


def test_traceparent_is_exposed_to_tools_and_forwarded_to_policy():
    provider = make_provider()
    seen_traces: List[Optional[str]] = []

    class TraceAwareMcp:
        def authorize_tool(
            self,
            server_id: str,
            subject_type: str,
            subject_id: str,
            tool: str,
            *,
            traceparent: Optional[str] = None,
        ):
            seen_traces.append(traceparent)
            return SimpleNamespace(allowed=True)

    policy = LumoToolPolicy(provider=provider, client=SimpleNamespace(mcp=TraceAwareMcp()))
    mcp = FastMCP("trace-test", auth=provider, middleware=[policy])

    @mcp.tool
    def trace_echo() -> dict:
        caller = current_caller()
        assert caller is not None
        return {
            "caller_tp": caller.traceparent,
            "caller_tid": caller.trace_id,
            "ctx_tp": current_traceparent(),
            "ctx_tid": current_trace_id(),
        }

    tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    tid = "4bf92f3577b34da6a3ce929d0e0e4736"
    app = mcp.http_app(path="/mcp", json_response=True, stateless_http=True)
    with TestClient(app, base_url=ORIGIN) as client:
        resp = call_tool(
            client,
            "trace_echo",
            {},
            {"Authorization": f"Bearer {make_token()}", "traceparent": tp},
        )
        assert resp.status_code == 200
        payload = json.loads(resp.json()["result"]["content"][0]["text"])
        assert payload == {
            "caller_tp": tp,
            "caller_tid": tid,
            "ctx_tp": tp,
            "ctx_tid": tid,
        }
        assert seen_traces == [tp]


# ── JIT / RAR (Insufficient-Authorization-Details) ──────────────────


def test_authorization_detail_matching():
    granted = [
        {
            "type": "payment_initiation",
            "actions": ["refund", "read"],
            "locations": ["https://api.stripe.com"],
            "identifier": "inv_123",
        }
    ]
    req_ok = build_authorization_detail(
        "payment_initiation",
        actions=["refund"],
        locations=["https://api.stripe.com"],
        identifier="inv_123",
    )
    req_wrong_action = build_authorization_detail("payment_initiation", actions=["wire_transfer"])
    req_wrong_id = build_authorization_detail(
        "payment_initiation", actions=["refund"], identifier="inv_999"
    )
    assert authorization_detail_covered(req_ok, granted) is True
    assert authorization_detail_covered(req_wrong_action, granted) is False
    assert authorization_detail_covered(req_wrong_id, granted) is False
    assert missing_authorization_details([req_ok, req_wrong_action], granted) == [req_wrong_action]


def test_jit_claims_extraction_from_permissions_and_top_level():
    c1 = claims_from_payload(
        {
            "sub": "agent_agt_1",
            "iss": ISSUER,
            "aud": RESOURCE,
            "exp": 9999999999,
            "jit": True,
            "permissions": {
                "jit_request_id": "jit_req_1",
                "authorization_details": [{"type": "db_admin", "actions": ["drop"]}],
            },
        }
    )
    assert c1.is_jit is True
    assert c1.authorization_details == ({"type": "db_admin", "actions": ["drop"]},)


def test_require_jit_and_ensure_jit_with_jit_token_header():
    provider = make_provider()
    mcp = FastMCP("jit-test", auth=provider)

    @mcp.tool(auth=require_jit("payment_initiation", actions=["refund"]))
    def refund(invoice_id: str) -> str:
        ensure_jit("payment_initiation", actions=["refund"], identifier=invoice_id)
        return f"refunded {invoice_id}"

    app = mcp.http_app(path="/mcp", json_response=True, stateless_http=True)
    with TestClient(app, base_url=ORIGIN) as client:
        base_token = make_token({"sub": "user-123"})

        # 1. Without JIT grant, tool is hidden in tools/list and denied on tools/call
        list_resp = rpc(
            client,
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            {"Authorization": f"Bearer {base_token}"},
        )
        assert [t["name"] for t in list_resp.json()["result"]["tools"]] == []

        # 2. With a valid X-LumoAuth-Jit-Token for inv_42, tool is visible and succeeds for inv_42
        jit_token = make_token(
            {
                "sub": "user-123",
                "aud": ISSUER,
                "jit": True,
                "permissions": {
                    "jit_request_id": "jit_1",
                    "authorization_details": [
                        {
                            "type": "payment_initiation",
                            "actions": ["refund"],
                            "identifier": "inv_42",
                        }
                    ],
                },
            }
        )
        headers = {
            "Authorization": f"Bearer {base_token}",
            "X-LumoAuth-Jit-Token": jit_token,
        }
        list_resp2 = rpc(
            client,
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            headers,
        )
        assert [t["name"] for t in list_resp2.json()["result"]["tools"]] == ["refund"]

        ok_resp = call_tool(client, "refund", {"invoice_id": "inv_42"}, headers)
        assert ok_resp.json()["result"]["content"][0]["text"] == "refunded inv_42"

        # 3. Calling refund for a different invoice_id fails ensure_jit with authorization_details_hint
        bad_id_resp = call_tool(client, "refund", {"invoice_id": "inv_99"}, headers)
        assert bad_id_resp.json()["result"]["isError"] is True
        err_text = bad_id_resp.json()["result"]["content"][0]["text"]
        assert "insufficient_authorization_details" in err_text
        assert "inv_99" in err_text

        # 4. A JIT token belonging to a different subject is ignored
        other_jit = make_token(
            {
                "sub": "user-other",
                "jit": True,
                "authorization_details": [{"type": "payment_initiation", "actions": ["refund"]}],
            }
        )
        list_resp3 = rpc(
            client,
            {"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
            {"Authorization": f"Bearer {base_token}", "X-LumoAuth-Jit-Token": other_jit},
        )
        assert [t["name"] for t in list_resp3.json()["result"]["tools"]] == []


def test_policy_jit_surfaces_insufficient_authorization_details():
    provider = make_provider()
    fake = SimpleNamespace(authorize_tool=lambda *a, **kw: SimpleNamespace(allowed=True))
    policy = LumoToolPolicy(
        provider=provider,
        client=SimpleNamespace(mcp=fake),
        jit={"refund": {"type": "payment_initiation", "actions": ["refund"]}},
    )
    mcp = FastMCP("policy-jit", auth=provider, middleware=[policy])

    @mcp.tool
    def refund(invoice_id: str) -> str:
        return f"refunded {invoice_id}"

    app = mcp.http_app(path="/mcp", json_response=True, stateless_http=True)
    with TestClient(app, base_url=ORIGIN) as client:
        # Denied without JIT
        denied = call_tool(
            client,
            "refund",
            {"invoice_id": "inv_1"},
            {"Authorization": f"Bearer {make_token()}"},
        )
        body = denied.json()
        raw = json.dumps(body)
        assert "insufficient_authorization_details" in raw
        assert "payment_initiation" in raw

        # Allowed when token carries authorization_details
        jit_tok = make_token(
            {"authorization_details": [{"type": "payment_initiation", "actions": ["refund"]}]}
        )
        allowed = call_tool(
            client,
            "refund",
            {"invoice_id": "inv_1"},
            {"Authorization": f"Bearer {jit_tok}"},
        )
        assert allowed.json()["result"]["content"][0]["text"] == "refunded inv_1"


# ── Token Vault Helper ───────────────────────────────────────────────


def test_vault_user_id_resolution():
    human = claims_from_payload({"sub": "user-123", "is_agent": False})
    delegated = claims_from_payload(
        {"sub": "user-123", "is_agent": False, "act": {"sub": "agent_agt_1"}}
    )
    autonomous = claims_from_payload({"sub": "agent_agt_1", "is_agent": True})

    assert resolve_vault_user_id(human) == "user-123"
    assert resolve_vault_user_id(delegated) == "user-123"
    assert resolve_vault_user_id(autonomous) is None
    assert resolve_vault_user_id(autonomous, explicit_user_id="user-override") == "user-override"


def test_provider_vault_token_inside_tool_and_caching():
    calls: List[Tuple[str, str, Dict[str, str], Optional[Dict[str, Any]]]] = []

    def fake_vault_request(
        method: str, url: str, headers: Dict[str, str], payload: Optional[Dict[str, Any]]
    ):
        calls.append((method, url, headers, payload))
        return 200, {
            "access_token": f"gho_token_{len(calls)}",
            "token_type": "Bearer",
            "expires_at": "2099-01-01T00:00:00Z",
            "scopes": ["repo", "read:user"],
        }

    provider = make_provider(agent_token="agk_test_token")
    vault = provider.vault(request_fn=fake_vault_request)
    provider._vault_client = vault

    mcp = FastMCP("vault-test", auth=provider)

    @mcp.tool
    def github_Action() -> dict:
        tok1 = provider.vault_token("conn_github")
        tok2 = provider.vault_token("conn_github")  # should hit cache
        return {
            "token": str(tok1),
            "same": tok1.access_token == tok2.access_token,
            "user_id": tok1.user_id,
            "scopes": list(tok1.scopes),
            "headers": tok1.headers(),
        }

    tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    app = mcp.http_app(path="/mcp", json_response=True, stateless_http=True)
    with TestClient(app, base_url=ORIGIN) as client:
        # 1. Delegated user call automatically passes user_id = "user-123" and traceparent
        delegated_token = make_token(
            {"sub": "user-123", "act": {"sub": "agent_agt_42", "sub_profile": "ai_agent"}}
        )
        resp = call_tool(
            client,
            "github_Action",
            {},
            {"Authorization": f"Bearer {delegated_token}", "traceparent": tp},
        )
        assert resp.status_code == 200
        result = json.loads(resp.json()["result"]["content"][0]["text"])
        assert result == {
            "token": "gho_token_1",
            "same": True,
            "user_id": "user-123",
            "scopes": ["repo", "read:user"],
            "headers": {"Authorization": "Bearer gho_token_1"},
        }
        assert len(calls) == 1
        assert calls[0][0] == "POST"
        assert calls[0][1] == f"{ISSUER}/agents/me/connections/conn_github/token"
        assert calls[0][2]["Authorization"] == "Bearer agk_test_token"
        assert calls[0][2]["traceparent"] == tp
        assert calls[0][3] == {"user_id": "user-123"}

        # 2. Autonomous agent call sends empty payload (no user_id) and does not collide with user cache
        agent_token = make_token({"sub": "agent_agt_42", "is_agent": True})
        resp2 = call_tool(
            client,
            "github_Action",
            {},
            {"Authorization": f"Bearer {agent_token}"},
        )
        result2 = json.loads(resp2.json()["result"]["content"][0]["text"])
        assert result2["token"] == "gho_token_2"
        assert result2["user_id"] is None
        assert len(calls) == 2
        assert calls[1][3] == {}
