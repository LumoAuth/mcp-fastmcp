"""An invoices MCP server protected by LumoAuth.

Run it with the organization and the registered server id in the
environment (register http://localhost:8000/mcp as the Resource URI for
local development):

    LUMOAUTH_ORG_ID=acme LUMOAUTH_MCP_SERVER_ID=mcp_... python examples/invoices_server.py

Add LUMOAUTH_MCP_CLIENT_ID / LUMOAUTH_MCP_CLIENT_SECRET to let LumoAuth's
per-tool policy decide who may run which tool.
"""

from __future__ import annotations

import os

from fastmcp import FastMCP
from fastmcp.server.middleware import AuthMiddleware

from lumoauth_fastmcp import LumoAuthProvider, current_caller, require_scopes, require_user

auth = LumoAuthProvider()

middleware = [AuthMiddleware(auth=require_scopes("mcp:read"))]
if os.environ.get("LUMOAUTH_MCP_CLIENT_ID"):
    middleware.append(auth.tool_policy())

mcp = FastMCP("Invoices", auth=auth, middleware=middleware)

INVOICES = {
    "inv_1": {"id": "inv_1", "customer": "Northwind", "amount": 1200, "status": "open"},
    "inv_2": {"id": "inv_2", "customer": "Contoso", "amount": 300, "status": "paid"},
}


@mcp.tool
def list_invoices() -> list[dict]:
    """List open and paid invoices."""
    return list(INVOICES.values())


@mcp.tool
def whoami() -> dict:
    """Show who LumoAuth says is calling."""
    caller = current_caller()
    if caller is None:
        return {"transport": "stdio"}
    return {
        "subject": caller.sub,
        "agent": caller.agent_id,
        "acting_for": caller.sub if caller.is_delegated else None,
        "actor": caller.actor,
        "scopes": list(caller.scopes),
    }


@mcp.tool(auth=require_scopes("invoices:refund"))
def refund(invoice_id: str) -> str:
    """Refund an invoice. Needs the invoices:refund scope."""
    invoice = INVOICES[invoice_id]
    invoice["status"] = "refunded"
    return f"Refunded {invoice['amount']} to {invoice['customer']}"


@mcp.tool(auth=require_user())
def change_bank_details(iban: str) -> str:
    """Change the payout account. Only a person may do this, never an agent."""
    return f"Payout account changed to {iban[:4]}…"


if __name__ == "__main__":
    mcp.run(transport="http", host="127.0.0.1", port=8000)
