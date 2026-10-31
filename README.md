# LumoAuth for FastMCP

`lumoauth-fastmcp` adds LumoAuth sign-in and authorization to a
[FastMCP](https://gofastmcp.com) server.

```python
from fastmcp import FastMCP
from lumoauth_fastmcp import LumoAuthProvider

mcp = FastMCP("Invoices", auth=LumoAuthProvider())
```

With `LUMOAUTH_ORG_ID` and `LUMOAUTH_MCP_SERVER_ID` in the environment, that
is the whole integration. Claude, ChatGPT, VS Code, Cursor and any other
MCP client that follows the MCP authorization specification can now sign
users in through LumoAuth and call the server with a token that LumoAuth
issued for it.

## How it works

LumoAuth is the authorization server. It registers MCP clients (Client ID
Metadata Documents, or dynamic client registration), shows the consent
screen, and issues access tokens whose audience is your server's Resource
URI. Your FastMCP server stays a pure resource server, and the provider
gives it what the MCP specification asks of one:

- **Discovery.** The server publishes protected resource metadata
  (RFC 9728) at `/.well-known/oauth-protected-resource/...`, naming your
  LumoAuth organization as the authorization server.
- **Challenges.** A request without a valid token gets `401` with a
  `WWW-Authenticate` header that points the client at that document. The
  challenge names the scopes that the registration advertises, and it
  states the real reason when a token is refused (expired, wrong audience,
  replayed DPoP proof, and so on).
- **Verification.** Tokens are verified locally: signature against the
  organization's keys, issuer, audience, expiry, `at+jwt` type, and no
  portal test tokens. A DPoP-bound token (RFC 9449) must arrive with the
  `DPoP` scheme and a fresh proof for this request.
- **Identity.** Tools can see who is calling: a user, an AI agent, or an
  agent acting for a user.

The provider reads the server's registration from LumoAuth once at start-up:
the Resource URI, the advertised scopes, and whether only DPoP-bound tokens
are accepted. Restart the server after you change the registration.

## Setup

1. In the LumoAuth portal, open **AI Agents → MCP servers** and register
   the server. The **Resource URI** is the URL that clients connect to,
   for example `https://invoices.example.com/mcp`. For local development,
   register a second server with `http://localhost:8000/mcp`, because a
   token for one Resource URI does not work at another.
2. Install the package:

   ```bash
   pip install lumoauth-fastmcp
   ```

3. Set the organization and the server id that the portal shows:

   ```bash
   export LUMOAUTH_ORG_ID=acme
   export LUMOAUTH_MCP_SERVER_ID=mcp_0123456789abcdef01234567
   ```

   For the EU region, also set `LUMOAUTH_URL=https://eu.app.lumoauth.dev`.

4. Add the provider and run the server over HTTP:

   ```python
   mcp = FastMCP("Invoices", auth=LumoAuthProvider())

   if __name__ == "__main__":
       mcp.run(transport="http", port=8000)
   ```

Authentication applies to HTTP transports. A server that runs over stdio
is started by the user's own MCP client and has no OAuth step.

## Who is calling

`current_caller()` returns the verified claims of the current request as
`lumoauth.verify.AccessTokenClaims`, the same object that
`verify_access_token` in the LumoAuth Python SDK returns:

```python
from lumoauth_fastmcp import current_caller

@mcp.tool
def list_invoices() -> list[dict]:
    caller = current_caller()
    if caller.is_agent:
        log.info("agent %s", caller.agent_id)          # "agt_…"
    elif caller.is_delegated:
        log.info("agent %s for user %s", caller.actor, caller.sub)
    return invoices_for(caller.sub)
```

`current_caller()` returns `None` on transports without OAuth, such as stdio
and in-memory clients.

## Scopes and callers

The checks plug into FastMCP's `auth=` argument and into `AuthMiddleware`.
They follow LumoAuth's rule: a granted scope that ends in `:*` (such as
`invoices:*`) covers the scopes under it, such as `invoices:refund`, and
every other scope compares exactly. Prefer narrow scopes: the MCP security
best practices list wildcard scopes as a common mistake.

```python
from fastmcp.server.middleware import AuthMiddleware
from lumoauth_fastmcp import require_agent, require_scopes, require_user

@mcp.tool(auth=require_scopes("invoices:refund"))
def refund(invoice_id: str) -> str: ...

@mcp.tool(auth=require_user())                       # people only, no agents
def change_bank_details(iban: str) -> str: ...

@mcp.tool(auth=require_agent("billing.reminders"))   # agents with this capability
def send_reminder(invoice_id: str) -> str: ...
```

`require_user(allow_delegation=True)` also admits an agent that acts for a
person.

A component-level check hides the component from callers who fail it. To
get an `insufficient_scope` step-up instead, so that the client can ask the
user for the missing scope, put the scope check in `AuthMiddleware`:

```python
mcp = FastMCP(
    "Invoices",
    auth=LumoAuthProvider(),
    middleware=[AuthMiddleware(auth=require_scopes("invoices:read"))],
)
```

## Per-tool policy from LumoAuth

A valid token proves that the caller may reach the server. Whether that
user or agent may run a particular tool can also be a policy that you
manage in LumoAuth (roles, relationships, ABAC rules, agent capabilities).
`tool_policy()` asks LumoAuth before every tool call and hides the tools
that a caller may not run:

```python
auth = LumoAuthProvider()
mcp = FastMCP("Invoices", auth=auth, middleware=[auth.tool_policy()])
```

The server asks as itself. It never forwards the caller's token, which the
MCP specification forbids. Set this up once:

1. Create an OAuth client for the MCP server with the `client_credentials`
   grant and the `mcp:authorize` scope.
2. Edit the MCP server in the portal. In the step **Who may connect and
   how**, select that client under **Per-tool authorization**.
3. Give the server its credentials:

   ```bash
   export LUMOAUTH_MCP_CLIENT_ID=...
   export LUMOAUTH_MCP_CLIENT_SECRET=...
   ```

Decisions are cached for 30 seconds (`tool_policy(cache_ttl=...)`), so a
policy change takes effect within that time. When LumoAuth cannot be
reached, the tool is refused.

## DPoP

When the registration has **Require DPoP** switched on, the server accepts
only DPoP-bound tokens and challenges with the `DPoP` scheme. Bound tokens
are checked on every server, whatever the switch says. Proof ids are
remembered per process to stop replays; with several workers, pass a shared
store:

```python
LumoAuthProvider(replay_cache=MyRedisReplayCache())
```

The store has one method, `check_and_add(key, ttl)`. It returns `True` for a
key that it already holds, which means a replay. Otherwise it stores the key
for `ttl` seconds and returns `False`.

The proof's `htu` must equal the URL that the client called. The provider
builds that URL from the origin of the Resource URI and the request path,
which suits a TLS-terminating proxy that keeps paths. For a proxy that
rewrites paths, pass `request_url=`.

## Configuration

Every argument is optional and falls back to an environment variable.

| Argument | Environment variable | Default |
| --- | --- | --- |
| `org_id` | `LUMOAUTH_ORG_ID` | required unless `issuer` is set |
| `server_id` | `LUMOAUTH_MCP_SERVER_ID` | none; without it pass `resource` |
| `resource` | `LUMOAUTH_MCP_RESOURCE` | from the registration |
| `lumoauth_url` | `LUMOAUTH_URL` | `https://app.lumoauth.dev` |
| `issuer` | `LUMOAUTH_ISSUER` | `{lumoauth_url}/orgs/{org_id}/api/v1` (set it for a custom domain) |
| `client_id`, `client_secret` | `LUMOAUTH_MCP_CLIENT_ID`, `LUMOAUTH_MCP_CLIENT_SECRET` | only for `tool_policy()` |
| `base_url` | | origin of the Resource URI |
| `required_scopes` | | none |
| `scopes_supported` | | the registration's basic scopes |
| `require_dpop` | | the registration's **Require DPoP** switch |
| `authorization_server_metadata` | | `True`: also serve LumoAuth's metadata at `/.well-known/oauth-authorization-server` for older clients |

## Requirements

Python 3.10 or later. The package installs FastMCP 4 (4.1 or later) and the
LumoAuth Python SDK 1.2 or later, the first release with `lumoauth.verify`.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest
```
