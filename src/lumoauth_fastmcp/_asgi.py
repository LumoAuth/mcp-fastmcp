"""HTTP layer: DPoP-scheme requests and precise ``WWW-Authenticate`` challenges.

FastMCP's bearer middleware only understands ``Authorization: Bearer``, and
a token verifier only receives the token string. LumoAuth tokens can be
DPoP-bound (RFC 9449), whose check needs the request method, URL and
``DPoP`` proof. This middleware runs first:

1. It records the request facts for the DPoP check in a context variable
   that :meth:`LumoAuthProvider.verify_token` reads.
2. It presents a ``DPoP`` scheme credential to FastMCP as ``Bearer`` so the
   standard machinery runs; the verifier still insists on the DPoP scheme
   for a bound token, because it sees the original scheme.
3. On a 401/403 it rewrites the challenge: the ``DPoP`` scheme with
   ``algs`` when the server requires DPoP, and the real reason a token was
   refused instead of a generic message.
"""

from __future__ import annotations

import re
from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from lumoauth.errors import LumoAuthTokenError
from starlette.types import ASGIApp, Message, Receive, Scope, Send

if TYPE_CHECKING:  # pragma: no cover
    from lumoauth_fastmcp.provider import LumoAuthProvider

__all__ = [
    "RequestAuth",
    "current_request_auth",
    "current_traceparent",
    "current_trace_id",
    "LumoAuthHttpMiddleware",
    "parse_authorization",
    "parse_traceparent",
]

_TRACEPARENT_RE = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")
_ZERO_TRACE_ID = "0" * 32
_ZERO_SPAN_ID = "0" * 16


def parse_traceparent(value: Optional[str]) -> Optional[Tuple[str, str]]:
    """Validate a W3C ``traceparent`` header and return ``(traceparent, trace_id)``."""
    if not value or not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    match = _TRACEPARENT_RE.match(normalized)
    if not match:
        return None
    trace_id, span_id, _flags = match.group(1), match.group(2), match.group(3)
    if trace_id == _ZERO_TRACE_ID or span_id == _ZERO_SPAN_ID:
        return None
    return normalized, trace_id


@dataclass
class RequestAuth:
    """What the verifier needs to know about the request it verifies."""

    method: str
    url: str
    proof: Optional[str]
    scheme: Optional[str]
    failure: Optional[LumoAuthTokenError] = None
    traceparent: Optional[str] = None
    trace_id: Optional[str] = None
    jit_token: Optional[str] = None
    jit_failure: Optional[Any] = None


current_request_auth: ContextVar[Optional[RequestAuth]] = ContextVar(
    "lumoauth_fastmcp_request_auth", default=None
)


def current_traceparent() -> Optional[str]:
    """The validated W3C ``traceparent`` header of the active HTTP request, if any."""
    state = current_request_auth.get()
    return state.traceparent if state is not None else None


def current_trace_id() -> Optional[str]:
    """The 32-hex W3C trace ID of the active HTTP request, if any."""
    state = current_request_auth.get()
    return state.trace_id if state is not None else None


def parse_authorization(value: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Split an ``Authorization`` value into ``("Bearer" | "DPoP", token)``."""
    if not value:
        return None, None
    parts = value.strip().split(None, 1)
    if len(parts) != 2 or not parts[1].strip():
        return None, None
    scheme = parts[0].lower()
    if scheme == "bearer":
        return "Bearer", parts[1].strip()
    if scheme == "dpop":
        return "DPoP", parts[1].strip()
    return None, None


def _header(headers: List[Tuple[bytes, bytes]], name: bytes) -> Optional[str]:
    for key, value in headers:
        if key.lower() == name:
            return value.decode("latin-1")
    return None


_PARAM = re.compile(r'([A-Za-z_][A-Za-z0-9_-]*)="((?:[^"\\]|\\.)*)"')
_PARAM_ORDER = ("error", "error_description", "scope", "resource_metadata", "algs")


def _quoted(value: str) -> str:
    # RFC 6750 §3: no '"' or '\' inside a quoted value, single line.
    cleaned = value.replace("\\", "").replace('"', "'")
    return " ".join(cleaned.split())


def rewrite_challenge(
    original: str,
    *,
    failure: Optional[LumoAuthTokenError],
    require_dpop: bool,
    dpop_algs: Tuple[str, ...],
    status: int,
) -> str:
    """Rebuild a ``WWW-Authenticate`` value with LumoAuth's view of the failure."""
    params: Dict[str, str] = {key: value for key, value in _PARAM.findall(original)}
    if failure is not None and status == 401:
        params["error"] = failure.error
        params["error_description"] = failure.message
    dpop_failure = failure is not None and failure.scheme.lower() == "dpop"
    scheme = "DPoP" if (require_dpop or dpop_failure) else "Bearer"
    if scheme == "DPoP":
        params["algs"] = " ".join(dpop_algs)
    else:
        params.pop("algs", None)
    ordered = [key for key in _PARAM_ORDER if key in params] + [
        key for key in params if key not in _PARAM_ORDER
    ]
    if not ordered:
        return scheme
    return scheme + " " + ", ".join(f'{key}="{_quoted(params[key])}"' for key in ordered)


class LumoAuthHttpMiddleware:
    """Pure ASGI middleware installed in front of FastMCP's authentication."""

    def __init__(self, app: ASGIApp, provider: "LumoAuthProvider") -> None:
        self.app = app
        self.provider = provider

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers: List[Tuple[bytes, bytes]] = list(scope.get("headers") or [])
        scheme, token = parse_authorization(_header(headers, b"authorization"))
        tp_parsed = parse_traceparent(_header(headers, b"traceparent"))
        jit_raw = _header(headers, b"x-lumoauth-jit-token")
        state = RequestAuth(
            method=str(scope.get("method") or "GET"),
            url=self.provider.request_url(scope),
            proof=_header(headers, b"dpop"),
            scheme=scheme,
            traceparent=tp_parsed[0] if tp_parsed else None,
            trace_id=tp_parsed[1] if tp_parsed else None,
            jit_token=jit_raw.strip() if jit_raw and jit_raw.strip() else None,
        )
        if scheme == "DPoP" and token:
            rewritten = [(k, v) for (k, v) in headers if k.lower() != b"authorization"]
            rewritten.append((b"authorization", b"Bearer " + token.encode("latin-1")))
            scope = {**scope, "headers": rewritten}

        reset = current_request_auth.set(state)
        try:
            await self.app(scope, receive, self._send(send, state))
        finally:
            current_request_auth.reset(reset)

    def _send(self, send: Send, state: RequestAuth) -> Send:
        provider = self.provider

        async def wrapped(message: Message) -> None:
            if message["type"] == "http.response.start" and message.get("status") in (401, 403):
                headers: List[Tuple[bytes, bytes]] = list(message.get("headers") or [])
                for index, (key, value) in enumerate(headers):
                    if key.lower() == b"www-authenticate":
                        challenge = rewrite_challenge(
                            value.decode("latin-1"),
                            failure=state.failure,
                            require_dpop=provider.require_dpop,
                            dpop_algs=provider.dpop_algs,
                            status=int(message["status"]),
                        )
                        if state.jit_failure is not None and int(message["status"]) == 403:
                            challenge = rewrite_challenge(
                                f'Bearer error="insufficient_authorization_details", '
                                f'error_description="{_quoted(str(state.jit_failure))}"',
                                failure=None,
                                require_dpop=provider.require_dpop,
                                dpop_algs=provider.dpop_algs,
                                status=403,
                            )
                        headers[index] = (b"www-authenticate", challenge.encode("latin-1"))
                        break
                if state.jit_failure is not None and int(message["status"]) == 403:
                    hint_b64 = getattr(state.jit_failure, "header_value", None)
                    if isinstance(hint_b64, str) and hint_b64:
                        headers.append(
                            (b"insufficient-authorization-details", hint_b64.encode("latin-1"))
                        )
                message = {**message, "headers": headers}
            await send(message)

        return wrapped
