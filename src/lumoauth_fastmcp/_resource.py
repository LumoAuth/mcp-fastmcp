"""Resource URI helpers.

LumoAuth puts the client's ``resource`` parameter into the token's ``aud``
as the client spelled it. An MCP client may send ``https://mcp.example.com``
or ``https://mcp.example.com/`` for the same registration, so audiences are
compared the way LumoAuth compares resource URIs, not byte for byte.
"""

from __future__ import annotations

from typing import Any, Iterable, List
from urllib.parse import urlsplit

__all__ = ["normalize_resource", "same_resource", "origin_of", "matching_audiences"]


def normalize_resource(uri: str) -> str:
    """Comparison form of a resource URI, as LumoAuth computes it.

    The scheme and host are lower-cased, a default port is dropped, trailing
    slashes are stripped from the path, the query is kept and the fragment
    is dropped. Path and query case stay significant.
    """
    uri = uri.strip()
    try:
        parts = urlsplit(uri)
        port = parts.port
    except ValueError:
        return uri.rstrip("/")
    if not parts.scheme or not parts.hostname:
        return uri.rstrip("/")
    scheme = parts.scheme.lower()
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        port = None
    out = f"{scheme}://{host}" + (f":{port}" if port is not None else "")
    out += parts.path.rstrip("/")
    if parts.query:
        out += "?" + parts.query
    return out


def same_resource(a: str, b: str) -> bool:
    """``True`` when two resource URIs name the same resource."""
    return normalize_resource(a) == normalize_resource(b)


def origin_of(url: str) -> str:
    """``scheme://host[:port]`` of an absolute URL."""
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def matching_audiences(aud: Any, resource: str) -> List[str]:
    """The entries of an ``aud`` claim that name *resource*, in token order."""
    values: Iterable[Any]
    if isinstance(aud, str):
        values = [aud]
    elif isinstance(aud, list):
        values = aud
    else:
        return []
    return [a for a in values if isinstance(a, str) and a and same_resource(a, resource)]
