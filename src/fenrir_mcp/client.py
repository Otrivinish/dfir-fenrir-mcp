"""HTTP client to FENRIR: TLS 1.3 floor, pinned internal CA, bearer auth,
structured error mapping, expensive-call serialization. Fail closed everywhere."""

from __future__ import annotations

import asyncio
import ssl
from typing import Any

import httpx
from mcp.server.mcpserver.exceptions import ToolError

from . import config, denylist, refcache, token_store


class FenrirError(ToolError):
    """Subclasses the SDK's ToolError so mcp 2.x delivers the message to the
    model verbatim — anything else is masked to a bare 'Error executing tool'."""


def ssl_context() -> ssl.SSLContext:
    ca = config.ca_cert()
    if ca:
        ctx = ssl.create_default_context(cafile=ca)
        # Python 3.13+ enables VERIFY_X509_STRICT by default, which rejects the
        # generate-certs.sh CA (no keyUsage extension). With a pinned single-CA
        # trust store, chain + hostname verification still fully apply; only the
        # RFC 5280 formalities check is relaxed. Strict stays on for the system
        # trust store below.
        ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    else:
        ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


_client: httpx.AsyncClient | None = None
# The backend runs --workers 1: expensive synchronous endpoints are serialized
# so the MCP can never freeze FENRIR for other responders (threat model T7).
_expensive_gate = asyncio.Semaphore(1)


def _get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(
            base_url=config.fenrir_url(),
            verify=ssl_context(),
            timeout=httpx.Timeout(config.READ_TIMEOUT, connect=config.CONNECT_TIMEOUT),
            follow_redirects=False,
        )
    return _client


def _bearer() -> dict[str, str]:
    token = token_store.load_token()
    if not token:
        raise FenrirError("no stored FENRIR token — run `fenrir-mcp login` in a terminal")
    if not token_store.token_age_ok():
        raise FenrirError("stored token is older than 8 h (client-side TTL) — run `fenrir-mcp login` again")
    return {"Authorization": f"Bearer {token}"}


def _raise_for(resp: httpx.Response) -> None:
    detail = ""
    try:
        body = resp.json()
        detail = body.get("detail") or body.get("message") or ""
        if isinstance(detail, (list, dict)):
            detail = str(detail)
    except Exception:
        detail = resp.text[:300]
    code = resp.status_code
    if code == 401:
        raise FenrirError("FENRIR rejected the token (401) — run `fenrir-mcp login` again. " + detail)
    if code == 403:
        raise FenrirError(
            f"forbidden (403): the token's role cap or incident access does not allow this. "
            f"Token role ≤ FENRIR role; check `fenrir-mcp status`. {detail}"
        )
    if code == 429:
        retry = resp.headers.get("Retry-After", "?")
        raise FenrirError(f"rate limited (429), Retry-After: {retry}s. Not retrying automatically. {detail}")
    raise FenrirError(f"FENRIR returned {code}: {detail}")


async def request(
    method: str,
    path: str,
    *,
    params: dict | None = None,
    json: Any = None,
    files: dict | None = None,
    data: dict | None = None,
    expensive: bool = False,
) -> Any:
    # Incident ref memory: /api/incidents/INC-0006/… → /api/incidents/<uuid>/…,
    # learning the mapping from a single list fetch when the ref is new.
    path, missing = refcache.rewrite_path(path)
    if missing:
        await request("GET", "/api/incidents", params={"limit": 200})
        path, missing = refcache.rewrite_path(path)
        if missing:
            raise FenrirError(
                f"unknown incident ref {missing!r} — not in the first 200 incidents; "
                "use the incident UUID (fenrir_incident_list shows both)"
            )
    reason = denylist.is_denied(method, path)
    if reason:
        raise FenrirError(f"denied by policy: {reason}")
    headers = _bearer()
    try:
        if expensive:
            async with _expensive_gate:
                resp = await _get_client().request(
                    method, path, params=params, json=json, files=files, data=data, headers=headers
                )
        else:
            resp = await _get_client().request(
                method, path, params=params, json=json, files=files, data=data, headers=headers
            )
    except ssl.SSLError as e:
        raise FenrirError(
            f"TLS verification failed: {e}. Check FENRIR_CA_CERT points at the FENRIR internal CA. "
            "Verification is never disabled."
        ) from e
    except httpx.ConnectError as e:
        raise FenrirError(f"FENRIR unreachable at {config.fenrir_url()}: {e}. VPN up?") from e
    except httpx.TimeoutException as e:
        raise FenrirError(f"FENRIR timed out on {method} {path}: {e}") from e

    if resp.status_code >= 400:
        _raise_for(resp)
    if resp.status_code == 204 or not resp.content:
        return {"status": resp.status_code}
    ctype = resp.headers.get("content-type", "")
    if "application/json" in ctype:
        body = resp.json()
        if path.startswith("/api/incidents"):
            refcache.learn(body)
        return slim(body) if config.slim_enabled() else body
    return resp.text


def slim(obj):
    """Drop null / empty-string / empty-collection fields recursively — FENRIR's
    Pydantic models carry many, and each one costs context tokens on every call."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            s = slim(v)
            if s is None or s == "" or s == [] or s == {}:
                continue
            out[k] = s
        return out
    if isinstance(obj, list):
        return [slim(v) for v in obj]
    return obj
