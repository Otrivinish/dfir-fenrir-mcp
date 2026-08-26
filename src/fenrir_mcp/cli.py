"""Companion CLI: login (password + TOTP → mint 8 h token), logout (revoke), status.

The MCP server itself never touches passwords or TOTP — credential issuance is
exclusively this interactive flow (threat model: denylist bans POST /api/tokens).
"""

from __future__ import annotations

import getpass
import sys

import httpx

from . import config, token_store
from .client import ssl_context

# Least-privilege coupling (docs/DESIGN.md §5.2): the minted token defaults to
# the weakest role that serves the configured mode.
_ROLE_BY_MODE = {"readonly": "viewer", "standard": "analyst", "full": None}  # None = own role

TOKEN_NAME = "claude-mcp"


def _client() -> httpx.Client:
    return httpx.Client(
        base_url=config.fenrir_url(),
        verify=ssl_context(),
        timeout=httpx.Timeout(30.0, connect=config.CONNECT_TIMEOUT),
    )


def _fail(msg: str) -> int:
    print(f"error: {msg}", file=sys.stderr)
    return 1


def login(role: str | None = None, name: str = TOKEN_NAME) -> int:
    try:
        return _login(role, name)
    except httpx.TransportError as e:
        return _fail(
            f"cannot reach FENRIR at {config.fenrir_url()}: {e}\n"
            "  → VPN up? FENRIR_URL correct? For TLS errors, check FENRIR_CA_CERT "
            "in ~/.config/fenrir-mcp/env (verification is never disabled)."
        )


def _login(role: str | None, name: str) -> int:
    mode = config.mode()
    with _client() as c:
        username = input("FENRIR username: ").strip()
        password = getpass.getpass("Password: ")
        r = c.post("/api/auth/login", json={"username": username, "password": password})
        if r.status_code >= 400:
            return _fail(f"login failed ({r.status_code}): {r.json().get('detail', r.text[:200])}")
        if r.json().get("requires_totp"):
            code = input("TOTP code: ").strip()
            r = c.post("/api/auth/totp/verify", json={"code": code})
            if r.status_code >= 400:
                return _fail(f"TOTP verification failed ({r.status_code})")

        me = c.get("/api/users/me")
        if me.status_code >= 400:
            return _fail("could not resolve current user after login")
        my_role = me.json()["role"]
        default_role = _ROLE_BY_MODE[mode] or my_role
        if role:
            token_role = role
        else:
            # The server's FENRIR_MCP_MODE usually lives in .mcp.json and is NOT
            # visible in this terminal — so never mint silently on the fallback.
            print(f"account role: {my_role} · mode in this terminal: {mode}")
            print("pick the token's role cap (least privilege: viewer=reads, analyst=daily IR writes, admin=admin tools)")
            entered = input(f"Token role [viewer/analyst/admin] (Enter = {default_role}): ").strip().lower()
            token_role = entered or default_role
            if token_role not in ("viewer", "analyst", "admin"):
                return _fail(f"invalid role: {token_role}")

        # Server expiry is days-granular (min 1). One day is the server-side
        # backstop; the 8 h design TTL is enforced client-side (token_store).
        r = c.post(
            "/api/tokens",
            json={"name": name, "role": token_role, "expires_in_days": 1},
        )
        if r.status_code >= 400:
            return _fail(f"token issue failed ({r.status_code}): {r.json().get('detail', r.text[:200])}")
        issued = r.json()
        token = issued.get("token") or issued.get("plain_token") or issued.get("value")
        if not token:
            return _fail(f"token issue response had no token field (keys: {sorted(issued)})")

        location = token_store.store(
            token,
            {
                "url": config.fenrir_url(),
                "username": username,
                "token_id": str(issued.get("id", "")),
                "token_prefix": issued.get("token_prefix", token[:13]),
                "role": token_role,
                "expires_at": issued.get("expires_at"),
            },
        )
        c.post("/api/auth/logout")

    print(f"logged in as {username}; token role={token_role} (mode={mode}), stored in {location}")
    print("client-side TTL: 8 h (server backstop 24 h). `fenrir-mcp logout` revokes immediately.")
    if mode != "readonly" and token_role == "viewer":
        print(f"warning: mode={mode} but token role=viewer — write tools will 403", file=sys.stderr)
    return 0


def logout() -> int:
    token = token_store.load_token()
    meta = token_store.load_meta() or {}
    if token and meta.get("token_id"):
        try:
            with _client() as c:
                r = c.delete(
                    f"/api/tokens/{meta['token_id']}",
                    headers={"Authorization": f"Bearer {token}"},
                )
            print("token revoked server-side" if r.status_code < 400 else f"server revoke returned {r.status_code} — revoke via GUI Settings → API tokens")
        except Exception as e:
            print(f"server revoke failed ({e.__class__.__name__}) — revoke via GUI Settings → API tokens", file=sys.stderr)
    token_store.clear()
    print("local token store cleared")
    return 0


def status() -> int:
    meta = token_store.load_meta()
    if not meta:
        print("no token stored — run `fenrir-mcp login`")
        return 1
    fresh = token_store.token_age_ok()
    print(f"url:        {meta.get('url')}")
    print(f"user:       {meta.get('username')}")
    print(f"token:      {meta.get('token_prefix')}… role={meta.get('role')} storage={meta.get('storage')}")
    print(f"issued_at:  {meta.get('issued_at')} ({'fresh' if fresh else 'EXPIRED — 8 h client TTL'})")
    print(f"mode:       {config.mode()}")
    if fresh:
        token = token_store.load_token()
        try:
            with _client() as c:
                r = c.get("/api/users/me", headers={"Authorization": f"Bearer {token}"})
            print(f"server:     {'ok — ' + r.json().get('username', '?') if r.status_code < 400 else f'rejected ({r.status_code})'}")
        except Exception as e:
            print(f"server:     unreachable ({e.__class__.__name__})")
    return 0
