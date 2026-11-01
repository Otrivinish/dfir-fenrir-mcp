"""R144: `fenrir-mcp tokens list` / `tokens revoke <id>` — the operator's own tokens, via the stored Bearer."""
import httpx
import pytest

from fenrir_mcp import cli, token_store

SEEN = []


def _handler(request: httpx.Request) -> httpx.Response:
    SEEN.append((request.method, request.url.path, request.headers.get("authorization")))
    if request.method == "GET" and request.url.path == "/api/tokens":
        return httpx.Response(200, json={"items": [
            {"id": "t-1", "name": "claude-mcp", "token_prefix": "fnr_v1_abcdef", "role": "analyst",
             "status": "active", "expires_at": "2026-10-08T10:00:00Z", "last_used_at": None},
            {"id": "t-2", "name": "old", "token_prefix": "fnr_v1_zzzzzz", "role": "viewer",
             "status": "revoked", "expires_at": None, "last_used_at": "2026-10-01T09:00:00Z"}]})
    if request.method == "DELETE" and request.url.path == "/api/tokens/t-2":
        return httpx.Response(204)
    if request.method == "DELETE":
        return httpx.Response(404, json={"detail": "Token not found", "code": "token_not_found"})
    return httpx.Response(500)


@pytest.fixture
def stored(monkeypatch):
    SEEN.clear()
    monkeypatch.setattr(token_store, "token_age_ok", lambda: True)
    monkeypatch.setattr(token_store, "load_token", lambda: "fnr_v1_secret")
    monkeypatch.setattr(token_store, "load_meta", lambda: {"token_id": "t-1"})
    monkeypatch.setattr(cli, "_client", lambda: httpx.Client(base_url="https://fenrir.test",
                                                             transport=httpx.MockTransport(_handler)))


def test_list_uses_stored_bearer_and_marks_own(stored, capsys):
    assert cli.tokens_list() == 0
    out = capsys.readouterr().out
    assert SEEN == [("GET", "/api/tokens", "Bearer fnr_v1_secret")]
    assert "t-1" in out and "(this MCP)" in out and "revoked" in out and "never" in out
    assert "fnr_v1_secret" not in out


def test_revoke_own_token(stored, capsys):
    assert cli.tokens_revoke("t-2") == 0
    assert SEEN == [("DELETE", "/api/tokens/t-2", "Bearer fnr_v1_secret")]
    assert "revoked" in capsys.readouterr().out


def test_revoke_unknown_fails_with_server_detail(stored, capsys):
    assert cli.tokens_revoke("t-9") == 1
    assert "Token not found" in capsys.readouterr().err


def test_no_stored_token_never_calls_server(monkeypatch, capsys):
    SEEN.clear()
    monkeypatch.setattr(token_store, "token_age_ok", lambda: False)
    monkeypatch.setattr(token_store, "load_meta", lambda: None)
    assert cli.tokens_list() == 1 and cli.tokens_revoke("t-1") == 1
    assert SEEN == [] and "fenrir-mcp login" in capsys.readouterr().err


def test_no_mcp_tool_creates_tokens():
    from fenrir_mcp import denylist
    assert denylist.is_denied("POST", "/api/tokens")
