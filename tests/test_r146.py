"""R146: credentials stay human-initiated.
(a) `fenrir_api` refuses every verb on token / session / user-credential endpoints,
    whatever the path encoding; (b) `fenrir-mcp login` still mints its token on the
    interactive cookie session (never with a Bearer)."""
import httpx
import pytest

from fenrir_mcp import cli, config, denylist, openapi_guard, token_store
from fenrir_mcp.client import FenrirError

VERBS = ("GET", "POST", "PATCH", "PUT", "DELETE")
TID = "0b9c3c1e-5f0a-4c55-9a52-2f7c7a8d1e01"

# Every verb on these is refused.
ALL_VERBS = [
    "/api/tokens", f"/api/tokens/{TID}",
    "/api/admin/tokens", f"/api/admin/tokens/{TID}",
    "/api/sessions", f"/api/sessions/{TID}", "/api/sessions/revoke-others", f"/api/sessions/{TID}/label",
    "/api/admin/sessions", f"/api/admin/sessions/{TID}",
    f"/api/users/{TID}/sessions", f"/api/users/{TID}/sessions/{TID}", f"/api/users/{TID}/sessions/revoke-all",
    f"/api/users/{TID}/reset-password", f"/api/users/{TID}/unlock",
    "/api/integrations/siem-key", "/api/integrations/siem-key/generate",
]
# Only these verbs are refused (reads stay: status, user lookup for assignment).
WRITES_ONLY = [
    (("POST", "PATCH", "PUT", "DELETE"), "/api/users"),
    (("POST", "PATCH", "PUT", "DELETE"), f"/api/users/{TID}"),
    (("PUT", "DELETE"), "/api/settings/api-keys/virustotal"),
]
BYPASSES = [
    "/API/TOKENS", "/Api/Admin/Tokens/" + TID,
    "/api/tokens/", "/api/tokens//", "//api//tokens",
    "/api/tokens?limit=1", "/api/tokens#x", "/api/tokens;x",
    "/api/%74okens", "/api/tokens%2F" + TID, "/api%2Ftokens", "/api/%2574okens", "/api/%252574okens",
    "/api/incidents/x/../../tokens", "/api/incidents/x/%2e%2e/%2e%2e/tokens", "/api/./tokens",
    "api/tokens", "/api/admin/./tokens", "/api/users/x/../../sessions",
]
ALLOWED = [
    ("GET", "/api/users/me"), ("GET", "/api/users/assignable"), ("GET", "/api/users"),
    ("GET", f"/api/users/{TID}"), ("GET", f"/api/users/{TID}/activity"), ("GET", "/api/settings/api-keys"),
    ("GET", "/api/incidents"), ("POST", "/api/incidents"), ("GET", "/api/tokensmith"),
]


@pytest.fixture
def spec(monkeypatch):
    """Every probed operation exists in the spec, so only the credential gate can refuse."""
    paths = {p: {v.lower(): {} for v in VERBS} for p in (
        "/api/tokens", "/api/tokens/{token_id}", "/api/admin/tokens", "/api/admin/tokens/{token_id}",
        "/api/sessions", "/api/sessions/{id}", "/api/sessions/{id}/label", "/api/admin/sessions",
        "/api/admin/sessions/{id}", "/api/users", "/api/users/{id}", "/api/users/{id}/sessions",
        "/api/users/{id}/sessions/{sid}", "/api/users/{id}/reset-password", "/api/users/{id}/unlock",
        "/api/users/{id}/activity", "/api/users/me", "/api/users/assignable", "/api/integrations/siem-key",
        "/api/integrations/siem-key/generate", "/api/settings/api-keys", "/api/settings/api-keys/{service}",
        "/api/incidents", "/api/tokensmith")}
    monkeypatch.setattr(openapi_guard, "_ops", openapi_guard._compile({"paths": paths}))


def _refused(verb, path):
    with pytest.raises(FenrirError) as e:
        openapi_guard.validate(verb, path, "full")
    return str(e.value)


@pytest.mark.parametrize("path", ALL_VERBS)
@pytest.mark.parametrize("verb", VERBS)
def test_every_verb_refused(spec, verb, path):
    msg = _refused(verb, path)
    assert "credential and auth management is human-only" in msg and "fenrir-mcp tokens" in msg


@pytest.mark.parametrize("verbs,path", WRITES_ONLY)
def test_credential_writes_refused(spec, verbs, path):
    for verb in verbs:
        assert "human-only" in _refused(verb, path)


@pytest.mark.parametrize("path", BYPASSES)
@pytest.mark.parametrize("verb", ("GET", "POST", "DELETE"))
def test_normalisation_bypasses_refused(spec, verb, path):
    assert "human-only" in _refused(verb, path)


@pytest.mark.parametrize("verb,path", ALLOWED)
def test_non_credential_paths_still_allowed(spec, verb, path):
    openapi_guard.validate(verb, path, "full")


def test_refused_even_in_readonly_mode_with_the_clear_message(spec):
    assert "human-only" in _refused("GET", "/api/tokens")
    assert "human-only" in _refused("DELETE", "/api/admin/tokens/" + TID)


def test_cli_tokens_subcommands_untouched():
    # The terminal CLI keeps list/revoke on the stored Bearer (test_tokens_cli.py);
    # the shared hard denylist still lets curated code list/revoke and never create.
    assert denylist.is_denied("POST", "/api/tokens")
    assert denylist.is_denied("GET", "/api/tokens") is None
    assert hasattr(cli, "tokens_list") and hasattr(cli, "tokens_revoke")


# ── login: password + TOTP on a cookie session, then POST /api/tokens on that session ──

LOGIN_SEEN = []


def _server(request: httpx.Request) -> httpx.Response:
    LOGIN_SEEN.append((request.method, request.url.path, request.headers.get("authorization"),
                       request.headers.get("cookie") or ""))
    p, m = request.url.path, request.method
    if m == "POST" and p == "/api/auth/login":
        return httpx.Response(200, json={"status": "totp_required", "requires_totp": True},
                              headers={"set-cookie": "fenrir_totp_pending=pend; Path=/; Secure; HttpOnly"})
    if m == "POST" and p == "/api/auth/totp/verify":
        return httpx.Response(200, json={"status": "ok"},
                              headers={"set-cookie": "fenrir_session=sess; Path=/; Secure; HttpOnly"})
    if m == "GET" and p == "/api/users/me":
        return httpx.Response(200, json={"role": "analyst"})
    if m == "POST" and p == "/api/tokens":
        # The R146 server rule: a Bearer create is refused; only the session may mint.
        if request.headers.get("authorization"):
            return httpx.Response(403, json={"detail": "needs session", "code": "token_create_requires_session"})
        if "fenrir_session=sess" not in (request.headers.get("cookie") or ""):
            return httpx.Response(401, json={"detail": "Not authenticated", "code": "not_authenticated"})
        return httpx.Response(200, json={"id": TID, "token": "fnr_v1_minted", "token_prefix": "fnr_v1_minte",
                                         "expires_at": "2026-10-08T10:00:00Z"})
    if m == "POST" and p == "/api/auth/logout":
        return httpx.Response(200, json={})
    return httpx.Response(500)


def test_login_mints_on_the_cookie_session(monkeypatch, tmp_path):
    LOGIN_SEEN.clear()
    monkeypatch.setenv("FENRIR_URL", "https://fenrir.test")
    answers = iter(["alice", "123456", ""])           # username, TOTP code, role (Enter = default)
    monkeypatch.setattr("builtins.input", lambda *_: next(answers))
    monkeypatch.setattr(cli.getpass, "getpass", lambda *_: "pw")
    monkeypatch.setattr(token_store, "_keyring", lambda: None)   # never touch the real OS keyring
    monkeypatch.setattr(cli, "_client", lambda: httpx.Client(base_url="https://fenrir.test",
                                                             transport=httpx.MockTransport(_server)))
    assert cli.login() == 0
    mint = [s for s in LOGIN_SEEN if s[:2] == ("POST", "/api/tokens")]
    assert len(mint) == 1 and mint[0][2] is None and "fenrir_session=sess" in mint[0][3]
    assert all(s[2] is None for s in LOGIN_SEEN)           # no Bearer anywhere in the login flow
    assert token_store.load_token() == "fnr_v1_minted"
    assert str(config.config_dir()).startswith(str(tmp_path))
    assert token_store.load_meta()["token_id"] == TID
