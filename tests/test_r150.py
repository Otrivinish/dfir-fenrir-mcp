"""R150/R151 (owner principle 2026-10-07): through the MCP the model never receives a
secret and never grants access; reducing/restoring access and reads stay.
(a) the curated FULL-mode tools no longer offer the granting/secret actions (schema-absent);
(b) their endpoints, plus SMTP/webhook/syslog config writes and team-member adds, are in
    the shared hard denylist — refused for curated tools AND `fenrir_api`, whatever the
    encoding; (c) member removal, unlock/session revoke/delete and the config reads still pass."""
import asyncio

import httpx
import pytest
from mcp.server.mcpserver import MCPServer

from fenrir_mcp import client, denylist, openapi_guard, tools
from fenrir_mcp.client import FenrirError
from fenrir_mcp.tools import admin

UID = "0b9c3c1e-5f0a-4c55-9a52-2f7c7a8d1e01"
TEAM = "6f1d2a3b-0c4d-4e5f-8a9b-0c1d2e3f4a5b"

REMOVED = {
    "fenrir_admin_users": {"create", "update", "reset_password"},
    "fenrir_admin_teams": {"member_add"},
    "fenrir_admin_platform": {"siem_key_generate", "api_key_set", "smtp_save", "syslog_save", "webhooks_save"},
}
KEPT = {
    "fenrir_admin_users": {"list", "get", "activity", "sessions", "teams", "unlock",
                           "revoke_session", "revoke_all_sessions", "delete"},
    "fenrir_admin_teams": {"team_create", "team_update", "team_delete", "member_remove",
                           "role_create", "role_update", "role_delete"},
    "fenrir_admin_platform": {"api_keys_status", "api_key_delete", "integration_get", "smtp_test",
                              "syslog_test", "siem_key_delete", "backups_list", "storage_usage",
                              "tokens_list", "token_revoke"},
}


@pytest.fixture(scope="module")
def schemas():
    mcp = MCPServer("t")
    tools.register_all(mcp, "full")
    return {t.name: t for t in asyncio.run(mcp.list_tools())}


@pytest.mark.parametrize("name", sorted(REMOVED))
def test_removed_actions_absent_from_schema(schemas, name):
    t = schemas[name]
    enum = set(t.input_schema["properties"]["action"]["enum"])
    assert not (REMOVED[name] & enum)
    assert not any(a in (t.description or "") for a in REMOVED[name])


@pytest.mark.parametrize("name", sorted(KEPT))
def test_kept_actions_present(schemas, name):
    assert KEPT[name] <= set(schemas[name].input_schema["properties"]["action"]["enum"])


# ── shared hard denylist ──────────────────────────────────────────────────────

BLOCKED = [
    ("POST", "/api/users"),
    ("PATCH", f"/api/users/{UID}"), ("PUT", f"/api/users/{UID}"),
    ("POST", f"/api/users/{UID}/reset-password"),
    ("POST", "/api/integrations/siem-key/generate"),
    ("PUT", "/api/settings/api-keys/virustotal"), ("POST", "/api/settings/api-keys/virustotal"),
    ("PUT", "/api/integrations/smtp"), ("POST", "/api/integrations/smtp"), ("PATCH", "/api/integrations/smtp"),
    ("PUT", "/api/integrations/webhooks"), ("POST", "/api/integrations/webhooks"),
    ("PUT", "/api/integrations/syslog"), ("PATCH", "/api/integrations/syslog"),
    ("POST", f"/api/teams/{TEAM}/members/{UID}"), ("PUT", f"/api/teams/{TEAM}/members/{UID}"),
    ("PATCH", f"/api/teams/{TEAM}/members/{UID}"), ("POST", f"/api/teams/{TEAM}/members"),
]
# Each must still hit the target endpoint on the wire, so each must be refused.
BYPASS_MEMBER = [
    f"/API/Teams/{TEAM}/Members/{UID}", f"/api/teams/{TEAM}/members/{UID}/", f"//api//teams/{TEAM}//members/{UID}",
    f"/api/teams/{TEAM}/members/{UID}?x=1", f"/api/teams/{TEAM}/members/{UID}#x", f"api/teams/{TEAM}/members/{UID}",
    f"/api/teams/{TEAM}/%6dembers/{UID}", f"/api/teams/{TEAM}/%256dembers/{UID}", f"/api/teams/{TEAM}%2Fmembers%2F{UID}",
    f"/api/incidents/x/../../teams/{TEAM}/members/{UID}", f"/api/incidents/%2e%2e/teams/{TEAM}/members/{UID}",
    f"/api/incidents%3F/../teams/{TEAM}/members/{UID}", f"/api/incidents%23/../teams/{TEAM}/members/{UID}",
    f"/api/incidents%253F/../teams/{TEAM}/members/{UID}",
]
BYPASS_SMTP = [
    "/API/INTEGRATIONS/SMTP", "/api/integrations/smtp/", "/api/integrations//smtp", "/api/integrations/%73mtp",
    "/api%2Fintegrations%2Fsmtp", "/api/integrations/smtp?x=1", "/api/integrations/./smtp",
    "/api/incidents/x%3F/../../integrations/smtp",
]
# R146's credential gate had the same "%3F" hole (normalise cut the path at the decoded "?").
BYPASS_CREDENTIAL = [f"/api/incidents/x%3F/../../admin/tokens/{UID}", "/api/incidents%23/../tokens"]
ALLOWED_API = [
    ("DELETE", f"/api/teams/{TEAM}/members/{UID}"), ("GET", f"/api/teams/{TEAM}/members"),
    ("GET", "/api/integrations/smtp"), ("GET", "/api/integrations/webhooks"), ("GET", "/api/integrations/syslog"),
    ("GET", "/api/settings/api-keys"), ("POST", "/api/integrations/smtp/test"),
    ("POST", "/api/integrations/syslog/test"), ("GET", "/api/users"), ("GET", f"/api/users/{UID}"),
    ("GET", f"/api/incidents/{UID}"),
]


@pytest.fixture
def spec(monkeypatch):
    """Every probed operation exists in the spec, so only the denylists can refuse."""
    verbs = ("get", "post", "put", "patch", "delete")
    paths = {p: {v: {} for v in verbs} for p in (
        "/api/users", "/api/users/{id}", "/api/users/{id}/reset-password", "/api/integrations/siem-key/generate",
        "/api/settings/api-keys", "/api/settings/api-keys/{service}", "/api/integrations/smtp",
        "/api/integrations/smtp/test", "/api/integrations/webhooks", "/api/integrations/syslog",
        "/api/integrations/syslog/test", "/api/teams/{team_id}/members", "/api/teams/{team_id}/members/{user_id}",
        "/api/incidents", "/api/incidents/{id}")}
    monkeypatch.setattr(openapi_guard, "_ops", openapi_guard._compile({"paths": paths}))


def _api_refused(verb, path):
    with pytest.raises(FenrirError, match="denied by policy"):
        openapi_guard.validate(verb, path, "full")


@pytest.mark.parametrize("verb,path", BLOCKED)
def test_blocked_in_shared_denylist_and_via_fenrir_api(spec, verb, path):
    assert denylist.is_denied(verb, path)          # curated tools: client.request applies this
    _api_refused(verb, path)


@pytest.mark.parametrize("path", BYPASS_MEMBER)
@pytest.mark.parametrize("verb", ("POST", "PUT", "PATCH"))
def test_member_add_bypasses_refused(spec, verb, path):
    assert denylist.is_denied(verb, path)
    _api_refused(verb, path)


@pytest.mark.parametrize("path", BYPASS_SMTP)
def test_smtp_write_bypasses_refused(spec, path):
    assert denylist.is_denied("PUT", path)
    _api_refused("PUT", path)


@pytest.mark.parametrize("path", BYPASS_CREDENTIAL)
def test_encoded_query_delimiter_no_longer_hides_a_credential_path(spec, path):
    _api_refused("DELETE", path)


@pytest.mark.parametrize("verb,path", ALLOWED_API)
def test_reads_and_access_reductions_still_pass_fenrir_api(spec, verb, path):
    assert denylist.is_denied(verb, path) is None
    openapi_guard.validate(verb, path, "full")


# ── curated tools on the wire ─────────────────────────────────────────────────

@pytest.fixture
def wire(monkeypatch):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.method, req.url.raw_path.decode()))
        return httpx.Response(200, json={"status": "ok"})
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    return seen


KEPT_CALLS = [
    (admin.fenrir_admin_users, dict(action="unlock", user_id=UID), ("POST", f"/api/users/{UID}/unlock")),
    (admin.fenrir_admin_users, dict(action="revoke_all_sessions", user_id=UID),
     ("POST", f"/api/users/{UID}/sessions/revoke-all")),
    (admin.fenrir_admin_users, dict(action="revoke_session", user_id=UID, session_id=TEAM),
     ("DELETE", f"/api/users/{UID}/sessions/{TEAM}")),
    (admin.fenrir_admin_users, dict(action="delete", user_id=UID), ("DELETE", f"/api/users/{UID}")),
    (admin.fenrir_admin_users, dict(action="get", user_id=UID), ("GET", f"/api/users/{UID}")),
    (admin.fenrir_admin_teams, dict(action="member_remove", team_id=TEAM, user_id=UID),
     ("DELETE", f"/api/teams/{TEAM}/members/{UID}")),
    (admin.fenrir_admin_platform, dict(action="integration_get", item_id="smtp"), ("GET", "/api/integrations/smtp")),
    (admin.fenrir_admin_platform, dict(action="integration_get", item_id="webhooks"),
     ("GET", "/api/integrations/webhooks")),
    (admin.fenrir_admin_platform, dict(action="integration_get", item_id="syslog"), ("GET", "/api/integrations/syslog")),
    (admin.fenrir_admin_platform, dict(action="api_keys_status"), ("GET", "/api/settings/api-keys")),
    (admin.fenrir_admin_platform, dict(action="api_key_delete", item_id="shodan"),
     ("DELETE", "/api/settings/api-keys/shodan")),
    (admin.fenrir_admin_platform, dict(action="siem_key_delete"), ("DELETE", "/api/integrations/siem-key")),
    (admin.fenrir_admin_platform, dict(action="smtp_test"), ("POST", "/api/integrations/smtp/test")),
    (admin.fenrir_admin_platform, dict(action="tokens_list"), ("GET", "/api/admin/tokens")),
    (admin.fenrir_admin_platform, dict(action="token_revoke", item_id=UID), ("DELETE", f"/api/admin/tokens/{UID}")),
]


@pytest.mark.parametrize("fn,kw,expected", KEPT_CALLS)
def test_kept_curated_actions_reach_fenrir(wire, fn, kw, expected):
    asyncio.run(fn(**kw))
    assert wire == [expected]


@pytest.mark.parametrize("team_id", [f"{TEAM}/members/{UID}", f"{TEAM}%2Fmembers%2F{UID}"])
def test_a_crafted_id_cannot_turn_a_kept_action_into_a_member_add(wire, team_id):
    with pytest.raises(FenrirError, match="denied by policy"):
        asyncio.run(admin.fenrir_admin_teams("team_update", team_id=team_id, data={}))
    assert wire == []
