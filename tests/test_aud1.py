"""FENRIR AUD-1: every audit entry carries the client ip_address and user_agent. fenrir_incident_audit
passes them through, gains a `fields` projection, and its docstring names both fields."""

import asyncio

import httpx

from fenrir_mcp import client, config
from fenrir_mcp.tools import incidents

INC = "11111111-1111-4111-8111-111111111111"
ROW = {"id": "a1", "timestamp": "2026-10-06T10:00:00Z", "username": "alice", "action": "incident_update",
       "ip_address": "192.0.2.10", "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0",
       "request_method": "PATCH", "request_path": f"/api/incidents/{INC}", "request_id": "r1",
       "row_hash": "f" * 64, "prev_hash": "e" * 64}
SYSTEM = {"id": "a2", "timestamp": "2026-10-06T10:01:00Z", "action": "anchor", "ip_address": None,
          "user_agent": None, "row_hash": "d" * 64, "prev_hash": "f" * 64}


def _recorder(monkeypatch, body):
    seen = []

    class T(httpx.AsyncBaseTransport):
        async def handle_async_request(self, req: httpx.Request) -> httpx.Response:
            seen.append({"method": req.method, "path": req.url.path, "query": dict(req.url.params)})
            return httpx.Response(200, json=body)
    monkeypatch.setattr(client, "_bearer", lambda: {})
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=T(), base_url="https://fenrir.test",
                                                             timeout=httpx.Timeout(config.READ_TIMEOUT, connect=5)))
    return seen


def test_audit_passes_ip_and_user_agent_through(monkeypatch):
    seen = _recorder(monkeypatch, {"items": [ROW, SYSTEM], "next_cursor": None})
    out = asyncio.run(incidents.fenrir_incident_audit(INC, limit=50))
    assert seen == [{"method": "GET", "path": f"/api/incidents/{INC}/audit-log", "query": {"limit": "50"}}]
    assert out["items"][0]["user_agent"] == ROW["user_agent"]
    assert out["items"][0]["ip_address"] == "192.0.2.10"


def test_audit_fields_projection_keeps_ip_and_user_agent(monkeypatch):
    _recorder(monkeypatch, {"items": [ROW, SYSTEM], "next_cursor": "c2"})
    out = asyncio.run(incidents.fenrir_incident_audit(INC, fields=["action", "ip_address", "user_agent"]))
    assert out["next_cursor"] == "c2"
    assert out["items"][0] == {"action": "incident_update", "ip_address": "192.0.2.10",
                               "user_agent": ROW["user_agent"]}
    assert out["items"][1] == {"action": "anchor"}            # a system row: nulls are omitted by design


def test_audit_docstring_names_the_fields():
    doc = incidents.fenrir_incident_audit.__doc__
    assert "user_agent" in doc and "ip_address" in doc and "fields" in doc
