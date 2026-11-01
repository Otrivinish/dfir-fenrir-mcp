"""FENRIR I2: the stakeholder notification tracker through fenrir_legal_list(view=notifications)
and fenrir_legal_write(notification_update) -- the exact requests, and the guards."""

import asyncio
import json

import httpx
import pytest

from fenrir_mcp import client
from fenrir_mcp.client import FenrirError
from fenrir_mcp.tools import legal_costs

INC = "11111111-1111-4111-8111-111111111111"
NID = "44444444-4444-4444-8444-444444444444"


def _recorder(monkeypatch, status=200, body=None):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append({"method": req.method, "path": req.url.path, "query": dict(req.url.params), "body": req.content})
        return httpx.Response(status, json=body if body is not None else {"items": [], "summary": {}})
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    return seen


def test_notifications_list_with_filters(monkeypatch):
    seen = _recorder(monkeypatch)
    asyncio.run(legal_costs.fenrir_legal_list("notifications", INC, status="pending", active=True))
    r = seen[-1]
    assert (r["method"], r["path"]) == ("GET", f"/api/incidents/{INC}/stakeholder-notifications")
    assert r["query"] == {"status": "pending", "active": "true"}


def test_notifications_list_plain(monkeypatch):
    seen = _recorder(monkeypatch)
    asyncio.run(legal_costs.fenrir_legal_list("notifications", INC))
    assert seen[-1]["query"] == {}


def test_notifications_guards(monkeypatch):
    _recorder(monkeypatch)
    with pytest.raises(FenrirError):
        asyncio.run(legal_costs.fenrir_legal_list("notifications"))                 # no incident
    with pytest.raises(FenrirError):
        asyncio.run(legal_costs.fenrir_legal_list("deadlines", INC, status="pending"))
    with pytest.raises(FenrirError):
        asyncio.run(legal_costs.fenrir_legal_write("notification_update", INC, data={"status": "notified"}))


def test_notification_record_patches_one(monkeypatch):
    seen = _recorder(monkeypatch, body={"id": NID, "status": "notified"})
    data = {"status": "notified", "channel": "phone", "notified_at": "2026-10-06T10:00:00Z"}
    out = asyncio.run(legal_costs.fenrir_legal_write("notification_update", INC, item_id=NID, data=data))
    r = seen[-1]
    assert (r["method"], r["path"]) == ("PATCH", f"/api/incidents/{INC}/stakeholder-notifications/{NID}")
    assert json.loads(r["body"]) == data and out["status"] == "notified"


def test_matrix_add_passes_incident_types(monkeypatch):
    seen = _recorder(monkeypatch, body={"id": NID})
    data = {"severity": "high", "role": "DPO", "notify_within_minutes": 60, "incident_types": ["data_breach"]}
    asyncio.run(legal_costs.fenrir_legal_write("matrix_add", data=data))
    assert (seen[-1]["method"], seen[-1]["path"]) == ("POST", "/api/stakeholder-matrix")
    assert json.loads(seen[-1]["body"])["incident_types"] == ["data_breach"]
