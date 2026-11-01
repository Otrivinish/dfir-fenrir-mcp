"""FENRIR I4: incident create passes the required + optional intake fields through unchanged, and
fenrir_incident_get start_checks=True reads GET …/start-checks (one view at a time)."""

import asyncio
import json

import httpx
import pytest

from fenrir_mcp import client
from fenrir_mcp.client import FenrirError
from fenrir_mcp.tools import incidents

INC = "11111111-1111-4111-8111-111111111111"


def _recorder(monkeypatch, body=None):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append({"method": req.method, "path": req.url.path, "body": req.content})
        return httpx.Response(200, json=body if body is not None else {})
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    return seen


def test_create_passes_intake_through(monkeypatch):
    seen = _recorder(monkeypatch, body={"id": INC})
    data = {"title": "Phish", "severity": "high", "incident_type": "phishing", "detection_method": "user_report",
            "detected_at": "2026-10-06T10:00:00Z", "ic_user_id": "22222222-2222-4222-8222-222222222222",
            "functional_impact": "low", "information_impact": "privacy", "recoverability": "regular",
            "severity_rationale": "Exec mailbox", "alert_reference": "Sentinel 4f2a91",
            "first_host": "FIN-WS-07", "first_ioc": {"type": "domain", "value": "evil.example"}}
    asyncio.run(incidents.fenrir_incident_write("create", data=data))
    r = seen[-1]
    assert (r["method"], r["path"]) == ("POST", "/api/incidents")
    assert json.loads(r["body"]) == data


def test_start_checks_view(monkeypatch):
    seen = _recorder(monkeypatch, body={"total": 0, "items": []})
    asyncio.run(incidents.fenrir_incident_get(INC, start_checks=True))
    assert (seen[-1]["method"], seen[-1]["path"]) == ("GET", f"/api/incidents/{INC}/start-checks")
    asyncio.run(incidents.fenrir_incident_get(INC))
    assert seen[-1]["path"] == f"/api/incidents/{INC}"


@pytest.mark.parametrize("kw", [{"snapshot": True, "start_checks": True}, {"gates": True, "start_checks": True},
                                {"snapshot": True, "gates": True}])
def test_one_view_only(monkeypatch, kw):
    _recorder(monkeypatch)
    with pytest.raises(FenrirError):
        asyncio.run(incidents.fenrir_incident_get(INC, **kw))
