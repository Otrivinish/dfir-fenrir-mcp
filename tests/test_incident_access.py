"""E3: fenrir_people_list view=incident_access reads GET /api/incidents/{id}/access, and a
403 not_incident_lead reaches the model as a coded business rule (no token role-cap hint)."""

import asyncio

import httpx
import pytest

from fenrir_mcp import client
from fenrir_mcp.client import FenrirError, _raise_for
from fenrir_mcp.tools import people

INC = "00000000-0000-4000-8000-000000000003"


def _mock(monkeypatch, handler):
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})


def test_incident_access_view(monkeypatch):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.method, req.url.path))
        return httpx.Response(200, json={"is_lead": True, "capabilities": ["read_audit_log", "override_gate"]})

    _mock(monkeypatch, handler)
    out = asyncio.run(people.fenrir_people_list("incident_access", incident_id=INC))
    assert seen == [("GET", f"/api/incidents/{INC}/access")]
    assert out["is_lead"] is True and "override_gate" in out["capabilities"]


def test_incident_access_needs_incident_id():
    with pytest.raises(FenrirError, match="incident_id is required"):
        asyncio.run(people.fenrir_people_list("incident_access"))


def test_not_incident_lead_is_coded_without_role_hint():
    with pytest.raises(FenrirError) as exc:
        _raise_for(httpx.Response(403, json={"detail": "Only this incident's lead … can do this.",
                                             "code": "not_incident_lead"}))
    msg = str(exc.value)
    assert msg.startswith("FENRIR returned 403: [not_incident_lead]")
    assert "role cap" not in msg
