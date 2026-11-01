"""FENRIR K4 (R40): fenrir_ioc_list sends entity_id and keeps first_seen_at / last_seen_at in a projection;
fenrir_entity_list sends the server-side compromised filter. K5: the docstrings name the new 422 codes."""

import asyncio

import httpx

from fenrir_mcp import client
from fenrir_mcp.tools import entities, iocs, legal_costs

INC = "11111111-1111-4111-8111-111111111111"
ENT = "22222222-2222-4222-8222-222222222222"


def _mock(monkeypatch, payload):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json=payload)
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    return seen


def test_ioc_list_entity_filter_and_seen_fields(monkeypatch):
    seen = _mock(monkeypatch, {"items": [{"id": "i1", "type": "ip", "value": "203.0.113.9", "notes": "x" * 40,
                                          "first_seen_at": "2026-10-07T08:00:00Z",
                                          "last_seen_at": "2026-10-07T09:30:00Z"}], "next_cursor": None})
    out = asyncio.run(iocs.fenrir_ioc_list(INC, entity_id=ENT, filters={"type": "ip"}, limit=20,
                                           fields=["id", "first_seen_at", "last_seen_at"]))
    r = seen[-1]
    assert (r.method, r.url.path) == ("GET", f"/api/incidents/{INC}/iocs")
    assert dict(r.url.params) == {"type": "ip", "entity_id": ENT, "limit": "20"}
    assert out["items"] == [{"id": "i1", "first_seen_at": "2026-10-07T08:00:00Z",
                             "last_seen_at": "2026-10-07T09:30:00Z"}]
    asyncio.run(iocs.fenrir_ioc_list(INC))
    assert dict(seen[-1].url.params) == {}          # nothing sent unless asked


def test_entity_list_compromised_filter(monkeypatch):
    seen = _mock(monkeypatch, {"items": [], "next_cursor": None})
    asyncio.run(entities.fenrir_entity_list(INC, compromised=True))
    r = seen[-1]
    assert (r.url.path, dict(r.url.params)) == (f"/api/incidents/{INC}/entities", {"compromised": "true"})
    asyncio.run(entities.fenrir_entity_list(INC, compromised=False, limit=5))
    assert dict(seen[-1].url.params) == {"compromised": "false", "limit": "5"}


def test_docs_name_the_new_fields_and_codes():
    doc = iocs.fenrir_ioc_list.__doc__
    for word in ("entity_id", "first_seen_at", "last_seen_at"):
        assert word in doc
    assert "anchor_in_future" in legal_costs.fenrir_legal_write.__doc__
    assert "invalid_currency" in legal_costs.fenrir_costs_write.__doc__
