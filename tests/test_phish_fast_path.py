"""FENRIR phishing fast path (docs/phishing-fast-path-slices.md in dfir-fenrir-v2): each MCP surface sends
the exact request the API expects. P1 seen-before, P2 hunting queries, P3 containment + export filter."""

import asyncio
import json

import httpx
import pytest

from fenrir_mcp import client
from fenrir_mcp.client import FenrirError
from fenrir_mcp.tools import forensic, iocs

INC = "11111111-1111-4111-8111-111111111111"
AID = "55555555-5555-4555-8555-555555555555"


def _recorder(monkeypatch, body=None):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append({"method": req.method, "path": req.url.path, "query": dict(req.url.params), "body": req.content})
        return httpx.Response(200, json=body if body is not None else {})
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    return seen


def test_seen_before_view(monkeypatch):
    seen = _recorder(monkeypatch, body={"summary": {"incidents": 0}, "items": []})
    asyncio.run(forensic.fenrir_forensic_list(INC, "email_seen_before", item_id=AID))
    assert (seen[-1]["method"], seen[-1]["path"]) == ("GET", f"/api/incidents/{INC}/email/{AID}/seen-before")


def test_seen_before_needs_item_id(monkeypatch):
    _recorder(monkeypatch)
    with pytest.raises(FenrirError):
        asyncio.run(forensic.fenrir_forensic_list(INC, "email_seen_before"))


def test_hunting_queries_view(monkeypatch):
    seen = _recorder(monkeypatch, body={"queries": []})
    asyncio.run(forensic.fenrir_forensic_list(INC, "email_hunting_queries", item_id=AID, lookback_days=7))
    r = seen[-1]
    assert (r["method"], r["path"], r["query"]) == ("GET", f"/api/incidents/{INC}/email/{AID}/hunting-queries",
                                                    {"lookback_days": "7"})
    asyncio.run(forensic.fenrir_forensic_list(INC, "email_hunting_queries", item_id=AID))
    assert seen[-1]["query"] == {}                       # the API's default (30 days)


def test_containment_plan_view(monkeypatch):
    seen = _recorder(monkeypatch, body={"items": []})
    asyncio.run(forensic.fenrir_forensic_list(INC, "email_containment_plan", item_id=AID))
    assert (seen[-1]["method"], seen[-1]["path"]) == ("GET", f"/api/incidents/{INC}/email/{AID}/containment-plan")


def test_containment_posts_references(monkeypatch):
    seen = _recorder(monkeypatch, body={"actions": []})
    data = {"items": [{"kind": "message"}, {"kind": "url", "ref": 0}]}
    asyncio.run(forensic.fenrir_email_analyze("containment", INC, analysis_id=AID, data=data))
    r = seen[-1]
    assert (r["method"], r["path"]) == ("POST", f"/api/incidents/{INC}/email/{AID}/containment")
    assert json.loads(r["body"]) == data


def test_export_ioc_ids_repeat(monkeypatch):
    seen = []

    def handler(req):
        seen.append(req)
        return httpx.Response(200, text="IndicatorType,IndicatorValue\n")
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    asyncio.run(iocs.fenrir_ioc_export(INC, "mde-csv", ioc_ids=["a1", "b2"]))
    assert seen[-1].url.path == f"/api/incidents/{INC}/iocs/export/mde-csv"
    assert seen[-1].url.params.get_list("ioc_id") == ["a1", "b2"]
    asyncio.run(iocs.fenrir_ioc_export(INC, "mde-csv"))
    assert "ioc_id" not in seen[-1].url.params


def test_export_empty_ioc_ids_refused(monkeypatch):
    seen = _recorder(monkeypatch)
    with pytest.raises(FenrirError):
        asyncio.run(iocs.fenrir_ioc_export(INC, "mde-csv", ioc_ids=[]))
    assert seen == []
