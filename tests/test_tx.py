"""FENRIR TX: timeline export layouts — fenrir_timeline_list(export=…) calls GET …/timeline/export with the list's
filters and returns the server-rendered file as text."""

import asyncio

import httpx

from fenrir_mcp import client
from fenrir_mcp.tools import timeline

INC = "11111111-1111-4111-8111-111111111111"
ENT = "22222222-2222-4222-8222-222222222222"


def _mock(monkeypatch, ctype="text/html; charset=utf-8", body="<!DOCTYPE html><html>…</html>"):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        if req.url.path.endswith("/timeline"):
            return httpx.Response(200, json={"items": [], "next_cursor": None})
        return httpx.Response(200, text=body, headers={"content-type": ctype})
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    return seen


def test_html_layout_with_filters(monkeypatch):
    seen = _mock(monkeypatch)
    out = asyncio.run(timeline.fenrir_timeline_list(INC, export="horizon", key=True, entity_id=ENT,
                                                    include_system=False, tz="Europe/Stockholm",
                                                    include_raw_logs=True, limit=5, sort="desc"))
    r = seen[-1]
    assert (r.method, r.url.path) == ("GET", f"/api/incidents/{INC}/timeline/export")
    assert dict(r.url.params) == {"layout": "horizon", "format": "html", "key": "true", "entity_id": ENT,
                                  "include_system": "false", "tz": "Europe/Stockholm", "include_raw_logs": "true"}
    assert out.startswith("<!DOCTYPE html>")


def test_csv_has_no_layout(monkeypatch):
    seen = _mock(monkeypatch, "text/csv; charset=utf-8", "event_time,description\r\n")
    out = asyncio.run(timeline.fenrir_timeline_list(INC, export="csv", q="beacon"))
    assert dict(seen[-1].url.params) == {"format": "csv", "q": "beacon"}
    assert out == "event_time,description\r\n"


def test_list_unchanged_without_export(monkeypatch):
    seen = _mock(monkeypatch)
    asyncio.run(timeline.fenrir_timeline_list(INC, key=True, limit=5))
    assert seen[-1].url.path == f"/api/incidents/{INC}/timeline"
    assert dict(seen[-1].url.params) == {"key": "true", "limit": "5"}
