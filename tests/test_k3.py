"""FENRIR K3 (R39): fenrir_timeline_list sends the server-side filters and maps sort asc/desc to event_time."""

import asyncio

import httpx

from fenrir_mcp import client
from fenrir_mcp.tools import timeline

INC = "11111111-1111-4111-8111-111111111111"
ENT = "22222222-2222-4222-8222-222222222222"
IOC = "33333333-3333-4333-8333-333333333333"


def _mock(monkeypatch):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json={"items": [{"id": "e1", "event_time": "2026-10-07T08:00:00Z",
                                                   "description": "C2 beacon", "key_event": True,
                                                   "linked_iocs": [{"id": IOC, "type": "ip", "value": "203.0.113.9"}],
                                                   "raw_log": "x" * 50}],
                                         "next_cursor": "abc"})
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    return seen


def test_timeline_list_filters_and_sort_desc(monkeypatch):
    seen = _mock(monkeypatch)
    out = asyncio.run(timeline.fenrir_timeline_list(
        INC, entity_id=ENT, ioc_id=IOC, ir_phase="detection_and_analysis", origin="forensic_import",
        key=True, q="beacon & 50%", include_system=False, sort="desc", limit=50, cursor="c1",
        fields=["id", "key_event", "linked_iocs"]))
    r = seen[-1]
    assert (r.method, r.url.path) == ("GET", f"/api/incidents/{INC}/timeline")
    qp = dict(r.url.params)
    assert qp == {"entity_id": ENT, "ioc_id": IOC, "ir_phase": "detection_and_analysis", "origin": "forensic_import",
                  "key": "true", "q": "beacon & 50%", "include_system": "false", "sort": "-event_time",
                  "limit": "50", "cursor": "c1"}
    assert out["items"] == [{"id": "e1", "key_event": True,
                             "linked_iocs": [{"id": IOC, "type": "ip", "value": "203.0.113.9"}]}]
    assert out["next_cursor"] == "abc"


def test_timeline_list_sort_asc_and_defaults(monkeypatch):
    seen = _mock(monkeypatch)
    asyncio.run(timeline.fenrir_timeline_list(INC, sort="asc", ir_phase="none"))
    assert dict(seen[-1].url.params) == {"sort": "event_time", "ir_phase": "none"}
    asyncio.run(timeline.fenrir_timeline_list(INC))
    assert dict(seen[-1].url.params) == {}          # nothing sent unless asked: the server defaults apply
    asyncio.run(timeline.fenrir_timeline_list(INC, key=False, filters={"q": "x"}))
    assert dict(seen[-1].url.params) == {"q": "x", "key": "false"}


def test_timeline_docs_name_the_filters():
    doc = timeline.fenrir_timeline_list.__doc__
    for word in ("entity_id", "ioc_id", "ir_phase", "origin", "key=True", "sort", "desc"):
        assert word in doc
    assert "is_key" in timeline.fenrir_timeline_write.__doc__
