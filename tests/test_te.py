"""FENRIR TE: timeline events pick up registered entities — link_entity (bulk link + dry run), the batch
link_entities switch, entity_list match=, email import_hops link_entities (a query parameter)."""

import asyncio
import json

import httpx
import pytest

from fenrir_mcp import client
from fenrir_mcp.client import FenrirError
from fenrir_mcp.tools import entities, forensic, timeline

INC = "11111111-1111-4111-8111-111111111111"
ENT = "22222222-2222-4222-8222-222222222222"
AID = "33333333-3333-4333-8333-333333333333"


def _mock(monkeypatch, payload=None):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json=payload if payload is not None else {"items": [], "next_cursor": None})
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    return seen


def test_link_entity_posts_entity_links(monkeypatch):
    seen = _mock(monkeypatch, {"entity_id": ENT, "matched": 3, "linked": 3})
    out = asyncio.run(timeline.fenrir_timeline_write("link_entity", INC, entity_id=ENT))
    r = seen[-1]
    assert (r.method, r.url.path) == ("POST", f"/api/incidents/{INC}/timeline/entity-links")
    assert json.loads(r.content) == {"entity_id": ENT, "dry_run": False}
    assert out == {"entity_id": ENT, "matched": 3, "linked": 3}
    asyncio.run(timeline.fenrir_timeline_write("link_entity", INC, entity_id=ENT, dry_run=True))
    assert json.loads(seen[-1].content) == {"entity_id": ENT, "dry_run": True}


def test_link_entity_needs_entity_id(monkeypatch):
    seen = _mock(monkeypatch)
    with pytest.raises(FenrirError):
        asyncio.run(timeline.fenrir_timeline_write("link_entity", INC))
    assert seen == []


def test_add_batch_link_entities_only_when_asked(monkeypatch):
    seen = _mock(monkeypatch, {"created": 1, "errors": [], "entities_linked": 1})
    ev = [{"event_time": "2026-10-31T08:00:00Z", "description": "x", "hostname": "dc01"}]
    asyncio.run(timeline.fenrir_timeline_write("add_batch", INC, events=ev))
    assert json.loads(seen[-1].content) == {"events": ev}          # the server default (link) applies
    asyncio.run(timeline.fenrir_timeline_write("add_batch", INC, events=ev, link_entities=False))
    assert json.loads(seen[-1].content) == {"events": ev, "link_entities": False}


def test_entity_list_match(monkeypatch):
    seen = _mock(monkeypatch)
    asyncio.run(entities.fenrir_entity_list(INC, match="dc01", fields=["id", "value"]))
    r = seen[-1]
    assert (r.method, r.url.path) == ("GET", f"/api/incidents/{INC}/entities")
    assert dict(r.url.params) == {"match": "dc01"}
    with pytest.raises(FenrirError):
        asyncio.run(entities.fenrir_entity_list(INC, view="relations", match="dc01"))


def test_import_hops_link_entities_is_a_query_parameter(monkeypatch):
    seen = _mock(monkeypatch, {"id": AID})
    asyncio.run(forensic.fenrir_email_analyze("import_hops", INC, analysis_id=AID))
    r = seen[-1]
    assert (r.method, r.url.path) == ("POST", f"/api/incidents/{INC}/email/{AID}/import-hops")
    assert dict(r.url.params) == {}                                  # server default: link
    asyncio.run(forensic.fenrir_email_analyze("import_hops", INC, analysis_id=AID, data={"link_entities": False}))
    assert dict(seen[-1].url.params) == {"link_entities": "false"}


def test_other_email_actions_unchanged(monkeypatch):
    seen = _mock(monkeypatch, {"id": AID})
    asyncio.run(forensic.fenrir_email_analyze("promote_iocs", INC, analysis_id=AID, data={"iocs": []}))
    assert seen[-1].url.path == f"/api/incidents/{INC}/email/{AID}/promote-iocs"
    assert json.loads(seen[-1].content) == {"iocs": []}


def test_docs_name_te():
    assert "entity_match" in timeline.fenrir_timeline_list.__doc__
    assert "link_entity" in timeline.fenrir_timeline_write.__doc__ and "dry_run" in timeline.fenrir_timeline_write.__doc__
    assert "match" in entities.fenrir_entity_list.__doc__
    for t in (forensic.fenrir_timeline_import, forensic.fenrir_defender_import, forensic.fenrir_pcap_analyze,
              forensic.fenrir_email_analyze):
        assert "link_entities" in t.__doc__, t.__name__
