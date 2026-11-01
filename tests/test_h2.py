"""FENRIR H2: case notes replace the scratchpad. fenrir_comms_list(view=case_notes|case_note|scratchpads)
and fenrir_comms_write(case_note_add) send the exact requests; the old note tools are gone."""

import asyncio
import inspect
import json
import typing

import httpx
import pytest

from fenrir_mcp import client
from fenrir_mcp.client import FenrirError
from fenrir_mcp.tools import admin, comms

INC = "11111111-1111-4111-8111-111111111111"
NID = "22222222-2222-4222-8222-222222222222"
EID = "33333333-3333-4333-8333-333333333333"


def _recorder(monkeypatch, status=200, body=None):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append({"method": req.method, "path": req.url.path, "query": dict(req.url.params), "body": req.content})
        return httpx.Response(status, json=body if body is not None else {"items": [], "next_cursor": None})
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    return seen


def test_list_case_notes_with_filters(monkeypatch):
    seen = _recorder(monkeypatch)
    asyncio.run(comms.fenrir_comms_list(INC, view="case_notes", limit=20,
                                        filters={"evidence_id": EID, "author_id": NID, "bogus": "x", "ioc_id": None}))
    r = seen[-1]
    assert (r["method"], r["path"]) == ("GET", f"/api/incidents/{INC}/case-notes")
    assert r["query"] == {"limit": "20", "evidence_id": EID, "author_id": NID}


def test_get_one_case_note_needs_id(monkeypatch):
    seen = _recorder(monkeypatch, body={"id": NID})
    asyncio.run(comms.fenrir_comms_list(INC, view="case_note", note_id=NID))
    assert (seen[-1]["method"], seen[-1]["path"]) == ("GET", f"/api/incidents/{INC}/case-notes/{NID}")
    with pytest.raises(FenrirError):
        asyncio.run(comms.fenrir_comms_list(INC, view="case_note"))


def test_scratchpads_view_is_read_only_legacy_list(monkeypatch):
    seen = _recorder(monkeypatch)
    asyncio.run(comms.fenrir_comms_list(INC, view="scratchpads"))
    assert (seen[-1]["method"], seen[-1]["path"]) == ("GET", f"/api/incidents/{INC}/notes")


def test_case_note_add_posts_body_links_and_correction(monkeypatch):
    seen = _recorder(monkeypatch, status=201, body={"id": NID})
    data = {"body": "Imaged disk", "evidence_ids": [EID], "corrects_id": NID}
    asyncio.run(comms.fenrir_comms_write("case_note_add", incident_id=INC, data=data))
    r = seen[-1]
    assert (r["method"], r["path"]) == ("POST", f"/api/incidents/{INC}/case-notes")
    assert json.loads(r["body"]) == data


def test_post_legacy_scratchpad(monkeypatch):
    seen = _recorder(monkeypatch, status=201, body={"id": NID})
    asyncio.run(comms.fenrir_comms_write("case_note_add", incident_id=INC, data={"source_scratchpad_id": NID}))
    assert json.loads(seen[-1]["body"]) == {"source_scratchpad_id": NID}


def _literal(fn, name):
    vals = set(typing.get_args(typing.get_type_hints(inspect.unwrap(fn))[name]))
    assert vals, f"{name} is not a Literal"
    return vals


def test_old_note_tools_are_gone():
    assert "note_save" not in _literal(comms.fenrir_comms_write, "action")
    assert {"notes", "note_versions"}.isdisjoint(_literal(comms.fenrir_comms_list, "view"))
    assert "note" not in admin._DELETABLE and "note" not in _literal(admin.fenrir_delete, "resource_type")
