"""FENRIR CN-2: editable, signed case notes. view=case_notes passes current=true, view=case_note_revisions
reads a note's revisions, and fenrir_comms_write(case_note_edit) posts the next revision (corrects_id)."""

import asyncio
import json

import pytest

from fenrir_mcp.client import FenrirError
from fenrir_mcp.tools import comms
from test_h2 import EID, INC, NID, _literal, _recorder


def test_list_current_revisions_only(monkeypatch):
    seen = _recorder(monkeypatch)
    asyncio.run(comms.fenrir_comms_list(INC, view="case_notes", filters={"current": True, "author_id": NID}))
    r = seen[-1]
    assert (r["method"], r["path"]) == ("GET", f"/api/incidents/{INC}/case-notes")
    assert r["query"] == {"current": "true", "author_id": NID}


def test_current_false_is_not_sent(monkeypatch):
    seen = _recorder(monkeypatch)
    asyncio.run(comms.fenrir_comms_list(INC, view="case_notes", filters={"current": False}))
    assert seen[-1]["query"] == {}


def test_revisions_view_needs_note_id(monkeypatch):
    seen = _recorder(monkeypatch)
    asyncio.run(comms.fenrir_comms_list(INC, view="case_note_revisions", note_id=NID, limit=10))
    r = seen[-1]
    assert (r["method"], r["path"]) == ("GET", f"/api/incidents/{INC}/case-notes/{NID}/revisions")
    assert r["query"] == {"limit": "10"}
    with pytest.raises(FenrirError):
        asyncio.run(comms.fenrir_comms_list(INC, view="case_note_revisions"))


def test_edit_posts_next_revision(monkeypatch):
    seen = _recorder(monkeypatch, status=201, body={"id": EID, "revision": 2})
    data = {"body": "Blocked at the proxy, not the edge", "ioc_ids": [EID]}
    asyncio.run(comms.fenrir_comms_write("case_note_edit", incident_id=INC, item_id=NID, data=data))
    r = seen[-1]
    assert (r["method"], r["path"]) == ("POST", f"/api/incidents/{INC}/case-notes")
    assert json.loads(r["body"]) == {**data, "corrects_id": NID}


def test_edit_item_id_wins_over_data(monkeypatch):
    seen = _recorder(monkeypatch, status=201, body={"id": EID})
    asyncio.run(comms.fenrir_comms_write("case_note_edit", incident_id=INC, item_id=NID,
                                         data={"body": "x", "corrects_id": EID}))
    assert json.loads(seen[-1]["body"])["corrects_id"] == NID


def test_edit_needs_item_id(monkeypatch):
    _recorder(monkeypatch, status=201)
    with pytest.raises(FenrirError):
        asyncio.run(comms.fenrir_comms_write("case_note_edit", incident_id=INC, data={"body": "x"}))


def test_new_literals_present():
    assert "case_note_edit" in _literal(comms.fenrir_comms_write, "action")
    assert "case_note_revisions" in _literal(comms.fenrir_comms_list, "view")
