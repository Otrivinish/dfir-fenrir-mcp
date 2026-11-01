"""S5 (FENRIR evidence HLD 2026-10-31, EG-6 / EG-7 / FP-7): the screenshot capture record and supporting-file links.

- fenrir_file_upload's docstring names exactly the form fields FENRIR accepts (FP-7: it used to promise a
  "description" the backend dropped), and `fields` reach the multipart form unchanged on both routes it posts to
  (incident Files, entity attachments);
- fenrir_entity_write link_file / unlink_file send the exact request; file_update passes the capture fields through;
- the read path: fenrir_entity_list view=incident_files with linked_type + linked_id.
Each test asserts the exact request sent; server refusals surface as FenrirError."""

import asyncio
import email
import json
import re

import httpx
import pytest

from fenrir_mcp import client
from fenrir_mcp.client import FenrirError
from fenrir_mcp.tools import entities

INC = "11111111-1111-4111-8111-111111111111"
ENT = "22222222-2222-4222-8222-222222222222"
FID = "44444444-4444-4444-8444-444444444444"
LID = "55555555-5555-4555-8555-555555555555"
TID = "66666666-6666-4666-8666-666666666666"
# backend/files/capture.py FIELDS: the capture form fields of POST …/files and POST …/entities/{id}/files.
CAPTURE_FIELDS = ("captured_at", "captured_by_id", "captured_by_name", "capture_tool", "capture_tool_version",
                  "capture_method", "capture_source", "capture_url", "capture_context", "capture_sha256")
CAPTURE = {"captured_at": "2026-10-30T10:15:30+02:00", "captured_by_name": "  PC 4471 Smith",
           "capture_tool": "Snagit", "capture_tool_version": "2024.2.1", "capture_method": "full_page",
           "capture_source": "WS-FIN-017 ", "capture_url": "https://login.phish.example/?u=jdoe",
           "capture_context": "Chrome window 'Sign in'", "capture_sha256": "ab" * 32}


def _recorder(monkeypatch, status=200, body=None):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        ct = req.headers.get("content-type", "")
        if ct.startswith("multipart/form-data"):
            msg = email.message_from_bytes(b"Content-Type: " + ct.encode() + b"\r\n\r\n" + req.content)
            form = {p.get_param("name", header="content-disposition"): p.get_payload(decode=True)
                    for p in msg.get_payload()}
            payload = {k: (v if k == "file" else v.decode()) for k, v in form.items()}
        else:
            payload = json.loads(req.content) if req.content else None
        seen.append((req.method, req.url.path, dict(req.url.params), payload))
        return httpx.Response(status, json=body if body is not None else {})
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    return seen


def test_file_upload_docstring_lists_exactly_the_backend_fields():
    doc = entities.fenrir_file_upload.__doc__
    named = set(re.findall(r"\bcaptured?_[a-z0-9_]+\b", doc)) - {"capture_hash_mismatch", "captured_by_conflict"}
    assert named == set(CAPTURE_FIELDS)                  # error codes aside, every capture word is a backend field
    assert "description" not in doc                      # FP-7: the field the backend never accepted


@pytest.mark.parametrize("entity_id,path", [(None, f"/api/incidents/{INC}/files"),
                                            (ENT, f"/api/incidents/{INC}/entities/{ENT}/files")])
def test_file_upload_sends_the_capture_fields_verbatim(monkeypatch, tmp_path, entity_id, path):
    monkeypatch.setenv("FENRIR_MCP_UPLOAD_DIRS", str(tmp_path))
    f = tmp_path / "shot.png"
    f.write_bytes(b"\x89PNG bytes")
    seen = _recorder(monkeypatch, status=201, body={"id": FID})
    asyncio.run(entities.fenrir_file_upload(INC, str(f), entity_id=entity_id, fields=CAPTURE))
    [(method, got_path, _, form)] = seen
    assert (method, got_path) == ("POST", path)
    assert form == {**CAPTURE, "file": b"\x89PNG bytes"}   # not trimmed, nothing added (no captured_by_id = you)


def test_file_upload_hash_mismatch_surfaces(monkeypatch, tmp_path):
    monkeypatch.setenv("FENRIR_MCP_UPLOAD_DIRS", str(tmp_path))
    f = tmp_path / "shot.png"
    f.write_bytes(b"x")
    _recorder(monkeypatch, status=422, body={"detail": "no", "code": "capture_hash_mismatch"})
    with pytest.raises(FenrirError, match="422"):
        asyncio.run(entities.fenrir_file_upload(INC, str(f), fields={"capture_sha256": "ab" * 32}))


def test_link_file_posts_the_target(monkeypatch):
    seen = _recorder(monkeypatch, status=201, body={"id": LID, "target_type": "timeline_event"})
    body = {"target_type": "timeline_event", "target_id": TID, "note": "the page the user opened"}
    out = asyncio.run(entities.fenrir_entity_write("link_file", INC, file_id=FID, data=body))
    assert seen == [("POST", f"/api/incidents/{INC}/files/{FID}/links", {}, body)]
    assert out["id"] == LID


def test_unlink_file_deletes_the_link(monkeypatch):
    seen = _recorder(monkeypatch, body={"status": "ok"})
    asyncio.run(entities.fenrir_entity_write("unlink_file", INC, file_id=FID, link_id=LID))
    assert seen == [("DELETE", f"/api/incidents/{INC}/files/{FID}/links/{LID}", {}, None)]


@pytest.mark.parametrize("action,kw,msg", [("link_file", {}, "file_id"), ("unlink_file", {"file_id": FID}, "link_id"),
                                           ("unlink_file", {"link_id": LID}, "file_id")])
def test_link_actions_need_their_ids(monkeypatch, action, kw, msg):
    seen = _recorder(monkeypatch)
    with pytest.raises(FenrirError, match=msg):
        asyncio.run(entities.fenrir_entity_write(action, INC, data={"target_type": "ioc", "target_id": TID}, **kw))
    assert seen == []


@pytest.mark.parametrize("status,code", [(404, "timeline_event_not_found"), (409, "already_linked"),
                                         (404, "link_not_found")])
def test_link_refusals_surface(monkeypatch, status, code):
    _recorder(monkeypatch, status=status, body={"detail": "no", "code": code})
    with pytest.raises(FenrirError, match=str(status)):
        asyncio.run(entities.fenrir_entity_write("link_file", INC, file_id=FID,
                                                 data={"target_type": "ioc", "target_id": TID}))


def test_file_update_passes_the_capture_fields(monkeypatch):
    seen = _recorder(monkeypatch, body={"id": FID})
    body = {k: v for k, v in CAPTURE.items() if k != "capture_sha256"} | {"captured_by_id": None}
    asyncio.run(entities.fenrir_entity_write("file_update", INC, file_id=FID, data=body))
    assert seen == [("PATCH", f"/api/incidents/{INC}/files/{FID}", {}, body)]


def test_incident_files_filter_by_link(monkeypatch):
    seen = _recorder(monkeypatch, body={"items": [{"id": FID, "links": [{"id": LID}], "capture_tool": "Snagit"}]})
    out = asyncio.run(entities.fenrir_entity_list(INC, view="incident_files", linked_type="ioc", linked_id=TID,
                                                  fields=["id", "links"]))
    assert seen == [("GET", f"/api/incidents/{INC}/files", {"linked_type": "ioc", "linked_id": TID}, None)]
    assert out == {"items": [{"id": FID, "links": [{"id": LID}]}]}


def test_link_filter_only_on_incident_files(monkeypatch):
    seen = _recorder(monkeypatch)
    with pytest.raises(FenrirError, match="incident_files"):
        asyncio.run(entities.fenrir_entity_list(INC, view="entities", linked_type="ioc", linked_id=TID))
    assert seen == []
