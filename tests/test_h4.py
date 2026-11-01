"""FENRIR H4: Supporting-documents delete sends its reason in the JSON body (file and entity_file);
file_update forwards a rename's reason; register_exhibit POSTs …/files/{id}/register-exhibit.
Each test asserts the exact request sent; server refusals surface as FenrirError."""

import asyncio
import json

import httpx
import pytest

from fenrir_mcp import client
from fenrir_mcp.client import FenrirError
from fenrir_mcp.tools import admin, entities

INC = "11111111-1111-4111-8111-111111111111"
ENT = "22222222-2222-4222-8222-222222222222"
FID = "44444444-4444-4444-8444-444444444444"


def _recorder(monkeypatch, status=200, body=None):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.method, req.url.path, json.loads(req.content) if req.content else None))
        return httpx.Response(status, json=body if body is not None else {})
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    return seen


def test_file_delete_sends_reason_in_body(monkeypatch):
    seen = _recorder(monkeypatch, body={"status": "ok"})
    asyncio.run(admin.fenrir_delete("file", FID, incident_id=INC, reason="duplicate screenshot upload"))
    assert seen == [("DELETE", f"/api/incidents/{INC}/files/{FID}", {"reason": "duplicate screenshot upload"})]


def test_entity_file_delete_sends_reason_in_body(monkeypatch):
    seen = _recorder(monkeypatch, body={"status": "ok"})
    asyncio.run(admin.fenrir_delete("entity_file", ENT, incident_id=INC, sub_id=FID, reason="wrong host attached"))
    assert seen == [("DELETE", f"/api/incidents/{INC}/entities/{ENT}/files/{FID}", {"reason": "wrong host attached"})]


@pytest.mark.parametrize("status,code", [(409, "file_referenced"), (422, "reason_required")])
def test_file_delete_refusals_surface(monkeypatch, status, code):
    _recorder(monkeypatch, status=status, body={"detail": "no", "code": code, "references": []})
    with pytest.raises(FenrirError, match=str(status)):
        asyncio.run(admin.fenrir_delete("file", FID, incident_id=INC, reason="0123456789"))


def test_rename_forwards_reason(monkeypatch):
    seen = _recorder(monkeypatch, body={"id": FID})
    asyncio.run(entities.fenrir_entity_write("file_update", INC, file_id=FID,
                                             data={"original_name": "b.png", "reason": "typo in the file name"}))
    assert seen == [("PATCH", f"/api/incidents/{INC}/files/{FID}",
                     {"original_name": "b.png", "reason": "typo in the file name"})]


def test_register_exhibit_posts(monkeypatch):
    seen = _recorder(monkeypatch, body={"evidence_id": "e", "exhibit_link": "registered"})
    out = asyncio.run(entities.fenrir_entity_write("register_exhibit", INC, file_id=FID))
    assert seen == [("POST", f"/api/incidents/{INC}/files/{FID}/register-exhibit", None)]
    assert out["exhibit_link"] == "registered"


def test_register_exhibit_needs_file_id(monkeypatch):
    seen = _recorder(monkeypatch)
    with pytest.raises(FenrirError, match="file_id"):
        asyncio.run(entities.fenrir_entity_write("register_exhibit", INC))
    assert seen == []


@pytest.mark.parametrize("status", [403, 409])
def test_register_exhibit_errors_surface(monkeypatch, status):
    _recorder(monkeypatch, status=status, body={"detail": "no", "code": "file_hash_mismatch"})
    with pytest.raises(FenrirError, match=str(status)):
        asyncio.run(entities.fenrir_entity_write("register_exhibit", INC, file_id=FID))
