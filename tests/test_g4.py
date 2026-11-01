"""G4: run records for Defender and Velociraptor; the exhibit's clock offset.
fenrir_defender_import (create_import / from_evidence / promote), the new forensic_list views,
and the structured offset on evidence register / update. Each test asserts the exact request sent."""

import asyncio
import json

import httpx
import pytest

from fenrir_mcp import client, config, tools
from fenrir_mcp.client import FenrirError
from fenrir_mcp.tools import evidence, forensic

INC = "11111111-1111-4111-8111-111111111111"
EID = "22222222-2222-4222-8222-222222222222"
IMP = "33333333-3333-4333-8333-333333333333"


def _recorder(monkeypatch, status=200, body=None):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append({"method": req.method, "path": req.url.path, "ctype": req.headers.get("content-type", ""),
                     "body": req.content})
        return httpx.Response(status, json=body if body is not None else {"id": IMP})
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    return seen


def test_defender_import_is_a_standard_write_tool():
    assert "fenrir_defender_import" in set(tools.registered("standard"))
    assert "fenrir_defender_import" not in set(tools.registered("readonly"))


def test_from_evidence_posts_without_a_body(monkeypatch):
    seen = _recorder(monkeypatch, status=201, body={"id": IMP, "evidence_id": EID, "parser_version": "1.0.0"})
    out = asyncio.run(forensic.fenrir_defender_import("from_evidence", INC, evidence_id=EID))
    assert [(r["method"], r["path"]) for r in seen] == [
        ("POST", f"/api/incidents/{INC}/forensic/defender-pdf/from-evidence/{EID}")]
    assert seen[0]["body"] == b""
    assert out["evidence_id"] == EID


def test_from_evidence_needs_evidence_id(monkeypatch):
    seen = _recorder(monkeypatch)
    with pytest.raises(FenrirError, match="evidence_id"):
        asyncio.run(forensic.fenrir_defender_import("from_evidence", INC))
    assert seen == []


def test_create_import_uploads_multipart(monkeypatch, tmp_path):
    monkeypatch.setenv("FENRIR_MCP_UPLOAD_DIRS", str(tmp_path))
    pdf = tmp_path / "incident.pdf"
    pdf.write_bytes(b"%PDF-1.7 test")
    seen = _recorder(monkeypatch, status=201)
    asyncio.run(forensic.fenrir_defender_import("create_import", INC, file_path=str(pdf)))
    r = seen[0]
    assert (r["method"], r["path"]) == ("POST", f"/api/incidents/{INC}/forensic/defender-pdf/imports")
    assert r["ctype"].startswith("multipart/form-data")
    assert b'filename="incident.pdf"' in r["body"] and b"%PDF-1.7 test" in r["body"]


def test_create_import_needs_file_path(monkeypatch):
    seen = _recorder(monkeypatch)
    with pytest.raises(FenrirError, match="file_path"):
        asyncio.run(forensic.fenrir_defender_import("create_import", INC))
    assert seen == []


def test_promote_sends_items_as_json(monkeypatch):
    seen = _recorder(monkeypatch, body={"created": 2, "created_indices": [0, 3]})
    items = [{"idx": 0, "destination": "ioc"}, {"idx": 3, "destination": "timeline_event"}]
    out = asyncio.run(forensic.fenrir_defender_import("promote", INC, import_id=IMP,
                                                      data={"items": items, "ir_phase": "detection_and_analysis"}))
    r = seen[0]
    assert (r["method"], r["path"]) == ("POST", f"/api/incidents/{INC}/forensic/defender-pdf/imports/{IMP}/promote")
    assert r["ctype"].startswith("application/json")
    assert json.loads(r["body"]) == {"items": items, "ir_phase": "detection_and_analysis"}
    assert out["created"] == 2


@pytest.mark.parametrize("data", [None, {}, {"items": []}, {"indices": [0]}, {"items": "0"}])
def test_promote_needs_items(monkeypatch, data):
    seen = _recorder(monkeypatch)
    with pytest.raises(FenrirError, match="items"):
        asyncio.run(forensic.fenrir_defender_import("promote", INC, import_id=IMP, data=data))
    assert seen == []


def test_promote_needs_import_id(monkeypatch):
    seen = _recorder(monkeypatch)
    with pytest.raises(FenrirError, match="import_id"):
        asyncio.run(forensic.fenrir_defender_import("promote", INC, data={"items": [{"idx": 0, "destination": "ioc"}]}))
    assert seen == []


def test_coded_409_is_surfaced(monkeypatch):
    _recorder(monkeypatch, status=409, body={"detail": "The stored exhibit no longer matches", "code": "evidence_hash_mismatch"})
    with pytest.raises(FenrirError, match=r"\[evidence_hash_mismatch\]"):
        asyncio.run(forensic.fenrir_defender_import("from_evidence", INC, evidence_id=EID))


@pytest.mark.parametrize("view,path", [
    ("defender_imports", f"/api/incidents/{INC}/forensic/defender-pdf/imports"),
    ("defender_import_item", f"/api/incidents/{INC}/forensic/defender-pdf/imports/{IMP}"),
])
def test_forensic_list_defender_views(monkeypatch, view, path):
    seen = _recorder(monkeypatch, body={"items": []})
    asyncio.run(forensic.fenrir_forensic_list(INC, view=view, item_id=IMP if view.endswith("_item") else None))
    assert (seen[0]["method"], seen[0]["path"]) == ("GET", path)


def test_defender_item_view_needs_item_id(monkeypatch):
    seen = _recorder(monkeypatch)
    with pytest.raises(FenrirError, match="item_id"):
        asyncio.run(forensic.fenrir_forensic_list(INC, view="defender_import_item"))
    assert seen == []


def test_evidence_digital_sends_offset_seconds_in_the_complete_body(monkeypatch, tmp_path):
    # G1 stage 3b: was a multipart form field; now JSON in POST …/uploads/{id}/complete.
    from test_g1b_uploads import FakeFenrir
    monkeypatch.setenv("FENRIR_MCP_UPLOAD_DIRS", str(tmp_path))
    f = tmp_path / "host.evtx"
    f.write_bytes(b"ElfFile\x00")
    srv = FakeFenrir()
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(srv), base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    asyncio.run(evidence.fenrir_evidence_register("digital", INC, file_path=str(f), data={
        "name": "host log", "identifier": "EXH-1", "system_time_offset": "device +2 min vs NTP",
        "system_time_offset_seconds": -120}))
    assert srv.complete["system_time_offset_seconds"] == -120
    assert srv.complete["system_time_offset"] == "device +2 min vs NTP"


def test_evidence_update_can_clear_the_offset_with_null(monkeypatch):
    seen = _recorder(monkeypatch, body={"id": EID})
    asyncio.run(evidence.fenrir_evidence_register("update", INC, evidence_id=EID,
                                                  data={"system_time_offset_seconds": None}))
    r = seen[0]
    assert (r["method"], r["path"]) == ("PATCH", f"/api/incidents/{INC}/evidence/{EID}")
    assert json.loads(r["body"]) == {"system_time_offset_seconds": None}   # null kept: it clears


def test_docstrings_explain_the_offset_convention():
    assert "device clock minus" in evidence.fenrir_evidence_register.__doc__
    assert "text_only" in forensic.fenrir_timeline_import.__doc__
    assert "container_sha256" in forensic.fenrir_collection_write.__doc__
    assert config  # imported for the upload allowlist env in the tests above
