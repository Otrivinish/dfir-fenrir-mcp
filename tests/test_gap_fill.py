"""Sync audit 2026-11-01 (MCP vs dfir-fenrir-v2 main): the fenrir_delete kind that pointed at a route v2 never had
is gone, and six v2 endpoints the MCP had no way to reach get a curated surface or a docstring hint."""

import asyncio
import typing

import httpx
import pytest

from fenrir_mcp import client
from fenrir_mcp.client import FenrirError
from fenrir_mcp.tools import admin, comms, entities, forensic, incidents

INC = "11111111-1111-4111-8111-111111111111"
NID = "33333333-3333-4333-8333-333333333333"
FID = "44444444-4444-4444-8444-444444444444"


def _recorder(monkeypatch, body=None):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append({"method": req.method, "path": req.url.path, "query": dict(req.url.params), "body": req.content,
                     "ctype": req.headers.get("content-type", "")})
        return httpx.Response(200, json=body if body is not None else {})
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    return seen


def test_delete_has_no_email_analysis_kind():
    # v2 has never had DELETE /api/incidents/{i}/email/{aid}: the kind could only ever 404/405.
    kinds = typing.get_args(typing.get_type_hints(admin.fenrir_delete)["resource_type"])
    assert "email_analysis" not in kinds
    assert all("/email/" not in path for _, path in admin._DELETABLE.values())


def test_phase_history(monkeypatch):
    seen = _recorder(monkeypatch, body={"phase": "containment", "periods": []})
    asyncio.run(incidents.fenrir_incident_get(INC, phase_history=True))
    assert (seen[-1]["method"], seen[-1]["path"]) == ("GET", f"/api/incidents/{INC}/phase-history")


def test_phase_history_is_exclusive(monkeypatch):
    seen = _recorder(monkeypatch)
    with pytest.raises(FenrirError):
        asyncio.run(incidents.fenrir_incident_get(INC, snapshot=True, phase_history=True))
    assert seen == []


def test_scratchpad_versions(monkeypatch):
    seen = _recorder(monkeypatch, body={"items": [{"version_number": 2}]})
    asyncio.run(comms.fenrir_comms_list(INC, view="scratchpad_versions", note_id=NID))
    assert (seen[-1]["method"], seen[-1]["path"]) == ("GET", f"/api/incidents/{INC}/notes/{NID}/versions")


def test_scratchpad_versions_needs_note_id(monkeypatch):
    _recorder(monkeypatch)
    with pytest.raises(FenrirError):
        asyncio.run(comms.fenrir_comms_list(INC, view="scratchpad_versions"))


def test_file_exhibit_prefill(monkeypatch):
    seen = _recorder(monkeypatch, body={"acquired_at": None, "left_empty": []})
    asyncio.run(entities.fenrir_entity_list(INC, view="file_exhibit_prefill", file_id=FID))
    assert (seen[-1]["method"], seen[-1]["path"]) == ("GET", f"/api/incidents/{INC}/files/{FID}/exhibit-prefill")


def test_file_exhibit_prefill_needs_file_id(monkeypatch):
    _recorder(monkeypatch)
    with pytest.raises(FenrirError):
        asyncio.run(entities.fenrir_entity_list(INC, view="file_exhibit_prefill"))


def test_domain_check(monkeypatch):
    seen = _recorder(monkeypatch, body={"domain": "example.com"})
    asyncio.run(forensic.fenrir_email_analyze("domain_check", INC, data={"domain": "example.com", "selector": "s1"}))
    r = seen[-1]
    assert (r["method"], r["path"], r["query"]) == ("GET", f"/api/incidents/{INC}/email/domain-check",
                                                    {"domain": "example.com", "selector": "s1"})


def test_domain_check_confirm_outbound_only_when_passed(monkeypatch):
    seen = _recorder(monkeypatch)
    asyncio.run(forensic.fenrir_email_analyze("domain_check", INC, data={"domain": "example.com"},
                                              confirm_outbound=True))
    assert seen[-1]["query"] == {"domain": "example.com", "confirm_outbound": "true"}


def test_domain_check_needs_domain(monkeypatch):
    seen = _recorder(monkeypatch)
    with pytest.raises(FenrirError):
        asyncio.run(forensic.fenrir_email_analyze("domain_check", INC))
    assert seen == []


def test_analyze_bulk_sends_every_file_under_one_field(monkeypatch, tmp_path):
    monkeypatch.setenv("FENRIR_MCP_UPLOAD_DIRS", str(tmp_path))
    a, b = tmp_path / "a.eml", tmp_path / "b.eml"
    a.write_bytes(b"From: a@example.com\r\n\r\nhi")
    b.write_bytes(b"From: b@example.com\r\n\r\nho")
    seen = _recorder(monkeypatch, body={"batch_id": "x", "items": []})
    asyncio.run(forensic.fenrir_email_analyze("analyze_bulk", INC, file_paths=[str(a), str(b)],
                                              data={"acquired_at": "2026-11-01T10:00:00Z"}))
    r = seen[-1]
    assert (r["method"], r["path"]) == ("POST", f"/api/incidents/{INC}/email/analyze-bulk")
    assert r["ctype"].startswith("multipart/form-data")
    assert r["body"].count(b'name="files"') == 2
    assert b'filename="a.eml"' in r["body"] and b'filename="b.eml"' in r["body"]
    assert b'name="acquired_at"' in r["body"]
    assert str(tmp_path).encode() not in r["body"]                     # only basenames leave the machine


def test_analyze_bulk_refuses_a_file_outside_the_upload_dirs(monkeypatch, tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "x.eml"
    outside.write_bytes(b"x")
    monkeypatch.setenv("FENRIR_MCP_UPLOAD_DIRS", str(allowed))
    seen = _recorder(monkeypatch)
    with pytest.raises(RuntimeError, match="outside FENRIR_MCP_UPLOAD_DIRS"):
        asyncio.run(forensic.fenrir_email_analyze("analyze_bulk", INC, file_paths=[str(outside)]))
    assert seen == []


def test_incident_ref_setting_is_named_in_admin_platform():
    assert "/api/settings/incident-ref" in admin.fenrir_admin_platform.__doc__
