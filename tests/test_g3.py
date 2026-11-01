"""G3: register-first Email, Browser history and PCAP. fenrir_email_analyze / fenrir_pcap_analyze /
fenrir_webhistory_import gain from_evidence (+ promote for PCAP and browser history), and
fenrir_evidence_register gains acquisition_record (complete a draft exhibit, then seal). Each test
asserts the exact request sent."""

import asyncio
import json

import httpx
import pytest

from fenrir_mcp import client, tools
from fenrir_mcp.client import FenrirError
from fenrir_mcp.tools import evidence, forensic

INC = "11111111-1111-4111-8111-111111111111"
EID = "22222222-2222-4222-8222-222222222222"
RID = "33333333-3333-4333-8333-333333333333"


def _recorder(monkeypatch, status=200, body=None):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append({"method": req.method, "path": req.url.path, "ctype": req.headers.get("content-type", ""),
                     "body": req.content})
        return httpx.Response(status, json=body if body is not None else {"id": RID})
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    return seen


def test_tools_stay_standard_writes():
    for name in ("fenrir_email_analyze", "fenrir_pcap_analyze", "fenrir_webhistory_import", "fenrir_evidence_register"):
        assert name in set(tools.registered("standard"))
        assert name not in set(tools.registered("readonly"))


# ── email ────────────────────────────────────────────────────────────────────

def test_email_from_evidence_posts_without_a_body(monkeypatch):
    seen = _recorder(monkeypatch, status=201, body={"id": RID, "evidence_id": EID, "exhibit_link": "from_evidence"})
    out = asyncio.run(forensic.fenrir_email_analyze("from_evidence", INC, evidence_id=EID))
    assert [(r["method"], r["path"]) for r in seen] == [("POST", f"/api/incidents/{INC}/email/from-evidence/{EID}")]
    assert seen[0]["body"] == b""
    assert out["exhibit_link"] == "from_evidence"


def test_email_from_evidence_needs_evidence_id(monkeypatch):
    seen = _recorder(monkeypatch)
    with pytest.raises(FenrirError, match="evidence_id"):
        asyncio.run(forensic.fenrir_email_analyze("from_evidence", INC))
    assert seen == []


def test_email_analyze_streams_an_upload_session_with_acquired_at(monkeypatch, tmp_path):
    # G1 stage 3b: was a multipart POST …/email/analyze; now an upload session, then from-evidence.
    from test_g1b_uploads import FakeFenrir
    monkeypatch.setenv("FENRIR_MCP_UPLOAD_DIRS", str(tmp_path))
    f = tmp_path / "phish.eml"
    f.write_bytes(b"Subject: hi\r\n\r\nbody")
    srv = FakeFenrir()
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(srv), base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    asyncio.run(forensic.fenrir_email_analyze("analyze", INC, file_path=str(f), data={"acquired_at": "2026-03-01T09:00:00Z"}))
    assert srv.body["filename"] == "phish.eml" and srv.body["purpose"] == "email"
    assert srv.complete == {"purpose": "email", "acquired_at": "2026-03-01T09:00:00Z"}
    assert bytes(srv.received) == f.read_bytes()
    assert srv.analysed[0].endswith("/email/from-evidence/22222222-2222-4222-8222-222222222222")
    assert not any("multipart" in c[2] for c in srv.calls)


def test_email_mint_is_still_routed_for_legacy_analyses(monkeypatch):
    seen = _recorder(monkeypatch)
    asyncio.run(forensic.fenrir_email_analyze("mint_evidence", INC, analysis_id=RID))
    assert (seen[0]["method"], seen[0]["path"]) == ("POST", f"/api/incidents/{INC}/email/{RID}/mint-evidence")


# ── pcap ─────────────────────────────────────────────────────────────────────

def test_pcap_from_evidence(monkeypatch):
    seen = _recorder(monkeypatch, status=201, body={"result_id": RID, "evidence_id": EID})
    asyncio.run(forensic.fenrir_pcap_analyze("from_evidence", INC, evidence_id=EID))
    assert [(r["method"], r["path"]) for r in seen] == [("POST", f"/api/incidents/{INC}/pcap/from-evidence/{EID}")]
    assert seen[0]["body"] == b""


def test_pcap_from_evidence_needs_evidence_id(monkeypatch):
    seen = _recorder(monkeypatch)
    with pytest.raises(FenrirError, match="evidence_id"):
        asyncio.run(forensic.fenrir_pcap_analyze("from_evidence", INC))
    assert seen == []


def test_pcap_promote_sends_indices_as_json(monkeypatch):
    seen = _recorder(monkeypatch, body={"created": 2, "created_indices": [0, 4]})
    out = asyncio.run(forensic.fenrir_pcap_analyze("promote", INC, result_id=RID,
                                                   data={"indices": [0, 4], "ir_phase": "detection_and_analysis"}))
    r = seen[0]
    assert (r["method"], r["path"]) == ("POST", f"/api/incidents/{INC}/pcap/{RID}/promote")
    assert r["ctype"].startswith("application/json")
    assert json.loads(r["body"]) == {"indices": [0, 4], "ir_phase": "detection_and_analysis"}
    assert out["created"] == 2


@pytest.mark.parametrize("data", [None, {}, {"indices": []}, {"indices": "0"}])
def test_pcap_promote_refuses_a_bad_body_locally(monkeypatch, data):
    seen = _recorder(monkeypatch)
    with pytest.raises(FenrirError, match="indices"):
        asyncio.run(forensic.fenrir_pcap_analyze("promote", INC, result_id=RID, data=data))
    assert seen == []


def test_pcap_promote_needs_result_id(monkeypatch):
    seen = _recorder(monkeypatch)
    with pytest.raises(FenrirError, match="result_id"):
        asyncio.run(forensic.fenrir_pcap_analyze("promote", INC, data={"indices": [0]}))
    assert seen == []


def test_pcap_import_iocs_unchanged(monkeypatch):
    seen = _recorder(monkeypatch, status=201, body={"imported": 1, "skipped_duplicates": 0})
    asyncio.run(forensic.fenrir_pcap_analyze("import_iocs", INC, result_id=RID,
                                             data={"iocs": [{"type": "ip", "value": "203.0.113.50"}]}))
    assert (seen[0]["method"], seen[0]["path"]) == ("POST", f"/api/incidents/{INC}/pcap/{RID}/import-iocs")


# ── browser history ──────────────────────────────────────────────────────────

def test_webhistory_from_evidence_sends_browser(monkeypatch):
    seen = _recorder(monkeypatch, status=201, body={"id": RID, "evidence_id": EID})
    asyncio.run(forensic.fenrir_webhistory_import("from_evidence", INC, evidence_id=EID,
                                                  data={"browser": "firefox", "form_history_evidence_id": RID}))
    r = seen[0]
    assert (r["method"], r["path"]) == ("POST", f"/api/incidents/{INC}/webhistory/from-evidence/{EID}")
    assert json.loads(r["body"]) == {"browser": "firefox", "form_history_evidence_id": RID}


@pytest.mark.parametrize("kw,msg", [({}, "evidence_id"), ({"evidence_id": EID}, "browser")])
def test_webhistory_from_evidence_local_checks(monkeypatch, kw, msg):
    seen = _recorder(monkeypatch)
    with pytest.raises(FenrirError, match=msg):
        asyncio.run(forensic.fenrir_webhistory_import("from_evidence", INC, **kw))
    assert seen == []


def test_webhistory_promote(monkeypatch):
    seen = _recorder(monkeypatch, body={"created": 1, "created_ids": [RID]})
    body = {"visit_ids": [RID], "download_ids": [], "ir_phase": "detection_and_analysis"}
    asyncio.run(forensic.fenrir_webhistory_import("promote", INC, data=body))
    r = seen[0]
    assert (r["method"], r["path"]) == ("POST", f"/api/incidents/{INC}/webhistory/promote")
    assert json.loads(r["body"]) == body


def test_webhistory_promote_needs_ids(monkeypatch):
    seen = _recorder(monkeypatch)
    with pytest.raises(FenrirError, match="visit_ids"):
        asyncio.run(forensic.fenrir_webhistory_import("promote", INC, data={"ir_phase": "detection_and_analysis"}))
    assert seen == []


def test_webhistory_upload_streams_an_upload_session_with_browser(monkeypatch, tmp_path):
    # G1 stage 3b: was a multipart POST …/webhistory; now an upload session, then from-evidence {browser}.
    from test_g1b_uploads import FakeFenrir
    monkeypatch.setenv("FENRIR_MCP_UPLOAD_DIRS", str(tmp_path))
    f = tmp_path / "History"
    f.write_bytes(b"SQLite format 3\x00rest")
    srv = FakeFenrir()
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(srv), base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    asyncio.run(forensic.fenrir_webhistory_import("upload", INC, file_path=str(f), data={"browser": "chrome"}))
    assert srv.complete == {"purpose": "webhistory", "browser": "chrome"}
    assert srv.analysed[1] == b'{"browser":"chrome"}' and "/webhistory/from-evidence/" in srv.analysed[0]
    assert not any("multipart" in c[2] for c in srv.calls)


# ── draft exhibit: complete the acquisition record ────────────────────────────

def test_acquisition_record_patches_json(monkeypatch):
    seen = _recorder(monkeypatch, body={"id": EID, "lawful_basis": "ir"})
    data = {"lawful_basis": "ir", "device_types": ["computer"], "acquisition_tool": "FTK Imager",
            "acquisition_tool_version": "4.7", "acquired_at": None}
    asyncio.run(evidence.fenrir_evidence_register("acquisition_record", INC, evidence_id=EID, data=data))
    r = seen[0]
    assert (r["method"], r["path"]) == ("PATCH", f"/api/incidents/{INC}/evidence/{EID}/acquisition-record")
    assert r["ctype"].startswith("application/json")
    assert json.loads(r["body"]) == data          # an explicit null is sent (it clears the field)


@pytest.mark.parametrize("kw,msg", [({"data": {"lawful_basis": "ir"}}, "evidence_id"), ({"evidence_id": EID}, "data")])
def test_acquisition_record_local_checks(monkeypatch, kw, msg):
    seen = _recorder(monkeypatch)
    with pytest.raises(FenrirError, match=msg):
        asyncio.run(evidence.fenrir_evidence_register("acquisition_record", INC, **kw))
    assert seen == []


def test_docstrings_flag_register_first():
    for fn in (forensic.fenrir_email_analyze, forensic.fenrir_pcap_analyze, forensic.fenrir_webhistory_import):
        doc = fn.__doc__ or ""
        assert "DRAFT" in doc and "from_evidence" in doc
    assert "acquisition_record" in (evidence.fenrir_evidence_register.__doc__ or "")
