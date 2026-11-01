"""G5: working copies, legal hold. fenrir_evidence_custody gains working_copy_record (alias
working_copy_create), working_copy_issue and legal_hold_set / legal_hold_release. The copy's bytes
never come here: the issue response's download_url is for the operator's browser, and the denylist
refuses the download route for curated tools and the escape hatch alike. Each test asserts the exact
request sent."""

import asyncio
import json

import httpx
import pytest

from fenrir_mcp import client, denylist
from fenrir_mcp.client import FenrirError
from fenrir_mcp.tools import evidence

INC = "11111111-1111-4111-8111-111111111111"
EID = "22222222-2222-4222-8222-222222222222"
CID = "44444444-4444-4444-8444-444444444444"
SHA = "a" * 64


def _recorder(monkeypatch, status=200, body=None):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append({"method": req.method, "path": req.url.path, "query": dict(req.url.params),
                     "ctype": req.headers.get("content-type", ""), "body": req.content})
        return httpx.Response(status, json=body if body is not None else {"id": CID})
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    return seen


@pytest.mark.parametrize("action", ["working_copy_record", "working_copy_create"])
def test_record_lab_copy_posts_the_copy_hashes(monkeypatch, action):
    seen = _recorder(monkeypatch, status=201, body={"id": CID, "kind": "lab_copy", "status": "verified"})
    data = {"purpose": "imaged to WS-04", "copy_sha256": SHA, "copy_tool": "FTK Imager 4.7.1"}
    out = asyncio.run(evidence.fenrir_evidence_custody(action, INC, evidence_id=EID, data=data))
    assert [(r["method"], r["path"]) for r in seen] == [("POST", f"/api/incidents/{INC}/evidence/{EID}/working-copy")]
    assert seen[0]["ctype"].startswith("application/json") and json.loads(seen[0]["body"]) == data
    assert out["status"] == "verified"


def test_issue_posts_and_never_fetches_the_bytes(monkeypatch):
    monkeypatch.setenv("FENRIR_URL", "https://fenrir.test")
    url = f"/api/incidents/{INC}/evidence/{EID}/working-copies/{CID}/download?token=t0k3n"
    seen = _recorder(monkeypatch, status=201, body={"copy": {"id": CID, "status": "issued"}, "download_url": url,
                                                    "token_expires_at": "2026-10-04T13:10:00Z"})
    out = asyncio.run(evidence.fenrir_evidence_custody(
        "working_copy_issue", INC, evidence_id=EID, data={"purpose": "memory analysis", "destination_note": "AN-07"}))
    assert [(r["method"], r["path"]) for r in seen] == [("POST", f"/api/incidents/{INC}/evidence/{EID}/working-copies")]
    assert json.loads(seen[0]["body"]) == {"purpose": "memory analysis", "destination_note": "AN-07"}
    assert out["download_url"] == "https://fenrir.test" + url   # for the operator's browser; no GET of the bytes


def test_the_download_route_is_denied_everywhere(monkeypatch):
    path = f"/api/incidents/{INC}/evidence/{EID}/working-copies/{CID}/download"
    assert denylist.is_denied("GET", path)
    assert denylist.is_denied("GET", path + "?token=x")
    seen = _recorder(monkeypatch)
    with pytest.raises(FenrirError, match="denied by policy"):
        asyncio.run(client.request("GET", path, params={"token": "x"}))
    assert seen == []


def test_spec_scan_flags_nothing_for_the_download_route():
    spec = {"paths": {"/api/incidents/{incident_id}/evidence/{evidence_id}/working-copies/{copy_id}/download": {
        "get": {"responses": {"200": {"content": {"application/octet-stream": {}}}}}}}}
    assert denylist.scan_spec_for_bytes(spec) == []


@pytest.mark.parametrize("action,held", [("legal_hold_set", True), ("legal_hold_release", False)])
def test_legal_hold_puts_the_state_and_reason(monkeypatch, action, held):
    seen = _recorder(monkeypatch, body={"id": EID, "legal_hold": held})
    # G-fix B (L20): a release also needs confirm=true
    asyncio.run(evidence.fenrir_evidence_custody(action, INC, evidence_id=EID, data={"reason": "counsel letter"},
                                                 confirm=True))
    assert [(r["method"], r["path"]) for r in seen] == [("PUT", f"/api/incidents/{INC}/evidence/{EID}/legal-hold")]
    assert json.loads(seen[0]["body"]) == {"legal_hold": held, "reason": "counsel letter"}


@pytest.mark.parametrize("data", [None, {}, {"reason": "   "}])
def test_legal_hold_needs_a_reason(monkeypatch, data):
    seen = _recorder(monkeypatch)
    with pytest.raises(FenrirError, match="reason"):
        asyncio.run(evidence.fenrir_evidence_custody("legal_hold_set", INC, evidence_id=EID, data=data))
    assert seen == []


def test_legal_hold_needs_evidence_id(monkeypatch):
    seen = _recorder(monkeypatch)
    with pytest.raises(FenrirError, match="evidence_id"):
        asyncio.run(evidence.fenrir_evidence_custody("legal_hold_release", INC, data={"reason": "x"}))
    assert seen == []


def test_examination_session_passes_the_copy_bracket(monkeypatch):
    seen = _recorder(monkeypatch, body={"ok": True})
    data = {"tool": "Volatility 3", "working_copy_id": CID, "post_exam_copy_hash": SHA}
    asyncio.run(evidence.fenrir_evidence_custody("examination_session", INC, evidence_id=EID, data=data))
    assert [(r["method"], r["path"]) for r in seen] == [
        ("POST", f"/api/incidents/{INC}/evidence/{EID}/examination-session")]
    assert json.loads(seen[0]["body"]) == data


def test_api_error_codes_reach_the_caller(monkeypatch):
    _recorder(monkeypatch, status=422, body={"detail": "Give the hash your copying tool reported", "code": "copy_hash_required"})
    with pytest.raises(FenrirError, match="copy_hash_required|copying tool"):
        asyncio.run(evidence.fenrir_evidence_custody("working_copy_record", INC, evidence_id=EID, data={"purpose": "x"}))
