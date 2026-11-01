"""FENRIR H1: artifact delete sends its reason in the JSON body; register creates hash IOCs only
when asked (create_hash_iocs form field); promote_iocs POSTs …/hash-iocs. Each test asserts the
exact request sent."""

import asyncio
import json

import httpx

from fenrir_mcp import client
from fenrir_mcp.tools import admin, forensic

INC = "11111111-1111-4111-8111-111111111111"
AID = "55555555-5555-4555-8555-555555555555"


def _recorder(monkeypatch, status=200, body=None):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append({"method": req.method, "path": req.url.path, "ctype": req.headers.get("content-type", ""),
                     "body": req.content})
        if status == 204:
            return httpx.Response(204)
        return httpx.Response(status, json=body if body is not None else {})
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    return seen


def test_artifact_delete_sends_reason_in_body(monkeypatch):
    seen = _recorder(monkeypatch, status=204)
    asyncio.run(admin.fenrir_delete("artifact", AID, incident_id=INC, reason="duplicate upload of the sample"))
    r = seen[-1]
    assert (r["method"], r["path"]) == ("DELETE", f"/api/incidents/{INC}/artifacts/{AID}")
    assert json.loads(r["body"]) == {"reason": "duplicate upload of the sample"}


def test_register_without_option_sends_no_ioc_flag(monkeypatch, tmp_path):
    seen = _recorder(monkeypatch, status=201, body={"id": AID})
    monkeypatch.setenv("FENRIR_MCP_UPLOAD_DIRS", str(tmp_path))
    f = tmp_path / "note.txt"
    f.write_bytes(b"ransom note")
    asyncio.run(forensic.fenrir_artifact_write("register", INC, file_path=str(f)))
    r = seen[-1]
    assert (r["method"], r["path"]) == ("POST", f"/api/incidents/{INC}/artifacts")
    assert b"create_hash_iocs" not in r["body"]


def test_register_with_create_hash_iocs_sends_form_true(monkeypatch, tmp_path):
    seen = _recorder(monkeypatch, status=201, body={"id": AID})
    monkeypatch.setenv("FENRIR_MCP_UPLOAD_DIRS", str(tmp_path))
    f = tmp_path / "evil.exe"
    f.write_bytes(b"MZ")
    asyncio.run(forensic.fenrir_artifact_write("register", INC, file_path=str(f), data={"create_hash_iocs": True}))
    body = seen[-1]["body"]
    assert b'name="create_hash_iocs"\r\n\r\ntrue' in body


def test_promote_iocs_posts_hash_iocs(monkeypatch):
    seen = _recorder(monkeypatch, body={"created": [], "existing": []})
    asyncio.run(forensic.fenrir_artifact_write("promote_iocs", INC, artifact_id=AID))
    r = seen[-1]
    assert (r["method"], r["path"]) == ("POST", f"/api/incidents/{INC}/artifacts/{AID}/hash-iocs")
