"""S3 + S4 (FENRIR evidence HLD 2026-10-31): the photo record's fields reach FENRIR's multipart form on
fenrir_evidence_register(photo_upload) exactly as given, next to the image; fenrir_evidence_list(view=seal_record)
reads GET …/evidence/{id}/seal-record. The docstrings name the fields. Each test asserts the exact request sent."""

import asyncio

import httpx
import pytest

from fenrir_mcp import client
from fenrir_mcp.client import FenrirError
from fenrir_mcp.tools import evidence

INC = "11111111-1111-4111-8111-111111111111"
EID = "22222222-2222-4222-8222-222222222222"
UID = "44444444-4444-4444-8444-444444444444"


def _recorder(monkeypatch, body=None):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append({"method": req.method, "path": req.url.path, "ctype": req.headers.get("content-type", ""),
                     "body": req.content})
        return httpx.Response(200, json=body if body is not None else {"id": EID})
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    return seen


def _form_field(body: bytes, name: str) -> str:
    """The value of one multipart form field (no file part)."""
    marker = f'name="{name}"\r\n\r\n'.encode()
    start = body.index(marker) + len(marker)
    return body[start:body.index(b"\r\n--", start)].decode()


def test_photo_upload_sends_the_photo_record_as_form_fields(monkeypatch, tmp_path):
    monkeypatch.setenv("FENRIR_MCP_UPLOAD_DIRS", str(tmp_path))
    img = tmp_path / "IMG_0001.JPG"
    img.write_bytes(b"\xff\xd8\xff\xe0 jpeg bytes \xff\xd9")
    seen = _recorder(monkeypatch)
    data = {"caption": "screen in situ", "taken_at": "2026-10-20T10:15:30+02:00", "taken_by_name": "PC 4471 Smith",
            "camera": "Canon EOS R6 SN 0123", "context": "Laptop screen showing the open workbook"}
    asyncio.run(evidence.fenrir_evidence_register("photo_upload", INC, evidence_id=EID, file_path=str(img), data=data))
    r = seen[0]
    assert (r["method"], r["path"]) == ("POST", f"/api/incidents/{INC}/evidence/{EID}/photos")
    assert r["ctype"].startswith("multipart/form-data")
    for k, v in data.items():
        assert _form_field(r["body"], k) == v, k                    # verbatim: FENRIR validates and normalises
    assert b'filename="IMG_0001.JPG"' in r["body"] and b"jpeg bytes" in r["body"]
    assert str(tmp_path).encode() not in r["body"]                    # only the basename leaves the machine


def test_photo_upload_with_a_photographer_user(monkeypatch, tmp_path):
    monkeypatch.setenv("FENRIR_MCP_UPLOAD_DIRS", str(tmp_path))
    img = tmp_path / "p.png"
    img.write_bytes(b"\x89PNG")
    seen = _recorder(monkeypatch)
    asyncio.run(evidence.fenrir_evidence_register("photo_upload", INC, evidence_id=EID, file_path=str(img),
                                                  data={"taken_by_id": UID}))
    assert _form_field(seen[0]["body"], "taken_by_id") == UID
    assert b'name="taken_by_name"' not in seen[0]["body"]


def test_seal_record_view(monkeypatch):
    rec = {"seal_tst_subject": None, "seal_record_sha256": "a" * 64, "sealed_record": '{"v":1}',
           "recomputed_now_sha256": "a" * 64, "changed_since_seal": False}
    seen = _recorder(monkeypatch, body=rec)
    out = asyncio.run(evidence.fenrir_evidence_list(INC, view="seal_record", evidence_id=EID))
    assert [(r["method"], r["path"]) for r in seen] == [("GET", f"/api/incidents/{INC}/evidence/{EID}/seal-record")]
    assert out["seal_record_sha256"] == "a" * 64 and out["changed_since_seal"] is False


def test_seal_record_view_needs_evidence_id(monkeypatch):
    seen = _recorder(monkeypatch)
    with pytest.raises(FenrirError, match="evidence_id"):
        asyncio.run(evidence.fenrir_evidence_list(INC, view="seal_record"))
    assert seen == []


def test_docstrings_name_the_fields():
    reg = evidence.fenrir_evidence_register.__doc__
    for f in ("taken_at", "invalid_taken_at", "taken_by_id", "taken_by_name", "taken_by_conflict", "camera",
              "context", "original_filename", "source_device", "source_unknown_reason"):
        assert f in reg, f
    lst = evidence.fenrir_evidence_list.__doc__
    for f in ("seal_record", "seal_record_sha256", "sealed_record", "seal_tst_subject", "recomputed_now_sha256",
              "changed_since_seal", "evidence_not_sealed", "taken_at_unparsed"):
        assert f in lst, f
    assert "view=seal_record" in evidence.fenrir_evidence_custody.__doc__
