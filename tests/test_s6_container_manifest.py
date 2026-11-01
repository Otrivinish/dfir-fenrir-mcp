"""S6 (FENRIR evidence HLD 2026-10-31): container exhibits. fenrir_evidence_register passes container_format through
`data` to the upload session's complete body and to PATCH …/acquisition-record unchanged; fenrir_evidence_list
(view=manifest) reads GET …/evidence/{id}/manifest with limit / cursor / q; fenrir_evidence_custody(manifest_rebuild)
posts …/manifest/rebuild. The docstrings name the fields. Each test asserts the exact request sent."""

import asyncio
import json

import httpx
import pytest

from fenrir_mcp import client
from fenrir_mcp.client import FenrirError
from fenrir_mcp.tools import evidence

from test_g1b_uploads import EID, INC, fake  # noqa: F401  (the upload-session fake + its fixture)


def _recorder(monkeypatch, body=None):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append({"method": req.method, "path": req.url.path, "params": dict(req.url.params),
                     "body": req.content})
        return httpx.Response(200, json=body if body is not None else {"id": EID})
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    return seen


def test_register_digital_passes_container_format(fake, tmp_path):  # noqa: F811
    srv = fake()
    f = tmp_path / "WS-01_kape.zip"
    f.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    data = {"name": "KAPE triage", "identifier": "EXH-9", "container_format": "zip", "acquisition_scope": "logical"}
    asyncio.run(evidence.fenrir_evidence_register("digital", INC, file_path=str(f), data=data))
    assert srv.complete == {"purpose": "evidence", **data}


def test_acquisition_record_passes_container_format(monkeypatch):
    seen = _recorder(monkeypatch)
    asyncio.run(evidence.fenrir_evidence_register("acquisition_record", INC, evidence_id=EID,
                                                  data={"container_format": "tar"}))
    assert [(r["method"], r["path"]) for r in seen] == [("PATCH", f"/api/incidents/{INC}/evidence/{EID}/acquisition-record")]
    assert json.loads(seen[0]["body"]) == {"container_format": "tar"}


def test_manifest_view_paginates_and_filters(monkeypatch):
    page = {"items": [{"seq": 1, "entry_path": "C/Windows/System32/config/SAM", "tool_hash_match": True}],
            "next_cursor": "eyJzIjoxfQ"}
    seen = _recorder(monkeypatch, body=page)
    out = asyncio.run(evidence.fenrir_evidence_list(INC, view="manifest", evidence_id=EID, limit=50,
                                                    cursor="eyJzIjowfQ", q="system32\\config"))
    assert [(r["method"], r["path"]) for r in seen] == [("GET", f"/api/incidents/{INC}/evidence/{EID}/manifest")]
    assert seen[0]["params"] == {"limit": "50", "cursor": "eyJzIjowfQ", "q": "system32\\config"}
    assert out["next_cursor"] == "eyJzIjoxfQ" and out["items"][0]["tool_hash_match"] is True


def test_manifest_view_without_filters_and_its_guards(monkeypatch):
    seen = _recorder(monkeypatch, body={"items": [], "next_cursor": None})
    asyncio.run(evidence.fenrir_evidence_list(INC, view="manifest", evidence_id=EID))
    assert seen[0]["params"] == {}
    with pytest.raises(FenrirError, match="evidence_id"):
        asyncio.run(evidence.fenrir_evidence_list(INC, view="manifest"))
    with pytest.raises(FenrirError, match="view=manifest"):
        asyncio.run(evidence.fenrir_evidence_list(INC, view="list", q="x"))
    assert len(seen) == 1


def test_manifest_rebuild(monkeypatch):
    seen = _recorder(monkeypatch, body={"id": EID, "manifest_status": "pending"})
    out = asyncio.run(evidence.fenrir_evidence_custody("manifest_rebuild", INC, evidence_id=EID))
    assert [(r["method"], r["path"]) for r in seen] == [("POST", f"/api/incidents/{INC}/evidence/{EID}/manifest/rebuild")]
    assert out["manifest_status"] == "pending"


def test_docstrings_name_the_fields():
    reg, lst, cus = (evidence.fenrir_evidence_register.__doc__, evidence.fenrir_evidence_list.__doc__,
                     evidence.fenrir_evidence_custody.__doc__)
    for word in ("container_format", "zip", "tar", "ad1", "l01", "aff4l", "manifest_pending", "manifest_built"):
        assert word in reg, word
    for word in ("manifest", "entry_path", "source_path", "tool_hash_match", "manifest_sha256", "q ="):
        assert word in lst, word
    assert "manifest_rebuild" in cus
