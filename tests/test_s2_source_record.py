"""S2 (FENRIR evidence HLD 2026-10-31): the source location record and device identifiers reach FENRIR through
fenrir_evidence_register's `data` unchanged — verbatim strings (no trim), nested source_details, explicit nulls — on
every action that takes them. The local file_path never fills them. Each test asserts the exact request body."""

import asyncio
import json

import httpx

from fenrir_mcp import client
from fenrir_mcp.tools import evidence

from test_g1b_uploads import EID, INC, fake  # noqa: F401  (the upload-session fake + its fixture)

SOURCE = {
    "make": "Dell", "model": "Latitude 7440", "serial": "SN-WS01",
    "source_system": "  WS-01.contoso.local",
    "source_path": "C:\\Users\\jdoe\\Desktop\\Q3.xlsx ",
    "source_path_style": "windows",
    "source_details": {
        "filename_on_source": "Q3.xlsx",
        "volume": {"label": "OS", "serial": "1A2B-3C4D", "filesystem": "NTFS"},
        "times": {"m": {"utc": "2026-10-20T06:00:00Z", "as_recorded": "20/10/2026 08:00:00"},
                  "basis": "NTFS $STANDARD_INFORMATION", "read_by": "MFTECmd 1.2.2.1"},
        "provider": {"provider": "SharePoint", "provider_hash": {"algorithm": "QuickXorHash", "value": "AAAA="}},
        "mail": {"mailbox": "jdoe@contoso.com", "message_id": "<a@b>"},
    },
}


def _recorder(monkeypatch):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append({"method": req.method, "path": req.url.path, "json": json.loads(req.content or b"null")})
        return httpx.Response(200, json={"id": EID})
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    return seen


def test_digital_complete_carries_the_source_record_verbatim(fake, tmp_path):  # noqa: F811
    srv = fake()
    f = tmp_path / "analyst-copy-of-Q3.xlsx"
    f.write_bytes(b"bytes")
    data = {"name": "Q3", "identifier": "EXH-S2", **SOURCE}
    asyncio.run(evidence.fenrir_evidence_register("digital", INC, file_path=str(f), data=data))
    assert srv.complete == {"purpose": "evidence", **data}
    assert srv.body["filename"] == "analyst-copy-of-Q3.xlsx"           # the upload name, never the source path
    assert str(tmp_path) not in json.dumps(srv.complete)                # the local path never fills the record


def test_physical_acquisition_record_and_update_pass_the_fields_through(monkeypatch):
    seen = _recorder(monkeypatch)
    phys = {"name": "Laptop", "identifier": "EXH-P", "make": "Dell", "serial": "5CG1", "physical_location": "B-12",
            "source_system": "LAPTOP-JDOE", "source_details": {"asset_tag": "IT-0042"}}
    asyncio.run(evidence.fenrir_evidence_register("physical", INC, data=phys))
    asyncio.run(evidence.fenrir_evidence_register("acquisition_record", INC, evidence_id=EID, data=SOURCE))
    amend = {"source_path": "\\\\?\\UNC\\fs01\\share\\Q3.xlsx", "source_path_style": "unc", "serial": None,
             "source_unknown_reason": None}
    asyncio.run(evidence.fenrir_evidence_register("update", INC, evidence_id=EID, data=amend))
    base = f"/api/incidents/{INC}/evidence"
    assert [(r["method"], r["path"]) for r in seen] == [
        ("POST", f"{base}/physical"), ("PATCH", f"{base}/{EID}/acquisition-record"), ("PATCH", f"{base}/{EID}")]
    assert [r["json"] for r in seen] == [phys, SOURCE, amend]           # explicit nulls kept: they clear a field


def test_the_docstring_names_the_source_fields():
    doc = evidence.fenrir_evidence_register.__doc__
    for f in ("make / model / serial", "source_system", "source_path", "source_path_style", "source_details",
              "source_unknown_reason", "source_path_norm", "provider_hash", "basis", "read_by"):
        assert f in doc, f
