"""EI (FENRIR automatic exhibit identifiers): the MCP never requires an identifier — fenrir_evidence_register passes
`data` through without one (digital: the upload session's complete body; physical: the POST body) and returns the
evidence FENRIR created, with the identifier it assigned. The naming convention and the preview are reached through
fenrir_api (GET / PATCH /api/settings/evidence-identifier, GET …/evidence/next-identifier): the denylist lets them
through and the tool description says so."""

import asyncio
import json

import httpx
import pytest

from fenrir_mcp import client, denylist, openapi_guard
from fenrir_mcp.client import FenrirError
from fenrir_mcp.tools import escape, evidence

from test_g1b_uploads import EID, INC, fake  # noqa: F401  (the upload-session fake + its fixture)

ASSIGNED = "INC-2026-00009-20261101-001"


def test_digital_without_identifier_sends_none_and_returns_the_assigned_one(fake, tmp_path):  # noqa: F811
    srv = fake()
    f = tmp_path / "disk.bin"
    f.write_bytes(b"bytes")
    out = asyncio.run(evidence.fenrir_evidence_register("digital", INC, file_path=str(f), data={"name": "disk"}))
    assert srv.complete == {"purpose": "evidence", "name": "disk"}          # no identifier invented locally
    assert out["identifier"] == "PCAP-ABC"                                   # whatever FENRIR returned, unchanged


def test_physical_without_identifier(monkeypatch):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.method, req.url.path, json.loads(req.content or b"null")))
        return httpx.Response(201, json={"id": EID, "identifier": ASSIGNED})
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    out = asyncio.run(evidence.fenrir_evidence_register("physical", INC, data={"name": "Laptop", "identifier": None}))
    assert seen == [("POST", f"/api/incidents/{INC}/evidence/physical", {"name": "Laptop", "identifier": None})]
    assert out["identifier"] == ASSIGNED


@pytest.mark.parametrize("verb,path", [("GET", "/api/settings/evidence-identifier"),
                                       ("PATCH", "/api/settings/evidence-identifier"),
                                       ("GET", f"/api/incidents/{INC}/evidence/next-identifier")])
def test_convention_and_preview_reachable_through_fenrir_api(monkeypatch, verb, path):
    assert denylist.is_denied(verb, path) is None
    monkeypatch.setattr(openapi_guard, "_ops", openapi_guard._compile({"paths": {
        "/api/settings/evidence-identifier": {"get": {}, "patch": {}},
        "/api/incidents/{incident_id}/evidence/next-identifier": {"get": {}}}}))
    openapi_guard.validate(verb, path, "standard")


def test_patch_needs_standard_mode(monkeypatch):
    monkeypatch.setattr(openapi_guard, "_ops", openapi_guard._compile({"paths": {
        "/api/settings/evidence-identifier": {"get": {}, "patch": {}}}}))
    openapi_guard.validate("GET", "/api/settings/evidence-identifier", "readonly")
    with pytest.raises(FenrirError):
        openapi_guard.validate("PATCH", "/api/settings/evidence-identifier", "readonly")


def test_descriptions_say_what_is_assigned_and_where_the_convention_is():
    doc = evidence.fenrir_evidence_register.__doc__ or ""
    assert "identifier is optional" in doc and "{incident}-{date}-{seq:3}" in doc
    assert "/api/settings/evidence-identifier" in doc and "next-identifier" in doc
    assert "fenrir_api" in doc
    assert "/api/" in (escape.fenrir_api.__doc__ or "")
