"""FENRIR H3: outbound TLP policy. fenrir_ioc_enrich and fenrir_osint_enrich expose
confirm_outbound; without it nothing extra is sent, with it the exact flag goes out, and a
409 outbound_confirmation_required reaches the caller as an error (no silent retry)."""

import asyncio

import httpx
import pytest

from fenrir_mcp import client, refcache
from fenrir_mcp.client import FenrirError
from fenrir_mcp.tools import forensic, iocs

INC = "11111111-1111-4111-8111-111111111111"
IOC = "22222222-2222-4222-8222-222222222222"


def _recorder(monkeypatch, status=200, body=None):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append({"method": req.method, "path": req.url.path, "query": dict(req.url.params),
                     "body": req.content})
        if req.method == "GET" and req.url.path == f"/api/incidents/{INC}":
            return httpx.Response(200, json={"id": INC})
        return httpx.Response(status, json=body if body is not None else {"ok": True})
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    return seen


def test_ioc_enrich_one_flag_only_when_confirmed(monkeypatch):
    seen = _recorder(monkeypatch, body=[])
    asyncio.run(iocs.fenrir_ioc_enrich("enrich_one", INC, ioc_id=IOC))
    assert (seen[-1]["path"], seen[-1]["query"]) == (f"/api/incidents/{INC}/iocs/{IOC}/enrich", {})
    asyncio.run(iocs.fenrir_ioc_enrich("enrich_one", INC, ioc_id=IOC, confirm_outbound=True))
    assert seen[-1]["query"] == {"confirm_outbound": "true"}


def test_ioc_enrich_all_flag_in_body(monkeypatch):
    seen = _recorder(monkeypatch)
    asyncio.run(iocs.fenrir_ioc_enrich("enrich_all", INC))
    assert seen[-1]["path"] == f"/api/incidents/{INC}/iocs/enrich-all" and seen[-1]["body"] in (b"", b"null")
    asyncio.run(iocs.fenrir_ioc_enrich("enrich_all", INC, confirm_outbound=True))
    assert seen[-1]["body"] == b'{"confirm_outbound":true}'


def test_osint_enrich_passes_incident_and_flag(monkeypatch):
    seen = _recorder(monkeypatch, body={"results": []})
    data = {"indicator": "198.51.100.7", "ioc_type": "ipv4", "sources": ["geoip"]}
    asyncio.run(forensic.fenrir_osint_enrich("enrich", data=data))
    assert seen[-1]["path"] == "/api/osint/enrich"
    assert b"incident_id" not in seen[-1]["body"] and b"confirm_outbound" not in seen[-1]["body"]
    asyncio.run(forensic.fenrir_osint_enrich("enrich", incident_id=INC, data=data, confirm_outbound=True))
    assert f'"incident_id":"{INC}"'.encode() in seen[-1]["body"] and b'"confirm_outbound":true' in seen[-1]["body"]
    assert data == {"indicator": "198.51.100.7", "ioc_type": "ipv4", "sources": ["geoip"]}   # caller's dict untouched


def test_osint_enrich_resolves_incident_ref(monkeypatch):
    seen = _recorder(monkeypatch, body={"results": []})
    refcache.learn({"items": [{"id": INC, "ref": "INC-2026-00042"}]})   # isolated per test (conftest)
    asyncio.run(forensic.fenrir_osint_enrich("enrich", incident_id="INC-2026-00042",
                                             data={"indicator": "x.test", "ioc_type": "domain", "sources": ["dns"]}))
    assert seen[-1]["path"] == "/api/osint/enrich" and f'"incident_id":"{INC}"'.encode() in seen[-1]["body"]


def test_confirmation_409_surfaces_as_error(monkeypatch):
    seen = _recorder(monkeypatch, status=409, body={"detail": "Automatic outbound is suppressed because the "
                                                    "incident is TLP:RED.", "code": "outbound_confirmation_required",
                                                    "reason": "tlp_red"})
    with pytest.raises(FenrirError) as ei:
        asyncio.run(iocs.fenrir_ioc_enrich("enrich_one", INC, ioc_id=IOC))
    assert "outbound_confirmation_required" in str(ei.value) or "TLP:RED" in str(ei.value)
    assert len([r for r in seen if r["method"] == "POST"]) == 1   # no automatic retry with the flag
