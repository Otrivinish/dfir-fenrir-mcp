"""FENRIR K1: Disclosure packages. fenrir_evidence_custody gains disclosure_create (POST …/disclosures, a long
call because the one-time bundle password is only in that response; include_unsealed_drafts passed through) and
fenrir_evidence_list gains the disclosures / disclosure_item views. Each test asserts the exact request sent."""

import asyncio
import json

import httpx
import pytest

from fenrir_mcp import client, config
from fenrir_mcp.client import FenrirError
from fenrir_mcp.tools import evidence

INC = "11111111-1111-4111-8111-111111111111"
EID = "22222222-2222-4222-8222-222222222222"
DID = "33333333-3333-4333-8333-333333333333"


def _recorder(monkeypatch, status=200, body=None):
    seen = []

    class T(httpx.AsyncBaseTransport):
        async def handle_async_request(self, req: httpx.Request) -> httpx.Response:
            await req.aread()
            seen.append({"method": req.method, "path": req.url.path, "query": dict(req.url.params),
                         "body": req.content, "timeout": req.extensions.get("timeout", {})})
            return httpx.Response(status, json=body if body is not None else {"id": DID})
    monkeypatch.setattr(client, "_bearer", lambda: {})
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=T(), base_url="https://fenrir.test",
                                                             timeout=httpx.Timeout(config.READ_TIMEOUT, connect=5)))
    return seen


def test_disclosure_create_posts_the_request_as_a_long_call(monkeypatch):
    seen = _recorder(monkeypatch, status=201, body={"id": DID, "purpose": "regulator", "bundle_password": "pw"})
    data = {"purpose": "regulator", "recipient_name": "Case officer", "item_ids": [EID], "case_reference": "IMY-1",
            "requesting_authority": "IMY", "legal_basis": "statutory"}
    out = asyncio.run(evidence.fenrir_evidence_custody("disclosure_create", INC, data=data, include_unsealed_drafts=True))
    assert [(r["method"], r["path"]) for r in seen] == [("POST", f"/api/incidents/{INC}/disclosures")]
    assert json.loads(seen[0]["body"]) == {**data, "include_unsealed_drafts": True}
    assert seen[0]["timeout"]["read"] == config.LONG_READ_TIMEOUT
    assert out["bundle_password"] == "pw"                   # relayed, the only copy


def test_disclosure_create_needs_no_evidence_id(monkeypatch):
    seen = _recorder(monkeypatch, status=201)
    asyncio.run(evidence.fenrir_evidence_custody("disclosure_create", INC, data={"purpose": "internal",
                                                                                 "recipient_name": "Counsel"}))
    assert json.loads(seen[0]["body"]) == {"purpose": "internal", "recipient_name": "Counsel"}


def test_disclosures_list_and_item(monkeypatch):
    seen = _recorder(monkeypatch, body={"items": [], "next_cursor": None})
    asyncio.run(evidence.fenrir_evidence_list(INC, view="disclosures", purpose="law_enforcement", limit=10))
    asyncio.run(evidence.fenrir_evidence_list(INC, view="disclosure_item", disclosure_id=DID))
    assert [(r["method"], r["path"], r["query"]) for r in seen] == [
        ("GET", f"/api/incidents/{INC}/disclosures", {"purpose": "law_enforcement", "limit": "10"}),
        ("GET", f"/api/incidents/{INC}/disclosures/{DID}", {}),
    ]


def test_disclosure_item_needs_its_id(monkeypatch):
    seen = _recorder(monkeypatch)
    with pytest.raises(FenrirError, match="disclosure_id is required"):
        asyncio.run(evidence.fenrir_evidence_list(INC, view="disclosure_item"))
    assert seen == []


def test_docs_name_the_rights_and_the_deprecation():
    doc = evidence.fenrir_evidence_custody.__doc__
    assert "disclosure_create" in doc and "not_incident_lead" in doc and "deprecated" in doc
