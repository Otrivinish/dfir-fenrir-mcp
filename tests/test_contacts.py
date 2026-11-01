"""E2: Contacts directory + out-of-band contact over the curated tools.
fenrir_people_list view=contacts, fenrir_people_write contact_add / contact_update / contact_verify
and roster_update with oob_contact_methods, fenrir_comms_write stakeholder_add (contact_id),
fenrir_delete org_contact. Each test asserts the exact request sent; a 403 surfaces as FenrirError."""

import asyncio
import json

import httpx
import pytest

from fenrir_mcp import client
from fenrir_mcp.client import FenrirError
from fenrir_mcp.tools import admin, comms, people

INC = "11111111-1111-4111-8111-111111111111"
CID = "22222222-2222-4222-8222-222222222222"
UID = "33333333-3333-4333-8333-333333333333"
CONTACT = {"id": CID, "name": "Datainspektionen", "type": "supervisory_authority", "organization": "IMY",
           "contact_methods": [{"channel": "email", "value": "breach@example.test", "preferred": True}],
           "last_verified_at": None, "verified_by_id": None}


def _mock(monkeypatch, handler):
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})


def _recorder(monkeypatch, status=200, body=None):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.method, req.url.path, dict(req.url.params), json.loads(req.content) if req.content else None))
        return httpx.Response(status, json=body if body is not None else {})
    _mock(monkeypatch, handler)
    return seen


def test_contacts_view_filters_paging_and_fields(monkeypatch):
    seen = _recorder(monkeypatch, body={"items": [CONTACT], "next_cursor": "abc"})
    out = asyncio.run(people.fenrir_people_list("contacts", contact_type="csirt", q="cert", limit=5,
                                                cursor="xyz", fields=["id", "name"]))
    assert seen == [("GET", "/api/contacts", {"type": "csirt", "q": "cert", "limit": "5", "cursor": "xyz"}, None)]
    assert out == {"items": [{"id": CID, "name": "Datainspektionen"}], "next_cursor": "abc"}


def test_contacts_view_no_filters(monkeypatch):
    seen = _recorder(monkeypatch, body={"items": [], "next_cursor": None})
    asyncio.run(people.fenrir_people_list("contacts"))
    assert seen == [("GET", "/api/contacts", {}, None)]


def test_contact_add_update_verify(monkeypatch):
    seen = _recorder(monkeypatch, body=CONTACT)
    asyncio.run(people.fenrir_people_write("contact_add", data={"name": "CERT-SE", "type": "csirt"}))
    asyncio.run(people.fenrir_people_write("contact_update", item_id=CID, data={"notes": "24/7 desk"}))
    asyncio.run(people.fenrir_people_write("contact_verify", item_id=CID, data={"ignored": True}))
    assert seen == [
        ("POST", "/api/contacts", {}, {"name": "CERT-SE", "type": "csirt"}),
        ("PATCH", f"/api/contacts/{CID}", {}, {"notes": "24/7 desk"}),
        ("PATCH", f"/api/contacts/{CID}", {}, {"verified": True}),   # only the flag: the server stamps the time
    ]


@pytest.mark.parametrize("action", ["contact_update", "contact_verify"])
def test_contact_update_and_verify_need_item_id(monkeypatch, action):
    _recorder(monkeypatch)
    with pytest.raises(FenrirError, match="item_id"):
        asyncio.run(people.fenrir_people_write(action, data={}))


def test_contact_add_as_analyst_is_forbidden(monkeypatch):
    _recorder(monkeypatch, status=403, body={"detail": "Requires role: ('admin',)"})
    with pytest.raises(FenrirError, match="403"):
        asyncio.run(people.fenrir_people_write("contact_add", data={"name": "x"}))


def test_roster_update_passes_oob_contact_methods(monkeypatch):
    seen = _recorder(monkeypatch, body={"user_id": UID})
    oob = [{"channel": "mobile", "value": "+46 70 000 00 00", "preferred": True}]
    asyncio.run(people.fenrir_people_write("roster_update", user_id=UID, data={"oob_contact_methods": oob}))
    assert seen == [("PATCH", f"/api/roster/{UID}", {}, {"oob_contact_methods": oob})]


def test_comms_stakeholder_add_from_directory(monkeypatch):
    seen = _recorder(monkeypatch, body={"id": "s1", **{k: CONTACT[k] for k in ("name", "type")}})
    out = asyncio.run(comms.fenrir_comms_write("stakeholder_add", incident_id=INC,
                                               data={"contact_id": CID, "notes": "case note"}))
    assert seen == [("POST", f"/api/incidents/{INC}/stakeholders", {}, {"contact_id": CID, "notes": "case note"})]
    assert out["type"] == "supervisory_authority"


def test_comms_stakeholder_add_needs_incident(monkeypatch):
    _recorder(monkeypatch)
    with pytest.raises(FenrirError, match="incident_id"):
        asyncio.run(comms.fenrir_comms_write("stakeholder_add", data={"contact_id": CID}))


def test_delete_org_contact(monkeypatch):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.method, req.url.path))
        return httpx.Response(204)
    _mock(monkeypatch, handler)
    asyncio.run(admin.fenrir_delete("org_contact", CID))
    assert seen == [("DELETE", f"/api/contacts/{CID}")]
